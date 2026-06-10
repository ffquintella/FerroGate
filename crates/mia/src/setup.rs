//! `mia setup` — interactive configuration wizard.
//!
//! A guided, rich-terminal wizard (built on [`inquire`]) that walks an operator
//! through configuring the Machine Identity Agent and writes the **TOML
//! configuration file** ([`crate::config`]) to the OS-appropriate location:
//!
//! - the system path ([`crate::config::system_config_path`]) by default
//!   (`/etc/ferrogate/mia.toml`, `/Library/Application Support/FerroGate/…`, or
//!   `%ProgramData%\FerroGate\…`), or
//! - the per-user path ([`crate::config::user_config_path`]) with `--user`, or
//! - any path with `--output`.
//!
//! Run against an existing file it pre-fills every prompt with the current
//! value, so it doubles as an editor.
//!
//! The wizard is interactive only: it requires a TTY. In non-interactive
//! contexts (CI, configuration management) write the TOML file directly from
//! the documented template (`crates/mia/dist/mia.toml`).
//!
//! `unsafe` is forbidden in this crate; `inquire` performs all terminal I/O.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ferro_crypto::pin::SpkiPin;
use inquire::validator::Validation;
use inquire::{Confirm, Text};

use crate::config::{system_config_path, user_config_path, Config};

/// Run the `mia setup` subcommand. `args` is everything after `setup` on the
/// command line.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut explicit_output: Option<PathBuf> = None;
    let mut user_scope = false;
    let mut force = false;
    let mut clean = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "-o" | "--output" => {
                let path = it.next().context("--output requires a path argument")?;
                explicit_output = Some(PathBuf::from(path));
            }
            "-u" | "--user" => user_scope = true,
            "-f" | "--force" => force = true,
            "-c" | "--clean" => clean = true,
            other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }

    let output = if let Some(path) = explicit_output {
        path
    } else if user_scope {
        user_config_path().context("no per-user config path available (HOME/APPDATA is unset)")?
    } else {
        system_config_path()
    };

    // `--clean` removes the stored config instead of writing one. It shares the
    // same path resolution (--user / --output), so it deletes whatever the
    // matching `mia setup` would have written.
    if clean {
        return clean_config(&output, force);
    }

    // A wizard with no TTY would deadlock or error obscurely; fail with a clear
    // message and point at the non-interactive path instead.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "`mia setup` is interactive and needs a terminal (no TTY detected).\n\
             For unattended provisioning, write {} from the template in \
             crates/mia/dist/mia.toml.",
            output.display()
        );
    }

    println!("FerroGate Machine Identity Agent — setup");
    println!("Configuring: {}", output.display());
    if output.exists() {
        println!("(existing file found — prompts are pre-filled with its current values)");
    }
    println!("Press Esc at any prompt to abort without writing.");

    // The default destination is a root-owned system directory. If it isn't
    // writable by the current user, surface that NOW — otherwise the operator
    // fills out the whole wizard only to have the mid-wizard key fetch and the
    // final config write both fail with "Permission denied".
    warn_if_target_unwritable(&output);
    println!();

    let existing = load_existing(&output);
    let settings = match prompt_all(&existing) {
        Ok(s) => s,
        // Esc / Ctrl-C: abort cleanly without writing.
        Err(WizardError::Aborted) => {
            println!("\nAborted — no changes written.");
            return Ok(());
        }
        Err(WizardError::Inquire(e)) => return Err(e.into()),
    };

    let rendered = render(&settings);

    println!("\n──────── {} ────────", output.display());
    print!("{rendered}");
    println!("────────────────────────────────────────\n");

    // The write prompt is the single point of consent (it already names the
    // destination, whose prior existence was announced above). `--force` skips
    // it for scripted runs.
    let proceed = if force {
        true
    } else {
        match Confirm::new(&format!(
            "Write this configuration to {}?",
            output.display()
        ))
        .with_default(true)
        .prompt()
        {
            Ok(v) => v,
            Err(
                inquire::InquireError::OperationCanceled
                | inquire::InquireError::OperationInterrupted,
            ) => false,
            Err(e) => return Err(e.into()),
        }
    };
    if !proceed {
        println!("Aborted — no changes written.");
        return Ok(());
    }

    write_file(&output, &rendered)?;
    println!("\n✓ Wrote {}", output.display());
    println!("  Review it, then (re)start the agent:  {}", restart_hint());
    Ok(())
}

/// The collected configuration. `None` ⇒ the key is left as a commented
/// template placeholder rather than an active assignment.
#[derive(Default)]
struct Settings {
    log: Option<String>,
    cmis_endpoint: Option<String>,
    cmis_spki_pin: Option<String>,
    helper_socket: Option<String>,
    helper_socket_mode: Option<String>,
    helper_windows_group: Option<String>,
    allowlist: Option<String>,
    allowlist_key: Option<String>,
    allowlist_max_age: Option<String>,
    allowlist_fetch: bool,
    allowlist_propose: bool,
    ima_log: Option<String>,
}

/// Internal error type so an Esc/Ctrl-C cancellation can short-circuit the
/// whole wizard without being mistaken for a real failure.
enum WizardError {
    Aborted,
    Inquire(inquire::InquireError),
}

fn map_inquire(e: inquire::InquireError) -> WizardError {
    match e {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => {
            WizardError::Aborted
        }
        other => WizardError::Inquire(other),
    }
}

impl From<inquire::InquireError> for WizardError {
    fn from(e: inquire::InquireError) -> Self {
        map_inquire(e)
    }
}

/// Drive every prompt section, seeding defaults from the existing config.
#[allow(clippy::too_many_lines)] // a linear wizard; splitting it hurts readability
fn prompt_all(existing: &Config) -> Result<Settings, WizardError> {
    let mut s = Settings::default();

    // ── Logging ───────────────────────────────────────────────────────────
    let log = Text::new("Log verbosity (tracing EnvFilter syntax):")
        .with_default(existing.log.as_deref().unwrap_or("info"))
        .with_help_message("e.g. info, debug, mia=debug,info")
        .prompt()?;
    s.log = non_empty(log);

    // ── CMIS connection (the server to attest to) ───────────────────────────
    println!("\n— CMIS server (the Central Machine Identity Service to connect to) —");
    let endpoint = Text::new("CMIS endpoint URL:")
        .with_default(existing.cmis.endpoint.as_deref().unwrap_or_default())
        .with_help_message("https://cmis.example.com:8443  (https ⇒ hybrid-PQC TLS, pinned)")
        .with_validator(|input: &str| {
            let t = input.trim();
            if t.is_empty() || t.starts_with("https://") || t.starts_with("http://") {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "must start with https:// or http:// (or be left blank)".into(),
                ))
            }
        })
        .prompt()?;
    s.cmis_endpoint = non_empty(endpoint);

    if s.cmis_endpoint
        .as_deref()
        .is_some_and(|e| e.starts_with("https://"))
    {
        println!(
            "  The SPKI pin authenticates the CMIS server by its public key — the\n\
             \x20 SHA-384 of the certificate's SubjectPublicKeyInfo, pinned directly\n\
             \x20 rather than trusted via a CA chain. Ask your CMIS operator for it,\n\
             \x20 or compute it from the deployed server certificate:\n\
             \x20   openssl x509 -in cmis.crt -pubkey -noout \\\n\
             \x20     | openssl pkey -pubin -outform der \\\n\
             \x20     | openssl dgst -sha384 -binary | xxd -p -c 256\n\
             \x20 (see docs/transport-tls.md). Required here so this host can fetch\n\
             \x20 keys from CMIS over the pinned TLS channel."
        );
        let pin = Text::new("CMIS SPKI pin (lowercase-hex SHA-384):")
            .with_default(existing.cmis.spki_pin.as_deref().unwrap_or_default())
            .with_help_message("96 hex chars; pins the CMIS TLS cert by public key, not by CA")
            .with_validator(|input: &str| {
                let t = input.trim();
                if t.is_empty() || SpkiPin::from_hex(t).is_ok() {
                    Ok(Validation::Valid)
                } else {
                    Ok(Validation::Invalid(
                        "must be a lowercase-hex SHA-384 (96 hex chars), or blank".into(),
                    ))
                }
            })
            .prompt()?;
        s.cmis_spki_pin = non_empty(pin);
    }

    // ── Helper API (the daemon's local serving surface) ──────────────────────
    println!("\n— Helper API (local listener the daemon serves) —");
    let enable_helper = Confirm::new("Enable the local helper API?")
        .with_default(existing.helper.socket.is_some())
        .with_help_message("the agent serves DPoP-bound child tokens to vetted local callers")
        .prompt()?;
    if enable_helper {
        let socket = Text::new("Helper listener (Unix socket path / Windows pipe name):")
            .with_default(&path_default(
                existing.helper.socket.as_deref(),
                default_socket(),
            ))
            .prompt()?;
        s.helper_socket = non_empty(socket);

        // Socket mode is Unix-only; on Windows the pipe DACL governs access.
        #[cfg(not(windows))]
        {
            let mode = Text::new("Helper socket mode (octal):")
                .with_default(existing.helper.socket_mode.as_deref().unwrap_or("660"))
                .with_validator(octal_validator)
                .prompt()?;
            s.helper_socket_mode = non_empty(mode);
        }
        #[cfg(not(windows))]
        {
            // Preserve an existing windows_group value even when configuring on
            // a non-Windows host, so cross-editing a shared file is lossless.
            s.helper_windows_group
                .clone_from(&existing.helper.windows_group);
        }

        // The pipe-access group is Windows-only.
        #[cfg(windows)]
        {
            s.helper_socket_mode
                .clone_from(&existing.helper.socket_mode);
            let group = Text::new("Windows group allowed to open the pipe (blank ⇒ default DACL):")
                .with_default(existing.helper.windows_group.as_deref().unwrap_or_default())
                .with_help_message("e.g. FerroGateClients")
                .prompt()?;
            s.helper_windows_group = non_empty(group);
        }
    } else {
        // Keep any platform fields from the existing file rather than dropping
        // them just because the helper section was skipped this run.
        s.helper_socket_mode
            .clone_from(&existing.helper.socket_mode);
        s.helper_windows_group
            .clone_from(&existing.helper.windows_group);
    }

    // ── Allowlist ────────────────────────────────────────────────────────────
    println!("\n— Caller allowlist (signed list of vetted local callers) —");
    println!(
        "  The helper API mints child tokens only for callers named on this list;\n\
         \x20 with no allowlist configured it fails closed and denies everyone. The\n\
         \x20 list is a CBOR document that CMIS issues per host and signs with its\n\
         \x20 enrollment key. You provide two files:\n\
         \x20   • path — the signed allowlist body (supplied out of band today;\n\
         \x20     ask your CMIS operator for this host's allowlist)\n\
         \x20   • key  — the CMIS enrollment public key that signed it, so the\n\
         \x20     agent can verify the signature (the wizard can fetch this for you\n\
         \x20     below if you gave a CMIS endpoint + SPKI pin above)."
    );
    let configure_allowlist = Confirm::new("Configure a signed caller allowlist?")
        .with_default(existing.allowlist.path.is_some())
        .with_help_message("absent ⇒ the helper API denies every caller (fail closed)")
        .prompt()?;
    if configure_allowlist {
        let path = Text::new("Allowlist path (signed CBOR):")
            .with_default(&path_default(
                existing.allowlist.path.as_deref(),
                dist_sibling("allowlist.cbor"),
            ))
            .with_help_message("the signed list CMIS issued for this host (place it here)")
            .prompt()?;
        s.allowlist = non_empty(path);

        let key = Text::new("Allowlist verification key (CMIS enrollment pubkey):")
            .with_default(&path_default(
                existing.allowlist.key.as_deref(),
                dist_sibling("allowlist.pub"),
            ))
            .with_help_message("public key that verifies the allowlist signature")
            .prompt()?;
        s.allowlist_key = non_empty(key);

        // Offer to fetch the enrollment key from CMIS now (needs endpoint + pin).
        if let (Some(key_path), Some(endpoint), Some(pin)) = (
            s.allowlist_key.as_deref(),
            s.cmis_endpoint.as_deref(),
            s.cmis_spki_pin.as_deref(),
        ) {
            let fetch = Confirm::new(&format!("Fetch this key from {endpoint} now?"))
                .with_default(true)
                .with_help_message("downloads the CMIS enrollment public key over pinned TLS")
                .prompt()?;
            if fetch {
                match fetch_enrollment_key_to(endpoint, pin, Path::new(key_path)) {
                    Ok(()) => println!("  ✓ wrote {key_path}"),
                    Err(e) => {
                        // Non-fatal: keep configuring; the operator can retry or
                        // place the key out of band.
                        println!("  ! could not fetch the key: {e:#}");
                        println!("    (continuing — provide {key_path} another way)");
                    }
                }
            }
        }

        let age_default = existing
            .allowlist
            .max_age_secs
            .map_or_else(|| "86400".to_string(), |n| n.to_string());
        let age = Text::new("Maximum accepted allowlist age (seconds):")
            .with_default(&age_default)
            .with_validator(uint_validator)
            .prompt()?;
        s.allowlist_max_age = non_empty(age);

        // Offer to keep the on-disk allowlist in sync with CMIS automatically.
        // This happens at daemon start (after attestation supplies the host's
        // identity), so it needs a CMIS endpoint + pin — not at setup time.
        if s.cmis_endpoint.is_some() && s.cmis_spki_pin.is_some() {
            s.allowlist_fetch = Confirm::new("Fetch the signed allowlist from CMIS on each start?")
                .with_default(existing.allowlist.fetch)
                .with_help_message(
                    "daemon pulls this host's allowlist (by EK-UUID) and overwrites the path above",
                )
                .prompt()?;

            // Offer host-driven bootstrap: propose the callers this host observes
            // back to CMIS, which can auto-adopt the first one (TOFU) or queue it
            // for review. Lets a fresh host populate its own allowlist.
            s.allowlist_propose = Confirm::new("Propose observed callers to CMIS (bootstrap)?")
                .with_default(existing.allowlist.propose)
                .with_help_message(
                    "daemon periodically sends the (uid, binary-hash) callers it sees, SVID-signed",
                )
                .prompt()?;
        } else {
            // Preserve any existing settings when CMIS details are absent this run.
            s.allowlist_fetch = existing.allowlist.fetch;
            s.allowlist_propose = existing.allowlist.propose;
        }
    }

    // ── Attestation (Linux IMA) ──────────────────────────────────────────────
    // IMA is a Linux concept; only offer the override there.
    #[cfg(target_os = "linux")]
    {
        println!("\n— Attestation —");
        let override_ima = Confirm::new("Override the IMA runtime-measurement log path?")
            .with_default(existing.attestation.ima_log.is_some())
            .with_help_message("only needed if your kernel exposes IMA at a non-standard path")
            .prompt()?;
        if override_ima {
            let ima = Text::new("IMA log path:")
                .with_default(&path_default(
                    existing.attestation.ima_log.as_deref(),
                    DEFAULT_IMA_LOG.to_string(),
                ))
                .prompt()?;
            s.ima_log = non_empty(ima);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Preserve any existing IMA path (e.g. editing a Linux-authored file).
        s.ima_log = existing
            .attestation
            .ima_log
            .as_deref()
            .map(|p| p.display().to_string());
    }

    Ok(s)
}

/// Standard Linux IMA runtime-measurement log path (default override target).
const DEFAULT_IMA_LOG: &str = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements";

/// The platform's default helper listener address (Windows named pipe).
#[cfg(windows)]
fn default_socket() -> String {
    r"\\.\pipe\ferrogate-mia".to_string()
}

/// The platform's default helper listener address (macOS Unix socket). macOS
/// has no `/run`; daemons use `/var/run`, matching the launchd plist's
/// `FERROGATE_HELPER_SOCKET` (`crates/mia/dist/com.ferrogate.mia.plist`).
#[cfg(target_os = "macos")]
fn default_socket() -> String {
    "/var/run/ferrogate/mia.sock".to_string()
}

/// The platform's default helper listener address (Linux/other Unix socket).
#[cfg(not(any(target_os = "macos", windows)))]
fn default_socket() -> String {
    "/run/ferrogate/mia.sock".to_string()
}

/// A file alongside the system config directory (e.g. the allowlist), as a
/// sensible default hint.
fn dist_sibling(name: &str) -> String {
    system_config_path()
        .parent()
        .map_or_else(|| PathBuf::from(name), |p| p.join(name))
        .display()
        .to_string()
}

/// Choose a prompt default: the existing path if set, else `fallback`.
fn path_default(existing: Option<&Path>, fallback: String) -> String {
    existing.map_or(fallback, |p| p.display().to_string())
}

/// Fetch the CMIS enrollment public key over pinned TLS and write it to
/// `key_path` (composite concat bytes). Spins a short-lived current-thread
/// runtime since the wizard is otherwise synchronous.
fn fetch_enrollment_key_to(endpoint: &str, pin_hex: &str, key_path: &Path) -> anyhow::Result<()> {
    let pin =
        SpkiPin::from_hex(pin_hex.trim()).map_err(|e| anyhow::anyhow!("invalid SPKI pin: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime")?;
    let key = rt.block_on(crate::client::fetch_enrollment_key(endpoint, vec![pin]))?;

    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(key_path, &key).with_context(|| format!("writing {}", key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Public key material — world-readable is fine.
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

/// The platform-appropriate service-restart hint shown after writing (Linux).
#[cfg(target_os = "linux")]
fn restart_hint() -> &'static str {
    "sudo systemctl restart mia"
}

/// The service-restart hint (macOS launchd).
#[cfg(target_os = "macos")]
fn restart_hint() -> &'static str {
    "sudo launchctl kickstart -k system/com.ferrogate.mia"
}

/// The service-restart hint (Windows service control).
#[cfg(windows)]
fn restart_hint() -> &'static str {
    "Restart-Service mia  (or: sc stop mia && sc start mia)"
}

/// The service-restart hint (other platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn restart_hint() -> &'static str {
    "restart the mia service"
}

/// An octal-mode validator (e.g. `660`, `0o640`).
fn octal_validator(input: &str) -> Result<Validation, inquire::CustomUserError> {
    let t = input.trim().trim_start_matches("0o");
    if t.is_empty() {
        return Ok(Validation::Valid);
    }
    match u32::from_str_radix(t, 8) {
        Ok(_) => Ok(Validation::Valid),
        Err(_) => Ok(Validation::Invalid("not an octal mode (e.g. 660)".into())),
    }
}

/// An unsigned-integer validator (seconds).
fn uint_validator(input: &str) -> Result<Validation, inquire::CustomUserError> {
    let t = input.trim();
    if t.is_empty() || t.parse::<u64>().is_ok() {
        Ok(Validation::Valid)
    } else {
        Ok(Validation::Invalid(
            "must be a whole number of seconds".into(),
        ))
    }
}

/// Trim and treat the empty string as "unset".
fn non_empty(s: String) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Parse an existing TOML config file for prompt pre-fill. A missing or
/// unparseable file yields defaults (the wizard then starts fresh).
fn load_existing(path: &Path) -> Config {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| Config::from_toml(&t).ok())
        .unwrap_or_default()
}

/// Render the documented, self-commenting TOML config file. Keys the operator
/// set are active assignments; everything else stays as a commented template
/// line so the file remains a reference.
#[allow(clippy::too_many_lines)] // a flat sequence of TOML-emitting blocks.
fn render(s: &Settings) -> String {
    // A quoted (TOML literal-string) value line, or a commented placeholder.
    fn str_line(set: Option<&str>, key: &str, placeholder: &str) -> String {
        match set {
            Some(v) => format!("{key} = '{v}'\n"),
            None => format!("#{key} = '{placeholder}'\n"),
        }
    }
    // An unquoted (numeric) value line, or a commented placeholder.
    fn int_line(set: Option<&str>, key: &str, placeholder: &str) -> String {
        match set {
            Some(v) => format!("{key} = {v}\n"),
            None => format!("#{key} = {placeholder}\n"),
        }
    }

    let mut out = String::new();
    out.push_str(
        "# FerroGate Machine Identity Agent (MIA) configuration.\n\
         #\n\
         # Generated by `mia setup`. Precedence: defaults < this file <\n\
         # environment variables. Re-run `mia setup` to edit. See docs/mia.md.\n\n",
    );

    out.push_str("# Tracing verbosity (tracing EnvFilter syntax). Default: info.\n");
    out.push_str(&str_line(s.log.as_deref(), "log", "info"));
    out.push('\n');

    out.push_str("[cmis]\n");
    out.push_str("# CMIS endpoint. An https:// URL is dialed over hybrid-PQC TLS, pinned by\n");
    out.push_str("# SPKI; http:// is plaintext bring-up only.\n");
    out.push_str(&str_line(
        s.cmis_endpoint.as_deref(),
        "endpoint",
        "https://cmis.example.com:8443",
    ));
    out.push_str("# Accepted CMIS SPKI pin (lowercase-hex SHA-384).\n");
    out.push_str(&str_line(
        s.cmis_spki_pin.as_deref(),
        "spki_pin",
        "<hex-sha384>",
    ));
    out.push('\n');

    out.push_str("[helper]\n");
    out.push_str("# Listener address: a Unix socket path (Linux/macOS) or a named-pipe name\n");
    out.push_str("# (Windows). Its presence ENABLES the helper API.\n");
    out.push_str(&str_line(
        s.helper_socket.as_deref(),
        "socket",
        &default_socket(),
    ));
    out.push_str("# Unix only. Octal socket mode. Default: 660.\n");
    out.push_str(&str_line(
        s.helper_socket_mode.as_deref(),
        "socket_mode",
        "660",
    ));
    out.push_str("# Windows only. Local group allowed to open the pipe (blank ⇒ default DACL).\n");
    out.push_str(&str_line(
        s.helper_windows_group.as_deref(),
        "windows_group",
        "FerroGateClients",
    ));
    out.push('\n');

    out.push_str("[allowlist]\n");
    out.push_str("# Signed CBOR allowlist of vetted local callers. Absent => deny every caller.\n");
    out.push_str(&str_line(
        s.allowlist.as_deref(),
        "path",
        "/etc/ferrogate/allowlist.cbor",
    ));
    out.push_str("# Trusted CMIS enrollment public key used to verify the allowlist. Required\n");
    out.push_str("# whenever `path` is set.\n");
    out.push_str(&str_line(
        s.allowlist_key.as_deref(),
        "key",
        "/etc/ferrogate/allowlist.pub",
    ));
    out.push_str("# Maximum accepted allowlist age in seconds. Default: 86400.\n");
    out.push_str(&int_line(
        s.allowlist_max_age.as_deref(),
        "max_age_secs",
        "86400",
    ));
    out.push_str(
        "# Fetch this host's allowlist from CMIS at startup (by EK-UUID) and write it\n\
         # to `path` before loading. Needs cmis.endpoint + spki_pin. Default: false.\n",
    );
    if s.allowlist_fetch {
        out.push_str("fetch = true\n");
    } else {
        out.push_str("#fetch = false\n");
    }
    out.push_str(
        "# Propose the local callers this host observes (granted and denied) to CMIS\n\
         # periodically. CMIS auto-adopts the first proposal on a host with no\n\
         # allowlist (bootstrap/TOFU) or queues it for operator review. Needs\n\
         # cmis.endpoint + spki_pin and a host SVID. Default: false.\n",
    );
    if s.allowlist_propose {
        out.push_str("propose = true\n");
    } else {
        out.push_str("#propose = false\n");
    }
    out.push('\n');

    out.push_str("[attestation]\n");
    out.push_str("# Linux only. Override the IMA runtime-measurement log path.\n");
    out.push_str(&str_line(s.ima_log.as_deref(), "ima_log", DEFAULT_IMA_LOG));

    out
}

/// Warn (but don't abort) if the wizard's destination directory isn't writable
/// by the current user — typically the root-owned system config path opened
/// without elevation. Continues so the operator can still preview the rendered
/// config; the actual write remains the point that enforces permissions.
fn warn_if_target_unwritable(output: &Path) {
    // Probe the nearest existing ancestor: the parent may not exist yet, in
    // which case writability is decided by whichever directory we'd create it
    // under.
    let mut dir = output.parent();
    while let Some(d) = dir {
        if d.as_os_str().is_empty() {
            return;
        }
        if d.exists() {
            if !dir_is_writable(d) {
                println!(
                    "\n⚠ {} isn't writable by the current user.\n\
                     \x20 Fetching keys into it and writing the config will fail with a\n\
                     \x20 permission error. Re-run with `sudo`/as admin, or use --user for a\n\
                     \x20 per-user file, or --output to write somewhere you can write.",
                    d.display()
                );
            }
            return;
        }
        dir = d.parent();
    }
}

/// Whether `dir` is writable by the current user, probed by creating and
/// removing a temporary file (the only portable, ownership-aware check).
fn dir_is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".mia-setup-write-probe.{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Write `content` to `path`, creating parent directories. The caller already
/// obtained consent (the write prompt names this exact path), so this
/// overwrites unconditionally. On Unix the file is created with mode `0640`.
fn write_file(path: &Path, content: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(path, content).with_context(|| {
        format!(
            "writing {} (the system path needs elevation — re-run with `sudo`/as admin, \
             use --user for a per-user file, or --output to write elsewhere)",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
    }
    Ok(())
}

/// Remove the stored configuration file at `path`. Prompts for confirmation
/// (a TTY is required) unless `force` is set. A missing file is reported and
/// treated as success — `--clean` is idempotent.
fn clean_config(path: &Path, force: bool) -> anyhow::Result<()> {
    if !path.exists() {
        println!("Nothing to clean — no configuration at {}.", path.display());
        return Ok(());
    }

    if !force {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            anyhow::bail!(
                "refusing to delete {} without confirmation (no TTY). \
                 Re-run with --force to delete non-interactively.",
                path.display()
            );
        }
        let proceed =
            match Confirm::new(&format!("Delete the configuration at {}?", path.display()))
                .with_default(false)
                .prompt()
            {
                Ok(v) => v,
                Err(
                    inquire::InquireError::OperationCanceled
                    | inquire::InquireError::OperationInterrupted,
                ) => false,
                Err(e) => return Err(e.into()),
            };
        if !proceed {
            println!("Aborted — nothing deleted.");
            return Ok(());
        }
    }

    std::fs::remove_file(path).with_context(|| {
        format!(
            "deleting {} (the system path needs elevation — re-run with `sudo`/as admin, \
             use --user for the per-user file, or --output to target a specific path)",
            path.display()
        )
    })?;
    println!("✓ Removed {}", path.display());
    Ok(())
}

const USAGE: &str = "usage: mia setup [--user] [--output <path>] [--force] [--clean]";

fn print_help() {
    println!(
        "mia setup — interactive configuration wizard\n\
         \n\
         {USAGE}\n\
         \n\
         Walks you through configuring the Machine Identity Agent (CMIS server,\n\
         helper API, allowlist, attestation, logging) and writes the TOML\n\
         configuration file. Pre-fills prompts from an existing file.\n\
         \n\
         By default it writes the OS system path:\n\
         \x20 {}\n\
         \n\
         With --clean it deletes that file instead of writing one (honouring\n\
         --user / --output to choose which).\n\
         \n\
         options:\n\
         \x20 -u, --user            target the per-user config path instead\n\
         \x20 -o, --output <path>   target a specific path\n\
         \x20 -c, --clean           delete the stored configuration\n\
         \x20 -f, --force           skip the confirmation prompt (write or clean)\n\
         \x20 -h, --help            show this help\n",
        system_config_path().display(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_existing_parses_toml_and_defaults_on_missing() {
        let dir = std::env::temp_dir().join(format!("mia-setup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mia.toml");
        std::fs::write(&path, "log = 'debug'\n[helper]\nsocket = '/run/x.sock'\n").unwrap();
        let cfg = load_existing(&path);
        assert_eq!(cfg.log.as_deref(), Some("debug"));
        assert_eq!(cfg.helper.socket.as_deref(), Some(Path::new("/run/x.sock")));
        // A missing file yields defaults, not an error.
        assert_eq!(load_existing(&dir.join("nope.toml")).log, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_emits_active_and_commented_toml() {
        let s = Settings {
            log: Some("info".into()),
            helper_socket: Some("/run/ferrogate/mia.sock".into()),
            allowlist_max_age: Some("3600".into()),
            ..Settings::default()
        };
        let out = render(&s);
        assert!(out.contains("\nlog = 'info'\n"));
        assert!(out.contains("\nsocket = '/run/ferrogate/mia.sock'\n"));
        // Integer key is unquoted.
        assert!(out.contains("\nmax_age_secs = 3600\n"));
        // Unset keys stay as commented placeholders.
        assert!(out.contains("#endpoint = 'https://cmis.example.com:8443'\n"));
        // The rendered file round-trips through the real config parser.
        let parsed = Config::from_toml(&out).expect("rendered TOML parses");
        assert_eq!(parsed.log.as_deref(), Some("info"));
        assert_eq!(parsed.allowlist_max_age(), 3600);
    }

    #[test]
    fn validators_accept_and_reject() {
        assert!(matches!(octal_validator("660"), Ok(Validation::Valid)));
        assert!(matches!(octal_validator("0o640"), Ok(Validation::Valid)));
        assert!(matches!(octal_validator("999"), Ok(Validation::Invalid(_))));
        assert!(matches!(uint_validator("86400"), Ok(Validation::Valid)));
        assert!(matches!(uint_validator("-1"), Ok(Validation::Invalid(_))));
    }

    #[test]
    fn clean_config_removes_file_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("mia-clean-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mia.toml");
        std::fs::write(&path, "log = 'info'\n").unwrap();

        // force=true skips the prompt; the file is removed.
        clean_config(&path, true).unwrap();
        assert!(!path.exists());
        // Cleaning an already-absent file is a no-op success.
        clean_config(&path, true).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_empty_trims_and_nullifies_blank() {
        assert_eq!(non_empty("  x ".into()), Some("x".into()));
        assert_eq!(non_empty("   ".into()), None);
    }
}
