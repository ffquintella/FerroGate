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
use inquire::{Confirm, Select, Text};

use crate::config::{
    system_config_path, system_config_path_for, user_config_path_for, validate_environment, Config,
};

/// Run the `mia setup` subcommand. `args` is everything after `setup` on the
/// command line.
#[allow(clippy::too_many_lines)] // linear flag parsing then one write step.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    // The non-interactive modes (feature F18) — `--check`, `--apply`, `--dump`
    // — need no TTY and share this wizard's validators and renderer.
    if args
        .iter()
        .any(|a| matches!(a.as_str(), "--check" | "--apply" | "--dump"))
    {
        return crate::setup_apply::run(args);
    }
    let mut explicit_output: Option<PathBuf> = None;
    let mut environment: Option<String> = None;
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
            "-e" | "--environment" => {
                let env = it
                    .next()
                    .context("--environment requires a name argument")?;
                validate_environment(env)?;
                environment = Some(env.clone());
            }
            "-u" | "--user" => user_scope = true,
            "-f" | "--force" => force = true,
            "-c" | "--clean" => clean = true,
            other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }

    // `--environment` selects which standard file (`mia-<env>.toml`) to write,
    // so it composes with `--user` but not with `--output`, which already names
    // an exact path.
    if environment.is_some() && explicit_output.is_some() {
        anyhow::bail!(
            "--output and --environment are mutually exclusive: --output names an exact file, \
             --environment selects mia-<env>.toml in the standard config location\n\n{USAGE}"
        );
    }
    let env = environment.as_deref();

    let output = target_path(explicit_output, user_scope, env)?;

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

    // The host's default environment decides this file's default helper
    // address; the file's environment is judged the way the daemon judges it
    // (the selector, else a `mia-<env>.toml` output name).
    let selection = crate::default_env::DefaultSelection::load()?;
    let file_env = env
        .map(str::to_owned)
        .or_else(|| crate::config::environment_for_path(&output));
    let listener = ListenerDefaults::new(file_env.as_deref(), &selection);

    let existing = load_existing(&output);
    let settings = match prompt_all(&existing, file_env.as_deref(), &listener) {
        Ok(s) => s,
        // Esc / Ctrl-C: abort cleanly without writing.
        Err(WizardError::Aborted) => {
            println!("\nAborted — no changes written.");
            return Ok(());
        }
        Err(WizardError::Inquire(e)) => return Err(e.into()),
    };

    let rendered = render(&settings, file_env.as_deref(), selection.environment());

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

    let changed = crate::setup_apply::write_config(&output, &rendered, &existing)?;
    println!("\n✓ Wrote {}", output.display());
    if !changed.is_empty() {
        println!("  Changed: {}", changed.join(", "));
    }
    println!("  Review it, then (re)start the agent:  {}", restart_hint());
    Ok(())
}

/// Resolve the file `mia setup` writes: `--output` verbatim, else the per-user
/// (`--user`) or system path for the `--environment` selector. Shared with
/// `mia setup --apply / --dump`.
pub(crate) fn target_path(
    explicit_output: Option<PathBuf>,
    user_scope: bool,
    environment: Option<&str>,
) -> anyhow::Result<PathBuf> {
    Ok(if let Some(path) = explicit_output {
        path
    } else if user_scope {
        user_config_path_for(environment)
            .context("no per-user config path available (HOME/APPDATA is unset)")?
    } else {
        system_config_path_for(environment)
    })
}

/// The collected configuration. `None` ⇒ the key is left as a commented
/// template placeholder rather than an active assignment.
///
/// Shared with the non-interactive `mia setup --apply` (feature F18), which
/// fills it from a draft file instead of prompts and renders it with the same
/// [`render`], so both front ends write byte-identical files for the same
/// answers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) log: Option<String>,
    pub(crate) cmis_endpoint: Option<String>,
    pub(crate) cmis_srv: Option<String>,
    pub(crate) cmis_spki_pin: Option<String>,
    /// `helper.enable`: `Some(false)` writes `enable = false` (helper API
    /// off); `None` or `Some(true)` leave the default (on) as a commented
    /// placeholder.
    pub(crate) helper_enable: Option<bool>,
    pub(crate) helper_socket: Option<String>,
    pub(crate) helper_socket_mode: Option<String>,
    pub(crate) helper_windows_group: Option<String>,
    pub(crate) allowlist: Option<String>,
    pub(crate) allowlist_key: Option<String>,
    pub(crate) allowlist_max_age: Option<String>,
    pub(crate) allowlist_fetch: bool,
    pub(crate) allowlist_propose: bool,
    pub(crate) ima_log: Option<String>,
    /// `attestation.backend`; `None` ⇒ the default `auto` (see
    /// [`backend_setting`]).
    pub(crate) attestation_backend: Option<String>,
    /// Keys the wizard does not prompt for, carried over unchanged from the
    /// file being edited so a rewrite does not drop them.
    pub(crate) carried: Carried,
}

/// Configuration the wizard does not edit but must not lose on a rewrite:
/// copied from the existing file and re-emitted verbatim by [`render`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Carried {
    helper_socket_gid: Option<String>,
    helper_require_authenticode: Option<bool>,
    allowlist_propose_interval_secs: Option<u64>,
    tpm_ek_cert: Option<String>,
    tpm_ek_intermediates: Vec<String>,
    status: crate::config::StatusConfig,
}

impl Carried {
    /// The non-wizard keys of `existing`.
    pub(crate) fn from_existing(existing: &Config) -> Self {
        let path = |p: &Path| p.display().to_string();
        Self {
            helper_socket_gid: existing.helper.socket_gid.clone(),
            helper_require_authenticode: existing.helper.require_authenticode,
            allowlist_propose_interval_secs: existing.allowlist.propose_interval_secs,
            tpm_ek_cert: existing.attestation.tpm.ek_cert.as_deref().map(path),
            tpm_ek_intermediates: existing
                .attestation
                .tpm
                .ek_intermediates
                .iter()
                .map(|p| path(p))
                .collect(),
            status: existing.status.clone(),
        }
    }
}

/// The attestation backends the wizard offers, in prompt order.
pub(crate) const BACKEND_CHOICES: [&str; 4] = ["auto", "tpm", "host-key", "virtual-tpm"];

/// Map a backend answer onto [`Settings::attestation_backend`]: `auto` (the
/// default) stays a commented placeholder; anything else is written.
pub(crate) fn backend_setting(choice: &str) -> Option<String> {
    (choice != "auto").then(|| choice.to_string())
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
/// `environment` is the file's environment as the daemon judges it (the
/// `--environment` selector, else a `mia-<env>.toml` output name), if any: it
/// suffixes the suggested default paths (allowlist body, verification key) so
/// a side-by-side deployment configured on the same host does not collide with
/// the default one.
#[allow(clippy::too_many_lines)] // a linear wizard; splitting it hurts readability
fn prompt_all(
    existing: &Config,
    environment: Option<&str>,
    listener: &ListenerDefaults,
) -> Result<Settings, WizardError> {
    let mut s = Settings::default();

    // ── Logging ───────────────────────────────────────────────────────────
    let log = Text::new("Log verbosity (tracing EnvFilter syntax):")
        .with_default(existing.log.as_deref().unwrap_or("info"))
        .with_help_message("e.g. info, debug, mia=debug,info")
        .with_validator(literal_validator)
        .prompt()?;
    s.log = non_empty(log);

    // ── CMIS connection (the server to attest to) ───────────────────────────
    println!("\n— CMIS server (the Central Machine Identity Service to connect to) —");
    // Discovery mode: one fixed endpoint, or a DNS SRV record advertising an HA
    // cluster the agent discovers and fails over across.
    let modes = vec![
        "Single endpoint (one CMIS server)",
        "SRV record (high availability — discover & fail over across nodes)",
    ];
    let start_cursor = usize::from(existing.cmis.srv.is_some());
    let mode = Select::new("How should this host reach CMIS?", modes)
        .with_starting_cursor(start_cursor)
        .with_help_message(
            "SRV lets one DNS record advertise several CMIS nodes; mia dials the best live one",
        )
        .prompt()?;
    let use_srv = mode.starts_with("SRV");

    if use_srv {
        let srv = Text::new("CMIS SRV record name:")
            .with_default(existing.cmis.srv.as_deref().unwrap_or_default())
            .with_help_message(
                "e.g. _cmis._tcp.example.com  (records dialed best-first over hybrid-PQC TLS)",
            )
            .with_validator(|input: &str| to_validation(check_srv(input)))
            .prompt()?;
        s.cmis_srv = non_empty(srv);
    } else {
        let endpoint = Text::new("CMIS endpoint URL:")
            .with_default(existing.cmis.endpoint.as_deref().unwrap_or_default())
            .with_help_message("https://cmis.example.com:8443  (https ⇒ hybrid-PQC TLS, pinned)")
            .with_validator(|input: &str| to_validation(check_endpoint(input)))
            .prompt()?;
        s.cmis_endpoint = non_empty(endpoint);
    }

    // The SPKI pin authenticates CMIS over TLS — required for any SRV record or
    // an https endpoint (a bare http:// endpoint, plaintext bring-up, needs none).
    let needs_pin = s.cmis_srv.is_some()
        || s.cmis_endpoint
            .as_deref()
            .is_some_and(|e| e.starts_with("https://"));
    if needs_pin {
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
            .with_validator(|input: &str| to_validation(check_pin(input)))
            .prompt()?;
        s.cmis_spki_pin = non_empty(pin);
    }

    // ── Helper API (the daemon's local serving surface) ──────────────────────
    println!("\n— Helper API (local listener the daemon serves) —");
    let enable_helper = Confirm::new("Enable the local helper API?")
        .with_default(existing.helper_enabled())
        .with_help_message(
            "on by default: the agent serves DPoP-bound child tokens to vetted local callers; \
             No writes `enable = false`",
        )
        .prompt()?;
    if enable_helper {
        println!("  {}", listener.note);
        // An existing explicit socket that another environment now owns is
        // not offered again (the daemon would refuse it).
        let existing_socket = existing.helper.socket.as_deref().filter(|p| {
            let ok = listener.check(&p.to_string_lossy()).is_ok();
            if !ok {
                println!(
                    "  (the current helper.socket {} is the well-known address, which another \
                     environment now owns — suggesting this environment's own address)",
                    p.display()
                );
            }
            ok
        });
        let not_claimed = listener.clone();
        let socket = Text::new("Helper listener (Unix socket path / Windows pipe name):")
            .with_default(&path_default(
                existing_socket,
                listener.default.display().to_string(),
            ))
            .with_help_message(
                "blank or the suggested default ⇒ left unset, following the platform default",
            )
            .with_validator(literal_validator)
            .with_validator(move |input: &str| to_validation(not_claimed.check(input)))
            .prompt()?;
        s.helper_socket = listener.normalize(non_empty(socket));

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
                .with_validator(literal_validator)
                .prompt()?;
            s.helper_windows_group = non_empty(group);
        }
    } else {
        // An unset socket no longer disables the helper API; say so explicitly.
        s.helper_enable = Some(false);
        // Keep any platform fields from the existing file rather than dropping
        // them just because the helper section was skipped this run.
        s.helper_socket_mode
            .clone_from(&existing.helper.socket_mode);
        s.helper_windows_group
            .clone_from(&existing.helper.windows_group);
    }

    // ── Allowlist ────────────────────────────────────────────────────────────
    println!("\n— Caller allowlist (signed list of vetted local callers) —");
    let default_body = crate::config::default_allowlist_path(environment);
    println!(
        "  The helper API mints child tokens only for callers named on this list;\n\
         \x20 with no verifiable allowlist it fails closed and denies everyone. The\n\
         \x20 list is a CBOR document that CMIS issues per host and signs with its\n\
         \x20 enrollment key. Two files are involved:\n\
         \x20   • path — the signed allowlist body; by default\n\
         \x20     {} (CMIS can deliver it there: allowlist.fetch\n\
         \x20     below, or `mia resync-allowlist`)\n\
         \x20   • key  — the CMIS enrollment public key that signed it, so the\n\
         \x20     agent can verify the signature. It has no default and must be set\n\
         \x20     for any caller to be allowed (the wizard can fetch it for you\n\
         \x20     below if you gave a CMIS endpoint + SPKI pin above).",
        default_body.display()
    );
    let configure_allowlist = Confirm::new("Configure a signed caller allowlist?")
        .with_default(existing.allowlist.path.is_some() || existing.allowlist.key.is_some())
        .with_help_message("no verification key ⇒ the helper API denies every caller (fail closed)")
        .prompt()?;
    if configure_allowlist {
        let path = Text::new("Allowlist path (signed CBOR):")
            .with_default(&path_default(
                existing.allowlist.path.as_deref(),
                default_body.display().to_string(),
            ))
            .with_help_message(
                "blank or the suggested default ⇒ left unset, following the platform default",
            )
            .with_validator(literal_validator)
            .prompt()?;
        s.allowlist = allowlist_path_setting(non_empty(path), environment);

        let key = Text::new("Allowlist verification key (CMIS enrollment pubkey):")
            .with_default(&path_default(
                existing.allowlist.key.as_deref(),
                dist_sibling(&env_filename("allowlist.pub", environment)),
            ))
            .with_help_message("public key that verifies the allowlist signature")
            .with_validator(literal_validator)
            .prompt()?;
        s.allowlist_key = non_empty(key);

        // Offer to fetch the enrollment key from CMIS now. Build a resolver from
        // the values just entered (static endpoint or SRV record); it needs a
        // CMIS source + SPKI pin, and for SRV it discovers and fails over.
        if let Some(key_path) = s.allowlist_key.as_deref() {
            let cfg = crate::config::CmisConfig {
                endpoint: s.cmis_endpoint.clone(),
                srv: s.cmis_srv.clone(),
                spki_pin: s.cmis_spki_pin.clone(),
            };
            if let Ok(Some(resolver)) = crate::endpoint::CmisResolver::from_config(&cfg) {
                let fetch =
                    Confirm::new(&format!("Fetch this key from {} now?", resolver.describe()))
                        .with_default(true)
                        .with_help_message(
                            "downloads the CMIS enrollment public key over pinned TLS",
                        )
                        .prompt()?;
                if fetch {
                    match install_enrollment_key(&resolver, Path::new(key_path)) {
                        Ok(done) => println!("  ✓ {done}"),
                        Err(e) => {
                            // Non-fatal: keep configuring; the operator can retry
                            // or place the key out of band.
                            println!("  ! could not install the key: {e:#}");
                            println!(
                                "    (continuing — later: sudo mia allowlist-key fetch, or \
                                 provide {key_path} another way)"
                            );
                        }
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
        // identity), so it needs a CMIS source + pin — not at setup time. Either
        // a static endpoint or an SRV record works: the daemon resolves both via
        // `CmisResolver::from_config`, so don't gate on `endpoint` alone.
        let cmis_reachable =
            (s.cmis_endpoint.is_some() || s.cmis_srv.is_some()) && s.cmis_spki_pin.is_some();
        if cmis_reachable {
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

    // ── Attestation backend ─────────────────────────────────────────────────
    println!("\n— Attestation —");
    let current = serde_json::to_value(existing.attestation.backend)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "auto".to_string());
    let cursor = BACKEND_CHOICES
        .iter()
        .position(|c| *c == current)
        .unwrap_or(0);
    let backend = Select::new("Attestation backend:", BACKEND_CHOICES.to_vec())
        .with_starting_cursor(cursor)
        .with_help_message(
            "auto = TPM when usable, else host-key; virtual-tpm is INSECURE (dev/test builds only)",
        )
        .prompt()?;
    s.attestation_backend = backend_setting(backend);

    // ── Attestation (Linux IMA) ──────────────────────────────────────────────
    // IMA is a Linux concept; only offer the override there.
    #[cfg(target_os = "linux")]
    {
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
                .with_validator(literal_validator)
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

    s.carried = Carried::from_existing(existing);
    Ok(s)
}

/// Standard Linux IMA runtime-measurement log path (default override target).
const DEFAULT_IMA_LOG: &str = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements";

/// Suffix a default filename with the `--environment` selector so side-by-side
/// deployments don't collide: `allowlist.cbor` + `Some("staging")` →
/// `allowlist-staging.cbor`; the suffix is inserted before the extension. With
/// no environment the name is returned unchanged.
fn env_filename(name: &str, environment: Option<&str>) -> String {
    match environment {
        None => name.to_string(),
        Some(env) => match name.rsplit_once('.') {
            Some((stem, ext)) => format!("{stem}-{env}.{ext}"),
            None => format!("{name}-{env}"),
        },
    }
}

/// The default helper listener address for `environment` under the host's
/// selected default environment (`selected_default`, `None` ⇒ `mia.toml`), as
/// the prompt and placeholder text. The address itself comes from
/// [`crate::config::default_helper_address`] — the one the daemon binds when
/// `helper.socket` is unset — so the wizard never suggests a different path.
fn default_socket(environment: Option<&str>, selected_default: Option<&str>) -> String {
    crate::config::default_helper_address(environment, selected_default)
        .display()
        .to_string()
}

/// The helper-listener prompt's view of the host's default environment
/// ([`crate::default_env`]) for the environment being configured.
#[derive(Debug, Clone)]
pub(crate) struct ListenerDefaults {
    /// What the daemon binds for this environment when `helper.socket` is
    /// unset.
    default: PathBuf,
    /// The selected default environment when it is *another* one: the
    /// well-known address is then off-limits here.
    claimed_by: Option<String>,
    /// One line for the operator: who owns the well-known address, and why.
    note: String,
}

impl ListenerDefaults {
    /// The defaults for `environment` (`None` ⇒ `mia.toml`) under `selection`.
    pub(crate) fn new(
        environment: Option<&str>,
        selection: &crate::default_env::DefaultSelection,
    ) -> Self {
        let default = crate::config::default_helper_address(environment, selection.environment());
        let well_known = crate::config::default_helper_socket(None);
        let owner = selection
            .environment()
            .map_or_else(|| "mia.toml".to_string(), |e| format!("`{e}`"));
        let role = if selection.is_default(environment) {
            format!(
                "this environment serves the well-known address {}",
                well_known.display()
            )
        } else {
            format!(
                "the well-known address {} is not this environment's; its default is {}",
                well_known.display(),
                default.display()
            )
        };
        Self {
            claimed_by: selection
                .environment()
                .filter(|_| !selection.is_default(environment))
                .map(str::to_owned),
            note: format!(
                "Default environment: {owner} ({}) — {role}.",
                selection.source()
            ),
            default,
        }
    }

    /// Refuse an answer that names the well-known address while another
    /// environment is the selected default (the daemon would refuse it too).
    fn check(&self, input: &str) -> Result<(), String> {
        let Some(owner) = &self.claimed_by else {
            return Ok(());
        };
        let t = input.trim();
        if !t.is_empty()
            && crate::default_env::same_helper_address(
                Path::new(t),
                &crate::config::default_helper_socket(None),
            )
        {
            return Err(format!(
                "this is the well-known default helper address, which belongs to the default \
                 environment `{owner}`; leave it blank to use {}",
                self.default.display()
            ));
        }
        Ok(())
    }

    /// The `helper.socket` value to write for `answer`: `None` when it is just
    /// this environment's default, so the file keeps following the platform
    /// default (and a later change of the default environment) instead of
    /// pinning today's path.
    fn normalize(&self, answer: Option<String>) -> Option<String> {
        answer.filter(|v| !crate::default_env::same_helper_address(Path::new(v), &self.default))
    }
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

/// The `allowlist.path` value to write for `answer`: `None` when it is just
/// this environment's default ([`crate::config::default_allowlist_path`]), so
/// the file keeps following the platform default instead of pinning today's
/// path — mirroring how the helper socket is written.
pub(crate) fn allowlist_path_setting(
    answer: Option<String>,
    environment: Option<&str>,
) -> Option<String> {
    let default = crate::config::default_allowlist_path(environment);
    answer.filter(|v| Path::new(v) != default)
}

/// Fetch the CMIS enrollment public key over the pinned channel and install
/// it at `key_path` for the interactive wizard, through the same validated,
/// atomic and audited path as `mia allowlist-key fetch`
/// ([`crate::allowlist_key`]). The wizard's "fetch now?" answer is the
/// consent for a first install; replacing a *different* installed key needs a
/// second, explicit confirmation (default: no), showing both fingerprints.
/// Returns what was done, for the wizard to print.
fn install_enrollment_key(
    resolver: &crate::endpoint::CmisResolver,
    key_path: &Path,
) -> anyhow::Result<String> {
    use crate::allowlist_key::{self as ak, Change, Refusal};
    let (_, fetched) = ak::fetch_key(resolver)?;
    let plan = match ak::plan(key_path, &fetched, None, false) {
        Ok(plan) => plan,
        Err(e) => {
            let Some(Refusal::Differs {
                installed,
                fetched: served,
                ..
            }) = e.downcast_ref::<Refusal>()
            else {
                return Err(e);
            };
            println!("  {} holds a different enrollment key:", key_path.display());
            println!("    installed: {installed}");
            println!("    CMIS:      {served}");
            let replace = Confirm::new("Replace the installed key with the one CMIS serves?")
                .with_default(false)
                .with_help_message(
                    "only if CMIS rotated its key — compare with `ferrogate enrollment-key`",
                )
                .prompt()?;
            anyhow::ensure!(replace, "kept the installed key; nothing written");
            ak::plan(key_path, &fetched, None, true)?
        }
    };
    ak::commit(&plan)?;
    let fp = plan.fingerprint();
    Ok(match plan.change() {
        Change::New => format!("installed {} — fingerprint {fp}", key_path.display()),
        Change::Unchanged => format!(
            "{} already holds this key — fingerprint {fp}",
            key_path.display()
        ),
        Change::Rotate { previous } => format!(
            "replaced {} ({} → {}) — fingerprint {fp}",
            key_path.display(),
            ak::short(previous),
            ak::short(fp)
        ),
    })
}

/// The platform-appropriate service-restart hint shown after writing (Linux).
#[cfg(target_os = "linux")]
pub(crate) fn restart_hint() -> &'static str {
    "sudo systemctl restart mia"
}

/// The service-restart hint (macOS launchd).
#[cfg(target_os = "macos")]
pub(crate) fn restart_hint() -> &'static str {
    "sudo launchctl kickstart -k system/com.ferrogate.mia"
}

/// The service-restart hint (Windows service control).
#[cfg(windows)]
pub(crate) fn restart_hint() -> &'static str {
    "Restart-Service mia  (or: sc stop mia && sc start mia)"
}

/// The service-restart hint (other platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn restart_hint() -> &'static str {
    "restart the mia service"
}

/// The argv that signals the running agent to reload its allowlist (SIGHUP)
/// without restarting it, so the helper socket never goes down. `None` on
/// platforms with no signal-reload path (Windows: no SIGHUP). The daemon must
/// be a build that handles SIGHUP — older builds treat it as terminate and the
/// supervisor simply restarts them (a degraded but safe fallback).
#[cfg(target_os = "linux")]
pub(crate) fn reload_command() -> Option<&'static [&'static str]> {
    Some(&["systemctl", "kill", "-s", "HUP", "mia"])
}

/// The reload command (macOS launchd).
#[cfg(target_os = "macos")]
pub(crate) fn reload_command() -> Option<&'static [&'static str]> {
    Some(&["launchctl", "kill", "HUP", "system/com.ferrogate.mia"])
}

/// The reload command (Windows — no SIGHUP, so none).
#[cfg(windows)]
pub(crate) fn reload_command() -> Option<&'static [&'static str]> {
    None
}

/// The reload command (other platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn reload_command() -> Option<&'static [&'static str]> {
    None
}

// ── Field validators ────────────────────────────────────────────────────────
//
// One implementation per field, shared by the interactive prompts (wrapped as
// `inquire` validators below) and by `mia setup --check/--apply` (feature
// F18), so the two front ends accept exactly the same values with the same
// error text. Each takes the raw answer; blank means "unset" and is valid.

/// Longest free-text answer accepted (paths, names, URLs).
pub(crate) const MAX_ANSWER_LEN: usize = 4096;

/// Every answer is written as a TOML *literal* string (`'…'`), which cannot
/// contain a `'` or a line break — so reject those (and other control
/// characters) instead of emitting a broken or key-injecting file.
pub(crate) fn check_literal(input: &str) -> Result<(), String> {
    if input.len() > MAX_ANSWER_LEN {
        return Err(format!("too long (at most {MAX_ANSWER_LEN} bytes)"));
    }
    if input.contains('\'') || input.chars().any(char::is_control) {
        return Err("must not contain a single quote (') or control characters".into());
    }
    Ok(())
}

/// A DNS SRV owner name (contains a dot), or blank.
pub(crate) fn check_srv(input: &str) -> Result<(), String> {
    check_literal(input)?;
    let t = input.trim();
    if t.is_empty() || t.contains('.') {
        Ok(())
    } else {
        Err("an SRV owner name, e.g. _cmis._tcp.example.com".into())
    }
}

/// An `https://` / `http://` endpoint URL, or blank.
pub(crate) fn check_endpoint(input: &str) -> Result<(), String> {
    check_literal(input)?;
    let t = input.trim();
    if t.is_empty() || t.starts_with("https://") || t.starts_with("http://") {
        Ok(())
    } else {
        Err("must start with https:// or http:// (or be left blank)".into())
    }
}

/// A lowercase-hex SHA-384 SPKI pin, or blank.
pub(crate) fn check_pin(input: &str) -> Result<(), String> {
    let t = input.trim();
    if t.is_empty() || SpkiPin::from_hex(t).is_ok() {
        Ok(())
    } else {
        Err("must be a lowercase-hex SHA-384 (96 hex chars), or blank".into())
    }
}

/// An octal file mode (e.g. `660`, `0o640`), or blank.
pub(crate) fn check_octal(input: &str) -> Result<(), String> {
    let raw = input.trim();
    let t = raw.trim_start_matches("0o");
    if raw.is_empty() || (!t.is_empty() && u32::from_str_radix(t, 8).is_ok()) {
        Ok(())
    } else {
        Err("not an octal mode (e.g. 660)".into())
    }
}

/// A whole number of seconds that fits the config's signed 64-bit field, or
/// blank.
pub(crate) fn check_uint(input: &str) -> Result<(), String> {
    let t = input.trim();
    if t.is_empty() || t.parse::<u64>().is_ok_and(|n| i64::try_from(n).is_ok()) {
        Ok(())
    } else {
        Err("must be a whole number of seconds".into())
    }
}

/// Adapt a shared check into an `inquire` validation result.
fn to_validation(r: Result<(), String>) -> Result<Validation, inquire::CustomUserError> {
    Ok(match r {
        Ok(()) => Validation::Valid,
        Err(msg) => Validation::Invalid(msg.into()),
    })
}

/// An octal-mode validator (e.g. `660`, `0o640`).
// Only the non-Windows socket-mode prompt uses this; `test` keeps it compiled
// for the platform-independent validator tests below.
#[cfg(any(not(windows), test))]
fn octal_validator(input: &str) -> Result<Validation, inquire::CustomUserError> {
    to_validation(check_octal(input))
}

/// An unsigned-integer validator (seconds).
fn uint_validator(input: &str) -> Result<Validation, inquire::CustomUserError> {
    to_validation(check_uint(input))
}

/// A free-text validator (paths, names): see [`check_literal`].
fn literal_validator(input: &str) -> Result<Validation, inquire::CustomUserError> {
    to_validation(check_literal(input))
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
pub(crate) fn load_existing(path: &Path) -> Config {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| Config::from_toml(&t).ok())
        .unwrap_or_default()
}

/// Render the documented, self-commenting TOML config file. Keys the operator
/// set are active assignments; everything else stays as a commented template
/// line so the file remains a reference.
#[allow(clippy::too_many_lines)] // a flat sequence of TOML-emitting blocks.
pub(crate) fn render(
    s: &Settings,
    environment: Option<&str>,
    selected_default: Option<&str>,
) -> String {
    use std::fmt::Write as _;

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
    out.push_str("# SPKI; http:// is plaintext bring-up only. Mutually exclusive with `srv`.\n");
    out.push_str(&str_line(
        s.cmis_endpoint.as_deref(),
        "endpoint",
        "https://cmis.example.com:8443",
    ));
    out.push_str(
        "# DNS SRV record advertising a CMIS HA cluster (alternative to `endpoint`).\n\
         # The agent resolves it, prefers records by priority/weight, dials the best\n\
         # live node, and fails over automatically. The pin below authenticates them all.\n",
    );
    out.push_str(&str_line(
        s.cmis_srv.as_deref(),
        "srv",
        "_cmis._tcp.example.com",
    ));
    out.push_str("# Accepted CMIS SPKI pin (lowercase-hex SHA-384).\n");
    out.push_str(&str_line(
        s.cmis_spki_pin.as_deref(),
        "spki_pin",
        "<hex-sha384>",
    ));
    out.push('\n');

    out.push_str("[helper]\n");
    out.push_str("# Serve the local helper API. Default: true. Set false to switch it off\n");
    out.push_str("# (leaving `socket` unset does not disable it).\n");
    out.push_str(if s.helper_enable == Some(false) {
        "enable = false\n"
    } else {
        "#enable = true\n"
    });
    out.push_str("# Listener address: a Unix socket path (Linux/macOS) or a named-pipe name\n");
    out.push_str("# (Windows). Default: the platform path for this environment, shown here —\n");
    out.push_str("# the well-known address if it is the host's default environment\n");
    out.push_str("# (environments.toml / FERROGATE_DEFAULT_ENVIRONMENT).\n");
    out.push_str(&str_line(
        s.helper_socket.as_deref(),
        "socket",
        &default_socket(environment, selected_default),
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
    let c = &s.carried;
    if c.helper_socket_gid.is_some() || c.helper_require_authenticode.is_some() {
        out.push_str("# Kept from the previous file (not edited by `mia setup`).\n");
        if let Some(gid) = &c.helper_socket_gid {
            let _ = writeln!(out, "socket_gid = {}", basic_str(gid));
        }
        if let Some(b) = c.helper_require_authenticode {
            let _ = writeln!(out, "require_authenticode = {b}");
        }
    }
    out.push('\n');

    out.push_str("[allowlist]\n");
    out.push_str("# Signed CBOR allowlist of vetted local callers. Default: the platform path\n");
    out.push_str("# for this environment, shown here. A missing, stale or unverifiable file\n");
    out.push_str("# denies every caller (fail closed).\n");
    out.push_str(&str_line(
        s.allowlist.as_deref(),
        "path",
        &crate::config::default_allowlist_path(environment)
            .display()
            .to_string(),
    ));
    out.push_str("# Trusted CMIS enrollment public key used to verify the allowlist. No\n");
    out.push_str(
        "# default: without it every caller is denied. Required whenever `path` is set.\n",
    );
    out.push_str(&str_line(
        s.allowlist_key.as_deref(),
        "key",
        &dist_sibling(&env_filename("allowlist.pub", environment)),
    ));
    out.push_str("# Maximum accepted allowlist age in seconds. Default: 86400.\n");
    out.push_str(&int_line(
        s.allowlist_max_age.as_deref(),
        "max_age_secs",
        "86400",
    ));
    out.push_str(
        "# Fetch this host's allowlist from CMIS at startup (by EK-UUID) and write it\n\
         # to `path` before loading. Needs a cmis source (endpoint or srv) + spki_pin.\n\
         # Default: false.\n",
    );
    if s.allowlist_fetch {
        out.push_str("fetch = true\n");
    } else {
        out.push_str("#fetch = false\n");
    }
    out.push_str(
        "# Propose the local callers this host observes (granted and denied) to CMIS\n\
         # periodically. CMIS auto-adopts the first proposal on a host with no\n\
         # allowlist (bootstrap/TOFU) or queues it for operator review. Needs a\n\
         # cmis source (endpoint or srv) + spki_pin and a host SVID. Default: false.\n",
    );
    if s.allowlist_propose {
        out.push_str("propose = true\n");
    } else {
        out.push_str("#propose = false\n");
    }
    if let Some(n) = c.allowlist_propose_interval_secs {
        out.push_str("# Kept from the previous file (not edited by `mia setup`).\n");
        let _ = writeln!(out, "propose_interval_secs = {n}");
    }
    out.push('\n');

    out.push_str("[attestation]\n");
    out.push_str("# Linux only. Override the IMA runtime-measurement log path.\n");
    out.push_str(&str_line(s.ima_log.as_deref(), "ima_log", DEFAULT_IMA_LOG));
    out.push_str(
        "# Attestation backend: auto (default: TPM when usable, else host-key), tpm,\n\
         # host-key, or virtual-tpm (INSECURE, dev/test builds only).\n",
    );
    out.push_str(&str_line(
        s.attestation_backend.as_deref(),
        "backend",
        "auto",
    ));
    render_carried_tail(&mut out, c);

    out
}

/// Emit the carried-over `[attestation.tpm]` and `[status]` tables, if the
/// edited file had them. Nothing is emitted otherwise, so files without them
/// render exactly as before.
fn render_carried_tail(out: &mut String, c: &Carried) {
    use std::fmt::Write as _;
    if c.tpm_ek_cert.is_some() || !c.tpm_ek_intermediates.is_empty() {
        out.push_str("\n# Kept from the previous file (not edited by `mia setup`).\n");
        out.push_str("[attestation.tpm]\n");
        if let Some(cert) = &c.tpm_ek_cert {
            let _ = writeln!(out, "ek_cert = {}", basic_str(cert));
        }
        if !c.tpm_ek_intermediates.is_empty() {
            let list: Vec<String> = c
                .tpm_ek_intermediates
                .iter()
                .map(|p| basic_str(p))
                .collect();
            let _ = writeln!(out, "ek_intermediates = [{}]", list.join(", "));
        }
    }
    let st = &c.status;
    if *st != crate::config::StatusConfig::default() {
        out.push_str("\n# Kept from the previous file (not edited by `mia setup`).\n");
        out.push_str("[status]\n");
        if let Some(v) = st.enable {
            let _ = writeln!(out, "enable = {v}");
        }
        if let Some(v) = &st.socket {
            let _ = writeln!(out, "socket = {}", basic_str(&v.display().to_string()));
        }
        if let Some(v) = &st.socket_gid {
            let _ = writeln!(out, "socket_gid = {}", basic_str(v));
        }
        if let Some(v) = &st.group {
            let _ = writeln!(out, "group = {}", basic_str(v));
        }
        if let Some(v) = st.rate_limit_per_sec {
            let _ = writeln!(out, "rate_limit_per_sec = {v}");
        }
        if let Some(v) = st.log_buffer_records {
            let _ = writeln!(out, "log_buffer_records = {v}");
        }
        if let Some(v) = st.log_buffer_bytes {
            let _ = writeln!(out, "log_buffer_bytes = {v}");
        }
    }
}

/// A TOML *basic* string (`"…"`) with the required escapes — used for values
/// carried over from an existing file, which (unlike wizard answers) may hold
/// any character.
fn basic_str(v: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for ch in v.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
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

const USAGE: &str =
    "usage: mia setup [--user] [--environment <env>] [--output <path>] [--force] [--clean]\n\
     \x20      mia setup --check <draft> | --apply <draft> [--reload]\n\
     \x20                [--fetch-enrollment-key [--expect-fingerprint <hex>]] | --dump [--json]";

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
         \x20 -e, --environment <env>  write mia-<env>.toml instead of mia.toml (for\n\
         \x20                       side-by-side deployments); composes with --user,\n\
         \x20                       excludes --output\n\
         \x20 -o, --output <path>   target a specific path\n\
         \x20 -c, --clean           delete the stored configuration\n\
         \x20 -f, --force           skip the confirmation prompt (write or clean)\n\
         \x20 -h, --help            show this help\n\
         \n\
         non-interactive modes (no TTY needed; used by the mia-tray wizard):\n\
         \x20 --check <draft>       validate a draft (the wizard's keys only) and exit\n\
         \x20 --apply <draft>       validate, then write the config atomically (same\n\
         \x20                       file the wizard would write), audit a ConfigChanged\n\
         \x20                       event and delete the draft; honours --user /\n\
         \x20                       --output / --environment\n\
         \x20   --reload            then signal the running agent to reload\n\
         \x20   --fetch-enrollment-key  then fetch the CMIS enrollment key into\n\
         \x20                       allowlist.key over the pinned channel\n\
         \x20   --expect-fingerprint <hex>  require that fetch to match the 96-hex\n\
         \x20                       fingerprint from `ferrogate enrollment-key`\n\
         \x20 --dump                print the effective values, the file path and which\n\
         \x20                       keys come from environment variables\n\
         \x20 --json                machine-readable output for --check/--apply/--dump\n",
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
        let out = render(&s, None, None);
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
    fn env_filename_suffixes_before_extension() {
        // No environment ⇒ unchanged.
        assert_eq!(env_filename("allowlist.cbor", None), "allowlist.cbor");
        // With an environment ⇒ inserted before the extension.
        assert_eq!(
            env_filename("allowlist.cbor", Some("staging")),
            "allowlist-staging.cbor"
        );
        assert_eq!(env_filename("mia.sock", Some("prod")), "mia-prod.sock");
        // No extension ⇒ appended.
        assert_eq!(
            env_filename("ferrogate-mia", Some("qa")),
            "ferrogate-mia-qa"
        );
    }

    #[test]
    fn listener_defaults_follow_the_default_environment() {
        use crate::default_env::DefaultSelection;
        let unset = DefaultSelection::unset();
        let prod = DefaultSelection::resolve(
            Path::new("/nonexistent/environments.toml"),
            Some("prod".into()),
        )
        .unwrap();
        let well_known = crate::config::default_helper_socket(None);
        let wk = well_known.display().to_string();

        // No selection: mia.toml's default is the well-known address, and
        // accepting the suggestion leaves helper.socket unset.
        let l = ListenerDefaults::new(None, &unset);
        assert_eq!(l.default, well_known);
        assert!(l.check(&wk).is_ok());
        assert_eq!(l.normalize(Some(wk.clone())), None);
        assert_eq!(
            l.normalize(Some("/tmp/x.sock".into())),
            Some("/tmp/x.sock".into())
        );

        // prod selected: prod is offered the well-known address…
        let l = ListenerDefaults::new(Some("prod"), &prod);
        assert_eq!(l.default, well_known);
        assert!(l.check(&wk).is_ok());
        // …and mia.toml yields: it may not claim it, and is told why.
        let l = ListenerDefaults::new(None, &prod);
        assert_eq!(l.default, crate::config::yielded_helper_socket());
        assert!(l.check(&wk).is_err());
        assert!(l.check("").is_ok());
        assert!(l.note.contains("`prod`"), "{}", l.note);

        // The rendered placeholder is the address the daemon would bind.
        let out = render(&Settings::default(), None, Some("prod"));
        let expected = format!(
            "#socket = '{}'",
            crate::config::yielded_helper_socket().display()
        );
        assert!(out.contains(&expected), "{out}");
    }

    #[test]
    fn default_socket_is_environment_scoped() {
        // The default-environment socket is unsuffixed; a selector suffixes it
        // so two daemons don't bind the same path.
        let default = default_socket(None, None);
        let staging = default_socket(Some("staging"), None);
        assert_ne!(default, staging);
        assert!(staging.contains("staging"));
        // The wizard suggests exactly what the daemon binds when unset.
        assert_eq!(
            Path::new(&staging),
            crate::config::default_helper_socket(Some("staging"))
        );
    }

    #[test]
    fn render_writes_the_helper_switch_only_when_off() {
        // Default (on): a commented placeholder; the file parses as enabled
        // and serves the default socket.
        let on = render(&Settings::default(), None, None);
        assert!(on.contains("\n#enable = true\n"), "{on}");
        let parsed = Config::from_toml(&on).unwrap();
        assert!(parsed.helper_enabled());
        assert_eq!(
            parsed.helper_socket(),
            Some(crate::config::default_helper_socket(None))
        );
        // An explicit true is the default too.
        let s = Settings {
            helper_enable: Some(true),
            ..Settings::default()
        };
        assert_eq!(render(&s, None, None), on);
        // Off: written as an active key, and the file parses as disabled.
        let s = Settings {
            helper_enable: Some(false),
            ..Settings::default()
        };
        let off = render(&s, None, None);
        assert!(off.contains("\nenable = false\n"), "{off}");
        let parsed = Config::from_toml(&off).unwrap();
        assert!(!parsed.helper_enabled());
        assert_eq!(parsed.helper_socket(), None);
    }

    #[test]
    fn render_environment_scopes_the_socket_placeholder() {
        // With a selector and no explicit socket, the commented placeholder
        // carries the env-suffixed default.
        let out = render(&Settings::default(), Some("staging"), None);
        assert!(out.contains("staging"), "{out}");
    }

    #[test]
    fn render_leaves_the_default_allowlist_path_unset() {
        use crate::config::default_allowlist_path;
        for env in [None, Some("staging")] {
            let out = render(&Settings::default(), env, None);
            let default = default_allowlist_path(env).display().to_string();
            // Only a commented placeholder showing this environment's default.
            assert!(out.contains(&format!("\n#path = '{default}'\n")), "{out}");
            let parsed = Config::from_toml(&out).unwrap();
            assert_eq!(parsed.allowlist.path, None);
            assert!(parsed.allowlist_path_is_default());
            // The key stays a placeholder too: no trust anchor is invented.
            assert_eq!(parsed.allowlist_key(), None);
        }
    }

    #[test]
    fn the_wizard_does_not_write_the_default_allowlist_path() {
        use crate::config::default_allowlist_path;
        let default = default_allowlist_path(None).display().to_string();
        let staging = default_allowlist_path(Some("staging"))
            .display()
            .to_string();
        // Accepting the suggested default (or leaving it blank) writes nothing.
        assert_eq!(allowlist_path_setting(Some(default.clone()), None), None);
        assert_eq!(allowlist_path_setting(None, None), None);
        assert_eq!(
            allowlist_path_setting(Some(staging.clone()), Some("staging")),
            None
        );
        // Anything else — including another environment's default — is kept.
        assert_eq!(
            allowlist_path_setting(Some(default.clone()), Some("staging")),
            Some(default)
        );
        assert_eq!(
            allowlist_path_setting(Some("/srv/al.cbor".into()), None),
            Some("/srv/al.cbor".into())
        );
        // And what is written renders as an active key.
        let s = Settings {
            allowlist: allowlist_path_setting(Some("/srv/al.cbor".into()), None),
            allowlist_key: Some("/srv/al.pub".into()),
            ..Settings::default()
        };
        let parsed = Config::from_toml(&render(&s, None, None)).unwrap();
        assert_eq!(parsed.allowlist_path(), Path::new("/srv/al.cbor"));
    }

    #[test]
    fn render_carries_keys_the_wizard_does_not_edit() {
        // A rewrite must not drop keys the wizard never asks about — in
        // particular the [status] section (feature F18) — and must quote
        // carried values safely, whatever characters they hold.
        let existing = Config::from_toml(
            "[helper]\nsocket_gid = '991'\nrequire_authenticode = false\n\
             [allowlist]\npropose_interval_secs = 60\n\
             [attestation.tpm]\nek_cert = \"/etc/ek \\\"q\\\".der\"\nek_intermediates = ['/a', '/b']\n\
             [status]\nsocket_gid = '992'\nrate_limit_per_sec = 3\nlog_buffer_records = 0\n",
        )
        .unwrap();
        let s = Settings {
            attestation_backend: backend_setting("tpm"),
            carried: Carried::from_existing(&existing),
            ..Settings::default()
        };
        let out = render(&s, None, None);
        let back = Config::from_toml(&out).expect("rendered TOML parses");
        assert_eq!(back.helper.socket_gid.as_deref(), Some("991"));
        assert_eq!(back.helper.require_authenticode, Some(false));
        assert_eq!(back.allowlist.propose_interval_secs, Some(60));
        assert_eq!(back.attestation.tpm, existing.attestation.tpm);
        assert_eq!(back.status, existing.status);
        assert_eq!(back.attestation.backend, crate::config::AttestBackend::Tpm);
        // Nothing carried ⇒ none of the extra tables appear.
        let plain = render(&Settings::default(), None, None);
        assert!(!plain.contains("[status]") && !plain.contains("[attestation.tpm]"));
        assert!(plain.contains("#backend = 'auto'"));
    }

    #[test]
    fn literal_check_rejects_quote_and_control_injection() {
        assert!(check_literal("/run/ferrogate/mia.sock").is_ok());
        assert!(check_literal("info'\n[cmis]").is_err());
        assert!(check_literal("a\u{7}b").is_err());
        assert!(check_literal(&"x".repeat(MAX_ANSWER_LEN + 1)).is_err());
        assert!(check_endpoint("https://x\n").is_err());
        assert!(check_octal("0o").is_err());
        assert!(check_octal("").is_ok());
        assert!(check_octal("0o640").is_ok());
    }

    #[test]
    fn non_empty_trims_and_nullifies_blank() {
        assert_eq!(non_empty("  x ".into()), Some("x".into()));
        assert_eq!(non_empty("   ".into()), None);
    }
}
