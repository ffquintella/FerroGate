//! `mia setup` — interactive configuration wizard.
//!
//! A guided, rich-terminal wizard (built on [`inquire`]) that walks an operator
//! through configuring the Machine Identity Agent and writes the result to the
//! environment file the systemd unit reads (`/etc/ferrogate/mia.env` by
//! default, overridable with `--output`).
//!
//! The agent itself is configured entirely by environment variable (see
//! [`crate`] docs and `docs/mia.md`); this wizard simply produces that file in
//! the documented, self-commenting template form. Running it against an
//! existing file pre-fills every prompt with the current value, so it doubles
//! as an editor.
//!
//! The wizard is interactive only: it requires a TTY. In non-interactive
//! contexts (CI, `EnvironmentFile` provisioning by configuration management)
//! write `mia.env` directly from the documented template instead.
//!
//! `unsafe` is forbidden in this crate; `inquire` performs all terminal I/O.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use inquire::validator::Validation;
use inquire::{Confirm, Text};

/// Default destination — the path the packaged systemd unit reads as its
/// `EnvironmentFile` (see `crates/mia/dist/mia.service`).
const DEFAULT_OUTPUT: &str = "/etc/ferrogate/mia.env";

/// Standard Linux IMA runtime-measurement log, offered as the default when the
/// operator opts into overriding it.
const DEFAULT_IMA_LOG: &str = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements";

/// Run the `mia setup` subcommand. `args` is everything after `setup` on the
/// command line.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut force = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "-o" | "--output" => {
                let path = it.next().context("--output requires a path argument")?;
                output = PathBuf::from(path);
            }
            "-f" | "--force" => force = true,
            other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }

    // A wizard with no TTY would deadlock or error obscurely; fail with a clear
    // message and point at the non-interactive path instead.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "`mia setup` is interactive and needs a terminal (no TTY detected).\n\
             For unattended provisioning, write {DEFAULT_OUTPUT} from the template in \
             crates/mia/dist/mia.env (or `docs/mia.md`)."
        );
    }

    println!("FerroGate Machine Identity Agent — setup");
    println!("Configuring: {}", output.display());
    if output.exists() {
        println!("(existing file found — prompts are pre-filled with its current values)");
    }
    println!("Press Esc at any prompt to abort without writing.\n");

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

    let proceed = match Confirm::new(&format!(
        "Write this configuration to {}?",
        output.display()
    ))
    .with_default(true)
    .prompt()
    {
        Ok(v) => v,
        // Esc / Ctrl-C at the final gate ⇒ abort cleanly.
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => false,
        Err(e) => return Err(e.into()),
    };
    if !proceed {
        println!("Aborted — no changes written.");
        return Ok(());
    }

    write_file(&output, &rendered, force)?;
    println!("\n✓ Wrote {}", output.display());
    println!("  Review it, then (re)start the agent:  sudo systemctl restart mia");
    Ok(())
}

/// The collected configuration. `None` ⇒ the key is left as a commented
/// template placeholder rather than an active assignment.
#[derive(Default)]
struct Settings {
    rust_log: Option<String>,
    cmis_endpoint: Option<String>,
    cmis_spki_pin: Option<String>,
    helper_socket: Option<String>,
    helper_socket_mode: Option<String>,
    allowlist: Option<String>,
    allowlist_key: Option<String>,
    allowlist_max_age: Option<String>,
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

/// Drive every prompt section, seeding defaults from `existing`.
fn prompt_all(existing: &BTreeMap<String, String>) -> Result<Settings, WizardError> {
    let mut s = Settings::default();
    let get = |k: &str| existing.get(k).cloned();

    // ── Logging ───────────────────────────────────────────────────────────
    let rust_log = Text::new("Log verbosity (tracing EnvFilter syntax):")
        .with_default(&get("RUST_LOG").unwrap_or_else(|| "info".into()))
        .with_help_message("e.g. info, debug, mia=debug,info")
        .prompt()?;
    s.rust_log = non_empty(rust_log);

    // ── CMIS connection (the server to attest to) ───────────────────────────
    println!("\n— CMIS server (the Central Machine Identity Service to connect to) —");
    let endpoint = Text::new("CMIS endpoint URL:")
        .with_default(&get("FERROGATE_CMIS_ENDPOINT").unwrap_or_default())
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
        let pin = Text::new("CMIS SPKI pin (SHA-384, base64):")
            .with_default(&get("FERROGATE_CMIS_SPKI_PIN").unwrap_or_default())
            .with_help_message("leave blank to pin from a server cert PEM at deploy time")
            .prompt()?;
        s.cmis_spki_pin = non_empty(pin);
    }

    // ── Helper API (the daemon's local serving surface) ──────────────────────
    println!("\n— Helper API (local socket the daemon serves; enables daemon mode) —");
    let enable_helper = Confirm::new("Enable the local helper API?")
        .with_default(get("FERROGATE_HELPER_SOCKET").is_some())
        .with_help_message("the agent serves DPoP-bound child tokens to vetted local callers")
        .prompt()?;
    if enable_helper {
        let socket = Text::new("Helper socket path:")
            .with_default(
                &get("FERROGATE_HELPER_SOCKET").unwrap_or_else(|| "/run/ferrogate/mia.sock".into()),
            )
            .prompt()?;
        s.helper_socket = non_empty(socket);

        let mode = Text::new("Helper socket mode (octal):")
            .with_default(&get("FERROGATE_HELPER_SOCKET_MODE").unwrap_or_else(|| "660".into()))
            .with_validator(octal_validator)
            .prompt()?;
        s.helper_socket_mode = non_empty(mode);
    }

    // ── Allowlist ────────────────────────────────────────────────────────────
    println!("\n— Caller allowlist (signed list of vetted local callers) —");
    let configure_allowlist = Confirm::new("Configure a signed caller allowlist?")
        .with_default(get("FERROGATE_ALLOWLIST").is_some())
        .with_help_message("absent ⇒ the helper API denies every caller (fail closed)")
        .prompt()?;
    if configure_allowlist {
        let path = Text::new("Allowlist path (signed CBOR):")
            .with_default(
                &get("FERROGATE_ALLOWLIST")
                    .unwrap_or_else(|| "/etc/ferrogate/allowlist.cbor".into()),
            )
            .prompt()?;
        s.allowlist = non_empty(path);

        let key = Text::new("Allowlist verification key (CMIS enrollment pubkey):")
            .with_default(
                &get("FERROGATE_ALLOWLIST_KEY")
                    .unwrap_or_else(|| "/etc/ferrogate/allowlist.pub".into()),
            )
            .prompt()?;
        s.allowlist_key = non_empty(key);

        let age = Text::new("Maximum accepted allowlist age (seconds):")
            .with_default(
                &get("FERROGATE_ALLOWLIST_MAX_AGE_SECS").unwrap_or_else(|| "86400".into()),
            )
            .with_validator(uint_validator)
            .prompt()?;
        s.allowlist_max_age = non_empty(age);
    }

    // ── Attestation ────────────────────────────────────────────────────────
    println!("\n— Attestation —");
    let override_ima = Confirm::new("Override the IMA runtime-measurement log path?")
        .with_default(get("FERROGATE_IMA_LOG").is_some())
        .with_help_message("only needed if your kernel exposes IMA at a non-standard path")
        .prompt()?;
    if override_ima {
        let ima = Text::new("IMA log path:")
            .with_default(&get("FERROGATE_IMA_LOG").unwrap_or_else(|| DEFAULT_IMA_LOG.into()))
            .prompt()?;
        s.ima_log = non_empty(ima);
    }

    Ok(s)
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

/// Parse `KEY=VALUE` lines from an existing env file, ignoring blanks and
/// comments. Tolerant of `export ` prefixes and surrounding quotes.
fn load_existing(path: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return map;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            map.insert(k.trim().to_string(), v.to_string());
        }
    }
    map
}

/// Render the documented, self-commenting env file. Keys the operator set are
/// active assignments; everything else stays as a commented template line so
/// the file remains a reference.
fn render(s: &Settings) -> String {
    // Emit an active `KEY=value` line when set, else a commented placeholder.
    fn line(set: Option<&str>, key: &str, placeholder: &str) -> String {
        match set {
            Some(v) => format!("{key}={v}\n"),
            None => format!("#{key}={placeholder}\n"),
        }
    }

    let mut out = String::new();
    out.push_str(
        "# FerroGate Machine Identity Agent (MIA) configuration.\n\
         #\n\
         # Generated by `mia setup`. Read by the systemd unit as an\n\
         # EnvironmentFile. Re-run `mia setup` to edit, or hand-edit and\n\
         # `systemctl restart mia`. See docs/mia.md for the full reference.\n\n",
    );

    out.push_str("# Tracing verbosity (tracing EnvFilter syntax). Default: info.\n");
    out.push_str(&line(s.rust_log.as_deref(), "RUST_LOG", "info"));
    out.push('\n');

    out.push_str(
        "# --- CMIS server ------------------------------------------------------------\n",
    );
    out.push_str("# CMIS endpoint. An https:// URL is dialed over hybrid-PQC TLS, pinned by\n");
    out.push_str("# SPKI; http:// is plaintext bring-up only.\n");
    out.push_str(&line(
        s.cmis_endpoint.as_deref(),
        "FERROGATE_CMIS_ENDPOINT",
        "https://cmis.example.com:8443",
    ));
    out.push_str("# Accepted CMIS SPKI pin (SHA-384, base64).\n");
    out.push_str(&line(
        s.cmis_spki_pin.as_deref(),
        "FERROGATE_CMIS_SPKI_PIN",
        "<base64-sha384>",
    ));
    out.push('\n');

    out.push_str(
        "# --- Helper API (feature F08) -----------------------------------------------\n",
    );
    out.push_str("# Path to the local helper-API Unix socket. Its presence ENABLES the helper\n");
    out.push_str("# API; if unset, MIA logs a banner and exits.\n");
    out.push_str(&line(
        s.helper_socket.as_deref(),
        "FERROGATE_HELPER_SOCKET",
        "/run/ferrogate/mia.sock",
    ));
    out.push_str("# Octal mode for the helper socket. Default: 660.\n");
    out.push_str(&line(
        s.helper_socket_mode.as_deref(),
        "FERROGATE_HELPER_SOCKET_MODE",
        "660",
    ));
    out.push('\n');

    out.push_str(
        "# --- Allowlist --------------------------------------------------------------\n",
    );
    out.push_str("# Signed CBOR allowlist of vetted local callers. Absent => deny every caller.\n");
    out.push_str(&line(
        s.allowlist.as_deref(),
        "FERROGATE_ALLOWLIST",
        "/etc/ferrogate/allowlist.cbor",
    ));
    out.push_str("# Trusted CMIS enrollment public key used to verify the allowlist. Required\n");
    out.push_str("# whenever FERROGATE_ALLOWLIST is set.\n");
    out.push_str(&line(
        s.allowlist_key.as_deref(),
        "FERROGATE_ALLOWLIST_KEY",
        "/etc/ferrogate/allowlist.pub",
    ));
    out.push_str("# Maximum accepted allowlist age in seconds. Default: 86400.\n");
    out.push_str(&line(
        s.allowlist_max_age.as_deref(),
        "FERROGATE_ALLOWLIST_MAX_AGE_SECS",
        "86400",
    ));
    out.push('\n');

    out.push_str(
        "# --- Attestation ------------------------------------------------------------\n",
    );
    out.push_str("# Override the IMA runtime-measurement log path.\n");
    out.push_str(&line(
        s.ima_log.as_deref(),
        "FERROGATE_IMA_LOG",
        DEFAULT_IMA_LOG,
    ));

    out
}

/// Write `content` to `path`, creating parent directories. Refuses to clobber
/// an existing file unless `force`, after the caller already confirmed intent.
fn write_file(path: &Path, content: &str, force: bool) -> anyhow::Result<()> {
    if path.exists() && !force {
        // The interactive Confirm already gave consent to write; this guard
        // only trips for `--output` onto a different pre-existing file the user
        // didn't expect. Re-confirm overwrite explicitly.
        let overwrite = Confirm::new(&format!("{} exists — overwrite?", path.display()))
            .with_default(false)
            .prompt()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if !overwrite {
            anyhow::bail!(
                "not overwriting {} (pass --force to skip this check)",
                path.display()
            );
        }
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(path, content).with_context(|| {
        format!(
            "writing {} (the default lives under /etc — re-run with `sudo` if this is a \
             permission error, or use --output to write elsewhere)",
            path.display()
        )
    })?;
    Ok(())
}

const USAGE: &str = "usage: mia setup [--output <path>] [--force]";

fn print_help() {
    println!(
        "mia setup — interactive configuration wizard\n\
         \n\
         {USAGE}\n\
         \n\
         Walks you through configuring the Machine Identity Agent (CMIS server,\n\
         helper API, allowlist, attestation, logging) and writes the systemd\n\
         EnvironmentFile. Pre-fills prompts from an existing file.\n\
         \n\
         options:\n\
         \x20 -o, --output <path>   destination env file (default {DEFAULT_OUTPUT})\n\
         \x20 -f, --force           overwrite an existing file without the extra prompt\n\
         \x20 -h, --help            show this help\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_existing_parses_kv_and_ignores_comments() {
        let dir = std::env::temp_dir().join(format!("mia-setup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mia.env");
        std::fs::write(
            &path,
            "# comment\nRUST_LOG=debug\nexport FERROGATE_HELPER_SOCKET=\"/run/x.sock\"\n\n#KEY=skip\n",
        )
        .unwrap();
        let map = load_existing(&path);
        assert_eq!(map.get("RUST_LOG").map(String::as_str), Some("debug"));
        assert_eq!(
            map.get("FERROGATE_HELPER_SOCKET").map(String::as_str),
            Some("/run/x.sock")
        );
        assert!(!map.contains_key("KEY"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_emits_active_and_commented_lines() {
        let s = Settings {
            rust_log: Some("info".into()),
            helper_socket: Some("/run/ferrogate/mia.sock".into()),
            ..Settings::default()
        };
        let out = render(&s);
        assert!(out.contains("\nRUST_LOG=info\n"));
        assert!(out.contains("\nFERROGATE_HELPER_SOCKET=/run/ferrogate/mia.sock\n"));
        // An unset key stays as a commented placeholder.
        assert!(out.contains("#FERROGATE_ALLOWLIST=/etc/ferrogate/allowlist.cbor\n"));
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
    fn non_empty_trims_and_nullifies_blank() {
        assert_eq!(non_empty("  x ".into()), Some("x".into()));
        assert_eq!(non_empty("   ".into()), None);
    }
}
