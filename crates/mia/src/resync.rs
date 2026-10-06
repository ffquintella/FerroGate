//! On-demand re-sync of a host's CMIS trust material — the client commands
//! `mia resync-allowlist`, `mia --resync` and `mia --reload`.
//!
//! - **`resync-allowlist`** re-fetches this host's signed caller allowlist. The
//!   daemon fetches it once at startup (when `allowlist.fetch` is set); this
//!   performs the **identical** fetch at any time — keyed by the same
//!   fingerprint-derived host UUID — writes the signed body to `allowlist.path`
//!   (or its per-environment default,
//!   [`Config::allowlist_path`](crate::config::Config::allowlist_path)),
//!   and verifies it against the locally pinned enrollment key so the operator
//!   gets immediate, authoritative feedback.
//! - The **enrollment key** that signs allowlists (`allowlist.key`) is
//!   installed by `mia allowlist-key fetch` ([`crate::allowlist_key`]); the
//!   former `mia refresh-key` is now a deprecated alias for it.
//!
//! The two compose: after a CMIS key rotation, `allowlist-key fetch --rotate`
//! then `resync-allowlist` re-establishes both halves of the allowlist trust
//! chain. `resync-allowlist --reload` (or `mia --reload`) signals the running
//! daemon (SIGHUP) to re-read the key and the body live — no restart, no
//! helper-socket downtime. Without `--reload`, the command prints the platform
//! restart hint.
//!
//! Like `mia setup`/`mia test`, these are client commands: no hardening profile,
//! no TPM, plain terminal output (no tracing).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use ferro_crypto::composite::CompositePublicKey;

use crate::config::Config;

const USAGE_RESYNC: &str =
    "usage: mia resync-allowlist [--config <path> | --environment <env>] [--reload]";
const USAGE_RELOAD: &str = "usage: mia --reload";

/// Run the top-level `mia --reload` command: signal the running agent (SIGHUP)
/// to re-read its configuration and signed allowlist live, without a restart, so
/// the helper socket never goes down. Unlike `resync-allowlist --reload`, this
/// fetches nothing — it only signals — so it is the right tool after editing the
/// local config file or dropping a new allowlist body in place by other means.
pub fn run_reload(args: &[String]) -> anyhow::Result<()> {
    if let Some(arg) = args.first() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help_reload();
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other}\n\n{USAGE_RELOAD}"),
        }
    }
    let Some(cmd) = crate::setup::reload_command() else {
        anyhow::bail!(
            "--reload is not supported on this platform (no SIGHUP); restart the agent instead:  {}",
            crate::setup::restart_hint()
        );
    };
    println!(
        "Signaling the running agent to reload its configuration and allowlist (SIGHUP via {}) …",
        cmd[0]
    );
    let status = std::process::Command::new(cmd[0])
        .args(&cmd[1..])
        .status()
        .with_context(|| format!("running `{}`", cmd[0]))?;
    if status.success() {
        println!(
            "✓ done — the agent re-read its configuration and signed allowlist live; the helper \
             socket stayed up."
        );
        Ok(())
    } else {
        anyhow::bail!(
            "reload command exited with {}; is mia running as a managed service? Otherwise restart \
             it to load changes:  {}",
            status
                .code()
                .map_or_else(|| "a signal".to_string(), |c| c.to_string()),
            crate::setup::restart_hint()
        )
    }
}

/// Run the `mia resync-allowlist` subcommand. `args` is everything after
/// `resync-allowlist` on the command line.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    // `--reload` is resync-only, so strip it before the shared option parser
    // (which rejects unknown flags) sees the rest.
    let mut reload = false;
    let rest: Vec<String> = args
        .iter()
        .filter(|a| {
            if a.as_str() == "--reload" {
                reload = true;
                false
            } else {
                true
            }
        })
        .cloned()
        .collect();
    let Some(config) = load(&rest, USAGE_RESYNC, print_help_resync, "allowlist resync")? else {
        return Ok(()); // --help printed
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(resync(&config, reload))
}

/// Run the top-level `mia --resync` command: the same fetch as
/// `resync-allowlist`, but with the live reload always on, so the running agent
/// picks up the freshly fetched allowlist without a restart. This is the
/// no-restart resync — `resync-allowlist` writes the body and (without
/// `--reload`) leaves the operator to restart; `--resync` writes it and signals
/// the agent (SIGHUP) in one shot.
pub fn run_resync(args: &[String]) -> anyhow::Result<()> {
    let Some(config) = load(args, USAGE_RESYNC, print_help_resync, "allowlist resync")? else {
        return Ok(()); // --help printed
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(resync(&config, true))
}

/// Run the deprecated `mia refresh-key` subcommand: forwards to
/// [`crate::allowlist_key::run_refresh_key`] (`mia allowlist-key fetch
/// --rotate --yes`), which is root-only, validated, atomic and audited.
#[deprecated(note = "use mia::allowlist_key::run_refresh_key (`mia allowlist-key fetch`)")]
pub fn run_refresh_key(args: &[String]) -> anyhow::Result<()> {
    crate::allowlist_key::run_refresh_key(args)
}

/// Parse the shared `[--config <path>]` / `--help` options and load the config,
/// printing a one-line banner. `Ok(None)` means `--help` was printed and the
/// caller should exit successfully.
fn load(
    args: &[String],
    usage: &str,
    help: fn(),
    banner: &str,
) -> anyhow::Result<Option<Config>> {
    let mut config_path = None;
    let mut environment = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                help();
                return Ok(None);
            }
            "-c" | "--config" => {
                let path = it.next().context("--config requires a path argument")?;
                config_path = Some(PathBuf::from(path));
            }
            "-e" | "--environment" => {
                let env = it.next().context("--environment requires a name argument")?;
                environment = Some(env.clone());
            }
            other => anyhow::bail!("unknown argument: {other}\n\n{usage}"),
        }
    }
    let (config, source) = Config::load(config_path.as_deref(), environment.as_deref())?;
    println!("FerroGate {banner} (mia {})", env!("CARGO_PKG_VERSION"));
    match &source {
        Some(path) => println!("config: {}", path.display()),
        None => println!("config: none found — using environment and defaults"),
    }
    Ok(Some(config))
}

/// Fetch the signed allowlist from CMIS, write it, and verify it. When `reload`
/// is set, signal the running agent to swap in the new body live (no restart).
async fn resync(config: &Config, reload: bool) -> anyhow::Result<()> {
    // `allowlist.path`, or its per-environment default — the same body the
    // daemon loads (`Config::allowlist_path`).
    let path = config.allowlist_path();
    let resolver = crate::endpoint::CmisResolver::from_config(&config.cmis)?
        .context("cmis is not configured (set cmis.endpoint or cmis.srv); run `mia setup`")?;

    // Derive this host's UUID locally from its hardware fingerprint — the same
    // identity the daemon's host-key attestation resolves to: CMIS keys a host's
    // allowlist under `host_uuid_from_ek_digest(fingerprint)` (feature F15). The
    // allowlist body is signature-protected, so fetching it needs no attestation
    // round-trip, only the right key.
    let facts =
        ferro_machineid::collect_facts().context("collecting this host's hardware fingerprint")?;
    let uuid = ferro_svid::host_uuid_from_ek_digest(facts.fingerprint().as_bytes()).to_string();
    println!("host: {uuid}\n");

    // Resolve + dial CMIS with fail-over (static endpoint or SRV-discovered HA
    // cluster); the chosen node is reported so the operator sees which served.
    let (endpoint, mut client) = resolver.connect().await.context("connecting to CMIS")?;
    if resolver.is_srv() {
        println!("cmis: {endpoint} (selected via SRV {})\n", resolver.describe());
    }

    let Some(bytes) = crate::client::fetch_allowlist(&mut client, &uuid)
        .await
        .context("fetching the signed allowlist from CMIS")?
    else {
        println!("CMIS has no allowlist for this host — nothing written.");
        println!(
            "  Provision callers on CMIS (`ferrogate allowlist set --host {uuid} …`), or enable\n  \
             allowlist.propose so the daemon proposes the callers it observes for approval."
        );
        anyhow::bail!("no allowlist available for this host");
    };

    // The body is integrity-protected by its CMIS signature, so a world-readable
    // file is fine (mirrors the daemon's own startup fetch).
    write_allowlist_file(&path, &bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    println!("✓ fetched and wrote {} ({} bytes)", path.display(), bytes.len());

    match config.allowlist_key() {
        Some(key_path) => verify_after_write(&bytes, key_path, config.allowlist_max_age()),
        None => println!(
            "note: allowlist.key is not configured, so the body was written unverified; the \
             daemon will deny all callers until a verification key is set and installed \
             (`mia setup`, then `sudo mia allowlist-key fetch`)."
        ),
    }

    if reload {
        signal_reload();
    } else {
        println!(
            "\nLoad it live (no restart, keeps the helper socket up):  mia resync-allowlist --reload"
        );
        println!("  or restart the agent:  {}", crate::setup::restart_hint());
    }
    Ok(())
}

/// Signal the running agent to reload the freshly written allowlist via SIGHUP,
/// printing the outcome. Falls back to the manual restart hint when the signal
/// can't be sent (no signal-reload path on this platform, or the service
/// manager command fails — e.g. the agent isn't running as a managed service).
pub(crate) fn signal_reload() {
    let Some(cmd) = crate::setup::reload_command() else {
        println!(
            "\n--reload is not supported on this platform; restart the agent to load it:  {}",
            crate::setup::restart_hint()
        );
        return;
    };
    print!("\nSignaling the running agent to reload (SIGHUP via {}) … ", cmd[0]);
    match std::process::Command::new(cmd[0]).args(&cmd[1..]).status() {
        Ok(status) if status.success() => {
            println!("done.");
            println!("  The new allowlist is now live — no restart, the helper socket stayed up.");
        }
        Ok(status) => {
            println!("failed (exit {}).", status.code().map_or_else(|| "signal".to_string(), |c| c.to_string()));
            println!("  Load it with a restart instead:  {}", crate::setup::restart_hint());
        }
        Err(e) => {
            println!("could not run `{}` ({e}).", cmd[0]);
            println!("  Load it with a restart instead:  {}", crate::setup::restart_hint());
        }
    }
}

/// Signal the running agent to reload (SIGHUP via the service manager)
/// without printing anything — for `mia setup --apply --json`, whose stdout
/// must stay one JSON document. Errors when the platform has no live reload
/// or the service manager command fails.
pub(crate) fn send_reload() -> anyhow::Result<()> {
    let cmd = crate::setup::reload_command().with_context(|| {
        format!(
            "live reload is not supported on this platform; restart the agent:  {}",
            crate::setup::restart_hint()
        )
    })?;
    let status = std::process::Command::new(cmd[0])
        .args(&cmd[1..])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("running `{}`", cmd[0]))?;
    anyhow::ensure!(
        status.success(),
        "the reload command exited with {status}; restart the agent:  {}",
        crate::setup::restart_hint()
    );
    Ok(())
}

/// Verify the freshly fetched allowlist against the locally pinned enrollment
/// key, reporting the outcome. Non-fatal: a verification failure still leaves
/// the body on disk (it is the daemon that fails closed), but the operator is
/// told exactly why the daemon would reject it.
pub(crate) fn verify_after_write(bytes: &[u8], key_path: &Path, max_age_secs: i64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));

    let key_bytes = match crate::system_dir::read_trusted(key_path) {
        Ok(b) => b,
        Err(e) => {
            println!(
                "⚠ could not read allowlist.key {} ({e}); the daemon will deny all callers until \
                 the key is present — install it with `sudo mia allowlist-key fetch`.",
                key_path.display()
            );
            return;
        }
    };
    let trusted = match CompositePublicKey::from_concat_bytes(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            println!(
                "⚠ allowlist.key {} is unparseable ({e}); replace it with `sudo mia \
                 allowlist-key fetch --rotate`.",
                key_path.display()
            );
            return;
        }
    };
    match crate::helper::allowlist::Allowlist::load(bytes, &trusted, now, max_age_secs) {
        Ok(al) => {
            let valid_for = (al.not_after() - now).max(0);
            println!(
                "✓ signature verifies against the pinned key — trust domain {}, valid for {valid_for}s",
                al.trust_domain()
            );
        }
        Err(e) => {
            println!("⚠ the daemon would REJECT this allowlist: {e}");
            println!(
                "  CMIS most likely rotated its enrollment key — compare `mia allowlist-key show` \
                 with `ferrogate enrollment-key`, re-fetch it (`sudo mia allowlist-key fetch \
                 --rotate`) and run `mia resync-allowlist` again."
            );
        }
    }
}

/// Write the signed allowlist CBOR to `path`, creating parent dirs. The body is
/// integrity-protected by its signature (not secret), so `0644`. On Windows,
/// inside the system configuration directory, the result is owned by
/// Administrators so the daemon trusts it (`crate::system_dir::write_file`).
fn write_allowlist_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::system_dir::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    crate::system_dir::write_file(path, bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

fn print_help_resync() {
    println!(
        "mia resync-allowlist — re-fetch this host's signed caller allowlist from CMIS\n\
         \n\
         {USAGE_RESYNC}\n\
         \n\
         Fetches the allowlist CMIS holds for this host (keyed by its hardware\n\
         fingerprint), writes it to allowlist.path (unset: allowlist[-<env>].cbor\n\
         beside the system mia.toml), and verifies it against the pinned\n\
         enrollment key (allowlist.key).\n\
         \n\
         With --reload, the running agent is signalled (SIGHUP) to swap in the\n\
         new body immediately — no restart, so the helper socket never drops.\n\
         Without it, restart the agent to load the refreshed body.\n\
         \n\
         options:\n\
         \x20 -c, --config <path>   TOML config file (default: the system config;\n\
         \x20                       environment variables override it)\n\
         \x20 -e, --environment <env>  select mia-<env>.toml from the standard config\n\
         \x20                       locations instead of mia.toml; excludes --config\n\
         \x20     --reload          signal the running agent to reload the allowlist\n\
         \x20                       live (SIGHUP) instead of requiring a restart\n\
         \x20 -h, --help            show this help"
    );
}

fn print_help_reload() {
    println!(
        "mia --reload — signal the running agent to reload its config and allowlist\n\
         \n\
         {USAGE_RELOAD}\n\
         \n\
         Sends SIGHUP to the running agent (via the service manager) so it re-reads\n\
         its configuration file and signed caller allowlist and swaps them in live —\n\
         no restart, so the helper socket never drops. Use it after editing the local\n\
         config or replacing the allowlist body on disk. To also re-fetch the body\n\
         from CMIS first, use `mia resync-allowlist --reload` instead.\n\
         \n\
         The live reload covers the log verbosity (`log`) and the allowlist\n\
         (`allowlist.path`/`key`/`max_age_secs`). Other settings — the helper socket,\n\
         the CMIS endpoint, attestation inputs — take effect only on a restart.\n\
         \n\
         Not supported on Windows (no SIGHUP); restart the service there.\n\
         \n\
         options:\n\
         \x20 -h, --help   show this help"
    );
}
