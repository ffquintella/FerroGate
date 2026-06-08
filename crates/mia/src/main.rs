//! `mia` — Machine Identity Agent binary.
//!
//! The daemon initializes logging and, when configured, stands up the local
//! helper API (feature F08): a Unix-domain-socket listener that mints
//! DPoP-bound child tokens for vetted local callers. The TPM attestation loop
//! and sealed-SVID recovery (features F02/F04) are not yet wired into the
//! binary; until they are, the helper API runs with **no** host SVID and so
//! refuses to mint (`no_host_svid`) while still enforcing caller
//! authentication and the signed allowlist — a fail-safe, deployable surface.
//!
//! The binary also exposes an interactive `mia setup` subcommand: a
//! rich-terminal wizard (see [`mia::setup`]) that walks an operator through the
//! configuration below. With no subcommand, `mia` is the daemon.
//!
//! ## Configuration
//!
//! MIA reads an optional TOML configuration file ([`mia::config`]) and overlays
//! environment variables on top, so the precedence is
//! **defaults < config file < environment**. The file is found at
//! `--config <path>`, then `$FERROGATE_CONFIG`, then `/etc/ferrogate/mia.toml`
//! (absent ⇒ env/defaults only). A deployment that sets everything through the
//! systemd `EnvironmentFile` keeps working with no file present.
//!
//! The environment variables (each also a TOML key — see `dist/mia.toml`):
//!
//! - `FERROGATE_HELPER_SOCKET` (`helper.socket`) — socket path; its presence
//!   enables the helper API. Absent ⇒ the daemon logs a banner and exits.
//! - `FERROGATE_HELPER_SOCKET_MODE` (`helper.socket_mode`) — octal socket mode
//!   (default `660`).
//! - `FERROGATE_ALLOWLIST` (`allowlist.path`) — path to the signed CBOR
//!   allowlist. Absent ⇒ the API denies every caller (fail closed).
//! - `FERROGATE_ALLOWLIST_KEY` (`allowlist.key`) — path to the trusted CMIS
//!   enrollment public key used to verify the allowlist. Required whenever the
//!   allowlist is set.
//! - `FERROGATE_ALLOWLIST_MAX_AGE_SECS` (`allowlist.max_age_secs`) — max
//!   allowlist age (default `86400`).
//! - `FERROGATE_IMA_LOG` (`attestation.ima_log`) — override the IMA
//!   runtime-measurement log path.
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`).

#![forbid(unsafe_code)]

use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    // Subcommand dispatch. `mia` with no subcommand is the daemon (the systemd
    // ExecStart); `mia setup` is the interactive configuration wizard, which
    // must run BEFORE logging init, hardening, and the async runtime — it is
    // synchronous terminal I/O and must not inherit the seccomp profile or the
    // dropped privileges the daemon installs.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("setup") => return mia::setup::run(&args[1..]),
        Some("-h" | "--help") => {
            print_usage();
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("mia {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        // A bare non-flag token is an unknown subcommand; flags (e.g. --config)
        // belong to the daemon and are parsed below.
        Some(other) if !other.starts_with('-') => {
            anyhow::bail!("unknown subcommand: {other}\n\nrun `mia --help` for usage")
        }
        _ => {}
    }

    // Resolve the configuration before logging/hardening: the file gives us the
    // log directive, and a malformed file must fail loudly and early.
    let config_path = parse_config_flag(&args)?;
    let (config, source) = mia::config::Config::load(config_path.as_deref())?;

    let filter =
        EnvFilter::try_new(config.log_directive()).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        component = "mia",
        "FerroGate Machine Identity Agent"
    );
    if let Some(path) = &source {
        tracing::info!(config = %path.display(), "loaded configuration file");
    } else {
        tracing::debug!("no configuration file; using environment and defaults");
    }

    // Apply the hardening profile (feature F12) on the single startup thread,
    // *before* building the async runtime — so the seccomp filter is inherited
    // by every tokio worker and `mlockall(MCL_FUTURE)` covers their allocations,
    // and before any TPM or network I/O. Fatal on failure: a MIA that cannot
    // harden must not serve.
    #[cfg(target_os = "linux")]
    mia::hardening::harden()?;
    #[cfg(not(target_os = "linux"))]
    tracing::debug!("hardening profile (seccomp/mlockall/privilege-drop) applies on Linux only");

    // Build the multi-threaded runtime by hand (rather than `#[tokio::main]`) so
    // hardening runs first. `enable_all` wires the I/O and time drivers the
    // helper server and CMIS client need.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config))
}

/// Parse the daemon's `--config`/`-c <path>` flag from `args`. Returns the
/// requested path, if any. Errors on a missing argument or an unknown flag.
fn parse_config_flag(args: &[String]) -> anyhow::Result<Option<std::path::PathBuf>> {
    let mut config = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let path = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path argument"))?;
                config = Some(std::path::PathBuf::from(path));
            }
            other => anyhow::bail!("unknown option: {other}\n\nrun `mia --help` for usage"),
        }
    }
    Ok(config)
}

/// Top-level CLI usage banner.
fn print_usage() {
    println!(
        "mia {} — FerroGate Machine Identity Agent\n\
         \n\
         usage: mia [--config <path>]\n\
         \x20      mia <command>\n\
         \n\
         commands:\n\
         \x20 (none)   run the agent daemon\n\
         \x20 setup    interactive wizard that writes the agent's config file\n\
         \n\
         options:\n\
         \x20 -c, --config <path>   TOML config file (default {}, then\n\
         \x20                       $FERROGATE_CONFIG; environment variables override it)\n\
         \x20 -h, --help            show this help\n\
         \x20 -V, --version         print the version\n\
         \n\
         Run `mia setup --help` for the wizard's options.",
        env!("CARGO_PKG_VERSION"),
        mia::config::system_config_path().display(),
    );
}

/// Daemon entry point. Starts the helper API when a helper socket is
/// configured, otherwise prints a banner and exits.
async fn run(config: mia::config::Config) -> anyhow::Result<()> {
    if config.helper_socket().is_none() {
        println!(
            "mia v{} — daemon idle; set a helper socket (helper.socket / \
             FERROGATE_HELPER_SOCKET) to start the helper API.",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    start_helper_api(&config).await
}

/// Build the platform's caller authenticator (Linux: SO_PEERCRED + IMA).
#[cfg(target_os = "linux")]
fn build_auth(config: &mia::config::Config) -> mia::helper::auth::ImaCallerAuth {
    use mia::helper::auth::ImaCallerAuth;
    match config.attestation.ima_log.as_deref() {
        Some(p) => ImaCallerAuth::with_ima_log(p.to_path_buf()),
        None => ImaCallerAuth::new(),
    }
}

/// Build the platform's caller authenticator (macOS: peer-cred + image hash).
#[cfg(target_os = "macos")]
fn build_auth(_config: &mia::config::Config) -> mia::helper::auth::MacCallerAuth {
    mia::helper::auth::MacCallerAuth::new()
}

/// Build the platform's caller authenticator (Windows: PID + image hash +
/// Authenticode).
#[cfg(windows)]
fn build_auth(_config: &mia::config::Config) -> mia::helper::auth::WindowsCallerAuth {
    mia::helper::auth::WindowsCallerAuth::new()
}

/// Start the local helper API. Supported on Linux, macOS, and Windows; the only
/// per-OS difference is the caller authenticator ([`build_auth`]) and the
/// transport `HelperServer` resolves from the target (UDS on Unix, a named pipe
/// on Windows).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn start_helper_api(config: &mia::config::Config) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let socket_path = config
        .helper_socket()
        .context("internal: start_helper_api called without a helper socket")?
        .to_path_buf();
    serve(config, socket_path, build_auth(config)).await
}

/// Bind and serve the helper API with the given caller authenticator. Shared by
/// every supported platform.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn serve<A>(
    config: &mia::config::Config,
    socket_path: std::path::PathBuf,
    auth: A,
) -> anyhow::Result<()>
where
    A: mia::helper::auth::CallerAuth,
{
    use anyhow::Context as _;
    use ferro_crypto::composite::CompositePublicKey;
    use mia::helper::{system_clock, Allowlist, CrlCache, HelperServer, HelperServerConfig};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    let max_age = config.allowlist_max_age();
    let clock = system_clock();

    // Audit sink: a forwarder task drains helper events. For now it logs them;
    // CMIS forwarding rides on F07's `AppendAuditEvent` path (`audit_client`).
    let (audit_tx, mut audit_rx) = mpsc::channel(256);
    tokio::spawn(async move {
        while let Some(event) = audit_rx.recv().await {
            tracing::info!(?event, "helper-api audit event");
        }
    });

    // Allowlist: configured ⇒ load and verify (fail loudly); absent ⇒ deny all.
    let allowlist = if let Some(path) = config.allowlist.path.as_deref() {
        let key_path = config.allowlist.key.as_deref().context(
            "allowlist.path is set but allowlist.key (FERROGATE_ALLOWLIST_KEY) is missing",
        )?;
        let key_bytes = std::fs::read(key_path).context("reading allowlist key")?;
        let trusted = CompositePublicKey::from_concat_bytes(&key_bytes)
            .map_err(|e| anyhow::anyhow!("trusted allowlist key: {e}"))?;
        let bytes = std::fs::read(path).context("reading allowlist")?;
        let al = Allowlist::load(&bytes, &trusted, clock(), max_age)
            .map_err(|e| anyhow::anyhow!("allowlist verification failed: {e}"))?;
        tracing::info!(trust_domain = al.trust_domain(), "loaded signed allowlist");
        Some(al)
    } else {
        tracing::warn!("no allowlist configured; helper API denies all callers (fail closed)");
        None
    };

    let helper_config = HelperServerConfig {
        socket_path: socket_path.clone(),
        // `socket_mode`/`socket_gid` are Unix-only; `windows_group` is
        // Windows-only. Each transport ignores the fields that don't apply.
        socket_mode: config.socket_mode()?,
        socket_gid: None,
        windows_group: config.helper.windows_group.clone(),
        max_concurrent: 64,
        read_timeout: Duration::from_secs(5),
    };

    // No minter yet: the host SVID composite key arrives with the attestation
    // loop (F04). Until then the server authenticates and authorizes callers
    // but refuses to mint with `no_host_svid`. The CRL cache (feature F11)
    // starts empty — once the attestation loop lands it will be fed by a puller
    // (`mia::helper::crl::spawn_puller`) against the host's CMIS endpoint; until
    // then an empty cache simply means the (absent) minter stays disabled.
    let crl = Arc::new(CrlCache::new());
    let server = HelperServer::bind(helper_config, auth, None, allowlist, crl, audit_tx, clock)?;
    tracing::warn!(
        "host SVID not present; token minting disabled (returns no_host_svid) until attestation lands"
    );
    tracing::info!(listener = %socket_path.display(), "helper API listening");

    server.serve_with_shutdown(shutdown_signal()).await;
    tracing::info!("helper API shut down cleanly");
    Ok(())
}

/// Fallback for platforms with no helper transport (neither Unix nor Windows).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[allow(clippy::unused_async)] // async to match the cross-platform signature
async fn start_helper_api(_config: &mia::config::Config) -> anyhow::Result<()> {
    anyhow::bail!("unsupported platform: mia's helper API runs on Linux, macOS, and Windows")
}

/// Resolve when the process is asked to stop: `SIGINT`/`SIGTERM` on Unix,
/// Ctrl-C / Ctrl-Break on Windows.
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT; shutting down"),
        () = term => tracing::info!("received SIGTERM; shutting down"),
    }
}

/// Resolve when the process receives Ctrl-C / Ctrl-Break (Windows).
#[cfg(windows)]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("received Ctrl-C; shutting down");
}
