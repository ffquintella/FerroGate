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
//! `--environment <env>` (mutually exclusive with `--config`) selects
//! `mia-<env>.toml` from the standard config locations instead of `mia.toml`,
//! so one host can carry side-by-side configs for different deployments
//! (`mia --environment staging`, `mia --environment prod`, …).
//!
//! With **no** selector at all (plain `mia`), the daemon serves *every*
//! discovered environment at once — `mia.toml` plus each `mia-<env>.toml` — in
//! one process, each attesting to its own CMIS and exposing its own helper
//! socket, so a single agent can mint tokens for several deployments
//! concurrently. `--config`/`--environment`/`$FERROGATE_CONFIG` pin it to one.
//!
//! The environment variables (each also a TOML key — see `dist/mia.toml`):
//!
//! - `FERROGATE_HELPER_ENABLE` (`helper.enable`) — serve the helper API
//!   (default on); `0`/`false` switches it off.
//! - `FERROGATE_HELPER_SOCKET` (`helper.socket`) — socket path. Absent ⇒ the
//!   platform default for the environment
//!   ([`mia::config::default_helper_socket`]: `/run/ferrogate/mia[-<env>].sock`
//!   on Linux, `/Library/Application Support/FerroGate/run/mia[-<env>].sock`
//!   on macOS, `\\.\pipe\ferrogate-mia[-<env>]` on Windows).
//! - `FERROGATE_DEFAULT_ENVIRONMENT` (`default_environment` in the system
//!   `environments.toml`, not `mia.toml`) — which environment serves the
//!   well-known (unsuffixed) helper address; unset ⇒ `mia.toml`. See
//!   [`mia::default_env`].
//! - `FERROGATE_HELPER_SOCKET_MODE` (`helper.socket_mode`) — octal socket mode
//!   (default `660`).
//! - `FERROGATE_HELPER_SOCKET_GID` (`helper.socket_gid`) — numeric gid to own
//!   the socket so that group's members may open it (Unix only; set by
//!   `make mia-install` to the dedicated FerroGate group). Unset on macOS ⇒ a
//!   socket in the default `run/` directory takes the group of
//!   `/Library/Application Support/FerroGate` (`ferrogate-status` after a
//!   package install), re-applied to `run/` on every start.
//! - `FERROGATE_ALLOWLIST` (`allowlist.path`) — path to the signed CBOR
//!   allowlist. Absent ⇒ the platform default for the environment
//!   ([`mia::config::default_allowlist_path`]: `allowlist[-<env>].cbor` beside
//!   the system `mia.toml` — `/etc/ferrogate` on Linux,
//!   `/Library/Application Support/FerroGate` on macOS,
//!   `%ProgramData%\FerroGate` on Windows). A missing, unreadable, stale or
//!   non-verifying body ⇒ the API denies every caller (fail closed).
//! - `FERROGATE_ALLOWLIST_KEY` (`allowlist.key`) — path to the trusted CMIS
//!   enrollment public key used to verify the allowlist. No default (it is the
//!   trust anchor): absent ⇒ every caller is denied; required whenever
//!   `allowlist.path` is set explicitly (the daemon refuses to start without
//!   it).
//! - `FERROGATE_ALLOWLIST_MAX_AGE_SECS` (`allowlist.max_age_secs`) — max
//!   allowlist age (default `345600`, i.e. 96 h).
//! - `FERROGATE_IMA_LOG` (`attestation.ima_log`) — override the IMA
//!   runtime-measurement log path.
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`).

#![forbid(unsafe_code)]

use std::sync::Arc;

use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, reload, EnvFilter};

/// A type-erased handle that swaps the live tracing filter, so a SIGHUP reload
/// can apply a changed `log` directive without a restart. Hides the concrete
/// `reload::Handle` type so it threads cleanly through the serve path.
type LogReload = Arc<dyn Fn(&str) + Send + Sync>;

fn main() -> anyhow::Result<()> {
    // Subcommand dispatch. `mia` with no subcommand is the daemon (the systemd
    // ExecStart / the Windows service `service run`); `mia setup` is the
    // interactive configuration wizard, which must run BEFORE logging init,
    // hardening, and the async runtime — it is synchronous terminal I/O and must
    // not inherit the seccomp profile or the dropped privileges the daemon
    // installs.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("setup") => return mia::setup::run(&args[1..]),
        Some("resync-allowlist") => return mia::resync::run(&args[1..]),
        // `--resync` re-fetches this host's signed allowlist from CMIS and swaps it
        // into the running agent live (SIGHUP) — the one-shot, no-restart resync.
        // It is `resync-allowlist` with the reload always on.
        Some("--resync") => return mia::resync::run_resync(&args[1..]),
        // Install / inspect allowlist.key, the CMIS enrollment key that verifies
        // the signed allowlist. Root only, pinned channel only, never replaces a
        // different key without --rotate; the daemon itself never fetches it.
        Some("allowlist-key") => return mia::allowlist_key::run(&args[1..]),
        // Deprecated alias: `allowlist-key fetch --rotate --yes`.
        Some("refresh-key") => return mia::allowlist_key::run_refresh_key(&args[1..]),
        // Explain why a caller is (not) allowlisted. Read-only and offline;
        // exits 0 permitted, 1 denied, 2 usage/IO error.
        Some("allowlist-diagnose") => std::process::exit(mia::allowlist_diagnose::run(&args[1..])),
        // Print this host's fingerprint-derived machine identity (the
        // `host/<uuid>` CMIS keys its allowlist and host SVID under). Read-only
        // and offline — no config, no CMIS, no daemon contact.
        Some("machine-id") => return mia::machine_id::run(&args[1..]),
        // Inspect the sealed X.509-SVID (feature F17). Read-only and offline;
        // opens the same machine-bound store the daemon writes.
        Some("x509-svid") => return mia::x509_svid::run(&args[1..]),
        // `--reload` is a management flag, not a daemon option: it signals the
        // running agent (SIGHUP) to re-read its config + allowlist, then exits.
        Some("--reload") => return mia::resync::run_reload(&args[1..]),
        Some("test") => return mia::selftest::run(&args[1..]),
        // Application registration (feature F19): `register` and `status` talk
        // to the running agent over the helper socket as the invoking user;
        // `list` reads the verified allowlist. Exit: 0 approved, 3 pending or
        // queued, 4 denied, 1 error, 2 usage.
        #[cfg(any(unix, windows))]
        Some("app") => std::process::exit(mia::app_cli::run(&args[1..])),
        // Read the running agent's status endpoint (feature F18). Exits with a
        // stable code: 0 healthy, 1 not all healthy, 3 agent not running, …
        Some("status") => std::process::exit(mia::status_cli::run(&args[1..])),
        // Show / set / clear which environment serves the well-known helper
        // address (environments.toml). Writes are atomic and audited; the
        // daemon applies a change when it restarts.
        Some("default-environment") => return mia::default_env_cli::run(&args[1..]),
        // Windows service management (install/uninstall/start/stop) and the
        // internal `service run` the SCM launches. Windows-only.
        Some("service") => return service_cmd(&args[1..]),
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

    // No subcommand: run the daemon, logging to stdout (interactive / systemd /
    // launchd capture it). The Windows service path calls `run_daemon` with
    // `service_log = true` instead, since the SCM gives it no console.
    run_daemon(&args, false)
}

/// Resolve configuration, apply the hardening profile, build the async runtime,
/// and serve every configured environment until shutdown. Shared by the
/// interactive/systemd/launchd path (`service_log = false`) and the Windows
/// service path (`service_log = true`, which routes logs to a file).
#[allow(clippy::too_many_lines)] // linear startup: resolve configs → harden → serve
fn run_daemon(args: &[String], service_log: bool) -> anyhow::Result<()> {
    let config_source = parse_daemon_flags(args)?;

    // The Windows service (`LocalSystem`) makes the system configuration
    // directory administrator-only before it reads anything from it — and
    // before the log file below creates it — so no local user can plant a
    // configuration, allowlist or key for it to load (see `mia::system_dir`).
    // Elsewhere, and for a foreground run, this is a no-op: the per-file
    // checks still refuse anything a non-administrator could have written.
    let system_dir = if service_log {
        Some(
            mia::system_dir::prepare()
                .map_err(|e| anyhow::anyhow!("securing the configuration directory: {e}"))?,
        )
    } else {
        None
    };

    // An explicit selection (`--config`, `--environment`, or `$FERROGATE_CONFIG`)
    // serves exactly that one configuration. Otherwise the daemon serves *every*
    // discovered environment (`mia.toml` + `mia-<env>.toml`), attesting to each
    // CMIS and exposing each environment's own helper socket, so a local caller
    // can fetch tokens for whichever environment it needs.
    let explicit = config_source.path.is_some()
        || config_source.environment.is_some()
        || std::env::var_os(mia::config::ENV_CONFIG).is_some();

    // The host-wide default environment (who serves the well-known helper
    // address), resolved once and applied to every environment served here.
    // Fails closed: an invalid selection stops startup.
    let selection = mia::default_env::DefaultSelection::load()?;

    // Resolve the configuration before logging/hardening: it gives us the log
    // directive, and a malformed file must fail loudly and early. The primary
    // config supplies the process-wide log directive; in all-environments mode
    // that is the default `mia.toml` (env/defaults if it is absent).
    let primary_source = if explicit {
        config_source.clone()
    } else {
        mia::config::ConfigSource::default()
    };
    let (primary_config, primary_path) = primary_source.load_with(&selection)?;

    // A reloadable filter layer: SIGHUP re-reads the config and applies a
    // changed `log` directive live (see `spawn_reload_task`).
    let filter = EnvFilter::try_new(primary_config.log_directive())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, filter_handle) = reload::Layer::new(filter);
    // Under the Windows SCM there is no console, so route logs to a file beside
    // the system config (%ProgramData%\FerroGate\logs\mia.log). Every other run
    // logs to stdout, where systemd/launchd or the operator's terminal sees it.
    let (writer, ansi) = log_writer(service_log)?;
    // The status endpoint's redacting log ring buffer (feature F18) sits under
    // the same global filter, so it only ever holds what the daemon's own
    // directive enables.
    // Nothing reads the buffer when the endpoint is off, so hold no records.
    let (log_records, log_bytes) = if primary_config.status_enabled() {
        primary_config.log_buffer_limits()
    } else {
        (0, 0)
    };
    let logbuf = mia::logbuf::LogBuffer::new(log_records, log_bytes);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_ansi(ansi).with_writer(writer))
        .with(mia::logbuf::LogBufferLayer::new(Arc::clone(&logbuf)))
        .init();
    let log_reload: LogReload =
        Arc::new(move |directive: &str| match EnvFilter::try_new(directive) {
            Ok(f) => {
                let _ = filter_handle.reload(f);
            }
            Err(e) => {
                tracing::warn!(directive, error = %e, "ignoring invalid log directive on reload");
            }
        });

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        component = "mia",
        "FerroGate Machine Identity Agent"
    );
    log_system_dir(system_dir.as_ref());
    // Which environment owns the well-known helper address, and why.
    tracing::info!(
        default_environment = %selection.label(),
        source = %selection.source(),
        well_known = %mia::config::default_helper_socket(None).display(),
        "default environment: entitled to the well-known helper address"
    );

    // The status endpoint is per process, configured from the primary config.
    let status_endpoint = status_endpoint_config(&primary_config);
    let status_rate_limit = primary_config.status_rate_limit();
    let started = unix_now();

    // Build the set of environment instances to serve.
    let instances = if explicit {
        let label = config_source
            .environment
            .clone()
            .unwrap_or_else(|| "default".to_string());
        if let Some(path) = &primary_path {
            tracing::info!(env = %label, config = %path.display(), "loaded configuration file");
        } else {
            tracing::debug!(env = %label, "no configuration file; using environment and defaults");
        }
        vec![EnvInstance {
            status: mia::status::StatusHandle::new(&label, started),
            label,
            config: primary_config,
            source: config_source,
        }]
    } else {
        let discovered = mia::config::discover_environment_configs();
        // A selected default with no mia-<env>.toml is a startup error, never
        // a silent fallback of the well-known address to mia.toml.
        selection.ensure_discovered(&discovered)?;
        if discovered.is_empty() {
            tracing::debug!("no configuration files found; using environment and defaults");
            vec![EnvInstance {
                label: "default".to_string(),
                config: primary_config,
                source: mia::config::ConfigSource::default(),
                status: mia::status::StatusHandle::new("default", started),
            }]
        } else {
            tracing::info!(
                count = discovered.len(),
                "serving all discovered environments"
            );
            let mut instances = Vec::new();
            for d in discovered {
                let label = d
                    .environment
                    .clone()
                    .unwrap_or_else(|| "default".to_string());
                // Load each by its concrete path (no env-name re-resolution).
                // Named environments load shared-only, so a process-wide
                // FERROGATE_HELPER_SOCKET (e.g. from a pre-0.19 launchd plist)
                // can't force them all onto the default environment's socket.
                let source = mia::config::ConfigSource {
                    path: Some(d.path.clone()),
                    environment: None,
                    discovered_named_env: d.environment.is_some(),
                };
                match source.load_with(&selection) {
                    Ok((config, _)) => {
                        tracing::info!(env = %label, config = %d.path.display(), "loaded environment configuration");
                        instances.push(EnvInstance {
                            status: mia::status::StatusHandle::new(&label, started),
                            label,
                            config,
                            source,
                        });
                    }
                    // One broken environment must not take down the others —
                    // but if it is the default, say that nobody else takes
                    // over the well-known address (fail closed).
                    Err(e) => tracing::error!(
                        env = %label, config = %d.path.display(), error = %e,
                        default_environment = selection.is_default(d.environment.as_deref()),
                        "skipping environment: its configuration failed to load{}",
                        if selection.is_default(d.environment.as_deref()) {
                            "; it is the default environment, so the well-known helper \
                             address stays unserved"
                        } else {
                            ""
                        }
                    ),
                }
            }
            if instances.is_empty() {
                anyhow::bail!("no environment configuration loaded successfully");
            }
            instances
        }
    };

    // Prefetch root-only inputs, hand the daemon's writable directories to the
    // privilege-drop user, then apply the hardening profile (feature F12) — all
    // on the single startup thread, *before* building the async runtime, so the
    // seccomp filter is inherited by every tokio worker and `mlockall(MCL_FUTURE)`
    // covers their allocations, and before any TPM or network I/O. Fatal on
    // failure: a MIA that cannot harden must not serve.
    let status_listener = prepare_and_harden(&instances, status_endpoint)?;
    let status = status_listener.map(|prepared| {
        let registry =
            mia::status::StatusRegistry::new(instances.iter().map(|i| i.status.clone()).collect());
        let service =
            mia::status_server::StatusService::new(registry, Some(logbuf), status_rate_limit);
        (prepared, service)
    });

    // Build the multi-threaded runtime by hand (rather than `#[tokio::main]`) so
    // hardening runs first. `enable_all` wires the I/O and time drivers the
    // helper server and CMIS client need.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_all(instances, log_reload, status))
}

/// The status endpoint's parameters (feature F18), or `None` when it is
/// disabled (`status.enable = false`) or misconfigured (logged; the daemon
/// still serves — the endpoint is diagnostics, not identity).
fn status_endpoint_config(
    config: &mia::config::Config,
) -> Option<mia::status_server::StatusEndpointConfig> {
    if !config.status_enabled() {
        tracing::info!("status endpoint disabled (status.enable = false)");
        return None;
    }
    match mia::status_server::StatusEndpointConfig::from_config(config) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::error!(error = %e, "status endpoint misconfigured; not serving it");
            None
        }
    }
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The status listener paired with the service that answers on it.
type StatusEndpoint = (
    mia::status_server::PreparedEndpoint,
    mia::status_server::StatusService,
);

/// One environment the daemon serves: its display label (`"default"` or the
/// environment name), its loaded configuration, the [`ConfigSource`] to
/// re-read on SIGHUP, and the status handle the status endpoint reports from.
struct EnvInstance {
    label: String,
    config: mia::config::Config,
    source: mia::config::ConfigSource,
    status: mia::status::StatusHandle,
}

/// Parse the daemon's config-source flags from `args`: `--config`/`-c <path>`
/// and `--environment`/`-e <env>`. Returns the resolved [`ConfigSource`]. Errors
/// on a missing argument or an unknown flag (mutual exclusivity of the two is
/// enforced later, by [`mia::config::Config::load`]).
fn parse_daemon_flags(args: &[String]) -> anyhow::Result<mia::config::ConfigSource> {
    let mut source = mia::config::ConfigSource::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let path = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path argument"))?;
                source.path = Some(std::path::PathBuf::from(path));
            }
            "-e" | "--environment" => {
                let env = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--environment requires a name argument"))?;
                source.environment = Some(env.clone());
            }
            other => anyhow::bail!("unknown option: {other}\n\nrun `mia --help` for usage"),
        }
    }
    Ok(source)
}

/// Log what [`mia::system_dir::prepare`] found at service start (it runs before
/// the subscriber exists). A repaired directory is a `warn`: until then any
/// local user could create files in it.
fn log_system_dir(prepared: Option<&mia::system_dir::Prepared>) {
    use mia::system_dir::Prepared;
    let dir = mia::config::system_config_path()
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    match prepared {
        None | Some(Prepared::Unmanaged) => {}
        Some(Prepared::Created) => tracing::info!(
            dir = %dir.display(),
            "created the configuration directory administrator-only (SYSTEM and Administrators)"
        ),
        Some(Prepared::AlreadyRestricted) => tracing::debug!(
            dir = %dir.display(),
            "configuration directory is administrator-only"
        ),
        Some(Prepared::Repaired { reason }) => tracing::warn!(
            dir = %dir.display(),
            %reason,
            "the configuration directory was not administrator-only; replaced its owner and DACL \
             (SYSTEM and Administrators only). Files other users created in it stay refused: \
             review and delete them"
        ),
    }
}

/// Resolve the tracing writer: a log file under `%ProgramData%\FerroGate\logs`
/// (no ANSI) when running as a Windows service, otherwise stdout (ANSI on).
fn log_writer(
    service_log: bool,
) -> anyhow::Result<(tracing_subscriber::fmt::writer::BoxMakeWriter, bool)> {
    use anyhow::Context as _;
    use tracing_subscriber::fmt::writer::BoxMakeWriter;

    if service_log {
        let dir = mia::config::system_config_path()
            .parent()
            .map_or_else(|| std::path::PathBuf::from("logs"), |p| p.join("logs"));
        mia::system_dir::create_dir_all(&dir)
            .with_context(|| format!("creating service log directory {}", dir.display()))?;
        let path = dir.join("mia.log");
        // Judged before the service writes to it: never through a junction,
        // symbolic link or hard link, and only in an administrator-only file.
        let file = mia::system_dir::open_log(&path)
            .with_context(|| format!("opening service log file {}", path.display()))?;
        Ok((BoxMakeWriter::new(std::sync::Mutex::new(file)), false))
    } else {
        Ok((BoxMakeWriter::new(std::io::stdout), true))
    }
}

/// Dispatch `mia service <subcommand>` — manage the Windows service so the agent
/// runs in the background and `Restart-Service mia` works. `run` is the internal
/// entry the SCM launches; the rest are operator/installer commands.
#[cfg(windows)]
fn service_cmd(args: &[String]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    match args.first().map(String::as_str) {
        Some("run") => {
            ferro_winauth::service::run_dispatcher(ferro_winauth::service::ServiceHooks {
                run: service_run_daemon,
                request_stop: service_request_stop,
            })
        }
        Some("install") => {
            let exe = std::env::current_exe().context("resolving the mia executable path")?;
            ferro_winauth::service::install(
                &exe,
                "FerroGate Machine Identity Agent",
                "Attests this host to CMIS and serves the local helper API for minting child tokens.",
            )?;
            println!("installed the 'mia' service (auto-start). Start it with: Start-Service mia");
            Ok(())
        }
        Some("uninstall") => {
            ferro_winauth::service::uninstall()?;
            println!("removed the 'mia' service.");
            Ok(())
        }
        Some("start") => {
            ferro_winauth::service::start()?;
            println!("started the 'mia' service.");
            Ok(())
        }
        // Make %ProgramData%\FerroGate administrator-only, exactly as the
        // service does at start (`mia::system_dir::prepare`). The installers
        // run it, and so can an administrator; it needs elevation.
        Some("secure-config") => {
            let dir = mia::config::system_config_path()
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_default();
            match mia::system_dir::prepare()
                .with_context(|| format!("securing {}", dir.display()))?
            {
                mia::system_dir::Prepared::Created => {
                    println!("created {} administrator-only.", dir.display());
                }
                mia::system_dir::Prepared::Repaired { reason } => println!(
                    "made {} administrator-only again ({reason}). Files other users created \
                     there are still refused: review and delete them.",
                    dir.display()
                ),
                mia::system_dir::Prepared::AlreadyRestricted
                | mia::system_dir::Prepared::Unmanaged => {
                    println!("{} is administrator-only.", dir.display());
                }
            }
            Ok(())
        }
        Some("stop") => {
            ferro_winauth::service::stop()?;
            println!("stopped the 'mia' service.");
            Ok(())
        }
        Some(other) => anyhow::bail!(
            "unknown service subcommand: {other}\n\nusage: mia service <install|uninstall|start|stop|secure-config>"
        ),
        None => {
            println!(
                "usage: mia service <install|uninstall|start|stop|secure-config>\n\n\
                 Manage the mia Windows service so it runs in the background and\n\
                 `Restart-Service mia` works. `install` registers an auto-start\n\
                 LocalSystem service that runs `mia service run` (used internally\n\
                 by the Service Control Manager). `secure-config` makes\n\
                 %ProgramData%\\FerroGate administrator-only, as the service does\n\
                 at every start (needs an elevated prompt)."
            );
            Ok(())
        }
    }
}

/// The daemon entry the SCM dispatcher runs: serves every configured environment
/// with logs routed to a file, mapping the result to a process exit code.
#[cfg(windows)]
fn service_run_daemon() -> i32 {
    match run_daemon(&[], true) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "mia daemon exited with an error");
            1
        }
    }
}

/// Ask the running daemon to stop. Called from the SCM control thread, so it
/// only sets the shared watch flag that [`shutdown_signal`] awaits.
#[cfg(windows)]
fn service_request_stop() {
    // `send_replace` (not `send`) so the flag is stored even if no serve loop
    // has subscribed yet — `send` discards the value when there are no
    // receivers, which would lose a stop that races startup.
    let _ = service_stop_signal().send_replace(true);
}

/// `mia service` manages the Windows service and is unavailable elsewhere.
#[cfg(not(windows))]
fn service_cmd(_args: &[String]) -> anyhow::Result<()> {
    anyhow::bail!(
        "the `service` command manages the Windows service and is only available on Windows"
    )
}

/// Top-level CLI usage banner.
fn print_usage() {
    println!(
        "mia {} — FerroGate Machine Identity Agent\n\
         \n\
         usage: mia [--config <path> | --environment <env>]\n\
         \x20      mia <command>\n\
         \n\
         commands:\n\
         \x20 (none)            run the agent daemon — serves every configured\n\
         \x20                   environment (mia.toml + mia-<env>.toml) at once,\n\
         \x20                   each on its own helper socket\n\
         \x20 setup             interactive wizard that writes the agent's config file\n\
         \x20 allowlist-key     fetch (root) or show allowlist.key, the CMIS enrollment\n\
         \x20                   key that verifies the signed allowlist\n\
         \x20 refresh-key       deprecated: allowlist-key fetch --rotate --yes\n\
         \x20 allowlist-diagnose  explain why a caller (uid + binary) is or is not\n\
         \x20                   permitted by the signed allowlist (read-only)\n\
         \x20 resync-allowlist  re-fetch this host's signed allowlist from CMIS\n\
         \x20 machine-id        print this host's fingerprint-derived machine identity\n\
         \x20 x509-svid         inspect the machine-bound X.509-SVID store\n\
         \x20 test              check CMIS connectivity and helper-token issuance\n\
         \x20 status            report each environment's state from the running agent\n\
         \x20 app               register an application (register --exe), show your\n\
         \x20                   requests (status), list the verified allowlist (list)\n\
         \x20 default-environment  show, set <env> or clear the environment that serves\n\
         \x20                   the well-known helper address (applies on restart)\n\
         \x20 service           manage the Windows service (install/uninstall/start/stop)\n\
         \n\
         options:\n\
         \x20 -c, --config <path>   serve only this TOML config file (otherwise the\n\
         \x20                       daemon serves all environments; default base {}, then\n\
         \x20                       $FERROGATE_CONFIG; environment variables override it)\n\
         \x20 -e, --environment <env>  serve only mia-<env>.toml from the standard config\n\
         \x20                       locations instead of every environment; mutually\n\
         \x20                       exclusive with --config\n\
         \x20     --reload          signal the running agent to reload its config and\n\
         \x20                       allowlist live (SIGHUP), then exit\n\
         \x20     --resync          re-fetch this host's signed allowlist from CMIS and\n\
         \x20                       reload it into the running agent live (no restart),\n\
         \x20                       then exit\n\
         \x20 -h, --help            show this help\n\
         \x20 -V, --version         print the version\n\
         \n\
         Run `mia <command> --help` for a command's own options.",
        env!("CARGO_PKG_VERSION"),
        mia::config::system_config_path().display(),
    );
}

/// Daemon entry point. Serves every environment instance whose helper API is
/// on (the default), concurrently, in this one process — each attesting to its
/// own CMIS and exposing its own helper socket (the configured `helper.socket`,
/// else the per-environment platform default). Environments with
/// `helper.enable = false` are idle (logged, not served); a duplicate socket
/// across environments is skipped (each needs a distinct `helper.socket`).
/// With nothing to serve it prints the idle banner and exits.
// The serve path holds a composite key (~4 KB ML-DSA) across awaits during
// attestation; the large future is inherent, not a bug.
#[allow(clippy::large_futures)]
async fn run_all(
    instances: Vec<EnvInstance>,
    log_reload: LogReload,
    status: Option<StatusEndpoint>,
) -> anyhow::Result<()> {
    use std::collections::HashSet;

    // The read-only status endpoint (feature F18) runs beside the helper
    // listeners for the life of the process.
    if let Some((prepared, service)) = status {
        tokio::spawn(async move {
            if let Err(e) =
                mia::status_server::serve(prepared, service, std::future::pending()).await
            {
                tracing::error!(error = %e, "status endpoint stopped");
            }
        });
    }

    // Keep only environments that actually serve a socket, rejecting duplicates
    // so the second bind on a shared path can't crash-loop the first.
    let mut seen_sockets: HashSet<std::path::PathBuf> = HashSet::new();
    let mut serveable: Vec<EnvInstance> = Vec::new();
    for inst in instances {
        match inst.config.helper_socket() {
            None => {
                tracing::info!(
                    env = %inst.label,
                    "helper API disabled for this environment (helper.enable = false); \
                     not serving it"
                );
                note_default_address(&inst, None);
                inst.status
                    .set_not_configured(mia_status_proto::error_codes::HELPER_NOT_CONFIGURED);
            }
            Some(socket) => {
                if seen_sockets.insert(socket.clone()) {
                    note_default_address(&inst, Some(&socket));
                    serveable.push(inst);
                } else {
                    inst.status
                        .set_not_configured(mia_status_proto::error_codes::HELPER_NOT_CONFIGURED);
                    // Name the likely culprit when the colliding path matches a
                    // process-wide FERROGATE_HELPER_SOCKET override.
                    let from_env_override = std::env::var_os("FERROGATE_HELPER_SOCKET")
                        .is_some_and(|v| std::path::Path::new(&v) == socket.as_path());
                    tracing::error!(
                        env = %inst.label, socket = %socket.display(),
                        from_env_override,
                        "duplicate helper socket across environments; skipping this one \
                         (each environment needs a distinct helper.socket){}",
                        if from_env_override {
                            " — this path comes from the FERROGATE_HELPER_SOCKET environment \
                             variable, which applies only to the default environment; set each \
                             environment's helper.socket in its own mia-<env>.toml instead"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
    }

    match serveable.len() {
        0 => {
            println!(
                "mia v{} — daemon idle; every environment has the helper API switched off \
                 (helper.enable = false / FERROGATE_HELPER_ENABLE=0).",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        // A single environment serves inline, so its outcome (including a bind
        // error) propagates as the process exit status, exactly as before.
        1 => serve_one(serveable.pop().expect("len == 1"), log_reload).await,
        n => {
            tracing::info!(environments = n, "serving {n} environments concurrently");
            // Run all environment serve loops on one task (each is I/O-bound and
            // runs until shutdown). A per-environment failure is logged; the
            // others keep serving.
            let futures = serveable
                .into_iter()
                .map(|inst| serve_one(inst, log_reload.clone()));
            futures::future::join_all(futures).await;
            Ok(())
        }
    }
}

/// Record in `inst`'s status whether it serves the well-known default helper
/// address (`socket` is its listener, `None` ⇒ helper API off), and log who
/// owns that address. When the host's default environment does not take it
/// (helper API off, or an explicit `helper.socket` elsewhere), say so: nobody
/// else will serve it in its place. That is a warning when the operator chose
/// the default explicitly, and informational for the built-in `mia.toml`.
fn note_default_address(inst: &EnvInstance, socket: Option<&std::path::Path>) {
    let well_known = mia::config::default_helper_socket(None);
    let serves = inst.config.serves_well_known_address();
    inst.status.set_default_address(serves);
    if serves {
        tracing::info!(
            env = %inst.label, listener = %well_known.display(),
            "this environment serves the well-known default helper address"
        );
        return;
    }
    if !inst.config.is_default_environment() {
        return;
    }
    let reason = socket.map_or_else(
        || "its helper API is switched off".to_string(),
        |s| format!("its helper.socket is {}", s.display()),
    );
    if inst.config.default_selection().environment().is_some() {
        tracing::warn!(
            env = %inst.label, well_known = %well_known.display(),
            "the default environment does not serve the well-known helper address ({reason}); \
             no other environment serves it in its place"
        );
    } else {
        tracing::info!(
            env = %inst.label, well_known = %well_known.display(),
            "the default environment does not serve the well-known helper address ({reason})"
        );
    }
}

/// Serve one environment's helper API, tagged with its label so every log line
/// names the environment it came from.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn serve_one(instance: EnvInstance, log_reload: LogReload) -> anyhow::Result<()> {
    use tracing::Instrument as _;

    let EnvInstance {
        label,
        config,
        source,
        status,
    } = instance;
    let span = tracing::info_span!("env", environment = %label);
    async move {
        if let Err(e) = start_helper_api(&config, source, log_reload, status).await {
            tracing::error!(error = %e, "environment helper API exited with error");
            return Err(e);
        }
        Ok(())
    }
    .instrument(span)
    .await
}

/// Serve one environment (fallback for platforms with no helper transport).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
async fn serve_one(instance: EnvInstance, log_reload: LogReload) -> anyhow::Result<()> {
    let EnvInstance {
        config,
        source,
        status,
        ..
    } = instance;
    start_helper_api(&config, source, log_reload, status).await
}

/// Build the platform's caller authenticator (Linux: SO_PEERCRED + IMA).
///
/// The IMA cross-check tracks the same `FERROGATE_REQUIRE_IMA` switch as the
/// startup enforcement check: when IMA is not required (dev / IMA-off hosts)
/// there is no measurement log to check against, so caller-auth falls back to
/// hashing the caller's loaded binary alone.
#[cfg(target_os = "linux")]
fn build_auth(config: &mia::config::Config) -> mia::helper::auth::ImaCallerAuth {
    use mia::helper::auth::ImaCallerAuth;
    let auth = match config.attestation.ima_log.as_deref() {
        Some(p) => ImaCallerAuth::with_ima_log(p.to_path_buf()),
        None => ImaCallerAuth::new(),
    };
    // Mirror `mia::hardening`: IMA is required unless FERROGATE_REQUIRE_IMA=0.
    let require_ima = std::env::var("FERROGATE_REQUIRE_IMA").map_or(true, |v| v != "0");
    if require_ima {
        auth
    } else {
        tracing::warn!(
            "FERROGATE_REQUIRE_IMA=0: helper caller-auth skips the IMA cross-check; \
             caller identity rests on the loaded-binary hash + allowlist (dev only)"
        );
        auth.without_ima()
    }
}

/// Build the platform's caller authenticator (macOS: peer-cred + image hash).
#[cfg(target_os = "macos")]
fn build_auth(_config: &mia::config::Config) -> mia::helper::auth::MacCallerAuth {
    mia::helper::auth::MacCallerAuth::new()
}

/// Build the platform's caller authenticator (Windows: PID + image hash + RID,
/// plus an Authenticode trust check unless `helper.require_authenticode = false`
/// for environments whose binaries are not code-signed).
#[cfg(windows)]
fn build_auth(config: &mia::config::Config) -> mia::helper::auth::WindowsCallerAuth {
    use mia::helper::auth::WindowsCallerAuth;
    if config.helper.require_authenticode.unwrap_or(true) {
        warn_if_own_image_untrusted();
        WindowsCallerAuth::new()
    } else {
        tracing::warn!(
            "helper.require_authenticode is false; caller images are NOT verified with \
             Authenticode (identity rests on PID + image SHA-384 + RID only)"
        );
        WindowsCallerAuth::without_authenticode()
    }
}

/// With the Authenticode caller check on, probe mia's own image once at
/// startup: if it fails (an unsigned build, e.g. stock `make pkg-win`), every
/// caller built the same way — including `mia test` — will be refused with
/// 'untrusted-binary'. Self-trust covers only the allowlist, not caller
/// authentication, so warn here rather than letting the first mint fail with
/// no daemon-side explanation.
#[cfg(windows)]
fn warn_if_own_image_untrusted() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if !matches!(ferro_winauth::verify_authenticode(&exe), Ok(true)) {
        tracing::warn!(
            image = %exe.display(),
            "mia's own binary does not pass Authenticode verification while \
             helper.require_authenticode is on (the default): unsigned local callers — \
             including `mia test` — will be refused with 'untrusted-binary'. Sign the \
             binaries (see WIN_SIGN_PFX in scripts/build-msi-amd64.sh), or set \
             helper.require_authenticode = false in mia.toml for hosts whose clients \
             are not code-signed"
        );
    }
}

/// Start the local helper API. Supported on Linux, macOS, and Windows; the only
/// per-OS difference is the caller authenticator ([`build_auth`]) and the
/// transport `HelperServer` resolves from the target (UDS on Unix, a named pipe
/// on Windows).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn start_helper_api(
    config: &mia::config::Config,
    config_source: mia::config::ConfigSource,
    log_reload: LogReload,
    status: mia::status::StatusHandle,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let socket_path = config
        .helper_socket()
        .context("internal: start_helper_api called with the helper API disabled")?;
    serve(
        config,
        socket_path,
        build_auth(config),
        config_source,
        log_reload,
        status,
    )
    .await
}

/// Directory for mia's writable runtime state — the persistent machine signing
/// key and SVID seed.
///
/// On Linux this is a dedicated state directory (`/var/lib/ferrogate`) that the
/// daemon creates and hands to the `_ferrogate` privilege-drop user *before*
/// dropping (see [`prepare_and_harden`]), so the unprivileged process can write
/// its key and seed. The config directory (`/etc/ferrogate`) stays root-owned
/// and read-only. On macOS / Windows — where the daemon does not drop — state
/// stays beside the system config, as it always has.
fn state_dir() -> std::path::PathBuf {
    mia::credstore::state_dir()
}

/// Resolve where the persistent machine signing key lives — in the service
/// [`state_dir`] (e.g. `/var/lib/ferrogate/host-key.bin` on Linux). Its
/// lifecycle — open, refuse, migrate, create only when none exists — is
/// [`mia::machine_key`]'s.
fn host_key_path() -> std::path::PathBuf {
    mia::machine_key::StateFile::MachineKey.path_in(&state_dir())
}

/// Resolve where this host's persistent SVID seed lives — beside the machine
/// signing key. The 32-byte seed deterministically derives the composite SVID
/// keypair (`CompositeSecretKey::from_seed`), so a daemon restart re-attests
/// under the *same* key and keeps the same child-signing `kid` — and thus the
/// same JWKS entry on CMIS — instead of rotating it every boot.
fn svid_seed_path() -> std::path::PathBuf {
    mia::machine_key::StateFile::SvidSeed.path_in(&state_dir())
}

/// The machine fingerprint, collected once *before* the privilege drop (the DMI
/// serials it hashes are root-only) and reused by attestation afterwards.
static PREFETCHED_FACTS: std::sync::OnceLock<Option<ferro_machineid::MachineFacts>> =
    std::sync::OnceLock::new();

/// Collect the machine fingerprint while still privileged and cache it for the
/// post-drop attestation. Called once, before hardening drops to `_ferrogate`.
fn prefetch_machine_facts() {
    match ferro_machineid::collect_facts() {
        Ok(facts) => {
            let _ = PREFETCHED_FACTS.set(Some(facts));
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cannot collect a hardware fingerprint; host-key attestation will be unavailable"
            );
            let _ = PREFETCHED_FACTS.set(None);
        }
    }
}

/// The machine fingerprint prefetched by [`prefetch_machine_facts`], if any.
fn prefetched_facts() -> Option<&'static ferro_machineid::MachineFacts> {
    PREFETCHED_FACTS.get().and_then(Option::as_ref)
}

/// Do the root-requiring startup work, then apply the hardening profile.
///
/// A privilege-dropping daemon must perform everything that needs root *before*
/// it drops: the machine fingerprint (root-only DMI serials) is prefetched, the
/// state secrets are made owner-only (`0600`; see
/// [`mia::credstore::restrict_secret_files`]), and
/// the directories the unprivileged process will write — each environment's
/// helper-socket directory plus the [`state_dir`] holding the machine key and
/// SVID seed — are created and handed to the `_ferrogate` user. Only then does
/// [`hardening::harden`] drop privileges. Fatal on failure: a MIA that cannot
/// harden must not serve.
///
/// The status socket (feature F18) is bound here too, before the runtime-path
/// preparation and the hardening profile: it needs `chown`, which the seccomp
/// filter forbids, and must be created while its directory is still
/// root-owned. A status-endpoint failure is logged, never fatal.
fn prepare_and_harden(
    instances: &[EnvInstance],
    status: Option<mia::status_server::StatusEndpointConfig>,
) -> anyhow::Result<Option<mia::status_server::PreparedEndpoint>> {
    // Prefetch the fingerprint on every platform so attestation reads it the
    // same way; on Linux it is the only chance to read the root-only DMI files.
    prefetch_machine_facts();
    // Close state secrets an older build left readable by other users, while
    // still root (on Linux, before the drop) so ownership never blocks it.
    let store = mia::credstore::store_path();
    let (key, seed) = (host_key_path(), svid_seed_path());
    let legacy: Vec<std::path::PathBuf> = mia::machine_key::StateFile::ALL
        .iter()
        .flat_map(|f| f.legacy_paths())
        .collect();
    mia::credstore::restrict_secret_files(
        [key.as_path(), seed.as_path(), store.as_path()]
            .into_iter()
            .chain(legacy.iter().map(std::path::PathBuf::as_path)),
    );

    let prepare_status = |cfg: mia::status_server::StatusEndpointConfig| {
        let path = cfg.path.clone();
        match mia::status_server::prepare(cfg) {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                tracing::error!(
                    error = %e, endpoint = %path.display(),
                    "could not bind the status endpoint; serving without it"
                );
                None
            }
        }
    };

    #[cfg(target_os = "linux")]
    {
        // Each served socket's directory, carrying the socket's group so the
        // post-drop bind inherits it (setgid) instead of calling the
        // seccomp-forbidden chown. A malformed gid is left to fail loudly at
        // bind time, where it is reported against its environment.
        let sockets = instances.iter().filter_map(|inst| {
            let socket = inst.config.helper_socket()?;
            Some((socket, inst.config.socket_gid().ok().flatten()))
        });
        let dirs = mia::hardening::plan_runtime_dirs(state_dir(), sockets);
        // Bind first, while the runtime directory is still root-owned (systemd
        // recreates it per start); then hand the directories over and let the
        // status group traverse to the socket.
        let prepared = status.and_then(prepare_status);
        mia::hardening::prepare_runtime_paths(&dirs)?;
        // Carry a machine key / seed an older release kept in /etc/ferrogate
        // into the state directory, handed to the service user — while still
        // root, because afterwards the legacy file is unreadable and `chown`
        // is forbidden. Never fatal: a file left behind is refused (not
        // replaced) when the bootstrap tries to use it.
        let owner = mia::hardening::state_owner()?;
        mia::machine_key::migrate_legacy_files(&state_dir(), owner);
        // Re-seal a pre-F16 plaintext key by atomic replace now: after the
        // drop `rename` is forbidden, so the bootstrap only reads it.
        let fingerprint = prefetched_facts().map(ferro_machineid::MachineFacts::fingerprint);
        mia::machine_key::reseal_machine_key(
            &state_dir(),
            fingerprint.as_ref().map(|f| f.as_bytes().as_slice()),
            owner,
        );
        if let Some(p) = &prepared {
            mia::status_server::grant_group_traverse(p);
        }
        mia::hardening::harden()?;
        Ok(prepared)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = instances;
        tracing::debug!(
            "hardening profile (seccomp/mlockall/privilege-drop) applies on Linux only"
        );
        // No former state location exists on macOS / Windows today; this keeps
        // a future move from minting a fresh key instead of migrating.
        mia::machine_key::migrate_legacy_files(&state_dir(), None);
        let fingerprint = prefetched_facts().map(ferro_machineid::MachineFacts::fingerprint);
        mia::machine_key::reseal_machine_key(
            &state_dir(),
            fingerprint.as_ref().map(|f| f.as_bytes().as_slice()),
            None,
        );
        let prepared = status.and_then(prepare_status);
        if let Some(p) = &prepared {
            mia::status_server::grant_group_traverse(p);
        }
        Ok(prepared)
    }
}

/// Bootstrap the host SVID via the TPM-less **host-key** attestation profile
/// (feature F15) and build the child-token minter the helper API mints with.
///
/// Returns the failure — with a logged reason — when the platform has no
/// hardware fingerprint, the machine key or seed cannot be used, or CMIS
/// cannot be reached or refuses the host. The helper API serves regardless;
/// it refuses to mint (`no_host_svid`) until an attempt succeeds.
///
/// With [`KeyPolicy::OpenOnly`] (a renewal after this run attested, T294) the
/// pinned key and seed are only reopened, never created.
///
/// [`KeyPolicy::OpenOnly`]: mia::renewal::KeyPolicy::OpenOnly
#[allow(clippy::too_many_lines)] // linear bootstrap: dial → attest → build minter
#[allow(clippy::large_futures)] // holds a composite key (~4 KB ML-DSA) across awaits
async fn bootstrap_host_svid_host_key(
    resolver: &mia::endpoint::CmisResolver,
    status: &mia::status::StatusHandle,
    policy: mia::renewal::KeyPolicy,
) -> Result<mia::renewal::Attested, mia::status::AttestFailure> {
    use mia::renewal::HostAttestor as _;

    let Some(facts) = prefetched_facts() else {
        tracing::warn!("no hardware fingerprint available; host-key attestation skipped");
        return Err(mia::status::AttestFailure::Other);
    };
    // The key is sealed at rest to the hardware fingerprint (clone resistance
    // bound to machine identity, docs/features/F16); CMIS pins its public
    // half, so it is only ever opened, and created only when none exists.
    mia::renewal::HostKeyAttestor::new(
        resolver.clone(),
        facts.clone(),
        host_key_path(),
        svid_seed_path(),
        status.clone(),
    )
    .attest(policy)
    .await
}

/// The owned attestation inputs the bootstrap and re-attestation paths need:
/// which backend to use, plus the operator-supplied EK certificate chain for
/// the genuine TPM backend. Cloned out of [`mia::config::Config`] so the
/// `'static` re-attestation task can hold it.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[derive(Clone, Default)]
struct HostAttestConfig {
    backend: mia::config::AttestBackend,
    tpm_ek_cert: Option<std::path::PathBuf>,
    // Only read by the Linux TPM bootstrap; unused on TPM-less platforms.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    tpm_ek_intermediates: Vec<std::path::PathBuf>,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl HostAttestConfig {
    fn from_config(c: &mia::config::Config) -> Self {
        Self {
            backend: c.attestation.backend,
            tpm_ek_cert: c.attestation.tpm.ek_cert.clone(),
            tpm_ek_intermediates: c.attestation.tpm.ek_intermediates.clone(),
        }
    }
}

/// Whether a usable TPM resource-manager device is present.
///
/// On Linux this opens `/dev/tpmrm0`: a device that is present but unusable
/// (permissions, no resource manager) reports unavailable, so `auto` degrades to
/// the software tier instead of committing to a TPM it cannot drive. Opening a
/// context is cheap and creates no persistent objects. On other platforms mia is
/// built without TPM support, so there is never a usable TPM.
#[cfg(target_os = "linux")]
fn tpm_available() -> bool {
    mia::tpm::TpmEngine::open_device().is_ok()
}
#[cfg(all(not(target_os = "linux"), any(target_os = "macos", windows)))]
fn tpm_available() -> bool {
    false
}

/// Dispatch host-SVID bootstrap to the configured attestation backend.
///
/// `auto` (the default) picks the strongest usable tier: the genuine TPM path
/// ([`bootstrap_host_svid_tpm`]) when a usable TPM *and* an EK certificate are
/// present, otherwise the software `host-key` profile
/// ([`bootstrap_host_svid_host_key`]). Selecting `tpm` explicitly is fail-closed
/// — a missing TPM/EK cert refuses to attest rather than downgrading. The
/// `virtual-tpm` backend is a dev/test-only software TPM
/// ([`bootstrap_host_svid_virtual_tpm`]) and requires the `virtual-tpm` cargo
/// feature; a build without it refuses to attest (fail closed) when selected.
///
/// The attestation phase is the caller's to report (start-up or renewal);
/// this records the backend, the CMIS node and the X.509 store.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn bootstrap_host_svid(
    resolver: &mia::endpoint::CmisResolver,
    attest: &HostAttestConfig,
    status: &mia::status::StatusHandle,
    policy: mia::renewal::KeyPolicy,
) -> Result<mia::renewal::Attested, mia::status::AttestFailure> {
    use mia::config::AttestBackend;
    let effective = match attest.backend {
        AttestBackend::Auto if tpm_available() && attest.tpm_ek_cert.is_some() => {
            tracing::info!(
                "attestation.backend = \"auto\": usable TPM detected; using the TPM attestation tier"
            );
            AttestBackend::Tpm
        }
        AttestBackend::Auto if tpm_available() => {
            tracing::warn!(
                "attestation.backend = \"auto\": a TPM is present but attestation.tpm.ek_cert is not \
                 configured; using the host-key software tier (set attestation.tpm.ek_cert to use the TPM)"
            );
            AttestBackend::HostKey
        }
        AttestBackend::Auto => {
            tracing::info!(
                "attestation.backend = \"auto\": no usable TPM; using the host-key software tier"
            );
            AttestBackend::HostKey
        }
        other => other,
    };
    status.set_attest_backend(effective);
    let session = match effective {
        // Unreachable: `auto` is resolved above.
        AttestBackend::Auto => Err(mia::status::AttestFailure::Other),
        AttestBackend::Tpm => bootstrap_host_svid_tpm(resolver, attest, status).await,
        AttestBackend::HostKey => bootstrap_host_svid_host_key(resolver, status, policy).await,
        AttestBackend::VirtualTpm => bootstrap_host_svid_virtual_tpm(resolver, status).await,
    };
    session
}

/// Attest at start-up, reporting the attestation phase, and seal the
/// X.509-SVID issued with it.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn startup_attest(
    resolver: &mia::endpoint::CmisResolver,
    attest: &HostAttestConfig,
    status: &mia::status::StatusHandle,
) -> Option<mia::renewal::Attested> {
    use mia::renewal::X509Sealer as _;
    status.attest_started();
    let policy = mia::renewal::KeyPolicy::OpenOrCreate;
    match bootstrap_host_svid(resolver, attest, status, policy).await {
        Ok(session) => {
            let svid = &session.svid;
            if let Some(backend) = x509_store().seal(svid) {
                status.set_x509_store(backend);
            }
            status.attest_succeeded(&svid.spiffe_id, svid.issued_at, svid.expires_at);
            Some(session)
        }
        Err(failure) => {
            status.attest_failed(failure);
            None
        }
    }
}

/// Bootstrap the host SVID via the genuine **TPM 2.0** path (feature F02): drive
/// the resource-manager device `/dev/tpmrm0` through the shared 4-phase
/// [`mia::client::run_attest`] handshake. Hardware-rooted; also covers hypervisor
/// vTPMs, which present as a normal TPM device.
///
/// The EK certificate (and any intermediates) are operator-supplied via
/// `[attestation.tpm]` — mia does not read the EK cert out of NV. Missing/unusable
/// TPM or EK cert is fail-closed: it refuses to attest rather than downgrading.
#[cfg(target_os = "linux")]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn bootstrap_host_svid_tpm(
    resolver: &mia::endpoint::CmisResolver,
    attest: &HostAttestConfig,
    status: &mia::status::StatusHandle,
) -> Result<mia::renewal::Attested, mia::status::AttestFailure> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use mia::client::AttestEvidence as _;
    use mia::status::AttestFailure;
    use mia::tpm::{TpmEngine, TpmEvidence};
    use sha2::{Digest, Sha256};

    let Some(ek_cert_path) = attest.tpm_ek_cert.as_deref() else {
        tracing::error!(
            "attestation.backend = \"tpm\" but attestation.tpm.ek_cert is not configured; \
             refusing to attest (fail closed)"
        );
        return Err(AttestFailure::TpmUnavailable);
    };
    let ek_cert = match std::fs::read(ek_cert_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, path = %ek_cert_path.display(), "cannot read attestation.tpm.ek_cert");
            return Err(AttestFailure::TpmUnavailable);
        }
    };
    let mut ek_intermediates = Vec::with_capacity(attest.tpm_ek_intermediates.len());
    for p in &attest.tpm_ek_intermediates {
        match std::fs::read(p) {
            Ok(b) => ek_intermediates.push(b),
            Err(e) => {
                tracing::error!(error = %e, path = %p.display(), "cannot read an attestation.tpm.ek_intermediates entry");
                return Err(AttestFailure::TpmUnavailable);
            }
        }
    }

    let engine = match TpmEngine::open_device() {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "cannot open the TPM device (/dev/tpmrm0); refusing to attest (fail closed)");
            return Err(AttestFailure::TpmUnavailable);
        }
    };
    let mut evidence = match TpmEvidence::new(engine, ek_cert, ek_intermediates) {
        Ok(ev) => ev,
        Err(e) => {
            tracing::error!(error = %e, "cannot initialize TPM attestation evidence (EK/AIK)");
            return Err(AttestFailure::TpmUnavailable);
        }
    };

    let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(evidence.aik_pub()));

    let (endpoint, mut client) = match resolver.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, cmis = %resolver.describe(), "could not connect to CMIS for attestation");
            return Err(mia::status::AttestFailure::from_connect_error(&e));
        }
    };
    status.set_cmis_node(&endpoint);
    let attested = match mia::client::run_attest(&mut client, &mut evidence, dpop_jkt).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "TPM attestation failed");
            return Err(AttestFailure::from_attest_error(&e, true));
        }
    };
    tracing::info!(
        spiffe_id = %attested.bundle.spiffe_id,
        cmis = %endpoint,
        "host SVID obtained via TPM attestation; token minting enabled"
    );
    // A TPM SVID binds the AIK, not a host-call key: no `Rotate` (D2).
    Ok(attested_from(attested, None, false))
}

/// Fallback when the `tpm` backend is selected on a non-Linux host, where mia is
/// built without a TSS2 stack: refuse to attest (fail closed) rather than
/// silently downgrading to a different identity path.
#[cfg(all(not(target_os = "linux"), any(target_os = "macos", windows)))]
#[allow(clippy::unused_async)] // matches the Linux signature the dispatcher awaits
async fn bootstrap_host_svid_tpm(
    _resolver: &mia::endpoint::CmisResolver,
    _attest: &HostAttestConfig,
    _status: &mia::status::StatusHandle,
) -> Result<mia::renewal::Attested, mia::status::AttestFailure> {
    tracing::error!(
        "attestation.backend = \"tpm\" is only supported on Linux (it needs a TSS2 stack); \
         refusing to attest (fail closed). Use \"host-key\" on this platform."
    );
    Err(mia::status::AttestFailure::TpmUnavailable)
}

/// The [`mia::renewal::Attested`] of a completed attestation, regardless of
/// which backend produced it. `host_call_key` is the machine key the SVID's
/// `cnf.jkt` binds, if any; `seeded` that its composite key came from the
/// persistent seed. Nothing is written: the X.509-SVID is sealed once the
/// SVID is accepted (start-up, or the renewal's install).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
// Only the TPM-class backends build one here (the host-key tier's comes from
// `mia::renewal::HostKeyAttestor`).
#[cfg_attr(
    not(any(target_os = "linux", feature = "virtual-tpm")),
    allow(dead_code)
)]
fn attested_from(
    attested: mia::client::AttestedSvid,
    host_call_key: Option<std::sync::Arc<dyn ferro_sep::MachineKey + Send + Sync>>,
    seeded: bool,
) -> mia::renewal::Attested {
    let kid = ferro_svid::child_signing_kid(&attested.svid_public);
    let svid = mia::renewal::HostSvid::new(
        attested.bundle,
        std::sync::Arc::new(attested.svid_secret),
        kid,
        host_call_key,
    );
    mia::renewal::Attested { svid, seeded }
}

/// The machine-bound X.509-SVID store: the leaf, its trust bundle and the
/// Ed25519 key it names, sealed with the strongest backend the host offers
/// (best-effort: a host that cannot seal keeps the in-memory credential).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn x509_store() -> mia::renewal::X509Store {
    mia::renewal::X509Store::new(
        mia::credstore::store_path(),
        prefetched_facts().map(|f| f.fingerprint().as_bytes().to_vec()),
    )
}

/// Report the sealed X.509-SVID left by a previous run, if it still opens here.
///
/// Purely informational at startup: the daemon re-attests regardless, and the
/// fresh issuance overwrites the store. What this buys is an early, explicit
/// signal — that a credential survived, or that it no longer opens (the TPM
/// refusing after a firmware change looks exactly like this). A store that
/// cannot be used is deleted so the next start does not retry a file that can
/// never open again.
///
/// Returns the store's backend name when a credential opened (feature F18).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn report_stored_x509_credential() -> Option<&'static str> {
    let path = mia::credstore::store_path();
    let fingerprint = prefetched_facts().map(|f| f.fingerprint().as_bytes().to_vec());
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX);

    let result = mia::credstore::with_sealer(fingerprint.as_deref(), |sealer| {
        mia::credstore::load(&path, sealer, now)
    })?;
    match result {
        Ok(None) => None,
        Ok(Some(loaded)) => {
            tracing::info!(
                spiffe_id = %loaded.spiffe_id,
                expires_in_secs = loaded.not_after - now,
                backend = loaded.backend,
                "recovered the sealed X.509-SVID from a previous run"
            );
            Some(loaded.backend)
        }
        Err(e) => {
            tracing::warn!(
                error = %e, path = %path.display(),
                "the stored X.509-SVID did not open on this host; discarding it and re-attesting"
            );
            mia::credstore::discard(&path);
            None
        }
    }
}

/// Resolve where the virtual TPM's persistent identity lives — beside the
/// machine signing key, so its synthetic EK/AIK is stable across restarts.
#[cfg(feature = "virtual-tpm")]
fn virtual_tpm_path() -> std::path::PathBuf {
    state_dir().join("virtual-tpm.json")
}

/// Bootstrap the host SVID via the in-process software **virtual TPM** — the
/// full four-phase TPM handshake, off real hardware. INSECURE; dev/test only.
///
/// This only succeeds against a CMIS configured to trust the synthetic EK root
/// and approve the synthetic PCR digest (both logged at startup) and to use a
/// matching software credential channel. A production CMIS rejects it.
#[cfg(feature = "virtual-tpm")]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn bootstrap_host_svid_virtual_tpm(
    resolver: &mia::endpoint::CmisResolver,
    status: &mia::status::StatusHandle,
) -> Result<mia::renewal::Attested, mia::status::AttestFailure> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use mia::virtual_tpm::{expected_pcr_digest, VirtualTpm};
    use sha2::{Digest, Sha256, Sha384};

    tracing::warn!(
        "attestation.backend = \"virtual-tpm\": using the INSECURE in-process software TPM \
         (no hardware root of trust). For dev/test only — never production."
    );

    let path = virtual_tpm_path();
    let mut vtpm = match VirtualTpm::open_or_create(&path) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "cannot open virtual-TPM state");
            return Err(mia::status::AttestFailure::TpmUnavailable);
        }
    };
    tracing::info!(
        ek_root_sha384 = %hex::encode(Sha384::digest(vtpm.ek_root_der())),
        pcr_digest_sha384 = %hex::encode(expected_pcr_digest()),
        "virtual-TPM identity ready (CMIS must trust this EK root and approve this PCR digest)"
    );

    let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(vtpm.aik_public_marshaled()));

    let (endpoint, mut client) = match resolver.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, cmis = %resolver.describe(), "could not connect to CMIS for attestation");
            return Err(mia::status::AttestFailure::from_connect_error(&e));
        }
    };
    status.set_cmis_node(&endpoint);
    let attested = match mia::client::run_attest(&mut client, &mut vtpm, dpop_jkt).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "virtual-TPM attestation failed");
            return Err(mia::status::AttestFailure::from_attest_error(&e, true));
        }
    };
    tracing::info!(
        spiffe_id = %attested.bundle.spiffe_id,
        cmis = %endpoint,
        "host SVID obtained via virtual-TPM attestation; token minting enabled"
    );
    Ok(attested_from(attested, None, false))
}

/// Fallback when the daemon was built without the `virtual-tpm` feature but the
/// config selects that backend: refuse to attest rather than silently fall back
/// to a different identity path (fail closed).
#[cfg(all(
    not(feature = "virtual-tpm"),
    any(target_os = "linux", target_os = "macos", windows)
))]
#[allow(clippy::unused_async)] // matches the feature build the dispatcher awaits
async fn bootstrap_host_svid_virtual_tpm(
    _resolver: &mia::endpoint::CmisResolver,
    _status: &mia::status::StatusHandle,
) -> Result<mia::renewal::Attested, mia::status::AttestFailure> {
    tracing::error!(
        "attestation.backend = \"virtual-tpm\" but mia was built without the `virtual-tpm` cargo \
         feature; refusing to attest (fail closed). Rebuild with `--features virtual-tpm` for \
         dev/test, or set attestation.backend = \"host-key\"."
    );
    Err(mia::status::AttestFailure::TpmUnavailable)
}

/// Extract the host UUID from a host SVID SPIFFE id (`spiffe://<td>/host/<uuid>`)
/// — the key CMIS stores a host's allowlist under.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn host_uuid_from_spiffe_id(spiffe_id: &str) -> Option<&str> {
    spiffe_id
        .rsplit_once("/host/")
        .map(|(_, uuid)| uuid)
        .filter(|u| !u.is_empty())
}

/// If `allowlist.fetch` is enabled, fetch this host's signed allowlist from CMIS
/// (keyed by its EK-derived host UUID) and write it to `path` — the resolved
/// `allowlist.path` or its per-environment default
/// ([`mia::config::Config::allowlist_path`]) — before the daemon loads it.
/// Every failure mode is non-fatal and logged: the daemon then falls back to
/// whatever is already on disk (or fails closed if nothing is), exactly as if
/// auto-fetch were off. With no verification `key` configured nothing is
/// written — no body could be verified — so an unconfigured host never writes
/// to the default location.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn maybe_fetch_allowlist(
    fetch: bool,
    path: &std::path::Path,
    key: Option<&std::path::Path>,
    resolver: Option<&mia::endpoint::CmisResolver>,
    host_spiffe_id: Option<&str>,
) {
    if !fetch {
        return;
    }
    if key.is_none() {
        tracing::warn!(
            path = %path.display(),
            "allowlist.fetch is set but allowlist.key is not; nothing could verify the body, \
             so it is not fetched"
        );
        return;
    }
    let Some(spiffe_id) = host_spiffe_id else {
        tracing::warn!(
            "allowlist.fetch is set but no host SVID this start; keeping any existing allowlist"
        );
        return;
    };
    let Some(host_uuid) = host_uuid_from_spiffe_id(spiffe_id) else {
        tracing::warn!(%spiffe_id, "could not derive host UUID from SVID; skipping allowlist fetch");
        return;
    };
    let Some(resolver) = resolver else {
        tracing::warn!("allowlist.fetch is set but CMIS is not configured; skipping");
        return;
    };
    let mut client = match resolver.connect().await {
        Ok((_, client)) => client,
        Err(e) => {
            tracing::warn!(error = %e, "could not reach CMIS; skipping allowlist fetch");
            return;
        }
    };

    match mia::client::fetch_allowlist(&mut client, host_uuid).await {
        Ok(Some(bytes)) => {
            if let Err(e) = write_allowlist_file(path, &bytes) {
                tracing::warn!(error = %e, path = %path.display(), "could not write fetched allowlist; keeping existing file");
            } else {
                tracing::info!(%host_uuid, path = %path.display(), bytes = bytes.len(), "fetched signed allowlist from CMIS");
            }
        }
        Ok(None) => {
            tracing::warn!(%host_uuid, "CMIS has no allowlist for this host; keeping any existing file");
        }
        Err(e) => {
            tracing::warn!(error = %e, "allowlist fetch failed; keeping any existing file");
        }
    }
}

/// Write the signed allowlist CBOR to `path`, creating parent dirs. The body is
/// integrity-protected by its signature (not secret), so `0644` like the key.
/// On Windows a missing system configuration directory is created
/// administrator-only, and a body written there replaces the old file with one
/// owned by Administrators (`mia::system_dir::write_file`), so the daemon
/// trusts it on the next load.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn write_allowlist_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            mia::system_dir::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    mia::system_dir::write_file(path, bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

/// Spawn the background allowlist-propose task (host-driven allowlist
/// bootstrap). It periodically snapshots the callers the helper API has observed
/// (granted *and* denied) and sends them to CMIS, signed by the host machine key
/// and accompanied by the host SVID. CMIS auto-adopts the first proposal on a
/// host with no allowlist (TOFU) or queues it for operator review; see
/// `ProposeAllowlist`.
///
/// Every proposal also carries a *self-registration* entry for the daemon's own
/// binary (`self_sha`, uid-wildcard — mirroring the helper API's self-trust,
/// which already permits `mia` under any uid), and the first proposal is sent
/// immediately at startup. A fresh host therefore registers itself with CMIS
/// the moment it starts, before any real caller has connected — without this,
/// a new host stayed invisible (no allowlist, no proposal) until both a caller
/// appeared and a full interval elapsed.
///
/// Every precondition failure logs and returns `false` without spawning —
/// proposing is strictly opt-in best-effort. The SVID presented is read from
/// `svid` on every round, so a renewal (T294) reaches the proposals without a
/// restart; a round without a valid SVID is skipped.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::too_many_lines)] // precondition checks + the periodic loop.
fn maybe_spawn_propose_task(
    resolver: Option<&mia::endpoint::CmisResolver>,
    host_spiffe_id: Option<&str>,
    svid: mia::renewal::SvidCell,
    ledger: mia::helper::CallerLedger,
    self_sha: Option<[u8; 48]>,
    propose_interval_secs: u64,
) -> bool {
    use ferro_sep::MachineKey as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(spiffe_id) = host_spiffe_id else {
        tracing::warn!("allowlist.propose is set but no host SVID this start; not proposing");
        return false;
    };
    let Some(host_uuid) = host_uuid_from_spiffe_id(spiffe_id).map(str::to_string) else {
        tracing::warn!(%spiffe_id, "could not derive host UUID; not proposing");
        return false;
    };
    let Some(resolver) = resolver.cloned() else {
        tracing::warn!("allowlist.propose is set but CMIS is not configured; not proposing");
        return false;
    };
    // Open the same machine key the host-key bootstrap uses. It is sealed to the
    // hardware fingerprint when one is available (matching `bootstrap_host_svid_host_key`);
    // a host with no fingerprint (e.g. the TPM backend) falls back to the plaintext key.
    // Same lifecycle as the bootstrap: open what exists, refuse (never
    // replace) what cannot be used, create only when none exists anywhere.
    let key_path = host_key_path();
    let fingerprint = prefetched_facts().map(ferro_machineid::MachineFacts::fingerprint);
    let seal = fingerprint.as_ref().map(|f| f.as_bytes().as_slice());
    let key = match mia::machine_key::open_or_create_machine_key(&key_path, seal) {
        Ok(opened) => opened.key,
        Err(e) => {
            tracing::error!(error = %e, path = %key_path.display(), "cannot use the machine key; not proposing");
            return false;
        }
    };
    let sep_pub = key.public_spki_der();
    let interval = std::time::Duration::from_secs(propose_interval_secs);
    tracing::info!(%host_uuid, interval_secs = propose_interval_secs, cmis = %resolver.describe(), "allowlist-propose task started");

    tokio::spawn(async move {
        let mut last_sent: Option<Vec<(u32, [u8; 48])>> = None;
        let mut ticker = tokio::time::interval(interval);
        loop {
            // The first tick fires immediately: the initial proposal is the
            // host's self-registration with CMIS, sent before any caller has
            // connected.
            ticker.tick().await;
            let mut snapshot = ledger.snapshot();
            if snapshot.is_empty() && self_sha.is_none() {
                continue; // nothing observed and no self entry to register
            }
            snapshot.sort_unstable();
            if last_sent.as_ref() == Some(&snapshot) {
                continue; // nothing new since the last successful proposal
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            // The SVID in force now (renewed in place, T294); none while the
            // host holds no valid SVID.
            let Some(jws) = svid.jws_valid_at(now) else {
                tracing::debug!("no valid host SVID; skipping proposal this round");
                continue;
            };
            let mut entries = proposal_entries(&snapshot, self_sha);
            // Resolve + dial CMIS with fail-over for this round (re-resolving SRV
            // so a failed-over or rescaled cluster is followed); the one
            // connection serves both the live-allowlist fetch and the proposal.
            let mut client = match resolver.connect().await {
                Ok((_, client)) => client,
                Err(e) => {
                    tracing::warn!(error = %e, "could not reach CMIS; skipping proposal this round");
                    continue;
                }
            };
            // A proposal is a *full set* that, on approval, replaces the live
            // allowlist (ADR-0003). The observed snapshot knows nothing about
            // entries an operator added by hand — a `bin_sha=*` wildcard, a
            // manual pin — so fold the live allowlist in and propose
            // `live ∪ observed`. Without this, approving a proposal silently
            // drops those operator entries.
            match mia::client::fetch_allowlist(&mut client, &host_uuid).await {
                Ok(Some(bytes)) => {
                    match ferro_svid::allowlist::decode(&bytes)
                        .and_then(|s| ferro_svid::allowlist::decode_body(&s.body))
                    {
                        Ok(live) => {
                            for e in live.entries {
                                if !entries
                                    .iter()
                                    .any(|x| x.uid == e.uid && x.bin_sha == e.bin_sha)
                                {
                                    entries.push(e);
                                }
                            }
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "live allowlist did not decode; proposing observed set only"
                        ),
                    }
                }
                // No live allowlist yet (first-use bootstrap): the observed set
                // is the whole proposal.
                Ok(None) => {}
                Err(e) => {
                    // Don't propose a replacement we couldn't make additive — we
                    // might drop operator entries. Retry on the next tick.
                    tracing::warn!(
                        error = %e,
                        "could not fetch live allowlist; skipping proposal this round"
                    );
                    continue;
                }
            }
            let doc = ferro_svid::ProposalDoc {
                host_uuid: host_uuid.clone(),
                issued_at: now,
                entries,
            };
            let body = match ferro_svid::allowlist::encode_proposal(&doc) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "encode proposal failed");
                    continue;
                }
            };
            let sig = match key.sign(&ferro_svid::allowlist::proposal_signing_input(&body)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "sign proposal failed");
                    continue;
                }
            };
            match mia::client::propose_allowlist(&mut client, body, sig, jws, sep_pub.clone()).await
            {
                Ok(outcome) => {
                    tracing::info!(
                        ?outcome,
                        entries = snapshot.len(),
                        "proposed observed allowlist to CMIS"
                    );
                    last_sent = Some(snapshot);
                }
                Err(e) => tracing::warn!(error = %e, "allowlist proposal failed; will retry"),
            }
        }
    });
    true
}

/// Build the entry set for one allowlist proposal: every observed caller with
/// its concrete uid, plus a uid-wildcard entry for the daemon's own binary
/// (`self_sha`) so the host registers itself with CMIS even before any caller
/// has connected.
///
/// Observed entries carry the concrete uid; relaxing one to a wildcard
/// (uid = None) is an operator decision (ADR-0002). The self entry is the one
/// exception: the helper API's self-trust already permits `mia`'s own binary
/// under any uid, so the wildcard grants nothing the daemon does not already
/// enforce locally — it only makes that standing grant visible in CMIS.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn proposal_entries(
    snapshot: &[(u32, [u8; 48])],
    self_sha: Option<[u8; 48]>,
) -> Vec<ferro_svid::AllowEntry> {
    let mut entries: Vec<ferro_svid::AllowEntry> = snapshot
        .iter()
        .map(|(uid, bin)| ferro_svid::AllowEntry {
            uid: Some(*uid),
            bin_sha: hex::encode(bin),
        })
        .collect();
    if let Some(sha) = self_sha {
        entries.push(ferro_svid::AllowEntry {
            uid: None,
            bin_sha: hex::encode(sha),
        });
    }
    entries
}

/// Interval between CRL pulls. CMIS republishes every 60 s and the helper-API
/// mint gate tolerates 300 s + 60 s leeway, so pulling at the publish cadence
/// keeps the cache fresh with margin for several consecutive failed pulls.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const CRL_PULL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Start the background CRL puller (feature F11) feeding `cache` from the CMIS
/// `JWKS` RPC over a pinned channel.
///
/// Without a usable CMIS configuration nothing can be pulled, so the cache
/// stays empty and every mint is refused (`crl_stale`, fail closed) — that is
/// loudly logged rather than silently accepted. The initial dial is retried
/// forever: CMIS being down at boot must not permanently disable minting.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn maybe_spawn_crl_puller(
    resolver: Option<mia::endpoint::CmisResolver>,
    cache: std::sync::Arc<mia::helper::CrlCache>,
) {
    let Some(resolver) = resolver else {
        tracing::warn!(
            "CMIS not configured; no CRL can be pulled, so token minting stays disabled \
             (crl_stale, fail closed)"
        );
        return;
    };

    tokio::spawn(async move {
        loop {
            // Resolve + dial with fail-over each cycle, so a CRL puller whose node
            // went down re-selects a live one (re-resolving SRV on the way).
            match resolver.connect().await {
                Ok((_, client)) => {
                    // The channel redials on demand after transient drops, so
                    // one successful connect is enough to hand the pull loop;
                    // it only resolves if the puller task itself dies.
                    let puller =
                        mia::helper::crl::spawn_puller(client, cache.clone(), CRL_PULL_INTERVAL);
                    let _ = puller.await;
                    tracing::warn!("CRL puller stopped unexpectedly; restarting");
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e, cmis = %resolver.describe(),
                        "cannot connect to CMIS for CRL pulls; retrying (minting stays \
                         fail-closed until the first verified pull)"
                    );
                }
            }
            tokio::time::sleep(CRL_PULL_INTERVAL).await;
        }
    });
}

/// The owned configuration the renewal hooks need to refresh what depends
/// on the host SVID (allowlist, proposals) after a renewal. Captured before
/// the task is spawned because [`mia::config::Config`] is borrowed for the
/// lifetime of `serve` and the task must be `'static`.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct RenewalParams {
    allowlist_fetch: bool,
    /// The resolved allowlist body (`allowlist.path` or its default).
    allowlist_path: std::path::PathBuf,
    /// The verification key; `None` ⇒ deny every caller (no default).
    allowlist_key: Option<std::path::PathBuf>,
    allowlist_max_age_secs: i64,
    propose: bool,
    propose_interval: u64,
    /// The daemon's own executable digest, for the proposal's self entry.
    self_sha: Option<[u8; 48]>,
    /// The host-call credentials the sync loop and the registration service
    /// sign with (swapped by [`mia::renewal::Swap`]).
    creds: mia::host_api::CredentialSlot,
    /// The running sync loop (F19), if any: a new SVID makes it sync at once,
    /// and it — not the start-only fetch — refreshes the allowlist.
    sync_trigger: Option<mia::allowlist_sync::SyncTrigger>,
}

/// The configured attestation backend, for the renewal (T294). The settings
/// are read once at start: SIGHUP does not re-read them.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct MainAttestor {
    resolver: mia::endpoint::CmisResolver,
    attest: HostAttestConfig,
    status: mia::status::StatusHandle,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl mia::renewal::HostAttestor for MainAttestor {
    #[allow(clippy::large_futures)] // attestation future holds a composite key
    fn attest(
        &self,
        policy: mia::renewal::KeyPolicy,
    ) -> futures::future::BoxFuture<'_, Result<mia::renewal::Attested, mia::status::AttestFailure>>
    {
        Box::pin(bootstrap_host_svid(
            &self.resolver,
            &self.attest,
            &self.status,
            policy,
        ))
    }
}

/// What a renewal refreshes in the running daemon: the allowlist (sync loop
/// or the legacy fetch and reload) and, once, the allowlist proposals.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct MainHooks<A: mia::helper::auth::CallerAuth> {
    resolver: mia::endpoint::CmisResolver,
    status: mia::status::StatusHandle,
    allowlist_reloader: mia::helper::AllowlistReloader<A>,
    ledger: mia::helper::CallerLedger,
    svid_cell: mia::renewal::SvidCell,
    params: RenewalParams,
    clock: mia::helper::Clock,
    /// The allowlist-propose task runs (it reads `svid_cell` every round).
    propose_started: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl<A: mia::helper::auth::CallerAuth> MainHooks<A> {
    /// The legacy start-only allowlist fetch, repeated after a renewal for a
    /// host without the F19 sync loop.
    async fn reload_allowlist(&self, spiffe_id: &str) {
        let p = &self.params;
        maybe_fetch_allowlist(
            p.allowlist_fetch,
            &p.allowlist_path,
            p.allowlist_key.as_deref(),
            Some(&self.resolver),
            Some(spiffe_id),
        )
        .await;
        match mia::helper::allowlist::load_for_reload(
            &p.allowlist_path,
            p.allowlist_key.as_deref(),
            (self.clock)(),
            p.allowlist_max_age_secs,
        ) {
            Ok((al, outcome)) => {
                let loaded = al.is_some();
                self.status.set_allowlist(outcome);
                self.allowlist_reloader.set(al).await;
                if loaded {
                    tracing::info!("allowlist reloaded after the host SVID renewal");
                } else {
                    tracing::warn!(
                        "allowlist absent or unverified after the host SVID renewal; serving \
                         deny-all (fail closed)"
                    );
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "could not reload the allowlist after the host SVID renewal; keeping the current one"
            ),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl<A: mia::helper::auth::CallerAuth> mia::renewal::RenewalHooks for MainHooks<A> {
    fn after_install<'a>(
        &'a mut self,
        svid: &'a mia::renewal::HostSvid,
    ) -> futures::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            // With the sync loop running and host calls signable, it refreshes
            // the allowlist (F19): wake it now. Otherwise re-run the legacy
            // fetch + reload, so a boot-time failure does not leave every
            // non-self caller denied.
            match (&self.params.sync_trigger, self.params.creds.get().is_some()) {
                (Some(trigger), true) => trigger.sync_now(),
                _ => self.reload_allowlist(&svid.spiffe_id).await,
            }
            // Start proposing the observed callers once (start-up skipped it
            // when there was no host SVID then).
            if self.params.propose && !self.propose_started {
                self.propose_started = maybe_spawn_propose_task(
                    Some(&self.resolver),
                    Some(&svid.spiffe_id),
                    self.svid_cell.clone(),
                    self.ledger.clone(),
                    self.params.self_sha,
                    self.params.propose_interval,
                );
            }
        })
    }
}

/// Spawn the host SVID renewal (T294), one per environment with CMIS
/// configured: it renews the start-up SVID (`session`) or, when start-up
/// failed, re-attests every ~5 minutes (the start-up attempt counts as the
/// first). The receiver resolves to a [`mia::renewal::Fatal`] when the
/// daemon must stop; the task ends when `stop` resolves.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn spawn_renewal_task<A: mia::helper::auth::CallerAuth>(
    attestor: MainAttestor,
    hooks: MainHooks<A>,
    swap: mia::renewal::Swap,
    session: Option<&mia::renewal::Attested>,
    stop: tokio::sync::oneshot::Receiver<()>,
) -> tokio::sync::watch::Receiver<Option<mia::renewal::Fatal>> {
    use mia::renewal::{schedule::REATTEST_INTERVAL, HostRenewer, Renewal};
    let clock = std::sync::Arc::clone(&hooks.clock);
    let status = hooks.status.clone();
    let cmis = attestor.resolver.describe().to_string();
    let dial = attestor.resolver.clone();
    let digest = prefetched_facts().map(|f| *f.fingerprint().as_bytes());
    let mut renewer = HostRenewer::new(
        attestor,
        dial,
        x509_store(),
        hooks,
        swap.clone(),
        status.clone(),
        digest,
    );
    if let Some(s) = session {
        renewer = renewer.with_current(s);
    }
    let mut renewal = Renewal::new(renewer, status);
    let now = clock();
    if let Some(s) = session {
        tracing::info!(
            spiffe_id = %s.svid.spiffe_id,
            expires_at = s.svid.expires_at,
            rotate = s.svid.host_call_key.is_some(),
            "host SVID renewal scheduled (60% of its lifetime, ±10% jitter)"
        );
        renewal = renewal.with_current(s.svid.info(), now);
    } else {
        tracing::info!(
            interval_secs = REATTEST_INTERVAL.as_secs(),
            cmis = %cmis,
            "no host SVID at startup; scheduling background re-attestation"
        );
        let wait = i64::try_from(REATTEST_INTERVAL.as_secs()).unwrap_or(i64::MAX);
        renewal = renewal.with_first_attempt_at(now.saturating_add(wait));
    }
    let stop = async {
        let _ = stop.await;
    };
    mia::renewal::spawn(renewal, swap, move || clock(), stop)
}

/// Bind and serve the helper API with the given caller authenticator. Shared by
/// every supported platform.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
#[allow(clippy::too_many_lines)] // linear startup wiring: attest → bind → spawn background tasks
async fn serve<A>(
    config: &mia::config::Config,
    socket_path: std::path::PathBuf,
    auth: A,
    config_source: mia::config::ConfigSource,
    log_reload: LogReload,
    status: mia::status::StatusHandle,
) -> anyhow::Result<()>
where
    A: mia::helper::auth::CallerAuth,
{
    use anyhow::Context as _;
    use mia::helper::{system_clock, CrlCache, HelperServer, HelperServerConfig};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    let max_age = config.allowlist_max_age();
    let clock = system_clock();

    // Audit sink: the helper API and the allowlist sync push their events
    // here; the forwarder (`mia::audit_forward`, started once the host
    // credentials exist) logs, spools and forwards them to CMIS.
    let (audit_tx, audit_rx) = mpsc::channel(mia::audit_forward::CHANNEL_CAPACITY);

    // Build the CMIS resolver once (static endpoint or SRV-discovered HA
    // cluster), shared by attestation, the allowlist fetch/propose, and the CRL
    // puller. `None` ⇒ CMIS not configured; `Err` ⇒ configured but unusable
    // (both sources set, or a bad pin) — both leave the helper API serving but
    // unable to reach CMIS (it refuses to mint, fail closed), loudly logged
    // rather than crashing.
    let resolver = match mia::endpoint::CmisResolver::from_config(&config.cmis) {
        Ok(Some(r)) => {
            tracing::info!(cmis = %r.describe(), srv = r.is_srv(), "CMIS endpoint configured");
            Some(r)
        }
        Ok(None) => {
            tracing::warn!("CMIS not configured (no cmis.endpoint or cmis.srv); cannot attest");
            status.set_not_configured(mia_status_proto::error_codes::CMIS_NOT_CONFIGURED);
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "CMIS is misconfigured; cannot attest");
            status.set_not_configured(mia_status_proto::error_codes::CMIS_MISCONFIGURED);
            None
        }
    };
    status.set_attest_backend(config.attestation.backend);

    // Say up front whether the X.509-SVID sealed by a previous run still opens
    // on this host. It does not change what happens next — the daemon attests
    // regardless — but a store that stopped opening (a TPM refusing after a
    // firmware change) is worth surfacing at startup rather than at first use.
    if let Some(backend) = report_stored_x509_credential() {
        status.set_x509_store(backend);
    }

    // Attest to CMIS first: a successful attestation yields the host SVID (and
    // thus the EK-derived identity that keys this host's allowlist) and the
    // token minter. When CMIS isn't configured or attestation fails, there is no
    // session — the helper API still serves but refuses to mint (`no_host_svid`).
    let session = match &resolver {
        Some(r) => startup_attest(r, &HostAttestConfig::from_config(config), &status).await,
        None => None,
    };
    let host_spiffe_id = session.as_ref().map(|s| s.svid.spiffe_id.clone());
    // The SVID the allowlist proposals present, swapped by every renewal.
    let svid_cell = mia::renewal::SvidCell::new();
    svid_cell.set(session.as_ref().map(|s| &s.svid));
    // Host-call credentials for the allowlist sync and app registration
    // (F19 §7.1); the renewal task replaces them (and fills them later if
    // this start had none).
    let creds = mia::host_api::CredentialSlot::new();
    creds.set(session.as_ref().and_then(|s| s.svid.credentials()));

    // T291: every audit event is logged locally and, with CMIS configured,
    // spooled (`0600`, state directory) and forwarded through
    // `AppendAuditEvent`, signed with these credentials once they exist. An
    // attested SVID binding no host-call key (TPM tier) can never sign one
    // on this run: log only rather than grow a spool nothing drains.
    let signs_host_calls = host_spiffe_id.is_none() || creds.get().is_some();
    if resolver.is_some() && !signs_host_calls {
        tracing::warn!(
            "host SVID binds no host-call key; audit events are logged locally, not forwarded to CMIS"
        );
    }
    let _audit_forwarder = mia::audit_forward::spawn(
        audit_rx,
        resolver
            .clone()
            .filter(|_| signs_host_calls)
            .map(|r| mia::audit_forward::Forwarding {
                api: Arc::new(mia::audit_forward::ResolverAuditApi::new(r)),
                creds: creds.clone(),
            }),
        &config.audit_spool_path(),
        mia::audit_forward::ForwarderConfig::default(),
    );
    let minter = session.as_ref().map(|s| s.svid.minter.clone());
    if minter.is_none() {
        tracing::warn!(
            "host SVID not present; token minting disabled (returns no_host_svid) until a future attestation succeeds"
        );
    }

    // Optionally refresh the on-disk allowlist from CMIS before loading it, so
    // the served body stays in sync with what the operator provisioned. The
    // F19 sync loop supersedes this start-only fetch when it runs.
    let sync_on = config.allowlist_sync_enabled() && resolver.is_some();
    let allowlist_path = config.allowlist_path();
    // A host whose SVID binds no host-call key (TPM tier today) cannot sync:
    // it keeps the start-only fetch.
    maybe_fetch_allowlist(
        config.allowlist.fetch && !(sync_on && creds.get().is_some()),
        &allowlist_path,
        config.allowlist_key(),
        resolver.as_ref(),
        host_spiffe_id.as_deref(),
    )
    .await;

    // Allowlist: the body at `allowlist.path` (or its per-environment
    // default), verified with `allowlist.key`. Every trust problem — no key,
    // a missing, stale or non-verifying body — denies all callers (fail
    // closed) rather than crashing: a crash here would loop under the service
    // supervisor and unbind the helper socket, hiding the real error behind
    // ECONNREFUSED. Only an explicitly configured allowlist without a key, or
    // one that cannot be read, refuses to start (see `load_for_startup`).
    let (allowlist, outcome) = mia::helper::allowlist::load_for_startup(config, clock())?;
    // With the sync on, the synced body (state directory) wins, and every
    // body must pass the host binding and rollback checks (F19 §6.2).
    let (allowlist, outcome, held) = if sync_on {
        let host = host_spiffe_id
            .as_deref()
            .and_then(mia::host_api::split_host_spiffe_id)
            .map(|(td, uuid)| (uuid, td));
        let f = mia::allowlist_sync::load_in_force(
            &mia::allowlist_sync::SyncConfig::from_config(config),
            (allowlist, outcome),
            host,
            clock(),
        );
        (f.allowlist, f.outcome, f.held)
    } else {
        (allowlist, outcome, None)
    };
    let nothing_in_force = allowlist.is_none();
    status.set_allowlist(outcome);

    // The socket's group: `helper.socket_gid` when set; on macOS, for a socket
    // in the daemon's own `run/` directory, the config directory's group
    // otherwise (`ferrogate-status` after a package install), re-applied to
    // `run/` on every start.
    let socket_dir = mia::helper::socket_dir::plan(config.socket_gid()?, &socket_path);
    let helper_config = HelperServerConfig {
        socket_path: socket_path.clone(),
        // `socket_mode`/`socket_gid`/`own_socket_dir` are Unix-only;
        // `windows_group` is Windows-only. Each transport ignores the fields
        // that don't apply.
        socket_mode: config.socket_mode()?,
        socket_gid: socket_dir.gid,
        own_socket_dir: socket_dir.own_dir,
        windows_group: config.helper.windows_group.clone(),
        max_concurrent: 64,
        read_timeout: Duration::from_secs(5),
    };

    // The CRL cache (feature F11) starts empty and the mint gate fails closed;
    // the puller's first verified pull (within seconds of startup) opens it.
    let crl = Arc::new(CrlCache::new());
    status.set_crl_cache(Arc::clone(&crl));
    maybe_spawn_crl_puller(resolver.clone(), Arc::clone(&crl));
    let services_audit = audit_tx.clone();
    let server = HelperServer::bind(
        helper_config,
        auth,
        minter,
        allowlist,
        crl,
        audit_tx,
        Arc::clone(&clock),
    )
    .with_context(|| {
        format!(
            "binding the helper API listener {} (set helper.socket to move it, or \
             helper.enable = false to switch the helper API off)",
            socket_path.display()
        )
    })?;
    tracing::info!(listener = %socket_path.display(), "helper API listening");

    // F19: app registration behind the helper API, and the allowlist sync
    // loop (which also drives the registration outbox).
    let services = mia::app_services::start(mia::app_services::ServiceInputs {
        config,
        resolver: resolver.clone(),
        creds: creds.clone(),
        sink: Arc::new(server.allowlist_reloader()),
        held,
        sync_now: nothing_in_force,
        audit: services_audit,
        status: status.clone(),
        clock: Arc::clone(&clock),
        ima_enforced: std::env::var("FERROGATE_REQUIRE_IMA").map_or(true, |v| v != "0"),
    });
    if let Some(registrar) = &services.registrar {
        server.set_registration(Arc::new(registrar.clone()));
    }

    // Live config + allowlist reload on SIGHUP: `mia --reload` /
    // `mia resync-allowlist --reload` (or a manual `kill -HUP`) re-reads the
    // configuration file and signed allowlist and swaps them in without a
    // restart, so the helper socket never goes down. Spawned unconditionally so
    // a reload can pick up a newly-added allowlist or a changed log directive;
    // reload mirrors startup's fail-closed semantics.
    #[cfg(unix)]
    spawn_reload_task(
        server.allowlist_reloader(),
        config_source,
        log_reload,
        clock.clone(),
        status.clone(),
        services.sync_trigger.clone(),
    );
    #[cfg(not(unix))]
    let _ = (&config_source, &log_reload, &clock, &status);

    // Optionally propose the callers the helper API observes back to CMIS, so a
    // host with no allowlist can bootstrap its own (subject to CMIS policy).
    let propose_started = config.allowlist.propose
        && maybe_spawn_propose_task(
            resolver.as_ref(),
            host_spiffe_id.as_deref(),
            svid_cell.clone(),
            server.ledger(),
            server.self_sha(),
            config.allowlist_propose_interval(),
        );

    // With CMIS configured, one long-lived task owns the host SVID (T294): it
    // renews it before expiry (Rotate or full attestation), re-attests every
    // few minutes when start-up attestation failed (CMIS or the network not
    // up yet at boot), and switches minting off if the SVID expires anyway.
    let (stop_renewal, renewal_stopped) = tokio::sync::oneshot::channel();
    let fatal = resolver.clone().map(|r| {
        let swap = mia::renewal::Swap::new(
            creds.clone(),
            Arc::new(server.minter_reloader()),
            svid_cell.clone(),
        );
        let attestor = MainAttestor {
            resolver: r.clone(),
            attest: HostAttestConfig::from_config(config),
            status: status.clone(),
        };
        let hooks = MainHooks {
            resolver: r,
            status: status.clone(),
            allowlist_reloader: server.allowlist_reloader(),
            ledger: server.ledger(),
            svid_cell: svid_cell.clone(),
            params: RenewalParams {
                allowlist_fetch: config.allowlist.fetch,
                allowlist_path,
                allowlist_key: config.allowlist_key().map(std::path::Path::to_path_buf),
                allowlist_max_age_secs: max_age,
                propose: config.allowlist.propose,
                propose_interval: config.allowlist_propose_interval(),
                self_sha: server.self_sha(),
                creds: creds.clone(),
                sync_trigger: services.sync_trigger.clone(),
            },
            clock: clock.clone(),
            propose_started,
        };
        spawn_renewal_task(attestor, hooks, swap, session.as_ref(), renewal_stopped)
    });
    drop(session);

    // Serve until asked to stop, or until the renewal task stops the daemon
    // (CMIS issued another identity, or the task died): then return an error
    // so the supervisor restarts it.
    let fatal_wait = fatal.clone();
    server
        .serve_with_shutdown(async move {
            tokio::select! {
                () = shutdown_signal() => {}
                f = mia::renewal::next_fatal(fatal_wait) => {
                    tracing::error!(error = %f, "stopping the helper API");
                }
            }
        })
        .await;
    drop(stop_renewal);
    if let Some(f) = fatal.and_then(|rx| rx.borrow().clone()) {
        anyhow::bail!("{f}; restart the agent");
    }
    tracing::info!("helper API shut down cleanly");
    Ok(())
}

/// Fallback for platforms with no helper transport (neither Unix nor Windows).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[allow(clippy::unused_async)] // async to match the cross-platform signature
async fn start_helper_api(
    _config: &mia::config::Config,
    _config_source: mia::config::ConfigSource,
    _log_reload: LogReload,
    _status: mia::status::StatusHandle,
) -> anyhow::Result<()> {
    anyhow::bail!("unsupported platform: mia's helper API runs on Linux, macOS, and Windows")
}

/// Install a `SIGHUP` handler that re-reads the configuration file and the
/// signed allowlist and live-swaps them into the running server, so a
/// `mia --reload` (or a re-synced allowlist) takes effect without a restart
/// (which would briefly unbind the helper socket).
///
/// The reload covers the parts that are safe to change live: the `log`
/// verbosity directive and the allowlist (`allowlist.path`/`key`/
/// `max_age_secs`). Settings that pin process-wide state at startup — the helper
/// socket, the CMIS endpoint, attestation inputs, the hardening profile — are
/// intentionally *not* re-applied here; they require a restart.
///
/// Reload mirrors `load_at_startup`: a missing or non-verifying body at the
/// resolved path (`allowlist.path` or its per-environment default), or a
/// verification key that has been removed from the config, swaps in deny-all
/// (fail closed); an unexpected I/O error keeps the current allowlist. A config file
/// that no longer parses is logged and the previous configuration is kept.
#[cfg(unix)]
fn spawn_reload_task<A>(
    reloader: mia::helper::AllowlistReloader<A>,
    config_source: mia::config::ConfigSource,
    log_reload: LogReload,
    clock: mia::helper::Clock,
    status: mia::status::StatusHandle,
    sync_trigger: Option<mia::allowlist_sync::SyncTrigger>,
) where
    A: mia::helper::auth::CallerAuth,
{
    use tokio::signal::unix::{signal, SignalKind};

    let mut hup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not install SIGHUP handler; live config/allowlist reload disabled");
            return;
        }
    };
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            tracing::info!("SIGHUP received; reloading configuration and signed allowlist");
            // Re-read the file the daemon was started with, re-overlaying the
            // environment, exactly as at startup (same --config/--environment).
            let config = match config_source.load() {
                Ok((config, _source)) => config,
                Err(e) => {
                    tracing::warn!(error = %e, "config reload failed to parse; keeping the current configuration and allowlist");
                    continue;
                }
            };

            // Log verbosity can change live.
            log_reload(config.log_directive());

            // With the F19 sync loop running, only it puts allowlists in
            // force (host binding, rollback checks): a reload asks it to sync
            // now instead of re-reading a body from disk. Turning the sync
            // off takes a restart.
            if let Some(trigger) = &sync_trigger {
                trigger.sync_now();
                tracing::info!("configuration reloaded; allowlist sync requested");
                continue;
            }

            // Allowlist: re-load from the (possibly changed) path/key/max-age.
            // The body falls back to its per-environment default; without a
            // verification key nothing can verify it, so fail closed.
            match mia::helper::allowlist::load_for_reload(
                &config.allowlist_path(),
                config.allowlist_key(),
                clock(),
                config.allowlist_max_age(),
            ) {
                // `load_at_startup` already logs loudly on a missing or
                // non-verifying body or key; here we only note the swap outcome.
                Ok((al, outcome)) => {
                    let loaded = al.is_some();
                    status.set_allowlist(outcome);
                    reloader.set(al).await;
                    if loaded {
                        tracing::info!(
                            "configuration and signed allowlist reloaded and swapped in live"
                        );
                    } else {
                        tracing::warn!("reloaded allowlist absent or unverified; serving deny-all (fail closed)");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "allowlist reload failed (I/O); keeping the current allowlist");
                }
            }
        }
    });
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

/// Broadcast stop signal for the Windows service path. A `watch` channel so
/// every environment's serve loop sees the stop (and so a stop that arrives
/// before a loop subscribes is not missed); `send` is callable from the SCM
/// control thread, which has no async context.
#[cfg(windows)]
fn service_stop_signal() -> &'static tokio::sync::watch::Sender<bool> {
    static TX: std::sync::OnceLock<tokio::sync::watch::Sender<bool>> = std::sync::OnceLock::new();
    TX.get_or_init(|| tokio::sync::watch::channel(false).0)
}

/// Resolve when the process is asked to stop on Windows: Ctrl-C / Ctrl-Break
/// (interactive) or a Service Control Manager Stop/Shutdown (via the watch flag
/// set by [`service_request_stop`]).
#[cfg(windows)]
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let service_stop = async {
        let mut rx = service_stop_signal().subscribe();
        // Returns immediately if a stop was already requested.
        let _ = rx.wait_for(|&stop| stop).await;
    };
    tokio::select! {
        () = ctrl_c => tracing::info!("received Ctrl-C; shutting down"),
        () = service_stop => tracing::info!("received service stop; shutting down"),
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests {
    use super::{host_uuid_from_spiffe_id, proposal_entries};

    #[test]
    fn proposal_carries_observed_uids_plus_wildcard_self_entry() {
        let snapshot = vec![(1000, [0xAA; 48]), (503, [0xBB; 48])];
        let entries = proposal_entries(&snapshot, Some([0xCC; 48]));
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].uid, Some(1000));
        assert_eq!(entries[0].bin_sha, hex::encode([0xAA; 48]));
        assert_eq!(entries[1].uid, Some(503));
        // The self entry is uid-wildcard, mirroring the helper API's self-trust.
        assert_eq!(entries[2].uid, None);
        assert_eq!(entries[2].bin_sha, hex::encode([0xCC; 48]));
    }

    #[test]
    fn empty_ledger_still_yields_the_self_registration_entry() {
        let entries = proposal_entries(&[], Some([0xCC; 48]));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, None);
    }

    #[test]
    fn no_self_sha_yields_only_observed_entries() {
        assert_eq!(
            proposal_entries(&[], None),
            [] as [ferro_svid::AllowEntry; 0]
        );
        let entries = proposal_entries(&[(0, [0x11; 48])], None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, Some(0));
    }

    #[test]
    fn extracts_host_uuid_from_spiffe_id() {
        let uuid = "11111111-1111-8111-8111-111111111111";
        assert_eq!(
            host_uuid_from_spiffe_id(&format!("spiffe://ferrogate.test/host/{uuid}")),
            Some(uuid)
        );
    }

    #[test]
    fn rejects_ids_without_a_host_segment() {
        assert_eq!(
            host_uuid_from_spiffe_id("spiffe://ferrogate.test/cmis"),
            None
        );
        assert_eq!(
            host_uuid_from_spiffe_id("spiffe://ferrogate.test/host/"),
            None
        );
        assert_eq!(host_uuid_from_spiffe_id(""), None);
    }
}
