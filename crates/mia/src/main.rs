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
//! - `FERROGATE_HELPER_SOCKET` (`helper.socket`) — socket path; its presence
//!   enables the helper API. Absent ⇒ the daemon logs a banner and exits.
//! - `FERROGATE_HELPER_SOCKET_MODE` (`helper.socket_mode`) — octal socket mode
//!   (default `660`).
//! - `FERROGATE_HELPER_SOCKET_GID` (`helper.socket_gid`) — numeric gid to own
//!   the socket so that group's members may open it (Unix only; set by
//!   `make mia-install` to the dedicated FerroGate group).
//! - `FERROGATE_ALLOWLIST` (`allowlist.path`) — path to the signed CBOR
//!   allowlist. Absent ⇒ the API denies every caller (fail closed).
//! - `FERROGATE_ALLOWLIST_KEY` (`allowlist.key`) — path to the trusted CMIS
//!   enrollment public key used to verify the allowlist. Required whenever the
//!   allowlist is set.
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
        Some("refresh-key") => return mia::resync::run_refresh_key(&args[1..]),
        // `--reload` is a management flag, not a daemon option: it signals the
        // running agent (SIGHUP) to re-read its config + allowlist, then exits.
        Some("--reload") => return mia::resync::run_reload(&args[1..]),
        Some("test") => return mia::selftest::run(&args[1..]),
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

    // An explicit selection (`--config`, `--environment`, or `$FERROGATE_CONFIG`)
    // serves exactly that one configuration. Otherwise the daemon serves *every*
    // discovered environment (`mia.toml` + `mia-<env>.toml`), attesting to each
    // CMIS and exposing each environment's own helper socket, so a local caller
    // can fetch tokens for whichever environment it needs.
    let explicit = config_source.path.is_some()
        || config_source.environment.is_some()
        || std::env::var_os(mia::config::ENV_CONFIG).is_some();

    // Resolve the configuration before logging/hardening: it gives us the log
    // directive, and a malformed file must fail loudly and early. The primary
    // config supplies the process-wide log directive; in all-environments mode
    // that is the default `mia.toml` (env/defaults if it is absent).
    let primary_source = if explicit {
        config_source.clone()
    } else {
        mia::config::ConfigSource::default()
    };
    let (primary_config, primary_path) = primary_source.load()?;

    // A reloadable filter layer: SIGHUP re-reads the config and applies a
    // changed `log` directive live (see `spawn_reload_task`).
    let filter = EnvFilter::try_new(primary_config.log_directive())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, filter_handle) = reload::Layer::new(filter);
    // Under the Windows SCM there is no console, so route logs to a file beside
    // the system config (%ProgramData%\FerroGate\logs\mia.log). Every other run
    // logs to stdout, where systemd/launchd or the operator's terminal sees it.
    let (writer, ansi) = log_writer(service_log)?;
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_ansi(ansi).with_writer(writer))
        .init();
    let log_reload: LogReload = Arc::new(move |directive: &str| {
        match EnvFilter::try_new(directive) {
            Ok(f) => {
                let _ = filter_handle.reload(f);
            }
            Err(e) => {
                tracing::warn!(directive, error = %e, "ignoring invalid log directive on reload");
            }
        }
    });

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        component = "mia",
        "FerroGate Machine Identity Agent"
    );

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
            label,
            config: primary_config,
            source: config_source,
        }]
    } else {
        let discovered = mia::config::discover_environment_configs();
        if discovered.is_empty() {
            tracing::debug!("no configuration files found; using environment and defaults");
            vec![EnvInstance {
                label: "default".to_string(),
                config: primary_config,
                source: mia::config::ConfigSource::default(),
            }]
        } else {
            tracing::info!(count = discovered.len(), "serving all discovered environments");
            let mut instances = Vec::new();
            for d in discovered {
                let label = d.environment.clone().unwrap_or_else(|| "default".to_string());
                // Load each by its concrete path (no env-name re-resolution).
                // Named environments load shared-only, so a process-wide
                // FERROGATE_HELPER_SOCKET (e.g. from a pre-0.19 launchd plist)
                // can't force them all onto the default environment's socket.
                let source = mia::config::ConfigSource {
                    path: Some(d.path.clone()),
                    environment: None,
                    discovered_named_env: d.environment.is_some(),
                };
                match source.load() {
                    Ok((config, _)) => {
                        tracing::info!(env = %label, config = %d.path.display(), "loaded environment configuration");
                        instances.push(EnvInstance {
                            label,
                            config,
                            source,
                        });
                    }
                    // One broken environment must not take down the others.
                    Err(e) => tracing::error!(
                        env = %label, config = %d.path.display(), error = %e,
                        "skipping environment: its configuration failed to load"
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
    prepare_and_harden(&instances)?;

    // Build the multi-threaded runtime by hand (rather than `#[tokio::main]`) so
    // hardening runs first. `enable_all` wires the I/O and time drivers the
    // helper server and CMIS client need.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_all(instances, log_reload))
}

/// One environment the daemon serves: its display label (`"default"` or the
/// environment name), its loaded configuration, and the [`ConfigSource`] to
/// re-read on SIGHUP.
struct EnvInstance {
    label: String,
    config: mia::config::Config,
    source: mia::config::ConfigSource,
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
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating service log directory {}", dir.display()))?;
        let path = dir.join("mia.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
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
        Some("stop") => {
            ferro_winauth::service::stop()?;
            println!("stopped the 'mia' service.");
            Ok(())
        }
        Some(other) => anyhow::bail!(
            "unknown service subcommand: {other}\n\nusage: mia service <install|uninstall|start|stop>"
        ),
        None => {
            println!(
                "usage: mia service <install|uninstall|start|stop>\n\n\
                 Manage the mia Windows service so it runs in the background and\n\
                 `Restart-Service mia` works. `install` registers an auto-start\n\
                 LocalSystem service that runs `mia service run` (used internally\n\
                 by the Service Control Manager)."
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
    anyhow::bail!("the `service` command manages the Windows service and is only available on Windows")
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
         \x20 refresh-key       re-fetch the CMIS enrollment key into allowlist.key\n\
         \x20 resync-allowlist  re-fetch this host's signed allowlist from CMIS\n\
         \x20 test              check CMIS connectivity and helper-token issuance\n\
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

/// Daemon entry point. Serves every environment instance that has a helper
/// socket configured, concurrently, in this one process — each attesting to its
/// own CMIS and exposing its own helper socket. Environments without a helper
/// socket are idle (logged, not served); a duplicate socket across environments
/// is skipped (each needs a distinct `helper.socket`). With nothing to serve it
/// prints the idle banner and exits.
// The serve path holds a composite key (~4 KB ML-DSA) across awaits during
// attestation; the large future is inherent, not a bug.
#[allow(clippy::large_futures)]
async fn run_all(instances: Vec<EnvInstance>, log_reload: LogReload) -> anyhow::Result<()> {
    use std::collections::HashSet;

    // Keep only environments that actually serve a socket, rejecting duplicates
    // so the second bind on a shared path can't crash-loop the first.
    let mut seen_sockets: HashSet<std::path::PathBuf> = HashSet::new();
    let mut serveable: Vec<EnvInstance> = Vec::new();
    for inst in instances {
        match inst.config.helper_socket() {
            None => tracing::info!(
                env = %inst.label,
                "no helper socket configured for this environment; not serving it"
            ),
            Some(socket) => {
                if seen_sockets.insert(socket.to_path_buf()) {
                    serveable.push(inst);
                } else {
                    // Name the likely culprit when the colliding path matches a
                    // process-wide FERROGATE_HELPER_SOCKET override.
                    let from_env_override = std::env::var_os("FERROGATE_HELPER_SOCKET")
                        .is_some_and(|v| std::path::Path::new(&v) == socket);
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
                "mia v{} — daemon idle; no environment has a helper socket configured \
                 (helper.socket / FERROGATE_HELPER_SOCKET) to start the helper API.",
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
    } = instance;
    let span = tracing::info_span!("env", environment = %label);
    async move {
        if let Err(e) = start_helper_api(&config, source, log_reload).await {
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
    let EnvInstance { config, source, .. } = instance;
    start_helper_api(&config, source, log_reload).await
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
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let socket_path = config
        .helper_socket()
        .context("internal: start_helper_api called without a helper socket")?
        .to_path_buf();
    serve(config, socket_path, build_auth(config), config_source, log_reload).await
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
    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from("/var/lib/ferrogate")
    }
    #[cfg(not(target_os = "linux"))]
    {
        mia::config::system_config_path()
            .parent()
            .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf)
    }
}

/// Resolve where the persistent machine signing key lives — in the service
/// [`state_dir`] (e.g. `/var/lib/ferrogate/host-key.bin` on Linux).
fn host_key_path() -> std::path::PathBuf {
    state_dir().join("host-key.bin")
}

/// Resolve where this host's persistent SVID seed lives — beside the machine
/// signing key. The 32-byte seed deterministically derives the composite SVID
/// keypair (`CompositeSecretKey::from_seed`), so a daemon restart re-attests
/// under the *same* key and keeps the same child-signing `kid` — and thus the
/// same JWKS entry on CMIS — instead of rotating it every boot.
fn svid_seed_path() -> std::path::PathBuf {
    state_dir().join("svid-seed.bin")
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
/// it drops: the machine fingerprint (root-only DMI serials) is prefetched, and
/// the directories the unprivileged process will write — each environment's
/// helper-socket directory plus the [`state_dir`] holding the machine key and
/// SVID seed — are created and handed to the `_ferrogate` user. Only then does
/// [`hardening::harden`] drop privileges. Fatal on failure: a MIA that cannot
/// harden must not serve.
fn prepare_and_harden(instances: &[EnvInstance]) -> anyhow::Result<()> {
    // Prefetch the fingerprint on every platform so attestation reads it the
    // same way; on Linux it is the only chance to read the root-only DMI files.
    prefetch_machine_facts();

    #[cfg(target_os = "linux")]
    {
        let mut dirs = vec![state_dir()];
        for inst in instances {
            if let Some(parent) = inst.config.helper_socket().and_then(std::path::Path::parent) {
                dirs.push(parent.to_path_buf());
            }
        }
        mia::hardening::prepare_runtime_paths(&dirs)?;
        mia::hardening::harden()?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = instances;
        tracing::debug!(
            "hardening profile (seccomp/mlockall/privilege-drop) applies on Linux only"
        );
    }
    Ok(())
}

/// Load the persistent 32-byte SVID seed, generating and persisting a fresh one
/// (`0600`) if the file is absent or malformed. The seed is a subordinate secret
/// — anyone who can read it already has the machine key beside it — so it is
/// stored with the same protection as `host-key.bin` rather than separately
/// sealed.
fn load_or_create_svid_seed(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use rand_core::{OsRng, RngCore};

    match std::fs::read(path) {
        Ok(bytes) => {
            if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(seed);
            }
            tracing::warn!(
                path = %path.display(),
                "SVID seed file has the wrong length; regenerating (the child-signing kid will change once)"
            );
        }
        // Absent on first boot — create it. Any other error (e.g. permission
        // denied) is propagated so we never overwrite an unreadable seed.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    write_secret_file(path, &seed)?;
    Ok(seed)
}

/// Write `bytes` to `path` as an owner-only (`0600`) secret, creating or
/// truncating the file.
///
/// On Unix the mode is applied by `open(2)` at creation, so the bytes are never
/// briefly world-readable *and* no separate `chmod` is needed — the hardened
/// seccomp profile deliberately forbids `chmod` (see `ferro-harden`), so a
/// post-write `set_permissions` would be killed with `SIGSYS` once the daemon
/// has dropped privileges.
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Bootstrap the host SVID via the TPM-less **host-key** attestation profile
/// (feature F15) and build the child-token minter the helper API mints with.
///
/// Returns `None` — with a logged reason — when CMIS is not configured, the
/// platform has no hardware fingerprint, or attestation fails. In every such
/// case the helper API still starts; it just refuses to mint (`no_host_svid`)
/// until a later attempt succeeds.
///
/// The signing key is a persistent [`ferro_sep::SoftwareMachineKey`]. Upgrading
/// the daemon to a non-exportable Secure-Enclave key needs keychain-backed
/// persistence in `ferro-sep` (see docs/features/F15.md) — the SEP backend's
/// cryptographic core is already proven by `ferro-sep`'s live test.
#[allow(clippy::too_many_lines)] // linear bootstrap: dial → attest → build minter
#[allow(clippy::large_futures)] // holds a composite key (~4 KB ML-DSA) across awaits
async fn bootstrap_host_svid_host_key(
    resolver: &mia::endpoint::CmisResolver,
) -> Option<HostSession> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ferro_sep::MachineKey as _;
    use sha2::{Digest, Sha256};

    let Some(facts) = prefetched_facts() else {
        tracing::warn!("no hardware fingerprint available; host-key attestation skipped");
        return None;
    };
    let key_path = host_key_path();
    // Seal the software key at rest to the hardware fingerprint: a key file
    // copied to another host won't decrypt there (its fingerprint differs). This
    // is clone resistance bound to machine identity, not a hardware root of
    // trust — see docs/features/F16.
    let key = match ferro_sep::SoftwareMachineKey::open_or_create_sealed(
        &key_path,
        facts.fingerprint().as_bytes(),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, path = %key_path.display(), "cannot open machine signing key");
            return None;
        }
    };

    // Host DPoP confirmation key thumbprint. A host-bound stand-in derived from
    // the machine key until the host DPoP key (F09) is wired; CMIS records it as
    // the SVID's `cnf.jkt`.
    let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(key.public_spki_der()));

    // Resolve + dial CMIS with fail-over (static endpoint or SRV-discovered HA
    // cluster); a successful pinned handshake selects a live node.
    let (endpoint, mut client) = match resolver.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, cmis = %resolver.describe(), "could not connect to CMIS for attestation");
            return None;
        }
    };
    // Recover (or first-boot create) the persistent SVID seed so the composite
    // key — and therefore the child-signing kid and its JWKS entry — is stable
    // across restarts. If the seed cannot be persisted we fall back to an
    // ephemeral key: minting still works, the kid just rotates as it did before.
    let seed_path = svid_seed_path();
    let seed = match load_or_create_svid_seed(&seed_path) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %seed_path.display(),
                "cannot persist the SVID seed; using an ephemeral key (the child-signing kid will rotate on restart)"
            );
            None
        }
    };
    let attested =
        match mia::client::run_attest_host_key(&mut client, facts, &key, dpop_jkt, seed.as_ref())
            .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(error = %e, "host-key attestation failed");
                return None;
            }
        };

    tracing::info!(
        spiffe_id = %attested.bundle.spiffe_id,
        fingerprint = %facts.fingerprint().to_hex(),
        cmis = %endpoint,
        "host SVID obtained via host-key attestation; token minting enabled"
    );
    Some(host_session_from_attested(attested))
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
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn bootstrap_host_svid(
    resolver: &mia::endpoint::CmisResolver,
    attest: &HostAttestConfig,
) -> Option<HostSession> {
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
    match effective {
        AttestBackend::Auto => None, // unreachable: resolved above
        AttestBackend::Tpm => bootstrap_host_svid_tpm(resolver, attest).await,
        AttestBackend::HostKey => bootstrap_host_svid_host_key(resolver).await,
        AttestBackend::VirtualTpm => bootstrap_host_svid_virtual_tpm(resolver).await,
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
) -> Option<HostSession> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use mia::client::AttestEvidence as _;
    use mia::tpm::{TpmEngine, TpmEvidence};
    use sha2::{Digest, Sha256};

    let Some(ek_cert_path) = attest.tpm_ek_cert.as_deref() else {
        tracing::error!(
            "attestation.backend = \"tpm\" but attestation.tpm.ek_cert is not configured; \
             refusing to attest (fail closed)"
        );
        return None;
    };
    let ek_cert = match std::fs::read(ek_cert_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, path = %ek_cert_path.display(), "cannot read attestation.tpm.ek_cert");
            return None;
        }
    };
    let mut ek_intermediates = Vec::with_capacity(attest.tpm_ek_intermediates.len());
    for p in &attest.tpm_ek_intermediates {
        match std::fs::read(p) {
            Ok(b) => ek_intermediates.push(b),
            Err(e) => {
                tracing::error!(error = %e, path = %p.display(), "cannot read an attestation.tpm.ek_intermediates entry");
                return None;
            }
        }
    }

    let engine = match TpmEngine::open_device() {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "cannot open the TPM device (/dev/tpmrm0); refusing to attest (fail closed)");
            return None;
        }
    };
    let mut evidence = match TpmEvidence::new(engine, ek_cert, ek_intermediates) {
        Ok(ev) => ev,
        Err(e) => {
            tracing::error!(error = %e, "cannot initialize TPM attestation evidence (EK/AIK)");
            return None;
        }
    };

    let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(evidence.aik_pub()));

    let (endpoint, mut client) = match resolver.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, cmis = %resolver.describe(), "could not connect to CMIS for attestation");
            return None;
        }
    };
    let attested = match mia::client::run_attest(&mut client, &mut evidence, dpop_jkt).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "TPM attestation failed");
            return None;
        }
    };
    tracing::info!(
        spiffe_id = %attested.bundle.spiffe_id,
        cmis = %endpoint,
        "host SVID obtained via TPM attestation; token minting enabled"
    );
    Some(host_session_from_attested(attested))
}

/// Fallback when the `tpm` backend is selected on a non-Linux host, where mia is
/// built without a TSS2 stack: refuse to attest (fail closed) rather than
/// silently downgrading to a different identity path.
#[cfg(all(not(target_os = "linux"), any(target_os = "macos", windows)))]
#[allow(clippy::unused_async)] // matches the Linux signature the dispatcher awaits
async fn bootstrap_host_svid_tpm(
    _resolver: &mia::endpoint::CmisResolver,
    _attest: &HostAttestConfig,
) -> Option<HostSession> {
    tracing::error!(
        "attestation.backend = \"tpm\" is only supported on Linux (it needs a TSS2 stack); \
         refusing to attest (fail closed). Use \"host-key\" on this platform."
    );
    None
}

/// Build the running [`HostSession`] (token minter + host identity) from a
/// completed attestation, regardless of which backend produced it.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn host_session_from_attested(attested: mia::client::AttestedSvid) -> HostSession {
    use mia::helper::{ChildTokenMinter, MinterConfig};
    use sha2::{Digest, Sha384};

    let mut parent = [0u8; 48];
    parent.copy_from_slice(&Sha384::digest(attested.bundle.jws.as_bytes()));
    let cfg = MinterConfig {
        host_spiffe_id: attested.bundle.spiffe_id.clone(),
        parent_svid_sha384: parent,
        kid: ferro_svid::child_signing_kid(&attested.svid_public),
    };
    HostSession {
        spiffe_id: attested.bundle.spiffe_id.clone(),
        jws: attested.bundle.jws.clone(),
        minter: ChildTokenMinter::new(attested.svid_secret, cfg),
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
) -> Option<HostSession> {
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
            return None;
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
            return None;
        }
    };
    let attested = match mia::client::run_attest(&mut client, &mut vtpm, dpop_jkt).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "virtual-TPM attestation failed");
            return None;
        }
    };
    tracing::info!(
        spiffe_id = %attested.bundle.spiffe_id,
        cmis = %endpoint,
        "host SVID obtained via virtual-TPM attestation; token minting enabled"
    );
    Some(host_session_from_attested(attested))
}

/// Fallback when the daemon was built without the `virtual-tpm` feature but the
/// config selects that backend: refuse to attest rather than silently fall back
/// to a different identity path (fail closed).
#[cfg(all(
    not(feature = "virtual-tpm"),
    any(target_os = "linux", target_os = "macos", windows)
))]
async fn bootstrap_host_svid_virtual_tpm(
    _resolver: &mia::endpoint::CmisResolver,
) -> Option<HostSession> {
    tracing::error!(
        "attestation.backend = \"virtual-tpm\" but mia was built without the `virtual-tpm` cargo \
         feature; refusing to attest (fail closed). Rebuild with `--features virtual-tpm` for \
         dev/test, or set attestation.backend = \"host-key\"."
    );
    None
}

/// The outcome of a successful host attestation: the token minter the helper API
/// mints with, plus the host's SVID SPIFFE id (its EK/fingerprint-derived
/// identity, used to key the host's allowlist fetch).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct HostSession {
    minter: mia::helper::ChildTokenMinter,
    spiffe_id: String,
    /// The host's compact-JWS SVID, presented when proposing an allowlist.
    jws: String,
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
/// (keyed by its EK-derived host UUID) and write it to `allowlist.path` before
/// the daemon loads it. Every failure mode is non-fatal and logged: the daemon
/// then falls back to whatever is already on disk (or fails closed if nothing
/// is), exactly as if auto-fetch were off.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn maybe_fetch_allowlist(
    fetch: bool,
    allowlist_path: Option<&std::path::Path>,
    resolver: Option<&mia::endpoint::CmisResolver>,
    host_spiffe_id: Option<&str>,
) {
    if !fetch {
        return;
    }
    let Some(path) = allowlist_path else {
        tracing::warn!("allowlist.fetch is set but allowlist.path is unset; nothing to write");
        return;
    };
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
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn write_allowlist_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
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
/// Every precondition failure logs and returns without spawning — proposing is
/// strictly opt-in best-effort. The SVID presented is the one obtained at
/// startup; once it expires CMIS rejects further proposals until mia restarts
/// (scheduled re-attestation is a follow-up).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::too_many_lines)] // precondition checks + the periodic loop.
fn maybe_spawn_propose_task(
    resolver: Option<&mia::endpoint::CmisResolver>,
    host_spiffe_id: Option<&str>,
    host_jws: Option<String>,
    ledger: mia::helper::CallerLedger,
    self_sha: Option<[u8; 48]>,
    propose_interval_secs: u64,
) {
    use ferro_sep::MachineKey as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(spiffe_id) = host_spiffe_id else {
        tracing::warn!("allowlist.propose is set but no host SVID this start; not proposing");
        return;
    };
    let Some(jws) = host_jws else {
        tracing::warn!("allowlist.propose is set but host SVID JWS is missing; not proposing");
        return;
    };
    let Some(host_uuid) = host_uuid_from_spiffe_id(spiffe_id).map(str::to_string) else {
        tracing::warn!(%spiffe_id, "could not derive host UUID; not proposing");
        return;
    };
    let Some(resolver) = resolver.cloned() else {
        tracing::warn!("allowlist.propose is set but CMIS is not configured; not proposing");
        return;
    };
    // Open the same machine key the host-key bootstrap uses. It is sealed to the
    // hardware fingerprint when one is available (matching `bootstrap_host_svid_host_key`);
    // a host with no fingerprint (e.g. the TPM backend) falls back to the plaintext key.
    let key_path = host_key_path();
    let key = match prefetched_facts() {
        Some(facts) => {
            ferro_sep::SoftwareMachineKey::open_or_create_sealed(&key_path, facts.fingerprint().as_bytes())
        }
        None => ferro_sep::SoftwareMachineKey::open_or_create(&key_path),
    };
    let key = match key {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "cannot open machine key; not proposing");
            return;
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
            match mia::client::propose_allowlist(
                &mut client,
                body,
                sig,
                jws.clone(),
                sep_pub.clone(),
            )
            .await
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

/// How often the background re-attestation task retries after a failed startup
/// attestation. Five minutes balances quick recovery (the network coming up
/// shortly after boot) against load on CMIS for a host that stays offline.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const REATTEST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// The owned configuration the re-attestation task needs to finish wiring up a
/// late-arriving host SVID (refresh the allowlist, optionally start proposing).
/// Captured before the task is spawned because [`mia::config::Config`] is
/// borrowed for the lifetime of `serve` and the task must be `'static`.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct ReattestParams {
    allowlist_fetch: bool,
    allowlist_path: Option<std::path::PathBuf>,
    allowlist_key: Option<std::path::PathBuf>,
    allowlist_max_age_secs: i64,
    propose: bool,
    propose_interval: u64,
    /// The daemon's own executable digest, for the proposal's self entry.
    self_sha: Option<[u8; 48]>,
    /// The attestation inputs (backend + TPM EK chain) the background
    /// re-attestation uses.
    attest: HostAttestConfig,
}

/// When startup attestation fails — CMIS unreachable, or (commonly) DNS/VPN not
/// up yet right after boot — the daemon serves but cannot mint: every caller
/// gets `no_host_svid`. Rather than wait for a manual restart, retry host-key
/// attestation every [`REATTEST_INTERVAL`]. The first success live-swaps the
/// minter into the running server (minting on, no restart), refreshes the signed
/// allowlist from CMIS, and — if configured — starts the allowlist-propose task;
/// then the task exits. Mirrors the CRL puller's stance that CMIS being down at
/// boot must not permanently disable minting ([`maybe_spawn_crl_puller`]).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
fn spawn_reattest_task<A>(
    resolver: mia::endpoint::CmisResolver,
    minter_reloader: mia::helper::MinterReloader<A>,
    allowlist_reloader: mia::helper::AllowlistReloader<A>,
    ledger: mia::helper::CallerLedger,
    params: ReattestParams,
    clock: mia::helper::Clock,
) where
    A: mia::helper::auth::CallerAuth,
{
    tracing::info!(
        interval_secs = REATTEST_INTERVAL.as_secs(),
        cmis = %resolver.describe(),
        "no host SVID at startup; scheduling background re-attestation"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REATTEST_INTERVAL);
        // The first tick fires immediately; the startup attempt already failed,
        // so wait a full interval before retrying.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(session) = bootstrap_host_svid(&resolver, &params.attest).await else {
                continue; // the failure is logged inside bootstrap; retry next tick
            };
            let spiffe_id = session.spiffe_id.clone();
            let jws = session.jws.clone();

            // 1. Switch minting on now that we hold a host SVID.
            minter_reloader.set(Some(session.minter)).await;
            tracing::info!(%spiffe_id, "re-attestation succeeded; token minting enabled");

            // 2. Refresh the signed allowlist from CMIS and live-swap it. Without
            //    this, minting is on but every non-self caller is denied
            //    (not-allowlisted) when the on-disk allowlist was missing or
            //    expired at startup — exactly the state a boot-time failure leaves.
            maybe_fetch_allowlist(
                params.allowlist_fetch,
                params.allowlist_path.as_deref(),
                Some(&resolver),
                Some(&spiffe_id),
            )
            .await;
            match (params.allowlist_path.as_deref(), params.allowlist_key.as_deref()) {
                (Some(path), Some(key)) => {
                    match mia::helper::allowlist::load_at_startup(
                        path,
                        key,
                        clock(),
                        params.allowlist_max_age_secs,
                    ) {
                        Ok(al) => {
                            let loaded = al.is_some();
                            allowlist_reloader.set(al).await;
                            if loaded {
                                tracing::info!("allowlist reloaded after re-attestation");
                            } else {
                                tracing::warn!(
                                    "allowlist absent or unverified after re-attestation; serving deny-all (fail closed)"
                                );
                            }
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "could not reload allowlist after re-attestation; keeping current"
                        ),
                    }
                }
                (Some(_), None) => tracing::warn!(
                    "allowlist.path set but allowlist.key missing; not reloading after re-attestation"
                ),
                (None, _) => {}
            }

            // 3. Start proposing the observed callers back to CMIS, if configured
            //    (startup skipped this because there was no host SVID then).
            if params.propose {
                maybe_spawn_propose_task(
                    Some(&resolver),
                    Some(&spiffe_id),
                    Some(jws),
                    ledger,
                    params.self_sha,
                    params.propose_interval,
                );
            }
            return; // host SVID obtained; nothing left to retry
        }
    });
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

    // Audit sink: a forwarder task drains helper events. For now it logs them;
    // CMIS forwarding rides on F07's `AppendAuditEvent` path (`audit_client`).
    let (audit_tx, mut audit_rx) = mpsc::channel(256);
    tokio::spawn(async move {
        while let Some(event) = audit_rx.recv().await {
            tracing::info!(?event, "helper-api audit event");
        }
    });

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
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "CMIS is misconfigured; cannot attest");
            None
        }
    };

    // Attest to CMIS first: a successful attestation yields the host SVID (and
    // thus the EK-derived identity that keys this host's allowlist) and the
    // token minter. When CMIS isn't configured or attestation fails, there is no
    // session — the helper API still serves but refuses to mint (`no_host_svid`).
    let session = match &resolver {
        Some(r) => bootstrap_host_svid(r, &HostAttestConfig::from_config(config)).await,
        None => None,
    };
    let host_spiffe_id = session.as_ref().map(|s| s.spiffe_id.clone());
    let host_jws = session.as_ref().map(|s| s.jws.clone());
    let minter = session.map(|s| s.minter);
    if minter.is_none() {
        tracing::warn!(
            "host SVID not present; token minting disabled (returns no_host_svid) until a future attestation succeeds"
        );
    }

    // Optionally refresh the on-disk allowlist from CMIS before loading it, so
    // the served body stays in sync with what the operator provisioned.
    maybe_fetch_allowlist(
        config.allowlist.fetch,
        config.allowlist.path.as_deref(),
        resolver.as_ref(),
        host_spiffe_id.as_deref(),
    )
    .await;

    // Allowlist: configured ⇒ load and verify, denying all callers (fail
    // closed) on a missing file or a verification failure rather than crashing
    // — a crash here would loop under the service supervisor and unbind the
    // helper socket, hiding the real error behind ECONNREFUSED. Absent
    // configuration also denies all.
    let allowlist = if let Some(path) = config.allowlist.path.as_deref() {
        let key_path = config.allowlist.key.as_deref().context(
            "allowlist.path is set but allowlist.key (FERROGATE_ALLOWLIST_KEY) is missing",
        )?;
        mia::helper::allowlist::load_at_startup(path, key_path, clock(), max_age)
            .with_context(|| format!("reading allowlist (allowlist.path) {}", path.display()))?
    } else {
        tracing::warn!("no allowlist configured; helper API denies all callers (fail closed)");
        None
    };

    let helper_config = HelperServerConfig {
        socket_path: socket_path.clone(),
        // `socket_mode`/`socket_gid` are Unix-only; `windows_group` is
        // Windows-only. Each transport ignores the fields that don't apply.
        socket_mode: config.socket_mode()?,
        socket_gid: config.socket_gid()?,
        windows_group: config.helper.windows_group.clone(),
        max_concurrent: 64,
        read_timeout: Duration::from_secs(5),
    };

    // The CRL cache (feature F11) starts empty and the mint gate fails closed;
    // the puller's first verified pull (within seconds of startup) opens it.
    let crl = Arc::new(CrlCache::new());
    maybe_spawn_crl_puller(resolver.clone(), Arc::clone(&crl));
    let server = HelperServer::bind(
        helper_config,
        auth,
        minter,
        allowlist,
        crl,
        audit_tx,
        Arc::clone(&clock),
    )?;
    tracing::info!(listener = %socket_path.display(), "helper API listening");

    // Live config + allowlist reload on SIGHUP: `mia --reload` /
    // `mia resync-allowlist --reload` (or a manual `kill -HUP`) re-reads the
    // configuration file and signed allowlist and swaps them in without a
    // restart, so the helper socket never goes down. Spawned unconditionally so
    // a reload can pick up a newly-added allowlist or a changed log directive;
    // reload mirrors startup's fail-closed semantics.
    #[cfg(unix)]
    spawn_reload_task(server.allowlist_reloader(), config_source, log_reload, clock.clone());
    #[cfg(not(unix))]
    let _ = (&config_source, &log_reload, &clock);

    // Optionally propose the callers the helper API observes back to CMIS, so a
    // host with no allowlist can bootstrap its own (subject to CMIS policy).
    if config.allowlist.propose {
        maybe_spawn_propose_task(
            resolver.as_ref(),
            host_spiffe_id.as_deref(),
            host_jws,
            server.ledger(),
            server.self_sha(),
            config.allowlist_propose_interval(),
        );
    }

    // If startup attestation failed but CMIS is configured, keep retrying in the
    // background so minting (and the allowlist + propose wiring) recover on their
    // own once CMIS becomes reachable — e.g. the network wasn't up yet at boot —
    // instead of requiring a manual restart.
    if host_spiffe_id.is_none() {
        if let Some(r) = resolver.clone() {
            spawn_reattest_task(
                r,
                server.minter_reloader(),
                server.allowlist_reloader(),
                server.ledger(),
                ReattestParams {
                    allowlist_fetch: config.allowlist.fetch,
                    allowlist_path: config.allowlist.path.clone(),
                    allowlist_key: config.allowlist.key.clone(),
                    allowlist_max_age_secs: max_age,
                    propose: config.allowlist.propose,
                    propose_interval: config.allowlist_propose_interval(),
                    self_sha: server.self_sha(),
                    attest: HostAttestConfig::from_config(config),
                },
                clock.clone(),
            );
        }
    }

    server.serve_with_shutdown(shutdown_signal()).await;
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
/// Reload mirrors `load_at_startup`: a missing or non-verifying body (or an
/// allowlist that has been removed from the config) swaps in deny-all (fail
/// closed); an unexpected I/O error keeps the current allowlist. A config file
/// that no longer parses is logged and the previous configuration is kept.
#[cfg(unix)]
fn spawn_reload_task<A>(
    reloader: mia::helper::AllowlistReloader<A>,
    config_source: mia::config::ConfigSource,
    log_reload: LogReload,
    clock: mia::helper::Clock,
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

            // Allowlist: re-load from the (possibly changed) path/key/max-age.
            // Both must be configured to verify a body; otherwise fail closed.
            if let (Some(path), Some(key_path)) =
                (config.allowlist.path.as_deref(), config.allowlist.key.as_deref())
            {
                match mia::helper::allowlist::load_at_startup(
                    path,
                    key_path,
                    clock(),
                    config.allowlist_max_age(),
                ) {
                    // `load_at_startup` already logs loudly on a missing or
                    // non-verifying body; here we only note the swap outcome.
                    Ok(al) => {
                        let loaded = al.is_some();
                        reloader.set(al).await;
                        if loaded {
                            tracing::info!("configuration and signed allowlist reloaded and swapped in live");
                        } else {
                            tracing::warn!("reloaded allowlist absent or unverified; serving deny-all (fail closed)");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "allowlist reload failed (I/O); keeping the current allowlist");
                    }
                }
            } else {
                tracing::warn!("no allowlist configured after reload; serving deny-all (fail closed)");
                reloader.set(None).await;
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
        assert!(proposal_entries(&[], None).is_empty());
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
