//! `mia status [--json] [-e <env>] [-c <config>]` — read the status endpoint
//! (feature F18) and report each environment's state.
//!
//! The same endpoint the `mia-tray` companion polls, so a headless host gets
//! the same answer without the tray. The endpoint address comes from
//! `status.socket` in `--config <path>` (or the default configuration);
//! `--environment` only filters the reply.
//!
//! Exit status (stable, for scripts):
//!
//! | code | meaning |
//! |------|---------|
//! | [`EXIT_HEALTHY`] (0) | every reported environment is `healthy` |
//! | [`EXIT_UNHEALTHY`] (1) | at least one is not (or none is served) |
//! | [`EXIT_ERROR`] (2) | bad arguments, unreadable config, protocol error |
//! | [`EXIT_NOT_RUNNING`] (3) | the endpoint is absent — the agent is not running |
//! | [`EXIT_PERMISSION_DENIED`] (4) | the endpoint exists but this user may not open it |

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use mia_status_proto::{
    error_codes, AgentState, AllowlistState, AttestBackend, ErrorSummary, FrameError,
    StatusErrorCode, StatusReq, StatusRequest, StatusResponse, StatusSnapshot,
};

use crate::config::Config;

/// Every reported environment is healthy.
pub const EXIT_HEALTHY: i32 = 0;
/// At least one environment is not healthy (or none was reported).
pub const EXIT_UNHEALTHY: i32 = 1;
/// Usage, configuration or protocol error.
pub const EXIT_ERROR: i32 = 2;
/// The status endpoint is absent: the agent is not running.
pub const EXIT_NOT_RUNNING: i32 = 3;
/// The endpoint exists but this user is not allowed to open it.
pub const EXIT_PERMISSION_DENIED: i32 = 4;

/// Socket read/write deadline.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const USAGE: &str = "usage: mia status [--json] [--environment <env>] [--config <path>]";

/// Run `mia status`. `args` is everything after `status`. Returns the process
/// exit code (see the module docs); errors are printed, not returned.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("mia status: {e:#}");
            EXIT_ERROR
        }
    }
}

struct Opts {
    json: bool,
    environment: Option<String>,
    config: Option<PathBuf>,
}

fn parse(args: &[String]) -> anyhow::Result<Option<Opts>> {
    let mut opts = Opts {
        json: false,
        environment: None,
        config: None,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "--json" => opts.json = true,
            "-e" | "--environment" => {
                let env = it
                    .next()
                    .context("--environment requires a name argument")?;
                if env != crate::status::DEFAULT_ENVIRONMENT_LABEL {
                    crate::config::validate_environment(env)?;
                }
                opts.environment = Some(env.clone());
            }
            "-c" | "--config" => {
                let path = it.next().context("--config requires a path argument")?;
                opts.config = Some(PathBuf::from(path));
            }
            other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }
    Ok(Some(opts))
}

fn run_inner(args: &[String]) -> anyhow::Result<i32> {
    let Some(opts) = parse(args)? else {
        return Ok(EXIT_HEALTHY);
    };
    let config = load_config(opts.config.as_deref())?;
    let endpoint = config.status_socket();
    let req = StatusRequest::Status(StatusReq {
        environment: opts.environment.clone(),
    });

    let snapshots = match query(&endpoint, &req) {
        Ok(StatusResponse::Status(snapshots)) => snapshots,
        Ok(StatusResponse::Error {
            code: StatusErrorCode::UnknownEnvironment,
            ..
        }) => {
            eprintln!(
                "mia status: environment {:?} is not served by the running agent",
                opts.environment.as_deref().unwrap_or_default()
            );
            return Ok(EXIT_UNHEALTHY);
        }
        Ok(StatusResponse::Error { code, retry_after }) => {
            anyhow::bail!(
                "the agent refused the request ({code:?}{})",
                retry_after.map_or(String::new(), |s| format!(", retry after {s}s"))
            )
        }
        Ok(StatusResponse::LogTail(_)) => anyhow::bail!("unexpected reply from the agent"),
        Err(QueryError::NotRunning) => {
            let snapshots = not_running_snapshots(opts.environment.as_deref());
            print(&snapshots, opts.json)?;
            if !opts.json {
                eprintln!(
                    "\nno status endpoint at {} — the mia service is not running (start it: {})",
                    endpoint.display(),
                    crate::setup::restart_hint()
                );
            }
            return Ok(EXIT_NOT_RUNNING);
        }
        Err(QueryError::PermissionDenied) => {
            eprintln!(
                "mia status: permission denied opening {} — read access needs membership in \
                 the status group ({}); add this user to it and start a new login session",
                endpoint.display(),
                config.status_group()
            );
            return Ok(EXIT_PERMISSION_DENIED);
        }
        Err(QueryError::Io(e)) => {
            return Err(e).with_context(|| format!("talking to {}", endpoint.display()))
        }
        Err(QueryError::Protocol(e)) => {
            return Err(e)
                .with_context(|| format!("decoding the reply from {}", endpoint.display()))
        }
    };

    print(&snapshots, opts.json)?;
    Ok(exit_code(&snapshots))
}

/// The configuration that names the endpoint. An explicit `--config` must
/// load; the default one often cannot be read by an unprivileged user (the
/// system file is `0640`), so fall back to defaults plus the environment —
/// the endpoint address is all `mia status` needs from it.
fn load_config(explicit: Option<&Path>) -> anyhow::Result<Config> {
    match Config::load(explicit, None) {
        Ok((config, _)) => Ok(config),
        Err(e) if explicit.is_none() => {
            eprintln!(
                "mia status: note: could not read the configuration ({e:#}); using the default \
                 status endpoint"
            );
            let mut config = Config::default();
            config.apply_env(crate::config::EnvOverrideScope::Full)?;
            Ok(config)
        }
        Err(e) => Err(e),
    }
}

/// [`EXIT_HEALTHY`] when there is at least one snapshot and all are healthy.
#[must_use]
pub fn exit_code(snapshots: &[StatusSnapshot]) -> i32 {
    if !snapshots.is_empty() && snapshots.iter().all(|s| s.state.is_healthy()) {
        EXIT_HEALTHY
    } else {
        EXIT_UNHEALTHY
    }
}

/// Why [`query`] failed.
#[derive(Debug)]
pub enum QueryError {
    /// No endpoint (absent socket/pipe, or nothing listening).
    NotRunning,
    /// The endpoint exists but may not be opened by this user.
    PermissionDenied,
    /// Other I/O failure.
    Io(std::io::Error),
    /// The reply could not be framed/decoded.
    Protocol(FrameError),
}

impl From<FrameError> for QueryError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Io(io) => Self::Io(io),
            other => Self::Protocol(other),
        }
    }
}

/// Send one request to the status endpoint at `endpoint` and read the reply.
pub fn query(endpoint: &Path, req: &StatusRequest) -> Result<StatusResponse, QueryError> {
    let mut stream = connect(endpoint)?;
    mia_status_proto::write_frame(&mut stream, req)?;
    Ok(mia_status_proto::read_frame(&mut stream)?)
}

#[cfg(unix)]
fn connect(endpoint: &Path) -> Result<std::os::unix::net::UnixStream, QueryError> {
    use std::io::ErrorKind;
    match std::os::unix::net::UnixStream::connect(endpoint) {
        Ok(s) => {
            s.set_read_timeout(Some(IO_TIMEOUT))
                .map_err(QueryError::Io)?;
            s.set_write_timeout(Some(IO_TIMEOUT))
                .map_err(QueryError::Io)?;
            Ok(s)
        }
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
            Err(QueryError::NotRunning)
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(QueryError::PermissionDenied),
        Err(e) => Err(QueryError::Io(e)),
    }
}

#[cfg(windows)]
fn connect(endpoint: &Path) -> Result<std::fs::File, QueryError> {
    // A pipe client is an ordinary file handle opened read/write.
    // ERROR_FILE_NOT_FOUND (2): no pipe; ERROR_PIPE_BUSY (231): retry once.
    let _ = IO_TIMEOUT;
    use std::os::windows::fs::OpenOptionsExt as _;
    // SECURITY_IDENTIFICATION: a squatting pipe server may learn who we are
    // but can never impersonate this (possibly privileged) client.
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    for attempt in 0..2 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(endpoint)
        {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(2) => return Err(QueryError::NotRunning),
            Err(e) if e.raw_os_error() == Some(231) && attempt == 0 => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(QueryError::PermissionDenied)
            }
            Err(e) => return Err(QueryError::Io(e)),
        }
    }
    Err(QueryError::Io(std::io::Error::other("status pipe busy")))
}

#[cfg(not(any(unix, windows)))]
fn connect(_endpoint: &Path) -> Result<std::fs::File, QueryError> {
    let _ = IO_TIMEOUT;
    Err(QueryError::NotRunning)
}

/// Synthesised snapshots for an agent that is not running: one per
/// configured environment (or the one asked for), state `not_running` — or
/// `ima_disabled` on a Linux host whose kernel does not enforce IMA appraisal
/// while the agent requires it (the agent refuses to start there).
#[must_use]
pub fn not_running_snapshots(environment: Option<&str>) -> Vec<StatusSnapshot> {
    let labels: Vec<Option<String>> = match environment {
        Some(e) if e == crate::status::DEFAULT_ENVIRONMENT_LABEL => vec![None],
        Some(e) => vec![Some(e.to_string())],
        None => {
            let found: Vec<Option<String>> = crate::config::discover_environment_configs()
                .into_iter()
                .map(|d| d.environment)
                .collect();
            if found.is_empty() {
                vec![None]
            } else {
                found
            }
        }
    };
    let (state, code) = if ima_blocks_startup() {
        (AgentState::ImaDisabled, error_codes::IMA_DISABLED)
    } else {
        (AgentState::NotRunning, error_codes::NOT_RUNNING)
    };
    let now = unix_now();
    labels
        .into_iter()
        .map(|environment| StatusSnapshot {
            environment,
            state,
            since: now,
            svid: None,
            attest_backend: AttestBackend::Auto,
            cmis_node: None,
            crl_age_secs: None,
            allowlist: AllowlistState::Missing,
            x509_store: None,
            last_error: Some(ErrorSummary {
                code: code.to_string(),
                message: crate::status::message_for(code).to_string(),
            }),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
        .collect()
}

/// Linux: the kernel does not enforce IMA appraisal and nothing visible to
/// this process turns the requirement off (`FERROGATE_REQUIRE_IMA=0` /
/// `FERROGATE_SKIP_HARDENING=1` in this environment or the packaged
/// `/etc/ferrogate/mia.env`). A heuristic: the daemon's own environment is
/// authoritative and may differ.
#[cfg(target_os = "linux")]
fn ima_blocks_startup() -> bool {
    let opted_out = |text: &str| {
        text.lines().any(|l| {
            let l = l.trim();
            l == "FERROGATE_REQUIRE_IMA=0" || l == "FERROGATE_SKIP_HARDENING=1"
        })
    };
    if std::env::var("FERROGATE_REQUIRE_IMA").is_ok_and(|v| v == "0")
        || std::env::var("FERROGATE_SKIP_HARDENING").is_ok_and(|v| v == "1")
    {
        return false;
    }
    if std::fs::read_to_string("/etc/ferrogate/mia.env").is_ok_and(|t| opted_out(&t)) {
        return false;
    }
    !crate::hardening::ima_enforced()
}

/// IMA is a Linux concept.
#[cfg(not(target_os = "linux"))]
fn ima_blocks_startup() -> bool {
    false
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn print(snapshots: &[StatusSnapshot], json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(snapshots)?);
    } else {
        print!("{}", render_human(snapshots, unix_now()));
    }
    Ok(())
}

/// The human-readable report.
#[must_use]
pub fn render_human(snapshots: &[StatusSnapshot], now: i64) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if snapshots.is_empty() {
        out.push_str("no environments reported\n");
    }
    for s in snapshots {
        let env = s
            .environment
            .as_deref()
            .unwrap_or(crate::status::DEFAULT_ENVIRONMENT_LABEL);
        let _ = writeln!(
            out,
            "[{env}] {} (for {})",
            s.state.as_str(),
            human_duration(now - s.since)
        );
        if let Some(e) = &s.last_error {
            let _ = writeln!(out, "  problem:      {} ({})", e.message, e.code);
        }
        if let Some(svid) = &s.svid {
            let _ = writeln!(
                out,
                "  svid:         {} (expires {}, renews {})",
                svid.spiffe_id,
                relative(svid.not_after - now),
                relative(svid.renew_at - now)
            );
        }
        let backend = match s.attest_backend {
            AttestBackend::Auto => "auto (not resolved yet)",
            AttestBackend::Tpm => "tpm",
            AttestBackend::HostKey => "host-key",
            AttestBackend::VirtualTpm => "virtual-tpm (INSECURE)",
        };
        let _ = writeln!(out, "  attestation:  {backend}");
        if let Some(node) = &s.cmis_node {
            let _ = writeln!(out, "  cmis node:    {node}");
        }
        match s.crl_age_secs {
            Some(age) => {
                let _ = writeln!(out, "  crl age:      {}", human_duration(i64::from(age)));
            }
            None => out.push_str("  crl age:      none pulled yet\n"),
        }
        let allowlist = match s.allowlist {
            AllowlistState::Missing => "missing".to_string(),
            AllowlistState::Invalid => "invalid".to_string(),
            AllowlistState::Loaded { entries, not_after } => {
                format!(
                    "loaded ({entries} entries, expires {})",
                    relative(not_after - now)
                )
            }
        };
        let _ = writeln!(out, "  allowlist:    {allowlist}");
        if let Some(store) = s.x509_store {
            let _ = writeln!(
                out,
                "  x509 store:   {}",
                serde_json::to_value(store)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default()
            );
        }
        let _ = writeln!(out, "  agent:        mia {}", s.version);
    }
    out
}

/// `in 3h12m` / `5m ago`.
fn relative(delta: i64) -> String {
    if delta >= 0 {
        format!("in {}", human_duration(delta))
    } else {
        format!("{} ago", human_duration(-delta))
    }
}

/// A compact duration: `42s`, `5m`, `3h12m`, `2d4h`.
fn human_duration(secs: i64) -> String {
    let secs = secs.max(0);
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86_400, (s % 86_400) / 3600),
    }
}

fn print_help() {
    println!(
        "mia status — report the agent's state per environment\n\
         \n\
         {USAGE}\n\
         \n\
         Reads the agent's read-only status endpoint (status.socket; default {}).\n\
         Read access needs membership in the status group (status.group).\n\
         \n\
         options:\n\
         \x20 --json                  print one JSON snapshot per environment\n\
         \x20 -e, --environment <env> report only this environment (\"default\" for mia.toml)\n\
         \x20 -c, --config <path>     take status.socket from this config file\n\
         \x20 -h, --help              show this help\n\
         \n\
         exit status: 0 all healthy, 1 not all healthy, 2 error, 3 agent not running,\n\
         4 permission denied",
        mia_status_proto::DEFAULT_ENDPOINT
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(state: AgentState) -> StatusSnapshot {
        let mut s = not_running_snapshots(Some("prod")).remove(0);
        s.state = state;
        s
    }

    #[test]
    fn exit_code_requires_every_environment_healthy() {
        assert_eq!(exit_code(&[]), EXIT_UNHEALTHY);
        assert_eq!(exit_code(&[snap(AgentState::Healthy)]), EXIT_HEALTHY);
        assert_eq!(
            exit_code(&[snap(AgentState::Healthy), snap(AgentState::CrlStale)]),
            EXIT_UNHEALTHY
        );
    }

    #[test]
    fn not_running_snapshots_honour_the_filter() {
        let s = not_running_snapshots(Some("default"));
        assert_eq!(s.len(), 1);
        assert!(s[0].environment.is_none());
        assert!(matches!(
            s[0].state,
            AgentState::NotRunning | AgentState::ImaDisabled
        ));
        let s = not_running_snapshots(Some("prod"));
        assert_eq!(s[0].environment.as_deref(), Some("prod"));
    }

    #[test]
    fn human_report_mentions_the_essentials() {
        let mut s = snap(AgentState::Healthy);
        s.last_error = None;
        s.crl_age_secs = Some(42);
        s.cmis_node = Some("cmis1:8443".into());
        let out = render_human(&[s], unix_now());
        assert!(out.contains("[prod] healthy"));
        assert!(out.contains("crl age:      42s"));
        assert!(out.contains("cmis node:    cmis1:8443"));
    }

    #[test]
    fn durations_are_compact() {
        assert_eq!(human_duration(42), "42s");
        assert_eq!(human_duration(300), "5m");
        assert_eq!(human_duration(3600 * 3 + 60 * 12), "3h12m");
        assert_eq!(human_duration(86_400 * 2 + 3600 * 4), "2d4h");
        assert_eq!(relative(-120), "2m ago");
    }

    #[test]
    fn bad_arguments_are_rejected() {
        assert!(parse(&["--bogus".to_string()]).is_err());
        assert!(parse(&["-e".to_string(), "../x".to_string()]).is_err());
        assert_eq!(run(&["--bogus".to_string()]), EXIT_ERROR);
    }
}
