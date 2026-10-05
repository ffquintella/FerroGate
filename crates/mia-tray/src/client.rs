//! The status endpoint client and the observation fallback chain.
//!
//! The tray only ever sends the two read-only requests the endpoint serves —
//! [`StatusReq`] and [`LogTailReq`]; it has no code path that builds a
//! helper-API request. Replies are bounded by the protocol's `MAX_FRAME_LEN`
//! (the length prefix is checked before anything is allocated), each exchange
//! has a deadline, and the decoded lists are capped again here.
//!
//! [`observe`] implements the degradation the spec asks for: the endpoint;
//! else `mia status --json` (an older daemon, or a non-default `status.socket`
//! that only the configuration knows); else a synthesised `NotRunning`; and
//! `NotInstalled` when no `mia` binary can be found at all.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use mia_status_proto::{
    error_codes, AgentState, AllowlistState, AttestBackend, ErrorSummary, FrameError, Level,
    LogTailReq, LogTailResp, StatusErrorCode, StatusReq, StatusRequest, StatusResponse,
    StatusSnapshot, MAX_TAIL_RECORDS,
};

use crate::process::{run_bounded, Limits};

/// Deadline for one endpoint exchange (connect + write + read).
pub const IO_TIMEOUT: Duration = Duration::from_secs(3);

/// Most snapshots the tray keeps from one reply (one per environment).
pub const MAX_SNAPSHOTS: usize = 64;

/// The variable `mia` honours for `status.socket`; the tray honours it too.
pub const STATUS_SOCKET_VAR: &str = "FERROGATE_STATUS_SOCKET";

/// Tray-side error code: the endpoint exists but this user may not open it.
pub const ACCESS_DENIED_CODE: &str = "status_access_denied";

/// Tray-side error code: no `mia` binary was found.
pub const NOT_INSTALLED_CODE: &str = "not_installed";

/// Desired access for opening the Windows status pipe: `GENERIC_READ |
/// FILE_WRITE_DATA`. The pipe DACL grants the status group no more than that —
/// `GENERIC_WRITE` would include `FILE_CREATE_PIPE_INSTANCE` and is denied.
/// Mirrors `ferro_winauth::pipe_acl::PIPE_CLIENT_DESIRED_ACCESS` (pinned by a
/// test) without pulling that FFI crate into the unprivileged tray.
#[cfg_attr(not(windows), allow(dead_code))]
const PIPE_CLIENT_DESIRED_ACCESS: u32 = 0x8000_0002;

/// Why talking to the endpoint failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// No endpoint (absent socket / pipe, nothing listening).
    #[error("the status endpoint is absent")]
    NotRunning,
    /// The endpoint exists but this user may not open it.
    #[error("permission denied opening the status endpoint")]
    PermissionDenied,
    /// No complete reply before [`IO_TIMEOUT`].
    #[error("the status endpoint did not answer in time")]
    Timeout,
    /// The daemon answered with a refusal.
    #[error("the agent refused the request ({0:?})")]
    Refused(StatusErrorCode),
    /// A reply of the wrong kind.
    #[error("unexpected reply from the agent")]
    UnexpectedReply,
    /// Other I/O failure.
    #[error("status endpoint I/O failed: {0}")]
    Io(String),
    /// The reply could not be framed or decoded.
    #[error("malformed reply from the agent: {0}")]
    Protocol(String),
}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Io(io)
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Self::Timeout
            }
            FrameError::Io(io) => Self::Io(io.to_string()),
            other => Self::Protocol(other.to_string()),
        }
    }
}

/// One request/reply exchange with a status endpoint.
pub trait Transport: Send + Sync {
    /// Send `req` and read the reply.
    fn exchange(&self, req: &StatusRequest) -> Result<StatusResponse, ClientError>;
}

/// The local status endpoint (Unix socket / Windows named pipe).
#[derive(Debug, Clone)]
pub struct LocalEndpoint {
    path: PathBuf,
    /// Windows: an exchange is still blocked on its helper thread (a hung or
    /// squatting pipe server); no new one is started until it ends, so
    /// abandoned threads cannot pile up.
    #[cfg(windows)]
    inflight: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LocalEndpoint {
    /// The endpoint at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            #[cfg(windows)]
            inflight: std::sync::Arc::default(),
        }
    }

    /// `$FERROGATE_STATUS_SOCKET` when set (the same override `mia` honours),
    /// else the platform default. The tray cannot read the root-owned config
    /// file, so a custom `status.socket` set only there is reached through the
    /// `mia status` fallback instead.
    #[must_use]
    pub fn from_env() -> Self {
        let path = std::env::var_os(STATUS_SOCKET_VAR)
            .filter(|v| !v.is_empty())
            .map_or_else(
                || PathBuf::from(mia_status_proto::DEFAULT_ENDPOINT),
                PathBuf::from,
            );
        Self::new(path)
    }

    /// The endpoint address.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Transport for LocalEndpoint {
    fn exchange(&self, req: &StatusRequest) -> Result<StatusResponse, ClientError> {
        #[cfg(windows)]
        {
            platform::exchange(&self.path, req, &self.inflight)
        }
        #[cfg(not(windows))]
        {
            platform::exchange(&self.path, req)
        }
    }
}

/// Run `f` on a helper thread and give up after `timeout`. Used where the OS
/// handle has no read deadline (Windows pipes); an abandoned thread ends when
/// its handle is closed by the peer.
#[cfg(any(windows, test))]
pub(crate) fn with_deadline<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> Result<T, ClientError> + Send + 'static,
) -> Result<T, ClientError> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(timeout)
        .unwrap_or(Err(ClientError::Timeout))
}

#[cfg(unix)]
mod platform {
    use super::{ClientError, IO_TIMEOUT};
    use mia_status_proto::{StatusRequest, StatusResponse};
    use std::io::{ErrorKind, Read};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Instant;

    /// Reads with one deadline for the whole reply: before each read the
    /// socket timeout is set to the time left, so a peer dripping a byte at a
    /// time cannot stretch a 64 KiB frame past [`IO_TIMEOUT`].
    struct Deadline<'a> {
        stream: &'a UnixStream,
        until: Instant,
    }

    impl Read for Deadline<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let left = self.until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ErrorKind::TimedOut.into());
            }
            // macOS refuses `setsockopt` (EINVAL) once the peer has closed;
            // the read then returns buffered data or EOF at once, and the
            // previous (shorter-or-equal) timeout still bounds it.
            let _ = self.stream.set_read_timeout(Some(left));
            let mut s: &UnixStream = self.stream;
            s.read(buf)
        }
    }

    pub(super) fn exchange(
        path: &Path,
        req: &StatusRequest,
    ) -> Result<StatusResponse, ClientError> {
        let until = Instant::now() + IO_TIMEOUT;
        let mut stream = match UnixStream::connect(path) {
            Ok(s) => s,
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                return Err(ClientError::NotRunning)
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return Err(ClientError::PermissionDenied)
            }
            Err(e) => return Err(ClientError::Io(e.to_string())),
        };
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|e| ClientError::Io(e.to_string()))?;
        mia_status_proto::write_frame(&mut stream, req)?;
        Ok(mia_status_proto::read_frame(&mut Deadline {
            stream: &stream,
            until,
        })?)
    }
}

#[cfg(windows)]
mod platform {
    use super::{with_deadline, ClientError, IO_TIMEOUT, PIPE_CLIENT_DESIRED_ACCESS};
    use mia_status_proto::{StatusRequest, StatusResponse};
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// `SECURITY_IDENTIFICATION`: a squatting pipe server may learn who we
    /// are but can never impersonate this client.
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;

    pub(super) fn exchange(
        path: &Path,
        req: &StatusRequest,
        inflight: &Arc<AtomicBool>,
    ) -> Result<StatusResponse, ClientError> {
        if inflight.swap(true, Ordering::AcqRel) {
            // The previous exchange is still stuck on a silent server.
            return Err(ClientError::Timeout);
        }
        let flag = Arc::clone(inflight);
        let path = path.to_path_buf();
        let req = req.clone();
        with_deadline(IO_TIMEOUT, move || {
            let result = open(&path).and_then(|mut pipe| {
                mia_status_proto::write_frame(&mut pipe, &req)?;
                Ok(mia_status_proto::read_frame(&mut pipe)?)
            });
            flag.store(false, Ordering::Release);
            result
        })
    }

    fn open(path: &Path) -> Result<std::fs::File, ClientError> {
        for attempt in 0..2 {
            match std::fs::OpenOptions::new()
                .access_mode(PIPE_CLIENT_DESIRED_ACCESS)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(path)
            {
                Ok(f) => return Ok(f),
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                    return Err(ClientError::NotRunning)
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt == 0 => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(ClientError::PermissionDenied)
                }
                Err(e) => return Err(ClientError::Io(e.to_string())),
            }
        }
        Err(ClientError::Io("the status pipe is busy".into()))
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::ClientError;
    use mia_status_proto::{StatusRequest, StatusResponse};
    use std::path::Path;

    pub(super) fn exchange(
        _path: &Path,
        _req: &StatusRequest,
    ) -> Result<StatusResponse, ClientError> {
        Err(ClientError::NotRunning)
    }
}

/// Ask for the snapshots (every environment, or one). The list is capped at
/// [`MAX_SNAPSHOTS`].
pub fn fetch_status(
    transport: &dyn Transport,
    environment: Option<&str>,
) -> Result<Vec<StatusSnapshot>, ClientError> {
    let req = StatusRequest::Status(StatusReq {
        environment: environment.map(str::to_string),
    });
    match transport.exchange(&req)? {
        StatusResponse::Status(mut snapshots) => {
            if snapshots.len() > MAX_SNAPSHOTS {
                tracing::warn!(count = snapshots.len(), "capping an oversized status reply");
                snapshots.truncate(MAX_SNAPSHOTS);
            }
            Ok(snapshots)
        }
        StatusResponse::Error { code, .. } => Err(ClientError::Refused(code)),
        StatusResponse::LogTail(_) => Err(ClientError::UnexpectedReply),
    }
}

/// Ask for log records with `seq >= since_seq`, at every level the daemon
/// buffered (the viewer filters locally, so changing the level filter never
/// loses records). At most [`MAX_TAIL_RECORDS`] are kept.
pub fn fetch_logs(transport: &dyn Transport, since_seq: u64) -> Result<LogTailResp, ClientError> {
    let req = StatusRequest::LogTail(LogTailReq {
        since_seq,
        min_level: Level::Trace,
        max: MAX_TAIL_RECORDS,
    });
    match transport.exchange(&req)? {
        StatusResponse::LogTail(mut resp) => {
            resp.records.truncate(usize::from(MAX_TAIL_RECORDS));
            Ok(resp)
        }
        StatusResponse::Error { code, .. } => Err(ClientError::Refused(code)),
        StatusResponse::Status(_) => Err(ClientError::UnexpectedReply),
    }
}

// ── The fallback chain ───────────────────────────────────────────────────────

/// Where an [`Observation`]'s snapshots came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The status endpoint answered.
    Endpoint,
    /// `mia status --json` answered (the endpoint did not).
    Cli,
    /// Neither answered; the tray synthesised the snapshot.
    Synthesised,
}

/// One poll's result: always at least one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// One snapshot per environment.
    pub snapshots: Vec<StatusSnapshot>,
    /// Where they came from.
    pub source: Source,
}

impl Observation {
    /// Whether the agent answered (endpoint or CLI) rather than being absent.
    #[must_use]
    pub fn reached_agent(&self) -> bool {
        self.source != Source::Synthesised
    }
}

/// Why `mia status --json` gave no snapshots.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    /// `mia status` exited 4: this user may not open the endpoint.
    #[error("permission denied")]
    PermissionDenied,
    /// The command failed or printed something unparseable.
    #[error("mia status failed: {0}")]
    Failed(String),
}

/// The `mia status --json` fallback.
pub trait StatusCli: Send + Sync {
    /// Run it and parse the snapshot array.
    fn status_json(&self) -> Result<Vec<StatusSnapshot>, CliError>;
}

/// [`StatusCli`] over a real `mia` binary.
#[derive(Debug, Clone)]
pub struct MiaStatusCli {
    mia: PathBuf,
}

impl MiaStatusCli {
    /// Use the `mia` at `mia`.
    #[must_use]
    pub fn new(mia: impl Into<PathBuf>) -> Self {
        Self { mia: mia.into() }
    }
}

/// `mia status` exit code: permission denied (see `mia::status_cli`).
const MIA_STATUS_PERMISSION_DENIED: i32 = 4;

impl StatusCli for MiaStatusCli {
    fn status_json(&self) -> Result<Vec<StatusSnapshot>, CliError> {
        let mut cmd = Command::new(&self.mia);
        cmd.args(["status", "--json"]);
        let out = run_bounded(cmd, Limits::QUICK).map_err(|e| CliError::Failed(e.to_string()))?;
        parse_status_cli(&out)
    }
}

/// Interpret a `mia status --json` run: exit 0 (healthy), 1 (unhealthy) and 3
/// (not running) all print the snapshot array; 4 is permission denied.
pub fn parse_status_cli(out: &crate::process::Captured) -> Result<Vec<StatusSnapshot>, CliError> {
    if out.code == Some(MIA_STATUS_PERMISSION_DENIED) {
        return Err(CliError::PermissionDenied);
    }
    if out.timed_out || !matches!(out.code, Some(0 | 1 | 3)) || out.truncated {
        return Err(CliError::Failed(format!("exit {:?}", out.code)));
    }
    let mut snapshots: Vec<StatusSnapshot> =
        serde_json::from_slice(&out.stdout).map_err(|e| CliError::Failed(e.to_string()))?;
    snapshots.truncate(MAX_SNAPSHOTS);
    Ok(snapshots)
}

/// A snapshot the tray made up because nothing answered.
#[must_use]
pub fn synthesised(state: AgentState, code: &str, message: &str, now: i64) -> StatusSnapshot {
    StatusSnapshot {
        environment: None,
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
            message: message.to_string(),
        }),
        version: String::new(),
        // Nothing answered, so nothing is known to serve the address.
        default_address: false,
    }
}

fn synth(state: AgentState, code: &str, message: &str, now: i64) -> Observation {
    Observation {
        snapshots: vec![synthesised(state, code, message, now)],
        source: Source::Synthesised,
    }
}

fn access_denied(now: i64) -> Observation {
    synth(
        AgentState::NotRunning,
        ACCESS_DENIED_CODE,
        "this user may not open the status endpoint",
        now,
    )
}

/// One poll: endpoint → `mia status --json` → synthesised `NotRunning`
/// (`NotInstalled` when `cli` is `None`, i.e. no `mia` was found). `Err` only
/// for a transient refusal (rate limited), on which the caller keeps the
/// previous observation.
pub fn observe(
    endpoint: &dyn Transport,
    cli: Option<&dyn StatusCli>,
    now: i64,
) -> Result<Observation, ClientError> {
    let failure = match fetch_status(endpoint, None) {
        Ok(snapshots) if snapshots.is_empty() => {
            return Ok(synth(
                AgentState::NotConfigured,
                error_codes::CMIS_NOT_CONFIGURED,
                "the agent serves no environment",
                now,
            ))
        }
        Ok(snapshots) => {
            return Ok(Observation {
                snapshots,
                source: Source::Endpoint,
            })
        }
        Err(e @ ClientError::Refused(StatusErrorCode::RateLimited)) => return Err(e),
        Err(ClientError::PermissionDenied) => return Ok(access_denied(now)),
        Err(e) => e,
    };
    let Some(cli) = cli else {
        return Ok(synth(
            AgentState::NotInstalled,
            NOT_INSTALLED_CODE,
            "the mia program was not found",
            now,
        ));
    };
    match cli.status_json() {
        Ok(snapshots) if !snapshots.is_empty() => Ok(Observation {
            snapshots,
            source: Source::Cli,
        }),
        Err(CliError::PermissionDenied) => Ok(access_denied(now)),
        other => {
            tracing::debug!(endpoint = %failure, cli = ?other.err(), "agent not reachable");
            Ok(synth(
                AgentState::NotRunning,
                error_codes::NOT_RUNNING,
                "the status endpoint is absent",
                now,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn pipe_access_matches_the_dacl_contract() {
        assert_eq!(
            PIPE_CLIENT_DESIRED_ACCESS,
            ferro_winauth::pipe_acl::PIPE_CLIENT_DESIRED_ACCESS
        );
    }

    struct Fake(
        Mutex<Vec<Result<StatusResponse, ClientError>>>,
        Mutex<Vec<StatusRequest>>,
    );

    impl Fake {
        fn new(replies: Vec<Result<StatusResponse, ClientError>>) -> Self {
            Self(Mutex::new(replies), Mutex::new(Vec::new()))
        }
    }

    impl Transport for Fake {
        fn exchange(&self, req: &StatusRequest) -> Result<StatusResponse, ClientError> {
            self.1.lock().unwrap().push(req.clone());
            self.0.lock().unwrap().remove(0)
        }
    }

    struct Cli(Result<Vec<StatusSnapshot>, CliError>);
    impl StatusCli for Cli {
        fn status_json(&self) -> Result<Vec<StatusSnapshot>, CliError> {
            self.0.clone()
        }
    }

    fn healthy(env: Option<&str>) -> StatusSnapshot {
        let mut s = synthesised(AgentState::Healthy, "x", "y", 1);
        s.environment = env.map(str::to_string);
        s.last_error = None;
        s
    }

    #[test]
    fn the_endpoint_wins_and_only_read_only_requests_are_sent() {
        let ep = Fake::new(vec![Ok(StatusResponse::Status(vec![healthy(None)]))]);
        let obs = observe(&ep, None, 5).unwrap();
        assert_eq!(obs.source, Source::Endpoint);
        assert!(obs.reached_agent());
        assert_eq!(obs.snapshots[0].state, AgentState::Healthy);
        // Exactly one StatusReq — the tray has no other request shape.
        let sent = ep.1.lock().unwrap();
        assert_eq!(
            *sent,
            vec![StatusRequest::Status(StatusReq { environment: None })]
        );
    }

    #[test]
    fn fallback_chain_endpoint_then_cli_then_not_running() {
        // Endpoint absent, CLI answers (e.g. a custom status.socket).
        let ep = Fake::new(vec![Err(ClientError::NotRunning)]);
        let cli = Cli(Ok(vec![healthy(Some("prod"))]));
        let obs = observe(&ep, Some(&cli), 5).unwrap();
        assert_eq!(obs.source, Source::Cli);
        assert_eq!(obs.snapshots[0].environment.as_deref(), Some("prod"));

        // Older daemon: endpoint garbage, CLI fails ⇒ NotRunning.
        let ep = Fake::new(vec![Err(ClientError::Protocol("x".into()))]);
        let cli = Cli(Err(CliError::Failed("no".into())));
        let obs = observe(&ep, Some(&cli), 5).unwrap();
        assert_eq!(obs.source, Source::Synthesised);
        assert_eq!(obs.snapshots[0].state, AgentState::NotRunning);
        assert_eq!(obs.snapshots[0].since, 5);

        // No mia binary ⇒ NotInstalled.
        let ep = Fake::new(vec![Err(ClientError::NotRunning)]);
        let obs = observe(&ep, None, 5).unwrap();
        assert_eq!(obs.snapshots[0].state, AgentState::NotInstalled);
    }

    #[test]
    fn permission_denied_and_rate_limits() {
        let ep = Fake::new(vec![Err(ClientError::PermissionDenied)]);
        let obs = observe(&ep, None, 5).unwrap();
        assert_eq!(
            obs.snapshots[0].last_error.as_ref().unwrap().code,
            ACCESS_DENIED_CODE
        );
        let ep = Fake::new(vec![Err(ClientError::NotRunning)]);
        let cli = Cli(Err(CliError::PermissionDenied));
        let obs = observe(&ep, Some(&cli), 5).unwrap();
        assert_eq!(
            obs.snapshots[0].last_error.as_ref().unwrap().code,
            ACCESS_DENIED_CODE
        );
        let ep = Fake::new(vec![Ok(StatusResponse::Error {
            code: StatusErrorCode::RateLimited,
            retry_after: Some(1),
        })]);
        assert!(observe(&ep, None, 5).is_err());
    }

    #[test]
    fn replies_are_capped_and_typed() {
        let many = vec![healthy(None); MAX_SNAPSHOTS + 10];
        let ep = Fake::new(vec![Ok(StatusResponse::Status(many))]);
        assert_eq!(fetch_status(&ep, None).unwrap().len(), MAX_SNAPSHOTS);
        let ep = Fake::new(vec![Ok(StatusResponse::Status(vec![]))]);
        assert_eq!(fetch_logs(&ep, 0), Err(ClientError::UnexpectedReply));
        let ep = Fake::new(vec![Ok(StatusResponse::Status(vec![]))]);
        let obs = observe(&ep, None, 1).unwrap();
        assert_eq!(obs.snapshots[0].state, AgentState::NotConfigured);
    }

    #[test]
    fn status_cli_output_is_parsed() {
        use crate::process::Captured;
        let json = serde_json::to_vec(&vec![healthy(None)]).unwrap();
        for code in [0, 1, 3] {
            let out = Captured {
                code: Some(code),
                stdout: json.clone(),
                ..Captured::default()
            };
            assert_eq!(parse_status_cli(&out).unwrap().len(), 1);
        }
        let denied = Captured {
            code: Some(4),
            ..Captured::default()
        };
        assert_eq!(parse_status_cli(&denied), Err(CliError::PermissionDenied));
        let garbage = Captured {
            code: Some(0),
            stdout: b"not json".to_vec(),
            ..Captured::default()
        };
        assert!(parse_status_cli(&garbage).is_err());
    }

    #[test]
    fn deadlines_apply() {
        let r: Result<(), _> = with_deadline(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(2));
            Ok(())
        });
        assert_eq!(r, Err(ClientError::Timeout));
        assert_eq!(with_deadline(Duration::from_secs(5), || Ok(7)), Ok(7));
    }

    #[cfg(unix)]
    #[test]
    fn a_real_socket_round_trip_and_an_absent_one() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        assert_eq!(
            fetch_status(&LocalEndpoint::new(&path), None),
            Err(ClientError::NotRunning)
        );
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let req: StatusRequest = mia_status_proto::read_frame(&mut s).unwrap();
            assert!(matches!(req, StatusRequest::LogTail(_)));
            mia_status_proto::write_frame(
                &mut s,
                &StatusResponse::LogTail(LogTailResp {
                    records: vec![],
                    next_seq: 9,
                    dropped: 0,
                    buffer_id: 1,
                }),
            )
            .unwrap();
        });
        let resp = fetch_logs(&LocalEndpoint::new(&path), 3).unwrap();
        assert_eq!(resp.next_seq, 9);
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_dripping_endpoint_hits_the_whole_reply_deadline() {
        use std::io::Write as _;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _drip = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // Announce a 1000-byte frame, then send one byte every 500 ms —
            // each read succeeds well inside a per-read timeout.
            let _ = s.write_all(&1000u32.to_be_bytes());
            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(500));
                if s.write_all(&[0xa0]).is_err() {
                    break;
                }
            }
        });
        let started = std::time::Instant::now();
        assert_eq!(
            fetch_status(&LocalEndpoint::new(&path), None),
            Err(ClientError::Timeout)
        );
        assert!(started.elapsed() < IO_TIMEOUT * 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_silent_endpoint_times_out() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _hold = std::thread::spawn(move || {
            let conn = listener.accept();
            std::thread::sleep(IO_TIMEOUT * 2);
            drop(conn);
        });
        assert_eq!(
            fetch_status(&LocalEndpoint::new(&path), None),
            Err(ClientError::Timeout)
        );
    }
}
