//! The status endpoint (feature F18): a read-only local IPC listener,
//! separate from the token-minting helper socket, serving [`StatusRequest`]s.
//!
//! - **Transport.** A Unix domain socket (mode `0660`, group-owned by the
//!   status group) on Linux/macOS; a named pipe whose DACL grants SYSTEM,
//!   Administrators and the status group on Windows (created through
//!   `ferro-winauth`, which owns the FFI — `mia` stays
//!   `#![forbid(unsafe_code)]`).
//! - **Framing.** Exactly the helper protocol's: a 4-byte big-endian length
//!   then one CBOR value, at most [`MAX_FRAME_LEN`], one exchange per
//!   connection, under a read deadline.
//! - **Requests.** Only `StatusReq` and `LogTailReq`. Anything else —
//!   including a helper-API `HelperReq` — is answered with
//!   [`StatusErrorCode::UnsupportedRequest`]. There is no write request.
//! - **Limits.** A bounded number of concurrent connections (excess
//!   connections are dropped, not queued), a per-uid request budget
//!   ([`RateLimiter`]), a clamped log-tail size and a reply that always fits
//!   the frame bound.
//!
//! **Seccomp.** On Linux the socket is bound, chmod'ed and chown'ed by
//! [`prepare`] *before* the hardening profile is applied (the daemon is still
//! root then), so after the privilege drop the listener only needs
//! `accept4`/`read`/`write` — syscalls the helper server already uses. In
//! particular no `chown` happens after seccomp is installed.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mia_status_proto::{
    decode_request, encode_frame, frame_len, LogTailResp, StatusErrorCode, StatusRequest,
    StatusResponse, MAX_ENVIRONMENT_LEN, MAX_FRAME_LEN, MAX_TAIL_RECORDS,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::Config;
use crate::logbuf::LogBuffer;
use crate::status::StatusRegistry;

/// Room left in a reply frame for everything but the log records.
const REPLY_HEADROOM: usize = 8 * 1024;

/// Most distinct uids the rate limiter tracks at once.
const MAX_TRACKED_UIDS: usize = 1024;

/// The uid bucket used when a peer's credentials cannot be read.
pub const UNKNOWN_PEER: u32 = u32::MAX;

/// A wall clock returning Unix seconds. Injectable for tests.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The system clock (Unix seconds).
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    })
}

/// Resolved listener parameters.
#[derive(Debug, Clone)]
pub struct StatusEndpointConfig {
    /// Socket path (Unix) or pipe name (Windows).
    pub path: PathBuf,
    /// **Unix only.** Socket mode (`0o660`).
    pub mode: u32,
    /// **Unix only.** Group that owns the socket, if resolved.
    pub gid: Option<u32>,
    /// **Windows only.** Local group granted on the pipe DACL.
    pub group: String,
    /// Requests per second per peer uid.
    pub rate_limit_per_sec: u32,
    /// Connections served concurrently; more are dropped.
    pub max_concurrent: usize,
    /// Deadline for receiving the request frame.
    pub read_timeout: Duration,
}

impl StatusEndpointConfig {
    /// Resolve the endpoint from the primary configuration. On Unix the
    /// owning group is `status.socket_gid`, else `status.group` looked up in
    /// `/etc/group`; if neither resolves the socket keeps the daemon's primary
    /// group (so only root can read it — fail closed) and a warning is logged.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let group = config.status_group().to_string();
        let gid = match config.status_socket_gid()? {
            Some(gid) => Some(gid),
            None => resolve_group(&group),
        };
        Ok(Self {
            path: config.status_socket(),
            mode: 0o660,
            gid,
            group,
            rate_limit_per_sec: config.status_rate_limit(),
            max_concurrent: 16,
            read_timeout: Duration::from_secs(5),
        })
    }
}

/// Look `name` up in `/etc/group` (pure Rust — `mia` will not call
/// `getgrnam`). Directory-service-only groups are not found; configure
/// `status.socket_gid` for those.
#[cfg(unix)]
fn resolve_group(name: &str) -> Option<u32> {
    use std::io::Read as _;
    let mut text = String::new();
    let file = std::fs::File::open("/etc/group").ok()?;
    // Bounded read: /etc/group is small; a pathological one is not parsed.
    file.take(1024 * 1024).read_to_string(&mut text).ok()?;
    let gid = parse_group_file(&text, name);
    if gid.is_none() {
        tracing::warn!(
            group = name,
            "status group not found in /etc/group; the status socket stays owned by the \
             daemon's primary group (set status.socket_gid to grant a group read access)"
        );
    }
    gid
}

/// Windows resolves the group by name inside `ferro-winauth`.
#[cfg(not(unix))]
fn resolve_group(_name: &str) -> Option<u32> {
    None
}

/// Find `name`'s gid in `/etc/group`-formatted text (`name:x:gid:members`).
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_group_file(text: &str, name: &str) -> Option<u32> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|line| {
            let mut parts = line.split(':');
            let n = parts.next()?;
            let _pw = parts.next()?;
            let gid = parts.next()?;
            (n == name).then(|| gid.trim().parse().ok()).flatten()
        })
}

/// A fixed-window, per-uid request budget. Bounded memory: at most
/// [`MAX_TRACKED_UIDS`] uids are tracked; when full, stale windows are purged
/// and, failing that, unknown uids are refused (fail closed).
#[derive(Debug)]
pub struct RateLimiter {
    per_sec: u32,
    windows: Mutex<HashMap<u32, (i64, u32)>>,
}

impl RateLimiter {
    /// A limiter allowing `per_sec` requests per uid per second (minimum 1).
    #[must_use]
    pub fn new(per_sec: u32) -> Self {
        Self {
            per_sec: per_sec.max(1),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Account one request from `uid` at Unix second `now`; `false` ⇒ refuse.
    pub fn allow(&self, uid: u32, now: i64) -> bool {
        let Ok(mut map) = self.windows.lock() else {
            return false;
        };
        if map.len() >= MAX_TRACKED_UIDS && !map.contains_key(&uid) {
            map.retain(|_, (window, _)| *window == now);
            if map.len() >= MAX_TRACKED_UIDS {
                return false;
            }
        }
        let entry = map.entry(uid).or_insert((now, 0));
        if entry.0 != now {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_sec {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Request handling shared by every connection.
#[derive(Clone)]
pub struct StatusService {
    registry: StatusRegistry,
    logbuf: Option<Arc<LogBuffer>>,
    limiter: Arc<RateLimiter>,
    clock: Clock,
}

impl std::fmt::Debug for StatusService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusService")
            .field("environments", &self.registry.handles().len())
            .field("logbuf", &self.logbuf.is_some())
            .finish_non_exhaustive()
    }
}

impl StatusService {
    /// A service answering from `registry` and `logbuf`, allowing
    /// `rate_limit_per_sec` requests per peer uid.
    #[must_use]
    pub fn new(
        registry: StatusRegistry,
        logbuf: Option<Arc<LogBuffer>>,
        rate_limit_per_sec: u32,
    ) -> Self {
        Self {
            registry,
            logbuf,
            limiter: Arc::new(RateLimiter::new(rate_limit_per_sec)),
            clock: system_clock(),
        }
    }

    /// Replace the clock (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Answer one request frame body from a peer with uid `peer_uid`.
    pub async fn handle_body(&self, peer_uid: u32, body: &[u8]) -> StatusResponse {
        let now = (self.clock)();
        if !self.limiter.allow(peer_uid, now) {
            tracing::debug!(peer_uid, "status request rate-limited");
            return error(StatusErrorCode::RateLimited, Some(1));
        }
        let Ok(req) = decode_request(body) else {
            tracing::debug!(peer_uid, "status endpoint rejected an unsupported request");
            return error(StatusErrorCode::UnsupportedRequest, None);
        };
        match req {
            StatusRequest::Status(req) => {
                if let Some(env) = req.environment.as_deref() {
                    if !valid_environment_filter(env) {
                        return error(StatusErrorCode::MalformedRequest, None);
                    }
                }
                match self
                    .registry
                    .snapshots(req.environment.as_deref(), now)
                    .await
                {
                    Ok(snapshots) => StatusResponse::Status(snapshots),
                    Err(_) => error(StatusErrorCode::UnknownEnvironment, None),
                }
            }
            StatusRequest::LogTail(req) => {
                let max = usize::from(req.max.clamp(1, MAX_TAIL_RECORDS));
                let resp = match &self.logbuf {
                    Some(buf) => buf.tail(
                        req.since_seq,
                        req.min_level,
                        max,
                        MAX_FRAME_LEN - REPLY_HEADROOM,
                    ),
                    None => LogTailResp {
                        records: Vec::new(),
                        next_seq: req.since_seq,
                        dropped: 0,
                        buffer_id: 0,
                    },
                };
                StatusResponse::LogTail(resp)
            }
        }
    }

    /// Encode `resp` as a frame that always fits [`MAX_FRAME_LEN`]: an
    /// oversize log tail is halved until it fits (its `next_seq` rewound so
    /// nothing is skipped); anything else that cannot be encoded becomes an
    /// `Internal` error.
    #[must_use]
    pub fn encode_reply(resp: StatusResponse) -> Vec<u8> {
        let mut resp = resp;
        loop {
            match encode_frame(&resp) {
                Ok(frame) => return frame,
                Err(e) => {
                    if let StatusResponse::LogTail(tail) = &mut resp {
                        if tail.records.len() > 1 {
                            let keep = tail.records.len() / 2;
                            tail.next_seq = tail.records[keep].seq;
                            tail.records.truncate(keep);
                            continue;
                        }
                    }
                    tracing::error!(error = %e, "could not encode a status reply");
                    return encode_frame(&error(StatusErrorCode::Internal, None))
                        .unwrap_or_default();
                }
            }
        }
    }
}

/// An environment filter is `"default"` or a valid environment name.
fn valid_environment_filter(env: &str) -> bool {
    env.len() <= MAX_ENVIRONMENT_LEN
        && (env == crate::status::DEFAULT_ENVIRONMENT_LABEL
            || crate::config::validate_environment(env).is_ok())
}

fn error(code: StatusErrorCode, retry_after: Option<u32>) -> StatusResponse {
    StatusResponse::Error { code, retry_after }
}

/// Serve one accepted connection: one request frame in (under `read_timeout`),
/// one reply frame out. A framing error or timeout drops the connection.
pub async fn serve_connection<S>(
    svc: &StatusService,
    mut stream: S,
    peer_uid: u32,
    read_timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let read = async {
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).await.ok()?;
        let len = frame_len(prefix).ok()?;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.ok()?;
        Some(body)
    };
    let Ok(Some(body)) = tokio::time::timeout(read_timeout, read).await else {
        return;
    };
    let reply = StatusService::encode_reply(svc.handle_body(peer_uid, &body).await);
    let write = async {
        stream.write_all(&reply).await?;
        stream.flush().await
    };
    if let Ok(Err(e)) = tokio::time::timeout(read_timeout, write).await {
        tracing::debug!(error = %e, "status reply write failed");
    }
}

/// A status listener made ready before the daemon hardens itself: on Unix the
/// socket is already bound with its final mode and owner; on Windows (where
/// the pipe must be created inside the async runtime) it carries the
/// parameters only.
#[derive(Debug)]
pub struct PreparedEndpoint {
    config: StatusEndpointConfig,
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
}

impl PreparedEndpoint {
    /// The listener parameters.
    #[must_use]
    pub fn config(&self) -> &StatusEndpointConfig {
        &self.config
    }
}

/// Bind the status socket (Unix) or record the pipe parameters (Windows).
/// Call while still privileged, before the hardening profile.
#[cfg(unix)]
pub fn prepare(config: StatusEndpointConfig) -> std::io::Result<PreparedEndpoint> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    let path = &config.path;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if parent.exists() {
            refuse_shared_parent(parent)?;
        } else {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
            if let Some(gid) = config.gid {
                std::os::unix::fs::chown(parent, None, Some(gid))?;
            }
        }
    }
    // Replace a stale socket from a previous run — but never another kind of
    // file: a misconfigured path must not delete arbitrary data as root.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                ),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(config.mode))?;
    if let Some(gid) = config.gid {
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    listener.set_nonblocking(true)?;
    Ok(PreparedEndpoint { config, listener })
}

/// Refuse to bind, chmod and chown by path as root inside a directory another
/// user can write: they could swap the fresh socket for a symlink in between
/// and have root re-own an arbitrary file. Under systemd the runtime
/// directory is recreated root-owned on every start (the daemon binds before
/// handing it to the service user), so this only trips on a stale directory
/// left by a run outside systemd — remove it, or point `status.socket`
/// elsewhere.
#[cfg(unix)]
fn refuse_shared_parent(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        if ferro_harden::is_root() {
            let meta = std::fs::metadata(dir)?;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is writable by a user other than root; refusing to create the \
                         status socket there as root",
                        dir.display()
                    ),
                ));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = dir;
    Ok(())
}

/// Let the status group reach the socket once the daemon has (re)arranged
/// its runtime directories — call after `hardening::prepare_runtime_paths`.
/// See [`ensure_group_can_traverse`].
pub fn grant_group_traverse(prepared: &PreparedEndpoint) {
    #[cfg(unix)]
    if let Some(parent) = prepared
        .config
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        ensure_group_can_traverse(parent, prepared.config.gid);
    }
    #[cfg(not(unix))]
    let _ = prepared;
}

/// The status socket's parent is often the helper's runtime directory
/// (`/run/ferrogate`, `0750`, owned by the service account). Members of the
/// status group must be able to traverse it, so grant search-only access to
/// others (`o+x`, no listing) when they could not otherwise reach the socket.
/// Every socket inside keeps its own `0660` mode, which the kernel enforces on
/// `connect(2)`, so this exposes no socket to a new peer. Best-effort: a
/// failure is logged and the bind continues.
#[cfg(unix)]
fn ensure_group_can_traverse(dir: &std::path::Path, gid: Option<u32>) {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let Some(gid) = gid else { return };
    let Ok(meta) = std::fs::metadata(dir) else {
        return;
    };
    let mode = meta.mode() & 0o7777;
    let others_search = mode & 0o001 != 0;
    let group_search = meta.gid() == gid && mode & 0o010 != 0;
    if others_search || group_search {
        return;
    }
    match std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode | 0o001)) {
        Ok(()) => tracing::info!(
            dir = %dir.display(),
            "granted search-only access (o+x) on the status socket's directory so the status \
             group can reach the socket; each socket keeps its own 0660 mode"
        ),
        Err(e) => tracing::warn!(
            dir = %dir.display(), error = %e,
            "the status group may not be able to reach the status socket (its directory is not \
             searchable); make the directory traversable or move status.socket"
        ),
    }
}

/// Record the pipe parameters (Windows creates the pipe inside the runtime).
#[cfg(windows)]
pub fn prepare(config: StatusEndpointConfig) -> std::io::Result<PreparedEndpoint> {
    Ok(PreparedEndpoint { config })
}

/// No local IPC transport on this platform.
#[cfg(not(any(unix, windows)))]
pub fn prepare(_config: StatusEndpointConfig) -> std::io::Result<PreparedEndpoint> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the status endpoint needs a Unix socket or a named pipe",
    ))
}

/// No local IPC transport on this platform.
#[cfg(not(any(unix, windows)))]
#[allow(clippy::unused_async)]
pub async fn serve<F>(
    _prepared: PreparedEndpoint,
    _svc: StatusService,
    _shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()>,
{
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the status endpoint needs a Unix socket or a named pipe",
    ))
}

/// Serve until `shutdown` resolves (Unix domain socket).
#[cfg(unix)]
pub async fn serve<F>(
    prepared: PreparedEndpoint,
    svc: StatusService,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()>,
{
    let PreparedEndpoint { config, listener } = prepared;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let sem = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent));
    tracing::info!(listener = %config.path.display(), "status endpoint listening");
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, _addr)) = accepted else { continue };
                // Shed load instead of queueing: a full house drops the newcomer.
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else { continue };
                let peer_uid = stream.peer_cred().map_or(UNKNOWN_PEER, |c| c.uid());
                let svc = svc.clone();
                let timeout = config.read_timeout;
                tokio::spawn(async move {
                    let _permit = permit;
                    serve_connection(&svc, stream, peer_uid, timeout).await;
                });
            }
        }
    }
    Ok(())
}

/// Serve until `shutdown` resolves (Windows named pipe, DACL-restricted to
/// SYSTEM, Administrators and the status group).
#[cfg(windows)]
pub async fn serve<F>(
    prepared: PreparedEndpoint,
    svc: StatusService,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()>,
{
    use std::os::windows::io::AsRawHandle as _;

    let PreparedEndpoint { config } = prepared;
    let addr = config.path.clone().into_os_string();
    let group = config.group.clone();
    let mut listener = ferro_winauth::create_server_pipe(&addr, true, Some(group.as_str()))?;
    let sem = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent));
    tracing::info!(listener = %config.path.display(), group = %group, "status endpoint listening");
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            res = listener.connect() => {
                if res.is_err() {
                    continue;
                }
                let next = match ferro_winauth::create_server_pipe(&addr, false, Some(group.as_str())) {
                    Ok(next) => next,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to create the next status pipe instance; stopping");
                        break;
                    }
                };
                let connected = std::mem::replace(&mut listener, next);
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else { continue };
                // The pipe client's user RID stands in for a uid (rate limiting).
                let peer_uid = ferro_winauth::client_process_id(connected.as_raw_handle())
                    .ok()
                    .and_then(|pid| ferro_winauth::process_user_rid(pid).ok())
                    .unwrap_or(UNKNOWN_PEER);
                let svc = svc.clone();
                let timeout = config.read_timeout;
                tokio::spawn(async move {
                    let _permit = permit;
                    serve_connection(&svc, connected, peer_uid, timeout).await;
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{StatusHandle, DEFAULT_ENVIRONMENT_LABEL};
    use mia_status_proto::{Level, LogTailReq, StatusReq};

    fn service(rate: u32) -> StatusService {
        let reg = StatusRegistry::new(vec![
            StatusHandle::new(DEFAULT_ENVIRONMENT_LABEL, 100),
            StatusHandle::new("prod", 100),
        ]);
        let buf = LogBuffer::new(100, 1 << 20);
        StatusService::new(reg, Some(buf), rate).with_clock(Arc::new(|| 100))
    }

    fn body<T: serde::Serialize>(v: &T) -> Vec<u8> {
        encode_frame(v).unwrap()[4..].to_vec()
    }

    #[tokio::test]
    #[allow(clippy::items_after_statements)]
    async fn answers_status_and_log_tail_and_rejects_everything_else() {
        let svc = service(100);
        let resp = svc
            .handle_body(1, &body(&StatusRequest::Status(StatusReq::default())))
            .await;
        assert!(matches!(resp, StatusResponse::Status(ref v) if v.len() == 2));

        let resp = svc
            .handle_body(
                1,
                &body(&StatusRequest::LogTail(LogTailReq {
                    since_seq: 0,
                    min_level: Level::Info,
                    max: 10,
                })),
            )
            .await;
        assert!(matches!(resp, StatusResponse::LogTail(_)));

        // A helper-API request shape is refused.
        #[derive(serde::Serialize)]
        struct HelperReq {
            audience: String,
            dpop_jkt: String,
            ttl_secs: u32,
        }
        let helper = body(&HelperReq {
            audience: "a".into(),
            dpop_jkt: "b".into(),
            ttl_secs: 1,
        });
        assert_eq!(
            svc.handle_body(1, &helper).await,
            StatusResponse::Error {
                code: StatusErrorCode::UnsupportedRequest,
                retry_after: None
            }
        );
        // Garbage too.
        assert!(matches!(
            svc.handle_body(1, &[0xff, 0x00, 0x13]).await,
            StatusResponse::Error {
                code: StatusErrorCode::UnsupportedRequest,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn environment_filters_are_validated() {
        let svc = service(100);
        let ask = |env: &str| {
            body(&StatusRequest::Status(StatusReq {
                environment: Some(env.to_string()),
            }))
        };
        assert!(matches!(
            svc.handle_body(1, &ask("prod")).await,
            StatusResponse::Status(ref v) if v.len() == 1
        ));
        assert!(matches!(
            svc.handle_body(1, &ask("../etc")).await,
            StatusResponse::Error {
                code: StatusErrorCode::MalformedRequest,
                ..
            }
        ));
        assert!(matches!(
            svc.handle_body(1, &ask("qa")).await,
            StatusResponse::Error {
                code: StatusErrorCode::UnknownEnvironment,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn rate_limit_is_per_uid() {
        let svc = service(2);
        let req = body(&StatusRequest::Status(StatusReq::default()));
        assert!(matches!(
            svc.handle_body(7, &req).await,
            StatusResponse::Status(_)
        ));
        assert!(matches!(
            svc.handle_body(7, &req).await,
            StatusResponse::Status(_)
        ));
        assert!(matches!(
            svc.handle_body(7, &req).await,
            StatusResponse::Error {
                code: StatusErrorCode::RateLimited,
                retry_after: Some(1)
            }
        ));
        // Another uid has its own budget.
        assert!(matches!(
            svc.handle_body(8, &req).await,
            StatusResponse::Status(_)
        ));
    }

    #[test]
    fn limiter_memory_is_bounded() {
        let l = RateLimiter::new(1);
        for uid in 0..u32::try_from(MAX_TRACKED_UIDS).unwrap() {
            assert!(l.allow(uid, 5));
        }
        // Full, all windows current: a new uid is refused (fail closed)...
        assert!(!l.allow(999_999, 5));
        // ...until the windows roll over and are purged.
        assert!(l.allow(999_999, 6));
    }

    #[test]
    fn oversize_log_tail_is_trimmed_to_fit() {
        use mia_status_proto::{LogField, LogRecord};
        let records = (0..200)
            .map(|i| LogRecord {
                seq: i,
                ts_ms: 0,
                level: Level::Info,
                target: "mia".into(),
                environment: None,
                message: "m".repeat(500),
                fields: vec![LogField {
                    name: "f".into(),
                    value: "v".repeat(500),
                }],
            })
            .collect();
        let frame = StatusService::encode_reply(StatusResponse::LogTail(LogTailResp {
            records,
            next_seq: 200,
            dropped: 0,
            buffer_id: 1,
        }));
        assert!(frame.len() <= MAX_FRAME_LEN + 4);
        let resp: StatusResponse = mia_status_proto::read_frame(&mut &frame[..]).unwrap();
        let StatusResponse::LogTail(tail) = resp else {
            panic!("expected a log tail")
        };
        assert!(!tail.records.is_empty() && tail.records.len() < 200);
        assert_eq!(tail.next_seq, tail.records.last().unwrap().seq + 1);
    }

    #[test]
    fn group_file_lookup() {
        let text = "# comment\nroot:x:0:\nferrogate-status:x:991:alice,bob\nstaff:*:20:\n";
        assert_eq!(parse_group_file(text, "ferrogate-status"), Some(991));
        assert_eq!(parse_group_file(text, "staff"), Some(20));
        assert_eq!(parse_group_file(text, "nope"), None);
        assert_eq!(parse_group_file("bad-line\n", "bad-line"), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_endpoint_round_trip_and_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("mia-status-srv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("run").join("s.sock");
        let prepared = prepare(StatusEndpointConfig {
            path: path.clone(),
            mode: 0o660,
            gid: None,
            group: String::new(),
            rate_limit_per_sec: 100,
            max_concurrent: 4,
            read_timeout: Duration::from_secs(2),
        })
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(prepared, service(100), async {
            let _ = rx.await;
        }));
        let p = path.clone();
        let resp: StatusResponse = tokio::task::spawn_blocking(move || {
            let mut s = std::os::unix::net::UnixStream::connect(&p).unwrap();
            mia_status_proto::write_frame(&mut s, &StatusRequest::Status(StatusReq::default()))
                .unwrap();
            mia_status_proto::read_frame(&mut s).unwrap()
        })
        .await
        .unwrap();
        assert!(matches!(resp, StatusResponse::Status(ref v) if v.len() == 2));
        let _ = tx.send(());
        task.await.unwrap().unwrap();

        // A non-socket file at the path is never deleted.
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"precious").unwrap();
        let err = prepare(StatusEndpointConfig {
            path: path.clone(),
            mode: 0o660,
            gid: None,
            group: String::new(),
            rate_limit_per_sec: 1,
            max_concurrent: 1,
            read_timeout: Duration::from_secs(1),
        })
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
