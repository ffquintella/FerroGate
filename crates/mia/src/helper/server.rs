//! The helper-API server: a Unix-domain-socket listener that authenticates
//! local callers and mints DPoP-bound child tokens.
//!
//! Concurrency model: the accept loop spawns one task per connection, each
//! holding a permit from a bounded [`Semaphore`]. A per-connection read
//! deadline ([`HelperServerConfig::read_timeout`]) means an idle or slow client
//! releases its permit promptly, so it cannot starve well-behaved callers.
//!
//! Audit contract: **every decoded request produces exactly one audit event**
//! (`LocalGrant` on success, `LocalDenied` otherwise). A connection that never
//! delivers a well-formed request frame is not a "request" and is dropped
//! silently. Events are pushed onto an `mpsc` channel; a forwarder task
//! (`audit_client`) drains them to CMIS, decoupling minting latency from the
//! audit network path.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferro_audit::{AuditEvent, Bytes16, Hash384};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, RwLock, Semaphore};

use crate::helper::allowlist::Allowlist;
use crate::helper::auth::{AuthError, CallerAuth, CallerIdentity, PeerCred};
use crate::helper::proto::{self, ChildToken, ErrorCode, HelperReq, HelperResp};
use crate::helper::token::ChildTokenMinter;

/// A monotonic-enough wall clock returning Unix seconds. Injectable for tests.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The default system clock (Unix seconds, saturating at 0 before the epoch).
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    })
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct HelperServerConfig {
    /// Filesystem path of the listening socket.
    pub socket_path: PathBuf,
    /// Permission bits applied to the socket (e.g. `0o660`).
    pub socket_mode: u32,
    /// Optional gid to `chown` the socket to (the `ferrogate-clients` group).
    pub socket_gid: Option<u32>,
    /// Maximum number of connections served concurrently.
    pub max_concurrent: usize,
    /// Per-connection deadline for receiving the request frame.
    pub read_timeout: Duration,
}

impl Default for HelperServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/ferrogate/mia.sock"),
            socket_mode: 0o660,
            socket_gid: None,
            max_concurrent: 64,
            read_timeout: Duration::from_secs(5),
        }
    }
}

/// Setup / bind failures.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Binding, permission, or ownership setup on the socket failed.
    #[error("socket setup: {0}")]
    Socket(#[from] std::io::Error),
}

/// Shared, hot-swappable handles the connection tasks read.
struct Shared<A: CallerAuth> {
    auth: A,
    /// `None` ⇒ the MIA holds no valid host SVID ⇒ refuse all minting.
    minter: Option<ChildTokenMinter>,
    /// `None` ⇒ no valid allowlist loaded ⇒ fail closed, deny all callers.
    allowlist: RwLock<Option<Allowlist>>,
    audit_tx: mpsc::Sender<AuditEvent>,
    clock: Clock,
}

/// The helper-API server.
pub struct HelperServer<A: CallerAuth> {
    listener: UnixListener,
    config: HelperServerConfig,
    shared: Arc<Shared<A>>,
}

impl<A: CallerAuth> HelperServer<A> {
    /// Bind the socket with the configured permissions and prepare to serve.
    ///
    /// Any existing file at `socket_path` is removed first (a stale socket from
    /// a previous run). The socket is created, then its mode (and optionally
    /// its group owner) is set before any client can connect.
    pub fn bind(
        config: HelperServerConfig,
        auth: A,
        minter: Option<ChildTokenMinter>,
        allowlist: Option<Allowlist>,
        audit_tx: mpsc::Sender<AuditEvent>,
        clock: Clock,
    ) -> Result<Self, ServerError> {
        match std::fs::remove_file(&config.socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(ServerError::Socket(e)),
        }
        let listener = UnixListener::bind(&config.socket_path)?;

        let perms = std::fs::Permissions::from_mode(config.socket_mode);
        std::fs::set_permissions(&config.socket_path, perms)?;
        if let Some(gid) = config.socket_gid {
            std::os::unix::fs::chown(&config.socket_path, None, Some(gid))?;
        }

        Ok(Self {
            listener,
            config,
            shared: Arc::new(Shared {
                auth,
                minter,
                allowlist: RwLock::new(allowlist),
                audit_tx,
                clock,
            }),
        })
    }

    /// Replace the live allowlist (e.g. after a signed refresh from CMIS).
    pub async fn set_allowlist(&self, allowlist: Option<Allowlist>) {
        *self.shared.allowlist.write().await = allowlist;
    }

    /// Serve until `shutdown` resolves. Accepted connections in flight are not
    /// forcibly cancelled, but no new connections are accepted afterwards.
    pub async fn serve_with_shutdown<F>(self, shutdown: F)
    where
        F: std::future::Future<Output = ()>,
    {
        let sem = Arc::new(Semaphore::new(self.config.max_concurrent));
        let read_timeout = self.config.read_timeout;
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let Ok((stream, _addr)) = accepted else { continue };
                    let shared = Arc::clone(&self.shared);
                    let sem = Arc::clone(&sem);
                    tokio::spawn(async move {
                        // Hold a permit for the connection's lifetime. The read
                        // deadline bounds how long a slow client can hold it.
                        let Ok(_permit) = sem.acquire().await else { return };
                        handle_conn(shared, stream, read_timeout).await;
                    });
                }
            }
        }
    }

    /// The bound socket path (for diagnostics / tests).
    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.config.socket_path
    }
}

/// Drive one client connection through the request/response exchange.
async fn handle_conn<A: CallerAuth>(
    shared: Arc<Shared<A>>,
    mut stream: UnixStream,
    read_timeout: Duration,
) {
    // Read the single request frame under a deadline. A timeout or framing
    // error is not a "request" — drop the connection without an audit event.
    let req: HelperReq =
        match tokio::time::timeout(read_timeout, proto::read_frame(&mut stream)).await {
            Ok(Ok(req)) => req,
            Ok(Err(_)) | Err(_) => return,
        };

    // Read SO_PEERCRED on the async side (a cheap, non-blocking syscall), then
    // run the authenticator's blocking filesystem work (IMA log,
    // `/proc/<pid>/exe`) on the blocking pool so it never stalls a runtime
    // worker thread.
    let Ok(ucred) = stream.peer_cred() else {
        let resp = process_request(&shared, Err(AuthError::PeerCredUnavailable), &req).await;
        let _ = proto::write_frame(&mut stream, &resp).await;
        return;
    };
    let cred = PeerCred {
        pid: ucred.pid().and_then(|p| u32::try_from(p).ok()),
        uid: ucred.uid(),
        gid: ucred.gid(),
    };

    let auth_shared = Arc::clone(&shared);
    let Ok(id_result) = tokio::task::spawn_blocking(move || auth_shared.auth.identify(cred)).await
    else {
        // The authenticator task panicked. Fail closed, but still record
        // exactly one audit event so the request is accounted for.
        deny(
            &shared,
            cred.pid.unwrap_or(0),
            cred.uid,
            [0u8; 48],
            "auth-internal",
        )
        .await;
        let _ = proto::write_frame(&mut stream, &err(ErrorCode::Internal, None)).await;
        return;
    };

    let resp = process_request(&shared, id_result, &req).await;
    // Best-effort reply; the audit event has already been recorded.
    let _ = proto::write_frame(&mut stream, &resp).await;
}

/// Authorize and mint (or refuse) for one decoded request given the caller
/// identity already resolved by [`CallerAuth`], emitting exactly one audit
/// event before returning the reply.
async fn process_request<A: CallerAuth>(
    shared: &Shared<A>,
    id: Result<CallerIdentity, AuthError>,
    req: &HelperReq,
) -> HelperResp {
    // 1. The caller identity must have been established from kernel-attested
    //    sources.
    let id = match id {
        Ok(id) => id,
        Err(e) => {
            let (pid, uid) = e.partial().unwrap_or((0, 0));
            deny(shared, pid, uid, [0u8; 48], e.reason()).await;
            return err(ErrorCode::PermissionDenied, None);
        }
    };

    // 2. Reject obviously malformed requests (identity is known now, so the
    //    refusal is still attributable).
    if req.audience.is_empty() || req.dpop_jkt.is_empty() || req.ttl_secs == 0 {
        deny(shared, id.pid, id.uid, id.bin_sha, "malformed-request").await;
        return err(ErrorCode::MalformedRequest, None);
    }

    // 3. The MIA must hold a valid host SVID to mint anything.
    let Some(minter) = shared.minter.as_ref() else {
        deny(shared, id.pid, id.uid, id.bin_sha, "no-host-svid").await;
        return err(ErrorCode::NoHostSvid, None);
    };

    // 4. The caller must be on the (signed, fresh) allowlist. A missing
    //    allowlist fails closed.
    let permitted = match &*shared.allowlist.read().await {
        Some(al) => al.permits(id.uid, &id.bin_sha),
        None => false,
    };
    if !permitted {
        deny(shared, id.pid, id.uid, id.bin_sha, "not-allowlisted").await;
        return err(ErrorCode::PermissionDenied, None);
    }

    // 5. Mint.
    let now = (shared.clock)();
    let Ok(tok) = minter.mint(&req.audience, &req.dpop_jkt, req.ttl_secs, &id, now) else {
        deny(shared, id.pid, id.uid, id.bin_sha, "mint-failed").await;
        return err(ErrorCode::Internal, None);
    };
    record(
        shared,
        AuditEvent::LocalGrant {
            pid: id.pid,
            uid: id.uid,
            bin_sha: Hash384(id.bin_sha),
            jti: Bytes16(tok.jti),
        },
    )
    .await;
    HelperResp::Token(ChildToken {
        jws: tok.jws,
        exp: tok.exp,
    })
}

fn err(code: ErrorCode, retry_after: Option<u32>) -> HelperResp {
    HelperResp::Error { code, retry_after }
}

async fn deny<A: CallerAuth>(
    shared: &Shared<A>,
    pid: u32,
    uid: u32,
    bin_sha: [u8; 48],
    reason: &str,
) {
    record(
        shared,
        AuditEvent::LocalDenied {
            pid,
            uid,
            bin_sha: Hash384(bin_sha),
            reason: reason.to_string(),
        },
    )
    .await;
}

async fn record<A: CallerAuth>(shared: &Shared<A>, event: AuditEvent) {
    if shared.audit_tx.send(event).await.is_err() {
        tracing::warn!("helper-api audit sink closed; event dropped");
    }
}
