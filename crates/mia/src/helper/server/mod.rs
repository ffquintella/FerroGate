//! The helper-API server: a local-IPC listener that authenticates callers and
//! mints DPoP-bound child tokens.
//!
//! The transport differs by platform — a Unix Domain Socket on Unix
//! ([`unix`]), a Named Pipe on Windows ([`windows`]) — but the request pipeline
//! is identical and lives here:
//!
//! 1. read one length-delimited CBOR request frame under a deadline;
//! 2. establish caller identity from kernel-attested credentials (the cheap
//!    `SO_PEERCRED` / `GetNamedPipeClientProcessId` step happens on the async
//!    side; the authenticator's blocking work runs on the blocking pool);
//! 3. authorize against the signed allowlist and mint, or refuse.
//!
//! Concurrency model: one task per connection, each holding a permit from a
//! bounded [`Semaphore`], under a per-connection read deadline so a slow or
//! idle client releases its permit promptly and cannot starve others.
//!
//! Audit contract: **every decoded request produces exactly one audit event**
//! (`LocalGrant` on success, `LocalDenied` otherwise). A connection that never
//! delivers a well-formed request frame is not a "request" and is dropped
//! silently. Events are pushed onto an `mpsc` channel; a forwarder task
//! (`audit_client`) drains them to CMIS, decoupling minting latency from the
//! audit network path.

#![cfg(any(unix, windows))]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferro_audit::{AuditEvent, Bytes16, Hash384};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, RwLock};

use crate::helper::allowlist::Allowlist;
use crate::helper::auth::{AuthError, CallerAuth, CallerIdentity, PeerCred};
use crate::helper::crl::{CrlCache, CrlGate};
use crate::helper::ledger::CallerLedger;
use crate::helper::proto::{self, ChildToken, ErrorCode, HelperReq, HelperResp};
use crate::helper::token::ChildTokenMinter;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::HelperServer;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::HelperServer;

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

/// Server configuration. A single struct serves both transports; fields that
/// do not apply to a platform are ignored there (documented per field).
#[derive(Debug, Clone)]
pub struct HelperServerConfig {
    /// Listening address: the UDS path on Unix, or the pipe name on Windows
    /// (e.g. `\\.\pipe\ferrogate-mia`).
    pub socket_path: PathBuf,
    /// **Unix only.** Permission bits applied to the socket (e.g. `0o660`).
    pub socket_mode: u32,
    /// **Unix only.** Optional gid to `chown` the socket to.
    pub socket_gid: Option<u32>,
    /// **Windows only.** Local group whose members may open the pipe (e.g.
    /// `FerroGateClients`). `None` ⇒ the pipe's default DACL applies.
    pub windows_group: Option<String>,
    /// Maximum number of connections served concurrently.
    pub max_concurrent: usize,
    /// Per-connection deadline for receiving the request frame.
    pub read_timeout: Duration,
}

impl Default for HelperServerConfig {
    fn default() -> Self {
        Self {
            #[cfg(unix)]
            socket_path: PathBuf::from("/run/ferrogate/mia.sock"),
            #[cfg(windows)]
            socket_path: PathBuf::from(r"\\.\pipe\ferrogate-mia"),
            socket_mode: 0o660,
            socket_gid: None,
            windows_group: None,
            max_concurrent: 64,
            read_timeout: Duration::from_secs(5),
        }
    }
}

/// Setup / bind failures.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Binding, permission, or ownership setup on the listener failed.
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
    /// The CRL freshness gate (feature F11). A stale or missing CRL, or one
    /// that revokes this host, blocks minting — fail closed.
    crl: Arc<CrlCache>,
    audit_tx: mpsc::Sender<AuditEvent>,
    clock: Clock,
    /// Distinct callers observed this run, fed to the allowlist-propose task.
    ledger: CallerLedger,
}

impl<A: CallerAuth> Shared<A> {
    async fn set_allowlist(&self, allowlist: Option<Allowlist>) {
        *self.allowlist.write().await = allowlist;
    }
}

/// A cheap, clonable handle that swaps the live allowlist while the server is
/// already serving — held by the daemon's SIGHUP reload task so a signed
/// re-sync takes effect without tearing down the helper socket. Obtained via
/// `HelperServer::allowlist_reloader` before `serve_with_shutdown` consumes the
/// server.
pub struct AllowlistReloader<A: CallerAuth> {
    shared: Arc<Shared<A>>,
}

// Derived `Clone` would demand `A: Clone`, which the handle does not need —
// it only ever clones the `Arc`.
impl<A: CallerAuth> Clone for AllowlistReloader<A> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<A: CallerAuth> AllowlistReloader<A> {
    /// Swap the live allowlist. `None` puts the server in deny-all mode (fail
    /// closed), matching startup semantics.
    pub async fn set(&self, allowlist: Option<Allowlist>) {
        self.shared.set_allowlist(allowlist).await;
    }
}

/// Drive one already-accepted connection through the request/response exchange.
///
/// `cred` is the caller's `SO_PEERCRED` / named-pipe credentials, read cheaply
/// on the async side before this is called (or an error if that failed).
async fn serve_connection<A, S>(
    shared: &Arc<Shared<A>>,
    mut stream: S,
    cred: Result<PeerCred, AuthError>,
    read_timeout: Duration,
) where
    A: CallerAuth,
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read the single request frame under a deadline. A timeout or framing
    // error is not a "request" — drop the connection without an audit event.
    let req: HelperReq =
        match tokio::time::timeout(read_timeout, proto::read_frame(&mut stream)).await {
            Ok(Ok(req)) => req,
            Ok(Err(_)) | Err(_) => return,
        };

    let cred = match cred {
        Ok(cred) => cred,
        Err(e) => {
            let resp = process_request(shared, Err(e), &req).await;
            let _ = proto::write_frame(&mut stream, &resp).await;
            return;
        }
    };

    // The authenticator's blocking work (IMA log / `/proc` on Unix; image
    // hashing on Windows) runs on the blocking pool so it never stalls a
    // runtime worker thread.
    let auth_shared = Arc::clone(shared);
    let Ok(id_result) = tokio::task::spawn_blocking(move || auth_shared.auth.identify(cred)).await
    else {
        // The authenticator task panicked. Fail closed, but still record
        // exactly one audit event so the request is accounted for.
        deny(
            shared,
            cred.pid.unwrap_or(0),
            cred.uid,
            [0u8; 48],
            "auth-internal",
        )
        .await;
        let _ = proto::write_frame(&mut stream, &err(ErrorCode::Internal, None)).await;
        return;
    };

    let resp = process_request(shared, id_result, &req).await;
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

    // Record this kernel-attested caller for the allowlist-propose task. Done
    // for every authenticated caller — granted or denied below — since a
    // deny-all host's denials are exactly the bootstrap proposal candidates.
    shared.ledger.observe(id.uid, id.bin_sha);

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

    let now = (shared.clock)();

    // 3.5 CRL gate (feature F11). Fail closed on a missing/stale CRL, and refuse
    //     to mint if this host has been revoked. Checked before allowlisting so
    //     a revoked host cannot mint even if it is otherwise permitted.
    match shared
        .crl
        .gate(&minter.parent_cert_sha_hex(), minter.host_spiffe_id(), now)
        .await
    {
        CrlGate::Ok => {}
        CrlGate::Stale => {
            deny(shared, id.pid, id.uid, id.bin_sha, "crl-stale").await;
            return err(ErrorCode::CrlStale, None);
        }
        CrlGate::Revoked => {
            deny(shared, id.pid, id.uid, id.bin_sha, "svid-revoked").await;
            return err(ErrorCode::PermissionDenied, None);
        }
    }

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
