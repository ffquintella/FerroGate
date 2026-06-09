//! Unix Domain Socket transport for the helper API.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use ferro_audit::AuditEvent;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Semaphore};

use super::{serve_connection, Clock, HelperServerConfig, ServerError, Shared};
use crate::helper::allowlist::Allowlist;
use crate::helper::auth::{AuthError, CallerAuth, PeerCred};
use crate::helper::crl::CrlCache;
use crate::helper::token::ChildTokenMinter;

/// The helper-API server, backed by a Unix Domain Socket.
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
    #[allow(clippy::too_many_arguments)] // each handle is a distinct collaborator.
    pub fn bind(
        config: HelperServerConfig,
        auth: A,
        minter: Option<ChildTokenMinter>,
        allowlist: Option<Allowlist>,
        crl: Arc<CrlCache>,
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
                allowlist: tokio::sync::RwLock::new(allowlist),
                crl,
                audit_tx,
                clock,
                ledger: crate::helper::ledger::CallerLedger::new(),
            }),
        })
    }

    /// Replace the live allowlist (e.g. after a signed refresh from CMIS).
    pub async fn set_allowlist(&self, allowlist: Option<Allowlist>) {
        self.shared.set_allowlist(allowlist).await;
    }

    /// A handle to the observed-caller ledger, for the allowlist-propose task.
    #[must_use]
    pub fn ledger(&self) -> crate::helper::ledger::CallerLedger {
        self.shared.ledger.clone()
    }

    /// The bound socket path (for diagnostics / tests).
    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.config.socket_path
    }

    /// Serve until `shutdown` resolves. Connections already accepted are not
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
                        // SO_PEERCRED is a cheap, non-blocking syscall.
                        let cred = stream
                            .peer_cred()
                            .map(|u| PeerCred {
                                pid: u.pid().and_then(|p| u32::try_from(p).ok()),
                                uid: u.uid(),
                                gid: u.gid(),
                            })
                            .map_err(|_| AuthError::PeerCredUnavailable);
                        serve_connection(&shared, stream, cred, read_timeout).await;
                    });
                }
            }
        }
    }
}
