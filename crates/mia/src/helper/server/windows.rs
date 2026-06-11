//! Windows Named Pipe transport for the helper API.
//!
//! Mirrors the Unix server: same bounded-concurrency model, read deadline, and
//! one-audit-event-per-request contract. The pipe is created (optionally with
//! a group-restricted DACL) and the connecting client's PID is read through
//! `ferro-winauth`, which owns all the FFI so `mia` stays
//! `#![forbid(unsafe_code)]`.

use std::ffi::OsString;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use ferro_audit::AuditEvent;
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::{mpsc, Semaphore};

use super::{serve_connection, AllowlistReloader, Clock, HelperServerConfig, ServerError, Shared};
use crate::helper::allowlist::Allowlist;
use crate::helper::auth::{AuthError, CallerAuth, PeerCred};
use crate::helper::crl::CrlCache;
use crate::helper::token::ChildTokenMinter;

/// The helper-API server, backed by a Windows Named Pipe.
pub struct HelperServer<A: CallerAuth> {
    addr: OsString,
    group: Option<String>,
    listener: NamedPipeServer,
    config: HelperServerConfig,
    shared: Arc<Shared<A>>,
}

impl<A: CallerAuth> HelperServer<A> {
    /// Create the first pipe instance (with the configured DACL, if any) and
    /// prepare to serve.
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
        let addr = config.socket_path.clone().into_os_string();
        let group = config.windows_group.clone();
        let listener = ferro_winauth::create_server_pipe(&addr, true, group.as_deref())?;
        Ok(Self {
            addr,
            group,
            listener,
            config,
            shared: Arc::new(Shared::new(auth, minter, allowlist, crl, audit_tx, clock)),
        })
    }

    /// Replace the live allowlist (e.g. after a signed refresh from CMIS).
    pub async fn set_allowlist(&self, allowlist: Option<Allowlist>) {
        self.shared.set_allowlist(allowlist).await;
    }

    /// A clonable handle to swap the live allowlist after serving has started.
    /// Windows has no SIGHUP, so the daemon does not currently drive this, but
    /// it keeps the transport API parallel with Unix.
    #[must_use]
    pub fn allowlist_reloader(&self) -> AllowlistReloader<A> {
        AllowlistReloader {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A handle to the observed-caller ledger, for the allowlist-propose task.
    #[must_use]
    pub fn ledger(&self) -> crate::helper::ledger::CallerLedger {
        self.shared.ledger.clone()
    }

    /// The bound pipe name (for diagnostics / tests).
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
        // The "listening" instance; once a client connects we hand it off and
        // create the next instance to keep accepting (the tokio pattern).
        let mut listener = self.listener;
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                res = listener.connect() => {
                    if res.is_err() {
                        continue;
                    }
                    let next =
                        match ferro_winauth::create_server_pipe(&self.addr, false, self.group.as_deref()) {
                            Ok(next) => next,
                            Err(e) => {
                                tracing::error!(error = %e, "failed to create next pipe instance; stopping accept loop");
                                break;
                            }
                        };
                    let connected = std::mem::replace(&mut listener, next);

                    let shared = Arc::clone(&self.shared);
                    let sem = Arc::clone(&sem);
                    tokio::spawn(async move {
                        let Ok(_permit) = sem.acquire().await else { return };
                        // GetNamedPipeClientProcessId is a cheap syscall; the
                        // expensive image attestation runs on the blocking pool
                        // inside serve_connection.
                        let cred = ferro_winauth::client_process_id(connected.as_raw_handle())
                            .map(|pid| PeerCred {
                                pid: Some(pid),
                                uid: 0,
                                gid: 0,
                            })
                            .map_err(|_| AuthError::PeerCredUnavailable);
                        serve_connection(&shared, connected, cred, read_timeout).await;
                    });
                }
            }
        }
    }
}
