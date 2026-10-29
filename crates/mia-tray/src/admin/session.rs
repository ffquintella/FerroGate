//! The window's link to CMIS (F22 §3): one worker thread runs a small tokio
//! runtime that owns the `ferrogate_admin_client::client::AdminSession`, and
//! with it the only copy of the session token. The window sends [`Cmd`]s and
//! polls [`Reply`]s each frame, so it never blocks on the network or on a
//! security-key prompt, and never holds the token.

//! Ending the session (sign-out, idle lock, close) goes through
//! [`Link::end_session`]: the token leaves the slot at once and a separate
//! task sends the `Logout`, so a stuck RPC can neither delay nor drop it.

use std::sync::Arc;
use std::time::Duration;

use ferrogate_admin_client::client::{
    logout_task, AdminSession, ClientConfig, Factor, LoginInfo, Methods,
};
use ferrogate_admin_client::error::ClientError;
use ferrogate_admin_client::session::SessionHandle;
use ferrogate_admin_client::webauthn::{Authenticator, AuthenticatorError};
use tokio::sync::mpsc;

use super::secret::Secret;

/// Commands waiting for the worker, at most.
pub const QUEUE: usize = 8;
/// How long closing the window waits for the `Logout` to leave.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

/// The second factor the window chose.
pub enum FactorChoice {
    /// A typed TOTP code.
    Code(Secret),
    /// A touch of the platform's security key.
    SecurityKey,
}

/// A command from the window. Carries secrets only for the one call that
/// needs them; dropped (wiped) when the call returns.
pub enum Cmd {
    /// `BeginLogin`: which factors `username` may use here.
    Offer {
        /// The user name.
        username: String,
    },
    /// Sign in.
    SignIn {
        /// The user name.
        username: String,
        /// The password.
        password: Secret,
        /// The second factor.
        factor: FactorChoice,
    },
    /// Step up.
    StepUp {
        /// The second factor.
        factor: FactorChoice,
    },
}

static_assertions::assert_not_impl_any!(Cmd: std::fmt::Debug, std::fmt::Display, Clone);

/// A [`Cmd`] and the session epoch the window saw when it queued it: one
/// queued before a lock, sign-out or close is answered but never sent.
struct Queued {
    epoch: u64,
    cmd: Cmd,
}

/// The worker's answer to one [`Cmd`]. Never carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Answer to [`Cmd::Offer`].
    Offered {
        /// The user name asked about.
        username: String,
        /// The offered methods.
        result: Result<Methods, ClientError>,
    },
    /// Answer to [`Cmd::SignIn`].
    SignedIn {
        /// The user name that signed in (or tried to).
        username: String,
        /// The session summary.
        result: Result<LoginInfo, ClientError>,
    },
    /// Answer to [`Cmd::StepUp`]: the end of the step-up window.
    SteppedUp(Result<i64, ClientError>),
}

/// What the window needs from the worker (a test double stands in for it).
pub trait Link {
    /// Queue `cmd`; `false` when the queue is full or the worker is gone
    /// (`cmd` is then dropped and wiped).
    fn send(&mut self, cmd: Cmd) -> bool;
    /// The next reply, if one arrived.
    fn try_recv(&mut self) -> Option<Reply>;
    /// End the session now (no network wait); the `Logout` follows.
    fn end_session(&mut self);
    /// The window is closing: end the session and let the `Logout` leave,
    /// waiting at most `wait`.
    fn shutdown(self: Box<Self>, wait: Duration) {
        let mut this = self;
        this.end_session();
        let _ = wait;
    }
}

/// The worker thread and its channels.
pub struct Worker {
    cmds: Option<mpsc::Sender<Queued>>,
    replies: std::sync::mpsc::Receiver<Reply>,
    session: Option<SessionHandle>,
    done: std::sync::mpsc::Receiver<()>,
}

static_assertions::assert_not_impl_any!(Worker: std::fmt::Debug, std::fmt::Display, Clone);

/// Start the worker for `cfg`, with the platform's security key (if any).
/// `wake` is called after each reply (the window repaints).
///
/// # Errors
/// The thread or its runtime cannot be created.
pub fn spawn(
    cfg: ClientConfig,
    key: Option<Arc<dyn Authenticator>>,
    wake: Arc<dyn Fn() + Send + Sync>,
) -> std::io::Result<Worker> {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Queued>(QUEUE);
    let (reply_tx, reply_rx) = std::sync::mpsc::channel::<Reply>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (logout_tx, logout) = logout_task(cfg.clone());
    let mut conn = AdminSession::new(cfg);
    let session = conn.session_handle(logout_tx);
    std::thread::Builder::new()
        .name("mia-tray-admin-client".into())
        .spawn(move || {
            runtime.block_on(async move {
                let logout = tokio::spawn(logout);
                while let Some(Queued { epoch, cmd }) = cmd_rx.recv().await {
                    let reply = run(&mut conn, epoch, cmd, key.as_ref()).await;
                    if reply_tx.send(reply).is_err() {
                        break;
                    }
                    wake();
                }
                // The window is gone: whatever is left is logged out.
                conn.logout().await;
                drop(conn);
                let _ = logout.await;
            });
            let _ = done_tx.send(());
        })?;
    Ok(Worker {
        cmds: Some(cmd_tx),
        replies: reply_rx,
        session: Some(session),
        done: done_rx,
    })
}

/// Carry out `cmd`, queued at session `epoch`; one queued before the session
/// was ended since is answered `SessionEnded` and not sent (its secrets are
/// wiped here), so the window still gets one reply per command.
async fn run(
    conn: &mut AdminSession,
    epoch: u64,
    cmd: Cmd,
    key: Option<&Arc<dyn Authenticator>>,
) -> Reply {
    if conn.slot().epoch() != epoch {
        let ended = ClientError::SessionEnded;
        let (step, reply) = match cmd {
            Cmd::Offer { username } => (
                "offer",
                Reply::Offered {
                    username,
                    result: Err(ended.clone()),
                },
            ),
            Cmd::SignIn { username, .. } => (
                "sign_in",
                Reply::SignedIn {
                    username,
                    result: Err(ended.clone()),
                },
            ),
            Cmd::StepUp { .. } => ("step_up", Reply::SteppedUp(Err(ended.clone()))),
        };
        log_failure(step, Some(&ended));
        return reply;
    }
    let factor = |choice: FactorChoice| match choice {
        FactorChoice::Code(code) => Ok(Factor::Totp(code)),
        FactorChoice::SecurityKey => key
            .map(|k| Factor::SecurityKey(Arc::clone(k)))
            .ok_or(ClientError::Authenticator(AuthenticatorError::Unavailable)),
    };
    match cmd {
        Cmd::Offer { username } => {
            let result = conn.offer(&username).await;
            log_failure("offer", result.as_ref().err());
            Reply::Offered { username, result }
        }
        Cmd::SignIn {
            username,
            password,
            factor: choice,
        } => {
            let result = match factor(choice) {
                Ok(f) => conn.sign_in(&username, password, f).await,
                Err(e) => Err(e),
            };
            log_failure("sign_in", result.as_ref().err());
            Reply::SignedIn { username, result }
        }
        Cmd::StepUp { factor: choice } => {
            let result = match factor(choice) {
                Ok(f) => conn.step_up(f).await,
                Err(e) => Err(e),
            };
            log_failure("step_up", result.as_ref().err());
            Reply::SteppedUp(result)
        }
    }
}

/// Errors go to the log (the window shows generic text, NRM §5.3.5). Never
/// the user name, a credential or a token: only the step and the inert cause.
fn log_failure(step: &'static str, e: Option<&ClientError>) {
    use ferrogate_admin_client::display::inert;
    match e {
        None => {}
        Some(ClientError::Connect(why)) => {
            tracing::warn!(event = "admin.client.unreachable", step, reason = %inert(why, 160));
        }
        Some(ClientError::Other(r)) => tracing::warn!(
            event = "admin.client.server_error",
            step,
            code = ?r.code,
            reason = %r.reason
        ),
        Some(ClientError::Authenticator(a)) => {
            tracing::info!(event = "admin.client.key_failed", step, reason = %inert(&a.to_string(), 160));
        }
        Some(other) => {
            let kind = match other {
                ClientError::Rejected => "rejected",
                ClientError::Throttled(_) => "throttled",
                ClientError::FactorNotOffered => "factor_not_offered",
                _ => "session_ended",
            };
            tracing::info!(event = "admin.client.refused", step, kind);
        }
    }
}

impl Worker {
    /// End the session, stop the worker and wait up to `wait` for the
    /// `Logout` to leave. A worker still busy then is left to finish on its
    /// own (the process is exiting; its memory goes with it).
    pub fn stop(mut self, wait: Duration) {
        self.end_session();
        self.session = None;
        self.cmds = None;
        let _ = self.done.recv_timeout(wait);
    }
}

impl Link for Worker {
    fn send(&mut self, cmd: Cmd) -> bool {
        let (Some(tx), Some(session)) = (&self.cmds, &self.session) else {
            return false;
        };
        tx.try_send(Queued {
            epoch: session.epoch(),
            cmd,
        })
        .is_ok()
    }

    fn try_recv(&mut self) -> Option<Reply> {
        self.replies.try_recv().ok()
    }

    fn end_session(&mut self) {
        if let Some(s) = &self.session {
            s.end();
        }
    }

    fn shutdown(self: Box<Self>, wait: Duration) {
        (*self).stop(wait);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.end_session();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_admin_client::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};

    /// A configuration that is refused before any dialling.
    fn refused() -> ClientConfig {
        ClientConfig {
            endpoint: "http://127.0.0.1:1".into(),
            pins: Vec::new(),
            device_token_path: None,
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
            client_kind: ferrogate_admin_client::client_kind::TRAY,
        }
    }

    fn secret(text: &str) -> Secret {
        let mut s = Secret::new();
        s.push_str(text);
        s
    }

    fn next(w: &mut Worker) -> Reply {
        for _ in 0..500 {
            if let Some(r) = w.try_recv() {
                return r;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no reply");
    }

    #[test]
    fn replies_come_back_and_a_missing_key_backend_sends_nothing() {
        let woken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let w2 = Arc::clone(&woken);
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            w2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let mut w = spawn(refused(), None, wake).unwrap();
        assert!(w.send(Cmd::SignIn {
            username: "alice".into(),
            password: secret("pw"),
            factor: FactorChoice::SecurityKey,
        }));
        assert_eq!(
            next(&mut w),
            Reply::SignedIn {
                username: "alice".into(),
                result: Err(ClientError::Authenticator(AuthenticatorError::Unavailable)),
            }
        );
        assert!(w.send(Cmd::Offer {
            username: "alice".into()
        }));
        let Reply::Offered {
            result: Err(ClientError::Connect(why)),
            ..
        } = next(&mut w)
        else {
            panic!("a plaintext endpoint is never dialled");
        };
        assert!(why.contains("https://"), "{why}");
        assert!(woken.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        w.stop(SHUTDOWN_WAIT);
    }

    #[test]
    fn a_command_queued_before_a_lock_is_answered_without_being_sent() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (logout_tx, _logout_rx) = mpsc::unbounded_channel();
        let mut conn = AdminSession::new(refused());
        let handle = conn.session_handle(logout_tx);
        let queued_at = handle.epoch();
        handle.end();
        let sign_in = Cmd::SignIn {
            username: "alice".into(),
            password: secret("pw"),
            factor: FactorChoice::Code(secret("123456")),
        };
        // Stale: refused here (a sent one would fail to dial instead).
        assert_eq!(
            rt.block_on(run(&mut conn, queued_at, sign_in, None)),
            Reply::SignedIn {
                username: "alice".into(),
                result: Err(ClientError::SessionEnded),
            }
        );
        let step_up = Cmd::StepUp {
            factor: FactorChoice::Code(secret("123456")),
        };
        assert_eq!(
            rt.block_on(run(&mut conn, queued_at, step_up, None)),
            Reply::SteppedUp(Err(ClientError::SessionEnded))
        );
        // Queued after the lock: it goes out.
        let offer = Cmd::Offer {
            username: "alice".into(),
        };
        let reply = rt.block_on(run(&mut conn, handle.epoch(), offer, None));
        assert!(
            matches!(
                reply,
                Reply::Offered {
                    result: Err(ClientError::Connect(_)),
                    ..
                }
            ),
            "{reply:?}"
        );
    }

    #[test]
    fn a_step_up_without_a_session_is_refused_locally() {
        let mut w = spawn(refused(), None, Arc::new(|| {})).unwrap();
        assert!(w.send(Cmd::StepUp {
            factor: FactorChoice::Code(secret("123456")),
        }));
        assert_eq!(
            next(&mut w),
            Reply::SteppedUp(Err(ClientError::SessionEnded))
        );
        w.end_session();
        w.stop(SHUTDOWN_WAIT);
    }
}
