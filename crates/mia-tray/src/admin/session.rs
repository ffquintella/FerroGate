//! The window's link to CMIS (F22 §3): one worker thread runs a small tokio
//! runtime that owns the `ferrogate_admin_client::client::AdminSession`, and
//! with it the only copy of the session token. The window sends [`Cmd`]s and
//! polls [`Reply`]s each frame, so it never blocks on the network or on a
//! security-key prompt, and never holds the token.

//! Ending the session (sign-out, idle lock, close) goes through
//! [`Link::end_session`]: the token leaves the slot at once and a separate
//! task sends the `Logout`, so a stuck RPC can neither delay nor drop it.

//! Enrollment and factor management (F22 §3a) ride the same queue; the
//! worker keeps no state between commands (nonces and creation requests go
//! back and forth with the window).

use std::sync::Arc;
use std::time::Duration;

use ferrogate_admin_client::client::{
    logout_task, AdminSession, ClientConfig, Factor, LoginInfo, Methods,
};
use ferrogate_admin_client::enroll::EnrollmentOffer;
use ferrogate_admin_client::error::ClientError;
use ferrogate_admin_client::factors::{register_key, AddNonce, AddOffer, FactorInfo, FactorMethod};
use ferrogate_admin_client::session::SessionHandle;
use ferrogate_admin_client::webauthn::{
    Authenticator, AuthenticatorError, CreationRequest, WebAuthnAttestation,
};
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
    /// `BeginEnrollment` (a copy of the token; the wizard keeps its own).
    BeginEnrollment {
        /// The enrollment or reset token.
        token: Secret,
    },
    /// Register the platform's key for an enrollment (no server call).
    EnrollKey {
        /// The server's creation request.
        request: Box<CreationRequest>,
        /// The key's label.
        label: String,
    },
    /// `CompleteEnrollment`.
    CompleteEnrollment {
        /// The token (a copy).
        token: Secret,
        /// The new password.
        password: Secret,
        /// A code from the new (or, for a reset, the current) authenticator.
        code: Option<Secret>,
        /// The registered key.
        key: Option<WebAuthnAttestation>,
    },
    /// `ListMyFactors`.
    ListFactors,
    /// `BeginAddFactor`.
    BeginAddFactor {
        /// What to add.
        method: FactorMethod,
    },
    /// `CompleteAddFactor` for a TOTP seed.
    CompleteAddTotp {
        /// The ceremony's nonce.
        nonce: AddNonce,
        /// A code from the new authenticator.
        code: Secret,
        /// Proof of a factor already held.
        proof: FactorChoice,
    },
    /// `CompleteAddFactor` for a new key of this platform.
    CompleteAddKey {
        /// The ceremony's nonce.
        nonce: AddNonce,
        /// The server's creation request.
        request: Box<CreationRequest>,
        /// The key's label.
        label: String,
        /// Proof of a factor already held.
        proof: FactorChoice,
    },
    /// `RemoveFactor`.
    RemoveFactor {
        /// The factor (as the server listed it).
        factor_id: String,
        /// Proof of a factor the account keeps.
        proof: FactorChoice,
    },
}

static_assertions::assert_not_impl_any!(Cmd: std::fmt::Debug, std::fmt::Display, Clone);

/// A [`Cmd`] and the session epoch the window saw when it queued it: one
/// queued before a lock, sign-out or close is answered but never sent.
struct Queued {
    epoch: u64,
    cmd: Cmd,
}

/// The worker's answer to one [`Cmd`]. Never carries a credential; a
/// TOTP seed offered by the server travels only inside its wiped buffer.
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
    /// Answer to [`Cmd::BeginEnrollment`].
    EnrollmentBegun(Result<Box<EnrollmentOffer>, ClientError>),
    /// Answer to [`Cmd::EnrollKey`].
    EnrollKeyMade(Result<WebAuthnAttestation, ClientError>),
    /// Answer to [`Cmd::CompleteEnrollment`]: the admin id.
    Enrolled(Result<String, ClientError>),
    /// Answer to [`Cmd::ListFactors`].
    Factors(Result<Vec<FactorInfo>, ClientError>),
    /// Answer to [`Cmd::BeginAddFactor`].
    AddFactorBegun(Result<(AddNonce, AddOffer), ClientError>),
    /// Answer to [`Cmd::CompleteAddTotp`] or [`Cmd::CompleteAddKey`]: the
    /// new factor's id.
    FactorAdded(Result<String, ClientError>),
    /// Answer to [`Cmd::RemoveFactor`].
    FactorRemoved(Result<(), ClientError>),
}

static_assertions::assert_not_impl_any!(Reply: std::fmt::Debug, std::fmt::Display, Clone);

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
        let (step, reply) = refused(cmd, &ended);
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
        other => run_factors(conn, other, key).await,
    }
}

/// [`run`] for enrollment and factor management.
async fn run_factors(
    conn: &mut AdminSession,
    cmd: Cmd,
    key: Option<&Arc<dyn Authenticator>>,
) -> Reply {
    let factor = |choice: FactorChoice| match choice {
        FactorChoice::Code(code) => Ok(Factor::Totp(code)),
        FactorChoice::SecurityKey => key
            .map(|k| Factor::SecurityKey(Arc::clone(k)))
            .ok_or(ClientError::Authenticator(AuthenticatorError::Unavailable)),
    };
    let platform_key = || {
        key.cloned()
            .ok_or(ClientError::Authenticator(AuthenticatorError::Unavailable))
    };
    match cmd {
        Cmd::BeginEnrollment { token } => {
            let result = conn.begin_enrollment(&token).await.map(Box::new);
            drop(token);
            log_failure("begin_enrollment", result.as_ref().err());
            Reply::EnrollmentBegun(result)
        }
        Cmd::EnrollKey { request, label } => {
            let result = match platform_key() {
                Ok(k) => register_key(k, &request, &label).await,
                Err(e) => Err(e),
            };
            log_failure("enroll_key", result.as_ref().err());
            Reply::EnrollKeyMade(result)
        }
        Cmd::CompleteEnrollment {
            token,
            password,
            code,
            key: attestation,
        } => {
            let result = conn
                .complete_enrollment(&token, password, code, attestation)
                .await;
            drop(token);
            log_failure("complete_enrollment", result.as_ref().err());
            Reply::Enrolled(result)
        }
        Cmd::ListFactors => {
            let result = conn.list_factors().await;
            log_failure("list_factors", result.as_ref().err());
            Reply::Factors(result)
        }
        Cmd::BeginAddFactor { method } => {
            let result = conn.begin_add_factor(method).await;
            log_failure("begin_add_factor", result.as_ref().err());
            Reply::AddFactorBegun(result)
        }
        Cmd::CompleteAddTotp { nonce, code, proof } => {
            let result = match factor(proof) {
                Ok(p) => conn.complete_add_totp(nonce, code, p).await,
                Err(e) => Err(e),
            };
            log_failure("complete_add_factor", result.as_ref().err());
            Reply::FactorAdded(result)
        }
        Cmd::CompleteAddKey {
            nonce,
            request,
            label,
            proof,
        } => {
            let result = match (platform_key(), factor(proof)) {
                (Ok(k), Ok(p)) => conn.complete_add_key(nonce, &request, k, &label, p).await,
                (Err(e), _) | (_, Err(e)) => Err(e),
            };
            log_failure("complete_add_factor", result.as_ref().err());
            Reply::FactorAdded(result)
        }
        Cmd::RemoveFactor { factor_id, proof } => {
            let result = match factor(proof) {
                Ok(p) => conn.remove_factor(&factor_id, p).await,
                Err(e) => Err(e),
            };
            log_failure("remove_factor", result.as_ref().err());
            Reply::FactorRemoved(result)
        }
        Cmd::Offer { .. } | Cmd::SignIn { .. } | Cmd::StepUp { .. } => {
            refused(cmd, &ClientError::FactorNotOffered).1
        }
    }
}

/// The reply to `cmd` when it is not sent (its secrets are wiped here).
fn refused(cmd: Cmd, e: &ClientError) -> (&'static str, Reply) {
    fn failed<T>(e: &ClientError) -> Result<T, ClientError> {
        Err(e.clone())
    }
    let err = || e;
    match cmd {
        Cmd::Offer { username } => (
            "offer",
            Reply::Offered {
                username,
                result: failed(err()),
            },
        ),
        Cmd::SignIn { username, .. } => (
            "sign_in",
            Reply::SignedIn {
                username,
                result: failed(err()),
            },
        ),
        Cmd::StepUp { .. } => ("step_up", Reply::SteppedUp(failed(err()))),
        Cmd::BeginEnrollment { .. } => ("begin_enrollment", Reply::EnrollmentBegun(failed(err()))),
        Cmd::EnrollKey { .. } => ("enroll_key", Reply::EnrollKeyMade(failed(err()))),
        Cmd::CompleteEnrollment { .. } => ("complete_enrollment", Reply::Enrolled(failed(err()))),
        Cmd::ListFactors => ("list_factors", Reply::Factors(failed(err()))),
        Cmd::BeginAddFactor { .. } => ("begin_add_factor", Reply::AddFactorBegun(failed(err()))),
        Cmd::CompleteAddTotp { .. } | Cmd::CompleteAddKey { .. } => {
            ("complete_add_factor", Reply::FactorAdded(failed(err())))
        }
        Cmd::RemoveFactor { .. } => ("remove_factor", Reply::FactorRemoved(failed(err()))),
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
    fn refused_config() -> ClientConfig {
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
        let mut w = spawn(refused_config(), None, wake).unwrap();
        assert!(w.send(Cmd::SignIn {
            username: "alice".into(),
            password: secret("pw"),
            factor: FactorChoice::SecurityKey,
        }));
        assert!(matches!(
            next(&mut w),
            Reply::SignedIn {
                username,
                result: Err(ClientError::Authenticator(AuthenticatorError::Unavailable)),
            } if username == "alice"
        ));
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
        let mut conn = AdminSession::new(refused_config());
        let handle = conn.session_handle(logout_tx);
        let queued_at = handle.epoch();
        handle.end();
        let sign_in = Cmd::SignIn {
            username: "alice".into(),
            password: secret("pw"),
            factor: FactorChoice::Code(secret("123456")),
        };
        // Stale: refused here (a sent one would fail to dial instead).
        assert!(matches!(
            rt.block_on(run(&mut conn, queued_at, sign_in, None)),
            Reply::SignedIn {
                username,
                result: Err(ClientError::SessionEnded),
            } if username == "alice"
        ));
        let step_up = Cmd::StepUp {
            factor: FactorChoice::Code(secret("123456")),
        };
        assert!(matches!(
            rt.block_on(run(&mut conn, queued_at, step_up, None)),
            Reply::SteppedUp(Err(ClientError::SessionEnded))
        ));
        // Enrollment and factor commands obey the same rule.
        let stale = [
            Cmd::BeginEnrollment {
                token: secret("fgae_token"),
            },
            Cmd::CompleteEnrollment {
                token: secret("fgae_token"),
                password: secret("pw"),
                code: Some(secret("123456")),
                key: None,
            },
            Cmd::ListFactors,
            Cmd::BeginAddFactor {
                method: FactorMethod::SecurityKey,
            },
            Cmd::RemoveFactor {
                factor_id: "totp".into(),
                proof: FactorChoice::Code(secret("123456")),
            },
        ];
        for cmd in stale {
            let ended = match rt.block_on(run(&mut conn, queued_at, cmd, None)) {
                Reply::EnrollmentBegun(r) => r.err(),
                Reply::Enrolled(r) => r.err(),
                Reply::Factors(r) => r.err(),
                Reply::AddFactorBegun(r) => r.err(),
                Reply::FactorRemoved(r) => r.err(),
                _ => panic!("a reply of another kind"),
            };
            assert_eq!(ended, Some(ClientError::SessionEnded));
        }
        // Queued after the lock: it goes out.
        let offer = Cmd::Offer {
            username: "alice".into(),
        };
        let reply = rt.block_on(run(&mut conn, handle.epoch(), offer, None));
        assert!(matches!(
            reply,
            Reply::Offered {
                result: Err(ClientError::Connect(_)),
                ..
            }
        ));
    }

    #[test]
    fn without_a_key_backend_no_key_is_registered_and_nothing_is_sent() {
        let mut w = spawn(refused_config(), None, Arc::new(|| {})).unwrap();
        let options =
            ferrogate_admin_client::webauthn::creation_request(&ferro_like_options()).unwrap();
        assert!(w.send(Cmd::EnrollKey {
            request: Box::new(options),
            label: "Desk key".into(),
        }));
        assert!(matches!(
            next(&mut w),
            Reply::EnrollKeyMade(Err(ClientError::Authenticator(
                AuthenticatorError::Unavailable
            )))
        ));
        // A factor command without a session never dials.
        assert!(w.send(Cmd::ListFactors));
        assert!(matches!(
            next(&mut w),
            Reply::Factors(Err(ClientError::SessionEnded))
        ));
        w.stop(SHUTDOWN_WAIT);
    }

    /// Creation options as CMIS sends them.
    fn ferro_like_options() -> ferrogate_admin_client::webauthn::CreationOptions {
        ferrogate_admin_client::webauthn::CreationOptions {
            challenge: vec![3; 32],
            rp_id: "ferrogate-admin.ferrogate.test".into(),
            rp_name: "FerroGate".into(),
            user_id: vec![4; 32],
            user_name: "alice".into(),
            display_name: "Alice".into(),
            pub_key_cred_params: vec![-7, -8],
            exclude_credential_ids: Vec::new(),
            user_verification: 1,
            attestation: 1,
        }
    }

    #[test]
    fn a_step_up_without_a_session_is_refused_locally() {
        let mut w = spawn(refused_config(), None, Arc::new(|| {})).unwrap();
        assert!(w.send(Cmd::StepUp {
            factor: FactorChoice::Code(secret("123456")),
        }));
        assert!(matches!(
            next(&mut w),
            Reply::SteppedUp(Err(ClientError::SessionEnded))
        ));
        w.end_session();
        w.stop(SHUTDOWN_WAIT);
    }
}
