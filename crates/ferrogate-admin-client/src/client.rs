//! [`AdminSession`]: one administrator's session with CMIS over the pinned
//! admin channel — sign-in (F20 §6) and step-up (F20 §7) with a TOTP code or
//! a FIDO2 key, `WhoAmI`, and logout. The token lives only in its
//! [`SessionSlot`]; callers see [`LoginInfo`], never the token.

//! Secrets travel in a request message only for the call that needs them and
//! are dropped (wiped) as soon as it returns; prost's own buffers cannot be
//! wiped, the residual exposure F20 §13 records.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ferro_crypto::pin::SpkiPin;
use ferro_proto::admin_v1::admin_client::AdminClient;
use ferro_proto::admin_v1::{
    login_request::SecondFactor, mfa_proof, BeginLoginRequest, BeginLoginResponse,
    BeginStepUpRequest, ClientInfo, LoginRequest, LogoutRequest, MfaProof, StepUpRequest,
    WebAuthnAssertion, WebAuthnChallenge, WhoAmIRequest, WhoAmIResponse,
};
use serde::Serialize;
use tokio::sync::mpsc;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use crate::error::{ClientError, RpcError};
use crate::secret::{Secret, SessionToken};
use crate::session::{bearer_value, Bearer, SessionHandle, SessionSlot};
use crate::transport::{dial, within};
use crate::webauthn::{assertion_request, into_proto, Authenticator, AuthenticatorError};

/// `BeginLoginResponse.methods` value of a TOTP code.
pub const METHOD_TOTP: u32 = 1;
/// `BeginLoginResponse.methods` value of a WebAuthn assertion.
pub const METHOD_WEBAUTHN: u32 = 2;

/// Where and how to connect, and as which client kind.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Admin listener (`https://host:port`).
    pub endpoint: String,
    /// Accepted SPKI pins (never empty).
    pub pins: Vec<SpkiPin>,
    /// Device-token file (throttle hint), if any.
    pub device_token_path: Option<PathBuf>,
    /// Longest wait for TCP plus the pinned TLS handshake.
    pub connect_timeout: Duration,
    /// Deadline of each RPC.
    pub rpc_timeout: Duration,
    /// `ClientInfo.kind` ([`crate::client_kind`]).
    pub client_kind: u32,
}

/// The second-factor methods the server offers this account from this
/// client (F20 §5): the tray may get both, or only a key under the FIDO2
/// policy; the TUI and the CLI get TOTP only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Methods {
    /// A TOTP code is accepted.
    pub totp: bool,
    /// A security key (WebAuthn assertion) is accepted.
    pub security_key: bool,
}

impl Methods {
    fn from_codes(codes: &[u32], challenge: Option<&WebAuthnChallenge>) -> Self {
        Self {
            totp: codes.contains(&METHOD_TOTP),
            security_key: codes.contains(&METHOD_WEBAUTHN) && challenge.is_some(),
        }
    }
}

/// The second factor of one sign-in or step-up.
pub enum Factor {
    /// A TOTP code (wiped after the call).
    Totp(Secret),
    /// A touch of a security key, through this authenticator.
    SecurityKey(Arc<dyn Authenticator>),
}

static_assertions::assert_not_impl_any!(Factor: std::fmt::Debug, std::fmt::Display, Clone);

/// What a successful sign-in reports (never the token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginInfo {
    /// Server idle timeout in seconds.
    pub idle_timeout_secs: i64,
    /// Absolute session expiry (Unix seconds).
    pub absolute_expires_at: i64,
    /// Authenticator assurance level reached (2 TOTP, 3 device-bound key).
    pub aal: u32,
    /// The password expired: the session only allows `ChangePassword`.
    pub password_change_required: bool,
    /// The FIDO2 tray policy holds this session to registering a key.
    pub factor_enrollment_required: bool,
    /// Pseudonymous administrator id.
    pub admin_id: String,
    /// Display name (untrusted text).
    pub display_name: String,
    /// Group names (untrusted text).
    pub groups: Vec<String>,
    /// The methods offered at sign-in, which step-up offers too.
    pub methods: Methods,
}

/// The typed admin client carrying the session's bearer token.
pub type Admin = AdminClient<InterceptedService<Channel, Bearer>>;

/// One administrator session over the pinned admin channel.
pub struct AdminSession {
    cfg: ClientConfig,
    channel: Option<Channel>,
    slot: SessionSlot,
}

static_assertions::assert_not_impl_any!(AdminSession: std::fmt::Debug, std::fmt::Display, Clone);

impl AdminSession {
    /// A session that dials lazily, on the first call.
    #[must_use]
    pub fn new(cfg: ClientConfig) -> Self {
        Self {
            cfg,
            channel: None,
            slot: SessionSlot::new(),
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    /// The session slot (shared with the interceptor).
    #[must_use]
    pub fn slot(&self) -> &SessionSlot {
        &self.slot
    }

    /// Whether a session token is held.
    #[must_use]
    pub fn has_session(&self) -> bool {
        self.slot.has_token()
    }

    /// The UI's handle: [`SessionHandle::end`] wipes the token at once and
    /// hands its `Logout` to `logout_tx`.
    #[must_use]
    pub fn session_handle(&self, logout_tx: mpsc::UnboundedSender<SessionToken>) -> SessionHandle {
        self.slot.handle(logout_tx)
    }

    fn client_info(&self) -> Option<ClientInfo> {
        Some(ClientInfo {
            kind: self.cfg.client_kind,
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    async fn channel(&mut self) -> Result<Channel, String> {
        if let Some(ch) = &self.channel {
            return Ok(ch.clone());
        }
        let ch = dial(&self.cfg.endpoint, &self.cfg.pins, self.cfg.connect_timeout).await?;
        self.channel = Some(ch.clone());
        Ok(ch)
    }

    /// The typed client with this session's bearer token; dials (pinned) on
    /// first use.
    ///
    /// # Errors
    /// Why the admin listener could not be reached; nothing was sent.
    pub async fn admin(&mut self) -> Result<Admin, String> {
        let ch = self.channel().await?;
        Ok(AdminClient::with_interceptor(ch, self.slot.bearer()))
    }

    /// Forget the channel, so the next call dials afresh (after a deadline).
    pub fn reset_channel(&mut self) {
        self.channel = None;
    }

    /// A deadline drops the channel, so the next call redials.
    fn settle<T>(&mut self, r: Result<T, ClientError>) -> Result<T, ClientError> {
        if r.as_ref().err().is_some_and(ClientError::is_deadline) {
            self.channel = None;
        }
        r
    }

    /// `BeginLogin` only: which second factors the server offers `username`
    /// from this client. Carries no secret; the nonce is discarded (a sign-in
    /// asks for a fresh one, so a slow typist never meets an expired nonce).
    ///
    /// # Errors
    /// [`ClientError::Connect`], [`ClientError::Throttled`] or another error.
    pub async fn offer(&mut self, username: &str) -> Result<Methods, ClientError> {
        let r = self.begin_login(username).await;
        self.settle(r)
            .map(|b| Methods::from_codes(&b.methods, b.webauthn.as_ref()))
    }

    async fn begin_login(&mut self, username: &str) -> Result<BeginLoginResponse, ClientError> {
        let mut admin = self.admin().await.map_err(ClientError::Connect)?;
        let device_token = crate::files::read_device_token(self.cfg.device_token_path.as_deref());
        within(
            self.cfg.rpc_timeout,
            admin.begin_login(BeginLoginRequest {
                username: username.to_string(),
                device_token,
                client: self.client_info(),
            }),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|s| ClientError::from_credential_status(&s))
    }

    /// Sign in (F20 §6): a fresh `BeginLogin`, the key's assertion when the
    /// factor is a key, then `Login`. A session held before is logged out
    /// first; the password and code are wiped when this returns.
    ///
    /// # Errors
    /// [`ClientError`]; `FactorNotOffered`, `Authenticator` and a lock before
    /// `Login` (`SessionEnded`) send no `Login`: no throttle failure counts.
    pub async fn sign_in(
        &mut self,
        username: &str,
        password: Secret,
        factor: Factor,
    ) -> Result<LoginInfo, ClientError> {
        let previous = self.slot.end();
        self.logout_token(previous).await;
        let r = self.sign_in_inner(username, password, factor).await;
        self.settle(r)
    }

    async fn sign_in_inner(
        &mut self,
        username: &str,
        password: Secret,
        factor: Factor,
    ) -> Result<LoginInfo, ClientError> {
        let epoch = self.slot.epoch();
        let begin = self.begin_login(username).await?;
        let methods = Methods::from_codes(&begin.methods, begin.webauthn.as_ref());
        let second = match factor {
            Factor::Totp(code) if methods.totp => SecondFactor::TotpCode(code.expose().to_string()),
            Factor::SecurityKey(key) if methods.security_key => {
                let challenge = begin
                    .webauthn
                    .as_ref()
                    .ok_or(ClientError::FactorNotOffered)?;
                SecondFactor::WebauthnAssertion(ask_key(key, challenge).await?)
            }
            _ => return Err(ClientError::FactorNotOffered),
        };
        // Locked or closed while the key was touched (or `BeginLogin` ran):
        // the server never sees this sign-in.
        if self.slot.epoch() != epoch {
            return Err(ClientError::SessionEnded);
        }
        let mut admin = self.admin().await.map_err(ClientError::Connect)?;
        let device_token = crate::files::read_device_token(self.cfg.device_token_path.as_deref());
        let result = within(
            self.cfg.rpc_timeout,
            admin.login(LoginRequest {
                login_nonce: begin.login_nonce,
                username: username.to_string(),
                password: password.expose().to_string(),
                second_factor: Some(second),
                device_token,
                client: self.client_info(),
            }),
        )
        .await;
        drop(password);
        let mut resp = result
            .map(tonic::Response::into_inner)
            .map_err(|s| ClientError::from_credential_status(&s))?;
        if let Some(path) = &self.cfg.device_token_path {
            // A throttle hint only; failing to keep it is not an error.
            let _ = crate::files::store_device_token(path, &resp.device_token);
        }
        if let Some(orphan) = self
            .slot
            .adopt(std::mem::take(&mut resp.session_token), epoch)
        {
            // Locked or closed while signing in: never show the new session.
            self.logout_token(orphan).await;
            return Err(ClientError::SessionEnded);
        }
        Ok(LoginInfo {
            idle_timeout_secs: resp.idle_timeout_secs,
            absolute_expires_at: resp.absolute_expires_at,
            aal: resp.aal,
            password_change_required: resp.password_change_required,
            factor_enrollment_required: resp.factor_enrollment_required,
            admin_id: resp.admin_id,
            display_name: resp.display_name,
            groups: resp.groups,
            methods,
        })
    }

    /// Step up (F20 §7): `BeginStepUp`, the factor's proof (a key signs the
    /// step-up challenge), then `StepUp`, whose rotated token replaces the
    /// old one. Returns the end of the step-up window (Unix seconds).
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] without a session (the token is wiped
    /// when the server ended it); otherwise as [`AdminSession::sign_in`].
    pub async fn step_up(&mut self, factor: Factor) -> Result<i64, ClientError> {
        if !self.slot.has_token() {
            return Err(ClientError::SessionEnded);
        }
        let r = self.step_up_inner(factor).await;
        if matches!(r, Err(ClientError::SessionEnded)) {
            self.slot.wipe();
        }
        self.settle(r)
    }

    async fn step_up_inner(&mut self, factor: Factor) -> Result<i64, ClientError> {
        let epoch = self.slot.epoch();
        let mut admin = self.admin().await.map_err(ClientError::Connect)?;
        let begin = within(
            self.cfg.rpc_timeout,
            admin.begin_step_up(BeginStepUpRequest {}),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|s| authenticated_error(&s))?;
        let proof = match factor {
            Factor::Totp(code) => MfaProof {
                f: Some(mfa_proof::F::TotpCode(code.expose().to_string())),
                nonce: Vec::new(),
            },
            Factor::SecurityKey(key) => {
                let challenge = begin
                    .webauthn
                    .as_ref()
                    .ok_or(ClientError::FactorNotOffered)?;
                MfaProof {
                    f: Some(mfa_proof::F::WebauthnAssertion(
                        ask_key(key, challenge).await?,
                    )),
                    nonce: begin.stepup_nonce.clone(),
                }
            }
        };
        // The session ended while the key was touched: send no proof.
        if self.slot.epoch() != epoch {
            return Err(ClientError::SessionEnded);
        }
        let result = within(
            self.cfg.rpc_timeout,
            admin.step_up(StepUpRequest {
                stepup_nonce: begin.stepup_nonce,
                proof: Some(proof),
            }),
        )
        .await;
        let mut resp = result
            .map(tonic::Response::into_inner)
            .map_err(|s| ClientError::from_credential_status(&s))?;
        if let Some(orphan) = self
            .slot
            .adopt(std::mem::take(&mut resp.session_token), epoch)
        {
            self.logout_token(orphan).await;
            return Err(ClientError::SessionEnded);
        }
        Ok(resp.step_up_valid_until)
    }

    /// `WhoAmI`.
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn who_am_i(&mut self) -> Result<WhoAmIResponse, ClientError> {
        let mut admin = self.admin().await.map_err(ClientError::Connect)?;
        let r = within(self.cfg.rpc_timeout, admin.who_am_i(WhoAmIRequest {}))
            .await
            .map(tonic::Response::into_inner)
            .map_err(|s| authenticated_error(&s));
        if matches!(r, Err(ClientError::SessionEnded)) {
            self.slot.wipe();
        }
        self.settle(r)
    }

    /// End the session here (the token leaves the slot first), then send a
    /// best-effort `Logout`.
    pub async fn logout(&mut self) {
        let token = self.slot.end();
        self.logout_token(token).await;
    }

    /// Best-effort `Logout` for `token`, carried explicitly (it already left
    /// the slot) and bounded by the connect and RPC deadlines; the token is
    /// wiped when this returns, whatever happened.
    pub async fn logout_token(&mut self, token: SessionToken) {
        if !token.is_set() {
            return;
        }
        let Ok(value) = bearer_value(&token) else {
            return;
        };
        let Ok(ch) = self.channel().await else {
            return;
        };
        // No interceptor: the header is this token's, whatever the slot holds.
        let mut admin = AdminClient::new(ch);
        let mut req = tonic::Request::new(LogoutRequest {});
        req.metadata_mut().insert("authorization", value);
        if within(self.cfg.rpc_timeout, admin.logout(req))
            .await
            .is_err_and(|s| s.code() == tonic::Code::DeadlineExceeded)
        {
            self.channel = None;
        }
    }
}

/// Classify a failure of an authenticated, non-credential call.
fn authenticated_error(s: &tonic::Status) -> ClientError {
    let e = RpcError::from_status(s);
    if e.is_session_invalid() {
        ClientError::SessionEnded
    } else {
        ClientError::Other(e)
    }
}

/// Ask `key` for an assertion over `challenge`, off the async threads (the
/// operating system's prompt blocks until a touch, a cancel or the timeout).
async fn ask_key(
    key: Arc<dyn Authenticator>,
    challenge: &WebAuthnChallenge,
) -> Result<WebAuthnAssertion, ClientError> {
    let request = assertion_request(challenge).map_err(ClientError::Authenticator)?;
    let asked = request.clone();
    let answer = tokio::task::spawn_blocking(move || key.get_assertion(&asked))
        .await
        .map_err(|_| {
            ClientError::Authenticator(AuthenticatorError::Failed("prompt aborted".into()))
        })?
        .map_err(ClientError::Authenticator)?;
    into_proto(&request, answer).map_err(ClientError::Authenticator)
}

/// A task that sends the `Logout` of every ended session over its own
/// connection (the caller's may be stuck in an RPC); run it next to the
/// client, and give its sender to [`AdminSession::session_handle`].
pub fn logout_task(
    cfg: ClientConfig,
) -> (
    mpsc::UnboundedSender<SessionToken>,
    impl std::future::Future<Output = ()> + Send,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<SessionToken>();
    let task = async move {
        let mut dialer = AdminSession::new(cfg);
        while let Some(token) = rx.recv().await {
            dialer.logout_token(token).await;
        }
    };
    (tx, task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};

    fn config(endpoint: &str) -> ClientConfig {
        ClientConfig {
            endpoint: endpoint.into(),
            pins: vec![SpkiPin::from_hex(&"a".repeat(96)).unwrap()],
            device_token_path: None,
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
            client_kind: crate::client_kind::TRAY,
        }
    }

    fn secret(text: &str) -> Secret {
        let mut s = Secret::new();
        s.push_str(text);
        s
    }

    #[test]
    fn methods_need_a_challenge_for_the_key() {
        let c = WebAuthnChallenge::default();
        let m = Methods::from_codes(&[1, 2], Some(&c));
        assert_eq!(
            m,
            Methods {
                totp: true,
                security_key: true
            }
        );
        let m = Methods::from_codes(&[2], None);
        assert!(!m.security_key && !m.totp, "no challenge, no key");
    }

    #[tokio::test]
    async fn a_plaintext_endpoint_is_never_dialled() {
        let mut s = AdminSession::new(config("http://127.0.0.1:1"));
        let r = s
            .sign_in("u", secret("p"), Factor::Totp(secret("123456")))
            .await;
        assert!(matches!(r, Err(ClientError::Connect(_))), "{r:?}");
        assert!(!s.has_session());
    }

    #[tokio::test]
    async fn a_silent_listener_times_out_before_any_credential_is_sent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (seen_tx, mut seen_rx) = mpsc::channel::<usize>(1);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0;
            while let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                total += n;
            }
            let _ = seen_tx.send(total).await;
        });
        let mut s = AdminSession::new(ClientConfig {
            connect_timeout: Duration::from_millis(300),
            ..config(&format!("https://{addr}"))
        });
        let r = s
            .sign_in("u", secret("p"), Factor::Totp(secret("123456")))
            .await;
        let Err(ClientError::Connect(why)) = r else {
            panic!("{r:?}");
        };
        assert!(why.contains("no answer within"), "{why}");
        // Only the TLS ClientHello reached the listener: no credential.
        let seen = seen_rx.recv().await.unwrap();
        assert!(seen > 0 && seen < 4096, "{seen} bytes");
    }

    #[tokio::test]
    async fn a_step_up_without_a_session_sends_nothing() {
        let mut s = AdminSession::new(config("https://127.0.0.1:1"));
        let r = s.step_up(Factor::Totp(secret("123456"))).await;
        assert_eq!(r, Err(ClientError::SessionEnded));
    }
}
