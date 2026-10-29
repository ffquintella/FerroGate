//! The gRPC side of the TUI (F21 §2 "Async boundary").
//!
//! One tokio task owns the admin channel and the session token
//! ([`AdminConnection`]). The UI loop sends it [`Cmd`]s and receives
//! [`Reply`]s over bounded channels ([`spawn`]), so the UI never blocks on the
//! network and the token never leaves this module.
//!
//! - **Transport.** Only the admin listener, only `https://`, only through
//!   [`ferro_transport::connect_pinned`]: TLS 1.3 with the hybrid
//!   `X25519MLKEM768` group and SPKI pinning. The handshake (and so the pin
//!   check) completes before the first RPC, so a wrong pin is refused before
//!   any username, password or code is sent.
//! - **Session.** The token from `Login`, `StepUp` or `ChangePassword` is
//!   kept in a [`SessionToken`] behind the [`Bearer`] interceptor, marked
//!   sensitive in the metadata, and wiped on logout, lock and exit. Any
//!   `UNAUTHENTICATED session_invalid` wipes it and answers
//!   [`Reply::SessionEnded`], whatever the cause.
//! - **Step-up.** [`Cmd::StepUp`] runs `BeginStepUp`/`StepUp` with the TOTP
//!   code, adopts the rotated token and replays the stored [`Mutation`]
//!   **once**, with the same idempotency key.
//! - **Direct add.** [`Cmd::Register`] always carries a fresh TOTP proof
//!   inline (`AdminRegisterApplication` needs a per-operation second factor,
//!   F20 §7), whatever the step-up window says.
//!
//! Secrets travel in the request message only for the call that needs them;
//! prost messages cannot be wiped, which is the same residual exposure as the
//! CLI's (they are dropped as soon as the call is encoded).

use std::path::PathBuf;
use std::time::Duration;

use ferro_crypto::pin::SpkiPin;
use ferro_proto::admin_v1::admin_client::AdminClient;
use ferro_proto::admin_v1::{
    login_request::SecondFactor, mfa_proof, AdminAccountInfo, AdminRegisterApplicationRequest,
    AdminRegisterApplicationResponse, ApproveAppRequestRequest, ApproveAppRequestResponse,
    BeginLoginRequest, BeginStepUpRequest, ChangePasswordRequest, ClientInfo,
    DenyAppRequestRequest, DenyAppRequestResponse, GetAppRequestRequest, GetAppRequestResponse,
    GetApprovalRequest, GetApprovalResponse, ListAdminAccountsRequest, ListAppRequestsRequest,
    ListAppRequestsResponse, ListApprovalsRequest, ListApprovalsResponse, ListMySessionsRequest,
    LoginRequest, LogoutRequest, MfaProof, PageRequest, RevokeApprovalRequest,
    RevokeApprovalResponse, SessionInfo, SetLineageAutoUpdateFrozenRequest, StepUpRequest,
    UpdateApprovalRequest, UpdateApprovalResponse, WhoAmIRequest, WhoAmIResponse,
};
use tokio::sync::mpsc;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use crate::sanitize;
use crate::secret::{Secret, SessionToken};

// The session slot, bearer interceptor, pinned dialling and deadlines are
// shared with the tray admin client (`ferrogate-admin-client`, T281).
use ferrogate_admin_client::session::bearer_value;
pub use ferrogate_admin_client::session::{Bearer, SessionHandle, SessionSlot};
pub use ferrogate_admin_client::transport::{within, CONNECT_TIMEOUT, RPC_TIMEOUT};

/// `ClientInfo.kind` of the TUI (`admin.proto`: 1 tui, 2 tray, 3 cli).
pub const CLIENT_KIND_TUI: u32 = ferrogate_admin_client::client_kind::TUI;
/// Capacity of each direction of the UI ↔ client channels.
pub const CHANNEL_CAPACITY: usize = 64;
/// Largest page the server accepts (`ferro_raft::apps::MAX_PAGE_SIZE`); the
/// dashboard counts up to this many rows per figure.
pub const DASHBOARD_PAGE: u32 = 200;

/// Where and how to connect.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Admin listener (`https://host:port`).
    pub endpoint: String,
    /// Accepted SPKI pins (never empty).
    pub pins: Vec<SpkiPin>,
    /// Device-token file (throttle hint), if any.
    pub device_token_path: Option<PathBuf>,
    /// Longest wait for the TCP connection and the pinned TLS handshake
    /// ([`CONNECT_TIMEOUT`] in the binary).
    pub connect_timeout: Duration,
    /// Deadline of each RPC ([`RPC_TIMEOUT`] in the binary).
    pub rpc_timeout: Duration,
}

/// A read the UI asks for. `seq` lets the UI drop a reply that a newer
/// query superseded.
#[derive(Debug, Clone, PartialEq)]
pub enum Query {
    /// `WhoAmI` (permissions for key gating).
    WhoAmI,
    /// `ListAppRequests`.
    Requests {
        /// UI sequence number.
        seq: u64,
        /// Structured filters and the page.
        req: ListAppRequestsRequest,
    },
    /// `GetAppRequest`.
    Request {
        /// UI sequence number.
        seq: u64,
        /// The request id.
        id: String,
    },
    /// `ListApprovals`.
    Approvals {
        /// UI sequence number.
        seq: u64,
        /// Structured filters and the page.
        req: ListApprovalsRequest,
    },
    /// `GetApproval`.
    Approval {
        /// UI sequence number.
        seq: u64,
        /// The approval id.
        id: String,
    },
    /// The dashboard counts at Unix time `now`.
    Dashboard {
        /// Unix seconds.
        now: i64,
    },
    /// `ListAdminAccounts`.
    Accounts,
    /// `ListMySessions`.
    Sessions,
}

/// A decision or edit (step-up operations, F20 §7 "S"). Carries no secret, so
/// it can be kept for the single retry after a step-up.
#[derive(Debug, Clone, PartialEq)]
pub enum Mutation {
    /// `ApproveAppRequest`.
    Approve(ApproveAppRequestRequest),
    /// `DenyAppRequest`.
    Deny(DenyAppRequestRequest),
    /// `UpdateApproval`.
    Update(UpdateApprovalRequest),
    /// `RevokeApproval`.
    Revoke(RevokeApprovalRequest),
    /// `SetLineageAutoUpdateFrozen`.
    Freeze(SetLineageAutoUpdateFrozenRequest),
}

impl Mutation {
    /// The idempotency key the request carries.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        match self {
            Self::Approve(r) => &r.idempotency_key,
            Self::Deny(r) => &r.idempotency_key,
            Self::Update(r) => &r.idempotency_key,
            Self::Revoke(r) => &r.idempotency_key,
            Self::Freeze(r) => &r.idempotency_key,
        }
    }
}

/// A command from the UI to the client task.
pub enum Cmd {
    /// `BeginLogin` then `Login` with a TOTP code.
    Login {
        /// Username as typed.
        username: String,
        /// Password (wiped after the call).
        password: Secret,
        /// TOTP code (wiped after the call).
        totp: Secret,
    },
    /// `ChangePassword` (forced on expiry), with a TOTP proof.
    ChangePassword {
        /// Current password.
        current: Secret,
        /// New password.
        new: Secret,
        /// TOTP code.
        totp: Secret,
    },
    /// `BeginStepUp` + `StepUp`, then replay `retry` once.
    StepUp {
        /// TOTP code.
        totp: Secret,
        /// The operation that asked for the step-up (same idempotency key).
        retry: Mutation,
    },
    /// A decision or edit.
    Mutate(Mutation),
    /// `AdminRegisterApplication` with a fresh TOTP proof.
    Register {
        /// The request; its `proof` is filled from `totp` here.
        req: Box<AdminRegisterApplicationRequest>,
        /// A TOTP code typed for this operation.
        totp: Secret,
    },
    /// A read.
    Query(Query),
    /// `Logout` (best effort), then wipe the token. Used for quit and lock.
    Logout,
}

static_assertions::assert_not_impl_any!(Cmd: std::fmt::Debug, std::fmt::Display, Clone);

/// What a successful login reports to the UI (never the token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginInfo {
    /// Server idle timeout in seconds.
    pub idle_timeout_secs: i64,
    /// Authenticator assurance level.
    pub aal: u32,
    /// The password expired: only `ChangePassword` is allowed.
    pub password_change_required: bool,
    /// Pseudonymous administrator id.
    pub admin_id: String,
    /// Display name (untrusted text).
    pub display_name: String,
    /// Group names.
    pub groups: Vec<String>,
}

/// One dashboard figure: rows counted, and whether there are more than one
/// page; `None` when the server refused the read.
pub type Count = Option<(usize, bool)>;

/// The dashboard figures (F21 §3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DashboardCounts {
    /// Pending requests.
    pub pending: Count,
    /// Requests auto-approved in the last 24 h (by submission time).
    pub auto_approved_24h: Count,
    /// Active approvals expiring within 14 days.
    pub expiring_14d: Count,
    /// Active legacy imports without expiry.
    pub legacy_no_expiry: Count,
}

/// A gRPC failure, reduced to what the UI may show: the status code, the
/// server's stable reason (sanitised, bounded) and the offending field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// gRPC status code.
    pub code: tonic::Code,
    /// Reason string from the server, sanitised (at most 64 columns).
    pub reason: String,
    /// `x-ferrogate-field`, sanitised, when present.
    pub field: Option<String>,
    /// `retry-after` seconds, when present.
    pub retry_after: Option<u64>,
}

impl RpcError {
    /// Build from a status.
    #[must_use]
    pub fn from_status(s: &tonic::Status) -> Self {
        let meta = |k: &str| {
            s.metadata()
                .get(k)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Self {
            code: s.code(),
            reason: sanitize::truncate_end(s.message(), 64),
            field: meta("x-ferrogate-field").map(|f| sanitize::truncate_end(&f, 64)),
            retry_after: meta("retry-after").and_then(|v| v.parse().ok()),
        }
    }

    /// The server asked for a fresh second factor.
    #[must_use]
    pub fn is_step_up_required(&self) -> bool {
        self.code == tonic::Code::FailedPrecondition && self.reason == "step_up_required"
    }

    /// The session is gone (expired, revoked, IP mismatch, …).
    #[must_use]
    pub fn is_session_invalid(&self) -> bool {
        self.code == tonic::Code::Unauthenticated && self.reason == "session_invalid"
    }

    /// One line for the status bar.
    #[must_use]
    pub fn describe(&self) -> String {
        let what = match self.code {
            tonic::Code::PermissionDenied => "refused",
            tonic::Code::InvalidArgument => "invalid input",
            tonic::Code::FailedPrecondition => "not possible now",
            tonic::Code::Aborted => "changed concurrently",
            tonic::Code::NotFound => "not found",
            tonic::Code::Unauthenticated => "not accepted",
            tonic::Code::ResourceExhausted => "rate limited",
            tonic::Code::Unavailable => "server unavailable",
            tonic::Code::AlreadyExists => "already exists",
            tonic::Code::Unimplemented => "not available on this server",
            tonic::Code::DeadlineExceeded => "no answer in time",
            _ => "error",
        };
        match &self.field {
            Some(f) => format!("{what}: {} ({f})", self.reason),
            None => format!("{what}: {}", self.reason),
        }
    }
}

/// Which operation a failure belongs to.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// A read.
    Query(Query),
    /// A decision or edit.
    Mutation(Mutation),
    /// The step-up itself (bad code).
    StepUp(Mutation),
    /// `AdminRegisterApplication`.
    Register(Box<AdminRegisterApplicationRequest>),
    /// `ChangePassword`.
    ChangePassword,
}

/// Why a login did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    /// The admin listener could not be reached or failed the pin check;
    /// nothing was sent.
    Connect(String),
    /// Any credential failure (one generic message, F20 §6).
    Rejected,
    /// Throttled: retry after this many seconds.
    Throttled(u64),
    /// Another server error.
    Other(RpcError),
}

/// The outcome of a mutation (boxed in [`Reply::Mutated`]).
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // one value per mutation, already boxed in `Reply`.
pub enum Mutated {
    /// `ApproveAppRequest`.
    Approved(ApproveAppRequestResponse),
    /// `DenyAppRequest`.
    Denied(DenyAppRequestResponse),
    /// `UpdateApproval`.
    Updated(UpdateApprovalResponse),
    /// `RevokeApproval`.
    Revoked(RevokeApprovalResponse),
    /// `SetLineageAutoUpdateFrozen` (the new state).
    Frozen(bool),
}

/// A reply from the client task.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// Signed in.
    LoggedIn(LoginInfo),
    /// Not signed in.
    LoginFailed(LoginError),
    /// `WhoAmI`.
    WhoAmI(Box<WhoAmIResponse>),
    /// The password was changed (expires at this Unix time).
    PasswordChanged(i64),
    /// The step-up succeeded; valid until this Unix time.
    SteppedUp(i64),
    /// `ListAppRequests` for query `seq`.
    Requests(u64, ListAppRequestsResponse),
    /// `GetAppRequest` for query `seq`.
    Request(u64, Box<GetAppRequestResponse>),
    /// `ListApprovals` for query `seq`.
    Approvals(u64, ListApprovalsResponse),
    /// `GetApproval` for query `seq`.
    Approval(u64, Box<GetApprovalResponse>),
    /// Dashboard figures.
    Dashboard(DashboardCounts),
    /// `ListAdminAccounts`.
    Accounts(Vec<AdminAccountInfo>),
    /// `ListMySessions`.
    Sessions(Vec<SessionInfo>),
    /// A mutation succeeded.
    Mutated(Box<Mutated>),
    /// `AdminRegisterApplication` succeeded.
    Registered(Box<AdminRegisterApplicationResponse>),
    /// An operation failed.
    Failed(Box<Op>, RpcError),
    /// The session is gone; the token was wiped.
    SessionEnded,
    /// `Logout` done (or attempted) and the token wiped.
    LoggedOut,
}

/// The typed client with the session interceptor.
type Admin = AdminClient<InterceptedService<Channel, Bearer>>;

fn client_info() -> Option<ClientInfo> {
    Some(ClientInfo {
        kind: CLIENT_KIND_TUI,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

fn totp_proof(code: &Secret) -> Option<MfaProof> {
    Some(MfaProof {
        f: Some(mfa_proof::F::TotpCode(code.expose().to_string())),
        nonce: Vec::new(),
    })
}

/// The admin connection and session, owned by the client task.
pub struct AdminConnection {
    cfg: ClientConfig,
    channel: Option<Channel>,
    slot: SessionSlot,
}

static_assertions::assert_not_impl_any!(AdminConnection: std::fmt::Debug, std::fmt::Display, Clone);

impl AdminConnection {
    /// A connection that dials lazily on the first command.
    #[must_use]
    pub fn new(cfg: ClientConfig) -> Self {
        Self {
            cfg,
            channel: None,
            slot: SessionSlot::new(),
        }
    }

    /// Whether a session token is held (for tests and the quit path).
    #[must_use]
    pub fn has_session(&self) -> bool {
        self.slot.has_token()
    }

    /// The UI's handle on this connection's session: [`SessionHandle::end`]
    /// wipes the token at once and hands the `Logout` to `logout_tx`.
    #[must_use]
    pub fn session_handle(&self, logout_tx: mpsc::UnboundedSender<SessionToken>) -> SessionHandle {
        self.slot.handle(logout_tx)
    }

    fn epoch(&self) -> u64 {
        self.slot.epoch()
    }

    /// Drop the token (the server already ended the session).
    fn wipe(&self) {
        self.slot.wipe();
    }

    /// Keep `token` when no lock or quit happened since `epoch`; otherwise
    /// hand it back so the caller logs it out.
    fn adopt(&self, token: String, epoch: u64) -> Option<SessionToken> {
        self.slot.adopt(token, epoch)
    }

    /// Best-effort `Logout` for `token`, carried explicitly (it already left
    /// the slot) and bounded by the connect and RPC deadlines; the token is
    /// wiped when this returns, whatever happened.
    async fn logout_with(&mut self, token: SessionToken) {
        if !token.is_set() {
            return;
        }
        let Ok(value) = bearer_value(&token) else {
            return;
        };
        if let Ok(ch) = self.channel().await {
            // No interceptor: the header is this token's, whatever the slot holds.
            let mut admin = AdminClient::new(ch);
            let mut req = tonic::Request::new(LogoutRequest {});
            req.metadata_mut().insert("authorization", value);
            let _ = within(self.cfg.rpc_timeout, admin.logout(req)).await;
        }
    }

    /// A token that arrived after the session was ended: log it out and
    /// tell the UI the session is gone.
    async fn orphan(&mut self, token: SessionToken) -> Reply {
        self.logout_with(token).await;
        Reply::SessionEnded
    }

    /// Dial the admin listener (pinned hybrid-PQC TLS, shared dialler). The
    /// pin is checked during the handshake, before any RPC.
    async fn channel(&mut self) -> Result<Channel, String> {
        if let Some(ch) = &self.channel {
            return Ok(ch.clone());
        }
        let ch = ferrogate_admin_client::transport::dial(
            &self.cfg.endpoint,
            &self.cfg.pins,
            self.cfg.connect_timeout,
        )
        .await
        .map_err(|e| sanitize::truncate_end(&e, 160))?;
        self.channel = Some(ch.clone());
        Ok(ch)
    }

    /// The typed client carrying this session's bearer token.
    async fn admin(&mut self) -> Result<Admin, String> {
        let ch = self.channel().await?;
        Ok(AdminClient::with_interceptor(ch, self.slot.bearer()))
    }

    /// Classify a failure of an authenticated call: a dead session wipes the
    /// token and ends the session in the UI.
    fn fail(&self, op: Op, status: &tonic::Status) -> Reply {
        let err = RpcError::from_status(status);
        if err.is_session_invalid() {
            self.wipe();
            return Reply::SessionEnded;
        }
        Reply::Failed(Box::new(op), err)
    }

    /// Run one command; returns the replies in order. After a deadline the
    /// connection is dropped, so the next command dials afresh.
    pub async fn handle(&mut self, cmd: Cmd) -> Vec<Reply> {
        let replies = self.run(cmd).await;
        if replies.iter().any(timed_out) {
            self.channel = None;
        }
        replies
    }

    async fn run(&mut self, cmd: Cmd) -> Vec<Reply> {
        match cmd {
            Cmd::Login {
                username,
                password,
                totp,
            } => vec![self.login(username, password, totp).await],
            Cmd::ChangePassword { current, new, totp } => {
                vec![self.change_password(current, new, totp).await]
            }
            Cmd::StepUp { totp, retry } => self.step_up(totp, retry).await,
            Cmd::Mutate(m) => vec![self.mutate(m).await],
            Cmd::Register { req, totp } => vec![self.register(*req, totp).await],
            Cmd::Query(q) => vec![self.query(q).await],
            Cmd::Logout => {
                // The token leaves the slot before any network I/O.
                let token = self.slot.end();
                self.logout_with(token).await;
                vec![Reply::LoggedOut]
            }
        }
    }

    async fn login(&mut self, username: String, password: Secret, totp: Secret) -> Reply {
        // A previous session (lock, then sign in again) is dropped first.
        self.wipe();
        let epoch = self.epoch();
        let mut admin = match self.admin().await {
            Ok(a) => a,
            Err(e) => return Reply::LoginFailed(LoginError::Connect(e)),
        };
        let device_token = crate::config::read_device_token(self.cfg.device_token_path.as_deref());
        let login_error = |s: &tonic::Status| {
            let e = RpcError::from_status(s);
            match e.code {
                tonic::Code::Unauthenticated => LoginError::Rejected,
                tonic::Code::ResourceExhausted => {
                    LoginError::Throttled(e.retry_after.unwrap_or(60))
                }
                _ => LoginError::Other(e),
            }
        };
        let begin = match within(
            self.cfg.rpc_timeout,
            admin.begin_login(BeginLoginRequest {
                username: username.clone(),
                device_token: device_token.clone(),
                client: client_info(),
            }),
        )
        .await
        {
            Ok(r) => r.into_inner(),
            Err(s) => return Reply::LoginFailed(login_error(&s)),
        };
        let result = within(
            self.cfg.rpc_timeout,
            admin.login(LoginRequest {
                login_nonce: begin.login_nonce,
                username,
                password: password.expose().to_string(),
                second_factor: Some(SecondFactor::TotpCode(totp.expose().to_string())),
                device_token,
                client: client_info(),
            }),
        )
        .await;
        drop((password, totp));
        let mut resp = match result {
            Ok(r) => r.into_inner(),
            Err(s) => return Reply::LoginFailed(login_error(&s)),
        };
        if let Some(path) = &self.cfg.device_token_path {
            // A throttle hint only; failing to keep it is not an error.
            let _ = crate::config::store_device_token(path, &resp.device_token);
        }
        if let Some(orphan) = self.adopt(std::mem::take(&mut resp.session_token), epoch) {
            return self.orphan(orphan).await;
        }
        Reply::LoggedIn(LoginInfo {
            idle_timeout_secs: resp.idle_timeout_secs,
            aal: resp.aal,
            password_change_required: resp.password_change_required,
            admin_id: resp.admin_id,
            display_name: resp.display_name,
            groups: resp.groups,
        })
    }

    async fn change_password(&mut self, current: Secret, new: Secret, totp: Secret) -> Reply {
        let epoch = self.epoch();
        let mut admin = match self.admin().await {
            Ok(a) => a,
            Err(e) => return Reply::LoginFailed(LoginError::Connect(e)),
        };
        let result = within(
            self.cfg.rpc_timeout,
            admin.change_password(ChangePasswordRequest {
                current_password: current.expose().to_string(),
                new_password: new.expose().to_string(),
                proof: totp_proof(&totp),
            }),
        )
        .await;
        drop((current, new, totp));
        match result {
            Ok(r) => {
                let mut r = r.into_inner();
                if let Some(orphan) = self.adopt(std::mem::take(&mut r.session_token), epoch) {
                    return self.orphan(orphan).await;
                }
                Reply::PasswordChanged(r.password_expires_at)
            }
            Err(s) => self.fail(Op::ChangePassword, &s),
        }
    }

    async fn step_up(&mut self, totp: Secret, retry: Mutation) -> Vec<Reply> {
        let epoch = self.epoch();
        let mut admin = match self.admin().await {
            Ok(a) => a,
            Err(e) => {
                return vec![Reply::Failed(
                    Box::new(Op::StepUp(retry)),
                    RpcError {
                        code: tonic::Code::Unavailable,
                        reason: e,
                        field: None,
                        retry_after: None,
                    },
                )]
            }
        };
        let begin = match within(
            self.cfg.rpc_timeout,
            admin.begin_step_up(BeginStepUpRequest {}),
        )
        .await
        {
            Ok(r) => r.into_inner(),
            Err(s) => return vec![self.fail(Op::StepUp(retry), &s)],
        };
        let result = within(
            self.cfg.rpc_timeout,
            admin.step_up(StepUpRequest {
                stepup_nonce: begin.stepup_nonce,
                proof: totp_proof(&totp),
            }),
        )
        .await;
        drop(totp);
        match result {
            Ok(r) => {
                let mut r = r.into_inner();
                if let Some(orphan) = self.adopt(std::mem::take(&mut r.session_token), epoch) {
                    // Locked meanwhile: end the rotated session, no replay.
                    return vec![self.orphan(orphan).await];
                }
                // Exactly one replay, with the same idempotency key.
                vec![
                    Reply::SteppedUp(r.step_up_valid_until),
                    self.mutate(retry).await,
                ]
            }
            Err(s) => vec![self.fail(Op::StepUp(retry), &s)],
        }
    }

    async fn mutate(&mut self, m: Mutation) -> Reply {
        let mut admin = match self.admin().await {
            Ok(a) => a,
            Err(e) => {
                return Reply::Failed(
                    Box::new(Op::Mutation(m)),
                    RpcError {
                        code: tonic::Code::Unavailable,
                        reason: e,
                        field: None,
                        retry_after: None,
                    },
                )
            }
        };
        let result = match m.clone() {
            Mutation::Approve(r) => within(self.cfg.rpc_timeout, admin.approve_app_request(r))
                .await
                .map(|x| Mutated::Approved(x.into_inner())),
            Mutation::Deny(r) => within(self.cfg.rpc_timeout, admin.deny_app_request(r))
                .await
                .map(|x| Mutated::Denied(x.into_inner())),
            Mutation::Update(r) => within(self.cfg.rpc_timeout, admin.update_approval(r))
                .await
                .map(|x| Mutated::Updated(x.into_inner())),
            Mutation::Revoke(r) => within(self.cfg.rpc_timeout, admin.revoke_approval(r))
                .await
                .map(|x| Mutated::Revoked(x.into_inner())),
            Mutation::Freeze(r) => {
                let frozen = r.frozen;
                within(
                    self.cfg.rpc_timeout,
                    admin.set_lineage_auto_update_frozen(r),
                )
                .await
                .map(|_| Mutated::Frozen(frozen))
            }
        };
        match result {
            Ok(done) => Reply::Mutated(Box::new(done)),
            Err(s) => self.fail(Op::Mutation(m), &s),
        }
    }

    async fn register(&mut self, mut req: AdminRegisterApplicationRequest, totp: Secret) -> Reply {
        let mut admin = match self.admin().await {
            Ok(a) => a,
            Err(e) => {
                return Reply::Failed(
                    Box::new(Op::Register(Box::new(req))),
                    RpcError {
                        code: tonic::Code::Unavailable,
                        reason: e,
                        field: None,
                        retry_after: None,
                    },
                )
            }
        };
        let mut sent = req.clone();
        sent.proof = totp_proof(&totp);
        drop(totp);
        req.proof = None;
        match within(self.cfg.rpc_timeout, admin.admin_register_application(sent)).await {
            Ok(r) => Reply::Registered(Box::new(r.into_inner())),
            Err(s) => self.fail(Op::Register(Box::new(req)), &s),
        }
    }

    async fn query(&mut self, q: Query) -> Reply {
        let mut admin = match self.admin().await {
            Ok(a) => a,
            Err(e) => {
                return Reply::Failed(
                    Box::new(Op::Query(q)),
                    RpcError {
                        code: tonic::Code::Unavailable,
                        reason: e,
                        field: None,
                        retry_after: None,
                    },
                )
            }
        };
        let result = match q.clone() {
            Query::WhoAmI => within(self.cfg.rpc_timeout, admin.who_am_i(WhoAmIRequest {}))
                .await
                .map(|r| Reply::WhoAmI(Box::new(r.into_inner()))),
            Query::Requests { seq, req } => {
                within(self.cfg.rpc_timeout, admin.list_app_requests(req))
                    .await
                    .map(|r| Reply::Requests(seq, r.into_inner()))
            }
            Query::Request { seq, id } => within(
                self.cfg.rpc_timeout,
                admin.get_app_request(GetAppRequestRequest { request_id: id }),
            )
            .await
            .map(|r| Reply::Request(seq, Box::new(r.into_inner()))),
            Query::Approvals { seq, req } => {
                within(self.cfg.rpc_timeout, admin.list_approvals(req))
                    .await
                    .map(|r| Reply::Approvals(seq, r.into_inner()))
            }
            Query::Approval { seq, id } => within(
                self.cfg.rpc_timeout,
                admin.get_approval(GetApprovalRequest { approval_id: id }),
            )
            .await
            .map(|r| Reply::Approval(seq, Box::new(r.into_inner()))),
            Query::Dashboard { now } => return self.dashboard(&mut admin, now).await,
            Query::Accounts => within(
                self.cfg.rpc_timeout,
                admin.list_admin_accounts(ListAdminAccountsRequest {}),
            )
            .await
            .map(|r| Reply::Accounts(r.into_inner().accounts)),
            Query::Sessions => within(
                self.cfg.rpc_timeout,
                admin.list_my_sessions(ListMySessionsRequest {}),
            )
            .await
            .map(|r| Reply::Sessions(r.into_inner().sessions)),
        };
        result.unwrap_or_else(|s| self.fail(Op::Query(q), &s))
    }

    /// Four bounded listings (`page_size` = the server maximum): the figure is
    /// the row count, flagged when a further page exists.
    async fn dashboard(&mut self, admin: &mut Admin, now: i64) -> Reply {
        let page = || {
            Some(PageRequest {
                page_size: DASHBOARD_PAGE,
                page_token: String::new(),
            })
        };
        let mut counts = DashboardCounts::default();
        let requests = [
            ListAppRequestsRequest {
                states: vec![1],
                page: page(),
                ..ListAppRequestsRequest::default()
            },
            ListAppRequestsRequest {
                states: vec![3],
                submitted_after: now - crate::timefmt::DAY,
                page: page(),
                ..ListAppRequestsRequest::default()
            },
        ];
        for (i, req) in requests.into_iter().enumerate() {
            let figure = match within(self.cfg.rpc_timeout, admin.list_app_requests(req)).await {
                Ok(r) => {
                    let r = r.into_inner();
                    Some((r.items.len(), !r.next_page_token.is_empty()))
                }
                Err(s) if RpcError::from_status(&s).is_session_invalid() => {
                    self.wipe();
                    return Reply::SessionEnded;
                }
                Err(_) => None,
            };
            if i == 0 {
                counts.pending = figure;
            } else {
                counts.auto_approved_24h = figure;
            }
        }
        let approvals = [
            ListApprovalsRequest {
                states: vec![1],
                expires_after: now,
                expires_before: now + 14 * crate::timefmt::DAY,
                page: page(),
                ..ListApprovalsRequest::default()
            },
            ListApprovalsRequest {
                states: vec![1],
                legacy_only: true,
                no_expiry_only: true,
                page: page(),
                ..ListApprovalsRequest::default()
            },
        ];
        for (i, req) in approvals.into_iter().enumerate() {
            let figure = match within(self.cfg.rpc_timeout, admin.list_approvals(req)).await {
                Ok(r) => {
                    let r = r.into_inner();
                    Some((r.items.len(), !r.next_page_token.is_empty()))
                }
                Err(s) if RpcError::from_status(&s).is_session_invalid() => {
                    self.wipe();
                    return Reply::SessionEnded;
                }
                Err(_) => None,
            };
            if i == 0 {
                counts.expiring_14d = figure;
            } else {
                counts.legacy_no_expiry = figure;
            }
        }
        Reply::Dashboard(counts)
    }
}

/// Whether `reply` reports a deadline (the connection is then redialled).
fn timed_out(reply: &Reply) -> bool {
    match reply {
        Reply::Failed(_, e) | Reply::LoginFailed(LoginError::Other(e)) => {
            e.code == tonic::Code::DeadlineExceeded
        }
        _ => false,
    }
}

/// The UI side of the client: the bounded command queue and the session
/// handle.
pub struct ClientHandle {
    cmds: mpsc::Sender<Cmd>,
    session: SessionHandle,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

static_assertions::assert_not_impl_any!(ClientHandle: std::fmt::Debug, std::fmt::Display, Clone);

impl ClientHandle {
    /// Queue `cmd` without blocking; `false` when the queue is full or the
    /// client task is gone. `Logout` never queues and never fails: the
    /// session ends at once ([`SessionHandle::end`]).
    #[must_use]
    pub fn send(&self, cmd: Cmd) -> bool {
        if matches!(cmd, Cmd::Logout) {
            self.session.end();
            return true;
        }
        self.cmds.try_send(cmd).is_ok()
    }

    /// Whether the client task is gone (it panicked or ended).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.cmds.is_closed()
    }

    /// End the session, close the queue and wait up to `wait` for the tasks
    /// to finish (an in-flight `Logout` or a late token's logout); tasks
    /// still running then are aborted, which drops and wipes their tokens.
    pub async fn shutdown(self, wait: Duration) {
        let Self {
            cmds,
            session,
            tasks,
        } = self;
        session.end();
        drop(cmds);
        drop(session);
        let aborts: Vec<_> = tasks
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect();
        let all = async {
            for t in tasks {
                let _ = t.await;
            }
        };
        if tokio::time::timeout(wait, all).await.is_err() {
            for a in aborts {
                a.abort();
            }
        }
    }
}

/// Start the client: one task runs the commands in order over the pinned
/// channel, another sends the `Logout` of every ended session. Commands go
/// in through the returned [`ClientHandle`]; replies come out of the bounded
/// receiver. The tasks end when the handle is shut down.
#[must_use]
pub fn spawn(cfg: ClientConfig) -> (ClientHandle, mpsc::Receiver<Reply>) {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(CHANNEL_CAPACITY);
    let (reply_tx, reply_rx) = mpsc::channel::<Reply>(CHANNEL_CAPACITY);
    let (logout_tx, mut logout_rx) = mpsc::unbounded_channel::<SessionToken>();
    let mut conn = AdminConnection::new(cfg.clone());
    let session = conn.session_handle(logout_tx);
    let replies = reply_tx.clone();
    let client = tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            for reply in conn.handle(cmd).await {
                if replies.send(reply).await.is_err() {
                    break;
                }
            }
        }
        // Whatever is left (normally nothing: the UI ended the session).
        let token = conn.slot.end();
        conn.logout_with(token).await;
    });
    let logout = tokio::spawn(async move {
        // Its own connection: the client task's may be stuck in an RPC.
        let mut dialer = AdminConnection::new(cfg);
        while let Some(token) = logout_rx.recv().await {
            dialer.logout_with(token).await;
            let _ = reply_tx.send(Reply::LoggedOut).await;
        }
    });
    (
        ClientHandle {
            cmds: cmd_tx,
            session,
            tasks: vec![client, logout],
        },
        reply_rx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: &str) -> ClientConfig {
        ClientConfig {
            endpoint: endpoint.into(),
            pins: vec![SpkiPin::from_hex(&"a".repeat(96)).unwrap()],
            device_token_path: None,
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
        }
    }

    #[test]
    fn the_bearer_header_is_sensitive_and_follows_rotation() {
        use tonic::service::Interceptor as _;
        let conn = AdminConnection::new(config("https://127.0.0.1:1"));
        let mut b = conn.slot.bearer();
        let req = b.call(tonic::Request::new(())).unwrap();
        assert!(req.metadata().get("authorization").is_none());
        assert!(conn.adopt("fgas_abc".into(), conn.epoch()).is_none());
        let req = b.call(tonic::Request::new(())).unwrap();
        let v = req.metadata().get("authorization").unwrap();
        assert_eq!(v, "Bearer fgas_abc");
        assert!(v.is_sensitive());
        assert!(conn.adopt("fgas_def".into(), conn.epoch()).is_none());
        let req = b.call(tonic::Request::new(())).unwrap();
        assert_eq!(
            req.metadata().get("authorization").unwrap(),
            "Bearer fgas_def"
        );
    }

    #[test]
    fn errors_are_classified_and_sanitised() {
        let e = RpcError::from_status(&tonic::Status::failed_precondition("step_up_required"));
        assert!(e.is_step_up_required());
        let e = RpcError::from_status(&tonic::Status::unauthenticated("session_invalid"));
        assert!(e.is_session_invalid());
        let mut s = tonic::Status::invalid_argument("bad\u{1b}[2Jvalue");
        s.metadata_mut()
            .insert("x-ferrogate-field", "terms.note".parse().unwrap());
        let e = RpcError::from_status(&s);
        assert_eq!(e.reason, "bad\\x1b[2Jvalue");
        assert_eq!(e.describe(), "invalid input: bad\\x1b[2Jvalue (terms.note)");
    }

    #[tokio::test]
    async fn a_plaintext_endpoint_is_never_dialled() {
        let mut conn = AdminConnection::new(config("http://127.0.0.1:1"));
        let mut password = Secret::new();
        password.push('p');
        let replies = conn
            .handle(Cmd::Login {
                username: "u".into(),
                password,
                totp: Secret::new(),
            })
            .await;
        assert!(matches!(
            &replies[..],
            [Reply::LoginFailed(LoginError::Connect(_))]
        ));
        assert!(!conn.has_session());
    }

    #[tokio::test]
    async fn a_silent_listener_times_out_before_any_credential_is_sent() {
        // Accepts TCP and never answers the TLS ClientHello (a black hole).
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
                tokio::time::timeout(std::time::Duration::from_secs(2), tcp.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                total += n;
            }
            let _ = seen_tx.send(total).await;
        });
        let mut conn = AdminConnection::new(ClientConfig {
            connect_timeout: Duration::from_millis(300),
            ..config(&format!("https://{addr}"))
        });
        let mut password = Secret::new();
        password.push('p');
        let mut totp = Secret::new();
        for c in "123456".chars() {
            totp.push(c);
        }
        let replies = conn
            .handle(Cmd::Login {
                username: "u".into(),
                password,
                totp,
            })
            .await;
        let [Reply::LoginFailed(LoginError::Connect(why))] = &replies[..] else {
            panic!("{replies:?}");
        };
        assert!(why.contains("no answer within"), "{why}");
        assert!(!conn.has_session());
        // Only the TLS ClientHello reached the listener: no gRPC frame, so no
        // username, password or code.
        let seen = seen_rx.recv().await.unwrap();
        assert!(seen > 0 && seen < 4096, "{seen} bytes");
    }

    #[tokio::test]
    async fn an_endpoint_without_a_port_is_never_dialled() {
        // `https://host` would reach the main listener on 8443.
        let mut conn = AdminConnection::new(config("https://127.0.0.1"));
        let mut password = Secret::new();
        password.push('p');
        let replies = conn
            .handle(Cmd::Login {
                username: "u".into(),
                password,
                totp: Secret::new(),
            })
            .await;
        let [Reply::LoginFailed(LoginError::Connect(why))] = &replies[..] else {
            panic!("{replies:?}");
        };
        assert!(why.contains("explicit port"), "{why}");
    }

    #[tokio::test]
    async fn a_call_that_never_answers_meets_its_deadline() {
        let never = std::future::pending::<Result<(), tonic::Status>>();
        let e = within(Duration::from_millis(20), never).await.unwrap_err();
        assert_eq!(e.code(), tonic::Code::DeadlineExceeded);
        let e = RpcError::from_status(&e);
        assert_eq!(e.describe(), "no answer in time: timeout");
        assert!(timed_out(&Reply::Failed(
            Box::new(Op::Query(Query::WhoAmI)),
            e
        )));
    }

    #[test]
    fn ending_the_session_wipes_at_once_and_a_late_token_is_not_adopted() {
        let conn = AdminConnection::new(config("https://127.0.0.1:1"));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = conn.session_handle(tx);
        let epoch = conn.epoch();
        assert!(conn.adopt("fgas_a".into(), epoch).is_none());
        assert!(conn.has_session());
        // Lock: the slot is empty at once, without any network I/O, and the
        // token goes to the logout task.
        handle.end();
        assert!(!conn.has_session());
        assert_eq!(rx.try_recv().unwrap().expose(), "fgas_a");
        // A step-up answered after the lock: its rotated token is handed
        // back for logout, never adopted.
        let orphan = conn.adopt("fgas_b".into(), epoch).expect("not adopted");
        assert_eq!(orphan.expose(), "fgas_b");
        assert!(!conn.has_session());
        // Without a logout task the token is wiped right away.
        drop(rx);
        assert!(conn.adopt("fgas_c".into(), conn.epoch()).is_none());
        handle.end();
        assert!(!conn.has_session());
    }

    #[test]
    fn a_logout_is_never_dropped_by_a_full_queue() {
        let conn = AdminConnection::new(config("https://127.0.0.1:1"));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let session = conn.session_handle(tx);
        let (cmd_tx, _cmd_rx) = mpsc::channel::<Cmd>(1);
        let client = ClientHandle {
            cmds: cmd_tx,
            session,
            tasks: Vec::new(),
        };
        assert!(conn.adopt("fgas_a".into(), conn.epoch()).is_none());
        assert!(client.send(Cmd::Query(Query::WhoAmI)));
        assert!(
            !client.send(Cmd::Query(Query::Sessions)),
            "the queue is full"
        );
        assert!(client.send(Cmd::Logout), "the logout still goes through");
        assert!(!conn.has_session(), "and the token is wiped at once");
        assert_eq!(rx.try_recv().unwrap().expose(), "fgas_a");
    }
}
