//! Authorization (F20 §7): the permission vocabulary, the **single** method →
//! access table that drives both the tower layer and the handler guards, the
//! per-request [`AdminContext`], and [`AdminAuthz`], the one component that
//! makes every authentication and authorization decision (NRM §5.3.1).
//!
//! Deny by default: a gRPC path missing from [`METHOD_ACCESS`] is refused with
//! `PERMISSION_DENIED (method_not_classified)`, and a test proves every method
//! of every compiled service has an entry. Permissions reach an account only
//! through groups (G-002) and are read from the database on every call.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use tonic::Status;

use ferro_audit::AuditEvent;
use ferro_raft::admin::{AdminAccountRow, ACCOUNT_ACTIVE};

use super::session::{self, Liveness, MfaMethod, RevokeReason};
use super::state::AdminState;

/// A function × operation permission (F20 §7). Assigned to groups only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// `app_request.list`
    AppRequestList,
    /// `app_request.read`
    AppRequestRead,
    /// `approval.list`
    ApprovalList,
    /// `approval.read`
    ApprovalRead,
    /// `host.list`
    HostList,
    /// `app_request.approve`
    AppRequestApprove,
    /// `app_request.deny`
    AppRequestDeny,
    /// `approval.update`
    ApprovalUpdate,
    /// `approval.revoke`
    ApprovalRevoke,
    /// `app.direct_register`
    AppDirectRegister,
    /// `account.list`
    AccountList,
    /// `account.create`
    AccountCreate,
    /// `account.update`
    AccountUpdate,
    /// `account.disable`
    AccountDisable,
    /// `account.reset`
    AccountReset,
    /// `session.revoke_any`
    SessionRevokeAny,
    /// `legacy.allowlist.read`
    LegacyAllowlistRead,
    /// `legacy.allowlist.write`
    LegacyAllowlistWrite,
    /// `svid.list`
    SvidList,
    /// `svid.revoke`
    SvidRevoke,
    /// `policy.epoch_bump`
    PolicyEpochBump,
    /// `settings.allowlist_mode`
    SettingsAllowlistMode,
    /// `allowlist.import`
    AllowlistImport,
}

impl Permission {
    /// Every permission.
    pub const ALL: [Self; 23] = [
        Self::AppRequestList,
        Self::AppRequestRead,
        Self::ApprovalList,
        Self::ApprovalRead,
        Self::HostList,
        Self::AppRequestApprove,
        Self::AppRequestDeny,
        Self::ApprovalUpdate,
        Self::ApprovalRevoke,
        Self::AppDirectRegister,
        Self::AccountList,
        Self::AccountCreate,
        Self::AccountUpdate,
        Self::AccountDisable,
        Self::AccountReset,
        Self::SessionRevokeAny,
        Self::LegacyAllowlistRead,
        Self::LegacyAllowlistWrite,
        Self::SvidList,
        Self::SvidRevoke,
        Self::PolicyEpochBump,
        Self::SettingsAllowlistMode,
        Self::AllowlistImport,
    ];

    /// The stored string form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AppRequestList => "app_request.list",
            Self::AppRequestRead => "app_request.read",
            Self::ApprovalList => "approval.list",
            Self::ApprovalRead => "approval.read",
            Self::HostList => "host.list",
            Self::AppRequestApprove => "app_request.approve",
            Self::AppRequestDeny => "app_request.deny",
            Self::ApprovalUpdate => "approval.update",
            Self::ApprovalRevoke => "approval.revoke",
            Self::AppDirectRegister => "app.direct_register",
            Self::AccountList => "account.list",
            Self::AccountCreate => "account.create",
            Self::AccountUpdate => "account.update",
            Self::AccountDisable => "account.disable",
            Self::AccountReset => "account.reset",
            Self::SessionRevokeAny => "session.revoke_any",
            Self::LegacyAllowlistRead => "legacy.allowlist.read",
            Self::LegacyAllowlistWrite => "legacy.allowlist.write",
            Self::SvidList => "svid.list",
            Self::SvidRevoke => "svid.revoke",
            Self::PolicyEpochBump => "policy.epoch_bump",
            Self::SettingsAllowlistMode => "settings.allowlist_mode",
            Self::AllowlistImport => "allowlist.import",
        }
    }

    /// Parse the stored string form.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

/// Built-in group names.
pub mod groups {
    /// Read-only on requests, approvals and hosts.
    pub const VIEWERS: &str = "ferrogate-viewers";
    /// F19 decisions and direct registration.
    pub const APPROVERS: &str = "ferrogate-approvers";
    /// Account and group management.
    pub const ACCOUNT_ADMINS: &str = "ferrogate-account-admins";
    /// Legacy allowlist RPCs, SVID revocation, epoch bump.
    pub const PLATFORM_OPERATORS: &str = "ferrogate-platform-operators";
    /// Every built-in group.
    pub const ALL: [&str; 4] = [VIEWERS, APPROVERS, ACCOUNT_ADMINS, PLATFORM_OPERATORS];
}

/// What a session-protected method requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRule {
    /// Permission the caller's groups must grant (`None`: any session).
    pub permission: Option<Permission>,
    /// A recent second-factor verification is required (F20 §7 "S").
    pub step_up: bool,
    /// Usable by a session whose password has expired (only `WhoAmI`,
    /// `Logout`, `ChangePassword`, and `BeginStepUp`, which only issues a
    /// challenge for the per-operation proof `ChangePassword` needs).
    pub allow_restricted: bool,
    /// Usable by a tray session that the FIDO2 policy holds to factor
    /// enrollment (`factor_enrollment_required`, F20 §5): `WhoAmI`,
    /// `Logout`, `ChangePassword`, `BeginStepUp` and the factor-enrollment
    /// methods.
    pub allow_factor_enrollment: bool,
}

/// How a gRPC method is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Unauthenticated host-facing or public read (unchanged by F20).
    Public,
    /// A host method, never an admin one: authenticated in band by the
    /// handler with the host's SVID and machine-key signature — the F19 §7.1
    /// `HostCallAuth` proof ([`crate::host_auth::authenticate`]) for
    /// `AppendAuditEvent`, the equivalent SVID + `cnf.jkt` + signature check
    /// for `ProposeAllowlist`. Allowed on any listener, TLS or not: the proof
    /// is a signature, not a transport property.
    Host,
    /// Admin login and enrollment: TLS only, no session, throttled by the
    /// handler.
    AdminPublic,
    /// Requires a valid admin session and the rule's permission.
    Session(SessionRule),
}

const fn session(
    permission: Option<Permission>,
    step_up: bool,
    allow_restricted: bool,
    allow_factor_enrollment: bool,
) -> Access {
    Access::Session(SessionRule {
        permission,
        step_up,
        allow_restricted,
        allow_factor_enrollment,
    })
}

/// Full gRPC paths of the methods handlers refer to.
pub mod paths {
    /// `MachineIdentity` service prefix.
    pub const MI: &str = "/ferrogate.v1.MachineIdentity/";
    /// `Admin` service prefix.
    pub const ADMIN: &str = "/ferrogate.admin.v1.Admin/";

    /// Legacy `SetAllowlist`.
    pub const SET_ALLOWLIST: &str = "/ferrogate.v1.MachineIdentity/SetAllowlist";
    /// Legacy `DeleteAllowlist`.
    pub const DELETE_ALLOWLIST: &str = "/ferrogate.v1.MachineIdentity/DeleteAllowlist";
    /// Legacy `ListAllowlists`.
    pub const LIST_ALLOWLISTS: &str = "/ferrogate.v1.MachineIdentity/ListAllowlists";
    /// Legacy `ListProposals`.
    pub const LIST_PROPOSALS: &str = "/ferrogate.v1.MachineIdentity/ListProposals";
    /// Legacy `DeleteProposal`.
    pub const DELETE_PROPOSAL: &str = "/ferrogate.v1.MachineIdentity/DeleteProposal";
    /// Legacy `RevokeSvid`.
    pub const REVOKE_SVID: &str = "/ferrogate.v1.MachineIdentity/RevokeSvid";
    /// Legacy `RevokeHost`.
    pub const REVOKE_HOST: &str = "/ferrogate.v1.MachineIdentity/RevokeHost";
    /// Legacy `BumpEpoch`.
    pub const BUMP_EPOCH: &str = "/ferrogate.v1.MachineIdentity/BumpEpoch";
    /// Legacy `ListSvids`.
    pub const LIST_SVIDS: &str = "/ferrogate.v1.MachineIdentity/ListSvids";

    /// `Admin/BeginStepUp`.
    pub const BEGIN_STEP_UP: &str = "/ferrogate.admin.v1.Admin/BeginStepUp";
    /// `Admin/StepUp`.
    pub const STEP_UP: &str = "/ferrogate.admin.v1.Admin/StepUp";
    /// `Admin/Logout`.
    pub const LOGOUT: &str = "/ferrogate.admin.v1.Admin/Logout";
    /// `Admin/WhoAmI`.
    pub const WHO_AM_I: &str = "/ferrogate.admin.v1.Admin/WhoAmI";
    /// `Admin/ListMySessions`.
    pub const LIST_MY_SESSIONS: &str = "/ferrogate.admin.v1.Admin/ListMySessions";
    /// `Admin/RevokeSession`.
    pub const REVOKE_SESSION: &str = "/ferrogate.admin.v1.Admin/RevokeSession";
    /// `Admin/ChangePassword`.
    pub const CHANGE_PASSWORD: &str = "/ferrogate.admin.v1.Admin/ChangePassword";
    /// `Admin/ListMyFactors`.
    pub const LIST_MY_FACTORS: &str = "/ferrogate.admin.v1.Admin/ListMyFactors";
    /// `Admin/BeginAddFactor`.
    pub const BEGIN_ADD_FACTOR: &str = "/ferrogate.admin.v1.Admin/BeginAddFactor";
    /// `Admin/CompleteAddFactor`.
    pub const COMPLETE_ADD_FACTOR: &str = "/ferrogate.admin.v1.Admin/CompleteAddFactor";
    /// `Admin/RemoveFactor`.
    pub const REMOVE_FACTOR: &str = "/ferrogate.admin.v1.Admin/RemoveFactor";
    /// `Admin/ListAdminAccounts`.
    pub const LIST_ADMIN_ACCOUNTS: &str = "/ferrogate.admin.v1.Admin/ListAdminAccounts";
    /// `Admin/ListAdminGroups`.
    pub const LIST_ADMIN_GROUPS: &str = "/ferrogate.admin.v1.Admin/ListAdminGroups";
    /// `Admin/CreateAdminAccount`.
    pub const CREATE_ADMIN_ACCOUNT: &str = "/ferrogate.admin.v1.Admin/CreateAdminAccount";
    /// `Admin/UpdateAdminAccount`.
    pub const UPDATE_ADMIN_ACCOUNT: &str = "/ferrogate.admin.v1.Admin/UpdateAdminAccount";
    /// `Admin/SetAdminAccountState`.
    pub const SET_ADMIN_ACCOUNT_STATE: &str = "/ferrogate.admin.v1.Admin/SetAdminAccountState";
    /// `Admin/ResetAdminCredentials`.
    pub const RESET_ADMIN_CREDENTIALS: &str = "/ferrogate.admin.v1.Admin/ResetAdminCredentials";

    /// `Admin/ListAppRequests` (F19).
    pub const LIST_APP_REQUESTS: &str = "/ferrogate.admin.v1.Admin/ListAppRequests";
    /// `Admin/GetAppRequest` (F19).
    pub const GET_APP_REQUEST: &str = "/ferrogate.admin.v1.Admin/GetAppRequest";
    /// `Admin/ApproveAppRequest` (F19).
    pub const APPROVE_APP_REQUEST: &str = "/ferrogate.admin.v1.Admin/ApproveAppRequest";
    /// `Admin/DenyAppRequest` (F19).
    pub const DENY_APP_REQUEST: &str = "/ferrogate.admin.v1.Admin/DenyAppRequest";
    /// `Admin/ListApprovals` (F19).
    pub const LIST_APPROVALS: &str = "/ferrogate.admin.v1.Admin/ListApprovals";
    /// `Admin/GetApproval` (F19).
    pub const GET_APPROVAL: &str = "/ferrogate.admin.v1.Admin/GetApproval";
    /// `Admin/UpdateApproval` (F19).
    pub const UPDATE_APPROVAL: &str = "/ferrogate.admin.v1.Admin/UpdateApproval";
    /// `Admin/RevokeApproval` (F19).
    pub const REVOKE_APPROVAL: &str = "/ferrogate.admin.v1.Admin/RevokeApproval";
    /// `Admin/SetLineageAutoUpdateFrozen` (F19).
    pub const SET_LINEAGE_AUTO_UPDATE_FROZEN: &str =
        "/ferrogate.admin.v1.Admin/SetLineageAutoUpdateFrozen";
    /// `Admin/AdminRegisterApplication` (F19).
    pub const ADMIN_REGISTER_APPLICATION: &str =
        "/ferrogate.admin.v1.Admin/AdminRegisterApplication";
}

use Permission as P;

/// The method → access table. One entry per RPC of every served service; the
/// layer, the handler guards and the coverage test all read it.
pub const METHOD_ACCESS: &[(&str, Access)] = &[
    // ---- MachineIdentity: host-facing and public (unchanged) ----
    ("/ferrogate.v1.MachineIdentity/Attest", Access::Public),
    ("/ferrogate.v1.MachineIdentity/FetchSVID", Access::Public),
    ("/ferrogate.v1.MachineIdentity/Rotate", Access::Public),
    ("/ferrogate.v1.MachineIdentity/JWKS", Access::Public),
    (
        "/ferrogate.v1.MachineIdentity/GetEnrollmentKey",
        Access::Public,
    ),
    ("/ferrogate.v1.MachineIdentity/GetAllowlist", Access::Public),
    ("/ferrogate.v1.MachineIdentity/Health", Access::Public),
    ("/ferrogate.v1.MachineIdentity/LatestSth", Access::Public),
    (
        "/ferrogate.v1.MachineIdentity/InclusionProof",
        Access::Public,
    ),
    (
        "/ferrogate.v1.MachineIdentity/ConsistencyProof",
        Access::Public,
    ),
    // ---- MachineIdentity: host methods, authenticated in the handler ----
    // SVID + machine-key signature over the proposal.
    (
        "/ferrogate.v1.MachineIdentity/ProposeAllowlist",
        Access::Host,
    ),
    // F19 §7.1 host proof, context `ferrogate-audit-forward-v1`, rate-limited
    // per host (F20 Phase 0).
    (
        "/ferrogate.v1.MachineIdentity/AppendAuditEvent",
        Access::Host,
    ),
    // F19 §7.1 host proof, each under its own context and per-host budget.
    (
        "/ferrogate.v1.MachineIdentity/SubmitAppRequest",
        Access::Host,
    ),
    (
        "/ferrogate.v1.MachineIdentity/GetAppRequestStatus",
        Access::Host,
    ),
    ("/ferrogate.v1.MachineIdentity/SyncAllowlist", Access::Host),
    // ---- MachineIdentity: legacy admin RPCs (F20 Phase 0) ----
    (
        paths::LIST_ALLOWLISTS,
        session(Some(P::LegacyAllowlistRead), false, false, false),
    ),
    (
        paths::LIST_PROPOSALS,
        session(Some(P::LegacyAllowlistRead), false, false, false),
    ),
    (
        paths::LIST_SVIDS,
        session(Some(P::SvidList), false, false, false),
    ),
    (
        paths::SET_ALLOWLIST,
        session(Some(P::LegacyAllowlistWrite), true, false, false),
    ),
    (
        paths::DELETE_ALLOWLIST,
        session(Some(P::LegacyAllowlistWrite), true, false, false),
    ),
    (
        paths::DELETE_PROPOSAL,
        session(Some(P::LegacyAllowlistWrite), true, false, false),
    ),
    (
        paths::REVOKE_SVID,
        session(Some(P::SvidRevoke), true, false, false),
    ),
    (
        paths::REVOKE_HOST,
        session(Some(P::SvidRevoke), true, false, false),
    ),
    (
        paths::BUMP_EPOCH,
        session(Some(P::PolicyEpochBump), true, false, false),
    ),
    // ---- Admin: public, throttled ----
    ("/ferrogate.admin.v1.Admin/BeginLogin", Access::AdminPublic),
    ("/ferrogate.admin.v1.Admin/Login", Access::AdminPublic),
    (
        "/ferrogate.admin.v1.Admin/BeginEnrollment",
        Access::AdminPublic,
    ),
    (
        "/ferrogate.admin.v1.Admin/CompleteEnrollment",
        Access::AdminPublic,
    ),
    // ---- Admin: any authenticated session ----
    (paths::WHO_AM_I, session(None, false, true, true)),
    (paths::LOGOUT, session(None, false, true, true)),
    (paths::CHANGE_PASSWORD, session(None, false, true, true)),
    (paths::LIST_MY_SESSIONS, session(None, false, false, false)),
    (paths::REVOKE_SESSION, session(None, false, false, false)),
    // Only issues a challenge (for StepUp or an inline MfaProof); a
    // restricted session needs one for ChangePassword's WebAuthn proof.
    (paths::BEGIN_STEP_UP, session(None, false, true, true)),
    (paths::STEP_UP, session(None, false, false, false)),
    // ---- Admin: second-factor management (M checked in the handler) ----
    (paths::LIST_MY_FACTORS, session(None, false, false, true)),
    (paths::BEGIN_ADD_FACTOR, session(None, true, false, true)),
    (
        paths::COMPLETE_ADD_FACTOR,
        session(None, false, false, true),
    ),
    (paths::REMOVE_FACTOR, session(None, false, false, false)),
    // ---- Admin: account administration (M checked in the handler) ----
    (
        paths::LIST_ADMIN_ACCOUNTS,
        session(Some(P::AccountList), false, false, false),
    ),
    (
        paths::LIST_ADMIN_GROUPS,
        session(Some(P::AccountList), false, false, false),
    ),
    (
        paths::CREATE_ADMIN_ACCOUNT,
        session(Some(P::AccountCreate), false, false, false),
    ),
    (
        paths::UPDATE_ADMIN_ACCOUNT,
        session(Some(P::AccountUpdate), false, false, false),
    ),
    (
        paths::SET_ADMIN_ACCOUNT_STATE,
        session(Some(P::AccountDisable), false, false, false),
    ),
    (
        paths::RESET_ADMIN_CREDENTIALS,
        session(Some(P::AccountReset), false, false, false),
    ),
    // ---- Admin: application approvals (F19 §5.4; S = step-up, M in handler) ----
    (
        paths::LIST_APP_REQUESTS,
        session(Some(P::AppRequestList), false, false, false),
    ),
    (
        paths::GET_APP_REQUEST,
        session(Some(P::AppRequestRead), false, false, false),
    ),
    (
        paths::LIST_APPROVALS,
        session(Some(P::ApprovalList), false, false, false),
    ),
    (
        paths::GET_APPROVAL,
        session(Some(P::ApprovalRead), false, false, false),
    ),
    (
        paths::APPROVE_APP_REQUEST,
        session(Some(P::AppRequestApprove), true, false, false),
    ),
    (
        paths::DENY_APP_REQUEST,
        session(Some(P::AppRequestDeny), true, false, false),
    ),
    (
        paths::UPDATE_APPROVAL,
        session(Some(P::ApprovalUpdate), true, false, false),
    ),
    (
        paths::SET_LINEAGE_AUTO_UPDATE_FROZEN,
        session(Some(P::ApprovalUpdate), true, false, false),
    ),
    (
        paths::REVOKE_APPROVAL,
        session(Some(P::ApprovalRevoke), true, false, false),
    ),
    // Single step also needs `app_request.approve` (checked in the handler
    // unless the strict policy queues the request); a per-operation MfaProof
    // replaces the step-up window.
    (
        paths::ADMIN_REGISTER_APPLICATION,
        session(Some(P::AppDirectRegister), false, false, false),
    ),
];

/// The access rule for a gRPC path; `None` means unclassified (denied).
#[must_use]
pub fn access_for(path: &str) -> Option<Access> {
    METHOD_ACCESS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, a)| *a)
}

/// The authenticated administrator behind a request. Inserted into the request
/// extensions by the layer after authentication and authorization; handlers
/// read it, and it can only originate in-process (extensions never come from
/// the wire).
#[derive(Debug, Clone)]
pub struct AdminContext {
    /// Pseudonymous administrator id (UUIDv7).
    pub admin_id: String,
    /// Reference to the session (never the token).
    pub session_ref: String,
    /// Group names, read from the database for this call.
    pub groups: Vec<String>,
    /// Permissions granted through those groups.
    pub permissions: BTreeSet<Permission>,
    /// Authenticator assurance level of the session.
    pub aal: i64,
    /// Unix seconds of the last second-factor verification.
    pub mfa_at: i64,
    /// Source IP of the call.
    pub source_ip: Option<IpAddr>,
    /// 1 tui, 2 tray, 3 cli.
    pub client_kind: i64,
    /// The account's password has expired.
    pub restricted: bool,
    /// A tray session of a `CMIS_ADMIN_TRAY_FIDO2_GROUPS` member that was
    /// not verified with FIDO2: held to factor enrollment (F20 §5).
    pub factor_enrollment_required: bool,
    pub(crate) session_hash: Vec<u8>,
}

impl AdminContext {
    /// A context for in-process callers (tests, tooling) that bypass the
    /// network layer. It is never derived from wire input: request extensions
    /// cannot be set by a client.
    #[must_use]
    pub fn synthetic(admin_id: &str, permissions: impl IntoIterator<Item = Permission>) -> Self {
        Self {
            admin_id: admin_id.to_string(),
            session_ref: "synthetic".to_string(),
            groups: Vec::new(),
            permissions: permissions.into_iter().collect(),
            aal: 2,
            mfa_at: 0,
            source_ip: None,
            client_kind: 0,
            restricted: false,
            factor_enrollment_required: false,
            session_hash: Vec::new(),
        }
    }

    /// Whether the caller holds `permission`.
    #[must_use]
    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }
}

/// Handler-side guard: the request must carry an [`AdminContext`] (put there
/// by the layer) that holds the permission [`METHOD_ACCESS`] requires for
/// `path`. Defense in depth: if the layer were ever missing, every admin
/// handler still fails closed.
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
pub fn require<T>(request: &tonic::Request<T>, path: &str) -> Result<AdminContext, Status> {
    let Some(Access::Session(rule)) = access_for(path) else {
        return Err(Status::permission_denied("method_not_classified"));
    };
    let ctx = request
        .extensions()
        .get::<AdminContext>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("session_invalid"))?;
    if let Some(p) = rule.permission {
        if !ctx.has(p) {
            return Err(Status::permission_denied("permission_denied"));
        }
    }
    if ctx.restricted && !rule.allow_restricted {
        return Err(Status::failed_precondition("password_expired"));
    }
    if ctx.factor_enrollment_required && !rule.allow_factor_enrollment {
        return Err(Status::failed_precondition("factor_enrollment_required"));
    }
    Ok(ctx)
}

/// Network facts about a caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// TCP peer address (proxies are not supported, F20 §2).
    pub ip: Option<IpAddr>,
    /// SHA-256 of the mTLS client leaf certificate, when one was presented.
    pub client_cert_sha256: Option<[u8; 32]>,
}

/// Extract [`PeerInfo`] from request extensions: the TLS listener's
/// [`crate::transport::PeerConnectInfo`], or tonic's plain TCP connect info.
#[must_use]
pub fn peer_info(ext: &tonic::codegen::http::Extensions) -> PeerInfo {
    use tonic::transport::server::TcpConnectInfo;
    if let Some(info) = ext.get::<crate::transport::PeerConnectInfo>() {
        return PeerInfo {
            ip: info.remote_addr.map(|a| a.ip()),
            client_cert_sha256: info.client_cert_sha256,
        };
    }
    PeerInfo {
        ip: ext
            .get::<TcpConnectInfo>()
            .and_then(TcpConnectInfo::remote_addr)
            .map(|a| a.ip()),
        client_cert_sha256: None,
    }
}

/// The single authentication and authorization decision point (NRM §5.3.1).
#[derive(Debug, Clone)]
pub struct AdminAuthz {
    state: Arc<AdminState>,
}

impl AdminAuthz {
    /// Wrap the admin state.
    #[must_use]
    pub fn new(state: Arc<AdminState>) -> Self {
        Self { state }
    }

    /// The admin state.
    #[must_use]
    pub fn state(&self) -> &Arc<AdminState> {
        &self.state
    }

    /// Authenticate the bearer session in `authorization` and authorize it
    /// for `path` under `rule`. On success the session's `last_seen_at` is
    /// refreshed (at most once a minute) and the authorized call is audited.
    #[allow(clippy::too_many_lines)] // the one ordered decision sequence of F20 §7.
    pub async fn authorize(
        &self,
        path: &str,
        rule: SessionRule,
        authorization: Option<&[u8]>,
        peer: &PeerInfo,
    ) -> Result<AdminContext, Status> {
        let st = &self.state;
        let now = st.now();
        let Some(token) = authorization.and_then(session::bearer_token) else {
            return Err(Status::unauthenticated("session_invalid"));
        };
        let hash = session::hash_token(&token);
        let row = st
            .cluster()
            .admin_session(&hash)
            .await
            .map_err(|e| st.store_error(&e))?
            .ok_or_else(|| Status::unauthenticated("session_invalid"))?;

        match session::liveness(&row, now) {
            Liveness::Live => {}
            Liveness::Revoked => return Err(Status::unauthenticated("session_invalid")),
            Liveness::Idle => {
                st.revoke_session(&row, RevokeReason::Idle, None).await;
                return Err(Status::unauthenticated("session_invalid"));
            }
            Liveness::Absolute => {
                st.revoke_session(&row, RevokeReason::Absolute, None).await;
                return Err(Status::unauthenticated("session_invalid"));
            }
        }

        if st.config().session_bind_ip {
            let same_ip = peer.ip.is_some() && super::state::canonical_ip(peer.ip) == row.source_ip;
            if !same_ip {
                tracing::warn!(
                    event = "admin.session.ip_mismatch",
                    session_ref = %session::session_ref(&row.session_hash),
                    "admin session used from another address; revoking it"
                );
                st.revoke_session(&row, RevokeReason::IpMismatch, None)
                    .await;
                return Err(Status::unauthenticated("session_invalid"));
            }
        }
        if let Some(bound) = &row.client_cert_sha256 {
            if peer.client_cert_sha256.map(|c| c.to_vec()).as_ref() != Some(bound) {
                st.revoke_session(&row, RevokeReason::CertMismatch, None)
                    .await;
                return Err(Status::unauthenticated("session_invalid"));
            }
        }

        let account = st
            .cluster()
            .admin_account(&row.admin_id)
            .await
            .map_err(|e| st.store_error(&e))?;
        let Some(account) = account.filter(|a| a.state == ACCOUNT_ACTIVE) else {
            st.revoke_session(&row, RevokeReason::AccountInactive, None)
                .await;
            return Err(Status::unauthenticated("session_invalid"));
        };

        let groups = st
            .cluster()
            .admin_groups_of(&account.admin_id)
            .await
            .map_err(|e| st.store_error(&e))?;
        let permissions: BTreeSet<Permission> = st
            .cluster()
            .admin_permissions_of(&account.admin_id)
            .await
            .map_err(|e| st.store_error(&e))?
            .iter()
            .filter_map(|p| Permission::parse(p))
            .collect();

        let restricted = password_expired(&account, now);
        // Computed live, so the tray FIDO2 policy follows the configuration
        // and the groups of this call, and a key registered from a TOTP
        // session does not lift the restriction: the holder signs in again
        // with the key (F22 §3a).
        let factor_enrollment_required =
            super::factors::fido2_required(st.config(), row.client_kind, &groups)
                && row.mfa_method != MfaMethod::WebAuthn.code();
        let ctx = AdminContext {
            admin_id: account.admin_id.clone(),
            session_ref: session::session_ref(&row.session_hash),
            groups,
            permissions,
            aal: row.aal,
            mfa_at: row.mfa_at,
            source_ip: peer.ip,
            client_kind: row.client_kind,
            restricted,
            factor_enrollment_required,
            session_hash: row.session_hash.clone(),
        };

        if restricted && !rule.allow_restricted {
            self.deny(Some(&ctx), path, rule, "password_expired");
            return Err(Status::failed_precondition("password_expired"));
        }
        if factor_enrollment_required && !rule.allow_factor_enrollment {
            self.deny(Some(&ctx), path, rule, "factor_enrollment_required");
            return Err(Status::failed_precondition("factor_enrollment_required"));
        }
        if let Some(p) = rule.permission {
            if !ctx.has(p) {
                self.deny(Some(&ctx), path, rule, "permission_denied");
                return Err(Status::permission_denied("permission_denied"));
            }
        }
        if rule.step_up {
            self.require_step_up(&ctx)?;
        }

        if now.saturating_sub(row.last_seen_at) >= session::TOUCH_INTERVAL_SECS {
            if let Err(e) = st
                .cluster()
                .admin_touch_session(&row.session_hash, now)
                .await
            {
                tracing::error!(error = %e, "admin session touch failed");
            }
        }
        st.audit(AuditEvent::AdminCallAuthorized {
            admin_id: ctx.admin_id.clone(),
            session_ref: ctx.session_ref.clone(),
            method: path.to_string(),
        });
        Ok(ctx)
    }

    /// `FAILED_PRECONDITION (step_up_required)` unless the session verified a
    /// second factor within `CMIS_ADMIN_STEP_UP_WINDOW_SECS`.
    #[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
    pub fn require_step_up(&self, ctx: &AdminContext) -> Result<(), Status> {
        let window = self.state.config().step_up_window_secs;
        if self.state.now().saturating_sub(ctx.mfa_at) > window {
            return Err(Status::failed_precondition("step_up_required"));
        }
        Ok(())
    }

    /// Record a refusal (`AdminAccessDenied`) for the SIEM.
    pub fn deny(&self, ctx: Option<&AdminContext>, path: &str, rule: SessionRule, reason: &str) {
        tracing::warn!(
            event = "admin.authz.denied",
            method = %path.chars().take(128).collect::<String>(),
            reason,
            admin_id = ctx.map_or("", |c| c.admin_id.as_str()),
            "admin call refused"
        );
        self.state.audit(AuditEvent::AdminAccessDenied {
            admin_id: ctx.map(|c| c.admin_id.clone()),
            // Caller-chosen for unclassified paths: bounded.
            method: path.chars().take(128).collect(),
            permission: rule.permission.map_or("", Permission::as_str).to_string(),
            reason: reason.to_string(),
        });
    }

    /// Separation of duties for a change to another account's groups, state
    /// or credentials (F20 §7):
    ///
    /// - rule 3 (always): nobody changes their own groups or state, or resets
    ///   their own credentials;
    /// - rule 2 (strict policy only): `ferrogate-account-admins` and
    ///   `ferrogate-approvers` are mutually exclusive in `new_groups`.
    #[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
    pub fn check_sod(
        &self,
        actor: &AdminContext,
        target_admin_id: &str,
        new_groups: Option<&[String]>,
    ) -> Result<(), Status> {
        if actor.admin_id == target_admin_id {
            return Err(Status::permission_denied("sod_violation"));
        }
        if let Some(g) = new_groups {
            self.check_group_set(g)?;
        }
        Ok(())
    }

    /// Strict-policy rule 2 on a group set (also used at creation).
    #[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
    pub fn check_group_set(&self, new_groups: &[String]) -> Result<(), Status> {
        if self.state.config().strict_sod
            && new_groups.iter().any(|g| g == groups::ACCOUNT_ADMINS)
            && new_groups.iter().any(|g| g == groups::APPROVERS)
        {
            return Err(Status::permission_denied("sod_violation"));
        }
        Ok(())
    }

    /// Rule 4 (always): the last active account administrator cannot be
    /// disabled or demoted. `removes_account_admin` says whether the change
    /// takes `target` out of the active account administrators.
    pub async fn check_last_account_admin(
        &self,
        target: &AdminAccountRow,
        removes_account_admin: bool,
    ) -> Result<(), Status> {
        if !removes_account_admin || target.state != ACCOUNT_ACTIVE {
            return Ok(());
        }
        let admins = self
            .state
            .cluster()
            .admin_active_members_of(groups::ACCOUNT_ADMINS)
            .await
            .map_err(|e| self.state.store_error(&e))?;
        if admins.iter().all(|a| *a == target.admin_id) {
            return Err(Status::permission_denied("sod_violation"));
        }
        Ok(())
    }
}

/// Whether the account's password is past its expiry at `now`.
#[must_use]
pub fn password_expired(account: &AdminAccountRow, now: i64) -> bool {
    account.password_expires_at.is_some_and(|e| e <= now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    fn descriptor_paths() -> Vec<String> {
        let set = prost_types::FileDescriptorSet::decode(ferro_proto::FILE_DESCRIPTOR_SET)
            .expect("descriptor set decodes");
        let mut out = Vec::new();
        for file in set.file {
            let package = file.package.clone().unwrap_or_default();
            for svc in &file.service {
                for m in &svc.method {
                    out.push(format!(
                        "/{package}.{}/{}",
                        svc.name.clone().unwrap_or_default(),
                        m.name.clone().unwrap_or_default()
                    ));
                }
            }
        }
        out
    }

    /// Every RPC of every compiled service is classified, so a new RPC cannot
    /// ship without an access decision (and is denied until it has one).
    #[test]
    fn every_compiled_method_has_an_access_entry() {
        let paths = descriptor_paths();
        assert!(paths.len() > 30, "both services were found: {paths:?}");
        let missing: Vec<_> = paths.iter().filter(|p| access_for(p).is_none()).collect();
        assert!(missing.is_empty(), "unclassified RPCs: {missing:?}");
    }

    #[test]
    fn the_table_names_only_real_methods_and_each_once() {
        let paths = descriptor_paths();
        let mut seen = std::collections::HashSet::new();
        for (p, _) in METHOD_ACCESS {
            assert!(paths.iter().any(|d| d == p), "stale entry {p}");
            assert!(seen.insert(*p), "duplicate entry {p}");
        }
    }

    #[test]
    fn unknown_methods_are_unclassified() {
        assert_eq!(access_for("/ferrogate.v1.MachineIdentity/DropTables"), None);
        assert_eq!(access_for("/ferrogate.admin.v1.Admin/Backdoor"), None);
        assert_eq!(access_for(""), None);
    }

    /// The Phase 0 table (F20 §1, §7): every legacy admin RPC needs a session
    /// and its permission; writes need a step-up.
    #[test]
    fn legacy_admin_rpcs_need_the_spec_permissions() {
        let want = [
            ("ListAllowlists", P::LegacyAllowlistRead, false),
            ("ListProposals", P::LegacyAllowlistRead, false),
            ("ListSvids", P::SvidList, false),
            ("SetAllowlist", P::LegacyAllowlistWrite, true),
            ("DeleteAllowlist", P::LegacyAllowlistWrite, true),
            ("DeleteProposal", P::LegacyAllowlistWrite, true),
            ("RevokeSvid", P::SvidRevoke, true),
            ("RevokeHost", P::SvidRevoke, true),
            ("BumpEpoch", P::PolicyEpochBump, true),
        ];
        for (m, perm, step_up) in want {
            let path = format!("{}{m}", paths::MI);
            assert_eq!(
                access_for(&path),
                Some(session(Some(perm), step_up, false, false)),
                "{path}"
            );
        }
    }

    /// F20 §7: the host methods are classified as host-authenticated —
    /// neither public nor admin — so the layer never asks them for a
    /// session and the handler's host proof is the gate.
    #[test]
    fn host_methods_are_host_authenticated() {
        for m in [
            "AppendAuditEvent",
            "ProposeAllowlist",
            "SubmitAppRequest",
            "GetAppRequestStatus",
            "SyncAllowlist",
        ] {
            let path = format!("{}{m}", paths::MI);
            assert_eq!(access_for(&path), Some(Access::Host), "{path}");
        }
        let hosts: Vec<_> = METHOD_ACCESS
            .iter()
            .filter(|(_, a)| *a == Access::Host)
            .map(|(p, _)| *p)
            .collect();
        assert_eq!(
            hosts.len(),
            5,
            "no other method is host-authenticated: {hosts:?}"
        );
    }

    /// F19 §5.4 / F20 §7: the app-management RPCs need their permission;
    /// decisions and edits a recent step-up; the direct registration its
    /// per-operation proof (handler) instead.
    #[test]
    fn app_management_rpcs_need_the_spec_permissions() {
        let want = [
            (paths::LIST_APP_REQUESTS, P::AppRequestList, false),
            (paths::GET_APP_REQUEST, P::AppRequestRead, false),
            (paths::LIST_APPROVALS, P::ApprovalList, false),
            (paths::GET_APPROVAL, P::ApprovalRead, false),
            (paths::APPROVE_APP_REQUEST, P::AppRequestApprove, true),
            (paths::DENY_APP_REQUEST, P::AppRequestDeny, true),
            (paths::UPDATE_APPROVAL, P::ApprovalUpdate, true),
            (
                paths::SET_LINEAGE_AUTO_UPDATE_FROZEN,
                P::ApprovalUpdate,
                true,
            ),
            (paths::REVOKE_APPROVAL, P::ApprovalRevoke, true),
            (
                paths::ADMIN_REGISTER_APPLICATION,
                P::AppDirectRegister,
                false,
            ),
        ];
        for (path, perm, step_up) in want {
            assert_eq!(
                access_for(path),
                Some(session(Some(perm), step_up, false, false)),
                "{path}"
            );
        }
    }

    /// F20 §7: factor management is open to any session; adding a factor
    /// needs a recent step-up to begin and a per-operation proof (handler)
    /// to complete; a session restricted by the FIDO2 tray policy may list
    /// and add factors but not remove them.
    #[test]
    fn factor_management_rpcs_are_classified() {
        let want = [
            (paths::LIST_MY_FACTORS, session(None, false, false, true)),
            (paths::BEGIN_ADD_FACTOR, session(None, true, false, true)),
            (
                paths::COMPLETE_ADD_FACTOR,
                session(None, false, false, true),
            ),
            (paths::REMOVE_FACTOR, session(None, false, false, false)),
            (paths::WHO_AM_I, session(None, false, true, true)),
            (paths::LOGOUT, session(None, false, true, true)),
            (paths::CHANGE_PASSWORD, session(None, false, true, true)),
            (paths::BEGIN_STEP_UP, session(None, false, true, true)),
            (paths::STEP_UP, session(None, false, false, false)),
            (paths::LIST_MY_SESSIONS, session(None, false, false, false)),
        ];
        for (path, access) in want {
            assert_eq!(access_for(path), Some(access), "{path}");
        }
    }

    #[test]
    fn the_guard_holds_a_fido2_restricted_session_to_factor_enrollment() {
        let mut ctx = AdminContext::synthetic("a", Permission::ALL);
        ctx.factor_enrollment_required = true;
        let call = |path: &str| {
            let mut req = tonic::Request::new(());
            req.extensions_mut().insert(ctx.clone());
            require(&req, path)
        };
        for ok in [
            paths::WHO_AM_I,
            paths::LOGOUT,
            paths::LIST_MY_FACTORS,
            paths::BEGIN_ADD_FACTOR,
            paths::COMPLETE_ADD_FACTOR,
        ] {
            assert!(call(ok).is_ok(), "{ok}");
        }
        for refused in [
            paths::LIST_MY_SESSIONS,
            paths::REMOVE_FACTOR,
            paths::STEP_UP,
            paths::SET_ALLOWLIST,
            paths::CREATE_ADMIN_ACCOUNT,
        ] {
            let e = call(refused).unwrap_err();
            assert_eq!(
                (e.code(), e.message()),
                (
                    tonic::Code::FailedPrecondition,
                    "factor_enrollment_required"
                ),
                "{refused}"
            );
        }
    }

    #[test]
    fn builtin_group_permissions_are_all_known() {
        for (group, perms) in ferro_raft::admin::BUILTIN_GROUPS {
            assert!(groups::ALL.contains(group));
            for p in *perms {
                assert!(Permission::parse(p).is_some(), "{group}: {p}");
            }
        }
        for p in Permission::ALL {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
        }
    }

    #[test]
    fn the_guard_fails_closed_without_a_context() {
        let req = tonic::Request::new(());
        let err = require(&req, paths::SET_ALLOWLIST).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let mut req = tonic::Request::new(());
        req.extensions_mut()
            .insert(AdminContext::synthetic("a", [P::SvidList]));
        let err = require(&req, paths::SET_ALLOWLIST).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let mut req = tonic::Request::new(());
        req.extensions_mut()
            .insert(AdminContext::synthetic("a", [P::LegacyAllowlistWrite]));
        assert!(require(&req, paths::SET_ALLOWLIST).is_ok());

        let err = require(&req, "/ferrogate.v1.MachineIdentity/Attest").unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "public path is not a session path"
        );
    }
}
