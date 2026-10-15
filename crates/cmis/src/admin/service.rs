//! The `ferrogate.admin.v1.Admin` service (F20 §6, §7, §9, §13): login,
//! step-up, sessions, password change, enrollment and account administration.
//!
//! Served only on the admin listener, behind [`super::layer::AdminAuthLayer`].
//! Every session method also calls [`require`] itself (defense in depth).
//! Every authentication failure answers the same `UNAUTHENTICATED
//! (invalid_credentials)`; throttled callers get `RESOURCE_EXHAUSTED
//! (login_throttled)` with `retry-after`. Secrets taken from requests are moved
//! into [`Zeroizing`] buffers at once and are never logged.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::admin_server::{Admin, AdminServer};
use ferro_proto::admin_v1::login_request::SecondFactor;
use ferro_proto::admin_v1::{
    AdminAccountInfo, AdminGroupInfo, BeginAddFactorRequest, BeginAddFactorResponse,
    BeginEnrollmentRequest, BeginEnrollmentResponse, BeginLoginRequest, BeginLoginResponse,
    BeginStepUpRequest, BeginStepUpResponse, ChangePasswordRequest, ChangePasswordResponse,
    ClientInfo, CompleteAddFactorRequest, CompleteAddFactorResponse, CompleteEnrollmentRequest,
    CompleteEnrollmentResponse, CreateAdminAccountRequest, CreateAdminAccountResponse,
    ListAdminAccountsRequest, ListAdminAccountsResponse, ListAdminGroupsRequest,
    ListAdminGroupsResponse, ListMyFactorsRequest, ListMyFactorsResponse, ListMySessionsRequest,
    ListMySessionsResponse, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse,
    RemoveFactorRequest, RemoveFactorResponse, ResetAdminCredentialsRequest,
    ResetAdminCredentialsResponse, RevokeSessionRequest, RevokeSessionResponse, SessionInfo,
    SetAdminAccountStateRequest, SetAdminAccountStateResponse, StepUpRequest, StepUpResponse,
    UpdateAdminAccountRequest, UpdateAdminAccountResponse, WebAuthnAssertion, WhoAmIRequest,
    WhoAmIResponse,
};
use ferro_proto::admin_v1::{
    AdminRegisterApplicationRequest, AdminRegisterApplicationResponse, ApproveAppRequestRequest,
    ApproveAppRequestResponse, DenyAppRequestRequest, DenyAppRequestResponse, GetAppRequestRequest,
    GetAppRequestResponse, GetApprovalRequest, GetApprovalResponse, ListAppRequestsRequest,
    ListAppRequestsResponse, ListApprovalsRequest, ListApprovalsResponse, RevokeApprovalRequest,
    RevokeApprovalResponse, SetLineageAutoUpdateFrozenRequest, SetLineageAutoUpdateFrozenResponse,
    UpdateApprovalRequest, UpdateApprovalResponse,
};
use ferro_raft::admin::{
    AdminAccountRow, EnrollmentCompletion, EnrollmentTokenRow, MfaVerification, PasswordUpdate,
    ACCOUNT_ACTIVE, ACCOUNT_DISABLED, ACCOUNT_PENDING, TOKEN_BOOTSTRAP, TOKEN_ENROLL, TOKEN_RESET,
};
use ferro_raft::ClusterError;

use super::authz::{
    groups, password_expired, paths, peer_info, require, AdminAuthz, AdminContext, PeerInfo,
    Permission, SessionRule,
};
use super::bootstrap::{
    self, BOOTSTRAPPED_KEY, ENROLLMENT_DEFAULT_TTL_SECS, ENROLLMENT_MAX_TTL_SECS, ENROLLMENT_PREFIX,
};
use super::factors::{self, factor_policy, ChallengePurpose, Verified, STEP_UP_NONCE};
use super::password::{self, check_policy, year_of, PasswordError, PolicyContext, PolicyFailure};
use super::session::{self, Liveness, MfaMethod, RevokeReason, CLIENT_TRAY};
use super::state::{
    canonical_ip, clean_display_name, normalize_username, username_throttle_key, AdminState,
};
use super::throttle::KeyKind;
use super::totp;

/// Largest admin request accepted (F20 §2).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Issuer label in TOTP provisioning URIs.
pub const TOTP_ISSUER: &str = "FerroGate";

/// The `Admin` gRPC service.
#[derive(Debug, Clone)]
pub struct AdminSvc {
    authz: Arc<AdminAuthz>,
}

impl AdminSvc {
    /// Build the service over the shared authorization component.
    #[must_use]
    pub fn new(authz: Arc<AdminAuthz>) -> Self {
        Self { authz }
    }

    /// The tonic server wrapper, with the 64 KiB request cap applied.
    #[must_use]
    pub fn into_server(self) -> AdminServer<Self> {
        AdminServer::new(self).max_decoding_message_size(MAX_REQUEST_BYTES)
    }

    fn st(&self) -> &AdminState {
        self.authz.state()
    }
}

fn invalid() -> Status {
    Status::unauthenticated("invalid_credentials")
}

fn throttled(wait: u64) -> Status {
    let mut s = Status::resource_exhausted("login_throttled");
    if let Ok(v) = wait.max(1).to_string().parse() {
        s.metadata_mut().insert("retry-after", v);
    }
    s
}

fn policy_failed(failures: &[PolicyFailure]) -> Status {
    let mut s = Status::failed_precondition("password_policy");
    let ids: Vec<&str> = failures.iter().map(|f| f.id()).collect();
    if let Ok(v) = ids.join(",").parse() {
        s.metadata_mut().insert("x-ferrogate-policy-failures", v);
    }
    s
}

fn password_error(e: &PasswordError) -> Status {
    match e {
        PasswordError::Busy => Status::unavailable("auth_busy"),
        PasswordError::Internal(_) => {
            tracing::error!(event = "admin.password.error", error = %e, "password hashing failed");
            Status::internal("internal_error")
        }
    }
}

fn client_info(info: Option<&ClientInfo>) -> (i64, Option<String>) {
    let kind = info.map_or(0, |c| c.kind);
    let kind = if (1..=3).contains(&kind) {
        i64::from(kind)
    } else {
        0
    };
    let version = info
        .map(|c| {
            c.version
                .chars()
                .filter(char::is_ascii_graphic)
                .take(64)
                .collect::<String>()
        })
        .filter(|v| !v.is_empty());
    (kind, version)
}

/// Validate and canonicalise a group set (built-in groups only in this wave;
/// custom groups are F20 Phase 2).
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
fn validate_groups(raw: &[String]) -> Result<Vec<String>, Status> {
    if raw.is_empty() {
        return Err(Status::invalid_argument("groups_required"));
    }
    if raw.len() > 16 {
        return Err(Status::invalid_argument("too_many_groups"));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for g in raw {
        let g = g.trim();
        if !groups::ALL.contains(&g) {
            return Err(Status::invalid_argument("unknown_group"));
        }
        if !out.iter().any(|x| x == g) {
            out.push(g.to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn ip_string(peer: &PeerInfo) -> String {
    canonical_ip(peer.ip)
}

impl AdminSvc {
    async fn account(&self, admin_id: &str) -> Result<Option<AdminAccountRow>, Status> {
        self.st()
            .cluster()
            .admin_account(admin_id)
            .await
            .map_err(|e| self.st().store_error(&e))
    }

    fn policy_ctx<'a>(
        &'a self,
        username: &'a str,
        display_name: Option<&'a str>,
    ) -> PolicyContext<'a> {
        PolicyContext {
            username,
            display_name,
            trust_domain: &self.st().config().trust_domain,
            year: year_of(self.st().now()),
            blocklist: self.st().blocklist(),
        }
    }

    /// `true` if `candidate` equals the account's current or any earlier
    /// password.
    async fn reused(
        &self,
        account: &AdminAccountRow,
        candidate: &Zeroizing<String>,
    ) -> Result<bool, Status> {
        let st = self.st();
        let mut hashes: Vec<(String, Option<i64>)> = st
            .cluster()
            .admin_password_history(&account.admin_id)
            .await
            .map_err(|e| st.store_error(&e))?
            .into_iter()
            .map(|h| (h.password_phc, h.pepper_id))
            .collect();
        if let Some(cur) = &account.password_phc {
            hashes.push((cur.clone(), account.pepper_id));
        }
        for (phc, pepper_id) in hashes {
            match st.hasher().verify(candidate.clone(), phc, pepper_id).await {
                Ok(v) if v.ok => return Ok(true),
                Ok(_) => {}
                // A history hash made under a retired pepper cannot be checked.
                Err(PasswordError::Internal(e)) => {
                    tracing::warn!(error = %e, "password history entry could not be checked");
                }
                Err(e) => return Err(password_error(&e)),
            }
        }
        Ok(false)
    }

    /// The live enrollment token named by `text`, with its account.
    async fn live_token(
        &self,
        text: &str,
    ) -> Result<Option<(EnrollmentTokenRow, Option<AdminAccountRow>)>, Status> {
        let st = self.st();
        let Some(hash) = bootstrap::token_hash(text) else {
            return Ok(None);
        };
        let Some(row) = st
            .cluster()
            .admin_enrollment_token(&hash)
            .await
            .map_err(|e| st.store_error(&e))?
        else {
            return Ok(None);
        };
        if row.used_at.is_some() || row.expires_at <= st.now() {
            return Ok(None);
        }
        match row.purpose {
            TOKEN_BOOTSTRAP => {
                let done = st
                    .cluster()
                    .setting(BOOTSTRAPPED_KEY)
                    .await
                    .map_err(|e| st.store_error(&e))?
                    .is_some_and(|v| v == "1");
                let count = st
                    .cluster()
                    .admin_account_count()
                    .await
                    .map_err(|e| st.store_error(&e))?;
                Ok((!done && count == 0).then_some((row, None)))
            }
            TOKEN_ENROLL | TOKEN_RESET => {
                let Some(id) = row.admin_id.clone() else {
                    return Ok(None);
                };
                let account = self.account(&id).await?;
                Ok(account
                    .filter(|a| a.state != ACCOUNT_DISABLED)
                    .map(|a| (row, Some(a))))
            }
            _ => Ok(None),
        }
    }

    async fn enrollment_failed(&self, peer: &PeerInfo, keys: &[(KeyKind, Vec<u8>)]) -> Status {
        let st = self.st();
        st.throttle_failure(keys).await;
        tracing::info!(
            event = "admin.enrollment.failed",
            "enrollment attempt failed"
        );
        st.security_log("enrollment.failed", None, None, peer.ip, None)
            .await;
        invalid()
    }

    async fn complete_bootstrap(
        &self,
        row: EnrollmentTokenRow,
        req: CompleteEnrollmentRequest,
        password: Zeroizing<String>,
        code: Zeroizing<String>,
        peer: &PeerInfo,
        ip_keys: &[(KeyKind, Vec<u8>)],
    ) -> Result<Response<CompleteEnrollmentResponse>, Status> {
        let st = self.st();
        if req.webauthn_attestation.is_some() {
            // F20 §9: the first account is bootstrapped with TOTP on the
            // CMIS node; it adds a key from the tray afterwards.
            return Err(Status::invalid_argument("factor_not_offered"));
        }
        let username = normalize_username(&req.username)
            .ok_or_else(|| Status::invalid_argument("invalid_username"))?;
        let display = clean_display_name(&req.display_name)
            .ok_or_else(|| Status::invalid_argument("invalid_display_name"))?;
        let display_opt = (!display.is_empty()).then_some(display.as_str());
        check_policy(&password, &self.policy_ctx(&username, display_opt))
            .map_err(|f| policy_failed(&f))?;
        let now = st.now();
        let Some(secret) =
            st.pending_enrollment_secret(&row.token_hash, row.pending_secret_enc.as_deref())
        else {
            return Err(self.enrollment_failed(peer, ip_keys).await);
        };
        let Some(step) = totp::verify(&secret, &code, now, None) else {
            return Err(self.enrollment_failed(peer, ip_keys).await);
        };
        let admin_id = uuid::Uuid::now_v7().to_string();
        let (phc, pepper_id) = st
            .hasher()
            .hash(password)
            .await
            .map_err(|e| password_error(&e))?;
        let sealed = st.keys().seal_totp(&admin_id, &secret).map_err(|e| {
            tracing::error!(error = %e, "TOTP sealing failed");
            Status::internal("internal_error")
        })?;
        let granted: Vec<String> = if st.config().strict_sod {
            vec![groups::ACCOUNT_ADMINS.to_string()]
        } else {
            groups::ALL.iter().map(|g| (*g).to_string()).collect()
        };
        let account = AdminAccountRow {
            admin_id: admin_id.clone(),
            username,
            display_name: display_opt.map(str::to_string),
            state: ACCOUNT_ACTIVE,
            created_at: now,
            created_by_admin_id: None,
            password_phc: None,
            pepper_id: None,
            password_changed_at: None,
            password_expires_at: None,
            totp_secret_enc: None,
            totp_last_step: None,
            last_login_at: None,
            disabled_at: None,
            disabled_by_admin_id: None,
            row_version: 1,
        };
        let completion = EnrollmentCompletion {
            token_hash: row.token_hash.clone(),
            admin_id: admin_id.clone(),
            password: Some(PasswordUpdate {
                password_phc: phc,
                pepper_id,
                changed_at: now,
                expires_at: now + password::LIFETIME_SECS,
            }),
            totp: Some((sealed, step)),
            webauthn: None,
            now,
        };
        match st
            .cluster()
            .admin_bootstrap_account(&account, &granted, &completion, &[(BOOTSTRAPPED_KEY, "1")])
            .await
        {
            Ok(()) => {}
            Err(ClusterError::Conflict(_)) => return Err(invalid()),
            Err(e) => return Err(st.store_error(&e)),
        }
        bootstrap::remove_token_file(&st.config().bootstrap_token_file);
        tracing::warn!(
            event = "admin.bootstrap.completed",
            admin_id = %admin_id,
            "first administrator bootstrapped; bootstrap will not re-arm"
        );
        st.audit(AuditEvent::AdminBootstrapCompleted {
            admin_id: admin_id.clone(),
        });
        st.security_log("bootstrap.completed", Some(&admin_id), None, peer.ip, None)
            .await;
        Ok(Response::new(CompleteEnrollmentResponse { admin_id }))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one ordered flow.
    async fn complete_enroll(
        &self,
        row: EnrollmentTokenRow,
        account: AdminAccountRow,
        req: CompleteEnrollmentRequest,
        password: Zeroizing<String>,
        code: Zeroizing<String>,
        peer: &PeerInfo,
        ip_keys: &[(KeyKind, Vec<u8>)],
    ) -> Result<Response<CompleteEnrollmentResponse>, Status> {
        let st = self.st();
        if !req.username.trim().is_empty()
            && normalize_username(&req.username).as_deref() != Some(account.username.as_str())
        {
            return Err(Status::invalid_argument("username_mismatch"));
        }
        let label = req
            .webauthn_attestation
            .as_ref()
            .map(|a| factors::clean_label(&a.label))
            .transpose()?;
        let now = st.now();
        let needs_password = account.password_phc.is_none();
        let creds = st.webauthn_credentials(&account.admin_id).await?;
        let needs_factor = account.totp_secret_enc.is_none() && creds.is_empty();
        if needs_password {
            check_policy(
                &password,
                &self.policy_ctx(&account.username, account.display_name.as_deref()),
            )
            .map_err(|f| policy_failed(&f))?;
        }
        let (totp_update, webauthn) = if needs_factor {
            // At least one factor, both welcome (F20 §5); each proven.
            if code.is_empty() && req.webauthn_attestation.is_none() {
                return Err(self.enrollment_failed(peer, ip_keys).await);
            }
            let totp_update = if code.is_empty() {
                None
            } else {
                let Some(secret) = st
                    .pending_enrollment_secret(&row.token_hash, row.pending_secret_enc.as_deref())
                else {
                    return Err(self.enrollment_failed(peer, ip_keys).await);
                };
                let Some(step) = totp::verify(&secret, &code, now, None) else {
                    return Err(self.enrollment_failed(peer, ip_keys).await);
                };
                let sealed = st
                    .keys()
                    .seal_totp(&account.admin_id, &secret)
                    .map_err(|e| {
                        tracing::error!(error = %e, "TOTP sealing failed");
                        Status::internal("internal_error")
                    })?;
                Some((sealed, step))
            };
            let webauthn = match (&req.webauthn_attestation, label) {
                (Some(att), Some(label)) => {
                    let Some(cred) = st.check_enrollment_attestation(
                        &row.token_hash,
                        &account.admin_id,
                        att,
                        label,
                    ) else {
                        return Err(self.enrollment_failed(peer, ip_keys).await);
                    };
                    Some(cred)
                }
                _ => None,
            };
            (totp_update, webauthn)
        } else {
            // Password-only reset: prove possession of the enrolled TOTP
            // factor (a reset of a key-only account must clear the factors
            // too, see ResetAdminCredentials). No new factor is enrolled.
            if req.webauthn_attestation.is_some() {
                return Err(Status::invalid_argument("factor_not_offered"));
            }
            if !st.check_totp(&account, &code).await? {
                return Err(self.enrollment_failed(peer, ip_keys).await);
            }
            (None, None)
        };
        let password_update = if needs_password {
            if self.reused(&account, &password).await? {
                return Err(policy_failed(&[PolicyFailure::Reused]));
            }
            let (phc, pepper_id) = st
                .hasher()
                .hash(password)
                .await
                .map_err(|e| password_error(&e))?;
            Some(PasswordUpdate {
                password_phc: phc,
                pepper_id,
                changed_at: now,
                expires_at: now + password::LIFETIME_SECS,
            })
        } else {
            None
        };
        // F20 §5 enrollment item 3: each enrolled factor is audited.
        let mut enrolled: Vec<(MfaMethod, String)> = Vec::new();
        if totp_update.is_some() {
            enrolled.push((MfaMethod::Totp, factors::FACTOR_TOTP.to_string()));
        }
        if let Some(cred) = &webauthn {
            enrolled.push((MfaMethod::WebAuthn, factors::factor_id(&cred.credential_id)));
        }
        let completion = EnrollmentCompletion {
            token_hash: row.token_hash.clone(),
            admin_id: account.admin_id.clone(),
            password: password_update,
            totp: totp_update,
            webauthn,
            now,
        };
        match st.cluster().admin_complete_enrollment(&completion).await {
            Ok(()) => {}
            Err(ClusterError::Conflict(_)) => return Err(invalid()),
            Err(e) => return Err(st.store_error(&e)),
        }
        let same_ip_as_creator = match &row.created_by_admin_id {
            Some(creator) => st
                .cluster()
                .admin_live_sessions(creator)
                .await
                .is_ok_and(|sessions| sessions.iter().any(|s| s.source_ip == ip_string(peer))),
            None => false,
        };
        let purpose = if row.purpose == TOKEN_RESET {
            "reset"
        } else {
            "enroll"
        };
        tracing::info!(
            event = "admin.enrollment.completed",
            admin_id = %account.admin_id,
            purpose,
            same_ip_as_creator,
            "enrollment completed"
        );
        st.audit(AuditEvent::AdminEnrollmentCompleted {
            admin_id: account.admin_id.clone(),
            purpose: purpose.to_string(),
            same_ip_as_creator,
        });
        st.security_log(
            "enrollment.completed",
            Some(&account.admin_id),
            None,
            peer.ip,
            Some(purpose),
        )
        .await;
        for (method, factor) in enrolled {
            st.audit(AuditEvent::AdminMfaEnrolled {
                admin_id: account.admin_id.clone(),
                method: method.label().to_string(),
            });
            st.security_log(
                "mfa.enrolled",
                Some(&account.admin_id),
                None,
                peer.ip,
                Some(&factor),
            )
            .await;
        }
        Ok(Response::new(CompleteEnrollmentResponse {
            admin_id: account.admin_id,
        }))
    }

    async fn rotate(
        &self,
        ctx: &AdminContext,
        mfa: Option<MfaVerification>,
        restricted: bool,
    ) -> Result<Zeroizing<String>, Status> {
        let st = self.st();
        let (token, hash) = session::new_token();
        let rotated = st
            .cluster()
            .admin_rotate_session(&ctx.session_hash, &hash, mfa, i64::from(restricted))
            .await
            .map_err(|e| st.store_error(&e))?;
        if !rotated {
            return Err(Status::unauthenticated("session_invalid"));
        }
        Ok(token)
    }

    async fn target(&self, admin_id: &str) -> Result<AdminAccountRow, Status> {
        if admin_id.len() > 64 {
            return Err(Status::invalid_argument("invalid_admin_id"));
        }
        self.account(admin_id)
            .await?
            .ok_or_else(|| Status::not_found("account_not_found"))
    }

    /// Why a guarded account write applied to no row: the last-account-admin
    /// guard (rule 4) when it was in force and now fails, else a concurrent
    /// edit.
    async fn refusal(&self, target: &AdminAccountRow, guarded: bool) -> Status {
        if guarded {
            if let Err(status) = self.authz.check_last_account_admin(target, true).await {
                return status;
            }
        }
        Status::aborted("row_version_mismatch")
    }

    async fn groups_of(&self, admin_id: &str) -> Result<Vec<String>, Status> {
        self.st()
            .cluster()
            .admin_groups_of(admin_id)
            .await
            .map_err(|e| self.st().store_error(&e))
    }
}

#[tonic::async_trait]
impl Admin for AdminSvc {
    // ---- F19 application approvals (see `super::apps`) ----

    async fn list_app_requests(
        &self,
        request: Request<ListAppRequestsRequest>,
    ) -> Result<Response<ListAppRequestsResponse>, Status> {
        super::apps::list_app_requests(&self.authz, request).await
    }

    async fn get_app_request(
        &self,
        request: Request<GetAppRequestRequest>,
    ) -> Result<Response<GetAppRequestResponse>, Status> {
        super::apps::get_app_request(&self.authz, request).await
    }

    async fn approve_app_request(
        &self,
        request: Request<ApproveAppRequestRequest>,
    ) -> Result<Response<ApproveAppRequestResponse>, Status> {
        super::apps::approve_app_request(&self.authz, request).await
    }

    async fn deny_app_request(
        &self,
        request: Request<DenyAppRequestRequest>,
    ) -> Result<Response<DenyAppRequestResponse>, Status> {
        super::apps::deny_app_request(&self.authz, request).await
    }

    async fn list_approvals(
        &self,
        request: Request<ListApprovalsRequest>,
    ) -> Result<Response<ListApprovalsResponse>, Status> {
        super::apps::list_approvals(&self.authz, request).await
    }

    async fn get_approval(
        &self,
        request: Request<GetApprovalRequest>,
    ) -> Result<Response<GetApprovalResponse>, Status> {
        super::apps::get_approval(&self.authz, request).await
    }

    async fn update_approval(
        &self,
        request: Request<UpdateApprovalRequest>,
    ) -> Result<Response<UpdateApprovalResponse>, Status> {
        super::apps::update_approval(&self.authz, request).await
    }

    async fn revoke_approval(
        &self,
        request: Request<RevokeApprovalRequest>,
    ) -> Result<Response<RevokeApprovalResponse>, Status> {
        super::apps::revoke_approval(&self.authz, request).await
    }

    async fn set_lineage_auto_update_frozen(
        &self,
        request: Request<SetLineageAutoUpdateFrozenRequest>,
    ) -> Result<Response<SetLineageAutoUpdateFrozenResponse>, Status> {
        super::apps::set_lineage_auto_update_frozen(&self.authz, request).await
    }

    async fn admin_register_application(
        &self,
        request: Request<AdminRegisterApplicationRequest>,
    ) -> Result<Response<AdminRegisterApplicationResponse>, Status> {
        super::apps::admin_register_application(&self.authz, request).await
    }

    async fn begin_login(
        &self,
        request: Request<BeginLoginRequest>,
    ) -> Result<Response<BeginLoginResponse>, Status> {
        let st = self.st();
        let peer = peer_info(request.extensions());
        if !st.allow_begin_login(peer.ip) {
            return Err(throttled(60));
        }
        let req = request.into_inner();
        if req.username.len() > 256 || req.device_token.len() > 128 {
            return Err(Status::invalid_argument("request_too_large"));
        }
        let key = username_throttle_key(&req.username);
        let nonce = st.issue_nonce("login-v1", &[ip_string(&peer).as_bytes(), key.as_bytes()]);
        let (kind, _) = client_info(req.client.as_ref());
        if kind != CLIENT_TRAY {
            // The TUI and the CLI get TOTP only, whatever the account holds
            // (no CTAP forwarding over SSH): identical for every username.
            return Ok(Response::new(BeginLoginResponse {
                login_nonce: nonce,
                methods: vec![1],
                webauthn: None,
            }));
        }
        // The tray: what this account may use under the policy (F20 §5,
        // §6.1). The same lookups run for unknown usernames, which get a
        // plausible offer fixed per username, with decoy credential ids.
        let account = match normalize_username(&req.username) {
            Some(u) => st
                .cluster()
                .admin_account_by_username(&u)
                .await
                .map_err(|e| st.store_error(&e))?,
            None => None,
        };
        let id = account.as_ref().map_or("", |a| a.admin_id.as_str());
        let creds = st.webauthn_credentials(id).await?;
        let groups = self.groups_of(id).await?;
        let usable = account
            .as_ref()
            .filter(|a| a.state == ACCOUNT_ACTIVE && a.password_phc.is_some())
            .filter(|a| a.totp_secret_enc.is_some() || !creds.is_empty());
        let (methods, allow) = match usable {
            Some(a) => {
                let policy = factor_policy(
                    st.config(),
                    kind,
                    &groups,
                    a.totp_secret_enc.is_some(),
                    !creds.is_empty(),
                );
                let mut methods = Vec::with_capacity(2);
                if policy.totp {
                    methods.push(1);
                }
                if policy.webauthn {
                    methods.push(2);
                }
                let allow: Vec<Vec<u8>> = creds.into_iter().map(|c| c.credential_id).collect();
                (methods, policy.webauthn.then_some(allow))
            }
            None => st.decoy_offer(&key),
        };
        let webauthn = allow.map(|ids| {
            st.assertion_options(st.webauthn_challenge(ChallengePurpose::Login, &nonce), ids)
        });
        Ok(Response::new(BeginLoginResponse {
            login_nonce: nonce,
            methods,
            webauthn,
        }))
    }

    #[allow(clippy::too_many_lines)] // the F20 §6 check sequence, in order.
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let st = self.st();
        let peer = peer_info(request.extensions());
        let mut req = request.into_inner();
        let password = Zeroizing::new(std::mem::take(&mut req.password));
        let (code, assertion): (Zeroizing<String>, Option<WebAuthnAssertion>) = match req
            .second_factor
            .take()
        {
            Some(SecondFactor::TotpCode(c)) => (Zeroizing::new(c), None),
            Some(SecondFactor::WebauthnAssertion(a)) => (Zeroizing::new(String::new()), Some(a)),
            None => (Zeroizing::new(String::new()), None),
        };
        let device_token = Zeroizing::new(std::mem::take(&mut req.device_token));
        if req.username.len() > 256
            || password.len() > 4 * password::MAX_LEN + 4
            || device_token.len() > 128
        {
            return Err(Status::invalid_argument("request_too_large"));
        }
        let client = client_info(req.client.as_ref());
        let ip = ip_string(&peer);
        let key = username_throttle_key(&req.username);

        let account = match normalize_username(&req.username) {
            Some(u) => st
                .cluster()
                .admin_account_by_username(&u)
                .await
                .map_err(|e| st.store_error(&e))?,
            None => None,
        };
        let device_ok = account.as_ref().is_some_and(|a| {
            !device_token.is_empty() && st.device_token_valid(&device_token, &a.admin_id)
        });
        let dev_key = (
            KeyKind::IpDevice,
            st.throttle_key(
                KeyKind::IpDevice,
                format!("{ip}|{}", device_token.as_str()).as_bytes(),
            ),
        );
        let acct_key = (
            KeyKind::Account,
            st.throttle_key(KeyKind::Account, key.as_bytes()),
        );
        let keys = if device_ok {
            vec![dev_key.clone()]
        } else {
            vec![
                (KeyKind::Ip, st.throttle_key(KeyKind::Ip, ip.as_bytes())),
                acct_key.clone(),
            ]
        };

        // Attempts sharing a throttle key run one at a time on this node, so a
        // burst of parallel guesses cannot all pass the lock check before the
        // first failure is counted.
        let _serial = st.serialize(&keys).await;
        // 1. Throttle, before any cryptography.
        if let Some(wait) = st.throttle_wait(&keys).await? {
            tracing::info!(
                event = "admin.login.throttled",
                retry_after = wait,
                "login throttled"
            );
            return Err(throttled(wait));
        }
        // 2. Nonce.
        let nonce_ok = st.redeem_nonce(
            "login-v1",
            &req.login_nonce,
            &[ip.as_bytes(), key.as_bytes()],
        );
        // The account's factors and groups decide which second factors the
        // policy accepts (F20 §5); looked up for unknown usernames too.
        let account_id = account.as_ref().map_or("", |a| a.admin_id.as_str());
        let creds = st.webauthn_credentials(account_id).await?;
        let groups = self.groups_of(account_id).await?;
        let policy = account.as_ref().map(|a| {
            factor_policy(
                st.config(),
                client.0,
                &groups,
                a.totp_secret_enc.is_some(),
                !creds.is_empty(),
            )
        });

        // 3.–5. Account state, password, second factor. Every failure costs
        // one Argon2 verification so timing is uniform.
        let mut reason = "invalid_credentials";
        let mut verified: Option<(AdminAccountRow, Verified)> = None;
        match (&account, policy) {
            _ if !nonce_ok => {
                reason = "nonce";
                st.hasher()
                    .verify_dummy(password.clone())
                    .await
                    .map_err(|e| password_error(&e))?;
            }
            (Some(a), Some(policy))
                if a.state == ACCOUNT_ACTIVE
                    && (a.totp_secret_enc.is_some() || !creds.is_empty()) =>
            {
                if let Some(phc) = a.password_phc.clone() {
                    let v = st
                        .hasher()
                        .verify(password.clone(), phc, a.pepper_id)
                        .await
                        .map_err(|e| password_error(&e))?;
                    let second = if !v.ok {
                        None
                    } else if let Some(asr) = &assertion {
                        if policy.webauthn {
                            let challenge =
                                st.webauthn_challenge(ChallengePurpose::Login, &req.login_nonce);
                            st.check_assertion(a, &creds, asr, &challenge, peer.ip)
                                .await?
                        } else {
                            reason = "method_not_allowed";
                            None
                        }
                    } else if !code.is_empty() && !policy.totp {
                        reason = "method_not_allowed";
                        None
                    } else {
                        st.check_totp(a, &code).await?.then(Verified::totp)
                    };
                    if let Some(second) = second {
                        if v.needs_rehash {
                            match st.hasher().hash(password.clone()).await {
                                Ok((phc, pepper)) => {
                                    if let Err(e) = st
                                        .cluster()
                                        .admin_rehash_password(&a.admin_id, &phc, pepper)
                                        .await
                                    {
                                        tracing::error!(error = %e, "password rehash store failed");
                                    }
                                }
                                Err(e) => tracing::error!(error = %e, "password rehash failed"),
                            }
                        }
                        verified = Some((a.clone(), second));
                    }
                } else {
                    st.hasher()
                        .verify_dummy(password.clone())
                        .await
                        .map_err(|e| password_error(&e))?;
                }
            }
            (Some(a), _) => {
                if a.state == ACCOUNT_DISABLED {
                    reason = "disabled";
                }
                st.hasher()
                    .verify_dummy(password.clone())
                    .await
                    .map_err(|e| password_error(&e))?;
            }
            (None, _) => {
                st.hasher()
                    .verify_dummy(password.clone())
                    .await
                    .map_err(|e| password_error(&e))?;
            }
        }
        drop(password);
        drop(code);

        let Some((account, second)) = verified else {
            // A request without a valid nonce never reached the account, so it
            // counts against the source only: junk requests cannot lock a
            // known administrator out through the account counter.
            let counted: Vec<_> = keys
                .iter()
                .filter(|(kind, _)| nonce_ok || *kind != KeyKind::Account)
                .cloned()
                .collect();
            let lock = st.throttle_failure(&counted).await;
            let account_ref = st.account_ref_hmac(&key);
            tracing::info!(
                event = "admin.login.failed",
                reason,
                account_ref = %account_ref,
                lock_secs = lock,
                "admin login failed"
            );
            st.audit(AuditEvent::AdminLoginFailed {
                account_ref_hmac: account_ref,
                reason: reason.to_string(),
                src_ip_hmac: st.src_ip_hmac(peer.ip),
                lock_secs: lock,
            });
            st.security_log(
                "login.failed",
                account.as_ref().map(|a| a.admin_id.as_str()),
                Some(&key),
                peer.ip,
                Some(reason),
            )
            .await;
            st.check_anomaly().await;
            return Err(invalid());
        };

        // Success: reset the device and account counters (K_ip is kept).
        let mut clear = vec![acct_key];
        if device_ok {
            clear.push(dev_key);
        }
        st.throttle_clear(&clear).await;
        let now = st.now();
        let restricted = password_expired(&account, now);
        // A listed-group tray member without a key signed in with TOTP: the
        // session is held to factor enrollment (F20 §5).
        let factor_enrollment_required = factors::fido2_required(st.config(), client.0, &groups)
            && second.method != MfaMethod::WebAuthn;
        let (token, row) = st
            .open_session(&account, &peer, client, second, restricted)
            .await?;
        if let Err(e) = st
            .cluster()
            .admin_set_last_login(&account.admin_id, now)
            .await
        {
            tracing::error!(error = %e, "last_login_at update failed");
        }
        let groups = self.groups_of(&account.admin_id).await?;
        let session_ref = session::session_ref(&row.session_hash);
        tracing::info!(
            event = "admin.login.succeeded",
            admin_id = %account.admin_id,
            session_ref = %session_ref,
            restricted,
            factor_enrollment_required,
            mfa_method = second.method.label(),
            "admin signed in"
        );
        st.audit(AuditEvent::AdminLoginSucceeded {
            admin_id: account.admin_id.clone(),
            session_ref,
            aal: u8::try_from(row.aal).unwrap_or(0),
            mfa_method: second.method.label().to_string(),
            client_kind: u8::try_from(row.client_kind).unwrap_or(0),
            src_ip_hmac: st.src_ip_hmac(peer.ip),
        });
        st.security_log(
            "login.succeeded",
            Some(&account.admin_id),
            Some(&key),
            peer.ip,
            None,
        )
        .await;
        Ok(Response::new(LoginResponse {
            session_token: token.to_string(),
            idle_timeout_secs: row.idle_timeout_secs,
            absolute_expires_at: row.absolute_expires_at,
            aal: u32::try_from(row.aal).unwrap_or(0),
            password_change_required: restricted,
            password_expires_at: account.password_expires_at.unwrap_or(0),
            device_token: st.issue_device_token(&account.admin_id),
            admin_id: account.admin_id,
            display_name: account.display_name.unwrap_or_default(),
            groups,
            factor_enrollment_required,
        }))
    }

    async fn begin_step_up(
        &self,
        request: Request<BeginStepUpRequest>,
    ) -> Result<Response<BeginStepUpResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::BEGIN_STEP_UP)?;
        let nonce = st.issue_nonce(STEP_UP_NONCE, &[&ctx.session_hash]);
        let (account, creds) = st.factor_holdings(&ctx.admin_id).await?;
        let policy = factor_policy(
            st.config(),
            ctx.client_kind,
            &ctx.groups,
            account.totp_secret_enc.is_some(),
            !creds.is_empty(),
        );
        let webauthn = policy.webauthn.then(|| {
            st.assertion_options(
                st.webauthn_challenge(ChallengePurpose::StepUp, &nonce),
                creds.into_iter().map(|c| c.credential_id).collect(),
            )
        });
        Ok(Response::new(BeginStepUpResponse {
            stepup_nonce: nonce,
            webauthn,
        }))
    }

    async fn step_up(
        &self,
        request: Request<StepUpRequest>,
    ) -> Result<Response<StepUpResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::STEP_UP)?;
        let req = request.into_inner();
        let attempted = match req.proof.as_ref().and_then(|p| p.f.as_ref()) {
            Some(ferro_proto::admin_v1::mfa_proof::F::WebauthnAssertion(_)) => MfaMethod::WebAuthn,
            _ => MfaMethod::Totp,
        };
        let mut result = if st.redeem_nonce(STEP_UP_NONCE, &req.stepup_nonce, &[&ctx.session_hash])
        {
            st.verify_factor(&ctx, req.proof, Some(&req.stepup_nonce))
                .await
        } else {
            st.second_factor_failed(&ctx).await;
            Err(invalid())
        };
        let mut token = None;
        if let Ok(v) = result {
            let now = st.now();
            match self
                .rotate(
                    &ctx,
                    Some(MfaVerification {
                        at: now,
                        method: v.method.code(),
                        aal: v.aal,
                    }),
                    ctx.restricted,
                )
                .await
            {
                Ok(t) => token = Some(t),
                Err(e) => result = Err(e),
            }
        }
        st.audit(AuditEvent::AdminStepUp {
            admin_id: ctx.admin_id.clone(),
            session_ref: ctx.session_ref.clone(),
            mfa_method: attempted.label().to_string(),
            success: result.is_ok(),
        });
        tracing::info!(
            event = "admin.step_up",
            admin_id = %ctx.admin_id,
            session_ref = %ctx.session_ref,
            success = result.is_ok(),
            "step-up"
        );
        result?;
        let token = token.ok_or_else(|| Status::unauthenticated("session_invalid"))?;
        Ok(Response::new(StepUpResponse {
            session_token: token.to_string(),
            step_up_valid_until: st.now() + st.config().step_up_window_secs,
        }))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::LOGOUT)?;
        match st
            .cluster()
            .admin_revoke_session(&ctx.session_hash, st.now(), RevokeReason::Logout.code())
            .await
        {
            Ok(true) => {
                tracing::info!(
                    event = "admin.logout",
                    admin_id = %ctx.admin_id,
                    session_ref = %ctx.session_ref,
                    "admin signed out"
                );
                st.audit(AuditEvent::AdminLogout {
                    admin_id: ctx.admin_id.clone(),
                    session_ref: ctx.session_ref.clone(),
                });
            }
            Ok(false) => {}
            Err(e) => return Err(st.store_error(&e)),
        }
        Ok(Response::new(LogoutResponse {}))
    }

    async fn who_am_i(
        &self,
        request: Request<WhoAmIRequest>,
    ) -> Result<Response<WhoAmIResponse>, Status> {
        let ctx = require(&request, paths::WHO_AM_I)?;
        let account = self.target(&ctx.admin_id).await?;
        Ok(Response::new(WhoAmIResponse {
            admin_id: account.admin_id,
            username: account.username,
            display_name: account.display_name.unwrap_or_default(),
            groups: ctx.groups.clone(),
            permissions: ctx
                .permissions
                .iter()
                .map(|p| p.as_str().to_string())
                .collect(),
            aal: u32::try_from(ctx.aal).unwrap_or(0),
            mfa_at: ctx.mfa_at,
            restricted: ctx.restricted,
            password_expires_at: account.password_expires_at.unwrap_or(0),
            session_ref: ctx.session_ref,
            factor_enrollment_required: ctx.factor_enrollment_required,
        }))
    }

    async fn list_my_sessions(
        &self,
        request: Request<ListMySessionsRequest>,
    ) -> Result<Response<ListMySessionsResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::LIST_MY_SESSIONS)?;
        let now = st.now();
        let sessions = st
            .cluster()
            .admin_live_sessions(&ctx.admin_id)
            .await
            .map_err(|e| st.store_error(&e))?
            .into_iter()
            .filter(|r| session::liveness(r, now) == Liveness::Live)
            .map(|r| SessionInfo {
                session_ref: session::session_ref(&r.session_hash),
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                source_ip: r.source_ip.clone(),
                client_kind: u32::try_from(r.client_kind).unwrap_or(0),
                current: r.session_hash == ctx.session_hash,
                aal: u32::try_from(r.aal).unwrap_or(0),
            })
            .collect();
        Ok(Response::new(ListMySessionsResponse { sessions }))
    }

    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<RevokeSessionResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::REVOKE_SESSION)?;
        let req = request.into_inner();
        let own = req.admin_id.is_empty() || req.admin_id == ctx.admin_id;
        let target = if own {
            ctx.admin_id.clone()
        } else {
            if !ctx.has(Permission::SessionRevokeAny) {
                let rule = SessionRule {
                    permission: Some(Permission::SessionRevokeAny),
                    step_up: true,
                    allow_restricted: false,
                    allow_factor_enrollment: false,
                };
                self.authz
                    .deny(Some(&ctx), paths::REVOKE_SESSION, rule, "permission_denied");
                return Err(Status::permission_denied("permission_denied"));
            }
            self.authz.require_step_up(&ctx)?;
            req.admin_id.clone()
        };
        let sessions = st
            .cluster()
            .admin_live_sessions(&target)
            .await
            .map_err(|e| st.store_error(&e))?;
        let row = sessions
            .iter()
            .find(|s| session::session_ref(&s.session_hash) == req.session_ref)
            .ok_or_else(|| Status::not_found("session_not_found"))?;
        let reason = if own {
            RevokeReason::ByUser
        } else {
            RevokeReason::ByAdmin
        };
        st.revoke_session(row, reason, Some(&ctx.admin_id)).await;
        Ok(Response::new(RevokeSessionResponse {}))
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::CHANGE_PASSWORD)?;
        let mut req = request.into_inner();
        let current = Zeroizing::new(std::mem::take(&mut req.current_password));
        let new = Zeroizing::new(std::mem::take(&mut req.new_password));
        if current.len() > 4 * password::MAX_LEN + 4 || new.len() > 4 * password::MAX_LEN + 4 {
            return Err(policy_failed(&[PolicyFailure::TooLong]));
        }
        let account = self.target(&ctx.admin_id).await?;
        check_policy(
            &new,
            &self.policy_ctx(&account.username, account.display_name.as_deref()),
        )
        .map_err(|f| policy_failed(&f))?;
        st.verify_proof(&ctx, req.proof.take()).await?;
        let Some(phc) = account.password_phc.clone() else {
            return Err(invalid());
        };
        let v = st
            .hasher()
            .verify(current, phc, account.pepper_id)
            .await
            .map_err(|e| password_error(&e))?;
        if !v.ok {
            st.second_factor_failed(&ctx).await;
            return Err(invalid());
        }
        if self.reused(&account, &new).await? {
            return Err(policy_failed(&[PolicyFailure::Reused]));
        }
        let (new_phc, pepper_id) = st
            .hasher()
            .hash(new)
            .await
            .map_err(|e| password_error(&e))?;
        let now = st.now();
        let update = PasswordUpdate {
            password_phc: new_phc,
            pepper_id,
            changed_at: now,
            expires_at: now + password::LIFETIME_SECS,
        };
        st.cluster()
            .admin_change_password(&account.admin_id, &update)
            .await
            .map_err(|e| st.store_error(&e))?;
        st.revoke_all_sessions(
            &account.admin_id,
            Some(&ctx.session_hash),
            RevokeReason::PasswordChanged,
            Some(&account.admin_id),
        )
        .await?;
        let token = self.rotate(&ctx, None, false).await?;
        tracing::info!(event = "admin.password.changed", admin_id = %account.admin_id, "password changed");
        st.audit(AuditEvent::AdminPasswordChanged {
            admin_id: account.admin_id.clone(),
            by_self: true,
        });
        Ok(Response::new(ChangePasswordResponse {
            session_token: token.to_string(),
            password_expires_at: update.expires_at,
        }))
    }

    async fn list_my_factors(
        &self,
        request: Request<ListMyFactorsRequest>,
    ) -> Result<Response<ListMyFactorsResponse>, Status> {
        factors::list_my_factors(&self.authz, request).await
    }

    async fn begin_add_factor(
        &self,
        request: Request<BeginAddFactorRequest>,
    ) -> Result<Response<BeginAddFactorResponse>, Status> {
        factors::begin_add_factor(&self.authz, request).await
    }

    async fn complete_add_factor(
        &self,
        request: Request<CompleteAddFactorRequest>,
    ) -> Result<Response<CompleteAddFactorResponse>, Status> {
        factors::complete_add_factor(&self.authz, request).await
    }

    async fn remove_factor(
        &self,
        request: Request<RemoveFactorRequest>,
    ) -> Result<Response<RemoveFactorResponse>, Status> {
        factors::remove_factor(&self.authz, request).await
    }

    async fn begin_enrollment(
        &self,
        request: Request<BeginEnrollmentRequest>,
    ) -> Result<Response<BeginEnrollmentResponse>, Status> {
        let st = self.st();
        let peer = peer_info(request.extensions());
        let ip_keys = [(
            KeyKind::Ip,
            st.throttle_key(KeyKind::Ip, ip_string(&peer).as_bytes()),
        )];
        let _serial = st.serialize(&ip_keys).await;
        if let Some(wait) = st.throttle_wait(&ip_keys).await? {
            return Err(throttled(wait));
        }
        let token = Zeroizing::new(request.into_inner().enrollment_token);
        let Some((row, account)) = self.live_token(&token).await? else {
            return Err(self.enrollment_failed(&peer, &ip_keys).await);
        };
        // A token enrolls second factors when the account holds none (a new
        // account, or a reset that cleared them); the bootstrap enrolls TOTP
        // only (F20 §9). A password-only reset enrolls nothing.
        let (username, choosable, display_name, needs_factor, creation) = match &account {
            None => (String::new(), true, String::new(), true, None),
            Some(a) => {
                let creds = st.webauthn_credentials(&a.admin_id).await?;
                let needs = a.totp_secret_enc.is_none() && creds.is_empty();
                let creation = needs.then(|| {
                    st.creation_options(
                        st.enrollment_creation_challenge(&row.token_hash),
                        a,
                        &creds,
                    )
                });
                (
                    a.username.clone(),
                    false,
                    a.display_name.clone().unwrap_or_default(),
                    needs,
                    creation,
                )
            }
        };
        let totp_provisioning_uri = if needs_factor {
            // A fresh seed on every call: a copy taken earlier by anyone else
            // who saw the token stops working once the holder begins.
            let Some(secret) = st.offer_enrollment_secret(&row.token_hash).await? else {
                return Err(invalid());
            };
            let label = if username.is_empty() {
                "admin"
            } else {
                username.as_str()
            };
            totp::provisioning_uri(secret.as_ref(), TOTP_ISSUER, label)
        } else {
            String::new()
        };
        tracing::info!(
            event = "admin.enrollment.begin",
            admin_id = account.as_ref().map_or("", |a| a.admin_id.as_str()),
            "enrollment started"
        );
        st.security_log(
            "enrollment.begin",
            account.as_ref().map(|a| a.admin_id.as_str()),
            None,
            peer.ip,
            None,
        )
        .await;
        Ok(Response::new(BeginEnrollmentResponse {
            username,
            username_choosable: choosable,
            display_name,
            totp_provisioning_uri,
            webauthn_creation_options: creation,
            password_min_len: u32::try_from(password::MIN_LEN).unwrap_or(24),
        }))
    }

    async fn complete_enrollment(
        &self,
        request: Request<CompleteEnrollmentRequest>,
    ) -> Result<Response<CompleteEnrollmentResponse>, Status> {
        let st = self.st();
        let peer = peer_info(request.extensions());
        let ip_keys = [(
            KeyKind::Ip,
            st.throttle_key(KeyKind::Ip, ip_string(&peer).as_bytes()),
        )];
        let _serial = st.serialize(&ip_keys).await;
        if let Some(wait) = st.throttle_wait(&ip_keys).await? {
            return Err(throttled(wait));
        }
        let mut req = request.into_inner();
        let token = Zeroizing::new(std::mem::take(&mut req.enrollment_token));
        let password = Zeroizing::new(std::mem::take(&mut req.password));
        let code = Zeroizing::new(std::mem::take(&mut req.totp_code));
        if password.len() > 4 * password::MAX_LEN + 4 || req.username.len() > 256 {
            return Err(Status::invalid_argument("request_too_large"));
        }
        let Some((row, account)) = self.live_token(&token).await? else {
            return Err(self.enrollment_failed(&peer, &ip_keys).await);
        };
        match account {
            None => {
                self.complete_bootstrap(row, req, password, code, &peer, &ip_keys)
                    .await
            }
            Some(account) => {
                self.complete_enroll(row, account, req, password, code, &peer, &ip_keys)
                    .await
            }
        }
    }

    async fn list_admin_accounts(
        &self,
        request: Request<ListAdminAccountsRequest>,
    ) -> Result<Response<ListAdminAccountsResponse>, Status> {
        let st = self.st();
        let _ctx = require(&request, paths::LIST_ADMIN_ACCOUNTS)?;
        let rows = st
            .cluster()
            .admin_accounts()
            .await
            .map_err(|e| st.store_error(&e))?;
        let mut accounts = Vec::with_capacity(rows.len());
        for a in rows {
            let groups = self.groups_of(&a.admin_id).await?;
            accounts.push(AdminAccountInfo {
                admin_id: a.admin_id,
                username: a.username,
                display_name: a.display_name.unwrap_or_default(),
                state: u32::try_from(a.state).unwrap_or(0),
                groups,
                created_at: a.created_at,
                last_login_at: a.last_login_at.unwrap_or(0),
                password_expires_at: a.password_expires_at.unwrap_or(0),
                row_version: u64::try_from(a.row_version).unwrap_or(0),
            });
        }
        Ok(Response::new(ListAdminAccountsResponse { accounts }))
    }

    async fn list_admin_groups(
        &self,
        request: Request<ListAdminGroupsRequest>,
    ) -> Result<Response<ListAdminGroupsResponse>, Status> {
        let st = self.st();
        let _ctx = require(&request, paths::LIST_ADMIN_GROUPS)?;
        let groups = st
            .cluster()
            .admin_groups()
            .await
            .map_err(|e| st.store_error(&e))?
            .into_iter()
            .map(|g| AdminGroupInfo {
                group_id: g.group_id,
                name: g.name,
                builtin: g.builtin,
                permissions: g.permissions,
            })
            .collect();
        Ok(Response::new(ListAdminGroupsResponse { groups }))
    }

    async fn create_admin_account(
        &self,
        request: Request<CreateAdminAccountRequest>,
    ) -> Result<Response<CreateAdminAccountResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::CREATE_ADMIN_ACCOUNT)?;
        let mut req = request.into_inner();
        let username = normalize_username(&req.username)
            .ok_or_else(|| Status::invalid_argument("invalid_username"))?;
        let display = clean_display_name(&req.display_name)
            .ok_or_else(|| Status::invalid_argument("invalid_display_name"))?;
        let granted = validate_groups(&req.groups)?;
        self.authz.check_group_set(&granted)?;
        let ttl = if req.enrollment_ttl_secs <= 0 {
            ENROLLMENT_DEFAULT_TTL_SECS
        } else {
            req.enrollment_ttl_secs.clamp(3600, ENROLLMENT_MAX_TTL_SECS)
        };
        if st
            .cluster()
            .admin_account_by_username(&username)
            .await
            .map_err(|e| st.store_error(&e))?
            .is_some()
        {
            return Err(Status::already_exists("username_taken"));
        }
        st.verify_proof(&ctx, req.proof.take()).await?;
        let now = st.now();
        let admin_id = uuid::Uuid::now_v7().to_string();
        let (token, hash) = bootstrap::new_token(ENROLLMENT_PREFIX);
        let account = AdminAccountRow {
            admin_id: admin_id.clone(),
            username,
            display_name: (!display.is_empty()).then_some(display),
            state: ACCOUNT_PENDING,
            created_at: now,
            created_by_admin_id: Some(ctx.admin_id.clone()),
            password_phc: None,
            pepper_id: None,
            password_changed_at: None,
            password_expires_at: None,
            totp_secret_enc: None,
            totp_last_step: None,
            last_login_at: None,
            disabled_at: None,
            disabled_by_admin_id: None,
            row_version: 1,
        };
        let token_row = EnrollmentTokenRow {
            token_hash: hash,
            admin_id: Some(admin_id.clone()),
            purpose: TOKEN_ENROLL,
            created_by_admin_id: Some(ctx.admin_id.clone()),
            created_at: now,
            expires_at: now + ttl,
            used_at: None,
            pending_secret_enc: None,
        };
        match st
            .cluster()
            .admin_create_account(&account, &granted, &token_row)
            .await
        {
            Ok(()) => {}
            Err(ClusterError::Conflict(_)) => return Err(Status::already_exists("username_taken")),
            Err(e) => return Err(st.store_error(&e)),
        }
        tracing::info!(
            event = "admin.account.created",
            admin_id = %admin_id,
            by_admin_id = %ctx.admin_id,
            "admin account created (pending enrollment)"
        );
        st.audit(AuditEvent::AdminAccountCreated {
            admin_id: admin_id.clone(),
            by_admin_id: ctx.admin_id.clone(),
            groups: granted,
        });
        Ok(Response::new(CreateAdminAccountResponse {
            admin_id,
            enrollment_token: token.to_string(),
            enrollment_expires_at: token_row.expires_at,
        }))
    }

    async fn update_admin_account(
        &self,
        request: Request<UpdateAdminAccountRequest>,
    ) -> Result<Response<UpdateAdminAccountResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::UPDATE_ADMIN_ACCOUNT)?;
        let mut req = request.into_inner();
        let target = self.target(&req.admin_id).await?;
        let new_groups = if req.replace_groups {
            Some(validate_groups(&req.groups)?)
        } else {
            None
        };
        let new_display = req
            .display_name
            .as_deref()
            .map(|d| {
                clean_display_name(d)
                    .ok_or_else(|| Status::invalid_argument("invalid_display_name"))
            })
            .transpose()?;
        if new_groups.is_none() && new_display.is_none() {
            return Err(Status::invalid_argument("nothing_to_update"));
        }
        let mut demotes_account_admin = false;
        if let Some(g) = &new_groups {
            self.authz.check_sod(&ctx, &target.admin_id, Some(g))?;
            let was_account_admin = self
                .groups_of(&target.admin_id)
                .await?
                .iter()
                .any(|x| x == groups::ACCOUNT_ADMINS);
            let stays = g.iter().any(|x| x == groups::ACCOUNT_ADMINS);
            demotes_account_admin = was_account_admin && !stays && target.state == ACCOUNT_ACTIVE;
            self.authz
                .check_last_account_admin(&target, demotes_account_admin)
                .await?;
        }
        let expected = i64::try_from(req.expected_row_version)
            .map_err(|_| Status::invalid_argument("expected_row_version"))?;
        st.verify_proof(&ctx, req.proof.take()).await?;
        let version = st
            .cluster()
            .admin_update_account(
                &target.admin_id,
                new_display.clone().map(|d| (!d.is_empty()).then_some(d)),
                new_groups.as_deref(),
                &ctx.admin_id,
                st.now(),
                expected,
                // Rule 4 again, inside the write: race-free against a
                // concurrent demotion or disable of the other admins.
                demotes_account_admin,
            )
            .await
            .map_err(|e| st.store_error(&e))?;
        let Some(version) = version else {
            return Err(self.refusal(&target, demotes_account_admin).await);
        };
        if new_groups.is_some() {
            st.revoke_all_sessions(
                &target.admin_id,
                None,
                RevokeReason::GroupsChanged,
                Some(&ctx.admin_id),
            )
            .await?;
        }
        let mut changed = Vec::new();
        if new_display.is_some() {
            changed.push("display_name".to_string());
        }
        if new_groups.is_some() {
            changed.push("groups".to_string());
        }
        tracing::info!(
            event = "admin.account.updated",
            admin_id = %target.admin_id,
            by_admin_id = %ctx.admin_id,
            "admin account updated"
        );
        st.audit(AuditEvent::AdminAccountUpdated {
            admin_id: target.admin_id.clone(),
            by_admin_id: ctx.admin_id.clone(),
            changed_fields: changed,
            groups: new_groups,
        });
        Ok(Response::new(UpdateAdminAccountResponse {
            row_version: u64::try_from(version).unwrap_or(0),
        }))
    }

    async fn set_admin_account_state(
        &self,
        request: Request<SetAdminAccountStateRequest>,
    ) -> Result<Response<SetAdminAccountStateResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::SET_ADMIN_ACCOUNT_STATE)?;
        let mut req = request.into_inner();
        let target = self.target(&req.admin_id).await?;
        self.authz.check_sod(&ctx, &target.admin_id, None)?;
        let wanted = match req.state {
            2 => ACCOUNT_ACTIVE,
            3 => ACCOUNT_DISABLED,
            _ => return Err(Status::invalid_argument("invalid_state")),
        };
        let mut removes_account_admin = false;
        if wanted == ACCOUNT_DISABLED {
            removes_account_admin = target.state == ACCOUNT_ACTIVE
                && self
                    .groups_of(&target.admin_id)
                    .await?
                    .iter()
                    .any(|x| x == groups::ACCOUNT_ADMINS);
            self.authz
                .check_last_account_admin(&target, removes_account_admin)
                .await?;
        }
        if wanted == ACCOUNT_ACTIVE && target.state == ACCOUNT_PENDING {
            return Err(Status::failed_precondition("enrollment_pending"));
        }
        // An account re-enabled before it ever enrolled goes back to pending.
        let stored = if wanted == ACCOUNT_ACTIVE && target.password_phc.is_none() {
            ACCOUNT_PENDING
        } else {
            wanted
        };
        st.verify_proof(&ctx, req.proof.take()).await?;
        let version = st
            .cluster()
            .admin_set_account_state(
                &target.admin_id,
                stored,
                &ctx.admin_id,
                st.now(),
                None,
                removes_account_admin,
            )
            .await
            .map_err(|e| st.store_error(&e))?;
        let Some(version) = version else {
            return Err(self.refusal(&target, removes_account_admin).await);
        };
        if wanted == ACCOUNT_DISABLED {
            st.revoke_all_sessions(
                &target.admin_id,
                None,
                RevokeReason::AccountDisabled,
                Some(&ctx.admin_id),
            )
            .await?;
        }
        let label = if wanted == ACCOUNT_DISABLED {
            "disabled"
        } else {
            "active"
        };
        tracing::info!(
            event = "admin.account.state_changed",
            admin_id = %target.admin_id,
            by_admin_id = %ctx.admin_id,
            state = label,
            "admin account state changed"
        );
        st.audit(AuditEvent::AdminAccountStateChanged {
            admin_id: target.admin_id.clone(),
            by_admin_id: ctx.admin_id.clone(),
            state: label.to_string(),
        });
        Ok(Response::new(SetAdminAccountStateResponse {
            row_version: u64::try_from(version).unwrap_or(0),
        }))
    }

    async fn reset_admin_credentials(
        &self,
        request: Request<ResetAdminCredentialsRequest>,
    ) -> Result<Response<ResetAdminCredentialsResponse>, Status> {
        let st = self.st();
        let ctx = require(&request, paths::RESET_ADMIN_CREDENTIALS)?;
        let mut req = request.into_inner();
        let target = self.target(&req.admin_id).await?;
        self.authz.check_sod(&ctx, &target.admin_id, None)?;
        if !req.reset_password && !req.reset_mfa {
            return Err(Status::invalid_argument("nothing_to_reset"));
        }
        if target.state == ACCOUNT_DISABLED {
            return Err(Status::failed_precondition("account_disabled"));
        }
        if !req.reset_mfa && target.totp_secret_enc.is_none() {
            // A password-only reset is completed with a TOTP code (proof of
            // the enrolled factor); a key-only account could never complete
            // it, so its reset must clear the second factor too.
            return Err(Status::failed_precondition("reset_mfa_required"));
        }
        st.verify_proof(&ctx, req.proof.take()).await?;
        let now = st.now();
        let (token, hash) = bootstrap::new_token(ENROLLMENT_PREFIX);
        let row = EnrollmentTokenRow {
            token_hash: hash,
            admin_id: Some(target.admin_id.clone()),
            purpose: TOKEN_RESET,
            created_by_admin_id: Some(ctx.admin_id.clone()),
            created_at: now,
            expires_at: now + ENROLLMENT_DEFAULT_TTL_SECS,
            used_at: None,
            pending_secret_enc: None,
        };
        st.cluster()
            .admin_reset_credentials(&target.admin_id, req.reset_password, req.reset_mfa, &row)
            .await
            .map_err(|e| st.store_error(&e))?;
        st.revoke_all_sessions(
            &target.admin_id,
            None,
            RevokeReason::CredentialsReset,
            Some(&ctx.admin_id),
        )
        .await?;
        tracing::info!(
            event = "admin.account.credentials_reset",
            admin_id = %target.admin_id,
            by_admin_id = %ctx.admin_id,
            "admin credentials reset"
        );
        st.audit(AuditEvent::AdminCredentialsReset {
            admin_id: target.admin_id.clone(),
            by_admin_id: ctx.admin_id.clone(),
            password: req.reset_password,
            mfa: req.reset_mfa,
        });
        Ok(Response::new(ResetAdminCredentialsResponse {
            enrollment_token: token.to_string(),
            expires_at: row.expires_at,
        }))
    }
}
