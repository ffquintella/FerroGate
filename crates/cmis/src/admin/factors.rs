//! Second factors (F20 §5–§7, §9, §13): which methods a session may use, the
//! server side of the WebAuthn ceremonies, per-operation proofs, and the
//! factor-management RPCs (`ListMyFactors`, `BeginAddFactor`,
//! `CompleteAddFactor`, `RemoveFactor`).
//!
//! **Policy.** TOTP works from every client; FIDO2 only from the tray admin
//! client (`ClientInfo.kind = 2`), the one client with local access to an
//! authenticator. For members of a `CMIS_ADMIN_TRAY_FIDO2_GROUPS` group on
//! the tray, login, step-up and proofs accept **only** a WebAuthn assertion;
//! such a member with no key yet signs in with TOTP to a session held to
//! factor enrollment (`factor_enrollment_required`). Client kind is declared
//! by the client, so the policy steers honest clients; it is not a boundary
//! against a client that lies about its kind (see the module report).
//!
//! **Challenges.** Stateless and single use, like the login and step-up
//! nonces they ride on: an assertion challenge is `HMAC(server key, purpose,
//! nonce)`, so it is bound to the login nonce (IP + username) or the
//! step-up nonce (session), and it dies with the nonce's single
//! redemption. Creation challenges are bound to the add-factor nonce
//! (session) or, for token enrollment, are themselves an enrollment nonce
//! bound to the token. Creation ceremonies live 10 minutes, assertions 2.
//!
//! **Clone detection.** After the signature verifies, the signature counter
//! must advance ([`super::webauthn::counter_advances`]), applied as a
//! compare-and-set in the replicated store so a concurrent replay on another
//! node also fails. A regression refuses the assertion and records
//! `AdminWebAuthnCloneDetected`.
//!
//! Credential material (keys, assertions, attestation objects, credential
//! ids) never reaches logs or audit events; factors are referenced by an
//! opaque `factor_id`.

use std::net::IpAddr;

use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::mfa_proof::F;
use ferro_proto::admin_v1::{
    BeginAddFactorRequest, BeginAddFactorResponse, CompleteAddFactorRequest,
    CompleteAddFactorResponse, FactorInfo, ListMyFactorsRequest, ListMyFactorsResponse, MfaProof,
    RemoveFactorRequest, RemoveFactorResponse, WebAuthnAssertion, WebAuthnAttestation,
    WebAuthnChallenge, WebAuthnCreationOptions,
};
use ferro_raft::admin::{AdminAccountRow, WebAuthnCredentialRow, MAX_WEBAUTHN_CREDENTIALS};
use ferro_raft::ClusterError;

use super::authz::{paths, require, AdminAuthz, AdminContext};
use super::config::AdminConfig;
use super::service::TOTP_ISSUER;
use super::session::{MfaMethod, RevokeReason, CLIENT_TRAY};
use super::state::{clean_display_name, AdminState, NONCE_LEN};
use super::totp;
use super::webauthn::{self, SUPPORTED_ALGORITHMS};

/// `factor_id` of an account's TOTP factor.
pub const FACTOR_TOTP: &str = "totp";
/// Prefix of a FIDO2 credential's `factor_id`.
pub const FACTOR_WEBAUTHN_PREFIX: &str = "wa_";
/// Lifetime of an assertion challenge, as sent to clients.
pub const ASSERTION_TIMEOUT_MS: i64 = 120_000;
/// Lifetime of a creation (registration) challenge.
pub const CREATION_TTL_SECS: i64 = 600;
/// Longest key label accepted, in characters after cleaning.
pub const MAX_LABEL_CHARS: usize = 64;
/// Relying-party name shown by authenticators.
pub const RP_NAME: &str = "FerroGate";
/// Label of a key registered without one.
pub const DEFAULT_KEY_LABEL: &str = "Security key";

/// Nonce label of `BeginAddFactor` / `CompleteAddFactor`.
const ADD_FACTOR_NONCE: &str = "addfactor-v1";
/// Nonce label of token-enrollment creation challenges.
const ENROLL_WEBAUTHN_NONCE: &str = "enroll-webauthn-v1";
/// Nonce label of `BeginStepUp` (also the challenge of inline proofs).
pub const STEP_UP_NONCE: &str = "stepup-v1";

/// What an assertion challenge is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePurpose {
    /// `BeginLogin` → `Login`.
    Login,
    /// `BeginStepUp` → `StepUp` or an inline `MfaProof`.
    StepUp,
    /// `BeginAddFactor` → `CompleteAddFactor` (creation).
    AddFactor,
}

impl ChallengePurpose {
    fn label(self) -> &'static str {
        match self {
            Self::Login => "webauthn-challenge-login-v1",
            Self::StepUp => "webauthn-challenge-stepup-v1",
            Self::AddFactor => "webauthn-challenge-addfactor-v1",
        }
    }
}

/// A successful second-factor verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// Method used.
    pub method: MfaMethod,
    /// Assurance level it reached.
    pub aal: i64,
}

impl Verified {
    /// A TOTP verification (AAL2).
    #[must_use]
    pub fn totp() -> Self {
        Self {
            method: MfaMethod::Totp,
            aal: MfaMethod::Totp.aal(),
        }
    }
}

/// Which second-factor methods a session may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorPolicy {
    /// TOTP is accepted.
    pub totp: bool,
    /// A WebAuthn assertion is accepted.
    pub webauthn: bool,
    /// The FIDO2 tray policy binds this session but the account holds no key
    /// yet: a TOTP session is held to factor enrollment.
    pub enrollment_required: bool,
}

/// Whether the tray FIDO2 policy binds a session of `client_kind` whose
/// account is in `groups` (F20 §5, `CMIS_ADMIN_TRAY_FIDO2_GROUPS`).
#[must_use]
pub fn fido2_required(config: &AdminConfig, client_kind: i64, groups: &[String]) -> bool {
    client_kind == CLIENT_TRAY
        && groups
            .iter()
            .any(|g| config.tray_fido2_groups.iter().any(|p| p == g))
}

/// The methods a session may use (F20 §5 and §6.1).
#[must_use]
pub fn factor_policy(
    config: &AdminConfig,
    client_kind: i64,
    groups: &[String],
    has_totp: bool,
    has_keys: bool,
) -> FactorPolicy {
    let bound = fido2_required(config, client_kind, groups);
    FactorPolicy {
        totp: has_totp && !(bound && has_keys),
        webauthn: client_kind == CLIENT_TRAY && has_keys,
        enrollment_required: bound && !has_keys,
    }
}

/// The opaque, stable `factor_id` of a credential: a short digest of its id,
/// so logs, audit events and clients never carry the credential id itself.
#[must_use]
pub fn factor_id(credential_id: &[u8]) -> String {
    format!(
        "{FACTOR_WEBAUTHN_PREFIX}{}",
        hex::encode(&Sha256::digest(credential_id)[..12])
    )
}

/// Clean a holder-chosen key label: NFKC, control and bidi characters
/// removed, at most [`MAX_LABEL_CHARS`]; empty becomes
/// [`DEFAULT_KEY_LABEL`].
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
pub fn clean_label(raw: &str) -> Result<String, Status> {
    let cleaned = clean_display_name(raw)
        .filter(|l| l.chars().count() <= MAX_LABEL_CHARS)
        .ok_or_else(|| Status::invalid_argument("invalid_label"))?;
    Ok(if cleaned.is_empty() {
        DEFAULT_KEY_LABEL.to_string()
    } else {
        cleaned
    })
}

fn invalid() -> Status {
    Status::unauthenticated("invalid_credentials")
}

fn add_factor_aad(nonce: &[u8]) -> String {
    format!("addfactor:{}", hex::encode(nonce))
}

impl AdminState {
    /// The account behind a session and its FIDO2 credentials.
    pub async fn factor_holdings(
        &self,
        admin_id: &str,
    ) -> Result<(AdminAccountRow, Vec<WebAuthnCredentialRow>), Status> {
        let account = self
            .cluster()
            .admin_account(admin_id)
            .await
            .map_err(|e| self.store_error(&e))?
            .ok_or_else(|| Status::unauthenticated("session_invalid"))?;
        let creds = self.webauthn_credentials(admin_id).await?;
        Ok((account, creds))
    }

    /// The FIDO2 credentials of `admin_id` (none for an empty id).
    pub async fn webauthn_credentials(
        &self,
        admin_id: &str,
    ) -> Result<Vec<WebAuthnCredentialRow>, Status> {
        self.cluster()
            .admin_webauthn_credentials(admin_id)
            .await
            .map_err(|e| self.store_error(&e))
    }

    /// The assertion or creation challenge bound to `nonce` for `purpose`.
    #[must_use]
    pub fn webauthn_challenge(&self, purpose: ChallengePurpose, nonce: &[u8]) -> Vec<u8> {
        self.keys().mac(purpose.label(), &[nonce]).to_vec()
    }

    /// The opaque WebAuthn user handle of an account (no personal data, not
    /// the `admin_id` used in audit events).
    #[must_use]
    pub fn webauthn_user_handle(&self, admin_id: &str) -> Vec<u8> {
        self.keys()
            .mac("webauthn-user-v1", &[admin_id.as_bytes()])
            .to_vec()
    }

    /// Decoy credential ids for a username with no usable account (F20 §6.1):
    /// one to three ids of 16, 32, 48 or 64 bytes (the common real lengths),
    /// stable per username and derived with the server key, so they cannot be
    /// told from real ones by count, length or content.
    #[must_use]
    pub fn decoy_credential_ids(&self, username_key: &str) -> Vec<Vec<u8>> {
        let seed = self
            .keys()
            .mac("webauthn-decoy-v1", &[username_key.as_bytes()]);
        let count = 1 + seed[0] % 3;
        let len = 16 * (1 + usize::from(seed[1] % 4));
        (0..count)
            .map(|i| {
                let mut id = self
                    .keys()
                    .mac("webauthn-decoy-id-v1", &[username_key.as_bytes(), &[i, 0]])
                    .to_vec();
                id.extend_from_slice(
                    &self
                        .keys()
                        .mac("webauthn-decoy-id-v1", &[username_key.as_bytes(), &[i, 1]]),
                );
                id.truncate(len);
                id
            })
            .collect()
    }

    /// The tray `BeginLogin` offer for a username with no usable account
    /// (F20 §6.1 "plausible response"): one of the shapes real accounts
    /// produce — TOTP only, both factors, or keys only — fixed per username
    /// so repeated queries agree, with decoy credential ids. A real account's
    /// offer is therefore not told apart from an unknown name's.
    #[must_use]
    pub fn decoy_offer(&self, username_key: &str) -> (Vec<u32>, Option<Vec<Vec<u8>>>) {
        let seed = self
            .keys()
            .mac("webauthn-decoy-shape-v1", &[username_key.as_bytes()]);
        match seed[0] % 4 {
            0 | 1 => (vec![1], None),
            2 => (vec![1, 2], Some(self.decoy_credential_ids(username_key))),
            _ => (vec![2], Some(self.decoy_credential_ids(username_key))),
        }
    }

    /// A request for an assertion over `challenge`.
    #[must_use]
    pub fn assertion_options(
        &self,
        challenge: Vec<u8>,
        allow_credential_ids: Vec<Vec<u8>>,
    ) -> WebAuthnChallenge {
        WebAuthnChallenge {
            challenge,
            rp_id: self.relying_party().rp_id().to_string(),
            allow_credential_ids,
            user_verification: 1,
            timeout_ms: ASSERTION_TIMEOUT_MS,
        }
    }

    /// A request for a new credential over `challenge` for `account`,
    /// excluding the keys it already holds.
    #[must_use]
    pub fn creation_options(
        &self,
        challenge: Vec<u8>,
        account: &AdminAccountRow,
        existing: &[WebAuthnCredentialRow],
    ) -> WebAuthnCreationOptions {
        WebAuthnCreationOptions {
            challenge,
            rp_id: self.relying_party().rp_id().to_string(),
            rp_name: RP_NAME.to_string(),
            user_id: self.webauthn_user_handle(&account.admin_id),
            user_name: account.username.clone(),
            display_name: account
                .display_name
                .clone()
                .unwrap_or_else(|| account.username.clone()),
            pub_key_cred_params: SUPPORTED_ALGORITHMS
                .iter()
                .filter_map(|a| i32::try_from(*a).ok())
                .collect(),
            exclude_credential_ids: existing.iter().map(|c| c.credential_id.clone()).collect(),
            user_verification: 1,
            attestation: 1,
        }
    }

    /// A creation challenge for token enrollment: itself a single-use
    /// enrollment nonce bound to the token (`BeginEnrollment` has no nonce
    /// field of its own).
    #[must_use]
    pub fn enrollment_creation_challenge(&self, token_hash: &[u8]) -> Vec<u8> {
        self.issue_nonce(ENROLL_WEBAUTHN_NONCE, &[token_hash])
    }

    /// Verify an attestation made during token enrollment: its challenge
    /// must be a live enrollment challenge of this token. The challenge is
    /// redeemed only once the ceremony verifies, so a refused registration
    /// can be retried on the same offer (whose TOTP seed the person may
    /// already have scanned); a verified one cannot be replayed.
    #[must_use]
    pub fn check_enrollment_attestation(
        &self,
        token_hash: &[u8],
        admin_id: &str,
        att: &WebAuthnAttestation,
        label: String,
    ) -> Option<WebAuthnCredentialRow> {
        let challenge = webauthn::client_data_challenge(&att.client_data_json)?;
        let row = self.check_attestation(admin_id, att, &challenge, label)?;
        self.redeem_nonce_within(
            ENROLL_WEBAUTHN_NONCE,
            &challenge,
            &[token_hash],
            CREATION_TTL_SECS,
        )
        .then_some(row)
    }

    /// Verify a registration response against `challenge`; the credential
    /// row to store, or `None` (logged with a reason, never the material).
    #[must_use]
    pub fn check_attestation(
        &self,
        admin_id: &str,
        att: &WebAuthnAttestation,
        challenge: &[u8],
        label: String,
    ) -> Option<WebAuthnCredentialRow> {
        match self.relying_party().verify_registration(
            challenge,
            &att.credential_id,
            &att.attestation_object,
            &att.client_data_json,
        ) {
            Ok(c) => Some(WebAuthnCredentialRow {
                credential_id: c.credential_id,
                admin_id: admin_id.to_string(),
                cose_public_key: c.cose_public_key,
                sign_count: i64::from(c.sign_count),
                aaguid: Some(c.aaguid.to_vec()),
                label: Some(label),
                created_at: self.now(),
                last_used_at: None,
            }),
            Err(e) => {
                tracing::info!(
                    event = "admin.webauthn.registration_rejected",
                    admin_id,
                    reason = e.label(),
                    "WebAuthn registration refused"
                );
                None
            }
        }
    }

    /// Verify a WebAuthn assertion by `account` over `challenge`: one of the
    /// account's credentials `creds` (already loaded by the caller, so a
    /// correct password does not cost an extra store read that a wrong one
    /// does not), the user handle, the ceremony
    /// ([`webauthn::RelyingParty::verify_assertion`]) and the signature
    /// counter (compare-and-set; a regression is audited as a possible
    /// clone). `None` on any refusal.
    pub async fn check_assertion(
        &self,
        account: &AdminAccountRow,
        creds: &[WebAuthnCredentialRow],
        assertion: &WebAuthnAssertion,
        challenge: &[u8],
        ip: Option<IpAddr>,
    ) -> Result<Option<Verified>, Status> {
        let reject = |reason: &str| {
            tracing::info!(
                event = "admin.webauthn.assertion_rejected",
                admin_id = %account.admin_id,
                reason,
                "WebAuthn assertion refused"
            );
            Ok(None)
        };
        if assertion.credential_id.is_empty()
            || assertion.credential_id.len() > webauthn::MAX_CREDENTIAL_ID_LEN
            || assertion.user_handle.len() > webauthn::MAX_USER_HANDLE_LEN
        {
            return reject("too_large");
        }
        let Some(cred) = creds
            .iter()
            .find(|c| c.admin_id == account.admin_id && c.credential_id == assertion.credential_id)
        else {
            return reject("unknown_credential");
        };
        if !assertion.user_handle.is_empty()
            && assertion.user_handle != self.webauthn_user_handle(&account.admin_id)
        {
            return reject("user_handle");
        }
        let ok = match self.relying_party().verify_assertion(
            challenge,
            &cred.cose_public_key,
            &assertion.authenticator_data,
            &assertion.client_data_json,
            &assertion.signature,
        ) {
            Ok(ok) => ok,
            Err(e) => return reject(e.label()),
        };
        let advanced = webauthn::counter_advances(cred.sign_count, ok.sign_count)
            && self
                .cluster()
                .admin_webauthn_used(
                    &account.admin_id,
                    &cred.credential_id,
                    i64::from(ok.sign_count),
                    self.now(),
                )
                .await
                .map_err(|e| self.store_error(&e))?;
        if !advanced {
            let fid = factor_id(&cred.credential_id);
            tracing::warn!(
                event = "admin.webauthn.clone_detected",
                admin_id = %account.admin_id,
                factor_id = %fid,
                "WebAuthn signature counter did not advance; possible cloned authenticator"
            );
            self.audit(AuditEvent::AdminWebAuthnCloneDetected {
                admin_id: account.admin_id.clone(),
                factor_id: fid.clone(),
            });
            self.security_log(
                "webauthn.clone_detected",
                Some(&account.admin_id),
                None,
                ip,
                Some(&fid),
            )
            .await;
            return Ok(None);
        }
        Ok(Some(Verified {
            method: MfaMethod::WebAuthn,
            aal: webauthn::aal(ok.backup_eligible),
        }))
    }

    /// Re-verify the second factor of a session: `StepUp` (with its already
    /// redeemed `stepup_nonce`) or an inline `MfaProof` (whose WebAuthn
    /// assertion must sign the challenge of a `BeginStepUp` nonce carried in
    /// `proof.nonce`, redeemed here). The method must be allowed by the
    /// session's policy. Wrong proofs count toward the step-up failure limit;
    /// a call carrying no proof at all is refused without counting.
    pub async fn verify_factor(
        &self,
        ctx: &AdminContext,
        proof: Option<MfaProof>,
        stepup_nonce: Option<&[u8]>,
    ) -> Result<Verified, Status> {
        if proof.as_ref().is_none_or(|p| p.f.is_none()) {
            return Err(invalid());
        }
        let (account, creds) = self.factor_holdings(&ctx.admin_id).await?;
        let policy = factor_policy(
            self.config(),
            ctx.client_kind,
            &ctx.groups,
            account.totp_secret_enc.is_some(),
            !creds.is_empty(),
        );
        let (f, proof_nonce) = proof.map_or((None, Vec::new()), |p| (p.f, p.nonce));
        let verified = match f {
            Some(F::TotpCode(code)) if policy.totp => {
                let code = Zeroizing::new(code);
                self.check_totp(&account, &code).await?.then(Verified::totp)
            }
            Some(F::WebauthnAssertion(a)) if policy.webauthn => {
                let nonce = match stepup_nonce {
                    Some(n) => Some(n.to_vec()),
                    None => self
                        .redeem_nonce(STEP_UP_NONCE, &proof_nonce, &[&ctx.session_hash])
                        .then_some(proof_nonce),
                };
                match nonce {
                    Some(n) => {
                        let challenge = self.webauthn_challenge(ChallengePurpose::StepUp, &n);
                        self.check_assertion(&account, &creds, &a, &challenge, ctx.source_ip)
                            .await?
                    }
                    None => None,
                }
            }
            _ => None,
        };
        if let Some(v) = verified {
            return Ok(v);
        }
        self.second_factor_failed(ctx).await;
        Err(invalid())
    }
}

/// `ListMyFactors`: the caller's TOTP factor and FIDO2 credentials.
pub async fn list_my_factors(
    authz: &AdminAuthz,
    request: Request<ListMyFactorsRequest>,
) -> Result<Response<ListMyFactorsResponse>, Status> {
    let st = authz.state();
    let ctx = require(&request, paths::LIST_MY_FACTORS)?;
    let (account, creds) = st.factor_holdings(&ctx.admin_id).await?;
    let mut factors = Vec::with_capacity(creds.len() + 1);
    if account.totp_secret_enc.is_some() {
        factors.push(FactorInfo {
            factor_id: FACTOR_TOTP.to_string(),
            method: 1,
            label: "TOTP authenticator".to_string(),
            created_at: 0,
            last_used_at: account.last_login_at.unwrap_or(0),
        });
    }
    factors.extend(creds.into_iter().map(|c| FactorInfo {
        factor_id: factor_id(&c.credential_id),
        method: 2,
        label: c.label.unwrap_or_default(),
        created_at: c.created_at,
        last_used_at: c.last_used_at.unwrap_or(0),
    }));
    Ok(Response::new(ListMyFactorsResponse { factors }))
}

/// `BeginAddFactor` (recent step-up required): a TOTP seed sealed into the
/// enroll nonce, or WebAuthn creation options (tray only).
pub async fn begin_add_factor(
    authz: &AdminAuthz,
    request: Request<BeginAddFactorRequest>,
) -> Result<Response<BeginAddFactorResponse>, Status> {
    let st = authz.state();
    let ctx = require(&request, paths::BEGIN_ADD_FACTOR)?;
    authz.require_step_up(&ctx)?;
    let (account, creds) = st.factor_holdings(&ctx.admin_id).await?;
    match request.get_ref().method {
        1 => {
            if account.totp_secret_enc.is_some() {
                return Err(Status::already_exists("factor_exists"));
            }
            let mut enroll_nonce = st.issue_nonce(ADD_FACTOR_NONCE, &[&ctx.session_hash, b"totp"]);
            let secret = totp::generate_secret();
            let sealed = st
                .keys()
                .seal_totp(&add_factor_aad(&enroll_nonce), secret.as_ref())
                .map_err(|e| {
                    tracing::error!(error = %e, "TOTP sealing failed");
                    Status::internal("internal_error")
                })?;
            let uri = totp::provisioning_uri(secret.as_ref(), TOTP_ISSUER, &account.username);
            enroll_nonce.extend_from_slice(&sealed);
            Ok(Response::new(BeginAddFactorResponse {
                enroll_nonce,
                totp_provisioning_uri: uri,
                webauthn_creation_options: None,
            }))
        }
        2 => {
            if ctx.client_kind != CLIENT_TRAY {
                return Err(Status::failed_precondition("method_not_available"));
            }
            if i64::try_from(creds.len()).unwrap_or(i64::MAX) >= MAX_WEBAUTHN_CREDENTIALS {
                return Err(Status::failed_precondition("factor_limit"));
            }
            let enroll_nonce = st.issue_nonce(ADD_FACTOR_NONCE, &[&ctx.session_hash, b"webauthn"]);
            let challenge = st.webauthn_challenge(ChallengePurpose::AddFactor, &enroll_nonce);
            let options = st.creation_options(challenge, &account, &creds);
            Ok(Response::new(BeginAddFactorResponse {
                enroll_nonce,
                totp_provisioning_uri: String::new(),
                webauthn_creation_options: Some(options),
            }))
        }
        _ => Err(Status::invalid_argument("invalid_method")),
    }
}

/// `CompleteAddFactor` (per-operation proof of an existing factor): store
/// the new TOTP secret or FIDO2 credential and audit `AdminMfaEnrolled`.
#[allow(clippy::too_many_lines)] // one ordered flow.
pub async fn complete_add_factor(
    authz: &AdminAuthz,
    request: Request<CompleteAddFactorRequest>,
) -> Result<Response<CompleteAddFactorResponse>, Status> {
    let st = authz.state();
    let ctx = require(&request, paths::COMPLETE_ADD_FACTOR)?;
    let mut req = request.into_inner();
    let code = Zeroizing::new(std::mem::take(&mut req.totp_code));
    if req.idempotency_key.len() > 128 || req.label.len() > 1024 || code.len() > 16 {
        return Err(Status::invalid_argument("request_too_large"));
    }
    let method = match (&req.webauthn_attestation, code.is_empty()) {
        (Some(_), true) => MfaMethod::WebAuthn,
        (None, false) => MfaMethod::Totp,
        _ => return Err(Status::invalid_argument("one_factor_required")),
    };
    let tag: &[u8] = match method {
        MfaMethod::Totp => b"totp",
        MfaMethod::WebAuthn => b"webauthn",
    };
    if req.enroll_nonce.len() < NONCE_LEN {
        return Err(invalid());
    }
    let (nonce, sealed) = req.enroll_nonce.split_at(NONCE_LEN);
    if !st.redeem_nonce_within(
        ADD_FACTOR_NONCE,
        nonce,
        &[&ctx.session_hash, tag],
        CREATION_TTL_SECS,
    ) {
        return Err(invalid());
    }
    // F20 §7 "M": proof of a factor the account already holds.
    st.verify_proof(&ctx, req.proof.take()).await?;

    let factor = match method {
        MfaMethod::Totp => {
            let Ok(secret) = st.keys().open_totp(&add_factor_aad(nonce), sealed) else {
                return Err(invalid());
            };
            let Some(step) = totp::verify(&secret, &code, st.now(), None) else {
                return Err(invalid());
            };
            let stored = st.keys().seal_totp(&ctx.admin_id, &secret).map_err(|e| {
                tracing::error!(error = %e, "TOTP sealing failed");
                Status::internal("internal_error")
            })?;
            if !st
                .cluster()
                .admin_add_totp(&ctx.admin_id, &stored, step)
                .await
                .map_err(|e| st.store_error(&e))?
            {
                return Err(Status::already_exists("factor_exists"));
            }
            FACTOR_TOTP.to_string()
        }
        MfaMethod::WebAuthn => {
            if ctx.client_kind != CLIENT_TRAY {
                return Err(Status::failed_precondition("method_not_available"));
            }
            let att = req.webauthn_attestation.as_ref().ok_or_else(invalid)?;
            let raw_label = if req.label.trim().is_empty() {
                att.label.as_str()
            } else {
                req.label.as_str()
            };
            let label = clean_label(raw_label)?;
            let challenge = st.webauthn_challenge(ChallengePurpose::AddFactor, nonce);
            let Some(row) = st.check_attestation(&ctx.admin_id, att, &challenge, label) else {
                return Err(invalid());
            };
            match st.cluster().admin_add_webauthn_credential(&row).await {
                Ok(true) => {}
                Ok(false) => return Err(Status::failed_precondition("factor_limit")),
                Err(ClusterError::Conflict(_)) => {
                    return Err(Status::already_exists("factor_exists"))
                }
                Err(e) => return Err(st.store_error(&e)),
            }
            factor_id(&row.credential_id)
        }
    };
    tracing::info!(
        event = "admin.mfa.enrolled",
        admin_id = %ctx.admin_id,
        method = method.label(),
        factor_id = %factor,
        "second factor added"
    );
    st.audit(AuditEvent::AdminMfaEnrolled {
        admin_id: ctx.admin_id.clone(),
        method: method.label().to_string(),
    });
    st.security_log(
        "mfa.enrolled",
        Some(&ctx.admin_id),
        None,
        ctx.source_ip,
        Some(&factor),
    )
    .await;
    Ok(Response::new(CompleteAddFactorResponse {
        factor_id: factor,
    }))
}

/// `RemoveFactor` (per-operation proof): never the last factor; the other
/// sessions of the account end (one of them may hold the removed factor).
pub async fn remove_factor(
    authz: &AdminAuthz,
    request: Request<RemoveFactorRequest>,
) -> Result<Response<RemoveFactorResponse>, Status> {
    let st = authz.state();
    let ctx = require(&request, paths::REMOVE_FACTOR)?;
    let mut req = request.into_inner();
    if req.idempotency_key.len() > 128 || req.factor_id.len() > 64 {
        return Err(Status::invalid_argument("request_too_large"));
    }
    let (account, creds) = st.factor_holdings(&ctx.admin_id).await?;
    let key = creds
        .iter()
        .find(|c| factor_id(&c.credential_id) == req.factor_id)
        .map(|c| c.credential_id.clone());
    let method = if req.factor_id == FACTOR_TOTP && account.totp_secret_enc.is_some() {
        MfaMethod::Totp
    } else if key.is_some() {
        MfaMethod::WebAuthn
    } else {
        return Err(Status::not_found("factor_not_found"));
    };
    let held = usize::from(account.totp_secret_enc.is_some()) + creds.len();
    if held <= 1 {
        return Err(Status::failed_precondition("last_factor"));
    }
    // F20 §7 "M".
    st.verify_proof(&ctx, req.proof.take()).await?;
    // The store re-checks "another factor remains" inside the write, so
    // concurrent removals cannot leave the account without one.
    let removed = match &key {
        Some(id) if method == MfaMethod::WebAuthn => {
            st.cluster()
                .admin_remove_webauthn_credential(&ctx.admin_id, id)
                .await
        }
        _ => st.cluster().admin_remove_totp(&ctx.admin_id).await,
    }
    .map_err(|e| st.store_error(&e))?;
    if !removed {
        return Err(Status::failed_precondition("last_factor"));
    }
    st.revoke_all_sessions(
        &ctx.admin_id,
        Some(&ctx.session_hash),
        RevokeReason::FactorRemoved,
        Some(&ctx.admin_id),
    )
    .await?;
    tracing::info!(
        event = "admin.mfa.removed",
        admin_id = %ctx.admin_id,
        method = method.label(),
        factor_id = %req.factor_id,
        "second factor removed"
    );
    st.audit(AuditEvent::AdminMfaRemoved {
        admin_id: ctx.admin_id.clone(),
        method: method.label().to_string(),
        by_admin_id: None,
    });
    st.security_log(
        "mfa.removed",
        Some(&ctx.admin_id),
        None,
        ctx.source_ip,
        Some(&req.factor_id),
    )
    .await;
    Ok(Response::new(RemoveFactorResponse {}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(groups: &[&str]) -> AdminConfig {
        AdminConfig {
            tray_fido2_groups: groups.iter().map(|g| (*g).to_string()).collect(),
            ..AdminConfig::default()
        }
    }

    fn g(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn webauthn_is_a_tray_method_only() {
        let c = cfg(&[]);
        for kind in [0, 1, 3] {
            let p = factor_policy(&c, kind, &g(&["ferrogate-viewers"]), true, true);
            assert!(p.totp && !p.webauthn, "kind {kind}");
        }
        let p = factor_policy(&c, CLIENT_TRAY, &g(&["ferrogate-viewers"]), true, true);
        assert!(p.totp && p.webauthn && !p.enrollment_required);
        let p = factor_policy(&c, CLIENT_TRAY, &g(&["ferrogate-viewers"]), false, true);
        assert!(!p.totp && p.webauthn);
    }

    #[test]
    fn the_tray_policy_binds_listed_groups_on_the_tray_only() {
        let c = cfg(&["ferrogate-approvers"]);
        let approver = g(&["ferrogate-approvers", "ferrogate-viewers"]);
        // With a key: the tray accepts only the key.
        let p = factor_policy(&c, CLIENT_TRAY, &approver, true, true);
        assert_eq!(
            p,
            FactorPolicy {
                totp: false,
                webauthn: true,
                enrollment_required: false
            }
        );
        // Without a key: TOTP, held to enrollment.
        let p = factor_policy(&c, CLIENT_TRAY, &approver, true, false);
        assert_eq!(
            p,
            FactorPolicy {
                totp: true,
                webauthn: false,
                enrollment_required: true
            }
        );
        // TUI and CLI keep TOTP.
        for kind in [1, 3] {
            let p = factor_policy(&c, kind, &approver, true, true);
            assert!(p.totp && !p.enrollment_required);
            assert!(!fido2_required(&c, kind, &approver));
        }
        // Other groups are not bound.
        assert!(!fido2_required(&c, CLIENT_TRAY, &g(&["ferrogate-viewers"])));
    }

    #[test]
    fn factor_ids_are_opaque_and_stable() {
        let a = factor_id(&[1; 64]);
        assert_eq!(a, factor_id(&[1; 64]));
        assert_ne!(a, factor_id(&[2; 64]));
        assert!(a.starts_with(FACTOR_WEBAUTHN_PREFIX) && a.len() == 3 + 24);
        assert!(!a.contains(&hex::encode([1u8; 8])));
    }

    #[test]
    fn labels_are_cleaned_and_bounded() {
        assert_eq!(clean_label(" Yubi\u{202E}Key\u{7} ").unwrap(), "YubiKey");
        assert_eq!(clean_label("").unwrap(), DEFAULT_KEY_LABEL);
        assert_eq!(clean_label(&"k".repeat(64)).unwrap().len(), 64);
        assert!(clean_label(&"k".repeat(65)).is_err());
    }
}
