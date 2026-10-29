//! Second-factor management from a signed-in session (F20 §5, F22 §3a):
//! `ListMyFactors`, adding a TOTP seed or a security key
//! (`BeginAddFactor`, which needs a recent step-up, then
//! `CompleteAddFactor`), and `RemoveFactor`. Adding and removing carry a
//! per-operation proof of a factor the account already holds.

//! A key proof signs the challenge of a fresh `BeginStepUp` nonce. When the
//! session ends while a key is touched, nothing more is sent.

use std::sync::Arc;

use ferro_proto::admin_v1::{
    mfa_proof, BeginAddFactorRequest, BeginStepUpRequest, CompleteAddFactorRequest,
    ListMyFactorsRequest, MfaProof, RemoveFactorRequest, WebAuthnAttestation,
};
use serde::Serialize;

use crate::client::{ask_key, authenticated_error, AdminSession, Factor};
use crate::error::{ClientError, RpcError};
use crate::secret::Secret;
use crate::totp::TotpSeed;
use crate::transport::within;
use crate::webauthn::{
    attestation_into_proto, clean_label, creation_request, Authenticator, AuthenticatorError,
    CreationRequest, MAX_LABEL_CHARS,
};

/// Most factors read from one `ListMyFactors` (an account holds at most
/// one TOTP factor and eight keys).
pub const MAX_FACTORS: usize = 16;
/// Longest factor id accepted, in bytes.
pub const MAX_FACTOR_ID_LEN: usize = 64;

/// A kind of second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorMethod {
    /// An authenticator app (TOTP).
    Totp,
    /// A FIDO2 security key or platform authenticator.
    SecurityKey,
}

impl FactorMethod {
    /// The `admin.proto` method code.
    #[must_use]
    pub fn code(self) -> u32 {
        match self {
            Self::Totp => 1,
            Self::SecurityKey => 2,
        }
    }

    fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::Totp),
            2 => Some(Self::SecurityKey),
            _ => None,
        }
    }
}

/// One factor of the signed-in account. `label` is untrusted text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactorInfo {
    /// Opaque id (`totp`, or `wa_…` for a key), checked by [`valid_factor_id`].
    pub factor_id: String,
    /// What it is.
    pub method: FactorMethod,
    /// The holder's label, at most [`MAX_LABEL_CHARS`] characters.
    pub label: String,
    /// When it was added (Unix seconds; 0 when unknown).
    pub created_at: i64,
    /// When it was last used (Unix seconds; 0 when never or unknown).
    pub last_used_at: i64,
}

/// Whether `id` looks like a factor id CMIS issues: short, letters, digits,
/// `_` and `-` only. Others are never sent back.
#[must_use]
pub fn valid_factor_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_FACTOR_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The single-use nonce of one add-factor ceremony: bound to this session,
/// alive 10 minutes, sealing the offered TOTP seed. Opaque to front ends.
pub struct AddNonce(Vec<u8>);

static_assertions::assert_not_impl_any!(AddNonce: std::fmt::Debug, std::fmt::Display, Clone);

impl AddNonce {
    /// Wrap nonce bytes (front-end tests build replies with it; CMIS checks
    /// every nonce it gets back).
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// What `BeginAddFactor` offers.
pub enum AddOffer {
    /// A fresh TOTP seed to scan (shown once).
    Totp(TotpSeed),
    /// The request for a new security-key credential.
    SecurityKey(Box<CreationRequest>),
}

/// A reply the server should never send (a missing or malformed field).
fn malformed() -> ClientError {
    ClientError::Other(RpcError::local(
        tonic::Code::Internal,
        "malformed server reply",
    ))
}

/// Register a new credential on `key` for `request`, off the async threads
/// (the operating system's prompt blocks), and check the answer.
///
/// # Errors
/// [`ClientError::Authenticator`]: a request that no longer holds together
/// ([`CreationRequest::is_consistent`]), a cancelled or failed prompt.
pub async fn register_key(
    key: Arc<dyn Authenticator>,
    request: &CreationRequest,
    label: &str,
) -> Result<WebAuthnAttestation, ClientError> {
    if !request.is_consistent() {
        return Err(ClientError::Authenticator(AuthenticatorError::BadRequest));
    }
    let asked = request.clone();
    let answer = tokio::task::spawn_blocking(move || key.make_credential(&asked))
        .await
        .map_err(|_| {
            ClientError::Authenticator(AuthenticatorError::Failed("prompt aborted".into()))
        })?
        .map_err(ClientError::Authenticator)?;
    attestation_into_proto(request, answer, label).map_err(ClientError::Authenticator)
}

impl AdminSession {
    /// The session's epoch now, or [`ClientError::SessionEnded`].
    pub(crate) fn require_session(&self) -> Result<u64, ClientError> {
        if self.has_session() {
            Ok(self.slot().epoch())
        } else {
            Err(ClientError::SessionEnded)
        }
    }

    /// The session ended since `epoch` (a lock while a key was touched).
    pub(crate) fn still(&self, epoch: u64) -> Result<(), ClientError> {
        if self.slot().epoch() == epoch {
            Ok(())
        } else {
            Err(ClientError::SessionEnded)
        }
    }

    /// `ListMyFactors`: the account's factors, at most [`MAX_FACTORS`];
    /// entries with an unknown method or a malformed id are left out.
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn list_factors(&mut self) -> Result<Vec<FactorInfo>, ClientError> {
        self.require_session()?;
        let r = self.list_factors_inner().await;
        self.finish(r)
    }

    async fn list_factors_inner(&mut self) -> Result<Vec<FactorInfo>, ClientError> {
        let timeout = self.config().rpc_timeout;
        let mut admin = self.admin().await.map_err(ClientError::Connect)?;
        let resp = within(timeout, admin.list_my_factors(ListMyFactorsRequest {}))
            .await
            .map(tonic::Response::into_inner)
            .map_err(|s| authenticated_error(&s))?;
        Ok(resp
            .factors
            .into_iter()
            .filter_map(|f| {
                let method = FactorMethod::from_code(f.method)?;
                valid_factor_id(&f.factor_id).then(|| FactorInfo {
                    factor_id: f.factor_id,
                    method,
                    label: f.label.chars().take(MAX_LABEL_CHARS).collect(),
                    created_at: f.created_at,
                    last_used_at: f.last_used_at,
                })
            })
            .take(MAX_FACTORS)
            .collect())
    }

    /// `BeginAddFactor`: a TOTP seed or a key-creation request, with the
    /// ceremony's nonce. Carries no secret.
    ///
    /// # Errors
    /// [`ClientError::needs_step_up`] when the last second factor is too
    /// old; [`ClientError::Authenticator`] for creation options outside the
    /// client's bounds; [`ClientError::SessionEnded`]; another error.
    pub async fn begin_add_factor(
        &mut self,
        method: FactorMethod,
    ) -> Result<(AddNonce, AddOffer), ClientError> {
        self.require_session()?;
        let r = self.begin_add_inner(method).await;
        self.finish(r)
    }

    async fn begin_add_inner(
        &mut self,
        method: FactorMethod,
    ) -> Result<(AddNonce, AddOffer), ClientError> {
        let timeout = self.config().rpc_timeout;
        let mut admin = self.admin().await.map_err(ClientError::Connect)?;
        let mut resp = within(
            timeout,
            admin.begin_add_factor(BeginAddFactorRequest {
                method: method.code(),
            }),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|s| authenticated_error(&s))?;
        if resp.enroll_nonce.is_empty() || resp.enroll_nonce.len() > 4096 {
            return Err(malformed());
        }
        let offer = match method {
            FactorMethod::Totp => AddOffer::Totp(
                TotpSeed::from_uri(std::mem::take(&mut resp.totp_provisioning_uri))
                    .ok_or_else(malformed)?,
            ),
            FactorMethod::SecurityKey => {
                let options = resp
                    .webauthn_creation_options
                    .as_ref()
                    .ok_or_else(malformed)?;
                AddOffer::SecurityKey(Box::new(
                    creation_request(options).map_err(ClientError::Authenticator)?,
                ))
            }
        };
        Ok((AddNonce(resp.enroll_nonce), offer))
    }

    /// `CompleteAddFactor` for a TOTP seed: `code` from the new
    /// authenticator, and `proof` of a factor already held. The code and a
    /// typed proof are wiped when this returns.
    ///
    /// # Errors
    /// [`ClientError::Rejected`] for a wrong code, proof or spent nonce
    /// (start again); otherwise as [`AdminSession::begin_add_factor`].
    pub async fn complete_add_totp(
        &mut self,
        nonce: AddNonce,
        code: Secret,
        proof: Factor,
    ) -> Result<String, ClientError> {
        let epoch = self.require_session()?;
        let r = self
            .complete_add(epoch, nonce, Some(code), None, proof)
            .await;
        self.finish(r)
    }

    /// `CompleteAddFactor` for a security key: `key` creates the credential
    /// for `request` (labelled `label`), then `proof` of a factor already
    /// held is taken. A lock during either prompt sends nothing.
    ///
    /// # Errors
    /// As [`AdminSession::complete_add_totp`], plus [`register_key`]'s.
    pub async fn complete_add_key(
        &mut self,
        nonce: AddNonce,
        request: &CreationRequest,
        key: Arc<dyn Authenticator>,
        label: &str,
        proof: Factor,
    ) -> Result<String, ClientError> {
        let epoch = self.require_session()?;
        let r = async {
            let attestation = register_key(key, request, label).await?;
            self.still(epoch)?;
            self.complete_add(epoch, nonce, None, Some(attestation), proof)
                .await
        }
        .await;
        self.finish(r)
    }

    async fn complete_add(
        &mut self,
        epoch: u64,
        nonce: AddNonce,
        code: Option<Secret>,
        attestation: Option<WebAuthnAttestation>,
        proof: Factor,
    ) -> Result<String, ClientError> {
        let proof = self.proof(epoch, proof).await?;
        let timeout = self.config().rpc_timeout;
        let mut admin = self.admin().await.map_err(ClientError::Connect)?;
        let label = attestation
            .as_ref()
            .map(|a| clean_label(&a.label))
            .unwrap_or_default();
        let result = within(
            timeout,
            admin.complete_add_factor(CompleteAddFactorRequest {
                idempotency_key: String::new(),
                enroll_nonce: nonce.0,
                label,
                totp_code: code
                    .as_ref()
                    .map(|c| c.expose().to_string())
                    .unwrap_or_default(),
                webauthn_attestation: attestation,
                proof: Some(proof),
            }),
        )
        .await;
        drop(code);
        result
            .map(|r| r.into_inner().factor_id)
            .map_err(|s| ClientError::from_credential_status(&s))
    }

    /// `RemoveFactor` with `proof` of a factor the account keeps. The server
    /// refuses to remove the last one and ends the account's other sessions.
    ///
    /// # Errors
    /// A malformed `factor_id` is refused here (nothing sent); otherwise as
    /// [`AdminSession::complete_add_totp`].
    pub async fn remove_factor(
        &mut self,
        factor_id: &str,
        proof: Factor,
    ) -> Result<(), ClientError> {
        if !valid_factor_id(factor_id) {
            return Err(ClientError::Other(RpcError::local(
                tonic::Code::InvalidArgument,
                "invalid factor id",
            )));
        }
        let epoch = self.require_session()?;
        let r = async {
            let proof = self.proof(epoch, proof).await?;
            let timeout = self.config().rpc_timeout;
            let mut admin = self.admin().await.map_err(ClientError::Connect)?;
            within(
                timeout,
                admin.remove_factor(RemoveFactorRequest {
                    idempotency_key: String::new(),
                    factor_id: factor_id.to_string(),
                    proof: Some(proof),
                }),
            )
            .await
            .map(|_| ())
            .map_err(|s| ClientError::from_credential_status(&s))
        }
        .await;
        self.finish(r)
    }

    /// A per-operation proof (F20 §7 "M"): a TOTP code, or a key's assertion
    /// over the challenge of a fresh `BeginStepUp` nonce. Nothing is
    /// returned when the session ended (since `epoch`) during the prompt.
    pub(crate) async fn proof(
        &mut self,
        epoch: u64,
        factor: Factor,
    ) -> Result<MfaProof, ClientError> {
        match factor {
            Factor::Totp(code) => Ok(MfaProof {
                f: Some(mfa_proof::F::TotpCode(code.expose().to_string())),
                nonce: Vec::new(),
            }),
            Factor::SecurityKey(key) => {
                let timeout = self.config().rpc_timeout;
                let mut admin = self.admin().await.map_err(ClientError::Connect)?;
                let begin = within(timeout, admin.begin_step_up(BeginStepUpRequest {}))
                    .await
                    .map(tonic::Response::into_inner)
                    .map_err(|s| authenticated_error(&s))?;
                let challenge = begin
                    .webauthn
                    .as_ref()
                    .ok_or(ClientError::FactorNotOffered)?;
                let assertion = ask_key(key, challenge).await?;
                self.still(epoch)?;
                Ok(MfaProof {
                    f: Some(mfa_proof::F::WebauthnAssertion(assertion)),
                    nonce: begin.stepup_nonce,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_ids_are_short_and_plain() {
        assert!(valid_factor_id("totp"));
        assert!(valid_factor_id("wa_0123456789abcdef01234567"));
        for bad in ["", "../totp", "wa_\u{1b}", "a b", &"a".repeat(65)] {
            assert!(!valid_factor_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn method_codes_match_the_proto() {
        assert_eq!(FactorMethod::Totp.code(), 1);
        assert_eq!(FactorMethod::SecurityKey.code(), 2);
        assert_eq!(FactorMethod::from_code(2), Some(FactorMethod::SecurityKey));
        assert_eq!(FactorMethod::from_code(9), None);
    }
}
