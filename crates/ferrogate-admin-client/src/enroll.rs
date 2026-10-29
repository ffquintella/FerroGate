//! Token enrollment (F20 §9, F22 §3a): redeem a single-use enrollment or
//! reset token without a session. `BeginEnrollment` offers a TOTP seed
//! and/or security-key creation options; `CompleteEnrollment` sends the new
//! password and the proof of each factor (at least one when offered).

//! The token travels only in these two requests and is never held here; the
//! calls carry no session token, whatever the slot holds.

use ferro_proto::admin_v1::admin_client::AdminClient;
use ferro_proto::admin_v1::{
    BeginEnrollmentRequest, CompleteEnrollmentRequest, WebAuthnAttestation,
};

use crate::client::AdminSession;
use crate::error::{ClientError, RpcError};
use crate::secret::Secret;
use crate::totp::TotpSeed;
use crate::transport::within;
use crate::webauthn::{creation_request, CreationRequest};

/// Bounds applied to the server's minimum password length (F20 §4: 24).
pub const PASSWORD_MIN_LEN_BOUNDS: (u32, u32) = (12, 256);

/// What `BeginEnrollment` offers. `username` and `display_name` are
/// untrusted text.
pub struct EnrollmentOffer {
    /// The account's user name (empty for the bootstrap token).
    pub username: String,
    /// The bootstrap token lets the first operator choose a user name.
    pub username_choosable: bool,
    /// The account's display name.
    pub display_name: String,
    /// The shortest password the policy accepts, within
    /// [`PASSWORD_MIN_LEN_BOUNDS`].
    pub password_min_len: u32,
    /// A fresh TOTP seed, when the token enrolls second factors.
    pub totp: Option<TotpSeed>,
    /// A key-creation request, when the token enrolls second factors for an
    /// existing account.
    pub key: Option<CreationRequest>,
}

static_assertions::assert_not_impl_any!(EnrollmentOffer: std::fmt::Debug, std::fmt::Display, Clone);

impl EnrollmentOffer {
    /// Whether the token enrolls second factors (otherwise it is a
    /// password-only reset, proven with the current TOTP code).
    #[must_use]
    pub fn enrolls_factors(&self) -> bool {
        self.totp.is_some() || self.key.is_some()
    }
}

fn malformed() -> ClientError {
    ClientError::Other(RpcError::local(
        tonic::Code::Internal,
        "malformed server reply",
    ))
}

impl AdminSession {
    /// `BeginEnrollment` for `token`. Each call makes the server offer a
    /// fresh TOTP seed (an earlier one stops working).
    ///
    /// # Errors
    /// [`ClientError::Rejected`] for an unknown, spent or expired token;
    /// throttling; [`ClientError::Authenticator`] for bad creation options.
    pub async fn begin_enrollment(
        &mut self,
        token: &Secret,
    ) -> Result<EnrollmentOffer, ClientError> {
        let r = self.begin_enrollment_inner(token).await;
        self.settle(r)
    }

    async fn begin_enrollment_inner(
        &mut self,
        token: &Secret,
    ) -> Result<EnrollmentOffer, ClientError> {
        let timeout = self.config().rpc_timeout;
        let ch = self.channel().await.map_err(ClientError::Connect)?;
        // No interceptor: an enrollment never carries a session token.
        let mut admin = AdminClient::new(ch);
        let mut resp = within(
            timeout,
            admin.begin_enrollment(BeginEnrollmentRequest {
                enrollment_token: token.expose().to_string(),
            }),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|s| ClientError::from_credential_status(&s))?;
        let totp = if resp.totp_provisioning_uri.is_empty() {
            None
        } else {
            Some(
                TotpSeed::from_uri(std::mem::take(&mut resp.totp_provisioning_uri))
                    .ok_or_else(malformed)?,
            )
        };
        let key = resp
            .webauthn_creation_options
            .as_ref()
            .map(creation_request)
            .transpose()
            .map_err(ClientError::Authenticator)?;
        Ok(EnrollmentOffer {
            username: resp.username,
            username_choosable: resp.username_choosable,
            display_name: resp.display_name,
            password_min_len: resp
                .password_min_len
                .clamp(PASSWORD_MIN_LEN_BOUNDS.0, PASSWORD_MIN_LEN_BOUNDS.1),
            totp,
            key,
        })
    }

    /// `CompleteEnrollment`: the new password, a code (from the offered
    /// seed, or the current one for a password-only reset) and/or a key.
    /// The password and code are wiped on return; returns the admin id.
    ///
    /// # Errors
    /// [`ClientError::Rejected`] (generic), `password_policy` as
    /// [`ClientError::Other`], throttling, others.
    pub async fn complete_enrollment(
        &mut self,
        token: &Secret,
        password: Secret,
        code: Option<Secret>,
        key: Option<WebAuthnAttestation>,
    ) -> Result<String, ClientError> {
        let r = async {
            let timeout = self.config().rpc_timeout;
            let ch = self.channel().await.map_err(ClientError::Connect)?;
            let mut admin = AdminClient::new(ch);
            let result = within(
                timeout,
                admin.complete_enrollment(CompleteEnrollmentRequest {
                    enrollment_token: token.expose().to_string(),
                    username: String::new(),
                    display_name: String::new(),
                    password: password.expose().to_string(),
                    totp_code: code
                        .as_ref()
                        .map(|c| c.expose().to_string())
                        .unwrap_or_default(),
                    webauthn_attestation: key,
                }),
            )
            .await;
            drop(password);
            drop(code);
            result
                .map(|r| r.into_inner().admin_id)
                .map_err(|s| ClientError::from_credential_status(&s))
        }
        .await;
        self.settle(r)
    }
}
