//! FIDO2 / WebAuthn on the client side (F20 §5, F22 §3a): the
//! [`Authenticator`] trait each front end implements over its platform
//! (Windows `webauthn.dll`, macOS AuthenticationServices, CTAP2 over USB HID)
//! or a test double, and the request this client builds for it.

//! The client writes the `clientDataJSON` itself, with origin
//! `https://<RP ID>` (CMIS's default origin), and refuses any RP ID outside
//! [`RP_ID_PREFIX`], so a server cannot use the key for another site.

use std::time::Duration;

use base64::Engine as _;
use ferro_proto::admin_v1::{WebAuthnAssertion, WebAuthnChallenge};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Every FerroGate RP ID is `ferrogate-admin.<trust_domain>` (F20 §5).
pub const RP_ID_PREFIX: &str = "ferrogate-admin.";
/// Longest RP ID accepted (a DNS name).
pub const MAX_RP_ID_LEN: usize = 253;
/// Challenge length bounds, in bytes (CMIS sends 32).
pub const CHALLENGE_LEN: std::ops::RangeInclusive<usize> = 16..=64;
/// Most credential ids accepted in an allow list (an account holds up to 8).
pub const MAX_ALLOW_CREDENTIALS: usize = 32;
/// Longest credential id accepted (WebAuthn Level 3 §5.1).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Largest `authenticatorData` or signature accepted from a backend.
pub const MAX_RESPONSE_FIELD_LEN: usize = 4096;
/// Longest user handle accepted (WebAuthn §5.4.3).
pub const MAX_USER_HANDLE_LEN: usize = 64;
/// Shortest and longest wait for a key touch. The upper bound stays inside
/// the server's two-minute nonce lifetime.
pub const TIMEOUT_RANGE: (Duration, Duration) = (Duration::from_secs(10), Duration::from_secs(100));

/// Why a security key gave no assertion. Shown generically; never carries
/// key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticatorError {
    /// The platform offers no authenticator API to this client.
    #[error("no security-key support on this platform")]
    Unavailable,
    /// The person cancelled the operating system's or the key's prompt.
    #[error("cancelled")]
    Cancelled,
    /// No touch within the timeout.
    #[error("timed out")]
    Timeout,
    /// No connected key holds a credential the server allows.
    #[error("no registered security key answered")]
    NoCredential,
    /// The server's request is outside what this client accepts.
    #[error("the server's security-key request was refused")]
    BadRequest,
    /// The backend failed (short, inert description).
    #[error("security key failure: {0}")]
    Failed(String),
}

/// An assertion request (`navigator.credentials.get`), ready for a backend:
/// CTAP2 backends sign [`AssertionRequest::client_data_hash`], platform APIs
/// take [`AssertionRequest::client_data_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionRequest {
    /// The relying party (`ferrogate-admin.<trust_domain>`).
    pub rp_id: String,
    /// `https://<rp_id>`.
    pub origin: String,
    /// The `clientDataJSON` the assertion signs over (by hash).
    pub client_data_json: Vec<u8>,
    /// SHA-256 of [`AssertionRequest::client_data_json`].
    pub client_data_hash: [u8; 32],
    /// Credentials the server accepts (empty: any discoverable one).
    pub allow_credential_ids: Vec<Vec<u8>>,
    /// Always `true`: CMIS requires user verification (PIN or biometric,
    /// entered in the key's or the OS's own prompt, never in this client).
    pub user_verification_required: bool,
    /// How long to wait for a touch.
    pub timeout: Duration,
}

/// What the authenticator returns (no private key ever leaves it).
pub struct AuthenticatorAssertion {
    /// The credential that signed.
    pub credential_id: Vec<u8>,
    /// `authenticatorData` (RP ID hash, flags, counter).
    pub authenticator_data: Vec<u8>,
    /// Signature over `authenticatorData ‖ client_data_hash`.
    pub signature: Vec<u8>,
    /// User handle, when the key returns one.
    pub user_handle: Vec<u8>,
}

/// A FIDO2 authenticator: a platform API, a CTAP2 device or a test double.
/// Calls block (the OS shows its own prompt); clients run them off the UI
/// and async threads.
pub trait Authenticator: Send + Sync {
    /// Answer `request` with an assertion.
    ///
    /// # Errors
    /// [`AuthenticatorError`]; nothing is sent to the server then.
    fn get_assertion(
        &self,
        request: &AssertionRequest,
    ) -> Result<AuthenticatorAssertion, AuthenticatorError>;
}

/// Whether `rp_id` is a FerroGate admin RP ID: `ferrogate-admin.` followed by
/// a lower-case DNS name.
#[must_use]
pub fn valid_rp_id(rp_id: &str) -> bool {
    let Some(rest) = rp_id.strip_prefix(RP_ID_PREFIX) else {
        return false;
    };
    rp_id.len() <= MAX_RP_ID_LEN
        && !rest.is_empty()
        && rest.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The `clientDataJSON` of a `webauthn.get` ceremony for `origin`.
#[must_use]
pub fn client_data_get(challenge: &[u8], origin: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        ty: &'a str,
        challenge: String,
        origin: &'a str,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }
    let doc = ClientData {
        ty: "webauthn.get",
        challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        origin,
        cross_origin: false,
    };
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// Build the request for the server's challenge, after checking every field
/// the server supplied.
///
/// # Errors
/// [`AuthenticatorError::BadRequest`] for an RP ID outside
/// [`RP_ID_PREFIX`], a challenge or allow list out of bounds.
pub fn assertion_request(c: &WebAuthnChallenge) -> Result<AssertionRequest, AuthenticatorError> {
    if !valid_rp_id(&c.rp_id)
        || !CHALLENGE_LEN.contains(&c.challenge.len())
        || c.allow_credential_ids.len() > MAX_ALLOW_CREDENTIALS
        || c.allow_credential_ids
            .iter()
            .any(|id| id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LEN)
    {
        return Err(AuthenticatorError::BadRequest);
    }
    let origin = format!("https://{}", c.rp_id);
    let client_data_json = client_data_get(&c.challenge, &origin);
    let client_data_hash = Sha256::digest(&client_data_json).into();
    let wanted = u64::try_from(c.timeout_ms).map_or(Duration::ZERO, Duration::from_millis);
    let timeout = if wanted.is_zero() {
        Duration::from_secs(60)
    } else {
        wanted.clamp(TIMEOUT_RANGE.0, TIMEOUT_RANGE.1)
    };
    Ok(AssertionRequest {
        rp_id: c.rp_id.clone(),
        origin,
        client_data_json,
        client_data_hash,
        allow_credential_ids: c.allow_credential_ids.clone(),
        user_verification_required: true,
        timeout,
    })
}

/// Check a backend's answer against its request and turn it into the proto
/// message: bounded fields, an allowed credential, and `authenticatorData`
/// for this RP ID with user presence and verification.
///
/// # Errors
/// [`AuthenticatorError::Failed`] when the answer does not match.
pub fn into_proto(
    request: &AssertionRequest,
    a: AuthenticatorAssertion,
) -> Result<WebAuthnAssertion, AuthenticatorError> {
    let bad = |why: &str| Err(AuthenticatorError::Failed(why.to_string()));
    if a.credential_id.is_empty()
        || a.credential_id.len() > MAX_CREDENTIAL_ID_LEN
        || a.authenticator_data.len() > MAX_RESPONSE_FIELD_LEN
        || a.signature.is_empty()
        || a.signature.len() > MAX_RESPONSE_FIELD_LEN
        || a.user_handle.len() > MAX_USER_HANDLE_LEN
    {
        return bad("malformed answer");
    }
    if !request.allow_credential_ids.is_empty()
        && !request.allow_credential_ids.contains(&a.credential_id)
    {
        return bad("unexpected credential");
    }
    // rpIdHash (32) ‖ flags (1) ‖ signCount (4).
    let rp_hash: [u8; 32] = Sha256::digest(request.rp_id.as_bytes()).into();
    let flags_ok = |f: u8| f & 0x01 != 0 && (!request.user_verification_required || f & 0x04 != 0);
    match a.authenticator_data.get(..37) {
        Some(head) if head[..32] == rp_hash && flags_ok(head[32]) => {}
        _ => return bad("answer for another site or without verification"),
    }
    Ok(WebAuthnAssertion {
        credential_id: a.credential_id,
        authenticator_data: a.authenticator_data,
        client_data_json: request.client_data_json.clone(),
        signature: a.signature,
        user_handle: a.user_handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RP: &str = "ferrogate-admin.ferrogate.test";

    fn challenge() -> WebAuthnChallenge {
        WebAuthnChallenge {
            challenge: vec![7; 32],
            rp_id: RP.into(),
            allow_credential_ids: vec![vec![1; 32]],
            user_verification: 1,
            timeout_ms: 0,
        }
    }

    fn answer(req: &AssertionRequest, flags: u8) -> AuthenticatorAssertion {
        let mut data = Sha256::digest(req.rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&1u32.to_be_bytes());
        AuthenticatorAssertion {
            credential_id: vec![1; 32],
            authenticator_data: data,
            signature: vec![9; 70],
            user_handle: Vec::new(),
        }
    }

    #[test]
    fn only_ferrogate_admin_rp_ids_are_accepted() {
        assert!(valid_rp_id(RP));
        for bad in [
            "google.com",
            "ferrogate-admin.",
            "ferrogate-admin.Example.com",
            "ferrogate-admin.a..b",
            "ferrogate-admin.-a.b",
            "ferrogate-admin.a\".b",
            "xferrogate-admin.a.b",
        ] {
            assert!(!valid_rp_id(bad), "{bad}");
        }
        let mut c = challenge();
        c.rp_id = "accounts.google.com".into();
        assert_eq!(assertion_request(&c), Err(AuthenticatorError::BadRequest));
    }

    #[test]
    fn the_client_data_names_the_challenge_and_the_rp_origin() {
        let req = assertion_request(&challenge()).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&req.client_data_json).unwrap();
        assert_eq!(doc["type"], "webauthn.get");
        assert_eq!(doc["origin"], format!("https://{RP}"));
        assert_eq!(doc["crossOrigin"], false);
        let sent = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(doc["challenge"].as_str().unwrap())
            .unwrap();
        assert_eq!(sent, vec![7; 32]);
        let hash: [u8; 32] = Sha256::digest(&req.client_data_json).into();
        assert_eq!(req.client_data_hash, hash);
        assert!(req.user_verification_required);
        assert_eq!(req.timeout, Duration::from_secs(60));
    }

    #[test]
    fn out_of_bounds_challenges_and_timeouts_are_handled() {
        let mut c = challenge();
        c.challenge = vec![1; 8];
        assert!(assertion_request(&c).is_err());
        let mut c = challenge();
        c.allow_credential_ids = vec![vec![1; 2000]];
        assert!(assertion_request(&c).is_err());
        let mut c = challenge();
        c.allow_credential_ids = vec![vec![1; 4]; MAX_ALLOW_CREDENTIALS + 1];
        assert!(assertion_request(&c).is_err());
        let mut c = challenge();
        c.timeout_ms = 3_600_000;
        assert_eq!(assertion_request(&c).unwrap().timeout, TIMEOUT_RANGE.1);
        c.timeout_ms = 1;
        assert_eq!(assertion_request(&c).unwrap().timeout, TIMEOUT_RANGE.0);
    }

    #[test]
    fn an_answer_for_another_site_credential_or_without_uv_is_refused() {
        let req = assertion_request(&challenge()).unwrap();
        let ok = into_proto(&req, answer(&req, 0x05)).unwrap();
        assert_eq!(ok.client_data_json, req.client_data_json);
        assert!(into_proto(&req, answer(&req, 0x01)).is_err(), "no UV");
        let mut other = answer(&req, 0x05);
        other.credential_id = vec![2; 32];
        assert!(into_proto(&req, other).is_err(), "not allowed");
        let mut site = answer(&req, 0x05);
        site.authenticator_data[0] ^= 1;
        assert!(into_proto(&req, site).is_err(), "another RP ID hash");
        let mut short = answer(&req, 0x05);
        short.authenticator_data.truncate(20);
        assert!(into_proto(&req, short).is_err());
    }
}
