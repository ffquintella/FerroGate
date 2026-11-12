//! FIDO2 / WebAuthn on the client side (F20 §5, F22 §3a): the
//! [`Authenticator`] trait each front end implements over its platform (the
//! tray admin client: CTAP2 over USB HID on macOS and Linux, `webauthn.dll`
//! on Windows) or a test double, and the requests this client builds for it
//! — an assertion
//! (sign-in, step-up, per-operation proof) or a new credential (enrollment,
//! adding a key).

//! The client writes the `clientDataJSON` itself, with origin
//! `https://<RP ID>` (CMIS's default origin), and refuses any RP ID outside
//! [`RP_ID_PREFIX`], so a server cannot use the key for another site.

use std::time::Duration;

use base64::Engine as _;
use ferro_proto::admin_v1::{WebAuthnAssertion, WebAuthnChallenge, WebAuthnCreationOptions};

/// A registered key, as `CompleteEnrollment` and `CompleteAddFactor` carry
/// it (public data: credential id, public key, client data, label).
pub use ferro_proto::admin_v1::WebAuthnAttestation;
/// The server's creation options (`BeginEnrollment`, `BeginAddFactor`), for
/// front ends that build or test a [`CreationRequest`].
pub use ferro_proto::admin_v1::WebAuthnCreationOptions as CreationOptions;
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
/// COSE algorithms a new credential may use: ES256 and EdDSA, the ones CMIS
/// verifies (F20 §5).
pub const SUPPORTED_ALGORITHMS: [i32; 2] = [-7, -8];
/// Longest user name, display name or RP name accepted in creation options,
/// in bytes (the key may store and show them).
pub const MAX_NAME_LEN: usize = 256;
/// Most credential ids accepted in an exclude list (an account holds up to 8).
pub const MAX_EXCLUDE_CREDENTIALS: usize = 32;
/// Largest attestation object accepted from a backend.
pub const MAX_ATTESTATION_OBJECT_LEN: usize = 16 * 1024;
/// Most transport hints passed on to the server.
pub const MAX_TRANSPORTS: usize = 8;
/// Longest key label, in characters (CMIS refuses longer ones).
pub const MAX_LABEL_CHARS: usize = 64;
/// How long a key registration waits for a touch (the server's creation
/// ceremony lives 10 minutes).
pub const CREATION_TIMEOUT: Duration = Duration::from_secs(100);

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
    /// Always `true`: CMIS requires user verification (the key's PIN or
    /// biometric). The PIN goes to the key only: entered in the OS's own
    /// prompt where the platform API has one, or, for USB HID keys on macOS
    /// and Linux, in the front end's masked, wiped PIN prompt. Never to CMIS.
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

/// A credential-creation request (`navigator.credentials.create`), ready for
/// a backend: CTAP2 backends sign over [`CreationRequest::client_data_hash`],
/// platform APIs take [`CreationRequest::client_data_json`]. Always asks for
/// user verification and `none` attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationRequest {
    /// The relying party (`ferrogate-admin.<trust_domain>`).
    pub rp_id: String,
    /// The relying party's name, shown by some authenticators.
    pub rp_name: String,
    /// `https://<rp_id>`.
    pub origin: String,
    /// The opaque user handle the server chose (not the admin id).
    pub user_id: Vec<u8>,
    /// The account's user name (stored on the key, shown by the OS prompt).
    pub user_name: String,
    /// The account's display name.
    pub display_name: String,
    /// The `clientDataJSON` (type `webauthn.create`) the credential covers.
    pub client_data_json: Vec<u8>,
    /// SHA-256 of [`CreationRequest::client_data_json`].
    pub client_data_hash: [u8; 32],
    /// COSE algorithms, in the server's order of preference, among
    /// [`SUPPORTED_ALGORITHMS`].
    pub algorithms: Vec<i32>,
    /// Credentials the account already holds (the key must not add another).
    pub exclude_credential_ids: Vec<Vec<u8>>,
    /// Always `true`: the key's PIN or biometric (the PIN as for
    /// [`AssertionRequest::user_verification_required`]).
    pub user_verification_required: bool,
    /// How long to wait for a touch.
    pub timeout: Duration,
}

impl CreationRequest {
    /// Whether the request still holds together (a caller may have edited
    /// its public fields): an admin RP ID, its own origin, and the hash of
    /// its own `clientDataJSON`.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        let hash: [u8; 32] = Sha256::digest(&self.client_data_json).into();
        valid_rp_id(&self.rp_id)
            && self.origin == format!("https://{}", self.rp_id)
            && hash == self.client_data_hash
            && self.user_verification_required
            && !self.algorithms.is_empty()
            && self
                .algorithms
                .iter()
                .all(|a| SUPPORTED_ALGORITHMS.contains(a))
    }
}

/// What the authenticator returns for a new credential (the private key
/// never leaves it).
pub struct AuthenticatorAttestation {
    /// The new credential's id.
    pub credential_id: Vec<u8>,
    /// The CBOR attestation object (`fmt`, `attStmt`, `authData` carrying
    /// the credential public key).
    pub attestation_object: Vec<u8>,
    /// Transport hints (`usb`, `nfc`, `internal`, …).
    pub transports: Vec<String>,
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

    /// Create a new credential for `request`. A backend that can only sign
    /// in keeps this default, which refuses with
    /// [`AuthenticatorError::Unavailable`].
    ///
    /// # Errors
    /// [`AuthenticatorError`]; nothing is sent to the server then.
    fn make_credential(
        &self,
        request: &CreationRequest,
    ) -> Result<AuthenticatorAttestation, AuthenticatorError> {
        let _ = request;
        Err(AuthenticatorError::Unavailable)
    }
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

/// The `clientDataJSON` of a ceremony of type `ty` for `origin`.
fn client_data(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
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
        ty,
        challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        origin,
        cross_origin: false,
    };
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// The `clientDataJSON` of a `webauthn.get` ceremony for `origin`.
#[must_use]
pub fn client_data_get(challenge: &[u8], origin: &str) -> Vec<u8> {
    client_data("webauthn.get", challenge, origin)
}

/// The `clientDataJSON` of a `webauthn.create` ceremony for `origin`.
#[must_use]
pub fn client_data_create(challenge: &[u8], origin: &str) -> Vec<u8> {
    client_data("webauthn.create", challenge, origin)
}

/// Build the registration request for the server's creation options, after
/// checking every field it supplied: an admin RP ID, the challenge, the user
/// handle and names (bounded, no control or invisible characters: the key
/// stores and shows them), a supported algorithm and the exclude list.
///
/// # Errors
/// [`AuthenticatorError::BadRequest`] for anything outside those bounds.
pub fn creation_request(
    o: &WebAuthnCreationOptions,
) -> Result<CreationRequest, AuthenticatorError> {
    let name_ok =
        |s: &str| s.len() <= MAX_NAME_LEN && !s.chars().any(crate::display::is_hidden_or_control);
    let mut algorithms: Vec<i32> = Vec::new();
    for a in &o.pub_key_cred_params {
        if SUPPORTED_ALGORITHMS.contains(a) && !algorithms.contains(a) {
            algorithms.push(*a);
        }
    }
    if !valid_rp_id(&o.rp_id)
        || !CHALLENGE_LEN.contains(&o.challenge.len())
        || o.user_id.is_empty()
        || o.user_id.len() > MAX_USER_HANDLE_LEN
        || o.user_name.trim().is_empty()
        || !name_ok(&o.user_name)
        || !name_ok(&o.display_name)
        || !name_ok(&o.rp_name)
        || algorithms.is_empty()
        || o.exclude_credential_ids.len() > MAX_EXCLUDE_CREDENTIALS
        || o.exclude_credential_ids
            .iter()
            .any(|id| id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LEN)
    {
        return Err(AuthenticatorError::BadRequest);
    }
    let origin = format!("https://{}", o.rp_id);
    let client_data_json = client_data_create(&o.challenge, &origin);
    let client_data_hash = Sha256::digest(&client_data_json).into();
    Ok(CreationRequest {
        rp_id: o.rp_id.clone(),
        rp_name: if o.rp_name.trim().is_empty() {
            "FerroGate".to_string()
        } else {
            o.rp_name.clone()
        },
        origin,
        user_id: o.user_id.clone(),
        user_name: o.user_name.clone(),
        display_name: if o.display_name.trim().is_empty() {
            o.user_name.clone()
        } else {
            o.display_name.clone()
        },
        client_data_json,
        client_data_hash,
        algorithms,
        exclude_credential_ids: o.exclude_credential_ids.clone(),
        user_verification_required: true,
        timeout: CREATION_TIMEOUT,
    })
}

/// A key label as the server will store it: trimmed, without control or
/// invisible characters, at most [`MAX_LABEL_CHARS`] characters (empty lets
/// the server use its default).
#[must_use]
pub fn clean_label(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| !crate::display::is_hidden_or_control(*c))
        .take(MAX_LABEL_CHARS)
        .collect()
}

/// Check a backend's new credential against its request (bounded fields, a
/// credential the account does not hold yet, sane transport hints) and turn
/// it into the proto message with the request's own `clientDataJSON`. CMIS
/// verifies the attestation object itself (RP ID hash, UP+UV, algorithm).
///
/// # Errors
/// [`AuthenticatorError::Failed`] when the answer does not fit.
pub fn attestation_into_proto(
    request: &CreationRequest,
    a: AuthenticatorAttestation,
    label: &str,
) -> Result<WebAuthnAttestation, AuthenticatorError> {
    let bad = |why: &str| Err(AuthenticatorError::Failed(why.to_string()));
    if a.credential_id.is_empty()
        || a.credential_id.len() > MAX_CREDENTIAL_ID_LEN
        || a.attestation_object.is_empty()
        || a.attestation_object.len() > MAX_ATTESTATION_OBJECT_LEN
    {
        return bad("malformed answer");
    }
    if request.exclude_credential_ids.contains(&a.credential_id) {
        return bad("this key is already registered");
    }
    let transports = a
        .transports
        .into_iter()
        .filter(|t| {
            (1..=32).contains(&t.len())
                && t.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .take(MAX_TRANSPORTS)
        .collect();
    Ok(WebAuthnAttestation {
        credential_id: a.credential_id,
        attestation_object: a.attestation_object,
        client_data_json: request.client_data_json.clone(),
        transports,
        label: clean_label(label),
    })
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

    fn options() -> WebAuthnCreationOptions {
        WebAuthnCreationOptions {
            challenge: vec![3; 32],
            rp_id: RP.into(),
            rp_name: "FerroGate".into(),
            user_id: vec![4; 32],
            user_name: "alice".into(),
            display_name: String::new(),
            pub_key_cred_params: vec![-257, -7, -8, -7],
            exclude_credential_ids: vec![vec![1; 32]],
            user_verification: 1,
            attestation: 1,
        }
    }

    #[test]
    fn a_creation_request_names_the_challenge_the_rp_and_supported_algorithms() {
        let req = creation_request(&options()).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&req.client_data_json).unwrap();
        assert_eq!(doc["type"], "webauthn.create");
        assert_eq!(doc["origin"], format!("https://{RP}"));
        let sent = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(doc["challenge"].as_str().unwrap())
            .unwrap();
        assert_eq!(sent, vec![3; 32]);
        assert_eq!(req.algorithms, vec![-7, -8], "RS256 dropped, no repeats");
        assert_eq!(req.display_name, "alice", "falls back to the user name");
        assert!(req.user_verification_required && req.is_consistent());
        assert_eq!(req.timeout, CREATION_TIMEOUT);
        let mut edited = req.clone();
        edited.rp_id = "ferrogate-admin.elsewhere.test".into();
        assert!(!edited.is_consistent(), "the origin no longer matches");
    }

    #[test]
    fn creation_options_outside_the_bounds_are_refused() {
        type Edit = fn(&mut WebAuthnCreationOptions);
        let cases: Vec<(&str, Edit)> = vec![
            ("foreign rp", |o| o.rp_id = "accounts.google.com".into()),
            ("short challenge", |o| o.challenge = vec![1; 8]),
            ("no user handle", |o| o.user_id.clear()),
            ("long user handle", |o| o.user_id = vec![1; 65]),
            ("no user name", |o| o.user_name = " ".into()),
            ("control in name", |o| o.user_name = "al\u{1b}[2Jice".into()),
            ("bidi in display", |o| o.display_name = "a\u{202e}b".into()),
            ("long rp name", |o| o.rp_name = "x".repeat(MAX_NAME_LEN + 1)),
            ("no algorithm", |o| o.pub_key_cred_params = vec![-257]),
            ("long exclude", |o| {
                o.exclude_credential_ids = vec![vec![1; 4]; MAX_EXCLUDE_CREDENTIALS + 1];
            }),
            ("empty exclude id", |o| {
                o.exclude_credential_ids = vec![vec![]];
            }),
        ];
        for (what, edit) in cases {
            let mut o = options();
            edit(&mut o);
            assert_eq!(
                creation_request(&o),
                Err(AuthenticatorError::BadRequest),
                "{what}"
            );
        }
    }

    #[test]
    fn a_new_credential_is_bounded_new_and_labelled_cleanly() {
        let req = creation_request(&options()).unwrap();
        let fresh = || AuthenticatorAttestation {
            credential_id: vec![2; 32],
            attestation_object: vec![0xa3; 200],
            transports: vec!["usb".into(), "Bad Transport".into(), "nfc".into()],
        };
        let ok = attestation_into_proto(&req, fresh(), "  Yubi\u{202e}Key\u{7} ").unwrap();
        assert_eq!(ok.label, "YubiKey");
        assert_eq!(ok.transports, vec!["usb".to_string(), "nfc".to_string()]);
        assert_eq!(ok.client_data_json, req.client_data_json);
        let mut known = fresh();
        known.credential_id = vec![1; 32];
        assert!(attestation_into_proto(&req, known, "").is_err(), "excluded");
        let mut huge = fresh();
        huge.attestation_object = vec![0; MAX_ATTESTATION_OBJECT_LEN + 1];
        assert!(attestation_into_proto(&req, huge, "").is_err());
        assert_eq!(
            clean_label(&"k".repeat(80)).chars().count(),
            MAX_LABEL_CHARS
        );
    }

    #[test]
    fn a_backend_without_registration_refuses_it() {
        struct SignOnly;
        impl Authenticator for SignOnly {
            fn get_assertion(
                &self,
                _: &AssertionRequest,
            ) -> Result<AuthenticatorAssertion, AuthenticatorError> {
                Err(AuthenticatorError::Cancelled)
            }
        }
        let req = creation_request(&options()).unwrap();
        assert!(matches!(
            SignOnly.make_credential(&req),
            Err(AuthenticatorError::Unavailable)
        ));
    }
}
