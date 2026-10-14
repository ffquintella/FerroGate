//! FIDO2 / WebAuthn relying-party verification (F20 §5, §6; W3C WebAuthn
//! Level 2 §7.1 "registering a new credential" and §7.2 "verifying an
//! authentication assertion").
//!
//! Written directly over crates already in the workspace — `p256` (ES256),
//! `ed25519-dalek` (EdDSA), `ciborium` (CBOR / COSE) and `x509-parser`
//! (`packed` attestation certificates) — instead of `webauthn-rs`, whose core
//! links OpenSSL, which `deny.toml` bans. The scope is exactly what F20
//! needs:
//!
//! - credential keys: ES256 (COSE -7) and EdDSA / Ed25519 (COSE -8);
//! - attestation statements: `none` and `packed` (self attestation, or an
//!   `x5c` leaf whose signature and AAGUID extension are checked). The
//!   attestation *trust* policy is "none" (OQ-F20-2): no attestation roots,
//!   no AAGUID allowlist, so `packed` proves no more than `none` does;
//! - user presence **and** user verification required in both ceremonies;
//! - origin from a configured allowlist, RP ID hash, ceremony type and
//!   challenge checked; cross-origin ceremonies refused;
//! - the backup-eligible flag is reported, so a synced passkey counts as
//!   AAL2 and a device-bound credential as AAL3 (OQ-F20-6).
//!
//! The module is pure: no I/O, clock or state. Challenge issuance and single
//! use, credential ownership, the signature-counter compare-and-set and the
//! audit trail live in [`super::factors`]. Every input has a size bound that
//! is checked before parsing.

use ciborium::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::codec::b64url_decode;

/// COSE algorithm id of ES256 (ECDSA P-256 with SHA-256).
pub const ALG_ES256: i64 = -7;
/// COSE algorithm id of EdDSA (Ed25519).
pub const ALG_EDDSA: i64 = -8;
/// The credential algorithms offered in creation options, in preference order.
pub const SUPPORTED_ALGORITHMS: [i64; 2] = [ALG_ES256, ALG_EDDSA];

/// Longest credential id accepted (WebAuthn Level 3 §5.1).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Largest `clientDataJSON` accepted.
pub const MAX_CLIENT_DATA_LEN: usize = 4096;
/// Largest assertion `authenticatorData` accepted.
pub const MAX_AUTHENTICATOR_DATA_LEN: usize = 4096;
/// Largest attestation object accepted (room for a short `x5c` chain).
pub const MAX_ATTESTATION_OBJECT_LEN: usize = 16 * 1024;
/// Largest signature accepted (an ECDSA DER signature is at most 72 bytes).
pub const MAX_SIGNATURE_LEN: usize = 512;
/// Largest user handle accepted (WebAuthn §5.4.3: at most 64 bytes).
pub const MAX_USER_HANDLE_LEN: usize = 64;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// OID of the FIDO AAGUID certificate extension (`id-fido-gen-ce-aaguid`).
const OID_FIDO_AAGUID: &str = "1.3.6.1.4.1.45724.1.1.4";

/// Why a ceremony was refused. The caller always answers the client with
/// the same generic error; [`WebAuthnError::label`] is for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebAuthnError {
    /// An input exceeds its size bound.
    #[error("input exceeds its size bound")]
    TooLarge,
    /// A structure does not parse, has trailing data or duplicate keys.
    #[error("malformed WebAuthn structure")]
    Malformed,
    /// `clientDataJSON.type` is not the expected ceremony.
    #[error("clientDataJSON type mismatch")]
    Type,
    /// The challenge is not the one issued.
    #[error("challenge mismatch")]
    Challenge,
    /// The origin is not configured.
    #[error("origin not allowed")]
    Origin,
    /// The ceremony ran in a cross-origin frame.
    #[error("cross-origin ceremony")]
    CrossOrigin,
    /// `rpIdHash` is not SHA-256 of the RP ID.
    #[error("RP ID hash mismatch")]
    RpId,
    /// The user-present flag is clear.
    #[error("user not present")]
    UserPresence,
    /// The user-verified flag is clear.
    #[error("user not verified")]
    UserVerification,
    /// The reported credential id is not the attested one.
    #[error("credential id mismatch")]
    CredentialId,
    /// The credential key uses an algorithm that was not offered.
    #[error("unsupported public key algorithm")]
    Algorithm,
    /// The credential key is not a valid key.
    #[error("invalid public key")]
    Key,
    /// The attestation statement format is not supported.
    #[error("unsupported attestation format")]
    AttestationFormat,
    /// The attestation statement does not verify.
    #[error("attestation statement invalid")]
    Attestation,
    /// The assertion signature does not verify.
    #[error("signature invalid")]
    Signature,
}

impl WebAuthnError {
    /// Stable opcode for logs (never contains request data).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::Type => "type",
            Self::Challenge => "challenge",
            Self::Origin => "origin",
            Self::CrossOrigin => "cross_origin",
            Self::RpId => "rp_id",
            Self::UserPresence => "user_presence",
            Self::UserVerification => "user_verification",
            Self::CredentialId => "credential_id",
            Self::Algorithm => "algorithm",
            Self::Key => "key",
            Self::AttestationFormat => "attestation_format",
            Self::Attestation => "attestation",
            Self::Signature => "signature",
        }
    }
}

/// A credential that passed the registration ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredential {
    /// Credential id chosen by the authenticator.
    pub credential_id: Vec<u8>,
    /// The COSE_Key exactly as the authenticator encoded it (stored as is).
    pub cose_public_key: Vec<u8>,
    /// COSE algorithm of the key ([`ALG_ES256`] or [`ALG_EDDSA`]).
    pub algorithm: i64,
    /// Initial signature counter.
    pub sign_count: u32,
    /// Authenticator model id.
    pub aaguid: [u8; 16],
    /// The credential may be synced (a passkey): AAL2, not AAL3.
    pub backup_eligible: bool,
}

/// An assertion whose signature verified with the stored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// Signature counter the authenticator reported; the caller must still
    /// apply [`counter_advances`] against the stored value.
    pub sign_count: u32,
    /// The credential may be synced (a passkey): AAL2, not AAL3.
    pub backup_eligible: bool,
}

/// The CMIS relying party: RP ID and the origins a `clientDataJSON` may name.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    rp_id: String,
    rp_id_hash: [u8; 32],
    origins: Vec<String>,
}

/// Parsed `authenticatorData`.
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredential<'a>>,
}

/// The attested credential data of a registration.
struct AttestedCredential<'a> {
    aaguid: [u8; 16],
    credential_id: &'a [u8],
    public_key: &'a [u8],
}

/// A credential public key.
enum PublicKey {
    Es256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl RelyingParty {
    /// A relying party for `rp_id` accepting exactly `origins`.
    #[must_use]
    pub fn new(rp_id: &str, origins: Vec<String>) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            rp_id_hash: Sha256::digest(rp_id.as_bytes()).into(),
            origins,
        }
    }

    /// The RP ID sent to clients in challenges and creation options.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The accepted origins.
    #[must_use]
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// Verify a registration ("create") response against the `challenge`
    /// this server issued (WebAuthn §7.1).
    pub fn verify_registration(
        &self,
        challenge: &[u8],
        credential_id: &[u8],
        attestation_object: &[u8],
        client_data_json: &[u8],
    ) -> Result<NewCredential, WebAuthnError> {
        if attestation_object.len() > MAX_ATTESTATION_OBJECT_LEN
            || credential_id.len() > MAX_CREDENTIAL_ID_LEN
        {
            return Err(WebAuthnError::TooLarge);
        }
        let client_data_hash =
            self.check_client_data(client_data_json, "webauthn.create", challenge)?;
        let (fmt, statement, auth_data) = parse_attestation_object(attestation_object)?;
        let ad = parse_auth_data(&auth_data)?;
        self.check_auth_data(&ad)?;
        let attested = ad.attested.as_ref().ok_or(WebAuthnError::Malformed)?;
        if credential_id != attested.credential_id {
            return Err(WebAuthnError::CredentialId);
        }
        let (key, algorithm) = parse_cose_key(attested.public_key)?;
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        match fmt.as_str() {
            "none" => {
                if !matches!(&statement, Value::Map(m) if m.is_empty()) {
                    return Err(WebAuthnError::Attestation);
                }
            }
            "packed" => verify_packed(&statement, &key, algorithm, &signed, &attested.aaguid)?,
            _ => return Err(WebAuthnError::AttestationFormat),
        }
        Ok(NewCredential {
            credential_id: attested.credential_id.to_vec(),
            cose_public_key: attested.public_key.to_vec(),
            algorithm,
            sign_count: ad.sign_count,
            aaguid: attested.aaguid,
            backup_eligible: ad.flags & FLAG_BE != 0,
        })
    }

    /// Verify an authentication ("get") response against the `challenge`
    /// this server issued and the credential's stored COSE key (WebAuthn
    /// §7.2, steps 7 to 20). Credential ownership, the user handle and the
    /// signature counter are the caller's (step 21 needs the store).
    pub fn verify_assertion(
        &self,
        challenge: &[u8],
        cose_public_key: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        if authenticator_data.len() > MAX_AUTHENTICATOR_DATA_LEN
            || signature.len() > MAX_SIGNATURE_LEN
        {
            return Err(WebAuthnError::TooLarge);
        }
        let client_data_hash =
            self.check_client_data(client_data_json, "webauthn.get", challenge)?;
        let ad = parse_auth_data(authenticator_data)?;
        if ad.attested.is_some() {
            return Err(WebAuthnError::Malformed);
        }
        self.check_auth_data(&ad)?;
        let (key, _) = parse_cose_key(cose_public_key)?;
        let mut signed = authenticator_data.to_vec();
        signed.extend_from_slice(&client_data_hash);
        verify_signature(&key, &signed, signature)?;
        Ok(VerifiedAssertion {
            sign_count: ad.sign_count,
            backup_eligible: ad.flags & FLAG_BE != 0,
        })
    }

    /// Check `clientDataJSON` (type, challenge, origin, cross-origin) and
    /// return its SHA-256.
    fn check_client_data(
        &self,
        json: &[u8],
        ceremony: &str,
        challenge: &[u8],
    ) -> Result<[u8; 32], WebAuthnError> {
        #[derive(serde::Deserialize)]
        struct ClientData {
            #[serde(rename = "type")]
            ty: String,
            challenge: String,
            origin: String,
            #[serde(rename = "crossOrigin", default)]
            cross_origin: Option<bool>,
        }
        if json.len() > MAX_CLIENT_DATA_LEN {
            return Err(WebAuthnError::TooLarge);
        }
        // serde rejects duplicate fields, so a document cannot carry two
        // different values for the same key.
        let cd: ClientData = serde_json::from_slice(json).map_err(|_| WebAuthnError::Malformed)?;
        if cd.ty != ceremony {
            return Err(WebAuthnError::Type);
        }
        let got = b64url_decode(&cd.challenge).ok_or(WebAuthnError::Challenge)?;
        if !bool::from(got.as_slice().ct_eq(challenge)) {
            return Err(WebAuthnError::Challenge);
        }
        if !self.origins.contains(&cd.origin) {
            return Err(WebAuthnError::Origin);
        }
        if cd.cross_origin == Some(true) {
            return Err(WebAuthnError::CrossOrigin);
        }
        Ok(Sha256::digest(json).into())
    }

    /// RP ID hash, user presence and user verification (required).
    fn check_auth_data(&self, ad: &AuthData<'_>) -> Result<(), WebAuthnError> {
        if !bool::from(ad.rp_id_hash.ct_eq(&self.rp_id_hash)) {
            return Err(WebAuthnError::RpId);
        }
        if ad.flags & FLAG_UP == 0 {
            return Err(WebAuthnError::UserPresence);
        }
        if ad.flags & FLAG_UV == 0 {
            return Err(WebAuthnError::UserVerification);
        }
        Ok(())
    }
}

/// The challenge a `clientDataJSON` carries, decoded, without verifying
/// anything else. Token enrollment uses it to find which single-use
/// enrollment challenge the client answered; the full ceremony is then
/// verified against that challenge.
#[must_use]
pub fn client_data_challenge(json: &[u8]) -> Option<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct Challenge {
        challenge: String,
    }
    if json.len() > MAX_CLIENT_DATA_LEN {
        return None;
    }
    let c: Challenge = serde_json::from_slice(json).ok()?;
    b64url_decode(&c.challenge)
}

/// WebAuthn §7.2 step 21: the counter must grow, unless the authenticator
/// keeps none (both zero). Anything else may be a cloned authenticator.
#[must_use]
pub fn counter_advances(stored: i64, received: u32) -> bool {
    (stored == 0 && received == 0) || i64::from(received) > stored
}

/// Assurance level a WebAuthn verification reaches: AAL3 for a device-bound
/// credential, AAL2 for a backup-eligible (synced) one (OQ-F20-6).
#[must_use]
pub fn aal(backup_eligible: bool) -> i64 {
    if backup_eligible {
        2
    } else {
        3
    }
}

/// Decode one CBOR item from the front of `bytes`; return it and the number
/// of bytes it used.
fn cbor_item(bytes: &[u8]) -> Result<(Value, usize), WebAuthnError> {
    let mut reader = bytes;
    let value: Value =
        ciborium::de::from_reader(&mut reader).map_err(|_| WebAuthnError::Malformed)?;
    Ok((value, bytes.len() - reader.len()))
}

/// Decode exactly one CBOR item spanning all of `bytes`.
fn cbor_exact(bytes: &[u8]) -> Result<Value, WebAuthnError> {
    let (value, used) = cbor_item(bytes)?;
    if used != bytes.len() {
        return Err(WebAuthnError::Malformed);
    }
    Ok(value)
}

/// The `fmt`, `attStmt` and `authData` of an attestation object.
fn parse_attestation_object(bytes: &[u8]) -> Result<(String, Value, Vec<u8>), WebAuthnError> {
    let Value::Map(entries) = cbor_exact(bytes)? else {
        return Err(WebAuthnError::Malformed);
    };
    let (mut fmt, mut statement, mut auth_data) = (None, None, None);
    for (k, v) in entries {
        let duplicate = match (k.as_text(), v) {
            (Some("fmt"), Value::Text(t)) => fmt.replace(t).is_some(),
            (Some("attStmt"), v @ Value::Map(_)) => statement.replace(v).is_some(),
            (Some("authData"), Value::Bytes(b)) => auth_data.replace(b).is_some(),
            _ => return Err(WebAuthnError::Malformed),
        };
        if duplicate {
            return Err(WebAuthnError::Malformed);
        }
    }
    match (fmt, statement, auth_data) {
        (Some(f), Some(s), Some(a)) => Ok((f, s, a)),
        _ => Err(WebAuthnError::Malformed),
    }
}

/// Parse `authenticatorData` (WebAuthn §6.1), consuming it exactly.
fn parse_auth_data(data: &[u8]) -> Result<AuthData<'_>, WebAuthnError> {
    if data.len() < 37 {
        return Err(WebAuthnError::Malformed);
    }
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        // Backed up but not backup eligible is impossible (WebAuthn L3 §6.1).
        return Err(WebAuthnError::Malformed);
    }
    let mut rest = &data[37..];
    let attested = if flags & FLAG_AT == 0 {
        None
    } else {
        if rest.len() < 18 {
            return Err(WebAuthnError::Malformed);
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&rest[..16]);
        let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        rest = &rest[18..];
        if len == 0 || len > MAX_CREDENTIAL_ID_LEN || rest.len() < len {
            return Err(WebAuthnError::Malformed);
        }
        let credential_id = &rest[..len];
        rest = &rest[len..];
        let (_, used) = cbor_item(rest)?;
        let public_key = &rest[..used];
        rest = &rest[used..];
        Some(AttestedCredential {
            aaguid,
            credential_id,
            public_key,
        })
    };
    if flags & FLAG_ED != 0 {
        let (extensions, used) = cbor_item(rest)?;
        if !matches!(extensions, Value::Map(_)) {
            return Err(WebAuthnError::Malformed);
        }
        rest = &rest[used..];
    }
    if !rest.is_empty() {
        return Err(WebAuthnError::Malformed);
    }
    Ok(AuthData {
        rp_id_hash: &data[..32],
        flags,
        sign_count,
        attested,
    })
}

fn cose_int(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

/// Parse a COSE_Key (RFC 9053) holding an ES256 or Ed25519 public key.
fn parse_cose_key(bytes: &[u8]) -> Result<(PublicKey, i64), WebAuthnError> {
    let Value::Map(entries) = cbor_exact(bytes)? else {
        return Err(WebAuthnError::Malformed);
    };
    let mut seen: Vec<i128> = Vec::with_capacity(entries.len());
    let (mut kty, mut alg, mut crv, mut x, mut y) = (None, None, None, None, None);
    for (k, v) in &entries {
        let label = cose_int(k).ok_or(WebAuthnError::Malformed)?;
        if seen.contains(&label) {
            return Err(WebAuthnError::Malformed);
        }
        seen.push(label);
        match label {
            1 => kty = cose_int(v),
            3 => alg = cose_int(v),
            -1 => crv = cose_int(v),
            -2 => x = v.as_bytes().cloned(),
            -3 => y = v.as_bytes().cloned(),
            _ => {}
        }
    }
    let alg = alg.ok_or(WebAuthnError::Malformed)?;
    match (kty, alg) {
        (Some(2), -7) => {
            let (Some(1), Some(x), Some(y)) = (crv, x, y) else {
                return Err(WebAuthnError::Key);
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(WebAuthnError::Key);
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| WebAuthnError::Key)?;
            Ok((PublicKey::Es256(vk), ALG_ES256))
        }
        (Some(1), -8) => {
            let (Some(6), Some(x)) = (crv, x) else {
                return Err(WebAuthnError::Key);
            };
            let raw: [u8; 32] = x.as_slice().try_into().map_err(|_| WebAuthnError::Key)?;
            let vk =
                ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| WebAuthnError::Key)?;
            if vk.is_weak() {
                return Err(WebAuthnError::Key);
            }
            Ok((PublicKey::Ed25519(vk), ALG_EDDSA))
        }
        (_, a) if !SUPPORTED_ALGORITHMS.iter().any(|s| i128::from(*s) == a) => {
            Err(WebAuthnError::Algorithm)
        }
        _ => Err(WebAuthnError::Key),
    }
}

/// Verify `signature` over `message` (ES256: ASN.1 DER; EdDSA: strict).
fn verify_signature(
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), WebAuthnError> {
    match key {
        PublicKey::Es256(vk) => {
            use p256::ecdsa::signature::Verifier as _;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| WebAuthnError::Signature)?;
            vk.verify(message, &sig)
                .map_err(|_| WebAuthnError::Signature)
        }
        PublicKey::Ed25519(vk) => {
            let raw: [u8; 64] = signature.try_into().map_err(|_| WebAuthnError::Signature)?;
            vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&raw))
                .map_err(|_| WebAuthnError::Signature)
        }
    }
}

/// Verify a `packed` attestation statement (WebAuthn §8.2): self
/// attestation with the credential key, or an `x5c` leaf certificate.
fn verify_packed(
    statement: &Value,
    credential_key: &PublicKey,
    credential_alg: i64,
    signed: &[u8],
    aaguid: &[u8; 16],
) -> Result<(), WebAuthnError> {
    let Value::Map(entries) = statement else {
        return Err(WebAuthnError::Attestation);
    };
    let (mut alg, mut sig, mut x5c) = (None, None, None);
    for (k, v) in entries {
        let duplicate = match (k.as_text(), v) {
            (Some("alg"), Value::Integer(i)) => alg.replace(i128::from(*i)).is_some(),
            (Some("sig"), Value::Bytes(b)) => sig.replace(b.as_slice()).is_some(),
            (Some("x5c"), Value::Array(a)) => x5c.replace(a.as_slice()).is_some(),
            _ => return Err(WebAuthnError::Attestation),
        };
        if duplicate {
            return Err(WebAuthnError::Attestation);
        }
    }
    let (Some(alg), Some(sig)) = (alg, sig) else {
        return Err(WebAuthnError::Attestation);
    };
    match x5c {
        None => {
            if alg != i128::from(credential_alg) {
                return Err(WebAuthnError::Attestation);
            }
            verify_signature(credential_key, signed, sig).map_err(|_| WebAuthnError::Attestation)
        }
        Some(chain) => {
            if alg != i128::from(ALG_ES256) {
                return Err(WebAuthnError::AttestationFormat);
            }
            let leaf = chain
                .first()
                .and_then(Value::as_bytes)
                .ok_or(WebAuthnError::Attestation)?;
            let attestation_key = leaf_certificate_key(leaf, aaguid)?;
            verify_signature(&attestation_key, signed, sig).map_err(|_| WebAuthnError::Attestation)
        }
    }
}

/// The P-256 key of a `packed` attestation certificate, after checking its
/// AAGUID extension (when present, it must match and not be critical).
fn leaf_certificate_key(der: &[u8], aaguid: &[u8; 16]) -> Result<PublicKey, WebAuthnError> {
    let (rest, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|_| WebAuthnError::Attestation)?;
    if !rest.is_empty() {
        return Err(WebAuthnError::Attestation);
    }
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == OID_FIDO_AAGUID {
            let mut expected = vec![0x04, 0x10];
            expected.extend_from_slice(aaguid);
            if ext.critical || ext.value != expected.as_slice() {
                return Err(WebAuthnError::Attestation);
            }
        }
    }
    let spki = cert.public_key();
    if spki.algorithm.algorithm != x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(WebAuthnError::Attestation);
    }
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&spki.subject_public_key.data)
        .map_err(|_| WebAuthnError::Attestation)?;
    Ok(PublicKey::Es256(vk))
}

/// The software authenticator shared with the integration tests.
#[cfg(test)]
#[path = "../../tests/support/soft_authenticator.rs"]
mod soft_authenticator;

#[cfg(test)]
mod tests {
    use super::soft_authenticator as soft;
    use super::*;

    use ciborium::Value;
    use sha2::{Digest, Sha256};
    use soft::{Fmt, SoftAuthenticator, AT, BE, BS, ED, UP, UV};

    const RP: &str = "ferrogate-admin.ferrogate.test";
    const ORIGIN: &str = "https://ferrogate-admin.ferrogate.test";
    const CHALLENGE: [u8; 32] = [7; 32];

    fn rp() -> RelyingParty {
        RelyingParty::new(RP, vec![ORIGIN.to_string()])
    }

    fn registered(auth: &SoftAuthenticator) -> NewCredential {
        let reg = auth.make_credential(RP, ORIGIN, &CHALLENGE);
        rp().verify_registration(
            &CHALLENGE,
            &reg.credential_id,
            &reg.attestation_object,
            &reg.client_data_json,
        )
        .unwrap()
    }

    fn check(
        cred: &NewCredential,
        a: &soft::Assertion,
    ) -> Result<VerifiedAssertion, WebAuthnError> {
        rp().verify_assertion(
            &CHALLENGE,
            &cred.cose_public_key,
            &a.authenticator_data,
            &a.client_data_json,
            &a.signature,
        )
    }

    #[test]
    fn es256_registration_with_none_attestation_yields_the_credential() {
        let auth = SoftAuthenticator::es256(3);
        let cred = registered(&auth);
        assert_eq!(cred.credential_id, auth.credential_id);
        assert_eq!(cred.cose_public_key, auth.cose_key());
        assert_eq!(cred.algorithm, ALG_ES256);
        assert_eq!(cred.sign_count, 1);
        assert_eq!(cred.aaguid, [0xAA; 16]);
        assert!(!cred.backup_eligible);
    }

    #[test]
    fn es256_and_eddsa_assertions_verify() {
        for mut auth in [SoftAuthenticator::es256(4), SoftAuthenticator::ed25519(5)] {
            let cred = registered(&auth);
            let a = auth.get_assertion(RP, ORIGIN, &CHALLENGE);
            let ok = check(&cred, &a).unwrap();
            assert_eq!(ok.sign_count, auth.counter);
            assert!(!ok.backup_eligible);
            let mut tampered = a.clone();
            tampered.signature[8] ^= 1;
            assert!(check(&cred, &tampered).is_err(), "a flipped bit fails");
        }
        let ed = registered(&SoftAuthenticator::ed25519(6));
        assert_eq!(ed.algorithm, ALG_EDDSA);
    }

    #[test]
    fn another_credentials_key_does_not_verify() {
        let mine = registered(&SoftAuthenticator::es256(8));
        let mut theirs = SoftAuthenticator::es256(9);
        let a = theirs.get_assertion(RP, ORIGIN, &CHALLENGE);
        assert_eq!(check(&mine, &a), Err(WebAuthnError::Signature));
    }

    #[test]
    fn a_wrong_origin_is_rejected_in_both_ceremonies() {
        let mut auth = SoftAuthenticator::es256(10);
        let reg = auth.make_credential(RP, "https://evil.example", &CHALLENGE);
        assert_eq!(
            rp().verify_registration(
                &CHALLENGE,
                &reg.credential_id,
                &reg.attestation_object,
                &reg.client_data_json
            ),
            Err(WebAuthnError::Origin)
        );
        let cred = registered(&auth);
        let a = auth.get_assertion(
            RP,
            "https://ferrogate-admin.ferrogate.test.evil",
            &CHALLENGE,
        );
        assert_eq!(check(&cred, &a), Err(WebAuthnError::Origin));
        let a = auth.get_assertion(RP, "http://ferrogate-admin.ferrogate.test", &CHALLENGE);
        assert_eq!(
            check(&cred, &a),
            Err(WebAuthnError::Origin),
            "scheme matters"
        );
    }

    #[test]
    fn a_wrong_rp_id_is_rejected_in_both_ceremonies() {
        let mut auth = SoftAuthenticator::es256(11);
        let reg = auth.make_credential("evil.example", ORIGIN, &CHALLENGE);
        assert_eq!(
            rp().verify_registration(
                &CHALLENGE,
                &reg.credential_id,
                &reg.attestation_object,
                &reg.client_data_json
            ),
            Err(WebAuthnError::RpId)
        );
        let cred = registered(&auth);
        let a = auth.get_assertion("ferrogate.test", ORIGIN, &CHALLENGE);
        assert_eq!(check(&cred, &a), Err(WebAuthnError::RpId));
    }

    #[test]
    fn the_challenge_and_ceremony_type_must_match() {
        let mut auth = SoftAuthenticator::es256(12);
        let cred = registered(&auth);
        let a = auth.get_assertion(RP, ORIGIN, &[8; 32]);
        assert_eq!(check(&cred, &a), Err(WebAuthnError::Challenge));
        // A registration response replayed as an assertion.
        let reg = auth.make_credential(RP, ORIGIN, &CHALLENGE);
        let mut a = auth.get_assertion(RP, ORIGIN, &CHALLENGE);
        a.client_data_json = reg.client_data_json;
        assert_eq!(check(&cred, &a), Err(WebAuthnError::Type));
    }

    #[test]
    fn user_verification_and_presence_are_required() {
        let auth = SoftAuthenticator::es256(13);
        let reg = auth.make_credential_with(RP, ORIGIN, &CHALLENGE, UP, Fmt::None);
        assert_eq!(
            rp().verify_registration(
                &CHALLENGE,
                &reg.credential_id,
                &reg.attestation_object,
                &reg.client_data_json
            ),
            Err(WebAuthnError::UserVerification)
        );
        let cred = registered(&auth);
        let a = auth.get_assertion_with(RP, ORIGIN, &CHALLENGE, UP, 9);
        assert_eq!(check(&cred, &a), Err(WebAuthnError::UserVerification));
        let a = auth.get_assertion_with(RP, ORIGIN, &CHALLENGE, UV, 9);
        assert_eq!(check(&cred, &a), Err(WebAuthnError::UserPresence));
    }

    #[test]
    fn backup_eligibility_is_reported_and_backup_state_needs_it() {
        let auth = SoftAuthenticator::es256(14);
        let cred = registered(&auth);
        let a = auth.get_assertion_with(RP, ORIGIN, &CHALLENGE, UP | UV | BE | BS, 9);
        assert!(check(&cred, &a).unwrap().backup_eligible);
        let a = auth.get_assertion_with(RP, ORIGIN, &CHALLENGE, UP | UV | BS, 9);
        assert_eq!(check(&cred, &a), Err(WebAuthnError::Malformed));
        assert_eq!(aal(true), 2, "a synced passkey is AAL2 (OQ-F20-6)");
        assert_eq!(aal(false), 3);
    }

    #[test]
    fn packed_self_attestation_is_verified() {
        for auth in [SoftAuthenticator::es256(15), SoftAuthenticator::ed25519(16)] {
            let reg = auth.make_credential_with(RP, ORIGIN, &CHALLENGE, UP | UV, Fmt::PackedSelf);
            let cred = rp()
                .verify_registration(
                    &CHALLENGE,
                    &reg.credential_id,
                    &reg.attestation_object,
                    &reg.client_data_json,
                )
                .unwrap();
            assert_eq!(cred.credential_id, auth.credential_id);
        }
        // A self attestation signed by another key fails.
        let auth = SoftAuthenticator::es256(17);
        let other = SoftAuthenticator::es256(18);
        let client = soft::client_data("webauthn.create", &CHALLENGE, ORIGIN);
        let auth_data = auth.auth_data(RP, UP | UV, 0, true);
        let forged = other.attestation_object(Fmt::PackedSelf, &auth_data, &client);
        assert_eq!(
            rp().verify_registration(&CHALLENGE, &auth.credential_id, &forged, &client),
            Err(WebAuthnError::Attestation)
        );
    }

    fn packed_x5c(
        auth: &SoftAuthenticator,
        aaguid_ext: Option<[u8; 16]>,
        tamper: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        use rcgen::SigningKey as _;
        let client = soft::client_data("webauthn.create", &CHALLENGE, ORIGIN);
        let auth_data = auth.auth_data(RP, UP | UV, 0, true);
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        if let Some(id) = aaguid_ext {
            let mut der = vec![0x04, 0x10];
            der.extend_from_slice(&id);
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
                    der,
                ));
        }
        let cert = params.self_signed(&kp).unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let mut sig = kp.sign(&signed).unwrap();
        if tamper {
            let n = sig.len() - 3;
            sig[n] ^= 1;
        }
        let text = |s: &str| Value::Text(s.to_string());
        let obj = soft::cbor(&Value::Map(vec![
            (text("fmt"), text("packed")),
            (
                text("attStmt"),
                Value::Map(vec![
                    (text("alg"), Value::Integer((-7).into())),
                    (text("sig"), Value::Bytes(sig)),
                    (
                        text("x5c"),
                        Value::Array(vec![Value::Bytes(cert.der().to_vec())]),
                    ),
                ]),
            ),
            (text("authData"), Value::Bytes(auth_data)),
        ]));
        (obj, client)
    }

    #[test]
    fn packed_x5c_attestation_is_verified_against_the_leaf_certificate() {
        let auth = SoftAuthenticator::ed25519(19);
        let (obj, client) = packed_x5c(&auth, Some(auth.aaguid), false);
        assert!(rp()
            .verify_registration(&CHALLENGE, &auth.credential_id, &obj, &client)
            .is_ok());
        let (obj, client) = packed_x5c(&auth, None, false);
        assert!(rp()
            .verify_registration(&CHALLENGE, &auth.credential_id, &obj, &client)
            .is_ok());
        let (obj, client) = packed_x5c(&auth, None, true);
        assert_eq!(
            rp().verify_registration(&CHALLENGE, &auth.credential_id, &obj, &client),
            Err(WebAuthnError::Attestation)
        );
        let (obj, client) = packed_x5c(&auth, Some([0x01; 16]), false);
        assert_eq!(
            rp().verify_registration(&CHALLENGE, &auth.credential_id, &obj, &client),
            Err(WebAuthnError::Attestation),
            "the certificate's AAGUID must match authenticatorData"
        );
    }

    #[test]
    fn other_attestation_formats_and_algorithms_are_refused() {
        let auth = SoftAuthenticator::es256(20);
        let client = soft::client_data("webauthn.create", &CHALLENGE, ORIGIN);
        let auth_data = auth.auth_data(RP, UP | UV, 0, true);
        let text = |s: &str| Value::Text(s.to_string());
        let obj = soft::cbor(&Value::Map(vec![
            (text("fmt"), text("fido-u2f")),
            (text("attStmt"), Value::Map(Vec::new())),
            (text("authData"), Value::Bytes(auth_data.clone())),
        ]));
        assert_eq!(
            rp().verify_registration(&CHALLENGE, &auth.credential_id, &obj, &client),
            Err(WebAuthnError::AttestationFormat)
        );
        // `none` with a non-empty statement.
        let obj = soft::cbor(&Value::Map(vec![
            (text("fmt"), text("none")),
            (
                text("attStmt"),
                Value::Map(vec![(text("sig"), Value::Bytes(vec![1]))]),
            ),
            (text("authData"), Value::Bytes(auth_data)),
        ]));
        assert_eq!(
            rp().verify_registration(&CHALLENGE, &auth.credential_id, &obj, &client),
            Err(WebAuthnError::Attestation)
        );
        // An RS256 key (COSE -257) is not offered.
        let int = |v: i64| Value::Integer(v.into());
        let rsa = soft::cbor(&Value::Map(vec![
            (int(1), int(3)),
            (int(3), int(-257)),
            (int(-1), Value::Bytes(vec![1; 256])),
            (int(-2), Value::Bytes(vec![1, 0, 1])),
        ]));
        let mut auth_data = Sha256::digest(RP.as_bytes()).to_vec();
        auth_data.push(UP | UV | AT);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&32u16.to_be_bytes());
        auth_data.extend_from_slice(&auth.credential_id);
        auth_data.extend_from_slice(&rsa);
        let obj = auth.attestation_object(Fmt::None, &auth_data, &client);
        assert_eq!(
            rp().verify_registration(&CHALLENGE, &auth.credential_id, &obj, &client),
            Err(WebAuthnError::Algorithm)
        );
    }

    #[test]
    fn the_reported_credential_id_must_be_the_attested_one() {
        let auth = SoftAuthenticator::es256(21);
        let reg = auth.make_credential(RP, ORIGIN, &CHALLENGE);
        assert_eq!(
            rp().verify_registration(
                &CHALLENGE,
                &[0xEE; 32],
                &reg.attestation_object,
                &reg.client_data_json
            ),
            Err(WebAuthnError::CredentialId)
        );
    }

    #[test]
    fn authenticator_data_must_be_exact() {
        let mut auth = SoftAuthenticator::es256(22);
        let cred = registered(&auth);
        // Trailing bytes after the fixed part.
        let mut a = auth.get_assertion(RP, ORIGIN, &CHALLENGE);
        a.authenticator_data.push(0);
        assert_eq!(check(&cred, &a), Err(WebAuthnError::Malformed));
        // Extension data present and well formed is accepted (and skipped).
        let client = soft::client_data("webauthn.get", &CHALLENGE, ORIGIN);
        let mut data = auth.auth_data(RP, UP | UV | ED, 50, false);
        data.extend_from_slice(&soft::cbor(&Value::Map(vec![(
            Value::Text("credProtect".into()),
            Value::Integer(2.into()),
        )])));
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let sig = auth.sign(&signed);
        assert!(rp()
            .verify_assertion(&CHALLENGE, &cred.cose_public_key, &data, &client, &sig)
            .is_ok());
        // Too short.
        assert_eq!(
            rp().verify_assertion(&CHALLENGE, &cred.cose_public_key, &[0; 36], &client, &sig),
            Err(WebAuthnError::Malformed)
        );
        // Oversized inputs are refused before parsing.
        assert_eq!(
            rp().verify_assertion(
                &CHALLENGE,
                &cred.cose_public_key,
                &vec![0; 64 * 1024],
                &client,
                &sig
            ),
            Err(WebAuthnError::TooLarge)
        );
    }

    #[test]
    fn client_data_must_be_strict_json_with_an_unpadded_challenge() {
        let mut auth = SoftAuthenticator::es256(23);
        let cred = registered(&auth);
        let mut a = auth.get_assertion(RP, ORIGIN, &CHALLENGE);
        let padded = format!(
            r#"{{"type":"webauthn.get","challenge":"{}=","origin":"{ORIGIN}"}}"#,
            soft::b64url(&CHALLENGE)
        );
        a.client_data_json = padded.into_bytes();
        assert_eq!(check(&cred, &a), Err(WebAuthnError::Challenge));
        a.client_data_json = br#"{"type":"webauthn.get","type":"webauthn.get"}"#.to_vec();
        assert_eq!(check(&cred, &a), Err(WebAuthnError::Malformed));
        let cross = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":true}}"#,
            soft::b64url(&CHALLENGE)
        );
        a.client_data_json = cross.into_bytes();
        assert_eq!(check(&cred, &a), Err(WebAuthnError::CrossOrigin));
    }

    #[test]
    fn signature_counters_must_advance_unless_both_are_zero() {
        assert!(counter_advances(0, 0));
        assert!(counter_advances(0, 1));
        assert!(counter_advances(41, 42));
        assert!(!counter_advances(42, 42));
        assert!(!counter_advances(42, 41));
        assert!(!counter_advances(42, 0), "a reset counter is a regression");
    }

    #[test]
    fn the_challenge_can_be_read_back_before_verification() {
        let json = soft::client_data("webauthn.create", &[9; 40], ORIGIN);
        assert_eq!(client_data_challenge(&json), Some(vec![9; 40]));
        assert_eq!(client_data_challenge(b"{}"), None);
        assert_eq!(client_data_challenge(&vec![b' '; 5000]), None);
    }

    #[test]
    fn errors_have_stable_labels() {
        assert_eq!(WebAuthnError::Origin.label(), "origin");
        assert_eq!(WebAuthnError::UserVerification.label(), "user_verification");
    }
}
