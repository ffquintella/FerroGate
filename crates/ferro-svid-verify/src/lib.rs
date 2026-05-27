//! `ferro-svid-verify` — a standalone reference verifier for FerroGate's
//! composite-signed JWS SVIDs (feature F04).
//!
//! This crate is deliberately self-contained: it re-declares the wire schema
//! and pins the wire constants rather than depending on the issuing crate, so
//! it can serve as a copy-pasteable reference for third-party verifiers. Its
//! only dependency beyond serde/base64 is [`ferro_crypto`] for the composite
//! signature primitive itself.
//!
//! Verification is fail-closed and checks, in order: three well-formed
//! segments, a recognised `alg`/`typ`, a `kid` present in the supplied JWK
//! set, a valid composite (Ed25519 **and** ML-DSA-65) signature over the
//! signing input, and finally the `nbf`/`exp` time bounds.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::{CompositePublicKey, CompositeSignature};
use serde::Deserialize;

/// JOSE `alg` this verifier accepts.
pub const SVID_ALG: &str = ferro_crypto::composite::COMPOSITE_JOSE_ALG;

/// JOSE `typ` this verifier accepts.
pub const SVID_TYP: &str = "ferrogate-svid+jwt";

/// Domain-separation context the SVID signature covers.
pub const SVID_SIGNING_CONTEXT: &[u8] = b"ferrogate-svid-v1";

/// JOSE header of an SVID.
#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    /// Signature algorithm.
    pub alg: String,
    /// Token type.
    pub typ: String,
    /// Verification key id.
    pub kid: String,
}

/// DPoP confirmation claim.
#[derive(Debug, Clone, Deserialize)]
pub struct Cnf {
    /// DPoP key thumbprint.
    pub jkt: String,
}

/// Attestation evidence claim.
#[derive(Debug, Clone, Deserialize)]
pub struct AttestClaims {
    /// Hex `SHA-384(ek_cert)`.
    pub ek_cert_sha384: String,
    /// Hex aggregate PCR digest.
    pub pcr_digest_sha384: String,
    /// RIM policy generation.
    pub policy_id: String,
    /// Optional TEE evidence id.
    #[serde(default)]
    pub tee_evidence_id: Option<String>,
}

/// The SVID claim set.
#[derive(Debug, Clone, Deserialize)]
pub struct SvidClaims {
    /// Issuer SPIFFE ID.
    pub iss: String,
    /// Subject SPIFFE ID.
    pub sub: String,
    /// Issued-at.
    pub iat: i64,
    /// Not-before.
    pub nbf: i64,
    /// Expiry.
    pub exp: i64,
    /// DPoP binding.
    pub cnf: Cnf,
    /// Attestation evidence.
    pub attest: AttestClaims,
}

/// One composite verification key.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type.
    pub kty: String,
    /// Key id.
    pub kid: String,
    /// base64url of the concatenated composite public key.
    #[serde(rename = "pub")]
    pub public: String,
}

/// A JWK set.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    /// Keys.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWK set from its JSON form.
    pub fn from_json(s: &str) -> Result<Self, VerifyError> {
        serde_json::from_str(s).map_err(|e| VerifyError::Malformed(e.to_string()))
    }

    fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// A verified SVID: its claims and the key id that signed it.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The validated claims.
    pub claims: SvidClaims,
    /// The key id that produced the signature.
    pub kid: String,
}

/// Why verification failed. The categories let callers distinguish a forged
/// or malformed token from one that is merely expired.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The compact form, base64url, or JSON was malformed.
    #[error("malformed SVID: {0}")]
    Malformed(String),
    /// `alg` or `typ` was not the FerroGate SVID profile.
    #[error("unexpected JOSE header: {0}")]
    UnexpectedHeader(String),
    /// No key in the JWK set matched the header `kid`.
    #[error("no key for kid {0}")]
    UnknownKid(String),
    /// The composite signature did not verify.
    #[error("signature did not verify")]
    BadSignature,
    /// The SVID is not yet valid (`now < nbf`).
    #[error("SVID not yet valid")]
    NotYetValid,
    /// The SVID has expired (`now >= exp`).
    #[error("SVID expired")]
    Expired,
}

/// Verify a compact-JWS SVID against a JWK set at reference time `now`
/// (Unix seconds), allowing `leeway_secs` of clock skew on the time bounds.
#[allow(clippy::similar_names)] // `jws` (the token) and `jwks` (the key set) are the standard names.
pub fn verify(
    jws: &str,
    jwks: &JwkSet,
    now: i64,
    leeway_secs: i64,
) -> Result<Verified, VerifyError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::Malformed(format!(
            "expected 3 segments, got {}",
            parts.len()
        )));
    }

    let header: Header = decode_json(parts[0])?;
    if header.alg != SVID_ALG {
        return Err(VerifyError::UnexpectedHeader(format!("alg={}", header.alg)));
    }
    if header.typ != SVID_TYP {
        return Err(VerifyError::UnexpectedHeader(format!("typ={}", header.typ)));
    }

    let jwk = jwks
        .find(&header.kid)
        .ok_or_else(|| VerifyError::UnknownKid(header.kid.clone()))?;
    if jwk.kty != "FERROGATE-COMPOSITE" {
        return Err(VerifyError::UnexpectedHeader(format!("kty={}", jwk.kty)));
    }
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(jwk.public.as_bytes())
        .map_err(|e| VerifyError::Malformed(format!("jwk pub: {e}")))?;
    let pk = CompositePublicKey::from_concat_bytes(&pk_bytes)
        .map_err(|e| VerifyError::Malformed(format!("jwk pub: {e}")))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|e| VerifyError::Malformed(format!("signature b64: {e}")))?;
    let sig =
        CompositeSignature::from_concat_bytes(&sig_bytes).map_err(|_| VerifyError::BadSignature)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    pk.verify(SVID_SIGNING_CONTEXT, signing_input.as_bytes(), &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    // Signature is good; now the claims can be trusted enough to time-check.
    let claims: SvidClaims = decode_json(parts[1])?;
    if now + leeway_secs < claims.nbf {
        return Err(VerifyError::NotYetValid);
    }
    if now - leeway_secs >= claims.exp {
        return Err(VerifyError::Expired);
    }

    Ok(Verified {
        claims,
        kid: header.kid,
    })
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|e| VerifyError::Malformed(format!("base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| VerifyError::Malformed(format!("json: {e}")))
}
