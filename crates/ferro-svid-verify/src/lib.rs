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
use sha2::{Digest, Sha384};

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
    /// Unix-seconds creation time, present when more than one root is published
    /// during a cross-sign window; used by [`JwkSet::preferred`] (feature F14).
    #[serde(rename = "x-ferrogate-created", default)]
    pub created: Option<i64>,
}

impl Jwk {
    /// Reconstruct the composite public key carried by this JWK.
    fn to_public_key(&self) -> Result<CompositePublicKey, VerifyError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(self.public.as_bytes())
            .map_err(|e| VerifyError::Malformed(format!("jwk pub: {e}")))?;
        CompositePublicKey::from_concat_bytes(&bytes)
            .map_err(|e| VerifyError::Malformed(format!("jwk pub: {e}")))
    }
}

/// A JWK set, optionally carrying FerroGate's CRL (feature F11) in the
/// `x-ferrogate-crl` extension member.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    /// Keys.
    pub keys: Vec<Jwk>,
    /// The composite-signed revocation list, when published.
    #[serde(rename = "x-ferrogate-crl", default)]
    pub crl: Option<SignedCrl>,
}

impl JwkSet {
    /// Parse a JWK set from its JSON form.
    pub fn from_json(s: &str) -> Result<Self, VerifyError> {
        serde_json::from_str(s).map_err(|e| VerifyError::Malformed(e.to_string()))
    }

    fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// The preferred key under "newer preferred" ordering: the one with the
    /// greatest `created` timestamp (absent counts as oldest), ties resolving to
    /// the first in publication order. A reference consumer uses this to pick
    /// the trust anchor when CMIS publishes both roots during a cross-sign
    /// rotation window (feature F14). `None` only for an empty set.
    #[must_use]
    pub fn preferred(&self) -> Option<&Jwk> {
        self.keys
            .iter()
            .enumerate()
            .max_by_key(|(i, k)| (k.created.unwrap_or(i64::MIN), std::cmp::Reverse(*i)))
            .map(|(_, k)| k)
    }
}

// ---- CRL (feature F11) -----------------------------------------------------
//
// Re-declared here, like the rest of the schema, so the reference verifier
// stays self-contained. The field order matches `ferro_svid::crl` exactly
// because the composite signature covers the canonical JSON (declaration
// order), and `serde_json` honours it.

/// Domain-separation context the CRL signature covers.
pub const CRL_SIGNING_CONTEXT: &[u8] = b"ferrogate-crl-v1";

/// Maximum CRL age (seconds) a verifier will trust.
pub const CRL_MAX_AGE_SECS: i64 = 300;

/// What a revocation targets. Both `Serialize` and `Deserialize` so the signed
/// body can be parsed from the JWKS and re-serialised byte-for-byte to recompute
/// the canonical JSON the signature covers.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevocationTarget {
    /// A single SVID by lowercase-hex `SHA-384(jws_bytes)`.
    Svid {
        /// The revoked SVID's `cert_sha`.
        cert_sha: String,
    },
    /// Every SVID/child token for a host SPIFFE id.
    Host {
        /// The revoked host SPIFFE id.
        spiffe_id: String,
    },
}

/// One revocation record.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CrlEntry {
    /// What is revoked.
    pub target: RevocationTarget,
    /// Stable reason opcode.
    pub reason: String,
    /// Unix seconds the revocation took effect.
    pub revoked_at: i64,
    /// Unix seconds after which the entry may be pruned.
    pub expires_at: i64,
}

/// The signable contents of one CRL.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CrlBody {
    /// Unix seconds the CRL was produced.
    pub issued_at: i64,
    /// Monotonic publish sequence number.
    pub number: u64,
    /// The active revocation entries.
    pub entries: Vec<CrlEntry>,
}

impl CrlBody {
    fn revokes_svid(&self, cert_sha_hex: &str) -> bool {
        self.entries.iter().any(|e| {
            matches!(&e.target, RevocationTarget::Svid { cert_sha } if cert_sha.eq_ignore_ascii_case(cert_sha_hex))
        })
    }
    fn revokes_host(&self, spiffe_id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(&e.target, RevocationTarget::Host { spiffe_id: s } if s == spiffe_id))
    }
    fn is_fresh(&self, now: i64, leeway_secs: i64) -> bool {
        let age = now - self.issued_at;
        age <= CRL_MAX_AGE_SECS && age >= -leeway_secs
    }
}

/// A [`CrlBody`] with the issuer's composite signature.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedCrl {
    /// The CRL contents.
    pub body: CrlBody,
    /// Key id selecting the issuer key in the JWK set.
    pub signer_kid: String,
    /// base64url of the concatenated composite signature.
    pub signature_b64: String,
}

impl SignedCrl {
    /// Verify the CRL signature against the keys in `jwks`. Fail-closed.
    fn verify<'a>(&'a self, jwks: &JwkSet) -> Result<&'a CrlBody, VerifyError> {
        let jwk = jwks.find(&self.signer_kid).ok_or_else(|| {
            VerifyError::CrlInvalid(format!("unknown signer kid {}", self.signer_kid))
        })?;
        let pk = jwk.to_public_key()?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(self.signature_b64.as_bytes())
            .map_err(|e| VerifyError::CrlInvalid(format!("signature b64: {e}")))?;
        let sig = CompositeSignature::from_concat_bytes(&sig_bytes)
            .map_err(|e| VerifyError::CrlInvalid(e.to_string()))?;
        let payload = serde_json::to_vec(&self.body)
            .map_err(|e| VerifyError::CrlInvalid(format!("canonical json: {e}")))?;
        pk.verify(CRL_SIGNING_CONTEXT, &payload, &sig)
            .map_err(|_| VerifyError::CrlInvalid("signature did not verify".to_string()))?;
        Ok(&self.body)
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
    /// No fresh CRL was available to make a revocation decision (feature F11).
    /// The CRL was absent or older than [`CRL_MAX_AGE_SECS`]; a revocation-aware
    /// verifier fails closed rather than treat a missing CRL as "not revoked".
    #[error("CRL missing or stale")]
    CrlStale,
    /// The CRL was present but its signature was malformed or did not verify.
    #[error("CRL invalid: {0}")]
    CrlInvalid(String),
    /// The SVID (or its host) is named in the CRL.
    #[error("SVID revoked")]
    Revoked,
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

/// Verify an SVID **and** check it against the CRL carried in the JWK set
/// (feature F11). On success the SVID's signature and time bounds hold *and* it
/// is not revoked.
///
/// Fail-closed revocation policy: a revocation decision requires a fresh,
/// signature-valid CRL in `jwks`. If the CRL is absent or older than
/// [`CRL_MAX_AGE_SECS`], this returns [`VerifyError::CrlStale`]; if its
/// signature does not verify, [`VerifyError::CrlInvalid`]. A revoked SVID (by
/// its `cert_sha` — the lowercase-hex `SHA-384` of the compact JWS — or by its
/// `sub` host SPIFFE id) returns [`VerifyError::Revoked`].
#[allow(clippy::similar_names)]
pub fn verify_unrevoked(
    jws: &str,
    jwks: &JwkSet,
    now: i64,
    leeway_secs: i64,
) -> Result<Verified, VerifyError> {
    let verified = verify(jws, jwks, now, leeway_secs)?;

    // A revocation decision is only possible against a fresh, authentic CRL.
    let signed = jwks.crl.as_ref().ok_or(VerifyError::CrlStale)?;
    let body = signed.verify(jwks)?;
    if !body.is_fresh(now, leeway_secs) {
        return Err(VerifyError::CrlStale);
    }

    let cert_sha = hex::encode(Sha384::digest(jws.as_bytes()));
    if body.revokes_svid(&cert_sha) || body.revokes_host(&verified.claims.sub) {
        return Err(VerifyError::Revoked);
    }
    Ok(verified)
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|e| VerifyError::Malformed(format!("base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| VerifyError::Malformed(format!("json: {e}")))
}
