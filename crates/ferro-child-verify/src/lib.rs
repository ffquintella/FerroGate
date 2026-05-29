//! `ferro-child-verify` — a standalone reference verifier for FerroGate's
//! DPoP-bound, composite-signed child tokens (feature F09).
//!
//! A child token is minted by the MIA helper API (`crates/mia`, feature F08/F09)
//! with the host's composite SVID key and handed to a host application, which
//! presents it to a third-party API. **This crate is that third party's
//! verifier.** It is deliberately self-contained — it re-declares the wire
//! schema and pins the wire constants rather than depending on the minting
//! crate — so it can serve as a copy-pasteable reference. Its only dependency
//! beyond serde/base64/sha2/ed25519 is [`ferro_crypto`] for the composite
//! signature primitive.
//!
//! Two layers of checking, both fail-closed:
//!
//! 1. [`verify`] validates the token itself — three well-formed segments, the
//!    FerroGate child `alg`/`typ`, a `kid` present in the supplied JWK set, a
//!    valid composite (Ed25519 **and** ML-DSA-65) signature over the signing
//!    input, and finally the `exp` bound.
//! 2. [`verify_bound`] additionally enforces the **DPoP sender constraint**
//!    (RFC 9449): the caller must present a DPoP proof JWS whose key thumbprint
//!    (RFC 7638) equals the token's `cnf.jkt`, and that proof must itself verify
//!    and match the HTTP request. A token presented with **no** DPoP proof is
//!    rejected — a captured bearer token cannot be replayed by a party that does
//!    not hold the DPoP private key.
//!
//! DPoP proofs are expected to use Ed25519 (`alg = "EdDSA"`, an OKP/Ed25519
//! `jwk`). Supporting additional proof algorithms is a localized extension of
//! [`verify_dpop_proof`].

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use ferro_crypto::composite::{CompositePublicKey, CompositeSignature};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// JOSE `alg` this verifier accepts on the child token.
pub const CHILD_ALG: &str = ferro_crypto::composite::COMPOSITE_JOSE_ALG;

/// JOSE `typ` this verifier accepts on the child token.
pub const CHILD_TYP: &str = "ferrogate-child+jwt";

/// Domain-separation context the child-token composite signature covers.
/// Distinct from the SVID, STH, and allowlist contexts.
pub const CHILD_SIGNING_CONTEXT: &[u8] = b"ferrogate-child-token-v1";

/// Key type marker for FerroGate composite verification keys.
pub const COMPOSITE_KTY: &str = "FERROGATE-COMPOSITE";

/// JOSE `typ` of a DPoP proof (RFC 9449).
pub const DPOP_TYP: &str = "dpop+jwt";

/// JOSE `alg` this verifier accepts on a DPoP proof.
pub const DPOP_ALG: &str = "EdDSA";

// ---------------------------------------------------------------------------
// Child-token wire schema (mirror of `mia::helper::token`).
// ---------------------------------------------------------------------------

/// JOSE header of a child token.
#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    /// Signature algorithm.
    pub alg: String,
    /// Token type.
    pub typ: String,
    /// Verification key id selecting the host key in the JWK set.
    pub kid: String,
}

/// DPoP confirmation claim (RFC 9449).
#[derive(Debug, Clone, Deserialize)]
pub struct Cnf {
    /// Base64url SHA-256 thumbprint of the caller's DPoP public JWK.
    pub jkt: String,
}

/// FerroGate provenance block.
#[derive(Debug, Clone, Deserialize)]
pub struct FerrogateClaim {
    /// Hex `SHA-384` of the parent host SVID.
    pub parent_svid: String,
    /// Local actor process id.
    pub actor_pid: u32,
    /// Local actor user id.
    pub actor_uid: u32,
    /// Hex `SHA-384` of the actor binary.
    pub actor_bin: String,
}

/// The child-token claim set (RFC 7519 plus the `ferrogate` block). Unlike an
/// SVID there is no `nbf` — child tokens are valid from issuance.
#[derive(Debug, Clone, Deserialize)]
pub struct ChildClaims {
    /// Issuer — the host SPIFFE id.
    pub iss: String,
    /// Subject — `<host-spiffe-id>#app:<bin_sha[:16]>`.
    pub sub: String,
    /// Audience.
    pub aud: String,
    /// Expiry, Unix seconds.
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// 128-bit token id, hex.
    pub jti: String,
    /// DPoP binding.
    pub cnf: Cnf,
    /// FerroGate provenance.
    pub ferrogate: FerrogateClaim,
}

/// One composite verification key, as served by the CMIS `JWKS` RPC.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type — must be [`COMPOSITE_KTY`].
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

/// A verified child token: its claims and the key id that signed it.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The validated claims.
    pub claims: ChildClaims,
    /// The key id that produced the signature.
    pub kid: String,
}

/// Why verification failed. The categories let callers distinguish a forged or
/// malformed token from one that is merely expired, and a missing DPoP proof
/// (a replayed bearer token) from a mismatched one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The compact form, base64url, or JSON was malformed.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// `alg` or `typ` was not the FerroGate child-token profile.
    #[error("unexpected JOSE header: {0}")]
    UnexpectedHeader(String),
    /// No key in the JWK set matched the header `kid`.
    #[error("no key for kid {0}")]
    UnknownKid(String),
    /// The composite signature did not verify.
    #[error("signature did not verify")]
    BadSignature,
    /// The token has expired (`now >= exp`).
    #[error("token expired")]
    Expired,
    /// No DPoP proof was presented — a bare bearer token is not accepted.
    #[error("missing DPoP proof")]
    MissingDpopProof,
    /// The DPoP proof was malformed or its own signature did not verify.
    #[error("invalid DPoP proof: {0}")]
    DpopProofInvalid(String),
    /// The DPoP proof's `htm`/`htu` did not match the request being made.
    #[error("DPoP proof does not match the request")]
    DpopBindingMismatch,
    /// The DPoP proof key thumbprint did not equal the token's `cnf.jkt`.
    #[error("DPoP key thumbprint does not match cnf.jkt")]
    DpopThumbprintMismatch,
    /// The DPoP proof is outside its acceptable age window.
    #[error("DPoP proof is stale or future-dated")]
    DpopStale,
}

/// Verify a compact-JWS child token against `jwks` at reference time `now`
/// (Unix seconds), allowing `leeway_secs` of clock skew on `exp`.
///
/// This validates the token *only*; it does not enforce the DPoP sender
/// constraint. Use [`verify_bound`] at a resource server that receives a DPoP
/// proof alongside the token.
#[allow(clippy::similar_names)] // `jws` (the token) and `jwks` (the key set).
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
    if header.alg != CHILD_ALG {
        return Err(VerifyError::UnexpectedHeader(format!("alg={}", header.alg)));
    }
    if header.typ != CHILD_TYP {
        return Err(VerifyError::UnexpectedHeader(format!("typ={}", header.typ)));
    }

    let jwk = jwks
        .find(&header.kid)
        .ok_or_else(|| VerifyError::UnknownKid(header.kid.clone()))?;
    if jwk.kty != COMPOSITE_KTY {
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
    pk.verify(CHILD_SIGNING_CONTEXT, signing_input.as_bytes(), &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    // Signature is good; the claims can now be trusted enough to time-check.
    let claims: ChildClaims = decode_json(parts[1])?;
    if now - leeway_secs >= claims.exp {
        return Err(VerifyError::Expired);
    }

    Ok(Verified {
        claims,
        kid: header.kid,
    })
}

/// What the resource server expects a DPoP proof to attest to: the HTTP method
/// and target URI of the request the token is being used on, plus the maximum
/// proof age it will accept (RFC 9449 §4.3).
#[derive(Debug, Clone)]
pub struct DpopExpectation<'a> {
    /// Expected HTTP method, e.g. `"POST"` (compared to the proof's `htm`).
    pub htm: &'a str,
    /// Expected HTTP target URI (compared to the proof's `htu`).
    pub htu: &'a str,
    /// Maximum acceptable age of the proof, in seconds.
    pub max_age_secs: i64,
}

/// A verified DPoP proof: the RFC 7638 thumbprint of the proving key. This is
/// the value that must equal a token's `cnf.jkt`.
#[derive(Debug, Clone)]
pub struct DpopOk {
    /// Base64url SHA-256 JWK thumbprint of the proving key.
    pub jkt: String,
}

// DPoP proof wire schema (the subset this reference verifier reads).

#[derive(Debug, Clone, Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: DpopJwk,
}

#[derive(Debug, Clone, Deserialize)]
struct DpopJwk {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
}

/// Verify a DPoP proof JWS (RFC 9449) and return the proving key's thumbprint.
///
/// Checks, in order: three segments, `typ = "dpop+jwt"` and `alg = "EdDSA"`
/// with an OKP/Ed25519 embedded `jwk`, a valid Ed25519 signature over the proof
/// signing input under that embedded key, the `htm`/`htu` binding to the
/// request, and the `iat` age window.
pub fn verify_dpop_proof(
    proof_jws: &str,
    expect: &DpopExpectation<'_>,
    now: i64,
    leeway_secs: i64,
) -> Result<DpopOk, VerifyError> {
    let parts: Vec<&str> = proof_jws.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::DpopProofInvalid(format!(
            "expected 3 segments, got {}",
            parts.len()
        )));
    }

    let header: DpopHeader = decode_dpop_json(parts[0])?;
    if header.typ != DPOP_TYP {
        return Err(VerifyError::DpopProofInvalid(format!("typ={}", header.typ)));
    }
    if header.alg != DPOP_ALG {
        return Err(VerifyError::DpopProofInvalid(format!("alg={}", header.alg)));
    }
    if header.jwk.kty != "OKP" || header.jwk.crv != "Ed25519" {
        return Err(VerifyError::DpopProofInvalid(format!(
            "jwk kty={} crv={}",
            header.jwk.kty, header.jwk.crv
        )));
    }

    // Reconstruct the Ed25519 verifying key from the embedded `x` member.
    let x_bytes = URL_SAFE_NO_PAD
        .decode(header.jwk.x.as_bytes())
        .map_err(|e| VerifyError::DpopProofInvalid(format!("jwk x b64: {e}")))?;
    let x_arr: [u8; 32] = x_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::DpopProofInvalid("jwk x length".to_string()))?;
    let vk = VerifyingKey::from_bytes(&x_arr)
        .map_err(|e| VerifyError::DpopProofInvalid(format!("jwk x point: {e}")))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|e| VerifyError::DpopProofInvalid(format!("sig b64: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::DpopProofInvalid("sig length".to_string()))?;
    let sig = Signature::from_bytes(&sig_arr);

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    vk.verify_strict(signing_input.as_bytes(), &sig)
        .map_err(|_| VerifyError::DpopProofInvalid("bad proof signature".to_string()))?;

    // The proof signature holds; bind it to this request and check freshness.
    let claims: DpopClaims = decode_dpop_json(parts[1])?;
    if claims.htm != expect.htm || claims.htu != expect.htu {
        return Err(VerifyError::DpopBindingMismatch);
    }
    if claims.iat > now + leeway_secs || claims.iat < now - expect.max_age_secs {
        return Err(VerifyError::DpopStale);
    }

    Ok(DpopOk {
        jkt: jwk_thumbprint_ed25519(&header.jwk.x),
    })
}

/// Verify a child token **and** the DPoP sender constraint that binds it.
///
/// `dpop_proof` is the proof the caller presented alongside the token on this
/// HTTP request. `None` — i.e. a bare bearer token — is rejected with
/// [`VerifyError::MissingDpopProof`]: this is exactly the replay a stolen token
/// would attempt. When a proof is present it must verify, match the request,
/// and carry the key whose thumbprint equals the token's `cnf.jkt`.
#[allow(clippy::similar_names)] // `jws`/`jwks`.
pub fn verify_bound(
    jws: &str,
    jwks: &JwkSet,
    dpop_proof: Option<&str>,
    expect: &DpopExpectation<'_>,
    now: i64,
    leeway_secs: i64,
) -> Result<Verified, VerifyError> {
    let verified = verify(jws, jwks, now, leeway_secs)?;
    let proof = dpop_proof.ok_or(VerifyError::MissingDpopProof)?;
    let ok = verify_dpop_proof(proof, expect, now, leeway_secs)?;
    if ok.jkt != verified.claims.cnf.jkt {
        return Err(VerifyError::DpopThumbprintMismatch);
    }
    Ok(verified)
}

/// Compute the RFC 7638 JWK thumbprint of an Ed25519 (OKP) public key given its
/// base64url `x` coordinate.
///
/// The thumbprint is the base64url-no-pad SHA-256 over the JWK's required
/// members in lexicographic order with no whitespace:
/// `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`.
#[must_use]
pub fn jwk_thumbprint_ed25519(x_b64url: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64url}"}}"#);
    let digest = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|e| VerifyError::Malformed(format!("base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| VerifyError::Malformed(format!("json: {e}")))
}

fn decode_dpop_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|e| VerifyError::DpopProofInvalid(format!("base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| VerifyError::DpopProofInvalid(format!("json: {e}")))
}
