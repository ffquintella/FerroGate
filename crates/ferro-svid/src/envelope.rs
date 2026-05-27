//! Compact-JWS encoding for SVIDs.
//!
//! Layout: `BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)`.
//! The composite signature covers the ASCII signing input
//! `BASE64URL(header) "." BASE64URL(payload)` under context
//! [`crate::SVID_SIGNING_CONTEXT`].

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::claims::SvidClaims;

/// The JOSE header of an SVID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsHeader {
    /// Signature algorithm — always [`crate::SVID_ALG`].
    pub alg: String,
    /// Token type — always [`crate::SVID_TYP`].
    pub typ: String,
    /// Key id selecting the verification key in the JWKS.
    pub kid: String,
}

impl JwsHeader {
    /// Build the standard SVID header for a given signing key id.
    #[must_use]
    pub fn new(kid: impl Into<String>) -> Self {
        Self {
            alg: crate::SVID_ALG.to_string(),
            typ: crate::SVID_TYP.to_string(),
            kid: kid.into(),
        }
    }
}

/// Errors from encoding or decoding a compact JWS.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// JSON (header or payload) failed to serialize/deserialize.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The compact form did not have exactly three dot-separated segments.
    #[error("malformed compact JWS: expected 3 segments, got {0}")]
    Segments(usize),
    /// A base64url segment failed to decode.
    #[error("base64url: {0}")]
    Base64(String),
}

/// Compute the ASCII signing input for a header/claims pair.
pub fn signing_input(header: &JwsHeader, claims: &SvidClaims) -> Result<String, EnvelopeError> {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?);
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    Ok(format!("{h}.{p}"))
}

/// Assemble the final compact JWS from a signing input and the raw composite
/// signature bytes (`classical(64) || pqc(3309)`).
#[must_use]
pub fn compact(signing_input: &str, signature_concat: &[u8]) -> String {
    let s = URL_SAFE_NO_PAD.encode(signature_concat);
    format!("{signing_input}.{s}")
}

/// A decoded (but not yet verified) compact JWS.
#[derive(Debug, Clone)]
pub struct DecodedJws {
    /// Parsed header.
    pub header: JwsHeader,
    /// Parsed claims.
    pub claims: SvidClaims,
    /// The ASCII signing input the signature covers.
    pub signing_input: String,
    /// Raw signature bytes (`classical || pqc`).
    pub signature: Vec<u8>,
}

/// Parse a compact JWS into its parts without verifying the signature.
pub fn decode(jws: &str) -> Result<DecodedJws, EnvelopeError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(EnvelopeError::Segments(parts.len()));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| EnvelopeError::Base64(e.to_string()))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| EnvelopeError::Base64(e.to_string()))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| EnvelopeError::Base64(e.to_string()))?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)?;
    let claims: SvidClaims = serde_json::from_slice(&payload_bytes)?;
    Ok(DecodedJws {
        header,
        claims,
        signing_input: format!("{}.{}", parts[0], parts[1]),
        signature,
    })
}
