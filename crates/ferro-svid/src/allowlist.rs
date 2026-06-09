//! The signed caller allowlist — the on-wire model shared by CMIS (which signs
//! and serves it) and the MIA (which fetches and verifies it).
//!
//! A MIA helper API mints tokens only for `(uid, bin_sha384)` callers present in
//! a signed allowlist. The artefact is a CBOR [`SignedAllowlist`]: a
//! canonical-CBOR [`AllowlistDoc`] body plus a detached composite signature over
//! those exact bytes under [`ALLOWLIST_SIGNING_CONTEXT`]. CBOR gives an
//! unambiguous canonical byte string to sign, matching the rest of FerroGate's
//! signed-artefact idiom.
//!
//! This module owns the wire types plus [`sign`]/[`encode`]/[`decode`]. The
//! issuer-side convenience that stamps the trust domain and signs with the CMIS
//! key is [`crate::Issuer::sign_allowlist`]. The MIA's runtime verifier — which
//! checks freshness and builds the membership set — lives in the `mia` crate and
//! fails closed on any error here.

use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey, CompositeSignature};
use serde::{Deserialize, Serialize};

/// Domain-separation context the allowlist signature covers. Distinct from the
/// SVID and child-token contexts so a signature cannot be reinterpreted.
pub const ALLOWLIST_SIGNING_CONTEXT: &[u8] = b"ferrogate-allowlist-v1";

/// One permitted caller: a uid plus the IMA hash of its binary (hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowEntry {
    /// Permitted user id.
    pub uid: u32,
    /// Lowercase hex `SHA-384` of the permitted binary.
    pub bin_sha: String,
}

/// The signed body: who may call, under which trust domain, and how long the
/// allowlist remains valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistDoc {
    /// Trust domain this allowlist was issued for.
    pub trust_domain: String,
    /// Issuance time, Unix seconds.
    pub issued_at: i64,
    /// Hard expiry, Unix seconds — the server refuses the file past this.
    pub not_after: i64,
    /// Permitted callers.
    pub entries: Vec<AllowEntry>,
}

/// The on-disk/on-wire artefact: a CBOR `AllowlistDoc` body and its signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAllowlist {
    /// Canonical CBOR encoding of the [`AllowlistDoc`].
    pub body: Vec<u8>,
    /// Composite signature (`classical || pqc`) over `body`.
    pub signature: Vec<u8>,
}

/// Allowlist encode/sign/verify failures. On the MIA side every variant denies
/// all callers (fail closed).
#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    /// The outer `SignedAllowlist` or inner `AllowlistDoc` CBOR was malformed.
    #[error("cbor: {0}")]
    Cbor(String),
    /// The signature bytes were not a valid composite signature.
    #[error("malformed signature")]
    MalformedSignature,
    /// The signature did not verify under the trusted key.
    #[error("bad signature")]
    BadSignature,
    /// An entry's `bin_sha` was not 48 bytes of hex.
    #[error("malformed entry hash")]
    MalformedEntry,
    /// `now` is past `not_after`.
    #[error("expired")]
    Expired,
    /// `now` is before `issued_at` (clock skew / not yet valid).
    #[error("not yet valid")]
    NotYetValid,
    /// The allowlist is older than the configured maximum age.
    #[error("too old")]
    TooOld,
}

/// Encode and sign an [`AllowlistDoc`] with `signer`. Used by the CMIS issuer
/// ([`crate::Issuer::sign_allowlist`]) and by tests; the MIA only ever verifies.
pub fn sign(
    doc: &AllowlistDoc,
    signer: &CompositeSecretKey,
) -> Result<SignedAllowlist, AllowlistError> {
    let mut body = Vec::with_capacity(256);
    ciborium::into_writer(doc, &mut body).map_err(|e| AllowlistError::Cbor(e.to_string()))?;
    let sig = signer
        .sign(ALLOWLIST_SIGNING_CONTEXT, &body)
        .map_err(|_| AllowlistError::BadSignature)?;
    Ok(SignedAllowlist {
        body,
        signature: sig.to_concat_bytes(),
    })
}

/// Serialize a [`SignedAllowlist`] to its on-disk/on-wire CBOR bytes.
pub fn encode(signed: &SignedAllowlist) -> Result<Vec<u8>, AllowlistError> {
    let mut out = Vec::with_capacity(signed.body.len() + signed.signature.len() + 32);
    ciborium::into_writer(signed, &mut out).map_err(|e| AllowlistError::Cbor(e.to_string()))?;
    Ok(out)
}

/// Parse the outer [`SignedAllowlist`] from its CBOR bytes. Does **not** verify
/// the signature — the MIA's `Allowlist::load` does that before trusting it.
pub fn decode(bytes: &[u8]) -> Result<SignedAllowlist, AllowlistError> {
    ciborium::from_reader(bytes).map_err(|e| AllowlistError::Cbor(e.to_string()))
}

/// Parse an [`AllowlistDoc`] from a `SignedAllowlist.body`. Used by CMIS to read
/// metadata (entry count, validity) out of an allowlist it already holds; it
/// does not re-verify the signature.
pub fn decode_body(body: &[u8]) -> Result<AllowlistDoc, AllowlistError> {
    ciborium::from_reader(body).map_err(|e| AllowlistError::Cbor(e.to_string()))
}

/// Verify `signed` under `trusted` and return its parsed body. Shared by the
/// MIA runtime verifier; callers layer freshness checks on top.
pub fn verify(
    signed: &SignedAllowlist,
    trusted: &CompositePublicKey,
) -> Result<AllowlistDoc, AllowlistError> {
    let sig = CompositeSignature::from_concat_bytes(&signed.signature)
        .map_err(|_| AllowlistError::MalformedSignature)?;
    trusted
        .verify(ALLOWLIST_SIGNING_CONTEXT, &signed.body, &sig)
        .map_err(|_| AllowlistError::BadSignature)?;
    // Only parse the body *after* the signature checks out.
    decode_body(&signed.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(now: i64) -> AllowlistDoc {
        AllowlistDoc {
            trust_domain: "ferrogate.test".into(),
            issued_at: now,
            not_after: now + 3600,
            entries: vec![AllowEntry {
                uid: 1001,
                bin_sha: hex::encode([0xAA; 48]),
            }],
        }
    }

    #[test]
    fn sign_encode_decode_verify_roundtrip() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let bytes = encode(&sign(&doc(1000), &sk).unwrap()).unwrap();
        let signed = decode(&bytes).unwrap();
        let body = verify(&signed, &pk).unwrap();
        assert_eq!(body.trust_domain, "ferrogate.test");
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].uid, 1001);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (sk, _pk) = CompositeSecretKey::generate().unwrap();
        let (_sk2, pk2) = CompositeSecretKey::generate().unwrap();
        let signed = sign(&doc(1000), &sk).unwrap();
        assert!(matches!(
            verify(&signed, &pk2).unwrap_err(),
            AllowlistError::BadSignature
        ));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let mut signed = sign(&doc(1000), &sk).unwrap();
        signed.body[0] ^= 0xFF;
        assert!(matches!(
            verify(&signed, &pk).unwrap_err(),
            AllowlistError::BadSignature
        ));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(matches!(
            decode(&[0xFF, 0x00, 0x42]).unwrap_err(),
            AllowlistError::Cbor(_)
        ));
    }
}
