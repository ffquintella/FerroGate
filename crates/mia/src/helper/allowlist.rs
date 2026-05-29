//! The signed caller allowlist.
//!
//! Only `(uid, bin_sha384)` pairs present in the allowlist may obtain a token.
//! The allowlist is signed by CMIS at host enrollment and re-verified before
//! use; verification **fails closed** — any decode, signature, or freshness
//! error yields no usable allowlist, so the server denies every caller rather
//! than fall back to an unauthenticated state.
//!
//! On-disk form is a CBOR [`SignedAllowlist`]: a canonical-CBOR-encoded
//! [`AllowlistDoc`] body plus a detached composite signature over those exact
//! bytes under [`ALLOWLIST_SIGNING_CONTEXT`]. CBOR (rather than the TOML the
//! prose docs sketch) gives an unambiguous canonical byte string to sign,
//! matching the rest of FerroGate's signed-artefact idiom.

use std::collections::HashSet;

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

/// The on-disk artefact: a CBOR `AllowlistDoc` body and its composite signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAllowlist {
    /// Canonical CBOR encoding of the [`AllowlistDoc`].
    pub body: Vec<u8>,
    /// Composite signature (`classical || pqc`) over `body`.
    pub signature: Vec<u8>,
}

/// Allowlist load/verify failures. Every variant denies all callers.
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

/// A verified, in-memory allowlist ready for `O(1)` membership checks.
#[derive(Debug, Clone)]
pub struct Allowlist {
    trust_domain: String,
    not_after: i64,
    members: HashSet<(u32, [u8; 48])>,
}

impl Allowlist {
    /// Verify and load a [`SignedAllowlist`] from its CBOR bytes.
    ///
    /// `trusted` is the CMIS enrollment public key; `now` is the reference
    /// clock; `max_age_secs` bounds how stale the file may be (`issued_at`).
    /// Any failure is fatal and fails closed.
    pub fn load(
        bytes: &[u8],
        trusted: &CompositePublicKey,
        now: i64,
        max_age_secs: i64,
    ) -> Result<Self, AllowlistError> {
        let signed: SignedAllowlist =
            ciborium::from_reader(bytes).map_err(|e| AllowlistError::Cbor(e.to_string()))?;

        let sig = CompositeSignature::from_concat_bytes(&signed.signature)
            .map_err(|_| AllowlistError::MalformedSignature)?;
        trusted
            .verify(ALLOWLIST_SIGNING_CONTEXT, &signed.body, &sig)
            .map_err(|_| AllowlistError::BadSignature)?;

        // Only parse the body *after* the signature checks out.
        let doc: AllowlistDoc = ciborium::from_reader(&signed.body[..])
            .map_err(|e| AllowlistError::Cbor(e.to_string()))?;

        if now < doc.issued_at {
            return Err(AllowlistError::NotYetValid);
        }
        if now > doc.not_after {
            return Err(AllowlistError::Expired);
        }
        if now - doc.issued_at > max_age_secs {
            return Err(AllowlistError::TooOld);
        }

        let mut members = HashSet::with_capacity(doc.entries.len());
        for e in &doc.entries {
            let raw = hex::decode(&e.bin_sha).map_err(|_| AllowlistError::MalformedEntry)?;
            let arr: [u8; 48] = raw.try_into().map_err(|_| AllowlistError::MalformedEntry)?;
            members.insert((e.uid, arr));
        }

        Ok(Self {
            trust_domain: doc.trust_domain,
            not_after: doc.not_after,
            members,
        })
    }

    /// Is `(uid, bin_sha)` permitted?
    #[must_use]
    pub fn permits(&self, uid: u32, bin_sha: &[u8; 48]) -> bool {
        self.members.contains(&(uid, *bin_sha))
    }

    /// The trust domain the allowlist was issued for.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Hard expiry of the allowlist, Unix seconds.
    #[must_use]
    pub fn not_after(&self) -> i64 {
        self.not_after
    }
}

/// Encode and sign an [`AllowlistDoc`] with `signer`. Used by the enrollment
/// tooling and by tests; the MIA itself only ever *verifies*.
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

/// Serialize a [`SignedAllowlist`] to its on-disk CBOR bytes.
pub fn encode(signed: &SignedAllowlist) -> Result<Vec<u8>, AllowlistError> {
    let mut out = Vec::with_capacity(signed.body.len() + signed.signature.len() + 32);
    ciborium::into_writer(signed, &mut out).map_err(|e| AllowlistError::Cbor(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (CompositeSecretKey, CompositePublicKey) {
        CompositeSecretKey::generate().unwrap()
    }

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

    fn signed_bytes(doc: &AllowlistDoc, sk: &CompositeSecretKey) -> Vec<u8> {
        encode(&sign(doc, sk).unwrap()).unwrap()
    }

    #[test]
    fn valid_allowlist_loads_and_permits_listed_caller() {
        let (sk, pk) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        let al = Allowlist::load(&bytes, &pk, 1000, 86_400).unwrap();
        assert!(al.permits(1001, &[0xAA; 48]));
        assert!(!al.permits(1001, &[0xBB; 48]));
        assert!(!al.permits(2002, &[0xAA; 48]));
        assert_eq!(al.trust_domain(), "ferrogate.test");
    }

    #[test]
    fn wrong_key_fails_closed() {
        let (sk, _pk) = keypair();
        let (_sk2, pk2) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        let err = Allowlist::load(&bytes, &pk2, 1000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::BadSignature));
    }

    #[test]
    fn tampered_body_fails_closed() {
        let (sk, pk) = keypair();
        let mut signed = sign(&doc(1000), &sk).unwrap();
        // Flip a byte in the signed body; the signature no longer matches.
        signed.body[0] ^= 0xFF;
        let bytes = encode(&signed).unwrap();
        let err = Allowlist::load(&bytes, &pk, 1000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::BadSignature));
    }

    #[test]
    fn expired_allowlist_is_rejected() {
        let (sk, pk) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        // not_after = 4600; now past it.
        let err = Allowlist::load(&bytes, &pk, 5000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::Expired));
    }

    #[test]
    fn too_old_allowlist_is_rejected() {
        let (sk, pk) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        // within not_after (issued 1000, not_after 4600) but issued long ago.
        let err = Allowlist::load(&bytes, &pk, 4000, 60).unwrap_err();
        assert!(matches!(err, AllowlistError::TooOld));
    }

    #[test]
    fn garbage_bytes_fail_closed() {
        let (_sk, pk) = keypair();
        let err = Allowlist::load(&[0xFF, 0x00, 0x42], &pk, 1000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::Cbor(_)));
    }
}
