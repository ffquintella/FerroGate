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

/// Domain-separation context a host-driven allowlist *proposal* signature
/// covers. Distinct from [`ALLOWLIST_SIGNING_CONTEXT`] so a proposal signed by a
/// host's machine key can never be mistaken for an allowlist signed by the CMIS
/// enrollment key (and vice versa).
pub const PROPOSAL_SIGNING_CONTEXT: &[u8] = b"ferrogate-allowlist-proposal-v1";

/// One permitted caller: the IMA hash of its binary (hex), optionally pinned to
/// a uid.
///
/// `uid = None` permits the binary run by **any** user — the restart-stable mode
/// for callers with an ephemeral uid (systemd `DynamicUser`, sandboxes). `uid =
/// Some(n)` additionally pins the entry to uid `n`. See ADR-0002.
///
/// On the wire (`ciborium`), `Some(n)` encodes as the bare integer `n` — exactly
/// as the historical `u32` field did — so pinned entries stay byte-identical and
/// their signatures unchanged; `None` encodes as CBOR `null`. `#[serde(default)]`
/// lets a body that predates this field (every entry had a uid) decode cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowEntry {
    /// Permitted user id, or `None` to permit the binary run by any user.
    #[serde(default)]
    pub uid: Option<u32>,
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

/// A host-driven proposal of the callers a host observes locally (feature:
/// host-driven allowlist bootstrap). Unlike [`AllowlistDoc`] this is *not* signed
/// by CMIS — the host signs the canonical CBOR with its machine key, and CMIS
/// verifies that signature against the key bound by the proposing SVID's
/// `cnf.jkt` before either auto-adopting it (first-use bootstrap) or queuing it
/// for operator review. CMIS, not the host, stamps the trust domain and validity
/// window when it turns an accepted proposal into a [`SignedAllowlist`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalDoc {
    /// EK/fingerprint-derived host UUID the proposal is for. CMIS rejects the
    /// proposal unless this matches the proposing SVID's host UUID.
    pub host_uuid: String,
    /// Proposal time, Unix seconds — CMIS layers a freshness check on this.
    pub issued_at: i64,
    /// The callers the host observed and proposes to allow.
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

/// Canonical CBOR of a [`ProposalDoc`] — the exact bytes the host signs and CMIS
/// verifies. Kept separate from [`encode`] so the signed proposal body is an
/// unambiguous byte string, matching the allowlist idiom.
pub fn encode_proposal(doc: &ProposalDoc) -> Result<Vec<u8>, AllowlistError> {
    let mut body = Vec::with_capacity(256);
    ciborium::into_writer(doc, &mut body).map_err(|e| AllowlistError::Cbor(e.to_string()))?;
    Ok(body)
}

/// Parse a [`ProposalDoc`] from its canonical CBOR bytes. Does **not** verify the
/// host signature — the caller checks that against the proposing SVID's bound key
/// (see [`proposal_signing_input`]).
pub fn decode_proposal(body: &[u8]) -> Result<ProposalDoc, AllowlistError> {
    ciborium::from_reader(body).map_err(|e| AllowlistError::Cbor(e.to_string()))
}

/// The byte string a host machine key signs (and CMIS verifies) for a proposal:
/// the domain-separation context followed by the canonical CBOR `body`. The host
/// signs this with `ferro_sep::MachineKey::sign` (ECDSA-P256/SHA-256) and CMIS
/// verifies it with `ferro_sep::verify_p256`, so neither crate needs the other's
/// key types — this helper just pins the exact pre-image both sides hash over.
#[must_use]
pub fn proposal_signing_input(body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(PROPOSAL_SIGNING_CONTEXT.len() + body.len());
    input.extend_from_slice(PROPOSAL_SIGNING_CONTEXT);
    input.extend_from_slice(body);
    input
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
                uid: Some(1001),
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
        assert_eq!(body.entries[0].uid, Some(1001));
    }

    /// ADR-0002 compat guard: a pinned (`Some`) uid must encode byte-identically
    /// to the historical bare-`u32` field, so existing signed allowlists keep
    /// verifying. We assert the entry's CBOR is exactly that of a struct whose
    /// `uid` is a plain `u32` — i.e. the integer, not a wrapped/tagged form.
    #[test]
    fn pinned_uid_encodes_as_bare_integer() {
        #[derive(serde::Serialize)]
        struct LegacyEntry {
            uid: u32,
            bin_sha: String,
        }
        let sha = hex::encode([0xAA; 48]);
        let mut new = Vec::new();
        ciborium::into_writer(
            &AllowEntry {
                uid: Some(1001),
                bin_sha: sha.clone(),
            },
            &mut new,
        )
        .unwrap();
        let mut legacy = Vec::new();
        ciborium::into_writer(&LegacyEntry { uid: 1001, bin_sha: sha }, &mut legacy).unwrap();
        assert_eq!(new, legacy, "Some(uid) must match the legacy u32 encoding");
    }

    /// A wildcard (`None`) entry round-trips, and a body that omits the `uid`
    /// field entirely (a pre-field encoding shape) decodes to `None`.
    #[test]
    fn wildcard_uid_roundtrips_and_missing_field_defaults_to_none() {
        let sha = hex::encode([0xCC; 48]);
        let mut buf = Vec::new();
        ciborium::into_writer(
            &AllowEntry {
                uid: None,
                bin_sha: sha.clone(),
            },
            &mut buf,
        )
        .unwrap();
        let back: AllowEntry = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back.uid, None);

        // A map carrying only `bin_sha` (no `uid` key) must default to None.
        #[derive(serde::Serialize)]
        struct OnlySha {
            bin_sha: String,
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&OnlySha { bin_sha: sha }, &mut buf).unwrap();
        let back: AllowEntry = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back.uid, None);
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

    #[test]
    fn proposal_encode_decode_roundtrip() {
        let doc = ProposalDoc {
            host_uuid: "5376139b-0117-8e2d-8049-1ab7b32e7d9a".into(),
            issued_at: 1000,
            entries: vec![AllowEntry {
                uid: Some(501),
                bin_sha: hex::encode([0xAB; 48]),
            }],
        };
        let body = encode_proposal(&doc).unwrap();
        assert_eq!(decode_proposal(&body).unwrap(), doc);
    }

    #[test]
    fn proposal_signing_input_is_context_prefixed_and_distinct() {
        let body = encode_proposal(&ProposalDoc {
            host_uuid: "h".into(),
            issued_at: 1,
            entries: vec![],
        })
        .unwrap();
        let input = proposal_signing_input(&body);
        assert!(input.starts_with(PROPOSAL_SIGNING_CONTEXT));
        assert_eq!(&input[PROPOSAL_SIGNING_CONTEXT.len()..], &body[..]);
        // The proposal context must not collide with the allowlist context.
        assert_ne!(PROPOSAL_SIGNING_CONTEXT, ALLOWLIST_SIGNING_CONTEXT);
    }
}
