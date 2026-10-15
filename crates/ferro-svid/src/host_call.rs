//! Host call documents — the signed body of a host-authenticated RPC
//! (feature F19 §7.1 `HostCallAuth`, first used by `AppendAuditEvent` in F20
//! Phase 0).
//!
//! A host proves who is calling by signing a small canonical-CBOR document with
//! its **machine key** (the ECDSA-P256 key its SVID is bound to through
//! `cnf.jkt`). The signature covers `context ‖ doc`, where `context` names the
//! RPC (for example [`AUDIT_FORWARD_CONTEXT`]) so a signature made for one RPC
//! can never be replayed against another. Every document carries the host
//! UUID, an `issued_at` timestamp and, for the RPCs that need replay
//! protection, a random 16-byte nonce; CMIS checks the UUID against the SVID,
//! the timestamp against its clock (±300 s) and the nonce against a replay
//! cache.
//!
//! This module owns the wire shape both sides share: MIA builds and signs the
//! document, CMIS (`cmis::host_auth`) verifies it. Neither side needs the
//! other's key types: the host signs [`signing_input`] with
//! `ferro_sep::MachineKey::sign` and CMIS verifies with
//! `ferro_sep::verify_p256`, exactly as for allowlist proposals.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

use crate::cbor_bytes::fixed as fixed_bytes;

/// Signing context of the `AppendAuditEvent` host proof (F20 Phase 0).
/// Distinct from every other FerroGate context and prefix-free with them.
pub const AUDIT_FORWARD_CONTEXT: &[u8] = b"ferrogate-audit-forward-v1";

/// The only document version this build reads or writes.
pub const DOC_VERSION: u8 = 1;

/// Length of the replay-protection nonce.
pub const NONCE_LEN: usize = 16;

/// Upper bound on an encoded host call document. The audit-forward document
/// is about 140 bytes; anything larger is refused before it is parsed.
pub const MAX_DOC_BYTES: usize = 1024;

/// Upper bound on `host_uuid` (F19 §7.2).
pub const MAX_HOST_UUID_LEN: usize = 64;

/// What CMIS needs from any host call document, whatever RPC it belongs to.
pub trait HostCallDoc {
    /// The host the document claims to come from; must equal the SVID's.
    fn host_uuid(&self) -> &str;
    /// Unix seconds the host signed the document.
    fn issued_at(&self) -> i64;
    /// The replay-protection nonce, for RPCs that are not otherwise
    /// idempotent. `None` skips the replay cache.
    fn nonce(&self) -> Option<&[u8; NONCE_LEN]>;
}

/// The document a host signs to forward one audit event (`AppendAuditEvent`).
///
/// It binds the event by digest (`event_sha384 = SHA-384(event_cbor)`) rather
/// than embedding it, so the event bytes travel once and the signed document
/// stays small.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditForwardDoc {
    /// Document version, [`DOC_VERSION`].
    pub v: u8,
    /// EK-derived host UUID; must equal the presenting SVID's.
    pub host_uuid: String,
    /// Unix seconds the host signed the document.
    pub issued_at: i64,
    /// Random replay-protection nonce.
    #[serde(with = "fixed_bytes")]
    pub nonce: [u8; NONCE_LEN],
    /// SHA-384 of the forwarded `event_cbor`.
    #[serde(with = "fixed_bytes")]
    pub event_sha384: [u8; 48],
}

impl AuditForwardDoc {
    /// A document forwarding `event_cbor` from `host_uuid`.
    #[must_use]
    pub fn new(
        host_uuid: impl Into<String>,
        issued_at: i64,
        nonce: [u8; NONCE_LEN],
        event_cbor: &[u8],
    ) -> Self {
        let mut event_sha384 = [0u8; 48];
        event_sha384.copy_from_slice(&Sha384::digest(event_cbor));
        Self {
            v: DOC_VERSION,
            host_uuid: host_uuid.into(),
            issued_at,
            nonce,
            event_sha384,
        }
    }

    /// Whether this document signs exactly `event_cbor`.
    #[must_use]
    pub fn binds_event(&self, event_cbor: &[u8]) -> bool {
        Sha384::digest(event_cbor).as_slice() == self.event_sha384
    }
}

impl HostCallDoc for AuditForwardDoc {
    fn host_uuid(&self) -> &str {
        &self.host_uuid
    }

    fn issued_at(&self) -> i64 {
        self.issued_at
    }

    fn nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        Some(&self.nonce)
    }
}

/// Failure modes for host call documents.
#[derive(Debug, thiserror::Error)]
pub enum HostCallDocError {
    /// CBOR encoding failed.
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding failed, or a field has the wrong shape.
    #[error("cbor decode: {0}")]
    Decode(String),
    /// The encoded document exceeds [`MAX_DOC_BYTES`].
    #[error("document too large ({0} bytes)")]
    TooLarge(usize),
    /// The document version is not [`DOC_VERSION`].
    #[error("unsupported document version {0}")]
    Version(u8),
    /// `host_uuid` is empty or longer than [`MAX_HOST_UUID_LEN`].
    #[error("host_uuid is empty or too long")]
    HostUuid,
}

/// Encode an [`AuditForwardDoc`] to the canonical CBOR the host signs.
///
/// # Errors
/// [`HostCallDocError::Encode`] if CBOR serialisation fails.
pub fn encode_audit_forward(doc: &AuditForwardDoc) -> Result<Vec<u8>, HostCallDocError> {
    let mut out = Vec::with_capacity(160);
    ciborium::into_writer(doc, &mut out).map_err(|e| HostCallDocError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode and validate an [`AuditForwardDoc`]: size bound, known fields only,
/// version 1, a non-empty `host_uuid` of at most 64 bytes.
///
/// # Errors
/// Any [`HostCallDocError`] variant describing the first check that failed.
pub fn decode_audit_forward(bytes: &[u8]) -> Result<AuditForwardDoc, HostCallDocError> {
    if bytes.len() > MAX_DOC_BYTES {
        return Err(HostCallDocError::TooLarge(bytes.len()));
    }
    let doc: AuditForwardDoc =
        ciborium::from_reader(bytes).map_err(|e| HostCallDocError::Decode(e.to_string()))?;
    if doc.v != DOC_VERSION {
        return Err(HostCallDocError::Version(doc.v));
    }
    if doc.host_uuid.is_empty() || doc.host_uuid.len() > MAX_HOST_UUID_LEN {
        return Err(HostCallDocError::HostUuid);
    }
    Ok(doc)
}

/// The byte string a host machine key signs (and CMIS verifies) for a host
/// call: `context` followed by the encoded document.
#[must_use]
pub fn signing_input(context: &[u8], doc: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(context.len() + doc.len());
    input.extend_from_slice(context);
    input.extend_from_slice(doc);
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> AuditForwardDoc {
        AuditForwardDoc::new("8d5e-host", 1_700_000_000, [7u8; 16], b"event bytes")
    }

    #[test]
    fn audit_forward_doc_round_trips() {
        let d = doc();
        let bytes = encode_audit_forward(&d).unwrap();
        assert!(bytes.len() < 200, "small document: {} bytes", bytes.len());
        assert_eq!(decode_audit_forward(&bytes).unwrap(), d);
    }

    #[test]
    fn the_doc_binds_the_event_by_sha384() {
        let d = doc();
        assert_eq!(d.v, 1);
        assert_eq!(
            hex::encode(d.event_sha384),
            hex::encode(Sha384::digest(b"event bytes"))
        );
        assert!(d.binds_event(b"event bytes"));
        assert!(!d.binds_event(b"event bytez"));
        assert!(!d.binds_event(b""));
    }

    #[test]
    fn byte_fields_are_cbor_byte_strings() {
        let bytes = encode_audit_forward(&doc()).unwrap();
        // 0x50 = byte string of length 16 (the nonce); 0x58 0x30 = byte
        // string of length 48 (the digest).
        assert!(bytes
            .windows(17)
            .any(|w| w[0] == 0x50 && w[1..] == [7u8; 16]));
        assert!(bytes.windows(2).any(|w| w == [0x58, 0x30]));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        #[derive(Serialize)]
        struct WithUnknownField {
            v: u8,
            host_uuid: String,
            issued_at: i64,
            #[serde(with = "fixed_bytes")]
            nonce: [u8; 16],
            #[serde(with = "fixed_bytes")]
            event_sha384: [u8; 48],
            unknown: u8,
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &WithUnknownField {
                v: 1,
                host_uuid: "h".into(),
                issued_at: 1,
                nonce: [0; 16],
                event_sha384: [0; 48],
                unknown: 1,
            },
            &mut bytes,
        )
        .unwrap();
        assert!(matches!(
            decode_audit_forward(&bytes),
            Err(HostCallDocError::Decode(_))
        ));
    }

    #[test]
    fn other_versions_and_bad_host_uuids_are_rejected() {
        let mut d = doc();
        d.v = 2;
        let bytes = encode_audit_forward(&d).unwrap();
        assert!(matches!(
            decode_audit_forward(&bytes),
            Err(HostCallDocError::Version(2))
        ));

        let mut d = doc();
        d.host_uuid = String::new();
        let bytes = encode_audit_forward(&d).unwrap();
        assert!(matches!(
            decode_audit_forward(&bytes),
            Err(HostCallDocError::HostUuid)
        ));

        let mut d = doc();
        d.host_uuid = "h".repeat(65);
        let bytes = encode_audit_forward(&d).unwrap();
        assert!(matches!(
            decode_audit_forward(&bytes),
            Err(HostCallDocError::HostUuid)
        ));
    }

    #[test]
    fn wrong_length_byte_fields_and_oversize_docs_are_rejected() {
        #[derive(Serialize)]
        struct Short {
            v: u8,
            host_uuid: String,
            issued_at: i64,
            #[serde(with = "fixed_bytes")]
            nonce: [u8; 8],
            #[serde(with = "fixed_bytes")]
            event_sha384: [u8; 48],
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &Short {
                v: 1,
                host_uuid: "h".into(),
                issued_at: 1,
                nonce: [0; 8],
                event_sha384: [0; 48],
            },
            &mut bytes,
        )
        .unwrap();
        assert!(matches!(
            decode_audit_forward(&bytes),
            Err(HostCallDocError::Decode(_))
        ));

        let big = vec![0u8; MAX_DOC_BYTES + 1];
        assert!(matches!(
            decode_audit_forward(&big),
            Err(HostCallDocError::TooLarge(_))
        ));
    }

    #[test]
    fn signing_input_is_context_prefixed() {
        let body = encode_audit_forward(&doc()).unwrap();
        let input = signing_input(AUDIT_FORWARD_CONTEXT, &body);
        assert!(input.starts_with(AUDIT_FORWARD_CONTEXT));
        assert_eq!(&input[AUDIT_FORWARD_CONTEXT.len()..], &body[..]);
    }

    /// The audit-forward context differs from, and is prefix-free with, every
    /// other signing context in this crate (the same guarantee
    /// `proposal_signing_input` has), so no signature can be reinterpreted.
    #[test]
    fn the_audit_forward_context_is_distinct_and_prefix_free() {
        let others: [&[u8]; 5] = [
            crate::SVID_SIGNING_CONTEXT,
            crate::ALLOWLIST_SIGNING_CONTEXT,
            crate::PROPOSAL_SIGNING_CONTEXT,
            crate::CRL_SIGNING_CONTEXT,
            crate::X509_ALT_SIGNATURE_CONTEXT,
        ];
        assert_eq!(AUDIT_FORWARD_CONTEXT, b"ferrogate-audit-forward-v1");
        for o in others {
            assert_ne!(AUDIT_FORWARD_CONTEXT, o);
            assert!(!AUDIT_FORWARD_CONTEXT.starts_with(o), "{o:?}");
            assert!(!o.starts_with(AUDIT_FORWARD_CONTEXT), "{o:?}");
        }
    }
}
