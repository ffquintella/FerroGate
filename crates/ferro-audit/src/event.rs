//! Audit event schema.
//!
//! Every event recorded in FerroGate's audit log is one of these variants.
//! Fields are restricted to hashes, counters, and small identifiers — there
//! is deliberately **no PII** so the log can be replicated and anchored
//! externally without leaking subject information. See `docs/audit.md`.
//!
//! Events are CBOR-encoded for the on-the-wire form and as the input to the
//! Merkle leaf hash. CBOR encoding via `ciborium` is deterministic for a
//! given Rust value, so the same event always hashes to the same leaf — the
//! invariant the inclusion / consistency proofs rely on.

use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes16, Hash384};

/// One audit event.
///
/// The `serde` tag is the variant name under a `"type"` field so an event's
/// type is self-describing inside the CBOR blob (and any JSON dumps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuditEvent {
    /// Phase 2 of a four-phase attestation began.
    AttestStart {
        /// SHA-384 of the EK certificate.
        ek_sha: Hash384,
        /// SHA-384 of the marshaled AIK public area.
        aik_sha: Hash384,
        /// RIM policy generation the boot state was approved under.
        policy_id: String,
    },
    /// An attestation was refused. The reason is a stable opcode string,
    /// never user input — there is no oracle surface here.
    AttestFail {
        /// Short, stable opcode describing why (e.g. `"quote-nonce-mismatch"`).
        reason: String,
    },
    /// An SVID was successfully issued.
    SvidIssued {
        /// SHA-384 of the composite certificate / JWS body.
        cert_sha: Hash384,
        /// Subject SPIFFE ID.
        spiffe_id: String,
    },
    /// An SVID was revoked (admin RPC).
    SvidRevoked {
        /// SHA-384 of the revoked artefact.
        cert_sha: Hash384,
        /// Stable opcode for the revocation reason.
        reason: String,
    },
    /// Every SVID and child token for a host was revoked (admin RPC).
    HostRevoked {
        /// The revoked host SPIFFE ID.
        spiffe_id: String,
        /// Stable opcode for the revocation reason.
        reason: String,
    },
    /// A host passed the F13 fleet-manifest pre-admission check at the start
    /// of `Attest` — its EK certificate hash is enrolled — and was allowed to
    /// proceed to TPM quote verification.
    HostEnrolled {
        /// SHA-384 of the EK certificate presented in phase 2.
        ek_sha: Hash384,
    },
    /// A host was refused at the F13 pre-admission check before any TPM
    /// verification work ran: its EK certificate hash is not in the active
    /// fleet manifest.
    HostRejected {
        /// SHA-384 of the EK certificate presented in phase 2.
        ek_sha: Hash384,
        /// Short, stable opcode (e.g. `"not-enrolled"`).
        reason: String,
    },
    /// The live RIM policy epoch was bumped by an admin RPC (feature F10).
    /// Every host attested under `old_epoch` is forced to fully re-attest on
    /// its next `Rotate`.
    PolicyEpochBumped {
        /// The epoch in force before the bump.
        old_epoch: u64,
        /// The epoch in force after the bump.
        new_epoch: u64,
        /// Short, stable opcode for why (e.g. `"rim-policy-change"`).
        reason: String,
    },
    /// A host's signed caller allowlist was stored or replaced (admin RPC).
    AllowlistSet {
        /// EK-derived host UUID the allowlist is keyed by.
        host_uuid: String,
        /// Number of permitted callers in the new allowlist.
        entry_count: u32,
        /// Hard expiry CMIS stamped, Unix seconds.
        not_after: i64,
    },
    /// A host's stored allowlist was deleted (admin RPC).
    AllowlistDeleted {
        /// EK-derived host UUID whose allowlist was removed.
        host_uuid: String,
    },
    /// A threshold key share was used to reconstruct the issuance key.
    KeyShareUsed {
        /// Which share (0..=4 in the 3-of-5 scheme).
        share_idx: u8,
        /// MRENCLAVE-equivalent of the consuming CMIS replica.
        mrenclave: Hash384,
    },
    /// MIA helper API granted a token to a local process.
    LocalGrant {
        /// Calling process id.
        pid: u32,
        /// Calling user id.
        uid: u32,
        /// IMA SHA-384 of the calling binary.
        bin_sha: Hash384,
        /// Token `jti` (RFC 7519, 128 bits).
        jti: Bytes16,
    },
    /// MIA helper API refused a request.
    LocalDenied {
        /// Calling process id.
        pid: u32,
        /// Calling user id.
        uid: u32,
        /// IMA SHA-384 of the calling binary.
        bin_sha: Hash384,
        /// Short, stable opcode for the refusal.
        reason: String,
    },
}

/// Failure modes for event codec.
#[derive(Debug, thiserror::Error)]
pub enum EventCodecError {
    /// CBOR encoding failed.
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding failed.
    #[error("cbor decode: {0}")]
    Decode(String),
}

/// Encode an event to canonical CBOR bytes.
pub fn encode(event: &AuditEvent) -> Result<Vec<u8>, EventCodecError> {
    let mut out = Vec::with_capacity(128);
    ciborium::into_writer(event, &mut out).map_err(|e| EventCodecError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode an event from CBOR bytes.
pub fn decode(bytes: &[u8]) -> Result<AuditEvent, EventCodecError> {
    ciborium::from_reader(bytes).map_err(|e| EventCodecError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditEvent {
        AuditEvent::SvidIssued {
            cert_sha: Hash384([0xAB; 48]),
            spiffe_id: "spiffe://ferrogate.test/host/abc".to_string(),
        }
    }

    #[test]
    fn cbor_roundtrip_preserves_event() {
        let e = sample();
        let bytes = encode(&e).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn encoding_is_deterministic() {
        let e = sample();
        let a = encode(&e).unwrap();
        let b = encode(&e).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_variants_have_different_encodings() {
        let a = encode(&AuditEvent::AttestFail {
            reason: "rim".into(),
        })
        .unwrap();
        let b = encode(&AuditEvent::SvidRevoked {
            cert_sha: Hash384([0u8; 48]),
            reason: "rim".into(),
        })
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(&[0xFF, 0xFF, 0xFF]).is_err());
    }
}
