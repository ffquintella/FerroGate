//! `ferro-svid` — SPIFFE-compatible JWS SVID envelope, issuance, and lifecycle
//! policy for FerroGate (feature F04).
//!
//! CMIS mints short-lived SVIDs after a successful attestation handshake. An
//! SVID is a compact JWS whose signature is a **composite** Ed25519 + ML-DSA-65
//! value (see [`ferro_crypto::composite`]) over the standard JWS signing input.
//!
//! This crate owns:
//!
//! - [`allowlist`] — the signed caller-allowlist wire model CMIS serves and the
//!   MIA verifies (format v1, unchanged).
//! - [`allowlist_v2`] — allowlist format v2 (ADR-0004): host-bound, with a
//!   generation and per-entry uid / SID-hash / path-hash / expiry
//!   constraints, under its own signing context; `path_hash` and `sid_hash`.
//! - [`app_docs`] — the host-signed documents of `SubmitAppRequest`,
//!   `GetAppRequestStatus` and `SyncAllowlist` (F19 §7).
//! - [`claims`] — the `ferrogate-svid-v1` payload schema.
//! - [`envelope`] — compact-JWS encode/decode and the signing transcript.
//! - [`host_call`] — the signed documents of host-authenticated RPCs (F19
//!   §7.1 `HostCallAuth`; `AppendAuditEvent` since F20 Phase 0).
//! - [`spiffe`] — SPIFFE-ID derivation from `SHA-384(ek_cert)`.
//! - [`jwks`] — the composite JWK / JWK-set the reference verifier consumes.
//! - [`issue`] — the [`issue::Issuer`] that produces signed SVIDs.
//! - [`lifecycle`] — renewal-vs-re-attestation decisions and the 60%-TTL
//!   rotation scheduler math.
//! - [`x509`] — the **X.509-SVID profile**: a SPIFFE X509-SVID leaf, issued
//!   from the same attestation and the same issuer key as the JWS, whose native
//!   signature is standard Ed25519 (so any TLS stack validates it) and whose
//!   ML-DSA-65 half rides in the ITU-T X.509 alternative-signature extensions.
//!
//! The independent reference verifier lives in the `ferro-svid-verify` crate.
//! Both crates pin the same wire constants below; a divergence is a bug.

#![forbid(unsafe_code)]

pub mod allowlist;
pub mod allowlist_v2;
pub mod app_docs;
mod cbor_bytes;
pub mod claims;
pub mod crl;
pub mod envelope;
pub mod host_call;
pub mod issue;
pub mod jwks;
pub mod lifecycle;
pub mod spiffe;
pub mod x509;

/// JOSE `alg` carried in every SVID header.
pub const SVID_ALG: &str = ferro_crypto::composite::COMPOSITE_JOSE_ALG;

/// JOSE `typ` marking the FerroGate JWS SVID profile.
pub const SVID_TYP: &str = "ferrogate-svid+jwt";

/// Domain-separation context the composite signature covers. Distinct from
/// other FerroGate artefacts (STHs, child tokens) so a signature cannot be
/// reinterpreted across contexts.
pub const SVID_SIGNING_CONTEXT: &[u8] = b"ferrogate-svid-v1";

/// Maximum SVID lifetime: `exp - iat` may never exceed 30 days.
pub const MAX_TTL_SECS: u64 = 30 * 24 * 3600;

/// Floor FerroGate enforces on operator-configurable signature TTLs (SVIDs and
/// caller-allowlists): 96 hours. Values supplied via the environment are
/// clamped up to this so a misconfiguration cannot mint near-expired artefacts.
pub const MIN_TTL_SECS: u64 = 96 * 3600;

/// `nbf` lookback applied at issuance to tolerate modest host clock skew.
pub const NBF_LOOKBACK_SECS: i64 = 60;

pub use allowlist::{
    AllowEntry, AllowlistDoc, AllowlistError, ProposalDoc, SignedAllowlist,
    ALLOWLIST_SIGNING_CONTEXT, PROPOSAL_SIGNING_CONTEXT,
};
pub use allowlist_v2::{
    path_hash, sid_hash, AllowEntryV2, AllowlistDocV2, AllowlistV2Error,
    ALLOWLIST_V2_SIGNING_CONTEXT,
};
pub use app_docs::{
    AllowlistSyncDoc, AppDocError, AppRequestDoc, AppStatusDoc, ALLOWLIST_SYNC_CONTEXT,
    APP_REQUEST_CONTEXT, APP_STATUS_CONTEXT,
};
pub use claims::{AttestClaims, Cnf, SvidClaims};
pub use crl::{
    CrlBody, CrlEntry, CrlError, RevocationTarget, SignedCrl, CRL_ENTRY_TTL_SECS, CRL_MAX_AGE_SECS,
    CRL_SIGNING_CONTEXT,
};
pub use issue::{IssueError, IssueParams, IssuedSvid, Issuer};
pub use jwks::{child_signing_kid, Jwk, JwkSet};
pub use lifecycle::{
    decide_renewal, rotation_at, rotation_delay_secs, LastAttestation, ReattestReason,
    RenewalDecision, REATTEST_WINDOW_SECS, ROTATE_FRACTION,
};
pub use spiffe::{host_uuid_from_ek_digest, spiffe_host_id, spiffe_issuer_id, SpiffeError};
pub use x509::{X509Error, X509Svid, ALT_SIGNATURE_CONTEXT as X509_ALT_SIGNATURE_CONTEXT};

#[cfg(test)]
mod context_tests {
    /// Every signing context is distinct from, and prefix-free with, every
    /// other: a signature over `context ‖ document` can never be replayed
    /// under another context (F19 §7.1).
    #[test]
    fn signing_contexts_are_pairwise_prefix_free() {
        let all: [&[u8]; 11] = [
            crate::SVID_SIGNING_CONTEXT,
            crate::ALLOWLIST_SIGNING_CONTEXT,
            crate::ALLOWLIST_V2_SIGNING_CONTEXT,
            crate::PROPOSAL_SIGNING_CONTEXT,
            crate::CRL_SIGNING_CONTEXT,
            crate::X509_ALT_SIGNATURE_CONTEXT,
            crate::host_call::AUDIT_FORWARD_CONTEXT,
            crate::host_call::ROTATE_CONTEXT,
            crate::APP_REQUEST_CONTEXT,
            crate::APP_STATUS_CONTEXT,
            crate::ALLOWLIST_SYNC_CONTEXT,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "{a:?} / {b:?}");
                }
            }
        }
        assert_eq!(
            crate::ALLOWLIST_V2_SIGNING_CONTEXT,
            b"ferrogate-allowlist-v2"
        );
        assert_eq!(crate::APP_REQUEST_CONTEXT, b"ferrogate-app-request-v1");
        assert_eq!(crate::APP_STATUS_CONTEXT, b"ferrogate-app-status-v1");
        assert_eq!(
            crate::ALLOWLIST_SYNC_CONTEXT,
            b"ferrogate-allowlist-sync-v1"
        );
    }
}
