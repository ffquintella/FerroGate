//! `ferro-svid` — SPIFFE-compatible JWS SVID envelope, issuance, and lifecycle
//! policy for FerroGate (feature F04).
//!
//! CMIS mints short-lived SVIDs after a successful attestation handshake. An
//! SVID is a compact JWS whose signature is a **composite** Ed25519 + ML-DSA-65
//! value (see [`ferro_crypto::composite`]) over the standard JWS signing input.
//!
//! This crate owns:
//!
//! - [`claims`] — the `ferrogate-svid-v1` payload schema.
//! - [`envelope`] — compact-JWS encode/decode and the signing transcript.
//! - [`spiffe`] — SPIFFE-ID derivation from `SHA-384(ek_cert)`.
//! - [`jwks`] — the composite JWK / JWK-set the reference verifier consumes.
//! - [`issue`] — the [`issue::Issuer`] that produces signed SVIDs.
//! - [`lifecycle`] — renewal-vs-re-attestation decisions and the 60%-TTL
//!   rotation scheduler math.
//!
//! The independent reference verifier lives in the `ferro-svid-verify` crate.
//! Both crates pin the same wire constants below; a divergence is a bug.

#![forbid(unsafe_code)]

pub mod claims;
pub mod crl;
pub mod envelope;
pub mod issue;
pub mod jwks;
pub mod lifecycle;
pub mod spiffe;

/// JOSE `alg` carried in every SVID header.
pub const SVID_ALG: &str = ferro_crypto::composite::COMPOSITE_JOSE_ALG;

/// JOSE `typ` marking the FerroGate SVID profile.
pub const SVID_TYP: &str = "ferrogate-svid+jwt";

/// Domain-separation context the composite signature covers. Distinct from
/// other FerroGate artefacts (STHs, child tokens) so a signature cannot be
/// reinterpreted across contexts.
pub const SVID_SIGNING_CONTEXT: &[u8] = b"ferrogate-svid-v1";

/// Maximum SVID lifetime: `exp - iat` may never exceed one hour.
pub const MAX_TTL_SECS: u64 = 3600;

/// `nbf` lookback applied at issuance to tolerate modest host clock skew.
pub const NBF_LOOKBACK_SECS: i64 = 60;

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
