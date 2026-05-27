//! The `ferrogate-svid-v1` JWS payload schema (see `docs/protocol.md` §"Phase 4").

use serde::{Deserialize, Serialize};

/// DPoP confirmation claim binding the SVID to a proof-of-possession key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    /// JWK SHA-256 thumbprint of the DPoP public key, base64url (RFC 7638).
    pub jkt: String,
}

/// Boot-state and hardware evidence recorded in the SVID at issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestClaims {
    /// Lowercase hex `SHA-384(ek_cert_der)`.
    pub ek_cert_sha384: String,
    /// Lowercase hex of the aggregate PCR digest the RIM approved.
    pub pcr_digest_sha384: String,
    /// The RIM policy generation the boot state was approved under.
    pub policy_id: String,
    /// TEE evidence identifier, when CMIS ran in an attested enclave. `None`
    /// in the M2 single-replica configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_evidence_id: Option<String>,
}

/// The full SVID claim set. Field order matches the documented schema; serde
/// is configured to omit nothing except an absent `tee_evidence_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvidClaims {
    /// Issuer SPIFFE ID, e.g. `spiffe://ferrogate.prod/cmis`.
    pub iss: String,
    /// Subject SPIFFE ID, e.g. `spiffe://ferrogate.prod/host/<uuid>`.
    pub sub: String,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Not-before, Unix seconds (issued with a [`crate::NBF_LOOKBACK_SECS`] lookback).
    pub nbf: i64,
    /// Expiry, Unix seconds. `exp - iat` never exceeds [`crate::MAX_TTL_SECS`].
    pub exp: i64,
    /// DPoP binding.
    pub cnf: Cnf,
    /// Attestation evidence.
    pub attest: AttestClaims,
}
