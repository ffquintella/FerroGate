//! Wire encoding for issued-SVID records replicated through the Raft cluster.
//!
//! [`IssuedRecord`](crate::state::IssuedRecord) embeds three structs from
//! `ferro-svid` (`IssueParams`, `LastAttestation`, `IssuedSvid`) that each
//! carry `[u8; 48]` fields. `serde`'s derived `Deserialize` does not cover
//! fixed-size arrays of that length, so we cannot just slap `Serialize` /
//! `Deserialize` derives onto the existing types without bleeding a custom
//! visitor through every crate that owns one. Instead this module owns the
//! wire shape: every byte field becomes a hex string, and conversion to and
//! from the runtime types is explicit and total.
//!
//! The payload stored in `issued_svids.payload` is plain JSON. Hiqlite already
//! pays the SQLite cost for replication; JSON gives us a debuggable record at
//! the `sqlite3 hiqlite.db` shell prompt with no extra dependency.

use serde::{Deserialize, Serialize};

use ferro_svid::{IssueParams, IssuedSvid, LastAttestation};

use crate::state::IssuedRecord;

/// Failure modes when (de)serialising the cluster wire form.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// JSON encode / decode error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Hex-encoded byte field had the wrong length or invalid characters.
    #[error("invalid hex field `{field}`: {reason}")]
    Hex {
        /// Which field failed.
        field: &'static str,
        /// Human-readable reason.
        reason: String,
    },
}

/// On-wire shape of an [`IssuedRecord`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireIssuedRecord {
    // IssueParams ---
    /// SHA-384 of the EK certificate, hex-encoded (96 chars).
    pub ek_cert_sha384_hex: String,
    /// PCR aggregate digest at issuance, hex-encoded.
    pub pcr_digest_hex: String,
    /// RIM policy generation id.
    pub policy_id: String,
    /// DPoP key thumbprint.
    pub dpop_jkt: String,
    /// Requested SVID lifetime, seconds.
    pub ttl_secs: u64,
    /// Optional TEE evidence id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_evidence_id: Option<String>,

    // LastAttestation ---
    /// Unix seconds of the last full attestation.
    pub last_attestation_at: i64,
    /// PCR digest at the last full attestation, hex-encoded.
    pub last_pcr_digest_hex: String,
    /// RIM policy epoch in force at the last full attestation.
    pub last_policy_epoch: u64,

    // IssuedSvid ---
    /// Compact JWS bundle.
    pub jws: String,
    /// Subject SPIFFE ID.
    pub spiffe_id: String,
    /// `iat` (Unix seconds).
    pub iat: i64,
    /// `exp` (Unix seconds).
    pub exp: i64,
}

fn hex_48(field: &'static str, s: &str) -> Result<[u8; 48], WireError> {
    let v = hex::decode(s).map_err(|e| WireError::Hex {
        field,
        reason: e.to_string(),
    })?;
    if v.len() != 48 {
        return Err(WireError::Hex {
            field,
            reason: format!("expected 48 bytes, got {}", v.len()),
        });
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&v);
    Ok(out)
}

impl WireIssuedRecord {
    /// Convert a runtime [`IssuedRecord`] into its wire form.
    #[must_use]
    pub fn from_record(r: &IssuedRecord) -> Self {
        Self {
            ek_cert_sha384_hex: hex::encode(r.params.ek_cert_sha384),
            pcr_digest_hex: hex::encode(r.params.pcr_digest),
            policy_id: r.params.policy_id.clone(),
            dpop_jkt: r.params.dpop_jkt.clone(),
            ttl_secs: r.params.ttl_secs,
            tee_evidence_id: r.params.tee_evidence_id.clone(),
            last_attestation_at: r.last_attestation.at,
            last_pcr_digest_hex: hex::encode(r.last_attestation.pcr_digest),
            last_policy_epoch: r.last_attestation.policy_epoch,
            jws: r.bundle.jws.clone(),
            spiffe_id: r.bundle.spiffe_id.clone(),
            iat: r.bundle.iat,
            exp: r.bundle.exp,
        }
    }

    /// Reverse [`Self::from_record`].
    pub fn into_record(self) -> Result<IssuedRecord, WireError> {
        let params = IssueParams {
            ek_cert_sha384: hex_48("ek_cert_sha384_hex", &self.ek_cert_sha384_hex)?,
            pcr_digest: hex_48("pcr_digest_hex", &self.pcr_digest_hex)?,
            policy_id: self.policy_id,
            dpop_jkt: self.dpop_jkt,
            ttl_secs: self.ttl_secs,
            tee_evidence_id: self.tee_evidence_id,
        };
        let last_attestation = LastAttestation {
            at: self.last_attestation_at,
            pcr_digest: hex_48("last_pcr_digest_hex", &self.last_pcr_digest_hex)?,
            policy_epoch: self.last_policy_epoch,
        };
        let bundle = IssuedSvid {
            jws: self.jws,
            spiffe_id: self.spiffe_id,
            iat: self.iat,
            exp: self.exp,
        };
        Ok(IssuedRecord {
            params,
            last_attestation,
            bundle,
        })
    }
}

/// Serialize an [`IssuedRecord`] to the JSON bytes stored in the cluster.
pub fn encode(record: &IssuedRecord) -> Result<Vec<u8>, WireError> {
    let wire = WireIssuedRecord::from_record(record);
    Ok(serde_json::to_vec(&wire)?)
}

/// Inverse of [`encode`].
pub fn decode(bytes: &[u8]) -> Result<IssuedRecord, WireError> {
    let wire: WireIssuedRecord = serde_json::from_slice(bytes)?;
    wire.into_record()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> IssuedRecord {
        IssuedRecord {
            params: IssueParams {
                ek_cert_sha384: [0xABu8; 48],
                pcr_digest: [0x11u8; 48],
                policy_id: "fleet-a".into(),
                dpop_jkt: "thumb".into(),
                ttl_secs: 3600,
                tee_evidence_id: Some("tee-1".into()),
            },
            last_attestation: LastAttestation {
                at: 1_700_000_000,
                pcr_digest: [0x22u8; 48],
                policy_epoch: 7,
            },
            bundle: IssuedSvid {
                jws: "eyJ...".into(),
                spiffe_id: "spiffe://td/host/x".into(),
                iat: 1_700_000_000,
                exp: 1_700_003_600,
            },
        }
    }

    #[test]
    fn roundtrip_through_json() {
        let r = sample_record();
        let bytes = encode(&r).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.params.ek_cert_sha384, r.params.ek_cert_sha384);
        assert_eq!(back.params.pcr_digest, r.params.pcr_digest);
        assert_eq!(back.params.policy_id, r.params.policy_id);
        assert_eq!(back.params.tee_evidence_id, r.params.tee_evidence_id);
        assert_eq!(back.last_attestation.at, r.last_attestation.at);
        assert_eq!(
            back.last_attestation.pcr_digest,
            r.last_attestation.pcr_digest
        );
        assert_eq!(back.bundle.jws, r.bundle.jws);
        assert_eq!(back.bundle.spiffe_id, r.bundle.spiffe_id);
    }

    #[test]
    fn rejects_short_hex() {
        let mut wire = WireIssuedRecord::from_record(&sample_record());
        wire.ek_cert_sha384_hex = "ab".into();
        let bytes = serde_json::to_vec(&wire).unwrap();
        let err = decode(&bytes).unwrap_err();
        match err {
            WireError::Hex { field, .. } => assert_eq!(field, "ek_cert_sha384_hex"),
            WireError::Json(e) => panic!("expected hex error, got json: {e}"),
        }
    }
}
