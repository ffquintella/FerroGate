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

use ferro_svid::{IssueParams, IssuedSvid, LastAttestation, X509Svid};

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

    /// Self-reported hostname captured at the last full attestation (display
    /// only). Optional with a default so records written before the field
    /// existed still decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// The host's composite CSR key, hex-encoded concat bytes — the subject key
    /// the X.509-SVID profile binds its leaf to. Optional with a default so
    /// records written before the profile existed still decode; such a record
    /// renews with the JWS profile only, until the host next attests.
    ///
    /// This is the same key as [`Self::child_pub_hex`]; the two are kept
    /// separate because they answer to different consumers (JWKS publication
    /// versus certificate issuance) and either may be absent on an old record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_pub_hex: Option<String>,

    /// The issued X.509-SVID leaf certificate, hex-encoded DER.
    ///
    /// Stored rather than re-derived: the leaf's ML-DSA-65 half is signed with
    /// FIPS-204's hedged (randomised) variant, so re-issuing would produce a
    /// *different* certificate for the same identity — and a replica must serve
    /// the byte-exact certificate the host holds. The trust bundle is not stored
    /// beside it because it *is* reproducible from the issuer key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_leaf_der_hex: Option<String>,

    /// The host's composite child-token signing key (F09), hex-encoded concat
    /// bytes. Persisting it here lets any replica — and any restarted
    /// instance — republish the key into the JWKS by `kid` on startup, so a
    /// child token does not fail verification with `no key for kid host-…`
    /// just because the issuing CMIS process is not the one that witnessed the
    /// attestation. Optional with a default so records written before the field
    /// existed (and SVIDs whose CSR key was malformed) still decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_pub_hex: Option<String>,
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
            hostname: r.hostname.clone(),
            subject_pub_hex: r.params.subject_pub.as_ref().map(hex::encode),
            x509_leaf_der_hex: r.bundle.x509.as_ref().map(|x| hex::encode(&x.leaf_der)),
            child_pub_hex: r.child_pub.as_ref().map(hex::encode),
        }
    }

    /// Reverse [`Self::from_record`].
    pub fn into_record(self) -> Result<IssuedRecord, WireError> {
        let subject_pub = match &self.subject_pub_hex {
            Some(h) => Some(hex::decode(h).map_err(|e| WireError::Hex {
                field: "subject_pub_hex",
                reason: e.to_string(),
            })?),
            None => None,
        };
        let params = IssueParams {
            ek_cert_sha384: hex_48("ek_cert_sha384_hex", &self.ek_cert_sha384_hex)?,
            pcr_digest: hex_48("pcr_digest_hex", &self.pcr_digest_hex)?,
            policy_id: self.policy_id,
            dpop_jkt: self.dpop_jkt,
            ttl_secs: self.ttl_secs,
            tee_evidence_id: self.tee_evidence_id,
            subject_pub,
        };
        let last_attestation = LastAttestation {
            at: self.last_attestation_at,
            pcr_digest: hex_48("last_pcr_digest_hex", &self.last_pcr_digest_hex)?,
            policy_epoch: self.last_policy_epoch,
        };
        // The certificate's own metadata is not stored: it is exactly what the
        // issuer derived from the JWS window (`ferro_svid::Issuer::issue`), so
        // reproducing it here keeps the two profiles from drifting apart.
        let x509 = match &self.x509_leaf_der_hex {
            Some(h) => Some(X509Svid {
                leaf_der: hex::decode(h).map_err(|e| WireError::Hex {
                    field: "x509_leaf_der_hex",
                    reason: e.to_string(),
                })?,
                spiffe_id: self.spiffe_id.clone(),
                not_before: self.iat - ferro_svid::NBF_LOOKBACK_SECS,
                not_after: self.exp,
            }),
            None => None,
        };
        let bundle = IssuedSvid {
            jws: self.jws,
            x509,
            spiffe_id: self.spiffe_id,
            iat: self.iat,
            exp: self.exp,
        };
        let child_pub = match self.child_pub_hex {
            Some(h) => Some(hex::decode(&h).map_err(|e| WireError::Hex {
                field: "child_pub_hex",
                reason: e.to_string(),
            })?),
            None => None,
        };
        Ok(IssuedRecord {
            params,
            last_attestation,
            bundle,
            hostname: self.hostname,
            child_pub,
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
        let subject_pub = ferro_crypto::composite::CompositeSecretKey::from_seed(&[0x5a; 32])
            .1
            .to_concat_bytes();
        IssuedRecord {
            params: IssueParams {
                ek_cert_sha384: [0xABu8; 48],
                pcr_digest: [0x11u8; 48],
                policy_id: "fleet-a".into(),
                dpop_jkt: "thumb".into(),
                ttl_secs: 3600,
                tee_evidence_id: Some("tee-1".into()),
                subject_pub: Some(subject_pub),
            },
            last_attestation: LastAttestation {
                at: 1_700_000_000,
                pcr_digest: [0x22u8; 48],
                policy_epoch: 7,
            },
            bundle: IssuedSvid {
                jws: "eyJ...".into(),
                x509: Some(X509Svid {
                    leaf_der: vec![0x30, 0x82, 0x01, 0x02],
                    spiffe_id: "spiffe://td/host/x".into(),
                    not_before: 1_700_000_000 - ferro_svid::NBF_LOOKBACK_SECS,
                    not_after: 1_700_003_600,
                }),
                spiffe_id: "spiffe://td/host/x".into(),
                iat: 1_700_000_000,
                exp: 1_700_003_600,
            },
            hostname: Some("segdc1vds0005".into()),
            child_pub: Some(vec![0xCD; 1984]),
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
        assert_eq!(back.hostname, r.hostname);
        assert_eq!(back.child_pub, r.child_pub);

        // Both profiles survive replication: the certificate byte-for-byte, and
        // the subject key it is bound to so a rotation can re-issue it.
        assert_eq!(back.bundle.x509, r.bundle.x509);
        assert_eq!(back.params.subject_pub, r.params.subject_pub);
    }

    #[test]
    fn a_record_written_before_the_x509_profile_still_decodes() {
        // Forward compatibility in the replicated store: a row persisted by an
        // older CMIS has neither field, and must decode to "JWS profile only"
        // rather than failing the whole rehydrate.
        let mut wire =
            serde_json::to_value(WireIssuedRecord::from_record(&sample_record())).expect("encode");
        let obj = wire.as_object_mut().unwrap();
        obj.remove("subject_pub_hex");
        obj.remove("x509_leaf_der_hex");

        let back = decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
        assert!(back.params.subject_pub.is_none());
        assert!(back.bundle.x509.is_none());
        assert_eq!(back.bundle.jws, "eyJ...");
    }

    #[test]
    fn decodes_record_written_before_child_pub_existed() {
        let mut wire =
            serde_json::to_value(WireIssuedRecord::from_record(&sample_record())).unwrap();
        wire.as_object_mut().unwrap().remove("child_pub_hex");
        let bytes = serde_json::to_vec(&wire).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.child_pub, None);
    }

    #[test]
    fn rejects_invalid_child_pub_hex() {
        let mut wire = WireIssuedRecord::from_record(&sample_record());
        wire.child_pub_hex = Some("zz".into());
        let bytes = serde_json::to_vec(&wire).unwrap();
        match decode(&bytes).unwrap_err() {
            WireError::Hex { field, .. } => assert_eq!(field, "child_pub_hex"),
            WireError::Json(e) => panic!("expected hex error, got json: {e}"),
        }
    }

    #[test]
    fn decodes_record_written_before_hostname_existed() {
        let mut wire =
            serde_json::to_value(WireIssuedRecord::from_record(&sample_record())).unwrap();
        wire.as_object_mut().unwrap().remove("hostname");
        let bytes = serde_json::to_vec(&wire).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.hostname, None);
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
