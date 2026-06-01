//! Ceremony minutes, signed by every participant.
//!
//! The minutes are the auditable record of a ceremony: who attended, what root
//! was retired or created, the threshold parameters, and the digests of every
//! artefact produced (the cross-sign bundle, each sealed share, the video
//! recording). Every participant signs the **same** canonical body with their
//! personal composite key; [`SignedMinutes::verify_all`] only succeeds when
//! every listed participant has contributed a valid signature, after which the
//! document is anchored to a WORM medium.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey, CompositeSignature};
use serde::{Deserialize, Serialize};

use crate::{CeremonyError, Result};

/// Domain-separation context for ceremony-minutes signatures.
pub const MINUTES_CONTEXT: &[u8] = b"ferrogate-ceremony-minutes-v1";

/// What kind of ceremony the minutes record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CeremonyKind {
    /// Annual root rotation: a new root is generated and cross-signed.
    Rotation,
    /// Periodic re-split of an unchanged root across fresh shares.
    ShareRefresh,
    /// End-of-window destruction of the outgoing root's shares.
    Destruction,
}

/// One ceremony participant and the personal key they sign minutes with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    /// Operator name.
    pub name: String,
    /// Role / separation-of-duties function (e.g. `share-holder`, `witness`).
    pub role: String,
    /// Personal signing key id.
    pub kid: String,
    /// Personal composite public key, base64 (standard) of the concat encoding.
    pub pubkey: String,
}

/// A labelled digest of an artefact the ceremony produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtefactDigest {
    /// What the digest covers (e.g. `cross-sign-bundle`, `video-recording`).
    pub label: String,
    /// Lowercase-hex `SHA3-256` of the artefact bytes.
    pub sha3_256: String,
}

/// The signed-over body of the ceremony minutes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyMinutes {
    /// Format version.
    pub version: u32,
    /// Unique ceremony identifier (e.g. `rotation-2026`).
    pub ceremony_id: String,
    /// What kind of ceremony this was.
    pub kind: CeremonyKind,
    /// Unix-seconds time the ceremony took place.
    pub occurred_at: i64,
    /// Physical location (e.g. `Faraday room B, DC-1`).
    pub location: String,
    /// SPIFFE trust domain the root serves.
    pub trust_domain: String,
    /// Key id of the root being retired, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_root_kid: Option<String>,
    /// Key id of the root being created, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_root_kid: Option<String>,
    /// Reconstruction threshold.
    pub threshold: usize,
    /// Total shares.
    pub total: usize,
    /// Quorum participants, each of whom must sign.
    pub participants: Vec<Participant>,
    /// Digests of artefacts produced by the ceremony.
    #[serde(default)]
    pub artefacts: Vec<ArtefactDigest>,
    /// Free-text notes (procedure deviations, observations).
    #[serde(default)]
    pub notes: String,
}

impl CeremonyMinutes {
    /// The canonical bytes participants sign — the compact JSON serialization of
    /// the body. Struct field order is fixed, so the encoding is deterministic.
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| CeremonyError::Serde(e.to_string()))
    }

    /// Look up a participant by signing-key id.
    #[must_use]
    pub fn participant(&self, kid: &str) -> Option<&Participant> {
        self.participants.iter().find(|p| p.kid == kid)
    }
}

/// A participant's signature over the minutes body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantSignature {
    /// Signing-key id, matching a [`Participant::kid`].
    pub kid: String,
    /// Composite signature, base64 (standard) of the concat encoding.
    pub sig: String,
}

/// Ceremony minutes plus the accumulated participant signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMinutes {
    /// The signed-over body.
    pub minutes: CeremonyMinutes,
    /// One entry per participant who has signed so far.
    pub signatures: Vec<ParticipantSignature>,
}

impl SignedMinutes {
    /// Start an unsigned record from a body.
    #[must_use]
    pub fn new(minutes: CeremonyMinutes) -> Self {
        Self {
            minutes,
            signatures: Vec::new(),
        }
    }

    /// Append `participant_kid`'s signature over the body.
    ///
    /// The kid must name a listed participant and must not already have signed;
    /// the provided secret key must match that participant's recorded public key.
    pub fn sign(&mut self, participant_kid: &str, sk: &CompositeSecretKey) -> Result<()> {
        let participant =
            self.minutes
                .participant(participant_kid)
                .ok_or_else(|| CeremonyError::Malformed {
                    what: "minutes signature",
                    detail: format!("{participant_kid:?} is not a listed participant"),
                })?;
        if self.signatures.iter().any(|s| s.kid == participant_kid) {
            return Err(CeremonyError::Malformed {
                what: "minutes signature",
                detail: format!("{participant_kid:?} has already signed"),
            });
        }
        // Guard against a key that does not match the recorded participant key,
        // so a stray signature can never validate later.
        let recorded = decode_pub(&participant.pubkey)?;
        let msg = self.minutes.signing_bytes()?;
        let sig = sk
            .sign(MINUTES_CONTEXT, &msg)
            .map_err(|e| CeremonyError::Signature(e.to_string()))?;
        recorded
            .verify(MINUTES_CONTEXT, &msg, &sig)
            .map_err(|_| CeremonyError::Malformed {
                what: "minutes signature",
                detail: format!("key does not match recorded public key for {participant_kid:?}"),
            })?;
        self.signatures.push(ParticipantSignature {
            kid: participant_kid.to_string(),
            sig: STANDARD.encode(sig.to_concat_bytes()),
        });
        Ok(())
    }

    /// Verify that **every** listed participant has contributed exactly one valid
    /// signature over the body. This is the "signed by all participants"
    /// gate before the minutes are written to WORM.
    pub fn verify_all(&self) -> Result<()> {
        let msg = self.minutes.signing_bytes()?;
        for participant in &self.minutes.participants {
            let entry = self
                .signatures
                .iter()
                .find(|s| s.kid == participant.kid)
                .ok_or_else(|| CeremonyError::Signature(format!(
                    "missing signature from {:?}",
                    participant.kid
                )))?;
            let pk = decode_pub(&participant.pubkey)?;
            let sig = decode_sig(&entry.sig)?;
            pk.verify(MINUTES_CONTEXT, &msg, &sig).map_err(|e| {
                CeremonyError::Signature(format!("{:?}: {e}", participant.kid))
            })?;
        }
        // Reject signatures attributed to non-participants.
        for entry in &self.signatures {
            if self.minutes.participant(&entry.kid).is_none() {
                return Err(CeremonyError::Signature(format!(
                    "signature from unlisted participant {:?}",
                    entry.kid
                )));
            }
        }
        Ok(())
    }

    /// How many of the listed participants have signed so far.
    #[must_use]
    pub fn signed_count(&self) -> usize {
        self.minutes
            .participants
            .iter()
            .filter(|p| self.signatures.iter().any(|s| s.kid == p.kid))
            .count()
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| CeremonyError::Serde(e.to_string()))
    }

    /// Parse from JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| CeremonyError::Serde(e.to_string()))
    }
}

fn decode_pub(field: &str) -> Result<CompositePublicKey> {
    let bytes = STANDARD
        .decode(field.as_bytes())
        .map_err(|e| CeremonyError::Malformed {
            what: "participant public key",
            detail: e.to_string(),
        })?;
    CompositePublicKey::from_concat_bytes(&bytes).map_err(|e| CeremonyError::Malformed {
        what: "participant public key",
        detail: e.to_string(),
    })
}

fn decode_sig(field: &str) -> Result<CompositeSignature> {
    let bytes = STANDARD
        .decode(field.as_bytes())
        .map_err(|e| CeremonyError::Malformed {
            what: "participant signature",
            detail: e.to_string(),
        })?;
    CompositeSignature::from_concat_bytes(&bytes).map_err(|e| CeremonyError::Malformed {
        what: "participant signature",
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Op {
        kid: String,
        sk: CompositeSecretKey,
        participant: Participant,
    }

    fn op(n: u8, role: &str) -> Op {
        let (sk, pk) = CompositeSecretKey::from_seed(&[n; 32]);
        let kid = format!("op-{n}");
        Op {
            participant: Participant {
                name: format!("operator-{n}"),
                role: role.to_string(),
                kid: kid.clone(),
                pubkey: STANDARD.encode(pk.to_concat_bytes()),
            },
            kid,
            sk,
        }
    }

    fn minutes(ops: &[Op]) -> CeremonyMinutes {
        CeremonyMinutes {
            version: 1,
            ceremony_id: "rotation-2026".to_string(),
            kind: CeremonyKind::Rotation,
            occurred_at: 1000,
            location: "Faraday room".to_string(),
            trust_domain: "ferrogate.prod".to_string(),
            old_root_kid: Some("root-2025".to_string()),
            new_root_kid: Some("root-2026".to_string()),
            threshold: 3,
            total: 5,
            participants: ops.iter().map(|o| o.participant.clone()).collect(),
            artefacts: Vec::new(),
            notes: String::new(),
        }
    }

    #[test]
    fn all_participants_must_sign() {
        let ops: Vec<Op> = (1..=3).map(|n| op(n, "share-holder")).collect();
        let mut signed = SignedMinutes::new(minutes(&ops));
        // Missing signatures fail.
        assert!(signed.verify_all().is_err());
        for o in &ops {
            signed.sign(&o.kid, &o.sk).unwrap();
        }
        assert_eq!(signed.signed_count(), 3);
        signed.verify_all().unwrap();
        // JSON round-trips and still verifies.
        let parsed = SignedMinutes::from_json(&signed.to_json().unwrap()).unwrap();
        parsed.verify_all().unwrap();
    }

    #[test]
    fn wrong_key_for_a_participant_is_rejected_at_signing() {
        let ops: Vec<Op> = (1..=2).map(|n| op(n, "share-holder")).collect();
        let mut signed = SignedMinutes::new(minutes(&ops));
        // op-2 tries to sign as op-1.
        let err = signed.sign(&ops[0].kid, &ops[1].sk).unwrap_err();
        assert!(matches!(err, CeremonyError::Malformed { .. }));
    }

    #[test]
    fn double_signing_is_rejected() {
        let ops: Vec<Op> = (1..=2).map(|n| op(n, "share-holder")).collect();
        let mut signed = SignedMinutes::new(minutes(&ops));
        signed.sign(&ops[0].kid, &ops[0].sk).unwrap();
        assert!(signed.sign(&ops[0].kid, &ops[0].sk).is_err());
    }

    #[test]
    fn unknown_signer_is_rejected() {
        let ops: Vec<Op> = (1..=2).map(|n| op(n, "share-holder")).collect();
        let mut signed = SignedMinutes::new(minutes(&ops));
        let stranger = op(9, "intruder");
        assert!(signed.sign(&stranger.kid, &stranger.sk).is_err());
    }

    #[test]
    fn editing_the_body_after_signing_breaks_verification() {
        let ops: Vec<Op> = (1..=2).map(|n| op(n, "share-holder")).collect();
        let mut signed = SignedMinutes::new(minutes(&ops));
        for o in &ops {
            signed.sign(&o.kid, &o.sk).unwrap();
        }
        signed.verify_all().unwrap();
        signed.minutes.notes = "tampered".to_string();
        assert!(signed.verify_all().is_err());
    }
}
