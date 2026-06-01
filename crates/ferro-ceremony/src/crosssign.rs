//! Cross-signing flow producing both directions of artefact.
//!
//! During the 90-day rotation window the outgoing ("old") root and the incoming
//! ("new") root vouch for each other: the old root signs the new root's public
//! key, and the new root signs the old root's. A relying party that trusts
//! *either* root can therefore bridge to the other, so SVIDs signed under the
//! old key keep validating while the fleet migrates to the new one.
//!
//! Both signatures cover a domain-separated transcript binding **both** key ids,
//! **both** public keys, and the window bounds, so a signature cannot be lifted
//! onto a different key pair or replayed into a different window.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey, CompositeSignature};
use serde::{Deserialize, Serialize};

use crate::{CeremonyError, Result};

/// Domain-separation context for cross-sign transcripts.
pub const CROSSSIGN_CONTEXT: &[u8] = b"ferrogate-root-crosssign-v1";

/// Default cross-sign window: 90 days in seconds.
pub const DEFAULT_WINDOW_SECS: i64 = 90 * 24 * 60 * 60;

/// Which way a cross-signature points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossSignDirection {
    /// The outgoing root signs the incoming root's public key.
    OldSignsNew,
    /// The incoming root signs the outgoing root's public key.
    NewSignsOld,
}

/// A bundle carrying both directions of a root cross-signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSignBundle {
    /// Format version.
    pub version: u32,
    /// Outgoing root key id.
    pub old_kid: String,
    /// Outgoing root public key, base64 (standard) of the concat encoding.
    pub old_pub: String,
    /// Incoming root key id.
    pub new_kid: String,
    /// Incoming root public key, base64 (standard) of the concat encoding.
    pub new_pub: String,
    /// Window start, Unix seconds.
    pub window_start: i64,
    /// Window end, Unix seconds (exclusive).
    pub window_end: i64,
    /// Old-signs-new composite signature, base64 of the concat encoding.
    pub old_signs_new: String,
    /// New-signs-old composite signature, base64 of the concat encoding.
    pub new_signs_old: String,
}

/// Canonical, length-prefixed transcript a cross-signature covers. `signer_*`
/// is the key producing the signature; `subject_*` is the key being vouched for.
fn transcript(
    signer_kid: &str,
    signer_pub: &[u8],
    subject_kid: &str,
    subject_pub: &[u8],
    window_start: i64,
    window_end: i64,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    field(signer_kid.as_bytes());
    field(signer_pub);
    field(subject_kid.as_bytes());
    field(subject_pub);
    field(&window_start.to_be_bytes());
    field(&window_end.to_be_bytes());
    out
}

impl CrossSignBundle {
    /// Cross-sign the old and new roots for `[window_start, window_start +
    /// window_secs)`. Both secret keys are needed because both directions are
    /// produced in the one air-gapped sitting.
    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    pub fn create(
        old_sk: &CompositeSecretKey,
        old_kid: impl Into<String>,
        old_pk: &CompositePublicKey,
        new_sk: &CompositeSecretKey,
        new_kid: impl Into<String>,
        new_pk: &CompositePublicKey,
        window_start: i64,
        window_secs: i64,
    ) -> Result<Self> {
        let old_kid = old_kid.into();
        let new_kid = new_kid.into();
        let old_bytes = old_pk.to_concat_bytes();
        let new_bytes = new_pk.to_concat_bytes();
        let window_end = window_start.saturating_add(window_secs);

        let old_signs_new = old_sk
            .sign(
                CROSSSIGN_CONTEXT,
                &transcript(&old_kid, &old_bytes, &new_kid, &new_bytes, window_start, window_end),
            )
            .map_err(|e| CeremonyError::Signature(e.to_string()))?;
        let new_signs_old = new_sk
            .sign(
                CROSSSIGN_CONTEXT,
                &transcript(&new_kid, &new_bytes, &old_kid, &old_bytes, window_start, window_end),
            )
            .map_err(|e| CeremonyError::Signature(e.to_string()))?;

        Ok(Self {
            version: 1,
            old_kid,
            old_pub: STANDARD.encode(&old_bytes),
            new_kid,
            new_pub: STANDARD.encode(&new_bytes),
            window_start,
            window_end,
            old_signs_new: STANDARD.encode(old_signs_new.to_concat_bytes()),
            new_signs_old: STANDARD.encode(new_signs_old.to_concat_bytes()),
        })
    }

    fn decode_pub(field: &str) -> Result<CompositePublicKey> {
        let bytes = STANDARD
            .decode(field.as_bytes())
            .map_err(|e| CeremonyError::Malformed {
                what: "cross-sign public key",
                detail: e.to_string(),
            })?;
        CompositePublicKey::from_concat_bytes(&bytes).map_err(|e| CeremonyError::Malformed {
            what: "cross-sign public key",
            detail: e.to_string(),
        })
    }

    fn decode_sig(field: &str) -> Result<CompositeSignature> {
        let bytes = STANDARD
            .decode(field.as_bytes())
            .map_err(|e| CeremonyError::Malformed {
                what: "cross-sign signature",
                detail: e.to_string(),
            })?;
        CompositeSignature::from_concat_bytes(&bytes).map_err(|e| CeremonyError::Malformed {
            what: "cross-sign signature",
            detail: e.to_string(),
        })
    }

    /// Verify one direction of the bundle.
    #[allow(clippy::similar_names)]
    pub fn verify_direction(&self, dir: CrossSignDirection) -> Result<()> {
        let old_pk = Self::decode_pub(&self.old_pub)?;
        let new_pk = Self::decode_pub(&self.new_pub)?;
        let old_bytes = old_pk.to_concat_bytes();
        let new_bytes = new_pk.to_concat_bytes();
        let (verifier, sig_field, signer_kid, signer_pub, subject_kid, subject_pub) = match dir {
            CrossSignDirection::OldSignsNew => (
                &old_pk,
                &self.old_signs_new,
                &self.old_kid,
                &old_bytes,
                &self.new_kid,
                &new_bytes,
            ),
            CrossSignDirection::NewSignsOld => (
                &new_pk,
                &self.new_signs_old,
                &self.new_kid,
                &new_bytes,
                &self.old_kid,
                &old_bytes,
            ),
        };
        let sig = Self::decode_sig(sig_field)?;
        let msg = transcript(
            signer_kid,
            signer_pub,
            subject_kid,
            subject_pub,
            self.window_start,
            self.window_end,
        );
        verifier
            .verify(CROSSSIGN_CONTEXT, &msg, &sig)
            .map_err(|e| CeremonyError::Signature(format!("{dir:?}: {e}")))
    }

    /// Verify **both** directions. The bundle is only sound when each root has
    /// vouched for the other.
    pub fn verify(&self) -> Result<()> {
        self.verify_direction(CrossSignDirection::OldSignsNew)?;
        self.verify_direction(CrossSignDirection::NewSignsOld)?;
        Ok(())
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

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;

    fn keypair(tag: u8) -> (CompositeSecretKey, CompositePublicKey) {
        CompositeSecretKey::from_seed(&[tag; 32])
    }

    #[test]
    fn both_directions_verify() {
        let (old_sk, old_pk) = keypair(1);
        let (new_sk, new_pk) = keypair(2);
        let bundle = CrossSignBundle::create(
            &old_sk, "root-2025", &old_pk, &new_sk, "root-2026", &new_pk, 1000, DEFAULT_WINDOW_SECS,
        )
        .unwrap();
        bundle.verify().unwrap();
        assert_eq!(bundle.window_end, 1000 + DEFAULT_WINDOW_SECS);
        let parsed = CrossSignBundle::from_json(&bundle.to_json().unwrap()).unwrap();
        parsed.verify().unwrap();
    }

    #[test]
    fn a_tampered_window_breaks_both_signatures() {
        let (old_sk, old_pk) = keypair(1);
        let (new_sk, new_pk) = keypair(2);
        let mut bundle = CrossSignBundle::create(
            &old_sk, "root-2025", &old_pk, &new_sk, "root-2026", &new_pk, 1000, DEFAULT_WINDOW_SECS,
        )
        .unwrap();
        bundle.window_end += 1;
        assert!(bundle.verify_direction(CrossSignDirection::OldSignsNew).is_err());
        assert!(bundle.verify_direction(CrossSignDirection::NewSignsOld).is_err());
    }

    #[test]
    fn a_swapped_signature_does_not_verify() {
        let (old_sk, old_pk) = keypair(1);
        let (new_sk, new_pk) = keypair(2);
        let mut bundle = CrossSignBundle::create(
            &old_sk, "root-2025", &old_pk, &new_sk, "root-2026", &new_pk, 1000, DEFAULT_WINDOW_SECS,
        )
        .unwrap();
        // Put the new-signs-old signature into the old-signs-new slot.
        bundle.old_signs_new = bundle.new_signs_old.clone();
        assert!(bundle.verify().is_err());
    }
}
