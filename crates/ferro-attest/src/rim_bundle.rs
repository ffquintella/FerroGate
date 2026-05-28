//! Signed RIM bundle format (feature F10).
//!
//! A [`RimBundle`] describes one RIM generation: a monotonic version, the
//! `policy_id` it stamps into SVIDs, a validity window, and the set of
//! approved aggregate PCR digests. CMIS only ever applies a [`SignedRimBundle`]
//! — i.e. the [`RimBundle`] together with a composite (Ed25519 + ML-DSA-65)
//! signature carried by a trusted publisher key. Unsigned input has no path
//! into the store; this module is the only constructor.
//!
//! The signature covers the **canonical JSON** of the [`RimBundle`] (struct
//! field declaration order, which `serde_json` honours), under the
//! domain-separation context [`RIM_SIGNING_CONTEXT`] so a bundle signature can
//! never be reinterpreted as an SVID or audit-log signature.

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::{
    CompositeError, CompositePublicKey, CompositeSecretKey, CompositeSignature,
};
use serde::{Deserialize, Serialize};

use crate::rim::{PolicyId, RimGeneration};

/// Domain-separation context for RIM signatures. Distinct from the SVID, STH,
/// and child-token contexts.
pub const RIM_SIGNING_CONTEXT: &[u8] = b"ferrogate-rim-v1";

/// The publishable contents of one RIM generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RimBundle {
    /// Monotonic version. New bundles must be strictly greater than the last
    /// applied version (see [`crate::rim::RimStore::apply`]).
    pub version: u64,
    /// Policy generation identifier stamped into every SVID issued under it.
    pub policy_id: String,
    /// Unix-seconds inclusive lower bound.
    pub not_before: i64,
    /// Unix-seconds exclusive upper bound.
    pub not_after: i64,
    /// Approved aggregate PCR digests, lowercase hex (96 chars each).
    pub approved_digests_hex: Vec<String>,
}

impl RimBundle {
    /// Encode this bundle to the canonical JSON form the signature covers.
    /// Field declaration order is the canonical key order.
    pub fn canonical_json(&self) -> Result<Vec<u8>, BundleError> {
        serde_json::to_vec(self).map_err(|e| BundleError::Json(e.to_string()))
    }

    /// Turn the bundle into the in-memory [`RimGeneration`] the store applies.
    /// Each hex digest is validated and decoded to 48 bytes.
    pub fn to_generation(&self) -> Result<RimGeneration, BundleError> {
        let mut approved = HashSet::with_capacity(self.approved_digests_hex.len());
        for (i, h) in self.approved_digests_hex.iter().enumerate() {
            let bytes =
                hex::decode(h).map_err(|e| BundleError::BadDigest(format!("digest[{i}]: {e}")))?;
            if bytes.len() != 48 {
                return Err(BundleError::BadDigest(format!(
                    "digest[{i}]: expected 48 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut d = [0u8; 48];
            d.copy_from_slice(&bytes);
            approved.insert(d);
        }
        Ok(RimGeneration {
            version: self.version,
            policy_id: PolicyId(self.policy_id.clone()),
            not_before: self.not_before,
            not_after: self.not_after,
            approved,
        })
    }
}

/// A [`RimBundle`] paired with a composite signature and a publisher key id.
///
/// The on-disk JSON object is `{ "bundle": …, "signer_kid": …, "signature_b64": … }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRimBundle {
    /// The bundle contents.
    pub bundle: RimBundle,
    /// Key id selecting the publisher key in a [`TrustedKeys`] set.
    pub signer_kid: String,
    /// base64url of the concatenated composite signature.
    pub signature_b64: String,
}

impl SignedRimBundle {
    /// Sign `bundle` with `signer` (intended for test fixtures and the offline
    /// signer tool; production publishers use the F14 ceremony tooling).
    pub fn sign(
        bundle: RimBundle,
        signer_kid: impl Into<String>,
        signer: &CompositeSecretKey,
    ) -> Result<Self, BundleError> {
        let bytes = bundle.canonical_json()?;
        let sig = signer
            .sign(RIM_SIGNING_CONTEXT, &bytes)
            .map_err(BundleError::Sign)?;
        Ok(Self {
            bundle,
            signer_kid: signer_kid.into(),
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_concat_bytes()),
        })
    }

    /// Decode from JSON.
    pub fn from_json(json: &[u8]) -> Result<Self, BundleError> {
        serde_json::from_slice(json).map_err(|e| BundleError::Json(e.to_string()))
    }

    /// Verify the composite signature against the trust set. Returns a borrow
    /// of the inner bundle on success; never returns a bundle without first
    /// authenticating it.
    pub fn verify<'a>(&'a self, trust: &TrustedKeys) -> Result<&'a RimBundle, BundleError> {
        let pk = trust
            .get(&self.signer_kid)
            .ok_or_else(|| BundleError::UnknownKid(self.signer_kid.clone()))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(self.signature_b64.as_bytes())
            .map_err(|e| BundleError::BadSignature(format!("base64url: {e}")))?;
        let sig = CompositeSignature::from_concat_bytes(&sig_bytes)
            .map_err(|e| BundleError::BadSignature(e.to_string()))?;
        let payload = self.bundle.canonical_json()?;
        pk.verify(RIM_SIGNING_CONTEXT, &payload, &sig)
            .map_err(|e| BundleError::BadSignature(e.to_string()))?;
        Ok(&self.bundle)
    }
}

/// Publisher trust anchors: `kid -> CompositePublicKey`. Only bundles signed
/// by a key in this set are accepted; an unknown `signer_kid` is rejected
/// before any cryptographic work.
#[derive(Default)]
pub struct TrustedKeys {
    keys: HashMap<String, CompositePublicKey>,
}

impl TrustedKeys {
    /// An empty trust set. With no keys, every bundle is refused.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted publisher key.
    pub fn add(&mut self, kid: impl Into<String>, pk: CompositePublicKey) {
        self.keys.insert(kid.into(), pk);
    }

    /// Look up a key by id.
    #[must_use]
    pub fn get(&self, kid: &str) -> Option<&CompositePublicKey> {
        self.keys.get(kid)
    }

    /// Number of trusted keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no publisher keys are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Failure modes for bundle encoding / decoding / signing / verification.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// JSON serialization or parsing failed.
    #[error("json: {0}")]
    Json(String),
    /// The composite signer failed.
    #[error("sign: {0}")]
    Sign(#[from] CompositeError),
    /// `signer_kid` is not in the trust set.
    #[error("unknown signer kid: {0}")]
    UnknownKid(String),
    /// The signature decoded but did not verify.
    #[error("bad signature: {0}")]
    BadSignature(String),
    /// An approved digest was not 48 hex bytes.
    #[error("bad digest: {0}")]
    BadDigest(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (CompositeSecretKey, CompositePublicKey) {
        CompositeSecretKey::generate().unwrap()
    }

    #[allow(clippy::cast_possible_truncation)] // small fixture versions fit a u8.
    fn sample_bundle(version: u64) -> RimBundle {
        RimBundle {
            version,
            policy_id: format!("fleet-{version}"),
            not_before: 1_700_000_000,
            not_after: 1_700_086_400,
            approved_digests_hex: vec![hex::encode([version as u8; 48])],
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, pk) = keypair();
        let signed = SignedRimBundle::sign(sample_bundle(1), "publisher-1", &sk).unwrap();
        let mut trust = TrustedKeys::new();
        trust.add("publisher-1", pk);
        let verified = signed.verify(&trust).expect("verify ok");
        assert_eq!(verified.version, 1);
        assert_eq!(verified.policy_id, "fleet-1");
    }

    #[test]
    fn unknown_kid_is_refused_before_crypto() {
        let (sk, _pk) = keypair();
        let signed = SignedRimBundle::sign(sample_bundle(1), "evil", &sk).unwrap();
        let trust = TrustedKeys::new();
        let err = signed.verify(&trust).unwrap_err();
        assert!(matches!(err, BundleError::UnknownKid(_)));
    }

    #[test]
    fn tampered_bundle_fails_signature() {
        let (sk, pk) = keypair();
        let mut signed = SignedRimBundle::sign(sample_bundle(1), "publisher-1", &sk).unwrap();
        signed.bundle.policy_id = "fleet-evil".to_string();
        let mut trust = TrustedKeys::new();
        trust.add("publisher-1", pk);
        let err = signed.verify(&trust).unwrap_err();
        assert!(matches!(err, BundleError::BadSignature(_)));
    }

    #[test]
    fn tampered_signature_fails() {
        let (sk, pk) = keypair();
        let mut signed = SignedRimBundle::sign(sample_bundle(1), "publisher-1", &sk).unwrap();
        // Flip a single base64url char.
        let last = signed.signature_b64.pop().unwrap();
        signed
            .signature_b64
            .push(if last == 'A' { 'B' } else { 'A' });
        let mut trust = TrustedKeys::new();
        trust.add("publisher-1", pk);
        assert!(matches!(
            signed.verify(&trust),
            Err(BundleError::BadSignature(_))
        ));
    }

    #[test]
    fn json_roundtrip_preserves_signature() {
        let (sk, pk) = keypair();
        let signed = SignedRimBundle::sign(sample_bundle(5), "p", &sk).unwrap();
        let blob = serde_json::to_vec(&signed).unwrap();
        let back = SignedRimBundle::from_json(&blob).unwrap();
        let mut trust = TrustedKeys::new();
        trust.add("p", pk);
        back.verify(&trust).expect("verify after json roundtrip");
    }

    #[test]
    fn to_generation_decodes_digests() {
        let bundle = sample_bundle(3);
        let g = bundle.to_generation().unwrap();
        assert_eq!(g.version, 3);
        assert_eq!(g.policy_id.as_str(), "fleet-3");
        assert!(g.approved.contains(&[3u8; 48]));
    }

    #[test]
    fn to_generation_rejects_bad_hex() {
        let mut b = sample_bundle(1);
        b.approved_digests_hex[0] = "not-hex".to_string();
        assert!(matches!(b.to_generation(), Err(BundleError::BadDigest(_))));
    }
}
