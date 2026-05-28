//! Quorum co-signed Signed Tree Heads (M4 / F07-continued).
//!
//! In an HA CMIS cluster, an STH must be co-signed by a Raft majority before
//! publication so that no single node — even a compromised one — can issue an
//! STH the rest of the cluster has not seen. The body itself is the same
//! canonical CBOR encoding of [`SthBody`] used by the single-signer flow; what
//! changes is that the on-wire artefact carries *multiple* independent
//! composite signatures (one per co-signing replica), and a verifier accepts
//! the artefact only when at least `threshold` distinct, listed signers
//! produce a valid signature over the exact `body_cbor`.
//!
//! The signatures themselves are independent — there is no MPC, no
//! aggregation. The threshold property is purely combinatorial: an attacker
//! who controls fewer than `threshold` of the listed replicas cannot publish.
//!
//! Distribution is out of scope here: in deployment each peer signs locally
//! and the proposer forwards the resulting [`CoSignature`]s over the
//! `ferro-raft` peer transport. The aggregator below is the local-process
//! seam ([`QuorumSigner`]) — it composes any number of [`SthSigner`]
//! trait objects and is the same call pattern the cluster path will use once
//! peer transport is wired through `cmis::cluster_store`.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::{CompositePublicKey, CompositeSignature};
use serde::{Deserialize, Serialize};

use crate::sth::{encode_body, SignedTreeHead, SthBody, SthError, SthSigner, STH_SIGNING_CONTEXT};

/// A single replica's composite signature over the canonical `body_cbor`.
///
/// The same `signer_kid` namespace is used as for single-signer STHs
/// ([`SignedTreeHead::signer_kid`]); a verifier looks `signer_kid` up in its
/// configured keyset and applies that key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoSignature {
    /// Key id selecting the verification key for this signature.
    pub signer_kid: String,
    /// base64url of the concatenated composite signature (Ed25519 || ML-DSA-65).
    pub signature_b64: String,
}

/// A Raft-majority co-signed tree head.
///
/// `body_cbor` is the exact canonical CBOR encoding of [`SthBody`] that every
/// listed signature covers under the same domain-separation context
/// [`STH_SIGNING_CONTEXT`] as the single-signer flow. The artefact is
/// considered valid only when at least the configured threshold of the
/// listed signatures verify under the keyset; see [`verify_cosigned`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoSignedTreeHead {
    /// Canonical CBOR encoding of [`SthBody`].
    pub body_cbor: Vec<u8>,
    /// One signature per co-signing replica. Order is not significant for
    /// verification but is preserved on the wire to keep the artefact a
    /// deterministic function of `(body, signers)`.
    pub signatures: Vec<CoSignature>,
}

impl CoSignedTreeHead {
    /// Decode the embedded [`SthBody`]. This does **not** verify any
    /// signature; pair with [`verify_cosigned`].
    pub fn body(&self) -> Result<SthBody, SthError> {
        ciborium::from_reader(self.body_cbor.as_slice())
            .map_err(|e| SthError::Decode(e.to_string()))
    }

    /// View the artefact as a single-signer [`SignedTreeHead`] by taking the
    /// `n`-th signature. Useful when a downstream API was built against the
    /// pre-quorum surface and the caller has already verified the artefact at
    /// the quorum threshold.
    #[must_use]
    pub fn as_single(&self, n: usize) -> Option<SignedTreeHead> {
        let s = self.signatures.get(n)?;
        Some(SignedTreeHead {
            body_cbor: self.body_cbor.clone(),
            signer_kid: s.signer_kid.clone(),
            signature_b64: s.signature_b64.clone(),
        })
    }
}

/// Failure modes for quorum signing / verification.
#[derive(Debug, thiserror::Error)]
pub enum QuorumError {
    /// `threshold` is zero, or exceeds the number of available signers.
    #[error("invalid threshold {threshold} for {signer_count} signers")]
    InvalidThreshold {
        /// Configured threshold.
        threshold: usize,
        /// Number of signers actually available to the aggregator (or, on the
        /// verify side, the number of distinct co-signatures attached).
        signer_count: usize,
    },
    /// Two signers share a `signer_kid`. The keyset is by-kid; duplicates
    /// would let a single compromised key count toward the threshold twice.
    #[error("duplicate signer_kid: {0}")]
    DuplicateSigner(String),
    /// A required signer failed to produce a signature.
    #[error("signer {kid} failed: {source}")]
    SignerFailed {
        /// The kid of the failing signer.
        kid: String,
        /// The underlying error.
        #[source]
        source: SthError,
    },
    /// Fewer than `threshold` listed signatures verified under the keyset.
    #[error("quorum not met: {accepted} of {threshold} required signatures verified")]
    QuorumNotMet {
        /// Number of distinct signatures that verified successfully.
        accepted: usize,
        /// Configured threshold.
        threshold: usize,
    },
    /// CBOR body decode failed during verification.
    #[error("body: {0}")]
    Body(#[from] SthError),
}

/// Aggregates signatures from `N` listed signers and produces a
/// [`CoSignedTreeHead`] requiring at least `threshold` to succeed.
///
/// In production the listed signers are the cluster peers (one trait object
/// per replica, each backed by a peer-transport RPC into that replica's
/// TEE-resident threshold signer). In tests and the M3 single-node path the
/// signers are [`crate::sth::InProcessSigner`] instances.
pub struct QuorumSigner {
    threshold: usize,
    signers: Vec<Arc<dyn SthSigner>>,
}

impl QuorumSigner {
    /// Build a quorum signer over the given signers.
    ///
    /// Returns [`QuorumError::InvalidThreshold`] if `threshold` is zero or
    /// exceeds `signers.len()`, and [`QuorumError::DuplicateSigner`] if any
    /// two signers share a `kid`.
    pub fn new(signers: Vec<Arc<dyn SthSigner>>, threshold: usize) -> Result<Self, QuorumError> {
        if threshold == 0 || threshold > signers.len() {
            return Err(QuorumError::InvalidThreshold {
                threshold,
                signer_count: signers.len(),
            });
        }
        let mut seen = BTreeSet::new();
        for s in &signers {
            if !seen.insert(s.kid().to_owned()) {
                return Err(QuorumError::DuplicateSigner(s.kid().to_owned()));
            }
        }
        Ok(Self { threshold, signers })
    }

    /// Configured quorum threshold.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Number of listed signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }

    /// Sign `body` with every listed signer and return the aggregated artefact.
    ///
    /// All signers are invoked sequentially in their listed order. The body is
    /// encoded to canonical CBOR exactly once and that byte slice is what each
    /// signer covers — verifiers reproduce the same bytes and re-check each
    /// listed signature independently.
    ///
    /// A signer-side failure surfaces as [`QuorumError::SignerFailed`] with
    /// the offending kid; partial co-signing (skip-on-error) is intentionally
    /// not done here — the cluster proposer is the right place to retry or
    /// degrade, not the local aggregator.
    pub fn sign(&self, body: SthBody) -> Result<CoSignedTreeHead, QuorumError> {
        let body_cbor = encode_body(&body).map_err(QuorumError::Body)?;
        let mut signatures = Vec::with_capacity(self.signers.len());
        for s in &self.signers {
            let sth = s
                .sign(body.clone())
                .map_err(|e| QuorumError::SignerFailed {
                    kid: s.kid().to_owned(),
                    source: e,
                })?;
            debug_assert_eq!(sth.body_cbor, body_cbor, "signer must cover the same body");
            signatures.push(CoSignature {
                signer_kid: sth.signer_kid,
                signature_b64: sth.signature_b64,
            });
        }
        Ok(CoSignedTreeHead {
            body_cbor,
            signatures,
        })
    }
}

/// Verification keyset for [`CoSignedTreeHead`]s.
///
/// Maps a `signer_kid` to the composite public key that signer is expected to
/// hold. `threshold` is the minimum number of *distinct* listed signatures
/// that must verify under this keyset for the artefact to be accepted.
///
/// The keyset itself does not carry policy: callers are expected to derive
/// `threshold` from a cluster config (typically `floor(N/2) + 1` for an
/// N-replica Raft cluster), and to populate `keys` from the same config.
pub struct VerifyingKeyset {
    keys: HashMap<String, CompositePublicKey>,
    threshold: usize,
}

impl VerifyingKeyset {
    /// Build a keyset from `(kid, pk)` pairs and a quorum threshold.
    ///
    /// Returns [`QuorumError::InvalidThreshold`] if `threshold` is zero or
    /// exceeds the number of keys provided, and
    /// [`QuorumError::DuplicateSigner`] if any two pairs share a kid.
    pub fn new(
        keys: impl IntoIterator<Item = (String, CompositePublicKey)>,
        threshold: usize,
    ) -> Result<Self, QuorumError> {
        let mut map = HashMap::new();
        for (kid, pk) in keys {
            if map.insert(kid.clone(), pk).is_some() {
                return Err(QuorumError::DuplicateSigner(kid));
            }
        }
        if threshold == 0 || threshold > map.len() {
            return Err(QuorumError::InvalidThreshold {
                threshold,
                signer_count: map.len(),
            });
        }
        Ok(Self {
            keys: map,
            threshold,
        })
    }

    /// Number of distinct verification keys in the set.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Configured quorum threshold.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

/// Verify `sth` against `keyset` and return the decoded body on success.
///
/// A signature is *accepted* iff:
///
/// 1. its `signer_kid` resolves to a key in the keyset (unknown kids are
///    silently ignored — they do not count toward quorum but do not fail
///    verification outright),
/// 2. the base64url signature decodes to a well-formed composite signature, and
/// 3. that signature verifies over `body_cbor` under [`STH_SIGNING_CONTEXT`].
///
/// Distinct kids count once each; duplicate kids in `sth.signatures` collapse
/// to a single contribution toward quorum. The check fails closed: any other
/// error short of a hard CBOR-decode error simply skips that signature.
///
/// On success the decoded [`SthBody`] is returned (already authenticated by
/// at least `threshold` distinct signers).
pub fn verify_cosigned(
    sth: &CoSignedTreeHead,
    keyset: &VerifyingKeyset,
) -> Result<SthBody, QuorumError> {
    let mut accepted: BTreeSet<&str> = BTreeSet::new();
    for sig in &sth.signatures {
        let Some(pk) = keyset.keys.get(&sig.signer_kid) else {
            continue;
        };
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(sig.signature_b64.as_bytes()) else {
            continue;
        };
        let Ok(parsed) = CompositeSignature::from_concat_bytes(&bytes) else {
            continue;
        };
        if pk
            .verify(STH_SIGNING_CONTEXT, &sth.body_cbor, &parsed)
            .is_ok()
        {
            accepted.insert(sig.signer_kid.as_str());
        }
    }
    if accepted.len() < keyset.threshold {
        return Err(QuorumError::QuorumNotMet {
            accepted: accepted.len(),
            threshold: keyset.threshold,
        });
    }
    sth.body().map_err(QuorumError::Body)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bytes::Hash384;
    use crate::sth::InProcessSigner;
    use ferro_crypto::composite::CompositeSecretKey;

    fn fixed_body() -> SthBody {
        SthBody {
            tree_size: 9,
            root_hash: Hash384([0xAB; 48]),
            timestamp: 1_770_000_000,
        }
    }

    type SignerVec = Vec<Arc<dyn SthSigner>>;
    type KeyVec = Vec<(String, CompositePublicKey)>;

    fn three_signers() -> (SignerVec, KeyVec) {
        let mut signers: Vec<Arc<dyn SthSigner>> = Vec::new();
        let mut keys = Vec::new();
        for kid in ["peer-a", "peer-b", "peer-c"] {
            let (s, pk) = InProcessSigner::generate(kid).unwrap();
            signers.push(Arc::new(s));
            keys.push((kid.to_owned(), pk));
        }
        (signers, keys)
    }

    #[test]
    fn three_of_three_verifies() {
        let (signers, keys) = three_signers();
        let q = QuorumSigner::new(signers, 2).unwrap();
        let sth = q.sign(fixed_body()).unwrap();
        let ks = VerifyingKeyset::new(keys, 2).unwrap();
        let body = verify_cosigned(&sth, &ks).unwrap();
        assert_eq!(body.tree_size, 9);
        assert_eq!(sth.signatures.len(), 3);
    }

    #[test]
    fn quorum_holds_when_minority_keys_unknown() {
        // 3 signers; only 2 of their keys are known to the verifier; threshold 2.
        let (signers, mut keys) = three_signers();
        let q = QuorumSigner::new(signers, 2).unwrap();
        let sth = q.sign(fixed_body()).unwrap();
        keys.pop();
        let ks = VerifyingKeyset::new(keys, 2).unwrap();
        verify_cosigned(&sth, &ks).expect("quorum still met with two known signers");
    }

    #[test]
    fn quorum_fails_when_minority_keys_known() {
        // 3 signers; only 1 key known to the verifier; threshold 2.
        let (signers, mut keys) = three_signers();
        let q = QuorumSigner::new(signers, 2).unwrap();
        let sth = q.sign(fixed_body()).unwrap();
        keys.truncate(1);
        let ks = VerifyingKeyset::new(keys, 1).unwrap();
        // threshold 1 still verifies
        verify_cosigned(&sth, &ks).unwrap();

        // Now build an artefact from a single signer, and verify under a
        // keyset that has *that* signer plus an outsider whose key never
        // signed: threshold=2 must fail with `accepted=1`.
        let (single_signer, single_pk) = InProcessSigner::generate("only").unwrap();
        let q2 = QuorumSigner::new(vec![Arc::new(single_signer) as Arc<dyn SthSigner>], 1).unwrap();
        let sth2 = q2.sign(fixed_body()).unwrap();
        assert_eq!(sth2.signatures.len(), 1);
        let (_outsider_sk, outsider_pk) = CompositeSecretKey::generate().unwrap();
        let ks2 = VerifyingKeyset::new(
            vec![("only".into(), single_pk), ("outsider".into(), outsider_pk)],
            2,
        )
        .unwrap();
        let err = verify_cosigned(&sth2, &ks2).unwrap_err();
        assert!(
            matches!(
                err,
                QuorumError::QuorumNotMet {
                    accepted: 1,
                    threshold: 2
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_body_fails_every_signature() {
        let (signers, keys) = three_signers();
        let q = QuorumSigner::new(signers, 2).unwrap();
        let mut sth = q.sign(fixed_body()).unwrap();
        sth.body_cbor[0] ^= 0x01;
        let ks = VerifyingKeyset::new(keys, 2).unwrap();
        let err = verify_cosigned(&sth, &ks).unwrap_err();
        assert!(matches!(
            err,
            QuorumError::QuorumNotMet {
                accepted: 0,
                threshold: 2,
            }
        ));
    }

    #[test]
    fn tampered_single_signature_still_meets_quorum() {
        let (signers, keys) = three_signers();
        let q = QuorumSigner::new(signers, 2).unwrap();
        let mut sth = q.sign(fixed_body()).unwrap();
        // Corrupt one signature; remaining two must still satisfy threshold=2.
        let s = &mut sth.signatures[0];
        let last = s.signature_b64.pop().unwrap();
        s.signature_b64.push(if last == 'A' { 'B' } else { 'A' });
        let ks = VerifyingKeyset::new(keys, 2).unwrap();
        let body = verify_cosigned(&sth, &ks).unwrap();
        assert_eq!(body.tree_size, 9);
    }

    #[test]
    fn duplicate_kids_only_count_once_toward_quorum() {
        // Build an artefact where the same valid signature is listed twice;
        // it must not let threshold=2 pass with only one underlying signer.
        let (mut signers, keys) = three_signers();
        signers.truncate(1);
        let q = QuorumSigner::new(signers, 1).unwrap();
        let mut sth = q.sign(fixed_body()).unwrap();
        sth.signatures.push(sth.signatures[0].clone());
        let ks = VerifyingKeyset::new(keys, 2).unwrap();
        let err = verify_cosigned(&sth, &ks).unwrap_err();
        assert!(matches!(
            err,
            QuorumError::QuorumNotMet {
                accepted: 1,
                threshold: 2
            }
        ));
    }

    #[test]
    fn unknown_signer_does_not_fail_verify_outright() {
        // An extra signature with an unknown kid is ignored, not rejected:
        // the remaining valid signatures still carry the artefact.
        let (signers, keys) = three_signers();
        let q = QuorumSigner::new(signers, 2).unwrap();
        let mut sth = q.sign(fixed_body()).unwrap();
        sth.signatures.push(CoSignature {
            signer_kid: "outsider".into(),
            signature_b64: "AAAA".into(),
        });
        let ks = VerifyingKeyset::new(keys, 2).unwrap();
        verify_cosigned(&sth, &ks).unwrap();
    }

    #[test]
    fn invalid_threshold_is_refused() {
        let (signers, _keys) = three_signers();
        let err = QuorumSigner::new(signers, 0).err().expect("zero threshold");
        assert!(matches!(err, QuorumError::InvalidThreshold { .. }));

        let (signers, _keys) = three_signers();
        let err = QuorumSigner::new(signers, 4).err().expect("over-threshold");
        assert!(matches!(err, QuorumError::InvalidThreshold { .. }));
    }

    #[test]
    fn duplicate_signers_refused_at_build_time() {
        let (sk1, _) = CompositeSecretKey::generate().unwrap();
        let (sk2, _) = CompositeSecretKey::generate().unwrap();
        let s1 = InProcessSigner::new("same-kid", sk1);
        let s2 = InProcessSigner::new("same-kid", sk2);
        let err = QuorumSigner::new(vec![Arc::new(s1), Arc::new(s2)], 1)
            .err()
            .expect("duplicate kid");
        assert!(matches!(err, QuorumError::DuplicateSigner(k) if k == "same-kid"));
    }

    #[test]
    fn as_single_extracts_a_per_replica_view() {
        let (signers, keys) = three_signers();
        let q = QuorumSigner::new(signers, 2).unwrap();
        let sth = q.sign(fixed_body()).unwrap();
        let one = sth.as_single(1).unwrap();
        // Verify the extracted single-signer STH against that signer's key.
        let kid = &sth.signatures[1].signer_kid;
        let pk = keys
            .iter()
            .find(|(k, _)| k == kid)
            .map(|(_, pk)| pk)
            .unwrap();
        let body = crate::sth::verify_sth(&one, pk).unwrap();
        assert_eq!(body.tree_size, 9);
    }
}
