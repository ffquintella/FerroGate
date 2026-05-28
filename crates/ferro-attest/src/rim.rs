//! Reference Integrity Measurement (RIM) allowlist (steps 6-9, feature F10).
//!
//! A RIM maps an approved aggregate PCR digest (SHA-384 over the selected PCR
//! bank in selection order) to a `policy_id`. CMIS keeps the active generation
//! plus the [`MAX_GENERATIONS`] previous ones so in-flight image rollouts don't
//! lock hosts out mid-update; an epoch bump (a new `policy_id`) mass-invalidates
//! older measurements.
//!
//! The store has interior mutability ([`parking_lot::RwLock`] under an `Arc`)
//! so a [`crate::rim_loader::RimLoader`] can hot-swap a new generation
//! atomically while a [`crate::TpmQuoteVerifier`] holds a clone — a single
//! write-lock makes the reload point-in-time consistent for in-flight
//! attestations.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;

/// How many prior RIM generations are retained alongside the active one.
///
/// Empirically sufficient for a two-week rollout window with weekly image
/// pushes (see `docs/features/F10-rim-pcr-policy.md`).
pub const MAX_GENERATIONS: usize = 6;

/// Identifies the policy generation an approved digest belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyId(pub String);

impl PolicyId {
    /// Borrow the underlying identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One published RIM generation: a `policy_id`, its validity window, and the
/// set of aggregate PCR digests it approves.
#[derive(Debug, Clone)]
pub struct RimGeneration {
    /// Monotonic bundle version that produced this generation.
    pub version: u64,
    /// The policy identifier stamped into every SVID issued under it.
    pub policy_id: PolicyId,
    /// Unix-seconds inclusive lower bound for active use.
    pub not_before: i64,
    /// Unix-seconds exclusive upper bound for active use.
    pub not_after: i64,
    /// The approved aggregate digests (SHA-384, 48 bytes each).
    pub approved: HashSet<[u8; 48]>,
}

impl RimGeneration {
    /// Whether this generation should be consulted at `now`.
    #[must_use]
    pub fn is_active(&self, now: i64) -> bool {
        self.not_before <= now && now < self.not_after
    }

    /// Whether this generation approves `digest`.
    #[must_use]
    pub fn approves(&self, digest: &[u8; 48]) -> bool {
        self.approved.contains(digest)
    }
}

/// A compact view of one retained generation, safe to expose to logs / RPCs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RimGenerationSummary {
    /// Monotonic bundle version.
    pub version: u64,
    /// Policy id.
    pub policy_id: PolicyId,
    /// Validity lower bound.
    pub not_before: i64,
    /// Validity upper bound.
    pub not_after: i64,
    /// Number of approved digests.
    pub approved_count: usize,
}

#[derive(Default)]
struct Inner {
    /// Oldest at the front, newest at the back.
    generations: VecDeque<RimGeneration>,
    /// Out-of-band approvals (no version / window — for tests and bring-up).
    manual: HashMap<[u8; 48], PolicyId>,
    /// The highest bundle version ever applied; updates strictly above this.
    last_version: u64,
}

/// Outcome of applying a fresh RIM generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// The version that became active.
    pub version: u64,
    /// Number of generations retained after applying.
    pub retained: usize,
    /// Number of generations dropped to honour [`MAX_GENERATIONS`].
    pub pruned: usize,
}

/// Why an attempted RIM apply was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// The new bundle's version is not strictly greater than the last applied.
    #[error("non-monotonic version: incoming {incoming} <= current {current}")]
    NonMonotonic {
        /// Highest version already applied.
        current: u64,
        /// Version on the rejected bundle.
        incoming: u64,
    },
    /// `not_before >= not_after`, i.e. the bundle's window is empty.
    #[error("invalid validity window: not_before {not_before} >= not_after {not_after}")]
    InvalidWindow {
        /// Lower bound.
        not_before: i64,
        /// Upper bound.
        not_after: i64,
    },
}

/// Process-shared allowlist. Cloning shares the underlying state.
#[derive(Default, Clone)]
pub struct RimStore {
    inner: Arc<RwLock<Inner>>,
}

impl RimStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Manually approve an aggregate PCR digest under `policy_id`. This is the
    /// pre-F10 escape hatch for bring-up and tests — entries are always active
    /// and survive every reload. Production deployments should publish a
    /// signed [`crate::rim_bundle::SignedRimBundle`] via the loader instead.
    pub fn approve(&self, digest: [u8; 48], policy_id: PolicyId) {
        self.inner.write().manual.insert(digest, policy_id);
    }

    /// Look up an aggregate PCR digest in the active generations or the manual
    /// allowlist. `now` is Unix seconds, used to gate the per-generation window.
    #[must_use]
    pub fn lookup_at(&self, digest: &[u8; 48], now: i64) -> Option<PolicyId> {
        let inner = self.inner.read();
        if let Some(p) = inner.manual.get(digest) {
            return Some(p.clone());
        }
        // Newest generations first — a host on the freshest image gets the
        // newest `policy_id` recorded in its SVID.
        for gen in inner.generations.iter().rev() {
            if gen.is_active(now) && gen.approves(digest) {
                return Some(gen.policy_id.clone());
            }
        }
        None
    }

    /// Convenience: lookup ignoring time windows. Retained generations always
    /// match; useful for tests that don't care about the clock.
    #[must_use]
    pub fn lookup(&self, digest: &[u8; 48]) -> Option<PolicyId> {
        let inner = self.inner.read();
        if let Some(p) = inner.manual.get(digest) {
            return Some(p.clone());
        }
        for gen in inner.generations.iter().rev() {
            if gen.approves(digest) {
                return Some(gen.policy_id.clone());
            }
        }
        None
    }

    /// Apply a fresh RIM generation atomically. Returns the apply outcome or
    /// the reason the bundle was refused.
    ///
    /// Reload semantics: the entire generation set is updated under a single
    /// write lock, so an in-flight attestation either sees the old set in full
    /// or the new set in full — never a torn intermediate.
    pub fn apply(&self, generation: RimGeneration) -> Result<ApplyOutcome, ApplyError> {
        if generation.not_before >= generation.not_after {
            return Err(ApplyError::InvalidWindow {
                not_before: generation.not_before,
                not_after: generation.not_after,
            });
        }
        let mut inner = self.inner.write();
        if generation.version <= inner.last_version {
            return Err(ApplyError::NonMonotonic {
                current: inner.last_version,
                incoming: generation.version,
            });
        }
        let version = generation.version;
        inner.last_version = version;
        inner.generations.push_back(generation);
        let mut pruned = 0usize;
        while inner.generations.len() > MAX_GENERATIONS {
            inner.generations.pop_front();
            pruned += 1;
        }
        Ok(ApplyOutcome {
            version,
            retained: inner.generations.len(),
            pruned,
        })
    }

    /// The highest bundle version ever applied (0 if none).
    #[must_use]
    pub fn current_version(&self) -> u64 {
        self.inner.read().last_version
    }

    /// A snapshot of the retained generations, newest last.
    #[must_use]
    pub fn generations(&self) -> Vec<RimGenerationSummary> {
        self.inner
            .read()
            .generations
            .iter()
            .map(|g| RimGenerationSummary {
                version: g.version,
                policy_id: g.policy_id.clone(),
                not_before: g.not_before,
                not_after: g.not_after,
                approved_count: g.approved.len(),
            })
            .collect()
    }

    /// Total number of approved digests across all retained generations plus
    /// the manual allowlist.
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.read();
        inner.manual.len()
            + inner
                .generations
                .iter()
                .map(|g| g.approved.len())
                .sum::<usize>()
    }

    /// Whether nothing has been approved at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen(version: u64, policy: &str, digest: u8, window: (i64, i64)) -> RimGeneration {
        let mut approved = HashSet::new();
        approved.insert([digest; 48]);
        RimGeneration {
            version,
            policy_id: PolicyId(policy.to_string()),
            not_before: window.0,
            not_after: window.1,
            approved,
        }
    }

    #[test]
    fn manual_approval_back_compat_works() {
        let rim = RimStore::new();
        let digest = [7u8; 48];
        rim.approve(digest, PolicyId("2026-05-fleet-a".into()));
        assert_eq!(
            rim.lookup(&digest).map(|p| p.0),
            Some("2026-05-fleet-a".to_string())
        );
        // Manual entries ignore the time window.
        assert_eq!(
            rim.lookup_at(&digest, 0).map(|p| p.0),
            Some("2026-05-fleet-a".to_string())
        );
    }

    #[test]
    fn unknown_digest_is_absent() {
        let rim = RimStore::new();
        assert!(rim.lookup(&[0u8; 48]).is_none());
    }

    #[test]
    fn generation_lookup_respects_window() {
        let rim = RimStore::new();
        let g = gen(1, "p1", 0xAA, (100, 200));
        rim.apply(g).unwrap();
        assert!(rim.lookup_at(&[0xAA; 48], 50).is_none());
        assert_eq!(rim.lookup_at(&[0xAA; 48], 150).unwrap().0, "p1");
        // not_after is exclusive.
        assert!(rim.lookup_at(&[0xAA; 48], 200).is_none());
    }

    #[test]
    fn non_monotonic_apply_is_refused() {
        let rim = RimStore::new();
        rim.apply(gen(5, "p", 1, (0, 1000))).unwrap();
        let err = rim.apply(gen(5, "p", 2, (0, 1000))).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::NonMonotonic {
                current: 5,
                incoming: 5
            }
        ));
        let err = rim.apply(gen(3, "p", 3, (0, 1000))).unwrap_err();
        assert!(matches!(err, ApplyError::NonMonotonic { .. }));
    }

    #[test]
    fn invalid_window_is_refused() {
        let rim = RimStore::new();
        let err = rim.apply(gen(1, "p", 1, (100, 100))).unwrap_err();
        assert!(matches!(err, ApplyError::InvalidWindow { .. }));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // v in 1..=8 fits a u8 by construction.
    fn retention_prunes_oldest_beyond_six() {
        let rim = RimStore::new();
        for v in 1..=8 {
            let outcome = rim.apply(gen(v, "p", v as u8, (0, 1_000_000))).unwrap();
            if v <= MAX_GENERATIONS as u64 {
                assert_eq!(outcome.pruned, 0);
            } else {
                assert_eq!(outcome.pruned, 1);
            }
        }
        // After 8 applies, only versions 3..=8 are retained.
        let gens = rim.generations();
        assert_eq!(gens.len(), MAX_GENERATIONS);
        assert_eq!(gens.first().unwrap().version, 3);
        assert_eq!(gens.last().unwrap().version, 8);
        // The pruned digest (from version 1) no longer resolves.
        assert!(rim.lookup_at(&[1u8; 48], 500).is_none());
        // The newest still does.
        assert_eq!(rim.lookup_at(&[8u8; 48], 500).unwrap().0, "p");
    }

    #[test]
    fn newer_generation_wins_when_both_active() {
        let rim = RimStore::new();
        let mut g1 = gen(1, "p1", 0xAA, (0, 1_000_000));
        // Same digest also approved in newer generation under a fresher policy.
        g1.approved.insert([0xBB; 48]);
        rim.apply(g1).unwrap();
        let mut g2 = RimGeneration {
            version: 2,
            policy_id: PolicyId("p2".into()),
            not_before: 0,
            not_after: 1_000_000,
            approved: HashSet::new(),
        };
        g2.approved.insert([0xAA; 48]);
        rim.apply(g2).unwrap();
        // Shared digest -> newer policy_id wins.
        assert_eq!(rim.lookup_at(&[0xAA; 48], 500).unwrap().0, "p2");
        // Old-only digest -> still resolves under old policy.
        assert_eq!(rim.lookup_at(&[0xBB; 48], 500).unwrap().0, "p1");
    }

    #[test]
    fn store_handles_clone_to_share_state() {
        let a = RimStore::new();
        let b = a.clone();
        a.apply(gen(1, "p", 0xCC, (0, 1_000_000))).unwrap();
        // Cloned handle sees the same update.
        assert_eq!(b.current_version(), 1);
        assert!(b.lookup_at(&[0xCC; 48], 500).is_some());
    }
}
