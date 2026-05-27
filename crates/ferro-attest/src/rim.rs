//! Reference Integrity Measurement (RIM) allowlist (steps 6-9).
//!
//! A RIM maps an approved aggregate PCR digest (SHA-384 over the selected PCR
//! bank, in selection order) to a `policy_id`. CMIS keeps the current RIM plus
//! prior generations so in-flight rollouts don't lock out hosts mid-update; an
//! epoch bump (`policy_id` change) mass-invalidates older measurements.

use std::collections::HashMap;

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

/// An allowlist of approved aggregate PCR digests.
#[derive(Default)]
pub struct RimStore {
    /// digest (48 bytes, SHA-384) -> policy generation it was approved under.
    approved: HashMap<[u8; 48], PolicyId>,
}

impl RimStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Approve an aggregate PCR digest under `policy_id`.
    pub fn approve(&mut self, digest: [u8; 48], policy_id: PolicyId) {
        self.approved.insert(digest, policy_id);
    }

    /// Look up an aggregate PCR digest; returns the `policy_id` it was approved
    /// under, or `None` if not in the allowlist.
    #[must_use]
    pub fn lookup(&self, digest: &[u8; 48]) -> Option<&PolicyId> {
        self.approved.get(digest)
    }

    /// Number of approved digests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.approved.len()
    }

    /// Whether the allowlist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.approved.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_digest_resolves_to_policy() {
        let mut rim = RimStore::new();
        let digest = [7u8; 48];
        rim.approve(digest, PolicyId("2026-05-fleet-a".into()));
        assert_eq!(
            rim.lookup(&digest).map(PolicyId::as_str),
            Some("2026-05-fleet-a")
        );
    }

    #[test]
    fn unknown_digest_is_absent() {
        let rim = RimStore::new();
        assert!(rim.lookup(&[0u8; 48]).is_none());
    }
}
