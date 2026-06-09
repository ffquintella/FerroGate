//! The observed-caller ledger — the raw material for host-driven allowlist
//! proposals.
//!
//! The helper API authorizes each caller against the signed allowlist and then
//! forgets it. To let mia *propose* the callers it actually sees (so CMIS can
//! bootstrap a host's allowlist instead of an operator hand-enumerating it), the
//! request pipeline records every authenticated `(uid, bin_sha)` it encounters —
//! granted *and* denied — into this shared ledger. The propose task
//! ([`crate::scheduler`]) snapshots it periodically and sends it to CMIS.
//!
//! Denied callers matter most: on a fresh, deny-all host every legitimate caller
//! is denied for "not-allowlisted", and those denials are exactly the entries a
//! bootstrap proposal should contain.
//!
//! In-memory only (resets on restart); the propose path is idempotent, so a
//! restarted mia simply re-accumulates and re-proposes.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// One observed caller: a uid and the SHA-384 of its binary.
type Caller = (u32, [u8; 48]);

/// A cheap, cloneable handle to the set of `(uid, bin_sha384)` callers the
/// helper API has observed this run. Clones share one underlying set.
#[derive(Clone, Default)]
pub struct CallerLedger {
    inner: Arc<Mutex<HashSet<Caller>>>,
}

impl CallerLedger {
    /// A fresh, empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observed caller. Idempotent — re-observing a known caller is a
    /// no-op. The lock is held only for the insert, never across an `.await`.
    pub fn observe(&self, uid: u32, bin_sha: [u8; 48]) {
        if let Ok(mut set) = self.inner.lock() {
            set.insert((uid, bin_sha));
        }
    }

    /// A snapshot of every observed caller, for building a proposal.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Caller> {
        self.inner
            .lock()
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Number of distinct callers observed so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |s| s.len())
    }

    /// Whether no caller has been observed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_is_deduplicating_and_snapshot_reflects_it() {
        let l = CallerLedger::new();
        assert!(l.is_empty());
        l.observe(1000, [0xAA; 48]);
        l.observe(1000, [0xAA; 48]); // dup
        l.observe(1001, [0xBB; 48]);
        assert_eq!(l.len(), 2);
        let mut snap = l.snapshot();
        snap.sort_unstable();
        assert_eq!(snap, vec![(1000, [0xAA; 48]), (1001, [0xBB; 48])]);
    }

    #[test]
    fn clones_share_state() {
        let a = CallerLedger::new();
        let b = a.clone();
        a.observe(7, [0x01; 48]);
        assert_eq!(b.len(), 1);
    }
}
