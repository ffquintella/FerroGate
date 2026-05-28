// The tree's `len()` returns `usize`; we narrow it to `u64` on the wire.
// Inside the proptest the loop variable is `usize` in a tiny 1..=12 range, so
// the casts to `u8`/`i64` are exact by construction.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

//! The [`AuditLog`] facade.
//!
//! Glues the in-memory Merkle tree, the backing store, and the STH signer
//! into the API CMIS calls. Appends are serialised under a mutex so the
//! per-leaf index assigned to a caller matches the leaf the tree records;
//! readers (proofs, latest STH) may race appends.
//!
//! Production deployments will swap [`crate::sth::InProcessSigner`] for the
//! TEE-resident threshold signer and [`crate::store::LocalDiskWormStore`] for
//! the S3 Object Lock store; the facade is unchanged.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::bytes::Hash384;
use crate::event::{self, AuditEvent, EventCodecError};
use crate::merkle::{leaf_hash, MerkleTree, HASH_LEN};
use crate::sth::{SignedTreeHead, SthBody, SthError, SthSigner};
use crate::store::{AuditStore, AuditStoreError};

/// Failure modes for [`AuditLog`] operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    /// Event codec failure.
    #[error("event: {0}")]
    Event(#[from] EventCodecError),
    /// Backing-store failure.
    #[error("store: {0}")]
    Store(#[from] AuditStoreError),
    /// STH signer failure.
    #[error("sth: {0}")]
    Sth(#[from] SthError),
    /// A requested leaf index or tree size is out of range.
    #[error("range: {0}")]
    Range(String),
}

/// Thread-safe audit log. Cloning is cheap (`Arc` clone) and shares state.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<TreeState>,
    store: Arc<dyn AuditStore>,
    signer: Arc<dyn SthSigner>,
}

struct TreeState {
    tree: MerkleTree,
    latest_sth: Option<SignedTreeHead>,
}

impl AuditLog {
    /// Build a log from a backing store and an STH signer.
    pub fn new(store: Arc<dyn AuditStore>, signer: Arc<dyn SthSigner>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(TreeState {
                    tree: MerkleTree::new(),
                    latest_sth: None,
                }),
                store,
                signer,
            }),
        }
    }

    /// Number of leaves currently in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.state.lock().tree.len()
    }

    /// Whether the log has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.state.lock().tree.is_empty()
    }

    /// Append `event`, persist its raw bytes to the backing store, and return
    /// its zero-based index. Appends are atomic with respect to readers: the
    /// tree is only updated after the store has accepted the bytes, so a
    /// later `produce_sth` covers exactly the same set of leaves the store
    /// reflects.
    pub fn append(&self, event: &AuditEvent) -> Result<u64, AuditLogError> {
        let raw = event::encode(event)?;
        let hash = leaf_hash(&raw);
        let mut state = self.inner.state.lock();
        let index = state.tree.len() as u64;
        self.inner.store.append_leaf(index, &raw, &hash)?;
        state.tree.append(hash);
        Ok(index)
    }

    /// Sign the current tree state into an STH, record it in the backing
    /// store, and cache it as the latest. Returns the new STH.
    pub fn produce_sth(&self, timestamp_unix: i64) -> Result<SignedTreeHead, AuditLogError> {
        let mut state = self.inner.state.lock();
        let tree_size = state.tree.len() as u64;
        let root_hash = state.tree.root().unwrap_or([0u8; HASH_LEN]);
        let body = SthBody {
            tree_size,
            root_hash: Hash384(root_hash),
            timestamp: timestamp_unix,
        };
        let sth = self.inner.signer.sign(body)?;
        self.inner.store.record_sth(&sth)?;
        state.latest_sth = Some(sth.clone());
        Ok(sth)
    }

    /// The most recent STH produced via [`Self::produce_sth`]. `None` if none
    /// has been produced yet.
    #[must_use]
    pub fn latest_sth(&self) -> Option<SignedTreeHead> {
        self.inner.state.lock().latest_sth.clone()
    }

    /// Inclusion proof for the leaf at `index` against the current tree.
    ///
    /// # Panics
    ///
    /// Panics only on a corrupt internal state where the tree is non-empty
    /// yet `MerkleTree::root` returns `None` — i.e. never, in practice; the
    /// invariant is maintained inside the mutex-guarded section.
    pub fn inclusion_proof(&self, index: u64) -> Result<InclusionProof, AuditLogError> {
        let state = self.inner.state.lock();
        let tree_size = state.tree.len();
        let i = usize::try_from(index)
            .map_err(|_| AuditLogError::Range(format!("index {index} out of usize range")))?;
        let leaf = *state
            .tree
            .leaf(i)
            .ok_or_else(|| AuditLogError::Range(format!("index {i} >= tree size {tree_size}")))?;
        let proof = state
            .tree
            .inclusion_proof(i)
            .ok_or_else(|| AuditLogError::Range(format!("index {i} >= tree size {tree_size}")))?;
        let root = state.tree.root().expect("non-empty tree has a root");
        Ok(InclusionProof {
            leaf_hash: leaf,
            leaf_index: index,
            tree_size: tree_size as u64,
            root_hash: root,
            audit_path: proof,
        })
    }

    /// Consistency proof between `old_size` and the current tree size.
    ///
    /// # Panics
    ///
    /// Panics only on a corrupt internal state where the tree is non-empty
    /// yet `MerkleTree::root` returns `None` — i.e. never, in practice; the
    /// invariant is maintained inside the mutex-guarded section.
    pub fn consistency_proof(&self, old_size: u64) -> Result<ConsistencyProof, AuditLogError> {
        let state = self.inner.state.lock();
        let new_size = state.tree.len();
        let m = usize::try_from(old_size)
            .map_err(|_| AuditLogError::Range(format!("old_size {old_size} out of range")))?;
        if m == 0 || m > new_size {
            return Err(AuditLogError::Range(format!(
                "old_size {m} not in 1..={new_size}"
            )));
        }
        let proof = state.tree.consistency_proof(m, new_size).ok_or_else(|| {
            AuditLogError::Range(format!("consistency ({m},{new_size}) out of range"))
        })?;
        let new_root = state.tree.root().expect("non-empty tree has a root");
        Ok(ConsistencyProof {
            old_size,
            new_size: new_size as u64,
            new_root_hash: new_root,
            audit_path: proof,
        })
    }
}

/// Inclusion-proof payload returned over the wire.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    /// SHA3-384 leaf hash.
    pub leaf_hash: [u8; HASH_LEN],
    /// Index of the leaf in the tree.
    pub leaf_index: u64,
    /// Tree size at which the proof was constructed.
    pub tree_size: u64,
    /// Root hash of that tree.
    pub root_hash: [u8; HASH_LEN],
    /// Audit path (sibling hashes), root-ward.
    pub audit_path: Vec<[u8; HASH_LEN]>,
}

/// Consistency-proof payload returned over the wire.
#[derive(Debug, Clone)]
pub struct ConsistencyProof {
    /// Older tree size.
    pub old_size: u64,
    /// Newer tree size.
    pub new_size: u64,
    /// Root hash of the newer tree.
    pub new_root_hash: [u8; HASH_LEN],
    /// Audit path between the two trees.
    pub audit_path: Vec<[u8; HASH_LEN]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sth::InProcessSigner;
    use crate::store::LocalDiskWormStore;
    use crate::{verify_consistency, verify_inclusion};

    use proptest::prelude::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-audit-log-{tag}-{nanos}"));
        p
    }

    fn fresh_log(tag: &str) -> (AuditLog, std::path::PathBuf) {
        let dir = temp_dir(tag);
        let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&dir).unwrap());
        let (signer, _pk) = InProcessSigner::generate("kid").unwrap();
        let log = AuditLog::new(store, Arc::new(signer));
        (log, dir)
    }

    fn event(i: u8) -> AuditEvent {
        AuditEvent::SvidIssued {
            cert_sha: Hash384([i; 48]),
            spiffe_id: format!("spiffe://x/host/{i}"),
        }
    }

    #[test]
    fn appended_events_get_sequential_indices() {
        let (log, dir) = fresh_log("seq");
        for i in 0..5u8 {
            assert_eq!(log.append(&event(i)).unwrap(), u64::from(i));
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn produced_sth_matches_tree_state() {
        let (log, dir) = fresh_log("sth");
        for i in 0..3u8 {
            log.append(&event(i)).unwrap();
        }
        let sth = log.produce_sth(1_770_000_000).unwrap();
        let body = sth.body().unwrap();
        assert_eq!(body.tree_size, 3);
        std::fs::remove_dir_all(dir).ok();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Property: for any sequence of appends, every leaf's inclusion proof
        /// must verify, and every (old_size, new_size) consistency proof must
        /// verify too. This subsumes the "deletion is detectable" property —
        /// the consistency check fails iff the history diverges.
        #[test]
        fn inclusion_and_consistency_hold_for_all_pairs(n in 1usize..=12) {
            let (log, dir) = fresh_log("prop");
            let mut roots = Vec::with_capacity(n);
            for i in 0..n {
                let idx = log.append(&event(i as u8)).unwrap();
                prop_assert_eq!(idx, i as u64);
                let sth = log.produce_sth(i as i64).unwrap();
                roots.push(sth.body().unwrap().root_hash);
            }
            // Inclusion: every leaf must verify against the current root.
            let final_root = *roots.last().unwrap();
            for i in 0..n {
                let p = log.inclusion_proof(i as u64).unwrap();
                prop_assert!(verify_inclusion(
                    &p.leaf_hash,
                    i,
                    n,
                    &final_root.0,
                    &p.audit_path
                ));
            }
            // Consistency: prefix m -> current must verify against the older root.
            for m in 1..=n {
                let p = log.consistency_proof(m as u64).unwrap();
                prop_assert!(verify_consistency(
                    m,
                    n,
                    &roots[m - 1].0,
                    &final_root.0,
                    &p.audit_path,
                ));
            }
            std::fs::remove_dir_all(dir).ok();
        }
    }
}
