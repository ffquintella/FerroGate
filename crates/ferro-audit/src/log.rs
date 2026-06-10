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
//! Production deployments swap [`crate::sth::InProcessSigner`] for the
//! TEE-resident threshold signer; the facade is unchanged.
//! [`crate::store::LocalDiskWormStore`] is the shipped WORM tier — a native S3
//! Object Lock store is dropped (see `docs/roadmap.md` "Dropped scope").

use std::sync::Arc;

use parking_lot::Mutex;

use crate::bytes::Hash384;
use crate::cosign::{CoSignedTreeHead, QuorumError, QuorumSigner};
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
    /// Quorum signer failure.
    #[error("quorum: {0}")]
    Quorum(#[from] QuorumError),
    /// A requested leaf index or tree size is out of range.
    #[error("range: {0}")]
    Range(String),
    /// The tree rebuilt from the store's leaves does not match a tree head the
    /// store itself recorded — the persisted log was tampered with or
    /// corrupted. Refusing to resume is the only safe answer.
    #[error("resume: {0}")]
    Resume(String),
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
    latest_cosigned_sth: Option<CoSignedTreeHead>,
}

impl AuditLog {
    /// Build a log from a backing store and an STH signer, resuming from
    /// whatever the store already holds.
    ///
    /// The in-memory Merkle tree is rebuilt by replaying every persisted leaf
    /// in index order, so the next append lands at the correct index instead
    /// of colliding with leaf `0` and wedging against the WORM invariant
    /// (which is exactly what an empty tree over a non-empty store would do —
    /// every later append fails `AlreadyExists`, permanently). The newest
    /// persisted STH is cross-checked against the rebuilt tree and seeds the
    /// latest-STH cache; a root mismatch means the persisted log was tampered
    /// with or corrupted, and construction refuses rather than continuing on
    /// a forked history.
    pub fn new(
        store: Arc<dyn AuditStore>,
        signer: Arc<dyn SthSigner>,
    ) -> Result<Self, AuditLogError> {
        let mut tree = MerkleTree::new();
        loop {
            match store.read_leaf(tree.len() as u64) {
                Ok(raw) => {
                    tree.append(leaf_hash(&raw));
                }
                Err(AuditStoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(e.into()),
            }
        }

        let latest_sth = store.latest_sth()?;
        if let Some(sth) = &latest_sth {
            let body = sth.body()?;
            let covered = usize::try_from(body.tree_size).map_err(|_| {
                AuditLogError::Resume(format!("persisted STH size {} out of range", body.tree_size))
            })?;
            if covered > tree.len() {
                return Err(AuditLogError::Resume(format!(
                    "persisted STH covers {} leaves but only {} are on disk",
                    covered,
                    tree.len()
                )));
            }
            // Root of the first `covered` leaves must match what was signed.
            let mut prefix = MerkleTree::new();
            for i in 0..covered {
                let Some(hash) = tree.leaf(i) else {
                    // Unreachable (`covered <= tree.len()` was checked above),
                    // but a Resume error beats a panic on a corrupt store.
                    return Err(AuditLogError::Resume(format!("leaf {i} missing")));
                };
                prefix.append(*hash);
            }
            if prefix.root().unwrap_or([0u8; HASH_LEN]) != body.root_hash.0 {
                return Err(AuditLogError::Resume(format!(
                    "rebuilt root for {covered} leaves does not match the persisted STH"
                )));
            }
        }
        let latest_cosigned_sth = store.latest_cosigned_sth()?;

        if !tree.is_empty() {
            tracing::info!(leaves = tree.len(), "audit log resumed from backing store");
        }
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(TreeState {
                    tree,
                    latest_sth,
                    latest_cosigned_sth,
                }),
                store,
                signer,
            }),
        })
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

    /// Sign the current tree state with a Raft-majority [`QuorumSigner`],
    /// persist the resulting [`CoSignedTreeHead`] to the backing store, and
    /// cache it as the latest co-signed STH.
    ///
    /// This is the M4 publication path: the proposer aggregates per-replica
    /// composite signatures from the cluster peers before any external
    /// observer ever sees the STH, so no single replica can publish a head
    /// the rest of the cluster has not endorsed. Callers should fetch the
    /// keyset from the same cluster config that defined `quorum` and verify
    /// with [`crate::cosign::verify_cosigned`].
    pub fn produce_cosigned_sth(
        &self,
        timestamp_unix: i64,
        quorum: &QuorumSigner,
    ) -> Result<CoSignedTreeHead, AuditLogError> {
        let mut state = self.inner.state.lock();
        let tree_size = state.tree.len() as u64;
        let root_hash = state.tree.root().unwrap_or([0u8; HASH_LEN]);
        let body = SthBody {
            tree_size,
            root_hash: Hash384(root_hash),
            timestamp: timestamp_unix,
        };
        let sth = quorum.sign(body)?;
        self.inner.store.record_cosigned_sth(&sth)?;
        state.latest_cosigned_sth = Some(sth.clone());
        Ok(sth)
    }

    /// The most recent co-signed STH produced via
    /// [`Self::produce_cosigned_sth`]. `None` if none has been produced yet.
    #[must_use]
    pub fn latest_cosigned_sth(&self) -> Option<CoSignedTreeHead> {
        self.inner.state.lock().latest_cosigned_sth.clone()
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
        let log = AuditLog::new(store, Arc::new(signer)).unwrap();
        (log, dir)
    }

    fn event(i: u8) -> AuditEvent {
        AuditEvent::SvidIssued {
            cert_sha: Hash384([i; 48]),
            spiffe_id: format!("spiffe://x/host/{i}"),
        }
    }

    /// A restart (new `AuditLog` over the same store) must resume at the next
    /// leaf index — not restart at 0 and wedge against the WORM invariant —
    /// and must seed the latest-STH cache from disk.
    #[test]
    fn reopening_a_populated_store_resumes_appends_and_sth() {
        let dir = temp_dir("resume");
        let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&dir).unwrap());
        let (signer, _pk) = InProcessSigner::generate("kid").unwrap();
        let log = AuditLog::new(Arc::clone(&store), Arc::new(signer)).unwrap();
        for i in 0..3u8 {
            log.append(&event(i)).unwrap();
        }
        let sth_before = log.produce_sth(1_770_000_000).unwrap();
        drop(log);

        // "Restart": fresh log over the same backing store.
        let (signer, _pk) = InProcessSigner::generate("kid").unwrap();
        let log = AuditLog::new(store, Arc::new(signer)).unwrap();
        assert_eq!(log.len(), 3, "tree must be rebuilt from persisted leaves");
        assert_eq!(
            log.latest_sth().unwrap().body().unwrap().root_hash,
            sth_before.body().unwrap().root_hash,
            "latest STH must be seeded from the store"
        );
        assert_eq!(
            log.append(&event(3)).unwrap(),
            3,
            "append must continue at the next index"
        );
        let p = log.inclusion_proof(0).unwrap();
        assert!(verify_inclusion(
            &p.leaf_hash,
            0,
            4,
            &log.produce_sth(1_770_000_001)
                .unwrap()
                .body()
                .unwrap()
                .root_hash
                .0,
            &p.audit_path
        ));
        std::fs::remove_dir_all(dir).ok();
    }

    /// A persisted leaf that no longer matches the signed tree head must make
    /// resume refuse — continuing would silently fork the log's history.
    #[test]
    fn reopening_refuses_a_tampered_leaf() {
        let dir = temp_dir("tamper");
        let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&dir).unwrap());
        let (signer, _pk) = InProcessSigner::generate("kid").unwrap();
        let log = AuditLog::new(Arc::clone(&store), Arc::new(signer)).unwrap();
        for i in 0..3u8 {
            log.append(&event(i)).unwrap();
        }
        log.produce_sth(1_770_000_000).unwrap();
        drop(log);

        // Tamper with leaf 1 behind the WORM store's back.
        let raw = event::encode(&event(9)).unwrap();
        std::fs::write(dir.join(format!("leaves/{:020}.cbor", 1)), raw).unwrap();

        let (signer, _pk) = InProcessSigner::generate("kid").unwrap();
        let Err(err) = AuditLog::new(store, Arc::new(signer)) else {
            panic!("resume over a tampered leaf must refuse");
        };
        assert!(matches!(err, AuditLogError::Resume(_)), "got: {err}");
        std::fs::remove_dir_all(dir).ok();
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
    fn cosigned_sth_matches_tree_and_verifies() {
        use crate::cosign::{verify_cosigned, QuorumSigner, VerifyingKeyset};
        let (log, dir) = fresh_log("cos");
        for i in 0..4u8 {
            log.append(&event(i)).unwrap();
        }
        let mut signers: Vec<Arc<dyn crate::sth::SthSigner>> = Vec::new();
        let mut keys = Vec::new();
        for kid in ["peer-a", "peer-b", "peer-c"] {
            let (s, pk) = InProcessSigner::generate(kid).unwrap();
            signers.push(Arc::new(s));
            keys.push((kid.to_owned(), pk));
        }
        let q = QuorumSigner::new(signers, 2).unwrap();
        let sth = log.produce_cosigned_sth(1_770_000_001, &q).unwrap();
        let ks = VerifyingKeyset::new(keys, 2).unwrap();
        let body = verify_cosigned(&sth, &ks).unwrap();
        assert_eq!(body.tree_size, 4);
        assert!(log.latest_cosigned_sth().is_some());
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
