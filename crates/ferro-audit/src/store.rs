//! Backing-store abstraction for the audit log.
//!
//! [`LocalDiskWormStore`] is the shipped WORM tier; the replicated copy lives
//! in the hiqlite-backed Raft state machine. A native S3 Object Lock store was
//! originally planned but is dropped (see `docs/roadmap.md` "Dropped scope");
//! deployments needing cloud durability sync the WORM directory to object
//! storage out of band. The [`AuditStore`] trait seam stays open for an
//! out-of-tree adapter, but no object-store impl is a FerroGate deliverable.
//!
//! The WORM property here is enforced by `OpenOptions::create_new(true)`:
//! once a leaf file (or an STH file) exists, the store refuses to overwrite
//! it and returns [`AuditStoreError::AlreadyExists`]. Stronger media-level
//! write-protection (immutable mounts, hardware WORM) is a deployment concern
//! layered under the same directory.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cosign::CoSignedTreeHead;
use crate::sth::SignedTreeHead;

/// Failure modes for backing-store operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditStoreError {
    /// Underlying filesystem / network I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The target file already exists; the WORM store refuses to overwrite.
    #[error("entry already exists: {0}")]
    AlreadyExists(PathBuf),
    /// An STH on disk failed to deserialize.
    #[error("decode: {0}")]
    Decode(String),
    /// An STH could not be serialized.
    #[error("encode: {0}")]
    Encode(String),
    /// The backing store does not implement the requested operation.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

/// Append-only backing store for audit leaves and signed tree heads.
///
/// Implementations must be safe to call concurrently from multiple threads:
/// the [`crate::log::AuditLog`] facade serialises *appends* itself but
/// `latest_sth` / `read_leaf` can race with them.
pub trait AuditStore: Send + Sync {
    /// Persist the raw event bytes (canonical CBOR) and the precomputed leaf
    /// hash at the given index. Implementations must refuse to overwrite an
    /// existing index — that is the WORM invariant a verifier relies on.
    fn append_leaf(
        &self,
        index: u64,
        raw_event: &[u8],
        leaf_hash: &[u8; 48],
    ) -> Result<(), AuditStoreError>;

    /// Persist a freshly-signed tree head, keyed by its `tree_size`.
    fn record_sth(&self, sth: &SignedTreeHead) -> Result<(), AuditStoreError>;

    /// Persist a co-signed tree head (quorum artefact), keyed by its
    /// `tree_size`. Defaults to a not-supported error so existing stores
    /// remain valid without M4 changes; the [`LocalDiskWormStore`] (and any
    /// out-of-tree backing store) override it.
    fn record_cosigned_sth(&self, sth: &CoSignedTreeHead) -> Result<(), AuditStoreError> {
        let _ = sth;
        Err(AuditStoreError::Unsupported(
            "record_cosigned_sth not implemented by this store",
        ))
    }

    /// Read back the raw event bytes for a previously-appended leaf.
    fn read_leaf(&self, index: u64) -> Result<Vec<u8>, AuditStoreError>;

    /// The largest tree size persisted so far. Returns `None` if the store has
    /// recorded no STHs yet.
    fn latest_sth(&self) -> Result<Option<SignedTreeHead>, AuditStoreError>;

    /// The largest co-signed tree size persisted so far. Defaults to `None`
    /// for stores that do not implement the quorum surface.
    fn latest_cosigned_sth(&self) -> Result<Option<CoSignedTreeHead>, AuditStoreError> {
        Ok(None)
    }
}

/// Local-disk WORM-style store.
///
/// Layout under `root`:
///
/// ```text
/// <root>/leaves/<20-digit zero-padded index>.cbor       # canonical event bytes
/// <root>/leaves/<20-digit zero-padded index>.hash       # 48-byte SHA3-384 leaf
/// <root>/sth/<20-digit zero-padded tree_size>.json      # SignedTreeHead JSON
/// <root>/cosigned/<20-digit zero-padded tree_size>.json # CoSignedTreeHead JSON (M4)
/// ```
///
/// Files are opened with `create_new(true)`; an existing path is a hard error
/// rather than an overwrite.
pub struct LocalDiskWormStore {
    root: PathBuf,
}

impl LocalDiskWormStore {
    /// Open (creating if needed) the store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, AuditStoreError> {
        let root = root.into();
        std::fs::create_dir_all(root.join("leaves"))?;
        std::fs::create_dir_all(root.join("sth"))?;
        std::fs::create_dir_all(root.join("cosigned"))?;
        Ok(Self { root })
    }

    /// Root directory of the store.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn leaf_path(&self, index: u64) -> PathBuf {
        self.root.join(format!("leaves/{index:020}.cbor"))
    }

    fn hash_path(&self, index: u64) -> PathBuf {
        self.root.join(format!("leaves/{index:020}.hash"))
    }

    fn sth_path(&self, tree_size: u64) -> PathBuf {
        self.root.join(format!("sth/{tree_size:020}.json"))
    }

    fn cosigned_path(&self, tree_size: u64) -> PathBuf {
        self.root.join(format!("cosigned/{tree_size:020}.json"))
    }

    fn read_latest_in(&self, subdir: &str) -> Result<Option<(u64, Vec<u8>)>, AuditStoreError> {
        let dir = self.root.join(subdir);
        let mut best: Option<(u64, PathBuf)> = None;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            let Ok(n) = stem.parse::<u64>() else {
                continue;
            };
            if best.as_ref().is_none_or(|(b, _)| n > *b) {
                best = Some((n, entry.path()));
            }
        }
        let Some((n, path)) = best else {
            return Ok(None);
        };
        Ok(Some((n, std::fs::read(&path)?)))
    }

    #[allow(clippy::unused_self)] // method-style for symmetry with other store ops.
    fn write_new(&self, path: &Path, bytes: &[u8]) -> Result<(), AuditStoreError> {
        match OpenOptions::new().create_new(true).write(true).open(path) {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.sync_data()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(AuditStoreError::AlreadyExists(path.to_path_buf()))
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl AuditStore for LocalDiskWormStore {
    fn append_leaf(
        &self,
        index: u64,
        raw_event: &[u8],
        leaf_hash: &[u8; 48],
    ) -> Result<(), AuditStoreError> {
        self.write_new(&self.leaf_path(index), raw_event)?;
        self.write_new(&self.hash_path(index), leaf_hash)?;
        Ok(())
    }

    fn record_sth(&self, sth: &SignedTreeHead) -> Result<(), AuditStoreError> {
        let body = sth
            .body()
            .map_err(|e| AuditStoreError::Encode(e.to_string()))?;
        let bytes =
            serde_json::to_vec_pretty(sth).map_err(|e| AuditStoreError::Encode(e.to_string()))?;
        self.write_new(&self.sth_path(body.tree_size), &bytes)
    }

    fn record_cosigned_sth(&self, sth: &CoSignedTreeHead) -> Result<(), AuditStoreError> {
        let body = sth
            .body()
            .map_err(|e| AuditStoreError::Encode(e.to_string()))?;
        let bytes =
            serde_json::to_vec_pretty(sth).map_err(|e| AuditStoreError::Encode(e.to_string()))?;
        self.write_new(&self.cosigned_path(body.tree_size), &bytes)
    }

    fn read_leaf(&self, index: u64) -> Result<Vec<u8>, AuditStoreError> {
        std::fs::read(self.leaf_path(index)).map_err(Into::into)
    }

    fn latest_sth(&self) -> Result<Option<SignedTreeHead>, AuditStoreError> {
        let Some((_, bytes)) = self.read_latest_in("sth")? else {
            return Ok(None);
        };
        let sth: SignedTreeHead =
            serde_json::from_slice(&bytes).map_err(|e| AuditStoreError::Decode(e.to_string()))?;
        Ok(Some(sth))
    }

    fn latest_cosigned_sth(&self) -> Result<Option<CoSignedTreeHead>, AuditStoreError> {
        let Some((_, bytes)) = self.read_latest_in("cosigned")? else {
            return Ok(None);
        };
        let sth: CoSignedTreeHead =
            serde_json::from_slice(&bytes).map_err(|e| AuditStoreError::Decode(e.to_string()))?;
        Ok(Some(sth))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sth::{InProcessSigner, SthBody, SthSigner};

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-audit-{tag}-{nanos}"));
        p
    }

    #[test]
    fn leaf_append_is_worm() {
        let dir = temp_dir("worm");
        let store = LocalDiskWormStore::open(&dir).unwrap();
        store.append_leaf(0, b"raw", &[1; 48]).unwrap();
        // Re-appending the same index is refused.
        let err = store.append_leaf(0, b"different", &[2; 48]).unwrap_err();
        assert!(matches!(err, AuditStoreError::AlreadyExists(_)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn read_back_what_was_written() {
        let dir = temp_dir("read");
        let store = LocalDiskWormStore::open(&dir).unwrap();
        store.append_leaf(7, b"event-7", &[7; 48]).unwrap();
        let back = store.read_leaf(7).unwrap();
        assert_eq!(back, b"event-7");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cosigned_sth_is_persisted_and_worm() {
        use crate::cosign::QuorumSigner;
        let dir = temp_dir("cosigned");
        let store = LocalDiskWormStore::open(&dir).unwrap();
        let mut signers: Vec<std::sync::Arc<dyn SthSigner>> = Vec::new();
        for kid in ["a", "b", "c"] {
            let (s, _) = InProcessSigner::generate(kid).unwrap();
            signers.push(std::sync::Arc::new(s));
        }
        let q = QuorumSigner::new(signers, 2).unwrap();
        let body = SthBody {
            tree_size: 7,
            root_hash: crate::bytes::Hash384([0x42; 48]),
            timestamp: 0,
        };
        let sth = q.sign(body).unwrap();
        store.record_cosigned_sth(&sth).unwrap();
        let latest = store.latest_cosigned_sth().unwrap().unwrap();
        assert_eq!(latest.body().unwrap().tree_size, 7);
        // WORM: re-recording the same tree_size is refused.
        let err = store.record_cosigned_sth(&sth).unwrap_err();
        assert!(matches!(err, AuditStoreError::AlreadyExists(_)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn latest_sth_returns_highest_tree_size() {
        let dir = temp_dir("sth");
        let store = LocalDiskWormStore::open(&dir).unwrap();
        let (signer, _pk) = InProcessSigner::generate("k").unwrap();
        for n in [1u64, 5, 3] {
            let sth = signer
                .sign(SthBody {
                    tree_size: n,
                    root_hash: crate::bytes::Hash384([u8::try_from(n).unwrap(); 48]),
                    timestamp: 0,
                })
                .unwrap();
            store.record_sth(&sth).unwrap();
        }
        let latest = store.latest_sth().unwrap().unwrap();
        assert_eq!(latest.body().unwrap().tree_size, 5);
        std::fs::remove_dir_all(dir).ok();
    }
}
