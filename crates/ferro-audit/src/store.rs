//! Backing-store abstraction for the audit log.
//!
//! Production deployments use S3 with Object Lock Compliance mode (10-year
//! retention) and a FoundationDB mirror; that lands in M4. The M3 surface
//! defines [`AuditStore`] and ships [`LocalDiskWormStore`], a local-filesystem
//! implementation suitable for dev and CI.
//!
//! The WORM property here is enforced by `OpenOptions::create_new(true)`:
//! once a leaf file (or an STH file) exists, the store refuses to overwrite
//! it and returns [`AuditStoreError::AlreadyExists`]. Real WORM (object lock
//! / hardware write-protect) lives in the production store.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

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

    /// Read back the raw event bytes for a previously-appended leaf.
    fn read_leaf(&self, index: u64) -> Result<Vec<u8>, AuditStoreError>;

    /// The largest tree size persisted so far. Returns `None` if the store has
    /// recorded no STHs yet.
    fn latest_sth(&self) -> Result<Option<SignedTreeHead>, AuditStoreError>;
}

/// Local-disk WORM-style store.
///
/// Layout under `root`:
///
/// ```text
/// <root>/leaves/<20-digit zero-padded index>.cbor       # canonical event bytes
/// <root>/leaves/<20-digit zero-padded index>.hash       # 48-byte SHA3-384 leaf
/// <root>/sth/<20-digit zero-padded tree_size>.json      # SignedTreeHead JSON
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

    fn read_leaf(&self, index: u64) -> Result<Vec<u8>, AuditStoreError> {
        std::fs::read(self.leaf_path(index)).map_err(Into::into)
    }

    fn latest_sth(&self) -> Result<Option<SignedTreeHead>, AuditStoreError> {
        let dir = self.root.join("sth");
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
        let Some((_, path)) = best else {
            return Ok(None);
        };
        let bytes = std::fs::read(&path)?;
        let sth: SignedTreeHead =
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
