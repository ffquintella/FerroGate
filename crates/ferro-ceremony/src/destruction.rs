//! End-of-window destruction with post-zeroization verification.
//!
//! At the close of the 90-day cross-sign window the outgoing root's five shares
//! are destroyed *simultaneously* — each holder zeroizes their medium. This
//! module models the per-medium step: overwrite the sealed-share file in place
//! with zeros, flush it to stable storage, then **read it back** and prove that
//! (a) every byte is zero and (b) no recoverable share survives. Destruction
//! that is not followed by a passing read-back is not destruction.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::media::SealedShare;
use crate::{CeremonyError, Result};

/// The observable, irreversible outcome of destroying one sealed-share medium.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestructionRecord {
    /// Path to the medium that was overwritten.
    pub path: String,
    /// Root key id the destroyed share belonged to.
    pub root_kid: String,
    /// Holder label recorded on the medium.
    pub holder: String,
    /// The destroyed share's evaluation index.
    pub index: u8,
    /// Number of bytes overwritten.
    pub bytes_zeroized: usize,
    /// Whether the post-zeroization read-back confirmed irrecoverability.
    pub verified: bool,
    /// Unix-seconds time of destruction.
    pub destroyed_at: i64,
}

/// Zeroize one sealed-share medium in place and verify it afterward.
///
/// The share's metadata (root kid, holder, index) is captured from the medium
/// *before* it is overwritten so the resulting [`DestructionRecord`] — which is
/// itself folded into the destruction-ceremony minutes — names exactly what was
/// destroyed. The file is then overwritten with `0x00` over its full length,
/// `fsync`'d, and read back; the call fails with [`CeremonyError::NotDestroyed`]
/// if any byte survives non-zero or the bytes still parse as a usable share.
pub fn destroy_media(path: impl AsRef<Path>, now: i64) -> Result<DestructionRecord> {
    let path = path.as_ref();
    let original = fs::read(path).map_err(|e| CeremonyError::Io(format!("read {}: {e}", path.display())))?;
    // Capture metadata while the share is still intact. We tolerate a medium
    // that no longer parses (already partly damaged) — destruction still runs.
    let (root_kid, holder, index) = match SealedShare::from_json(&original) {
        Ok(share) => (share.root_kid, share.holder, share.index),
        Err(_) => ("<unparseable>".to_string(), "<unknown>".to_string(), 0),
    };
    let len = original.len();
    drop(original);

    overwrite_zeros(path, len)?;
    verify_destruction(path)?;

    Ok(DestructionRecord {
        path: path.display().to_string(),
        root_kid,
        holder,
        index,
        bytes_zeroized: len,
        verified: true,
        destroyed_at: now,
    })
}

/// Overwrite `path` with `len` zero bytes and flush to stable storage.
fn overwrite_zeros(path: &Path, len: usize) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| CeremonyError::Io(format!("open {}: {e}", path.display())))?;
    let zeros = vec![0u8; len];
    f.write_all(&zeros)
        .map_err(|e| CeremonyError::Io(format!("overwrite {}: {e}", path.display())))?;
    f.flush()
        .map_err(|e| CeremonyError::Io(format!("flush {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| CeremonyError::Io(format!("fsync {}: {e}", path.display())))?;
    Ok(())
}

/// Read `path` back and prove the share is irrecoverable: every byte is zero and
/// the contents no longer form a usable sealed share. Used standalone to
/// re-audit a previously-destroyed medium.
pub fn verify_destruction(path: impl AsRef<Path>) -> Result<()> {
    let path: PathBuf = path.as_ref().to_path_buf();
    let after =
        fs::read(&path).map_err(|e| CeremonyError::Io(format!("read-back {}: {e}", path.display())))?;

    if let Some(pos) = after.iter().position(|&b| b != 0) {
        return Err(CeremonyError::NotDestroyed(format!(
            "{}: non-zero byte at offset {pos} after zeroization",
            path.display()
        )));
    }
    // Belt and braces: zero bytes cannot parse as a sealed share, but if a
    // future format ever made all-zero valid we still refuse to call it gone.
    if SealedShare::from_json(&after)
        .and_then(|s| s.to_share())
        .is_ok()
    {
        return Err(CeremonyError::NotDestroyed(format!(
            "{}: a usable share survived zeroization",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::SealedShareSet;

    fn scratch_file(name: &str, bytes: &[u8]) -> PathBuf {
        let mut dir = std::env::temp_dir();
        // Unique-ish per test name; tests here use distinct names.
        dir.push(format!("ferro-ceremony-destroy-{name}"));
        let path = dir.with_extension("json");
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn destroy_zeroizes_and_verifies() {
        let set = SealedShareSet::seal("root-x", &[7u8; 32], 3, &["a".into(), "b".into(), "c".into()], 1000).unwrap();
        let json = set.shares[0].to_json().unwrap();
        let path = scratch_file("ok", &json);

        // Intact share reconstructs through verify_integrity before destruction.
        set.shares[0].to_share().unwrap();

        let record = destroy_media(&path, 2000).unwrap();
        assert!(record.verified);
        assert_eq!(record.root_kid, "root-x");
        assert_eq!(record.bytes_zeroized, json.len());

        // Independent re-audit passes, and the bytes no longer parse as a share.
        verify_destruction(&path).unwrap();
        let after = fs::read(&path).unwrap();
        assert!(after.iter().all(|&b| b == 0));
        assert!(SealedShare::from_json(&after).is_err());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_destruction_rejects_a_live_share() {
        let set = SealedShareSet::seal("root-y", &[9u8; 32], 3, &["a".into(), "b".into(), "c".into()], 1000).unwrap();
        let path = scratch_file("live", &set.shares[0].to_json().unwrap());
        assert!(matches!(
            verify_destruction(&path),
            Err(CeremonyError::NotDestroyed(_))
        ));
        fs::remove_file(&path).ok();
    }
}
