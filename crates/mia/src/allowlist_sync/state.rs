//! `allowlist.state`: what this host last accepted from `SyncAllowlist`
//! (F19 §6.2) — the rollback floor the next body is checked against.
//!
//! One small JSON file per environment, root-owned `0600`, replaced
//! atomically. It records the host the body was bound to, its generation and
//! entry digest, and its validity window. It holds no entries and no personal
//! data.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::helper::allowlist::Allowlist;

/// Format version of the state file.
const STATE_VERSION: u8 = 1;

/// Largest state file read, in bytes (it is a few hundred).
const MAX_STATE_BYTES: u64 = 4096;

/// The held v2 generation of one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncState {
    /// Format version, 1.
    pub v: u8,
    /// The host the accepted body was bound to.
    pub host_uuid: String,
    /// Its generation.
    pub generation: u64,
    /// Its `entries_digest`, lowercase hex.
    pub entries_digest: String,
    /// Its issuance time, Unix seconds.
    pub issued_at: i64,
    /// Its hard expiry, Unix seconds.
    pub not_after: i64,
}

impl SyncState {
    /// The state of an accepted v2 allowlist (`None` for a v1 body).
    #[must_use]
    pub fn of(allowlist: &Allowlist) -> Option<Self> {
        Some(Self {
            v: STATE_VERSION,
            host_uuid: allowlist.host_uuid()?.to_string(),
            generation: allowlist.generation()?,
            entries_digest: hex::encode(allowlist.entries_digest()?),
            issued_at: allowlist.issued_at(),
            not_after: allowlist.not_after(),
        })
    }

    /// The digest as bytes; `None` when the file held a malformed one.
    #[must_use]
    pub fn digest(&self) -> Option<[u8; 48]> {
        hex::decode(&self.entries_digest).ok()?.try_into().ok()
    }

    /// Whether more than half of the body's validity window has passed, so
    /// the next sync asks for a fresh body (`have_generation = 0`) even when
    /// the generation is unchanged.
    #[must_use]
    pub fn past_half_life(&self, now: i64) -> bool {
        let half = (self.not_after - self.issued_at) / 2;
        now >= self.issued_at.saturating_add(half)
    }

    /// Read the state at `path`. A missing file is `Ok(None)`; an unreadable
    /// or malformed one is an error the caller logs (it then falls back to
    /// the generation of the allowlist in force, if any).
    pub fn load(path: &Path) -> std::io::Result<Option<Self>> {
        let file = match crate::system_dir::open_trusted(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(file, MAX_STATE_BYTES + 1),
            &mut bytes,
        )?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "allowlist state file too large",
            ));
        }
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if state.v != STATE_VERSION || state.digest().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported allowlist state file",
            ));
        }
        Ok(Some(state))
    }

    /// Replace the state at `path` atomically, `0600`.
    pub fn store(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        crate::atomic_file::write(path, &bytes, 0o600)
    }
}

/// The default state file of the allowlist body at `allowlist_path`: the same
/// name with the extension `state` (`allowlist.cbor` → `allowlist.state`,
/// `allowlist-<env>.cbor` → `allowlist-<env>.state`).
#[must_use]
pub fn default_state_path(allowlist_path: &Path) -> PathBuf {
    allowlist_path.with_extension("state")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SyncState {
        SyncState {
            v: 1,
            host_uuid: "h".into(),
            generation: 9,
            entries_digest: hex::encode([7u8; 48]),
            issued_at: 1000,
            not_after: 2000,
        }
    }

    #[test]
    fn state_round_trips_and_rejects_unknown_fields() {
        let dir = std::env::temp_dir().join(format!("mia-sync-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.state");
        assert_eq!(SyncState::load(&path).unwrap(), None);
        state().store(&path).unwrap();
        assert_eq!(SyncState::load(&path).unwrap(), Some(state()));
        std::fs::write(
            &path,
            br#"{"v":1,"host_uuid":"h","generation":1,"entries_digest":"00","issued_at":0,"not_after":1,"x":1}"#,
        )
        .unwrap();
        assert!(SyncState::load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn half_life_and_default_path() {
        assert!(!state().past_half_life(1499));
        assert!(state().past_half_life(1500));
        assert_eq!(
            default_state_path(Path::new("/etc/ferrogate/allowlist-prod.cbor")),
            Path::new("/etc/ferrogate/allowlist-prod.state")
        );
    }
}
