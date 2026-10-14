//! The local app-request ledger (F19 §7.6, `app-requests.cbor`): every
//! registration request this host made, its CMIS outcome, and — while it
//! waits in the outbox — the request document to submit.
//!
//! The file is root-owned `0600` (the service user's after the Linux
//! privilege drop) and replaced atomically. It holds personal data (paths
//! under home directories, uids, user names inside queued documents): queued
//! documents are dropped as soon as CMIS has the request, and terminal
//! entries are pruned [`RETENTION_SECS`] after their last change (F19 §10).

use std::path::{Path, PathBuf};

use ferro_svid::app_docs::AppRequestDoc;
use mia_helper_proto::{LocalRequestStatus, LocalState, ID_LEN};
use serde::{Deserialize, Serialize};

/// How long a terminal entry is kept (30 days).
pub const RETENTION_SECS: i64 = 30 * 86_400;

/// Most entries kept; a new request is refused beyond it.
pub const MAX_ENTRIES: usize = 1000;

/// Largest ledger file read, in bytes.
const MAX_LEDGER_BYTES: u64 = 32 * 1024 * 1024;

/// Most entries one status answer carries.
pub const MAX_STATUS_ENTRIES: usize = 100;

/// Format version of the file.
const LEDGER_VERSION: u8 = 1;

/// One local request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// The daemon's id, returned to the requester.
    pub local_id: [u8; ID_LEN],
    /// The requester's idempotency id (`RegisterSelf`/`RegisterFile`).
    pub caller_request_id: [u8; ID_LEN],
    /// The daemon-generated `client_request_id` sent to CMIS (never the
    /// requester's: another local user could collide with it).
    pub client_request_id: [u8; ID_LEN],
    /// The CMIS request id, once submitted.
    pub request_id: Option<[u8; ID_LEN]>,
    /// The approval, once approved.
    pub approval_id: Option<[u8; ID_LEN]>,
    /// Who asked.
    pub requester_uid: u32,
    /// For whom (Unix uid; the RID on Windows).
    pub target_uid: Option<u32>,
    /// Canonical path of the binary.
    pub path: String,
    /// Lowercase hex SHA-384 of the binary.
    pub bin_sha: String,
    /// Where it stands.
    pub state: LocalState,
    /// Revision in its lineage, once known.
    pub revision: Option<u32>,
    /// Denial reason code.
    pub deny_reason_code: Option<u32>,
    /// Denial message for the requester (≤ 200, from an administrator).
    pub deny_message: Option<String>,
    /// Created, Unix seconds.
    pub created_at: i64,
    /// Last changed, Unix seconds.
    pub updated_at: i64,
    /// Earliest next submission attempt (outbox), Unix seconds.
    pub next_attempt_at: i64,
    /// The document still to submit (outbox); `None` once CMIS has it.
    pub doc: Option<AppRequestDoc>,
}

impl LedgerEntry {
    /// The wire status of this entry.
    #[must_use]
    pub fn status(&self) -> LocalRequestStatus {
        LocalRequestStatus {
            local_id: self.local_id,
            request_id: self.request_id,
            state: self.state,
            revision: self.revision,
            approval_id: self.approval_id,
            path: self.path.clone(),
            updated_at: self.updated_at,
            deny_reason_code: self.deny_reason_code,
            deny_message: self.deny_message.clone(),
        }
    }

    fn visible_to(&self, uid: u32) -> bool {
        uid == 0 || self.requester_uid == uid
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    v: u8,
    entries: Vec<LedgerEntry>,
}

/// The ledger, in memory and on disk.
#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    entries: Vec<LedgerEntry>,
}

impl Ledger {
    /// Load the ledger at `path`. A missing file is an empty ledger; an
    /// unreadable or malformed one is logged and starts empty (it is
    /// replaced on the next change).
    #[must_use]
    pub fn open(path: &Path) -> Self {
        let entries = match read(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "app-request ledger unreadable; starting empty");
                Vec::new()
            }
        };
        Self {
            path: path.to_path_buf(),
            entries,
        }
    }

    /// Write the ledger (atomic, `0600`).
    pub fn save(&self) -> std::io::Result<()> {
        let file = LedgerFile {
            v: LEDGER_VERSION,
            entries: self.entries.clone(),
        };
        let mut bytes = Vec::with_capacity(256 * self.entries.len() + 16);
        ciborium::into_writer(&file, &mut bytes).map_err(std::io::Error::other)?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        crate::atomic_file::write(&self.path, &bytes, 0o600)
    }

    /// Every entry.
    #[must_use]
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// Room for one more entry.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.entries.len() < MAX_ENTRIES
    }

    /// The entry `uid` created with idempotency id `caller_request_id`.
    #[must_use]
    pub fn by_caller_id(&self, uid: u32, caller_request_id: &[u8; ID_LEN]) -> Option<&LedgerEntry> {
        self.entries
            .iter()
            .find(|e| e.requester_uid == uid && &e.caller_request_id == caller_request_id)
    }

    /// An open (queued or pending) entry for the same binary, path and users.
    #[must_use]
    pub fn open_duplicate(
        &self,
        requester_uid: u32,
        target_uid: Option<u32>,
        path: &str,
        bin_sha: &str,
    ) -> Option<&LedgerEntry> {
        self.entries.iter().find(|e| {
            e.state.is_open()
                && e.requester_uid == requester_uid
                && e.target_uid == target_uid
                && e.path == path
                && e.bin_sha == bin_sha
        })
    }

    /// The entry with local id `local_id`.
    #[must_use]
    pub fn get(&self, local_id: &[u8; ID_LEN]) -> Option<&LedgerEntry> {
        self.entries.iter().find(|e| &e.local_id == local_id)
    }

    /// Mutable access to the entry with local id `local_id`.
    pub fn get_mut(&mut self, local_id: &[u8; ID_LEN]) -> Option<&mut LedgerEntry> {
        self.entries.iter_mut().find(|e| &e.local_id == local_id)
    }

    /// Add an entry.
    pub fn insert(&mut self, entry: LedgerEntry) {
        self.entries.push(entry);
    }

    /// The entries `uid` may see (its own; all for root) among `ids` (local
    /// or CMIS ids), or the most recent ones when `ids` is empty.
    #[must_use]
    pub fn visible(&self, uid: u32, ids: &[[u8; ID_LEN]]) -> Vec<LocalRequestStatus> {
        let mut out: Vec<&LedgerEntry> = self
            .entries
            .iter()
            .filter(|e| e.visible_to(uid))
            .filter(|e| {
                ids.is_empty()
                    || ids
                        .iter()
                        .any(|id| &e.local_id == id || e.request_id.as_ref() == Some(id))
            })
            .collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.updated_at));
        out.truncate(MAX_STATUS_ENTRIES);
        out.into_iter().map(LedgerEntry::status).collect()
    }

    /// Queued entries due for submission at `now`.
    #[must_use]
    pub fn due(&self, now: i64) -> Vec<[u8; ID_LEN]> {
        self.entries
            .iter()
            .filter(|e| {
                e.state == LocalState::Queued && e.doc.is_some() && e.next_attempt_at <= now
            })
            .map(|e| e.local_id)
            .collect()
    }

    /// Pending entries with a CMIS request id, for the status poll.
    #[must_use]
    pub fn pending_request_ids(&self) -> Vec<[u8; ID_LEN]> {
        self.entries
            .iter()
            .filter(|e| e.state == LocalState::Pending)
            .filter_map(|e| e.request_id)
            .collect()
    }

    /// Drop terminal entries unchanged for [`RETENTION_SECS`]. Returns
    /// whether anything was dropped.
    pub fn prune(&mut self, now: i64) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.state.is_open() || now - e.updated_at < RETENTION_SECS);
        self.entries.len() != before
    }

    /// Counts by state, for the status endpoint.
    #[must_use]
    pub fn counts(&self) -> mia_status_proto::RegistrationCounts {
        let mut c = mia_status_proto::RegistrationCounts::default();
        for e in &self.entries {
            let slot = match e.state {
                LocalState::Queued => &mut c.queued,
                LocalState::Pending => &mut c.pending,
                LocalState::Approved | LocalState::AutoApproved => &mut c.approved,
                LocalState::Denied | LocalState::Expired | LocalState::Refused => &mut c.closed,
            };
            *slot = slot.saturating_add(1);
        }
        c
    }
}

fn read(path: &Path) -> std::io::Result<Vec<LedgerEntry>> {
    let file = crate::system_dir::open_trusted(path)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAX_LEDGER_BYTES + 1),
        &mut bytes,
    )?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ledger too large",
        ));
    }
    let file: LedgerFile = ciborium::from_reader(&bytes[..])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    if file.v != LEDGER_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported ledger version",
        ));
    }
    Ok(file.entries)
}

/// Read the ledger at `path` for a read-only listing (`mia app list`).
pub fn read_only(path: &Path) -> std::io::Result<Vec<LedgerEntry>> {
    read(path)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn entry(n: u8, uid: u32, state: LocalState, updated_at: i64) -> LedgerEntry {
        LedgerEntry {
            local_id: [n; ID_LEN],
            caller_request_id: [n ^ 0xff; ID_LEN],
            client_request_id: [n ^ 0x0f; ID_LEN],
            request_id: None,
            approval_id: None,
            requester_uid: uid,
            target_uid: Some(uid),
            path: format!("/opt/app{n}"),
            bin_sha: hex::encode([n; 48]),
            state,
            revision: None,
            deny_reason_code: None,
            deny_message: None,
            created_at: updated_at,
            updated_at,
            next_attempt_at: 0,
            doc: None,
        }
    }

    #[test]
    fn persists_scopes_visibility_and_prunes() {
        let dir = std::env::temp_dir().join(format!("mia-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("app-requests.cbor");
        let mut l = Ledger::open(&path);
        assert_eq!(l.entries().len(), 0);
        l.insert(entry(1, 1000, LocalState::Pending, 10));
        l.insert(entry(2, 1001, LocalState::Denied, 20));
        l.insert(entry(3, 1000, LocalState::Approved, 30));
        l.save().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let mut l = Ledger::open(&path);
        assert_eq!(l.entries().len(), 3);

        // A user sees only their own entries; root sees all, newest first.
        let mine: Vec<_> = l.visible(1000, &[]).iter().map(|s| s.local_id[0]).collect();
        assert_eq!(mine, vec![3, 1]);
        assert_eq!(l.visible(1000, &[[2; ID_LEN]]).len(), 0);
        assert_eq!(l.visible(0, &[]).len(), 3);
        assert_eq!(l.counts().pending, 1);
        assert_eq!(l.counts().closed, 1);

        // Idempotency and open-duplicate lookups.
        assert!(l.by_caller_id(1000, &[1 ^ 0xff; ID_LEN]).is_some());
        assert!(l.by_caller_id(1001, &[1 ^ 0xff; ID_LEN]).is_none());
        assert!(l
            .open_duplicate(1000, Some(1000), "/opt/app1", &hex::encode([1u8; 48]))
            .is_some());
        assert!(l
            .open_duplicate(1000, Some(1000), "/opt/app3", &hex::encode([3u8; 48]))
            .is_none());

        // Terminal entries go after 30 days; open ones stay.
        assert!(l.prune(20 + RETENTION_SECS));
        let left: Vec<_> = l.entries().iter().map(|e| e.local_id[0]).collect();
        assert_eq!(left, vec![1, 3]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_ledger_starts_empty() {
        let dir = std::env::temp_dir().join(format!("mia-ledger-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app-requests.cbor");
        std::fs::write(&path, b"not cbor").unwrap();
        assert_eq!(Ledger::open(&path).entries().len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
