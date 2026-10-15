//! The local app-request ledger (F19 §7.6, `app-requests.cbor`): every
//! registration request this host made, its CMIS outcome, and — while it
//! waits in the outbox — the request document to submit.
//!
//! The file is root-owned `0600` (the service user's after the Linux
//! privilege drop) and replaced atomically. It holds personal data (paths
//! under home directories, uids, user names inside queued documents): queued
//! documents are dropped as soon as CMIS has the request, and terminal
//! entries are pruned [`RETENTION_SECS`] after their last change (F19 §10).
//!
//! Entries belong to a [`Requester`]: the uid on Unix, the full user SID on
//! Windows, where a RID alone is shared by users of different domains.
//!
//! The ledger holds at most [`MAX_ENTRIES`]. Each requester has at most
//! `registration.max_open_per_uid` open (queued or pending) entries, enforced
//! by the registrar; when the ledger is full, room is made by dropping the
//! oldest closed entry of the requester holding the most closed entries
//! ([`Ledger::make_room`]), so one requester's flood of requests costs that
//! requester its history, not everyone else their ability to register.

use std::path::{Path, PathBuf};

use ferro_svid::app_docs::AppRequestDoc;
use mia_helper_proto::{LocalRequestStatus, LocalState, ID_LEN};
use serde::{Deserialize, Serialize};

use crate::helper::auth::CallerIdentity;

/// How long a terminal entry is kept (30 days).
pub const RETENTION_SECS: i64 = 30 * 86_400;

/// Most entries kept. Beyond it a closed entry is dropped to make room, and
/// a new request is refused only when every entry is still open.
pub const MAX_ENTRIES: usize = 1000;

/// Largest ledger file read, in bytes.
const MAX_LEDGER_BYTES: u64 = 32 * 1024 * 1024;

/// Most entries one status answer carries.
pub const MAX_STATUS_ENTRIES: usize = 100;

/// Format version of the file.
const LEDGER_VERSION: u8 = 1;

/// Who made a local request: the key of every per-requester lookup
/// (idempotency, visibility, duplicates, the open-request cap). The uid on
/// Unix; on Windows the full user SID, because the RID (`uid`) alone is
/// shared by users of different domains (`S-1-5-21-A-…-1104` and
/// `S-1-5-21-B-…-1104`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Requester {
    uid: u32,
    /// Uppercase, so equal SIDs compare equal.
    sid: Option<String>,
}

impl Requester {
    /// The requester an authenticated caller is: keyed by its SID when the
    /// authenticator resolved one (Windows), by its uid otherwise. `None` on
    /// Windows when the SID is unknown: the RID is never used as a key there
    /// (fail closed).
    #[must_use]
    pub fn of(caller: &CallerIdentity) -> Option<Self> {
        match &caller.user_sid {
            Some(sid) => Some(Self {
                uid: caller.uid,
                sid: Some(sid.to_ascii_uppercase()),
            }),
            None if cfg!(windows) => None,
            None => Some(Self::uid(caller.uid)),
        }
    }

    /// A Unix requester.
    #[must_use]
    pub const fn uid(uid: u32) -> Self {
        Self { uid, sid: None }
    }

    /// The requester's SID (Windows), uppercase.
    #[must_use]
    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// Unix root, which sees every request.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.sid.is_none() && self.uid == 0
    }
}

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
    /// Who asked (Windows: the RID; the key is `requester_sid`).
    pub requester_uid: u32,
    /// **Windows.** The requester's full user SID, uppercase: the key that
    /// tells same-RID users of different domains apart. `None` on Unix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_sid: Option<String>,
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

    /// The requester that owns this entry.
    #[must_use]
    pub fn requester(&self) -> Requester {
        Requester {
            uid: self.requester_uid,
            sid: self.requester_sid.clone(),
        }
    }

    /// Whether `who` made this entry: the same SID when either side has
    /// one (Windows), the same uid otherwise.
    fn owned_by(&self, who: &Requester) -> bool {
        match (&who.sid, &self.requester_sid) {
            (Some(theirs), Some(mine)) => theirs.eq_ignore_ascii_case(mine),
            (None, None) => self.requester_uid == who.uid,
            _ => false,
        }
    }

    fn visible_to(&self, who: &Requester) -> bool {
        who.is_root() || self.owned_by(who)
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

    /// Make room for one more entry: when the ledger is full, drop the
    /// oldest closed entry of the requester holding the most closed entries
    /// (the one flooding it). Returns `false` when every entry is still open
    /// and nothing may be dropped; the new request is then refused.
    pub fn make_room(&mut self) -> bool {
        if self.entries.len() < MAX_ENTRIES {
            return true;
        }
        let mut closed: std::collections::HashMap<Requester, usize> =
            std::collections::HashMap::new();
        for e in self.entries.iter().filter(|e| !e.state.is_open()) {
            *closed.entry(e.requester()).or_default() += 1;
        }
        // Ties go to the smaller key, so the choice is deterministic.
        let Some(heaviest) = closed
            .into_iter()
            .max_by(|(a, na), (b, nb)| {
                na.cmp(nb)
                    .then_with(|| (b.uid, &b.sid).cmp(&(a.uid, &a.sid)))
            })
            .map(|(who, _)| who)
        else {
            return false;
        };
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.state.is_open() && e.owned_by(&heaviest))
            .min_by_key(|(_, e)| e.updated_at)
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                self.entries.remove(i);
                self.entries.len() < MAX_ENTRIES
            }
            None => false,
        }
    }

    /// How many open (queued or pending) entries `who` has.
    #[must_use]
    pub fn open_count(&self, who: &Requester) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state.is_open() && e.owned_by(who))
            .count()
    }

    /// The entry `who` created with idempotency id `caller_request_id`.
    #[must_use]
    pub fn by_caller_id(
        &self,
        who: &Requester,
        caller_request_id: &[u8; ID_LEN],
    ) -> Option<&LedgerEntry> {
        self.entries
            .iter()
            .find(|e| e.owned_by(who) && &e.caller_request_id == caller_request_id)
    }

    /// An open (queued or pending) entry of `who` for the same binary, path
    /// and target user.
    #[must_use]
    pub fn open_duplicate(
        &self,
        who: &Requester,
        target_uid: Option<u32>,
        path: &str,
        bin_sha: &str,
    ) -> Option<&LedgerEntry> {
        self.entries.iter().find(|e| {
            e.state.is_open()
                && e.owned_by(who)
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

    /// The entries `who` may see (its own; all for Unix root) among `ids`
    /// (local or CMIS ids), or the most recent ones when `ids` is empty.
    #[must_use]
    pub fn visible(&self, who: &Requester, ids: &[[u8; ID_LEN]]) -> Vec<LocalRequestStatus> {
        let mut out: Vec<&LedgerEntry> = self
            .entries
            .iter()
            .filter(|e| e.visible_to(who))
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
    // The decoder's message can quote stored strings (paths under home
    // directories, user names): it never reaches the log (F19 §8 "I").
    let file: LedgerFile = ciborium::from_reader(&bytes[..])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed ledger"))?;
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
            requester_sid: None,
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
        let alice = Requester::uid(1000);
        let mine: Vec<_> = l
            .visible(&alice, &[])
            .iter()
            .map(|s| s.local_id[0])
            .collect();
        assert_eq!(mine, vec![3, 1]);
        assert_eq!(l.visible(&alice, &[[2; ID_LEN]]).len(), 0);
        assert_eq!(l.visible(&Requester::uid(0), &[]).len(), 3);
        assert_eq!(l.counts().pending, 1);
        assert_eq!(l.counts().closed, 1);
        assert_eq!(l.open_count(&alice), 1);

        // Idempotency and open-duplicate lookups.
        assert!(l.by_caller_id(&alice, &[1 ^ 0xff; ID_LEN]).is_some());
        assert!(l
            .by_caller_id(&Requester::uid(1001), &[1 ^ 0xff; ID_LEN])
            .is_none());
        assert!(l
            .open_duplicate(&alice, Some(1000), "/opt/app1", &hex::encode([1u8; 48]))
            .is_some());
        assert!(l
            .open_duplicate(&alice, Some(1000), "/opt/app3", &hex::encode([3u8; 48]))
            .is_none());

        // Terminal entries go after 30 days; open ones stay.
        assert!(l.prune(20 + RETENTION_SECS));
        let left: Vec<_> = l.entries().iter().map(|e| e.local_id[0]).collect();
        assert_eq!(left, vec![1, 3]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Windows: two users of different domains with the same RID never see
    /// each other's requests nor collide on idempotency ids or duplicates.
    #[test]
    fn same_rid_users_of_different_domains_are_kept_apart() {
        let sid_a = "S-1-5-21-1111-2222-3333-1104";
        let sid_b = "S-1-5-21-4444-5555-6666-1104";
        let caller = |sid: &str| {
            let mut c = CallerIdentity::new(7, 1104, 0, [1; 48]);
            c.user_sid = Some(sid.to_string());
            c
        };
        let a = Requester::of(&caller(sid_a)).unwrap();
        let b = Requester::of(&caller(sid_b)).unwrap();
        assert_ne!(a, b);
        // SIDs compare case-insensitively.
        assert_eq!(
            Requester::of(&caller(&sid_a.to_ascii_lowercase())).unwrap(),
            a
        );
        assert!(!a.is_root());

        let mut l = Ledger::open(Path::new("/nonexistent/mia-ledger-sid"));
        let mut e = entry(1, 1104, LocalState::Pending, 10);
        e.requester_sid = a.sid().map(str::to_string);
        l.insert(e);

        assert_eq!(l.visible(&a, &[]).len(), 1);
        assert_eq!(l.visible(&b, &[]).len(), 0);
        assert_eq!(l.visible(&b, &[[1; ID_LEN]]).len(), 0);
        assert!(l.by_caller_id(&a, &[1 ^ 0xff; ID_LEN]).is_some());
        assert!(l.by_caller_id(&b, &[1 ^ 0xff; ID_LEN]).is_none());
        let sha = hex::encode([1u8; 48]);
        assert!(l
            .open_duplicate(&b, Some(1104), "/opt/app1", &sha)
            .is_none());
        assert_eq!(l.open_count(&b), 0);
        // Nor does the Unix uid 1104, or Unix root, match a SID-keyed entry
        // as its owner (root still sees everything on Unix).
        assert!(l
            .by_caller_id(&Requester::uid(1104), &[1 ^ 0xff; ID_LEN])
            .is_none());
        assert_eq!(l.visible(&Requester::uid(0), &[]).len(), 1);
    }

    /// One requester filling the ledger loses its own oldest closed entry;
    /// the others keep theirs, and the ledger refuses only when every entry
    /// is still open.
    #[test]
    fn a_full_ledger_drops_the_flooders_oldest_closed_entry() {
        let mut l = Ledger::open(Path::new("/nonexistent/mia-ledger-full"));
        let id = |i: usize| {
            let mut b = [0u8; ID_LEN];
            b[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
            b
        };
        for i in 0..MAX_ENTRIES {
            let (uid, state) = if i < 10 {
                (1000, LocalState::Denied)
            } else {
                (666, LocalState::Refused)
            };
            let mut e = entry(0, uid, state, 1_000 + i64::try_from(i).unwrap());
            e.local_id = id(i);
            e.caller_request_id = id(i);
            l.insert(e);
        }
        assert_eq!(l.entries().len(), MAX_ENTRIES);
        assert!(l.make_room());
        assert_eq!(l.entries().len(), MAX_ENTRIES - 1);
        assert!(l.get(&id(10)).is_none(), "the flooder's oldest went");
        assert!((0..10).all(|i| l.get(&id(i)).is_some()), "others kept");

        // Every entry open: nothing may be dropped.
        let mut l = Ledger::open(Path::new("/nonexistent/mia-ledger-open"));
        for i in 0..MAX_ENTRIES {
            let mut e = entry(
                0,
                1000 + u32::try_from(i % 50).unwrap(),
                LocalState::Pending,
                1,
            );
            e.local_id = id(i);
            l.insert(e);
        }
        assert!(!l.make_room());
        assert_eq!(l.entries().len(), MAX_ENTRIES);
    }

    /// The decode error of a damaged ledger is logged: it must not quote the
    /// personal data stored in it.
    #[test]
    fn a_malformed_ledger_error_never_quotes_its_contents() {
        use ciborium::Value;
        let dir = std::env::temp_dir().join(format!("mia-ledger-pii-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app-requests.cbor");
        // The decoder quotes an unknown key (`deny_unknown_fields`) in its
        // message; a damaged file can hold any stored string there.
        let secret = "/home/alice/secret-tool";
        let bad = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (
                Value::Text("entries".into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text(secret.into()),
                    Value::Integer(1.into()),
                )])]),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&bad, &mut bytes).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let e = read_only(&path).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(!format!("{e} {e:?}").contains("alice"), "{e:?}");
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
