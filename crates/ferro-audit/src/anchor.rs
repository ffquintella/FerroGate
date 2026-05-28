//! External transparency-log anchor publisher with persistent back-fill
//! (M4 / F07-continued).
//!
//! Once per minute the latest co-signed STH is meant to be anchored to a
//! public transparency log (Sigsum or Rekor) so that any divergence between
//! the WORM bucket and the public log is itself detectable. External logs
//! can be unavailable — network blips, rate-limits, outages — and an audit
//! pipeline that silently drops anchors during an outage is worse than one
//! that hasn't been built yet. This module therefore separates *what* is
//! anchored from *where* it goes:
//!
//! - [`Anchor`] — the transparency-log driver trait. One implementation per
//!   log family (Sigsum, Rekor v1, Rekor v2, …); the HTTP wire is the
//!   operator's deployment-wiring concern and stays behind this trait.
//!   The publisher only cares about its [`AnchorError`] taxonomy
//!   (`Transient` ⇒ retry next drain, `Permanent` ⇒ park in `dead/`).
//! - [`AnchorQueue`] — a disk-backed WORM queue keyed by `tree_size`.
//!   Pending [`CoSignedTreeHead`]s and per-entry `enqueued_at` markers
//!   survive process restarts; receipts ([`AnchorReceipt`]) land alongside
//!   them under `receipts/`. The queue is the back-fill artefact — pending
//!   entries are never lost just because the publisher process died.
//! - [`AnchorPublisher`] — drives a single drain pass over the queue.
//!   Returns a [`DrainOutcome`] (counts + worst-case backlog age) which the
//!   caller's monitoring uses to alert on backlog ≥ 5 min, per
//!   `docs/audit.md` §"Anchor outage".
//!
//! Scheduling is out of scope here: a 60-second tokio task in CMIS calls
//! [`AnchorPublisher::drain_once`] and feeds the [`DrainOutcome`] into the
//! existing metrics surface. Tests in this module exercise the queue and
//! drain semantics with an in-memory anchor that can be flipped between
//! "succeed", "transient-fail", and "permanent-fail" between drains.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cosign::CoSignedTreeHead;

/// A receipt returned by an external transparency log after it has accepted
/// an STH. Stored alongside the queue entry under `receipts/`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorReceipt {
    /// Human-readable name of the anchor that produced the receipt
    /// (e.g. `"sigsum.example.org"`, `"rekor.sigstore.dev"`).
    pub anchor_name: String,
    /// `tree_size` of the STH this receipt covers; the same key the queue
    /// uses on disk.
    pub tree_size: u64,
    /// 1-based index assigned to the entry by the external log. Together
    /// with `anchor_name` this is the public coordinate a third party can
    /// use to look the entry up.
    pub log_index: u64,
    /// Opaque bytes returned by the log. The publisher does not interpret
    /// them; verification of the receipt against the log's own STH is the
    /// reader's job and is per-log family.
    pub receipt_bytes: Vec<u8>,
    /// Unix-seconds timestamp at which this receipt was recorded locally.
    pub anchored_at_unix: i64,
}

/// Failure modes a transparency-log driver can report.
///
/// The publisher uses the distinction operationally: `Transient` entries
/// stay in the queue and are retried on the next drain; `Permanent` entries
/// are quarantined under `dead/` so they do not block back-fill of the
/// rest of the queue, and an operator can inspect them later.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// Network blip, rate limit, log temporarily unavailable: retry later.
    #[error("transient: {0}")]
    Transient(String),
    /// The log rejected the entry for a structural reason (malformed body,
    /// unknown log key, retired log instance). Retrying will not help.
    #[error("permanent: {0}")]
    Permanent(String),
}

/// A transparency-log driver. One implementation per log family.
///
/// Implementations must be safe to call from any thread, and `submit` is
/// expected to be blocking from the publisher's perspective: scheduling the
/// HTTP call onto a runtime is the implementation's concern.
pub trait Anchor: Send + Sync {
    /// Human-readable name of this anchor; stamped into every
    /// [`AnchorReceipt`].
    fn name(&self) -> &str;
    /// Submit `sth` to the log and return the receipt on success.
    fn submit(&self, sth: &CoSignedTreeHead) -> Result<AnchorReceipt, AnchorError>;
}

/// Failure modes for queue and publisher operations.
#[derive(Debug, thiserror::Error)]
pub enum AnchorQueueError {
    /// Filesystem I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A queue entry already exists for this `tree_size`. The queue is
    /// WORM-keyed by `tree_size` so that two replicas that produce the
    /// same STH cannot both enqueue it under the same key — the second
    /// enqueue is a no-op (`Ok(false)` from [`AnchorQueue::enqueue`]) and
    /// this error is reserved for paths where the absence is unexpected.
    #[error("entry already exists: {0}")]
    AlreadyExists(PathBuf),
    /// JSON encode/decode failed.
    #[error("codec: {0}")]
    Codec(String),
    /// A queue entry on disk parsed as the wrong shape.
    #[error("malformed entry: {0}")]
    Malformed(String),
}

/// Disk-backed pending-anchor queue.
///
/// Layout under `root`:
///
/// ```text
/// <root>/pending/<tree_size:020>.sth.json    # CoSignedTreeHead awaiting anchor
/// <root>/pending/<tree_size:020>.enq         # Unix-seconds (ASCII) of first enqueue
/// <root>/receipts/<tree_size:020>.json       # AnchorReceipt after success
/// <root>/dead/<tree_size:020>.sth.json       # entries the anchor refused permanently
/// <root>/dead/<tree_size:020>.err            # the permanent error string
/// ```
///
/// Pending entries are WORM-keyed by `tree_size`: re-enqueuing the same
/// `tree_size` is a no-op rather than an overwrite, so a publisher restart
/// that re-observes the same STH does not lose the original `enqueued_at`
/// marker (and therefore the backlog age).
pub struct AnchorQueue {
    root: PathBuf,
}

impl AnchorQueue {
    /// Open (creating if needed) the queue rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, AnchorQueueError> {
        let root = root.into();
        for sub in ["pending", "receipts", "dead"] {
            std::fs::create_dir_all(root.join(sub))?;
        }
        Ok(Self { root })
    }

    /// Root directory of the queue.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn pending_sth_path(&self, tree_size: u64) -> PathBuf {
        self.root.join(format!("pending/{tree_size:020}.sth.json"))
    }

    fn pending_enq_path(&self, tree_size: u64) -> PathBuf {
        self.root.join(format!("pending/{tree_size:020}.enq"))
    }

    fn receipt_path(&self, tree_size: u64) -> PathBuf {
        self.root.join(format!("receipts/{tree_size:020}.json"))
    }

    fn dead_sth_path(&self, tree_size: u64) -> PathBuf {
        self.root.join(format!("dead/{tree_size:020}.sth.json"))
    }

    fn dead_err_path(&self, tree_size: u64) -> PathBuf {
        self.root.join(format!("dead/{tree_size:020}.err"))
    }

    /// Enqueue `sth` for anchoring at `now_unix`. Returns `Ok(true)` if a
    /// new entry was created, `Ok(false)` if an entry for that `tree_size`
    /// already existed (the original `enqueued_at` is preserved).
    pub fn enqueue(&self, sth: &CoSignedTreeHead, now_unix: i64) -> Result<bool, AnchorQueueError> {
        let body = sth
            .body()
            .map_err(|e| AnchorQueueError::Codec(e.to_string()))?;
        let sth_path = self.pending_sth_path(body.tree_size);
        let enq_path = self.pending_enq_path(body.tree_size);
        if sth_path.exists() {
            return Ok(false);
        }
        // Already anchored? Don't re-enqueue.
        if self.receipt_path(body.tree_size).exists() {
            return Ok(false);
        }
        let bytes =
            serde_json::to_vec_pretty(sth).map_err(|e| AnchorQueueError::Codec(e.to_string()))?;
        write_new(&sth_path, &bytes)?;
        write_new(&enq_path, now_unix.to_string().as_bytes())?;
        Ok(true)
    }

    /// List pending entries ordered by `tree_size` ascending. Each item
    /// carries the decoded STH and the `enqueued_at` marker. Malformed
    /// entries are skipped (logged through `tracing` would be a normal
    /// production refinement; the M4 surface keeps the dependency footprint
    /// to `serde_json`).
    pub fn pending(&self) -> Result<Vec<PendingEntry>, AnchorQueueError> {
        let dir = self.root.join("pending");
        let mut entries: Vec<(u64, PathBuf)> = Vec::new();
        for ent in std::fs::read_dir(&dir)? {
            let ent = ent?;
            let name = ent.file_name();
            let name = name.to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".sth.json") else {
                continue;
            };
            let Ok(n) = stem.parse::<u64>() else {
                continue;
            };
            entries.push((n, ent.path()));
        }
        entries.sort_by_key(|(n, _)| *n);
        let mut out = Vec::with_capacity(entries.len());
        for (tree_size, sth_path) in entries {
            let sth_bytes = std::fs::read(&sth_path)?;
            let sth: CoSignedTreeHead = serde_json::from_slice(&sth_bytes)
                .map_err(|e| AnchorQueueError::Codec(e.to_string()))?;
            let enq_bytes = std::fs::read(self.pending_enq_path(tree_size))?;
            let enqueued_at = std::str::from_utf8(&enq_bytes)
                .map_err(|e| AnchorQueueError::Malformed(e.to_string()))?
                .trim()
                .parse::<i64>()
                .map_err(|e| AnchorQueueError::Malformed(e.to_string()))?;
            out.push(PendingEntry {
                tree_size,
                sth,
                enqueued_at_unix: enqueued_at,
            });
        }
        Ok(out)
    }

    /// Record a receipt for `tree_size` and remove the pending entry.
    /// Returns the path of the written receipt.
    pub fn mark_anchored(
        &self,
        tree_size: u64,
        receipt: &AnchorReceipt,
    ) -> Result<PathBuf, AnchorQueueError> {
        let path = self.receipt_path(tree_size);
        let bytes = serde_json::to_vec_pretty(receipt)
            .map_err(|e| AnchorQueueError::Codec(e.to_string()))?;
        write_new(&path, &bytes)?;
        // Best-effort cleanup of pending markers.
        let _ = std::fs::remove_file(self.pending_sth_path(tree_size));
        let _ = std::fs::remove_file(self.pending_enq_path(tree_size));
        Ok(path)
    }

    /// Move a pending entry to `dead/` with the permanent error attached.
    /// The pending markers are removed.
    pub fn quarantine(&self, tree_size: u64, reason: &str) -> Result<(), AnchorQueueError> {
        let sth = std::fs::read(self.pending_sth_path(tree_size))?;
        write_new(&self.dead_sth_path(tree_size), &sth)?;
        write_new(&self.dead_err_path(tree_size), reason.as_bytes())?;
        let _ = std::fs::remove_file(self.pending_sth_path(tree_size));
        let _ = std::fs::remove_file(self.pending_enq_path(tree_size));
        Ok(())
    }

    /// Load the receipt for `tree_size`, if one has been recorded.
    pub fn receipt(&self, tree_size: u64) -> Result<Option<AnchorReceipt>, AnchorQueueError> {
        let path = self.receipt_path(tree_size);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let receipt: AnchorReceipt =
            serde_json::from_slice(&bytes).map_err(|e| AnchorQueueError::Codec(e.to_string()))?;
        Ok(Some(receipt))
    }

    /// Worst-case backlog age in seconds: `now_unix - min(enqueued_at)`
    /// across all pending entries, or `None` if the queue is empty.
    /// Operators alert when this exceeds the documented 5-minute threshold.
    pub fn backlog_seconds(&self, now_unix: i64) -> Result<Option<i64>, AnchorQueueError> {
        let mut oldest: Option<i64> = None;
        for entry in self.pending()? {
            oldest = Some(oldest.map_or(entry.enqueued_at_unix, |o| o.min(entry.enqueued_at_unix)));
        }
        Ok(oldest.map(|t| now_unix - t))
    }
}

/// A pending queue entry: the STH that still needs anchoring, plus the
/// `enqueued_at` marker used for backlog tracking.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    /// Key on disk; matches `sth.body()?.tree_size`.
    pub tree_size: u64,
    /// The co-signed tree head awaiting anchor.
    pub sth: CoSignedTreeHead,
    /// Unix-seconds timestamp at which this entry first entered the queue.
    pub enqueued_at_unix: i64,
}

/// Per-drain statistics returned by [`AnchorPublisher::drain_once`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Number of entries successfully anchored in this drain.
    pub published: usize,
    /// Number of entries that hit a transient failure and remain pending.
    pub transient_failures: usize,
    /// Number of entries quarantined under `dead/` in this drain.
    pub quarantined: usize,
    /// Worst-case backlog age after the drain, in seconds.
    pub backlog_seconds_after: Option<i64>,
}

impl DrainOutcome {
    /// `true` iff this drain made forward progress (anchored or quarantined
    /// at least one entry).
    #[must_use]
    pub fn made_progress(&self) -> bool {
        self.published + self.quarantined > 0
    }
}

/// Drives one drain pass over an [`AnchorQueue`] against an [`Anchor`].
pub struct AnchorPublisher {
    queue: AnchorQueue,
    anchor: Arc<dyn Anchor>,
}

impl AnchorPublisher {
    /// Build a publisher over `queue` that submits to `anchor`.
    #[must_use]
    pub fn new(queue: AnchorQueue, anchor: Arc<dyn Anchor>) -> Self {
        Self { queue, anchor }
    }

    /// Access to the underlying queue (for enqueueing fresh STHs from the
    /// audit-log path; tests; backlog probes).
    #[must_use]
    pub fn queue(&self) -> &AnchorQueue {
        &self.queue
    }

    /// Attempt to drain the queue.
    ///
    /// Entries are submitted in `tree_size` order. A `Transient` failure
    /// stops the drain immediately — the underlying log is likely
    /// unavailable and pounding it is counter-productive; the remaining
    /// entries are reported as backlog through the returned
    /// [`DrainOutcome::backlog_seconds_after`]. A `Permanent` failure
    /// quarantines the offending entry and the drain continues with the
    /// next one, since the rest of the queue might still be publishable.
    pub fn drain_once(&self, now_unix: i64) -> Result<DrainOutcome, AnchorQueueError> {
        let pending = self.queue.pending()?;
        let mut outcome = DrainOutcome::default();
        for entry in pending {
            match self.anchor.submit(&entry.sth) {
                Ok(receipt) => {
                    debug_assert_eq!(
                        receipt.tree_size, entry.tree_size,
                        "anchor must echo the tree_size it received"
                    );
                    self.queue.mark_anchored(entry.tree_size, &receipt)?;
                    outcome.published += 1;
                }
                Err(AnchorError::Transient(_)) => {
                    outcome.transient_failures += 1;
                    break;
                }
                Err(AnchorError::Permanent(reason)) => {
                    self.queue.quarantine(entry.tree_size, &reason)?;
                    outcome.quarantined += 1;
                }
            }
        }
        outcome.backlog_seconds_after = self.queue.backlog_seconds(now_unix)?;
        Ok(outcome)
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), AnchorQueueError> {
    match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(mut f) => {
            f.write_all(bytes)?;
            f.sync_data()?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(AnchorQueueError::AlreadyExists(path.to_path_buf()))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use crate::bytes::Hash384;
    use crate::cosign::QuorumSigner;
    use crate::sth::{InProcessSigner, SthBody, SthSigner};

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-anchor-{tag}-{nanos}"));
        p
    }

    fn make_sth(tree_size: u64) -> CoSignedTreeHead {
        let (s, _pk) = InProcessSigner::generate("k").unwrap();
        let q = QuorumSigner::new(vec![Arc::new(s) as Arc<dyn SthSigner>], 1).unwrap();
        q.sign(SthBody {
            tree_size,
            root_hash: Hash384([u8::try_from(tree_size & 0xFF).unwrap(); 48]),
            timestamp: 1_770_000_000 + i64::try_from(tree_size).unwrap(),
        })
        .unwrap()
    }

    /// In-memory anchor whose behaviour can be flipped between drains.
    struct ScriptedAnchor {
        name: String,
        next_index: AtomicU64,
        submissions: AtomicUsize,
        mode: Mutex<AnchorMode>,
        log: Mutex<Vec<u64>>,
    }

    #[derive(Clone)]
    enum AnchorMode {
        Succeed,
        Transient,
        Permanent,
    }

    impl ScriptedAnchor {
        fn new(name: &str) -> Self {
            Self {
                name: name.into(),
                next_index: AtomicU64::new(1),
                submissions: AtomicUsize::new(0),
                mode: Mutex::new(AnchorMode::Succeed),
                log: Mutex::new(Vec::new()),
            }
        }
        fn set(&self, mode: AnchorMode) {
            *self.mode.lock().unwrap() = mode;
        }
        fn submissions(&self) -> usize {
            self.submissions.load(Ordering::SeqCst)
        }
        fn anchored(&self) -> Vec<u64> {
            self.log.lock().unwrap().clone()
        }
    }

    impl Anchor for ScriptedAnchor {
        fn name(&self) -> &str {
            &self.name
        }
        fn submit(&self, sth: &CoSignedTreeHead) -> Result<AnchorReceipt, AnchorError> {
            self.submissions.fetch_add(1, Ordering::SeqCst);
            let mode = self.mode.lock().unwrap().clone();
            match mode {
                AnchorMode::Succeed => {
                    let body = sth.body().unwrap();
                    let idx = self.next_index.fetch_add(1, Ordering::SeqCst);
                    self.log.lock().unwrap().push(body.tree_size);
                    Ok(AnchorReceipt {
                        anchor_name: self.name.clone(),
                        tree_size: body.tree_size,
                        log_index: idx,
                        receipt_bytes: format!("receipt-{}", body.tree_size).into_bytes(),
                        anchored_at_unix: body.timestamp,
                    })
                }
                AnchorMode::Transient => Err(AnchorError::Transient("upstream blip".into())),
                AnchorMode::Permanent => Err(AnchorError::Permanent("malformed body".into())),
            }
        }
    }

    #[test]
    fn enqueue_then_drain_publishes_in_order() {
        let dir = temp_dir("happy");
        let queue = AnchorQueue::open(&dir).unwrap();
        for n in [1u64, 2, 3] {
            assert!(queue.enqueue(&make_sth(n), 1_770_000_000).unwrap());
        }
        let anchor = Arc::new(ScriptedAnchor::new("sigsum"));
        let pub_ = AnchorPublisher::new(queue, anchor.clone());
        let out = pub_.drain_once(1_770_000_060).unwrap();
        assert_eq!(out.published, 3);
        assert_eq!(out.transient_failures, 0);
        assert_eq!(out.quarantined, 0);
        assert_eq!(out.backlog_seconds_after, None);
        assert_eq!(anchor.anchored(), vec![1, 2, 3]);
        for n in [1u64, 2, 3] {
            let r = pub_.queue().receipt(n).unwrap().unwrap();
            assert_eq!(r.tree_size, n);
            assert_eq!(r.anchor_name, "sigsum");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn enqueue_is_idempotent_per_tree_size() {
        let dir = temp_dir("idem");
        let queue = AnchorQueue::open(&dir).unwrap();
        assert!(queue.enqueue(&make_sth(7), 1_770_000_000).unwrap());
        // Second enqueue at a later time is a no-op; the original
        // enqueued_at must be preserved.
        assert!(!queue.enqueue(&make_sth(7), 1_770_000_999).unwrap());
        let pending = queue.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].enqueued_at_unix, 1_770_000_000);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn transient_failure_stops_drain_and_preserves_queue() {
        let dir = temp_dir("transient");
        let queue = AnchorQueue::open(&dir).unwrap();
        for n in [1u64, 2, 3] {
            queue.enqueue(&make_sth(n), 1_770_000_000).unwrap();
        }
        let anchor = Arc::new(ScriptedAnchor::new("rekor"));
        anchor.set(AnchorMode::Transient);
        let pub_ = AnchorPublisher::new(queue, anchor.clone());
        let out = pub_.drain_once(1_770_000_120).unwrap();
        assert_eq!(out.published, 0);
        assert_eq!(out.transient_failures, 1);
        assert_eq!(out.quarantined, 0);
        // Exactly one submit attempt: the publisher must stop on the first
        // transient failure rather than hammer the upstream log.
        assert_eq!(anchor.submissions(), 1);
        // Backlog is measured from the earliest enqueue.
        assert_eq!(out.backlog_seconds_after, Some(120));
        // All three still pending.
        assert_eq!(pub_.queue().pending().unwrap().len(), 3);
        // Flip the anchor to success; next drain catches up entirely.
        anchor.set(AnchorMode::Succeed);
        let out = pub_.drain_once(1_770_000_180).unwrap();
        assert_eq!(out.published, 3);
        assert_eq!(out.backlog_seconds_after, None);
        assert_eq!(anchor.anchored(), vec![1, 2, 3]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn permanent_failure_quarantines_and_drain_continues() {
        let dir = temp_dir("perm");
        let queue = AnchorQueue::open(&dir).unwrap();
        for n in [1u64, 2] {
            queue.enqueue(&make_sth(n), 1_770_000_000).unwrap();
        }
        let anchor = Arc::new(ScriptedAnchor::new("anchor"));
        anchor.set(AnchorMode::Permanent);
        let pub_ = AnchorPublisher::new(queue, anchor.clone());
        let out = pub_.drain_once(1_770_000_005).unwrap();
        assert_eq!(out.quarantined, 2);
        assert_eq!(out.published, 0);
        assert_eq!(out.backlog_seconds_after, None);
        // Both pending entries are gone; both dead artefacts exist.
        let pending = pub_.queue().pending().unwrap();
        assert!(pending.is_empty());
        for n in [1u64, 2] {
            assert!(pub_.queue().dead_sth_path(n).exists());
            let reason = std::fs::read_to_string(pub_.queue().dead_err_path(n)).unwrap();
            assert!(reason.contains("malformed body"));
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn queue_survives_reopen() {
        let dir = temp_dir("reopen");
        {
            let queue = AnchorQueue::open(&dir).unwrap();
            queue.enqueue(&make_sth(42), 1_770_000_000).unwrap();
        }
        // Re-open the queue from disk and drain.
        let queue = AnchorQueue::open(&dir).unwrap();
        let anchor = Arc::new(ScriptedAnchor::new("a"));
        let pub_ = AnchorPublisher::new(queue, anchor.clone());
        let out = pub_.drain_once(1_770_000_300).unwrap();
        assert_eq!(out.published, 1);
        assert_eq!(anchor.anchored(), vec![42]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn already_anchored_tree_size_is_not_re_enqueued() {
        let dir = temp_dir("anchored-dedup");
        let queue = AnchorQueue::open(&dir).unwrap();
        queue.enqueue(&make_sth(9), 1_770_000_000).unwrap();
        let anchor = Arc::new(ScriptedAnchor::new("a"));
        let pub_ = AnchorPublisher::new(queue, anchor.clone());
        pub_.drain_once(1_770_000_050).unwrap();
        // Now ask the same queue to enqueue tree_size 9 again — the
        // anchored receipt exists, so the queue refuses (returns false).
        assert!(!pub_.queue().enqueue(&make_sth(9), 1_770_000_400).unwrap());
        assert_eq!(anchor.submissions(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn backlog_seconds_tracks_earliest_pending_entry() {
        let dir = temp_dir("backlog");
        let queue = AnchorQueue::open(&dir).unwrap();
        queue.enqueue(&make_sth(1), 1_770_000_000).unwrap();
        queue.enqueue(&make_sth(2), 1_770_000_100).unwrap();
        assert_eq!(queue.backlog_seconds(1_770_000_300).unwrap(), Some(300));
        std::fs::remove_dir_all(dir).ok();
    }
}
