//! The on-disk audit spool (T291): events waiting for CMIS, kept `0600` in
//! the daemon's state directory. JSON lines: `{"v":1,"seq":N,"ts":T,
//! "cbor":"<base64>"}` per event and `{"v":1,"done":N}` finishing all up to
//! `N`; no proof or SVID is stored. Bounded, oldest dropped first; a torn or
//! malformed line is skipped on open, and a file that cannot be read in full
//! is moved aside, never rewritten. Format and limits: `docs/audit.md`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write as _};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Largest event (canonical CBOR) the spool accepts: CMIS refuses anything
/// larger (`MAX_FORWARDED_EVENT_BYTES`), so a bigger event stays in the local
/// log only.
pub const MAX_EVENT_CBOR_BYTES: usize = 64 * 1024;

/// Longest spool line read back (an event of [`MAX_EVENT_CBOR_BYTES`] in
/// base64 plus the record's fields). Longer lines are skipped unread.
pub const MAX_LINE_BYTES: usize = 96 * 1024;

/// Default event cap.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default byte cap (records as stored).
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Dead bytes tolerated before a compaction, at minimum (amortises rewrites
/// of a small spool).
const COMPACT_MIN_DEAD_BYTES: u64 = 64 * 1024;

/// Record format version.
const RECORD_VERSION: u8 = 1;

/// File mode: owner only. Events carry caller pids, uids, binary hashes and
/// token `jti`s.
const SPOOL_MODE: u32 = 0o600;

/// How much the spool may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolLimits {
    /// Most events held; the oldest is dropped beyond it.
    pub max_entries: usize,
    /// Most record bytes held; the oldest events are dropped beyond it.
    pub max_bytes: u64,
}

impl Default for SpoolLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// One spooled event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Spool sequence number (strictly increasing; renumbered from 1 on
    /// open).
    pub seq: u64,
    /// When it was spooled, Unix seconds.
    pub ts: i64,
    /// The event's canonical CBOR, exactly as forwarded.
    pub cbor: Vec<u8>,
    /// Upper bound on the length of its stored record.
    record_len: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventRecord {
    v: u8,
    seq: u64,
    ts: i64,
    cbor: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DoneRecord {
    v: u8,
    done: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Record {
    Event(EventRecord),
    Done(DoneRecord),
}

/// What [`Spool::open`] found.
#[derive(Debug, Default)]
pub struct OpenReport {
    /// Events loaded and still waiting.
    pub loaded: usize,
    /// Lines skipped: torn, over-long, malformed or out of order (and a
    /// non-file at the spool's place, which is replaced unread).
    pub skipped_lines: usize,
    /// Events dropped because the file held more than the cap.
    pub dropped_over_cap: u64,
    /// The file could not be rewritten (or, when it was not read in full,
    /// moved aside); the spool runs from memory and retries on its next
    /// change.
    pub error: Option<std::io::Error>,
}

/// What [`Spool::push`] did.
#[derive(Debug, Default)]
pub struct PushReport {
    /// Events added.
    pub spooled: usize,
    /// Oldest events dropped to stay within the cap.
    pub dropped: u64,
    /// Events dropped over the cap since open, this push included.
    pub dropped_total: u64,
    /// The spool file could not be written; the events are held in memory
    /// and the file is rewritten on the next change.
    pub error: Option<std::io::Error>,
}

/// The audit spool: the pending events in memory, mirrored to a `0600`
/// JSON-lines file. Events leave only from the front (acknowledged, refused
/// or dropped over the cap), so one `done` watermark records every removal.
#[derive(Debug)]
pub struct Spool {
    path: PathBuf,
    limits: SpoolLimits,
    pending: VecDeque<Entry>,
    pending_bytes: u64,
    next_seq: u64,
    file_bytes: u64,
    needs_rewrite: bool,
    dropped_total: u64,
    /// Why the file at `path` was not read in full: until it is moved aside
    /// ([`Self::set_aside`]) nothing is written there.
    unread: Option<std::io::Error>,
}

impl Spool {
    /// Open the spool at `path`, replaying what an earlier run left. Never
    /// fails: unreadable lines are reported and skipped, a file that cannot
    /// be read in full is moved aside unchanged (`<name>.unreadable-<unix
    /// time>`) for a fresh spool, and a file that cannot be written leaves
    /// the spool in memory until it can.
    #[must_use]
    pub fn open(path: &Path, limits: SpoolLimits) -> (Self, OpenReport) {
        Self::open_with(path, limits, crate::system_dir::open_trusted)
    }

    /// [`Self::open`], reading the file through `read` (a test seam).
    fn open_with<R: Read>(
        path: &Path,
        limits: SpoolLimits,
        read: impl FnOnce(&Path) -> std::io::Result<R>,
    ) -> (Self, OpenReport) {
        let limits = SpoolLimits {
            max_entries: limits.max_entries.max(1),
            max_bytes: limits.max_bytes.max(1),
        };
        let mut spool = Self {
            path: path.to_path_buf(),
            limits,
            pending: VecDeque::new(),
            pending_bytes: 0,
            next_seq: 1,
            file_bytes: 0,
            needs_rewrite: true,
            dropped_total: 0,
            unread: None,
        };
        let mut report = OpenReport::default();
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_file() => {
                match read(path).and_then(|file| spool.load(file, &mut report)) {
                    Ok(clean) => {
                        spool.needs_rewrite = !clean || !owner_only(&meta);
                        spool.file_bytes = meta.len();
                    }
                    // Keep what was not read: start empty, move it aside.
                    Err(e) => {
                        spool.forget_pending();
                        report = OpenReport::default();
                        spool.unread = Some(e);
                    }
                }
            }
            // A symlink or anything else at the spool's place is replaced,
            // never followed or read.
            Ok(_) => report.skipped_lines += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Whatever is there may hold events: never write over it.
            Err(e) => spool.unread = Some(e),
        }
        report.loaded = spool.pending.len();
        report.dropped_over_cap = spool.dropped_total;
        if spool.needs_rewrite {
            if let Err(e) = spool.rewrite() {
                report.error.get_or_insert(e);
            }
        }
        (spool, report)
    }

    /// Read the file into `self.pending`. Returns whether it was already in
    /// canonical form (nothing dead, skipped, dropped or renumbered).
    fn load(&mut self, file: impl Read, report: &mut OpenReport) -> std::io::Result<bool> {
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        let mut clean = true;
        let mut watermark = 0u64;
        let mut last_seq = 0u64;
        loop {
            match read_line_bounded(&mut reader, &mut line, MAX_LINE_BYTES)? {
                LineRead::Eof => break,
                LineRead::TooLong | LineRead::Torn => {
                    report.skipped_lines += 1;
                    clean = false;
                    continue;
                }
                LineRead::Line => {}
            }
            match parse_record(&line) {
                Some(Parsed::Event { seq, ts, cbor }) if seq > last_seq && seq > watermark => {
                    last_seq = seq;
                    self.push_entry(ts, cbor, seq);
                    self.drop_over_cap();
                }
                Some(Parsed::Done(n)) => {
                    clean = false;
                    watermark = watermark.max(n);
                    while self.pending.front().is_some_and(|e| e.seq <= watermark) {
                        self.pop_front();
                    }
                }
                Some(Parsed::Event { .. }) | None => {
                    report.skipped_lines += 1;
                    clean = false;
                }
            }
        }
        // Renumber from 1 so a damaged sequence never runs the counter out.
        let mut seq = 0u64;
        for e in &mut self.pending {
            seq += 1;
            if e.seq != seq {
                clean = false;
                e.seq = seq;
            }
        }
        self.next_seq = seq + 1;
        Ok(clean && self.dropped_total == 0)
    }

    /// Append `batch` (`(spooled_at, canonical CBOR)`, each at most
    /// [`MAX_EVENT_CBOR_BYTES`]) and flush it, dropping the oldest events
    /// beyond the cap.
    pub fn push(&mut self, batch: Vec<(i64, Vec<u8>)>) -> PushReport {
        let mut report = PushReport::default();
        let dropped_before = self.dropped_total;
        let mut new_records: Vec<(u64, Vec<u8>)> = Vec::with_capacity(batch.len());
        for (ts, cbor) in batch {
            let seq = self.next_seq;
            self.next_seq = self.next_seq.saturating_add(1);
            new_records.push((seq, event_record(seq, ts, &cbor)));
            self.push_entry(ts, cbor, seq);
            report.spooled += 1;
            self.drop_over_cap();
        }
        report.dropped = self.dropped_total - dropped_before;
        report.dropped_total = self.dropped_total;

        let mut bytes = Vec::new();
        if report.dropped > 0 {
            bytes.extend(done_record(self.front_seq().saturating_sub(1)));
        }
        let first_live = self.front_seq();
        for (seq, record) in new_records {
            if seq >= first_live {
                bytes.extend(record);
            }
        }
        if let Err(e) = self.persist_append(&bytes) {
            report.error = Some(e);
        }
        report
    }

    /// The oldest waiting event.
    #[must_use]
    pub fn front(&self) -> Option<&Entry> {
        self.pending.front()
    }

    /// Finish every event numbered `seq` or less (forwarded or refused) and
    /// record it on disk; a no-op when the cap already dropped them.
    pub fn complete_through(&mut self, seq: u64) -> std::io::Result<()> {
        let mut finished = false;
        while self.pending.front().is_some_and(|e| e.seq <= seq) {
            self.pop_front();
            finished = true;
        }
        if !finished {
            return Ok(());
        }
        self.persist_append(&done_record(seq))
    }

    /// Events waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing waits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Events dropped over the cap since open (load included).
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    /// When the oldest waiting event was spooled.
    #[must_use]
    pub fn oldest_ts(&self) -> Option<i64> {
        self.pending.front().map(|e| e.ts)
    }

    /// The spool file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn front_seq(&self) -> u64 {
        self.pending.front().map_or(self.next_seq, |e| e.seq)
    }

    fn push_entry(&mut self, ts: i64, cbor: Vec<u8>, seq: u64) {
        let record_len = encoded_event_len(cbor.len());
        self.pending_bytes = self.pending_bytes.saturating_add(record_len);
        self.pending.push_back(Entry {
            seq,
            ts,
            cbor,
            record_len,
        });
    }

    fn pop_front(&mut self) {
        if let Some(e) = self.pending.pop_front() {
            self.pending_bytes = self.pending_bytes.saturating_sub(e.record_len);
        }
    }

    /// Back to an empty spool (what a failed load read stays in its file).
    fn forget_pending(&mut self) {
        self.pending.clear();
        self.pending_bytes = 0;
        self.next_seq = 1;
        self.file_bytes = 0;
        self.dropped_total = 0;
    }

    /// Move a file that was not read in full aside, unchanged, so that it is
    /// never written over; logs where (paths and I/O errors only).
    fn set_aside(&mut self) -> std::io::Result<()> {
        let Some(unread) = &self.unread else {
            return Ok(());
        };
        let failed = |e: std::io::Error| {
            std::io::Error::new(
                e.kind(),
                format!("audit spool not read in full ({unread}) and not moved aside: {e}"),
            )
        };
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.file_type().is_file() => {}
            // Gone, or no longer a file (replaced as at open): nothing kept.
            Ok(_) => {
                self.unread = None;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.unread = None;
                return Ok(());
            }
            Err(e) => return Err(failed(e)),
        }
        let aside = free_aside_path(&self.path, super::unix_now()).map_err(failed)?;
        std::fs::rename(&self.path, &aside).map_err(failed)?;
        restrict_to_owner(&aside);
        tracing::error!(
            spool = %self.path.display(),
            moved_to = %aside.display(),
            error = %unread,
            "audit spool could not be read in full; moved it aside unchanged and started a fresh spool"
        );
        self.unread = None;
        self.file_bytes = 0;
        Ok(())
    }

    /// Drop the oldest events while over either cap (never the newest one).
    fn drop_over_cap(&mut self) {
        while self.pending.len() > 1
            && (self.pending.len() > self.limits.max_entries
                || self.pending_bytes > self.limits.max_bytes)
        {
            self.pop_front();
            self.dropped_total += 1;
        }
    }

    /// Append `bytes` and flush; when that fails (a torn tail is possible)
    /// or a rewrite is owed, rewrite the whole spool instead. Compacts once
    /// dead records outweigh live ones.
    fn persist_append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if self.needs_rewrite {
            return self.rewrite();
        }
        if let Err(e) = append(&self.path, bytes) {
            self.needs_rewrite = true;
            return self.rewrite().map_err(|_| e);
        }
        self.file_bytes = self.file_bytes.saturating_add(bytes.len() as u64);
        let dead = self.file_bytes.saturating_sub(self.pending_bytes);
        if dead > self.pending_bytes.max(COMPACT_MIN_DEAD_BYTES) {
            self.rewrite()?;
        }
        Ok(())
    }

    /// Replace the file with exactly the live events (atomic, `0600`),
    /// after moving aside a file that was not read in full.
    fn rewrite(&mut self) -> std::io::Result<()> {
        let mut bytes = Vec::with_capacity(usize::try_from(self.pending_bytes).unwrap_or(0));
        for e in &self.pending {
            bytes.extend(event_record(e.seq, e.ts, &e.cbor));
        }
        let result = self
            .set_aside()
            .and_then(
                |()| match self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    Some(parent) => crate::system_dir::create_dir_all(parent),
                    None => Ok(()),
                },
            )
            .and_then(|()| crate::atomic_file::write(&self.path, &bytes, SPOOL_MODE));
        match result {
            Ok(()) => {
                self.file_bytes = bytes.len() as u64;
                self.needs_rewrite = false;
                Ok(())
            }
            Err(e) => {
                self.needs_rewrite = true;
                Err(e)
            }
        }
    }
}

/// Whether the file grants nothing to group or others (Unix); elsewhere the
/// state directory's own protection applies.
fn owner_only(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let group_and_other = meta.permissions().mode() & 0o077;
        group_and_other == 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
}

/// `<name>.unreadable-<now>` beside `path` (suffixed `-N` if taken).
fn free_aside_path(path: &Path, now: i64) -> std::io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    for n in 0..100u32 {
        let mut candidate = OsString::from(name);
        candidate.push(format!(".unreadable-{now}"));
        if n > 0 {
            candidate.push(format!("-{n}"));
        }
        let candidate = path.with_file_name(candidate);
        match std::fs::symlink_metadata(&candidate) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free name to move the audit spool aside",
    ))
}

/// Best effort: `0600` on a file moved aside (Unix; never follows a link).
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        if let Ok(f) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            let _ = f.set_permissions(std::fs::Permissions::from_mode(SPOOL_MODE));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Append `bytes` and flush: created `0600` on Unix, refusing a symlink at
/// `path` (`O_NOFOLLOW`); on Windows through [`crate::system_dir::open_log`],
/// which refuses a planted link or a file that is not administrator-only
/// inside the system directory.
fn append(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(SPOOL_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = crate::system_dir::open_log(path)?;
    file.write_all(bytes)?;
    file.sync_data()
}

/// An upper bound on the stored length of an event record whose CBOR is
/// `cbor_len` bytes (`{"v":1,"seq":…,"ts":…,"cbor":"…"}\n`).
fn encoded_event_len(cbor_len: usize) -> u64 {
    let b64 = cbor_len.div_ceil(3) * 4;
    (b64 + 72) as u64
}

fn event_record(seq: u64, ts: i64, cbor: &[u8]) -> Vec<u8> {
    let rec = EventRecord {
        v: RECORD_VERSION,
        seq,
        ts,
        cbor: STANDARD.encode(cbor),
    };
    // Serialising integers and a base64 string cannot fail.
    let mut out = serde_json::to_vec(&rec).unwrap_or_default();
    out.push(b'\n');
    out
}

fn done_record(done: u64) -> Vec<u8> {
    let mut out = serde_json::to_vec(&DoneRecord {
        v: RECORD_VERSION,
        done,
    })
    .unwrap_or_default();
    out.push(b'\n');
    out
}

enum Parsed {
    Event { seq: u64, ts: i64, cbor: Vec<u8> },
    Done(u64),
}

/// Parse and validate one record: known version, base64 that decodes, an
/// event within the size bound that decodes as an `AuditEvent`.
fn parse_record(line: &[u8]) -> Option<Parsed> {
    match serde_json::from_slice::<Record>(line).ok()? {
        Record::Event(r) if r.v == RECORD_VERSION => {
            let cbor = STANDARD.decode(r.cbor.as_bytes()).ok()?;
            if cbor.is_empty() || cbor.len() > MAX_EVENT_CBOR_BYTES {
                return None;
            }
            ferro_audit::event::decode(&cbor).ok()?;
            Some(Parsed::Event {
                seq: r.seq,
                ts: r.ts,
                cbor,
            })
        }
        Record::Done(r) if r.v == RECORD_VERSION => Some(Parsed::Done(r.done)),
        _ => None,
    }
}

enum LineRead {
    /// A complete line is in the buffer (without its newline).
    Line,
    /// A line longer than the bound was skipped.
    TooLong,
    /// The file ended inside a line (a torn append).
    Torn,
    /// End of file.
    Eof,
}

/// Read one `\n`-terminated line into `buf`, holding at most `max` bytes of
/// it; a longer line is consumed and reported, never buffered.
fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    buf.clear();
    let mut too_long = false;
    let mut any = false;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(if any { LineRead::Torn } else { LineRead::Eof });
        }
        any = true;
        let newline = available.iter().position(|&b| b == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if !too_long {
            if buf.len() + chunk.len() > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        let used = chunk.len() + usize::from(newline.is_some());
        reader.consume(used);
        if newline.is_some() {
            return Ok(if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
    }
}

#[cfg(test)]
#[path = "spool_tests.rs"]
mod tests;
