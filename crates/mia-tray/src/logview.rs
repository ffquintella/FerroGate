//! Following the daemon's log ring buffer, and filtering it.
//!
//! [`Follower`] turns successive `LogTailResp`s into a stream of [`Entry`]s
//! **without duplicates**: it only accepts records with `seq >= since_seq`
//! and advances `since_seq` past them. A `dropped > 0` reply becomes a visible
//! [`Entry::Gap`]; a changed `buffer_id` (the daemon restarted and `seq` began
//! again) becomes [`Entry::Restarted`] and restarts the follow from `0`.
//! [`LogBuffer`] keeps a bounded window for display, [`Filter`] selects by
//! level, environment and text, and [`render_record`] produces the escaped
//! plain-text line the viewer shows.

use std::collections::VecDeque;

use mia_status_proto::{Level, LogRecord, LogTailResp, MAX_TAIL_RECORDS};

use crate::text::{display_safe, rfc3339_utc_ms};

/// Records the viewer keeps in memory.
pub const MAX_KEPT: usize = 5000;

/// One viewer line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A log record.
    Record(LogRecord),
    /// Records evicted from the daemon's buffer before the viewer read them.
    Gap(u64),
    /// The daemon restarted; numbering began again.
    Restarted,
}

/// Follow state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Follower {
    since_seq: u64,
    buffer_id: Option<u64>,
}

/// What one [`Follower::ingest`] produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ingested {
    /// New entries, oldest first.
    pub entries: Vec<Entry>,
    /// Ask again immediately (a full page, or a restart was detected).
    pub more: bool,
}

impl Follower {
    /// The `since_seq` for the next request.
    #[must_use]
    pub fn since_seq(&self) -> u64 {
        self.since_seq
    }

    /// Fold one reply in.
    pub fn ingest(&mut self, resp: LogTailResp) -> Ingested {
        match self.buffer_id {
            Some(id) if id != resp.buffer_id => {
                // The reply was computed against the old numbering: discard
                // it and start over from the new buffer's beginning.
                self.buffer_id = Some(resp.buffer_id);
                self.since_seq = 0;
                return Ingested {
                    entries: vec![Entry::Restarted],
                    more: true,
                };
            }
            _ => {}
        }
        let first = self.buffer_id.is_none();
        self.buffer_id = Some(resp.buffer_id);
        let mut entries = Vec::with_capacity(resp.records.len() + 1);
        // The first read starts wherever the buffer starts; older records
        // were never "ours", so that is not a gap.
        if resp.dropped > 0 && !first {
            entries.push(Entry::Gap(resp.dropped));
        }
        let full = resp.records.len() >= usize::from(MAX_TAIL_RECORDS);
        let mut next = self.since_seq;
        for r in resp.records {
            if r.seq >= self.since_seq && r.seq >= next {
                next = r.seq + 1;
                entries.push(Entry::Record(r));
            }
        }
        self.since_seq = next.max(resp.next_seq).max(self.since_seq);
        Ingested {
            entries,
            more: full,
        }
    }
}

/// A bounded display window.
#[derive(Debug, Clone, Default)]
pub struct LogBuffer {
    entries: VecDeque<Entry>,
}

impl LogBuffer {
    /// Append, evicting the oldest past [`MAX_KEPT`].
    pub fn extend(&mut self, entries: impl IntoIterator<Item = Entry>) {
        for e in entries {
            if self.entries.len() >= MAX_KEPT {
                self.entries.pop_front();
            }
            self.entries.push_back(e);
        }
    }

    /// Everything kept, oldest first.
    #[must_use]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Entry> + ExactSizeIterator {
        self.entries.iter()
    }

    /// Number kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The last `n` records (for the diagnostics bundle).
    #[must_use]
    pub fn last_records(&self, n: usize) -> Vec<LogRecord> {
        let mut v: Vec<LogRecord> = self
            .entries
            .iter()
            .rev()
            .filter_map(|e| match e {
                Entry::Record(r) => Some(r.clone()),
                _ => None,
            })
            .take(n)
            .collect();
        v.reverse();
        v
    }
}

/// Which environments to show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EnvFilter {
    /// All records.
    #[default]
    All,
    /// Records logged outside any environment (the default one).
    Default,
    /// One named environment.
    Named(String),
}

/// The viewer's filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Least severe level shown.
    pub min_level: Level,
    /// Environment selector.
    pub environment: EnvFilter,
    /// Case-insensitive substring over message, target and fields.
    pub text: String,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            min_level: Level::Info,
            environment: EnvFilter::All,
            text: String::new(),
        }
    }
}

/// Longest search text accepted.
pub const MAX_SEARCH_LEN: usize = 256;

impl Filter {
    /// Whether `entry` is shown (gaps and restarts always are).
    #[must_use]
    pub fn matches(&self, entry: &Entry) -> bool {
        let Entry::Record(r) = entry else {
            return true;
        };
        if !r.level.passes(self.min_level) {
            return false;
        }
        let env_ok = match &self.environment {
            EnvFilter::All => true,
            EnvFilter::Default => r.environment.is_none(),
            EnvFilter::Named(n) => r.environment.as_deref() == Some(n.as_str()),
        };
        if !env_ok {
            return false;
        }
        let needle: String = self
            .text
            .chars()
            .take(MAX_SEARCH_LEN)
            .collect::<String>()
            .to_lowercase();
        if needle.trim().is_empty() {
            return true;
        }
        let hay = |s: &str| s.to_lowercase().contains(&needle);
        hay(&r.message) || hay(&r.target) || r.fields.iter().any(|f| hay(&f.name) || hay(&f.value))
    }
}

/// Longest rendered line.
pub const MAX_LINE_CHARS: usize = 2048;

/// One record as an escaped plain-text line:
/// `2026-10-02T12:34:56.789Z WARN [env] target: message k=v …`.
#[must_use]
pub fn render_record(r: &LogRecord) -> String {
    use std::fmt::Write as _;
    let mut line = format!(
        "{} {:<5} ",
        rfc3339_utc_ms(r.ts_ms),
        r.level.as_str().to_uppercase()
    );
    if let Some(env) = &r.environment {
        let _ = write!(line, "[{}] ", display_safe(env, 64));
    }
    let _ = write!(
        line,
        "{}: {}",
        display_safe(&r.target, 128),
        display_safe(&r.message, 1024)
    );
    for f in &r.fields {
        let _ = write!(
            line,
            " {}={}",
            display_safe(&f.name, 64),
            display_safe(&f.value, 512)
        );
    }
    display_safe(&line, MAX_LINE_CHARS)
}

/// Environments seen in the buffer (for the filter drop-down).
#[must_use]
pub fn environments(buf: &LogBuffer) -> Vec<String> {
    let mut v: Vec<String> = buf
        .iter()
        .filter_map(|e| match e {
            Entry::Record(r) => r.environment.clone(),
            _ => None,
        })
        .collect();
    v.sort();
    v.dedup();
    v.truncate(64);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use mia_status_proto::LogField;

    fn rec(seq: u64, level: Level, env: Option<&str>, msg: &str) -> LogRecord {
        LogRecord {
            seq,
            ts_ms: 1_700_000_000_000 + i64::try_from(seq).unwrap(),
            level,
            target: "mia::daemon".into(),
            environment: env.map(str::to_string),
            message: msg.into(),
            fields: vec![LogField {
                name: "node".into(),
                value: "cmis1".into(),
            }],
        }
    }

    fn resp(records: Vec<LogRecord>, next: u64, dropped: u64, id: u64) -> LogTailResp {
        LogTailResp {
            records,
            next_seq: next,
            dropped,
            buffer_id: id,
        }
    }

    fn seqs(entries: &[Entry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| match e {
                Entry::Record(r) => r.seq.to_string(),
                Entry::Gap(n) => format!("gap{n}"),
                Entry::Restarted => "restart".into(),
            })
            .collect()
    }

    #[test]
    fn follows_without_duplicates_and_reports_gaps() {
        let mut f = Follower::default();
        // First read: an initial "dropped" is not a gap.
        let r = f.ingest(resp(
            vec![
                rec(5, Level::Info, None, "a"),
                rec(6, Level::Info, None, "b"),
            ],
            7,
            5,
            1,
        ));
        assert_eq!(seqs(&r.entries), ["5", "6"]);
        assert_eq!(f.since_seq(), 7);
        // A reply that repeats old records (e.g. a retried request) adds none.
        let r = f.ingest(resp(
            vec![
                rec(6, Level::Info, None, "b"),
                rec(7, Level::Info, None, "c"),
            ],
            8,
            0,
            1,
        ));
        assert_eq!(seqs(&r.entries), ["7"]);
        // Eviction between reads is a visible gap.
        let r = f.ingest(resp(vec![rec(20, Level::Warn, None, "d")], 21, 12, 1));
        assert_eq!(seqs(&r.entries), ["gap12", "20"]);
        assert_eq!(f.since_seq(), 21);
    }

    #[test]
    fn a_daemon_restart_resets_the_follow() {
        let mut f = Follower::default();
        f.ingest(resp(vec![rec(100, Level::Info, None, "old")], 101, 0, 1));
        // New buffer: the reply is discarded and the follow restarts at 0.
        let r = f.ingest(resp(
            vec![rec(101, Level::Info, None, "new-numbering")],
            102,
            0,
            2,
        ));
        assert_eq!(seqs(&r.entries), ["restart"]);
        assert!(r.more);
        assert_eq!(f.since_seq(), 0);
        let r = f.ingest(resp(
            vec![
                rec(0, Level::Info, None, "x"),
                rec(1, Level::Info, None, "y"),
            ],
            2,
            0,
            2,
        ));
        assert_eq!(seqs(&r.entries), ["0", "1"]);
    }

    #[test]
    fn a_full_page_asks_for_more() {
        let mut f = Follower::default();
        let page: Vec<_> = (0..u64::from(MAX_TAIL_RECORDS))
            .map(|s| rec(s, Level::Debug, None, "m"))
            .collect();
        assert!(f.ingest(resp(page, u64::from(MAX_TAIL_RECORDS), 0, 1)).more);
    }

    #[test]
    fn filters_by_level_environment_and_text() {
        let e = |r| Entry::Record(r);
        let warn = e(rec(1, Level::Warn, Some("prod"), "CMIS unreachable"));
        let debug = e(rec(2, Level::Debug, None, "tick"));
        let mut f = Filter::default();
        assert!(f.matches(&warn));
        assert!(!f.matches(&debug), "info filter hides debug");
        f.min_level = Level::Trace;
        assert!(f.matches(&debug));
        f.environment = EnvFilter::Named("prod".into());
        assert!(f.matches(&warn) && !f.matches(&debug));
        f.environment = EnvFilter::Default;
        assert!(!f.matches(&warn) && f.matches(&debug));
        f.environment = EnvFilter::All;
        f.text = "unreach".into();
        assert!(f.matches(&warn) && !f.matches(&debug));
        f.text = "CMIS1".into(); // field value, case-insensitive
        assert!(f.matches(&warn));
        assert!(f.matches(&Entry::Gap(3)));
    }

    #[test]
    fn rendering_escapes_control_characters() {
        let mut r = rec(
            1,
            Level::Error,
            Some("prod"),
            "line1\nFAKE 2026 ERROR spoof\u{1b}[2J",
        );
        r.fields[0].value = "a\u{202e}b".into();
        let line = render_record(&r);
        assert!(!line.contains('\n') && !line.contains('\u{1b}') && !line.contains('\u{202e}'));
        assert!(line.starts_with("2023-11-14T22:13:20.001Z ERROR [prod] mia::daemon: line1\\nFAKE"));
        assert!(line.ends_with("node=a\\u{202e}b"));
    }

    #[test]
    fn the_buffer_is_bounded() {
        let mut b = LogBuffer::default();
        b.extend(
            (0..(MAX_KEPT as u64 + 10)).map(|s| Entry::Record(rec(s, Level::Info, Some("e"), "m"))),
        );
        assert_eq!(b.len(), MAX_KEPT);
        let last = b.last_records(3);
        assert_eq!(
            last.iter().map(|r| r.seq).collect::<Vec<_>>(),
            [
                MAX_KEPT as u64 + 7,
                MAX_KEPT as u64 + 8,
                MAX_KEPT as u64 + 9
            ]
        );
        assert_eq!(environments(&b), ["e"]);
    }
}
