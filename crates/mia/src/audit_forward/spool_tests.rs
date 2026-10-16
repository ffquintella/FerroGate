use super::*;
use crate::audit_forward::tests::TempDir;
use ferro_audit::{AuditEvent, Hash384};

fn temp_dir(tag: &str) -> TempDir {
    TempDir::new(&format!("mia-audit-spool-{tag}"))
}

fn event(n: u32) -> Vec<u8> {
    ferro_audit::event::encode(&AuditEvent::LocalDenied {
        pid: n,
        uid: 1000,
        bin_sha: Hash384([7; 48]),
        reason: "not_allowlisted".into(),
    })
    .unwrap()
}

fn pids(spool: &Spool) -> Vec<u32> {
    spool
        .pending
        .iter()
        .map(|e| match ferro_audit::event::decode(&e.cbor).unwrap() {
            AuditEvent::LocalDenied { pid, .. } => pid,
            other => panic!("unexpected {other:?}"),
        })
        .collect()
}

#[test]
fn events_survive_a_reopen_and_finished_ones_do_not() {
    let dir = temp_dir("reopen");
    let path = dir.join("audit-spool.jsonl");
    let (mut s, r) = Spool::open(&path, SpoolLimits::default());
    assert!(r.error.is_none() && r.loaded == 0);
    assert!(path.exists(), "the file is created at open");
    let r = s.push((1..=5).map(|n| (100, event(n))).collect());
    assert!(r.error.is_none());
    assert_eq!((r.spooled, r.dropped), (5, 0));
    let seq2 = s.pending[1].seq;
    s.complete_through(seq2).unwrap();
    drop(s);

    let (s, r) = Spool::open(&path, SpoolLimits::default());
    assert!(r.error.is_none());
    assert_eq!((r.loaded, r.skipped_lines), (3, 0));
    assert_eq!(pids(&s), vec![3, 4, 5]);
    assert_eq!(s.front().unwrap().seq, 1, "renumbered from 1");
    assert_eq!(s.oldest_ts(), Some(100));
    // The reopen compacted the file to the live events only.
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 3);
    assert!(!text.contains("done"));
}

#[cfg(unix)]
#[test]
fn the_spool_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = temp_dir("mode");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    // A file left group/world-readable is rewritten 0600 on open.
    let path = dir.join("audit-spool.jsonl");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (mut s, _) = Spool::open(&path, SpoolLimits::default());
    assert_eq!(mode(&path), 0o600);
    s.push(vec![(1, event(1))]);
    assert_eq!(mode(&path), 0o600);
    // Created fresh (directory included): 0600 as well.
    let fresh = dir.join("sub").join("fresh.jsonl");
    let (mut s, r) = Spool::open(&fresh, SpoolLimits::default());
    assert!(r.error.is_none());
    s.push(vec![(1, event(1))]);
    assert_eq!(mode(&fresh), 0o600);
}

#[test]
fn a_torn_last_line_and_garbage_are_skipped_not_fatal() {
    let dir = temp_dir("torn");
    let path = dir.join("audit-spool.jsonl");
    let (mut s, _) = Spool::open(&path, SpoolLimits::default());
    s.push(vec![(1, event(1)), (2, event(2))]);
    drop(s);
    // Garbage, an over-long line, a record whose CBOR is no event, then a
    // crash in the middle of an append.
    let mut extra = b"not json\n".to_vec();
    extra.extend(vec![b'x'; MAX_LINE_BYTES + 10]);
    extra.push(b'\n');
    extra.extend(br#"{"v":1,"seq":9,"ts":1,"cbor":"AAAA"}"#);
    extra.push(b'\n');
    extra.extend(br#"{"v":1,"seq":10,"ts":1,"cb"#);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    f.write_all(&extra).unwrap();
    drop(f);

    let (mut s, r) = Spool::open(&path, SpoolLimits::default());
    assert!(r.error.is_none());
    assert_eq!(r.loaded, 2);
    assert_eq!(r.skipped_lines, 4);
    assert_eq!(pids(&s), vec![1, 2]);
    // The torn tail is gone: a new append lands on its own line.
    s.push(vec![(3, event(3))]);
    drop(s);
    let (s, r) = Spool::open(&path, SpoolLimits::default());
    assert_eq!(r.skipped_lines, 0);
    assert_eq!(pids(&s), vec![1, 2, 3]);
}

#[test]
fn the_cap_drops_the_oldest_events_and_records_it_on_disk() {
    let dir = temp_dir("cap");
    let path = dir.join("audit-spool.jsonl");
    let limits = SpoolLimits {
        max_entries: 3,
        max_bytes: DEFAULT_MAX_BYTES,
    };
    let (mut s, _) = Spool::open(&path, limits);
    let r = s.push(vec![(1, event(1)), (1, event(2))]);
    assert_eq!(r.dropped, 0);
    let r = s.push((3..=6).map(|n| (1, event(n))).collect());
    assert_eq!((r.spooled, r.dropped), (4, 3));
    assert_eq!(pids(&s), vec![4, 5, 6]);
    assert_eq!(s.dropped_total(), 3);
    drop(s);
    let (s, r) = Spool::open(&path, limits);
    assert_eq!(pids(&s), vec![4, 5, 6]);
    assert_eq!(r.dropped_over_cap, 0, "the watermark already finished them");
    drop(s);

    // A file holding more than a (lowered) cap keeps the newest on open.
    let tight = SpoolLimits {
        max_entries: 2,
        max_bytes: DEFAULT_MAX_BYTES,
    };
    let (s, r) = Spool::open(&path, tight);
    assert_eq!(r.dropped_over_cap, 1);
    assert_eq!(pids(&s), vec![5, 6]);

    // The byte cap holds too.
    let one = encoded_event_len(event(1).len());
    let limits = SpoolLimits {
        max_entries: 100,
        max_bytes: one * 2,
    };
    let (mut s, _) = Spool::open(&dir.join("bytes.jsonl"), limits);
    let r = s.push((1..=5).map(|n| (1, event(n))).collect());
    assert_eq!(r.dropped, 3);
    assert_eq!(pids(&s), vec![4, 5]);
}

#[test]
fn the_byte_accounting_never_undercounts_a_record() {
    for len in [1usize, 2, 3, 100, 4096, MAX_EVENT_CBOR_BYTES] {
        let rec = event_record(u64::MAX, i64::MIN, &vec![0xAB; len]);
        assert!(rec.len() as u64 <= encoded_event_len(len), "{len}");
    }
    // The largest event still fits a readable line.
    assert!(encoded_event_len(MAX_EVENT_CBOR_BYTES) <= MAX_LINE_BYTES as u64);
}

#[test]
fn dead_records_are_compacted_away() {
    let dir = temp_dir("compact");
    let path = dir.join("audit-spool.jsonl");
    let (mut s, _) = Spool::open(&path, SpoolLimits::default());
    // ~5.5 KiB records, so a few dozen cross the compaction threshold.
    let big = |n: u32| {
        ferro_audit::event::encode(&AuditEvent::LocalDenied {
            pid: n,
            uid: 0,
            bin_sha: Hash384([1; 48]),
            reason: "x".repeat(4096),
        })
        .unwrap()
    };
    let mut largest = 0;
    for n in 0..60 {
        s.push(vec![(1, big(n))]);
        let seq = s.front().unwrap().seq;
        s.complete_through(seq).unwrap();
        largest = largest.max(std::fs::metadata(&path).unwrap().len());
    }
    assert!(s.is_empty());
    let record = encoded_event_len(big(0).len());
    assert!(largest <= COMPACT_MIN_DEAD_BYTES + 2 * record, "{largest}");
    assert!(std::fs::metadata(&path).unwrap().len() < largest);
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_spool_path_is_replaced_not_followed() {
    let dir = temp_dir("link");
    let target = dir.join("elsewhere");
    std::fs::write(&target, b"keep me\n").unwrap();
    let path = dir.join("audit-spool.jsonl");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let (mut s, r) = Spool::open(&path, SpoolLimits::default());
    assert!(r.error.is_none());
    assert_eq!(r.loaded, 0);
    s.push(vec![(1, event(1))]);
    assert_eq!(std::fs::read(&target).unwrap(), b"keep me\n");
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_file());
}

#[test]
fn an_unwritable_spool_keeps_events_in_memory_and_recovers() {
    let dir = temp_dir("unwritable");
    // The parent "directory" is a file: nothing can be created under it.
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"").unwrap();
    let path = blocker.join("audit-spool.jsonl");
    let (mut s, r) = Spool::open(&path, SpoolLimits::default());
    assert!(r.error.is_some());
    let r = s.push(vec![(1, event(1)), (1, event(2))]);
    assert!(r.error.is_some());
    assert_eq!(pids(&s), vec![1, 2], "held in memory");
    // Once the location is usable, the next change writes everything.
    std::fs::remove_file(&blocker).unwrap();
    s.push(vec![(1, event(3))]);
    drop(s);
    let (s, r) = Spool::open(&path, SpoolLimits::default());
    assert!(r.error.is_none());
    assert_eq!(pids(&s), vec![1, 2, 3]);
}

/// Yields `head`, then fails as a failing disk would.
struct FailsAfter(std::io::Cursor<Vec<u8>>);

impl Read for FailsAfter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buf)? {
            0 => Err(std::io::Error::other("injected read error")),
            n => Ok(n),
        }
    }
}

/// A spool file holding events 1..=3, and its bytes.
fn three_events(path: &Path) -> Vec<u8> {
    let (mut s, _) = Spool::open(path, SpoolLimits::default());
    s.push((1..=3).map(|n| (1, event(n))).collect());
    drop(s);
    std::fs::read(path).unwrap()
}

fn set_aside_files(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().contains(".unreadable-"))
        .collect();
    found.sort();
    found
}

#[test]
fn a_spool_not_read_in_full_is_moved_aside_never_overwritten() {
    let dir = temp_dir("unreadable");
    let path = dir.join("audit-spool.jsonl");
    let original = three_events(&path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    // Mid-read I/O error after the first record.
    let first_line = original.split_inclusive(|&b| b == b'\n').next().unwrap();
    let (mut s, r) = Spool::open_with(&path, SpoolLimits::default(), |_| {
        Ok(FailsAfter(std::io::Cursor::new(first_line.to_vec())))
    });
    assert!(r.error.is_none(), "{:?}", r.error);
    assert_eq!((r.loaded, s.len()), (0, 0), "a fresh spool");
    let aside = set_aside_files(dir.path());
    assert_eq!(aside.len(), 1);
    assert_eq!(
        std::fs::read(&aside[0]).unwrap(),
        original,
        "kept unchanged"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&aside[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    s.push(vec![(1, event(4))]);
    drop(s);
    let (s, _) = Spool::open(&path, SpoolLimits::default());
    assert_eq!(pids(&s), vec![4]);
    let (s, _) = Spool::open(&aside[0], SpoolLimits::default());
    assert_eq!(pids(&s), vec![1, 2, 3], "nothing lost");

    // A file that cannot even be opened (Windows: not administrator-only).
    let path = dir.join("refused.jsonl");
    let original = three_events(&path);
    let (s, r) = Spool::open_with(&path, SpoolLimits::default(), |_| {
        Err::<std::fs::File, _>(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refused",
        ))
    });
    assert!(r.error.is_none() && s.is_empty());
    let moved: Vec<_> = set_aside_files(dir.path())
        .into_iter()
        .filter(|p| p.to_string_lossy().contains("refused.jsonl."))
        .collect();
    assert_eq!(moved.len(), 1);
    assert_eq!(std::fs::read(&moved[0]).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn an_unread_spool_that_cannot_be_moved_is_left_untouched() {
    use std::os::unix::fs::PermissionsExt as _;
    /// Gives the directory back its write right, a failed test included.
    struct Writable(PathBuf);
    impl Drop for Writable {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    let dir = temp_dir("stuck");
    let sub = dir.join("state");
    std::fs::create_dir(&sub).unwrap();
    let path = sub.join("audit-spool.jsonl");
    let original = three_events(&path);
    let _writable = Writable(sub.clone());
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(sub.join("probe"), b"").is_ok() {
        return; // Running as root: a read-only directory proves nothing.
    }
    let fail = |_: &Path| Ok(FailsAfter(std::io::Cursor::new(Vec::new())));
    let (mut s, r) = Spool::open_with(&path, SpoolLimits::default(), fail);
    assert!(r.error.is_some(), "reported, not hidden");
    let r = s.push(vec![(1, event(4)), (1, event(5))]);
    assert!(r.error.is_some());
    assert_eq!(pids(&s), vec![4, 5], "held in memory");
    assert_eq!(std::fs::read(&path).unwrap(), original, "never overwritten");

    // Once it can be moved, the next change does it, then writes the spool.
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    let r = s.push(vec![(1, event(6))]);
    assert!(r.error.is_none(), "{:?}", r.error);
    drop(s);
    let aside = set_aside_files(&sub);
    assert_eq!(aside.len(), 1);
    assert_eq!(std::fs::read(&aside[0]).unwrap(), original);
    let (s, _) = Spool::open(&path, SpoolLimits::default());
    assert_eq!(pids(&s), vec![4, 5, 6]);
}

#[test]
fn aside_names_never_replace_an_existing_file() {
    let dir = temp_dir("names");
    let path = dir.join("audit-spool.jsonl");
    let first = free_aside_path(&path, 42).unwrap();
    assert_eq!(first, dir.join("audit-spool.jsonl.unreadable-42"));
    std::fs::write(&first, b"taken").unwrap();
    let second = free_aside_path(&path, 42).unwrap();
    assert_eq!(second, dir.join("audit-spool.jsonl.unreadable-42-1"));
}

#[cfg(unix)]
#[test]
fn appends_never_follow_a_symlink() {
    let dir = temp_dir("nofollow");
    let target = dir.join("elsewhere");
    std::fs::write(&target, b"keep me\n").unwrap();
    let path = dir.join("audit-spool.jsonl");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(append(&path, b"x\n").is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"keep me\n");
}

#[test]
fn bounded_lines_are_read_whole_or_skipped() {
    let data = b"abc\ndefghij\nkl";
    let mut r = std::io::BufReader::with_capacity(2, &data[..]);
    let mut buf = Vec::new();
    assert!(matches!(
        read_line_bounded(&mut r, &mut buf, 5).unwrap(),
        LineRead::Line
    ));
    assert_eq!(buf, b"abc");
    assert!(matches!(
        read_line_bounded(&mut r, &mut buf, 5).unwrap(),
        LineRead::TooLong
    ));
    assert!(matches!(
        read_line_bounded(&mut r, &mut buf, 5).unwrap(),
        LineRead::Torn
    ));
    assert!(matches!(
        read_line_bounded(&mut r, &mut buf, 5).unwrap(),
        LineRead::Eof
    ));
}
