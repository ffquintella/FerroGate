//! Progressive login throttling (NRM §5.3.5, F20 §8).
//!
//! Three key kinds, counted in the replicated `admin_login_throttle` table so
//! every node enforces the same lock:
//!
//! | Key | Applies to | Locks |
//! |-----|------------|-------|
//! | `K_ip` (source IP, the main control) | attempts without a valid device token | 3 → 1 min, 5 → 15 min, 7 → 1 h, each further 2 → 1 h |
//! | `K_dev` (IP + device token) | attempts with a valid device token | same as `K_ip` |
//! | `K_acct` (normalised username) | attempts without a valid device token | 9 → 1 min, 15 → 15 min, 21 → 1 h, each further 6 → 1 h |
//!
//! Counters with no failure for 24 h start over. The lock is checked before
//! any password work. The `K_acct` multipliers are pending ESI validation.

use ferro_raft::admin::ThrottleRow;

/// Seconds without a failure after which a counter starts over.
pub const RESET_AFTER_SECS: i64 = 24 * 3600;

/// Which counter a throttle row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Source IP (`K_ip`).
    Ip = 1,
    /// Source IP plus a valid device token (`K_dev`).
    IpDevice = 2,
    /// Normalised attempted username (`K_acct`).
    Account = 3,
}

impl KeyKind {
    /// Stable label for logs and audit events.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::IpDevice => "ip_device",
            Self::Account => "account",
        }
    }

    /// The integer stored in `admin_login_throttle.key_kind`.
    #[must_use]
    pub fn code(self) -> i64 {
        self as i64
    }
}

/// Lock, in seconds, applied when a key reaches `failures` failures (0 when
/// this failure does not cross a threshold).
#[must_use]
pub fn lock_secs(kind: KeyKind, failures: i64) -> u64 {
    // (first, second, third threshold, step between later hour-long locks)
    let (t1, t2, t3, step) = match kind {
        KeyKind::Ip | KeyKind::IpDevice => (3, 5, 7, 2),
        KeyKind::Account => (9, 15, 21, 6),
    };
    if failures == t1 {
        60
    } else if failures == t2 {
        900
    } else if failures >= t3 && (failures - t3) % step == 0 {
        3600
    } else {
        0
    }
}

/// The row after one more failure at `now`. A counter idle for 24 h starts
/// over; an existing longer lock is never shortened.
#[must_use]
pub fn register_failure(
    prev: Option<&ThrottleRow>,
    key_hash: &[u8],
    kind: KeyKind,
    now: i64,
) -> ThrottleRow {
    let live = prev.filter(|r| now.saturating_sub(r.last_failure_at) < RESET_AFTER_SECS);
    let failures = live.map_or(0, |r| r.failures).saturating_add(1);
    let lock = i64::try_from(lock_secs(kind, failures)).unwrap_or(i64::MAX);
    let previous_lock = live.map_or(0, |r| r.locked_until);
    let locked_until = if lock > 0 {
        previous_lock.max(now.saturating_add(lock))
    } else {
        previous_lock
    };
    ThrottleRow {
        key_hash: key_hash.to_vec(),
        key_kind: kind.code(),
        failures,
        locked_until,
        last_failure_at: now,
    }
}

/// Seconds the key stays locked at `now`, if it is locked.
#[must_use]
pub fn locked_for(row: &ThrottleRow, now: i64) -> Option<u64> {
    (row.locked_until > now).then(|| u64::try_from(row.locked_until - now).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `n` failures one second apart starting at `t0`; return the lock
    /// (seconds) in force right after each failure.
    fn locks_after(kind: KeyKind, n: i64, t0: i64) -> Vec<Option<u64>> {
        let mut row: Option<ThrottleRow> = None;
        let mut out = Vec::new();
        for i in 0..n {
            let now = t0 + i;
            let next = register_failure(row.as_ref(), b"k", kind, now);
            out.push(locked_for(&next, now));
            row = Some(next);
        }
        out
    }

    #[test]
    fn ip_and_device_keys_follow_the_nrm_schedule() {
        for kind in [KeyKind::Ip, KeyKind::IpDevice] {
            assert_eq!(lock_secs(kind, 1), 0);
            assert_eq!(lock_secs(kind, 2), 0);
            assert_eq!(lock_secs(kind, 3), 60);
            assert_eq!(lock_secs(kind, 4), 0);
            assert_eq!(lock_secs(kind, 5), 900);
            assert_eq!(lock_secs(kind, 6), 0);
            assert_eq!(lock_secs(kind, 7), 3600);
            assert_eq!(lock_secs(kind, 8), 0);
            assert_eq!(lock_secs(kind, 9), 3600);
            assert_eq!(lock_secs(kind, 11), 3600);
        }
    }

    #[test]
    fn account_key_uses_the_wider_schedule() {
        assert_eq!(lock_secs(KeyKind::Account, 3), 0);
        assert_eq!(lock_secs(KeyKind::Account, 9), 60);
        assert_eq!(lock_secs(KeyKind::Account, 15), 900);
        assert_eq!(lock_secs(KeyKind::Account, 21), 3600);
        assert_eq!(lock_secs(KeyKind::Account, 27), 3600);
        assert_eq!(lock_secs(KeyKind::Account, 22), 0);
    }

    #[test]
    fn progression_with_a_controlled_clock_locks_3_5_7_9() {
        // Failures arrive as soon as each lock lifts.
        let mut row: Option<ThrottleRow> = None;
        let mut now = 1_000_000;
        let mut seen = Vec::new();
        for _ in 0..9 {
            if let Some(r) = &row {
                if let Some(wait) = locked_for(r, now) {
                    now += i64::try_from(wait).unwrap();
                }
            }
            let next = register_failure(row.as_ref(), b"ip", KeyKind::Ip, now);
            seen.push((next.failures, locked_for(&next, now)));
            row = Some(next);
        }
        assert_eq!(
            seen,
            [
                (1, None),
                (2, None),
                (3, Some(60)),
                (4, None),
                (5, Some(900)),
                (6, None),
                (7, Some(3600)),
                (8, None),
                (9, Some(3600)),
            ]
        );
    }

    #[test]
    fn a_lock_expires_and_counters_reset_after_a_quiet_day() {
        let locks = locks_after(KeyKind::Ip, 3, 500);
        assert_eq!(locks[2], Some(60));
        let row = register_failure(None, b"k", KeyKind::Ip, 500);
        let row = register_failure(Some(&row), b"k", KeyKind::Ip, 501);
        let row = register_failure(Some(&row), b"k", KeyKind::Ip, 502);
        assert_eq!(locked_for(&row, 502 + 59), Some(1));
        assert_eq!(locked_for(&row, 502 + 60), None);
        let fresh = register_failure(Some(&row), b"k", KeyKind::Ip, 502 + RESET_AFTER_SECS);
        assert_eq!(fresh.failures, 1, "a quiet day starts the count over");
    }

    #[test]
    fn a_later_failure_never_shortens_an_existing_lock() {
        let mut row = None;
        for i in 0..7 {
            row = Some(register_failure(row.as_ref(), b"k", KeyKind::Ip, 10 + i));
        }
        let r7 = row.unwrap();
        assert_eq!(locked_for(&r7, 16), Some(3600));
        // An 8th failure (no threshold) keeps the hour lock.
        let r8 = register_failure(Some(&r7), b"k", KeyKind::Ip, 20);
        assert_eq!(r8.locked_until, r7.locked_until);
    }
}
