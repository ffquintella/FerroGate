//! Wall-clock seam for the admin subsystem, so session lifetimes, TOTP steps
//! and throttle locks can be tested with a controlled clock.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of Unix time in whole seconds.
pub trait Clock: Send + Sync + 'static {
    /// Current Unix time in seconds.
    fn now(&self) -> i64;
}

/// The operating-system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}

/// A clock that only moves when told to (tests).
#[derive(Debug)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// Start at `now`.
    #[must_use]
    pub fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    /// Jump to `now`.
    pub fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }

    /// Move forward by `secs`.
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
