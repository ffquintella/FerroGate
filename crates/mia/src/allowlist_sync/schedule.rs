//! When the sync loop runs next (F19 §6.5): the configured interval with
//! ± jitter, a random first delay after start, and a capped exponential
//! back-off after transport failures. Pure functions of a uniform random
//! `unit` in `[0, 1)`, so the bounds are testable.

use std::time::Duration;

/// Shortest accepted `allowlist.sync_interval_secs`.
pub const MIN_INTERVAL_SECS: u64 = 60;
/// Longest accepted `allowlist.sync_interval_secs`.
pub const MAX_INTERVAL_SECS: u64 = 3600;
/// Default `allowlist.sync_interval_secs`.
pub const DEFAULT_INTERVAL_SECS: u64 = 300;
/// Largest accepted `allowlist.sync_jitter_pct`.
pub const MAX_JITTER_PCT: u8 = 50;
/// Default `allowlist.sync_jitter_pct`.
pub const DEFAULT_JITTER_PCT: u8 = 10;
/// First step of the transport back-off.
const BACKOFF_BASE: Duration = Duration::from_secs(5);

/// `interval × uniform(1 − jitter, 1 + jitter)`, with `jitter_pct` clamped to
/// [`MAX_JITTER_PCT`].
#[must_use]
pub fn jittered(interval: Duration, jitter_pct: u8, unit: f64) -> Duration {
    let jitter = f64::from(jitter_pct.min(MAX_JITTER_PCT)) / 100.0;
    let unit = unit.clamp(0.0, 1.0);
    interval.mul_f64(1.0 - jitter + 2.0 * jitter * unit)
}

/// `uniform(0, interval)`: the first sync after a start, so a fleet restarted
/// at once does not poll CMIS in lock-step.
#[must_use]
pub fn initial_delay(interval: Duration, unit: f64) -> Duration {
    interval.mul_f64(unit.clamp(0.0, 1.0))
}

/// `min(interval, 2^failures × 5 s)` after `failures` consecutive transport
/// failures (`failures ≥ 1`).
#[must_use]
pub fn backoff(interval: Duration, failures: u32) -> Duration {
    let factor = 1u32 << failures.saturating_sub(1).min(16);
    BACKOFF_BASE.saturating_mul(factor).min(interval)
}

/// A server `retry-after`, bounded to `[1 s, interval]`.
#[must_use]
pub fn retry_after(interval: Duration, secs: u64) -> Duration {
    Duration::from_secs(secs.max(1)).min(interval)
}

/// The configured interval clamped to `60..=3600` s.
#[must_use]
pub fn clamp_interval(secs: u64) -> Duration {
    Duration::from_secs(secs.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS))
}

/// A uniform `f64` in `[0, 1)` from the OS RNG.
#[must_use]
pub fn unit_random() -> f64 {
    let bytes = crate::host_api::random_bytes();
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[..8]);
    // 53 random bits: exactly representable, uniform over [0, 1).
    #[allow(clippy::cast_precision_loss)]
    let v = (u64::from_le_bytes(word) >> 11) as f64;
    v / 9_007_199_254_740_992.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_bounds() {
        let interval = Duration::from_secs(300);
        assert_eq!(jittered(interval, 10, 0.0), Duration::from_secs(270));
        assert_eq!(jittered(interval, 10, 0.5), Duration::from_secs(300));
        assert!(jittered(interval, 10, 0.999_999) <= Duration::from_secs(330));
        assert_eq!(jittered(interval, 0, 0.9), interval);
        // An out-of-range percentage is clamped to 50 %.
        assert_eq!(jittered(interval, 90, 0.0), Duration::from_secs(150));
        for _ in 0..1000 {
            let d = jittered(interval, 10, unit_random());
            assert!(d >= Duration::from_secs(270) && d <= Duration::from_secs(330));
            let first = initial_delay(interval, unit_random());
            assert!(first < interval);
        }
    }

    #[test]
    fn backoff_doubles_up_to_the_interval() {
        let interval = Duration::from_secs(300);
        assert_eq!(backoff(interval, 1), Duration::from_secs(5));
        assert_eq!(backoff(interval, 2), Duration::from_secs(10));
        assert_eq!(backoff(interval, 4), Duration::from_secs(40));
        assert_eq!(backoff(interval, 7), Duration::from_secs(300));
        assert_eq!(backoff(interval, 99), interval);
        assert_eq!(retry_after(interval, 0), Duration::from_secs(1));
        assert_eq!(retry_after(interval, 9999), interval);
        assert_eq!(clamp_interval(5), Duration::from_secs(60));
        assert_eq!(clamp_interval(86_400), Duration::from_secs(3600));
    }
}
