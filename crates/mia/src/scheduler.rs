//! Rotation scheduling.
//!
//! A healthy SVID is rotated proactively at 60% of its TTL with ±10% jitter
//! (the math lives in [`ferro_svid::lifecycle`]) so a fleet does not stampede
//! CMIS at a synchronized renewal boundary.

use std::time::Duration;

use ferro_svid::rotation_at;
use rand_core::{OsRng, RngCore};

/// A uniform jitter sample in `[0, 1)` from the OS CSPRNG, suitable for
/// [`ferro_svid::rotation_delay_secs`].
#[must_use]
#[allow(clippy::cast_precision_loss)] // 53-bit value into an f64 mantissa is exact.
pub fn random_jitter() -> f64 {
    // 53-bit mantissa worth of randomness mapped into [0, 1).
    let x = OsRng.next_u64() >> 11;
    (x as f64) / ((1u64 << 53) as f64)
}

/// How long to wait, from `now`, before rotating an SVID issued at `iat` and
/// expiring at `exp`. Never negative; if the rotation point has already passed
/// (e.g. a slow boot), returns [`Duration::ZERO`] so the caller rotates now.
#[must_use]
#[allow(clippy::cast_sign_loss)] // `secs` is clamped to ≥ 0 before the cast.
pub fn delay_until_rotation(now: i64, iat: i64, exp: i64, jitter_unit: f64) -> Duration {
    let target = rotation_at(iat, exp, jitter_unit);
    let secs = target.saturating_sub(now).max(0);
    Duration::from_secs(secs as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_is_about_sixty_percent_for_centered_jitter() {
        // iat=1000, ttl=3600 -> rotate at 1000+2160; from now=1000 that's 2160s.
        let d = delay_until_rotation(1000, 1000, 1000 + 3600, 0.5);
        assert_eq!(d, Duration::from_secs(2160));
    }

    #[test]
    fn delay_clamps_to_zero_when_overdue() {
        // now already past the rotation point.
        let d = delay_until_rotation(1000 + 3000, 1000, 1000 + 3600, 0.5);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn jitter_sample_in_unit_interval() {
        for _ in 0..1000 {
            let j = random_jitter();
            assert!((0.0..1.0).contains(&j), "jitter {j} out of [0,1)");
        }
    }

    #[test]
    fn jitter_keeps_delay_within_band() {
        let lo = delay_until_rotation(1000, 1000, 1000 + 3600, 0.0);
        let hi = delay_until_rotation(1000, 1000, 1000 + 3600, 1.0);
        assert_eq!(lo, Duration::from_secs(1800)); // 50%
        assert_eq!(hi, Duration::from_secs(2520)); // 70%
    }
}
