//! When the daemon renews its host SVID next, and what a refused `Rotate`
//! means (T294). Pure functions of the clock and a jitter sample in `[0, 1)`.
//!
//! Healthy: the jittered 60 % point of the TTL. After `n` failures with the
//! SVID still valid: [`RETRY_BASE`] × 2ⁿ⁻¹, jittered, capped at [`RETRY_CAP`]
//! and a quarter of the time left, never later than [`EXPIRY_MARGIN_SECS`]
//! before expiry. Without a valid SVID: every [`REATTEST_INTERVAL`] ±10 %.

use std::time::Duration;

use tonic::{Code, Status};

use crate::scheduler::delay_until_rotation;

/// How often a host without a valid SVID retries a full attestation: quick
/// recovery after boot, bounded load on CMIS for a host that stays offline.
pub const REATTEST_INTERVAL: Duration = Duration::from_mins(5);

/// First step of the back-off after a failed renewal.
pub const RETRY_BASE: Duration = Duration::from_secs(30);

/// Longest wait between two renewal attempts while the SVID is valid.
pub const RETRY_CAP: Duration = Duration::from_mins(15);

/// A retry is scheduled no later than this many seconds before expiry, so the
/// last attempt still lands while the SVID can sign it.
pub const EXPIRY_MARGIN_SECS: i64 = 60;

/// `Rotate` is tried only while the last full attestation is this far inside
/// CMIS's 24 h window ([`ferro_svid::REATTEST_WINDOW_SECS`]): the margin
/// absorbs host/CMIS clock skew, so a renewal at the edge re-attests at once
/// instead of collecting a predictable refusal.
pub const ROTATE_WINDOW_MARGIN_SECS: i64 = 600;

/// The shortest wait ever returned, so a failing renewal never spins.
const MIN_WAIT: Duration = Duration::from_secs(1);

/// What to do after `Rotate` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// CMIS wants a full attestation (or `Rotate` cannot work): run one now.
    FullAttest,
    /// A transient failure: retry `Rotate` after the back-off.
    Retry,
    /// Rate limited: retry after the server's `retry-after`.
    RetryAfter(Duration),
}

/// Classify a failed `Rotate` (T293 contract). `UNAVAILABLE`
/// (`store_unavailable`, unreachable), time-outs and internal errors retry;
/// `RESOURCE_EXHAUSTED` honours `retry-after` when sent. Everything else —
/// `FAILED_PRECONDITION`, `NOT_FOUND`, `UNAUTHENTICATED`,
/// `PERMISSION_DENIED`, anything undocumented — re-attests.
#[must_use]
pub fn classify(status: &Status) -> Next {
    match status.code() {
        Code::ResourceExhausted => crate::host_api::retry_after(status)
            .map_or(Next::Retry, |secs| {
                Next::RetryAfter(Duration::from_secs(secs))
            }),
        Code::Unavailable
        | Code::DeadlineExceeded
        | Code::Cancelled
        | Code::Aborted
        | Code::Unknown
        | Code::Internal => Next::Retry,
        _ => Next::FullAttest,
    }
}

/// Whether `Rotate` may be tried at `now` for a host last fully attested at
/// `last_full_attest_at` (decision D1: keep CMIS's window, check it locally).
#[must_use]
pub fn rotate_allowed(now: i64, last_full_attest_at: i64) -> bool {
    now < last_full_attest_at
        .saturating_add(ferro_svid::REATTEST_WINDOW_SECS)
        .saturating_sub(ROTATE_WINDOW_MARGIN_SECS)
}

/// How long to wait from `now` before the next attempt to renew an SVID valid
/// `iat..exp`, after `failures` consecutive failures. `jitter_unit` (uniform
/// in `[0, 1)`) places a healthy renewal in the ±10 % band around 60 % of
/// the TTL, and a retry in `[base/2, base]`. Whole seconds.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)] // whole seconds of a back-off capped at 15 min
pub fn next_wait(now: i64, iat: i64, exp: i64, failures: u32, jitter_unit: f64) -> Duration {
    if now >= exp {
        return reattest_wait(jitter_unit);
    }
    if failures == 0 {
        return delay_until_rotation(now, iat, exp, jitter_unit);
    }
    let left = exp - now;
    let base = RETRY_BASE
        .saturating_mul(1u32 << failures.saturating_sub(1).min(16))
        .min(RETRY_CAP)
        .min(secs(left / 4));
    // Jittered after the caps, so a fleet near expiry does not retry in step.
    let jittered = (base.as_secs() as f64 * (0.5 + 0.5 * jitter_unit.clamp(0.0, 1.0))) as u64;
    bound_before_expiry(Duration::from_secs(jittered), left)
}

/// The wait between full attestations of a host without a valid SVID:
/// [`REATTEST_INTERVAL`] ±10 %, whole seconds.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)] // whole seconds around 300
pub fn reattest_wait(jitter_unit: f64) -> Duration {
    let factor = 0.9 + 0.2 * jitter_unit.clamp(0.0, 1.0);
    Duration::from_secs((REATTEST_INTERVAL.as_secs() as f64 * factor) as u64)
}

/// The wait after a rate-limited `Rotate`: the server's `retry-after`,
/// bounded to `[1 s, RETRY_CAP]` and never past expiry while the SVID is
/// valid — the daemon must be awake to switch minting off then.
#[must_use]
pub fn retry_after_wait(now: i64, exp: i64, retry_after: Duration) -> Duration {
    let d = retry_after.clamp(MIN_WAIT, RETRY_CAP);
    if now < exp {
        d.min(secs(exp - now))
    } else {
        d
    }
}

/// `d`, at least [`MIN_WAIT`], waking no later than [`EXPIRY_MARGIN_SECS`]
/// before expiry while that is still ahead, and at expiry otherwise.
fn bound_before_expiry(d: Duration, left: i64) -> Duration {
    let latest = if left > EXPIRY_MARGIN_SECS {
        left - EXPIRY_MARGIN_SECS
    } else {
        left
    };
    d.max(MIN_WAIT).min(secs(latest))
}

/// Non-negative whole seconds.
#[allow(clippy::cast_sign_loss)] // clamped to ≥ 0 first
pub(crate) fn secs(s: i64) -> Duration {
    Duration::from_secs(s.max(0) as u64)
}
