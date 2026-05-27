//! Renewal-vs-re-attestation policy and the rotation scheduler math.
//!
//! A live SVID can be renewed cheaply (a single `Rotate` RPC, no TPM I/O) only
//! while the host is still inside its re-attestation window *and* its boot
//! state and the governing policy epoch are unchanged. Otherwise a full
//! four-phase attestation is required (`docs/protocol.md` §"Renewal vs
//! re-attestation").

/// Re-attestation window: a full handshake is required at least this often.
pub const REATTEST_WINDOW_SECS: i64 = 24 * 3600;

/// Fraction of TTL at which a healthy SVID is proactively rotated.
pub const ROTATE_FRACTION: f64 = 0.60;

/// Jitter applied around the rotation point, as a fraction of TTL (±).
pub const ROTATE_JITTER_FRACTION: f64 = 0.10;

/// Why a full re-attestation is being forced instead of a cheap renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReattestReason {
    /// More than [`REATTEST_WINDOW_SECS`] since the last full attestation.
    WindowExpired,
    /// The reported PCR digest differs from the last attested value.
    PcrDrift,
    /// The active RIM policy epoch was bumped.
    EpochBump,
}

/// The outcome of a renewal decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalDecision {
    /// Cheap path: issue a fresh SVID without touching the TPM.
    ShortPath,
    /// Force a full four-phase attestation, with the reason for the audit log.
    FullReattest(ReattestReason),
}

/// State recorded at the last full attestation, used to gate renewals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastAttestation {
    /// Unix seconds of the last full attestation.
    pub at: i64,
    /// Aggregate PCR digest attested at that time.
    pub pcr_digest: [u8; 48],
    /// RIM policy epoch in force at that time.
    pub policy_epoch: u64,
}

/// Decide whether a `Rotate` may take the short path or must re-attest.
///
/// Epoch and PCR mismatches take precedence over window expiry so the audit
/// log records the most specific cause.
#[must_use]
pub fn decide_renewal(
    last: &LastAttestation,
    now: i64,
    current_pcr_digest: &[u8; 48],
    current_epoch: u64,
) -> RenewalDecision {
    if current_epoch != last.policy_epoch {
        return RenewalDecision::FullReattest(ReattestReason::EpochBump);
    }
    if current_pcr_digest != &last.pcr_digest {
        return RenewalDecision::FullReattest(ReattestReason::PcrDrift);
    }
    if now.saturating_sub(last.at) > REATTEST_WINDOW_SECS {
        return RenewalDecision::FullReattest(ReattestReason::WindowExpired);
    }
    RenewalDecision::ShortPath
}

/// Seconds after issuance at which to rotate, given a TTL and a jitter sample.
///
/// `jitter_unit` is a uniform sample in `[0, 1)`; it is mapped to ±
/// [`ROTATE_JITTER_FRACTION`] of the TTL around the [`ROTATE_FRACTION`] point.
/// The result is clamped to `[0, ttl]` so a degenerate TTL never schedules a
/// rotation in the past or after expiry.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)] // TTLs are small (≤ 1 h), so the f64 round-trip is exact and in-range.
pub fn rotation_delay_secs(ttl_secs: i64, jitter_unit: f64) -> i64 {
    if ttl_secs <= 0 {
        return 0;
    }
    let ttl = ttl_secs as f64;
    let base = ttl * ROTATE_FRACTION;
    let jitter = (jitter_unit.clamp(0.0, 1.0) * 2.0 - 1.0) * ttl * ROTATE_JITTER_FRACTION;
    let delay = (base + jitter).round();
    delay.clamp(0.0, ttl) as i64
}

/// Absolute Unix-seconds rotation time for an SVID with the given `iat`/`exp`.
#[must_use]
pub fn rotation_at(iat: i64, exp: i64, jitter_unit: f64) -> i64 {
    iat + rotation_delay_secs(exp.saturating_sub(iat), jitter_unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last(at: i64, pcr: u8, epoch: u64) -> LastAttestation {
        LastAttestation {
            at,
            pcr_digest: [pcr; 48],
            policy_epoch: epoch,
        }
    }

    #[test]
    fn short_path_when_fresh_and_unchanged() {
        let l = last(1000, 9, 3);
        let d = decide_renewal(&l, 1000 + 3600, &[9; 48], 3);
        assert_eq!(d, RenewalDecision::ShortPath);
    }

    #[test]
    fn window_expiry_forces_reattest() {
        let l = last(0, 9, 3);
        let d = decide_renewal(&l, REATTEST_WINDOW_SECS + 1, &[9; 48], 3);
        assert_eq!(
            d,
            RenewalDecision::FullReattest(ReattestReason::WindowExpired)
        );
    }

    #[test]
    fn pcr_drift_forces_reattest() {
        let l = last(0, 9, 3);
        let d = decide_renewal(&l, 10, &[8; 48], 3);
        assert_eq!(d, RenewalDecision::FullReattest(ReattestReason::PcrDrift));
    }

    #[test]
    fn epoch_bump_takes_precedence() {
        let l = last(0, 9, 3);
        // Both PCR drift and epoch bump present; epoch wins.
        let d = decide_renewal(&l, 10, &[8; 48], 4);
        assert_eq!(d, RenewalDecision::FullReattest(ReattestReason::EpochBump));
    }

    #[test]
    fn rotation_centered_at_60_percent() {
        // jitter_unit = 0.5 maps to zero jitter -> exactly 60%.
        assert_eq!(rotation_delay_secs(3600, 0.5), 2160);
    }

    #[test]
    fn rotation_jitter_bounds() {
        let lo = rotation_delay_secs(3600, 0.0); // 60% - 10% = 50%
        let hi = rotation_delay_secs(3600, 1.0); // 60% + 10% = 70%
        assert_eq!(lo, 1800);
        assert_eq!(hi, 2520);
        for i in 0..=100 {
            let d = rotation_delay_secs(3600, f64::from(i) / 100.0);
            assert!((1800..=2520).contains(&d), "delay {d} out of band");
        }
    }

    #[test]
    fn rotation_at_is_iat_plus_delay() {
        assert_eq!(rotation_at(1_000, 1_000 + 3600, 0.5), 1_000 + 2160);
    }

    #[test]
    fn degenerate_ttl_is_safe() {
        assert_eq!(rotation_delay_secs(0, 0.5), 0);
        assert_eq!(rotation_delay_secs(-10, 0.5), 0);
    }
}
