//! RFC 6238 TOTP (HMAC-SHA-1, 6 digits, 30-second step, ±1 step) — the
//! second factor every admin client supports (F20 §5).
//!
//! A code is accepted only if its time step is strictly greater than the last
//! step accepted for the account (`totp_last_step`), so a code can be used at
//! most once; the caller persists the returned step with a compare-and-set.

use hmac::{KeyInit, Mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::codec::base32_encode;

/// Length of a TOTP time step, in seconds.
pub const STEP_SECS: i64 = 30;
/// Number of digits in a code.
pub const DIGITS: usize = 6;
/// Secret length in bytes (160 bits, RFC 4226 §4 recommendation).
pub const SECRET_LEN: usize = 20;
/// Steps of clock skew tolerated on either side of the current step.
pub const SKEW_STEPS: i64 = 1;

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// The time step containing Unix time `now`.
#[must_use]
pub fn step_at(now: i64) -> i64 {
    now.div_euclid(STEP_SECS)
}

/// The HOTP value (RFC 4226) for `step`, truncated to [`DIGITS`] digits.
///
/// # Panics
///
/// Never: HMAC accepts keys of any length.
#[must_use]
pub fn code_at(secret: &[u8], step: i64) -> String {
    // HMAC accepts keys of any length, so `new_from_slice` cannot fail.
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    // Steps before the epoch never occur; clamp rather than wrap.
    mac.update(&u64::try_from(step).unwrap_or(0).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:0width$}", binary % 1_000_000, width = DIGITS)
}

/// Verify `code` against the steps around `now`. Returns the matched step when
/// it is newer than `last_step`; `None` for a wrong, malformed, or replayed
/// code. Every candidate step is compared in constant time.
#[must_use]
pub fn verify(secret: &[u8], code: &str, now: i64, last_step: Option<i64>) -> Option<i64> {
    if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = step_at(now);
    let mut matched = None;
    // Check every candidate (no early exit) so timing does not reveal which
    // step matched.
    for step in (current - SKEW_STEPS)..=(current + SKEW_STEPS) {
        let expected = Zeroizing::new(code_at(secret, step));
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            matched = Some(step);
        }
    }
    matched.filter(|step| last_step.is_none_or(|last| *step > last))
}

/// A fresh random secret from the OS CSPRNG.
///
/// # Panics
///
/// Panics if the operating system's random source fails.
#[must_use]
pub fn generate_secret() -> Zeroizing<[u8; SECRET_LEN]> {
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    getrandom::fill(secret.as_mut()).expect("OS random source");
    secret
}

/// The `otpauth://` provisioning URI an authenticator app imports (shown once
/// at enrollment). `account` must already be a validated username.
#[must_use]
pub fn provisioning_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let secret = Zeroizing::new(base32_encode(secret));
    format!(
        "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        secret.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, SHA-1 secret.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_rfc6238_sha1_vectors_truncated_to_six_digits() {
        // (Unix time, 8-digit RFC value) → the last 6 digits.
        for (t, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code_at(RFC_SECRET, step_at(t)), code, "t={t}");
        }
    }

    #[test]
    fn accepts_one_step_of_skew_either_side() {
        let now = 1_111_111_111;
        let s = step_at(now);
        for delta in [-1, 0, 1] {
            let code = code_at(RFC_SECRET, s + delta);
            assert_eq!(verify(RFC_SECRET, &code, now, None), Some(s + delta));
        }
        let far = code_at(RFC_SECRET, s + 2);
        assert_eq!(verify(RFC_SECRET, &far, now, None), None);
        let old = code_at(RFC_SECRET, s - 2);
        assert_eq!(verify(RFC_SECRET, &old, now, None), None);
    }

    #[test]
    fn rejects_a_replay_at_the_same_or_an_earlier_step() {
        let now = 1_234_567_890;
        let s = step_at(now);
        let code = code_at(RFC_SECRET, s);
        assert_eq!(verify(RFC_SECRET, &code, now, Some(s - 1)), Some(s));
        assert_eq!(verify(RFC_SECRET, &code, now, Some(s)), None, "same step");
        assert_eq!(
            verify(RFC_SECRET, &code, now, Some(s + 1)),
            None,
            "older step"
        );
    }

    #[test]
    fn rejects_malformed_codes() {
        let now = 59;
        for bad in ["", "28708", "2870822", "28708a", " 287082", "２８７０８２"] {
            assert_eq!(verify(RFC_SECRET, bad, now, None), None, "{bad:?}");
        }
    }

    #[test]
    fn provisioning_uri_carries_the_base32_secret() {
        let uri = provisioning_uri(RFC_SECRET, "FerroGate", "alice");
        assert!(uri.starts_with(
            "otpauth://totp/FerroGate:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&"
        ));
        assert!(uri.contains("digits=6") && uri.contains("period=30"));
    }
}
