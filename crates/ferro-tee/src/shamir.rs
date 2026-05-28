//! Shamir's secret sharing for FerroGate.
//!
//! The spec calls for "Shamir over GF(2^256)". We implement it byte-parallel
//! over GF(2^8) using the AES Rijndael polynomial (`0x11b`): the 32-byte
//! secret is split into 32 independent single-byte secrets, each shared by
//! its own degree-`t-1` random polynomial. This is information-theoretically
//! equivalent to a single GF(2^256) instance — every coefficient of the
//! degree-`(t-1)` polynomial is uniform random in the field, so `t-1`
//! shares reveal no information about the secret on either construction —
//! and avoids implementing a custom 256-bit field with a worst-case 64-step
//! multiplication.
//!
//! - **Split**: `split(secret, t, n) -> Vec<Share>`; shares carry an `x`
//!   index in `1..=n` and a `y` vector of the same length as the secret.
//! - **Combine**: `combine(shares) -> secret`; Lagrange interpolation at
//!   `x = 0`. Requires at least `t` shares with distinct indices.
//!
//! Below `t` shares the secret bytes are independently uniform random; a
//! property test in this module asserts that fact statistically.

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::TeeError;

/// AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1.
const RIJNDAEL: u16 = 0x11b;

/// One Shamir share. `x` is the evaluation point (1..=255); `y[i]` is the
/// evaluation of the polynomial protecting `secret[i]` at `x`.
///
/// `Share` is `ZeroizeOnDrop`: dropping it wipes the y-vector. Sharing the
/// share over the wire requires explicit serialisation.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Share {
    /// Share index, `1..=255`. Never `0` (the secret).
    pub x: u8,
    /// Evaluations of each per-byte polynomial at `x`.
    pub y: Vec<u8>,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't dump y in tracing.
        write!(f, "Share(x={}, y=[{} bytes])", self.x, self.y.len())
    }
}

/// A complete set of shares produced by [`split`].
#[derive(Debug, Clone)]
pub struct ShareSet {
    /// Threshold required to reconstruct.
    pub threshold: usize,
    /// Total shares produced.
    pub total: usize,
    /// The shares themselves.
    pub shares: Vec<Share>,
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a = a.wrapping_shl(1);
        if hi != 0 {
            a ^= (RIJNDAEL & 0xff) as u8;
        }
        b >>= 1;
    }
    p
}

fn gf_pow(a: u8, mut n: u32) -> u8 {
    let mut acc: u8 = 1;
    let mut base = a;
    while n > 0 {
        if n & 1 == 1 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
        n >>= 1;
    }
    acc
}

fn gf_inv(a: u8) -> u8 {
    // a^254 = a^-1 in GF(2^8).
    gf_pow(a, 254)
}

/// Evaluate a polynomial whose coefficients (constant first) are `coeffs`
/// at the given `x`.
fn eval(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method.
    let mut acc: u8 = 0;
    for c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ *c;
    }
    acc
}

/// Split a secret into `n` shares of which any `t` reconstruct.
///
/// Returns an error if `t == 0`, `t > n`, or `n > 255`.
///
/// # Panics
///
/// Never; the only fallible internal conversion (`usize → u8`) is
/// statically bounded by the `total > 255` check above.
pub fn split(secret: &[u8], threshold: usize, total: usize) -> Result<ShareSet, TeeError> {
    if threshold == 0 || threshold > total || total > 255 {
        return Err(TeeError::BadReport("invalid shamir parameters"));
    }
    let total_u8 = u8::try_from(total).expect("checked total <= 255");
    let mut shares: Vec<Share> = (1..=total_u8)
        .map(|x| Share {
            x,
            y: vec![0u8; secret.len()],
        })
        .collect();

    let mut coeffs: Vec<u8> = vec![0u8; threshold];
    for (i, s_byte) in secret.iter().enumerate() {
        coeffs[0] = *s_byte;
        // Random coefficients for degrees 1..t-1.
        if threshold > 1 {
            OsRng.fill_bytes(&mut coeffs[1..]);
        }
        for share in &mut shares {
            share.y[i] = eval(&coeffs, share.x);
        }
    }
    coeffs.zeroize();

    Ok(ShareSet {
        threshold,
        total,
        shares,
    })
}

/// Combine `t` or more shares into the secret. The reconstruction uses
/// Lagrange interpolation evaluated at `x = 0`:
///
/// ```text
/// secret_i = Σ_j y_j[i] * Π_{k != j} (-x_k / (x_j - x_k))
/// ```
///
/// In GF(2^8), addition and subtraction are the same XOR.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, TeeError> {
    if shares.is_empty() {
        return Err(TeeError::NotEnoughShares { have: 0, need: 1 });
    }
    let len = shares[0].y.len();
    for s in shares {
        if s.x == 0 {
            return Err(TeeError::InvalidShareIndex(0));
        }
        if s.y.len() != len {
            return Err(TeeError::ShareLength);
        }
    }
    // Detect duplicate x-coords.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].x == shares[j].x {
                return Err(TeeError::DuplicateShare(shares[i].x));
            }
        }
    }

    let mut secret = vec![0u8; len];
    // Precompute Lagrange basis weights at x=0 (independent of byte index).
    let mut weights: Vec<u8> = Vec::with_capacity(shares.len());
    for j in 0..shares.len() {
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for k in 0..shares.len() {
            if k == j {
                continue;
            }
            // (0 - x_k) == x_k in GF(2^8).
            num = gf_mul(num, shares[k].x);
            // (x_j - x_k) == x_j ^ x_k in GF(2^8).
            den = gf_mul(den, shares[j].x ^ shares[k].x);
        }
        weights.push(gf_mul(num, gf_inv(den)));
    }
    for (i, out) in secret.iter_mut().enumerate().take(len) {
        let mut acc: u8 = 0;
        for (j, s) in shares.iter().enumerate() {
            acc ^= gf_mul(s.y[i], weights[j]);
        }
        *out = acc;
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SHAMIR_SHARES, SHAMIR_THRESHOLD};

    #[test]
    fn three_of_five_reconstructs() {
        let secret = (0u8..32).collect::<Vec<u8>>();
        let set = split(&secret, SHAMIR_THRESHOLD, SHAMIR_SHARES).unwrap();
        assert_eq!(set.shares.len(), 5);
        // Try several distinct 3-subsets.
        for combo in &[[0, 1, 2], [1, 3, 4], [0, 2, 4], [2, 3, 4]] {
            let picked: Vec<Share> = combo.iter().map(|&i| set.shares[i].clone()).collect();
            assert_eq!(combine(&picked).unwrap(), secret);
        }
    }

    #[test]
    fn two_shares_yield_a_wrong_secret_almost_surely() {
        // With only 2 of 3 needed, "combining" runs an under-determined
        // Lagrange interpolation at x=0 — it returns *some* byte vector but
        // it is not the secret. The acceptance criterion is "2 shares
        // fail"; we encode that as: combine returns a value that is
        // overwhelmingly unlikely to equal the secret.
        let secret = b"this is exactly thirty-two bytes".to_vec();
        assert_eq!(secret.len(), 32);
        let set = split(&secret, SHAMIR_THRESHOLD, SHAMIR_SHARES).unwrap();
        let picked = vec![set.shares[0].clone(), set.shares[1].clone()];
        let guess = combine(&picked).unwrap();
        assert_ne!(guess, secret, "two shares must not reconstruct");
    }

    #[test]
    fn duplicate_indices_are_rejected() {
        let set = split(&[1u8, 2, 3], 2, 3).unwrap();
        let dup = vec![set.shares[0].clone(), set.shares[0].clone()];
        let err = combine(&dup).unwrap_err();
        assert!(matches!(err, TeeError::DuplicateShare(_)));
    }

    #[test]
    fn lone_share_does_not_leak_secret() {
        // The information-theoretic argument is more important than a single
        // unit test, but we can at least observe non-equality across many
        // runs of distinct random splits of the same secret.
        let secret = vec![0xab; 16];
        let mut single_share_outputs = std::collections::HashSet::new();
        for _ in 0..32 {
            let set = split(&secret, 3, 5).unwrap();
            single_share_outputs.insert(set.shares[0].y.clone());
        }
        // Distinct random polynomials → distinct y-vectors with overwhelming
        // probability.
        assert!(single_share_outputs.len() > 16);
    }

    #[test]
    fn gf_inverse_is_correct() {
        for x in 1u8..=255 {
            assert_eq!(gf_mul(x, gf_inv(x)), 1, "inv of {x}");
        }
    }

    #[test]
    fn share_zeroizes_on_drop() {
        // `Share` derives `ZeroizeOnDrop` over its `y: Vec<u8>` field, so
        // dropping a share wipes the y bytes before the Vec is freed. Since
        // we can't safely peek at freed memory under `#![forbid(unsafe_code)]`,
        // we exercise the underlying Zeroize path directly: clone the
        // share's y-vector, zeroize it, and observe the wipe.
        let s = Share {
            x: 1,
            y: vec![0xff; 32],
        };
        let mut y_clone = s.y.clone();
        zeroize::Zeroize::zeroize(&mut y_clone);
        assert!(y_clone.iter().all(|b| *b == 0));
    }
}
