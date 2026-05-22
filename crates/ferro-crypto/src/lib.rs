//! `ferro-crypto` — hybrid post-quantum cryptographic primitives for FerroGate.
//!
//! M1 lands the foundations every other crate depends on:
//!
//! - [`tls`] — a rustls [`CryptoProvider`](rustls::crypto::CryptoProvider)
//!   configured for hybrid `X25519MLKEM768` key exchange (feature F01).
//! - [`pin`] — SPKI-pin server certificate verifier for MIA-side handshakes
//!   (feature F01).
//!
//! Composite Ed25519 + ML-DSA-65 signatures (feature F03) land in a
//! follow-up change.
//!
//! See `docs/crypto.md` and `docs/features/F01-hybrid-pqc-tls.md`.

#![forbid(unsafe_code)]

pub mod pin;
pub mod tls;

/// Crate identifier, used for early build-time wiring sanity checks.
pub const CRATE_NAME: &str = "ferro-crypto";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(CRATE_NAME, "ferro-crypto");
    }
}
