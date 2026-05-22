//! `ferro-crypto` — hybrid post-quantum cryptographic primitives for FerroGate.
//!
//! This crate is intentionally empty in milestone M0; it will host the
//! composite Ed25519 + ML-DSA-65 signature scheme (F03) and the hybrid TLS
//! provider (F01) in milestone M1.
//!
//! See `docs/crypto.md` and `docs/features/F01-hybrid-pqc-tls.md`.

#![forbid(unsafe_code)]

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
