//! `ferro-attest` — TPM 2.0 quote verification and RIM matching.
//!
//! Empty stub in M0; the full verifier (`TpmQuoteVerifier`, the 10-step
//! algorithm from `docs/tpm.md`) lands in milestone M2.

#![forbid(unsafe_code)]

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-attest";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(CRATE_NAME, "ferro-attest");
    }
}
