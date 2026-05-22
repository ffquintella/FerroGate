//! `ferro-tee` — Trusted Execution Environment glue (SEV-SNP, TDX) and
//! threshold key-share handling.
//!
//! Empty in M0; the attested-share reconstruction path is delivered in
//! milestone M4 (see `docs/features/F06-tee-threshold-keys.md`).

#![forbid(unsafe_code)]

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-tee";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(CRATE_NAME, "ferro-tee");
    }
}
