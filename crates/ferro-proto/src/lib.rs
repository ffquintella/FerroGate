//! `ferro-proto` — generated gRPC stubs and shared wire types.
//!
//! Empty in M0. From M2 onward, this crate will host the `tonic`-generated
//! `MachineIdentity` service stubs (see `docs/cmis.md`) plus any wire-shared
//! types that do not belong in a higher-level crate.

#![forbid(unsafe_code)]

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-proto";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(CRATE_NAME, "ferro-proto");
    }
}
