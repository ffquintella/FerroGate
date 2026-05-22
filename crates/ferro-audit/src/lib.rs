//! `ferro-audit` — append-only, Merkle-chained, externally-anchored audit log.
//!
//! Empty stub in M0; full implementation lands in milestone M3
//! (see `docs/audit.md` and `docs/features/F07-audit-log.md`).

#![forbid(unsafe_code)]

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-audit";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(CRATE_NAME, "ferro-audit");
    }
}
