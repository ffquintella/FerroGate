//! Aggregate PCR digest helper.
//!
//! The RIM allowlist is keyed by the aggregate digest
//! `SHA-384( concat(pcr_i for i in ascending index) )`. CMIS recomputes the
//! same aggregate from the raw PCR values a client reports on `Rotate` so it
//! can detect boot-state drift without a fresh quote.

use sha2::{Digest, Sha384};

/// Compute the aggregate SHA-384 digest over `(index, value)` pairs, taken in
/// ascending index order (duplicates last-wins, matching a sorted selection).
#[must_use]
pub fn aggregate_digest(pcrs: &[(u8, Vec<u8>)]) -> [u8; 48] {
    let mut sorted: Vec<&(u8, Vec<u8>)> = pcrs.iter().collect();
    sorted.sort_by_key(|(idx, _)| *idx);
    let mut h = Sha384::new();
    for (_, value) in sorted {
        h.update(value);
    }
    let out = h.finalize();
    let mut digest = [0u8; 48];
    digest.copy_from_slice(&out);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_independent_of_input_order() {
        let a = aggregate_digest(&[(4, vec![1, 2]), (0, vec![3, 4]), (7, vec![5])]);
        let b = aggregate_digest(&[(0, vec![3, 4]), (7, vec![5]), (4, vec![1, 2])]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_values_differ() {
        let a = aggregate_digest(&[(0, vec![1])]);
        let b = aggregate_digest(&[(0, vec![2])]);
        assert_ne!(a, b);
    }
}
