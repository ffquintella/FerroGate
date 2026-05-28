//! RFC 6962-style Merkle Hash Tree over SHA3-384.
//!
//! Leaves are domain-separated from internal nodes:
//!
//! ```text
//! leaf_hash(x)    = SHA3-384( 0x00 || x )
//! node_hash(l,r)  = SHA3-384( 0x01 || l || r )
//! ```
//!
//! For a tree containing leaves `D = (d_0, …, d_{n-1})` the Merkle Tree Hash
//! `MTH(D)` is defined for `n >= 1` as `MTH({d_0}) = leaf_hash(d_0)` and for
//! `n > 1`, with `k` the largest power of two strictly less than `n`,
//! `MTH(D) = node_hash(MTH(D[0..k]), MTH(D[k..n]))`.
//!
//! Inclusion and consistency proofs follow RFC 6962 §2.1.1 and §2.1.2. The
//! verifiers ([`verify_inclusion`], [`verify_consistency`]) are independent
//! of the tree state — a third party in possession of an old STH can check a
//! consistency proof against the freshly-published STH and detect *any*
//! insertion, deletion, or reordering.

use sha3::{Digest, Sha3_384};

/// Domain-separation prefix on leaf hashes.
pub const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix on internal-node hashes.
pub const NODE_PREFIX: u8 = 0x01;
/// Size of one SHA-3-384 digest.
pub const HASH_LEN: usize = 48;

/// Compute `SHA3-384(0x00 || data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha3_384::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&h.finalize());
    out
}

/// Compute `SHA3-384(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut h = Sha3_384::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&h.finalize());
    out
}

/// Largest power of two strictly less than `n`. Requires `n >= 2`.
fn largest_pow2_below(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// In-memory append-only Merkle tree. Stores leaf hashes; the root and proofs
/// are recomputed on demand from those hashes. Suitable for the in-process
/// audit log; an external store keeps the raw leaf bytes alongside.
#[derive(Debug, Default, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; HASH_LEN]>,
}

impl MerkleTree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a pre-hashed leaf and return its index.
    pub fn append(&mut self, leaf: [u8; HASH_LEN]) -> usize {
        let i = self.leaves.len();
        self.leaves.push(leaf);
        i
    }

    /// Current number of leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree has no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Borrow the i'th leaf hash, if it exists.
    #[must_use]
    pub fn leaf(&self, index: usize) -> Option<&[u8; HASH_LEN]> {
        self.leaves.get(index)
    }

    /// Root hash of the current tree. `None` iff the tree is empty (the empty
    /// tree's root is undefined in RFC 6962; callers must treat it specially).
    #[must_use]
    pub fn root(&self) -> Option<[u8; HASH_LEN]> {
        if self.leaves.is_empty() {
            None
        } else {
            Some(mth(&self.leaves))
        }
    }

    /// Inclusion proof for the leaf at `index` against the current tree.
    /// `None` if `index` is out of range.
    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<[u8; HASH_LEN]>> {
        if index >= self.leaves.len() {
            return None;
        }
        Some(path(index, &self.leaves))
    }

    /// Consistency proof between the prefix of size `old_size` and the
    /// current tree of size `new_size`. Requires `0 < old_size <= new_size`.
    #[must_use]
    pub fn consistency_proof(
        &self,
        old_size: usize,
        new_size: usize,
    ) -> Option<Vec<[u8; HASH_LEN]>> {
        if old_size == 0 || old_size > new_size || new_size != self.leaves.len() {
            return None;
        }
        Some(proof(old_size, &self.leaves[..new_size]))
    }
}

/// RFC 6962 MTH(D) for `D.len() >= 1`.
fn mth(d: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    if d.len() == 1 {
        return d[0];
    }
    let k = largest_pow2_below(d.len());
    let left = mth(&d[..k]);
    let right = mth(&d[k..]);
    node_hash(&left, &right)
}

/// RFC 6962 PATH(m, D): inclusion proof for leaf at index `m` in `D`.
#[allow(clippy::many_single_char_names)] // m/d/n/k/p are the RFC 6962 letters.
fn path(m: usize, d: &[[u8; HASH_LEN]]) -> Vec<[u8; HASH_LEN]> {
    let n = d.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = largest_pow2_below(n);
    if m < k {
        // Leaf is in the left subtree.
        let mut p = path(m, &d[..k]);
        p.push(mth(&d[k..]));
        p
    } else {
        // Leaf is in the right subtree.
        let mut p = path(m - k, &d[k..]);
        p.push(mth(&d[..k]));
        p
    }
}

/// RFC 6962 PROOF(m, D): consistency proof between prefix of size `m` and
/// current `D` of size `n`. `m` must satisfy `1 <= m <= n`.
fn proof(m: usize, d: &[[u8; HASH_LEN]]) -> Vec<[u8; HASH_LEN]> {
    subproof(m, d, true)
}

#[allow(clippy::many_single_char_names)] // m/d/n/k/b/p are the RFC 6962 letters.
fn subproof(m: usize, d: &[[u8; HASH_LEN]], b: bool) -> Vec<[u8; HASH_LEN]> {
    let n = d.len();
    if m == n {
        if b {
            // Old tree's root is a subtree of the new tree.
            return Vec::new();
        }
        return vec![mth(d)];
    }
    // m < n
    let k = largest_pow2_below(n);
    if m <= k {
        let mut p = subproof(m, &d[..k], b);
        p.push(mth(&d[k..]));
        p
    } else {
        let mut p = subproof(m - k, &d[k..], false);
        p.push(mth(&d[..k]));
        p
    }
}

/// Verify an RFC 6962 inclusion proof.
///
/// Returns `true` iff there exists a tree of `tree_size` leaves whose root is
/// `root` and whose leaf at `leaf_index` has hash `leaf`. Implementation
/// follows the standard "walk from the leaf to the root" algorithm.
#[must_use]
pub fn verify_inclusion(
    leaf: &[u8; HASH_LEN],
    leaf_index: usize,
    tree_size: usize,
    root: &[u8; HASH_LEN],
    proof: &[[u8; HASH_LEN]],
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut fn_idx = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = *leaf;
    let mut it = proof.iter();
    while sn > 0 {
        let Some(p) = it.next() else {
            return false;
        };
        if fn_idx % 2 == 1 || fn_idx == sn {
            // Right child or rightmost-odd subtree boundary.
            r = node_hash(p, &r);
            if fn_idx % 2 == 0 {
                while fn_idx % 2 == 0 {
                    fn_idx >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }
    it.next().is_none() && &r == root
}

/// Verify an RFC 6962 consistency proof between trees of sizes `old_size`
/// (root `old_root`) and `new_size` (root `new_root`).
#[must_use]
pub fn verify_consistency(
    old_size: usize,
    new_size: usize,
    old_root: &[u8; HASH_LEN],
    new_root: &[u8; HASH_LEN],
    proof: &[[u8; HASH_LEN]],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        // Tree did not grow; proof must be empty and roots equal.
        return proof.is_empty() && old_root == new_root;
    }
    // Pad proof for the case where old_size is a power of two and equal to
    // the size of an entire subtree of the new tree: the proof omits the
    // (then-known) old_root.
    let (mut fr, mut sr, proof_slice) = if old_size.is_power_of_two() && old_size <= new_size {
        // RFC 6962: when m is a power of 2, the first node in the proof is
        // skipped because it equals old_root.
        (*old_root, *old_root, proof)
    } else {
        if proof.is_empty() {
            return false;
        }
        (proof[0], proof[0], &proof[1..])
    };
    let mut fn_idx = old_size - 1;
    let mut sn = new_size - 1;
    while fn_idx % 2 == 1 {
        fn_idx >>= 1;
        sn >>= 1;
    }
    let mut it = proof_slice.iter();
    while sn > 0 {
        let Some(c) = it.next() else {
            return false;
        };
        if fn_idx % 2 == 1 || fn_idx == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_idx % 2 == 0 {
                while fn_idx % 2 == 0 && fn_idx != 0 {
                    fn_idx >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }
    it.next().is_none() && &fr == old_root && &sr == new_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; HASH_LEN]> {
        (0..n)
            .map(|i| leaf_hash(format!("event-{i}").as_bytes()))
            .collect()
    }

    fn tree_of(n: usize) -> MerkleTree {
        let mut t = MerkleTree::new();
        for l in leaves(n) {
            t.append(l);
        }
        t
    }

    #[test]
    fn empty_tree_has_no_root() {
        assert!(MerkleTree::new().root().is_none());
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let mut t = MerkleTree::new();
        let l = leaf_hash(b"only");
        t.append(l);
        assert_eq!(t.root().unwrap(), l);
    }

    #[test]
    fn inclusion_proof_is_verifiable_for_each_leaf() {
        for n in 1..=17 {
            let t = tree_of(n);
            let root = t.root().unwrap();
            for i in 0..n {
                let p = t.inclusion_proof(i).unwrap();
                assert!(
                    verify_inclusion(t.leaf(i).unwrap(), i, n, &root, &p),
                    "incl proof for ({i}, {n}) must verify"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_is_verifiable_for_every_prefix() {
        for n in 1..=17 {
            let t = tree_of(n);
            let new_root = t.root().unwrap();
            for m in 1..=n {
                let t_old = tree_of(m);
                let old_root = t_old.root().unwrap();
                let p = t.consistency_proof(m, n).unwrap();
                assert!(
                    verify_consistency(m, n, &old_root, &new_root, &p),
                    "cons proof ({m},{n}) must verify"
                );
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_root() {
        let t = tree_of(8);
        let p = t.inclusion_proof(3).unwrap();
        let wrong = [0u8; HASH_LEN];
        assert!(!verify_inclusion(t.leaf(3).unwrap(), 3, 8, &wrong, &p));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let t = tree_of(8);
        let p = t.inclusion_proof(3).unwrap();
        let wrong_leaf = leaf_hash(b"forged");
        assert!(!verify_inclusion(&wrong_leaf, 3, 8, &t.root().unwrap(), &p));
    }

    #[test]
    fn consistency_proof_rejects_diverging_history() {
        // Build two trees of size 5 with one differing leaf, then try to use
        // tree A's consistency proof to claim tree B is a prefix extension.
        let t_a = tree_of(5);
        let mut t_b = MerkleTree::new();
        for (i, l) in leaves(5).into_iter().enumerate() {
            if i == 2 {
                t_b.append(leaf_hash(b"tampered"));
            } else {
                t_b.append(l);
            }
        }
        let p = t_a.consistency_proof(3, 5).unwrap();
        let old_root = tree_of(3).root().unwrap();
        // Verifying against the *tampered* new root must fail.
        assert!(!verify_consistency(
            3,
            5,
            &old_root,
            &t_b.root().unwrap(),
            &p
        ));
    }

    #[test]
    fn consistency_at_equal_sizes_requires_empty_proof_and_equal_root() {
        let t = tree_of(7);
        let r = t.root().unwrap();
        assert!(verify_consistency(7, 7, &r, &r, &[]));
        assert!(!verify_consistency(7, 7, &r, &r, &[r]));
    }
}
