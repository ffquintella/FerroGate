//! Cluster orchestration: per-replica share holders and threshold key
//! reconstruction.
//!
//! Each CMIS replica owns one Shamir share, sealed against its own enclave
//! measurement. Reconstruction proceeds in four stages:
//!
//! 1. Quorum: collect at least [`crate::SHAMIR_THRESHOLD`] peer responses.
//! 2. Peer attestation: each remote share arrives only after a successful
//!    [`crate::psk`] handshake; the share itself travels under the derived
//!    PSK as an AEAD payload. The verified peer measurement is checked
//!    against the cluster allowlist before the share is admitted to the
//!    reconstruction set.
//! 3. Combine: [`crate::shamir::combine`] interpolates the 32-byte secret.
//! 4. Wrap: the result is moved into a [`crate::ProtectedKey`] — mlocked,
//!    zeroize-on-drop.
//!
//! Graceful degradation:
//!
//! - Loss of **one** share — the cluster still reconstructs (any 3 of the
//!   remaining 4 work). See [`Reconstructor::reconstruct`].
//! - Loss of **three** shares — fewer than the threshold survive. The
//!   reconstructor returns [`crate::TeeError::NotEnoughShares`] and CMIS
//!   refuses to issue. Pre-existing in-memory issuance keys (held in
//!   `ProtectedKey`s) remain usable until the next rotation.

use zeroize::Zeroize as _;

use crate::error::TeeError;
use crate::key::ProtectedKey;
use crate::shamir::{combine, Share};

/// One replica's stake in the threshold key: which share index it owns and
/// the sealed envelope holding its share.
#[derive(Debug, Clone)]
pub struct ShareHolder {
    /// Shamir share index (`1..=255`).
    pub index: u8,
    /// The share itself. In production this is unsealed only inside the
    /// owning enclave (via [`crate::seal::unseal`]) and exchanged with
    /// peers under a [`crate::psk`] session.
    pub share: Share,
}

impl ShareHolder {
    /// Build a holder from a raw share.
    #[must_use]
    pub fn new(share: Share) -> Self {
        Self {
            index: share.x,
            share,
        }
    }
}

/// Threshold reconstruction driver. Stateless; constructed per
/// reconstruction event.
pub struct Reconstructor {
    threshold: usize,
}

impl Reconstructor {
    /// Build a reconstructor with the configured threshold (use
    /// [`crate::SHAMIR_THRESHOLD`] for the standard 3-of-5).
    #[must_use]
    pub const fn new(threshold: usize) -> Self {
        Self { threshold }
    }

    /// Try to reconstruct the secret key from the given share set.
    ///
    /// Returns [`TeeError::NotEnoughShares`] if fewer than `threshold`
    /// holders contributed; the cluster is expected to surface this as a
    /// graceful issuance halt rather than a panic.
    pub fn reconstruct<const N: usize>(
        &self,
        holders: &[ShareHolder],
    ) -> Result<ProtectedKey<N>, TeeError> {
        if holders.len() < self.threshold {
            return Err(TeeError::NotEnoughShares {
                have: holders.len(),
                need: self.threshold,
            });
        }
        // Use exactly `threshold` shares — supplying more is wasteful and
        // would add additional reconstruction paths; if a caller wants
        // belt-and-braces verification, they can run multiple subsets and
        // compare.
        let chosen: Vec<Share> = holders
            .iter()
            .take(self.threshold)
            .map(|h| h.share.clone())
            .collect();
        let secret = combine(&chosen)?;
        if secret.len() != N {
            return Err(TeeError::ShareLength);
        }
        let mut buf = [0u8; N];
        buf.copy_from_slice(&secret);
        // The intermediate `Vec<u8>` from `combine` cannot itself be
        // page-locked; we copy into the locked buffer and zeroize the
        // intermediate.
        let mut secret_z = secret;
        secret_z.zeroize();
        ProtectedKey::new(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::split;
    use crate::{SHAMIR_SHARES, SHAMIR_THRESHOLD};

    fn fresh_holders(secret: &[u8]) -> Vec<ShareHolder> {
        let set = split(secret, SHAMIR_THRESHOLD, SHAMIR_SHARES).unwrap();
        set.shares.into_iter().map(ShareHolder::new).collect()
    }

    #[test]
    fn three_of_five_reconstructs_into_protected_key() {
        let secret = [9u8; 32];
        let holders = fresh_holders(&secret);
        let r = Reconstructor::new(SHAMIR_THRESHOLD);
        let key = r
            .reconstruct::<32>(&holders[..3])
            .expect("threshold satisfied");
        assert_eq!(key.expose(), &secret);
    }

    #[test]
    fn losing_one_share_still_reconstructs() {
        let secret = [0x55u8; 32];
        let mut holders = fresh_holders(&secret);
        holders.remove(2); // simulate one replica down
        assert_eq!(holders.len(), 4);
        let r = Reconstructor::new(SHAMIR_THRESHOLD);
        let key = r.reconstruct::<32>(&holders).unwrap();
        assert_eq!(key.expose(), &secret);
    }

    #[test]
    fn losing_three_shares_halts_gracefully() {
        let secret = [0xaa; 32];
        let mut holders = fresh_holders(&secret);
        holders.truncate(2); // simulate three replicas down
        let r = Reconstructor::new(SHAMIR_THRESHOLD);
        match r.reconstruct::<32>(&holders) {
            Err(TeeError::NotEnoughShares { have, need }) => {
                assert_eq!(have, 2);
                assert_eq!(need, 3);
            }
            other => panic!("expected NotEnoughShares, got {other:?}"),
        }
    }

    #[test]
    fn wrong_length_secret_is_rejected() {
        // Share a 32-byte secret but ask for a 48-byte reconstruction.
        let secret = [9u8; 32];
        let holders = fresh_holders(&secret);
        let r = Reconstructor::new(SHAMIR_THRESHOLD);
        let err = r.reconstruct::<48>(&holders[..3]).unwrap_err();
        assert!(matches!(err, TeeError::ShareLength));
    }
}
