//! Sealed transport media format for one Shamir share.
//!
//! The root master seed is split 3-of-5 (see [`ferro_tee::shamir`]); each share
//! is written to a distinct piece of tamper-evident physical media (a sealed
//! USB key per holder) inside a [`SealedShare`] JSON envelope. The envelope
//! carries an integrity **tag** — `SHA3-256` over the canonical field bytes — so
//! any later alteration of the share index, threshold, or share value is
//! detected on read-back ([`SealedShare::verify_integrity`]).
//!
//! ## What "sealed" means here
//!
//! Confidentiality of the root key rests on the **3-of-5 threshold** plus the
//! physical custody of each holder's media — fewer than three envelopes reveal
//! nothing about the seed. Measurement-bound *encryption* of shares against a
//! CMIS enclave is the online F06 path ([`ferro_tee::seal`]); this offline
//! envelope is the air-gapped transport and integrity wrapper, not an
//! encryption layer. The tag is tamper-evidence, not secrecy.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ferro_tee::shamir::{self, Share, ShareSet};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::{CeremonyError, Result, ROOT_SEED_LEN};

/// Magic string identifying the sealed-share media format.
pub const SEALED_SHARE_MAGIC: &str = "ferrogate-sealed-share";

/// Current sealed-share format version.
pub const SEALED_SHARE_VERSION: u32 = 1;

/// One Shamir share on its tamper-evident transport medium.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedShare {
    /// Format magic — always [`SEALED_SHARE_MAGIC`].
    pub format: String,
    /// Format version — [`SEALED_SHARE_VERSION`].
    pub version: u32,
    /// Key id of the root this share reconstructs (e.g. `root-2026`).
    pub root_kid: String,
    /// Reconstruction threshold (`t` of `n`).
    pub threshold: usize,
    /// Total number of shares minted (`n`).
    pub total: usize,
    /// This share's evaluation index `x` (`1..=255`, never `0`).
    pub index: u8,
    /// Human label of the operator holding this medium.
    pub holder: String,
    /// Unix-seconds time the share was sealed.
    pub created_at: i64,
    /// Base64 (standard) of the share's per-byte evaluation vector `y`.
    pub share: String,
    /// Lowercase-hex `SHA3-256` integrity tag over the canonical field bytes.
    pub tag: String,
}

impl SealedShare {
    /// Recompute the integrity tag over the canonical, length-prefixed encoding
    /// of every field except the tag itself.
    fn compute_tag(
        root_kid: &str,
        threshold: usize,
        total: usize,
        index: u8,
        holder: &str,
        created_at: i64,
        share_y: &[u8],
    ) -> String {
        let mut h = Sha3_256::new();
        let mut field = |bytes: &[u8]| {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        };
        field(SEALED_SHARE_MAGIC.as_bytes());
        field(&SEALED_SHARE_VERSION.to_be_bytes());
        field(root_kid.as_bytes());
        field(&(threshold as u64).to_be_bytes());
        field(&(total as u64).to_be_bytes());
        field(&[index]);
        field(holder.as_bytes());
        field(&created_at.to_be_bytes());
        field(share_y);
        hex::encode(h.finalize())
    }

    /// Wrap a single Shamir [`Share`] into a sealed envelope for `holder`.
    #[must_use]
    pub fn seal(
        root_kid: impl Into<String>,
        threshold: usize,
        total: usize,
        share: &Share,
        holder: impl Into<String>,
        created_at: i64,
    ) -> Self {
        let root_kid = root_kid.into();
        let holder = holder.into();
        let tag = Self::compute_tag(
            &root_kid, threshold, total, share.x, &holder, created_at, &share.y,
        );
        Self {
            format: SEALED_SHARE_MAGIC.to_string(),
            version: SEALED_SHARE_VERSION,
            root_kid,
            threshold,
            total,
            index: share.x,
            holder,
            created_at,
            share: STANDARD.encode(&share.y),
            tag,
        }
    }

    /// Verify the format magic, version, and integrity tag. A mismatch means the
    /// medium has been altered since it was sealed.
    pub fn verify_integrity(&self) -> Result<()> {
        if self.format != SEALED_SHARE_MAGIC {
            return Err(CeremonyError::Malformed {
                what: "sealed share",
                detail: format!("unexpected format {:?}", self.format),
            });
        }
        if self.version != SEALED_SHARE_VERSION {
            return Err(CeremonyError::Malformed {
                what: "sealed share",
                detail: format!("unsupported version {}", self.version),
            });
        }
        if self.index == 0 {
            return Err(CeremonyError::Malformed {
                what: "sealed share",
                detail: "share index 0 is the secret, not a share".to_string(),
            });
        }
        let y = self.share_bytes()?;
        let expected = Self::compute_tag(
            &self.root_kid,
            self.threshold,
            self.total,
            self.index,
            &self.holder,
            self.created_at,
            &y,
        );
        // Constant-time-ish: hex compare of fixed-length digests.
        if expected.as_bytes() != self.tag.as_bytes() {
            return Err(CeremonyError::Integrity("sealed share"));
        }
        Ok(())
    }

    /// Decode the share's `y` vector.
    fn share_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(self.share.as_bytes())
            .map_err(|e| CeremonyError::Malformed {
                what: "sealed share",
                detail: format!("share base64: {e}"),
            })
    }

    /// Reconstruct the [`Share`] this envelope carries, after checking integrity.
    pub fn to_share(&self) -> Result<Share> {
        self.verify_integrity()?;
        Ok(Share {
            x: self.index,
            y: self.share_bytes()?,
        })
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| CeremonyError::Serde(e.to_string()))
    }

    /// Parse from JSON (does **not** verify integrity — call
    /// [`verify_integrity`](Self::verify_integrity) after).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| CeremonyError::Serde(e.to_string()))
    }
}

/// A full set of sealed shares for one root, one per holder.
#[derive(Debug, Clone)]
pub struct SealedShareSet {
    /// The sealed envelopes.
    pub shares: Vec<SealedShare>,
}

impl SealedShareSet {
    /// Split `seed` 3-of-5 (or any `t`-of-`n`) and seal each share to its holder.
    ///
    /// `holders.len()` must equal the share count; each label rides along on its
    /// share's medium so the ceremony minutes can record who holds what.
    pub fn seal(
        root_kid: impl Into<String>,
        seed: &[u8; ROOT_SEED_LEN],
        threshold: usize,
        holders: &[String],
        created_at: i64,
    ) -> Result<Self> {
        let total = holders.len();
        let set: ShareSet = shamir::split(seed, threshold, total)
            .map_err(|e| CeremonyError::Shamir(e.to_string()))?;
        let root_kid = root_kid.into();
        let shares = set
            .shares
            .iter()
            .zip(holders)
            .map(|(share, holder)| {
                SealedShare::seal(
                    root_kid.clone(),
                    threshold,
                    total,
                    share,
                    holder,
                    created_at,
                )
            })
            .collect();
        Ok(Self { shares })
    }

    /// Reconstruct the root seed from `t` or more sealed shares.
    ///
    /// Every supplied envelope must pass its integrity check and agree on
    /// `root_kid`, `threshold`, and `total`; the reconstructed seed is returned
    /// in a [`Zeroizing`] buffer so it is wiped when the caller drops it.
    pub fn combine(shares: &[SealedShare]) -> Result<Zeroizing<[u8; ROOT_SEED_LEN]>> {
        let first = shares.first().ok_or_else(|| CeremonyError::Malformed {
            what: "sealed share set",
            detail: "no shares supplied".to_string(),
        })?;
        for s in shares {
            s.verify_integrity()?;
            if s.root_kid != first.root_kid
                || s.threshold != first.threshold
                || s.total != first.total
            {
                return Err(CeremonyError::Malformed {
                    what: "sealed share set",
                    detail: "shares are from different roots or parameter sets".to_string(),
                });
            }
        }
        if shares.len() < first.threshold {
            return Err(CeremonyError::Shamir(format!(
                "have {} shares, need {}",
                shares.len(),
                first.threshold
            )));
        }
        let raw: Vec<Share> = shares
            .iter()
            .map(SealedShare::to_share)
            .collect::<Result<_>>()?;
        let secret = shamir::combine(&raw).map_err(|e| CeremonyError::Shamir(e.to_string()))?;
        let arr: [u8; ROOT_SEED_LEN] =
            secret
                .try_into()
                .map_err(|v: Vec<u8>| CeremonyError::Malformed {
                    what: "reconstructed seed",
                    detail: format!("expected {ROOT_SEED_LEN} bytes, got {}", v.len()),
                })?;
        Ok(Zeroizing::new(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; ROOT_SEED_LEN] {
        let mut s = [0u8; ROOT_SEED_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap().wrapping_add(1);
        }
        s
    }

    fn holders() -> Vec<String> {
        (1..=5).map(|i| format!("op-{i}")).collect()
    }

    #[test]
    fn three_of_five_round_trips_through_sealed_media() {
        let set = SealedShareSet::seal("root-2026", &seed(), 3, &holders(), 1000).unwrap();
        assert_eq!(set.shares.len(), 5);
        // Any 3 reconstruct.
        let recovered = SealedShareSet::combine(&set.shares[..3]).unwrap();
        assert_eq!(*recovered, seed());
        // A different 3 also reconstruct.
        let recovered2 = SealedShareSet::combine(&set.shares[2..5]).unwrap();
        assert_eq!(*recovered2, seed());
    }

    #[test]
    fn two_shares_do_not_reconstruct() {
        let set = SealedShareSet::seal("root-2026", &seed(), 3, &holders(), 1000).unwrap();
        let err = SealedShareSet::combine(&set.shares[..2]).unwrap_err();
        assert!(matches!(err, CeremonyError::Shamir(_)));
    }

    #[test]
    fn json_round_trip_preserves_share() {
        let set = SealedShareSet::seal("root-2026", &seed(), 3, &holders(), 1000).unwrap();
        let json = set.shares[0].to_json().unwrap();
        let parsed = SealedShare::from_json(&json).unwrap();
        assert_eq!(parsed, set.shares[0]);
        parsed.verify_integrity().unwrap();
    }

    #[test]
    fn tampering_with_any_field_breaks_the_tag() {
        let set = SealedShareSet::seal("root-2026", &seed(), 3, &holders(), 1000).unwrap();
        let mut tampered = set.shares[0].clone();
        tampered.holder = "attacker".to_string();
        assert!(matches!(
            tampered.verify_integrity(),
            Err(CeremonyError::Integrity(_))
        ));

        let mut tampered = set.shares[0].clone();
        tampered.index = tampered.index.wrapping_add(1);
        assert!(tampered.verify_integrity().is_err());
    }

    #[test]
    fn combine_rejects_mixed_roots() {
        let a = SealedShareSet::seal("root-a", &seed(), 3, &holders(), 1000).unwrap();
        let b = SealedShareSet::seal("root-b", &seed(), 3, &holders(), 1000).unwrap();
        let mixed = vec![
            a.shares[0].clone(),
            a.shares[1].clone(),
            b.shares[2].clone(),
        ];
        assert!(SealedShareSet::combine(&mixed).is_err());
    }
}
