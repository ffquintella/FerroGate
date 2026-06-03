//! `ferro-ceremony` — air-gapped root-key ceremony primitives (feature F14).
//!
//! FerroGate's composite issuance root is rotated annually in a Faraday-shielded
//! ceremony by a 3-of-5 operator quorum. This crate holds the *offline* building
//! blocks the ceremony tool ([`tools/offline-signer`]) wires together; none of
//! it touches the network, and every artefact it emits is a plain, auditable
//! JSON document.
//!
//! The pieces:
//!
//! - [`media`] — **sealed transport media**: one Shamir share of the 32-byte
//!   root seed wrapped in a tamper-evident, integrity-tagged JSON envelope, one
//!   per share holder. Reuses [`ferro_tee::shamir`] for the 3-of-5 split.
//! - [`crosssign`] — the **cross-signing** flow: the outgoing root signs the
//!   incoming root's public key and the incoming root signs the outgoing one,
//!   producing a single bundle that validates in **both** directions for the
//!   90-day window.
//! - [`minutes`] — **ceremony minutes** signed by every participant, ready to be
//!   anchored to a WORM medium.
//! - [`destruction`] — end-of-window **destruction** of the old shares with a
//!   mandatory **post-zeroization read-back** proving the media is irrecoverable.
//!
//! [`tools/offline-signer`]: ../../../tools/offline-signer/index.html

#![forbid(unsafe_code)]

pub mod crosssign;
pub mod destruction;
pub mod media;
pub mod minutes;

pub use crosssign::{CrossSignBundle, CrossSignDirection};
pub use destruction::{destroy_media, verify_destruction, DestructionRecord};
pub use media::{SealedShare, SealedShareSet};
pub use minutes::{
    ArtefactDigest, CeremonyKind, CeremonyMinutes, Participant, ParticipantSignature, SignedMinutes,
};

/// Length of the root master seed in bytes — the secret that is Shamir-split.
/// The composite root keypair is derived from it via
/// [`ferro_crypto::composite::CompositeSecretKey::from_seed`].
pub const ROOT_SEED_LEN: usize = 32;

/// Failure modes shared across the ceremony primitives.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// A JSON document failed to (de)serialize.
    #[error("serialization: {0}")]
    Serde(String),
    /// A field carried a value of the wrong length or shape.
    #[error("malformed {what}: {detail}")]
    Malformed {
        /// Which field/artefact.
        what: &'static str,
        /// Human-readable detail.
        detail: String,
    },
    /// An integrity tag did not match the recomputed value — the media or
    /// document has been altered.
    #[error("integrity check failed for {0}: tag mismatch")]
    Integrity(&'static str),
    /// A composite signature did not verify.
    #[error("signature verification failed: {0}")]
    Signature(String),
    /// The Shamir layer rejected the share parameters or set.
    #[error("shamir: {0}")]
    Shamir(String),
    /// A post-zeroization read-back still found recoverable share material.
    #[error("destruction verification failed: {0}")]
    NotDestroyed(String),
    /// A filesystem operation failed.
    #[error("io: {0}")]
    Io(String),
}

/// Convenience result alias for ceremony operations.
pub type Result<T> = std::result::Result<T, CeremonyError>;
