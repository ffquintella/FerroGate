//! Error type for `ferro-tee`.

/// Failure modes across the TEE module surface.
#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    /// Memory page-locking (`mlock` / `VirtualLock`) was refused by the
    /// kernel. CMIS refuses to start in this state: a non-locked key
    /// reconstruction buffer could be paged to disk.
    #[error("mlock failed: {0}")]
    Mlock(String),

    /// Attestation report signature did not verify against the configured
    /// vendor root.
    #[error("attestation report signature invalid")]
    BadReportSignature,

    /// Attestation report failed a structural / freshness check (wrong
    /// nonce, wrong vendor tag, wrong version field).
    #[error("attestation report malformed: {0}")]
    BadReport(&'static str),

    /// The measurement carried by an otherwise-valid attestation report is
    /// not on the approved CMIS image allowlist.
    #[error("measurement not in allowlist")]
    MeasurementNotAllowed,

    /// CBOR encode/decode failed on a wire envelope.
    #[error("codec: {0}")]
    Codec(String),

    /// AEAD sealing or unsealing failed (most often: ciphertext was sealed
    /// against a different measurement than the local replica's).
    #[error("seal/unseal failed")]
    Seal,

    /// The PSK handshake produced inconsistent transcripts on the two sides
    /// — a tamper or version-skew indicator.
    #[error("psk transcript mismatch")]
    PskTranscript,

    /// Threshold reconstruction was attempted with fewer than the required
    /// shares.
    #[error("not enough shares: have {have}, need {need}")]
    NotEnoughShares {
        /// Shares supplied.
        have: usize,
        /// Shares required (the configured threshold).
        need: usize,
    },

    /// Two supplied shares carry the same x-coordinate; reconstruction is
    /// undefined.
    #[error("duplicate share index {0}")]
    DuplicateShare(u8),

    /// A share index was outside the legal `1..=255` range.
    #[error("invalid share index {0}")]
    InvalidShareIndex(u8),

    /// Two supplied shares disagree on the secret length.
    #[error("share length mismatch")]
    ShareLength,

    /// An ML-KEM operation failed at the library boundary.
    #[error("ml-kem failure")]
    MlKem,
}
