//! `ferro-tee` — Trusted Execution Environment integration for FerroGate
//! (feature F06).
//!
//! CMIS runs **only** inside an attested TEE (AMD SEV-SNP or Intel TDX) and
//! its composite issuance key is **never** whole on disk. The key is
//! Shamir-split 3-of-5 over a finite field; each share is sealed against a
//! per-replica enclave measurement; reconstruction happens only transiently
//! in mlocked, zeroize-on-drop memory inside a peer-attested enclave.
//!
//! See `docs/features/F06-tee-threshold-keys.md` and `docs/cmis.md`
//! §"Issuance key handling".
//!
//! ## Module map
//!
//! - [`measurement`] — 48-byte SHA3-384 enclave measurements and the
//!   allowlist of approved CMIS images.
//! - [`attest`] — `Attestor` trait plus AMD SEV-SNP and Intel TDX report
//!   shapes; a `SoftwareAttestor` for unit tests provides the same wire
//!   surface as the hardware paths.
//! - [`shamir`] — Shamir's secret-sharing, byte-parallel over GF(2^8) (AES
//!   irreducible 0x11b). 32-byte secrets reconstruct from any threshold-many
//!   shares; below threshold reveals nothing.
//! - [`seal`] — measurement-bound sealing of a share envelope using ChaCha20
//!   -Poly1305 keyed via HKDF-SHA3-384 from the replica's sealing root.
//! - [`psk`] — ML-KEM-768 (FIPS 203) handshake that binds the peer's
//!   attestation report to the encapsulated shared secret and derives a 32-
//!   byte session PSK for share transport.
//! - [`key`] — `ProtectedKey`, a `Box<[u8; N]>` page-locked via `region` and
//!   zeroized on drop.
//! - [`cluster`] — orchestration: `ShareHolder` (a single replica's stake) and
//!   `Reconstructor` (3-of-5 → `ProtectedKey`), with graceful degradation
//!   when shares are missing.

#![forbid(unsafe_code)]

pub mod attest;
pub mod cluster;
pub mod error;
pub mod key;
pub mod measurement;
pub mod psk;
pub mod seal;
pub mod shamir;

pub use attest::{Attestor, AttestorKind, Report, SoftwareAttestor};
pub use cluster::{Reconstructor, ShareHolder};
pub use error::TeeError;
pub use key::ProtectedKey;
pub use measurement::{Allowlist, Measurement};
pub use shamir::{Share, ShareSet};

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-tee";

/// Threshold required to reconstruct the issuance key.
pub const SHAMIR_THRESHOLD: usize = 3;
/// Total number of shares produced at split.
pub const SHAMIR_SHARES: usize = 5;
