//! `ferro-attest` — TPM 2.0 quote verification and RIM matching (feature F02).
//!
//! This is the CMIS-side verifier: given the evidence a MIA gathers from its
//! TPM (EK certificate, AIK public area, PCR quote and signature, reported PCR
//! values), [`TpmQuoteVerifier::verify_quote`] runs the fail-closed, ten-step
//! algorithm from `docs/tpm.md` and `docs/protocol.md` phase 2:
//!
//! 1. The EK certificate chains to a trusted vendor root ([`vendor`]).
//! 2. The AIK public area satisfies the required attribute mask ([`aik`]).
//! 3. `magic == TPM_GENERATED_VALUE` and `type == TPM_ST_ATTEST_QUOTE`.
//! 4. `extraData` equals the issued nonce.
//! 5. The ECDSA-P256 signature over the quote body verifies under the AIK.
//! 6. The recomputed aggregate PCR digest (SHA-384) equals the quote's.
//! 7. The aggregate digest is in the active RIM allowlist ([`rim`]); the
//!    resulting `policy_id` is recorded.
//!
//! Phase 3 (credential activation) compares the MIA-returned secret against the
//! wrapped value in constant time via [`verify::credential_secret_matches`].
//!
//! Every rejection carries a precise [`verify::RejectReason`] for the audit log
//! while the peer sees only a generic denial.

#![forbid(unsafe_code)]

pub mod aik;
pub mod rim;
pub mod tpm;
pub mod vendor;
pub mod verify;

pub use rim::{PolicyId, RimStore};
pub use vendor::{ChainError, Vendor, VendorMatch, VendorTrustStore};
pub use verify::{
    credential_secret_matches, verify_aik_signature, PcrSet, QuoteVerification, RejectReason,
    TpmQuoteVerifier, VerifiedQuote,
};

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-attest";
