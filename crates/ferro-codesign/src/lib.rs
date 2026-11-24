//! `ferro-codesign` — trusted publishers (ADR-0006).
//!
//! A *trusted publisher* is a rule an administrator stores in CMIS: "a binary
//! whose code signature verifies, whose chain contains this CA, and whose leaf
//! certificate has this pin, is approved on every host".

//! Matching never trusts a display name: a rule matches only on SHA-256
//! digests of DER (the leaf, its key or its subject, and a CA in the chain).

//! Modules: [`model`] (the rule), [`facts`] (digests read from a chain or a
//! certificate file), [`matching`] (the pure decision) and [`verifier`] (the
//! [`SignatureVerifier`] trait and the platform verifier).

pub mod facts;
pub mod matching;
pub mod model;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
pub mod verifier;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub use facts::{
    cert_facts, certificate_der, subject_pin, CertFacts, FactsError, SignerFacts,
    MAX_CERTIFICATE_BYTES,
};
pub use matching::{match_publisher, Refusal};
pub use model::{PinKind, PublisherRule, SignatureKind};
pub use verifier::{
    platform_verifier, CallerTarget, SignatureVerifier, UnsupportedVerifier, VerifiedSignature,
    VerifyError,
};
