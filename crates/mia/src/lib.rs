//! `mia` — Machine Identity Agent library surface.
//!
//! The daemon binary (`src/main.rs`) is a thin wrapper; the reusable pieces
//! live here so they can be integration-tested. Today that is the TPM 2.0
//! attestation engine (feature F02).
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`).

#![forbid(unsafe_code)]

/// TPM 2.0 attestation glue (feature F02). Linux-only: needs a TSS2 stack.
#[cfg(target_os = "linux")]
pub mod tpm;
