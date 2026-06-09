//! `mia` — Machine Identity Agent library surface.
//!
//! The daemon binary (`src/main.rs`) is a thin wrapper; the reusable pieces
//! live here so they can be integration-tested:
//!
//! - [`tpm`] — the TPM 2.0 attestation engine and PCR sealing (feature F02/F04,
//!   Linux-only).
//! - [`client`] — drives the four-phase `Attest` handshake against CMIS and
//!   recovers a freshly issued SVID plus its composite private key (F04).
//! - [`scheduler`] — computes when to rotate a live SVID (60% of TTL, jittered).
//! - [`helper`] — the local helper API: a UDS server that mints DPoP-bound
//!   child tokens for vetted local callers (features F08/F09).
//! - [`hardening`] — the startup defence-in-depth profile (feature F12): the
//!   fail-closed IMA check and the policy that drives the `ferro-harden`
//!   syscall wrappers (mlockall, seccomp, privilege drop).
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`);
//! every privileged syscall lives in the `ferro-harden` (Linux) and
//! `ferro-winauth` (Windows) FFI crates.

#![forbid(unsafe_code)]

pub mod audit_client;
pub mod client;

/// The TOML configuration file and its merge with the environment.
pub mod config;

pub mod hardening;
pub mod helper;
pub mod scheduler;

/// Interactive `mia setup` configuration wizard (rich-terminal prompts).
pub mod setup;

/// TPM 2.0 attestation glue and PCR sealing (features F02/F04). Linux-only:
/// needs a TSS2 stack.
#[cfg(target_os = "linux")]
pub mod tpm;

/// PCR-bound sealing of the SVID cache (feature F04). Linux-only.
#[cfg(target_os = "linux")]
pub mod seal;
