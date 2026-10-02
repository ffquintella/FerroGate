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
//! - [`credstore`] — machine-bound at-rest storage for the host's X.509-SVID
//!   (features F04/F17): the certificate and its private key sealed under a
//!   TPM- or fingerprint-derived key that only opens on this host.
//! - [`hardening`] — the startup defence-in-depth profile (feature F12): the
//!   fail-closed IMA check and the policy that drives the `ferro-harden`
//!   syscall wrappers (mlockall, seccomp, privilege drop).
//! - [`status`], [`status_server`], [`logbuf`], [`status_cli`] — the
//!   read-only status endpoint the `mia-tray` companion and `mia status` read
//!   (feature F18); its wire types live in the `mia-status-proto` crate.
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`);
//! every privileged syscall lives in the `ferro-harden` (Linux) and
//! `ferro-winauth` (Windows) FFI crates.

#![forbid(unsafe_code)]

pub mod audit_client;
pub mod client;

/// The TOML configuration file and its merge with the environment.
pub mod config;

/// CMIS endpoint discovery (static or SRV), best-first selection, and fail-over.
pub mod endpoint;

pub mod hardening;
pub mod helper;
pub mod scheduler;

/// `mia machine-id` — print this host's fingerprint-derived machine identity.
pub mod machine_id;

/// `mia x509-svid` — inspect the machine-bound X.509-SVID store.
pub mod x509_svid;

/// `mia resync-allowlist` on-demand allowlist re-fetch.
pub mod resync;

/// `mia test` connectivity and token-issuance self-test.
pub mod selftest;

/// Interactive `mia setup` configuration wizard (rich-terminal prompts).
pub mod setup;

/// Non-interactive `mia setup --check / --apply / --dump` (feature F18).
pub mod setup_apply;

/// Per-environment status model: what the status endpoint reports (F18).
pub mod status;

/// The status endpoint listener (UDS / named pipe) and request handling (F18).
pub mod status_server;

/// `mia status` — read the status endpoint from the command line (F18).
pub mod status_cli;

/// Redacting in-memory ring buffer of the daemon's log records (F18).
pub mod logbuf;

// The status endpoint promises the helper protocol's framing bound; keep the
// two constants from drifting apart.
const _: () = assert!(mia_status_proto::MAX_FRAME_LEN == helper::proto::MAX_FRAME_LEN);

/// TPM 2.0 attestation glue and PCR sealing (features F02/F04). Linux-only:
/// needs a TSS2 stack.
#[cfg(target_os = "linux")]
pub mod tpm;

/// PCR-bound sealing of the SVID cache (feature F04). Linux-only.
#[cfg(target_os = "linux")]
pub mod seal;

/// Machine-bound storage for the host's X.509-SVID (features F04/F17):
/// TPM-sealed where there is a TPM, machine-key sealed everywhere else.
pub mod credstore;

/// In-process software **virtual TPM** for TPM-less dev/test hosts (macOS,
/// Windows, CI). INSECURE — never for production. Behind the off-by-default
/// `virtual-tpm` cargo feature; cross-platform (no TSS2 stack needed).
#[cfg(feature = "virtual-tpm")]
pub mod virtual_tpm;
