//! The local helper API (feature F08).
//!
//! Vetted applications on the host talk to the MIA over a local IPC channel
//! (Unix Domain Socket on Linux/macOS; a Named Pipe on Windows — not yet
//! implemented) and receive short-lived, audience-bound, DPoP-bound child
//! tokens. The caller's identity is established from kernel-attested sources
//! rather than anything the caller claims. See `docs/helper-api.md` and
//! `docs/features/F08-helper-api.md`.
//!
//! Module layout:
//!
//! - [`proto`] — CBOR request/response types and length-delimited framing.
//! - [`auth`] — caller authentication (`SO_PEERCRED` + IMA cross-check).
//! - [`allowlist`] — the signed, fail-closed caller allowlist.
//! - [`token`] — the DPoP-bound child-token minter (feature F09).
//! - [`server`] — the UDS listener that wires them together (Unix only).

pub mod allowlist;
pub mod auth;
pub mod proto;
pub mod token;

#[cfg(unix)]
pub mod server;

pub use allowlist::{Allowlist, AllowlistError};
pub use auth::{AuthError, CallerAuth, CallerIdentity, PeerCred};
pub use proto::{ChildToken, ErrorCode, HelperReq, HelperResp};
pub use token::{ChildTokenMinter, MintedToken, MinterConfig, MAX_CHILD_TTL_SECS};

#[cfg(unix)]
pub use server::{system_clock, Clock, HelperServer, HelperServerConfig, ServerError};
