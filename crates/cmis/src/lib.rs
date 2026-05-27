//! `cmis` — Central Machine Identity Service library.
//!
//! Hosts the `MachineIdentity` gRPC service (feature F04): the four-phase
//! attestation handshake, SVID issuance, in-window `Rotate`, and `JWKS`. The
//! daemon binary (`src/main.rs`) is a thin wrapper that assembles
//! [`state::CmisState`] and serves [`service::MachineIdentitySvc`].
//!
//! TEE residency, Raft replication, and the audit log are layered on in later
//! milestones; the seams (the credential maker, the issued-SVID store) are
//! called out where they will be replaced.

#![forbid(unsafe_code)]

pub mod credential;
pub mod pcr;
pub mod service;
pub mod state;

pub use credential::{CredentialError, CredentialMaker, WrappedCredential};
pub use service::MachineIdentitySvc;
pub use state::{CmisConfig, CmisState, IssuedRecord};
