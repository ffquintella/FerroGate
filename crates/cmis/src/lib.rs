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

pub mod cluster_store;
pub mod credential;
pub mod crl_publisher;
pub mod fleet_manifest;
pub mod fleet_watcher;
pub mod pcr;
pub mod rim_watcher;
pub mod service;
pub mod state;

pub use credential::{CredentialError, CredentialMaker, WrappedCredential};
pub use fleet_manifest::{
    EnrolledHosts, EnrollmentDecision, FleetManifest, FleetManifestLoader, FleetStore,
    SignedFleetManifest,
};
pub use service::MachineIdentitySvc;
pub use state::{CmisConfig, CmisState, IssuedRecord};
