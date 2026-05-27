//! `ferro-proto` — generated gRPC stubs for the FerroGate `MachineIdentity`
//! service (feature F04).
//!
//! The wire surface is defined in `proto/machine_identity.proto` and compiled
//! by `build.rs` into tonic client and server stubs, re-exported here under
//! [`v1`]. See `docs/cmis.md` §"gRPC surface" and `docs/protocol.md`.

#![forbid(unsafe_code)]

/// Generated `ferrogate.v1` protobuf types and tonic service stubs.
///
/// Lints are relaxed inside this module because the contents are machine
/// generated and not under our style control.
pub mod v1 {
    #![allow(
        clippy::all,
        clippy::pedantic,
        clippy::nursery,
        missing_docs,
        unreachable_pub,
        rust_2018_idioms
    )]
    tonic::include_proto!("ferrogate.v1");
}

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-proto";
