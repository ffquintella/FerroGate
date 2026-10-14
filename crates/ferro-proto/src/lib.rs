//! `ferro-proto` — generated gRPC stubs for the FerroGate `MachineIdentity`
//! service (feature F04) and the administrator `Admin` service (feature F20).
//!
//! The wire surface is defined in `proto/machine_identity.proto` and
//! `proto/admin.proto` and compiled by `build.rs` into tonic client and server
//! stubs, re-exported here under [`v1`] and [`admin_v1`]. See `docs/cmis.md`
//! §"gRPC surface", `docs/protocol.md` and
//! `docs/features/F20-admin-authentication.md`.

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

/// Generated `ferrogate.admin.v1` protobuf types and tonic service stubs for
/// the administrator surface (feature F20).
///
/// Lints are relaxed inside this module because the contents are machine
/// generated and not under our style control.
pub mod admin_v1 {
    #![allow(
        clippy::all,
        clippy::pedantic,
        clippy::nursery,
        missing_docs,
        unreachable_pub,
        rust_2018_idioms
    )]
    tonic::include_proto!("ferrogate.admin.v1");
}

/// Encoded `google.protobuf.FileDescriptorSet` covering every FerroGate proto
/// file. CMIS decodes it in tests to prove that every RPC of every service has
/// an entry in its method access table (F20 §7, deny by default).
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("ferrogate_descriptor");

/// Crate identifier.
pub const CRATE_NAME: &str = "ferro-proto";
