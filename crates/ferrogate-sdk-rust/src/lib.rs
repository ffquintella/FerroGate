//! `ferrogate-sdk-rust` — the Rust integration SDK for [FerroGate].
//!
//! This crate is a **facade**. It contains no logic of its own: it re-exports
//! the relying-party / verifier-side crates of the FerroGate workspace under
//! short, stable module names so a third party can depend on one versioned
//! crate instead of tracking six. The server (`cmis`), the host agent (`mia`),
//! and the operational crates are intentionally not part of the surface.
//!
//! | Module | Crate | Feature | Purpose |
//! |--------|-------|---------|---------|
//! | [`crypto`]       | `ferro-crypto`       | *(always)* | Hybrid post-quantum primitives: composite Ed25519 + ML-DSA-65 signatures, `X25519MLKEM768` rustls provider, SPKI pinning. |
//! | [`svid_verify`]  | `ferro-svid-verify`  | `verify`   | Reference verifier for composite-signed JWS SVIDs. |
//! | [`child_verify`] | `ferro-child-verify` | `verify`   | Reference verifier for DPoP-bound composite-signed child tokens. |
//! | [`svid`]         | `ferro-svid`         | `svid`     | SVID envelope, claims schema, SPIFFE-ID derivation, JWKS, lifecycle policy. |
//! | [`attest`]       | `ferro-attest`       | `attest`   | TPM 2.0 quote verification, RIM matching, host-key profile. |
//! | [`proto`]        | `ferro-proto`        | `proto`    | Generated gRPC stubs for the `MachineIdentity` service. |
//!
//! # Features
//!
//! `default = ["verify"]` — the common case is a third-party API that receives
//! a FerroGate child token and must decide whether to honour it.
//!
//! `proto` is **off by default**: `ferro-proto` compiles `.proto` files in a
//! build script, so enabling it requires `protoc` (the `protobuf-compiler`
//! package) on `PATH`. `full` turns everything on.
//!
//! ```toml
//! [dependencies]
//! # Verify child tokens presented to your API (the default).
//! ferrogate-sdk-rust = { version = "0.21", registry = "ferrogate" }
//!
//! # Or: everything, including the gRPC stubs (needs protoc).
//! ferrogate-sdk-rust = { version = "0.21", registry = "ferrogate", features = ["full"] }
//! ```
//!
//! The crate is published to a private Cargo registry rather than crates.io.
//! See the crate `README.md` for the `.cargo/config.toml` stanza that defines
//! the `ferrogate` registry.
//!
//! # Versioning
//!
//! Every crate in the SDK is released in lockstep with the FerroGate workspace
//! version, and the facade pins its re-exports to the exact matching version.
//! [`VERSION`] is that version at compile time.
//!
//! [FerroGate]: https://github.com/ffquintella/FerroGate

#![forbid(unsafe_code)]

/// The FerroGate workspace version this SDK was built from.
///
/// Every re-exported crate is pinned to exactly this version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Hybrid post-quantum cryptographic primitives (`ferro-crypto`).
///
/// The composite Ed25519 + ML-DSA-65 signature primitive that every FerroGate
/// signature is built from, plus the `X25519MLKEM768` rustls provider and the
/// SPKI-pinning certificate verifier used on the transport.
pub use ferro_crypto as crypto;

/// Reference verifier for composite-signed JWS SVIDs (`ferro-svid-verify`).
///
/// Requires the `verify` feature (on by default).
#[cfg(feature = "verify")]
pub use ferro_svid_verify as svid_verify;

/// Reference verifier for DPoP-bound child tokens (`ferro-child-verify`).
///
/// This is the crate a third-party API uses to validate a token a FerroGate
/// host handed to one of its applications. Requires the `verify` feature (on
/// by default).
#[cfg(feature = "verify")]
pub use ferro_child_verify as child_verify;

/// SVID envelope, claims, SPIFFE derivation, JWKS, and lifecycle (`ferro-svid`).
///
/// Requires the `svid` feature.
#[cfg(feature = "svid")]
pub use ferro_svid as svid;

/// TPM 2.0 attestation verification (`ferro-attest`).
///
/// Requires the `attest` feature.
#[cfg(feature = "attest")]
pub use ferro_attest as attest;

/// Generated gRPC stubs for the `MachineIdentity` service (`ferro-proto`).
///
/// Requires the `proto` feature, which adds a `protoc` build dependency.
#[cfg(feature = "proto")]
pub use ferro_proto as proto;

#[cfg(test)]
mod tests {
    /// The facade must report the same version its re-exports are pinned to.
    #[test]
    fn version_is_the_package_version() {
        assert_eq!(super::VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!super::VERSION.is_empty());
    }

    /// Smoke-test that the default feature set actually re-exports the
    /// verifiers — a broken `#[cfg]` would otherwise fail silently.
    #[cfg(feature = "verify")]
    #[test]
    fn verify_surface_is_reachable() {
        assert_eq!(super::svid_verify::SVID_TYP, "ferrogate-svid+jwt");
        assert_eq!(
            super::svid_verify::SVID_ALG,
            super::crypto::composite::COMPOSITE_JOSE_ALG
        );
    }
}
