# ferrogate-sdk-rust

The Rust integration SDK for [FerroGate](https://github.com/ffquintella/FerroGate).

One versioned crate that re-exports the relying-party / verifier-side crates a
third party needs: verify FerroGate SVIDs and DPoP-bound child tokens, verify
TPM 2.0 attestations, and speak the `MachineIdentity` gRPC protocol. The server
(`cmis`), the host agent (`mia`), and the operational crates are not part of the
surface.

## Install

The SDK is published to a private Cargo registry, not crates.io. Define the
registry once in `.cargo/config.toml` (index URL only — never a token):

```toml
[registries.ferrogate]
index = "sparse+https://cargo.cloudsmith.io/uox/ferrogate/"
credential-provider = "cargo:token"
```

Supply the token out of band, via the environment:

```sh
export CARGO_REGISTRIES_FERROGATE_TOKEN="Token $CLOUDSMITH_API_KEY"
```

Then depend on it:

```toml
[dependencies]
ferrogate-sdk-rust = { version = "0.21", registry = "ferrogate" }
```

## Features

| Feature | Module | Crate | Purpose |
|---------|--------|-------|---------|
| *(always)* | `crypto`       | `ferro-crypto`       | Composite Ed25519 + ML-DSA-65 signatures, `X25519MLKEM768` rustls provider, SPKI pinning. |
| `verify` (default) | `svid_verify`  | `ferro-svid-verify`  | Reference verifier for composite-signed JWS SVIDs. |
| `verify` (default) | `child_verify` | `ferro-child-verify` | Reference verifier for DPoP-bound child tokens. |
| `svid`   | `svid`   | `ferro-svid`   | SVID envelope, claims, SPIFFE derivation, JWKS, lifecycle. |
| `attest` | `attest` | `ferro-attest` | TPM 2.0 quote verification, RIM matching, host-key profile. |
| `proto`  | `proto`  | `ferro-proto`  | Generated `MachineIdentity` gRPC stubs. |
| `full`   | *(all)*  | | Everything above. |

`proto` is off by default because `ferro-proto` compiles `.proto` files in a
build script, which requires `protoc` (`protobuf-compiler`) on `PATH`.

## Use

```rust,ignore
use ferrogate_sdk_rust::child_verify;

// Reject anything that is not a live, correctly signed, DPoP-bound token.
let claims = child_verify::verify_bound(token, &proof, &request, &jwks, now)?;
```

Every crate in the SDK is released in lockstep with the FerroGate workspace
version; the facade pins its re-exports to the exact matching version.

Licensed under Apache-2.0.
