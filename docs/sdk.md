# Integration SDK — `ferrogate-sdk-rust`

`ferrogate-sdk-rust` is the crate a third party depends on to integrate with
FerroGate: verify SVIDs and DPoP-bound child tokens, verify TPM 2.0
attestations, and speak the `MachineIdentity` gRPC protocol.

It is a **facade**. It contains no logic of its own — it re-exports the
relying-party / verifier-side crates of the workspace under short module names
so integrators track one version instead of eight. The server (`cmis`), the host
agent (`mia`), and the operational crates (`ferro-raft`, `ferro-ceremony`,
`ferro-harden`, `ferro-winauth`, `ferro-tee`, `ferro-audit`, `ferro-transport`,
`ferrogate-cli`) are deliberately outside the surface.

## Contents

| Feature | Module | Crate | Purpose |
|---------|--------|-------|---------|
| *(always)* | `crypto` | [`ferro-crypto`](crypto.md) | Composite Ed25519 + ML-DSA-65 signatures, `X25519MLKEM768` rustls provider, SPKI pinning. |
| `verify` *(default)* | `svid_verify` | `ferro-svid-verify` | Reference verifier for composite-signed JWS SVIDs ([F04](features/F04-svid-lifecycle.md)). |
| `verify` *(default)* | `child_verify` | `ferro-child-verify` | Reference verifier for DPoP-bound child tokens ([F09](features/F09-dpop-child-tokens.md)). |
| `svid` | `svid` | `ferro-svid` | SVID envelope, claims, SPIFFE derivation, JWKS, lifecycle. |
| `attest` | `attest` | `ferro-attest` | TPM 2.0 quote verification, RIM matching ([F02](features/F02-tpm-attestation.md), [F10](features/F10-rim-pcr-policy.md)). |
| `proto` | `proto` | `ferro-proto` | Generated `MachineIdentity` gRPC stubs. |
| `full` | *(all)* | | Everything above. |

`ferro-sep` and `ferro-machineid` are also published: they are not part of the
documented surface, but `ferro-attest` depends on them for the TPM-less host-key
profile ([F15](features/README.md)).

`proto` is off by default because `ferro-proto` compiles `.proto` files in a
build script, which requires `protoc` (`protobuf-compiler`) on `PATH`. A
consumer that only validates tokens should not inherit that build dependency.

## Consuming it

The SDK is published to a private Cargo registry (Cloudsmith,
`uox/ferrogate`), not to crates.io. Define the registry once, in the consuming
project's `.cargo/config.toml`:

```toml
[registries.ferrogate]
index = "sparse+https://cargo.cloudsmith.io/uox/ferrogate/"
credential-provider = "cargo:token"
```

The **index URL is not a secret and belongs in version control; the token is and
does not.** Supply it through the environment, in Cloudsmith's required
`Token <api-key>` form:

```sh
read -rs CLOUDSMITH_API_KEY
export CARGO_REGISTRIES_FERROGATE_TOKEN="Token $CLOUDSMITH_API_KEY"
```

Then:

```toml
[dependencies]
ferrogate-sdk-rust = { version = "0.21", registry = "ferrogate" }
```

### Or: the vendored tarball

`make pkg-sdk` produces `target/sdk/ferrogate-sdk-rust-<version>.tgz`, a
self-contained Cargo workspace with the same crates wired by `path`. It builds
offline with no registry configured, and is attached to every GitHub Release.
Use it for air-gapped or vendored builds; prefer the registry otherwise.

## Publishing it

Everything is driven from the single `[workspace.package] version` in the root
`Cargo.toml`. Bump it, commit, and cut the release — the SDK crates go out at
that version, in lockstep.

| Command | Effect |
|---------|--------|
| `make pkg-sdk` | Build the `.tgz` bundle. |
| `make publish-sdk-dry-run` | Package and verify all SDK crates. No upload, no token. |
| `make publish-sdk` | Publish all SDK crates to the `ferrogate` registry. |
| `make deploy-release` | Tag `releases/v<version>` and push, which triggers the release workflow. |

`scripts/publish-sdk.sh` stages the crates into `target/sdk-publish/` and
publishes from there rather than from the repo workspace. The repo's manifests
keep bare `path` dependencies; the exact `version` and `registry` that
`cargo publish` requires are injected into the staged copy at publish time, so
they are derived from the workspace version on every run and cannot drift on a
version bump. `cargo publish --workspace` then uploads the whole set in
dependency order, verifying each packaged crate against its locally staged
dependencies instead of waiting for the registry index between uploads.
Already-published versions are skipped, so re-running after a partial failure is
safe.

## Release automation

`.github/workflows/release.yml` fires on a `releases/**` tag:

1. **`release`** — builds the `.deb`, `.rpm`, and SDK `.tgz` and attaches them to
   the GitHub Release.
2. **`publish-sdk`** — needs `release`; dry-runs the crate packaging first, then
   publishes to the registry.

The publish job runs in the `cargo-registry` GitHub Environment, which holds the
`CLOUDSMITH_API_KEY` secret. Scoping it to an environment rather than the
repository means only runs of that job can read it, and the environment can
require a reviewer before the credential is released.

### Secret handling

No credential is stored in the repository.

- `.cargo/config.toml` is committed and holds the **index URL only**.
- The token reaches cargo exclusively through
  `CARGO_REGISTRIES_FERROGATE_TOKEN`, set from the `CLOUDSMITH_API_KEY`
  environment secret on the one step that publishes. GitHub masks it in logs;
  `publish-sdk.sh` never echoes or writes it.
- `.cargo/credentials.toml` — where `cargo login` would persist a token — is
  git-ignored. Prefer the environment variable over `cargo login`.
- Locally, read the key into the environment (`read -rs`) rather than passing it
  on a command line, where it would land in shell history.
