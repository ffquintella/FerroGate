#!/usr/bin/env bash
#
# sdk-common.sh — shared definitions for the ferrogate-sdk-rust packaging
# (pack-sdk.sh) and publishing (publish-sdk.sh) scripts. Sourced, not executed.
#
# Both scripts stage the same set of crates into a self-contained Cargo
# workspace; they differ only in what they do with it — tar it up, or publish it
# to a Cargo registry.

# Crates that make up the public integration surface, in dependency order (which
# is also publish order). The relying-party / verifier-side crates only: the
# server (cmis), the host agent (mia), and the operational crates (raft,
# ceremony, harden, winauth, tee, audit, transport, cli) are excluded.
#
# `ferro-machineid` and `ferro-sep` are not part of the documented API surface,
# but `ferro-attest` depends on them for the TPM-less host-key profile, so they
# must ship and publish alongside it.
#
# `ferrogate-sdk-rust` is last: it is the facade crate that re-exports the rest
# behind one versioned dependency, so it depends on all of them.
SDK_CRATES=(
  ferro-crypto
  ferro-machineid
  ferro-sep
  ferro-proto
  ferro-svid-verify
  ferro-child-verify
  ferro-svid
  ferro-attest
  ferrogate-sdk-rust
)

SDK_NAME="ferrogate-sdk-rust"

# Cargo registry to publish to. Must match a [registries.<name>] entry in
# .cargo/config.toml; the token comes from CARGO_REGISTRIES_<NAME>_TOKEN.
SDK_REGISTRY="${SDK_REGISTRY:-ferrogate}"

# Read a field out of the root [workspace.package] table.
sdk_workspace_field() {
  awk -v key="$1" '
    /^\[workspace.package\]/ { p = 1; next }
    p && /^\[/              { exit }
    p && $1 == key          { gsub(/[" ]/, "", $3); print $3; exit }
  ' "${SDK_ROOT}/Cargo.toml"
}

# sdk_stage <stage-dir> <mode>
#
# Materialise the SDK crates as a standalone Cargo workspace at <stage-dir>.
#
#   mode = tarball  — inter-crate dependencies stay bare `path` deps, so the
#                     unpacked workspace builds offline with no registry
#                     configured.
#   mode = publish  — inter-crate dependencies additionally carry an exact
#                     `version` and the `registry` they resolve from, which
#                     `cargo publish` requires. The `path` is kept so cargo can
#                     verify the whole set locally, in order, before any of it
#                     reaches the registry.
sdk_stage() {
  local stage="$1" mode="$2"
  local version repo c

  version="$(sdk_workspace_field version)"
  repo="$(sdk_workspace_field repository)"
  [ -n "$version" ] || { echo "ERROR: could not read the workspace version" >&2; return 1; }

  echo "==> Staging ${SDK_NAME} v${version} (${#SDK_CRATES[@]} crates, mode=${mode})"
  rm -rf "$stage"
  mkdir -p "$stage/crates"

  for c in "${SDK_CRATES[@]}"; do
    [ -d "${SDK_ROOT}/crates/$c" ] || { echo "ERROR: crates/$c not found" >&2; return 1; }
    # Copy crate sources; the workspace `target/` lives at the repo root, so
    # per-crate dirs hold only sources/manifests — nothing to exclude.
    cp -R "${SDK_ROOT}/crates/$c" "$stage/crates/$c"
  done

  # Workspace manifest: reuse the repo's [workspace.package], lints, and
  # [workspace.dependencies] verbatim so each crate's `workspace = true`
  # inheritance resolves standalone, but rewrite `members` to just the SDK set.
  awk -v list="${SDK_CRATES[*]}" '
    /^members[[:space:]]*=[[:space:]]*\[/ {
      print "members = ["
      n = split(list, a, " ")
      for (i = 1; i <= n; i++) print "    \"crates/" a[i] "\","
      skip = 1; next
    }
    skip && /^\]/ { print "]"; skip = 0; next }
    skip          { next }
                  { print }
  ' "${SDK_ROOT}/Cargo.toml" > "$stage/Cargo.toml"

  if [ "$mode" = publish ]; then
    # `cargo publish` refuses a path dependency that carries no version, and a
    # dependency with no `registry` is assumed to live on crates.io. Add both to
    # every inter-crate `path = "../<crate>"` dep. The version is pinned exactly
    # (`=x.y.z`): the SDK crates are released in lockstep and are only ever
    # consumed as a matched set.
    #
    # Only `../`-prefixed paths are touched, so `[lib] path = "src/lib.rs"` and
    # any other intra-crate path is left alone.
    for c in "${SDK_CRATES[@]}"; do
      sed -E "s|(path = \"\.\./[A-Za-z0-9_-]+\")|\1, version = \"=${version}\", registry = \"${SDK_REGISTRY}\"|g" \
        "$stage/crates/$c/Cargo.toml" > "$stage/crates/$c/Cargo.toml.tmp"
      mv "$stage/crates/$c/Cargo.toml.tmp" "$stage/crates/$c/Cargo.toml"
    done
  fi

  sdk_write_workspace_readme "$stage" "$version" "$repo"
}

sdk_write_workspace_readme() {
  local stage="$1" version="$2" repo="$3"
  cat > "$stage/README.md" <<EOF
# ferrogate-sdk-rust

Rust integration SDK for [FerroGate](${repo}) — version ${version}.

This is a self-contained Cargo workspace with the relying-party / verifier-side
crates needed to integrate with FerroGate:

| Crate | Purpose |
|-------|---------|
| \`ferrogate-sdk-rust\` | Facade: re-exports everything below behind one versioned dependency. |
| \`ferro-proto\`        | Generated gRPC stubs and shared wire types (\`MachineIdentity\` service). |
| \`ferro-svid\`         | JWS SVID envelope, SPIFFE derivation, and lifecycle policy. |
| \`ferro-svid-verify\`  | Reference verifier for composite-signed JWS SVIDs. |
| \`ferro-child-verify\` | Reference verifier for DPoP-bound composite-signed child tokens. |
| \`ferro-attest\`       | TPM 2.0 attestation verification. |
| \`ferro-sep\`          | Machine signing key for the TPM-less host-key profile (\`ferro-attest\` dependency). |
| \`ferro-machineid\`    | Stable hardware fingerprint for the TPM-less host-key profile (\`ferro-attest\` dependency). |
| \`ferro-crypto\`       | Hybrid post-quantum cryptographic primitives (shared dependency). |

## Build

\`\`\`sh
cargo build --workspace
cargo test  --workspace
\`\`\`

\`ferro-proto\` compiles \`.proto\` files at build time, so a \`protoc\`
(protobuf-compiler) on \`PATH\` is required.

## Use

These same crates are published to a Cargo registry, which is the preferred way
to consume them — see \`crates/ferrogate-sdk-rust/README.md\`. To vendor this
tarball instead, depend on it by path:

\`\`\`toml
[dependencies]
ferrogate-sdk-rust = { path = "crates/ferrogate-sdk-rust" }
\`\`\`

Licensed under Apache-2.0. See ${repo}.
EOF
}
