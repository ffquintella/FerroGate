#!/usr/bin/env bash
#
# pack-sdk.sh — bundle the FerroGate Rust integration SDK into a .tgz.
#
# The SDK ships the relying-party / verifier-side crates a third party needs to
# integrate with FerroGate: speak the gRPC protocol, parse and verify SVIDs and
# DPoP-bound child tokens, and verify TPM 2.0 attestations. The server (cmis),
# the host agent (mia), and the operational crates (raft, ceremony, harden,
# winauth, tee, audit, cli) are intentionally excluded.
#
# Output: target/sdk/ferrogate-sdk-rust-<version>.tgz, unpacking to a
# self-contained Cargo workspace named `ferrogate-sdk-rust/`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Crates that make up the public integration surface, in dependency order.
SDK_CRATES=(
  ferro-crypto
  ferro-proto
  ferro-svid-verify
  ferro-child-verify
  ferro-svid
  ferro-attest
)

VERSION="$(awk '/^\[workspace.package\]/{p=1} p&&/^version/{gsub(/[" ]/,"",$3); print $3; exit}' Cargo.toml)"
REPO="$(awk '/^\[workspace.package\]/{p=1} p&&/^repository/{gsub(/[" ]/,"",$3); print $3; exit}' Cargo.toml)"

NAME="ferrogate-sdk-rust"
STAGE="target/sdk/${NAME}"
OUT="target/sdk/${NAME}-${VERSION}.tgz"

echo "==> Staging ${NAME} v${VERSION} (${#SDK_CRATES[@]} crates)"
rm -rf "$STAGE"
mkdir -p "$STAGE/crates"

for c in "${SDK_CRATES[@]}"; do
  [ -d "crates/$c" ] || { echo "ERROR: crates/$c not found"; exit 1; }
  # Copy crate sources; the workspace `target/` lives at the repo root, so per-
  # crate dirs hold only sources/manifests — nothing to exclude.
  cp -R "crates/$c" "$STAGE/crates/$c"
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
' Cargo.toml > "$STAGE/Cargo.toml"

cat > "$STAGE/README.md" <<EOF
# ferrogate-sdk-rust

Rust integration SDK for [FerroGate](${REPO}) — version ${VERSION}.

This is a self-contained Cargo workspace with the relying-party / verifier-side
crates needed to integrate with FerroGate:

| Crate | Purpose |
|-------|---------|
| \`ferro-proto\`        | Generated gRPC stubs and shared wire types (\`MachineIdentity\` service). |
| \`ferro-svid\`         | JWS SVID envelope, SPIFFE derivation, and lifecycle policy. |
| \`ferro-svid-verify\`  | Reference verifier for composite-signed JWS SVIDs. |
| \`ferro-child-verify\` | Reference verifier for DPoP-bound composite-signed child tokens. |
| \`ferro-attest\`       | TPM 2.0 attestation verification. |
| \`ferro-crypto\`       | Hybrid post-quantum cryptographic primitives (shared dependency). |

## Build

\`\`\`sh
cargo build --workspace
cargo test  --workspace
\`\`\`

\`ferro-proto\` compiles \`.proto\` files at build time, so a \`protoc\`
(protobuf-compiler) on \`PATH\` is required.

## Use

Add the crate you need as a path or vendored dependency, e.g.:

\`\`\`toml
[dependencies]
ferro-svid-verify = { path = "crates/ferro-svid-verify" }
\`\`\`

Licensed under Apache-2.0. See ${REPO}.
EOF

echo "==> Writing $OUT"
mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "target/sdk" "$NAME"
echo "==> SDK written to $OUT"
