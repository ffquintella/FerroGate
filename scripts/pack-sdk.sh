#!/usr/bin/env bash
#
# pack-sdk.sh — bundle the FerroGate Rust integration SDK into a .tgz.
#
# The SDK ships the relying-party / verifier-side crates a third party needs to
# integrate with FerroGate: speak the gRPC protocol, parse and verify SVIDs and
# DPoP-bound child tokens, and verify TPM 2.0 attestations. The server (cmis),
# the host agent (mia), and the operational crates (raft, ceremony, harden,
# winauth, tee, audit, cli) are intentionally excluded. The crate set itself
# lives in scripts/sdk-common.sh, shared with publish-sdk.sh.
#
# Output: target/sdk/ferrogate-sdk-rust-<version>.tgz, unpacking to a
# self-contained Cargo workspace named `ferrogate-sdk-rust/`.
#
# To publish the same crates to the Cargo registry instead, see publish-sdk.sh
# (`make publish-sdk`).
set -euo pipefail

SDK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SDK_ROOT"
# shellcheck source=scripts/sdk-common.sh
. "${SDK_ROOT}/scripts/sdk-common.sh"

VERSION="$(sdk_workspace_field version)"
STAGE="target/sdk/${SDK_NAME}"
OUT="target/sdk/${SDK_NAME}-${VERSION}.tgz"

sdk_stage "$STAGE" tarball

echo "==> Writing $OUT"
mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "target/sdk" "$SDK_NAME"
echo "==> SDK written to $OUT"
