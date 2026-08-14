#!/usr/bin/env bash
#
# publish-sdk.sh — publish the FerroGate Rust integration SDK to a Cargo
# registry (Cloudsmith: https://cloudsmith.io/~uox/repos/ferrogate/).
#
# Same crate set as pack-sdk.sh (see scripts/sdk-common.sh), but instead of
# tarring the staged workspace it runs `cargo publish` over it. Publishing is
# done from a staged copy rather than the repo workspace so the repo's manifests
# keep bare `path` dependencies — the exact version and `registry` that
# `cargo publish` requires are injected at publish time from the single
# [workspace.package] version, and cannot drift on a version bump.
#
# Usage:
#   scripts/publish-sdk.sh              # publish
#   scripts/publish-sdk.sh --dry-run    # package + verify only, no upload
#
# Environment:
#   SDK_REGISTRY   registry name from .cargo/config.toml (default: ferrogate)
#   CARGO_REGISTRIES_<REGISTRY>_TOKEN
#                  API token, Cloudsmith-style: "Token <api-key>". Never
#                  committed — supplied by the operator or by CI from a secret.
#
# The token is only ever read from the environment and handed to cargo; it is
# never written to disk or echoed.
set -euo pipefail

SDK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SDK_ROOT"
# shellcheck source=scripts/sdk-common.sh
. "${SDK_ROOT}/scripts/sdk-common.sh"

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
  esac
done

VERSION="$(sdk_workspace_field version)"
STAGE="target/sdk-publish/${SDK_NAME}"

# CARGO_REGISTRIES_<NAME>_TOKEN — cargo upper-cases the registry name and maps
# hyphens to underscores.
REG_UPPER="$(printf '%s' "$SDK_REGISTRY" | tr '[:lower:]-' '[:upper:]_')"
TOKEN_VAR="CARGO_REGISTRIES_${REG_UPPER}_TOKEN"

# ── Preflight ────────────────────────────────────────────────────────────────

if ! grep -q "^\[registries\.${SDK_REGISTRY}\]" "${SDK_ROOT}/.cargo/config.toml" 2>/dev/null; then
  echo "ERROR: registry '${SDK_REGISTRY}' is not defined in .cargo/config.toml." >&2
  exit 1
fi

if ! cargo publish --help 2>/dev/null | grep -q -- '--workspace'; then
  echo "ERROR: this cargo does not support 'cargo publish --workspace'." >&2
  echo "       Rust 1.90 or newer is required to publish inter-dependent crates" >&2
  echo "       in one pass. Installed: $(cargo --version)" >&2
  exit 1
fi

if [ "$DRY_RUN" -eq 0 ] && [ -z "${!TOKEN_VAR:-}" ]; then
  cat >&2 <<EOF
ERROR: ${TOKEN_VAR} is not set, so there is no credential to publish with.

Set it in your shell (do NOT commit it, and do NOT pass it on a command line
where it would land in your shell history):

    read -rs CLOUDSMITH_API_KEY && export ${TOKEN_VAR}="Token \$CLOUDSMITH_API_KEY"

In CI it is populated from the CLOUDSMITH_API_KEY repository secret — see
.github/workflows/release.yml. Use --dry-run to package and verify without a
token.
EOF
  exit 1
fi

# ── Stage ────────────────────────────────────────────────────────────────────

sdk_stage "$STAGE" publish

# ── Publish ──────────────────────────────────────────────────────────────────
#
# `--workspace` publishes every member in dependency order in a single pass, and
# verifies each packaged crate against its locally staged dependencies rather
# than waiting for the registry index to catch up between uploads. Already
# published versions are skipped, so a re-run after a partial failure is safe.
#
# `--allow-dirty` refers to the staged copy under target/, which is git-ignored
# and therefore always "untracked" from git's point of view. It does not relax
# any check on the repository sources.
PUBLISH_ARGS=(publish --workspace --registry "$SDK_REGISTRY" --allow-dirty)
if [ "$DRY_RUN" -eq 1 ]; then
  PUBLISH_ARGS+=(--dry-run)
  echo "==> Dry run: packaging and verifying ${SDK_NAME} v${VERSION} (nothing is uploaded)"
else
  echo "==> Publishing ${SDK_NAME} v${VERSION} to registry '${SDK_REGISTRY}'"
  echo "    crates: ${SDK_CRATES[*]}"
fi

cd "$STAGE"
cargo "${PUBLISH_ARGS[@]}"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> Dry run OK — ${#SDK_CRATES[@]} crates package and verify cleanly."
else
  echo "==> Published ${SDK_NAME} v${VERSION} to '${SDK_REGISTRY}'."
  echo "    Consume it with:"
  echo "      ferrogate-sdk-rust = { version = \"${VERSION}\", registry = \"${SDK_REGISTRY}\" }"
fi
