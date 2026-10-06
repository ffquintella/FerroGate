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
# Dry run: `--workspace` packages every member in dependency order and verifies
# each against its locally staged dependencies, so nothing has to exist in the
# registry yet.
#
# Real publish: one crate at a time, in dependency order (SDK_CRATES). A
# single `--workspace` pass is not re-runnable — cargo aborts with "already
# exists" on the first crate a previous attempt uploaded, and it gives up when
# the registry index lags behind an upload ("timeout while waiting for published
# dependencies"). Publishing per crate lets a re-run skip what is already
# there and retry a crate whose dependency is not indexed yet.
#
# `--allow-dirty` refers to the staged copy under target/, which is git-ignored
# and therefore always "untracked" from git's point of view. It does not relax
# any check on the repository sources.
PUBLISH_ATTEMPTS="${SDK_PUBLISH_ATTEMPTS:-12}"
PUBLISH_RETRY_SLEEP="${SDK_PUBLISH_RETRY_SLEEP:-20}"

# publish_crate NAME — upload one crate. Returns 0 when it was uploaded or the
# exact version already exists; retries while a dependency is not yet indexed.
publish_crate() {
  local name="$1" attempt=1 out status
  while :; do
    set +e
    out="$(cargo publish -p "$name" --registry "$SDK_REGISTRY" --allow-dirty 2>&1)"
    status=$?
    set -e
    printf '%s\n' "$out"
    if [ "$status" -eq 0 ]; then
      return 0
    fi
    if printf '%s' "$out" | grep -q "already exists"; then
      echo "==> ${name} v${VERSION} is already published — skipping."
      return 0
    fi
    if [ "$attempt" -ge "$PUBLISH_ATTEMPTS" ]; then
      echo "ERROR: ${name} v${VERSION} was not published after ${attempt} attempts." >&2
      return 1
    fi
    echo "==> ${name}: publish failed (attempt ${attempt}/${PUBLISH_ATTEMPTS}); the registry index may lag — retrying in ${PUBLISH_RETRY_SLEEP}s." >&2
    attempt=$((attempt + 1))
    sleep "$PUBLISH_RETRY_SLEEP"
  done
}

if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> Dry run: packaging and verifying ${SDK_NAME} v${VERSION} (nothing is uploaded)"
else
  echo "==> Publishing ${SDK_NAME} v${VERSION} to registry '${SDK_REGISTRY}'"
  echo "    crates: ${SDK_CRATES[*]}"
fi

cd "$STAGE"
if [ "$DRY_RUN" -eq 1 ]; then
  cargo publish --workspace --registry "$SDK_REGISTRY" --allow-dirty --dry-run
else
  for crate in "${SDK_CRATES[@]}"; do
    publish_crate "$crate"
  done
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> Dry run OK — ${#SDK_CRATES[@]} crates package and verify cleanly."
else
  echo "==> Published ${SDK_NAME} v${VERSION} to '${SDK_REGISTRY}'."
  echo "    Consume it with:"
  echo "      ferrogate-sdk-rust = { version = \"${VERSION}\", registry = \"${SDK_REGISTRY}\" }"
fi
