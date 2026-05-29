#!/usr/bin/env bash
# Cross-compile / check the workspace for Windows from a Linux/macOS host.
#
# Targets x86_64-pc-windows-gnu inside the ferrogate-wincross image (MinGW-w64
# + the windows-gnu Rust target). Builds the ferrogate-f02 base image first if
# needed. Cargo caches live in named volumes so repeat runs are fast. Usage:
#
#   scripts/win-cross.sh build -p mia -p ferro-winauth
#   scripts/win-cross.sh clippy -p mia --all-targets
#
# The `--target x86_64-pc-windows-gnu` flag is appended automatically.
set -euo pipefail

BASE="ferrogate-f02"
IMAGE="ferrogate-wincross"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! docker image inspect "$BASE" >/dev/null 2>&1; then
    echo "Building $BASE ..." >&2
    docker build -f "$REPO_ROOT/docker/f02-dev.Dockerfile" -t "$BASE" "$REPO_ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE ..." >&2
    docker build -f "$REPO_ROOT/docker/win-cross.Dockerfile" -t "$IMAGE" "$REPO_ROOT"
fi

exec docker run --rm \
    -v "$REPO_ROOT":/work \
    -v ferrogate-cargo-registry:/usr/local/cargo/registry \
    -v ferrogate-wincross-target:/work/target \
    -w /work \
    "$IMAGE" \
    bash -c "rustup target add x86_64-pc-windows-gnu >/dev/null 2>&1; cargo $* --target x86_64-pc-windows-gnu"
