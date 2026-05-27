#!/usr/bin/env bash
# Run a command inside the F02 Linux dev image with the workspace mounted.
#
# The cargo registry and the target dir are cached in named volumes so repeat
# builds are fast. Usage:
#
#   scripts/f02-docker.sh cargo build --workspace
#   scripts/f02-docker.sh cargo test -p ferro-attest
#   scripts/f02-docker.sh bash        # interactive shell
set -euo pipefail

IMAGE="ferrogate-f02"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE ..." >&2
    docker build -f "$REPO_ROOT/docker/f02-dev.Dockerfile" -t "$IMAGE" "$REPO_ROOT"
fi

TTY_FLAGS=()
if [ -t 0 ]; then TTY_FLAGS=(-it); fi

exec docker run --rm "${TTY_FLAGS[@]}" \
    -v "$REPO_ROOT":/work \
    -v ferrogate-cargo-registry:/usr/local/cargo/registry \
    -v ferrogate-f02-target:/work/target \
    -w /work \
    "$IMAGE" "$@"
