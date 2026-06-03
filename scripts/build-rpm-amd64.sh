#!/usr/bin/env bash
# Build the mia .rpm for x86_64 (amd64) Linux inside a container.
# mia links the system TPM2 TSS libs (tss-esapi), so it must be built on a
# Linux host/image that provides libtss2-dev — cross-compiling from macOS is
# not viable. Produces target/generate-rpm/*.x86_64.rpm with a real Linux ELF.
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm --platform linux/amd64 \
  -v "$PWD":/work -w /work \
  -e CARGO_TERM_COLOR=always \
  rust:bookworm bash -euo pipefail -c '
    apt-get update -qq
    apt-get install -y -qq libtss2-dev pkg-config protobuf-compiler >/dev/null
    cargo install cargo-generate-rpm --quiet
    cargo build --release -p mia --bin mia
    strip target/release/mia
    cargo generate-rpm -p crates/mia -a x86_64
  '
echo "==> amd64 .rpm written under target/generate-rpm/"
