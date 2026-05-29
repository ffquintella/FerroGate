#!/usr/bin/env bash
# Reproducible-build check for the MIA (feature F12).
#
# Builds `mia` twice, from a clean target directory each time, with
# determinism-forcing flags, and asserts the two binaries are byte-identical.
# Prints the `bin_sha384` — the same SHA-384 the IMA appraisal and the helper
# allowlist key the binary by — so a release can be pinned to a known hash.
#
# Usage: scripts/reproducible-build.sh [target-triple]
#   With no argument, builds for the host target (the default in CI). Pass an
#   explicit triple (e.g. x86_64-unknown-linux-musl) to cross-build; that needs
#   the matching cross C toolchain (`<triple>-gcc`) installed.
#
# Prerequisites (Debian/Ubuntu): protobuf-compiler, libtss2-dev.
set -euo pipefail

TARGET="${1:-}"
CRATE="mia"

# Pin everything that could otherwise vary between two builds of identical
# source: timestamps, locale, time zone, incremental caches, and the absolute
# paths rustc would otherwise bake into panic messages / debug info. Dropping
# the ELF build-id removes the one remaining content-hash that differs trivially.
export SOURCE_DATE_EPOCH=1
export CARGO_INCREMENTAL=0
export LC_ALL=C
export TZ=UTC
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=${PWD}=/build --remap-path-prefix=${CARGO_HOME_DIR}=/cargo -C relocation-model=pic -C link-arg=-Wl,--build-id=none"

# An explicit non-host target needs its std and (for C deps) a cross compiler.
TARGET_ARGS=()
REL_PATH="release/${CRATE}"
if [ -n "${TARGET}" ]; then
    TARGET_ARGS=(--target "${TARGET}")
    REL_PATH="${TARGET}/release/${CRATE}"
    if command -v rustup >/dev/null 2>&1; then
        rustup target add "${TARGET}" >/dev/null 2>&1 || true
    fi
fi

# Both builds must use the SAME target directory path: build scripts for C deps
# (aws-lc-rs, ring) embed their absolute OUT_DIR, which lives under the target
# dir. Two different target dirs ⇒ two different binaries even from identical
# source. So we build into one fixed path, cleaning it between runs, and copy the
# artefact out before the second build. The fixed path is under `target/` (which
# `--remap-path-prefix=$PWD` rewrites and `.gitignore` excludes).
work="${PWD}/target/_repro"
out="$(mktemp -d)"
trap 'rm -rf "${work}" "${out}"' EXIT

build() {
    rm -rf "${work}"
    CARGO_TARGET_DIR="${work}" cargo build --release --locked -p "${CRATE}" "${TARGET_ARGS[@]}"
}

echo ">> build 1/2 (${TARGET:-host})"
build
cp "${work}/${REL_PATH}" "${out}/mia.1"
echo ">> build 2/2 (${TARGET:-host})"
build
cp "${work}/${REL_PATH}" "${out}/mia.2"

bin_a="${out}/mia.1"
bin_b="${out}/mia.2"

hash_a="$(sha384sum "${bin_a}" | awk '{print $1}')"
hash_b="$(sha384sum "${bin_b}" | awk '{print $1}')"

echo "bin_sha384 (build 1): ${hash_a}"
echo "bin_sha384 (build 2): ${hash_b}"

if [ "${hash_a}" != "${hash_b}" ]; then
    echo "FAIL: builds are NOT byte-identical" >&2
    cmp "${bin_a}" "${bin_b}" || true
    exit 1
fi

echo "OK: reproducible build, bin_sha384=${hash_a}"
