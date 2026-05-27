# F02 development / CI image.
#
# Provides a Linux toolchain with the TSS2 ESAPI stack (for the `tss-esapi`
# crate that backs `mia::tpm`) plus `swtpm` and `tpm2-tools` so the
# software-TPM integration test can run without real hardware.
#
# Build:  docker build -f docker/f02-dev.Dockerfile -t ferrogate-f02 .
# Use:    via scripts/f02-docker.sh (mounts the workspace + cargo caches).
FROM rust:1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        libtss2-dev \
        tpm2-tools \
        swtpm \
        swtpm-tools \
        libssl-dev \
        pkg-config \
        clang \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

WORKDIR /work
