# Windows cross-compile / CI image.
#
# Layers the MinGW-w64 toolchain and the `x86_64-pc-windows-gnu` Rust target on
# top of the F02 dev image (which already carries protobuf-compiler etc.) so the
# Windows Named Pipe helper-API transport (`mia` + `ferro-winauth`) can be
# compile-checked from a Linux host. We cannot *run* Windows tests here, but the
# cross build exercises all the Windows FFI and `cfg(windows)` code paths.
#
# Build:  docker build -f docker/win-cross.Dockerfile -t ferrogate-wincross .
#         (requires the ferrogate-f02 base image; see f02-dev.Dockerfile)
# Use:    via scripts/win-cross.sh
FROM ferrogate-f02

RUN apt-get update && apt-get install -y --no-install-recommends \
        mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-pc-windows-gnu

WORKDIR /work
