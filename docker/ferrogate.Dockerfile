# FerroGate runtime image (linux/amd64).
#
# Multi-stage build producing a small, non-root image that runs the FerroGate
# servers. Both `cmis` (Central Machine Identity Service, gRPC) and `mia`
# (Machine Identity Agent) are built in; the default command runs `cmis`.
#
# The servers emit tracing to stdout; the entrypoint tees that to a rotating
# log file under /opt/ferrogate/logs (a mountable volume) while still writing
# to the container's stdout. The CMIS audit WORM store lives under
# /var/lib/ferrogate/audit, also a volume.
#
# Build (via the Makefile):  make docker-image
# Build (directly):
#   docker buildx build --platform linux/amd64 \
#       -f docker/ferrogate.Dockerfile -t ferrogate:latest --load .
#
# Run CMIS, mounting logs + audit on the host and overriding configuration:
#   docker run --rm -p 8443:8443 \
#       -v "$PWD/logs:/opt/ferrogate/logs" \
#       -v "$PWD/audit:/var/lib/ferrogate/audit" \
#       -e RUST_LOG=debug \
#       -e CMIS_LISTEN=0.0.0.0:8443 \
#       ferrogate:latest cmis
#
# Run MIA instead:  docker run ... ferrogate:latest mia

# ---------------------------------------------------------------------------
# Stage 1: build the release binaries for linux/amd64.
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

# ferro-proto compiles the gRPC surface with tonic-build (needs protoc); mia
# links the TSS2 ESAPI stack on Linux (needs libtss2-dev + clang).
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        libtss2-dev \
        libssl-dev \
        pkg-config \
        clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release -p cmis -p mia --bin cmis --bin mia \
    && strip target/release/cmis target/release/mia

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime image, runs as an unprivileged user.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Runtime deps: TSS2 shared libs for mia, OpenSSL, CA certs, and tini for
# correct PID 1 signal handling/zombie reaping.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
        libssl3 \
        libtss2-esys-3.0.2-0 \
        libtss2-mu0 \
        libtss2-rc0 \
        libtss2-tctildr0 \
        libtss2-tcti-device0 \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged user/group (no shell, no login).
ARG FERROGATE_UID=10001
ARG FERROGATE_GID=10001
RUN groupadd --system --gid "${FERROGATE_GID}" ferrogate \
    && useradd --system --uid "${FERROGATE_UID}" --gid "${FERROGATE_GID}" \
        --home-dir /opt/ferrogate --no-create-home --shell /usr/sbin/nologin ferrogate

# Application layout. The log dir and the audit WORM root are created up front
# and owned by the service user so they stay writable when running unprivileged
# and when bind-mounted from the host.
RUN mkdir -p /opt/ferrogate/logs /var/lib/ferrogate/audit \
    && chown -R ferrogate:ferrogate /opt/ferrogate /var/lib/ferrogate

COPY --from=builder /src/target/release/cmis /usr/local/bin/cmis
COPY --from=builder /src/target/release/mia  /usr/local/bin/mia
COPY docker/ferrogate-entrypoint.sh /usr/local/bin/ferrogate-entrypoint.sh

# ---------------------------------------------------------------------------
# FerroGate configuration variables (override with `docker run -e ...`).
# These are the env vars the servers read; values here are safe defaults.
# ---------------------------------------------------------------------------
# Tracing verbosity (EnvFilter).
ENV RUST_LOG=info
# Directory the entrypoint tees tracing output into (mountable volume).
ENV FERROGATE_LOG_DIR=/opt/ferrogate/logs
# --- CMIS ---
ENV CMIS_LISTEN=0.0.0.0:8443
ENV CMIS_AUDIT_ROOT=/var/lib/ferrogate/audit
# --- MIA hardening (feature F12) ---
# A generic container cannot satisfy the host hardening profile (enforced IMA,
# seccomp install, privilege drop from root). It is DISABLED here for container
# use. REMOVE this for production host deployments, where mia must run its full
# hardening profile.
ENV FERROGATE_SKIP_HARDENING=1

WORKDIR /opt/ferrogate
USER ferrogate

EXPOSE 8443

# Persist tracing logs and the audit store outside the container.
VOLUME ["/opt/ferrogate/logs", "/var/lib/ferrogate/audit"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ferrogate-entrypoint.sh"]
# Default server; override with `docker run <image> mia`.
CMD ["cmis"]
