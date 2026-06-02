# FerroGate runtime image (linux/amd64).
#
# Multi-stage build producing a small, non-root image that runs `cmis`, the
# Central Machine Identity Service (gRPC server). The `ferrogate` operator CLI
# is shipped alongside it so an operator can `docker exec` into a running
# server and drive the admin RPCs against the local CMIS (status, list-svids,
# revoke-svid, revoke-host, bump-epoch). The `mia` Machine Identity Agent is
# NOT shipped here — it is the host-side client, installed directly on each
# machine from the OS packages (`make pkg`: .deb / .rpm / .msi / .pkg).
#
# cmis emits tracing to stdout; the entrypoint tees that to a rotating log file
# under /opt/ferrogate/logs (a mountable volume) while still writing to the
# container's stdout. The CMIS audit WORM store lives under
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
#       ferrogate:latest

# ---------------------------------------------------------------------------
# Stage 1: build the release binaries for linux/amd64.
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

# ferro-proto compiles the gRPC surface with tonic-build (needs protoc).
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        libssl-dev \
        pkg-config \
        clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build the server (`cmis`) and the operator CLI (`ferrogate`) in one pass so
# they share the dependency compile.
RUN cargo build --release -p cmis --bin cmis -p ferrogate-cli --bin ferrogate \
    && strip target/release/cmis target/release/ferrogate

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime image, runs as an unprivileged user.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Runtime deps: OpenSSL, CA certs, and tini for correct PID 1 signal
# handling/zombie reaping.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
        libssl3 \
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
COPY --from=builder /src/target/release/ferrogate /usr/local/bin/ferrogate
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
# --- ferrogate operator CLI ---
# Default target for the bundled CLI: the CMIS in this same container, over the
# loopback. Override with `-e FERROGATE_CMIS_ENDPOINT=...` to point at another
# replica.
ENV FERROGATE_CMIS_ENDPOINT=http://127.0.0.1:8443

WORKDIR /opt/ferrogate
USER ferrogate

EXPOSE 8443

# Persist tracing logs and the audit store outside the container.
VOLUME ["/opt/ferrogate/logs", "/var/lib/ferrogate/audit"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ferrogate-entrypoint.sh"]
CMD ["cmis"]
