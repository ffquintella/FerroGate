# Builds the SRV fail-over probe (crates/mia/examples/srv_failover_probe.rs) —
# the production CmisResolver driving a real RPC. Single stage on purpose: the
# mia crate links libtss2 dynamically on Linux, so the runtime needs the same
# libraries as the build; image size is irrelevant for a throwaway test image.
# Build from the repo root:
#   docker build -f docker/failover-test/probe.Dockerfile -t ferrogate-failover-probe:latest .
FROM rust:1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler cmake clang pkg-config libtss2-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p mia --example srv_failover_probe \
    && cp target/release/examples/srv_failover_probe /usr/local/bin/srv_failover_probe \
    && rm -rf target /usr/local/cargo/registry
ENTRYPOINT ["srv_failover_probe"]
