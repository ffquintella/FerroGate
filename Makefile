.PHONY: build test run-cmis run-mia fmt fmt-check lint check audit deny coverage clean \
        formal formal-tamarin formal-cryptoverif

build:
	cargo build --workspace

test:
	cargo test --workspace --all-targets

run-cmis:
	cargo run -p cmis

run-mia:
	cargo run -p mia

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

check:
	cargo check --workspace --all-targets

audit:
	cargo audit

deny:
	cargo deny check

coverage:
	cargo llvm-cov --workspace --lcov --output-path lcov.info

clean:
	cargo clean

# Formal verification (feature: M6). Both targets degrade gracefully when the
# prover is not installed locally; CI installs both so the gate is real there.
# Per-proof wall-clock ceiling in seconds (CI sets this explicitly).
FERROGATE_FORMAL_TIMEOUT ?= 600

formal: formal-tamarin formal-cryptoverif

formal-tamarin:
	@if command -v tamarin-prover >/dev/null 2>&1; then \
		echo "==> Tamarin: formal/tamarin/attestation.spthy"; \
		tamarin-prover --prove formal/tamarin/attestation.spthy; \
	else \
		echo "SKIP: tamarin-prover not on PATH (see formal/README.md to install)"; \
	fi

formal-cryptoverif:
	@if command -v cryptoverif >/dev/null 2>&1; then \
		echo "==> CryptoVerif: formal/cryptoverif/hybrid_ake.cv"; \
		cryptoverif formal/cryptoverif/hybrid_ake.cv; \
	else \
		echo "SKIP: cryptoverif not on PATH (see formal/README.md to install)"; \
	fi
