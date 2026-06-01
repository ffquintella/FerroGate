.PHONY: help build test run run-cmis run-mia fmt fmt-check lint check audit deny coverage clean \
        formal formal-tamarin formal-cryptoverif docs

# Default target: list available targets with their descriptions.
.DEFAULT_GOAL := help

help: ## List available targets
	@echo "Usage: make <target>"
	@echo
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the entire workspace
	cargo build --workspace

test: ## Run all workspace tests
	cargo test --workspace --all-targets

run: ## Run the ferrogate CLI (pass args with ARGS="...")
	cargo run -p ferrogate-cli --bin ferrogate -- $(ARGS)

run-cmis: ## Run the cmis service
	cargo run -p cmis

run-mia: ## Run the mia service
	cargo run -p mia

fmt: ## Format all code
	cargo fmt --all

fmt-check: ## Check formatting without modifying files
	cargo fmt --all -- --check

lint: ## Run clippy with warnings denied
	cargo clippy --workspace --all-targets -- -D warnings

check: ## Type-check the workspace
	cargo check --workspace --all-targets

audit: ## Audit dependencies for known vulnerabilities
	cargo audit

deny: ## Run cargo-deny checks
	cargo deny check

coverage: ## Generate LCOV coverage report
	cargo llvm-cov --workspace --lcov --output-path lcov.info

clean: ## Remove build artifacts
	cargo clean

docs: ## Serve the Docsify documentation site locally (PORT=3000 by default)
	./serve-docs.sh $(PORT)

# Formal verification (feature: M6). Both targets degrade gracefully when the
# prover is not installed locally; CI installs both so the gate is real there.
# Per-proof wall-clock ceiling in seconds (CI sets this explicitly).
FERROGATE_FORMAL_TIMEOUT ?= 600

formal: formal-tamarin formal-cryptoverif ## Run all formal verification proofs

formal-tamarin: ## Run the Tamarin attestation proof
	@if command -v tamarin-prover >/dev/null 2>&1; then \
		echo "==> Tamarin: formal/tamarin/attestation.spthy"; \
		tamarin-prover --prove formal/tamarin/attestation.spthy; \
	else \
		echo "SKIP: tamarin-prover not on PATH (see formal/README.md to install)"; \
	fi

formal-cryptoverif: ## Run the CryptoVerif hybrid AKE proof
	@if command -v cryptoverif >/dev/null 2>&1; then \
		echo "==> CryptoVerif: formal/cryptoverif/hybrid_ake.cv"; \
		cryptoverif formal/cryptoverif/hybrid_ake.cv; \
	else \
		echo "SKIP: cryptoverif not on PATH (see formal/README.md to install)"; \
	fi
