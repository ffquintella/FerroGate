.PHONY: build test run-cmis run-mia fmt fmt-check lint check audit deny coverage clean

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
