# Changelog

All notable changes to FerroGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches a tagged release. Until then, changes are grouped by delivery milestone
(see [docs/roadmap.md](docs/roadmap.md)).

## [Unreleased]

### Added — F02: TPM 2.0 attestation engine (M2)

- **`ferro-attest` — CMIS-side quote verifier.** `TpmQuoteVerifier::verify_quote`
  runs the ordered, fail-closed algorithm: EK-certificate chain → AIK
  attribute mask → `magic`/`type` → nonce → ECDSA-P256 signature → recomputed
  SHA-384 PCR digest → RIM `policy_id`. Every rejection carries a precise,
  audit-only `RejectReason` while the peer sees only a generic denial.
  Fail-closed parsers for the canonical TPM wire structures (`TPMS_ATTEST`,
  `TPMT_PUBLIC`, `TPMT_SIGNATURE`) and a constant-time credential-activation
  compare.
- **`mia::tpm::TpmEngine` — host glue over `tss-esapi`** (Linux-gated). Exposes
  `load_ek`, `create_aik` (restricted ECDSA P-256 child of the EK), `quote`
  (policy PCRs over the SHA-384 bank), `activate_credential` (endorsement
  `PolicySecret` session), and `sign_aik` (restricted-key `TPM2_Hash` + ticket
  path). All sensitive commands run under HMAC-bound sessions with parameter
  encryption, flushed after use.
- **Vendor root CA bundling.** Per-vendor trust store (Infineon, Nuvoton, ST,
  Intel PTT), independently loadable, with roots embedded at build time from
  `crates/ferro-attest/vendor-roots/<vendor>/`. Nothing is trusted by default.
- **CA provisioning tool** `scripts/ferrogate-ca.sh` (`fingerprint` / `add`
  with pinned SHA-256 / `list` / `verify`) and the documented procedure in
  `crates/ferro-attest/vendor-roots/README.md` and `docs/tpm.md`.
- **Tests & harness.** 26 `ferro-attest` tests including negative cases
  (tampered quote, wrong nonce, missing PCR, non-restricted AIK, untrusted
  root, not-in-RIM, wrong signing key, credential mismatch); an end-to-end
  `swtpm` integration test (`crates/mia/tests/swtpm_attest.rs`); and a Linux
  build/test image (`docker/f02-dev.Dockerfile` + `scripts/f02-docker.sh`)
  carrying the TSS2 + `swtpm` toolchain.

## [M1] — 2026-05-26 — Cryptographic foundation

### Added

- **F01: Hybrid post-quantum TLS transport** (`ferro-crypto`). A rustls
  provider exposing only `X25519MLKEM768` in hybrid mode, SHA-384 SPKI pinning
  for the MIA, and tests covering hybrid-only rejection of legacy clients, the
  `ClientHello` key-share wire format, and AEAD Wycheproof vectors.
- **F03: Composite Ed25519 + ML-DSA-65 signatures** (`ferro-crypto`). An
  AND-combiner signature over a domain-separated SHA3-384 transcript, with
  concat / DER (`2.16.840.1.114027.80.8.1.7`) / JOSE (`MLDSA65+Ed25519`) wire
  forms, KAT runners, and property tests proving either-half corruption fails
  verification.

## [M0] — 2026-05-22 — Workspace bootstrap

### Added

- Cargo workspace under `crates/` with stub crates for `cmis`, `mia`,
  `ferro-crypto`, `ferro-attest`, `ferro-audit`, `ferro-proto`, `ferro-tee`,
  and the relocated `ferrogate-cli`.
- CI (GitHub Actions): `fmt`, `clippy`, `test`, `cargo audit`, `cargo deny`,
  and an `llvm-cov` coverage job; `Makefile` targets mirroring them.
- `#![forbid(unsafe_code)]` on every crate plus a workspace-wide
  `unsafe_code = "deny"` lint.
- Design documentation under `docs/` (architecture, protocol, threat model,
  TPM, crypto, per-feature specs, and the roadmap).
