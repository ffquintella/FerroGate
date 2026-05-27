# Changelog

All notable changes to FerroGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches a tagged release. Until then, changes are grouped by delivery milestone
(see [docs/roadmap.md](docs/roadmap.md)).

## [Unreleased]

### Added — F04: SVID issuance and lifecycle (M2)

- **`ferro-proto` — `MachineIdentity` gRPC surface.** A proto3 service
  (`Attest` bidi stream, `Rotate`, `FetchSVID`, `JWKS`) compiled to tonic
  client/server stubs. `Attest` is server-first: it opens with a `Nonce`
  supplying the quote's `qualifyingData`, then drives the four-phase handshake.
- **`ferro-svid` — JWS SVID envelope, issuance, and lifecycle.** The
  `ferrogate-svid-v1` claim schema; composite-signed compact JWS
  (`alg = MLDSA65+Ed25519`, `typ = ferrogate-svid+jwt`); SPIFFE-ID derivation
  from `SHA-384(ek_cert)`; a composite JWK / JWK-set; the
  renewal-vs-re-attestation decision (24 h window, PCR drift, epoch bump); and
  the 60%-of-TTL ±10% rotation-scheduler math. 1 h max TTL, `nbf` with a 60 s
  lookback.
- **`ferro-svid-verify` — standalone reference verifier.** Self-contained
  (re-declares the schema, depends only on `ferro-crypto` for the composite
  primitive): parses the compact JWS, verifies the AND-combined signature
  against a JWK set, and enforces `nbf`/`exp` fail-closed. Refuses expired SVIDs.
- **`cmis` — the issuance server.** `MachineIdentitySvc` runs the four-phase
  `Attest` (F02 quote verification → phase-3 credential activation via the
  `CredentialMaker` seam → phase-4 AIK-bound composite CSR check → composite
  SVID issuance), the in-window `Rotate` short path with forced re-attestation
  on drift/epoch change, `FetchSVID`, and `JWKS`. Client-visible errors collapse
  to the fixed status set in `docs/cmis.md`; precise reasons are logged only.
- **`mia` — attest client, sealing, scheduler.** `client::run_attest` drives the
  handshake (generic over an `AttestEvidence` trait so it runs against a real
  TPM or a software stand-in) and returns the SVID plus its composite key.
  `seal` (Linux-only) seals a 256-bit key to a `PolicyPCR` over PCRs
  `{0,4,7,8}` (SHA-384) and ChaCha20-Poly1305-encrypts the cache; a sealed-PCR
  change makes the cache fail to unseal. `scheduler` computes the jittered
  rotation instant.
- **Tests.** An end-to-end gRPC test over a real in-process tonic channel
  (`crates/mia/tests/e2e_attest.rs`: issuance accepted by the reference
  verifier, `Rotate` short path, `Rotate` refused on drift), an `swtpm` sealing
  test (`crates/mia/tests/swtpm_seal.rs`), plus unit/round-trip coverage in
  `ferro-svid`. The TPM-backed modules are verified in the Linux/`swtpm` image.

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
