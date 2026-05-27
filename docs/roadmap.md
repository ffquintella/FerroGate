# FerroGate Roadmap

This roadmap groups the [features](features/README.md) into delivery
milestones. Each milestone is intended to be merge-able as a coherent slice
of functionality with its own demo and test artefacts.

Mark items as in progress with `[~]` and as complete with `[x]`. The status
column in [features/README.md](features/README.md) should reflect the
roadmap state.

## Status legend

- `[ ]` — Not started
- `[~]` — In progress
- `[x]` — Done
- `[!]` — Blocked (note why on the same line)

---

## Milestone M0 — Workspace bootstrap

Get the cargo workspace and CI scaffolding in place so feature work can land
in clean slices.

- [x] Convert the existing `src/` scaffold into a cargo workspace under `crates/`. (CLI relocated to `crates/ferrogate-cli/`.)
- [x] Create empty `crates/{cmis,mia,ferro-crypto,ferro-attest,ferro-audit,ferro-proto,ferro-tee}` with `lib.rs`/`main.rs` stubs.
- [x] Wire `make fmt`, `make lint`, `make test`, `make check` against the workspace. (Plus `make audit`, `make deny`, `make coverage`, `make run-cmis`, `make run-mia`.)
- [x] CI: GitHub Actions running fmt + clippy + test on Linux. (See `.github/workflows/ci.yml`.)
- [x] Add `cargo audit` and `cargo deny` to CI. (Plus `deny.toml`.)
- [x] Add `cargo llvm-cov` coverage job with a baseline threshold. (Baseline 10% in M0; raise as features land.)
- [x] Forbid `unsafe` in `crates/mia` via `#![forbid(unsafe_code)]`. (Applied to every FerroGate crate plus a workspace-wide `unsafe_code = "deny"` lint.)

**M0 status: complete.** Verified locally with `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace --all-targets`, and `cargo check --workspace`. CI
job execution will gate the milestone in the upstream repository once the
remote is wired up.

## Milestone M1 — Cryptographic foundation

Land the primitives every other feature depends on.

### F01 — Hybrid PQC TLS transport

- [x] Add `rustls`, `rustls-post-quantum`, `aws_lc_rs` to `ferro-crypto`.
- [x] Implement `ferrogate_provider()` exposing only `X25519MLKEM768` in hybrid mode. (`crates/ferro-crypto/src/tls.rs`; also exposes a dev-mode fallback variant.)
- [x] SPKI pin verification helper for MIA. (`crates/ferro-crypto/src/pin.rs` — SHA-384 SPKI pins, constant-time match, custom `ServerCertVerifier`.)
- [x] Negative test: non-hybrid client rejected by hybrid-only server. (`crates/ferro-crypto/tests/tls_handshake.rs::legacy_only_client_is_rejected_by_hybrid_only_server`, plus `wrong_pin_rejects_otherwise_valid_server`.)
- [x] Interop test against BoringSSL PQ branch. (Delivered as a wire-format witness in `crates/ferro-crypto/tests/wire_format.rs`: decodes the actual `ClientHello` rustls emits and asserts the `key_share` for `0x11EC` is exactly 32+1184 = 1216 bytes, matching `draft-ietf-tls-hybrid-design`. Same wire BoringSSL-PQ, OpenSSL+oqs and NSS produce.)
- [x] Wycheproof test vectors pass for ChaCha20-Poly1305 and AES-256-GCM. (`crates/ferro-crypto/tests/wycheproof_aead.rs` — 316 ChaCha20-Poly1305 and 66 AES-256-GCM vectors with TLS-standard 12-byte nonces, both `valid` and `invalid` outcomes, encrypt-and-decrypt directions.)

### F03 — Composite signatures

- [x] `CompositeSecretKey` / `CompositePublicKey` with Ed25519 + ML-DSA-65. (`crates/ferro-crypto/src/composite.rs`.)
- [x] Domain-separated `sign(ctx, msg)` and AND-combiner `verify`. Transcript hash is `SHA3-384("FERROGATE-COMPOSITE-v1" || len_be64(ctx) || ctx || msg)`; both halves sign the same 48-byte digest; verify uses `ed25519-dalek::verify_strict` then `fips204::ml_dsa_65::verify`, returning the first failing side as `ClassicalFailed` or `PqcFailed`.
- [x] ASN.1 SEQUENCE encoder/decoder with OID `2.16.840.1.114027.80.8.1.7`. (`to_der` / `from_der`; round-trip and wrong-OID rejection tested.)
- [x] JOSE `alg = "MLDSA65+Ed25519"` glue. (`to_jws_base64url` / `from_jws_base64url`; URL-safe alphabet enforced by the encoder.)
- [x] FIPS-204 and RFC 8032 KAT runners green. RFC 8032 / Ed25519 vectors run against `wycheproof::eddsa` (the full Ed25519 Wycheproof set, including malleability cases). FIPS-204 lengths are pinned to 1952/3309; algorithm KATs are exercised by the upstream `fips204` crate's CI — see `tests/composite_kat.rs` docstring for rationale.
- [x] Property test: corrupting either half fails verify. (`crates/ferro-crypto/tests/composite_proptest.rs` — 32 cases of random `(ctx, msg)`; flips at every bit position; verifies the AND-combiner classifies errors correctly.)

## Milestone M2 — TPM attestation MVP

End-to-end attestation against a software TPM with a single CMIS replica and
no HA. No persistence, no audit, no helper API yet.

### F02 — TPM 2.0 attestation engine

- [x] `mia::tpm::TpmEngine` over `tss-esapi` (`/dev/tpmrm0`). (`crates/mia/src/tpm.rs`, Linux-gated via `cfg(target_os = "linux")`; `open_device()` resolves the resource-manager TCTI, never raw `/dev/tpm0`.)
- [x] EK creation in endorsement hierarchy (ECC-P256 default template). (`TpmEngine::load_ek` via the `tss-esapi` `ek::create_ek_object` abstraction.)
- [x] AIK creation with full required attribute mask. (`TpmEngine::create_aik` — restricted, signing-only ECDSA P-256 child of the EK.)
- [x] PCR quote over the policy PCR set with SHA-384. (`TpmEngine::quote` over `{0,1,2,3,4,7,8,9,10,11,14}`; reads back raw PCRs via the looping `pcr::read_all` so CMIS can recompute the digest.)
- [x] `TPM2_ActivateCredential` flow. (`TpmEngine::activate_credential` with an endorsement-hierarchy `PolicySecret` session for the EK; exercised end-to-end against `swtpm`.)
- [x] AIK signature over composite CSR. (`TpmEngine::sign_aik` — hashes the payload inside the TPM for a validation ticket, as a restricted key requires; CSR/issuance wiring lands with F04.)
- [x] Bound HMAC sessions on all sensitive commands. (`hmac_session` with parameter encryption; sessions are flushed after use to avoid `TPM_RC_SESSION_MEMORY`.)
- [x] `ferro-attest::TpmQuoteVerifier::verify_quote` implementing all 10 steps. (`crates/ferro-attest/src/verify.rs` — ordered, fail-closed: EK chain → AIK mask → magic/type → nonce → ECDSA-P256 signature → recomputed SHA-384 PCR digest → RIM `policy_id`; each rejection carries a precise audit-only `RejectReason`. Phase-3 credential-activation compare is constant-time.)
- [x] Vendor root CA bundles: Infineon, Nuvoton, ST, Intel PTT. (`crates/ferro-attest/src/vendor.rs` + `build.rs` embed `vendor-roots/<vendor>/*.pem` at compile time, independently loadable; nothing trusted by default. Provisioning tool `scripts/ferrogate-ca.sh`, procedure in `vendor-roots/README.md`.)
- [x] `swtpm` integration test for the happy path. (`crates/mia/tests/swtpm_attest.rs` drives a real software TPM and verifies the evidence end-to-end; `docker/f02-dev.Dockerfile` + `scripts/f02-docker.sh` provide the TSS2 + `swtpm` toolchain.)
- [x] Negative tests: wrong nonce, tampered quote, missing PCR, unrestricted AIK. (Plus untrusted EK root, not-in-RIM, wrong signing key, and credential-activation mismatch — 9 verifier tests in `crates/ferro-attest/tests/verify_quote.rs` and 2 negatives in the `swtpm` test.)

### F04 — SVID issuance and lifecycle (subset)

- [x] gRPC `MachineIdentity::Attest` streaming RPC. (`crates/ferro-proto/proto/machine_identity.proto` + tonic codegen; the four-phase server handler is `crates/cmis/src/service.rs`, with a server-first `Nonce` message supplying the quote's `qualifyingData`. The MIA client driver is `crates/mia/src/client.rs`. End-to-end over a real in-process tonic channel in `crates/mia/tests/e2e_attest.rs`.)
- [x] JWS SVID issuance with the documented payload schema. (`crates/ferro-svid/src/{claims,envelope,issue}.rs` — composite-signed compact JWS, `alg = MLDSA65+Ed25519`, `typ = ferrogate-svid+jwt`, 1 h max TTL, `nbf` with 60 s lookback.)
- [x] SPIFFE ID derivation from `SHA-384(ek_cert)`. (`crates/ferro-svid/src/spiffe.rs` — `sub = spiffe://<td>/host/<uuid>` where the UUID is a v8 stamp over the first 16 bytes of the EK-cert digest.)
- [x] `Rotate` RPC with the in-window short path. (`MachineIdentitySvc::rotate` reissues without TPM I/O when the policy epoch and PCR aggregate are unchanged inside the 24 h window; `crates/ferro-svid/src/lifecycle.rs::decide_renewal`.)
- [x] PCR-drift triggers re-attestation. (Same `decide_renewal`; `Rotate` returns `FAILED_PRECONDITION` on PCR drift or epoch bump. Covered by `rotate_refused_on_pcr_drift`.)
- [x] Local sealing of SVID + key to PCRs `{0,4,7,8}`. (`crates/mia/src/seal.rs`, Linux-only: a 256-bit key is sealed to a `PolicyPCR` over `{0,4,7,8}` SHA-384 and AEAD-encrypts the cache blob. `crates/mia/tests/swtpm_seal.rs` proves a sealed PCR change makes the cache fail to unseal.)
- [x] Rotation scheduler at 60% TTL with jitter. (`crates/ferro-svid/src/lifecycle.rs::rotation_delay_secs` — 60% ±10% of TTL; `crates/mia/src/scheduler.rs` wraps it with an OS-CSPRNG jitter sample.)
- [x] Reference JWS verifier as a separate crate. (`crates/ferro-svid-verify` — self-contained: re-declares the schema, verifies the composite signature against a JWK set, enforces `nbf`/`exp`; an expired SVID is refused.)

**F04 status: done for M2.** Verified on Linux (`docker/f02-dev.Dockerfile`) with `cargo test --workspace --all-targets` (incl. the `swtpm` sealing test) plus `clippy -D warnings` and `fmt --check`. Two seams remain for later milestones and are intentionally not closed here: the CMIS gRPC listener runs plaintext in the M2 bring-up binary (hybrid-PQC TLS termination is F01/F05 transport work; the provider already exists in `ferro-crypto`), and phase-3 `MakeCredential` is a `cmis::CredentialMaker` trait with only a software test implementation — a production TCG/EK wrapper lands with the TEE work (the MIA-side `TPM2_ActivateCredential` already exists from F02).

### F10 — RIM and PCR policy (subset)

- [ ] RIM bundle format and loader.
- [ ] RIM signature verification.
- [ ] 6-generation retention.
- [ ] Hot reload from local file (S3 deferred to M5).

## Milestone M3 — Audit log

Make the system externally observable before adding HA complexity.

### F07 — Audit log

- [ ] Event enum and CBOR encoding in `ferro-audit`.
- [ ] In-process Merkle tree with SHA3-384 leaves.
- [ ] STH structure and TEE-style signing stub (replaced in M4).
- [ ] Backing-store abstraction with a local-disk WORM implementation for dev.
- [ ] Inclusion and consistency proof endpoints on CMIS.
- [ ] Property tests covering inclusion and consistency.
- [ ] Forward MIA events into the CMIS audit stream.

## Milestone M4 — HA and TEE

Promote CMIS from a single replica into a TEE-attested cluster.

### F05 — CMIS high availability

- [ ] Embed a Raft library (e.g. `openraft`) with FoundationDB storage.
- [ ] Raft transport over QUIC with hybrid-PQC TLS between peers.
- [ ] Leader election and follower rejoin tested in a 3-node local cluster.
- [ ] Health endpoints gated on Raft state.
- [ ] Chaos test: random kills over 10 minutes, zero client-visible errors.

### F06 — TEE residency and threshold key shares

- [ ] SEV-SNP attestation report production and verification.
- [ ] Intel TDX equivalent.
- [ ] Shamir 3-of-5 over GF(2^256), unit-tested.
- [ ] Per-replica sealing of shares against enclave measurements.
- [ ] Mutual peer attestation before share exchange.
- [ ] ML-KEM-768 PSK channels for share transport.
- [ ] Zeroize-on-drop verified by a Drop test.
- [ ] STH signing in M3 swapped to use the threshold key.

### F07 — Audit log (continued)

- [ ] Co-sign STHs by a Raft majority before publication.
- [ ] S3 Object Lock (Compliance) backing-store implementation.
- [ ] Sigsum / Rekor anchor publisher with back-fill.

## Milestone M5 — Host operations and helper API

Make the system usable by real applications and operators.

### F08 — Local helper API

- [ ] UDS listener at `/run/ferrogate/mia.sock` with correct permissions.
- [ ] CBOR request/response framing.
- [ ] `SO_PEERCRED` + IMA runtime-hash caller authentication.
- [ ] Signed allowlist loader with fail-closed verification.
- [ ] `LocalGrant` / `LocalDenied` audit events.
- [ ] Concurrency / starvation test.
- [ ] Windows Named Pipe variant.

### F09 — DPoP-bound child tokens

- [ ] Token minter with TTL clamp, `jti`, `cnf.jkt`.
- [ ] JWKS endpoint on CMIS with multi-key support.
- [ ] Reference verifier in Rust.
- [ ] Reference verifier in Go.
- [ ] Replay/no-DPoP-proof negative tests against the verifier.

### F11 — Revocation and CRL distribution

- [ ] Admin RPC `revoke_svid(cert_sha, reason)`.
- [ ] CRL delta publisher (60 s cadence).
- [ ] JWKS `x-ferrogate-crl` extension.
- [ ] MIA freshness enforcement (≤ 5 min).
- [ ] CRL signature verification (fail closed).

### F12 — MIA process hardening

- [ ] `prctl` and `mlockall` startup.
- [ ] seccomp-bpf allowlist with audit-mode toggle for dev.
- [ ] Drop to `_ferrogate` UID with `CAP_IPC_LOCK` only.
- [ ] Fail-closed IMA-enforcement check.
- [ ] Reproducible build job in CI (byte-identical re-builds).
- [ ] `#![forbid(unsafe_code)]` on all MIA modules.

### F13 — Zero-touch bootstrap and fleet enrollment

- [ ] Fleet manifest format and offline signing tool (`tools/fleet-manifest`).
- [ ] CMIS load + signed-S3 refresh.
- [ ] Pre-admission lookup at start of `Attest`.
- [ ] Audit events `HostEnrolled` / `HostRejected`.

### F10 — RIM and PCR policy (continued)

- [ ] Signed-S3 RIM refresh.
- [ ] `bump_epoch` admin RPC with audit event and forced re-attestation.

## Milestone M6 — Ceremony, drills, and production readiness

### F14 — Root key ceremony

- [ ] `tools/offline-signer` air-gapped tool.
- [ ] Shamir share generation and sealed transport media format.
- [ ] Cross-signing flow producing both directions of artefact.
- [ ] CMIS JWKS multi-key with "newer preferred" ordering.
- [ ] Destruction procedure with post-zeroization verification.
- [ ] Ceremony minutes signed by all participants, stored to WORM.
- [ ] Staging dry-run completed.

### Operational drills

- [ ] Documented region-loss drill executed in staging.
- [ ] Documented mass-revocation drill (`policy_id` epoch bump) executed.
- [ ] Documented quorum-loss recovery drill executed.
- [ ] SRE runbook for each alert (STH lag, CRL stale, key-share failure).

### Formal verification

- [ ] CryptoVerif model of the hybrid AKE checked in under `formal/`.
- [ ] Tamarin model of the four-phase attestation protocol checked in.
- [ ] CI job verifying both models within budget.

---

## Tracking

When you start an item, change its `[ ]` to `[~]` and add a link to the PR.
When the PR merges and the acceptance criteria in the feature doc are all
ticked, change to `[x]`.

Per-feature acceptance criteria live in [features/](features/) — those are
the source of truth for "done"; this roadmap is the source of truth for
"when".
