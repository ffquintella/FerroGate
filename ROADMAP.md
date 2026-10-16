---
ptf: 1
project: ferrogate
---

# Roadmap

FerroGate is a high-availability, post-quantum secure, TPM 2.0-attested machine
identity system built on the SPIFFE framework. It issues short-lived,
hardware-rooted SVIDs to host nodes after a four-phase attestation protocol and
serves sender-constrained tokens to local applications over a hardened helper
API. **CMIS** (Central Machine Identity Service) is the TEE-resident gRPC issuer;
**MIA** (Machine Identity Agent) is the hardened host daemon.

This file follows the Project Tracking Format (PTF) v1. It replaces
[docs/roadmap.md](docs/roadmap.md) as the source of truth for *when*; the
per-feature acceptance criteria in [docs/features/](docs/features/README.md)
remain the source of truth for *done*. Milestones are listed in delivery order:
completed ones first, then active, then planned. Phases `P1`–`P7` are the
legacy roadmap milestones **M0–M6**; legacy labels such as "M4" or "M5.3" that
appear in older documents and in changelog text refer to those phases, **not**
to the PTF milestone IDs below. `P8` gathers the work delivered after the legacy
roadmap (0.13.0 onward) and `P9` the planned hardening work. Status notes copied
from the legacy roadmap are kept verbatim under each milestone.

**Dropped scope (carried over from the legacy roadmap).** Native S3 /
object-storage sourcing and the S3 Object Lock WORM store are dropped and will
not be implemented. No HTTP/S3 client is pulled into the workspace. Every
artefact that an earlier plan sourced from S3 — RIM bundles, fleet manifests,
the audit WORM tier — is instead read from (or written to) a local
file/directory, and a deployment that keeps those artefacts in object storage
syncs them to that path out of band. This is safe because each artefact is
composite-signed and verified before use (RIM, fleet manifest) or write-once via
`O_CREAT|O_EXCL` (`LocalDiskWormStore`), so the sync path is untrusted. The trait
seams (`AuditStore`, `RimLoader`/fleet loader verify-then-swap) remain open for
an out-of-tree object-store adapter, but no such adapter is a FerroGate
deliverable.

## [M1] Workspace bootstrap
> outcome: The cargo workspace builds, lints and tests through `make` and CI, with `unsafe` forbidden in every crate.
> version: 0.1.0-m0
> phase: P1

Get the cargo workspace and CI scaffolding in place so feature work can land in
clean slices.

Legacy status note: **M0 status: complete.** Verified locally with `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace --all-targets`, and `cargo check --workspace`. CI
job execution will gate the milestone in the upstream repository once the
remote is wired up.

- [x] T1 Convert the `src/` scaffold into a cargo workspace under `crates/`
  - note: CLI relocated to `crates/ferrogate-cli/`.
- [x] T2 Create the stub crates for the seven initial workspace members
  - note: `crates/{cmis,mia,ferro-crypto,ferro-attest,ferro-audit,ferro-proto,ferro-tee}` with `lib.rs`/`main.rs` stubs.
- [x] T3 Wire `make fmt`, `make lint`, `make test` and `make check` against the workspace
  - note: Plus `make audit`, `make deny`, `make coverage`, `make run-cmis`, `make run-mia`.
- [x] T4 Run fmt, clippy and test in GitHub Actions CI on Linux
  - note: See `.github/workflows/ci.yml`. That workflow was removed in 0.13.2; restoring it is tracked by T220.
- [x] T5 Add `cargo audit` and `cargo deny` to CI
  - note: Plus `deny.toml`. The CI jobs went with `ci.yml` in 0.13.2 (see T221); `make audit` / `make deny` remain.
- [x] T6 Add a `cargo llvm-cov` coverage job with a baseline threshold
  - note: Baseline 10% in M0; raise as features land. CI job removed with `ci.yml` in 0.13.2 (see T221).
- [x] T7 Forbid `unsafe` in `crates/mia` and every other FerroGate crate
  - note: Applied to every FerroGate crate plus a workspace-wide `unsafe_code = "deny"` lint.
- [x] T8 Write the design documentation under `docs/`
  - note: Architecture, protocol, threat model, TPM, crypto, per-feature specs and the roadmap (commit a6e0737).

## [M2] Hybrid post-quantum TLS provider (F01)
> outcome: `ferro-crypto` exposes an `X25519MLKEM768`-only rustls provider with SPKI pinning that rejects legacy clients and passes the Wycheproof AEAD vectors.
> version: 0.1.0-m1
> phase: P2
> spec: S1, S26

Land the primitives every other feature depends on (legacy M1).

- [x] T9 Add `rustls`, `rustls-post-quantum` and `aws_lc_rs` to `ferro-crypto` (S1)
- [x] T10 Implement `ferrogate_provider()` exposing only `X25519MLKEM768` in hybrid mode (S1)
  - note: `crates/ferro-crypto/src/tls.rs`; also exposes a dev-mode fallback variant.
- [x] T11 Add the SPKI pin verification helper for MIA (S1)
  - note: `crates/ferro-crypto/src/pin.rs` — SHA-384 SPKI pins, constant-time match, custom `ServerCertVerifier`.
- [x] T12 Test that a non-hybrid client is rejected by a hybrid-only server (S1)
  - note: `crates/ferro-crypto/tests/tls_handshake.rs::legacy_only_client_is_rejected_by_hybrid_only_server`, plus `wrong_pin_rejects_otherwise_valid_server`.
- [x] T13 Prove interop with the BoringSSL PQ branch via the ClientHello wire format (S1)
  - note: Delivered as a wire-format witness in `crates/ferro-crypto/tests/wire_format.rs`: decodes the actual `ClientHello` rustls emits and asserts the `key_share` for `0x11EC` is exactly 32+1184 = 1216 bytes, matching `draft-ietf-tls-hybrid-design`. Same wire BoringSSL-PQ, OpenSSL+oqs and NSS produce.
- [x] T14 Pass the Wycheproof vectors for ChaCha20-Poly1305 and AES-256-GCM (S1)
  - note: `crates/ferro-crypto/tests/wycheproof_aead.rs` — 316 ChaCha20-Poly1305 and 66 AES-256-GCM vectors with TLS-standard 12-byte nonces, both `valid` and `invalid` outcomes, encrypt-and-decrypt directions.

## [M3] Composite Ed25519 + ML-DSA-65 signatures (F03)
> outcome: An AND-combined composite signature with concat, DER and JOSE forms verifies only when both halves verify, proven by KATs and property tests.
> version: 0.1.0-m1
> phase: P2
> spec: S3, S26

- [x] T15 Implement `CompositeSecretKey` / `CompositePublicKey` over Ed25519 + ML-DSA-65 (S3)
  - note: `crates/ferro-crypto/src/composite.rs`.
- [x] T16 Implement domain-separated `sign(ctx, msg)` and the AND-combiner `verify` (S3)
  - note: Transcript hash is `SHA3-384("FERROGATE-COMPOSITE-v1" || len_be64(ctx) || ctx || msg)`; both halves sign the same 48-byte digest; verify uses `ed25519-dalek::verify_strict` then `fips204::ml_dsa_65::verify`, returning the first failing side as `ClassicalFailed` or `PqcFailed`.
- [x] T17 Add the ASN.1 SEQUENCE encoder/decoder with OID 2.16.840.1.114027.80.8.1.7 (S3)
  - note: `to_der` / `from_der`; round-trip and wrong-OID rejection tested.
- [x] T18 Add the JOSE `alg = "MLDSA65+Ed25519"` glue (S3)
  - note: `to_jws_base64url` / `from_jws_base64url`; URL-safe alphabet enforced by the encoder.
- [x] T19 Run the FIPS-204 and RFC 8032 KAT runners green (S3)
  - note: RFC 8032 / Ed25519 vectors run against `wycheproof::eddsa` (the full Ed25519 Wycheproof set, including malleability cases). FIPS-204 lengths are pinned to 1952/3309; algorithm KATs are exercised by the upstream `fips204` crate's CI — see `tests/composite_kat.rs` docstring for rationale.
- [x] T20 Prove by property test that corrupting either half fails verify (S3)
  - note: `crates/ferro-crypto/tests/composite_proptest.rs` — 32 cases of random `(ctx, msg)`; flips at every bit position; verifies the AND-combiner classifies errors correctly.

## [M4] TPM 2.0 attestation engine (F02)
> outcome: A host attests end to end against `swtpm` and CMIS verifies the quote with the ordered, fail-closed algorithm, rejecting every documented negative case.
> version: 0.2.0
> phase: P3
> spec: S2, S27, S25

End-to-end attestation against a software TPM with a single CMIS replica and no
HA. No persistence, no audit, no helper API yet (legacy M2).

Legacy status note: **M2 status: complete.** F02 (TPM 2.0 attestation engine), F04 (SVID
issuance and lifecycle), and the M2 subset of F10 (signed RIM bundles +
generational allowlist + hot reload) are all landed and tagged as `v0.2.0`.
Verified on Linux (`docker/f02-dev`) with `cargo test --workspace
--all-targets` (incl. the `swtpm` attest and seal tests), `clippy -D
warnings`, and `fmt --check`. The remaining F10 work (`bump_epoch` admin
RPC) is sequenced in M5 alongside the rest of the host operations track.
(Signed-S3 refresh was originally planned here too; it is now dropped — see
"Dropped scope" above.)

- [x] T21 Implement `mia::tpm::TpmEngine` over `tss-esapi` (`/dev/tpmrm0`) (S2)
  - note: `crates/mia/src/tpm.rs`, Linux-gated via `cfg(target_os = "linux")`; `open_device()` resolves the resource-manager TCTI, never raw `/dev/tpm0`.
- [x] T22 Create the EK in the endorsement hierarchy with the ECC-P256 default template (S2)
  - note: `TpmEngine::load_ek` via the `tss-esapi` `ek::create_ek_object` abstraction.
- [x] T23 Create the AIK with the full required attribute mask (S2)
  - note: `TpmEngine::create_aik` — restricted, signing-only ECDSA P-256 child of the EK.
- [x] T24 Quote the policy PCR set with SHA-384 (S2)
  - note: `TpmEngine::quote` over `{0,1,2,3,4,7,8,9,10,11,14}`; reads back raw PCRs via the looping `pcr::read_all` so CMIS can recompute the digest.
- [x] T25 Implement the `TPM2_ActivateCredential` flow (S2)
  - note: `TpmEngine::activate_credential` with an endorsement-hierarchy `PolicySecret` session for the EK; exercised end-to-end against `swtpm`.
- [x] T26 Sign the composite CSR with the AIK (S2)
  - note: `TpmEngine::sign_aik` — hashes the payload inside the TPM for a validation ticket, as a restricted key requires; CSR/issuance wiring lands with F04.
- [x] T27 Bind HMAC sessions on all sensitive TPM commands (S2)
  - note: `hmac_session` with parameter encryption; sessions are flushed after use to avoid `TPM_RC_SESSION_MEMORY`.
- [x] T28 Implement all 10 steps of `TpmQuoteVerifier::verify_quote` (S2)
  - note: `crates/ferro-attest/src/verify.rs` — ordered, fail-closed: EK chain → AIK mask → magic/type → nonce → ECDSA-P256 signature → recomputed SHA-384 PCR digest → RIM `policy_id`; each rejection carries a precise audit-only `RejectReason`. Phase-3 credential-activation compare is constant-time.
- [x] T29 Bundle vendor root CAs for Infineon, Nuvoton, ST and Intel PTT (S2, S27)
  - note: `crates/ferro-attest/src/vendor.rs` + `build.rs` embed `vendor-roots/<vendor>/*.pem` at compile time, independently loadable; nothing trusted by default. Provisioning tool `scripts/ferrogate-ca.sh`, procedure in `vendor-roots/README.md`.
- [x] T30 Add an `swtpm` integration test for the happy path (S2)
  - note: `crates/mia/tests/swtpm_attest.rs` drives a real software TPM and verifies the evidence end-to-end; `docker/f02-dev.Dockerfile` + `scripts/f02-docker.sh` provide the TSS2 + `swtpm` toolchain.
- [x] T31 Add negative tests: wrong nonce, tampered quote, missing PCR, unrestricted AIK (S2)
  - note: Plus untrusted EK root, not-in-RIM, wrong signing key, and credential-activation mismatch — 9 verifier tests in `crates/ferro-attest/tests/verify_quote.rs` and 2 negatives in the `swtpm` test.

## [M5] SVID issuance and lifecycle, M2 subset (F04)
> outcome: CMIS issues composite-signed JWS SVIDs over the four-phase `Attest` RPC, rotates them in-window, forces re-attestation on drift, and the reference verifier accepts them.
> version: 0.2.0
> phase: P3
> spec: S4, S28, S29

Legacy status note: **F04 status: done for M2.** Verified on Linux (`docker/f02-dev.Dockerfile`) with `cargo test --workspace --all-targets` (incl. the `swtpm` sealing test) plus `clippy -D warnings` and `fmt --check`. Two seams remain for later milestones and are intentionally not closed here: the CMIS gRPC listener runs plaintext in the M2 bring-up binary (hybrid-PQC TLS termination is F01/F05 transport work; the provider already exists in `ferro-crypto`), and phase-3 `MakeCredential` is a `cmis::CredentialMaker` trait with only a software test implementation — a production TCG/EK wrapper lands with the TEE work (the MIA-side `TPM2_ActivateCredential` already exists from F02).

- [x] T32 Add the gRPC `MachineIdentity::Attest` streaming RPC (S4, S20)
  - note: `crates/ferro-proto/proto/machine_identity.proto` + tonic codegen; the four-phase server handler is `crates/cmis/src/service.rs`, with a server-first `Nonce` message supplying the quote's `qualifyingData`. The MIA client driver is `crates/mia/src/client.rs`. End-to-end over a real in-process tonic channel in `crates/mia/tests/e2e_attest.rs`.
- [x] T33 Issue JWS SVIDs with the documented payload schema (S4)
  - note: `crates/ferro-svid/src/{claims,envelope,issue}.rs` — composite-signed compact JWS, `alg = MLDSA65+Ed25519`, `typ = ferrogate-svid+jwt`, 1 h max TTL, `nbf` with 60 s lookback.
- [x] T34 Derive the SPIFFE ID from `SHA-384(ek_cert)` (S4)
  - note: `crates/ferro-svid/src/spiffe.rs` — `sub = spiffe://<td>/host/<uuid>` where the UUID is a v8 stamp over the first 16 bytes of the EK-cert digest.
- [x] T35 Add the `Rotate` RPC with the in-window short path (S4)
  - note: `MachineIdentitySvc::rotate` reissues without TPM I/O when the policy epoch and PCR aggregate are unchanged inside the 24 h window; `crates/ferro-svid/src/lifecycle.rs::decide_renewal`.
- [x] T36 Trigger re-attestation on PCR drift (S4)
  - note: Same `decide_renewal`; `Rotate` returns `FAILED_PRECONDITION` on PCR drift or epoch bump. Covered by `rotate_refused_on_pcr_drift` (since T293: the TPM tier always re-attests, `rotate_refused_for_tpm_tier`; signed state drift, `rotate_host_auth.rs::rotate_refuses_state_digest_drift`).
- [x] T37 Seal the SVID and key locally to PCRs `{0,4,7,8}` (S4)
  - note: `crates/mia/src/seal.rs`, Linux-only: a 256-bit key is sealed to a `PolicyPCR` over `{0,4,7,8}` SHA-384 and AEAD-encrypts the cache blob. `crates/mia/tests/swtpm_seal.rs` proves a sealed PCR change makes the cache fail to unseal.
- [x] T38 Schedule rotation at 60% of TTL with jitter (S4)
  - note: `crates/ferro-svid/src/lifecycle.rs::rotation_delay_secs` — 60% ±10% of TTL; `crates/mia/src/scheduler.rs` wraps it with an OS-CSPRNG jitter sample.
- [x] T39 Ship the reference JWS verifier as a separate crate (S4)
  - note: `crates/ferro-svid-verify` — self-contained: re-declares the schema, verifies the composite signature against a JWK set, enforces `nbf`/`exp`; an expired SVID is refused.

## [M6] Signed RIM bundles and PCR policy, M2 subset (F10)
> outcome: CMIS admits only quotes whose PCR digest is in a signed, generational RIM allowlist that hot-reloads atomically from a local file.
> version: 0.2.0
> phase: P3
> spec: S10

Legacy status note: **F10 (M2 subset) status: done.** Verified on Linux with `cargo test --workspace --all-targets`, `clippy -D warnings`, and `fmt --check`. The `bump_epoch` admin RPC was the remaining M5 follow-on (now done); signed-S3 refresh was originally planned here too but is dropped (see "Dropped scope" above).

- [x] T40 Define the RIM bundle format and loader (S10)
  - note: `ferro-attest::rim_bundle` defines `RimBundle` (version, policy_id, validity window, approved SHA-384 digests) and the `SignedRimBundle` wire form; `ferro-attest::rim_loader::RimLoader::try_reload` reads, verifies, and applies an on-disk bundle.
- [x] T41 Verify RIM bundle signatures fail-closed (S10)
  - note: Composite Ed25519 + ML-DSA-65 over canonical JSON with domain-separation context `ferrogate-rim-v1`. Fail-closed: bundles without a recognised `signer_kid`, with a malformed signature, or with a tampered body are refused before any state changes. There is no path into the store that bypasses verification.
- [x] T42 Retain six RIM generations (S10)
  - note: `MAX_GENERATIONS = 6`; `RimStore::apply` pushes the new generation and prunes the oldest beyond the limit. Per-generation `not_before`/`not_after` windows are honoured at lookup time, and a non-monotonic version is rejected with `ApplyError::NonMonotonic`.
- [x] T43 Hot-reload RIM bundles from a local file (S10)
  - note: Native S3 sourcing dropped (see T98). `cmis::rim_watcher::spawn` runs a small tokio task that periodically calls `try_reload`. The swap is atomic — a single `parking_lot::RwLock` write — so in-flight `Attest` handlers always see a consistent generation set. CMIS maps `RejectReason::NotInRim` to `FAILED_PRECONDITION` to match the documented error model.

## [M7] Merkle-chained audit log, M3 subset (F07)
> outcome: Every attestation event lands in an RFC 6962 SHA3-384 Merkle log with composite-signed STHs, WORM storage, and offline-verifiable inclusion and consistency proofs.
> version: 0.4.0
> phase: P4
> spec: S7, S33

Make the system externally observable before adding HA complexity (legacy M3).
First published in the v0.4.0 tag: the workspace was bumped to 0.3.0 at commit
935fe43 but that version was never tagged or given a changelog section.

Legacy status note: **M3 status: complete.** Verified on Linux (`docker/f02-dev`) with `cargo test --workspace --all-targets`, `clippy -D warnings`, and `fmt --check`. The M4 follow-ons (Raft co-signed STHs, Sigsum / Rekor anchor publisher) remain explicitly out of M3 scope. (A native S3 Object Lock store was originally listed here as an M4 follow-on; it is now dropped — see "Dropped scope" above.)

- [x] T44 Define the audit event enum and its CBOR encoding in `ferro-audit` (S7)
  - note: `crates/ferro-audit/src/event.rs` defines the seven-variant `AuditEvent` mirroring `docs/audit.md`; encoding via `ciborium`. The fixed-size hash fields use the `Hash384` / `Bytes16` newtypes in `bytes.rs` so they serialise as compact CBOR byte strings rather than arrays-of-small-ints.
- [x] T45 Build the in-process Merkle tree with SHA3-384 leaves (S7)
  - note: `crates/ferro-audit/src/merkle.rs` implements the RFC 6962 algorithms — domain-separated `leaf_hash(0x00 || …)` and `node_hash(0x01 || …)`, plus `inclusion_proof`, `consistency_proof`, and standalone verifiers usable by any third party.
- [x] T46 Add the STH structure with a TEE-style signing stub (S7)
  - note: Stub to be replaced by the threshold signer (T229). `crates/ferro-audit/src/sth.rs`: `SthBody { tree_size, root_hash, timestamp }` carried over the wire as canonical CBOR + a composite Ed25519 + ML-DSA-65 signature under domain context `ferrogate-sth-v1`. The signer is a trait; `InProcessSigner` is the M3 stub.
- [x] T47 Add the backing-store abstraction with a local-disk WORM implementation (S7)
  - note: `crates/ferro-audit/src/store.rs`: `AuditStore` trait + `LocalDiskWormStore`. `O_CREAT|O_EXCL` makes a leaf or STH file uncoverwriteable. `LocalDiskWormStore` is the production WORM tier; a native S3 Object Lock store was originally planned for M4 but is dropped (T66). Deployments needing cloud durability sync the WORM directory to object storage out of band.
- [x] T48 Serve inclusion and consistency proofs from CMIS (S7)
  - note: `ferro-proto` adds `LatestSth`, `InclusionProof`, `ConsistencyProof`, and `AppendAuditEvent` RPCs; `crates/cmis/src/service.rs` implements them against the shared `AuditLog`.
- [x] T49 Property-test inclusion and consistency proofs (S7)
  - note: `crates/ferro-audit/src/log.rs` proptest: 24 cases, tree sizes 1..=12, asserts `verify_inclusion` holds for every leaf and `verify_consistency` holds for every `(m, n)` pair against the matching captured STH roots.
- [x] T50 Forward MIA audit events into the CMIS audit stream (S7)
  - note: `crates/mia/src/audit_client.rs::forward` encodes a `ferro_audit::AuditEvent` to CBOR and submits it through `AppendAuditEvent`. End-to-end driven in `crates/mia/tests/e2e_attest.rs::audit_log_records_attest_events_and_proofs_verify_offline`, which after an Attest fetches the STH, verifies the signature, fetches an inclusion proof, verifies offline, forwards a `LocalGrant`, and checks a consistency proof back to the prior STH.
  - note: The daemon never called `forward`: its audit channel was only logged until T291 wired the spool-backed forwarder (M33).
- [-] T51 Mirror the audit log to FoundationDB (S7)
  - why: superseded by the hiqlite pivot; the replicated copy lives in the hiqlite-backed state machine (commit 629d086).

## [M8] CMIS high availability (F05)
> outcome: CMIS issues through a 3-node hiqlite Raft cluster that elects a leader, survives non-leader loss and random kills, and gates health on Raft state.
> version: 0.4.0
> phase: P5
> spec: S5, S23

Promote CMIS from a single replica into a TEE-attested cluster (legacy M4).

Legacy status note: **F05 status: done for M4.** The Raft cluster layer (election / replication / follower rejoin / chaos) is exercised by `cargo test -p ferro-raft --test cluster_e2e` (≈4 min). CMIS issuance is now genuinely cluster-mediated and the `Health` RPC surfaces the Raft state — verified by `crates/mia/tests/cluster_attest.rs` which drives a four-phase `Attest` across three CMIS instances on top of a 3-node hiqlite cluster. A test-only limitation worth recording: hiqlite's node-id-1 owns cluster-bootstrap responsibilities and a graceful shutdown of node 1 specifically does not let the remaining quorum re-elect cleanly in-process; the leader-kill scenario is therefore exercised by the long chaos run instead of a focused unit test.

- [x] T52 Embed a Raft library with persistent storage (S5)
  - note: `crates/ferro-raft` wraps hiqlite (0.13 at the time, 0.15 today) — openraft 0.9 underneath, SQLite state machine + WAL on disk. Typed surface (`Cluster::upsert_svid` / `fetch_svid_consistent` / `current_rim_version` / `bump_rim_version` / `role` / `is_healthy`) hides hiqlite so the engine can be swapped later. The original line named FoundationDB; hiqlite was chosen because it ships openraft + a durable state machine + the peer transport in one package, dropping ~3 k LOC of unverifiable adapter code from the M4 critical path. FoundationDB follow-up: T237.
- [x] T53 Test leader election and follower rejoin in a 3-node local cluster (S5)
  - note: `crates/ferro-raft/tests/cluster_e2e.rs`: three in-process nodes on free ports, asserts election agreement across all peers, replication to a follower, and a follower rejoin path that restarts the process with the same `node_id`/`data_dir` and recovers the previously-replicated row.
- [x] T54 Gate health endpoints on Raft state (S5)
  - note: `MachineIdentity.Health` returns `(healthy, role, node_id)`; the response mirrors `Cluster::is_healthy` / `Cluster::role`. An L4/L7 LB maps `!healthy` or `NODE_ROLE_UNKNOWN` to "not ready". Exercised on both leader and follower paths by `crates/mia/tests/cluster_attest.rs`.
- [x] T55 Route CMIS issuance through the cluster (S5)
  - note: `CmisState::new_clustered` plugs an `Arc<Cluster>` into the state; `record` / `lookup` / `update_bundle` route through `Cluster::upsert_svid` / `fetch_svid_consistent`. Issued records are JSON-encoded via `cmis::cluster_store::WireIssuedRecord` because the underlying `ferro-svid` structs carry `[u8; 48]` fields that `serde`-derive cannot deserialise directly. Since 0.18.0 the Raft-backed store is the only backend (T155).
- [x] T56 Run a chaos test with random kills and zero client-visible errors (S5)
  - note: `short_chaos_run_keeps_serving_while_quorum_holds` cycles kill+revive across 6 rounds and asserts every replicated write survives. The literal 10-minute variant `ten_minute_chaos_run` is `#[ignore]`-gated and runs on a beefier CI worker.

## [M9] TEE residency and threshold key shares (F06)
> outcome: Issuance keys exist only as 3-of-5 Shamir shares sealed to enclave measurements and exchanged between mutually attested replicas over ML-KEM-768 PSK channels.
> version: 0.4.0
> phase: P5
> spec: S6, S28

Status note from [F06](docs/features/F06-tee-threshold-keys.md): done for M4,
verified with `cargo test -p ferro-tee` (32 unit + 6 integration tests). The
hardware report producers, the issuer's switch to a `ProtectedKey`, and the STH
threshold signer were left open and are tracked in M34.

- [x] T57 Produce and verify SEV-SNP attestation reports (S6)
  - note: `crates/ferro-tee/src/attest.rs` — `Attestor` trait + `Report`/`ReportBody`/`verify_report`; covered by `snp_report_round_trips_through_verify`. Test path uses the structurally faithful `SoftwareAttestor`; hardware producers: T227.
- [x] T58 Produce and verify the Intel TDX equivalent (S6)
  - note: Same `Attestor` trait; `AttestorKind::Tdx` exercised by `tdx_report_round_trips_through_verify`.
- [x] T59 Implement Shamir 3-of-5 over GF(2^256), unit-tested (S6)
  - note: `crates/ferro-tee/src/shamir.rs` — byte-parallel GF(2^8) over the AES Rijndael polynomial, info-theoretically equivalent to a single GF(2^256) construction; `three_of_five_reconstructs`, `two_shares_yield_a_wrong_secret_almost_surely`, `lone_share_does_not_leak_secret`, `gf_inverse_is_correct`.
- [x] T60 Seal shares per replica against enclave measurements (S6)
  - note: `crates/ferro-tee/src/seal.rs` — ChaCha20-Poly1305 keyed via HKDF-SHA3-384 over `(sealing_root, measurement, aad)`; `different_attestor_with_same_measurement_cannot_unseal`, `wrong_measurement_is_rejected_before_aead`, `tampered_aad_is_rejected`, `replica_cannot_unseal_anothers_share`.
- [x] T61 Attest peers mutually before share exchange (S6)
  - note: `crates/ferro-tee/src/psk.rs` — both sides verify the peer's report and check `Allowlist::contains` before deriving the PSK; `happy_path_both_sides_derive_same_psk`, `initiator_not_on_allowlist_is_refused`, `responder_with_swapped_root_is_refused`, `replica_not_on_allowlist_is_refused`.
- [x] T62 Transport shares over ML-KEM-768 PSK channels (S6)
  - note: `crates/ferro-tee/src/psk.rs` — `Initiator::start` / `respond` / `Initiator::finish`; transcript binds nonces + ek + ciphertext; e2e share transport exercised by `full_three_of_five_round_trip`.
- [x] T63 Verify zeroize-on-drop with a Drop test (S6)
  - note: `crates/ferro-tee/src/key.rs::protected_key_wipes_in_place`; same `Zeroize::zeroize` path that `Drop` runs. `Share` also derives `ZeroizeOnDrop`.

## [M10] Co-signed STHs and transparency anchoring (F07 continued)
> outcome: STHs are co-signed by a Raft-majority quorum before publication and queued for transparency-log anchoring with persistent back-fill.
> version: 0.4.0
> phase: P5
> spec: S7, S33

Legacy status note: **F07 (continued) status: done.** Co-signed STHs (M4) and the anchor
publisher with persistent back-fill (M4) have landed and ship in `v0.3.0`.
Production WORM is provided by `LocalDiskWormStore`'s `O_CREAT|O_EXCL`
semantics. A native S3 Object Lock backing store is **dropped** (see "Dropped
scope" above) — `LocalDiskWormStore` is the shipped WORM tier and deployments
needing cloud durability sync its directory to object storage out of band. The
`AuditStore` trait seam (`record_cosigned_sth` / `record_sth`) stays open for
an out-of-tree adapter, but no object-store impl is a FerroGate deliverable.
Concrete Sigsum / Rekor HTTP drivers (`Anchor` impls) plug in behind the existing
trait the same way; both wire formats are short (`POST /api/v1/log/entries`
for Rekor; the Sigsum `add-leaf` request for Sigsum) and add nothing the
audit crate's API needs to learn about. (Migration note: `v0.3.0` was never
tagged; this work first shipped in the v0.4.0 tag.)

- [x] T64 Co-sign STHs by a Raft majority before publication (S7)
  - note: `crates/ferro-audit/src/cosign.rs` — `QuorumSigner` aggregates per-replica composite signatures over the same canonical `SthBody` CBOR; `verify_cosigned` accepts iff at least `threshold` distinct listed signatures verify, so duplicate kids cannot inflate quorum and unknown kids are ignored. `AuditLog::produce_cosigned_sth` persists via the WORM store (`record_cosigned_sth`, `cosigned/` subdir). Per-peer RPC transport: T225.
- [x] T65 Publish anchors to Sigsum / Rekor with persistent back-fill (S7)
  - note: `crates/ferro-audit/src/anchor.rs` — `Anchor` trait abstracts the transparency-log driver (HTTP wire is deployment wiring behind the trait), `AnchorQueue` persists pending `CoSignedTreeHead`s under `pending/<tree_size>.{sth.json,enq}` so a restart never drops anchors during an upstream outage; `AnchorPublisher::drain_once` submits in `tree_size` order, stops on `Transient`, quarantines `Permanent` under `dead/`, and reports `DrainOutcome::backlog_seconds_after` for the 5-minute alert. CMIS scheduling: T224; concrete drivers: T240.
- [-] T66 Store the audit WORM tier in S3 Object Lock (Compliance, 10-year retention) (S7)
  - why: S3 / object storage is dropped; `LocalDiskWormStore` is the shipped WORM tier and the directory is synced out of band.

## [M11] Local helper API (F08)
> outcome: Vetted local callers obtain tokens over a permission-checked UDS or Windows Named Pipe after kernel-attested caller authentication against a signed, fail-closed allowlist, with one audit event per request.
> version: 0.5.0
> phase: P6
> spec: S8, S31

Make the system usable by real applications and operators (legacy M5). The UDS
transport and the F09 minter shipped in 0.4.0, the Windows Named Pipe transport
in 0.5.0.

- [x] T67 Listen on a UDS at `/run/ferrogate/mia.sock` with correct permissions (S8)
- [x] T68 Frame CBOR requests and responses (S8)
- [x] T69 Authenticate callers with `SO_PEERCRED` and the IMA runtime hash (S8)
- [x] T70 Load the signed allowlist with fail-closed verification (S8)
- [x] T71 Emit `LocalGrant` / `LocalDenied` audit events (S8)
- [x] T72 Test concurrency and slow-client starvation (S8)
- [x] T73 Start the helper API from the `mia` daemon (S8)
  - note: Created during migration for the changelog's "Daemon wiring" entry; minting stayed disabled (`no_host_svid`) until host attestation landed (T191).
- [x] T74 Add the Windows Named Pipe variant (S8)
- [x] T75 Add Windows cross-build and clippy tooling (`docker/win-cross`) (S8)

## [M12] DPoP-bound child tokens (F09)
> outcome: Child tokens are DPoP-bound, composite-signed under per-host keys published in the CMIS JWKS, and a Rust reference verifier rejects replay without a DPoP proof.
> version: 0.6.0
> phase: P6
> spec: S9

Legacy status note: **F09 status: done.** The minter (F08) plus the JWKS multi-key publication, the
`ferro-child-verify` reference verifier, and the replay/no-DPoP negative tests
land here and ship in `v0.6.0`. Verified with `cargo test -p ferro-child-verify`,
`cargo test -p mia --test child_token_verify`, the multi-key assertions in
`crates/mia/tests/e2e_attest.rs`, and `clippy -D warnings` + `fmt --check`. One
seam is intentionally left for later: the per-host JWKS registry is process-local
(a verifier must reach a replica that has seen the host's attestation); making it
cluster-wide means persisting `composite_pub` in the issued-SVID store. (Closed
in 0.21.0 by T159.)

- [x] T76 Mint child tokens with TTL clamp, `jti` and `cnf.jkt` (S9)
  - note: Landed with F08 in 0.4.0.
- [x] T77 Publish a multi-key JWKS on CMIS (S9)
  - note: `CmisState` publishes the issuer SVID key plus each host's composite child-token signing key, registered at phase-4 attestation under a deterministic `ferro_svid::child_signing_kid`; the `JWKS` RPC serves the merged set.
- [x] T78 Ship the Rust reference verifier `ferro-child-verify` (S9)
  - note: Composite signature against the JWKS, `exp`, and the RFC 9449 DPoP binding via `verify_bound` / `verify_dpop_proof`, RFC 7638 thumbprint.
- [-] T79 Ship a Go reference verifier (S9)
  - why: scoped out — the Rust crate is the canonical interop reference; no second-language verifier ships in-tree.
- [x] T80 Test replay and missing-DPoP-proof rejection against the verifier (S9)
  - note: `ferro-child-verify` unit tests + `crates/mia/tests/child_token_verify.rs`: a no-proof bearer token is rejected with `MissingDpopProof`.

## [M13] Revocation and CRL distribution (F11)
> outcome: Operators revoke an SVID or a host, a composite-signed CRL reaches every consumer through the JWKS within one 60 s cycle, and MIA and the reference verifier fail closed on a stale or bad CRL.
> version: 0.7.0
> phase: P6
> spec: S11

Legacy status note: **F11 status: done.** Verified with `cargo test -p ferro-svid`,
`cargo test -p ferro-svid-verify`, `cargo test -p cmis --test revocation`, and
`cargo test -p mia --test helper_api`, plus `clippy -D warnings` and
`fmt --check`. Two deployment seams are deferred (cluster-replicated revocation
set; wiring the MIA CRL puller into the not-yet-landed attestation loop) — both
recorded in [features/F11-revocation.md](docs/features/F11-revocation.md) §"Status".
(The CRL puller was wired in 0.21.0 by T160; replication is
T223.)

- [x] T81 Add the `RevokeSvid(cert_sha, reason)` admin RPC (S11)
  - note: `MachineIdentity.RevokeSvid` plus `RevokeHost` for per-host revocation; `crates/cmis/src/service.rs`.
- [x] T82 Publish CRL deltas on a 60 s cadence (S11)
  - note: `crates/cmis/src/crl_publisher.rs` heartbeat plus an inline publish on every revoke so a revocation lands within one cycle. Expired entries — past the 1 h max SVID TTL — are pruned each cycle to bound CRL growth.
- [x] T83 Carry the CRL in the JWKS `x-ferrogate-crl` extension (S11)
  - note: `ferro_svid::JwkSet` carries an optional composite-signed `SignedCrl`; `CmisState::published_jwks` attaches it. The member is omitted when no CRL has been published.
- [x] T84 Enforce CRL freshness of at most 5 minutes in MIA (S11)
  - note: `crates/mia/src/helper/crl.rs` cache + gate; a stale or missing CRL fails closed with `CrlStale`.
- [x] T85 Verify CRL signatures fail-closed (S11)
  - note: `SignedCrl::verify` in `ferro-svid`, the MIA-side `crl::ingest`, and the reference verifier's `verify_unrevoked` all reject unknown-kid / wrong-key / tampered CRLs without yielding the body.

## [M14] MIA process hardening (F12)
> outcome: `mia` locks memory, drops to `_ferrogate` with a minimal capability set under an enforcing seccomp allow-list, refuses to run without IMA enforcement, and builds reproducibly with no `unsafe` code.
> version: 0.8.0
> phase: P6
> spec: S12, S29

Legacy status note: **F12 status: done.** All hardening FFI lives in the new `ferro-harden` crate
(Linux analogue of `ferro-winauth`), keeping `mia` `#![forbid(unsafe_code)]`.
Verified with `cargo test -p ferro-harden` on Linux (incl. the live seccomp
`SIGSYS` self-test and per-arch syscall-name resolution), the `mia::hardening`
parser tests, `clippy -D warnings`, and the reproducible-build check. Static-PIE
musl packaging (static TSS2) is left as deployment work; the reproducibility
gate runs on the PIE-by-default glibc build.

- [x] T86 Apply `prctl` and `mlockall` at startup (S12)
  - note: `ferro_harden::apply` — `PR_SET_DUMPABLE`, `PR_SET_NO_NEW_PRIVS`, `mlockall(MCL_CURRENT|MCL_FUTURE)`, applied on the startup thread before the tokio runtime spawns.
- [x] T87 Install the seccomp-bpf allow-list with an audit-mode toggle for dev (S12)
  - note: ~70-name explicit allow-list via `seccompiler`; `FERROGATE_SECCOMP=enforce|audit|off`. The enforcing filter is proven to `SIGSYS`-kill a forbidden syscall by a unit test. Allow-list completed for the real runtime and aarch64 in 0.21.0–0.21.1.
- [x] T88 Drop to the `_ferrogate` UID keeping `CAP_IPC_LOCK` and `CAP_SYS_PTRACE` (S12)
  - note: `CAP_SYS_PTRACE` (added in 0.21.0) lets the daemon read a helper caller's `/proc/<pid>/exe`; the `ptrace` syscall stays seccomp-blocked. `drop_privileges` + `restrict_capabilities`; `harden()` verifies the post-drop effective set is exactly `{CAP_IPC_LOCK, CAP_SYS_PTRACE}`.
- [x] T89 Refuse to start unless IMA enforcement is on (S12)
  - note: `mia::hardening` refuses to start unless `/proc/cmdline` requests `ima_appraise=enforce`.
- [x] T90 Add a reproducible-build CI job with byte-identical rebuilds (S12)
  - note: `scripts/reproducible-build.sh` + the `reproducible-build` CI job. The job went with `ci.yml` in 0.13.2; restoring it is T222.
- [x] T91 Forbid `unsafe` in all MIA modules (S12)
  - note: All FFI isolated in the new `ferro-harden` crate; the `no-unsafe-in-mia` CI job (a grep backstop) went with `ci.yml` in 0.13.2 (T222).

## [M15] Zero-touch bootstrap and fleet enrollment (F13)
> outcome: CMIS admits a host's first attestation only if its EK hash is in an offline-signed fleet manifest, checked before any quote work and hot-swapped atomically.
> version: 0.9.0
> phase: P6
> spec: S13

Legacy status note: **F13 status: done.** Zero-touch enrolment anchors a host's first SVID in the
vendor EK signature plus an offline-signed fleet manifest of approved EK
SHA-384 hashes. Admission is checked at the cheapest point — before quote
verification — and is atomic: a refresh swaps an `Arc<EnrolledHosts>` under a
write lock, so an in-flight `Attest` sees a consistent snapshot. Verified with
`cargo test` across `ferro-crypto` (seed determinism), `cmis::fleet_manifest`
(sign/verify/tamper/atomic-swap), the `mia` e2e harness (enrolled host attests;
un-enrolled host rejected before any quote work, one `HostRejected` leaf only),
and the `fleet-manifest` CLI lifecycle, plus `clippy -D warnings`.

- [x] T92 Define the fleet manifest format and the offline `tools/fleet-manifest` tool (S13)
  - note: `SignedFleetManifest` in `crates/cmis/src/fleet_manifest.rs`, composite-signed canonical JSON under the `ferrogate-fleet-v1` context; the `fleet-manifest` CLI does `keygen`/`new`/`add`/`remove`/`sign`/`verify`/`show`, with deterministic seed-derived publisher keys via `CompositeSecretKey::from_seed`.
- [x] T93 Load the fleet manifest into CMIS from a local file (S13)
  - note: `FleetManifestLoader` + `fleet_watcher` poll/verify/hot-swap into the `FleetStore` held by `CmisState`; `main` loads from `CMIS_FLEET_MANIFEST` fail-closed and spawns the watcher. A deployment keeping the manifest in object storage syncs it out of band — the composite signature gates what is admitted, so the sync path is untrusted.
- [-] T94 Source the fleet manifest natively from S3 (S13)
  - why: S3 / object storage is dropped; the manifest is read from a local file.
- [x] T95 Look up enrollment at the start of `Attest` before any TPM work (S13)
  - note: `CmisState::check_enrollment` runs on the phase-2 EK hash before any TPM verification work; unenforced until a manifest is loaded, so a CMIS with no manifest behaves as before.
- [x] T96 Emit `HostEnrolled` / `HostRejected` audit events (S13)

## [M16] RIM epoch bump and signed refresh wiring (F10 continued)
> outcome: CMIS refreshes signed RIM bundles from a local file at runtime and `BumpEpoch` forces every host attested under the old epoch through full re-attestation.
> version: 0.10.0
> phase: P6
> spec: S10

Legacy status note: **F10 (continued) status: done (`bump_epoch` + local-file RIM refresh; S3
dropped).** The policy epoch is now runtime-mutable: `bump_epoch` flips an
`AtomicU64` and every host re-attests on its next rotate. RIM bundles load and
hot-reload from a signed local file; sourcing them directly from S3 is dropped
and will not be implemented (see "Dropped scope" above). Verified with the
`mia` e2e harness
(`bump_epoch_forces_full_reattestation_on_next_rotate`: short-path rotate before
the bump, `FAILED_PRECONDITION` after, one `PolicyEpochBumped` leaf) plus
`clippy -D warnings`.

- [x] T97 Wire signed RIM refresh from a local file into CMIS (S10)
  - note: `RimLoader` + `rim_watcher` are spawned from `cmis` `main` (env `CMIS_RIM_BUNDLE` + `CMIS_RIM_SIGNER_KID`/`CMIS_RIM_SIGNER_PUB`, fail-closed) and load the bundle from a local file; because the bundle is composite-signed and verified before apply, the sync path is untrusted.
- [-] T98 Source signed RIM bundles natively from S3 (S10)
  - why: S3 / object storage is dropped; no HTTP/S3 client is pulled into the workspace.
- [x] T99 Add the `bump_epoch` admin RPC with audit event and forced re-attestation (S10)
  - note: `BumpEpoch` RPC → `CmisState::bump_epoch` advances a live `AtomicU64` epoch; the next `Rotate` for any host attested under the old epoch is refused (`FAILED_PRECONDITION`) via `decide_renewal`'s `EpochBump` branch. Records a `PolicyEpochBumped` audit event.

## [M17] Root key ceremony and rotation (F14)
> outcome: An air-gapped ceremony splits, cross-signs, rotates and destroys root keys with minutes signed by every participant, and a staging dry-run produces verifiable artefacts.
> version: 0.11.0
> phase: P7
> spec: S14, S38

Legacy status note: **F14 status: done for M6.** The air-gapped ceremony surface lives in the new
`crates/ferro-ceremony` library (`media`, `crosssign`, `minutes`, `destruction`)
and the `tools/offline-signer` CLI that wires them together, plus the JWKS
"newer preferred" multi-root support in `ferro-svid` / `ferro-svid-verify` /
`cmis`. Verified with `cargo test --workspace` (15 `ferro-ceremony` unit tests,
the 2 `offline-signer` CLI integration tests including the end-to-end dry-run,
and the `cmis` `root_rotation` integration test) and `cargo clippy --workspace
--all-targets`. The online emergency-rotation path remains explicitly out of
scope (separate runbook). Per-feature acceptance detail is in
[features/F14-root-key-ceremony.md](docs/features/F14-root-key-ceremony.md).

- [x] T100 Build the air-gapped `tools/offline-signer` tool (S14)
  - note: New `#![forbid(unsafe_code)]` binary with `keygen`/`pubkey`/`split`/`combine`/`cross-sign`/`verify-cross`/`jwks`/`minutes-new`/`minutes-sign`/`minutes-verify`/`destroy`/`verify-destruction`/`dry-run` subcommands, built on the new `crates/ferro-ceremony` library. No network dependency; every artefact is auditable JSON.
- [x] T101 Generate Shamir shares in a sealed transport-media format (S14)
  - note: `ferro_ceremony::media::SealedShareSet` reuses the `ferro-tee` 3-of-5 GF(2⁸) split and wraps each share in a `SealedShare` envelope — `SHA3-256` tamper-evidence tag over the canonical fields, holder label, root kid, and threshold params; `combine` reconstructs into a `Zeroizing` buffer after checking every envelope's integrity and parameter agreement.
- [x] T102 Produce cross-signing artefacts in both directions (S14)
  - note: `ferro_ceremony::crosssign::CrossSignBundle::create` produces old-signs-new and new-signs-old composite signatures over a domain-separated transcript binding both kids, both public keys, and the window bounds; `verify` requires both directions.
- [x] T103 Order the CMIS JWKS roots with newer preferred (S14)
  - note: `Jwk` carries an optional `x-ferrogate-created` stamp; `JwkSet::preferred()` (in both `ferro-svid` and the reference `ferro-svid-verify`) selects the newest. `CmisState::register_root_key` publishes the incoming root for the cross-sign window, and `published_jwks` orders roots newest-first ahead of the per-host child keys, all still resolvable by `kid`.
- [x] T104 Destroy share media with post-zeroization verification (S14)
  - note: `ferro_ceremony::destroy_media` overwrites a sealed-share medium in place with zeros, `fsync`s, then reads it back and fails unless every byte is zero and the bytes no longer parse as a usable share; `verify_destruction` re-audits a previously-destroyed medium standalone.
- [x] T105 Sign ceremony minutes by all participants and store them to WORM (S14)
  - note: `ferro_ceremony::minutes::SignedMinutes`: every listed `Participant` contributes one composite signature over the canonical body — including artefact `SHA3-256` digests — and `verify_all` only passes when all have signed; the signed JSON is what gets anchored to the audit WORM medium.
- [x] T106 Complete the staging dry-run (S14, S38)
  - note: `offline-signer dry-run` runs the full eight-step rotation against a scratch directory with five synthetic operators and is driven by the CLI integration test `dry_run_produces_all_verifiable_artefacts`; the recorded run is captured in `docs/operations/root-key-ceremony.md` §"Staging dry-run".
- [x] T107 Write the root key ceremony operations runbook (S38)

## [M18] Operational drills and SRE runbooks
> outcome: Region-loss, mass-revocation and quorum-loss drills each have a runbook and a repeatable rehearsal harness, and every alert has an SRE runbook.
> version: 0.12.0
> phase: P7
> spec: S37, S39, S40, S41, S42

Legacy status note: **Operational drills status: done for M6.** Each drill ships as a documented
runbook (pre-flight → procedure → pass criteria → abort) plus a repeatable
**rehearsal harness** under `scripts/drills/` that exercises the behaviour
against the real in-process subsystems — the 3-node hiqlite cluster
(`cluster_e2e`) for region/quorum loss, and the `bump_epoch` + `revocation`
integration tests for mass revocation. The region-loss harness was executed on
2026-06-01 (4 passed / 1 ignored, 104 s; log captured in the drill doc). The
three alert runbooks quote their thresholds directly from the code so the alert
rule and the runbook cannot drift. Recurring staging executions append a dated
row to each drill's **Drill log** table; the `#[ignore]`-gated
`ten_minute_chaos_run` is the long-form staging counterpart of the local
region-loss rehearsal. All four drill/runbook docs are linked from
[operations.md](docs/operations.md) (§"Disaster recovery", §"Day-2 SRE concerns").

- [x] T108 Execute the documented region-loss drill in staging (S39)
  - note: `docs/operations/drills/region-loss.md`; harness `scripts/drills/region-loss.sh`.
- [x] T109 Execute the documented mass-revocation drill (`policy_id` epoch bump) (S40)
  - note: `docs/operations/drills/mass-revocation.md`; harness `scripts/drills/mass-revocation.sh`.
- [x] T110 Execute the documented quorum-loss recovery drill (S41)
  - note: `docs/operations/drills/quorum-loss-recovery.md`; harness `scripts/drills/quorum-loss-recovery.sh`.
- [x] T111 Write an SRE runbook for each alert: STH lag, CRL stale and key-share failure (S42, S43, S44, S45)
  - note: `docs/operations/runbooks/`.

## [M19] Formal verification
> outcome: Tamarin proves the attestation authentication goals and CryptoVerif proves hybrid-AKE key secrecy, and a CI job fails the build on any falsified lemma or unproved query.
> version: 0.12.0
> phase: P7
> spec: S47, S46

Legacy status note: **Formal verification status: done for M6.** The Tamarin model proves the
attestation authentication goals (an SVID is issued only to the TPM that holds
the named EK; quotes cannot be replayed; the residency secret and host key stay
secret); the CryptoVerif model proves the hybrid session key stays
indistinguishable from random even if X25519 is fully broken, as long as
ML-KEM-768 is IND-CCA2 (harvest-now-decrypt-later resistance). The
`formal-verification` CI job installs both provers, runs each within a 600 s
per-proof budget (`FERROGATE_FORMAL_TIMEOUT`), and **fails the build** if any
Tamarin lemma is falsified or any CryptoVerif query is not proved. The provers
are heavyweight (Maude/Haskell and OCaml respectively) and are not in the local
dev toolchain — `make formal` degrades gracefully when they are absent, and the
CI job is the authoritative gate. Scope and abstractions are documented in
[formal/README.md](formal/README.md) and in each model's header comment.
(Migration note: the `formal-verification` job lived in `ci.yml`, which was
removed in 0.13.2; see T222.)

- [x] T112 Check in the CryptoVerif model of the hybrid AKE under `formal/` (S48)
  - note: `formal/cryptoverif/hybrid_ake.cv`.
- [x] T113 Check in the Tamarin model of the four-phase attestation protocol (S49)
  - note: `formal/tamarin/attestation.spthy`.
- [x] T114 Verify both models in CI within budget (S47)
  - note: `.github/workflows/ci.yml` job `formal-verification`; `make formal`. The CI job was removed with `ci.yml` in 0.13.2 (T222); `make formal` remains.

## [M20] Operator CLI
> outcome: Operators run `ferrogate status`, `list-svids`, `revoke-svid`, `revoke-host` and `bump-epoch` against CMIS, including from inside the server container.
> version: 0.13.1
> phase: P8
> spec: S37

Created during migration from the 0.13.x changelog sections; the legacy roadmap
had no entry for this work.

- [x] T115 Turn `ferrogate-cli` into the `ferrogate` operator CLI over the admin RPCs
- [x] T116 Add the `ListSvids` admin RPC
- [x] T117 Bundle the `ferrogate` CLI in the server container image
- [x] T118 Report the CLI version with `-V`, `--version` and `version`

## [M21] Hybrid-PQC TLS on the live gRPC transport (F01 continued)
> outcome: CMIS terminates `X25519MLKEM768`-only TLS and both MIA and the `ferrogate` CLI dial it with SPKI pinning, rejecting legacy or wrong-pin peers before any RPC.
> version: 0.15.0
> phase: P7
> spec: S1, S36, S37

Wire the existing `ferro-crypto` hybrid-PQC TLS provider into the live gRPC
transport. The provider (`ferrogate_provider()`, `X25519MLKEM768` hybrid
mode) and the SPKI-pinning verifier already exist from M1, but the CMIS gRPC
listener still runs plaintext in the bring-up binary and the MIA client does
not yet terminate TLS — the seam flagged in F04's status note.

Legacy status note: **F01 (continued) status: done.** The hybrid-PQC TLS provider is now wired into
the live transport on both sides: the CMIS listener terminates
`X25519MLKEM768`-only TLS (`CMIS_TLS_CERT` / `CMIS_TLS_KEY`) and MIA dials it
with SPKI pinning via `connect_pinned`. The shared rustls config builders live
in `ferro_crypto::transport`. Verified with
`cargo test -p ferro-crypto --test tls_handshake` (5), `cargo test -p mia
--test tls_transport` (3 — pinned-hybrid JWKS over TLS, legacy-client reject,
wrong-pin reject), and `clippy -D warnings` on `ferro-crypto`/`cmis`/`mia`.

- [x] T119 Terminate hybrid-PQC TLS on the CMIS gRPC listener (S1)
  - note: Uses `ferro_crypto::transport::server_config(HybridOnly, …)` (`X25519MLKEM768`-only). `cmis::transport::tls_incoming` runs a `tokio_rustls` accept loop and feeds handshake-complete connections to `tonic`'s `serve_with_incoming`; `cmis` `main` enables it when `CMIS_TLS_CERT` + `CMIS_TLS_KEY` are set (plaintext bring-up otherwise, with a loud warning).
- [x] T120 Dial CMIS from MIA over the hybrid provider with SPKI pin verification (S1)
  - note: `mia::client::connect_pinned` builds a `Channel` over a custom `tokio_rustls` connector using `ferro_crypto::transport::client_config(HybridOnly, pins)`; a non-hybrid or wrong-pin server is rejected before any RPC.
- [x] T121 Test that a legacy client cannot handshake with the live CMIS listener (S1)
  - note: `crates/mia/tests/tls_transport.rs::legacy_non_pqc_client_cannot_handshake_against_cmis_listener`, plus `wrong_pin_client_is_rejected_by_connect_pinned`.
- [x] T122 Surface the negotiated key-exchange group as a telemetry field (S1)
  - note: `tls_incoming` logs `kx_group = X25519MLKEM768` per accepted connection (and warns loudly on any non-hybrid group, unreachable under `HybridOnly`). The `ferro_crypto::transport::{is_hybrid_group, group_label}` helpers and the `transport_builders_negotiate_the_hybrid_group` test pin the value.
- [x] T123 Document the transport configuration in `operations.md` (S37)
  - note: `docs/operations.md` §"Transport security (hybrid-PQC TLS)" (cert/pin provisioning).
- [x] T124 Write the transport security guide `docs/transport-tls.md` (S36)
- [x] T125 Dial CMIS from the `ferrogate` CLI over pinned hybrid-PQC TLS (S1, S36)
- [x] T126 Extract the pinned dialer into the `ferro-transport` crate (S1)

## [M22] Cross-platform MIA configuration and self-test
> outcome: MIA runs on Linux, macOS and Windows from a validated TOML configuration written by `mia setup`, serves one token surface per deployment, and `mia test` diagnoses the full issuance path.
> version: 0.21.0
> phase: P8
> spec: S29, S31

Created during migration from the 0.21.0 changelog section (work tagged
0.15.2–0.20.24) and from git history; the legacy roadmap had no entry for it.

- [x] T127 Read an optional TOML configuration file in MIA (S29)
- [x] T128 Discover the configuration at per-OS system and user paths (S29)
- [x] T129 Add the interactive `mia setup` configuration wizard (S29)
- [x] T130 Add `mia setup --clean` and OS-aware install defaults (S29)
- [x] T131 Serve the helper API on Linux, macOS and Windows (S29, S31)
- [x] T132 Add the `mia test` connectivity and token-issuance self-test (S29)
- [x] T133 Serve the enrollment key via `GetEnrollmentKey` and fetch it in `mia setup` (S32)
- [x] T134 Add `mia refresh-key` to re-fetch the enrollment key non-interactively (S32)
- [x] T135 Add `ferrogate spki-pin` to print the CMIS SPKI pin from a certificate (S36)
- [x] T136 Hand the helper socket to a dedicated group for non-root callers (S31)
- [x] T137 Select side-by-side deployments with `mia --environment` (S29)
- [x] T138 Serve every discovered environment from one daemon (S29)
- [x] T139 Show self-reported host names in `ferrogate list-svids` (S29)
- [x] T140 Add `make mia-install` and `mia-uninstall` with OS service registration (S29)

## [M23] Windows support for MIA
> outcome: MIA installs on Windows from a container-built MSI or Chocolatey package that registers a native service and the `FerroGateClients` group, with optional Authenticode signing and an operator-controlled caller Authenticode check.
> version: 0.21.0
> phase: P8
> spec: S29, S31, S8

Created during migration from the 0.21.0 changelog section; the legacy roadmap
had no entry for it.

- [x] T141 Run MIA as a native Windows service (S29)
- [x] T142 Create the `FerroGateClients` helper group in the Windows installer (S31)
- [x] T143 Make the Windows caller Authenticode check configurable (S31)
- [x] T144 Build a self-contained NSIS installer with `make pkg-win` (S29)
  - note: Superseded by the container-built MSI (T145).
- [x] T145 Cross-build the Windows MSI and Chocolatey package in a container (S29)

## [M24] Allowlist provisioning and lifecycle
> outcome: CMIS signs and serves per-host caller allowlists that hosts fetch, propose, renew and reload live, with an operator review queue and fail-closed handling of every bad or missing body.
> version: 0.21.0
> phase: P8
> spec: S32, S21, S31

Created during migration from the 0.21.0 changelog section and git history; the
legacy roadmap had no entry for it. The ADR-0003 follow-up is M35.

- [x] T146 Serve signed per-host allowlists from CMIS with `ferrogate allowlist` commands (S32)
- [x] T147 Make the caller-entry uid optional with hash-primary matching (S21)
- [x] T148 Let hosts propose observed callers with a TOFU bootstrap and review queue (S32)
- [x] T149 Self-register a host with CMIS when its daemon attests (S32)
- [x] T150 Add `mia resync-allowlist` and `mia --resync` to re-fetch the allowlist (S32)
- [x] T151 Reload the signed allowlist live on `SIGHUP` (S32)
- [x] T152 Add `mia --reload` to reload configuration and allowlist without a restart (S29)
- [x] T153 Always permit `mia`'s own binary through self-trust (S31)
- [x] T154 Support the any-binary allowlist wildcard `bin_sha = "*"` (S32, S21)

## [M25] CMIS HA and runtime robustness in production
> outcome: A multi-node CMIS keeps one issuer identity, persists all state across restarts, serves every host key from every replica over an encrypted peer network, and MIA reaches it through DNS SRV fail-over without restarts.
> version: 0.21.0
> phase: P8
> spec: S5, S9, S11, S37

Created during migration from the 0.21.0 changelog section and git history; it
also closes two seams left open by M12 and M13.

- [x] T155 Make the Raft store the only CMIS backend and resume the audit log on restart (S5, S7)
- [x] T156 Persist the CMIS issuer seed and replicate it across the cluster (S5)
- [x] T157 Run Raft and management traffic over TLS with a routable bind (S5)
- [x] T158 Discover CMIS through DNS SRV records with best-first fail-over (S29)
- [x] T159 Publish every host's child-token key from every CMIS replica (S9)
  - note: Seam postponed out of M12 in 0.6.0.
- [x] T160 Start the MIA CRL puller at daemon startup (S11)
  - note: Seam postponed out of M13 in 0.7.0.
- [x] T161 Retry host attestation in the background until a host SVID is obtained (S29)

## [M26] Tiered attestation for VMs (F16)
> outcome: MIA picks the strongest usable attestation tier at boot — a real (v)TPM when present, else a clone-resistant software key — and CMIS can require pre-registration and shorter lifetimes for the software tier.
> version: 0.21.2
> phase: P8
> spec: S16, S15

Created during migration from the 0.21.0 and 0.21.2 changelog sections; F16 was
not on the legacy roadmap.

- [x] T162 Select the attestation tier at boot with backend `auto`, `tpm` or `host-key` (S16)
- [x] T163 Drive a real (v)TPM through the shared `run_attest` handshake (S16)
  - note: MIA side (`TpmEvidence`) only. Verified during migration: the shipped `cmis` binary still wires `UnconfiguredCredentialMaker` (`crates/cmis/src/main.rs`), so tier-A attestation cannot complete phase 3 against it until T230 lands.
- [x] T164 Seal the software machine key at rest to the hardware fingerprint (S16)
- [x] T165 Add CMIS knobs for host-key pre-registration, host-key TTL and vTPM EK roots (S16)
- [x] T166 Add an in-process virtual TPM for TPM-less dev and test hosts (S16)
- [x] T167 Report the TPM and attestation posture in `mia test` (S16)

## [M27] Release engineering, packaging and documentation site
> outcome: Tagging `releases/v<version>` publishes the MIA packages and the integration SDK, the server image builds reproducibly from the workspace version, and the docs are served as a site.
> version: 0.21.5
> phase: P8
> spec: S34, S35, S20

Created during migration from the 0.13.2 and 0.21.5 changelog sections and from
git history (tags v0.12.1, v0.13.0 and releases/v0.21.5).

- [x] T168 Build the linux/amd64 server container image with `make docker-image`
- [x] T169 Serve the documentation as a Docsify site
- [x] T170 Record ADR-0001 and the networking and firewall requirements (S20, S35)
- [x] T171 Package `mia` as deb, rpm, msi and macOS pkg installers (S29)
- [x] T172 Publish packages and the SDK from a Release workflow on `releases/**` tags (S34)
- [x] T173 Build the amd64 RPM inside a linux/amd64 container (#13)
- [x] T174 Add `make deploy-release` to tag and push `releases/v<version>`
- [x] T175 Publish `ferrogate-sdk-rust` as a crate to the Cargo registry (S34)
- [x] T176 Add `LICENSE.md` pointing to Apache-2.0

## [M28] Toolchain, dependency and CI maintenance
> outcome: The workspace stays formatted, on supported toolchains and on maintained, advisory-free dependencies, with `make deny` and the tray workflow green.
> phase: P8

Created during migration to give maintenance changelog entries a home. This
milestone has no single release; it includes unreleased work.

- [x] T177 Enable Dependabot for cargo and GitHub Actions
- [x] T178 Reformat the workspace so `cargo fmt --check` passes
- [x] T179 Upgrade the cryptographic dependencies to their current major versions (S26)
  - note: ed25519-dalek 3, rand_core 0.10 (randomness via getrandom 0.4 `SysRng`), p256 0.14, chacha20poly1305 0.11, sha3 0.12.
- [x] T180 Document the mandatory AI-assistant skills in `AGENTS.md`
- [x] T181 Replace the unmaintained `rustls-pemfile` with the `rustls-pki-types` PEM API
- [x] T182 Upgrade hiqlite to 0.15.0 in `ferro-raft` (S5)
- [x] T183 Raise the workspace MSRV to 1.95
- [x] T184 Make the `mia-tray` workflow and `cargo deny` pass again (#44, #45)
- [x] T292 Document the `cortex-memory` skill in `AGENTS.md`

## [M29] TPM-less host-key attestation (F15)
> outcome: A host without a TPM attests with a hardware-fingerprint identity and a non-exportable Secure Enclave key, its SVID cache is sealed by the Enclave, and the daemon's Enclave key persists across restarts.
> phase: P8
> spec: S15, S13

Created during migration from git history (F15 merged in 0.16.0, commit
fc08a4f) and the 0.21.x changelog sections; F15 was not on the legacy roadmap.
The shipped parts went out in 0.21.0–0.21.4. Status from
[F15](docs/features/F15-apple-attestation.md): implemented (host-key profile);
the two open acceptance criteria below remain.

- [x] T185 Derive a stable hardware fingerprint in `ferro-machineid` (S15)
- [x] T186 Carry host-key evidence in `AttestInit` with a 3-phase handshake (S15, S25)
- [x] T187 Sign the handshake with a Secure Enclave key or a software fallback (S15)
- [x] T188 Verify host-key evidence in CMIS and stamp SVIDs `policy_id = "host-key"` (S15)
- [x] T189 Pin the fingerprint to the Enclave key on first use, with pre-registration (S15)
- [x] T190 Enroll machine fingerprints in the fleet manifest (S15, S13)
- [x] T191 Attest on daemon startup and enable the child-token minter (S15)
- [x] T192 Add the Windows hardware-fingerprint backend for host-key attestation (S15)
- [x] T193 Add `mia machine-id` to print the host's machine identity (S15)
- [ ] T194 Seal the SVID cache with the Secure Enclave (S15)
  - note: F15 criterion: "SVID cache seals via the SEP (F04 substitute) — not yet (`seal/sep.rs`)".
- [ ] T195 Persist the daemon's Secure Enclave attestation key in the keychain (S15)
  - note: The daemon uses a persistent software key today; the SEP crypto core is proven by its live test. Since 0.21.6 `ferro-sep` can persist an Enclave *sealing* key when the binary carries the keychain entitlement (T202).

## [M30] X.509-SVID profile (F17)
> outcome: Every attestation also yields a hybrid-signed SPIFFE X.509-SVID that stock TLS stacks validate, the reference verifier requires both signature halves, and the host stores it sealed to the machine, with Enclave key persistence verified on a codesigned build.
> phase: P8
> spec: S17, S15

Created during migration from the 0.21.6 changelog section; F17 was not on the
legacy roadmap. The shipped parts went out in 0.21.6; one acceptance criterion
is blocked.

- [x] T196 Issue a hybrid-signed X.509-SVID beside every JWS SVID (S17)
- [x] T197 Publish the X.509 trust anchor in the JWKS `x-ferrogate-x509-bundle` member (S17)
- [x] T198 Require both signature halves in `ferro-svid-verify`'s `x509` module (S17)
- [x] T199 Revoke the X.509-SVID together with its JWS SVID (S17, S11)
- [x] T200 Store the host's X.509-SVID sealed to the machine (S17)
- [x] T201 Add `mia x509-svid` to inspect the stored credential (S17)
- [x] T202 Seal the credential store with the macOS Secure Enclave (S17)
- [x] T203 Generalise the machine-key AEAD envelope to arbitrary payloads (S17)
- [x] T204 Export the classical key half as PKCS#8 for TLS stacks (S17)
- [x] T205 Add standard-format Ed25519 and ML-DSA-65 interop signers (S17, S3)
- [!] T206 Test Secure Enclave key persistence across processes (S17)
  - blocked-by: needs a Developer ID-codesigned `mia` carrying the keychain-access-group entitlement; `ferro_sep::enclave::seal_tests::persistent_seal_key_round_trips` is `#[ignore]`d

## [M31] MIA tray companion (F18)
> outcome: An unprivileged tray app shows per-environment agent health, guides recovery through OS-consent-gated `mia` commands, ships in every desktop package, and is verified end to end against real prompts and packages.
> phase: P6
> spec: S18, S30, S29

Listed under legacy M5 in the old roadmap; it is the active milestone. The
daemon side and the tray shipped in 0.21.7.

Legacy status note: **F18 status: in progress.** The daemon side and the tray are implemented and
unit-tested (`cargo test -p mia-tray -p mia-status-proto`; the GUI build with
`make lint-tray` / `make test-tray`, and on all three desktop platforms in
`.github/workflows/mia-tray.yml`). Open: the criteria above that need real
packages, a real consent prompt or the e2e harness, and the ESI decision on
whether the OS administrator prompt satisfies NRM §5.3.1 for configuration
changes on workstations.

- [x] T207 Serve a read-only status endpoint with a redacting log ring buffer (S18)
  - note: Phase 1: `StatusReq` / `LogTailReq` in a dedicated listener, `mia-status-proto` wire crate, `mia status [--json]`, `mia test --json`, redacting log ring buffer.
- [x] T208 Add `mia setup --check / --apply / --dump` with the `ConfigChanged` event (S18)
  - note: Phase 1.
- [x] T209 Build the `mia-tray` icon, menu and transition notifications (S18)
  - note: Phase 2: worst state wins, per-environment detail; endpoint → `mia status` → `NotRunning` fallback; notifications with de-duplication and rate limiting.
- [x] T210 Add tray windows for status, recovery, setup, logs and diagnostics (S18)
  - note: Phase 2: egui, no web view; guided recovery over a closed set of fixed `mia` commands with OS-consent elevation (`pkexec` / macOS admin prompt / UAC; cancel ⇒ "cancelled"), setup wizard on private `0600` drafts, log viewer, diagnostics bundle; English and Portuguese.
- [/] T211 Ship `mia-tray` in the macOS, Windows and Linux packages (S18)
  - note: Wired into `pkg-macos` (LaunchAgent), `pkg-win` (Startup entry) and the opt-in Linux `ferrogate-mia-tray` package (XDG autostart, polkit policy, status group); the package builds have not been run yet.
- [x] T212 Ship the macOS tray as the `FerroGate MIA.app` bundle (S18, S30)
- [ ] T213 Drive every `AgentState` from the daemon's e2e harness (S18)
- [ ] T214 Test per platform that a peer outside the status group cannot connect (S18)
  - note: Needs root and real groups; answering `StatusReq`/`LogTailReq` and refusing anything else is already tested over a real socket.
- [ ] T215 Run the setup wizard and consent prompts end to end against real prompts (S18)
- [ ] T216 Test as root that `mia setup --apply` preserves a different file owner (S18)
  - note: The rest of the `--apply` criterion (rejections, atomic write, `0640`, `ConfigChanged`, byte-identity with the TTY wizard) is tested.
- [ ] T217 Fall back to a minimised window when Linux has no StatusNotifierItem host (S18)
- [ ] T218 Obtain the ESI decision on whether the OS consent prompt satisfies NRM §5.3.1 (S18)
  - note: NRM §5.3.1 asks for MFA for configuration changes; the alternative is an operator-issued approval from CMIS for system-path changes.
- [ ] T219 Pass the ESI pre-production security verification gate for the tray (S18)

## [M32] Restore continuous verification gates
> outcome: Every push to `main` again runs fmt, clippy, tests, `cargo audit`/`cargo deny`, coverage, the reproducible-build and no-unsafe-in-mia gates, and the formal-verification job.
> phase: P9
> spec: S46, S12, S47

Created during migration. The roadmap still claims these CI gates, but
`.github/workflows/ci.yml` was removed in 0.13.2 (commit 6c925b1) and only the
`release` and `mia-tray` workflows exist on `main`; commit c0a4e0f also notes
that repository Actions were disabled at the time.

- [ ] T220 Restore a CI workflow running fmt, clippy, test and check on every push
  - note: Inferred during migration from the removal of `ci.yml`; confirm intent with the maintainers.
- [ ] T221 Restore the `cargo audit`, `cargo deny` and coverage jobs in CI
- [ ] T222 Restore the reproducible-build, no-unsafe-in-mia and formal-verification CI jobs (S12, S47)

## [M33] Cluster-wide audit and revocation wiring
> outcome: Every CMIS replica publishes the same revocations, the anchor publisher runs on a schedule with backlog metrics, STHs are co-signed over real peer RPC, and host-side config audit events reach CMIS.
> phase: P9
> spec: S11, S7, S33

- [>] T223 Replicate the revocation working set through the Raft store (S11)
  - from: M13
  - why: deployment seam on `CmisState::revoke`; the working set is still process-local (`crates/cmis/src/state.rs`).
- [>] T224 Schedule the CMIS anchor publisher every 60 s with backlog metrics (S7)
  - from: M10
  - why: lands with the wider F07-anchor wiring task; `AnchorPublisher` is not yet driven by CMIS.
- [>] T225 Co-sign STHs through an RPC `SthSigner` that talks to peers over `ferro-raft` (S7)
  - from: M10
  - why: deployment wiring behind the existing `SthSigner` trait; only `InProcessSigner` exists today.
- [>] T226 Forward the `ConfigChanged` journal to CMIS through `AppendAuditEvent` (S18, S33)
  - from: M31
  - why: follow-up; today the event goes to a local append-only `config-audit.jsonl` beside the config file.
- [x] T291 Forward the MIA daemon's audit events to CMIS through a durable spool (S7)
  - note: `crates/mia/src/audit_forward/` (`mod.rs` forwarder, `spool.rs` spool), started from `main.rs::serve` with `ResolverAuditApi` (cached pinned channel, re-resolved after transport errors) and the host `CredentialSlot`. Every event from the helper API and the allowlist sync is logged on `mia::audit`, staged without waiting on disk or CMIS, appended to `audit-spool[-<env>].jsonl` in the state directory (`0600`, JSON lines of base64 canonical CBOR plus `done` watermarks, `fdatasync` per append, compaction through `atomic_file`, capped at 10 000 events / 8 MiB with the oldest dropped) and sent in order, one call at a time, signed per attempt (`audit_client::signed_request_now`). Transient errors and `rate_limited` retry (backoff 1 s → 5 min, equal jitter, `retry-after` honoured); refused proofs (`UNAUTHENTICATED`, `PERMISSION_DENIED` incl. the ambiguous `host_mismatch`, `INVALID_ARGUMENT malformed_doc` or any unrecognised reason) hold the event until new credentials or the next retry; only `INVALID_ARGUMENT field_too_long` / `malformed audit event` and `event_not_forwardable` drop it with a warning. An expired SVID holds forwarding with one warning until a re-attestation succeeds (renewed while running since T294). A spool that cannot be read to its end is renamed to `<name>.unreadable-<unix time>` (unchanged, `0600`) before anything is written; the spool opens on the blocking pool; appends use `O_NOFOLLOW`. No CMIS, or an attested SVID without a host-call key: log only, no spool. The helper API keeps its awaiting `send` (no audit loss under a flood); the intake drains the channel regardless of CMIS. Tests: `audit_forward::tests` (`events_are_forwarded_in_order`, `a_transient_failure_is_retried_not_lost`, `a_permanent_rejection_drops_that_event_and_the_next_is_sent`, `auth_refusals_hold_the_queue_until_new_credentials`, `proof_document_and_host_mismatch_refusals_hold_the_queue`, `an_expired_svid_is_told_apart_and_logged_once`, `missing_or_expired_credentials_hold_events_until_valid_ones_appear`, `the_spool_survives_a_restart`, `helper_pushes_never_wait_on_cmis_and_the_cap_drops_oldest`, `without_cmis_events_are_logged_and_never_spooled`, classification and backoff), `audit_forward::spool::tests` (reopen, `0600`, torn/garbage lines, caps, compaction, symlink replaced, unwritable directory, `a_spool_not_read_in_full_is_moved_aside_never_overwritten`, `an_unread_spool_that_cannot_be_moved_is_left_untouched`, `aside_names_never_replace_an_existing_file`, `appends_never_follow_a_symlink`), `config::tests::the_audit_spool_lives_in_the_state_directory_per_environment`, and `e2e_attest.rs::audit_log_records_attest_events_and_proofs_verify_offline` (a spooled event reaches a real CMIS tree). Follow-ups: ~~host SVID renewal in the running daemon~~ (done in T294); backlog counters in the status endpoint; `ConfigChanged` journal (T226).
- [x] T293 Require a host proof on `Rotate` and refuse the TPM tier, superseded, expired and revoked SVIDs (S4, S51, S11)
  - note: Closes the unauthenticated issuance oracle (`Rotate` was `Access::Public` and decoded the SVID without verifying it). `RotateRequest` gains `auth`/`doc`; `ferro_svid::host_call::{RotateDoc, encode_rotate, decode_rotate, ROTATE_CONTEXT}` (`ferrogate-rotate-v1`); `cmis::service::rotate_with_host_proof` runs `host_auth::authenticate` (rotate limiter, `CMIS_ROTATE_MAX_PER_HOUR`, default 6), then refuses the TPM tier (`rotate-tier-requires-attest`), an unknown subject, a superseded SVID (`rotate-superseded`) and `decide_renewal` over the **signed** state digest (`rotate-reattest-<reason>`); renewal audits `SvidIssued` and stores through `CmisState::replace_bundle_if_current` (compare-and-swap `Cluster::replace_svid_if_unchanged`). `authz.rs` marks `Rotate` `Access::Host`. `mia::client::{rotate, rotate_request}` build the signed request. `REATTEST_WINDOW_SECS` unchanged (24 h). Tests: `crates/cmis/tests/rotate_host_auth.rs` (24 with the review fixes), `ferro_svid::host_call::tests::rotate_doc_*`, `host_auth::tests::from_lookup_reads_rotate_limit`, `admin::authz::tests::host_methods_are_host_authenticated`, `cluster_e2e.rs::replace_svid_if_unchanged_is_a_compare_and_swap`, `mia::client::tests::rotate_request_carries_a_verifiable_host_proof`, `e2e_attest.rs::{rotate_short_path_for_host_key_tier, rotate_refused_for_tpm_tier, bump_epoch_forces_full_reattestation_on_next_rotate}`. Part 2 (daemon renewal loop, the T291 follow-up) is T294.
  - note: Security review fixes: `host-key` is reserved in the RIM (`ferro_attest::HOST_KEY_POLICY_ID`, the single definition, re-exported as `cmis::host_auth::TIER_HOST_KEY`; `RimStore::{apply, approve}` answer `ApplyError::ReservedPolicyId`; `rim_watcher` logs `rim.reserved_policy_id`), `Rotate` reads the record through `CmisState::lookup_checked` (store or decode failure → `UNAVAILABLE store_unavailable`, audited `rotate-store-failed`), `RotateRequest` fields 2–3 are `[deprecated = true]`, and `docs/protocol.md` notes the per-node replay window. Tests: `rim::tests::{rim_policy_id_host_key_is_reserved, manual_approval_of_the_host_key_policy_id_is_refused}`, `rim_loader::tests::reload_refuses_a_signed_bundle_with_the_reserved_policy_id`, `rotate_host_auth.rs::{rotate_store_error_is_unavailable_not_not_found, rotate_store_swap_refuses_a_record_changed_after_lookup, rotate_rejects_forged_svid_with_the_victims_pcr_values}`. Follow-up (out of scope): derive the tier from a dedicated issuance claim instead of `policy_id`.
- [x] T294 Renew the host SVID in the running MIA daemon and fail closed at expiry (S4, S7, S18)
  - note: `crates/mia/src/renewal/` (`mod.rs` state machine `Renewal::{step, run}` over the `Renewer` trait plus the `spawn` supervisor and `next_fatal`, `host.rs` the daemon's `HostRenewer` over `HostAttestor` / `CmisDial` / `X509Sealer` (`X509Store`) / `RenewalHooks`, `schedule.rs` pure `next_wait` / `reattest_wait` / `classify` / `rotate_allowed` / `retry_after_wait`, `swap.rs` `HostSvid`, `Swap`, `SvidCell`, `MinterSink`, `rotate_host_svid`); `main.rs::{MainAttestor, MainHooks, spawn_renewal_task}` replace `spawn_reattest_task`. Renewal at 60 % of TTL ±10 % (jitter per SVID, reported as the status renewal point, ≥ 30 s after a renewal); `Rotate` only on the host-key tier inside the local window (`last_full_attest_at + REATTEST_WINDOW_SECS − 600 s > now`, D1), with < 3 consecutive transient failures and > ¼ of the lifetime left, never on the TPM tier (D2); refusals → full attestation in the same step; transient → 30 s × 2ⁿ⁻¹ ≤ min(15 min, left/4), jittered, ≤ exp − 60 s; `rate_limited` → `retry-after`; no valid SVID → `REATTEST_INTERVAL` ±10 %. Deadlines (`Timeouts`: rotate 60 s, full attestation 120 s, refresh 60 s) cut at expiry, which abandons the attempt and disables. Clock skew (< max(30 s, TTL/10) left) is a failure. Swap order: `CredentialSlot`, `MinterReloader`, status, hooks (sync or legacy fetch, propose once), then `X509Store::seal`. The minter refuses an expired parent (`MinterConfig::parent_expires_at`) and clamps child `exp`. Renewals reopen key and seed only (`KeyPolicy::OpenOnly { seed_required, kid }`, `Unusable::{Vanished, Replaced}`); the host-key backend (`renewal::HostKeyAttestor`, moved from `main.rs`) refuses a seed that no longer derives the `kid` in force before dialing CMIS, and `HostRenewer` still refuses another `kid` after attestation. Another SPIFFE id → not installed, minting off, `host_identity_changed`, `serve` error; a dead task → `Fatal::TaskEnded`, minting off. Tests: `renewal::tests` (state machine, schedule, swap, deadlines, skew, fallback, supervisor, `HostRenewer` key policy / kid / seal-after-accept), `status::tests` (`renewal_failure_keeps_attested_phase`, `svid_renewal_due_clears_after_renewal`, `the_renewal_point_follows_the_renewal_schedule`, `an_identity_change_has_its_own_code_and_fixed_message`), `machine_key::tests::{a_renewal_*, a_replaced_seed_is_refused_on_renewal}`, `renewal::tests::a_replaced_seed_is_refused_before_any_cmis_call`, `helper::token::tests::{with_parent_keeps_the_key_and_names_the_new_parent, mint_refuses_once_the_parent_svid_expired, child_exp_is_clamped_to_the_parent_expiry}`, `helper_api.rs::expired_parent_svid_refuses_to_mint`, `mia_tray::i18n::tests::a_failing_renewal_is_explained_as_retried_by_the_agent`, `e2e_attest.rs::{daemon_renews_host_svid_before_expiry, an_identity_change_stops_the_daemon_and_minting}` (real CMIS and `HostRenewer`: `Rotate`, minting, audit forwarding and the X.509 re-seal under the renewed SVID; epoch bump → `OpenOnly` full attestation with the same `kid`; identity change → fatal, minting off). Follow-ups: with several environments an identity change stops only that environment until a restart.

## [M34] TEE hardware and production trust integration
> outcome: CMIS runs with real SEV-SNP or TDX report producers, signs SVIDs and STHs with the reconstructed threshold key, and completes phase 3 with a production TCG `MakeCredential`.
> phase: P9
> spec: S6, S4, S2, S28

- [>] T227 Produce real SEV-SNP and TDX reports in hardware `Attestor` drivers (S6)
  - from: M9
  - why: real SEV-SNP `MSG_REPORT_RSP` / TDX-quote producers were out of scope for F06; the test path uses the structurally faithful `SoftwareAttestor`.
- [>] T228 Key the CMIS `Issuer` off a `ProtectedKey` from the `Reconstructor` (S6, S28)
  - from: M9
  - why: lands when the SEV-SNP / TDX hardware drivers arrive; the swap is non-API-breaking.
- [>] T229 Sign STHs with the threshold key instead of the in-process signer (S6, S7)
  - from: M9
  - why: deferred to land with the hardware `Attestor` driver work; the `Reconstructor` → `ProtectedKey` seam and the STH signer trait are in place.
- [>] T230 Implement a production TCG `MakeCredential` for phase 3 (S4, S2)
  - from: M5
  - why: lands with the TEE work; CMIS ships only `UnconfiguredCredentialMaker`, which refuses so no half-configured node can appear to attest TPM hosts.

## [M35] Host-side allowlist request and status (ADR-0003)
> outcome: An on-host operator can request explicit apps with `mia request-allowlist` and confirm approval with `mia allowlist-status`, while signing stays with the CMIS issuer and approval with the operator.
> phase: P9
> spec: S22, S32

ADR-0003 is **Proposed**, not Accepted; these tasks follow its rollout plan and
start only once it is accepted. ADR-0004 (S54) supersedes it on acceptance; the
replacement work is M37.

- [ ] T231 Add the `GetProposalStatus` request, response and RPC to `ferro-proto` (S22)
- [ ] T232 Implement read-only `GetProposalStatus` in CMIS (S22)
- [ ] T233 Add `mia request-allowlist` to request explicit apps for this host (S22)
- [ ] T234 Add `mia allowlist-status` to report live, pending or absent apps (S22)
- [ ] T235 Document operator-gated approval with `CMIS_ALLOWLIST_PROPOSALS=off` (S22, S32)

## [M36] Authenticated administration surface (F20 Phase 0)
> outcome: No CMIS admin RPC answers without an authenticated, authorized administrator session over TLS; local admin accounts sign in with a password plus TOTP or FIDO2, and `AppendAuditEvent` accepts only host-signed events.
> phase: P10
> spec: S51, S55, S56, S35

Blocking: closes the critical finding in the overview (S56, "Findings" 1-3) and
must ship before M37-M40. Breaking change for old `ferrogate` binaries (0.29.0).

- [x] T250 Gate every legacy admin RPC behind an admin session and permission, refuse admin methods without TLS (S51)
  - note: Tower layer `crates/cmis/src/admin/layer.rs` on every listener plus per-handler `authz::require`; one `METHOD_ACCESS` table, deny by default, coverage test over the compiled file descriptor set (`admin::authz` unit tests). Plaintext listeners answer `FAILED_PRECONDITION tls_required`. Tests: `crates/cmis/tests/admin_layer.rs`, `admin_guard.rs`, `admin_e2e.rs`. Shipped in 0.29.0.
- [x] T251 Add local admin accounts with Argon2id passwords, policy, history and expiry (S51, S55)
  - note: `crates/cmis/src/admin/password.rs` (Argon2id RFC 9106, optional pepper, ≥ 24 chars and four classes, blocklist, forbidden substrings, history, 180-day expiry); tables in `crates/ferro-raft/src/admin.rs`. Tests: `admin_flows.rs::change_password_enforces_policy_and_forbids_reuse`, `an_expired_password_restricts_the_session_until_it_changes`, `ferro-raft/tests/admin_store.rs`.
- [x] T252 Verify TOTP second factors with replay protection and encrypted secrets (S51)
  - note: `crates/cmis/src/admin/totp.rs` (RFC 6238 vectors, ±1 step, forward-only step counter) and `keys.rs` (XChaCha20-Poly1305 sealing under `CMIS_ADMIN_SECRETS_KEY_FILE`). Tests: `admin_flows.rs::a_totp_code_is_accepted_once`, `admin_store.rs::totp_steps_only_move_forward`.
- [x] T253 Issue IP-bound admin sessions with idle and absolute limits, step-up and revocation (S51)
  - note: `crates/cmis/src/admin/session.rs`: hashed opaque tokens, 900 s idle and 12 h absolute caps, step-up window, rotation on step-up, eviction at 5. Tests: `admin_layer.rs::a_session_used_from_another_ip_is_revoked`, `idle_and_absolute_expiry_end_the_session`, `admin_flows.rs::five_failed_proofs_revoke_the_session`.
- [x] T254 Throttle admin logins per NRM §5.3.5 (S51)
  - note: `crates/cmis/src/admin/throttle.rs`, K_ip / K_dev / K_acct schedules 3 → 1 min, +2 → 15 min, +2 → 1 h. Tests: `admin_flows.rs::login_locks_the_source_ip_as_nrm_5_3_5_prescribes`, `parallel_guesses_cannot_outrun_the_lock`, `begin_login_floods_are_limited_per_ip`.
- [x] T255 Serve `ferrogate.admin.v1.Admin` on a dedicated hybrid-PQC TLS listener with optional mTLS (S51, S36)
  - note: `crates/cmis/src/server.rs` (`CMIS_ADMIN_LISTEN`, default `127.0.0.1:8444`, `CMIS_ADMIN_CLIENT_CA`), `ferro_crypto::transport::server_config_with_client_auth`. Tests: `crates/ferro-crypto/tests/mtls.rs`, `admin_layer.rs::the_admin_service_is_served_only_on_the_admin_listener`.
- [x] T256 Bootstrap the first admin account and enroll TOTP (S51)
  - note: `crates/cmis/src/admin/bootstrap.rs`: leader writes a one-time `0400` token to `CMIS_ADMIN_BOOTSTRAP_TOKEN_FILE`, never re-arms. Tests: `admin_e2e.rs`, `admin_flows.rs::enrollment_tokens_are_single_use_and_bootstrap_never_re_arms`, `admin_store.rs::bootstrap_creates_an_active_account_and_burns_the_token`.
- [x] T257 Add `ferrogate login`, `logout` and bearer-authenticated admin commands to the CLI (S51)
  - note: Delivered as `ferrogate admin login|logout|whoami|sessions|passwd|bootstrap|enroll|accounts|groups|factors` (`crates/ferrogate-cli/src/admin.rs`); legacy commands send the session to the admin listener and retry once after a step-up. Tests: `crates/ferrogate-cli/tests/admin_cli.rs`.
- [x] T258 Verify FIDO2/WebAuthn login, step-up and factor enrollment on the server (S51, S55)
  - note: `crates/cmis/src/admin/webauthn.rs` (ES256/EdDSA, `packed` attestation, origin and RP ID checks, counter clone detection) and `factors.rs`; `CMIS_ADMIN_TRAY_FIDO2_GROUPS`, `CMIS_ADMIN_WEBAUTHN_ORIGINS`. Tests: `crates/cmis/tests/admin_webauthn.rs` with a software authenticator. Client-side enrollment ships with M40 (F22).
- [x] T259 Require a host signature on `AppendAuditEvent` and rate-limit it per host (S51, S50)
  - note: Reusable F19 §7.1 verifier `crates/cmis/src/host_auth.rs` (SVID issued here, unexpired, not revoked; `cnf.jkt`; ECDSA-P256 over `ferrogate-audit-forward-v1 ‖ doc`; ±300 s; 600 s per-node nonce cache; per-host token bucket `CMIS_AUDIT_FORWARD_MAX_PER_MIN`, default 600); document `crates/ferro-svid/src/host_call.rs`; only host-originated event types accepted; MIA signs in `mia::audit_client::forward`. `ProposeAllowlist` now shares the SVID check, so revoked hosts are refused. Tests: `crates/cmis/tests/audit_forward.rs` (unsigned, wrong host, unbound key, foreign SVID, stale/future, replay, tampered event and document, wrong context, revoked host and SVID, rate limit, CMIS-only events), `proposals.rs::rejects_a_revoked_host`, `crates/mia/tests/e2e_attest.rs::audit_log_records_attest_events_and_proofs_verify_offline`.
- [x] T260 Propagate store write failures from the legacy allowlist and proposal paths (S50, S56)
  - note: `CmisState::{put_allowlist, put_proposal, delete_allowlist, delete_proposal}` return `ClusterError`; `SetAllowlist`, `ProposeAllowlist`, `DeleteAllowlist`, `DeleteProposal` answer `UNAVAILABLE store_unavailable` and audit nothing. Tests: `crates/cmis/tests/store_failures.rs` (SQLite trigger fault injection).
- [x] T261 Correct the admin-gating claim in the networking docs and bump the workspace to 0.29.0 (S35, S56)
  - note: `docs/networking.md` §1/§1a, `docs/operations.md` "Administrator access (F20)" and "Audit forwarding from hosts", `docs/cmis.md`, `docs/audit.md`, `docs/allowlist-provisioning.md`; `docs/change-v0.29.0.md`; CHANGELOG 0.29.0 records the breaking change and the known limitations.
- [x] T262 Pass the ESI pre-production security verification gate for the admin surface (S51, S56)

## [M37] App registration and approval ledger (F19)
> outcome: A user registers an application through the MIA helper, an administrator approves or denies it with a manual or same-path-and-user auto-update policy, approvals are never replaced by requests, and every MIA picks up new authorizations within 5 minutes.
> phase: P10
> spec: S50, S54, S56, S8

Supersedes the host-request flow of M35 once ADR-0004 is accepted.

- [x] T263 Add the hiqlite app-request, approval and lineage tables with the non-replacement invariant (S50, S54)
  - note: Ordered `schema_migrations` runner (`crates/ferro-raft/src/migrations.rs`); migration 1 is the F19 §2 ledger (`crates/ferro-raft/src/apps/schema.rs`): lineages, binaries, requests, approvals, approval revisions, `host_allowlist_state`. INV-1 to INV-3 are enforced twice: the store API (`apps::{intake, decisions, approvals}`: intake only inserts; every approval change names one id, checks `row_version` and appends a PII-free revision in the same Raft transaction; guarded transactions abort on a failed precondition) and SQLite triggers (no deletes, immutable binaries/revisions/identity columns, one decision per request, terminal states final, scope only narrows, `REVOKED` final, versioned changes need their revision row, auto-update copies an active unfrozen parent incl. expiry and never re-approves revoked/denied hashes, one open request per dedup key, dense never-reused revisions, monotonic generation). Store API also covers dedup, auto-approve conditions #2–#7, approve/deny/direct-register/revoke/edit/renew/expire, §7.5 search with keyset paging, host-scoped status, compile input and generation/digest CAS. Tests: `crates/ferro-raft/tests/app_ledger.rs` (`a_request_never_overwrites_an_approval`, `revisions_are_sequential_stable_and_never_reused`, `host_operations_never_change_existing_approvals`, auto-update, decisions, versioning, generation, search).
  - note: Security review fix: migration 2 (`apps::schema::APPROVAL_USER_GUARDS`) replaces three `app_approvals` triggers of migration 1 (kept as applied; `DROP TRIGGER IF EXISTS` + `CREATE` in one transaction, so existing databases are upgraded): `sid`/`user_name` changes are versioned and covered by `REVOKED`-final, and the only unversioned user change left is pseudonymising a `REVOKED` approval to `pseudonym:v1:<64 hex>` (`apps::is_pseudonym`). Tests: `app_ledger.rs::an_approvals_user_changes_in_place_only_by_pseudonymisation_once_revoked`, `migrations::tests::migration_2_replaces_the_guards_of_a_migration_1_database`.
- [x] T264 Identify binaries per platform without executing them, with sequential versions per lineage (S50)
  - note: New crate `crates/ferro-appid` (`#![forbid(unsafe_code)]`): hash and metadata from one handle (`identify`), §4.2 canonical path and `path_key` per platform, bounded read-only ELF `.note.package`, PE `VS_VERSIONINFO`/certificate table, Mach-O `LC_CODE_SIGNATURE`, bundle `Info.plist` (event stream, depth-bounded, symlink/hard-link/owner checks) and dpkg file parsers, §4.5 flags, display version `"<declared> (r<N>)"`; revisions are allocated by `Cluster::app_observe_binary`. No process spawning (`clippy.toml` `disallowed-methods` plus `tests/no_exec.rs`). Shared wire types in `crates/ferro-svid/src/{allowlist_v2,app_docs}.rs` (v2 context, `path_hash`/`sid_hash`; v1 unchanged). Tests: `crates/ferro-appid/tests/identify.rs` (fixtures, every truncation and 10 000 mutations never panic), `crates/ferro-svid/tests/f19_vectors.rs`.
- [x] T265 Add the host-authenticated `SubmitAppRequest`, `GetAppRequestStatus` and `SyncAllowlist` RPCs (S50)
  - note: Proto in `machine_identity.proto` (plus additive `GetAllowlistRequest.accept_formats`, ignored). Handlers in `crates/cmis/src/service.rs` over `crates/cmis/src/apps/{intake,status,compile}.rs`; `host_auth` generalised (per-RPC context, size bound, field-level `INVALID_ARGUMENT`, SVID tier) with per-host budgets `CMIS_APP_SUBMIT_MAX_PER_HOUR`, `CMIS_APP_STATUS_MAX_PER_HOUR`, `CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS`. Idempotent by `client_request_id`; dedup before any write; pending caps; `mode_legacy` while `cmis_settings.allowlist_mode` is `legacy` (switch is M38). Forwarded `AllowlistSync*` events must name the forwarding host. Tests: `crates/cmis/tests/app_host_rpcs.rs` (`host_auth_negatives_change_nothing`, `retries_and_duplicates_return_the_stored_request_unchanged`, `requests_never_replace_or_remove_an_approval`, `status_reveals_only_the_callers_own_requests`, `pending_caps_and_the_submission_budget_are_enforced`, `store_failures_answer_unavailable_and_audit_nothing`).
- [x] T266 Auto-approve same-publisher updates under `AutoSamePathUser`, never re-approving denied or revoked hashes (S50, S54)
  - note: `apps::intake::submit`: config gates #1 (`CMIS_APP_AUTO_UPDATE`, `CMIS_APP_AUTO_UPDATE_TIERS`) then `Cluster::app_try_auto_approve` (#2–#7 in the writing transaction); CMIS-set flags (signer change, version collision/downgrade, hash revoked/denied, `host_tier_b`); `AppRequestAutoApproved` records the continuity basis. Tests: `app_host_rpcs.rs::a_protected_path_update_is_auto_approved_with_the_parent_expiry`, `auto_update_never_reapproves_revoked_or_denied_hashes`, `configuration_gates_come_first`, `app_admin.rs::revoke_update_and_freeze_are_audited_and_change_the_served_allowlist` (lineage freeze).
- [x] T267 Add admin approve, deny, edit, revoke and direct-register operations with same-actor auditing (S50, S51)
  - note: Ten `Admin` RPCs (`admin.proto`; `ListHosts` deferred) in `crates/cmis/src/admin/apps.rs`, classified in `METHOD_ACCESS` (step-up for decisions/edits, per-operation `MfaProof` for `AdminRegisterApplication` and for approving one's own request with strict SoD off); `CMIS_ADMIN_STRICT_SOD` queues direct adds and forbids self-decisions; expiry/any-user caps (`CMIS_APPROVAL_*`); HMAC page tokens; exactly one F19 event per mutation, no PII (`ferro-audit` variants). CLI `ferrogate admin apps …` (`crates/ferrogate-cli/src/apps.rs`). Tests: `crates/cmis/tests/app_admin.rs`, `admin::authz` coverage tests, `crates/ferrogate-cli/tests/admin_cli.rs::apps_register_list_revoke_and_show_the_history`.
  - note: Security review fixes: `ApproveAppRequest` with `also_revoke_approval_ids` also needs `approval.revoke` (`app_admin.rs::also_revoking_needs_the_revoke_permission`); a host document that fails to decode is logged by reason/field code only, never the decoder's message, which can quote paths and user names (`app_host_rpcs.rs::a_malformed_document_is_logged_without_its_contents`).
- [x] T268 Compile per-host signed allowlist v2 with generation and rollback protection (S50, S54)
  - note: `crates/cmis/src/apps/compile.rs`: v2 entries from live approvals (uid / `sid_hash` / `path_hash` / expiry; legacy v1 entries with zero ids in `legacy` mode), digest compared on every sync and recorded by generation CAS (any change bumps `max(gen+1, unix_ms)`; the store trigger refuses a decrease), signed under `ferrogate-allowlist-v2`, cached until half-life, `not_modified` for the current generation, `AllowlistCompiled` once per change. v1 `GetAllowlist` unchanged. Tests: `app_host_rpcs.rs::sync_serves_signed_v2_bodies_with_monotonic_generations`, `legacy_mode_sync_serves_the_legacy_entries`.
- [x] T269 Poll `SyncAllowlist` from MIA every 5 minutes with jitter and atomic swap (S50)
  - note: `crates/mia/src/allowlist_sync/` (`allowlist.sync`, opt-in per F19-OQ1; interval 60–3600 s, ±jitter, random first delay, back-off, `retry-after`, wake on approval/`SIGHUP`): host-signed `AllowlistSyncDoc` (`mia::host_api`, signing shared with `audit_client::host_call_auth`), v2 body verified for signature, freshness, host, trust domain, rollback and equal-generation digest, written atomically with `allowlist.state` to the state directory (`allowlist[-<env>].synced.cbor`; never over `allowlist.path`), swapped live, `AllowlistSyncApplied`/`AllowlistSyncRejected`; `UNIMPLEMENTED` falls back to `GetAllowlist` v1 unless v2 is held. v2 matcher (`Allowlist::permits_caller`: uid, `sid_hash`, `path_hash`, entry expiry, hard `not_after` on every call); `CallerIdentity.exe_path`/`user_sid` (`ferro_winauth::process_user_sid`). F18 `sync`/`registrations` snapshot fields. Seccomp allow-list gains `rename`/`renameat2`/`lgetxattr`. Tests: `allowlist_sync::tests` (apply, rollback, wrong host, bad signature, generation conflict, half-life refresh, back-off, no SVID, v1 fallback, no downgrade, start-up admission), `helper::allowlist::tests::v2_*`, `allowlist_sync::schedule::tests`.
- [x] T270 Add helper protocol v2 and the `mia app` registration commands (S50, S8)
  - note: Wire types in the new `crates/mia-helper-proto` (v1 + `{v: 2, op}` envelope, `deny_unknown_fields`, bounded), re-exported by `mia::helper::proto`; the UDS server reads frames with `recvmsg` and takes one `SCM_RIGHTS` descriptor (`helper/server/fdpass.rs`). `crates/mia/src/registration/`: identify with `ferro-appid` from one open file (running image must match the authenticated hash; passed descriptor must be readable, regular, executable), MIA flags (protected/user-/world-writable, temp, network, ACL), signed `SubmitAppRequest` with a daemon-generated `client_request_id`, `0600` ledger with 30-day pruning, outbox (`mode_legacy` stays queued, `retry-after` honoured, invalid → refused), status poll, per-uid/host budgets. `mia app register|status|list` (`app_cli.rs`, exit 0/3/4/1/2); SDK feature `helper-client` (`helper::request_token`, `register_self`, `registration_status`). Tests: `mia-helper-proto` unit tests, `registration::tests`, `helper::server::fdpass::tests`, `app_cli::tests`, `crates/mia/tests/app_registration.rs` (register → approve → sync → token; legacy queue; legacy-mode sync), `ferrogate-sdk-rust` helper tests. Follow-ups: tray items, Windows `RegisterFile` (impersonated open) and signer summaries, macOS ACL/Windows DACL for `path_protected` (T290).
  - note: Security review fixes: (1) canonical paths are bound to the hashed file — `(st_dev, st_ino)` in MIA's mount namespace, and for a process the same mount namespace and root as MIA (`helper::exe_path::{bind, of_running_image}`) — for registration and for the runtime `path_hash` match, so a bind mount in a user namespace cannot fake a protected path; unbound paths are unresolved (fail closed), a deleted running image keeps its path but never `path_protected`; (2) `registration.max_open_per_uid` (default 50) caps open requests per requester and a full ledger drops the heaviest requester's oldest closed entry instead of refusing everyone; (3) ledger, limiter and status are keyed by the full SID on Windows; (4) macOS never sets `path_protected` (no ACL check, T290); (5) ledger decode and request-encode errors are logged without contents. Tests: `exe_path::tests`, `identify::tests::a_path_that_names_another_file_is_refused_not_protected`, `flags::tests::without_an_acl_check_nothing_is_protected`, `ledger::tests::{same_rid_users_of_different_domains_are_kept_apart, a_full_ledger_drops_the_flooders_oldest_closed_entry, a_malformed_ledger_error_never_quotes_its_contents}`, `registration::tests::{open_requests_are_capped_per_requester, a_full_ledger_does_not_block_other_requesters, same_rid_users_of_different_domains_get_their_own_requests}`.
- [x] T271 Expire approvals and sweep stale requests on the leader (S50)
  - note: `crates/cmis/src/apps/sweep.rs`, spawned from `main.rs`, every 60 s on the Raft leader: pending past `CMIS_APP_PENDING_TTL_SECS` → `EXPIRED` (`AppRequestExpired`), active past `expires_at` → `EXPIRED` with revision row and generation bump (`ApprovalExpired`); store failures end the pass and audit nothing. PII pseudonymisation after retention is not implemented (retention period awaits the DPO; open follow-up T289). Tests: `app_host_rpcs.rs::the_sweeper_expires_stale_requests_and_approvals`, `store_failures_answer_unavailable_and_audit_nothing`.

## [M38] Allowlist migration to approvals
> outcome: The fleet runs MIA agents that sync allowlist v2, legacy allowlists are imported as approvals, and CMIS switches to approvals mode with v1 kept only for old agents.
> phase: P10
> spec: S50, S54, S56

- [x] T272 Import legacy allowlists as approvals (S50, S54)
  - note: Store: `crates/ferro-raft/src/apps/legacy.rs` (`Cluster::app_import_legacy`, `app_legacy_imported`): each `(uid, bin_sha)` becomes an `ACTIVE` `legacy_import` approval (any path, manual each time, no expiry, no revision/approver, uid and `"*"` as stored) under an id derived from the entry (UUIDv8 of `SHA-256(host, uid, bin_sha)`), so a re-run creates nothing and a revoked import is never recreated; one Raft transaction per batch (≤ 256 entries) with a `stale` guard, the creation revision naming the importer, and a generation bump. Legacy imports name a per-host lineage id with no `app_lineages` row; schema migration 3 (`apps::schema::LEGACY_IMPORT_GUARDS`) refuses any other terms or a real lineage. `Cluster::list_allowlists_consistent` reads `host_allowlists` (never written). Policy and RPC: `crates/cmis/src/apps/migration.rs` (plan = dry run; undecodable bodies and non-UUID keys skipped and reported), `crates/cmis/src/admin/migration.rs` `ImportLegacyAllowlists` (`allowlist.import`, step-up, report bounded to 10 000 entries), one `AllowlistImported` per host that gained approvals after its batch committed; dry run audited only by the layer's `AdminCallAuthorized`. CLI `ferrogate admin migrate-allowlists [--dry-run]` (`crates/ferrogate-cli/src/migration.rs`). Tests: `crates/ferro-raft/tests/app_ledger.rs` (`legacy_import_creates_the_spec_approvals_once`, `legacy_import_validates_before_writing`, `the_database_holds_legacy_imports_to_their_terms`), `crates/cmis/tests/allowlist_migration.rs` (`a_dry_run_reports_the_import_and_writes_nothing`, `the_import_creates_the_approvals_once_and_keeps_the_legacy_rows`, `only_platform_operators_with_a_fresh_step_up_import_or_switch`, `store_failures_answer_unavailable_and_audit_nothing`).
- [x] T273 Switch CMIS to approvals mode and keep v1 `GetAllowlist` behind `CMIS_LEGACY_GETALLOWLIST` (S50)
  - note: `SetAllowlistMode` (`settings.allowlist_mode`, step-up) and `GetAllowlistMode` (any session) in `crates/cmis/src/admin/migration.rs`, classified in `METHOD_ACCESS` (`authz::tests::allowlist_migration_rpcs_need_the_spec_permissions`). `approvals` refused with `FAILED_PRECONDITION import_incomplete` while a legacy entry is not imported (override `allow_unimported`); `legacy` needs `confirm_rollback` and the dry run reports `approvals_not_reflected` (live non-legacy approvals) and `imports_readmitted` (revoked/expired legacy imports); same mode or dry run writes and audits nothing; a switch emits `AllowlistModeChanged`. In approvals mode `SetAllowlist`/`DeleteAllowlist` answer `FAILED_PRECONDITION mode_approvals` (`mode_legacy` kept for intake in legacy mode); `ProposeAllowlist` maps each new entry to an `observed` request in a per-hash "unknown path" placeholder lineage (`crates/cmis/src/apps/proposals.rs`; no TOFU, no legacy write; at most 4096 distinct entries, `too_many_entries`; submission budget and pending caps, deferred entries answered `RESOURCE_EXHAUSTED` so the agent retries; any-path scope enforced by `ApproveAppRequest`, `path_unknown`); `GetAllowlist` serves the F19 §6.4 lossy-safe v1 compile (`crates/cmis/src/apps/v1.rs`, per-node cache, signed body for any known host) and `CMIS_LEGACY_GETALLOWLIST=off` (`AppConfig::legacy_get_allowlist`, default on) answers `FAILED_PRECONDITION legacy_getallowlist_disabled` in both modes. CLI `ferrogate admin set-allowlist-mode legacy|approvals [--yes] [--allow-unimported]` (dry run first, confirmation or `--yes` for a rollback); `ferrogate allowlist add|remove` map to `AdminRegisterApplication` / `RevokeApproval` in approvals mode. Tests: `allowlist_migration.rs` (`approvals_mode_needs_the_import_and_retires_the_legacy_writes`, `v1_get_allowlist_serves_the_lossy_safe_compile_of_the_approvals`, `v1_get_allowlist_is_refused_once_turned_off`, `a_rollback_reports_what_changes_and_serves_the_preserved_legacy_body`, `proposals_become_observed_requests_and_are_never_adopted`, `an_oversized_proposal_is_refused_before_any_work`), `apps::v1::tests`, `crates/ferrogate-cli/tests/admin_cli.rs::migrate_allowlists_switch_modes_and_map_the_allowlist_commands`.
  - note: Security review fixes: (1) an import whose entry left its legacy body after the import (`SetAllowlist`/`DeleteAllowlist` in legacy mode) is reported as stale (`apps::migration::plan`, `Cluster::app_legacy_imports_of`, `app_hosts_with_open_legacy_imports`), revoked by the next import (reason `LEGACY_ENTRY_REMOVED` = 1000, one `ApprovalRevoked` each), and blocks the switch (`FAILED_PRECONDITION import_stale`, no override), so a removed binary cannot return in approvals mode; (2) legacy writes check the mode in their own Raft transaction (`Cluster::upsert_allowlist_unless_setting`, `delete_allowlist_unless_setting`) and the switch to approvals commits only if the legacy store is unchanged since its plan (`put_setting_if_legacy_unchanged`, `ABORTED concurrent_change`); (3) the public `GetAllowlist` answers malformed or unknown hosts from the local replica (`setting_local`, `app_host_known_local`); (4) an approvals-mode proposal reads the host's live approvals and open requests once per call; (5) the import report caps host lines (`hosts_truncated`); (6) CLI `allowlist remove` lists and confirms (`--yes` off a terminal) and refuses a truncated scan, and `allowlist add|remove` treat an `UNIMPLEMENTED` `GetAllowlistMode` as legacy. Tests: `allowlist_migration.rs::imports_whose_entry_left_the_legacy_body_are_revoked_before_the_switch`, `app_ledger.rs::legacy_writes_are_refused_in_the_same_transaction_as_the_mode`, `admin_cli.rs::migrate_allowlists_switch_modes_and_map_the_allowlist_commands`.
- [x] T274 Write the change document and migration runbook for 0.29 (S56)
  - note: 0.29.0 shipped F20 Phase 0 alone, so F19 (M37, M38) is planned as 0.30.0: `docs/change-v0.30.0.md` (FGV *documento de mudança*, draft; ESI pre-production verification pending; workspace version stays 0.29.0 until the release commit, as with M37). Runbook in `docs/operations.md` ("Migrating legacy allowlists to approvals"); approvals-mode behaviour, error codes and `CMIS_LEGACY_GETALLOWLIST` in `docs/cmis.md`, `docs/allowlist-provisioning.md`, `docs/audit.md`, `docs/mia.md`, F19 §7.4/§7.7/§11 and the F20 §7 table; `CHANGELOG.md` `[Unreleased]` (Added, Changed, Deprecated: v1 `GetAllowlist`).

## [M39] Server admin TUI (F21)
> outcome: An administrator on the server lists, searches, approves, denies, edits, revokes and adds applications from a curses-style terminal UI that goes through the same gRPC authorization as every other client.
> phase: P10
> spec: S52, S51, S50

- [x] T275 Build the `ferrogate-tui` ratatui app with TOTP login (S52)
  - note: New crate `crates/ferrogate-tui` (lib + bin, `#![forbid(unsafe_code)]`, ratatui 0.30 via its crossterm 0.29 backend, tokio): `app` (headless `App::update(Msg) -> Vec<Cmd>`), `screens` (pure views), `client` (one tokio task owning the channel and the token over bounded channels), `config`, `input`, `sanitize`, `secret`, `timefmt`; `main.rs` only owns the terminal (alternate screen, raw mode, bracketed paste; restored on exit, `Ctrl-C`, SIGTERM/SIGHUP and panic hook; cleared on lock and exit). Config `$XDG_CONFIG_HOME/ferrogate/admin.toml` (`~/.config/…`) else `/etc/ferrogate/admin.toml` or `--config` (`endpoint`, `spki_pins`, `device_token_path`, `refresh_secs` (0 off, else at least 5); the file is opened once with `O_NOFOLLOW | O_NONBLOCK` and checked on the handle (regular, ≤ 64 KiB, owned by the effective user or root, not group/other-writable) and every directory above it must pass the same owner check, sticky directories excepted — `config::{open_no_follow, trusted_owner_and_mode}`, through `rustix`), `FERROGATE_ADMIN_ENDPOINT`/`FERROGATE_ADMIN_SPKI_PIN` override; no pin → instructions and exit 2 (no TOFU); `https://host:port` with an explicit port only (`config::check_endpoint`: without one the transport would dial the main listener on 8443, whose certificate the admin listener shares by default), through `ferro_transport::connect_pinned` (hybrid-PQC, pin checked in the handshake before any RPC; dialling gives up after 10 s, `client::CONNECT_TIMEOUT`; every RPC has a 30 s deadline, `client::RPC_TIMEOUT`, after which the connection is redialled). `BeginLogin`/`Login` (client kind 1, TOTP only), forced `ChangePassword`, step-up modal (`BeginStepUp`/`StepUp`, rotated token adopted, one replay with the same idempotency key, no loop on a second `step_up_required`), idle lock at server idle − 30 s of no key (also on the password screen), `Ctrl-L`, `Logout` on quit (also when the terminal is lost, and a quit during the sign-in never shows the new session); lock and quit end the session through `client::SessionHandle::end`, which empties the shared token slot at once and moves its epoch (a token answered after the lock is logged out, never adopted) and hands `Logout` to a separate logout task, so a full command queue or a stuck RPC can neither drop it nor keep the token; a panic in any thread (`fatal` flag raised before the terminal is restored) or a dead client/input task stops drawing, ends the session and exits after clearing the screen, `session_invalid` → "Session ended"; replies to reads sent before a lock are dropped. Secrets in fixed-capacity `Zeroizing` buffers (`secret::Secret`, `SessionToken`), sensitive `authorization` metadata; `static_assertions` prove `Secret`, `SessionToken`, `Cmd`, `App`, `Msg`, `Phase`, `Modal`, `Form`, `Field`, `AdminConnection` implement neither `Debug` nor `Display` (nor `Clone`); no logging; device token `0600`, written and read never through a symlink (read with `O_NOFOLLOW`, private, ≤ 1 KiB). `NO_COLOR`/`--monochrome`, "terminal too small" below 80×24; EN strings only (PT and `--log-file` deferred). Decision: no `ferrogate-admin-client` crate yet (the CLI's admin code is bound to `inquire` prompts and `anyhow`; the shared part is the bearer interceptor and the `0600` file writer) — extract it with the tray admin client (M40). Tests: `app::tests` (login, throttle countdown, forced change, screen keys, idle lock incl. a hostile server idle timeout, `Ctrl-L`, session end, quit), `config::tests` (`only_files_and_directories_of_the_user_or_root_are_trusted`, `a_writable_configuration_or_directory_is_refused`), `client::tests` (incl. `a_silent_listener_times_out_before_any_credential_is_sent`, `an_endpoint_without_a_port_is_never_dialled`, `a_call_that_never_answers_meets_its_deadline`, `ending_the_session_wipes_at_once_and_a_late_token_is_not_adopted`, `a_logout_is_never_dropped_by_a_full_queue`), `config::tests::{an_endpoint_needs_https_and_an_explicit_port, a_symlinked_oversized_or_badly_placed_configuration_is_refused, the_device_token_is_read_from_a_private_bounded_file_only}`, `fatal::tests`, `app::tests::a_quit_during_the_sign_in_never_shows_the_new_session`, `secret::tests`, `screens::tests` (80×24 `TestBackend`), `crates/ferrogate-tui/tests/admin_tui.rs::{a_wrong_pin_is_refused_before_any_credential_is_sent, a_server_that_never_answers_meets_the_rpc_deadline, a_logout_through_the_session_handle_ends_the_server_session}`. Follow-ups: optional admin mTLS client certificate (`CMIS_ADMIN_CLIENT_CA`; the CLI has it, the TUI does not), password generator.
- [x] T276 Add request and approval lists with search and filters (S52)
  - note: `app/filters.rs`: Requests (state, origin, kind, host UUID, path/product contains, user, declared version, hash prefix ≥ 8 hex, flags any-of, submitted from/to `YYYY-MM-DD`, free text) and Approvals (preset expiring ≤ 14 d / legacy no expiry / superseded / auto-update, state, policy, origin, expires after/before, superseded, lineage, host, path, product, user, hash prefix, text) map one-to-one to `ListAppRequestsRequest`/`ListApprovalsRequest` fields; inline validation, 128-character limit, invalid panels never sent. Server paging (`n`/`p` with the MAC'd page tokens, 50 per page), `s` newest/oldest (the RPCs have no other sort key), `c` clear, `/` search, auto-refresh (`refresh_secs`), stale replies dropped by sequence number; a list made stale by a mutation is reloaded on the way back from a detail view. No hostname or user-scope filter (no such server field). Request and approval detail views (lineage binaries, requests, approvals, revisions; `h` full hash, `l` lineage), Dashboard (four bounded listings at `page_size` 200, "200+" when more). Hosts screen says "not available" (no `ListHosts` RPC, deferred in M37); Accounts (`ListAdminAccounts`, `account.list`) and Sessions (`ListMySessions`) are read-only. Tests: `app::filters::tests`, `app::tests::{the_filter_panel_validates_inline_and_sends_structured_fields, lists_page_with_server_tokens_and_drop_stale_replies, keys_needing_a_permission_are_refused_with_the_reason}`, `screens::tests`, `admin_tui.rs::login_list_and_approve_with_a_step_up_that_reuses_the_key`.
- [x] T277 Add approve, deny, edit, revoke and delete flows with confirmation (S52)
  - note: `app/dialogs.rs`: form → extra `y` for "Any user" / "Path + user only" → review page → `y` builds the request with a fresh idempotency key; `Esc` sends nothing. Approve defaults manual / anchored / this user / exact path / server default expiry; auto-update preselected only on `path_protected` or a valid signer equal to the previous active or expired (never revoked) revision's (`auto_update_preselected`); any-user auto-update on an unprotected path flagged inline; optional "also revoke" of active lineage approvals. Deny reason codes 1–6 (`unknown_software` … `other`), message ≤ 200. Edit sends only changed fields, narrowing only, `expected_row_version`; loosening continuity to "Path + user only" needs the extra `y` and the review flags it and a switch to auto-update; `ABORTED` reloads, lists what changed against the approval the edit was based on and re-opens the edit on the new row version. Revoke needs the typed short id (`A-` + the last 8 id characters: the head of a UUIDv7 is shared by approvals created in the same hours), reason codes 1–5. Freeze/unfreeze lineage (`z`). Success shows the ids, host generation and "within 5 minutes", then refreshes. Bulk revocation from the lineage view deferred. Tests: `app::dialogs::tests`, `app::dialogs::tests::{loosening_continuity_in_an_edit_needs_the_extra_y_and_is_flagged, a_revoked_previous_revision_does_not_preselect_auto_update}`, `app::tests::{approve_uses_safe_defaults_and_the_step_up_retry_reuses_the_key_once, a_wrong_step_up_code_asks_again_for_the_same_operation, edit_aborted_reloads_shows_the_change_and_asks_again, revoke_needs_the_typed_short_id}`, `admin_tui.rs::{login_list_and_approve_with_a_step_up_that_reuses_the_key, deny_edit_revoke_and_freeze_go_end_to_end, a_viewer_is_refused_by_the_server_even_when_the_client_is_forced}` (the end-to-end test denies with a reason code, edits against a concurrent edit through `ABORTED` → reload → re-ask, revokes after a refused wrong short id and freezes, each audited once by CMIS).
- [x] T278 Add the single-step "add application" flow with a fresh TOTP (S52, S50)
  - note: `A` (needs `app.direct_register`) opens `Dialog::register`: host UUID, platform, canonical path, SHA-384 (exactly 96 hex, lowercased), Unix uid or Windows SID/RID, user name, version, reason, "path writable only by administrators" (your assertion), and the approve terms with the same defaults and warnings. The review page states "registers AND approves … recorded as approved by the same person" (or, without `app_request.approve`, only the strict-SoD queue) and that the hash and path are the administrator's assertion. `y` always opens a fresh TOTP prompt, even inside the step-up window; the client task adds the `MfaProof` to `AdminRegisterApplication`; a wrong code changes nothing and the retry reuses the idempotency key. Outcome: "Registered and approved", "Queued for another approver" (strict SoD) or "Already approved" (deduplicated). Tests: `app::tests::a_direct_add_always_asks_for_a_fresh_code_and_reuses_its_key`, `app::dialogs::tests::the_add_dialog_validates_the_hash_and_states_the_outcome`, `admin_tui.rs::{add_application_asks_a_fresh_code_and_is_approved_in_one_step, under_strict_sod_the_add_stays_pending_for_another_approver}`.
- [x] T279 Strip terminal escape sequences from every rendered field (S52)
  - note: `crates/ferrogate-tui/src/sanitize.rs`: `display` turns C0, `DEL` and C1 into `\xNN` (so ESC-introduced CSI/OSC/DCS sequences, OSC 52 and OSC 8 included, and their BEL/ST terminators become inert text) and every `Default_Ignorable_Code_Point` (bidi overrides/isolates, direction marks, zero-width, variation selectors, Hangul fillers, tag characters) plus line/paragraph separators and interlinear annotations into `⟨U+XXXX⟩`; `width`, `truncate_end`, `truncate_middle` (paths) and `wrap` measure per grapheme exactly as ratatui's buffer does (`unicode-segmentation` + `unicode-width`), so a fitted cell never spills into the next column. Every server-supplied string (and every server error reason) reaches a ratatui span only through these helpers. Tests: `sanitize::tests::the_unit_table_escapes_every_dangerous_class`, `truncation_is_width_aware_and_keeps_both_ends_of_a_path`, `oversize_server_strings_are_cut_without_panicking`, proptest `arbitrary_bytes_never_emit_a_control` / `arbitrary_strings_never_emit_a_control` / `fitted_text_never_spills_out_of_its_column` (emoji + selectors, ZWJ, lam-alef, combining and halfwidth marks, checked against ratatui's own layout; 2 000 cases each, in `make test`), `screens::tests::{the_request_list_renders_hostile_strings_inert_and_flags_the_row, the_request_detail_shows_the_full_escaped_values, modals_render_inert_messages_and_masked_codes}`.

## [M40] Tray admin client (F22)
> outcome: An administrator logs in to the `mia-tray-admin` app with a password plus TOTP or FIDO2, enrolls factors, runs the admin routines and adds a local application in one step.
> phase: P10
> spec: S53, S51, S50, S18

- [ ] T280 Ship the `mia-tray-admin` binary with in-memory, zeroized credentials (S53)
- [ ] T281 Log in and step up with TOTP or FIDO2 from the tray admin client (S53, S51)
- [ ] T282 Enroll and manage TOTP and FIDO2 factors from the tray admin client (S53, S51)
- [ ] T283 Add request and approval administration screens to the tray admin client (S53)
- [ ] T284 Add a local application in one step from the tray admin client (S53, S50)
- [ ] T285 Package the tray admin client next to the unprivileged tray on every desktop platform (S53, S30)

## [M41] App approval hardening
> outcome: macOS signer identity feeds auto-update continuity, binary parsers run sandboxed, and a hardware-backed mTLS profile is available for administrators.
> phase: P10
> spec: S50, S51, S56

- [ ] T286 Use the macOS code-signing identity as the auto-update continuity anchor (S50)
  - note: Until T286 or T290 lands, a macOS binary has no continuity anchor at all: `path_protected` is never set on macOS (security review, fail closed), so an `anchored` auto-update there always downgrades to a pending request (`no_continuity_anchor`), and `any_user` cannot combine with `AutoSamePathUser`; `path_user_only` is unaffected.
- [ ] T287 Run binary metadata parsers in a sandbox (S50)
- [ ] T288 Offer a hardware-backed mTLS client-certificate profile for admins (S51, S55)
- [ ] T289 Pseudonymise closed F19 records after the DPO-approved retention period (S50, S56)
  - note: Open follow-up of T271 and the F19 security review; waits for the DPO's retention periods (F19 §10). The store accepts it already: a `REVOKED` approval's `sid`/`user_name` may be replaced in place by `pseudonym:v1:<64 hex>` only (migration 2); `EXPIRED` approvals must be revoked first. Also covers `app_requests` personal-data columns (terminal requests; the trigger does not yet restrict their pseudonym format) and MIA's `app-requests.cbor`.
- [ ] T290 Check macOS ACLs and Windows DACLs before setting `path_protected` (S50)
  - note: Security review: an ACL entry (`chmod +a`) can give a user write on a root-owned directory, and `mia` (`#![forbid(unsafe_code)]`) has no safe wrapper for `acl_get_link_np`/`getattrlist`, so macOS (and Windows) never set `path_protected` until this lands (`registration::flags`, fail closed).

## Backlog
- [>] T236 Run Raft peer traffic over hybrid-PQC TLS once hiqlite supports it (S5)
  - from: M8
  - why: now an upstream-hiqlite concern; QUIC was dropped with the hiqlite pivot, peer TLS is classical since T157, and operators who need PQC between peers pin the peer network to a private subnet.
- [>] T237 Offer a FoundationDB-backed Raft store for very large fleets (S5)
  - from: M8
  - why: hiqlite replaced FoundationDB on the M4 critical path; an FDB-backed `RaftLogStorage` stays a later follow-up.
- [>] T238 Package `mia` as a static-PIE musl build with statically linked TSS2 (S12)
  - from: M14
  - why: left as deployment work; the reproducibility gate runs on the PIE-by-default glibc build.
- [>] T239 Write the online emergency root-rotation runbook (S14, S38)
  - from: M17
  - why: deliberately out of F14's scope — risky and off the happy path; F14 covers only the planned annual rotation and periodic share refresh.
- [>] T240 Provide concrete Rekor and Sigsum `Anchor` drivers (S7)
  - from: M10
  - why: out of the 0.4.0 slice; the old text expects them to ship with per-deployment config, so whether they are an in-tree deliverable is undecided.
- [ ] T241 Add an Apple Managed Device Attestation (ACME-DA) tier to host-key attestation (S15)
- [ ] T242 Add an Apple App Attest tier to host-key attestation (S15)
- [ ] T243 Carry a richer assurance level than `policy_id` in host-key SVIDs (S15)
- [ ] T244 Serve the X.509-SVID credential to local workloads through the helper API (S17, S8)
- [ ] T245 Emit the incoming root's X.509 anchor from the offline ceremony (S17, S14)
- [ ] T246 Reuse the stored SVID credential to skip attestation within the F04 window (S4, S17)
- [ ] T247 Suppress allowlist proposal noise from `DynamicUser` hosts (S21)
- [ ] T248 Keep a short-lived rejection record for allowlist proposals (S22)
- [ ] T249 Refresh stale status notes in the READMEs, doc indexes and transport-tls.md (S19)
  - note: Inferred during migration: README.md / docs/README.md say crates are not split out of `src/`; docs/features/README.md shows stale F05/F06/F07/F10 statuses and omits F15/F16; docs/adr/README.md lists only ADR-0001; docs/transport-tls.md says the daemon does not yet dial CMIS; docs/testing.md says `formal/` is "to be created".

## Specs
| ID | Title | Path |
|----|-------|------|
| S1 | F01 — Hybrid PQC TLS transport | docs/features/F01-hybrid-pqc-tls.md |
| S2 | F02 — TPM 2.0 attestation engine | docs/features/F02-tpm-attestation.md |
| S3 | F03 — Composite Ed25519 + ML-DSA-65 signatures | docs/features/F03-composite-signatures.md |
| S4 | F04 — SVID issuance and lifecycle | docs/features/F04-svid-lifecycle.md |
| S5 | F05 — CMIS high availability | docs/features/F05-cmis-ha.md |
| S6 | F06 — TEE residency and threshold key shares | docs/features/F06-tee-threshold-keys.md |
| S7 | F07 — Merkle-chained immutable audit log | docs/features/F07-audit-log.md |
| S8 | F08 — Local helper API | docs/features/F08-helper-api.md |
| S9 | F09 — DPoP-bound child tokens | docs/features/F09-dpop-child-tokens.md |
| S10 | F10 — RIM and PCR policy management | docs/features/F10-rim-pcr-policy.md |
| S11 | F11 — Revocation and CRL distribution | docs/features/F11-revocation.md |
| S12 | F12 — MIA process hardening | docs/features/F12-mia-hardening.md |
| S13 | F13 — Zero-touch bootstrap and fleet enrollment | docs/features/F13-bootstrap-enrollment.md |
| S14 | F14 — Root key ceremony and rotation | docs/features/F14-root-key-ceremony.md |
| S15 | F15 — Host machine-identity attestation without a TPM | docs/features/F15-apple-attestation.md |
| S16 | F16 — Tiered attestation for VMs | docs/features/F16-vtpm-tiered-attestation.md |
| S17 | F17 — X.509-SVID profile | docs/features/F17-x509-svid.md |
| S18 | F18 — MIA tray companion | docs/features/F18-mia-tray.md |
| S19 | Feature index and status table | docs/features/README.md |
| S20 | ADR-0001 — gRPC over HTTP/REST for the control plane (Accepted) | docs/adr/0001-grpc-over-http-transport.md |
| S21 | ADR-0002 — Optional uid in caller allowlist entries (Accepted) | docs/adr/0002-allowlist-optional-uid.md |
| S22 | ADR-0003 — Host-side allowlist request and status commands (Proposed) | docs/adr/0003-host-allowlist-request-status.md |
| S23 | Architecture | docs/architecture.md |
| S24 | Threat model | docs/threat-model.md |
| S25 | Attestation protocol | docs/protocol.md |
| S26 | Cryptographic design | docs/crypto.md |
| S27 | TPM 2.0 engine | docs/tpm.md |
| S28 | CMIS server design | docs/cmis.md |
| S29 | MIA agent design | docs/mia.md |
| S30 | MIA tray companion user guide | docs/mia-tray.md |
| S31 | Local helper API | docs/helper-api.md |
| S32 | Allowlist provisioning | docs/allowlist-provisioning.md |
| S33 | Audit log design | docs/audit.md |
| S34 | Integration SDK | docs/sdk.md |
| S35 | Networking and ports | docs/networking.md |
| S36 | Transport security (TLS) | docs/transport-tls.md |
| S37 | Operations guide | docs/operations.md |
| S38 | Root key ceremony runbook | docs/operations/root-key-ceremony.md |
| S39 | Region-loss drill | docs/operations/drills/region-loss.md |
| S40 | Mass-revocation drill | docs/operations/drills/mass-revocation.md |
| S41 | Quorum-loss recovery drill | docs/operations/drills/quorum-loss-recovery.md |
| S42 | SRE alert runbooks index | docs/operations/runbooks/README.md |
| S43 | Runbook — CRL stale | docs/operations/runbooks/crl-stale.md |
| S44 | Runbook — key-share failure | docs/operations/runbooks/key-share-failure.md |
| S45 | Runbook — STH lag | docs/operations/runbooks/sth-lag.md |
| S46 | Testing and verification plan | docs/testing.md |
| S47 | Formal verification models | formal/README.md |
| S48 | CryptoVerif model of the hybrid AKE | formal/cryptoverif/hybrid_ake.cv |
| S49 | Tamarin model of the attestation protocol | formal/tamarin/attestation.spthy |
| S50 | F19 — Application registration and approval lifecycle | docs/features/F19-app-registration-approval.md |
| S51 | F20 — Administrator authentication and authorization | docs/features/F20-admin-authentication.md |
| S52 | F21 — Server administration TUI | docs/features/F21-admin-tui.md |
| S53 | F22 — Tray admin client | docs/features/F22-tray-admin-client.md |
| S54 | ADR-0004 — App approval ledger and non-replacement invariant (Proposed) | docs/adr/0004-app-approval-ledger.md |
| S55 | ADR-0005 — Administrator authentication (Proposed) | docs/adr/0005-admin-authentication.md |
| S56 | App approval and administration overview | docs/app-approval-and-admin.md |

## Phases
| ID | Title | Outcome |
|----|-------|---------|
| P1 | Workspace bootstrap (legacy roadmap M0) | The workspace and CI scaffolding let feature work land in clean slices. |
| P2 | Cryptographic foundation (legacy roadmap M1) | The hybrid-PQC TLS and composite-signature primitives every feature depends on exist and are tested. |
| P3 | TPM attestation MVP (legacy roadmap M2) | A host attests against a software TPM to a single CMIS replica and receives a verifiable SVID. |
| P4 | Audit log (legacy roadmap M3) | The system is externally observable through a verifiable Merkle audit log. |
| P5 | HA and TEE (legacy roadmap M4) | CMIS runs as a replicated, TEE-attested cluster with threshold key shares. |
| P6 | Host operations and helper API (legacy roadmap M5) | Real applications and operators can use the system through the helper API, revocation, hardening, enrollment and the tray. |
| P7 | Ceremony, drills, and production readiness (legacy roadmap M6) | Root keys rotate through an audited ceremony, drills are rehearsed, the protocols are formally verified and the live transport is hybrid-PQC. |
| P8 | Fleet deployment and cross-platform agents (post-roadmap, 0.13.0 onward) | MIA and CMIS deploy across Linux, macOS and Windows fleets with provisioning, HA, TPM-less attestation and the X.509-SVID profile. |
| P9 | Production hardening (planned) | The seams left open by earlier milestones are closed and the CI gates are restored. |
| P10 | App approval and administration (planned, 0.29.0 onward) | Applications are registered and approved through an audited ledger, and administrators authenticate to every admin surface. |
