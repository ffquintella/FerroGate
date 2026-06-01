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

**M2 status: complete.** F02 (TPM 2.0 attestation engine), F04 (SVID
issuance and lifecycle), and the M2 subset of F10 (signed RIM bundles +
generational allowlist + hot reload) are all landed and tagged as `v0.2.0`.
Verified on Linux (`docker/f02-dev`) with `cargo test --workspace
--all-targets` (incl. the `swtpm` attest and seal tests), `clippy -D
warnings`, and `fmt --check`. The remaining F10 work (`bump_epoch` admin
RPC, signed-S3 refresh) is sequenced in M5 alongside the rest of the host
operations track.

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

- [x] RIM bundle format and loader. (`ferro-attest::rim_bundle` defines `RimBundle` (version, policy_id, validity window, approved SHA-384 digests) and the `SignedRimBundle` wire form; `ferro-attest::rim_loader::RimLoader::try_reload` reads, verifies, and applies an on-disk bundle.)
- [x] RIM signature verification. (Composite Ed25519 + ML-DSA-65 over canonical JSON with domain-separation context `ferrogate-rim-v1`. Fail-closed: bundles without a recognised `signer_kid`, with a malformed signature, or with a tampered body are refused before any state changes. There is no path into the store that bypasses verification.)
- [x] 6-generation retention. (`MAX_GENERATIONS = 6`; `RimStore::apply` pushes the new generation and prunes the oldest beyond the limit. Per-generation `not_before`/`not_after` windows are honoured at lookup time, and a non-monotonic version is rejected with `ApplyError::NonMonotonic`.)
- [x] Hot reload from local file (S3 deferred to M5). (`cmis::rim_watcher::spawn` runs a small tokio task that periodically calls `try_reload`. The swap is atomic — a single `parking_lot::RwLock` write — so in-flight `Attest` handlers always see a consistent generation set. CMIS maps `RejectReason::NotInRim` to `FAILED_PRECONDITION` to match the documented error model.)

**F10 (M2 subset) status: done.** Verified on Linux with `cargo test --workspace --all-targets`, `clippy -D warnings`, and `fmt --check`. The M5 follow-ons (`bump_epoch` admin RPC and signed-S3 refresh) remain explicitly out of M2 scope.

## Milestone M3 — Audit log

Make the system externally observable before adding HA complexity.

### F07 — Audit log

- [x] Event enum and CBOR encoding in `ferro-audit`. (`crates/ferro-audit/src/event.rs` defines the seven-variant `AuditEvent` mirroring `docs/audit.md`; encoding via `ciborium`. The fixed-size hash fields use the `Hash384` / `Bytes16` newtypes in `bytes.rs` so they serialise as compact CBOR byte strings rather than arrays-of-small-ints.)
- [x] In-process Merkle tree with SHA3-384 leaves. (`crates/ferro-audit/src/merkle.rs` implements the RFC 6962 algorithms — domain-separated `leaf_hash(0x00 || …)` and `node_hash(0x01 || …)`, plus `inclusion_proof`, `consistency_proof`, and standalone verifiers usable by any third party.)
- [x] STH structure and TEE-style signing stub (replaced in M4). (`crates/ferro-audit/src/sth.rs`: `SthBody { tree_size, root_hash, timestamp }` carried over the wire as canonical CBOR + a composite Ed25519 + ML-DSA-65 signature under domain context `ferrogate-sth-v1`. The signer is a trait; `InProcessSigner` is the M3 stub.)
- [x] Backing-store abstraction with a local-disk WORM implementation for dev. (`crates/ferro-audit/src/store.rs`: `AuditStore` trait + `LocalDiskWormStore`. `O_CREAT|O_EXCL` makes a leaf or STH file uncoverwriteable. The S3 Object Lock implementation lands in M4.)
- [x] Inclusion and consistency proof endpoints on CMIS. (`ferro-proto` adds `LatestSth`, `InclusionProof`, `ConsistencyProof`, and `AppendAuditEvent` RPCs; `crates/cmis/src/service.rs` implements them against the shared `AuditLog`.)
- [x] Property tests covering inclusion and consistency. (`crates/ferro-audit/src/log.rs` proptest: 24 cases, tree sizes 1..=12, asserts `verify_inclusion` holds for every leaf and `verify_consistency` holds for every `(m, n)` pair against the matching captured STH roots.)
- [x] Forward MIA events into the CMIS audit stream. (`crates/mia/src/audit_client.rs::forward` encodes a `ferro_audit::AuditEvent` to CBOR and submits it through `AppendAuditEvent`. End-to-end driven in `crates/mia/tests/e2e_attest.rs::audit_log_records_attest_events_and_proofs_verify_offline`, which after an Attest fetches the STH, verifies the signature, fetches an inclusion proof, verifies offline, forwards a `LocalGrant`, and checks a consistency proof back to the prior STH.)

**M3 status: complete.** Verified on Linux (`docker/f02-dev`) with `cargo test --workspace --all-targets`, `clippy -D warnings`, and `fmt --check`. The M4 follow-ons (Raft co-signed STHs, S3 Object Lock store, Sigsum / Rekor anchor publisher) remain explicitly out of M3 scope.

## Milestone M4 — HA and TEE

Promote CMIS from a single replica into a TEE-attested cluster.

### F05 — CMIS high availability

- [x] Embed a Raft library with persistent storage. (`crates/ferro-raft` wraps [hiqlite](https://crates.io/crates/hiqlite) 0.13 — openraft 0.9 underneath, SQLite state machine + WAL on disk. Typed surface (`Cluster::upsert_svid` / `fetch_svid_consistent` / `current_rim_version` / `bump_rim_version` / `role` / `is_healthy`) hides hiqlite from the rest of CMIS so the underlying engine can be swapped later.) **Note:** the original roadmap line named FoundationDB; hiqlite was chosen because it ships openraft + a durable state machine + the peer transport in one package, dropping ~3 k LOC of unverifiable adapter code from the M4 critical path. A FoundationDB store remains an option for very-large-fleet deployments and is tracked as a follow-up task.
- [ ] Raft transport over QUIC with hybrid-PQC TLS between peers. *(Now an upstream-hiqlite concern. Hiqlite uses its own peer transport over TCP; PQC TLS between peers is tracked at the hiqlite project. Operators that need PQC peer TLS today pin the peer network to a private subnet.)*
- [x] Leader election and follower rejoin tested in a 3-node local cluster. (`crates/ferro-raft/tests/cluster_e2e.rs`: three in-process nodes on free ports, asserts election agreement across all peers, replication to a follower, and a follower rejoin path that restarts the process with the same `node_id`/`data_dir` and recovers the previously-replicated row.)
- [x] Health endpoints gated on Raft state. (`MachineIdentity.Health` returns `(healthy, role, node_id)`; the response mirrors `Cluster::is_healthy` / `Cluster::role`. An L4/L7 LB maps `!healthy` or `NODE_ROLE_UNKNOWN` to "not ready". Exercised on both leader and follower paths by `crates/mia/tests/cluster_attest.rs`.)
- [x] CMIS issuance routed through the cluster. (`CmisState::new_clustered` plugs an `Arc<Cluster>` into the state; `record` / `lookup` / `update_bundle` route through `Cluster::upsert_svid` / `fetch_svid_consistent`. Issued records are JSON-encoded via `cmis::cluster_store::WireIssuedRecord` because the underlying `ferro-svid` structs carry `[u8; 48]` fields that `serde`-derive cannot deserialise directly. `crates/mia/tests/cluster_attest.rs` drives a full four-phase `Attest` on the leader and asserts the SVID is visible via `FetchSVID` on a follower.)
- [x] Chaos test: random kills, zero client-visible errors. (`short_chaos_run_keeps_serving_while_quorum_holds` cycles kill+revive across 6 rounds and asserts every replicated write survives. The literal 10-minute variant `ten_minute_chaos_run` is `#[ignore]`-gated and runs on a beefier CI worker.)

**F05 status: done for M4.** The Raft cluster layer (election / replication / follower rejoin / chaos) is exercised by `cargo test -p ferro-raft --test cluster_e2e` (≈4 min). CMIS issuance is now genuinely cluster-mediated and the `Health` RPC surfaces the Raft state — verified by `crates/mia/tests/cluster_attest.rs` which drives a four-phase `Attest` across three CMIS instances on top of a 3-node hiqlite cluster. A test-only limitation worth recording: hiqlite's node-id-1 owns cluster-bootstrap responsibilities and a graceful shutdown of node 1 specifically does not let the remaining quorum re-elect cleanly in-process; the leader-kill scenario is therefore exercised by the long chaos run instead of a focused unit test.

### F06 — TEE residency and threshold key shares

- [x] SEV-SNP attestation report production and verification. (`crates/ferro-tee/src/attest.rs` — `Attestor` trait + `Report`/`ReportBody`/`verify_report`; covered by `snp_report_round_trips_through_verify`.)
- [x] Intel TDX equivalent. (Same `Attestor` trait; `AttestorKind::Tdx` exercised by `tdx_report_round_trips_through_verify`.)
- [x] Shamir 3-of-5 over GF(2^256), unit-tested. (`crates/ferro-tee/src/shamir.rs` — byte-parallel GF(2^8) over the AES Rijndael polynomial, info-theoretically equivalent to a single GF(2^256) construction; `three_of_five_reconstructs`, `two_shares_yield_a_wrong_secret_almost_surely`, `lone_share_does_not_leak_secret`, `gf_inverse_is_correct`.)
- [x] Per-replica sealing of shares against enclave measurements. (`crates/ferro-tee/src/seal.rs` — ChaCha20-Poly1305 keyed via HKDF-SHA3-384 over `(sealing_root, measurement, aad)`; `different_attestor_with_same_measurement_cannot_unseal`, `wrong_measurement_is_rejected_before_aead`, `tampered_aad_is_rejected`, `replica_cannot_unseal_anothers_share`.)
- [x] Mutual peer attestation before share exchange. (`crates/ferro-tee/src/psk.rs` — both sides verify the peer's report and check `Allowlist::contains` before deriving the PSK; `happy_path_both_sides_derive_same_psk`, `initiator_not_on_allowlist_is_refused`, `responder_with_swapped_root_is_refused`, `replica_not_on_allowlist_is_refused`.)
- [x] ML-KEM-768 PSK channels for share transport. (`crates/ferro-tee/src/psk.rs` — `Initiator::start` / `respond` / `Initiator::finish`; transcript binds nonces + ek + ciphertext; e2e share transport exercised by `full_three_of_five_round_trip`.)
- [x] Zeroize-on-drop verified by a Drop test. (`crates/ferro-tee/src/key.rs::protected_key_wipes_in_place`; same `Zeroize::zeroize` path that `Drop` runs. `Share` also derives `ZeroizeOnDrop`.)
- [ ] STH signing in M3 swapped to use the threshold key. *(Deferred: lands with the hardware `Attestor` driver work — the `ferro_tee::Reconstructor` → `ProtectedKey` seam is in place and the M3 audit signer is already a trait, so the swap is a non-API-breaking change on either side.)*

### F07 — Audit log (continued)

- [x] Co-sign STHs by a Raft majority before publication. (`crates/ferro-audit/src/cosign.rs` — `QuorumSigner` aggregates per-replica composite signatures over the same canonical `SthBody` CBOR; `verify_cosigned` accepts the artefact iff at least `threshold` *distinct* listed signatures verify under the keyset, so duplicate kids cannot inflate quorum and unknown kids are silently ignored. `AuditLog::produce_cosigned_sth` produces a `CoSignedTreeHead` from the current tree, persists it via the WORM store (new `record_cosigned_sth` on `AuditStore`, with a `cosigned/` subdir on `LocalDiskWormStore`), and caches it as the latest. Per-peer transport — i.e. an RPC `SthSigner` that talks to the cluster peers through `ferro-raft` — remains a deployment-wiring task; the trait seam already accepts it without further API changes.)
- [x] Sigsum / Rekor anchor publisher with back-fill. (`crates/ferro-audit/src/anchor.rs` — `Anchor` trait abstracts the transparency-log driver (one impl per log family; the HTTP wire is deployment-wiring behind the trait), `AnchorQueue` persists pending `CoSignedTreeHead`s on disk under `pending/<tree_size>.{sth.json,enq}` so a publisher restart never drops anchors during an upstream outage, and `AnchorPublisher::drain_once` drives a single drain pass: entries are submitted in `tree_size` order, a `Transient` failure stops the drain so the publisher does not hammer an unavailable log, a `Permanent` failure quarantines the entry under `dead/` and the drain continues, and `DrainOutcome::backlog_seconds_after` reports the worst-case age the operator alerts on at the documented 5-minute threshold.)
**F07 (continued) status: done.** Co-signed STHs (M4) and the anchor
publisher with persistent back-fill (M4) have landed and ship in `v0.3.0`.
Production WORM is provided by `LocalDiskWormStore`'s `O_CREAT|O_EXCL`
semantics; deployments that want a cloud-object backing store plug it in
behind the existing `AuditStore` trait as deployment wiring (the seam —
`record_cosigned_sth` / `record_sth` — is already in place). Concrete
Sigsum / Rekor HTTP drivers (`Anchor` impls) plug in behind the existing
trait the same way; both wire formats are short (`POST /api/v1/log/entries`
for Rekor; the Sigsum `add-leaf` request for Sigsum) and add nothing the
audit crate's API needs to learn about.

## Milestone M5 — Host operations and helper API

Make the system usable by real applications and operators.

### F08 — Local helper API

- [x] UDS listener at `/run/ferrogate/mia.sock` with correct permissions.
- [x] CBOR request/response framing.
- [x] `SO_PEERCRED` + IMA runtime-hash caller authentication.
- [x] Signed allowlist loader with fail-closed verification.
- [x] `LocalGrant` / `LocalDenied` audit events.
- [x] Concurrency / starvation test.
- [x] Windows Named Pipe variant.

### F09 — DPoP-bound child tokens

- [x] Token minter with TTL clamp, `jti`, `cnf.jkt` (landed with F08).
- [x] JWKS endpoint on CMIS with multi-key support. (`CmisState` publishes the
      issuer SVID key plus each host's composite child-token signing key,
      registered at phase-4 attestation under a deterministic
      `ferro_svid::child_signing_kid`; the `JWKS` RPC serves the merged set.)
- [x] Reference verifier in Rust. (`crates/ferro-child-verify`: composite
      signature against the JWKS, `exp`, and the RFC 9449 DPoP binding via
      `verify_bound` / `verify_dpop_proof`, RFC 7638 thumbprint.)
- [~] ~~Reference verifier in Go.~~ Scoped out — the Rust crate is the canonical
      interop reference; no second-language verifier ships in-tree.
- [x] Replay/no-DPoP-proof negative tests against the verifier.
      (`ferro-child-verify` unit tests + `crates/mia/tests/child_token_verify.rs`:
      a no-proof bearer token is rejected with `MissingDpopProof`.)

**F09 status: done.** The minter (F08) plus the JWKS multi-key publication, the
`ferro-child-verify` reference verifier, and the replay/no-DPoP negative tests
land here and ship in `v0.6.0`. Verified with `cargo test -p ferro-child-verify`,
`cargo test -p mia --test child_token_verify`, the multi-key assertions in
`crates/mia/tests/e2e_attest.rs`, and `clippy -D warnings` + `fmt --check`. One
seam is intentionally left for later: the per-host JWKS registry is process-local
(a verifier must reach a replica that has seen the host's attestation); making it
cluster-wide means persisting `composite_pub` in the issued-SVID store.

### F11 — Revocation and CRL distribution

- [x] Admin RPC `revoke_svid(cert_sha, reason)`. (`MachineIdentity.RevokeSvid`
      plus `RevokeHost` for per-host revocation; `crates/cmis/src/service.rs`.)
- [x] CRL delta publisher (60 s cadence). (`crates/cmis/src/crl_publisher.rs`
      heartbeat plus an inline publish on every revoke so a revocation lands
      within one cycle. Expired entries — past the 1 h max SVID TTL — are pruned
      each cycle to bound CRL growth.)
- [x] JWKS `x-ferrogate-crl` extension. (`ferro_svid::JwkSet` carries an
      optional composite-signed `SignedCrl`; `CmisState::published_jwks`
      attaches it. The member is omitted when no CRL has been published.)
- [x] MIA freshness enforcement (≤ 5 min). (`crates/mia/src/helper/crl.rs`
      cache + gate; a stale or missing CRL fails closed with `CrlStale`.)
- [x] CRL signature verification (fail closed). (`SignedCrl::verify` in
      `ferro-svid`, the MIA-side `crl::ingest`, and the reference verifier's
      `verify_unrevoked` all reject unknown-kid / wrong-key / tampered CRLs
      without yielding the body.)

**F11 status: done.** Verified with `cargo test -p ferro-svid`,
`cargo test -p ferro-svid-verify`, `cargo test -p cmis --test revocation`, and
`cargo test -p mia --test helper_api`, plus `clippy -D warnings` and
`fmt --check`. Two deployment seams are deferred (cluster-replicated revocation
set; wiring the MIA CRL puller into the not-yet-landed attestation loop) — both
recorded in [features/F11-revocation.md](features/F11-revocation.md) §"Status".

### F12 — MIA process hardening

- [x] `prctl` and `mlockall` startup. (`ferro_harden::apply` — `PR_SET_DUMPABLE`,
      `PR_SET_NO_NEW_PRIVS`, `mlockall(MCL_CURRENT|MCL_FUTURE)`, applied on the
      startup thread before the tokio runtime spawns.)
- [x] seccomp-bpf allowlist with audit-mode toggle for dev. (~70-name explicit
      allow-list via `seccompiler`; `FERROGATE_SECCOMP=enforce|audit|off`. The
      enforcing filter is proven to `SIGSYS`-kill a forbidden syscall by a
      unit test.)
- [x] Drop to `_ferrogate` UID with `CAP_IPC_LOCK` only. (`drop_privileges` +
      `restrict_caps_to_ipc_lock`; `harden()` verifies the post-drop effective
      set is exactly `{CAP_IPC_LOCK}`.)
- [x] Fail-closed IMA-enforcement check. (`mia::hardening` refuses to start
      unless `/proc/cmdline` requests `ima_appraise=enforce`.)
- [x] Reproducible build job in CI (byte-identical re-builds).
      (`scripts/reproducible-build.sh` + the `reproducible-build` CI job.)
- [x] `#![forbid(unsafe_code)]` on all MIA modules. (All FFI isolated in the new
      `ferro-harden` crate; the `no-unsafe-in-mia` CI job is a grep backstop.)

**F12 status: done.** All hardening FFI lives in the new `ferro-harden` crate
(Linux analogue of `ferro-winauth`), keeping `mia` `#![forbid(unsafe_code)]`.
Verified with `cargo test -p ferro-harden` on Linux (incl. the live seccomp
`SIGSYS` self-test and per-arch syscall-name resolution), the `mia::hardening`
parser tests, `clippy -D warnings`, and the reproducible-build check. Static-PIE
musl packaging (static TSS2) is left as deployment work; the reproducibility
gate runs on the PIE-by-default glibc build.

### F13 — Zero-touch bootstrap and fleet enrollment

- [x] Fleet manifest format and offline signing tool (`tools/fleet-manifest`).
      (`SignedFleetManifest` in `crates/cmis/src/fleet_manifest.rs`,
      composite-signed canonical JSON under the `ferrogate-fleet-v1` context;
      the `fleet-manifest` CLI does `keygen`/`new`/`add`/`remove`/`sign`/
      `verify`/`show`, with deterministic seed-derived publisher keys via
      `CompositeSecretKey::from_seed`.)
- [x] CMIS load. (`FleetManifestLoader` + `fleet_watcher` poll/verify/hot-swap
      into the `FleetStore` held by `CmisState`; `main` loads from
      `CMIS_FLEET_MANIFEST` fail-closed and spawns the watcher. Signed-S3
      refresh reuses the loader's verify-then-swap path and is tracked under the
      M5 follow-ons below.)
- [x] Pre-admission lookup at start of `Attest`. (`CmisState::check_enrollment`
      runs on the phase-2 EK hash before any TPM verification work; unenforced
      until a manifest is loaded, so a CMIS with no manifest behaves as before.)
- [x] Audit events `HostEnrolled` / `HostRejected`.

**F13 status: done.** Zero-touch enrolment anchors a host's first SVID in the
vendor EK signature plus an offline-signed fleet manifest of approved EK
SHA-384 hashes. Admission is checked at the cheapest point — before quote
verification — and is atomic: a refresh swaps an `Arc<EnrolledHosts>` under a
write lock, so an in-flight `Attest` sees a consistent snapshot. Verified with
`cargo test` across `ferro-crypto` (seed determinism), `cmis::fleet_manifest`
(sign/verify/tamper/atomic-swap), the `mia` e2e harness (enrolled host attests;
un-enrolled host rejected before any quote work, one `HostRejected` leaf only),
and the `fleet-manifest` CLI lifecycle, plus `clippy -D warnings`.

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
