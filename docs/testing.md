# Testing and Verification

## Test plan

| Layer | Test | Tooling |
|-------|------|---------|
| Hybrid TLS handshake | Wycheproof vectors plus interop against BoringSSL PQ branch | `cargo test`, cross-impl harness |
| Composite signature | NIST FIPS-204 KAT plus Ed25519 RFC 8032 vectors; AND-combiner conformance | KAT runner |
| TPM quote verify | `swtpm` with scripted PCR sequences; positive and negative cases | integration tests |
| Credential activation | `swtpm` with mismatched AIK/EK pairs to confirm rejection | integration tests |
| Audit Merkle tree | Property tests on random insertions and inclusion/exclusion proofs | `proptest` |
| Attestation state machine | Out-of-order and replayed phases, malformed CBOR | `cargo test` |
| TEE report parsers | Differential fuzzing of SEV-SNP and TDX report decoders | `cargo-fuzz` |
| Helper allowlist enforcement | Spoofed `/proc/<pid>/exe` and IMA-disabled rejected | qemu-kvm with IMA |
| Forward secrecy | Replay captured handshake with a simulated ML-KEM secret leak | red-team harness |
| Sealing on PCR drift | Mutate one of `{0,4,7,8}` and confirm unseal fails | swtpm integration |

## Coverage targets

- Line coverage ≥ 85% on `ferro-crypto`, `ferro-attest`, `ferro-audit`.
- Branch coverage ≥ 80% on the CMIS attestation handler and the MIA helper
  authentication path.

`cargo llvm-cov` is the canonical tool. CI fails on regression of coverage by
more than two points.

## Formal verification targets

The handshake and the hybrid AKE are too important to leave to property
tests alone. Two formal artefacts are maintained alongside the code:

- **CryptoVerif model** of the hybrid AKE. Proves IND-CCA2 of session keys
  under the assumption that *at least one* of `{X25519, ML-KEM-768}` is
  secure.
- **Tamarin model** of the four-phase attestation protocol. Proves:
  - Injective agreement between MIA and CMIS on the tuple
    `(EK, AIK, nonce, pcr_digest)`.
  - Aliveness of the AIK in the same TPM as the EK
    (TPM2_ActivateCredential as proof-of-residency).
  - Secrecy of the activation challenge against all configured adversary
    classes (see [threat-model.md](threat-model.md)).

The Tamarin and CryptoVerif models live under `formal/` (to be created) and
must remain consistent with the proto3 definitions in `crates/ferro-proto`.

## CI gates

1. `make fmt`, `make lint`, `make test`, `make check` — all clean.
2. `cargo audit` — no known advisories on the dependency tree.
3. `cargo deny check` — license and source policy.
4. KAT runner passes.
5. Tamarin and CryptoVerif models build and verify within budget.
6. Coverage targets met.
7. Reproducible build check: two independent builds of the MIA binary must
   yield byte-identical artefacts. This anchors the IMA-measured hash that
   appears in helper allowlists across the fleet.

## Manual test surfaces

A small number of behaviours cannot be fully automated and require periodic
manual rehearsal:

- Annual root key rotation (full ceremony dry run, quarterly).
- Mass revocation drill (`policy_id` epoch bump in a staging fleet).
- Region loss drill (cut a region; confirm traffic moves; confirm STH
  publication continues from survivors).
