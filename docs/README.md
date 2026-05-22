# FerroGate Documentation

FerroGate is a high-availability, post-quantum secure, TPM 2.0-attested machine
identity system built on the SPIFFE framework. It issues short-lived, hardware-
rooted SVIDs to host nodes after a four-phase attestation protocol and serves
sender-constrained tokens to local applications over a hardened helper API.

The system is split into two components:

- **CMIS** (Central Machine Identity Service) — stateless gRPC server, runs in a
  TEE (AMD SEV-SNP / Intel TDX), validates TPM evidence, issues PQC-signed
  SVIDs.
- **MIA** (Machine Identity Agent) — tamper-resistant host daemon, talks to the
  local TPM 2.0, authenticates to CMIS over hybrid-PQC TLS, exposes a local
  helper socket to applications.

## Documents

| File | Purpose |
|------|---------|
| [architecture.md](architecture.md) | System topology, HA design, component map |
| [threat-model.md](threat-model.md) | Adversary classes, security goals, mitigations |
| [protocol.md](protocol.md) | Four-phase attestation handshake, wire formats |
| [crypto.md](crypto.md) | Hybrid PQC primitives, composite signatures, TLS groups |
| [tpm.md](tpm.md) | TPM 2.0 attestation engine, PCR policy, credential activation |
| [cmis.md](cmis.md) | CMIS server design, threshold signing, TEE integration |
| [mia.md](mia.md) | MIA agent design, hardening, TPM glue |
| [helper-api.md](helper-api.md) | Local UDS/Named-Pipe API, caller authentication |
| [audit.md](audit.md) | Merkle-chained immutable audit log |
| [operations.md](operations.md) | Bootstrap, rotation, revocation, key ceremony |
| [testing.md](testing.md) | Test plan, formal verification targets |
| [features/](features/README.md) | Per-feature design notes and acceptance criteria |
| [roadmap.md](roadmap.md) | Milestone-organised checklist tracking implementation progress |

## Quick orientation

If you are new to the system, read in this order:

1. [architecture.md](architecture.md) — what the parts are.
2. [threat-model.md](threat-model.md) — what we are defending against.
3. [protocol.md](protocol.md) — how a host gets an identity.
4. The component docs ([cmis.md](cmis.md), [mia.md](mia.md)) for implementation
   details.

## Status

This repository currently contains the design documentation and an ironroot
CLI scaffold. The Rust workspace described in [cmis.md](cmis.md) and
[mia.md](mia.md) is the target structure; implementation crates have not yet
been split out of `src/`.
