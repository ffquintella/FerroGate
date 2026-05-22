# FerroGate

High-availability, post-quantum secure, TPM 2.0-attested machine identity
system built on the SPIFFE framework.

FerroGate issues short-lived, hardware-rooted SVIDs to host nodes after a
four-phase attestation protocol, and serves sender-constrained tokens to
local applications over a hardened helper API. It is split into:

- **CMIS** — Central Machine Identity Service. Stateless gRPC server running
  inside a TEE (AMD SEV-SNP or Intel TDX). Validates TPM evidence and issues
  composite Ed25519 + ML-DSA-65 SVIDs.
- **MIA** — Machine Identity Agent. Tamper-resistant host daemon that owns
  the TPM, authenticates to CMIS over hybrid-PQC TLS, and exposes a local
  helper socket to applications.

## Documentation

The full system design lives under [`docs/`](docs/README.md):

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Attestation protocol](docs/protocol.md)
- [Cryptographic design](docs/crypto.md)
- [TPM 2.0 engine](docs/tpm.md)
- [CMIS — server](docs/cmis.md)
- [MIA — agent](docs/mia.md)
- [Local helper API](docs/helper-api.md)
- [Audit log](docs/audit.md)
- [Operations](docs/operations.md)
- [Testing and verification](docs/testing.md)
- [Features](docs/features/README.md)
- [Roadmap](docs/roadmap.md)

## Status

The repository currently contains the design documentation and an ironroot
CLI scaffold. The Rust workspace layout described in [docs/cmis.md](docs/cmis.md)
is the target structure; implementation crates have not yet been split out
of `src/`.

## Quickstart (scaffold)

```bash
make build
make test
make run
```

See [AGENTS.md](AGENTS.md) for AI-assistant guidance.
