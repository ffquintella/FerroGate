- [Overview](README.md)

- Core design
  - [Architecture](architecture.md)
  - [Networking & ports](networking.md)
  - [Transport security (TLS)](transport-tls.md)
  - [Threat model](threat-model.md)
  - [Attestation protocol](protocol.md)
  - [Cryptography](crypto.md)
  - [TPM 2.0 engine](tpm.md)

- Components
  - [CMIS server](cmis.md)
  - [MIA agent](mia.md)
  - [Helper API](helper-api.md)
  - [Allowlist provisioning](allowlist-provisioning.md)
  - [Audit log](audit.md)

- Operations
  - [Operations guide](operations.md)
  - [Root key ceremony](operations/root-key-ceremony.md)
  - Runbooks
    - [Overview](operations/runbooks/README.md)
    - [CRL stale](operations/runbooks/crl-stale.md)
    - [Key share failure](operations/runbooks/key-share-failure.md)
    - [STH lag](operations/runbooks/sth-lag.md)
  - Drills
    - [Mass revocation](operations/drills/mass-revocation.md)
    - [Quorum loss recovery](operations/drills/quorum-loss-recovery.md)
    - [Region loss](operations/drills/region-loss.md)

- Features
  - [Feature index](features/README.md)
  - [F01 — Hybrid PQC TLS](features/F01-hybrid-pqc-tls.md)
  - [F02 — TPM attestation](features/F02-tpm-attestation.md)
  - [F03 — Composite signatures](features/F03-composite-signatures.md)
  - [F04 — SVID lifecycle](features/F04-svid-lifecycle.md)
  - [F05 — CMIS high availability](features/F05-cmis-ha.md)
  - [F06 — TEE threshold keys](features/F06-tee-threshold-keys.md)
  - [F07 — Audit log](features/F07-audit-log.md)
  - [F08 — Helper API](features/F08-helper-api.md)
  - [F09 — DPoP child tokens](features/F09-dpop-child-tokens.md)
  - [F10 — RIM & PCR policy](features/F10-rim-pcr-policy.md)
  - [F11 — Revocation](features/F11-revocation.md)
  - [F12 — MIA hardening](features/F12-mia-hardening.md)
  - [F13 — Bootstrap & enrollment](features/F13-bootstrap-enrollment.md)
  - [F14 — Root key ceremony](features/F14-root-key-ceremony.md)

- Decisions
  - [ADR index](adr/README.md)
  - [ADR-0001 — gRPC over HTTP](adr/0001-grpc-over-http-transport.md)

- Process
  - [Testing](testing.md)
  - [Roadmap](roadmap.md)
