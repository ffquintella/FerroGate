# Features

Each document in this directory describes a single, independently-deliverable
feature of FerroGate. Features are scoped so that they can be implemented and
reviewed in isolation, even though some have ordering dependencies.

| ID  | Feature | Component(s) | Status |
|-----|---------|--------------|--------|
| F01 | [Hybrid PQC TLS transport](F01-hybrid-pqc-tls.md) | CMIS, MIA | Done |
| F02 | [TPM 2.0 attestation engine](F02-tpm-attestation.md) | MIA, CMIS | Done |
| F03 | [Composite Ed25519 + ML-DSA-65 signatures](F03-composite-signatures.md) | CMIS, MIA | Done |
| F04 | [SVID issuance and lifecycle](F04-svid-lifecycle.md) | CMIS, MIA | Done |
| F05 | [CMIS high availability](F05-cmis-ha.md) | CMIS | Not started |
| F06 | [TEE residency and threshold key shares](F06-tee-threshold-keys.md) | CMIS | Not started |
| F07 | [Merkle-chained immutable audit log](F07-audit-log.md) | CMIS, MIA | M3 subset done |
| F08 | [Local helper API](F08-helper-api.md) | MIA | Not started |
| F09 | [DPoP-bound child tokens](F09-dpop-child-tokens.md) | MIA | Not started |
| F10 | [RIM and PCR policy management](F10-rim-pcr-policy.md) | CMIS | M2 subset done |
| F11 | [Revocation and CRL distribution](F11-revocation.md) | CMIS, MIA | Not started |
| F12 | [MIA process hardening](F12-mia-hardening.md) | MIA | Not started |
| F13 | [Zero-touch bootstrap and fleet enrollment](F13-bootstrap-enrollment.md) | CMIS, MIA | Not started |
| F14 | [Root key ceremony and rotation](F14-root-key-ceremony.md) | CMIS, offline | Not started |

For the planned ordering and progress tracking see
[../roadmap.md](../roadmap.md).

## Document template

Every feature doc uses the same sections:

- **Summary** — one paragraph on what the feature is and why it exists.
- **Scope** — what is in and explicitly what is out.
- **Components touched** — which crates and external systems.
- **Dependencies** — other features that must land first.
- **Design notes** — links into [`docs/`](..) for the deep design.
- **Acceptance criteria** — concrete, testable bullets.
- **Risks** — what could go wrong, with mitigation.
