# Architecture Decision Records

This directory records significant architectural decisions for FerroGate using
lightweight ADRs (Architecture Decision Records). Each ADR captures the context,
the decision, and its consequences so that future readers understand *why* a
choice was made — not just *what* the code does.

ADRs are immutable once **Accepted**. To revise a decision, add a new ADR that
**Supersedes** the old one and update the old one's status with a back-link.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-grpc-over-http-transport.md) | gRPC over HTTP/REST for the control plane | Accepted |

## Status values

- **Proposed** — under discussion, not yet binding.
- **Accepted** — the decision is in force.
- **Superseded by ADR-NNNN** — replaced by a later decision.
- **Deprecated** — no longer relevant, not replaced.
