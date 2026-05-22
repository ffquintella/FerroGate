# F05 — CMIS High Availability

## Summary

CMIS runs as a stateless replica set fronted by an anycast L4 load balancer
with TLS passthrough. Replicas form a Raft group over QUIC (with hybrid-PQC
TLS between peers) to replicate issued-SVID metadata, CRL deltas, and RIM
versions.

## Scope

In:

- Minimum 3 replicas spread across ≥ 2 regions and ≥ 2 cloud providers.
- Raft group with FoundationDB-backed storage and a QUIC transport.
- TLS-passthrough LB; clients pin SPKI end-to-end.
- Failure tolerance: `f = ⌊(n-1)/2⌋` for issuance, `f = ⌊(n-1)/3⌋` for key
  reconstruction (see F06).
- Health endpoints (`/healthz`, `/readyz`) gated on Raft state.
- Graceful node drain and re-join.

Out:

- Multi-tenant isolation (one fleet per cluster).
- Active-active across continents at >100 ms latency (Raft would suffer).

## Components touched

- `crates/cmis` — Raft glue, LB-friendly liveness.
- Deployment manifests (cloud-specific, not in repo).

## Dependencies

- F01, F03, F04. F06 layered on top.

## Design notes

See [../architecture.md](../architecture.md) §"High availability" and
[../operations.md](../operations.md) §"Adding a CMIS replica".

## Acceptance criteria

- [ ] Three-node Raft cluster forms, elects a leader, and replicates a write
      in under 1 s on a local network.
- [ ] Killing the leader produces a new leader within one election timeout
      and the cluster continues issuing SVIDs without operator action.
- [ ] A reboot of a follower rejoins without data loss.
- [ ] LB health endpoints flip to "not ready" when Raft state is unhealthy.
- [ ] Chaos test: random node kills over 10 minutes; zero issuance errors
      from the client's perspective while a quorum remains.

## Risks

- **Cross-region latency.** Raft commit latency directly affects issuance.
  Mitigation: keep regions within ~80 ms; offload audit publication to async.
- **Split brain.** Raft prevents this by design; verified by Jepsen-style
  test plan.
