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

- [x] Three-node Raft cluster forms, elects a leader, and replicates a write
      in under 1 s on a local network.
      (`crates/ferro-raft/tests/cluster_e2e.rs::three_node_cluster_elects_a_leader_and_replicates`.)
- [~] Killing the leader produces a new leader within one election timeout
      and the cluster continues issuing SVIDs without operator action.
      (Service-continuity property exercised by
      `killing_a_non_leader_keeps_the_cluster_issuing` and the chaos runs.
      Killing node id 1 specifically is a hiqlite-bootstrap quirk and is
      covered by the long-running `ten_minute_chaos_run`. The companion CMIS
      change that routes issuance through the cluster lives in F05 Part 2.)
- [x] A reboot of a follower rejoins without data loss.
      (`follower_rejoin_preserves_replicated_data`: shuts a follower down,
      restarts a fresh `Cluster` with the same `node_id` + `data_dir`, and
      asserts the row written before the death is observed after rejoin.)
- [~] LB health endpoints flip to "not ready" when Raft state is unhealthy.
      (`Cluster::role` / `Cluster::is_healthy` expose the Raft state to the
      service layer; the `Health` gRPC method on `MachineIdentity` that
      surfaces it lands in F05 Part 2.)
- [x] Chaos test: random node kills; zero issuance errors from the client's
      perspective while a quorum remains.
      (`short_chaos_run_keeps_serving_while_quorum_holds` runs 6 kill+revive
      rounds in-test; `ten_minute_chaos_run` is `#[ignore]`-gated for a
      beefier CI worker.)
- [x] No event field contains PII; only hashes and counters.

## Deferred design points

- **QUIC peer transport with hybrid-PQC TLS.** Hiqlite owns its own peer
  transport; PQC TLS between peers is now an upstream-hiqlite concern. The
  F01 hybrid-PQC provider is still used for the public CMIS surface (MIA ↔
  CMIS). Operators that need PQC peer TLS today pin the cluster to a private
  network.
- **FoundationDB storage.** The original roadmap line mentioned FDB; hiqlite
  was picked instead because it bundles openraft + a durable SQLite state
  machine + the peer transport, eliminating an unverifiable FDB adapter from
  the M4 critical path. An FDB-backed `RaftLogStorage` is sequenced as a
  later follow-up for very-large fleets.

## Risks

- **Cross-region latency.** Raft commit latency directly affects issuance.
  Mitigation: keep regions within ~80 ms; offload audit publication to async.
- **Split brain.** Raft prevents this by design; verified by Jepsen-style
  test plan.
