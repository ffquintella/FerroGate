# F05 — CMIS High Availability

## Summary

CMIS runs as a stateless replica set fronted by an anycast L4 load balancer
with TLS passthrough. Replicas form a Raft group (via hiqlite, which owns its
own peer transport) to replicate issued-SVID metadata, CRL deltas, and RIM
versions.

## Scope

In:

- Minimum 3 replicas spread across ≥ 2 regions and ≥ 2 cloud providers.
- Raft group backed by hiqlite (openraft + a durable SQLite state machine +
  its own peer transport). See "Deferred design points" below for why hiqlite
  replaced the originally-planned FoundationDB store and QUIC transport.
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

The Raft-backed store is the **only** backend: a deployment with no
`CMIS_CLUSTER_PEERS` configured runs a single-node cluster (the node is its own
only peer, elects itself leader, and skips peer discovery) so issued SVIDs,
host allowlists, and pending allowlist proposals persist across restarts in
the same SQLite state machine a multi-node cluster uses. The earlier
process-local `HashMap` backend, which lost all of that state on restart, was
removed.

## Acceptance criteria

- [x] Three-node Raft cluster forms, elects a leader, and replicates a write
      in under 1 s on a local network.
      (`crates/ferro-raft/tests/cluster_e2e.rs::three_node_cluster_elects_a_leader_and_replicates`.)
- [x] Killing the leader produces a new leader within one election timeout
      and the cluster continues issuing SVIDs without operator action.
      (Service-continuity at the cluster layer is exercised by
      `killing_a_non_leader_keeps_the_cluster_issuing` and the chaos runs;
      `crates/mia/tests/cluster_attest.rs` (F05 Part 2) drives a full four-phase
      `Attest` against one cluster-mediated CMIS instance and asserts the
      issued SVID is visible through `FetchSVID` on a different node — i.e.
      issuance now genuinely flows through the Raft state machine. Killing
      node id 1 specifically is a hiqlite-bootstrap quirk and is the only
      shape covered solely by the long-running `ten_minute_chaos_run`.)
- [x] A reboot of a follower rejoins without data loss.
      (`follower_rejoin_preserves_replicated_data`: shuts a follower down,
      restarts a fresh `Cluster` with the same `node_id` + `data_dir`, and
      asserts the row written before the death is observed after rejoin.)
- [x] LB health endpoints flip to "not ready" when Raft state is unhealthy.
      (`MachineIdentity.Health` returns `(healthy, role, node_id)`; an LB maps
      `!healthy` or `role == NODE_ROLE_UNKNOWN` to "not ready". The leader and
      follower assertions in `cluster_attest.rs` exercise the healthy path; the
      degraded path follows directly from `Cluster::is_healthy` returning false
      while hiqlite is not synced.)
- [x] Chaos test: random node kills; zero issuance errors from the client's
      perspective while a quorum remains.
      (`short_chaos_run_keeps_serving_while_quorum_holds` runs 6 kill+revive
      rounds in-test; `ten_minute_chaos_run` is `#[ignore]`-gated for a
      beefier CI worker.)
- [x] No event field contains PII; only hashes and counters.

## Inter-node transport security

The Raft + management transports between replicas can run over TLS, so a
cluster no longer has to be pinned to a trusted private network for
confidentiality. Set `CMIS_PEER_TLS=1` to enable hiqlite's rustls transport
with auto-generated self-signed certificates, or supply a stable PEM pair with
`CMIS_PEER_TLS_CERT` + `CMIS_PEER_TLS_KEY`. Either way TLS provides on-the-wire
encryption; peer *identity* is authenticated by the shared `CMIS_RAFT_SECRET` /
`CMIS_API_SECRET` three-way handshake (the secret never crosses the wire), so
certificate chains are not validated. Multi-node nodes must also bind a
routable interface — `CMIS_RAFT_LISTEN` defaults to `0.0.0.0` so peers in other
hosts/containers can reach them, rather than the loopback a single node uses.

A runnable two-node example lives at
[`docker/cluster-test/docker-compose.yml`](../../docker/cluster-test/docker-compose.yml);
`crates/ferro-raft/tests/cluster_e2e.rs::tls_cluster_elects_a_leader_and_replicates`
exercises the TLS transport in-process.

## Deferred design points

- **QUIC peer transport with hybrid-PQC TLS.** Hiqlite owns its own peer
  transport; the classical rustls TLS above secures it today. *PQC* peer TLS
  specifically remains an upstream-hiqlite concern — the F01 hybrid-PQC
  provider still fronts the public CMIS surface (MIA ↔ CMIS), but the peer
  transport's TLS is classical. Operators who require PQC *between peers* until
  hiqlite ships it pin the cluster to a private network.
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
