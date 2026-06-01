# Drill: region loss

**Goal.** Prove that losing an entire region — up to one CMIS replica of a
three-replica cluster — causes **zero client-visible issuance errors**, and
that the region recovers cleanly when it comes back.

**Frequency.** Quarterly, and after any change to the Raft topology or the
anycast routing.

**Roles.** One drill lead (executes), one observer (watches dashboards and
records), one on-call SRE (ready to abort).

**Maps to.** `docs/operations.md` §"Disaster recovery" (loss of a single
region) and feature F05 (CMIS high availability).

---

## Pre-flight

1. Confirm the cluster is healthy on all three replicas:
   ```sh
   for n in cmis-a cmis-b cmis-c; do
     grpcurl -d '{}' "$n:8443" ferrogate.MachineIdentity/Health
   done
   # Expect healthy=true on all three; exactly one role=NODE_ROLE_LEADER.
   ```
2. Confirm a steady issuance baseline on the dashboard (issuance p50/p99,
   attestation success rate).
3. Announce the drill window; silence non-drill pages.

## Procedure

1. **Identify a non-leader region.** From the `Health` responses pick a replica
   whose `role` is `NODE_ROLE_FOLLOWER`. Killing a follower keeps quorum (2/3)
   and is the realistic single-region-loss case.
   > **Note on node-id-1.** hiqlite node-id-1 owns cluster bootstrap
   > (`crates/ferro-raft/src/cluster.rs`). A *graceful* shutdown of node 1
   > specifically does not let the remaining quorum re-elect cleanly in-process,
   > so for the leader-loss variant prefer an *abrupt* kill (below) and never
   > pick node 1 for the graceful-drain sub-step.
2. **Drain routing.** Withdraw the region's anycast advertisement (or set the
   LB to drain) so new connections stop landing there. `!healthy` /
   `NODE_ROLE_UNKNOWN` already maps to "not ready" at the LB.
3. **Kill the region.** Stop every CMIS process in the region:
   ```sh
   ssh cmis-c 'sudo systemctl stop ferrogate-cmis'   # abrupt: add `--signal=SIGKILL`
   ```
4. **Observe (5 min).** The remaining two replicas hold quorum. Watch:
   - issuance error rate stays at zero,
   - a leader is present at all times (`Health.role`),
   - Raft commit lag on the survivors stays bounded.
5. **Recover the region.** Restart CMIS on the killed nodes with the **same**
   `node_id` and `data_dir`:
   ```sh
   ssh cmis-c 'sudo systemctl start ferrogate-cmis'
   ```
   The node rejoins on its existing identity and re-syncs the log; no manual
   re-seed is needed.
6. **Re-advertise** the region's anycast route once `Health.healthy=true`.

## Pass criteria

- Zero issuance errors visible to clients for the whole window.
- A leader was present continuously (no issuance gap during re-election).
- The recovered region re-synced every write committed while it was down
  (spot-check a SPIFFE ID issued during the outage via `FetchSVID` on the
  recovered node).

## Abort / rollback

If issuance errors appear (quorum was thinner than believed), immediately
re-advertise the drained region and restart any stopped process. No data
action is required — Raft state is durable on `data_dir`.

---

## Local rehearsal harness

The same behaviours are exercised deterministically in-process before any
staging run:

```sh
scripts/drills/region-loss.sh
```

This drives `cargo test -p ferro-raft --test cluster_e2e`, which spins up a
real 3-node hiqlite cluster on free ports and asserts election, a non-leader
kill that keeps the cluster issuing, follower rejoin recovering replicated
data, and a randomized kill/revive chaos run while quorum holds.

## Drill log

| Date | Environment | Result | Evidence |
|------|-------------|--------|----------|
| 2026-06-01 | Local rehearsal harness (`scripts/drills/region-loss.sh`) | **PASS** | run below |

```
   Running tests/cluster_e2e.rs
running 5 tests
test ten_minute_chaos_run ... ignored, runs for 10 minutes; flip on in CI with `cargo test -- --ignored`
test three_node_cluster_elects_a_leader_and_replicates ... ok
test killing_a_non_leader_keeps_the_cluster_issuing ... ok
test follower_rejoin_preserves_replicated_data ... ok
test short_chaos_run_keeps_serving_while_quorum_holds ... ok
test result: ok. 4 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 104.27s
```

> Staging execution: append a new row each quarter with the dashboard
> screenshots and the `Health` transcripts from the procedure above. The
> long-form `ten_minute_chaos_run` (the `#[ignore]`-gated variant) is the
> CI/staging counterpart of the local rehearsal — run it with
> `cargo test -p ferro-raft --test cluster_e2e -- --ignored` on the drill host.
