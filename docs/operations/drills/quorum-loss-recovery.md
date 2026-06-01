# Drill: quorum-loss recovery

**Goal.** Prove the team can recognise quorum loss, ride out the graceful-
degradation window, and recover — either by restoring quorum (transient loss)
or by re-seeding the issuance key through the offline ceremony (permanent loss).

**Frequency.** Annually, paired with the root-key ceremony rehearsal.

**Roles.** Incident commander, two ceremony operators (for the re-seed path),
one verifier.

**Maps to.** `docs/operations.md` §"Disaster recovery" (loss of quorum) and
§"Root key rotation"; features F05 (Raft) and F06/F14 (threshold shares, root
ceremony).

---

## What "quorum loss" means here

- A 3-node Raft cluster has quorum at 2 nodes. Losing two of three (or a
  3-of-5 **share** quorum for the issuance key) stops new issuance.
- **Graceful degradation:** while issuance is halted, *existing* SVIDs remain
  valid until they expire. With a ≤1 h max TTL this is a degradation window of
  up to one hour before the first host cannot rotate — ample time to recover.
- Two recovery paths:
  - **Transient** (nodes return): survivors re-form quorum and rejoined nodes
    re-sync from `data_dir`. No key action.
  - **Permanent** (data/enclaves lost): the offline root-key ceremony
    provisions a new composite issuance key and re-splits Shamir shares 3-of-5;
    all hosts re-attest at next rotation.

---

## Pre-flight

1. Confirm cluster health and note each node's `node_id` / `data_dir`.
2. Confirm you can reach the ceremony material custodians (for the permanent
   path) and that the air-gapped `offline-signer` host is available.
3. Note the current max SVID TTL (the size of the degradation window).

## Procedure — transient loss

1. **Induce.** Stop two of the three replicas (quorum lost):
   ```sh
   ssh cmis-b 'sudo systemctl stop ferrogate-cmis'
   ssh cmis-c 'sudo systemctl stop ferrogate-cmis'
   ```
2. **Confirm graceful degradation.** New `Attest`/`Rotate` calls fail
   (no quorum); a host with a still-valid SVID continues to use it. Verify the
   surviving node reports `healthy=false` (it cannot commit) and the LB marks
   it not-ready.
3. **Recover.** Restart the stopped nodes with the **same** `node_id` /
   `data_dir`. Quorum re-forms; issuance resumes within one heartbeat.
4. **Verify** a fresh `Attest` succeeds and a write made after recovery is
   visible on all three nodes.

## Procedure — permanent loss (re-seed)

Run only if `data_dir`/enclave state is unrecoverable on a majority.

1. **Declare.** Incident commander records the permanent-loss decision.
2. **Convene the ceremony.** Follow
   [root-key-ceremony.md](../root-key-ceremony.md): the 3-of-5 operators
   reconstruct (or, if the old key is lost, generate) the composite root,
   re-split shares, and seal transport media.
3. **Re-provision replicas.** Stand up fresh CMIS nodes in attested TEEs;
   sealed-deliver the new shares (mutual peer attestation before share exchange,
   F06).
4. **Republish JWKS.** The new root is published; verifiers prefer the newer key
   ("newer preferred" ordering, F14).
5. **Fleet re-attest.** All hosts re-attest at next rotation and receive SVIDs
   under the new issuance key.

## Pass criteria

- During the outage: no *new* issuance, but existing SVIDs keep working
  (graceful degradation confirmed, not a hard outage).
- Transient path: quorum re-forms on restart; post-recovery write replicates to
  all nodes.
- Permanent path: ceremony produces verifiable artefacts (cross-sign verifies
  both directions; minutes signed by all participants); a sample host attests
  under the new key.

## Abort / rollback

Transient path has no destructive step — restarting the stopped nodes is the
recovery. For the permanent path, **do not destroy the old key shares** until
the new key is confirmed serving and the cross-sign window has been honoured
(see the ceremony doc's destruction read-back).

---

## Local rehearsal harness

```sh
scripts/drills/quorum-loss-recovery.sh
```

Drives `follower_rejoin_preserves_replicated_data` (the transient-recovery path,
real 3-node hiqlite) and the `offline-signer dry-run` (the re-seed path, full
eight-step rotation against a scratch directory).

## Drill log

| Date | Environment | Result | Evidence |
|------|-------------|--------|----------|
| 2026-06-01 | Local rehearsal harness (`scripts/drills/quorum-loss-recovery.sh`) | **PASS** | `follower_rejoin_preserves_replicated_data` + `offline-signer dry-run` (`dry_run_produces_all_verifiable_artefacts`) |

> Staging execution: append a row each year alongside the ceremony rehearsal,
> with the degradation-window timeline and the re-seed artefact verification.
