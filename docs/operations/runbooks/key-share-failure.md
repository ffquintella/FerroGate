# Runbook: key-share failure

**Alert.** One of:
- `ferrogate_key_share_reconstruct_failures_total` increments (a TEE replica
  could not reconstruct the issuance key from its shares), or
- `ferrogate_anchor_backlog_seconds > 300` (the transparency-anchor queue's
  oldest pending STH is older than 5 minutes).

**Severity.** Critical for reconstruction failure (issuance depends on the key);
High for anchor backlog (transparency lag, not issuance).

## What it means

The composite issuance key is split **3-of-5** (Shamir, `SHAMIR_THRESHOLD=3`,
`SHAMIR_SHARES=5`, `crates/ferro-tee/src/lib.rs`). A CMIS replica reconstructs
the key inside its TEE from at least 3 shares, each sealed to that replica's
enclave measurement. Every reconstruction records a `KeyShareUsed { share_idx,
mrenclave }` audit event.

Two distinct failure surfaces share this runbook because they share the
threshold-key machinery:

1. **Reconstruction failure** — fewer than 3 valid shares are available to a
   replica, or a share fails to unseal (wrong enclave measurement, tampered
   AAD, or a share sealed for a different replica). The replica cannot obtain
   the signing key and cannot issue.
2. **Anchor backlog** — co-signed STHs are queued for the Sigsum/Rekor anchor
   but not draining. `AnchorPublisher::drain_once` reports
   `backlog_seconds_after`; the documented alert threshold is **5 minutes**
   (`crates/ferro-audit/src/anchor.rs`). A `Transient` upstream failure stops
   the drain (so the publisher does not hammer a down log); a `Permanent`
   failure quarantines the entry under `dead/` and the drain continues.

## Impact

- **Reconstruction failure on a replica** → that replica cannot sign; if it is
  the leader, issuance stalls until another replica with a healthy key takes
  over or quorum reconstructs. If enough replicas fail, this becomes a
  quorum-loss event → see the quorum-loss-recovery drill.
- **Anchor backlog** → external transparency lags; the internal co-signed STHs
  and WORM store are unaffected, so tamper-evidence is preserved locally. No
  customer-facing issuance impact.

## Diagnose

### Reconstruction failure
1. **Which replica, which share?** The `KeyShareUsed` audit events and the
   replica logs name the `share_idx` (0..=4) and `mrenclave`. A failure to
   unseal points at one of:
   - wrong enclave measurement (the replica was re-deployed with a new
     `mrenclave` but old sealed shares) — `wrong_measurement_is_rejected`,
   - a share sealed for a different replica — `replica_cannot_unseal_anothers_share`,
   - tampered sealed blob / AAD.
2. **How many valid shares remain?** If ≥ 3 healthy replicas still hold valid
   shares, the cluster can still reconstruct; a single replica's failure is
   recoverable by re-sealing its share. If < 3, you are in quorum loss.

### Anchor backlog
1. **Is the upstream log reachable?** A `Transient` classification means the
   Sigsum/Rekor endpoint is down or rate-limiting. Check the anchor publisher
   logs for the failure class and the `pending/` queue depth
   (`pending/<tree_size>.{sth.json,enq}`).
2. **Anything in `dead/`?** Entries quarantined as `Permanent` need manual
   review — a permanent rejection usually means a malformed submission or a
   credential problem with the log account.

## Remediate

### Reconstruction failure
- **Stale enclave measurement after re-deploy** → re-run the
  "Adding a CMIS replica" flow (`docs/operations.md`): the replica presents a
  fresh attestation report to the quorum and is sealed-delivered a new share
  bound to its current `mrenclave`. Do **not** copy a share blob between
  replicas — sealing is per-enclave by design.
- **< 3 shares available (quorum lost)** → escalate to the quorum-loss recovery
  drill / root-key ceremony to re-seed shares.

### Anchor backlog
- **Transient upstream down** → the publisher resumes draining automatically
  when the log returns; confirm by watching `backlog_seconds` fall. No action
  beyond restoring upstream reachability.
- **`dead/` entries** → inspect the quarantined STH JSON, fix the root cause
  (log credentials / format), and re-enqueue per the anchor tooling. Never
  delete a dead entry without recording why — anchoring is a compliance trail.

## Escalate

- Reconstruction failure that drops the cluster below 3 healthy shares → page
  security **and** the incident commander; this is a potential issuance outage
  and possibly an enclave-integrity incident. Preserve the failing replica's
  logs and sealed-share state.
- Any sign of share theft or an unexpected `mrenclave` in `KeyShareUsed` → treat
  as a key-compromise incident; the response is a root-key rotation
  (`docs/operations/root-key-ceremony.md`), not just a re-seal.

## Verify recovery

- Reconstruction: the affected replica logs a successful `KeyShareUsed` and
  returns `healthy=true`; a fresh `Attest` against it issues an SVID.
- Anchor: `backlog_seconds` returns below 300 and `pending/` drains to near
  empty; spot-check that a recently-anchored STH is queryable in the upstream
  transparency log.
