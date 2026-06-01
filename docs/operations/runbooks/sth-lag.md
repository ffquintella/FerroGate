# Runbook: STH publish lag

**Alert.** `ferrogate_sth_publish_lag_seconds > 300` (5 minutes since the last
Signed Tree Head was published).

**Severity.** High. The audit log is the system's tamper-evidence; if STHs stop
advancing, third parties can no longer confirm the log is append-only over the
gap, and co-signed STHs are not reaching the transparency anchor.

## What it means

The audit log produces a co-signed STH (`SthBody { tree_size, root_hash,
timestamp }`, signed composite Ed25519 + ML-DSA-65 under `ferrogate-sth-v1`,
co-signed by a Raft majority). The latest STH is served by the `LatestSth` RPC.
"Lag" is `now − sth.timestamp`. The documented threshold is **5 minutes**
(`crates/ferro-audit/src/anchor.rs`, "backlog ≥ 5 min, per docs/audit.md").

Lag means **one** of:

1. New events are being appended but no STH is being produced/co-signed.
2. The co-sign step cannot reach a Raft majority of signers.
3. Events have simply stopped (low traffic) — STHs may legitimately not advance
   if `tree_size` is unchanged; distinguish this from a stall.

## Impact

- New audit events may not yet be covered by a published STH (inclusion proofs
  for them will not verify until the next STH).
- The Sigsum/Rekor anchor backlog grows (see the key-share-failure runbook for
  the anchor side).
- Issuance itself is **not** blocked by STH lag — SVIDs still mint. This is an
  observability/compliance alert, not a customer-facing outage.

## Diagnose

1. **Is the tree actually growing?**
   ```sh
   grpcurl -d '{}' cmis-a:8443 ferrogate.MachineIdentity/LatestSth
   # Note tree_size and timestamp; compare against issuance volume.
   ```
   If `tree_size` is advancing but `timestamp` is not, STH production is stuck.
   If `tree_size` is flat and traffic is low, this is benign — confirm by
   checking issuance metrics, then snooze.
2. **Can a majority co-sign?** Check `Health` on all replicas; a co-signed STH
   needs `threshold` distinct signers. If a replica is unhealthy or partitioned,
   the quorum signer cannot assemble enough signatures.
3. **Is the WORM store writable?** STHs persist via `record_cosigned_sth`
   (`O_CREAT|O_EXCL` on `LocalDiskWormStore`). A full or read-only volume blocks
   the write. Check disk on the audit store path (`CMIS_AUDIT_ROOT`).

## Remediate

- **Co-sign quorum lost** → restore replica health (see the region-loss /
  quorum-loss drills). Once a majority is healthy, STH production resumes on the
  next tick.
- **WORM volume full/read-only** → expand or remount the audit volume; the next
  STH write succeeds. Never delete prior STH/leaf files — they are WORM by
  design and removal is itself an audit-integrity incident.
- **Producer stuck (tree growing, STH not)** → roll the affected CMIS replica;
  the STH producer re-derives the latest tree on restart.

## Escalate

If lag exceeds **15 minutes** or you find evidence of WORM deletion/tampering,
page the security on-call: a tamper-evidence gap is a security incident, not
just an availability one. Preserve the audit volume for forensics before any
remount.

## Verify recovery

```sh
grpcurl -d '{}' cmis-a:8443 ferrogate.MachineIdentity/LatestSth
# timestamp within the last minute; tree_size >= the value seen during the alert.
```
Then fetch an inclusion proof for an event appended during the gap and verify it
offline against the new STH.
