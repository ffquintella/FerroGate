# F07 — Merkle-chained Immutable Audit Log

## Summary

Every protocol event (attestation start, fail, SVID issuance, revocation,
local grant, local denial, key-share use) is appended to a per-shard Merkle
tree. The tree's root is signed inside the TEE every second as a Signed Tree
Head (STH), replicated and co-signed by Raft peers, committed to a WORM
bucket, and anchored to a public transparency log once a minute.

## Scope

In:

- Append-only event API on CMIS and forwarded events from MIA.
- SHA3-384 leaf hashing; binary Merkle tree.
- STH structure `{ tree_size, root_hash, timestamp }` signed via F03.
- Backing store: S3 Object Lock (Compliance, 10-year retention) and
  FoundationDB mirror.
- Sigsum / Rekor anchor every minute.
- Inclusion and consistency proof endpoints.

Out:

- Real-time alerting (out of scope; consumes the audit stream externally).
- Encryption of the log (no PII in events; hashes only).

## Components touched

- `crates/ferro-audit`.
- `crates/cmis`.
- `crates/mia` (event forwarder).

## Dependencies

- F03 (signing), F05 (Raft co-sign).

## Design notes

See [../audit.md](../audit.md).

## Acceptance criteria

- [ ] Property test: random insertions, then `verify_inclusion` and
      `verify_consistency` hold for all pairs.
- [ ] STHs are co-signed by a Raft majority before publication.
- [ ] S3 Object Lock prevents deletion in an integration test.
- [ ] An anchor receipt appears in the configured Sigsum log within 90 s of
      STH publication.
- [ ] Replaying a deleted leaf is detectable from the public STHs alone.
- [ ] No event field contains PII; only hashes and counters.

## Risks

- **Anchor outage.** External transparency log may be unavailable.
  Mitigation: queue and back-fill anchors; alert if backlog > 5 min.
- **Storage cost.** WORM retention 10 years for high-volume fleets.
  Mitigation: log only protocol-level events; everything else is hashed.
