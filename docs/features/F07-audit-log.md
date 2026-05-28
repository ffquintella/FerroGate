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

- [x] Property test: random insertions, then `verify_inclusion` and
      `verify_consistency` hold for all pairs.
      (`crates/ferro-audit/src/log.rs::inclusion_and_consistency_hold_for_all_pairs`
      — 24 proptest cases, tree sizes 1..=12, every leaf and every
      `(old_size, new_size)` pair checked offline against the captured STH
      roots.)
- [ ] STHs are co-signed by a Raft majority before publication.
      *(Deferred to M4 — `docs/roadmap.md` §M4 / F07 continued.)*
- [ ] S3 Object Lock prevents deletion in an integration test.
      *(Deferred to M4. The M3 dev WORM uses `O_CREAT|O_EXCL` against a local
      filesystem; `crates/ferro-audit/src/store.rs::leaf_append_is_worm`
      proves a previously-written leaf cannot be re-appended.)*
- [ ] An anchor receipt appears in the configured Sigsum log within 90 s of
      STH publication. *(Deferred to M4.)*
- [x] Replaying a deleted leaf is detectable from the public STHs alone.
      (The consistency proof verifier ([`ferro_audit::verify_consistency`])
      is independent of the tree state: a third party in possession of an
      earlier STH can check the proof against a later STH offline; deletion
      or reordering breaks the algebraic check.
      `merkle::tests::consistency_proof_rejects_diverging_history` exercises
      this directly.)
- [x] No event field contains PII; only hashes and counters.
      (Enforced by the `AuditEvent` schema: every variant carries SHA-384
      hashes, stable opcode strings (never user input), small numeric
      identifiers, or SPIFFE IDs that are themselves derived from hashes.)

## Risks

- **Anchor outage.** External transparency log may be unavailable.
  Mitigation: queue and back-fill anchors; alert if backlog > 5 min.
- **Storage cost.** WORM retention 10 years for high-volume fleets.
  Mitigation: log only protocol-level events; everything else is hashed.
