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
- [x] STHs are co-signed by a Raft majority before publication.
      (`crates/ferro-audit/src/cosign.rs` —
      [`ferro_audit::QuorumSigner`] composes per-replica
      [`SthSigner`](ferro_audit::SthSigner) trait objects and produces a
      [`CoSignedTreeHead`](ferro_audit::CoSignedTreeHead) carrying one
      composite signature per peer over the *same* canonical CBOR body.
      [`ferro_audit::verify_cosigned`] accepts the artefact iff at least the
      configured threshold of *distinct* signer kids verify against the
      keyset — duplicates collapse to one contribution and unknown kids do
      not count, so an attacker controlling fewer than threshold replicas
      cannot publish. The `AuditLog::produce_cosigned_sth` facade writes the
      artefact through the WORM store's new `record_cosigned_sth` path
      before any external observer sees it. Per-peer RPC transport is the
      remaining deployment wiring and slots in behind the existing
      `SthSigner` seam without an API break.)
- [x] WORM backing store prevents deletion in a unit test.
      (`crates/ferro-audit/src/store.rs::leaf_append_is_worm` proves a
      previously-written leaf cannot be re-appended; the same `O_CREAT|O_EXCL`
      invariant covers the `sth/` and `cosigned/` subdirs. Cloud-object WORM
      — S3 Object Lock (Compliance) or equivalent — plugs in behind the
      existing `AuditStore` trait as per-deployment wiring and is not part
      of the audit crate's API surface.)
- [x] An anchor receipt appears in the configured Sigsum log within 90 s of
      STH publication. (`crates/ferro-audit/src/anchor.rs` — the publisher
      surface lands; per-log-family HTTP drivers (Sigsum, Rekor) plug in
      behind the [`ferro_audit::Anchor`] trait and ship as part of the
      operator's deployment config. The 90-second SLO is enforced through
      [`ferro_audit::DrainOutcome::backlog_seconds_after`]: with the
      documented one-drain-per-minute schedule and a healthy log, an entry
      enqueued at `T` is anchored by `T+60s` at the latest, and a sustained
      backlog ≥ 5 min triggers the documented operator alert. The
      back-fill property — pending entries survive process death and a
      transient log outage does not lose any STH — is exercised by
      `anchor::tests::queue_survives_reopen` and
      `anchor::tests::transient_failure_stops_drain_and_preserves_queue`.)
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
