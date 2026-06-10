# Audit Log

## Goal

Make the protocol externally observable: any third party in possession of the
public Signed Tree Heads (STHs) must be able to detect any insertion,
deletion, or reordering of audit entries.

## Event types

```rust
enum AuditEvent {
    AttestStart  { ek_sha:  [u8;48], aik_sha: [u8;48], policy_id: String },
    AttestFail   { reason:  &'static str },
    SvidIssued   { cert_sha:[u8;48], spiffe_id: String },
    SvidRevoked  { cert_sha:[u8;48], reason:    String },
    HostRevoked  { spiffe_id: String, reason:   String },
    KeyShareUsed { share_idx: u8,    mrenclave: [u8;48] },
    LocalGrant   { pid: u32, uid: u32, bin_sha: [u8;48], jti: [u8;16] },
    LocalDenied  { pid: u32, uid: u32, bin_sha: [u8;48], reason: &'static str },
}
```

No personally identifiable information is recorded. EK certificates and
binary contents are referenced only by SHA-384 hash.

## Construction

Each CMIS replica maintains a per-shard Merkle tree of audit leaves where:

```
leaf_i = SHA3-384( CBOR(event_i) )
```

Every second, or every 1024 entries (whichever comes first), the replica:

1. Computes the current Merkle root.
2. Builds a `SignedTreeHead { tree_size, root_hash, timestamp }`.
3. Signs the STH with the composite issuance key inside the TEE.
4. Replicates the STH and leaves to Raft peers; a quorum must co-sign before
   publication.
5. Commits the leaves and STH to the local-disk WORM store (`LocalDiskWormStore`,
   write-once via `O_CREAT|O_EXCL`); the replicated copy is durably held in the
   hiqlite-backed Raft state machine shared with the rest of CMIS. (A native S3
   Object Lock store was originally planned but is dropped — see
   [roadmap.md](roadmap.md) §"Dropped scope". Deployments needing cloud
   durability sync the WORM directory to object storage out of band.)

Once per minute the latest STH is anchored to a public transparency log
(Sigsum or Rekor). The anchor receipt is recorded as a separate audit
artefact so that mutual divergence between the WORM store and the public
log is itself detectable.

On startup the in-memory tree is **resumed** from the WORM store: every
persisted leaf is replayed in index order, the rebuilt root is cross-checked
against the newest persisted STH, and the next append continues at the next
free index. (An empty tree over a non-empty store would try to re-write leaf
`0`, which the WORM invariant refuses — wedging the log permanently after any
restart.) A root mismatch on resume means the persisted log was tampered with
or corrupted; CMIS refuses to start rather than continue on a forked history.

## Inclusion proofs

Any reader can fetch:

- The current `SignedTreeHead`.
- An inclusion proof for a leaf by index or by `cert_sha`.
- A consistency proof between two STHs.

A verifier who has recorded an earlier STH can confirm append-only behaviour
by checking the consistency proof; any deletion or reordering breaks it.

## Tamper-resistance properties

| Property | How |
|----------|-----|
| Append-only | Local-disk WORM store writes each leaf/STH once via `O_CREAT|O_EXCL`; an existing file is never reopened for write |
| Cannot rewrite history | STH signed inside TEE with a key whose private half is not extractable |
| Cross-replica consistency | Raft quorum must co-sign each STH before publication |
| Public verifiability | STHs anchored to an external Merkle transparency log |
| Local audit reaches global log | MIA-side events are forwarded to CMIS and absorbed into the same tree |

## What is *not* audited

- Successful key reconstruction is not logged at leaf granularity, only as
  per-share usage events. The reconstructed key itself never leaves the
  enclave so there is nothing meaningful to log about its bytes.
- Helper API token *bodies* are not audited; only `jti`, caller identity, and
  audience are. This prevents the audit log from becoming a token-disclosure
  oracle.
