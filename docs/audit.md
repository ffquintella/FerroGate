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
    ConfigChanged { path: String, by_uid: u32, keys: Vec<String> },
}
```

`ConfigChanged` (feature F18) is written by `mia setup --apply` when it
rewrites a MIA configuration file non-interactively. It carries the file path,
the invoking user id and the dotted *names* of the changed keys — never their
values. Today it is appended to a local, append-only JSON-lines journal beside
the configuration file (`config-audit.jsonl`), which the daemon does not read:
forwarding that journal to CMIS through `AppendAuditEvent` is a follow-up
(T226). The daemon's own events are forwarded, see below.

**Forwarding from hosts.** The MIA daemon appends its own events
(`LocalGrant`, `LocalDenied`, `AllowlistSyncApplied`, `AllowlistSyncRejected`)
through `AppendAuditEvent`. CMIS also accepts `ConfigChanged` from a host,
but MIA does not send it yet (T226). Since 0.29.0 every forward is
host-authenticated (F19 §7.1 `HostCallAuth`): the host presents its
SVID and signs, with the machine key the SVID binds, a fresh single-use
document `{v, host_uuid, issued_at, nonce, event_sha384}` under the context
`ferrogate-audit-forward-v1`. CMIS refuses unsigned, stale (more than 300 s
off), replayed or tampered forwards, forwards from revoked hosts, and every
event type a host does not produce, and rate-limits each host
(`CMIS_AUDIT_FORWARD_MAX_PER_MIN`). The leaf is the event bytes exactly as
forwarded. See [operations.md](operations.md#audit-forwarding-from-hosts).

**The MIA forwarder (T291).** The daemon logs every event it emits on the
`mia::audit` tracing target, whether or not it can forward it: that local
trail never reaches the status endpoint. With CMIS configured it also
appends the event to a spool and forwards the spool to CMIS:

- **Spool.** `audit-spool.jsonl` (`audit-spool-<env>.jsonl` for a named
  environment) in the daemon's state directory (`/var/lib/ferrogate` on
  Linux, the system configuration directory elsewhere), mode `0600`. One JSON
  line per event holds the event's canonical CBOR (base64), a sequence number
  and the time it was spooled; `{"v":1,"done":N}` lines mark events up to `N`
  as finished. No SVID, signature or proof is stored: every attempt is signed
  afresh, with a new nonce. Each append is flushed to disk; once finished
  records outweigh pending ones the file is rewritten (temporary file,
  `fsync`, rename).
- **Order and retries.** One call at a time, oldest event first. When CMIS is
  unreachable, times out or gives any other error, the event is kept and
  retried with exponential backoff: 1 s doubling to 5 min, each delay
  randomised between half and all of its value. `RESOURCE_EXHAUSTED
  rate_limited` waits the `retry-after` seconds. A refused host proof keeps
  the event: `UNAUTHENTICATED`, any `PERMISSION_DENIED` other than
  `event_not_forwardable` (revoked SVID, host clock more than 300 s off,
  `host_mismatch`) and any `INVALID_ARGUMENT` other than the two below (such
  as `malformed_doc`, a proof document this CMIS cannot decode). It is retried
  on the same backoff, and at once when new credentials appear.
- **SVID expiry.** Forwarding needs an unexpired host SVID, and the daemon
  does not renew it while running: the background re-attestation only runs
  when attestation failed at start, and stops at its first success. Once the
  SVID expires, forwarding holds (one warning, `host SVID expired`) until
  the daemon re-attests, which today means a restart; events keep
  being spooled, and beyond the cap the oldest are dropped.
- **What is dropped.** Only CMIS's answers about the event itself drop it,
  with a warning, so one bad event cannot block the queue:
  `INVALID_ARGUMENT field_too_long` or `malformed audit event`, and
  `PERMISSION_DENIED event_not_forwardable`. An event over 64 KiB of CBOR is
  never spooled. Once the spool holds 10 000 events or 8 MiB, the oldest are
  dropped, with a warning that gives the counts. Dropped events stay in the
  local log.
- **Restarts.** The spool is replayed before new events. A torn last line
  (a crash mid-append) or a line that does not parse is skipped, never
  fatal, and the file is rewritten clean. A file that cannot be read to its
  end (an I/O error; on Windows, a file that is not administrator-only) is
  never rewritten: it is renamed, unchanged, to
  `<name>.unreadable-<unix time>` beside it (`0600`, not replayed, logged
  at error with both paths) and a fresh spool starts. Until that rename
  succeeds, new events are held in memory. Delivery is at least once: an event
  acknowledged just before a crash can be sent again.
- **Shutdown.** An event the forwarder has received but not yet appended
  when the daemon stops is not spooled; it is already in the local log.
  An event still queued in the channel at that instant is in neither (the
  forwarder keeps the channel drained, so this is rare).
- **No CMIS.** When CMIS is not configured (or misconfigured), events are
  only logged: no spool is created or grown, and one left by an earlier run
  is kept. An
  attested SVID that binds no host-call key (the TPM tier today) cannot sign
  forwards, so such a host also only logs.
- **Back-pressure.** The helper API hands events over through a 256-slot
  channel, which the forwarder drains at memory speed: disk writes and CMIS
  calls run elsewhere, so issuing a token never waits on CMIS. The helper
  waits only once a whole spool's worth of events is staged behind a stalled
  disk. It never drops an event to keep going.

**Application approvals (F19 §9).** CMIS records `AppRequestSubmitted`,
`AppRequestAutoApproved`, `AppRequestApproved`, `AppRequestDenied`,
`AppRequestExpired`, `ApprovalUpdated`, `ApprovalRevoked`, `ApprovalExpired`,
`LineageAutoUpdateFrozen`, `AppApprovedBySameActor` (requester and approver
were one administrator: every single-step direct registration),
`AdminDirectRegistration` (strict SoD: queued) and `AllowlistCompiled`.
Requests, approvals and lineages appear as UUID bytes, binaries as SHA-384,
paths only as the host-salted `path_hash`; user names, SIDs, paths and
free-text messages never. Hosts may forward `AllowlistSyncApplied` /
`AllowlistSyncRejected`, and only for themselves (`host_mismatch` otherwise).

**Allowlist migration (F19 §11).** `AllowlistImported {host_uuid,
approvals_created, admin_id}` is written once per host whose legacy body
gained `legacy_import` approvals, after the batch committed; a dry run or a
re-run that creates nothing writes none. `AllowlistModeChanged {old_mode,
new_mode, admin_id, session_ref, approvals_not_reflected, imports_readmitted,
entries_not_imported}` records each switch of the replicated mode with what
it changed (counts only); a dry run or a switch to the mode already in force
writes none. Both calls are still recorded as `AdminCallAuthorized` by the
admin layer, so every attempt — dry runs included — is traceable. Neither
event carries a uid, a hash list or a path. An import also revokes the
imports whose entry left the legacy body, each recorded as an ordinary
`ApprovalRevoked` with reason code 1000 and the importer's `admin_id`. A
failed write audits nothing.
Review `AllowlistModeChanged` with `new_mode = legacy` (a rollback re-admits
revoked legacy imports) and `entries_not_imported > 0` in the SIEM.

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
| Local audit reaches global log | The MIA daemon spools its events (`0600`, bounded) and forwards them in order to CMIS, which absorbs them into the same tree; `ConfigChanged` from `mia setup` stays in its local journal for now (T226) |

## What is *not* audited

- Successful key reconstruction is not logged at leaf granularity, only as
  per-share usage events. The reconstructed key itself never leaves the
  enclave so there is nothing meaningful to log about its bytes.
- Helper API token *bodies* are not audited; only `jti`, caller identity, and
  audience are. This prevents the audit log from becoming a token-disclosure
  oracle.
