# ADR-0004 — Application approval ledger and the non-replacement invariant

- **Status:** Proposed
- **Date:** 2026-10-14
- **Deciders:** FerroGate core team and the product owner (single-step direct add,
  decision D4 in the [Decisions log](../app-approval-and-admin.md#decisions-log)).
  Pending ESI review of the security premises, see
  [app-approval-and-admin.md](../app-approval-and-admin.md#security-premises), and
  ESI acknowledgement of the accepted risk in §6.
- **Scope:** How CMIS records application registration requests and approvals,
  how they compile into the signed caller allowlist a MIA verifies, and the rule
  that a new request never replaces an existing approval. Detailed design is in
  [F19](../features/F19-app-registration-approval.md).
- **Relation to earlier ADRs:**
  - **Supersedes, on acceptance, [ADR-0003](0003-host-allowlist-request-status.md)**
    (host-side `request-allowlist` / unauthenticated `GetProposalStatus`). ADR-0003
    is still *Proposed* and its commands are not implemented. Its status line is
    left unchanged in this change and should be updated to "Superseded by
    ADR-0004" when this ADR is accepted.
  - **Amends [ADR-0002](0002-allowlist-optional-uid.md)** without changing it: the
    v1 entry model `(uid?, bin_sha)` and its signing context stay byte-identical.
    The new constraints exist only in a new **v2** document format.

## Context

Today a host's allowlist is one opaque, full-set artefact:

| Today (code) | Consequence |
|--------------|-------------|
| `host_allowlists(host_uuid PK, payload)` holds one signed CBOR blob per host (`crates/ferro-raft/src/cluster.rs`) | No record of *why* an entry exists, who approved it or until when it is valid |
| `pending_allowlist_proposals(host_uuid PK, …)` holds **one** proposal per host; `put_proposal` upserts it (`crates/cmis/src/state.rs`) | A second proposal **overwrites** the first (last write wins, which ADR-0003 acknowledges) |
| A proposal is a **full set** that replaces the host's allowlist when adopted (`propose_allowlist`, `ferrogate allowlist approve` → `SetAllowlist`) | Approving one app's request can silently drop another app's entry |
| `reject` deletes the proposal and leaves no tombstone (ADR-0003, "Limitations") | A denial cannot be shown to the requester or audited per app |
| `AllowlistDoc` carries `{trust_domain, issued_at, not_after, entries}` and nothing else (`crates/ferro-svid/src/allowlist.rs`) | A body is not bound to a host and has no generation, so another host's body, or an older body of the same host that is still valid, verifies |
| The MIA fetches the body only at start (`allowlist.fetch`) or on `mia resync-allowlist` | Approvals arrive only after a manual action or a restart |

The new product requirements (see [F19](../features/F19-app-registration-approval.md#summary))
are incompatible with that model:

1. An app is registered per **binary** (path, hash, version) and **OS user**, and an
   administrator approves or denies *that request*.
2. At approval time the administrator chooses an **update policy**: manual approval
   for every new binary, or automatic approval of updates that keep the same path and
   the same user.
3. The MIA picks up new authorizations by itself, polling every 5 minutes.
4. **New requests never replace old approvals.** Approvals end only by expiry or by
   an administrator removing them.

## Decision

### 1. Requests and approvals are separate, first-class records

- An **application request** is an immutable record of "host H asks that binary
  (path P, hash S) be usable by user U". Only its decision columns change, and only
  once, from `PENDING` to a terminal state.
- An **approval** is a record of "binary S at path P may be used by user U (or any
  user) on host H, under update policy X, until time T". It is created by an
  administrator, by the auto-update policy of an earlier approval, or by the legacy
  import. It is never created, changed or removed by a host.
- A **lineage** groups everything seen at one `(host, canonical path)`. Each distinct
  hash in a lineage gets a **revision** number (1, 2, 3, …) allocated once and never
  reused. The revision is the sequential version shown when the binary declares no
  version of its own.

### 2. The non-replacement invariant

Let `A_H(t)` be the set of `ACTIVE` approvals of host `H` at time `t`.

> **INV-1.** No host-originated operation (`SubmitAppRequest`, `ProposeAllowlist`,
> `SyncAllowlist`, `GetAppRequestStatus`, legacy `GetAllowlist`) removes an element
> of `A_H` or changes any of its attributes. The only change such an operation can
> make to `A_H` is to **add** a new approval through an auto-update policy that an
> administrator set earlier.
>
> **INV-2.** An element leaves `A_H` only when its `expires_at` passes, or through
> an authenticated administrator call that names that approval by id
> (`RevokeApproval`, or `UpdateApproval` that moves the expiry). Approving request R
> creates or reuses exactly one approval. It never alters any other approval unless
> the administrator lists those approval ids in the same call. Each listed id is
> then its own audited revocation.
>
> **INV-3.** Request records are append-only. Deduplication returns an existing
> record and never overwrites one. A denied or expired request stays visible with
> its decision.

INV-1 to INV-3 are enforced in CMIS code (the only writer). They are covered by a
property test that drives random interleavings of host and admin operations and
asserts that the active set changes only through INV-2 paths (F19, "Testing").

Superseded binaries stay `ACTIVE` when a newer revision of the same lineage is
approved. The older approval is only **marked** `superseded_by` for display.
Retiring it is an explicit administrator act (Open Question F19-OQ3 discusses an
opt-in grace-period policy).

### 3. The signed allowlist is a compiled view

For each host, CMIS compiles the signed allowlist deterministically from
`A_H(now)`. Every write that changes `A_H` bumps the host's **generation** in the
same Raft transaction. The generation is hybrid-logical:
`gen' = max(gen + 1, unix_millis_now)`, so it keeps increasing across a database
restore from backup.

### 4. A new allowlist format, v2, with its own signing context

```rust
/// Signed with context `ferrogate-allowlist-v2`; `deny_unknown_fields`.
pub struct AllowlistDocV2 {
    pub format: u32,            // = 2
    pub trust_domain: String,
    pub host_uuid: String,      // MIA rejects a body for another host
    pub generation: u64,        // MIA rejects generation < last accepted
    pub issued_at: i64,
    pub not_after: i64,
    pub entries: Vec<AllowEntryV2>,
}
/// `deny_unknown_fields`: a constraint an old verifier does not understand must
/// make it fail closed, never be ignored.
pub struct AllowEntryV2 {
    pub approval_id: [u8; 16],           // UUID bytes — audit correlation
    pub bin_sha: String,                 // hex SHA-384; "*" only for legacy imports
    pub uid: Option<u32>,                // Unix exact-user approvals
    pub user_sid_hash: Option<[u8; 32]>, // Windows exact-user approvals (full SID, not RID)
    pub path_hash: Option<[u8; 32]>,     // exact-path approvals
    pub expires_at: Option<i64>,         // enforced locally, even offline
}
```

- A **distinct signing context** makes an old (v1-only) MIA reject a v2 body with
  `bad signature`, so it fails closed. It never mis-parses a v2 body as v1 and drops
  the path or expiry constraints.
- **No personal data in the signed artefact.** Paths and Windows SIDs appear only
  as domain-separated SHA-256 hashes salted with the host UUID. The cached body
  (`allowlist.path`) and diagnostics bundles therefore carry no home-directory
  paths or account names.
- **v1 is unchanged.** For old MIAs, CMIS keeps serving v1 through the legacy
  `GetAllowlist`, compiled "lossy-safe": an approval that needs a v2 constraint is
  **omitted** (fail closed for that app on old agents), and the document is never
  valid beyond any included entry's expiry.

### 5. Update policy is part of the approval

`UpdatePolicy::{ManualEachTime, AutoSamePathUser}` is chosen by the administrator
when approving. Under `AutoSamePathUser` CMIS approves a new hash on its own only
when **all** of these hold:

- same host, same canonical path, and the same user identity (Unix uid **and**
  user name; Windows full SID);
- the parent approval is `ACTIVE`, its lineage is not frozen, and the global kill
  switch is on;
- a **continuity anchor** holds: the path is protected (not writable by non-admin
  principals), or the new binary carries the same code-signing identity as the
  parent. The administrator may waive this per approval (`continuity =
  PathUserOnly`), with a warning;
- the hash was never revoked or denied in this lineage;
- the lineage's auto-approval rate limit is not exceeded.

The new approval **inherits** the parent's expiry. Auto-update can never extend the
time window that a person approved.

### 6. Direct administrator registration is a single step by default

An administrator who holds both `app.direct_register` and `app_request.approve`
(F20) can register **and** approve an application in one call
(`AdminRegisterApplication`, origin `admin_direct`). CMIS creates the request, marks
it `APPROVED` and creates the approval in one Raft transaction, with
`decided_by_admin_id = requested_by_admin_id` and `same_actor_approved = 1`.

- **Default behaviour.** The product owner decided on 2026-10-14 (D4) that this is
  the default. It is **an accepted risk**, to be acknowledged by the ESI: one
  compromised approver account plus its second factor can authorize a binary
  without a second person.
- **Controls that stay.** Every single-step add needs a **fresh second factor** for
  that call (a per-operation proof, not the 5-minute step-up window), passes the
  same validation as any approval (scope and expiry limits, confirmation for
  any-user scope, §5), and emits the distinct audit event `AppApprovedBySameActor`
  (F19 §9). The event marks that the requester and the approver were the same
  person, so reviews and SIEM rules can single it out.
- **Optional strict policy.** `CMIS_ADMIN_STRICT_SOD=true` (default off) makes
  direct add create only a `PENDING` request that a different approver must decide,
  and forbids approving or denying one's own request (F20 §7).
- **INV-1 to INV-3 are unaffected.** A single-step add creates exactly one approval
  and never alters another one.

## Consequences

**Positive**

- Requirement 4 holds by construction and is testable (INV-1 to INV-3).
- Every entry in a signed allowlist traces back to an approval id. Every approval
  traces back to a request and an administrator, or to a policy and its parent.
- v2 closes two gaps in v1: cross-host substitution (host binding) and rollback
  within the validity window (generation).
- Hosts sync incrementally (`have_generation` → `NOT_MODIFIED`), which keeps
  5-minute polling cheap.

**Negative / risks**

- Approvals accumulate, because superseded revisions stay active until they expire
  or are revoked. Mitigations: a default approval TTL (180 days), a "superseded"
  report in the admin UIs, and bulk revocation by lineage.
- Two allowlist formats must be maintained during migration.
- Path-exact matching breaks updaters that install into versioned directories
  (Squirrel `app-1.2.3\`, snap revisions). Such apps either use
  `path_match = Any` or get a new lineage on each update (F19-OQ4).
- More state lives in Raft: requests, approvals, revisions and a per-host compile
  cache.
- **Accepted risk (D4): single-step direct add.** The default has no second human
  in the loop for administrator-added applications. Mitigations: a fresh second
  factor per add, the `AppApprovedBySameActor` audit event, expiry caps, revocation
  within one sync interval, and the optional strict separation-of-duties policy for
  deployments that want a second approver. The ESI must acknowledge the risk.

## Alternatives considered

- **Keep full-set proposals, merge instead of replace.** Rejected. A merge still
  cannot represent per-app decisions, policies, expiry or denial, and a single row
  per host keeps last-write-wins.
- **One signed artefact per approval.** Rejected. The MIA would verify N
  signatures, and revocation would need a separate revocation list. Compiling a
  per-host document keeps a single signature and a single freshness check.
- **Supersede the old approval automatically on update.** Rejected by requirement 4.
- **Require a second approver for every direct add (strict separation of duties as
  the default).** Not chosen: the product owner decided on single-step add (D4).
  It remains available as the optional policy `CMIS_ADMIN_STRICT_SOD`.
- **Trust the self-declared version for policy (for example "auto-approve patch
  releases").** Rejected. Versions are claims made by the binary and are never
  security inputs. Only hash, path, user and signer are.
- **Lineage keyed by (host, path, user).** Rejected. The same binary at the same
  location would get different revision numbers for different users, which
  confuses reviewers. The user is an attribute of requests and approvals, not of
  the lineage.
- **Plaintext path in the signed body.** Rejected because of LGPD minimisation:
  paths under `/home/<name>` or `C:\Users\<name>` are personal data.
