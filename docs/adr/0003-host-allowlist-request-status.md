# ADR-0003 — Host-side allowlist *request* and *status* commands

- **Status:** Proposed
- **Date:** 2026-06-10
- **Deciders:** FerroGate core team
- **Scope:** New MIA agent commands `mia request-allowlist` and
  `mia allowlist-status`, a read-only `GetProposalStatus` CMIS RPC, and the
  proposal-policy guidance that makes approval operator-gated. Builds on the
  existing `ProposeAllowlist` machinery and the optional-uid entry model
  ([ADR-0002](0002-allowlist-optional-uid.md)). Does **not** change how the
  authoritative allowlist is signed.

## Context

Today a MIA host influences its allowlist in exactly one way: the daemon's
background **propose** task periodically sends CMIS the callers it has *observed*
(`maybe_spawn_propose_task` → `ProposeAllowlist`). There is no way for an
operator *on the host* to explicitly request that a specific app (a binary hash,
optionally a uid) be allowlisted, and no way to ask CMIS whether a request has
been **approved** — the host can only poll `GetAllowlist` and infer adoption from
membership.

We want two host-side commands:

- **`mia request-allowlist`** — submit a request to allowlist one or more
  explicit apps for *this* host.
- **`mia allowlist-status`** — report whether those apps are approved (live),
  still pending review, or absent.

### The governing constraint

> The MIA agent must be able to **request** an allowlist change and **query its
> status** — and nothing more. It must **never** be able to produce or approve
> the authoritative signed allowlist.

This is already true of the cryptography and must remain true of the new surface:

- The authoritative allowlist is signed **only** by the CMIS **issuer key**
  (`Issuer::sign_allowlist`), which never leaves the server.
- A host's machine-key signature on a proposal (`proposal_sig` over
  `proposal_signing_input`, context `ferrogate-allowlist-proposal-v1`)
  **authenticates the request** — it proves *which attested host* is asking — and
  is verified by CMIS against the key bound to the proposing SVID's `cnf.jkt`. It
  does **not** sign, and cannot be turned into, a `SignedAllowlist`.
- `SetAllowlist`/`DeleteAllowlist` (the operator approve/reject path) are
  **admin RPCs**, authenticated out of band (network location + SPKI-pinned TLS);
  a host has no path to call them.

The one place a host's *request* can directly cause adoption is the CMIS
**proposal policy** (`CMIS_ALLOWLIST_PROPOSALS`): under `BootstrapOnly` (default)
CMIS auto-adopts a host's *first* proposal (TOFU), and under `Always` it
auto-adopts every proposal. That is **CMIS** signing under an operator-chosen
policy, not the host signing — but from a trust standpoint it lets a host's
request take effect with no human in the loop. So honoring the constraint is
partly a **deployment** decision, addressed below.

## Decision

Add two host commands and one read-only RPC, and make the capability boundary
explicit:

1. **`mia request-allowlist`** authenticates and submits a `ProposeAllowlist` for
   this host. It can only *propose*; CMIS decides.
2. **`mia allowlist-status`** reads this host's live + pending allowlist state via
   a new unauthenticated **`GetProposalStatus`** RPC and reports per-app status.
3. **Operator-gated approval is the recommended posture:** run CMIS with
   `CMIS_ALLOWLIST_PROPOSALS=off` so *every* proposal — including the first —
   queues for `ferrogate allowlist approve`. Under `off`, a host genuinely cannot
   cause its own allowlist to change; it can only request and wait.

No change to issuer signing, to `SetAllowlist`, or to the operator
approve/reject/review commands.

## Design

### 1. Capability boundary (enforced, not just documented)

| Action | Who | Mechanism |
|--------|-----|-----------|
| Request an entry | **host** (`mia request-allowlist`) | `ProposeAllowlist`, authenticated by SVID + machine-key sig |
| Query status | **host** (`mia allowlist-status`) | `GetProposalStatus` (read-only, unauthenticated) |
| Approve / sign | **operator + CMIS** | `ferrogate allowlist approve` → `SetAllowlist` → issuer signs |
| Reject | **operator + CMIS** | `ferrogate allowlist reject` → `DeleteProposal` |
| Auto-adopt | **CMIS policy only** | `CMIS_ALLOWLIST_PROPOSALS` (recommend `off`) |

The host holds a **machine key** (proposal authentication) and obtains **SVIDs**
(host identity). It never holds the **issuer key**. No new code path gives it
one; both new commands call only `ProposeAllowlist` (write-but-not-sign) and
`GetProposalStatus` (read).

### 2. `mia request-allowlist`

```
mia request-allowlist (--entry [uid:]sha | --bin [uid:]path)... [--config <path>] [--replace]
```

Entry syntax matches the operator CLI (ADR-0002): a `uid:` prefix pins to a user,
its absence is a wildcard (any user). `--bin` hashes the file for you.

Behavior:

1. **Attest for a fresh SVID.** A proposal is authenticated by a *currently
   valid* SVID JWS, so the command performs a host-key attestation
   (`run_attest_host_key`, exactly as `bootstrap_host_svid` does) to obtain a
   fresh `{ jws, spiffe_id }` and the machine key. A cached SVID would fail
   CMIS's freshness check. (This is the one command here that needs the network
   attestation; `allowlist-status` does not.)
2. **Compose the proposed set additively by default.** A proposal is a *full
   set* that, if adopted, *replaces* the host's allowlist. To make a request
   purely additive, the command fetches the current state via `GetProposalStatus`
   and proposes `live ∪ pending ∪ requested`. `--replace` proposes exactly the
   `--entry/--bin` set instead (for deliberate pruning). The command prints the
   resulting set and the diff vs live before sending.
3. **Sign the request and submit.** Build `ProposalDoc { host_uuid, issued_at,
   entries }`, sign `proposal_signing_input(body)` with the machine key, and call
   `propose_allowlist(endpoint, pins, body, sig, jws, sep_pub)`.
4. **Report the outcome honestly.**
   - `Pending` → "queued for operator review; approve with `ferrogate allowlist
     approve <uuid>`, then `mia allowlist-status` to confirm." (the expected
     outcome under the recommended `off` policy)
   - `AutoAdopted` → printed as a **warning** that CMIS policy adopted the request
     without review (`CMIS_ALLOWLIST_PROPOSALS` is not `off`), naming the policy
     so the operator can lock it down if that was unintended.
   - `Unchanged` → already live; nothing to do.

The command exits non-zero only on transport/auth failure, so it scripts cleanly;
`Pending` is a success (the request was accepted).

### 3. `mia allowlist-status`

```
mia allowlist-status [--entry [uid:]sha | --bin [uid:]path]... [--config <path>]
```

A **read-only** command — no attestation, no machine-key signature. It derives
the host UUID locally from the hardware fingerprint
(`host_uuid_from_ek_digest(fingerprint)`, as `mia resync-allowlist` does),
calls `GetProposalStatus`, and reports:

- **Overall:** whether a proposal is pending and how many entries are live.
- **Per requested entry** (when `--entry/--bin` are given), one of:
  - **approved** — present in the live signed allowlist;
  - **pending** — present in the pending proposal but not yet live;
  - **absent** — in neither (never requested, or **rejected** — see Limitations).

With no entry flags it prints the full live set and the pending set (a superset
of what `ferrogate allowlist review` shows the operator, minus operator-only
metadata). No secrets are involved: the allowlist body is already
signature-public and is served unauthenticated by `GetAllowlist`.

### 4. New RPC: `GetProposalStatus`

```proto
message GetProposalStatusRequest { string host_uuid = 1; }

message GetProposalStatusResponse {
  bool has_pending = 1;                       // a proposal is queued for review
  repeated AllowEntryMsg live_entries = 2;    // the current signed allowlist (may be empty)
  repeated AllowEntryMsg pending_entries = 3; // the queued proposal's entries (empty if none)
  int64 proposed_at = 4;                      // when the pending proposal arrived (0 if none)
}
```

- **Unauthenticated**, like `GetAllowlist`: it exposes only this host's
  allowlist/proposal state (keyed by `host_uuid`), which is not secret, and lets
  a host check status *before* it has attested. It is read-only and cannot
  mutate anything.
- CMIS implements it from the same stores `ListProposals`/`GetAllowlist` already
  read (the Raft-replicated `host_allowlists` keyspace and the pending-proposal
  store). No new persistence.
- Reuses `AllowEntryMsg` (now `optional uint32 uid`, ADR-0002), so wildcard and
  pinned entries render correctly.

### 5. Proposal policy guidance

Document, in `docs/allowlist-provisioning.md` and `docs/mia.md`, that the
capability boundary holds in full **only under `CMIS_ALLOWLIST_PROPOSALS=off`**:

| Policy | A host's request can adopt without an operator? |
|--------|--------------------------------------------------|
| `off` | **No** — every proposal queues for `ferrogate allowlist approve`. *Recommended for this model.* |
| `bootstrapOnly` (default) | Only the host's **first** proposal (TOFU), when it has no allowlist yet. |
| `always` | Yes — every proposal. |

`request-allowlist` surfaces an `AutoAdopted` outcome as a warning precisely so a
deployment that expected `off` notices a misconfiguration.

### 6. Operator side — unchanged

`ferrogate allowlist proposals | review | approve | reject` are untouched.
Approval remains: operator reviews → `SetAllowlist` (issuer signs) →
`DeleteProposal`. The new host commands feed the *same* review queue and read the
*same* live/pending state.

## Rollout

1. Add `GetProposalStatusRequest/Response` + the RPC to `ferro-proto` (additive;
   new message + method, no field changes).
2. Implement `GetProposalStatus` in CMIS (read-only).
3. Add the two `mia` commands (client-only; `request-allowlist` reuses the
   attestation + propose code paths, `allowlist-status` the fingerprint-UUID +
   the new RPC).
4. For hosts that must be operator-gated, set `CMIS_ALLOWLIST_PROPOSALS=off`.

All additive — no wire break. An old CMIS without `GetProposalStatus` makes
`allowlist-status` fail with `Unimplemented`, which the command reports as "this
CMIS does not support status queries; upgrade CMIS or use `ferrogate allowlist
show`."

## Consequences

**Positive**
- An on-host operator can explicitly request apps and confirm approval without
  shell access to CMIS or the `ferrogate` CLI.
- The agent's power is provably bounded to *request + read*; signing stays with
  the issuer, approval with the operator.
- `allowlist-status` needs no attestation, so checking state is cheap and
  side-effect-free.

**Negative / limitations**
- **`rejected` is indistinguishable from `absent`.** `reject` deletes the pending
  proposal, leaving no tombstone, so the host sees "absent". Operators
  communicate rejection out of band. A short-lived rejection record is a possible
  future addition; deliberately out of scope here.
- **Additive semantics rely on a read-then-propose race window.** Two concurrent
  `request-allowlist` runs could each propose `live ∪ their-own`; last write wins
  in the pending queue. Acceptable for an operator-driven command; the printed
  diff makes the proposed set explicit.
- **The boundary's "no auto-adopt" guarantee is a deployment setting**, not a
  code invariant — it holds only under `CMIS_ALLOWLIST_PROPOSALS=off`. The
  `AutoAdopted` warning makes a non-`off` policy visible at request time.

## Alternatives considered

- **Let `mia` sign/apply the allowlist directly.** Rejected outright — it would
  hand the agent issuer-equivalent authority and defeat the entire trust model.
- **No status RPC; poll `GetAllowlist` only.** Workable for "approved?" but
  cannot show "pending", so an operator on the host can't tell a queued request
  from a lost one. The read-only `GetProposalStatus` is a small, side-effect-free
  addition that closes that gap.
- **Authenticate `GetProposalStatus` with the host SVID.** Unnecessary: the data
  is signature-public and host-scoped, and requiring attestation just to read
  status would force a needless handshake (and prevent pre-attestation checks).
