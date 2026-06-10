# ADR-0002 — Optional uid in caller allowlist entries (hash-primary matching)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** FerroGate core team
- **Scope:** The signed caller **allowlist** consumed by the MIA helper API
  (feature [F08](../features/F08-helper-api.md)) and issued by CMIS. Affects the
  shared wire model (`ferro-svid`), the proto (`ferro-proto`), the MIA runtime
  matcher, the observed-caller ledger and proposal flow, the CMIS allowlist RPCs,
  and the `ferrogate allowlist` operator CLI.

## Context

The helper API mints a child token only for a caller present on a **signed
allowlist**. Today each entry is a pair `(uid, bin_sha384)` and a caller is
permitted only if **both** its authenticated uid and its binary hash match an
entry (`crates/mia/src/helper/allowlist.rs`):

```rust
members: HashSet<(u32, [u8; 48])>
fn permits(&self, uid: u32, bin_sha: &[u8; 48]) -> bool {
    self.members.contains(&(uid, *bin_sha))
}
```

The uid is unstable for an important class of callers:

- **systemd `DynamicUser=yes`** allocates a *transient* uid/gid per service
  start. The executable is constant; the uid is different on every restart.
- **Sandboxed / containerized callers** frequently run under an ephemeral or
  per-instance uid for the same image.

For these, a `(uid, bin_sha)` entry goes stale the moment the service restarts,
forcing a re-provision (or re-approval of a proposal) on every launch. The
**binary hash is the stable, security-relevant identity**; the uid is noise.

We want hash-primary matching while preserving the ability to pin a uid where it
*is* stable and meaningful (a long-lived service account, root-only tooling).

### Trust note on `bin_sha` per platform

The weight that the hash can bear differs by platform, and hash-primary matching
leans harder on it:

| Platform | `bin_sha` source | Integrity |
|----------|------------------|-----------|
| Linux | IMA measurement cross-checked against the on-disk hash | Kernel-attested; a post-exec swap is detected |
| macOS | on-disk read of the caller's image (resolved from pid) | **Not** swap-proof; trusts the disk read at mint time |
| Windows | on-disk read + optional Authenticode verification | Code-signing strengthens it when required |

This ADR does not change how `bin_sha` is obtained; it changes only what the
allowlist *requires*. Operators on macOS/Windows should be aware that an entry
which omits the uid is gated solely on that platform's hash source.

## Decision

Make the uid **optional** in an allowlist entry. An entry matches when the
**binary hash matches** and, **if** the entry specifies a uid, the caller's uid
also matches:

- `uid = None` (wildcard) — the binary run by **any** user is permitted. This is
  the restart-stable mode for `DynamicUser`/sandboxed callers.
- `uid = Some(n)` — the binary run **specifically by uid `n`** is permitted
  (today's behaviour; defense-in-depth preserved where the uid is stable).

We deliberately **keep** the uid as an optional constraint rather than dropping
it from the model (the rejected "hash-only" alternative; see below), so that the
expressive, safer pin remains available.

## Design

### 1. Wire model — `crates/ferro-svid/src/allowlist.rs`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowEntry {
    /// Permitted user id, or `None` to permit the binary run by ANY user.
    #[serde(default)]
    pub uid: Option<u32>,
    /// Lowercase hex SHA-384 of the permitted binary.
    pub bin_sha: String,
}
```

**CBOR compatibility.** serde represents `Some(n)` for a self-describing format
exactly as the bare integer `n`, and `None` as `null`. Therefore:

- A re-signed allowlist whose entries are **all pinned** (`Some`) is
  **byte-identical** to one produced by the old code — existing pinned
  provisioning is unaffected and signatures over such bodies are unchanged.
- `#[serde(default)]` makes a missing `uid` field decode to `None`, so the new
  code reads any **old** body (every old entry had a `uid` integer → `Some`).
- Only a **wildcard** entry introduces a new shape (`uid: null`). An *old*
  binary cannot decode `null` into `u32` and would fail closed. This is
  acceptable under the coordinated rollout below (the fleet upgrades together;
  allowlists are short-lived and re-signed continuously).

The signing context stays `ferrogate-allowlist-v1`: the change is additive and
backward-readable, and bumping it would invalidate every in-flight allowlist for
no safety gain. (Revisit only if we ever need old binaries to *reject* new
bodies explicitly rather than fail closed on decode.)

`ProposalDoc` reuses `AllowEntry`, so it inherits the optional uid for free.

### 2. Proto — `crates/ferro-proto/proto/machine_identity.proto`

```proto
message AllowEntryMsg {
  optional uint32 uid = 1;   // proto3 explicit presence: absent ⇒ wildcard
  string bin_sha = 2;        // lowercase hex SHA-384 (96 chars)
}
```

proto3 `optional` gives prost a `pub uid: Option<u32>`, mapping 1:1 to
`AllowEntry.uid`. Field numbers are unchanged, so the wire stays compatible; an
old client that always sets uid simply never produces the wildcard.

### 3. MIA matcher — `crates/mia/src/helper/allowlist.rs`

Replace the tuple set with a hash-keyed map carrying the uid rule:

```rust
enum UidScope { Any, Only(HashSet<u32>) }

pub struct Allowlist {
    trust_domain: String,
    not_after: i64,
    members: HashMap<[u8; 48], UidScope>,
}

pub fn permits(&self, uid: u32, bin_sha: &[u8; 48]) -> bool {
    match self.members.get(bin_sha) {
        Some(UidScope::Any) => true,
        Some(UidScope::Only(uids)) => uids.contains(&uid),
        None => false,
    }
}
```

`load()` folds entries per hash: a `None` uid sets the hash to `Any`
(`Any` always wins if the same hash also appears with specific uids); a `Some`
uid is inserted into the hash's `Only` set. `permits`'s **signature is
unchanged**, so its single call site in
`crates/mia/src/helper/server/mod.rs` needs no edit — the caller's concrete uid
is still passed and is simply ignored for `Any` entries.

### 4. Ledger & proposals — `ledger.rs`, `main.rs`

The observed-caller ledger keeps recording the **concrete** `(uid, bin_sha)` it
sees — that is ground truth and feeds audit. The proposal task continues to
propose entries with `uid = Some(observed_uid)`. Relaxing an entry to a wildcard
is an **operator action** (via the CLI), not something the host infers.

Consequence to document: a `DynamicUser` host keeps proposing a *fresh*
`(uid, hash)` each restart until an operator installs a **wildcard** entry for
that binary; once that wildcard entry is adopted, `permits` passes for the
binary regardless of uid and the caller is served. (The host may still re-propose
the concrete pair, which CMIS treats as a no-op diff against the wildcard live
entry — noise, not a security issue. A later optional refinement: suppress
proposals already covered by a live wildcard.)

### 5. CMIS — `crates/cmis/src/service.rs`

`set_allowlist` / `propose_allowlist` build `AllowEntry { uid, bin_sha }` from
the proto; with `uid: Option<u32>` they pass presence through unchanged.
`entries_match` (proposal-vs-live diff) compares on `(uid, bin_sha)` and keeps
working once both sides are `Option<u32>` — `None == None`, `Some == Some`.
`parse_cert_sha` validation of `bin_sha` is untouched. No storage-format change
beyond the entry type (proposals are stored as CBOR `Vec<AllowEntry>`).

### 6. Operator CLI — `crates/ferrogate-cli/src/allowlist.rs`

Make the uid prefix **optional** in entry syntax; absence means wildcard:

| Input | Meaning |
|-------|---------|
| `--entry <uid>:<sha>` | pin to uid (today's behaviour) |
| `--entry <sha>` | **wildcard** — any user running this binary |
| `--bin <uid>:<path>` | hash the file, pin to uid |
| `--bin <path>` | hash the file, **wildcard** |
| `remove --bin-sha <sha>` (no `--uid`) | drop the entry for that hash (any scope) |
| `remove --uid <n> [--bin-sha <sha>]` | drop pinned entries for that uid |

`split_uid` becomes "split *iff* a `uid:` prefix is present, else uid = None".
`show`/`review` print `uid=*` for wildcard entries, `uid=<n>` otherwise.

### 7. Audit

No change. `LocalGrant`/`LocalDenied` already record the **concrete** observed
uid + bin_sha of the caller; matching semantics changed, the recorded caller
identity did not.

### 8. Tests & docs

- `ferro-svid`: roundtrip tests for both `Some` and `None` uid; assert a
  `Some(n)` body is byte-identical to the pre-change encoding (compat guard).
- `mia` matcher: wildcard permits any uid; pinned permits only the listed uid;
  `Any` wins when a hash appears both ways; deny on unknown hash.
- `cmis` set/propose/get: optional-uid entries round-trip and re-sign; mixed sets.
- CLI: parse `--entry sha` vs `--entry uid:sha`; `show`/`review` formatting.
- Docs: update `docs/allowlist-provisioning.md`, `docs/helper-api.md`,
  `docs/mia.md` to describe the `(uid?, bin_sha)` model and the wildcard
  workflow; note the per-platform `bin_sha` trust caveat.

## Rollout order

The only unsafe direction is an **old MIA** meeting a **wildcard** body it cannot
decode (it fails closed → denies that caller). So:

1. Ship `ferro-svid` + `ferro-proto` + CMIS + MIA **together** in one release
   (a version bump, as with prior fixes). All three understand `Option<u32>`;
   none of them *emit* a wildcard yet because the CLI is the only producer.
2. Upgrade the MIA fleet (now understands wildcard) **before** any operator
   starts omitting the uid.
3. Operators begin using wildcard entries (`--entry <sha>`) where uids are
   ephemeral.

Step 1's coordinated release keeps every consumer ahead of the first wildcard
producer, so no old binary ever sees a body it can't read.

## Consequences

**Positive**

- `DynamicUser`/sandboxed callers are provisioned **once** by binary hash and
  survive restarts — the original problem is solved.
- uid pinning remains available where it is stable, so no security expressiveness
  is lost.
- `permits` signature and its call site are unchanged; the runtime hot path is
  still a single hash-keyed lookup.
- Pinned-only allowlists are byte-identical on the wire — zero churn for existing
  deployments.

**Negative / risks**

- A wildcard entry permits the binary under **any** local uid; on macOS/Windows
  that rests entirely on a non-attested on-disk hash read. Operators must choose
  wildcard deliberately. (Mitigation: keep pinning where the uid is stable; rely
  on Authenticode on Windows.)
- A coordinated release is required (old MIA cannot read wildcard bodies). Failure
  mode is safe (fail-closed deny), not unsafe.
- Proposal noise from `DynamicUser` hosts persists until a wildcard is installed;
  optional follow-up to suppress.

## Alternatives considered

- **Hash-only (drop uid entirely).** Simpler model, but permanently discards the
  ability to constrain by user even when the uid is stable, and offers no upgrade
  path back. Rejected in favour of the strictly-more-expressive optional uid.
- **Bump the signing context to `-v2`.** Forces a clean break and re-issue of
  every allowlist, and makes old/new strictly incompatible for no safety benefit
  given the backward-readable encoding. Rejected; keep `-v1`.
- **Host infers wildcard for ephemeral uids.** The host cannot reliably tell an
  ephemeral uid from a stable one; relaxing to wildcard is a policy decision that
  belongs to the operator. Rejected.
