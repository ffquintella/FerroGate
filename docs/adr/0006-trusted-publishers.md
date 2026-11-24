# ADR-0006 — Trusted publishers: automatic approval of applications signed by an allowlisted publisher

- **Status:** Proposed. It adds an administrator-configured approval policy, so it
  changes security premise P5 of the
  [overview](../app-approval-and-admin.md#security-premises) and needs ESI review
  before production use.
- **Date:** 2026-11-24
- **Deciders:** FerroGate core team. Pending: ESI (premises, accepted risks in §7),
  product owner (scope defaults in §8).
- **Scope:** How an administrator declares a code-signing publisher trusted, how
  that reaches every MIA, how a MIA verifies a caller's code signature, and where
  this hooks into the helper API's approval decision.
- **Relation to earlier ADRs:** extends [ADR-0004](0004-app-approval-ledger.md)
  (the signed allowlist gains a format 3; INV-1 to INV-3 are unchanged) and uses
  the administrator authentication of [ADR-0005](0005-admin-authentication.md)
  (F20) unchanged.

## Context

Today an application obtains tokens from the MIA helper API (`/run/ferrogate/mia.sock`,
`\\.\pipe\ferrogate-mia` on Windows) only when an entry of the host's signed
allowlist admits it. The MIA identifies the caller from the kernel (peer PID/UID
or the named-pipe client PID, the executable path, the `SHA-384` of the image) and
checks the allowlist in `crates/mia/src/helper/server/mod.rs` (`process_request`,
step 4). Entries come from approvals (F19): an application asks, an administrator
approves, CMIS compiles a signed, host-bound body (ADR-0004), the MIA syncs it.

Every new binary or version of a vendor's application therefore needs a request
and an approval on every host, even when the vendor signs all its binaries with
the same code-signing certificate. The request is: "if an app is signed by a valid
publisher it is automatically accepted to use MIA, without requiring another
approval".

## Decision

### 1. Trusted publishers are CMIS records, managed only through the F20 admin path

A trusted publisher is a replicated record (`trusted_publishers`, schema
migration 4, `crates/ferro-raft/src/publishers.rs`). Three admin RPCs manage it:

| RPC | Permission | Second factor | Audit |
|-----|-----------|---------------|-------|
| `ListTrustedPublishers` | `publisher.list` (viewers, approvers, platform operators) | — | layer only |
| `AddTrustedPublisher` | `publisher.manage` (platform operators) | **fresh, per operation** (F20 §7 "M") | `TrustedPublisherAdded` |
| `RemoveTrustedPublisher` | `publisher.manage` | recent step-up (F20 §7 "S") | `TrustedPublisherRemoved` |

They go through the one decision point `AdminAuthz` and `METHOD_ACCESS`, like every
admin call. There is no file, environment variable or host-side command that adds
a publisher, and no host RPC (MIA, or an application asking the MIA for access)
reaches these methods. The `ferrogate admin publishers` CLI and the tray admin
client's "Trusted publishers" view both use the same client library
(`ferrogate_admin_client::publishers`) to read an identity, build and check the
request and display records; the server re-checks everything.

Records are never deleted. Removal happens once and is final; what a record trusts
never changes (SQLite triggers enforce both). At most 256 publishers are active and
at most one active record pins the same thing.

### 2. What a rule pins: a CA in the chain AND the leaf, by digest

A rule is `(kind, anchor_sha256, pin_kind, pin, require_timestamp, expires_at)`:

- `kind`: Authenticode (Windows) or Apple code signature (macOS).
- `anchor_sha256`: SHA-256 of a CA certificate (root or, preferably, the issuing
  intermediate) that must appear **above the leaf** in the chain the OS verified.
- `pin_kind`/`pin`: SHA-256 of the leaf certificate (thumbprint), of its
  `SubjectPublicKeyInfo`, or `SHA-256("ferrogate-publisher-subject-v1" ‖ 0 ‖
  subject DER)`.
- Display strings (label, subject, issuer) are stored for people only and never
  matched. A bare display name or CN is never a pin.

A subject pin survives certificate renewals; it is safe only because the CA pin
binds it to one issuer that verified the subject. The add flow warns about it, and
about anchoring on a root instead of the intermediate.

### 3. The decision (pure, fail closed)

`ferro_codesign::match_publisher` admits a caller when the OS verified its
signature and some unexpired rule of the same kind has the leaf's pin and its CA in
the chain, and, when the rule requires it, the signature carries a verified
timestamp. A leaf outside its validity window admits only with a timestamp. Every
error (no rules, no match, wrong chain, missing timestamp, expired rule) admits
nobody.

### 4. Per-platform verification, bound to the kernel-identified image

The `SignatureVerifier` trait (`crates/ferro-codesign`) asks the OS; tests use a
fake. The caller is the one the kernel identified: the verifier gets its PID, path
and the `SHA-384` the helper hashed.

- **Windows:** the image path of the client PID is opened with `FILE_SHARE_READ`
  only (no writer or deleter while it is checked); its bytes must hash to the
  identified `bin_sha`; `WinVerifyTrust` verifies **that handle** with whole-chain
  revocation checking (root excluded); the chain comes from the WinTrust provider
  state (`ferro-winauth::authenticode_signature`). Unknown revocation status fails
  closed.
- **macOS:** `SecCodeCopyGuestWithAttributes` by PID and `SecCodeCheckValidity`
  validate the *running* code (dynamic validity) under `anchor apple generic`; the
  code's path must be the executable or its bundle, and the executable must still
  hash to `bin_sha`; the chain and secure timestamp come from
  `SecCodeCopySigningInformation`.
- **Linux and other platforms:** no verifier. Every check returns `Unsupported`;
  publishers never admit anyone there. Approvals work as before.

### 5. Distribution: allowlist format 3, only to MIAs that ask for it

CMIS compiles the active, unexpired publishers into the signed allowlist of every
host whose `SyncAllowlist` lists format 3 in `accept_formats` (this MIA sends
`[2, 3]`). The body is the same `AllowlistDocV2` struct under the same signature
context, with `format = 3` and a `publishers` field. Without publishers, or for a
host that asks only for format 2, the body is byte-identical to before. The digest
CMIS records per generation covers the publishers, so an add, a removal or an
expiry moves the generation of every capable host on its next sync (5 minutes);
rollback and host-binding protection (ADR-0004) apply unchanged. An older MIA never
receives format 3, so it cannot fail on an unknown field.

### 6. Hook into the approval decision, and audit

In `process_request`, after the host SVID and CRL gates and only when **no allowlist
entry admits the caller** and the body carries publishers, the MIA verifies the
caller's signature on the blocking pool and matches it. A match mints the token and
records `LocalGrantByPublisher {pid, uid, bin_sha, jti, publisher_id,
leaf_cert_sha256}` in place of `LocalGrant` (still exactly one audit event per
request), plus an INFO log line `helper.publisher.auto_approved`. A refusal records
the usual `LocalDenied not-allowlisted`; the specific reason goes to the local log
only. No request is sent to CMIS and no operator is involved. Without publishers
nothing is verified, so behaviour is unchanged.

### 7. Threat model and limits

| Threat | Mitigation | Residual |
|--------|-----------|----------|
| A caller adds itself, or a host adds a publisher | Only F20 admin RPCs write records; hosts only read signed bodies | — |
| A stolen admin session adds a publisher | `publisher.manage` (platform operators only) plus a fresh second factor per add; audited | One compromised operator with their second factor can trust a publisher fleet-wide (as for D4) |
| Look-alike certificate (same name, other CA) | Pins are digests; the CA pin is mandatory | A mis-issuing pinned CA |
| Revoked or expired signing certificate | Windows revocation checks (fail closed); timestamp rules | macOS relies on the OS's own revocation handling |
| Binary swapped between identification and check | Re-hash must equal `bin_sha`; Windows verifies the held handle; macOS validates the running code | A swap before the helper's own first read (as for approvals); PID reuse on macOS |
| A signed but vulnerable or malicious build of a trusted vendor | none: the rule trusts everything that publisher signs | Accepted by design; use narrow pins, expiry and prompt removal |
| Old body replayed | Generation and host binding (ADR-0004) | A removal takes up to one sync interval |

### 8. Defaults chosen

- Scope is **fleet-wide and any user**: a per-host or per-user scope is a
  follow-up. `require_timestamp` defaults to on in the clients.
- Linux is out of scope (fail closed) until a signing standard is chosen.

## Consequences

**Positive:** vendors' updates no longer need an approval per host and version; every
auto-approval is attributable to a publisher record and an administrator.

**Negative / risks:** a powerful, fleet-wide grant; Windows revocation checks need
CRL/OCSP reachability (without it auto-approval fails closed and approvals still
work); signature verification costs a few milliseconds per non-allowlisted request
from a signed binary (no cache yet).

## Alternatives considered

- **A host-local list in `mia.toml`.** Rejected: it bypasses F20 authentication,
  MFA and the central audit, and differs per host.
- **CMIS turns a signer claim in `SubmitAppRequest` into an auto-approval.** Rejected:
  the user asked for no request at all, and it still needs a round trip and sync.
- **Match on the subject CN or Team ID alone.** Rejected: a display name is not
  bound to a CA; the CA pin is mandatory.
- **A separate signed publisher document.** Rejected: it would duplicate the
  generation, rollback and host-binding machinery the allowlist already has.
