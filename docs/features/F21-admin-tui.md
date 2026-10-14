# F21 — Server administration TUI (`ferrogate-tui`)

> Uses: [F20](F20-admin-authentication.md) (login, sessions, permissions) and
> [F19](F19-app-registration-approval.md) (request and approval RPCs). Overview:
> [app-approval-and-admin.md](../app-approval-and-admin.md).
>
> **Decision (D1, 2026-10-14).** The server admin UI is a **curses-style TUI**: a
> full-screen, keyboard-driven terminal UI built with `ratatui` and `crossterm`,
> as decided by the product owner (see the
> [Decisions log](../app-approval-and-admin.md#decisions-log)). The request's
> wording "written in curl" was read as curses. A REST/JSON gateway driven with
> `curl` is not planned.

## Summary

`ferrogate-tui` is an interactive terminal application for administrators. It
runs on a CMIS server host, or on an administrator workstation, and connects to
the CMIS **admin listener** over hybrid-PQC TLS with SPKI pinning. An
administrator signs in with username, password and a TOTP code. (FIDO2 is
available only in the tray admin client, F22.) They can then:

- list and search registration requests;
- approve or deny them, choosing the update policy and expiry;
- browse, edit and revoke ("delete") approvals;
- freeze auto-updates of a lineage;
- add an application directly by known hash and path, as a single step (register and
  approve together) by default;
- manage administrator accounts and sessions, if they hold those permissions.

The TUI holds no authority of its own. Every action is a gRPC call checked by
`AdminAuthz` (F20), exactly like the CLI and the tray admin client. It **never
opens the database** (FGV NRM §5.4.2: no screens that query the database
directly).

## Scope

### Goals (in)

- Login with password and TOTP, password change on expiry, step-up prompts and idle
  lock. Account enrollment and factor management (TOTP and FIDO2) are done in the
  tray admin client (F22), not here.
- Screens: Dashboard, Requests, Request detail, Approvals, Approval detail,
  Hosts, Accounts (account administrators only), Sessions, Help.
- Search and filtering backed by server-side filters (F19 §7.5), with server-side
  pagination.
- Flows: approve (policy, continuity, scope, path match, expiry, note, optional
  revocation of older revisions), deny (reason code and message), edit approval,
  revoke with typed confirmation, freeze or unfreeze a lineage, **add application**
  by known hash and path (single step by default, §6), create, disable and reset
  accounts, revoke sessions.
- Safe rendering of untrusted strings, works over SSH, 80×24 minimum, `NO_COLOR`.

### Non-goals (out)

- Direct database or audit-store access. Any "raw query" or diagnostic screen is
  out.
- Registering applications by browsing local files. That is the tray admin
  client's flow (F22), because the TUI usually runs on the server, not the
  application host. The TUI can add an application by **known hash and path** for a
  remote host (`AdminRegisterApplication`, a goal above), with the hash typed or
  pasted.
- Account enrollment and FIDO2. The TUI signs in with TOTP only. Enrolling TOTP or a
  FIDO2 key is done in the tray admin client (F22).
- Legacy allowlist editing, SVID revocation and epoch bump. Those stay in the
  `ferrogate` CLI (platform operators). A later phase may add read-only views.
- Mouse-only interactions. The mouse is optional.

## Actors

Viewers (read-only screens), approvers (decisions and direct add), account
administrators (Accounts and Sessions), as defined in F20. The OS user running the binary needs
no privileges.

## User stories

1. *As an approver*, I SSH to a CMIS node, run `ferrogate-tui`, sign in with
   password and TOTP, press `2`, and see the pending requests sorted by age.
2. I type `/zoom` to filter, open a request, read the warnings (unsigned,
   user-writable path), press `a`, choose "Manual each time", 90 days, review, and
   confirm. The TUI asks for my TOTP because my last check is older than 5 minutes.
3. I open Approvals, filter "expiring in 14 days", extend one by 180 days, and
   revoke another after typing its short id.
4. *As a viewer*, I can search everything, but the approve and deny keys are
   disabled and labelled "requires approver".
5. I walk away. After 15 minutes the screen clears and asks me to sign in again.
6. *As an approver who knows the hash*, I press `A` in Requests, enter the host,
   path, user and SHA-384 of an internal tool, review, and confirm with a fresh TOTP
   code. It is registered and approved at once (single step). If the organisation
   turned on strict separation of duties, it is queued for a different approver.

## Components touched

| Crate | Change |
|-------|--------|
| `crates/ferrogate-tui` (**new** binary crate, `#![forbid(unsafe_code)]`) | `app` (headless state machine), `screens/*` (pure view functions), `input` (key-map), `sanitize` (untrusted-text rendering), `main` (terminal setup, panic hook, runtime) |
| `crates/ferrogate-admin-client` (from F20) | Typed admin RPC calls, login and step-up flow, session in `Zeroizing`, password generator and pre-check |
| Packaging | `ferrogate-tui` shipped with the CMIS packages (deb, rpm, container image `ferrogate-cmis` tools layer) and as a standalone archive for workstations |
| Docs | `docs/operations.md` (admin section), a man page or `--help` |

Dependencies: `ratatui` (0.29+), `crossterm`, `tokio`, `zeroize`, `qrcode` (TOTP
enrollment QR rendered as Unicode half-blocks), workspace `tonic` and
`ferro-transport`. No HTML or web view.

## Dependencies

- F20 Phase 0 and Phase 1 (admin listener, accounts, sessions, `AdminAuthz`).
- F19 admin RPCs (`ListAppRequests`, `ApproveAppRequest`, …).

## Design notes

### 1. Where it runs and how it connects

```
 admin's terminal ──ssh──▶ CMIS node                         or   admin workstation
                            └─ ferrogate-tui (unprivileged user)    └─ ferrogate-tui
                                 │  gRPC, hybrid-PQC TLS 1.3, SPKI-pinned
                                 ▼
                            CMIS admin listener (default 127.0.0.1:8444)
                                 │  AdminAuthz (F20) → handlers (F19)
                                 ▼
                            hiqlite (Raft)        ferro-audit (WORM)
```

- **gRPC through the same authorization path. No direct database access.** The
  TUI is just another client. Running it on the CMIS host grants nothing extra:
  OS access to the node does not bypass `AdminAuthz`.
- **Configuration** (no secrets): `$XDG_CONFIG_HOME/ferrogate/admin.toml`, falling
  back to `/etc/ferrogate/admin.toml`:

```toml
endpoint   = "https://127.0.0.1:8444"
spki_pins  = ["<sha384-hex>"]          # required; refuse to start without one
device_token_path = ""                 # default: $XDG_STATE_HOME/ferrogate/device-token (0600)
refresh_secs = 30                      # list auto-refresh; 0 disables
```

  Environment overrides: `FERROGATE_ADMIN_ENDPOINT`, `FERROGATE_ADMIN_SPKI_PIN`.
  On first run without a pin, the TUI prints how to obtain one
  (`transport-tls.md`) and exits. It never offers trust on first use.
- **Second factor:** TOTP, in every setting including SSH. The TUI does not offer
  FIDO2 (no CTAP forwarding over SSH). FIDO2 is available through the tray admin
  client (F22, F20 §5). Production can require FIDO2 for approvers *in the tray* while
  TUI sessions use TOTP.

### 2. Architecture

- **Model, update, view.** `App` is a plain state machine (`Screen`, `Modal`,
  list caches, filter state, session view) updated by `Msg` values (keys, RPC
  results, ticks). Views are pure functions `fn(&App, Rect, &mut Frame)`. All
  logic is testable without a terminal (`ratatui::backend::TestBackend`).
- **Async boundary.** One tokio task owns the gRPC client and session. The UI loop
  sends `Cmd`s and receives `Msg`s over bounded channels. The UI never blocks on
  the network; a spinner shows outstanding calls.
- **Terminal hygiene.** Alternate screen and raw mode, restored on normal exit,
  `Ctrl-C` and panic (panic hook). The screen is cleared on exit and on lock so
  scroll-back keeps no records.
- **No logging by default.** `--log-file <path>` (debug) writes only event names
  and reason codes through the shared redaction layer, never field values
  shown on screen.

### 3. Screens

```
┌ FerroGate admin · cmis-1:8444 · jsilva (approver) · AAL2 · idle 14:32 · step-up ✓ 3:10 ┐
│ 1 Dashboard  2 Requests (12)  3 Approvals  4 Hosts  5 Accounts  6 Sessions        ? help │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ / zoom   state:pending  origin:any  kind:any  host:*          12 results · page 1/1      │
│ ID       STATE    HOST      APP (path tail)              VERSION      USER     KIND  AGE │
│ 0192ab3c PENDING  ws-0423   …/Zoom.app/Contents/MacOS/zo 6.2.1 (r3)   jsouza   upd   2h  │
│ 0192a9f1 PENDING  srv-db-02 /usr/local/bin/backup-agent  r4           backup   upd   5h  │
│   ⚠ unsigned · user-writable path                                                        │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ Enter open · a approve · d deny · / search · f filters · s sort · r refresh · q quit     │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

| Screen | Content | Data source |
|--------|---------|-------------|
| **Login** | Endpoint and pin fingerprint (read-only), username, password (masked, paste allowed), TOTP code; a hint "Not enrolled? Use the tray admin client"; generic error line; lock countdown when throttled | `BeginLogin`, `Login` |
| **Change password** | Forced when `password_change_required`; policy hints; generator (`g`) | `ChangePassword` |
| **Dashboard** | Counts: pending requests, auto-approved in the last 24 h, approvals expiring in 14 days, legacy no-expiry approvals, hosts with sync failures (when exposed); session info | `ListAppRequests`/`ListApprovals` with `page_size = 0` (counts) |
| **Requests** | Table as above; flag line per row; sort by age, host or app | `ListAppRequests` |
| **Request detail** | Full path, SHA-384 (wrapped, monospace), declared version and source, revision, product, bundle or package, signer, user (name, uid or SID), requester, origin, host and tier, reason, flags explained, **lineage history** (revisions with their approvals and decisions), auto-downgrade reason | `GetAppRequest` |
| **Approvals** | ID, state, host, app, version, user scope, policy, continuity, expires, origin, superseded badge | `ListApprovals` |
| **Approval detail** | All fields, revision history (who, when, what changed), lineage tree (parent and children), the request that created it | `GetApproval` |
| **Hosts** | Host uuid, display hostname, tier, last attest, approval and pending counts; Enter opens Requests filtered by host | `ListHosts` |
| **Accounts** (account administrators) | Username, display name, state, groups, last login, password expiry; create, edit groups, disable or enable, reset | `ListAdminAccounts`, … |
| **Sessions** | Own sessions (and any account's, with `session.revoke_any`): created, last seen, IP, client, AAL; revoke | `ListMySessions`, `RevokeSession` |
| **Help** | Key map, flag glossary, policy explanations (EN/PT) | static |

### 4. Keybindings

| Context | Keys | Action |
|---------|------|--------|
| Global | `1`–`6`, `Tab` / `Shift-Tab` | Switch screen |
| Global | `?` | Help overlay |
| Global | `Ctrl-L` | Lock now (clear screen, wipe the token, back to login) |
| Global | `q` | Quit (asks for confirmation; logs out on the server) |
| Global | `r` | Refresh |
| Lists | `↑ ↓` / `j k`, `PgUp PgDn`, `g G` | Move, page, first, last |
| Lists | `Enter` | Open |
| Lists | `/` | Free-text search (≤ 128) |
| Lists | `f` | Filter panel |
| Lists | `s` | Cycle sort |
| Lists | `n` / `p` | Next / previous page |
| Lists | `c` | Clear filters |
| Requests / Approvals | `A` | Add application by known hash and path (needs `app.direct_register`; otherwise disabled and labelled) |
| Request list / detail | `a` | Approve |
| Request list / detail | `d` | Deny (approvers; otherwise disabled and labelled) |
| Request detail | `h` | Toggle full hash |
| Request detail | `l` | Jump to lineage |
| Approval detail | `e` | Edit |
| Approval detail | `x` | Revoke ("delete") |
| Approval detail | `z` | Freeze or unfreeze lineage auto-update |
| Approval detail | `h` | Full hash |
| Dialogs | `Tab` / `Shift-Tab`, `Space` | Move between fields, toggle option |
| Dialogs | `Enter` | Next or review |
| Dialogs | `y` | Confirm on the review page |
| Dialogs | `Esc` | Cancel (nothing sent) |
| Accounts | `n` | New account |
| Accounts | `e` | Edit groups |
| Accounts | `D` | Disable or enable |
| Accounts | `R` | Reset credentials |
| Sessions | `x` | Revoke |

Keys that need a permission the session lacks are greyed out and explain why when
pressed. That is a convenience only; the server enforces permissions.

### 5. Search and filter panel

The panel maps one-to-one to the F19 §7.5 request fields:

- **Requests:** state (multi), origin (multi), kind, host (uuid or hostname
  substring), path contains, product contains, user name, declared version, hash
  prefix (≥ 8 hex), flags (any of), submitted from and to (`YYYY-MM-DD`), free text.
- **Approvals:** state, policy, approval origin, user scope, expires before and
  after, presets "expiring ≤ 14 d" / "legacy, no expiry" / "superseded" /
  "auto-update", lineage id, host, free text.

Input limits match the server (128 characters for text). Invalid input (a bad
date, a hash prefix that is not hex) is flagged inline and never sent. Filters are
sent as structured fields and never concatenated into a query string. The server
uses parameterized SQL.

### 6. Flows

**Approve.**

1. The approve dialog (mock-up below) is pre-filled with the safe defaults:
   - *Manual each time*, *Anchored* continuity, *This user only*, *Exact path*;
   - the server default expiry;
   - auto-update preselected **only** when the request has `path_protected`, or a
     valid signer equal to the lineage's previous approved signer.
2. Choosing **Any user** or **Path + user only** shows a warning and needs an
   extra `y`.
3. The review page summarises everything, including the effective expiry date,
   the "also revoke" list and the warnings. `y` sends `ApproveAppRequest` with an
   `idempotency_key`.
4. On `step_up_required` the TOTP modal appears and the call is retried once with
   the same idempotency key.
5. On success the result shows the approval id and the new host generation, and
   says the host will pick it up within 5 minutes.

```
┌ Approve 0192a9f1 · /usr/local/bin/backup-agent · r4 · srv-db-02 · user backup (993) ┐
│ Update policy  (•) Manual approval for every new binary                              │
│                ( ) Auto-approve updates (same path + same user)                      │
│ Continuity     (•) Anchored: protected path or same signer   ( ) Path+user only ⚠     │
│ User scope     (•) This user only                            ( ) Any user ⚠           │
│ Path match     (•) Exact path                                ( ) Any path             │
│ Expires        [ 180 days ▾ ]  → 2027-04-12 (max 365)                               │
│ Note           [________________________________________________] (≤ 500)            │
│ Also revoke    [ ] r3  A-0191c2… (active, superseded)                                │
│ ⚠ unsigned binary · path writable by non-admins → auto-update needs "path+user only"  │
│                                              Enter: review · Esc: cancel              │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

**Add application (direct).** For an administrator with `app.direct_register`.

1. The dialog asks for: host (search through `ListHosts`), canonical path, SHA-384
   (96 hex characters, typed or pasted), user (name and uid or SID), update policy,
   continuity, user scope, path match, expiry and note. Defaults and warnings are the
   same as in the approve dialog.
2. The review page states the outcome: "This registers **and approves** the
   application now. It is recorded as approved by the same person who requested it"
   (single step, the default), or "This queues a request for a different approver"
   (strict policy on). It also notes that the hash and path are **your assertion**
   and are not checked against the host.
3. `y` always prompts for a **fresh TOTP code**, even when the step-up window is
   still valid, because `AdminRegisterApplication` needs a per-operation second
   factor (F20 §7). The call carries an `idempotency_key` and the proof, and the
   retry after a failed proof reuses the key.
4. On success the TUI shows the request and approval ids, and says the host picks
   it up within 5 minutes. The server audits the add as `AppApprovedBySameActor`.

**Deny.** Pick a reason code (`unknown_software`, `policy_violation`,
`insufficient_justification`, `duplicate`, `security_risk`, `other`) and an
optional message to the requester (≤ 200 characters, with the hint "Do not
include personal data"). Review, `y`, step-up if needed.

**Edit approval.** Editable fields:

- update policy;
- continuity;
- expiry (extend within the maximum, shorten, or renew an `EXPIRED` approval);
- note;
- narrowing scope (any → this user, any → exact path).

Widening is not offered. Edits send `expected_row_version`; on `ABORTED` the TUI
reloads, shows what changed and asks again.

**Revoke ("delete").** The dialog explains that the approval stays in history and
the host loses access at its next sync. The administrator must type the short id
shown (for example `A-0191C2`) and pick a reason code, then step up if needed.
`RevokeApproval` follows. Bulk revocation is offered from a lineage view: select
several revisions, then one typed confirmation that lists the ids. The client still
sends one call per approval, each audited.

**Freeze lineage.** A toggle with confirmation. A frozen lineage shows a ❄ badge
and every update request in it goes to manual review.

**Accounts.** Create: username, display name, groups (approvers and account
administrators cannot be combined when the strict SoD policy is on; the UI explains why), MFA
proof, then the enrollment token shown **once**:

- in a modal with the warning "deliver over a second channel after verifying
  identity";
- the new administrator completes enrollment in the tray admin client (F22);
- the token is never written to the clipboard automatically. The administrator
  can press `c` to copy it, and the clipboard is cleared after 60 s. OSC 52 is not
  used over SSH.

Disable, enable and reset all require an MFA proof.

### 7. Rendering untrusted data

Paths, product names, user names, hostnames, reasons and messages originate on
hosts or from other people. Before rendering, `sanitize::display(&str)` does the
following:

- replaces C0 and C1 control characters, `DEL`, and every ESC-introduced
  sequence (CSI, OSC, DCS, including OSC 52 clipboard writes and OSC 8
  hyperlinks) with visible escapes (`\x1b`);
- neutralises bidirectional overrides and isolates (U+202A–202E, U+2066–2069,
  Trojan-Source class) and zero-width characters, showing `⟨U+202E⟩`;
- truncates by display width (`unicode-width`) with a middle ellipsis for paths,
  and offers full text in detail views wrapped and sanitised.

`ratatui` only draws the sanitised `Span`s and interprets no markup. A fuzz test
feeds arbitrary bytes to `display()` and asserts that the output contains no ESC
or C0/C1 code point.

### 8. Session behaviour

- The token and password buffers live in the client library (`Zeroizing`) and are
  never printed.
- The status bar shows the idle countdown and step-up validity. The client locks
  itself at the server idle timeout minus 30 s.
- On `session_invalid` the TUI wipes its state and returns to Login with the
  message "Session ended", whatever the cause, so the error leaks nothing.
- On quit the TUI sends `Logout` (best effort) and then wipes.
- The device token (a throttle hint, not a credential, F20 §6) is stored at
  `device_token_path` with `0600`.

### 9. Accessibility and internationalisation

- English and Portuguese strings (`--lang`, or the locale).
- Colours supplement text and are never the only signal. `NO_COLOR` and
  `--monochrome` are honoured.
- Minimum 80×24. Narrower terminals show a "terminal too small" notice instead of
  garbling.

## Security considerations and threat model

| Threat | Mitigation |
|--------|------------|
| Terminal-escape injection from host-supplied strings (OSC 52 clipboard hijack, screen spoofing, hidden text) | `sanitize::display`, fuzzed; no markup rendering |
| Bidi or homoglyph spoofing of paths ("…/gpj.exe") | Bidi and zero-width characters neutralised; full path and hash in detail; hash-prefix filter |
| Shoulder-surfing or a leftover screen | Masked password, alternate screen, clear on lock and exit, idle lock |
| Session token theft from the process | Memory only, `Zeroizing`; F20 IP binding and short idle |
| Operator acts on stale data | Optimistic concurrency (`expected_row_version`), refresh after every mutation, timestamps shown |
| Mis-click approvals | Review page plus explicit `y`; warnings for wide scope; typed confirmation for revoke |
| A compromised approver session adds and approves a malicious binary alone (single-step add) | **Accepted risk (D4).** A fresh TOTP code per add, review page, the distinct `AppApprovedBySameActor` audit event, optional strict SoD policy on the server |
| Typed hash or path that does not match the real binary | Shown wrapped and monospace on the review page; the approval pins that exact hash and MIA re-hashes at every mint, so a wrong hash grants nothing |
| Running on a shared CMIS node | No privileges needed; no secrets on disk; per-person accounts (no shared logins, G-002) |
| Bypass through local DB access | The TUI has no DB code. Server-side, the database is reachable only by CMIS (OS permissions on `CMIS_RAFT_DIR`). |

## Testing strategy

- **Unit (headless):**
  - `App` update transitions for every key in every screen;
  - permission-based key enablement;
  - filter-panel validation;
  - dialog defaults (the auto-update preselection rule);
  - the review page content;
  - the idempotency key reused on step-up retry.
- **Rendering snapshots** (`TestBackend`) at 80×24 and 160×48, in EN and PT, for
  every screen and modal. Snapshots are checked in.
- **Sanitisation:** a unit table (ESC, OSC 52, CSI, bidi, zero-width, NUL) and a
  fuzz target.
- **Integration:** against an in-process CMIS (F19 and F20 test harness), drive
  login → list → approve → verify the audit event and generation bump; deny; edit
  with a concurrent edit (`ABORTED` path); revoke; idle lock; viewer cannot approve
  (server returns `PERMISSION_DENIED` even if the client is forced).
- **Add application:** drive the dialog with a valid step-up window and check that the
  TOTP prompt still appears; in the default mode the request is `APPROVED`, the
  approval `ACTIVE`, and exactly one `AppApprovedBySameActor` event exists; with
  `CMIS_ADMIN_STRICT_SOD=true` the request stays `PENDING`; a wrong code changes
  nothing; a viewer cannot open the dialog and the server refuses a forced call.
- **Negative:** connect with a wrong pin (refused before any credential is sent);
  missing pin (refuses to start); the server forcing `step_up_required` twice (no
  loop); oversize server strings (truncated, no panic).
- **Secret hygiene:** a process-memory test is not portable. Instead, assert that
  no type holding a password or token implements `Debug` or `Display` (compile-
  time `static_assertions`) and that the log-capture scan from F20 passes.

## Packaging and rollout

- Shipped from F20 Phase 1 onwards; installed with CMIS packages and available as
  a standalone tarball or zip (Linux, macOS, Windows).
- Release notes and the change document list the new binary. The operations guide
  gains an "Administering approvals" section.

## Acceptance criteria

- [ ] `ferrogate-tui` refuses to run without an SPKI pin and talks only to the
      admin listener over hybrid-PQC TLS.
- [ ] Login works with password + TOTP, including forced password change; a failure
      shows only a generic message or a throttle countdown. The TUI offers no FIDO2
      and no enrollment.
- [ ] Add application by known hash and path works as a single step by default with
      a fresh TOTP prompt, queues a request under the strict policy, and shows the
      matching notice (tests above).
- [ ] Every screen in §3 is implemented. Search and filters map to server-side
      fields with pagination.
- [ ] Approve, deny, edit, revoke and freeze flows work end to end, require the
      review step, prompt for step-up when needed, and are audited server-side.
- [ ] Revoke requires typed confirmation. Wide-scope options require an extra
      confirmation.
- [ ] Untrusted strings never emit terminal control sequences (fuzzed).
- [ ] Idle lock clears the screen and wipes the token. Nothing secret is written
      to disk or logs.
- [ ] `#![forbid(unsafe_code)]`, `make lint` clean, snapshot and integration tests
      in `make test`.

## Risks

- **TOTP only in the TUI** (AAL2, no AAL3 from a remote shell). Mitigation: do
  approvals from the tray admin client with FIDO2, which the server policy
  `CMIS_ADMIN_TRAY_FIDO2_GROUPS` can require for approvers; use hardware mTLS
  (F20 §2); or ask the ESI to accept AAL2 for TUI sessions (overview OQ1).
- **Single-step add from a terminal** relies on a typed hash. Mitigation: review
  page, fresh TOTP, audit event, MIA re-hash at every mint.
- **Terminal emulator differences** in Unicode width. Mitigation: `unicode-width`,
  conservative box drawing, an ASCII fallback (`--ascii`).

## Open questions

- **OQ-F21-1** — Should the TUI also expose platform-operator functions (legacy
  allowlists, SVID revocation, epoch bump), or keep them CLI-only (proposed)?
- **OQ-F21-2** — Should account administration in the TUI be limited to the CMIS
  host's loopback (an extra network control), or allowed from workstations too?
