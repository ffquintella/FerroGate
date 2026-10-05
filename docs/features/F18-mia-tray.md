# F18 — MIA Tray Companion

## Summary

`mia-tray` is a small, unprivileged desktop companion that lives in the system
tray (macOS menu bar, Windows notification area, Linux StatusNotifierItem). It
answers one question at a glance — *is this machine's identity agent healthy?*
— and, when it is not, walks the person at the keyboard through fixing it:
first-time configuration, guided recovery from the known failure states, and a
filtered view of the agent's recent logs.

Today all of that requires a terminal: `mia setup` needs a TTY, `mia test`
prints to stdout, and the logs sit in a root-owned file or the journal. That is
fine on servers and a real obstacle on the macOS and Windows workstations MIA
now supports. The tray is a *front end* for capabilities `mia` already has; it
adds no new trust, holds no key material, and never mints a token.

## Scope

In:

- **Status indicator.** A tray icon whose colour and badge reflect the daemon's
  state (table in *Design notes*), with a menu showing the per-environment
  detail: SVID validity and time to renewal, CMIS node in use, CRL freshness,
  allowlist state, attestation backend, X.509-SVID store backend.
- **Desktop notifications** on state transitions that need a human (healthy →
  error, SVID about to expire without renewal, CRL stale), rate-limited and
  de-duplicated.
- **Read-only status channel** in the daemon (`mia` side): a new
  `StatusReq`/`StatusResp` exchange on a dedicated status endpoint, plus
  `mia status [--json]` on the CLI for scripts and for the tray's fallback.
- **Graphical setup wizard.** The same fields, validation and help text as
  `mia setup` (CMIS endpoint or SRV, SPKI pins, helper socket/pipe, allowlist,
  `allowlist.fetch` / `allowlist.propose`, attestation backend, log level,
  environment), pre-filled from the current file. The result is applied by
  `mia` itself through a new non-interactive `mia setup --apply <file>` mode,
  run with OS elevation when the target is the system path.
- **Guided recovery.** For every recognised failure state, a short explanation
  and one-click actions that wrap existing commands: run the self-test
  (`mia test --json`), restart the service, resync the allowlist
  (`mia resync-allowlist --reload`), refresh the machine key
  (`mia refresh-key`), re-fetch the enrollment key, copy the machine
  identifiers an operator needs to enrol the host (`mia machine-id`), and open
  the matching runbook.
- **Log viewer.** A window that tails the daemon's recent log records, with
  level filter (error / warn / info / debug), environment filter, text search,
  pause/follow, and "copy diagnostics bundle" (status + self-test + the last
  N redacted records) for support tickets. Plus "open full log", which hands
  off to the platform tool (Console.app, Event Viewer / the log file,
  `journalctl -u mia`).
- **Packaging:** shipped beside `mia` in `make pkg-deb` (XDG autostart and an
  immediately-started user service), `make pkg-macos` (login item), and
  `make pkg-win` (Startup entry). RPM keeps a separate opt-in tray package for
  headless server distributions.

Out:

- **Any privileged long-running component.** The tray never runs as root /
  LocalSystem and installs no privileged helper (no `SMJobBless`, no setuid,
  no Windows service). Elevated work is a one-shot `mia` invocation behind the
  OS consent prompt.
- **Token minting, credential display or export.** The tray does not call the
  helper API's `HelperReq`, does not show or copy SVIDs, child tokens, keys or
  sealed-store contents.
- **Operator workflows on CMIS** (approving allowlist proposals, enrolling EK
  hashes, revocation). Those stay in `ferrogate` / `fleet-manifest`; the tray
  only hands the user the identifiers to send to an operator.
- **Remote / fleet monitoring.** One tray shows one machine.
- Editing arbitrary config keys outside what `mia setup` covers.
- Localisation beyond English and Portuguese in the first cut.

## Components touched

- `crates/mia-tray` (new binary crate) — tray icon and menu, wizard, recovery
  panel, log viewer. `#![forbid(unsafe_code)]`; tray/menu via `tray-icon` +
  `muda`, windows via `eframe`/`egui` (native rendering, **no embedded web
  view**, so there is no HTML/JS injection surface for log text or config
  values).
- `crates/mia` —
  - `status` module: builds the `StatusSnapshot` from daemon state; serves it
    on the status endpoint.
  - `logbuf` module: a `tracing` layer feeding a bounded, redacting in-memory
    ring buffer served through the status endpoint.
  - `setup`: `--apply <file>` (non-interactive, validate-then-atomic-write)
    and `--check <file>` (validate only), sharing the wizard's validators.
  - `selftest`: `--json` output.
  - `main`: `mia status [--json] [-e <env>]` subcommand.
- `crates/mia/dist` — status-endpoint defaults in `mia.toml`, systemd
  `RuntimeDirectory` unchanged; new `mia-tray.desktop`, macOS login-item plist,
  WiX Startup shortcut.
- `Makefile` — `pkg-*` targets include `mia-tray`.
- `docs/mia.md`, `docs/helper-api.md` — status endpoint and new CLI flags.

## Dependencies

- F08 (helper API: transport and peer-credential primitives reused for the
  status endpoint).
- F11 (CRL freshness is part of the status), F13 (enrollment identifiers),
  F16/F17 (attestation tier and X.509-SVID store backend shown in status).

## Design notes

### Architecture

```
 ┌──────────── user session (unprivileged) ────────────┐
 │  mia-tray                                           │
 │   ├─ status poller ──── StatusReq / LogTailReq ─────┼──▶ status endpoint ─┐
 │   ├─ wizard ─────────── writes draft TOML (0600) ───┼─┐                  │
 │   └─ recovery actions ─ spawn `mia …` ──────────────┼─┤                  │
 └─────────────────────────────────────────────────────┘ │                  │
                         OS consent prompt (if system) ▼                  ▼
                         `mia setup --apply` / service ctl          mia daemon
                         (one-shot, elevated)                       (unchanged trust)
```

The tray is a thin client. Everything that decides — config validation,
what counts as healthy, how a resync works — stays in `mia`, so there is one
implementation and the CLI and the tray can never disagree.

### Status endpoint

A **separate** endpoint from the helper socket, so status reads never touch
the token-minting path or its allowlist:

| OS | endpoint | access |
|----|----------|--------|
| Linux | `/run/ferrogate/mia-status.sock` | `0660`, group `ferrogate-status` |
| macOS | `/var/run/ferrogate/mia-status.sock` | `0660`, group `ferrogate-status` |
| Windows | `\\.\pipe\ferrogate-mia-status` | DACL: `FerroGateStatus` group + Administrators |

Installers create the group and add the installing (console) user. Same CBOR
framing and `MAX_FRAME_LEN` as F08. Requests:

- `StatusReq { environment: Option<String> }` → `StatusResp(Vec<StatusSnapshot>)`
- `LogTailReq { since_seq: u64, min_level: Level, max: u16 }` →
  `LogTailResp { records, next_seq, dropped }`

Both are **read-only and idempotent**; there is no write request on this
endpoint. Peer credentials are recorded for audit/rate-limit purposes but no
allowlist check applies, because the payload is non-sensitive by construction
(next section). Each connection is rate-limited (default 10 req/s per uid).

`mia status` reads the same endpoint, so a headless host gets the same
information without the tray.

### What the status snapshot contains — and what it never contains

```rust
struct StatusSnapshot {
    environment:     Option<String>,
    state:           AgentState,          // table below
    since:           i64,                 // unix secs, entered this state
    svid:            Option<SvidSummary>, // spiffe id, not_after, renew_at
    attest_backend:  AttestBackend,       // tpm | host-key | virtual-tpm
    cmis_node:       Option<String>,      // host:port selected (SRV-aware)
    crl_age_secs:    Option<u32>,
    allowlist:       AllowlistState,      // missing | loaded{entries,not_after} | invalid
    x509_store:      Option<StoreBackend>,
    last_error:      Option<ErrorSummary>,// stable code + short message
    version:         String,
}
```

Never included: SVID or token bytes, signatures, private or public key
material, SPKI pins, `jti` values, caller PIDs/UIDs/binary hashes from the
helper audit stream, file contents of the allowlist. The type is defined in
its own module with a unit test that serialises a fully-populated snapshot and
asserts none of those fields exist, so adding one is a visible change.

### Agent states

| `AgentState` | Icon | Meaning | Offered recovery |
|---|---|---|---|
| `NotInstalled` | grey | tray cannot find `mia` | link to installer docs |
| `NotRunning` | grey | status endpoint absent / service stopped | start service (elevated) |
| `NotConfigured` | grey ! | no CMIS source / no helper socket (daemon idles) | open wizard |
| `Attesting` | blue (animated) | startup or re-attestation in progress | — |
| `CmisUnreachable` | yellow | retrying (startup retries forever) | self-test, show SRV candidates, open networking doc |
| `NotEnrolled` | red | CMIS rejects host (`HostRejected` / `no_host_svid`) | copy machine identifiers for operator |
| `PinMismatch` | red | SPKI pin abort | open wizard at the pins step; runbook |
| `TpmUnavailable` | red | TPM missing or busy | self-test; explain backend options |
| `ImaDisabled` | red | Linux IMA required but off | runbook link (kernel cmdline) |
| `CrlStale` | yellow | CRL older than 5 min, minting refused | self-test (server vs agent fault) |
| `AllowlistMissing` / `AllowlistInvalid` | yellow | every caller denied | resync allowlist; explain `allowlist.fetch` / `propose` |
| `SvidExpiring` | yellow | past renew point, renewal failing | self-test, restart service |
| `Healthy` | green | SVID valid, CRL fresh, allowlist loaded | — |

When several environments are configured, the icon shows the **worst** state
and the menu lists each one. The daemon computes `state`; the tray only maps
it to presentation. A `last_error.code` the tray does not recognise renders as
a generic error with the message and a "run self-test" action, so older trays
keep working against newer daemons.

### Setup wizard and `mia setup --apply`

1. The wizard reads the current config through `mia setup --dump --json`
   (effective values, file path, which values come from env overrides — those
   are shown read-only, since writing the file would not change them).
2. Each field is validated locally *and* the whole draft is checked with
   `mia setup --check <draft>` before the user can confirm, so error text comes
   from `mia`.
3. The draft is written to a fresh `0600` file in the user's private temp dir.
4. For the per-user path the tray runs `mia setup --apply <draft> --user`
   directly. For the system path it runs the same command through the OS
   consent mechanism — `pkexec` (polkit action `br.fgv.ferrogate.mia.setup`
   with `auth_admin`), `osascript … with administrator privileges` on macOS,
   `ShellExecuteEx` `runas` (UAC) on Windows. The tray never sees, asks for or
   stores the admin password.
5. `--apply` re-validates everything (it treats the draft as untrusted input:
   size cap 64 KiB, strict TOML schema, unknown keys rejected), writes the
   target atomically (temp + `fsync` + rename) with the same mode/ownership
   `mia setup` uses, appends a local `ConfigChanged { path, by_uid, keys }`
   audit event (key names only, no values), deletes the draft, and optionally
   signals the daemon to reload (`--reload`).
6. The "fetch enrollment key from CMIS" step runs inside the elevated `mia`
   (`--apply --fetch-enrollment-key`), not in the tray, so the pinned TLS dial
   and the key write stay in one place.

### Recovery actions

Every action is a fixed `mia` invocation chosen from an enum in the tray —
never a command line composed from user or log text. Arguments that vary
(environment name) are validated with `config::validate_environment` before
use. Actions that change system state (service start/stop/restart, resync,
refresh-key, system config apply) go through the consent prompt; read-only
ones (`mia test --json`, `mia machine-id`, `mia status`) run as the user.
Results are shown inline and attached to the diagnostics bundle.

### Log viewer

- Source: the daemon's `logbuf` ring buffer (default 2 000 records / 1 MiB,
  whichever is hit first), streamed via `LogTailReq` with a monotonic `seq` so
  the viewer can follow without duplicates and report `dropped` gaps. This
  works identically on all three OSes and needs no read access to
  `/var/log/ferrogate`, `%ProgramData%\FerroGate\logs` or the journal.
- **Redaction happens in the daemon, before a record enters the buffer**: the
  layer keeps level, timestamp, target, environment and message, and drops or
  masks fields whose names or types mark them sensitive (`token`, `svid`,
  `key`, `secret`, `pin`, `jwk`, `dpop`, `authorization`, raw byte blobs);
  values are truncated to 512 bytes. A `debug`/`trace` record is only buffered
  when the daemon's own directive enables that level — the tray cannot raise
  it.
- Text is rendered as plain text by `egui` (no markup interpretation), with
  control characters escaped.
- "Open full log" launches the platform viewer; on Linux this is
  `journalctl -u mia` and may require the user to be in `systemd-journal`/`adm`
  — the tray says so rather than escalating.
- The diagnostics bundle is written only where the user chooses, is plain
  text, and contains only what the viewer already shows plus the status
  snapshot and self-test result.

### Security posture

- No new trust: the tray's binary is not allowlisted, not self-trusted, and
  cannot reach `HelperReq` successfully; compromising it yields the status a
  `ferrogate-status` member can already read.
- The status endpoint has a fixed, read-only request set and bounded responses;
  a fuzz target covers its decoder like the helper protocol's.
- Elevation is delegated to the OS, scoped to one `mia` invocation, and logged
  by the OS (polkit / Authorization Services / UAC) as well as by the
  `ConfigChanged` audit event.
- On Linux hosts with seccomp enforced, the status listener uses only syscalls
  already in the allowlist (it is the same UDS machinery as F08).
- **FGV compliance note.** Configuration change is a sensitive operation under
  NRM §5.3.1, which asks for MFA. Here the gate is the local OS administrator
  consent prompt; whether that satisfies the requirement for workstations — or
  whether system-path changes should additionally require an operator-issued
  approval from CMIS — is an **open point for ESI validation** before
  production rollout. The ESI pre-production security verification gate also
  applies.

## Acceptance criteria

- [x] `mia status --json` prints one `StatusSnapshot` per configured
      environment and exits non-zero unless all are `Healthy`.
- [ ] The status endpoint answers `StatusReq` and `LogTailReq` and rejects any
      other request; a peer outside `ferrogate-status` /
      `FerroGateStatus` cannot connect (OS-level test per platform).
- [x] Serialised `StatusSnapshot` and `LogRecord` contain no key, token, SVID,
      pin or `jti` material (`status_snapshot_has_no_secret_fields`,
      `logbuf_redacts_sensitive_fields`).
- [ ] Each `AgentState` in the table is reachable from the daemon's e2e
      harness and produces the documented icon and recovery actions in the
      tray's state-mapping unit tests.
- [ ] `mia setup --apply` rejects oversize, malformed and unknown-key drafts,
      writes atomically, preserves mode/ownership, emits `ConfigChanged`, and
      produces a file byte-identical to what the TTY wizard writes for the same
      answers.
- [ ] Wizard round-trip: load existing config → change one field → apply →
      reload shows the change; env-overridden fields are read-only.
- [ ] System-path apply and service actions go through `pkexec` / macOS
      admin prompt / UAC; cancelling the prompt leaves config and service
      untouched and is reported as "cancelled", not as an error.
- [x] Log viewer follows the ring buffer without duplicates across a daemon
      restart, reports dropped gaps, and filters by level/environment/text.
      (`logview::tests::follows_without_duplicates_and_reports_gaps`,
      `a_daemon_restart_resets_the_follow`,
      `filters_by_level_environment_and_text`.)
- [x] The tray degrades sensibly when the daemon is older (no status endpoint):
      falls back to `mia status`, then to `NotRunning`.
      (`client::tests::fallback_chain_endpoint_then_cli_then_not_running`;
      also observed on macOS: no `mia` ⇒ `not_installed`, a `mia` without a
      running daemon ⇒ `not_running` via `mia status --json`.)
- [ ] `mia-tray` builds with `#![forbid(unsafe_code)]`, passes
      `make lint`, and ships in `pkg-macos`, `pkg-win` and the Linux package
      with autostart.

### Progress — phase 1 (daemon side)

Done in `crates/mia` and the new `crates/mia-status-proto` (wire types shared
with the future tray): the `status`, `status_server`, `status_cli` and `logbuf`
modules, `mia status`, `mia test --json`, `mia setup --check/--apply/--dump`,
the `[status]` config section and the `ConfigChanged` audit event. Partially
met criteria, still open:

- *Status endpoint*: answering `StatusReq`/`LogTailReq` and refusing anything
  else (including `HelperReq`) is tested over a real socket
  (`tests/status_endpoint.rs`); the per-platform OS-level test that a peer
  outside the status group cannot connect needs root and real groups and is
  not automated yet.
- *Agent states*: every daemon-reportable state is derived and unit-tested
  (`status::tests::every_daemon_reachable_state_is_derived`); driving each
  from the e2e harness and the tray's mapping tests remain.
- *`--apply`*: oversize / malformed / unknown-key rejection, atomic write,
  `0640`, `ConfigChanged` and byte-identity with the TTY wizard are tested;
  copying a *different* owner onto the new file only happens as root and has
  no automated test yet.
- `ImaDisabled` / `NotRunning` are client-side (the daemon refuses to start
  without IMA, so it cannot report it): `mia status` synthesises them when the
  endpoint is absent.
- `ConfigChanged` goes to a local append-only journal beside the config file
  (`config-audit.jsonl`); forwarding it to CMIS is a follow-up.

### Progress — phase 2 (tray)

`crates/mia-tray` (binary `mia-tray`, `#![forbid(unsafe_code)]`) implements the
tray side; user documentation is [docs/mia-tray.md](../mia-tray.md). The
environment-name rule moved into `mia_status_proto::validate_environment`, which
`mia`'s `config::validate_environment` now wraps (same messages), so the tray
and `mia` apply one implementation.

- **Build hygiene.** The GUI (`tray-icon`/`muda`, `eframe`/`egui`,
  `notify-rust`, `arboard`, `rfd`; GTK 3 on Linux) is behind the off-by-default
  `gui` feature and the binary has `required-features = ["gui"]`. `make lint` /
  `make test` therefore build, lint and test the headless core everywhere;
  `make tray` / `make lint-tray` / `make test-tray` / `make deny-tray` cover the
  GUI, and `.github/workflows/mia-tray.yml` runs them on Linux, macOS and
  Windows. `deny.toml` gained crate-scoped licence exceptions for egui's fonts
  (OFL-1.1, Ubuntu Font Licence) and the Windows clipboard backend (BSL-1.0);
  its `[graph]` checks default features only, hence `make deny-tray`.
- **Architecture.** Headless modules — `client` (endpoint + fallback chain),
  `model` (state → icon/menu/recoveries), `alerts` (dedup + rate limit),
  `actions` (closed command set, per-OS elevation wrappers, cancel
  classification), `wizard` (dump parsing, validation, TOML rendering, private
  `0600` drafts), `logview`, `bundle`, `selftest`, `poll`, `icon`, `i18n`
  (English/Portuguese table), `text` (escaping), `locate`, `process` (bounded
  children) — carry all the logic and the unit tests; `gui` only draws and
  dispatches. Windows run as separate processes (`mia-tray --window <kind>`,
  a closed set) started by the tray process.
- **Partially met, still open:** the e2e half of the agent-state criterion (the
  tray half is `model::tests::every_agent_state_maps_to_the_documented_icon_and_recoveries`);
  the wizard round-trip and the consent-prompt criteria are implemented and
  their pieces unit-tested (dump parsing / env-override handling, draft
  rendering and staging, `--check`/`--apply` output parsing, the
  `pkexec`/`osascript`/UAC command construction, cancel ⇒ `cancelled`, the
  macOS script compiles under `osacompile`) but have no automated end-to-end
  run against a real prompt; packaging is wired into `pkg-macos` (LaunchAgent),
  `pkg-win` (MSI Startup entry; stripped automatically if the tray does not
  build), the combined Linux `ferrogate-mia` deb, and the opt-in tray RPM
  (XDG autostart, polkit policy, `ferrogate-status` group). The status-group
  creation is in the macOS postinstall, the Chocolatey install script (wixl
  cannot run commands), and the Linux package postinst.
- **Not done:** a minimised-window fallback when Linux has no
  StatusNotifierItem host; a `.app` bundle for macOS (notifications from an
  unbundled binary may be attributed to another application).

## Risks

- **Linux tray fragmentation.** GNOME has no tray without an extension.
  Mitigation: StatusNotifierItem via `tray-icon`; if no host is present, start
  minimised to a normal window and still send notifications; `mia status`
  remains the universal path.
- **Status leaks more than intended over time.** New fields are added casually.
  Mitigation: the no-secret-fields test, and the snapshot lives in its own
  module that requires review on change.
- **Wizard and TTY wizard drift.** Two front ends for one config.
  Mitigation: both call the same validators and writer; the byte-identical
  acceptance test.
- **Elevation prompt fatigue / social engineering.** A user who clicks "yes"
  to every prompt. Mitigation: the prompt names the exact `mia` action;
  elevated actions are a closed set; `ConfigChanged` is audited and synced to
  CMIS.
- **Ring buffer memory on Linux under `mlockall`.** Mitigation: hard byte cap
  (1 MiB default, configurable down to 0 to disable).
- **Unsigned Windows build.** An unsigned `mia-tray.exe` triggers SmartScreen.
  Mitigation: signed with the same `WIN_SIGN_PFX` as `mia.exe`.
