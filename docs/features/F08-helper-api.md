# F08 — Local Helper API

## Summary

The MIA exposes a local IPC channel (Unix Domain Socket on Linux, Named Pipe
on Windows) over which vetted applications request short-lived,
audience-bound, DPoP-bound tokens. Caller identity is established from
kernel-attested sources (SO_PEERCRED + IMA on Linux; pipe peer pid + Code
Integrity on Windows).

## Scope

In:

- UDS at `/run/ferrogate/mia.sock`, mode `0660`, dedicated group.
- Named pipe on Windows with ACL gating.
- CBOR request/response framing.
- Caller authentication: `(uid, bin_sha384)` cross-checked with IMA runtime
  measurement on Linux.
- Signed allowlist file refreshed from CMIS at enrollment.
- Audit events: `LocalGrant`, `LocalDenied`.

Out:

- Cross-host helper invocation (always local).
- Token minting without a valid host SVID (refused).

## Components touched

- `crates/mia` (helper module: transport-agnostic pipeline + UDS and Named
  Pipe listeners).
- `crates/ferro-winauth` (Windows FFI boundary: client PID, image
  attestation, ACL — keeps `mia` `#![forbid(unsafe_code)]`).

## Dependencies

- F04 (host SVID), F09 (token format).

## Design notes

See [../helper-api.md](../helper-api.md).

Implemented in `crates/mia/src/helper/`:

- `proto` — CBOR request/response types and length-delimited framing
  (4-byte big-endian length, bounded by `MAX_FRAME_LEN`).
- `auth` — the `CallerAuth` trait plus the pure `cross_check_ima` parser; the
  Linux `ImaCallerAuth` (`SO_PEERCRED` + IMA) is compiled only on Linux while
  the trait, identity type, and cross-check logic are portable and unit-tested
  on any host.
- `allowlist` — a fail-closed, signed loader. The on-disk artefact is a CBOR
  `SignedAllowlist` (a canonical-CBOR `AllowlistDoc` body plus a detached
  composite signature over those exact bytes under `ferrogate-allowlist-v1`),
  rather than the TOML the prose sketch suggests: CBOR gives an unambiguous
  byte string to sign and matches the rest of FerroGate's signed-artefact
  idiom. Freshness (`not_after` and a max-age bound on `issued_at`) is enforced
  on load.
- `token` — the DPoP-bound child-token minter (feature F09): a compact JWS
  signed with the host composite SVID key under `ferrogate-child-token-v1`,
  TTL clamped to ≤ 600 s, `jti` a fresh 128-bit value.
- `server` — a transport-agnostic request pipeline (`serve_connection` over any
  `AsyncRead + AsyncWrite`) plus two listeners: a Unix Domain Socket (`unix`)
  and a Windows Named Pipe (`windows`). The cheap credential step
  (`SO_PEERCRED` / `GetNamedPipeClientProcessId`) runs on the async side; the
  authenticator's blocking work (IMA log + `/proc/<pid>/exe` on Linux; image
  hashing + Authenticode on Windows) runs on the blocking pool, so it never
  stalls a runtime worker. Each connection holds a `Semaphore` permit under a
  read deadline, so a slow client is reaped rather than starving others.

#### Windows transport

The Windows variant listens on `\\.\pipe\ferrogate-mia`, optionally with a DACL
restricting access to a named local group (`windows_group`, e.g.
`FerroGateClients`) plus SYSTEM and Administrators. Because `mia` is
`#![forbid(unsafe_code)]`, **all** Windows FFI lives in the separate
`ferro-winauth` crate (which has no dependency on `mia`, so there is no cycle):

- `client_process_id` — `GetNamedPipeClientProcessId` on the connected pipe
  instance;
- `process_image_path` / `process_user_rid` — `QueryFullProcessImageNameW` and
  the token user SID's RID (the Windows analogue of a Unix uid in the
  allowlist);
- `verify_authenticode` — `WinVerifyTrust`, the Code-Integrity analogue of the
  IMA cross-check;
- `create_server_pipe` — the named-pipe instance with the optional group DACL.

`mia`'s `WindowsCallerAuth` composes these (hashing the image with `sha2` on the
safe side) into a `CallerIdentity`. The allowlist, CBOR protocol, token minter,
audit pipeline, and concurrency model are shared verbatim with the Unix path.

Because Windows tests cannot run in this environment, the Windows code is
compile- and clippy-checked by cross-building to `x86_64-pc-windows-gnu`
(`scripts/win-cross.sh`); the transport-agnostic pipeline is exercised by the
Unix integration tests.

### Daemon bring-up

The `mia` binary starts the helper API when `FERROGATE_HELPER_SOCKET` is set
(Linux only — it needs `SO_PEERCRED` + IMA). It loads and verifies the signed
allowlist from `FERROGATE_ALLOWLIST` (key in `FERROGATE_ALLOWLIST_KEY`), binds
the socket with `FERROGATE_HELPER_SOCKET_MODE` (default `660`), drains audit
events to the log, and serves until `SIGINT`/`SIGTERM`. Until the attestation
loop (F04) is wired into the daemon to supply the host SVID composite key, the
server runs with **no minter**: it authenticates and authorizes callers but
refuses to mint (`no_host_svid`) — a fail-safe, deployable surface for
verifying socket permissions, caller attestation, and the allowlist in
production ahead of minting.

## Acceptance criteria

- [x] Server listens with correct UDS permissions; verified by `stat` in a
      test (`socket_is_created_with_0660_permissions`).
- [x] Spoofed `/proc/<pid>/exe` (symlink swap) is detected via IMA
      cross-check and rejected (`auth::tests::swapped_binary_is_a_mismatch`,
      `spoofed_exe_ima_mismatch_is_rejected`).
- [x] Caller whose `(uid, bin_sha)` is absent from the allowlist gets
      `permission_denied` (`caller_absent_from_allowlist_is_denied`).
- [x] Caller in allowlist receives a properly-formed child token
      (`allowlisted_caller_receives_well_formed_child_token`).
- [x] Allowlist signature verification fails closed (`allowlist::tests`:
      wrong key, tampered body, garbage, expired, too-old; plus
      `no_allowlist_fails_closed`).
- [x] Every request produces exactly one audit event (asserted across the
      grant/deny integration tests).
- [x] Concurrent clients are isolated; one slow client cannot starve others
      (`slow_client_does_not_starve_a_good_client`).

## Risks

- **IMA disabled.** A host without IMA cannot prove caller binary integrity.
  Mitigation: MIA refuses to start unless IMA is enforced.
- **Allowlist staleness.** Mitigation: max age enforced; refresh on a timer.
