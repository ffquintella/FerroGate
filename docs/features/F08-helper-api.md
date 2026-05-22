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

- `crates/mia` (helper module).

## Dependencies

- F04 (host SVID), F09 (token format).

## Design notes

See [../helper-api.md](../helper-api.md).

## Acceptance criteria

- [ ] Server listens with correct UDS permissions; verified by `stat` in a
      test.
- [ ] Spoofed `/proc/<pid>/exe` (symlink swap) is detected via IMA
      cross-check and rejected.
- [ ] Caller whose `(uid, bin_sha)` is absent from the allowlist gets
      `permission_denied`.
- [ ] Caller in allowlist receives a properly-formed child token.
- [ ] Allowlist signature verification fails closed.
- [ ] Every request produces exactly one audit event.
- [ ] Concurrent clients are isolated; one slow client cannot starve others.

## Risks

- **IMA disabled.** A host without IMA cannot prove caller binary integrity.
  Mitigation: MIA refuses to start unless IMA is enforced.
- **Allowlist staleness.** Mitigation: max age enforced; refresh on a timer.
