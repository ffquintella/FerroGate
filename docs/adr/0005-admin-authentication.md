# ADR-0005 — Administrator authentication and authorization for CMIS

- **Status:** Proposed. Local accounts were **decided by the product owner** on
  2026-10-14 (D2 in the [Decisions log](../app-approval-and-admin.md#decisions-log)).
  The FGV G-002 guide (§6.2) and the norm prefer AD/IdP federation and rank local
  authentication third, so this deviation **must be recorded with the ESI**, whose
  approval is still required.
- **Date:** 2026-10-14
- **Deciders:** FerroGate core team, product owner (D2, D3, D4), ESI (security premises,
  acknowledgement of the accepted risks), DPO (personal data)
- **Scope:** How people prove who they are to CMIS and what they may then do. This
  covers every admin RPC (new and legacy), the server TUI ([F21](../features/F21-admin-tui.md)),
  the tray admin client ([F22](../features/F22-tray-admin-client.md)) and the
  `ferrogate` CLI. Detailed design: [F20](../features/F20-admin-authentication.md).

## Context

- CMIS serves one gRPC listener (`:8443`). TLS is server-authenticated only:
  `ServerConfig::…with_no_client_auth()` in `crates/ferro-crypto/src/transport.rs`.
- The admin RPCs are `SetAllowlist`, `DeleteAllowlist`, `ListAllowlists`,
  `ListProposals`, `DeleteProposal`, `RevokeSvid`, `RevokeHost`, `BumpEpoch` and
  `ListSvids`. They are documented as "authenticated out of band", but
  `crates/cmis/src/service.rs` performs **no** caller check in any of them.
  `docs/networking.md` describes them as "gated at the TLS layer (operator-only TLS
  credentials)", but no client credential is requested. Every MIA must reach
  `:8443`, so **any party that completes a TLS handshake can rewrite any host's
  allowlist, revoke any host, or bump the policy epoch.** This is a critical
  pre-existing vulnerability (see the overview's findings table).
- With `CMIS_TLS_CERT`/`CMIS_TLS_KEY` unset, the same surface is served in
  **plaintext**.
- The new features add human approval workflows (F19) that require individual,
  attributable administrator identities, under the FGV NRM rules: a single
  authentication point, MFA for sensitive operations, progressive lockout, RBAC by
  groups, and auditing of logins and account changes.
- The user asked for **username + password** administrator access in both the
  tray admin client and the server.

## Decision

1. **Local administrator accounts in CMIS**, stored in the Raft-replicated hiqlite
   store (decision D2). They authenticate with a password **plus a mandatory second
   factor**, and **both methods are supported and ship together** (decision D3):
   - **TOTP** (RFC 6238, AAL2) works in every client, including the server TUI over
     SSH.
   - **FIDO2/WebAuthn** (security keys through CTAP2, and platform authenticators)
     is the phishing-resistant option (AAL3 for device-bound credentials). It is
     supported through the **tray admin client** (F22), because that client has
     local access to the authenticator. The TUI and the CLI offer TOTP only.
   - An account may hold **both** factors (and several keys). Both are **enrolled
     from the tray admin client**. The only exception is the first account, which
     the CLI bootstraps on the CMIS node with TOTP.
   - **Policy option.** `CMIS_ADMIN_TRAY_FIDO2_GROUPS` lists groups whose members
     must use FIDO2 when they sign in from the tray. Production can set it to
     `ferrogate-approvers`. TUI sessions keep using TOTP.
   - Federation with the corporate directory (OIDC/AD) is a **future item and a
     non-goal** of this ADR. `AdminAuthz` consumes only an authenticated `admin_id`
     and its groups, so federation could be added later without changing the
     authorization layer.
2. **Passwords** are hashed with **Argon2id** (RFC 9106 second recommended
   profile: m = 64 MiB, t = 3, p = 4, 16-byte salt, 32-byte output, PHC string
   with parameters stored per hash, rehash on login when parameters are raised).
   An optional server-side pepper is applied with HMAC-SHA-256 before hashing.
   Minimum length is 24 characters for these administrative credentials (FGV
   §2.1), with no silent truncation. Passwords rotate every 6 months, can never be
   reused, and are checked against a blocklist.
3. **Login is two calls and never acts as a password oracle.** `BeginLogin`
   returns a challenge. `Login` carries the password **and** the second factor
   together and fails with one generic error. Unknown users run a dummy Argon2
   verification so that response timing is the same.
4. **Progressive lockout exactly as NRM §5.3.5 states:** after 3 failures, 1 min;
   2 more, 15 min; 2 more, 1 h. **IP is the primary key.** A client instance id
   (the analogue of the norm's cookie) only separates people behind one IP.
   Account and IP-aggregate counters bound distributed and rotation attacks. The
   lock is checked before any password verification.
5. **Sessions** use an opaque 256-bit token from a CSPRNG (`fgas_` prefix). Only its
   SHA-256 is stored. A session is bound to the login source IP, has a 15 min idle
   and 12 h absolute lifetime, and is revoked on the server at logout, password
   change, credential reset or account disable. Roles are **read from the database
   on every call** and never embedded in the token. Sensitive operations need a
   recent second-factor verification (**step-up**, default window 5 min). Account
   administration, password change, adding or removing a second factor and
   **direct application registration** (decision 7) need a per-operation second
   factor.
6. **Authorization** is RBAC through **groups only**; permissions are never assigned
   to a user directly. A permission is *function × operation*. One component,
   `AdminAuthz`, makes every decision. A tower layer in front of the admin service
   maps each gRPC method to its required permission from **one table** and denies
   any method that is not in the table. Handlers call the same component for
   object-level and separation-of-duties checks.
7. **Single-step direct add is the default; strict separation of duties is an
   optional policy** (decision D4). An administrator with `app.direct_register` and
   `app_request.approve` registers and approves an application in one step. Each
   such add needs a fresh second factor and emits the distinct audit event
   `AppApprovedBySameActor`, which flags that requester and approver were the same
   person. This is an **accepted risk decided by the product owner**, to be
   acknowledged by the ESI. The server setting `CMIS_ADMIN_STRICT_SOD=true`
   (default off) turns on strict separation: nobody approves or denies their own
   request, direct add only queues a `PENDING` request, and the account-admin and
   approver groups are mutually exclusive. Two rules hold in both modes: nobody
   changes their own groups, and the last account administrator cannot be removed.
8. **Transport.** Admin RPCs are served on a **separate admin listener**
   (`CMIS_ADMIN_LISTEN`, default `127.0.0.1:8444`). That listener uses hybrid-PQC
   TLS 1.3 only (`X25519MLKEM768`, same provider as F01), clients pin its SPKI, and
   client certificates (mTLS) are optional as an extra factor. **No plaintext
   mode:** without TLS material the admin listener does not start, and the legacy
   admin RPCs on `:8443` answer `FAILED_PRECONDITION`. The listener must not be
   reachable from the internet; administrators reach it through VPN or the
   management network.
9. **Legacy admin RPCs on `:8443`** require the same session token from the first
   release that ships this ADR. There is no unauthenticated compatibility mode,
   because the gap is critical. Serving them on `:8443` can be switched off
   entirely once operators have migrated.
10. **Audit.** Every authentication event and every admin mutation appends one
    `ferro-audit` event. Events reference the administrator by an opaque
    `admin_id` (UUIDv7) and the source IP by a keyed HMAC, so the Merkle log stays
    free of personal data (F07 invariant). Clear-text usernames and IPs live only
    in the access-controlled hiqlite tables, under a retention period agreed with
    the DPO.
11. **Bootstrap and recovery.** The first account is created by redeeming a
    one-time token that CMIS writes to a root-only file on first start. A break-glass
    recovery flag issues a new token the same way, loudly audited. **Nobody,
    bootstrap included, ever chooses a password for someone else.** Every account
    activates through a single-use enrollment token, delivered out of band with
    identity verified over a second channel (FGV "atendimento" rule), and the
    person sets their own password and second factor.

## Consequences

**Positive**

- Closes the critical unauthenticated-admin gap with one decision point.
- Gives individual, non-repudiable attribution for every approval, as F19 needs.
- Works without a dependency on a corporate IdP. CMIS is identity infrastructure
  and must stay administrable when the IdP is down or when the IdP itself depends
  on FerroGate SVIDs.
- The Merkle audit log stays free of personal data.

**Negative / risks**

- **Non-conformance until resolved with the ESI:** (a) local authentication instead
  of AD federation, decided by the product owner (D2) and to be recorded with the
  ESI; (b) TOTP is AAL2, while G-002 asks for AAL3 for administrative functions. The
  TUI runs over SSH and cannot reach a FIDO2 key on the administrator's laptop.
  FIDO2 in the tray and the policy option that requires it for approvers narrow the
  gap, but TUI sessions stay at AAL2 (overview OQ1). (c) The audit trail is
  cryptographically tamper-evident (Merkle + WORM files), whereas the norm describes
  INSERT-only grants in a separate database instance. These items are listed as
  gates in the overview.
- **Accepted risk (D4):** with single-step direct add as the default, one
  compromised approver account and its second factor can authorize a binary alone.
  Mitigations: a fresh second factor per add, the `AppApprovedBySameActor` event,
  expiry caps, fast revocation, and the optional strict policy. The ESI must
  acknowledge it.
- Breaking change for operators: the old `ferrogate` CLI can no longer call admin
  RPCs. The release becomes 0.29.0 and needs a change document.
- Non-interactive automation, such as configuration-management calls to
  `ferrogate allowlist`, loses access until a service-principal design exists
  (overview OQ4).

## Alternatives considered

- **OIDC federation with the corporate IdP (Entra ID / ADFS).** Preferred by G-002
  §6.2, **not chosen** (D2): a future item and a non-goal here. It would need the
  Device Authorization Grant (RFC 8628) for the TUI and Authorization Code + PKCE on
  a loopback redirect for the tray. It adds an availability dependency and does not
  work on air-gapped CMIS deployments.
- **TOTP first, FIDO2 later.** Rejected (D3). Both factors ship in the admin-auth
  phase, so the phishing-resistant option exists from the first rollout.
- **Strict separation of duties as the default.** Not chosen (D4). It stays as the
  optional policy `CMIS_ADMIN_STRICT_SOD`.
- **mTLS client certificates as the only factor.** Strong, and with a hardware
  token it reaches AAL3. Rejected as the *sole* mechanism because it needs a human
  PKI (issuance, revocation, smart-card logistics). Kept as an optional additional
  factor (`CMIS_ADMIN_CLIENT_CA`).
- **Self-contained JWT sessions.** Rejected. Revocation would lag until expiry,
  roles would be embedded in the token, and G-002 §6.1 warns against both.
- **Rely on SSH access to the CMIS host.** Rejected. It gives no per-person
  attribution inside CMIS, does not cover the remote tray client, and makes OS
  access equal to approval authority.
- **Reuse SPIFFE SVIDs for administrators.** Rejected. SVIDs identify machines,
  not people.
- **A tonic `Interceptor`.** Rejected because interceptors are synchronous and
  session checks need an async database read. A tower layer gives the same single
  enforcement point.
