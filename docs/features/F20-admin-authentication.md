# F20 — Administrator authentication and authorization

> Decision record: [ADR-0005](../adr/0005-admin-authentication.md). Consumers:
> [F19](F19-app-registration-approval.md) (app approval RPCs), [F21](F21-admin-tui.md)
> (server TUI), [F22](F22-tray-admin-client.md) (tray admin client), and the
> `ferrogate` CLI. Overview: [app-approval-and-admin.md](../app-approval-and-admin.md).
> Decisions applied here (local accounts, TOTP plus FIDO2, optional strict
> separation of duties): [Decisions log](../app-approval-and-admin.md#decisions-log).

## Summary

CMIS gains individual administrator accounts, stored locally in CMIS (decided by the
product owner, D2). People sign in with a username, a password **and a mandatory
second factor**: TOTP, FIDO2, or both. Every admin RPC goes through one
authentication and authorization component (`AdminAuthz`) with role-based
permissions assigned through groups. Admin traffic uses a dedicated listener with
hybrid-PQC TLS only, and every login, account change and admin action is recorded
in the ferro-audit Merkle log under a pseudonymous administrator id.

F20 also **closes a critical pre-existing gap**. The existing admin RPCs
(`SetAllowlist`, `DeleteAllowlist`, `ListAllowlists`, `ListProposals`,
`DeleteProposal`, `RevokeSvid`, `RevokeHost`, `BumpEpoch`, `ListSvids`) perform no
caller check. The CMIS TLS listener does not request client certificates
(`crates/ferro-crypto/src/transport.rs`, `with_no_client_auth()`), so anyone who
can reach `:8443` — every MIA host, for one — can call them. That part is
**Phase 0** and blocks F19, F21 and F22 (FGV NRM §5.3.7: an open critical flaw
blocks new functionality).

## Scope

### Goals (in)

- **Phase 0 (blocking):**
  - authenticate and authorize every legacy admin RPC;
  - never serve the admin surface without TLS;
  - authenticate `AppendAuditEvent` with the host proof from F19 §7.1;
  - make the `ferrogate` CLI log in.
- A dedicated admin listener (`ferrogate.admin.v1.Admin` service) over hybrid-PQC
  TLS 1.3 with SPKI pinning; mTLS optional.
- Local accounts:
  - Argon2id password hashing and an optional pepper;
  - an FGV-conformant password policy with 6-month rotation, no reuse and a
    blocklist;
  - a mandatory second factor with **two supported methods that ship together**:
    TOTP (every client, including the TUI over SSH) and FIDO2/WebAuthn (through the
    tray admin client, which has local access to the authenticator). An account
    may hold both;
  - enrollment of both factors from the tray admin client (the CLI only bootstraps
    the first account, with TOTP);
  - a policy option to require FIDO2 for chosen groups (production: `approver`)
    when they sign in from the tray, while TUI sessions use TOTP.
- Login throttling per NRM §5.3.5 (3 → 1 min, +2 → 15 min, +2 → 1 h), with IP as
  the primary control.
- Sessions:
  - opaque tokens, hashed at rest, bound to the source IP;
  - 15 min idle and 12 h absolute lifetime;
  - step-up for sensitive operations;
  - an active-sessions view and server-side revocation.
- RBAC through groups only; one method → permission table; deny by default.
- Single-step direct add of applications as the default (fresh second factor,
  distinct `AppApprovedBySameActor` audit event), and strict separation of duties as
  an optional server policy (default off).
- Bootstrap of the first administrator, enrollment and reset through single-use
  tokens, break-glass recovery.
- Audit events for every authentication and admin action; an LGPD inventory.

### Non-goals (out)

- Federation with the corporate directory (OIDC / AD). Local accounts were decided
  by the product owner (D2). The FGV norm prefers federation, so the deviation must
  be recorded with the ESI. Federation is a **future item**, not designed here.
- Non-interactive service principals for automation (overview OQ4).
- Self-service password recovery (by e-mail, security questions or similar). G-002
  forbids knowledge-based recovery. Resets are administrator-mediated, with
  identity checked over a second channel.
- Administrator access to raw database or audit tables (NRM §5.4.2 forbids
  direct-query shortcuts).
- Authorization of hosts (SVIDs, F04/F19) and of local helper callers (F08).

## Actors

| Actor | Group(s) | Notes |
|-------|----------|-------|
| Viewer | `ferrogate-viewers` | Read-only on requests, approvals and hosts |
| Approver | `ferrogate-approvers` | F19 decisions and direct registration (register and approve in one step) |
| Account administrator | `ferrogate-account-admins` | Manages accounts and groups; under the strict SoD policy (optional, default off) may **not** also be an approver |
| Platform operator | `ferrogate-platform-operators` | Legacy allowlist RPCs, SVID revocation, epoch bump, allowlist mode and import |
| Bootstrap / recovery operator | none (holds a one-time token) | Person with root on a CMIS node; redeems the bootstrap or recovery token |
| Attacker | — | Network attacker, credential stuffer, malicious host, insider (see threat model) |

## User stories

1. *As the first operator*, I redeem the bootstrap token that CMIS wrote to a
   root-only file, choose my username and password and enroll TOTP. From then on
   every admin action requires signing in.
2. *As an account administrator*, I create an account for a colleague with the
   right groups. CMIS gives me a single-use enrollment token to deliver over a
   second channel, and the colleague enrolls from the tray admin client: their own
   password, a TOTP secret, and optionally a FIDO2 security key.
3. *As an approver*, I sign in once in the morning. A sensitive action asks for my
   second factor again only if more than 5 minutes have passed since the last
   check.
4. *As any administrator*, I can see my active sessions and end them. Changing my
   password ends all my other sessions.
5. *As the ESI*, I can show that three wrong passwords block the source for one
   minute, that every single-step add needed a fresh second factor and is flagged by
   the `AppApprovedBySameActor` event, that with the strict policy on nobody approved
   their own request, and that every login and change is in the audit trail.
6. *As an approver on my workstation*, I enroll a FIDO2 security key in the tray
   admin client next to my TOTP secret. From then on I sign in to the tray by
   touching the key. Over SSH, in the TUI, I still use TOTP.

## Components touched

| Crate | Change |
|-------|--------|
| `crates/cmis` | `admin` module: `AdminAuthz`, the tower layer, the method → permission table, accounts, sessions, throttling, bootstrap and recovery, admin listener wiring (`CMIS_ADMIN_*` env). Legacy admin handlers read `AdminContext`. `transport.rs` exposes `remote_addr` (`Connected` / `TcpConnectInfo`). Plaintext mode refuses admin methods. |
| `crates/ferro-proto` | New `proto/admin.proto` (`ferrogate.admin.v1.Admin`). `AppendAuditRequest` gains `HostCallAuth auth = 2`. |
| `crates/ferro-raft` | Migrations for the admin tables (§3). |
| `crates/ferro-audit` | New `AuditEvent` variants (§10), all PII-free. |
| `crates/ferrogate-admin-client` (**new** library) | Shared client: pinned dial (`ferro-transport`), login/MFA/step-up flows, session handling (`Zeroizing`), password-policy pre-check and generator, typed wrappers for the Admin RPCs. Used by `ferrogate`, `ferrogate-tui` and `mia-tray-admin`. WebAuthn authenticator access (platform APIs, CTAP2 HID) plugs in through a trait implemented only in `mia-tray-admin` (F22); the TUI and CLI link none of it. |
| `crates/ferrogate-cli` | `ferrogate admin login|logout|whoami|sessions|passwd|bootstrap|accounts …` (TOTP only; factor enrollment is done in the tray admin client, F22, and `bootstrap` enrolls the first account's TOTP on the CMIS node); legacy commands send the session token. |
| `crates/mia` | The audit forwarder signs `AppendAuditEvent` with the host proof. |
| Docs | `networking.md` (admin listener, correcting "operator-only TLS credentials"), `operations.md`, `cmis.md`, `transport-tls.md`, credential-in-config record (FGV template) for the pepper and secrets key files. |

## Dependencies

- F01 (hybrid-PQC TLS provider and SPKI pinning), F05 (replicated store), F07
  (audit log).
- F19 §7.1 `HostCallAuth` (reused for `AppendAuditEvent`).
- F22 (tray admin client) is the client that enrolls and uses FIDO2. The server side
  of both factors ships with this feature.
- External gates: recording the local-accounts deviation with the ESI (D2), ESI
  acknowledgement of the accepted single-step add risk (D4), the AAL decision for
  TUI sessions and the audit mechanism; DPO validation (overview "Gates").

## Design notes

### 1. Phase 0 — closing the unauthenticated admin surface

| Item | Today | Phase 0 |
|------|-------|---------|
| Legacy admin RPCs on `MachineIdentity` | No check (`service.rs`) | Require a valid admin session (`authorization: Bearer …`) and the permission in the §7 table; otherwise `UNAUTHENTICATED` or `PERMISSION_DENIED`. |
| Serving them on `:8443` | Always | `CMIS_LEGACY_ADMIN_ON_MAIN=true` (default in 0.29, still authenticated); set it to `false` to serve them only on the admin listener. |
| Plaintext bring-up (`CMIS_TLS_*` unset) | Full surface in plaintext | Admin methods answer `FAILED_PRECONDITION (tls_required)`; the admin listener does not start. |
| `AppendAuditEvent` | Unauthenticated: anyone can append events and fill the WORM store | Requires `HostCallAuth` (context `ferrogate-audit-forward-v1`, doc = SHA-384 of `event_cbor` + `host_uuid`, `issued_at`, `nonce`). Rate-limited per host. |
| Docs | `networking.md` claims operator-only TLS credentials | Corrected |

There is **no** unauthenticated compatibility switch. Old `ferrogate` binaries
stop working against 0.29 CMIS, which is a breaking change: 0.29.0 and a change
document. Operators should also review the existing audit log for
`AllowlistSet`, `AllowlistDeleted`, `HostRevoked` and `PolicyEpochBumped` events
nobody can account for (overview "Findings", item 1).

### 2. Admin listener and transport

- `CMIS_ADMIN_LISTEN` (default `127.0.0.1:8444`). To serve remote tray clients,
  bind a management interface. The listener **must not** be reachable from the
  internet (proposed classification level 4: VPN plus employee plus NDA).
- TLS 1.3 only, `X25519MLKEM768` only (`ProviderMode::HybridOnly`, as F01). The
  certificate is `CMIS_ADMIN_TLS_CERT`/`_KEY`, or by default the main listener's.
  Clients pin the SPKI (SHA-384, `transport-tls.md` recipe). Cipher suites follow
  F01; **the ESI-indicated cipher list is an open dependency** (NRM §5.2 "Tráfego").
- Optional mTLS: with `CMIS_ADMIN_CLIENT_CA` set, a client certificate chaining to
  that CA is required **in addition** to the session. Its SHA-256 is recorded on the
  session and must match on every call. Combined with a hardware-backed key
  (smart card, PIV, TPM, Secure Enclave), this is the "certificado digital em
  hardware" second-factor option of G-002 and counts toward AAL3.
- The client IP is the TCP peer address. A proxy in front of the admin listener is
  **not supported** in Phase 1, because the IP would be lost; PROXY-protocol v2
  from a fixed trusted LB list is OQ-F20-3.
- Message size cap of 64 KiB per admin request; `ListApp*` page size ≤ 200.

### 3. Data model (hiqlite)

```sql
CREATE TABLE admin_accounts (
  admin_id            TEXT PRIMARY KEY,           -- UUIDv7; pseudonym used in audit
  username            TEXT NOT NULL UNIQUE,       -- NFKC + casefold, [a-z0-9._-]{3,64} (PERSONAL DATA)
  display_name        TEXT,                       -- <= 128 (PERSONAL DATA)
  state               INTEGER NOT NULL,           -- 1 pending_enrollment, 2 active, 3 disabled
  created_at          INTEGER NOT NULL,
  created_by_admin_id TEXT,                       -- NULL for bootstrap/recovery
  password_phc        TEXT,                       -- $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
  pepper_id           INTEGER,
  password_changed_at INTEGER,
  password_expires_at INTEGER,
  totp_secret_enc     BLOB,                       -- XChaCha20-Poly1305(secrets key, AAD=admin_id||"totp-v1")
  totp_last_step      INTEGER,                    -- replay guard
  last_login_at       INTEGER,
  disabled_at         INTEGER,
  disabled_by_admin_id TEXT,
  row_version         INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE admin_password_history (            -- every previous hash; reuse forbidden
  admin_id TEXT NOT NULL, password_phc TEXT NOT NULL, pepper_id INTEGER, set_at INTEGER NOT NULL,
  PRIMARY KEY (admin_id, set_at)
);
CREATE TABLE admin_webauthn_credentials (        -- FIDO2; an account may hold several keys plus TOTP
  credential_id BLOB PRIMARY KEY, admin_id TEXT NOT NULL, cose_public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL, aaguid BLOB, label TEXT, created_at INTEGER NOT NULL, last_used_at INTEGER
);
CREATE TABLE admin_groups (group_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, builtin INTEGER NOT NULL);
CREATE TABLE admin_group_permissions (group_id TEXT NOT NULL, permission TEXT NOT NULL,
  PRIMARY KEY (group_id, permission));
CREATE TABLE admin_group_members (admin_id TEXT NOT NULL, group_id TEXT NOT NULL,
  granted_by_admin_id TEXT, granted_at INTEGER NOT NULL, PRIMARY KEY (admin_id, group_id));
CREATE TABLE admin_sessions (
  session_hash        BLOB PRIMARY KEY,           -- SHA-256(token); token never stored
  admin_id            TEXT NOT NULL,
  created_at          INTEGER NOT NULL,
  last_seen_at        INTEGER NOT NULL,           -- written at most once per 60 s
  absolute_expires_at INTEGER NOT NULL,
  idle_timeout_secs   INTEGER NOT NULL,
  aal                 INTEGER NOT NULL,           -- 2 TOTP, 3 FIDO2-UV / hardware mTLS
  mfa_at              INTEGER NOT NULL,           -- last second-factor verification (step-up)
  mfa_method          INTEGER NOT NULL,           -- 1 totp, 2 webauthn (method of the last verification)
  source_ip           TEXT NOT NULL,              -- PERSONAL DATA
  client_cert_sha256  BLOB,                       -- when mTLS is on
  client_kind         INTEGER NOT NULL,           -- 1 tui, 2 tray, 3 cli
  client_version      TEXT,
  restricted          INTEGER NOT NULL DEFAULT 0, -- password expired: only passwd/logout/whoami
  revoked_at          INTEGER, revoked_reason INTEGER
);
CREATE INDEX admin_sessions_admin ON admin_sessions(admin_id);
CREATE TABLE admin_enrollment_tokens (
  token_hash BLOB PRIMARY KEY, admin_id TEXT, purpose INTEGER NOT NULL, -- 1 bootstrap 2 enroll 3 reset 4 recovery
  created_by_admin_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE TABLE admin_login_throttle (
  key_hash BLOB PRIMARY KEY, key_kind INTEGER NOT NULL, -- 1 ip, 2 ip+device, 3 account
  failures INTEGER NOT NULL, locked_until INTEGER NOT NULL, last_failure_at INTEGER NOT NULL
);
CREATE TABLE admin_idempotency (
  admin_id TEXT NOT NULL, rpc TEXT NOT NULL, key TEXT NOT NULL, response BLOB NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (admin_id, rpc, key)
);
CREATE TABLE admin_security_log (                -- operational investigation; INSERT-only (trigger)
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, event TEXT NOT NULL,
  admin_id TEXT, username_attempted_hmac BLOB, source_ip TEXT, detail TEXT
);
```

- Triggers make `admin_password_history`, `admin_security_log` and used
  `admin_enrollment_tokens` rows immutable, and forbid deleting `admin_accounts`
  rows. Accounts are **disabled, never deleted**, so `admin_id` attribution in the
  audit log stays resolvable.
- Usernames typed at login that match no account are stored only as
  `HMAC-SHA-256(audit pseudonym key, username)`. People sometimes type a password
  into the username field.

### 4. Passwords

| Aspect | Requirement |
|--------|-------------|
| Hash | Argon2id, `m = 65536 KiB, t = 3, p = 4`, salt 16 bytes from the OS CSPRNG, 32-byte output, PHC string (RFC 9106 §4, second recommended option). Parameters are read from the PHC string. If the configured parameters are stronger, rehash on the next successful login. |
| Pepper (SHOULD) | `HMAC-SHA-256(pepper[pepper_id], NFKC(password))` is the Argon2 input. The pepper file is `CMIS_ADMIN_PEPPER_FILE` (32 bytes, `0400`, owner `cmis`), documented with the FGV *credenciais em configuração* template. Rotation: add a new id and rehash on login; drop the old id after 180 days, when every password has expired anyway. |
| Verification | Constant-time comparison (inside the `argon2` crate). At most 4 concurrent verifications (semaphore, 256 MiB peak); waiting more than 5 s returns `UNAVAILABLE`. Unknown usernames verify against a dummy PHC so the timing is the same. |
| Length | **≥ 24** characters (G-002 table, "administrativas"). Up to 256 accepted, never truncated; longer is rejected with `password_too_long`. Counted in Unicode scalar values after NFKC. |
| Composition | All 4 classes (upper, lower, digit, symbol), as G-002 requires for administrative credentials. Any printable character, spaces and Unicode included, is accepted. |
| Forbidden content | The username, display-name tokens of 3 or more characters, `ferrogate`, `fgv`, `senha`, `password`, `cmis`, the trust domain, the current year (case-insensitive substring check). |
| Blocklist | An embedded list of at least 100k common or breached passwords, compared against the whole password case-insensitively. No online lookup (no third-party calls). |
| History | No reuse of **any** earlier password of the account (G-002, administrative column). |
| Rotation | `password_expires_at = changed + 180 days` (NRM §5.3.8). Warning from 14 days before. After expiry the session is `restricted` until the password changes. Immediate rotation through an administrator reset on suspected compromise or ESI request. |
| Paste | Allowed in every client; clients offer a 32-character random generator (G-002 favours manager-generated passwords). |
| Transport | Only inside the admin TLS channel; never in a URL, log, error or audit event. |

### 5. Second factor and AAL

Both methods are specified here and ship together in the admin-auth phase. There is
no "TOTP first, FIDO2 later" split (decision D3).

- **Factors per account.** Every account has at least one factor and may hold
  **both**: TOTP, and any number of FIDO2 credentials (up to 8). `Login` accepts
  either method the account holds, subject to the policy below.
- **TOTP (AAL2, every client).** RFC 6238, HMAC-SHA-1, 6 digits, 30 s step, ±1 step.
  The 160-bit secret is generated by CMIS at enrollment, shown once as an
  `otpauth://` URI (QR in the tray), and
  stored encrypted with `CMIS_ADMIN_SECRETS_KEY_FILE`, decrypted in memory only
  during verification (`Zeroizing`), per NRM §5.3.2. A code is rejected if its time
  step is less than or equal to `totp_last_step` (replay guard). SMS is not offered
  (G-002 excludes it for administrative functions). TOTP is the only method in the
  TUI and the CLI, including over SSH.
- **FIDO2 / WebAuthn (AAL3, tray admin client).** CMIS is the relying party with a
  fixed RP ID `ferrogate-admin.<trust_domain>`. Supported authenticators are
  roaming security keys (CTAP2 over USB or NFC) and platform authenticators. User
  verification is required, ES256 and EdDSA are accepted, attestation is "none"
  (OQ-F20-2), sign counts are checked. The tray reaches the authenticator through
  platform APIs (Windows `webauthn.dll`, macOS AuthenticationServices) or CTAP2 HID
  on Linux (F22 §3a). The TUI and the CLI do **not** offer FIDO2: there is no CTAP
  forwarding over SSH, so FIDO2 is available only where the authenticator is local
  to the client, which is the tray. Device-bound credentials count as AAL3.
  Synced (backup-eligible) passkeys count as AAL2 (OQ-F20-6).
- **Enrollment (from the tray admin client).**
  1. *With an enrollment token* (new account, or after `ResetAdminCredentials`):
     `BeginEnrollment` returns the TOTP provisioning URI and the WebAuthn creation
     options. The person sets a password, then enrolls **at least one** factor and is
     encouraged to enroll **both**. `CompleteEnrollment` carries the proof of
     possession for each factor (a TOTP code, a WebAuthn attestation).
  2. *Later, from a signed-in session* ("My account", F22): `ListMyFactors`,
     `BeginAddFactor` / `CompleteAddFactor` and `RemoveFactor`. Adding or removing a
     factor needs a per-operation proof (`M`) from a factor the account already
     holds, and removing the last factor is refused (`last_factor`).
  3. Each enrollment or removal is audited (`AdminMfaEnrolled`, `AdminMfaRemoved`).
     The first account is bootstrapped by the CLI on the CMIS node with TOTP, and
     can add a FIDO2 key from the tray afterwards.
- **Policy option: FIDO2 for approvers in the tray.**
  `CMIS_ADMIN_TRAY_FIDO2_GROUPS` (default empty) lists groups, for example
  `ferrogate-approvers` in production. When a member of a listed group signs in
  from the tray (`client_kind = 2`), `Login` and `StepUp` accept **only** a WebAuthn
  assertion, and the session's `aal` is 3. TUI and CLI sessions of the same account
  keep using TOTP (AAL2). A listed-group member with no FIDO2 credential yet can sign
  in to the tray with TOTP, but the session is `restricted` to factor enrollment,
  `WhoAmI` and `Logout` (`factor_enrollment_required`) until a key is registered.
- **AAL position.** G-002 asks for **AAL3 for administrative functions and
  production access**. With the policy set, approvers who use the tray meet it. TUI
  sessions stay at AAL2, which needs an ESI decision, or limiting the TUI to viewers
  in production (overview OQ1).
- Hardware mTLS (§2) can also satisfy AAL3, as an alternative or addition to FIDO2.

### 6. Login protocol

```
BeginLogin{username, device_token?, client}            → {login_nonce, methods, webauthn (challenge)}
Login{login_nonce, username, password, totp|assertion} → {session_token, timeouts, aal, password state,
                                                          device_token (new or refreshed)}
```

1. `BeginLogin` always succeeds for well-formed input. `methods` lists what this
   account and this client kind may use (the TUI and CLI get TOTP only; the tray
   gets TOTP and WebAuthn, or WebAuthn only under the FIDO2 policy). For an unknown
   username it returns a plausible response: the same method list and decoy
   credential ids derived from `HMAC(server key, username)`. The `login_nonce`
   (32 bytes, 2 min, single use) is bound to the source IP and the username. For
   WebAuthn, `webauthn.challenge` is 32 fresh random bytes bound to the nonce.
2. `Login` checks, in this order:
   1. the throttle on all applicable keys (§8), **before** any cryptography;
   2. the nonce;
   3. the account state;
   4. the password (Argon2id; a dummy verification for unknown or disabled
      accounts);
   5. the second factor. A TOTP code is checked as in §5. A **WebAuthn assertion**
      is checked for: a known credential of this account; `clientDataJSON` type
      `webauthn.get` with the issued challenge; `rpIdHash` equal to the SHA-256 of
      the RP ID; the user-present and user-verified flags; the signature over
      `authenticatorData ‖ SHA-256(clientDataJSON)` with the stored COSE key; and a
      sign counter that increases (when the authenticator reports a non-zero value).
      The method must be allowed by the policy of §5.

   **Every failure returns the same `UNAUTHENTICATED (invalid_credentials)`.** A
   throttled request returns `RESOURCE_EXHAUSTED (login_throttled)` plus
   `retry-after`, regardless of whether the account exists. Each failure increments
   the throttle counters once.
3. On success:
   - create the session (§7);
   - reset the `ip+device` and `account` counters;
   - set `last_login_at`;
   - issue or refresh a **device token**;
   - audit `AdminLoginSucceeded`;
   - if the password has expired, mark the session `restricted` and set
     `password_change_required`.

The device token is the norm's "cookie". It is server-issued,
`HMAC(server key, admin_id ‖ random ‖ issued_at)`, valid for 180 days, and
**not** a credential. It only selects the throttle bucket (§8). Clients may keep
it in a `0600` file.

### 7. Sessions, permissions and `AdminAuthz`

**Token and lifetime**

- The token is `fgas_` followed by base64url of 32 CSPRNG bytes. Only
  `SHA-256(token)` is stored. It travels only in the `authorization: Bearer`
  metadata of the admin TLS channel.
- Idle timeout is 15 min and absolute lifetime 12 h, configurable lower, never
  higher (the AAL2 cap is 30 min idle). `last_seen_at` is written at most once per
  60 s.
- The session is bound to the login source IP (`CMIS_ADMIN_SESSION_BIND_IP=true`).
  A call from another IP revokes the session (`ip_mismatch`) and is audited.
- At most 5 sessions per account; a new login evicts the oldest (audited).

**Step-up and per-operation MFA**

- Operations marked *step-up* need `now − mfa_at ≤ CMIS_ADMIN_STEP_UP_WINDOW_SECS`
  (default 300; 0 means every time). Otherwise CMIS returns
  `FAILED_PRECONDITION (step_up_required)`. `BeginStepUp`/`StepUp` re-verify the
  second factor (the same methods and policy as `Login`) and **rotate the token**
  (identifier renewal on privilege elevation, G-002 §6).
- Account administration, `ChangePassword`, adding or removing a second factor, and
  **`AdminRegisterApplication`** (the single-step direct add, F19 §5.4) carry an
  inline `MfaProof` (per-operation, no window): a recent step-up does not
  substitute. The tray satisfies it with a key touch or a TOTP code, as the policy
  allows.
- Five failed step-ups revoke the session.

**Revocation.** Revocation is server-side: logout, `RevokeSession`, password
change (other sessions), administrator reset, account disable, and group change
(all sessions of the target, so new permissions take effect immediately). Groups
and permissions are **read from the database on every call** and never cached in
the token.

**Permission table.** One table maps each gRPC method to its access rule, and the
same table drives the tower layer and the tests. `S` = step-up, `M` = per-operation
MFA.

| Method(s) | Access | V | A | AA | P |
|-----------|--------|---|---|----|---|
| `BeginLogin`, `Login`, `BeginEnrollment`, `CompleteEnrollment` | public, throttled | | | | |
| `WhoAmI`, `Logout`, `ListMySessions`, `RevokeSession` (own), `BeginStepUp`, `StepUp`, `ChangePassword` (M), `ListMyFactors`, `BeginAddFactor`, `CompleteAddFactor` (M), `RemoveFactor` (M) | any authenticated session (`restricted` allowed only for `WhoAmI`, `Logout`, `ChangePassword`; a session restricted by the FIDO2 policy may also use `ListMyFactors`, `BeginAddFactor`, `CompleteAddFactor`) | ✓ | ✓ | ✓ | ✓ |
| `ListAppRequests`, `GetAppRequest`, `ListApprovals`, `GetApproval`, `ListHosts` | `app_request.list/read`, `approval.list/read`, `host.list` | ✓ | ✓ | | ✓ (`host.list`) |
| `ApproveAppRequest` (S) / `DenyAppRequest` (S) | `app_request.approve` / `app_request.deny` | | ✓ | | |
| `UpdateApproval` (S), `SetLineageAutoUpdateFrozen` (S) / `RevokeApproval` (S) | `approval.update` / `approval.revoke` | | ✓ | | |
| `AdminRegisterApplication` (M) | `app.direct_register` + `app_request.approve` (single step); `app.direct_register` alone queues a `PENDING` request under the strict policy | | ✓ | | |
| `ListAdminAccounts`, `ListAdminGroups` | `account.list` | | | ✓ | |
| `CreateAdminAccount` (M), `UpdateAdminAccount` (M), `SetAdminAccountState` (M), `ResetAdminCredentials` (M) | `account.create/update/disable/reset` | | | ✓ | |
| `RevokeSession` (other account) (S) | `session.revoke_any` | | | ✓ | |
| legacy `ListAllowlists`, `ListProposals`, `ListSvids` | `legacy.allowlist.read`, `svid.list` | | | | ✓ |
| legacy `SetAllowlist` (S), `DeleteAllowlist` (S), `DeleteProposal` (S) | `legacy.allowlist.write` | | | | ✓ |
| legacy `RevokeSvid` (S), `RevokeHost` (S), `UnrevokeHost` (S, T296) | `svid.revoke` | | | | ✓ |
| legacy `BumpEpoch` (S) | `policy.epoch_bump` | | | | ✓ |
| `SetAllowlistMode` (S), `ImportLegacyAllowlists` (S) (F19 §11) | `settings.allowlist_mode`, `allowlist.import` | | | | ✓ |
| `GetAllowlistMode` (F19 §11; read-only, lets every client pick the legacy or approvals flow) | any authenticated session | ✓ | ✓ | ✓ | ✓ |
| `MachineIdentity` host methods (`SubmitAppRequest`, `GetAppRequestStatus`, `SyncAllowlist`, `ProposeAllowlist`, `AppendAuditEvent`, `Rotate` (T293, context `ferrogate-rotate-v1`)) | host proof (F19 §7.1) | | | | |
| `Attest`, `FetchSVID`, `JWKS`, `GetEnrollmentKey`, `GetAllowlist` (legacy), `Health`, `LatestSth`, `InclusionProof`, `ConsistencyProof` | public (unchanged) | | | | |

V = viewers, A = approvers, AA = account-admins, P = platform-operators. Groups
are the only way permissions reach an account. Custom groups with any subset of
permissions can be added later (Phase 2); the built-in groups cannot be edited.

**Enforcement (single decision point, NRM §5.3.1).**

- `AdminAuthz::authorize(&Request, Access) -> Result<AdminContext, Status>` makes
  every decision.
- A tower `Layer` installed on **both** services looks the gRPC path up in
  `METHOD_ACCESS`. A method missing from the table is denied
  (`PERMISSION_DENIED`, which is deny by default). Otherwise the layer
  authenticates, authorizes, inserts `AdminContext{admin_id, session_ref, groups,
  permissions, aal, mfa_at, source_ip, client_kind}` into the request extensions,
  and audits denials (`AdminAccessDenied`).
- Handlers call `AdminAuthz` again for **object-level** and **separation-of-duties**
  checks (for example `ApproveAppRequest` on a request whose `requested_by_admin_id`
  is the caller).
- A unit test iterates the compiled file descriptor sets of both services and
  fails if any method lacks a `METHOD_ACCESS` entry, so a new RPC cannot ship
  unclassified.

**Separation of duties** (`CMIS_ADMIN_STRICT_SOD = true | false`, default `false`).
The product owner decided that single-step direct add is the default and that strict
separation is an optional policy (D4). The rules:

1. *Strict policy only.* Nobody approves or denies a request with
   `requested_by_admin_id == self`, and `AdminRegisterApplication` creates only a
   `PENDING` request for a different approver.
2. *Strict policy only.* `ferrogate-account-admins` and `ferrogate-approvers` are
   mutually exclusive.
3. *Always.* Nobody changes their own groups or state, or resets their own
   credentials (changing one's own password is allowed).
4. *Always.* The last active account administrator cannot be disabled or demoted.

With the policy **off** (default), an approver may register and approve an
application in one step (F19 §5.4), and may approve their own `admin_direct`
request. Each such case needs a fresh second factor (`M`) and emits the distinct
event `AppApprovedBySameActor` (F19 §9), so the requester-equals-approver case is
always visible. This is an **accepted risk decided by the product owner**, to be
acknowledged by the ESI. Setting the policy is audited as `AdminSodModeChanged`
whenever the value differs from the one last recorded. Changing it never alters
existing approvals. Self-approval of a request that came from the administrator's own
*workstation OS account* (origin `self`/`assisted`) cannot be detected without
linking OS identities to admin accounts; that is OQ-F20-1.

### 8. Login throttling (NRM §5.3.5)

| Key | Applies to | Thresholds → lock |
|-----|------------|-------------------|
| **K_ip** — source IP | attempts **without** a valid device token for the attempted account (the IP is the main control) | 3 → 1 min; 5 → 15 min; 7 → 1 h; each further 2 → 1 h |
| **K_dev** — (IP, device token) | attempts **with** a valid device token: separates a known person behind a shared IP from the attacker | 3 → 1 min; 5 → 15 min; 7 → 1 h; each further 2 → 1 h |
| **K_acct** — account (normalised username, including non-existent) | attempts without a valid device token (distributed guessing) | 9 → 1 min; 15 → 15 min; 21 → 1 h. The multipliers need ESI validation. |

- The lock is checked before any password work. Counters live in the replicated
  `admin_login_throttle` table, so every node enforces the same lock.
- Counters with no new failure for 24 h reset. A success resets `K_dev` and that
  account's `K_acct`.
- The same counters cover `CompleteEnrollment` (token guessing), TOTP and
  assertion failures, and `BeginLogin` floods (10 per IP per minute, separately).
- Attackers cannot mint device tokens, because a token is only issued after a
  successful login. Rotating the client instance therefore cannot evade K_ip, and
  a legitimate administrator holding a device token is not locked out by
  distributed attacks on K_acct (FGV: avoid DoS against legitimate users).
- Alerting: more than 20 failures in 10 min (all keys), or any 1 h lock, raises a
  `warn` log and an `AdminLoginAnomaly` audit event for the SIEM. How this reaches
  the ESI is an integration point (OQ-F20-4).

### 9. Bootstrap, enrollment, reset, recovery

**Bootstrap**

1. At start, with no account at all and no unexpired bootstrap token, the leader
   writes a 32-byte token, base32 with a checksum, to `CMIS_ADMIN_BOOTSTRAP_TOKEN_FILE`
   (default `/var/lib/ferrogate/admin-bootstrap.token`, `O_EXCL`, `0400`, owner
   `cmis`), valid for 24 h.
2. It logs **the path only**.
3. `ferrogate admin bootstrap --token-file <path>` (run on that node) asks for the
   username, display name and password, and enrolls TOTP.
4. The account joins `ferrogate-account-admins` (strict policy on) or every built-in
   group (default). CMIS sets `cmis_settings.admin_bootstrapped = 1`, removes the file
   and audits `AdminBootstrapCompleted`. Bootstrap never re-arms by itself.

**Account creation**

1. `CreateAdminAccount` (M) creates a `pending_enrollment` account **with its
   groups** (FGV: no account without permissions) and returns a single-use
   enrollment token once (default 24 h, at most 72 h).
2. The account administrator delivers it over a second channel after verifying
   the person's identity through a previously registered contact (G-002 §7). It is
   never sent in the same channel as the request.
3. The new administrator calls `BeginEnrollment` and `CompleteEnrollment` from the
   tray admin client (F22) to set their password and enroll their second factor(s):
   TOTP, FIDO2, or both (§5).
4. Residual risk: the creator holds the token and could enroll in the person's
   place. Mitigations: under the strict policy the creator cannot be an approver
   (SoD 2), enrollment from the creator's own session IP is flagged in the audit
   (`AdminEnrollmentCompleted{same_ip_as_creator}`), and the person must confirm
   their first login out of band. The risk is accepted with local accounts (D2).
   Federation, a future item, would remove it.

**Reset.** `ResetAdminCredentials` (M) revokes every session of the target,
clears the password and/or second factor, and issues a `reset` token, delivered
as above. Self-service recovery does not exist.

**Recovery (break-glass).** Starting CMIS with `CMIS_ADMIN_RECOVERY=1` (root on a
node) writes a `recovery` token (1 h) for a **new** account in
`ferrogate-account-admins`. It audits `AdminRecoveryInvoked` at `warn` level and
refuses to run if the flag is still set after the token is redeemed. The recovery
account must be disabled once normal administration is restored. It is an
emergency credential under G-002 §3.1: rotate after any use.

### 10. Audit events (`ferro-audit`, no PII)

`AdminLoginSucceeded{admin_id, session_ref, aal, mfa_method, client_kind, src_ip_hmac}`,
`AdminLoginFailed{account_ref_hmac, reason (invalid_credentials|throttled|disabled|nonce), src_ip_hmac, lock_secs}`,
`AdminLockoutApplied{key_kind, lock_secs}`, `AdminLoginAnomaly{failures_10m}`,
`AdminLogout{admin_id, session_ref}`, `AdminSessionRevoked{admin_id, session_ref, by_admin_id?, reason}`,
`AdminStepUp{admin_id, session_ref, mfa_method, success}`, `AdminPasswordChanged{admin_id, by_self}`,
`AdminAccountCreated{admin_id, by_admin_id, groups}`, `AdminAccountUpdated{admin_id, by_admin_id, changed_fields, groups?}`,
`AdminAccountStateChanged{admin_id, by_admin_id, state}`, `AdminCredentialsReset{admin_id, by_admin_id, password, mfa}`,
`AdminEnrollmentCompleted{admin_id, purpose, same_ip_as_creator}`, `AdminMfaEnrolled{admin_id, method}`,
`AdminMfaRemoved{admin_id, method, by_admin_id?}`,
`AdminBootstrapCompleted{admin_id}`, `AdminRecoveryInvoked{}`, `AdminSodModeChanged{strict}`,
`AdminAccessDenied{admin_id?, method, permission, reason}`.

`src_ip_hmac` and the `*_hmac` fields use a per-deployment **audit pseudonymisation
key** (`CMIS_AUDIT_PSEUDONYM_KEY_FILE`). The clear values are kept in
`admin_sessions` and `admin_security_log` under DPO-defined retention, so an
investigation can join them. Every admin mutation in F19 and here emits **exactly
one** event; this is asserted in tests. The single-step add and the same-actor
approval emit `AppApprovedBySameActor` (F19 §9) in place of the ordinary approval
event. An audit append failure is logged at
`error` and raises an alert. It never passes silently (G-002 "perda silenciosa
não").

### 11. Logs (single `tracing` pipeline)

- Event names are stable and dotted (`admin.login.failed`, `admin.session.revoked`,
  `admin.authz.denied`, …), with levels Info, Warn and Error. Details carry ids,
  never secrets.
- **Never logged:** passwords, session, device or enrollment tokens, TOTP secrets
  or codes, WebAuthn assertions, `authorization` metadata. A test captures every
  log line of a full bootstrap/login/step-up/logout run and asserts none of the
  secret values appear.
- Errors go to the log and generic codes go to the client (NRM §5.3.5).
- **Gap:** the workspace has no formatter for the G-002 line format
  `[dd/mm/aaaa] hh:mm:ss ; evento ; detalhes`. This predates F20 and affects
  every crate. It is recorded in the overview; a shared `tracing` formatter, or ESI
  acceptance of structured JSON with the same fields, is needed.

### 12. Client-side requirements (TUI, tray admin, CLI)

These are common to every client and implemented once in `ferrogate-admin-client`:

- Password and second-factor inputs are held in `Zeroizing<String>`, wiped right
  after the `Login`, `StepUp` or `ChangePassword` call returns, and never kept for
  re-authentication.
- The session token is held in memory only (`Zeroizing`) and wiped on logout,
  idle lock or exit. It is never written to disk, keychain, clipboard, logs, crash
  reports or diagnostics bundles. The CLI exception (opt-in
  `--session-file $XDG_RUNTIME_DIR/…`, `0600`, tmpfs, deleted on logout) is a
  documented decision; see Risks.
- Clients pin the admin SPKI and refuse to connect without a pin.
- A client idle lock mirrors the server (15 min): it clears every displayed record
  and requires a new login.
- Every server-provided string is untrusted. Clients strip or escape control
  characters, ANSI/OSC sequences and bidi overrides before rendering (F21 and F22).

### 13. Proto sketch (`admin.proto`, auth and account part)

```proto
syntax = "proto3";
package ferrogate.admin.v1;

service Admin {
  rpc BeginLogin (BeginLoginRequest) returns (BeginLoginResponse);
  rpc Login (LoginRequest) returns (LoginResponse);
  rpc BeginStepUp (BeginStepUpRequest) returns (BeginStepUpResponse);
  rpc StepUp (StepUpRequest) returns (StepUpResponse);
  rpc Logout (LogoutRequest) returns (LogoutResponse);
  rpc WhoAmI (WhoAmIRequest) returns (WhoAmIResponse);
  rpc ListMySessions (ListMySessionsRequest) returns (ListMySessionsResponse);
  rpc RevokeSession (RevokeSessionRequest) returns (RevokeSessionResponse);
  rpc ChangePassword (ChangePasswordRequest) returns (ChangePasswordResponse);
  rpc BeginEnrollment (BeginEnrollmentRequest) returns (BeginEnrollmentResponse);
  rpc CompleteEnrollment (CompleteEnrollmentRequest) returns (CompleteEnrollmentResponse);
  rpc ListAdminAccounts (ListAdminAccountsRequest) returns (ListAdminAccountsResponse);
  rpc ListAdminGroups (ListAdminGroupsRequest) returns (ListAdminGroupsResponse);
  rpc CreateAdminAccount (CreateAdminAccountRequest) returns (CreateAdminAccountResponse);
  rpc UpdateAdminAccount (UpdateAdminAccountRequest) returns (UpdateAdminAccountResponse);
  rpc SetAdminAccountState (SetAdminAccountStateRequest) returns (SetAdminAccountStateResponse);
  rpc ResetAdminCredentials (ResetAdminCredentialsRequest) returns (ResetAdminCredentialsResponse);
  rpc ListMyFactors (ListMyFactorsRequest) returns (ListMyFactorsResponse);
  rpc BeginAddFactor (BeginAddFactorRequest) returns (BeginAddFactorResponse);
  rpc CompleteAddFactor (CompleteAddFactorRequest) returns (CompleteAddFactorResponse);
  rpc RemoveFactor (RemoveFactorRequest) returns (RemoveFactorResponse);
  rpc GetAllowlistMode (GetAllowlistModeRequest) returns (GetAllowlistModeResponse);
  rpc SetAllowlistMode (SetAllowlistModeRequest) returns (SetAllowlistModeResponse);
  rpc ImportLegacyAllowlists (ImportLegacyAllowlistsRequest) returns (ImportLegacyAllowlistsResponse);
  // F19 app-management RPCs: ListAppRequests, GetAppRequest, ApproveAppRequest, DenyAppRequest,
  // ListApprovals, GetApproval, UpdateApproval, RevokeApproval, SetLineageAutoUpdateFrozen,
  // AdminRegisterApplication, ListHosts — see F19 §5.4 / §7.
  // AdminRegisterApplication carries `string idempotency_key = 1; MfaProof proof = 2;` plus the F19 fields.
}

message ClientInfo { uint32 kind = 1; string version = 2; }            // 1 tui, 2 tray, 3 cli
message MfaProof   { oneof f { string totp_code = 1; WebAuthnAssertion webauthn_assertion = 2; } bytes nonce = 3; }

// WebAuthn (CTAP2 security keys and platform authenticators), driven by the tray admin client.
message WebAuthnChallenge {                       // BeginLogin, BeginStepUp: request for an assertion
  bytes  challenge = 1;                           // 32 random bytes, single use, 2 min, bound to the nonce
  string rp_id = 2;                               // ferrogate-admin.<trust_domain>
  repeated bytes allow_credential_ids = 3;        // decoys for unknown accounts
  uint32 user_verification = 4;                   // 1 = required
  int64  timeout_ms = 5;
}
message WebAuthnAssertion {                       // authenticator response to WebAuthnChallenge
  bytes credential_id = 1; bytes authenticator_data = 2; bytes client_data_json = 3;
  bytes signature = 4;     bytes user_handle = 5;
}
message WebAuthnCreationOptions {                 // BeginEnrollment, BeginAddFactor: request for a new credential
  bytes  challenge = 1; string rp_id = 2; string rp_name = 3;
  bytes  user_id = 4;   string user_name = 5; string display_name = 6;
  repeated int32 pub_key_cred_params = 7;         // COSE alg ids: -7 ES256, -8 EdDSA
  repeated bytes exclude_credential_ids = 8;      // already enrolled keys
  uint32 user_verification = 9;                   // 1 = required
  uint32 attestation = 10;                        // 1 = none
}
message WebAuthnAttestation {                     // authenticator response to WebAuthnCreationOptions
  bytes credential_id = 1; bytes attestation_object = 2; bytes client_data_json = 3;
  repeated string transports = 4; string label = 5;
}

message BeginLoginRequest  { string username = 1; string device_token = 2; ClientInfo client = 3; }
message BeginLoginResponse { bytes login_nonce = 1; repeated uint32 methods = 2; WebAuthnChallenge webauthn = 3; }  // methods: 1 totp, 2 webauthn
message LoginRequest {
  bytes login_nonce = 1; string username = 2; string password = 3;
  oneof second_factor { string totp_code = 4; WebAuthnAssertion webauthn_assertion = 5; }
}
message LoginResponse {
  string session_token = 1; int64 idle_timeout_secs = 2; int64 absolute_expires_at = 3;
  uint32 aal = 4; bool password_change_required = 5; int64 password_expires_at = 6;
  string device_token = 7; string admin_id = 8; string display_name = 9; repeated string groups = 10;
}
message BeginStepUpRequest  {}
message BeginStepUpResponse { bytes stepup_nonce = 1; WebAuthnChallenge webauthn = 2; }
message StepUpRequest  { bytes stepup_nonce = 1; MfaProof proof = 2; }
message StepUpResponse { string session_token = 1; int64 step_up_valid_until = 2; }  // token rotated
message ChangePasswordRequest  { string current_password = 1; string new_password = 2; MfaProof proof = 3; }
message ChangePasswordResponse { string session_token = 1; int64 password_expires_at = 2; }
message SessionInfo { string session_ref = 1; int64 created_at = 2; int64 last_seen_at = 3;
                      string source_ip = 4; uint32 client_kind = 5; bool current = 6; uint32 aal = 7; }
message RevokeSessionRequest { string session_ref = 1; string admin_id = 2; }        // empty admin_id = self
message CreateAdminAccountRequest  { string idempotency_key = 1; string username = 2; string display_name = 3;
                                     repeated string groups = 4; MfaProof proof = 5; }
message CreateAdminAccountResponse { string admin_id = 1; string enrollment_token = 2; int64 enrollment_expires_at = 3; }
message UpdateAdminAccountRequest  { string idempotency_key = 1; string admin_id = 2; uint64 expected_row_version = 3;
                                     optional string display_name = 4; bool replace_groups = 5;
                                     repeated string groups = 6; MfaProof proof = 7; }
message SetAdminAccountStateRequest { string idempotency_key = 1; string admin_id = 2; uint32 state = 3; MfaProof proof = 4; }
message ResetAdminCredentialsRequest { string idempotency_key = 1; string admin_id = 2; bool reset_password = 3;
                                       bool reset_mfa = 4; MfaProof proof = 5; }
message ResetAdminCredentialsResponse { string enrollment_token = 1; int64 expires_at = 2; }
message BeginEnrollmentRequest  { string enrollment_token = 1; }
message BeginEnrollmentResponse { string username = 1; bool username_choosable = 2; string display_name = 3;
                                  string totp_provisioning_uri = 4; WebAuthnCreationOptions webauthn_creation_options = 5;
                                  uint32 password_min_len = 6; }
message CompleteEnrollmentRequest {                // at least one of totp_code / webauthn_attestation; both may be sent
  string enrollment_token = 1; string username = 2; string display_name = 3; string password = 4;
  string totp_code = 5; WebAuthnAttestation webauthn_attestation = 6;
}
message CompleteEnrollmentResponse { string admin_id = 1; }

// Factor management from a signed-in session (tray admin client)
message FactorInfo { string factor_id = 1; uint32 method = 2; string label = 3; int64 created_at = 4; int64 last_used_at = 5; }
message ListMyFactorsRequest {}
message ListMyFactorsResponse { repeated FactorInfo factors = 1; }
message BeginAddFactorRequest  { uint32 method = 1; }                                  // 1 totp, 2 webauthn
message BeginAddFactorResponse { bytes enroll_nonce = 1; string totp_provisioning_uri = 2;
                                 WebAuthnCreationOptions webauthn_creation_options = 3; }
message CompleteAddFactorRequest { string idempotency_key = 1; bytes enroll_nonce = 2; string label = 3;
                                   string totp_code = 4; WebAuthnAttestation webauthn_attestation = 5;
                                   MfaProof proof = 6; }                               // proof of an existing factor
message CompleteAddFactorResponse { string factor_id = 1; }
message RemoveFactorRequest { string idempotency_key = 1; string factor_id = 2; MfaProof proof = 3; }
message RemoveFactorResponse {}
```

On the server, secret fields are moved into `Zeroizing` buffers as soon as they
are decoded. prost's own buffers cannot be wiped reliably (see Risks).

### 13a. Error codes

| Code | Reason | Meaning |
|------|--------|---------|
| `UNAUTHENTICATED` | `invalid_credentials` | Any login, enrollment or second-factor failure |
| `UNAUTHENTICATED` | `session_invalid` | Missing, unknown, expired, revoked or IP-mismatched session |
| `RESOURCE_EXHAUSTED` | `login_throttled` | With `retry-after` |
| `PERMISSION_DENIED` | `permission_denied` | Permission missing |
| `PERMISSION_DENIED` | `sod_violation` | Separation-of-duties rule hit (rules 1 and 2 only with the strict policy on) |
| `PERMISSION_DENIED` | `method_not_classified` | Method absent from `METHOD_ACCESS` |
| `FAILED_PRECONDITION` | `step_up_required`, `password_expired`, `tls_required`, `password_policy`, `factor_enrollment_required`, `last_factor` | `password_policy` comes with `x-ferrogate-policy-failures`: rule ids, never echoing the password. `factor_enrollment_required`: a tray session restricted by the FIDO2 policy until a key is registered. `last_factor`: `RemoveFactor` would leave the account with none |
| `ABORTED` | `row_version_mismatch` | Concurrent edit |
| `UNAVAILABLE` | `auth_busy`, `store_unavailable` | |

## Security considerations and threat model

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| S | Credential stuffing or brute force | 24-character policy and blocklist, mandatory second factor, NRM throttle on IP, device and account, uniform errors and timing |
| S | Phished password plus TOTP relayed in real time | FIDO2 (RP-ID-bound, AAL3) in the tray, which the policy can require for approvers; hardware mTLS option; IP-bound sessions; SPKI-pinned clients (a relay must also be the client). TUI sessions stay on TOTP, which needs an ESI decision (overview OQ1) |
| S | An attacker with a stolen password and TOTP code enrolls their own FIDO2 key | Adding a factor needs a per-operation proof of an existing factor and is audited (`AdminMfaEnrolled`); the factor list is visible in the tray; `ResetAdminCredentials` clears all factors |
| S | WebAuthn assertion replay or a cloned authenticator | Single-use challenge bound to the login nonce (2 min), RP ID and flag checks, sign-counter regression rejected |
| S | Stolen session token | Never persisted, IP-bound, 15 min idle, rotated on step-up, hashed at rest, revocable; optional mTLS binding |
| S | Admin impersonation at enrollment by the creator | SoD 2 (strict policy), same-IP flag, out-of-band first-login confirmation. Residual risk accepted with local accounts (D2) |
| T | Tampering with accounts or groups through the database | Only CMIS writes. Triggers on history tables. The DB lives on the TEE-hosted CMIS (F06), with OS access limited to operations. |
| R | "I didn't approve that" | Individual accounts, never shared (G-002); every action audited with `admin_id` and `session_ref` in the Merkle log; anchored STHs |
| I | Username enumeration | Uniform `BeginLogin`/`Login` behaviour, dummy hashing, decoy WebAuthn ids, IP-keyed throttle |
| I | Secrets in logs or audit | Field-level redaction, a log-capture test, PII-free audit |
| D | Argon2 memory exhaustion | Concurrency semaphore, per-IP `BeginLogin` limit, throttle before hashing |
| D | Locking a legitimate admin out | Device-token bucket isolation; the account lock applies only to device-less attempts |
| E | Unclassified or new RPC exposed without checks | Deny-by-default layer plus the descriptor-coverage test |
| E | Account admin grants themself approver rights | SoD 3 (always) and SoD 2 (strict policy) enforced in `AdminAuthz` |
| E / R | An approver registers and approves a malicious binary alone (single-step add, no second person) | **Accepted risk (D4), ESI to acknowledge.** Per-operation second factor, the distinct `AppApprovedBySameActor` event for SIEM review, F19 scope and expiry caps, fast revocation, optional strict policy |
| E | Host calls admin RPCs | Hosts hold no admin session. Host proofs are only accepted on host methods. |

## FGV conformance (NRM / G-002)

| Rule | Status in this design |
|------|----------------------|
| Single authentication and authorization point (§5.3.1) | **Conforme** — `AdminAuthz` plus the layer |
| MFA for sensitive operations (§5.3.1) | **Conforme** — mandatory at login, step-up or per-operation MFA on sensitive calls; window length subject to ESI validation |
| AAL3 for administrative functions (G-002 §2.2) | **Pendente** — FIDO2 (AAL3) is supported in the tray and the policy can require it for approvers; TUI sessions use TOTP (AAL2), which the ESI must accept or restrict (overview OQ1) |
| AD / corporate IdP integration (§5.3.4) | **Não conforme — decisão do product owner (D2, 2026-10-14)** — local accounts are the 3rd-priority option; the deviation must be recorded with the ESI. Federation is a future item |
| Separation of duties / four-eyes on approvals | **Risco aceito pelo product owner (D4)** — single-step direct add is the default, with a fresh second factor and the `AppApprovedBySameActor` event; strict separation is optional. The ESI must acknowledge |
| Progressive lockout 3/5/7, IP primary (§5.3.5) | **Conforme** — K_ip and K_dev follow it exactly; K_acct multipliers need validation |
| Groups or profiles, never direct user permissions (G-002) | **Conforme** |
| One-way password hash (§5.3.2) | **Conforme** — Argon2id |
| Reversible secret open only in server memory (§5.3.2) | **Conforme** — TOTP secret; **Lacuna:** the ESI official crypto library and cipher are not known |
| Admin password ≥ 24, 4 classes, blocklist, no reuse, 6-month rotation (G-002 §2.1, NRM §5.3.8) | **Conforme** |
| Audit login, account creation and account change (§5.3.1) | **Conforme** |
| Audit in a separate instance, INSERT-only enforced by the DB (§5.3.1) | **Pendente** — ferro-audit uses Merkle chaining, WORM files and external anchoring instead of DB grants (stronger tamper evidence, a different mechanism); the ESI must accept (overview OQ2) |
| Log format `[dd/mm/aaaa] hh:mm:ss ; evento ; detalhes` (§5.3.10) | **Não conforme (pré-existente, transversal)** |
| Encrypted transport with ESI-indicated ciphers (§5.2) | **Conforme / Lacuna** — hybrid-PQC TLS 1.3; the ESI cipher list is not known |
| Credentials in config files documented (G-002) | **Pendente** — pepper, secrets key and pseudonym key files need the template record |
| No direct-DB diagnostic screens (§5.4.2) | **Conforme** — the TUI and tray use gRPC only |

## Testing strategy

**Unit**

- Argon2 PHC round-trip, rehash on parameter upgrade, pepper id handling.
- Password policy: a table of accepted and rejected passwords, one per rule; no
  truncation at 256; NFKC.
- TOTP: RFC 6238 vectors, ±1 window, replay rejected at the same or an earlier
  step.
- **WebAuthn:** assertion verification vectors for ES256 and EdDSA; rejected for an
  RP ID hash mismatch, a missing user-present or user-verified flag, a wrong or
  replayed challenge, a regressing sign counter, a credential of another account;
  attestation parsing and `none` attestation on enrollment; decoy credential ids for
  unknown usernames.
- **Factor policy:** a member of a `CMIS_ADMIN_TRAY_FIDO2_GROUPS` group on a tray
  session is refused TOTP and accepted with an assertion (`aal = 3`); the same
  account on a TUI or CLI session is accepted with TOTP (`aal = 2`); with no key
  enrolled the tray session is `restricted` to factor enrollment.
- Throttle progression with a mocked clock (3 → 60 s, 5 → 900 s, 7 → 3600 s,
  9 → 3600 s); device-token isolation; K_acct only for device-less attempts.
- Session idle and absolute expiry; IP mismatch revokes; restricted sessions;
  eviction at 5.
- `METHOD_ACCESS` covers every method in both file descriptor sets; an
  unclassified method is denied.
- SoD rules 3 and 4 hold in both modes; rules 1 and 2 hold only with
  `CMIS_ADMIN_STRICT_SOD=true`. **Policy toggle test:** the same self-approval and
  direct-add calls succeed (with `AppApprovedBySameActor`) with the policy off and
  return `sod_violation` or a queued `PENDING` request with it on.

**Integration** (in-process CMIS on TLS)

- Bootstrap end to end.
- Create, enroll and log in; step-up flow and token rotation.
- **FIDO2 enrollment and login flow** (virtual authenticator): enrollment token →
  `BeginEnrollment` → `CompleteEnrollment` with TOTP **and** a WebAuthn attestation
  (both stored); login by assertion; step-up by assertion; `BeginAddFactor` /
  `CompleteAddFactor` of a second key with the proof of an existing factor;
  `RemoveFactor`, with removal of the last factor refused (`last_factor`); an account
  holding both factors can use either.
- **Single-step add** by an approver: `AdminRegisterApplication` with a fresh
  `MfaProof` → one `AppApprovedBySameActor` event. Rejected with only a recent
  step-up and no proof.
- `ChangePassword` revokes other sessions; disable revokes everything.
- A group change takes effect on the next call.
- Legacy `SetAllowlist` without a token → `UNAUTHENTICATED`; with a viewer token →
  `PERMISSION_DENIED`; with an operator token and a fresh step-up → OK.
- Plaintext mode refuses admin methods.
- `AppendAuditEvent` without a host proof → `UNAUTHENTICATED`.

**Negative**

- Response-time comparison for unknown versus wrong-password users (statistical,
  for example 200 samples, difference under a set bound).
- Replayed `login_nonce`; a token used after logout; a token from another IP; a
  TOTP code reused.
- An enrollment token used twice or expired.
- A replayed WebAuthn assertion or attestation; an assertion for another account's
  credential; `CompleteAddFactor` without a valid proof of an existing factor.
- 10k-request `BeginLogin` flood stays within memory bounds.

**Audit**

- Exactly one event per mutation.
- The no-PII test is extended to the new variants.
- The log-capture secret scan.

**Fuzz:** `admin.proto` request decoding plus the policy checker on arbitrary
Unicode.

## Migration and rollout

1. **0.29.0 (Phase 0 + Phase 1 auth):**
   - deploy CMIS with the admin listener;
   - bootstrap the first account on the leader;
   - create the other accounts;
   - upgrade `ferrogate` CLIs on operator workstations;
   - update automation that called admin RPCs. Until service principals exist
     (overview OQ4), it must run interactively, for example from `ferrogate admin shell`.
2. Set `CMIS_LEGACY_ADMIN_ON_MAIN=false` once all operators use 0.29 clients.
3. Phase 2: hardware mTLS profile, custom groups. FIDO2 is **not** deferred: the
   server side ships in step 1 with TOTP, and approvers enroll keys from the tray
   admin client (F22) as soon as it is installed. Until then accounts use TOTP.
4. Each step: change document, ESI pre-production verification, rotation dates
   for the pepper, secrets and pseudonym keys entered in the credential inventory.

## Acceptance criteria

- [ ] No admin method (legacy or new) can be invoked without a valid session and
      the mapped permission. The coverage test passes.
- [ ] No admin method is served without TLS. `AppendAuditEvent` requires a host
      proof.
- [ ] Throttle locks exactly as NRM §5.3.5 on K_ip and K_dev. Responses are
      identical for unknown users and wrong passwords.
- [ ] Passwords are stored only as Argon2id PHC strings, and the policy rules are
      enforced server-side.
- [ ] A second factor is required for every login. Both TOTP and FIDO2 are
      supported, an account may hold both, FIDO2 is offered only to tray sessions,
      and enrollment of both works from the tray admin client. The
      `CMIS_ADMIN_TRAY_FIDO2_GROUPS` policy is enforced (tests). Step-up and
      per-operation MFA are enforced per the table.
- [ ] Sessions expire (idle and absolute), are IP-bound, are revocable and listed;
      the token rotates on step-up and password change.
- [ ] SoD rules 3 and 4 always hold; rules 1 and 2 hold under
      `CMIS_ADMIN_STRICT_SOD=true`. A single-step add needs a fresh second factor
      and emits exactly one `AppApprovedBySameActor` event.
- [ ] Every authentication and admin event in §10 is emitted exactly once with
      no PII. No secret appears in logs.
- [ ] Bootstrap and recovery work as specified and never re-arm silently.
- [ ] `networking.md`, `operations.md`, `cmis.md` and the change document are
      updated; credential-in-config records exist for the three key files.

## Risks

- **AAL gap for TUI sessions** (TOTP only, notably over SSH). Mitigation: FIDO2 in
  the tray, the policy requiring it for approvers there, the hardware mTLS profile,
  or an ESI exception (overview OQ1).
- **Single-step add concentrates authority (accepted, D4).** Mitigation: fresh
  second factor per add, the `AppApprovedBySameActor` event, the optional strict
  policy; the ESI must acknowledge.
- **Creator can impersonate at enrollment.** Mitigated, not eliminated (§9).
- **prost buffers keep secret copies** until freed. Mitigation: CMIS runs with
  `mlockall` and hardening, inside the TEE target (F06); secrets are moved to
  `Zeroizing` right away; core dumps are disabled.
- **CLI session file** (opt-in) is a persisted bearer token. Mitigation: tmpfs,
  `0600`, IP-bound, 15 min idle, removed on logout. Off by default.
- **Clock skew across nodes** affects TOTP and throttle timing. Mitigation: NTP is
  required on CMIS nodes (already needed for SVIDs).
- **Operational lockout** (all account administrators lost). Mitigation: rule 4
  plus break-glass recovery.

## Open questions

- **OQ-F20-1** — Link administrator accounts to the OS identities they use, so
  self-approval of their own workstation requests can be blocked?
- **OQ-F20-2** — FIDO2 attestation policy: "none" (proposed) or an AAGUID
  allowlist of approved authenticators?
- **OQ-F20-3** — Support the admin listener behind an L4 load balancer through
  PROXY v2 from fixed trusted addresses?
- **OQ-F20-4** — SIEM and ESI alert channel for `AdminLoginAnomaly` and lockouts.
- **OQ-F20-5** — Step-up window: 5 min (proposed) or per-operation for approvals
  as well?
- **OQ-F20-6** — Synced (backup-eligible) passkeys: count as AAL2 (proposed), or
  refuse them at enrollment so every FIDO2 credential is device-bound?
