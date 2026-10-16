# Operations

## Bootstrapping a new host (zero-touch)

1. **Factory.** TPM vendor provisions and signs the EK certificate at
   manufacture, burning it into TPM NV storage.
2. **Fleet manifest.** The fleet owner publishes an offline-signed manifest
   listing the SHA-384 of every accepted EK certificate. CMIS loads this
   manifest on startup and hot-reloads it from a local file (a deployment that
   keeps it in object storage syncs it to that path out of band; the composite
   signature, not the transport, gates what is admitted).
3. **First boot.** The MIA reads the EK certificate and connects to CMIS
   over hybrid-PQC TLS (server-auth only; the client has no identity yet).
4. **Pre-admission check.** CMIS looks up `SHA-384(ek_cert)` in the active
   fleet manifest *before* any TPM verification work runs. Unknown hosts are
   rejected immediately (`HostRejected` audit event); enrolled hosts are logged
   (`HostEnrolled`) and proceed. The EK chain to a vendor root is then verified
   as part of phase 2 quote validation.
5. **Attestation.** Protocol phases 2–4 run; on success the SVID is delivered
   and the MIA seals it to PCRs `{0, 4, 7, 8}`.

There is no shared secret or pre-distributed credential between the host and
CMIS at any point. The whole bootstrap is anchored in the vendor signature
on the EK cert.

### Operating the fleet manifest

- **Build and sign** with the offline `fleet-manifest` tool. `keygen` derives a
  publisher keypair from a 32-byte master seed (keep the seed air-gapped; only
  it is secret). `new` / `add` / `remove` edit an unsigned manifest; `sign`
  emits the composite-signed bundle; `verify` / `show` inspect it.
- **Configure CMIS** with `CMIS_FLEET_MANIFEST` (path to the signed bundle),
  `CMIS_FLEET_SIGNER_KID`, and `CMIS_FLEET_SIGNER_PUB` (the publisher public key
  as concat-bytes hex, printed by `keygen`). With `CMIS_FLEET_MANIFEST` unset,
  enrolment is **unenforced** and every host that can attest is admitted. A
  configured-but-unloadable manifest aborts startup (fail-closed).
- **Refreshes are atomic.** A newer manifest is verified and hot-swapped under a
  write lock, so in-flight attestations see a consistent enrolment snapshot. The
  manifest is read from a local file; native S3 sourcing is dropped (see
  [roadmap.md](roadmap.md) §"Dropped scope") — sync from object storage to the
  watched path out of band if needed.

## Transport security (hybrid-PQC TLS)

All MIA→CMIS control-plane traffic runs over TLS 1.3 using the hybrid
`X25519MLKEM768` group only (feature F01). The shared rustls configs are built
by `ferro_crypto::transport::{server_config, client_config}`; the server
listener glue is `cmis::transport`, the client dialer is
`mia::client::connect_pinned`. See [transport-tls.md](transport-tls.md) for the
full how-it-works, the OpenSSL pin recipe, and troubleshooting.

- **CMIS server identity.** Configure the listener with `CMIS_TLS_CERT` (PEM
  certificate chain: end-entity first, then any intermediates) and
  `CMIS_TLS_KEY` (PEM private key — PKCS#8 / PKCS#1 / SEC1). Both must be set
  together; setting only one aborts startup, and setting neither falls back to
  a **plaintext** bring-up server (development only, logged as a warning). With
  TLS on, the listener advertises only `X25519MLKEM768`, so a non-PQC client
  fails the handshake before reaching the gRPC layer.
- **MIA pin provisioning.** The MIA does not trust a CA hierarchy; it pins the
  SHA-384 of the CMIS certificate's `SubjectPublicKeyInfo`. Compute the pin
  from the deployed cert with `ferro_crypto::pin::SpkiPin::from_certificate_der`
  (or its `to_hex`/`from_hex` round-trip) and hand the pin set to
  `connect_pinned`. A server whose SPKI hash is not pinned — or that does not
  speak the hybrid group — is rejected before any RPC.
- **Telemetry.** Every accepted connection logs `kx_group = X25519MLKEM768`.
  Operators confirm post-quantum coverage by asserting no accepted connection
  ever logs a non-hybrid group (which, under the hybrid-only provider, cannot
  occur — a downgrade attempt fails the handshake instead).
- **Certificate rotation.** Replace the cert/key files and restart (or
  hot-reload, when wired); update the MIA pin set to include the new SPKI pin
  ahead of the cutover so both old and new certificates verify during the
  overlap window.

## Administrator access (F20)

Since **0.29.0** every CMIS admin RPC requires an individual administrator
account: a session obtained with a password **and** a second factor, a group
that grants the method's permission, and — for writes such as `SetAllowlist`,
`RevokeHost` or `BumpEpoch` — a second-factor step-up in the last 5 minutes.
Before 0.29.0 those RPCs performed no caller check at all. Design:
[F20](features/F20-admin-authentication.md); listener and firewall:
[networking.md](networking.md#1a-cmis-admin-listener--tcp-8444).

### Configuration

All variables are read at CMIS start. A malformed value aborts startup rather
than falling back to a weaker default.

| Variable | Default | Meaning |
|----------|---------|---------|
| `CMIS_ADMIN_LISTEN` | `127.0.0.1:8444` | Admin listener (`Admin` service + legacy admin RPCs). TLS only; bind a management interface, never an internet-facing one |
| `CMIS_ADMIN_TLS_CERT` / `CMIS_ADMIN_TLS_KEY` | the main listener's (`CMIS_TLS_CERT`/`_KEY`) | Admin listener certificate and key (PEM); set both or neither. Without any certificate the admin listener does not start |
| `CMIS_ADMIN_CLIENT_CA` | unset | PEM CA bundle; when set the admin listener also requires an mTLS client certificate from it |
| `CMIS_LEGACY_ADMIN_ON_MAIN` | `true` | Also serve the legacy admin RPCs on the main listener (`:8443`), still session-authenticated. Set `false` once every operator uses a 0.29 CLI |
| `CMIS_ADMIN_STRICT_SOD` | `false` | Strict separation of duties: an account administrator may not hold the approver group, and nobody approves their own request |
| `CMIS_ADMIN_STEP_UP_WINDOW_SECS` | `300` | How long a second-factor step-up stays valid for sensitive methods (capped at 900; `0` = only the same second) |
| `CMIS_ADMIN_SESSION_BIND_IP` | `true` | Revoke a session presented from another source IP |
| `CMIS_ADMIN_SESSION_IDLE_SECS` | `900` | Session idle timeout (60–900) |
| `CMIS_ADMIN_SESSION_ABSOLUTE_SECS` | `43200` | Session absolute lifetime (at least the idle timeout, at most 12 h) |
| `CMIS_ADMIN_SECRETS_KEY_FILE` | `/var/lib/ferrogate/admin/secrets.key` | 32-byte key sealing TOTP secrets and keying server MACs. Every node of a cluster must hold the same file (a node with a different key refuses to start the admin subsystem). Generated (`0400`, with a warning) only when unset and the default file is missing; an explicitly configured file must already exist |
| `CMIS_AUDIT_PSEUDONYM_KEY_FILE` | `/var/lib/ferrogate/admin/audit-pseudonym.key` | 32-byte key for the keyed pseudonyms (source IPs, attempted usernames) written to the audit log. Same generation rule |
| `CMIS_ADMIN_PEPPER_FILE` | unset | Optional 32-byte password pepper (id 1) mixed into Argon2id |
| `CMIS_ADMIN_PASSWORD_BLOCKLIST_FILE` | unset | Breached-password corpus, one password per line, checked on every password set |
| `CMIS_ADMIN_BOOTSTRAP_TOKEN_FILE` | `/var/lib/ferrogate/admin-bootstrap.token` | Where the leader writes the one-time first-account bootstrap token |
| `CMIS_ADMIN_TRAY_FIDO2_GROUPS` | empty | Comma-separated built-in groups whose members must use FIDO2 when signing in from the tray admin client (for example `ferrogate-approvers`). An unknown group name aborts startup |
| `CMIS_ADMIN_WEBAUTHN_ORIGINS` | `https://ferrogate-admin.<trust domain>` | Comma-separated `https://` origins a WebAuthn `clientDataJSON` may name; each must be the RP ID `ferrogate-admin.<CMIS_TRUST_DOMAIN>` or a subdomain |
| `CMIS_TRUST_DOMAIN` | `ferrogate.dev` | Also fixes the WebAuthn RP ID and is forbidden inside passwords |
| `CMIS_AUDIT_FORWARD_MAX_PER_MIN` | `600` | `AppendAuditEvent` calls each host may make per minute, per CMIS node (1–60000) — see [Audit forwarding from hosts](#audit-forwarding-from-hosts) |
| `CMIS_ROTATE_MAX_PER_HOUR` | `6` | Host-signed `Rotate` calls each host may make per hour, per CMIS node (1–3600; zero or garbage aborts startup). Every authenticated call spends one, refused or not — see [SVID rotation](#svid-rotation) |

The key files (secrets, pseudonym, pepper) are credentials kept in
configuration: keep them root-owned and unreadable by group and others (CMIS
refuses them otherwise) on every CMIS node, identical across the cluster, out
of version control and of backups that leave the node, and enter their
rotation dates in the credential inventory. Argon2id parameters are not
configurable; production always runs the RFC 9106 values.

The `ferrogate` CLI reads, besides its flags:

| Variable | Meaning |
|----------|---------|
| `FERROGATE_ADMIN_ENDPOINT` | Admin listener URL (default `https://127.0.0.1:8444`), pinned like `--endpoint` (`--spki-pin` / `--tls-cert`) |
| `FERROGATE_SESSION_FILE` | Opt-in file (`0600`) keeping the session token between commands; put it on a tmpfs such as `$XDG_RUNTIME_DIR`. Without it each admin command signs in and out |
| `FERROGATE_DEVICE_FILE` | Where the server-issued device token is kept (default `~/.config/ferrogate/admin-device.token`; empty disables). It only separates people behind one IP for throttling |
| `FERROGATE_ADMIN_CLIENT_CERT` / `FERROGATE_ADMIN_CLIENT_KEY` | Client certificate and key for an admin listener with mTLS |

### Bootstrapping the first administrator

1. Start CMIS 0.29.0 with TLS material (`CMIS_TLS_CERT`/`CMIS_TLS_KEY` or the
   `CMIS_ADMIN_TLS_*` pair). On a fresh deployment — no account, bootstrap
   never completed — the Raft leader writes a one-time token to
   `CMIS_ADMIN_BOOTSTRAP_TOKEN_FILE` (`0400`, valid 24 h) and logs only its
   path.
2. On **that** node, as root, redeem it:

   ```sh
   ferrogate admin bootstrap --token-file /var/lib/ferrogate/admin-bootstrap.token
   ```

   Choose a username, display name and a password of at least 24 characters
   (the CLI can be fed a password manager's output on stdin). CMIS shows a
   TOTP provisioning URI **once**: add it to an authenticator app, then type
   the current code.
3. The first account receives every built-in group (only
   `ferrogate-account-admins` under `CMIS_ADMIN_STRICT_SOD=true`). CMIS
   deletes the token file, records the bootstrap in the replicated store and
   never re-arms it. An `AdminBootstrapCompleted` event is audited.

### Signing in with the CLI

```sh
ferrogate --admin-endpoint https://cmis-1.mgmt:8444 --spki-pin <hex> \
  --session-file "$XDG_RUNTIME_DIR/ferrogate.session" admin login
ferrogate --session-file "$XDG_RUNTIME_DIR/ferrogate.session" allowlist list
ferrogate --session-file "$XDG_RUNTIME_DIR/ferrogate.session" admin logout
```

`admin login` prompts (without echo) for the username, password and TOTP
code. Commands that need a step-up (writes, revocation, epoch bump) prompt for
a fresh TOTP code and retry once. Without `--session-file` every admin command
signs in, runs and signs out. `ferrogate admin help` lists `whoami`,
`sessions`, `passwd`, `accounts`, `groups` and `factors`. FIDO2 security keys
are enrolled and used from the tray admin client; the CLI uses TOTP.

**Adding administrators.** An account administrator runs
`ferrogate admin accounts create <username> --group <group>…`. CMIS prints a
single-use enrollment token (24 h by default) — deliver it over a second
channel; the new administrator redeems it with `ferrogate admin enroll
--token-file <file>` (password + TOTP) or from the tray admin client.
Built-in groups: `ferrogate-viewers` (read-only), `ferrogate-approvers`
(application approvals), `ferrogate-account-admins` (accounts, other
sessions), `ferrogate-platform-operators` (legacy allowlists, SVID and host
revocation, epoch bump). `ferrogate admin groups` prints their permissions.

### Upgrading to 0.29.0 (breaking change)

- **Old `ferrogate` CLIs stop working.** A 0.28 or older CLI sends no session,
  so every admin command it issues (`allowlist set/add/remove/delete/list`,
  `list-svids`, `revoke-svid`, `revoke-host`, `bump-epoch`) is refused with
  `UNAUTHENTICATED`. There is no unauthenticated compatibility switch. Upgrade
  the CLI on operator workstations and on CMIS nodes, bootstrap the first
  account, create the others, and move automation that called admin RPCs to
  an interactive administrator (non-interactive service principals are not
  available yet).
- `CMIS_LEGACY_ADMIN_ON_MAIN` defaults to `true`, so 0.29 CLIs still pointed
  at `:8443` keep working with a session. Set it to `false` once every
  operator uses the admin listener.
- `AppendAuditEvent` now requires a host proof; senders older than 0.29 are
  refused (`UNAUTHENTICATED`). The shipped MIA daemon does not forward events
  over the network yet, so nothing in a stock deployment breaks.
- **Review the audit log.** Until 0.29.0 anyone who could reach `:8443` —
  every MIA host, for one — could call the admin RPCs. Before relying on the
  new controls, review the existing audit log for `AllowlistSet`,
  `AllowlistDeleted`, `HostRevoked` and `PolicyEpochBumped` events that no
  operator can account for, and re-issue the affected allowlists. Events
  written before 0.29.0 carry no `by_admin_id`.

### Known limitations (0.29.0)

- The client kind (TUI, tray, CLI) is self-declared by the client, so the
  `CMIS_ADMIN_TRAY_FIDO2_GROUPS` policy can be sidestepped by a client that
  claims to be the CLI or TUI and signs in with TOTP.
- Login and step-up nonces are single-use **per node** only; on a multi-node
  cluster a captured nonce could be presented once to each node within its
  lifetime (the password and second factor are still required).
- `idempotency_key` fields are accepted but not yet enforced: a retried
  mutation is executed again.
- There is no break-glass recovery yet: if every account administrator is
  locked out, recovery needs a new deployment-level procedure (planned).
- The `AppendAuditEvent` replay cache and rate limit are per node, like the
  revocation working set; host revocation reaches only the node that received
  `RevokeHost` until revocations are replicated.

## SVID rotation

- `Rotate` is a host method (0.30.0, T293): the request carries the host
  proof (SVID, machine key matching `cnf.jkt`, signature over a fresh
  single-use `RotateDoc` under `ferrogate-rotate-v1`) and must name the
  host's latest stored SVID. Budget: `CMIS_ROTATE_MAX_PER_HOUR` (6) per host
  and node. A client calling `Rotate` without the proof gets
  `UNAUTHENTICATED host_auth_failed` and must run `Attest` instead.
- Only the **host-key** tier renews on the short path: same signed machine
  fingerprint, same `policy_id` epoch, and less than 24 h since the last full
  attestation. A TPM-tier host is always answered `FAILED_PRECONDITION` and
  re-attests (its PCRs need a fresh quote).
- With the 96 h SVID TTL floor, a renewal at 60 % of TTL is past the 24 h
  window, so it is normally a full re-attestation. See
  [Host SVID renewal in the daemon](#host-svid-renewal-in-the-daemon).
- Refusals after authentication are audited as `AttestFail`
  (`rotate-tier-requires-attest`, `rotate-superseded`,
  `rotate-reattest-state-drift|epoch-bump|window-expired`,
  `rotate-unknown-subject`); renewals as `SvidIssued`. Proof failures are
  only logged (`host_auth.failed`), like the other host methods.
- Any PCR change detected at boot invalidates the cached SVID (sealing breaks)
  and forces full re-attestation.

### Host SVID renewal in the daemon

Since 0.30.0 (T294) the MIA daemon renews its host SVID while running; no
restart is needed. Each environment runs one renewal task whenever CMIS is
configured:

- **When.** At 60 % of the SVID's lifetime, ±10 % jitter drawn per SVID, so
  a fleet attested together does not renew together. After a renewal the
  next one is at least 30 s away.
- **How.** A host-key host whose last *full* attestation is more than 10
  minutes inside CMIS's 24 h window renews with one host-signed `Rotate`
  (same key, same child-signing `kid`; the sealed X.509-SVID is re-sealed).
  Otherwise — always with real TTLs (96 h floor), always on the TPM tier —
  it runs a full attestation with the configured backend. A refused
  `Rotate` (`FAILED_PRECONDITION`, `NOT_FOUND`, `UNAUTHENTICATED`,
  `PERMISSION_DENIED`, or any undocumented code) falls back to a full
  attestation in the same attempt.
- **Retries.** `UNAVAILABLE` (`store_unavailable`, CMIS unreachable),
  time-outs and internal errors retry after 30 s × 2ⁿ⁻¹, jittered to
  `[½, 1]`, at most 15 minutes and a quarter of the time left, and never
  later than 60 s before expiry; `rate_limited` waits CMIS's `retry-after`
  (at most 15 minutes, never past expiry). A host with no valid SVID (start-up
  attestation failed, or the SVID expired) re-attests every 5 minutes; the
  start-up attempt counts as the first.
- **Swap.** A new SVID goes in force in a fixed order: host-call credentials
  (allowlist sync, registration, audit forwarding), the child-token minter,
  the status endpoint, then an allowlist sync (or, without the F19 sync, the
  start-only fetch and reload) and, if `allowlist.propose` is on, the
  proposals, which read the current SVID on every round.
- **Fail closed.** If the SVID expires before a renewal succeeds (CMIS down
  for its whole remaining lifetime, a suspended host), minting
  (`no_host_svid`), host calls and proposals stop at expiry — checked against
  the wall clock at least every minute — until a full attestation succeeds.
- **Same key, same identity.** A renewal reopens the machine key and SVID
  seed the daemon started with and never creates either: a key file that
  vanished is refused (`machine_key_refused`; restore it from a backup). If a
  full re-attestation comes back under another SPIFFE id (the host was
  re-enrolled), the SVID is not put in force, minting stops, and the
  environment's serve loop exits with an error — the process exits non-zero
  when it serves one environment, so the service supervisor restarts it under
  the new identity (with several environments the others keep serving).
- **Not reloaded.** `SIGHUP` does not re-read the attestation settings
  (`attestation.*`, `cmis.*`): renewals use the ones read at start; restart
  to change them.
- **Status.** A failing renewal leaves the phase *attested*: before the
  renewal point the state stays `healthy`; past it, `svid_expiring` with the
  failure's code (`cmis_unreachable`, `attestation_failed`, `host_rejected`,
  `pin_mismatch`, `tpm_unavailable`, `machine_key_refused`), or
  `svid_renewal_due` while an attempt is in flight. After expiry the state is
  the attestation failure itself. The renewal point shown (`renews …`) is the
  un-jittered 60 %, so a healthy host can report `svid_renewal_due` for up to
  10 % of the TTL before its jittered renewal runs.
- **Log lines** (target `mia`, never the JWS, keys or nonces):
  - `host SVID renewal scheduled (60% of its lifetime, ±10% jitter)`
    (`spiffe_id`, `expires_at`, `rotate`) at start, or
    `no host SVID at startup; scheduling background re-attestation`
    (`interval_secs`);
  - `host SVID renewed; token minting and host calls use it` (`spiffe_id`,
    `path` = `rotate` | `full_attestation`, `expires_at`,
    `next_renewal_in_secs`);
  - `CMIS refused the Rotate renewal; renewing with a full attestation`
    (`code`, `reason`);
  - `host SVID renewal (Rotate) failed; retrying` (warning; `code`,
    `reason`) and `host SVID renewal (Rotate) rate limited; retrying later`
    (warning; `retry_after_secs`); a failed full attestation logs its cause
    as at start (`host-key attestation failed`, `could not connect to CMIS
    for attestation`, …);
  - `host SVID expired before it was renewed; token minting and host calls
    are off until a full attestation succeeds` (warning; `spiffe_id`,
    `expired_at`);
  - `CMIS issued an SVID that is not valid now (check the host clock);
    keeping the current one` (error);
  - `CMIS issued an SVID for another host identity; it is not put in force …`
    (error; `held`, `issued`), then `stopping the helper API: the host
    identity changed`.

## RIM policy and epoch bump

- **RIM bundle.** CMIS maps attested PCR digests to a `policy_id` via a
  versioned, composite-signed RIM bundle (the active generation plus six prior).
  Configure it with `CMIS_RIM_BUNDLE` (path to the signed bundle file),
  `CMIS_RIM_SIGNER_KID`, and `CMIS_RIM_SIGNER_PUB` (publisher composite pubkey
  as concat-bytes hex). CMIS loads it fail-closed at startup and a watcher
  hot-swaps any strictly-newer signed bundle (verified before apply, atomic).
  With `CMIS_RIM_BUNDLE` unset the allowlist is empty and every quote fails the
  RIM lookup (`FAILED_PRECONDITION`) — fail-closed by default. The policy id
  `host-key` (any case) is reserved for the host-key tier: a bundle using it is
  refused (startup aborts; a hot reload keeps the previous generations and
  logs `rim.reserved_policy_id`).
- **Native S3 sourcing is dropped** (see [roadmap.md](roadmap.md) §"Dropped
  scope"). The bundle is read from a local file; a deployment that keeps it in
  object storage syncs it to that path out of band. Because the bundle is
  composite-signed and verified before apply, that sync path is untrusted —
  only the signature gates what is admitted.
- **Epoch bump (mass re-attestation).** For a compromised RIM generation or a
  vulnerable kernel image, the operator calls the `BumpEpoch(reason)` admin RPC
  (`ferrogate bump-epoch`; an administrator session with `policy.epoch_bump`
  and a fresh step-up, see [Administrator access](#administrator-access-f20)).
  It advances the live
  policy epoch and records a `PolicyEpochBumped` audit event. Every host whose
  last full attestation was under the previous epoch is refused at its next
  `Rotate` (`FAILED_PRECONDITION`) and driven back through a full four-phase
  `Attest`. The bump is process-local; replicating it across a cluster is a
  documented deployment seam.

## Revocation

- CMIS publishes a composite-signed CRL delta every 60 s as a JWKS extension
  (`x-ferrogate-crl`). The CRL is signed with the composite issuance key under
  the `ferrogate-crl-v1` domain context and verified against the issuer key the
  same JWKS publishes.
- Operators revoke through the `MachineIdentity` admin RPCs (an administrator
  session with `svid.revoke` and a fresh step-up, see
  [Administrator access](#administrator-access-f20)):
  - `RevokeSvid(cert_sha, reason)` — revoke one SVID by the lowercase-hex
    `SHA-384` of its compact JWS.
  - `RevokeHost(spiffe_id, reason)` — revoke every SVID and child token for a
    host.
  Each revocation is recorded in the audit log (`SvidRevoked` / `HostRevoked`,
  with the reason opcode) and republishes the CRL immediately, so the change
  reaches consumers within one publish cycle rather than after the next tick.
- The MIA refuses to mint helper tokens if the cached CRL is missing or more
  than 5 minutes old (fail closed), and refuses if the CRL revokes its own
  host. The independent reference verifier (`ferro-svid-verify`) likewise
  rejects a revoked SVID, requiring a fresh, signature-valid CRL to make the
  decision.
- CRL entries are pruned once they age past the 1 h max SVID TTL: a revoked
  artefact can never reappear after expiry, so dropping the entry bounds CRL
  growth.
- For mass revocation (compromised RIM generation, vulnerable kernel image),
  the operator bumps the policy epoch via `BumpEpoch` — see "RIM policy and
  epoch bump" above. Every host attested under the old epoch re-attests at its
  next rotation; the global audit log records the bump (`PolicyEpochBumped`).

## Audit forwarding from hosts

`AppendAuditEvent` lets a MIA host append its own events (`LocalGrant`,
`LocalDenied`, `AllowlistSyncApplied`, `AllowlistSyncRejected`; CMIS also
accepts `ConfigChanged`, which MIA does not send yet) to the CMIS audit log.
Since 0.29.0 (F20
Phase 0) each call carries a **host proof** (F19 §7.1 `HostCallAuth`):

- the host's current SVID, issued by this CMIS, unexpired and not revoked
  (neither the SVID nor its host);
- the machine key the SVID binds through `cnf.jkt`, and its ECDSA-P256
  signature over `ferrogate-audit-forward-v1 ‖ doc`, where `doc` is
  `{v, host_uuid, issued_at, nonce, event_sha384}` and `event_sha384` is the
  SHA-384 of the forwarded event bytes.

CMIS refuses, without appending anything, a missing or invalid proof, a
document naming another host (`PERMISSION_DENIED host_mismatch`), an
`issued_at` more than 300 s from its clock, a `(host, nonce)` pair already seen
in the last 600 s, event bytes that do not match the signed digest, and any
event type a host does not produce (`PERMISSION_DENIED event_not_forwardable`
— a host cannot write issuance, revocation or admin events). Authentication
failures all answer `UNAUTHENTICATED host_auth_failed`; the precise reason is
in the CMIS log (`event = "host_auth.failed"`). Each host may forward
`CMIS_AUDIT_FORWARD_MAX_PER_MIN` events per minute per node (default 600,
burst of one minute's budget); beyond that CMIS answers
`RESOURCE_EXHAUSTED rate_limited` with a `retry-after` header in seconds.
Keep host clocks synchronised (NTP): a host more than 5 minutes off cannot
forward.

### On the host: the audit spool

The MIA daemon forwards through an on-disk spool (T291; behaviour in
[audit.md](audit.md#event-types), "The MIA forwarder"):

- **Where.** `/var/lib/ferrogate/audit-spool.jsonl` on Linux
  (`audit-spool-<env>.jsonl` for a named environment); on macOS and Windows,
  the same name in the system configuration directory. Mode `0600`, owned by
  the daemon's user. It holds caller pids, uids, binary hashes and token
  `jti`s, so treat it like the daemon log: keep it out of backups that leave
  the host. It is never created when CMIS is not configured, and a host whose
  SVID binds no host-call key (TPM tier) only logs its events.
- **Bounds.** At most 10 000 pending events or 8 MiB of them; beyond that
  the oldest are dropped. Between compactions the file can reach about twice
  that size. A busy host must stay under `CMIS_AUDIT_FORWARD_MAX_PER_MIN`
  (600 per minute per CMIS node by default) on average: the forwarder sends
  one event per call and waits out `rate_limited`, so a sustained higher rate
  grows the backlog until the cap drops events. Raise the CMIS limit for such
  hosts rather than letting the spool overflow.
- **Watching it.** The daemon log (targets `mia::audit_forward` and
  `mia::audit_forward::spool`; the status
  endpoint's log tail shows these lines too, never the events) reports, with
  counts and stable reason codes only:
  - `replaying audit events spooled by an earlier run` (`pending`) at start;
  - `audit forwarding to CMIS failing` (`reason`, `pending`) on the first
    failure, `still failing` at most every 10 minutes (`pending`,
    `dropped_total`, `failing_secs`), then `recovered` (`pending`);
  - `audit forwarding waits for a valid host SVID …` while no credentials
    exist yet;
  - `host SVID expired; audit events are held in the spool …` (warning,
    once): the SVID ran out before the renewal task replaced it (see
    [Host SVID renewal in the daemon](#host-svid-renewal-in-the-daemon)); it
    keeps re-attesting every 5 minutes, and until it succeeds events are
    spooled and, past the cap, the oldest dropped;
  - `audit forwarding over the CMIS rate limit` (`wait_secs`, `pending`), at
    most every 10 minutes;
  - `audit spool full; oldest events dropped` (`dropped`, `dropped_total`), at
    most every 10 minutes;
  - `CMIS refused an audit event for good` (`reason`, `event_type`) for each
    event dropped on a permanent refusal;
  - `could not write the audit spool` / `audit spool unusable` (an I/O error):
    events are then held in memory, within the same bounds, until the file
    can be written; fix the state directory's permissions or free space;
  - `audit spool could not be read in full; moved it aside` (`spool`,
    `moved_to`, `error`): see Recovery.

  `mia status` does not show the backlog yet. Each event is also logged
  locally on the `mia::audit` target, forwarded or not.
- **Recovery.** Nothing to do after an outage or a restart: the spool is
  replayed in order. Do not edit it by hand; deleting it discards the events
  it holds (they remain in the local log). A damaged line is skipped with a
  warning (`skipped unreadable audit spool records`). A spool that cannot be
  read to its end is renamed, unchanged, to
  `audit-spool[-<env>].jsonl.unreadable-<unix time>` (`0600`) and a fresh
  one starts. That file is not replayed and nothing removes it. Inspect it
  (its events are also in the local log), then delete it; it holds the
  same data as the spool.
- **Shutdown.** Events received but not yet appended when the daemon stops
  are not spooled (they are in the local `mia::audit` log); an event still
  queued in the helper channel at that instant is in neither.

## Caller allowlists

Each MIA host gates its helper API with a **signed caller allowlist** — the
`(uid, binary-SHA-384)` pairs allowed to mint child tokens. CMIS stores, signs,
and serves these per host; operators manage them with the `ferrogate allowlist`
commands. The issuer secret never leaves CMIS — the CLI submits entries and CMIS
signs them with the enrollment key.

- Allowlists are keyed by the host's **EK-derived UUID**
  (`ferro_svid::host_uuid_from_ek_digest`), so a host can be provisioned before
  it attests. Name the host with `--host <uuid>`, `--ek-cert <pem>`, or
  `--ek-sha384 <hex>`.
- Provision and edit:
  - `ferrogate allowlist set --host <uuid> --bin <uid>:<path>` — replace a host's
    allowlist (the CLI hashes the binary; `--entry <uid>:<sha384>` takes a
    precomputed hash).
  - `ferrogate allowlist add/remove …` — read-modify-write a single entry; CMIS
    re-signs.
- Inspect and retrieve:
  - `ferrogate allowlist show --host <uuid>` / `ferrogate allowlist list`.
  - `ferrogate allowlist get --host <uuid> --out allowlist.cbor` — fetch the raw
    signed CBOR to place at a host's `allowlist.path` (a MIA with `GetAllowlist`
    reachability can fetch it directly instead).
- `Set`/`Delete`/`ListAllowlists` are admin RPCs that need an administrator
  session (`legacy.allowlist.write` plus a fresh step-up for set and delete,
  `legacy.allowlist.read` to list), exactly like revocation; `GetAllowlist` is
  unauthenticated (the body is signature-protected and not secret). Each set or
  delete records an audit event (`AllowlistSet` / `AllowlistDeleted`) naming
  the administrator. If the replicated store refuses the write, the RPC
  answers `UNAVAILABLE (store_unavailable)` and records nothing; retry once the
  cluster is healthy. Host proposals (`ProposeAllowlist`) behave the same. CMIS
  stamps a validity window (default 96 h via `CMIS_ALLOWLIST_TTL_SECS`, floored
  at 96 h and capped at 30 days); re-issue rather than
  mint long-lived lists. Full workflow: [allowlist-provisioning.md](allowlist-provisioning.md).
- **In `approvals` mode** (after the migration below) these legacy bodies are
  read-only: `SetAllowlist` and `DeleteAllowlist` answer
  `FAILED_PRECONDITION mode_approvals`, `ferrogate allowlist add` registers
  one binary as an approval and `ferrogate allowlist remove` revokes the
  matching approvals. `GetAllowlist` then serves the lossy-safe v1 compile of
  the approvals while `CMIS_LEGACY_GETALLOWLIST` is on.

## Application approvals (F19)

Hosts ask for one binary at a time; administrators approve or deny
(`crates/cmis/src/apps/`, `crates/cmis/src/admin/apps.rs`). A request never
replaces or removes an approval: approvals end only by expiry or an
administrator (ADR-0004).

- **Mode.** The replicated setting `cmis_settings.allowlist_mode` is `legacy`
  until a platform operator switches it (`ferrogate admin set-allowlist-mode
  approvals`, after the legacy import; runbook below). In `legacy` mode
  `SubmitAppRequest` answers `FAILED_PRECONDITION mode_legacy` (MIA keeps the
  request queued) and `SyncAllowlist` serves the host's hand-provisioned v1
  entries as a v2 body, so upgraded agents can already sync every 5 minutes.
  In `approvals` mode the v2 body is compiled from the host's active
  approvals, the legacy allowlist writes are refused (`mode_approvals`), and
  `ProposeAllowlist` from a pre-F19 agent records one `observed` request per
  new entry instead of adopting or queuing the set. Any administrator
  session can read the mode (`GetAllowlistMode`).
- **Host RPCs.** All three need the host proof (SVID, `cnf.jkt`, machine-key
  signature, ±300 s). Budgets per host and node: `CMIS_APP_SUBMIT_MAX_PER_HOUR`
  (30; a retry of a recorded request is free), `CMIS_APP_STATUS_MAX_PER_HOUR`
  (60), one `SyncAllowlist` per `CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS` (30).
  Open requests are capped per host (`CMIS_APP_MAX_PENDING_PER_HOST`, 50) and
  per host and user (`CMIS_APP_MAX_PENDING_PER_USER`, 10). A request equal to
  one denied within `CMIS_APP_DENIED_COOLDOWN_SECS` (86400; 0 disables) gets
  that denial back. Pending requests expire after `CMIS_APP_PENDING_TTL_SECS`
  (30 days).
- **Auto-update.** An approval with policy `AutoSamePathUser` approves later
  binaries at the same path for the same user when the path is protected or the
  signer is unchanged (or the approval says `path_user_only`), never for a
  hash once revoked or denied in the lineage, at most
  `CMIS_APP_AUTO_UPDATE_MAX_PER_DAY` (3) per lineage per day. The child copies
  the parent's expiry. Kill switches: `CMIS_APP_AUTO_UPDATE=off`,
  `CMIS_APP_AUTO_UPDATE_TIERS` (`tpm,host-key` by default; drop `host-key` to
  exclude the software tier) and the per-lineage freeze.
- **Decisions.** Viewers list and read; approvers approve, deny, edit, revoke,
  freeze and register directly (`ferrogate admin apps …`). Decisions and edits
  need a recent step-up. Expiry defaults to `CMIS_APPROVAL_DEFAULT_TTL_SECS`
  (180 days), may not exceed `CMIS_APPROVAL_MAX_TTL_SECS` (365 days), and
  "no expiry" needs `CMIS_APPROVAL_ALLOW_NO_EXPIRY=true`. `any_user` needs an
  explicit confirmation and combines with auto-update only on a protected path.
- **Direct registration (accepted risk D4).** By default an approver registers
  and approves in one step with a fresh TOTP or FIDO2 proof; the audit log
  records it as `AppApprovedBySameActor` — review that event type in the SIEM.
  `CMIS_ADMIN_STRICT_SOD=true` queues the request for a different approver
  instead (`AdminDirectRegistration`) and forbids deciding one's own request.
- **Sync and revocation.** Every change to a host's approvals bumps its
  generation to `max(generation + 1, unix_ms)`; MIA refuses lower generations.
  A revocation reaches an online host within one sync interval; offline hosts
  keep their last body until its `not_after` (`CMIS_ALLOWLIST_TTL_SECS`; 24 h
  is recommended once hosts sync). The leader's sweeper expires approvals and
  stale requests every 60 s. Keep CMIS clocks under NTP: a clock that steps
  backwards only delays new generations.
- **Audit and personal data.** Events carry ids, hashes and codes only (no
  user names, SIDs, paths or messages); user names, SIDs and paths stay in the
  ledger, readable by viewers and approvers (F19 §10). Store failures answer
  `UNAVAILABLE store_unavailable` and audit nothing.

### Migrating legacy allowlists to approvals (runbook)

F19 §11. The migration is reversible until the legacy bodies are deleted, which this
release never does. Both commands need a `ferrogate-platform-operators`
session and a recent step-up (the CLI asks for a TOTP code when needed).

1. **Prerequisites.** Every CMIS node runs this release (the mode is
   replicated; an older node would ignore it). F20 administrator accounts are
   in place.
2. **Upgrade the MIA fleet** and turn on `allowlist.sync = true`
   ([mia.md](mia.md)). Agents that are not upgraded keep using `GetAllowlist`
   (v1); they keep working through the switch with the limits in step 6.
3. **Dry run.** `ferrogate admin migrate-allowlists --dry-run` lists, per
   host, the entries that would become approvals ("legacy, no expiry") and
   the ones already imported, and writes nothing. A body stored under a key
   that is not a host UUID, or that does not decode, is reported as
   `skipped` and is never imported: fix or delete it while still in
   `legacy` mode.
4. **Import.** `ferrogate admin migrate-allowlists` creates, for each legacy
   entry, an `ACTIVE` approval with origin `legacy_import`, any path, manual
   updates and no expiry, with the uid and the `*` wildcard exactly as
   stored. The `host_allowlists` rows are not changed. One
   `AllowlistImported` event per host that gained approvals; re-running
   creates nothing new, and an import revoked later is never recreated. The
   import keeps the ledger in step with the legacy bodies: entries added to a
   body after an earlier run (still `legacy` mode) are imported by the next
   run, and an import whose entry was removed from its body — or whose body
   was deleted — is **revoked** (reason code 1000, one `ApprovalRevoked`
   event each), so a binary removed in `legacy` mode cannot come back after
   the switch. An entry removed and then added again stays revoked; register
   it with `ferrogate admin apps register` if it is still wanted. If the
   store fails part-way the command answers `UNAVAILABLE`: hosts already
   handled stay handled and audited, so simply re-run it.
5. **Review** the imported approvals: `ferrogate admin apps approvals
   --state active` (or the `legacy_only` filter of `ListApprovals`). Narrow or
   revoke wildcards (`*`, any user) you no longer want, and plan expiries:
   legacy imports have none.
6. **Switch.** `ferrogate admin set-allowlist-mode approvals`. CMIS refuses
   with `FAILED_PRECONDITION import_stale` while an import whose entry left
   its legacy body is still open (re-run the import; there is no override),
   and with `import_incomplete` while a legacy entry has no approval or a
   body was skipped; `--allow-unimported` overrides the latter after a
   warning (those callers are denied in `approvals` mode). Legacy writes
   check the mode inside their own transaction, so none lands after the
   switch, and the switch commits only if no legacy body changed since its
   checks (`ABORTED concurrent_change` otherwise: re-run the import, then
   the switch). The switch is
   audited as `AllowlistModeChanged`; switching to the mode in force changes
   nothing and is not audited. From now on:
   - upgraded agents sync the approvals within one interval;
   - old agents fetch `GetAllowlist`, compiled **lossy-safe**: only approvals
     they can enforce — any path, and a Unix uid, any user or a legacy
     import, valid until the document's `not_after` — are included; an
     approval with an exact path, a Windows SID or a nearer expiry is
     omitted, so that application is denied on old agents only;
   - `ferrogate allowlist set|delete|approve` are refused; `add` and `remove`
     map onto direct registration and revocation (`remove` lists the
     matches and asks; `--yes` when not on a terminal); pre-F19 proposals become
     `observed` requests (an approver must choose an any-path scope, since
     the path is unknown) and are never adopted.
7. **Rollback** (if needed): `ferrogate admin set-allowlist-mode legacy`. The
   CLI first shows how many live approvals other than legacy imports (in
   practice those created since the switch) the preserved legacy bodies do
   not carry — their callers are denied — and how many revoked or expired
   legacy imports the legacy bodies admit again, then asks for confirmation
   (`--yes` when not on a terminal; the RPC itself needs
   `confirm_rollback`). The approvals stay in the ledger; switching to
   `approvals` again restores them.
8. **Retire v1.** Once no pre-F19 agent remains (`GetAllowlist` traffic in the
   logs), set `CMIS_LEGACY_GETALLOWLIST=off` on every node. `GetAllowlist`
   then answers `FAILED_PRECONDITION legacy_getallowlist_disabled` in both
   modes; an old agent keeps its current file until that file's `not_after`
   and then fails closed. `GetAllowlist` is deprecated and will be removed in
   a later release.

### Administering approvals with `ferrogate-tui` (F21)

`ferrogate-tui` is a full-screen terminal UI for viewers and approvers
(`crates/ferrogate-tui`). It runs as an unprivileged user on a CMIS node (over
SSH) or on a workstation, and talks only to the **admin listener** over the
hybrid-PQC TLS transport with SPKI pinning. It has no database code: every
action is an `Admin` gRPC call authorised by CMIS exactly like the CLI's, so
running it on a CMIS node grants nothing extra.

1. **Configure** (no secrets): `$XDG_CONFIG_HOME/ferrogate/admin.toml`
   (`~/.config/…`), else `/etc/ferrogate/admin.toml`, or `--config <path>`:

   ```toml
   endpoint          = "https://127.0.0.1:8444"
   spki_pins         = ["<sha384-hex>"]   # required: no trust on first use
   device_token_path = ""                 # default $XDG_STATE_HOME/ferrogate/device-token (0600)
   refresh_secs      = 30                 # list auto-refresh (at least 5); 0 disables
   ```

   `FERROGATE_ADMIN_ENDPOINT` and `FERROGATE_ADMIN_SPKI_PIN` (comma-separated)
   override the file. The endpoint must be `https://host:port` with an
   **explicit port** (no path, query or user information): `https://cmis-1`
   is refused, because without a port the transport would dial 8443, the
   main listener, which by default presents the same certificate as the
   admin listener. Get the pin with `ferrogate spki-pin --tls-cert
   /etc/ferrogate/tls/cmis.crt` ([transport-tls.md](transport-tls.md)). Without
   a pin the TUI prints these instructions and exits (status 2); an endpoint
   that is not `https://` is refused, and so is a configuration file (or its
   directory or any directory above it, unless sticky) that is owned by
   someone other than you or root or is writable by group or others — it
   decides where your password goes. The file is opened once without
   following a symbolic link (a symlinked `admin.toml` is refused), checked
   on the open handle and read from it (at most 64 KiB).
   A wrong pin fails the TLS handshake before any username, password or code
   is sent, and an endpoint that does not answer within 10 s is reported as
   unreachable. Every call has a 30 s deadline, so a server that stops
   answering cannot hold the TUI: lock and quit wipe the session token at
   once and send `Logout` on a separate connection. The admin listener's optional client certificate
   (`CMIS_ADMIN_CLIENT_CA`) is not supported by the TUI yet: on such a
   listener use the CLI.
2. **Sign in** with username, password and a TOTP code (FIDO2 and enrollment
   are the tray admin client's, F22). Failures show one generic line or the
   throttle countdown. An expired password must be changed first.
3. **Work.** `1`–`6` switch Dashboard, Requests, Approvals, Hosts, Accounts,
   Sessions; `?` shows the key map. Lists use server-side filters (`f`, the
   F19 §7.5 fields of `ListAppRequests` and `ListApprovals`, validated inline:
   dates `YYYY-MM-DD`, hash prefix 8–96 hex, host UUID, text ≤ 128) and
   search (`/`), with paging (`n`/`p`) and order (`s`, newest or oldest
   first). Lists and details reload after every change you make.
   - **Approve** (`a`): safe defaults (manual each time, anchored, this user
     only, exact path, server default expiry); auto-update is preselected only
     on a protected path or for the same valid signer as the previous approved
     revision. "Any user" or "Path + user only" need an extra `y`. The review
     page shows everything; `y` sends with an idempotency key. When CMIS
     answers `step_up_required` the TUI asks for a TOTP code and retries
     **once** with the same key.
   - **Deny** (`d`) with a reason code (1 `unknown_software`, 2
     `policy_violation`, 3 `insufficient_justification`, 4 `duplicate`, 5
     `security_risk`, 6 `other`) and an optional message (≤ 200, no personal
     data).
   - **Edit** (`e`, approval detail): policy, continuity, expiry, note, and
     narrowing only; loosening continuity to "Path + user only" needs the
     extra `y`, and the review page flags it and a switch to auto-update;
     sent with `expected_row_version`. On `ABORTED` the TUI
     reloads, shows what changed and asks again.
   - **Revoke** (`x`): type the short id shown (`A-` and the **last** eight
     characters of the approval id) and pick a reason (1
     `no_longer_needed`, 2 `security_risk`, 3 `policy_violation`, 4
     `replaced`, 5 `other`; 1000 is the legacy import's). **Freeze** (`z`)
     toggles a lineage's auto-update.
   - **Add application** (`A`, `app.direct_register`): host UUID, canonical
     path, SHA-384 (96 hex), user, terms. The review page says whether it is
     registered and approved in one step (default) or queued for a different
     approver (`CMIS_ADMIN_STRICT_SOD=true`), and that the hash and path are
     your assertion. `y` **always** asks for a fresh TOTP code, even inside
     the step-up window; a wrong code changes nothing and the retry reuses the
     idempotency key.
4. **Leave.** `q` (confirm) or `Ctrl-C` logs out on the server and wipes the
   token; `Ctrl-L` locks at once. With no key press the TUI locks itself 30 s
   before the server idle timeout; a `session_invalid` answer returns to the
   sign-in screen with "Session ended". Lock and exit clear the screen.

Security notes: the password, TOTP codes and the session token live only in
zeroized memory (never on disk, in the clipboard or in a log; the TUI has no
logging). The device token is a throttle hint kept in a `0600` file and read
only from a private regular file of at most 1 KiB, never through a symlink.
A panic anywhere in the TUI stops it: nothing more is drawn, the session is
ended and the screen cleared. Every
string from a host or another administrator is rendered through
`sanitize::display`: control characters and escape sequences (including
OSC 52 clipboard writes and OSC 8 links) show as `\x1b`-style text, and bidi,
zero-width and other default-ignorable characters (variation selectors,
Hangul fillers, tag characters) as `⟨U+202E⟩`; widths are measured per
grapheme exactly as the terminal grid is filled, so a hostile path cannot
push text into the next column. `NO_COLOR` or `--monochrome` draws
without colours; the minimum terminal is 80×24.

Not in this release: the Hosts screen (CMIS has no `ListHosts` RPC yet),
account and session administration (read-only lists here; use `ferrogate
admin accounts|sessions`), bulk revocation from the lineage view, the
password generator, Portuguese strings and `--log-file`.

## Root key rotation

The composite issuance key is rotated annually in an air-gapped ceremony:

1. Quorum of 3-of-5 trusted operators assembles in a Faraday-shielded room.
2. The offline signer device produces a new composite root keypair inside an
   attested enclave; participants are video-recorded.
3. The new root signs the old root, and the old root signs the new root, for
   a 90-day cross-sign window.
4. JWKS publishes both roots during the cross-sign window with the new root
   listed first; verifiers prefer the newer key.
5. After the window, the old key is destroyed by zeroising all five Shamir
   shares simultaneously.

The step-by-step operator procedure — the `offline-signer` commands for each
step, the sealed-share/cross-sign/minutes formats, the destruction read-back,
and the staging dry-run — is in
[operations/root-key-ceremony.md](operations/root-key-ceremony.md) (feature F14).

## Adding a CMIS replica

1. Provision a node in a supported TEE (SEV-SNP or TDX).
2. The new node generates an attestation report and presents it to the
   existing Raft quorum.
3. Quorum members verify the report against the approved CMIS measurement
   allowlist; on success they sealed-deliver a key share to the new node.
4. The new node joins the Raft cluster and begins serving traffic after
   one heartbeat interval.

### Raft transport configuration

Each replica needs the same view of the cluster and a shared secret pair:

- `CMIS_CLUSTER_PEERS` — every peer as `id=raft_addr,api_addr`, `;`-separated,
  e.g. `1=cmis1:9601,cmis1:9602;2=cmis2:9601,cmis2:9602`. The addresses are
  what peers *dial*, so they must be routable from the other nodes (hostnames
  or stable IPs, not loopback).
- `CMIS_NODE_ID` — which entry above is this node.
- `CMIS_RAFT_SECRET`, `CMIS_API_SECRET` — shared across the fleet, ≥ 16 chars
  each. These authenticate the inter-node handshake; the secret never crosses
  the wire.
- `CMIS_RAFT_LISTEN` — the interface the Raft + management transports *bind*
  (default `0.0.0.0` for a multi-node cluster, so peers can reach this node).
  Must be an IP literal (`0.0.0.0`, `10.0.0.5`, or bracketed IPv6 such as
  `[::]`); a hostname fails startup.
- `CMIS_PEER_TLS=1` — encrypt the inter-node transport with TLS (recommended
  whenever the peers are not on a trusted private network). Zero-config: every
  node derives the same peer certificate from the shared secret, so split-brain
  detection works out of the box (no `UnknownIssuer` log spam). Supply
  `CMIS_PEER_TLS_CERT` + `CMIS_PEER_TLS_KEY` (PEM) for a stable certificate
  instead. Linux is the supported target for multi-node self-signed clusters
  (the trust step uses `SSL_CERT_FILE`, which macOS ignores). See
  [features/F05-cmis-ha.md](features/F05-cmis-ha.md) §"Inter-node transport
  security".

A runnable two-node example is in
[../docker/cluster-test/docker-compose.yml](../docker/cluster-test/docker-compose.yml).

## Removing a CMIS replica

1. Operator decommissions the node via the operations API (signed command).
2. Remaining quorum issues a `KeyShareRevoked` event and reissues fresh
   shares to the survivors. The departing node's share is no longer one of
   the valid 5; it cannot participate even if its enclave is preserved.

## Disaster recovery

- Loss of any single region: traffic shifts to the remaining regions via
  anycast; no operational action required.
- Loss of all but one region: the surviving region continues issuing SVIDs as
  long as a 3-of-5 share quorum is reachable. If quorum is lost, issuance
  halts; existing SVIDs remain valid until expiry, providing a graceful
  degradation window of up to one TTL (1 hour).
- Loss of quorum permanently: the offline root key ceremony provisions a
  new composite issuance key and re-seeds shares. All hosts must re-attest
  at next rotation.

The step-by-step drill procedures — with pre-flight, pass criteria, abort
paths, a runnable local rehearsal harness, and the drill log — are in
[operations/drills/](operations/drills/):
[region-loss](operations/drills/region-loss.md),
[mass-revocation](operations/drills/mass-revocation.md), and
[quorum-loss recovery](operations/drills/quorum-loss-recovery.md).

## Day-2 SRE concerns

- **Metrics.** Issuance latency p50/p99, attestation failure breakdown,
  CRL freshness, Raft commit lag, STH publish lag.
- **Alerts.** STH publish lag > 5 min, key-share reconstruction failure,
  RIM allowlist age > 24 h since last refresh, helper API denial rate spike.
  Per-alert response procedures are in [operations/runbooks/](operations/runbooks/):
  [STH lag](operations/runbooks/sth-lag.md),
  [CRL stale](operations/runbooks/crl-stale.md), and
  [key-share failure](operations/runbooks/key-share-failure.md).
- **Capacity.** The dominant cost is ML-DSA-65 signing (~1 ms on modern
  cores). A single CMIS replica handles ~1000 full attestations / second
  before saturating one core.
