# CMIS — Central Machine Identity Service

## Responsibilities

- Terminate hybrid-PQC TLS from MIA clients.
- Run the four-phase attestation handshake.
- Sign SVIDs using the composite (Ed25519 + ML-DSA-65) issuance key.
- Replicate issued-SVID metadata via Raft across the cluster.
- Append every protocol event to the Merkle-chained audit log.
- Serve JWKS, CRL deltas, and RIM policy versions.

## Process model

- Single multi-threaded Tokio runtime, ~N+1 worker threads (one per core, one
  for I/O reactor).
- `tonic` gRPC only, on two listeners (rationale:
  [ADR-0001](adr/0001-grpc-over-http-transport.md); ports and firewall rules:
  [networking.md](networking.md)): the control plane (`CMIS_LISTEN`, `:8443`)
  and, since 0.29.0, the admin listener (`CMIS_ADMIN_LISTEN`, default
  `127.0.0.1:8444`, TLS only). One authorization layer sits in front of both
  (see "Administrator authentication" below).
- A small set of background tasks: Raft tick, audit-flush, CRL publisher,
  RIM refresh, key-share heartbeat.

## TEE integration

CMIS only runs inside an attested enclave:

- **AMD SEV-SNP:** uses the VCEK-derived sealing key for the local key-share
  envelope; the launch measurement (`MRENCLAVE`-equivalent) is included in
  attestation reports peers exchange before Raft membership.
- **Intel TDX:** equivalent flow using the TDX quote and MRTD.

A node that cannot produce a valid remote attestation report is refused
membership and cannot reconstruct a key share.

## Issuance key handling

The composite issuance key is never present in whole form except transiently
in mlocked, zeroize-on-drop memory inside an attested enclave.

- Shamir 3-of-5 split over GF(2^256).
- Each share is sealed against a *distinct* CMIS measurement so a single
  compromised image cannot unseal a quorum.
- Reconstruction is gated by mutual SEV-SNP / TDX attestation between peers
  and tunnelled over ML-KEM-768 PSK channels.
- Reconstructed key is dropped immediately after issuing a batch; nothing is
  written to disk.

Annual root rotation is performed offline (see [operations.md](operations.md)).

### Bring-up persistence (pre-TEE)

Until the TEE-sealed path above is wired, the shipped binary keeps the issuer
key stable across restarts by persisting a **32-byte master seed** and rebuilding
the composite key deterministically (`Issuer::from_seed`). Only the seed is
secret material at rest — the expanded private key never touches disk.
`CMIS_ISSUER_KID` (default `cmis-dev-1`) and `CMIS_TRUST_DOMAIN` (default
`ferrogate.dev`) set the published `kid` and trust domain and must stay constant
for a given seed, since the `kid` is how verifiers resolve the JWKS key.

**Signature lifetimes** are operator-tunable. `CMIS_SVID_TTL_SECS` (default 30
days) sets the SVID lifetime and `CMIS_ALLOWLIST_TTL_SECS` (default 96 h) sets
the caller-allowlist validity window. Both floor at 96 h and cap at 30 days; a
value outside that range is clamped (a non-integer is ignored with a warning).
The allowlist TTL must not exceed the MIA's `allowlist.max_age_secs`
(`FERROGATE_ALLOWLIST_MAX_AGE_SECS`, also defaulting to 96 h) or freshly signed
lists will be rejected as too old.

**The seed lives in the Raft-replicated store, not a per-node file.** It is the
cluster's single signing identity: on the first boot of a fresh cluster the
*leader* establishes the seed once (adopting an existing on-disk seed if there
is one, else minting a fresh one) and every other node adopts it from the
replicated store. This is what lets an HA cluster sit behind one SRV name — a
client that load-balances across nodes always fetches an allowlist signed by,
and verified against, the same key. (Before this, each node generated its own
seed in a non-replicated local file, so a client could fetch an allowlist signed
by one node yet verify it against another's enrollment key → spurious
`bad signature`.)

`CMIS_ISSUER_KEY` (default `/var/lib/ferrogate/issuer/issuer.seed`) is no longer
the source of truth on an established cluster — it is only (a) the migration
source the leader promotes on first boot and (b) a `0600` disaster-recovery
mirror CMIS keeps in lock-step with the canonical seed. Because every node
mirrors the *same* cluster seed, the file can no longer diverge between nodes,
and a node whose mirror is stale is healed to the canonical seed on next boot.

Losing the seed everywhere (replicated store *and* every mirror) rotates the
signing key, which invalidates every issued SVID, the allowlist a MIA has
adopted, and the published CRL — MIAs then fail closed (`crl-stale` / bad
signature). Keep the Raft volume durable and back up the mirror.

## Crate layout (target)

```
crates/
├── cmis/                 # gRPC server binary
├── ferro-crypto/         # Composite signatures, hybrid TLS provider
├── ferro-attest/         # TPM 2.0 quote verification + RIM matching
├── ferro-audit/          # Merkle-chained WORM audit log
├── ferro-proto/          # Generated tonic stubs (proto3)
└── ferro-tee/            # SEV-SNP / TDX glue, Shamir reconstruction
```

The MIA shares `ferro-crypto`, `ferro-proto`, and `ferro-audit` but not
`ferro-tee`.

## gRPC surface (proto3)

A representative subset (the authoritative service is
`crates/ferro-proto/proto/machine_identity.proto`):

```proto
service MachineIdentity {
  rpc Attest           (stream AttestRequest) returns (stream AttestResponse);
  rpc FetchSVID        (FetchRequest)         returns (SVIDBundle);
  rpc Rotate           (RotateRequest)        returns (SVIDBundle);
  rpc JWKS             (JWKSRequest)          returns (JWKSResponse);

  // Caller-allowlist provisioning (see allowlist-provisioning.md).
  rpc GetEnrollmentKey (GetEnrollmentKeyRequest) returns (GetEnrollmentKeyResponse);
  rpc GetAllowlist     (GetAllowlistRequest)     returns (GetAllowlistResponse);
  rpc SetAllowlist     (SetAllowlistRequest)     returns (SetAllowlistResponse);    // admin
  rpc DeleteAllowlist  (DeleteAllowlistRequest)  returns (DeleteAllowlistResponse); // admin
  rpc ListAllowlists   (ListAllowlistsRequest)   returns (ListAllowlistsResponse);  // admin

  // F19 application registration (host proof, see below).
  rpc SubmitAppRequest    (SubmitAppRequestRequest)    returns (SubmitAppRequestResponse);
  rpc GetAppRequestStatus (GetAppRequestStatusRequest) returns (GetAppRequestStatusResponse);
  rpc SyncAllowlist       (SyncAllowlistRequest)       returns (SyncAllowlistResponse);

  // (plus the revocation, audit-log, and health RPCs.)
}
```

- `Attest` is the only RPC that does not require an existing valid SVID; the
  client authenticates anonymously at the TLS layer and proves identity in-band
  via the four-phase protocol.
- `Rotate` requires presenting the current SVID; if PCRs and `policy_id` are
  unchanged and the SVID is within its 24 h re-attestation window, no TPM
  interaction is needed.
- `JWKS` carries the composite verification key set plus an extension
  `x-ferrogate-crl` containing a signed CRL delta.
- `GetEnrollmentKey`/`GetAllowlist` are unauthenticated (public key material and
  signature-protected allowlist bodies); `Set`/`Delete`/`ListAllowlists` are
  admin RPCs that need an administrator session, like revocation (see
  "Administrator authentication"). Allowlists are keyed by EK-derived host UUID
  and stored in the same backend as issued SVIDs (the `host_allowlists` Raft
  keyspace when clustered). A store write that fails is returned as
  `UNAVAILABLE (store_unavailable)`, never reported as done.
- `AppendAuditEvent` is a host method: it needs the F19 §7.1 host proof (SVID
  + machine-key signature over a fresh `{v, host_uuid, issued_at, nonce,
  event_sha384}` document, context `ferrogate-audit-forward-v1`), accepts only
  host-originated event types and is rate-limited per host
  (`CMIS_AUDIT_FORWARD_MAX_PER_MIN`, default 600/min). The shared verifier is
  `cmis::host_auth`, reused by the F19 host RPCs.
- `SubmitAppRequest`, `GetAppRequestStatus` and `SyncAllowlist` (F19,
  `crates/cmis/src/apps/`) are host methods with the same proof, each under
  its own context (`ferrogate-app-request-v1`, `ferrogate-app-status-v1`,
  `ferrogate-allowlist-sync-v1`). A submission is deduplicated before any
  write, auto-approved under an `AutoSamePathUser` approval when every F19
  §5.3 condition holds, or queued `PENDING`; it never replaces or removes an
  approval. Status only answers for the caller's own requests. `SyncAllowlist`
  serves the host-bound allowlist **v2** (context `ferrogate-allowlist-v2`)
  with a monotonic generation, or `not_modified`. While the replicated
  `allowlist_mode` is `legacy` (the default until the M38 switch) submissions
  answer `FAILED_PRECONDITION mode_legacy` and `SyncAllowlist` serves the
  host's legacy v1 entries in v2 form. `GetAllowlist` is unchanged and never
  serves v2. Administrators decide requests through the `Admin` service
  (`ListAppRequests` … `AdminRegisterApplication`, F19 §5.4); a leader-only
  sweeper expires stale requests and approvals every 60 s. Details:
  [operations.md](operations.md#application-approvals-f19).

## Administrator authentication

Feature [F20](features/F20-admin-authentication.md), Phase 0 shipped in 0.29.0
(`crates/cmis/src/admin/`):

- Local administrator accounts: Argon2id passwords (optional pepper,
  blocklist, history, 6-month expiry) and a mandatory second factor — TOTP for
  every client, FIDO2/WebAuthn from the tray admin client.
- Opaque session tokens, stored only as hashes, bound to the source IP, with
  idle and absolute expiry, step-up for sensitive methods and server-side
  revocation; NRM §5.3.5 progressive login throttling keyed by IP.
- One method → access table (`admin::authz::METHOD_ACCESS`) drives the tower
  layer on every listener and the per-handler guards; a method missing from it
  is refused, and a test proves every compiled RPC is classified. Access is
  `Public`, `Host` (host proof in the handler), `AdminPublic` (login and
  enrollment, TLS only) or `Session` (permission from groups, optional
  step-up).
- Admin methods are never served without TLS (`FAILED_PRECONDITION
  tls_required`); the legacy admin RPCs are also served on the control plane
  while `CMIS_LEGACY_ADMIN_ON_MAIN=true`.
- Every login, account change and admin action is audited under a
  pseudonymous administrator id.

Every `CMIS_ADMIN_*` variable, the bootstrap of the first account, CLI sign-in,
the 0.29.0 upgrade notes and the known limitations are in
[operations.md](operations.md#administrator-access-f20).

## Configuration sketch

```toml
[server]
listen        = "0.0.0.0:8443"
spiffe_trust_domain = "ferrogate.prod"

[tls]
# The shipped binary reads these from env: CMIS_TLS_CERT / CMIS_TLS_KEY
# (both or neither). Hybrid-only (X25519MLKEM768) is enforced by the provider.
# See transport-tls.md for the full configuration and the SPKI pin recipe.
hybrid_only   = true
cert          = "/var/lib/ferrogate/cmis.crt"   # composite X.509
key           = "/var/lib/ferrogate/cmis.key"   # references TEE-sealed key id

[tee]
provider      = "sev-snp"                       # or "tdx"
peer_roots    = "/etc/ferrogate/peer-roots.pem"

[raft]
# The shipped binary reads these from env. All durable state (issued SVIDs,
# host allowlists, pending allowlist proposals) lives in this store. With no
# CMIS_CLUSTER_PEERS set, CMIS runs a single-node cluster: it elects itself
# leader, never looks for peers, and still persists to data_dir across
# restarts. Multi-node: CMIS_CLUSTER_PEERS="1=h1:9601,h1:9602;2=h2:9601,..."
# plus CMIS_NODE_ID and shared CMIS_RAFT_SECRET / CMIS_API_SECRET. Multi-node
# nodes bind CMIS_RAFT_LISTEN (default 0.0.0.0) so peers can reach them, and
# CMIS_PEER_TLS=1 encrypts the inter-node transport (secret-authenticated) so
# the cluster need not be pinned to a private network. Self-signed mode derives
# a shared peer cert from the secret on every node, so split-brain detection
# works with no cert distribution (Linux). See F05.
peers         = ["cmis-1:9443", "cmis-2:9443", "cmis-3:9443"]
node_id       = 1                               # 1.. ; node 1 bootstraps
data_dir      = "/var/lib/ferrogate/raft"       # hiqlite SQLite state + WAL (CMIS_RAFT_DIR)
peer_tls      = true                            # CMIS_PEER_TLS=1 (rustls inter-node transport)

[rim]
allowlist     = "/var/lib/ferrogate/rim/current.json"
generations   = 6

[admin]
# The shipped binary reads these from env (full table: operations.md
# "Administrator access"). Admin listener, TLS only, never internet-facing.
listen               = "127.0.0.1:8444"         # CMIS_ADMIN_LISTEN
client_ca            = ""                       # CMIS_ADMIN_CLIENT_CA (optional mTLS)
legacy_admin_on_main = true                     # CMIS_LEGACY_ADMIN_ON_MAIN
strict_sod           = false                    # CMIS_ADMIN_STRICT_SOD
secrets_key          = "/var/lib/ferrogate/admin/secrets.key"          # CMIS_ADMIN_SECRETS_KEY_FILE
audit_pseudonym_key  = "/var/lib/ferrogate/admin/audit-pseudonym.key"  # CMIS_AUDIT_PSEUDONYM_KEY_FILE
tray_fido2_groups    = ["ferrogate-approvers"]  # CMIS_ADMIN_TRAY_FIDO2_GROUPS
audit_forward_max_per_min = 600                 # CMIS_AUDIT_FORWARD_MAX_PER_MIN (host proof RPC)

[audit]
worm_dir      = "/var/lib/ferrogate/audit"      # local-disk WORM store (O_CREAT|O_EXCL)
sigsum_log    = "https://sigsum.example.org/log1"
```

## Error model

All client-visible errors map to a small fixed set of gRPC status codes; the
*detailed reason* is never returned to the client to avoid oracles. Detailed
failure reasons go only to the audit log and the CMIS log. Host-proof and
admin methods put one stable reason code per class in the status message (in
parentheses below) — for example every host-authentication failure is the same
`host_auth_failed`.

| Condition | gRPC status |
|-----------|-------------|
| TLS group not hybrid | (handshake aborted before RPC) |
| Quote verification failed | `PERMISSION_DENIED` |
| PCRs not in RIM | `FAILED_PRECONDITION` |
| Credential activation mismatch | `PERMISSION_DENIED` |
| AIK signature over CSR invalid | `PERMISSION_DENIED` |
| Replay of nonce | `ABORTED` |
| Internal (signer unavailable, …) | `UNAVAILABLE` |
| Replicated-store write failed | `UNAVAILABLE` (`store_unavailable`) |
| Host proof missing or invalid (SVID, revoked, `cnf.jkt`, signature, freshness, replay, event digest) | `UNAUTHENTICATED` (`host_auth_failed`) |
| Host proof document names another host | `PERMISSION_DENIED` (`host_mismatch`) |
| Host over its rate limit | `RESOURCE_EXHAUSTED` (`rate_limited`, `retry-after`) |
| Host at its open-request cap (F19) | `RESOURCE_EXHAUSTED` (`too_many_pending`, `retry-after`) |
| F19 field invalid (with `x-ferrogate-field`) | `INVALID_ARGUMENT` (`field_too_long`, `path_not_absolute`, `bad_sha`, …) |
| F19 submission while `allowlist_mode` is `legacy` | `FAILED_PRECONDITION` (`mode_legacy`) |
| F19 transition from the wrong state / stale `row_version` | `FAILED_PRECONDITION` (`invalid_state`) / `ABORTED` (`row_version_mismatch`) |
| Deciding one's own request under strict SoD | `PERMISSION_DENIED` (`sod_self_approval`) |
| Admin method without a valid session | `UNAUTHENTICATED` (`session_invalid`) |
| Admin method without the permission | `PERMISSION_DENIED` (`permission_denied`) |
| Admin method over plaintext | `FAILED_PRECONDITION` (`tls_required`) |
