# Networking, ports & firewall requirements

This page enumerates every listener FerroGate opens, who connects to whom, and
the firewall rules required for a working deployment. It complements
[ADR-0001](adr/0001-grpc-over-http-transport.md) (why the control plane is gRPC)
and the [architecture overview](architecture.md).

> Conventions in this document follow the configuration sketch in
> [cmis.md](cmis.md#configuration-sketch). Ports are operator-configurable; the
> values below are the documented defaults. Where the running binary is driven
> by an environment variable today, the variable is noted.

## Listener inventory

| Listener | Transport | Default | Wire protocol | Reachability |
|----------|-----------|---------|---------------|--------------|
| **CMIS control plane** | TCP | `:8443` | gRPC (HTTP/2) over hybrid PQC TLS 1.3 | Clients (MIA) + operators |
| **CMIS admin listener** | TCP | `127.0.0.1:8444` | gRPC (HTTP/2) over hybrid PQC TLS 1.3, optional mTLS | Operators only (management network) |
| **Raft peer transport** | TCP | `:9443` | hiqlite peer protocol over TLS | CMIS peers only |
| **Raft management API** | TCP | separate port | hiqlite management/forwarding | CMIS peers only |
| **Helper API (Linux)** | Unix domain socket | `/run/ferrogate/mia.sock` | CBOR request/response | Local host only |
| **Helper API (Windows)** | Named pipe | `\\.\pipe\ferrogate-mia` | CBOR request/response | Local host only |

There is **no** separate HTTP `/healthz` and no Prometheus/metrics listener.
Health is an RPC on the control plane (`:8443`). Since 0.29.0 (feature F20
Phase 0) administration has its own listener (`:8444`, §1a); the legacy admin
RPCs can still be reached on `:8443` during the migration, but only with an
authenticated administrator session (see below).

## 1. CMIS control plane — TCP `:8443`

The single client-facing listener. One `tonic` gRPC server, no other HTTP
surface. Configured via the `[server] listen` key (binary env var:
`CMIS_LISTEN`).

All control-plane operations multiplex onto this one port:

- **Issuance / lifecycle:** `Attest` (bidirectional stream), `FetchSVID`,
  `Rotate` (a host method since T293: host proof under `ferrogate-rotate-v1`,
  `CMIS_ROTATE_MAX_PER_HOUR`), `JWKS`.
- **Audit transparency:** `LatestSth`, `InclusionProof`, `ConsistencyProof`.
- **Forwarding:** `AppendAuditEvent`, a host method authenticated by a host
  proof — the host's SVID plus a machine-key signature over a fresh,
  single-use document that binds the event (context
  `ferrogate-audit-forward-v1`) — and rate-limited per host
  (`CMIS_AUDIT_FORWARD_MAX_PER_MIN`). See
  [operations.md](operations.md#audit-forwarding-from-hosts).
- **Legacy admin RPCs:** `SetAllowlist`, `DeleteAllowlist`, `ListAllowlists`,
  `ListProposals`, `DeleteProposal`, `RevokeSvid`, `RevokeHost`, `BumpEpoch`,
  `ListSvids`, and `UnrevokeHost` (T296). They are **not** gated at the TLS layer: this listener does not
  request client certificates, so every MIA host that can reach `:8443` can
  also reach these methods. What gates them is the authorization layer in
  front of every listener: each call needs an administrator session token
  (`authorization: Bearer …`, from `ferrogate admin login`), a group that
  grants the method's permission and, for writes, a recent second-factor
  step-up; otherwise CMIS answers `UNAUTHENTICATED` or `PERMISSION_DENIED`.
  They are served here only while `CMIS_LEGACY_ADMIN_ON_MAIN=true` (the 0.29
  default, for old automation paths); set it to `false` to serve them only on
  the admin listener. On a plaintext bring-up listener (no `CMIS_TLS_*`) they
  answer `FAILED_PRECONDITION (tls_required)`. Before 0.29.0 these RPCs
  performed no caller check at all.
- **Readiness:** `Health` returns Raft role and cluster health; load balancers
  treat `!healthy` or `role == UNKNOWN` as not-ready.

**TLS:** a single hybrid PQC TLS 1.3 certificate (`hybrid_only = true`) secures
this port. See [F01 — Hybrid PQC TLS](features/F01-hybrid-pqc-tls.md).

**Load balancer requirement:** because gRPC needs HTTP/2 end-to-end, the LB in
front of CMIS must do **L4 / TLS passthrough** (or be HTTP/2-aware). An
HTTP/1.1-terminating L7 proxy will break streaming. The reference topology uses
an L4 anycast / Maglev LB with TLS passthrough.

## 1a. CMIS admin listener — TCP `:8444`

The administrator surface (feature F20): the `ferrogate.admin.v1.Admin`
service (login, sessions, step-up, accounts, second factors) plus the legacy
admin RPCs of `MachineIdentity`. Configured by `CMIS_ADMIN_LISTEN` (default
`127.0.0.1:8444`).

- **TLS only.** Hybrid-PQC TLS 1.3 (`X25519MLKEM768` only), with
  `CMIS_ADMIN_TLS_CERT`/`CMIS_ADMIN_TLS_KEY` or, when unset, the main
  listener's certificate. Without any certificate the admin listener does not
  start, and admin methods on the plaintext main listener answer
  `FAILED_PRECONDITION (tls_required)`. Clients pin the listener's SPKI like
  the control plane.
- **Optional mTLS.** With `CMIS_ADMIN_CLIENT_CA` set, the listener requires a
  client certificate from that CA in addition to the session.
- **Session authentication.** Every admin method needs a session obtained with
  a password plus a second factor (TOTP, or FIDO2 from the tray admin client),
  bound to the source IP, expiring after 15 minutes idle and 12 hours
  absolute (the defaults, which are also the maxima). Authorization is by group, one table maps each method to its
  permission, and anything unclassified is refused.
- **Exposure.** Bind it to loopback (the default, for `ferrogate` on the CMIS
  node) or to a management interface reachable only from administrator
  workstations (VPN). It **must never** be reachable from the internet or from
  the MIA host network, and it must not sit behind a proxy: login throttling
  uses the TCP peer address.

## 2. Raft cluster — TCP `:9443` (+ management API port)

CMIS nodes replicate issued-SVID hashes, CRL deltas, and the RIM allowlist via
[hiqlite](https://crates.io/crates/hiqlite) (openraft + SQLite). Configured via
`[raft] peers = ["cmis-1:9443", ...]`.

- **Peer transport** (`:9443` by default): the Raft log/replication channel.
- **Management API** (separate port, `listen_addr_api`): follower→leader request
  forwarding and cluster management.

Both are **bidirectional, mesh** — every node dials every other node. These
ports must be reachable *only* between CMIS nodes and must **never** be exposed
to clients or the internet. Peer transport carries its own shared-secret auth
(`secret_raft` / `secret_api`, ≥16 chars) and TLS.

## 3. Helper API — local IPC, no TCP

MIA serves child-token minting to co-located applications over a local IPC
channel, never the network:

- **Linux:** Unix domain socket, default `/run/ferrogate/mia.sock`, mode `0660`,
  owned by group `ferrogate-clients`. On by default (path overridable via
  `FERROGATE_HELPER_SOCKET`, switched off with `FERROGATE_HELPER_ENABLE=0` /
  `helper.enable = false`); mode overridable via `FERROGATE_HELPER_SOCKET_MODE`.
- **Windows:** named pipe `\\.\pipe\ferrogate-mia`, ACL'd to the
  `FerroGateClients` local group.

Callers are authenticated by the kernel (`SO_PEERCRED` + IMA on Linux;
`GetNamedPipeClientProcessId` + `WinVerifyTrust` on Windows), so no transport
encryption is used. **No firewall rule is required or appropriate** — this never
crosses the host boundary. See [helper-api.md](helper-api.md).

## Connection directions

```
 application ──(UDS / named pipe)──▶ MIA          [local host only]
        MIA ──(gRPC/TLS :8443)─────▶ CMIS         [client → server]
   operator ──(gRPC/TLS :8444)─────▶ CMIS         [admin RPCs, session-authenticated]
       CMIS ◀─(Raft :9443 + API)──▶ CMIS (peers)  [bidirectional mesh]
       CMIS ──(HTTPS)─────────────▶ Sigsum log                  [audit egress]
```

## Firewall rules

### CMIS nodes

**Inbound**

| Source | Port | Purpose |
|--------|------|---------|
| Clients (MIA) + operators | TCP `8443` | gRPC control plane |
| Administrator workstations / management network only | TCP `8444` | Admin listener (when bound off loopback) |
| Other CMIS nodes only | TCP `9443` | Raft peer transport |
| Other CMIS nodes only | TCP *(management API port)* | Raft management/forwarding |

**Outbound**

| Destination | Port | Purpose |
|-------------|------|---------|
| Other CMIS nodes | TCP `9443` + management API port | Raft mesh |
| Sigsum log | TCP `443` | Audit notarization |

> Restrict `9443` and the management API port to the CMIS peer set (security
> group / source-IP allowlist). Exposing them publicly is a misconfiguration.

### MIA hosts

**Outbound only**

| Destination | Port | Purpose |
|-------------|------|---------|
| CMIS (via LB VIP) | TCP `8443` | Attestation, fetch, rotate |

MIA opens **no inbound network ports**. Its only server endpoint is the local
helper socket/pipe.

### Load balancer

- Forward TCP `8443` to the CMIS pool with **TLS passthrough** (L4). Do not
  terminate TLS or downgrade to HTTP/1.1. TLS is terminated on the CMIS node
  itself (hybrid-PQC, `X25519MLKEM768`-only) — see
  [transport-tls.md](transport-tls.md).
- Health-check the pool via the gRPC `Health` RPC, not an HTTP path.

## Quick reference

| Port | Who opens it | Who may connect | Exposure |
|------|--------------|-----------------|----------|
| `8443/tcp` | CMIS | MIA clients, operators | Public (behind L4 LB) |
| `8444/tcp` | CMIS | Administrators | Loopback by default; management network only, never public |
| `9443/tcp` | CMIS | CMIS peers only | Private |
| *(mgmt API)/tcp* | CMIS | CMIS peers only | Private |
| `443/tcp` (egress) | CMIS | → Sigsum | Egress |
| UDS / named pipe | MIA | Local apps | Host-local, no firewall |
