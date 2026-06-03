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
| **Raft peer transport** | TCP | `:9443` | hiqlite peer protocol over TLS | CMIS peers only |
| **Raft management API** | TCP | separate port | hiqlite management/forwarding | CMIS peers only |
| **Helper API (Linux)** | Unix domain socket | `/run/ferrogate/mia.sock` | CBOR request/response | Local host only |
| **Helper API (Windows)** | Named pipe | `\\.\pipe\ferrogate-mia` | CBOR request/response | Local host only |

There is **no** separate HTTP `/healthz`, no Prometheus/metrics listener, and no
admin port. Health and admin operations are RPCs on the gRPC service (`:8443`),
not standalone listeners.

## 1. CMIS control plane — TCP `:8443`

The single client-facing listener. One `tonic` gRPC server, no other HTTP
surface. Configured via the `[server] listen` key (binary env var:
`CMIS_LISTEN`).

All control-plane operations multiplex onto this one port:

- **Issuance / lifecycle:** `Attest` (bidirectional stream), `FetchSVID`,
  `Rotate`, `JWKS`.
- **Audit transparency:** `LatestSth`, `InclusionProof`, `ConsistencyProof`.
- **Forwarding:** `AppendAuditEvent`.
- **Admin (operator-only TLS credentials):** `RevokeSvid`, `RevokeHost`,
  `BumpEpoch`. These are *not* on a separate port — they are gated at the TLS
  layer (see [operations.md](operations.md)).
- **Readiness:** `Health` returns Raft role and cluster health; load balancers
  treat `!healthy` or `role == UNKNOWN` as not-ready.

**TLS:** a single hybrid PQC TLS 1.3 certificate (`hybrid_only = true`) secures
this port. See [F01 — Hybrid PQC TLS](features/F01-hybrid-pqc-tls.md).

**Load balancer requirement:** because gRPC needs HTTP/2 end-to-end, the LB in
front of CMIS must do **L4 / TLS passthrough** (or be HTTP/2-aware). An
HTTP/1.1-terminating L7 proxy will break streaming. The reference topology uses
an L4 anycast / Maglev LB with TLS passthrough.

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
  owned by group `ferrogate-clients`. Enabled via `FERROGATE_HELPER_SOCKET`;
  mode overridable via `FERROGATE_HELPER_SOCKET_MODE`.
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
   operator ──(gRPC/TLS :8443)─────▶ CMIS         [admin RPCs]
       CMIS ◀─(Raft :9443 + API)──▶ CMIS (peers)  [bidirectional mesh]
       CMIS ──(HTTPS)─────────────▶ Sigsum log                  [audit egress]
```

## Firewall rules

### CMIS nodes

**Inbound**

| Source | Port | Purpose |
|--------|------|---------|
| Clients (MIA) + operators | TCP `8443` | gRPC control plane |
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
  terminate TLS or downgrade to HTTP/1.1.
- Health-check the pool via the gRPC `Health` RPC, not an HTTP path.

## Quick reference

| Port | Who opens it | Who may connect | Exposure |
|------|--------------|-----------------|----------|
| `8443/tcp` | CMIS | MIA clients, operators | Public (behind L4 LB) |
| `9443/tcp` | CMIS | CMIS peers only | Private |
| *(mgmt API)/tcp* | CMIS | CMIS peers only | Private |
| `443/tcp` (egress) | CMIS | → Sigsum | Egress |
| UDS / named pipe | MIA | Local apps | Host-local, no firewall |
