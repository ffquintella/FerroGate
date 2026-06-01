# ADR-0001 — gRPC over HTTP/REST for the control plane

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** FerroGate core team
- **Scope:** CMIS↔MIA and CMIS↔CMIS control plane. Does **not** cover the local
  helper API (see [Consequences](#consequences)).

## Context

FerroGate's control plane carries the machine-identity issuance protocol between
the Machine Identity Agent (MIA) and the Central Machine Identity Service
(CMIS). The defining workload is the **attestation handshake** described in
[protocol.md](../protocol.md): a host obtains an SVID through a four-phase
exchange.

The shape of that exchange constrains the transport:

1. **The server speaks first.** Phase 2 begins with the server sending a
   `Nonce` that becomes the `qualifyingData` for the TPM quote. The client
   cannot proceed until it receives a server-chosen, single-use value.
2. **It is multi-phase and stateful within one connection.** TLS handshake →
   quote verification → credential-activation challenge/response → CSR and
   issuance. Each phase depends on state established by the previous one, and
   the credential-activation step is a server→client challenge that the client
   must answer.
3. **It is bidirectional.** Both parties send multiple messages, interleaved,
   over the lifetime of a single logical session.

A conventional HTTP/REST design (client-initiated request/response, one
resource per call, stateless server) fits this poorly:

- Server-initiated messages (the nonce, the activation challenge) have to be
  faked with polling or long-polling.
- Cross-phase state must be carried in an explicit server-side session keyed by
  a correlation token threaded through every request — a bespoke state machine
  we would hand-roll and have to secure.
- The protocol's framing and ordering guarantees would be reimplemented on top
  of HTTP instead of being provided by the transport.

Secondary considerations also favored a schema-first RPC framework: a single
typed service surface is easier to reason about as a security boundary than a
sprawl of REST endpoints, and a fixed status-code taxonomy supports the
oracle-avoidance requirement in [cmis.md](../cmis.md) (clients see only a small
fixed set of codes; reasons go to the audit log).

## Decision

**Use gRPC with Protocol Buffers (proto3), implemented with `tonic`/`prost`,
for the entire control plane.** The attestation handshake is modeled as a
**bidirectional streaming RPC**:

```proto
// crates/ferro-proto/proto/machine_identity.proto
rpc Attest (stream AttestRequest) returns (stream AttestResponse);
// Four-phase streaming attestation handshake. The server speaks first with
// a Nonce, then drives challenge/response and finally returns the SVID.
```

All other control-plane operations (`FetchSVID`, `Rotate`, `JWKS`, the admin
`RevokeSvid`/`RevokeHost`/`BumpEpoch` RPCs, the audit-transparency
`LatestSth`/`InclusionProof`/`ConsistencyProof` RPCs, and `Health`) are unary or
server-streaming RPCs on the **same** gRPC service, served from a single
`tonic` listener. CMIS exposes no other listeners and no HTTP/REST surface.

The control plane runs over hybrid post-quantum TLS 1.3 (see
[F01 — Hybrid PQC TLS](../features/F01-hybrid-pqc-tls.md)). Because gRPC runs on
HTTP/2, this is still "HTTP transport" at the wire level — the decision is about
*RPC semantics*, not about avoiding HTTP/2 framing.

## Alternatives considered

- **HTTP/REST + JSON.** Rejected: cannot model server-first, multi-phase,
  bidirectional exchange without reimplementing session state and faking
  server-push. Largest surface area to secure.
- **HTTP/REST + WebSocket upgrade for the handshake, REST for the rest.**
  Rejected: introduces two transports and two framing models for one control
  plane, and we would still hand-roll message framing inside the socket. gRPC
  streaming gives the same bidirectionality with a typed schema and one server.
- **Plain protobuf over a raw TLS socket (no gRPC).** Rejected: we would
  rebuild multiplexing, deadlines, status codes, and streaming flow control
  that `tonic` already provides.

## Consequences

**Positive**

- The four-phase handshake maps directly onto one streaming RPC; phase state
  lives in the stream, not in a separate session store.
- One typed service surface and one listener per node — a smaller, more
  auditable boundary.
- gRPC status codes give the fixed, reason-free error taxonomy the threat model
  wants.
- Schema-driven clients/servers via `prost`; the `.proto` is the contract.

**Negative / trade-offs**

- gRPC requires HTTP/2 end-to-end. Load balancers must do **L4 / TLS
  passthrough** (or be HTTP/2-aware); naive L7 HTTP/1.1 proxies will break
  streaming. This is reflected in the [architecture](../architecture.md)
  topology (L4 anycast / Maglev, TLS passthrough).
- Browsers cannot speak native gRPC; this is acceptable because FerroGate
  clients are agents (MIA) and operators, not web browsers. No gRPC-Web gateway
  is provided.
- Debugging requires gRPC-aware tooling (`grpcurl`) rather than `curl`.

**Out of scope — the local helper API.** MIA↔application traffic does **not**
use gRPC. It uses CBOR request/response over a Unix Domain Socket (Linux) or
Named Pipe (Windows), because that path is local, kernel-attested, and
single-exchange. See [helper-api.md](../helper-api.md). This ADR governs only
the network control plane.

## References

- [Attestation protocol](../protocol.md)
- [CMIS server](../cmis.md)
- [Architecture](../architecture.md)
- [Networking, ports & firewall requirements](../networking.md)
- `crates/ferro-proto/proto/machine_identity.proto`
