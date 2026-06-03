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
- One `tonic` gRPC server, no other listeners (rationale:
  [ADR-0001](adr/0001-grpc-over-http-transport.md); ports and firewall rules:
  [networking.md](networking.md)).
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

```proto
service MachineIdentity {
  rpc Attest    (stream AttestRequest) returns (stream AttestResponse);
  rpc FetchSVID (FetchRequest)         returns (SVIDBundle);
  rpc Rotate    (RotateRequest)        returns (SVIDBundle);
  rpc JWKS      (JWKSRequest)          returns (JWKSResponse);
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
peers         = ["cmis-1:9443", "cmis-2:9443", "cmis-3:9443"]
node_id       = 1                               # 1.. ; node 1 bootstraps
data_dir      = "/var/lib/ferrogate/raft"       # hiqlite SQLite state + WAL

[rim]
allowlist     = "/var/lib/ferrogate/rim/current.json"
generations   = 6

[audit]
worm_dir      = "/var/lib/ferrogate/audit"      # local-disk WORM store (O_CREAT|O_EXCL)
sigsum_log    = "https://sigsum.example.org/log1"
```

## Error model

All client-visible errors map to a small fixed set of gRPC status codes; the
*reason* is never returned to the client to avoid oracles. Detailed failure
reasons go only to the audit log.

| Condition | gRPC status |
|-----------|-------------|
| TLS group not hybrid | (handshake aborted before RPC) |
| Quote verification failed | `PERMISSION_DENIED` |
| PCRs not in RIM | `FAILED_PRECONDITION` |
| Credential activation mismatch | `PERMISSION_DENIED` |
| AIK signature over CSR invalid | `PERMISSION_DENIED` |
| Replay of nonce | `ABORTED` |
| Internal (signer unavailable, …) | `UNAVAILABLE` |
