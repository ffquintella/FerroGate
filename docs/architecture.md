# Architecture

## Components

```
        ┌────────────────────────────────┐
        │  L4 Anycast / Maglev LB        │
        │  (TLS passthrough)             │
        └──────────────┬─────────────────┘
                       │
   ┌───────────────────┼───────────────────┐
   │                   │                   │
┌──▼───┐            ┌──▼───┐            ┌──▼───┐
│CMIS-1│            │CMIS-2│            │CMIS-3│
│SEV-SNP│           │ TDX  │            │SEV-SNP│
└──┬───┘            └──┬───┘            └──┬───┘
   │   Raft (hiqlite), TCP peer transport  │
   └───────────────────┬───────────────────┘
                       │
            ┌──────────▼──────────┐
            │ hiqlite (SQLite +   │
            │ Raft) · local-disk  │
            │ WORM store          │
            └──────────┬──────────┘
                       │
            ┌──────────▼──────────┐
            │ Audit Notary        │
            │ (Merkle + Sigsum)   │
            └─────────────────────┘
```

### CMIS — Central Machine Identity Service

- Stateless gRPC server; nodes are interchangeable.
- Runs inside a Trusted Execution Environment (SEV-SNP or TDX). Its own boot is
  remotely attested by peers before a node joins the cluster.
- Long-term composite signing key (Ed25519 + ML-DSA-65) is **never** stored
  whole on disk. It is Shamir-split (3-of-5) across enclaves and reconstructed
  in mlocked, zeroize-on-drop memory only when needed.
- Replicated metadata (issued SVID hashes, CRL deltas, RIM allowlist) via a
  Raft cluster backed by [hiqlite](https://crates.io/crates/hiqlite) — openraft
  plus a durable SQLite state machine and its own peer transport. (The original
  design named FoundationDB; see [roadmap.md](roadmap.md) and
  [features/F05-cmis-ha.md](features/F05-cmis-ha.md) for why hiqlite was chosen.
  An FDB-backed store remains a follow-up option for very-large fleets.)

### MIA — Machine Identity Agent

- Static-PIE Rust binary, runs as a dedicated unprivileged UID with seccomp-bpf
  allowlist (~35 syscalls) and `mlockall`.
- Owns the TPM 2.0 device (`/dev/tpmrm0`), holds the locally-sealed SVID, mints
  child DPoP tokens for applications.
- Exposes a Unix Domain Socket (Linux) or Named Pipe (Windows) helper API.

### Audit Notary

- Per-shard Merkle tree of audit events, signed in the TEE every second.
- Backing store: a local-disk WORM tier (`LocalDiskWormStore`, write-once via
  `O_CREAT|O_EXCL`), with the replicated copy living in the hiqlite-backed Raft
  state machine. (A native S3 Object Lock store was originally planned but is
  dropped — see [roadmap.md](roadmap.md) §"Dropped scope". Deployments needing
  cloud durability sync the WORM directory to object storage out of band; the
  write-once semantics and STH signatures gate integrity, so that path is
  untrusted.)
- Signed Tree Heads (STH) are published to a public transparency log
  (Sigsum / Rekor) once per minute.

## High availability

- Minimum 3 CMIS replicas across ≥2 regions and ≥2 cloud providers.
- Failure tolerance:
  - Issuance: `f = ⌊(n-1)/2⌋` nodes may fail.
  - Key reconstruction: `f = ⌊(n-1)/3⌋` nodes may fail (3-of-5 threshold).
- L4 anycast load balancer with TLS passthrough; clients verify hybrid-PQC
  cert chain end-to-end against pinned SPKI hashes.
- Offline, air-gapped quorum holds the **root** signing material for annual
  cross-signed rotation (see [operations.md](operations.md)).

## Why two components

The split exists because the trust boundaries are different:

| Concern | CMIS | MIA |
|---------|------|-----|
| Holds long-term issuance key | yes (in TEE) | no |
| Touches TPM hardware | no | yes |
| Reachable from the internet | yes (mTLS) | no (host-local only) |
| Failure radius if compromised | the fleet | a single host |
| Update cadence | quarterly | with host image |

Keeping the issuance authority remote and stateless lets us scale issuance
horizontally and contain a host-level breach to that host alone.
