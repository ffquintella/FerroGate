# Local Helper API

Applications on the host do not interact with the TPM or CMIS directly.
Instead, they talk to the MIA over a local IPC channel and receive
short-lived, sender-constrained tokens for a specific audience.

## Transport

- **Linux:** Unix Domain Socket at `/run/ferrogate/mia.sock`, mode `0660`,
  group `ferrogate-clients`.
- **Windows:** Named pipe `\\.\pipe\ferrogate-mia`, ACL grants only members
  of the `FerroGateClients` local group.

The wire encoding is CBOR (`ciborium`). The protocol is request/response, one
exchange per connection.

## Caller authentication

The MIA does not trust the caller's claimed identity. It establishes the
caller's identity from kernel-attested sources:

### Linux

1. `SO_PEERCRED` on the connected socket yields `(pid, uid, gid)`.
2. The MIA computes `bin_sha = SHA-384(/proc/<pid>/exe)` from disk.
3. It cross-checks `bin_sha` against the IMA runtime measurement log at
   `/sys/kernel/security/ima/binary_runtime_measurements`. IMA is
   kernel-enforced and cannot be forged from userspace.
4. The pair `(uid, bin_sha)` is looked up in the host allowlist. The
   allowlist is signed by CMIS at host enrollment; the MIA verifies the
   signature before each access and **fails closed** — any decode, signature,
   or freshness failure leaves no usable allowlist, so every caller is denied.

   The on-disk artefact is a CBOR `SignedAllowlist`: a canonical-CBOR
   `AllowlistDoc` body (`trust_domain`, `issued_at`, `not_after`, `entries`)
   plus a detached composite signature over those exact body bytes under the
   domain-separation context `ferrogate-allowlist-v1`. CBOR (rather than the
   TOML this doc originally sketched) gives an unambiguous canonical byte
   string to sign and matches FerroGate's other signed artefacts. Freshness is
   enforced on load: `now` must lie in `[issued_at, not_after]` and
   `now - issued_at` must not exceed a configured max age.

### Windows

`GetNamedPipeClientProcessId` gives the caller PID;
`QueryFullProcessImageNameW` gives its image path (hashed to `bin_sha`,
`SHA-384`); the process token's user SID RID serves as the allowlist `uid`; and
`WinVerifyTrust` (Authenticode / Code Integrity) provides the equivalent of the
IMA cross-check. The allowlist format is identical.

All Windows FFI lives in the `ferro-winauth` crate, so `mia` itself remains
`#![forbid(unsafe_code)]`. `mia`'s `WindowsCallerAuth` composes those
primitives into the same `CallerIdentity` the Unix path produces.

Any step failing terminates the request with `permission_denied` and
appends a `LocalDenied` audit event.

## Request / response

```rust
struct HelperReq {
    audience:   String,            // e.g. "https://api.example.com"
    dpop_jkt:   String,            // base64url SHA-256 of caller's DPoP pubkey JWK
    ttl_secs:   u32,               // requested TTL, clamped to <= 600
}

enum HelperResp {
    Token(ChildToken),
    Error { code: ErrorCode, retry_after: Option<u32> },
}
```

The MIA mints a compact JWS (`typ = "ferrogate-child+jwt"`,
`alg = "MLDSA65+Ed25519"`) signed by the host's composite SVID key under the
domain-separation context `ferrogate-child-token-v1` — distinct from the SVID
and allowlist contexts, so a signature can never be reinterpreted across
artefacts. The requested `ttl_secs` is clamped to ≤ 600 s server-side:

```jsonc
{
  "iss":  "spiffe://ferrogate.prod/host/<uuid>",
  "sub":  "spiffe://ferrogate.prod/host/<uuid>#app:<bin_sha[:16]>",
  "aud":  "https://api.example.com",
  "exp":  ...,
  "iat":  ...,
  "jti":  "<128-bit random>",
  "cnf":  { "jkt": "<dpop_jkt>" },
  "ferrogate": {
     "parent_svid": "<sha384 of host SVID>",
     "actor_pid":   1234,
     "actor_uid":   1001,
     "actor_bin":   "<sha384 of /usr/bin/foo>"
  }
}
```

The third-party verifier (an API gateway, sidecar, …) validates:

1. The composite signature against the CMIS JWKS endpoint.
2. The `parent_svid` reference is current (CRL check).
3. The `cnf.jkt` matches the DPoP proof presented alongside.
4. Application-level policy on `actor_bin` and `actor_uid`.

## Why DPoP

A pure bearer token can be stolen and replayed by anyone who reads it once.
DPoP (RFC 9449) requires the caller to attach a signed proof of possession of
the key referenced in `cnf.jkt`. A token captured on the wire cannot be used
by an adversary without the corresponding private key, which the caller holds
in memory only.

## Audit

Every helper interaction appends one of:

- `LocalGrant { pid, uid, bin_sha, jti }`
- `LocalDenied { pid, uid, bin_sha, reason }`

The full local audit stream is folded into the host's append-only audit feed
and synchronised opportunistically to CMIS for inclusion in the global STH.
