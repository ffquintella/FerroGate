# F09 — DPoP-Bound Child Tokens

## Summary

MIA mints short-lived JWS tokens signed with the host's composite SVID key.
Each token is bound to a caller-supplied DPoP key (RFC 9449) via the `cnf.jkt`
claim, so a stolen bearer token cannot be replayed by a party that does not
hold the corresponding private key.

## Scope

In:

- JWS child tokens, `alg = "MLDSA65+Ed25519"`, TTL ≤ 600 s.
- `cnf.jkt` carries SHA-256 thumbprint of the caller's DPoP public JWK.
- `ferrogate` claim block records `parent_svid`, `actor_pid`, `actor_uid`,
  `actor_bin`.
- JWKS exposed via CMIS for downstream verifiers.

Out:

- DPoP proof verification itself (done by the third-party API, not by MIA).
- OAuth introspection bridges.

## Components touched

- `crates/mia` (minter).
- `crates/cmis` (JWKS endpoint).

## Dependencies

- F03, F04, F08.

## Design notes

See [../helper-api.md](../helper-api.md) §"Token shape" and
[../crypto.md](../crypto.md).

## Acceptance criteria

- [x] Tokens validate against the published JWKS with a reference verifier.
      (`crates/ferro-child-verify` — `verify`; round-tripped against the real
      minter in `crates/mia/tests/child_token_verify.rs`.)
- [x] `cnf.jkt` matches the supplied DPoP public key thumbprint.
      (`verify_bound` computes the RFC 7638 thumbprint of the presented DPoP
      proof key and requires equality with the token's `cnf.jkt`.)
- [x] TTL is clamped server-side to ≤ 600 s. (`ChildTokenMinter::mint` clamps to
      `MAX_CHILD_TTL_SECS`; landed with F08.)
- [x] `jti` is unique per token (128-bit random). (`OsRng`-drawn 16 bytes per
      mint; landed with F08.)
- [x] Replay test: a token with no DPoP proof is rejected by the third-party
      verifier sample. (`verify_bound(.., None, ..) → MissingDpopProof`, covered
      by `token_without_dpop_proof_is_rejected` and the MIA e2e test.)
- [x] Audit log records `jti` and caller identity but never the token body.
      (`LocalGrant { pid, uid, bin_sha, jti }` in
      `crates/mia/src/helper/server/mod.rs`; the JWS is never logged.)

## Reference verifier

`crates/ferro-child-verify` is a self-contained Rust verifier: it re-declares
the wire schema, validates the composite signature against a CMIS JWK set,
enforces `exp`, and — via `verify_bound` — the DPoP sender constraint. DPoP
proofs are Ed25519 (`alg = "EdDSA"`, OKP `jwk`); `verify_dpop_proof` checks the
proof signature, the `htm`/`htu` binding, and proof freshness.

## Risks

- **Verifier interop.** Composite `alg` is non-standard at JOSE level today.
  Mitigation: the reference verifier crate (`ferro-child-verify`) ships as the
  canonical interop target. A Go port was scoped out (no second-language
  verifier in-tree); third parties on other stacks port from the Rust reference.
