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

- [ ] Tokens validate against the published JWKS with a reference verifier.
- [ ] `cnf.jkt` matches the supplied DPoP public key thumbprint.
- [ ] TTL is clamped server-side to ≤ 600 s.
- [ ] `jti` is unique per token (128-bit random).
- [ ] Replay test: a token with no DPoP proof is rejected by the third-party
      verifier sample.
- [ ] Audit log records `jti` and caller identity but never the token body.

## Risks

- **Verifier interop.** Composite `alg` is non-standard at JOSE level today.
  Mitigation: ship a reference verifier crate and a Go variant.
