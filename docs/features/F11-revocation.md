# F11 — Revocation and CRL Distribution

## Summary

CMIS publishes a composite-signed CRL delta every 60 s as a JWKS extension
(`x-ferrogate-crl`). MIAs pull it on every child-token mint and refuse to
mint if the cached CRL is more than 5 minutes old. Mass revocation is done
by bumping the `policy_id` epoch (F10).

## Scope

In:

- Per-SVID revocation by `cert_sha`.
- Per-host revocation by SPIFFE ID.
- Delta CRLs signed with the composite issuance key.
- Max-age enforcement on the MIA.
- Audit events: `SvidRevoked`, `HostRevoked`.

Out:

- OCSP-style live lookups (deliberately avoided; CRL is cacheable and
  observable).
- Selective unrevocation (revoke is final).

## Components touched

- `crates/cmis` (CRL publisher and admin RPC).
- `crates/mia` (CRL puller and freshness check).

## Dependencies

- F03, F04.

## Design notes

See [../operations.md](../operations.md) §"Revocation".

## Acceptance criteria

- [x] `revoke_svid(cert_sha, reason)` admin RPC produces a CRL delta within
      one publish cycle. (`MachineIdentity.RevokeSvid` / `RevokeHost` in
      `crates/ferro-proto`; `crates/cmis/src/service.rs` validates the
      `cert_sha`, records the revocation, and publishes a fresh signed CRL
      inline — within the same call. Covered by
      `crates/cmis/tests/revocation.rs`.)
- [x] MIAs refuse child-token mint if cached CRL age > 300 s.
      (`crates/mia/src/helper/crl.rs::CrlCache::gate` returns `Stale` once the
      cached CRL ages past `CRL_MAX_AGE_SECS`; the helper pipeline
      (`server/mod.rs`) maps it to `CrlStale` and a `LocalDenied{crl-stale}`
      audit event before allowlisting. Covered by `stale_crl_refuses_to_mint`
      and `missing_crl_refuses_to_mint` in `crates/mia/tests/helper_api.rs`.)
- [x] CRL signature verification fails closed.
      (`ferro_svid::crl::SignedCrl::verify` and the MIA-side
      `crl::ingest` reject an unknown `signer_kid`, a wrong key, or a tampered
      signature without yielding the body, leaving the cache stale. Covered by
      unit tests in both crates.)
- [x] Revoked SVID is rejected by the reference verifier after CRL
      propagation. (`ferro_svid_verify::verify_unrevoked` checks the SVID
      against the fresh, signature-valid CRL carried in the JWKS — by
      `cert_sha` or host SPIFFE id — and returns `Revoked`. Covered by the
      cross-crate `crates/ferro-svid/tests/verify_roundtrip.rs` and the
      end-to-end `revoked_svid_is_rejected_by_reference_verifier_after_propagation`
      in `crates/cmis/tests/revocation.rs`.)
- [x] Audit log records every revocation with reason. (`SvidRevoked` /
      `HostRevoked` events appended by `crates/cmis/src/service.rs`; the
      bounded reason opcode is carried verbatim. Tree growth asserted in
      `revoke_svid_appears_in_jwks_crl_and_audit`.)

## Status

**Done.** Per-SVID and per-host revocation, the composite-signed CRL delta in
the `x-ferrogate-crl` JWKS extension (60 s publisher heartbeat plus inline
publish on revoke), MIA freshness/revocation enforcement, fail-closed CRL
signature verification, and reference-verifier rejection all landed. Two seams
are intentionally deferred, matching the precedent set by the F09 JWKS
registry: the revocation working set is **process-local** (replicating it
through the Raft store so every replica's CRL agrees is deployment wiring on
the existing `CmisState::revoke` seam), and the MIA CRL puller
(`crl::spawn_puller`) is wired by the attestation loop that supplies the host
SVID — until that lands the daemon runs with an empty cache and therefore
refuses to mint (fail closed). The admin RPCs are authenticated as operator
actions out of band (mTLS/role gating at the transport), not in the message.

## Risks

- **CRL bloat.** Long-running fleets accumulate revocations. Mitigation:
  expire CRL entries past max SVID TTL (1 h); they cannot resurface.
