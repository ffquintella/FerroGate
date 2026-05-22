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

- [ ] `revoke_svid(cert_sha, reason)` admin RPC produces a CRL delta within
      one publish cycle.
- [ ] MIAs refuse child-token mint if cached CRL age > 300 s.
- [ ] CRL signature verification fails closed.
- [ ] Revoked SVID is rejected by the reference verifier after CRL
      propagation.
- [ ] Audit log records every revocation with reason.

## Risks

- **CRL bloat.** Long-running fleets accumulate revocations. Mitigation:
  expire CRL entries past max SVID TTL (1 h); they cannot resurface.
