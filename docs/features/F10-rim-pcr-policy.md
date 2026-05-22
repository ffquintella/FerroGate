# F10 — RIM and PCR Policy Management

## Summary

CMIS maintains a versioned Reference Integrity Measurement (RIM) bundle
mapping approved PCR digests to a `policy_id`. The active RIM plus the six
prior generations are retained to allow in-flight image rollouts; an explicit
epoch bump on the active `policy_id` can mass-invalidate older measurements.

## Scope

In:

- RIM bundle format (signed JSON / CBOR) with explicit version, validity
  window, and approved PCR digest set.
- Hot reload from a signed S3 object (or local file for development).
- Retention of 6 prior generations.
- `policy_id` epoch bump as a first-class admin operation, audited.
- Mapping at attestation time from PCR digest to `policy_id`.

Out:

- TPM Event Log replay (we accept digests directly; event-log validation is
  a future feature).
- Per-host PCR exceptions.

## Components touched

- `crates/ferro-attest` (matcher).
- `crates/cmis` (RIM store, admin RPC).

## Dependencies

- F02.

## Design notes

See [../tpm.md](../tpm.md) §"PCR policy" and [../operations.md](../operations.md)
§"Revocation".

## Acceptance criteria

- [ ] RIM signature verification fails closed; unsigned bundles are refused.
- [ ] Reload of a new RIM is hot and atomic; in-flight attestations see a
      consistent generation.
- [ ] Old generations beyond 6 are pruned and no longer accepted.
- [ ] Admin RPC `bump_epoch` emits a `PolicyEpochBumped` audit event and
      forces re-attestation at next rotation for all hosts.
- [ ] PCR digest not in any active generation → `FAILED_PRECONDITION`.

## Risks

- **Image rollout chaos.** Too few generations retained → hosts on the last
  good image are locked out. Mitigation: 6 generations is empirically
  sufficient for a 2-week rollout window.
- **Bundle drift.** Multiple operators publishing concurrently.
  Mitigation: monotonic version counter; refuse non-monotonic updates.
