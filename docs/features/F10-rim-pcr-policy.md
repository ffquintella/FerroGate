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

- [x] RIM signature verification fails closed; unsigned bundles are refused.
      (Composite signature in `ferro-attest::rim_bundle`; there is no
      constructor that yields a bundle without verifying. Tamper/unknown-kid
      cases in `rim_bundle::tests`.)
- [x] Reload of a new RIM is hot and atomic; in-flight attestations see a
      consistent generation. (Single `RwLock` write in `RimStore::apply`;
      `cmis::rim_watcher` drives the polling loop.)
- [x] Old generations beyond 6 are pruned and no longer accepted.
      (`MAX_GENERATIONS = 6`; `rim::tests::retention_prunes_oldest_beyond_six`
      proves pruned digests no longer resolve.)
- [x] Admin RPC `bump_epoch` emits a `PolicyEpochBumped` audit event and
      forces re-attestation at next rotation for all hosts. (`BumpEpoch` RPC →
      `CmisState::bump_epoch` advances a live `AtomicU64` epoch; `decide_renewal`'s
      `EpochBump` branch then refuses `Rotate` with `FAILED_PRECONDITION`.
      `mia/tests/e2e_attest.rs::bump_epoch_forces_full_reattestation_on_next_rotate`.)
- [x] PCR digest not in any active generation → `FAILED_PRECONDITION`.
      (`service::verifier_status` collapses `RejectReason::NotInRim` to
      `FAILED_PRECONDITION`; `mia/tests/e2e_attest.rs::attest_returns_failed_precondition_when_digest_not_in_rim`
      asserts it end-to-end over a real tonic channel.)

## Risks

- **Image rollout chaos.** Too few generations retained → hosts on the last
  good image are locked out. Mitigation: 6 generations is empirically
  sufficient for a 2-week rollout window.
- **Bundle drift.** Multiple operators publishing concurrently.
  Mitigation: monotonic version counter; refuse non-monotonic updates.
