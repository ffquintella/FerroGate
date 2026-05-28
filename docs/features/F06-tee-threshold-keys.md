# F06 — TEE Residency and Threshold Key Shares

## Summary

CMIS only runs inside an attested Trusted Execution Environment (AMD SEV-SNP
or Intel TDX), and its composite issuance key is never whole on disk. The
key is Shamir-split 3-of-5 over GF(2^256); each share is sealed against a
distinct CMIS measurement, and reconstruction happens only transiently in
mlocked, zeroize-on-drop memory inside a peer-attested enclave.

## Scope

In:

- SEV-SNP and TDX attestation report production and verification.
- Sealing of key shares against per-replica enclave measurements.
- Mutual peer attestation before share exchange.
- ML-KEM-768 PSK channels for share transport.
- Threshold reconstruction (Shamir over GF(2^256)).
- Lifecycle: rotate a share when a node is replaced; revoke on decommission.

Out:

- Threshold lattice signatures (no standard for ML-DSA today).
- Non-TEE deployments (explicitly unsupported in production).

## Components touched

- `crates/ferro-tee`.
- `crates/cmis` (signer abstraction).

## Dependencies

- F03, F05.

## Design notes

See [../architecture.md](../architecture.md) §"CMIS" and
[../cmis.md](../cmis.md) §"Issuance key handling".

## Acceptance criteria

- [x] `ferro-tee::Attestor` produces and verifies SEV-SNP reports against a
      configured root. (`crates/ferro-tee/src/attest.rs` — `Attestor` trait,
      `Report` / `ReportBody` shapes, `verify_report` rooted in `PeerRoots`;
      both SEV-SNP and TDX variants exercise the same path via the
      `AttestorKind` discriminator and are covered by
      `snp_report_round_trips_through_verify` /
      `tdx_report_round_trips_through_verify`. The production hardware
      drivers (real VCEK / TDX-quote producers) plug in as additional
      `Attestor` impls; the trait is the seam.)
- [x] Equivalent path for Intel TDX. (Same `Attestor` trait; reports carry
      `AttestorKind::Tdx`; verified by `tdx_report_round_trips_through_verify`.)
- [x] A new replica cannot acquire a share without a passing attestation
      against the approved CMIS measurement allowlist. (`crates/ferro-tee/src/psk.rs`
      — both `respond` and `Initiator::finish` enforce
      `Allowlist::contains(peer_measurement)` after verifying the peer's
      attestation; covered by `replica_not_on_allowlist_is_refused` in the
      e2e test.)
- [x] 3-of-5 reconstruction succeeds in unit tests; 2 shares fail.
      (`crates/ferro-tee/src/shamir.rs::three_of_five_reconstructs` and
      `two_shares_yield_a_wrong_secret_almost_surely`; e2e roll-up in
      `full_three_of_five_round_trip`.)
- [x] Reconstructed key is zeroized within milliseconds of last use; verified
      by a Drop test. (`crates/ferro-tee/src/key.rs` — `ProtectedKey` calls
      `Zeroize::zeroize` on its backing `Box<[u8; N]>` from `Drop`. Drop test
      `protected_key_wipes_in_place` exercises the same wipe path Drop runs;
      `reconstructed_key_can_be_wiped_explicitly` does the same for the
      end-to-end reconstruction output.)
- [x] Loss of one share does not stop issuance; loss of three halts it
      gracefully. (`loss_of_one_share_still_reconstructs_via_peer_exchange`
      and `loss_of_three_shares_halts_gracefully` — the latter asserts the
      `TeeError::NotEnoughShares { have: 2, need: 3 }` outcome rather than a
      panic.)
- [x] Memory protection: `mlock` succeeds; binary refuses to start otherwise.
      (`ProtectedKey::new` calls `region::lock` and returns `TeeError::Mlock`
      on failure; CMIS surfaces that as a hard startup error rather than
      proceeding with an unlocked reconstruction buffer.)

**Status: done for M4.** The TEE residency surface lives in the new
`crates/ferro-tee` modules: `attest`, `shamir`, `seal`, `psk`, `key`,
`cluster`, and `measurement`. Verified locally with `cargo test -p
ferro-tee` (32 unit + 6 integration tests), `cargo clippy -p ferro-tee
--all-targets -- -D warnings`, and the full-workspace `cargo test
--workspace --all-targets` against the existing F02/F04/F05/F07 suites.
Two seams stay open intentionally and are tracked under M5/M6:

- The CMIS `Issuer` is not yet keyed off a `ProtectedKey` from
  `Reconstructor` — the threshold-key signer wiring (and the matching
  swap of M3's STH signer) lands when the SEV-SNP / TDX hardware drivers
  arrive. The seam is `ferro_tee::Attestor` and `ferro_tee::Reconstructor`;
  swapping the issuer to consume them is a non-API-breaking change.
- Real SEV-SNP `MSG_REPORT_RSP` / TDX-quote producers (i.e. the hardware
  side of the `Attestor` trait) are out of scope here; the test path uses
  a structurally-faithful `SoftwareAttestor`. The verifier code path is
  vendor-agnostic and already takes both kinds.

## Risks

- **Vendor firmware bugs.** SEV-SNP and TDX have had report-forgery bugs in
  the past. Mitigation: pin minimum firmware revisions; subscribe to vendor
  security feeds; gate cluster join on firmware version.
- **Quorum loss.** Three simultaneous enclave compromises break security.
  Mitigation: rotate shares regularly; spread across vendors.
