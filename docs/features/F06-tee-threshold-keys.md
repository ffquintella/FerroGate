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

- [ ] `ferro-tee::Attestor` produces and verifies SEV-SNP reports against a
      configured root.
- [ ] Equivalent path for Intel TDX.
- [ ] A new replica cannot acquire a share without a passing attestation
      against the approved CMIS measurement allowlist.
- [ ] 3-of-5 reconstruction succeeds in unit tests; 2 shares fail.
- [ ] Reconstructed key is zeroized within milliseconds of last use; verified
      by a Drop test.
- [ ] Loss of one share does not stop issuance; loss of three halts it
      gracefully.
- [ ] Memory protection: `mlock` succeeds; binary refuses to start otherwise.

## Risks

- **Vendor firmware bugs.** SEV-SNP and TDX have had report-forgery bugs in
  the past. Mitigation: pin minimum firmware revisions; subscribe to vendor
  security feeds; gate cluster join on firmware version.
- **Quorum loss.** Three simultaneous enclave compromises break security.
  Mitigation: rotate shares regularly; spread across vendors.
