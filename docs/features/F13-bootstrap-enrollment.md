# F13 — Zero-Touch Bootstrap and Fleet Enrollment

## Summary

A new host obtains its first SVID with no pre-distributed secret. Trust is
anchored in the TPM vendor's signature on the EK certificate plus an
offline-signed fleet manifest enumerating accepted EK hashes. CMIS performs
a pre-admission check against the manifest before the four-phase protocol
runs.

## Scope

In:

- Fleet manifest format (signed JSON / CBOR; SHA-384 of every accepted EK
  cert).
- Offline signing tool that produces and updates the manifest.
- CMIS startup load and signed-S3 refresh of the manifest.
- Pre-admission lookup at the start of `Attest`.
- Audit events: `HostEnrolled`, `HostRejected`.

Out:

- IPMI / DHCP-based enrollment shortcuts.
- Bulk pre-issuance of SVIDs before host boot.

## Components touched

- `crates/cmis`.
- `tools/fleet-manifest` (admin CLI; to be created).

## Dependencies

- F02, F03, F10.

## Design notes

See [../operations.md](../operations.md) §"Bootstrapping a new host".

## Acceptance criteria

- [ ] Fleet manifest verifies under the offline root key; tampered manifests
      are refused.
- [ ] Host with EK cert in the manifest succeeds end-to-end.
- [ ] Host with EK cert *not* in the manifest is rejected before any TPM
      verification work runs.
- [ ] Manifest refresh from S3 is atomic; in-flight attestations see a
      consistent snapshot.
- [ ] CLI tool can add and remove EK hashes and produce a properly signed
      bundle.

## Risks

- **Manifest size.** Very large fleets imply a large signed manifest.
  Mitigation: shard by EK-hash prefix; sign each shard independently.
- **Lost factory data.** A host whose EK cert was not captured at provisioning
  cannot enroll. Mitigation: documented out-of-band re-provisioning flow
  with quorum approval.
