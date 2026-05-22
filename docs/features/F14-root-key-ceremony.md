# F14 — Root Key Ceremony and Rotation

## Summary

The composite issuance root key is rotated annually in an air-gapped
ceremony. A 3-of-5 operator quorum generates a new root inside an attested
offline signer, cross-signs old and new for a 90-day window, and zeroizes
the old shares at the end of the window. All steps are video-recorded and
logged to an offline audit medium.

## Scope

In:

- Offline signer firmware (or hardened laptop image) with attestation.
- Quorum tooling: Shamir share generation, sealed transport media.
- Cross-signing flow: old-signs-new and new-signs-old.
- JWKS publication of both roots during the window with newer preferred.
- End-of-window destruction procedure.
- Auditability: ceremony minutes signed by all participants.

Out:

- Online emergency rotation (separate runbook; risky and explicitly
  off-the-happy-path).

## Components touched

- `tools/offline-signer` (to be created).
- `crates/cmis` (JWKS multi-key support).
- Operational runbooks (under `docs/operations/`).

## Dependencies

- F03, F06.

## Design notes

See [../operations.md](../operations.md) §"Root key rotation".

## Acceptance criteria

- [ ] Dry-run ceremony completes end-to-end in a staging environment.
- [ ] JWKS publishes both roots; reference verifier picks the newer.
- [ ] Cross-signing artefacts validate in both directions.
- [ ] Destruction step is observable and irreversible (shares overwritten on
      tamper-evident media; verified by post-zeroization read).
- [ ] Ceremony minutes are signed by all participants and stored to WORM.

## Risks

- **Operator loss.** Losing more than two of five share holders prevents
  reconstruction. Mitigation: 3-of-5 (not 5-of-5); periodic share refresh.
- **Insider collusion.** Three colluding operators can reconstruct the key.
  Mitigation: separation of duties; ceremony video; transparency anchor of
  ceremony minutes.
