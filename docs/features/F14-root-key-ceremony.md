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

- [x] Dry-run ceremony completes end-to-end in a staging environment.
      (`offline-signer dry-run` runs all eight steps with five synthetic
      operators; exercised by the CLI integration test
      `dry_run_produces_all_verifiable_artefacts` and recorded in
      [../operations/root-key-ceremony.md](../operations/root-key-ceremony.md)
      §"Staging dry-run".)
- [x] JWKS publishes both roots; reference verifier picks the newer.
      (`CmisState::register_root_key` + newest-first `published_jwks`;
      `JwkSet::preferred()` in `ferro-svid-verify` selects the newer root,
      asserted by `cmis` `root_rotation` and the CLI tests.)
- [x] Cross-signing artefacts validate in both directions.
      (`CrossSignBundle::verify` requires old-signs-new *and* new-signs-old;
      `both_directions_verify` and the tamper/swap negative tests.)
- [x] Destruction step is observable and irreversible (shares overwritten on
      tamper-evident media; verified by post-zeroization read).
      (`ferro_ceremony::destroy_media` overwrites + `fsync`s + reads back,
      returning an auditable `DestructionRecord`; `destroy_zeroizes_and_verifies`
      and the dry-run's old-share destruction step.)
- [x] Ceremony minutes are signed by all participants and stored to WORM.
      (`SignedMinutes::verify_all` requires every `Participant` to have signed;
      the signed JSON is anchored to the audit WORM medium. `all_participants_
      must_sign` plus the CLI `minutes-*` flow.)

**Status: done for M6.** Implemented in the new `crates/ferro-ceremony` library
(`media`, `crosssign`, `minutes`, `destruction`) and the `tools/offline-signer`
CLI, with JWKS "newer preferred" multi-root support added to `ferro-svid`,
`ferro-svid-verify`, and `cmis`. The operational procedure is in
[../operations/root-key-ceremony.md](../operations/root-key-ceremony.md).
Confidentiality of a root rests on the 3-of-5 threshold and physical custody of
each holder's tamper-evident medium; measurement-bound *encryption* of shares
against a CMIS enclave is the online F06 path (`ferro_tee::seal`), not this
offline transport envelope. Online emergency rotation stays out of scope.

## Risks

- **Operator loss.** Losing more than two of five share holders prevents
  reconstruction. Mitigation: 3-of-5 (not 5-of-5); periodic share refresh.
- **Insider collusion.** Three colluding operators can reconstruct the key.
  Mitigation: separation of duties; ceremony video; transparency anchor of
  ceremony minutes.
