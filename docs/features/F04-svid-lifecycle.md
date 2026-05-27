# F04 — SVID Issuance and Lifecycle

## Summary

CMIS mints SPIFFE-compatible JWS SVIDs after successful attestation. SVIDs
carry boot-state evidence, are bound to a DPoP key, expire within one hour,
and rotate at 60% of TTL. Renewal skips TPM interaction inside a 24-hour
re-attestation window; outside it, a full four-phase handshake is required.

## Scope

In:

- JWS SVID envelope with the `ferrogate-svid-v1` profile.
- SPIFFE ID derivation from `SHA-384(ek_cert)`.
- `cnf.jkt` binding to a DPoP thumbprint.
- 1-hour maximum TTL; configurable lower in policy.
- `Rotate` RPC for in-window renewal.
- Forced re-attestation triggers: 24 h elapsed, PCR drift, `policy_id` epoch
  bump.
- Local sealing of SVID and private key to PCRs `{0, 4, 7, 8}`.

Out:

- X.509 SVIDs (JWS first; X.509 a follow-on).
- Workload-attestation (per-app) SVIDs from CMIS; those are minted locally
  by MIA as child tokens (see F09).

## Components touched

- `crates/cmis` — issuance handler, rotation handler.
- `crates/mia` — local cache, sealing, rotation scheduler.
- `crates/ferro-crypto` — composite signing.

## Dependencies

- F02 (attestation), F03 (signatures), F01 (transport).

## Design notes

See [../protocol.md](../protocol.md) §"Phase 4" and §"Renewal vs re-attestation",
and [../cmis.md](../cmis.md) §"gRPC surface".

## Acceptance criteria

- [x] CMIS `issue_svid` returns a JWS that validates against the published
      JWKS and matches the documented payload schema.
      (`ferro-svid` issuance + the `JWKS` RPC; `mia/tests/e2e_attest.rs::attest_issues_svid_that_reference_verifier_accepts`.)
- [x] `Rotate` succeeds without TPM I/O when within the 24 h window and PCRs
      are unchanged. (`rotate_short_path_when_pcrs_unchanged`.)
- [x] `Rotate` forces re-attestation when PCRs differ or epoch differs.
      (`lifecycle::decide_renewal`; `rotate_refused_on_pcr_drift`.)
- [x] MIA seals the SVID under PCR policy `{0,4,7,8}`; reboot into a different
      PCR state silently invalidates the cache. (`mia::seal`, Linux-only;
      `mia/tests/swtpm_seal.rs` extends a sealed PCR and shows the unseal fails.)
- [x] Rotation scheduler triggers at 60% of TTL with jitter.
      (`lifecycle::rotation_delay_secs`, `mia::scheduler`.)
- [x] An expired SVID is refused by a reference verifier.
      (`ferro-svid-verify`; `ferro-svid/tests/verify_roundtrip.rs::expired_svid_is_refused`.)

## Implementation notes

Two seams are deliberately left for later milestones:

- The CMIS gRPC server runs **plaintext** in the M2 bring-up binary. The
  hybrid-PQC TLS provider already exists in `ferro-crypto` (F01); terminating it
  under the tonic transport is sequenced with the F05 peer-transport work.
- Phase-3 `MakeCredential` is injected through the `cmis::CredentialMaker`
  trait. Only a software stand-in (in the integration test) exists today; a
  production TCG/EK wrapper lands with the TEE milestone. The MIA-side
  `TPM2_ActivateCredential` is already real (F02).

## Risks

- **Clock skew.** SVIDs are short-lived; large host clock skew causes false
  expiry. Mitigation: NTP/chrony required by host baseline; CMIS issues `nbf`
  with a 60 s lookback.
- **Sealing brittleness.** Legitimate firmware updates may change PCR 0.
  Mitigation: PCR-drift triggers a re-attestation, not a hard failure.
