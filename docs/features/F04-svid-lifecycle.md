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
- `Rotate` RPC for in-window renewal: a host method since T293 (host proof
  over a `RotateDoc`, context `ferrogate-rotate-v1`), host-key tier only,
  from the latest stored SVID only.
- Forced re-attestation triggers: 24 h elapsed, state (PCR / fingerprint)
  drift, `policy_id` epoch bump, and always for the TPM tier.
- Local sealing of SVID and private key to PCRs `{0, 4, 7, 8}`.

Out:

- X.509 SVIDs — delivered as a separate profile beside this one, see
  [F17](F17-x509-svid.md).
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
- [x] `Rotate` succeeds without TPM I/O when within the 24 h window and the
      signed state digest is unchanged (host-key tier, T293).
      (`mia/tests/e2e_attest.rs::rotate_short_path_for_host_key_tier`,
      `cmis/tests/rotate_host_auth.rs::rotate_succeeds_short_path`.)
- [x] `Rotate` forces re-attestation when the state digest or epoch differs,
      the window expired, or the host is on the TPM tier.
      (`lifecycle::decide_renewal`; `rotate_refused_for_tpm_tier`,
      `rotate_refuses_state_digest_drift`, `rotate_refuses_after_epoch_bump`,
      `rotate_refuses_outside_the_reattest_window`.)
- [x] `Rotate` needs a host proof and refuses forged, foreign, expired,
      revoked and superseded SVIDs (T293). (`cmis/tests/rotate_host_auth.rs`.)
- [x] MIA seals the SVID under PCR policy `{0,4,7,8}`; reboot into a different
      PCR state silently invalidates the cache. (`mia::seal`, Linux-only;
      `mia/tests/swtpm_seal.rs` extends a sealed PCR and shows the unseal fails.)
- [x] Rotation scheduler triggers at 60% of TTL with jitter.
      (`lifecycle::rotation_delay_secs`, `mia::scheduler`.)
- [x] The MIA daemon renews its host SVID while running — `Rotate` inside
      the window on the host-key tier, full attestation otherwise — and fails
      closed at expiry (T294). (`mia::renewal::tests`,
      `e2e_attest.rs::daemon_renews_host_svid_before_expiry`.)
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
- **Issuance oracle (fixed in T293).** Until 0.30.0, `Rotate` was public,
  never verified the presented SVID's signature, expiry or revocation, and
  trusted unsigned PCR values: anyone with a host's SPIFFE id and PCR values
  could have CMIS mint and store a fresh SVID for it (still bound to the
  host's key). It now requires the host proof and refuses the TPM tier and
  superseded, expired and revoked SVIDs (see [../protocol.md](../protocol.md)
  §"Renewal vs re-attestation").
- **Short path rarely used.** With the 96 h TTL floor and the 24 h window, a
  scheduled renewal is normally a full re-attestation (decision D1 of T294:
  the window stays; the daemon tries `Rotate` only inside it).
- **Renewal in the running daemon (T294).** One task per environment
  (`mia::renewal`) renews at the jittered 60 % point, swaps credentials,
  minter, status and allowlist sync in a fixed order, retries with a bounded
  back-off, switches minting off at expiry and stops the daemon if CMIS
  issues another identity (see [../operations.md](../operations.md)
  §"Host SVID renewal in the daemon"). Before 0.30.0 only a restart renewed
  an expired SVID.
