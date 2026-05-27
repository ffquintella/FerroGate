# F02 — TPM 2.0 Attestation Engine

## Summary

The MIA drives a TPM 2.0 device to produce hardware-anchored evidence: an EK
certificate, a freshly-created Attestation Identity Key (AIK), a PCR quote
over the policy PCR set, and a credential-activation response. The CMIS
verifies this evidence as the basis for issuing an SVID.

## Scope

In:

- `tss-esapi` integration on Linux (`/dev/tpmrm0`).
- EK creation in the endorsement hierarchy with the TCG-default ECC-P256
  template.
- AIK creation as a restricted, signing-only child of the EK with the full
  required attribute mask.
- PCR quotes over `{0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 14}` with SHA-384.
- `TPM2_ActivateCredential` for proof-of-residency.
- HMAC-bound sessions for all sensitive commands.
- CMIS-side quote verification (10-step algorithm, see [../tpm.md](../tpm.md)).
- Windows TPM support (`TBS` via `tss-esapi`).

Out:

- TPM 1.2.
- Software TPM in production (swtpm is for test only).
- PCR extension by FerroGate itself; PCRs are extended by the platform.

## Components touched

- `crates/ferro-attest` — verification.
- `crates/mia` — TPM glue.
- Test rig: `swtpm` driven by integration tests.

## Dependencies

- F01 (transport must exist before attestation rides on it).

## Design notes

See [../tpm.md](../tpm.md) and [../protocol.md](../protocol.md) phases 2–3.

## Acceptance criteria

- [x] `mia::tpm::TpmEngine` exposes `load_ek`, `create_aik`, `quote`,
      `activate_credential`, `sign_aik`. (`crates/mia/src/tpm.rs`.)
- [x] `ferro-attest::TpmQuoteVerifier::verify_quote` implements all 10 steps
      and rejects every malformed input with a precise (audit-only) reason.
      (`crates/ferro-attest/src/verify.rs`; `RejectReason` per step.)
- [x] Vendor root CAs for Infineon, Nuvoton, ST, and Intel PTT are bundled and
      independently loadable. (`vendor.rs` + `build.rs`; per-vendor
      `with_vendor`. No roots ship by default — operators provision them with
      `scripts/ferrogate-ca.sh`, see `vendor-roots/README.md`.)
- [x] Integration test under `swtpm` produces a valid quote and CMIS accepts
      it end-to-end. (`crates/mia/tests/swtpm_attest.rs`.)
- [x] Negative tests: tampered quote, wrong nonce, missing PCR, AIK not
      restricted — each is rejected. (`tests/verify_quote.rs`, plus untrusted
      root, not-in-RIM, and wrong-key cases.)
- [x] Credential-activation mismatch is rejected in constant time.
      (`verify::credential_secret_matches`, `subtle::ConstantTimeEq`.)
- [x] All TPM commands run under bound HMAC sessions. (`TpmEngine::hmac_session`
      with parameter encryption; flushed after use.)

## Risks

- **Vendor cert chain quirks.** Some TPM vendors ship intermediate certs
  out-of-band or with non-standard extensions. Mitigation: per-vendor parser
  modules with shared test corpora.
- **Resource manager contention.** Other host consumers may claim TPM
  objects. Mitigation: use `/dev/tpmrm0`, never `/dev/tpm0`.
