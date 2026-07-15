# F16 — Tiered attestation for VMs (vTPM when available, hardened software otherwise)

## Summary

> **Status: implemented.** `mia` selects an attestation tier at boot; CMIS gains
> the trust knobs each tier needs. Builds on F02 (TPM), F13 (fleet manifest), and
> F15 (host-key profile).

mia agents run on VMs (on-prem KVM/QEMU and VMware) where **most hosts have no
(v)TPM**. F16 makes mia use a real (v)TPM opportunistically — when a host has one
— and fall back to a *hardened* software identity when it does not, with CMIS
distinguishing the two by assurance.

A hypervisor vTPM presents as an ordinary TPM 2.0 device, so the strongest option
is simply to drive it through the genuine F02 path (`mia::tpm::TpmEngine`). Pure
software attestation has **no hardware root of trust** — its key/state file is
copyable and its measurements are self-asserted — so it is treated as a strictly
lower-assurance tier: clone-resistant, explicitly enrolled, short-lived, and
policy-distinguishable.

## The tiers

| Tier | Backend (`attestation.backend`) | Used when | Root of trust |
|------|----------------------------------|-----------|----------------|
| A | `tpm` | a usable TPM device **and** an EK cert are present | Hardware / hypervisor (vendor or operator EK-CA) |
| B | `host-key` | no usable TPM | Software, machine-bound (fingerprint) — **clone resistance, not a root of trust** |
| — | `virtual-tpm` | dev/test only | None (insecure) |

`auto` (the new default) picks the strongest usable tier: tier A when
`tpm_available()` **and** `attestation.tpm.ek_cert` is set, else tier B. Selecting
`tpm` explicitly is **fail-closed** — a missing/unusable TPM or EK cert refuses to
attest rather than downgrading. `auto` may downgrade (that is its contract) and
logs the choice.

## mia side

- **`attestation.backend`** (`crates/mia/src/config.rs`): `auto` (default) | `tpm`
  | `host-key` | `virtual-tpm`. Env: `FERROGATE_ATTEST_BACKEND`.
- **`[attestation.tpm]`**: `ek_cert` (DER path, env `FERROGATE_TPM_EK_CERT`) and
  `ek_intermediates` (DER paths). mia does not read the EK cert out of NV, so the
  operator supplies it — natural for on-prem, where the operator runs the EK-CA.
- **`TpmEvidence`** (`crates/mia/src/tpm.rs`): adapts `TpmEngine` to the shared
  `AttestEvidence` trait so the TPM tier uses the same 4-phase `run_attest`
  handshake as the dev virtual TPM. Linux-only; non-Linux `tpm` selection is
  fail-closed.
- **Clone-resistant software key** (`crates/ferro-sep`,
  `SoftwareMachineKey::open_or_create_sealed`): the P-256 scalar is sealed at rest
  with ChaCha20-Poly1305 under an HKDF-SHA256 key derived from the **hardware
  fingerprint** (`ferro_machineid::Fingerprint::as_bytes`). A key file copied to
  another host will not decrypt there. Pre-F16 plaintext key files are migrated in
  place on first open, preserving the pinned identity. **This is clone resistance
  bound to machine identity, not confidentiality against a local root attacker.**

## CMIS side

- **`require_preregistered_host_key`** (`CmisConfig`, env
  `CMIS_REQUIRE_PREREGISTERED_HOST_KEY`): when set, a software host-key node that
  is not pre-registered in the signed fleet manifest is **refused**, not
  trust-on-first-use pinned. Enforcement lives inside `CmisState::bind_host_key`
  so a rejected node leaves **no TOFU pin** behind (a pin would let the next
  attempt appear `Pinned` and bypass the gate). Default off (backward-compatible);
  production deployments using tier B should enable it.
- **`host_key_svid_ttl_secs`** (env `CMIS_HOST_KEY_SVID_TTL_SECS`): optional
  shorter SVID lifetime for the `host-key` policy tier so the lower-assurance
  identities re-attest more often.
- **On-prem vTPM EK trust** (`CMIS_VTPM_EK_ROOTS`, `:`-separated PEM paths): loads
  operator-run EK-CA root(s) into the `VendorTrustStore` under the new
  `Vendor::OnPrem`, so a swtpm/vSphere vTPM EK (which does not chain to a hardware
  vendor) can be trusted. The guest image's PCR-aggregate digest must also be
  approved in the RIM allowlist (`CMIS_RIM_BUNDLE`).

## Operating a vTPM host (tier A)

1. Give the guest a vTPM (KVM: `swtpm`/libvirt `<tpm model='tpm-crb'>`; vSphere:
   add a vTPM device; both need EFI/secure boot).
2. Provision the EK cert from your EK-CA; place the DER on the host and set
   `attestation.tpm.ek_cert`.
3. On CMIS: `CMIS_VTPM_EK_ROOTS=/etc/ferrogate/vtpm-ek-ca.pem`, and approve the
   golden image's PCR digest in the RIM bundle.
4. mia with `backend = "auto"` (or `"tpm"`) now attests hardware-rooted; the SVID
   carries a non-`host-key` policy id.

## Verification

- `cargo test -p ferro-sep` — sealed round-trip, clone rejection, legacy migration.
- `cargo test -p cmis --test host_key_enrollment` — strict-mode rejects
  unregistered nodes and leaves no pin.
- `cargo test -p mia --test swtpm_attest` (Linux + `swtpm`) — the `TpmEvidence`
  adapter's quote verifies end-to-end against the CMIS verifier.
- See `scripts/f02-docker.sh` for the Linux/TSS2 + swtpm test image.
