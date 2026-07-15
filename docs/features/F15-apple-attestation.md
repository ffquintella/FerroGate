# F15 — Host Machine-Identity Attestation (no TPM)

## Summary

> **Status: implemented (host-key profile).** Shipping today: `ferro-machineid`
> (fingerprint), `ferro-sep` (software + Secure-Enclave backends), the
> `host_key` wire profile, the CMIS verifier branch, fleet-manifest
> `enrolled_machine_id` enrollment, and the `mia` `run_attest_host_key` client.
> The Apple attestation tiers (MDA / App Attest) under "Future hardening"
> remain unbuilt. See "Implementation map" at the end.
>
> **On Linux VMs**, this `host-key` profile is the software fallback tier of
> [F16](F16-vtpm-tiered-attestation.md): mia uses a real (v)TPM when the host has
> one and this profile only when it does not. F16 also hardens the software key
> by sealing it at rest to the hardware fingerprint (clone resistance) and adds a
> CMIS knob to require fleet-manifest pre-registration instead of trust-on-first-use.

A Mac has no TPM and cannot run the TSS2 / `tss-esapi` stack that F02 and F04
depend on. As a pragmatic first step (and a useful fallback on any TPM-less
host), `mia` gains a second, lightweight attestation profile — **`host-key`** —
that anchors machine identity in **stable hardware serials** and signs the
handshake with a **non-exportable Secure Enclave key**.

This is deliberately *not* hardware-attested in the cryptographic sense the TPM
provides (no EK vendor chain, no measured-boot quote). It trades that for
near-zero deployment friction: no Apple Developer account, no MDM, no App Attest
entitlement, no Apple attestation servers. Apple's full attestation paths
(Managed Device Attestation, App Attest) are recorded below as a **future
hardening tier**, not the v1 target.

## The two ingredients

### 1. Identity anchor — hardware fingerprint (EK substitute)

A stable per-machine fingerprint, collected at runtime:

```
H = SHA-384( IOPlatformSerialNumber ‖ IOPlatformUUID ‖ boot-disk-serial )
```

Concrete macOS sources (all readable by the root `mia` daemon):

| Component | Source | Stability |
|-----------|--------|-----------|
| `IOPlatformSerialNumber` (board/machine serial — the Apple-Silicon analog of a "CPU serial") | `IOPlatformExpertDevice` via IOKit | burned-in |
| `IOPlatformUUID` | `IOPlatformExpertDevice` | burned-in |
| Boot-disk hardware serial (e.g. NVMe `Serial Number`) | IOKit storage tree | tied to the physical SSD, survives reformat |

`H` is the machine's **enrolled identity** — the direct analog of the EK-cert
hash in F13. It is *not* used as key material.

### 2. Signing key — random Secure Enclave key (AIK substitute)

A **randomly generated** P-256 key created once inside the **Secure Enclave**
(`kSecAttrTokenIDSecureEnclave`, non-exportable, `SecAccessControl` =
private-key-usage, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`). The
private key never leaves the SEP and cannot be lifted off a running host or a
cloned disk. Its public key (DER SPKI) is what CMIS pins.

> **Why random-in-SEP, not derived-from-serials.** A key *derived* from the
> serials (`HKDF(serials)`) would be reproducible by anyone who can read those
> serials — any root process, a disk-image copy, a cloned VM, a captured
> `ioreg` log. That yields identity but no secret. A random SEP key gives a
> genuine non-extractable secret for nearly the same code, so the fingerprint is
> used only for *identity*, the SEP key only for *signing*.

Fallback when no SEP exists (Intel Macs without T2, Linux without TPM, CI): a
random key stored in the platform keychain / a `0600` file bound to `H`. This is
weaker (the key sits at rest and can be copied) and CMIS issues it a lower
assurance level — see trust model.

## How the two are bound (the crux)

There is no attestation proving the SEP key is genuinely SEP-resident, so the
`H ↔ pubkey` binding is established two ways, both required:

1. **Manifest gate (offline trust).** `H` must appear in the offline-signed
   fleet manifest (F13) before any handshake proceeds — exactly the EK-hash
   pre-admission check (`crates/cmis/src/service.rs:196`).
2. **Pinned binding.** On first successful attest, CMIS records `(H → sep_pub)`.
   Every later attest for `H` must present the same `sep_pub`; a mismatch is
   rejected and audited (`HostKeyRebindRejected`). Optionally, operators
   pre-register `sep_pub` in the manifest (`enrolled_machine_pubkey`) to remove
   the trust-on-first-use window entirely.

Each handshake also carries a **freshly signed fingerprint claim** — the SEP key
signs `nonce ‖ H` — so CMIS confirms the presenter currently observes that
hardware and the signature is live (replay-bound by the server nonce).

## Protocol

Extends the F02 wire protocol with a profile discriminator (also lays the
groundwork for the Apple tiers later):

```
message AttestInit {
  oneof evidence {
    TpmEvidence     tpm      = 1;   // existing, byte-compatible
    HostKeyEvidence host_key = 2;   // NEW
  }
}
message HostKeyEvidence {
  bytes fingerprint = 1;  // H (SHA-384)
  MachineFacts facts = 2; // raw serials, so CMIS can recompute H and sanity-check
  bytes sep_pub     = 3;  // DER SPKI of the SEP key            (≈ aik_pub)
  bytes signature   = 4;  // ECDSA_sep(nonce ‖ H)               (≈ quote signature)
}
```

`host-key` runs a **3-phase** handshake (nonce → init → csr); the TPM-specific
phase-3 `ActivateCredential` round is skipped. Phase 4 is unchanged in shape:
the SEP key signs the composite SVID public key (`sign_aik` → SEP signature),
binding the issued SVID to the machine key.

## Trait & code organization

Generalize the TPM-shaped `AttestEvidence` (`crates/mia/src/client.rs:83`) into a
profile-agnostic attestor; `run_attest` branches on the profile:

```rust
pub enum Evidence { Tpm(TpmEvidence), HostKey(HostKeyEvidence) }
pub trait Attestor {
    fn collect(&mut self, nonce: &[u8]) -> anyhow::Result<Evidence>;
    /// TPM returns Some(secret); host-key returns None (no ActivateCredential).
    fn activate(&mut self, cred: &[u8], secret: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    fn sign_binding(&mut self, message: &[u8]) -> anyhow::Result<Vec<u8>>;
}
```

```
crates/mia/src/
  attest/mod.rs        // Attestor trait, Evidence enum (cross-platform)
  attest/tpm.rs        // #[cfg(target_os = "linux")]  (moved from src/tpm.rs)
  attest/host_key.rs   // HostKeyAttestor — SEP key + fingerprint
  seal/mod.rs          // SecretSealer trait
  seal/pcr.rs          // #[cfg(linux)]  (moved from src/seal.rs)
  seal/sep.rs          // #[cfg(macos)]  SEP-wrapped sealing
crates/ferro-sep/      // NEW. FFI: SEP key create/load/sign/export + IOKit fingerprint.
```

`mia` stays `#![forbid(unsafe_code)]`; all unsafe FFI lives in `ferro-sep`
(mirrors `ferro-harden` / `ferro-winauth` / `libproc`). Use the
`security-framework` crate for `SecKey`/Keychain and `io-kit-sys` for the
fingerprint; no shelling out to `ioreg`/`system_profiler` for security-critical
reads. A `ferro-machineid` module provides the per-OS fingerprint (macOS IOKit,
Linux DMI `product_uuid` + disk serial, Windows WMI) so `host-key` is usable as
the universal TPM-less fallback, not macOS-only.

## Sealing on macOS (F04 substitute)

1. Generate a 256-bit data-protection key.
2. Wrap it with the SEP key (`SecKeyCreateEncryptedData`,
   `eciesEncryptionStandardX963SHA256AESGCM`), or store it as a SEP-gated
   keychain item.
3. Reuse the existing ChaCha20-Poly1305 path (`seal.rs:222`) to encrypt the
   SVID + composite key.
4. Fold `H` into the AEAD **AAD**, so a cache that lands on different hardware
   (disk image moved to another machine) fails to unseal → forces re-attestation.

Device-bound via the SEP, but **not boot-state-bound** (no PCR equivalent).

## Enrollment (F13 extension)

`FleetManifest` gains a section parallel to `enrolled_ek_sha384`:

- `enrolled_machine_id: Vec<String>` — approved fingerprints `H` (lowercase hex).
- `enrolled_machine_pubkey` *(optional)* — pre-registered `sep_pub` per `H`, to
  close the TOFU window.

CMIS pre-admission (`service.rs:196`) branches on profile, checks `H` against the
manifest before signature verification, exactly as the EK gate does.

## Trust model (must land in `threat-model.md`)

This profile is an **assurance tier below TPM/SEP-attested**. CMIS marks SVIDs
issued under `host-key` with a lower assurance level (tie into F10 policy), so
policy can refuse it for sensitive trust domains.

- **No hardware attestation.** Nothing proves the SEP key is genuinely
  SEP-resident or that the host is unmodified at boot. Trust rests on: (a) `H`
  being in the offline-signed manifest, (b) the pinned/​pre-registered `H↔pubkey`
  binding, and (c) SEP non-exportability.
- **SEP payoff — disk clones don't transfer the key.** A copied disk on
  different hardware cannot sign (SEP keys are device-bound) *and* would present
  a different `H`. The file/keychain fallback loses this property → lower tier.
- **Spoofed fingerprint.** A root attacker on a host could forge `MachineFacts`,
  but `H` must already be enrolled in the signed manifest, so impersonation
  requires the operator to have enrolled the attacker's forged `H`.
- **TOFU race.** Without `enrolled_machine_pubkey`, the first claimant of an
  enrolled `H` binds the key. Mitigate with operator-confirmed enrollment or
  pubkey pre-registration.

## Future hardening (not in this feature)

When stronger assurance is needed, upgrade the same `host-key` plumbing to a real
Apple attestation, both of which prove genuine-Apple-hardware key residency:

- **Managed Device Attestation (ACME-DA)** — macOS 14+. The OS mints a SEP key
  inside an ACME CSR; the attestation cert carries the **serial number**, mapping
  cleanly onto serial-pinned enrollment. Requires the host be MDM-enrolled and
  **supervised** (ABM/ADE or Apple Configurator) and an APNs MDM push cert (via
  Apple Business Manager — free but org-verified). FerroGate could run the ACME
  CA itself, and optionally bundle a minimal MDM (NanoMDM-style) for orgs without
  one — but ABM + supervision remain Apple-side preconditions.
- **App Attest** (`DCAppAttestService`) — no MDM, but needs a paid Apple
  Developer account, the App Attest entitlement, and a signed/notarized `mia`.
  Proves genuine-Apple-hardware + our signed binary; identity = per-device key ID.

## Components touched

- `crates/mia` (attest/seal modules, `lib.rs` cfg gating, `client.rs` trait/handshake).
- `crates/ferro-sep` (new), `crates/ferro-machineid` (new or module).
- `crates/cmis` (verifier branch, fleet manifest, pre-admission, assurance level).
- `crates/ferro-proto` (`AttestInit` oneof, `HostKeyEvidence`, `MachineFacts`).

## Dependencies

- F02 (protocol shape), F03 (composite SVID binding), F04 (sealing), F10
  (policy / assurance level), F13 (enrollment manifest).

## Acceptance criteria

- [x] `Attest` proto carries the host-key evidence (added as `AttestInit.host_key`
      rather than a `oneof`, to keep the TPM flow byte-compatible).
- [x] `mia` computes a stable fingerprint `H` from board serial + platform UUID +
      disk serial; identical across reboots, differs across machines.
      (`ferro_machineid`; verified on real macOS hardware.)
- [x] macOS `mia` creates a non-exportable SEP key, signs `nonce ‖ H`, completes
      the 3-phase handshake, and is issued an SVID. (SEP key + sign verified live
      on an M2 via `ferro-sep`'s `live_sep_sign_then_verify`; end-to-end issuance
      via `host_key_attest.rs` using the software backend.)
- [x] CMIS gates on `H` ∈ manifest and verifies the `nonce ‖ H` and CSR
      signatures, with `HostEnrolled` / `HostRejected` / `SvidIssued` audit
      events.
- [x] `H ↔ sep_pub` pin: trust-on-first-use in CMIS (`bind_host_key`) plus
      optional operator pre-registration via the manifest
      (`enrolled_machine_pubkey`), which closes the TOFU window. Rebinds are
      rejected and audited.
- [x] The `mia` daemon attests on startup (`bootstrap_host_svid`) and enables the
      child-token minter from the issued SVID, replacing the `no_host_svid` stub.
- [ ] SVID cache seals via the SEP (F04 substitute) — **not yet** (`seal/sep.rs`).
- [ ] Daemon SEP key persistence — the daemon uses a persistent *software* key
      today; a non-exportable SEP key needs keychain-backed load/store in
      `ferro-sep` (the SEP crypto core is already proven by its live test).
- [x] `host-key` SVIDs carry a distinguishing `policy_id` (`"host-key"`) so policy
      can treat them as a lower assurance tier. (A richer assurance field is
      future work.)
- [x] `mia` remains `#![forbid(unsafe_code)]`; all FFI isolated in `ferro-sep`
      (which itself uses only `security-framework`'s safe wrappers).
- [x] Fallback (no SEP) path works on Intel/Linux/CI via `SoftwareMachineKey`.

## Implementation map

| Piece | Where |
|-------|-------|
| Hardware fingerprint `H` | `crates/ferro-machineid` (macOS `ioreg`, Linux sysfs/DMI) |
| `MachineKey` trait, software + SEP backends, P-256 verify | `crates/ferro-sep` (SEP behind the off-by-default `secure-enclave` feature) |
| Wire evidence | `AttestInit.host_key`, `HostKeyEvidence`, `MachineFacts` in `crates/ferro-proto/proto/machine_identity.proto` |
| Server-side verification | `crates/ferro-attest/src/host_key.rs` |
| Handshake branch + issuance | `run_attest_host_key` in `crates/cmis/src/service.rs` |
| Enrollment | `enrolled_machine_id` in `crates/cmis/src/fleet_manifest.rs`; `--machine` / `--machine-pubkey` flags in `tools/fleet-manifest` |
| `H ↔ sep_pub` pin | `bind_host_key` / `HostKeyBinding` in `crates/cmis/src/state.rs`; pre-registration via `MachinePubkey` / `enrolled_machine_pubkey` in `fleet_manifest.rs` |
| Client | `run_attest_host_key` in `crates/mia/src/client.rs` |
| Daemon bootstrap | `bootstrap_host_svid` in `crates/mia/src/main.rs` (attest on startup → build the F09 minter) |
| End-to-end test | `crates/mia/tests/host_key_attest.rs` (issuance, rejection, forged facts, TOFU rebind, pre-registration) |
