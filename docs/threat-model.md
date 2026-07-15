# Threat Model

## Adversary classes

| ID | Adversary | Capability | Mitigation |
|----|-----------|------------|------------|
| A1 | Network attacker | Active MitM; harvest-now-decrypt-later traffic capture | Hybrid X25519 + ML-KEM-768 TLS 1.3, SPKI pinning |
| A2 | Compromised host OS (kernel root) | Read/write of MIA memory, syscall interception | SVID sealed to PCRs; TPM HMAC + bound sessions; IMA-measured binary hash gating |
| A3 | Compromised CMIS operator | Steal signing key from disk or RAM | TEE-resident keys; Shamir 3-of-5 sealed to enclave measurements; mlocked, zeroize-on-drop reconstruction |
| A4 | Cryptographically Relevant Quantum Computer | Break ECC/RSA retroactively | ML-DSA-65 for signatures, ML-KEM-768 for KEX; both hybridized with classical (AND-combiner) |
| A5 | Malicious peer host | Replay another node's TPM quote | Per-session 32-byte server nonce; EK certificate pinning; TPM2_ActivateCredential proof-of-residency |
| A6 | Insider with SIEM write access | Tamper with audit trail | Merkle-chained STH signed inside TEE; write-once local-disk WORM store (`O_CREAT|O_EXCL`); public transparency anchor |
| A7 | Local userspace attacker | Steal token from MIA UDS socket | SO_PEERCRED + IMA runtime hash + signed allowlist; DPoP sender-constraint |

## Security goals

- **G1 — Hardware-rooted identity.** Every SVID is provably bound to a specific
  TPM EK whose certificate chains to a vendor root (Infineon, Nuvoton, ST,
  Intel PTT, …).
- **G2 — Boot integrity binding.** SVIDs are only valid when PCRs match an
  approved Reference Integrity Measurement (RIM) bundle covering Secure Boot,
  the signed kernel, and the signed initramfs.
- **G3 — Forward and post-quantum secrecy.** All channels and signatures must
  remain secure against an adversary who can break either the classical or the
  PQC primitive, but not both.
- **G4 — Tamper-evident audit.** Removal or mutation of audit entries is
  cryptographically detectable by any third party with the public STH stream.
- **G5 — Sender-constraint.** Stolen bearer tokens cannot be replayed by a
  party that does not hold the DPoP key.
- **G6 — Compromise containment.** A single CMIS node compromise cannot mint
  backdated or long-lived SVIDs; key reconstruction requires a threshold of
  enclaves with valid attestation.

## Attestation assurance tiers (F16)

Not every host has a TPM. mia attests at the strongest tier a host supports, and
CMIS distinguishes them:

- **Tier A — (v)TPM (F02/F16).** Satisfies G1/G2: a hardware or hypervisor vTPM
  quote chaining to a trusted EK root (vendor, or an operator EK-CA for on-prem
  vTPMs via `Vendor::OnPrem`) with an approved PCR/RIM digest.
- **Tier B — software host-key (F15/F16).** For TPM-less hosts. **Does not meet
  G1 or G2** — there is no hardware root of trust and no measured boot. Identity
  is a machine-fingerprint-derived signing key. The at-rest key is sealed to the
  fingerprint (clone *resistance* against a copied key file), but this is **not**
  confidentiality against a local root attacker, who can re-derive the seal secret
  from DMI. Tier B is therefore gated: offline-signed fleet-manifest enrollment
  (optionally requiring pre-registration, refusing trust-on-first-use), a distinct
  `host-key` policy id so trust domains can refuse it, and an optionally shorter
  SVID TTL. Treat tier-B identities as continuity-of-a-key, not proof of a genuine
  machine.

## Out of scope

- Physical attacks against the TPM package (decapping, side-channel against
  silicon). FerroGate assumes vendor TPM tamper-resistance is intact; remediation
  is fleet-level EK revocation, not in-band.
- Supply-chain compromise of vendor EK certificates. Mitigated by maintaining
  multiple vendor roots and a manually-curated allowlist of fleet EK hashes.
- Denial of service against CMIS or the LB tier. Standard cloud DDoS controls
  apply; not addressed by this design.
