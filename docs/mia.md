# MIA — Machine Identity Agent

## Responsibilities

- Own the local TPM 2.0 device and drive the attestation protocol.
- Maintain a sealed, short-lived SVID and refresh it before expiry.
- Authenticate to CMIS over hybrid-PQC TLS with pinned SPKI.
- Serve a local helper API (see [helper-api.md](helper-api.md)) that mints
  short-lived, DPoP-bound child tokens for vetted applications.
- Append local events (token grants, denials, rotations) to the audit channel.

## Hardening profile

The MIA is a single static-PIE Rust binary. It runs with the following
defences applied at startup, before any network or TPM I/O:

- `prctl(PR_SET_DUMPABLE, 0)` to prevent core dumps.
- `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
- `mlockall(MCL_CURRENT | MCL_FUTURE)` so key material never swaps to disk.
- `seccomp-bpf` allowlist of approximately 35 syscalls (TPM ioctl, socket,
  read/write, epoll, futex, mmap with guards, …).
- Drops to dedicated UID `_ferrogate` with capabilities reduced to
  `CAP_IPC_LOCK` only.
- Linux kernel command line is expected to include
  `ima_appraise=enforce ima_policy=appraise_tcb` so IMA-measured binary hashes
  are kernel-enforced.

The profile is applied by `mia::hardening::harden` on the startup thread,
*before* the tokio runtime spawns workers (so the seccomp filter is inherited
and `mlockall(MCL_FUTURE)` covers their allocations) and before any TPM or
network I/O. Every privileged syscall lives in the `ferro-harden` crate (the
Linux analogue of `ferro-winauth`); `mia` itself is `#![forbid(unsafe_code)]`.

Environment toggles for staged rollout and development:

- `FERROGATE_SECCOMP=enforce|audit|off` — seccomp mode. `audit` logs violations
  instead of killing, to discover allow-list drift before enforcing (default
  `enforce`).
- `FERROGATE_REQUIRE_IMA=0` — do not require enforced IMA (dev/CI only; default
  is to require it and refuse to start otherwise).
- `FERROGATE_RUN_AS_UID` / `FERROGATE_RUN_AS_GID` — drop to these instead of
  resolving the `_ferrogate` user.
- `FERROGATE_SKIP_HARDENING=1` — disable the whole profile (development only).

`unsafe` is forbidden in MIA code; FFI to `tss-esapi` (TPM) and `ferro-harden`
(hardening syscalls) are the only paths out, both through audited safe wrappers.

## Operational state machine

```
                ┌──────────────────────────────┐
                ▼                              │
        ┌──────────────┐  PCRs unchanged       │
   ┌───▶│ Have SVID    │──────────────────────▶│
   │    │ valid, fresh │  60% of TTL elapsed   │
   │    └──────┬───────┘                       │
   │           │ PCRs changed                  │
   │           │ or TTL expired                │
   │           ▼                               │
   │    ┌──────────────┐                       │
   │    │ Re-attest    │                       │
   │    │ (4-phase)    │                       │
   │    └──────┬───────┘                       │
   │           │ success                       │
   └───────────┘                               │
                                               │
        ┌───────────────────────────┐          │
        │ Serve helper API          │◀─────────┘
        │ (always while SVID valid) │
        └───────────────────────────┘
```

The MIA serves the helper API only while it holds a valid SVID. There is no
"degraded mode" that returns un-attested tokens.

## TPM glue

The MIA uses `tss-esapi` and exposes a small synchronous engine wrapping:

- `load_ek()` — creates the EK in the endorsement hierarchy using the TCG
  default ECC-P256 template.
- `create_aik(ek)` — creates a restricted ECDSA signing child of the EK.
- `quote(aik, nonce)` — TPM2_Quote over the policy PCR set with the supplied
  nonce as `qualifyingData`.
- `activate_credential(aik, ek, credential_blob, secret)` — TPM2_ActivateCredential.
- `sign_aik(aik, message)` — TPM2_Sign with the AIK, used to bind the composite
  CSR.

All TPM operations run under bound HMAC sessions to defeat physical interposer
attacks on the LPC / SPI bus.

## Local SVID storage

The SVID and its composite private key are sealed using `TPM2_Create` against
a policy over PCRs `{0, 4, 7, 8}`. On reboot:

- If the unseal succeeds, the MIA continues with the cached SVID until
  rotation is due.
- If the unseal fails (PCR drift, lid open, kernel update), the cached SVID
  is treated as gone and a full re-attestation runs.

## Configuration sketch

```toml
[hardening]
seccomp_profile     = "strict"
memlock             = true
no_new_privs        = true
ima_required        = true
allowed_pcr_policy  = "secure-boot-v3"
ek_vendor_roots     = ["/etc/ferrogate/roots/infineon.pem",
                       "/etc/ferrogate/roots/nuvoton.pem",
                       "/etc/ferrogate/roots/st.pem"]
tpm_device          = "/dev/tpmrm0"

[cmis]
endpoint            = "https://cmis.prod.ferrogate.internal:8443"
spki_pins_sha384    = ["<pin1>", "<pin2>"]
hybrid_tls_only     = true
crl_max_age_seconds = 300

[helper]
uds_path            = "/run/ferrogate/mia.sock"
uds_mode            = 0o660
uds_group           = "ferrogate-clients"
allowlist           = "/etc/ferrogate/allowlist.toml"
```

## Failure modes

| Failure | Behaviour |
|---------|-----------|
| TPM device missing or busy | exit non-zero; service manager retries with backoff |
| CMIS unreachable at startup | retry forever; helper API not started |
| CMIS reachable but rejects attestation | exit non-zero; audit local denial |
| SPKI pin mismatch | abort immediately; no TPM operations performed |
| IMA disabled at runtime | abort immediately |
| Cached SVID unseal fails | full re-attestation; not an error |
