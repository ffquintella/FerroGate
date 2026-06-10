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

## Configuration

MIA reads an optional TOML **configuration file** and overlays **environment
variables** on top. The precedence, lowest to highest, is:

```
built-in defaults  <  configuration file  <  environment variables
```

so an explicitly-set `FERROGATE_*` / `RUST_LOG` variable always overrides the
file, and a deployment that sets everything through the systemd
`EnvironmentFile` (`/etc/ferrogate/mia.env`) keeps working with no file present.

### Supported platforms

MIA runs on **Linux, macOS, and Windows**. The helper-API transport and caller
authentication differ per OS:

| OS | transport | caller authentication | hardening |
|----|-----------|------------------------|-----------|
| Linux | Unix domain socket | `SO_PEERCRED` + IMA cross-check | seccomp / mlockall / privilege-drop |
| macOS | Unix domain socket | peer-cred (`LOCAL_PEERPID`) + on-disk image SHA-384 (via `libproc`) | n/a |
| Windows | named pipe | client PID + image SHA-384 + Authenticode | n/a |

The TPM attestation loop is Linux-only; on macOS/Windows MIA runs as the
helper-API surface. The startup hardening profile applies on Linux only.

### Configuration file

The file is discovered in this order:

1. `mia --config <path>` (must exist),
2. `$FERROGATE_CONFIG` (if set, must exist),
3. the OS **system path**, then the **per-user path** (each loaded if present;
   absent ⇒ env/defaults only).

Per-OS locations:

| OS | system path | per-user path |
|----|-------------|---------------|
| Linux | `/etc/ferrogate/mia.toml` | `$XDG_CONFIG_HOME/ferrogate/mia.toml` (or `~/.config/...`) |
| macOS | `/Library/Application Support/FerroGate/mia.toml` | `~/Library/Application Support/FerroGate/mia.toml` |
| Windows | `%ProgramData%\FerroGate\mia.toml` | `%APPDATA%\FerroGate\mia.toml` |

A malformed file — including an unknown key — fails the daemon loudly at
startup rather than being silently ignored. The packaged template (source:
`crates/mia/dist/mia.toml`) is installed at the system path; every value is
commented out, so a fresh install behaves exactly as defaults until edited:

```toml
log = "info"

[cmis]
endpoint = "https://cmis.example.com:8443"
spki_pin = "<hex-sha384>"

[helper]
socket = "/run/ferrogate/mia.sock"   # presence enables the helper API
socket_mode = "660"

[allowlist]
path = "/etc/ferrogate/allowlist.cbor"
key  = "/etc/ferrogate/allowlist.pub"
max_age_secs = 86400
fetch = false   # fetch this host's allowlist from CMIS at startup and write `path`
propose = false # propose the callers this host observes back to CMIS (bootstrap)

[attestation]
ima_log = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
```

Each key has an environment-variable equivalent that overrides it:

| TOML key | Environment variable |
|----------|----------------------|
| `log` | `RUST_LOG` |
| `cmis.endpoint` | `FERROGATE_CMIS_ENDPOINT` |
| `cmis.spki_pin` | `FERROGATE_CMIS_SPKI_PIN` |
| `helper.socket` | `FERROGATE_HELPER_SOCKET` |
| `helper.socket_mode` | `FERROGATE_HELPER_SOCKET_MODE` |
| `helper.windows_group` | `FERROGATE_HELPER_WINDOWS_GROUP` |
| `allowlist.path` | `FERROGATE_ALLOWLIST` |
| `allowlist.key` | `FERROGATE_ALLOWLIST_KEY` |
| `allowlist.max_age_secs` | `FERROGATE_ALLOWLIST_MAX_AGE_SECS` |
| `allowlist.fetch` | `FERROGATE_ALLOWLIST_FETCH` |
| `allowlist.propose` | `FERROGATE_ALLOWLIST_PROPOSE` |
| `allowlist.propose_interval_secs` | `FERROGATE_ALLOWLIST_PROPOSE_INTERVAL_SECS` |
| `attestation.ima_log` | `FERROGATE_IMA_LOG` |

### `mia setup` — interactive wizard

Rather than hand-editing the env file, run the bundled wizard:

```console
$ sudo mia setup
```

`mia setup` is a rich-terminal, guided wizard (arrow keys / typed answers, with
validation and per-field help) that walks through the agent's configuration —
the CMIS server to connect to, the local helper API, the caller allowlist,
attestation, and log verbosity — and writes the **TOML configuration file** in
the documented, self-commenting form. It writes the OS **system path** by
default (see the per-OS table above) and prompts platform-appropriately (socket
mode on Unix, the pipe group on Windows). Run against an existing file it
pre-fills every prompt with the current value, so it doubles as an editor.
Options:

- `-u, --user` — target the per-user config path instead of the system path
  (no elevation needed).
- `-o, --output <path>` — target a specific path.
- `-c, --clean` — delete the stored configuration instead of writing one
  (honours `--user`/`--output` to choose which file; prompts unless `--force`).
- `-f, --force` — skip the confirmation prompt (write or clean).

When you configure an allowlist *and* have supplied a CMIS endpoint + SPKI pin,
the wizard offers to **fetch the enrollment public key from CMIS** (the
`GetEnrollmentKey` RPC, over the pinned hybrid-PQC TLS channel) and write it to
your `allowlist.key`. This is the key that signs the allowlist, so the agent can
verify it. The signed allowlist *body* itself (the CBOR at `allowlist.path`) is
also issued and served by CMIS per host: an operator stores it with
`ferrogate allowlist set` and the body is fetched with the `GetAllowlist` RPC,
keyed by the host's EK-derived UUID. The wizard additionally offers to enable
**`allowlist.fetch`** — when set, the daemon pulls this host's allowlist from
CMIS at every start (after attestation supplies its identity) and writes
`allowlist.path` before loading, so it stays in sync without out-of-band
delivery. See [allowlist-provisioning.md](allowlist-provisioning.md) for the full
workflow.

**`allowlist.propose`** closes the bootstrap gap from the other direction. With
it enabled the daemon periodically sends CMIS the local callers it has actually
observed — every `(uid, binary SHA-384)` it authenticates, *granted or denied* —
via the `ProposeAllowlist` RPC. The proposal is signed by the host machine key
and accompanied by the host SVID, so CMIS can prove which attested host sent it
(there is no mTLS; the SVID is the in-band proof). What CMIS does with it is set
by its `CMIS_ALLOWLIST_PROPOSALS` policy:

- `bootstrap` (default) — auto-adopt the proposal **only** when the host has no
  allowlist yet (trust-on-first-use). It is signed and served immediately, so a
  freshly installed host populates its own allowlist instead of an operator
  hand-enumerating callers. Any later change to an existing allowlist is queued.
- `off` — never auto-adopt; every proposal is queued for review.
- `always` — auto-adopt every proposal (weakest; a compromised-but-attesting
  host can grant itself callers).

Queued proposals are reviewed by an operator with `ferrogate allowlist
proposals` / `review <host>` / `approve <host>` / `reject <host>`. Because a
deny-all host denies (and therefore records) every legitimate caller, those
denials are exactly the entries a first proposal carries. The presented SVID is
the one obtained at startup, so proposals stop being accepted once it expires
until mia restarts.

It requires a TTY; for unattended provisioning (configuration management),
write the TOML file directly from the template in `crates/mia/dist/mia.toml`.

### `mia test` — connectivity and token-issuance self-test

```console
$ mia test
```

A non-interactive diagnostic that exercises the full path a local application
depends on and exits non-zero if any step fails, so it can gate provisioning
scripts. It runs four checks in order:

1. **configuration** — a CMIS endpoint and a valid SPKI pin resolve from the
   usual config-file/environment precedence;
2. **CMIS connection** — an eager dial over pinned hybrid-PQC TLS, validating
   DNS, TCP, the X25519MLKEM768 handshake, and the SPKI pin;
3. **CMIS CRL publishing** — the `JWKS` RPC returns a signature-valid, fresh
   CRL (the freshness the helper API fail-closed gates minting on, F11);
4. **helper token mint** — a real `HelperReq` over the local helper socket,
   reporting the minted token or interpreting the refusal.

Each failing step prints targeted remediation hints (mirroring the
[operations runbooks](operations/runbooks/README.md)); a `crl_stale` refusal in
step 4 is cross-referenced with step 3's result to say whether the server or
the agent is at fault. Note that step 4 authenticates *this command's binary
and uid* like any other caller, so on a host with a restrictive allowlist a
`PermissionDenied` ("not-allowlisted") refusal still proves everything up to
the allowlist check works. Options:

- `-c, --config <path>` — TOML config file (same resolution as the daemon).
- `-a, --audience <aud>` — audience for the test token (default
  `https://selftest.ferrogate.invalid`).

## Configuration sketch (aspirational)

> Forward-looking superset showing where the schema is headed (hardening
> toggles, multiple SPKI pins, CRL age). The authoritative, currently-honored
> keys are the ones in **Configuration** above and in `crates/mia/dist/mia.toml`.

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
# Dialed over hybrid-PQC TLS via mia::client::connect_pinned. The endpoint is
# trusted by SPKI pin, not by CA chain; compute pins with the OpenSSL recipe in
# transport-tls.md. Multiple pins allow overlap during certificate rotation.
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
