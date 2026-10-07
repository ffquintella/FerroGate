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
  `CAP_IPC_LOCK` (keep secret memory `mlock`'d) and `CAP_SYS_PTRACE` (read a
  helper-API caller's `/proc/<pid>/exe` to authenticate it — a non-root daemon
  needs this to identify callers under other UIDs; the `ptrace` **syscall**
  itself stays blocked by the seccomp allowlist, so this is read-access only).
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

### The X.509-SVID store

The certificate profile (feature [F17](features/F17-x509-svid.md)) is persisted
the same way, by `mia::credstore`, in `<state-dir>/x509-svid.sealed` (`0600`;
`/var/lib/ferrogate` on Linux). One file holds the leaf certificate, the trust
bundle it chains to, and the Ed25519 private key the certificate names — the
key a TLS stack needs to use the credential. The ML-DSA-65 half of the host's
composite key is not stored: it is not needed to use the certificate, so the
blast radius stays with the classical key.

The data-protection key is bound to the machine, and how depends on what the
host has:

| Backend | Key protected by | Opens only |
|---|---|---|
| `tpm` | a random key sealed by the TPM to PCRs `{0,4,7,8}` | on this TPM, in this boot state |
| `secure-enclave` | a random key ECIES-wrapped to a non-exportable macOS Secure Enclave key | on this Mac's Enclave |
| `machine-key` | HKDF over the hardware fingerprint `H` (F16) | on a host with this fingerprint |

The first two are hardware roots of trust and are preferred in that order, even
on a host that attests through the software tier — a key the hardware releases
beats one derived from a fingerprint, and there is no reason to protect the
credential more weakly than the machine allows. A host with none of them gets
**no** store: writing the private key unsealed is worse than re-attesting.

#### The Secure Enclave backend (macOS)

The Enclave is the Mac's answer to a TPM. `mia` generates a P-256 key *inside*
it — the private half cannot be exported by anyone, root included — and
encrypts the store's data-protection key to its public half. Unwrapping is a
private-key operation the Enclave performs internally, so the file is inert on
any other Mac.

It needs two things:

1. the `secure-enclave` cargo feature (off by default, since it links
   Security.framework), which `make pkg-macos` enables; and
2. a **codesigned** binary carrying a keychain-access-group entitlement. macOS
   refuses to keep a Secure Enclave key in the keychain otherwise
   (`errSecMissingEntitlement`, -34018), and a key that dies with the process
   would leave the next start unable to open its own store. The entitlement is
   restricted, so ad-hoc signing does not work — AMFI kills the process at
   launch. Sign with a real Developer ID:

```sh
make pkg-macos CODESIGN_ID="Developer ID Application: Example (TEAMID)"
```

   after putting your team identifier into `crates/mia/dist/mia.entitlements`.

A build without either simply falls through to `machine-key`, logging the
reason at debug level. Nothing fails; the credential is just protected at the
software tier.

Loading is fail-closed. The daemon returns a stored credential only if it
unseals here *and* still verifies — the certificate must chain to its bundle
under both signature halves, must not have expired, and its stored key must be
the one the certificate names. Anything else is logged and the file is deleted,
so the next start does not retry a file that can never open again. This is what
a TPM host sees after a firmware update, and it is the intended behaviour.

The store does not decide whether to attest: the daemon attests on every start
regardless, and a fresh issuance overwrites the file. What the store buys is a
credential that survives a restart and can be inspected — and, critically, one
that is worthless on any other machine.

### The machine key and SVID seed

The host-key profile's software machine signing key lives in
`<state-dir>/host-key.bin` (`ferro_sep::SoftwareMachineKey`), sealed to the
hardware fingerprint `H` (F16). The 32-byte seed the composite SVID key is
derived from lives beside it in `svid-seed.bin`. `<state-dir>` is
`/var/lib/ferrogate` on Linux (`0750`, owned by `_ferrogate`) and the system
config directory elsewhere. On macOS that is
`/Library/Application Support/FerroGate`, which is `0755`. On Windows it is
`%ProgramData%\FerroGate`, where there is no file mode: the directory's
administrator-only DACL is what keeps these files private (see
[Configuration directory permissions](#configuration-directory-permissions)).

The seal stops a copied file from opening on another machine. It does **not**
stop a local user on the same machine: the fingerprint inputs are not secret,
and on macOS `ioreg` gives them to any user. The file mode is what keeps the
key private, so all three state secrets (`host-key.bin`, `svid-seed.bin`,
`x509-svid.sealed`) are owner-only:

- **New files** are created exclusively with mode `0600` by `open(2)`, so they
  are never wider than `0600` at any point, whatever the umask.
- **Existing files** that group or other can access are tightened to `0600`
  at daemon start, on Linux before the privilege drop. Each repair is logged at
  `warn` with the old mode. `ferro-sep` repeats the check whenever it opens the
  machine key, and refuses a key file it cannot make owner-only. The macOS
  package's postinstall does the same repair at upgrade.
- The pre-F16 migration (plaintext scalar re-sealed to the fingerprint) runs
  at daemon start while still privileged and replaces the file atomically
  (sealed copy written beside it, verified, then renamed over it), so a crash
  never leaves a torn key. The unprivileged attestation path only reads such a
  file.

Up to 0.22.0, `host-key.bin` was created with the process umask (`0644`). On
macOS that meant any local user could read it and recover the machine key. If a
host logs the `restricted it to 0600` warning, treat its machine key as
exposed. Tightening the mode does not undo a copy that was already made.
Rotating the key needs a new CMIS binding as well as a new file, because CMIS
pins `H ↔ pubkey` and rejects a rebind (`HostKeyRebindRejected`). No documented
procedure clears that binding yet.

#### The key is an identity: it is never silently replaced

Because CMIS pins the machine key's public half on first contact and refuses
any other key for the same fingerprint from then on, a host that mints a new
key while the pinned one still exists — or could be restored — is locked out
(status `host_rejected`) until a CMIS operator intervenes. MIA
therefore treats `host-key.bin` and `svid-seed.bin` as follows
(`mia::machine_key`):

| What is at `<state-dir>` | What MIA does |
|---|---|
| a regular, owner-only file owned by root or the state directory's owner, readable, that opens on this host | opens it; never rewrites it |
| a file that is a symlink or not a regular file, group/other-accessible, owned by anyone else, unreadable, refused by the Windows trust check, the wrong length, or sealed to another fingerprint | **refuses it (fail closed)** and leaves it untouched: no SVID, status code `machine_key_refused`, and an `error` log naming the file and the fix (e.g. `chown`/`chmod 0600`, restore from backup) |
| nothing, but the file is at a former location (Linux before 0.20.19: `/etc/ferrogate`) | the daemon moves it at start while still root — exclusive copy, `0600`, handed to `_ferrogate`, verified, then the old copy removed — and uses it; if the move fails it refuses rather than mint |
| no key, but `svid-seed.bin` is still there (it is only ever created after the key, so the key was lost) | **refuses** to create a key: restore `host-key.bin` from backup, or — only for a deliberate re-enrollment after the CMIS operator cleared the pin — delete the seed too |
| nothing anywhere | creates it exclusively (`O_EXCL`, `0600`) and logs at `warn` that a new host identity was created |

A refused file is retried at every re-attestation (every 5 minutes), so
repairing ownership or mode is enough — no restart is needed. If CMIS then
refuses a host whose key this agent created at the same start, the log says
that the likeliest cause is a key rebind and that the original `host-key.bin`
should be restored from backup.

Installs, upgrades and uninstalls never create, replace or delete these
files: the Debian/RPM packages do not own `/var/lib/ferrogate`, the Windows
installers do not own `%ProgramData%\FerroGate`, and the macOS package ships
its default configuration as templates in `/usr/local/share/ferrogate` (copied
into place only where no file exists), so its receipt owns neither
`/etc/ferrogate` nor `/Library/Application Support/FerroGate`. On macOS,
`sudo mia-uninstall` removes the programs and keeps the configuration and the
identity; `sudo mia-uninstall --purge` deletes them too, which is only right
when the machine is retired or is to be re-enrolled after the CMIS operator has
cleared its key pin. Do not delete `/Library/Application Support/FerroGate` by
hand to "reset" an install.

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

### Running as a Windows service

On Windows the daemon runs under the Service Control Manager as the **`mia`**
service, so `Restart-Service mia` (or `sc start mia` / `sc stop mia`) works and
the agent starts at boot. The Windows installer (`make pkg-win`) registers and
starts it automatically; to manage it by hand:

```powershell
mia service install     # register an auto-start LocalSystem service (needs admin)
mia service start
mia service stop
mia service uninstall
mia service secure-config  # make %ProgramData%\FerroGate administrator-only (needs admin)
Restart-Service mia      # once installed
```

The service runs as `LocalSystem`, reads its configuration from the system path
(`%ProgramData%\FerroGate\mia.toml`), and — because it has no console — writes
its logs to `%ProgramData%\FerroGate\logs\mia.log`. `mia service run` is the
internal entry point the SCM launches and is not meant to be run by hand. The
helper API is on by default, so a freshly installed service starts and stays
*Running*, serving `\\.\pipe\ferrogate-mia` and refusing every token request
until CMIS and the allowlist are configured (fail closed). Set
`helper.enable = false` to switch the helper API off; the daemon then exits
cleanly (idle) and the service shows as *Stopped*.

The pipe's DACL restricts access to the local group named by
`helper.windows_group` (default `FerroGateClients`). The installer creates this
group; **add the accounts of vetted client applications to it** so they may
request tokens (`net localgroup FerroGateClients <account> /add`). If the group
does not exist, the daemon cannot resolve its SID and fails to bind the pipe
(`ERROR_NONE_MAPPED`); set `helper.windows_group` blank to fall back to the
default DACL. On a manual `mia service install` (no installer), create the group
yourself first.

Past the pipe DACL, the daemon also authenticates each caller's *image*: by
default it requires a valid **Authenticode** signature (the Code-Integrity
analogue of the Linux IMA check). An unsigned caller — including an unsigned
`mia.exe` running `mia test` — is refused as `untrusted-binary`. Note that the
stock `make pkg-win` build is unsigned, so this refusal happens out of the box;
pass `WIN_SIGN_PFX=/path/to/codesign.pfx` to `make pkg-win` to sign `mia.exe`
and the MSI (the daemon also warns at startup when its own image would fail the
check it enforces). For
environments that do not code-sign their binaries, set
`helper.require_authenticode = false` (or `FERROGATE_HELPER_REQUIRE_AUTHENTICODE=0`);
identity then rests on PID + image SHA-384 + RID, and `mia`'s self-trust still
lets the agent talk to its own daemon. Token minting additionally needs a host
SVID, which on Windows comes from host-key attestation
([`ferro-machineid`](../crates/ferro-machineid) collects the SMBIOS/disk
fingerprint); a host that CMIS has not enrolled is refused `no_host_svid`.

#### Configuration directory permissions

The service trusts what it finds in `%ProgramData%\FerroGate` without being
told where to look: the discovered `mia.toml` / `mia-<env>.toml`,
`environments.toml`, the default allowlist body `allowlist[-<env>].cbor`,
usually `allowlist.key`, and — because the state directory is the
configuration directory on Windows — the machine key `host-key.bin`,
`svid-seed.bin` and `x509-svid.sealed`. A folder created under
`%ProgramData%` inherits a DACL that lets `BUILTIN\Users` create files and
folders in it (and owns what they create) and lets every user read it. Up to
0.24.0 the directory was created that way, so any local user could plant a
configuration, an environment selection, an allowlist body (still verified
against `allowlist.key`, but able to deny every caller or replay an older
signed body within `max_age`) or a machine key for the `LocalSystem` service to
load, and could read the machine key, which on Windows has no file mode to
protect it.

The directory is now **administrator-only**: owner `BUILTIN\Administrators`, a
protected DACL (nothing inherited from `%ProgramData%`) granting `SYSTEM` and
`BUILTIN\Administrators` full control, inherited by everything below it, and no
other principal — not `Users`, `Authenticated Users` or `CREATOR OWNER`, not
even read access. In SDDL: `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`.

- **Service start.** Before it reads anything — and before it opens its log —
  the service makes the directory administrator-only (`mia::system_dir`). It
  opens every object without following reparse points and judges and changes
  it through that same handle, so a directory swapped for a junction is never
  what gets changed:
  1. a missing directory is created with that descriptor in one step; an
     existing one that is not administrator-only gets that owner and DACL
     (on the directory alone, for now);
  2. everything below it is walked: a symbolic link, junction or other
     reparse point anywhere refuses the start, and every subdirectory that is
     not administrator-only — for example a `logs` folder a user created
     before the install — is locked the same way;
  3. only then are the inherited ACEs of the files below each locked
     directory re-derived. Their owners and explicit ACEs are left alone.

  A repair is logged as a `warn` naming each directory and why. A failed
  repair, or a reparse point, stops the service.
- **Installers.** The Chocolatey package and the legacy NSIS installer run the
  same code with `mia service secure-config` (elevated) on every install and
  upgrade, and abort if it fails. The bare MSI cannot run commands (`wixl`);
  there the service does it at its first start. An administrator can run
  `mia service secure-config` at any time to repair the directory; prefer it
  to `icacls` sequences such as `/reset` followed by `/inheritance:r`, which
  briefly re-open the directory to `Users` in between.
- **Every load.** Before reading a configuration file, `environments.toml`, the
  allowlist body or key, the machine key, the SVID seed or the sealed
  X.509-SVID store **inside that directory**, `mia` refuses the file
  (`PermissionDenied`) when the file — or any directory between it and
  `%ProgramData%\FerroGate` — is owned by anyone but `SYSTEM` or
  `BUILTIN\Administrators`, has a NULL DACL, is a reparse point, is a file
  with more than one hard link, or has an ACE that grants anyone else a write
  right (`FILE_WRITE_DATA`/`ADD_FILE`,
  `FILE_APPEND_DATA`/`ADD_SUBDIRECTORY`, `FILE_WRITE_EA`,
  `FILE_WRITE_ATTRIBUTES`, `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`,
  `WRITE_OWNER`, or a generic right that maps to one). Deny ACEs and
  inherit-only ACEs are ignored; an ACE type it does not recognise that carries
  a write right is refused. The file is opened without following a reparse
  point, judged through that handle and read from it, so nothing can be
  swapped in between; a guarding directory that does not exist is `NotFound`.
  The service's `logs\mia.log` is opened the same way and refused under the
  same rules (a junction, link, hard link or foreign-owned file there stops
  the service). The outcome follows the existing fail-closed rules:
  a refused configuration or `environments.toml` stops the service; a refused
  default allowlist body or key denies every caller (an explicit
  `allowlist.path` stops it, as any read error does); a refused machine key
  disables host-key attestation; a refused SVID seed is never overwritten and
  an ephemeral key is used. Paths named explicitly **outside** the directory
  (`--config`, `allowlist.path`, `allowlist.key`) and the per-user directory
  are not judged.
- **Writers.** On Windows clients a file an elevated administrator creates is
  owned by their own account, which the check refuses. `mia setup` (wizard and
  `--apply`), `mia default-environment`, `mia resync-allowlist`,
  `mia allowlist-key fetch` (and its deprecated alias `mia refresh-key`) and
  the daemon's `allowlist.fetch` therefore write a fresh
  file owned by `BUILTIN\Administrators` and rename it over the target. They
  need an elevated prompt, and run the same preparation as the service first:
  a missing directory is created administrator-only and an existing one is
  checked and repaired, or refused when the prompt is not elevated.

A file someone else created stays refused, by design: the service cannot tell
a planted file from an intended one. The error names the file, its owner or
the offending ACE. If you did not put the file there, delete it. To keep a file
you created yourself (for example one copied in with Explorer, or written by an
older `mia` before this change), review it, then:

```powershell
icacls "$env:ProgramData\FerroGate\mia.toml" /setowner *S-1-5-32-544
icacls "$env:ProgramData\FerroGate\mia.toml" /reset
```

On upgrade the Chocolatey package does this for files whose owner is a direct
member of the local Administrators group, and lists every other foreign-owned
file without touching it. To inspect the directory, run
`icacls "$env:ProgramData\FerroGate"`: it should list only
`NT AUTHORITY\SYSTEM:(OI)(CI)(F)` and `BUILTIN\Administrators:(OI)(CI)(F)`.

Unprivileged users can no longer read anything in the directory, matching the
`0640` configuration and `0600` secrets on Linux. `mia status` falls back to
the default status endpoint as it does on Linux; `mia test`, `mia setup --dump`
of the system configuration and the tray's **Open full log** (Notepad on
`logs\mia.log`) need an elevated prompt. To let users read the log file only:

```powershell
icacls "$env:ProgramData\FerroGate\logs" /grant *S-1-5-32-545:(OI)(CI)RX
```

This grant does not affect the checks above, which only look at write rights
and at the directories that hold trusted files.

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

#### Selecting an environment

`--environment <env>` (short `-e`) selects `mia-<env>.toml` instead of `mia.toml`
at the **system path** and **per-user path** above — so one host can carry
side-by-side configs for different deployments and switch between them per
invocation:

```
mia --environment staging              # daemon reads mia-staging.toml
mia test --environment staging         # self-test against the staging deployment
mia resync-allowlist -e prod --reload  # resync against prod
mia setup --environment staging        # write mia-staging.toml (composes with --user)
```

The selector accepts every command that reads or writes the config (`mia`,
`setup`, `test`, `resync-allowlist`, `allowlist-key`, `refresh-key`). The name must be a safe
filename component (letters, digits, `.`, `-`, `_`). It is **mutually exclusive
with `--config`/`--output`**, which name one exact file; it only changes which
file the standard discovery (step 3) looks for, leaving `$FERROGATE_CONFIG` and
the `FERROGATE_*` env overlays unchanged. The daemon's SIGHUP live-reload
re-reads the same `mia-<env>.toml` it started from.

#### Serving every environment at once

Run **without** a selector and the daemon serves *all* discovered environments
concurrently in one process:

```
mia          # serve mia.toml AND every mia-<env>.toml found, each on its own socket
```

It scans the system and per-user config directories for `mia.toml` (the
`default` environment) and every `mia-<env>.toml`, then for each one attests to
that environment's CMIS and binds that environment's **own** `helper.socket`. A
local caller fetches a token for whichever environment it needs by connecting to
that environment's socket — so a single agent backs several deployments at once
(e.g. `prod` and `staging` CMIS clusters side by side). Each environment runs its
own attestation, allowlist fetch/propose, and CRL puller, including SRV-based HA
fail-over, independently — one environment failing (unreachable CMIS, a socket
that won't bind) is logged and isolated; the others keep serving.

Notes and constraints:

- **Each environment needs a distinct `helper.socket`.** An unset
  `helper.socket` already resolves to an env-suffixed default (e.g.
  `mia-staging.sock`, see [Helper listener](#helper-listener-default-and-off-switch));
  a duplicate socket across environments is skipped with an error rather than
  crash-looping the one that bound first.
- `mia.toml` serves the well-known `mia.sock` unless another environment is
  selected as the host's default; see
  [Default environment](#default-environment-who-serves-the-well-known-address).
- An environment with `helper.enable = false` is left idle (not served).
- `--config`, `--environment`, or `$FERROGATE_CONFIG` pins the daemon to **one**
  environment (the all-environments scan is bypassed). To serve only the default
  `mia.toml` when named environments also exist, pass its path with `--config`.
- The process-wide log directive comes from the base `mia.toml` (or `RUST_LOG`);
  every log line is tagged with its `environment`. A SIGHUP reloads all of them.
- The `FERROGATE_*` environment overlay applies to every loaded config, so avoid
  setting host-wide overrides like `FERROGATE_HELPER_SOCKET` in this mode (they
  would collide across environments).

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
enable = true                        # the default; false switches the helper API off
socket = "/run/ferrogate/mia.sock"   # optional; this is the Linux default
socket_mode = "660"

[allowlist]
path = "/etc/ferrogate/allowlist.cbor"   # optional; this is the Linux default
key  = "/etc/ferrogate/allowlist.pub"    # no default: required for any caller to be allowed
max_age_secs = 345600   # 96 h; must be >= the CMIS allowlist TTL
fetch = false   # fetch this host's allowlist from CMIS at startup and write `path`
propose = false # propose the callers this host observes back to CMIS (bootstrap)

[attestation]
ima_log = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
backend = "host-key"   # or "virtual-tpm" (INSECURE, dev/test only — see below)
```

Each key has an environment-variable equivalent that overrides it:

| TOML key | Environment variable |
|----------|----------------------|
| `log` | `RUST_LOG` |
| `cmis.endpoint` | `FERROGATE_CMIS_ENDPOINT` |
| `cmis.srv` | `FERROGATE_CMIS_SRV` |
| `cmis.spki_pin` | `FERROGATE_CMIS_SPKI_PIN` |
| `helper.enable` | `FERROGATE_HELPER_ENABLE` |
| `helper.socket` | `FERROGATE_HELPER_SOCKET` |
| `helper.socket_mode` | `FERROGATE_HELPER_SOCKET_MODE` |
| `helper.windows_group` | `FERROGATE_HELPER_WINDOWS_GROUP` |
| `helper.require_authenticode` | `FERROGATE_HELPER_REQUIRE_AUTHENTICODE` |
| `allowlist.path` | `FERROGATE_ALLOWLIST` |
| `allowlist.key` | `FERROGATE_ALLOWLIST_KEY` |
| `allowlist.max_age_secs` | `FERROGATE_ALLOWLIST_MAX_AGE_SECS` |
| `allowlist.fetch` | `FERROGATE_ALLOWLIST_FETCH` |
| `allowlist.propose` | `FERROGATE_ALLOWLIST_PROPOSE` |
| `allowlist.propose_interval_secs` | `FERROGATE_ALLOWLIST_PROPOSE_INTERVAL_SECS` |
| `attestation.ima_log` | `FERROGATE_IMA_LOG` |
| `attestation.backend` | `FERROGATE_ATTEST_BACKEND` |

#### Helper listener: default and off switch

The helper API is **on by default**. When neither `helper.socket` nor
`FERROGATE_HELPER_SOCKET` is set (a blank value counts as unset), the daemon,
`mia test` and `mia setup` all resolve the same per-platform, per-environment
default:

| OS | default environment (`mia.toml`) | named environment (`mia-<env>.toml`) |
|----|----------------------------------|--------------------------------------|
| Linux | `/run/ferrogate/mia.sock` | `/run/ferrogate/mia-<env>.sock` |
| macOS | `/Library/Application Support/FerroGate/run/mia.sock` | `…/FerroGate/run/mia-<env>.sock` |
| Windows | `\\.\pipe\ferrogate-mia` | `\\.\pipe\ferrogate-mia-<env>` |

The environment is the `--environment` selector or, for a file loaded by path
(`--config`, `$FERROGATE_CONFIG`, serve-all discovery), the `<env>` in its
`mia-<env>.toml` name; any other file name is the default environment. An
explicit value still wins (precedence: default < `helper.socket` <
`FERROGATE_HELPER_SOCKET`).

To switch the helper API **off**, set `helper.enable = false` (or
`FERROGATE_HELPER_ENABLE=0`, which also overrides the file and, being
process-wide, applies to every environment the daemon serves). It wins over any
socket value. An unset `helper.socket` **no longer** disables the helper API:
configurations that relied on that must add `enable = false`. Being on is not
being open — callers still need a signed allowlist entry, and with no allowlist
every request is refused (fail closed).

Directories and permissions: on Linux, systemd creates `/run/ferrogate`
(`RuntimeDirectory=`) and the daemon, still root, hands each socket directory to
`_ferrogate` before dropping privileges — `0750`, or `02750` group-owned by
`helper.socket_gid` (the Debian package and `make mia-install` set
`FERROGATE_HELPER_SOCKET_GID` to `ferrogate-clients` / `ferrogate`), so the
socket bound after the drop inherits that group without a `chown` (forbidden by
the seccomp profile).

On macOS the root daemon owns `/Library/Application Support/FerroGate/run`:

- On **every** start it creates `run/` if needed and gives it mode `0750` and
  the helper group. The sockets in it get the same group.
- The helper group is `helper.socket_gid` when set. Otherwise it is the group of
  `/Library/Application Support/FerroGate`, which is `ferrogate-status` once the
  package's postinstall has handed the directory over. Members of that group can
  connect to the helper socket; the signed allowlist still decides who may mint.
- The config directory's group is adopted only while that directory is
  root-owned and not group- or world-writable. Otherwise `run/` is left as it is
  and a warning is logged. A `run/` that is a symlink is refused.
- macOS gives a new directory or socket its parent directory's group. A `run/`
  created by an older install, before the config directory was handed to
  `ferrogate-status`, therefore kept `wheel`, and so did its sockets. The daemon
  repairs this on start, and the postinstall repairs a `wheel` `run/` and its
  sockets during the upgrade.
- Environments that share `run/` should not set different `helper.socket_gid`
  values: each one re-applies its own gid to the shared directory on start.
- A custom `helper.socket` outside `run/` keeps the old behaviour: a directory
  the daemon creates gets `0750` and `helper.socket_gid`, and a pre-existing one
  is left alone.

On Linux and macOS sockets are `0660` (`socket_mode`), and a pre-existing
non-socket file at the path is refused, never deleted.

#### Allowlist: default location

Like the helper socket, the signed allowlist **body** has a per-platform,
per-environment default. When neither `allowlist.path` nor
`FERROGATE_ALLOWLIST` is set (a blank value counts as unset), the daemon,
`mia test`, `mia setup`, `mia resync-allowlist` and `mia allowlist-key` all
resolve the same file through `mia::config::default_allowlist_path`, beside the
system `mia.toml`:

| OS | default environment (`mia.toml`) | named environment (`mia-<env>.toml`) |
|----|----------------------------------|--------------------------------------|
| Linux | `/etc/ferrogate/allowlist.cbor` | `/etc/ferrogate/allowlist-<env>.cbor` |
| macOS | `/Library/Application Support/FerroGate/allowlist.cbor` | `…/FerroGate/allowlist-<env>.cbor` |
| Windows | `%ProgramData%\FerroGate\allowlist.cbor` | `%ProgramData%\FerroGate\allowlist-<env>.cbor` |

The environment is judged as for the helper socket, and the system directory is
used even for a per-user configuration file. Precedence: default <
`allowlist.path` < `FERROGATE_ALLOWLIST`. `allowlist.fetch` and
`mia resync-allowlist` write the body there.

The verification key **`allowlist.key` has no default**. It is the trust
anchor of the allowlist, so it must be named explicitly: a key file merely
present at a well-known path is never trusted. The default does not loosen the
fail-closed rules:

- no `allowlist.key` ⇒ every caller is denied (logged), and `allowlist.fetch`
  does not write anything; with an **explicit** `allowlist.path` and no key the
  daemon still refuses to start;
- a body that is missing, stale, unsigned or does not verify ⇒ every caller is
  denied;
- a default location that cannot be read (for example a directory in its place)
  ⇒ every caller is denied and the error is logged. The daemon still starts. An
  explicit `allowlist.path` that cannot be read still stops it, as before.

`mia test` prints the resolved body (marked `(default)`) and whether it verifies.

#### Installing `allowlist.key`: `mia allowlist-key`

Nothing installs the key by itself — not the daemon, not the installers, not
the helper or status socket. The daemon only *reads* it (at startup and on a
SIGHUP reload). An operator or a provisioning script installs it, as root:

```sh
# On CMIS (or any host with the CMIS SPKI pin): the value to expect.
ferrogate enrollment-key                     # 96 hex digits (SHA-384)
ferrogate enrollment-key --format flag       # --expect-fingerprint <hex>

# On the host (if allowlist.key is unset, fetch also names it in mia.toml):
sudo mia allowlist-key fetch --expect-fingerprint <hex> --reload
sudo mia allowlist-key fetch --reload        # on a terminal: asks for <hex>
sudo mia test --fix                          # the same, from the self-test
mia allowlist-key show                       # path + fingerprint, no privileges
```

`mia allowlist-key fetch [-c <config> | -e <env>] [--expect-fingerprint <hex>]
[--yes] [--rotate] [--reload]`:

- **Root only** (Windows: an elevated prompt, with `allowlist.key` inside
  `%ProgramData%\FerroGate`, whose administrator-only ACL enforces it). On Unix
  the key's directory must also be root-owned and not group/other-writable.
  The check runs before any network traffic.
- **Pinned channel only**: CMIS is dialed through the configured endpoint or
  SRV record with `cmis.spki_pin` over hybrid-PQC TLS. There is no unpinned
  fallback, and the reply must parse as a composite public key.
- **Consent, before any network traffic**: `--expect-fingerprint <hex>` checks
  the fetched key against the value from `ferrogate enrollment-key` and aborts,
  writing nothing, on a mismatch. Without the flag, on a terminal, the command
  asks for that fingerprint (96 hex digits, validated as typed; Esc aborts) and
  verifies the fetched key against it the same way. `--yes` accepts the key
  fetched over the pinned channel without a comparison (kept for `mia
  refresh-key` and the tray; not recommended). A non-interactive run with
  neither flag fails closed before dialing CMIS: nothing is fetched or written,
  and there is no trust-on-first-use path.
- **Unset `allowlist.key`**: `fetch` names the key file itself instead of
  failing — `allowlist.pub` (`allowlist-<env>.pub`) in the system configuration
  directory, the path `mia setup` suggests. It edits the configuration file it
  loaded surgically: one `key = "…"` line below the existing `[allowlist]`
  header, or a new `[allowlist]` table when there is none (never a second
  one); comments and every other key are kept, and the result must parse and
  differ by `allowlist.key` alone. The edit is written only after the key was
  fetched and accepted (a mismatch writes neither file), only by root into a
  root-owned directory, atomically (`0640`, owner kept, symlinks refused), with
  a `ConfigChanged { keys: ["allowlist.key"] }` audit record, and is abandoned
  if the file changed meanwhile. It is not a load-time default: the daemon
  still has none. Dotted keys, an inline `allowlist` table, a blank `key`, or a
  blank `FERROGATE_ALLOWLIST_KEY` are refused with the line to add by hand.
  `mia refresh-key` still requires a configured path.
- **Never silently replaced**: an identical installed key is left alone (no
  write, no audit record). A *different* installed key is refused, with both
  fingerprints shown, unless you pass `--rotate`.
- **Atomic and audited**: temp file, `fsync`, rename, mode `0644` (public
  material that the Linux daemon re-reads as its service user on a reload),
  owned by root. A symlinked or non-regular target is refused. Before the
  rename, a `ConfigChanged` record is appended to `config-audit.jsonl` beside
  the key. It carries key names only: `allowlist.key:enrollment-key`, or
  `allowlist.key:enrollment-key:rotated` for a rotation. Only fingerprints are
  ever printed.
- Afterwards it reports whether the allowlist body on disk verifies under the
  new key. `--reload` signals the running agent (SIGHUP) to pick it up live.

`mia refresh-key` is now a **deprecated alias** for `mia allowlist-key fetch
--rotate --yes`. It keeps its old meaning (replace the key after a CMIS key
rotation, without a prompt; the `mia-tray` "Re-fetch the enrollment key" action
runs it elevated), but it gains every check above. Unlike before, it needs
root, and on Windows a key path inside `%ProgramData%\FerroGate`.

After a CMIS key rotation: compare `mia allowlist-key show` with
`ferrogate enrollment-key`, then run `sudo mia allowlist-key fetch --rotate
--expect-fingerprint <new hex>` and `mia resync-allowlist --reload`.

#### Default environment: who serves the well-known address

The default-environment address in the table above (`mia.sock` /
`\\.\pipe\ferrogate-mia`) is the **well-known** helper address: the one local
callers dial without configuration. By default `mia.toml` serves it. To have a
named environment serve it instead, select it host-wide:

```toml
# /etc/ferrogate/environments.toml   (macOS: /Library/Application Support/FerroGate/,
#                                     Windows: %ProgramData%\FerroGate\)
default_environment = "prod"
```

or set `FERROGATE_DEFAULT_ENVIRONMENT=prod` (e.g. in `mia.env`). The variable
wins over the file; a **blank** variable clears the selection (`mia.toml` keeps
the address) whatever the file says. Unset everywhere ⇒ the behaviour above,
unchanged. The template is `crates/mia/dist/environments.toml`.

- **Only the system directory is read** — never the per-user one, which an
  unprivileged user could write — and the file is separate from `mia.toml`, so
  it works whether or not `mia.toml` exists and in every mode (serve-all,
  `--environment`, `--config`). Keep it root-owned and world-readable (`0644`):
  it holds no secret, and `mia test` run by an ordinary user must read it.
  Unknown keys are rejected; the file is capped at 16 KiB.
- With `prod` selected and `helper.socket` unset in `mia-prod.toml`, `prod`
  binds the well-known address **instead of** `mia-prod.sock` (one listener).
  Callers that dialled `mia-prod.sock` must move to the well-known address (or
  give `prod` an explicit `helper.socket`).
- `mia.toml` **yields**: with `helper.socket` unset it listens on
  `mia.default.sock` beside the well-known socket
  (`\\.\pipe\ferrogate-mia.default` on Windows). Environment-scoped addresses
  always start with `mia-`, so no environment name — not even one called
  `default` — can produce that address.
- An explicit `helper.socket` (or `FERROGATE_HELPER_SOCKET`) that names the
  well-known address in any environment other than the selected one is refused
  at load (two identities never share an address). With no selection this rule
  does not apply, so existing configurations keep working.
- **Fails closed.** An invalid name, the reserved name `default` (the label of
  `mia.toml`), an unreadable or malformed file, or — when the daemon serves
  every environment — a selection with no matching `mia-<env>.toml` stops the
  daemon (and `mia test` / `mia setup`) with an error. It never falls back to
  `mia.toml`. If the selected environment's file exists but fails to load, it
  is skipped like any broken environment and the well-known address stays
  unserved (logged as an error).
- The selection is a startup setting, like the socket itself: restart the
  daemon after changing it (`mia --reload` does not move a bound listener).

The daemon logs the selection and its source at startup, then which
environment serves the well-known address (a warning if the selected
environment does not, e.g. because its helper API is off). `mia test` prints a
`default environment` line, `mia setup` explains it at the helper-listener
prompt and leaves `helper.socket` unset when the suggested default is accepted,
and `mia status` marks the environment that serves the address (`helper:`
line; `default_address` in `--json`).

##### `mia default-environment` — show, set or clear the selection

```sh
mia default-environment [show] [--json]     # effective selection and its source
sudo mia default-environment set prod [--json]
sudo mia default-environment clear [--json] # mia.toml is the default again
sudo systemctl restart mia                  # apply (launchctl kickstart -k / Restart-Service)
```

`show` is read-only and needs no privileges; it fails closed exactly as the
daemon would (an invalid file is an error, not "nothing selected"). Its
`--json` form is `{"default_environment": "prod" | null, "label",
"source": "built-in" | "file" | "env", "file", "well_known_address"}`.

`set` and `clear` write `environments.toml` in the system config directory and
nothing else — they take no path — so they need root / Administrator. This is
the command [`mia-tray`](mia-tray.md) runs, through the OS consent prompt, for
**Set as default environment** and **Use mia.toml as default**. They:

- validate `<env>` with the same rule the loader applies (environment-name
  characters, bounded length, `default` reserved) and require
  `mia-<env>.toml` in the **system** config directory, beside
  `environments.toml` (a per-user copy is not enough: an elevated process may
  not see the same home directory as the daemon, and a selection the daemon
  cannot find stops it at startup);
- refuse a selection under which another environment that loads today would
  stop loading (an explicit `helper.socket` on the well-known address outside
  the selected environment), before anything is written;
- render the file from the shipped template plus one
  `default_environment = "<env>"` line (`clear` writes the template alone;
  an absent file stays absent) and write it atomically — temp file, `fsync`,
  rename, directory `fsync` — with mode `0644`, owned by the writer (root),
  refusing a symlink or non-regular file at the target;
- append `ConfigChanged { path, by_uid, keys: ["default_environment"] }` to the
  local audit journal beside the file **before** the rename (no audit record ⇒
  no change), the same journal `mia setup --apply` writes;
- write and audit nothing when the selection is already the requested one,
  and do not need the existing file to parse, so they also repair a broken one.

`--json` prints `{"ok", "path", "previous", "default_environment", "changed",
"restart_required", "env_override"}`. Exit status is `0` on success (also when
nothing changed) and `1` on any error. A `FERROGATE_DEFAULT_ENVIRONMENT` in the
service's own environment (e.g. `mia.env`) still overrides the file for the
daemon. The change applies when the agent restarts; until then `mia status`
keeps marking the environment that serves the address now.

#### Attestation backend

`attestation.backend` selects how the host obtains its SVID:

- **`host-key`** (default) — the TPM-less profile (feature F15): a hardware
  fingerprint plus a machine signing key. Works on every supported platform and
  is the correct choice for hosts without a usable TPM.
- **`virtual-tpm`** — runs the full four-phase TPM attestation handshake against
  an **in-process software virtual TPM**. This is **insecure** — there is no
  hardware root of trust — and exists only to exercise the TPM path on dev/test
  hosts (macOS, Windows, CI) that have neither a real TPM nor `swtpm`. It is
  available only when `mia` is built with the off-by-default `virtual-tpm` cargo
  feature (`cargo build -p mia --features virtual-tpm`); a normal release build
  refuses this backend and declines to attest (fail closed). It also only
  succeeds against a CMIS configured to trust the synthetic EK root and PCR
  digest that `mia` logs at startup. **Never enable it in production.**

### High availability via DNS SRV discovery

Instead of a single static `cmis.endpoint`, point the agent at a DNS **SRV
record** that advertises the CMIS nodes:

```toml
[cmis]
srv      = "_cmis._tcp.example.com"   # mutually exclusive with `endpoint`
spki_pin = "<hex-sha384>"             # authenticates every node (shared identity)
```

`cmis.srv` and `cmis.endpoint` are mutually exclusive — set exactly one. When
`srv` is set the agent:

1. **resolves** the SRV record (via the platform's DNS resolver) to its
   `(priority, weight, port, target)` entries;
2. **orders** them by RFC 2782 — ascending priority, then descending weight — so
   the most-preferred node is tried first;
3. **selects the best live node**: it dials candidates best-first and uses the
   first that completes the pinned hybrid-PQC TLS handshake. That handshake *is*
   the health check — an unreachable, non-hybrid, or wrong-identity node is
   skipped (a per-node 10 s timeout keeps a black-holed node from stalling the
   sweep); and
4. **fails over** automatically: every CMIS interaction (startup attestation,
   the allowlist fetch, the background CRL puller, and the allowlist-propose
   loop) re-resolves and re-selects on each (re)connect, so a node that goes down
   — or a cluster that is rescaled in DNS — is followed without a restart.

Because CMIS authenticates by **SPKI pin** rather than a CA chain, the cluster
shares one pinned identity, so a single `cmis.spki_pin` covers every node. All
SRV targets are dialed over `https` hybrid-PQC TLS regardless of the record's
port. Run `mia test` to see the discovered candidates and which node was
selected (it probes each and prints per-node reachability).

To publish such a record, add SRV entries pointing at your CMIS nodes, e.g.:

```dns
_cmis._tcp.example.com. 300 IN SRV 10 50 8443 cmis-a.example.com.
_cmis._tcp.example.com. 300 IN SRV 10 50 8443 cmis-b.example.com.
_cmis._tcp.example.com. 300 IN SRV 20 0  8443 cmis-dr.example.com.
```

Here `cmis-a`/`cmis-b` (priority 10) are preferred and load-shared, and
`cmis-dr` (priority 20) is a fallback used only when both primaries are down.

### `mia setup` — interactive wizard

Rather than hand-editing the env file, run the bundled wizard:

```console
$ sudo mia setup
```

`mia setup` is a rich-terminal, guided wizard (arrow keys / typed answers, with
validation and per-field help) that walks through the agent's configuration —
how to reach CMIS (a single endpoint, or an **SRV record for HA**), the local
helper API, the caller allowlist, attestation, and log verbosity — and writes
the **TOML configuration file** in
the documented, self-commenting form. It writes the OS **system path** by
default (see the per-OS table above) and prompts platform-appropriately (socket
mode on Unix, the pipe group on Windows). Run against an existing file it
pre-fills every prompt with the current value, so it doubles as an editor.
Options:

- `-u, --user` — target the per-user config path instead of the system path
  (no elevation needed).
- `-e, --environment <env>` — write `mia-<env>.toml` instead of `mia.toml` (for
  side-by-side deployments); composes with `--user`, excludes `--output`.
- `-o, --output <path>` — target a specific path.
- `-c, --clean` — delete the stored configuration instead of writing one
  (honours `--user`/`--output` to choose which file; prompts unless `--force`).
- `-f, --force` — skip the confirmation prompt (write or clean).

When you configure an allowlist *and* have supplied a CMIS endpoint + SPKI pin,
the wizard offers to **fetch the enrollment public key from CMIS** (the
`GetEnrollmentKey` RPC, over the pinned hybrid-PQC TLS channel) and install it at
your `allowlist.key`. It uses the same validated, atomic and audited writer as
[`mia allowlist-key fetch`](#installing-allowlistkey-mia-allowlist-key) and
prints the fingerprint. If a *different* key is already installed, it shows both
fingerprints and asks before replacing it (default: no). This is the key that
signs the allowlist, so the agent can verify it. The signed allowlist *body* itself (the CBOR at `allowlist.path`) is
also issued and served by CMIS per host: an operator stores it with
`ferrogate allowlist set` and the body is fetched with the `GetAllowlist` RPC,
keyed by the host's EK-derived UUID. The wizard additionally offers to enable
**`allowlist.fetch`** — when set, the daemon pulls this host's allowlist from
CMIS at every start (after attestation supplies its identity) and writes
`allowlist.path` before loading, so it stays in sync without out-of-band
delivery. The wizard suggests the per-environment default body path (see
[Allowlist: default location](#allowlist-default-location)) and leaves
`allowlist.path` unset in the file when you accept it, as it does for the
helper socket; the key is always written. See
[allowlist-provisioning.md](allowlist-provisioning.md) for the full workflow.

**`allowlist.propose`** closes the bootstrap gap from the other direction. With
it enabled the daemon sends CMIS the local callers it has actually observed —
every `(uid, binary SHA-384)` it authenticates, *granted or denied* — via the
`ProposeAllowlist` RPC. The first proposal goes out immediately at startup and
always includes a **self-registration entry**: a uid-wildcard entry for `mia`'s
own binary, mirroring the helper API's self-trust (which already permits `mia`
under any uid). A freshly installed host therefore shows up in CMIS — as a
bootstrap-adopted allowlist or a queued proposal, per policy below — as soon as
its daemon starts, before any real caller has connected. Observed entries carry
the concrete uid; an operator may relax an approved entry to a wildcard (any
user) where the uid is ephemeral — see
[ADR-0002](adr/0002-allowlist-optional-uid.md). The proposal is signed by the host machine key
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

The interactive wizard requires a TTY; for unattended provisioning
(configuration management), write the TOML file directly from the template in
`crates/mia/dist/mia.toml`, or use the non-interactive modes below.

The wizard also asks for the **attestation backend** (`auto`, `tpm`, `host-key`,
`virtual-tpm`). Keys it does not ask about — `helper.socket_gid`,
`helper.require_authenticode`, `allowlist.propose_interval_secs`,
`[attestation.tpm]` and `[status]` — are carried over unchanged from the file
being edited. Values containing a single quote or control characters are
rejected (every answer is written as a TOML literal string). The file is
written atomically (temp file, `fsync`, rename) with mode `0640` and the
previous file's owner and group; a symbolic link at the target is refused.
Every write appends a `ConfigChanged { path, by_uid, keys }` event — key
*names* only — to the local audit journal `config-audit.jsonl` beside the file
([audit.md](audit.md)); if that record cannot be written the configuration is
not changed.

#### Non-interactive modes (`--check`, `--apply`, `--dump`)

These back the `mia-tray` graphical wizard (feature F18) and need no TTY:

- `mia setup --check <draft> [--json]` — validate a *draft* and exit (non-zero
  on any problem). Error text is the wizard's own; `--json` prints
  `{"ok": …, "errors": [{"key": …, "message": …}]}`.
- `mia setup --apply <draft> [--user | --output <path> | -e <env>] [--reload]
  [--fetch-enrollment-key [--expect-fingerprint <hex>]] [--json]` — validate
  the draft, then write the same
  file the interactive wizard would write for the same answers (byte for
  byte), audit `ConfigChanged`, and delete the draft (unprivileged runs only —
  an elevated run leaves it for its owner to remove, since deleting by path as
  root could be redirected). `--reload` then signals the running agent
  (SIGHUP; restart hint on Windows); `--fetch-enrollment-key` then fetches the
  CMIS enrollment key into `allowlist.key` over the pinned channel the new
  configuration describes, inside this (possibly elevated) process — only over
  pinned TLS (never `http://`), only into an absolute path without `..` (when
  elevated: beside the configuration file), only if the reply parses as a
  composite public key, written atomically and audited. The optional
  `--expect-fingerprint <hex>` accepts the 96-character text printed by
  `ferrogate enrollment-key` and writes nothing when the fetched key differs.
  `--json` prints one
  object: `ok`, `path`, `changed_keys`, `draft_deleted`, `enrollment_key`,
  `reloaded`, `error`.
- `mia setup --dump [--json] [--user | --output <path> | -e <env>]` — the
  effective values (file + environment overlay), the file path and whether it
  exists, and which keys come from environment variables (`env_overridden`,
  e.g. `{"key": "cmis.endpoint", "var": "FERROGATE_CMIS_ENDPOINT"}`) — a wizard
  shows those read-only, since writing the file would not change them.

A **draft** is laid out like `mia.toml` but holds only the wizard's keys:

```toml
log = "info"
[cmis]
endpoint = "https://cmis.example.com:8443"   # or: srv = "_cmis._tcp.example.com"
spki_pin = "<hex-sha384>"
[helper]
enable = true                                # false ⇒ `enable = false` (helper API off);
                                             # omitted ⇒ the file's current value is kept
socket = "/run/ferrogate/mia.sock"           # optional; blank ⇒ the platform default
socket_mode = "660"                          # windows_group = "FerroGateClients"
[allowlist]
path = "/etc/ferrogate/allowlist.cbor"       # optional; omitted or blank ⇒ the default
key = "/etc/ferrogate/allowlist.pub"         # no default
max_age_secs = 259200
fetch = true
propose = false
[attestation]
backend = "auto"                             # ima_log = "…" (Linux)
```

`--apply` treats the draft as untrusted input (it may be written by an
unprivileged process and applied by an elevated one): at most 64 KiB, a
regular file opened without following symlinks, not hard-linked, on Unix not
writable by group/others and owned by the caller — or, when elevated (root,
behind the OS consent prompt), by the `PKEXEC_UID` / `SUDO_UID` user, else by
any user but root (macOS `osascript` sets neither variable); that user is
recorded as `ConfigChanged.by_uid`. An elevated run (and every run on Windows,
where elevation cannot be ruled out) refuses `--output` and reports parser
errors by line number only, so it cannot be aimed at, or made to echo, an
arbitrary file. Unknown keys are rejected; every value goes through the wizard's
validators plus the cross-field rules the daemon enforces at startup
(`endpoint` xor `srv`; `spki_pin` required with `https://` or SRV;
`allowlist.key` required with `allowlist.path`; a valid `log` directive). A
rejected draft is left in place and nothing is written.

### `mia test` — connectivity and token-issuance self-test

```console
$ mia test
```

A non-interactive diagnostic that exercises the full path a local application
depends on and exits non-zero if any step fails, so it can gate provisioning
scripts. `sudo mia test --fix` first repairs a missing `allowlist.key`: when it
is unset or names a file that does not exist, it runs `mia allowlist-key fetch
--reload` (root only; asks for the enrollment-key fingerprint on the terminal;
names the key file in the configuration when unset — see "Installing
`allowlist.key`"), then runs the checks. An installed key is never replaced
(that is `fetch --rotate`), and `--fix` cannot be combined with `--json`. It
runs four checks in order:

1. **configuration** — a CMIS source (a static `endpoint`, or an `srv` record)
   and a valid SPKI pin resolve from the usual config-file/environment
   precedence;
2. **CMIS connection** — an eager dial over pinned hybrid-PQC TLS, validating
   DNS, TCP, the X25519MLKEM768 handshake, and the SPKI pin. For an SRV source it
   resolves the record, probes each node best-first (printing per-node
   reachability), and selects the first live one — so the check doubles as an HA
   readout;
3. **CMIS CRL publishing** — the `JWKS` RPC returns a signature-valid, fresh
   CRL (the freshness the helper API fail-closed gates minting on, F11);
4. **helper token mint** — a real `HelperReq` over the local helper socket
   (`helper.socket`, else the platform default above), reporting the minted
   token or interpreting the refusal. It fails only if the helper API is
   switched off (`helper.enable = false`) or the daemon cannot be reached.
   When the daemon refuses with `NoHostSvid` (it holds no host SVID), the
   test asks the running daemon for its status (the same endpoint as
   `mia status`, 5 s bound) and turns the reported problem into a specific
   hint, also recording the daemon's `state` / `problem` as the step's notes:
   `cmis_not_configured` while the test's own config names a CMIS source means
   the daemon was started before the config was written (CMIS/attestation
   settings need a restart, not a reload); `host_rejected` / `not_enrolled`
   means the host is not enrolled (send the fingerprint from
   `mia machine-id --verbose` to the CMIS operator); `cmis_unreachable`,
   `pin_mismatch`, `tpm_unavailable` and others get their own hint, and an
   unknown code is shown verbatim. If the status endpoint cannot be read
   (absent, permission denied, timeout) the generic hint is printed instead.

Informational lines, never failures, also report the attestation backend, the
default environment and the **allowlist**: the body the daemon loads
(`allowlist.path`, else the default, marked `(default)`) and whether it
verifies against `allowlist.key` (`warn` when every caller would be denied).

Each failing step prints targeted remediation hints (mirroring the
[operations runbooks](operations/runbooks/README.md)); a `crl_stale` refusal in
step 4 is cross-referenced with step 3's result to say whether the server or
the agent is at fault. Note that step 4 authenticates *this command's binary
and uid* like any other caller, so on a host with a restrictive allowlist a
`PermissionDenied` ("not-allowlisted") refusal still proves everything up to
the allowlist check works. Options:

- `-c, --config <path>` — TOML config file (same resolution as the daemon).
- `-e, --environment <env>` — select `mia-<env>.toml` from the standard config
  locations instead of `mia.toml`; mutually exclusive with `--config`.
- `-a, --audience <aud>` — audience for the test token (default
  `https://selftest.ferrogate.invalid`).
- `--json` — print the results as one JSON document instead (same exit status):
  `{"version", "config", "environment", "passed", "failures": [...],
  "checks": [{"id", "step", "status", "detail", "hints": [...], "notes": [...]}]}`,
  where `id` is a stable slug (`configuration`, `cmis_connection`,
  `cluster_identity`, `cmis_crl_publishing`, `helper_token_mint`,
  `attestation`, `default_environment`, `allowlist`) and `status` is `ok` /
  `FAIL` / `skip` / `info` / `warn`.

### Status endpoint and `mia status`

Besides the helper socket, the daemon serves a **read-only status endpoint**
(feature F18) that the `mia-tray` companion and `mia status` read. It is a
separate listener, so status reads never touch the token-minting path:

| OS | default endpoint | access |
|----|------------------|--------|
| Linux | `/run/ferrogate/mia-status.sock` | `0660`, group `status.socket_gid` (or `status.group`, default `ferrogate-status`, from `/etc/group`) |
| macOS | `/var/run/ferrogate/mia-status.sock` | `0660`, group `status.socket_gid` (dscl groups are not in `/etc/group`) |
| Windows | `\\.\pipe\ferrogate-mia-status` | DACL: SYSTEM, Administrators, `status.group` (default `FerroGateStatus`; read + write-data only, no pipe-instance creation — see [helper-api.md](helper-api.md#windows-pipe-clients)) |

Framing is the helper protocol's (4-byte big-endian length + one CBOR value,
≤ 64 KiB, one exchange per connection, 5 s read deadline). Two requests are
accepted — `StatusReq { environment }` → one `StatusSnapshot` per environment,
and `LogTailReq { since_seq, min_level, max }` → redacted log records — and
everything else, including a helper `HelperReq`, is answered with
`unsupported_request`. Each peer uid gets `status.rate_limit_per_sec` requests
per second (default 10); at most 16 connections are served at once. The wire
types live in the small `mia-status-proto` crate so clients need not depend on
the daemon.

A snapshot carries the environment, its **state** (`healthy`, `attesting`,
`cmis_unreachable`, `not_enrolled`, `pin_mismatch`, `tpm_unavailable`,
`crl_stale`, `allowlist_missing`, `allowlist_invalid`, `svid_expiring`,
`not_configured`; `not_running` / `ima_disabled` are reported client-side when
there is no endpoint), when it entered it, the SVID's SPIFFE ID / expiry /
renewal point, the attestation backend, the CMIS node in use, the CRL age, the
allowlist state (entry *count* and expiry only), the X.509-SVID store backend,
a stable error code with a fixed message, and the agent version. It never
carries SVID or token bytes, signatures, key material, SPKI pins, `jti`s,
helper-audit caller identities or allowlist contents.

The log tail comes from an in-memory ring buffer (`status.log_buffer_records`,
default 2000, and `status.log_buffer_bytes`, default 1 MiB; `0` disables it).
Records are **redacted before they are buffered**: fields named like
`token`/`svid`/`key`/`secret`/`pin`/`jwk`/`dpop`/`authorization` (and `jti`,
`sig`, `seed`, `bin_sha`, `pid`, `uid`, …) and byte blobs are masked, JWS /
long-hex / long-base64 runs in free text are replaced with `[redacted]`,
control characters are escaped and values are cut at 512 bytes. Helper-API
audit events (target `mia::audit`) are never buffered, and only levels the
`log` directive already enables are kept — a client cannot raise verbosity.

On Linux the status socket is bound, `chmod`ed and `chown`ed as root *before*
the runtime directories are handed to the service user and before the
hardening profile is applied, so the seccomp filter (which forbids `chown`) is
unaffected and no other user can interfere with those path operations; a
socket directory writable by anyone but root at that point (e.g. one left by a
run outside systemd) is refused. When the directory is then not searchable by
the status group (`/run/ferrogate` is `0750` for the service user), the daemon
adds search-only `o+x` to it and logs that — each socket inside keeps its own
`0660` mode. `[status]` is read from
the primary configuration only and is not re-applied on SIGHUP.

```console
$ mia status
[default] healthy (for 3h12m)
  svid:         spiffe://ferrogate.prod/host/0192b0d0-… (expires in 47m, renews in 11m)
  attestation:  host-key
  cmis node:    cmis-a.example.com:8443
  crl age:      42s
  allowlist:    loaded (12 entries, expires in 2d4h)
  x509 store:   machine-key
  agent:        mia 0.21.6
```

`mia status [--json] [-e <env>] [-c <config>]` takes `status.socket` from
`--config` (or the default configuration); `-e` filters the reply (`default`
names `mia.toml`). `--json` prints the snapshot array. Exit status: `0` every
reported environment is healthy, `1` not all healthy (or the environment is not
served), `2` usage/config/protocol error, `3` the endpoint is absent (agent not
running — the JSON still lists `not_running` snapshots, or `ima_disabled` on a
Linux host whose kernel does not enforce IMA appraisal), `4` permission denied
(not a member of the status group).

### `mia-tray` — desktop companion

On workstations, the unprivileged [`mia-tray`](mia-tray.md) companion (feature
F18) shows the state above as a tray icon (worst state across environments),
notifies on transitions that need a human, and offers a graphical setup wizard
(`mia setup --dump` / `--check` / `--apply`, the system file through the OS
consent prompt), guided recovery from a closed set of fixed `mia` commands, and
a viewer for the redacted log tail. It reads only the status endpoint and the
output of `mia` commands; it holds no key material and never talks to the
helper socket. It ships inside `make pkg-deb`, `make pkg-macos` and
`make pkg-win`; RPM keeps the separate, opt-in `ferrogate-mia-tray` package. See
[mia-tray](mia-tray.md).

### `mia x509-svid` — inspect the machine-bound certificate store

```console
$ mia x509-svid
spiffe-id:   spiffe://ferrogate.prod/host/0192b0d0-…
sealed-with: tpm (opens only on this machine)
store:       /var/lib/ferrogate/x509-svid.sealed
not-after:   1774000000 (expires in 0h 47m)
leaf:        5461 bytes DER
bundle:      5502 bytes DER
private-key: held, not printed
```

On a Mac the same command reports the Enclave tier and the macOS state
directory:

```console
$ mia x509-svid
spiffe-id:   spiffe://ferrogate.prod/host/0192b0d0-…
sealed-with: secure-enclave (opens only on this machine)
store:       /Library/Application Support/FerroGate/x509-svid.sealed
not-after:   1774000000 (expires in 0h 47m)
leaf:        5461 bytes DER
bundle:      5502 bytes DER
private-key: held, not printed
```

Read-only and offline: it opens the sealed store exactly as the daemon does and
reports what is inside. Running it on another host — or on a TPM host after a
boot-state change — fails, which is the practical demonstration that the file is
machine-bound.

- `--pem` — print the leaf certificate as PEM.
- `--bundle-pem` — print the trust bundle as PEM.

The private key is never printed. It is sealed so that this host can terminate
mTLS with the credential; a copy on a terminal or in shell history would undo
that. Serving the key to a local workload belongs to the helper API, not to this
command.

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
