---
ptf: 1
project: ferrogate
---

# Changelog

All notable changes to FerroGate are documented here. The format is based on
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) with the Project
Tracking Format (PTF) v1 extensions — the `Postponed` and `Abandoned` categories
and a trailing reference group on every entry whose `M<n>` / `T<n>` / `S<n>` IDs
are defined in [ROADMAP.md](ROADMAP.md) — and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was migrated to PTF on 2026-10-05. Each entry opens with a one-sentence
imperative summary and its reference group; the indented text under it is the
pre-migration entry, kept verbatim. Sections that were headed by a legacy roadmap
milestone (`[M0]` … `[M6.0]`) are now headed by the version they shipped as, with
the old heading quoted below; `0.1.0-m0` and `0.1.0-m1` are migration labels for
the untagged legacy M0 and M1 sections. Legacy labels such as "M4" inside entry
text refer to the old roadmap milestones, which are phases P1–P7 in ROADMAP.md,
not to PTF milestone IDs. Sections and entries marked as reconstructed were
rebuilt from git tags and commits because the pre-migration changelog did not
record them.

## [Unreleased]

## [0.27.0] - 2026-10-06

### Added

- Add `mia allowlist-diagnose` to explain why a local caller is or is not permitted by the host's signed allowlist (S32)
  A caller the allowlist refuses only saw an opaque `permission_denied`.
  `mia allowlist-diagnose (--exe <path> | --sha384 <hex>) [--uid <n>]
  [-c <config> | -e <env>] [--json]` replays the allowlist decision offline.
  It checks the allowlist file, `allowlist.key`, the signature, validity and
  trust domain, an entry for the uid (ADR-0002), an entry for the binary hash,
  and the verdict of the helper's own `permits()` check. It stops at the first
  blocking cause with a remediation hint. When the hash is not listed, it shows
  the listed binaries by their first 12 hex characters, so a hash left stale by
  an upgrade stands out. `--exe` hashes through the same `bin_sha384` the
  helper's authenticators now share, and `mia`'s own binary is reported as
  self-trusted. The command is read-only and contacts neither CMIS nor the
  daemon. It never prints key material. It exits `0` permitted, `1` denied or
  `2` on a usage or I/O error.

## [0.26.0] - 2026-10-06

### Added

- Add `mia allowlist-key fetch | show` to install and inspect `allowlist.key` on demand, root-only and over the pinned channel (S32)
  `allowlist.key`, the CMIS enrollment key that verifies the signed caller
  allowlist, has no default, and nothing installed it on a fresh machine
  except the interactive `mia setup`. `sudo mia allowlist-key fetch` now does
  it non-interactively. It runs as root only (Windows: an elevated prompt, with
  the key inside `%ProgramData%\FerroGate`), and on Unix only into a root-owned
  directory that is not group/other-writable. The check runs before any
  network traffic. The key is fetched only over the SPKI-pinned hybrid-PQC
  channel (no unpinned fallback) and must parse as a composite public key.
  `--expect-fingerprint <hex>` verifies it and writes nothing on a mismatch;
  without that flag, `--yes` or a terminal confirmation is required. An
  identical installed key is a no-op. A different one is refused unless you
  pass `--rotate`. The key is written atomically (`0644` public material,
  root-owned, symlinks refused) with a `ConfigChanged` record
  (`allowlist.key:enrollment-key[:rotated]`, names only) in the local audit
  journal before the rename. Only fingerprints are printed, and `--reload`
  applies the key live. `mia allowlist-key show` prints the installed key's
  path and fingerprint. The daemon still never fetches or trusts a key by
  itself, and no socket can trigger a fetch.
- Add `ferrogate enrollment-key [--format hex|flag]` to print the CMIS enrollment key's SHA-384 fingerprint (S32)
  This is the CMIS-side value an operator compares with the fingerprint
  `mia allowlist-key fetch` prints, or passes to it as `--expect-fingerprint`.
  Both sides use the new `CompositePublicKey::fingerprint_hex` in
  `ferro-crypto`.

### Changed

- Route every `allowlist.key` write in the interactive wizard through the validated, atomic, audited installer (S32)
  The `mia setup` key fetch and `mia refresh-key` used a plain truncating
  write. That write followed a symlink at the target, did not check that the
  reply was a key, recorded no audit event, and silently replaced a different
  key. The wizard now uses the `allowlist-key` installer and prints the
  fingerprint. It asks before replacing a different installed key (default:
  no). `mia test`, `mia status` and the `resync-allowlist` messages now point
  to `mia allowlist-key fetch`. The macOS installer prints the next steps (it
  never fetches the key itself).

### Deprecated

- Deprecate `mia refresh-key` in favour of `mia allowlist-key fetch` (S32)
  `mia refresh-key` is now an alias for `mia allowlist-key fetch --rotate --yes`.
  It keeps its meaning (replace the key, without a prompt, as the `mia-tray`
  action runs it), but it gains the checks above. Behaviour change: it now
  needs root, and on Windows a key path inside `%ProgramData%\FerroGate`. The
  library function `mia::resync::run_refresh_key` is deprecated and forwards
  to `mia::allowlist_key::run_refresh_key`.

### Fixed

- Never regenerate, overwrite or delete an existing MIA machine key or SVID seed; fail closed with an operator-facing fix instead (S15, S16, S29)
  CMIS pins the machine key's public half to the hardware fingerprint on first
  contact and refuses any other key for it (`key-rebind`), so a host that mints
  a new `host-key.bin` while the pinned one exists is stranded without an SVID.
  The new `mia::machine_key` module decides every use of `host-key.bin` and
  `svid-seed.bin`: a usable file is opened and never rewritten; a file that
  exists but cannot be used (symlink or not a regular file, group/other
  access, foreign owner, unreadable, refused by the Windows trust check, wrong
  length, sealed to another fingerprint) is refused and left untouched, with
  the new status code `machine_key_refused` and an error log naming the file
  and the fix; a file stranded at a former location (Linux `/etc/ferrogate`,
  before 0.20.19 — that move used to mint a fresh key) is migrated by the
  privileged startup; a key is created only when none exists anywhere — not
  even an SVID seed, which is only ever created after the key and so proves a
  lost one — and that is logged as a new host identity. A wrong-length SVID seed is no longer
  silently regenerated. The allowlist-propose task follows the same rules
  instead of creating a key of its own. `ferro-sep` gains the open-only
  `SoftwareMachineKey::open_sealed` / `open_existing` (which never rewrite the
  file) and the create-only `create_sealed` / `create_plain`; a partly written
  new key file is removed instead of left torn, and a pre-F16 plaintext key is
  re-sealed at privileged start by atomic replace instead of the truncating
  in-place rewrite. Behaviour change: a
  symlinked `host-key.bin`/`svid-seed.bin` is now refused.
- Stop the macOS package from overwriting `mia.env` / `mia.toml` on upgrade and from owning the directory that holds the machine key (S29)
  The `.pkg` payload installed `/etc/ferrogate/mia.env` and
  `/Library/Application Support/FerroGate/mia.toml`, so every upgrade reset the
  operator's configuration, and the receipt listed the state directory, so
  receipt-driven removal deleted `host-key.bin`. The defaults now ship as
  templates in `/usr/local/share/ferrogate`, which postinstall copies only
  where no file exists. The package now installs `mia-uninstall`, which
  removes the programs and keeps the configuration and machine identity unless
  given `--purge`.

## [0.25.0] - 2026-10-06

### Security

- Make the Windows MIA configuration directory administrator-only and refuse files a non-administrator could have written (S12, S29)
  `%ProgramData%\FerroGate` was created with a plain `create_dir_all`, so it
  inherited `%ProgramData%`'s DACL: `BUILTIN\Users` could create files and
  folders in it, owned what they created, and could read everything in it.
  The `LocalSystem` service trusts that directory without being told where to
  look, so any local user could plant `mia-<env>.toml`, `environments.toml`,
  an allowlist body (verified, but able to deny every caller or replay an
  older signed body) or a machine key or SVID seed for it to load, and could
  read the machine key, which on Windows has no file mode to protect it. The
  directory is now owner `BUILTIN\Administrators` with a protected DACL that
  grants only SYSTEM and Administrators full control
  (`O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`). Before it reads anything or
  opens its log, the service creates the directory with that descriptor in
  one step, or locks an existing one. It then walks everything below it,
  refusing any reparse point and locking every subdirectory that is not
  administrator-only (a user could otherwise pre-create `logs` as a junction
  and have SYSTEM write its log elsewhere). Only after that does it re-derive
  inherited ACEs. Every object is opened without following reparse points and
  judged and changed through that same handle. The Chocolatey package and the
  NSIS installer run the same code (`mia service secure-config`, new) on every
  install and upgrade and abort on failure. Before loading a configuration
  file, `environments.toml`, the allowlist body or key, the machine key, the
  SVID seed or the sealed X.509-SVID store from inside the directory, `mia`
  refuses the file when it or a directory above it is owned by anyone but
  SYSTEM or Administrators, has a NULL DACL, is a reparse point or a
  hard-linked file, or grants anyone else a write right. The bytes are read
  from the handle that was judged. The log file is opened and judged the same
  way. The ACL parsing and decision are pure and unit-tested in
  `ferro-winauth::file_acl`; the FFI lives in `ferro-winauth`, so `mia` stays
  `forbid(unsafe_code)`. Linux and macOS are unchanged.
  - **Behaviour:** a file in the directory that SYSTEM or Administrators do not
    own is refused, even after the service repairs the directory, because a
    planted file cannot be told from an intended one. A refused configuration
    or `environments.toml` stops the service; a refused default allowlist body
    or key denies every caller. A reparse point anywhere below the directory,
    or a junction, link or foreign-owned file at `logs\mia.log`, stops the
    service. `mia setup`, `mia default-environment`,
    `mia resync-allowlist`, `mia refresh-key` and `allowlist.fetch` now write
    Administrators-owned files and need an elevated prompt. Unprivileged users
    can no longer read the directory, so the tray's **Open full log**,
    `mia test` and `mia setup --dump` of the system configuration need
    elevation on Windows; `mia status` falls back to the default endpoint.
  - **Action:** on upgrade, files written by an elevated administrator with an
    older `mia` are owned by that administrator's account. The Chocolatey
    package hands those whose owner is a direct member of the local
    Administrators group to the group and lists the rest. Elsewhere, review
    each refused file and either delete it or run
    `icacls "<file>" /setowner *S-1-5-32-544` and `icacls "<file>" /reset`.
    Under the default `%ProgramData%` DACL the machine key was readable by
    every local user until now: treat it as exposed and rotate it with its
    CMIS binding.

## [0.24.0] - 2026-10-05

### Added

- Give the MIA tray companion its own application icon (S18)
  A steel shield carrying a machine chip with a green keyhole, mastered as
  `crates/mia-tray/dist/icons/ferrogate-mia.svg`. `make icons`
  (`scripts/gen-mia-icons.sh`) regenerates the committed 256 px PNG, macOS
  `.icns` and Windows `.ico` from it. `FerroGate MIA.app` now carries the
  `.icns` (`CFBundleIconFile`). The Debian and RPM packages install the SVG
  and PNG into the hicolor theme, and the XDG autostart entry uses
  `Icon=ferrogate-mia` instead of the generic `security-high`. The MSI sets
  it as the Add or Remove Programs icon. The tray's live state disc is
  unchanged.
- Report the resolved signed allowlist in `mia test` (S8, S29)
  A new informational `allowlist` line (`--json` id `allowlist`) names the body
  the daemon loads, marked `(default)` when it is the per-environment default,
  and verifies it against `allowlist.key` the way the daemon does. It is `warn`
  whenever every caller would be denied (no key, body missing or not
  verifying) and never counts as a failure.

### Changed

- Default the MIA allowlist body to a per-platform, per-environment path (S8, S29, S32)
  When neither `allowlist.path` nor `FERROGATE_ALLOWLIST` is set (blank counts
  as unset), the daemon, `mia test`, `mia setup`, `mia resync-allowlist` and
  `mia refresh-key` all resolve the same body through
  `mia::config::default_allowlist_path`: `allowlist.cbor`, or
  `allowlist-<env>.cbor` for a named environment, beside the system
  `mia.toml` (`/etc/ferrogate`, `/Library/Application Support/FerroGate`,
  `%ProgramData%\FerroGate`). Precedence: default < `allowlist.path` <
  `FERROGATE_ALLOWLIST`. `mia setup` suggests the default and, as for the
  helper socket, does not write it to the file when accepted; `mia setup
  --apply` (and the tray wizard) leave `path` out when the draft omits it or
  leaves it blank. The tray's help text says so.
  `allowlist.key` deliberately has **no default**: it is the trust anchor,
  so it is never inferred from a file at a well-known path. Everything stays
  fail closed. No key, or a body that is missing, stale or does not verify,
  denies every caller. `allowlist.fetch` writes nothing without a key. A
  default location that cannot be read is logged and denies every caller; it
  never stops the daemon. An explicit `allowlist.path` without a key, or one
  that cannot be read, still refuses to start, as before.
  - **Migration:** configurations that set `allowlist.key` but not
    `allowlist.path` used to deny every caller and ignore the key. They now
    load and verify the default body if it exists. To keep denying every
    caller, remove `allowlist.key`. `mia resync-allowlist` no longer fails with
    "allowlist.path is not configured"; it writes the default body. An
    explicit `allowlist.path` with `key = ''` now refuses to start, because a
    blank key counts as unset; before, it served deny-all.

## [0.23.1] - 2026-10-05

### Fixed

- Reload the macOS MIA daemon on package upgrade (T171)
  The pkg `postinstall` restarted the tray but left a loaded daemon running
  the replaced binary, so its self-trust digest no longer matched
  `/usr/local/bin/mia` and `mia test` was refused (`not-allowlisted`).
  `launchctl kickstart -k` was no cure: it keeps the job definition launchd
  parsed at first bootstrap, so a daemon kickstarted after 0.23.0 still saw
  the removed `FERROGATE_HELPER_SOCKET`, claimed the well-known helper
  address for `mia.toml` while another environment was the default, and
  crash-looped. The new `macos-scripts/restart-daemon` boots a loaded daemon
  out and bootstraps it from the new plist; an unloaded daemon (fresh
  install) is still left for the operator to configure and load.

## [0.23.0] - 2026-10-05

### Added

- Let the operator choose which environment serves the well-known MIA helper address (S8, S29, S31)
  A new host-wide file, `environments.toml` in the system config directory
  (`/etc/ferrogate`, `/Library/Application Support/FerroGate`,
  `%ProgramData%\FerroGate`; template `crates/mia/dist/environments.toml`),
  takes `default_environment = "<env>"`. `FERROGATE_DEFAULT_ENVIRONMENT`
  overrides it, and a blank value clears it. With nothing set, `mia.toml`
  keeps the well-known address (`mia.sock` / `\\.\pipe\ferrogate-mia`) exactly
  as before. When an environment is selected and its `helper.socket` is unset,
  it serves the well-known address instead of `mia-<env>.sock`, and `mia.toml`
  moves to `mia.default.sock` (`\\.\pipe\ferrogate-mia.default`), an address
  no environment name can produce. The per-user directory is never read.
  - **Fails closed:** an invalid or reserved (`default`) name, an unreadable,
    oversized or malformed file, or, in serve-all mode, a selection with no
    `mia-<env>.toml` stops the daemon instead of falling back to `mia.toml`.
    With a selection in force, an explicit `helper.socket` that names the
    well-known address in another environment is refused.
  - The daemon logs the selection and which environment serves the address.
    `mia test` prints a `default environment` line. `mia status` marks that
    environment, and the status snapshot gains `default_address`; older tray
    and daemon versions read it as `false`.
  - `mia setup` explains the selection at the helper-listener prompt and refuses
    the well-known address for an environment that does not own it. It now
    leaves `helper.socket` unset when the suggested default is accepted, so a
    file follows a later change of default environment instead of pinning the
    old path.
  - Takes effect at daemon start; `mia --reload` does not move a bound
    listener.
  - `mia default-environment [show | set <env> | clear] [--json]` manages the
    selection. `show` is read-only. `set` and `clear` write only the system
    `environments.toml`, so they need root or Administrator. `set` checks the
    name with the loader's own validator (`default` is reserved) and requires
    `mia-<env>.toml` in the system config directory. It refuses a selection that would stop
    another environment's configuration from loading. The file is written
    atomically with mode `0644`, owned by the writer, and a symlink target is
    refused. Each change appends `ConfigChanged` (key name
    `default_environment`) to the local audit journal before the rename. An
    unchanged selection writes nothing.
  - `mia-tray` marks the environment that serves the well-known address as
    `[default address]` in its menu and Status window. Other environments
    offer **Set as default environment**, and `mia.toml` offers **Use mia.toml
    as default**. Both run `mia default-environment` through the consent
    prompt and then ask for a service restart. English and Portuguese strings
    are included.

### Security

- Create the host-key machine signing key `0600` and repair a world-readable one (S15, S16, S29)
  `host-key.bin`, the TPM-less profile's software machine signing key, was
  written with the process umask and so was `0644`. On macOS it sits in the
  `0755` config directory, and the hardware fingerprint it is sealed to is
  readable by any user through `ioreg`. Any local user could therefore read the
  file, re-derive the seal key and recover the machine key. `ferro-sep` now
  creates the file exclusively (`O_EXCL`) with mode `0600` set by `open(2)`, so
  it is never wider at any point. It tightens an existing file that group or
  other can access before reading it (new `restrict_key_file`). The pre-F16
  re-seal rewrites only an owner-only file. The daemon makes `host-key.bin`,
  `svid-seed.bin` and `x509-svid.sealed` owner-only at start, before the Linux
  privilege drop, and logs each repair at `warn`. The macOS postinstall does
  the same at upgrade. Linux hosts were less exposed, because
  `/var/lib/ferrogate` is `0750`.
  - **Behaviour:** `ferro-sep` refuses to open a key file it cannot make
    owner-only, so a key file the daemon user neither owns nor can `chmod`
    now fails attestation instead of loading.
  - **Action:** a host that logs `restricted it to 0600` had an exposed key.
    Treat the key as compromised and rotate it together with its CMIS binding.

## [0.22.0] - 2026-10-05

### Added

- Add `helper.enable` / `FERROGATE_HELPER_ENABLE` as the explicit off switch for the MIA helper API (S8, S29, S31)
  `helper.enable = false` (or `FERROGATE_HELPER_ENABLE=0`) switches the helper
  API off and wins over any `helper.socket` value. The variable overrides the
  file and, being process-wide, reaches every environment the daemon serves.
  `mia setup` writes `enable = false` when the helper API is declined, and
  `mia setup --apply` accepts `helper.enable` in drafts; a draft that omits it
  keeps the file's current value, so an older front end cannot switch the
  helper API back on by leaving the key out.

### Changed

- Breaking: serve the MIA helper API by default on a per-platform, per-environment socket (S8, S29, S31)
  **An unset `helper.socket` no longer disables the helper API.** When neither
  `helper.socket` nor `FERROGATE_HELPER_SOCKET` is set (blank counts as unset),
  the daemon, `mia test` and `mia setup` all resolve the same default through
  `mia::config::default_helper_socket`: `/run/ferrogate/mia[-<env>].sock`
  (Linux), `/Library/Application Support/FerroGate/run/mia[-<env>].sock`
  (macOS), `\\.\pipe\ferrogate-mia[-<env>]` (Windows). The environment is the
  `--environment` selector or the `<env>` in a `mia-<env>.toml` file name.
  Precedence is unchanged: default < `helper.socket` < `FERROGATE_HELPER_SOCKET`.
  Callers still need a signed allowlist entry; with no allowlist every request is
  refused. `mia test` no longer fails with "helper.socket is not configured".
  - **Migration:** hosts that relied on an unset socket to keep the helper API
    off must add `helper.enable = false`. A Windows service now stays running
    after install instead of exiting idle.
  - **macOS:** the launchd plist no longer sets `FERROGATE_HELPER_SOCKET`. Its
    value was the new default. A `helper.socket` in `mia.toml` now takes effect
    for the default environment; before, the plist variable overrode it.

### Fixed

- Bind the Linux helper socket with `helper.socket_gid` without a `chown` that the seccomp profile forbids (S8, S12)
  On Linux the hardened daemon binds the helper socket after dropping to
  `_ferrogate`, and the seccomp allow-list has no `chown`. With
  `FERROGATE_HELPER_SOCKET_GID` set, as the Debian package and
  `make mia-install` do, the daemon was killed with `SIGSYS` at bind. Now, while
  still root, it hands each helper-socket directory to `_ferrogate` group-owned
  by `helper.socket_gid` with the setgid bit (`02750`). The socket inherits the
  group, and the bind calls `chown` only if the group is still wrong.

- Give the macOS helper socket directory and sockets the `ferrogate-status` group (S8, S29, S31)
  On macOS `/Library/Application Support/FerroGate` is `root:ferrogate-status`,
  but `run/` and the helper sockets in it (`mia.sock`, `mia-<env>.sock`) could
  stay `root:wheel`, so status-group members could not reach the helper API.
  macOS gives a new entry its parent directory's group, so a `run/` created
  before the postinstall handed the config directory to the group kept
  `wheel`. The daemon only set `run/` up when it created it and never
  re-applied the group. Now, when `helper.socket_gid` is unset, a socket in
  `run/` takes the config directory's group. That group is adopted only while
  the config directory is root-owned and not group- or world-writable. The
  daemon re-applies mode `0750` and the group to `run/` on every start and
  refuses a `run/` that is a symlink. An explicit `helper.socket_gid` /
  `FERROGATE_HELPER_SOCKET_GID` still wins. The postinstall regroups a `wheel`
  `run/` and its sockets, so an upgrade fixes access before the daemon
  restarts. Linux and custom socket paths are unchanged.
  - **Access:** members of `ferrogate-status` can now connect to the macOS
    helper socket. The signed allowlist still decides who may mint.

### Security

- Refuse to replace a non-socket file at the helper socket path (S8)
  The helper listener used to unlink whatever was at `helper.socket` before
  binding. It now removes only a stale socket and refuses any other file type,
  symlinks included, as the status endpoint already did. A mistyped path can no
  longer make the daemon delete data.

## [0.21.9] - 2026-10-05

### Fixed

- macOS package: the postinstall now gives `/Library/Application Support/FerroGate` and its `mia*.toml` files to the `ferrogate-status` group (mode 0640), so status-group members can read configs such as `mia-homolog.toml`

## [0.21.8] - 2026-10-05

### Added

#### Reconstructed from git history during the PTF migration

- Ship the macOS tray as the `FerroGate MIA.app` bundle installed by `make pkg-macos` (T212, #45)
  Commit 7dc0162, merged as 3f431b8 (#45). The bundle (`Info.plist` with `LSUIElement`, bundle id
  `com.ferrogate.mia-tray`) is installed to `/Applications/FerroGate MIA.app` instead of a bare
  `/usr/local/bin` binary, so it shows in Finder, Launchpad and Login Items and can be reopened after
  quitting. The whole bundle is signed (Developer ID when `CODESIGN_ID` is set, ad hoc otherwise) and
  verified with `codesign --strict`; `/usr/local/bin/mia-tray` stays as a symlink; the bundle is pinned to
  `/Applications` (`BundleIsRelocatable=false`) so the installer never strands the LaunchAgent; the
  LaunchAgent runs the bundle executable with `AssociatedBundleIdentifiers`; postinstall boots out a
  running tray before bootstrapping so upgrades run the new bundle. Closes the F18 "`.app` bundle for
  macOS" gap.

### Changed

- Breaking: require Windows pipe clients to open the pipe with `GENERIC_READ | FILE_WRITE_DATA` only (T74, T207, #43)
  **Breaking for Windows pipe clients:** open the pipe with desired access
  `GENERIC_READ | FILE_WRITE_DATA`. A non-administrator that requests
  `GENERIC_WRITE` now gets `ERROR_ACCESS_DENIED`. New
  `ferro_winauth::open_client_pipe` does this and sets
  `SECURITY_IDENTIFICATION`; `mia test` uses it, and `mia status` and `mia-tray`
  request the same access. See
  [docs/helper-api.md](docs/helper-api.md#windows-pipe-clients).

- Replace the unmaintained `rustls-pemfile` (RUSTSEC-2025-0134) with the `rustls-pki-types` PEM API in cmis and ferrogate-cli (T181)
  **`rustls-pemfile` dropped (`cmis`, `ferrogate-cli`).** It is unmaintained
  (RUSTSEC-2025-0134). PEM certificates and keys are now parsed with the
  `rustls-pki-types` `PemObject` API. Error messages are unchanged, and
  `cargo deny check` is clean again.

- Upgrade hiqlite 0.13.2 → 0.15.0 in ferro-raft: full-stop cluster upgrade, unchanged durability, constant-time peer secret checks and a new unauthenticated `/version` route (T182)
  **hiqlite 0.13.2 → 0.15.0 (`ferro-raft`).** Same feature set (`sqlite`,
  `auto-heal`); openraft stays on 0.9. 0.14.0 was skipped: with TLS on both
  transports its `Client::shutdown` panics, so `Cluster::shutdown` did too
  under `PeerTls`. 0.15 fixes that and shuts the TLS listeners down
  gracefully.
  - **Upgrade a multi-node cluster with a full stop and start**, not a
    rolling restart; upstream does not support mixing 0.15 with older nodes.
    The database WAL, state machine and wire formats are unchanged, so data
    directories carry over. Upstream's cache-WAL cleanup step does not apply
    (we do not enable the `cache` feature).
  - **Durability unchanged:** 0.15 moves the `wal_sync` default from
    `ImmediateAsync` to `IntervalMillis(200)`; `ferro-raft` now sets
    `ImmediateAsync` explicitly to keep the previous behaviour.
    `health_check_delay_secs` became `health_check_delay: Duration` (still
    zero). The `learner_only` and `rate_limit_db` fields added in 0.14 keep
    their defaults (every peer votes, no client-side rate limit). Unit tests
    in `ferro_raft::cluster` pin all of this.
  - **Security:** hiqlite now compares the peer challenge-response and the
    API secret header in constant time. It also adds an unauthenticated
    `/version` route on the Raft and API ports (like the existing `/health`
    and `/ping`) that returns the hiqlite version.
  - **`CMIS_RAFT_LISTEN` must be an IP literal.** hiqlite now parses the bind
    address strictly, so a hostname fails startup instead of being resolved.

- Raise the workspace MSRV from 1.88 to 1.95 because hiqlite 0.15 requires it (T183)
  **Workspace MSRV 1.88 → 1.95**, because hiqlite 0.15 declares
  `rust-version = "1.95.0"`.

### Fixed

- Make the Debian MIA installer provision its runtime identities and install and start the desktop tray (T211)
  `make pkg-deb` now produces the complete Debian workstation package: the
  `_ferrogate` service account, `ferrogate-clients` and `ferrogate-status`
  access groups, helper-socket systemd drop-in, `mia-tray`, polkit policy and
  XDG autostart entry are installed together. The sudo installer is enrolled in
  both access groups; other active local graphical users receive read-only
  status access. Their tray user service starts during installation, and group
  access takes effect on their next login.

#### Reconstructed from git history during the PTF migration

- Make the `mia-tray` workflow and `make deny` pass again under clippy 1.99 and cargo-deny (T184, #44, #45)
  Commits 9b64f3b (#44) and 3f431b8 (#45). Clippy 1.99 lints (`assert_is_empty`, a redundant
  `#[must_use]`) are satisfied across the workspace. For cargo-deny, every workspace crate is marked
  `publish = false` and `[bans] allow-wildcard-paths = true` accepts the internal version-less path deps
  while wildcards stay denied for everything else (`scripts/sdk-common.sh` drops `publish = false` from
  the staged SDK crates in publish mode; a stray `cargo publish` from the repo is now refused).
  `CDLA-Permissive-2.0` is allowed for `webpki-root-certs` only (Mozilla root bundle as data, via hiqlite
  → rustls-platform-verifier); it is not added to the workspace-wide allow list.

### Security

- Stop Windows pipe clients from creating extra server instances of the helper and status pipes (T74, T207, #43)
  **Windows pipe clients can no longer create pipe instances.** The named-pipe
  DACL built by `ferro_winauth::create_server_pipe` (helper pipe
  `\\.\pipe\ferrogate-mia`, status pipe `\\.\pipe\ferrogate-mia-status`)
  granted the client group (`FerroGateClients` / `FerroGateStatus`) `GRGW`. On
  a pipe, `GENERIC_WRITE` includes `FILE_APPEND_DATA` =
  `FILE_CREATE_PIPE_INSTANCE`, so any group member could create an extra server
  instance and answer other users' connections (forged helper tokens or status;
  impersonation of clients that did not restrict their SQOS level). The group
  now gets only `FILE_GENERIC_READ | FILE_WRITE_DATA` (`0x0012008B`). SYSTEM,
  Administrators and the pipe owner (`OW`, the account running `mia`) keep
  `GRGW`.

## [0.21.7] - 2026-10-02

### Added

- Add `mia-tray`, an unprivileged system-tray companion for the MIA agent that holds no key material (T209, T210, T211, S18)
  **`mia-tray`, a system-tray companion for the MIA agent (F18).** A small,
  unprivileged desktop app (macOS menu bar, Windows notification area, Linux
  StatusNotifierItem) that shows the agent's health per environment, raises
  notifications when a human is needed, runs a graphical setup wizard, offers
  guided recovery for each known failure state, and tails the daemon's
  recent, redacted logs. It holds no key material, never sends `HelperReq`,
  and runs every state-changing action as a fixed `mia` command behind the OS
  consent prompt (pkexec / macOS admin prompt / UAC). The GUI sits behind the
  default-off `gui` feature, so `make lint` / `make test` need no GTK; build it
  with `make tray`. Shipped in `pkg-macos`, `pkg-win` and `pkg-tray` (deb/rpm).

- Add a separate, read-only, rate-limited status endpoint to `mia` that never exposes key, token, SVID, pin or `jti` material (T207, S18)
  **Read-only status endpoint in `mia`.** A separate listener
  (`mia-status.sock` / `\\.\pipe\ferrogate-mia-status`, group
  `ferrogate-status` / `FerroGateStatus`) answering only `StatusReq` and
  `LogTailReq`, rate-limited per uid. Snapshots and log records carry no key,
  token, SVID, pin or `jti` material; redaction happens before a record enters
  the bounded in-memory log buffer. Wire types live in the new
  `mia-status-proto` crate. Configured by the new `[status]` section.

- Add `mia status [--json]`, `mia test --json` and `mia setup --check / --apply / --dump` (T207, T208)
  **`mia status [--json]`**, **`mia test --json`**, and
  **`mia setup --check / --apply / --dump`**. `--apply` validates the draft
  as untrusted input, writes atomically with the TTY wizard's mode and
  ownership, and appends a `ConfigChanged` audit event (key names only).

### Changed

- Make `mia setup` prompt for the attestation backend, refuse quotes, control characters and symlinked targets, and preserve keys it does not edit (T129, T208)
  `mia setup` now also prompts for the attestation backend, refuses `'` and
  control characters, refuses a symlinked target, and preserves keys it does
  not edit.

- Upgrade the cryptographic dependencies to ed25519-dalek 3, rand_core 0.10, p256 0.14, chacha20poly1305 0.11 and sha3 0.12 (T179)
  Cryptographic dependencies upgraded: `ed25519-dalek` 3, `rand_core` 0.10
  (randomness via `getrandom` 0.4 `SysRng`), `p256` 0.14, `chacha20poly1305`
  0.11, `sha3` 0.12.

- Document the `agent-router` and `fgv-desenvolvimento-seguro` skills as mandatory for AI assistants in `AGENTS.md` (T180)
  `AGENTS.md` documents the `agent-router` and `fgv-desenvolvimento-seguro`
  skills as mandatory for AI assistants.

### Postponed

#### Reconstructed from git history during the PTF migration

- Postpone forwarding the `ConfigChanged` journal to CMIS: `mia setup --apply` writes it to a local append-only `config-audit.jsonl` for now (T226)
  Recorded as a follow-up in `docs/features/F18-mia-tray.md` §"Progress — phase 1", `docs/audit.md`
  and `crates/mia/src/audit_client.rs`. The event carries the file path, the invoking user id and the
  dotted names of the changed keys — never their values.

## [0.21.6] - 2026-09-01

Not tagged in git; the date comes from the pre-migration changelog (release commit e85daa0).

### Added

- Issue a hybrid-signed SPIFFE X.509-SVID beside the JWS SVID from every attestation, revocable with it (T196, T197, T198, T199, S17)
  **X.509-SVID profile, issued beside the JWS one (F17).** CMIS now mints a
  SPIFFE X509-SVID certificate from every attestation, alongside the compact-JWS
  SVID it already issued — same SPIFFE ID, same validity window, same issuer
  key, both returned in `SVIDBundle` (`x509_svid`, `x509_bundle`). The JWS
  profile is unchanged; nothing has to migrate.

  The certificate exists so a workload can do mTLS, which the JWS profile cannot
  support, so its native signature is a **standard** RFC 8410 Ed25519 signature
  over the `TBSCertificate`: rustls, OpenSSL, and Envoy validate the chain with
  no FerroGate code in the loop. The post-quantum half is not given up — the
  ML-DSA-65 signature over the same body travels in the ITU-T X.509 (2019) §9.8
  alternative-signature extensions (`subjectAltPublicKeyInfo`,
  `altSignatureAlgorithm`, `altSignatureValue`), all non-critical, and
  `ferro-svid-verify`'s new `x509` module **requires** both halves. A stock stack
  therefore gets classical assurance and an opted-in consumer gets the same
  AND-combined assurance as the JWS profile; there is no PQ-only path and no way
  to strip the classical half.

  The leaf follows the SPIFFE X509-SVID shape (SPIFFE ID as the sole URI SAN,
  `CA:FALSE`, `keyUsage = digitalSignature`) and binds the Ed25519 half of the
  host's phase-4 composite CSR key, with the ML-DSA-65 half in
  `subjectAltPublicKeyInfo` — so the key that mints child tokens is the key that
  terminates mTLS. The trust anchor is a self-signed CMIS signing certificate,
  published in the JWKS `x-ferrogate-x509-bundle` member so one fetch arms a
  verifier for both profiles. It takes nothing from the clock and signs its PQ
  half with FIPS-204's deterministic variant, so every replica sharing an issuer
  seed publishes byte-identical anchor DER.

  Revocation covers both profiles: `RevokeHost` already did, and `RevokeSvid` on
  a JWS digest now also revokes the certificate issued with it, so an operator
  cannot accidentally leave a live certificate behind. See
  [docs/features/F17-x509-svid.md](docs/features/F17-x509-svid.md) for the shape,
  the two-pass signing order, and the two known gaps: MIA does not yet write the
  certificate anywhere (making it usable for local mTLS means putting private key
  material on disk, which needs its own decisions), and an F14 cross-sign window
  publishes only the live root's certificate anchor.

- Store the host's X.509-SVID sealed to a machine-bound key and add `mia x509-svid` to inspect it (T200, T201, S17)
  **The host stores its X.509-SVID under a machine-bound key (F17).** MIA now
  persists the certificate it was issued — leaf, trust bundle, and the Ed25519
  private key the certificate names — to `<state-dir>/x509-svid.sealed` (`0600`),
  sealed so the file **only opens on the machine that wrote it**. Where the host
  has a TPM the data-protection key is sealed by the chip to PCRs `{0,4,7,8}`,
  so the credential is unreadable on other hardware *and* after a boot-state
  change; elsewhere it is derived from the hardware fingerprint (F16), the same
  clone resistance the machine key already has. A usable TPM always wins, even
  on a host that attests through the software tier. A host with neither gets no
  store at all, because writing the private key unsealed is worse than
  re-attesting.

  Loading is fail-closed: a stored credential is returned only if it unseals
  here *and* still verifies — chains to its bundle under both signature halves,
  is unexpired, and its key is the one the certificate names. A store that fails
  any of that is logged and deleted rather than retried forever, which is what a
  TPM host sees after a firmware update. The store never decides whether to
  attest; the daemon attests on every start regardless.

  New `mia x509-svid` prints what is held (SPIFFE ID, sealing backend, expiry)
  and, with `--pem` / `--bundle-pem`, the certificates. It never prints the
  private key — serving that to a local workload belongs to the helper API, and
  is not implemented yet, so a workload still cannot do mTLS with the host's
  X.509-SVID.

- Seal the credential store with the macOS Secure Enclave behind the `secure-enclave` feature (T202)
  **The Secure Enclave seals the credential store on macOS.** The store gained a
  third backend beside the TPM and the fingerprint-derived machine key: `mia`
  generates a P-256 key *inside* the Apple Secure Enclave — non-exportable, root
  included — and ECIES-encrypts the store's data-protection key to its public
  half. Unwrapping happens inside the Enclave, so the file is inert on any other
  Mac. A hardware root is preferred in the order TPM → Secure Enclave → machine
  key, even on a host that attests through the software tier.

  Behind the new `secure-enclave` feature (off by default; it links
  Security.framework), which `make pkg-macos` now enables. Persisting the
  Enclave key needs a **codesigned** binary carrying a keychain-access-group
  entitlement — macOS answers `errSecMissingEntitlement` (-34018) otherwise, for
  every keychain and for Apple's canonical recipe alike, and ad-hoc signing is
  killed at launch by AMFI. `make pkg-macos CODESIGN_ID="Developer ID
  Application: …"` signs with `crates/mia/dist/mia.entitlements`. Since a
  non-persistent Enclave key would leave the next start unable to open its own
  store, `with_sealer` selects this backend only when it can actually keep the
  key, and otherwise falls through to the machine key with a logged reason.

  The Enclave *cryptography* needs no entitlement, so it is covered by live
  tests on real hardware: wrap/unwrap round trips, a blob refusing to open under
  a different Enclave key, tamper rejection, and a full credential round-trip
  through the store. Only cross-process persistence is `#[ignore]`d, since it
  cannot run from an unsigned build.

- Generalise `ferro_sep::seal_bytes` / `unseal_bytes` to arbitrary payloads bound to a purpose tag (T203)
  `ferro_sep::seal_bytes` / `unseal_bytes` generalise the machine-key AEAD
  envelope from a fixed 32-byte scalar to arbitrary payloads, with a purpose tag
  mixed into both the HKDF `info` and the AEAD associated data so a blob sealed
  for one use cannot be presented as another. The machine-key file is a
  purpose-empty envelope, so existing `host-key.bin` files still open unchanged.

- Add `CompositeSecretKey::to_ed25519_pkcs8_der` to export only the classical key half as PKCS#8 (T204)
  `CompositeSecretKey::to_ed25519_pkcs8_der` exports the classical half as
  PKCS#8 v1 (RFC 8410 §7) — the form a TLS stack loads a private key from, and
  the only way an X.509-SVID is usable. It is the one API that hands out private
  key material; the ML-DSA-65 half is deliberately not exportable.

- Add standard-format Ed25519 and ML-DSA-65 interop signers that refuse 48-byte messages (T205)
  `ferro_crypto::composite` gained `sign_interop_ed25519` /
  `sign_interop_mldsa65` (and their `verify_` counterparts, plus a deterministic
  ML-DSA variant): standard-format signatures over a raw message, for artefacts
  a third party must verify without FerroGate. They refuse a 48-byte message —
  the length of a composite transcript hash — so the interop and composite
  message spaces stay disjoint by construction.

## [0.21.5] - 2026-07-28

Tag `v0.21.5` (2026-07-28) marks the version-bump commit 41999e4; tag `releases/v0.21.5`, which triggers the release workflow, was cut on 2026-08-14 at commit 198b356 and so also carries the two reconstructed entries below.

### Added

#### Reconstructed from git history during the PTF migration

- Publish `ferrogate-sdk-rust` as a versioned crate to the `ferrogate` Cargo registry (T175, S34)
  Commit 198b356 (tagged `releases/v0.21.5`). `crates/ferrogate-sdk-rust` is a facade workspace member
  re-exporting the relying-party / verifier-side crates behind one versioned dependency, with features
  `verify` (default), `svid`, `attest`, `proto` and `full`; `proto` is off by default so a
  token-verifying consumer does not inherit `ferro-proto`'s protoc build requirement.
  `scripts/publish-sdk.sh` + `make publish-sdk` / `make publish-sdk-dry-run` stage and publish the
  workspace (registry: Cloudsmith `uox/ferrogate`).

- Add `LICENSE.md` pointing to Apache-2.0 (T176)
  Commit 1795acc; matches the `license = "Apache-2.0"` declaration in `[workspace.package]`.

### Changed

- Bump the workspace version only, with no functional changes since 0.21.4 (M27)
  **Version bump only.** No functional changes since [0.21.4]; this release
  exists to publish a new workspace version and its artifacts.

## [0.21.4] - 2026-07-27

### Fixed

- Exclude removable drives from the machine fingerprint so an external enclosure no longer changes a host's identity (T185, T164)
  **Removable drives no longer take part in the machine fingerprint (F15/F16).**
  The hardware fingerprint `H` folds in a disk serial, and every platform
  backend picked the *first* disk it enumerated — including a drive in an
  external enclosure. On macOS an attached Thunderbolt/USB NVMe enclosure can
  register ahead of the built-in SSD, so plugging one in silently changed `H`:
  the sealed machine key stopped decrypting (`sealed machine key did not
  decrypt (wrong host or corrupt file)`), the daemon never obtained a host SVID,
  and every mint was refused with `no-host-svid` — which surfaces as `mia test`
  failing at *helper token mint* while its own CMIS steps pass. `ferro-machineid`
  now considers only built-in storage: macOS skips NVMe controllers reporting
  `Physical Interconnect Location = External`, Linux skips devices flagged
  `removable` or sitting behind a USB/FireWire controller, and Windows filters
  `Win32_DiskDrive` down to non-USB, non-removable media. A host with no
  internal disk serial now contributes an empty one (already tolerated by the
  fingerprint) rather than borrowing a removable drive's identity or refusing to
  collect facts at all. Hosts enrolled while a removable drive supplied the
  serial will report a different `mia machine-id` after this change and need
  re-enrolling; hosts affected by the bug go back to their originally enrolled
  fingerprint.

## [0.21.3] - 2026-07-22

Date kept from the pre-migration changelog; tag `releases/v0.21.3` points at a commit dated 2026-07-27.

### Added

- Add `mia machine-id` to print this host's machine identity offline (T193)
  **`mia machine-id` — a dedicated command to print this host's machine
  identity.** The identity is the `<uuid>` in the host's SPIFFE id
  `spiffe://<trust-domain>/host/<uuid>` — the value CMIS keys the host's signed
  allowlist and host SVID under — derived locally from the hardware fingerprint
  (feature F15) via the same code path as `resync-allowlist`'s `host: <uuid>`
  line. Default output is the bare UUID on one line so it composes in scripts
  (e.g. `ferrogate allowlist set --host "$(mia machine-id)" …`); `--verbose`
  also prints the SHA-384 fingerprint and the raw hardware facts (board serial,
  platform UUID, disk serial). The command is read-only and offline — it never
  contacts CMIS, reads the daemon config, or touches the running agent, and
  warns on stderr (keeping stdout clean) when the hardware identifiers are
  incomplete.

## [0.21.2] - 2026-07-22

### Added

- Report the TPM and attestation posture as an informational line in `mia test` (T167)
  **`mia test` now reports the TPM / attestation posture.** A new
  informational `attestation` line (printed after the configuration check)
  states whether a real TPM was detected on the host and whether the daemon
  will actually attest with it — mirroring the daemon's own backend selection
  (`auto` → TPM when a usable device *and* `attestation.tpm.ek_cert` are
  present, otherwise the host-key software tier). The line is never a pass/fail
  result: a TPM-less host (the common VM case) is fully supported via the
  software tier, so it prints `info`; only a configuration that cannot attest
  (`backend = tpm` with no usable TPM, or `virtual-tpm`) prints `warn`, and
  neither affects the exit code. The probe is a cheap, read-only device open
  and never drives the TPM.

## [0.21.1] - 2026-07-15

### Fixed

- Build and run `ferro-harden` on aarch64 by gating legacy syscalls to x86_64 and allowing `unlinkat` and `fchmodat` (T87)
  **`ferro-harden` now compiles and runs on `aarch64`.** The seccomp
  name→number table mapped `readlink`/`unlink`/`chmod` to the legacy
  `libc::SYS_readlink`/`SYS_unlink`/`SYS_chmod` constants, which do not exist on
  `aarch64` (arm64 kept only the `*at` forms), so the crate failed to build for
  that target. Those three arms are now gated to `x86_64`, and `unlinkat` /
  `fchmodat` join the allow-list (`readlinkat` was already present). This is not
  only a compile fix: mia's dropped, seccomp'd runtime calls
  `std::fs::remove_file` / `set_permissions` / `read_link`, whose glibc wrappers
  dispatch to `unlinkat` / `fchmodat` / `readlinkat` on arm64 — without the new
  entries the daemon would `SIGSYS` on its first helper-socket cleanup or chmod
  under the enforcing filter. Verified building and testing `ferro-harden` on
  native `aarch64-unknown-linux-gnu`.

## [0.21.0] - 2026-07-15

This release accumulates the work tagged 0.15.1 through 0.20.24, which was collected under `[Unreleased]` and never given sections of its own. The pre-migration section repeated its Added, Changed and Fixed groups; they are merged here in canonical order, keeping the original order within each category.

### Added

- Add F16 tiered attestation for VMs: a real (v)TPM when available, a hardened software tier otherwise (T162, T163, T164, T165, S16)
  **F16 — tiered attestation for VMs (vTPM when available, hardened software
  otherwise).** mia now selects an attestation tier at boot. The new default
  `attestation.backend = "auto"` uses a real (v)TPM when the host has a usable
  one *and* an EK certificate is configured (`[attestation.tpm].ek_cert`),
  otherwise it falls back to the software `host-key` profile; `"tpm"` forces the
  TPM and is fail-closed. A new `TpmEvidence` adapter drives the genuine
  `TpmEngine` through the shared `run_attest` handshake, so hypervisor vTPMs
  (swtpm, vSphere) attest hardware-rooted. The software tier is hardened: the
  P-256 machine key is sealed at rest (ChaCha20-Poly1305 + HKDF) to the hardware
  fingerprint for clone resistance — a key file copied to another host will not
  decrypt there — with transparent in-place migration of pre-F16 plaintext keys.
  CMIS gains `CMIS_REQUIRE_PREREGISTERED_HOST_KEY` (refuse trust-on-first-use for
  un-enrolled software nodes), `CMIS_HOST_KEY_SVID_TTL_SECS` (shorter lifetime for
  the lower-assurance tier), and `CMIS_VTPM_EK_ROOTS` (trust an operator-run EK-CA
  for on-prem vTPMs, under the new `Vendor::OnPrem`). See
  [docs/features/F16-vtpm-tiered-attestation.md](docs/features/F16-vtpm-tiered-attestation.md).

- Add an in-process software virtual TPM, insecure by construction, for TPM-less dev and test hosts (T166)
  **In-process software virtual TPM for TPM-less dev/test hosts.** A new
  `mia::virtual_tpm::VirtualTpm` implements the `AttestEvidence` contract in pure
  Rust, so the full four-phase TPM attestation handshake can run on any OS
  (macOS, Windows, CI) without a real TPM or `swtpm` — unlike `mia::tpm`, which
  is Linux-only and needs hardware. It emits wire-correct TPM 2.0 structures the
  CMIS-side verifier accepts, persists a stable synthetic EK/AIK identity, and is
  gated behind the off-by-default `virtual-tpm` cargo feature. The daemon selects
  it only via `attestation.backend = "virtual-tpm"` (env `FERROGATE_ATTEST_BACKEND`);
  a build without the feature refuses that backend and fails closed. It is
  **insecure by construction** (no hardware root of trust) and for dev/test only.
  `make pkg-rpm MIA_FEATURES=virtual-tpm` builds an RPM with the feature compiled
  in. The two integration-test mocks were de-duplicated onto this module. See
  docs/mia.md "Attestation backend".

- Self-register `mia` with CMIS at startup by proposing its own binary immediately (T149)
  **`mia` self-registers with CMIS at startup (allowlist.propose).** The
  allowlist-propose task no longer waits for a local caller plus a full
  interval before its first proposal: it now fires immediately at startup, and
  every proposal carries a uid-wildcard entry for `mia`'s own binary — the
  proposal-side mirror of the helper API's self-trust, which already permits
  `mia` under any uid. A freshly provisioned host therefore appears in CMIS
  (a bootstrap-adopted allowlist, or a queued proposal under
  `CMIS_ALLOWLIST_PROPOSALS=off`) the moment its daemon attests, instead of
  staying invisible until a caller happened to connect. Previously a new host
  with `propose = true` proposed nothing at all until both a caller had been
  observed and the 300 s interval had elapsed.

- Cross-build the Windows MSI and the Chocolatey/NuGet package for `mia` in a container (T145)
  **Windows MSI + NuGet/Chocolatey packaging for `mia`, cross-built in a
  container.** `make pkg-win` no longer needs a Windows host: it cross-compiles
  `mia.exe` to `x86_64-pc-windows-msvc` with cargo-xwin in a `linux/amd64`
  container, builds an MSI with msitools (`wixl`, from `crates/mia/wix/mia.wxs`),
  and wraps it in a Chocolatey/NuGet package (`crates/mia/nuget/`) that installs
  the MSI via `msiexec`. The MSI mirrors the previous NSIS installer — installs
  to `Program Files\FerroGate\MIA`, adds it to the system PATH, creates the
  `FerroGateClients` helper group, and registers + starts the mia service. See
  `scripts/build-msi-amd64.sh`.

- Add `mia --resync` for a one-shot allowlist resync without a restart (T150)
  **`mia --resync` — one-shot, no-restart allowlist resync.** Re-fetches this
  host's signed caller allowlist from CMIS and swaps it into the running agent
  live (SIGHUP), so the helper socket never drops and no restart is needed. It is
  `mia resync-allowlist` with the live reload always on; on platforms without
  SIGHUP it falls back to the restart hint, and honors `--config`/`--environment`.

- Let `mia` obtain a host SVID on Windows through a Windows hardware-fingerprint backend (T192)
  **Windows host-key attestation — `mia` can now obtain a host SVID on
  Windows.** `ferro-machineid` gained a Windows backend that derives the stable
  hardware fingerprint from the SMBIOS system UUID, the baseboard/product serial,
  and the boot-disk serial (read via CIM through an absolute-path PowerShell, so
  `PATH` cannot be hijacked — the same rationale as the macOS `ioreg` backend).
  Previously `collect_facts()` returned "not supported on this platform", so the
  daemon had no host SVID and refused every mint with `no_host_svid`; Windows
  hosts can now attest via the TPM-less host-key profile (F15) like Linux/macOS,
  subject to CMIS enrolment.

- Add `helper.require_authenticode` to opt out of the Windows caller Authenticode check (T143)
  **`helper.require_authenticode` — opt out of the Windows caller Authenticode
  check.** The Windows helper API verifies each caller's image with Authenticode
  by default (the Code-Integrity analogue of the Linux IMA cross-check), which
  rejects unsigned callers — including an unsigned `mia.exe` running `mia test` —
  as `untrusted-binary`. The new `helper.require_authenticode` setting
  (`FERROGATE_HELPER_REQUIRE_AUTHENTICODE`, default `true`) lets environments
  whose binaries are not code-signed disable it; identity then rests on PID +
  image SHA-384 + RID, and `mia`'s self-trust still applies.

- Run MIA as a native Windows service managed with `mia service` (T141)
  **MIA runs as a native Windows service.** The daemon now integrates with the
  Windows Service Control Manager, so `Restart-Service mia` (and `sc start/stop
  mia`) work and the agent starts at boot. A new `mia service
  <install|uninstall|start|stop>` subcommand manages it (`mia service run` is the
  internal entry point the SCM launches); the service runs as `LocalSystem`,
  reads `%ProgramData%\FerroGate\mia.toml`, and — having no console — logs to
  `%ProgramData%\FerroGate\logs\mia.log`. The SCM glue lives in `ferro-winauth`
  (which permits `unsafe`) so `mia` stays `#![forbid(unsafe_code)]`. The Windows
  installer registers and starts the service automatically. See
  [docs/mia.md](docs/mia.md).

- Create the `FerroGateClients` helper group in the Windows installer (T142)
  **Windows installer creates the `FerroGateClients` helper group.** The default
  `helper.windows_group` restricts the helper pipe's DACL to this local group;
  the installer now creates it on install (and removes it on uninstall) so the
  daemon can resolve its SID and bind the pipe. Add vetted client accounts to the
  group so they may request tokens.

- Let hosts self-report their OS hostname for operator display, never as identity (T139)
  **Hosts self-report their OS hostname for operator display.** MIA now sends
  its OS hostname in `AttestInit`, and CMIS stores it on the issued record and
  surfaces it in `ferrogate list-svids` (and the `SvidSummary` RPC field). It
  is a display-only convenience — never identity (which stays rooted in the
  EK/host-key fingerprint) and never verified: CMIS sanitises it to printable
  ASCII and truncates to 64 chars before storing, a host that cannot report one
  sends the empty string, and records written before the field existed still
  decode (it is optional).

- Run the MIA daemon and helper API on Linux, macOS and Windows (T131)
  **MIA runs on Linux, macOS, and Windows.** The daemon now wires up and serves
  the helper API on all three platforms instead of only Linux: Linux uses
  `SO_PEERCRED` + IMA, Windows uses the named-pipe transport with PID + image
  hash + Authenticode, and macOS gains a new `MacCallerAuth` (peer-cred +
  on-disk image SHA-384 via the `libproc` crate; FFI stays out of `mia`, which
  remains `#![forbid(unsafe_code)]`). The startup hardening profile and TPM
  attestation remain Linux-only; shutdown handles `SIGINT`/`SIGTERM` on Unix and
  Ctrl-C on Windows.

- Discover the MIA configuration file at per-OS system and user locations (T128)
  **Per-OS configuration-file locations.** The config file is now discovered at
  the OS-idiomatic system path then the per-user path — Linux
  `/etc/ferrogate/mia.toml` / `~/.config/ferrogate/mia.toml`, macOS
  `/Library/Application Support/FerroGate/mia.toml` / `~/Library/...`, Windows
  `%ProgramData%\FerroGate\mia.toml` / `%APPDATA%\...` — in addition to
  `--config` and `$FERROGATE_CONFIG`. `mia setup` now writes the **TOML config
  file** (not the env file) to the system path by default, with `--user` for the
  per-user path, prompting platform-appropriately (socket mode on Unix, pipe
  group on Windows). New `helper.windows_group` key / `FERROGATE_HELPER_WINDOWS_GROUP`.

- Read an optional MIA TOML configuration file with defaults < file < environment precedence (T127)
  **MIA TOML configuration file.** MIA now reads an optional structured TOML
  configuration file (`crates/mia/src/config.rs`) in addition to environment
  variables, with precedence **defaults < config file < environment** — so
  existing env-driven deployments (the systemd `EnvironmentFile`) are unchanged.
  The file is discovered at `mia --config <path>`, then `$FERROGATE_CONFIG`,
  then `/etc/ferrogate/mia.toml`; a malformed file (including an unknown key)
  fails the daemon loudly at startup. Sections: `log`, `[cmis]`, `[helper]`,
  `[allowlist]`, `[attestation]`. A documented template is shipped at
  `/etc/ferrogate/mia.toml` (deb/rpm/macOS); source `crates/mia/dist/mia.toml`.

- Add the interactive `mia setup` configuration wizard (T129)
  **`mia setup` interactive configuration wizard.** A guided, rich-terminal
  wizard (built on `inquire`) that walks an operator through configuring the
  Machine Identity Agent — the CMIS server to connect to, the local helper API,
  the caller allowlist, attestation, and log verbosity — and writes the systemd
  `EnvironmentFile` (`/etc/ferrogate/mia.env`) in the documented, self-commenting
  template form. Run against an existing file it pre-fills every prompt, so it
  doubles as an editor. `--output <path>` targets a different file, `--force`
  skips the overwrite confirmation. Requires a TTY; unattended provisioning
  should write `mia.env` from the template directly.

- Add `make mia-install` to build and install the release `mia` binary (T140)
  **`make mia-install`.** Compiles `mia` in release mode and installs the
  stripped binary to `$(PREFIX)/bin` (default `/usr/local/bin`), falling back to
  `sudo` when the destination is not writable.

#### Reconstructed from git history during the PTF migration

- Add F15 TPM-less host-key attestation anchored in a hardware fingerprint and a non-exportable Secure Enclave key (T185, T186, T187, T188, T189, T190, T191, S15)
  Commit fc08a4f (merged for 0.16.0). Identity is `H = SHA-384(board serial | platform UUID | disk
  serial)` from the new `ferro-machineid` crate; the handshake is signed by a Secure Enclave key from the
  new `ferro-sep` crate (`secure-enclave` feature, off by default) with a portable software-key fallback.
  `AttestInit.host_key` (`HostKeyEvidence`, `MachineFacts`) keeps the TPM wire format unchanged and runs a
  3-phase handshake (no credential activation). CMIS verifies the evidence (`ferro-attest::host_key`),
  stamps SVIDs `policy_id = "host-key"` as a lower assurance tier than EK-rooted TPM quotes, pins
  `H ↔ sep_pub` on first use with optional operator pre-registration (`enrolled_machine_pubkey`) that
  closes the TOFU window, and rejects and audits rebinds. The fleet manifest gains `enrolled_machine_id` /
  `enrolled_machine_pubkey` (`--machine` / `--machine-pubkey`). The daemon attests on startup
  (`bootstrap_host_svid`) and enables the F09 minter, replacing the `no_host_svid` stub. `mia` stays
  `#![forbid(unsafe_code)]`. Remaining per the commit: daemon SEP-key keychain persistence, SEP-backed SVID
  cache sealing, and the host DPoP key (F09) for `cnf.jkt`.

- Store, sign and serve per-host caller allowlists from CMIS and manage them with `ferrogate allowlist` (T146, S32)
  Commit 974982f. Allowlists are keyed by the EK-derived host UUID and replicated through a
  `host_allowlists` Raft keyspace; `GetAllowlist` is unauthenticated (the body is signature-protected) and
  the admin `Set` / `Delete` / `ListAllowlists` RPCs manage them. The wire model moves to `ferro-svid`
  (`Issuer::sign_allowlist`). The CLI gains `allowlist set/add/remove/get/show/list/delete` with host
  selection by `--host` / `--ek-cert` / `--ek-sha384`; the daemon can auto-fetch its own allowlist
  (`allowlist.fetch` / `FERROGATE_ALLOWLIST_FETCH`). New `AllowlistSet` / `AllowlistDeleted` audit events.

- Make the caller-entry uid optional so an allowlist entry can match a binary hash under any user (T147, S21)
  Commit aea05e4, decision recorded in ADR-0002 (Accepted). `AllowEntry.uid` becomes `Option<u32>`;
  `Some(n)` encodes byte-identically to the old field so existing signed allowlists keep verifying. The
  MIA matcher keys members by hash with a `UidScope`; proposals keep the concrete observed uid (relaxing to
  a wildcard is an operator action). Rollout: upgrade the MIA fleet before any operator omits a uid — an
  old MIA cannot decode a wildcard body and fails closed (safe deny).

- Add `mia resync-allowlist` to re-fetch and verify the signed allowlist on demand (T150)
  Commit bc01487. Derives the host UUID locally from the hardware fingerprint, writes the signed CBOR to
  `allowlist.path`, and verifies it against the pinned enrollment key so a key rotation surfaces as an
  explicit "the daemon would REJECT this" message instead of a silent deny-all after the next restart.

- Add `mia refresh-key` to re-fetch the enrollment key non-interactively over the pinned channel (T134)
  Commit ded9602. After writing `allowlist.key` it verifies the on-disk allowlist against the new key and
  reports whether a `mia resync-allowlist` is needed; exits non-zero on failure.

- Add `ferrogate spki-pin` to compute the CMIS SPKI pin from a certificate without contacting CMIS (T135)
  Commit 26d6acc; pin derivation is refactored into `pin_from_cert` for reuse.

- Hand the helper socket to a dedicated group so non-root callers can connect (T136)
  Commit 62ed8a0. `helper.socket_gid` / `FERROGATE_HELPER_SOCKET_GID` chowns the socket to a numeric gid
  (it was hard-coded to none, leaving the socket unreachable by non-root callers); `make mia-install`
  creates `_ferrogate` (macOS) or `ferrogate` (Linux), adds the invoking user and passes the gid to the
  service. `mia` stays `#![forbid(unsafe_code)]` — the installer resolves the name, the daemon accepts only
  the number.

- Encrypt Raft and management traffic between CMIS nodes with TLS and bind a routable interface (T157, S5)
  Commit 2596ad1. Multi-node clusters bind `CMIS_RAFT_LISTEN` (default `0.0.0.0`) and can run both
  transports over TLS (`CMIS_PEER_TLS=1`, or operator PEM via `CMIS_PEER_TLS_CERT` / `KEY`). TLS
  encrypts the wire; the shared `CMIS_RAFT_SECRET` / `CMIS_API_SECRET` handshake authenticates peers. This
  removes the F05 "pin the cluster to a private network" limitation for classical TLS; PQC peer TLS remains
  an upstream concern.

- Discover CMIS through DNS SRV records with best-first selection and fail-over (T158)
  Commit 7564731. `cmis.srv` (`FERROGATE_CMIS_SRV`, exclusive with `cmis.endpoint`) is resolved and
  ordered by RFC 2782 priority and weight; the pinned hybrid-PQC TLS handshake is the health check, so an
  unreachable, non-hybrid or wrong-identity node is skipped. Every CMIS interaction re-resolves on
  reconnect. One `cmis.spki_pin` authenticates all nodes. `mia test` probes each node.

- Add `mia --environment <env>` to target side-by-side deployments from `mia-<env>.toml` (T137)
  Commit d58784b. Applies to the daemon, `setup`, `test`, `resync-allowlist` and `refresh-key`;
  `validate_environment` refuses traversal; exclusive with `--config` / `setup --output`.

- Serve every discovered environment from one daemon, each with its own CMIS and helper socket (T138)
  Commit 114f2d7 (0.19.0). A failing environment is logged and isolated; duplicate sockets across
  environments are skipped rather than crash-looping. `--config`, `--environment` and
  `$FERROGATE_CONFIG` still pin the daemon to one environment.

- Add `mia setup --clean`, OS-aware `make mia-install` locations and `mia-uninstall` with OS service registration (T130, T140)
  Commits 3c135e2 and 02df70c. `mia-install` installs to `/usr/local/bin` (Linux/macOS) or
  `%LOCALAPPDATA%\Programs\FerroGate` (Windows) and registers the launchd plist or systemd unit;
  `mia-uninstall` deregisters it and removes the binary, leaving config, logs and socket intact.

- Add `make deploy-release` to tag and push `releases/v<version>` (T174)
  Commit cf39eb8. Pushing the tag triggers `.github/workflows/release.yml`; guards against a dirty tree
  and an existing tag.

### Changed

- Replace the WiX/MSI Windows packaging with a self-contained NSIS installer built by `make pkg-win` (T144)
  **Windows packaging migrated from WiX/MSI to NSIS.** `make pkg-msi` (cargo-wix
  + the end-of-life WiX v3 toolset) is replaced by `make pkg-win`, which builds a
  self-contained `.exe` installer with NSIS from `crates/mia/nsis/installer.nsi`.
  The installer drops `mia.exe` under `Program Files\FerroGate\MIA`, adds it to
  the system PATH, registers the Windows service, and ships an uninstaller.
  `make pkg-tools` installs NSIS via winget on Windows.

- Always permit `mia`'s own binary through self-trust while the host-SVID and CRL gates still apply (T153)
  **`mia` self-trust — the binary never loses access to its own daemon.** `mia`
  ships as one executable serving as the daemon, the CLI, and the `mia test`
  self-test. The daemon now computes the `SHA-384` of its own executable once at
  startup and **always permits a caller whose `bin_sha` matches it**, regardless
  of the signed allowlist or the caller's `uid`. This fixes `mia test`'s helper
  token mint step (`[4/4]`) failing with `PermissionDenied` on a host whose
  allowlist has not yet been provisioned — `mia` talking to itself is always
  allowed. Self-trust substitutes only for the allowlist membership check; the
  host-SVID requirement and the CRL freshness/revocation gate (F11) still apply,
  so a revoked host cannot mint even for `mia`'s own binary, and a modified
  binary (different hash, or an IMA mismatch on Linux) does not inherit the
  trust. See [docs/helper-api.md](docs/helper-api.md).

- Support an any-binary allowlist wildcard `bin_sha = "*"` symmetric to the uid wildcard (T154, S21)
  **Any-binary allowlist wildcard (`bin_sha = "*"`).** Allowlist entries now
  support a binary-side wildcard symmetric to the existing uid wildcard: a
  `bin_sha` of `"*"` permits **any** binary, so `(uid 1000, "*")` admits any
  program run by uid 1000 and `(any uid, "*")` admits any program run by any
  user. CMIS validates and signs `"*"` entries (`SetAllowlist` and host
  proposals), the MIA folds them into an any-binary scope it checks alongside
  the per-hash entries (a wildcard subsumes uid pins exactly as before), and
  the CLI accepts `--entry <uid>:*`, `--entry *`, and `--bin-sha *` (for
  `remove`). Existing hash-pinned entries and their signatures are unchanged —
  `"*"` can never collide with a 96-hex-char hash, so the signed wire shape
  stays a plain string. See [docs/allowlist-provisioning.md](docs/allowlist-provisioning.md)
  and [ADR-0002](docs/adr/0002-allowlist-optional-uid.md).

- Add `mia --reload` to signal a live configuration and allowlist reload (T152)
  **`mia --reload` — signal a live config + allowlist reload.** A top-level
  management flag that sends `SIGHUP` to the running agent (via the service
  manager) so it re-reads its configuration file and signed allowlist and swaps
  them in without a restart — the helper socket never drops. The daemon's
  `SIGHUP` handler now reloads the configuration (not just the allowlist): it
  re-applies the `log` verbosity directive live and re-loads the allowlist from
  the possibly-changed `allowlist.path`/`key`/`max_age_secs`. Settings that pin
  process-wide state at startup — the helper socket, the CMIS endpoint,
  attestation inputs, the hardening profile — still require a restart. Unlike
  `mia resync-allowlist --reload`, `mia --reload` fetches nothing; it only
  signals, so it is the right tool after editing the local config or replacing
  the allowlist body on disk. Not supported on Windows (no `SIGHUP`).

- Reload the signed allowlist live on `SIGHUP` and add `mia resync-allowlist --reload` (T151, T150)
  **Live allowlist reload on `SIGHUP` (`mia resync-allowlist --reload`).** The
  agent now re-reads and swaps in its signed caller allowlist on `SIGHUP`
  without restarting, so a re-sync no longer tears down the helper socket (the
  restart window that surfaced as a transient `ECONNREFUSED` in `mia test`).
  `resync-allowlist` gains an opt-in `--reload` flag that signals the running
  service (`launchctl kill HUP …` on macOS, `systemctl kill -s HUP mia` on
  Linux) after writing and verifying the new body; without it the command
  still prints the restart hint. Reload mirrors startup's fail-closed
  semantics — a missing or non-verifying body swaps in deny-all, an
  unexpected I/O error keeps the current allowlist — and Windows (no SIGHUP)
  continues to require a restart.

- Show each host's self-reported hostname, marked display-only, in `ferrogate list-svids` (T139)
  **Hostname shown in `ferrogate list-svids`.** mia now reports the host's OS
  hostname in `AttestInit` as a display-only label; CMIS sanitises it
  (printable ASCII, 64-char cap), stores it on the issued record, and the CLI
  prints it under the SPIFFE id marked "(self-reported, display only)". It is
  never identity — the SPIFFE id stays rooted in the EK / hardware-fingerprint
  UUID — and records written before the field existed still decode.

- Add `mia test`, a connectivity and token-issuance self-test with targeted remediation hints (T132)
  **`mia test` — connectivity and token-issuance self-test.** A new
  non-interactive subcommand that exercises the full path a local application
  depends on: configuration (CMIS endpoint + SPKI pin), the eager pinned
  hybrid-PQC TLS dial to CMIS, CMIS CRL publishing (`JWKS` RPC, signature
  verification, freshness), and a live child-token mint through the local
  helper socket. Every failing step prints targeted remediation hints
  mirroring the operations runbooks — a `crl_stale` refusal is
  cross-referenced with the server-side CRL check to say which side is at
  fault — and the command exits non-zero so provisioning scripts can gate on
  it.

- Let hosts propose observed callers to CMIS with a TOFU bootstrap and an operator review queue (T148, S32)
  **Host-driven allowlist proposals (TOFU bootstrap + review queue).** mia can
  now propose the local callers it observes back to CMIS so a freshly installed
  host populates its own allowlist instead of an operator hand-enumerating every
  caller. The helper API records each authenticated `(uid, binary SHA-384)` it
  sees (granted *and* denied — a deny-all host's denials are the bootstrap
  candidates); when `allowlist.propose` is on, a background task periodically
  sends them via a new `ProposeAllowlist` RPC, signed by the host machine key
  and carrying the host SVID. CMIS verifies the SVID it issued, checks the
  signature against the key bound by `cnf.jkt`, and confirms the host UUID, then
  applies its `CMIS_ALLOWLIST_PROPOSALS` policy: `bootstrap` (default) auto-signs
  the first proposal on a host with no allowlist (trust-on-first-use) and queues
  any later change; `off` queues everything; `always` auto-adopts every
  proposal. Operators review the queue with `ferrogate allowlist proposals` /
  `review` / `approve` / `reject`. New audit events `AllowlistProposed`,
  `AllowlistAutoAdopted`, `AllowlistProposalRejected`. The signing context
  `ferrogate-allowlist-proposal-v1` is distinct from the issuance context so a
  proposal signature can never be replayed as a signed allowlist.

- Serve the enrollment key through the `GetEnrollmentKey` RPC and fetch it in `mia setup` (T133)
  **`GetEnrollmentKey` RPC + `mia setup` key fetch.** CMIS now serves its
  enrollment public key (the composite key that signs caller allowlists, as
  `from_concat_bytes` bytes) via a new `GetEnrollmentKey` gRPC. `mia setup`,
  when an allowlist is configured and a CMIS endpoint + SPKI pin are present,
  offers to fetch that key over the pinned hybrid-PQC TLS channel and write it
  to `allowlist.key`. Also fixes the SPKI-pin format wording (lowercase-hex
  SHA-384, not base64) and validates the pin in the wizard. The signed
  allowlist *body* served from CMIS (per-host store + admin path) is planned.

#### Reconstructed from git history during the PTF migration

- Explain the SPKI pin and the allowlist in `mia setup` and warn before prompting when the target is not writable (T129)
  Commits 1d797a4 and 898a59f.

- Rename the `docker-image*` make targets to `container-image*` (T168)
  Commit 0bcea1b.

### Fixed

- Allow `mkdir` and `mkdirat` under seccomp so `mia` stops SIGSYS crash-looping when it creates state directories (T87)
  **mia no longer SIGSYS-crash-loops when it creates a runtime/state directory
  under seccomp.** The F12 seccomp allow-list omitted `mkdir`/`mkdirat`. Rust's
  `std::fs::create_dir_all` issues the `mkdir(2)` syscall *unconditionally* —
  even when the target directory already exists it lets the kernel reject it
  with `EEXIST` — so the first post-drop `create_dir_all` (e.g. caching the
  CMIS-fetched allowlist under the state dir right after the host SVID is
  obtained) was killed with `SIGSYS` before the syscall ran, leaving the daemon
  in a `code=dumped, status=31/SYS` restart loop. `mkdir` (x86_64) and
  `mkdirat` (all arches) are now on the allow-list, matching how the daemon
  already manages its own socket and state files (`unlink`, `chmod`).

- Authenticate helper callers by binary hash plus allowlist on hosts that do not enforce IMA (T69)
  **Helper caller-auth works on hosts that don't enforce IMA.** The Linux
  authenticator cross-checked every caller's binary hash against the kernel IMA
  measurement log; on a host running `FERROGATE_REQUIRE_IMA=0` (IMA not enforced,
  log empty and root-only) this failed with `ima-unavailable`, so the helper API
  refused all callers even after the daemon was otherwise healthy. The IMA
  cross-check now tracks the same `FERROGATE_REQUIRE_IMA` switch as the startup
  check: when IMA is not required, `ImaCallerAuth::without_ima` authenticates by
  the SHA-384 of the caller's loaded binary (read through `/proc/<pid>/exe`) plus
  the allowlist, skipping the measurement-log lookup — mirroring how the Windows
  authenticator drops its Authenticode check when not required. When IMA *is*
  required the full cross-check is unchanged.

- Retain `CAP_SYS_PTRACE` after the non-root drop so the helper API can authenticate callers again (T88, T69)
  **Helper API can authenticate callers again after the non-root drop.** Once
  the daemon stayed up and served (0.20.21), the helper API refused every caller
  with `exe-unreadable`: caller authentication reads and hashes the caller's
  `/proc/<pid>/exe`, but a daemon dropped to `_ferrogate` fails
  `ptrace_may_access` on any caller under a different UID (including root's
  `mia test`), so it could authenticate no one but itself. The privilege drop now
  retains **`CAP_SYS_PTRACE`** alongside `CAP_IPC_LOCK` (`restrict_capabilities`),
  which re-enables that read-access check. The `ptrace` **syscall** stays off the
  seccomp allow-list, so this grants read access to callers' `/proc` entries only
  — not active tracing/injection — and is strictly less privileged than running
  the daemon as root.

- Complete the seccomp allow-list for `mia`'s attestation and async-runtime path (T87)
  **seccomp allow-list completed for mia's attestation and async-runtime path.**
  With the fingerprint building (0.20.20), `mia` finally exercised its full
  post-drop path — attesting to CMIS and running the tokio reactor — and was
  killed by `SIGSYS` on syscalls the allow-list still lacked: `epoll_wait`
  (the reactor on kernels that use it over `epoll_pwait`), `poll`, `fstat`, and
  `sendmmsg` (DNS). All four are now allow-listed (`epoll_wait`/`poll`/`fstat`
  gated to x86_64, where those legacy syscalls exist; arm64 uses the `*at` /
  `*_pwait` forms). The complete set was captured by enumerating seccomp audit
  records **by executable** rather than thread name — tokio renames its worker
  threads, so a `comm`-based filter had missed the reactor's syscalls. With this,
  `mia` attests, obtains a host SVID, and serves the helper API under full
  seccomp enforce.

- Make the disk serial best-effort and allow-list `mia`'s real runtime syscalls so hardened startup completes on VMware (T87, T185)
  **`mia` completes hardened startup on hosts without a disk serial, and the
  seccomp allow-list now covers its real runtime.** After 0.20.19 let hardening
  finish, two more never-exercised gaps surfaced: (1) the machine fingerprint
  could not be built on VMware VMs, which expose no block-device serial — the
  disk serial is now **best-effort** (`ferro-machineid`), with identity resting
  on the board serial + SMBIOS `product_uuid` (both stable and unique); hosts
  that *do* report a disk serial still fold it in, so their fingerprint is
  unchanged. (2) The daemon was killed by `SIGSYS` on syscalls the allow-list
  had never seen at runtime — `prctl` (tokio thread naming), `socketpair`
  (runtime), `unlink` + `chmod` (stale-socket removal and helper-socket mode),
  and `readlink`; all five are now allow-listed. The complete set was captured
  in one pass via a seccomp audit-mode run. `chmod` is now permitted (a dropped
  process setting its own socket's mode); process-execution and tracing remain
  forbidden.

- Finish wiring the non-root privilege drop: allow `capget`, prefetch the fingerprint and hand state directories over before dropping (T88, T87)
  **`mia` still failed to start after the `PR_CAPBSET_DROP` fix — the non-root
  privilege drop was never fully wired.** With hardening able to complete, three
  further problems surfaced, all because root-only work ran *after* dropping to
  the unprivileged `_ferrogate` user: (1) the seccomp filter killed `mia` with
  `SIGSYS` on `capget` (its own post-drop capability check) — `capget` is now in
  the allow-list; (2) the machine fingerprint could not be read (DMI serials are
  root-only) — it is now **prefetched before the drop** and cached for
  attestation; (3) the helper socket (`/run/ferrogate`) and the persistent key +
  SVID seed (previously under the root-owned `/etc/ferrogate`) could not be
  written. The key and seed now live in a dedicated state directory
  (`/var/lib/ferrogate` on Linux) that `mia`, while still root, creates and hands
  to `_ferrogate` — along with the helper-socket directory — *before* dropping
  privileges. The SVID seed is written `0600` at creation rather than via a
  post-drop `chmod` (which the seccomp profile forbids). `ferro-harden` gains
  `prepare_runtime_paths` for the pre-drop directory hand-off, and mia now does
  all root-requiring startup in a single `prepare_and_harden` step. The config
  directory (`/etc/ferrogate`) stays root-owned and read-only.

- Stop the `PR_CAPBSET_DROP` crash loop by re-raising `CAP_SETPCAP` before trimming the bounding set (T88)
  **`mia` crash-loop on Linux during privilege-drop hardening
  (`PR_CAPBSET_DROP failure: Operation not permitted`).** When `mia` started as
  root and dropped to the non-root `_ferrogate` service user, the `setuid()`
  cleared the effective capability set (`PR_SET_KEEPCAPS` preserves only the
  *permitted* set), so the subsequent bounding-set trim — which needs
  `CAP_SETPCAP` in the *effective* set — failed with `EPERM`, the hardening step
  aborted, and systemd restarted the agent in a tight loop (it never attested).
  `ferro-harden` now re-raises `CAP_SETPCAP` into the effective set before
  `PR_CAPBSET_DROP` and collapses to `{CAP_IPC_LOCK}` afterwards. Any Linux host
  running as root with the default non-root privilege drop was affected.

- Tolerate up to 60 s of forward clock skew when verifying a freshly signed allowlist (T70, T146)
  **Clock-skew race rejected a freshly signed allowlist as "not yet valid",
  putting the helper API in deny-all.** `mia` verifies the CMIS-signed caller
  allowlist with a strict not-before check (`now < issued_at`). When the CMIS
  clock ran a hair ahead of the host, a just-fetched allowlist carried an
  `issued_at` a fraction of a second in the future, so verification failed
  `NotYetValid` and the helper socket fell to fail-closed (deny every caller —
  no wildcard or exact-hash entry could admit anyone) until the next
  re-attestation. The not-before check now tolerates up to
  `ALLOWLIST_NOT_BEFORE_LEEWAY_SECS` (60 s) of forward skew, mirroring the
  CRL freshness gate's existing `CRL_FRESHNESS_LEEWAY_SECS`; a genuinely
  future-dated allowlist beyond the leeway is still rejected.

- Republish a missing host child-token key on a JWKS miss so HA replicas stop failing with `no key for kid` (T159)
  **Cross-node `no key for kid host-…` on HA CMIS clusters — JWKS on-miss
  rehydrate.** A host's child-token signing key was published into the JWKS
  only by the CMIS replica that witnessed its attestation
  (`register_child_key` is process-local); startup rehydration (F09) healed a
  *restarted* replica, but a replica up since before the attestation kept
  serving a JWKS without that host's kid, so any verifier routed to it failed
  child-token verification spuriously. `JWKSRequest` gained an optional
  `kid_hint` field (wire-compatible; older clients send nothing and are
  unaffected): when a caller names a `host-…` kid missing from the replica's
  published set, the replica re-reads the replicated issued-SVID store —
  where the attesting node persisted the key — before answering
  (`CmisState::ensure_child_key_published`). A kid in nobody's store still
  fails exactly as before; the hint can only turn spurious misses into
  successes.

- Diagnose an unsigned Windows `mia.exe` failing its own `mia test` and add optional Authenticode signing to `make pkg-win` (T143, T145)
  **Clearer guidance when an unsigned Windows `mia.exe` fails its own `mia
  test`.** On Windows the helper API's caller check requires a valid
  Authenticode signature by default (`helper.require_authenticode`), and the
  `mia.exe` that `make pkg-win` produces is unsigned — so `mia test` step 5
  (helper token mint) failed out of the box with `PermissionDenied`
  (`untrusted-binary`), and self-trust does not bypass caller authentication.
  Three things now make this diagnosable and fixable: the step-5 failure hint
  names the `untrusted-binary` reason and the `helper.require_authenticode`
  knob; the daemon warns at startup on Windows when its own binary fails
  Authenticode while the check is enabled; and `make pkg-win` gained an
  optional signing step (`WIN_SIGN_PFX=…`, plus `WIN_SIGN_PASS` / `WIN_SIGN_TS`)
  that Authenticode-signs `mia.exe` and the MSI with `osslsigncode`, printing a
  NOTE when the build is left unsigned.

- Explain a Windows helper pipe already owned by another `mia` instead of a bare "Access is denied" (T74)
  **Clearer error when the Windows helper pipe is already owned by another
  `mia`.** Creating the first helper-pipe instance while the `mia` service (or
  any other instance) is already running failed with the bare, baffling `socket
  setup: Access is denied. (os error 5)` — Windows returns `ERROR_ACCESS_DENIED`
  for `FILE_FLAG_FIRST_PIPE_INSTANCE` when a pipe of that name already exists.
  `ferro-winauth::create_server_pipe` now translates that specific case into an
  actionable message naming the cause (another instance already running; stop
  the service first). All other errors and subsequent pipe instances are
  unchanged.

- Resolve `net.exe` by absolute path in the Chocolatey scripts so installs work under a minimal `PATH` (T145)
  **The `ferrogate-mia` Chocolatey package no longer fails to install under a
  service account with a minimal `PATH`.** Both `chocolateyInstall.ps1` and
  `chocolateyUninstall.ps1` invoked `net.exe` by bare name, which PowerShell
  resolves via `PATH`; when Chocolatey is driven by a config-management agent
  (e.g. Puppet running as a Windows service) rather than an interactive admin
  shell, `PATH` may not include `System32` and the call fails with `The term
  'net.exe' is not recognized`, aborting the install before the MSI step runs.
  Both scripts now resolve `net.exe` via `$env:SystemRoot\System32\net.exe`.

- Make the Chocolatey scripts tolerate a `FerroGateClients` group that already exists or is already gone (T145, T142)
  **The `ferrogate-mia` Chocolatey package no longer fails when the
  `FerroGateClients` group already exists.** `chocolateyInstall.ps1` ran `net
  localgroup FerroGateClients /add` with its stderr redirected (`2>&1`);
  under `$ErrorActionPreference = 'Stop'` PowerShell turns a native command's
  stderr output into a terminating error, so on hosts where the group was
  left behind by a previous install the script aborted with `Erro de sistema
  1379` ("the specified local group already exists") before the MSI step ran.
  The install script now probes for the group and only creates it when
  missing, checking `$LASTEXITCODE` explicitly with the error preference
  relaxed around the `net.exe` calls; `chocolateyUninstall.ps1` had the
  mirror-image bug (`/delete` on an already-removed group) and is guarded the
  same way.

- Guarantee the Chocolatey package registers and starts the `mia` service and stop masking a failed registration (T145, T141)
  **The `ferrogate-mia` Chocolatey package now guarantees the `mia` service is
  registered, and no longer masks a failed service registration.** The MSI
  declares its `ServiceInstall` non-vital (a bare-MSI install must not
  hard-fail on service quirks), so Windows Installer can report success even
  when `CreateService` failed at runtime — leaving a "successful" install with
  no `mia` service. `chocolateyInstall.ps1` now (a) passes `/l*v` to msiexec so
  a verbose MSI log lands in `chocolatey\logs\ferrogate-mia.msi.install.log`,
  (b) verifies the service exists after the MSI and, if not, registers it via
  `mia.exe service install` (identical parameters), failing loudly if that also
  fails, and (c) starts the service if it is not running, downgrading a start
  failure to a warning (on first install the config is typically laid down by
  the config-management agent right after the package).

- Keep child-token keys stable across `mia` and CMIS restarts with a persisted SVID seed and JWKS rehydration at startup (T159, T191)
  **Child tokens no longer fail with `no key for kid host-…` after a `mia` or
  CMIS restart.** A host's child-token signing key (F09) has a `kid` derived
  from its composite public key, and two independent causes made that key
  disappear from the verifier's view:
  - On the TPM-less **host-key** profile, `mia` generated a *fresh* composite
    SVID key on every daemon start (the persistent thing was the machine key,
    not the SVID key), so each restart rotated the `kid`. `mia` now persists a
    32-byte **SVID seed** beside `host-key.bin` (`svid-seed.bin`, `0600`) and
    derives the composite key deterministically with
    `CompositeSecretKey::from_seed`, so a restart re-attests under the same key
    and keeps the same `kid`. If the seed cannot be persisted the daemon falls
    back to an ephemeral key (the previous behaviour) and logs it.
  - CMIS held the per-host child keys only in a process-local in-memory
    registry, so a restarted (or never-attested-to HA replica) served a JWKS
    with just the issuer root key until each host happened to re-attest. The
    host's `composite_pub` is now persisted in the replicated issued-SVID store
    and **rehydrated into the JWKS at startup**, so any replica republishes
    every known host key by `kid`. Records written before this change carry no
    stored key and are simply skipped (republished on the host's next
    attestation), and the wire format stays backward-compatible.

- Auto-renew allowlists on serve so a stable allowlist no longer ages out and locks hosts out (T146)
  **CMIS now auto-renews allowlists on serve, so they no longer rot and lock
  hosts out.** `GetAllowlist` re-stamps an aging allowlist with a fresh validity
  window (re-signs `(now, now+ttl)` with the same entries) once its window is
  past half-life or expired, so a host that keeps fetching never sees its
  allowlist rejected as `TooOld`/`Expired` and fall closed. Previously CMIS
  served the stored blob verbatim and nothing refreshed it — the propose loop
  dedups unchanged caller sets, and the MIA only checks freshness at load — so a
  stable allowlist eventually aged past `max_age_secs` and denied every caller.
  The refresh is stateless and HA-safe (served, not persisted; signed with the
  replicated issuer key, so any node can do it with no Raft write) and fails
  safe (serves the stored bytes unchanged on any error). The default allowlist
  validity window is now **72 h** on both sides (CMIS `allowlist_ttl_secs` and
  the MIA's `allowlist.max_age_secs`); the CMIS env floor drops to 1 h since the
  window is continuously renewed.

- Retry host attestation every 5 minutes so `mia` recovers a missing host SVID without a restart (T161, T191)
  **`mia` now recovers a missing host SVID on its own — no restart needed.**
  When attestation to CMIS fails at startup (CMIS unreachable, or — the common
  case — DNS/VPN not up yet right after boot), the daemon used to serve forever
  with minting disabled (`no_host_svid`) because attestation ran only once at
  startup. It now retries host-key attestation every 5 minutes in the
  background; the first success live-swaps the minter into the running server
  (minting on, no socket downtime), refreshes the signed allowlist from CMIS,
  and — if configured — starts the allowlist-propose task. Mirrors the CRL
  puller's stance that CMIS being down at boot must not permanently disable
  minting.

- Run `mia test` step 5, the helper token mint, on Windows over the named pipe (T132, T74)
  **`mia test` step 5 (helper token mint) now runs on Windows.** It previously
  bailed with "the named-pipe self-test is not supported on this platform yet";
  it now connects the helper named pipe (mirroring the Unix UDS path) and either
  mints a token or reports the real reason (pipe missing ⇒ service down, busy, a
  DACL denial, or a daemon refusal such as `no_host_svid`) with remediation
  hints. The request/response exchange is shared between the Unix and Windows
  transports.

- Restore split-brain detection on self-signed peer-TLS clusters with a deterministic shared peer certificate (T157, S5)
  **CMIS split-brain detection now works on a self-signed peer-TLS cluster
  (`CMIS_PEER_TLS=1`).** hiqlite's periodic `split_brain_check` fetches
  `/cluster/metrics/*` from peers with a client that does platform/CA
  certificate verification. In the zero-config self-signed mode each node minted
  its own ephemeral cert, which no peer could verify, so the check failed every
  cycle with `UnknownIssuer` / `check_compare_membership` errors — Raft
  replication was unaffected, but split-brain *detection* (a safety check)
  silently stopped working. Self-signed peer TLS now derives the **same** CA +
  leaf certificate on every node *deterministically from the shared cluster
  secret* (no distribution needed) and advertises the CA via `SSL_CERT_FILE`, so
  the verifying client accepts its peers. Peer *identity* is still authenticated
  by the shared-secret handshake; the cert exists only to satisfy that one
  verifying client. The `CMIS_PEER_TLS` env contract is unchanged. Operator
  certs (`CMIS_PEER_TLS_CERT`/`KEY`) are likewise advertised as a trust anchor,
  so split-brain detection works there too even when the cert is self-signed.
  New code lives in `ferro_raft::peer_cert` +
  `ClusterConfig::materialize_peer_tls`. *Linux note: the trust step relies on
  `rustls-platform-verifier` honoring `SSL_CERT_FILE`, which holds on Linux (the
  supported deployment target); macOS uses the system keychain.* See
  [docs/features/F05-cmis-ha.md](docs/features/F05-cmis-ha.md).

- Serve deny-all instead of crash-looping when the allowlist cannot be verified (T70)
  **mia no longer crash-loops on an unverifiable allowlist; it serves deny-all
  instead.** A bad allowlist signature at startup — typically a CMIS redeploy
  that changed the enrollment key, leaving the locally pinned `allowlist.pub`
  stale — aborted the daemon, which the service supervisor then restarted
  every few seconds: the helper socket never bound, callers saw `ECONNREFUSED`
  against a stale socket file, and `mia test` misread the failure as a socket
  path/permissions problem. Signature/freshness failures, a missing or
  unparseable key file, and a missing allowlist body now all log a loud error
  and serve in deny-all mode (`mia::helper::allowlist::load_at_startup`), so
  the daemon stays up and the deny is diagnosable from the daemon log and
  audit events; only unexpected I/O errors remain fatal. `mia test` gained
  connection-refused hints pointing at supervisor restart loops, and its
  `permission_denied` hints now mention the deny-all mode and re-fetching the
  enrollment key with `mia setup`.

- Start the CRL puller at daemon startup so helper tokens can actually be minted (T160)
  **mia now starts the CRL puller, so helper tokens can actually be minted.**
  The daemon created the F11 CRL cache empty and never wired
  `mia::helper::crl::spawn_puller`, so the helper API's fail-closed freshness
  gate refused every mint with `crl_stale` forever — even against a healthy
  CMIS publishing a fresh CRL every 60 s. Startup now spawns the puller against
  the pinned CMIS channel (`maybe_spawn_crl_puller`), pulling at the 60 s
  publish cadence and retrying the initial dial forever so CMIS being down at
  boot cannot permanently disable minting; a missing/invalid CMIS configuration
  is loudly logged as leaving minting disabled. Covered by a new integration
  test (`crates/mia/tests/crl_pull.rs`) running a real in-process CMIS:
  fail-closed when empty or unpublished, gate opens after the first verified
  pull, and `spawn_puller` pulls immediately rather than after the first tick.

- Persist the CMIS issuer signing seed across restarts instead of minting a fresh key on every boot (T156)
  **CMIS now persists its issuer signing key across restarts.** The bring-up
  path minted a fresh in-memory composite key on every boot (`Issuer::generate`),
  so a CMIS restart rotated the JWKS key out from under every consumer: issued
  SVIDs, the allowlist a MIA had adopted, and the published CRL all failed
  signature verification, and MIAs fell back to denying callers (`crl-stale`).
  CMIS now loads a persisted 32-byte master seed from `CMIS_ISSUER_KEY` (default
  `/var/lib/ferrogate/issuer/issuer.seed`, `0600`), generating and storing one
  on first run, and rebuilds the issuer deterministically via `Issuer::from_seed`.
  `CMIS_ISSUER_KID` / `CMIS_TRUST_DOMAIN` override the key id / trust domain.
  The container image pre-creates and persists `/var/lib/ferrogate/issuer` as a
  volume. Only the seed is secret material at rest; the expanded private key
  never touches disk.

- Treat a missing allowlist file as deny-all instead of crash-looping (T70)
  **mia no longer crash-loops when the allowlist file is absent.** With
  `allowlist.path` configured and `allowlist.fetch` on, if CMIS has no allowlist
  for the host and none was ever written to disk, the daemon read the missing
  `allowlist.cbor` as a fatal error and exited — launchd/systemd then restarted
  it every few seconds. The loader now treats a `NotFound` allowlist file as
  deny-all (fail closed) with a warning, matching the documented contract.
  (Present-but-invalid allowlists initially kept failing loudly; the
  deny-all-instead-of-crash entry above extends the same treatment to them.)

- Remove the redundant overwrite prompt when `mia setup` edits an existing file (T129)
  **`mia setup` no longer double-prompts when editing an existing file.** The
  final "Write this configuration to …?" prompt is now the single point of
  consent; the redundant secondary "… exists — overwrite?" prompt (which always
  triggered because the wizard pre-fills from the existing file, and aborted on
  a natural "No") is removed. `--force` now skips the single write confirmation.

#### Reconstructed from git history during the PTF migration

- Persist allowlists, proposals and SVIDs through the Raft store and resume the audit log after a restart instead of wedging it (T155, S7)
  Commit 810cc3c (0.18.0). CMIS lost every per-host allowlist and pending proposal on restart because the
  default single-replica backend kept them in process-local maps; the hiqlite/Raft store is now the only
  backend, and a deployment without `CMIS_CLUSTER_PEERS` runs a one-node cluster under `CMIS_RAFT_DIR`.
  `AuditLog::new` started an empty tree over a non-empty WORM store, so every post-restart append failed
  and CRL publication stopped, leaving MIAs failing closed with `crl-stale`. It now replays persisted
  leaves, **cross-checks the rebuilt root against the newest persisted STH and refuses on mismatch (a
  tampered or forked history)**, and continues at the next free index; audit append/STH failures log at
  ERROR.

- Replicate the CMIS issuer seed through Raft so an HA cluster signs under one identity, and cross-check it in `mia test` (T156, S5)
  Commit 0968c5f (0.19.3). Each node had minted its own seed from a local file, so a load-balanced client
  could fetch an allowlist signed by one node and verify it against another's enrollment key (spurious
  `bad signature`, machine-login denial). The seed now lives in a replicated `issuer_seed` table written
  with insert-or-ignore (exactly one bootstrapper wins); the leader promotes an existing on-disk seed so
  enrolled hosts keep working; `CMIS_ISSUER_KEY` becomes a migration source and a `0600` DR mirror. `mia
  test` dials every SRV node and fails loudly on a split-brain signing identity.

- Move the macOS helper socket to a persistent path so the daemon survives reboots (T136)
  Commit 844ac3c. `/var/run` is cleared at boot on macOS; the socket now lives under
  `/Library/Application Support/FerroGate/run/mia.sock`, and `HelperServer::bind` creates a missing parent
  as `root:<helper gid> 0750` only when it creates it.

- Propose `live ∪ observed` callers so approving a proposal no longer drops operator-added entries (T148)
  Commit eb6f010. On a fetch error the round is skipped rather than proposing a non-additive
  replacement; `ferrogate allowlist review` states the replace-on-approval semantics.

- Apply `FERROGATE_HELPER_SOCKET` only to the default environment when serving all environments (T138)
  Commit b22ed9f (0.19.1).

- Offer allowlist auto-fetch in `mia setup` for SRV deployments too (T158, T129)
  Commit ea3f042 (0.19.2).

- Build the amd64 RPM inside a linux/amd64 container instead of emitting a wrong-arch package (T173, #13)
  Commit 2487a1c (0.15.1). `mia` links the system TPM2 TSS libraries, so cross-compiling from macOS is
  not viable; `scripts/build-rpm-amd64.sh` builds with `libtss2-dev` and passes `-a x86_64`.

- Print the required `--host <uuid>` selector in `ferrogate allowlist` hints (T146)
  Commit 465bc02.

## [0.15.0] - 2026-06-03

### Added

- Dial CMIS from the `ferrogate` operator CLI over hybrid-PQC TLS with SPKI pinning (T125)
  **F01 hybrid-PQC TLS in the `ferrogate` operator CLI.** The CLI can now dial
  CMIS over the hybrid-PQC TLS transport with SPKI pinning, closing the gap that
  left the in-container CLI broken once CMIS terminates TLS by default.
  - An `https://` endpoint is dialed over TLS 1.3 / `X25519MLKEM768`-only and
    authenticated by SPKI pin (not a CA chain); `http://` (or a bare authority)
    keeps the plaintext dev/bring-up path unchanged.
  - New `--spki-pin <hex>` (repeatable) / `$FERROGATE_CMIS_SPKI_PIN`
    (comma-separated) and `--tls-cert <path>` / `$FERROGATE_CMIS_TLS_CERT`
    flags. Pin resolution precedence: explicit pins → first certificate of the
    server-cert PEM (defaulting to `/etc/ferrogate/tls/cmis.crt`, the path the
    `puppet-ferrogate` module mounts) → a clear error. So
    `ferrogate --endpoint https://127.0.0.1:8443 status` works inside the cmis
    container with no extra flags.

- Add the `ferro-transport` crate holding the shared pinned client dialer (T126)
  **New `ferro-transport` crate.** The client-side pinned dialer (formerly the
  body of `mia::client::connect_pinned`) now lives in
  `ferro_transport::connect_pinned`, returning a bare tonic `Channel`. It is
  shared by the MIA agent and the `ferrogate` CLI, keeping
  `ferro-crypto::transport` free of tonic/tokio-rustls and avoiding a `mia`
  dependency in the CLI. `mia::client::connect_pinned` delegates to it; MIA
  behaviour and its `tls_transport.rs` tests are unchanged.

### Changed

- Document the CLI's TLS support in `docs/transport-tls.md` (T124, T125)
  `docs/transport-tls.md` documents the CLI's TLS support (endpoint scheme,
  pin-resolution precedence, the in-container zero-config default) and notes the
  earlier plaintext-only caveat is resolved; the code map and troubleshooting
  tables gained CLI / `ferro-transport` rows.

## [0.14.0] - 2026-06-03

### Added

- Add the transport security guide `docs/transport-tls.md` (T124, S36)
  **Transport security documentation.** New
  [docs/transport-tls.md](docs/transport-tls.md): how the F01 hybrid-PQC TLS
  transport works (TLS 1.3, `X25519MLKEM768`-only, SPKI pinning, ALPN h2, code
  map) and how to configure it end to end — `CMIS_TLS_CERT` / `CMIS_TLS_KEY`,
  generating a server cert, the OpenSSL SPKI-pin recipe, `connect_pinned`
  usage, telemetry/verification, certificate + pin rotation, and
  troubleshooting. Linked from the sidebar and cross-referenced from the
  operations, crypto, cmis, mia, and networking docs.

### Changed

- Reformat the workspace with `cargo fmt` so `cargo fmt --check` passes (T178)
  Reformatted the workspace with `cargo fmt` so `cargo fmt --check` passes
  cleanly (no behavioural change).

## [0.13.4] - 2026-06-03

### Added

- Wire F01 hybrid-PQC TLS into the live gRPC transport on both CMIS and MIA (T119, T120, T121, T122, T123)
  **F01 hybrid-PQC TLS on the live gRPC transport.** The `ferro-crypto`
  hybrid-PQC provider and SPKI-pin verifier are now wired into the actual
  transport on both sides, closing the seam flagged in F04's status note.
  - New `ferro_crypto::transport` module with shared rustls config builders
    `server_config` / `client_config` (TLS 1.3 only, `X25519MLKEM768`-only,
    ALPN `h2`), plus `is_hybrid_group` / `group_label` telemetry helpers.
  - `cmis::transport::tls_incoming` terminates TLS via a `tokio_rustls` accept
    loop and feeds handshake-complete connections to tonic's
    `serve_with_incoming`; logs the negotiated key-exchange group per accepted
    connection. The `cmis` binary enables TLS when `CMIS_TLS_CERT` +
    `CMIS_TLS_KEY` are set, falling back to the plaintext bring-up server
    (dev-only, loud warning) otherwise.
  - `mia::client::connect_pinned` dials CMIS over a custom `tokio_rustls`
    connector with SPKI pinning; a non-hybrid or wrong-pin server is rejected
    before any RPC.
  - Tests: `crates/mia/tests/tls_transport.rs` (pinned-hybrid JWKS over the
    live listener, legacy non-PQC client rejected, wrong-pin rejected) and the
    `transport_builders_negotiate_the_hybrid_group` handshake test.
  - Operator guidance in [docs/operations.md](docs/operations.md) §"Transport
    security (hybrid-PQC TLS)".

### Changed

- Enable tonic's `tls` feature and add the transport glue dependencies (T119, T120)
  Enabled tonic's `tls` feature and promoted `tokio-rustls` to a regular
  dependency of `cmis`/`mia`; added `hyper-util`, `tower`, and `rustls-pemfile`
  workspace dependencies for the transport glue.

## [0.13.3] - 2026-06-03

### Abandoned

- Abandon native S3 / object-storage sourcing and the S3 Object Lock WORM store: artefacts live at local paths and the sync path is untrusted (T98, T94, T66)
  **S3 / object-storage support is dropped and will not be implemented.**
  Documented as a new "Dropped scope" section in
  [docs/roadmap.md](docs/roadmap.md): native S3 sourcing (RIM bundles, fleet
  manifests) and the S3 Object Lock WORM store are removed from all future
  tasks. Every artefact is read from / written to a local file or directory;
  a deployment that keeps artefacts in object storage syncs them to the local
  path out of band, and because each is composite-signed (RIM, fleet manifest)
  or write-once via `O_CREAT|O_EXCL` (`LocalDiskWormStore`), that sync path is
  untrusted. The `AuditStore` / loader trait seams stay open for an
  out-of-tree adapter, but no object-store impl is a FerroGate deliverable.
  Updated the roadmap, design docs (architecture, audit, threat-model,
  networking, cmis, operations), the F07/F10/F13 feature docs, and the
  corresponding source doc-comments to match.

## [0.13.2] - 2026-06-02

### Added

- Add a Release workflow that publishes the `mia` packages and the integration SDK on `releases/**` tags (T172)
  **Release pipeline.** A `Release` GitHub Actions workflow now fires on
  `releases/**` tags and publishes the mia `.deb` and `.rpm` packages plus a
  `ferrogate-sdk-rust-<version>.tgz` integration SDK to the GitHub Release.
  New `make release` / `make pkg-sdk` targets build the same artifacts locally;
  the SDK bundles the verifier-side crates (`ferro-proto`, `ferro-svid`,
  `ferro-svid-verify`, `ferro-child-verify`, `ferro-attest`, `ferro-crypto`)
  as a self-contained Cargo workspace.

### Removed

- Remove the standalone CI workflow `.github/workflows/ci.yml` (T4)
  The standalone `CI` workflow (`.github/workflows/ci.yml`).

## [0.13.1] - 2026-06-02

### Added

- Report the `ferrogate` CLI version with `-V`, `--version` or the `version` subcommand (T118)
  **`ferrogate -V` / `--version`.** The operator CLI now reports its version
  (sourced from the workspace `CARGO_PKG_VERSION`) via `-V`, `--version`, or
  the `version` subcommand.

## [0.13.0] - 2026-06-02

Operator CLI. Pre-migration heading: `[0.13.0] — 2026-06-02 — Operator CLI`.

### Added

- Turn `crates/ferrogate-cli` into the `ferrogate` operator CLI over the `MachineIdentity` admin RPCs (T115)
  **`crates/ferrogate-cli` — the `ferrogate` operator CLI.** The former
  ironroot scaffold is now a real admin tool: a thin gRPC client over the
  existing `MachineIdentity` admin surface. Subcommands map one-to-one onto
  RPCs CMIS already exposes — `status` → `Health`, `list-svids` → `ListSvids`,
  `revoke-svid` → `RevokeSvid`, `revoke-host` → `RevokeHost`, `bump-epoch` →
  `BumpEpoch`. Targets the local CMIS by default
  (`http://127.0.0.1:8443`), overridable with `--endpoint` /
  `FERROGATE_CMIS_ENDPOINT`.

- Add the `ListSvids` admin RPC enumerating issued SVIDs (T116)
  **`ListSvids` RPC.** New admin RPC enumerating issued SVIDs (local store on a
  single replica, the full replicated set when clustered). Each `SvidSummary`
  carries the `cert_sha` an operator can feed straight into `RevokeSvid`.

#### Reconstructed from git history during the PTF migration

- Package the `mia` client as deb, rpm, msi and macOS pkg installers and drop `mia` from the container image (T171)
  Commit c582a82: `pkg-deb` (cargo-deb), `pkg-rpm` (cargo-generate-rpm), `pkg-msi` (cargo-wix),
  `pkg-macos` (pkgbuild/productbuild), `pkg` and `pkg-tools` Makefile targets; packaging metadata lives in
  `crates/mia/Cargo.toml`.

### Changed

- Bundle the `ferrogate` CLI in the server container image (T117)
  **Container image bundles the `ferrogate` CLI.** `docker/ferrogate.Dockerfile`
  now builds and ships the `ferrogate` binary alongside the `cmis` server, so an
  operator can `docker exec <container> ferrogate status` and drive the admin
  RPCs against the local CMIS. `mia` remains a host-side package, not shipped in
  the image.

## [0.12.1] - 2026-06-01

Reconstructed during the PTF migration from tag `v0.12.1` (commit d13bb17); the pre-migration changelog had no section for this release.

### Added

- Add `make docker-image` building a non-root linux/amd64 server image (T168)
  Commit 47087db. Multi-stage build of `cmis` and `mia` into a small runtime image (uid/gid 10001); the
  entrypoint tees server output to a mountable log volume; the CMIS audit WORM store is a volume; the
  image tag derives from the workspace version.

- Serve the documentation as a Docsify site with `make docs` (T169)
  Commit 990946e: `docs/index.html` with search and highlighting, a grouped `docs/_sidebar.md`,
  `docs/.nojekyll` and `serve-docs.sh`.

- Record ADR-0001 (gRPC over HTTP/REST for the control plane) and the networking and firewall requirements (T170, S20, S35)
  Commit 4b6bb95 adds `docs/adr/0001-grpc-over-http-transport.md` and `docs/networking.md`.

- Enable Dependabot for weekly cargo and GitHub Actions dependency updates (T177)
  Commit c0a4e0f; its message notes that repository Actions were disabled at the time.

### Changed

- Describe hiqlite instead of FoundationDB as the CMIS Raft store across the design docs (T52)
  Commit 629d086 updates architecture, cmis, audit, F05 and F07 docs.

### Abandoned

- Drop the FoundationDB audit mirror: the replicated copy lives in the hiqlite-backed state machine (T51)
  Commit 629d086 removed the stale "M4 FoundationDB mirror" note from `ferro-audit` `store.rs` and
  updated `docs/audit.md` / F07; the 0.4.0 entry had said the mirror would arrive in M4.

## [0.12.0] - 2026-06-01

Reconstructed during the PTF migration from tag `v0.12.0` (commit 5036d1a); the pre-migration changelog had no section for this release.

### Added

- Add the region-loss, mass-revocation and quorum-loss recovery drills with repeatable rehearsal harnesses (T108, T109, T110)
  Commit 5036d1a. Each drill is a documented runbook (pre-flight → procedure → pass criteria → abort)
  under `docs/operations/drills/` plus a harness under `scripts/drills/` that exercises the real in-process
  subsystems; the region-loss harness was executed (`cluster_e2e`: 4 passed / 1 ignored, 104 s).

- Add SRE runbooks for the STH-lag, CRL-stale and key-share-failure alerts (T111)
  `docs/operations/runbooks/`; thresholds are quoted from the code.

- Add the Tamarin model of the four-phase attestation protocol and the CryptoVerif model of the hybrid AKE (T112, T113, S47)
  `formal/tamarin/attestation.spthy` and `formal/cryptoverif/hybrid_ake.cv`.

- Add the `formal-verification` CI job and `make formal` targets with a 600 s per-proof budget (T114)
  The job installs both provers and fails on any falsified lemma or unproved query; `make formal` skips
  gracefully when the provers are absent. Wired into `docs/operations.md`.

## [0.11.0] - 2026-06-01

Root key ceremony and rotation. Pre-migration heading: `[M6.0] — 2026-06-01 — Root key ceremony and rotation (v0.11.0)`. Not tagged in git.

**Verification.** `cargo test --workspace` (15 `ferro-ceremony` unit tests across media/crosssign/minutes/destruction; the 2 `offline-signer` CLI integration tests including the end-to-end `dry-run`; the `cmis` `root_rotation` integration test) and `cargo clippy --workspace --all-targets`, alongside the existing F01–F13 suites.

### Added

#### F14: Root key ceremony and rotation

- Add the air-gapped `ferro-ceremony` library for sealed media, cross-signing, signed minutes and destruction (T101, T102, T105, T104, S14)
  **`crates/ferro-ceremony` — air-gapped ceremony library.** New
  `#![forbid(unsafe_code)]` crate holding the offline primitives the ceremony
  tool wires together. None of it touches the network; every artefact is
  auditable JSON.
  - `media` — **sealed transport media**. `SealedShareSet::seal` reuses the
    `ferro-tee` 3-of-5 GF(2⁸) Shamir split of the 32-byte root seed and wraps
    each share in a `SealedShare` envelope: a `SHA3-256` tamper-evidence tag
    over the canonical fields (root kid, threshold, index, holder, created-at,
    share bytes), one per holder. `combine` reconstructs into a `Zeroizing`
    buffer after checking every envelope's integrity and that they agree on
    root/threshold/total. Confidentiality rests on the threshold plus physical
    custody — the envelope is integrity + labelling, not encryption (the online
    F06 `ferro_tee::seal` path is where shares are measurement-bound).
  - `crosssign` — **both directions**. `CrossSignBundle::create` produces
    old-signs-new *and* new-signs-old composite signatures over a
    domain-separated transcript (`ferrogate-root-crosssign-v1`) binding both
    kids, both public keys, and the `[start, start+90d)` window; `verify`
    requires both directions, so a signature can't be lifted onto another key
    pair or replayed into another window.
  - `minutes` — **signed by all participants**. `SignedMinutes` accumulates one
    composite signature per listed `Participant` over the canonical body
    (including artefact `SHA3-256` digests); `verify_all` passes only when every
    participant has signed and rejects signatures from unlisted signers. The
    verified JSON is anchored to the audit WORM medium.
  - `destruction` — **post-zeroization verification**. `destroy_media`
    overwrites a sealed-share medium in place with zeros, `fsync`s, then reads
    it back, failing unless every byte is zero *and* the bytes no longer parse
    as a usable share; returns an auditable `DestructionRecord`.
    `verify_destruction` re-audits a destroyed medium standalone.

- Add the `tools/offline-signer` ceremony CLI with a full staging dry-run (T100, T106)
  **`tools/offline-signer` — the ceremony CLI.** New air-gapped binary with
  `keygen` / `pubkey` / `split` / `combine` / `cross-sign` / `verify-cross` /
  `jwks` / `minutes-new` / `minutes-sign` / `minutes-verify` / `destroy` /
  `verify-destruction` / `dry-run` subcommands, mirroring the `fleet-manifest`
  CLI conventions (`@file` value resolution, `--out`/stdout). `dry-run` runs the
  full eight-step rotation against a scratch directory with five synthetic
  operators — the executable form of the staging dry-run.

- Publish multiple JWKS roots from CMIS with newer-preferred ordering (T103)
  **CMIS JWKS multi-key with "newer preferred" ordering.** `ferro_svid::Jwk`
  carries an optional `x-ferrogate-created` stamp (omitted on the wire when
  unset); `JwkSet::preferred()` — in both `ferro-svid` and the reference
  `ferro-svid-verify` — selects the newest key. `CmisState::register_root_key`
  publishes the incoming root for the cross-sign window, and `published_jwks`
  now orders roots newest-first ahead of the per-host child keys, all still
  resolvable by `kid`. SVID verification is unchanged (still by header `kid`);
  the ordering only affects trust-anchor choice during the window.

- Add the root key ceremony operations runbook (T107, T106, S38)
  **Operations runbook.** New `docs/operations/root-key-ceremony.md` with the
  step-by-step operator procedure, artefact formats, the destruction read-back,
  failure/recovery notes, and the recorded staging dry-run.

### Postponed

#### Not yet supported

- Postpone online emergency rotation to the backlog: it is deliberately out of F14's scope, a separate off-the-happy-path runbook (T239)
  **Online emergency rotation.** Deliberately out of scope — a separate,
  off-the-happy-path runbook. F14 covers only the planned annual rotation and
  periodic share refresh.

## [0.10.0] - 2026-06-01

RIM epoch bump and signed RIM refresh wiring. Pre-migration heading: `[M5.6] — 2026-06-01 — RIM epoch bump and signed RIM refresh wiring (v0.10.0)`. Not tagged in git.

### Added

#### F10 (continued): RIM and PCR policy

- Add the `BumpEpoch` admin RPC that forces full re-attestation and records `PolicyEpochBumped` (T99)
  **`BumpEpoch` admin RPC.** New `MachineIdentity` RPC that advances the live
  RIM policy epoch. `CmisState` now holds the epoch in an `AtomicU64` (seeded
  from `CmisConfig::policy_epoch`); `current_epoch` / `bump_epoch` replace the
  frozen `config.policy_epoch` at the issuance and `Rotate` decision points. A
  bump forces every host attested under the previous epoch through a full
  four-phase re-attestation on its next `Rotate` (`FAILED_PRECONDITION` via
  `decide_renewal`'s `EpochBump` branch), and records a new `PolicyEpochBumped`
  audit event (`old_epoch`, `new_epoch`, bounded reason opcode).

- Wire signed RIM refresh into CMIS from a local bundle file, fail-closed at startup (T97)
  **Signed RIM refresh wired into CMIS.** `RimLoader` + `rim_watcher` (built in
  M2 but never spawned) are now started from `cmis` `main` behind
  `CMIS_RIM_BUNDLE` + `CMIS_RIM_SIGNER_KID` / `CMIS_RIM_SIGNER_PUB`, sharing one
  `RimStore` with the quote verifier. Startup is fail-closed (a configured but
  unloadable bundle aborts); with nothing configured the allowlist is empty and
  every quote fails the RIM lookup. The trust-from-env helper is now shared with
  the F13 fleet-manifest loader.

### Postponed

#### Not yet supported

- Postpone S3-sourced RIM refresh: no HTTP/S3 client is pulled into the workspace and the signed bundle loads from a local file (T98)
  **S3-sourced RIM refresh.** Fetching the bundle directly from S3 is
  deliberately out of scope for now — no HTTP/S3 client is pulled into the
  workspace. The bundle loads/hot-reloads from a local file; deployments sync it
  from object storage out of band, and the composite signature (verified before
  apply) is the only trust gate. A native fetcher can slot in behind the same
  seam later.

## [0.9.0] - 2026-06-01

Zero-touch bootstrap and fleet enrollment. Pre-migration heading: `[M5.5] — 2026-06-01 — Zero-touch bootstrap and fleet enrollment (v0.9.0)`. Not tagged in git.

### Added

#### F13: Zero-touch bootstrap and fleet enrollment

- Define the composite-signed fleet manifest format (T92)
  **Fleet manifest format (`cmis::fleet_manifest`).** `FleetManifest` enumerates
  the SHA-384 of every approved EK certificate; it is only ever applied as a
  `SignedFleetManifest` — a composite (Ed25519 + ML-DSA-65) signature over the
  manifest's canonical JSON under the new `ferrogate-fleet-v1` domain context,
  carried by a trusted publisher key. Mirrors the F10 `SignedRimBundle` shape.

- Add the live enrolment store and a verify-then-swap manifest loader (T93)
  **Live enrolment store + loader.** `EnrolledHosts` is the lookup-optimised
  (48-byte hash set) resolution of a manifest; `FleetStore` holds it behind an
  `RwLock<Arc<…>>` so a refresh swaps the `Arc` under the write lock and an
  in-flight `Attest` that took a snapshot sees a consistent set for the whole
  handshake. `FleetManifestLoader` reads, verifies, and hot-swaps a strictly
  newer manifest; `fleet_watcher::spawn` polls it. The signed-S3 refresh reuses
  the loader's verify-then-swap path.

- Check enrollment in `Attest` before any TPM quote verification (T95)
  **Pre-admission lookup in `Attest`.** `CmisState::check_enrollment` runs on
  the phase-2 EK-cert hash *before* any TPM quote verification. With no manifest
  configured it is a no-op (every host admitted, as before F13); once a manifest
  is loaded an un-enrolled host is refused at the cheapest possible point.
  `cmis` `main` loads `CMIS_FLEET_MANIFEST` fail-closed (a configured-but-broken
  manifest aborts startup) using `CMIS_FLEET_SIGNER_KID` / `CMIS_FLEET_SIGNER_PUB`.

- Add the `HostEnrolled` and `HostRejected` audit events (T96)
  **Audit events `HostEnrolled` / `HostRejected`** added to
  `ferro_audit::AuditEvent` (EK hash plus, for rejection, a stable opcode).

- Add the offline `fleet-manifest` CLI with seed-derived publisher keys (T92)
  **`fleet-manifest` CLI (`tools/fleet-manifest`).** Offline tool with
  `keygen`/`new`/`add`/`remove`/`sign`/`verify`/`show`. The publisher key is
  derived deterministically from a 32-byte master seed, so only the seed is
  secret at rest — backed by the new `CompositeSecretKey::from_seed` in
  `ferro-crypto` (independent SHA3-keyed sub-seeds for the two halves; the
  expanded private key is never serialized). Production root-key handling stays
  the F14 ceremony's job.

## [0.8.0] - 2026-05-29

MIA process hardening. Pre-migration heading: `[M5.4] — 2026-05-29 — MIA process hardening (v0.8.0)`.

### Added

#### F12: MIA process hardening

- Add the `ferro-harden` crate that isolates every privileged hardening syscall (T86, T87, T88, T91)
  **`ferro-harden` crate.** A new Linux-gated FFI crate — the analogue of
  `ferro-winauth` — that isolates every privileged syscall so `mia` stays
  `#![forbid(unsafe_code)]`. It applies, in dependency order:
  `mlockall(MCL_CURRENT|MCL_FUTURE)`, `prctl(PR_SET_DUMPABLE, 0)`, a drop to a
  dedicated UID/GID retaining only `CAP_IPC_LOCK` (via `PR_SET_KEEPCAPS` +
  `setgroups`/`setgid`/`setuid` + bounding/effective/permitted/ambient
  restriction), `prctl(PR_SET_NO_NEW_PRIVS, 1)`, and a seccomp-bpf **allow-list**
  (`seccompiler`) defaulting to `SECCOMP_RET_KILL_PROCESS`. The allow-list is an
  explicit ~70-name set resolved to per-architecture numbers (x86_64 + aarch64;
  unknown names skipped for portability). Helpers: `resolve_user`, `is_root`,
  `effective_capabilities`.

- Harden `mia` on the startup thread before the runtime starts, behind a fail-closed IMA check (T89, T88)
  **MIA hardening orchestration (`mia::hardening`).** `harden()` runs the
  fail-closed IMA check (refuses to start unless `/proc/cmdline` carries
  `ima_appraise=enforce`) then drives `ferro_harden::apply`, and verifies the
  post-drop effective capability set is exactly `{CAP_IPC_LOCK}`. `main` was
  restructured from `#[tokio::main]` to a plain `main` that hardens on the
  startup thread *before* building the runtime, so the seccomp filter is
  inherited by tokio workers and `MCL_FUTURE` covers their allocations.

- Add dev and rollout toggles for seccomp mode, IMA, the run-as user and skipping hardening (T87, T89)
  **Dev/rollout toggles.** `FERROGATE_SECCOMP=enforce|audit|off` (audit =
  log-only, to discover allow-list drift), `FERROGATE_REQUIRE_IMA=0`,
  `FERROGATE_RUN_AS_UID/GID`, `FERROGATE_SKIP_HARDENING=1`.

- Add a reproducible-build script and CI job asserting byte-identical `mia` binaries (T90)
  **Reproducible build.** `scripts/reproducible-build.sh` builds `mia` twice with
  path remapping, `--build-id=none`, and pinned `SOURCE_DATE_EPOCH`/locale/TZ,
  and asserts byte-identical binaries, printing the `bin_sha384`. A new
  `reproducible-build` CI job runs it.

- Add the `no-unsafe-in-mia` CI gate (T91)
  **CI `no-unsafe-in-mia` gate.** Greps `crates/mia/src` for unsafe constructs as
  a belt-and-suspenders backstop to `#![forbid(unsafe_code)]`.

- Test the enforcing seccomp filter live, the per-arch syscall resolution and the IMA parser (T87, T89)
  **Tests.** `ferro-harden` carries a live seccomp self-test that forks, installs
  the enforcing filter, calls a forbidden syscall, and asserts the child died
  from `SIGSYS`; plus per-arch syscall-name resolution and BPF-build tests. The
  IMA cmdline parser is unit-tested in `mia::hardening`. The Linux paths are
  exercised in the `rust:1.88-bookworm` container (CI runs them natively).

### Postponed

#### Notes

- Postpone static-PIE musl packaging with static TSS2 as deployment work: the reproducibility gate runs on the PIE glibc build (T238)
  Static-PIE musl packaging (statically linking TSS2) is left as deployment
  work; the reproducibility gate runs on the glibc build, which is PIE by
  default. The `effective_capabilities == {CAP_IPC_LOCK}` and privilege-drop
  paths require root and are exercised in privileged deployment, not unprivileged
  CI.

## [0.7.0] - 2026-05-29

Revocation and CRL distribution. Pre-migration heading: `[M5.3] — 2026-05-29 — Revocation and CRL distribution (v0.7.0)`.

### Added

#### F11: Revocation and CRL distribution

- Add the composite-signed CRL data model with self-expiring entries (T85, T82)
  **CRL data model (`ferro-svid::crl`).** A composite-signed `SignedCrl`
  carrying a `CrlBody { issued_at, number, entries }`. Each `CrlEntry` revokes
  either a single SVID by `cert_sha` (lowercase hex `SHA-384` of the compact
  JWS) or a whole host by SPIFFE id, with a stable reason opcode and an
  `expires_at` one max-SVID-TTL out (the "CRL bloat" mitigation — a revoked
  artefact can never reappear once its TTL elapses). The signature covers the
  canonical JSON under a distinct domain-separation context
  (`ferrogate-crl-v1`). `Issuer::sign_crl` signs with the composite issuance
  key; `SignedCrl::verify` is fail-closed (unknown kid, wrong key, or tampered
  bytes never yield the body).

- Carry the latest CRL in the JWKS `x-ferrogate-crl` extension (T83)
  **JWKS `x-ferrogate-crl` extension.** `ferro_svid::JwkSet` gained an optional
  `crl` member, serialised as `x-ferrogate-crl` and omitted when absent, so a
  stock JWKS parser is unaffected. `CmisState::published_jwks` attaches the
  latest published CRL.

- Add the `RevokeSvid` and `RevokeHost` admin RPCs, the revocation store and the 60 s CRL publisher (T81, T82)
  **CMIS revocation store, admin RPCs, and publisher.** `MachineIdentity`
  gained `RevokeSvid(cert_sha, reason)` and `RevokeHost(spiffe_id, reason)`.
  Each validates and records the revocation, appends a `SvidRevoked` /
  `HostRevoked` audit event, and republishes a fresh signed CRL inline so the
  change lands within one publish cycle. `crates/cmis/src/crl_publisher.rs`
  is the 60 s heartbeat that keeps `issued_at` fresh (and prunes expired
  entries) between revocations; wired into the CMIS binary.

- Gate every child-token mint in MIA on a fresh, verified CRL (T84, T85)
  **MIA freshness gate and CRL cache (`mia::helper::crl`).** A `CrlCache`
  holding the most recently *verified* CRL body, a puller
  (`spawn_puller` / `refresh_once` / `ingest`) that pulls the CRL from the CMIS
  `JWKS` RPC and verifies its signature fail-closed before caching, and a gate
  consulted on every child-token mint: a missing or stale (> 5 min) CRL refuses
  with `CrlStale`, and a CRL that revokes this host (by parent SVID `cert_sha`
  or by SPIFFE id) refuses with `permission_denied`. The gate runs before
  allowlisting, so a revoked host cannot mint even if otherwise permitted. Every
  refusal emits exactly one `LocalDenied` audit event.

- Add revocation support to the `ferro-svid-verify` reference verifier (T85)
  **Reference-verifier revocation support (`ferro-svid-verify`).** A new
  `verify_unrevoked` re-declares the CRL schema (staying self-contained),
  verifies the CRL signature against the JWKS keys, requires a fresh CRL (fail
  closed: absent/stale ⇒ `CrlStale`, bad signature ⇒ `CrlInvalid`), and rejects
  a revoked SVID (`Revoked`).

- Add the `HostRevoked` audit event (T81)
  **Audit.** Added the `HostRevoked { spiffe_id, reason }` event alongside the
  existing `SvidRevoked`.

- Test revocation end to end across CMIS, the reference verifier and the MIA mint gate (T81, T84, T85)
  **Tests.** `crates/cmis/tests/revocation.rs` drives the admin RPCs through to
  the published JWKS CRL, asserts audit growth, and proves a revoked SVID is
  rejected by the reference verifier after propagation;
  `crates/ferro-svid/tests/verify_roundtrip.rs` proves the CMIS-signed CRL
  verifies under the independent verifier across the crate boundary (canonical
  JSON match), with revoked-by-cert / revoked-by-host / stale / absent / tampered
  cases; `crates/mia/tests/helper_api.rs` covers the stale / missing / revoked
  mint refusals; plus unit tests in `ferro-svid` and `mia` for fail-closed
  verification.

### Postponed

#### Deferred (deployment seams)

- Postpone replicating the revocation working set through Raft: it is deployment wiring on the `CmisState::revoke` seam (T223)
  The CMIS revocation working set is process-local; replicating it through the
  Raft store so every replica's CRL agrees is wiring on the existing
  `CmisState::revoke` seam (mirrors the F09 process-local JWKS registry note).

- Postpone wiring the MIA CRL puller until the attestation loop supplies the host SVID; until then minting fails closed (T160)
  The MIA CRL puller is wired by the attestation loop that supplies the host
  SVID (not yet landed); until then the daemon runs with an empty cache and so
  refuses to mint (fail closed).

## [0.6.0] - 2026-05-29

DPoP child-token verification. Pre-migration heading: `[M5.2] — 2026-05-29 — DPoP child-token verification (v0.6.0)`.

### Added

#### F09: DPoP-bound child tokens (completion)

- Add the `ferro-child-verify` Rust reference verifier with the RFC 9449 DPoP binding (T78, T80)
  **`ferro-child-verify` crate.** A self-contained Rust reference verifier for
  the DPoP-bound, composite-signed child tokens minted by the helper API. It
  re-declares the wire schema, validates the composite (Ed25519 + ML-DSA-65)
  signature against a CMIS JWK set, and enforces `exp`. `verify_bound` adds the
  RFC 9449 sender constraint: the caller must present a DPoP proof JWS whose
  RFC 7638 key thumbprint equals the token's `cnf.jkt`, and that proof must
  itself verify and match the HTTP request (`htm`/`htu`, freshness). A token
  presented with **no** DPoP proof is rejected (`MissingDpopProof`) — a captured
  bearer token cannot be replayed without the DPoP private key. DPoP proofs use
  Ed25519 (`alg = "EdDSA"`, OKP `jwk`).

- Publish a multi-key JWKS that includes each host's child-token signing key (T77)
  **Multi-key JWKS on CMIS.** `CmisState` now publishes a set of verification
  keys — the issuer's SVID key plus each host's composite child-token signing
  key, registered at phase-4 attestation under a deterministic key id
  (`ferro_svid::child_signing_kid`, shared with the MIA minter so the two sides
  never coordinate a name out of band). The `JWKS` RPC serves the merged set.
  The registry is process-local (a verifier must reach a replica that has seen
  the host's attestation); cluster-wide publication is a documented follow-up.

- Test the child-token verifier against the real minter and the replay and tampering cases (T80, T77)
  **Tests.** `ferro-child-verify` unit tests cover the happy path, the no-proof
  replay rejection, thumbprint/request/freshness mismatches, expiry, unknown
  kid, and tampered/wrong-key signatures. `crates/mia/tests/child_token_verify.rs`
  round-trips the *real* `ChildTokenMinter` through the independent verifier, and
  `crates/mia/tests/e2e_attest.rs` asserts the host child-signing key is
  published in the JWKS after a full attestation.

### Postponed

#### Derived from the legacy roadmap during the PTF migration

- Postpone cluster-wide publication of per-host child-token keys: the JWKS registry stays process-local until `composite_pub` is persisted (T159)
  From the legacy roadmap's F09 status note: a verifier must reach a replica that has seen the host's
  attestation; making the registry cluster-wide means persisting `composite_pub` in the issued-SVID store.

### Abandoned

#### Scoped out

- Drop the Go reference verifier: the Rust crate is the canonical interop target (T79)
  The originally-planned **Go** reference verifier is dropped: the Rust crate is
  the canonical interop target and no second-language verifier ships in-tree.

## [0.5.0] - 2026-05-29

Windows Named Pipe helper transport. Pre-migration heading: `[M5.1] — 2026-05-29 — Windows Named Pipe helper transport (v0.5.0)`.

### Added

#### F08: Windows Named Pipe transport for the helper API

- Add the `ferro-winauth` crate as the Windows FFI boundary for caller attestation (T74)
  **`ferro-winauth` crate.** The Windows FFI boundary for caller attestation,
  kept separate so `mia` stays `#![forbid(unsafe_code)]` (the crate has no
  dependency on `mia`, so there is no cycle). Safe wrappers over
  `GetNamedPipeClientProcessId` (client PID), `QueryFullProcessImageNameW`
  (image path), the token user SID's RID (the Windows analogue of a uid),
  `WinVerifyTrust` (Authenticode / Code-Integrity, the IMA-cross-check
  analogue), and named-pipe creation with an optional group-restricted DACL.

- Share one transport-agnostic helper pipeline between the UDS and Named Pipe listeners (T74)
  **Transport-agnostic server pipeline.** `helper::server` is refactored so the
  request pipeline (`serve_connection` over any `AsyncRead + AsyncWrite`,
  authenticate → authorize → mint → audit) is shared, with a Unix Domain Socket
  listener (`server::unix`) and a Windows Named Pipe listener
  (`server::windows`). The cheap credential step runs on the async side; the
  authenticator's blocking work runs on the blocking pool on both platforms.

- Authenticate Windows callers with `WindowsCallerAuth` over a DACL-restricted named pipe (T74)
  **`WindowsCallerAuth`.** Composes the `ferro-winauth` primitives (plus
  `sha2` image hashing on the safe side) into a `CallerIdentity`; new
  `AuthError::ImageUnreadable` / `Untrusted` opcodes describe Windows failures.
  The pipe binds `\\.\pipe\ferrogate-mia` with an optional `FerroGateClients`
  DACL (`HelperServerConfig::windows_group`).

- Add Windows cross-build tooling for compile and clippy checks (T75)
  **Cross-build tooling.** `docker/win-cross.Dockerfile` + `scripts/win-cross.sh`
  compile- and clippy-check the `x86_64-pc-windows-gnu` target from a
  Linux/macOS host (Windows tests cannot run here; the shared pipeline is
  covered by the Unix integration tests).

## [0.4.0] - 2026-05-29

Local helper API and DPoP child tokens. Pre-migration heading: `[M5] — 2026-05-29 — Local helper API and DPoP child tokens (v0.4.0)`. This first tagged release also carries the legacy M3 and M4 work (F05, F06, F07): the workspace was bumped to 0.3.0 at commit 935fe43, but 0.3.0 was never tagged or given a section.

### Added

#### F08: Local helper API (with the F09 child-token minter)

- Add the `mia::helper` local IPC channel for vetted host applications (T67, S8)
  **`mia::helper` module.** A local IPC channel over which vetted host
  applications request short-lived, audience-bound, DPoP-bound child tokens.
  Caller identity is derived from kernel-attested sources, never from anything
  the caller claims.

- Frame helper requests as length-delimited CBOR bounded to 64 KiB (T68)
  **`helper::proto`.** CBOR request/response (`HelperReq` / `HelperResp` /
  `ChildToken` / `ErrorCode`) with length-delimited framing — a 4-byte
  big-endian length bounded by `MAX_FRAME_LEN` (64 KiB), so a hostile prefix
  cannot make the MIA allocate without limit.

- Add caller authentication with the IMA cross-check that catches post-exec binary swaps (T69)
  **`helper::auth`.** The `CallerAuth` trait and `CallerIdentity` it produces,
  plus the pure `cross_check_ima` parser: an on-disk `SHA-384(/proc/<pid>/exe)`
  must equal the IMA-measured runtime hash for the same path, so a post-exec
  symlink/file swap is caught (`MismatchOutcome::Mismatch`). The Linux
  `ImaCallerAuth` (`SO_PEERCRED` + IMA log) is compiled only on Linux; the
  trait, identity type, and cross-check are portable and unit-tested anywhere.

- Add the fail-closed signed allowlist loader (T70)
  **`helper::allowlist`.** A fail-closed signed loader. The on-disk artefact is
  a CBOR `SignedAllowlist` (canonical-CBOR `AllowlistDoc` body + detached
  composite signature over those bytes under `ferrogate-allowlist-v1`).
  Verification happens before the body is parsed; freshness (`now ∈
  [issued_at, not_after]` and a max-age bound on `issued_at`) is enforced on
  load. Any failure yields no usable allowlist, denying every caller.

- Add the F09 `ChildTokenMinter` for DPoP-bound, audience-bound child tokens (T76)
  **`helper::token` (feature F09 minter).** `ChildTokenMinter` mints a compact
  JWS (`typ = "ferrogate-child+jwt"`, `alg = "MLDSA65+Ed25519"`) signed with
  the host composite SVID key under the distinct context
  `ferrogate-child-token-v1`. TTL is clamped to ≤ 600 s, `jti` is a fresh
  128-bit value, `cnf.jkt` carries the caller DPoP thumbprint, and a
  `ferrogate` block records `parent_svid` / `actor_pid` / `actor_uid` /
  `actor_bin`.

- Add the UDS helper server with bounded concurrency, read deadlines and one audit event per request (T67, T72, T71)
  **`helper::server`.** A Unix-domain-socket listener (Unix only) created with
  the configured mode (default `0o660`) and optional group owner. The accept
  loop spawns one task per connection bounded by a `Semaphore`, with a
  per-connection read deadline so a slow/idle client releases its permit
  promptly and cannot starve well-behaved callers. `SO_PEERCRED` is read on the
  async side (`CallerAuth::identify` takes a `PeerCred` value), and the
  authenticator's blocking IMA / `/proc` reads run on the blocking pool so they
  never stall a runtime worker. Every decoded request produces exactly one
  audit event (`LocalGrant` / `LocalDenied`) pushed onto an `mpsc` channel for
  the `audit_client` forwarder to drain to CMIS.

- Start the helper API from the `mia` daemon with minting disabled until a host SVID exists (T73)
  **Daemon wiring (`mia` binary).** The daemon now starts the helper API when
  `FERROGATE_HELPER_SOCKET` is set (Linux): it loads/verifies the signed
  allowlist (`FERROGATE_ALLOWLIST` + `FERROGATE_ALLOWLIST_KEY`), binds the
  socket with `FERROGATE_HELPER_SOCKET_MODE` (default `660`), uses the real
  `ImaCallerAuth`, drains audit events to the log, and serves until
  `SIGINT`/`SIGTERM`. Token minting stays disabled (`no_host_svid`) until the
  attestation loop supplies the host SVID key — a fail-safe surface for
  verifying socket permissions, caller attestation, and the allowlist in
  production ahead of minting.

- Test every F08 acceptance criterion with unit and socket-level integration tests (T67, T69, T70, T71, T72)
  **Tests.** 23 lib unit tests and 9 socket-level integration tests covering
  every F08 acceptance criterion: `0o660` socket mode (via `stat`), IMA
  swap rejection, allowlist-absent and not-allowlisted denial, well-formed
  grant, signature fail-closed (wrong key / tampered body / garbage / expired /
  too-old), exactly-one-audit-event per request, and slow-client
  non-starvation. The minted token's composite signature verifies under the
  host key (what a downstream JWKS verifier does).

#### F07 continued: Sigsum / Rekor anchor publisher with back-fill (M4 subset)

- Add the `ferro_audit::anchor` transparency-log publisher with persistent back-fill (T65)
  **`ferro_audit::anchor` module.** A transparency-log publisher with
  persistent back-fill so an upstream outage cannot silently drop anchors.
  The `Anchor` trait abstracts the log family (Sigsum, Rekor v1/v2, …); a
  driver's only contract is `submit(&CoSignedTreeHead) -> Result<AnchorReceipt,
  AnchorError>` with a `Transient` (retry) vs. `Permanent` (quarantine)
  error taxonomy. The HTTP wire for each log lives behind this trait and is
  part of the operator's deployment config.

- Persist pending, published and quarantined anchors in a disk-backed `AnchorQueue` (T65)
  **Disk-backed `AnchorQueue`.** Pending STHs land under
  `pending/<tree_size:020>.{sth.json,enq}` (the `.enq` marker carries the
  first-enqueue Unix-seconds timestamp); successful submissions land under
  `receipts/<tree_size:020>.json`; permanent failures move to
  `dead/<tree_size:020>.{sth.json,err}`. All writes use `O_CREAT|O_EXCL`, so
  re-enqueueing the same `tree_size` is a deterministic no-op and a
  publisher restart that re-observes the same STH does not lose the
  original backlog age.

- Drain the anchor queue in order, stopping on transient failures and quarantining permanent ones (T65)
  **`AnchorPublisher::drain_once`.** Submits pending entries in `tree_size`
  order. A `Transient` failure stops the drain (so the publisher does not
  hammer an unavailable log); a `Permanent` failure quarantines the entry
  and the drain continues with the rest of the queue. Returns a
  `DrainOutcome { published, transient_failures, quarantined,
  backlog_seconds_after }`. Operators alert on backlog ≥ 5 min, as
  documented in `docs/audit.md` §"Anchor outage".

- Test anchor queue ordering, idempotency, back-fill across restarts and quarantine (T65)
  **Tests.** 7 tests in `anchor`: happy-path enqueue + drain (order
  preserved, receipts persisted); enqueue is idempotent per `tree_size`
  and preserves the original `enqueued_at`; a transient failure makes
  exactly one submit attempt, leaves all entries pending, and the next
  drain (with the anchor flipped to success) catches up entirely; a
  permanent failure quarantines and the drain continues; the queue
  survives reopen from disk (back-fill across a process restart); an
  already-anchored `tree_size` is not re-enqueued; backlog age tracks the
  earliest pending entry.

#### F07 continued: Raft-majority co-signed STHs (M4 subset)

- Add Raft-majority co-signed tree heads verified against a distinct-signer quorum (T64)
  **New `ferro_audit::cosign` module.** `CoSignedTreeHead` carries the same
  canonical CBOR `SthBody` as the single-signer flow plus a `Vec<CoSignature>`
  — one composite (Ed25519 + ML-DSA-65) signature per cluster replica over
  the *identical* `body_cbor` under the existing `ferrogate-sth-v1` domain
  context. `QuorumSigner` composes any number of `SthSigner` trait objects
  and refuses duplicate `signer_kid`s or out-of-range thresholds at build
  time. `verify_cosigned` accepts the artefact iff at least `threshold`
  *distinct* signer kids verify under the keyset: duplicate kids collapse to
  one contribution toward quorum and unknown kids are silently ignored
  rather than failing verification outright, so an attacker who controls
  fewer than threshold listed replicas cannot publish.

- Persist co-signed tree heads write-once in the WORM store (T64)
  **WORM persistence for co-signed heads.** `AuditStore` gains
  `record_cosigned_sth` / `latest_cosigned_sth` (default `Unsupported` so
  existing stores stay valid); `LocalDiskWormStore` persists artefacts under
  `cosigned/<tree_size:020>.json` with the same `O_CREAT|O_EXCL` invariant
  as the single-signer subdir.

- Produce co-signed STHs through a `QuorumSigner` before any external observer sees them (T64)
  **`AuditLog::produce_cosigned_sth`.** Mirrors `produce_sth` but signs
  through a `QuorumSigner` and writes through the new WORM path before any
  external observer sees the head; `latest_cosigned_sth` caches it for
  cheap reads.

- Test co-signing quorum, tampering and duplicate-signer cases (T64)
  **Tests.** 10 new `cosign` tests (3-of-3 happy path; threshold met with
  minority of keys unknown; threshold not met when keys unknown; full body
  tamper kills every signature; single-signature tamper still meets
  quorum=2; duplicate kids cannot inflate quorum; unknown kids ignored;
  invalid threshold refused; duplicate signers refused at build; `as_single`
  extracts a per-replica view) plus end-to-end `AuditLog::produce_cosigned_sth`
  and the WORM round-trip on `cosigned/`.

#### F05 Part 1: CMIS Raft cluster layer (M4)

- Add the `ferro-raft` crate wrapping hiqlite behind a typed `Cluster` API (T52)
  **New crate `ferro-raft`.** Wraps [hiqlite](https://crates.io/crates/hiqlite)
  0.13 (openraft 0.9 + SQLite state machine + WAL on disk) behind a typed
  `Cluster` API: `upsert_svid` / `fetch_svid` / `fetch_svid_consistent` /
  `list_svids` / `delete_svid` / `current_rim_version` / `bump_rim_version`,
  plus `role` / `is_healthy` / `leader_id` for health gating. The schema is
  two idempotent `CREATE TABLE` statements (issued-SVID payloads keyed by
  SPIFFE id; a one-row `rim_state` for the policy epoch). Workspace MSRV
  bumped to 1.88 to match hiqlite's `edition = "2024"` floor.

- Test 3-node election, non-leader loss, follower rejoin and chaos runs (T53, T56)
  **3-node cluster integration tests** (`crates/ferro-raft/tests/cluster_e2e.rs`,
  ≈4 min wall-clock):
  - `three_node_cluster_elects_a_leader_and_replicates`: starts three nodes
    on free localhost ports, asserts every peer agrees on the elected
    leader, writes through the leader, reads from a follower.
  - `killing_a_non_leader_keeps_the_cluster_issuing`: drops a non-leader
    cleanly, asserts the leader id is preserved, and that writes still
    succeed while the surviving 2/3 quorum holds.
  - `follower_rejoin_preserves_replicated_data`: shuts a follower, starts
    a fresh `Cluster` with the same `node_id` + `data_dir`, and asserts
    pre-death rows are observed after rejoin.
  - `short_chaos_run_keeps_serving_while_quorum_holds`: 6 kill+revive
    rounds; every replicated write survives.
  - `ten_minute_chaos_run`: the full 10-minute random-kill loop,
    `#[ignore]`-gated so a beefier CI runner can flip it on with
    `cargo test -- --ignored`.

#### F05 Part 2: CMIS issuance over the cluster (M4)

- Give `CmisState` a cluster backend routed through ferro-raft (T55)
  **`CmisState` gains a cluster backend.** A new `CmisState::new_clustered`
  constructor wires an `Arc<ferro_raft::Cluster>` into the state; `record` /
  `lookup` / `update_bundle` become async and route through
  `Cluster::upsert_svid` / `fetch_svid_consistent` when set, falling back to
  the process-local `HashMap` otherwise. Existing single-replica callers
  (F02/F04/F07/F10 tests, the `cmis` binary) keep working unchanged.

- Replicate issued records through the hex-encoded `WireIssuedRecord` adapter (T55)
  **Wire-type adapter (`cmis::cluster_store`).** A new `WireIssuedRecord`
  with hex-encoded byte fields and JSON serialisation lets us replicate the
  three `[u8; 48]`-bearing `ferro-svid` structs (`IssueParams`,
  `LastAttestation`, `IssuedSvid`) through hiqlite without bleeding a
  custom `serde` visitor through every owning crate. Round-trip plus
  invalid-hex unit tests live alongside the module.

- Add the `MachineIdentity.Health` RPC mirroring the Raft role and health (T54)
  **`MachineIdentity.Health` gRPC method.** Returns `(healthy, role,
  node_id)`. A non-clustered CMIS is always healthy and reports
  `NODE_ROLE_UNKNOWN`; a clustered one mirrors `Cluster::role` /
  `Cluster::is_healthy`. An L4/L7 load balancer maps `!healthy` or
  `NODE_ROLE_UNKNOWN` to "not ready".

- Test four-phase attestation across three CMIS instances on a hiqlite cluster (T55, T54)
  **3-node CMIS integration test** (`crates/mia/tests/cluster_attest.rs`).
  Stands up three CMIS instances backed by a 3-node hiqlite cluster, drives
  a full four-phase `Attest` against the leader, and asserts the issued
  bundle is observable through `FetchSVID` on a follower. Also exercises
  the `Health` RPC on both leader and follower.

#### F07: Merkle-chained audit log (M3 subset)

- Flesh out `ferro-audit` with a seven-variant, PII-free `AuditEvent` encoded as CBOR (T44)
  **`ferro-audit` crate fleshed out.** Seven-variant `AuditEvent` enum
  (`AttestStart` / `AttestFail` / `SvidIssued` / `SvidRevoked` /
  `KeyShareUsed` / `LocalGrant` / `LocalDenied`) — hashes and counters only,
  no PII. Encoded via `ciborium`; fixed-size hash fields use `Hash384` /
  `Bytes16` newtypes that emit single CBOR byte strings.

- Implement the RFC 6962 Merkle tree over SHA3-384 with offline proof verifiers (T45)
  **RFC 6962 Merkle tree, SHA3-384.** Domain-separated leaf / node hashing
  (`0x00 || x`, `0x01 || l || r`). Inclusion and consistency proof
  construction plus state-free `verify_inclusion` / `verify_consistency`
  callable by any third party — a verifier in possession of an earlier STH
  can detect deletion or reordering against a later one.

- Composite-sign Signed Tree Heads behind an `SthSigner` trait (T46)
  **Signed Tree Heads.** `SthBody { tree_size, root_hash, timestamp }`
  encoded canonically as CBOR and composite-signed (Ed25519 + ML-DSA-65)
  under domain context `ferrogate-sth-v1`. Signing is behind an `SthSigner`
  trait; `InProcessSigner` is the M3 stub (TEE-resident threshold signer
  lands in M4).

- Add the `AuditStore` trait and the write-once `LocalDiskWormStore` (T47)
  **WORM backing store.** `AuditStore` trait + `LocalDiskWormStore` whose
  `O_CREAT|O_EXCL` semantics refuse to overwrite a leaf or STH file. S3
  Object Lock (Compliance, 10-year retention) and the FoundationDB mirror
  arrive in M4.

- Add the `LatestSth`, `InclusionProof`, `ConsistencyProof` and `AppendAuditEvent` RPCs and record attestation events (T48)
  **Inclusion / consistency / STH RPCs.** `LatestSth`, `InclusionProof`,
  `ConsistencyProof`, and `AppendAuditEvent` added to the proto and
  implemented in CMIS. The CMIS `Attest` handler now records `AttestStart`
  on phase-2 success, `AttestFail` (with stable opcode strings, never user
  input) on every rejection branch, and `SvidIssued` after issuance — each
  followed by a fresh STH.

- Forward MIA audit events to CMIS through `AppendAuditEvent` (T50)
  **MIA forwarder.** `mia::audit_client::forward` encodes any
  `ferro_audit::AuditEvent` to CBOR and submits it via `AppendAuditEvent`.

- Property-test inclusion and consistency proofs and verify them end to end (T49, T50)
  **Tests.** Property test (`inclusion_and_consistency_hold_for_all_pairs`):
  24 cases, tree sizes 1..=12, asserts every leaf's inclusion proof and
  every `(old_size, new_size)` consistency proof verify offline against the
  captured STH roots. New end-to-end test in `crates/mia/tests/e2e_attest.rs`:
  attest → fetch latest STH → verify composite signature → fetch inclusion
  proof → verify offline → forward a `LocalGrant` → fetch consistency proof
  → verify back to the prior STH.

#### F06: TEE residency and threshold key shares (reconstructed during the PTF migration)

- Add the `ferro-tee` SEV-SNP and TDX attestation report model with a vendor-agnostic verifier (T57, T58, S6)
  Commit a887495 (2026-05-28); the pre-migration changelog had no F06 entry. `Attestor` trait,
  `Report` / `ReportBody` / `verify_report`; the test path uses a structurally faithful `SoftwareAttestor`.

- Split issuance keys into Shamir 3-of-5 shares sealed per replica to enclave measurements and zeroized on drop (T59, T60, T63)
  Byte-parallel GF(2^8) Shamir; ChaCha20-Poly1305 sealing keyed by HKDF-SHA3-384 over
  `(sealing_root, measurement, aad)`; `ProtectedKey` is mlocked (startup fails otherwise) and wiped on
  drop; loss of one share still reconstructs, loss of three halts gracefully. `cargo test -p ferro-tee`
  (32 unit + 6 integration tests).

- Exchange key shares only between mutually attested replicas over ML-KEM-768 PSK channels (T61, T62)
  Both sides verify the peer report and allowlist membership before deriving the PSK; the transcript binds
  nonces, the encapsulation key and the ciphertext.

### Postponed

#### F08: Local helper API (with the F09 child-token minter)

- Postpone the Windows Named Pipe transport, the CMIS child-token JWKS endpoint and the Rust and Go reference verifiers out of the 0.4.0 slice (T74, T77, T78, T79)
  **Out of this slice:** the Windows Named Pipe transport, the CMIS JWKS
  endpoint for child tokens, and the Rust/Go reference verifiers (the rest of
  F09). DPoP *proof* verification is the third-party API's job, by design.

#### F07 continued: Sigsum / Rekor anchor publisher with back-fill (M4 subset)

- Postpone the concrete Rekor and Sigsum HTTP drivers and the CMIS drain scheduling: drivers ship with deployment config, scheduling lands with the anchor wiring (T240, T224)
  **Out of this slice:** the actual Rekor / Sigsum HTTP drivers (concrete
  `Anchor` impls). Both are short — `POST /api/v1/log/entries` for Rekor,
  the Sigsum `add-leaf` request for Sigsum — and ship as part of the
  per-deployment config so operators can choose their preferred log
  family without forking the audit crate. CMIS scheduling (a 60-second
  tokio task that calls `drain_once` and feeds the outcome into metrics)
  lands with the wider F07-anchor wiring task in the CMIS service.

#### F07 continued: Raft-majority co-signed STHs (M4 subset)

- Postpone the per-peer RPC `SthSigner` as deployment wiring, keeping S3 Object Lock and the anchor publisher deferred at that point (T225, T66, T65)
  **Out of this slice:** per-peer RPC transport (an `SthSigner` that talks
  to the cluster peers through `ferro-raft`) is a deployment-wiring task
  and slots in behind the existing trait without an API break. The
  remaining F07-continued items — S3 Object Lock storage and the
  Sigsum / Rekor anchor publisher with back-fill — stay deferred per
  `docs/roadmap.md` §M4 / "F07 continued".

#### F05 Part 1: CMIS Raft cluster layer (M4)

- Postpone FoundationDB storage and the custom QUIC peer transport: hiqlite bundles both, and PQC peer TLS becomes an upstream hiqlite concern (T237, T236)
  **Roadmap pivots, explicitly noted in `docs/features/F05-cmis-ha.md`.**
  Hiqlite replaces the originally-planned FoundationDB storage + a custom
  QUIC peer transport: it bundles openraft + a durable state machine + the
  peer transport into one crate and removes ~3 k LOC of unverifiable adapter
  work from the M4 critical path. PQC peer TLS becomes an upstream-hiqlite
  concern; the F01 hybrid-PQC provider continues to terminate the public
  MIA↔CMIS surface.

#### F07: Merkle-chained audit log (M3 subset)

- Postpone Raft co-signed STHs, S3 Object Lock storage and the Sigsum / Rekor anchor publisher out of M3 scope (T64, T66, T65)
  **Out of M3 scope:** Raft co-signed STHs, S3 Object Lock storage, and the
  Sigsum / Rekor anchor publisher remain M4 work (`docs/roadmap.md` §M4 /
  "F07 (continued)").

#### F06: TEE residency and threshold key shares (reconstructed during the PTF migration)

- Postpone the hardware SEV-SNP / TDX report producers, keying the issuer off a `ProtectedKey` and the threshold STH signer until the hardware `Attestor` drivers land (T227, T228, T229)
  From the F06 status note and the legacy roadmap: the seams are `ferro_tee::Attestor` and
  `ferro_tee::Reconstructor`, and swapping the issuer and the M3 STH signer to consume them is a
  non-API-breaking change.

## [0.2.0] - 2026-05-28

TPM attestation MVP. Pre-migration heading: `[M2] — 2026-05-28 — TPM attestation MVP (v0.2.0)`. Not tagged in git.

### Added

#### F10: RIM and PCR policy (M2 subset)

- Refactor the `RimStore` into versioned generations with six-generation retention (T42)
  **Generational `RimStore`.** Refactored from a flat allowlist to a versioned
  generation set: `RimGeneration { version, policy_id, not_before, not_after,
  approved }` with `MAX_GENERATIONS = 6` retention and per-generation validity
  windows. Interior mutability (`parking_lot::RwLock`) lets a loader hot-swap
  a generation while a `TpmQuoteVerifier` holds a clone — readers always see a
  point-in-time consistent set. Back-compat `RimStore::approve(...)` survives
  via a separate manual allowlist for tests / bring-up. `RimStore::apply`
  rejects non-monotonic versions (`ApplyError::NonMonotonic`) and empty
  windows (`ApplyError::InvalidWindow`).

- Define the composite-signed RIM bundle format under `ferrogate-rim-v1` (T40, T41)
  **Signed RIM bundle format.** `ferro_attest::rim_bundle` defines `RimBundle`
  and `SignedRimBundle` with a composite (Ed25519 + ML-DSA-65) signature over
  the bundle's canonical JSON under domain-separation context
  `ferrogate-rim-v1`. `TrustedKeys` holds publisher `kid -> CompositePublicKey`
  mappings; unknown `signer_kid`, malformed signatures, and bodies tampered
  after signing are refused before any state changes.

- Hot-reload signed RIM bundles from disk and map `NotInRim` to `FAILED_PRECONDITION` (T43)
  **File-backed hot reload.** `ferro_attest::rim_loader::RimLoader::try_reload`
  reads a signed bundle from disk, verifies it, and applies it atomically.
  Non-monotonic on-disk versions return `ReloadOutcome::UpToDate` rather than
  escalating, so a regression publish is silently ignored. `cmis::rim_watcher`
  spawns the polling loop; `RejectReason::NotInRim` now maps to
  `FAILED_PRECONDITION` (per `docs/cmis.md` §"Error model"), separated from
  other quote-validation failures.

- Test RIM windows, retention, signatures, hot reload and the status mapping (T42, T41, T43)
  **Tests.** 17 new ferro-attest tests (window honoured, retention prune at 7
  generations, sign-then-verify roundtrip, tamper/unknown-kid/non-monotonic
  refusal, file-backed hot reload happy path + rollback rejection, atomic
  generation swap). Two new end-to-end tests in `crates/mia/tests/e2e_attest.rs`:
  `attest_returns_failed_precondition_when_digest_not_in_rim` proves the new
  status mapping over real gRPC, and `rim_loader_hot_swap_admits_a_freshly_published_generation`
  drives the whole loader-to-issued-SVID path with the `policy_id` flowing
  through into the SVID claim set.

#### F04: SVID issuance and lifecycle (M2)

- Add the `MachineIdentity` gRPC surface with a server-first `Attest` stream (T32, S20)
  **`ferro-proto` — `MachineIdentity` gRPC surface.** A proto3 service
  (`Attest` bidi stream, `Rotate`, `FetchSVID`, `JWKS`) compiled to tonic
  client/server stubs. `Attest` is server-first: it opens with a `Nonce`
  supplying the quote's `qualifyingData`, then drives the four-phase handshake.

- Add the JWS SVID envelope, issuance and lifecycle logic in `ferro-svid` (T33, T34, T35, T36, T38)
  **`ferro-svid` — JWS SVID envelope, issuance, and lifecycle.** The
  `ferrogate-svid-v1` claim schema; composite-signed compact JWS
  (`alg = MLDSA65+Ed25519`, `typ = ferrogate-svid+jwt`); SPIFFE-ID derivation
  from `SHA-384(ek_cert)`; a composite JWK / JWK-set; the
  renewal-vs-re-attestation decision (24 h window, PCR drift, epoch bump); and
  the 60%-of-TTL ±10% rotation-scheduler math. 1 h max TTL, `nbf` with a 60 s
  lookback.

- Add the standalone `ferro-svid-verify` reference verifier (T39)
  **`ferro-svid-verify` — standalone reference verifier.** Self-contained
  (re-declares the schema, depends only on `ferro-crypto` for the composite
  primitive): parses the compact JWS, verifies the AND-combined signature
  against a JWK set, and enforces `nbf`/`exp` fail-closed. Refuses expired SVIDs.

- Add the `cmis` issuance server for `Attest`, `Rotate`, `FetchSVID` and `JWKS` (T32, T35, T36)
  **`cmis` — the issuance server.** `MachineIdentitySvc` runs the four-phase
  `Attest` (F02 quote verification → phase-3 credential activation via the
  `CredentialMaker` seam → phase-4 AIK-bound composite CSR check → composite
  SVID issuance), the in-window `Rotate` short path with forced re-attestation
  on drift/epoch change, `FetchSVID`, and `JWKS`. Client-visible errors collapse
  to the fixed status set in `docs/cmis.md`; precise reasons are logged only.

- Add the `mia` attest client, PCR sealing and the rotation scheduler (T32, T37, T38)
  **`mia` — attest client, sealing, scheduler.** `client::run_attest` drives the
  handshake (generic over an `AttestEvidence` trait so it runs against a real
  TPM or a software stand-in) and returns the SVID plus its composite key.
  `seal` (Linux-only) seals a 256-bit key to a `PolicyPCR` over PCRs
  `{0,4,7,8}` (SHA-384) and ChaCha20-Poly1305-encrypts the cache; a sealed-PCR
  change makes the cache fail to unseal. `scheduler` computes the jittered
  rotation instant.

- Test issuance end to end over gRPC and sealing against `swtpm` (T32, T37, T39)
  **Tests.** An end-to-end gRPC test over a real in-process tonic channel
  (`crates/mia/tests/e2e_attest.rs`: issuance accepted by the reference
  verifier, `Rotate` short path, `Rotate` refused on drift), an `swtpm` sealing
  test (`crates/mia/tests/swtpm_seal.rs`), plus unit/round-trip coverage in
  `ferro-svid`. The TPM-backed modules are verified in the Linux/`swtpm` image.

#### F02: TPM 2.0 attestation engine (M2)

- Add the fail-closed CMIS-side TPM quote verifier (T28)
  **`ferro-attest` — CMIS-side quote verifier.** `TpmQuoteVerifier::verify_quote`
  runs the ordered, fail-closed algorithm: EK-certificate chain → AIK
  attribute mask → `magic`/`type` → nonce → ECDSA-P256 signature → recomputed
  SHA-384 PCR digest → RIM `policy_id`. Every rejection carries a precise,
  audit-only `RejectReason` while the peer sees only a generic denial.
  Fail-closed parsers for the canonical TPM wire structures (`TPMS_ATTEST`,
  `TPMT_PUBLIC`, `TPMT_SIGNATURE`) and a constant-time credential-activation
  compare.

- Add `mia::tpm::TpmEngine` over `tss-esapi` with HMAC-bound, parameter-encrypted sessions (T21, T22, T23, T24, T25, T26, T27)
  **`mia::tpm::TpmEngine` — host glue over `tss-esapi`** (Linux-gated). Exposes
  `load_ek`, `create_aik` (restricted ECDSA P-256 child of the EK), `quote`
  (policy PCRs over the SHA-384 bank), `activate_credential` (endorsement
  `PolicySecret` session), and `sign_aik` (restricted-key `TPM2_Hash` + ticket
  path). All sensitive commands run under HMAC-bound sessions with parameter
  encryption, flushed after use.

- Bundle per-vendor TPM root CAs with nothing trusted by default (T29)
  **Vendor root CA bundling.** Per-vendor trust store (Infineon, Nuvoton, ST,
  Intel PTT), independently loadable, with roots embedded at build time from
  `crates/ferro-attest/vendor-roots/<vendor>/`. Nothing is trusted by default.

- Add the `scripts/ferrogate-ca.sh` CA provisioning tool (T29, S27)
  **CA provisioning tool** `scripts/ferrogate-ca.sh` (`fingerprint` / `add`
  with pinned SHA-256 / `list` / `verify`) and the documented procedure in
  `crates/ferro-attest/vendor-roots/README.md` and `docs/tpm.md`.

- Add the F02 negative tests, the `swtpm` integration test and the Linux build image (T30, T31)
  **Tests & harness.** 26 `ferro-attest` tests including negative cases
  (tampered quote, wrong nonce, missing PCR, non-restricted AIK, untrusted
  root, not-in-RIM, wrong signing key, credential mismatch); an end-to-end
  `swtpm` integration test (`crates/mia/tests/swtpm_attest.rs`); and a Linux
  build/test image (`docker/f02-dev.Dockerfile` + `scripts/f02-docker.sh`)
  carrying the TSS2 + `swtpm` toolchain.

### Postponed

#### F10: RIM and PCR policy (M2 subset)

- Postpone the `bump_epoch` admin RPC and signed-S3 refresh out of M2 scope (T99, T98)
  **Out of M2 scope:** the `bump_epoch` admin RPC and signed-S3 refresh remain
  M5 work (`docs/roadmap.md` §M5).

#### F04: SVID issuance seams (derived from the legacy roadmap during the PTF migration)

- Postpone hybrid-PQC TLS on the CMIS listener and a production TCG `MakeCredential`: the bring-up binary stays plaintext and phase 3 has only a software `CredentialMaker` (T119, T230)
  From the legacy roadmap's F04 status note. TLS termination landed in 0.13.4; the production
  `MakeCredential` was to land with the TEE work and is still open (CMIS ships an
  `UnconfiguredCredentialMaker` that refuses).

## [0.1.0-m1] - 2026-05-26

Cryptographic foundation. Pre-migration heading: `[M1] — 2026-05-26 — Cryptographic foundation`. `0.1.0-m1` is a migration label: the workspace stayed at version 0.1.0 through legacy M0 and M1 and neither was tagged.

### Added

- Add the F01 hybrid post-quantum TLS provider with SPKI pinning to `ferro-crypto` (T9, T10, T11, T12, T13, T14)
  **F01: Hybrid post-quantum TLS transport** (`ferro-crypto`). A rustls
  provider exposing only `X25519MLKEM768` in hybrid mode, SHA-384 SPKI pinning
  for the MIA, and tests covering hybrid-only rejection of legacy clients, the
  `ClientHello` key-share wire format, and AEAD Wycheproof vectors.

- Add F03 composite Ed25519 + ML-DSA-65 signatures to `ferro-crypto` (T15, T16, T17, T18, T19, T20)
  **F03: Composite Ed25519 + ML-DSA-65 signatures** (`ferro-crypto`). An
  AND-combiner signature over a domain-separated SHA3-384 transcript, with
  concat / DER (`2.16.840.1.114027.80.8.1.7`) / JOSE (`MLDSA65+Ed25519`) wire
  forms, KAT runners, and property tests proving either-half corruption fails
  verification.

## [0.1.0-m0] - 2026-05-22

Workspace bootstrap. Pre-migration heading: `[M0] — 2026-05-22 — Workspace bootstrap`. `0.1.0-m0` is a migration label (see 0.1.0-m1).

### Added

- Create the cargo workspace with stub crates and the relocated `ferrogate-cli` (T1, T2)
  Cargo workspace under `crates/` with stub crates for `cmis`, `mia`,
  `ferro-crypto`, `ferro-attest`, `ferro-audit`, `ferro-proto`, `ferro-tee`,
  and the relocated `ferrogate-cli`.

- Add CI for fmt, clippy, test, `cargo audit`, `cargo deny` and coverage, with mirroring Makefile targets (T4, T5, T6, T3)
  CI (GitHub Actions): `fmt`, `clippy`, `test`, `cargo audit`, `cargo deny`,
  and an `llvm-cov` coverage job; `Makefile` targets mirroring them.

- Forbid unsafe code on every crate plus a workspace-wide lint (T7)
  `#![forbid(unsafe_code)]` on every crate plus a workspace-wide
  `unsafe_code = "deny"` lint.

- Add the design documentation under `docs/` (T8)
  Design documentation under `docs/` (architecture, protocol, threat model,
  TPM, crypto, per-feature specs, and the roadmap).

[Unreleased]: https://github.com/ffquintella/FerroGate/compare/releases/v0.27.0...HEAD
[0.27.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.27.0
[0.26.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.26.0
[0.25.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.25.0
[0.24.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.24.0
[0.23.1]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.23.1
[0.23.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.23.0
[0.22.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.22.0
[0.21.9]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.9
[0.21.8]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.8
[0.21.7]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.7
[0.21.5]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.5
[0.21.4]: https://github.com/ffquintella/FerroGate/releases/tag/v0.21.4
[0.21.3]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.3
[0.21.2]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.2
[0.21.1]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.1
[0.21.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.0
[0.15.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.15.0
[0.14.0]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.14.0
[0.13.4]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.13.4
[0.13.3]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.13.3
[0.13.2]: https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.13.2
[0.13.0]: https://github.com/ffquintella/FerroGate/releases/tag/v0.13.0
[0.12.1]: https://github.com/ffquintella/FerroGate/releases/tag/v0.12.1
[0.12.0]: https://github.com/ffquintella/FerroGate/releases/tag/v0.12.0
[0.8.0]: https://github.com/ffquintella/FerroGate/releases/tag/v0.8.0
[0.7.0]: https://github.com/ffquintella/FerroGate/releases/tag/v0.7.0
[0.6.0]: https://github.com/ffquintella/FerroGate/releases/tag/v0.6.0
[0.5.0]: https://github.com/ffquintella/FerroGate/releases/tag/v0.5.0
[0.4.0]: https://github.com/ffquintella/FerroGate/releases/tag/v0.4.0
