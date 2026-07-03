# Changelog

All notable changes to FerroGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches a tagged release. Until then, changes are grouped by delivery milestone
(see [docs/roadmap.md](docs/roadmap.md)).

## [Unreleased]

### Added

- **Windows MSI + NuGet/Chocolatey packaging for `mia`, cross-built in a
  container.** `make pkg-win` no longer needs a Windows host: it cross-compiles
  `mia.exe` to `x86_64-pc-windows-msvc` with cargo-xwin in a `linux/amd64`
  container, builds an MSI with msitools (`wixl`, from `crates/mia/wix/mia.wxs`),
  and wraps it in a Chocolatey/NuGet package (`crates/mia/nuget/`) that installs
  the MSI via `msiexec`. The MSI mirrors the previous NSIS installer — installs
  to `Program Files\FerroGate\MIA`, adds it to the system PATH, creates the
  `FerroGateClients` helper group, and registers + starts the mia service. See
  `scripts/build-msi-amd64.sh`.
- **`mia --resync` — one-shot, no-restart allowlist resync.** Re-fetches this
  host's signed caller allowlist from CMIS and swaps it into the running agent
  live (SIGHUP), so the helper socket never drops and no restart is needed. It is
  `mia resync-allowlist` with the live reload always on; on platforms without
  SIGHUP it falls back to the restart hint, and honors `--config`/`--environment`.
- **Windows host-key attestation — `mia` can now obtain a host SVID on
  Windows.** `ferro-machineid` gained a Windows backend that derives the stable
  hardware fingerprint from the SMBIOS system UUID, the baseboard/product serial,
  and the boot-disk serial (read via CIM through an absolute-path PowerShell, so
  `PATH` cannot be hijacked — the same rationale as the macOS `ioreg` backend).
  Previously `collect_facts()` returned "not supported on this platform", so the
  daemon had no host SVID and refused every mint with `no_host_svid`; Windows
  hosts can now attest via the TPM-less host-key profile (F15) like Linux/macOS,
  subject to CMIS enrolment.

- **`helper.require_authenticode` — opt out of the Windows caller Authenticode
  check.** The Windows helper API verifies each caller's image with Authenticode
  by default (the Code-Integrity analogue of the Linux IMA cross-check), which
  rejects unsigned callers — including an unsigned `mia.exe` running `mia test` —
  as `untrusted-binary`. The new `helper.require_authenticode` setting
  (`FERROGATE_HELPER_REQUIRE_AUTHENTICODE`, default `true`) lets environments
  whose binaries are not code-signed disable it; identity then rests on PID +
  image SHA-384 + RID, and `mia`'s self-trust still applies.

- **MIA runs as a native Windows service.** The daemon now integrates with the
  Windows Service Control Manager, so `Restart-Service mia` (and `sc start/stop
  mia`) work and the agent starts at boot. A new `mia service
  <install|uninstall|start|stop>` subcommand manages it (`mia service run` is the
  internal entry point the SCM launches); the service runs as `LocalSystem`,
  reads `%ProgramData%\FerroGate\mia.toml`, and — having no console — logs to
  `%ProgramData%\FerroGate\logs\mia.log`. The SCM glue lives in `ferro-winauth`
  (which permits `unsafe`) so `mia` stays `#![forbid(unsafe_code)]`. The Windows
  installer registers and starts the service automatically. See
  [docs/mia.md](docs/mia.md).

- **Windows installer creates the `FerroGateClients` helper group.** The default
  `helper.windows_group` restricts the helper pipe's DACL to this local group;
  the installer now creates it on install (and removes it on uninstall) so the
  daemon can resolve its SID and bind the pipe. Add vetted client accounts to the
  group so they may request tokens.

### Changed

- **Windows packaging migrated from WiX/MSI to NSIS.** `make pkg-msi` (cargo-wix
  + the end-of-life WiX v3 toolset) is replaced by `make pkg-win`, which builds a
  self-contained `.exe` installer with NSIS from `crates/mia/nsis/installer.nsi`.
  The installer drops `mia.exe` under `Program Files\FerroGate\MIA`, adds it to
  the system PATH, registers the Windows service, and ships an uninstaller.
  `make pkg-tools` installs NSIS via winget on Windows.

- **`mia` self-trust — the binary never loses access to its own daemon.** `mia`
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

- **Any-binary allowlist wildcard (`bin_sha = "*"`).** Allowlist entries now
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

- **`mia --reload` — signal a live config + allowlist reload.** A top-level
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

- **Live allowlist reload on `SIGHUP` (`mia resync-allowlist --reload`).** The
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

- **Hostname shown in `ferrogate list-svids`.** mia now reports the host's OS
  hostname in `AttestInit` as a display-only label; CMIS sanitises it
  (printable ASCII, 64-char cap), stores it on the issued record, and the CLI
  prints it under the SPIFFE id marked "(self-reported, display only)". It is
  never identity — the SPIFFE id stays rooted in the EK / hardware-fingerprint
  UUID — and records written before the field existed still decode.
- **`mia test` — connectivity and token-issuance self-test.** A new
  non-interactive subcommand that exercises the full path a local application
  depends on: configuration (CMIS endpoint + SPKI pin), the eager pinned
  hybrid-PQC TLS dial to CMIS, CMIS CRL publishing (`JWKS` RPC, signature
  verification, freshness), and a live child-token mint through the local
  helper socket. Every failing step prints targeted remediation hints
  mirroring the operations runbooks — a `crl_stale` refusal is
  cross-referenced with the server-side CRL check to say which side is at
  fault — and the command exits non-zero so provisioning scripts can gate on
  it.
- **Host-driven allowlist proposals (TOFU bootstrap + review queue).** mia can
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
- **`GetEnrollmentKey` RPC + `mia setup` key fetch.** CMIS now serves its
  enrollment public key (the composite key that signs caller allowlists, as
  `from_concat_bytes` bytes) via a new `GetEnrollmentKey` gRPC. `mia setup`,
  when an allowlist is configured and a CMIS endpoint + SPKI pin are present,
  offers to fetch that key over the pinned hybrid-PQC TLS channel and write it
  to `allowlist.key`. Also fixes the SPKI-pin format wording (lowercase-hex
  SHA-384, not base64) and validates the pin in the wizard. The signed
  allowlist *body* served from CMIS (per-host store + admin path) is planned.

### Fixed

- **Clearer error when the Windows helper pipe is already owned by another
  `mia`.** Creating the first helper-pipe instance while the `mia` service (or
  any other instance) is already running failed with the bare, baffling `socket
  setup: Access is denied. (os error 5)` — Windows returns `ERROR_ACCESS_DENIED`
  for `FILE_FLAG_FIRST_PIPE_INSTANCE` when a pipe of that name already exists.
  `ferro-winauth::create_server_pipe` now translates that specific case into an
  actionable message naming the cause (another instance already running; stop
  the service first). All other errors and subsequent pipe instances are
  unchanged.

- **The `ferrogate-mia` Chocolatey package no longer fails to install under a
  service account with a minimal `PATH`.** Both `chocolateyInstall.ps1` and
  `chocolateyUninstall.ps1` invoked `net.exe` by bare name, which PowerShell
  resolves via `PATH`; when Chocolatey is driven by a config-management agent
  (e.g. Puppet running as a Windows service) rather than an interactive admin
  shell, `PATH` may not include `System32` and the call fails with `The term
  'net.exe' is not recognized`, aborting the install before the MSI step runs.
  Both scripts now resolve `net.exe` via `$env:SystemRoot\System32\net.exe`.

- **The `ferrogate-mia` Chocolatey package no longer fails when the
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

- **The `ferrogate-mia` Chocolatey package now guarantees the `mia` service is
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

- **Child tokens no longer fail with `no key for kid host-…` after a `mia` or
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

- **CMIS now auto-renews allowlists on serve, so they no longer rot and lock
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

- **`mia` now recovers a missing host SVID on its own — no restart needed.**
  When attestation to CMIS fails at startup (CMIS unreachable, or — the common
  case — DNS/VPN not up yet right after boot), the daemon used to serve forever
  with minting disabled (`no_host_svid`) because attestation ran only once at
  startup. It now retries host-key attestation every 5 minutes in the
  background; the first success live-swaps the minter into the running server
  (minting on, no socket downtime), refreshes the signed allowlist from CMIS,
  and — if configured — starts the allowlist-propose task. Mirrors the CRL
  puller's stance that CMIS being down at boot must not permanently disable
  minting.

- **`mia test` step 5 (helper token mint) now runs on Windows.** It previously
  bailed with "the named-pipe self-test is not supported on this platform yet";
  it now connects the helper named pipe (mirroring the Unix UDS path) and either
  mints a token or reports the real reason (pipe missing ⇒ service down, busy, a
  DACL denial, or a daemon refusal such as `no_host_svid`) with remediation
  hints. The request/response exchange is shared between the Unix and Windows
  transports.

- **CMIS split-brain detection now works on a self-signed peer-TLS cluster
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
- **mia no longer crash-loops on an unverifiable allowlist; it serves deny-all
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
- **mia now starts the CRL puller, so helper tokens can actually be minted.**
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
- **CMIS now persists its issuer signing key across restarts.** The bring-up
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
- **mia no longer crash-loops when the allowlist file is absent.** With
  `allowlist.path` configured and `allowlist.fetch` on, if CMIS has no allowlist
  for the host and none was ever written to disk, the daemon read the missing
  `allowlist.cbor` as a fatal error and exited — launchd/systemd then restarted
  it every few seconds. The loader now treats a `NotFound` allowlist file as
  deny-all (fail closed) with a warning, matching the documented contract.
  (Present-but-invalid allowlists initially kept failing loudly; the
  deny-all-instead-of-crash entry above extends the same treatment to them.)
- **`mia setup` no longer double-prompts when editing an existing file.** The
  final "Write this configuration to …?" prompt is now the single point of
  consent; the redundant secondary "… exists — overwrite?" prompt (which always
  triggered because the wizard pre-fills from the existing file, and aborted on
  a natural "No") is removed. `--force` now skips the single write confirmation.

### Added

- **Hosts self-report their OS hostname for operator display.** MIA now sends
  its OS hostname in `AttestInit`, and CMIS stores it on the issued record and
  surfaces it in `ferrogate list-svids` (and the `SvidSummary` RPC field). It
  is a display-only convenience — never identity (which stays rooted in the
  EK/host-key fingerprint) and never verified: CMIS sanitises it to printable
  ASCII and truncates to 64 chars before storing, a host that cannot report one
  sends the empty string, and records written before the field existed still
  decode (it is optional).
- **MIA runs on Linux, macOS, and Windows.** The daemon now wires up and serves
  the helper API on all three platforms instead of only Linux: Linux uses
  `SO_PEERCRED` + IMA, Windows uses the named-pipe transport with PID + image
  hash + Authenticode, and macOS gains a new `MacCallerAuth` (peer-cred +
  on-disk image SHA-384 via the `libproc` crate; FFI stays out of `mia`, which
  remains `#![forbid(unsafe_code)]`). The startup hardening profile and TPM
  attestation remain Linux-only; shutdown handles `SIGINT`/`SIGTERM` on Unix and
  Ctrl-C on Windows.
- **Per-OS configuration-file locations.** The config file is now discovered at
  the OS-idiomatic system path then the per-user path — Linux
  `/etc/ferrogate/mia.toml` / `~/.config/ferrogate/mia.toml`, macOS
  `/Library/Application Support/FerroGate/mia.toml` / `~/Library/...`, Windows
  `%ProgramData%\FerroGate\mia.toml` / `%APPDATA%\...` — in addition to
  `--config` and `$FERROGATE_CONFIG`. `mia setup` now writes the **TOML config
  file** (not the env file) to the system path by default, with `--user` for the
  per-user path, prompting platform-appropriately (socket mode on Unix, pipe
  group on Windows). New `helper.windows_group` key / `FERROGATE_HELPER_WINDOWS_GROUP`.
- **MIA TOML configuration file.** MIA now reads an optional structured TOML
  configuration file (`crates/mia/src/config.rs`) in addition to environment
  variables, with precedence **defaults < config file < environment** — so
  existing env-driven deployments (the systemd `EnvironmentFile`) are unchanged.
  The file is discovered at `mia --config <path>`, then `$FERROGATE_CONFIG`,
  then `/etc/ferrogate/mia.toml`; a malformed file (including an unknown key)
  fails the daemon loudly at startup. Sections: `log`, `[cmis]`, `[helper]`,
  `[allowlist]`, `[attestation]`. A documented template is shipped at
  `/etc/ferrogate/mia.toml` (deb/rpm/macOS); source `crates/mia/dist/mia.toml`.
- **`mia setup` interactive configuration wizard.** A guided, rich-terminal
  wizard (built on `inquire`) that walks an operator through configuring the
  Machine Identity Agent — the CMIS server to connect to, the local helper API,
  the caller allowlist, attestation, and log verbosity — and writes the systemd
  `EnvironmentFile` (`/etc/ferrogate/mia.env`) in the documented, self-commenting
  template form. Run against an existing file it pre-fills every prompt, so it
  doubles as an editor. `--output <path>` targets a different file, `--force`
  skips the overwrite confirmation. Requires a TTY; unattended provisioning
  should write `mia.env` from the template directly.
- **`make mia-install`.** Compiles `mia` in release mode and installs the
  stripped binary to `$(PREFIX)/bin` (default `/usr/local/bin`), falling back to
  `sudo` when the destination is not writable.

## [0.15.0] — 2026-06-03

### Added

- **F01 hybrid-PQC TLS in the `ferrogate` operator CLI.** The CLI can now dial
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
- **New `ferro-transport` crate.** The client-side pinned dialer (formerly the
  body of `mia::client::connect_pinned`) now lives in
  `ferro_transport::connect_pinned`, returning a bare tonic `Channel`. It is
  shared by the MIA agent and the `ferrogate` CLI, keeping
  `ferro-crypto::transport` free of tonic/tokio-rustls and avoiding a `mia`
  dependency in the CLI. `mia::client::connect_pinned` delegates to it; MIA
  behaviour and its `tls_transport.rs` tests are unchanged.

### Changed

- `docs/transport-tls.md` documents the CLI's TLS support (endpoint scheme,
  pin-resolution precedence, the in-container zero-config default) and notes the
  earlier plaintext-only caveat is resolved; the code map and troubleshooting
  tables gained CLI / `ferro-transport` rows.

## [0.14.0] — 2026-06-03

### Added

- **Transport security documentation.** New
  [docs/transport-tls.md](docs/transport-tls.md): how the F01 hybrid-PQC TLS
  transport works (TLS 1.3, `X25519MLKEM768`-only, SPKI pinning, ALPN h2, code
  map) and how to configure it end to end — `CMIS_TLS_CERT` / `CMIS_TLS_KEY`,
  generating a server cert, the OpenSSL SPKI-pin recipe, `connect_pinned`
  usage, telemetry/verification, certificate + pin rotation, and
  troubleshooting. Linked from the sidebar and cross-referenced from the
  operations, crypto, cmis, mia, and networking docs.

### Changed

- Reformatted the workspace with `cargo fmt` so `cargo fmt --check` passes
  cleanly (no behavioural change).

## [0.13.4] — 2026-06-03

### Added

- **F01 hybrid-PQC TLS on the live gRPC transport.** The `ferro-crypto`
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

- Enabled tonic's `tls` feature and promoted `tokio-rustls` to a regular
  dependency of `cmis`/`mia`; added `hyper-util`, `tower`, and `rustls-pemfile`
  workspace dependencies for the transport glue.

## [0.13.3] — 2026-06-03

### Changed

- **S3 / object-storage support is dropped and will not be implemented.**
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

## [0.13.2] — 2026-06-02

### Added

- **Release pipeline.** A `Release` GitHub Actions workflow now fires on
  `releases/**` tags and publishes the mia `.deb` and `.rpm` packages plus a
  `ferrogate-sdk-rust-<version>.tgz` integration SDK to the GitHub Release.
  New `make release` / `make pkg-sdk` targets build the same artifacts locally;
  the SDK bundles the verifier-side crates (`ferro-proto`, `ferro-svid`,
  `ferro-svid-verify`, `ferro-child-verify`, `ferro-attest`, `ferro-crypto`)
  as a self-contained Cargo workspace.

### Removed

- The standalone `CI` workflow (`.github/workflows/ci.yml`).

## [0.13.1] — 2026-06-02

### Added

- **`ferrogate -V` / `--version`.** The operator CLI now reports its version
  (sourced from the workspace `CARGO_PKG_VERSION`) via `-V`, `--version`, or
  the `version` subcommand.

## [0.13.0] — 2026-06-02 — Operator CLI

### Added

- **`crates/ferrogate-cli` — the `ferrogate` operator CLI.** The former
  ironroot scaffold is now a real admin tool: a thin gRPC client over the
  existing `MachineIdentity` admin surface. Subcommands map one-to-one onto
  RPCs CMIS already exposes — `status` → `Health`, `list-svids` → `ListSvids`,
  `revoke-svid` → `RevokeSvid`, `revoke-host` → `RevokeHost`, `bump-epoch` →
  `BumpEpoch`. Targets the local CMIS by default
  (`http://127.0.0.1:8443`), overridable with `--endpoint` /
  `FERROGATE_CMIS_ENDPOINT`.
- **`ListSvids` RPC.** New admin RPC enumerating issued SVIDs (local store on a
  single replica, the full replicated set when clustered). Each `SvidSummary`
  carries the `cert_sha` an operator can feed straight into `RevokeSvid`.

### Changed

- **Container image bundles the `ferrogate` CLI.** `docker/ferrogate.Dockerfile`
  now builds and ships the `ferrogate` binary alongside the `cmis` server, so an
  operator can `docker exec <container> ferrogate status` and drive the admin
  RPCs against the local CMIS. `mia` remains a host-side package, not shipped in
  the image.

## [M6.0] — 2026-06-01 — Root key ceremony and rotation (v0.11.0)

### Added — F14: Root key ceremony and rotation

- **`crates/ferro-ceremony` — air-gapped ceremony library.** New
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
- **`tools/offline-signer` — the ceremony CLI.** New air-gapped binary with
  `keygen` / `pubkey` / `split` / `combine` / `cross-sign` / `verify-cross` /
  `jwks` / `minutes-new` / `minutes-sign` / `minutes-verify` / `destroy` /
  `verify-destruction` / `dry-run` subcommands, mirroring the `fleet-manifest`
  CLI conventions (`@file` value resolution, `--out`/stdout). `dry-run` runs the
  full eight-step rotation against a scratch directory with five synthetic
  operators — the executable form of the staging dry-run.
- **CMIS JWKS multi-key with "newer preferred" ordering.** `ferro_svid::Jwk`
  carries an optional `x-ferrogate-created` stamp (omitted on the wire when
  unset); `JwkSet::preferred()` — in both `ferro-svid` and the reference
  `ferro-svid-verify` — selects the newest key. `CmisState::register_root_key`
  publishes the incoming root for the cross-sign window, and `published_jwks`
  now orders roots newest-first ahead of the per-host child keys, all still
  resolvable by `kid`. SVID verification is unchanged (still by header `kid`);
  the ordering only affects trust-anchor choice during the window.
- **Operations runbook.** New `docs/operations/root-key-ceremony.md` with the
  step-by-step operator procedure, artefact formats, the destruction read-back,
  failure/recovery notes, and the recorded staging dry-run.

### Verification

`cargo test --workspace` (15 `ferro-ceremony` unit tests across
media/crosssign/minutes/destruction; the 2 `offline-signer` CLI integration
tests including the end-to-end `dry-run`; the `cmis` `root_rotation` integration
test) and `cargo clippy --workspace --all-targets`, alongside the existing
F01–F13 suites.

### Not yet supported

- **Online emergency rotation.** Deliberately out of scope — a separate,
  off-the-happy-path runbook. F14 covers only the planned annual rotation and
  periodic share refresh.

## [M5.6] — 2026-06-01 — RIM epoch bump and signed RIM refresh wiring (v0.10.0)

### Added — F10 (continued): RIM and PCR policy

- **`BumpEpoch` admin RPC.** New `MachineIdentity` RPC that advances the live
  RIM policy epoch. `CmisState` now holds the epoch in an `AtomicU64` (seeded
  from `CmisConfig::policy_epoch`); `current_epoch` / `bump_epoch` replace the
  frozen `config.policy_epoch` at the issuance and `Rotate` decision points. A
  bump forces every host attested under the previous epoch through a full
  four-phase re-attestation on its next `Rotate` (`FAILED_PRECONDITION` via
  `decide_renewal`'s `EpochBump` branch), and records a new `PolicyEpochBumped`
  audit event (`old_epoch`, `new_epoch`, bounded reason opcode).
- **Signed RIM refresh wired into CMIS.** `RimLoader` + `rim_watcher` (built in
  M2 but never spawned) are now started from `cmis` `main` behind
  `CMIS_RIM_BUNDLE` + `CMIS_RIM_SIGNER_KID` / `CMIS_RIM_SIGNER_PUB`, sharing one
  `RimStore` with the quote verifier. Startup is fail-closed (a configured but
  unloadable bundle aborts); with nothing configured the allowlist is empty and
  every quote fails the RIM lookup. The trust-from-env helper is now shared with
  the F13 fleet-manifest loader.

### Not yet supported

- **S3-sourced RIM refresh.** Fetching the bundle directly from S3 is
  deliberately out of scope for now — no HTTP/S3 client is pulled into the
  workspace. The bundle loads/hot-reloads from a local file; deployments sync it
  from object storage out of band, and the composite signature (verified before
  apply) is the only trust gate. A native fetcher can slot in behind the same
  seam later.

## [M5.5] — 2026-06-01 — Zero-touch bootstrap and fleet enrollment (v0.9.0)

### Added — F13: Zero-touch bootstrap and fleet enrollment

- **Fleet manifest format (`cmis::fleet_manifest`).** `FleetManifest` enumerates
  the SHA-384 of every approved EK certificate; it is only ever applied as a
  `SignedFleetManifest` — a composite (Ed25519 + ML-DSA-65) signature over the
  manifest's canonical JSON under the new `ferrogate-fleet-v1` domain context,
  carried by a trusted publisher key. Mirrors the F10 `SignedRimBundle` shape.
- **Live enrolment store + loader.** `EnrolledHosts` is the lookup-optimised
  (48-byte hash set) resolution of a manifest; `FleetStore` holds it behind an
  `RwLock<Arc<…>>` so a refresh swaps the `Arc` under the write lock and an
  in-flight `Attest` that took a snapshot sees a consistent set for the whole
  handshake. `FleetManifestLoader` reads, verifies, and hot-swaps a strictly
  newer manifest; `fleet_watcher::spawn` polls it. The signed-S3 refresh reuses
  the loader's verify-then-swap path.
- **Pre-admission lookup in `Attest`.** `CmisState::check_enrollment` runs on
  the phase-2 EK-cert hash *before* any TPM quote verification. With no manifest
  configured it is a no-op (every host admitted, as before F13); once a manifest
  is loaded an un-enrolled host is refused at the cheapest possible point.
  `cmis` `main` loads `CMIS_FLEET_MANIFEST` fail-closed (a configured-but-broken
  manifest aborts startup) using `CMIS_FLEET_SIGNER_KID` / `CMIS_FLEET_SIGNER_PUB`.
- **Audit events `HostEnrolled` / `HostRejected`** added to
  `ferro_audit::AuditEvent` (EK hash plus, for rejection, a stable opcode).
- **`fleet-manifest` CLI (`tools/fleet-manifest`).** Offline tool with
  `keygen`/`new`/`add`/`remove`/`sign`/`verify`/`show`. The publisher key is
  derived deterministically from a 32-byte master seed, so only the seed is
  secret at rest — backed by the new `CompositeSecretKey::from_seed` in
  `ferro-crypto` (independent SHA3-keyed sub-seeds for the two halves; the
  expanded private key is never serialized). Production root-key handling stays
  the F14 ceremony's job.

## [M5.4] — 2026-05-29 — MIA process hardening (v0.8.0)

### Added — F12: MIA process hardening

- **`ferro-harden` crate.** A new Linux-gated FFI crate — the analogue of
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
- **MIA hardening orchestration (`mia::hardening`).** `harden()` runs the
  fail-closed IMA check (refuses to start unless `/proc/cmdline` carries
  `ima_appraise=enforce`) then drives `ferro_harden::apply`, and verifies the
  post-drop effective capability set is exactly `{CAP_IPC_LOCK}`. `main` was
  restructured from `#[tokio::main]` to a plain `main` that hardens on the
  startup thread *before* building the runtime, so the seccomp filter is
  inherited by tokio workers and `MCL_FUTURE` covers their allocations.
- **Dev/rollout toggles.** `FERROGATE_SECCOMP=enforce|audit|off` (audit =
  log-only, to discover allow-list drift), `FERROGATE_REQUIRE_IMA=0`,
  `FERROGATE_RUN_AS_UID/GID`, `FERROGATE_SKIP_HARDENING=1`.
- **Reproducible build.** `scripts/reproducible-build.sh` builds `mia` twice with
  path remapping, `--build-id=none`, and pinned `SOURCE_DATE_EPOCH`/locale/TZ,
  and asserts byte-identical binaries, printing the `bin_sha384`. A new
  `reproducible-build` CI job runs it.
- **CI `no-unsafe-in-mia` gate.** Greps `crates/mia/src` for unsafe constructs as
  a belt-and-suspenders backstop to `#![forbid(unsafe_code)]`.
- **Tests.** `ferro-harden` carries a live seccomp self-test that forks, installs
  the enforcing filter, calls a forbidden syscall, and asserts the child died
  from `SIGSYS`; plus per-arch syscall-name resolution and BPF-build tests. The
  IMA cmdline parser is unit-tested in `mia::hardening`. The Linux paths are
  exercised in the `rust:1.88-bookworm` container (CI runs them natively).

### Notes

- Static-PIE musl packaging (statically linking TSS2) is left as deployment
  work; the reproducibility gate runs on the glibc build, which is PIE by
  default. The `effective_capabilities == {CAP_IPC_LOCK}` and privilege-drop
  paths require root and are exercised in privileged deployment, not unprivileged
  CI.

## [M5.3] — 2026-05-29 — Revocation and CRL distribution (v0.7.0)

### Added — F11: Revocation and CRL distribution

- **CRL data model (`ferro-svid::crl`).** A composite-signed `SignedCrl`
  carrying a `CrlBody { issued_at, number, entries }`. Each `CrlEntry` revokes
  either a single SVID by `cert_sha` (lowercase hex `SHA-384` of the compact
  JWS) or a whole host by SPIFFE id, with a stable reason opcode and an
  `expires_at` one max-SVID-TTL out (the "CRL bloat" mitigation — a revoked
  artefact can never reappear once its TTL elapses). The signature covers the
  canonical JSON under a distinct domain-separation context
  (`ferrogate-crl-v1`). `Issuer::sign_crl` signs with the composite issuance
  key; `SignedCrl::verify` is fail-closed (unknown kid, wrong key, or tampered
  bytes never yield the body).
- **JWKS `x-ferrogate-crl` extension.** `ferro_svid::JwkSet` gained an optional
  `crl` member, serialised as `x-ferrogate-crl` and omitted when absent, so a
  stock JWKS parser is unaffected. `CmisState::published_jwks` attaches the
  latest published CRL.
- **CMIS revocation store, admin RPCs, and publisher.** `MachineIdentity`
  gained `RevokeSvid(cert_sha, reason)` and `RevokeHost(spiffe_id, reason)`.
  Each validates and records the revocation, appends a `SvidRevoked` /
  `HostRevoked` audit event, and republishes a fresh signed CRL inline so the
  change lands within one publish cycle. `crates/cmis/src/crl_publisher.rs`
  is the 60 s heartbeat that keeps `issued_at` fresh (and prunes expired
  entries) between revocations; wired into the CMIS binary.
- **MIA freshness gate and CRL cache (`mia::helper::crl`).** A `CrlCache`
  holding the most recently *verified* CRL body, a puller
  (`spawn_puller` / `refresh_once` / `ingest`) that pulls the CRL from the CMIS
  `JWKS` RPC and verifies its signature fail-closed before caching, and a gate
  consulted on every child-token mint: a missing or stale (> 5 min) CRL refuses
  with `CrlStale`, and a CRL that revokes this host (by parent SVID `cert_sha`
  or by SPIFFE id) refuses with `permission_denied`. The gate runs before
  allowlisting, so a revoked host cannot mint even if otherwise permitted. Every
  refusal emits exactly one `LocalDenied` audit event.
- **Reference-verifier revocation support (`ferro-svid-verify`).** A new
  `verify_unrevoked` re-declares the CRL schema (staying self-contained),
  verifies the CRL signature against the JWKS keys, requires a fresh CRL (fail
  closed: absent/stale ⇒ `CrlStale`, bad signature ⇒ `CrlInvalid`), and rejects
  a revoked SVID (`Revoked`).
- **Audit.** Added the `HostRevoked { spiffe_id, reason }` event alongside the
  existing `SvidRevoked`.
- **Tests.** `crates/cmis/tests/revocation.rs` drives the admin RPCs through to
  the published JWKS CRL, asserts audit growth, and proves a revoked SVID is
  rejected by the reference verifier after propagation;
  `crates/ferro-svid/tests/verify_roundtrip.rs` proves the CMIS-signed CRL
  verifies under the independent verifier across the crate boundary (canonical
  JSON match), with revoked-by-cert / revoked-by-host / stale / absent / tampered
  cases; `crates/mia/tests/helper_api.rs` covers the stale / missing / revoked
  mint refusals; plus unit tests in `ferro-svid` and `mia` for fail-closed
  verification.

### Deferred (deployment seams)

- The CMIS revocation working set is process-local; replicating it through the
  Raft store so every replica's CRL agrees is wiring on the existing
  `CmisState::revoke` seam (mirrors the F09 process-local JWKS registry note).
- The MIA CRL puller is wired by the attestation loop that supplies the host
  SVID (not yet landed); until then the daemon runs with an empty cache and so
  refuses to mint (fail closed).

## [M5.2] — 2026-05-29 — DPoP child-token verification (v0.6.0)

### Added — F09: DPoP-bound child tokens (completion)

- **`ferro-child-verify` crate.** A self-contained Rust reference verifier for
  the DPoP-bound, composite-signed child tokens minted by the helper API. It
  re-declares the wire schema, validates the composite (Ed25519 + ML-DSA-65)
  signature against a CMIS JWK set, and enforces `exp`. `verify_bound` adds the
  RFC 9449 sender constraint: the caller must present a DPoP proof JWS whose
  RFC 7638 key thumbprint equals the token's `cnf.jkt`, and that proof must
  itself verify and match the HTTP request (`htm`/`htu`, freshness). A token
  presented with **no** DPoP proof is rejected (`MissingDpopProof`) — a captured
  bearer token cannot be replayed without the DPoP private key. DPoP proofs use
  Ed25519 (`alg = "EdDSA"`, OKP `jwk`).
- **Multi-key JWKS on CMIS.** `CmisState` now publishes a set of verification
  keys — the issuer's SVID key plus each host's composite child-token signing
  key, registered at phase-4 attestation under a deterministic key id
  (`ferro_svid::child_signing_kid`, shared with the MIA minter so the two sides
  never coordinate a name out of band). The `JWKS` RPC serves the merged set.
  The registry is process-local (a verifier must reach a replica that has seen
  the host's attestation); cluster-wide publication is a documented follow-up.
- **Tests.** `ferro-child-verify` unit tests cover the happy path, the no-proof
  replay rejection, thumbprint/request/freshness mismatches, expiry, unknown
  kid, and tampered/wrong-key signatures. `crates/mia/tests/child_token_verify.rs`
  round-trips the *real* `ChildTokenMinter` through the independent verifier, and
  `crates/mia/tests/e2e_attest.rs` asserts the host child-signing key is
  published in the JWKS after a full attestation.

### Scoped out

- The originally-planned **Go** reference verifier is dropped: the Rust crate is
  the canonical interop target and no second-language verifier ships in-tree.

## [M5.1] — 2026-05-29 — Windows Named Pipe helper transport (v0.5.0)

### Added — F08: Windows Named Pipe transport for the helper API

- **`ferro-winauth` crate.** The Windows FFI boundary for caller attestation,
  kept separate so `mia` stays `#![forbid(unsafe_code)]` (the crate has no
  dependency on `mia`, so there is no cycle). Safe wrappers over
  `GetNamedPipeClientProcessId` (client PID), `QueryFullProcessImageNameW`
  (image path), the token user SID's RID (the Windows analogue of a uid),
  `WinVerifyTrust` (Authenticode / Code-Integrity, the IMA-cross-check
  analogue), and named-pipe creation with an optional group-restricted DACL.
- **Transport-agnostic server pipeline.** `helper::server` is refactored so the
  request pipeline (`serve_connection` over any `AsyncRead + AsyncWrite`,
  authenticate → authorize → mint → audit) is shared, with a Unix Domain Socket
  listener (`server::unix`) and a Windows Named Pipe listener
  (`server::windows`). The cheap credential step runs on the async side; the
  authenticator's blocking work runs on the blocking pool on both platforms.
- **`WindowsCallerAuth`.** Composes the `ferro-winauth` primitives (plus
  `sha2` image hashing on the safe side) into a `CallerIdentity`; new
  `AuthError::ImageUnreadable` / `Untrusted` opcodes describe Windows failures.
  The pipe binds `\\.\pipe\ferrogate-mia` with an optional `FerroGateClients`
  DACL (`HelperServerConfig::windows_group`).
- **Cross-build tooling.** `docker/win-cross.Dockerfile` + `scripts/win-cross.sh`
  compile- and clippy-check the `x86_64-pc-windows-gnu` target from a
  Linux/macOS host (Windows tests cannot run here; the shared pipeline is
  covered by the Unix integration tests).

## [M5] — 2026-05-29 — Local helper API and DPoP child tokens (v0.4.0)

### Added — F08: Local helper API (with the F09 child-token minter)

- **`mia::helper` module.** A local IPC channel over which vetted host
  applications request short-lived, audience-bound, DPoP-bound child tokens.
  Caller identity is derived from kernel-attested sources, never from anything
  the caller claims.
- **`helper::proto`.** CBOR request/response (`HelperReq` / `HelperResp` /
  `ChildToken` / `ErrorCode`) with length-delimited framing — a 4-byte
  big-endian length bounded by `MAX_FRAME_LEN` (64 KiB), so a hostile prefix
  cannot make the MIA allocate without limit.
- **`helper::auth`.** The `CallerAuth` trait and `CallerIdentity` it produces,
  plus the pure `cross_check_ima` parser: an on-disk `SHA-384(/proc/<pid>/exe)`
  must equal the IMA-measured runtime hash for the same path, so a post-exec
  symlink/file swap is caught (`MismatchOutcome::Mismatch`). The Linux
  `ImaCallerAuth` (`SO_PEERCRED` + IMA log) is compiled only on Linux; the
  trait, identity type, and cross-check are portable and unit-tested anywhere.
- **`helper::allowlist`.** A fail-closed signed loader. The on-disk artefact is
  a CBOR `SignedAllowlist` (canonical-CBOR `AllowlistDoc` body + detached
  composite signature over those bytes under `ferrogate-allowlist-v1`).
  Verification happens before the body is parsed; freshness (`now ∈
  [issued_at, not_after]` and a max-age bound on `issued_at`) is enforced on
  load. Any failure yields no usable allowlist, denying every caller.
- **`helper::token` (feature F09 minter).** `ChildTokenMinter` mints a compact
  JWS (`typ = "ferrogate-child+jwt"`, `alg = "MLDSA65+Ed25519"`) signed with
  the host composite SVID key under the distinct context
  `ferrogate-child-token-v1`. TTL is clamped to ≤ 600 s, `jti` is a fresh
  128-bit value, `cnf.jkt` carries the caller DPoP thumbprint, and a
  `ferrogate` block records `parent_svid` / `actor_pid` / `actor_uid` /
  `actor_bin`.
- **`helper::server`.** A Unix-domain-socket listener (Unix only) created with
  the configured mode (default `0o660`) and optional group owner. The accept
  loop spawns one task per connection bounded by a `Semaphore`, with a
  per-connection read deadline so a slow/idle client releases its permit
  promptly and cannot starve well-behaved callers. `SO_PEERCRED` is read on the
  async side (`CallerAuth::identify` takes a `PeerCred` value), and the
  authenticator's blocking IMA / `/proc` reads run on the blocking pool so they
  never stall a runtime worker. Every decoded request produces exactly one
  audit event (`LocalGrant` / `LocalDenied`) pushed onto an `mpsc` channel for
  the `audit_client` forwarder to drain to CMIS.
- **Daemon wiring (`mia` binary).** The daemon now starts the helper API when
  `FERROGATE_HELPER_SOCKET` is set (Linux): it loads/verifies the signed
  allowlist (`FERROGATE_ALLOWLIST` + `FERROGATE_ALLOWLIST_KEY`), binds the
  socket with `FERROGATE_HELPER_SOCKET_MODE` (default `660`), uses the real
  `ImaCallerAuth`, drains audit events to the log, and serves until
  `SIGINT`/`SIGTERM`. Token minting stays disabled (`no_host_svid`) until the
  attestation loop supplies the host SVID key — a fail-safe surface for
  verifying socket permissions, caller attestation, and the allowlist in
  production ahead of minting.
- **Tests.** 23 lib unit tests and 9 socket-level integration tests covering
  every F08 acceptance criterion: `0o660` socket mode (via `stat`), IMA
  swap rejection, allowlist-absent and not-allowlisted denial, well-formed
  grant, signature fail-closed (wrong key / tampered body / garbage / expired /
  too-old), exactly-one-audit-event per request, and slow-client
  non-starvation. The minted token's composite signature verifies under the
  host key (what a downstream JWKS verifier does).
- **Out of this slice:** the Windows Named Pipe transport, the CMIS JWKS
  endpoint for child tokens, and the Rust/Go reference verifiers (the rest of
  F09). DPoP *proof* verification is the third-party API's job, by design.

### Added — F07 continued: Sigsum / Rekor anchor publisher with back-fill (M4 subset)

- **`ferro_audit::anchor` module.** A transparency-log publisher with
  persistent back-fill so an upstream outage cannot silently drop anchors.
  The `Anchor` trait abstracts the log family (Sigsum, Rekor v1/v2, …); a
  driver's only contract is `submit(&CoSignedTreeHead) -> Result<AnchorReceipt,
  AnchorError>` with a `Transient` (retry) vs. `Permanent` (quarantine)
  error taxonomy. The HTTP wire for each log lives behind this trait and is
  part of the operator's deployment config.
- **Disk-backed `AnchorQueue`.** Pending STHs land under
  `pending/<tree_size:020>.{sth.json,enq}` (the `.enq` marker carries the
  first-enqueue Unix-seconds timestamp); successful submissions land under
  `receipts/<tree_size:020>.json`; permanent failures move to
  `dead/<tree_size:020>.{sth.json,err}`. All writes use `O_CREAT|O_EXCL`, so
  re-enqueueing the same `tree_size` is a deterministic no-op and a
  publisher restart that re-observes the same STH does not lose the
  original backlog age.
- **`AnchorPublisher::drain_once`.** Submits pending entries in `tree_size`
  order. A `Transient` failure stops the drain (so the publisher does not
  hammer an unavailable log); a `Permanent` failure quarantines the entry
  and the drain continues with the rest of the queue. Returns a
  `DrainOutcome { published, transient_failures, quarantined,
  backlog_seconds_after }`. Operators alert on backlog ≥ 5 min, as
  documented in `docs/audit.md` §"Anchor outage".
- **Tests.** 7 tests in `anchor`: happy-path enqueue + drain (order
  preserved, receipts persisted); enqueue is idempotent per `tree_size`
  and preserves the original `enqueued_at`; a transient failure makes
  exactly one submit attempt, leaves all entries pending, and the next
  drain (with the anchor flipped to success) catches up entirely; a
  permanent failure quarantines and the drain continues; the queue
  survives reopen from disk (back-fill across a process restart); an
  already-anchored `tree_size` is not re-enqueued; backlog age tracks the
  earliest pending entry.
- **Out of this slice:** the actual Rekor / Sigsum HTTP drivers (concrete
  `Anchor` impls). Both are short — `POST /api/v1/log/entries` for Rekor,
  the Sigsum `add-leaf` request for Sigsum — and ship as part of the
  per-deployment config so operators can choose their preferred log
  family without forking the audit crate. CMIS scheduling (a 60-second
  tokio task that calls `drain_once` and feeds the outcome into metrics)
  lands with the wider F07-anchor wiring task in the CMIS service.

### Added — F07 continued: Raft-majority co-signed STHs (M4 subset)

- **New `ferro_audit::cosign` module.** `CoSignedTreeHead` carries the same
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
- **WORM persistence for co-signed heads.** `AuditStore` gains
  `record_cosigned_sth` / `latest_cosigned_sth` (default `Unsupported` so
  existing stores stay valid); `LocalDiskWormStore` persists artefacts under
  `cosigned/<tree_size:020>.json` with the same `O_CREAT|O_EXCL` invariant
  as the single-signer subdir.
- **`AuditLog::produce_cosigned_sth`.** Mirrors `produce_sth` but signs
  through a `QuorumSigner` and writes through the new WORM path before any
  external observer sees the head; `latest_cosigned_sth` caches it for
  cheap reads.
- **Tests.** 10 new `cosign` tests (3-of-3 happy path; threshold met with
  minority of keys unknown; threshold not met when keys unknown; full body
  tamper kills every signature; single-signature tamper still meets
  quorum=2; duplicate kids cannot inflate quorum; unknown kids ignored;
  invalid threshold refused; duplicate signers refused at build; `as_single`
  extracts a per-replica view) plus end-to-end `AuditLog::produce_cosigned_sth`
  and the WORM round-trip on `cosigned/`.
- **Out of this slice:** per-peer RPC transport (an `SthSigner` that talks
  to the cluster peers through `ferro-raft`) is a deployment-wiring task
  and slots in behind the existing trait without an API break. The
  remaining F07-continued items — S3 Object Lock storage and the
  Sigsum / Rekor anchor publisher with back-fill — stay deferred per
  `docs/roadmap.md` §M4 / "F07 continued".

### Added — F05 Part 1: CMIS Raft cluster layer (M4)

- **New crate `ferro-raft`.** Wraps [hiqlite](https://crates.io/crates/hiqlite)
  0.13 (openraft 0.9 + SQLite state machine + WAL on disk) behind a typed
  `Cluster` API: `upsert_svid` / `fetch_svid` / `fetch_svid_consistent` /
  `list_svids` / `delete_svid` / `current_rim_version` / `bump_rim_version`,
  plus `role` / `is_healthy` / `leader_id` for health gating. The schema is
  two idempotent `CREATE TABLE` statements (issued-SVID payloads keyed by
  SPIFFE id; a one-row `rim_state` for the policy epoch). Workspace MSRV
  bumped to 1.88 to match hiqlite's `edition = "2024"` floor.
- **3-node cluster integration tests** (`crates/ferro-raft/tests/cluster_e2e.rs`,
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
- **Roadmap pivots, explicitly noted in `docs/features/F05-cmis-ha.md`.**
  Hiqlite replaces the originally-planned FoundationDB storage + a custom
  QUIC peer transport: it bundles openraft + a durable state machine + the
  peer transport into one crate and removes ~3 k LOC of unverifiable adapter
  work from the M4 critical path. PQC peer TLS becomes an upstream-hiqlite
  concern; the F01 hybrid-PQC provider continues to terminate the public
  MIA↔CMIS surface.
### Added — F05 Part 2: CMIS issuance over the cluster (M4)

- **`CmisState` gains a cluster backend.** A new `CmisState::new_clustered`
  constructor wires an `Arc<ferro_raft::Cluster>` into the state; `record` /
  `lookup` / `update_bundle` become async and route through
  `Cluster::upsert_svid` / `fetch_svid_consistent` when set, falling back to
  the process-local `HashMap` otherwise. Existing single-replica callers
  (F02/F04/F07/F10 tests, the `cmis` binary) keep working unchanged.
- **Wire-type adapter (`cmis::cluster_store`).** A new `WireIssuedRecord`
  with hex-encoded byte fields and JSON serialisation lets us replicate the
  three `[u8; 48]`-bearing `ferro-svid` structs (`IssueParams`,
  `LastAttestation`, `IssuedSvid`) through hiqlite without bleeding a
  custom `serde` visitor through every owning crate. Round-trip plus
  invalid-hex unit tests live alongside the module.
- **`MachineIdentity.Health` gRPC method.** Returns `(healthy, role,
  node_id)`. A non-clustered CMIS is always healthy and reports
  `NODE_ROLE_UNKNOWN`; a clustered one mirrors `Cluster::role` /
  `Cluster::is_healthy`. An L4/L7 load balancer maps `!healthy` or
  `NODE_ROLE_UNKNOWN` to "not ready".
- **3-node CMIS integration test** (`crates/mia/tests/cluster_attest.rs`).
  Stands up three CMIS instances backed by a 3-node hiqlite cluster, drives
  a full four-phase `Attest` against the leader, and asserts the issued
  bundle is observable through `FetchSVID` on a follower. Also exercises
  the `Health` RPC on both leader and follower.

### Added — F07: Merkle-chained audit log (M3 subset)

- **`ferro-audit` crate fleshed out.** Seven-variant `AuditEvent` enum
  (`AttestStart` / `AttestFail` / `SvidIssued` / `SvidRevoked` /
  `KeyShareUsed` / `LocalGrant` / `LocalDenied`) — hashes and counters only,
  no PII. Encoded via `ciborium`; fixed-size hash fields use `Hash384` /
  `Bytes16` newtypes that emit single CBOR byte strings.
- **RFC 6962 Merkle tree, SHA3-384.** Domain-separated leaf / node hashing
  (`0x00 || x`, `0x01 || l || r`). Inclusion and consistency proof
  construction plus state-free `verify_inclusion` / `verify_consistency`
  callable by any third party — a verifier in possession of an earlier STH
  can detect deletion or reordering against a later one.
- **Signed Tree Heads.** `SthBody { tree_size, root_hash, timestamp }`
  encoded canonically as CBOR and composite-signed (Ed25519 + ML-DSA-65)
  under domain context `ferrogate-sth-v1`. Signing is behind an `SthSigner`
  trait; `InProcessSigner` is the M3 stub (TEE-resident threshold signer
  lands in M4).
- **WORM backing store.** `AuditStore` trait + `LocalDiskWormStore` whose
  `O_CREAT|O_EXCL` semantics refuse to overwrite a leaf or STH file. S3
  Object Lock (Compliance, 10-year retention) and the FoundationDB mirror
  arrive in M4.
- **Inclusion / consistency / STH RPCs.** `LatestSth`, `InclusionProof`,
  `ConsistencyProof`, and `AppendAuditEvent` added to the proto and
  implemented in CMIS. The CMIS `Attest` handler now records `AttestStart`
  on phase-2 success, `AttestFail` (with stable opcode strings, never user
  input) on every rejection branch, and `SvidIssued` after issuance — each
  followed by a fresh STH.
- **MIA forwarder.** `mia::audit_client::forward` encodes any
  `ferro_audit::AuditEvent` to CBOR and submits it via `AppendAuditEvent`.
- **Tests.** Property test (`inclusion_and_consistency_hold_for_all_pairs`):
  24 cases, tree sizes 1..=12, asserts every leaf's inclusion proof and
  every `(old_size, new_size)` consistency proof verify offline against the
  captured STH roots. New end-to-end test in `crates/mia/tests/e2e_attest.rs`:
  attest → fetch latest STH → verify composite signature → fetch inclusion
  proof → verify offline → forward a `LocalGrant` → fetch consistency proof
  → verify back to the prior STH.
- **Out of M3 scope:** Raft co-signed STHs, S3 Object Lock storage, and the
  Sigsum / Rekor anchor publisher remain M4 work (`docs/roadmap.md` §M4 /
  "F07 (continued)").

## [M2] — 2026-05-28 — TPM attestation MVP (v0.2.0)

End-to-end attestation against a software TPM with a single CMIS replica:
F02, F04, and the M2 subset of F10 all landed. Workspace version bumped from
`0.1.0` to `0.2.0`. Verified on Linux (`docker/f02-dev`) with
`cargo test --workspace --all-targets` (incl. `swtpm_attest` and
`swtpm_seal`), `clippy -D warnings`, and `fmt --check`.

### Added — F10: RIM and PCR policy (M2 subset)

- **Generational `RimStore`.** Refactored from a flat allowlist to a versioned
  generation set: `RimGeneration { version, policy_id, not_before, not_after,
  approved }` with `MAX_GENERATIONS = 6` retention and per-generation validity
  windows. Interior mutability (`parking_lot::RwLock`) lets a loader hot-swap
  a generation while a `TpmQuoteVerifier` holds a clone — readers always see a
  point-in-time consistent set. Back-compat `RimStore::approve(...)` survives
  via a separate manual allowlist for tests / bring-up. `RimStore::apply`
  rejects non-monotonic versions (`ApplyError::NonMonotonic`) and empty
  windows (`ApplyError::InvalidWindow`).
- **Signed RIM bundle format.** `ferro_attest::rim_bundle` defines `RimBundle`
  and `SignedRimBundle` with a composite (Ed25519 + ML-DSA-65) signature over
  the bundle's canonical JSON under domain-separation context
  `ferrogate-rim-v1`. `TrustedKeys` holds publisher `kid -> CompositePublicKey`
  mappings; unknown `signer_kid`, malformed signatures, and bodies tampered
  after signing are refused before any state changes.
- **File-backed hot reload.** `ferro_attest::rim_loader::RimLoader::try_reload`
  reads a signed bundle from disk, verifies it, and applies it atomically.
  Non-monotonic on-disk versions return `ReloadOutcome::UpToDate` rather than
  escalating, so a regression publish is silently ignored. `cmis::rim_watcher`
  spawns the polling loop; `RejectReason::NotInRim` now maps to
  `FAILED_PRECONDITION` (per `docs/cmis.md` §"Error model"), separated from
  other quote-validation failures.
- **Tests.** 17 new ferro-attest tests (window honoured, retention prune at 7
  generations, sign-then-verify roundtrip, tamper/unknown-kid/non-monotonic
  refusal, file-backed hot reload happy path + rollback rejection, atomic
  generation swap). Two new end-to-end tests in `crates/mia/tests/e2e_attest.rs`:
  `attest_returns_failed_precondition_when_digest_not_in_rim` proves the new
  status mapping over real gRPC, and `rim_loader_hot_swap_admits_a_freshly_published_generation`
  drives the whole loader-to-issued-SVID path with the `policy_id` flowing
  through into the SVID claim set.
- **Out of M2 scope:** the `bump_epoch` admin RPC and signed-S3 refresh remain
  M5 work (`docs/roadmap.md` §M5).

### Added — F04: SVID issuance and lifecycle (M2)

- **`ferro-proto` — `MachineIdentity` gRPC surface.** A proto3 service
  (`Attest` bidi stream, `Rotate`, `FetchSVID`, `JWKS`) compiled to tonic
  client/server stubs. `Attest` is server-first: it opens with a `Nonce`
  supplying the quote's `qualifyingData`, then drives the four-phase handshake.
- **`ferro-svid` — JWS SVID envelope, issuance, and lifecycle.** The
  `ferrogate-svid-v1` claim schema; composite-signed compact JWS
  (`alg = MLDSA65+Ed25519`, `typ = ferrogate-svid+jwt`); SPIFFE-ID derivation
  from `SHA-384(ek_cert)`; a composite JWK / JWK-set; the
  renewal-vs-re-attestation decision (24 h window, PCR drift, epoch bump); and
  the 60%-of-TTL ±10% rotation-scheduler math. 1 h max TTL, `nbf` with a 60 s
  lookback.
- **`ferro-svid-verify` — standalone reference verifier.** Self-contained
  (re-declares the schema, depends only on `ferro-crypto` for the composite
  primitive): parses the compact JWS, verifies the AND-combined signature
  against a JWK set, and enforces `nbf`/`exp` fail-closed. Refuses expired SVIDs.
- **`cmis` — the issuance server.** `MachineIdentitySvc` runs the four-phase
  `Attest` (F02 quote verification → phase-3 credential activation via the
  `CredentialMaker` seam → phase-4 AIK-bound composite CSR check → composite
  SVID issuance), the in-window `Rotate` short path with forced re-attestation
  on drift/epoch change, `FetchSVID`, and `JWKS`. Client-visible errors collapse
  to the fixed status set in `docs/cmis.md`; precise reasons are logged only.
- **`mia` — attest client, sealing, scheduler.** `client::run_attest` drives the
  handshake (generic over an `AttestEvidence` trait so it runs against a real
  TPM or a software stand-in) and returns the SVID plus its composite key.
  `seal` (Linux-only) seals a 256-bit key to a `PolicyPCR` over PCRs
  `{0,4,7,8}` (SHA-384) and ChaCha20-Poly1305-encrypts the cache; a sealed-PCR
  change makes the cache fail to unseal. `scheduler` computes the jittered
  rotation instant.
- **Tests.** An end-to-end gRPC test over a real in-process tonic channel
  (`crates/mia/tests/e2e_attest.rs`: issuance accepted by the reference
  verifier, `Rotate` short path, `Rotate` refused on drift), an `swtpm` sealing
  test (`crates/mia/tests/swtpm_seal.rs`), plus unit/round-trip coverage in
  `ferro-svid`. The TPM-backed modules are verified in the Linux/`swtpm` image.

### Added — F02: TPM 2.0 attestation engine (M2)

- **`ferro-attest` — CMIS-side quote verifier.** `TpmQuoteVerifier::verify_quote`
  runs the ordered, fail-closed algorithm: EK-certificate chain → AIK
  attribute mask → `magic`/`type` → nonce → ECDSA-P256 signature → recomputed
  SHA-384 PCR digest → RIM `policy_id`. Every rejection carries a precise,
  audit-only `RejectReason` while the peer sees only a generic denial.
  Fail-closed parsers for the canonical TPM wire structures (`TPMS_ATTEST`,
  `TPMT_PUBLIC`, `TPMT_SIGNATURE`) and a constant-time credential-activation
  compare.
- **`mia::tpm::TpmEngine` — host glue over `tss-esapi`** (Linux-gated). Exposes
  `load_ek`, `create_aik` (restricted ECDSA P-256 child of the EK), `quote`
  (policy PCRs over the SHA-384 bank), `activate_credential` (endorsement
  `PolicySecret` session), and `sign_aik` (restricted-key `TPM2_Hash` + ticket
  path). All sensitive commands run under HMAC-bound sessions with parameter
  encryption, flushed after use.
- **Vendor root CA bundling.** Per-vendor trust store (Infineon, Nuvoton, ST,
  Intel PTT), independently loadable, with roots embedded at build time from
  `crates/ferro-attest/vendor-roots/<vendor>/`. Nothing is trusted by default.
- **CA provisioning tool** `scripts/ferrogate-ca.sh` (`fingerprint` / `add`
  with pinned SHA-256 / `list` / `verify`) and the documented procedure in
  `crates/ferro-attest/vendor-roots/README.md` and `docs/tpm.md`.
- **Tests & harness.** 26 `ferro-attest` tests including negative cases
  (tampered quote, wrong nonce, missing PCR, non-restricted AIK, untrusted
  root, not-in-RIM, wrong signing key, credential mismatch); an end-to-end
  `swtpm` integration test (`crates/mia/tests/swtpm_attest.rs`); and a Linux
  build/test image (`docker/f02-dev.Dockerfile` + `scripts/f02-docker.sh`)
  carrying the TSS2 + `swtpm` toolchain.

## [M1] — 2026-05-26 — Cryptographic foundation

### Added

- **F01: Hybrid post-quantum TLS transport** (`ferro-crypto`). A rustls
  provider exposing only `X25519MLKEM768` in hybrid mode, SHA-384 SPKI pinning
  for the MIA, and tests covering hybrid-only rejection of legacy clients, the
  `ClientHello` key-share wire format, and AEAD Wycheproof vectors.
- **F03: Composite Ed25519 + ML-DSA-65 signatures** (`ferro-crypto`). An
  AND-combiner signature over a domain-separated SHA3-384 transcript, with
  concat / DER (`2.16.840.1.114027.80.8.1.7`) / JOSE (`MLDSA65+Ed25519`) wire
  forms, KAT runners, and property tests proving either-half corruption fails
  verification.

## [M0] — 2026-05-22 — Workspace bootstrap

### Added

- Cargo workspace under `crates/` with stub crates for `cmis`, `mia`,
  `ferro-crypto`, `ferro-attest`, `ferro-audit`, `ferro-proto`, `ferro-tee`,
  and the relocated `ferrogate-cli`.
- CI (GitHub Actions): `fmt`, `clippy`, `test`, `cargo audit`, `cargo deny`,
  and an `llvm-cov` coverage job; `Makefile` targets mirroring them.
- `#![forbid(unsafe_code)]` on every crate plus a workspace-wide
  `unsafe_code = "deny"` lint.
- Design documentation under `docs/` (architecture, protocol, threat model,
  TPM, crypto, per-feature specs, and the roadmap).
