# mia-tray — the MIA desktop companion

`mia-tray` (feature [F18](features/F18-mia-tray.md)) is a small, **unprivileged**
desktop companion for the [MIA agent](mia.md). It lives in the macOS menu bar,
the Windows notification area or a Linux StatusNotifierItem tray and answers one
question at a glance — *is this machine's identity agent healthy?* — and, when
it is not, walks the person at the keyboard through fixing it.

It is a front end for capabilities `mia` already has. It adds no trust: it holds
no key material, never sends a helper-API `HelperReq`, never shows or copies
SVIDs, tokens or keys, and every privileged step is a one-shot `mia` (or
service-manager) command behind the operating system's own consent prompt.

## What it shows

The icon colour is the **worst** state across the environments the agent serves
(the daemon computes the state; the tray only maps it):

| Colour | States |
|---|---|
| grey | `not_installed` (no `mia` found), `not_running` (no status endpoint), `not_configured` (with a `!` badge) |
| blue (pulsing) | `attesting` |
| green | `healthy` |
| yellow | `cmis_unreachable`, `crl_stale`, `allowlist_missing`, `allowlist_invalid`, `svid_expiring` |
| red | `not_enrolled`, `pin_mismatch`, `tpm_unavailable`, `ima_disabled` |

The menu has one submenu per environment (state, problem, SPIFFE ID with expiry
and renewal time, CMIS node, CRL age, allowlist entry count and expiry,
attestation backend, X.509-SVID store, agent version), the recovery actions for
the worst state, and **Open status**, **Setup…**, **Logs…**, **Run self-test**
and **Quit**. A `last_error.code` the tray does not know (a newer daemon) is
shown generically, with "Run self-test" offered.

**The default environment.** The environment that serves the helper API's
well-known address — `mia.sock` / `\\.\pipe\ferrogate-mia`, the one local
applications reach without configuration (see
[the default environment](mia.md#default-environment-who-serves-the-well-known-address))
— is marked **[default address]** in its submenu title and in the Status
window, with a "Helper API: serves the well-known default address" line. Every
other environment's submenu and Status block offer:

- **Set as default environment** (a named environment) —
  `mia default-environment set <env>`;
- **Use mia.toml as default** (the `mia.toml` environment) —
  `mia default-environment clear`.

Both need administrator approval and change `environments.toml` in the system
config directory; the agent applies the change when it restarts, so the tray
then says to restart the service (Recovery → **Restart the service**). Until
the restart the marker stays where the agent actually serves the address. No
action is offered while the agent is not reachable, for the environment that
already has the address, or for an environment named `default` (reserved). The
marker comes from the daemon's `default_address` field; an older agent does not
send it, so nothing is marked.

**Notifications** fire only on transitions that need a human — healthy → any
degraded/broken/absent state, entering `svid_expiring`, entering `crl_stale` —
never for the state the tray starts in. Each (environment, kind) is
de-duplicated for 30 minutes and at most 3 notifications are sent per 10
minutes.

Where the data comes from, in order: the status endpoint
(`/run/ferrogate/mia-status.sock`, `/var/run/ferrogate/mia-status.sock`,
`\\.\pipe\ferrogate-mia-status`, or `$FERROGATE_STATUS_SOCKET`); else
`mia status --json` (an older agent, or a custom `status.socket` that only the
configuration file knows); else a synthesised `not_running`. The tray polls
every 5 s while the agent answers and backs off to once a minute while it does
not.

### Who may read the status

The status endpoint is readable by members of the status group —
`ferrogate-status` on Linux and macOS, `FerroGateStatus` on Windows. The
installers create it and add the installing user (macOS `.pkg`: the console
user; Chocolatey package: the installing account; Linux `ferrogate-mia`:
`$SUDO_USER` plus active local graphical users). Group membership applies from
the next login. A user outside the group sees "Status not readable by this
user" and a link to this page; add them with
`sudo usermod -aG ferrogate-status <user>` (Linux),
`sudo dscl . -append /Groups/ferrogate-status GroupMembership <user>` (macOS) or
`net localgroup FerroGateStatus <user> /add` (Windows), then restart the agent
once on Linux so its socket picks the group up.

## The windows

Every window is a separate process (`mia-tray --window <kind>`, a closed set),
drawn natively with egui — there is no web view, and every string from the
daemon or from `mia` is rendered as plain text with control and bidirectional
characters escaped.

- **Status** — the per-environment detail with the explanation and recovery
  buttons for each state.
- **Recovery** — the closed set of actions below, run in the background with
  the outcome shown inline (raw output folded under "Output"; `mia test` is
  shown check by check), **Copy machine identifiers** and documentation links.
- **Setup** — the graphical `mia setup` (below).
- **Logs** — the agent's recent, redacted log records (below).

### Recovery actions

Each action is a fixed command line; the only variable argument is an
environment name, validated with the same rule `mia` applies
(`mia_status_proto::validate_environment`) plus a length cap and no leading
`-` (so it can never read as an option). Nothing is ever built from log text
or typed text.

| Action | Command | Runs as |
|---|---|---|
| Run self-test | `mia test --json [-e <env>]` | user |
| Show machine ID / copy identifiers | `mia machine-id` (only a UUID-shaped first line is copied) | user |
| Show status | `mia status --json [-e <env>]` | user |
| Start / stop / restart the service | Linux `systemctl start\|stop\|restart mia.service`; macOS `launchctl bootstrap system …/com.ferrogate.mia.plist` / `bootout system/com.ferrogate.mia` / `kickstart -k system/com.ferrogate.mia`; Windows `mia service start\|stop`, `Restart-Service -Name mia` | administrator |
| Resync the allowlist | `mia resync-allowlist --reload [-e <env>]` | administrator |
| Re-fetch the enrollment key | `mia refresh-key [-e <env>]` (deprecated alias of `mia allowlist-key fetch --rotate --yes`: pinned channel, audited, fingerprint printed) | administrator |
| Set as default environment | `mia default-environment set <env>` (for the default `mia.toml` environment: `mia default-environment clear`) | administrator |
| Use mia.toml as default | `mia default-environment clear` | administrator |
| Apply the configuration (system file) | `mia setup --apply <draft> --json [-e <env>] [--reload] [--fetch-enrollment-key [--expect-fingerprint <hex>]]` | administrator |

"Administrator" means the platform's consent prompt; the tray never sees, asks
for or stores a password:

| OS | Mechanism | Cancelling |
|---|---|---|
| Linux | `pkexec <absolute program> <args>`; the `mia` commands use the polkit action `br.fgv.ferrogate.mia.setup` (`auth_admin`, never cached, active local sessions only; the prompt shows the exact command line), shipped in `/usr/share/polkit-1/actions/` | exit 126 → "cancelled" |
| macOS | `osascript` runs a fixed script that shell-quotes every argument with `quoted form of` and calls `do shell script … with administrator privileges` | error −128 → "cancelled" |
| Windows | `powershell.exe` runs a fixed script that calls `Process.Start` with the `runas` verb (UAC); the program and its argument string are passed in environment variables, never as script text | error 1223 → "cancelled" |

Elevation only ever runs a `mia` from the packaged locations (`/usr/bin/mia` or
`/usr/local/bin/mia` on Linux, `/usr/local/bin/mia` on macOS,
`<Program Files>\FerroGate\MIA\mia.exe` on Windows) and, on Unix, only when that
file and its directory are root-owned and not writable by group or others —
otherwise the tray says so and does not prompt. The same rule is re-checked
for every elevated program (`systemctl`, `launchctl`, PowerShell) right before
it runs. On Windows the program must sit under the Program Files or Windows
directory as recorded in `HKLM` — never as given by the user-controllable
`%ProgramFiles%` / `%SystemRoot%` variables. A UAC-elevated process cannot
return its output, so on Windows elevated actions report only their outcome.

### Setup wizard

1. **Load** runs `mia setup --dump --json --editable` (`--user` for the
   per-user file, `-e <env>` for a named environment). On Linux and macOS the
   protected system file is read through the same administrator-consent
   mechanism used by Apply; the reduced dump contains only fields this screen
   can edit. Per-user files are read without elevation. Keys set by environment
   variables are shown read-only with their effective value; the draft keeps
   the file's own value for them (read with those variables removed), so
   applying never copies an environment value into the file. On Windows, where
   a UAC child cannot return output, an unreadable system file still offers
   **Start from defaults**; Apply preserves keys the wizard does not manage.
2. Every field is validated locally with `mia`'s own rules (CMIS endpoint or
   SRV record, SPKI pin, helper socket / pipe group, allowlist path, key, max
   age, `fetch` / `propose`, attestation backend, IMA log, log directive) plus
   the cross-field rules. A blank helper socket or allowlist file leaves the
   key out of the file, so `mia` uses the platform default for the
   environment; the allowlist key has no default and must be filled in for
   any caller to be allowed. For system setup, the **Enrollment public key
   (paste)** field accepts the public-key value from
   `ferrogate enrollment-key --format public-key`; the value is validated and
   installed into the selected key file by the administrator-approved `mia`
   process. The optional fingerprint field can confirm the pasted key against
   `ferrogate enrollment-key`'s default fingerprint output. Pasting and fetching
   are mutually exclusive; an already installed, different key still requires
   the explicit rotation workflow.
3. **Check with mia** writes the draft to a fresh private directory (`0700`,
   random name, under `$XDG_RUNTIME_DIR` or the per-user temp directory) as
   `draft.toml` (`0600`, created exclusively) and runs `mia setup --check`;
   mia's own error text is shown per key. **Apply** is enabled only for exactly
   the draft mia accepted, and always writes the file that was loaded:
   changing the scope or environment selector disables Check and Apply until
   that file is loaded.
4. **Apply** runs `mia setup --apply` — directly for the per-user file, through
   the consent prompt for the system file — and then reloads the configuration
   so the change is visible. `--reload` (signal the running agent) and
   `--fetch-enrollment-key` (fetched inside the elevated `mia`, over the pinned
   channel) or a pasted public key are options. The paste field accepts the
   base64url value from `ferrogate enrollment-key --format public-key`. The
   screen also accepts the optional 96-character fingerprint printed by
   `ferrogate enrollment-key`; `mia` writes nothing when the key differs. The
   tray removes its private
   directory afterwards, including the draft an elevated `mia` deliberately
   leaves to its owner.

### Log viewer

The viewer follows the agent's in-memory ring buffer through the status
endpoint (`LogTailReq` with `since_seq`), so it needs no access to
`/var/log/ferrogate`, `%ProgramData%\FerroGate\logs` or the journal. Records are
redacted by the agent before they are buffered. It never shows a record twice,
marks evicted ranges ("… N record(s) dropped …") and agent restarts, and
filters by level, environment and text. **Follow** can be paused (new records
are held and counted).

- **Open full log** opens the platform viewer: Console.app on
  `/var/log/ferrogate/mia.log` (macOS), Notepad on
  `%ProgramData%\FerroGate\logs\mia.log` (Windows), `journalctl -u mia -f` in a
  terminal (Linux). Reading the journal needs membership in `systemd-journal`
  or `adm`; the tray says so and never elevates for it. On Windows the
  configuration directory, logs included, is readable by SYSTEM and
  Administrators only; an administrator can let users read the log with
  `icacls "%ProgramData%\FerroGate\logs" /grant *S-1-5-32-545:(OI)(CI)RX` (see
  "Configuration directory permissions" in [mia.md](mia.md)).
- **Save diagnostics bundle…** writes, where you choose (`0600`), a plain-text
  file with the status snapshots, the latest `mia test --json` result (run now
  if there was none) and the last 500 log records — only what the tray already
  shows.

## Installing

| Platform | Package | Autostart |
|---|---|---|
| macOS | inside `make pkg-macos` (`/Applications/FerroGate MIA.app`, symlinked as `/usr/local/bin/mia-tray`) | LaunchAgent `/Library/LaunchAgents/com.ferrogate.mia-tray.plist` (login item; started for the console user at install) |
| Windows | inside `make pkg-win` (`%ProgramFiles%\FerroGate\MIA\mia-tray.exe`) | `HKLM\…\CurrentVersion\Run\FerroGateMiaTray` |
| Linux (Debian/Ubuntu) | inside `ferrogate-mia` (`make pkg-deb`) | started for active graphical users during install; XDG autostart `/etc/xdg/autostart/mia-tray.desktop` on later logins |
| Linux (RPM) | separate, opt-in `ferrogate-mia-tray` package (`make pkg-rpm-tray`) | XDG autostart `/etc/xdg/autostart/mia-tray.desktop` |

The application icon is mastered as `crates/mia-tray/dist/icons/ferrogate-mia.svg`.
After editing it, run `make icons` (`scripts/gen-mia-icons.sh`) to regenerate
the committed PNG, `.icns` (app bundle) and `.ico` (MSI). The packages install
it as `ferrogate-mia` in the hicolor icon theme on Linux. The menu-bar icon
itself is the state disc drawn in `src/icon.rs`.

`MIA_TRAY=0 make pkg-macos` / `MIA_TRAY=0 make pkg-win` build the agent
packages without the tray. On Linux the tray needs a StatusNotifierItem host:
KDE, Xfce, Cinnamon and most others have one; GNOME needs the
"AppIndicator and KStatusNotifierItem Support" extension.

## Building from source

The GUI is behind the off-by-default `gui` cargo feature, so the ordinary
`make build` / `make lint` / `make test` build, lint and test the tray's
headless core (endpoint client, state mapping, notification policy, command
builders and elevation wrappers, wizard drafts, log follower, diagnostics
bundle) on any host, without GUI system libraries.

```console
$ make tray        # release build with the GUI
$ make lint-tray   # clippy -D warnings with the GUI compiled in
$ make test-tray   # tests with the GUI compiled in
$ make deny-tray   # cargo-deny over the GUI dependency graph
```

On Linux these need `libgtk-3-dev libxdo-dev libayatana-appindicator3-dev`
(runtime: `libgtk-3-0 libxdo3 libayatana-appindicator3-1`). The
`.github/workflows/mia-tray.yml` workflow builds, lints and tests the GUI on
Linux, macOS and Windows.

| Variable | Effect |
|---|---|
| `FERROGATE_STATUS_SOCKET` | status endpoint address (same override `mia` honours) |
| `MIA_TRAY_MIA` | absolute path of a development `mia`, used for **unprivileged** actions only — never elevated |
| `MIA_TRAY_LOG` | the tray's own tracing directive on stderr (default `info`) |
| `LC_ALL` / `LC_MESSAGES` / `LANG` / `LANGUAGE`, then the OS locale | English or Portuguese |

## Limitations

- On Linux without a StatusNotifierItem host the icon is not visible; the tray
  still sends notifications, and `mia status` remains the universal path.
- Unsigned builds: macOS may attribute notifications to another application and
  Gatekeeper may warn; Windows SmartScreen warns. Sign with `CODESIGN_ID` /
  `WIN_SIGN_PFX` like `mia`.
- Configuration changes are gated by the local OS administrator prompt; whether
  that satisfies FGV NRM §5.3.1 (MFA for sensitive operations) on workstations
  is an open point for ESI validation (see the F18 spec).
