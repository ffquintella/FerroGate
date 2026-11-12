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

The icon shows the **worst** state across the environments the agent serves
(the daemon computes the state; the tray only maps it) as a colour *and* a
glyph, so it never depends on colour alone; it does not blink. The tooltip
reads `FerroGate MIA — <state>`.

| Icon | States |
|---|---|
| grey – | `not_installed` (no `mia` found), `not_running` (no status endpoint) |
| grey ! | `not_configured` |
| blue … | `attesting` |
| green ✓ | `healthy` |
| yellow ! | `cmis_unreachable`, `crl_stale`, `allowlist_missing`, `allowlist_invalid`, `svid_expiring` |
| red × | `not_enrolled`, `pin_mismatch`, `tpm_unavailable`, `ima_disabled` |

**Left click** (macOS, Windows) opens the window; **right click** opens the
menu. On Linux the status-icon protocol always shows the menu, whose first
command opens the window. The menu holds only what applies now (F23):

1. the summary line, and the result of the last action, if any;
2. the fixes for the worst state (for example **Start the service**), with the
   environment named when there are several;
3. **Open FerroGate…**; **Environments ▸** (only with two or more, each with
   its own fixes and default-environment action); **Review approvals…** (only
   when the admin client is installed, see below);
4. **Setup…** and **Quit**.

The details (state, problem, SPIFFE ID with expiry and renewal time, CMIS
node, CRL age, allowlist, attestation backend, X.509-SVID store, agent
version), **Logs** and **Run self-test** live in the window. A
`last_error.code` the tray does not know (a newer daemon) is shown
generically, with "Run self-test" offered.

**The default environment.** The environment that serves the helper API's
well-known address — `mia.sock` / `\\.\pipe\ferrogate-mia`, the one local
applications reach without configuration (see
[the default environment](mia.md#default-environment-who-serves-the-well-known-address))
— is marked **[default address]** in the Environments submenu and in the Status
tab, with a "Helper API: serves the well-known default address" line. Every
other environment's card in the Status tab (and its submenu, with two or more
environments) offers:

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

**Notifications** use the operating system's own centre (freedesktop
notifications on Linux, toasts on Windows, Notification Center on macOS) and
one format for everything: title **FerroGate**, the environment or app as the
subtitle, one or two short sentences, and a kind — information, done,
warning, error or approval pending (urgency is critical only for errors and
pending approvals). They fire on state transitions that need a human —
healthy → any degraded/broken/absent state, entering `svid_expiring`,
entering `crl_stale`, never for the state the tray starts in — and for the
result of an action run from the menu. Clicking one (or **Open**; **Review**
for approvals) opens the matching view; nothing is ever decided from a
notification, and none carries a code, secret, token, path or user name.
Linux and Windows show the buttons; macOS opens on click. A repeat of the
same kind replaces the previous one on Linux. Each (environment, kind) state
alert is de-duplicated for 30 minutes and at most 3 are sent per 10 minutes;
other notices are de-duplicated for a minute, 6 per 10 minutes. The same
message appears in the menu's second line and in the window's status bar, so
nothing is lost when no notification service is running.

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

There is one window, a separate process (`mia-tray --window <kind>`, a closed
set), drawn natively with egui — there is no web view, and every string from
the daemon or from `mia` is rendered as plain text with control and
bidirectional characters escaped. Opening it again from the menu or a
notification raises the open window at the right tab instead of starting
another: the tray writes `show <kind>` lines (a closed set, bounded lines) to
the window's standard input. It is freely resizable down to 380 × 300 points;
every page scrolls and wraps.

The **header** shows the state badge (glyph and text), the explanation, when
the status was last read and from where, the fixes for the worst state as
buttons, **Refresh**, and the **Language** selector (System default, English,
Português (Brasil), Español). The choice applies at once, is saved in the
per-user preference file (`mia-tray.toml` beside `admin.toml`, owner-only,
the language tag only) and the tray menu follows within two seconds. The
**status bar** at the bottom mirrors the notifications (newest first, with
**Dismiss**).

- **Status** — one card per environment: badge, explanation, fix buttons and
  the details folded under **Details**.
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

The tab loads the configuration when it opens; **Check and apply** then runs
the check and, only if `mia` accepted exactly the draft on screen, applies it
(one click instead of two; **Check only** stays available). In detail:

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
   the consent prompt for the system file — then keeps the accepted values on
   screen and refreshes agent status. It does not immediately start a second
   privileged read of the root-owned file; **Load** is the explicit boundary
   for that fresh consent prompt. `--reload` (signal the running agent) and
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

The optional administrator client (`mia-tray-admin`, see [Admin client](#admin-client-mia-tray-admin))
is **not** part of the workstation `ferrogate-mia` `.deb`, and it is off by
default in the MSI; it has its own packages (`make pkg-tray-admin`) and shows
up in the tray menu only once installed. It is meant for approvers on managed
devices: install it from [Installing the admin client](#installing-the-admin-client).

`MIA_TRAY=0 make pkg-macos` / `MIA_TRAY=0 make pkg-win` build the agent
packages without the tray (and so without the admin client);
`MIA_TRAY_ADMIN=0` leaves out only the Windows admin client; `MIA_TRAY_ADMIN_MACOS=0` leaves out only the macOS admin client (the `.pkg` ships it by default). On Windows `mia-tray.exe` is a GUI-subsystem
program (no console window at logon), so `mia-tray --help` / `--version` print
only when stdout is redirected (`mia-tray --version | more`). On Linux the tray needs a StatusNotifierItem host:
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
(runtime: `libgtk-3-0 libxdo3 libayatana-appindicator3-1`), and the admin
client (security keys over USB HID) also `libudev-dev` (runtime: `libudev1`). The
`.github/workflows/mia-tray.yml` workflow builds, lints and tests the GUI on
Linux, macOS and Windows.

| Variable | Effect |
|---|---|
| `FERROGATE_STATUS_SOCKET` | status endpoint address (same override `mia` honours) |
| `MIA_TRAY_MIA` | absolute path of a development `mia`, used for **unprivileged** actions only — never elevated |
| `MIA_TRAY_LOG` | the tray's own tracing directive on stderr (default `info`) |
| `MIA_TRAY_LANG` | the UI language (`en`, `pt-BR`, `es`), over the preference file |
| `LC_ALL` / `LC_MESSAGES` / `LANG` / `LANGUAGE`, then the OS locale | English, Portuguese (any `pt-*`) or Spanish (any `es-*`); anything else is English |

## Admin client (`mia-tray-admin`)

An optional, **separate binary** for FerroGate administrators (feature F22). It
is not part of the tray: `mia-tray` holds no credentials and links none of the
admin code, and nothing flows between the two. Build it with
`make tray-admin` (cargo feature `admin`, which implies `gui`); `make
check-tray-isolation` asserts that the `mia-tray` dependency graph contains no
`tonic`, `tokio`, `rustls`, `hyper`, `prost`, `ferro-transport`,
`ferro-proto`, `ferro-crypto`, `zeroize` or `ferrogate-admin-client`, that the
admin build does link `ferrogate-admin-client` (so the check is not blind), and
that `eframe` persistence stays off.

Current state (T280 to T285): sign-in and step-up against CMIS, token
enrollment and second-factor management, the request and approval views, adding
an application in one step, packaged on every desktop platform and offered from
the tray menu.

### Installing the admin client

**Who.** Approvers on managed devices only (FIDO2 is recommended and can be
required by the server policy). Regular workstations do not need it: the Debian
workstation package and the RPM tray package leave it out, and it is off by
default in the MSI (the macOS `.pkg` carries it in the bundle by default; build with
`MIA_TRAY_ADMIN_MACOS=0` to leave it out). It runs as the signed-in
user and **needs no privileges** at install time or run time: no group
membership (not `ferrogate-status`, not `ferrogate-clients`), no setuid or setgid,
no polkit action, no service, no autostart or login item, and no Windows
elevation manifest (`asInvoker`, like `mia-tray.exe`). Get the CMIS admin
endpoint and its pin from operations first (see [Configuration](#configuration)).

| Platform | How to install | Where it lands |
|---|---|---|
| Linux (Debian/Ubuntu) | `sudo apt install ./ferrogate-mia-tray-admin_<version>-1_amd64.deb` (`make pkg-deb-tray-admin`); depends on the tray (`ferrogate-mia` provides it) | `/usr/bin/mia-tray-admin` |
| Linux (RPM) | `sudo dnf install ./ferrogate-mia-tray-admin-<version>-1.x86_64.rpm` (`make pkg-rpm-tray-admin`); requires `ferrogate-mia-tray` | `/usr/bin/mia-tray-admin` |
| macOS | shipped by default in the same signed bundle as the tray; `MIA_TRAY_ADMIN_MACOS=0 make pkg-macos` leaves it out | `/Applications/FerroGate MIA.app/Contents/MacOS/mia-tray-admin` |
| Windows | the MSI feature **Admin client**, off by default: `msiexec /i ferrogate-mia-<version>-x64.msi ADDLOCAL=Main,AdminClient`, or with Chocolatey `choco install ferrogate-mia --params "'/AdminClient'"` (repeat the parameter on `choco upgrade`) | `%ProgramFiles%\FerroGate\MIA\mia-tray-admin.exe` |

On macOS the binary is signed with the same identity as the bundle
(`CODESIGN_ID`, ad hoc otherwise), hardened runtime, no entitlements. On every
platform it is installed beside `mia-tray`, owned by root and not writable by
anyone else.

**Menu entry.** Within a few seconds of installing (the tray looks again on every
status refresh, no restart needed) **Review approvals…** appears in the tray menu,
only when `mia-tray-admin` is found in the same directory as the running `mia-tray` *and* passes the same
trust rule `mia` must pass to run elevated (Unix: a regular file, not a link,
owned by root and not group- or world-writable, in a root-owned directory that is
not group- or world-writable; Windows: under the machine's Program Files). The
rule is checked again right before each launch. The tray starts it as you, with
no arguments and no elevation; the only thing that ever flows to it is a
`focus` line on its standard input, so a second click brings the open window
to the front instead of starting another. A copy in a
user-writable place (a development build, a Homebrew-owned `/usr/local/bin`) is
never offered: run such a build directly. The client also works without the tray
(run it from a terminal by the path above).

### Configuration

`admin.toml` holds the admin endpoint and its SPKI pin, nothing secret. The
client reads the first file that exists among the per-user file —
`~/.config/ferrogate/admin.toml` (or `$XDG_CONFIG_HOME/ferrogate/`) on Linux,
`~/Library/Application Support/FerroGate/admin.toml` on macOS,
`%APPDATA%\FerroGate\admin.toml` on Windows — and `/etc/ferrogate/admin.toml`
(Unix):

```toml
endpoint          = "https://cmis-admin.example.internal:8444"  # explicit port
spki_pins         = ["<sha384-hex>"]                            # required
device_token_path = ""   # default: device-token beside the per-user file (0600)
```

`FERROGATE_ADMIN_ENDPOINT` and `FERROGATE_ADMIN_SPKI_PIN` override the file.
The file is the same format the TUI reads and passes the same checks (opened
without following a symlink, owned by you or root, not group/other-writable,
directories above it too; unknown keys refused). Without a pin the window sends
nothing: there is no trust on first use. Get the pin from operations over a
trusted channel (`ferrogate spki-pin --tls-cert …` on a CMIS node); the sign-in
window shows the endpoint and a short pin fingerprint to compare.

**Admin server screen.** With no usable configuration the window opens on the
**Admin server** screen instead of the sign-in form; **Change server…** beside
the server line (signed out only) opens it too. It has two fields, the admin
endpoint (`https://host:port`) and the SPKI pin (96 hex digits), and **Save**.
Both are checked by the same parser as the file (https only, a host and an
explicit port, no user information, path or query; exactly one SHA-384 in hex),
and the screen names what is wrong. The pin is only ever what you paste: the
client never fetches the server's certificate to pin it, and **Change server…**
pre-fills the endpoint but never the pin. Save writes the per-user file above
(directory created `0700`, an existing one of yours made private; file `0600`,
written to a temporary file and renamed over the old one; a symlink, a file of
another user or a group/other-writable file or directory is refused and
nothing is written), then reloads it and shows the sign-in form; no restart.
When a file is in effect, Save first shows its endpoint and every pin beside the
new ones and asks you to **Replace**. Its `device_token_path` and
`refresh_secs` are kept, every old pin is replaced by the one pasted, and
comments are not kept; a file that does not parse is replaced by the endpoint
and pin only. A system file (`/etc/ferrogate/admin.toml`) is never written: a
per-user file is created that takes precedence over it. When
`FERROGATE_ADMIN_ENDPOINT` or `FERROGATE_ADMIN_SPKI_PIN` is set the screen says
so: the variable keeps winning over what you save. Each save logs
`admin.client.server_config_changed` with the endpoint and the new and previous
pin fingerprints (no path, nothing secret).

### Signing in and stepping up

Sign-in is one screen (F23); the F20 protocol is unchanged — the same
`BeginLogin` and `Login` calls, in the same order, as before.

1. Type the user name and press **Tab** or **Enter** (the hint under the
   field says so). Leaving the field sends only the user name
   (`BeginLogin`, client kind 2), once — a second Tab or Enter for the same
   name sends nothing, and a "Checking…" spinner shows while it runs. The
   answer says which second factors the account may use here; unknown
   names get the same plausible answer from the server, and the window
   treats both alike (no "user not found", no extra delay of its own).
2. The fields that answer calls for appear **below the name, on the same
   screen**: the password and the authenticator code (**Sign in**, or Enter
   in the code), the password and **Use security key**, or both buttons.
   Under `CMIS_ADMIN_TRAY_FIDO2_GROUPS` no code field is shown. Nothing is
   shown before the answer. Editing the name drops the answer and anything
   typed below it; leaving the field asks again. An answer that lands for a
   name already edited is ignored. Sign-in itself still runs a fresh
   `BeginLogin` right before `Login`, so the window never holds a nonce;
   if the answer on screen is older than a nonce lives (2 min), it is asked
   again before signing in, with what you typed kept. The password and code
   are wiped when submitted, nothing is written to disk, and the user name
   is not remembered between runs.
3. Signed in, the window opens on the **pending requests** (below). One line
   shows where you are (**Account › Requests › R-… › Approve R-…**) and the
   session: display name, assurance level (AAL3 for a device-bound key) and
   groups, with **Confirm it is you** (step-up: `BeginStepUp`/`StepUp` with a
   code or a key; the server rotates the token), **Second factors** and
   **Sign out**. The user name is not remembered between runs (F22 keeps
   nothing on disk).

Failures are generic ("Sign-in failed"), a throttle shows its countdown, and a
factor that is not offered or a cancelled key prompt sends no `Login`, so it
counts no throttle failure. An expired password ends the session with a pointer
to `ferrogate-tui` or the CLI. An account that must register a key first
(FIDO2 policy) gets the restricted session described below; without a key
backend in this build it is told so and the session ends.

The window locks 30 s before the server's idle timeout (the server value is
clamped to 1–15 min), also on a half-typed form: everything is wiped and the
session is logged out. **Sign out**, the lock and closing the window end the
session at once (the token leaves memory before any network call) and a
separate task sends `Logout`; a session answered after a lock is logged out,
never shown.

**Security keys.** The client builds the WebAuthn `clientDataJSON` itself with
origin `https://<RP ID>` (CMIS's default origin; if `CMIS_ADMIN_WEBAUTHN_ORIGINS`
is set it must include it) and refuses any RP ID that is not
`ferrogate-admin.<trust domain>`, so a server cannot use the key for another
site; user verification is always required. The authenticator is reached
through the `ferrogate_admin_client::webauthn::Authenticator` trait.

- **macOS and Linux:** FIDO2 keys (YubiKey and the like) over USB, CTAP2
  through Mozilla's `authenticator` crate. The window says when to touch the
  key, or which of several keys to touch. **The PIN is typed in this window**:
  raw USB HID has no system PIN prompt, so this is the one secret the client
  handles that is not for CMIS. It goes into a masked field (dots only, fed
  from the key events, never a text widget, at most 63 bytes, at least 4
  characters), is handed to the key and nowhere else (never to CMIS, a file,
  the clipboard or the log), and is wiped on submit, **Cancel**/`Esc`,
  sign-out, the idle lock and close. A wrong PIN is asked again, with a warning on the last attempt.
  Keys with a built-in fingerprint reader use it instead of the PIN. The
  library's own log (credential ids, PIN hashes, HID frames) is dropped
  whatever `MIA_TRAY_LOG` says. A new key is registered with `none`
  attestation. On Linux the logged-in user needs access to the key's
  `/dev/hidraw*` node (systemd's `uaccess` rule for FIDO devices grants it on
  current distributions).
- **Windows:** the system's WebAuthn API (`webauthn.dll`, loaded from
  System32 only). **Windows Security shows its own dialog** for the touch,
  the PIN or the fingerprint: the PIN never passes through this client, and
  the window only says to follow that prompt. The dialog is parented to the
  admin window; the idle lock, sign-out and close cancel it. A new key is
  registered as ES256 with `none` attestation (a server that accepts only
  EdDSA keys is refused with a logged reason); roaming keys only, no Windows
  Hello. Without `webauthn.dll` (Windows older than 10 1903) the key button
  is disabled with an explanation, and TOTP works unless the FIDO2 policy
  requires a key.

The flows are tested with a software authenticator against an in-process CMIS,
the USB HID backend with a scripted key and the Windows backend with a
scripted API; no real key and no real `webauthn.dll` were used in tests.

### Enrolling and managing second factors

**Enroll with a token…** (on the sign-in screen) redeems a single-use
enrollment or reset token, pasted into a masked field (`BeginEnrollment`). The
wizard shows the account name, asks for the new password twice (at least the
policy's length; the server checks the rest and a reset that kept the password
ignores it), and then, as the token offers:

- **authenticator app (TOTP):** the seed as a QR code painted in memory, and as
  text on request (**Show the key as text**), then the code the app shows;
- **security key:** an optional label and **Register security key** (the
  key's own `makeCredential` prompt, user verification required, `none`
  attestation; the client writes the `clientDataJSON` as for sign-in).

At least one factor is required and both are recommended; **Finish
enrollment** sends the password and the proof of each (`CompleteEnrollment`). A
password-only reset asks for the current authenticator's code instead. A
bootstrap token is refused here: the first operator enrolls with `ferrogate
admin bootstrap` on the server host.

Signed in, **Second factors** lists the account's factors (`ListMyFactors`,
labels escaped) and offers **Add an authenticator app** (when the account has
none; proven with a security key), **Add a security key** (proven with a code
or another key) and **Remove** (never the last one; the account's other
sessions end). Adding asks the server first (`BeginAddFactor`, which needs a
step-up in the last 5 minutes: the window asks for it and then goes on), then
a fresh proof of a factor already held (`CompleteAddFactor`; a key proof signs
a fresh `BeginStepUp` challenge). A refused code or proof changes nothing and
the add starts again with a new seed.

Under `CMIS_ADMIN_TRAY_FIDO2_GROUPS`, an account without a key that signs in
with its code gets a **restricted** session: the window offers only **Register
a security key** (proven with the code), then ends the session so the
administrator signs in again with the key.

The seed is shown once: it lives in wiped buffers (the URI is wiped as soon as
the QR matrix and the text are made), is never copied to the clipboard, and is
dropped when the wizard or form closes, is used, or the window locks. The QR
code is painted as squares and the text one character at a time, so no `egui`
galley holds the seed (tests scan the painted shapes and `egui` memory).

### Requests and approvals

Signed in, the window opens on **Requests** filtered to pending ones; the
tab counts them ("Requests · 3 pending") and the status bar says how many
wait (a count only; an OS notification only when the window is in the
background). **Requests** and **Approvals** switch between the views
(F22 §4, the F21 flows). The window first reads the session's permissions
(`WhoAmI`): they decide which buttons are drawn, as a convenience only, since
CMIS's `AdminAuthz` checks every call. The lists page through
`ListAppRequests` / `ListApprovals` (50 rows a page) with **Search and
filters…**: state, origin, kind or policy, preset, superseded, oldest first,
free text, path, product, version, host UUID, user, hash prefix, dates and
lineage. Values are checked before anything is sent (a date is `YYYY-MM-DD`, a
hash prefix 8 to 96 hex, a host a UUID, texts at most 128 characters) and go as
separate protobuf fields.

**Open** shows a request (path, SHA-384, version, host, user, requester, the
requester's reason, signer, risk warnings, the lineage's approvals) or an
approval (terms, expiry, note, row version). From there:

- **Approve…** starts from the safe defaults: manual, anchored, this user,
  exact path, server-default expiry. Auto-update is preselected only on a
  protected path or the same valid signer as the lineage's previous active or
  expired revision; older approvals of the lineage can be revoked with it;
- **Deny…** takes a reason code and an optional message (at most 200
  characters, no personal data);
- **Edit or renew…** only narrows the user and path scope; a future expiry
  renews an expired approval;
- **Revoke…** takes a reason and the typed short id (`A-` and the last eight
  characters of the id);
- **Freeze or unfreeze…** stops or resumes auto-updates of the lineage.

Approve and deny show, under the form, **What will be sent**: the review
lines, live. With a narrow scope **Approve and send** / **Deny and send**
sends it at once (step 1 of 2 saved). "Any user" and "path + user only" are
never sent from the form: they need an extra **Accept the wider scope** and
the review page with **Confirm and send** (steps 1–3 of 3), and auto-update
for any user needs a protected path. Edits, revocations, freezes and adds
keep the review page. Enter never sends; each send uses a fresh idempotency
key.
When the server asks for a step-up, the window opens the step-up prompt and then
sends the same request once more (same key); a second request for a step-up is
not looped, and cancelling the prompt sends nothing more. An edit refused as
changed meanwhile (`ABORTED`) reloads the approval, names what changed and asks
again. After each decision the window shows its outcome and reloads the record.

The rules, the filters and the calls are the TUI's, from
`ferrogate-admin-client::approvals`. Every server string is shown as plain text
with controls, bidi and zero-width characters made visible, failures are shown
by kind only (the reason goes to the log), and an idle lock, sign-out or close
drops every record shown.

### Adding an application

**Add application…** (shown with `app.direct_register`) registers a binary whose
SHA-384 and path you already know, the tray's version of the TUI's `A` dialog
(F22 §5): host UUID, platform, canonical path, SHA-384 (exactly 96 hex
characters, typed or pasted; sent lowercased), a Unix uid or a Windows SID or
RID, user name, optional declared version and reason, and the "path writable
only by administrators" box, followed by the same approval terms, safe
defaults and wide-scope confirmation as **Approve…**. The fields are checked
before anything is sent, by the rules the TUI uses
(`ferrogate-admin-client::approvals::register`).

The review page says what will happen: the add **registers AND approves** the
application in one step and is recorded as approved by the same person
(`AppApprovedBySameActor`), or, without `app_request.approve` or under the
server's strict separation of duties (`CMIS_ADMIN_STRICT_SOD`), only queues a
request for a different approver. It also says that the hash, the path and the
protected-path box are **your assertion**: nothing checks them against the
host, the approval pins the exact hash, and MIA re-hashes the binary at every
mint, so a wrong hash grants nothing.

**Confirm with a fresh second factor…** always opens the second-factor prompt,
even right after a step-up: every add carries its own proof (a TOTP code, or a
key touch where the session offers one), sent with `AdminRegisterApplication`.
A wrong code changes nothing and the prompt asks again for the same request, so
the retry reuses its idempotency key (so does a retry after no answer); closing
the prompt sends nothing. The outcome names the request and approval
("Registered and approved", "Queued for another approver" or "Already
approved") and the list reloads. Picking a local file, identifying it with
`ferro-appid`, taking this machine's host UUID and "Sync this machine now" are
not in the tray yet.

Credential handling:

- the password and the TOTP code live in fixed-capacity `Zeroizing` buffers
  (`admin::secret::Secret`, shared with the TUI through
  `ferrogate-admin-client`) with no `Debug`, `Display` or `Clone`, checked at
  compile time; they are moved into the one request that carries them and
  wiped when it returns;
- the session token has the same guarantees and lives only in the worker
  thread's session slot: never in a view model (tests serialise the views and
  scan them), a file, the clipboard or a log;
- the window never gives a secret to an `egui` text widget: it reads the
  keystrokes straight from the input events and hands them to the model by
  reference, and draws the mask from a length, so `egui`'s undo history and
  galley cache never hold a copy (tests type a password through real frames and
  scan the painted text and `egui` memory);
- the buffers are wiped on submit, on `Esc`, when the window closes and on lock;
- nothing is persisted: `persist_window` and `persist_egui_memory` are off, there
  is no "remember me", and the window title never carries a user name.

Residual risk: the toolkit keeps a typed character in its per-frame input queue
until the frame ends, and input-method (IME) composition is not supported in the
secret fields. prost's request buffers cannot be wiped (F20 §13): a password,
code or enrollment token is in one encoded request for the duration of that
call, and the QR encoder's scratch buffers are freed unwiped. If closing the
window cannot get the `Logout` out within 3 s, the process exits anyway and the
server's idle timeout ends the session.

## Limitations

- On Linux without a StatusNotifierItem host the icon is not visible; the tray
  still sends notifications, and `mia status` remains the universal path.
- Unsigned builds: macOS may attribute notifications to another application and
  Gatekeeper may warn; Windows SmartScreen warns. Sign with `CODESIGN_ID` /
  `WIN_SIGN_PFX` like `mia`.
- Configuration changes are gated by the local OS administrator prompt; whether
  that satisfies FGV NRM §5.3.1 (MFA for sensitive operations) on workstations
  is an open point for ESI validation (see the F18 spec).
