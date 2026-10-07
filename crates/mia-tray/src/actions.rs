//! Recovery and maintenance actions: a **closed set** of fixed command lines.
//!
//! Nothing here builds a command from free text. An [`Action`] (or a setup
//! step) maps to an [`Invocation`] — a program chosen from [`Program`] plus
//! arguments that are string literals, a validated [`EnvName`], or a path the
//! tray created itself (the wizard draft) and re-validated by
//! [`checked_path_arg`]. Read-only actions run as the user; state-changing ones
//! are wrapped by [`spec`] in the platform's consent mechanism:
//!
//! | OS | wrapper | cancel ⇒ |
//! |----|---------|----------|
//! | Linux | `pkexec <abs-program> <args…>` (polkit; the `mia` actions carry the `br.fgv.ferrogate.mia.setup` policy) | exit 126 |
//! | macOS | `osascript` running a fixed script that shell-quotes every argument with `quoted form of` and runs it `with administrator privileges` | error −128 |
//! | Windows | `powershell.exe` running a fixed script that calls `Start-Process -Verb RunAs` (UAC) with the program and argument string taken from environment variables | exit 1223 |
//!
//! In none of them is a variable value interpolated into script or shell
//! text: macOS and Windows receive the values as `argv` / environment data,
//! and Linux never involves a shell. Cancelling the prompt is reported as
//! [`Outcome::Cancelled`], not as a failure.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::i18n::Msg;
use crate::locate::MiaBinary;
use crate::process::{run_bounded, Captured, Limits};

/// The platforms the tray drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    /// Linux (systemd, polkit).
    Linux,
    /// macOS (launchd, Authorization Services).
    MacOs,
    /// Windows (SCM, UAC).
    Windows,
}

impl Os {
    /// The platform this binary was built for; `None` elsewhere (no actions).
    #[must_use]
    pub const fn current() -> Option<Self> {
        if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(windows) {
            Some(Self::Windows)
        } else {
            None
        }
    }
}

/// Who an invocation runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// The logged-in user (no prompt).
    User,
    /// An administrator, through the OS consent prompt.
    Admin,
}

/// The programs the tray may run. Paths are fixed per OS (see [`Tools`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// The located `mia` binary.
    Mia,
    /// `systemctl` (Linux).
    Systemctl,
    /// `launchctl` (macOS).
    Launchctl,
    /// Windows PowerShell (only for the fixed `Restart-Service -Name mia`).
    PowerShell,
}

/// Recovery / maintenance actions offered by the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// `mia test --json` (user).
    RunSelfTest,
    /// `mia machine-id` (user).
    ShowMachineId,
    /// `mia status --json` (user).
    ShowStatus,
    /// Start the `mia` service (admin).
    ServiceStart,
    /// Stop the `mia` service (admin).
    ServiceStop,
    /// Restart the `mia` service (admin).
    ServiceRestart,
    /// `mia resync-allowlist --reload` (admin).
    ResyncAllowlist,
    /// `mia refresh-key` (admin).
    RefreshKey,
    /// `mia default-environment set <env>` (admin): hand the helper API's
    /// well-known address to `<env>`. For the `mia.toml` environment (no
    /// name) it is `mia default-environment clear` — the same outcome.
    SetDefaultEnvironment,
    /// `mia default-environment clear` (admin): `mia.toml` serves the
    /// well-known address again.
    ClearDefaultEnvironment,
}

impl Action {
    /// Every action, in display order.
    pub const ALL: [Self; 10] = [
        Self::RunSelfTest,
        Self::ShowMachineId,
        Self::ShowStatus,
        Self::ServiceStart,
        Self::ServiceStop,
        Self::ServiceRestart,
        Self::ResyncAllowlist,
        Self::RefreshKey,
        Self::SetDefaultEnvironment,
        Self::ClearDefaultEnvironment,
    ];

    /// Read-only actions run as the user; the rest need consent.
    #[must_use]
    pub fn privilege(self) -> Privilege {
        match self {
            Self::RunSelfTest | Self::ShowMachineId | Self::ShowStatus => Privilege::User,
            Self::ServiceStart
            | Self::ServiceStop
            | Self::ServiceRestart
            | Self::ResyncAllowlist
            | Self::RefreshKey
            | Self::SetDefaultEnvironment
            | Self::ClearDefaultEnvironment => Privilege::Admin,
        }
    }

    /// Whether the action takes `-e <env>`.
    #[must_use]
    pub fn takes_environment(self) -> bool {
        matches!(
            self,
            Self::RunSelfTest
                | Self::ShowStatus
                | Self::ResyncAllowlist
                | Self::RefreshKey
                | Self::SetDefaultEnvironment
        )
    }

    /// Whether a successful run only takes effect when the service restarts
    /// (the default environment is read at startup).
    #[must_use]
    pub fn applies_on_restart(self) -> bool {
        matches!(
            self,
            Self::SetDefaultEnvironment | Self::ClearDefaultEnvironment
        )
    }

    /// The label.
    #[must_use]
    pub fn label(self) -> Msg {
        match self {
            Self::RunSelfTest => Msg::ActionRunSelfTest,
            Self::ShowMachineId => Msg::ActionShowMachineId,
            Self::ShowStatus => Msg::ActionShowStatus,
            Self::ServiceStart => Msg::ActionServiceStart,
            Self::ServiceStop => Msg::ActionServiceStop,
            Self::ServiceRestart => Msg::ActionServiceRestart,
            Self::ResyncAllowlist => Msg::ActionResyncAllowlist,
            Self::RefreshKey => Msg::ActionRefreshKey,
            Self::SetDefaultEnvironment => Msg::ActionSetDefaultEnvironment,
            Self::ClearDefaultEnvironment => Msg::ActionClearDefaultEnvironment,
        }
    }

    /// Output and time bounds.
    #[must_use]
    pub fn limits(self) -> Limits {
        match (self.privilege(), self) {
            (Privilege::Admin, _) => Limits::ELEVATED,
            (_, Self::RunSelfTest) => Limits::NETWORK,
            _ => Limits::QUICK,
        }
    }
}

/// Why an action could not be run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    /// No `mia` binary was found.
    #[error("mia was not found")]
    MiaNotFound,
    /// `mia` is not in a location that may be run elevated.
    #[error("mia is not in a trusted location for elevation")]
    MiaUntrusted,
    /// A system tool to be run elevated failed the trust rule.
    #[error("a system tool is not in a trusted location for elevation")]
    ToolUntrusted,
    /// A required system tool is missing (`pkexec`, `osascript`, …).
    #[error("missing system tool: {0}")]
    ToolMissing(&'static str),
    /// Not available on this platform.
    #[error("not supported on this platform")]
    Unsupported,
    /// An environment name failed validation.
    #[error("invalid environment name")]
    BadEnvironment,
    /// A path argument failed validation.
    #[error("invalid path argument")]
    BadPath,
    /// An option combination `mia` would refuse.
    #[error("invalid option combination: {0}")]
    BadOptions(&'static str),
    /// The command could not be started.
    #[error("could not start the command: {0}")]
    Spawn(String),
}

impl ActionError {
    /// The friendly message for the UI.
    #[must_use]
    pub fn message(&self) -> Msg {
        match self {
            Self::MiaNotFound => Msg::ErrorMiaNotFound,
            Self::MiaUntrusted => Msg::ErrorMiaUntrusted,
            Self::ToolUntrusted => Msg::ErrorToolUntrusted,
            Self::ToolMissing(_) => Msg::ErrorNoElevationTool,
            Self::Unsupported | Self::BadOptions(_) => Msg::ErrorUnsupported,
            Self::BadEnvironment => Msg::ErrorBadEnvironment,
            Self::BadPath | Self::Spawn(_) => Msg::ErrorStartFailed,
        }
    }
}

/// A validated environment name: [`mia_status_proto::validate_environment`]
/// (the rule `mia` itself applies) plus the status endpoint's length cap.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnvName(String);

impl EnvName {
    /// Validate `name`.
    pub fn parse(name: &str) -> Result<Self, ActionError> {
        // Stricter than `mia` in one respect: a leading `-` is refused, so a
        // name can never be mistaken for an option by any argument parser
        // (e.g. `resync-allowlist` strips `--reload` from the whole argv).
        if name.len() > mia_status_proto::MAX_ENVIRONMENT_LEN || name.starts_with('-') {
            return Err(ActionError::BadEnvironment);
        }
        mia_status_proto::validate_environment(name).map_err(|_| ActionError::BadEnvironment)?;
        Ok(Self(name.to_string()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated SHA-384 fingerprint of the CMIS enrollment public key.
///
/// This is public key metadata, accepted in the same 96-character hexadecimal
/// form printed by `ferrogate enrollment-key` and consumed by
/// `mia allowlist-key fetch --expect-fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentKeyFingerprint(String);

impl EnrollmentKeyFingerprint {
    /// Validate and normalise a textual enrollment-key fingerprint.
    pub fn parse(input: &str) -> Result<Self, ActionError> {
        const SHA384_HEX_LEN: usize = 96;
        let value = input.trim();
        if input.len() > 256
            || value.len() != SHA384_HEX_LEN
            || !value.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ActionError::BadOptions(
                "invalid enrollment-key fingerprint",
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// The normalised lowercase hexadecimal fingerprint.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One fixed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// What to run.
    pub program: Program,
    /// Its arguments.
    pub args: Vec<String>,
    /// Who runs it.
    pub privilege: Privilege,
    /// Output and time bounds.
    pub limits: Limits,
    /// What the consent prompt says (macOS shows it; fixed text).
    pub purpose: Msg,
}

fn env_args(args: &mut Vec<String>, env: Option<&EnvName>) {
    if let Some(e) = env {
        args.push("-e".into());
        args.push(e.as_str().to_string());
    }
}

/// The macOS launchd label and plist of the `mia` daemon.
const LAUNCHD_LABEL: &str = "system/com.ferrogate.mia";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.ferrogate.mia.plist";

/// The fixed command line for `action` (environment ignored when the action
/// takes none).
#[must_use]
pub fn invocation(action: Action, env: Option<&EnvName>, os: Os) -> Invocation {
    let env = env.filter(|_| action.takes_environment());
    let strings = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    let (program, args) = match (action, os) {
        (Action::RunSelfTest, _) => {
            let mut a = strings(&["test", "--json"]);
            env_args(&mut a, env);
            (Program::Mia, a)
        }
        (Action::ShowMachineId, _) => (Program::Mia, strings(&["machine-id"])),
        (Action::ShowStatus, _) => {
            let mut a = strings(&["status", "--json"]);
            env_args(&mut a, env);
            (Program::Mia, a)
        }
        (Action::ResyncAllowlist, _) => {
            let mut a = strings(&["resync-allowlist", "--reload"]);
            env_args(&mut a, env);
            (Program::Mia, a)
        }
        (Action::RefreshKey, _) => {
            let mut a = strings(&["refresh-key"]);
            env_args(&mut a, env);
            (Program::Mia, a)
        }
        // The name is a positional argument here; an `EnvName` never starts
        // with `-`, so `mia` cannot read it as an option.
        (Action::SetDefaultEnvironment, _) => match env {
            Some(e) => {
                let mut a = strings(&["default-environment", "set"]);
                a.push(e.as_str().to_string());
                (Program::Mia, a)
            }
            None => (Program::Mia, strings(&["default-environment", "clear"])),
        },
        (Action::ClearDefaultEnvironment, _) => {
            (Program::Mia, strings(&["default-environment", "clear"]))
        }
        (Action::ServiceStart, Os::Linux) => {
            (Program::Systemctl, strings(&["start", "mia.service"]))
        }
        (Action::ServiceStop, Os::Linux) => (Program::Systemctl, strings(&["stop", "mia.service"])),
        (Action::ServiceRestart, Os::Linux) => {
            (Program::Systemctl, strings(&["restart", "mia.service"]))
        }
        (Action::ServiceStart, Os::MacOs) => (
            Program::Launchctl,
            strings(&["bootstrap", "system", LAUNCHD_PLIST]),
        ),
        (Action::ServiceStop, Os::MacOs) => {
            (Program::Launchctl, strings(&["bootout", LAUNCHD_LABEL]))
        }
        (Action::ServiceRestart, Os::MacOs) => (
            Program::Launchctl,
            strings(&["kickstart", "-k", LAUNCHD_LABEL]),
        ),
        (Action::ServiceStart, Os::Windows) => (Program::Mia, strings(&["service", "start"])),
        (Action::ServiceStop, Os::Windows) => (Program::Mia, strings(&["service", "stop"])),
        (Action::ServiceRestart, Os::Windows) => (
            Program::PowerShell,
            strings(&[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Restart-Service -Name mia",
            ]),
        ),
    };
    Invocation {
        program,
        args,
        privilege: action.privilege(),
        limits: action.limits(),
        purpose: action.label(),
    }
}

// ── Setup (`mia setup --dump / --check / --apply`) ───────────────────────────

/// Which configuration file the wizard edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// The system file the service reads (elevated apply).
    #[default]
    System,
    /// The per-user file (`--user`, no elevation).
    User,
}

/// Options for [`apply_invocation`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplyOptions {
    /// Target file.
    pub scope: Scope,
    /// `-e <env>`.
    pub environment: Option<EnvName>,
    /// `--reload` (system scope only: it signals the system service).
    pub reload: bool,
    /// `--fetch-enrollment-key`.
    pub fetch_enrollment_key: bool,
    /// `--expect-fingerprint <hex>` for the fetched enrollment key.
    pub expected_enrollment_key_fingerprint: Option<EnrollmentKeyFingerprint>,
}

/// Longest path argument accepted.
pub const MAX_PATH_ARG: usize = 4096;

/// A path the tray passes to `mia`: absolute, UTF-8, bounded, and free of
/// control characters and double quotes (so it survives every platform's
/// argument quoting unchanged).
pub fn checked_path_arg(path: &Path) -> Result<String, ActionError> {
    let s = path.to_str().ok_or(ActionError::BadPath)?;
    if !path.is_absolute()
        || s.len() > MAX_PATH_ARG
        || s.chars().any(|c| c.is_control() || c == '"')
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ActionError::BadPath);
    }
    Ok(s.to_string())
}

/// `mia setup --dump --json [--user] [-e <env>]` (user).
#[must_use]
pub fn dump_invocation(scope: Scope, env: Option<&EnvName>) -> Invocation {
    let mut args = vec!["setup".to_string(), "--dump".into(), "--json".into()];
    if scope == Scope::User {
        args.push("--user".into());
    }
    env_args(&mut args, env);
    Invocation {
        program: Program::Mia,
        args,
        privilege: Privilege::User,
        limits: Limits::QUICK,
        purpose: Msg::SetupLoad,
    }
}

/// `mia setup --check <draft> --json` (user).
pub fn check_invocation(draft: &Path) -> Result<Invocation, ActionError> {
    Ok(Invocation {
        program: Program::Mia,
        args: vec![
            "setup".into(),
            "--check".into(),
            checked_path_arg(draft)?,
            "--json".into(),
        ],
        privilege: Privilege::User,
        limits: Limits::QUICK,
        purpose: Msg::SetupCheck,
    })
}

/// `mia setup --apply <draft> --json [--user] [-e <env>] [--reload]
/// [--fetch-enrollment-key [--expect-fingerprint <hex>]]` — as the user for
/// [`Scope::User`], elevated for [`Scope::System`].
pub fn apply_invocation(draft: &Path, opts: &ApplyOptions) -> Result<Invocation, ActionError> {
    if opts.reload && opts.scope == Scope::User {
        return Err(ActionError::BadOptions(
            "--reload signals the system service",
        ));
    }
    if opts.expected_enrollment_key_fingerprint.is_some() && !opts.fetch_enrollment_key {
        return Err(ActionError::BadOptions(
            "--expect-fingerprint requires --fetch-enrollment-key",
        ));
    }
    let mut args = vec![
        "setup".to_string(),
        "--apply".into(),
        checked_path_arg(draft)?,
        "--json".into(),
    ];
    if opts.scope == Scope::User {
        args.push("--user".into());
    }
    env_args(&mut args, opts.environment.as_ref());
    if opts.reload {
        args.push("--reload".into());
    }
    if opts.fetch_enrollment_key {
        args.push("--fetch-enrollment-key".into());
    }
    if let Some(fingerprint) = &opts.expected_enrollment_key_fingerprint {
        args.push("--expect-fingerprint".into());
        args.push(fingerprint.as_str().to_string());
    }
    let (privilege, limits) = match opts.scope {
        Scope::System => (Privilege::Admin, Limits::ELEVATED),
        Scope::User => (
            Privilege::User,
            if opts.fetch_enrollment_key {
                Limits::NETWORK
            } else {
                Limits::QUICK
            },
        ),
    };
    Ok(Invocation {
        program: Program::Mia,
        args,
        privilege,
        limits,
        purpose: Msg::ActionApplySetup,
    })
}

// ── Elevation wrappers ───────────────────────────────────────────────────────

/// The fixed system tools, located once.
#[derive(Debug, Clone)]
pub struct Tools {
    /// The located `mia`.
    pub mia: Option<MiaBinary>,
    /// `systemctl`.
    pub systemctl: Option<PathBuf>,
    /// `launchctl`.
    pub launchctl: Option<PathBuf>,
    /// `powershell.exe`.
    pub powershell: Option<PathBuf>,
    /// `pkexec`.
    pub pkexec: Option<PathBuf>,
    /// `osascript`.
    pub osascript: Option<PathBuf>,
    /// The elevation trust rule applied to every program right before it is
    /// run elevated ([`crate::locate::trusted_for_elevation`]; replaceable
    /// only so tests can use paths that do not exist on the test host).
    pub trust: fn(&Path) -> bool,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            mia: None,
            systemctl: None,
            launchctl: None,
            powershell: None,
            pkexec: None,
            osascript: None,
            trust: crate::locate::trusted_for_elevation,
        }
    }
}

impl Tools {
    /// Locate everything at its fixed path for this OS.
    #[must_use]
    pub fn discover() -> Self {
        use crate::locate::first_existing;
        // From HKLM, not %SystemRoot% (see `locate`).
        let powershell = crate::locate::windows_dir().map(|root| {
            root.join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        });
        Self {
            mia: crate::locate::locate_mia(),
            systemctl: first_existing(&["/usr/bin/systemctl", "/bin/systemctl"]),
            launchctl: first_existing(&["/bin/launchctl"]),
            powershell: powershell.filter(|p| p.is_file()),
            pkexec: first_existing(&["/usr/bin/pkexec", "/bin/pkexec"]),
            osascript: first_existing(&["/usr/bin/osascript"]),
            trust: crate::locate::trusted_for_elevation,
        }
    }
}

/// A concrete process to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// Absolute program path.
    pub program: PathBuf,
    /// Arguments, passed as `argv` (never through a shell).
    pub args: Vec<OsString>,
    /// Extra environment variables (data for the Windows wrapper).
    pub env: Vec<(String, OsString)>,
}

impl Spec {
    /// The [`Command`] for this spec.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut c = Command::new(&self.program);
        c.args(&self.args);
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }
}

/// The fixed AppleScript run by `osascript` for elevated actions on macOS.
/// `argv` item 1 is the prompt; the rest is the command, each item shell-quoted
/// with `quoted form of` before `do shell script` sees it.
pub const MACOS_ELEVATE_SCRIPT: [&str; 9] = [
    "on run argv",
    "set p to item 1 of argv",
    "set c to \"\"",
    "repeat with i from 2 to (count of argv)",
    "set c to c & quoted form of (item i of argv) & \" \"",
    "end repeat",
    "return do shell script c with prompt p with administrator privileges without altering line endings",
    "end run",
    "",
];

/// The fixed PowerShell run for elevated actions on Windows. The program and
/// its (already quoted) argument string arrive in [`WIN_FILE_VAR`] /
/// [`WIN_ARGS_VAR`] — data, never script text. It calls
/// `Process.Start` with the `runas` verb directly (rather than
/// `Start-Process`, which re-throws a UAC refusal without its
/// `Win32Exception`), so a declined prompt is recognisable: it exits 1223
/// (`ERROR_CANCELLED`).
pub const WINDOWS_ELEVATE_SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
try { \
$psi = New-Object System.Diagnostics.ProcessStartInfo; \
$psi.FileName = $env:FG_TRAY_ELEVATE_FILE; \
$psi.Arguments = $env:FG_TRAY_ELEVATE_ARGS; \
$psi.Verb = 'runas'; \
$psi.UseShellExecute = $true; \
$psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden; \
$p = [System.Diagnostics.Process]::Start($psi); \
if ($null -eq $p) { exit 1 }; \
$p.WaitForExit(); \
exit $p.ExitCode \
} catch { \
$e = $_.Exception; \
while ($e) { if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223) { exit 1223 }; $e = $e.InnerException }; \
exit 1 \
}";

/// Environment variable carrying the elevated program on Windows.
pub const WIN_FILE_VAR: &str = "FG_TRAY_ELEVATE_FILE";
/// Environment variable carrying the elevated argument string on Windows.
pub const WIN_ARGS_VAR: &str = "FG_TRAY_ELEVATE_ARGS";

/// Quote one argument for a Windows command line (the `CommandLineToArgvW` /
/// MSVC CRT rules), so `Start-Process -ArgumentList` hands it to the program
/// unchanged.
#[must_use]
pub fn windows_quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Every elevated argument must be printable and bounded (defence in depth on
/// top of the closed set: nothing that could alter a prompt's or a command
/// line's structure).
fn safe_elevated_arg(a: &str) -> bool {
    a.len() <= MAX_PATH_ARG && !a.chars().any(|c| c.is_control() || c == '"')
}

/// The prompt text for an elevated invocation (fixed, English: the OS prompt
/// is a security surface, so it is not localised by the tray).
fn prompt_text(inv: &Invocation) -> String {
    format!(
        "FerroGate MIA: {}. Administrator approval is required.",
        inv.purpose.text(crate::i18n::Lang::En)
    )
}

/// The absolute path of `inv`'s program on `os`.
fn resolve_program(inv: &Invocation, os: Os, tools: &Tools) -> Result<PathBuf, ActionError> {
    Ok(match inv.program {
        Program::Mia => {
            let mia = tools.mia.as_ref().ok_or(ActionError::MiaNotFound)?;
            if inv.privilege == Privilege::Admin && !mia.trusted {
                return Err(ActionError::MiaUntrusted);
            }
            mia.path.clone()
        }
        Program::Systemctl if os == Os::Linux => tools
            .systemctl
            .clone()
            .ok_or(ActionError::ToolMissing("systemctl"))?,
        Program::Launchctl if os == Os::MacOs => tools
            .launchctl
            .clone()
            .ok_or(ActionError::ToolMissing("launchctl"))?,
        Program::PowerShell if os == Os::Windows => tools
            .powershell
            .clone()
            .ok_or(ActionError::ToolMissing("powershell"))?,
        _ => return Err(ActionError::Unsupported),
    })
}

/// Resolve `inv` to a process for `os`: direct for [`Privilege::User`],
/// wrapped in the OS consent mechanism for [`Privilege::Admin`].
pub fn spec(inv: &Invocation, os: Os, tools: &Tools) -> Result<Spec, ActionError> {
    let target = resolve_program(inv, os, tools)?;
    if inv.privilege == Privilege::User {
        return Ok(Spec {
            program: target,
            args: inv.args.iter().map(OsString::from).collect(),
            env: Vec::new(),
        });
    }
    // Re-check at use: the program an administrator approves must not be
    // replaceable by an unprivileged process (mia was also checked when it
    // was located; systemctl / launchctl / PowerShell are checked here).
    if !(tools.trust)(&target) {
        return Err(if inv.program == Program::Mia {
            ActionError::MiaUntrusted
        } else {
            ActionError::ToolUntrusted
        });
    }
    let target_str = checked_path_arg(&target)?;
    if !inv.args.iter().all(|a| safe_elevated_arg(a)) {
        return Err(ActionError::BadPath);
    }
    match os {
        Os::Linux => {
            let pkexec = tools
                .pkexec
                .clone()
                .ok_or(ActionError::ToolMissing("pkexec"))?;
            let mut args = vec![OsString::from(target_str)];
            args.extend(inv.args.iter().map(OsString::from));
            Ok(Spec {
                program: pkexec,
                args,
                env: Vec::new(),
            })
        }
        Os::MacOs => {
            let osascript = tools
                .osascript
                .clone()
                .ok_or(ActionError::ToolMissing("osascript"))?;
            let mut args = Vec::new();
            for line in MACOS_ELEVATE_SCRIPT.iter().filter(|l| !l.is_empty()) {
                args.push(OsString::from("-e"));
                args.push(OsString::from(*line));
            }
            // The first positional must not start with '-' (osascript would
            // read it as an option); the prompt never does.
            args.push(OsString::from(prompt_text(inv)));
            args.push(OsString::from(target_str));
            args.extend(inv.args.iter().map(OsString::from));
            Ok(Spec {
                program: osascript,
                args,
                env: Vec::new(),
            })
        }
        Os::Windows => {
            let powershell = tools
                .powershell
                .clone()
                .ok_or(ActionError::ToolMissing("powershell"))?;
            let joined = inv
                .args
                .iter()
                .map(|a| windows_quote(a))
                .collect::<Vec<_>>()
                .join(" ");
            Ok(Spec {
                program: powershell,
                args: [
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    WINDOWS_ELEVATE_SCRIPT,
                ]
                .iter()
                .map(OsString::from)
                .collect(),
                env: vec![
                    (WIN_FILE_VAR.to_string(), OsString::from(target_str)),
                    (WIN_ARGS_VAR.to_string(), OsString::from(joined)),
                ],
            })
        }
    }
}

// ── Outcomes ─────────────────────────────────────────────────────────────────

/// How an action ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Exit 0.
    Succeeded,
    /// Non-zero exit (the code, when known).
    Failed(Option<i32>),
    /// The person dismissed the consent prompt. Nothing was changed.
    Cancelled,
    /// Authorisation was refused (wrong password, no polkit agent, …).
    NotAuthorized,
    /// The deadline passed and the child was killed.
    TimedOut,
}

impl Outcome {
    /// The short label.
    #[must_use]
    pub fn label(self) -> Msg {
        match self {
            Self::Succeeded => Msg::OutcomeSucceeded,
            Self::Failed(_) => Msg::OutcomeFailed,
            Self::Cancelled => Msg::OutcomeCancelled,
            Self::NotAuthorized => Msg::OutcomeNotAuthorized,
            Self::TimedOut => Msg::OutcomeTimedOut,
        }
    }
}

/// `pkexec`: the dialog was dismissed.
const PKEXEC_DISMISSED: i32 = 126;
/// `pkexec`: not authorised / authentication failed / no agent.
const PKEXEC_NOT_AUTHORIZED: i32 = 127;
/// Windows `ERROR_CANCELLED` (UAC declined), surfaced by the wrapper script.
const WIN_ERROR_CANCELLED: i32 = 1223;

/// Classify a finished run.
#[must_use]
pub fn classify(os: Os, privilege: Privilege, out: &Captured) -> Outcome {
    if out.timed_out {
        return Outcome::TimedOut;
    }
    if out.code == Some(0) {
        return Outcome::Succeeded;
    }
    if privilege == Privilege::Admin {
        match os {
            Os::Linux if out.code == Some(PKEXEC_DISMISSED) => return Outcome::Cancelled,
            Os::Linux if out.code == Some(PKEXEC_NOT_AUTHORIZED) => return Outcome::NotAuthorized,
            Os::MacOs => {
                // `User canceled. (-128)` from Authorization Services.
                // osascript ends its message with the AppleScript error
                // number; match only that, never text from mia's own output.
                let err = String::from_utf8_lossy(&out.stderr);
                let tail = err.trim_end();
                if tail.ends_with("(-128)") {
                    return Outcome::Cancelled;
                }
                if tail.ends_with("(-60005)") || tail.ends_with("(-60007)") {
                    return Outcome::NotAuthorized;
                }
            }
            Os::Windows if out.code == Some(WIN_ERROR_CANCELLED) => return Outcome::Cancelled,
            _ => {}
        }
    }
    Outcome::Failed(out.code)
}

/// A finished action: its outcome plus the captured output (raw; escape it
/// with [`crate::text`] before display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionResult {
    /// How it ended.
    pub outcome: Outcome,
    /// What it printed.
    pub captured: Captured,
}

/// Build, run (bounded) and classify `inv`. Errors before the start are
/// returned; everything after is an [`ActionResult`]. Logged with `tracing`
/// (purpose and outcome only — never the output).
pub fn run(inv: &Invocation, os: Os, tools: &Tools) -> Result<ActionResult, ActionError> {
    let spec = match spec(inv, os, tools) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(purpose = ?inv.purpose, error = %e, "action not started");
            return Err(e);
        }
    };
    let captured = run_bounded(spec.command(), inv.limits).map_err(|e| {
        tracing::warn!(purpose = ?inv.purpose, error = %e, "action could not be started");
        ActionError::Spawn(e.to_string())
    })?;
    let outcome = classify(os, inv.privilege, &captured);
    tracing::info!(purpose = ?inv.purpose, privilege = ?inv.privilege, ?outcome, "action finished");
    Ok(ActionResult { outcome, captured })
}

/// Start `spec` without waiting (viewers, browsers); a helper thread reaps it.
pub fn spawn_detached(spec: &Spec) -> Result<(), ActionError> {
    let mut cmd = spec.command();
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().map_err(|e| {
        tracing::warn!(program = %spec.program.display(), error = %e, "could not start");
        ActionError::Spawn(e.to_string())
    })?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// The machine id printed by `mia machine-id`: its first line, accepted only
/// when it is UUID-shaped (hex digits and dashes, at most 64 characters), so
/// nothing else ever reaches the clipboard.
#[must_use]
pub fn parse_machine_id(stdout: &[u8]) -> Option<String> {
    let line = std::str::from_utf8(stdout).ok()?.lines().next()?.trim();
    (!line.is_empty()
        && line.len() <= 64
        && line.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
    .then(|| line.to_string())
}

// ── Documentation and the full log ───────────────────────────────────────────

/// Documentation the tray links to — a fixed table of URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Doc {
    /// Supported platforms / installation.
    Install,
    /// Networking and ports.
    Networking,
    /// The CRL-stale runbook.
    CrlStale,
    /// Allowlist provisioning.
    Allowlist,
    /// TPM and attestation backends.
    Tpm,
    /// IMA and the hardening profile.
    Hardening,
    /// SPKI pinning.
    Pins,
    /// Bootstrap and enrollment.
    Enrollment,
    /// The tray's own guide (status group, troubleshooting).
    Tray,
    /// The runbook index.
    Runbooks,
}

/// Base URL of the published documentation.
pub const DOCS_BASE: &str = "https://github.com/ffquintella/FerroGate/blob/main/docs/";

impl Doc {
    /// Every document.
    pub const ALL: [Self; 10] = [
        Self::Install,
        Self::Networking,
        Self::CrlStale,
        Self::Allowlist,
        Self::Tpm,
        Self::Hardening,
        Self::Pins,
        Self::Enrollment,
        Self::Tray,
        Self::Runbooks,
    ];

    /// Path below [`DOCS_BASE`].
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Self::Install => "mia.md#supported-platforms",
            Self::Networking => "networking.md",
            Self::CrlStale => "operations/runbooks/crl-stale.md",
            Self::Allowlist => "allowlist-provisioning.md",
            Self::Tpm => "tpm.md",
            Self::Hardening => "mia.md#hardening-profile",
            Self::Pins => "transport-tls.md#authentication-spki-pinning-not-a-ca",
            Self::Enrollment => "features/F13-bootstrap-enrollment.md",
            Self::Tray => "mia-tray.md",
            Self::Runbooks => "operations/runbooks/README.md",
        }
    }

    /// The full URL.
    #[must_use]
    pub fn url(self) -> String {
        format!("{DOCS_BASE}{}", self.path())
    }

    /// The label.
    #[must_use]
    pub fn label(self) -> Msg {
        match self {
            Self::Install => Msg::DocInstall,
            Self::Networking => Msg::DocNetworking,
            Self::CrlStale => Msg::DocCrlStale,
            Self::Allowlist => Msg::DocAllowlist,
            Self::Tpm => Msg::DocTpm,
            Self::Hardening => Msg::DocHardening,
            Self::Pins => Msg::DocPins,
            Self::Enrollment => Msg::DocEnrollment,
            Self::Tray => Msg::DocTray,
            Self::Runbooks => Msg::DocRunbooks,
        }
    }
}

fn system_root() -> PathBuf {
    crate::locate::windows_dir().unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// The process that opens `doc` in the default browser.
pub fn open_doc_spec(doc: Doc, os: Os) -> Result<Spec, ActionError> {
    let url = OsString::from(doc.url());
    let (program, args) = match os {
        Os::MacOs => (PathBuf::from("/usr/bin/open"), vec![url]),
        Os::Linux => (
            crate::locate::first_existing(&["/usr/bin/xdg-open", "/bin/xdg-open"])
                .ok_or(ActionError::ToolMissing("xdg-open"))?,
            vec![url],
        ),
        // explorer.exe hands an https URL to the default browser; no `cmd /c
        // start`, so no cmd.exe metacharacter parsing is involved.
        Os::Windows => (system_root().join("explorer.exe"), vec![url]),
    };
    Ok(Spec {
        program,
        args,
        env: Vec::new(),
    })
}

/// Terminal emulators tried (in order) to show `journalctl -u mia -f` on
/// Linux, with the flag that introduces the command.
const LINUX_TERMINALS: [(&str, &str); 5] = [
    ("/usr/bin/x-terminal-emulator", "-e"),
    ("/usr/bin/gnome-terminal", "--"),
    ("/usr/bin/konsole", "-e"),
    ("/usr/bin/xfce4-terminal", "-x"),
    ("/usr/bin/xterm", "-e"),
];

/// The process that shows the agent's full log with the platform's own
/// viewer: Console.app (macOS), Notepad on `%ProgramData%\FerroGate\logs\
/// mia.log` (Windows), `journalctl -u mia -f` in a terminal (Linux — which
/// needs `systemd-journal`/`adm` membership; the tray says so and never
/// elevates for it).
pub fn open_full_log_spec(os: Os) -> Result<Spec, ActionError> {
    let (program, args): (PathBuf, Vec<OsString>) = match os {
        Os::MacOs => (
            PathBuf::from("/usr/bin/open"),
            ["-a", "Console", "/var/log/ferrogate/mia.log"]
                .iter()
                .map(OsString::from)
                .collect(),
        ),
        Os::Windows => {
            let data = std::env::var_os("ProgramData")
                .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
            (
                system_root().join("System32").join("notepad.exe"),
                vec![data
                    .join("FerroGate")
                    .join("logs")
                    .join("mia.log")
                    .into_os_string()],
            )
        }
        Os::Linux => {
            let (term, flag) = LINUX_TERMINALS
                .iter()
                .find(|(p, _)| Path::new(p).is_file())
                .ok_or(ActionError::ToolMissing("terminal emulator"))?;
            (
                PathBuf::from(term),
                [*flag, "journalctl", "-u", "mia", "-f"]
                    .iter()
                    .map(OsString::from)
                    .collect(),
            )
        }
    };
    Ok(Spec {
        program,
        args,
        env: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path that is absolute on the host running the tests (the elevation
    /// wrappers insist on absolute programs, and `Path::is_absolute` follows
    /// the host's rules).
    const fn host(unix: &'static str, windows: &'static str) -> &'static str {
        if cfg!(windows) {
            windows
        } else {
            unix
        }
    }
    const PS: &str = host(
        "/opt/test/powershell.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    );
    const SYSTEMCTL: &str = host("/usr/bin/systemctl", r"C:\test\systemctl");
    const LAUNCHCTL: &str = host("/bin/launchctl", r"C:\test\launchctl");
    const PKEXEC: &str = host("/usr/bin/pkexec", r"C:\test\pkexec");
    const OSASCRIPT: &str = host("/usr/bin/osascript", r"C:\test\osascript");

    fn tools(trusted: bool) -> Tools {
        Tools {
            mia: Some(MiaBinary {
                path: PathBuf::from(if cfg!(windows) {
                    r"C:\Program Files\FerroGate\MIA\mia.exe"
                } else {
                    "/usr/bin/mia"
                }),
                trusted,
            }),
            systemctl: Some(SYSTEMCTL.into()),
            launchctl: Some(LAUNCHCTL.into()),
            powershell: Some(PS.into()),
            pkexec: Some(PKEXEC.into()),
            osascript: Some(OSASCRIPT.into()),
            trust: |_| true,
        }
    }

    fn os_args(s: &Spec) -> Vec<String> {
        s.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn read_only_actions_run_as_the_user_with_fixed_arguments() {
        let prod = EnvName::parse("prod").unwrap();
        let inv = invocation(Action::RunSelfTest, Some(&prod), Os::Linux);
        assert_eq!(inv.privilege, Privilege::User);
        let s = spec(&inv, Os::Linux, &tools(false)).unwrap();
        assert_eq!(s.program, tools(false).mia.unwrap().path);
        assert_eq!(os_args(&s), ["test", "--json", "-e", "prod"]);
        let inv = invocation(Action::ShowMachineId, Some(&prod), Os::MacOs);
        assert_eq!(inv.args, ["machine-id"], "machine-id takes no environment");
        let inv = invocation(Action::ShowStatus, None, Os::Windows);
        assert_eq!(inv.args, ["status", "--json"]);
    }

    #[test]
    fn every_state_changing_action_needs_consent() {
        for a in Action::ALL {
            for os in [Os::Linux, Os::MacOs, Os::Windows] {
                let inv = invocation(a, None, os);
                assert_eq!(inv.privilege, a.privilege());
                if a.privilege() == Privilege::Admin {
                    let s = spec(&inv, os, &tools(true)).unwrap();
                    let wrapper = match os {
                        Os::Linux => PKEXEC,
                        Os::MacOs => OSASCRIPT,
                        Os::Windows => PS,
                    };
                    assert_eq!(s.program, PathBuf::from(wrapper), "{a:?} on {os:?}");
                }
            }
        }
    }

    #[test]
    fn untrusted_or_missing_mia_is_never_elevated() {
        let inv = invocation(Action::ResyncAllowlist, None, Os::Linux);
        assert_eq!(
            spec(&inv, Os::Linux, &tools(false)),
            Err(ActionError::MiaUntrusted)
        );
        let none = Tools {
            mia: None,
            ..tools(true)
        };
        assert_eq!(spec(&inv, Os::Linux, &none), Err(ActionError::MiaNotFound));
        let no_pkexec = Tools {
            pkexec: None,
            ..tools(true)
        };
        assert_eq!(
            spec(&inv, Os::Linux, &no_pkexec),
            Err(ActionError::ToolMissing("pkexec"))
        );
        // A wrapped tool that fails the trust rule at use time is refused.
        let picky = Tools {
            trust: |p| !p.ends_with("systemctl"),
            ..tools(true)
        };
        let inv = invocation(Action::ServiceStop, None, Os::Linux);
        assert_eq!(
            spec(&inv, Os::Linux, &picky),
            Err(ActionError::ToolUntrusted)
        );
        // systemctl on macOS is not a thing.
        let inv = invocation(Action::ServiceRestart, None, Os::Linux);
        assert_eq!(
            spec(&inv, Os::MacOs, &tools(true)),
            Err(ActionError::Unsupported)
        );
    }

    #[test]
    fn linux_elevation_is_pkexec_with_an_absolute_program() {
        let env = EnvName::parse("prod").unwrap();
        let inv = invocation(Action::ResyncAllowlist, Some(&env), Os::Linux);
        let s = spec(&inv, Os::Linux, &tools(true)).unwrap();
        let mia = tools(true).mia.unwrap().path.display().to_string();
        assert_eq!(
            os_args(&s),
            [mia.as_str(), "resync-allowlist", "--reload", "-e", "prod"]
        );
        let inv = invocation(Action::ServiceRestart, None, Os::Linux);
        let s = spec(&inv, Os::Linux, &tools(true)).unwrap();
        assert_eq!(os_args(&s), [SYSTEMCTL, "restart", "mia.service"]);
    }

    #[test]
    fn macos_elevation_passes_values_as_argv_not_script_text() {
        let inv = invocation(Action::ServiceRestart, None, Os::MacOs);
        let s = spec(&inv, Os::MacOs, &tools(true)).unwrap();
        let args = os_args(&s);
        // The script lines are the fixed constant…
        let script: Vec<&str> = args
            .iter()
            .skip(1)
            .step_by(2)
            .take(8)
            .map(String::as_str)
            .collect();
        assert_eq!(script, MACOS_ELEVATE_SCRIPT[..8]);
        // …and the command follows as separate argv items.
        assert_eq!(
            &args[16..],
            [
                prompt_text(&inv).as_str(),
                LAUNCHCTL,
                "kickstart",
                "-k",
                "system/com.ferrogate.mia"
            ]
        );
        assert!(!args[16].starts_with('-'));
    }

    #[test]
    fn windows_elevation_carries_values_in_the_environment() {
        let env = EnvName::parse("prod").unwrap();
        let inv = invocation(Action::RefreshKey, Some(&env), Os::Windows);
        let t = tools(true);
        let s = spec(&inv, Os::Windows, &t).unwrap();
        assert_eq!(os_args(&s).last().unwrap(), WINDOWS_ELEVATE_SCRIPT);
        assert_eq!(s.env[0].0, WIN_FILE_VAR);
        assert_eq!(s.env[0].1, t.mia.unwrap().path.into_os_string());
        assert_eq!(
            s.env[1],
            (
                WIN_ARGS_VAR.to_string(),
                OsString::from("refresh-key -e prod")
            )
        );
        // The script never contains a double quote (it is passed as one argv
        // item) and reads both values from the environment.
        assert!(!WINDOWS_ELEVATE_SCRIPT.contains('"'));
        assert!(WINDOWS_ELEVATE_SCRIPT.contains("$env:FG_TRAY_ELEVATE_FILE"));
        assert!(WINDOWS_ELEVATE_SCRIPT.contains("$env:FG_TRAY_ELEVATE_ARGS"));
    }

    #[test]
    fn windows_quoting_follows_the_crt_rules() {
        assert_eq!(windows_quote("refresh-key"), "refresh-key");
        assert_eq!(windows_quote(""), "\"\"");
        assert_eq!(
            windows_quote(r"C:\Users\Jo Doe\AppData\Local\Temp\d.toml"),
            r#""C:\Users\Jo Doe\AppData\Local\Temp\d.toml""#
        );
        assert_eq!(windows_quote(r"a b\"), r#""a b\\""#);
        assert_eq!(windows_quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(windows_quote(r#"a\"b c"#), r#""a\\\"b c""#);
    }

    #[test]
    fn environment_names_use_the_shared_validator() {
        assert!(EnvName::parse("prod").is_ok());
        for bad in [
            "",
            "..",
            "a/b",
            "a b",
            "x;rm -rf /",
            "$(id)",
            "a\nb",
            "--reload",
            "-x",
        ] {
            assert_eq!(
                EnvName::parse(bad),
                Err(ActionError::BadEnvironment),
                "{bad:?}"
            );
        }
        let long = "a".repeat(mia_status_proto::MAX_ENVIRONMENT_LEN + 1);
        assert!(EnvName::parse(&long).is_err());
    }

    #[test]
    fn default_environment_actions_are_fixed_elevated_command_lines() {
        let prod = EnvName::parse("prod").unwrap();
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            let set = invocation(Action::SetDefaultEnvironment, Some(&prod), os);
            assert_eq!(set.program, Program::Mia);
            assert_eq!(set.args, ["default-environment", "set", "prod"]);
            assert_eq!(set.privilege, Privilege::Admin);
            assert_eq!(set.limits, Limits::ELEVATED);
            assert_eq!(set.purpose, Msg::ActionSetDefaultEnvironment);
            // "Set as default" for mia.toml (no name) is a clear.
            let to_main = invocation(Action::SetDefaultEnvironment, None, os);
            assert_eq!(to_main.args, ["default-environment", "clear"]);
            // Clear never takes a name, even when one is offered.
            let clear = invocation(Action::ClearDefaultEnvironment, Some(&prod), os);
            assert_eq!(clear.args, ["default-environment", "clear"]);
            assert_eq!(clear.privilege, Privilege::Admin);
        }
        assert!(Action::SetDefaultEnvironment.takes_environment());
        assert!(!Action::ClearDefaultEnvironment.takes_environment());
        assert!(Action::SetDefaultEnvironment.applies_on_restart());
        assert!(Action::ClearDefaultEnvironment.applies_on_restart());
        assert!(!Action::ServiceRestart.applies_on_restart());

        // Through each consent wrapper the name stays one argv item.
        let t = tools(true);
        let mia = t.mia.clone().unwrap().path.display().to_string();
        let inv = invocation(Action::SetDefaultEnvironment, Some(&prod), Os::Linux);
        let s = spec(&inv, Os::Linux, &t).unwrap();
        assert_eq!(s.program, PathBuf::from(PKEXEC));
        assert_eq!(
            os_args(&s),
            [mia.as_str(), "default-environment", "set", "prod"]
        );
        let s = spec(&inv, Os::MacOs, &t).unwrap();
        assert_eq!(
            os_args(&s)[16..],
            [
                prompt_text(&inv).as_str(),
                mia.as_str(),
                "default-environment",
                "set",
                "prod"
            ]
        );
        let s = spec(&inv, Os::Windows, &t).unwrap();
        assert_eq!(
            s.env[1],
            (
                WIN_ARGS_VAR.to_string(),
                OsString::from("default-environment set prod")
            )
        );
        // An untrusted mia is never elevated for it.
        assert_eq!(
            spec(&inv, Os::Linux, &tools(false)),
            Err(ActionError::MiaUntrusted)
        );
        // Names that could inject an option, a second argument or shell
        // syntax never become an EnvName, so never reach the command line.
        for bad in [
            "prod --json",
            "prod;id",
            "$(id)",
            "`id`",
            "--output",
            "-e",
            "a\"b",
            "a'b",
            "prod\nclear",
        ] {
            assert_eq!(
                EnvName::parse(bad),
                Err(ActionError::BadEnvironment),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn setup_invocations() {
        let draft = std::env::temp_dir().join("mia-tray-x").join("draft.toml");
        let inv = check_invocation(&draft).unwrap();
        assert_eq!(inv.privilege, Privilege::User);
        assert_eq!(inv.args[..2], ["setup", "--check"]);

        let user = ApplyOptions {
            scope: Scope::User,
            ..ApplyOptions::default()
        };
        let inv = apply_invocation(&draft, &user).unwrap();
        assert_eq!(inv.privilege, Privilege::User);
        assert!(inv.args.contains(&"--user".to_string()));

        let system = ApplyOptions {
            scope: Scope::System,
            environment: Some(EnvName::parse("prod").unwrap()),
            reload: true,
            fetch_enrollment_key: true,
            expected_enrollment_key_fingerprint: Some(
                EnrollmentKeyFingerprint::parse(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
                )
                .unwrap(),
            ),
        };
        let inv = apply_invocation(&draft, &system).unwrap();
        assert_eq!(inv.privilege, Privilege::Admin);
        assert_eq!(
            inv.args[3..],
            [
                "--json",
                "-e",
                "prod",
                "--reload",
                "--fetch-enrollment-key",
                "--expect-fingerprint",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            ]
        );
        assert!(!inv.args.contains(&"--output".to_string()));

        assert!(apply_invocation(
            &draft,
            &ApplyOptions {
                reload: true,
                ..user
            }
        )
        .is_err());
        assert!(apply_invocation(
            &draft,
            &ApplyOptions {
                expected_enrollment_key_fingerprint: Some(
                    EnrollmentKeyFingerprint::parse(&"a".repeat(96)).unwrap(),
                ),
                ..ApplyOptions::default()
            }
        )
        .is_err());
        let dump = dump_invocation(Scope::User, None);
        assert_eq!(dump.args, ["setup", "--dump", "--json", "--user"]);
    }

    #[test]
    fn enrollment_key_fingerprint_is_strict_and_normalised() {
        let upper = "A".repeat(96);
        assert_eq!(
            EnrollmentKeyFingerprint::parse(&format!("  {upper}  "))
                .unwrap()
                .as_str(),
            "a".repeat(96)
        );
        assert!(EnrollmentKeyFingerprint::parse("abcd").is_err());
        assert!(EnrollmentKeyFingerprint::parse(&"g".repeat(96)).is_err());
        assert!(EnrollmentKeyFingerprint::parse(&"a".repeat(257)).is_err());
    }

    #[test]
    fn path_arguments_are_checked() {
        assert!(checked_path_arg(Path::new("relative/draft.toml")).is_err());
        let base = std::env::temp_dir();
        assert!(checked_path_arg(&base.join("a").join("..").join("b")).is_err());
        assert!(checked_path_arg(&base.join("a\"b")).is_err());
        assert!(checked_path_arg(&base.join("a\nb")).is_err());
        assert!(checked_path_arg(&base.join("ok draft.toml")).is_ok());
    }

    #[test]
    fn outcomes_distinguish_cancel_from_failure() {
        let run = |code: Option<i32>, stderr: &str| Captured {
            code,
            stderr: stderr.as_bytes().to_vec(),
            ..Captured::default()
        };
        let a = Privilege::Admin;
        assert_eq!(
            classify(Os::Linux, a, &run(Some(0), "")),
            Outcome::Succeeded
        );
        assert_eq!(
            classify(Os::Linux, a, &run(Some(126), "")),
            Outcome::Cancelled
        );
        assert_eq!(
            classify(Os::Linux, a, &run(Some(127), "")),
            Outcome::NotAuthorized
        );
        assert_eq!(
            classify(Os::Linux, a, &run(Some(1), "")),
            Outcome::Failed(Some(1))
        );
        assert_eq!(
            classify(
                Os::MacOs,
                a,
                &run(Some(1), "execution error: User canceled. (-128)")
            ),
            Outcome::Cancelled
        );
        assert_eq!(
            classify(Os::MacOs, a, &run(Some(1), "execution error: boom (1)")),
            Outcome::Failed(Some(1))
        );
        // mia's own output mentioning "(-128)" is not a cancel.
        assert_eq!(
            classify(
                Os::MacOs,
                a,
                &run(Some(1), "execution error: mia said (-128) somewhere (1)")
            ),
            Outcome::Failed(Some(1))
        );
        assert_eq!(
            classify(Os::Windows, a, &run(Some(1223), "")),
            Outcome::Cancelled
        );
        // As the user, 126 is just a failure (no wrapper involved).
        assert_eq!(
            classify(Os::Linux, Privilege::User, &run(Some(126), "")),
            Outcome::Failed(Some(126))
        );
        let timed = Captured {
            timed_out: true,
            ..Captured::default()
        };
        assert_eq!(classify(Os::Linux, a, &timed), Outcome::TimedOut);
    }

    #[test]
    fn only_uuid_shaped_machine_ids_are_accepted() {
        assert_eq!(
            parse_machine_id(b"0192b0d0-1111-8111-8111-111111111111\n").as_deref(),
            Some("0192b0d0-1111-8111-8111-111111111111")
        );
        assert_eq!(parse_machine_id(b"warning: incomplete identifiers\n"), None);
        assert_eq!(parse_machine_id(b""), None);
        assert_eq!(parse_machine_id(&[b'a'; 65]), None);
    }

    #[test]
    fn docs_are_a_fixed_https_table() {
        for d in Doc::ALL {
            let url = d.url();
            assert!(url.starts_with("https://github.com/ffquintella/FerroGate/blob/main/docs/"));
            assert!(!url.contains(['"', '\'', ' ', '&', '|', ';']), "{url}");
            for os in [Os::MacOs, Os::Windows] {
                let s = open_doc_spec(d, os).unwrap();
                assert_eq!(s.args, vec![OsString::from(url.clone())]);
            }
        }
    }

    #[test]
    fn the_full_log_is_opened_with_fixed_arguments() {
        let s = open_full_log_spec(Os::MacOs).unwrap();
        assert_eq!(os_args(&s), ["-a", "Console", "/var/log/ferrogate/mia.log"]);
        let s = open_full_log_spec(Os::Windows).unwrap();
        assert!(os_args(&s)[0].ends_with("mia.log"));
    }

    #[cfg(unix)]
    #[test]
    fn running_a_user_action_end_to_end() {
        // `/bin/echo` stands in for mia: the exact argv reaches the child.
        let t = Tools {
            mia: Some(MiaBinary {
                path: PathBuf::from("/bin/echo"),
                trusted: false,
            }),
            ..Tools::default()
        };
        let os = Os::current().unwrap_or(Os::Linux);
        let env = EnvName::parse("staging").unwrap();
        let r = run(&invocation(Action::RunSelfTest, Some(&env), os), os, &t).unwrap();
        assert_eq!(r.outcome, Outcome::Succeeded);
        assert_eq!(r.captured.stdout, b"test --json -e staging\n");
    }

    /// The elevation script must at least compile as AppleScript (compiling
    /// does not run it, so no prompt appears).
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_elevation_script_compiles() {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = Command::new("/usr/bin/osacompile");
        for line in MACOS_ELEVATE_SCRIPT.iter().filter(|l| !l.is_empty()) {
            cmd.arg("-e").arg(line);
        }
        cmd.arg("-o").arg(dir.path().join("s.scpt"));
        let out = run_bounded(cmd, Limits::QUICK).unwrap();
        assert!(
            out.success(),
            "osacompile: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
