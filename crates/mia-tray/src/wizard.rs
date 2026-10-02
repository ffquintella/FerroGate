//! The setup wizard's headless half: load, validate, render and stage a
//! draft for `mia setup --check` / `--apply`.
//!
//! - **Load.** The current configuration comes from `mia setup --dump
//!   --json`: effective values, the file path, and the keys overridden by
//!   environment variables. Overridden keys are shown read-only with their
//!   effective value, but the draft keeps the *file's* value for them (read
//!   by a second dump with those variables removed), so applying never copies
//!   an environment value into the file.
//! - **Validate.** Each field is checked locally with the same rules as `mia`'s
//!   wizard (`crates/mia/src/setup.rs` `check_*`); `mia setup --check` then
//!   has the final word, and `--apply` re-validates everything anyway.
//! - **Render.** The draft is serialised with the `toml` crate (never by
//!   string concatenation), limited to the keys `--apply` accepts.
//! - **Stage.** [`DraftFile`] writes it to a fresh private directory
//!   (`0700`, random name) as `draft.toml` (`0600`, created exclusively), and
//!   removes the directory when dropped — which is how the tray cleans up
//!   after an elevated apply (`mia` leaves the draft to its owner then).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::i18n::Msg;
use crate::process::Captured;

/// Largest draft `mia setup --apply` accepts (`MAX_DRAFT_BYTES`).
pub const MAX_DRAFT_BYTES: usize = 64 * 1024;

/// Longest free-text answer (`mia`'s `MAX_ANSWER_LEN`).
pub const MAX_ANSWER_LEN: usize = 4096;

/// The attestation backends the wizard offers.
pub const BACKEND_CHOICES: [&str; 4] = ["auto", "tpm", "host-key", "virtual-tpm"];

/// Wizard steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Step {
    /// CMIS source and pin.
    Cmis,
    /// Helper API listener.
    Helper,
    /// Caller allowlist.
    Allowlist,
    /// Attestation backend, IMA log, log level.
    Attestation,
}

impl Step {
    /// Every step, in order.
    pub const ALL: [Self; 4] = [Self::Cmis, Self::Helper, Self::Allowlist, Self::Attestation];

    /// The step title.
    #[must_use]
    pub fn title(self) -> Msg {
        match self {
            Self::Cmis => Msg::StepCmis,
            Self::Helper => Msg::StepHelper,
            Self::Allowlist => Msg::StepAllowlist,
            Self::Attestation => Msg::StepAttestation,
        }
    }
}

/// Every key the wizard (and `mia setup --apply`) manages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Field {
    /// `cmis.endpoint`.
    CmisEndpoint,
    /// `cmis.srv`.
    CmisSrv,
    /// `cmis.spki_pin`.
    CmisSpkiPin,
    /// `helper.socket`.
    HelperSocket,
    /// `helper.socket_mode` (Unix).
    HelperSocketMode,
    /// `helper.windows_group` (Windows).
    HelperWindowsGroup,
    /// `allowlist.path`.
    AllowlistPath,
    /// `allowlist.key`.
    AllowlistKey,
    /// `allowlist.max_age_secs`.
    AllowlistMaxAge,
    /// `allowlist.fetch` (boolean).
    AllowlistFetch,
    /// `allowlist.propose` (boolean).
    AllowlistPropose,
    /// `attestation.backend`.
    AttestationBackend,
    /// `attestation.ima_log` (Linux).
    ImaLog,
    /// `log`.
    Log,
}

impl Field {
    /// Every field, in wizard order.
    pub const ALL: [Self; 14] = [
        Self::CmisEndpoint,
        Self::CmisSrv,
        Self::CmisSpkiPin,
        Self::HelperSocket,
        Self::HelperSocketMode,
        Self::HelperWindowsGroup,
        Self::AllowlistPath,
        Self::AllowlistKey,
        Self::AllowlistMaxAge,
        Self::AllowlistFetch,
        Self::AllowlistPropose,
        Self::AttestationBackend,
        Self::ImaLog,
        Self::Log,
    ];

    /// The dotted configuration key.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::CmisEndpoint => "cmis.endpoint",
            Self::CmisSrv => "cmis.srv",
            Self::CmisSpkiPin => "cmis.spki_pin",
            Self::HelperSocket => "helper.socket",
            Self::HelperSocketMode => "helper.socket_mode",
            Self::HelperWindowsGroup => "helper.windows_group",
            Self::AllowlistPath => "allowlist.path",
            Self::AllowlistKey => "allowlist.key",
            Self::AllowlistMaxAge => "allowlist.max_age_secs",
            Self::AllowlistFetch => "allowlist.fetch",
            Self::AllowlistPropose => "allowlist.propose",
            Self::AttestationBackend => "attestation.backend",
            Self::ImaLog => "attestation.ima_log",
            Self::Log => "log",
        }
    }

    /// Look a dotted key up.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.key() == key)
    }

    /// A checkbox rather than a text field.
    #[must_use]
    pub fn is_bool(self) -> bool {
        matches!(self, Self::AllowlistFetch | Self::AllowlistPropose)
    }

    /// The step it belongs to.
    #[must_use]
    pub fn step(self) -> Step {
        match self {
            Self::CmisEndpoint | Self::CmisSrv | Self::CmisSpkiPin => Step::Cmis,
            Self::HelperSocket | Self::HelperSocketMode | Self::HelperWindowsGroup => Step::Helper,
            Self::AllowlistPath
            | Self::AllowlistKey
            | Self::AllowlistMaxAge
            | Self::AllowlistFetch
            | Self::AllowlistPropose => Step::Allowlist,
            Self::AttestationBackend | Self::ImaLog | Self::Log => Step::Attestation,
        }
    }

    /// Whether the field means anything on this OS (others stay in the draft
    /// unchanged but are not shown).
    #[must_use]
    pub fn applies_here(self) -> bool {
        match self {
            Self::HelperSocketMode => cfg!(unix),
            Self::HelperWindowsGroup => cfg!(windows),
            Self::ImaLog => cfg!(target_os = "linux"),
            _ => true,
        }
    }

    /// Label and help text.
    #[must_use]
    pub fn texts(self) -> (Msg, Msg) {
        match self {
            Self::CmisEndpoint => (Msg::FieldCmisEndpoint, Msg::HelpCmisEndpoint),
            Self::CmisSrv => (Msg::FieldCmisSrv, Msg::HelpCmisSrv),
            Self::CmisSpkiPin => (Msg::FieldCmisSpkiPin, Msg::HelpCmisSpkiPin),
            Self::HelperSocket => (Msg::FieldHelperSocket, Msg::HelpHelperSocket),
            Self::HelperSocketMode => (Msg::FieldHelperSocketMode, Msg::HelpHelperSocketMode),
            Self::HelperWindowsGroup => (Msg::FieldHelperWindowsGroup, Msg::HelpHelperWindowsGroup),
            Self::AllowlistPath => (Msg::FieldAllowlistPath, Msg::HelpAllowlistPath),
            Self::AllowlistKey => (Msg::FieldAllowlistKey, Msg::HelpAllowlistKey),
            Self::AllowlistMaxAge => (Msg::FieldAllowlistMaxAge, Msg::HelpAllowlistMaxAge),
            Self::AllowlistFetch => (Msg::FieldAllowlistFetch, Msg::HelpAllowlistFetch),
            Self::AllowlistPropose => (Msg::FieldAllowlistPropose, Msg::HelpAllowlistPropose),
            Self::AttestationBackend => (Msg::FieldAttestationBackend, Msg::HelpAttestationBackend),
            Self::ImaLog => (Msg::FieldImaLog, Msg::HelpImaLog),
            Self::Log => (Msg::FieldLog, Msg::HelpLog),
        }
    }
}

/// The wizard's answers. Booleans are `"true"` / `"false"`; blank = unset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values(pub BTreeMap<Field, String>);

impl Values {
    /// The (trimmed) value of `f`; `""` when unset.
    #[must_use]
    pub fn get(&self, f: Field) -> &str {
        self.0.get(&f).map_or("", |v| v.trim())
    }

    /// Set `f`.
    pub fn set(&mut self, f: Field, v: impl Into<String>) {
        self.0.insert(f, v.into());
    }

    /// A boolean field.
    #[must_use]
    pub fn flag(&self, f: Field) -> bool {
        self.get(f) == "true"
    }

    fn opt(&self, f: Field) -> Option<String> {
        let v = self.get(f);
        (!v.is_empty()).then(|| v.to_string())
    }
}

/// What the wizard loaded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    /// The file `--apply` will write.
    pub path: String,
    /// Whether it exists yet.
    pub exists: bool,
    /// The values the draft starts from (the file's own).
    pub values: Values,
    /// Effective values of env-overridden fields (shown read-only).
    pub effective: Values,
    /// Overridden fields → the variable that sets them.
    pub overridden: BTreeMap<Field, String>,
}

/// Why loading failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// `mia setup --dump` failed (typically: the file is not readable by
    /// this user).
    #[error("mia setup --dump failed")]
    DumpFailed {
        /// `mia`'s own message (escaped), for the details view.
        detail: String,
    },
    /// The output was not the expected JSON.
    #[error("unexpected output from mia setup --dump")]
    BadOutput,
}

/// Parsed `mia setup --dump --json` document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dump {
    /// Target path.
    pub path: String,
    /// Whether it exists.
    pub exists: bool,
    /// The wizard-managed values.
    pub values: Values,
    /// Overridden fields → variable.
    pub overridden: BTreeMap<Field, String>,
    /// Every overriding variable reported (wizard-managed or not).
    pub override_vars: Vec<String>,
}

/// Interpret a `mia setup --dump --json` run.
pub fn parse_dump(out: &Captured) -> Result<Dump, LoadError> {
    if !out.success() || out.truncated {
        return Err(LoadError::DumpFailed {
            detail: crate::text::output_text(&out.stderr),
        });
    }
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|_| LoadError::BadOutput)?;
    let values_doc = doc.get("values").ok_or(LoadError::BadOutput)?;
    let mut values = Values::default();
    for f in Field::ALL {
        let mut node = values_doc;
        for part in f.key().split('.') {
            node = node.get(part).unwrap_or(&serde_json::Value::Null);
        }
        let text = match node {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            _ if f.is_bool() => "false".to_string(),
            _ => String::new(),
        };
        values.set(f, text);
    }
    let mut overridden = BTreeMap::new();
    let mut override_vars = Vec::new();
    for o in doc
        .get("env_overridden")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(key), Some(var)) = (
            o.get("key").and_then(serde_json::Value::as_str),
            o.get("var").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        // Only plausible variable names are ever used to edit an environment.
        if var.is_empty() || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        override_vars.push(var.to_string());
        if let Some(f) = Field::from_key(key) {
            overridden.insert(f, var.to_string());
        }
    }
    Ok(Dump {
        path: doc
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        exists: doc
            .get("exists")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        values,
        overridden,
        override_vars,
    })
}

/// Combine the effective dump with the dump taken without the overriding
/// variables (`None` when nothing was overridden).
#[must_use]
pub fn combine(effective: Dump, file_only: Option<Dump>) -> Loaded {
    let values = file_only.map_or_else(|| effective.values.clone(), |d| d.values);
    Loaded {
        path: effective.path,
        exists: effective.exists,
        values,
        effective: effective.values,
        overridden: effective.overridden,
    }
}

// ── Validation (mirrors `mia`'s `check_*`) ───────────────────────────────────

fn check_literal(v: &str) -> Result<(), Msg> {
    if v.len() > MAX_ANSWER_LEN {
        return Err(Msg::ValTooLong);
    }
    if v.contains('\'') || v.chars().any(char::is_control) {
        return Err(Msg::ValLiteral);
    }
    Ok(())
}

/// Validate one field's value (blank is always valid: "unset").
pub fn validate_field(f: Field, raw: &str) -> Result<(), Msg> {
    check_literal(raw)?;
    let v = raw.trim();
    if v.is_empty() {
        return Ok(());
    }
    match f {
        Field::CmisSrv if !v.contains('.') => Err(Msg::ValSrv),
        Field::CmisEndpoint if !(v.starts_with("https://") || v.starts_with("http://")) => {
            Err(Msg::ValEndpoint)
        }
        Field::CmisSpkiPin if v.len() != 96 || !v.chars().all(|c| c.is_ascii_hexdigit()) => {
            Err(Msg::ValPin)
        }
        Field::HelperSocketMode => {
            let t = v.trim_start_matches("0o");
            if !t.is_empty() && u32::from_str_radix(t, 8).is_ok() {
                Ok(())
            } else {
                Err(Msg::ValOctal)
            }
        }
        Field::AllowlistMaxAge if !v.parse::<u64>().is_ok_and(|n| i64::try_from(n).is_ok()) => {
            Err(Msg::ValUint)
        }
        Field::AttestationBackend if !BACKEND_CHOICES.contains(&v) => Err(Msg::ValBackend),
        Field::AllowlistFetch | Field::AllowlistPropose if v != "true" && v != "false" => {
            Err(Msg::ValLiteral)
        }
        Field::Log if tracing_subscriber::EnvFilter::try_new(v).is_err() => {
            Err(Msg::ValLogDirective)
        }
        _ => Ok(()),
    }
}

/// Validate every field plus the cross-field rules `mia` enforces. Returns
/// the problems keyed by field (empty ⇒ valid).
#[must_use]
pub fn validate(values: &Values) -> Vec<(Field, Msg)> {
    let mut errs: Vec<(Field, Msg)> = Field::ALL
        .into_iter()
        .filter_map(|f| validate_field(f, values.get(f)).err().map(|m| (f, m)))
        .collect();
    let endpoint = values.get(Field::CmisEndpoint);
    let srv = values.get(Field::CmisSrv);
    if !endpoint.is_empty() && !srv.is_empty() {
        errs.push((Field::CmisSrv, Msg::ValEndpointSrvExclusive));
    }
    if (!srv.is_empty() || endpoint.starts_with("https://"))
        && values.get(Field::CmisSpkiPin).is_empty()
    {
        errs.push((Field::CmisSpkiPin, Msg::ValPinRequired));
    }
    if !values.get(Field::AllowlistPath).is_empty() && values.get(Field::AllowlistKey).is_empty() {
        errs.push((Field::AllowlistKey, Msg::ValKeyRequired));
    }
    errs
}

// ── Rendering ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct DraftDoc {
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<String>,
    cmis: DraftCmis,
    helper: DraftHelper,
    allowlist: DraftAllowlist,
    attestation: DraftAttestation,
}

#[derive(Serialize)]
struct DraftCmis {
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spki_pin: Option<String>,
}

#[derive(Serialize)]
struct DraftHelper {
    #[serde(skip_serializing_if = "Option::is_none")]
    socket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_group: Option<String>,
}

#[derive(Serialize)]
struct DraftAllowlist {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_age_secs: Option<u64>,
    fetch: bool,
    propose: bool,
}

#[derive(Serialize)]
struct DraftAttestation {
    #[serde(skip_serializing_if = "Option::is_none")]
    ima_log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<String>,
}

/// Render the draft TOML (exactly the schema `mia setup --apply` accepts).
/// Call [`validate`] first; an unparsable max age is dropped here.
#[must_use]
pub fn render(values: &Values) -> String {
    let doc = DraftDoc {
        log: values.opt(Field::Log),
        cmis: DraftCmis {
            endpoint: values.opt(Field::CmisEndpoint),
            srv: values.opt(Field::CmisSrv),
            spki_pin: values.opt(Field::CmisSpkiPin),
        },
        helper: DraftHelper {
            socket: values.opt(Field::HelperSocket),
            socket_mode: values.opt(Field::HelperSocketMode),
            windows_group: values.opt(Field::HelperWindowsGroup),
        },
        allowlist: DraftAllowlist {
            path: values.opt(Field::AllowlistPath),
            key: values.opt(Field::AllowlistKey),
            max_age_secs: values
                .opt(Field::AllowlistMaxAge)
                .and_then(|v| v.parse().ok()),
            fetch: values.flag(Field::AllowlistFetch),
            propose: values.flag(Field::AllowlistPropose),
        },
        attestation: DraftAttestation {
            ima_log: values.opt(Field::ImaLog),
            backend: values.opt(Field::AttestationBackend),
        },
    };
    toml::to_string(&doc).unwrap_or_default()
}

// ── Staging ──────────────────────────────────────────────────────────────────

/// A draft on disk in a private directory; dropping it removes both.
#[derive(Debug)]
pub struct DraftFile {
    dir: tempfile::TempDir,
    path: PathBuf,
}

impl DraftFile {
    /// The draft's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The private directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
}

/// Where private drafts go: `$XDG_RUNTIME_DIR` (Linux, a `0700` per-user
/// tmpfs) when usable, else the user's temp directory (`$TMPDIR` is per-user
/// on macOS; `%TEMP%` is under the profile on Windows).
#[must_use]
pub fn draft_base_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        if dir.is_absolute() && dir.is_dir() {
            return dir;
        }
    }
    std::env::temp_dir()
}

/// Stage `contents` as a private draft under `base` (see [`DraftFile`]).
pub fn write_draft(base: &Path, contents: &str) -> std::io::Result<DraftFile> {
    if contents.len() > MAX_DRAFT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the draft is larger than 64 KiB",
        ));
    }
    // A fresh, randomly named directory: `mkdir` fails on anything already
    // there (including a planted symlink). tempfile's default directory mode
    // is 0777 & ~umask, so ask for 0700 explicitly — it is passed to
    // `mkdir(2)` itself, so the directory is never briefly more open.
    let mut builder = tempfile::Builder::new();
    builder.prefix("mia-tray-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder.tempdir_in(base)?;
    let path = dir.path().join("draft.toml");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Exactly 0600 whatever the umask (`--apply` refuses group/other
        // write); through the handle, so no path is re-resolved.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(DraftFile { dir, path })
}

// ── `--check` / `--apply` output ─────────────────────────────────────────────

/// `mia setup --check --json`'s verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// Accepted.
    pub ok: bool,
    /// `(key, message)` problems, escaped for display.
    pub errors: Vec<(String, String)>,
}

/// Parse `mia setup --check --json` / `--apply --json` problem output (both
/// print `{"ok": …, "errors": [{key, message}]}` on rejection).
pub fn parse_check(out: &Captured) -> Result<CheckReport, LoadError> {
    let doc: serde_json::Value =
        serde_json::from_slice(out.stdout.trim_ascii()).map_err(|_| LoadError::BadOutput)?;
    let ok = doc
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or(LoadError::BadOutput)?;
    let errors = doc
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(64)
        .map(|e| {
            let s = |k: &str| {
                crate::text::display_safe(
                    e.get(k)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                    300,
                )
            };
            (s("key"), s("message"))
        })
        .collect();
    Ok(CheckReport {
        ok: ok && out.success(),
        errors,
    })
}

/// `mia setup --apply --json`'s summary (when its stdout is available).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// The file written.
    pub path: String,
    /// Changed key names (never values).
    pub changed_keys: Vec<String>,
    /// Whether `mia` deleted the draft (only when unprivileged).
    pub draft_deleted: bool,
    /// `--reload` result.
    pub reloaded: Option<bool>,
    /// A post-write error (`--reload` / key fetch), escaped.
    pub error: Option<String>,
}

/// Parse the apply summary; `None` when stdout holds no summary (elevated on
/// Windows, or a failure before writing).
#[must_use]
pub fn parse_apply(stdout: &[u8]) -> Option<ApplyReport> {
    let doc: serde_json::Value = serde_json::from_slice(stdout.trim_ascii()).ok()?;
    doc.get("changed_keys")?;
    let esc = |v: Option<&serde_json::Value>| {
        v.and_then(serde_json::Value::as_str)
            .map(|s| crate::text::display_safe(s, 300))
    };
    Some(ApplyReport {
        path: esc(doc.get("path")).unwrap_or_default(),
        changed_keys: doc
            .get("changed_keys")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .take(64)
            .filter_map(|k| k.as_str().map(|s| crate::text::display_safe(s, 128)))
            .collect(),
        draft_deleted: doc
            .get("draft_deleted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        reloaded: doc.get("reloaded").and_then(serde_json::Value::as_bool),
        error: esc(doc.get("error")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

    fn captured(stdout: &str, code: i32) -> Captured {
        Captured {
            code: Some(code),
            stdout: stdout.as_bytes().to_vec(),
            ..Captured::default()
        }
    }

    fn dump_json(endpoint: &str, overridden: &str) -> String {
        format!(
            r#"{{"path": "/etc/ferrogate/mia.toml", "exists": true, "environment": null,
               "values": {{"log": "info",
                 "cmis": {{"endpoint": "{endpoint}", "srv": null, "spki_pin": "{PIN}"}},
                 "helper": {{"socket": "/run/ferrogate/mia.sock", "socket_mode": "660",
                             "socket_gid": "991", "windows_group": null, "require_authenticode": null}},
                 "allowlist": {{"path": null, "key": null, "max_age_secs": 3600, "fetch": true,
                                "propose": false, "propose_interval_secs": null}},
                 "attestation": {{"ima_log": null, "backend": "host-key", "tpm": {{}}}},
                 "status": {{}}}},
               "env_overridden": [{overridden}]}}"#
        )
    }

    #[test]
    fn a_dump_is_parsed_into_wizard_values() {
        let d = parse_dump(&captured(&dump_json("https://cmis:8443", ""), 0)).unwrap();
        assert_eq!(d.path, "/etc/ferrogate/mia.toml");
        assert!(d.exists);
        assert_eq!(d.values.get(Field::CmisEndpoint), "https://cmis:8443");
        assert_eq!(d.values.get(Field::AllowlistMaxAge), "3600");
        assert!(d.values.flag(Field::AllowlistFetch));
        assert!(!d.values.flag(Field::AllowlistPropose));
        assert_eq!(d.values.get(Field::AttestationBackend), "host-key");
        assert_eq!(d.values.get(Field::CmisSrv), "");
        assert!(validate(&d.values).is_empty());
    }

    #[test]
    fn overridden_fields_keep_the_file_value() {
        let eff = parse_dump(&captured(
            &dump_json(
                "https://from-env:1",
                r#"{"key": "cmis.endpoint", "var": "FERROGATE_CMIS_ENDPOINT"},
                   {"key": "status.socket", "var": "FERROGATE_STATUS_SOCKET"},
                   {"key": "log", "var": "bad var$(x)"}"#,
            ),
            0,
        ))
        .unwrap();
        assert_eq!(
            eff.overridden.get(&Field::CmisEndpoint).map(String::as_str),
            Some("FERROGATE_CMIS_ENDPOINT")
        );
        // Implausible variable names are ignored; non-wizard keys are still
        // removed for the second dump.
        assert_eq!(
            eff.override_vars,
            ["FERROGATE_CMIS_ENDPOINT", "FERROGATE_STATUS_SOCKET"]
        );
        let file = parse_dump(&captured(&dump_json("https://from-file:2", ""), 0)).unwrap();
        let loaded = combine(eff, Some(file));
        assert_eq!(
            loaded.values.get(Field::CmisEndpoint),
            "https://from-file:2"
        );
        assert_eq!(
            loaded.effective.get(Field::CmisEndpoint),
            "https://from-env:1"
        );
    }

    #[test]
    fn dump_failures_are_reported() {
        let mut out = captured("", 1);
        out.stderr = b"Error: reading /etc/ferrogate/mia.toml: Permission denied".to_vec();
        assert!(matches!(
            parse_dump(&out),
            Err(LoadError::DumpFailed { .. })
        ));
        assert_eq!(parse_dump(&captured("nope", 0)), Err(LoadError::BadOutput));
    }

    #[test]
    fn field_validation_mirrors_mia() {
        use Field as F;
        assert_eq!(
            validate_field(F::CmisEndpoint, "cmis:8443"),
            Err(Msg::ValEndpoint)
        );
        assert_eq!(
            validate_field(F::CmisEndpoint, "https://x'y"),
            Err(Msg::ValLiteral)
        );
        assert_eq!(
            validate_field(F::CmisEndpoint, "https://x\ny"),
            Err(Msg::ValLiteral)
        );
        assert_eq!(validate_field(F::CmisSrv, "cmis"), Err(Msg::ValSrv));
        assert!(validate_field(F::CmisSrv, "_cmis._tcp.example.com").is_ok());
        assert!(validate_field(F::CmisSpkiPin, PIN).is_ok());
        assert!(validate_field(F::CmisSpkiPin, &PIN.to_uppercase()).is_ok());
        assert_eq!(validate_field(F::CmisSpkiPin, "abcd"), Err(Msg::ValPin));
        assert!(validate_field(F::HelperSocketMode, "0o660").is_ok());
        assert_eq!(
            validate_field(F::HelperSocketMode, "999"),
            Err(Msg::ValOctal)
        );
        assert_eq!(validate_field(F::AllowlistMaxAge, "-1"), Err(Msg::ValUint));
        assert_eq!(
            validate_field(F::AllowlistMaxAge, "18446744073709551615"),
            Err(Msg::ValUint)
        );
        assert_eq!(
            validate_field(F::AttestationBackend, "magic"),
            Err(Msg::ValBackend)
        );
        assert!(validate_field(F::Log, "mia=debug,info").is_ok());
        assert_eq!(validate_field(F::Log, "mia=[["), Err(Msg::ValLogDirective));
        assert_eq!(
            validate_field(F::HelperSocket, &"a".repeat(MAX_ANSWER_LEN + 1)),
            Err(Msg::ValTooLong)
        );
        // Blank is "unset" and valid.
        for f in Field::ALL {
            assert!(validate_field(f, "  ").is_ok(), "{f:?}");
        }
    }

    #[test]
    fn cross_field_rules() {
        let mut v = Values::default();
        v.set(Field::CmisEndpoint, "https://a:1");
        v.set(Field::CmisSrv, "_cmis._tcp.a.b");
        v.set(Field::AllowlistPath, "/etc/ferrogate/allowlist.cbor");
        let errs = validate(&v);
        assert!(errs.contains(&(Field::CmisSrv, Msg::ValEndpointSrvExclusive)));
        assert!(errs.contains(&(Field::CmisSpkiPin, Msg::ValPinRequired)));
        assert!(errs.contains(&(Field::AllowlistKey, Msg::ValKeyRequired)));
        let mut v = Values::default();
        v.set(Field::CmisEndpoint, "http://dev:1");
        assert!(validate(&v).is_empty(), "plain http needs no pin");
    }

    #[test]
    fn the_draft_renders_to_the_apply_schema() {
        let mut v = Values::default();
        v.set(Field::CmisEndpoint, " https://cmis.example.com:8443 ");
        v.set(Field::CmisSpkiPin, PIN);
        v.set(Field::HelperSocket, "/run/ferrogate/mia.sock");
        v.set(Field::AllowlistMaxAge, "3600");
        v.set(Field::AllowlistFetch, "true");
        v.set(Field::AttestationBackend, "host-key");
        v.set(Field::Log, "info");
        let text = render(&v);
        let doc: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(
            doc["cmis"]["endpoint"].as_str(),
            Some("https://cmis.example.com:8443")
        );
        assert_eq!(doc["allowlist"]["max_age_secs"].as_integer(), Some(3600));
        assert_eq!(doc["allowlist"]["fetch"].as_bool(), Some(true));
        assert_eq!(doc["allowlist"]["propose"].as_bool(), Some(false));
        assert!(doc["cmis"].get("srv").is_none(), "blank keys are omitted");
        // Only the keys `--apply` accepts.
        let allowed = ["log", "cmis", "helper", "allowlist", "attestation"];
        assert!(doc.keys().all(|k| allowed.contains(&k.as_str())));
    }

    #[test]
    fn values_cannot_inject_keys() {
        // Even an unvalidated value is a TOML string, never structure.
        let mut v = Values::default();
        v.set(Field::HelperSocket, "x\"\n[status]\nsocket = \"/tmp/evil");
        let doc: toml::Table = toml::from_str(&render(&v)).unwrap();
        assert!(doc.get("status").is_none());
        assert_eq!(
            doc["helper"]["socket"].as_str(),
            Some("x\"\n[status]\nsocket = \"/tmp/evil")
        );
    }

    #[test]
    fn drafts_are_private_and_cleaned_up() {
        let base = tempfile::tempdir().unwrap();
        let draft = write_draft(base.path(), "log = 'info'\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(draft.path()).unwrap(),
            "log = 'info'\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(draft.path()), 0o600);
            assert_eq!(mode(draft.dir()), 0o700);
        }
        let dir = draft.dir().to_path_buf();
        drop(draft);
        assert!(!dir.exists(), "the private dir is removed on drop");
        assert!(write_draft(base.path(), &"x".repeat(MAX_DRAFT_BYTES + 1)).is_err());
    }

    #[test]
    fn check_and_apply_output_is_parsed() {
        let r = parse_check(&captured(r#"{"ok": true, "errors": []}"#, 0)).unwrap();
        assert!(r.ok && r.errors.is_empty());
        let r = parse_check(&captured(
            r#"{"ok": false, "errors": [{"key": "cmis.spki_pin", "message": "bad\npin"}]}"#,
            1,
        ))
        .unwrap();
        assert!(!r.ok);
        assert_eq!(r.errors, [("cmis.spki_pin".into(), "bad\\npin".into())]);
        assert!(parse_check(&captured("✓ ok", 0)).is_err());

        let a = parse_apply(
            br#"{"ok": true, "path": "/etc/ferrogate/mia.toml", "changed_keys": ["cmis.endpoint"],
                "draft_deleted": false, "enrollment_key": null, "reloaded": true, "error": null}"#,
        )
        .unwrap();
        assert_eq!(a.changed_keys, ["cmis.endpoint"]);
        assert_eq!(a.reloaded, Some(true));
        assert!(!a.draft_deleted);
        assert_eq!(parse_apply(b""), None);
    }
}
