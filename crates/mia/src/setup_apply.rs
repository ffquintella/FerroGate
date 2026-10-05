//! Non-interactive `mia setup` modes (feature F18): the back end of the
//! `mia-tray` graphical wizard, usable from scripts too. No TTY is needed.
//!
//! - `mia setup --check <draft>` — validate a draft without writing anything.
//! - `mia setup --apply <draft> [--user | --output <path> | -e <env>]
//!   [--reload] [--fetch-enrollment-key] [--json]` — validate, then write the
//!   configuration file atomically and record a `ConfigChanged` audit event.
//! - `mia setup --dump [--json] [--user | --output <path> | -e <env>]` — the
//!   effective configuration, the file it came from, and which keys are
//!   overridden by environment variables (shown read-only by the wizard,
//!   since writing the file would not change them).
//!
//! **The draft is untrusted input.** It may be written by an unprivileged
//! process and applied by an elevated one, so `--apply`:
//!
//! - refuses symlinks, hard links and non-regular files, and anything over
//!   [`MAX_DRAFT_BYTES`]; on Unix also a draft writable by group/others or
//!   owned by the wrong user (see `check_draft_owner`);
//! - when elevated (root; on Windows always, since elevation cannot be ruled
//!   out) refuses `--output`, reports parser errors by line number only, and
//!   confines `--fetch-enrollment-key` to the configuration directory — so a
//!   draft writer can neither aim a privileged write at an arbitrary path nor
//!   make it echo an arbitrary file;
//! - parses a strict schema — exactly the keys the interactive wizard asks
//!   for, unknown keys rejected — and runs every value through the wizard's
//!   own validators (`crate::setup::check_*`), plus the cross-field rules the
//!   daemon enforces at startup;
//! - renders with the wizard's renderer ([`crate::setup::render`]), so the
//!   file is byte-identical to what the TTY wizard writes for the same
//!   answers, and carries over the keys the wizard does not edit;
//! - writes atomically (temp file + `fsync` + rename + directory `fsync`)
//!   with the wizard's mode (`0640`) and the previous file's ownership,
//!   refusing a symlink at the target;
//! - appends `ConfigChanged { path, by_uid, keys }` — key *names* only —
//!   to the local audit journal *before* the rename, so a change is never
//!   made without its audit record;
//! - deletes the draft once applied when unprivileged (an elevated run leaves
//!   it to its owner: deleting by path as root could be redirected).

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ferro_audit::AuditEvent;
use serde::{Deserialize, Serialize};

use crate::config::{validate_environment, Config, EnvOverrideScope};
use crate::setup::{self, Carried, Settings};

/// Largest draft accepted, in bytes.
pub const MAX_DRAFT_BYTES: usize = 64 * 1024;

const USAGE: &str = "usage: mia setup --check <draft> [--json]\n\
     \x20      mia setup --apply <draft> [--user | --output <path> | --environment <env>]\n\
     \x20                [--reload] [--fetch-enrollment-key] [--json]\n\
     \x20      mia setup --dump [--json] [--user | --output <path> | --environment <env>]";

/// Run a non-interactive `mia setup` mode. `args` is everything after
/// `setup`.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(opts) = Opts::parse(args)? else {
        return Ok(());
    };
    match &opts.mode {
        Mode::Check(draft) => check(draft, opts.json),
        Mode::Apply(draft) => apply(draft, &opts),
        Mode::Dump => dump(&opts),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Check(PathBuf),
    Apply(PathBuf),
    Dump,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent CLI switches
struct Opts {
    mode: Mode,
    json: bool,
    user: bool,
    output: Option<PathBuf>,
    environment: Option<String>,
    reload: bool,
    fetch_key: bool,
}

impl Opts {
    fn parse(args: &[String]) -> anyhow::Result<Option<Self>> {
        let mut mode: Option<Mode> = None;
        let mut set_mode = |m: Mode| -> anyhow::Result<()> {
            anyhow::ensure!(
                mode.replace(m).is_none(),
                "--check, --apply and --dump are mutually exclusive\n\n{USAGE}"
            );
            Ok(())
        };
        let (mut json, mut user, mut reload, mut fetch_key) = (false, false, false, false);
        let mut output = None;
        let mut environment = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    println!("{USAGE}\n\nSee `mia setup --help` and docs/mia.md.");
                    return Ok(None);
                }
                "--check" => set_mode(Mode::Check(PathBuf::from(
                    it.next().context("--check requires a draft path")?,
                )))?,
                "--apply" => set_mode(Mode::Apply(PathBuf::from(
                    it.next().context("--apply requires a draft path")?,
                )))?,
                "--dump" => set_mode(Mode::Dump)?,
                "--json" => json = true,
                "-u" | "--user" => user = true,
                "--reload" => reload = true,
                "--fetch-enrollment-key" => fetch_key = true,
                "-o" | "--output" => {
                    output = Some(PathBuf::from(
                        it.next().context("--output requires a path argument")?,
                    ));
                }
                "-e" | "--environment" => {
                    let env = it
                        .next()
                        .context("--environment requires a name argument")?;
                    validate_environment(env)?;
                    environment = Some(env.clone());
                }
                other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
            }
        }
        let mode = mode.context(USAGE)?;
        anyhow::ensure!(
            !(environment.is_some() && output.is_some()),
            "--output and --environment are mutually exclusive\n\n{USAGE}"
        );
        anyhow::ensure!(
            matches!(mode, Mode::Apply(_)) || !(reload || fetch_key),
            "--reload and --fetch-enrollment-key apply only to --apply\n\n{USAGE}"
        );
        Ok(Some(Self {
            mode,
            json,
            user,
            output,
            environment,
            reload,
            fetch_key,
        }))
    }

    fn target(&self) -> anyhow::Result<PathBuf> {
        setup::target_path(self.output.clone(), self.user, self.environment.as_deref())
    }
}

// ── The draft schema ─────────────────────────────────────────────────────────

/// A draft: the wizard's answers, laid out like `mia.toml` but limited to
/// the keys the wizard asks for. Unknown keys are rejected.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Draft {
    log: Option<String>,
    cmis: DraftCmis,
    helper: DraftHelper,
    allowlist: DraftAllowlist,
    attestation: DraftAttestation,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DraftCmis {
    endpoint: Option<String>,
    srv: Option<String>,
    spki_pin: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DraftHelper {
    /// `helper.enable`. Absent ⇒ keep the target file's current value, so a
    /// draft from a front end that predates the key cannot silently re-enable
    /// a helper API the operator switched off.
    enable: Option<bool>,
    socket: Option<String>,
    socket_mode: Option<String>,
    windows_group: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DraftAllowlist {
    path: Option<String>,
    key: Option<String>,
    max_age_secs: Option<u64>,
    fetch: bool,
    propose: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DraftAttestation {
    ima_log: Option<String>,
    backend: Option<String>,
}

/// One validation failure, keyed by the dotted config key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DraftError {
    /// The dotted key (or `"draft"` for whole-file problems).
    pub key: String,
    /// What is wrong, in the wizard's own words.
    pub message: String,
}

impl DraftError {
    fn new(key: &str, message: impl Into<String>) -> Self {
        Self {
            key: key.to_string(),
            message: message.into(),
        }
    }
}

/// Read a draft file defensively (see the module docs). `apply` additionally
/// enforces the Unix write-permission rule.
fn read_draft(path: &Path, apply: bool) -> Result<(String, std::fs::Metadata), DraftError> {
    use std::io::Read as _;
    let err = |m: String| DraftError::new("draft", m);
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| err(format!("cannot read {}: {e}", path.display())))?;
    if meta.file_type().is_symlink() {
        return Err(err("the draft must not be a symbolic link".into()));
    }
    if !meta.is_file() {
        return Err(err("the draft must be a regular file".into()));
    }
    if meta.len() > MAX_DRAFT_BYTES as u64 {
        return Err(err(format!(
            "the draft is larger than {MAX_DRAFT_BYTES} bytes"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if apply && meta.mode() & 0o022 != 0 {
            return Err(err(
                "the draft is writable by group or others; create it with mode 0600".into(),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = apply;
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        // Never follow a symlink swapped in after the check above, and never
        // block on a FIFO swapped in either.
        use std::os::unix::fs::OpenOptionsExt as _;
        open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = open
        .open(path)
        .map_err(|e| err(format!("cannot open {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file
            .metadata()
            .map_err(|e| err(format!("cannot stat {}: {e}", path.display())))?;
        if !opened.is_file() || opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return Err(err("the draft was replaced while being opened".into()));
        }
        // A hard link could make a file the caller cannot read look like
        // their draft.
        if opened.nlink() != 1 {
            return Err(err("the draft must not be hard-linked".into()));
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_DRAFT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| err(format!("cannot read {}: {e}", path.display())))?;
    if bytes.len() > MAX_DRAFT_BYTES {
        return Err(err(format!(
            "the draft is larger than {MAX_DRAFT_BYTES} bytes"
        )));
    }
    let text = String::from_utf8(bytes).map_err(|_| err("the draft is not UTF-8".into()))?;
    Ok((text, meta))
}

/// Parse a draft's text against the strict schema. Parser messages can quote
/// the input, so unless `detailed` (an unprivileged caller reading its own
/// file) only the line number is reported.
fn parse_draft(text: &str, detailed: bool) -> Result<Draft, DraftError> {
    toml::from_str(text).map_err(|e| {
        if detailed {
            let mut msg = e.message().to_string();
            msg.truncate(300);
            DraftError::new("draft", format!("not a valid draft: {msg}"))
        } else {
            let line = e
                .span()
                .map_or(0, |r| text[..r.start.min(text.len())].matches('\n').count() + 1);
            DraftError::new(
                "draft",
                format!("not a valid draft (TOML syntax, or an unknown or mistyped key, at line {line})"),
            )
        }
    })
}

/// Trim an answer and treat blank as unset, after the shared check.
fn answer(
    key: &str,
    value: Option<String>,
    check: fn(&str) -> Result<(), String>,
    errors: &mut Vec<DraftError>,
) -> Option<String> {
    let v = value?;
    if let Err(m) = check(&v) {
        errors.push(DraftError::new(key, m));
        return None;
    }
    let t = v.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Validate a parsed draft into wizard [`Settings`] (without carried keys).
fn validate(draft: Draft) -> Result<Settings, Vec<DraftError>> {
    use crate::setup::{check_endpoint, check_literal, check_octal, check_pin, check_srv};
    let mut e = Vec::new();
    let pin_check = |v: &str| check_literal(v).and_then(|()| check_pin(v));
    let octal_check = |v: &str| check_literal(v).and_then(|()| check_octal(v));
    let mut s = Settings {
        log: answer("log", draft.log, check_literal, &mut e),
        cmis_endpoint: answer("cmis.endpoint", draft.cmis.endpoint, check_endpoint, &mut e),
        cmis_srv: answer("cmis.srv", draft.cmis.srv, check_srv, &mut e),
        cmis_spki_pin: answer("cmis.spki_pin", draft.cmis.spki_pin, pin_check, &mut e),
        helper_enable: draft.helper.enable,
        helper_socket: answer("helper.socket", draft.helper.socket, check_literal, &mut e),
        helper_socket_mode: answer(
            "helper.socket_mode",
            draft.helper.socket_mode,
            octal_check,
            &mut e,
        ),
        helper_windows_group: answer(
            "helper.windows_group",
            draft.helper.windows_group,
            check_literal,
            &mut e,
        ),
        allowlist: answer(
            "allowlist.path",
            draft.allowlist.path,
            check_literal,
            &mut e,
        ),
        allowlist_key: answer("allowlist.key", draft.allowlist.key, check_literal, &mut e),
        allowlist_max_age: None,
        allowlist_fetch: draft.allowlist.fetch,
        allowlist_propose: draft.allowlist.propose,
        ima_log: answer(
            "attestation.ima_log",
            draft.attestation.ima_log,
            check_literal,
            &mut e,
        ),
        attestation_backend: None,
        carried: Carried::default(),
    };
    if let Some(n) = draft.allowlist.max_age_secs {
        let text = n.to_string();
        match crate::setup::check_uint(&text) {
            Ok(()) => s.allowlist_max_age = Some(text),
            Err(m) => e.push(DraftError::new("allowlist.max_age_secs", m)),
        }
    }
    if let Some(b) = draft.attestation.backend.as_deref().map(str::trim) {
        if setup::BACKEND_CHOICES.contains(&b) {
            s.attestation_backend = setup::backend_setting(b);
        } else {
            e.push(DraftError::new(
                "attestation.backend",
                format!("must be one of {}", setup::BACKEND_CHOICES.join(", ")),
            ));
        }
    }
    if let Some(log) = s.log.as_deref() {
        if tracing_subscriber::EnvFilter::try_new(log).is_err() {
            e.push(DraftError::new(
                "log",
                "not a valid log directive (tracing EnvFilter syntax, e.g. info or mia=debug,info)",
            ));
        }
    }
    // Cross-field rules the daemon enforces at startup.
    if s.cmis_endpoint.is_some() && s.cmis_srv.is_some() {
        e.push(DraftError::new(
            "cmis",
            "cmis.endpoint and cmis.srv are mutually exclusive",
        ));
    }
    let needs_pin = s.cmis_srv.is_some()
        || s.cmis_endpoint
            .as_deref()
            .is_some_and(|ep| ep.starts_with("https://"));
    if needs_pin && s.cmis_spki_pin.is_none() {
        e.push(DraftError::new(
            "cmis.spki_pin",
            "required with an https:// endpoint or an SRV record",
        ));
    }
    if s.allowlist.is_some() && s.allowlist_key.is_none() {
        e.push(DraftError::new(
            "allowlist.key",
            "required whenever allowlist.path is set",
        ));
    }
    if e.is_empty() {
        Ok(s)
    } else {
        Err(e)
    }
}

/// A draft that does not mention `helper.enable` keeps the target file's
/// value: the switch is fail-safe in the "off" direction, so it is never
/// flipped back on by omission.
fn keep_helper_switch(settings: &mut Settings, existing: &Config) {
    if settings.helper_enable.is_none() {
        settings.helper_enable = existing.helper.enable;
    }
}

/// Read, parse and validate a draft (see [`parse_draft`] for `detailed`).
fn load_draft(
    path: &Path,
    apply: bool,
    detailed: bool,
) -> Result<(Settings, std::fs::Metadata), Vec<DraftError>> {
    let (text, meta) = read_draft(path, apply).map_err(|e| vec![e])?;
    let draft = parse_draft(&text, detailed).map_err(|e| vec![e])?;
    Ok((validate(draft)?, meta))
}

fn report_errors(errors: &[DraftError], json: bool) {
    if json {
        println!("{}", serde_json::json!({ "ok": false, "errors": errors }));
    } else {
        for err in errors {
            eprintln!("  {}: {}", err.key, err.message);
        }
    }
}

// ── --check ──────────────────────────────────────────────────────────────────

fn check(draft: &Path, json: bool) -> anyhow::Result<()> {
    match load_draft(draft, false, true) {
        Ok(_) => {
            if json {
                println!("{}", serde_json::json!({ "ok": true, "errors": [] }));
            } else {
                println!("✓ {} is a valid draft", draft.display());
            }
            Ok(())
        }
        Err(errors) => {
            report_errors(&errors, json);
            anyhow::bail!("draft rejected ({} problem(s))", errors.len())
        }
    }
}

// ── --apply ──────────────────────────────────────────────────────────────────

fn apply(draft: &Path, opts: &Opts) -> anyhow::Result<()> {
    let target = opts.target()?;
    let parent = parent_dir(&target);
    if !parent.exists() {
        // Only the standard config directories are created on demand.
        anyhow::ensure!(
            opts.output.is_none(),
            "the directory of --output ({}) does not exist",
            parent.display()
        );
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {} ({ELEVATION_HINT})", parent.display()))?;
    }
    let who = invoker(parent)?;
    // Elevated, the target must be a standard location: a draft writer must not
    // be able to aim a root-owned write at an arbitrary path.
    anyhow::ensure!(
        !(who.elevated && opts.output.is_some()),
        "--output is refused when `mia setup --apply` may be running elevated; write the \
         standard path (optionally with --environment or --user) instead"
    );

    let (mut settings, draft_meta) = match load_draft(draft, true, !who.elevated) {
        Ok(v) => v,
        Err(errors) => {
            report_errors(&errors, opts.json);
            anyhow::bail!(
                "draft rejected ({} problem(s)); nothing written",
                errors.len()
            );
        }
    };
    let by_uid = check_draft_owner(&draft_meta, who)?;
    let existing = setup::load_existing(&target);
    settings.carried = Carried::from_existing(&existing);
    keep_helper_switch(&mut settings, &existing);
    let rendered = setup::render(&settings, opts.environment.as_deref());

    let staged = stage(&target, rendered.as_bytes(), CONFIG_MODE)?;
    let keys = commit(staged, &target, &rendered, &existing, by_uid)?;

    // Unprivileged, the draft is the caller's own file: delete it. Elevated,
    // deleting by path could be redirected (a directory in the path swapped for
    // a link), so leave it for the caller, who wrote it, to remove.
    let draft_deleted = !who.elevated
        && match std::fs::remove_file(draft) {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "warning: applied, but could not delete the draft {}: {e}",
                    draft.display()
                );
                false
            }
        };

    let fetched = opts
        .fetch_key
        .then(|| fetch_enrollment_key(&settings, &target, who, by_uid));
    let reloaded = opts.reload.then(|| {
        if opts.json {
            crate::resync::send_reload()
        } else {
            crate::resync::signal_reload();
            Ok(())
        }
    });
    let error = match (&fetched, &reloaded) {
        (Some(Err(e)), _) | (_, Some(Err(e))) => Some(format!("{e:#}")),
        _ => None,
    };

    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": error.is_none(),
                "path": target,
                "changed_keys": keys,
                "draft_deleted": draft_deleted,
                "enrollment_key": fetched.as_ref().and_then(|r| r.as_ref().ok()),
                "reloaded": reloaded.as_ref().map(Result::is_ok),
                "error": error,
            })
        );
    } else {
        println!("✓ Wrote {}", target.display());
        if !keys.is_empty() {
            println!("  Changed: {}", keys.join(", "));
        }
        if !draft_deleted {
            println!(
                "  The draft {} was left in place; remove it.",
                draft.display()
            );
        }
        if let Some(Ok(path)) = &fetched {
            println!("✓ Fetched the CMIS enrollment key into {}", path.display());
        }
        if !opts.reload {
            println!(
                "  (Re)start or reload the agent to apply it:  {}",
                setup::restart_hint()
            );
        }
    }
    match error {
        Some(e) => anyhow::bail!("the configuration was written, but: {e}"),
        None => Ok(()),
    }
}

/// The mode the wizard writes configuration files with.
const CONFIG_MODE: u32 = 0o640;

/// The mode enrollment public keys are written with (public material).
const KEY_MODE: u32 = 0o644;

/// The directory a file lives in (`.` for a bare file name).
fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Who is running this `--apply`, decided before the draft is read.
#[derive(Debug, Clone, Copy)]
struct Invoker {
    /// The effective uid.
    #[cfg(unix)]
    euid: u32,
    /// Running as root — or, where that cannot be told apart (Windows UAC),
    /// possibly elevated. Elevation tightens every rule below.
    elevated: bool,
}

/// Determine the effective uid by creating (and removing) a private probe
/// file in `dir` — `mia` makes no libc calls, so this is how it learns its
/// euid without `unsafe`. `dir` is the directory about to be written anyway.
#[cfg(unix)]
fn invoker(dir: &Path) -> anyhow::Result<Invoker> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let probe = dir.join(format!(
        ".mia-setup-probe-{}-{:016x}",
        std::process::id(),
        random_u64()
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&probe)
        .with_context(|| format!("writing in {} ({ELEVATION_HINT})", dir.display()))?;
    let euid = file.metadata().map(|m| m.uid());
    drop(file);
    std::fs::remove_file(&probe)
        .with_context(|| format!("removing the probe file {}", probe.display()))?;
    let euid = euid.with_context(|| format!("inspecting {}", probe.display()))?;
    Ok(Invoker {
        euid,
        elevated: euid == 0,
    })
}

/// Windows: elevation cannot be ruled out cheaply, so assume it.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn invoker(_dir: &Path) -> anyhow::Result<Invoker> {
    Ok(Invoker { elevated: true })
}

/// Fetch the CMIS enrollment key into `allowlist.key`, over the pinned
/// channel the new configuration describes, inside this (possibly elevated)
/// process so the pinned dial and the key write stay in `mia`. Returns the
/// key path.
///
/// Because the draft names both the server and the destination, the write is
/// constrained: a pinned TLS source is required (never plaintext `http://`),
/// the reply must parse as a composite public key, the path must be absolute
/// with no `..` and — when elevated — sit beside the configuration file, and
/// the file is replaced atomically (no symlink is followed) and audited.
fn fetch_enrollment_key(
    s: &Settings,
    target: &Path,
    who: Invoker,
    by_uid: u32,
) -> anyhow::Result<PathBuf> {
    use std::path::Component;
    let key_path = PathBuf::from(
        s.allowlist_key
            .as_deref()
            .context("--fetch-enrollment-key needs allowlist.key in the draft")?,
    );
    anyhow::ensure!(
        key_path.is_absolute() && !key_path.components().any(|c| c == Component::ParentDir),
        "allowlist.key must be an absolute path without `..` to fetch the enrollment key into it"
    );
    if who.elevated {
        anyhow::ensure!(
            key_path.parent() == Some(parent_dir(target)),
            "when elevated, --fetch-enrollment-key writes only beside the configuration file \
             ({}); place allowlist.key there",
            parent_dir(target).display()
        );
    }
    let pinned_tls = s.cmis_spki_pin.is_some()
        && (s.cmis_srv.is_some()
            || s.cmis_endpoint
                .as_deref()
                .is_some_and(|e| e.starts_with("https://")));
    anyhow::ensure!(
        pinned_tls,
        "--fetch-enrollment-key needs a pinned https:// endpoint or SRV record (cmis.spki_pin)"
    );
    let cfg = crate::config::CmisConfig {
        endpoint: s.cmis_endpoint.clone(),
        srv: s.cmis_srv.clone(),
        spki_pin: s.cmis_spki_pin.clone(),
    };
    let resolver = crate::endpoint::CmisResolver::from_config(&cfg)?
        .context("--fetch-enrollment-key needs cmis.endpoint or cmis.srv in the draft")?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime")?;
    let key = rt
        .block_on(async {
            let (_, mut client) = resolver.connect().await?;
            crate::client::fetch_enrollment_key(&mut client).await
        })
        .context("fetching the enrollment key from CMIS")?;
    ferro_crypto::composite::CompositePublicKey::from_concat_bytes(&key).map_err(|e| {
        anyhow::anyhow!(
            "CMIS returned something that is not a composite public key ({e}); nothing written"
        )
    })?;
    let staged = stage(&key_path, &key, KEY_MODE)?;
    staged.commit(&AuditEvent::ConfigChanged {
        path: key_path.display().to_string(),
        by_uid,
        keys: vec!["allowlist.key:enrollment-key".to_string()],
    })?;
    Ok(key_path)
}

/// Decide whether the draft may be applied and on whose behalf, returning the
/// `by_uid` to audit.
///
/// Unprivileged, only the caller's own drafts are applied. Elevated (root),
/// the draft must belong to the user who elevated (`PKEXEC_UID` /
/// `SUDO_UID`) or — when neither is set, as with macOS `osascript … with
/// administrator privileges` — to any user but root, so an elevated run can
/// never be pointed at a root-only file. Either way the draft cannot be
/// writable by group/others (checked when it was read).
#[cfg(unix)]
fn check_draft_owner(meta: &std::fs::Metadata, who: Invoker) -> anyhow::Result<u32> {
    use std::os::unix::fs::MetadataExt as _;
    let owner = meta.uid();
    if !who.elevated {
        anyhow::ensure!(
            owner == who.euid,
            "the draft is owned by uid {owner}, not by the invoking user (uid {}); refusing to \
             apply it",
            who.euid
        );
        return Ok(who.euid);
    }
    if let Some(user) = elevating_user() {
        anyhow::ensure!(
            owner == user,
            "the draft is owned by uid {owner}, not by the user who elevated (uid {user}); \
             refusing to apply it"
        );
        return Ok(user);
    }
    anyhow::ensure!(
        owner != 0,
        "an elevated apply refuses drafts owned by root; write the draft as the requesting user"
    );
    Ok(owner)
}

/// Windows: the change is attributed to this process's user RID.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn check_draft_owner(_meta: &std::fs::Metadata, _who: Invoker) -> anyhow::Result<u32> {
    Ok(process_rid())
}

/// Write `rendered` to `target` for the interactive wizard: the same atomic,
/// audited path `--apply` uses. Returns the changed key names.
pub(crate) fn write_config(
    target: &Path,
    rendered: &str,
    existing: &Config,
) -> anyhow::Result<Vec<String>> {
    let staged = stage(target, rendered.as_bytes(), CONFIG_MODE)?;
    let by_uid = by_uid(&staged);
    commit(staged, target, rendered, existing, by_uid)
}

/// Audit, then atomically move the staged file over `target`.
fn commit(
    staged: Staged,
    target: &Path,
    rendered: &str,
    existing: &Config,
    by_uid: u32,
) -> anyhow::Result<Vec<String>> {
    let new = Config::from_toml(rendered)
        .context("internal: the rendered configuration does not parse")?;
    let keys = changed_keys(existing, &new);
    let event = AuditEvent::ConfigChanged {
        path: target.display().to_string(),
        by_uid,
        keys: keys.clone(),
    };
    staged.commit(&event)?;
    Ok(keys)
}

// ── Atomic write ─────────────────────────────────────────────────────────────

/// A fully written and flushed temp file beside the target, not yet renamed
/// into place. Dropping it without [`Staged::commit`] removes the temp file.
#[derive(Debug)]
struct Staged {
    tmp: Option<PathBuf>,
    target: PathBuf,
    /// The effective uid that created the temp file (its owner before any
    /// ownership is copied from the previous file).
    #[cfg(unix)]
    euid: u32,
}

const ELEVATION_HINT: &str = "the system path needs elevation — re-run with `sudo`/as admin, use \
     --user for a per-user file, or --output to write elsewhere";

/// Write `content` to a fresh temp file in `target`'s directory with `mode`
/// (the wizard's `0640` for configuration) and — when `target` exists — its
/// owner and group, then `fsync` it. A symlink at `target` is refused.
fn stage(target: &Path, content: &[u8], mode: u32) -> anyhow::Result<Staged> {
    use std::io::Write as _;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating {} ({ELEVATION_HINT})", parent.display()))?;
    let previous = match std::fs::symlink_metadata(target) {
        Ok(m) if m.file_type().is_symlink() => anyhow::bail!(
            "{} is a symbolic link; refusing to replace it (edit the link's target directly)",
            target.display()
        ),
        Ok(m) if !m.is_file() => {
            anyhow::bail!("{} exists and is not a regular file", target.display())
        }
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", target.display())),
    };
    let name = target
        .file_name()
        .context("the configuration path has no file name")?
        .to_string_lossy();
    let tmp = parent.join(format!(
        ".{name}.tmp-{}-{:016x}",
        std::process::id(),
        random_u64()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("writing {} ({ELEVATION_HINT})", target.display()))?;
    // Built before any fallible step below so an early return drops it and
    // removes the temp file.
    let staged = Staged {
        tmp: Some(tmp.clone()),
        target: target.to_path_buf(),
        #[cfg(unix)]
        euid: {
            use std::os::unix::fs::MetadataExt as _;
            file.metadata().map_or(u32::MAX, |m| m.uid())
        },
    };
    file.write_all(content)
        .with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // Exactly `mode`, whatever the umask — the wizard always set 0640.
        // Through the open handle, so no path is re-resolved.
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode of {}", tmp.display()))?;
        if let Some(prev) = &previous {
            if (prev.uid(), prev.gid()) != (staged.euid, file.metadata()?.gid()) {
                std::os::unix::fs::chown(&tmp, Some(prev.uid()), Some(prev.gid())).with_context(
                    || {
                        format!(
                        "keeping the owner of {} (uid {}, gid {}) needs the same privileges that \
                         wrote it",
                        target.display(),
                        prev.uid(),
                        prev.gid()
                    )
                    },
                )?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = &previous;
    file.sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))?;
    drop(file);
    Ok(staged)
}

impl Staged {
    /// Record `event` in the local audit journal, then rename the temp file
    /// over the target and `fsync` the directory. If the audit record cannot
    /// be written nothing is changed.
    fn commit(mut self, event: &AuditEvent) -> anyhow::Result<()> {
        let tmp = self
            .tmp
            .take()
            .context("internal: staged file already consumed")?;
        let journal = crate::audit_client::local_journal_for(&self.target);
        if let Err(e) = crate::audit_client::append_local(&journal, event) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| {
                format!(
                    "could not record the ConfigChanged audit event in {}; the configuration was \
                     NOT changed",
                    journal.display()
                )
            });
        }
        if let Err(e) = std::fs::rename(&tmp, &self.target) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| {
                format!("replacing {} ({ELEVATION_HINT})", self.target.display())
            });
        }
        #[cfg(unix)]
        if let Some(parent) = self.target.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Err(e) = std::fs::File::open(parent).and_then(|d| d.sync_all()) {
                eprintln!(
                    "warning: wrote {}, but could not flush its directory: {e}",
                    self.target.display()
                );
            }
        }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some(tmp) = self.tmp.take() {
            if let Err(e) = std::fs::remove_file(&tmp) {
                eprintln!(
                    "warning: could not remove the temp file {}: {e}",
                    tmp.display()
                );
            }
        }
    }
}

fn random_u64() -> u64 {
    use getrandom::SysRng;
    use rand_core::{Rng as _, UnwrapErr};
    UnwrapErr(SysRng).next_u64()
}

/// The user who elevated this process through `pkexec` / `sudo`
/// (`PKEXEC_UID` / `SUDO_UID`). Only consulted when the process really is
/// root.
#[cfg(unix)]
fn elevating_user() -> Option<u32> {
    ["PKEXEC_UID", "SUDO_UID"]
        .iter()
        .find_map(|var| std::env::var(var).ok().and_then(|v| v.trim().parse().ok()))
}

/// The user on whose behalf the change is made: when root, the `sudo` /
/// `pkexec` user if known; otherwise the effective uid.
#[cfg(unix)]
fn by_uid(staged: &Staged) -> u32 {
    if staged.euid == 0 {
        elevating_user().unwrap_or(0)
    } else {
        staged.euid
    }
}

/// Windows: the RID of this process's user stands in for a uid.
#[cfg(windows)]
fn process_rid() -> u32 {
    ferro_winauth::process_user_rid(std::process::id()).unwrap_or(u32::MAX)
}

/// Windows: the change is attributed to this process's user RID.
#[cfg(windows)]
fn by_uid(_staged: &Staged) -> u32 {
    process_rid()
}

#[cfg(not(any(unix, windows)))]
fn process_rid() -> u32 {
    u32::MAX
}

#[cfg(not(any(unix, windows)))]
fn by_uid(_staged: &Staged) -> u32 {
    u32::MAX
}

/// Dotted names of every configuration key whose value differs between `old`
/// and `new` (added, removed or changed). Names only — the values never leave
/// this function.
#[must_use]
pub fn changed_keys(old: &Config, new: &Config) -> Vec<String> {
    let mut a = std::collections::BTreeMap::new();
    let mut b = std::collections::BTreeMap::new();
    flatten(&serde_json::to_value(old).unwrap_or_default(), "", &mut a);
    flatten(&serde_json::to_value(new).unwrap_or_default(), "", &mut b);
    let mut keys: Vec<String> = a
        .keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Flatten a JSON object into dotted leaf keys.
fn flatten(
    v: &serde_json::Value,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, serde_json::Value>,
) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(child, &key, out);
            }
        }
        leaf => {
            out.insert(prefix.to_string(), leaf.clone());
        }
    }
}

// ── --dump ───────────────────────────────────────────────────────────────────

fn dump(opts: &Opts) -> anyhow::Result<()> {
    let target = opts.target()?;
    let exists = target.exists();
    let mut config = if exists {
        let text = std::fs::read_to_string(&target)
            .with_context(|| format!("reading {}", target.display()))?;
        Config::from_toml(&text).with_context(|| format!("parsing {}", target.display()))?
    } else {
        Config::default()
    };
    // Named environments are served with the shared-only overlay (the
    // process-wide helper-socket path does not apply to them).
    let scope = if opts.environment.is_some() {
        EnvOverrideScope::SharedOnly
    } else {
        EnvOverrideScope::Full
    };
    config.apply_env(scope)?;
    let overridden: Vec<serde_json::Value> =
        crate::config::env_overridden(scope, |k| std::env::var(k).ok())
            .into_iter()
            .map(|o| serde_json::json!({ "key": o.key, "var": o.var }))
            .collect();
    let report = serde_json::json!({
        "path": target,
        "exists": exists,
        "environment": opts.environment,
        "values": config,
        "env_overridden": overridden,
    });
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} ({})",
            target.display(),
            if exists {
                "present"
            } else {
                "absent — defaults"
            }
        );
        let mut leaves = std::collections::BTreeMap::new();
        flatten(&report["values"], "", &mut leaves);
        for (k, v) in leaves.iter().filter(|(_, v)| !v.is_null()) {
            let env = crate::config::ENV_OVERRIDES
                .iter()
                .find(|o| o.key == k && overridden.iter().any(|x| x["key"] == o.key));
            match env {
                Some(o) => println!("  {k} = {v}   (from ${}, read-only)", o.var),
                None => println!("  {k} = {v}"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mia-apply-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_draft(dir: &Path, text: &str) -> PathBuf {
        let p = dir.join("draft.toml");
        std::fs::write(&p, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        p
    }

    const PIN: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

    fn full_draft() -> String {
        format!(
            "log = 'mia=debug,info'\n\
             [cmis]\nendpoint = 'https://cmis.example.com:8443'\nspki_pin = '{PIN}'\n\
             [helper]\nsocket = '/run/ferrogate/mia.sock'\nsocket_mode = '660'\n\
             [allowlist]\npath = '/etc/ferrogate/allowlist.cbor'\nkey = '/etc/ferrogate/allowlist.pub'\n\
             max_age_secs = 3600\nfetch = true\npropose = true\n\
             [attestation]\nbackend = 'host-key'\n"
        )
    }

    /// The settings the interactive wizard produces for the same answers as
    /// [`full_draft`].
    fn tty_settings() -> Settings {
        Settings {
            log: Some("mia=debug,info".into()),
            cmis_endpoint: Some("https://cmis.example.com:8443".into()),
            cmis_spki_pin: Some(PIN.into()),
            helper_socket: Some("/run/ferrogate/mia.sock".into()),
            helper_socket_mode: Some("660".into()),
            allowlist: Some("/etc/ferrogate/allowlist.cbor".into()),
            allowlist_key: Some("/etc/ferrogate/allowlist.pub".into()),
            allowlist_max_age: Some("3600".into()),
            allowlist_fetch: true,
            allowlist_propose: true,
            attestation_backend: setup::backend_setting("host-key"),
            ..Settings::default()
        }
    }

    fn apply_opts(output: &Path) -> Opts {
        Opts {
            mode: Mode::Dump,
            json: true,
            user: false,
            output: Some(output.to_path_buf()),
            environment: None,
            reload: false,
            fetch_key: false,
        }
    }

    #[test]
    fn apply_writes_byte_identical_to_the_tty_wizard_and_audits() {
        let dir = scratch("identical");
        let target = dir.join("mia.toml");
        // An existing file with a key the wizard does not edit.
        std::fs::write(
            &target,
            "[helper]\nsocket_gid = '991'\n[status]\nsocket_gid = '992'\n",
        )
        .unwrap();
        let existing = setup::load_existing(&target);
        let mut tty = tty_settings();
        tty.carried = Carried::from_existing(&existing);
        let expected = setup::render(&tty, None);

        let draft = write_draft(&dir, &full_draft());
        apply(&draft, &apply_opts(&target)).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), expected);
        // The carried keys survive; the draft is gone.
        let cfg = Config::from_toml(&expected).unwrap();
        assert_eq!(cfg.helper.socket_gid.as_deref(), Some("991"));
        assert_eq!(cfg.status_socket_gid().unwrap(), Some(992));
        assert!(!draft.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640);
        }
        // One ConfigChanged event, names only.
        let journal =
            std::fs::read_to_string(crate::audit_client::local_journal_for(&target)).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(journal.lines().next().unwrap()).unwrap();
        assert_eq!(line["event"]["type"], "ConfigChanged");
        let keys: Vec<String> = serde_json::from_value(line["event"]["keys"].clone()).unwrap();
        assert!(keys.contains(&"cmis.endpoint".to_string()));
        assert!(keys.contains(&"attestation.backend".to_string()));
        assert!(!keys.contains(&"helper.socket_gid".to_string()));
        assert!(
            !journal.contains(PIN),
            "audit must carry key names, not values"
        );
        assert!(!journal.contains("cmis.example.com"));
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_rejects_unknown_keys_malformed_and_oversize_drafts() {
        let dir = scratch("reject");
        let target = dir.join("mia.toml");
        for bad in [
            "nonsense = true\n".to_string(),
            "[status]\nsocket = '/tmp/x'\n".to_string(), // not a wizard key
            "[cmis\n".to_string(),
            "log = 'info'\n# ".to_string() + &"x".repeat(MAX_DRAFT_BYTES),
            "[cmis]\nendpoint = 'ftp://x'\n".to_string(),
            format!("[cmis]\nendpoint = 'https://x:1'\nsrv = '_c._tcp.x'\nspki_pin = '{PIN}'\n"),
            "[cmis]\nendpoint = 'https://x:1'\n".to_string(), // pin missing
            "[allowlist]\npath = '/x'\n".to_string(),         // key missing
            "[attestation]\nbackend = 'quantum'\n".to_string(),
            "[helper]\nsocket_mode = '999'\n".to_string(),
            "log = \"info'\\n[cmis]\\nendpoint = 'https://evil'\"\n".to_string(), // injection
        ] {
            let draft = write_draft(&dir, &bad);
            assert!(
                apply(&draft, &apply_opts(&target)).is_err(),
                "accepted: {bad:.80}"
            );
            assert!(!target.exists(), "wrote despite: {bad:.80}");
            // A rejected draft is left for the caller to inspect.
            assert!(draft.exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn apply_refuses_shared_writable_or_symlinked_drafts() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("perm");
        let target = dir.join("mia.toml");
        let draft = write_draft(&dir, "log = 'info'\n");
        std::fs::set_permissions(&draft, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(apply(&draft, &apply_opts(&target)).is_err());
        std::fs::set_permissions(&draft, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&draft, &link).unwrap();
        assert!(apply(&link, &apply_opts(&target)).is_err());
        assert!(!target.exists());
        // The real file applies fine.
        apply(&draft, &apply_opts(&target)).unwrap();
        assert!(target.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn apply_refuses_hard_linked_drafts() {
        let dir = scratch("hardlink");
        let target = dir.join("mia.toml");
        let draft = write_draft(&dir, "log = 'info'\n");
        std::fs::hard_link(&draft, dir.join("other-name.toml")).unwrap();
        assert!(apply(&draft, &apply_opts(&target)).is_err());
        assert!(!target.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrollment_key_fetch_is_constrained_before_any_network() {
        let dir = scratch("fetch");
        let target = dir.join("mia.toml");
        let who = Invoker {
            #[cfg(unix)]
            euid: 0,
            elevated: true,
        };
        let base = || Settings {
            cmis_endpoint: Some("https://cmis.example.com:8443".into()),
            cmis_spki_pin: Some(PIN.into()),
            allowlist_key: Some(dir.join("allowlist.pub").display().to_string()),
            ..Settings::default()
        };
        // Plaintext http:// is never used to fetch a trust anchor.
        let mut s = base();
        s.cmis_endpoint = Some("http://cmis.example.com:8080".into());
        s.cmis_spki_pin = None;
        let e = fetch_enrollment_key(&s, &target, who, 1000).unwrap_err();
        assert!(format!("{e:#}").contains("pinned"), "{e:#}");
        // Relative or `..` destinations are refused.
        let mut s = base();
        s.allowlist_key = Some("allowlist.pub".into());
        assert!(fetch_enrollment_key(&s, &target, who, 1000).is_err());
        let mut s = base();
        s.allowlist_key = Some(dir.join("../escape.pub").display().to_string());
        assert!(fetch_enrollment_key(&s, &target, who, 1000).is_err());
        // Elevated, the key must sit beside the configuration file.
        let mut s = base();
        s.allowlist_key = Some("/tmp/elsewhere/allowlist.pub".into());
        let e = fetch_enrollment_key(&s, &target, who, 1000).unwrap_err();
        assert!(
            format!("{e:#}").contains("beside the configuration"),
            "{e:#}"
        );
        assert!(!dir.join("allowlist.pub").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn elevated_parse_errors_do_not_echo_the_input() {
        let err = parse_draft("secret_token_line = 1\n", false).unwrap_err();
        assert!(
            !err.message.contains("secret_token_line"),
            "{}",
            err.message
        );
        assert!(err.message.contains("line 1"));
        let err = parse_draft("secret_token_line = 1\n", true).unwrap_err();
        assert!(err.message.contains("secret_token_line"));
    }

    #[cfg(unix)]
    #[test]
    fn apply_refuses_to_replace_a_symlinked_target() {
        let dir = scratch("symtarget");
        let real = dir.join("real.toml");
        std::fs::write(&real, "log = 'info'\n").unwrap();
        let target = dir.join("mia.toml");
        std::os::unix::fs::symlink(&real, &target).unwrap();
        let draft = write_draft(&dir, "log = 'debug'\n");
        assert!(apply(&draft, &apply_opts(&target)).is_err());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "log = 'info'\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_reports_every_problem() {
        let dir = scratch("check");
        let draft = write_draft(
            &dir,
            "log = 'info'\n[cmis]\nendpoint = 'ftp://x'\n[allowlist]\npath = '/x'\n",
        );
        let errors = load_draft(&draft, false, true).unwrap_err();
        let keys: Vec<&str> = errors.iter().map(|e| e.key.as_str()).collect();
        assert!(keys.contains(&"cmis.endpoint"));
        assert!(keys.contains(&"allowlist.key"));
        let ok = write_draft(&dir, &full_draft());
        assert!(load_draft(&ok, false, true).is_ok());
        assert!(check(&ok, true).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_keys_lists_names_only() {
        let old = Config::from_toml("log = 'info'\n[cmis]\nendpoint = 'https://a:1'\n").unwrap();
        let new = Config::from_toml(
            "log = 'info'\n[cmis]\nendpoint = 'https://b:1'\n[status]\nenable = false\n",
        )
        .unwrap();
        assert_eq!(
            changed_keys(&old, &new),
            vec!["cmis.endpoint", "status.enable"]
        );
        assert_eq!(changed_keys(&old, &old), [] as [String; 0]);
    }

    #[test]
    fn option_parsing_enforces_exclusivity() {
        let a = |v: &[&str]| Opts::parse(&v.iter().map(ToString::to_string).collect::<Vec<_>>());
        assert!(a(&["--check", "x", "--apply", "y"]).is_err());
        assert!(a(&["--dump", "--reload"]).is_err());
        assert!(a(&["--apply", "x", "-e", "prod", "-o", "/tmp/x"]).is_err());
        assert!(a(&["--apply", "x", "-e", "../etc"]).is_err());
        assert!(a(&["--json"]).is_err()); // no mode
        let o = a(&[
            "--apply",
            "d.toml",
            "--user",
            "--reload",
            "--fetch-enrollment-key",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(o.mode, Mode::Apply(PathBuf::from("d.toml")));
        assert!(o.user && o.reload && o.fetch_key);
    }

    #[test]
    fn apply_keeps_or_sets_the_helper_switch() {
        let dir = scratch("helper-switch");
        let target = dir.join("mia.toml");
        std::fs::write(&target, "[helper]\nenable = false\n").unwrap();

        // A draft that omits `enable` must not re-enable the helper API.
        let draft = write_draft(&dir, "log = 'info'\n");
        apply(&draft, &apply_opts(&target)).unwrap();
        let cfg = setup::load_existing(&target);
        assert!(!cfg.helper_enabled());
        assert_eq!(cfg.helper_socket(), None);

        // An explicit `enable = true` turns it back on (at the default socket).
        let draft = write_draft(&dir, "[helper]\nenable = true\n");
        apply(&draft, &apply_opts(&target)).unwrap();
        let cfg = setup::load_existing(&target);
        assert!(cfg.helper_enabled());
        assert_eq!(
            cfg.helper_socket(),
            Some(crate::config::default_helper_socket(None))
        );

        // And `enable = false` switches it off again.
        let draft = write_draft(&dir, "[helper]\nenable = false\n");
        apply(&draft, &apply_opts(&target)).unwrap();
        assert!(!setup::load_existing(&target).helper_enabled());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_reports_values_and_env_overrides() {
        let dir = scratch("dump");
        let target = dir.join("mia.toml");
        std::fs::write(&target, "log = 'debug'\n").unwrap();
        let mut o = apply_opts(&target);
        o.mode = Mode::Dump;
        dump(&o).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
