//! `mia allowlist-diagnose` — explain why a local caller is, or is not,
//! permitted by this host's signed caller allowlist.
//!
//! The helper API answers a refused caller with an opaque `permission_denied`
//! (the audit log records `not-allowlisted`). This command replays, offline,
//! the allowlist half of that decision for one caller — a uid plus a binary,
//! given as `--exe <path>` (hashed with [`bin_sha384`], exactly as the helper
//! hashes a caller's image) or as a precomputed `--sha384 <hex>` — and reports,
//! in order, stopping at the first blocking cause with a targeted remediation
//! hint:
//!
//! 1. the allowlist body (`allowlist.path`, or its per-environment default);
//! 2. the verification key `allowlist.key`;
//! 3. the signature;
//! 4. validity (the `issued_at`/`not_after` window and `allowlist.max_age`),
//!    and the trust domain;
//! 5. whether any entry admits the uid (an entry may omit the uid, ADR-0002);
//! 6. whether any entry covers the binary — when none does, the binaries that
//!    *are* listed are shown by their first 12 hex characters, so a stale hash
//!    left behind by an upgrade stands out;
//! 7. the verdict of [`Allowlist::permits`], the very check the helper runs.
//!
//! The files are read and verified exactly as the daemon reads them at start
//! (through [`crate::system_dir::read_trusted`] and [`Allowlist::load`]).
//! `mia`'s own binary is self-trusted by the daemon and never reaches the
//! allowlist; the command reports that instead. Caller authentication (IMA,
//! Authenticode), the host SVID and the CRL gate are out of scope — `mia test`
//! exercises the live path.
//!
//! It is strictly read-only and offline: it never contacts CMIS or the running
//! daemon and writes nothing. It prints the caller's own hash, 12-character
//! prefixes of listed hashes, uids and the key's short fingerprint — never key
//! material.
//!
//! Exit status (stable, for scripts):
//!
//! | code | meaning |
//! |------|---------|
//! | [`EXIT_PERMITTED`] (0) | the allowlist admits the caller |
//! | [`EXIT_DENIED`] (1) | the caller is denied; the report names the cause |
//! | [`EXIT_ERROR`] (2) | bad arguments, or a file could not be read |

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ferro_crypto::composite::CompositePublicKey;

use crate::allowlist_key::short;
use crate::config::Config;
use crate::helper::allowlist::{
    AllowRule, Allowlist, AllowlistError, RuleUids, ALLOWLIST_NOT_BEFORE_LEEWAY_SECS,
};
use crate::helper::auth::{bin_sha384, running_exe_sha384};
use crate::status_cli::{human_duration, unix_now};

/// The allowlist admits the caller.
pub const EXIT_PERMITTED: i32 = 0;
/// The caller is denied; the report names the blocking cause.
pub const EXIT_DENIED: i32 = 1;
/// Usage error, or the configuration, allowlist, key or binary could not be
/// read.
pub const EXIT_ERROR: i32 = 2;

/// Longest command-line argument accepted.
const MAX_ARG_LEN: usize = 4096;
/// Length of a hex SHA-384.
const SHA384_HEX_LEN: usize = 96;
/// Bytes of a listed hash shown (12 hex characters).
const PREFIX_BYTES: usize = 6;
/// Most listed entries or uids printed before the rest is summarised.
const MAX_LISTED: usize = 16;
/// Largest binary `--exe` hashes (larger ones: pass `--sha384`).
const MAX_EXE_BYTES: u64 = 1 << 30;
/// Longest `#!` line inspected for the interpreter hint.
const MAX_SHEBANG_LEN: usize = 256;

const USAGE: &str = "usage: mia allowlist-diagnose (--exe <path> | --sha384 <hex>) [--uid <n>]\n\
     \x20                            [--config <path> | --environment <env>] [--json]";

/// Shared remediation: pull the host's allowlist again.
const RESYNC_HINT: &str = "Pull this host's allowlist from CMIS with `mia resync-allowlist \
     --reload` (add -e <env> for a named environment), or enable allowlist.fetch.";

/// Shared hint: which uid the helper matches.
const UID_HINT: &str = "The helper matches the uid the caller *process* runs as (SO_PEERCRED / \
     getpeereid; on Windows the user SID's RID), not the binary's owner — check --uid \
     (default: the uid running this command).";

/// Shared hint: which binary the helper hashes.
const EXE_HINT: &str = "The helper hashes the executable the caller process was started from \
     (/proc/<pid>/exe, symlinks resolved): for a launcher, wrapper or script that is the program \
     finally exec'd, not the file that was run.";

/// The seven checks, in order: stable id (for `--json`) and label.
const STEPS: [(&str, &str); 7] = [
    ("allowlist_file", "[1/7] allowlist file"),
    ("allowlist_key", "[2/7] allowlist.key"),
    ("signature", "[3/7] signature"),
    ("validity", "[4/7] validity"),
    ("uid", "[5/7] uid"),
    ("binary_hash", "[6/7] binary hash"),
    ("verdict", "[7/7] verdict"),
];

/// Run `mia allowlist-diagnose`. `args` is everything after
/// `allowlist-diagnose`. Returns the process exit code (see the module docs);
/// errors are printed, not returned.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("mia allowlist-diagnose: {e:#}");
            EXIT_ERROR
        }
    }
}

fn run_inner(args: &[String]) -> anyhow::Result<i32> {
    let Some(opts) = parse(args)? else {
        return Ok(EXIT_PERMITTED); // --help printed
    };
    let (config, source) = Config::load(opts.config.as_deref(), opts.environment.as_deref())?;
    let uid = match opts.uid {
        Some(uid) => uid,
        None => current_uid()?,
    };
    let caller = match &opts.binary {
        Binary::Exe(path) => {
            let (bin_sha, exe) = hash_exe(path)?;
            Caller {
                uid,
                bin_sha,
                exe: Some(exe),
            }
        }
        Binary::Sha384(bin_sha) => Caller {
            uid,
            bin_sha: *bin_sha,
            exe: None,
        },
    };
    let report = diagnose(
        &AllowlistSource::from_config(&config),
        &caller,
        unix_now(),
        running_exe_sha384(),
    )?;
    if opts.json {
        let doc = to_json(
            &report,
            &caller,
            source.as_deref(),
            opts.environment.as_deref(),
        );
        println!("{}", serde_json::to_string_pretty(&doc)?);
    } else {
        print!("{}", render(&report, &caller, source.as_deref()));
    }
    Ok(report.exit_code())
}

// ── Options ──────────────────────────────────────────────────────────────────

/// How the caller's binary is named.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Binary {
    /// `--exe <path>`: hash this file.
    Exe(PathBuf),
    /// `--sha384 <hex>`: a precomputed hash.
    Sha384([u8; 48]),
}

/// Parsed command-line options.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opts {
    /// `--config <path>` override (same resolution as the daemon).
    config: Option<PathBuf>,
    /// `--environment <env>`: select `mia-<env>.toml`.
    environment: Option<String>,
    /// The caller's binary (required).
    binary: Binary,
    /// `--uid <n>`; `None` means the uid running this command.
    uid: Option<u32>,
    /// `--json`: one machine-readable document.
    json: bool,
}

/// Parse `args`; `Ok(None)` means `--help` was printed.
fn parse(args: &[String]) -> anyhow::Result<Option<Opts>> {
    let mut config = None;
    let mut environment = None;
    let mut binary: Option<Binary> = None;
    let mut uid = None;
    let mut json = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        anyhow::ensure!(arg.len() <= MAX_ARG_LEN, "argument too long\n\n{USAGE}");
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "-c" | "--config" => config = Some(PathBuf::from(value(&mut it, "--config")?)),
            "-e" | "--environment" => {
                let env = value(&mut it, "--environment")?;
                crate::config::validate_environment(env)?;
                environment = Some(env.to_owned());
            }
            "--exe" => set_binary(&mut binary, Binary::Exe(value(&mut it, "--exe")?.into()))?,
            "--sha384" => {
                let sha = parse_sha384(value(&mut it, "--sha384")?)?;
                set_binary(&mut binary, Binary::Sha384(sha))?;
            }
            "-u" | "--uid" => {
                let n = value(&mut it, "--uid")?.trim().parse().ok().context(
                    "--uid must be a non-negative integer (a numeric uid; on Windows the user's RID)",
                )?;
                uid = Some(n);
            }
            "--json" => json = true,
            other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }
    anyhow::ensure!(
        !(config.is_some() && environment.is_some()),
        "--config and --environment are mutually exclusive\n\n{USAGE}"
    );
    let binary = binary.with_context(|| {
        format!("name the caller's binary with --exe <path> or --sha384 <hex>\n\n{USAGE}")
    })?;
    Ok(Some(Opts {
        config,
        environment,
        binary,
        uid,
        json,
    }))
}

/// The value following `flag`, bounded in length.
fn value<'a>(it: &mut std::slice::Iter<'a, String>, flag: &str) -> anyhow::Result<&'a str> {
    let v = it
        .next()
        .with_context(|| format!("{flag} requires a value\n\n{USAGE}"))?;
    anyhow::ensure!(v.len() <= MAX_ARG_LEN, "{flag} value is too long");
    Ok(v)
}

/// Record the caller's binary, refusing a second `--exe` / `--sha384`.
fn set_binary(slot: &mut Option<Binary>, binary: Binary) -> anyhow::Result<()> {
    anyhow::ensure!(
        slot.is_none(),
        "--exe and --sha384 are mutually exclusive, and each is given once\n\n{USAGE}"
    );
    *slot = Some(binary);
    Ok(())
}

/// Validate a `--sha384` value: exactly 96 hex digits (either case,
/// surrounding whitespace ignored). The value is never echoed back.
fn parse_sha384(input: &str) -> anyhow::Result<[u8; 48]> {
    let hex = input.trim();
    anyhow::ensure!(
        hex.len() == SHA384_HEX_LEN && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "--sha384 must be the {SHA384_HEX_LEN}-character hex SHA-384 of the caller's binary (got \
         {} characters)",
        hex.len()
    );
    let mut sha = [0u8; 48];
    hex::decode_to_slice(hex, &mut sha).context("--sha384 is not valid hex")?;
    Ok(sha)
}

fn print_help() {
    println!(
        "mia allowlist-diagnose — explain why a local caller is or is not allowlisted\n\
         \n\
         {USAGE}\n\
         \n\
         Replays, offline, the helper API's allowlist decision for one caller (a uid\n\
         and a binary) and reports, in order: the allowlist file, allowlist.key, the\n\
         signature, validity and trust domain, an entry for the uid, an entry for\n\
         the binary hash, and the verdict. It stops at the first blocking cause with\n\
         a remediation hint. Read-only: it never contacts CMIS or the running agent\n\
         and writes nothing.\n\
         \n\
         Exit status: 0 permitted, 1 denied (the cause is reported), 2 usage or\n\
         I/O error.\n\
         \n\
         options:\n\
         \x20     --exe <path>        the caller's executable, hashed (SHA-384) as the\n\
         \x20                         helper hashes it (for a script: its interpreter)\n\
         \x20     --sha384 <hex>      the binary's SHA-384 instead of --exe (96 hex digits)\n\
         \x20 -u, --uid <n>           the caller's uid (Windows: user RID); default: the\n\
         \x20                         uid running this command\n\
         \x20 -c, --config <path>     TOML config file (same resolution as the daemon)\n\
         \x20 -e, --environment <env> select mia-<env>.toml instead of mia.toml; excludes\n\
         \x20                         --config\n\
         \x20     --json              print the result as one JSON document (same exit\n\
         \x20                         status)\n\
         \x20 -h, --help              show this help\n\
         \n\
         The allowlist and key are often readable by root only: run it with sudo."
    );
}

// ── The caller ───────────────────────────────────────────────────────────────

/// The caller being diagnosed.
#[derive(Debug, Clone)]
struct Caller {
    /// The uid the caller runs as.
    uid: u32,
    /// [`bin_sha384`] of its binary.
    bin_sha: [u8; 48],
    /// The file it was hashed from (`--exe`), if any.
    exe: Option<Exe>,
}

/// What `--exe` hashed.
#[derive(Debug, Clone)]
struct Exe {
    /// The path as given.
    given: PathBuf,
    /// The path with symlinks resolved, when it resolves.
    resolved: Option<PathBuf>,
    /// For a `#!` script: what to pass as `--exe` instead.
    interpreter: Option<String>,
}

impl Exe {
    /// The path actually hashed, for display.
    fn shown(&self) -> &Path {
        self.resolved.as_deref().unwrap_or(&self.given)
    }
}

/// Hash `path` with [`bin_sha384`], as the helper hashes a caller's image.
/// Only a regular file of at most [`MAX_EXE_BYTES`] is read.
fn hash_exe(path: &Path) -> anyhow::Result<([u8; 48], Exe)> {
    let too_large = || {
        format!(
            "--exe {} is larger than {MAX_EXE_BYTES} bytes; pass its hash with --sha384",
            path.display()
        )
    };
    let not_regular = || format!("--exe {} is not a regular file", path.display());
    let meta =
        std::fs::metadata(path).with_context(|| format!("reading --exe {}", path.display()))?;
    anyhow::ensure!(meta.is_file(), not_regular());
    anyhow::ensure!(meta.len() <= MAX_EXE_BYTES, too_large());
    let file =
        std::fs::File::open(path).with_context(|| format!("reading --exe {}", path.display()))?;
    // Re-checked on the opened handle: the path may have changed since.
    anyhow::ensure!(file.metadata()?.is_file(), not_regular());
    let mut image = Vec::new();
    file.take(MAX_EXE_BYTES + 1)
        .read_to_end(&mut image)
        .with_context(|| format!("reading --exe {}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(image.len()).is_ok_and(|n| n <= MAX_EXE_BYTES),
        too_large()
    );
    let exe = Exe {
        given: path.to_path_buf(),
        resolved: std::fs::canonicalize(path).ok(),
        interpreter: shebang_interpreter(&image),
    };
    Ok((bin_sha384(&image), exe))
}

/// For a `#!` script, the `--exe` value that names its interpreter (for
/// `#!/usr/bin/env prog`, a `$(command -v prog)` substitution). `None` for
/// anything else, or a line too odd to echo safely.
fn shebang_interpreter(image: &[u8]) -> Option<String> {
    let rest = image.strip_prefix(b"#!")?;
    let line = rest.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line.get(..MAX_SHEBANG_LEN).unwrap_or(line)).ok()?;
    let mut words = line.split_whitespace();
    let interpreter = words.next()?;
    let shown = if Path::new(interpreter).file_name() == Some(std::ffi::OsStr::new("env")) {
        let program = words.find(|w| !w.starts_with('-'))?;
        format!("\"$(command -v {program})\"")
    } else {
        interpreter.to_owned()
    };
    (!shown.chars().any(char::is_control)).then_some(shown)
}

/// The uid the helper would see for a caller running as this user: the peer
/// credentials of a connected socket pair, read with the same portable
/// `peer_cred` (`SO_PEERCRED` / `getpeereid`) the helper listener uses — no
/// `unsafe`.
#[cfg(unix)]
fn current_uid() -> anyhow::Result<u32> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .context("starting an I/O runtime")?;
    runtime
        .block_on(async {
            let (ours, _theirs) = tokio::net::UnixStream::pair()?;
            Ok::<u32, std::io::Error>(ours.peer_cred()?.uid())
        })
        .context("reading this process's uid (pass --uid <n>)")
}

/// The caller's `uid` on Windows is its user SID's RID, read as the helper's
/// `WindowsCallerAuth` reads it.
#[cfg(windows)]
fn current_uid() -> anyhow::Result<u32> {
    ferro_winauth::process_user_rid(std::process::id())
        .context("reading this process's user RID (pass --uid <n>)")
}

#[cfg(not(any(unix, windows)))]
fn current_uid() -> anyhow::Result<u32> {
    anyhow::bail!("cannot determine the current uid on this platform; pass --uid <n>")
}

// ── The diagnosis ────────────────────────────────────────────────────────────

/// Where the allowlist and its key come from, as resolved from [`Config`].
#[derive(Debug, Clone)]
struct AllowlistSource {
    /// The body: `allowlist.path` or its per-environment default.
    path: PathBuf,
    /// `path` is the built-in default, not an operator's choice.
    path_is_default: bool,
    /// `allowlist.key` (no default).
    key: Option<PathBuf>,
    /// `allowlist.max_age`, seconds.
    max_age_secs: i64,
}

impl AllowlistSource {
    fn from_config(config: &Config) -> Self {
        Self {
            path: config.allowlist_path(),
            path_is_default: config.allowlist_path_is_default(),
            key: config.allowlist_key().map(Path::to_path_buf),
            max_age_secs: config.allowlist_max_age(),
        }
    }

    /// The body path, marked `(default)` when it is.
    fn body_label(&self) -> String {
        if self.path_is_default {
            format!("{} (default)", self.path.display())
        } else {
            self.path.display().to_string()
        }
    }
}

/// One check's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Fail,
    Skip,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Fail => "FAIL",
            Self::Skip => "skip",
        }
    }
}

/// One reported check.
#[derive(Debug, Clone)]
struct Step {
    id: &'static str,
    label: &'static str,
    status: Status,
    detail: String,
    /// Extra lines (e.g. the listed binaries).
    notes: Vec<String>,
    /// Remediation hints.
    hints: Vec<String>,
}

/// Why the caller is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cause {
    AllowlistMissing,
    KeyNotConfigured,
    KeyMissing,
    KeyUnparseable,
    Undecodable,
    BadSignature,
    Expired,
    NotYetValid,
    TooOld,
    MalformedEntry,
    NoEntryForUid,
    NoEntryForBinary,
    PairNotListed,
}

impl Cause {
    /// Stable code for `--json` and the summary line.
    fn code(self) -> &'static str {
        match self {
            Self::AllowlistMissing => "allowlist-missing",
            Self::KeyNotConfigured => "key-not-configured",
            Self::KeyMissing => "key-missing",
            Self::KeyUnparseable => "key-unparseable",
            Self::Undecodable => "allowlist-undecodable",
            Self::BadSignature => "bad-signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not-yet-valid",
            Self::TooOld => "too-old",
            Self::MalformedEntry => "malformed-entry",
            Self::NoEntryForUid => "no-entry-for-uid",
            Self::NoEntryForBinary => "no-entry-for-binary",
            Self::PairNotListed => "pair-not-listed",
        }
    }
}

/// The overall answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Permitted — by the allowlist, or as `mia`'s own binary.
    Permitted { self_trust: bool },
    /// Denied, for this cause.
    Denied(Cause),
}

/// The full diagnosis.
#[derive(Debug, Clone)]
struct Report {
    steps: Vec<Step>,
    verdict: Verdict,
}

impl Report {
    fn exit_code(&self) -> i32 {
        match self.verdict {
            Verdict::Permitted { .. } => EXIT_PERMITTED,
            Verdict::Denied(_) => EXIT_DENIED,
        }
    }

    fn cause(&self) -> Option<Cause> {
        match self.verdict {
            Verdict::Permitted { .. } => None,
            Verdict::Denied(cause) => Some(cause),
        }
    }
}

/// The checks run so far, in [`STEPS`] order.
#[derive(Debug, Default)]
struct Checks {
    steps: Vec<Step>,
}

impl Checks {
    fn push(&mut self, status: Status, detail: String) -> &mut Step {
        let (id, label) = STEPS[self.steps.len()];
        self.steps.push(Step {
            id,
            label,
            status,
            detail,
            notes: Vec::new(),
            hints: Vec::new(),
        });
        let last = self.steps.len() - 1;
        &mut self.steps[last]
    }

    /// The next check passed.
    fn ok(&mut self, detail: String) -> &mut Step {
        self.push(Status::Ok, detail)
    }

    /// The next check is the blocking cause: record it and skip the rest.
    fn deny(
        mut self,
        cause: Cause,
        detail: String,
        notes: Vec<String>,
        hints: Vec<String>,
    ) -> Report {
        let step = self.push(Status::Fail, detail);
        step.notes = notes;
        step.hints = hints;
        while self.steps.len() < STEPS.len() {
            self.push(
                Status::Skip,
                "not checked (an earlier check blocks)".to_owned(),
            );
        }
        Report {
            steps: self.steps,
            verdict: Verdict::Denied(cause),
        }
    }
}

/// Diagnose `caller` against the allowlist `src` names, at `now`. `self_sha`
/// is the daemon's self-trust hash ([`running_exe_sha384`]). `Err` only for
/// an unexpected I/O failure (not `NotFound`) reading the body or key — the
/// same failures that make the daemon refuse to start (explicit path) or
/// serve deny-all (default path).
fn diagnose(
    src: &AllowlistSource,
    caller: &Caller,
    now: i64,
    self_sha: Option<[u8; 48]>,
) -> anyhow::Result<Report> {
    if self_sha == Some(caller.bin_sha) {
        return Ok(self_trusted(caller));
    }
    let mut checks = Checks::default();
    let (body, key) = match read_files(&mut checks, src)? {
        Ok(files) => files,
        Err(denied) => return Ok(*denied),
    };
    let fingerprint = key.fingerprint_hex();
    let allowlist = match Allowlist::load(&body, &key, now, src.max_age_secs) {
        Ok(allowlist) => allowlist,
        Err(e) => return Ok(not_verified(checks, e, &body, &key, now, src)),
    };
    checks.ok(format!(
        "verifies under allowlist.key (fingerprint {}…)",
        short(&fingerprint)
    ));
    checks.ok(format!(
        "trust domain {}; expires in {} (not_after {}); {} rule(s)",
        printable(allowlist.trust_domain()),
        human_duration(allowlist.not_after() - now),
        allowlist.not_after(),
        allowlist.entry_count()
    ));
    Ok(membership(checks, &allowlist, caller))
}

/// `mia`'s own binary: the daemon permits it without the allowlist.
fn self_trusted(caller: &Caller) -> Report {
    let mut steps = vec![Step {
        id: "self_trust",
        label: "self-trust",
        status: Status::Ok,
        detail: format!(
            "binary {}… is this mia build's own executable: the daemon permits it without \
             consulting the allowlist",
            prefix(&caller.bin_sha)
        ),
        notes: Vec::new(),
        hints: vec![
            "This holds only while the running daemon is this same mia build. If the helper \
             still refuses mia as not-allowlisted, restart the daemon after the upgrade."
                .to_owned(),
        ],
    }];
    steps.extend(STEPS.iter().map(|&(id, label)| Step {
        id,
        label,
        status: Status::Skip,
        detail: "not consulted for mia's own binary".to_owned(),
        notes: Vec::new(),
        hints: Vec::new(),
    }));
    Report {
        steps,
        verdict: Verdict::Permitted { self_trust: true },
    }
}

/// A finished report that denies the caller (boxed: it is the rare path).
type Denied = Box<Report>;

/// Checks 1 and 2: read the body and the key through the daemon's trust gate.
/// The outer `Err` is an unexpected I/O failure; the inner one a denial.
fn read_files(
    checks: &mut Checks,
    src: &AllowlistSource,
) -> anyhow::Result<Result<(Vec<u8>, CompositePublicKey), Denied>> {
    let deny = |checks: &mut Checks, cause, detail, hints: Vec<String>| {
        Err(Box::new(std::mem::take(checks).deny(
            cause,
            detail,
            Vec::new(),
            hints,
        )))
    };
    let body = match crate::system_dir::read_trusted(&src.path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut hints = vec![RESYNC_HINT.to_owned()];
            if src.path_is_default {
                hints.push(
                    "If the allowlist is delivered out of band, set allowlist.path to where it \
                     is placed."
                        .to_owned(),
                );
            }
            let detail = format!(
                "{} not found — every caller is denied (fail closed)",
                src.body_label()
            );
            return Ok(deny(checks, Cause::AllowlistMissing, detail, hints));
        }
        Err(e) => return Err(read_error("the allowlist", &src.path, &e)),
    };
    checks.ok(format!("{} — {} bytes", src.body_label(), body.len()));

    let Some(key_path) = src.key.as_deref() else {
        let detail = format!(
            "allowlist.key is not set (it has no default) — every caller is denied (fail \
             closed){}",
            if src.path_is_default {
                ""
            } else {
                "; with an explicit allowlist.path the daemon refuses to start"
            }
        );
        let hints = vec![
            "Name the CMIS enrollment public key file as allowlist.key (`mia setup`, or \
             [allowlist] key = \"…\"), then install it as root: `sudo mia allowlist-key fetch \
             --expect-fingerprint <hex>` — <hex> is what `ferrogate enrollment-key` prints on \
             CMIS."
                .to_owned(),
        ];
        return Ok(deny(checks, Cause::KeyNotConfigured, detail, hints));
    };
    let key_bytes = match crate::system_dir::read_trusted(key_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let detail = format!(
                "{} does not exist — every caller is denied (fail closed)",
                key_path.display()
            );
            let hints = vec![
                "Install it as root: `sudo mia allowlist-key fetch --expect-fingerprint <hex>` \
                 (<hex> from `ferrogate enrollment-key` on CMIS), or deliver it out of band."
                    .to_owned(),
            ];
            return Ok(deny(checks, Cause::KeyMissing, detail, hints));
        }
        Err(e) => return Err(read_error("allowlist.key", key_path, &e)),
    };
    let Ok(key) = CompositePublicKey::from_concat_bytes(&key_bytes) else {
        let detail = format!(
            "{} does not parse as a composite public key ({} bytes) — every caller is denied \
             (fail closed)",
            key_path.display(),
            key_bytes.len()
        );
        let hints = vec![
            "Replace it as root: `sudo mia allowlist-key fetch --rotate --expect-fingerprint \
             <hex>` (<hex> from `ferrogate enrollment-key` on CMIS)."
                .to_owned(),
        ];
        return Ok(deny(checks, Cause::KeyUnparseable, detail, hints));
    };
    checks.ok(format!(
        "{} — fingerprint {}… (`mia allowlist-key show` prints it in full)",
        key_path.display(),
        short(&key.fingerprint_hex())
    ));
    Ok(Ok((body, key)))
}

/// An I/O failure other than `NotFound`, with the usual fix.
fn read_error(what: &str, path: &Path, e: &std::io::Error) -> anyhow::Error {
    let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
        " — run it as root (sudo) or as the mia service user; on Windows the file is also \
         refused when a non-administrator could modify it"
    } else {
        ""
    };
    anyhow::anyhow!("cannot read {what} {}: {e}{hint}", path.display())
}

/// Checks 3 and 4 when [`Allowlist::load`] refused the body.
fn not_verified(
    mut checks: Checks,
    err: AllowlistError,
    body: &[u8],
    key: &CompositePublicKey,
    now: i64,
    src: &AllowlistSource,
) -> Report {
    let fingerprint = key.fingerprint_hex();
    let fp = short(&fingerprint);
    let key_hints = || {
        vec![
            "The key and the allowlist come from different issuers — commonly after a CMIS \
             redeploy changed its enrollment key, or behind an HA name whose nodes serve \
             different keys. Compare `mia allowlist-key show` with `ferrogate enrollment-key` \
             on CMIS."
                .to_owned(),
            "If CMIS's key changed: `sudo mia allowlist-key fetch --rotate --expect-fingerprint \
             <hex>`, then `mia resync-allowlist --reload`."
                .to_owned(),
        ]
    };
    let signature_detail = |what: &str| {
        format!(
            "{what} under allowlist.key (fingerprint {fp}…) — every caller is denied (fail closed)"
        )
    };
    match err {
        AllowlistError::Cbor(e) => checks.deny(
            Cause::Undecodable,
            format!(
                "{} does not decode as a signed allowlist ({}) — every caller is denied (fail \
                 closed)",
                src.path.display(),
                printable(&e)
            ),
            Vec::new(),
            vec![RESYNC_HINT.to_owned()],
        ),
        AllowlistError::MalformedSignature => checks.deny(
            Cause::BadSignature,
            signature_detail("its signature is malformed and cannot verify"),
            Vec::new(),
            key_hints(),
        ),
        AllowlistError::BadSignature => checks.deny(
            Cause::BadSignature,
            signature_detail("its signature does not verify"),
            Vec::new(),
            key_hints(),
        ),
        // The signature verified; the window or content did not.
        err @ (AllowlistError::Expired
        | AllowlistError::NotYetValid
        | AllowlistError::TooOld
        | AllowlistError::MalformedEntry) => {
            checks.ok(format!("verifies under allowlist.key (fingerprint {fp}…)"));
            let (cause, detail, hints) = invalid(&err, signed_window(body, key), now, src);
            checks.deny(cause, detail, Vec::new(), hints)
        }
    }
}

/// `(issued_at, not_after)` of a body whose signature verified (its
/// freshness is what failed), read back through the shared verifier.
fn signed_window(body: &[u8], key: &CompositePublicKey) -> Option<(i64, i64)> {
    let signed = crate::helper::allowlist::decode(body).ok()?;
    let doc = ferro_svid::allowlist::verify(&signed, key).ok()?;
    Some((doc.issued_at, doc.not_after))
}

/// Check 4's failure: cause, detail and hints for a verified but unusable
/// body.
fn invalid(
    err: &AllowlistError,
    window: Option<(i64, i64)>,
    now: i64,
    src: &AllowlistSource,
) -> (Cause, String, Vec<String>) {
    const DENY_ALL: &str = "every caller is denied (fail closed)";
    let clock = "Check this host's clock (NTP / chrony / w32time): validity is judged against it."
        .to_owned();
    let (issued_at, not_after) = window.unwrap_or((now, now));
    match err {
        AllowlistError::Expired => (
            Cause::Expired,
            format!(
                "expired {} ago (not_after {not_after}) — {DENY_ALL}",
                human_duration(now - not_after)
            ),
            vec![
                format!(
                    "{RESYNC_HINT} CMIS re-stamps validity on every `ferrogate allowlist \
                     set/add`; if the fetched body is still expired, ask the CMIS operator to \
                     re-issue it."
                ),
                clock,
            ],
        ),
        AllowlistError::NotYetValid => (
            Cause::NotYetValid,
            format!(
                "issued {} in the future (issued_at {issued_at}), beyond the \
                 {ALLOWLIST_NOT_BEFORE_LEEWAY_SECS}s skew allowance — {DENY_ALL}",
                human_duration(issued_at - now)
            ),
            vec![clock],
        ),
        AllowlistError::TooOld => (
            Cause::TooOld,
            format!(
                "issued {} ago, older than allowlist.max_age ({}) — {DENY_ALL}",
                human_duration(now - issued_at),
                human_duration(src.max_age_secs)
            ),
            vec![
                RESYNC_HINT.to_owned(),
                "Or raise allowlist.max_age if this host legitimately goes that long between \
                 re-syncs."
                    .to_owned(),
            ],
        ),
        // `MalformedEntry`, the only other variant `not_verified` passes here.
        _ => (
            Cause::MalformedEntry,
            format!(
                "the signature verifies, but an entry's bin_sha is neither a 96-digit hex \
                 SHA-384 nor `*` — {DENY_ALL}"
            ),
            vec![
                "A CMIS-side data problem: inspect with `ferrogate allowlist show --host <uuid>` \
                 (`mia machine-id` on this host prints <uuid>), drop the bad entry with \
                 `ferrogate allowlist remove`, then `mia resync-allowlist --reload`."
                    .to_owned(),
            ],
        ),
    }
}

/// Checks 5–7 over a verified allowlist.
fn membership(mut checks: Checks, allowlist: &Allowlist, caller: &Caller) -> Report {
    let rules = allowlist.rules();
    let (uid, sha) = (caller.uid, &caller.bin_sha);
    let pinned = rules.iter().find(|r| r.bin_sha.as_ref() == Some(sha));

    // 5. Some entry admits the uid.
    let admitting = rules.iter().filter(|r| r.uids.admits(uid)).count();
    if admitting == 0 {
        return no_entry_for_uid(checks, &rules, pinned, caller);
    }
    checks.ok(format!(
        "uid {uid} is admitted by {admitting} of {} rule(s)",
        rules.len()
    ));

    // 6. Some entry covers the binary.
    let any_bin = rules.iter().find(|r| r.bin_sha.is_none());
    match (pinned, any_bin) {
        (Some(rule), _) => {
            checks.ok(format!(
                "binary {}… is listed for {}",
                prefix(sha),
                describe(&rule.uids)
            ));
        }
        (None, Some(rule)) if rule.uids.admits(uid) => {
            checks.ok(format!(
                "binary {}… is not listed by hash, but uid {uid} may run any binary (bin_sha = *)",
                prefix(sha)
            ));
        }
        _ => return no_entry_for_binary(checks, &rules, caller),
    }

    // 7. The helper's own check.
    if allowlist.permits(uid, sha) {
        checks
            .ok(format!(
                "permitted — uid {uid} running {}… passes the allowlist",
                prefix(sha)
            ))
            .notes
            .push(
                "The helper's other gates still apply: caller authentication (IMA on Linux, \
                 Authenticode on Windows), the host SVID and a fresh CRL. `mia test` exercises \
                 the live path; a denial's audit reason names the gate that failed."
                    .to_owned(),
            );
        return Report {
            steps: checks.steps,
            verdict: Verdict::Permitted { self_trust: false },
        };
    }
    let listed_for = pinned.map_or_else(String::new, |r| describe(&r.uids));
    checks.deny(
        Cause::PairNotListed,
        format!(
            "uid {uid} and binary {}… are each listed, but not together: the binary is listed \
             for {listed_for} only",
            prefix(sha)
        ),
        Vec::new(),
        vec![add_entry_hint(caller), UID_HINT.to_owned()],
    )
}

/// Check 5's failure.
fn no_entry_for_uid(
    checks: Checks,
    rules: &[AllowRule],
    pinned: Option<&AllowRule>,
    caller: &Caller,
) -> Report {
    let uid = caller.uid;
    let detail = if rules.is_empty() {
        "the allowlist has no entries — every caller is denied".to_owned()
    } else {
        format!(
            "no entry admits uid {uid}: none of the {} rule(s) is for this uid or for any uid",
            rules.len()
        )
    };
    let mut hints = Vec::new();
    if let Some(rule) = pinned {
        hints.push(format!(
            "Binary {}… is listed, but only for {}: the caller runs as a different user. Pin this \
             uid too, or — for a caller whose uid changes between runs (systemd DynamicUser, \
             sandboxes) — use a uid-wildcard entry, `--entry {}` (ADR-0002).",
            prefix(&caller.bin_sha),
            describe(&rule.uids),
            hex::encode(caller.bin_sha)
        ));
    }
    hints.push(add_entry_hint(caller));
    hints.push(UID_HINT.to_owned());
    checks.deny(
        Cause::NoEntryForUid,
        detail,
        vec![format!("uids on the allowlist: {}", listed_uids(rules))],
        hints,
    )
}

/// Check 6's failure: list what *is* allowlisted so a stale hash stands out.
fn no_entry_for_binary(checks: Checks, rules: &[AllowRule], caller: &Caller) -> Report {
    let mut notes = vec!["allowlisted binaries (SHA-384 prefix → uids):".to_owned()];
    notes.extend(listing(rules));
    if let Some(exe) = &caller.exe {
        if exe.resolved.as_deref().is_some_and(|r| r != exe.given) {
            notes.push(format!(
                "hashed {} (resolved from {})",
                exe.shown().display(),
                exe.given.display()
            ));
        }
    }
    let mut hints = vec![format!(
        "If the binary was upgraded or rebuilt, its hash changed and the allowlist still names \
         the old build: compare the prefixes above with {}…, drop the stale entry (`ferrogate \
         allowlist remove --host <uuid> --bin-sha <old-hex>`) and add the new one (below).",
        prefix(&caller.bin_sha)
    )];
    if let Some((exe, interpreter)) = caller
        .exe
        .as_ref()
        .and_then(|e| e.interpreter.as_ref().map(|i| (e, i)))
    {
        hints.push(format!(
            "{} is a script: the kernel runs its interpreter, so the helper hashes the \
             interpreter, not the script — re-run with --exe {interpreter}.",
            exe.given.display()
        ));
    }
    hints.push(add_entry_hint(caller));
    hints.push(EXE_HINT.to_owned());
    checks.deny(
        Cause::NoEntryForBinary,
        format!("no entry lists binary {}…", prefix(&caller.bin_sha)),
        notes,
        hints,
    )
}

/// How to allowlist exactly this caller.
fn add_entry_hint(caller: &Caller) -> String {
    let sha = hex::encode(caller.bin_sha);
    format!(
        "Allowlist the caller on CMIS: `ferrogate allowlist add --host <uuid> --entry {}:{sha}` \
         (or `--entry {sha}` for any uid, ADR-0002; `mia machine-id` on this host prints \
         <uuid>), then pull it here with `mia resync-allowlist --reload`.",
        caller.uid
    )
}

/// The first 12 hex characters of a hash — never the full value of a listed
/// entry.
fn prefix(sha: &[u8; 48]) -> String {
    hex::encode(&sha[..PREFIX_BYTES])
}

/// `any uid`, `uid 7` or `uids 7, 8`.
fn describe(uids: &RuleUids) -> String {
    match uids {
        RuleUids::Any => "any uid".to_owned(),
        RuleUids::Only(list) if list.len() == 1 => format!("uid {}", list[0]),
        RuleUids::Only(list) => format!("uids {}", capped(list.iter().map(u32::to_string))),
    }
}

/// The distinct uids pinned anywhere on the allowlist.
fn listed_uids(rules: &[AllowRule]) -> String {
    let mut uids: Vec<u32> = rules
        .iter()
        .filter_map(|r| match &r.uids {
            RuleUids::Only(list) => Some(list.iter().copied()),
            RuleUids::Any => None,
        })
        .flatten()
        .collect();
    uids.sort_unstable();
    uids.dedup();
    if uids.is_empty() {
        "none".to_owned()
    } else {
        capped(uids.iter().map(u32::to_string))
    }
}

/// One line per rule, capped at [`MAX_LISTED`].
fn listing(rules: &[AllowRule]) -> Vec<String> {
    let mut lines: Vec<String> = rules
        .iter()
        .take(MAX_LISTED)
        .map(|r| {
            let bin = r.bin_sha.as_ref().map_or_else(
                || "* (any binary)".to_owned(),
                |sha| format!("{}…", prefix(sha)),
            );
            format!("  {bin} → {}", describe(&r.uids))
        })
        .collect();
    if rules.is_empty() {
        lines.push("  (none)".to_owned());
    } else if rules.len() > MAX_LISTED {
        lines.push(format!("  … and {} more", rules.len() - MAX_LISTED));
    }
    lines
}

/// A comma-separated list capped at [`MAX_LISTED`] items.
fn capped(items: impl ExactSizeIterator<Item = String>) -> String {
    let total = items.len();
    let mut out = items.take(MAX_LISTED).collect::<Vec<_>>().join(", ");
    if total > MAX_LISTED {
        let _ = write!(out, ", … and {} more", total - MAX_LISTED);
    }
    out
}

/// `s` with control characters replaced, safe to print to a terminal.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

// ── Output ───────────────────────────────────────────────────────────────────

/// The human report, `mia test` style.
fn render(report: &Report, caller: &Caller, config: Option<&Path>) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "FerroGate MIA allowlist diagnosis (mia {})",
        env!("CARGO_PKG_VERSION")
    );
    let _ = match config {
        Some(path) => writeln!(out, "config: {}", path.display()),
        None => writeln!(out, "config: none found — using environment and defaults"),
    };
    let _ = writeln!(
        out,
        "caller: uid {}, binary sha384 {}",
        caller.uid,
        hex::encode(caller.bin_sha)
    );
    if let Some(exe) = &caller.exe {
        let _ = writeln!(out, "        hashed from {}", exe.shown().display());
    }
    out.push('\n');
    for step in &report.steps {
        let _ = writeln!(
            out,
            "{:<28} {:<5} {}",
            step.label,
            step.status.as_str(),
            step.detail
        );
        for note in &step.notes {
            let _ = writeln!(out, "        {note}");
        }
        for hint in &step.hints {
            let _ = writeln!(out, "        - {hint}");
        }
    }
    out.push('\n');
    let _ = match report.verdict {
        Verdict::Permitted { self_trust: true } => writeln!(
            out,
            "PERMITTED — mia's own binary is self-trusted by the daemon."
        ),
        Verdict::Permitted { self_trust: false } => {
            writeln!(out, "PERMITTED — the allowlist admits this caller.")
        }
        Verdict::Denied(cause) => writeln!(
            out,
            "DENIED ({}) — the helper API refuses this caller; see the failing check above.",
            cause.code()
        ),
    };
    out
}

/// The `--json` document.
fn to_json(
    report: &Report,
    caller: &Caller,
    config: Option<&Path>,
    environment: Option<&str>,
) -> serde_json::Value {
    let checks: Vec<serde_json::Value> = report
        .steps
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "step": s.label,
                "status": s.status.as_str(),
                "detail": s.detail,
                "notes": s.notes,
                "hints": s.hints,
            })
        })
        .collect();
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "config": config.map(|p| p.display().to_string()),
        "environment": environment,
        "caller": {
            "uid": caller.uid,
            "bin_sha384": hex::encode(caller.bin_sha),
            "exe": caller.exe.as_ref().map(|e| e.shown().display().to_string()),
        },
        "permitted": matches!(report.verdict, Verdict::Permitted { .. }),
        "self_trusted": report.verdict == Verdict::Permitted { self_trust: true },
        "cause": report.cause().map(Cause::code),
        "checks": checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::allowlist::{
        encode, load_classified, sign, AllowEntry, AllowlistDoc, AllowlistLoad, BIN_SHA_WILDCARD,
    };
    use ferro_crypto::composite::CompositeSecretKey;

    const NOW: i64 = 10_000;
    const MAX_AGE: i64 = 86_400;

    /// A scratch directory with a fresh issuer key pair; removed on drop.
    struct Fixture {
        dir: PathBuf,
        sk: CompositeSecretKey,
        pk: CompositePublicKey,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mia-allowlist-diagnose-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let (sk, pk) = CompositeSecretKey::generate().unwrap();
            Self { dir, sk, pk }
        }

        fn body(&self) -> PathBuf {
            self.dir.join("allowlist.cbor")
        }

        fn key(&self) -> PathBuf {
            self.dir.join("allowlist.pub")
        }

        /// Sign `entries` valid over `[issued_at, not_after]` and install the
        /// matching key.
        fn install(&self, entries: Vec<AllowEntry>, issued_at: i64, not_after: i64) -> &Self {
            let doc = AllowlistDoc {
                trust_domain: "ferrogate.test".into(),
                issued_at,
                not_after,
                entries,
            };
            std::fs::write(self.body(), encode(&sign(&doc, &self.sk).unwrap()).unwrap()).unwrap();
            std::fs::write(self.key(), self.pk.to_concat_bytes()).unwrap();
            self
        }

        /// A fresh allowlist (valid for an hour from `NOW`).
        fn fresh(&self, entries: Vec<AllowEntry>) -> &Self {
            self.install(entries, NOW, NOW + 3600)
        }

        fn source(&self) -> AllowlistSource {
            AllowlistSource {
                path: self.body(),
                path_is_default: false,
                key: Some(self.key()),
                max_age_secs: MAX_AGE,
            }
        }

        fn diagnose(&self, caller: &Caller) -> Report {
            diagnose(&self.source(), caller, NOW, None).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn pin(uid: u32, byte: u8) -> AllowEntry {
        AllowEntry {
            uid: Some(uid),
            bin_sha: hex::encode([byte; 48]),
        }
    }

    fn any_uid(byte: u8) -> AllowEntry {
        AllowEntry {
            uid: None,
            bin_sha: hex::encode([byte; 48]),
        }
    }

    fn caller(uid: u32, byte: u8) -> Caller {
        Caller {
            uid,
            bin_sha: [byte; 48],
            exe: None,
        }
    }

    /// The failing step, asserting every later step was skipped.
    fn failing(report: &Report) -> &Step {
        let at = report
            .steps
            .iter()
            .position(|s| s.status == Status::Fail)
            .expect("a failing step");
        assert!(report.steps[..at].iter().all(|s| s.status == Status::Ok));
        assert!(report.steps[at + 1..]
            .iter()
            .all(|s| s.status == Status::Skip));
        assert_eq!(report.steps.len(), STEPS.len());
        &report.steps[at]
    }

    fn assert_denied(report: &Report, cause: Cause, step_id: &str) -> Step {
        assert_eq!(report.verdict, Verdict::Denied(cause));
        assert_eq!(report.exit_code(), EXIT_DENIED);
        let step = failing(report).clone();
        assert_eq!(step.id, step_id, "{step:?}");
        step
    }

    #[test]
    fn permitted_pinned_caller() {
        let f = Fixture::new("permit-pinned");
        f.fresh(vec![pin(1001, 0xAA)]);
        let report = f.diagnose(&caller(1001, 0xAA));
        assert_eq!(report.verdict, Verdict::Permitted { self_trust: false });
        assert_eq!(report.exit_code(), EXIT_PERMITTED);
        assert_eq!(report.steps.len(), STEPS.len());
        assert!(report.steps.iter().all(|s| s.status == Status::Ok));
        assert!(report.steps[3].detail.contains("ferrogate.test"));
    }

    #[test]
    fn permitted_by_uid_wildcard_and_by_any_binary() {
        let f = Fixture::new("permit-wild");
        f.fresh(vec![
            any_uid(0xAA),
            AllowEntry {
                uid: Some(7),
                bin_sha: BIN_SHA_WILDCARD.to_owned(),
            },
        ]);
        assert_eq!(
            f.diagnose(&caller(4242, 0xAA)).verdict,
            Verdict::Permitted { self_trust: false }
        );
        let report = f.diagnose(&caller(7, 0xCC));
        assert_eq!(report.verdict, Verdict::Permitted { self_trust: false });
        assert!(report.steps[5].detail.contains("any binary"));
    }

    #[test]
    fn missing_allowlist_is_the_first_cause() {
        let f = Fixture::new("no-body");
        let step = assert_denied(
            &f.diagnose(&caller(1001, 0xAA)),
            Cause::AllowlistMissing,
            "allowlist_file",
        );
        assert!(step.detail.contains("not found"), "{step:?}");
        assert!(step.hints.iter().any(|h| h.contains("resync-allowlist")));
    }

    #[test]
    fn unset_key_is_reported() {
        let f = Fixture::new("key-unset");
        f.fresh(vec![pin(1001, 0xAA)]);
        let mut src = f.source();
        src.key = None;
        let report = diagnose(&src, &caller(1001, 0xAA), NOW, None).unwrap();
        let step = assert_denied(&report, Cause::KeyNotConfigured, "allowlist_key");
        assert!(step.detail.contains("refuses to start"), "{step:?}");
        assert!(step.hints.iter().any(|h| h.contains("allowlist-key fetch")));
    }

    #[test]
    fn missing_key_file_is_reported() {
        let f = Fixture::new("key-missing");
        f.fresh(vec![pin(1001, 0xAA)]);
        std::fs::remove_file(f.key()).unwrap();
        assert_denied(
            &f.diagnose(&caller(1001, 0xAA)),
            Cause::KeyMissing,
            "allowlist_key",
        );
    }

    #[test]
    fn unparseable_key_is_reported() {
        let f = Fixture::new("key-bad");
        f.fresh(vec![pin(1001, 0xAA)]);
        std::fs::write(f.key(), [0x42; 7]).unwrap();
        let step = assert_denied(
            &f.diagnose(&caller(1001, 0xAA)),
            Cause::KeyUnparseable,
            "allowlist_key",
        );
        assert!(step.hints.iter().any(|h| h.contains("--rotate")));
    }

    #[test]
    fn undecodable_body_is_reported() {
        let f = Fixture::new("garbage");
        f.fresh(vec![pin(1001, 0xAA)]);
        std::fs::write(f.body(), b"not an allowlist").unwrap();
        assert_denied(
            &f.diagnose(&caller(1001, 0xAA)),
            Cause::Undecodable,
            "signature",
        );
    }

    /// A key from another issuer: bad signature, with the fingerprint
    /// comparison as the fix — and no key material in the output.
    #[test]
    fn bad_signature_is_reported_without_key_material() {
        let f = Fixture::new("bad-sig");
        f.fresh(vec![pin(1001, 0xAA)]);
        let (_, other) = CompositeSecretKey::generate().unwrap();
        std::fs::write(f.key(), other.to_concat_bytes()).unwrap();
        let c = caller(1001, 0xAA);
        let report = f.diagnose(&c);
        let step = assert_denied(&report, Cause::BadSignature, "signature");
        assert!(step
            .hints
            .iter()
            .any(|h| h.contains("ferrogate enrollment-key")));
        let fp = other.fingerprint_hex();
        let text = render(&report, &c, None) + &to_json(&report, &c, None, None).to_string();
        assert!(text.contains(short(&fp)), "{text}");
        assert!(!text.contains(&fp), "the full fingerprint is not printed");
        let key_hex = hex::encode(other.to_concat_bytes());
        assert!(!text.contains(&key_hex[..24]), "no key bytes are printed");
    }

    #[test]
    fn expired_allowlist_is_reported_with_its_expiry() {
        let f = Fixture::new("expired");
        f.install(vec![pin(1001, 0xAA)], NOW - 7200, NOW - 3600);
        let step = assert_denied(&f.diagnose(&caller(1001, 0xAA)), Cause::Expired, "validity");
        assert!(
            step.detail.contains(&format!("not_after {}", NOW - 3600)),
            "{step:?}"
        );
    }

    #[test]
    fn not_yet_valid_allowlist_is_reported() {
        let f = Fixture::new("future");
        f.install(vec![pin(1001, 0xAA)], NOW + 1000, NOW + 5000);
        let step = assert_denied(
            &f.diagnose(&caller(1001, 0xAA)),
            Cause::NotYetValid,
            "validity",
        );
        assert!(step.hints.iter().any(|h| h.contains("clock")));
    }

    #[test]
    fn too_old_allowlist_is_reported() {
        let f = Fixture::new("too-old");
        f.install(vec![pin(1001, 0xAA)], NOW - MAX_AGE - 100, NOW + 3600);
        let step = assert_denied(&f.diagnose(&caller(1001, 0xAA)), Cause::TooOld, "validity");
        assert!(step.detail.contains("max_age"), "{step:?}");
    }

    #[test]
    fn malformed_entry_is_reported() {
        let f = Fixture::new("malformed");
        f.fresh(vec![AllowEntry {
            uid: Some(1001),
            bin_sha: "zz".into(),
        }]);
        assert_denied(
            &f.diagnose(&caller(1001, 0xAA)),
            Cause::MalformedEntry,
            "validity",
        );
    }

    /// The binary is listed for another uid: the uid check fails and says so,
    /// pointing at a uid wildcard for transient uids.
    #[test]
    fn unknown_uid_is_reported_with_the_listed_uids() {
        let f = Fixture::new("uid");
        f.fresh(vec![pin(1001, 0xAA), pin(1002, 0xBB)]);
        let step = assert_denied(
            &f.diagnose(&caller(2000, 0xAA)),
            Cause::NoEntryForUid,
            "uid",
        );
        assert!(
            step.notes.iter().any(|n| n.contains("1001, 1002")),
            "{step:?}"
        );
        assert!(
            step.hints
                .iter()
                .any(|h| h.contains("only for uid 1001") && h.contains("ADR-0002")),
            "{step:?}"
        );
    }

    #[test]
    fn empty_allowlist_denies_at_the_uid_check() {
        let f = Fixture::new("empty");
        f.fresh(Vec::new());
        let step = assert_denied(
            &f.diagnose(&caller(1001, 0xAA)),
            Cause::NoEntryForUid,
            "uid",
        );
        assert!(step.detail.contains("no entries"), "{step:?}");
    }

    /// An unlisted hash (e.g. after an upgrade): the listed binaries are shown
    /// by 12-hex prefix only, never in full.
    #[test]
    fn unknown_binary_lists_prefixes_only() {
        let f = Fixture::new("binary");
        f.fresh(vec![pin(1001, 0xBB), any_uid(0xDD)]);
        let c = caller(1001, 0xCC);
        let report = f.diagnose(&c);
        let step = assert_denied(&report, Cause::NoEntryForBinary, "binary_hash");
        let notes = step.notes.join("\n");
        assert!(
            notes.contains(&format!("{}… → uid 1001", "bb".repeat(6))),
            "{notes}"
        );
        assert!(
            notes.contains(&format!("{}… → any uid", "dd".repeat(6))),
            "{notes}"
        );
        let text = render(&report, &c, None) + &to_json(&report, &c, None, None).to_string();
        assert!(
            !text.contains(&"bb".repeat(7)),
            "a listed hash is never printed in full"
        );
        assert!(
            text.contains(&hex::encode([0xCC; 48])),
            "the caller's own hash is"
        );
        assert!(step.hints.iter().any(|h| h.contains("upgraded")));
    }

    /// A lone any-binary rule for another uid does not cover the binary.
    #[test]
    fn any_binary_rule_for_another_uid_does_not_cover_the_binary() {
        let f = Fixture::new("anybin-other");
        f.fresh(vec![
            pin(1001, 0xBB),
            AllowEntry {
                uid: Some(7),
                bin_sha: BIN_SHA_WILDCARD.to_owned(),
            },
        ]);
        let step = assert_denied(
            &f.diagnose(&caller(1001, 0xCC)),
            Cause::NoEntryForBinary,
            "binary_hash",
        );
        assert!(step
            .notes
            .iter()
            .any(|n| n.contains("* (any binary) → uid 7")));
    }

    /// uid and binary each listed, never together: only the verdict fails.
    #[test]
    fn pair_not_listed_fails_only_the_verdict() {
        let f = Fixture::new("pair");
        f.fresh(vec![pin(1001, 0xAA), pin(1002, 0xBB)]);
        let step = assert_denied(
            &f.diagnose(&caller(1001, 0xBB)),
            Cause::PairNotListed,
            "verdict",
        );
        assert!(step.detail.contains("uid 1002 only"), "{step:?}");
    }

    #[test]
    fn listing_is_capped() {
        let f = Fixture::new("cap");
        f.fresh((1u8..=20).map(|b| pin(1001, b)).collect());
        let step = assert_denied(
            &f.diagnose(&caller(1001, 0xEE)),
            Cause::NoEntryForBinary,
            "binary_hash",
        );
        assert!(
            step.notes.iter().any(|n| n.contains("… and 4 more")),
            "{step:?}"
        );
    }

    /// mia's own binary is self-trusted: permitted without touching the
    /// allowlist (here, there is none).
    #[test]
    fn own_binary_is_self_trusted() {
        let f = Fixture::new("self");
        let c = caller(1001, 0xAA);
        let report = diagnose(&f.source(), &c, NOW, Some([0xAA; 48])).unwrap();
        assert_eq!(report.verdict, Verdict::Permitted { self_trust: true });
        assert_eq!(report.exit_code(), EXIT_PERMITTED);
        assert_eq!(report.steps[0].id, "self_trust");
        assert!(report.steps[1..].iter().all(|s| s.status == Status::Skip));
    }

    /// An unreadable body (a directory) is an I/O error — exit 2, not a deny.
    #[test]
    fn unreadable_body_is_an_error() {
        let f = Fixture::new("unreadable");
        std::fs::create_dir_all(f.body()).unwrap();
        assert!(diagnose(&f.source(), &caller(1001, 0xAA), NOW, None).is_err());
    }

    /// Checks 1–4 pass exactly when the daemon's own loader puts the allowlist
    /// in force, so the diagnosis cannot drift from the daemon.
    #[test]
    fn agrees_with_the_daemon_loader() {
        let f = Fixture::new("agree");
        let (_, other) = CompositeSecretKey::generate().unwrap();
        let cases: [&dyn Fn(&Fixture); 4] = [
            &|f| {
                f.fresh(vec![pin(1001, 0xAA)]);
            },
            &|f| {
                f.install(vec![pin(1001, 0xAA)], NOW - 7200, NOW - 1);
            },
            &|f| {
                f.fresh(vec![pin(1001, 0xAA)]);
                std::fs::write(f.key(), other.to_concat_bytes()).unwrap();
            },
            &|f| {
                let _ = std::fs::remove_file(f.body());
            },
        ];
        for setup in cases {
            setup(&f);
            let report = f.diagnose(&caller(1001, 0xAA));
            let verified = report.steps[..4].iter().all(|s| s.status == Status::Ok);
            let (_, outcome) = load_classified(&f.body(), &f.key(), NOW, MAX_AGE).unwrap();
            assert_eq!(
                verified,
                matches!(outcome, AllowlistLoad::Loaded { .. }),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn json_names_the_cause() {
        let f = Fixture::new("json");
        f.fresh(vec![pin(1001, 0xBB)]);
        let c = caller(1001, 0xCC);
        let doc = to_json(&f.diagnose(&c), &c, None, Some("staging"));
        assert_eq!(doc["permitted"], false);
        assert_eq!(doc["cause"], "no-entry-for-binary");
        assert_eq!(doc["environment"], "staging");
        assert_eq!(doc["checks"].as_array().unwrap().len(), STEPS.len());
        assert_eq!(doc["checks"][5]["status"], "FAIL");
    }

    #[test]
    fn exe_is_hashed_like_the_helper_and_scripts_name_their_interpreter() {
        let f = Fixture::new("exe");
        let script = f.dir.join("tool.sh");
        let content = b"#!/bin/sh -e\necho hi\n";
        std::fs::write(&script, content).unwrap();
        let (sha, exe) = hash_exe(&script).unwrap();
        assert_eq!(sha, bin_sha384(content));
        assert_eq!(exe.interpreter.as_deref(), Some("/bin/sh"));

        let env_script = f.dir.join("tool.py");
        std::fs::write(&env_script, b"#!/usr/bin/env -S python3 -u\n").unwrap();
        assert_eq!(
            hash_exe(&env_script).unwrap().1.interpreter.as_deref(),
            Some("\"$(command -v python3)\"")
        );

        let binary = f.dir.join("tool");
        std::fs::write(&binary, [0x7F, b'E', b'L', b'F', 0, 1]).unwrap();
        assert!(hash_exe(&binary).unwrap().1.interpreter.is_none());

        assert!(hash_exe(&f.dir).is_err(), "a directory is refused");
        assert!(shebang_interpreter(b"#!/bin/\x1b[2Jsh\n").is_none());
    }

    #[test]
    fn script_hint_is_given_for_an_unlisted_script() {
        let f = Fixture::new("script-hint");
        f.fresh(vec![pin(1001, 0xBB)]);
        let script = f.dir.join("run.sh");
        std::fs::write(&script, b"#!/bin/bash\n").unwrap();
        let (bin_sha, exe) = hash_exe(&script).unwrap();
        let c = Caller {
            uid: 1001,
            bin_sha,
            exe: Some(exe),
        };
        let step = assert_denied(&f.diagnose(&c), Cause::NoEntryForBinary, "binary_hash");
        assert!(
            step.hints.iter().any(|h| h.contains("--exe /bin/bash")),
            "{step:?}"
        );
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parse_accepts_the_documented_forms() {
        let sha = "Ab".repeat(48);
        let opts = parse(&args(&[
            "--sha384", &sha, "--uid", "1001", "--json", "-e", "staging",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(opts.binary, Binary::Sha384([0xAB; 48]));
        assert_eq!(opts.uid, Some(1001));
        assert!(opts.json);
        assert_eq!(opts.environment.as_deref(), Some("staging"));

        let opts = parse(&args(&["--exe", "/usr/bin/foo", "-c", "/etc/x.toml"]))
            .unwrap()
            .unwrap();
        assert_eq!(opts.binary, Binary::Exe("/usr/bin/foo".into()));
        assert_eq!(opts.uid, None);
        assert!(parse(&args(&["--help"])).unwrap().is_none());
    }

    #[test]
    fn parse_rejects_bad_input() {
        let sha = "ab".repeat(48);
        for bad in [
            args(&[]),                                     // no binary
            args(&["--exe", "/a", "--sha384", &sha]),      // both
            args(&["--exe", "/a", "--exe", "/b"]),         // twice
            args(&["--sha384", "abc"]),                    // short hash
            args(&["--sha384", &"zz".repeat(48)]),         // not hex
            args(&["--exe", "/a", "--uid", "-1"]),         // negative uid
            args(&["--exe", "/a", "--uid"]),               // missing value
            args(&["--exe", "/a", "-c", "/x", "-e", "s"]), // config + env
            args(&["--exe", "/a", "--bogus"]),             // unknown flag
            args(&["--exe", &"a".repeat(MAX_ARG_LEN + 1)]),
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
        // A rejected hash is not echoed back.
        let err = parse(&args(&["--sha384", "secretish"])).unwrap_err();
        assert!(!err.to_string().contains("secretish"), "{err}");
    }

    /// The default uid is the one the helper would read off this process's
    /// socket — the owner of a file this process creates.
    #[cfg(unix)]
    #[test]
    fn current_uid_matches_the_process_owner() {
        use std::os::unix::fs::MetadataExt as _;
        let f = Fixture::new("uid-self");
        let probe = f.dir.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        assert_eq!(
            current_uid().unwrap(),
            std::fs::metadata(&probe).unwrap().uid()
        );
    }
}
