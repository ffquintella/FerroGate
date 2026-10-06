//! `mia allowlist-key` — install and inspect `allowlist.key`, the CMIS
//! enrollment public key that verifies the signed caller allowlist.
//!
//! `allowlist.key` is the trust anchor of the whole allowlist, so it
//! deliberately has no default ([`crate::config`]): without it the daemon
//! denies every caller (fail closed). This module is the one privileged,
//! operator-driven way to put it in place:
//!
//! - `mia allowlist-key fetch [-c <config> | -e <env>]
//!   [--expect-fingerprint <hex>] [--yes] [--rotate] [--reload]` — fetch the
//!   key from CMIS and install it at the configured `allowlist.key`;
//! - `mia allowlist-key show [-c <config> | -e <env>]` — print the installed
//!   key's path and fingerprint (offline, no privileges needed);
//! - `mia refresh-key` — deprecated alias for `fetch --rotate --yes` (its old
//!   behaviour: replace the key, non-interactively), now with every check
//!   below.
//!
//! ## Trust rules for `fetch`
//!
//! - **Privileged only** ([`require_privileged`]): root on Unix, writing into
//!   a directory only root can change; on Windows an elevated administrator,
//!   writing inside `%ProgramData%\FerroGate`, whose administrator-only ACL and
//!   Administrators ownership hand-over refuse anyone else. Checked before any
//!   network traffic.
//! - **Pinned channel only**: the key comes over
//!   [`crate::endpoint::CmisResolver`], which needs `cmis.spki_pin` and dials
//!   with the hybrid-PQC-only provider. There is no unpinned fallback.
//! - **Validated**: the reply must parse as a composite public key.
//! - **Explicit consent**: `--expect-fingerprint <hex>` (verified, the
//!   recommended non-interactive form), `--yes`, or a confirmation prompt on
//!   a terminal. Without one of them nothing is written.
//! - **Never silently replaced** ([`plan`]): an identical key is a no-op (no
//!   write, no audit record); a different key is refused unless `--rotate`.
//! - **Atomic and audited** ([`commit`]): temp file + `fsync` + rename via
//!   [`crate::setup_apply::write_policy_file`], a symlink or non-regular
//!   target refused, mode [`KEY_MODE`], owned by the writer, and a
//!   `ConfigChanged` record ([`AUDIT_KEY_INSTALLED`] / [`AUDIT_KEY_ROTATED`])
//!   appended to the local audit journal before the rename.
//! - **No key material in output**: only fingerprints
//!   ([`CompositePublicKey::fingerprint_hex`]) are printed, to compare with
//!   `ferrogate enrollment-key` on the CMIS side.
//!
//! The daemon never runs any of this: it only *reads* `allowlist.key` (at
//! startup and on a SIGHUP reload) and never fetches or trusts a key by
//! itself, and neither the helper nor the status socket can trigger a fetch.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use ferro_crypto::composite::CompositePublicKey;

use crate::config::Config;
use crate::endpoint::CmisResolver;

/// The mode `allowlist.key` is written with: world-readable. It is public
/// material whose integrity — not secrecy — matters, and it must stay readable
/// by the Linux daemon after it drops to its service user (a SIGHUP reload
/// re-reads it) and by `mia test` run as any user. Integrity comes from root
/// ownership, no group/other write bit, and the atomic replace.
pub const KEY_MODE: u32 = 0o644;

/// Audit-journal key name for a key installed where none was.
pub const AUDIT_KEY_INSTALLED: &str = "allowlist.key:enrollment-key";

/// Audit-journal key name for an installed key replaced by a different one
/// (`--rotate`).
pub const AUDIT_KEY_ROTATED: &str = "allowlist.key:enrollment-key:rotated";

/// Length of a full fingerprint: hex SHA-384.
pub const FINGERPRINT_HEX_LEN: usize = 96;

/// Characters of a fingerprint shown where a short form suffices (as in
/// `mia test`'s cluster check).
const SHORT_FINGERPRINT_LEN: usize = 12;

/// Longest option value accepted (the fingerprint is 96 characters).
const MAX_ARG_LEN: usize = 256;

/// Largest file accepted as an installed key (a composite key is ~2 KiB).
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Bound on the enrollment-key RPC once connected (each dial is bounded by
/// the resolver).
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

const USAGE: &str = "usage: mia allowlist-key fetch [--config <path> | --environment <env>]\n\
     \x20                      [--expect-fingerprint <hex>] [--yes] [--rotate] [--reload]\n\
     \x20      mia allowlist-key show [--config <path> | --environment <env>]";

/// The Unix refusal for a run that is not root.
#[cfg(unix)]
const NOT_PRIVILEGED: &str = "installing allowlist.key needs root: it is the trust anchor of the \
     caller allowlist, so only a privileged local user may install it — re-run with sudo";

/// Run `mia allowlist-key`. `args` is everything after `allowlist-key`.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let Some((sub, rest)) = args.split_first() else {
        anyhow::bail!("missing subcommand\n\n{USAGE}");
    };
    match sub.as_str() {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "fetch" => match parse(rest, true)? {
            Some(opts) => fetch(&opts),
            None => Ok(()),
        },
        "show" => match parse(rest, false)? {
            Some(opts) => show(&opts),
            None => Ok(()),
        },
        other => anyhow::bail!("unknown subcommand: {other}\n\n{USAGE}"),
    }
}

/// Run the deprecated `mia refresh-key`: `mia allowlist-key fetch --rotate
/// --yes`, accepting only its historical `--config` / `--environment`. It keeps
/// its old meaning — replace the key after a CMIS key rotation, without a
/// prompt (the `mia-tray` action runs it elevated with no terminal) — and gains
/// every `fetch` check: root only, validated, atomic, audited, fingerprinted.
pub fn run_refresh_key(args: &[String]) -> anyhow::Result<()> {
    let Some(mut opts) = parse(args, false)? else {
        return Ok(());
    };
    eprintln!(
        "note: `mia refresh-key` is deprecated; it runs `mia allowlist-key fetch --rotate --yes`. \
         Prefer `mia allowlist-key fetch --expect-fingerprint <hex>` (add --rotate to replace a \
         key)."
    );
    opts.rotate = true;
    opts.yes = true;
    fetch(&opts)
}

/// Parsed options. `expect`, `yes`, `rotate` and `reload` exist for `fetch`
/// only.
#[derive(Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent CLI switches
struct Opts {
    config: Option<PathBuf>,
    environment: Option<String>,
    /// Normalised (lowercase) expected fingerprint.
    expect: Option<String>,
    yes: bool,
    rotate: bool,
    reload: bool,
}

/// Parse options; `fetch` enables the fetch-only flags. `Ok(None)` means
/// `--help` was printed.
fn parse(args: &[String], fetch: bool) -> anyhow::Result<Option<Opts>> {
    let mut opts = Opts::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "-c" | "--config" => {
                let path = it.next().context("--config requires a path argument")?;
                anyhow::ensure!(path.len() <= 4096, "--config path is too long");
                opts.config = Some(PathBuf::from(path));
            }
            "-e" | "--environment" => {
                let env = it
                    .next()
                    .context("--environment requires a name argument")?;
                crate::config::validate_environment(env)?;
                opts.environment = Some(env.clone());
            }
            "--expect-fingerprint" if fetch => {
                let hex = it
                    .next()
                    .context("--expect-fingerprint requires a hex fingerprint argument")?;
                opts.expect = Some(parse_fingerprint(hex)?);
            }
            "-y" | "--yes" if fetch => opts.yes = true,
            "--rotate" if fetch => opts.rotate = true,
            "--reload" if fetch => opts.reload = true,
            other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }
    anyhow::ensure!(
        !(opts.config.is_some() && opts.environment.is_some()),
        "--config and --environment are mutually exclusive\n\n{USAGE}"
    );
    Ok(Some(opts))
}

/// Validate and normalise an `--expect-fingerprint` value: exactly
/// [`FINGERPRINT_HEX_LEN`] hex digits (either case, surrounding whitespace
/// ignored), returned lowercase. The value is never echoed back in an error.
///
/// # Errors
///
/// When the value is not a full hex SHA-384 fingerprint.
pub fn parse_fingerprint(input: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        input.len() <= MAX_ARG_LEN,
        "--expect-fingerprint is too long"
    );
    let hex = input.trim();
    anyhow::ensure!(
        hex.len() == FINGERPRINT_HEX_LEN && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "--expect-fingerprint must be the full {FINGERPRINT_HEX_LEN}-character hex SHA-384 \
         fingerprint printed by `ferrogate enrollment-key` (got {} characters)",
        hex.len()
    );
    Ok(hex.to_ascii_lowercase())
}

/// The short display form of a fingerprint (its first characters).
#[must_use]
pub fn short(fingerprint: &str) -> &str {
    fingerprint
        .get(..SHORT_FINGERPRINT_LEN)
        .unwrap_or(fingerprint)
}

// ── Plan and commit ──────────────────────────────────────────────────────────

/// What installing a fetched key would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// No key is installed: the fetched one is written.
    New,
    /// The identical key is already installed: nothing is written or audited.
    Unchanged,
    /// A different key is installed and is replaced (only with `rotate`).
    Rotate {
        /// The installed key's fingerprint (or a note that it does not parse).
        previous: String,
    },
}

/// A validated, not yet written install of an enrollment key.
#[derive(Debug, Clone)]
pub struct Plan {
    path: PathBuf,
    /// Canonical composite encoding of the fetched key.
    key: Vec<u8>,
    fingerprint: String,
    change: Change,
}

impl Plan {
    /// Where the key goes (`allowlist.key`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The fetched key's full fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// What committing the plan changes.
    #[must_use]
    pub fn change(&self) -> &Change {
        &self.change
    }
}

/// Why an install was refused before anything was written. Returned inside
/// the [`anyhow::Error`] of [`plan`], so callers can `downcast_ref` it.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// CMIS answered with something that is not a composite public key.
    #[error("CMIS returned something that is not a composite public key ({0}); nothing written")]
    NotAKey(String),
    /// The fetched key does not match `--expect-fingerprint`.
    #[error(
        "the fetched key's fingerprint {actual} does not match --expect-fingerprint {expected}; \
         nothing written — check cmis.spki_pin / the CMIS endpoint and compare with \
         `ferrogate enrollment-key` on CMIS"
    )]
    FingerprintMismatch {
        /// The expected fingerprint.
        expected: String,
        /// The fetched key's fingerprint.
        actual: String,
    },
    /// A different key is installed and `--rotate` was not given.
    #[error(
        "{} already holds a different enrollment key (fingerprint {installed}); CMIS now serves \
         {fetched}. Not replaced: if CMIS really rotated its key (compare with `ferrogate \
         enrollment-key` on CMIS), re-run with --rotate",
        .path.display()
    )]
    Differs {
        /// The key file.
        path: PathBuf,
        /// The installed key's fingerprint (or why it has none).
        installed: String,
        /// The fetched key's fingerprint.
        fetched: String,
    },
}

/// Decide what installing `fetched` at `key_path` would do, without writing
/// anything: validate the key, check it against `expected` (a normalised
/// fingerprint, see [`parse_fingerprint`]), and compare it with the key
/// already installed. A different installed key is refused
/// ([`Refusal::Differs`]) unless `rotate`.
///
/// # Errors
///
/// A [`Refusal`], an invalid `key_path` (not absolute, or with `..`), or an
/// installed key that cannot be read safely (a symlink, not a regular file,
/// refused by the Windows trust check, oversized).
pub fn plan(
    key_path: &Path,
    fetched: &[u8],
    expected: Option<&str>,
    rotate: bool,
) -> anyhow::Result<Plan> {
    check_key_path(key_path)?;
    let key = CompositePublicKey::from_concat_bytes(fetched)
        .map_err(|e| Refusal::NotAKey(e.to_string()))?;
    let fingerprint = key.fingerprint_hex();
    if let Some(expected) = expected {
        if expected != fingerprint {
            return Err(Refusal::FingerprintMismatch {
                expected: expected.to_owned(),
                actual: fingerprint,
            }
            .into());
        }
    }
    let key = key.to_concat_bytes();
    let change = match read_installed(key_path)? {
        None => Change::New,
        Some(installed) if installed == key => Change::Unchanged,
        Some(installed) => {
            let previous = describe(&installed);
            if !rotate {
                return Err(Refusal::Differs {
                    path: key_path.to_path_buf(),
                    installed: previous,
                    fetched: fingerprint,
                }
                .into());
            }
            Change::Rotate { previous }
        }
    };
    Ok(Plan {
        path: key_path.to_path_buf(),
        key,
        fingerprint,
        change,
    })
}

/// Write a [`Plan`]: nothing for [`Change::Unchanged`]; otherwise the atomic,
/// audited replace of [`crate::setup_apply::write_policy_file`] with
/// [`KEY_MODE`], recording [`AUDIT_KEY_INSTALLED`] or [`AUDIT_KEY_ROTATED`]
/// in the local audit journal beside the key before the rename (no record, no
/// change).
///
/// # Errors
///
/// The staging, audit or rename failure; the target is then unchanged.
pub fn commit(plan: &Plan) -> anyhow::Result<()> {
    let audit_key = match plan.change {
        Change::Unchanged => return Ok(()),
        Change::New => AUDIT_KEY_INSTALLED,
        Change::Rotate { .. } => AUDIT_KEY_ROTATED,
    };
    crate::setup_apply::write_policy_file(
        &plan.path,
        &plan.key,
        KEY_MODE,
        vec![audit_key.to_owned()],
    )
    .with_context(|| format!("installing {}", plan.path.display()))
}

/// `allowlist.key` must be absolute, without `..`, and name a file.
fn check_key_path(key_path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        key_path.is_absolute()
            && !key_path.components().any(|c| c == Component::ParentDir)
            && key_path.file_name().is_some(),
        "allowlist.key ({}) must be an absolute file path without `..`",
        key_path.display()
    );
    Ok(())
}

/// The installed key's bytes, `None` when absent. A symlink, a non-regular
/// file or an oversized one is refused rather than read or replaced.
fn read_installed(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => anyhow::bail!(
            "{} is a symbolic link; refusing to read or replace the allowlist trust anchor \
             through it",
            path.display()
        ),
        Ok(m) if !m.is_file() => {
            anyhow::bail!("{} exists and is not a regular file", path.display())
        }
        Ok(m) if m.len() > MAX_KEY_FILE_BYTES => anyhow::bail!(
            "{} is {} bytes, far larger than an enrollment key; inspect and remove it first",
            path.display(),
            m.len()
        ),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", path.display())),
    }
    // Judged as the daemon judges it (`crate::system_dir`, Windows).
    crate::system_dir::read_trusted(path)
        .map(Some)
        .with_context(|| format!("reading the installed key {}", path.display()))
}

/// An installed key's fingerprint, or why it has none.
fn describe(installed: &[u8]) -> String {
    CompositePublicKey::from_concat_bytes(installed).map_or_else(
        |_| {
            format!(
                "none — the file does not parse as a key, {} bytes",
                installed.len()
            )
        },
        |k| k.fingerprint_hex(),
    )
}

// ── Privilege ────────────────────────────────────────────────────────────────

/// Refuse unless this process may install the allowlist trust anchor at
/// `key_path`.
///
/// - **Unix:** the effective uid must be 0 (learned with
///   [`crate::setup_apply::probe_euid`] — no `unsafe`), and the key's
///   directory must exist, be owned by root and not be group/other-writable,
///   so nobody else can swap the key after it is written.
/// - **Windows:** `key_path` must lie inside the system configuration
///   directory (`%ProgramData%\FerroGate`): that directory is
///   administrator-only and the written file must be handed to
///   Administrators, so a process that is not elevated cannot complete the
///   install there. Elsewhere elevation cannot be verified, so it is refused.
///
/// # Errors
///
/// The refusal, naming the fix.
pub fn require_privileged(key_path: &Path) -> anyhow::Result<()> {
    check_key_path(key_path)?;
    let dir = key_path
        .parent()
        .context("allowlist.key has no directory")?;
    require_privileged_in(dir, key_path)
}

#[cfg(unix)]
fn require_privileged_in(dir: &Path, _key_path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(dir).with_context(|| {
        format!(
            "the directory of allowlist.key ({}) is missing; create it (root-owned, 0755) or \
             point allowlist.key into the configuration directory",
            dir.display()
        )
    })?;
    anyhow::ensure!(meta.is_dir(), "{} is not a directory", dir.display());
    // Not writable ⇒ certainly not root here; the probe error itself is noise.
    let euid = crate::setup_apply::probe_euid(dir).ok();
    unix_verdict(euid, dir, meta.uid(), meta.mode())
}

/// The Unix decision of [`require_privileged`], separated for testing.
#[cfg(unix)]
fn unix_verdict(euid: Option<u32>, dir: &Path, dir_uid: u32, dir_mode: u32) -> anyhow::Result<()> {
    anyhow::ensure!(euid == Some(0), NOT_PRIVILEGED);
    anyhow::ensure!(
        dir_uid == 0 && dir_mode & 0o022 == 0,
        "{} is not owned by root or is writable by group/others (owner uid {dir_uid}, mode \
         {:o}); refusing to install the allowlist trust anchor where another user could \
         replace it",
        dir.display(),
        dir_mode & 0o7777
    );
    Ok(())
}

#[cfg(windows)]
fn require_privileged_in(_dir: &Path, key_path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        crate::system_dir::is_inside_system_dir(key_path),
        "on Windows, allowlist.key is installed only inside {} — where administrator rights \
         are enforced — so point allowlist.key there and run this from an elevated prompt",
        crate::config::system_config_dir().display()
    );
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn require_privileged_in(_dir: &Path, _key_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("allowlist-key fetch is not supported on this platform")
}

// ── Fetch ────────────────────────────────────────────────────────────────────

/// Dial CMIS through `resolver` (pinned hybrid-PQC TLS, fail-over across its
/// candidates) and fetch the enrollment key. Returns the endpoint that served
/// it and the raw reply, which is **not** validated here — pass it to
/// [`plan`]. Synchronous: runs its own current-thread runtime.
///
/// # Errors
///
/// No CMIS node completed the pinned handshake, or the RPC failed or timed
/// out.
pub fn fetch_key(resolver: &CmisResolver) -> anyhow::Result<(String, Vec<u8>)> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime")?
        .block_on(fetch_key_async(resolver))
}

/// [`fetch_key`] for callers already inside a Tokio runtime.
///
/// # Errors
///
/// As [`fetch_key`].
pub async fn fetch_key_async(resolver: &CmisResolver) -> anyhow::Result<(String, Vec<u8>)> {
    let (endpoint, mut client) = resolver
        .connect()
        .await
        .context("connecting to CMIS over the pinned channel")?;
    let key = tokio::time::timeout(
        RPC_TIMEOUT,
        crate::client::fetch_enrollment_key(&mut client),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "the enrollment-key RPC to {endpoint} timed out after {}s",
            RPC_TIMEOUT.as_secs()
        )
    })?
    .with_context(|| format!("fetching the enrollment key from {endpoint}"))?;
    Ok((endpoint, key))
}

// ── Commands ─────────────────────────────────────────────────────────────────

/// `mia allowlist-key fetch`.
fn fetch(opts: &Opts) -> anyhow::Result<()> {
    let (config, source) = Config::load(opts.config.as_deref(), opts.environment.as_deref())?;
    println!(
        "FerroGate allowlist-key fetch (mia {})",
        env!("CARGO_PKG_VERSION")
    );
    print_source(source.as_deref());
    let key_path = configured_key(&config, source.as_deref())?;
    check_key_path(&key_path)?;
    println!("key:    {}", key_path.display());
    note_env_overrides();

    // Privilege first: an unprivileged run never reaches the network.
    require_privileged(&key_path)?;
    let resolver = CmisResolver::from_config(&config.cmis)?.context(
        "cmis is not configured (set cmis.endpoint or cmis.srv, and cmis.spki_pin); run \
         `mia setup`",
    )?;
    let (endpoint, fetched) = fetch_key(&resolver)?;
    if resolver.is_srv() {
        println!(
            "cmis:   {endpoint} (pinned hybrid-PQC TLS, via SRV {})",
            resolver.describe()
        );
    } else {
        println!("cmis:   {endpoint} (pinned hybrid-PQC TLS)");
    }

    let plan = plan(&key_path, &fetched, opts.expect.as_deref(), opts.rotate)?;
    println!(
        "\nenrollment key fingerprint (SHA-384):\n  {}",
        plan.fingerprint()
    );
    if opts.expect.is_some() {
        println!("  ✓ matches --expect-fingerprint");
    } else {
        println!(
            "  compare it with `ferrogate enrollment-key` on CMIS (or pass \
             --expect-fingerprint <hex> to have it checked)"
        );
    }

    match plan.change() {
        Change::Unchanged => {
            println!(
                "\n✓ {} already holds this key; nothing written.",
                key_path.display()
            );
            report_body(&config, &key_path);
            return Ok(());
        }
        Change::New | Change::Rotate { .. } => consent(&plan, opts)?,
    }

    commit(&plan)?;
    let journal = crate::audit_client::local_journal_for(&key_path);
    match plan.change() {
        Change::Rotate { previous } => println!(
            "\n✓ rotated {}: {} → {} (audit: {})",
            key_path.display(),
            short(previous),
            short(plan.fingerprint()),
            journal.display()
        ),
        _ => println!(
            "\n✓ installed {} (fingerprint {}; audit: {})",
            key_path.display(),
            short(plan.fingerprint()),
            journal.display()
        ),
    }
    report_body(&config, &key_path);

    if opts.reload {
        crate::resync::signal_reload();
    } else {
        println!(
            "\nLoad it into the running agent:  sudo mia --reload   (or restart: {})",
            crate::setup::restart_hint()
        );
    }
    Ok(())
}

/// Require explicit consent for a write: `--expect-fingerprint` (already
/// verified by [`plan`]) or `--yes`, else a prompt on a terminal. A
/// non-interactive run without either writes nothing.
fn consent(plan: &Plan, opts: &Opts) -> anyhow::Result<()> {
    if opts.expect.is_some() || opts.yes {
        return Ok(());
    }
    anyhow::ensure!(
        std::io::IsTerminal::is_terminal(&std::io::stdin()),
        "no consent to install the allowlist trust anchor: pass --expect-fingerprint <hex> (the \
         value `ferrogate enrollment-key` prints on CMIS; recommended) or --yes; nothing written"
    );
    let question = match plan.change() {
        Change::Rotate { previous } => format!(
            "Replace the installed key {} with this one ({})?",
            short(previous),
            short(plan.fingerprint())
        ),
        _ => format!(
            "Install this key ({}) as {}?",
            short(plan.fingerprint()),
            plan.path().display()
        ),
    };
    let answer = inquire::Confirm::new(&question)
        .with_default(false)
        .with_help_message("compare the fingerprint above with `ferrogate enrollment-key` on CMIS")
        .prompt();
    match answer {
        Ok(true) => Ok(()),
        Ok(false)
        | Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => anyhow::bail!("not confirmed; nothing written"),
        Err(e) => Err(e.into()),
    }
}

/// `mia allowlist-key show`: the installed key's path and fingerprint.
fn show(opts: &Opts) -> anyhow::Result<()> {
    let (config, source) = Config::load(opts.config.as_deref(), opts.environment.as_deref())?;
    let key_path = configured_key(&config, source.as_deref())?;
    let bytes = match crate::system_dir::read_trusted(&key_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
            "{} does not exist yet — every caller is denied; install it: sudo mia allowlist-key \
             fetch",
            key_path.display()
        ),
        Err(e) => return Err(e).with_context(|| format!("reading {}", key_path.display())),
    };
    let key = CompositePublicKey::from_concat_bytes(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "{} is not a composite public key ({e}) — every caller is denied; replace it: sudo \
             mia allowlist-key fetch --rotate",
            key_path.display()
        )
    })?;
    println!("allowlist.key: {}", key_path.display());
    println!("fingerprint:   {}", key.fingerprint_hex());
    Ok(())
}

/// The configured `allowlist.key`, or an error saying where to set it.
fn configured_key(config: &Config, source: Option<&Path>) -> anyhow::Result<PathBuf> {
    config
        .allowlist_key()
        .map(Path::to_path_buf)
        .with_context(|| not_configured(config, source))
}

/// Why there is nothing to install into: `allowlist.key` has no default.
fn not_configured(config: &Config, source: Option<&Path>) -> String {
    let name = config.environment().map_or_else(
        || "allowlist.pub".to_owned(),
        |env| format!("allowlist-{env}.pub"),
    );
    let suggested = crate::config::system_config_dir().join(name);
    format!(
        "allowlist.key is not set{} — it deliberately has no default. Name the file first, then \
         re-run: `mia setup` (it can also fetch the key), or add under [allowlist]:  key = \"{}\"",
        source.map_or_else(String::new, |p| format!(" in {}", p.display())),
        suggested.display()
    )
}

fn print_source(source: Option<&Path>) {
    match source {
        Some(path) => println!("config: {}", path.display()),
        None => println!("config: none found — using environment and defaults"),
    }
}

/// Say when a trust-relevant setting comes from this process's environment
/// rather than the configuration file, so the operator knows which pin and
/// path were used.
fn note_env_overrides() {
    const TRUST_KEYS: [&str; 4] = [
        "cmis.endpoint",
        "cmis.srv",
        "cmis.spki_pin",
        "allowlist.key",
    ];
    for o in crate::config::env_overridden(crate::config::EnvOverrideScope::Full, |v| {
        std::env::var(v).ok()
    }) {
        if TRUST_KEYS.contains(&o.key) {
            println!(
                "note:   {} comes from ${} in this environment",
                o.key, o.var
            );
        }
    }
}

/// Report whether the allowlist body on disk verifies under the key now
/// installed at `key_path`, and what to do next.
fn report_body(config: &Config, key_path: &Path) {
    let path = config.allowlist_path();
    match crate::system_dir::read_trusted(&path) {
        Ok(bytes) => {
            crate::resync::verify_after_write(&bytes, key_path, config.allowlist_max_age());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!(
            "note: no allowlist at {} yet — pull it: mia resync-allowlist --reload",
            path.display()
        ),
        Err(e) => println!("note: could not read {} ({e}).", path.display()),
    }
}

fn print_help() {
    println!(
        "mia allowlist-key — install or inspect allowlist.key, the CMIS enrollment\n\
         public key that verifies the signed caller allowlist\n\
         \n\
         {USAGE}\n\
         \n\
         fetch  Dial CMIS over the pinned hybrid-PQC channel (cmis.spki_pin; no\n\
         \x20      unpinned fallback), fetch the enrollment key, print its SHA-384\n\
         \x20      fingerprint and install it at the configured allowlist.key —\n\
         \x20      atomically, mode 0644, root-owned, with an audit record. Needs\n\
         \x20      root (Windows: an elevated prompt, key inside %ProgramData%\\FerroGate).\n\
         \x20      An identical installed key is left alone; a different one is\n\
         \x20      refused unless --rotate. Nothing is written without consent:\n\
         \x20      --expect-fingerprint, --yes, or a confirmation prompt.\n\
         show   Print the installed key's path and fingerprint (no privileges).\n\
         \n\
         Compare the fingerprint with `ferrogate enrollment-key` run against CMIS.\n\
         \n\
         options:\n\
         \x20 -c, --config <path>        TOML config file (default: the system config;\n\
         \x20                            environment variables override it)\n\
         \x20 -e, --environment <env>    use mia-<env>.toml; excludes --config\n\
         \x20     --expect-fingerprint <hex>  (fetch) install only if the fetched key has\n\
         \x20                            this 96-hex-digit fingerprint; no prompt\n\
         \x20 -y, --yes                  (fetch) install without a prompt (no comparison)\n\
         \x20     --rotate               (fetch) allow replacing a different installed key\n\
         \x20     --reload               (fetch) signal the running agent to reload (SIGHUP)\n\
         \x20 -h, --help                 show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_crypto::composite::CompositeSecretKey;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mia-allowlist-key-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // canonicalize: macOS temp dirs sit behind the /var → /private/var link.
        dir.canonicalize().unwrap()
    }

    fn key(seed: u8) -> (Vec<u8>, String) {
        let (_sk, pk) = CompositeSecretKey::from_seed(&[seed; 32]);
        (pk.to_concat_bytes(), pk.fingerprint_hex())
    }

    fn journal_lines(key_path: &Path) -> Vec<String> {
        std::fs::read_to_string(crate::audit_client::local_journal_for(key_path))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn fetch_writes_the_key_atomically_and_audits_it() {
        let dir = scratch("new");
        let path = dir.join("allowlist.pub");
        let (bytes, fp) = key(1);
        let p = plan(&path, &bytes, Some(&fp), false).unwrap();
        assert_eq!(p.change(), &Change::New);
        assert_eq!(p.fingerprint(), fp);
        commit(&p).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, KEY_MODE);
        }
        let lines = journal_lines(&path);
        assert_eq!(lines.len(), 1, "{lines:?}");
        let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(v["event"]["type"], "ConfigChanged");
        assert_eq!(v["event"]["keys"][0], AUDIT_KEY_INSTALLED);
        // Names only: neither the key nor its fingerprint is in the journal.
        assert!(!lines[0].contains(&fp[..SHORT_FINGERPRINT_LEN]));
        assert_eq!(leftovers(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_identical_installed_key_is_a_no_op() {
        let dir = scratch("same");
        let path = dir.join("allowlist.pub");
        let (bytes, _) = key(2);
        commit(&plan(&path, &bytes, None, false).unwrap()).unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Even with --rotate, the same key changes nothing and audits nothing.
        for rotate in [false, true] {
            let p = plan(&path, &bytes, None, rotate).unwrap();
            assert_eq!(p.change(), &Change::Unchanged);
            commit(&p).unwrap();
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        assert_eq!(journal_lines(&path).len(), 1, "only the first install");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_different_key_is_refused_without_rotate_and_audited_with_it() {
        let dir = scratch("differs");
        let path = dir.join("allowlist.pub");
        let (old, old_fp) = key(3);
        let (new, new_fp) = key(4);
        commit(&plan(&path, &old, None, false).unwrap()).unwrap();

        let err = plan(&path, &new, None, false).unwrap_err();
        match err.downcast_ref::<Refusal>() {
            Some(Refusal::Differs {
                installed, fetched, ..
            }) => assert_eq!((installed, fetched), (&old_fp, &new_fp)),
            other => panic!("expected Differs, got {other:?} ({err:#})"),
        }
        assert!(format!("{err:#}").contains("--rotate"));
        assert_eq!(std::fs::read(&path).unwrap(), old, "untouched");
        assert_eq!(journal_lines(&path).len(), 1);

        let p = plan(&path, &new, None, true).unwrap();
        assert_eq!(p.change(), &Change::Rotate { previous: old_fp });
        commit(&p).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), new);
        let lines = journal_lines(&path);
        assert_eq!(lines.len(), 2);
        let v: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(v["event"]["keys"][0], AUDIT_KEY_ROTATED);
        assert_eq!(leftovers(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_expected_fingerprint_aborts_and_writes_nothing() {
        let dir = scratch("mismatch");
        let path = dir.join("allowlist.pub");
        let (bytes, _) = key(5);
        let (_, other_fp) = key(6);
        let err = plan(&path, &bytes, Some(&other_fp), false).unwrap_err();
        assert!(
            matches!(
                err.downcast_ref::<Refusal>(),
                Some(Refusal::FingerprintMismatch { .. })
            ),
            "{err:#}"
        );
        assert!(!path.exists());
        assert_eq!(journal_lines(&path), Vec::<String>::new());
        assert_eq!(leftovers(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reply_that_is_not_a_key_writes_nothing() {
        let dir = scratch("garbage");
        let path = dir.join("allowlist.pub");
        let err = plan(&path, b"not a key", None, true).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<Refusal>(),
            Some(Refusal::NotAKey(_))
        ));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsafe_targets_are_refused() {
        let dir = scratch("targets");
        let (bytes, _) = key(7);
        // Relative or `..` paths.
        assert!(plan(Path::new("allowlist.pub"), &bytes, None, false).is_err());
        assert!(plan(&dir.join("..").join("x.pub"), &bytes, None, false).is_err());
        // A directory at the target.
        std::fs::create_dir(dir.join("d.pub")).unwrap();
        assert!(plan(&dir.join("d.pub"), &bytes, None, true).is_err());
        // A symlink at the target is neither followed nor replaced.
        #[cfg(unix)]
        {
            let real = dir.join("real.pub");
            std::fs::write(&real, b"x").unwrap();
            let link = dir.join("link.pub");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let err = plan(&link, &bytes, None, true).unwrap_err();
            assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
            assert_eq!(std::fs::read(&real).unwrap(), b"x");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expected_fingerprints_are_validated_and_normalised() {
        let (_, fp) = key(8);
        assert_eq!(parse_fingerprint(&fp.to_ascii_uppercase()).unwrap(), fp);
        assert_eq!(parse_fingerprint(&format!("  {fp}\n")).unwrap(), fp);
        assert!(
            parse_fingerprint(short(&fp)).is_err(),
            "a prefix is not enough"
        );
        assert!(parse_fingerprint(&format!("{}zz", &fp[..94])).is_err());
        assert!(parse_fingerprint(&"a".repeat(1000)).is_err());
        let err = parse_fingerprint("secret-looking-input").unwrap_err();
        assert!(!format!("{err:#}").contains("secret-looking-input"));
    }

    #[test]
    fn option_parsing_is_a_closed_set() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let (_, fp) = key(9);
        let o = parse(
            &args(&[
                "-e",
                "prod",
                "--expect-fingerprint",
                &fp,
                "--rotate",
                "--reload",
                "-y",
            ]),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(o.environment.as_deref(), Some("prod"));
        assert_eq!(o.expect.as_deref(), Some(fp.as_str()));
        assert!(o.rotate && o.reload && o.yes);
        // Fetch-only flags are unknown to `show` and the `refresh-key` alias.
        assert!(parse(&args(&["--rotate"]), false).is_err());
        assert!(parse(&args(&["--yes"]), false).is_err());
        assert!(parse(&args(&["--bogus"]), true).is_err());
        assert!(parse(&args(&["-c", "/x.toml", "-e", "prod"]), true).is_err());
        assert!(parse(&args(&["-e", "../etc"]), true).is_err());
        assert!(run(&args(&["frobnicate"])).is_err());
        assert!(run(&[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_privilege_verdict() {
        let dir = Path::new("/etc/ferrogate");
        assert!(unix_verdict(Some(0), dir, 0, 0o755).is_ok());
        let not_root = unix_verdict(Some(1000), dir, 0, 0o755).unwrap_err();
        assert!(format!("{not_root:#}").contains("needs root"));
        assert!(
            unix_verdict(None, dir, 0, 0o755).is_err(),
            "probe failed ⇒ not root"
        );
        assert!(
            unix_verdict(Some(0), dir, 1000, 0o755).is_err(),
            "user-owned dir"
        );
        assert!(
            unix_verdict(Some(0), dir, 0, 0o775).is_err(),
            "group-writable dir"
        );
        assert!(
            unix_verdict(Some(0), dir, 0, 0o757).is_err(),
            "world-writable dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unprivileged_user_is_refused_before_any_network() {
        let dir = scratch("unprivileged");
        let path = dir.join("allowlist.pub");
        match require_privileged(&path) {
            Err(e) => assert!(format!("{e:#}").contains("needs root"), "{e:#}"),
            // Only reachable when the suite itself runs as root.
            Ok(()) => assert_eq!(crate::setup_apply::probe_euid(&dir).unwrap(), 0),
        }
        assert_eq!(leftovers(&dir), Vec::<String>::new());
        assert!(!path.exists());
        assert!(
            std::fs::read_dir(&dir).unwrap().next().is_none(),
            "the euid probe leaves nothing behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_key_setting_names_the_fix() {
        let config = Config::from_toml("").unwrap();
        let err = configured_key(&config, Some(Path::new("/etc/ferrogate/mia.toml")))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("allowlist.key is not set in /etc/ferrogate/mia.toml"),
            "{err}"
        );
        assert!(err.contains("allowlist.pub"), "{err}");
    }
}
