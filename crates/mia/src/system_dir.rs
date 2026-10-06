//! The system configuration directory as a trust boundary.
//!
//! The daemon trusts what it finds in the system configuration directory
//! ([`crate::config::system_config_dir`]) without being told where to look:
//! the discovered `mia.toml` / `mia-<env>.toml`, `environments.toml`, the
//! default allowlist body `allowlist[-<env>].cbor`, and usually
//! `allowlist.key`. On macOS and Windows the daemon also keeps its state
//! there — the machine key `host-key.bin`, `svid-seed.bin` and
//! `x509-svid.sealed` ([`crate::credstore::state_dir`]) — and on Windows the
//! service writes its log to `logs\mia.log` below it.
//!
//! On Windows that directory is `%ProgramData%\FerroGate`. A directory created
//! there with a plain `CreateDirectory` inherits `%ProgramData%`'s DACL, which
//! lets `BUILTIN\Users` create files and folders in it and makes them the
//! owner of what they create, and lets every user read what is in it. A local
//! user could plant a configuration, an environment selection, an allowlist
//! body (verified against the key, but able to deny every caller or replay an
//! older signed body) or a machine key for the `LocalSystem` service to load;
//! could pre-create `logs` as a junction so the service writes its log
//! wherever they point; and could read the machine key, whose only protection
//! on Windows is the directory's DACL
//! (`ferro_sep::KeyFilePermissions::Unmanaged`).
//!
//! This module closes that, on Windows only. Every object is opened without
//! following reparse points (`FILE_FLAG_OPEN_REPARSE_POINT`) and judged — and,
//! for a directory, changed — through that same handle
//! ([`ferro_winauth::file_acl`], [`ferro_winauth::open_no_follow`]):
//!
//! - [`prepare`] — at Windows service start (and from
//!   `mia service secure-config`, which the installers run), before anything
//!   is read: create the directory with the administrator-only, protected
//!   [`ferro_winauth::file_acl::ADMIN_ONLY_DIR_SDDL`] in one step, or lock an
//!   existing one that is not administrator-only; then walk everything below
//!   it, refusing any reparse point and locking every subdirectory that is not
//!   administrator-only; only then let Windows re-derive the inherited ACEs
//!   below what it locked;
//! - [`create_dir_all`] — create a directory; when it is inside the system
//!   directory, [`prepare`] runs first (repairing as an elevated
//!   administrator, refusing otherwise);
//! - [`open_trusted`] / [`read_trusted`] / [`check_trusted_file`] — refuse a
//!   trust-relevant file inside the system directory (`PermissionDenied`)
//!   unless it is a plain file with a single name, owned by SYSTEM or
//!   Administrators, granting no one else a write right, below directories
//!   that are the same; the bytes are read from the handle that was judged;
//! - [`open_log`] — the service's log file, judged the same way;
//! - [`write_file`] / [`claim`] — make Administrators the owner of what an
//!   elevated `mia` command writes there (an elevated administrator's files
//!   are otherwise owned by their own account on Windows clients, which the
//!   check refuses); `write_file` replaces the target with a fresh file rather
//!   than rewriting or adopting the old one.
//!
//! Directories are repaired; files never are: a file a user planted keeps that
//! user as owner, so it stays refused until an administrator deletes it (or
//! reviews and adopts it).
//!
//! **Scope.** Only paths inside the system configuration directory are judged
//! — the locations the daemon trusts implicitly. A path the operator names
//! explicitly elsewhere (`--config`, `allowlist.path`, `allowlist.key`) and
//! the per-user configuration directory are not, so development set-ups and
//! tests that use scratch directories are unaffected.
//!
//! On Linux and macOS every function here is a pass-through: the packages
//! create `/etc/ferrogate` and `/Library/Application Support/FerroGate`
//! root-owned and not group/other-writable, the daemon's own Unix ownership
//! checks live where it creates paths as root (`helper::socket_dir`,
//! `status_server`), and the state secrets are `0600`
//! ([`crate::credstore::restrict_secret_files`]).

use std::io;
use std::path::{Component, Path, PathBuf, Prefix};

/// What [`prepare`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// Not Windows: the OS package owns the directory's permissions.
    Unmanaged,
    /// The directory did not exist and was created administrator-only.
    Created,
    /// The directory and every directory below it were already
    /// administrator-only.
    AlreadyRestricted,
    /// The directory, or directories below it, were not administrator-only
    /// and their owner and DACL were replaced. No file was changed.
    Repaired {
        /// Each repaired directory and why it was not administrator-only.
        reason: String,
    },
}

/// Make the system configuration directory administrator-only before
/// anything is read from it (Windows; [`Prepared::Unmanaged`] elsewhere):
///
/// 1. create it in one step with the protected administrator-only security
///    descriptor if it is missing; otherwise open it without following a
///    reparse point (a junction or symbolic link is refused) and, if it is not
///    administrator-only, give it that owner and DACL through the same handle,
///    without touching anything below it yet;
/// 2. walk everything below it: any reparse point is refused, and every
///    subdirectory that is not administrator-only is locked the same way;
/// 3. only then, with no reparse point left anywhere below and nobody but
///    SYSTEM and Administrators able to add one, re-apply the descriptor to
///    each locked directory so Windows re-derives the inherited ACEs of the
///    files below it. Their owners and explicit ACEs are untouched, so
///    [`check_trusted_file`] still refuses a planted file.
///
/// Run by the `LocalSystem` service at start and by `mia service
/// secure-config`; changing a directory needs the right to name
/// Administrators as its owner (SYSTEM or an elevated administrator).
///
/// # Errors
///
/// `PermissionDenied` for a reparse point or a non-directory at a directory's
/// place, or for a directory still not administrator-only after the repair;
/// the creation or repair failure otherwise (e.g. when not elevated). Nothing
/// may be read from the directory after an error.
pub fn prepare() -> io::Result<Prepared> {
    #[cfg(windows)]
    {
        imp::prepare(&crate::config::system_config_dir())
    }
    #[cfg(not(windows))]
    {
        Ok(Prepared::Unmanaged)
    }
}

/// [`std::fs::create_dir_all`], except that on Windows, when `dir` is the
/// system configuration directory or lies inside it, [`prepare`] runs first:
/// a missing system directory is created administrator-only (never with the
/// DACL it would inherit from `%ProgramData%`), and an existing one — with
/// everything below it — is verified, and repaired when the caller is
/// elevated, before anything is created in it.
///
/// # Errors
///
/// The [`prepare`] refusal or failure — `ERROR_INVALID_OWNER` (1307) or
/// `PermissionDenied` when a process that is not elevated would have to create
/// or repair the system directory — or the creation failure.
pub fn create_dir_all(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    imp::ensure_system_dir_for(&crate::config::system_config_dir(), dir)?;
    std::fs::create_dir_all(dir)
}

/// Open the trust-relevant file `path` for reading. On Windows, when `path`
/// lies inside the system configuration directory, refuse it unless every
/// directory from the system directory down to its parent exists, is a real
/// directory (not a reparse point) and is administrator-only, and the file
/// itself — opened without following a reparse point — is a regular file with
/// a single name, owned by SYSTEM or `BUILTIN\Administrators`, with a DACL
/// that grants no other principal a write right. The returned handle is the
/// one that was judged, so what is read is what was checked. Paths outside
/// the system directory, and every path on Linux and macOS, are plain
/// [`std::fs::File::open`].
///
/// # Errors
///
/// `NotFound` for an absent file or guarding directory; `PermissionDenied`,
/// naming the object and why, for a refused one; other I/O errors as they
/// come.
pub fn open_trusted(path: &Path) -> io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        imp::open_trusted(&crate::config::system_config_dir(), path)
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(path)
    }
}

/// [`open_trusted`], then read the whole file from that handle.
///
/// # Errors
///
/// As [`open_trusted`], or the read error.
pub fn read_trusted(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut file = open_trusted(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Judge `path` as [`open_trusted`] does without reading it, for a file that
/// another library opens or creates by path (the machine key). An absent file
/// passes when its directories do — nobody but an administrator can then
/// create it — while an absent guarding directory is `NotFound`. Elsewhere,
/// and outside the system directory, `Ok`.
///
/// # Errors
///
/// `NotFound` for an absent guarding directory; `PermissionDenied` for a
/// refused file or directory; other I/O errors as they come.
pub fn check_trusted_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        imp::check_trusted_file(&crate::config::system_config_dir(), path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
}

/// Open (creating it if needed) the log file `path` for appending. On
/// Windows, inside the system configuration directory, its directories are
/// judged as for [`open_trusted`], the file is opened without following a
/// reparse point, and a file that is a reparse point, has more than one name
/// or is not administrator-only is refused — so the service never writes
/// through a link a user planted.
///
/// # Errors
///
/// The open failure, or `PermissionDenied` for a refused file or directory.
pub fn open_log(path: &Path) -> io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        imp::open_log(&crate::config::system_config_dir(), path)
    }
    #[cfg(not(windows))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }
}

/// Write `bytes` to `path`, like [`std::fs::write`].
///
/// On Windows, when `path` is inside the system configuration directory (whose
/// directories are judged first), the bytes go to a fresh file beside it that
/// is handed to Administrators through its own handle and then renamed over
/// `path`. An existing file — possibly one another user created, and may still
/// hold open — is replaced, never rewritten in place or adopted. Elsewhere
/// this is [`std::fs::write`].
///
/// # Errors
///
/// The refusal of a guarding directory, or the write, ownership change or
/// rename failure; the temp file is removed.
pub fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        imp::write_file(&crate::config::system_config_dir(), path, bytes)
    }
    #[cfg(not(windows))]
    {
        std::fs::write(path, bytes)
    }
}

/// After an elevated `mia` command has created the file `path`: on Windows,
/// when `path` is inside the system configuration directory, open it without
/// following a reparse point, check it is a regular file with a single name,
/// and make `BUILTIN\Administrators` its owner through that handle, so the
/// daemon's [`check_trusted_file`] accepts it. On Windows clients a file an
/// elevated administrator creates is owned by their own account by default,
/// which the check refuses. Elsewhere a no-op.
///
/// # Errors
///
/// On Windows, the refusal of the file or a guarding directory, or the
/// ownership change failing (`ERROR_INVALID_OWNER` (1307) when the process is
/// not elevated).
pub fn claim(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        imp::claim(&crate::config::system_config_dir(), path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
}

/// Whether `path` lies strictly inside the system configuration directory
/// ([`crate::config::system_config_dir`]), compared as [`guarding_dirs`] does
/// (lexically, case-insensitively, after making `path` absolute).
///
/// On Windows that directory is administrator-only ([`prepare`]) and a file
/// written in it must be handed to Administrators ([`claim`]), so only an
/// elevated process can change what is there: `mia allowlist-key fetch`
/// ([`crate::allowlist_key`]) relies on this to refuse a non-elevated install,
/// since elevation cannot otherwise be read without `unsafe`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn is_inside_system_dir(path: &Path) -> bool {
    std::path::absolute(path)
        .is_ok_and(|p| guarding_dirs(&crate::config::system_config_dir(), &p).is_some())
}

/// The directories that guard `path` inside `system_dir`, outermost
/// (`system_dir` itself) first and `path`'s parent last, or `None` when `path`
/// is not strictly inside `system_dir`.
///
/// Comparison is lexical and case-insensitive, as Windows file names are:
/// `.` and `..` are folded first, and `C:` and `\\?\C:` count as the same
/// drive. Callers pass absolute paths (`std::path::absolute`). The returned
/// directories are spelled as in `path`.
#[cfg_attr(not(windows), allow(dead_code))]
fn guarding_dirs(system_dir: &Path, path: &Path) -> Option<Vec<PathBuf>> {
    let base = normalized(system_dir);
    let target = normalized(path);
    if target.len() <= base.len() || !same_prefix(&base, &target) {
        return None;
    }
    Some(
        (base.len()..target.len())
            .map(|end| target[..end].iter().collect())
            .collect(),
    )
}

/// Whether `dir` is `system_dir` or lies inside it (see [`guarding_dirs`] for
/// how paths are compared).
#[cfg_attr(not(windows), allow(dead_code))]
fn is_within(system_dir: &Path, dir: &Path) -> bool {
    let base = normalized(system_dir);
    let target = normalized(dir);
    target.len() >= base.len() && same_prefix(&base, &target)
}

/// Whether `target` starts with every component of `base`.
fn same_prefix(base: &[Component<'_>], target: &[Component<'_>]) -> bool {
    base.iter()
        .zip(target)
        .all(|(a, b)| component_key(a) == component_key(b))
}

/// `path`'s components with `.` dropped and `..` folded into its parent.
fn normalized(path: &Path) -> Vec<Component<'_>> {
    let mut out: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if matches!(out.last(), Some(Component::Normal(_))) => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// A case-folded comparison key for one path component.
fn component_key(component: &Component<'_>) -> String {
    match component {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                format!("disk:{}", char::from(drive).to_ascii_lowercase())
            }
            Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => format!(
                "unc:{}\\{}",
                server.to_string_lossy().to_lowercase(),
                share.to_string_lossy().to_lowercase()
            ),
            _ => prefix.as_os_str().to_string_lossy().to_lowercase(),
        },
        other => other.as_os_str().to_string_lossy().to_lowercase(),
    }
}

/// The Windows implementation. Every function takes the system directory so
/// the tests can point it at a scratch directory.
#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::io::{self, Write as _};
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};

    use ferro_winauth::file_acl::{
        check_admin_only, check_object, ObjectKind, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, GENERIC_WRITE, READ_CONTROL,
        SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
    };

    use super::Prepared;

    /// The most entries [`prepare`] walks below the system directory.
    const MAX_ENTRIES: usize = 4096;
    /// The deepest nesting [`prepare`] walks below the system directory.
    const MAX_DEPTH: usize = 16;
    /// The rights needed to judge an object through its handle.
    const JUDGE: u32 = READ_CONTROL | FILE_READ_ATTRIBUTES;
    /// How an administrator makes a directory administrator-only again.
    const SECURE_HINT: &str = "restart the mia service, or run `mia service secure-config` \
         from an elevated prompt, to make it administrator-only again";

    /// The `PermissionDenied` error for an object that is refused, with the
    /// remedy for its kind.
    fn refused(path: &Path, why: &str, kind: ObjectKind) -> io::Error {
        let remedy = match kind {
            ObjectKind::Directory => SECURE_HINT.to_string(),
            ObjectKind::File => format!(
                "delete it if you did not put it there; to keep it, review it, then run \
                 icacls \"{0}\" /setowner *S-1-5-32-544 && icacls \"{0}\" /reset",
                path.display()
            ),
        };
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not administrator-only: {why}; refusing to trust it (only SYSTEM and \
                 BUILTIN\\Administrators may own or modify what the MIA uses in its \
                 configuration directory) — {remedy}",
                path.display()
            ),
        )
    }

    /// Wrap a failure to create `dir` administrator-only.
    fn creating(dir: &Path, e: &io::Error) -> io::Error {
        io::Error::new(
            e.kind(),
            format!(
                "creating {} administrator-only: {e} (this needs the mia service or an \
                 elevated administrator prompt)",
                dir.display()
            ),
        )
    }

    /// `NotFound` for a directory that is gone or was never there.
    fn missing(dir: &Path) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} does not exist", dir.display()),
        )
    }

    /// Open the existing object at `path` with `access` (plus what judging it
    /// needs) without following a reparse point, and refuse it unless it is a
    /// plain object of `kind` ([`check_object`]). `Ok(None)` when absent.
    fn open_plain(path: &Path, kind: ObjectKind, access: u32) -> io::Result<Option<File>> {
        let file = match ferro_winauth::open_no_follow(path, access | JUDGE) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        check_object(kind, ferro_winauth::object_info(&file)?)
            .map_err(|v| refused(path, &v.to_string(), kind))?;
        Ok(Some(file))
    }

    /// Refuse the open object unless its owner and DACL are
    /// administrator-only.
    fn require_admin_only(file: &File, path: &Path, kind: ObjectKind) -> io::Result<()> {
        check_admin_only(&ferro_winauth::security_of(file)?)
            .map_err(|v| refused(path, &v.to_string(), kind))
    }

    /// Refuse an open file unless it is a plain, single-named file that is
    /// administrator-only.
    fn judge_file(file: &File, path: &Path) -> io::Result<()> {
        check_object(ObjectKind::File, ferro_winauth::object_info(file)?)
            .map_err(|v| refused(path, &v.to_string(), ObjectKind::File))?;
        require_admin_only(file, path, ObjectKind::File)
    }

    /// Refuse unless every directory in `dirs` exists, is a real directory and
    /// is administrator-only. A missing one is `NotFound`: nothing below it
    /// can exist.
    fn require_dirs(dirs: &[PathBuf]) -> io::Result<()> {
        for dir in dirs {
            let file = open_plain(dir, ObjectKind::Directory, 0)?.ok_or_else(|| missing(dir))?;
            require_admin_only(&file, dir, ObjectKind::Directory)?;
        }
        Ok(())
    }

    /// `path` made absolute and the directories guarding it, or `None` when it
    /// is not inside `system_dir`.
    fn scope(system_dir: &Path, path: &Path) -> io::Result<Option<(PathBuf, Vec<PathBuf>)>> {
        let path = std::path::absolute(path)?;
        let dirs = super::guarding_dirs(&std::path::absolute(system_dir)?, &path);
        Ok(dirs.map(|dirs| (path, dirs)))
    }

    /// See [`super::prepare`].
    pub(super) fn prepare(dir: &Path) -> io::Result<Prepared> {
        let mut created = false;
        if open_plain(dir, ObjectKind::Directory, 0)?.is_none() {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match ferro_winauth::create_admin_only_dir(dir) {
                Ok(()) => created = true,
                // Something appeared meanwhile: judge it like any other.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(creating(dir, &e)),
            }
        }
        let mut locked = Vec::new();
        let mut reasons = Vec::new();
        lock_if_needed(dir, &mut locked, &mut reasons)?;
        let mut budget = MAX_ENTRIES;
        walk(dir, 0, &mut budget, &mut locked, &mut reasons)?;
        // No reparse point is left below, and nobody but SYSTEM and
        // Administrators can add one: let Windows re-derive the inherited
        // ACEs below each locked directory.
        for (path, handle) in &locked {
            ferro_winauth::set_admin_only(handle, true).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "updating the inherited permissions below {}: {e}",
                        path.display()
                    ),
                )
            })?;
        }
        Ok(match (created, reasons.is_empty()) {
            (true, true) => Prepared::Created,
            (false, true) => Prepared::AlreadyRestricted,
            (_, false) => Prepared::Repaired {
                reason: reasons.join("; "),
            },
        })
    }

    /// If the directory `dir` is not administrator-only, give it that owner and
    /// protected DACL — on the directory alone, through a handle opened
    /// without following a reparse point and checked to be a directory — and
    /// keep that handle in `locked` for the final propagation.
    fn lock_if_needed(
        dir: &Path,
        locked: &mut Vec<(PathBuf, File)>,
        reasons: &mut Vec<String>,
    ) -> io::Result<()> {
        let file = open_plain(dir, ObjectKind::Directory, 0)?.ok_or_else(|| missing(dir))?;
        let Err(violation) = check_admin_only(&ferro_winauth::security_of(&file)?) else {
            return Ok(());
        };
        drop(file);
        let cannot = |e: &io::Error| {
            io::Error::new(
                e.kind(),
                format!(
                    "{} is not administrator-only ({violation}) and could not be repaired: {e} \
                     — {SECURE_HINT}",
                    dir.display()
                ),
            )
        };
        // Reopen with the rights to change it; the object is checked again
        // through the very handle that changes it.
        let writable = open_plain(dir, ObjectKind::Directory, WRITE_DAC | WRITE_OWNER)
            .map_err(|e| cannot(&e))?
            .ok_or_else(|| missing(dir))?;
        ferro_winauth::set_admin_only(&writable, false).map_err(|e| cannot(&e))?;
        require_admin_only(&writable, dir, ObjectKind::Directory)?;
        reasons.push(format!("{}: {violation}", dir.display()));
        locked.push((dir.to_path_buf(), writable));
        Ok(())
    }

    /// Walk everything below `dir`, refusing any reparse point and locking
    /// every subdirectory that is not administrator-only before listing it.
    fn walk(
        dir: &Path,
        depth: usize,
        budget: &mut usize,
        locked: &mut Vec<(PathBuf, File)>,
        reasons: &mut Vec<String>,
    ) -> io::Result<()> {
        if depth >= MAX_DEPTH {
            return Err(refused(
                dir,
                "it is nested too deeply below the configuration directory",
                ObjectKind::Directory,
            ));
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            *budget = budget.checked_sub(1).ok_or_else(|| {
                refused(
                    dir,
                    "the configuration directory holds too many entries",
                    ObjectKind::Directory,
                )
            })?;
            let path = entry.path();
            // A directory entry's metadata never follows a reparse point.
            let meta = entry.metadata()?;
            let kind = if meta.is_dir() {
                ObjectKind::Directory
            } else {
                ObjectKind::File
            };
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(refused(
                    &path,
                    "it is a symbolic link, junction or other reparse point",
                    kind,
                ));
            }
            if kind == ObjectKind::Directory {
                lock_if_needed(&path, locked, reasons)?;
                walk(&path, depth + 1, budget, locked, reasons)?;
            }
        }
        Ok(())
    }

    /// See [`super::create_dir_all`].
    pub(super) fn ensure_system_dir_for(system_dir: &Path, dir: &Path) -> io::Result<()> {
        let system_dir = std::path::absolute(system_dir)?;
        if !super::is_within(&system_dir, &std::path::absolute(dir)?) {
            return Ok(());
        }
        prepare(&system_dir).map(drop)
    }

    /// See [`super::open_trusted`].
    pub(super) fn open_trusted(system_dir: &Path, path: &Path) -> io::Result<File> {
        let Some((path, dirs)) = scope(system_dir, path)? else {
            return File::open(path);
        };
        require_dirs(&dirs)?;
        // GENERIC_READ includes READ_CONTROL and FILE_READ_ATTRIBUTES.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        judge_file(&file, &path)?;
        Ok(file)
    }

    /// See [`super::check_trusted_file`].
    pub(super) fn check_trusted_file(system_dir: &Path, path: &Path) -> io::Result<()> {
        let Some((path, dirs)) = scope(system_dir, path)? else {
            return Ok(());
        };
        require_dirs(&dirs)?;
        match open_plain(&path, ObjectKind::File, 0)? {
            None => Ok(()),
            Some(file) => require_admin_only(&file, &path, ObjectKind::File),
        }
    }

    /// See [`super::open_log`].
    pub(super) fn open_log(system_dir: &Path, path: &Path) -> io::Result<File> {
        let Some((path, dirs)) = scope(system_dir, path)? else {
            return std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path);
        };
        require_dirs(&dirs)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .access_mode(FILE_APPEND_DATA | SYNCHRONIZE | JUDGE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        judge_file(&file, &path)?;
        Ok(file)
    }

    /// See [`super::write_file`].
    pub(super) fn write_file(system_dir: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let Some((path, dirs)) = scope(system_dir, path)? else {
            return std::fs::write(path, bytes);
        };
        require_dirs(&dirs)?;
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} has no file name", path.display()),
            ));
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let tmp = parent.join(format!(
            ".{}.tmp-{}-{nanos:09}",
            name.to_string_lossy(),
            std::process::id()
        ));
        let result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_WRITE | WRITE_OWNER | READ_CONTROL)
            .open(&tmp)
            .and_then(|mut file| {
                file.write_all(bytes)?;
                ferro_winauth::set_administrators_owner(&file)
                    .map_err(|e| not_elevated(&path, &e))?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, &path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// See [`super::claim`].
    pub(super) fn claim(system_dir: &Path, path: &Path) -> io::Result<()> {
        let Some((path, dirs)) = scope(system_dir, path)? else {
            return Ok(());
        };
        require_dirs(&dirs)?;
        let file =
            open_plain(&path, ObjectKind::File, WRITE_OWNER)?.ok_or_else(|| missing(&path))?;
        ferro_winauth::set_administrators_owner(&file).map_err(|e| not_elevated(&path, &e))
    }

    /// Wrap a failure to make Administrators the owner of `path`.
    fn not_elevated(path: &Path, e: &io::Error) -> io::Error {
        io::Error::new(
            e.kind(),
            format!(
                "making BUILTIN\\Administrators the owner of {}: {e} (writing the system \
                 configuration directory needs an elevated administrator prompt)",
                path.display()
            ),
        )
    }

    #[cfg(test)]
    mod tests {
        //! Windows-only: the real ACL round trip on a scratch "system"
        //! directory. Naming Administrators as owner needs an elevated token
        //! (CI runners are elevated); unelevated, the tests print why and
        //! return.

        use std::ffi::OsStr;
        use std::path::{Path, PathBuf};
        use std::process::Command;

        use super::{
            check_trusted_file, claim, ensure_system_dir_for, open_log, open_trusted, prepare,
            write_file, Prepared,
        };

        /// `ERROR_INVALID_OWNER`.
        const ERROR_INVALID_OWNER: i32 = 1307;

        fn scratch(tag: &str) -> PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            std::env::temp_dir().join(format!(
                "mia-system-dir-{tag}-{}-{nanos}",
                std::process::id()
            ))
        }

        /// Run a System32 tool, asserting it succeeds.
        fn run(tool: &str, args: &[&OsStr]) {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
            let status = Command::new(Path::new(&root).join("System32").join(tool))
                .args(args)
                .status()
                .expect("run tool");
            assert!(status.success(), "{tool} {args:?} failed: {status}");
        }

        fn icacls(path: &Path, args: &[&str]) {
            let mut all = vec![path.as_os_str()];
            all.extend(args.iter().map(OsStr::new));
            run("icacls.exe", &all);
        }

        /// `mklink /J` (junction) or `/H` (hard link): no privilege needed.
        fn mklink(flag: &str, link: &Path, target: &Path) {
            run(
                "cmd.exe",
                &[
                    "/c".as_ref(),
                    "mklink".as_ref(),
                    flag.as_ref(),
                    link.as_os_str(),
                    target.as_os_str(),
                ],
            );
        }

        /// `prepare` a fresh scratch system directory, or `None` unelevated.
        fn prepared(tag: &str) -> Option<PathBuf> {
            let dir = scratch(tag);
            match prepare(&dir) {
                Ok(Prepared::Created) => Some(dir),
                Err(e) if e.raw_os_error() == Some(ERROR_INVALID_OWNER) => {
                    eprintln!("skipping: not elevated");
                    None
                }
                other => panic!("prepare: {other:?}"),
            }
        }

        fn denied(result: std::io::Result<impl std::fmt::Debug>) -> String {
            let err = result.expect_err("refused");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
            err.to_string()
        }

        #[test]
        fn prepared_directory_trusts_claimed_files_until_users_may_write() {
            let Some(dir) = prepared("trust") else {
                return;
            };
            assert_eq!(prepare(&dir).unwrap(), Prepared::AlreadyRestricted);

            let file = dir.join("mia.toml");
            // Absent: passes the check, and opening it is NotFound.
            check_trusted_file(&dir, &file).expect("absent file passes");
            assert_eq!(
                open_trusted(&dir, &file).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
            std::fs::write(&file, b"log = 'info'\n").unwrap();
            claim(&dir, &file).expect("claim");
            check_trusted_file(&dir, &file).expect("claimed file passes");
            open_trusted(&dir, &file).expect("claimed file opens");

            // Users may now write to the directory (and, inherited, the file).
            icacls(&dir, &["/grant", "*S-1-5-32-545:(OI)(CI)(W)"]);
            assert!(denied(check_trusted_file(&dir, &file)).contains("S-1-5-32-545"));

            // Preparing again repairs the directory; the inherited Users ACE
            // goes with it, so the administrator's file is trusted again.
            assert!(matches!(prepare(&dir).unwrap(), Prepared::Repaired { .. }));
            open_trusted(&dir, &file).expect("trusted after repair");

            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn absent_guarding_directory_is_not_found() {
            let dir = scratch("absent");
            let file = dir.join("mia.toml");
            for err in [
                open_trusted(&dir, &file).unwrap_err(),
                check_trusted_file(&dir, &file).unwrap_err(),
            ] {
                assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
            }
        }

        #[test]
        fn a_file_owned_by_someone_else_stays_refused_after_repair() {
            let Some(dir) = prepared("owner") else {
                return;
            };
            let file = dir.join("environments.toml");
            std::fs::write(&file, b"").unwrap();
            // Hand the file to an ordinary principal, as a planted file would be.
            icacls(&file, &["/setowner", "*S-1-5-32-545"]);
            assert!(denied(open_trusted(&dir, &file)).contains("owned by S-1-5-32-545"));
            assert_eq!(prepare(&dir).unwrap(), Prepared::AlreadyRestricted);
            denied(check_trusted_file(&dir, &file));

            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn write_file_replaces_a_foreign_file_with_an_administrators_one() {
            let Some(dir) = prepared("write") else {
                return;
            };
            let file = dir.join("allowlist.cbor");
            std::fs::write(&file, b"planted").unwrap();
            icacls(&file, &["/setowner", "*S-1-5-32-545"]);
            denied(check_trusted_file(&dir, &file));

            write_file(&dir, &file, b"signed body").expect("write");
            assert_eq!(std::fs::read(&file).unwrap(), b"signed body");
            check_trusted_file(&dir, &file).expect("replaced file is trusted");
            // No temp file is left behind.
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_junction_as_the_system_directory_is_refused() {
            let Some(target) = prepared("junction-target") else {
                return;
            };
            let system = scratch("junction");
            mklink("/J", &system, &target);
            assert!(denied(prepare(&system)).contains("reparse point"));
            denied(check_trusted_file(&system, &system.join("mia.toml")));
            denied(ensure_system_dir_for(&system, &system.join("logs")));

            std::fs::remove_dir(&system).unwrap(); // the junction, not its target
            std::fs::remove_dir_all(&target).unwrap();
        }

        #[test]
        fn a_junction_below_the_system_directory_is_refused() {
            let Some(dir) = prepared("guard") else {
                return;
            };
            let target = scratch("guard-target");
            std::fs::create_dir(&target).unwrap();
            let keys = dir.join("keys");
            mklink("/J", &keys, &target);
            // As a guarding directory of a trusted file…
            assert!(denied(open_trusted(&dir, &keys.join("allowlist.key"))).contains("reparse"));
            // …as the log directory…
            denied(open_log(&dir, &keys.join("mia.log")));
            // …and anywhere in the tree when preparing.
            assert!(denied(prepare(&dir)).contains("reparse point"));

            std::fs::remove_dir(&keys).unwrap();
            std::fs::remove_dir_all(&target).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_subdirectory_someone_else_owns_is_locked() {
            let Some(dir) = prepared("logs") else {
                return;
            };
            let logs = dir.join("logs");
            std::fs::create_dir(&logs).unwrap();
            icacls(&logs, &["/setowner", "*S-1-5-32-545"]);
            icacls(&logs, &["/grant", "*S-1-5-32-545:(OI)(CI)(F)"]);
            denied(open_log(&dir, &logs.join("mia.log")));

            match prepare(&dir).unwrap() {
                Prepared::Repaired { reason } => assert!(reason.contains("logs"), "{reason}"),
                other => panic!("{other:?}"),
            }
            let facts = ferro_winauth::read_security(&logs).unwrap();
            assert_eq!(ferro_winauth::file_acl::check_admin_only(&facts), Ok(()));
            open_log(&dir, &logs.join("mia.log")).expect("log opens once logs is locked");

            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn hard_links_are_refused() {
            let Some(dir) = prepared("hardlink") else {
                return;
            };
            let outside = scratch("hardlink-outside");
            std::fs::write(&outside, b"elsewhere").unwrap();
            let file = dir.join("mia.toml");
            mklink("/H", &file, &outside);
            assert!(denied(check_trusted_file(&dir, &file)).contains("hard links"));
            denied(open_trusted(&dir, &file));

            std::fs::create_dir(dir.join("logs")).unwrap();
            let log = dir.join("logs").join("mia.log");
            mklink("/H", &log, &outside);
            assert!(denied(open_log(&dir, &log)).contains("hard links"));

            std::fs::remove_dir_all(&dir).unwrap();
            std::fs::remove_file(&outside).unwrap();
        }

        #[test]
        fn paths_outside_the_system_directory_are_not_judged() {
            let system = scratch("absent-system");
            let elsewhere = std::env::temp_dir().join("mia-system-dir-elsewhere.toml");
            check_trusted_file(&system, &elsewhere).expect("out of scope");
            claim(&system, &elsewhere).expect("out of scope");
            ensure_system_dir_for(&system, &std::env::temp_dir()).expect("out of scope");
            assert!(!system.exists());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_inside_system_dir_is_strict_and_lexical() {
        let system = crate::config::system_config_dir();
        assert!(is_inside_system_dir(&system.join("allowlist.pub")));
        assert!(is_inside_system_dir(&system.join("sub").join("k.pub")));
        assert!(
            !is_inside_system_dir(&system),
            "the directory itself is not inside"
        );
        assert!(!is_inside_system_dir(
            &system.join("..").join("elsewhere.pub")
        ));
        assert!(!is_inside_system_dir(&std::env::temp_dir().join("k.pub")));
    }

    #[test]
    fn guarding_dirs_lists_every_directory_from_the_system_dir_down() {
        let system = Path::new("/srv/FerroGate");
        assert_eq!(
            guarding_dirs(system, Path::new("/srv/FerroGate/mia.toml")),
            Some(vec![PathBuf::from("/srv/FerroGate")])
        );
        assert_eq!(
            guarding_dirs(system, Path::new("/srv/FerroGate/keys/allowlist.key")),
            Some(vec![
                PathBuf::from("/srv/FerroGate"),
                PathBuf::from("/srv/FerroGate/keys"),
            ])
        );
    }

    #[test]
    fn guarding_dirs_compares_case_insensitively_and_folds_dots() {
        let system = Path::new("/srv/FerroGate");
        assert_eq!(
            guarding_dirs(system, Path::new("/SRV/ferrogate/./mia.toml")),
            Some(vec![PathBuf::from("/SRV/ferrogate")])
        );
        // `..` that climbs back into the directory is still inside it…
        assert!(guarding_dirs(system, Path::new("/srv/other/../FerroGate/mia.toml")).is_some());
        // …and `..` that climbs out of it is not.
        assert_eq!(
            guarding_dirs(system, Path::new("/srv/FerroGate/../elsewhere/mia.toml")),
            None
        );
    }

    #[test]
    fn paths_outside_or_equal_to_the_system_dir_are_out_of_scope() {
        let system = Path::new("/srv/FerroGate");
        assert_eq!(guarding_dirs(system, Path::new("/srv/FerroGate")), None);
        assert_eq!(
            guarding_dirs(system, Path::new("/srv/FerroGateX/mia.toml")),
            None
        );
        assert_eq!(
            guarding_dirs(system, Path::new("/home/u/.config/mia.toml")),
            None
        );
        assert!(is_within(system, Path::new("/srv/FerroGate")));
        assert!(is_within(system, Path::new("/srv/ferrogate/logs")));
        assert!(!is_within(system, Path::new("/srv")));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_a_pass_through() {
        let dir = std::env::temp_dir().join(format!("mia-system-dir-unix-{}", std::process::id()));
        let nested = dir.join("a/b");
        create_dir_all(&nested).unwrap();
        assert!(nested.is_dir());
        let file = nested.join("f");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(read_trusted(&file).unwrap(), b"x");
        assert!(open_trusted(&file).is_ok());
        claim(&file).unwrap();
        check_trusted_file(&file).unwrap();
        write_file(&file, b"y").unwrap();
        {
            use std::io::Write as _;
            open_log(&nested.join("log"))
                .unwrap()
                .write_all(b"a")
                .unwrap();
            open_log(&nested.join("log"))
                .unwrap()
                .write_all(b"b")
                .unwrap();
        }
        assert_eq!(std::fs::read(nested.join("log")).unwrap(), b"ab");
        assert_eq!(std::fs::read(&file).unwrap(), b"y");
        assert_eq!(
            read_trusted(&dir.join("absent")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(prepare().unwrap(), Prepared::Unmanaged);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
