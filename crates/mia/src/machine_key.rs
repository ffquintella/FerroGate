//! The on-disk lifecycle of the host's identity secrets — the machine signing
//! key `host-key.bin` and the SVID seed `svid-seed.bin`: when an existing file
//! may be used, when it must be refused, when a new one may be created, and
//! how a file left at a former location is moved.
//!
//! CMIS pins the machine key's public half to the hardware fingerprint on
//! first contact (trust on first use) and refuses any other key for that
//! fingerprint from then on (`key-rebind`). The machine key is therefore an
//! identity, not a cache: a key minted while the old one still exists — or
//! could be restored — strands the host without an SVID until an operator
//! intervenes on CMIS. The seed is subordinate (a new one only rotates the
//! child-signing `kid` once) but follows the same rules. Every caller goes
//! through [`plan`]:
//!
//! 1. a usable file at the current location is **opened**, never rewritten;
//! 2. a file that exists but cannot be used — not a regular file, accessible
//!    to group or other, owned by someone other than root or the state
//!    directory's owner, unreadable, refused by the Windows trust check
//!    ([`crate::system_dir`]), malformed, or sealed to another host — is
//!    **refused** (fail closed): the caller reports
//!    [`crate::status::AttestFailure::MachineKey`] and logs the [`Refusal`],
//!    which names the file and the fix. Nothing is created in its place;
//! 3. a file absent at the current location but present at a legacy location
//!    is **migrated** — copied exclusively, verified, then the legacy copy
//!    removed — by the privileged startup ([`migrate_legacy`]), never
//!    replaced by a fresh one;
//! 4. only when no file exists anywhere is a new one **created**, exclusively
//!    (`O_EXCL`) and owner-only (`0600`). For the machine key "anywhere"
//!    includes the SVID seed beside it: the seed is only ever created after
//!    the key, so a seed without a key means the key was lost
//!    ([`Unusable::Lost`]) and a new one is refused.
//!
//! [`plan`] and [`classify`] are pure and unit-tested; [`probe`],
//! [`migrate_legacy`], [`open_or_create_machine_key`] and
//! [`load_or_create_seed`] do the I/O. Only paths, modes, uids and error
//! kinds are ever reported — never file contents.

use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// One of the identity secrets kept in the daemon's state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFile {
    /// The persistent machine signing key, `host-key.bin`.
    MachineKey,
    /// The 32-byte seed the composite SVID key is derived from,
    /// `svid-seed.bin`.
    SvidSeed,
}

impl StateFile {
    /// Both identity secrets, machine key first.
    pub const ALL: [Self; 2] = [Self::MachineKey, Self::SvidSeed];

    /// The file name inside the state directory.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::MachineKey => "host-key.bin",
            Self::SvidSeed => "svid-seed.bin",
        }
    }

    /// The file's path inside `state_dir`.
    #[must_use]
    pub fn path_in(self, state_dir: &Path) -> PathBuf {
        state_dir.join(self.file_name())
    }

    /// Where earlier releases kept this file, most recent first. A file found
    /// there while the current location is empty is migrated, never replaced.
    ///
    /// On Linux, releases before 0.20.19 kept both secrets in the config
    /// directory `/etc/ferrogate`; they now live in `/var/lib/ferrogate`
    /// ([`crate::credstore::state_dir`]). On macOS and Windows the state has
    /// always lived in the system config directory, so there is none.
    #[must_use]
    pub fn legacy_paths(self) -> Vec<PathBuf> {
        legacy_state_dirs()
            .iter()
            .map(|dir| self.path_in(dir))
            .collect()
    }

    /// What the file is, for messages.
    const fn label(self) -> &'static str {
        match self {
            Self::MachineKey => "machine signing key",
            Self::SvidSeed => "SVID seed",
        }
    }

    /// Why a replacement would hurt, for messages.
    const fn consequence(self) -> &'static str {
        match self {
            Self::MachineKey => {
                "CMIS has pinned this key's public half to the hardware fingerprint \
                 and would refuse a new key as a key rebind"
            }
            Self::SvidSeed => {
                "a new seed would rotate this host's child-signing key and invalidate \
                 tokens verifiers already trust"
            }
        }
    }
}

/// The state directories of earlier releases (see [`StateFile::legacy_paths`]).
fn legacy_state_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![PathBuf::from("/etc/ferrogate")]
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Why an existing file cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// Something other than a regular file — a symbolic link, a directory, a
    /// device — occupies the path.
    NotRegularFile,
    /// Group or other may access the file (Unix permission bits).
    GroupOrOtherAccess {
        /// The permission bits found (e.g. `0o644`).
        mode: u32,
    },
    /// The file belongs to neither root nor the owner of its directory (the
    /// service account), so someone else may have planted or changed it.
    ForeignOwner {
        /// The file's owner.
        uid: u32,
        /// The owner it should have: the state directory's owner.
        expected: u32,
    },
    /// The file's metadata or contents cannot be read by this process.
    Unreadable {
        /// The I/O error.
        error: String,
    },
    /// The Windows system-directory trust check refused the file
    /// ([`crate::system_dir::check_trusted_file`]); the reason names the fix.
    Untrusted {
        /// The refusal.
        reason: String,
    },
    /// The file was read but is not a valid key or seed for this host: wrong
    /// length, corrupt, or sealed to a different hardware fingerprint.
    Malformed {
        /// What is wrong with it.
        reason: String,
    },
    /// The current location is empty but the file still sits at a legacy
    /// location this process could not move it from.
    NotMigrated {
        /// Where the file still is.
        legacy: PathBuf,
    },
    /// The machine key is missing although a file only ever created after it
    /// (the SVID seed beside it) is still there: a key existed and was lost.
    /// Minting a new one would be refused by CMIS as a key rebind.
    Lost {
        /// The file whose presence shows a key existed.
        evidence: PathBuf,
    },
}

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegularFile => f.write_str("it is not a regular file"),
            Self::GroupOrOtherAccess { mode } => {
                write!(f, "its mode is {mode:o}: group or other may access it")
            }
            Self::ForeignOwner { uid, expected } => {
                write!(f, "it is owned by uid {uid}, not by root or uid {expected}")
            }
            Self::Unreadable { error } => write!(f, "it cannot be read: {error}"),
            Self::Untrusted { reason } => write!(f, "it is not trusted: {reason}"),
            Self::Malformed { reason } => write!(f, "it is not usable: {reason}"),
            Self::NotMigrated { legacy } => write!(
                f,
                "it is still at its former location {} and was not migrated",
                legacy.display()
            ),
            Self::Lost { evidence } => write!(
                f,
                "it is missing although {} — created only after it — is still there, so a key \
                 existed and was lost",
                evidence.display()
            ),
        }
    }
}

/// What a probe found at one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    /// Nothing is there.
    Absent,
    /// A regular, private, correctly owned and readable file is there.
    Usable,
    /// Something is there that must not be used — and must not be replaced.
    Unusable(Unusable),
}

/// An existing file the daemon refuses to use or replace, with the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Which secret.
    pub file: StateFile,
    /// The path that was refused (the current location).
    pub path: PathBuf,
    /// Why.
    pub reason: Unusable,
}

impl Refusal {
    /// The operator's fix, in one sentence.
    #[must_use]
    pub fn remedy(&self) -> String {
        let path = self.path.display();
        match &self.reason {
            Unusable::NotRegularFile => format!(
                "remove whatever occupies {path} and put the original {} back there",
                self.file.file_name()
            ),
            Unusable::GroupOrOtherAccess { .. } => format!(
                "make it owner-only (chmod 0600 {path}), and treat the secret as possibly copied"
            ),
            Unusable::ForeignOwner { expected, .. } => format!(
                "give it back to uid {expected} (chown {expected} {path}; chmod 0600 {path}) and \
                 find out who changed it"
            ),
            Unusable::Unreadable { .. } => format!(
                "restore its owner (the service account: root on macOS, _ferrogate on Linux, \
                 SYSTEM or Administrators on Windows) and mode 0600 on {path}"
            ),
            Unusable::Untrusted { .. } => {
                "follow the trust check's instructions above (repair the owner and ACL), then \
                 restart the service"
                    .to_string()
            }
            Unusable::Malformed { .. } => format!(
                "restore the original {} from a backup. Only if this host's identity must \
                 really change, move the file aside and have the CMIS operator clear this \
                 host's key pin first",
                self.file.file_name()
            ),
            Unusable::NotMigrated { legacy } => format!(
                "move {} to {path} keeping it owner-only and owned by the service account, or \
                 restart the service as root so it migrates the file itself",
                legacy.display()
            ),
            Unusable::Lost { evidence } => format!(
                "restore {path} from a backup. Only if this host must become a new identity \
                 (after the CMIS operator has cleared its key pin), delete {} as well so the \
                 agent may create a new key",
                evidence.display()
            ),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the {} {} exists but cannot be used: {}. It will not be replaced: {}. Fix: {}",
            self.file.label(),
            self.path.display(),
            self.reason,
            self.file.consequence(),
            self.remedy()
        )
    }
}

impl std::error::Error for Refusal {}

/// What to do about one identity secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Use the file at the current location as it is.
    Open {
        /// Legacy locations that also hold something. The current file wins;
        /// these are reported because, if CMIS refuses the host as a key
        /// rebind, one of them may be the key it pinned.
        shadowed_legacy: Vec<PathBuf>,
    },
    /// Nothing exists anywhere: create the file.
    Create,
    /// The current location is empty and the file is at this legacy location:
    /// move it.
    Migrate {
        /// The legacy path.
        from: PathBuf,
    },
    /// Fail closed: neither use nor replace anything.
    Refuse(Refusal),
}

/// Decide what to do with `file`, given what is at its current location
/// `path` and at each legacy location (most recent first). Pure.
///
/// The current location decides when anything is there: usable ⇒ open,
/// unusable ⇒ refuse. When it is empty, the first legacy location holding
/// anything decides: usable ⇒ migrate, unusable ⇒ refuse. Only when every
/// location is empty is the file created.
#[must_use]
pub fn plan(
    file: StateFile,
    path: &Path,
    current: &FileState,
    legacy: &[(PathBuf, FileState)],
) -> Plan {
    let refuse = |reason: Unusable| {
        Plan::Refuse(Refusal {
            file,
            path: path.to_path_buf(),
            reason,
        })
    };
    match current {
        FileState::Usable => Plan::Open {
            shadowed_legacy: legacy
                .iter()
                .filter(|(_, state)| *state != FileState::Absent)
                .map(|(p, _)| p.clone())
                .collect(),
        },
        FileState::Unusable(reason) => refuse(reason.clone()),
        FileState::Absent => match legacy.iter().find(|(_, s)| *s != FileState::Absent) {
            None => Plan::Create,
            Some((from, FileState::Usable)) => Plan::Migrate { from: from.clone() },
            Some((from, _)) => refuse(Unusable::NotMigrated {
                legacy: from.clone(),
            }),
        },
    }
}

/// The metadata [`classify`] judges, gathered by [`probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    /// The path is a regular file (not followed through a symbolic link).
    pub is_file: bool,
    /// Unix permission bits, `None` where there are none (Windows).
    pub mode: Option<u32>,
    /// Unix owner, `None` where there is none (Windows).
    pub uid: Option<u32>,
    /// Unix owner of the containing directory, if it could be read.
    pub dir_uid: Option<u32>,
}

/// Judge an existing file from its metadata: `None` when nothing in the
/// metadata forbids using it. Pure.
///
/// Root may always own the file. Otherwise it must belong to the owner of
/// its directory — the service account the daemon runs as (`_ferrogate` for
/// `/var/lib/ferrogate` on Linux).
#[must_use]
pub fn classify(facts: Facts) -> Option<Unusable> {
    if !facts.is_file {
        return Some(Unusable::NotRegularFile);
    }
    if let Some(mode) = facts.mode {
        if mode & 0o077 != 0 {
            return Some(Unusable::GroupOrOtherAccess { mode });
        }
    }
    if let Some(uid) = facts.uid {
        if uid != 0 && Some(uid) != facts.dir_uid {
            return Some(Unusable::ForeignOwner {
                uid,
                expected: facts.dir_uid.unwrap_or(0),
            });
        }
    }
    None
}

/// Look at `path` without following a symbolic link and say whether a file is
/// there and whether it may be used. Never changes anything.
#[must_use]
pub fn probe(path: &Path) -> FileState {
    // Windows: the system-directory trust check judges the file and every
    // directory above it; elsewhere it is a pass-through.
    if let Err(e) = crate::system_dir::check_trusted_file(path) {
        return if e.kind() == io::ErrorKind::NotFound {
            FileState::Absent
        } else {
            FileState::Unusable(Unusable::Untrusted {
                reason: e.to_string(),
            })
        };
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return FileState::Absent,
        Err(e) => {
            return FileState::Unusable(Unusable::Unreadable {
                error: e.to_string(),
            })
        }
    };
    if let Some(reason) = classify(facts_of(path, &meta)) {
        return FileState::Unusable(reason);
    }
    match std::fs::File::open(path) {
        Ok(_) => FileState::Usable,
        Err(e) if e.kind() == io::ErrorKind::NotFound => FileState::Absent,
        Err(e) => FileState::Unusable(Unusable::Unreadable {
            error: e.to_string(),
        }),
    }
}

#[cfg(unix)]
fn facts_of(path: &Path, meta: &std::fs::Metadata) -> Facts {
    use std::os::unix::fs::MetadataExt;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Facts {
        is_file: meta.file_type().is_file(),
        mode: Some(meta.mode() & 0o7777),
        uid: Some(meta.uid()),
        dir_uid: std::fs::metadata(dir).ok().as_ref().map(MetadataExt::uid),
    }
}

#[cfg(not(unix))]
fn facts_of(_path: &Path, meta: &std::fs::Metadata) -> Facts {
    Facts {
        is_file: meta.file_type().is_file(),
        mode: None,
        uid: None,
        dir_uid: None,
    }
}

/// Probe each legacy path other than `current`.
fn probe_legacy(legacy: &[PathBuf], current: &Path) -> Vec<(PathBuf, FileState)> {
    legacy
        .iter()
        .filter(|p| p.as_path() != current)
        .map(|p| (p.clone(), probe(p)))
        .collect()
}

/// [`plan`] for `file` in `state_dir`, probing the current location and
/// every legacy one ([`StateFile::legacy_paths`]).
#[must_use]
pub fn plan_for(file: StateFile, state_dir: &Path) -> (PathBuf, Plan) {
    let path = file.path_in(state_dir);
    let decision = plan_at(file, &path, &file.legacy_paths());
    (path, decision)
}

/// [`plan`] for `file` at `path` with explicit legacy locations.
fn plan_at(file: StateFile, path: &Path, legacy: &[PathBuf]) -> Plan {
    plan(file, path, &probe(path), &probe_legacy(legacy, path))
}

/// Create `path` exclusively (`O_EXCL`, never truncating or following a file
/// that appeared meanwhile), owner-only (`0600`, applied by `open(2)`), write
/// `bytes` and flush them to disk. If the write or flush fails the partial
/// file — which this call created — is removed.
///
/// # Errors
///
/// `AlreadyExists` if anything is at `path`; any other I/O error.
pub fn create_exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        // The exclusive open proves this call created the file: remove the
        // partial copy so no later start trips over a torn secret.
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// What [`migrate_legacy`] did for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// Nothing to move: the file is already at its current location, or
    /// exists nowhere, or is refused (the bootstrap reports the refusal).
    NotNeeded,
    /// The file was moved from this legacy path.
    Migrated {
        /// Where it was.
        from: PathBuf,
    },
}

/// Move `file` from a legacy location into `state_dir` if the current
/// location is empty and a usable legacy copy exists — run by the daemon at
/// start, while still privileged (on Linux, before the privilege drop:
/// afterwards the root-only legacy file is unreadable and the hardened
/// profile forbids the `chown`).
///
/// The copy is created exclusively with mode `0600`, handed to `owner`
/// (`uid`, `gid`) when given, flushed and read back; only when it matches is
/// the legacy file removed, so exactly one copy of the secret remains. A
/// failed copy is removed and the legacy file left untouched.
///
/// # Errors
///
/// The copy, ownership or verification failure; the legacy file is intact.
pub fn migrate_legacy(
    file: StateFile,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> io::Result<Migration> {
    migrate_from(file, &file.path_in(state_dir), &file.legacy_paths(), owner)
}

/// [`migrate_legacy`] to `path` from explicit legacy locations.
fn migrate_from(
    file: StateFile,
    path: &Path,
    legacy: &[PathBuf],
    owner: Option<(u32, u32)>,
) -> io::Result<Migration> {
    let Plan::Migrate { from } = plan_at(file, path, legacy) else {
        return Ok(Migration::NotNeeded);
    };
    move_file(&from, path, owner)?;
    Ok(Migration::Migrated { from })
}

/// Copy `from` to a new `to`, verify, then remove `from`. See
/// [`migrate_legacy`].
fn move_file(from: &Path, to: &Path, owner: Option<(u32, u32)>) -> io::Result<()> {
    let bytes = Zeroizing::new(std::fs::read(from)?);
    create_exclusive(to, &bytes)?;
    let finish = || -> io::Result<()> {
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(to, Some(uid), Some(gid))?;
        }
        #[cfg(not(unix))]
        let _ = owner;
        let back = Zeroizing::new(std::fs::read(to)?);
        if *back != *bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the copy at {} does not match the original", to.display()),
            ));
        }
        #[cfg(unix)]
        if let Some(dir) = to.parent() {
            // Persist the new directory entry before the old one goes.
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    if let Err(e) = finish() {
        // Only the copy this call created is removed; the original stays.
        let _ = std::fs::remove_file(to);
        return Err(e);
    }
    if let Err(e) = std::fs::remove_file(from) {
        tracing::warn!(
            error = %e, from = %from.display(), to = %to.display(),
            "migrated the file but could not remove the old copy; delete it by hand so only one \
             copy of the secret remains"
        );
    }
    Ok(())
}

/// Migrate every identity secret ([`StateFile::ALL`]) into `state_dir`,
/// logging each move at `warn` and each failure at `error`. Never fatal: a
/// file left behind is refused — not replaced — when the daemon later tries
/// to use it.
pub fn migrate_legacy_files(state_dir: &Path, owner: Option<(u32, u32)>) {
    for file in StateFile::ALL {
        match migrate_legacy(file, state_dir, owner) {
            Ok(Migration::NotNeeded) => {}
            Ok(Migration::Migrated { from }) => tracing::warn!(
                from = %from.display(),
                to = %file.path_in(state_dir).display(),
                "moved the {} to its current location (kept, not regenerated)",
                file.label()
            ),
            Err(e) => tracing::error!(
                error = %e,
                file = file.file_name(),
                state_dir = %state_dir.display(),
                "could not migrate the {} from its former location; it is left in place and the \
                 agent will refuse to attest until it is moved",
                file.label()
            ),
        }
    }
}

/// Re-seal a pre-F16 machine key — a plaintext 32-byte scalar — at `path` to
/// `seal_secret` (the hardware fingerprint), replacing the file **atomically**:
/// the sealed copy is written to a sibling temp file (exclusive, `0600`,
/// handed to `owner`), flushed, read back and checked to unseal to the same
/// scalar, then renamed over the original. A crash at any point leaves either
/// the old file or the new one, never a torn key. Returns whether the file was
/// re-sealed.
///
/// Run by the daemon at start while still privileged: on Linux the hardened
/// profile forbids `rename` after the privilege drop, which is why the
/// unprivileged opener ([`open_or_create_machine_key`]) loads such a file as it
/// is instead of rewriting it.
///
/// # Errors
///
/// Any read, seal, write, ownership, verification or rename failure; the
/// original file is intact and the temp file removed.
pub fn reseal_unsealed_key(
    path: &Path,
    seal_secret: &[u8],
    owner: Option<(u32, u32)>,
) -> io::Result<bool> {
    if probe(path) != FileState::Usable {
        return Ok(false);
    }
    let bytes = Zeroizing::new(std::fs::read(path)?);
    if !ferro_sep::is_unsealed_scalar(&bytes) {
        return Ok(false);
    }
    let invalid =
        |e: ferro_sep::SepError| io::Error::new(io::ErrorKind::InvalidData, e.to_string());
    ferro_sep::SoftwareMachineKey::from_bytes(&bytes).map_err(invalid)?;
    let blob = ferro_sep::seal_bytes(&bytes, seal_secret, b"").map_err(invalid)?;
    if *ferro_sep::unseal_bytes(&blob, seal_secret, b"").map_err(invalid)? != *bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the sealed copy does not unseal to the original key",
        ));
    }
    let name = path.file_name().map_or_else(
        || "machine-key".into(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = path.with_file_name(format!("{name}.reseal"));
    // A temp file left by an interrupted earlier attempt is ours to remove;
    // anything else at that name is not touched.
    match std::fs::symlink_metadata(&tmp) {
        Ok(m) if m.file_type().is_file() => std::fs::remove_file(&tmp)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a regular file", tmp.display()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    create_exclusive(&tmp, &blob)?;
    let finish = || -> io::Result<()> {
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(&tmp, Some(uid), Some(gid))?;
        }
        #[cfg(not(unix))]
        let _ = owner;
        if std::fs::read(&tmp)? != blob {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the copy at {} does not match", tmp.display()),
            ));
        }
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    if let Err(e) = finish() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(true)
}

/// Run [`reseal_unsealed_key`] on the machine key in `state_dir`, logging the
/// outcome. Never fatal: an unsealed key still opens, it just stays unsealed.
pub fn reseal_machine_key(state_dir: &Path, seal_secret: Option<&[u8]>, owner: Option<(u32, u32)>) {
    let Some(secret) = seal_secret else {
        return;
    };
    let path = StateFile::MachineKey.path_in(state_dir);
    match reseal_unsealed_key(&path, secret, owner) {
        Ok(false) => {}
        Ok(true) => tracing::info!(
            path = %path.display(),
            "re-sealed the pre-F16 machine key to the hardware fingerprint (same key)"
        ),
        Err(e) => tracing::warn!(
            error = %e, path = %path.display(),
            "could not re-seal the pre-F16 machine key; it is used unsealed and left as it is"
        ),
    }
}

/// Why the machine key could not be obtained.
#[derive(Debug)]
pub enum KeyError {
    /// An existing key (or a stranded legacy one) must not be used or
    /// replaced — fail closed and tell the operator ([`Refusal`]).
    Refused(Refusal),
    /// No key existed and creating one failed (e.g. the state directory is
    /// not writable). Nothing was replaced.
    CreateFailed(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => fmt::Display::fmt(r, f),
            Self::CreateFailed(e) => write!(f, "could not create the machine signing key: {e}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The machine key, and whether this call created it.
pub struct MachineKey {
    /// The key.
    pub key: ferro_sep::SoftwareMachineKey,
    /// True when no key existed anywhere and this call created a new one — a
    /// new host identity CMIS has never seen.
    pub created: bool,
}

/// Open this host's machine signing key at `path`, creating it only when no
/// key exists anywhere ([`plan`]). With `seal_secret` the key is sealed to it
/// at rest (the hardware fingerprint); without, it is a plain scalar.
///
/// # Errors
///
/// [`KeyError::Refused`] for an existing key that cannot be used — including
/// one that does not unseal on this host — or one stranded at a legacy
/// location; [`KeyError::CreateFailed`] when there was none and creating one
/// failed.
pub fn open_or_create_machine_key(
    path: &Path,
    seal_secret: Option<&[u8]>,
) -> Result<MachineKey, KeyError> {
    open_or_create_machine_key_with(path, &StateFile::MachineKey.legacy_paths(), seal_secret)
}

/// [`open_or_create_machine_key`] with explicit legacy locations.
fn open_or_create_machine_key_with(
    path: &Path,
    legacy: &[PathBuf],
    seal_secret: Option<&[u8]>,
) -> Result<MachineKey, KeyError> {
    let file = StateFile::MachineKey;
    let refused = |reason: Unusable| {
        KeyError::Refused(Refusal {
            file,
            path: path.to_path_buf(),
            reason,
        })
    };
    match plan_at(file, path, legacy) {
        Plan::Open { shadowed_legacy } => {
            for other in shadowed_legacy {
                tracing::warn!(
                    current = %path.display(), legacy = %other.display(),
                    "a second machine key exists at a former location; this one is used. If CMIS \
                     refuses this host as a key rebind, the other file may hold the pinned key"
                );
            }
            let opened = match seal_secret {
                Some(secret) => ferro_sep::SoftwareMachineKey::open_sealed(path, secret),
                None => ferro_sep::SoftwareMachineKey::open_existing(path),
            };
            opened
                .map(|key| MachineKey {
                    key,
                    created: false,
                })
                .map_err(|e| refused(unusable_from_sep(&e)))
        }
        Plan::Create => {
            // "None exists anywhere" includes the seed: it is only ever
            // created after the key, so a seed without a key means the key
            // was lost — refuse rather than mint a new identity.
            if let Some(reason) = lost_key_evidence(path) {
                return Err(refused(reason));
            }
            // Create exclusively; if another opener won the race, open the
            // key it persisted instead (and do not report it as created).
            let created = match seal_secret {
                Some(secret) => ferro_sep::SoftwareMachineKey::create_sealed(path, secret),
                None => ferro_sep::SoftwareMachineKey::create_plain(path),
            }
            .map_err(|e| KeyError::CreateFailed(e.to_string()))?;
            if let Some(key) = created {
                return Ok(MachineKey { key, created: true });
            }
            let opened = match seal_secret {
                Some(secret) => ferro_sep::SoftwareMachineKey::open_sealed(path, secret),
                None => ferro_sep::SoftwareMachineKey::open_existing(path),
            };
            opened
                .map(|key| MachineKey {
                    key,
                    created: false,
                })
                .map_err(|e| refused(unusable_from_sep(&e)))
        }
        // The bootstrap runs unprivileged on Linux, where moving a root-owned
        // legacy file is impossible; the privileged startup does the move.
        Plan::Migrate { from } => Err(refused(Unusable::NotMigrated { legacy: from })),
        Plan::Refuse(r) => Err(KeyError::Refused(r)),
    }
}

/// The [`Unusable::Lost`] reason when the SVID seed beside the absent machine
/// key at `key_path` exists (in any state), else `None`.
fn lost_key_evidence(key_path: &Path) -> Option<Unusable> {
    let dir = key_path.parent()?;
    let seed = StateFile::SvidSeed.path_in(dir);
    (probe(&seed) != FileState::Absent).then_some(Unusable::Lost { evidence: seed })
}

/// Map a `ferro-sep` failure to open an existing key to the refusal reason.
fn unusable_from_sep(e: &ferro_sep::SepError) -> Unusable {
    match e {
        ferro_sep::SepError::Malformed(m) => Unusable::Malformed {
            reason: format!(
                "{m} (sealed to a different hardware fingerprint, corrupt, or not a key file)"
            ),
        },
        other => Unusable::Unreadable {
            error: other.to_string(),
        },
    }
}

/// The SVID seed, and whether this call created it. Its `Debug` output never
/// shows the bytes.
#[derive(Clone, Copy)]
pub enum Seed {
    /// The existing seed.
    Loaded([u8; 32]),
    /// No seed existed anywhere; this one was just created and persisted.
    Created([u8; 32]),
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Loaded(_) => "Seed::Loaded(<redacted>)",
            Self::Created(_) => "Seed::Created(<redacted>)",
        })
    }
}

impl Seed {
    /// The seed bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::Loaded(s) | Self::Created(s) => s,
        }
    }
}

/// Why the SVID seed could not be obtained.
#[derive(Debug)]
pub enum SeedError {
    /// An existing seed must not be used or replaced (fail closed).
    Refused(Refusal),
    /// No seed existed and persisting a new one failed. Nothing was replaced;
    /// the caller may fall back to an ephemeral key.
    CreateFailed(io::Error),
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => fmt::Display::fmt(r, f),
            Self::CreateFailed(e) => write!(f, "could not persist a new SVID seed: {e}"),
        }
    }
}

impl std::error::Error for SeedError {}

/// Load the 32-byte SVID seed at `path`, creating and persisting a random one
/// (`0600`, exclusively) only when no seed exists anywhere ([`plan`]). An
/// existing seed of the wrong length, or one that cannot be read or trusted,
/// is refused — never overwritten.
///
/// # Errors
///
/// [`SeedError::Refused`] for an existing seed that cannot be used (or one
/// stranded at a legacy location); [`SeedError::CreateFailed`] when there was
/// none and persisting one failed.
pub fn load_or_create_seed(path: &Path) -> Result<Seed, SeedError> {
    load_or_create_seed_with(path, &StateFile::SvidSeed.legacy_paths())
}

/// [`load_or_create_seed`] with explicit legacy locations.
fn load_or_create_seed_with(path: &Path, legacy: &[PathBuf]) -> Result<Seed, SeedError> {
    let file = StateFile::SvidSeed;
    let refused = |reason: Unusable| {
        SeedError::Refused(Refusal {
            file,
            path: path.to_path_buf(),
            reason,
        })
    };
    match plan_at(file, path, legacy) {
        Plan::Open { .. } => read_seed(path).map(Seed::Loaded).map_err(refused),
        Plan::Create => {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut_slice()).map_err(|e| {
                SeedError::CreateFailed(io::Error::other(format!("system RNG: {e}")))
            })?;
            match create_exclusive(path, seed.as_slice()) {
                Ok(()) => Ok(Seed::Created(*seed)),
                // Another opener created it meanwhile: use theirs.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    read_seed(path).map(Seed::Loaded).map_err(refused)
                }
                Err(e) => Err(SeedError::CreateFailed(e)),
            }
        }
        Plan::Migrate { from } => Err(refused(Unusable::NotMigrated { legacy: from })),
        Plan::Refuse(r) => Err(SeedError::Refused(r)),
    }
}

/// Read an existing seed through the trust-checked reader.
fn read_seed(path: &Path) -> Result<[u8; 32], Unusable> {
    let bytes = Zeroizing::new(crate::system_dir::read_trusted(path).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            Unusable::Untrusted {
                reason: e.to_string(),
            }
        } else {
            Unusable::Unreadable {
                error: e.to_string(),
            }
        }
    })?);
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Unusable::Malformed {
        reason: format!("expected 32 bytes, found {}", bytes.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mia-machine-key-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn every_unusable() -> Vec<Unusable> {
        vec![
            Unusable::NotRegularFile,
            Unusable::GroupOrOtherAccess { mode: 0o644 },
            Unusable::ForeignOwner {
                uid: 501,
                expected: 0,
            },
            Unusable::Unreadable {
                error: "permission denied".into(),
            },
            Unusable::Untrusted {
                reason: "owned by a user".into(),
            },
            Unusable::Malformed {
                reason: "expected 32 bytes, found 7".into(),
            },
        ]
    }

    const CURRENT: &str = "/state/host-key.bin";
    const LEGACY: &str = "/etc/ferrogate/host-key.bin";

    fn decide(current: &FileState, legacy: &[(PathBuf, FileState)]) -> Plan {
        plan(StateFile::MachineKey, Path::new(CURRENT), current, legacy)
    }

    #[test]
    fn a_key_is_created_only_when_none_exists_anywhere() {
        assert_eq!(decide(&FileState::Absent, &[]), Plan::Create);
        assert_eq!(
            decide(&FileState::Absent, &[(LEGACY.into(), FileState::Absent)]),
            Plan::Create
        );
    }

    #[test]
    fn a_usable_key_is_opened_never_recreated() {
        assert_eq!(
            decide(&FileState::Usable, &[]),
            Plan::Open {
                shadowed_legacy: vec![]
            }
        );
        // A leftover legacy copy does not displace the current key; it is
        // only reported.
        for legacy_state in [
            FileState::Usable,
            FileState::Unusable(Unusable::NotRegularFile),
        ] {
            assert_eq!(
                decide(&FileState::Usable, &[(LEGACY.into(), legacy_state)]),
                Plan::Open {
                    shadowed_legacy: vec![LEGACY.into()]
                }
            );
        }
    }

    #[test]
    fn an_existing_but_unusable_key_fails_closed_and_is_never_replaced() {
        for reason in every_unusable() {
            for legacy in [
                vec![],
                vec![(PathBuf::from(LEGACY), FileState::Usable)],
                vec![(PathBuf::from(LEGACY), FileState::Absent)],
            ] {
                let decision = decide(&FileState::Unusable(reason.clone()), &legacy);
                assert_eq!(
                    decision,
                    Plan::Refuse(Refusal {
                        file: StateFile::MachineKey,
                        path: CURRENT.into(),
                        reason: reason.clone(),
                    }),
                    "{reason:?} with legacy {legacy:?}"
                );
            }
        }
    }

    #[test]
    fn a_moved_key_is_migrated_not_regenerated() {
        assert_eq!(
            decide(&FileState::Absent, &[(LEGACY.into(), FileState::Usable)]),
            Plan::Migrate {
                from: LEGACY.into()
            }
        );
        // An unusable legacy key still exists: refuse rather than mint.
        let decision = decide(
            &FileState::Absent,
            &[(
                LEGACY.into(),
                FileState::Unusable(Unusable::Unreadable {
                    error: "permission denied".into(),
                }),
            )],
        );
        assert_eq!(
            decision,
            Plan::Refuse(Refusal {
                file: StateFile::MachineKey,
                path: CURRENT.into(),
                reason: Unusable::NotMigrated {
                    legacy: LEGACY.into()
                },
            })
        );
    }

    #[test]
    fn the_first_occupied_legacy_location_decides() {
        let older = PathBuf::from("/older/host-key.bin");
        assert_eq!(
            decide(
                &FileState::Absent,
                &[
                    (LEGACY.into(), FileState::Absent),
                    (older.clone(), FileState::Usable),
                ],
            ),
            Plan::Migrate { from: older }
        );
    }

    #[test]
    fn classify_accepts_a_private_root_or_service_owned_file() {
        let ok = |uid, dir_uid| Facts {
            is_file: true,
            mode: Some(0o600),
            uid: Some(uid),
            dir_uid: Some(dir_uid),
        };
        assert_eq!(classify(ok(0, 0)), None, "root daemon, root directory");
        assert_eq!(classify(ok(0, 990)), None, "root may own a file anywhere");
        assert_eq!(
            classify(ok(990, 990)),
            None,
            "service account owns its state"
        );
        // Windows: no Unix metadata, the trust check judged it already.
        let windows = Facts {
            is_file: true,
            mode: None,
            uid: None,
            dir_uid: None,
        };
        assert_eq!(classify(windows), None);
    }

    #[test]
    fn classify_refuses_what_another_user_could_have_planted_or_read() {
        let base = Facts {
            is_file: true,
            mode: Some(0o600),
            uid: Some(0),
            dir_uid: Some(0),
        };
        assert_eq!(
            classify(Facts {
                is_file: false,
                ..base
            }),
            Some(Unusable::NotRegularFile)
        );
        assert_eq!(
            classify(Facts {
                mode: Some(0o640),
                ..base
            }),
            Some(Unusable::GroupOrOtherAccess { mode: 0o640 })
        );
        assert_eq!(
            classify(Facts {
                uid: Some(501),
                ..base
            }),
            Some(Unusable::ForeignOwner {
                uid: 501,
                expected: 0
            })
        );
    }

    #[test]
    fn every_refusal_names_the_file_and_a_fix() {
        let mut reasons = every_unusable();
        reasons.push(Unusable::NotMigrated {
            legacy: LEGACY.into(),
        });
        reasons.push(Unusable::Lost {
            evidence: "/state/svid-seed.bin".into(),
        });
        for reason in reasons {
            for file in StateFile::ALL {
                let r = Refusal {
                    file,
                    path: file.path_in(Path::new("/state")),
                    reason: reason.clone(),
                };
                let text = r.to_string();
                assert!(text.contains(file.file_name()), "{text}");
                assert!(text.contains("will not be replaced"), "{text}");
                assert!(text.contains("Fix: "), "{text}");
                assert_ne!(r.remedy(), "");
            }
        }
    }

    #[test]
    fn probe_sees_absent_usable_and_refused_files() {
        let dir = scratch("probe");
        let path = dir.join("host-key.bin");
        assert_eq!(probe(&path), FileState::Absent);
        create_exclusive(&path, b"key").unwrap();
        assert_eq!(probe(&path), FileState::Usable);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                probe(&path),
                FileState::Unusable(Unusable::GroupOrOtherAccess { mode: 0o644 })
            );
            std::fs::remove_file(&path).unwrap();
            // A dangling symbolic link is "something there", never "absent":
            // creating through it would write wherever it points.
            std::os::unix::fs::symlink(dir.join("elsewhere"), &path).unwrap();
            assert_eq!(probe(&path), FileState::Unusable(Unusable::NotRegularFile));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_exclusive_never_overwrites_and_is_owner_only() {
        let dir = scratch("exclusive");
        let path = dir.join("svid-seed.bin");
        create_exclusive(&path, b"first").unwrap();
        let err = create_exclusive(&path, b"second").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_machine_key_survives_reopening_and_is_created_once() {
        use ferro_sep::MachineKey as _;
        // The upgrade path: a new daemon build opens the key the previous one
        // created, byte for byte, and reports it as existing.
        let dir = scratch("reopen");
        let path = dir.join("host-key.bin");
        let first = open_or_create_machine_key_with(&path, &[], Some(b"fingerprint")).unwrap();
        assert!(first.created);
        let on_disk = std::fs::read(&path).unwrap();
        let again = open_or_create_machine_key_with(&path, &[], Some(b"fingerprint")).unwrap();
        assert!(!again.created);
        assert_eq!(first.key.public_spki_der(), again.key.public_spki_der());
        assert_eq!(std::fs::read(&path).unwrap(), on_disk, "never rewritten");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_lost_key_is_not_replaced_while_its_seed_remains() {
        // Only host-key.bin was deleted (or lost in a restore): the seed
        // beside it proves this host had an identity CMIS has pinned.
        let dir = scratch("lost");
        let path = dir.join("host-key.bin");
        let seed = dir.join("svid-seed.bin");
        create_exclusive(&seed, &[7u8; 32]).unwrap();
        let Err(KeyError::Refused(r)) = open_or_create_machine_key_with(&path, &[], Some(b"fp"))
        else {
            panic!("a key must not be minted while its seed remains");
        };
        assert_eq!(
            r.reason,
            Unusable::Lost {
                evidence: seed.clone()
            }
        );
        assert!(!path.exists(), "nothing was created");
        assert!(r.remedy().contains("delete"), "{r}");

        // The operator's explicit choice — removing the seed too — allows a
        // new identity.
        std::fs::remove_file(&seed).unwrap();
        assert!(
            open_or_create_machine_key_with(&path, &[], Some(b"fp"))
                .unwrap()
                .created
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pre_f16_key_is_resealed_atomically_and_keeps_its_identity() {
        use ferro_sep::MachineKey as _;
        let dir = scratch("reseal");
        let path = dir.join("host-key.bin");
        let legacy = ferro_sep::SoftwareMachineKey::generate().unwrap();
        create_exclusive(&path, &legacy.to_bytes()).unwrap();

        // The unprivileged opener uses it as it is, without rewriting it.
        let opened = open_or_create_machine_key_with(&path, &[], Some(b"fp")).unwrap();
        assert!(!opened.created);
        assert_eq!(opened.key.public_spki_der(), legacy.public_spki_der());
        assert_eq!(std::fs::read(&path).unwrap(), legacy.to_bytes());

        // A stale temp file from an interrupted attempt does not block it.
        create_exclusive(&dir.join("host-key.bin.reseal"), b"torn").unwrap();
        assert!(reseal_unsealed_key(&path, b"fp", None).unwrap());
        assert!(!dir.join("host-key.bin.reseal").exists());
        assert!(!ferro_sep::is_unsealed_scalar(
            &std::fs::read(&path).unwrap()
        ));
        assert_eq!(probe(&path), FileState::Usable, "still owner-only");
        let resealed = open_or_create_machine_key_with(&path, &[], Some(b"fp")).unwrap();
        assert_eq!(resealed.key.public_spki_der(), legacy.public_spki_der());
        // Idempotent.
        assert!(!reseal_unsealed_key(&path, b"fp", None).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_that_does_not_open_here_is_refused_and_left_intact() {
        // Fingerprint change, corruption or a key from another host: the old
        // behaviour of minting a fresh key would strand the host forever.
        let dir = scratch("foreign");
        let path = dir.join("host-key.bin");
        open_or_create_machine_key_with(&path, &[], Some(b"host-A")).unwrap();
        let before = std::fs::read(&path).unwrap();
        let Err(KeyError::Refused(r)) =
            open_or_create_machine_key_with(&path, &[], Some(b"host-B"))
        else {
            panic!("a key sealed to another fingerprint must be refused");
        };
        assert!(matches!(r.reason, Unusable::Malformed { .. }), "{r}");
        assert_eq!(std::fs::read(&path).unwrap(), before, "left untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_exposed_key_is_refused_without_being_touched() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("exposed");
        let path = dir.join("host-key.bin");
        open_or_create_machine_key_with(&path, &[], Some(b"fp")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            open_or_create_machine_key_with(&path, &[], Some(b"fp")),
            Err(KeyError::Refused(Refusal {
                reason: Unusable::GroupOrOtherAccess { mode: 0o644 },
                ..
            }))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_seed_is_created_once_and_a_bad_one_is_never_overwritten() {
        let dir = scratch("seed");
        let path = dir.join("svid-seed.bin");
        let Seed::Created(created) = load_or_create_seed_with(&path, &[]).unwrap() else {
            panic!("first call creates");
        };
        let Seed::Loaded(loaded) = load_or_create_seed_with(&path, &[]).unwrap() else {
            panic!("second call loads");
        };
        assert_eq!(loaded, created);
        assert_eq!(
            format!("{:?}", Seed::Loaded(loaded)),
            "Seed::Loaded(<redacted>)",
            "Debug never shows the seed"
        );

        // Wrong length: refused, and the file is left exactly as it was
        // (the old behaviour regenerated it silently).
        std::fs::remove_file(&path).unwrap();
        create_exclusive(&path, b"short").unwrap();
        assert!(matches!(
            load_or_create_seed_with(&path, &[]),
            Err(SeedError::Refused(Refusal {
                reason: Unusable::Malformed { .. },
                ..
            }))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn move_file_copies_verifies_then_removes_the_original() {
        let dir = scratch("move");
        let from = dir.join("legacy-host-key.bin");
        let to = dir.join("host-key.bin");
        create_exclusive(&from, b"pinned key").unwrap();
        move_file(&from, &to, None).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"pinned key");
        assert!(!from.exists(), "exactly one copy of the secret remains");
        assert_eq!(probe(&to), FileState::Usable);

        // Never over an existing file: the original stays put.
        create_exclusive(&from, b"other key").unwrap();
        assert_eq!(
            move_file(&from, &to, None).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&from).unwrap(), b"other key");
        assert_eq!(std::fs::read(&to).unwrap(), b"pinned key");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relocated_key_is_migrated_and_keeps_its_identity() {
        use ferro_sep::MachineKey as _;
        // An upgrade that moves the state directory (Linux 0.20.19 moved it
        // from /etc/ferrogate to /var/lib/ferrogate): the key CMIS pinned is
        // carried over, not replaced by a fresh one.
        let root = scratch("relocate");
        let (old_dir, new_dir) = (root.join("etc"), root.join("var-lib"));
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::create_dir_all(&new_dir).unwrap();
        let old_key = StateFile::MachineKey.path_in(&old_dir);
        let new_key = StateFile::MachineKey.path_in(&new_dir);
        let pinned = open_or_create_machine_key_with(&old_key, &[], Some(b"fp")).unwrap();
        let legacy = [old_key.clone()];

        // The unprivileged bootstrap never migrates and never mints: refused.
        assert!(matches!(
            open_or_create_machine_key_with(&new_key, &legacy, Some(b"fp")),
            Err(KeyError::Refused(Refusal {
                reason: Unusable::NotMigrated { .. },
                ..
            }))
        ));
        assert!(!new_key.exists());

        // The privileged startup migrates it ...
        assert_eq!(
            migrate_from(StateFile::MachineKey, &new_key, &legacy, None).unwrap(),
            Migration::Migrated {
                from: old_key.clone()
            }
        );
        assert!(!old_key.exists());
        // ... and the bootstrap then opens the very same key.
        let opened = open_or_create_machine_key_with(&new_key, &legacy, Some(b"fp")).unwrap();
        assert!(!opened.created);
        assert_eq!(opened.key.public_spki_der(), pinned.key.public_spki_der());
        // A second start has nothing left to move.
        assert_eq!(
            migrate_from(StateFile::MachineKey, &new_key, &legacy, None).unwrap(),
            Migration::NotNeeded
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migrate_legacy_is_a_no_op_when_the_key_is_already_current() {
        let dir = scratch("migrate-noop");
        let path = StateFile::MachineKey.path_in(&dir);
        let legacy = [dir.join("legacy-host-key.bin")];
        create_exclusive(&path, b"key").unwrap();
        create_exclusive(&legacy[0], b"older key").unwrap();
        assert_eq!(
            migrate_from(StateFile::MachineKey, &path, &legacy, None).unwrap(),
            Migration::NotNeeded
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"key",
            "current key untouched"
        );
        assert_eq!(std::fs::read(&legacy[0]).unwrap(), b"older key");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
