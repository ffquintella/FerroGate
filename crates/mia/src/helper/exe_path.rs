//! Canonical executable paths, resolved by the operating system from an
//! **open** file or a running process (feature F19 §4.2), and bound to that
//! file in the daemon's own view of the file system.
//!
//! The path the allowlist v2 matches (`path_hash`) and the path an app
//! registration reports must be the one the kernel resolved for the bytes
//! that were hashed, never a path a caller claimed. This module asks the OS
//! for it and normalises the answer with [`ferro_appid::path`]:
//!
//! - Linux: `readlink` of `/proc/<pid>/exe` or of `/proc/self/fd/<n>` (a
//!   trailing ` (deleted)` is stripped and reported);
//! - macOS: `fcntl(F_GETPATH)` on the open file, with the
//!   `/System/Volumes/Data` firmlink prefix stripped when the stripped path is
//!   the same file;
//! - Windows: resolved by the caller authenticator (`GetFinalPathNameByHandleW`
//!   through `std::fs::canonicalize`).
//!
//! **Binding.** On Linux the kernel renders a path in the mount namespace
//! the file was opened in. A user can `unshare -Urm`, bind-mount any file
//! over `/usr/bin/foo` and run it: `/proc/<pid>/exe` then reads
//! `/usr/bin/foo`, although that name denotes another file in the daemon's
//! namespace, and the daemon's checks of that name (protection flags, the
//! allowlist path constraint) would describe the wrong file. So a resolved
//! path is used only when it is **bound** ([`bind`]): it names, in the
//! daemon's namespace, the very file that was hashed — same `(st_dev,
//! st_ino)` as the open descriptor. For a running process the process must
//! also share the daemon's mount namespace and root directory
//! ([`same_view`]). Anything else is treated as unresolved (fail closed).
//!
//! The one exception is an image that was replaced or removed on disk after
//! it started (`nlink == 0`): its path cannot bind any more, but for a
//! process that shares the daemon's view it still says where the image was,
//! so a process running after an upgrade keeps matching (F19 §4.2). Such a
//! path is reported as `deleted_on_disk` and never counts as protected.

#[cfg(unix)]
use ferro_appid::CanonicalPath;

/// Why a path could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExePathError {
    /// The OS did not return a path for the file.
    #[error("the operating system did not resolve a path")]
    Unresolved,
    /// The resolved path broke a canonical-path rule.
    #[error("{0}")]
    Invalid(#[from] ferro_appid::PathError),
}

/// A file's identity: its device and inode numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileKey {
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
}

#[cfg(unix)]
impl FileKey {
    fn of_meta(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    /// The identity of an open file (`fstat`).
    #[must_use]
    pub fn of_file(file: &std::fs::File) -> Option<Self> {
        file.metadata().ok().map(|m| Self::of_meta(&m))
    }

    /// The identity of what `path` itself names, without following a final
    /// symbolic link (`lstat`), in this process's mount namespace.
    #[must_use]
    pub fn of_path(path: impl AsRef<std::path::Path>) -> Option<Self> {
        std::fs::symlink_metadata(path)
            .ok()
            .map(|m| Self::of_meta(&m))
    }

    /// The identity of what `path` leads to, following links (`stat`): for
    /// the `/proc/<pid>/{ns/mnt,root}` magic links.
    #[cfg(all(unix, not(target_os = "macos")))]
    fn of_target(path: impl AsRef<std::path::Path>) -> Option<Self> {
        std::fs::metadata(path).ok().map(|m| Self::of_meta(&m))
    }
}

/// How a resolved path relates to the open file it was resolved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathBinding {
    /// The path names this very file in the daemon's namespace.
    Bound,
    /// The file has no name left (`nlink == 0`): the path is where it was.
    Deleted,
    /// The path names another file, or nothing, in the daemon's namespace:
    /// it was resolved in another mount namespace, or the file moved.
    Unbound,
}

/// Classify a path (pure): `opened` is the identity of the open file,
/// `at_path` that of what the path names here, `unlinked` whether the open
/// file has no name left. An unknown identity on either side never binds.
#[must_use]
pub fn classify(opened: Option<FileKey>, at_path: Option<FileKey>, unlinked: bool) -> PathBinding {
    match (opened, at_path) {
        (Some(a), Some(b)) if a == b => PathBinding::Bound,
        _ if unlinked => PathBinding::Deleted,
        _ => PathBinding::Unbound,
    }
}

/// `canonical` if it is bound to the open `file`, with `deleted_on_disk`
/// set exactly when the file has no name left; `None` (unresolved) when the
/// path names another file here, or when the file was deleted and
/// `trust_deleted` is false.
///
/// Pass `trust_deleted` only for a running process that shares the
/// daemon's view ([`same_view`]): only then does a deleted image's last path
/// mean the same thing to the daemon.
#[cfg(unix)]
#[must_use]
pub fn bind(
    file: &std::fs::File,
    canonical: CanonicalPath,
    trust_deleted: bool,
) -> Option<CanonicalPath> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = file.metadata().ok()?;
    let binding = classify(
        Some(FileKey::of_meta(&meta)),
        FileKey::of_path(&canonical.path),
        meta.nlink() == 0,
    );
    match binding {
        PathBinding::Bound => Some(CanonicalPath {
            deleted_on_disk: false,
            ..canonical
        }),
        PathBinding::Deleted if trust_deleted => Some(CanonicalPath {
            deleted_on_disk: true,
            ..canonical
        }),
        PathBinding::Deleted | PathBinding::Unbound => None,
    }
}

/// How a process resolves paths: the identities of its mount namespace and
/// of its root directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessView {
    /// `/proc/<pid>/ns/mnt`.
    pub mount_ns: Option<FileKey>,
    /// `/proc/<pid>/root`.
    pub root: Option<FileKey>,
}

/// Whether two processes resolve paths alike (pure): the same mount
/// namespace and the same root directory, both known on both sides.
#[must_use]
pub fn same_view(theirs: ProcessView, ours: ProcessView) -> bool {
    let same =
        |a: Option<FileKey>, b: Option<FileKey>| matches!((a, b), (Some(a), Some(b)) if a == b);
    same(theirs.mount_ns, ours.mount_ns) && same(theirs.root, ours.root)
}

#[cfg(all(unix, not(target_os = "macos")))]
impl ProcessView {
    /// The view of the process whose `/proc` directory is `dir`.
    fn of_proc(dir: &str) -> Self {
        Self {
            mount_ns: FileKey::of_target(format!("{dir}/ns/mnt")),
            root: FileKey::of_target(format!("{dir}/root")),
        }
    }
}

/// Linux: whether process `pid` resolves paths as this daemon does (same
/// mount namespace and root). Unknown (the process is gone, `/proc` is not
/// readable) is `false`.
#[cfg(all(unix, not(target_os = "macos")))]
#[must_use]
pub fn shares_view(pid: u32) -> bool {
    same_view(
        ProcessView::of_proc(&format!("/proc/{pid}")),
        ProcessView::of_proc("/proc/self"),
    )
}

/// Linux: the canonical path of the running image of process `pid`, given
/// `file`, the image opened through `/proc/<pid>/exe` (and hashed). `None`
/// unless the process shares the daemon's view and the path is bound to
/// `file` (or the image was deleted on disk, see the module docs).
#[cfg(all(unix, not(target_os = "macos")))]
#[must_use]
pub fn of_running_image(pid: u32, file: &std::fs::File) -> Option<CanonicalPath> {
    if !shares_view(pid) {
        return None;
    }
    bind(file, of_open_file(file).ok()?, true)
}

/// The canonical path of an open file, as the OS renders it. It is **not**
/// yet bound to the file: pass it through [`bind`] before relying on it.
///
/// # Errors
///
/// [`ExePathError::Unresolved`] when the OS gives no path (the file was
/// unlinked on macOS, `/proc` is not mounted); [`ExePathError::Invalid`] when
/// the path is not UTF-8, too long or not absolute.
#[cfg(unix)]
pub fn of_open_file(file: &std::fs::File) -> Result<CanonicalPath, ExePathError> {
    #[cfg(target_os = "macos")]
    {
        macos_resolve(file)
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::fd::AsRawFd as _;
        linux_link(&format!("/proc/self/fd/{}", file.as_raw_fd()))
    }
}

/// The canonical path of the running image of process `pid` (Linux
/// `/proc/<pid>/exe`), as the kernel renders it in that process's mount
/// namespace. Not bound: prefer [`of_running_image`].
///
/// # Errors
///
/// As [`of_open_file`].
#[cfg(all(unix, not(target_os = "macos")))]
pub fn of_process(pid: u32) -> Result<CanonicalPath, ExePathError> {
    linux_link(&format!("/proc/{pid}/exe"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_link(link: &str) -> Result<CanonicalPath, ExePathError> {
    use std::os::unix::ffi::OsStrExt as _;
    let target = std::fs::read_link(link).map_err(|_| ExePathError::Unresolved)?;
    Ok(ferro_appid::path::from_linux_link(
        target.as_os_str().as_bytes(),
    )?)
}

#[cfg(target_os = "macos")]
fn macos_resolve(file: &std::fs::File) -> Result<CanonicalPath, ExePathError> {
    let raw = rustix::fs::getpath(file).map_err(|_| ExePathError::Unresolved)?;
    let raw = raw
        .to_str()
        .map_err(|_| ExePathError::Invalid(ferro_appid::PathError::NotUtf8))?;
    let opened = FileKey::of_file(file).ok_or(ExePathError::Unresolved)?;
    Ok(ferro_appid::path::from_macos_path(raw, |stripped| {
        std::fs::metadata(stripped).is_ok_and(|m| FileKey::of_meta(&m) == opened)
    })?)
}

/// macOS: the canonical path of an open image, bound to it, or `None` when
/// it cannot be resolved or does not name the image any more (the caller
/// authenticator then reports no path, and v2 entries with a path
/// constraint admit nobody).
#[cfg(target_os = "macos")]
#[must_use]
pub fn macos_canonical(file: &std::fs::File) -> Option<String> {
    let resolved = macos_resolve(file).ok()?;
    bind(file, resolved, false).map(|c| c.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: FileKey = FileKey { dev: 1, ino: 10 };
    const B: FileKey = FileKey { dev: 1, ino: 11 };
    const OTHER_DEV: FileKey = FileKey { dev: 2, ino: 10 };

    #[test]
    fn only_the_same_device_and_inode_bind() {
        assert_eq!(classify(Some(A), Some(A), false), PathBinding::Bound);
        assert_eq!(classify(Some(A), Some(B), false), PathBinding::Unbound);
        assert_eq!(
            classify(Some(A), Some(OTHER_DEV), false),
            PathBinding::Unbound
        );
        assert_eq!(classify(Some(A), None, false), PathBinding::Unbound);
        assert_eq!(classify(None, None, false), PathBinding::Unbound);
        // A deleted image's path names another file (or nothing) now.
        assert_eq!(classify(Some(A), Some(B), true), PathBinding::Deleted);
        assert_eq!(classify(Some(A), None, true), PathBinding::Deleted);
    }

    #[test]
    fn views_match_only_when_namespace_and_root_are_known_and_equal() {
        let ours = ProcessView {
            mount_ns: Some(A),
            root: Some(B),
        };
        assert!(same_view(ours, ours));
        // `unshare -m`: another mount namespace.
        let unshared = ProcessView {
            mount_ns: Some(OTHER_DEV),
            ..ours
        };
        assert!(!same_view(unshared, ours));
        // `chroot`: another root directory.
        let chrooted = ProcessView {
            root: Some(A),
            ..ours
        };
        assert!(!same_view(chrooted, ours));
        // Unknown (process gone, `/proc` unreadable) fails closed.
        let unknown = ProcessView {
            mount_ns: None,
            root: None,
        };
        assert!(!same_view(unknown, ours));
        assert!(!same_view(unknown, unknown));
    }

    #[cfg(unix)]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mia-exe-path-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn an_open_file_resolves_to_its_absolute_path() {
        let dir = scratch("abs");
        let path = dir.join("tool");
        std::fs::write(&path, b"\x7fELF").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let resolved = bind(&file, of_open_file(&file).unwrap(), false).unwrap();
        let expected = std::fs::canonicalize(&path).unwrap();
        // macOS may report the firmlinked or the plain form of a temp path;
        // either way it names the same file.
        let same = std::fs::canonicalize(&resolved.path).unwrap();
        assert_eq!(same, expected);
        assert!(resolved.path.starts_with('/'));
        assert!(!resolved.deleted_on_disk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The mount-namespace attack seen from the daemon: the path the kernel
    /// rendered for the hashed file names another file here (`/bin/sh`
    /// stands in for the bind-mounted-over protected binary).
    #[cfg(unix)]
    #[test]
    fn a_path_naming_another_file_is_never_bound() {
        let dir = scratch("other");
        let path = dir.join("evil");
        std::fs::write(&path, b"evil").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        let claimed = CanonicalPath {
            path: sh.to_str().unwrap().to_string(),
            deleted_on_disk: false,
        };
        assert_eq!(bind(&file, claimed.clone(), false), None);
        assert_eq!(bind(&file, claimed, true), None, "not deleted either");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_deleted_file_binds_only_when_its_view_is_trusted() {
        let dir = scratch("deleted");
        let path = dir.join("tool");
        std::fs::write(&path, b"old").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let last = CanonicalPath {
            path: path.to_str().unwrap().to_string(),
            deleted_on_disk: false,
        };
        // An upgrade: the old image is unlinked and a new file takes its name.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"new").unwrap();
        assert_eq!(bind(&file, last.clone(), false), None);
        let kept = bind(&file, last.clone(), true).unwrap();
        assert!(kept.deleted_on_disk);
        assert_eq!(kept.path, last.path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_daemon_shares_its_own_view_and_not_an_unknown_ones() {
        assert!(shares_view(std::process::id()));
        assert!(!shares_view(u32::MAX), "no such process: unknown");
        let exe = std::fs::File::open("/proc/self/exe").unwrap();
        let resolved = of_running_image(std::process::id(), &exe).unwrap();
        assert_eq!(
            std::path::Path::new(&resolved.path),
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
        assert!(!resolved.deleted_on_disk);
        assert!(of_running_image(u32::MAX, &exe).is_none());
    }

    /// The attack end to end: in a new user and mount namespace a copy of
    /// `sleep` is bind-mounted over `/usr/bin/true` and run as
    /// `/usr/bin/true`. Seen from here, that process neither shares our view
    /// nor has a bound path. Skipped where user namespaces are not allowed
    /// (containers with the default seccomp profile, hardened kernels).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_bind_mount_in_another_mount_namespace_never_resolves() {
        use std::process::{Command, Stdio};
        let target = std::fs::canonicalize("/usr/bin/true").unwrap();
        let sleep = std::fs::canonicalize("/bin/sleep").unwrap();
        let dir = scratch("unshare");
        let evil = dir.join("evil");
        std::fs::copy(&sleep, &evil).unwrap();
        let script = format!(
            "mount --bind {} {} && exec {} 30",
            evil.display(),
            target.display(),
            target.display()
        );
        let Ok(mut child) = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "sh", "-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            eprintln!("skipping: unshare not available");
            return;
        };
        let pid = child.id();
        let evil_key = FileKey::of_path(&evil);
        let mut running = false;
        for _ in 0..200 {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            if FileKey::of_target(format!("/proc/{pid}/exe")) == evil_key {
                running = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !running {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("skipping: user and mount namespaces not permitted here");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let image = std::fs::File::open(format!("/proc/{pid}/exe")).unwrap();
        let rendered = of_open_file(&image).unwrap();
        let outcome = (
            shares_view(pid),
            of_running_image(pid, &image),
            bind(&image, rendered.clone(), false),
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        let (shares, running_path, bound) = outcome;
        assert!(!shares, "another mount namespace");
        assert_eq!(running_path, None);
        // The kernel renders the protected path for the user's file...
        assert_eq!(std::path::Path::new(&rendered.path), target);
        // ...which names another file here.
        assert_eq!(bound, None);
    }
}
