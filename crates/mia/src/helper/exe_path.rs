//! Canonical executable paths, resolved by the operating system from an
//! **open** file or a running process (feature F19 §4.2).
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

/// The canonical path of an open file.
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
/// `/proc/<pid>/exe`).
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
    use std::os::unix::fs::MetadataExt as _;
    let raw = rustix::fs::getpath(file).map_err(|_| ExePathError::Unresolved)?;
    let raw = raw
        .to_str()
        .map_err(|_| ExePathError::Invalid(ferro_appid::PathError::NotUtf8))?;
    let meta = file.metadata().map_err(|_| ExePathError::Unresolved)?;
    let (dev, ino) = (meta.dev(), meta.ino());
    Ok(ferro_appid::path::from_macos_path(raw, |stripped| {
        std::fs::metadata(stripped).is_ok_and(|m| m.dev() == dev && m.ino() == ino)
    })?)
}

/// macOS: the canonical path of an open image, or `None` when it cannot be
/// resolved (the caller authenticator then reports no path, and v2 entries
/// with a path constraint admit nobody).
#[cfg(target_os = "macos")]
#[must_use]
pub fn macos_canonical(file: &std::fs::File) -> Option<String> {
    macos_resolve(file).ok().map(|c| c.path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn an_open_file_resolves_to_its_absolute_path() {
        let dir = std::env::temp_dir().join(format!("mia-exe-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tool");
        std::fs::write(&path, b"\x7fELF").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let resolved = of_open_file(&file).unwrap();
        let expected = std::fs::canonicalize(&path).unwrap();
        // macOS may report the firmlinked or the plain form of a temp path;
        // either way it names the same file.
        let same = std::fs::canonicalize(&resolved.path).unwrap();
        assert_eq!(same, expected);
        assert!(resolved.path.starts_with('/'));
        assert!(!resolved.deleted_on_disk);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
