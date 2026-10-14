//! Canonical paths and the lineage `path_key` (F19 §4.2).
//!
//! The operating system resolves the path (`/proc/<pid>/exe`, `F_GETPATH`,
//! `GetFinalPathNameByHandleW`); this module normalises what it returns and
//! derives the key a lineage is stored under:
//!
//! - Linux: the kernel's absolute path, with a trailing ` (deleted)` stripped
//!   (and reported, so the `deleted_on_disk` flag can be set). The key is the
//!   UTF-8 bytes as-is, case-sensitive; non-UTF-8 paths are refused.
//! - macOS: the canonical on-disk form, with the `/System/Volumes/Data`
//!   firmlink prefix stripped when the stripped path is the same file. The
//!   key is the UTF-8 bytes.
//! - Windows: the final path with `\\?\` removed and `\\?\UNC\` turned into
//!   `\\`. NTFS is case-insensitive, so the key is the Unicode **simple**
//!   uppercase of every character.
//!
//! Every path is at most 4096 bytes, absolute, free of NUL and of `..`
//! components.

use crate::platform::Platform;

/// Longest canonical path accepted, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// Suffix the Linux kernel appends to `/proc/<pid>/exe` of a replaced file.
const DELETED_SUFFIX: &str = " (deleted)";

/// The macOS firmlink prefix of the data volume.
const MACOS_DATA_PREFIX: &str = "/System/Volumes/Data";

/// A validated canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    /// The path.
    pub path: String,
    /// The running image was replaced or removed on disk (Linux ` (deleted)`).
    pub deleted_on_disk: bool,
}

/// Why a path was refused. [`PathError::reason`] gives the F19 §7.4 code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// Empty path.
    #[error("empty path")]
    Empty,
    /// Not valid UTF-8.
    #[error("path is not UTF-8")]
    NotUtf8,
    /// Longer than [`MAX_PATH_BYTES`].
    #[error("path is too long")]
    TooLong,
    /// Contains a NUL character.
    #[error("path contains NUL")]
    Nul,
    /// Not absolute for its platform.
    #[error("path is not absolute")]
    NotAbsolute,
    /// Contains a `..` component.
    #[error("path contains a parent component")]
    ParentComponent,
}

impl PathError {
    /// The stable `x-ferrogate-reason` code of the error.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotUtf8 => "path_not_utf8",
            Self::TooLong => "field_too_long",
            Self::NotAbsolute => "path_not_absolute",
            Self::Empty | Self::Nul | Self::ParentComponent => "bad_path",
        }
    }
}

/// Normalise the target of Linux `/proc/<pid>/exe` (or `/proc/self/fd/<n>`):
/// refuse non-UTF-8, strip a trailing ` (deleted)` and report it, validate.
pub fn from_linux_link(raw: &[u8]) -> Result<CanonicalPath, PathError> {
    let text = std::str::from_utf8(raw).map_err(|_| PathError::NotUtf8)?;
    let (path, deleted_on_disk) = match text.strip_suffix(DELETED_SUFFIX) {
        Some(stripped) => (stripped, true),
        None => (text, false),
    };
    validate(Platform::Linux, path)?;
    Ok(CanonicalPath {
        path: path.to_string(),
        deleted_on_disk,
    })
}

/// Normalise a macOS canonical path: strip the `/System/Volumes/Data`
/// firmlink prefix when `same_file(stripped)` confirms the stripped path is
/// the same file (same device and inode), then validate.
pub fn from_macos_path(
    raw: &str,
    same_file: impl FnOnce(&str) -> bool,
) -> Result<CanonicalPath, PathError> {
    let path = match raw.strip_prefix(MACOS_DATA_PREFIX) {
        Some(rest) if rest.starts_with('/') && same_file(rest) => rest,
        _ => raw,
    };
    validate(Platform::MacOs, path)?;
    Ok(CanonicalPath {
        path: path.to_string(),
        deleted_on_disk: false,
    })
}

/// Normalise the output of `GetFinalPathNameByHandleW`: remove `\\?\`, turn
/// `\\?\UNC\server\share` into `\\server\share`, validate.
pub fn from_windows_final_path(raw: &str) -> Result<CanonicalPath, PathError> {
    let path = if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.to_string()
    };
    validate(Platform::Windows, &path)?;
    Ok(CanonicalPath {
        path,
        deleted_on_disk: false,
    })
}

/// Check the F19 §4.2 limits: non-empty, at most 4096 bytes, no NUL,
/// absolute for `platform`, no `..` component.
pub fn validate(platform: Platform, path: &str) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    if path.contains('\0') {
        return Err(PathError::Nul);
    }
    let absolute = match platform {
        Platform::Linux | Platform::MacOs => path.starts_with('/'),
        Platform::Windows => is_windows_absolute(path),
    };
    if !absolute {
        return Err(PathError::NotAbsolute);
    }
    let separators: &[char] = match platform {
        Platform::Windows => &['\\', '/'],
        Platform::Linux | Platform::MacOs => &['/'],
    };
    if path.split(separators).any(|c| c == "..") {
        return Err(PathError::ParentComponent);
    }
    Ok(())
}

/// `X:\…` or `\\server\share\…`.
fn is_windows_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let unc = path.starts_with(r"\\") && !path.starts_with(r"\\?\") && path.len() > 2;
    drive || unc
}

/// The lineage key of a canonical path (F19 §4.2): the UTF-8 bytes on Linux
/// and macOS, the Unicode simple-uppercase form on Windows.
pub fn path_key(platform: Platform, path: &str) -> Result<Vec<u8>, PathError> {
    validate(platform, path)?;
    Ok(match platform {
        Platform::Linux | Platform::MacOs => path.as_bytes().to_vec(),
        Platform::Windows => path
            .chars()
            .map(simple_uppercase)
            .collect::<String>()
            .into_bytes(),
    })
}

/// The Unicode simple (one-to-one) uppercase mapping of `c`. The standard
/// library implements the full mapping; it differs from the simple one
/// exactly where the full mapping expands to several characters (`ß` → `SS`),
/// and there the simple mapping leaves the character unchanged.
fn simple_uppercase(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_deleted_suffix_is_stripped_and_reported() {
        let p = from_linux_link(b"/usr/bin/tool (deleted)").unwrap();
        assert_eq!(p.path, "/usr/bin/tool");
        assert!(p.deleted_on_disk);
        let p = from_linux_link(b"/usr/bin/tool").unwrap();
        assert!(!p.deleted_on_disk);
        assert_eq!(from_linux_link(b"/usr/bin/\xff"), Err(PathError::NotUtf8));
        assert_eq!(PathError::NotUtf8.reason(), "path_not_utf8");
    }

    #[test]
    fn macos_firmlink_prefix_is_stripped_only_for_the_same_file() {
        let p = from_macos_path(
            "/System/Volumes/Data/Applications/X.app/Contents/MacOS/X",
            |s| s == "/Applications/X.app/Contents/MacOS/X",
        )
        .unwrap();
        assert_eq!(p.path, "/Applications/X.app/Contents/MacOS/X");
        let p = from_macos_path("/System/Volumes/Data/opt/x", |_| false).unwrap();
        assert_eq!(p.path, "/System/Volumes/Data/opt/x");
        let p = from_macos_path("/System/Volumes/Database", |_| true).unwrap();
        assert_eq!(p.path, "/System/Volumes/Database");
    }

    #[test]
    fn windows_prefixes_are_normalised() {
        assert_eq!(
            from_windows_final_path(r"\\?\C:\Program Files\App\app.exe")
                .unwrap()
                .path,
            r"C:\Program Files\App\app.exe"
        );
        assert_eq!(
            from_windows_final_path(r"\\?\UNC\srv\share\app.exe")
                .unwrap()
                .path,
            r"\\srv\share\app.exe"
        );
        assert_eq!(
            from_windows_final_path(r"relative\app.exe"),
            Err(PathError::NotAbsolute)
        );
    }

    #[test]
    fn keys_fold_case_only_on_windows() {
        assert_eq!(
            path_key(Platform::Linux, "/opt/App").unwrap(),
            b"/opt/App".to_vec()
        );
        assert_eq!(
            path_key(Platform::Windows, r"c:\Users\Zoë\straße.exe").unwrap(),
            r"C:\USERS\ZOË\STRAßE.EXE".as_bytes().to_vec()
        );
        assert_eq!(
            path_key(Platform::Windows, r"C:\X\a.exe").unwrap(),
            path_key(Platform::Windows, r"c:\x\A.EXE").unwrap()
        );
    }

    #[test]
    fn limits_are_enforced() {
        assert_eq!(validate(Platform::Linux, ""), Err(PathError::Empty));
        assert_eq!(
            validate(Platform::Linux, "opt/x"),
            Err(PathError::NotAbsolute)
        );
        assert_eq!(validate(Platform::Linux, "/opt/\0x"), Err(PathError::Nul));
        assert_eq!(
            validate(Platform::Linux, "/opt/../etc/shadow"),
            Err(PathError::ParentComponent)
        );
        assert_eq!(
            validate(Platform::Windows, r"C:\a\..\b"),
            Err(PathError::ParentComponent)
        );
        assert!(validate(Platform::Linux, "/opt/..x/y").is_ok());
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        assert_eq!(validate(Platform::Linux, &long), Err(PathError::TooLong));
        assert_eq!(
            validate(Platform::Windows, r"\\?\C:\x"),
            Err(PathError::NotAbsolute)
        );
    }
}
