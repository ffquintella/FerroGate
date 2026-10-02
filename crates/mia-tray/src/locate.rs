//! Finding the `mia` binary — and deciding whether it may be run **elevated**.
//!
//! Read-only actions run `mia` as the user, so any `mia` the user could run
//! from a terminal will do (the packaged location first, then `PATH`, or the
//! `MIA_TRAY_MIA` override for development). Elevated actions are different:
//! the OS prompt asks an administrator to run *that file* as root, so a binary
//! an unprivileged process could have replaced would turn the consent prompt
//! into a privilege escalation. Elevation therefore only ever uses a binary
//! from the packaged locations that is (Unix) owned by root, not writable by
//! group or others, in a root-owned directory that is not writable by group
//! or others either. On Windows the elevated program must sit under the
//! machine's Program Files or Windows directory — read from `HKLM`, never from
//! the user-controlled `%ProgramFiles%` / `%SystemRoot%` variables — which only
//! administrators can write by default (ACLs and Authenticode are not
//! inspected here; see the F18 spec's follow-ups).

use std::path::{Path, PathBuf};

/// Environment variable naming a `mia` binary for **unprivileged** use only
/// (development builds). Never used for elevation.
pub const OVERRIDE_VAR: &str = "MIA_TRAY_MIA";

/// A located `mia` binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiaBinary {
    /// Absolute path (canonical when it could be resolved).
    pub path: PathBuf,
    /// Whether it passed [`is_trusted_for_elevation`] and may be run behind
    /// an OS consent prompt.
    pub trusted: bool,
}

/// The packaged install locations, most specific first.
#[must_use]
pub fn packaged_locations() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/bin/mia"),
            PathBuf::from("/usr/local/bin/mia"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from("/usr/local/bin/mia")]
    }
    #[cfg(windows)]
    {
        program_files_dir()
            .map(|base| base.join("FerroGate").join("MIA").join("mia.exe"))
            .into_iter()
            .collect()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Vec::new()
    }
}

/// The executable file name of `mia` on this OS.
#[must_use]
pub fn exe_name() -> &'static str {
    if cfg!(windows) {
        "mia.exe"
    } else {
        "mia"
    }
}

/// Ownership and permission facts about one file-system object, as needed by
/// [`is_trusted_for_elevation`] (kept separate so the rule is unit-testable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// Owning uid.
    pub uid: u32,
    /// Permission bits.
    pub mode: u32,
    /// A regular file (for the binary) / a directory (for its parent).
    pub right_kind: bool,
}

/// The elevation trust rule: binary and parent directory both root-owned,
/// neither writable by group or others, and of the right kind.
#[must_use]
pub fn is_trusted_for_elevation(binary: FileFacts, parent: FileFacts) -> bool {
    let safe = |f: FileFacts| f.right_kind && f.uid == 0 && f.mode & 0o022 == 0;
    safe(binary) && safe(parent)
}

#[cfg(unix)]
fn facts(path: &Path, want_dir: bool) -> Option<FileFacts> {
    use std::os::unix::fs::MetadataExt as _;
    let m = std::fs::symlink_metadata(path).ok()?;
    Some(FileFacts {
        uid: m.uid(),
        mode: m.mode(),
        right_kind: if want_dir { m.is_dir() } else { m.is_file() },
    })
}

/// Whether the program at `path` may be run behind an OS consent prompt
/// (Unix: [`is_trusted_for_elevation`] on the file and its directory; Windows:
/// it exists — see the module docs; elsewhere: never). Checked when `mia` is
/// located and again, for every elevated program, right before it is run.
#[cfg(unix)]
#[must_use]
pub fn trusted_for_elevation(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    matches!(
        (facts(path, false), facts(parent, true)),
        (Some(b), Some(p)) if is_trusted_for_elevation(b, p)
    )
}

/// See the Unix variant: on Windows, an existing file under the HKLM Program
/// Files or Windows directory ([`is_under_trusted_root`]).
#[cfg(windows)]
#[must_use]
pub fn trusted_for_elevation(path: &Path) -> bool {
    let roots: Vec<PathBuf> = [program_files_dir(), windows_dir()]
        .into_iter()
        .flatten()
        .collect();
    path.is_file() && is_under_trusted_root(path, &roots)
}

/// Whether `path` is absolute, free of `..`, and inside one of `roots` (the
/// Windows elevation rule, kept separate so it is unit-tested everywhere).
#[must_use]
pub fn is_under_trusted_root(path: &Path, roots: &[PathBuf]) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        && roots.iter().any(|r| r.is_absolute() && path.starts_with(r))
}

#[cfg(windows)]
fn hklm_dir(key: &str, value: &str) -> Option<PathBuf> {
    winreg::HKLM
        .open_subkey(key)
        .and_then(|k| k.get_value::<String, _>(value))
        .map_err(|e| tracing::debug!(key, value, error = %e, "registry lookup failed"))
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The machine's Program Files directory from
/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir`
/// (`None` off Windows).
#[must_use]
pub fn program_files_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        hklm_dir(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            "ProgramFilesDir",
        )
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The Windows directory from
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot`
/// (`None` off Windows).
#[must_use]
pub fn windows_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        hklm_dir(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "SystemRoot",
        )
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Canonicalise on Unix (resolving symlinks, so the trust rule sees the real
/// file); keep the path as is on Windows, where `canonicalize` yields a
/// `\\?\` verbatim path that `ShellExecuteEx` and the UAC prompt handle badly.
fn resolved(p: PathBuf) -> PathBuf {
    if cfg!(windows) {
        p
    } else {
        std::fs::canonicalize(&p).unwrap_or(p)
    }
}

/// See the Unix variant.
#[cfg(not(any(unix, windows)))]
#[must_use]
pub fn trusted_for_elevation(_path: &Path) -> bool {
    false
}

/// Search `PATH` for `name`.
fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Locate `mia`: the packaged locations (trusted for elevation when they pass
/// the rule), else the `MIA_TRAY_MIA` override, else `PATH` (both untrusted).
/// `None` ⇒ the agent is not installed.
#[must_use]
pub fn locate_mia() -> Option<MiaBinary> {
    for candidate in packaged_locations() {
        if candidate.is_file() {
            let path = resolved(candidate);
            let trusted = trusted_for_elevation(&path);
            return Some(MiaBinary { path, trusted });
        }
    }
    let untrusted = |p: PathBuf| MiaBinary {
        path: resolved(p),
        trusted: false,
    };
    if let Some(p) = std::env::var_os(OVERRIDE_VAR).map(PathBuf::from) {
        if p.is_absolute() && p.is_file() {
            return Some(untrusted(p));
        }
        tracing::warn!(
            var = OVERRIDE_VAR,
            "ignoring a non-absolute or missing override"
        );
    }
    on_path(exe_name()).map(untrusted)
}

/// The first of `candidates` that exists as a file (fixed system tools such
/// as `pkexec`, `systemctl`, `xdg-open`).
#[must_use]
pub fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_FILE: FileFacts = FileFacts {
        uid: 0,
        mode: 0o100_755,
        right_kind: true,
    };
    const ROOT_DIR: FileFacts = FileFacts {
        uid: 0,
        mode: 0o040_755,
        right_kind: true,
    };

    #[test]
    fn only_root_owned_unwritable_binaries_are_trusted() {
        assert!(is_trusted_for_elevation(ROOT_FILE, ROOT_DIR));
        // A user-owned binary or directory (e.g. a Homebrew-chowned
        // /usr/local/bin) is not.
        assert!(!is_trusted_for_elevation(
            FileFacts {
                uid: 501,
                ..ROOT_FILE
            },
            ROOT_DIR
        ));
        assert!(!is_trusted_for_elevation(
            ROOT_FILE,
            FileFacts {
                uid: 501,
                ..ROOT_DIR
            }
        ));
        // Group- or world-writable anything is not.
        assert!(!is_trusted_for_elevation(
            FileFacts {
                mode: 0o100_775,
                ..ROOT_FILE
            },
            ROOT_DIR
        ));
        assert!(!is_trusted_for_elevation(
            FileFacts {
                mode: 0o100_757,
                ..ROOT_FILE
            },
            ROOT_DIR
        ));
        assert!(!is_trusted_for_elevation(
            ROOT_FILE,
            FileFacts {
                mode: 0o041_777,
                ..ROOT_DIR
            }
        ));
        // Wrong kinds (a directory named mia, a file as parent) are not.
        assert!(!is_trusted_for_elevation(
            FileFacts {
                right_kind: false,
                ..ROOT_FILE
            },
            ROOT_DIR
        ));
    }

    #[test]
    fn windows_rule_requires_a_trusted_root() {
        let base = std::env::temp_dir();
        let pf = base.join("Program Files");
        let roots = vec![pf.clone()];
        assert!(is_under_trusted_root(
            &pf.join("FerroGate").join("MIA").join("mia.exe"),
            &roots
        ));
        // Outside the roots, relative, or escaping with `..`: refused.
        assert!(!is_under_trusted_root(
            &base.join("Users").join("mia.exe"),
            &roots
        ));
        assert!(!is_under_trusted_root(
            Path::new("Program Files/mia.exe"),
            &roots
        ));
        assert!(!is_under_trusted_root(
            &pf.join("..").join("evil").join("mia.exe"),
            &roots
        ));
        assert!(!is_under_trusted_root(&pf.join("mia.exe"), &[]));
    }

    #[test]
    fn packaged_locations_are_absolute() {
        for p in packaged_locations() {
            assert!(p.is_absolute(), "{}", p.display());
            assert!(p.ends_with(exe_name()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_user_owned_temp_binary_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("mia");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        // Unless the tests run as root, the file (and the temp dir) is
        // user-owned, so it must never be trusted for elevation.
        if facts(&bin, false).is_some_and(|f| f.uid != 0) {
            assert!(!trusted_for_elevation(&bin));
        }
    }
}
