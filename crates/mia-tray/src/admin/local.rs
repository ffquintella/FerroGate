//! This machine's facts for the "add an application" form (F22): the host
//! UUID, platform and current user as defaults, and a chosen local file's
//! canonical path and SHA-384.
//!
//! Everything here is *read-only* and offline, and only fills the form: the
//! administrator still reviews every value, and the server checks again.

use sha2::{Digest, Sha384};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Defaults describing the machine the administrator is sitting at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalHost {
    /// The host UUID derived from the hardware fingerprint (`mia machine-id`),
    /// when it could be derived completely.
    pub host_uuid: Option<String>,
    /// Index into `PLATFORMS` (Linux, macOS, Windows).
    pub platform: usize,
    /// A Windows user rather than a Unix uid.
    pub windows_user: bool,
    /// The uid (Unix only; empty elsewhere).
    pub uid: String,
    /// The user name.
    pub user: String,
}

impl LocalHost {
    /// Detect once per process (the hardware query can run a helper).
    #[must_use]
    pub fn cached() -> &'static Self {
        static HOST: OnceLock<LocalHost> = OnceLock::new();
        HOST.get_or_init(Self::detect)
    }

    /// Detect now.
    #[must_use]
    pub fn detect() -> Self {
        let host_uuid = ferro_machineid::collect_facts().ok().and_then(|facts| {
            // An incomplete fingerprint is not the id CMIS enrolled: leave
            // the field empty rather than prefill a wrong host.
            facts.is_complete().then(|| {
                ferro_svid::host_uuid_from_ek_digest(facts.fingerprint().as_bytes()).to_string()
            })
        });
        let windows_user = cfg!(windows);
        let platform = if cfg!(windows) {
            2
        } else {
            usize::from(cfg!(target_os = "macos"))
        };
        let user = ["USER", "USERNAME", "LOGNAME"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .unwrap_or_default();
        Self {
            host_uuid,
            platform,
            windows_user,
            uid: current_uid(),
            user,
        }
    }
}

#[cfg(unix)]
fn current_uid() -> String {
    rustix::process::getuid().as_raw().to_string()
}

#[cfg(not(unix))]
fn current_uid() -> String {
    String::new()
}

/// An application chosen on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalApp {
    /// Its canonical (symlink-free) path.
    pub path: String,
    /// The SHA-384 of the file, lowercase hex.
    pub sha384: String,
}

/// Why a chosen file could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAppError {
    /// Not found, or not a regular file.
    NotAFile,
    /// Unreadable.
    Unreadable,
    /// The path is not valid text.
    BadPath,
}

/// A macOS `.app` bundle runs the executable named by its `Contents/MacOS`
/// directory: take the only file there, else the one named like the bundle.
fn resolve_bundle(path: &Path) -> PathBuf {
    let is_app = path.is_dir() && path.extension().is_some_and(|e| e == "app");
    if !is_app {
        return path.to_path_buf();
    }
    let macos = path.join("Contents/MacOS");
    let named = path.file_stem().map(|s| macos.join(s));
    if let Some(n) = named.filter(|n| n.is_file()) {
        return n;
    }
    let mut files = std::fs::read_dir(&macos)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file());
    match (files.next(), files.next()) {
        (Some(only), None) => only,
        _ => path.to_path_buf(),
    }
}

impl LocalApp {
    /// Canonicalise `path` (resolving a `.app` bundle) and hash the file.
    ///
    /// # Errors
    /// [`LocalAppError`] when it is not a readable regular file.
    pub fn from_path(path: &Path) -> Result<Self, LocalAppError> {
        let real =
            std::fs::canonicalize(resolve_bundle(path)).map_err(|_| LocalAppError::NotAFile)?;
        if !real.is_file() {
            return Err(LocalAppError::NotAFile);
        }
        let mut file = std::fs::File::open(&real).map_err(|_| LocalAppError::Unreadable)?;
        let mut hasher = Sha384::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(|_| LocalAppError::Unreadable)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha384 = hasher.finalize().iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        let path = real.to_str().ok_or(LocalAppError::BadPath)?.to_string();
        Ok(Self { path, sha384 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_canonicalises_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("app");
        std::fs::write(&f, b"abc").unwrap();
        let app = LocalApp::from_path(&f).unwrap();
        // SHA-384("abc"), FIPS 180-4 test vector.
        assert!(app.sha384.starts_with("cb00753f45a35e8bb5a03d699ac65007"));
        assert_eq!(app.sha384.len(), 96);
        assert!(app.path.ends_with("/app"));
    }

    #[test]
    fn a_directory_or_missing_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            LocalApp::from_path(dir.path()),
            Err(LocalAppError::NotAFile)
        );
        assert_eq!(
            LocalApp::from_path(&dir.path().join("nope")),
            Err(LocalAppError::NotAFile)
        );
    }

    #[test]
    fn an_app_bundle_resolves_to_its_executable() {
        let dir = tempfile::tempdir().unwrap();
        let macos = dir.path().join("Tool.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::write(macos.join("Tool"), b"abc").unwrap();
        let app = LocalApp::from_path(&dir.path().join("Tool.app")).unwrap();
        assert!(app.path.ends_with("Tool.app/Contents/MacOS/Tool"));
    }
}
