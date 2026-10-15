//! Crash-safe replacement of a daemon-owned file: write a temporary sibling
//! (created exclusively, with its final mode), `fsync` it, rename it over the
//! target, then `fsync` the directory. A reader sees the old file or the new
//! one, never a torn mix. Used for the synced allowlist body, its
//! `allowlist.state` and the app-request ledger (feature F19).

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Atomically replace `path` with `bytes`. On Unix the file gets `mode`
/// before any byte is written; on Windows a file inside the system
/// configuration directory is handed to Administrators before it replaces
/// the target ([`crate::system_dir::claim`]), so the daemon keeps trusting
/// it. A symlink at `path` is replaced, never followed.
pub fn write(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = temp_sibling(path)?;
    let result = write_temp(&tmp, bytes, mode).and_then(|()| {
        crate::system_dir::claim(&tmp)?;
        std::fs::rename(&tmp, path)
    });
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        // Persist the rename itself. A failure here leaves a correct file
        // that may not survive a power loss; it is reported, not fatal.
        if let Err(e) = std::fs::File::open(parent).and_then(|d| d.sync_all()) {
            tracing::warn!(error = %e, dir = %parent.display(), "could not flush directory after replacing a file");
        }
    }
    Ok(())
}

/// A fresh, unique temporary name beside `path`.
fn temp_sibling(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let suffix = hex::encode(&crate::host_api::random_bytes()[..8]);
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{suffix}.tmp"));
    Ok(path.with_file_name(tmp_name))
}

fn write_temp(tmp: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(tmp)?;
    #[cfg(unix)]
    {
        // `mode` is filtered by the umask at creation; set it exactly, by
        // path (`chmod`/`fchmodat`, which the hardened Linux daemon's seccomp
        // profile allows; `fchmod` is not).
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(mode))?;
    }
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_file_with_the_requested_mode_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("mia-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("state.json");
        write(&target, b"one", 0o600).unwrap();
        write(&target, b"two", 0o640).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640);
        }
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
