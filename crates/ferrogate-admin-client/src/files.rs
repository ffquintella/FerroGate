//! Files an administrator client reads or writes: the configuration (it
//! decides where the password goes, so it must be trusted) and the device
//! token (a throttle hint, F20 §8, kept in a private `0600` file). Every file
//! is opened once without following a symlink and checked on the opened
//! handle, so it cannot be swapped between the check and the read.

use std::io::Read as _;
use std::path::Path;

/// Longest configuration file read, in bytes.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Longest device-token file read, in bytes.
pub const MAX_DEVICE_TOKEN_BYTES: u64 = 1024;

/// Whether an owner and mode are trustworthy for the configuration (or its
/// directory, when `dir`): owned by the effective user or root, and not
/// writable by group or others (a sticky directory is accepted, as `/tmp`).
///
/// # Errors
/// A short reason when they are not.
pub fn trusted_owner_and_mode(
    uid: u32,
    mode: u32,
    euid: u32,
    dir: bool,
) -> Result<(), &'static str> {
    if uid != euid && uid != 0 {
        return Err("is owned by another user (neither you nor root)");
    }
    let sticky = mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !(dir && sticky) {
        return Err("is writable by group or others");
    }
    Ok(())
}

/// Open `path` read-only without following a symbolic link in its last
/// component and without blocking on a FIFO (Unix: `O_NOFOLLOW |
/// O_NONBLOCK`).
///
/// # Errors
/// The file cannot be opened, or is a symbolic link.
pub fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == rustix::io::Errno::LOOP {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "is a symbolic link (refused)",
                )
            } else {
                std::io::Error::from(e)
            }
        })?;
        Ok(std::fs::File::from(fd))
    }
    #[cfg(not(unix))]
    {
        // No O_NOFOLLOW: refuse a link by its own metadata, then check the
        // opened handle as on Unix.
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "is a symbolic link (refused)",
            ));
        }
        std::fs::File::open(path)
    }
}

/// Read at most `max` bytes from `file`; `None` when it holds more.
///
/// # Errors
/// The read fails.
pub fn read_bounded(file: std::fs::File, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    let fits = u64::try_from(buf.len()).is_ok_and(|n| n <= max);
    Ok(fits.then_some(buf))
}

/// Read a configuration file the administrator can trust: the opened handle
/// is a regular file of at most [`MAX_CONFIG_BYTES`], owned by the effective
/// user or root, not group/other-writable; on Unix so is every directory
/// above it (sticky ones excepted).
///
/// # Errors
/// An operator-facing reason naming the file.
pub fn read_trusted_file(path: &Path) -> Result<String, String> {
    let invalid = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    let file = open_no_follow(path).map_err(|e| invalid(&e))?;
    let meta = file.metadata().map_err(|e| invalid(&e))?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "{} is not a regular file of at most {MAX_CONFIG_BYTES} bytes",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let euid = rustix::process::geteuid().as_raw();
        let refuse = |what: &Path, why: &str| {
            format!(
                "{} {why}; refusing the configuration (it decides where your password goes)",
                what.display()
            )
        };
        trusted_owner_and_mode(meta.uid(), meta.mode(), euid, false)
            .map_err(|why| refuse(path, why))?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let dir = std::fs::canonicalize(parent).map_err(|e| invalid(&e))?;
        for ancestor in dir.ancestors() {
            let dmeta = std::fs::metadata(ancestor).map_err(|e| invalid(&e))?;
            trusted_owner_and_mode(dmeta.uid(), dmeta.mode(), euid, true)
                .map_err(|why| refuse(ancestor, why))?;
        }
    }
    let bytes = read_bounded(file, MAX_CONFIG_BYTES)
        .map_err(|e| invalid(&e))?
        .ok_or_else(|| invalid(&format!("larger than {MAX_CONFIG_BYTES} bytes")))?;
    String::from_utf8(bytes).map_err(|_| invalid(&"not UTF-8 text"))
}

/// Read the device token from `path`, opened without following a symlink.
/// Empty when absent, not a regular file, not owned by the effective user,
/// readable by group or others, larger than 1 KiB or not printable ASCII.
#[must_use]
pub fn read_device_token(path: Option<&Path>) -> String {
    let Some(path) = path else {
        return String::new();
    };
    let Ok(file) = open_no_follow(path) else {
        return String::new();
    };
    let Ok(meta) = file.metadata() else {
        return String::new();
    };
    if !meta.is_file() || meta.len() > MAX_DEVICE_TOKEN_BYTES {
        return String::new();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.mode() & 0o077 != 0 || meta.uid() != rustix::process::geteuid().as_raw() {
            return String::new();
        }
    }
    let Ok(Some(bytes)) = read_bounded(file, MAX_DEVICE_TOKEN_BYTES) else {
        return String::new();
    };
    String::from_utf8(bytes)
        .map(|t| t.trim().to_string())
        .ok()
        .filter(|t| t.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or_default()
}

/// Keep the device token in a fresh `0600` file at `path` (directory `0700`),
/// never through a symlink. A token that is empty, longer than 512 bytes or
/// not printable ASCII is not written.
///
/// # Errors
/// The directory or file cannot be created, or `path` is not a regular file
/// (the caller ignores it: the token is a throttle hint only).
pub fn store_device_token(path: &Path, token: &str) -> std::io::Result<()> {
    if token.is_empty() || token.len() > 512 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        b.create(dir)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "device token path is not a regular file",
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    std::io::Write::write_all(&mut f, token.as_bytes())?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn private_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrogate-admin-client-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        b.create(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn only_files_and_directories_of_the_user_or_root_are_trusted() {
        let me = 1000;
        assert!(trusted_owner_and_mode(me, 0o100_600, me, false).is_ok());
        assert!(trusted_owner_and_mode(0, 0o100_644, me, false).is_ok());
        assert!(trusted_owner_and_mode(1001, 0o100_644, me, false).is_err());
        assert!(trusted_owner_and_mode(me, 0o100_664, me, false).is_err());
        assert!(trusted_owner_and_mode(0, 0o041_777, me, true).is_ok());
        assert!(trusted_owner_and_mode(0, 0o040_777, me, true).is_err());
        assert!(trusted_owner_and_mode(0, 0o041_777, me, false).is_err());
    }

    #[test]
    fn the_device_token_file_is_private_bounded_and_never_follows_a_symlink() {
        let dir = private_dir("dt");
        let path = dir.join("state/device-token");
        store_device_token(&path, "fgdt_abc").unwrap();
        assert_eq!(read_device_token(Some(&path)), "fgdt_abc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            chmod(&path, 0o640);
            assert_eq!(read_device_token(Some(&path)), "", "group-readable ignored");
            let link = dir.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(store_device_token(&link, "fgdt_x").is_err());
            assert_eq!(read_device_token(Some(&link)), "");
        }
        let big = dir.join("big");
        store_device_token(&big, &"x".repeat(512)).unwrap();
        std::fs::write(&big, "x".repeat(2048)).unwrap();
        assert_eq!(read_device_token(Some(&big)), "");
        assert_eq!(read_device_token(None), "");
        store_device_token(&dir.join("ctl"), "a\u{1b}b").unwrap();
        assert!(!dir.join("ctl").exists(), "a control is never written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlinked_oversized_or_writable_configuration_is_refused() {
        let dir = private_dir("cfg");
        let file = dir.join("admin.toml");
        std::fs::write(&file, "endpoint = \"https://h:1\"\n").unwrap();
        #[cfg(unix)]
        {
            chmod(&file, 0o600);
            assert!(read_trusted_file(&file).is_ok());
            chmod(&file, 0o666);
            let e = read_trusted_file(&file).unwrap_err();
            assert!(e.contains("writable"), "{e}");
            chmod(&file, 0o600);
            let link = dir.join("link.toml");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(read_trusted_file(&link)
                .unwrap_err()
                .contains("symbolic link"));
        }
        let big = dir.join("big.toml");
        std::fs::write(&big, "#".repeat(70 * 1024)).unwrap();
        #[cfg(unix)]
        chmod(&big, 0o600);
        assert!(read_trusted_file(&big).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
