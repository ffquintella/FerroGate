//! Identify the binary a registration names (F19 §4.1, §4.6), without ever
//! executing it, and describe it as an `AppRequestDoc` `binary`.
//!
//! - **`RegisterSelf`**: the authenticated caller's running image. The image
//!   is opened once; hash, metadata and canonical path come from that open
//!   file, and the hash must equal the one the caller authenticator derived,
//!   so a process that exited (or exec'd) in between cannot register another
//!   binary in its place.
//! - **`RegisterFile`**: the descriptor the client opened and passed. The
//!   daemon never opens a client-named path with its own privileges, so it is
//!   no hash oracle for files the client cannot read (`/etc/shadow`). The
//!   descriptor must be open for reading (not `O_PATH`) and name a regular
//!   file with an execute bit.
//!
//! In both cases the canonical path must be **bound** to the hashed file
//! ([`crate::helper::exe_path::bind`]): it must name that very file (same
//! device and inode) in the daemon's mount namespace, and a running process
//! must share the daemon's mount namespace and root. A path rendered in
//! another namespace (a bind mount over `/usr/bin/foo` after `unshare -Urm`)
//! would otherwise be reported, and flagged `path_protected`, for a file the
//! user controls. An unbound path is refused as `path_unresolved`. A running
//! image deleted on disk keeps its last path but is never `path_protected`.

use std::fs::File;

#[cfg(unix)]
use ferro_appid::CanonicalPath;
use ferro_appid::{IdentifyError, IdentifyOptions, Limits, Platform, RiskFlags, VersionSources};
use ferro_svid::app_docs::{BinaryDesc, SignerDesc};
use mia_helper_proto::RegErrorCode;

use crate::helper::auth::CallerIdentity;

/// Identification settings (`[registration]`).
#[derive(Debug, Clone)]
pub struct IdentifyConfig {
    /// Largest file identified, in bytes.
    pub max_file_size: u64,
    /// Version sources consulted.
    pub sources: VersionSources,
    /// Linux: callers are IMA-verified (`FERROGATE_REQUIRE_IMA`); otherwise
    /// `RegisterSelf` requests carry `ima_unverified`.
    pub ima_enforced: bool,
}

/// An identified binary.
#[derive(Debug, Clone)]
pub struct Identified {
    /// The request's `binary` description.
    pub binary: BinaryDesc,
}

/// Why a binary cannot be registered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentifyFailure {
    /// Not a registrable file (stable reason for the log).
    #[error("not eligible: {0}")]
    NotEligible(&'static str),
    /// Larger than `registration.max_file_size_mib`.
    #[error("file_too_large")]
    TooLarge,
    /// Reading failed unexpectedly.
    #[error("internal: {0}")]
    Internal(String),
}

impl IdentifyFailure {
    /// The opcode returned to the requester.
    #[must_use]
    pub const fn code(&self) -> RegErrorCode {
        match self {
            Self::NotEligible(_) => RegErrorCode::FileNotEligible,
            Self::TooLarge => RegErrorCode::FileTooLarge,
            Self::Internal(_) => RegErrorCode::Internal,
        }
    }
}

/// The running image of the authenticated `caller` (`RegisterSelf`).
pub fn running_image(
    caller: &CallerIdentity,
    cfg: &IdentifyConfig,
) -> Result<Identified, IdentifyFailure> {
    let (mut file, canonical, deleted) = open_running_image(caller)?;
    let mut ident = describe(&mut file, &canonical, deleted, cfg)?;
    if ident.binary.sha384 != caller.bin_sha {
        return Err(IdentifyFailure::NotEligible("binary_changed"));
    }
    if cfg!(target_os = "linux") && !cfg.ima_enforced {
        ident.binary.flags |= RiskFlags::IMA_UNVERIFIED;
    }
    Ok(ident)
}

#[cfg(unix)]
fn open_running_image(caller: &CallerIdentity) -> Result<(File, String, bool), IdentifyFailure> {
    // Linux: the kernel's handle on the running image, even when the file was
    // replaced or removed on disk; its path counts only when the process
    // shares the daemon's mount namespace and root, and is bound to the
    // image (a deleted image keeps its last path). macOS: the path the
    // authenticator resolved from the process, bound to the opened file.
    #[cfg(not(target_os = "macos"))]
    let (file, canonical) = {
        let file = File::open(format!("/proc/{}/exe", caller.pid))
            .map_err(|_| IdentifyFailure::NotEligible("exe_unreadable"))?;
        let canonical = crate::helper::exe_path::of_running_image(caller.pid, &file)
            .ok_or(IdentifyFailure::NotEligible("path_unresolved"))?;
        (file, canonical)
    };
    #[cfg(target_os = "macos")]
    let (file, canonical) = {
        let path = caller
            .exe_path
            .as_deref()
            .ok_or(IdentifyFailure::NotEligible("exe_unresolved"))?;
        let file = File::open(path).map_err(|_| IdentifyFailure::NotEligible("exe_unreadable"))?;
        let resolved = crate::helper::exe_path::of_open_file(&file)
            .map_err(|_| IdentifyFailure::NotEligible("path_unresolved"))?;
        let canonical = bound(&file, resolved, false)?;
        (file, canonical)
    };
    Ok((file, canonical.path, canonical.deleted_on_disk))
}

/// `resolved` bound to `file` ([`crate::helper::exe_path::bind`]), or
/// `path_unresolved`.
#[cfg(unix)]
fn bound(
    file: &File,
    resolved: CanonicalPath,
    trust_deleted: bool,
) -> Result<CanonicalPath, IdentifyFailure> {
    crate::helper::exe_path::bind(file, resolved, trust_deleted)
        .ok_or(IdentifyFailure::NotEligible("path_unresolved"))
}

#[cfg(windows)]
fn open_running_image(caller: &CallerIdentity) -> Result<(File, String, bool), IdentifyFailure> {
    let path = caller
        .exe_path
        .clone()
        .ok_or(IdentifyFailure::NotEligible("exe_unresolved"))?;
    let file = File::open(&path).map_err(|_| IdentifyFailure::NotEligible("exe_unreadable"))?;
    Ok((file, path, false))
}

/// A descriptor the client opened and passed (`RegisterFile`, Unix).
#[cfg(unix)]
pub fn passed_file(mut file: File, cfg: &IdentifyConfig) -> Result<Identified, IdentifyFailure> {
    use std::os::unix::fs::PermissionsExt as _;
    let flags =
        rustix::fs::fcntl_getfl(&file).map_err(|e| IdentifyFailure::Internal(e.to_string()))?;
    #[cfg(target_os = "linux")]
    if flags.contains(rustix::fs::OFlags::PATH) {
        return Err(IdentifyFailure::NotEligible("descriptor_not_readable"));
    }
    let access = flags & rustix::fs::OFlags::RWMODE;
    if access != rustix::fs::OFlags::RDONLY && access != rustix::fs::OFlags::RDWR {
        return Err(IdentifyFailure::NotEligible("descriptor_not_readable"));
    }
    let meta = file
        .metadata()
        .map_err(|e| IdentifyFailure::Internal(e.to_string()))?;
    if !meta.is_file() {
        return Err(IdentifyFailure::NotEligible("not_a_regular_file"));
    }
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(IdentifyFailure::NotEligible("not_executable"));
    }
    let resolved = crate::helper::exe_path::of_open_file(&file)
        .map_err(|_| IdentifyFailure::NotEligible("path_unresolved"))?;
    let mut ident = describe_resolved(&mut file, resolved, cfg)?;
    // A file is not a measured `execve`: IMA never vouched for it.
    if cfg!(target_os = "linux") {
        ident.binary.flags |= RiskFlags::IMA_UNVERIFIED;
    }
    Ok(ident)
}

/// Describe a passed descriptor at the path the OS `resolved` for it. The
/// descriptor may come from another mount namespace, so the path must be
/// bound to it here, and a deleted file (whose last path cannot be checked
/// in the namespace it came from) is refused.
#[cfg(unix)]
fn describe_resolved(
    file: &mut File,
    resolved: CanonicalPath,
    cfg: &IdentifyConfig,
) -> Result<Identified, IdentifyFailure> {
    let canonical = bound(file, resolved, false)?;
    describe(file, &canonical.path, canonical.deleted_on_disk, cfg)
}

/// Hash and describe the open `file` at `canonical`, a path already bound
/// to it (or, `deleted_on_disk`, where the deleted image was).
fn describe(
    file: &mut File,
    canonical: &str,
    deleted_on_disk: bool,
    cfg: &IdentifyConfig,
) -> Result<Identified, IdentifyFailure> {
    let platform = Platform::current();
    let opts = IdentifyOptions {
        platform,
        limits: Limits {
            max_file_size: cfg.max_file_size,
            ..Limits::default()
        },
        sources: cfg.sources,
        exe_owner: owner_of(file),
        ..IdentifyOptions::default()
    };
    // Platform signature verification (Authenticode, Apple code signing)
    // feeding the signer summary is a follow-up; without it a PE or Mach-O
    // binary is flagged `unsigned` and never anchors on a signer.
    let ident = ferro_appid::identify(file, canonical, None, &opts).map_err(|e| match e {
        IdentifyError::FileTooLarge => IdentifyFailure::TooLarge,
        IdentifyError::Io(e) => IdentifyFailure::Internal(e.to_string()),
    })?;
    let mut flags = ident.flags.0 | super::flags::path_flags(canonical);
    if deleted_on_disk {
        // The path now names another file (or nothing): what protects it
        // says nothing about the image that was hashed.
        flags &= !RiskFlags::PATH_PROTECTED;
        flags |= RiskFlags::DELETED_ON_DISK;
    }
    let signer: Option<SignerDesc> = None;
    Ok(Identified {
        binary: BinaryDesc {
            canonical_path: canonical.to_string(),
            platform: platform.code(),
            sha384: ident.sha384,
            size: ident.size,
            format: ident.format.code(),
            declared_version: ident.version.declared_version,
            version_source: ident.version.source.code(),
            product_name: ident.version.product_name,
            bundle_id: ident.version.bundle_id,
            package_name: ident.version.package_name,
            signer,
            flags: flags & ferro_appid::RiskFlags::HOST_SETTABLE,
        },
    })
}

#[cfg(unix)]
fn owner_of(file: &File) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    file.metadata().ok().map(|m| m.uid())
}

#[cfg(not(unix))]
fn owner_of(_file: &File) -> Option<u32> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn cfg() -> IdentifyConfig {
        IdentifyConfig {
            max_file_size: 1024 * 1024,
            sources: VersionSources::default(),
            ima_enforced: true,
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mia-ident-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_exec(path: &std::path::Path, bytes: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_passed_executable_is_hashed_from_its_descriptor() {
        let dir = scratch("ok");
        let path = dir.join("tool");
        write_exec(&path, b"#!/bin/true\nbody", 0o755);
        let file = File::open(&path).unwrap();
        let ident = passed_file(file, &cfg()).unwrap();
        assert_eq!(
            ident.binary.sha384,
            crate::helper::auth::bin_sha384(b"#!/bin/true\nbody")
        );
        assert_eq!(ident.binary.size, 16);
        assert_eq!(
            std::fs::canonicalize(&ident.binary.canonical_path).unwrap(),
            std::fs::canonicalize(&path).unwrap()
        );
        assert_ne!(ident.binary.flags & RiskFlags::TEMP_DIR, 0, "a temp file");
        assert_eq!(ident.binary.flags & RiskFlags::PATH_PROTECTED, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_executables_directories_and_write_only_descriptors_are_refused() {
        let dir = scratch("refuse");
        let data = dir.join("data");
        write_exec(&data, b"secret", 0o644);
        assert_eq!(
            passed_file(File::open(&data).unwrap(), &cfg()).unwrap_err(),
            IdentifyFailure::NotEligible("not_executable")
        );
        assert_eq!(
            passed_file(File::open(&dir).unwrap(), &cfg()).unwrap_err(),
            IdentifyFailure::NotEligible("not_a_regular_file")
        );
        let tool = dir.join("tool");
        write_exec(&tool, b"x", 0o755);
        let write_only = std::fs::OpenOptions::new().write(true).open(&tool).unwrap();
        assert_eq!(
            passed_file(write_only, &cfg()).unwrap_err(),
            IdentifyFailure::NotEligible("descriptor_not_readable")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_over_the_limit_are_too_large() {
        let dir = scratch("big");
        let path = dir.join("big");
        write_exec(&path, &vec![0u8; 2048], 0o755);
        let small = IdentifyConfig {
            max_file_size: 1024,
            ..cfg()
        };
        assert_eq!(
            passed_file(File::open(&path).unwrap(), &small).unwrap_err(),
            IdentifyFailure::TooLarge
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The mount-namespace attack (`unshare -Urm`, bind mount over a
    /// protected binary): the OS renders a protected path for a file the
    /// user controls. `/bin/sh` stands in for the protected path; the hashed
    /// file is a user's. The path must be refused, never reported or flagged
    /// `path_protected`.
    #[test]
    fn a_path_that_names_another_file_is_refused_not_protected() {
        let dir = scratch("spoof");
        let path = dir.join("evil");
        write_exec(&path, b"#!/bin/true\nevil", 0o755);
        let mut file = File::open(&path).unwrap();
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        let spoofed = CanonicalPath {
            path: sh.to_str().unwrap().to_string(),
            deleted_on_disk: false,
        };
        assert_eq!(
            describe_resolved(&mut file, spoofed, &cfg()).unwrap_err(),
            IdentifyFailure::NotEligible("path_unresolved")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_passed_file_deleted_on_disk_is_refused() {
        let dir = scratch("gone");
        let path = dir.join("tool");
        write_exec(&path, b"#!/bin/true\ngone", 0o755);
        let file = File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            passed_file(file, &cfg()).unwrap_err(),
            IdentifyFailure::NotEligible("path_unresolved")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A running image deleted on disk keeps its last path, but that path
    /// now names another file: it never counts as protected.
    #[test]
    fn a_deleted_image_is_never_path_protected() {
        let dir = scratch("deleted");
        let path = dir.join("old");
        write_exec(&path, b"#!/bin/true\nold", 0o755);
        let mut file = File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        let ident = describe(&mut file, sh.to_str().unwrap(), true, &cfg()).unwrap();
        assert_ne!(ident.binary.flags & RiskFlags::DELETED_ON_DISK, 0);
        assert_eq!(ident.binary.flags & RiskFlags::PATH_PROTECTED, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_running_image_must_be_the_authenticated_binary() {
        // This test process stands in for the caller.
        let exe = std::env::current_exe().unwrap();
        let sha = crate::helper::auth::bin_sha384(&std::fs::read(&exe).unwrap());
        let caller =
            CallerIdentity::new(std::process::id(), 0, 0, sha).with_exe_path(exe.to_str().unwrap());
        let big = IdentifyConfig {
            max_file_size: 2 * 1024 * 1024 * 1024,
            ..cfg()
        };
        let ident = running_image(&caller, &big).unwrap();
        assert_eq!(ident.binary.sha384, sha);
        let impostor = CallerIdentity::new(std::process::id(), 0, 0, [7; 48])
            .with_exe_path(exe.to_str().unwrap());
        assert_eq!(
            running_image(&impostor, &big).unwrap_err(),
            IdentifyFailure::NotEligible("binary_changed")
        );
    }
}
