//! The risk flags MIA decides about a binary's location (F19 §4.5):
//! `path_protected`, `user_writable_path`, `world_writable`, `temp_dir`,
//! `network_path`. `ferro-appid` adds `interpreter` and `unsigned`; the
//! registration adds `deleted_on_disk` and `ima_unverified`.
//!
//! The walk covers the file and every ancestor directory up to `/`, with
//! `lstat` on the canonical (kernel-resolved) path, which the caller has
//! already bound to the hashed file in the daemon's mount namespace
//! ([`crate::helper::exe_path::bind`]). A component is *protected* when root
//! owns it, it is not writable by others, and a group that can write it is
//! an administrators' group (root's; also `admin` on macOS), and it carries
//! no access ACL, which could grant write to anyone. `path_protected` needs
//! every component protected and a local file system.
//!
//! ACLs are inspected on Linux only (the `system.posix_acl_access`
//! attribute). macOS exposes ACLs only through the ACL API
//! (`acl_get_link_np`, `getattrlist`), FFI this `#![forbid(unsafe_code)]`
//! crate has no safe wrapper for, and Windows needs a DACL walk: on those
//! platforms the ACL check cannot be made, so it fails closed and
//! **`path_protected` is never set** there until it exists (ROADMAP M41).
//! The other flags are still reported.
//!
//! The flags inform the approver and the auto-update continuity rule; they
//! never grant anything by themselves (CMIS decides, F19 §5.3).

#[cfg(unix)]
use std::path::Path;

use ferro_appid::RiskFlags;

/// Group ids whose write access still counts as administrator-only.
#[cfg(target_os = "macos")]
const ADMIN_GIDS: &[u32] = &[0, 80];
/// Group ids whose write access still counts as administrator-only.
#[cfg(all(unix, not(target_os = "macos")))]
const ADMIN_GIDS: &[u32] = &[0];

/// Temporary or download locations (`temp_dir`).
#[cfg(unix)]
const TEMP_PREFIXES: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/private/tmp/",
    "/private/var/tmp/",
    "/var/folders/",
    "/private/var/folders/",
];

/// The location flags of the binary at `canonical` (Unix).
#[cfg(unix)]
#[must_use]
pub fn path_flags(canonical: &str) -> u32 {
    let mut bits = 0;
    if is_temp(canonical) {
        bits |= RiskFlags::TEMP_DIR;
    }
    let network = is_network(canonical);
    if network {
        bits |= RiskFlags::NETWORK_PATH;
    }
    let walk = walk(Path::new(canonical));
    if walk.world_writable {
        bits |= RiskFlags::WORLD_WRITABLE | RiskFlags::USER_WRITABLE_PATH;
    }
    if walk.user_writable {
        bits |= RiskFlags::USER_WRITABLE_PATH;
    }
    if walk.complete && !walk.user_writable && !walk.world_writable && !walk.acl && !network {
        bits |= RiskFlags::PATH_PROTECTED;
    }
    bits
}

/// The location flags on Windows: the temp and network checks only. The DACL
/// walk that would set `path_protected` is a follow-up in `ferro-winauth`;
/// until then a Windows binary never claims a protected path.
#[cfg(windows)]
#[must_use]
pub fn path_flags(canonical: &str) -> u32 {
    let mut bits = 0;
    let upper = canonical.to_ascii_uppercase();
    if upper.starts_with(r"\\") {
        bits |= RiskFlags::NETWORK_PATH;
    }
    if upper.contains(r"\TEMP\") || upper.contains(r"\DOWNLOADS\") {
        bits |= RiskFlags::TEMP_DIR;
    }
    bits
}

#[cfg(unix)]
fn is_temp(path: &str) -> bool {
    TEMP_PREFIXES.iter().any(|p| path.starts_with(p)) || path.split('/').any(|c| c == "Downloads")
}

/// What the ancestor walk found.
#[cfg(unix)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one switch per finding of the walk.
struct Walk {
    /// Every component could be inspected.
    complete: bool,
    /// Some component is writable by someone other than root/administrators.
    user_writable: bool,
    /// Some component is writable by everyone.
    world_writable: bool,
    /// Some component carries an access ACL, or ACLs cannot be inspected
    /// on this platform (fail closed).
    acl: bool,
}

#[cfg(unix)]
fn walk(path: &Path) -> Walk {
    use std::os::unix::fs::MetadataExt as _;
    let mut w = Walk {
        complete: true,
        ..Walk::default()
    };
    for component in path.ancestors() {
        let Ok(meta) = std::fs::symlink_metadata(component) else {
            w.complete = false;
            continue;
        };
        let mode = meta.mode();
        if mode & 0o002 != 0 {
            w.world_writable = true;
        }
        if meta.uid() != 0 || (mode & 0o020 != 0 && !ADMIN_GIDS.contains(&meta.gid())) {
            w.user_writable = true;
        }
        if may_have_access_acl(component) {
            w.acl = true;
        }
    }
    w
}

/// Whether `path` may carry an extended POSIX access ACL (an unexpected
/// error counts as "may").
#[cfg(target_os = "linux")]
fn may_have_access_acl(path: &Path) -> bool {
    match rustix::fs::lgetxattr(path, "system.posix_acl_access", &mut [0u8; 0][..]) {
        Ok(_) => true,
        // No ACL, or a file system without ACL support.
        Err(e) => e != rustix::io::Errno::NODATA && e != rustix::io::Errno::NOTSUP,
    }
}

/// macOS (and other Unix): ACLs cannot be inspected here. Root can grant a
/// user write on a root-owned directory with an ACL entry (`chmod +a`), so
/// "no ACL" cannot be assumed: always "may", so `path_protected` is never
/// set (fail closed).
#[cfg(all(unix, not(target_os = "linux")))]
fn may_have_access_acl(_path: &Path) -> bool {
    true
}

/// Network and FUSE file systems, by type name.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
const NETWORK_FS: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "smb",
    "afpfs",
    "webdav",
    "9p",
    "ceph",
    "glusterfs",
    "afs",
    "davfs",
    "sshfs",
    "ftp",
];

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn network_fs(fstype: &str) -> bool {
    NETWORK_FS.contains(&fstype)
        || fstype.starts_with("fuse")
        || fstype.starts_with("macfuse")
        || fstype.starts_with("osxfuse")
}

/// Linux: the file system type of the longest mount point containing
/// `path`, from `/proc/self/mountinfo` (no `statfs`: the hardened daemon's
/// seccomp profile does not allow it).
#[cfg(target_os = "linux")]
fn is_network(path: &str) -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|info| mount_fstype(&info, path))
        .is_some_and(|t| network_fs(&t))
}

/// The fstype of the mount containing `path` in a `mountinfo` text.
#[cfg(any(target_os = "linux", test))]
fn mount_fstype(info: &str, path: &str) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for line in info.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        let (Some(mount), Some(fstype)) = (fields.get(4), fields.get(sep + 1)) else {
            continue;
        };
        let mount = unescape_mount(mount);
        let inside = path == mount
            || mount == "/"
            || path
                .strip_prefix(mount.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
        if inside && best.as_ref().is_none_or(|(len, _)| mount.len() >= *len) {
            best = Some((mount.len(), (*fstype).to_string()));
        }
    }
    best.map(|(_, t)| t)
}

/// `mountinfo` escapes space, tab, newline and backslash as `\ooo`.
#[cfg(any(target_os = "linux", test))]
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// macOS: the file system type name from `statfs`.
#[cfg(target_os = "macos")]
fn is_network(path: &str) -> bool {
    let Ok(fs) = rustix::fs::statfs(path) else {
        return false;
    };
    let name: Vec<u8> = fs
        .f_fstypename
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| u8::from_ne_bytes(c.to_ne_bytes()))
        .collect();
    network_fs(&String::from_utf8_lossy(&name))
}

/// Other Unix: not detected.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn is_network(_path: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn temp_and_download_locations_are_flagged() {
        assert!(is_temp("/tmp/tool"));
        assert!(is_temp("/home/alice/Downloads/tool"));
        assert!(is_temp("/private/var/folders/xy/T/tool"));
        assert!(!is_temp("/usr/bin/tool"));
        assert!(!is_temp("/opt/Downloadsx/tool"));
    }

    #[test]
    fn the_longest_mount_decides_the_file_system() {
        let info = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 0:50 / /mnt/share rw,relatime - nfs4 srv:/export rw
41 40 0:51 / /mnt/share/local rw - ext4 /dev/sdb1 rw
42 22 0:52 / /mnt/with\\040space rw - cifs //srv/x rw
43 22 0:53 / /home/alice/remote rw - fuse.sshfs alice@srv: rw
";
        assert_eq!(mount_fstype(info, "/usr/bin/tool").as_deref(), Some("ext4"));
        assert_eq!(
            mount_fstype(info, "/mnt/share/app").as_deref(),
            Some("nfs4")
        );
        assert_eq!(
            mount_fstype(info, "/mnt/share/local/app").as_deref(),
            Some("ext4")
        );
        assert_eq!(
            mount_fstype(info, "/mnt/sharex/app").as_deref(),
            Some("ext4")
        );
        assert_eq!(
            mount_fstype(info, "/mnt/with space/app").as_deref(),
            Some("cifs")
        );
        assert!(network_fs("nfs4") && network_fs("fuse.sshfs") && network_fs("cifs"));
        assert!(!network_fs("ext4") && !network_fs("apfs"));
    }

    #[cfg(unix)]
    #[test]
    fn a_user_owned_file_is_user_writable_and_never_protected() {
        let dir = std::env::temp_dir().join(format!("mia-flags-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("tool");
        std::fs::write(&file, b"x").unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let bits = path_flags(canonical.to_str().unwrap());
        let is_root = nix::unistd::geteuid().is_root();
        if !is_root {
            assert_ne!(bits & RiskFlags::USER_WRITABLE_PATH, 0);
        }
        assert_eq!(
            bits & RiskFlags::PATH_PROTECTED,
            0,
            "a temp dir is never protected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_root_owned_system_binary_is_protected() {
        // `/bin/sh` is root-owned, in root-owned, non-world-writable
        // directories on a local file system, without ACLs.
        let canonical = std::fs::canonicalize("/bin/sh").unwrap();
        let bits = path_flags(canonical.to_str().unwrap());
        assert_ne!(bits & RiskFlags::PATH_PROTECTED, 0, "flags {bits:#x}");
        assert_eq!(bits & RiskFlags::USER_WRITABLE_PATH, 0);
    }

    /// Without an ACL check (macOS, other Unix) even a root-owned system
    /// binary is not `path_protected`: an ACL could grant a user write.
    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn without_an_acl_check_nothing_is_protected() {
        let canonical = std::fs::canonicalize("/bin/sh").unwrap();
        let bits = path_flags(canonical.to_str().unwrap());
        assert_eq!(bits & RiskFlags::PATH_PROTECTED, 0, "flags {bits:#x}");
        assert_eq!(
            bits & RiskFlags::USER_WRITABLE_PATH,
            0,
            "the mode-bit walk still runs"
        );
    }
}
