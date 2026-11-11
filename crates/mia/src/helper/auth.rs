//! Caller authentication for the helper API.
//!
//! The MIA never trusts a caller's *claimed* identity. It derives the caller's
//! identity from kernel-attested sources (see `docs/helper-api.md`):
//!
//! 1. `SO_PEERCRED` on the connected socket yields `(pid, uid, gid)`.
//! 2. `SHA-384(/proc/<pid>/exe)` is computed from disk.
//! 3. That hash is cross-checked against the IMA runtime measurement log. IMA
//!    measures a binary at `execve` time and the kernel will not let userspace
//!    rewrite the log, so a post-exec symlink/file swap of `/proc/<pid>/exe`
//!    is caught: the on-disk hash no longer matches the measured one.
//!
//! The authoritative `bin_sha` is the IMA-measured value; a request is only
//! authenticated when the disk hash equals it.
//!
//! The platform-independent pieces — the [`CallerAuth`] trait, the
//! [`CallerIdentity`] it produces, and the pure [`cross_check_ima`] parser —
//! live here so they can be unit-tested on any host. The Linux wiring that
//! reads real `SO_PEERCRED` / IMA state is [`ImaCallerAuth`], compiled only on
//! Linux.

/// Peer credentials read from the connected socket via `SO_PEERCRED`.
///
/// The server reads these on the async side (a cheap, non-blocking syscall via
/// tokio's portable `UnixStream::peer_cred`) and hands them to a [`CallerAuth`]
/// so the authenticator's blocking filesystem work can run on the blocking
/// pool without borrowing the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Peer process id, if the platform reports one.
    pub pid: Option<u32>,
    /// Peer user id.
    pub uid: u32,
    /// Peer group id.
    pub gid: u32,
}

/// A caller identity established from kernel-attested sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    /// Calling process id.
    pub pid: u32,
    /// Calling user id (the token user's RID on Windows).
    pub uid: u32,
    /// Calling group id.
    pub gid: u32,
    /// IMA-verified `SHA-384` of the calling binary.
    pub bin_sha: [u8; 48],
    /// Canonical path of the calling executable (F19 §4.2), as the kernel
    /// resolved it: `/proc/<pid>/exe` without a ` (deleted)` suffix on Linux,
    /// the on-disk form of the opened image on macOS, the final path name on
    /// Windows. On Unix it is set only when it is bound to the hashed image
    /// in the daemon's own mount namespace (same device and inode; on Linux
    /// the caller also shares the daemon's mount namespace and root), see
    /// [`crate::helper::exe_path`]. `None` when the platform could not
    /// resolve a valid, bound one; an allowlist v2 entry with a path
    /// constraint then admits nobody (fail closed).
    pub exe_path: Option<String>,
    /// **Windows.** The caller's full user SID (`S-1-5-…`), for allowlist v2
    /// SID constraints. `None` elsewhere, or when it could not be read.
    pub user_sid: Option<String>,
}

impl CallerIdentity {
    /// An identity with no resolved path or SID.
    #[must_use]
    pub const fn new(pid: u32, uid: u32, gid: u32, bin_sha: [u8; 48]) -> Self {
        Self {
            pid,
            uid,
            gid,
            bin_sha,
            exe_path: None,
            user_sid: None,
        }
    }

    /// The same identity with `exe_path` set.
    #[must_use]
    pub fn with_exe_path(mut self, exe_path: impl Into<String>) -> Self {
        self.exe_path = Some(exe_path.into());
        self
    }
}

/// The failing step of reading a caller's image and the OS's answer, carried
/// by [`AuthError::ExeUnreadable`] / [`AuthError::ImageUnreadable`].
///
/// For the daemon's local WARN log only ([`AuthError::detail`]): replies and
/// `LocalDenied` events carry just [`AuthError::reason`]. No contents/hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableDetail {
    /// The failing step. macOS: `pid-range`, `proc_pidpath`, `open`, `read`.
    /// Linux: `read_link`, `path-utf8`, `open`, `read`. Windows:
    /// `process_image_path`, `open`, `read`, `process_user_rid`.
    pub step: &'static str,
    /// The `io::ErrorKind` plus, from the OS, its text and raw code (or
    /// `libproc`'s error string). `None` for `pid-range` and `path-utf8`.
    pub os_error: Option<String>,
    /// The resolved executable path, when the failure came after resolving it.
    pub path: Option<String>,
}

impl UnreadableDetail {
    /// A failure at `step`, with no OS error and no resolved path yet.
    #[must_use]
    pub const fn new(step: &'static str) -> Self {
        Self {
            step,
            os_error: None,
            path: None,
        }
    }

    /// The same detail with [`Self::os_error`] from an `io::Error`: its kind,
    /// then the OS text and raw code when the OS reported one. A non-OS error
    /// contributes only its kind, so no free-form message reaches the log.
    #[must_use]
    pub fn with_io_error(mut self, e: &std::io::Error) -> Self {
        self.os_error = Some(match e.raw_os_error() {
            Some(_) => format!("{:?}: {e}", e.kind()),
            None => format!("{:?}", e.kind()),
        });
        self
    }

    /// The same detail with [`Self::os_error`] set verbatim (a library's
    /// error string, such as `libproc`'s `errno` message).
    #[must_use]
    pub fn with_os_error(mut self, os_error: impl Into<String>) -> Self {
        self.os_error = Some(os_error.into());
        self
    }

    /// The same detail with the resolved executable path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

/// Why caller authentication failed. Each variant maps to a stable opcode for
/// the audit log ([`AuthError::reason`], also the `Display`) that echoes no
/// caller-controlled bytes; the image-read variants also carry an
/// [`UnreadableDetail`] for the local log only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// `SO_PEERCRED` could not be read from the socket.
    #[error("peer-cred-unavailable")]
    PeerCredUnavailable,
    /// The caller's executable (`/proc/<pid>/exe` on Linux, the
    /// `proc_pidpath` image on macOS) could not be read to hash it.
    #[error("exe-unreadable")]
    ExeUnreadable {
        /// PID/UID recovered from peer-cred before the failure, if any.
        partial: Option<(u32, u32)>,
        /// The failing step and the OS's answer, for the local log only.
        detail: UnreadableDetail,
    },
    /// IMA is not available/enforced on this host.
    #[error("ima-unavailable")]
    ImaUnavailable {
        /// PID/UID recovered from peer-cred before the failure, if any.
        partial: Option<(u32, u32)>,
    },
    /// No IMA entry was found for the caller's executable path.
    #[error("ima-missing-entry")]
    ImaMissingEntry {
        /// PID/UID recovered from peer-cred before the failure, if any.
        partial: Option<(u32, u32)>,
    },
    /// The on-disk hash disagrees with the IMA-measured hash — a swap.
    #[error("ima-mismatch")]
    ImaMismatch {
        /// PID/UID recovered from peer-cred before the failure, if any.
        partial: Option<(u32, u32)>,
    },
    /// **Windows.** The caller's image path or user token could not be read.
    #[error("image-unreadable")]
    ImageUnreadable {
        /// PID/UID recovered before the failure, if any.
        partial: Option<(u32, u32)>,
        /// The failing step and the OS's answer, for the local log only.
        detail: UnreadableDetail,
    },
    /// **Windows.** The caller's image failed Authenticode / Code-Integrity
    /// verification (the analogue of an IMA mismatch).
    #[error("untrusted-binary")]
    Untrusted {
        /// PID/UID recovered before the failure, if any.
        partial: Option<(u32, u32)>,
    },
}

impl AuthError {
    /// The stable opcode recorded in a `LocalDenied` audit event.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            AuthError::PeerCredUnavailable => "peer-cred-unavailable",
            AuthError::ExeUnreadable { .. } => "exe-unreadable",
            AuthError::ImaUnavailable { .. } => "ima-unavailable",
            AuthError::ImaMissingEntry { .. } => "ima-missing-entry",
            AuthError::ImaMismatch { .. } => "ima-mismatch",
            AuthError::ImageUnreadable { .. } => "image-unreadable",
            AuthError::Untrusted { .. } => "untrusted-binary",
        }
    }

    /// PID/UID recovered before the failure, when known — used so a denial can
    /// still be attributed in the audit log.
    #[must_use]
    pub fn partial(&self) -> Option<(u32, u32)> {
        match self {
            AuthError::PeerCredUnavailable => None,
            AuthError::ExeUnreadable { partial, .. }
            | AuthError::ImaUnavailable { partial }
            | AuthError::ImaMissingEntry { partial }
            | AuthError::ImaMismatch { partial }
            | AuthError::ImageUnreadable { partial, .. }
            | AuthError::Untrusted { partial } => *partial,
        }
    }

    /// Which step of reading the caller's image failed and the OS's answer,
    /// for [`AuthError::ExeUnreadable`] and [`AuthError::ImageUnreadable`];
    /// `None` for the other variants.
    ///
    /// Log it locally (the helper server does, at WARN). Never put it in an
    /// audit event or a client reply: those carry only [`AuthError::reason`].
    #[must_use]
    pub fn detail(&self) -> Option<&UnreadableDetail> {
        match self {
            AuthError::ExeUnreadable { detail, .. } | AuthError::ImageUnreadable { detail, .. } => {
                Some(detail)
            }
            AuthError::PeerCredUnavailable
            | AuthError::ImaUnavailable { .. }
            | AuthError::ImaMissingEntry { .. }
            | AuthError::ImaMismatch { .. }
            | AuthError::Untrusted { .. } => None,
        }
    }
}

/// Open the caller's image at `open` and `SHA-384` its bytes, naming the
/// failing step (`open` or `read`) with `shown` — the resolved executable
/// path — in the returned [`UnreadableDetail`].
///
/// The open file is returned so the caller can derive the canonical path
/// from the same image it hashed (F19 §4.1).
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux", windows)),
    allow(dead_code)
)]
fn open_and_hash(
    open: &std::path::Path,
    shown: &str,
) -> Result<(std::fs::File, [u8; 48]), UnreadableDetail> {
    let mut file = std::fs::File::open(open).map_err(|e| {
        UnreadableDetail::new("open")
            .with_io_error(&e)
            .with_path(shown)
    })?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).map_err(|e| {
        UnreadableDetail::new("read")
            .with_io_error(&e)
            .with_path(shown)
    })?;
    Ok((file, bin_sha384(&bytes)))
}

/// Establishes the identity of a peer from its `SO_PEERCRED` credentials.
///
/// Implementations are synchronous and may block on filesystem reads (IMA log,
/// `/proc/<pid>/exe`); the server runs `identify` on the blocking pool, so the
/// credentials are passed by value rather than borrowing the socket.
pub trait CallerAuth: Send + Sync + 'static {
    /// Identify the peer described by `cred`, or explain why it cannot be
    /// trusted.
    fn identify(&self, cred: PeerCred) -> Result<CallerIdentity, AuthError>;
}

/// Cross-check an on-disk binary hash against the IMA runtime measurement log.
///
/// `disk_sha` is `SHA-384(/proc/<pid>/exe)` read from disk now; `exe_path` is
/// the resolved executable path; `ima_log` is the ASCII content of
/// `/sys/kernel/security/ima/binary_runtime_measurements`. Each IMA line is
///
/// ```text
/// <pcr> <template-hash> <template-name> <algo>:<filehash-hex> <path>
/// ```
///
/// We require an entry whose path matches `exe_path` *and* whose `sha384`
/// file-hash equals `disk_sha`. A path entry that exists but whose hash
/// differs is a [`MismatchOutcome::Mismatch`] (the swap case); no entry at all
/// is [`MismatchOutcome::Missing`].
///
/// Returns the verified 48-byte hash on success.
pub fn cross_check_ima(
    disk_sha: &[u8; 48],
    exe_path: &str,
    ima_log: &str,
) -> Result<[u8; 48], MismatchOutcome> {
    let mut saw_path = false;
    for line in ima_log.lines() {
        let mut fields = line.split_whitespace();
        // pcr, template-hash, template-name, file-hash, path...
        let (Some(_pcr), Some(_tmpl_hash), Some(_tmpl_name), Some(file_hash)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // The path is the remainder of the line (paths may, in theory, contain
        // spaces); reconstruct it from the rest of the fields.
        let path: String = fields.collect::<Vec<_>>().join(" ");
        if path != exe_path {
            continue;
        }

        let Some((algo, hex_hash)) = file_hash.split_once(':') else {
            continue;
        };
        if !algo.eq_ignore_ascii_case("sha384") {
            continue;
        }
        let Ok(measured) = hex::decode(hex_hash) else {
            continue;
        };
        // A comparable sha384 measurement for this path exists; from here a
        // failure to match is a genuine mismatch, not a missing entry.
        saw_path = true;
        if measured.as_slice() == disk_sha.as_slice() {
            return Ok(*disk_sha);
        }
    }

    if saw_path {
        Err(MismatchOutcome::Mismatch)
    } else {
        Err(MismatchOutcome::Missing)
    }
}

/// `SHA-384` of a caller binary's image bytes — the allowlist's `bin_sha`.
///
/// Every platform authenticator hashes the caller's image with this, as do the
/// daemon's self-trust probe ([`running_exe_sha384`]) and the offline
/// `mia allowlist-diagnose`, so an operator's diagnosis computes exactly the
/// digest the helper API matches against the allowlist. (On Linux the helper
/// additionally requires this digest to equal the IMA measurement.)
#[must_use]
pub fn bin_sha384(image: &[u8]) -> [u8; 48] {
    use sha2::{Digest as _, Sha384};
    Sha384::digest(image).into()
}

/// [`bin_sha384`] of this process's own executable, or `None` when its path or
/// bytes cannot be read.
///
/// The daemon computes it once at startup as its self-trust hash (see
/// `docs/helper-api.md`, "`mia` self-trust"): a caller whose `bin_sha` equals
/// it is `mia` itself and is permitted without consulting the allowlist.
#[must_use]
pub fn running_exe_sha384() -> Option<[u8; 48]> {
    let path = std::env::current_exe().ok()?;
    let bytes = std::fs::read(path).ok()?;
    Some(bin_sha384(&bytes))
}

/// Result of a failed [`cross_check_ima`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchOutcome {
    /// An IMA entry for the path exists but its hash differs (swap detected).
    Mismatch,
    /// No usable IMA entry exists for the path.
    Missing,
}

#[cfg(windows)]
pub use windows_auth::WindowsCallerAuth;

#[cfg(windows)]
mod windows_auth {
    use super::{AuthError, CallerAuth, CallerIdentity, PeerCred, UnreadableDetail};

    /// The production Windows caller authenticator.
    ///
    /// From the client PID (supplied in [`PeerCred`] by the named-pipe
    /// transport via `GetNamedPipeClientProcessId`), it resolves the caller's
    /// image path and user-token RID, hashes the image (`SHA-384`, the
    /// allowlist's `bin_sha`), and — when configured — requires the image to
    /// pass Authenticode / Code-Integrity verification. All FFI lives in the
    /// `ferro-winauth` crate so `mia` stays `#![forbid(unsafe_code)]`.
    pub struct WindowsCallerAuth {
        require_authenticode: bool,
    }

    impl WindowsCallerAuth {
        /// Require a valid Authenticode signature on the caller's image.
        #[must_use]
        pub fn new() -> Self {
            Self {
                require_authenticode: true,
            }
        }

        /// Skip the Authenticode check (identity by PID + image hash + RID
        /// only). For environments without code-signing.
        #[must_use]
        pub fn without_authenticode() -> Self {
            Self {
                require_authenticode: false,
            }
        }
    }

    impl Default for WindowsCallerAuth {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CallerAuth for WindowsCallerAuth {
        fn identify(&self, cred: PeerCred) -> Result<CallerIdentity, AuthError> {
            let pid = cred.pid.ok_or(AuthError::PeerCredUnavailable)?;
            let partial = Some((pid, 0));
            let unreadable =
                |detail: UnreadableDetail| AuthError::ImageUnreadable { partial, detail };

            let path = ferro_winauth::process_image_path(pid).map_err(|e| {
                unreadable(UnreadableDetail::new("process_image_path").with_io_error(&e))
            })?;
            let shown = path.to_string_lossy().into_owned();
            // The handle is dropped at once, as `std::fs::read` did.
            let (_, bin_sha) = super::open_and_hash(&path, &shown).map_err(unreadable)?;
            // `canonicalize` opens the image and asks for its final path name
            // (`GetFinalPathNameByHandleW`), which expands 8.3 names; the
            // F19 rules then strip `\\?\` and map `\\?\UNC\` to `\\`.
            let exe_path = std::fs::canonicalize(&path)
                .ok()
                .and_then(|p| p.to_str().map(str::to_string))
                .and_then(|p| ferro_appid::path::from_windows_final_path(&p).ok())
                .map(|c| c.path);
            let user_sid = ferro_winauth::process_user_sid(pid).ok();

            let uid = ferro_winauth::process_user_rid(pid).map_err(|e| {
                unreadable(
                    UnreadableDetail::new("process_user_rid")
                        .with_io_error(&e)
                        .with_path(shown.as_str()),
                )
            })?;
            let partial = Some((pid, uid));

            if self.require_authenticode {
                let trusted = ferro_winauth::verify_authenticode(&path)
                    .map_err(|_| AuthError::Untrusted { partial })?;
                if !trusted {
                    return Err(AuthError::Untrusted { partial });
                }
            }

            Ok(CallerIdentity {
                pid,
                uid,
                gid: 0, // not meaningful on Windows
                bin_sha,
                exe_path,
                user_sid,
            })
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos_auth::MacCallerAuth;

#[cfg(target_os = "macos")]
mod macos_auth {
    use super::{AuthError, CallerAuth, CallerIdentity, PeerCred, UnreadableDetail};

    /// The macOS caller authenticator: `getpeereid`/`LOCAL_PEERPID` peer
    /// credentials plus an on-disk image hash.
    ///
    /// From the peer PID (read by the UDS transport) it resolves the caller's
    /// executable path via `libproc` (`proc_pidpath`), hashes the image
    /// (`SHA-384`, the allowlist's `bin_sha`), and reports `(pid, uid, gid)`
    /// from the socket credentials. This is the analogue of
    /// [`WindowsCallerAuth::without_authenticode`](super::WindowsCallerAuth):
    /// it establishes binary identity but does **not** verify a code signature
    /// (macOS has no IMA-equivalent runtime measurement). All FFI lives in the
    /// external `libproc` crate, so `mia` itself stays `#![forbid(unsafe_code)]`.
    pub struct MacCallerAuth {
        _private: (),
    }

    impl MacCallerAuth {
        /// Construct the authenticator.
        #[must_use]
        pub fn new() -> Self {
            Self { _private: () }
        }
    }

    impl Default for MacCallerAuth {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CallerAuth for MacCallerAuth {
        fn identify(&self, cred: PeerCred) -> Result<CallerIdentity, AuthError> {
            let pid = cred.pid.ok_or(AuthError::PeerCredUnavailable)?;
            let partial = Some((pid, cred.uid));
            let unreadable =
                |detail: UnreadableDetail| AuthError::ExeUnreadable { partial, detail };
            let pid_i32 =
                i32::try_from(pid).map_err(|_| unreadable(UnreadableDetail::new("pid-range")))?;

            let path = libproc::proc_pid::pidpath(pid_i32)
                .map_err(|e| unreadable(UnreadableDetail::new("proc_pidpath").with_os_error(e)))?;
            // Hash and canonical path come from one open file, so they
            // describe the same image (F19 §4.1).
            let (file, bin_sha) =
                super::open_and_hash(std::path::Path::new(&path), &path).map_err(unreadable)?;
            let exe_path = crate::helper::exe_path::macos_canonical(&file);

            Ok(CallerIdentity {
                pid,
                uid: cred.uid,
                gid: cred.gid,
                bin_sha,
                exe_path,
                user_sid: None,
            })
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::ImaCallerAuth;

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        AuthError, CallerAuth, CallerIdentity, MismatchOutcome, PeerCred, UnreadableDetail,
    };
    use std::path::{Path, PathBuf};

    /// Default location of the IMA runtime measurement log.
    pub(crate) const DEFAULT_IMA_LOG: &str = "/sys/kernel/security/ima/binary_runtime_measurements";

    /// The Linux caller authenticator: `SO_PEERCRED` + a SHA-384 of the caller's
    /// `/proc/<pid>/exe`.
    ///
    /// When `require_ima` is set (the production default) that hash is
    /// cross-checked against the kernel IMA measurement log, so a caller whose
    /// binary was not IMA-measured — or whose on-disk bytes no longer match its
    /// measurement — is rejected. When it is clear (the daemon started with
    /// `FERROGATE_REQUIRE_IMA=0`, i.e. IMA is not enforced on this host) the IMA
    /// cross-check is skipped and identity rests on the hash of the loaded binary
    /// alone — mirroring how [`WindowsCallerAuth`](super::WindowsCallerAuth) drops
    /// the Authenticode check when it is not required. The hash is always read
    /// *through* the `/proc/<pid>/exe` handle, so it covers the bytes the process
    /// was actually loaded from even if the on-disk path was swapped.
    pub struct ImaCallerAuth {
        ima_log_path: PathBuf,
        require_ima: bool,
    }

    impl ImaCallerAuth {
        /// Use the default IMA log path, cross-checking against IMA.
        #[must_use]
        pub fn new() -> Self {
            Self {
                ima_log_path: PathBuf::from(DEFAULT_IMA_LOG),
                require_ima: true,
            }
        }

        /// Use a custom IMA log path (testing / non-standard mounts).
        #[must_use]
        pub fn with_ima_log(path: impl Into<PathBuf>) -> Self {
            Self {
                ima_log_path: path.into(),
                require_ima: true,
            }
        }

        /// Authenticate by the loaded-binary hash alone, without the IMA
        /// cross-check. For hosts that do not enforce IMA (`FERROGATE_REQUIRE_IMA=0`),
        /// where there is no measurement log to check against.
        #[must_use]
        pub fn without_ima(mut self) -> Self {
            self.require_ima = false;
            self
        }
    }

    impl Default for ImaCallerAuth {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CallerAuth for ImaCallerAuth {
        fn identify(&self, cred: PeerCred) -> Result<CallerIdentity, AuthError> {
            let pid = cred.pid.ok_or(AuthError::PeerCredUnavailable)?;
            let uid = cred.uid;
            let gid = cred.gid;
            let partial = Some((pid, uid));
            let unreadable =
                |detail: UnreadableDetail| AuthError::ExeUnreadable { partial, detail };

            let exe_link = format!("/proc/{pid}/exe");
            let exe_path = std::fs::read_link(&exe_link)
                .map_err(|e| unreadable(UnreadableDetail::new("read_link").with_io_error(&e)))?;
            let exe_path_str = exe_path
                .to_str()
                .ok_or_else(|| {
                    unreadable(
                        UnreadableDetail::new("path-utf8").with_path(exe_path.to_string_lossy()),
                    )
                })?
                .to_string();
            // Read through the /proc/<pid>/exe handle so we hash the bytes the
            // running process was loaded from, even if the on-disk name moved.
            let (image, disk_sha) =
                super::open_and_hash(Path::new(&exe_link), &exe_path_str).map_err(unreadable)?;
            // The F19 §4.2 canonical form (` (deleted)` stripped, so a process
            // still running after an upgrade keeps matching by path), taken
            // from the same open image and bound to it in the daemon's mount
            // namespace: a path rendered in another namespace (a bind mount
            // over a protected binary) is no path at all, so a v2 entry with
            // a path constraint admits nobody (fail closed).
            let canonical = crate::helper::exe_path::of_running_image(pid, &image).map(|c| c.path);

            // IMA not enforced on this host: trust the hash of the loaded binary
            // (read through /proc/<pid>/exe) without a measurement-log cross-check.
            if !self.require_ima {
                return Ok(CallerIdentity {
                    pid,
                    uid,
                    gid,
                    bin_sha: disk_sha,
                    exe_path: canonical,
                    user_sid: None,
                });
            }

            let ima_log = std::fs::read_to_string(&self.ima_log_path)
                .map_err(|_| AuthError::ImaUnavailable { partial })?;

            match super::cross_check_ima(&disk_sha, &exe_path_str, &ima_log) {
                Ok(bin_sha) => Ok(CallerIdentity {
                    pid,
                    uid,
                    gid,
                    bin_sha,
                    exe_path: canonical,
                    user_sid: None,
                }),
                Err(MismatchOutcome::Mismatch) => Err(AuthError::ImaMismatch { partial }),
                Err(MismatchOutcome::Missing) => Err(AuthError::ImaMissingEntry { partial }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(byte: u8) -> [u8; 48] {
        [byte; 48]
    }

    fn line(path: &str, algo: &str, hash: &[u8; 48]) -> String {
        format!("10 abcd ima-ng {algo}:{} {path}", hex::encode(hash))
    }

    #[test]
    fn matching_entry_returns_verified_hash() {
        let h = sha(0xAB);
        let log = line("/usr/bin/foo", "sha384", &h);
        assert_eq!(cross_check_ima(&h, "/usr/bin/foo", &log).unwrap(), h);
    }

    // With IMA not required, identify() hashes the caller's loaded binary
    // (/proc/<pid>/exe) and returns it directly, never touching the IMA log — so
    // a host without a readable/populated IMA log can still authenticate callers.
    #[cfg(target_os = "linux")]
    #[test]
    fn without_ima_authenticates_by_loaded_binary_hash() {
        // Point at a bogus IMA path to prove the log is never read on this path.
        let auth = ImaCallerAuth::with_ima_log("/nonexistent/ima/log").without_ima();
        let cred = PeerCred {
            pid: Some(std::process::id()),
            uid: 0,
            gid: 0,
        };
        let id = auth
            .identify(cred)
            .expect("without_ima identify should succeed with no IMA log");
        assert_eq!(id.pid, std::process::id());
        assert_ne!(
            id.bin_sha, [0u8; 48],
            "bin_sha must be the real binary hash"
        );
        // This process shares the daemon's view: its path is bound.
        assert_eq!(
            id.exe_path.as_deref().map(std::path::Path::new),
            Some(std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()).as_deref()
        );
    }

    #[test]
    fn swapped_binary_is_a_mismatch() {
        // IMA measured 0xAB at exec; disk now hashes to 0xCD (attacker swap).
        let measured = sha(0xAB);
        let disk = sha(0xCD);
        let log = line("/usr/bin/foo", "sha384", &measured);
        assert_eq!(
            cross_check_ima(&disk, "/usr/bin/foo", &log).unwrap_err(),
            MismatchOutcome::Mismatch
        );
    }

    #[test]
    fn unknown_path_is_missing_not_mismatch() {
        let h = sha(0xAB);
        let log = line("/usr/bin/other", "sha384", &h);
        assert_eq!(
            cross_check_ima(&h, "/usr/bin/foo", &log).unwrap_err(),
            MismatchOutcome::Missing
        );
    }

    #[test]
    fn non_sha384_entries_are_ignored() {
        let h = sha(0xAB);
        // Only a sha256 entry for the path — unusable, so "missing".
        let log = line("/usr/bin/foo", "sha256", &h);
        assert_eq!(
            cross_check_ima(&h, "/usr/bin/foo", &log).unwrap_err(),
            MismatchOutcome::Missing
        );
    }

    #[test]
    fn empty_log_is_missing() {
        let h = sha(0x01);
        assert_eq!(
            cross_check_ima(&h, "/usr/bin/foo", "").unwrap_err(),
            MismatchOutcome::Missing
        );
    }

    /// `bin_sha384` is plain file-content SHA-384 (FIPS 180-2 "abc" vector), so
    /// it matches `openssl dgst -sha384` and `ferrogate allowlist --bin`.
    #[test]
    fn bin_sha384_is_file_content_sha384() {
        assert_eq!(
            hex::encode(bin_sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    fn detail(step: &'static str) -> UnreadableDetail {
        UnreadableDetail::new(step)
            .with_os_error("NotFound: No such file or directory (os error 2)")
            .with_path("/Applications/Some.app/Contents/MacOS/some")
    }

    /// Every variant keeps its `LocalDenied` opcode, and `Display` stays that
    /// bare opcode: the diagnostic detail reaches neither.
    #[test]
    fn auth_error_reason_codes_are_stable() {
        let p = Some((7, 8));
        let cases = [
            (AuthError::PeerCredUnavailable, "peer-cred-unavailable"),
            (
                AuthError::ExeUnreadable {
                    partial: p,
                    detail: detail("open"),
                },
                "exe-unreadable",
            ),
            (AuthError::ImaUnavailable { partial: p }, "ima-unavailable"),
            (
                AuthError::ImaMissingEntry { partial: p },
                "ima-missing-entry",
            ),
            (AuthError::ImaMismatch { partial: p }, "ima-mismatch"),
            (
                AuthError::ImageUnreadable {
                    partial: p,
                    detail: detail("read"),
                },
                "image-unreadable",
            ),
            (AuthError::Untrusted { partial: p }, "untrusted-binary"),
        ];
        for (e, code) in cases {
            assert_eq!(e.reason(), code);
            assert_eq!(e.to_string(), code, "Display must stay the bare opcode");
            let want = (e != AuthError::PeerCredUnavailable).then_some((7, 8));
            assert_eq!(e.partial(), want, "{code}");
        }
    }

    #[test]
    fn detail_is_only_on_the_image_read_variants() {
        let d = detail("open");
        let exe = AuthError::ExeUnreadable {
            partial: None,
            detail: d.clone(),
        };
        let image = AuthError::ImageUnreadable {
            partial: None,
            detail: d.clone(),
        };
        assert_eq!(exe.detail(), Some(&d));
        assert_eq!(image.detail(), Some(&d));
        for e in [
            AuthError::PeerCredUnavailable,
            AuthError::ImaUnavailable { partial: None },
            AuthError::ImaMissingEntry { partial: None },
            AuthError::ImaMismatch { partial: None },
            AuthError::Untrusted { partial: None },
        ] {
            assert_eq!(e.detail(), None, "{e}");
        }
    }

    /// An OS error names its kind, text and raw code; any other `io::Error`
    /// names only its kind, so a free-form message never reaches the log.
    #[cfg(unix)]
    #[test]
    fn io_error_detail_names_kind_and_os_code_only() {
        // 13 is `EACCES` on every Unix this crate targets.
        let os =
            UnreadableDetail::new("open").with_io_error(&std::io::Error::from_raw_os_error(13));
        let text = os.os_error.unwrap();
        assert!(text.starts_with("PermissionDenied: "), "{text}");
        assert!(text.ends_with("(os error 13)"), "{text}");

        let custom = UnreadableDetail::new("read")
            .with_io_error(&std::io::Error::other("caller-chosen text"));
        assert_eq!(custom.os_error.as_deref(), Some("Other"));
    }

    #[test]
    fn open_failure_is_the_open_step_with_path_and_os_error() {
        let missing = std::env::temp_dir().join(format!(
            "ferrogate-auth-missing-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let shown = missing.to_string_lossy().into_owned();
        let d = open_and_hash(&missing, &shown).unwrap_err();
        assert_eq!(d.step, "open");
        assert_eq!(d.path.as_deref(), Some(shown.as_str()));
        let os = d.os_error.unwrap();
        assert!(os.starts_with("NotFound: "), "{os}");
        assert!(os.contains("os error"), "{os}");
    }

    /// A directory opens on Unix but cannot be read, which isolates the
    /// `read` step.
    #[cfg(unix)]
    #[test]
    fn read_failure_is_the_read_step_with_path_and_os_error() {
        let dir = std::env::temp_dir();
        let d = open_and_hash(&dir, "/shown/path").unwrap_err();
        assert_eq!(d.step, "read");
        assert_eq!(d.path.as_deref(), Some("/shown/path"));
        assert!(d.os_error.unwrap().contains("os error"));
    }

    #[test]
    fn open_and_hash_hashes_the_file_bytes() {
        let exe = std::env::current_exe().unwrap();
        let (_, sha) = open_and_hash(&exe, "shown").unwrap();
        assert_eq!(sha, bin_sha384(&std::fs::read(&exe).unwrap()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pid_beyond_i32_is_the_pid_range_step() {
        let cred = PeerCred {
            pid: Some(u32::MAX),
            uid: 501,
            gid: 20,
        };
        let err = MacCallerAuth::new().identify(cred).unwrap_err();
        assert_eq!(err.reason(), "exe-unreadable");
        assert_eq!(err.partial(), Some((u32::MAX, 501)));
        assert_eq!(err.detail(), Some(&UnreadableDetail::new("pid-range")));
    }

    /// macOS pids stay below 100 000, so `i32::MAX` names no process.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_unknown_pid_is_the_proc_pidpath_step() {
        let cred = PeerCred {
            pid: Some(0x7fff_ffff),
            uid: 501,
            gid: 20,
        };
        let err = MacCallerAuth::new().identify(cred).unwrap_err();
        assert_eq!(err.reason(), "exe-unreadable");
        let d = err.detail().unwrap();
        assert_eq!(d.step, "proc_pidpath");
        assert!(
            d.os_error.as_deref().is_some_and(|e| e.contains("errno")),
            "{d:?}"
        );
        assert_eq!(d.path, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_identifies_this_process() {
        let cred = PeerCred {
            pid: Some(std::process::id()),
            uid: 501,
            gid: 20,
        };
        let id = MacCallerAuth::new().identify(cred).unwrap();
        assert_eq!(Some(id.bin_sha), running_exe_sha384());
        assert_eq!((id.uid, id.gid), (501, 20));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unknown_pid_is_the_read_link_step() {
        let cred = PeerCred {
            pid: Some(u32::MAX),
            uid: 1000,
            gid: 1000,
        };
        let err = ImaCallerAuth::new().identify(cred).unwrap_err();
        assert_eq!(err.reason(), "exe-unreadable");
        assert_eq!(err.partial(), Some((u32::MAX, 1000)));
        let d = err.detail().unwrap();
        assert_eq!(d.step, "read_link");
        assert!(
            d.os_error
                .as_deref()
                .is_some_and(|e| e.starts_with("NotFound")),
            "{d:?}"
        );
        assert_eq!(d.path, None);
    }
}
