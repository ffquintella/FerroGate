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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerIdentity {
    /// Calling process id.
    pub pid: u32,
    /// Calling user id.
    pub uid: u32,
    /// Calling group id.
    pub gid: u32,
    /// IMA-verified `SHA-384` of the calling binary.
    pub bin_sha: [u8; 48],
}

/// Why caller authentication failed. Each variant maps to a stable opcode for
/// the audit log; none of them echoes caller-controlled bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// `SO_PEERCRED` could not be read from the socket.
    #[error("peer-cred-unavailable")]
    PeerCredUnavailable,
    /// `/proc/<pid>/exe` could not be read to hash the caller binary.
    #[error("exe-unreadable")]
    ExeUnreadable {
        /// PID/UID recovered from peer-cred before the failure, if any.
        partial: Option<(u32, u32)>,
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
            AuthError::ExeUnreadable { partial }
            | AuthError::ImaUnavailable { partial }
            | AuthError::ImaMissingEntry { partial }
            | AuthError::ImaMismatch { partial }
            | AuthError::ImageUnreadable { partial }
            | AuthError::Untrusted { partial } => *partial,
        }
    }
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
    use super::{AuthError, CallerAuth, CallerIdentity, PeerCred};
    use sha2::{Digest, Sha384};

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

            let path = ferro_winauth::process_image_path(pid)
                .map_err(|_| AuthError::ImageUnreadable { partial })?;
            let bytes = std::fs::read(&path).map_err(|_| AuthError::ImageUnreadable { partial })?;
            let bin_sha: [u8; 48] = Sha384::digest(&bytes).into();

            let uid = ferro_winauth::process_user_rid(pid)
                .map_err(|_| AuthError::ImageUnreadable { partial })?;
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
            })
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::ImaCallerAuth;

#[cfg(target_os = "linux")]
mod linux {
    use super::{AuthError, CallerAuth, CallerIdentity, MismatchOutcome, PeerCred};
    use sha2::{Digest, Sha384};
    use std::path::PathBuf;

    /// Default location of the IMA runtime measurement log.
    pub(crate) const DEFAULT_IMA_LOG: &str = "/sys/kernel/security/ima/binary_runtime_measurements";

    /// The production caller authenticator: `SO_PEERCRED` + IMA cross-check.
    pub struct ImaCallerAuth {
        ima_log_path: PathBuf,
    }

    impl ImaCallerAuth {
        /// Use the default IMA log path.
        #[must_use]
        pub fn new() -> Self {
            Self {
                ima_log_path: PathBuf::from(DEFAULT_IMA_LOG),
            }
        }

        /// Use a custom IMA log path (testing / non-standard mounts).
        #[must_use]
        pub fn with_ima_log(path: impl Into<PathBuf>) -> Self {
            Self {
                ima_log_path: path.into(),
            }
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

            let exe_link = format!("/proc/{pid}/exe");
            let exe_path =
                std::fs::read_link(&exe_link).map_err(|_| AuthError::ExeUnreadable { partial })?;
            let exe_path_str = exe_path
                .to_str()
                .ok_or(AuthError::ExeUnreadable { partial })?
                .to_string();
            // Read through the /proc/<pid>/exe handle so we hash the bytes the
            // running process was loaded from, even if the on-disk name moved.
            let contents =
                std::fs::read(&exe_link).map_err(|_| AuthError::ExeUnreadable { partial })?;
            let disk_sha: [u8; 48] = Sha384::digest(&contents).into();

            let ima_log = std::fs::read_to_string(&self.ima_log_path)
                .map_err(|_| AuthError::ImaUnavailable { partial })?;

            match super::cross_check_ima(&disk_sha, &exe_path_str, &ima_log) {
                Ok(bin_sha) => Ok(CallerIdentity {
                    pid,
                    uid,
                    gid,
                    bin_sha,
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

    #[test]
    fn auth_error_reason_codes_are_stable() {
        assert_eq!(
            AuthError::PeerCredUnavailable.reason(),
            "peer-cred-unavailable"
        );
        assert_eq!(
            AuthError::ImaMismatch {
                partial: Some((7, 8))
            }
            .reason(),
            "ima-mismatch"
        );
        assert_eq!(
            AuthError::ImaMismatch {
                partial: Some((7, 8))
            }
            .partial(),
            Some((7, 8))
        );
    }
}
