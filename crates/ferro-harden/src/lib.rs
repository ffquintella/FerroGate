//! `ferro-harden` — Linux process-hardening primitives for the MIA (feature F12).
//!
//! `mia` is `#![forbid(unsafe_code)]`; this crate is the **only** place the
//! hardening FFI lives, mirroring how `ferro-winauth` isolates the Windows FFI.
//! It applies, in order, the defence-in-depth profile from `docs/mia.md`
//! §"Hardening profile":
//!
//! 1. `mlockall(MCL_CURRENT | MCL_FUTURE)` — key material never swaps to disk;
//! 2. `prctl(PR_SET_DUMPABLE, 0)` — no core dumps of secret-bearing memory;
//! 3. drop to a dedicated UID retaining only `CAP_IPC_LOCK`;
//! 4. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — required before seccomp without
//!    `CAP_SYS_ADMIN`, and a hardening win in its own right;
//! 5. a seccomp-bpf **allow-list** (`SECCOMP_RET_KILL_PROCESS` for anything not
//!    listed; a dev "audit" mode logs instead of killing, to discover drift).
//!
//! Everything that touches a syscall is gated on `cfg(target_os = "linux")`; on
//! other platforms the crate compiles to no-op stubs that return
//! [`HardenError::Unsupported`], so it can be an unconditional dependency.

#![allow(unsafe_code)]
// this crate is the hardening syscall boundary by design
// FFI idiom: passing `&mut x` as a `*mut` out-parameter to a libc function is
// unavoidable and idiomatic here (same rationale as `ferro-winauth`).
#![allow(clippy::borrow_as_ptr)]

use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;

/// How a seccomp violation (a syscall not on the allow-list) is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    /// Kill the whole process with `SIGSYS` (production).
    Enforce,
    /// Log the violation and allow the call (development, to discover drift in
    /// the allow-list before rolling out `Enforce`).
    Audit,
}

impl SeccompMode {
    /// Parse a mode from a configuration string (`"enforce"` / `"audit"`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "enforce" | "strict" => Some(Self::Enforce),
            "audit" | "log" => Some(Self::Audit),
            _ => None,
        }
    }
}

/// A target UID/GID to drop to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunAs {
    /// The user id to switch to.
    pub uid: u32,
    /// The primary group id to switch to.
    pub gid: u32,
}

/// The hardening steps to apply, in dependency order. A `None`/`false` field is
/// skipped, so callers can compose a partial profile (e.g. for staged rollout).
#[derive(Debug, Clone)]
pub struct HardenProfile {
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)`.
    pub mlock: bool,
    /// `prctl(PR_SET_DUMPABLE, 0)`.
    pub non_dumpable: bool,
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Forced on when `seccomp` is set.
    pub no_new_privs: bool,
    /// Drop to this UID/GID, retaining only `CAP_IPC_LOCK`.
    pub drop_to: Option<RunAs>,
    /// Install the seccomp-bpf allow-list in the given mode.
    pub seccomp: Option<SeccompMode>,
}

impl HardenProfile {
    /// The full production profile: every defence on, seccomp enforcing, drop to
    /// `run_as`.
    #[must_use]
    pub fn production(run_as: RunAs) -> Self {
        Self {
            mlock: true,
            non_dumpable: true,
            no_new_privs: true,
            drop_to: Some(run_as),
            seccomp: Some(SeccompMode::Enforce),
        }
    }
}

/// Failure modes for the hardening steps. Each is fatal: the MIA must exit
/// non-zero rather than continue with a weaker profile than configured.
#[derive(Debug, Error)]
pub enum HardenError {
    /// `mlockall` failed (commonly `RLIMIT_MEMLOCK` too low, or no privilege).
    #[error("mlockall failed: {0}")]
    Mlock(String),
    /// A `prctl` call failed.
    #[error("prctl {0} failed: {1}")]
    Prctl(&'static str, String),
    /// Dropping to the target UID/GID failed.
    #[error("privilege drop failed: {0}")]
    DropPrivileges(String),
    /// Restricting the capability set failed.
    #[error("capability restriction failed: {0}")]
    Capabilities(String),
    /// Building or installing the seccomp filter failed.
    #[error("seccomp install failed: {0}")]
    Seccomp(String),
    /// A configured syscall name is unknown on this architecture.
    #[error("unknown syscall in allow-list: {0}")]
    UnknownSyscall(String),
    /// Hardening is not supported on this platform (non-Linux build).
    #[error("process hardening is only supported on Linux")]
    Unsupported,
}

/// The seccomp syscall allow-list, by name.
///
/// Covers what the MIA's async runtime (tokio), gRPC stack (tonic / hyper / h2),
/// TLS (rustls / aws-lc), the TPM `ioctl` path, and the UDS helper server need
/// at steady state. Names are resolved to per-architecture numbers at install
/// time; a name that does not exist on the target arch (e.g. legacy `poll` on
/// aarch64) is simply skipped, so the same list is portable.
///
/// This is an **allow-list**: anything not here trips the filter. The dev
/// `Audit` mode exists precisely to surface a missing entry before it kills a
/// production process (see the F12 "syscall set churn" risk).
pub const ALLOWED_SYSCALLS: &[&str] = &[
    // I/O.
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "close",
    "lseek",
    "fcntl",
    "fsync",
    "fdatasync",
    "ftruncate",
    "openat",
    "readlinkat",
    "getdents64",
    "newfstatat",
    "statx",
    // Memory.
    "mmap",
    "munmap",
    "mprotect",
    "madvise",
    "brk",
    "mlockall",
    // Sockets / networking (UDS helper + CMIS gRPC client).
    "socket",
    "connect",
    "bind",
    "listen",
    "accept4",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    // TPM and generic device control.
    "ioctl",
    // Async runtime: epoll, eventfd, futex, timers, signals, threads.
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "eventfd2",
    "futex",
    "nanosleep",
    "clock_nanosleep",
    "clock_gettime",
    "gettimeofday",
    "sched_yield",
    "sched_getaffinity",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "clone",
    "clone3",
    "set_robust_list",
    "rseq",
    "membarrier",
    "ppoll",
    "pipe2",
    "dup3",
    "tgkill",
    // Identity / limits / entropy / housekeeping.
    "getpid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getrandom",
    "prlimit64",
    "uname",
    "restart_syscall",
    "exit",
    "exit_group",
];

/// Apply the hardening `profile`. On success the process is running under the
/// requested constraints; on failure the error is fatal and the caller must
/// exit non-zero.
///
/// # Errors
///
/// Returns the first step that fails, or [`HardenError::Unsupported`] on a
/// non-Linux build.
pub fn apply(profile: &HardenProfile) -> Result<(), HardenError> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(profile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile;
        Err(HardenError::Unsupported)
    }
}

/// Whether the process's effective UID is 0 (root). Privilege dropping only
/// applies when started as root; a non-root MIA skips that step.
#[must_use]
pub fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::is_root()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Resolve a system user name to its UID/GID (`getpwnam_r`). Returns `None` if
/// the user does not exist or the lookup fails.
#[must_use]
pub fn resolve_user(name: &str) -> Option<RunAs> {
    #[cfg(target_os = "linux")]
    {
        linux::resolve_user(name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        None
    }
}

/// The process's current effective capabilities, as `CAP_*` names (sorted). Used
/// to assert the post-drop capability set is exactly `{CAP_IPC_LOCK}`.
///
/// # Errors
///
/// Returns [`HardenError::Capabilities`] if the set cannot be read, or
/// [`HardenError::Unsupported`] on a non-Linux build.
pub fn effective_capabilities() -> Result<Vec<String>, HardenError> {
    #[cfg(target_os = "linux")]
    {
        linux::effective_capabilities()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(HardenError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_mode_parses_known_spellings() {
        assert_eq!(SeccompMode::parse("enforce"), Some(SeccompMode::Enforce));
        assert_eq!(SeccompMode::parse("STRICT"), Some(SeccompMode::Enforce));
        assert_eq!(SeccompMode::parse("audit"), Some(SeccompMode::Audit));
        assert_eq!(SeccompMode::parse(" Log "), Some(SeccompMode::Audit));
        assert_eq!(SeccompMode::parse("off"), None);
    }

    #[test]
    fn production_profile_is_fully_armed() {
        let p = HardenProfile::production(RunAs { uid: 999, gid: 999 });
        assert!(p.mlock && p.non_dumpable && p.no_new_privs);
        assert_eq!(p.drop_to, Some(RunAs { uid: 999, gid: 999 }));
        assert_eq!(p.seccomp, Some(SeccompMode::Enforce));
    }

    #[test]
    fn allowlist_is_an_explicit_allow_list_of_the_expected_shape() {
        // ~35+ syscalls per the design note; an allow-list, not a deny-list.
        assert!(
            ALLOWED_SYSCALLS.len() >= 35,
            "expected ~35+ syscalls, got {}",
            ALLOWED_SYSCALLS.len()
        );
        // Core families must be present.
        for must in [
            "read",
            "write",
            "close",
            "mmap",
            "munmap",
            "futex",
            "ioctl",
            "epoll_pwait",
            "recvmsg",
            "sendmsg",
            "getrandom",
            "exit_group",
            "mlockall",
            "clock_gettime",
        ] {
            assert!(
                ALLOWED_SYSCALLS.contains(&must),
                "allow-list missing {must}"
            );
        }
        // No duplicates.
        let mut sorted = ALLOWED_SYSCALLS.to_vec();
        sorted.sort_unstable();
        let len = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), len, "allow-list has duplicate entries");
    }

    #[test]
    fn dangerous_syscalls_are_absent() {
        // A few syscalls a hardened MIA must never need; their presence would be
        // a regression in the allow-list.
        for forbidden in [
            "execve", "execveat", "ptrace", "mount", "chmod", "fork", "vfork",
        ] {
            assert!(
                !ALLOWED_SYSCALLS.contains(&forbidden),
                "allow-list should not contain {forbidden}"
            );
        }
    }
}
