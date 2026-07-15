//! Linux implementation of the hardening primitives.
//!
//! All `unsafe` in the workspace's MIA path is confined here. Each wrapper does
//! one syscall, checks its return value, and maps failure to a typed
//! [`HardenError`]; nothing returns a partially-applied state.

use std::collections::{BTreeMap, HashSet};

use caps::{CapSet, Capability};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

use crate::{HardenError, HardenProfile, RunAs, SeccompMode, ALLOWED_SYSCALLS};

/// Apply the profile in dependency order (see the crate docs).
pub(crate) fn apply(profile: &HardenProfile) -> Result<(), HardenError> {
    if profile.mlock {
        mlock_all()?;
    }
    if profile.non_dumpable {
        set_non_dumpable()?;
    }
    if let Some(run_as) = profile.drop_to {
        drop_privileges(run_as)?;
        restrict_capabilities()?;
    }
    // `no_new_privs` is mandatory before installing a seccomp filter without
    // CAP_SYS_ADMIN, so force it on whenever seccomp is requested.
    if profile.no_new_privs || profile.seccomp.is_some() {
        set_no_new_privs()?;
    }
    if let Some(mode) = profile.seccomp {
        install_seccomp(mode)?;
    }
    Ok(())
}

fn last_os_error() -> String {
    std::io::Error::last_os_error().to_string()
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)` — lock current and future pages so key
/// material never reaches swap.
fn mlock_all() -> Result<(), HardenError> {
    // SAFETY: `mlockall` takes a flags int and has no memory-safety
    // preconditions; we check the return value.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HardenError::Mlock(last_os_error()))
    }
}

/// `prctl(PR_SET_DUMPABLE, 0)` — suppress core dumps and ptrace-by-default.
fn set_non_dumpable() -> Result<(), HardenError> {
    // SAFETY: prctl with this option ignores the remaining args.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HardenError::Prctl("PR_SET_DUMPABLE", last_os_error()))
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
fn set_no_new_privs() -> Result<(), HardenError> {
    // SAFETY: prctl with this option ignores the remaining args.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HardenError::Prctl("PR_SET_NO_NEW_PRIVS", last_os_error()))
    }
}

/// Drop the supplementary groups, then the gid, then the uid, keeping
/// capabilities across the uid change (`PR_SET_KEEPCAPS`) so the subsequent
/// [`restrict_capabilities`] can retain [`RETAINED_CAPS`].
fn drop_privileges(run_as: RunAs) -> Result<(), HardenError> {
    // Retain the permitted capability set across the setuid() that follows.
    // SAFETY: prctl with this option ignores the remaining args.
    let rc = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(HardenError::DropPrivileges(format!(
            "PR_SET_KEEPCAPS: {}",
            last_os_error()
        )));
    }

    // Drop all supplementary groups.
    // SAFETY: a zero-length setgroups with a null list clears the set.
    let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
    if rc != 0 {
        return Err(HardenError::DropPrivileges(format!(
            "setgroups: {}",
            last_os_error()
        )));
    }

    // gid before uid, so we still have the privilege to change the gid.
    // SAFETY: plain scalar syscall; return value checked.
    let rc = unsafe { libc::setgid(run_as.gid) };
    if rc != 0 {
        return Err(HardenError::DropPrivileges(format!(
            "setgid({}): {}",
            run_as.gid,
            last_os_error()
        )));
    }
    // SAFETY: plain scalar syscall; return value checked.
    let rc = unsafe { libc::setuid(run_as.uid) };
    if rc != 0 {
        return Err(HardenError::DropPrivileges(format!(
            "setuid({}): {}",
            run_as.uid,
            last_os_error()
        )));
    }

    // Defence in depth: confirm we cannot regain root.
    // SAFETY: getuid never fails.
    if unsafe { libc::setuid(0) } == 0 {
        return Err(HardenError::DropPrivileges(
            "regained uid 0 after drop".to_string(),
        ));
    }
    Ok(())
}

/// The capabilities the daemon retains after dropping privileges:
///
/// - `CAP_IPC_LOCK` — keep secret-bearing pages `mlock`'d out of swap.
/// - `CAP_SYS_PTRACE` — read a helper-API caller's `/proc/<pid>/exe` to hash and
///   authenticate it (see `mia::helper::auth`). Without it a non-root daemon
///   fails `ptrace_may_access` on any caller running under a different uid
///   (including root), so it could authenticate no one but itself. Note the
///   seccomp filter still **forbids the `ptrace` syscall** — this grants the
///   read-access check only, not active tracing/injection.
const RETAINED_CAPS: [Capability; 2] = [Capability::CAP_IPC_LOCK, Capability::CAP_SYS_PTRACE];

/// Reduce every capability set to exactly [`RETAINED_CAPS`]: drop everything else
/// from the bounding set, set effective/permitted to those, and clear the
/// inheritable and ambient sets.
fn restrict_capabilities() -> Result<(), HardenError> {
    let keep: HashSet<Capability> = RETAINED_CAPS.into_iter().collect();

    let cap_err = |e: caps::errors::CapsError| HardenError::Capabilities(e.to_string());

    // Dropping a capability from the bounding set (PR_CAPBSET_DROP) requires
    // CAP_SETPCAP in the caller's *effective* set. When [`drop_privileges`] ran
    // first, its setuid() away from root cleared the effective set — PR_SET_KEEPCAPS
    // preserves only the *permitted* set — so CAP_SETPCAP, though still permitted,
    // is no longer effective and the drops below would fail with EPERM. Re-raise
    // it (alongside the caps we mean to retain) before trimming the set.
    let mut working = keep.clone();
    working.insert(Capability::CAP_SETPCAP);
    caps::set(None, CapSet::Effective, &working).map_err(cap_err)?;

    // Drop everything except the retained caps from the bounding set so they can
    // never be re-acquired.
    let bounding = caps::read(None, CapSet::Bounding).map_err(cap_err)?;
    for cap in bounding {
        if !keep.contains(&cap) {
            caps::drop(None, CapSet::Bounding, cap).map_err(cap_err)?;
        }
    }

    // Collapse to exactly the retained caps, which also sheds the CAP_SETPCAP
    // raised just above. Lower effective before permitted: the kernel requires
    // the effective set to remain a subset of the permitted set at all times.
    caps::set(None, CapSet::Effective, &keep).map_err(cap_err)?;
    caps::set(None, CapSet::Permitted, &keep).map_err(cap_err)?;
    caps::set(None, CapSet::Inheritable, &HashSet::new()).map_err(cap_err)?;
    caps::clear(None, CapSet::Ambient).map_err(cap_err)?;
    Ok(())
}

/// The process's effective capabilities as sorted `CAP_*` names.
pub(crate) fn effective_capabilities() -> Result<Vec<String>, HardenError> {
    let set = caps::read(None, CapSet::Effective)
        .map_err(|e| HardenError::Capabilities(e.to_string()))?;
    let mut names: Vec<String> = set.iter().map(ToString::to_string).collect();
    names.sort();
    Ok(names)
}

/// Whether the effective UID is 0.
pub(crate) fn is_root() -> bool {
    // SAFETY: geteuid never fails and takes no arguments.
    unsafe { libc::geteuid() == 0 }
}

/// Resolve a user name to its UID/GID via `getpwnam_r`.
pub(crate) fn resolve_user(name: &str) -> Option<RunAs> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `passwd` is a plain-old-data struct; zeroing it is a valid
    // initial state for getpwnam_r to fill.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    // `char` signedness differs by arch (signed on x86_64, unsigned on aarch64),
    // so size the scratch buffer in `c_char` to match `getpwnam_r`'s signature
    // on every target.
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call; `buf` is
    // sized by `buf.len()`. On success `result` aliases `&pwd`.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(RunAs {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
    })
}

/// The seccompiler target architecture for this build, if supported.
fn target_arch() -> Option<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Some(TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Some(TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

/// Build (but do not install) the seccomp BPF program for `mode`. Split out so
/// tests can construct the program in the parent process before forking.
pub(crate) fn build_program(mode: SeccompMode) -> Result<BpfProgram, HardenError> {
    let arch = target_arch().ok_or_else(|| {
        HardenError::Seccomp("unsupported architecture for seccomp filter".to_string())
    })?;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for name in ALLOWED_SYSCALLS {
        // A name absent on this architecture is skipped, keeping the list
        // portable (e.g. legacy `poll` on aarch64).
        if let Some(nr) = syscall_nr(name) {
            rules.entry(nr).or_default();
        }
    }

    let mismatch = match mode {
        SeccompMode::Enforce => SeccompAction::KillProcess,
        SeccompMode::Audit => SeccompAction::Log,
    };
    let filter = SeccompFilter::new(rules, mismatch, SeccompAction::Allow, arch)
        .map_err(|e| HardenError::Seccomp(e.to_string()))?;
    BpfProgram::try_from(filter).map_err(|e| HardenError::Seccomp(e.to_string()))
}

/// Build and install the seccomp allow-list for `mode`.
fn install_seccomp(mode: SeccompMode) -> Result<(), HardenError> {
    let prog = build_program(mode)?;
    seccompiler::apply_filter(&prog).map_err(|e| HardenError::Seccomp(e.to_string()))
}

/// Resolve a syscall name to its number on this architecture, or `None` if the
/// name does not exist here. Every name in [`ALLOWED_SYSCALLS`] is covered for
/// x86_64 and aarch64.
#[allow(clippy::too_many_lines)] // a flat name→number table is clearest here.
fn syscall_nr(name: &str) -> Option<i64> {
    let nr: libc::c_long = match name {
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "readv" => libc::SYS_readv,
        "writev" => libc::SYS_writev,
        "pread64" => libc::SYS_pread64,
        "pwrite64" => libc::SYS_pwrite64,
        "close" => libc::SYS_close,
        "lseek" => libc::SYS_lseek,
        "fcntl" => libc::SYS_fcntl,
        "fsync" => libc::SYS_fsync,
        "fdatasync" => libc::SYS_fdatasync,
        "ftruncate" => libc::SYS_ftruncate,
        "openat" => libc::SYS_openat,
        "readlinkat" => libc::SYS_readlinkat,
        "unlinkat" => libc::SYS_unlinkat,
        "fchmodat" => libc::SYS_fchmodat,
        // `readlink`/`unlink`/`chmod` are legacy syscalls that arm64 never
        // implemented (it has only the `*at` forms), so the `libc::SYS_*`
        // constants do not exist there — gate them to x86_64. glibc's
        // `readlink`/`unlink`/`chmod` wrappers dispatch to `readlinkat`/
        // `unlinkat`/`fchmodat` on arm64, all allow-listed above, so the runtime
        // behaviour is preserved. `build_program` skips any name that resolves to
        // `None`.
        #[cfg(target_arch = "x86_64")]
        "readlink" => libc::SYS_readlink,
        #[cfg(target_arch = "x86_64")]
        "unlink" => libc::SYS_unlink,
        #[cfg(target_arch = "x86_64")]
        "chmod" => libc::SYS_chmod,
        // `mkdir` is x86_64-only; arm64 exposes only the `mkdirat` variant.
        #[cfg(target_arch = "x86_64")]
        "mkdir" => libc::SYS_mkdir,
        "mkdirat" => libc::SYS_mkdirat,
        "getdents64" => libc::SYS_getdents64,
        #[cfg(target_arch = "x86_64")]
        "fstat" => libc::SYS_fstat,
        "newfstatat" => libc::SYS_newfstatat,
        "statx" => libc::SYS_statx,
        "mmap" => libc::SYS_mmap,
        "munmap" => libc::SYS_munmap,
        "mprotect" => libc::SYS_mprotect,
        "madvise" => libc::SYS_madvise,
        "brk" => libc::SYS_brk,
        "mlockall" => libc::SYS_mlockall,
        "socket" => libc::SYS_socket,
        "socketpair" => libc::SYS_socketpair,
        "sendmmsg" => libc::SYS_sendmmsg,
        "connect" => libc::SYS_connect,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "accept4" => libc::SYS_accept4,
        "getsockname" => libc::SYS_getsockname,
        "getpeername" => libc::SYS_getpeername,
        "setsockopt" => libc::SYS_setsockopt,
        "getsockopt" => libc::SYS_getsockopt,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "shutdown" => libc::SYS_shutdown,
        "ioctl" => libc::SYS_ioctl,
        "epoll_create1" => libc::SYS_epoll_create1,
        "epoll_ctl" => libc::SYS_epoll_ctl,
        "epoll_pwait" => libc::SYS_epoll_pwait,
        // `epoll_wait`, `poll`, and `fstat` are legacy syscalls that arm64
        // never implemented (it has only the `*_pwait` / `*at` variants), so
        // the `libc::SYS_*` constants do not exist there — gate them to x86_64.
        // `build_program` skips any name that resolves to `None`.
        #[cfg(target_arch = "x86_64")]
        "epoll_wait" => libc::SYS_epoll_wait,
        "eventfd2" => libc::SYS_eventfd2,
        "futex" => libc::SYS_futex,
        "nanosleep" => libc::SYS_nanosleep,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "clock_gettime" => libc::SYS_clock_gettime,
        "gettimeofday" => libc::SYS_gettimeofday,
        "sched_yield" => libc::SYS_sched_yield,
        "sched_getaffinity" => libc::SYS_sched_getaffinity,
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "sigaltstack" => libc::SYS_sigaltstack,
        "clone" => libc::SYS_clone,
        "clone3" => libc::SYS_clone3,
        "set_robust_list" => libc::SYS_set_robust_list,
        "rseq" => libc::SYS_rseq,
        "membarrier" => libc::SYS_membarrier,
        #[cfg(target_arch = "x86_64")]
        "poll" => libc::SYS_poll,
        "ppoll" => libc::SYS_ppoll,
        "pipe2" => libc::SYS_pipe2,
        "dup3" => libc::SYS_dup3,
        "tgkill" => libc::SYS_tgkill,
        "prctl" => libc::SYS_prctl,
        "getpid" => libc::SYS_getpid,
        "gettid" => libc::SYS_gettid,
        "getuid" => libc::SYS_getuid,
        "geteuid" => libc::SYS_geteuid,
        "getgid" => libc::SYS_getgid,
        "getegid" => libc::SYS_getegid,
        "capget" => libc::SYS_capget,
        "getrandom" => libc::SYS_getrandom,
        "prlimit64" => libc::SYS_prlimit64,
        "uname" => libc::SYS_uname,
        "restart_syscall" => libc::SYS_restart_syscall,
        "exit" => libc::SYS_exit,
        "exit_group" => libc::SYS_exit_group,
        _ => return None,
    };
    Some(nr as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_allowlisted_name_resolves_on_this_arch() {
        // On the two architectures we target, every name must resolve — a typo
        // or a name missing from the table would silently shrink the allow-list
        // (and thus over-block at runtime). The exception is a handful of legacy
        // syscalls that exist only on x86_64 (arm64 kept only the `*at` /
        // `*_pwait` forms); `build_program` skips them where they don't resolve.
        const X86_64_ONLY: &[&str] =
            &["fstat", "poll", "epoll_wait", "mkdir", "readlink", "unlink", "chmod"];
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        for name in ALLOWED_SYSCALLS {
            if X86_64_ONLY.contains(name) && !cfg!(target_arch = "x86_64") {
                assert!(
                    syscall_nr(name).is_none(),
                    "{name} is expected to be x86_64-only but resolved on this arch"
                );
            } else {
                assert!(syscall_nr(name).is_some(), "unresolved syscall: {name}");
            }
        }
    }

    #[test]
    fn build_program_succeeds_for_both_modes() {
        // Building the BPF (without installing) must succeed on a supported
        // arch; this exercises the seccompiler integration without altering the
        // test process.
        if target_arch().is_some() {
            assert!(!build_program(SeccompMode::Enforce).unwrap().is_empty());
            assert!(!build_program(SeccompMode::Audit).unwrap().is_empty());
        }
    }

    #[test]
    fn unknown_syscall_name_resolves_to_none() {
        assert_eq!(syscall_nr("definitely_not_a_syscall"), None);
    }

    // The headline F12 acceptance test: a forbidden syscall under an enforcing
    // filter kills the process with SIGSYS. We build the BPF in the parent
    // (allocation-safe), fork, install + trip the filter in the child, and
    // assert the child died from SIGSYS. seccomp needs no privilege once
    // no_new_privs is set, so this runs in unprivileged CI.
    #[test]
    fn seccomp_enforce_kills_forbidden_syscall() {
        if target_arch().is_none() {
            return;
        }
        let prog = build_program(SeccompMode::Enforce).expect("build bpf");

        // SAFETY: fork() in a test; the child performs only async-signal-safe
        // syscalls (prctl, the seccomp install, one forbidden syscall, _exit)
        // and does not allocate, so other threads' locks are irrelevant.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", last_os_error());

        if pid == 0 {
            // Child.
            // SAFETY: prctl is async-signal-safe; args beyond the option are 0.
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            }
            // Install the enforcing filter. After this, `getcwd` (absent from
            // the allow-list) must be fatal.
            let _ = seccompiler::apply_filter(&prog);
            let mut buf = [0_u8; 64];
            // SAFETY: getcwd writes up to buf.len() bytes into buf.
            unsafe {
                libc::syscall(libc::SYS_getcwd, buf.as_mut_ptr(), buf.len());
                // Should be unreachable; if the kill failed, exit 0 so the
                // parent's assertion fails loudly.
                libc::_exit(0);
            }
        } else {
            // Parent: reap and inspect.
            let mut status: libc::c_int = 0;
            // SAFETY: standard waitpid on our own child.
            let w = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(w, pid, "waitpid failed: {}", last_os_error());
            assert!(
                libc::WIFSIGNALED(status),
                "child should have been killed by a signal, status={status:#x}"
            );
            assert_eq!(
                libc::WTERMSIG(status),
                libc::SIGSYS,
                "child should die from SIGSYS (seccomp), got signal {}",
                libc::WTERMSIG(status)
            );
        }
    }

    // Regression for the crash-loop observed in production: after the setuid()
    // in `drop_privileges` clears the effective set (KEEPCAPS keeps only the
    // permitted set), `restrict_capabilities` must re-raise CAP_SETPCAP before
    // PR_CAPBSET_DROP — otherwise the bounding-set trim fails with EPERM
    // ("PR_CAPBSET_DROP failure: Operation not permitted"). We reproduce that
    // exact precondition (effective emptied, permitted intact) and assert the
    // trim now succeeds, leaving effective == RETAINED_CAPS.
    //
    // Needs root (only a privileged process holds CAP_SETPCAP in its permitted
    // set); skipped otherwise, like the swtpm integration tests.
    #[test]
    fn restrict_capabilities_recovers_setpcap_after_cleared_effective() {
        if !is_root() {
            eprintln!("not root; skipping capability-restriction regression test");
            return;
        }
        // The bounding-set drop is irreversible for the process, so isolate it
        // in a forked child rather than poisoning sibling tests.
        //
        // SAFETY: fork() in a test. The child only reads/writes its own
        // capability sets and then _exit()s; it does not touch shared test
        // state. (As with `seccomp_enforce_kills_forbidden_syscall`, this forks
        // from a possibly-threaded harness; the child avoids other threads'
        // state entirely.)
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", last_os_error());

        if pid == 0 {
            // Child: empty the effective set (mimics the post-setuid state),
            // then run the real restriction and verify the final effective set
            // is exactly the retained caps.
            let empty: HashSet<Capability> = HashSet::new();
            let want: HashSet<Capability> = RETAINED_CAPS.into_iter().collect();
            let ok = caps::set(None, CapSet::Effective, &empty).is_ok()
                && restrict_capabilities().is_ok()
                && caps::read(None, CapSet::Effective).is_ok_and(|e| e == want);
            // SAFETY: _exit is async-signal-safe.
            unsafe { libc::_exit(i32::from(!ok)) };
        } else {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid on our own child.
            let w = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(w, pid, "waitpid failed: {}", last_os_error());
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "restrict_capabilities must recover CAP_SETPCAP into the effective \
                 set before PR_CAPBSET_DROP; child status={status:#x}"
            );
        }
    }
}
