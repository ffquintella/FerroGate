//! MIA process-hardening orchestration (feature F12).
//!
//! [`harden`] applies the defence-in-depth profile from `docs/mia.md`
//! §"Hardening profile" at startup, **before** any TPM or network I/O: it
//! refuses to start unless IMA appraisal is kernel-enforced, then drives the
//! syscall-level steps in `ferro_harden` (mlockall, no-dumpable, drop to
//! `_ferrogate` retaining `CAP_IPC_LOCK` + `CAP_SYS_PTRACE`, no-new-privs,
//! seccomp allow-list).
//!
//! `mia` is `#![forbid(unsafe_code)]`; every privileged syscall lives in the
//! `ferro-harden` crate. The pieces that need no FFI — the IMA cmdline parser
//! and the environment-driven policy — live here so they can be unit-tested on
//! any host.
//!
//! ## Environment overrides
//!
//! - `FERROGATE_SKIP_HARDENING=1` — **dev only.** Skip the whole profile and
//!   log a loud warning. Never set this in production.
//! - `FERROGATE_REQUIRE_IMA=0` — do not require enforced IMA (dev/CI). Default
//!   is to require it and fail closed.
//! - `FERROGATE_SECCOMP=enforce|audit|off` — seccomp mode (default `enforce`).
//!   `audit` logs violations instead of killing — used to discover allow-list
//!   drift before rollout.
//! - `FERROGATE_RUN_AS_UID` / `FERROGATE_RUN_AS_GID` — drop to these instead of
//!   resolving the `_ferrogate` user.
//! - `FERROGATE_CMDLINE_PATH` — read the kernel cmdline from here instead of
//!   `/proc/cmdline` (testing).

/// The kernel-cmdline token that signals enforced IMA appraisal.
const IMA_ENFORCE_KEY: &str = "ima_appraise";

/// The dedicated service account the MIA drops to.
pub const SERVICE_USER: &str = "_ferrogate";

/// Whether the kernel command line requests **enforced** IMA appraisal.
///
/// Looks for an `ima_appraise=enforce` token (also accepting `enforce-evm`).
/// Pure and platform-independent so it can be unit-tested anywhere; the Linux
/// reader [`ima_enforced`] feeds it the real `/proc/cmdline`.
#[must_use]
pub fn ima_cmdline_enforced(cmdline: &str) -> bool {
    cmdline.split_whitespace().any(|tok| {
        tok.split_once('=')
            .is_some_and(|(k, v)| k == IMA_ENFORCE_KEY && v.starts_with("enforce"))
    })
}

/// A directory the daemon writes to after it drops privileges, prepared as
/// root by `prepare_runtime_paths` (Linux).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDir {
    /// The directory.
    pub path: std::path::PathBuf,
    /// For a helper-socket directory, the gid the sockets inside must carry
    /// (`helper.socket_gid`). The directory is then group-owned by it with the
    /// setgid bit set (`02750`), so a socket the unprivileged daemon binds
    /// there inherits the group from the directory — no `chown` after the
    /// drop, which the seccomp allow-list forbids (it would kill the daemon
    /// with `SIGSYS`). `None` ⇒ the service user's own group, mode `0750`.
    pub socket_gid: Option<u32>,
}

/// Plan the post-drop runtime directories: `state_dir` plus the parent of every
/// helper socket, each listed once.
///
/// `sockets` pairs each served helper socket with its `helper.socket_gid`.
/// Environments whose sockets share a directory share its group; when they
/// disagree the first gid wins and the conflict is logged — the later
/// environment's bind then needs a `chown` the hardened daemon cannot make, so
/// give such environments distinct socket directories (or one gid). The state
/// directory (machine key, SVID seed) is never handed to a socket group: a
/// socket placed there keeps the service user's group.
#[must_use]
pub fn plan_runtime_dirs(
    state_dir: std::path::PathBuf,
    sockets: impl IntoIterator<Item = (std::path::PathBuf, Option<u32>)>,
) -> Vec<RuntimeDir> {
    let mut dirs = vec![RuntimeDir {
        path: state_dir,
        socket_gid: None,
    }];
    for (socket, gid) in sockets {
        let Some(parent) = socket.parent().filter(|p| !p.as_os_str().is_empty()) else {
            continue;
        };
        if parent == dirs[0].path {
            if gid.is_some() {
                tracing::warn!(
                    dir = %parent.display(),
                    "a helper socket in the state directory cannot take helper.socket_gid; \
                     the state directory stays private to the service user — move the socket"
                );
            }
            continue;
        }
        match dirs.iter_mut().find(|d| d.path == parent) {
            None => dirs.push(RuntimeDir {
                path: parent.to_path_buf(),
                socket_gid: gid,
            }),
            Some(dir) => match (dir.socket_gid, gid) {
                (None, Some(_)) => dir.socket_gid = gid,
                (Some(have), Some(want)) if have != want => tracing::warn!(
                    dir = %dir.path.display(), kept = have, ignored = want,
                    "helper sockets sharing a directory ask for different socket_gid \
                     values; the directory keeps the first"
                ),
                _ => {}
            },
        }
    }
    dirs
}

/// Create `dir` if needed and hand it to `uid:gid` — mode `02750` (setgid, so
/// new entries inherit `gid`) when `setgid`, else `0750`. Ownership is set
/// before the mode so the setgid bit is applied last.
#[cfg(unix)]
pub fn hand_over_dir(
    dir: &std::path::Path,
    uid: u32,
    gid: u32,
    setgid: bool,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir)?;
    std::os::unix::fs::chown(dir, Some(uid), Some(gid))?;
    let mode = if setgid { 0o2750 } else { 0o750 };
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
}

#[cfg(target_os = "linux")]
pub use linux::{harden, ima_enforced, prepare_runtime_paths, state_owner};

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{bail, Context as _};
    use ferro_harden::{HardenProfile, RunAs, SeccompMode};

    use super::{hand_over_dir, ima_cmdline_enforced, RuntimeDir, SERVICE_USER};

    /// Default path to the kernel command line.
    const DEFAULT_CMDLINE: &str = "/proc/cmdline";

    fn env_flag_set(key: &str) -> bool {
        std::env::var(key).is_ok_and(|v| v == "1")
    }

    /// Whether enforced IMA appraisal is active, per the kernel command line.
    /// The path can be overridden with `FERROGATE_CMDLINE_PATH` for testing.
    #[must_use]
    pub fn ima_enforced() -> bool {
        let path =
            std::env::var("FERROGATE_CMDLINE_PATH").unwrap_or_else(|_| DEFAULT_CMDLINE.to_string());
        match std::fs::read_to_string(&path) {
            Ok(cmdline) => ima_cmdline_enforced(&cmdline),
            // Fail closed: if we cannot read the cmdline, treat IMA as not
            // enforced.
            Err(e) => {
                tracing::warn!(error = %e, path, "could not read kernel cmdline for IMA check");
                false
            }
        }
    }

    /// Resolve the UID/GID to drop to: an explicit `FERROGATE_RUN_AS_UID/GID`
    /// override, otherwise the `_ferrogate` system user.
    fn resolve_run_as() -> anyhow::Result<RunAs> {
        if let (Ok(uid), Ok(gid)) = (
            std::env::var("FERROGATE_RUN_AS_UID"),
            std::env::var("FERROGATE_RUN_AS_GID"),
        ) {
            let uid = uid
                .parse()
                .context("FERROGATE_RUN_AS_UID is not a valid uid")?;
            let gid = gid
                .parse()
                .context("FERROGATE_RUN_AS_GID is not a valid gid")?;
            return Ok(RunAs { uid, gid });
        }
        ferro_harden::resolve_user(SERVICE_USER).with_context(|| {
            format!(
                "service user {SERVICE_USER} not found; create it or set FERROGATE_RUN_AS_UID/GID"
            )
        })
    }

    /// The `(uid, gid)` that files created for the daemon *before* the
    /// privilege drop must be handed to — e.g. a machine key migrated into the
    /// state directory ([`crate::machine_key::migrate_legacy_files`]) — or
    /// `None` when no drop follows (hardening skipped, or not root), in which
    /// case the creating process already is the right owner. Resolves the same
    /// target as [`prepare_runtime_paths`] and [`harden`].
    pub fn state_owner() -> anyhow::Result<Option<(u32, u32)>> {
        if env_flag_set("FERROGATE_SKIP_HARDENING") || !ferro_harden::is_root() {
            return Ok(None);
        }
        let run_as = resolve_run_as()?;
        Ok(Some((run_as.uid, run_as.gid)))
    }

    /// Prepare, as root, the directories the daemon will write to *after* it
    /// drops to the service user: create each one if missing and hand it to the
    /// privilege-drop target — `uid:gid 0750`, or, for a helper-socket
    /// directory with a [`RuntimeDir::socket_gid`], `uid:socket_gid 02750` so
    /// the sockets bound there after the drop inherit that group without a
    /// (seccomp-forbidden) `chown`. Must be called before [`harden`]; the two
    /// resolve the same target via [`resolve_run_as`].
    ///
    /// This is what lets a MIA that starts as root, then drops to `_ferrogate`,
    /// still bind its helper socket under `/run/ferrogate` and persist its key
    /// and seed under the state directory — both of which live in root-owned
    /// trees the unprivileged process could not otherwise create files in.
    ///
    /// A no-op when hardening is skipped or we are not root (no drop follows, so
    /// ownership is already correct). `mia` stays `#![forbid(unsafe_code)]`:
    /// `std::os::unix::fs::chown` is a safe wrapper over the syscall.
    pub fn prepare_runtime_paths(dirs: &[RuntimeDir]) -> anyhow::Result<()> {
        if env_flag_set("FERROGATE_SKIP_HARDENING") || !ferro_harden::is_root() {
            return Ok(());
        }
        let run_as = resolve_run_as()?;
        for dir in dirs {
            let gid = dir.socket_gid.unwrap_or(run_as.gid);
            hand_over_dir(&dir.path, run_as.uid, gid, dir.socket_gid.is_some()).with_context(
                || {
                    format!(
                        "hand runtime directory {} to the service user",
                        dir.path.display()
                    )
                },
            )?;
            tracing::info!(
                dir = %dir.path.display(),
                uid = run_as.uid,
                gid,
                setgid = dir.socket_gid.is_some(),
                "handed runtime directory to the privilege-drop user"
            );
        }
        Ok(())
    }

    /// The configured seccomp mode, or `None` to skip seccomp
    /// (`FERROGATE_SECCOMP=off`). Defaults to enforcing.
    fn seccomp_mode() -> anyhow::Result<Option<SeccompMode>> {
        match std::env::var("FERROGATE_SECCOMP") {
            Ok(s) if s.eq_ignore_ascii_case("off") => Ok(None),
            Ok(s) => {
                Ok(Some(SeccompMode::parse(&s).with_context(|| {
                    format!("invalid FERROGATE_SECCOMP value: {s}")
                })?))
            }
            Err(_) => Ok(Some(SeccompMode::Enforce)),
        }
    }

    /// Apply the full hardening profile. Fatal on any failure — the caller must
    /// exit non-zero rather than serve in a weaker state than configured.
    pub fn harden() -> anyhow::Result<()> {
        if env_flag_set("FERROGATE_SKIP_HARDENING") {
            tracing::warn!(
                "FERROGATE_SKIP_HARDENING=1 set; process hardening DISABLED (development only)"
            );
            return Ok(());
        }

        // 1. IMA enforcement — refuse to start unless the kernel enforces
        //    measured-binary appraisal (fail closed).
        let require_ima = std::env::var("FERROGATE_REQUIRE_IMA").map_or(true, |v| v != "0");
        if require_ima {
            if !ima_enforced() {
                bail!(
                    "IMA appraisal is not enforced (kernel cmdline lacks `ima_appraise=enforce`); \
                     refusing to start. Set FERROGATE_REQUIRE_IMA=0 only for development."
                );
            }
            tracing::info!("IMA enforcement confirmed");
        } else {
            tracing::warn!("FERROGATE_REQUIRE_IMA=0 set; IMA enforcement NOT required (dev only)");
        }

        // 2. Decide the privilege-drop target. Only meaningful when started as
        //    root; otherwise we cannot setuid and skip that step.
        let drop_to = if ferro_harden::is_root() {
            Some(resolve_run_as()?)
        } else {
            tracing::warn!(
                "not running as root; skipping privilege drop and capability restriction"
            );
            None
        };

        let seccomp = seccomp_mode()?;

        let profile = HardenProfile {
            mlock: true,
            non_dumpable: true,
            no_new_privs: true,
            drop_to,
            seccomp,
        };

        ferro_harden::apply(&profile).context("applying hardening profile")?;

        // Confirm the post-drop capability set is exactly the retained pair
        // (CAP_IPC_LOCK for mlock'd memory; CAP_SYS_PTRACE so the non-root daemon
        // can read a helper caller's /proc/<pid>/exe to authenticate it — the
        // `ptrace` syscall itself stays seccomp-blocked). `effective_capabilities`
        // returns the names sorted.
        if drop_to.is_some() {
            match ferro_harden::effective_capabilities() {
                Ok(caps) => {
                    if caps != ["CAP_IPC_LOCK", "CAP_SYS_PTRACE"] {
                        bail!("unexpected effective capabilities after drop: {caps:?}");
                    }
                    tracing::info!(?caps, "capabilities reduced");
                }
                Err(e) => tracing::warn!(error = %e, "could not read effective capabilities"),
            }
        }

        tracing::info!(
            seccomp = ?seccomp,
            dropped = drop_to.is_some(),
            "process hardening applied"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforced_cmdline_is_detected() {
        assert!(ima_cmdline_enforced(
            "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ima_appraise=enforce ima_policy=appraise_tcb"
        ));
        assert!(ima_cmdline_enforced("ima_appraise=enforce-evm quiet"));
        assert!(ima_cmdline_enforced("ima_appraise=enforce"));
    }

    #[test]
    fn non_enforced_cmdline_is_rejected() {
        assert!(!ima_cmdline_enforced(
            "BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet"
        ));
        assert!(!ima_cmdline_enforced("ima_appraise=log")); // measuring, not enforcing
        assert!(!ima_cmdline_enforced("ima_appraise=fix")); // fix mode is not enforcement
        assert!(!ima_cmdline_enforced(""));
        // A substring that merely contains the value must not match.
        assert!(!ima_cmdline_enforced("xima_appraise=enforce"));
        assert!(!ima_cmdline_enforced("not_ima_appraise=enforce"));
    }

    #[test]
    fn runtime_dir_plan_dedups_and_carries_the_socket_group() {
        use std::path::PathBuf;
        let state = PathBuf::from("/var/lib/ferrogate");
        let plan = plan_runtime_dirs(
            state.clone(),
            [
                // Default env with no gid, then a named env asking for one:
                // the shared /run/ferrogate takes the gid.
                (PathBuf::from("/run/ferrogate/mia.sock"), None),
                (PathBuf::from("/run/ferrogate/mia-qa.sock"), Some(555)),
                // A conflicting gid for the same directory: the first wins.
                (PathBuf::from("/run/ferrogate/mia-prod.sock"), Some(777)),
                // Its own directory, its own gid.
                (PathBuf::from("/srv/sock/mia-x.sock"), Some(42)),
                // The state directory never takes a socket group.
                (state.join("mia-odd.sock"), Some(9)),
            ],
        );
        assert_eq!(
            plan,
            vec![
                RuntimeDir {
                    path: state,
                    socket_gid: None
                },
                RuntimeDir {
                    path: PathBuf::from("/run/ferrogate"),
                    socket_gid: Some(555)
                },
                RuntimeDir {
                    path: PathBuf::from("/srv/sock"),
                    socket_gid: Some(42)
                },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn hand_over_dir_sets_owner_then_setgid_mode() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let base = std::env::temp_dir().join(format!("mia-handover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("run");
        // Our own uid/gid: a chown any user may make, so this runs unprivileged.
        let meta = {
            std::fs::create_dir_all(&base).unwrap();
            std::fs::metadata(&base).unwrap()
        };
        hand_over_dir(&dir, meta.uid(), meta.gid(), true).unwrap();
        let got = std::fs::metadata(&dir).unwrap();
        assert_eq!(got.permissions().mode() & 0o7777, 0o2750);
        assert_eq!(got.gid(), meta.gid());
        // Without a socket group: plain 0750, and re-running is idempotent.
        hand_over_dir(&dir, meta.uid(), meta.gid(), false).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
