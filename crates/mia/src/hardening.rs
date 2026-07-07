//! MIA process-hardening orchestration (feature F12).
//!
//! [`harden`] applies the defence-in-depth profile from `docs/mia.md`
//! §"Hardening profile" at startup, **before** any TPM or network I/O: it
//! refuses to start unless IMA appraisal is kernel-enforced, then drives the
//! syscall-level steps in `ferro_harden` (mlockall, no-dumpable, drop to
//! `_ferrogate` retaining only `CAP_IPC_LOCK`, no-new-privs, seccomp allow-list).
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

#[cfg(target_os = "linux")]
pub use linux::{harden, ima_enforced, prepare_runtime_paths};

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{bail, Context as _};
    use ferro_harden::{HardenProfile, RunAs, SeccompMode};

    use super::{ima_cmdline_enforced, SERVICE_USER};

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

    /// Prepare, as root, the directories the daemon will write to *after* it
    /// drops to the service user: create each one (mode `0750`) if missing and
    /// hand ownership to the privilege-drop target. Must be called before
    /// [`harden`]; the two resolve the same target via [`resolve_run_as`].
    ///
    /// This is what lets a MIA that starts as root, then drops to `_ferrogate`,
    /// still bind its helper socket under `/run/ferrogate` and persist its key
    /// and seed under the state directory — both of which live in root-owned
    /// trees the unprivileged process could not otherwise create files in.
    ///
    /// A no-op when hardening is skipped or we are not root (no drop follows, so
    /// ownership is already correct). `mia` stays `#![forbid(unsafe_code)]`:
    /// `std::os::unix::fs::chown` is a safe wrapper over the syscall.
    pub fn prepare_runtime_paths(dirs: &[std::path::PathBuf]) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        if env_flag_set("FERROGATE_SKIP_HARDENING") || !ferro_harden::is_root() {
            return Ok(());
        }
        let run_as = resolve_run_as()?;
        for dir in dirs {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create runtime directory {}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
                .with_context(|| format!("set mode on {}", dir.display()))?;
            std::os::unix::fs::chown(dir, Some(run_as.uid), Some(run_as.gid))
                .with_context(|| format!("chown {} to the service user", dir.display()))?;
            tracing::info!(
                dir = %dir.display(),
                uid = run_as.uid,
                gid = run_as.gid,
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

        // Confirm the post-drop capability set is exactly {CAP_IPC_LOCK} when we
        // dropped privileges.
        if drop_to.is_some() {
            match ferro_harden::effective_capabilities() {
                Ok(caps) => {
                    if caps != ["CAP_IPC_LOCK"] {
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
}
