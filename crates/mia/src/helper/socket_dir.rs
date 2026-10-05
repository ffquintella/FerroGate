//! Group and mode of the helper socket's directory (feature F08).
//!
//! On macOS the default helper sockets live in `run/` under the system config
//! directory — `/Library/Application Support/FerroGate/run`, the directory the
//! daemon owns ([`crate::config::owned_helper_socket_dir`]). The package hands
//! the config directory to the `ferrogate-status` group; `run/` and the
//! sockets in it take the same group, so that group's members can reach the
//! helper API. Reaching it is not being trusted by it: the signed allowlist
//! still decides who may mint.
//!
//! macOS gives a new directory or socket the group of the directory it is
//! created in, so `run/` only came out right when it was created *after* the
//! config directory was handed to the group. A `run/` left by an older install
//! kept `wheel`, as did every socket later bound in it, because nothing
//! re-applied the group to an existing directory. The daemon now picks the
//! group itself ([`plan`]) and `HelperServer::bind` re-applies it, with mode
//! `0750`, on every start.
//!
//! Linux is unaffected: its socket directories are prepared as root before the
//! privilege drop (`hardening::prepare_runtime_paths`), and the hardened
//! daemon may not `chown` afterwards.

use std::path::Path;

/// Owner, group and permission bits of a directory, as `lstat(2)` reports
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirOwner {
    /// Owning uid.
    pub uid: u32,
    /// Owning gid.
    pub gid: u32,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
}

/// What `HelperServer::bind` does with the helper socket's directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketDirPlan {
    /// Group for the socket, and for its directory whenever the bind creates
    /// it or the daemon owns it. `None` ⇒ both keep the group they are
    /// created with.
    pub gid: Option<u32>,
    /// The directory is the daemon's own: re-apply mode `0750` and
    /// [`Self::gid`] on every bind, not only when the bind creates it.
    pub own_dir: bool,
}

/// Decide the helper socket's group and whether the daemon owns its directory.
///
/// - A socket outside `owned_dir` — any custom `helper.socket`, and every
///   socket on Linux and Windows, where `owned_dir` is `None` — keeps the
///   `configured` gid, if any, and a pre-existing directory is left as the
///   operator set it. This is the behaviour before the macOS default existed.
/// - A socket directly inside `owned_dir` takes the `configured` gid
///   (`helper.socket_gid` / `FERROGATE_HELPER_SOCKET_GID`) when one is set,
///   else the group of `owned_dir`'s parent — the system config directory —
///   as read by `stat_parent`. The directory is the daemon's, so its mode and
///   group are re-applied on every start.
///
/// The parent must be owned by root and writable by nobody else. Only root
/// can then have chosen its group, and nobody else can replace `run/` with a
/// symlink that the root daemon would `chmod`/`chown` through. When it is not,
/// or cannot be read, the socket is treated as outside `owned_dir`. The result
/// is never a wider group than the configuration and the root-owned config
/// directory grant (fail closed).
#[must_use]
pub fn plan_socket_dir(
    configured: Option<u32>,
    socket_path: &Path,
    owned_dir: Option<&Path>,
    stat_parent: impl FnOnce(&Path) -> Option<DirOwner>,
) -> SocketDirPlan {
    let unowned = SocketDirPlan {
        gid: configured,
        own_dir: false,
    };
    let Some(owned) = owned_dir.filter(|dir| in_dir(socket_path, dir)) else {
        return unowned;
    };
    match owned.parent().and_then(stat_parent) {
        Some(holder) if only_root_can_write(holder) => SocketDirPlan {
            gid: configured.or(Some(holder.gid)),
            own_dir: true,
        },
        _ => unowned,
    }
}

/// [`plan_socket_dir`] for this host — the platform's
/// [`owned_helper_socket_dir`](crate::config::owned_helper_socket_dir) and a
/// real `lstat` — with the decision logged.
#[must_use]
pub fn plan(configured: Option<u32>, socket_path: &Path) -> SocketDirPlan {
    let owned_dir = crate::config::owned_helper_socket_dir();
    let plan = plan_socket_dir(configured, socket_path, owned_dir.as_deref(), stat_dir);
    let Some(dir) = owned_dir.filter(|dir| in_dir(socket_path, dir)) else {
        return plan;
    };
    if plan.own_dir {
        tracing::info!(
            dir = %dir.display(),
            gid = ?plan.gid,
            source = if configured.is_some() { "helper.socket_gid" } else { "config directory" },
            "helper socket directory: re-applying mode 0750 and the socket group"
        );
    } else {
        tracing::warn!(
            dir = %dir.display(),
            "the directory holding the helper socket directory is not root-owned, is writable \
             by group or others, or cannot be read; the socket directory is left as it is and \
             the socket keeps the group it is created with unless helper.socket_gid is set — \
             restore root ownership and mode 0755 on the config directory"
        );
    }
    plan
}

/// Whether `socket_path` sits directly in `dir`.
fn in_dir(socket_path: &Path, dir: &Path) -> bool {
    socket_path.parent() == Some(dir)
}

/// Owned by root and not writable by group or others.
fn only_root_can_write(dir: DirOwner) -> bool {
    dir.uid == 0 && dir.mode & 0o022 == 0
}

/// `lstat` a directory; `None` if it is missing, unreadable or not a real
/// directory (a symlink is not followed).
#[cfg(unix)]
fn stat_dir(path: &Path) -> Option<DirOwner> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata(path).ok()?;
    meta.is_dir().then(|| DirOwner {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o7777,
    })
}

/// No Unix ownership to read on this platform.
#[cfg(not(unix))]
fn stat_dir(_path: &Path) -> Option<DirOwner> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "/Library/Application Support/FerroGate/run";
    const STATUS_GID: u32 = 501;

    /// The config directory as the macOS package leaves it:
    /// `root:ferrogate-status 0755`.
    fn config_dir() -> Option<DirOwner> {
        Some(DirOwner {
            uid: 0,
            gid: STATUS_GID,
            mode: 0o755,
        })
    }

    fn plan_with(
        configured: Option<u32>,
        socket: &str,
        owned: Option<&str>,
        holder: Option<DirOwner>,
    ) -> SocketDirPlan {
        plan_socket_dir(configured, Path::new(socket), owned.map(Path::new), |p| {
            assert_eq!(p, Path::new("/Library/Application Support/FerroGate"));
            holder
        })
    }

    #[test]
    fn unset_gid_defaults_to_the_config_directory_group() {
        for name in ["mia.sock", "mia-homolog.sock"] {
            let socket = format!("{RUN}/{name}");
            assert_eq!(
                plan_with(None, &socket, Some(RUN), config_dir()),
                SocketDirPlan {
                    gid: Some(STATUS_GID),
                    own_dir: true
                }
            );
        }
    }

    #[test]
    fn explicit_gid_wins_over_the_config_directory_group() {
        assert_eq!(
            plan_with(
                Some(777),
                &format!("{RUN}/mia.sock"),
                Some(RUN),
                config_dir()
            ),
            SocketDirPlan {
                gid: Some(777),
                own_dir: true
            }
        );
    }

    #[test]
    fn sockets_outside_the_owned_directory_keep_the_old_behaviour() {
        let never_stat = |configured, socket: &str, owned: Option<&str>| {
            plan_socket_dir(configured, Path::new(socket), owned.map(Path::new), |_| {
                panic!("a socket outside the owned directory must not stat anything")
            })
        };
        // A custom helper.socket on macOS, even one nested below run/.
        for socket in ["/tmp/mia.sock", "/var/run/ferrogate/mia.sock"] {
            assert_eq!(
                never_stat(None, socket, Some(RUN)),
                SocketDirPlan {
                    gid: None,
                    own_dir: false
                }
            );
        }
        assert_eq!(
            never_stat(Some(42), &format!("{RUN}/sub/mia.sock"), Some(RUN)),
            SocketDirPlan {
                gid: Some(42),
                own_dir: false
            }
        );
        // Linux / Windows: no owned directory, so the configured gid only.
        assert_eq!(
            never_stat(Some(555), "/run/ferrogate/mia.sock", None),
            SocketDirPlan {
                gid: Some(555),
                own_dir: false
            }
        );
        assert_eq!(
            never_stat(None, "/run/ferrogate/mia.sock", None),
            SocketDirPlan {
                gid: None,
                own_dir: false
            }
        );
    }

    #[test]
    fn an_untrusted_config_directory_is_never_adopted() {
        let socket = format!("{RUN}/mia.sock");
        let unowned = |gid| SocketDirPlan {
            gid,
            own_dir: false,
        };
        for holder in [
            // Not owned by root.
            Some(DirOwner {
                uid: 501,
                gid: STATUS_GID,
                mode: 0o755,
            }),
            // Group-writable: a member could swap run/ for a symlink.
            Some(DirOwner {
                uid: 0,
                gid: STATUS_GID,
                mode: 0o775,
            }),
            // World-writable.
            Some(DirOwner {
                uid: 0,
                gid: STATUS_GID,
                mode: 0o1777,
            }),
            // Missing, unreadable or a symlink.
            None,
        ] {
            assert_eq!(plan_with(None, &socket, Some(RUN), holder), unowned(None));
            // An explicit gid still applies to the socket, but the directory
            // is not re-owned through an untrusted parent.
            assert_eq!(
                plan_with(Some(9), &socket, Some(RUN), holder),
                unowned(Some(9))
            );
        }
    }

    #[test]
    fn a_wheel_config_directory_keeps_wheel() {
        // An install whose postinstall has not handed the config directory to
        // ferrogate-status yet: the default is wheel, which is no wider than
        // what the daemon created before.
        let holder = Some(DirOwner {
            uid: 0,
            gid: 0,
            mode: 0o755,
        });
        assert_eq!(
            plan_with(None, &format!("{RUN}/mia.sock"), Some(RUN), holder),
            SocketDirPlan {
                gid: Some(0),
                own_dir: true
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn stat_dir_reads_real_directories_and_skips_symlinks() {
        use std::os::unix::fs::MetadataExt as _;
        let base = std::env::temp_dir().join(format!("mia-sockdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let meta = std::fs::metadata(&base).unwrap();
        assert_eq!(
            stat_dir(&base),
            Some(DirOwner {
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode() & 0o7777,
            })
        );
        let link = base.join("link");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        assert_eq!(stat_dir(&link), None);
        assert_eq!(stat_dir(&base.join("absent")), None);
        let _ = std::fs::remove_dir_all(&base);
    }
}
