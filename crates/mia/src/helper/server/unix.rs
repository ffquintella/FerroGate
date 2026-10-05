//! Unix Domain Socket transport for the helper API.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use ferro_audit::AuditEvent;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Semaphore};

use super::{
    serve_connection, AllowlistReloader, Clock, HelperServerConfig, MinterReloader, ServerError,
    Shared,
};
use crate::helper::allowlist::Allowlist;
use crate::helper::auth::{AuthError, CallerAuth, PeerCred};
use crate::helper::crl::CrlCache;
use crate::helper::token::ChildTokenMinter;

/// The helper-API server, backed by a Unix Domain Socket.
pub struct HelperServer<A: CallerAuth> {
    listener: UnixListener,
    config: HelperServerConfig,
    shared: Arc<Shared<A>>,
}

impl<A: CallerAuth> HelperServer<A> {
    /// Bind the socket with the configured permissions and prepare to serve.
    ///
    /// The socket's directory is prepared first (`prepare_socket_dir`). A
    /// stale socket from a previous run at `socket_path` is then removed; any
    /// other kind of file there is an error, never deleted (a mistyped path
    /// must not unlink data). The socket is created, then its mode (and
    /// optionally its group owner) is set before any client can connect.
    ///
    /// The group is only `chown`ed when the socket did not already get it from
    /// its directory: on Linux the hardened daemon binds after dropping
    /// privileges, inside a runtime directory prepared setgid to `socket_gid`
    /// (`hardening::prepare_runtime_paths`), and its seccomp allow-list has no
    /// `chown` — calling it there would kill the process. On macOS (no
    /// seccomp, root daemon) a new socket takes its directory's group, which
    /// `prepare_socket_dir` has just set.
    #[allow(clippy::too_many_arguments)] // each handle is a distinct collaborator.
    pub fn bind(
        config: HelperServerConfig,
        auth: A,
        minter: Option<ChildTokenMinter>,
        allowlist: Option<Allowlist>,
        crl: Arc<CrlCache>,
        audit_tx: mpsc::Sender<AuditEvent>,
        clock: Clock,
    ) -> Result<Self, ServerError> {
        if let Some(parent) = config
            .socket_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            prepare_socket_dir(parent, config.socket_gid, config.own_socket_dir)?;
        }
        remove_stale_socket(&config.socket_path)?;
        let listener = UnixListener::bind(&config.socket_path)?;

        let perms = std::fs::Permissions::from_mode(config.socket_mode);
        std::fs::set_permissions(&config.socket_path, perms)?;
        if let Some(gid) = config.socket_gid {
            ensure_gid(&config.socket_path, gid)?;
        }

        Ok(Self {
            listener,
            config,
            shared: Arc::new(Shared::new(auth, minter, allowlist, crl, audit_tx, clock)),
        })
    }

    /// Replace the live allowlist (e.g. after a signed refresh from CMIS).
    pub async fn set_allowlist(&self, allowlist: Option<Allowlist>) {
        self.shared.set_allowlist(allowlist).await;
    }

    /// A clonable handle to swap the live allowlist after serving has started
    /// (used by the SIGHUP reload task).
    #[must_use]
    pub fn allowlist_reloader(&self) -> AllowlistReloader<A> {
        AllowlistReloader {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A clonable handle to switch minting on after serving has started (used by
    /// the background re-attestation task when CMIS was unreachable at startup).
    #[must_use]
    pub fn minter_reloader(&self) -> MinterReloader<A> {
        MinterReloader {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A handle to the observed-caller ledger, for the allowlist-propose task.
    #[must_use]
    pub fn ledger(&self) -> crate::helper::ledger::CallerLedger {
        self.shared.ledger.clone()
    }

    /// `SHA-384` of the daemon's own executable (the self-trust digest), for the
    /// allowlist-propose task's self-registration entry. `None` if the binary
    /// could not be read at startup.
    #[must_use]
    pub fn self_sha(&self) -> Option<[u8; 48]> {
        self.shared.self_sha
    }

    /// The bound socket path (for diagnostics / tests).
    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.config.socket_path
    }

    /// Serve until `shutdown` resolves. Connections already accepted are not
    /// forcibly cancelled, but no new connections are accepted afterwards.
    pub async fn serve_with_shutdown<F>(self, shutdown: F)
    where
        F: std::future::Future<Output = ()>,
    {
        let sem = Arc::new(Semaphore::new(self.config.max_concurrent));
        let read_timeout = self.config.read_timeout;
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let Ok((stream, _addr)) = accepted else { continue };
                    let shared = Arc::clone(&self.shared);
                    let sem = Arc::clone(&sem);
                    tokio::spawn(async move {
                        // Hold a permit for the connection's lifetime. The read
                        // deadline bounds how long a slow client can hold it.
                        let Ok(_permit) = sem.acquire().await else { return };
                        // SO_PEERCRED is a cheap, non-blocking syscall.
                        let cred = stream
                            .peer_cred()
                            .map(|u| PeerCred {
                                pid: u.pid().and_then(|p| u32::try_from(p).ok()),
                                uid: u.uid(),
                                gid: u.gid(),
                            })
                            .map_err(|_| AuthError::PeerCredUnavailable);
                        serve_connection(&shared, stream, cred, read_timeout).await;
                    });
                }
            }
        }
    }
}

/// Make sure the socket's directory `dir` exists and peers that may open the
/// socket may also reach it.
///
/// A missing directory is created. Creating it also guards against one wiped
/// out of band (e.g. under the boot-cleared `/var/run` tmpfs): without it
/// `bind` fails with ENOENT and the daemon crash-loops under the supervisor,
/// hiding the real cause behind the socket's apparent absence.
///
/// A directory created here, or the daemon's own directory (`own`, macOS
/// `…/FerroGate/run`), gets mode `0750` and group `gid`; the latter on every
/// start, so a directory an older release left with the wrong group (a `run/`
/// created before the config directory was handed to `ferrogate-status` kept
/// `wheel`) is repaired. The daemon's own directory must be a real directory,
/// never a symlink the root daemon would `chmod`/`chown` through. Any other
/// pre-existing directory (a shared system dir like `/tmp`) is left as the
/// operator set it.
fn prepare_socket_dir(
    dir: &std::path::Path,
    gid: Option<u32>,
    own: bool,
) -> Result<(), ServerError> {
    let created = !dir.exists();
    if created {
        std::fs::create_dir_all(dir)?;
    } else if !own {
        return Ok(());
    }
    if own && !std::fs::symlink_metadata(dir)?.is_dir() {
        return Err(ServerError::Socket(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} is not a directory; refusing to take it over as the helper socket directory",
                dir.display()
            ),
        )));
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))?;
    if let Some(gid) = gid {
        ensure_gid(dir, gid)?;
    }
    Ok(())
}

/// Remove a stale socket left at `path` by a previous run. Anything that is not
/// a socket (a regular file, a directory, a symlink — never followed) is
/// refused rather than deleted, so a misconfigured `helper.socket` cannot make
/// the daemon unlink arbitrary data.
fn remove_stale_socket(path: &std::path::Path) -> Result<(), ServerError> {
    use std::os::unix::fs::FileTypeExt as _;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(ServerError::Socket(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                ),
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(ServerError::Socket(e)),
    }
    Ok(())
}

/// Give `path` the group `gid`, issuing `chown` only when it does not already
/// carry it (e.g. inherited from a setgid directory). A `stat` is always
/// permitted by the hardened seccomp profile; a `chown` is not.
fn ensure_gid(path: &std::path::Path, gid: u32) -> Result<(), ServerError> {
    use std::os::unix::fs::MetadataExt as _;
    if std::fs::metadata(path)?.gid() != gid {
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mia-uds-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn stale_sockets_are_replaced_other_files_are_not() {
        let dir = scratch("stale");
        // Absent: nothing to do.
        remove_stale_socket(&dir.join("absent.sock")).unwrap();
        // A socket from a previous run is removed.
        let sock = dir.join("old.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        drop(listener);
        remove_stale_socket(&sock).unwrap();
        assert!(!sock.exists());
        // A regular file is refused and left intact.
        let file = dir.join("data.sock");
        std::fs::write(&file, b"keep me").unwrap();
        let err = remove_stale_socket(&file).unwrap_err();
        assert!(err.to_string().contains("not a socket"), "{err}");
        assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
        // A symlink is refused, and its target untouched.
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(remove_stale_socket(&link).is_err());
        assert!(file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn socket_dir_is_reowned_only_when_created_or_owned() {
        use std::os::unix::fs::MetadataExt as _;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
        let dir = scratch("sockdir");
        // Our own group: a chown any user may make, so this runs unprivileged.
        let gid = std::fs::metadata(&dir).unwrap().gid();

        // A missing directory is created 0750 with the socket's group.
        let created = dir.join("new/run");
        prepare_socket_dir(&created, Some(gid), false).unwrap();
        assert_eq!(mode(&created), 0o750);
        assert_eq!(std::fs::metadata(&created).unwrap().gid(), gid);

        // A pre-existing directory the daemon does not own is left alone.
        let shared = dir.join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_socket_dir(&shared, Some(gid), false).unwrap();
        assert_eq!(mode(&shared), 0o755);

        // The daemon's own directory is repaired on every start, e.g. a run/
        // an older release left with another mode.
        let own = dir.join("run");
        std::fs::create_dir(&own).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_socket_dir(&own, Some(gid), true).unwrap();
        assert_eq!(mode(&own), 0o750);
        assert_eq!(std::fs::metadata(&own).unwrap().gid(), gid);
        // Idempotent, and fine without a group to apply.
        prepare_socket_dir(&own, None, true).unwrap();
        assert_eq!(mode(&own), 0o750);

        // A symlink in its place is refused and its target left untouched.
        let link = dir.join("link-run");
        std::os::unix::fs::symlink(&shared, &link).unwrap();
        let err = prepare_socket_dir(&link, Some(gid), true).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
        assert_eq!(mode(&shared), 0o755);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_gid_skips_chown_when_the_group_already_matches() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = scratch("gid");
        let file = dir.join("f");
        std::fs::write(&file, b"").unwrap();
        let gid = std::fs::metadata(&file).unwrap().gid();
        // Already the right group ⇒ Ok without a chown (works for any user).
        ensure_gid(&file, gid).unwrap();
        assert_eq!(std::fs::metadata(&file).unwrap().gid(), gid);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
