//! T214: a local peer outside the status group cannot reach the status socket.
//!
//! Needs root, to chown the socket and to run probes under other uids; skips
//! without it. Run: `cargo test -p mia --test status_group_peer --no-run`,
//! then the printed binary under `sudo` with `--nocapture`.

#![cfg(unix)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(not(target_os = "macos"))]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use mia::status::{StatusHandle, StatusRegistry, DEFAULT_ENVIRONMENT_LABEL};
use mia::status_server::{prepare, serve, StatusEndpointConfig, StatusService};
use mia_status_proto::{read_frame, write_frame, StatusReq, StatusRequest, StatusResponse};

/// A gid no account on the host belongs to, standing for the status group.
const STATUS_GID: u32 = 54_321;
#[cfg(not(target_os = "macos"))]
const PROBE_UID: u32 = 65_534;
const OUTSIDER_GID: u32 = 65_534;
const SOCKET_ENV: &str = "MIA_STATUS_PROBE_SOCKET";
const CHILD_TEST: &str = "probe_child";

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `connect(2)` failed with `EACCES`.
    Denied,
    /// Connected, and the daemon answered a status request.
    Answered,
}

/// The probe: connect, ask for the status, print the verdict. A no-op unless
/// the parent test set [`SOCKET_ENV`].
#[test]
fn probe_child() {
    let Ok(path) = std::env::var(SOCKET_ENV) else {
        return;
    };
    match std::os::unix::net::UnixStream::connect(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => println!("PROBE:denied"),
        Err(e) => println!("PROBE:error:connect:{e}"),
        Ok(mut conn) => {
            if let Err(e) = write_frame(&mut conn, &StatusRequest::Status(StatusReq::default())) {
                println!("PROBE:error:write:{e}");
                return;
            }
            match read_frame::<_, StatusResponse>(&mut conn) {
                Ok(StatusResponse::Status(_)) => println!("PROBE:answered"),
                Ok(other) => println!("PROBE:error:reply:{other:?}"),
                Err(e) => println!("PROBE:error:read:{e}"),
            }
        }
    }
}

/// A command running `binary args` as an unprivileged uid whose only group is
/// `gid`. Darwin's `setgid` leaves `egid` at 0 (the probe would still be in
/// `wheel`), and `unsafe` is off limits, so there `chroot(8)` sets the list.
fn as_peer(binary: &Path, args: &[&str], gid: u32) -> Command {
    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("/usr/sbin/chroot");
        let gid = gid.to_string();
        cmd.args(["-u", "nobody", "-g", &gid, "-G", &gid, "/"])
            .arg(binary)
            .args(args);
        cmd
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut cmd = Command::new(binary);
        cmd.args(args).uid(PROBE_UID).gid(gid);
        cmd
    }
}

/// Run the probe binary as a peer whose group is `gid`.
fn probe(binary: &Path, socket: &Path, gid: u32) -> Outcome {
    let out = as_peer(
        binary,
        &["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"],
        gid,
    )
    .env(SOCKET_ENV, socket)
    .output()
    .expect("spawn the probe");
    let stdout = String::from_utf8_lossy(&out.stdout);
    match stdout
        .lines()
        .find_map(|l| l.split_once("PROBE:").map(|(_, v)| v))
    {
        Some("denied") => Outcome::Denied,
        Some("answered") => Outcome::Answered,
        other => panic!(
            "probe reached no verdict ({other:?}); status {}, stdout:\n{stdout}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// Root owns what it creates, whatever the umask.
fn running_as_root(dir: &Path) -> bool {
    let marker = dir.join("owner-probe");
    std::fs::write(&marker, b"").is_ok() && std::fs::metadata(&marker).is_ok_and(|m| m.uid() == 0)
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Both identities, probed against the same socket.
async fn probe_both(binary: &Path, socket: &Path) -> (Outcome, Outcome) {
    let (b, s) = (binary.to_path_buf(), socket.to_path_buf());
    tokio::task::spawn_blocking(move || (probe(&b, &s, STATUS_GID), probe(&b, &s, OUTSIDER_GID)))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_outside_the_status_group_cannot_connect() {
    // Fixed /tmp: the probe uid must reach it, and a macOS temp dir is 0700.
    let base = PathBuf::from(format!("/tmp/mst-gp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    if !running_as_root(&base) {
        eprintln!("SKIPPED: needs root to chown the socket and probe as another uid");
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    let binary = base.join("probe");
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();

    // `prepare` creates the missing parent as the daemon does: 0750, group-owned.
    let run_dir = base.join("run");
    let socket = run_dir.join("s.sock");
    let prepared = prepare(StatusEndpointConfig {
        path: socket.clone(),
        mode: 0o660,
        gid: Some(STATUS_GID),
        group: String::new(),
        rate_limit_per_sec: 100,
        max_concurrent: 4,
        read_timeout: std::time::Duration::from_secs(5),
    })
    .unwrap();
    let registry = StatusRegistry::new(vec![StatusHandle::new(DEFAULT_ENVIRONMENT_LABEL, now())]);
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(
        prepared,
        StatusService::new(registry, None, 100),
        async {
            let _ = rx.await;
        },
    ));

    let sock = std::fs::metadata(&socket).unwrap();
    assert_eq!((sock.mode() & 0o777, sock.gid()), (0o660, STATUS_GID));
    let dir = std::fs::metadata(&run_dir).unwrap();
    assert_eq!((dir.mode() & 0o777, dir.gid()), (0o750, STATUS_GID));

    let (inside, outside) = probe_both(&binary, &socket).await;
    assert_eq!(inside, Outcome::Answered, "a status-group member connects");
    assert_eq!(outside, Outcome::Denied, "an outsider is refused");

    // With the directory open to everyone, the socket's own mode still refuses.
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (inside, outside) = probe_both(&binary, &socket).await;
    assert_eq!(inside, Outcome::Answered);
    assert_eq!(outside, Outcome::Denied, "the socket mode alone refuses");

    let _ = stop.send(());
    let _ = server.await;
    let _ = std::fs::remove_dir_all(&base);
}
