//! T214 (Windows half): a local account outside the status group cannot open
//! the status pipe.
//!
//! Needs an elevated shell: it creates a throwaway local group and two local
//! users, then runs this test binary as each of them through PowerShell's
//! `Start-Process -Credential`. Skips when not elevated. Run:
//! `cargo test -p mia --test status_group_peer_windows -- --nocapture`.

#![cfg(windows)]

use std::io::Write as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferro_winauth::pipe_acl::{PIPE_CLIENT_DESIRED_ACCESS, SECURITY_IDENTIFICATION};
use mia::status::{StatusHandle, StatusRegistry, DEFAULT_ENVIRONMENT_LABEL};
use mia::status_server::{prepare, serve, StatusEndpointConfig, StatusService};
use mia_status_proto::{read_frame, write_frame, StatusReq, StatusRequest, StatusResponse};

/// File next to the probe binary naming the pipe to connect to; an env var
/// would not survive `Start-Process -Credential`, which uses the target
/// user's environment.
const PIPE_FILE: &str = "pipe.txt";
const CHILD_TEST: &str = "probe_child";
/// `ERROR_ACCESS_DENIED`.
const ACCESS_DENIED: i32 = 5;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `CreateFileW` failed with `ERROR_ACCESS_DENIED`.
    Denied,
    /// Connected, and the daemon answered a status request.
    Answered,
}

/// The probe: open the pipe named in [`PIPE_FILE`] beside the binary, ask for
/// the status, print the verdict. A no-op when the file is absent.
#[test]
fn probe_child() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Ok(name) = std::fs::read_to_string(exe.with_file_name(PIPE_FILE)) else {
        return;
    };
    // Same open as the real client: no GENERIC_WRITE, which the DACL denies
    // even to the group.
    let opened = std::fs::OpenOptions::new()
        .access_mode(PIPE_CLIENT_DESIRED_ACCESS)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name.trim());
    match opened {
        Err(e) if e.raw_os_error() == Some(ACCESS_DENIED) => println!("PROBE:denied"),
        Err(e) => println!("PROBE:error:open:{e}"),
        Ok(mut conn) => {
            if let Err(e) = write_frame(&mut conn, &StatusRequest::Status(StatusReq::default())) {
                println!("PROBE:error:write:{e}");
                return;
            }
            let _ = conn.flush();
            match read_frame::<_, StatusResponse>(&mut conn) {
                Ok(StatusResponse::Status(_)) => println!("PROBE:answered"),
                Ok(other) => println!("PROBE:error:reply:{other:?}"),
                Err(e) => println!("PROBE:error:read:{e}"),
            }
        }
    }
}

fn run(program: &str, args: &[&str]) -> std::process::Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"))
}

/// `net session` only succeeds from an elevated shell.
fn elevated() -> bool {
    run("net", &["session"]).status.success()
}

/// A throwaway local group and users, removed on drop.
struct Accounts {
    group: String,
    member: String,
    outsider: String,
    password: String,
}

impl Accounts {
    fn create(tag: &str) -> Self {
        let group = format!("fgt214g{tag}");
        let member = format!("fgt214m{tag}");
        let outsider = format!("fgt214o{tag}");
        // Throwaway account, never reused: derived from the clock, not a secret.
        let password = format!("Aa1!{:x}x{tag}", clock_nanos());
        let this = Self {
            group,
            member,
            outsider,
            password,
        };
        assert!(
            run("net", &["localgroup", &this.group, "/add"])
                .status
                .success(),
            "create the group"
        );
        for user in [&this.member, &this.outsider] {
            let out = run("net", &["user", user, &this.password, "/add", "/y"]);
            assert!(out.status.success(), "create user {user}: {out:?}");
        }
        let out = run("net", &["localgroup", &this.group, &this.member, "/add"]);
        assert!(out.status.success(), "add the member: {out:?}");
        this
    }
}

impl Drop for Accounts {
    fn drop(&mut self) {
        for user in [&self.member, &self.outsider] {
            let _ = run("net", &["user", user, "/delete"]);
        }
        let _ = run("net", &["localgroup", &self.group, "/delete"]);
    }
}

fn clock_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// Run the probe binary as `user` and read its verdict.
fn probe(binary: &Path, out_file: &Path, user: &str, password: &str) -> Outcome {
    let _ = std::fs::remove_file(out_file);
    // Credentials go through the environment of this elevated process, not the
    // command line, so they stay out of the process list.
    let script = format!(
        "$p = ConvertTo-SecureString $env:T214_PW -AsPlainText -Force; \
         $c = New-Object System.Management.Automation.PSCredential($env:T214_USER, $p); \
         Start-Process -FilePath '{bin}' -ArgumentList '--exact {CHILD_TEST} --nocapture --test-threads=1' \
         -Credential $c -Wait -WindowStyle Hidden -RedirectStandardOutput '{out}'",
        bin = binary.display(),
        out = out_file.display(),
    );
    let res = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .env("T214_USER", format!(".\\{user}"))
        .env("T214_PW", password)
        .output()
        .expect("spawn powershell");
    let stdout = std::fs::read_to_string(out_file).unwrap_or_default();
    match stdout
        .lines()
        .find_map(|l| l.split_once("PROBE:").map(|(_, v)| v))
    {
        Some("denied") => Outcome::Denied,
        Some("answered") => Outcome::Answered,
        other => panic!(
            "probe as {user} reached no verdict ({other:?}); stdout:\n{stdout}\npowershell stderr:\n{}",
            String::from_utf8_lossy(&res.stderr)
        ),
    }
}

fn now() -> i64 {
    i64::try_from(clock_nanos() / 1_000_000_000).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_account_outside_the_status_group_cannot_open_the_pipe() {
    if !elevated() {
        eprintln!("SKIPPED: needs an elevated shell to create local accounts");
        return;
    }
    let tag = format!("{}", std::process::id());
    let accounts = Accounts::create(&tag);

    // `Users` can read and execute under Public; the probe binary and its
    // output live there so both accounts reach them.
    let dir: PathBuf = PathBuf::from(r"C:\Users\Public").join(format!("mia-t214-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let binary = dir.join("probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    // The probe's output file is created by the probe's account; open the
    // directory to modification by everyone for the duration of the test.
    assert!(
        run(
            "icacls",
            &[dir.to_str().unwrap(), "/grant", "*S-1-1-0:(OI)(CI)M"]
        )
        .status
        .success(),
        "open the probe directory"
    );

    let pipe = format!(r"\\.\pipe\mia-status-t214-{tag}");
    std::fs::write(dir.join(PIPE_FILE), &pipe).unwrap();

    let prepared = prepare(StatusEndpointConfig {
        path: PathBuf::from(&pipe),
        mode: 0,
        gid: None,
        group: accounts.group.clone(),
        rate_limit_per_sec: 100,
        max_concurrent: 4,
        read_timeout: Duration::from_secs(5),
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
    // Let the first pipe instance come up before the probes race it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (member, outsider, password) = (
        accounts.member.clone(),
        accounts.outsider.clone(),
        accounts.password.clone(),
    );
    let (inside, outside) = tokio::task::spawn_blocking({
        let (binary, dir) = (binary.clone(), dir.clone());
        move || {
            (
                probe(&binary, &dir.join("member.out"), &member, &password),
                probe(&binary, &dir.join("outsider.out"), &outsider, &password),
            )
        }
    })
    .await
    .unwrap();

    let _ = stop.send(());
    let _ = server.await;
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(inside, Outcome::Answered, "a status-group member connects");
    assert_eq!(outside, Outcome::Denied, "an outsider is refused");
}
