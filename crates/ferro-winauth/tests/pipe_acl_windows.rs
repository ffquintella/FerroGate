//! Windows-only: a group-restricted pipe created by `create_server_pipe` is
//! reachable through `open_client_pipe`, which requests only
//! `GENERIC_READ | FILE_WRITE_DATA`.
//!
//! The test process is usually elevated on CI, so the Administrators ACE also
//! applies; this exercises the requested access and SQOS flags end to end,
//! while `pipe_acl`'s unit tests pin the DACL contents themselves.
#![cfg(windows)]

use std::ffi::OsString;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn group_pipe_round_trips_with_least_privilege_client() {
    let name = OsString::from(format!(
        r"\\.\pipe\ferro-winauth-test-{}",
        std::process::id()
    ));
    // BUILTIN\Users: present on every Windows install (English name).
    let mut server =
        ferro_winauth::create_server_pipe(&name, true, Some("Users")).expect("create pipe");

    let mut client = ferro_winauth::open_client_pipe(&name).expect("open client");
    server.connect().await.expect("server connect");

    client.write_all(b"ping").await.expect("client write");
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.expect("server read");
    assert_eq!(&buf, b"ping");

    server.write_all(b"pong").await.expect("server write");
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"pong");
}

#[tokio::test]
async fn blocking_client_round_trips_with_least_privilege_access() {
    use std::io::{Read as _, Write as _};
    use std::time::Duration;

    let name = OsString::from(format!(
        r"\\.\pipe\ferro-winauth-blocking-{}",
        std::process::id()
    ));
    let mut server =
        ferro_winauth::create_server_pipe(&name, true, Some("Users")).expect("create pipe");

    let client_name = name.clone();
    let client = std::thread::spawn(move || {
        let mut pipe =
            ferro_winauth::open_client_pipe_blocking(&client_name).expect("open blocking client");
        ferro_winauth::pipe_client::with_deadline(Duration::from_secs(10), move || {
            pipe.write_all(b"ping")?;
            let mut buf = [0u8; 4];
            pipe.read_exact(&mut buf)?;
            Ok(buf)
        })
    });

    server.connect().await.expect("server connect");
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.expect("server read");
    assert_eq!(&buf, b"ping");
    server.write_all(b"pong").await.expect("server write");

    let reply = tokio::task::spawn_blocking(move || client.join().expect("client thread"))
        .await
        .expect("join")
        .expect("exchange");
    assert_eq!(&reply, b"pong");
}

#[test]
fn a_file_path_is_never_opened_as_a_pipe() {
    let path =
        std::env::temp_dir().join(format!("ferro-winauth-not-a-pipe-{}", std::process::id()));
    std::fs::write(&path, b"keep").expect("write");
    let err = ferro_winauth::open_client_pipe_blocking(path.as_os_str()).expect_err("refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(std::fs::read(&path).expect("read"), b"keep");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn blocking_client_reports_missing_pipe() {
    let err = ferro_winauth::open_client_pipe_blocking(&OsString::from(
        r"\\.\pipe\ferro-winauth-absent-blocking",
    ))
    .expect_err("no such pipe");
    assert_eq!(err.raw_os_error(), Some(2)); // ERROR_FILE_NOT_FOUND
}

#[tokio::test]
async fn open_client_pipe_reports_missing_pipe() {
    let err = ferro_winauth::open_client_pipe(&OsString::from(r"\\.\pipe\ferro-winauth-absent"))
        .expect_err("no such pipe");
    assert_eq!(err.raw_os_error(), Some(2)); // ERROR_FILE_NOT_FOUND
}
