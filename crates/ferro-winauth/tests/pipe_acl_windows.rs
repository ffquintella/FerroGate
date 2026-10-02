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
async fn open_client_pipe_reports_missing_pipe() {
    let err = ferro_winauth::open_client_pipe(&OsString::from(r"\\.\pipe\ferro-winauth-absent"))
        .expect_err("no such pipe");
    assert_eq!(err.raw_os_error(), Some(2)); // ERROR_FILE_NOT_FOUND
}
