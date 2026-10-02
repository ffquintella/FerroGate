//! Status endpoint end to end (feature F18): a real listener on a temporary
//! Unix socket, driven by `mia status` and by a raw protocol client.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mia::helper::allowlist::AllowlistLoad;
use mia::helper::CrlCache;
use mia::logbuf::{LogBuffer, LogBufferLayer};
use mia::status::{AttestFailure, StatusHandle, StatusRegistry, DEFAULT_ENVIRONMENT_LABEL};
use mia::status_cli::{EXIT_HEALTHY, EXIT_NOT_RUNNING, EXIT_UNHEALTHY};
use mia::status_server::{prepare, serve, StatusEndpointConfig, StatusService};
use mia_status_proto::{
    read_frame, write_frame, AgentState, Level, LogTailReq, StatusErrorCode, StatusReq,
    StatusRequest, StatusResponse,
};
use tracing_subscriber::prelude::*;

/// The helper API's request shape, sent to the wrong endpoint.
#[derive(serde::Serialize)]
struct HelperReq {
    audience: String,
    dpop_jkt: String,
    ttl_secs: u32,
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

fn scratch(tag: &str) -> PathBuf {
    // Short: Unix socket paths are limited to ~104 bytes on macOS.
    let dir = std::env::temp_dir().join(format!("mst-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A healthy default environment and a `prod` environment whose CMIS pin
/// does not match.
fn registry() -> StatusRegistry {
    let t = now();
    let healthy = StatusHandle::new(DEFAULT_ENVIRONMENT_LABEL, t);
    healthy.set_crl_cache(Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at: t,
        number: 1,
        entries: vec![],
    })));
    healthy.set_allowlist(AllowlistLoad::Loaded {
        entries: 2,
        not_after: t + 86_400,
    });
    healthy.attest_succeeded("spiffe://ferrogate.test/host/abc", t, t + 3600);
    let broken = StatusHandle::new("prod", t);
    broken.attest_failed(AttestFailure::PinMismatch);
    StatusRegistry::new(vec![healthy, broken])
}

fn start(
    dir: &Path,
    logbuf: Option<Arc<LogBuffer>>,
) -> (PathBuf, tokio::sync::oneshot::Sender<()>) {
    let socket = dir.join("s.sock");
    let prepared = prepare(StatusEndpointConfig {
        path: socket.clone(),
        mode: 0o660,
        gid: None,
        group: String::new(),
        rate_limit_per_sec: 100,
        max_concurrent: 4,
        read_timeout: std::time::Duration::from_secs(2),
    })
    .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve(
        prepared,
        StatusService::new(registry(), logbuf, 100),
        async {
            let _ = rx.await;
        },
    ));
    (socket, tx)
}

fn config_pointing_at(dir: &Path, socket: &Path) -> PathBuf {
    let cfg = dir.join("mia.toml");
    std::fs::write(&cfg, format!("[status]\nsocket = '{}'\n", socket.display())).unwrap();
    cfg
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn mia_status_exit_codes_follow_the_snapshots() {
    let dir = scratch("cli");
    let (socket, stop) = start(&dir, None);
    let cfg = config_pointing_at(&dir, &socket);
    let c = cfg.display().to_string();

    let codes = tokio::task::spawn_blocking(move || {
        (
            // Both environments: one is pin_mismatch ⇒ non-zero.
            mia::status_cli::run(&args(&["--json", "-c", &c])),
            // Only the healthy one ⇒ zero.
            mia::status_cli::run(&args(&["--json", "-c", &c, "-e", "default"])),
            mia::status_cli::run(&args(&["-c", &c, "-e", "prod"])),
            // Not served ⇒ non-zero.
            mia::status_cli::run(&args(&["--json", "-c", &c, "-e", "qa"])),
        )
    })
    .await
    .unwrap();
    assert_eq!(
        codes,
        (EXIT_UNHEALTHY, EXIT_HEALTHY, EXIT_UNHEALTHY, EXIT_UNHEALTHY)
    );

    // The reply carries one snapshot per environment, with the derived state.
    let s = socket.clone();
    let resp: StatusResponse = tokio::task::spawn_blocking(move || {
        let mut conn = std::os::unix::net::UnixStream::connect(&s).unwrap();
        write_frame(&mut conn, &StatusRequest::Status(StatusReq::default())).unwrap();
        read_frame(&mut conn).unwrap()
    })
    .await
    .unwrap();
    let StatusResponse::Status(snaps) = resp else {
        panic!("expected snapshots")
    };
    let states: Vec<AgentState> = snaps.iter().map(|s| s.state).collect();
    assert_eq!(states, vec![AgentState::Healthy, AgentState::PinMismatch]);

    let _ = stop.send(());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mia_status_reports_not_running_when_the_endpoint_is_absent() {
    let dir = scratch("absent");
    let cfg = config_pointing_at(&dir, &dir.join("nothing-here.sock"));
    let code = mia::status_cli::run(&args(&["--json", "-c", &cfg.display().to_string()]));
    assert_eq!(code, EXIT_NOT_RUNNING);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn log_tail_is_redacted_and_helper_requests_are_rejected() {
    let dir = scratch("logs");
    let buf = LogBuffer::new(100, 1 << 20);
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .with(LogBufferLayer::new(Arc::clone(&buf)));
    let jws = "eyJhbGciOiJFZERTQSIsImtpZCI6ImNtaXMtMSJ9.eyJzdWIiOiJzcGlmZmU6Ly94In0.c2lnbmF0dXJlLWJ5dGVzLXRoYXQtYXJlLWxvbmctZW5vdWdo";
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(token = jws, "minted a child token");
        tracing::debug!("not enabled by the directive");
        tracing::warn!(target: mia::logbuf::AUDIT_TARGET, pid = 7, "audit");
    });
    let (socket, stop) = start(&dir, Some(buf));

    let s = socket.clone();
    let (tail, helper) = tokio::task::spawn_blocking(move || {
        let mut conn = std::os::unix::net::UnixStream::connect(&s).unwrap();
        write_frame(
            &mut conn,
            &StatusRequest::LogTail(LogTailReq {
                since_seq: 0,
                min_level: Level::Trace,
                max: 50,
            }),
        )
        .unwrap();
        let tail: StatusResponse = read_frame(&mut conn).unwrap();

        // A helper-API request on the status socket is refused.
        let mut conn = std::os::unix::net::UnixStream::connect(&s).unwrap();
        write_frame(
            &mut conn,
            &HelperReq {
                audience: "https://api.example.com".into(),
                dpop_jkt: "abc".into(),
                ttl_secs: 60,
            },
        )
        .unwrap();
        let helper: StatusResponse = read_frame(&mut conn).unwrap();
        (tail, helper)
    })
    .await
    .unwrap();

    let StatusResponse::LogTail(tail) = tail else {
        panic!("expected a log tail")
    };
    assert_eq!(
        tail.records.len(),
        1,
        "debug and audit records are never buffered"
    );
    let text = serde_json::to_string(&tail).unwrap();
    assert!(!text.contains(jws));
    assert!(text.contains("minted a child token"));
    assert_eq!(
        helper,
        StatusResponse::Error {
            code: StatusErrorCode::UnsupportedRequest,
            retry_after: None
        }
    );

    let _ = stop.send(());
    let _ = std::fs::remove_dir_all(&dir);
}
