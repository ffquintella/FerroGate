//! Every `AgentState` the daemon can report, served over the real status
//! endpoint (T213, F18): one environment per state, built with the same
//! `StatusHandle` calls the daemon makes, read back by a protocol client.

// `NotRunning` is driven against an absent socket; `NotInstalled` and
// `ImaDisabled` are client-side only and asserted as such.

#![cfg(unix)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mia::helper::allowlist::AllowlistLoad;
use mia::helper::CrlCache;
use mia::status::{AttestFailure, StatusHandle, StatusRegistry};
use mia::status_server::{prepare, serve, StatusEndpointConfig, StatusService};
use mia_status_proto::{
    read_frame, write_frame, AgentState, StatusReq, StatusRequest, StatusResponse,
};

const TTL: i64 = 3600;

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn crl(issued_at: i64) -> Arc<CrlCache> {
    Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at,
        number: 1,
        entries: vec![],
    }))
}

/// A healthy environment: valid SVID, fresh CRL, loaded allowlist. Each
/// scenario then breaks one thing.
fn healthy(label: &str, t: i64) -> StatusHandle {
    let h = StatusHandle::new(label, t);
    h.set_crl_cache(crl(t));
    h.set_allowlist(AllowlistLoad::Loaded {
        entries: 2,
        not_after: t + 86_400,
    });
    h.attest_succeeded("spiffe://ferrogate.test/host/abc", t, t + TTL);
    h
}

/// The scenarios: the state each must reach and the handle that gets there.
fn scenarios(t: i64) -> Vec<(AgentState, StatusHandle)> {
    let failed = |s: AgentState, why: AttestFailure| {
        let h = StatusHandle::new(s.as_str(), t);
        h.attest_started();
        h.attest_failed(why);
        (s, h)
    };
    let mut v = Vec::new();

    let h = StatusHandle::new(AgentState::NotConfigured.as_str(), t);
    h.set_not_configured(mia_status_proto::error_codes::CMIS_NOT_CONFIGURED);
    v.push((AgentState::NotConfigured, h));

    let h = StatusHandle::new(AgentState::Attesting.as_str(), t);
    h.attest_started();
    v.push((AgentState::Attesting, h));

    v.push(failed(
        AgentState::CmisUnreachable,
        AttestFailure::CmisUnreachable,
    ));
    v.push(failed(AgentState::NotEnrolled, AttestFailure::NotEnrolled));
    v.push(failed(AgentState::PinMismatch, AttestFailure::PinMismatch));
    v.push(failed(
        AgentState::TpmUnavailable,
        AttestFailure::TpmUnavailable,
    ));

    let h = healthy(AgentState::CrlStale.as_str(), t);
    h.set_crl_cache(crl(t - 301));
    v.push((AgentState::CrlStale, h));

    let h = healthy(AgentState::AllowlistMissing.as_str(), t);
    h.set_allowlist(AllowlistLoad::Missing);
    v.push((AgentState::AllowlistMissing, h));

    let h = healthy(AgentState::AllowlistInvalid.as_str(), t);
    h.set_allowlist(AllowlistLoad::Invalid);
    v.push((AgentState::AllowlistInvalid, h));

    let h = healthy(AgentState::SvidExpiring.as_str(), t);
    h.set_renew_at(t - 1);
    v.push((AgentState::SvidExpiring, h));

    v.push((
        AgentState::Healthy,
        healthy(AgentState::Healthy.as_str(), t),
    ));
    v
}

fn scratch() -> PathBuf {
    // Short: Unix socket paths are limited to ~104 bytes on macOS.
    let dir = std::env::temp_dir().join(format!("mas-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn every_daemon_reportable_state_is_served_over_the_endpoint() {
    let t = now();
    let cases = scenarios(t);
    let handles: Vec<StatusHandle> = cases.iter().map(|(_, h)| h.clone()).collect();

    let dir = scratch();
    let socket = dir.join("s.sock");
    let prepared = prepare(StatusEndpointConfig {
        path: socket.clone(),
        mode: 0o660,
        gid: None,
        group: String::new(),
        rate_limit_per_sec: 100,
        max_concurrent: 4,
        read_timeout: Duration::from_secs(2),
    })
    .unwrap();
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve(
        prepared,
        StatusService::new(StatusRegistry::new(handles), None, 100),
        async {
            let _ = rx.await;
        },
    ));

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
    assert_eq!(snaps.len(), cases.len());

    let mut reached = HashSet::new();
    for (want, _) in &cases {
        let snap = snaps
            .iter()
            .find(|s| s.environment.as_deref() == Some(want.as_str()))
            .unwrap_or_else(|| panic!("no snapshot for {want:?}"));
        assert_eq!(snap.state, *want, "environment {}", want.as_str());
        assert_eq!(
            snap.last_error.is_none(),
            matches!(want, AgentState::Healthy | AgentState::Attesting),
            "{want:?} error presence"
        );
        reached.insert(snap.state);
    }

    // NotRunning: the endpoint is gone, so the client names it itself.
    let _ = stop.send(());
    let absent = dir.join("absent.sock");
    let err = mia::status_cli::query(&absent, &StatusRequest::Status(StatusReq::default()));
    assert!(err.is_err(), "an absent socket must not answer");
    let not_running = mia::status_cli::not_running_snapshots(None);
    assert_eq!(not_running[0].state, AgentState::NotRunning);
    reached.insert(AgentState::NotRunning);

    for s in AgentState::ALL {
        let client_only = matches!(s, AgentState::NotInstalled | AgentState::ImaDisabled);
        assert_eq!(reached.contains(&s), !client_only, "{s:?}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
