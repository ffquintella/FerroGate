//! End-to-end integration tests for the F08 local helper API.
//!
//! These drive a real [`HelperServer`] over a real Unix Domain Socket with an
//! injectable [`CallerAuth`] so the kernel-attestation step (`SO_PEERCRED` +
//! IMA, which needs Linux and a real measured binary) can be simulated. They
//! cover the acceptance criteria from `docs/features/F08-helper-api.md`:
//!
//! - the socket is created with the configured permissions (`stat`);
//! - an IMA cross-check failure (spoofed `/proc/<pid>/exe`) is rejected;
//! - a caller absent from the allowlist gets `permission_denied`;
//! - a caller on the allowlist receives a well-formed child token;
//! - every request produces exactly one audit event;
//! - a slow client cannot starve a well-behaved concurrent client.

#![cfg(unix)]
// `other => panic!(...)` arms in two-variant `match`es read more clearly than
// naming the single remaining variant.
#![allow(clippy::match_wildcard_for_single_variants)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ferro_audit::AuditEvent;
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey, CompositeSignature};
use mia::helper::allowlist::{self, AllowEntry, Allowlist, AllowlistDoc};
use mia::helper::auth::{AuthError, CallerAuth, CallerIdentity, PeerCred};
use mia::helper::proto::{self, ChildToken, ErrorCode, HelperReq, HelperResp};
use mia::helper::server::{Clock, HelperServer, HelperServerConfig};
use mia::helper::token::{ChildTokenMinter, MinterConfig};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

// --- test doubles -----------------------------------------------------------

/// A `CallerAuth` that returns a fixed identity (or a fixed error), ignoring
/// the real credentials — the only way to exercise distinct identities/IMA
/// outcomes portably (real `SO_PEERCRED` would report the test process itself).
struct FixedAuth(Result<CallerIdentity, AuthError>);

impl CallerAuth for FixedAuth {
    fn identify(&self, _cred: PeerCred) -> Result<CallerIdentity, AuthError> {
        self.0.clone()
    }
}

fn fixed_clock(t: i64) -> Clock {
    std::sync::Arc::new(move || t)
}

static SOCK_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_socket_path() -> PathBuf {
    let n = SOCK_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "ferrogate-mia-test-{}-{n}.sock",
        std::process::id()
    ));
    p
}

const APP_BIN: [u8; 48] = [0xAB; 48];
const APP_UID: u32 = 1001;

fn id(uid: u32, bin: [u8; 48]) -> CallerIdentity {
    CallerIdentity {
        pid: 4321,
        uid,
        gid: uid,
        bin_sha: bin,
    }
}

fn minter() -> ChildTokenMinter {
    let (sk, _pk) = CompositeSecretKey::generate().unwrap();
    ChildTokenMinter::new(
        sk,
        MinterConfig {
            host_spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
            parent_svid_sha384: [0x33; 48],
            kid: "host-kid-1".into(),
        },
    )
}

/// Build a signed allowlist permitting `(APP_UID, APP_BIN)` and return its
/// loaded form, valid at `now`.
fn allowlist_with_app(now: i64) -> Allowlist {
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    signed_allowlist(
        &sk,
        &pk,
        now,
        vec![AllowEntry {
            uid: APP_UID,
            bin_sha: hex::encode(APP_BIN),
        }],
    )
}

fn signed_allowlist(
    sk: &CompositeSecretKey,
    pk: &CompositePublicKey,
    now: i64,
    entries: Vec<AllowEntry>,
) -> Allowlist {
    let doc = AllowlistDoc {
        trust_domain: "ferrogate.test".into(),
        issued_at: now,
        not_after: now + 3600,
        entries,
    };
    let bytes = allowlist::encode(&allowlist::sign(&doc, sk).unwrap()).unwrap();
    Allowlist::load(&bytes, pk, now, 86_400).unwrap()
}

/// Spawn a server; return its socket path, the audit receiver, and a shutdown
/// trigger.
fn spawn_server(
    auth: FixedAuth,
    minter: Option<ChildTokenMinter>,
    allowlist: Option<Allowlist>,
    now: i64,
) -> (
    PathBuf,
    mpsc::Receiver<AuditEvent>,
    tokio::sync::oneshot::Sender<()>,
) {
    let path = unique_socket_path();
    let (audit_tx, audit_rx) = mpsc::channel(64);
    let cfg = HelperServerConfig {
        socket_path: path.clone(),
        socket_mode: 0o660,
        socket_gid: None,
        windows_group: None,
        max_concurrent: 16,
        read_timeout: Duration::from_millis(300),
    };
    let server =
        HelperServer::bind(cfg, auth, minter, allowlist, audit_tx, fixed_clock(now)).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stop_rx.await;
            })
            .await;
    });
    (path, audit_rx, stop_tx)
}

/// One request/response round trip on a fresh connection.
async fn round_trip(path: &PathBuf, req: &HelperReq) -> HelperResp {
    let mut stream = connect(path).await;
    proto::write_frame(&mut stream, req).await.unwrap();
    proto::read_frame(&mut stream).await.unwrap()
}

async fn connect(path: &PathBuf) -> UnixStream {
    // The accept side may not be ready the instant bind() returns; retry briefly.
    for _ in 0..50 {
        if let Ok(s) = UnixStream::connect(path).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("could not connect to {}", path.display());
}

fn good_req() -> HelperReq {
    HelperReq {
        audience: "https://api.example.com".into(),
        dpop_jkt: "jkt-thumbprint".into(),
        ttl_secs: 300,
    }
}

// --- tests ------------------------------------------------------------------

#[tokio::test]
async fn socket_is_created_with_0660_permissions() {
    let (path, _rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        1000,
    );
    // Ensure the socket file exists before we stat it.
    let _ = connect(&path).await;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o660, "socket mode should be 0660");
}

#[tokio::test]
async fn allowlisted_caller_receives_well_formed_child_token() {
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    let ChildToken { jws, exp } = match resp {
        HelperResp::Token(t) => t,
        other => panic!("expected token, got {other:?}"),
    };
    assert_eq!(exp, 1000 + 300);
    assert_eq!(jws.split('.').count(), 3, "compact JWS has three segments");

    // Exactly one audit event, and it is a grant for this caller.
    let ev = rx.recv().await.unwrap();
    match ev {
        AuditEvent::LocalGrant { uid, pid, .. } => {
            assert_eq!(uid, APP_UID);
            assert_eq!(pid, 4321);
        }
        other => panic!("expected LocalGrant, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "exactly one audit event per request"
    );
}

#[tokio::test]
async fn caller_absent_from_allowlist_is_denied() {
    // Authenticated, but a different binary hash than the allowlist permits.
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, [0xCC; 48]))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    assert!(matches!(
        resp,
        HelperResp::Error {
            code: ErrorCode::PermissionDenied,
            ..
        }
    ));

    match rx.recv().await.unwrap() {
        AuditEvent::LocalDenied { reason, .. } => assert_eq!(reason, "not-allowlisted"),
        other => panic!("expected LocalDenied, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "exactly one audit event per request"
    );
}

#[tokio::test]
async fn spoofed_exe_ima_mismatch_is_rejected() {
    // The authenticator reports an IMA mismatch (the on-disk binary was swapped
    // after exec); the server must refuse before consulting the allowlist.
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Err(AuthError::ImaMismatch {
            partial: Some((4321, APP_UID)),
        })),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    assert!(matches!(
        resp,
        HelperResp::Error {
            code: ErrorCode::PermissionDenied,
            ..
        }
    ));

    match rx.recv().await.unwrap() {
        AuditEvent::LocalDenied { reason, uid, .. } => {
            assert_eq!(reason, "ima-mismatch");
            assert_eq!(uid, APP_UID, "denial still attributed via peer-cred");
        }
        other => panic!("expected LocalDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn no_allowlist_fails_closed() {
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        None, // no allowlist loaded
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    assert!(matches!(
        resp,
        HelperResp::Error {
            code: ErrorCode::PermissionDenied,
            ..
        }
    ));
    assert!(matches!(
        rx.recv().await.unwrap(),
        AuditEvent::LocalDenied { .. }
    ));
}

#[tokio::test]
async fn no_host_svid_refuses_to_mint() {
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        None, // no minter ⇒ no valid host SVID
        Some(allowlist_with_app(1000)),
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    assert!(matches!(
        resp,
        HelperResp::Error {
            code: ErrorCode::NoHostSvid,
            ..
        }
    ));
    match rx.recv().await.unwrap() {
        AuditEvent::LocalDenied { reason, .. } => assert_eq!(reason, "no-host-svid"),
        other => panic!("expected LocalDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn slow_client_does_not_starve_a_good_client() {
    let (path, _rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        1000,
    );

    // A slow client connects but never sends a request frame; it holds its
    // connection (and a permit) until the server's read deadline reaps it.
    let slow_path = path.clone();
    let slow = tokio::spawn(async move {
        let _stream = connect(&slow_path).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    // A well-behaved client must still get a prompt token.
    let resp = tokio::time::timeout(Duration::from_millis(500), round_trip(&path, &good_req()))
        .await
        .expect("good client should not be starved by the slow one");
    assert!(matches!(resp, HelperResp::Token(_)));

    slow.abort();
}

#[tokio::test]
async fn malformed_request_is_rejected_with_one_audit_event() {
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        1000,
    );

    let bad = HelperReq {
        audience: String::new(), // empty audience
        dpop_jkt: "jkt".into(),
        ttl_secs: 300,
    };
    let resp = round_trip(&path, &bad).await;
    assert!(matches!(
        resp,
        HelperResp::Error {
            code: ErrorCode::MalformedRequest,
            ..
        }
    ));
    match rx.recv().await.unwrap() {
        AuditEvent::LocalDenied { reason, .. } => assert_eq!(reason, "malformed-request"),
        other => panic!("expected LocalDenied, got {other:?}"),
    }
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn minted_token_verifies_against_published_jwks_key() {
    // Mint a token, then verify its composite signature under the host key —
    // exactly what a downstream verifier does via the CMIS JWKS endpoint.
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    let m = ChildTokenMinter::new(
        sk,
        MinterConfig {
            host_spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
            parent_svid_sha384: [0x33; 48],
            kid: "host-kid-1".into(),
        },
    );
    let (path, _rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(m),
        Some(allowlist_with_app(1000)),
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    let jws = match resp {
        HelperResp::Token(t) => t.jws,
        other => panic!("expected token, got {other:?}"),
    };
    let parts: Vec<&str> = jws.split('.').collect();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[2])
            .unwrap();
    let sig = CompositeSignature::from_concat_bytes(&sig_bytes).unwrap();
    pk.verify(
        mia::helper::token::CHILD_TOKEN_SIGNING_CONTEXT,
        signing_input.as_bytes(),
        &sig,
    )
    .expect("child token must verify under the host JWKS key");
}
