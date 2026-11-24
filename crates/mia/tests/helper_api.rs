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
use mia::helper::auth::{AuthError, CallerAuth, CallerIdentity, PeerCred, UnreadableDetail};
use mia::helper::crl::CrlCache;
use mia::helper::proto::{
    self, ChildToken, ErrorCode, HelperFrame, HelperOp, HelperReq, HelperResp, RegErrorCode,
    RegistrationResp,
};
use mia::helper::server::{Clock, HelperServer, HelperServerConfig, RegistrationHandler};
use mia::helper::token::{ChildTokenMinter, MinterConfig};
use std::sync::Arc;
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
    CallerIdentity::new(4321, uid, uid, bin)
}

fn minter() -> ChildTokenMinter {
    let (sk, _pk) = CompositeSecretKey::generate().unwrap();
    ChildTokenMinter::new(
        sk,
        MinterConfig {
            host_spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
            parent_svid_sha384: [0x33; 48],
            parent_expires_at: i64::MAX,
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
            uid: Some(APP_UID),
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

/// A CRL cache seeded with a fresh, empty (no-revocation) CRL at `now`, so the
/// F11 gate admits minting. Tests that exercise stale/revoked behaviour build
/// their own cache instead (see [`spawn_server_with_crl`]).
fn fresh_crl_cache(now: i64) -> Arc<CrlCache> {
    Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at: now,
        number: 1,
        entries: vec![],
    }))
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
    spawn_server_with_crl(auth, minter, allowlist, fresh_crl_cache(now), now)
}

/// Like [`spawn_server`] but with a caller-supplied CRL cache, to drive the
/// F11 freshness/revocation gate.
fn spawn_server_with_crl(
    auth: FixedAuth,
    minter: Option<ChildTokenMinter>,
    allowlist: Option<Allowlist>,
    crl: Arc<CrlCache>,
    now: i64,
) -> (
    PathBuf,
    mpsc::Receiver<AuditEvent>,
    tokio::sync::oneshot::Sender<()>,
) {
    spawn_server_full(auth, minter, allowlist, crl, now, None)
}

/// Like [`spawn_server_with_crl`], optionally installing a registration
/// handler before serving.
fn spawn_server_full(
    auth: FixedAuth,
    minter: Option<ChildTokenMinter>,
    allowlist: Option<Allowlist>,
    crl: Arc<CrlCache>,
    now: i64,
    registration: Option<Arc<dyn RegistrationHandler>>,
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
        own_socket_dir: false,
        windows_group: None,
        max_concurrent: 16,
        read_timeout: Duration::from_millis(300),
    };
    let server = HelperServer::bind(
        cfg,
        auth,
        minter,
        allowlist,
        crl,
        audit_tx,
        fixed_clock(now),
    )
    .unwrap();
    if let Some(handler) = registration {
        server.set_registration(handler);
    }
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

/// `SHA-384` of the running test binary. Because these integration tests *are*
/// the process hosting the [`HelperServer`], this equals the server's own
/// `self_sha`, so a caller presenting this hash is "mia talking to itself".
fn own_exe_sha() -> [u8; 48] {
    use sha2::{Digest, Sha384};
    let path = std::env::current_exe().unwrap();
    let bytes = std::fs::read(path).unwrap();
    Sha384::digest(&bytes).into()
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
async fn mia_own_binary_is_always_permitted_even_without_allowlist() {
    // `mia` ships as one binary serving as the daemon, the CLI, and `mia test`.
    // A caller whose hash is the daemon's own (mia talking to itself) must mint
    // even with NO allowlist loaded and an arbitrary uid that is listed nowhere
    // — self-trust substitutes for allowlist membership so the binary never
    // loses the ability to reach its own daemon.
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Ok(id(4242, own_exe_sha()))),
        Some(minter()),
        None, // no allowlist at all
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    match resp {
        HelperResp::Token(_) => {}
        other => panic!("mia's own binary must always mint, got {other:?}"),
    }
    match rx.recv().await.unwrap() {
        AuditEvent::LocalGrant { uid, .. } => assert_eq!(uid, 4242),
        other => panic!("expected LocalGrant, got {other:?}"),
    }
}

#[tokio::test]
async fn mia_own_binary_still_subject_to_crl_gate() {
    // Self-trust substitutes only for the allowlist membership check; the host
    // SVID and CRL gates still apply. A revoked host must not mint even for
    // mia's own binary.
    let crl = Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at: 1000,
        number: 2,
        entries: vec![ferro_svid::CrlEntry::new(
            ferro_svid::RevocationTarget::Host {
                spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
            },
            "decommissioned",
            1000,
        )],
    }));
    let (path, mut rx, _stop) = spawn_server_with_crl(
        FixedAuth(Ok(id(4242, own_exe_sha()))),
        Some(minter()),
        None,
        crl,
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
        AuditEvent::LocalDenied { reason, .. } => assert_eq!(reason, "svid-revoked"),
        other => panic!("expected LocalDenied svid-revoked, got {other:?}"),
    }
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

/// An unreadable caller image whose error carries the OS diagnostic.
fn unreadable_exe() -> FixedAuth {
    FixedAuth(Err(AuthError::ExeUnreadable {
        partial: Some((4321, APP_UID)),
        detail: UnreadableDetail::new("open")
            .with_os_error("PermissionDenied: Operation not permitted (os error 1)")
            .with_path("/Applications/Diag.app/Contents/MacOS/diag"),
    }))
}

#[tokio::test]
async fn unreadable_exe_detail_stays_out_of_token_reply_and_audit() {
    let (path, mut rx, _stop) = spawn_server(
        unreadable_exe(),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    assert_eq!(
        resp,
        HelperResp::Error {
            code: ErrorCode::PermissionDenied,
            retry_after: None,
        }
    );

    let event = rx.recv().await.unwrap();
    let rendered = format!("{event:?}");
    match event {
        AuditEvent::LocalDenied {
            reason, pid, uid, ..
        } => {
            assert_eq!(reason, "exe-unreadable");
            assert_eq!((pid, uid), (4321, APP_UID));
        }
        other => panic!("expected LocalDenied, got {other:?}"),
    }
    for leaked in ["Diag.app", "os error", "PermissionDenied"] {
        assert!(!rendered.contains(leaked), "{leaked} in {rendered}");
    }
}

/// A registration handler for an unauthenticated caller, which must never
/// be reached.
struct NeverRegistrar;

impl RegistrationHandler for NeverRegistrar {
    fn handle(
        &self,
        _caller: CallerIdentity,
        _op: HelperOp,
        _file: Option<std::fs::File>,
    ) -> futures::future::BoxFuture<'_, RegistrationResp> {
        Box::pin(async { RegistrationResp::Status(Vec::new()) })
    }
}

#[tokio::test]
async fn unreadable_exe_registration_reply_is_bare_permission_denied() {
    let (path, mut rx, _stop) = spawn_server_full(
        unreadable_exe(),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        fresh_crl_cache(1000),
        1000,
        Some(Arc::new(NeverRegistrar)),
    );

    let frame = mia_helper_proto::encode_frame(&HelperFrame::new(HelperOp::RequestStatus {
        request_ids: Vec::new(),
    }))
    .unwrap();
    let mut stream = connect(&path).await;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &frame)
        .await
        .unwrap();
    let resp: RegistrationResp = proto::read_frame(&mut stream).await.unwrap();
    assert_eq!(
        resp,
        RegistrationResp::Error {
            code: RegErrorCode::PermissionDenied,
            retry_after: None,
        }
    );
    // The registration path records no `LocalDenied`, before or after.
    assert!(rx.try_recv().is_err());
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
async fn stale_crl_refuses_to_mint() {
    // A CRL cached well in the past (older than the 5-min freshness bound) must
    // make the MIA fail closed even for an otherwise-permitted caller (F11).
    let crl = Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at: 0,
        number: 1,
        entries: vec![],
    }));
    let (path, mut rx, _stop) = spawn_server_with_crl(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1_000_000)),
        crl,
        1_000_000, // far past issued_at=0 ⇒ stale
    );

    let resp = round_trip(&path, &good_req()).await;
    assert!(matches!(
        resp,
        HelperResp::Error {
            code: ErrorCode::CrlStale,
            ..
        }
    ));
    match rx.recv().await.unwrap() {
        AuditEvent::LocalDenied { reason, .. } => assert_eq!(reason, "crl-stale"),
        other => panic!("expected LocalDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_crl_refuses_to_mint() {
    // No CRL ever pulled ⇒ fail closed.
    let crl = Arc::new(CrlCache::new());
    let (path, mut rx, _stop) = spawn_server_with_crl(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        crl,
        1000,
    );

    let resp = round_trip(&path, &good_req()).await;
    assert!(matches!(
        resp,
        HelperResp::Error {
            code: ErrorCode::CrlStale,
            ..
        }
    ));
    assert!(matches!(
        rx.recv().await.unwrap(),
        AuditEvent::LocalDenied { .. }
    ));
}

#[tokio::test]
async fn revoked_host_refuses_to_mint() {
    // A fresh CRL that revokes this MIA's host SPIFFE id blocks minting even
    // when the caller is allowlisted — and the gate runs before allowlisting.
    let crl = Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at: 1000,
        number: 2,
        entries: vec![ferro_svid::CrlEntry::new(
            ferro_svid::RevocationTarget::Host {
                // Matches the host id in `minter()`.
                spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
            },
            "decommissioned",
            1000,
        )],
    }));
    let (path, mut rx, _stop) = spawn_server_with_crl(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        crl,
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
        AuditEvent::LocalDenied { reason, .. } => assert_eq!(reason, "svid-revoked"),
        other => panic!("expected LocalDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn revoked_svid_by_cert_sha_refuses_to_mint() {
    // The same, but revoking the specific parent SVID by cert_sha. `minter()`
    // uses parent_svid_sha384 = [0x33; 48].
    let crl = Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at: 1000,
        number: 3,
        entries: vec![ferro_svid::CrlEntry::new(
            ferro_svid::RevocationTarget::Svid {
                cert_sha: hex::encode([0x33u8; 48]),
            },
            "key-compromise",
            1000,
        )],
    }));
    let (path, _rx, _stop) = spawn_server_with_crl(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(minter()),
        Some(allowlist_with_app(1000)),
        crl,
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
async fn expired_parent_svid_refuses_to_mint() {
    // T294 review: a minter whose parent SVID has expired refuses with
    // `no_host_svid`, even before the renewal task takes it out.
    let m = minter().with_parent([0x33; 48], 1000);
    let (path, mut rx, _stop) = spawn_server(
        FixedAuth(Ok(id(APP_UID, APP_BIN))),
        Some(m),
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
async fn minted_token_verifies_against_published_jwks_key() {
    // Mint a token, then verify its composite signature under the host key —
    // exactly what a downstream verifier does via the CMIS JWKS endpoint.
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    let m = ChildTokenMinter::new(
        sk,
        MinterConfig {
            host_spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
            parent_svid_sha384: [0x33; 48],
            parent_expires_at: i64::MAX,
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

// --- trusted publishers (ADR-0006) ------------------------------------------

mod trusted_publishers {
    use super::*;
    use ferro_codesign::testing::{FakeVerifier, TestChain};
    use ferro_codesign::{cert_facts, PinKind, SignatureKind, SignatureVerifier, VerifyError};
    use ferro_svid::allowlist_v2::{
        sign_v2, AllowlistDocV2, TrustedPublisherV3, ALLOWLIST_V2_FORMAT, ALLOWLIST_V3_FORMAT,
    };

    const HOST: &str = "8d5e0000-0000-4000-8000-0000000000aa";
    /// 2026-01-01: inside the test chain's validity window.
    const NOW: i64 = 1_767_225_600;
    const SIGNED_APP: [u8; 48] = [0x5A; 48];

    fn publisher(chain: &TestChain, id: u8) -> TrustedPublisherV3 {
        let leaf = cert_facts(&chain.leaf_der).unwrap();
        TrustedPublisherV3 {
            publisher_id: [id; 16],
            kind: SignatureKind::Apple.code(),
            anchor_sha256: cert_facts(&chain.ca_der).unwrap().cert_sha256,
            pin_kind: PinKind::LeafSpkiSha256.code(),
            pin: leaf.spki_sha256,
            require_timestamp: true,
            expires_at: None,
        }
    }

    /// A signed format-3 body (format 2 when `publishers` is empty) that
    /// admits `(APP_UID, APP_BIN)` only.
    fn allowlist(publishers: Vec<TrustedPublisherV3>) -> Allowlist {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let doc = AllowlistDocV2 {
            format: if publishers.is_empty() {
                ALLOWLIST_V2_FORMAT
            } else {
                ALLOWLIST_V3_FORMAT
            },
            trust_domain: "ferrogate.test".into(),
            host_uuid: HOST.into(),
            generation: 1,
            issued_at: NOW,
            not_after: NOW + 3600,
            entries: vec![ferro_svid::allowlist_v2::AllowEntryV2 {
                approval_id: [1; 16],
                bin_sha: hex::encode(APP_BIN),
                uid: Some(APP_UID),
                user_sid_hash: None,
                path_hash: None,
                expires_at: None,
            }],
            publishers,
        };
        let bytes = allowlist::encode(&sign_v2(&doc, &sk).unwrap()).unwrap();
        Allowlist::load_v2(&bytes, &pk, NOW, 86_400).unwrap()
    }

    fn spawn(
        bin: [u8; 48],
        allowlist: Allowlist,
        verifier: Arc<FakeVerifier>,
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
            own_socket_dir: false,
            windows_group: None,
            max_concurrent: 16,
            read_timeout: Duration::from_millis(300),
        };
        let server = HelperServer::bind(
            cfg,
            FixedAuth(Ok(
                id(APP_UID, bin).with_exe_path("/Applications/Signed.app/x")
            )),
            Some(minter()),
            Some(allowlist),
            fresh_crl_cache(NOW),
            audit_tx,
            fixed_clock(NOW),
        )
        .unwrap();
        server.set_signature_verifier(verifier as Arc<dyn SignatureVerifier>);
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

    async fn only_event(rx: &mut mpsc::Receiver<AuditEvent>) -> AuditEvent {
        let ev = rx.recv().await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "exactly one audit event per request"
        );
        ev
    }

    /// The approval path end to end: a caller no entry admits, signed by a
    /// trusted publisher, gets a token with no request sent anywhere, and the
    /// grant is audited with the publisher, the leaf thumbprint, the binary
    /// hash and the caller.
    #[tokio::test]
    async fn a_trusted_publishers_binary_is_auto_approved_and_audited() {
        let chain = TestChain::new("ACME Corp");
        let fake = Arc::new(FakeVerifier::new(Ok(
            chain.signature(SignatureKind::Apple, true)
        )));
        let (path, mut rx, _stop) = spawn(
            SIGNED_APP,
            allowlist(vec![publisher(&chain, 7)]),
            Arc::clone(&fake),
        );
        let resp = round_trip(&path, &good_req()).await;
        assert!(matches!(resp, HelperResp::Token(_)), "{resp:?}");
        assert_eq!(fake.calls(), 1);
        match only_event(&mut rx).await {
            AuditEvent::LocalGrantByPublisher {
                pid,
                uid,
                bin_sha,
                publisher_id,
                leaf_cert_sha256,
                ..
            } => {
                assert_eq!((pid, uid), (4321, APP_UID));
                assert_eq!(bin_sha.0, SIGNED_APP);
                assert_eq!(publisher_id.0, [7; 16]);
                assert_eq!(
                    leaf_cert_sha256.0,
                    cert_facts(&chain.leaf_der).unwrap().cert_sha256
                );
            }
            other => panic!("expected LocalGrantByPublisher, got {other:?}"),
        }
    }

    async fn assert_denied(path: &PathBuf, rx: &mut mpsc::Receiver<AuditEvent>) {
        let resp = round_trip(path, &good_req()).await;
        assert!(
            matches!(
                resp,
                HelperResp::Error {
                    code: ErrorCode::PermissionDenied,
                    ..
                }
            ),
            "{resp:?}"
        );
        match only_event(rx).await {
            AuditEvent::LocalDenied { reason, .. } => assert_eq!(reason, "not-allowlisted"),
            other => panic!("expected LocalDenied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verification_errors_fail_closed() {
        let chain = TestChain::new("ACME Corp");
        for e in [
            VerifyError::Unsigned,
            VerifyError::Untrusted,
            VerifyError::Revoked,
            VerifyError::ImageChanged,
            VerifyError::Unsupported,
        ] {
            let fake = Arc::new(FakeVerifier::new(Err(e)));
            let (path, mut rx, _stop) = spawn(
                SIGNED_APP,
                allowlist(vec![publisher(&chain, 7)]),
                Arc::clone(&fake),
            );
            assert_denied(&path, &mut rx).await;
            assert_eq!(fake.calls(), 1);
        }
    }

    #[tokio::test]
    async fn another_publisher_or_a_missing_timestamp_is_denied() {
        let trusted = TestChain::new("ACME Corp");
        let other = TestChain::new("Evil Corp");
        let fake = Arc::new(FakeVerifier::new(Ok(
            other.signature(SignatureKind::Apple, true)
        )));
        let (path, mut rx, _stop) = spawn(
            SIGNED_APP,
            allowlist(vec![publisher(&trusted, 7)]),
            Arc::clone(&fake),
        );
        assert_denied(&path, &mut rx).await;

        let untimed = Arc::new(FakeVerifier::new(Ok(
            trusted.signature(SignatureKind::Apple, false)
        )));
        let (path, mut rx, _stop) =
            spawn(SIGNED_APP, allowlist(vec![publisher(&trusted, 7)]), untimed);
        assert_denied(&path, &mut rx).await;
    }

    /// Without publishers nothing is verified: the old behaviour.
    #[tokio::test]
    async fn no_publishers_means_no_verification() {
        let chain = TestChain::new("ACME Corp");
        let fake = Arc::new(FakeVerifier::new(Ok(
            chain.signature(SignatureKind::Apple, true)
        )));
        let (path, mut rx, _stop) = spawn(SIGNED_APP, allowlist(Vec::new()), Arc::clone(&fake));
        assert_denied(&path, &mut rx).await;
        assert_eq!(fake.calls(), 0);
    }

    /// An allowlisted caller is granted as before, without a verification.
    #[tokio::test]
    async fn an_allowlisted_caller_skips_the_publisher_check() {
        let chain = TestChain::new("ACME Corp");
        let fake = Arc::new(FakeVerifier::new(Err(VerifyError::Unsigned)));
        let (path, mut rx, _stop) = spawn(
            APP_BIN,
            allowlist(vec![publisher(&chain, 7)]),
            Arc::clone(&fake),
        );
        let resp = round_trip(&path, &good_req()).await;
        assert!(matches!(resp, HelperResp::Token(_)), "{resp:?}");
        assert!(matches!(
            only_event(&mut rx).await,
            AuditEvent::LocalGrant { .. }
        ));
        assert_eq!(fake.calls(), 0);
    }
}
