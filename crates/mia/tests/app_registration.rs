//! End-to-end F19 app registration against an in-process CMIS (feature F19,
//! T269/T270): a binary is registered through the real helper socket (the
//! client passes the open file with `SCM_RIGHTS`), an administrator approves
//! it in the ledger, the MIA sync loop pulls the signed allowlist v2, and the
//! same binary — at the same path — then obtains a token; a copy elsewhere
//! does not.

#![cfg(unix)]
#![allow(clippy::large_futures)]

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{PolicyId, RimStore, TpmQuoteVerifier, Vendor, VendorTrustStore};
use ferro_audit::{AuditEvent, AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::composite::CompositeSecretKey;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_raft::apps::{
    ApprovalChoice, ApprovalTerms, Approve, Continuity, PathMatch, UpdatePolicy, UserScope,
};
use ferro_svid::Issuer;
use mia::allowlist_sync::{AllowlistSink, AllowlistSync, SyncConfig, TickOutcome};
use mia::helper::auth::{AuthError, CallerAuth, CallerIdentity, PeerCred};
use mia::helper::crl::CrlCache;
use mia::helper::proto::{
    ErrorCode, HelperFrame, HelperOp, HelperReq, HelperResp, LocalState, RegistrationResp,
};
use mia::helper::server::{system_clock, HelperServer, HelperServerConfig};
use mia::helper::token::{ChildTokenMinter, MinterConfig};
use mia::host_api::{ChannelApi, CredentialSlot, HostApi, HostCredentials};
use mia::registration::identify::IdentifyConfig;
use mia::registration::{Registrar, RegistrarConfig};
use mia::virtual_tpm::{expected_pcr_digest, software_credential_blob, VirtualTpm};
use sha2::Digest as _;

// --- in-process CMIS ---------------------------------------------------------

struct SoftwareCredentialMaker;

impl CredentialMaker for SoftwareCredentialMaker {
    fn make_credential(
        &self,
        ek_pub: &[u8],
        aik_pub: &[u8],
        secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Ok(WrappedCredential {
            credential_blob: software_credential_blob(ek_pub, aik_pub, secret),
            secret_blob: Vec::new(),
        })
    }
}

fn scratch(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("mia-f19-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn cmis(evidence: &VirtualTpm, dir: &Path) -> Arc<CmisState> {
    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(evidence.ek_root_der(), Vendor::Infineon)
        .unwrap();
    let rim = RimStore::new();
    rim.approve(expected_pcr_digest(), PolicyId("test-fleet".into()));
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(dir.join("audit")).unwrap());
    let (signer, _) = InProcessSigner::generate("audit-test").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let cluster = Arc::new(
        ferro_raft::Cluster::start_single_node(dir.join("raft").to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    Arc::new(CmisState::new(
        Issuer::generate("kid-f19", "ferrogate.test").unwrap(),
        TpmQuoteVerifier::new(trust, rim),
        Box::new(SoftwareCredentialMaker),
        CmisConfig {
            trust_domain: "ferrogate.test".to_string(),
            svid_ttl_secs: 3600,
            ..CmisConfig::default()
        },
        audit,
        cluster,
    ))
}

async fn serve_cmis(state: Arc<CmisState>) -> MachineIdentityClient<tonic::transport::Channel> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MachineIdentitySvc::new(state).into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap();
    MachineIdentityClient::new(endpoint.connect_lazy())
}

/// Attest a virtual-TPM host whose SVID binds a software machine key.
async fn attested_host(
    client: &mut MachineIdentityClient<tonic::transport::Channel>,
    evidence: &mut VirtualTpm,
) -> HostCredentials {
    use base64::Engine as _;
    use ferro_sep::MachineKey as _;
    let key = ferro_sep::SoftwareMachineKey::generate().unwrap();
    let jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(key.public_spki_der()));
    let attested = mia::client::run_attest(client, evidence, jkt)
        .await
        .unwrap();
    HostCredentials::new(
        Arc::new(key),
        attested.bundle.jws.clone(),
        &attested.bundle.spiffe_id,
        attested.bundle.expires_at,
    )
    .expect("a host SPIFFE id")
}

// --- MIA side ----------------------------------------------------------------

/// The caller the helper server sees (switchable between requests).
#[derive(Clone)]
struct SwitchableAuth(Arc<Mutex<CallerIdentity>>);

impl CallerAuth for SwitchableAuth {
    fn identify(&self, _cred: PeerCred) -> Result<CallerIdentity, AuthError> {
        Ok(self.0.lock().unwrap().clone())
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

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

/// A small executable `name` in `dir`, returned with its canonical path.
fn tool(dir: &Path, name: &str, body: &[u8]) -> (PathBuf, String) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let canonical = mia::helper::exe_path::of_open_file(&file).unwrap().path;
    (path, canonical)
}

/// One exchange on the helper socket, passing `file` with `SCM_RIGHTS`.
async fn exchange<T: serde::de::DeserializeOwned + Send + 'static>(
    socket: &Path,
    frame: Vec<u8>,
    file: Option<std::fs::File>,
) -> T {
    let socket = socket.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut stream = loop {
            match std::os::unix::net::UnixStream::connect(&socket) {
                Ok(s) => break s,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        let fds: Vec<_> = file.iter().map(|f| f.as_fd()).collect();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
        if !fds.is_empty() {
            assert!(control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
        }
        let sent = rustix::net::sendmsg(
            &stream,
            &[IoSlice::new(&frame)],
            &mut control,
            rustix::net::SendFlags::empty(),
        )
        .unwrap();
        std::io::Write::write_all(&mut stream, &frame[sent..]).unwrap();
        mia_helper_proto::read_frame(&mut stream).unwrap()
    })
    .await
    .unwrap()
}

fn register_frame(path: &Path) -> Vec<u8> {
    mia_helper_proto::encode_frame(&HelperFrame::new(HelperOp::RegisterFile {
        client_request_id: mia::host_api::random_uuid(),
        path: path.display().to_string(),
        for_user: None,
        reason: Some("e2e".into()),
    }))
    .unwrap()
}

fn token_frame() -> Vec<u8> {
    mia_helper_proto::encode_frame(&HelperReq {
        audience: "https://api.example.com".into(),
        dpop_jkt: "jkt".into(),
        ttl_secs: 60,
    })
    .unwrap()
}

struct Rig {
    dir: PathBuf,
    state: Arc<CmisState>,
    creds: CredentialSlot,
    api: Arc<dyn HostApi>,
    socket: PathBuf,
    caller: Arc<Mutex<CallerIdentity>>,
    registrar: Registrar,
    sync: AllowlistSync,
    audit_rx: tokio::sync::mpsc::Receiver<AuditEvent>,
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn rig(tag: &str) -> Rig {
    let dir = scratch(tag);
    let mut evidence = VirtualTpm::ephemeral().unwrap();
    let state = cmis(&evidence, &dir).await;
    let mut client = serve_cmis(Arc::clone(&state)).await;
    let creds = CredentialSlot::new();
    creds.set(Some(attested_host(&mut client, &mut evidence).await));
    let api: Arc<dyn HostApi> = Arc::new(ChannelApi::new(client));

    // `allowlist.key`: the CMIS issuer key that signs allowlists.
    let key_path = dir.join("allowlist.pub");
    std::fs::write(&key_path, state.issuer.public_key().to_concat_bytes()).unwrap();

    let caller = Arc::new(Mutex::new(CallerIdentity::new(1, 1000, 1000, [0; 48])));
    let socket = dir.join("mia.sock");
    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel(64);
    let crl = Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
        issued_at: now(),
        number: 1,
        entries: vec![],
    }));
    let server = HelperServer::bind(
        HelperServerConfig {
            socket_path: socket.clone(),
            socket_mode: 0o660,
            socket_gid: None,
            own_socket_dir: false,
            windows_group: None,
            max_concurrent: 8,
            read_timeout: Duration::from_secs(5),
        },
        SwitchableAuth(Arc::clone(&caller)),
        Some(minter()),
        None,
        crl,
        audit_tx.clone(),
        system_clock(),
    )
    .unwrap();

    let trigger = mia::allowlist_sync::SyncTrigger::new();
    let registrar = Registrar::new(
        RegistrarConfig {
            enable: true,
            assisted: true,
            max_per_uid_per_hour: 10,
            max_open_per_uid: 50,
            ledger_path: dir.join("app-requests.cbor"),
            identify: IdentifyConfig {
                max_file_size: 1024 * 1024,
                sources: ferro_appid::VersionSources::default(),
                ima_enforced: true,
            },
        },
        Arc::clone(&api),
        creds.clone(),
        trigger.clone(),
        system_clock(),
    );
    server.set_registration(Arc::new(registrar.clone()));
    let state_path = dir.join("allowlist.state");
    let sync = AllowlistSync::new(
        SyncConfig {
            interval: Duration::from_secs(300),
            jitter_pct: 10,
            body_path: mia::allowlist_sync::synced_body_path(&state_path),
            state_path,
            key_path: Some(key_path),
            max_age_secs: 86_400,
        },
        Arc::clone(&api),
        creds.clone(),
        Arc::new(server.allowlist_reloader()) as Arc<dyn AllowlistSink>,
        None,
    )
    .with_trigger(trigger)
    .with_audit(audit_tx);

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.serve_with_shutdown(async {
        let _ = stopped.await;
    }));
    Rig {
        dir,
        state,
        creds,
        api,
        socket,
        caller,
        registrar,
        sync,
        audit_rx,
        _stop: stop,
    }
}

async fn approve(state: &CmisState, request_id: &[u8; 16]) {
    let now = now();
    state
        .cluster()
        .app_approve_request(&Approve {
            request_id: mia_helper_proto::format_id(request_id),
            admin_id: "approver-1".into(),
            now,
            choice: ApprovalChoice::New {
                approval_id: mia_helper_proto::format_id(&mia::host_api::random_uuid()),
                terms: ApprovalTerms {
                    user_scope: UserScope::ExactUser,
                    path_match: PathMatch::Exact,
                    update_policy: UpdatePolicy::ManualEachTime,
                    continuity: Continuity::Anchored,
                    expires_at: Some(now + 86_400),
                    note: None,
                },
            },
            forbid_self_approval: false,
            also_revoke: vec![],
            generation_millis: now * 1000,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn register_approve_sync_then_the_caller_is_allowed() {
    let mut r = rig("e2e").await;
    cmis::apps::mode::set(r.state.cluster(), cmis::apps::AllowlistMode::Approvals)
        .await
        .unwrap();
    let body = b"#!/bin/true\nthe e2e tool\n";
    let (path, canonical) = tool(&r.dir, "tool", body);
    let sha = mia::helper::auth::bin_sha384(body);
    *r.caller.lock().unwrap() =
        CallerIdentity::new(4242, 1000, 1000, sha).with_exe_path(canonical.clone());

    // Not on the allowlist yet.
    let denied: HelperResp = exchange(&r.socket, token_frame(), None).await;
    assert!(matches!(
        denied,
        HelperResp::Error {
            code: ErrorCode::PermissionDenied,
            ..
        }
    ));

    // 1. Register the file through the socket, passing the open descriptor.
    let resp: RegistrationResp = exchange(
        &r.socket,
        register_frame(&path),
        Some(std::fs::File::open(&path).unwrap()),
    )
    .await;
    let RegistrationResp::Submitted {
        request_id: Some(request_id),
        state: LocalState::Pending,
        ..
    } = resp
    else {
        panic!("unexpected {resp:?}")
    };

    // 2. An administrator approves it (exact user and path).
    approve(&r.state, &request_id).await;

    // 3. The status poll sees it; the sync loop pulls the signed v2 body.
    r.registrar.refresh(now()).await;
    let status: RegistrationResp = exchange(
        &r.socket,
        mia_helper_proto::encode_frame(&HelperFrame::new(HelperOp::RequestStatus {
            request_ids: vec![request_id],
        }))
        .unwrap(),
        None,
    )
    .await;
    let RegistrationResp::Status(items) = status else {
        panic!("unexpected {status:?}")
    };
    assert_eq!(items[0].state, LocalState::Approved);
    let outcome = r.sync.tick(now()).await;
    let TickOutcome::Applied { generation, .. } = outcome else {
        panic!("unexpected {outcome:?}")
    };
    assert!(generation > 0);
    let mut events = Vec::new();
    while let Ok(e) = r.audit_rx.try_recv() {
        events.push(e);
    }
    assert!(
        events.iter().any(|e| matches!(
            e,
            AuditEvent::AllowlistSyncApplied { generation: g, .. } if *g == generation
        )),
        "{events:?}"
    );

    // 4. The approved binary at its path now gets a token, without a restart.
    let granted: HelperResp = exchange(&r.socket, token_frame(), None).await;
    assert!(matches!(granted, HelperResp::Token(_)), "{granted:?}");

    // The same bytes at another path, or as another user, do not.
    let (_, elsewhere) = tool(&r.dir, "copy", body);
    *r.caller.lock().unwrap() = CallerIdentity::new(4243, 1000, 1000, sha).with_exe_path(elsewhere);
    let other_path: HelperResp = exchange(&r.socket, token_frame(), None).await;
    assert!(matches!(other_path, HelperResp::Error { .. }));
    *r.caller.lock().unwrap() = CallerIdentity::new(4244, 1001, 1001, sha).with_exe_path(canonical);
    let other_user: HelperResp = exchange(&r.socket, token_frame(), None).await;
    assert!(matches!(other_user, HelperResp::Error { .. }));

    // A second sync has nothing new (and is within CMIS's 30 s minimum
    // interval, so it is told to retry later): the allowlist stays.
    let again = r.sync.tick(now()).await;
    assert!(
        matches!(again, TickOutcome::NotModified | TickOutcome::Failed { .. }),
        "{again:?}"
    );
    let _ = (&r.creds, &r.api);
}

#[tokio::test]
async fn legacy_mode_queues_requests_until_cmis_accepts_them() {
    let r = rig("legacy").await;
    let (path, canonical) = tool(&r.dir, "tool", b"#!/bin/true\nlegacy\n");
    *r.caller.lock().unwrap() =
        CallerIdentity::new(4242, 1000, 1000, [1; 48]).with_exe_path(canonical);

    // CMIS is still in legacy allowlist mode: the request stays queued.
    let resp: RegistrationResp = exchange(
        &r.socket,
        register_frame(&path),
        Some(std::fs::File::open(&path).unwrap()),
    )
    .await;
    assert!(
        matches!(
            resp,
            RegistrationResp::Submitted {
                state: LocalState::Queued,
                request_id: None,
                ..
            }
        ),
        "{resp:?}"
    );

    // After the switch the outbox submits it on the next tick.
    cmis::apps::mode::set(r.state.cluster(), cmis::apps::AllowlistMode::Approvals)
        .await
        .unwrap();
    r.registrar.refresh(now()).await;
    let status: RegistrationResp = exchange(
        &r.socket,
        mia_helper_proto::encode_frame(&HelperFrame::new(HelperOp::RequestStatus {
            request_ids: vec![],
        }))
        .unwrap(),
        None,
    )
    .await;
    let RegistrationResp::Status(items) = status else {
        panic!("unexpected {status:?}")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].state, LocalState::Pending);
    assert!(items[0].request_id.is_some());
}

#[tokio::test]
async fn legacy_mode_sync_serves_the_hand_provisioned_entries_as_v2() {
    let mut r = rig("legacy-sync").await;
    // CMIS in legacy mode with no allowlist for this host: an empty v2 body
    // bound to this host is served and applied.
    let outcome = r.sync.tick(now()).await;
    assert!(
        matches!(outcome, TickOutcome::Applied { entries: 0, .. }),
        "{outcome:?}"
    );
    assert!(matches!(
        r.audit_rx.try_recv(),
        Ok(AuditEvent::AllowlistSyncApplied { .. })
    ));
}
