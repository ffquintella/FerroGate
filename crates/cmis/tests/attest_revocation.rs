//! T295: `Attest` refuses a host whose SPIFFE id is revoked
//! (`RevocationTarget::Host`), so `RevokeHost` cannot be undone by simply
//! re-attesting. Driven over a real tonic channel on the host-key tier (the
//! TPM tier is covered end to end in `crates/mia/tests/e2e_attest.rs`); the
//! refusal is `PERMISSION_DENIED host_revoked`, audited as
//! `AttestFail { reason: "attest-host-revoked" }`, and nothing is issued.
//!
//! T296: `UnrevokeHost` lifts the host entry so the host attests again,
//! keeps the stored SVID revoked by digest, leaves `RevokeSvid` and other
//! hosts' entries alone, and fails closed (audit or store unavailable,
//! caller without `svid.revoke`).

#![allow(clippy::large_futures)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{event as audit_event, AuditEvent, AuditLog, AuditStore, InProcessSigner};
use ferro_audit::{AuditStoreError, Hash384, LocalDiskWormStore, SignedTreeHead};
use ferro_proto::v1::attest_request::Phase as ReqPhase;
use ferro_proto::v1::attest_response::Phase as RespPhase;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::machine_identity_server::MachineIdentity as _;
use ferro_proto::v1::{
    AttestInit, AttestRequest, Csr, HostKeyEvidence, MachineFacts, RevokeHostRequest,
    RevokeSvidRequest, SvidBundle, UnrevokeHostRequest,
};
use ferro_raft::Cluster;
use ferro_sep::{MachineKey as _, SoftwareMachineKey};
use ferro_svid::{Issuer, RevocationTarget};
use sha2::{Digest, Sha256, Sha384};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

struct UnusedCredentialMaker;
impl CredentialMaker for UnusedCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap("unused".to_string()))
    }
}

/// Removes the test's directories on drop.
struct TmpDirs(Vec<std::path::PathBuf>);
impl Drop for TmpDirs {
    fn drop(&mut self) {
        for dir in &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Per-test sequence so concurrent tests get their own directories.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A local WORM store whose appends can be made to fail, to drive the
/// fail-closed path of `UnrevokeHost`.
struct FlakyStore {
    inner: LocalDiskWormStore,
    fail_appends: AtomicBool,
}

impl AuditStore for FlakyStore {
    fn append_leaf(
        &self,
        index: u64,
        raw_event: &[u8],
        leaf_hash: &[u8; 48],
    ) -> Result<(), AuditStoreError> {
        if self.fail_appends.load(Ordering::SeqCst) {
            return Err(AuditStoreError::Io(std::io::Error::other(
                "injected append failure",
            )));
        }
        self.inner.append_leaf(index, raw_event, leaf_hash)
    }
    fn record_sth(&self, sth: &SignedTreeHead) -> Result<(), AuditStoreError> {
        self.inner.record_sth(sth)
    }
    fn read_leaf(&self, index: u64) -> Result<Vec<u8>, AuditStoreError> {
        self.inner.read_leaf(index)
    }
    fn latest_sth(&self) -> Result<Option<SignedTreeHead>, AuditStoreError> {
        self.inner.latest_sth()
    }
}

/// A CMIS for the host-key tier plus a handle on its audit store, so the
/// test can read back the events it appended, and the guard that removes
/// its directories.
async fn state() -> (Arc<CmisState>, Arc<dyn AuditStore>, TmpDirs) {
    let (state, store, _flaky, dirs) = state_with_flaky_audit().await;
    (state, store, dirs)
}

/// [`state`], also returning the store's failure switch.
async fn state_with_flaky_audit() -> (
    Arc<CmisState>,
    Arc<dyn AuditStore>,
    Arc<FlakyStore>,
    TmpDirs,
) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tag = format!("ferrogate-cmis-attrev-{}-{seq}", std::process::id());
    let issuer = Issuer::generate("cmis-test-attrev", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(&tag);
    let _ = std::fs::remove_dir_all(&tmp);
    let flaky = Arc::new(FlakyStore {
        inner: LocalDiskWormStore::open(&tmp).unwrap(),
        fail_appends: AtomicBool::new(false),
    });
    let store: Arc<dyn AuditStore> = Arc::clone(&flaky) as Arc<dyn AuditStore>;
    let (signer, _pk) = InProcessSigner::generate("audit-test-attrev").unwrap();
    let audit = AuditLog::new(Arc::clone(&store), Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!("{tag}-raft"));
    let _ = std::fs::remove_dir_all(&raft_dir);
    let cluster = Arc::new(
        Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnusedCredentialMaker),
        CmisConfig {
            trust_domain: "ferrogate.test".to_string(),
            ..CmisConfig::default()
        },
        audit,
        cluster,
    ));
    (state, store, flaky, TmpDirs(vec![tmp, raft_dir]))
}

async fn spawn_server(state: Arc<CmisState>) -> MachineIdentityClient<tonic::transport::Channel> {
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

/// Synthetic hardware identifiers; `tag` makes distinct hosts.
fn facts(tag: &str) -> ferro_machineid::MachineFacts {
    ferro_machineid::MachineFacts {
        board_serial: format!("WT3QF2J3YL-{tag}"),
        platform_uuid: "38D33B14-6DDD-51DD-B8CD-9854CAF977D5".to_string(),
        disk_serial: format!("0ba0206164386025-{tag}"),
    }
}

/// One host-key `Attest` (the 3-phase F15 handshake), as the MIA client
/// drives it: evidence over `nonce ‖ fingerprint`, then a CSR signed by the
/// machine key.
async fn attest_host_key(
    client: &mut MachineIdentityClient<tonic::transport::Channel>,
    facts: &ferro_machineid::MachineFacts,
    key: &SoftwareMachineKey,
) -> Result<SvidBundle, tonic::Status> {
    let (tx, rx) = mpsc::channel::<AttestRequest>(8);
    let mut responses = client
        .attest(tonic::Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();
    let Some(RespPhase::Nonce(nonce)) = responses.message().await?.and_then(|r| r.phase) else {
        panic!("the server speaks first with a nonce");
    };

    let fingerprint = facts.fingerprint();
    let normalised = facts.normalised();
    let init = AttestInit {
        host_key: Some(HostKeyEvidence {
            fingerprint: fingerprint.as_bytes().to_vec(),
            facts: Some(MachineFacts {
                board_serial: normalised.board_serial,
                platform_uuid: normalised.platform_uuid,
                disk_serial: normalised.disk_serial,
            }),
            sep_pub: key.public_spki_der(),
            signature: key
                .sign(&ferro_sep::host_key_binding(
                    &nonce.nonce,
                    fingerprint.as_bytes(),
                ))
                .unwrap(),
        }),
        hostname: "attest-revocation-test".to_string(),
        ..Default::default()
    };
    tx.send(AttestRequest {
        phase: Some(ReqPhase::Init(init)),
    })
    .await
    .unwrap();

    let (_secret, public) = ferro_crypto::composite::CompositeSecretKey::generate().unwrap();
    let composite_pub = public.to_concat_bytes();
    let aik_sig = key.sign(&composite_pub).unwrap();
    let jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(key.public_spki_der()));
    // The server may already have refused (and closed its side); the status
    // then arrives on the response stream below.
    let _ = tx
        .send(AttestRequest {
            phase: Some(ReqPhase::Csr(Csr {
                composite_pub,
                dpop_jkt: jkt,
                aik_sig,
            })),
        })
        .await;

    match responses.message().await?.and_then(|r| r.phase) {
        Some(RespPhase::Svid(bundle)) => Ok(bundle),
        other => panic!("expected an SVID or a status, got {other:?}"),
    }
}

/// Every audit event appended so far, decoded.
fn audit_events(state: &CmisState, store: &Arc<dyn AuditStore>) -> Vec<AuditEvent> {
    (0..state.audit.len() as u64)
        .map(|i| audit_event::decode(&store.read_leaf(i).unwrap()).unwrap())
        .collect()
}

fn svids_issued(events: &[AuditEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, AuditEvent::SvidIssued { .. }))
        .count()
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[tokio::test]
async fn attest_refuses_revoked_host_key_tier() {
    let (state, store, _dirs) = state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let key = SoftwareMachineKey::generate().unwrap();
    let host = facts("revoked");

    let first = attest_host_key(&mut client, &host, &key)
        .await
        .expect("an unrevoked host attests");
    state.revoke(
        RevocationTarget::Host {
            spiffe_id: first.spiffe_id.clone(),
        },
        "compromised",
        now(),
    );
    let before = audit_events(&state, &store);
    let keys_before = state.published_jwks().keys.len();

    let status = attest_host_key(&mut client, &host, &key)
        .await
        .expect_err("a revoked host must not re-attest");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), cmis::service::HOST_REVOKED);
    assert_eq!(cmis::service::HOST_REVOKED, "host_revoked");

    // Audited with the stable opcode, and nothing issued or stored.
    let after = audit_events(&state, &store);
    let new = &after[before.len()..];
    assert!(
        new.contains(&AuditEvent::AttestFail {
            reason: "attest-host-revoked".to_string(),
        }),
        "the refusal is audited: {new:?}"
    );
    assert_eq!(svids_issued(new), 0, "no SVID was issued");
    assert_eq!(
        state.published_jwks().keys.len(),
        keys_before,
        "the refused attempt's child key was not published"
    );
    let stored = state
        .lookup(&first.spiffe_id)
        .await
        .expect("first record kept");
    assert_eq!(
        stored.bundle.jws, first.jws,
        "the stored record is still the pre-revocation one"
    );
}

#[tokio::test]
async fn attest_of_unrevoked_host_still_succeeds() {
    let (state, store, _dirs) = state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;

    // Another host's revocation does not touch this one.
    let other = attest_host_key(
        &mut client,
        &facts("other"),
        &SoftwareMachineKey::generate().unwrap(),
    )
    .await
    .unwrap();
    state.revoke(
        RevocationTarget::Host {
            spiffe_id: other.spiffe_id.clone(),
        },
        "compromised",
        now(),
    );

    let key = SoftwareMachineKey::generate().unwrap();
    let host = facts("healthy");
    let first = attest_host_key(&mut client, &host, &key)
        .await
        .expect("an unrevoked host attests");
    assert_ne!(first.spiffe_id, other.spiffe_id);

    // Revoking one SVID (not the host) leaves the host free to re-attest:
    // that is how a host recovers from a single leaked credential.
    state.revoke(
        RevocationTarget::Svid {
            cert_sha: hex::encode(Sha384::digest(first.jws.as_bytes())),
        },
        "leaked",
        now(),
    );
    let before = audit_events(&state, &store).len();
    let second = attest_host_key(&mut client, &host, &key)
        .await
        .expect("an SVID revocation does not block re-attestation");
    assert_eq!(second.spiffe_id, first.spiffe_id);
    assert_ne!(second.jws, first.jws);
    let after = audit_events(&state, &store);
    assert_eq!(svids_issued(&after[before..]), 1);
    assert!(!after[before..].iter().any(|e| matches!(
        e,
        AuditEvent::AttestFail { reason } if reason == "attest-host-revoked"
    )));
}

// ---- T296: UnrevokeHost ------------------------------------------------

/// An admin request as the authorization layer hands it to the handler (the
/// layer itself, with its session and step-up checks, is covered by
/// `admin_layer.rs` and the CLI test).
fn admin<T>(msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.extensions_mut()
        .insert(cmis::admin::AdminContext::synthetic(
            "test-operator",
            cmis::admin::Permission::ALL,
        ));
    req
}

fn cert_sha(bytes: &[u8]) -> String {
    hex::encode(Sha384::digest(bytes))
}

/// The CRL CMIS publishes now, signature-checked.
fn published_crl(state: &CmisState) -> ferro_svid::CrlBody {
    let jwks = state.published_jwks();
    jwks.crl
        .as_ref()
        .expect("a CRL is published")
        .verify(&jwks)
        .expect("the CRL verifies")
        .clone()
}

/// The reason of the CRL's `cert_sha` entry for `sha`, if any.
fn entry_reason(crl: &ferro_svid::CrlBody, sha: &str) -> Option<String> {
    crl.entries.iter().find_map(|e| match &e.target {
        RevocationTarget::Svid { cert_sha } if cert_sha == sha => Some(e.reason.clone()),
        _ => None,
    })
}

async fn revoke_host_rpc(svc: &MachineIdentitySvc, spiffe_id: &str) -> u64 {
    svc.revoke_host(admin(RevokeHostRequest {
        spiffe_id: spiffe_id.to_string(),
        reason: "compromised".into(),
    }))
    .await
    .expect("RevokeHost")
    .into_inner()
    .crl_number
}

fn unrevoke_req(spiffe_id: &str) -> UnrevokeHostRequest {
    UnrevokeHostRequest {
        spiffe_id: spiffe_id.to_string(),
        reason: "re-enrolled".into(),
    }
}

fn host_unrevoked_events(events: &[AuditEvent]) -> Vec<&AuditEvent> {
    events
        .iter()
        .filter(|e| matches!(e, AuditEvent::HostUnrevoked { .. }))
        .collect()
}

#[tokio::test]
async fn unrevoke_lets_a_revoked_host_attest_again_and_keeps_its_old_svid_revoked() {
    let (state, store, _dirs) = state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let svc = MachineIdentitySvc::new(Arc::clone(&state));
    let key = SoftwareMachineKey::generate().unwrap();
    let host = facts("unrevoked");

    let first = attest_host_key(&mut client, &host, &key).await.unwrap();
    let spiffe = first.spiffe_id.clone();
    let revoked_crl = revoke_host_rpc(&svc, &spiffe).await;
    let status = attest_host_key(&mut client, &host, &key)
        .await
        .expect_err("revoked");
    assert_eq!(status.message(), cmis::service::HOST_REVOKED);

    let before = audit_events(&state, &store).len();
    let resp = svc
        .unrevoke_host(admin(unrevoke_req(&spiffe)))
        .await
        .expect("UnrevokeHost")
        .into_inner();
    assert!(resp.existed);
    assert!(resp.crl_number > revoked_crl, "the CRL is republished");

    // Audited once, attributed, naming the host and the SVID kept revoked.
    let after = audit_events(&state, &store);
    let first_sha = Sha384::digest(first.jws.as_bytes());
    assert_eq!(
        host_unrevoked_events(&after[before..]),
        vec![&AuditEvent::HostUnrevoked {
            spiffe_id: spiffe.clone(),
            reason: "re-enrolled".into(),
            by_admin_id: Some("test-operator".into()),
            svid_cert_sha: Some(Hash384(first_sha.into())),
        }]
    );

    // The host entry is gone from the working set and the published CRL;
    // the pre-un-revoke SVID and its X.509 pair are revoked by digest.
    assert!(!state.is_host_revoked(&spiffe));
    let crl = published_crl(&state);
    assert_eq!(crl.number, resp.crl_number);
    assert!(!crl.revokes_host(&spiffe));
    assert!(crl.revokes_svid(&cert_sha(first.jws.as_bytes())));
    assert!(
        !first.x509_svid.is_empty(),
        "the host-key tier issues X.509"
    );
    assert!(crl.revokes_svid(&cert_sha(&first.x509_svid)));
    for sha in [cert_sha(first.jws.as_bytes()), cert_sha(&first.x509_svid)] {
        assert_eq!(
            entry_reason(&crl, &sha).as_deref(),
            Some("compromised"),
            "kept revoked for the host's reason"
        );
    }
    assert!(
        state.is_revoked(&spiffe, &cert_sha(first.jws.as_bytes())),
        "the old SVID cannot authenticate host calls"
    );

    // The host attests again and gets a fresh, unrevoked SVID.
    let before = audit_events(&state, &store).len();
    let second = attest_host_key(&mut client, &host, &key)
        .await
        .expect("an un-revoked host attests again");
    assert_eq!(second.spiffe_id, spiffe);
    assert_ne!(second.jws, first.jws);
    assert!(!state.is_revoked(&spiffe, &cert_sha(second.jws.as_bytes())));
    let after = audit_events(&state, &store);
    assert_eq!(svids_issued(&after[before..]), 1);
}

#[tokio::test]
async fn unrevoke_lifts_only_that_hosts_entry() {
    let (state, _store, _dirs) = state().await;
    let svc = MachineIdentitySvc::new(Arc::clone(&state));
    let (a, b) = (
        "spiffe://ferrogate.test/host/aaaa",
        "spiffe://ferrogate.test/host/bbbb",
    );
    let leaked = hex::encode([0xCD; 48]);
    revoke_host_rpc(&svc, a).await;
    revoke_host_rpc(&svc, b).await;
    svc.revoke_svid(admin(RevokeSvidRequest {
        cert_sha: leaked.clone(),
        reason: "leaked".into(),
    }))
    .await
    .unwrap();

    let resp = svc
        .unrevoke_host(admin(unrevoke_req(a)))
        .await
        .unwrap()
        .into_inner();
    assert!(resp.existed);
    let crl = published_crl(&state);
    assert!(!crl.revokes_host(a));
    assert!(crl.revokes_host(b), "another host's entry stays");
    assert!(crl.revokes_svid(&leaked), "a RevokeSvid entry stays");
    assert!(state.is_host_revoked(b));
}

#[tokio::test]
async fn unrevoking_a_host_that_is_not_revoked_is_a_no_op() {
    let (state, _store, _dirs) = state().await;
    let svc = MachineIdentitySvc::new(Arc::clone(&state));
    let host = "spiffe://ferrogate.test/host/cccc";
    // Only an SVID entry exists; un-revoking the host must not lift it.
    let leaked = hex::encode([0xEF; 48]);
    svc.revoke_svid(admin(RevokeSvidRequest {
        cert_sha: leaked.clone(),
        reason: "leaked".into(),
    }))
    .await
    .unwrap();
    let crl_before = published_crl(&state).number;
    let audit_before = state.audit.len();

    for _ in 0..2 {
        let resp = svc
            .unrevoke_host(admin(unrevoke_req(host)))
            .await
            .expect("a no-op, not an error")
            .into_inner();
        assert!(!resp.existed);
        assert_eq!(resp.crl_number, 0, "no CRL published for a no-op");
    }
    assert_eq!(state.audit.len(), audit_before, "nothing recorded");
    let crl = published_crl(&state);
    assert_eq!(crl.number, crl_before);
    assert!(crl.revokes_svid(&leaked));

    let empty = svc
        .unrevoke_host(admin(unrevoke_req("")))
        .await
        .expect_err("empty id");
    assert_eq!(empty.code(), tonic::Code::InvalidArgument);
    let long = svc
        .unrevoke_host(admin(unrevoke_req(&"x".repeat(2049))))
        .await
        .expect_err("oversized id");
    assert_eq!(long.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn unrevoke_without_svid_revoke_is_refused_and_the_host_stays_refused() {
    let (state, store, _dirs) = state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let svc = MachineIdentitySvc::new(Arc::clone(&state));
    let key = SoftwareMachineKey::generate().unwrap();
    let host = facts("unauthorized");
    let first = attest_host_key(&mut client, &host, &key).await.unwrap();
    revoke_host_rpc(&svc, &first.spiffe_id).await;

    let no_session = svc
        .unrevoke_host(tonic::Request::new(unrevoke_req(&first.spiffe_id)))
        .await
        .expect_err("no admin context");
    assert_eq!(no_session.code(), tonic::Code::Unauthenticated);
    let mut viewer = tonic::Request::new(unrevoke_req(&first.spiffe_id));
    viewer
        .extensions_mut()
        .insert(cmis::admin::AdminContext::synthetic(
            "viewer",
            [
                cmis::admin::Permission::HostList,
                cmis::admin::Permission::SvidList,
            ],
        ));
    let denied = svc.unrevoke_host(viewer).await.expect_err("no svid.revoke");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    assert!(state.is_host_revoked(&first.spiffe_id));
    assert_eq!(
        host_unrevoked_events(&audit_events(&state, &store)).len(),
        0,
        "no HostUnrevoked leaf"
    );
    let status = attest_host_key(&mut client, &host, &key)
        .await
        .expect_err("still revoked");
    assert_eq!(status.message(), cmis::service::HOST_REVOKED);
}

#[tokio::test]
async fn unrevoke_fails_closed_when_the_audit_log_cannot_record_it() {
    let (state, store, flaky, _dirs) = state_with_flaky_audit().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let svc = MachineIdentitySvc::new(Arc::clone(&state));
    let key = SoftwareMachineKey::generate().unwrap();
    let host = facts("audit-down");
    let first = attest_host_key(&mut client, &host, &key).await.unwrap();
    let crl_number = revoke_host_rpc(&svc, &first.spiffe_id).await;

    flaky.fail_appends.store(true, Ordering::SeqCst);
    let status = svc
        .unrevoke_host(admin(unrevoke_req(&first.spiffe_id)))
        .await
        .expect_err("no audit, no un-revoke");
    assert_eq!(
        (status.code(), status.message()),
        (tonic::Code::Unavailable, "audit log unavailable")
    );
    flaky.fail_appends.store(false, Ordering::SeqCst);

    assert!(state.is_host_revoked(&first.spiffe_id), "nothing changed");
    assert!(!state.is_revoked("spiffe://other", &cert_sha(first.jws.as_bytes())));
    assert_eq!(published_crl(&state).number, crl_number, "no republish");
    assert_eq!(
        host_unrevoked_events(&audit_events(&state, &store)).len(),
        0,
        "no HostUnrevoked leaf"
    );
    let refused = attest_host_key(&mut client, &host, &key)
        .await
        .expect_err("still revoked");
    assert_eq!(refused.message(), cmis::service::HOST_REVOKED);
}

#[tokio::test]
async fn unrevoke_fails_closed_when_the_stored_record_is_unreadable() {
    let (state, store, _dirs) = state().await;
    let svc = MachineIdentitySvc::new(Arc::clone(&state));
    let spiffe = "spiffe://ferrogate.test/host/dddd";
    revoke_host_rpc(&svc, spiffe).await;
    state
        .cluster()
        .upsert_svid(spiffe, b"not a record", now())
        .await
        .unwrap();

    let status = svc
        .unrevoke_host(admin(unrevoke_req(spiffe)))
        .await
        .expect_err("unreadable record");
    assert_eq!(
        (status.code(), status.message()),
        (tonic::Code::Unavailable, "store_unavailable")
    );
    assert!(state.is_host_revoked(spiffe), "nothing changed");
    assert_eq!(
        host_unrevoked_events(&audit_events(&state, &store)).len(),
        0,
        "no HostUnrevoked leaf"
    );
}

#[tokio::test]
async fn unrevoke_leaves_an_existing_svid_revocation_as_it_was() {
    let (state, _store, _dirs) = state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let svc = MachineIdentitySvc::new(Arc::clone(&state));
    let key = SoftwareMachineKey::generate().unwrap();
    let first = attest_host_key(&mut client, &facts("svid-first"), &key)
        .await
        .unwrap();
    let jws_sha = cert_sha(first.jws.as_bytes());
    svc.revoke_svid(admin(RevokeSvidRequest {
        cert_sha: jws_sha.clone(),
        reason: "leaked".into(),
    }))
    .await
    .unwrap();
    revoke_host_rpc(&svc, &first.spiffe_id).await;
    let before = published_crl(&state)
        .entries
        .iter()
        .find(|e| matches!(&e.target, RevocationTarget::Svid { cert_sha } if *cert_sha == jws_sha))
        .cloned()
        .expect("the SVID entry");

    svc.unrevoke_host(admin(unrevoke_req(&first.spiffe_id)))
        .await
        .unwrap();
    let crl = published_crl(&state);
    let after = crl
        .entries
        .iter()
        .find(|e| matches!(&e.target, RevocationTarget::Svid { cert_sha } if *cert_sha == jws_sha))
        .expect("still revoked");
    assert_eq!(after, &before, "reason and timestamps unchanged");
    assert!(!crl.revokes_host(&first.spiffe_id));
}
