//! T295: `Attest` refuses a host whose SPIFFE id is revoked
//! (`RevocationTarget::Host`), so `RevokeHost` cannot be undone by simply
//! re-attesting. Driven over a real tonic channel on the host-key tier (the
//! TPM tier is covered end to end in `crates/mia/tests/e2e_attest.rs`); the
//! refusal is `PERMISSION_DENIED host_revoked`, audited as
//! `AttestFail { reason: "attest-host-revoked" }`, and nothing is issued.

#![allow(clippy::large_futures)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::LocalDiskWormStore;
use ferro_audit::{event as audit_event, AuditEvent, AuditLog, AuditStore, InProcessSigner};
use ferro_proto::v1::attest_request::Phase as ReqPhase;
use ferro_proto::v1::attest_response::Phase as RespPhase;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{AttestInit, AttestRequest, Csr, HostKeyEvidence, MachineFacts, SvidBundle};
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

/// A CMIS for the host-key tier plus a handle on its audit store, so the
/// test can read back the events it appended, and the guard that removes
/// its directories.
async fn state() -> (Arc<CmisState>, Arc<dyn AuditStore>, TmpDirs) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tag = format!("ferrogate-cmis-attrev-{}-{seq}", std::process::id());
    let issuer = Issuer::generate("cmis-test-attrev", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(&tag);
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
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
    (state, store, TmpDirs(vec![tmp, raft_dir]))
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
