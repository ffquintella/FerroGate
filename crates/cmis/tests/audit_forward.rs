//! `AppendAuditEvent` host proof (F20 Phase 0, F19 §7.1 `HostCallAuth`).
//!
//! A host forwards an audit event by signing an `AuditForwardDoc`
//! `{v, host_uuid, issued_at, nonce, event_sha384}` with the machine key its
//! SVID is bound to (`cnf.jkt`), under context `ferrogate-audit-forward-v1`.
//! These tests drive the handler against an in-process CMIS and check that
//! only a fresh, unreplayed proof from an unrevoked host, within its rate
//! limit, appends anything — and that every refusal leaves the log untouched.

#![allow(clippy::large_futures)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditEvent, AuditLog, AuditStore, Bytes16, Hash384, InProcessSigner};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::{AppendAuditRequest, HostCallAuth};
use ferro_raft::Cluster;
use ferro_sep::{MachineKey, SoftwareMachineKey};
use ferro_svid::host_call::{self, AuditForwardDoc, AUDIT_FORWARD_CONTEXT};
use ferro_svid::{host_uuid_from_ek_digest, IssueParams, Issuer, RevocationTarget};
use sha2::{Digest, Sha256, Sha384};
use tonic::Code;

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

struct TmpDirs(Vec<std::path::PathBuf>);
impl Drop for TmpDirs {
    fn drop(&mut self) {
        for dir in &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// One attested host: its machine key, the SVID bound to it, its UUID.
struct Host {
    key: SoftwareMachineKey,
    jws: String,
    uuid: String,
    spiffe_id: String,
}

fn mint_host(issuer: &Issuer, ek_byte: u8) -> Host {
    let key = SoftwareMachineKey::generate().unwrap();
    let jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(key.public_spki_der()));
    let ek_sha = [ek_byte; 48];
    let minted = issuer
        .issue(
            &IssueParams {
                ek_cert_sha384: ek_sha,
                pcr_digest: [0u8; 48],
                policy_id: "p1".into(),
                dpop_jkt: jkt,
                ttl_secs: 3600,
                tee_evidence_id: None,
                subject_pub: None,
            },
            now_unix(),
        )
        .unwrap();
    Host {
        key,
        jws: minted.jws,
        uuid: host_uuid_from_ek_digest(&ek_sha).to_string(),
        spiffe_id: minted.spiffe_id,
    }
}

struct Fixture {
    svc: MachineIdentitySvc,
    state: Arc<CmisState>,
    host: Host,
    other: Host,
    _dirs: TmpDirs,
}

async fn setup_with(config: CmisConfig) -> Fixture {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let issuer = Issuer::generate("cmis-test-fwd", "ferrogate.test").unwrap();
    let host = mint_host(&issuer, 0x42);
    let other = mint_host(&issuer, 0x43);

    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(format!("ferrogate-cmis-fwd-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(ferro_audit::LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-fwd").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!(
        "ferrogate-cmis-fwd-raft-{}-{n}",
        std::process::id()
    ));
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
        config,
        audit,
        cluster,
    ));
    Fixture {
        svc: MachineIdentitySvc::new(Arc::clone(&state)),
        state,
        host,
        other,
        _dirs: TmpDirs(vec![tmp, raft_dir]),
    }
}

async fn setup() -> Fixture {
    setup_with(CmisConfig::default()).await
}

fn grant(pid: u32) -> AuditEvent {
    AuditEvent::LocalGrant {
        pid,
        uid: 1000,
        bin_sha: Hash384([0xAA; 48]),
        jti: Bytes16([0x55; 16]),
    }
}

fn nonce(n: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = n;
    out[15] = 0xF0;
    out
}

/// What a test may vary when building a proof.
struct Proof<'a> {
    signer: &'a Host,
    svid_of: &'a Host,
    doc_host_uuid: Option<&'a str>,
    issued_at: i64,
    nonce: [u8; 16],
    context: &'a [u8],
}

impl<'a> Proof<'a> {
    fn honest(host: &'a Host, nonce_byte: u8) -> Self {
        Self {
            signer: host,
            svid_of: host,
            doc_host_uuid: None,
            issued_at: now_unix(),
            nonce: nonce(nonce_byte),
            context: AUDIT_FORWARD_CONTEXT,
        }
    }

    fn request(&self, event: &AuditEvent) -> AppendAuditRequest {
        let event_cbor = ferro_audit::event::encode(event).unwrap();
        let doc = AuditForwardDoc::new(
            self.doc_host_uuid.unwrap_or(&self.svid_of.uuid),
            self.issued_at,
            self.nonce,
            &event_cbor,
        );
        let doc = host_call::encode_audit_forward(&doc).unwrap();
        let sig = self
            .signer
            .key
            .sign(&host_call::signing_input(self.context, &doc))
            .unwrap();
        AppendAuditRequest {
            event_cbor,
            auth: Some(HostCallAuth {
                svid_jws: self.svid_of.jws.clone(),
                sep_pub: self.signer.key.public_spki_der(),
                sig,
            }),
            doc,
        }
    }
}

async fn append(f: &Fixture, req: AppendAuditRequest) -> Result<u64, tonic::Status> {
    f.svc
        .append_audit_event(tonic::Request::new(req))
        .await
        .map(|r| r.into_inner().leaf_index)
}

/// Assert `req` is refused with `(code, message)` and appends nothing.
async fn refused(f: &Fixture, req: AppendAuditRequest, code: Code, message: &str) {
    let before = f.state.audit.len();
    let e = append(f, req).await.expect_err("must be refused");
    assert_eq!((e.code(), e.message()), (code, message));
    assert_eq!(
        f.state.audit.len(),
        before,
        "a refused call appends nothing"
    );
}

#[tokio::test]
async fn a_host_signed_event_is_appended() {
    let f = setup().await;
    let before = f.state.audit.len();
    let req = Proof::honest(&f.host, 1).request(&grant(1));
    let expected_leaf = ferro_audit::leaf_hash(&req.event_cbor);
    let idx = append(&f, req).await.expect("accepted");
    assert_eq!(idx, u64::try_from(before).unwrap());
    assert_eq!(f.state.audit.len(), before + 1);
    let proof = f.state.audit.inclusion_proof(idx).unwrap();
    assert_eq!(
        proof.leaf_hash, expected_leaf,
        "the event is stored verbatim"
    );
}

#[tokio::test]
async fn an_unsigned_event_is_refused() {
    let f = setup().await;
    let event_cbor = ferro_audit::event::encode(&grant(1)).unwrap();
    refused(
        &f,
        AppendAuditRequest {
            event_cbor,
            auth: None,
            doc: Vec::new(),
        },
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
}

#[tokio::test]
async fn a_proof_with_a_bad_signature_is_refused() {
    let f = setup().await;
    let mut req = Proof::honest(&f.host, 1).request(&grant(1));
    req.auth.as_mut().unwrap().sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    refused(&f, req, Code::Unauthenticated, "host_auth_failed").await;
}

#[tokio::test]
async fn a_document_naming_another_host_is_refused() {
    let f = setup().await;
    let other_uuid = f.other.uuid.clone();
    let mut p = Proof::honest(&f.host, 1);
    p.doc_host_uuid = Some(&other_uuid);
    refused(
        &f,
        p.request(&grant(1)),
        Code::PermissionDenied,
        "host_mismatch",
    )
    .await;
}

#[tokio::test]
async fn another_hosts_key_cannot_use_this_hosts_svid() {
    let f = setup().await;
    let mut p = Proof::honest(&f.host, 1);
    // The other host's machine key signs, presenting this host's SVID.
    p.signer = &f.other;
    refused(
        &f,
        p.request(&grant(1)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
}

#[tokio::test]
async fn an_svid_from_another_issuer_is_refused() {
    let f = setup().await;
    let foreign = mint_host(&Issuer::generate("other", "ferrogate.test").unwrap(), 0x42);
    refused(
        &f,
        Proof::honest(&foreign, 1).request(&grant(1)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
}

#[tokio::test]
async fn a_stale_or_future_issued_at_is_refused() {
    // The window is ±300 s; the offsets leave a few seconds of slack because
    // the handler reads the wall clock after the test does.
    let f = setup().await;
    let mut p = Proof::honest(&f.host, 1);
    p.issued_at = now_unix() - 301;
    refused(
        &f,
        p.request(&grant(1)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
    let mut p = Proof::honest(&f.host, 2);
    p.issued_at = now_unix() + 305;
    refused(
        &f,
        p.request(&grant(1)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
    // Inside the window both ways is fine.
    let mut p = Proof::honest(&f.host, 3);
    p.issued_at = now_unix() - 250;
    append(&f, p.request(&grant(1))).await.expect("250 s old");
    let mut p = Proof::honest(&f.host, 4);
    p.issued_at = now_unix() + 250;
    append(&f, p.request(&grant(1)))
        .await
        .expect("250 s ahead (host clock skew)");
}

#[tokio::test]
async fn a_replayed_nonce_is_refused() {
    let f = setup().await;
    let req = Proof::honest(&f.host, 9).request(&grant(1));
    append(&f, req.clone()).await.expect("first use");
    refused(&f, req, Code::Unauthenticated, "host_auth_failed").await;
    // The same nonce with a different event is still a replay.
    refused(
        &f,
        Proof::honest(&f.host, 9).request(&grant(2)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
    // Another host may use the same nonce value: the cache key is
    // (host_uuid, nonce).
    append(&f, Proof::honest(&f.other, 9).request(&grant(1)))
        .await
        .expect("other host, same nonce");
}

#[tokio::test]
async fn a_tampered_event_is_refused() {
    let f = setup().await;
    let mut req = Proof::honest(&f.host, 1).request(&grant(1));
    req.event_cbor = ferro_audit::event::encode(&grant(666)).unwrap();
    refused(&f, req, Code::Unauthenticated, "host_auth_failed").await;
    // A tampered request does not burn the nonce of the genuine one.
    append(&f, Proof::honest(&f.host, 1).request(&grant(1)))
        .await
        .expect("the genuine request still goes through");
}

#[tokio::test]
async fn a_tampered_document_is_refused() {
    let f = setup().await;
    let mut req = Proof::honest(&f.host, 1).request(&grant(1));
    let last = req.doc.len() - 1;
    req.doc[last] ^= 0x01;
    refused(&f, req, Code::Unauthenticated, "host_auth_failed").await;
}

#[tokio::test]
async fn a_signature_under_another_context_is_refused() {
    let f = setup().await;
    let mut p = Proof::honest(&f.host, 1);
    p.context = ferro_svid::PROPOSAL_SIGNING_CONTEXT;
    refused(
        &f,
        p.request(&grant(1)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
}

#[tokio::test]
async fn a_revoked_host_is_refused() {
    let f = setup().await;
    f.state.revoke(
        RevocationTarget::Host {
            spiffe_id: f.host.spiffe_id.clone(),
        },
        "compromised",
        now_unix(),
    );
    refused(
        &f,
        Proof::honest(&f.host, 1).request(&grant(1)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
    // Other hosts are unaffected.
    append(&f, Proof::honest(&f.other, 1).request(&grant(1)))
        .await
        .expect("unrevoked host");
}

#[tokio::test]
async fn a_revoked_svid_is_refused() {
    let f = setup().await;
    f.state.revoke(
        RevocationTarget::Svid {
            cert_sha: hex::encode(Sha384::digest(f.host.jws.as_bytes())),
        },
        "superseded",
        now_unix(),
    );
    refused(
        &f,
        Proof::honest(&f.host, 1).request(&grant(1)),
        Code::Unauthenticated,
        "host_auth_failed",
    )
    .await;
}

/// A host may forward only the events a host produces; CMIS-side events
/// (admin actions, issuance) cannot be forged into the log by a host.
#[tokio::test]
async fn cmis_only_event_types_are_refused() {
    let f = setup().await;
    let forged = AuditEvent::AllowlistSet {
        by_admin_id: Some("0192-forged-admin".into()),
        host_uuid: f.host.uuid.clone(),
        entry_count: 1,
        not_after: now_unix() + 3600,
    };
    refused(
        &f,
        Proof::honest(&f.host, 1).request(&forged),
        Code::PermissionDenied,
        "event_not_forwardable",
    )
    .await;
    let config_changed = AuditEvent::ConfigChanged {
        path: "/etc/ferrogate/mia.toml".into(),
        by_uid: 0,
        keys: vec!["cmis.endpoint".into()],
    };
    append(&f, Proof::honest(&f.host, 2).request(&config_changed))
        .await
        .expect("host-originated event");
}

#[tokio::test]
async fn an_oversized_event_is_refused_before_any_crypto() {
    let f = setup().await;
    let mut req = Proof::honest(&f.host, 1).request(&grant(1));
    req.event_cbor = vec![0u8; 64 * 1024 + 1];
    refused(&f, req, Code::InvalidArgument, "field_too_long").await;
}

#[tokio::test]
async fn a_host_over_its_rate_limit_is_refused() {
    let f = setup_with(CmisConfig {
        host_calls: cmis::host_auth::HostCallConfig {
            audit_forward_per_min: 2,
            ..Default::default()
        },
        ..CmisConfig::default()
    })
    .await;
    append(&f, Proof::honest(&f.host, 1).request(&grant(1)))
        .await
        .expect("1st");
    append(&f, Proof::honest(&f.host, 2).request(&grant(2)))
        .await
        .expect("2nd");
    let before = f.state.audit.len();
    let e = append(&f, Proof::honest(&f.host, 3).request(&grant(3)))
        .await
        .expect_err("3rd call in the same minute");
    assert_eq!(
        (e.code(), e.message()),
        (Code::ResourceExhausted, "rate_limited")
    );
    // 2 per minute refills one call every 30 s. The handler reads the wall
    // clock, so a second may tick between the calls (exact arithmetic is
    // covered by the `host_auth` unit tests on a controlled clock).
    let retry_after: u64 = e
        .metadata()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("a numeric retry-after");
    assert!(
        (28..=30).contains(&retry_after),
        "retry-after {retry_after}"
    );
    assert_eq!(f.state.audit.len(), before);
    // The budget is per host.
    append(&f, Proof::honest(&f.other, 1).request(&grant(1)))
        .await
        .expect("another host has its own budget");
    // A replay is refused as a replay, without touching the budget.
    let e = append(&f, Proof::honest(&f.host, 1).request(&grant(1)))
        .await
        .expect_err("replay");
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "host_auth_failed")
    );
}
