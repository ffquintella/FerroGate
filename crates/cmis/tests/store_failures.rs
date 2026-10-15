//! Store write failures are returned, never swallowed (F19 §7.4, F20 Phase
//! 0): when the replicated store refuses a write, the legacy allowlist and
//! proposal RPCs answer `UNAVAILABLE (store_unavailable)` instead of
//! reporting success, and record no audit event for the change that did not
//! happen.
//!
//! The failure is injected with a SQLite trigger through the cluster's
//! client escape hatch, so the cluster stays healthy and only the targeted
//! table refuses writes — no production test hooks.

#![allow(clippy::large_futures)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::state::ProposalPolicy;
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::{
    AllowEntryMsg, DeleteAllowlistRequest, DeleteProposalRequest, GetAllowlistRequest,
    ListProposalsRequest, ProposeAllowlistRequest, SetAllowlistRequest,
};
use ferro_raft::Cluster;
use ferro_sep::{MachineKey, SoftwareMachineKey};
use ferro_svid::allowlist::{self, AllowEntry, ProposalDoc};
use ferro_svid::{host_uuid_from_ek_digest, IssueParams, Issuer};
use sha2::{Digest, Sha256};
use tonic::Code;

fn admin<T>(msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.extensions_mut()
        .insert(cmis::admin::AdminContext::synthetic(
            "test-operator",
            cmis::admin::Permission::ALL,
        ));
    req
}

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

struct Fixture {
    svc: MachineIdentitySvc,
    state: Arc<CmisState>,
    key: SoftwareMachineKey,
    host: String,
    jws: String,
    _dirs: TmpDirs,
}

async fn setup(policy: ProposalPolicy) -> Fixture {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let issuer = Issuer::generate("cmis-test-store", "ferrogate.test").unwrap();
    let key = SoftwareMachineKey::generate().unwrap();
    let ek_sha = [0x42u8; 48];
    let jws = issuer
        .issue(
            &IssueParams {
                ek_cert_sha384: ek_sha,
                pcr_digest: [0u8; 48],
                policy_id: "p1".into(),
                dpop_jkt: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(key.public_spki_der())),
                ttl_secs: 3600,
                tee_evidence_id: None,
                subject_pub: None,
            },
            now_unix(),
        )
        .unwrap()
        .jws;
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(format!("ferrogate-cmis-store-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-store").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!(
        "ferrogate-cmis-store-raft-{}-{n}",
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
        CmisConfig {
            allowlist_proposal_policy: policy,
            ..CmisConfig::default()
        },
        audit,
        cluster,
    ));
    Fixture {
        svc: MachineIdentitySvc::new(Arc::clone(&state)),
        state,
        key,
        host: host_uuid_from_ek_digest(&ek_sha).to_string(),
        jws,
        _dirs: TmpDirs(vec![tmp, raft_dir]),
    }
}

/// Make every `op` (`INSERT` or `DELETE`) on `table` fail.
async fn fail_writes(f: &Fixture, table: &str, op: &str) {
    f.state
        .cluster()
        .client()
        .execute(
            format!(
                "CREATE TRIGGER fail_{op}_{table} BEFORE {op} ON {table} \
                 BEGIN SELECT RAISE(ABORT, 'injected store failure'); END"
            ),
            vec![],
        )
        .await
        .expect("trigger installed");
}

fn set_req(host: &str) -> SetAllowlistRequest {
    SetAllowlistRequest {
        host_uuid: host.into(),
        entries: vec![AllowEntryMsg {
            uid: Some(1000),
            bin_sha: hex::encode([0xAB; 48]),
        }],
        ttl_secs: 3600,
    }
}

fn proposal(f: &Fixture) -> ProposeAllowlistRequest {
    let body = allowlist::encode_proposal(&ProposalDoc {
        host_uuid: f.host.clone(),
        issued_at: now_unix(),
        entries: vec![AllowEntry {
            uid: Some(1000),
            bin_sha: hex::encode([0xCD; 48]),
        }],
    })
    .unwrap();
    let sig = f
        .key
        .sign(&allowlist::proposal_signing_input(&body))
        .unwrap();
    ProposeAllowlistRequest {
        signed_proposal: body,
        proposal_sig: sig,
        svid_jws: f.jws.clone(),
        sep_pub: f.key.public_spki_der(),
    }
}

fn assert_store_unavailable(e: &tonic::Status) {
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unavailable, "store_unavailable")
    );
}

#[tokio::test]
async fn set_allowlist_fails_when_the_store_refuses_the_write() {
    let f = setup(ProposalPolicy::BootstrapOnly).await;
    fail_writes(&f, "host_allowlists", "INSERT").await;
    let audit_before = f.state.audit.len();
    let e = f
        .svc
        .set_allowlist(admin(set_req(&f.host)))
        .await
        .expect_err("a failed write is not a success");
    assert_store_unavailable(&e);
    assert_eq!(f.state.audit.len(), audit_before, "no AllowlistSet event");
    let got = f
        .svc
        .get_allowlist(tonic::Request::new(GetAllowlistRequest {
            host_uuid: f.host.clone(),
            accept_formats: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(got.signed_allowlist.is_empty(), "nothing was stored");
}

#[tokio::test]
async fn auto_adopted_proposal_fails_when_the_store_refuses_the_write() {
    let f = setup(ProposalPolicy::BootstrapOnly).await;
    fail_writes(&f, "host_allowlists", "INSERT").await;
    let audit_before = f.state.audit.len();
    let e = f
        .svc
        .propose_allowlist(tonic::Request::new(proposal(&f)))
        .await
        .expect_err("a failed adoption is not AutoAdopted");
    assert_store_unavailable(&e);
    assert_eq!(
        f.state.audit.len(),
        audit_before,
        "no AllowlistAutoAdopted event"
    );
}

#[tokio::test]
async fn queued_proposal_fails_when_the_store_refuses_the_write() {
    let f = setup(ProposalPolicy::Off).await;
    fail_writes(&f, "pending_allowlist_proposals", "INSERT").await;
    let audit_before = f.state.audit.len();
    let e = f
        .svc
        .propose_allowlist(tonic::Request::new(proposal(&f)))
        .await
        .expect_err("a failed queue write is not Pending");
    assert_store_unavailable(&e);
    assert_eq!(
        f.state.audit.len(),
        audit_before,
        "no AllowlistProposed event"
    );
    let listed = f
        .svc
        .list_proposals(admin(ListProposalsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.items, []);
}

#[tokio::test]
async fn delete_allowlist_fails_when_the_store_refuses_the_write() {
    let f = setup(ProposalPolicy::BootstrapOnly).await;
    f.svc.set_allowlist(admin(set_req(&f.host))).await.unwrap();
    fail_writes(&f, "host_allowlists", "DELETE").await;
    let audit_before = f.state.audit.len();
    let e = f
        .svc
        .delete_allowlist(admin(DeleteAllowlistRequest {
            host_uuid: f.host.clone(),
        }))
        .await
        .expect_err("a failed delete is neither `existed` nor `absent`");
    assert_store_unavailable(&e);
    assert_eq!(
        f.state.audit.len(),
        audit_before,
        "no AllowlistDeleted event"
    );
}

#[tokio::test]
async fn delete_proposal_fails_when_the_store_refuses_the_write() {
    let f = setup(ProposalPolicy::Off).await;
    f.svc
        .propose_allowlist(tonic::Request::new(proposal(&f)))
        .await
        .unwrap();
    fail_writes(&f, "pending_allowlist_proposals", "DELETE").await;
    let audit_before = f.state.audit.len();
    let e = f
        .svc
        .delete_proposal(admin(DeleteProposalRequest {
            host_uuid: f.host.clone(),
        }))
        .await
        .expect_err("a failed delete is neither `existed` nor `absent`");
    assert_store_unavailable(&e);
    assert_eq!(f.state.audit.len(), audit_before);
}
