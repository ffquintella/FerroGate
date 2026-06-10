//! Host-driven allowlist proposals. These tests drive the `ProposeAllowlist`,
//! `ListProposals`, and `DeleteProposal` RPCs against an in-process CMIS,
//! exercising the SVID/signature binding and the bootstrap-vs-review policy.
//!
//! A proposal is bound to an attested host the same way mia does it: mint a host
//! SVID whose `cnf.jkt` is the SHA-256 of a machine key's SPKI, then sign the
//! CBOR `ProposalDoc` with that key. CMIS re-verifies the SVID under its own
//! issuer key, checks the signature against `sep_pub`, and confirms the host
//! UUID matches.

#![allow(clippy::large_futures)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::state::ProposalPolicy;
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::composite::CompositePublicKey;
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::propose_allowlist_response::Outcome;
use ferro_proto::v1::{
    AllowEntryMsg, DeleteProposalRequest, GetAllowlistRequest, GetEnrollmentKeyRequest,
    ListProposalsRequest, ProposeAllowlistRequest, SetAllowlistRequest,
};
use ferro_raft::Cluster;
use ferro_sep::{MachineKey, SoftwareMachineKey};
use ferro_svid::allowlist::{self, AllowEntry, ProposalDoc};
use ferro_svid::{host_uuid_from_ek_digest, IssueParams, Issuer};
use sha2::{Digest, Sha256};

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

/// Build an in-process CMIS with `policy`, plus a host machine key and a fresh
/// SVID bound to it (issued at "now" so the validity check passes).
async fn setup(
    policy: ProposalPolicy,
) -> (MachineIdentitySvc, SoftwareMachineKey, String, String, TmpDirs) {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let issuer = Issuer::generate("cmis-test-prop", "ferrogate.test").unwrap();

    // The host's machine key, and the SVID that binds it via cnf.jkt.
    let key = SoftwareMachineKey::generate().unwrap();
    let jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(key.public_spki_der()));
    let ek_sha = [0x42u8; 48];
    let host_uuid = host_uuid_from_ek_digest(&ek_sha).to_string();
    let minted = issuer
        .issue(
            &IssueParams {
                ek_cert_sha384: ek_sha,
                pcr_digest: [0u8; 48],
                policy_id: "p1".into(),
                dpop_jkt: jkt,
                ttl_secs: 3600,
                tee_evidence_id: None,
            },
            now_unix(),
        )
        .unwrap();
    let jws = minted.jws;

    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(format!("ferrogate-cmis-prop-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-prop").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let config = CmisConfig {
        allowlist_proposal_policy: policy,
        ..CmisConfig::default()
    };
    let raft_dir =
        std::env::temp_dir().join(format!("ferrogate-cmis-prop-raft-{}-{n}", std::process::id()));
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
    (
        MachineIdentitySvc::new(state),
        key,
        host_uuid,
        jws,
        TmpDirs(vec![tmp, raft_dir]),
    )
}

fn entry(uid: u32, byte: u8) -> AllowEntry {
    AllowEntry {
        uid,
        bin_sha: hex::encode([byte; 48]),
    }
}

/// Build a signed proposal request for `host_uuid` with `entries`.
fn proposal_req(
    key: &SoftwareMachineKey,
    host_uuid: &str,
    entries: Vec<AllowEntry>,
    jws: &str,
) -> ProposeAllowlistRequest {
    let doc = ProposalDoc {
        host_uuid: host_uuid.to_string(),
        issued_at: now_unix(),
        entries,
    };
    let body = allowlist::encode_proposal(&doc).unwrap();
    let sig = key.sign(&allowlist::proposal_signing_input(&body)).unwrap();
    ProposeAllowlistRequest {
        signed_proposal: body,
        proposal_sig: sig,
        svid_jws: jws.to_string(),
        sep_pub: key.public_spki_der(),
    }
}

async fn enrollment_key(svc: &MachineIdentitySvc) -> CompositePublicKey {
    let resp = svc
        .get_enrollment_key(tonic::Request::new(GetEnrollmentKeyRequest {}))
        .await
        .unwrap()
        .into_inner();
    CompositePublicKey::from_concat_bytes(&resp.public_key).unwrap()
}

#[tokio::test]
async fn bootstrap_auto_adopts_when_no_allowlist() {
    let (svc, key, host, jws, _g) = setup(ProposalPolicy::BootstrapOnly).await;
    let pk = enrollment_key(&svc).await;

    let resp = svc
        .propose_allowlist(tonic::Request::new(proposal_req(
            &key,
            &host,
            vec![entry(1000, 0xAA), entry(1001, 0xBB)],
            &jws,
        )))
        .await
        .expect("propose ok")
        .into_inner();
    assert_eq!(resp.outcome, Outcome::AutoAdopted as i32);
    assert!(resp.not_after > resp.issued_at);

    // The adopted allowlist is now served and verifies under the enrollment key.
    let got = svc
        .get_allowlist(tonic::Request::new(GetAllowlistRequest {
            host_uuid: host.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let signed = allowlist::decode(&got.signed_allowlist).unwrap();
    let doc = allowlist::verify(&signed, &pk).expect("adopted allowlist verifies");
    assert_eq!(doc.entries.len(), 2);

    // Re-proposing the same set is a no-op.
    let again = svc
        .propose_allowlist(tonic::Request::new(proposal_req(
            &key,
            &host,
            vec![entry(1000, 0xAA), entry(1001, 0xBB)],
            &jws,
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.outcome, Outcome::Unchanged as i32);
}

#[tokio::test]
async fn existing_allowlist_queues_proposal_for_review() {
    let (svc, key, host, jws, _g) = setup(ProposalPolicy::BootstrapOnly).await;

    // An operator has already provisioned an allowlist.
    svc.set_allowlist(tonic::Request::new(SetAllowlistRequest {
        host_uuid: host.clone(),
        entries: vec![AllowEntryMsg {
            uid: 1,
            bin_sha: hex::encode([0x01u8; 48]),
        }],
        ttl_secs: 3600,
    }))
    .await
    .unwrap();

    // A proposal with new callers must not auto-adopt; it queues.
    let resp = svc
        .propose_allowlist(tonic::Request::new(proposal_req(
            &key,
            &host,
            vec![entry(1000, 0xAA)],
            &jws,
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.outcome, Outcome::Pending as i32);

    let pending = svc
        .list_proposals(tonic::Request::new(ListProposalsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(pending.items.len(), 1);
    assert_eq!(pending.items[0].host_uuid, host);
    assert_eq!(pending.items[0].entries.len(), 1);
    assert_eq!(pending.items[0].entries[0].uid, 1000);

    // The live allowlist is untouched while the proposal waits.
    let got = svc
        .get_allowlist(tonic::Request::new(GetAllowlistRequest {
            host_uuid: host.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let doc = allowlist::decode_body(&allowlist::decode(&got.signed_allowlist).unwrap().body).unwrap();
    assert_eq!(doc.entries[0].uid, 1);

    // Rejecting drops it.
    let del = svc
        .delete_proposal(tonic::Request::new(DeleteProposalRequest {
            host_uuid: host.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(del.existed);
    let empty = svc
        .list_proposals(tonic::Request::new(ListProposalsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(empty.items.is_empty());
}

#[tokio::test]
async fn off_policy_never_auto_adopts() {
    let (svc, key, host, jws, _g) = setup(ProposalPolicy::Off).await;
    let resp = svc
        .propose_allowlist(tonic::Request::new(proposal_req(
            &key,
            &host,
            vec![entry(1000, 0xAA)],
            &jws,
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.outcome, Outcome::Pending as i32);
    // Nothing was served.
    let got = svc
        .get_allowlist(tonic::Request::new(GetAllowlistRequest {
            host_uuid: host.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(got.signed_allowlist.is_empty());
}

#[tokio::test]
async fn rejects_tampered_signature() {
    let (svc, key, host, jws, _g) = setup(ProposalPolicy::BootstrapOnly).await;
    let mut req = proposal_req(&key, &host, vec![entry(1000, 0xAA)], &jws);
    req.proposal_sig[0] ^= 0xFF;
    let err = svc
        .propose_allowlist(tonic::Request::new(req))
        .await
        .expect_err("bad signature rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn rejects_sep_pub_not_bound_to_svid() {
    let (svc, key, host, jws, _g) = setup(ProposalPolicy::BootstrapOnly).await;
    let mut req = proposal_req(&key, &host, vec![entry(1000, 0xAA)], &jws);
    // A different key's SPKI does not match the SVID's cnf.jkt.
    req.sep_pub = SoftwareMachineKey::generate().unwrap().public_spki_der();
    let err = svc
        .propose_allowlist(tonic::Request::new(req))
        .await
        .expect_err("unbound key rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn rejects_host_uuid_mismatch() {
    let (svc, key, _host, jws, _g) = setup(ProposalPolicy::BootstrapOnly).await;
    // Propose for a different host than the SVID attests.
    let req = proposal_req(&key, "some-other-host-uuid", vec![entry(1000, 0xAA)], &jws);
    let err = svc
        .propose_allowlist(tonic::Request::new(req))
        .await
        .expect_err("host mismatch rejected");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn rejects_unissued_svid() {
    let (svc, key, host, _jws, _g) = setup(ProposalPolicy::BootstrapOnly).await;
    // An SVID signed by a *different* issuer is not one this CMIS issued.
    let other = Issuer::generate("other", "ferrogate.test").unwrap();
    let bogus = other
        .issue(
            &IssueParams {
                ek_cert_sha384: [0x42u8; 48],
                pcr_digest: [0u8; 48],
                policy_id: "p".into(),
                dpop_jkt: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(key.public_spki_der())),
                ttl_secs: 3600,
                tee_evidence_id: None,
            },
            now_unix(),
        )
        .unwrap()
        .jws;
    let req = proposal_req(&key, &host, vec![entry(1000, 0xAA)], &bogus);
    let err = svc
        .propose_allowlist(tonic::Request::new(req))
        .await
        .expect_err("foreign svid rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}
