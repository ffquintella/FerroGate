//! CMIS stores, signs, and serves per-host caller allowlists. These tests drive
//! the `SetAllowlist`/`GetAllowlist`/`ListAllowlists`/`DeleteAllowlist` RPCs
//! against an in-process single-replica CMIS and verify the served body the same
//! way a MIA does: decode the CBOR `SignedAllowlist`, check its signature under
//! the enrollment key (`GetEnrollmentKey`), and confirm the entries/validity.

#![allow(clippy::large_futures)]

use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::composite::CompositePublicKey;
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::{
    AllowEntryMsg, DeleteAllowlistRequest, GetAllowlistRequest, GetEnrollmentKeyRequest,
    ListAllowlistsRequest, SetAllowlistRequest,
};
use ferro_raft::Cluster;
use ferro_svid::Issuer;

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

/// Removes its directories (audit WORM store, raft data dir) on drop, so each
/// test gets isolated state (tests run in parallel in one process — a shared
/// dir would race).
struct TmpDirs(Vec<std::path::PathBuf>);
impl Drop for TmpDirs {
    fn drop(&mut self) {
        for dir in &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

async fn svc() -> (MachineIdentitySvc, TmpDirs) {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let issuer = Issuer::generate("cmis-test-al", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(format!("ferrogate-cmis-al-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-al").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir =
        std::env::temp_dir().join(format!("ferrogate-cmis-al-raft-{}-{n}", std::process::id()));
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
        CmisConfig::default(),
        audit,
        cluster,
    ));
    (MachineIdentitySvc::new(state), TmpDirs(vec![tmp, raft_dir]))
}

/// The enrollment public key CMIS publishes, parsed for verification.
async fn enrollment_key(svc: &MachineIdentitySvc) -> CompositePublicKey {
    let resp = svc
        .get_enrollment_key(tonic::Request::new(GetEnrollmentKeyRequest {}))
        .await
        .expect("enrollment key rpc")
        .into_inner();
    CompositePublicKey::from_concat_bytes(&resp.public_key).expect("parse enrollment key")
}

fn entry(uid: u32, byte: u8) -> AllowEntryMsg {
    AllowEntryMsg {
        uid: Some(uid),
        bin_sha: hex::encode([byte; 48]),
    }
}

#[tokio::test]
async fn set_then_get_serves_a_verifiable_signed_allowlist() {
    let (svc, _g) = svc().await;
    let pk = enrollment_key(&svc).await;
    let host = "host-uuid-1";

    let set = svc
        .set_allowlist(tonic::Request::new(SetAllowlistRequest {
            host_uuid: host.into(),
            entries: vec![entry(1000, 0xAA), entry(1001, 0xBB)],
            ttl_secs: 3600,
        }))
        .await
        .expect("set ok")
        .into_inner();
    assert_eq!(set.not_after - set.issued_at, 3600);

    let got = svc
        .get_allowlist(tonic::Request::new(GetAllowlistRequest {
            host_uuid: host.into(),
        }))
        .await
        .expect("get ok")
        .into_inner();
    assert!(!got.signed_allowlist.is_empty(), "an allowlist was stored");

    // Verify exactly as a MIA would: decode, check the signature under the
    // enrollment key, then read the body.
    let signed = ferro_svid::allowlist::decode(&got.signed_allowlist).expect("decode");
    let doc = ferro_svid::allowlist::verify(&signed, &pk).expect("signature verifies");
    assert_eq!(doc.trust_domain, "ferrogate.test");
    assert_eq!(doc.entries.len(), 2);
    assert_eq!(doc.issued_at, set.issued_at);
    assert_eq!(doc.not_after, set.not_after);
    assert!(doc.entries.iter().any(|e| e.uid == Some(1000)));

}

#[tokio::test]
async fn get_unknown_host_returns_empty_not_error() {
    let (svc, _g) = svc().await;
    let got = svc
        .get_allowlist(tonic::Request::new(GetAllowlistRequest {
            host_uuid: "nobody".into(),
        }))
        .await
        .expect("get ok")
        .into_inner();
    assert!(got.signed_allowlist.is_empty());
}

#[tokio::test]
async fn set_rejects_malformed_entry_hash() {
    let (svc, _g) = svc().await;
    let err = svc
        .set_allowlist(tonic::Request::new(SetAllowlistRequest {
            host_uuid: "host".into(),
            entries: vec![AllowEntryMsg {
                uid: Some(1),
                bin_sha: "not-hex".into(),
            }],
            ttl_secs: 60,
        }))
        .await
        .expect_err("malformed entry rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn set_rejects_empty_host_uuid() {
    let (svc, _g) = svc().await;
    let err = svc
        .set_allowlist(tonic::Request::new(SetAllowlistRequest {
            host_uuid: "  ".into(),
            entries: vec![entry(1, 0x11)],
            ttl_secs: 60,
        }))
        .await
        .expect_err("empty host rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn list_and_delete_reflect_stored_allowlists() {
    let (svc, _g) = svc().await;
    for (host, n) in [("h1", 0x01u8), ("h2", 0x02u8)] {
        svc.set_allowlist(tonic::Request::new(SetAllowlistRequest {
            host_uuid: host.into(),
            entries: vec![entry(1000, n)],
            ttl_secs: 600,
        }))
        .await
        .expect("set ok");
    }

    let listed = svc
        .list_allowlists(tonic::Request::new(ListAllowlistsRequest {}))
        .await
        .expect("list ok")
        .into_inner();
    assert_eq!(listed.items.len(), 2);
    assert!(listed.items.iter().all(|s| s.entry_count == 1));

    let del = svc
        .delete_allowlist(tonic::Request::new(DeleteAllowlistRequest {
            host_uuid: "h1".into(),
        }))
        .await
        .expect("delete ok")
        .into_inner();
    assert!(del.existed);

    // Deleting again reports it was already gone.
    let del2 = svc
        .delete_allowlist(tonic::Request::new(DeleteAllowlistRequest {
            host_uuid: "h1".into(),
        }))
        .await
        .expect("delete ok")
        .into_inner();
    assert!(!del2.existed);

    let listed = svc
        .list_allowlists(tonic::Request::new(ListAllowlistsRequest {}))
        .await
        .expect("list ok")
        .into_inner();
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].host_uuid, "h2");

}

#[tokio::test]
async fn ttl_zero_falls_back_to_a_default_window() {
    let (svc, _g) = svc().await;
    let set = svc
        .set_allowlist(tonic::Request::new(SetAllowlistRequest {
            host_uuid: "h".into(),
            entries: vec![entry(1, 0x11)],
            ttl_secs: 0,
        }))
        .await
        .expect("set ok")
        .into_inner();
    // Default is the 72 h served window (`CmisConfig::default`), matched to the
    // MIA's `allowlist.max_age_secs` default so the served window never outruns
    // the MIA's staleness bound. (This is unrelated to `ferro_svid::MIN_TTL_SECS`,
    // the 96 h SVID lifetime floor — the allowlist window floors at 1 h.)
    assert_eq!(set.not_after - set.issued_at, 72 * 3600);
}
