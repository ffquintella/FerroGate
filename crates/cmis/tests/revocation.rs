//! F11 integration: the `RevokeSvid` / `RevokeHost` admin RPCs produce a
//! composite-signed CRL in the published JWKS within one publish cycle, the
//! audit log records each revocation, and a revoked SVID is rejected by the
//! independent reference verifier.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::{JwksRequest, RevokeHostRequest, RevokeSvidRequest};
use ferro_svid::{IssueParams, Issuer};
use sha2::{Digest, Sha384};

/// A credential maker that is never exercised by these RPCs.
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

/// Per-test sequence so each gets a unique audit WORM directory even when the
/// suite's tests run concurrently in one binary.
static SEQ: AtomicU64 = AtomicU64::new(0);

fn svc() -> (MachineIdentitySvc, Arc<CmisState>) {
    let issuer = Issuer::generate("cmis-test-1", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());

    let tmp = std::env::temp_dir().join(format!(
        "ferrogate-cmis-rev-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-1").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer));

    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnusedCredentialMaker),
        CmisConfig::default(),
        audit,
    ));
    (MachineIdentitySvc::new(Arc::clone(&state)), state)
}

fn params() -> IssueParams {
    IssueParams {
        ek_cert_sha384: [0x11; 48],
        pcr_digest: [0x22; 48],
        policy_id: "rim-gen-1".to_string(),
        dpop_jkt: "dpop".to_string(),
        ttl_secs: 3600,
        tee_evidence_id: None,
    }
}

async fn fetch_jwks(svc: &MachineIdentitySvc) -> ferro_svid_verify::JwkSet {
    let resp = svc
        .jwks(tonic::Request::new(JwksRequest {}))
        .await
        .unwrap()
        .into_inner();
    ferro_svid_verify::JwkSet::from_json(&resp.jwks_json).unwrap()
}

/// Fetch and parse the JWKS into `ferro_svid`'s own types, whose CRL `verify`
/// and membership helpers are public (the reference verifier keeps its CRL
/// internals private — it only exposes `verify_unrevoked`).
async fn jwks_native(svc: &MachineIdentitySvc) -> ferro_svid::JwkSet {
    let resp = svc
        .jwks(tonic::Request::new(JwksRequest {}))
        .await
        .unwrap()
        .into_inner();
    serde_json::from_str(&resp.jwks_json).unwrap()
}

#[tokio::test]
async fn revoke_svid_appears_in_jwks_crl_and_audit() {
    let (svc, state) = svc();
    let cert_sha = hex::encode([0xAB; 48]);
    let audit_len_before = state.audit.len();

    let resp = svc
        .revoke_svid(tonic::Request::new(RevokeSvidRequest {
            cert_sha: cert_sha.clone(),
            reason: "key-compromise".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(resp.crl_number >= 1);

    // The CRL is published within the same call (one publish cycle), signed and
    // verifiable against the published issuer key, and names the revoked SVID.
    let jwks = jwks_native(&svc).await;
    let crl = jwks.crl.as_ref().expect("CRL present in JWKS");
    let body = crl.verify(&jwks).expect("CRL signature verifies");
    assert!(body.revokes_svid(&cert_sha));

    // The revocation was recorded in the audit log.
    assert_eq!(
        state.audit.len(),
        audit_len_before + 1,
        "one SvidRevoked leaf appended"
    );
}

#[tokio::test]
async fn revoke_host_appears_in_jwks_crl() {
    let (svc, _state) = svc();
    let spiffe = "spiffe://ferrogate.test/host/deadbeef".to_string();

    svc.revoke_host(tonic::Request::new(RevokeHostRequest {
        spiffe_id: spiffe.clone(),
        reason: "decommissioned".into(),
    }))
    .await
    .unwrap();

    let jwks = jwks_native(&svc).await;
    let crl = jwks.crl.as_ref().expect("CRL present");
    let body = crl.verify(&jwks).unwrap();
    assert!(body.revokes_host(&spiffe));
}

#[tokio::test]
async fn revoked_svid_is_rejected_by_reference_verifier_after_propagation() {
    let (svc, state) = svc();
    // The admin RPC stamps the CRL with the real wall clock, so the SVID and the
    // verification reference time must use it too (otherwise the CRL looks
    // future-dated and fails freshness before the revocation check).
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();

    // Issue a real SVID from this CMIS's issuer.
    let issued = state.issuer.issue(&params(), now).unwrap();
    let cert_sha = hex::encode(Sha384::digest(issued.jws.as_bytes()));

    // Before revocation, the reference verifier accepts it (CRL is empty but
    // fresh once published).
    state.publish_crl(now).unwrap();
    let jwks = fetch_jwks(&svc).await;
    ferro_svid_verify::verify_unrevoked(&issued.jws, &jwks, now + 60, 0)
        .expect("accepted before revocation");

    // Revoke it; the admin RPC republishes the CRL immediately.
    svc.revoke_svid(tonic::Request::new(RevokeSvidRequest {
        cert_sha,
        reason: "key-compromise".into(),
    }))
    .await
    .unwrap();

    // After propagation the reference verifier refuses it.
    let jwks = fetch_jwks(&svc).await;
    let err = ferro_svid_verify::verify_unrevoked(&issued.jws, &jwks, now + 60, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::Revoked);
}

#[tokio::test]
async fn malformed_cert_sha_is_rejected() {
    let (svc, _state) = svc();
    let err = svc
        .revoke_svid(tonic::Request::new(RevokeSvidRequest {
            cert_sha: "not-hex".into(),
            reason: "x".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
