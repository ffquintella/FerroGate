//! `GetEnrollmentKey` returns the issuer's composite public key as concat
//! bytes — exactly the format a host agent's `allowlist.key` expects
//! (`CompositePublicKey::from_concat_bytes`). This is the key that signs caller
//! allowlists, fetched by `mia setup` over the pinned CMIS channel.

use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::composite::CompositePublicKey;
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::GetEnrollmentKeyRequest;
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

fn svc() -> (MachineIdentitySvc, Arc<CmisState>) {
    let issuer = Issuer::generate("cmis-test-ek", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(format!("ferrogate-cmis-ek-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-ek").unwrap();
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

#[tokio::test]
async fn get_enrollment_key_returns_issuer_public_concat() {
    let (svc, state) = svc();

    let resp = svc
        .get_enrollment_key(tonic::Request::new(GetEnrollmentKeyRequest {}))
        .await
        .expect("rpc ok")
        .into_inner();

    // It matches the issuer's published composite public key, byte for byte.
    let expected = state.issuer.public_key().to_concat_bytes();
    assert_eq!(resp.public_key, expected);

    // And it round-trips through the exact parser the allowlist verifier uses.
    let parsed = CompositePublicKey::from_concat_bytes(&resp.public_key);
    assert!(
        parsed.is_ok(),
        "enrollment key must parse as a composite public key"
    );

    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("ferrogate-cmis-ek-{}", std::process::id())),
    );
}
