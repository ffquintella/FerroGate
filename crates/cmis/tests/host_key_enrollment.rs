//! Strict host-key enrollment (F16): with `require_preregistered_host_key`,
//! a software host-key node that is not pre-registered in the fleet manifest is
//! refused rather than trust-on-first-use pinned — and the refusal must not
//! leave a TOFU pin that would let the next attempt slip through as `Pinned`.

#![allow(clippy::large_futures)]

use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::state::HostKeyBinding;
use cmis::{CmisConfig, CmisState};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
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

async fn state_with(config: CmisConfig, label: &str) -> Arc<CmisState> {
    let tag = format!("ferrogate-cmis-hke-{}-{label}", std::process::id());
    let issuer = Issuer::generate("cmis-test-ek", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp = std::env::temp_dir().join(&tag);
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-ek").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!("{tag}-raft"));
    let _ = std::fs::remove_dir_all(&raft_dir);
    let cluster = Arc::new(
        Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnusedCredentialMaker),
        config,
        audit,
        cluster,
    ))
}

#[tokio::test]
async fn tofu_pins_when_not_strict() {
    let state = state_with(CmisConfig::default(), "tofu").await;
    let fp = [7u8; 48];
    let key = b"machine-pubkey-A";
    assert!(matches!(
        state.bind_host_key(&fp, key, false),
        HostKeyBinding::FirstSeen
    ));
    // Second time the same key is now pinned.
    assert!(matches!(
        state.bind_host_key(&fp, key, false),
        HostKeyBinding::Pinned
    ));
}

#[tokio::test]
async fn strict_rejects_unregistered_and_leaves_no_pin() {
    let config = CmisConfig {
        require_preregistered_host_key: true,
        ..CmisConfig::default()
    };
    let state = state_with(config, "strict").await;
    let fp = [9u8; 48];
    let key = b"machine-pubkey-B";

    // Strict mode with no pre-registration: refused, not pinned.
    assert!(matches!(
        state.bind_host_key(&fp, key, true),
        HostKeyBinding::RejectedNotPreRegistered
    ));

    // Crucially, the refusal left no pin behind: a non-strict call still sees it
    // as first-seen (if a pin had been inserted this would be `Pinned`, which
    // would have let a strict attempt slip past on the next round).
    assert!(matches!(
        state.bind_host_key(&fp, key, false),
        HostKeyBinding::FirstSeen
    ));
}
