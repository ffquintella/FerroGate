//! F14 integration: during a cross-sign rotation window CMIS publishes the
//! incoming root alongside the outgoing issuer root in its JWKS, ordered
//! newest-first so a verifier prefers the newer root, while both — and the
//! per-host child keys — stay resolvable by `kid`.

#![allow(clippy::large_futures)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::composite::CompositeSecretKey;
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

static SEQ: AtomicU64 = AtomicU64::new(0);

async fn state() -> CmisState {
    let issuer = Issuer::generate("root-2025", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!(
        "ferrogate-cmis-rot-{}-{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-rot-1").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!(
        "ferrogate-cmis-rot-raft-{}-{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&raft_dir);
    let cluster = Arc::new(
        Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    CmisState::new(
        issuer,
        verifier,
        Box::new(UnusedCredentialMaker),
        CmisConfig::default(),
        audit,
        cluster,
    )
}

#[tokio::test]
async fn incoming_root_is_published_newest_first_and_preferred() {
    let state = state().await;

    // Before the window the issuer root is the only key, and it is preferred.
    let jwks = state.published_jwks();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.preferred().unwrap().kid, "root-2025");

    // Register a host child key (feature F09) — it must stay after the roots.
    let (_csk, child_pk) = CompositeSecretKey::from_seed(&[3u8; 32]);
    state.register_child_key(&child_pk);

    // Open a cross-sign window: publish the incoming root with a newer stamp.
    let (_nsk, new_pk) = CompositeSecretKey::from_seed(&[9u8; 32]);
    state.register_root_key(&new_pk, "root-2026", 1_780_000_000);

    let jwks = state.published_jwks();
    // Roots first (newest first), then the child key.
    assert_eq!(jwks.keys[0].kid, "root-2026");
    assert_eq!(jwks.keys[1].kid, "root-2025");
    assert!(jwks.keys[2].kid.starts_with("host-"));

    // Newer preferred.
    assert_eq!(jwks.preferred().unwrap().kid, "root-2026");

    // Both roots and the child remain resolvable by kid through the window.
    assert!(jwks.find("root-2025").is_some());
    assert!(jwks.find("root-2026").is_some());
    assert!(jwks.find(&jwks.keys[2].kid).is_some());

    // Re-registering the same root refreshes its stamp without duplicating.
    state.register_root_key(&new_pk, "root-2026", 1_790_000_000);
    let jwks = state.published_jwks();
    assert_eq!(jwks.keys.iter().filter(|k| k.kid == "root-2026").count(), 1);
}
