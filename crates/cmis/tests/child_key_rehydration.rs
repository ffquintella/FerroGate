//! A host's child-token signing key (F09) persisted in the replicated
//! issued-SVID store is republished into the JWKS by `kid` when a fresh CMIS
//! process rehydrates from that store — so a child token minted before a
//! restart no longer fails verification with `no key for kid host-…` just
//! because the issuing process never witnessed the attestation.

#![allow(clippy::large_futures)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, IssuedRecord};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::composite::CompositeSecretKey;
use ferro_raft::Cluster;
use ferro_svid::{child_signing_kid, IssueParams, IssuedSvid, Issuer, LastAttestation};

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

async fn state() -> Arc<CmisState> {
    let issuer = Issuer::generate("cmis-test-rehy", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp =
        std::env::temp_dir().join(format!("ferrogate-cmis-rehy-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-rehy").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();

    let raft_dir = std::env::temp_dir().join(format!(
        "ferrogate-cmis-rehy-raft-{}-{seq}",
        std::process::id()
    ));
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
        CmisConfig::default(),
        audit,
        cluster,
    ))
}

fn record_with_child_key(spiffe_id: &str, child_pub: Vec<u8>) -> IssuedRecord {
    IssuedRecord {
        params: IssueParams {
            ek_cert_sha384: [0x11; 48],
            pcr_digest: [0x22; 48],
            policy_id: "host-key".to_string(),
            dpop_jkt: "dpop".to_string(),
            ttl_secs: 3600,
            tee_evidence_id: None,
        },
        last_attestation: LastAttestation {
            at: 1_700_000_000,
            pcr_digest: [0x22; 48],
            policy_epoch: 1,
        },
        bundle: IssuedSvid {
            jws: "eyJ...".to_string(),
            spiffe_id: spiffe_id.to_string(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
        },
        hostname: None,
        child_pub: Some(child_pub),
    }
}

#[tokio::test]
async fn rehydrate_republishes_persisted_child_keys() {
    let state = state().await;

    // A host's child key, as it would have been stored at attestation time.
    let (_sk, pk) = CompositeSecretKey::generate().unwrap();
    let kid = child_signing_kid(&pk);
    state
        .record(record_with_child_key(
            "spiffe://ferrogate.test/host/abc",
            pk.to_concat_bytes(),
        ))
        .await;

    // `record` only persists — it does not touch this process's JWKS, modelling
    // a replica that never witnessed the attestation.
    assert!(
        state.published_jwks().find(&kid).is_none(),
        "persisting a record must not by itself publish the child key"
    );

    // Rehydration (run once at startup) republishes it by kid.
    state.rehydrate_child_keys().await;
    assert!(
        state.published_jwks().find(&kid).is_some(),
        "rehydration must republish the persisted child key into the JWKS"
    );
}

#[tokio::test]
async fn ensure_child_key_published_rehydrates_on_miss() {
    let state = state().await;

    // Persisted by a *different* replica at attestation time; this process's
    // JWKS has never seen the key and no startup rehydration has run — the
    // exact cross-node gap behind spurious `no key for kid host-…` failures.
    let (_sk, pk) = CompositeSecretKey::generate().unwrap();
    let kid = child_signing_kid(&pk);
    state
        .record(record_with_child_key(
            "spiffe://ferrogate.test/host/other-node",
            pk.to_concat_bytes(),
        ))
        .await;
    assert!(state.published_jwks().find(&kid).is_none());

    // A JWKS request hinting at the missing kid pulls it from the store.
    assert!(
        state.ensure_child_key_published(&kid).await,
        "on-miss rehydrate must publish a kid present in the replicated store"
    );
    assert!(state.published_jwks().find(&kid).is_some());

    // Already-published (the fast path) stays true; a kid in nobody's store
    // and a non-host kid both report absent without publishing anything.
    assert!(state.ensure_child_key_published(&kid).await);
    assert!(!state.ensure_child_key_published("host-0000000000000000").await);
    assert!(!state.ensure_child_key_published("not-a-host-kid").await);
}

#[tokio::test]
async fn rehydrate_skips_records_without_a_child_key() {
    let state = state().await;
    let before = state.published_jwks().keys.len();

    // A legacy record (written before the field existed) carries no child key.
    let mut rec = record_with_child_key("spiffe://ferrogate.test/host/legacy", Vec::new());
    rec.child_pub = None;
    state.record(rec).await;

    state.rehydrate_child_keys().await;
    assert_eq!(
        state.published_jwks().keys.len(),
        before,
        "a record without a stored child key must add nothing to the JWKS"
    );
}
