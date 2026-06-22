//! Integration test of the MIA-side CRL puller (feature F11) against a real
//! in-process CMIS over a tonic gRPC channel.
//!
//! The daemon wires `mia::helper::crl::spawn_puller` at startup so the helper
//! API's fail-closed mint gate opens once a verified CRL lands. We assert the
//! pieces end-to-end:
//!
//! - an empty cache fails closed (`CrlGate::Stale`);
//! - one `refresh_once` against a publishing CMIS verifies and stores the CRL,
//!   and the gate opens;
//! - against a CMIS that never published a CRL, the pull fails (`Absent`) and
//!   the gate stays closed;
//! - `spawn_puller` performs its first pull immediately, not after the first
//!   interval tick.

// Building CmisState holds the issuer's composite key (~4 KB ML-DSA) across
// awaits; the large future is inherent, as in the other CMIS-backed tests.
#![allow(clippy::large_futures)]

use std::sync::Arc;
use std::time::Duration;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_svid::Issuer;
use mia::helper::crl::{refresh_once, spawn_puller, CrlIngestError, CrlRefreshError};
use mia::helper::{CrlCache, CrlGate};

/// The CRL tests never attest, so credential activation is unreachable.
struct UnusedCredentialMaker;
impl CredentialMaker for UnusedCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        unreachable!("CRL tests do not activate a credential")
    }
}

/// A minimal single-node CMIS state (the JWKS/CRL path needs no TPM verifier
/// content and no fleet manifest).
async fn build_state() -> Arc<CmisState> {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let tag = format!("{nanos}-{n}");

    let issuer = Issuer::generate("kid-crl-pull", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::new(), RimStore::new());
    let audit_root = std::env::temp_dir().join(format!("ferrogate-crlpull-audit-{tag}"));
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, _audit_pk) = InProcessSigner::generate("audit-test").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!("ferrogate-crlpull-raft-{tag}"));
    let _ = std::fs::remove_dir_all(&raft_dir);
    let cluster = Arc::new(
        ferro_raft::Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnusedCredentialMaker),
        CmisConfig {
            trust_domain: "ferrogate.test".to_string(),
            svid_ttl_secs: 3600,
            ..CmisConfig::default()
        },
        audit,
        cluster,
    ))
}

/// Serve `state` on an ephemeral local port and return a connected client.
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

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Gate arguments for a host the CRL does not revoke.
const HOST_SHA: &str = "00aa";
const HOST_ID: &str = "spiffe://ferrogate.test/host/11111111-2222-3333-4444-555555555555";

#[tokio::test]
async fn refresh_once_populates_cache_and_opens_gate() {
    let state = build_state().await;
    state.publish_crl(now_secs()).unwrap();
    let mut client = spawn_server(state).await;

    let cache = CrlCache::new();
    let now = now_secs();
    assert_eq!(
        cache.gate(HOST_SHA, HOST_ID, now).await,
        CrlGate::Stale,
        "an empty cache must fail closed"
    );

    let number = refresh_once(&mut client, &cache).await.unwrap();
    assert_eq!(cache.number().await, Some(number));
    assert_eq!(
        cache.gate(HOST_SHA, HOST_ID, now_secs()).await,
        CrlGate::Ok,
        "a freshly pulled, verified CRL must open the mint gate"
    );
}

#[tokio::test]
async fn unpublished_crl_fails_closed() {
    // No publish_crl: the JWKS carries no x-ferrogate-crl extension.
    let mut client = spawn_server(build_state().await).await;

    let cache = CrlCache::new();
    let err = refresh_once(&mut client, &cache).await.unwrap_err();
    assert!(
        matches!(err, CrlRefreshError::Ingest(CrlIngestError::Absent)),
        "expected Absent, got: {err}"
    );
    assert_eq!(
        cache.number().await,
        None,
        "a failed pull must not store anything"
    );
    assert_eq!(
        cache.gate(HOST_SHA, HOST_ID, now_secs()).await,
        CrlGate::Stale
    );
}

#[tokio::test]
async fn spawn_puller_pulls_immediately() {
    let state = build_state().await;
    state.publish_crl(now_secs()).unwrap();
    let client = spawn_server(state).await;

    let cache = Arc::new(CrlCache::new());
    // An interval far longer than the test: only the immediate first pull can
    // populate the cache.
    let puller = spawn_puller(client, Arc::clone(&cache), Duration::from_secs(3600));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if cache.number().await.is_some() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "puller did not populate the cache within 5s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(cache.gate(HOST_SHA, HOST_ID, now_secs()).await, CrlGate::Ok);
    puller.abort();
}
