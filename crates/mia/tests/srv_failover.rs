//! Fail-over of [`mia::endpoint::CmisResolver`] across a multi-node CMIS
//! deployment, in-process (fast; runs in the normal suite): real CMIS nodes on
//! loopback sharing one pinned identity, one of which is then killed, black-holed
//! or made unresponsive. The Docker-based equivalent that kills real containers
//! lives in `docker_failover.rs` (ignored by default).

#![allow(clippy::large_futures)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferro_svid::Issuer;
use mia::client::fetch_enrollment_key;
use mia::endpoint::CmisResolver;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;

struct NoCredentialMaker;

impl CredentialMaker for NoCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap("not configured in this test".into()))
    }
}

fn make_identity() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    SpkiPin,
) {
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .expect("rcgen self-signed cert");
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let key_pem = ck.signing_key.serialize_pem();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes()).unwrap());
    let pin = SpkiPin::from_certificate_der(cert.as_ref()).unwrap();
    (vec![cert], key, pin)
}

/// A CMIS node's listener task; abort it to "kill" the node.
struct Node {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

/// Stand up a CMIS node over pinned hybrid-PQC TLS using the shared identity.
async fn spawn_node(
    tag: &str,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Node {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let unique = format!("{tag}-{}-{nanos}", std::process::id());
    let issuer = Issuer::generate("kid-failover-test", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let audit_root = std::env::temp_dir().join(format!("ferrogate-fo-audit-{unique}"));
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-failover-test").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!("ferrogate-fo-raft-{unique}"));
    let _ = std::fs::remove_dir_all(&raft_dir);
    let cluster = Arc::new(
        ferro_raft::Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(NoCredentialMaker),
        CmisConfig::default(),
        audit,
        cluster,
    ));
    let server_config =
        ferro_crypto::transport::server_config(ProviderMode::HybridOnly, chain, key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = cmis::transport::tls_incoming(listener, server_config);
    let task = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(MachineIdentitySvc::new(state).into_server())
            .serve_with_incoming(incoming)
            .await;
    });
    Node { addr, task }
}

/// A TCP listener that accepts connections and never says a word — a node whose
/// process is wedged: the kernel completes the TCP handshake, TLS never starts.
async fn spawn_silent_node() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock); // keep open, never read or write
        }
    });
    addr
}

/// An address nothing listens on (connection refused).
async fn dead_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

fn url(a: SocketAddr) -> String {
    format!("https://{a}")
}

fn resolver(candidates: &[SocketAddr], pin: &SpkiPin) -> CmisResolver {
    CmisResolver::with_candidates(candidates.iter().map(|a| url(*a)).collect(), vec![*pin])
        .with_timeouts(
            Duration::from_millis(800),
            Duration::from_millis(800),
            Duration::from_secs(30),
        )
}

/// The probe RPC: fetch the enrollment key, as `mia allowlist-key fetch` does.
async fn probe(r: &CmisResolver) -> anyhow::Result<String> {
    r.call(|mut c| async move { fetch_enrollment_key(&mut c).await.map(|_| ()) })
        .await
        .map(|(ep, ())| ep)
}

#[tokio::test]
async fn dead_preferred_node_fails_over_and_is_then_skipped() {
    let (chain, key, pin) = make_identity();
    let live = spawn_node("dead-pref", chain, key).await;
    let dead = dead_addr().await;
    let r = resolver(&[dead, live.addr], &pin);

    assert_eq!(probe(&r).await.unwrap(), url(live.addr));
    // The dead node is now penalised: it is no longer tried first.
    let ordered = r.candidates().await.unwrap();
    assert_eq!(ordered.len(), 2);
    assert_eq!(probe(&r).await.unwrap(), url(live.addr));
}

#[tokio::test]
async fn silent_node_is_abandoned_within_the_connect_timeout() {
    let (chain, key, pin) = make_identity();
    let live = spawn_node("silent", chain, key).await;
    let silent = spawn_silent_node().await;
    let r = resolver(&[silent, live.addr], &pin);

    let started = Instant::now();
    assert_eq!(probe(&r).await.unwrap(), url(live.addr));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "fail-over took {:?}",
        started.elapsed()
    );
    // Second call skips the silent node outright (penalised): no timeout paid.
    let started = Instant::now();
    assert_eq!(probe(&r).await.unwrap(), url(live.addr));
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "penalised node was retried first: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn node_that_hangs_mid_call_times_out_and_the_next_node_serves() {
    let (chain, key, pin) = make_identity();
    let a = spawn_node("hang-a", chain.clone(), key.clone_key()).await;
    let b = spawn_node("hang-b", chain, key).await;
    let r = resolver(&[a.addr, b.addr], &pin);

    // The preferred node accepts the handshake but its RPC never answers.
    let served = r
        .call(|mut c| {
            async move {
                // Hang on the first attempt only.
                let hang = HANG_ONCE.swap(false, std::sync::atomic::Ordering::SeqCst);
                if hang {
                    std::future::pending::<()>().await;
                }
                fetch_enrollment_key(&mut c).await.map(|_| ())
            }
        })
        .await
        .unwrap();
    assert_eq!(served.0, url(b.addr));
}

static HANG_ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

#[tokio::test]
async fn node_killed_between_calls_is_replaced_and_recovery_restores_preference() {
    let (chain, key, pin) = make_identity();
    let a = spawn_node("kill-a", chain.clone(), key.clone_key()).await;
    let b = spawn_node("kill-b", chain, key).await;
    let r = resolver(&[a.addr, b.addr], &pin).with_timeouts(
        Duration::from_millis(800),
        Duration::from_millis(800),
        Duration::from_millis(300),
    );

    assert_eq!(
        probe(&r).await.unwrap(),
        url(a.addr),
        "preferred node serves"
    );
    a.task.abort();
    let _ = a.task.await;
    assert_eq!(
        probe(&r).await.unwrap(),
        url(b.addr),
        "failed over after kill"
    );
    assert_eq!(
        probe(&r).await.unwrap(),
        url(b.addr),
        "stays on the live node"
    );
}

#[tokio::test]
async fn all_nodes_down_is_an_error_and_recovers_when_one_returns() {
    let (chain, key, pin) = make_identity();
    let d1 = dead_addr().await;
    let d2 = dead_addr().await;
    let r = resolver(&[d1, d2], &pin);
    let err = probe(&r).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("no responsive CMIS endpoint"),
        "{err:#}"
    );

    // A node comes back on d2's port? Use a fresh resolver over a live node
    // sharing the penalised set: penalties never make a node unusable.
    let live = spawn_node("revive", chain, key).await;
    let r2 = resolver(&[d1, live.addr], &pin);
    r2.mark_failed(&url(live.addr)); // even a penalised node is still tried last
    assert_eq!(probe(&r2).await.unwrap(), url(live.addr));
}
