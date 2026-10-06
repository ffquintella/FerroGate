//! End-to-end test for `mia allowlist-key fetch`'s library half: the real
//! CMIS `MachineIdentity` service behind its hybrid-PQC TLS listener on a
//! loopback port, dialed through [`mia::endpoint::CmisResolver`] with the
//! server's SPKI pin, the enrollment key fetched and installed by
//! [`mia::allowlist_key::plan`] / [`mia::allowlist_key::commit`].
//!
//! It proves the key that lands in `allowlist.key` is exactly CMIS's issuer
//! key (same fingerprint as `ferrogate enrollment-key` prints), that
//! `--expect-fingerprint` is honoured, and that a wrong pin fails before any
//! byte is written. The root-only gate of the CLI (`require_privileged`) is
//! covered by the module's unit tests.

#![allow(clippy::large_futures)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferro_svid::Issuer;
use mia::allowlist_key::{commit, fetch_key_async, plan, Change, Refusal};
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

/// Stand up CMIS over pinned hybrid-PQC TLS. Returns its address, its SPKI
/// pin and the fingerprint of the enrollment key it serves.
async fn spawn_tls_cmis(tag: &str) -> (SocketAddr, SpkiPin, String) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let unique = format!("{tag}-{}-{nanos}", std::process::id());
    let issuer = Issuer::generate("kid-allowlist-key-test", "ferrogate.test").unwrap();
    let fingerprint = issuer.public_key().fingerprint_hex();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let audit_root = std::env::temp_dir().join(format!("ferrogate-alkey-audit-{unique}"));
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-alkey-test").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!("ferrogate-alkey-raft-{unique}"));
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

    let (chain, key, pin) = make_identity();
    let server_config =
        ferro_crypto::transport::server_config(ProviderMode::HybridOnly, chain, key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = cmis::transport::tls_incoming(listener, server_config);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MachineIdentitySvc::new(state).into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    (addr, pin, fingerprint)
}

fn resolver(addr: SocketAddr, pin: &SpkiPin) -> CmisResolver {
    CmisResolver::from_config(&mia::config::CmisConfig {
        endpoint: Some(format!("https://{addr}")),
        srv: None,
        spki_pin: Some(pin.to_hex()),
    })
    .unwrap()
    .unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mia-alkey-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn fetch_over_pinned_tls_installs_cmis_issuer_key() {
    let (addr, pin, cmis_fp) = spawn_tls_cmis("ok").await;
    let dir = scratch("ok");
    let key_path = dir.join("allowlist.pub");

    let (endpoint, fetched) = fetch_key_async(&resolver(addr, &pin)).await.unwrap();
    assert_eq!(endpoint, format!("https://{addr}"));

    // A wrong expectation stops before anything is written.
    let wrong = "0".repeat(96);
    let err = plan(&key_path, &fetched, Some(&wrong), false).unwrap_err();
    assert!(matches!(
        err.downcast_ref::<Refusal>(),
        Some(Refusal::FingerprintMismatch { .. })
    ));
    assert!(!key_path.exists());

    // The right one installs exactly CMIS's key.
    let p = plan(&key_path, &fetched, Some(&cmis_fp), false).unwrap();
    assert_eq!(p.change(), &Change::New);
    assert_eq!(p.fingerprint(), cmis_fp);
    commit(&p).unwrap();
    let installed = std::fs::read(&key_path).unwrap();
    let parsed =
        ferro_crypto::composite::CompositePublicKey::from_concat_bytes(&installed).unwrap();
    assert_eq!(parsed.fingerprint_hex(), cmis_fp);

    // Fetching again changes nothing.
    let (_, again) = fetch_key_async(&resolver(addr, &pin)).await.unwrap();
    assert_eq!(
        plan(&key_path, &again, None, false).unwrap().change(),
        &Change::Unchanged
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_wrong_pin_fails_before_anything_is_written() {
    let (addr, _pin, _fp) = spawn_tls_cmis("wrong-pin").await;
    let bogus = SpkiPin::from_hex(&"ab".repeat(48)).unwrap();
    let err = fetch_key_async(&resolver(addr, &bogus)).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("pinned channel"),
        "unexpected error: {err:#}"
    );
}
