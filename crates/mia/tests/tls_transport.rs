//! Live-transport integration tests for feature F01 — hybrid-PQC TLS on the
//! CMIS gRPC listener and the MIA client dialer.
//!
//! Unlike `ferro-crypto`'s `tls_handshake` tests (which exercise the rustls
//! config builders over an in-memory duplex), these stand up the *actual*
//! CMIS `MachineIdentity` service behind [`cmis::transport::tls_incoming`] on
//! a real loopback TCP socket and drive it with the production
//! [`mia::client::connect_pinned`] dialer. They prove, end to end:
//!
//! 1. a pinned hybrid client completes the handshake and runs a real gRPC RPC
//!    (`JWKS`) over the TLS transport;
//! 2. a legacy, non-PQC client cannot complete the handshake against the
//!    `HybridOnly` listener; and
//! 3. a client carrying the wrong SPKI pin is refused by `connect_pinned`
//!    before any RPC.

use std::net::SocketAddr;
use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::pin::{SpkiPin, SpkiPinVerifier};
use ferro_crypto::tls::{ferrogate_provider, ProviderMode};
use ferro_svid::Issuer;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::TlsConnector;

/// A phase-3 credential maker that always refuses — `JWKS` (the RPC these
/// tests use) does not touch it, but `CmisState::new` requires one.
struct NoCredentialMaker;

impl CredentialMaker for NoCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap("not configured in tls test".to_string()))
    }
}

/// Self-signed server cert + key plus the SPKI pin a client would carry.
fn make_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, SpkiPin) {
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .expect("rcgen self-signed cert");
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let key_pem = ck.key_pair.serialize_pem();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes()).unwrap());
    let pin = SpkiPin::from_certificate_der(cert.as_ref()).unwrap();
    (vec![cert], key, pin)
}

fn build_state() -> Arc<CmisState> {
    let issuer = Issuer::generate("kid-tls-test", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let audit_root = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ferrogate-tls-test-audit-{nanos}"))
    };
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-tls-test").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer));
    Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(NoCredentialMaker),
        CmisConfig::default(),
        audit,
    ))
}

/// Stand up the real CMIS service behind a hybrid-PQC TLS listener on a free
/// loopback port. Returns the bound address and the server's SPKI pin.
async fn spawn_tls_cmis() -> (SocketAddr, SpkiPin) {
    let (chain, key, pin) = make_identity();
    let server_config: Arc<ServerConfig> =
        ferro_crypto::transport::server_config(ProviderMode::HybridOnly, chain, key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = build_state();
    let incoming = cmis::transport::tls_incoming(listener, server_config);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MachineIdentitySvc::new(state).into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    (addr, pin)
}

#[tokio::test]
async fn pinned_hybrid_client_completes_jwks_over_tls() {
    let (addr, pin) = spawn_tls_cmis().await;
    let mut client = mia::client::connect_pinned(&format!("https://{addr}"), vec![pin])
        .await
        .expect("pinned hybrid client must connect over the TLS transport");
    let resp = client
        .jwks(ferro_proto::v1::JwksRequest {})
        .await
        .expect("JWKS RPC over TLS")
        .into_inner();
    assert!(
        !resp.jwks_json.is_empty(),
        "JWKS must be served over the hybrid-PQC TLS transport"
    );
}

#[tokio::test]
async fn legacy_non_pqc_client_cannot_handshake_against_cmis_listener() {
    let (addr, pin) = spawn_tls_cmis().await;

    // Deliberately weakened client: offers only legacy X25519, no hybrid
    // group at all — the post-quantum downgrade attempt. Pin trust is still
    // wired so the failure can only come from the key-exchange mismatch.
    let provider = {
        let mut p = ferrogate_provider(ProviderMode::HybridOnly);
        p.kx_groups = vec![tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519];
        Arc::new(p)
    };
    let verifier = SpkiPinVerifier::new(vec![pin], Arc::clone(&provider));
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(addr.ip().to_string()).unwrap();
    let res = connector.connect(server_name, tcp).await;
    assert!(
        res.is_err(),
        "a legacy non-PQC client must NOT complete a handshake against the hybrid-only CMIS listener"
    );
}

#[tokio::test]
async fn wrong_pin_client_is_rejected_by_connect_pinned() {
    let (addr, _pin) = spawn_tls_cmis().await;
    // A pin for some other certificate — the genuine server cert will not
    // match it, so certificate verification fails before any RPC.
    let bogus = SpkiPin::from_bytes([0u8; 48]);
    let res = mia::client::connect_pinned(&format!("https://{addr}"), vec![bogus]).await;
    assert!(
        res.is_err(),
        "connect_pinned must fail closed when the server SPKI pin does not match"
    );
}
