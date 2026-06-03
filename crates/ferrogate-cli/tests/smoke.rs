//! End-to-end transport tests for the `ferrogate` operator CLI.
//!
//! These run the *actual* compiled `ferrogate` binary
//! (`CARGO_BIN_EXE_ferrogate`) against a real CMIS `MachineIdentity` service on
//! a loopback port, covering both transports the CLI speaks:
//!
//! - an `https://` endpoint dialed over hybrid-PQC TLS (feature F01), with the
//!   SPKI pin either derived from the served certificate (`--tls-cert`) or
//!   supplied explicitly (`--spki-pin`); and
//! - the legacy plaintext `http://` bring-up path.
//!
//! The TLS listener harness mirrors `crates/mia/tests/tls_transport.rs`.

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
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::process::Command;

/// A phase-3 credential maker that always refuses — `Health`/`status` (what
/// these tests drive) never touches it, but `CmisState::new` requires one.
struct NoCredentialMaker;

impl CredentialMaker for NoCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap(
            "not configured in cli test".to_string(),
        ))
    }
}

/// Self-signed server cert + key, its SPKI pin, and the cert PEM text (so a
/// test can write it to disk and point `--tls-cert` at it).
fn make_identity() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    SpkiPin,
    String,
) {
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .expect("rcgen self-signed cert");
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes()).unwrap());
    let pin = SpkiPin::from_certificate_der(cert.as_ref()).unwrap();
    (vec![cert], key, pin, cert_pem)
}

fn build_state() -> Arc<CmisState> {
    let issuer = Issuer::generate("kid-cli-test", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let audit_root = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ferrogate-cli-test-audit-{nanos}"))
    };
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-cli-test").unwrap();
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
/// loopback port. Returns the bound address, the server's SPKI pin, and the
/// served certificate's PEM text.
async fn spawn_tls_cmis() -> (SocketAddr, SpkiPin, String) {
    let (chain, key, pin, cert_pem) = make_identity();
    let server_config =
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
    (addr, pin, cert_pem)
}

/// Stand up the real CMIS service behind a plaintext listener (the `http://`
/// bring-up path). Returns the bound address.
async fn spawn_plaintext_cmis() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = build_state();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MachineIdentitySvc::new(state).into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    addr
}

/// Path to the compiled `ferrogate` binary under test.
fn ferrogate_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ferrogate"))
}

/// Write `pem` to a unique temp file and return its path.
fn write_temp_cert(pem: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("ferrogate-cli-test-cert-{nanos}.pem"));
    std::fs::write(&path, pem).unwrap();
    path
}

#[tokio::test]
async fn https_status_succeeds_with_pin_derived_from_served_cert() {
    let (addr, _pin, cert_pem) = spawn_tls_cmis().await;
    let cert_path = write_temp_cert(&cert_pem);

    let out = Command::new(ferrogate_bin())
        .args([
            "--endpoint",
            &format!("https://{addr}"),
            "--tls-cert",
            cert_path.to_str().unwrap(),
            "status",
        ])
        .output()
        .await
        .expect("run ferrogate");

    let _ = std::fs::remove_file(&cert_path);
    assert!(
        out.status.success(),
        "status over TLS (cert-derived pin) must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("healthy:"),
        "unexpected status output: {stdout}"
    );
}

#[tokio::test]
async fn https_status_succeeds_with_explicit_pin() {
    let (addr, pin, _cert_pem) = spawn_tls_cmis().await;

    let out = Command::new(ferrogate_bin())
        .args([
            "--endpoint",
            &format!("https://{addr}"),
            "--spki-pin",
            &pin.to_hex(),
            "status",
        ])
        .output()
        .await
        .expect("run ferrogate");

    assert!(
        out.status.success(),
        "status over TLS (explicit pin) must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn https_wrong_pin_is_rejected_before_rpc() {
    let (addr, _pin, _cert_pem) = spawn_tls_cmis().await;
    let bogus = SpkiPin::from_bytes([0u8; 48]).to_hex();

    let out = Command::new(ferrogate_bin())
        .args([
            "--endpoint",
            &format!("https://{addr}"),
            "--spki-pin",
            &bogus,
            "status",
        ])
        .output()
        .await
        .expect("run ferrogate");

    assert!(
        !out.status.success(),
        "a wrong SPKI pin must fail the handshake before any RPC"
    );
}

#[tokio::test]
async fn explicit_pin_takes_precedence_over_cert() {
    // Correct explicit pin + a bogus --tls-cert path. If the cert were
    // consulted the run would fail reading it; success proves the explicit pin
    // wins (precedence step 1 beats step 2).
    let (addr, pin, _cert_pem) = spawn_tls_cmis().await;

    let out = Command::new(ferrogate_bin())
        .args([
            "--endpoint",
            &format!("https://{addr}"),
            "--spki-pin",
            &pin.to_hex(),
            "--tls-cert",
            "/nonexistent/ferrogate-cli-test/cmis.crt",
            "status",
        ])
        .output()
        .await
        .expect("run ferrogate");

    assert!(
        out.status.success(),
        "explicit --spki-pin must take precedence over --tls-cert; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn https_without_pin_or_readable_cert_errors_clearly() {
    let (addr, _pin, _cert_pem) = spawn_tls_cmis().await;

    let out = Command::new(ferrogate_bin())
        .args([
            "--endpoint",
            &format!("https://{addr}"),
            "--tls-cert",
            "/nonexistent/ferrogate-cli-test/cmis.crt",
            "status",
        ])
        .output()
        .await
        .expect("run ferrogate");

    assert!(
        !out.status.success(),
        "an https:// endpoint with no resolvable pin must error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TLS cert") || stderr.contains("SPKI pin"),
        "error must explain the missing pin/cert; got: {stderr}"
    );
}

#[tokio::test]
async fn plaintext_http_status_still_works() {
    let addr = spawn_plaintext_cmis().await;

    let out = Command::new(ferrogate_bin())
        .args(["--endpoint", &format!("http://{addr}"), "status"])
        .output()
        .await
        .expect("run ferrogate");

    assert!(
        out.status.success(),
        "plaintext http:// path must remain unchanged; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("healthy:"),
        "unexpected status output: {stdout}"
    );
}
