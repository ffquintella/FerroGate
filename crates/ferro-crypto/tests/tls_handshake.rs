//! Integration tests for feature F01 — hybrid PQC TLS transport.
//!
//! These tests drive a real `tokio-rustls` handshake across an in-memory
//! duplex stream to verify the two production-relevant claims:
//!
//! 1. **Happy path.** A client speaking only `X25519MLKEM768` completes
//!    a TLS 1.3 handshake against a hybrid-only FerroGate server.
//! 2. **Rejection path.** A client that offers only legacy `X25519`
//!    cannot handshake against a hybrid-only FerroGate server. This is
//!    the headline F01 acceptance criterion: a non-hybrid peer must fail
//!    closed, not silently fall back.
//!
//! Both tests also exercise [`ferro_crypto::pin::SpkiPinVerifier`] in the
//! client to prove that pinning is the authentication path actually used.

use std::sync::Arc;

use ferro_crypto::pin::{SpkiPin, SpkiPinVerifier};
use ferro_crypto::tls::{ferrogate_provider, ProviderMode};
use rustls::pki_types::{
    pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// A self-signed cert + key for the test server, plus the SPKI pin a
/// pinning client would carry.
struct TestServerIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    pin: SpkiPin,
}

fn make_server_identity() -> TestServerIdentity {
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .expect("rcgen self-signed cert");
    let cert_der: CertificateDer<'static> = ck.cert.der().clone();
    let key_pem = ck.key_pair.serialize_pem();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes()).unwrap());
    let pin = SpkiPin::from_certificate_der(cert_der.as_ref()).unwrap();
    TestServerIdentity {
        cert: cert_der,
        key: key_der,
        pin,
    }
}

fn server_config(mode: ProviderMode, ident: &TestServerIdentity) -> Arc<ServerConfig> {
    let provider = Arc::new(ferrogate_provider(mode));
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .with_no_client_auth()
        .with_single_cert(vec![ident.cert.clone()], ident.key.clone_key())
        .expect("server cert");
    Arc::new(cfg)
}

fn client_config(mode: ProviderMode, pin: SpkiPin) -> Arc<ClientConfig> {
    let provider = Arc::new(ferrogate_provider(mode));
    let verifier = SpkiPinVerifier::new(vec![pin], Arc::clone(&provider));
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Arc::new(cfg)
}

async fn run_handshake(
    server_mode: ProviderMode,
    client_mode: ProviderMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ident = make_server_identity();
    let s_cfg = server_config(server_mode, &ident);
    let c_cfg = client_config(client_mode, ident.pin);

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let acceptor = TlsAcceptor::from(s_cfg);
    let connector = TlsConnector::from(c_cfg);
    let server_name = ServerName::try_from("cmis.test.ferrogate.invalid").unwrap();

    let server_task = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await?;
        stream.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });

    let mut client = connector.connect(server_name, client_io).await?;
    client.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"pong");

    server_task.await.expect("server task")?;
    Ok(())
}

#[tokio::test]
async fn hybrid_client_succeeds_against_hybrid_only_server() {
    run_handshake(ProviderMode::HybridOnly, ProviderMode::HybridOnly)
        .await
        .expect("hybrid handshake must succeed");
}

#[tokio::test]
async fn fallback_client_succeeds_against_hybrid_only_server() {
    // The client offers hybrid first and X25519 second; the server
    // should pick the hybrid group, not the legacy one.
    run_handshake(
        ProviderMode::HybridOnly,
        ProviderMode::HybridPreferredWithX25519Fallback,
    )
    .await
    .expect("fallback client must still negotiate hybrid");
}

#[tokio::test]
async fn legacy_only_client_is_rejected_by_hybrid_only_server() {
    // Build a *deliberately weakened* client provider that offers only
    // legacy X25519 — no hybrid group at all. This is the post-quantum
    // adversary's last-ditch downgrade attempt. The handshake must fail.
    let ident = make_server_identity();
    let s_cfg = server_config(ProviderMode::HybridOnly, &ident);

    let weak_provider = {
        let mut p = ferrogate_provider(ProviderMode::HybridOnly);
        // Replace KX groups with the legacy-only set.
        p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        Arc::new(p)
    };
    let verifier = SpkiPinVerifier::new(vec![ident.pin], Arc::clone(&weak_provider));
    let c_cfg = ClientConfig::builder_with_provider(weak_provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(s_cfg);
    let connector = TlsConnector::from(Arc::new(c_cfg));
    let server_name = ServerName::try_from("cmis.test.ferrogate.invalid").unwrap();

    let server_task = tokio::spawn(async move {
        // Expected to fail; we don't care how exactly.
        let _ = acceptor.accept(server_io).await;
    });

    let res = connector.connect(server_name, client_io).await;
    assert!(
        res.is_err(),
        "legacy-only client must NOT complete a handshake against hybrid-only server"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn transport_builders_negotiate_the_hybrid_group() {
    // Exercise the *production* config builders (the ones cmis/mia use), not
    // the inline ones above, and assert the negotiated key-exchange group is
    // the hybrid group — the value the CMIS listener surfaces as telemetry.
    use ferro_crypto::transport::{client_config, is_hybrid_group, server_config};

    let ident = make_server_identity();
    let s_cfg = server_config(
        ProviderMode::HybridOnly,
        vec![ident.cert.clone()],
        ident.key.clone_key(),
    )
    .expect("server config");
    let c_cfg = client_config(ProviderMode::HybridOnly, vec![ident.pin]).expect("client config");

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(s_cfg);
    let connector = TlsConnector::from(c_cfg);
    let server_name = ServerName::try_from("cmis.test.ferrogate.invalid").unwrap();

    let server_task = tokio::spawn(async move {
        let stream = acceptor.accept(server_io).await.expect("server handshake");
        let group = {
            let (_io, conn) = stream.get_ref();
            conn.negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name)
        };
        assert!(
            is_hybrid_group(group),
            "server side must record the hybrid group as negotiated"
        );
    });

    let client = connector
        .connect(server_name, client_io)
        .await
        .expect("client handshake");
    let group = {
        let (_io, conn) = client.get_ref();
        conn.negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name)
    };
    assert!(
        is_hybrid_group(group),
        "client side must negotiate X25519MLKEM768"
    );

    server_task.await.expect("server task");
}

#[tokio::test]
async fn wrong_pin_rejects_otherwise_valid_server() {
    // Server cert is genuine; the client carries a pin for a *different*
    // certificate. The handshake must fail at certificate verification,
    // before any application traffic flows.
    let real = make_server_identity();
    let imposter = make_server_identity();
    let s_cfg = server_config(ProviderMode::HybridOnly, &real);

    let provider = Arc::new(ferrogate_provider(ProviderMode::HybridOnly));
    let verifier = SpkiPinVerifier::new(vec![imposter.pin], Arc::clone(&provider));
    let c_cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(s_cfg);
    let connector = TlsConnector::from(Arc::new(c_cfg));
    let server_name = ServerName::try_from("cmis.test.ferrogate.invalid").unwrap();

    let server_task = tokio::spawn(async move {
        let _ = acceptor.accept(server_io).await;
    });

    let res = connector.connect(server_name, client_io).await;
    assert!(res.is_err(), "wrong pin must fail closed");

    let _ = server_task.await;
}
