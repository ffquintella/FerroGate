//! Optional mutual TLS for the CMIS admin listener (feature F20 §2,
//! `CMIS_ADMIN_CLIENT_CA`): the server requires a client certificate chaining
//! to the configured CA, on top of the hybrid-PQC transport.

use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferro_crypto::transport::{
    client_config, client_config_with_client_auth, server_config_with_client_auth,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct Ca {
    cert: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

fn make_ca(name: &str) -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Ca {
        cert: cert.der().clone(),
        issuer: Issuer::new(params, key),
    }
}

fn client_identity(ca: &Ca) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut params = CertificateParams::new(vec!["admin.example.invalid".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    (
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

fn server_identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>, SpkiPin) {
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .unwrap();
    let cert = ck.cert.der().clone();
    let pin = SpkiPin::from_certificate_der(cert.as_ref()).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    (cert, key, pin)
}

/// Run one handshake; returns the client certificate chain the server saw.
async fn handshake(
    client_ca: &Ca,
    client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Option<Vec<CertificateDer<'static>>>, String> {
    let (cert, key, pin) = server_identity();
    let s_cfg = server_config_with_client_auth(
        ProviderMode::HybridOnly,
        vec![cert],
        key,
        vec![client_ca.cert.clone()],
    )
    .map_err(|e| e.to_string())?;
    let c_cfg = match client {
        Some((chain, key)) => {
            client_config_with_client_auth(ProviderMode::HybridOnly, vec![pin], chain, key)
        }
        None => client_config(ProviderMode::HybridOnly, vec![pin]),
    }
    .map_err(|e| e.to_string())?;

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(s_cfg);
    let server = tokio::spawn(async move {
        acceptor.accept(server_io).await.map(|s| {
            let (_io, conn) = s.get_ref();
            conn.peer_certificates().map(<[CertificateDer<'_>]>::to_vec)
        })
    });
    let connector = TlsConnector::from(c_cfg);
    let name = ServerName::try_from("cmis.test.ferrogate.invalid").unwrap();
    // TLS 1.3 client auth is verified after the client's handshake completes,
    // so the server side is the authoritative outcome.
    let _client = connector.connect(name, client_io).await;
    server
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn a_client_certificate_from_the_configured_ca_is_accepted_and_visible() {
    let ca = make_ca("admin-ca");
    let ident = client_identity(&ca);
    let leaf = ident.0[0].clone();
    let seen = handshake(&ca, Some(ident)).await.expect("handshake");
    assert_eq!(seen.unwrap()[0], leaf, "server sees the client leaf");
}

#[tokio::test]
async fn a_client_without_a_certificate_is_refused() {
    let ca = make_ca("admin-ca");
    assert!(handshake(&ca, None).await.is_err());
}

#[tokio::test]
async fn a_client_certificate_from_another_ca_is_refused() {
    let ca = make_ca("admin-ca");
    let other = make_ca("rogue-ca");
    assert!(handshake(&ca, Some(client_identity(&other))).await.is_err());
}
