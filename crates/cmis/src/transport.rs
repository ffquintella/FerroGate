//! Hybrid-PQC TLS termination for the CMIS gRPC listener (feature F01).
//!
//! [`tls_incoming`] turns a bound [`TcpListener`] plus a rustls
//! [`ServerConfig`] (built by [`ferro_crypto::transport::server_config`]) into
//! a stream of accepted, handshake-complete TLS connections suitable for
//! [`tonic::transport::Server::serve_with_incoming`]. Each connection's
//! negotiated key-exchange group is logged as a telemetry field so operators
//! can confirm every accepted connection used the hybrid `X25519MLKEM768`
//! group; a connection that fails the handshake (for example a legacy,
//! non-PQC client against a `HybridOnly` server) is logged and dropped before
//! it ever reaches the gRPC layer.
//!
//! [`load_pem_identity`] reads the server certificate chain and private key
//! from PEM files for the bring-up binary.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;

/// Channel depth for accepted-but-not-yet-served TLS connections. Bounds the
/// number of completed handshakes buffered ahead of the gRPC server.
const ACCEPT_BUFFER: usize = 128;

/// Load a PEM certificate chain and private key for the server identity.
///
/// `cert_path` holds the end-entity certificate followed by any intermediates;
/// `key_path` holds a single PKCS#8 / PKCS#1 / SEC1 private key.
pub fn load_pem_identity(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("reading TLS cert {}: {e}", cert_path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing TLS cert {}: {e}", cert_path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let key_bytes = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("reading TLS key {}: {e}", key_path.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| match e {
        pem::Error::NoItemsFound => {
            anyhow::anyhow!("no private key found in {}", key_path.display())
        }
        e => anyhow::anyhow!("parsing TLS key {}: {e}", key_path.display()),
    })?;

    Ok((certs, key))
}

/// Accept TLS connections on `listener` and yield the handshake-complete
/// streams for [`tonic::transport::Server::serve_with_incoming`].
///
/// Handshakes run concurrently (one task per connection) so a slow or stalled
/// peer cannot block accepting others. A failed handshake is logged at debug
/// and dropped — it never appears in the returned stream — so the gRPC server
/// only ever sees authenticated, hybrid-PQC-protected connections.
pub fn tls_incoming(
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
) -> impl Stream<Item = Result<TlsStream<TcpStream>, io::Error>> {
    let acceptor = TlsAcceptor::from(server_config);
    let (tx, rx) = tokio::sync::mpsc::channel(ACCEPT_BUFFER);

    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept failed");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match acceptor.accept(tcp).await {
                    Ok(stream) => {
                        let group = {
                            let (_io, conn) = stream.get_ref();
                            conn.negotiated_key_exchange_group()
                                .map(tokio_rustls::rustls::crypto::SupportedKxGroup::name)
                        };
                        let label = ferro_crypto::transport::group_label(group);
                        if ferro_crypto::transport::is_hybrid_group(group) {
                            tracing::info!(
                                %peer,
                                kx_group = %label,
                                "TLS connection established (hybrid PQC)"
                            );
                        } else {
                            // Unreachable under ProviderMode::HybridOnly (the
                            // handshake would have failed); log loudly if a
                            // fallback-mode deployment ever lets it through.
                            tracing::warn!(
                                %peer,
                                kx_group = %label,
                                "TLS connection negotiated a NON-hybrid group"
                            );
                        }
                        // Receiver gone ⇒ server is shutting down; drop quietly.
                        let _ = tx.send(Ok(stream)).await;
                    }
                    Err(e) => {
                        tracing::debug!(
                            %peer,
                            error = %e,
                            "TLS handshake failed; dropping connection"
                        );
                    }
                }
            });
        }
    });

    ReceiverStream::new(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `cert` and `key` PEM into a fresh per-test temp dir.
    fn write_pair(tag: &str, cert: &str, key: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "cmis-transport-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path) = (dir.join("server.crt"), dir.join("server.key"));
        std::fs::write(&cert_path, cert).unwrap();
        std::fs::write(&key_path, key).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn loads_rcgen_identity() {
        let ck =
            rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".into()]).unwrap();
        let (cert, key) = write_pair("ok", &ck.cert.pem(), &ck.signing_key.serialize_pem());
        let (certs, key) = load_pem_identity(&cert, &key).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), ck.cert.der().as_ref());
        assert_eq!(key.secret_der(), ck.signing_key.serialize_der().as_slice());
    }

    #[test]
    fn rejects_missing_cert_and_key() {
        let ck =
            rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".into()]).unwrap();
        let key_pem = ck.signing_key.serialize_pem();

        let (cert, key) = write_pair("nocert", "not a pem file\n", &key_pem);
        let err = load_pem_identity(&cert, &key).unwrap_err().to_string();
        assert!(err.starts_with("no certificates found"), "{err}");

        // A certificate where the key should be: no private key section.
        let (cert, key) = write_pair("nokey", &ck.cert.pem(), &ck.cert.pem());
        let err = load_pem_identity(&cert, &key).unwrap_err().to_string();
        assert!(err.starts_with("no private key found"), "{err}");
    }
}
