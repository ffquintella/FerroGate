//! `ferro-transport` — the shared client-side dialer for the FerroGate
//! hybrid-PQC gRPC transport (feature F01).
//!
//! [`connect_pinned`] dials an `https://host:port` CMIS authority over TLS 1.3
//! with the hybrid `X25519MLKEM768` key-exchange group, authenticating the
//! server by SPKI pin rather than a CA chain. It returns a bare tonic
//! [`Channel`] so each caller wraps it in its own generated client:
//!
//! - the MIA agent wraps it in `MachineIdentityClient` for the attestation loop
//!   (see [`mia::client::connect_pinned`](../mia/client/fn.connect_pinned.html));
//! - the `ferrogate` operator CLI wraps it in `MachineIdentityClient` for the
//!   admin surface.
//!
//! The rustls config (provider + pin verifier) is built by
//! [`ferro_crypto::transport::client_config`]; this crate only adds the
//! per-runtime glue (a `tokio_rustls` connector behind a tower service) that
//! `ferro-crypto` is deliberately kept free of.

#![forbid(unsafe_code)]

use std::io;

use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};

/// Dial a CMIS endpoint over the FerroGate hybrid-PQC transport (feature F01),
/// authenticating the server by SPKI pin.
///
/// `endpoint` is an `https://host:port` authority; `pins` are the accepted
/// SHA-384 SPKI pins of the CMIS certificate. The returned [`Channel`]'s
/// connections:
///
/// - use the `X25519MLKEM768`-only provider, so a non-hybrid CMIS is rejected
///   at the handshake; and
/// - trust the server by SPKI pin, not a CA chain, so a wrong-pin (or
///   otherwise-valid-but-unpinned) server is rejected before any application
///   RPC — the hostname is used only for SNI/routing.
///
/// Callers wrap the returned channel in their own generated gRPC client (for
/// example `MachineIdentityClient::new(channel)`).
///
/// # Panics
///
/// Panics if `pins` is empty; see [`ferro_crypto::transport::client_config`].
pub async fn connect_pinned(endpoint: &str, pins: Vec<SpkiPin>) -> anyhow::Result<Channel> {
    let tls = ferro_crypto::transport::client_config(ProviderMode::HybridOnly, pins)?;
    let connector = TlsConnector::from(tls);

    // The custom connector performs the TLS upgrade itself, so tonic's own
    // (disabled) TLS must not engage: hand the `Endpoint` an `http://`
    // authority derived from the requested host:port. The connector still
    // wraps every connection in hybrid-PQC TLS below.
    let requested: Uri = endpoint
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid endpoint {endpoint:?}: {e}"))?;
    let host = requested
        .host()
        .ok_or_else(|| anyhow::anyhow!("endpoint {endpoint:?} has no host"))?;
    let port = requested.port_u16().unwrap_or(8443);
    let ep = Endpoint::from_shared(format!("http://{host}:{port}"))?;

    let service = tower::service_fn(move |uri: Uri| {
        let connector = connector.clone();
        async move {
            let host = uri.host().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no host")
            })?;
            let port = uri.port_u16().unwrap_or(8443);
            let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid server name: {e}"),
                )
            })?;
            let tcp = TcpStream::connect((host, port)).await?;
            let tls = connector.connect(server_name, tcp).await?;
            Ok::<_, io::Error>(TokioIo::new(tls))
        }
    });

    let channel = ep.connect_with_connector(service).await?;
    Ok(channel)
}
