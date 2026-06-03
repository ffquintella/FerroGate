//! Transport-agnostic rustls config builders for the FerroGate gRPC
//! transport (feature F01).
//!
//! These wrap [`crate::tls::ferrogate_provider`] and
//! [`crate::pin::SpkiPinVerifier`] into ready-to-use rustls [`ServerConfig`]
//! / [`ClientConfig`] values so the CMIS listener and the MIA client share one
//! definition of "the FerroGate transport": TLS 1.3 only, the hybrid
//! `X25519MLKEM768` group, the two FerroGate AEAD suites, and ALPN `h2`
//! (gRPC runs over HTTP/2).
//!
//! The module is deliberately free of any tonic / tokio-rustls dependency:
//! it produces plain rustls configs. The per-runtime glue (a `TlsAcceptor`
//! accept loop on the server, a tower connector on the client) lives in the
//! `cmis` and `mia` crates respectively.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, NamedGroup, ServerConfig};

use crate::pin::{SpkiPin, SpkiPinVerifier};
use crate::tls::{ferrogate_provider, ProviderMode};

/// ALPN protocol identifier for HTTP/2. gRPC is always carried over h2, so
/// both peers advertise exactly this and nothing else.
const ALPN_H2: &[u8] = b"h2";

/// The hybrid named group every accepted FerroGate connection must use.
///
/// Exposed so telemetry can compare a negotiated group against it without
/// re-deriving the IANA codepoint.
pub const HYBRID_GROUP: NamedGroup = NamedGroup::X25519MLKEM768;

/// Failure modes when building a transport config.
#[derive(Debug, thiserror::Error)]
pub enum TransportConfigError {
    /// rustls rejected the assembled configuration (e.g. the cert/key pair
    /// did not match, or the key could not be parsed).
    #[error("rustls config: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Build a server-side rustls config for the FerroGate transport.
///
/// `cert_chain` is the server's end-entity certificate followed by any
/// intermediates; `key` is its private key. The resulting config is TLS 1.3
/// only, restricted to the `mode`'s named groups (use
/// [`ProviderMode::HybridOnly`] in production), and advertises ALPN `h2`.
pub fn server_config(
    mode: ProviderMode,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TransportConfigError> {
    let provider = Arc::new(ferrogate_provider(mode));
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(Arc::new(cfg))
}

/// Build a client-side rustls config that authenticates the server by SPKI
/// pin instead of a CA chain.
///
/// The handshake fails closed (before any application byte flows) if the
/// server's end-entity SPKI hash is not one of `pins`, or — in
/// [`ProviderMode::HybridOnly`] — if the server does not support the hybrid
/// group. ALPN is fixed to `h2`.
///
/// # Panics
///
/// Panics if `pins` is empty (an empty pin set would silently reject every
/// connection); see [`SpkiPinVerifier::new`].
pub fn client_config(
    mode: ProviderMode,
    pins: Vec<SpkiPin>,
) -> Result<Arc<ClientConfig>, TransportConfigError> {
    let provider = Arc::new(ferrogate_provider(mode));
    let verifier = SpkiPinVerifier::new(pins, Arc::clone(&provider));
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(Arc::new(cfg))
}

/// Whether a negotiated key-exchange group is the FerroGate hybrid group.
///
/// `group` is what `rustls`'s `negotiated_key_exchange_group().map(|g|
/// g.name())` yields after a handshake. In [`ProviderMode::HybridOnly`] this
/// is always true for an *accepted* connection — the assertion exists so
/// telemetry can prove it rather than assume it.
#[must_use]
pub fn is_hybrid_group(group: Option<NamedGroup>) -> bool {
    group == Some(HYBRID_GROUP)
}

/// Human-readable label for a negotiated group, for logs and audit fields.
///
/// Returns `"X25519MLKEM768"` for the hybrid group and a debug rendering for
/// anything else (which, under `HybridOnly`, should never appear on an
/// accepted connection).
#[must_use]
pub fn group_label(group: Option<NamedGroup>) -> String {
    match group {
        Some(HYBRID_GROUP) => "X25519MLKEM768".to_string(),
        Some(other) => format!("{other:?}"),
        None => "none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_group_constant_matches_codepoint() {
        // Independent witness: the hybrid group's IANA codepoint is 0x11EC
        // (draft-ietf-tls-hybrid-design). A silent upstream rename would
        // surface here.
        assert_eq!(HYBRID_GROUP, NamedGroup::from(0x11ECu16));
    }

    #[test]
    fn is_hybrid_group_classifies() {
        assert!(is_hybrid_group(Some(HYBRID_GROUP)));
        assert!(!is_hybrid_group(Some(NamedGroup::X25519)));
        assert!(!is_hybrid_group(None));
    }

    #[test]
    fn group_label_is_friendly_for_hybrid() {
        assert_eq!(group_label(Some(HYBRID_GROUP)), "X25519MLKEM768");
        assert_eq!(group_label(None), "none");
    }
}
