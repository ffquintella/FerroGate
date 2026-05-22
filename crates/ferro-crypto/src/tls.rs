//! Hybrid post-quantum rustls [`CryptoProvider`] for FerroGate (feature F01).
//!
//! Production deployments use [`ferrogate_provider`] with
//! [`ProviderMode::HybridOnly`], which advertises *only* the
//! `X25519MLKEM768` named group. A development-mode escape hatch
//! ([`ProviderMode::HybridPreferredWithX25519Fallback`]) keeps a pure
//! `X25519` group as a lower-priority fallback for interop bring-up;
//! CMIS rejects it in production via configuration.
//!
//! All sessions are TLS 1.3 with one of the two AEAD suites mandated by
//! the design document.

use rustls::crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup};
use rustls::SupportedCipherSuite;

/// Operating mode for the FerroGate crypto provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderMode {
    /// Advertise only `X25519MLKEM768`. The handshake fails if the peer
    /// does not support the hybrid group. This is the production setting.
    HybridOnly,
    /// Advertise `X25519MLKEM768` first and plain `X25519` second. Useful
    /// for interop bring-up. CMIS must reject this in production by
    /// configuration (`hybrid_tls_only = true`).
    HybridPreferredWithX25519Fallback,
}

/// AEAD cipher suites accepted by FerroGate, in preference order.
///
/// TLS 1.3 only; the two suites match the design document and both are
/// AEAD-secure under hybrid key exchange.
pub const FERROGATE_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
];

/// Build a rustls [`CryptoProvider`] preconfigured for FerroGate.
///
/// The returned provider:
///
/// - Uses the `aws_lc_rs` backend for all primitives.
/// - Restricts cipher suites to those in [`FERROGATE_CIPHER_SUITES`].
/// - Restricts named groups according to `mode`.
///
/// The provider is meant to be installed as a process default with
/// [`CryptoProvider::install_default`] or threaded into per-connection
/// `ClientConfig` / `ServerConfig` builders.
#[must_use]
pub fn ferrogate_provider(mode: ProviderMode) -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = kx_groups(mode);
    provider.cipher_suites = FERROGATE_CIPHER_SUITES.to_vec();
    provider
}

/// Return the named groups for `mode`, in advertised preference order.
///
/// Exposed for tests and for callers that want to assert on the exact
/// configuration before installing a provider.
#[must_use]
pub fn kx_groups(mode: ProviderMode) -> Vec<&'static dyn SupportedKxGroup> {
    match mode {
        ProviderMode::HybridOnly => vec![rustls_post_quantum::X25519MLKEM768],
        ProviderMode::HybridPreferredWithX25519Fallback => vec![
            rustls_post_quantum::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::NamedGroup;

    /// IANA codepoint for the hybrid group, draft-ietf-tls-hybrid-design.
    /// Kept here as an independent witness so a silent rename upstream
    /// would surface as a failing test.
    const X25519_MLKEM768_CODEPOINT: u16 = 0x11EC;

    #[test]
    fn hybrid_only_lists_exactly_one_kx_group() {
        let groups = kx_groups(ProviderMode::HybridOnly);
        assert_eq!(groups.len(), 1, "hybrid-only must advertise only one group");
        assert_eq!(
            groups[0].name(),
            NamedGroup::from(X25519_MLKEM768_CODEPOINT),
            "the single advertised group must be X25519MLKEM768",
        );
    }

    #[test]
    fn fallback_mode_lists_hybrid_first_then_x25519() {
        let groups = kx_groups(ProviderMode::HybridPreferredWithX25519Fallback);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].name(),
            NamedGroup::from(X25519_MLKEM768_CODEPOINT)
        );
        assert_eq!(groups[1].name(), NamedGroup::X25519);
    }

    #[test]
    fn provider_uses_only_ferrogate_cipher_suites() {
        let provider = ferrogate_provider(ProviderMode::HybridOnly);
        assert_eq!(provider.cipher_suites.len(), FERROGATE_CIPHER_SUITES.len());
        // No TLS 1.2 suites should slip in.
        for cs in &provider.cipher_suites {
            assert_eq!(cs.version().version, rustls::ProtocolVersion::TLSv1_3);
        }
    }

    #[test]
    fn provider_hybrid_only_does_not_contain_plain_x25519() {
        let provider = ferrogate_provider(ProviderMode::HybridOnly);
        for g in &provider.kx_groups {
            assert_ne!(
                g.name(),
                NamedGroup::X25519,
                "plain X25519 must not appear in HybridOnly mode",
            );
        }
    }
}
