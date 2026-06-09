//! SPKI pin verification for FerroGate client connections (feature F01).
//!
//! The MIA does not rely on a public CA hierarchy to authenticate CMIS.
//! Instead it pins one or more SHA-384 hashes of the
//! `SubjectPublicKeyInfo` (SPKI) of accepted CMIS certificates. The MIA
//! must abort the handshake before any TPM operation when the presented
//! certificate's SPKI hash is not in the pin set.
//!
//! [`SpkiPin`] computes and represents these hashes. [`SpkiPinVerifier`]
//! plugs into a rustls [`ClientConfig`] via
//! [`ClientConfig::dangerous().with_custom_certificate_verifier(...)`].
//! "Dangerous" here just means "we are not delegating to a CA"; pinning is
//! the intended trust model.
//!
//! Pins are SHA-2 / FIPS-180-4, **not** SHA-3. That is consistent with
//! every other SPKI-pinning ecosystem (HPKP, RFC 7469 family) and with
//! `docs/crypto.md` §"Hash" for the TPM/X.509 surface.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use rustls::{DigitallySignedStruct, Error};
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;
use x509_parser::prelude::*;

/// Length of a SHA-384 SPKI hash in bytes.
pub const SPKI_PIN_LEN: usize = 48;

/// A SHA-384 pin over a certificate's `SubjectPublicKeyInfo`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpkiPin([u8; SPKI_PIN_LEN]);

/// Errors returned when constructing or parsing an [`SpkiPin`].
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// The supplied certificate could not be parsed as DER X.509.
    #[error("certificate DER parse failed: {0}")]
    CertParse(String),
    /// The supplied hex string did not decode to a 48-byte SHA-384.
    #[error("invalid SHA-384 hex pin: {0}")]
    HexDecode(String),
}

impl SpkiPin {
    /// Build a pin from a raw 48-byte SHA-384 digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SPKI_PIN_LEN]) -> Self {
        Self(bytes)
    }

    /// Build a pin from a hex string (case-insensitive, no `0x` prefix).
    pub fn from_hex(s: &str) -> Result<Self, PinError> {
        let raw = hex::decode(s.trim()).map_err(|e| PinError::HexDecode(e.to_string()))?;
        let arr: [u8; SPKI_PIN_LEN] = raw
            .try_into()
            .map_err(|_| PinError::HexDecode(format!("expected {SPKI_PIN_LEN} bytes")))?;
        Ok(Self(arr))
    }

    /// Compute the SPKI pin of a DER-encoded X.509 certificate.
    pub fn from_certificate_der(cert_der: &[u8]) -> Result<Self, PinError> {
        let (_, parsed) =
            X509Certificate::from_der(cert_der).map_err(|e| PinError::CertParse(e.to_string()))?;
        // `subject_pki.raw` is the DER of the full SubjectPublicKeyInfo
        // SEQUENCE, which is what every SPKI-pinning convention hashes.
        let spki_der = parsed.tbs_certificate.subject_pki.raw;
        let mut hasher = Sha384::new();
        hasher.update(spki_der);
        let digest = hasher.finalize();
        let mut out = [0u8; SPKI_PIN_LEN];
        out.copy_from_slice(&digest);
        Ok(Self(out))
    }

    /// Raw 48-byte view of the pin.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SPKI_PIN_LEN] {
        &self.0
    }

    /// Lowercase hex encoding (no `0x` prefix).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Debug for SpkiPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Pins are not secret, but a short prefix is friendlier in logs.
        let s = self.to_hex();
        write!(f, "SpkiPin({}…)", &s[..16])
    }
}

impl ConstantTimeEq for SpkiPin {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// rustls server certificate verifier that authenticates a peer by SPKI pin.
///
/// Verification rules:
///
/// 1. The end-entity certificate's SPKI hash must equal one of the
///    configured pins (constant-time compared).
/// 2. The end-entity certificate's TLS 1.3 handshake signature must verify
///    under the FerroGate [`CryptoProvider`]'s signature algorithms.
///
/// Intermediate certificates are intentionally *not* validated. The trust
/// anchor is the pin, not a CA chain.
#[derive(Debug)]
pub struct SpkiPinVerifier {
    pins: Vec<SpkiPin>,
    provider: Arc<CryptoProvider>,
}

impl SpkiPinVerifier {
    /// Create a new verifier accepting any of the supplied pins.
    ///
    /// # Panics
    ///
    /// Panics if `pins` is empty: an empty pin set would either reject
    /// every connection (silent denial-of-service) or, worse, accidentally
    /// be combined with a `pins.is_empty()` shortcut. The caller must
    /// intend a non-empty set.
    #[must_use]
    pub fn new(pins: Vec<SpkiPin>, provider: Arc<CryptoProvider>) -> Arc<Self> {
        assert!(
            !pins.is_empty(),
            "SpkiPinVerifier requires at least one pin"
        );
        Arc::new(Self { pins, provider })
    }

    fn matches(&self, candidate: &SpkiPin) -> bool {
        let mut found = subtle::Choice::from(0u8);
        for pin in &self.pins {
            found |= pin.ct_eq(candidate);
        }
        bool::from(found)
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let candidate = SpkiPin::from_certificate_der(end_entity.as_ref())
            .map_err(|e| Error::General(format!("SPKI parse failed: {e}")))?;
        if self.matches(&candidate) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("SPKI pin mismatch".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // FerroGate is TLS 1.3-only; surface this loudly rather than
        // silently accepting a downgrade.
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny rcgen self-signed cert helper to keep tests focused on pin logic.
    fn sample_cert() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["test.ferrogate.invalid".to_string()])
            .expect("rcgen self-signed cert")
    }

    #[test]
    fn pin_from_certificate_der_is_stable() {
        let ck = sample_cert();
        let der = ck.cert.der();
        let pin1 = SpkiPin::from_certificate_der(der.as_ref()).unwrap();
        let pin2 = SpkiPin::from_certificate_der(der.as_ref()).unwrap();
        assert_eq!(pin1, pin2, "SPKI pin must be deterministic for one cert");
        assert_eq!(pin1.as_bytes().len(), SPKI_PIN_LEN);
    }

    #[test]
    fn different_certs_have_different_pins() {
        let a = SpkiPin::from_certificate_der(sample_cert().cert.der().as_ref()).unwrap();
        let b = SpkiPin::from_certificate_der(sample_cert().cert.der().as_ref()).unwrap();
        assert_ne!(a, b, "two freshly generated certs must differ in SPKI");
    }

    #[test]
    fn hex_roundtrip() {
        let ck = sample_cert();
        let pin = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
        let s = pin.to_hex();
        let back = SpkiPin::from_hex(&s).unwrap();
        assert_eq!(pin, back);
    }

    #[test]
    fn hex_rejects_wrong_length() {
        let too_short = "deadbeef";
        assert!(matches!(
            SpkiPin::from_hex(too_short),
            Err(PinError::HexDecode(_))
        ));
    }

    #[test]
    fn from_certificate_der_rejects_garbage() {
        assert!(matches!(
            SpkiPin::from_certificate_der(b"this is not DER"),
            Err(PinError::CertParse(_))
        ));
    }

    #[test]
    #[should_panic(expected = "at least one pin")]
    fn verifier_rejects_empty_pin_set() {
        let provider = Arc::new(crate::tls::ferrogate_provider(
            crate::tls::ProviderMode::HybridOnly,
        ));
        let _ = SpkiPinVerifier::new(vec![], provider);
    }

    #[test]
    fn verifier_matches_known_pin_in_constant_time() {
        let ck = sample_cert();
        let pin = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
        let provider = Arc::new(crate::tls::ferrogate_provider(
            crate::tls::ProviderMode::HybridOnly,
        ));
        let verifier = SpkiPinVerifier::new(vec![pin], provider);
        assert!(verifier.matches(&pin));

        let other = SpkiPin::from_certificate_der(sample_cert().cert.der().as_ref()).unwrap();
        assert!(!verifier.matches(&other));
    }
}
