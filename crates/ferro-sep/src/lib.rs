//! `ferro-sep` — the machine signing key for the TPM-less `host-key`
//! attestation profile (feature F15).
//!
//! In the TPM profile the AIK — a restricted hardware signing key — signs the
//! quote and binds the issued SVID to the hardware. On a machine with no TPM,
//! this crate provides the substitute: an ECDSA P-256 key that signs the
//! handshake nonce and the SVID CSR.
//!
//! Two backends implement the [`MachineKey`] trait:
//!
//! - [`SoftwareMachineKey`] — a portable key persisted to a `0600` file. The
//!   default; used on Intel Macs, Linux, Windows, and in CI. The key sits at
//!   rest, so CMIS issues it a lower assurance level.
//! - [`enclave::SecureEnclaveKey`] — a **non-exportable** key generated inside
//!   the macOS Secure Enclave (`kSecAttrTokenIDSecureEnclave`). The private key
//!   never leaves the SEP and cannot be lifted off a running host or a cloned
//!   disk. Behind the off-by-default `secure-enclave` feature and only built on
//!   macOS, since it needs Security.framework (and, in production, a
//!   signed/entitled binary).
//!
//! The public key crosses the wire as DER `SubjectPublicKeyInfo`; the verifier
//! ([`verify_p256`]) re-parses it and checks the ECDSA signature. Both backends
//! sign with `ECDSA-P256 / SHA-256` and emit X9.62 DER signatures, so the
//! verifier is backend-agnostic.

#![forbid(unsafe_code)]

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::EncodedPoint;

#[cfg(all(target_os = "macos", feature = "secure-enclave"))]
pub mod enclave;

/// A hardware-or-software machine signing key.
///
/// Implementors hold (or reference) an ECDSA P-256 private key and expose only
/// what the handshake needs: the public key and a signing oracle. The private
/// key is never returned.
pub trait MachineKey {
    /// The public key as DER `SubjectPublicKeyInfo` (sent in `HostKeyEvidence`).
    fn public_spki_der(&self) -> Vec<u8>;

    /// Sign `message` with ECDSA-P256 over SHA-256, returning an X9.62 DER
    /// signature. The implementation hashes `message` internally.
    ///
    /// # Errors
    /// Returns [`SepError`] if the backing keystore refuses the operation.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SepError>;
}

/// Failure modes for machine-key operations.
#[derive(Debug, thiserror::Error)]
pub enum SepError {
    /// Key generation or random-number generation failed.
    #[error("key generation failed: {0}")]
    KeyGen(String),
    /// A signing operation failed in the backing keystore.
    #[error("signing failed: {0}")]
    Sign(String),
    /// Persisting or loading the key from disk failed.
    #[error("key store i/o: {0}")]
    Io(String),
    /// The stored key material was malformed.
    #[error("malformed key material: {0}")]
    Malformed(String),
    /// The Secure Enclave backend was unavailable or refused the request.
    #[error("secure enclave: {0}")]
    Enclave(String),
}

// ---- DER SubjectPublicKeyInfo for P-256 ---------------------------------

/// Fixed DER `SubjectPublicKeyInfo` prefix for an uncompressed `prime256v1`
/// (P-256) public key: the `SEQUENCE { AlgorithmIdentifier { ecPublicKey,
/// prime256v1 }, BIT STRING }` header, up to and including the unused-bits
/// octet. A 65-byte uncompressed EC point (`0x04 ‖ X ‖ Y`) follows.
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Wrap a 65-byte uncompressed SEC1 EC point into DER `SubjectPublicKeyInfo`.
#[must_use]
pub fn spki_from_sec1(point: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(P256_SPKI_PREFIX.len() + point.len());
    der.extend_from_slice(&P256_SPKI_PREFIX);
    der.extend_from_slice(point);
    der
}

/// Recover a P-256 verifying key from DER `SubjectPublicKeyInfo`.
///
/// Accepts the fixed-shape SPKI this crate emits (prefix + 65-byte point); also
/// tolerates a bare 65-byte uncompressed point for robustness.
fn verifying_key_from_spki(spki: &[u8]) -> Result<VerifyingKey, SepError> {
    let point_bytes: &[u8] = if spki.len() == P256_SPKI_PREFIX.len() + 65
        && spki[..P256_SPKI_PREFIX.len()] == P256_SPKI_PREFIX
    {
        &spki[P256_SPKI_PREFIX.len()..]
    } else if spki.len() == 65 && spki[0] == 0x04 {
        spki
    } else {
        return Err(SepError::Malformed(format!(
            "unexpected SPKI length {} or header",
            spki.len()
        )));
    };
    let point = EncodedPoint::from_bytes(point_bytes)
        .map_err(|e| SepError::Malformed(format!("EC point: {e}")))?;
    VerifyingKey::from_encoded_point(&point)
        .map_err(|e| SepError::Malformed(format!("verifying key: {e}")))
}

/// The canonical message the machine key signs in phase 2 of the host-key
/// handshake: the server `nonce` concatenated with the hardware fingerprint
/// `H`. Both the client (signer) and CMIS (verifier) build it through this one
/// function so the two can never drift.
#[must_use]
pub fn host_key_binding(nonce: &[u8], fingerprint: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(nonce.len() + fingerprint.len());
    m.extend_from_slice(nonce);
    m.extend_from_slice(fingerprint);
    m
}

/// Verify an X9.62 DER ECDSA-P256 signature over SHA-256(`message`) under the
/// public key in `spki`.
///
/// # Errors
/// Returns [`SepError::Malformed`] if the key or signature cannot be parsed, or
/// [`SepError::Sign`] if the signature does not verify.
pub fn verify_p256(spki: &[u8], message: &[u8], der_sig: &[u8]) -> Result<(), SepError> {
    let vk = verifying_key_from_spki(spki)?;
    let sig = Signature::from_der(der_sig)
        .map_err(|e| SepError::Malformed(format!("DER signature: {e}")))?;
    vk.verify(message, &sig)
        .map_err(|_| SepError::Sign("signature did not verify".to_string()))
}

// ---- Portable software backend ------------------------------------------

/// A portable machine key backed by an on-disk ECDSA P-256 private key.
///
/// Used wherever the Secure Enclave is unavailable (Intel Macs, Linux, Windows,
/// CI). The key is stored as its raw 32-byte scalar in a caller-protected file.
pub struct SoftwareMachineKey {
    signing: SigningKey,
}

impl SoftwareMachineKey {
    /// Generate a fresh random key.
    ///
    /// # Errors
    /// Returns [`SepError::KeyGen`] if the system RNG fails.
    pub fn generate() -> Result<Self, SepError> {
        // Rejection-sample a valid scalar from OS randomness. Out-of-range draws
        // are astronomically rare for P-256, but the loop keeps it correct.
        for _ in 0..16 {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes)
                .map_err(|e| SepError::KeyGen(format!("getrandom: {e}")))?;
            if let Ok(signing) = SigningKey::from_bytes((&bytes).into()) {
                return Ok(Self { signing });
            }
        }
        Err(SepError::KeyGen("no valid scalar after 16 draws".to_string()))
    }

    /// Reconstruct from a raw 32-byte scalar (as produced by [`Self::to_bytes`]).
    ///
    /// # Errors
    /// Returns [`SepError::Malformed`] if the bytes are not a valid scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SepError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SepError::Malformed(format!("expected 32 bytes, got {}", bytes.len())))?;
        let signing = SigningKey::from_bytes((&arr).into())
            .map_err(|e| SepError::Malformed(format!("scalar: {e}")))?;
        Ok(Self { signing })
    }

    /// The raw 32-byte private scalar, for persistence. Handle as a secret.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes().into()
    }

    /// Load the key from `path`, generating and persisting a new one if absent.
    ///
    /// The file holds the raw 32-byte scalar. Callers are responsible for the
    /// directory and file permissions (`0600`).
    ///
    /// # Errors
    /// Returns [`SepError::Io`] on filesystem errors and [`SepError::Malformed`]
    /// if an existing file is corrupt.
    pub fn open_or_create(path: &std::path::Path) -> Result<Self, SepError> {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_bytes(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                std::fs::write(path, key.to_bytes())
                    .map_err(|e| SepError::Io(format!("write {}: {e}", path.display())))?;
                Ok(key)
            }
            Err(e) => Err(SepError::Io(format!("read {}: {e}", path.display()))),
        }
    }

    fn verifying_key(&self) -> VerifyingKey {
        *self.signing.verifying_key()
    }
}

impl MachineKey for SoftwareMachineKey {
    fn public_spki_der(&self) -> Vec<u8> {
        let point = self.verifying_key().to_encoded_point(false);
        spki_from_sec1(point.as_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SepError> {
        let sig: Signature = self.signing.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_sign_then_verify_roundtrips() {
        let key = SoftwareMachineKey::generate().unwrap();
        let spki = key.public_spki_der();
        let msg = b"nonce || fingerprint";
        let sig = key.sign(msg).unwrap();
        verify_p256(&spki, msg, &sig).expect("signature verifies");
    }

    #[test]
    fn wrong_message_fails() {
        let key = SoftwareMachineKey::generate().unwrap();
        let spki = key.public_spki_der();
        let sig = key.sign(b"message one").unwrap();
        assert!(verify_p256(&spki, b"message two", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let signer = SoftwareMachineKey::generate().unwrap();
        let other = SoftwareMachineKey::generate().unwrap();
        let msg = b"bind me";
        let sig = signer.sign(msg).unwrap();
        assert!(verify_p256(&other.public_spki_der(), msg, &sig).is_err());
    }

    #[test]
    fn spki_is_well_formed() {
        let key = SoftwareMachineKey::generate().unwrap();
        let spki = key.public_spki_der();
        assert_eq!(spki.len(), P256_SPKI_PREFIX.len() + 65);
        assert_eq!(spki[P256_SPKI_PREFIX.len()], 0x04); // uncompressed point tag
    }

    #[test]
    fn persistence_roundtrip() {
        let key = SoftwareMachineKey::generate().unwrap();
        let bytes = key.to_bytes();
        let restored = SoftwareMachineKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.public_spki_der(), restored.public_spki_der());
    }

    #[test]
    fn bare_uncompressed_point_also_verifies() {
        // The verifier tolerates a raw 65-byte point as well as full SPKI.
        let key = SoftwareMachineKey::generate().unwrap();
        let spki = key.public_spki_der();
        let bare = &spki[P256_SPKI_PREFIX.len()..];
        let msg = b"x";
        let sig = key.sign(msg).unwrap();
        verify_p256(bare, msg, &sig).expect("bare point verifies");
    }
}
