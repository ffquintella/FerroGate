//! macOS Secure Enclave backend for [`MachineKey`](crate::MachineKey).
//!
//! Generates and uses a **non-exportable** ECDSA P-256 key inside the Secure
//! Enclave (`kSecAttrTokenIDSecureEnclave`). The private key never leaves the
//! SEP: [`SecureEnclaveKey::sign`] hands the message to the Enclave and gets
//! back a signature. A cloned disk cannot carry the key to other hardware, and
//! root cannot extract it — the property a file-backed key lacks.
//!
//! Built only on macOS, and only with the `secure-enclave` feature, because it
//! links Security.framework. In production `mia` must be code-signed (and, to
//! persist the key in the keychain, carry a keychain-access-group entitlement);
//! generation on an unsigned binary may be refused by the OS at runtime. The
//! crate stays `#![forbid(unsafe_code)]` — all FFI is inside the safe
//! `security-framework` wrappers.

use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

use crate::{spki_from_sec1, MachineKey, SepError};

/// ECDSA-P256 message signing with an internal SHA-256 hash — the algorithm the
/// portable verifier ([`crate::verify_p256`]) expects.
const SIGN_ALG: Algorithm = Algorithm::ECDSASignatureMessageX962SHA256;

/// A signing key resident in the macOS Secure Enclave.
pub struct SecureEnclaveKey {
    key: SecKey,
}

impl SecureEnclaveKey {
    /// Generate a fresh non-exportable P-256 key inside the Secure Enclave,
    /// tagged with `label`.
    ///
    /// # Errors
    /// Returns [`SepError::Enclave`] if the Enclave refuses generation (e.g. no
    /// SEP present, or the binary lacks the required signing/entitlement).
    pub fn generate(label: &str) -> Result<Self, SepError> {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec());
        opts.set_size_in_bits(256);
        opts.set_token(Token::SecureEnclave);
        opts.set_label(label);
        let key = SecKey::new(&opts)
            .map_err(|e| SepError::Enclave(format!("generate in Secure Enclave: {e}")))?;
        Ok(Self { key })
    }

    /// The Enclave-resident public key as a 65-byte uncompressed SEC1 point.
    fn public_point(&self) -> Result<Vec<u8>, SepError> {
        let pubkey = self
            .key
            .public_key()
            .ok_or_else(|| SepError::Enclave("no public key for SEP key".to_string()))?;
        let data = pubkey
            .external_representation()
            .ok_or_else(|| SepError::Enclave("public key has no external representation".to_string()))?;
        Ok(data.to_vec())
    }
}

impl MachineKey for SecureEnclaveKey {
    fn public_spki_der(&self) -> Vec<u8> {
        // external_representation of an EC public key is the X9.63 uncompressed
        // point (0x04 ‖ X ‖ Y); wrap it in DER SPKI. On the rare failure path we
        // return an empty vec, which the verifier rejects cleanly.
        self.public_point()
            .map(|p| spki_from_sec1(&p))
            .unwrap_or_default()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SepError> {
        self.key
            .create_signature(SIGN_ALG, message)
            .map_err(|e| SepError::Sign(format!("Secure Enclave signature: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256;

    /// Live Secure Enclave round-trip on real hardware. Ignored by default: it
    /// needs a SEP-equipped Mac and may require a signed binary, so it is opt-in
    /// via `cargo test -p ferro-sep --features secure-enclave -- --ignored`.
    #[test]
    #[ignore = "requires a Secure Enclave and possibly a signed binary"]
    fn live_sep_sign_then_verify() {
        let key = SecureEnclaveKey::generate("ferrogate-mia-test-key")
            .expect("generate SEP key on this hardware");
        let spki = key.public_spki_der();
        assert!(!spki.is_empty(), "SEP public key should export");
        let msg = b"nonce || fingerprint";
        let sig = key.sign(msg).expect("SEP signs");
        verify_p256(&spki, msg, &sig).expect("SEP signature verifies with the portable verifier");
    }
}
