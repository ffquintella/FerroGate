//! Measurement-bound sealing for share envelopes.
//!
//! Each CMIS replica owns a Shamir share at rest. The share must only be
//! unsealable inside the same enclave measurement that sealed it: a node
//! whose firmware is rolled back, or a different vendor image, must not be
//! able to read the share even with disk access.
//!
//! The construction:
//!
//! 1. The replica's [`Attestor::sealing_root`](crate::attest::Attestor)
//!    yields a 32-byte high-entropy secret bound to its launch
//!    measurement. In hardware this comes from the SEV-SNP VCEK / TDX
//!    sealing key; in tests the software attestor derives it from its
//!    private signing material so a different attestor instance — even
//!    with the same measurement — gets a fresh sealing root.
//! 2. The per-envelope encryption key is derived as
//!    `HKDF-SHA3-384(salt = measurement, ikm = sealing_root,
//!                   info = "ferro-tee-seal-v1" || aad).expand(32)`.
//!    Binding the salt to the measurement is belt-and-braces — the IKM is
//!    already measurement-bound — and keeps the construction safe if a
//!    future attestor variant doesn't fold the measurement into its root.
//! 3. ChaCha20-Poly1305 encrypts the plaintext with a fresh 12-byte random
//!    nonce. The nonce is stored alongside the ciphertext; the AAD is
//!    bound into the tag.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChachaKey, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::Sha3_384;

use crate::attest::Attestor;
use crate::error::TeeError;
use crate::measurement::Measurement;

/// Domain separator for the seal KDF.
const SEAL_INFO: &[u8] = b"ferro-tee-seal-v1";

/// A measurement-bound sealed envelope. Carries the AAD in the clear so
/// unsealing can recompute the binding without a side-channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// Measurement the envelope was sealed against.
    pub measurement: Measurement,
    /// Random 12-byte ChaCha20-Poly1305 nonce.
    pub nonce: [u8; 12],
    /// Application-defined AAD (e.g. share index, key id).
    #[serde(with = "serde_bytes")]
    pub aad: Vec<u8>,
    /// Ciphertext + 16-byte Poly1305 tag.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

fn derive_key(sealing_root: &[u8; 32], measurement: &Measurement, aad: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_384>::new(Some(measurement.as_bytes()), sealing_root);
    let mut info = Vec::with_capacity(SEAL_INFO.len() + 8 + aad.len());
    info.extend_from_slice(SEAL_INFO);
    info.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    info.extend_from_slice(aad);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("HKDF-Expand of 32 bytes from SHA3-384 always succeeds");
    out
}

/// Seal `plaintext` against the local attestor's measurement and root.
///
/// `aad` is bound into the AEAD tag and the KDF and travels in clear.
pub fn seal(
    attestor: &dyn Attestor,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedEnvelope, TeeError> {
    let measurement = attestor.measurement();
    let sealing_root = attestor.sealing_root();
    let key = derive_key(&sealing_root, &measurement, aad);
    let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| TeeError::Seal)?;
    Ok(SealedEnvelope {
        measurement,
        nonce: nonce_bytes,
        aad: aad.to_vec(),
        ciphertext: ct,
    })
}

/// Unseal an envelope using the local attestor.
///
/// Fails closed if the envelope was sealed against a different measurement
/// than the local attestor's, or if the ciphertext / AAD has been tampered
/// with.
pub fn unseal(attestor: &dyn Attestor, env: &SealedEnvelope) -> Result<Vec<u8>, TeeError> {
    if env.measurement != attestor.measurement() {
        return Err(TeeError::Seal);
    }
    let sealing_root = attestor.sealing_root();
    let key = derive_key(&sealing_root, &env.measurement, &env.aad);
    let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&key));
    cipher
        .decrypt(
            Nonce::from_slice(&env.nonce),
            Payload {
                msg: &env.ciphertext,
                aad: &env.aad,
            },
        )
        .map_err(|_| TeeError::Seal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::SoftwareAttestor;

    #[test]
    fn seal_and_unseal_round_trips() {
        let a = SoftwareAttestor::generate(Measurement([5u8; 48]));
        let pt = b"secret share material".to_vec();
        let env = seal(&a, b"aad", &pt).unwrap();
        let got = unseal(&a, &env).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn different_attestor_with_same_measurement_cannot_unseal() {
        let a1 = SoftwareAttestor::generate(Measurement([5u8; 48]));
        let a2 = SoftwareAttestor::generate(Measurement([5u8; 48]));
        let env = seal(&a1, b"aad", b"top secret").unwrap();
        // Same measurement label but different sealing root: the AEAD must
        // fail. (In hardware the sealing root is derived from the per-CPU
        // VCEK plus measurement, so the analogue is "different CPU".)
        let err = unseal(&a2, &env).unwrap_err();
        assert!(matches!(err, TeeError::Seal));
    }

    #[test]
    fn tampered_aad_is_rejected() {
        let a = SoftwareAttestor::generate(Measurement([6u8; 48]));
        let mut env = seal(&a, b"aad", b"plaintext").unwrap();
        env.aad = b"AAD".to_vec();
        let err = unseal(&a, &env).unwrap_err();
        assert!(matches!(err, TeeError::Seal));
    }

    #[test]
    fn wrong_measurement_is_rejected_before_aead() {
        let sealer = SoftwareAttestor::generate(Measurement([1u8; 48]));
        let unsealer = SoftwareAttestor::generate(Measurement([2u8; 48]));
        let env = seal(&sealer, b"aad", b"plaintext").unwrap();
        let err = unseal(&unsealer, &env).unwrap_err();
        assert!(matches!(err, TeeError::Seal));
    }
}
