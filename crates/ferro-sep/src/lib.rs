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
            getrandom::fill(&mut bytes)
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

    /// Load a **sealed** key from `path`, generating and persisting a new sealed
    /// one if absent.
    ///
    /// Unlike [`Self::open_or_create`], the on-disk scalar is encrypted with an
    /// AEAD key derived (HKDF-SHA256) from `seal_secret` — a machine-bound value
    /// such as the hardware fingerprint. A key file copied to a different host
    /// will not decrypt there, because that host derives a different
    /// `seal_secret`. This is clone *resistance* bound to machine identity, not a
    /// hardware root of trust: an attacker with both the file and the seal secret
    /// (e.g. root on the same host) can still recover the key.
    ///
    /// The file still holds a secret and callers remain responsible for `0600`
    /// permissions.
    ///
    /// # Errors
    /// Returns [`SepError::Io`] on filesystem errors, [`SepError::KeyGen`] on RNG
    /// or key-derivation failure, and [`SepError::Malformed`] if an existing file
    /// is not a sealed key or fails to decrypt (wrong host or corruption).
    pub fn open_or_create_sealed(
        path: &std::path::Path,
        seal_secret: &[u8],
    ) -> Result<Self, SepError> {
        match std::fs::read(path) {
            // Seamless upgrade: a pre-F16 file is the raw 32-byte scalar with no
            // magic. Load it, then re-seal in place so the *same* key (and thus
            // the pubkey CMIS has pinned) is preserved — regenerating would change
            // the identity and be rejected at enrollment.
            Ok(bytes) if bytes.len() == 32 && bytes[0..4] != SEAL_MAGIC => {
                let key = Self::from_bytes(&bytes)?;
                let mut scalar = key.to_bytes();
                let blob = seal_scalar(&scalar, seal_secret);
                scalar.zeroize();
                if let Ok(blob) = blob {
                    // Best-effort: if the re-seal write fails the daemon still runs
                    // this session; it just re-migrates next start.
                    let _ = std::fs::write(path, &blob);
                }
                Ok(key)
            }
            Ok(bytes) => {
                let mut scalar = unseal_scalar(&bytes, seal_secret)?;
                let key = Self::from_bytes(&scalar);
                scalar.zeroize();
                key
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                let mut scalar = key.to_bytes();
                let blob = seal_scalar(&scalar, seal_secret);
                scalar.zeroize();
                let blob = blob?;
                std::fs::write(path, &blob)
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

// ---- Clone-resistant at-rest sealing (F16) ------------------------------

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// File magic identifying a sealed machine key.
const SEAL_MAGIC: [u8; 4] = *b"FGMK";
/// Seal format version (bumped on any layout/AEAD change).
const SEAL_VERSION: u8 = 1;
/// HKDF `info` string — domain-separates this key derivation from any other use
/// of the same seal secret.
const SEAL_INFO: &[u8] = b"ferrogate-machine-key-seal-v1";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// `MAGIC ‖ VERSION ‖ salt ‖ nonce` — the fixed-size header before the ciphertext.
const SEAL_HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;

/// The additional authenticated data binding the header version to the ciphertext.
fn seal_aad() -> [u8; 5] {
    [SEAL_MAGIC[0], SEAL_MAGIC[1], SEAL_MAGIC[2], SEAL_MAGIC[3], SEAL_VERSION]
}

/// Derive the AEAD key from `seal_secret` and the per-file `salt`.
fn derive_seal_key(seal_secret: &[u8], salt: &[u8]) -> Result<[u8; 32], SepError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), seal_secret);
    let mut key = [0u8; 32];
    hk.expand(SEAL_INFO, &mut key)
        .map_err(|e| SepError::KeyGen(format!("HKDF expand: {e}")))?;
    Ok(key)
}

/// Seal a raw 32-byte scalar under `seal_secret`, producing the on-disk blob
/// `MAGIC ‖ VERSION ‖ salt ‖ nonce ‖ ciphertext ‖ tag`.
fn seal_scalar(scalar: &[u8; 32], seal_secret: &[u8]) -> Result<Vec<u8>, SepError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| SepError::KeyGen(format!("getrandom salt: {e}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| SepError::KeyGen(format!("getrandom nonce: {e}")))?;

    let mut key_bytes = derive_seal_key(seal_secret, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let aad = seal_aad();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: scalar,
                aad: &aad,
            },
        )
        .map_err(|_| SepError::KeyGen("AEAD seal failed".to_string()));
    key_bytes.zeroize();
    let ciphertext = ciphertext?;

    let mut out = Vec::with_capacity(SEAL_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&SEAL_MAGIC);
    out.push(SEAL_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reverse [`seal_scalar`]. Returns [`SepError::Malformed`] if `blob` is not a
/// sealed key or does not decrypt under `seal_secret` (wrong host or corruption).
fn unseal_scalar(blob: &[u8], seal_secret: &[u8]) -> Result<[u8; 32], SepError> {
    if blob.len() <= SEAL_HEADER_LEN || blob[0..4] != SEAL_MAGIC {
        return Err(SepError::Malformed(
            "not a sealed machine key (bad magic or truncated)".to_string(),
        ));
    }
    let version = blob[4];
    if version != SEAL_VERSION {
        return Err(SepError::Malformed(format!(
            "unsupported sealed-key version {version}"
        )));
    }
    let salt = &blob[5..5 + SALT_LEN];
    let nonce = &blob[5 + SALT_LEN..SEAL_HEADER_LEN];
    let ciphertext = &blob[SEAL_HEADER_LEN..];

    let mut key_bytes = derive_seal_key(seal_secret, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let aad = seal_aad();
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            SepError::Malformed(
                "sealed machine key did not decrypt (wrong host or corrupt file)".to_string(),
            )
        });
    key_bytes.zeroize();
    let mut plaintext = plaintext?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(SepError::Malformed(format!(
            "sealed payload is {len} bytes, expected 32"
        )));
    }
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(scalar)
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

    /// A unique scratch path per test (no external temp-file crate).
    fn seal_scratch(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ferro-sep-seal-{}-{tag}", std::process::id()))
    }

    #[test]
    fn sealed_roundtrip_same_secret() {
        let path = seal_scratch("roundtrip");
        let _ = std::fs::remove_file(&path);
        let secret = b"machine-fingerprint-H-bytes";

        let created = SoftwareMachineKey::open_or_create_sealed(&path, secret).unwrap();
        let reopened = SoftwareMachineKey::open_or_create_sealed(&path, secret).unwrap();
        assert_eq!(
            created.public_spki_der(),
            reopened.public_spki_der(),
            "reopening with the same seal secret recovers the same key"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sealed_wrong_secret_is_rejected() {
        // Clone resistance: a key file moved to a host with a different
        // fingerprint (different seal secret) must not decrypt.
        let path = seal_scratch("clone");
        let _ = std::fs::remove_file(&path);

        SoftwareMachineKey::open_or_create_sealed(&path, b"host-A-fingerprint").unwrap();
        let result = SoftwareMachineKey::open_or_create_sealed(&path, b"host-B-fingerprint");
        assert!(
            matches!(result, Err(SepError::Malformed(_))),
            "a different seal secret must fail to decrypt"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sealed_file_is_not_plaintext_scalar() {
        let path = seal_scratch("format");
        let _ = std::fs::remove_file(&path);
        let key = SoftwareMachineKey::open_or_create_sealed(&path, b"secret").unwrap();

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(&on_disk[0..4], &SEAL_MAGIC, "sealed file starts with magic");
        assert!(on_disk.len() > 32, "sealed blob is larger than a raw scalar");
        assert_ne!(
            &on_disk[SEAL_HEADER_LEN..],
            &key.to_bytes()[..],
            "ciphertext is not the raw scalar"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn legacy_plaintext_key_is_migrated_in_place() {
        // A pre-F16 file is the raw 32-byte scalar. Opening it sealed must load
        // the SAME key (identity preserved) and rewrite the file as sealed.
        let path = seal_scratch("legacy");
        let _ = std::fs::remove_file(&path);
        let legacy = SoftwareMachineKey::generate().unwrap();
        std::fs::write(&path, legacy.to_bytes()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap().len(), 32);

        let secret = b"fingerprint";
        let opened = SoftwareMachineKey::open_or_create_sealed(&path, secret).unwrap();
        assert_eq!(
            legacy.public_spki_der(),
            opened.public_spki_der(),
            "migration preserves the existing key"
        );
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(&on_disk[0..4], &SEAL_MAGIC, "file is now sealed");

        // And it reopens under the same secret afterward.
        let reopened = SoftwareMachineKey::open_or_create_sealed(&path, secret).unwrap();
        assert_eq!(legacy.public_spki_der(), reopened.public_spki_der());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn seal_unseal_direct_roundtrip() {
        let scalar = SoftwareMachineKey::generate().unwrap().to_bytes();
        let blob = seal_scalar(&scalar, b"secret").unwrap();
        let recovered = unseal_scalar(&blob, b"secret").unwrap();
        assert_eq!(scalar, recovered);
        assert!(unseal_scalar(&blob, b"other").is_err());
        // Tampering with the ciphertext is caught by the AEAD tag.
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(unseal_scalar(&tampered, b"secret").is_err());
    }
}
