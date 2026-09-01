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

use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use zeroize::Zeroizing;

use crate::{spki_from_sec1, MachineKey, SepError};

/// ECDSA-P256 message signing with an internal SHA-256 hash — the algorithm the
/// portable verifier ([`crate::verify_p256`]) expects.
const SIGN_ALG: Algorithm = Algorithm::ECDSASignatureMessageX962SHA256;

/// ECIES with cofactor ECDH, X9.63 SHA-256 KDF, and AES-GCM — the algorithm the
/// Enclave offers for encrypting *to* a P-256 key it holds. Encryption uses only
/// the public half (so anyone can seal); decryption is a private-key operation
/// that happens inside the Enclave and nowhere else.
const WRAP_ALG: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

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
        let data = pubkey.external_representation().ok_or_else(|| {
            SepError::Enclave("public key has no external representation".to_string())
        })?;
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

// ---------------------------------------------------------------------------
// Secure Enclave as a sealing root (the macOS answer to TPM sealing)
// ---------------------------------------------------------------------------

/// A Secure Enclave key used to **wrap small secrets** — the macOS equivalent of
/// sealing a data-protection key to a TPM.
///
/// The TPM path seals a key to a PCR policy and the chip refuses to release it
/// elsewhere. Here the same guarantee comes from a different direction: a P-256
/// key is generated *inside* the Enclave and cannot be exported by anyone,
/// including root. Wrapping encrypts to its public half (ECIES); unwrapping is a
/// private-key operation the Enclave performs internally. A blob wrapped on this
/// Mac is undecryptable on any other, and undecryptable on this one if the key
/// is gone.
///
/// ## Persistence needs a signed binary
///
/// [`Self::open_or_create`] stores the key in the data-protection keychain so a
/// later process can find it again. macOS refuses that to a binary without a
/// keychain-access-group entitlement — `errSecMissingEntitlement` (-34018) —
/// which in practice means a production `mia` must be codesigned by a real
/// Apple Developer team. Ad-hoc signing does not work: the entitlement is
/// restricted, so AMFI kills the process at launch. A build that cannot
/// persist should fall back to the fingerprint-derived tier rather than pretend.
///
/// [`Self::ephemeral`] skips the keychain entirely. The Enclave still generates
/// and holds the key, so the *cryptography* is exercised for real — but the key
/// dies with the process, so it is for tests, not for storage that must outlive
/// a restart.
pub struct SecureEnclaveSealKey {
    key: SecKey,
}

impl SecureEnclaveSealKey {
    /// Recover the persistent Enclave wrapping key labelled `label`, generating
    /// it on first use.
    ///
    /// # Errors
    /// Returns [`SepError::Enclave`] when the Enclave or the keychain refuses —
    /// most often `-34018` on a binary without the keychain entitlement.
    pub fn open_or_create(label: &str) -> Result<Self, SepError> {
        if let Some(key) = Self::find(label)? {
            return Ok(Self { key });
        }
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec());
        opts.set_size_in_bits(256);
        opts.set_token(Token::SecureEnclave);
        opts.set_label(label);
        // Secure-Enclave keys live in the data-protection keychain; this is what
        // makes the key outlive the process at all.
        opts.set_location(Location::DataProtectionKeychain);
        let key = SecKey::new(&opts).map_err(|e| {
            SepError::Enclave(format!(
                "persist a Secure Enclave key in the keychain: {e} \
                 (a binary without a keychain-access-group entitlement gets -34018)"
            ))
        })?;
        Ok(Self { key })
    }

    /// Generate a **process-local** Enclave key: real hardware, no keychain, and
    /// therefore no way to recover it after this process exits.
    ///
    /// # Errors
    /// Returns [`SepError::Enclave`] if the Enclave refuses generation.
    pub fn ephemeral(label: &str) -> Result<Self, SepError> {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec());
        opts.set_size_in_bits(256);
        opts.set_token(Token::SecureEnclave);
        opts.set_label(label);
        let key = SecKey::new(&opts)
            .map_err(|e| SepError::Enclave(format!("generate in Secure Enclave: {e}")))?;
        Ok(Self { key })
    }

    /// Look up a persistent Enclave key by label.
    fn find(label: &str) -> Result<Option<SecKey>, SepError> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(label)
            .ignore_legacy_keychains()
            .load_refs(true)
            .limit(1);
        let results = match search.search() {
            Ok(r) => r,
            // "not found" is the ordinary first-boot case, not a failure.
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
            Err(e) => return Err(SepError::Enclave(format!("keychain search: {e}"))),
        };
        for result in results {
            if let SearchResult::Ref(Reference::Key(key)) = result {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    /// Wrap `secret` so that only this Enclave can recover it.
    ///
    /// # Errors
    /// Returns [`SepError::Enclave`] if the Enclave has no usable public half or
    /// the encryption fails.
    pub fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>, SepError> {
        let public = self
            .key
            .public_key()
            .ok_or_else(|| SepError::Enclave("Enclave key has no public half".to_string()))?;
        public
            .encrypt_data(WRAP_ALG, secret)
            .map_err(|e| SepError::Enclave(format!("ECIES wrap: {e}")))
    }

    /// Unwrap a blob produced by [`Self::wrap`] on this machine.
    ///
    /// # Errors
    /// Returns [`SepError::Enclave`] if the Enclave refuses — which is what a
    /// blob from another Mac, or a corrupt one, looks like. The recovered secret
    /// zeroes itself on drop.
    pub fn unwrap_secret(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, SepError> {
        self.key
            .decrypt_data(WRAP_ALG, blob)
            .map(Zeroizing::new)
            .map_err(|e| SepError::Enclave(format!("ECIES unwrap: {e}")))
    }

    /// Remove the persistent key from the keychain. Used by tests to clean up.
    ///
    /// # Errors
    /// Returns [`SepError::Enclave`] if the keychain refuses the deletion.
    pub fn delete(self) -> Result<(), SepError> {
        self.key
            .delete()
            .map_err(|e| SepError::Enclave(format!("delete Enclave key: {e}")))
    }
}

/// `errSecItemNotFound` — an empty keychain search, not an error condition.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

#[cfg(test)]
mod seal_tests {
    use super::*;

    /// Live Secure Enclave wrap/unwrap on real hardware.
    ///
    /// Runs unsigned: generating a *process-local* Enclave key needs no
    /// entitlement, so the cryptography — ECIES to the Enclave's public half,
    /// decryption inside the Enclave — is exercised for real. Only persistence
    /// is gated behind codesigning, which
    /// [`persistent_seal_key_round_trips`] covers separately.
    #[test]
    fn live_enclave_wrap_then_unwrap() {
        let Ok(key) = SecureEnclaveSealKey::ephemeral("FerroGate test wrap key") else {
            eprintln!("no usable Secure Enclave here; skipping");
            return;
        };

        let secret = [0x5au8; 32];
        let blob = key
            .wrap(&secret)
            .expect("the Enclave wraps a 32-byte secret");
        assert_ne!(
            blob.as_slice(),
            &secret[..],
            "the blob must not be the plaintext"
        );
        assert!(
            !blob.windows(secret.len()).any(|w| w == secret),
            "the wrapped blob must not contain the secret"
        );

        let recovered = key.unwrap_secret(&blob).expect("the Enclave unwraps it");
        assert_eq!(recovered.as_slice(), &secret[..]);
    }

    /// A blob wrapped to one Enclave key does not open under another — the
    /// property that makes a stolen store useless. Two keys in the same Enclave
    /// stand in for two machines: neither can decrypt for the other, and neither
    /// private half ever leaves the hardware.
    #[test]
    fn a_blob_does_not_open_under_a_different_enclave_key() {
        let (Ok(a), Ok(b)) = (
            SecureEnclaveSealKey::ephemeral("FerroGate test key A"),
            SecureEnclaveSealKey::ephemeral("FerroGate test key B"),
        ) else {
            eprintln!("no usable Secure Enclave here; skipping");
            return;
        };

        let blob = a.wrap(b"data-protection-key").expect("wrap under A");
        assert!(
            b.unwrap_secret(&blob).is_err(),
            "a blob wrapped to one Enclave key must not open under another"
        );
        assert!(
            a.unwrap_secret(&blob).is_ok(),
            "but it must open under its own"
        );
    }

    /// A corrupt blob is refused rather than silently returning garbage.
    #[test]
    fn a_tampered_blob_is_refused() {
        let Ok(key) = SecureEnclaveSealKey::ephemeral("FerroGate test tamper key") else {
            eprintln!("no usable Secure Enclave here; skipping");
            return;
        };
        let mut blob = key.wrap(b"data-protection-key").expect("wrap");
        let n = blob.len();
        blob[n - 1] ^= 0x01;
        assert!(key.unwrap_secret(&blob).is_err());
    }

    /// The persistent path: an Enclave key that outlives the process.
    ///
    /// Ignored by default because macOS refuses to put a Secure Enclave key in
    /// the keychain unless the binary is codesigned with a keychain-access-group
    /// entitlement — an unsigned `cargo test` gets `-34018`, and ad-hoc signing
    /// does not help (the entitlement is restricted, so AMFI kills the process).
    /// Run it from a properly signed build:
    /// `cargo test -p ferro-sep --features secure-enclave -- --ignored`.
    #[test]
    #[ignore = "keychain persistence needs a codesigned binary with a keychain entitlement"]
    fn persistent_seal_key_round_trips() {
        const LABEL: &str = "FerroGate test persistent wrap key";
        let key = SecureEnclaveSealKey::open_or_create(LABEL)
            .expect("persist an Enclave key (needs a signed binary)");
        let blob = key.wrap(b"data-protection-key").expect("wrap");

        // A second open must find the *same* key, as a later process would.
        let reopened = SecureEnclaveSealKey::open_or_create(LABEL).expect("reopen");
        let recovered = reopened.unwrap_secret(&blob).expect("unwrap after reopen");
        assert_eq!(recovered.as_slice(), b"data-protection-key");

        reopened.delete().expect("clean up the test key");
    }
}
