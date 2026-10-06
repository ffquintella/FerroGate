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
use p256::Sec1Point;

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
    let point = Sec1Point::from_bytes(point_bytes)
        .map_err(|e| SepError::Malformed(format!("EC point: {e}")))?;
    VerifyingKey::from_sec1_point(&point)
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
/// CI). The key is stored as its raw 32-byte scalar, or sealed, in a file the
/// constructors keep owner-only (`0600`) on Unix.
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
            getrandom::fill(&mut bytes).map_err(|e| SepError::KeyGen(format!("getrandom: {e}")))?;
            if let Ok(signing) = SigningKey::from_bytes((&bytes).into()) {
                return Ok(Self { signing });
            }
        }
        Err(SepError::KeyGen(
            "no valid scalar after 16 draws".to_string(),
        ))
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
    /// The file holds the raw 32-byte scalar. On Unix a new file is created
    /// exclusively with mode [`KEY_FILE_MODE`] (`0600`), and an existing file
    /// that group or other can access is tightened to `0600` before it is read
    /// (see [`restrict_key_file`]). The caller still owns the directory's
    /// permissions.
    ///
    /// # Errors
    /// Returns [`SepError::Io`] on filesystem errors — including an existing
    /// file whose permissions cannot be tightened — and [`SepError::Malformed`]
    /// if an existing file is corrupt.
    pub fn open_or_create(path: &std::path::Path) -> Result<Self, SepError> {
        if let Some(bytes) = read_key_file(path)? {
            return Self::from_bytes(&bytes);
        }
        let key = Self::generate()?;
        let scalar = Zeroizing::new(key.to_bytes());
        match create_key_file(path, scalar.as_slice()) {
            Ok(()) => Ok(key),
            // Another opener won the race: use the key it persisted.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let bytes = read_key_file(path)?.ok_or_else(|| {
                    SepError::Io(format!("{} vanished while being created", path.display()))
                })?;
                Self::from_bytes(&bytes)
            }
            Err(e) => Err(SepError::Io(format!("create {}: {e}", path.display()))),
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
    /// The file still holds a secret, and the seal adds no confidentiality
    /// against a local user who can read the fingerprint inputs (on macOS
    /// `ioreg` hands them to any user). File permissions are therefore what keep
    /// other local users out: on Unix a new file is created exclusively with
    /// mode [`KEY_FILE_MODE`] (`0600`), an existing file that group or other can
    /// access is tightened to `0600` before it is read, and the pre-F16 re-seal
    /// only ever rewrites an owner-only file (see [`restrict_key_file`]).
    ///
    /// # Errors
    /// Returns [`SepError::Io`] on filesystem errors — including an existing
    /// file whose permissions cannot be tightened — [`SepError::KeyGen`] on RNG
    /// or key-derivation failure, and [`SepError::Malformed`] if an existing file
    /// is not a sealed key or fails to decrypt (wrong host or corruption).
    pub fn open_or_create_sealed(
        path: &std::path::Path,
        seal_secret: &[u8],
    ) -> Result<Self, SepError> {
        if let Some(bytes) = read_key_file(path)? {
            return Self::load_sealed(path, &bytes, seal_secret, true);
        }
        if let Some(key) = Self::create_sealed(path, seal_secret)? {
            return Ok(key);
        }
        // Another opener won the race: use the key it persisted.
        let bytes = read_key_file(path)?.ok_or_else(|| {
            SepError::Io(format!("{} vanished while being created", path.display()))
        })?;
        Self::load_sealed(path, &bytes, seal_secret, true)
    }

    /// Generate a new key and persist it **sealed** to `seal_secret` at
    /// `path`, only if nothing is there: `Ok(None)` when a file already exists
    /// (it is never truncated, followed or replaced). The file is created
    /// exclusively with mode [`KEY_FILE_MODE`]; a write that fails part-way
    /// removes the partial file this call created.
    ///
    /// # Errors
    /// [`SepError::KeyGen`] on RNG or key-derivation failure, [`SepError::Io`]
    /// on any other filesystem error.
    pub fn create_sealed(
        path: &std::path::Path,
        seal_secret: &[u8],
    ) -> Result<Option<Self>, SepError> {
        let key = Self::generate()?;
        let scalar = Zeroizing::new(key.to_bytes());
        let blob = seal_scalar(&scalar, seal_secret)?;
        match create_key_file(path, &blob) {
            Ok(()) => Ok(Some(key)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(SepError::Io(format!("create {}: {e}", path.display()))),
        }
    }

    /// [`Self::create_sealed`] for a plain (unsealed) scalar file.
    ///
    /// # Errors
    /// As [`Self::create_sealed`].
    pub fn create_plain(path: &std::path::Path) -> Result<Option<Self>, SepError> {
        let key = Self::generate()?;
        let scalar = Zeroizing::new(key.to_bytes());
        match create_key_file(path, scalar.as_slice()) {
            Ok(()) => Ok(Some(key)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(SepError::Io(format!("create {}: {e}", path.display()))),
        }
    }

    /// Load an **existing** sealed key from `path`; never creates one.
    ///
    /// The counterpart of [`Self::open_or_create_sealed`] for a caller that
    /// has already established that a key file exists and must not be
    /// replaced: if the file has vanished in the meantime this fails instead of
    /// minting a new identity. The same permission repair applies, but the
    /// file is **never rewritten**: a pre-F16 plaintext scalar is loaded as it
    /// is (the in-place re-seal truncates first, so a crash part-way would
    /// destroy the only copy of the pinned key). Re-seal such a file with an
    /// atomic replace instead — see [`is_unsealed_scalar`].
    ///
    /// # Errors
    /// [`SepError::Io`] if the file is absent or cannot be read (or made
    /// owner-only), and [`SepError::Malformed`] if it is not a sealed key or
    /// fails to decrypt (wrong host or corruption).
    pub fn open_sealed(path: &std::path::Path, seal_secret: &[u8]) -> Result<Self, SepError> {
        let bytes = read_key_file(path)?
            .ok_or_else(|| SepError::Io(format!("{}: no machine key file", path.display())))?;
        Self::load_sealed(path, &bytes, seal_secret, false)
    }

    /// Load an **existing** plaintext key from `path`; never creates one.
    ///
    /// The open-only counterpart of [`Self::open_or_create`].
    ///
    /// # Errors
    /// [`SepError::Io`] if the file is absent or cannot be read (or made
    /// owner-only), and [`SepError::Malformed`] if it is not a raw scalar.
    pub fn open_existing(path: &std::path::Path) -> Result<Self, SepError> {
        let bytes = read_key_file(path)?
            .ok_or_else(|| SepError::Io(format!("{}: no machine key file", path.display())))?;
        Self::from_bytes(&bytes)
    }

    /// Decode the contents of an existing sealed key file read from `path`,
    /// migrating a pre-F16 plaintext scalar in place when `reseal_in_place`.
    fn load_sealed(
        path: &std::path::Path,
        bytes: &[u8],
        seal_secret: &[u8],
        reseal_in_place: bool,
    ) -> Result<Self, SepError> {
        // Seamless upgrade: a pre-F16 file is the raw 32-byte scalar with no
        // magic. Load it, then (if asked) re-seal in place so the *same* key
        // (and thus the pubkey CMIS has pinned) is preserved — regenerating
        // would change the identity and be rejected at enrollment.
        if is_unsealed_scalar(bytes) {
            let key = Self::from_bytes(bytes)?;
            if reseal_in_place {
                let scalar = Zeroizing::new(key.to_bytes());
                if let Ok(blob) = seal_scalar(&scalar, seal_secret) {
                    // Best-effort: if the re-seal write fails the daemon still
                    // runs this session; it just re-migrates next start.
                    let _ = rewrite_key_file(path, &blob);
                }
            }
            return Ok(key);
        }
        let mut scalar = unseal_scalar(bytes, seal_secret)?;
        let key = Self::from_bytes(&scalar);
        scalar.zeroize();
        key
    }

    fn verifying_key(&self) -> VerifyingKey {
        *self.signing.verifying_key()
    }
}

impl MachineKey for SoftwareMachineKey {
    fn public_spki_der(&self) -> Vec<u8> {
        let point = self.verifying_key().to_sec1_point(false);
        spki_from_sec1(point.as_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SepError> {
        let sig: Signature = self.signing.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// Whether `bytes` — the contents of a machine-key file — are a pre-F16
/// plaintext 32-byte scalar rather than a sealed envelope. Such a file still
/// opens ([`SoftwareMachineKey::open_sealed`] loads it as is); a caller that
/// can replace files atomically should re-seal it with [`seal_bytes`] (empty
/// purpose) and swap it in.
#[must_use]
pub fn is_unsealed_scalar(bytes: &[u8]) -> bool {
    bytes.len() == 32 && bytes[0..4] != SEAL_MAGIC
}

// ---- Key-file permissions -------------------------------------------------

/// Unix permission bits of a machine-key file: owner read/write only.
pub const KEY_FILE_MODE: u32 = 0o600;

/// The group and other permission bits; none may be set on a key file.
#[cfg(unix)]
const GROUP_OTHER: u32 = 0o077;

/// What [`restrict_key_file`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFilePermissions {
    /// There is no file at the path; nothing was changed.
    Absent,
    /// The file was already inaccessible to group and other; nothing changed.
    AlreadyPrivate,
    /// The file was accessible to group or other and is now [`KEY_FILE_MODE`].
    Tightened {
        /// The permission bits the file had before (e.g. `0o644`).
        previous_mode: u32,
    },
    /// Not a Unix platform: access is governed by the directory's ACL and the
    /// file was left as it is.
    Unmanaged,
}

/// Make the key file at `path` owner-only ([`KEY_FILE_MODE`]) if group or other
/// can access it.
///
/// Both `open_or_create*` constructors call this before reading, so every
/// caller gets the repair. It is public so a daemon can also run it early — for
/// instance before it drops root, or to log the repair, which this crate does
/// not do. The `chmod` follows a symlink, as the read that follows does.
///
/// # Errors
/// Returns [`SepError::Io`] if the file's metadata cannot be read or its mode
/// cannot be changed (e.g. the process neither owns the file nor is root).
pub fn restrict_key_file(path: &std::path::Path) -> Result<KeyFilePermissions, SepError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(KeyFilePermissions::Absent)
            }
            Err(e) => return Err(SepError::Io(format!("stat {}: {e}", path.display()))),
        };
        let previous_mode = meta.permissions().mode() & 0o7777;
        if previous_mode & GROUP_OTHER == 0 {
            return Ok(KeyFilePermissions::AlreadyPrivate);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_FILE_MODE)).map_err(
            |e| {
                SepError::Io(format!(
                    "restrict {} to {KEY_FILE_MODE:o} (was {previous_mode:o}): {e}",
                    path.display()
                ))
            },
        )?;
        Ok(KeyFilePermissions::Tightened { previous_mode })
    }
    #[cfg(not(unix))]
    {
        match std::fs::metadata(path) {
            Ok(_) => Ok(KeyFilePermissions::Unmanaged),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeyFilePermissions::Absent),
            Err(e) => Err(SepError::Io(format!("stat {}: {e}", path.display()))),
        }
    }
}

/// Read an existing key file after making it owner-only; `None` if absent.
///
/// The repair comes first so a file left group/world-readable by an older build
/// is closed before the process relies on it again.
fn read_key_file(path: &std::path::Path) -> Result<Option<Zeroizing<Vec<u8>>>, SepError> {
    if restrict_key_file(path)? == KeyFilePermissions::Absent {
        return Ok(None);
    }
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SepError::Io(format!("read {}: {e}", path.display()))),
    }
}

/// Create `path` exclusively and write `bytes` to it.
///
/// On Unix `open(2)` applies [`KEY_FILE_MODE`] at creation, so the file is
/// never wider than `0600` (the umask can only clear bits) and no follow-up
/// `chmod` is needed. Exclusive creation (`O_EXCL`) never truncates or follows
/// a file that appeared after the caller saw the path empty; the caller sees
/// `AlreadyExists` instead. A temp-file-and-rename was rejected: the Linux
/// daemon writes this file after its privilege drop, and the seccomp
/// allow-list (`ferro-harden`) has no `rename`.
fn create_key_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(KEY_FILE_MODE);
    }
    let mut f = opts.open(path)?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        // The exclusive open proves this call created the file: remove the
        // partial copy rather than leave a torn key a later start would trip on.
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// Overwrite the existing key file at `path` with `bytes`, making it owner-only
/// first so the new contents never land in a group/world-readable file.
///
/// Not atomic: a crash mid-write leaves a torn file (see [`create_key_file`] for
/// why there is no rename).
fn rewrite_key_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), SepError> {
    use std::io::Write as _;
    if restrict_key_file(path)? == KeyFilePermissions::Absent {
        return create_key_file(path, bytes)
            .map_err(|e| SepError::Io(format!("create {}: {e}", path.display())));
    }
    let io = |e: std::io::Error| SepError::Io(format!("rewrite {}: {e}", path.display()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)
}

// ---- Clone-resistant at-rest sealing (F16) ------------------------------

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

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

/// The purpose tag of the machine-key file. Empty, because that format predates
/// the parameter and its bytes must not change.
const MACHINE_KEY_PURPOSE: &[u8] = b"";

/// The additional authenticated data: the header, plus the purpose so a blob
/// sealed for one use cannot be replayed as another.
fn seal_aad(purpose: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5 + purpose.len());
    aad.extend_from_slice(&SEAL_MAGIC);
    aad.push(SEAL_VERSION);
    aad.extend_from_slice(purpose);
    aad
}

/// Derive the AEAD key from `seal_secret`, the per-file `salt`, and `purpose`.
fn derive_seal_key(seal_secret: &[u8], salt: &[u8], purpose: &[u8]) -> Result<[u8; 32], SepError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), seal_secret);
    let mut info = Vec::with_capacity(SEAL_INFO.len() + purpose.len());
    info.extend_from_slice(SEAL_INFO);
    info.extend_from_slice(purpose);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|e| SepError::KeyGen(format!("HKDF expand: {e}")))?;
    Ok(key)
}

/// Seal arbitrary bytes under `seal_secret`, producing the on-disk blob
/// `MAGIC ‖ VERSION ‖ salt ‖ nonce ‖ ciphertext ‖ tag`.
///
/// `purpose` domain-separates one kind of sealed file from another: it is mixed
/// into both the HKDF `info` and the AEAD associated data, so a blob sealed for
/// one purpose cannot be presented as another even under the same secret. Pass
/// an empty slice for the machine-key format that predates the parameter.
///
/// The confidentiality of the result is exactly the secrecy of `seal_secret`.
/// Callers derive it from something the host cannot carry elsewhere — the
/// hardware fingerprint, or a value a TPM will only release on this machine.
///
/// # Errors
/// Returns [`SepError::KeyGen`] if the RNG, the key derivation, or the AEAD
/// fails.
pub fn seal_bytes(
    plaintext: &[u8],
    seal_secret: &[u8],
    purpose: &[u8],
) -> Result<Vec<u8>, SepError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| SepError::KeyGen(format!("getrandom salt: {e}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| SepError::KeyGen(format!("getrandom nonce: {e}")))?;

    let mut key_bytes = derive_seal_key(seal_secret, &salt, purpose)?;
    let cipher = ChaCha20Poly1305::new((&key_bytes).into());
    let aad = seal_aad(purpose);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
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

/// Reverse [`seal_bytes`]. The plaintext zeroes itself on drop.
///
/// # Errors
/// Returns [`SepError::Malformed`] if `blob` is not a sealed file of this
/// format and purpose, or does not decrypt under `seal_secret` — the same
/// answer for a wrong host, a wrong purpose, and a corrupt file, because a
/// caller should treat all three identically: discard and re-provision.
pub fn unseal_bytes(
    blob: &[u8],
    seal_secret: &[u8],
    purpose: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SepError> {
    if blob.len() <= SEAL_HEADER_LEN || blob[0..4] != SEAL_MAGIC {
        return Err(SepError::Malformed(
            "not a sealed file (bad magic or truncated)".to_string(),
        ));
    }
    let version = blob[4];
    if version != SEAL_VERSION {
        return Err(SepError::Malformed(format!(
            "unsupported seal version {version}"
        )));
    }
    let salt = &blob[5..5 + SALT_LEN];
    let nonce = &blob[5 + SALT_LEN..SEAL_HEADER_LEN];
    let ciphertext = &blob[SEAL_HEADER_LEN..];

    let mut key_bytes = derive_seal_key(seal_secret, salt, purpose)?;
    let cipher = ChaCha20Poly1305::new((&key_bytes).into());
    let aad = seal_aad(purpose);
    let plaintext = cipher
        .decrypt(
            <&Nonce>::try_from(nonce)
                .map_err(|_| SepError::Malformed("seal nonce length".into()))?,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            SepError::Malformed(
                "sealed file did not decrypt (wrong host or corrupt file)".to_string(),
            )
        });
    key_bytes.zeroize();
    Ok(Zeroizing::new(plaintext?))
}

/// Seal a raw 32-byte scalar under `seal_secret`.
///
/// The empty purpose keeps the encoding byte-identical to the pre-`seal_bytes`
/// format, so machine-key files written by an earlier build still open.
fn seal_scalar(scalar: &[u8; 32], seal_secret: &[u8]) -> Result<Vec<u8>, SepError> {
    seal_bytes(scalar, seal_secret, MACHINE_KEY_PURPOSE)
}

/// Reverse [`seal_scalar`]. Returns [`SepError::Malformed`] if `blob` is not a
/// sealed key or does not decrypt under `seal_secret` (wrong host or corruption).
fn unseal_scalar(blob: &[u8], seal_secret: &[u8]) -> Result<[u8; 32], SepError> {
    let plaintext = unseal_bytes(blob, seal_secret, MACHINE_KEY_PURPOSE).map_err(|e| match e {
        // Keep the machine-key wording operators and runbooks already know.
        SepError::Malformed(_) => SepError::Malformed(
            "sealed machine key did not decrypt (wrong host or corrupt file)".to_string(),
        ),
        other => other,
    })?;
    if plaintext.len() != 32 {
        return Err(SepError::Malformed(format!(
            "sealed payload is {} bytes, expected 32",
            plaintext.len()
        )));
    }
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&plaintext);
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
    fn machine_key_file_is_a_purpose_empty_envelope() {
        // The generic envelope did not change the machine-key format: a file
        // written by `open_or_create_sealed` opens as a plain purpose-empty
        // sealed blob, which is what an older build wrote.
        let path = seal_scratch("compat");
        let _ = std::fs::remove_file(&path);
        let secret = b"machine-fingerprint-H-bytes";

        let key = SoftwareMachineKey::open_or_create_sealed(&path, secret).unwrap();
        let blob = std::fs::read(&path).unwrap();
        let plaintext = unseal_bytes(&blob, secret, b"").unwrap();
        assert_eq!(plaintext.as_slice(), key.to_bytes().as_slice());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_purpose_binds_the_blob_to_one_use() {
        // Same secret, different purpose: the AEAD must refuse. Without this a
        // sealed certificate store could be swapped in for a sealed key file.
        let secret = b"same-host-secret";
        let blob = seal_bytes(b"credential store contents", secret, b"x509-store").unwrap();

        assert!(unseal_bytes(&blob, secret, b"x509-store").is_ok());
        assert!(matches!(
            unseal_bytes(&blob, secret, b"other-purpose"),
            Err(SepError::Malformed(_))
        ));
        assert!(matches!(
            unseal_bytes(&blob, secret, b""),
            Err(SepError::Malformed(_))
        ));
    }

    #[test]
    fn sealed_bytes_roundtrip_at_arbitrary_length() {
        let secret = b"host-secret";
        for len in [0usize, 1, 32, 5000] {
            let msg = vec![0xa5; len];
            let blob = seal_bytes(&msg, secret, b"p").unwrap();
            assert_eq!(
                unseal_bytes(&blob, secret, b"p").unwrap().as_slice(),
                &msg[..]
            );
            assert!(unseal_bytes(&blob, b"other-host", b"p").is_err());
        }
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
    fn open_only_constructors_never_create_a_key() {
        // A caller that knows a key must already exist uses the open-only
        // constructors; an absent file is an error, never a fresh identity.
        let path = seal_scratch("open-only");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            SoftwareMachineKey::open_sealed(&path, b"fingerprint"),
            Err(SepError::Io(_))
        ));
        assert!(matches!(
            SoftwareMachineKey::open_existing(&path),
            Err(SepError::Io(_))
        ));
        assert!(!path.exists(), "an open-only call must not create the file");

        let created = SoftwareMachineKey::open_or_create_sealed(&path, b"fingerprint").unwrap();
        let reopened = SoftwareMachineKey::open_sealed(&path, b"fingerprint").unwrap();
        assert_eq!(created.public_spki_der(), reopened.public_spki_der());
        // A create-only call never touches an existing file.
        let before = std::fs::read(&path).unwrap();
        assert!(SoftwareMachineKey::create_sealed(&path, b"fingerprint")
            .unwrap()
            .is_none());
        assert!(SoftwareMachineKey::create_plain(&path).unwrap().is_none());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_sealed_loads_a_pre_f16_key_without_rewriting_it() {
        // The in-place re-seal truncates first; the strict opener must not
        // risk the only copy of a pinned key, so it loads it as it is.
        let path = seal_scratch("legacy-open-only");
        let _ = std::fs::remove_file(&path);
        let legacy = SoftwareMachineKey::generate().unwrap();
        create_key_file(&path, &legacy.to_bytes()).unwrap();
        assert!(is_unsealed_scalar(&std::fs::read(&path).unwrap()));
        let opened = SoftwareMachineKey::open_sealed(&path, b"fingerprint").unwrap();
        assert_eq!(legacy.public_spki_der(), opened.public_spki_der());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            legacy.to_bytes(),
            "untouched"
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
        assert!(
            on_disk.len() > 32,
            "sealed blob is larger than a raw scalar"
        );
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

    /// The permission bits of `path` (Unix).
    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn created_key_file_is_owner_only() {
        // `open(2)` applies the mode at creation and the umask can only clear
        // bits, so "no group/other bits" holds under any umask — and fails
        // under the common 022 umask if the file is written with the default
        // 0666 creation mode.
        for (tag, sealed) in [("create-sealed", true), ("create-plain", false)] {
            let path = seal_scratch(tag);
            let _ = std::fs::remove_file(&path);
            if sealed {
                SoftwareMachineKey::open_or_create_sealed(&path, b"fingerprint").unwrap();
            } else {
                SoftwareMachineKey::open_or_create(&path).unwrap();
            }
            let mode = mode_of(&path);
            assert_eq!(
                mode & 0o077,
                0,
                "{tag}: key file is {mode:o}, must be owner-only"
            );
            assert_eq!(mode & 0o600, 0o600, "{tag}: owner must keep read/write");
            let _ = std::fs::remove_file(&path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn legacy_reseal_leaves_file_owner_only() {
        // The pre-F16 migration rewrites the file in place; the sealed blob must
        // never land in a group/world-readable file, even when the legacy file
        // was (as `std::fs::write` left it) 0644.
        use std::os::unix::fs::PermissionsExt as _;
        let path = seal_scratch("legacy-mode");
        let _ = std::fs::remove_file(&path);
        let legacy = SoftwareMachineKey::generate().unwrap();
        std::fs::write(&path, legacy.to_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let opened = SoftwareMachineKey::open_or_create_sealed(&path, b"fingerprint").unwrap();
        assert_eq!(legacy.public_spki_der(), opened.public_spki_der());
        assert_eq!(&std::fs::read(&path).unwrap()[0..4], &SEAL_MAGIC);
        assert_eq!(mode_of(&path), 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_key_file_is_tightened() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = seal_scratch("tighten");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            restrict_key_file(&path).unwrap(),
            KeyFilePermissions::Absent
        );

        let key = SoftwareMachineKey::open_or_create_sealed(&path, b"fingerprint").unwrap();
        assert_eq!(
            restrict_key_file(&path).unwrap(),
            KeyFilePermissions::AlreadyPrivate
        );

        // A file an older build left 0644: the helper reports and fixes it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            restrict_key_file(&path).unwrap(),
            KeyFilePermissions::Tightened {
                previous_mode: 0o644
            }
        );
        assert_eq!(mode_of(&path), KEY_FILE_MODE);

        // And opening such a file repairs it too, without changing the key.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let reopened = SoftwareMachineKey::open_or_create_sealed(&path, b"fingerprint").unwrap();
        assert_eq!(key.public_spki_der(), reopened.public_spki_der());
        assert_eq!(mode_of(&path), KEY_FILE_MODE);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn create_never_clobbers_an_existing_file() {
        // Exclusive creation: a file that appeared after the caller saw the
        // path empty is reported, never truncated or overwritten.
        let path = seal_scratch("excl");
        let _ = std::fs::remove_file(&path);
        create_key_file(&path, b"first").unwrap();
        let err = create_key_file(&path, b"second").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
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
