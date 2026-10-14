//! Admin key material (F20 §3–§6, §10).
//!
//! - **Secrets key** (`CMIS_ADMIN_SECRETS_KEY_FILE`, 32 bytes): seals TOTP
//!   secrets at rest with XChaCha20-Poly1305 (AAD = `admin_id || "totp-v1"`)
//!   and, through domain-separated HMAC derivation, keys the server MACs that
//!   bind login nonces, step-up nonces, device tokens and enrollment TOTP
//!   secrets. Every node of a cluster must hold the same file; a key-check
//!   value in `cmis_settings` refuses a node whose key differs.
//! - **Audit pseudonymisation key** (`CMIS_AUDIT_PSEUDONYM_KEY_FILE`, 32
//!   bytes): keys the HMACs that stand in for source IPs and attempted
//!   usernames in audit events, so the Merkle log carries no personal data.
//! - **Pepper** (`CMIS_ADMIN_PEPPER_FILE`, 32 bytes, optional): see
//!   [`crate::admin::password`].
//!
//! Key files must be regular files that are not readable by group or others.
//! When the variable is unset and the default file is missing, the key is
//! generated (`0400`, `O_EXCL`) with a warning; an explicitly configured file
//! must exist. Decrypted secrets live only in [`Zeroizing`] buffers, in server
//! memory, for the duration of one verification (NRM §5.3.2).

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{KeyInit, Mac};
use zeroize::Zeroizing;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Default secrets-key path.
pub const DEFAULT_SECRETS_KEY_FILE: &str = "/var/lib/ferrogate/admin/secrets.key";
/// Default audit pseudonymisation key path.
pub const DEFAULT_PSEUDONYM_KEY_FILE: &str = "/var/lib/ferrogate/admin/audit-pseudonym.key";

const SEAL_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;

/// Key-file and sealing failures.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Reading or creating a key file failed.
    #[error("key file {path}: {reason}")]
    File {
        /// The file.
        path: PathBuf,
        /// What went wrong (no key bytes).
        reason: String,
    },
    /// A sealed blob is malformed or does not open under this key.
    #[error("sealed secret does not open (wrong key or corrupt row)")]
    Unseal,
    /// Sealing failed.
    #[error("sealing failed")]
    Seal,
}

/// Where the key files live, and whether a missing one may be generated.
#[derive(Debug, Clone)]
pub struct KeyFile {
    /// File path.
    pub path: PathBuf,
    /// Generate the key if the file is absent (only for unset variables that
    /// fell back to the default path).
    pub generate_if_missing: bool,
}

/// The loaded admin keys.
pub struct AdminKeys {
    totp_key: Zeroizing<[u8; 32]>,
    server_key: Zeroizing<[u8; 32]>,
    pseudonym_key: Zeroizing<[u8; 32]>,
    key_check: String,
}

impl std::fmt::Debug for AdminKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminKeys")
            .field("key_check", &self.key_check)
            .finish_non_exhaustive()
    }
}

fn derive(root: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(root).expect("HMAC accepts any key length");
    mac.update(label);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

impl AdminKeys {
    /// Build from raw key material (tests, and [`Self::load`]).
    #[must_use]
    pub fn from_material(secrets: &[u8; 32], pseudonym: &[u8; 32]) -> Self {
        let check_s = derive(secrets, b"ferrogate-admin-key-check-v1");
        let check_p = derive(pseudonym, b"ferrogate-admin-key-check-v1");
        Self {
            totp_key: derive(secrets, b"ferrogate-admin-totp-aead-v1"),
            server_key: derive(secrets, b"ferrogate-admin-server-mac-v1"),
            pseudonym_key: Zeroizing::new(*pseudonym),
            key_check: format!(
                "{}:{}",
                hex::encode(&check_s[..8]),
                hex::encode(&check_p[..8])
            ),
        }
    }

    /// Load (or, where allowed, generate) the secrets and pseudonym key files.
    pub fn load(secrets: &KeyFile, pseudonym: &KeyFile) -> Result<Self, KeyError> {
        let s = read_or_create_key(secrets)?;
        let p = read_or_create_key(pseudonym)?;
        Ok(Self::from_material(&s, &p))
    }

    /// A non-secret fingerprint of both keys, stored once in `cmis_settings`
    /// so a node configured with a different key refuses to serve admin
    /// authentication instead of failing every TOTP check.
    #[must_use]
    pub fn key_check(&self) -> &str {
        &self.key_check
    }

    /// Seal a TOTP secret for `admin_id`.
    pub fn seal_totp(&self, admin_id: &str, secret: &[u8]) -> Result<Vec<u8>, KeyError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| KeyError::Seal)?;
        let key: &[u8; 32] = &self.totp_key;
        let cipher = XChaCha20Poly1305::new(key.into());
        let aad = totp_aad(admin_id);
        let ct = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyError::Seal)?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(SEAL_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a sealed TOTP secret of `admin_id`. The plaintext zeroes itself on
    /// drop.
    pub fn open_totp(&self, admin_id: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if blob.len() <= 1 + NONCE_LEN || blob[0] != SEAL_VERSION {
            return Err(KeyError::Unseal);
        }
        let key: &[u8; 32] = &self.totp_key;
        let cipher = XChaCha20Poly1305::new(key.into());
        let aad = totp_aad(admin_id);
        cipher
            .decrypt(
                <&XNonce>::try_from(&blob[1..=NONCE_LEN]).map_err(|_| KeyError::Unseal)?,
                Payload {
                    msg: &blob[1 + NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| KeyError::Unseal)
    }

    /// Server MAC over length-prefixed `parts` under a domain `label`.
    ///
    /// # Panics
    ///
    /// Never: HMAC accepts keys of any length.
    #[must_use]
    pub fn mac(&self, label: &str, parts: &[&[u8]]) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(self.server_key.as_ref()).expect("HMAC accepts any key");
        mac.update(label.as_bytes());
        for part in parts {
            mac.update(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    /// Keyed pseudonym (32 hex chars) of a personal value for audit events.
    #[must_use]
    pub fn pseudonym(&self, label: &str, value: &[u8]) -> String {
        hex::encode(&self.pseudonym_raw(label, value)[..16])
    }

    /// Keyed pseudonym bytes (`admin_security_log.username_attempted_hmac`).
    ///
    /// # Panics
    ///
    /// Never: HMAC accepts keys of any length.
    #[must_use]
    pub fn pseudonym_raw(&self, label: &str, value: &[u8]) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(self.pseudonym_key.as_ref()).expect("HMAC accepts any key");
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(value);
        mac.finalize().into_bytes().into()
    }
}

fn totp_aad(admin_id: &str) -> Vec<u8> {
    let mut aad = admin_id.as_bytes().to_vec();
    aad.extend_from_slice(b"totp-v1");
    aad
}

fn file_err(path: &Path, reason: impl Into<String>) -> KeyError {
    KeyError::File {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// Read a 32-byte key file, refusing group/world-readable files; generate it
/// when allowed and absent.
pub fn read_or_create_key(file: &KeyFile) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let path = file.path.as_path();
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_file() {
                return Err(file_err(path, "not a regular file"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(file_err(
                        path,
                        format!("mode {mode:o} is readable by group or others; use 0400 or 0600"),
                    ));
                }
            }
            let bytes =
                Zeroizing::new(std::fs::read(path).map_err(|e| file_err(path, e.to_string()))?);
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| file_err(path, format!("{} bytes, expected 32", bytes.len())))?;
            Ok(Zeroizing::new(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && file.generate_if_missing => {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(key.as_mut()).map_err(|e| file_err(path, e.to_string()))?;
            write_new_secret_file(path, key.as_ref()).map_err(|e| file_err(path, e.to_string()))?;
            tracing::warn!(
                path = %path.display(),
                "admin key file generated; every node of a multi-node cluster must use the same file"
            );
            Ok(key)
        }
        Err(e) => Err(file_err(path, e.to_string())),
    }
}

/// Create `path` exclusively (`O_EXCL`, never following an existing file or
/// symlink) with mode `0400` and write `bytes` to it.
pub fn write_new_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o400);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> AdminKeys {
        AdminKeys::from_material(&[1; 32], &[2; 32])
    }

    #[test]
    fn a_sealed_totp_secret_opens_only_for_its_account() {
        let k = keys();
        let blob = k.seal_totp("acct-a", b"0123456789abcdefghij").unwrap();
        assert_ne!(&blob[1 + NONCE_LEN..], b"0123456789abcdefghij");
        assert_eq!(
            k.open_totp("acct-a", &blob).unwrap().as_slice(),
            b"0123456789abcdefghij"
        );
        assert!(
            k.open_totp("acct-b", &blob).is_err(),
            "AAD binds the account"
        );
        let other = AdminKeys::from_material(&[9; 32], &[2; 32]);
        assert!(
            other.open_totp("acct-a", &blob).is_err(),
            "another key fails"
        );
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(k.open_totp("acct-a", &tampered).is_err());
    }

    #[test]
    fn macs_are_domain_separated_and_length_prefixed() {
        let k = keys();
        assert_ne!(k.mac("a", &[b"x"]), k.mac("b", &[b"x"]));
        assert_ne!(k.mac("a", &[b"ab", b"c"]), k.mac("a", &[b"a", b"bc"]));
        assert_eq!(k.mac("a", &[b"x"]), keys().mac("a", &[b"x"]));
    }

    #[test]
    fn pseudonyms_depend_on_the_pseudonym_key_only() {
        let a = AdminKeys::from_material(&[1; 32], &[2; 32]);
        let b = AdminKeys::from_material(&[3; 32], &[2; 32]);
        let c = AdminKeys::from_material(&[1; 32], &[4; 32]);
        assert_eq!(
            a.pseudonym("ip", b"10.0.0.1"),
            b.pseudonym("ip", b"10.0.0.1")
        );
        assert_ne!(
            a.pseudonym("ip", b"10.0.0.1"),
            c.pseudonym("ip", b"10.0.0.1")
        );
        assert_eq!(a.pseudonym("ip", b"10.0.0.1").len(), 32);
        assert!(!a.pseudonym("ip", b"10.0.0.1").contains("10.0.0.1"));
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_generated_0400_and_loose_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("ferrogate-admin-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("k/secrets.key");

        let missing = KeyFile {
            path: path.clone(),
            generate_if_missing: false,
        };
        assert!(
            read_or_create_key(&missing).is_err(),
            "explicit file must exist"
        );

        let auto = KeyFile {
            path: path.clone(),
            generate_if_missing: true,
        };
        let first = read_or_create_key(&auto).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
        assert_eq!(
            *read_or_create_key(&auto).unwrap(),
            *first,
            "stable once created"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            read_or_create_key(&auto).is_err(),
            "world-readable key refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
