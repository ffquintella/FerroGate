//! The [`SignatureVerifier`] trait and the per-platform verifier.
//!
//! A verifier asks the OS whether a binary's code signature is valid and
//! chains to a root the OS trusts, then returns the chain for the pure
//! matching in [`crate::matching`]. Every failure is an error, and the MIA
//! treats every error as "no auto-approval" (fail closed).

use std::path::Path;
use std::sync::Arc;

use crate::model::SignatureKind;

/// The kernel-identified caller whose signature is checked.
#[derive(Debug, Clone, Copy)]
pub struct CallerTarget<'a> {
    /// Caller process id (from the socket or pipe credentials).
    pub pid: u32,
    /// Canonical path of the caller's executable, when it was resolved.
    pub exe_path: Option<&'a str>,
    /// `SHA-384` of the image the MIA hashed while identifying the caller.
    /// The verifier must check the signature of exactly these bytes, or
    /// fail with [`VerifyError::ImageChanged`].
    pub bin_sha: &'a [u8; 48],
}

/// A signature the OS verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// Signature technology.
    pub kind: SignatureKind,
    /// The signer chain as DER, leaf first, as the OS built and trusted it.
    pub chain_der: Vec<Vec<u8>>,
    /// The OS verified a timestamp countersignature.
    pub timestamped: bool,
}

/// Why a signature was not verified. Each maps to a stable opcode
/// ([`VerifyError::reason`]) that echoes no caller-controlled bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// This platform has no verifier (Linux and others).
    #[error("publisher-unsupported")]
    Unsupported,
    /// The binary carries no code signature (or only an ad-hoc one).
    #[error("publisher-unsigned")]
    Unsigned,
    /// The signature or its chain did not verify, or does not chain to a
    /// root the OS trusts.
    #[error("publisher-untrusted")]
    Untrusted,
    /// A certificate in the chain is revoked.
    #[error("publisher-revoked")]
    Revoked,
    /// Revocation status could not be determined (offline, no CRL/OCSP).
    #[error("publisher-revocation-unknown")]
    RevocationUnknown,
    /// A certificate is expired and the signature carries no valid
    /// timestamp.
    #[error("publisher-expired")]
    Expired,
    /// The bytes now at the executable path are not the image the caller
    /// was identified by (a swap between identification and verification).
    #[error("publisher-image-changed")]
    ImageChanged,
    /// The caller's image or process could not be read.
    #[error("publisher-unreadable")]
    Unreadable,
}

impl VerifyError {
    /// Stable opcode for the local log.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Unsupported => "publisher-unsupported",
            Self::Unsigned => "publisher-unsigned",
            Self::Untrusted => "publisher-untrusted",
            Self::Revoked => "publisher-revoked",
            Self::RevocationUnknown => "publisher-revocation-unknown",
            Self::Expired => "publisher-expired",
            Self::ImageChanged => "publisher-image-changed",
            Self::Unreadable => "publisher-unreadable",
        }
    }
}

/// Verifies code signatures through the OS. Implementations block (file
/// reads, OS trust evaluation, maybe a revocation fetch): call them on a
/// blocking thread.
pub trait SignatureVerifier: Send + Sync + 'static {
    /// Verify the signature of the running caller `target`, bound to the
    /// image hash it was identified by.
    fn verify_caller(&self, target: &CallerTarget<'_>) -> Result<VerifiedSignature, VerifyError>;

    /// Verify the signature of the file at `path` (an administrator's
    /// "add from executable" flow; never used to authorize a caller).
    fn verify_file(&self, path: &Path) -> Result<VerifiedSignature, VerifyError>;
}

/// The verifier of platforms without one: every call is
/// [`VerifyError::Unsupported`], so no caller is ever auto-approved.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedVerifier;

impl SignatureVerifier for UnsupportedVerifier {
    fn verify_caller(&self, _target: &CallerTarget<'_>) -> Result<VerifiedSignature, VerifyError> {
        Err(VerifyError::Unsupported)
    }

    fn verify_file(&self, _path: &Path) -> Result<VerifiedSignature, VerifyError> {
        Err(VerifyError::Unsupported)
    }
}

/// This platform's verifier: Authenticode on Windows, the Apple code
/// signature on macOS, [`UnsupportedVerifier`] elsewhere.
#[must_use]
pub fn platform_verifier() -> Arc<dyn SignatureVerifier> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(crate::macos::MacVerifier)
    }
    #[cfg(windows)]
    {
        Arc::new(crate::windows::WindowsVerifier)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Arc::new(UnsupportedVerifier)
    }
}

/// The [`VerifyError`] of a failed `WinVerifyTrust` status (an `HRESULT`).
/// Pure, so it is tested on every host; anything unknown is
/// [`VerifyError::Untrusted`].
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[allow(clippy::cast_possible_wrap)] // HRESULT bit patterns.
pub(crate) const fn authenticode_status_error(status: i32) -> VerifyError {
    const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;
    const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003_u32 as i32;
    const CERT_E_EXPIRED: i32 = 0x800B_0101_u32 as i32;
    const CERT_E_REVOKED: i32 = 0x800B_010C_u32 as i32;
    const CRYPT_E_REVOKED: i32 = 0x8009_2010_u32 as i32;
    const CERT_E_REVOCATION_FAILURE: i32 = 0x800B_010E_u32 as i32;
    const CRYPT_E_NO_REVOCATION_CHECK: i32 = 0x8009_2012_u32 as i32;
    const CRYPT_E_REVOCATION_OFFLINE: i32 = 0x8009_2013_u32 as i32;
    match status {
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN => VerifyError::Unsigned,
        CERT_E_EXPIRED => VerifyError::Expired,
        CERT_E_REVOKED | CRYPT_E_REVOKED => VerifyError::Revoked,
        CERT_E_REVOCATION_FAILURE | CRYPT_E_NO_REVOCATION_CHECK | CRYPT_E_REVOCATION_OFFLINE => {
            VerifyError::RevocationUnknown
        }
        _ => VerifyError::Untrusted,
    }
}

/// Read `file` to the end and compare its `SHA-384` with `expected`.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
pub(crate) fn same_image(file: &mut std::fs::File, expected: &[u8; 48]) -> Result<(), VerifyError> {
    use sha2::{Digest as _, Sha384};
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(file, &mut bytes).map_err(|_| VerifyError::Unreadable)?;
    let actual: [u8; 48] = Sha384::digest(&bytes).into();
    if &actual == expected {
        Ok(())
    } else {
        Err(VerifyError::ImageChanged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_fails_closed() {
        let v = UnsupportedVerifier;
        let sha = [0u8; 48];
        let t = CallerTarget {
            pid: 1,
            exe_path: Some("/bin/true"),
            bin_sha: &sha,
        };
        assert_eq!(v.verify_caller(&t), Err(VerifyError::Unsupported));
        assert_eq!(
            v.verify_file(Path::new("/bin/true")),
            Err(VerifyError::Unsupported)
        );
        assert_eq!(VerifyError::Unsupported.reason(), "publisher-unsupported");
    }

    #[test]
    #[allow(clippy::cast_possible_wrap)]
    fn authenticode_statuses_fail_closed() {
        let s = |h: u32| authenticode_status_error(h as i32);
        assert_eq!(s(0x800B_0100), VerifyError::Unsigned);
        assert_eq!(s(0x800B_0101), VerifyError::Expired);
        assert_eq!(s(0x800B_010C), VerifyError::Revoked);
        assert_eq!(s(0x8009_2013), VerifyError::RevocationUnknown);
        assert_eq!(s(0x800B_0109), VerifyError::Untrusted, "untrusted root");
        assert_eq!(s(0x8009_6010), VerifyError::Untrusted, "bad digest");
    }

    #[test]
    fn a_changed_image_is_detected() {
        use sha2::{Digest as _, Sha384};
        let dir = std::env::temp_dir().join(format!("ferro-codesign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image");
        std::fs::write(&path, b"original").unwrap();
        let good: [u8; 48] = Sha384::digest(b"original").into();
        let mut f = std::fs::File::open(&path).unwrap();
        assert_eq!(same_image(&mut f, &good), Ok(()));
        std::fs::write(&path, b"swapped").unwrap();
        let mut f = std::fs::File::open(&path).unwrap();
        assert_eq!(same_image(&mut f, &good), Err(VerifyError::ImageChanged));
        let _ = std::fs::remove_dir_all(dir);
    }
}
