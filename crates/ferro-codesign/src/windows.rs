//! Windows verifier: Authenticode through `WinVerifyTrust`, on the same open
//! handle the image hash is read from (ADR-0006 §4).

//! The image is opened with `FILE_SHARE_READ` only, so it cannot be written
//! or deleted while it is hashed and verified; its `SHA-384` must equal the
//! hash the caller was identified by. Revocation is checked for the whole
//! chain except the root; an unknown status fails closed.

use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;

use ferro_winauth::{authenticode_signature, AuthenticodeError};

use crate::model::SignatureKind;
use crate::verifier::{
    authenticode_status_error, same_image, CallerTarget, SignatureVerifier, VerifiedSignature,
    VerifyError,
};

/// `FILE_SHARE_READ`: other openers may read, never write or delete.
const FILE_SHARE_READ: u32 = 1;

/// The production Windows verifier.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WindowsVerifier;

fn open_shared_read(path: &Path) -> Result<std::fs::File, VerifyError> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| VerifyError::Unreadable)
}

fn verify_open(file: &std::fs::File, path: &Path) -> Result<VerifiedSignature, VerifyError> {
    match authenticode_signature(file, path) {
        Ok(sig) => Ok(VerifiedSignature {
            kind: SignatureKind::Authenticode,
            chain_der: sig.chain,
            timestamped: sig.timestamped,
        }),
        Err(AuthenticodeError::Status(status)) => Err(authenticode_status_error(status)),
        Err(AuthenticodeError::NoSigner) => Err(VerifyError::Untrusted),
    }
}

impl SignatureVerifier for WindowsVerifier {
    fn verify_caller(&self, target: &CallerTarget<'_>) -> Result<VerifiedSignature, VerifyError> {
        let path =
            ferro_winauth::process_image_path(target.pid).map_err(|_| VerifyError::Unreadable)?;
        let mut file = open_shared_read(&path)?;
        same_image(&mut file, target.bin_sha)?;
        verify_open(&file, &path)
    }

    fn verify_file(&self, path: &Path) -> Result<VerifiedSignature, VerifyError> {
        let file = open_shared_read(path)?;
        verify_open(&file, path)
    }
}
