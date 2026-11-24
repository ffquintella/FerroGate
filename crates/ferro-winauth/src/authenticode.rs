//! Authenticode signer chain of an open file (ADR-0006 §4): `WinVerifyTrust`
//! on the caller's handle with whole-chain revocation checks, then the
//! signer's certificate chain from the provider state.

use std::ffi::c_void;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// Most certificates copied out of one signer chain.
const MAX_CHAIN: usize = 16;

/// A verified Authenticode signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticodeSignature {
    /// The signer chain as DER, signer first, as WinTrust built it.
    pub chain: Vec<Vec<u8>>,
    /// WinTrust verified at least one timestamp countersignature.
    pub timestamped: bool,
}

/// Why no verified chain was returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticodeError {
    /// `WinVerifyTrust` failed with this status (an `HRESULT`).
    Status(i32),
    /// Verification passed but the provider state held no usable signer
    /// chain (treated as untrusted).
    NoSigner,
}

/// Verify the Authenticode signature of `file` (opened from `path`) with
/// revocation checks on every certificate but the root, and return the
/// signer chain. The handle is verified, so the bytes checked are the bytes
/// of `file`, not whatever `path` names later.
pub fn authenticode_signature(
    file: &File,
    path: &Path,
) -> Result<AuthenticodeSignature, AuthenticodeError> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();

    // SAFETY: zeroed is a valid initial state for these C structs; every
    // mandatory field is set before use.
    let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    file_info.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
    file_info.pcwszFilePath = wide.as_ptr();
    file_info.hFile = file.as_raw_handle() as HANDLE;

    // SAFETY: as above.
    let mut wtd: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    wtd.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.Anonymous.pFile = &mut file_info;

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `wtd`, `file_info`, `wide`, `action` and the file handle are
    // valid and outlive both calls; the close call frees the provider state
    // the verify call allocated.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            ptr::from_mut(&mut wtd).cast::<c_void>(),
        )
    };
    let result = if status == 0 {
        // SAFETY: the state handle is live until the close call below.
        unsafe { signer_chain(wtd.hWVTStateData) }
    } else {
        Err(AuthenticodeError::Status(status))
    };
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: releases the state allocated by the verify call.
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            ptr::from_mut(&mut wtd).cast::<c_void>(),
        )
    };
    result
}

/// Copy the first signer's chain out of a live WinTrust state.
///
/// # Safety
/// `state` must be the `hWVTStateData` of a successful verify call that has
/// not been closed yet.
unsafe fn signer_chain(state: HANDLE) -> Result<AuthenticodeSignature, AuthenticodeError> {
    // SAFETY: `state` is live (caller contract).
    let prov = unsafe { WTHelperProvDataFromStateData(state) };
    if prov.is_null() {
        return Err(AuthenticodeError::NoSigner);
    }
    // SAFETY: `prov` is the provider data of the live state; signer 0, not a
    // countersigner.
    let signer = unsafe { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
    if signer.is_null() {
        return Err(AuthenticodeError::NoSigner);
    }
    // SAFETY: non-null and owned by the live state.
    let signer = unsafe { &*signer };
    let count = signer.csCertChain as usize;
    if count == 0 || count > MAX_CHAIN || signer.pasCertChain.is_null() {
        return Err(AuthenticodeError::NoSigner);
    }
    // SAFETY: WinTrust allocated `csCertChain` entries at `pasCertChain`.
    let certs = unsafe { std::slice::from_raw_parts(signer.pasCertChain, count) };
    let mut chain = Vec::with_capacity(count);
    for c in certs {
        if c.pCert.is_null() {
            return Err(AuthenticodeError::NoSigner);
        }
        // SAFETY: a non-null CERT_CONTEXT owned by the live state.
        let ctx = unsafe { &*c.pCert };
        if ctx.pbCertEncoded.is_null() || ctx.cbCertEncoded == 0 {
            return Err(AuthenticodeError::NoSigner);
        }
        // SAFETY: `cbCertEncoded` bytes of DER at `pbCertEncoded`, copied out
        // before the state is closed.
        let der =
            unsafe { std::slice::from_raw_parts(ctx.pbCertEncoded, ctx.cbCertEncoded as usize) };
        chain.push(der.to_vec());
    }
    Ok(AuthenticodeSignature {
        chain,
        timestamped: signer.csCounterSigners > 0,
    })
}
