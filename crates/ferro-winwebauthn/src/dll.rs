//! `webauthn.dll`, loaded at first use from System32 only and never
//! unloaded, and the two ceremonies over it. Every `unsafe` block of the
//! admin client's Windows key backend is in this file, each with its
//! `SAFETY` note.

//! Inputs are built from borrowed slices and locals that outlive the one
//! blocking call; outputs are read field by field (version-1 fields only,
//! never a reference to the whole, possibly newer, struct), copied within
//! [`Limits`], and freed by a guard with the matching `WebAuthNFree*`.

#![allow(unsafe_code)] // the FFI boundary, by design (see the crate docs)

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use windows_sys::core::{GUID, HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::{HMODULE, HWND};
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_API_VERSION_1, WEBAUTHN_ASSERTION, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
    WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIALS, WEBAUTHN_CREDENTIAL_ATTESTATION,
    WEBAUTHN_CREDENTIAL_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_EXTENSIONS,
    WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

use crate::{
    len32, out_len, watch, wide, Assertion, AssertionArgs, Attestation, CreationArgs, Error,
    Limits, CANCEL_POLL,
};

// The declarations of webauthn.h (API version 1, Windows 10 1903).
type GetApiVersionNumber = unsafe extern "system" fn() -> u32;
type GetAssertion = unsafe extern "system" fn(
    HWND,
    PCWSTR,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> HRESULT;
type MakeCredential = unsafe extern "system" fn(
    HWND,
    *const WEBAUTHN_RP_ENTITY_INFORMATION,
    *const WEBAUTHN_USER_ENTITY_INFORMATION,
    *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> HRESULT;
type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
type FreeCredentialAttestation = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION);
type GetCancellationId = unsafe extern "system" fn(*mut GUID) -> HRESULT;
type CancelCurrentOperation = unsafe extern "system" fn(*const GUID) -> HRESULT;
type Raw = unsafe extern "system" fn() -> isize;

/// The options versions filled here, both within API version 1: the first
/// that carries a cancellation id (`pCancellationId`).
const GET_ASSERTION_OPTIONS_VERSION: u32 = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3;
const MAKE_CREDENTIAL_OPTIONS_VERSION: u32 =
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2;

/// The loaded API: function pointers into `webauthn.dll`, which stays
/// loaded for the life of the process.
pub struct Api {
    get_assertion: GetAssertion,
    make_credential: MakeCredential,
    free_assertion: FreeAssertion,
    free_attestation: FreeCredentialAttestation,
    get_cancellation_id: GetCancellationId,
    cancel: CancelCurrentOperation,
}

static API: OnceLock<Option<Api>> = OnceLock::new();

/// The Windows WebAuthn API, or `None` when this Windows has no
/// `webauthn.dll` in System32, lacks one of its functions, or reports an
/// API version below 1.
#[must_use]
pub fn api() -> Option<&'static Api> {
    API.get_or_init(load).as_ref()
}

/// `name`'s address in `module`.
fn symbol(module: HMODULE, name: &'static [u8]) -> Option<Raw> {
    debug_assert!(name.ends_with(&[0]));
    // SAFETY: `module` is a module handle that is never freed and `name` a
    // NUL-terminated ASCII string with a 'static lifetime.
    unsafe { GetProcAddress(module, name.as_ptr()) }
}

/// `name`'s address in `module` as the function pointer type `T`.
///
/// # Safety
/// `T` must be the `extern "system"` function pointer type of `name` as
/// webauthn.h declares it.
unsafe fn function<T: Copy>(module: HMODULE, name: &'static [u8]) -> Option<T> {
    assert_eq!(size_of::<T>(), size_of::<Raw>());
    let f = symbol(module, name)?;
    // SAFETY: same size (asserted above); the caller guarantees `T` is the
    // function's declared signature, so calls through it match the ABI.
    Some(unsafe { std::mem::transmute_copy::<Raw, T>(&f) })
}

fn load() -> Option<Api> {
    let file = wide("webauthn.dll").ok()?;
    // SAFETY: `file` is a NUL-terminated UTF-16 string alive across the
    // call, no file handle is passed, and LOAD_LIBRARY_SEARCH_SYSTEM32 keeps
    // the search to System32 (not the current or application directory, not
    // PATH), so a planted DLL is never picked up. The module is never freed.
    let module = unsafe { LoadLibraryExW(file.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return None;
    }
    // SAFETY: each `T` (the field's or the binding's type) is the webauthn.h
    // declaration of the function named next to it.
    let (version, api) = unsafe {
        let version: GetApiVersionNumber = function(module, b"WebAuthNGetApiVersionNumber\0")?;
        let api = Api {
            get_assertion: function(module, b"WebAuthNAuthenticatorGetAssertion\0")?,
            make_credential: function(module, b"WebAuthNAuthenticatorMakeCredential\0")?,
            free_assertion: function(module, b"WebAuthNFreeAssertion\0")?,
            free_attestation: function(module, b"WebAuthNFreeCredentialAttestation\0")?,
            get_cancellation_id: function(module, b"WebAuthNGetCancellationId\0")?,
            cancel: function(module, b"WebAuthNCancelCurrentOperation\0")?,
        };
        (version, api)
    };
    // SAFETY: no arguments; returns the API version number.
    (unsafe { version() } >= WEBAUTHN_API_VERSION_1).then_some(api)
}

/// An API-allocated result, freed once with its matching function.
struct Owned<T> {
    ptr: *mut T,
    free: unsafe extern "system" fn(*const T),
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr` came from the API call this guard was made for
            // and is freed exactly once, here, with that call's free function.
            unsafe { (self.free)(self.ptr) };
        }
    }
}

/// Copy `len` bytes at `ptr` (an API output) within `limit`.
fn copy_out(ptr: *const u8, len: u32, limit: usize, required: bool) -> Result<Vec<u8>, Error> {
    let n = out_len(len, limit, required, ptr.is_null())?;
    if n == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: the API returned `ptr` (non-null, checked) with `len` readable
    // bytes in a result that is freed only after this copy.
    Ok(unsafe { std::slice::from_raw_parts(ptr, n) }.to_vec())
}

fn parent(hwnd: usize) -> HWND {
    if hwnd != 0 {
        return std::ptr::with_exposed_provenance_mut::<c_void>(hwnd);
    }
    // SAFETY: no arguments; returns the foreground window or null (the
    // system then places its dialog on the desktop).
    unsafe { GetForegroundWindow() }
}

/// The client data: the API hashes `json` with SHA-256 itself. It only
/// reads `pbClientDataJSON` (declared non-const in the C header).
fn client_data(json: &[u8]) -> Result<WEBAUTHN_CLIENT_DATA, Error> {
    Ok(WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: len32(json.len())?,
        pbClientDataJSON: json.as_ptr().cast_mut(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    })
}

/// Credential descriptors pointing into `ids` (read only by the API).
fn credentials(ids: &[Vec<u8>]) -> Result<Vec<WEBAUTHN_CREDENTIAL>, Error> {
    ids.iter()
        .map(|id| {
            Ok(WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: len32(id.len())?,
                pbId: id.as_ptr().cast_mut(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            })
        })
        .collect()
}

const NO_EXTENSIONS: WEBAUTHN_EXTENSIONS = WEBAUTHN_EXTENSIONS {
    cExtensions: 0,
    pExtensions: null_mut(),
};

/// The registration options, with this crate's fixed policy: user
/// verification required, a roaming authenticator, `none` attestation, no
/// resident key. `exclude` and `cancel_id` must outlive the call they are
/// passed to.
fn creation_options(
    timeout_ms: u32,
    exclude: &mut [WEBAUTHN_CREDENTIAL],
    cancel_id: *mut GUID,
) -> Result<WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, Error> {
    Ok(WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: MAKE_CREDENTIAL_OPTIONS_VERSION,
        dwTimeoutMilliseconds: timeout_ms,
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: len32(exclude.len())?,
            pCredentials: exclude.as_mut_ptr(),
        },
        Extensions: NO_EXTENSIONS,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        bRequireResidentKey: 0,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        dwFlags: 0,
        pCancellationId: cancel_id,
        pExcludeCredentialList: null_mut(),
        dwEnterpriseAttestation: 0,
        dwLargeBlobSupport: 0,
        bPreferResidentKey: 0,
        bBrowserInPrivateMode: 0,
        bEnablePrf: 0,
        pLinkedDevice: null_mut(),
        cbJsonExt: 0,
        pbJsonExt: null_mut(),
    })
}

impl Api {
    /// A fresh cancellation id, when the API gives one.
    fn cancellation_id(&self) -> Option<GUID> {
        let mut id = GUID::from_u128(0);
        // SAFETY: `id` is a valid GUID out-parameter for the call.
        let hr = unsafe { (self.get_cancellation_id)(&raw mut id) };
        (hr >= 0).then_some(id)
    }

    /// Ask the system to end the operation registered under `id`.
    fn cancel_with(&self, id: Option<&GUID>) {
        if let Some(id) = id {
            // SAFETY: `id` points to a valid GUID for the call.
            let _ = unsafe { (self.cancel)(id) };
        }
    }

    /// `WebAuthNAuthenticatorGetAssertion` for `args`, cancelled when
    /// `cancelled` turns true; outputs copied within `limits`.
    ///
    /// # Errors
    /// [`Error`].
    pub fn get_assertion(
        &self,
        args: &AssertionArgs<'_>,
        limits: &Limits,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Assertion, Error> {
        let rp_id = wide(args.rp_id)?;
        let client_data = client_data(args.client_data_json)?;
        let mut allow = credentials(args.allow)?;
        let mut cancel_id = self.cancellation_id();
        let watched = cancel_id;
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: GET_ASSERTION_OPTIONS_VERSION,
            dwTimeoutMilliseconds: args.timeout_ms,
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: len32(allow.len())?,
                pCredentials: allow.as_mut_ptr(),
            },
            Extensions: NO_EXTENSIONS,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwFlags: 0,
            pwszU2fAppId: null(),
            pbU2fAppId: null_mut(),
            pCancellationId: cancel_id.as_mut().map_or(null_mut(), std::ptr::from_mut),
            pAllowCredentialList: null_mut(),
            dwCredLargeBlobOperation: 0,
            cbCredLargeBlob: 0,
            pbCredLargeBlob: null_mut(),
            pHmacSecretSaltValues: null_mut(),
            bBrowserInPrivateMode: 0,
            pLinkedDevice: null_mut(),
            bAutoFill: 0,
            cbJsonExt: 0,
            pbJsonExt: null_mut(),
        };
        let hwnd = parent(args.hwnd);
        let mut out: *mut WEBAUTHN_ASSERTION = null_mut();
        let hr = watch(
            cancelled,
            &|| self.cancel_with(watched.as_ref()),
            CANCEL_POLL,
            || {
                // SAFETY: `rp_id`, `client_data`, `options` and everything they
                // point to (`allow`, `cancel_id`, the argument slices, static
                // strings) are alive until this blocking call returns; the API
                // only reads them; `out` is a valid out-pointer.
                unsafe {
                    (self.get_assertion)(
                        hwnd,
                        rp_id.as_ptr(),
                        &raw const client_data,
                        &raw const options,
                        &raw mut out,
                    )
                }
            },
        );
        let owned = Owned {
            ptr: out,
            free: self.free_assertion,
        };
        if hr < 0 {
            return Err(Error::Api(hr));
        }
        if owned.ptr.is_null() {
            return Err(Error::Malformed);
        }
        let p = owned.ptr;
        // SAFETY: on success `p` points to a WEBAUTHN_ASSERTION of version 1
        // or later, owned until `owned` frees it; only version-1 fields are
        // read, by value through the raw pointer.
        let (ad, ad_len, sig, sig_len, cred, uid, uid_len) = unsafe {
            (
                (*p).pbAuthenticatorData,
                (*p).cbAuthenticatorData,
                (*p).pbSignature,
                (*p).cbSignature,
                (*p).Credential,
                (*p).pbUserId,
                (*p).cbUserId,
            )
        };
        Ok(Assertion {
            credential_id: copy_out(cred.pbId, cred.cbId, limits.credential_id, true)?,
            authenticator_data: copy_out(ad, ad_len, limits.authenticator_data, true)?,
            signature: copy_out(sig, sig_len, limits.signature, true)?,
            user_handle: copy_out(uid, uid_len, limits.user_handle, false)?,
        })
    }

    /// `WebAuthNAuthenticatorMakeCredential` for `args` (`none` attestation,
    /// no resident key), cancelled when `cancelled` turns true; outputs
    /// copied within `limits`.
    ///
    /// # Errors
    /// [`Error`].
    pub fn make_credential(
        &self,
        args: &CreationArgs<'_>,
        limits: &Limits,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Attestation, Error> {
        let rp_id = wide(args.rp_id)?;
        let rp_name = wide(args.rp_name)?;
        let user_name = wide(args.user_name)?;
        let display_name = wide(args.display_name)?;
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: len32(args.user_id.len())?,
            pbId: args.user_id.as_ptr().cast_mut(),
            pwszName: user_name.as_ptr(),
            pwszIcon: null(),
            pwszDisplayName: display_name.as_ptr(),
        };
        let mut params: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> = args
            .algorithms
            .iter()
            .map(|alg| WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                lAlg: *alg,
            })
            .collect();
        let cose = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: len32(params.len())?,
            pCredentialParameters: params.as_mut_ptr(),
        };
        let client_data = client_data(args.client_data_json)?;
        let mut exclude = credentials(args.exclude)?;
        let mut cancel_id = self.cancellation_id();
        let watched = cancel_id;
        let options = creation_options(
            args.timeout_ms,
            &mut exclude,
            cancel_id.as_mut().map_or(null_mut(), std::ptr::from_mut),
        )?;
        let hwnd = parent(args.hwnd);
        let mut out: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = null_mut();
        let hr = watch(
            cancelled,
            &|| self.cancel_with(watched.as_ref()),
            CANCEL_POLL,
            || {
                // SAFETY: `rp`, `user`, `cose`, `client_data`, `options` and
                // everything they point to (the UTF-16 strings, `params`,
                // `exclude`, `cancel_id`, the argument slices, static strings)
                // are alive until this blocking call returns; the API only reads
                // them; `out` is a valid out-pointer.
                unsafe {
                    (self.make_credential)(
                        hwnd,
                        &raw const rp,
                        &raw const user,
                        &raw const cose,
                        &raw const client_data,
                        &raw const options,
                        &raw mut out,
                    )
                }
            },
        );
        let owned = Owned {
            ptr: out,
            free: self.free_attestation,
        };
        if hr < 0 {
            return Err(Error::Api(hr));
        }
        if owned.ptr.is_null() {
            return Err(Error::Malformed);
        }
        let p = owned.ptr;
        // SAFETY: on success `p` points to a WEBAUTHN_CREDENTIAL_ATTESTATION
        // of version 1 or later, owned until `owned` frees it; only version-1
        // fields are read, by value through the raw pointer.
        let (obj, obj_len, id, id_len) = unsafe {
            (
                (*p).pbAttestationObject,
                (*p).cbAttestationObject,
                (*p).pbCredentialId,
                (*p).cbCredentialId,
            )
        };
        Ok(Attestation {
            credential_id: copy_out(id, id_len, limits.credential_id, true)?,
            attestation_object: copy_out(obj, obj_len, limits.attestation_object, true)?,
        })
    }
}
