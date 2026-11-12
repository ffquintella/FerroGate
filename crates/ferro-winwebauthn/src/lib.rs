//! `ferro-winwebauthn` — the Windows WebAuthn API (`webauthn.dll`) for the
//! tray admin client's security keys (F22 §3a): the one FFI boundary of that
//! backend. `mia-tray` is `#![forbid(unsafe_code)]`; the `unsafe` lives in
//! the Windows-only `dll` module (`api()`, `Api`). Everything in this file —
//! argument and output bounds, UTF-16 strings, the cancel watcher — is plain
//! Rust, compiled and tested on every host.

//! The touch, PIN and biometric prompts are the operating system's (Windows
//! Security): nothing secret passes through this crate. The ceremony policy
//! is fixed in `dll` and no caller can relax it: user verification required,
//! a roaming (cross-platform) authenticator, `none` attestation, no resident
//! key, SHA-256 client data.

// Every `unsafe` block states why it is sound.
#![warn(clippy::undocumented_unsafe_blocks)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(windows)]
mod dll;
#[cfg(windows)]
pub use dll::{api, Api};

/// How often a running ceremony looks at the caller's cancel flag.
pub const CANCEL_POLL: Duration = Duration::from_millis(50);

/// An assertion (`navigator.credentials.get`), as checked by the caller.
pub struct AssertionArgs<'a> {
    /// The parent window, as an `HWND` address (0: the foreground window).
    pub hwnd: usize,
    /// The relying party id.
    pub rp_id: &'a str,
    /// The `clientDataJSON` (the API hashes it with SHA-256).
    pub client_data_json: &'a [u8],
    /// Credentials the server accepts.
    pub allow: &'a [Vec<u8>],
    /// How long the system waits for the person.
    pub timeout_ms: u32,
}

/// A registration (`navigator.credentials.create`), as checked by the caller.
pub struct CreationArgs<'a> {
    /// The parent window, as an `HWND` address (0: the foreground window).
    pub hwnd: usize,
    /// The relying party id.
    pub rp_id: &'a str,
    /// The relying party's name.
    pub rp_name: &'a str,
    /// The opaque user handle.
    pub user_id: &'a [u8],
    /// The account name.
    pub user_name: &'a str,
    /// The account's display name.
    pub display_name: &'a str,
    /// The `clientDataJSON` (the API hashes it with SHA-256).
    pub client_data_json: &'a [u8],
    /// COSE algorithms, in order of preference.
    pub algorithms: &'a [i32],
    /// Credentials the account already holds.
    pub exclude: &'a [Vec<u8>],
    /// How long the system waits for the person.
    pub timeout_ms: u32,
}

/// The largest output accepted per field, in bytes; anything larger is
/// refused before it is copied.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Credential id.
    pub credential_id: usize,
    /// `authenticatorData`.
    pub authenticator_data: usize,
    /// Signature.
    pub signature: usize,
    /// User handle.
    pub user_handle: usize,
    /// Attestation object.
    pub attestation_object: usize,
}

/// An assertion, copied out of the API's buffers (no `Debug`: it carries a
/// credential id).
pub struct Assertion {
    /// The credential that signed.
    pub credential_id: Vec<u8>,
    /// `authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// The signature over `authenticatorData ‖ SHA-256(clientDataJSON)`.
    pub signature: Vec<u8>,
    /// The user handle (may be empty).
    pub user_handle: Vec<u8>,
}

/// A new credential, copied out of the API's buffers.
pub struct Attestation {
    /// The new credential's id.
    pub credential_id: Vec<u8>,
    /// The CBOR attestation object.
    pub attestation_object: Vec<u8>,
}

/// Why a call gave no answer. Carries no data from the request or the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The API failed with this `HRESULT`.
    Api(i32),
    /// An argument cannot be passed (an interior NUL, a length past `u32`).
    Input,
    /// An output field is larger than its [`Limits`] entry.
    TooLarge,
    /// The API answered success without the expected data.
    Malformed,
}

/// `s` as a NUL-terminated UTF-16 string; [`Error::Input`] for an interior
/// NUL (it would cut the string short).
///
/// # Errors
/// [`Error::Input`].
pub fn wide(s: &str) -> Result<Vec<u16>, Error> {
    if s.contains('\0') {
        return Err(Error::Input);
    }
    Ok(s.encode_utf16().chain(std::iter::once(0)).collect())
}

/// A length as the `u32` (`DWORD`) the API takes.
///
/// # Errors
/// [`Error::Input`] past `u32::MAX`.
pub fn len32(n: usize) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| Error::Input)
}

/// Check an output field's length before it is copied: at most `limit`
/// bytes, present when `required`, and a non-null pointer when not empty.
///
/// # Errors
/// [`Error::TooLarge`] past `limit`; [`Error::Malformed`] for an empty
/// required field or a null pointer with a length.
pub fn out_len(len: u32, limit: usize, required: bool, null: bool) -> Result<usize, Error> {
    let n = usize::try_from(len).map_err(|_| Error::TooLarge)?;
    if n > limit {
        return Err(Error::TooLarge);
    }
    if n == 0 {
        return if required {
            Err(Error::Malformed)
        } else {
            Ok(0)
        };
    }
    if null {
        return Err(Error::Malformed);
    }
    Ok(n)
}

/// Sets its flag when dropped, so the watcher stops even if `call` unwinds.
struct Done<'a>(&'a AtomicBool);

impl Drop for Done<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Run the blocking `call` while a watcher thread checks `cancelled` every
/// `poll` and, while it holds, calls `on_cancel` (again each time: a cancel
/// sent before the system registered the operation is not lost). The
/// watcher ends with `call`.
pub fn watch<R>(
    cancelled: &(dyn Fn() -> bool + Sync),
    on_cancel: &(dyn Fn() + Sync),
    poll: Duration,
    call: impl FnOnce() -> R,
) -> R {
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                if cancelled() {
                    on_cancel();
                }
                std::thread::sleep(poll);
            }
        });
        let _done = Done(&done);
        call()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    #[test]
    fn strings_are_nul_terminated_utf16_and_interior_nuls_are_refused() {
        assert_eq!(
            wide("ab").unwrap(),
            vec![u16::from(b'a'), u16::from(b'b'), 0]
        );
        assert_eq!(wide("é").unwrap(), vec![0xe9, 0]);
        assert_eq!(wide("").unwrap(), vec![0]);
        assert_eq!(wide("ferrogate-admin.a\0evil"), Err(Error::Input));
    }

    #[test]
    fn lengths_fit_a_dword_or_are_refused() {
        assert_eq!(len32(7), Ok(7));
        assert_eq!(len32(usize::try_from(u32::MAX).unwrap()), Ok(u32::MAX));
        if let Some(big) = usize::try_from(u32::MAX).unwrap().checked_add(1) {
            assert_eq!(len32(big), Err(Error::Input));
        }
    }

    #[test]
    fn outputs_are_bounded_present_and_non_null() {
        assert_eq!(out_len(32, 1023, true, false), Ok(32));
        assert_eq!(out_len(1024, 1023, true, false), Err(Error::TooLarge));
        assert_eq!(out_len(u32::MAX, 4096, false, false), Err(Error::TooLarge));
        assert_eq!(
            out_len(0, 64, true, false),
            Err(Error::Malformed),
            "required"
        );
        assert_eq!(
            out_len(0, 64, false, true),
            Ok(0),
            "an empty optional field"
        );
        assert_eq!(
            out_len(8, 64, false, true),
            Err(Error::Malformed),
            "null with a length"
        );
    }

    #[test]
    fn the_watcher_cancels_while_asked_and_stops_with_the_call() {
        let cancels = AtomicUsize::new(0);
        let asked = AtomicBool::new(false);
        let on_cancel = || {
            cancels.fetch_add(1, Ordering::SeqCst);
        };
        let cancelled = || asked.load(Ordering::SeqCst);
        // A call that ends by itself: no cancel sent.
        let r = watch(&cancelled, &on_cancel, Duration::from_millis(5), || 7);
        assert_eq!(r, 7);
        assert_eq!(cancels.load(Ordering::SeqCst), 0);
        // A call that blocks until the cancel arrives, as the system's does.
        let started = Instant::now();
        let r = watch(&cancelled, &on_cancel, Duration::from_millis(5), || {
            asked.store(true, Ordering::SeqCst);
            while cancels.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            "cancelled"
        });
        assert_eq!(r, "cancelled");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
