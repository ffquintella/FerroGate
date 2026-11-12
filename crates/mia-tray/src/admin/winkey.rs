//! The admin client's security-key backend on Windows (F22 §3a): the Windows
//! WebAuthn API (`webauthn.dll`), reached through the `ferro-winwebauthn`
//! FFI crate, which holds this backend's only `unsafe`. Windows shows its own
//! dialog (Windows Security) for the touch, the PIN or the biometric: the PIN
//! never passes through this client.

//! [`WinKey`] checks each request again (`keycheck`) before the API is
//! called, offers ES256 only (an EdDSA-only request is refused with a fixed
//! reason), words `HRESULT`s generically, and turns a new credential's
//! attestation into `none` after checking its RP ID hash, flags, credential
//! id and algorithm. Calls go through [`WinApi`], so all of it is tested on
//! every host with a double; only the adapter (`dll`) is Windows-only.

// Off Windows only the tests use this module.
#![cfg_attr(not(windows), allow(dead_code))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciborium::Value;
use ferrogate_admin_client::webauthn::{
    AssertionRequest, Authenticator, AuthenticatorAssertion, AuthenticatorAttestation,
    AuthenticatorError, CreationRequest,
};
use sha2::{Digest as _, Sha256};

use super::keycheck::{check_assertion, check_creation};
use super::keyprompt::KeyPrompt;

/// ES256, the one COSE algorithm this backend registers.
const ES256: i32 = -7;

// HRESULTs the API reports (values as in windows-sys `Win32::Foundation`).
const NTE_USER_CANCELLED: u32 = 0x8009_0036;
const NTE_NOT_FOUND: u32 = 0x8009_0011;
const NTE_EXISTS: u32 = 0x8009_000F;
const NTE_NOT_SUPPORTED: u32 = 0x8009_0029;
const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
const NTE_DEVICE_NOT_FOUND: u32 = 0x8009_0035;
const NTE_TOKEN_KEYSET_STORAGE_FULL: u32 = 0x8009_0023;
const E_ABORT: u32 = 0x8000_4004;
const E_NOTIMPL: u32 = 0x8000_4001;
const E_INVALIDARG: u32 = 0x8007_0057;
/// `HRESULT_FROM_WIN32(ERROR_CANCELLED)`.
const HR_CANCELLED: u32 = 0x8007_04C7;
/// `HRESULT_FROM_WIN32(ERROR_TIMEOUT)`.
const HR_TIMEOUT: u32 = 0x8007_05B4;

// Fixed descriptions for `AuthenticatorError::Failed` (logged, never shown:
// the window words every key failure generically).
const FAILURE: &str = "security key failure";
const MALFORMED: &str = "malformed answer";
const EXCLUDED: &str = "this key is already registered";
const UNSUPPORTED: &str = "the key does not support this request";
const REFUSED: &str = "the system refused the request";
const NO_KEY: &str = "no security key was found";
const KEY_FULL: &str = "the key has no room for another credential";
const EDDSA_ONLY: &str =
    "the server accepts EdDSA keys only, which this Windows backend does not offer (ES256 only)";
const WRONG_SITE: &str = "answer for another site or without verification";
const WRONG_ALGORITHM: &str = "answer with an algorithm not asked for";

// `authenticatorData` layout (WebAuthn §6.1): rpIdHash, flags, signCount,
// then the attested credential: AAGUID, id length, id, COSE key.
const FLAGS_AT: usize = 32;
const AAGUID: std::ops::Range<usize> = 37..53;
const ID_LEN: std::ops::Range<usize> = 53..55;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

fn failed(why: &str) -> AuthenticatorError {
    AuthenticatorError::Failed(why.to_string())
}

/// An assertion as the API takes it.
pub(crate) struct AssertionCall<'a> {
    hwnd: usize,
    rp_id: &'a str,
    client_data_json: &'a [u8],
    allow: &'a [Vec<u8>],
    timeout_ms: u32,
}

/// A registration as the API takes it.
pub(crate) struct CreationCall<'a> {
    hwnd: usize,
    rp_id: &'a str,
    rp_name: &'a str,
    user_id: &'a [u8],
    user_name: &'a str,
    display_name: &'a str,
    client_data_json: &'a [u8],
    algorithms: &'a [i32],
    exclude: &'a [Vec<u8>],
    timeout_ms: u32,
}

/// The API's assertion, copied out within the client's bounds.
pub(crate) struct WinAssertion {
    credential_id: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Vec<u8>,
}

/// The API's new credential, copied out within the client's bounds.
pub(crate) struct WinAttestation {
    credential_id: Vec<u8>,
    attestation_object: Vec<u8>,
}

/// Why the API gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WinFailure {
    /// The API's `HRESULT`.
    Hresult(i32),
    /// An argument could not be passed.
    Input,
    /// An output was past its bound.
    TooLarge,
    /// The API answered success without the expected data.
    Malformed,
}

/// The Windows WebAuthn API calls this backend makes (`webauthn.dll`, or a
/// test double). Both block until the person answers the system's dialog,
/// it times out, or `cancelled` turns true.
pub(crate) trait WinApi: Send + Sync {
    /// `WebAuthNAuthenticatorGetAssertion`.
    fn get_assertion(
        &self,
        call: &AssertionCall<'_>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<WinAssertion, WinFailure>;

    /// `WebAuthNAuthenticatorMakeCredential`.
    fn make_credential(
        &self,
        call: &CreationCall<'_>,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<WinAttestation, WinFailure>;
}

/// The Windows backend (see the module documentation).
pub(crate) struct WinKey<A> {
    api: A,
    /// Armed by the window for key commands; cancelled on lock, sign-out
    /// and close (no prompt is shown through it: Windows has its own).
    prompt: Arc<KeyPrompt>,
    /// The admin window's `HWND` (0: the foreground window).
    parent: Arc<AtomicUsize>,
}

impl<A: WinApi> WinKey<A> {
    /// The backend over `api`, cancelled through `prompt`, its dialog
    /// parented to the window in `parent`.
    pub(crate) fn new(api: A, prompt: Arc<KeyPrompt>, parent: Arc<AtomicUsize>) -> Self {
        Self {
            api,
            prompt,
            parent,
        }
    }

    /// Run one call while the window's command is armed; a cancel from the
    /// window ends the system's dialog.
    fn ceremony<T>(
        &self,
        call: impl FnOnce(usize, &(dyn Fn() -> bool + Sync)) -> Result<T, WinFailure>,
    ) -> Result<T, AuthenticatorError> {
        let ceremony = self.prompt.begin().ok_or(AuthenticatorError::Cancelled)?;
        let result = {
            let cancelled = || self.prompt.cancelled(&ceremony);
            call(self.parent.load(Ordering::Relaxed), &cancelled)
        };
        self.prompt.finish(ceremony);
        result.map_err(failure)
    }
}

impl<A: WinApi> Authenticator for WinKey<A> {
    fn get_assertion(
        &self,
        request: &AssertionRequest,
    ) -> Result<AuthenticatorAssertion, AuthenticatorError> {
        check_assertion(request)?;
        let a = self.ceremony(|hwnd, cancelled| {
            let call = AssertionCall {
                hwnd,
                rp_id: &request.rp_id,
                client_data_json: &request.client_data_json,
                allow: &request.allow_credential_ids,
                timeout_ms: millis(request.timeout),
            };
            self.api.get_assertion(&call, cancelled)
        })?;
        Ok(AuthenticatorAssertion {
            credential_id: a.credential_id,
            authenticator_data: a.authenticator_data,
            signature: a.signature,
            user_handle: a.user_handle,
        })
    }

    fn make_credential(
        &self,
        request: &CreationRequest,
    ) -> Result<AuthenticatorAttestation, AuthenticatorError> {
        check_creation(request)?;
        let algorithms = windows_algorithms(request)?;
        let a = self.ceremony(|hwnd, cancelled| {
            let call = CreationCall {
                hwnd,
                rp_id: &request.rp_id,
                rp_name: &request.rp_name,
                user_id: &request.user_id,
                user_name: &request.user_name,
                display_name: &request.display_name,
                client_data_json: &request.client_data_json,
                algorithms: &algorithms,
                exclude: &request.exclude_credential_ids,
                timeout_ms: millis(request.timeout),
            };
            self.api.make_credential(&call, cancelled)
        })?;
        let attestation_object =
            none_attestation(request, &a.credential_id, &a.attestation_object)?;
        Ok(AuthenticatorAttestation {
            credential_id: a.credential_id,
            attestation_object,
            transports: Vec::new(),
        })
    }
}

fn millis(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// The algorithms offered to Windows: ES256 when the server accepts it; an
/// EdDSA-only request is refused with a clear, fixed reason.
fn windows_algorithms(r: &CreationRequest) -> Result<Vec<i32>, AuthenticatorError> {
    if r.algorithms.contains(&ES256) {
        Ok(vec![ES256])
    } else {
        Err(failed(EDDSA_ONLY))
    }
}

/// The API's failure, worded generically (never a code or data in the text).
fn failure(f: WinFailure) -> AuthenticatorError {
    match f {
        WinFailure::Hresult(hr) => map_hresult(hr),
        WinFailure::Input => AuthenticatorError::BadRequest,
        WinFailure::TooLarge | WinFailure::Malformed => failed(MALFORMED),
    }
}

/// An `HRESULT` from the API as the client's error.
fn map_hresult(hr: i32) -> AuthenticatorError {
    match hr.cast_unsigned() {
        NTE_USER_CANCELLED | HR_CANCELLED | E_ABORT => AuthenticatorError::Cancelled,
        HR_TIMEOUT => AuthenticatorError::Timeout,
        NTE_NOT_FOUND => AuthenticatorError::NoCredential,
        NTE_EXISTS => failed(EXCLUDED),
        NTE_NOT_SUPPORTED | E_NOTIMPL => failed(UNSUPPORTED),
        NTE_INVALID_PARAMETER | E_INVALIDARG => failed(REFUSED),
        NTE_DEVICE_NOT_FOUND => failed(NO_KEY),
        NTE_TOKEN_KEYSET_STORAGE_FULL => failed(KEY_FULL),
        _ => failed(FAILURE),
    }
}

/// The COSE key's algorithm (label 3).
fn cose_alg(key: &Value) -> Option<i32> {
    let int = |v: &Value| v.as_integer().and_then(|i| i32::try_from(i).ok());
    key.as_map()?
        .iter()
        .find(|(k, _)| int(k) == Some(3))
        .and_then(|(_, v)| int(v))
}

/// The new credential's attestation object as `none`: the statement
/// dropped and the AAGUID zeroed, after checking the authenticator data is
/// for this RP ID, with user presence and verification, for `credential_id`,
/// with an ES256 key the request asked for.
fn none_attestation(
    request: &CreationRequest,
    credential_id: &[u8],
    object: &[u8],
) -> Result<Vec<u8>, AuthenticatorError> {
    let malformed = || failed(MALFORMED);
    let doc: Value = ciborium::from_reader(object).map_err(|_| malformed())?;
    let mut auth = doc
        .into_map()
        .map_err(|_| malformed())?
        .into_iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.into_bytes().ok())
        .ok_or_else(malformed)?;
    let rp_hash: [u8; 32] = Sha256::digest(request.rp_id.as_bytes()).into();
    let flags = *auth.get(FLAGS_AT).ok_or_else(malformed)?;
    if auth.get(..32) != Some(&rp_hash[..]) || flags & (FLAG_UP | FLAG_UV) != FLAG_UP | FLAG_UV {
        return Err(failed(WRONG_SITE));
    }
    let len = auth.get(ID_LEN).ok_or_else(malformed)?;
    let key_at = ID_LEN.end + usize::from(u16::from_be_bytes([len[0], len[1]]));
    if flags & FLAG_AT == 0 || auth.get(ID_LEN.end..key_at) != Some(credential_id) {
        return Err(malformed());
    }
    let key: Value = ciborium::from_reader(auth.get(key_at..).ok_or_else(malformed)?)
        .map_err(|_| malformed())?;
    if cose_alg(&key) != Some(ES256) || !request.algorithms.contains(&ES256) {
        return Err(failed(WRONG_ALGORITHM));
    }
    auth[AAGUID].fill(0);
    let none = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (Value::Text("authData".into()), Value::Bytes(auth)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&none, &mut out).map_err(|_| malformed())?;
    Ok(out)
}

/// The adapter to `webauthn.dll` (through `ferro-winwebauthn`).
#[cfg(windows)]
mod dll {
    use ferro_winwebauthn::{Api, AssertionArgs, CreationArgs, Error, Limits};
    use ferrogate_admin_client::webauthn::{
        MAX_ATTESTATION_OBJECT_LEN, MAX_CREDENTIAL_ID_LEN, MAX_RESPONSE_FIELD_LEN,
        MAX_USER_HANDLE_LEN,
    };

    use super::{AssertionCall, CreationCall, WinApi, WinAssertion, WinAttestation, WinFailure};

    /// Every output is copied within the client's own bounds.
    const LIMITS: Limits = Limits {
        credential_id: MAX_CREDENTIAL_ID_LEN,
        authenticator_data: MAX_RESPONSE_FIELD_LEN,
        signature: MAX_RESPONSE_FIELD_LEN,
        user_handle: MAX_USER_HANDLE_LEN,
        attestation_object: MAX_ATTESTATION_OBJECT_LEN,
    };

    /// `webauthn.dll`, loaded from System32.
    pub(crate) struct Dll(&'static Api);

    /// The system's WebAuthn API, when this Windows has one.
    pub(crate) fn dll() -> Option<Dll> {
        ferro_winwebauthn::api().map(Dll)
    }

    fn failure(e: Error) -> WinFailure {
        match e {
            Error::Api(hr) => WinFailure::Hresult(hr),
            Error::Input => WinFailure::Input,
            Error::TooLarge => WinFailure::TooLarge,
            Error::Malformed => WinFailure::Malformed,
        }
    }

    impl WinApi for Dll {
        fn get_assertion(
            &self,
            c: &AssertionCall<'_>,
            cancelled: &(dyn Fn() -> bool + Sync),
        ) -> Result<WinAssertion, WinFailure> {
            let args = AssertionArgs {
                hwnd: c.hwnd,
                rp_id: c.rp_id,
                client_data_json: c.client_data_json,
                allow: c.allow,
                timeout_ms: c.timeout_ms,
            };
            let a = self
                .0
                .get_assertion(&args, &LIMITS, cancelled)
                .map_err(failure)?;
            Ok(WinAssertion {
                credential_id: a.credential_id,
                authenticator_data: a.authenticator_data,
                signature: a.signature,
                user_handle: a.user_handle,
            })
        }

        fn make_credential(
            &self,
            c: &CreationCall<'_>,
            cancelled: &(dyn Fn() -> bool + Sync),
        ) -> Result<WinAttestation, WinFailure> {
            let args = CreationArgs {
                hwnd: c.hwnd,
                rp_id: c.rp_id,
                rp_name: c.rp_name,
                user_id: c.user_id,
                user_name: c.user_name,
                display_name: c.display_name,
                client_data_json: c.client_data_json,
                algorithms: c.algorithms,
                exclude: c.exclude,
                timeout_ms: c.timeout_ms,
            };
            let a = self
                .0
                .make_credential(&args, &LIMITS, cancelled)
                .map_err(failure)?;
            Ok(WinAttestation {
                credential_id: a.credential_id,
                attestation_object: a.attestation_object,
            })
        }
    }
}

#[cfg(windows)]
pub(crate) use dll::dll;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use ferrogate_admin_client::webauthn::{
        attestation_into_proto, client_data_get, creation_request, CreationOptions,
    };

    const RP: &str = "ferrogate-admin.ferrogate.test";

    fn request() -> AssertionRequest {
        let origin = format!("https://{RP}");
        let client_data_json = client_data_get(&[7; 32], &origin);
        AssertionRequest {
            rp_id: RP.into(),
            client_data_hash: Sha256::digest(&client_data_json).into(),
            origin,
            client_data_json,
            allow_credential_ids: vec![vec![1; 32]],
            user_verification_required: true,
            timeout: Duration::from_secs(60),
        }
    }

    fn creation(algorithms: Vec<i32>) -> CreationRequest {
        creation_request(&CreationOptions {
            challenge: vec![3; 32],
            rp_id: RP.into(),
            rp_name: "FerroGate".into(),
            user_id: vec![4; 32],
            user_name: "alice".into(),
            display_name: "Alice".into(),
            pub_key_cred_params: algorithms,
            exclude_credential_ids: vec![vec![1; 32]],
            user_verification: 1,
            attestation: 1,
        })
        .unwrap()
    }

    /// An attestation object as a key answers through Windows (`packed`,
    /// with its AAGUID), for `rp_id` with `flags`, credential `[2; 32]` and
    /// a COSE key of algorithm `alg`.
    fn attestation_object(rp_id: &str, flags: u8, alg: i32) -> Vec<u8> {
        let mut key = Vec::new();
        let int = |i: i64| Value::Integer(i.into());
        ciborium::into_writer(
            &Value::Map(vec![
                (int(1), int(2)),
                (int(3), int(alg.into())),
                (int(-1), int(1)),
                (int(-2), Value::Bytes(vec![1; 32])),
                (int(-3), Value::Bytes(vec![2; 32])),
            ]),
            &mut key,
        )
        .unwrap();
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&5u32.to_be_bytes());
        auth.extend_from_slice(&[0xaa; 16]);
        auth.extend_from_slice(&32u16.to_be_bytes());
        auth.extend_from_slice(&[2; 32]);
        auth.extend_from_slice(&key);
        let mut out = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("packed".into())),
                (
                    Value::Text("attStmt".into()),
                    Value::Map(vec![(Value::Text("sig".into()), Value::Bytes(vec![9; 70]))]),
                ),
                (Value::Text("authData".into()), Value::Bytes(auth)),
            ]),
            &mut out,
        )
        .unwrap();
        out
    }

    const OK_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_AT;

    /// What the fake API saw and does.
    #[derive(Default)]
    struct Seen {
        calls: usize,
        hwnd: usize,
        rp_id: String,
        allow: Vec<Vec<u8>>,
        algorithms: Vec<i32>,
        timeout_ms: u32,
    }

    #[derive(Clone, Copy)]
    enum Answer {
        Ok,
        Fail(WinFailure),
        /// Block until the window cancels, then report the system's cancel.
        UntilCancelled,
    }

    struct FakeApi {
        seen: Arc<Mutex<Seen>>,
        answer: Answer,
        object: Vec<u8>,
    }

    impl FakeApi {
        fn answer<T>(
            &self,
            cancelled: &(dyn Fn() -> bool + Sync),
            ok: impl FnOnce() -> T,
        ) -> Result<T, WinFailure> {
            match self.answer {
                Answer::Ok => Ok(ok()),
                Answer::Fail(f) => Err(f),
                Answer::UntilCancelled => {
                    while !cancelled() {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(WinFailure::Hresult(NTE_USER_CANCELLED.cast_signed()))
                }
            }
        }
    }

    impl WinApi for FakeApi {
        fn get_assertion(
            &self,
            c: &AssertionCall<'_>,
            cancelled: &(dyn Fn() -> bool + Sync),
        ) -> Result<WinAssertion, WinFailure> {
            {
                let mut s = self.seen.lock().unwrap();
                s.calls += 1;
                s.hwnd = c.hwnd;
                s.rp_id = c.rp_id.into();
                s.allow = c.allow.to_vec();
                s.timeout_ms = c.timeout_ms;
            }
            self.answer(cancelled, || WinAssertion {
                credential_id: vec![1; 32],
                authenticator_data: vec![5; 37],
                signature: vec![9; 70],
                user_handle: Vec::new(),
            })
        }

        fn make_credential(
            &self,
            c: &CreationCall<'_>,
            cancelled: &(dyn Fn() -> bool + Sync),
        ) -> Result<WinAttestation, WinFailure> {
            {
                let mut s = self.seen.lock().unwrap();
                s.calls += 1;
                s.algorithms = c.algorithms.to_vec();
                s.rp_id = c.rp_id.into();
            }
            let object = self.object.clone();
            self.answer(cancelled, || WinAttestation {
                credential_id: vec![2; 32],
                attestation_object: object,
            })
        }
    }

    fn key(answer: Answer, object: Vec<u8>) -> (WinKey<FakeApi>, Arc<Mutex<Seen>>, Arc<KeyPrompt>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let prompt = KeyPrompt::new();
        let api = FakeApi {
            seen: Arc::clone(&seen),
            answer,
            object,
        };
        let parent = Arc::new(AtomicUsize::new(0x1234));
        (WinKey::new(api, Arc::clone(&prompt), parent), seen, prompt)
    }

    #[test]
    fn requests_are_checked_before_the_system_is_asked() {
        let (k, seen, prompt) = key(Answer::Ok, Vec::new());
        prompt.arm();
        let mut foreign = request();
        foreign.origin = "https://evil.test".into();
        assert_eq!(
            k.get_assertion(&foreign).err(),
            Some(AuthenticatorError::BadRequest)
        );
        let mut no_uv = request();
        no_uv.user_verification_required = false;
        assert_eq!(
            k.get_assertion(&no_uv).err(),
            Some(AuthenticatorError::BadRequest)
        );
        let mut edited = creation(vec![-7]);
        edited.rp_id = "ferrogate-admin.elsewhere.test".into();
        assert_eq!(
            k.make_credential(&edited).err(),
            Some(AuthenticatorError::BadRequest)
        );
        assert_eq!(seen.lock().unwrap().calls, 0);
    }

    #[test]
    fn the_call_carries_the_request_the_admin_window_and_the_timeout() {
        let (k, seen, prompt) = key(Answer::Ok, Vec::new());
        prompt.arm();
        let a = k.get_assertion(&request()).expect("answered");
        assert_eq!(a.credential_id, vec![1; 32]);
        let s = seen.lock().unwrap();
        assert_eq!((s.hwnd, s.rp_id.as_str()), (0x1234, RP));
        assert_eq!(s.allow, vec![vec![1; 32]]);
        assert_eq!(s.timeout_ms, 60_000);
    }

    #[test]
    fn only_es256_is_offered_and_an_eddsa_only_request_is_refused_clearly() {
        let object = attestation_object(RP, OK_FLAGS, ES256);
        let (k, seen, prompt) = key(Answer::Ok, object);
        prompt.arm();
        k.make_credential(&creation(vec![-8, -7]))
            .expect("registered");
        assert_eq!(seen.lock().unwrap().algorithms, vec![ES256]);
        let calls = seen.lock().unwrap().calls;
        assert_eq!(
            k.make_credential(&creation(vec![-8])).err(),
            Some(failed(EDDSA_ONLY))
        );
        assert_eq!(
            seen.lock().unwrap().calls,
            calls,
            "the system was not asked"
        );
    }

    #[test]
    fn hresults_and_failures_are_worded_generically() {
        let cases = [
            (NTE_USER_CANCELLED, AuthenticatorError::Cancelled),
            (HR_CANCELLED, AuthenticatorError::Cancelled),
            (E_ABORT, AuthenticatorError::Cancelled),
            (HR_TIMEOUT, AuthenticatorError::Timeout),
            (NTE_NOT_FOUND, AuthenticatorError::NoCredential),
            (NTE_EXISTS, failed(EXCLUDED)),
            (NTE_NOT_SUPPORTED, failed(UNSUPPORTED)),
            (E_INVALIDARG, failed(REFUSED)),
            (NTE_DEVICE_NOT_FOUND, failed(NO_KEY)),
            (0x8000_FFFF, failed(FAILURE)),
        ];
        for (hr, want) in cases {
            assert_eq!(map_hresult(hr.cast_signed()), want, "{hr:#x}");
            assert!(!want.to_string().contains("0x"), "no code in the text");
        }
        assert_eq!(failure(WinFailure::Input), AuthenticatorError::BadRequest);
        assert_eq!(failure(WinFailure::TooLarge), failed(MALFORMED));
        assert_eq!(failure(WinFailure::Malformed), failed(MALFORMED));
        let (k, _, prompt) = key(
            Answer::Fail(WinFailure::Hresult(NTE_EXISTS.cast_signed())),
            Vec::new(),
        );
        prompt.arm();
        assert_eq!(
            k.make_credential(&creation(vec![-7])).err(),
            Some(failed(EXCLUDED))
        );
    }

    #[test]
    fn a_lock_or_close_cancels_the_system_dialog_and_nothing_starts_unarmed() {
        let (k, seen, prompt) = key(Answer::UntilCancelled, Vec::new());
        assert_eq!(
            k.get_assertion(&request()).err(),
            Some(AuthenticatorError::Cancelled),
            "nothing armed"
        );
        assert_eq!(seen.lock().unwrap().calls, 0);
        prompt.arm();
        let k = Arc::new(k);
        let worker = Arc::clone(&k);
        let call = std::thread::spawn(move || worker.get_assertion(&request()));
        while seen.lock().unwrap().calls == 0 {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(prompt.asking(), None, "Windows shows its own dialog");
        prompt.cancel();
        assert_eq!(
            call.join().unwrap().err(),
            Some(AuthenticatorError::Cancelled)
        );
    }

    #[test]
    fn a_new_credential_leaves_with_none_attestation_for_this_site_only() {
        let c = creation(vec![-7]);
        let object = attestation_object(RP, OK_FLAGS, ES256);
        let none = none_attestation(&c, &[2; 32], &object).expect("checked");
        let doc: Value = ciborium::from_reader(none.as_slice()).unwrap();
        let map = doc.into_map().unwrap();
        let get = |k: &str| {
            map.iter()
                .find(|(key, _)| key.as_text() == Some(k))
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(get("fmt").as_text(), Some("none"));
        assert!(
            get("attStmt").into_map().unwrap().is_empty(),
            "statement dropped"
        );
        let auth = get("authData").into_bytes().unwrap();
        assert_eq!(&auth[AAGUID], &[0; 16], "AAGUID zeroed");
        assert_eq!(&auth[..32], &Sha256::digest(RP.as_bytes())[..]);
        let (k, _, prompt) = key(Answer::Ok, object);
        prompt.arm();
        let made = k.make_credential(&c).expect("registered");
        assert!(attestation_into_proto(&c, made, "Desk key").is_ok());

        let refused: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            (
                "another site",
                attestation_object("ferrogate-admin.elsewhere.test", OK_FLAGS, ES256),
                vec![2; 32],
            ),
            (
                "no UV",
                attestation_object(RP, FLAG_UP | FLAG_AT, ES256),
                vec![2; 32],
            ),
            (
                "EdDSA key",
                attestation_object(RP, OK_FLAGS, -8),
                vec![2; 32],
            ),
            (
                "other credential",
                attestation_object(RP, OK_FLAGS, ES256),
                vec![3; 32],
            ),
            ("not CBOR", vec![0xff, 0x00], vec![2; 32]),
            (
                "truncated",
                attestation_object(RP, OK_FLAGS, ES256)[..60].to_vec(),
                vec![2; 32],
            ),
        ];
        for (what, object, id) in refused {
            assert!(none_attestation(&c, &id, &object).is_err(), "{what}");
        }
    }
}
