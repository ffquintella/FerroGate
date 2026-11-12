//! CTAP2 over USB HID: the admin client's security-key backend on macOS and
//! Linux (F22 §3a), through Mozilla's `authenticator` crate (IOKit on macOS,
//! hidraw + libudev on Linux, pure-Rust crypto for the PIN protocol).

//! [`HidKey`] implements `ferrogate_admin_client::webauthn::Authenticator`.
//! Each call checks the request again (the admin RP ID, its own origin and
//! `clientDataJSON` hash, user verification, the `MAX_*` bounds) before any
//! device is opened, runs one ceremony on the key the administrator touches,
//! and turns the answer into the client's types, which the client checks
//! once more. User verification is always required; the PIN is asked through
//! [`KeyPrompt`] and typed in the admin window.

//! A new credential's attestation is reduced to `none` (statement dropped,
//! AAGUID zeroed) before it leaves, as the request promises. Failures are
//! [`AuthenticatorError`]s with fixed wording: no PIN, credential id, key
//! data or library error text ever reaches them, and this module logs
//! nothing (the library's own log is silenced, see `webauthn::may_log`).

use std::sync::mpsc::{self, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
use authenticator::crypto::COSEAlgorithm;
use authenticator::ctap2::attestation::AuthenticatorDataFlags;
use authenticator::ctap2::commands::{CommandError, StatusCode};
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
    ResidentKeyRequirement, UserVerificationRequirement,
};
use authenticator::errors::{
    AuthenticatorError as CtapError, HIDError, PinError, U2FTokenError, UnsupportedOption,
};
use authenticator::statecallback::StateCallback;
use authenticator::{Pin, RegisterResult, SignResult, StatusPinUv, StatusUpdate};
use ferrogate_admin_client::webauthn::{
    AssertionRequest, Authenticator, AuthenticatorAssertion, AuthenticatorAttestation,
    AuthenticatorError, CreationRequest, SUPPORTED_ALGORITHMS,
};
use sha2::{Digest as _, Sha256};

use super::keycheck::{check_assertion, check_creation};
use super::keyprompt::{Ceremony, KeyAsk, KeyPrompt, PinAnswer};

/// How often a ceremony looks at the key's status, the window's cancel and
/// the deadline.
const POLL: Duration = Duration::from_millis(50);

// Fixed descriptions for `AuthenticatorError::Failed` (logged, never shown:
// the window words every key failure generically).
const FAILURE: &str = "security key failure";
const MALFORMED: &str = "malformed answer";
const NO_ACCESS: &str = "no access to USB security keys";
const EXCLUDED: &str = "this key is already registered";
const WRONG_PIN: &str = "wrong PIN";
const PIN_BLOCKED: &str = "the key's PIN is blocked";
const PIN_AUTH_BLOCKED: &str = "too many wrong PINs: unplug the key and try again";
const PIN_NOT_SET: &str = "the key has no PIN";
const PIN_RULES: &str = "the PIN does not meet the key's rules";
const NO_UV: &str = "the key cannot verify its user";
const UNSUPPORTED: &str = "the key does not support this request";
const WRONG_SITE: &str = "answer for another site or without verification";
const WRONG_ALGORITHM: &str = "answer with an algorithm not asked for";

fn failed(why: &str) -> AuthenticatorError {
    AuthenticatorError::Failed(why.to_string())
}

/// The CTAP library calls a ceremony makes: the `authenticator` crate's
/// service, or a test double.
pub(crate) trait Ctap {
    /// Start an assertion (`authenticatorGetAssertion`).
    fn sign(
        &mut self,
        timeout_ms: u64,
        args: SignArgs,
        status: Sender<StatusUpdate>,
        done: StateCallback<authenticator::Result<SignResult>>,
    ) -> authenticator::Result<()>;

    /// Start a registration (`authenticatorMakeCredential`).
    fn register(
        &mut self,
        timeout_ms: u64,
        args: RegisterArgs,
        status: Sender<StatusUpdate>,
        done: StateCallback<authenticator::Result<RegisterResult>>,
    ) -> authenticator::Result<()>;

    /// Stop the ceremony in flight (the key stops blinking).
    fn cancel(&mut self);
}

impl Ctap for AuthenticatorService {
    fn sign(
        &mut self,
        timeout_ms: u64,
        args: SignArgs,
        status: Sender<StatusUpdate>,
        done: StateCallback<authenticator::Result<SignResult>>,
    ) -> authenticator::Result<()> {
        AuthenticatorService::sign(self, timeout_ms, args, status, done)
    }

    fn register(
        &mut self,
        timeout_ms: u64,
        args: RegisterArgs,
        status: Sender<StatusUpdate>,
        done: StateCallback<authenticator::Result<RegisterResult>>,
    ) -> authenticator::Result<()> {
        AuthenticatorService::register(self, timeout_ms, args, status, done)
    }

    fn cancel(&mut self) {
        let _ = AuthenticatorService::cancel(self);
    }
}

/// Opens the CTAP library for one ceremony.
type Open = Box<dyn Fn() -> Result<Box<dyn Ctap>, AuthenticatorError> + Send + Sync>;

/// The USB HID security-key backend (see the module documentation).
pub(crate) struct HidKey {
    prompt: Arc<KeyPrompt>,
    open: Open,
}

static_assertions::assert_not_impl_any!(HidKey: std::fmt::Debug, Clone);

impl HidKey {
    /// The backend over this machine's USB HID keys, asking through `prompt`.
    pub(crate) fn new(prompt: Arc<KeyPrompt>) -> Self {
        Self::with(prompt, Box::new(open_usb))
    }

    fn with(prompt: Arc<KeyPrompt>, open: Open) -> Self {
        Self { prompt, open }
    }

    /// Run one ceremony started by `start`, with the prompt the window armed.
    fn ceremony<T: Send + 'static>(
        &self,
        timeout: Duration,
        start: impl FnOnce(
            &mut dyn Ctap,
            u64,
            Sender<StatusUpdate>,
            StateCallback<authenticator::Result<T>>,
        ) -> authenticator::Result<()>,
    ) -> Result<T, AuthenticatorError> {
        // Nothing armed: the window gave the command up (or never sent one).
        let ceremony = self.prompt.begin().ok_or(AuthenticatorError::Cancelled)?;
        let result = (self.open)()
            .and_then(|mut ctap| drive(ctap.as_mut(), &self.prompt, &ceremony, timeout, start));
        self.prompt.finish(ceremony);
        result
    }
}

/// The `authenticator` service over USB HID.
fn open_usb() -> Result<Box<dyn Ctap>, AuthenticatorError> {
    let mut service = AuthenticatorService::new().map_err(|_| failed(NO_ACCESS))?;
    service.add_u2f_usb_hid_platform_transports();
    Ok(Box::new(service))
}

impl Authenticator for HidKey {
    fn get_assertion(
        &self,
        request: &AssertionRequest,
    ) -> Result<AuthenticatorAssertion, AuthenticatorError> {
        check_assertion(request)?;
        let args = sign_args(request);
        let answer = self.ceremony(request.timeout, |ctap, ms, status, done| {
            ctap.sign(ms, args, status, done)
        })?;
        assertion_from(request, answer)
    }

    fn make_credential(
        &self,
        request: &CreationRequest,
    ) -> Result<AuthenticatorAttestation, AuthenticatorError> {
        check_creation(request)?;
        let args = register_args(request)?;
        let answer = self.ceremony(request.timeout, |ctap, ms, status, done| {
            ctap.register(ms, args, status, done)
        })?;
        attestation_from(request, answer)
    }
}

// ── Requests ────────────────────────────────────────────────────────────

fn descriptors(ids: &[Vec<u8>]) -> Vec<PublicKeyCredentialDescriptor> {
    ids.iter()
        .map(|id| PublicKeyCredentialDescriptor {
            id: id.clone(),
            transports: Vec::new(),
        })
        .collect()
}

/// The COSE algorithm this client accepts, by its COSE number.
fn cose(alg: i32) -> Option<COSEAlgorithm> {
    match alg {
        -7 => Some(COSEAlgorithm::ES256),
        -8 => Some(COSEAlgorithm::EDDSA),
        _ => None,
    }
}

/// The library's arguments for an assertion: user verification and presence
/// required, no PIN preset, no U2F fallback (U2F cannot verify the user).
fn sign_args(r: &AssertionRequest) -> SignArgs {
    SignArgs {
        client_data_hash: r.client_data_hash,
        origin: r.origin.clone(),
        relying_party_id: r.rp_id.clone(),
        allow_list: descriptors(&r.allow_credential_ids),
        user_verification_req: UserVerificationRequirement::Required,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    }
}

/// The library's arguments for a registration: user verification required,
/// a non-resident credential (sign-in always names its credentials), the
/// request's algorithms in its order, no PIN preset, no U2F fallback.
fn register_args(r: &CreationRequest) -> Result<RegisterArgs, AuthenticatorError> {
    let pub_cred_params = r
        .algorithms
        .iter()
        .map(|a| {
            cose(*a)
                .filter(|_| SUPPORTED_ALGORITHMS.contains(a))
                .map(|alg| PublicKeyCredentialParameters { alg })
                .ok_or(AuthenticatorError::BadRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RegisterArgs {
        client_data_hash: r.client_data_hash,
        relying_party: RelyingParty {
            id: r.rp_id.clone(),
            name: Some(r.rp_name.clone()),
        },
        origin: r.origin.clone(),
        user: PublicKeyCredentialUserEntity {
            id: r.user_id.clone(),
            name: Some(r.user_name.clone()),
            display_name: Some(r.display_name.clone()),
        },
        pub_cred_params,
        exclude_list: descriptors(&r.exclude_credential_ids),
        user_verification_req: UserVerificationRequirement::Required,
        resident_key_req: ResidentKeyRequirement::Discouraged,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    })
}

// ── The ceremony ────────────────────────────────────────────────────────

/// Run one ceremony to its end: follow the key's status (touch, choice of
/// key, PIN), stop it when the window cancels or `timeout` passes.
fn drive<T: Send + 'static>(
    ctap: &mut dyn Ctap,
    prompt: &KeyPrompt,
    ceremony: &Ceremony,
    timeout: Duration,
    start: impl FnOnce(
        &mut dyn Ctap,
        u64,
        Sender<StatusUpdate>,
        StateCallback<authenticator::Result<T>>,
    ) -> authenticator::Result<()>,
) -> Result<T, AuthenticatorError> {
    let deadline = Instant::now() + timeout;
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let (status_tx, status_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let done = StateCallback::new(Box::new(move |r: authenticator::Result<T>| {
        let _ = done_tx.send(r);
    }));
    start(ctap, timeout_ms, status_tx, done).map_err(|e| map_error(&e))?;
    loop {
        match done_rx.try_recv() {
            Ok(r) => return r.map_err(|e| map_error(&e)),
            Err(TryRecvError::Disconnected) => return Err(failed(FAILURE)),
            Err(TryRecvError::Empty) => {}
        }
        let stop = if prompt.cancelled(ceremony) {
            Some(AuthenticatorError::Cancelled)
        } else if Instant::now() >= deadline {
            Some(AuthenticatorError::Timeout)
        } else {
            match status_rx.recv_timeout(POLL) {
                Ok(update) => on_status(update, prompt, ceremony, deadline),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(POLL);
                    None
                }
            }
        };
        if let Some(e) = stop {
            // A PIN request still queued in `status_rx` is dropped with it,
            // which releases the library's thread waiting for the PIN.
            ctap.cancel();
            return Err(e);
        }
    }
}

/// Follow one status update; `Some` ends the ceremony with that error.
fn on_status(
    update: StatusUpdate,
    prompt: &KeyPrompt,
    ceremony: &Ceremony,
    deadline: Instant,
) -> Option<AuthenticatorError> {
    match update {
        StatusUpdate::PresenceRequired => {
            prompt.show(ceremony, KeyAsk::Touch);
            None
        }
        StatusUpdate::SelectDeviceNotice => {
            prompt.show(ceremony, KeyAsk::ChooseKey);
            None
        }
        StatusUpdate::PinUvError(StatusPinUv::PinRequired(reply)) => {
            send_pin(&reply, prompt, ceremony, false, None, deadline)
        }
        StatusUpdate::PinUvError(StatusPinUv::InvalidPin(reply, retries)) => {
            send_pin(&reply, prompt, ceremony, true, retries, deadline)
        }
        // Several accounts on one key for an empty allow list: CMIS names
        // the account's credentials, so this client never picks one.
        StatusUpdate::SelectResultNotice(reply, _) => {
            let _ = reply.send(None);
            None
        }
        // A blocked or missing PIN and the like: the library ends the
        // ceremony with the matching error, which `map_error` words.
        StatusUpdate::PinUvError(_) | StatusUpdate::InteractiveManagement(_) => None,
    }
}

/// Ask the window for the PIN and pass it on. The library's [`Pin`] is a
/// plain `String` (not wiped): it is made right here, from the wiped buffer,
/// and moved into the library at once.
fn send_pin(
    reply: &Sender<Pin>,
    prompt: &KeyPrompt,
    ceremony: &Ceremony,
    again: bool,
    retries: Option<u8>,
    deadline: Instant,
) -> Option<AuthenticatorError> {
    match prompt.wait_pin(ceremony, again, retries, deadline) {
        PinAnswer::Pin(secret) => {
            let _ = reply.send(Pin::new(secret.expose()));
            None
        }
        PinAnswer::Cancelled => Some(AuthenticatorError::Cancelled),
        PinAnswer::TimedOut => Some(AuthenticatorError::Timeout),
    }
}

/// The library's error, worded generically (never its own text: it may
/// carry device paths or data).
fn map_error(e: &CtapError) -> AuthenticatorError {
    match e {
        CtapError::CancelledByUser => AuthenticatorError::Cancelled,
        // The library's own deadline.
        CtapError::U2FToken(U2FTokenError::NotAllowed) => AuthenticatorError::Timeout,
        CtapError::NoConfiguredTransports => failed(NO_ACCESS),
        CtapError::CredentialExcluded => failed(EXCLUDED),
        CtapError::PinError(p) => failed(match p {
            PinError::InvalidPin(_) | PinError::InvalidUv(_) | PinError::PinAuthInvalid => {
                WRONG_PIN
            }
            PinError::PinBlocked | PinError::UvBlocked => PIN_BLOCKED,
            PinError::PinAuthBlocked => PIN_AUTH_BLOCKED,
            PinError::PinNotSet => PIN_NOT_SET,
            PinError::PinIsTooShort | PinError::PinIsTooLong(_) => PIN_RULES,
            PinError::PinRequired | PinError::Crypto(_) => FAILURE,
        }),
        CtapError::UnsupportedOption(UnsupportedOption::UserVerification) => failed(NO_UV),
        CtapError::UnsupportedOption(_) => failed(UNSUPPORTED),
        CtapError::HIDError(HIDError::Command(CommandError::StatusCode(code, _))) => match code {
            StatusCode::NoCredentials | StatusCode::InvalidCredential => {
                AuthenticatorError::NoCredential
            }
            StatusCode::CredentialExcluded => failed(EXCLUDED),
            StatusCode::KeepaliveCancel | StatusCode::OperationDenied => {
                AuthenticatorError::Cancelled
            }
            StatusCode::UserActionTimeout | StatusCode::ActionTimeout => {
                AuthenticatorError::Timeout
            }
            StatusCode::PinInvalid | StatusCode::PinAuthInvalid => failed(WRONG_PIN),
            StatusCode::PinBlocked => failed(PIN_BLOCKED),
            StatusCode::PinAuthBlocked => failed(PIN_AUTH_BLOCKED),
            StatusCode::PinNotSet => failed(PIN_NOT_SET),
            StatusCode::PinPolicyViolation => failed(PIN_RULES),
            _ => failed(FAILURE),
        },
        _ => failed(FAILURE),
    }
}

// ── Answers ─────────────────────────────────────────────────────────────

/// An assertion as the client takes it. A key may leave the credential out
/// when the allow list named exactly one (CTAP 2.0): that one signed.
fn assertion_from(
    request: &AssertionRequest,
    answer: SignResult,
) -> Result<AuthenticatorAssertion, AuthenticatorError> {
    let a = answer.assertion;
    let credential_id = match (a.credentials, request.allow_credential_ids.as_slice()) {
        (Some(d), _) => d.id,
        (None, [only]) => only.clone(),
        (None, _) => return Err(failed(MALFORMED)),
    };
    let Ok(ciborium::Value::Bytes(authenticator_data)) = ciborium::Value::serialized(&a.auth_data)
    else {
        return Err(failed(MALFORMED));
    };
    Ok(AuthenticatorAssertion {
        credential_id,
        authenticator_data,
        signature: a.signature,
        user_handle: a.user.map(|u| u.id).unwrap_or_default(),
    })
}

/// A new credential as the client takes it: for this RP ID, with user
/// presence and verification, an algorithm the request asked for, and its
/// attestation reduced to `none`.
fn attestation_from(
    request: &CreationRequest,
    answer: RegisterResult,
) -> Result<AuthenticatorAttestation, AuthenticatorError> {
    let mut att = answer.att_obj;
    let data = &att.auth_data;
    let rp_hash: [u8; 32] = Sha256::digest(request.rp_id.as_bytes()).into();
    let flags = AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED;
    if data.rp_id_hash.0 != rp_hash || !data.flags.contains(flags) {
        return Err(failed(WRONG_SITE));
    }
    let credential = data
        .credential_data
        .as_ref()
        .ok_or_else(|| failed(MALFORMED))?;
    let asked = request
        .algorithms
        .iter()
        .any(|a| cose(*a) == Some(credential.credential_public_key.alg));
    if !asked {
        return Err(failed(WRONG_ALGORITHM));
    }
    let credential_id = credential.credential_id.clone();
    att.anonymize();
    let mut attestation_object = Vec::new();
    ciborium::into_writer(&att, &mut attestation_object).map_err(|_| failed(MALFORMED))?;
    Ok(AuthenticatorAttestation {
        credential_id,
        attestation_object,
        transports: vec!["usb".to_string()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use authenticator::crypto::{COSEEC2Key, COSEKey, COSEKeyType, Curve};
    use authenticator::ctap2::attestation::{
        AAGuid, AttestationObject, AttestationStatement, AttestedCredentialData, AuthenticatorData,
        Extension,
    };
    use authenticator::ctap2::server::{
        AuthenticationExtensionsClientOutputs, AuthenticatorAttachment, RpIdHash,
    };
    use authenticator::{Assertion, MakeCredentialsResult};
    use ferrogate_admin_client::webauthn::{
        attestation_into_proto, client_data_get, creation_request, into_proto, CreationOptions,
        MAX_ALLOW_CREDENTIALS, MAX_CREDENTIAL_ID_LEN, MAX_EXCLUDE_CREDENTIALS, MAX_NAME_LEN,
        MAX_USER_HANDLE_LEN, TIMEOUT_RANGE,
    };

    use crate::admin::secret::Secret;

    const RP: &str = "ferrogate-admin.ferrogate.test";
    const PIN: &str = "4711";

    /// An assertion request as `assertion_request` builds it.
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

    fn creation() -> CreationRequest {
        creation_request(&CreationOptions {
            challenge: vec![3; 32],
            rp_id: RP.into(),
            rp_name: "FerroGate".into(),
            user_id: vec![4; 32],
            user_name: "alice".into(),
            display_name: "Alice".into(),
            pub_key_cred_params: vec![-8, -7],
            exclude_credential_ids: vec![vec![1; 32]],
            user_verification: 1,
            attestation: 1,
        })
        .unwrap()
    }

    fn auth_data(rp_id: &str, flags: AuthenticatorDataFlags) -> AuthenticatorData {
        AuthenticatorData {
            rp_id_hash: RpIdHash(Sha256::digest(rp_id.as_bytes()).into()),
            flags,
            counter: 7,
            credential_data: None,
            extensions: Extension::default(),
        }
    }

    fn up_uv() -> AuthenticatorDataFlags {
        AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED
    }

    fn signed(credential: Option<Vec<u8>>) -> SignResult {
        SignResult {
            assertion: Assertion {
                credentials: credential.map(|id| PublicKeyCredentialDescriptor {
                    id,
                    transports: Vec::new(),
                }),
                auth_data: auth_data(RP, up_uv()),
                signature: vec![9; 70],
                user: None,
            },
            attachment: AuthenticatorAttachment::CrossPlatform,
            extensions: AuthenticationExtensionsClientOutputs::default(),
        }
    }

    fn registered(
        rp_id: &str,
        flags: AuthenticatorDataFlags,
        alg: COSEAlgorithm,
    ) -> RegisterResult {
        let mut data = auth_data(rp_id, flags | AuthenticatorDataFlags::ATTESTED);
        data.credential_data = Some(AttestedCredentialData {
            aaguid: AAGuid([0xaa; 16]),
            credential_id: vec![2; 32],
            credential_public_key: COSEKey {
                alg,
                key: COSEKeyType::EC2(COSEEC2Key {
                    curve: Curve::SECP256R1,
                    x: vec![1; 32],
                    y: vec![2; 32],
                }),
            },
        });
        MakeCredentialsResult {
            att_obj: AttestationObject {
                auth_data: data,
                att_stmt: AttestationStatement::None,
            },
            attachment: AuthenticatorAttachment::CrossPlatform,
            extensions: AuthenticationExtensionsClientOutputs::default(),
        }
    }

    /// What the fake key does once a ceremony starts.
    #[derive(Clone, Copy)]
    enum Script {
        /// Ask for a touch, then for the PIN; a wrong first PIN is asked
        /// again with 2 retries left; answer when the PIN is right.
        Pin,
        /// Ask for the PIN and never answer (the test cancels or times out).
        PinForever,
        /// Fail at once with this library error.
        Fail(fn() -> CtapError),
    }

    /// A key behind the `Ctap` seam, run on its own thread like the library.
    struct FakeKey {
        script: Script,
        /// PINs the key received.
        pins: Arc<Mutex<Vec<String>>>,
        cancels: Arc<AtomicUsize>,
    }

    impl FakeKey {
        fn run<T: Send + 'static>(
            &self,
            status: Sender<StatusUpdate>,
            done: StateCallback<authenticator::Result<T>>,
            answer: impl FnOnce() -> T + Send + 'static,
        ) {
            let script = self.script;
            let pins = Arc::clone(&self.pins);
            std::thread::spawn(move || match script {
                Script::Fail(e) => done.call(Err(e())),
                Script::Pin | Script::PinForever => {
                    let _ = status.send(StatusUpdate::PresenceRequired);
                    let mut again = false;
                    loop {
                        let (tx, rx) = mpsc::channel();
                        let ask = if again {
                            StatusPinUv::InvalidPin(tx, Some(2))
                        } else {
                            StatusPinUv::PinRequired(tx)
                        };
                        let _ = status.send(StatusUpdate::PinUvError(ask));
                        // A dropped sender means the client gave up.
                        let Ok(pin) = rx.recv() else {
                            done.call(Err(CtapError::CancelledByUser));
                            return;
                        };
                        let typed = String::from_utf8_lossy(pin.as_bytes()).into_owned();
                        let right = typed == PIN && matches!(script, Script::Pin);
                        pins.lock().unwrap().push(typed);
                        if right {
                            done.call(Ok(answer()));
                            return;
                        }
                        again = true;
                    }
                }
            });
        }
    }

    impl Ctap for FakeKey {
        fn sign(
            &mut self,
            _: u64,
            args: SignArgs,
            status: Sender<StatusUpdate>,
            done: StateCallback<authenticator::Result<SignResult>>,
        ) -> authenticator::Result<()> {
            assert_eq!(
                args.user_verification_req,
                UserVerificationRequirement::Required
            );
            self.run(status, done, || signed(Some(vec![1; 32])));
            Ok(())
        }

        fn register(
            &mut self,
            _: u64,
            _: RegisterArgs,
            status: Sender<StatusUpdate>,
            done: StateCallback<authenticator::Result<RegisterResult>>,
        ) -> authenticator::Result<()> {
            self.run(status, done, || {
                registered(RP, up_uv(), COSEAlgorithm::ES256)
            });
            Ok(())
        }

        fn cancel(&mut self) {
            self.cancels.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Rig {
        key: Arc<HidKey>,
        prompt: Arc<KeyPrompt>,
        opened: Arc<AtomicUsize>,
        pins: Arc<Mutex<Vec<String>>>,
        cancels: Arc<AtomicUsize>,
    }

    fn rig(script: Script) -> Rig {
        let prompt = KeyPrompt::new();
        let opened = Arc::new(AtomicUsize::new(0));
        let pins = Arc::new(Mutex::new(Vec::new()));
        let cancels = Arc::new(AtomicUsize::new(0));
        let (o, p, c) = (Arc::clone(&opened), Arc::clone(&pins), Arc::clone(&cancels));
        let open: Open = Box::new(move || {
            o.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeKey {
                script,
                pins: Arc::clone(&p),
                cancels: Arc::clone(&c),
            }) as Box<dyn Ctap>)
        });
        Rig {
            key: Arc::new(HidKey::with(Arc::clone(&prompt), open)),
            prompt,
            opened,
            pins,
            cancels,
        }
    }

    fn pin(text: &str) -> Secret {
        let mut s = Secret::new();
        s.push_str(text);
        s
    }

    /// Wait until the key asks for `ask`.
    fn until(prompt: &KeyPrompt, ask: KeyAsk) {
        for _ in 0..1000 {
            if prompt.asking() == Some(ask) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the key never asked for {ask:?}");
    }

    #[test]
    fn requests_outside_the_bounds_are_refused_before_any_key_is_opened() {
        type EditA = fn(&mut AssertionRequest);
        type EditC = fn(&mut CreationRequest);
        let r = rig(Script::Pin);
        r.prompt.arm();
        let assertions: Vec<(&str, EditA)> = vec![
            ("foreign rp", |q| {
                q.rp_id = "accounts.example.com".into();
                q.origin = "https://accounts.example.com".into();
            }),
            ("other origin", |q| q.origin = "https://evil.test".into()),
            ("other client data", |q| q.client_data_json.push(b' ')),
            ("no uv", |q| q.user_verification_required = false),
            ("long allow list", |q| {
                q.allow_credential_ids = vec![vec![1; 4]; MAX_ALLOW_CREDENTIALS + 1];
            }),
            ("empty id", |q| q.allow_credential_ids = vec![Vec::new()]),
            ("long id", |q| {
                q.allow_credential_ids = vec![vec![1; MAX_CREDENTIAL_ID_LEN + 1]];
            }),
            ("long timeout", |q| q.timeout = TIMEOUT_RANGE.1 * 2),
        ];
        for (what, edit) in assertions {
            let mut q = request();
            edit(&mut q);
            assert!(
                matches!(r.key.get_assertion(&q), Err(AuthenticatorError::BadRequest)),
                "{what}"
            );
        }
        let creations: Vec<(&str, EditC)> = vec![
            ("edited rp", |q| {
                q.rp_id = "ferrogate-admin.elsewhere.test".into();
            }),
            ("no uv", |q| q.user_verification_required = false),
            ("long user handle", |q| {
                q.user_id = vec![1; MAX_USER_HANDLE_LEN + 1];
            }),
            ("long name", |q| {
                q.display_name = "x".repeat(MAX_NAME_LEN + 1);
            }),
            ("rs256", |q| q.algorithms = vec![-257]),
            ("long exclude list", |q| {
                q.exclude_credential_ids = vec![vec![1; 4]; MAX_EXCLUDE_CREDENTIALS + 1];
            }),
        ];
        for (what, edit) in creations {
            let mut q = creation();
            edit(&mut q);
            assert!(
                matches!(
                    r.key.make_credential(&q),
                    Err(AuthenticatorError::BadRequest)
                ),
                "{what}"
            );
        }
        assert_eq!(r.opened.load(Ordering::SeqCst), 0, "no key was opened");
    }

    #[test]
    fn requests_become_library_arguments_that_always_require_verification() {
        let q = request();
        let s = sign_args(&q);
        assert_eq!(
            (s.relying_party_id.as_str(), s.origin.as_str()),
            (RP, format!("https://{RP}").as_str())
        );
        assert_eq!(s.client_data_hash, q.client_data_hash);
        assert_eq!(s.allow_list.len(), 1);
        assert_eq!(s.allow_list[0].id, vec![1; 32]);
        assert_eq!(
            s.user_verification_req,
            UserVerificationRequirement::Required
        );
        assert!(s.user_presence_req && s.pin.is_none() && !s.use_ctap1_fallback);

        let c = creation();
        let a = register_args(&c).unwrap();
        assert_eq!(a.relying_party.id, RP);
        assert_eq!(a.relying_party.name.as_deref(), Some("FerroGate"));
        assert_eq!(a.user.id, vec![4; 32]);
        assert_eq!(a.user.name.as_deref(), Some("alice"));
        assert_eq!(a.user.display_name.as_deref(), Some("Alice"));
        let algs: Vec<COSEAlgorithm> = a.pub_cred_params.iter().map(|p| p.alg).collect();
        assert_eq!(
            algs,
            vec![COSEAlgorithm::EDDSA, COSEAlgorithm::ES256],
            "server order"
        );
        assert_eq!(a.exclude_list.len(), 1);
        assert_eq!(
            a.user_verification_req,
            UserVerificationRequirement::Required
        );
        assert_eq!(a.resident_key_req, ResidentKeyRequirement::Discouraged);
        assert!(a.pin.is_none() && !a.use_ctap1_fallback);
    }

    #[test]
    fn a_pin_typed_in_the_window_reaches_the_key_and_a_wrong_one_is_asked_again() {
        let r = rig(Script::Pin);
        r.prompt.arm();
        let key = Arc::clone(&r.key);
        let q = request();
        let asked = q.clone();
        let call = std::thread::spawn(move || key.get_assertion(&asked));
        until(
            &r.prompt,
            KeyAsk::Pin {
                again: false,
                retries: None,
            },
        );
        assert!(r.prompt.answer(pin("0000")));
        until(
            &r.prompt,
            KeyAsk::Pin {
                again: true,
                retries: Some(2),
            },
        );
        assert!(r.prompt.answer(pin(PIN)));
        let answer = call.join().unwrap().expect("signed");
        assert_eq!(
            *r.pins.lock().unwrap(),
            vec!["0000".to_string(), PIN.into()]
        );
        assert_eq!(r.prompt.asking(), None, "nothing left on screen");
        // The client's own checks accept the translated answer.
        let proto = into_proto(&q, answer).expect("for this RP, with UP and UV");
        assert_eq!(proto.credential_id, vec![1; 32]);
        assert_eq!(
            &proto.authenticator_data[..32],
            &Sha256::digest(RP.as_bytes())[..]
        );
    }

    #[test]
    fn a_cancel_from_the_window_stops_the_key_and_answers_cancelled() {
        let r = rig(Script::PinForever);
        r.prompt.arm();
        let key = Arc::clone(&r.key);
        let call = std::thread::spawn(move || key.get_assertion(&request()));
        until(
            &r.prompt,
            KeyAsk::Pin {
                again: false,
                retries: None,
            },
        );
        r.prompt.cancel();
        assert!(matches!(
            call.join().unwrap(),
            Err(AuthenticatorError::Cancelled)
        ));
        assert_eq!(r.cancels.load(Ordering::SeqCst), 1, "the key was told");
        assert!(r.pins.lock().unwrap().is_empty(), "no PIN reached the key");
        assert_eq!(r.prompt.asking(), None);
    }

    #[test]
    fn without_an_armed_prompt_no_key_is_opened() {
        let r = rig(Script::Pin);
        assert!(matches!(
            r.key.get_assertion(&request()),
            Err(AuthenticatorError::Cancelled)
        ));
        r.prompt.arm();
        r.prompt.cancel();
        assert!(matches!(
            r.key.make_credential(&creation()),
            Err(AuthenticatorError::Cancelled)
        ));
        assert_eq!(r.opened.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_deadline_ends_a_ceremony_nobody_answers() {
        let prompt = KeyPrompt::new();
        prompt.arm();
        let ceremony = prompt.begin().unwrap();
        let cancels = Arc::new(AtomicUsize::new(0));
        let mut key = FakeKey {
            script: Script::PinForever,
            pins: Arc::new(Mutex::new(Vec::new())),
            cancels: Arc::clone(&cancels),
        };
        let started = Instant::now();
        let r = drive(
            &mut key,
            &prompt,
            &ceremony,
            Duration::from_millis(150),
            |c, ms, status, done| c.sign(ms, sign_args(&request()), status, done),
        );
        assert!(matches!(r, Err(AuthenticatorError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(cancels.load(Ordering::SeqCst), 1);
        assert_eq!(
            prompt.asking(),
            None,
            "the PIN prompt went with the deadline"
        );
    }

    #[test]
    fn library_errors_are_worded_generically() {
        let cases: Vec<(CtapError, AuthenticatorError)> = vec![
            (CtapError::CancelledByUser, AuthenticatorError::Cancelled),
            (
                CtapError::U2FToken(U2FTokenError::NotAllowed),
                AuthenticatorError::Timeout,
            ),
            (
                CtapError::HIDError(HIDError::Command(CommandError::StatusCode(
                    StatusCode::NoCredentials,
                    None,
                ))),
                AuthenticatorError::NoCredential,
            ),
            (CtapError::CredentialExcluded, failed(EXCLUDED)),
            (
                CtapError::PinError(PinError::InvalidPin(Some(1))),
                failed(WRONG_PIN),
            ),
            (
                CtapError::PinError(PinError::PinBlocked),
                failed(PIN_BLOCKED),
            ),
            (
                CtapError::PinError(PinError::PinNotSet),
                failed(PIN_NOT_SET),
            ),
            (
                CtapError::UnsupportedOption(UnsupportedOption::UserVerification),
                failed(NO_UV),
            ),
        ];
        for (e, want) in cases {
            assert_eq!(map_error(&e), want);
        }
        // Library text never comes through: it may carry paths or data.
        for e in [
            CtapError::Custom("cred 0xdeadbeef /dev/hidraw3".into()),
            CtapError::InternalError("pin_hash = 0x1234".into()),
            CtapError::Io(std::io::Error::other("/dev/hidraw3")),
        ] {
            let shown = map_error(&e).to_string();
            assert_eq!(shown, format!("security key failure: {FAILURE}"));
        }
    }

    #[test]
    fn an_assertion_without_a_credential_id_is_the_only_one_allowed() {
        let q = request();
        let a = assertion_from(&q, signed(None)).expect("one credential allowed");
        assert_eq!(a.credential_id, vec![1; 32]);
        let mut two = request();
        two.allow_credential_ids.push(vec![2; 32]);
        assert!(assertion_from(&two, signed(None)).is_err());
        // An oversized answer is refused by the client's checks.
        let mut big = assertion_from(&q, signed(Some(vec![1; 32]))).unwrap();
        big.signature = vec![0; 5000];
        assert!(into_proto(&q, big).is_err());
    }

    #[test]
    fn a_new_credential_leaves_with_none_attestation_for_this_site_only() {
        let c = creation();
        let a = attestation_from(&c, registered(RP, up_uv(), COSEAlgorithm::ES256)).unwrap();
        assert_eq!(a.credential_id, vec![2; 32]);
        assert_eq!(a.transports, vec!["usb".to_string()]);
        let doc: ciborium::Value = ciborium::from_reader(a.attestation_object.as_slice()).unwrap();
        let map = doc.into_map().unwrap();
        let get = |k: &str| {
            map.iter()
                .find(|(key, _)| key.as_text() == Some(k))
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(get("fmt").as_text(), Some("none"));
        assert_eq!(
            get("attStmt").into_map().unwrap().len(),
            0,
            "statement dropped"
        );
        let auth = get("authData").into_bytes().unwrap();
        assert_eq!(&auth[..32], &Sha256::digest(RP.as_bytes())[..]);
        assert_eq!(&auth[37..53], &[0; 16], "AAGUID zeroed");
        // The client's checks accept it.
        assert!(attestation_into_proto(&c, a, "Desk key").is_ok());

        let refused = [
            registered(
                "ferrogate-admin.elsewhere.test",
                up_uv(),
                COSEAlgorithm::ES256,
            ),
            registered(
                RP,
                AuthenticatorDataFlags::USER_PRESENT,
                COSEAlgorithm::ES256,
            ),
            registered(RP, up_uv(), COSEAlgorithm::RS256),
        ];
        for answer in refused {
            assert!(attestation_from(&c, answer).is_err());
        }
    }

    #[test]
    fn a_registration_runs_through_the_same_pin_prompt() {
        let r = rig(Script::Pin);
        r.prompt.arm();
        let key = Arc::clone(&r.key);
        let call = std::thread::spawn(move || key.make_credential(&creation()));
        until(
            &r.prompt,
            KeyAsk::Pin {
                again: false,
                retries: None,
            },
        );
        assert!(r.prompt.answer(pin(PIN)));
        let made = call.join().unwrap().expect("registered");
        assert_eq!(made.credential_id, vec![2; 32]);
    }

    #[test]
    fn a_library_failure_ends_the_ceremony_with_its_generic_error() {
        let r = rig(Script::Fail(|| CtapError::PinError(PinError::PinBlocked)));
        r.prompt.arm();
        assert_eq!(
            r.key.get_assertion(&request()).err(),
            Some(failed(PIN_BLOCKED))
        );
        assert_eq!(r.prompt.asking(), None);
    }
}
