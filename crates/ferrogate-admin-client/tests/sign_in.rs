//! `ferrogate-admin-client` end to end: sign-in and step-up as the tray
//! (client kind 2) over the pinned hybrid-PQC TLS admin listener of an
//! in-process CMIS (the harness of `crates/cmis/tests/support`, by path), with
//! a TOTP code and with that harness's software FIDO2 authenticator behind
//! the [`Authenticator`] trait. The server verifies every signature.

#![allow(clippy::large_futures, clippy::missing_panics_doc)]

#[path = "../../cmis/tests/support/mod.rs"]
mod support;

use std::sync::{Arc, Mutex};

use ferro_audit::AuditEvent;
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferrogate_admin_client::client::{AdminSession, ClientConfig, Factor, Methods};
use ferrogate_admin_client::error::ClientError;
use ferrogate_admin_client::secret::Secret;
use ferrogate_admin_client::session::SessionHandle;
use ferrogate_admin_client::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};
use ferrogate_admin_client::webauthn::{
    AssertionRequest, Authenticator, AuthenticatorAssertion, AuthenticatorError,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use support::soft_authenticator::{SoftAuthenticator, UP, UV};
use support::{Admin1, Harness};
use tokio::net::TcpListener;

const APPROVERS: &str = "ferrogate-approvers";

/// The harness's software key behind the client's trait: it signs the
/// `clientDataJSON` hash the client built, as a CTAP2 device would.
struct SoftKey {
    key: Mutex<SoftAuthenticator>,
    /// Runs inside the "prompt" (to lock the client meanwhile).
    during: Option<Box<dyn Fn() + Send + Sync>>,
    /// Answer with this error instead (a cancelled prompt).
    fail: Option<AuthenticatorError>,
}

impl SoftKey {
    fn new(key: SoftAuthenticator) -> Arc<Self> {
        Arc::new(Self {
            key: Mutex::new(key),
            during: None,
            fail: None,
        })
    }
}

impl Authenticator for SoftKey {
    fn get_assertion(
        &self,
        req: &AssertionRequest,
    ) -> Result<AuthenticatorAssertion, AuthenticatorError> {
        if let Some(f) = &self.during {
            f();
        }
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        let mut k = self.key.lock().unwrap();
        if !req.allow_credential_ids.is_empty()
            && !req.allow_credential_ids.contains(&k.credential_id)
        {
            return Err(AuthenticatorError::NoCredential);
        }
        if k.counter != 0 {
            k.counter += 1;
        }
        let authenticator_data = k.auth_data(&req.rp_id, UP | UV, k.counter, false);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&req.client_data_hash);
        Ok(AuthenticatorAssertion {
            credential_id: k.credential_id.clone(),
            signature: k.sign(&signed),
            authenticator_data,
            user_handle: Vec::new(),
        })
    }
}

/// An in-process CMIS behind a real TLS admin listener.
struct Server {
    h: Harness,
    endpoint: String,
    pin: SpkiPin,
    root: Admin1,
    root_token: String,
}

async fn server(tag: &str, fido2_groups: &[&str]) -> Server {
    let groups: Vec<String> = fido2_groups.iter().map(|g| (*g).to_string()).collect();
    let h = support::harness_with(tag, |c| c.tray_fido2_groups = groups).await;
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .unwrap();
    let pin = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
    let tls = ferro_crypto::transport::server_config(
        ProviderMode::HybridOnly,
        vec![ck.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(cmis::server::serve_admin(
        listener,
        tls,
        Arc::clone(&h.cmis),
        Arc::clone(&h.authz),
    ));
    let root = support::bootstrap(&h, "root-admin").await;
    let root_token = h.login(&root).await;
    Server {
        h,
        endpoint: format!("https://{addr}"),
        pin,
        root,
        root_token,
    }
}

impl Server {
    fn session(&self, pin: SpkiPin) -> AdminSession {
        AdminSession::new(ClientConfig {
            endpoint: self.endpoint.clone(),
            pins: vec![pin],
            device_token_path: None,
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
            client_kind: ferrogate_admin_client::client_kind::TRAY,
        })
    }

    async fn key_holder(&self, name: &str, groups: &[&str], key: &SoftAuthenticator) -> Admin1 {
        self.h
            .create_and_enroll_key(&self.root, &self.root_token, name, groups, key, true)
            .await
    }

    fn count(&self, want: impl Fn(&AuditEvent) -> bool) -> usize {
        self.h.audit_events().iter().filter(|e| want(e)).count()
    }

    fn failed_logins(&self) -> usize {
        self.count(|e| matches!(e, AuditEvent::AdminLoginFailed { .. }))
    }
}

fn secret(text: &str) -> Secret {
    let mut s = Secret::new();
    s.push_str(text);
    s
}

fn totp(s: &Server, who: &Admin1) -> Factor {
    Factor::Totp(secret(&s.h.fresh_code(who)))
}

#[tokio::test]
async fn a_tray_signs_in_and_steps_up_with_a_totp_code() {
    let s = server("ac-totp", &[]).await;
    let mut c = s.session(s.pin);
    // The root account holds TOTP only: no key is offered.
    let offered = c.offer(&s.root.username).await.unwrap();
    assert_eq!(
        offered,
        Methods {
            totp: true,
            security_key: false
        }
    );
    let info = c
        .sign_in(
            &s.root.username,
            secret(support::PASSWORD),
            totp(&s, &s.root),
        )
        .await
        .unwrap();
    assert_eq!(info.aal, 2);
    assert_eq!(info.admin_id, s.root.admin_id);
    assert!(info.idle_timeout_secs > 0);
    assert!(!info.password_change_required && !info.factor_enrollment_required);
    assert!(c.has_session());
    assert_eq!(c.who_am_i().await.unwrap().admin_id, s.root.admin_id);
    let tray_logins = s.count(|e| {
        matches!(e, AuditEvent::AdminLoginSucceeded { client_kind: 2, mfa_method, .. } if mfa_method == "totp")
    });
    assert_eq!(tray_logins, 1);

    // Step-up rotates the token; the session keeps working on the new one.
    let until = c.step_up(totp(&s, &s.root)).await.unwrap();
    assert!(until > s.h.clock_now());
    assert!(c.who_am_i().await.unwrap().mfa_at > 0);
    // A stale code (already used) is refused generically, the session stays.
    let reused = Factor::Totp(secret(&support::code(&s.root.secret, s.h.clock_now())));
    assert_eq!(c.step_up(reused).await, Err(ClientError::Rejected));
    assert!(c.has_session());

    // Logout ends it server-side.
    c.logout().await;
    assert!(!c.has_session());
    assert_eq!(c.who_am_i().await.unwrap_err(), ClientError::SessionEnded);
    assert_eq!(s.count(|e| matches!(e, AuditEvent::AdminLogout { .. })), 1);
}

#[tokio::test]
async fn a_tray_signs_in_and_steps_up_with_a_security_key() {
    let s = server("ac-key", &[]).await;
    let soft = SoftAuthenticator::es256(7);
    let who = s.key_holder("key.holder", &[APPROVERS], &soft).await;
    let key = SoftKey::new(soft);
    let mut c = s.session(s.pin);
    let offered = c.offer(&who.username).await.unwrap();
    assert!(offered.totp && offered.security_key);
    let info = c
        .sign_in(
            &who.username,
            secret(support::PASSWORD),
            Factor::SecurityKey(key.clone()),
        )
        .await
        .unwrap();
    assert_eq!(info.aal, 3, "a device-bound key is AAL3");
    let key_logins = s.count(|e| {
        matches!(e, AuditEvent::AdminLoginSucceeded { client_kind: 2, mfa_method, .. } if mfa_method == "webauthn")
    });
    assert_eq!(key_logins, 1);
    let until = c.step_up(Factor::SecurityKey(key.clone())).await.unwrap();
    assert!(until > s.h.clock_now());
    let steps = s.count(|e| {
        matches!(e, AuditEvent::AdminStepUp { mfa_method, success: true, .. } if mfa_method == "webauthn")
    });
    assert_eq!(steps, 1);
    // The same account may still step up with its TOTP code.
    assert!(c.step_up(totp(&s, &who)).await.is_ok());
    c.logout().await;
}

#[tokio::test]
async fn the_fido2_policy_offers_only_the_key_and_a_code_is_never_sent() {
    let s = server("ac-policy", &[APPROVERS]).await;
    let soft = SoftAuthenticator::ed25519(9);
    let who = s.key_holder("approver.one", &[APPROVERS], &soft).await;
    let key = SoftKey::new(soft);
    let mut c = s.session(s.pin);
    let offered = c.offer(&who.username).await.unwrap();
    assert_eq!(
        offered,
        Methods {
            totp: false,
            security_key: true
        }
    );
    let before = s.failed_logins();
    let r = c
        .sign_in(&who.username, secret(support::PASSWORD), totp(&s, &who))
        .await;
    assert_eq!(r, Err(ClientError::FactorNotOffered));
    assert_eq!(s.failed_logins(), before, "no Login was sent");
    let info = c
        .sign_in(
            &who.username,
            secret(support::PASSWORD),
            Factor::SecurityKey(key.clone()),
        )
        .await
        .unwrap();
    assert_eq!(info.methods, offered);
    assert!(!info.factor_enrollment_required);
    // Step-up under the policy takes the key only.
    assert!(c.step_up(Factor::SecurityKey(key)).await.is_ok());
    c.logout().await;
}

#[tokio::test]
async fn failures_are_generic_and_a_cancelled_key_sends_nothing() {
    let s = server("ac-fail", &[]).await;
    let soft = SoftAuthenticator::es256(11);
    let who = s.key_holder("key.two", &[APPROVERS], &soft).await;
    let mut c = s.session(s.pin);
    let before = s.failed_logins();
    let cancelled = Arc::new(SoftKey {
        key: Mutex::new(SoftAuthenticator::es256(11)),
        during: None,
        fail: Some(AuthenticatorError::Cancelled),
    });
    let r = c
        .sign_in(
            &who.username,
            secret(support::PASSWORD),
            Factor::SecurityKey(cancelled),
        )
        .await;
    assert_eq!(
        r,
        Err(ClientError::Authenticator(AuthenticatorError::Cancelled))
    );
    assert_eq!(
        s.failed_logins(),
        before,
        "a cancelled prompt sends no Login"
    );
    // A wrong password with a valid code: the same generic rejection.
    let r = c
        .sign_in(&who.username, secret("Wrong-Password-123!"), totp(&s, &who))
        .await;
    assert_eq!(r, Err(ClientError::Rejected));
    // An unknown account's key: the decoy challenge allows no real key.
    let stranger = SoftKey::new(SoftAuthenticator::es256(12));
    let r = c
        .sign_in(
            "nobody.here",
            secret(support::PASSWORD),
            Factor::SecurityKey(stranger),
        )
        .await;
    assert!(
        matches!(
            r,
            Err(ClientError::Authenticator(AuthenticatorError::NoCredential)
                | ClientError::Rejected
                | ClientError::FactorNotOffered)
        ),
        "{r:?}"
    );
    assert!(!c.has_session());
}

#[tokio::test]
async fn a_wrong_pin_is_refused_before_any_credential_is_sent() {
    let s = server("ac-pin", &[]).await;
    let ck = rcgen::generate_simple_self_signed(vec!["elsewhere.invalid".to_string()]).unwrap();
    let wrong = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
    let mut c = s.session(wrong);
    let before = s.count(|_| true);
    let r = c
        .sign_in(
            &s.root.username,
            secret(support::PASSWORD),
            totp(&s, &s.root),
        )
        .await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{r:?}");
    assert_eq!(s.count(|_| true), before, "the server saw no request");
}

impl Server {
    fn logins(&self) -> usize {
        self.count(|e| {
            matches!(
                e,
                AuditEvent::AdminLoginSucceeded { .. } | AuditEvent::AdminLoginFailed { .. }
            )
        })
    }

    fn logouts(&self) -> usize {
        self.count(|e| matches!(e, AuditEvent::AdminLogout { .. }))
    }

    fn step_ups(&self) -> usize {
        self.count(|e| matches!(e, AuditEvent::AdminStepUp { .. }))
    }
}

/// `soft` behind the trait, locking the client through `handle` while the
/// administrator touches it.
fn locking_key(soft: SoftAuthenticator, handle: &Arc<SessionHandle>) -> Arc<SoftKey> {
    let locker = Arc::clone(handle);
    Arc::new(SoftKey {
        key: Mutex::new(soft),
        during: Some(Box::new(move || locker.end())),
        fail: None,
    })
}

#[tokio::test]
async fn a_lock_during_the_key_prompt_sends_no_login() {
    let s = server("ac-lock", &[]).await;
    let soft = SoftAuthenticator::es256(13);
    let who = s.key_holder("key.three", &[APPROVERS], &soft).await;
    let mut c = s.session(s.pin);
    let (logout_tx, mut logout_rx) = tokio::sync::mpsc::unbounded_channel();
    let handle: Arc<SessionHandle> = Arc::new(c.session_handle(logout_tx));
    let key = locking_key(soft, &handle);
    let (logins, logouts) = (s.logins(), s.logouts());
    let r = c
        .sign_in(
            &who.username,
            secret(support::PASSWORD),
            Factor::SecurityKey(key),
        )
        .await;
    assert_eq!(r, Err(ClientError::SessionEnded));
    assert!(!c.has_session());
    // The assertion is dropped: the server sees neither a sign-in nor the
    // logout of a session nobody asked for any more.
    assert_eq!(s.logins(), logins, "no Login after the lock");
    assert_eq!(s.logouts(), logouts, "no session, so no Logout");
    // The handle's own end carried no token (nothing was held then).
    assert!(!logout_rx.try_recv().unwrap().is_set());
}

#[tokio::test]
async fn a_lock_during_the_step_up_key_prompt_sends_no_step_up() {
    let s = server("ac-lock-up", &[]).await;
    let soft = SoftAuthenticator::es256(14);
    let who = s.key_holder("key.four", &[APPROVERS], &soft).await;
    let mut c = s.session(s.pin);
    c.sign_in(&who.username, secret(support::PASSWORD), totp(&s, &who))
        .await
        .unwrap();
    let (logout_tx, mut logout_rx) = tokio::sync::mpsc::unbounded_channel();
    let handle: Arc<SessionHandle> = Arc::new(c.session_handle(logout_tx));
    let key = locking_key(soft, &handle);
    let (step_ups, logouts) = (s.step_ups(), s.logouts());
    let r = c.step_up(Factor::SecurityKey(key)).await;
    assert_eq!(r, Err(ClientError::SessionEnded));
    assert!(!c.has_session());
    assert_eq!(s.step_ups(), step_ups, "no StepUp after the lock");
    assert_eq!(s.logouts(), logouts, "no rotated session to log out");
    // The lock took the live token (its Logout is the handle's to send).
    assert!(logout_rx.try_recv().unwrap().is_set());
}
