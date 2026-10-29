//! `ferrogate-admin-client` end to end for second-factor enrollment and
//! management (F20 §5, F22 §3a), as the tray (client kind 2) over the pinned
//! admin listener of an in-process CMIS: token enrollment with a TOTP seed
//! and/or a security key, `ListMyFactors`, adding a key or TOTP with a
//! per-operation proof of a factor already held, removing a factor (never
//! the last), and the FIDO2 policy's key-registration-only session.

#![allow(clippy::large_futures, clippy::missing_panics_doc)]

#[path = "../../cmis/tests/support/mod.rs"]
mod support;

mod common;

use std::sync::{Arc, Mutex};

use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::admin_server::Admin as _;
use ferro_proto::admin_v1::CreateAdminAccountRequest;
use ferrogate_admin_client::client::{Factor, Methods};
use ferrogate_admin_client::error::ClientError;
use ferrogate_admin_client::factors::{register_key, AddOffer, FactorMethod};
use ferrogate_admin_client::session::SessionHandle;
use support::soft_authenticator::SoftAuthenticator;

use common::{secret, server, totp, Server, SoftKey, APPROVERS};

impl Server {
    /// Create an account in `groups` (as root); its enrollment token.
    async fn create_account(&self, username: &str, groups: &[&str]) -> String {
        self.h
            .call(
                &self.root_token,
                cmis::admin::authz::paths::CREATE_ADMIN_ACCOUNT,
                CreateAdminAccountRequest {
                    idempotency_key: String::new(),
                    username: username.into(),
                    display_name: "New Person".into(),
                    groups: groups.iter().map(|g| (*g).to_string()).collect(),
                    proof: self.h.proof(&self.root),
                    enrollment_ttl_secs: 0,
                },
                |svc, req| Box::pin(async move { svc.create_admin_account(req).await }),
            )
            .await
            .unwrap()
            .enrollment_token
    }

    fn enrolled(&self, method: &str) -> usize {
        self.count(|e| matches!(e, AuditEvent::AdminMfaEnrolled { method: m, .. } if m == method))
    }

    fn removed(&self) -> usize {
        self.count(|e| matches!(e, AuditEvent::AdminMfaRemoved { .. }))
    }
}

#[tokio::test]
async fn a_new_account_enrolls_a_key_and_totp_from_the_tray() {
    let s = server("fa-enroll", &[]).await;
    let token = s.create_account("new.person", &[APPROVERS]).await;
    let mut c = s.session(s.pin);
    let offer = c.begin_enrollment(&secret(&token)).await.unwrap();
    assert_eq!(offer.username, "new.person");
    assert!(!offer.username_choosable);
    assert_eq!(offer.password_min_len, 24);
    let seed = offer.totp.as_ref().expect("a TOTP seed for a new account");
    let request = offer
        .key
        .as_ref()
        .expect("creation options for a new account");
    assert!(request.user_verification_required);

    // The key registers over the client's own clientDataJSON.
    let soft = SoftAuthenticator::es256(24);
    let key = SoftKey::new(SoftAuthenticator::es256(24));
    let attestation = register_key(key.clone(), request, "Desk key")
        .await
        .unwrap();
    assert_eq!(attestation.label, "Desk key");

    // The password policy is checked first, and says so.
    let r = c
        .complete_enrollment(&secret(&token), secret("short"), None, None)
        .await;
    assert!(
        matches!(&r, Err(ClientError::Other(e)) if e.reason == "password_policy"),
        "{r:?}"
    );
    // At least one factor: none is refused, generically.
    let r = c
        .complete_enrollment(&secret(&token), secret(support::PASSWORD), None, None)
        .await;
    assert_eq!(r, Err(ClientError::Rejected));

    s.h.next_step();
    let raw = support::secret_from_uri(seed.uri());
    let code = support::code(&raw, s.h.clock_now());
    assert_eq!(seed.secret_base32().len(), 32, "a 160-bit seed");
    let admin_id = c
        .complete_enrollment(
            &secret(&token),
            secret(support::PASSWORD),
            Some(secret(&code)),
            Some(attestation),
        )
        .await
        .unwrap();
    assert_ne!(admin_id, "");
    assert_eq!((s.enrolled("totp"), s.enrolled("webauthn")), (1, 1));
    // The token is spent.
    assert_eq!(
        c.begin_enrollment(&secret(&token)).await.err(),
        Some(ClientError::Rejected)
    );

    // Either factor signs in; the account lists both.
    let info = c
        .sign_in(
            "new.person",
            secret(support::PASSWORD),
            Factor::SecurityKey(SoftKey::new(soft)),
        )
        .await
        .unwrap();
    assert_eq!(info.aal, 3);
    let factors = c.list_factors().await.unwrap();
    let methods: Vec<FactorMethod> = factors.iter().map(|f| f.method).collect();
    assert_eq!(methods, vec![FactorMethod::Totp, FactorMethod::SecurityKey]);
    assert_eq!(factors[1].label, "Desk key");
    assert!(factors[1].factor_id.starts_with("wa_"));
    c.logout().await;
}

#[tokio::test]
async fn a_key_only_enrollment_and_a_totp_only_enrollment_both_work() {
    let s = server("fa-enroll-one", &[]).await;
    // Key only.
    let token = s.create_account("key.person", &[APPROVERS]).await;
    let mut c = s.session(s.pin);
    let offer = c.begin_enrollment(&secret(&token)).await.unwrap();
    let key = SoftKey::new(SoftAuthenticator::ed25519(25));
    let att = register_key(key.clone(), offer.key.as_ref().unwrap(), "")
        .await
        .unwrap();
    c.complete_enrollment(&secret(&token), secret(support::PASSWORD), None, Some(att))
        .await
        .unwrap();
    let offered = c.offer("key.person").await.unwrap();
    assert_eq!(
        offered,
        Methods {
            totp: false,
            security_key: true
        }
    );
    // TOTP only.
    let token = s.create_account("code.person", &[APPROVERS]).await;
    let offer = c.begin_enrollment(&secret(&token)).await.unwrap();
    s.h.next_step();
    let raw = support::secret_from_uri(offer.totp.as_ref().unwrap().uri());
    let code = support::code(&raw, s.h.clock_now());
    c.complete_enrollment(
        &secret(&token),
        secret(support::PASSWORD),
        Some(secret(&code)),
        None,
    )
    .await
    .unwrap();
    let offered = c.offer("code.person").await.unwrap();
    assert!(offered.totp && !offered.security_key);
}

#[tokio::test]
async fn a_tray_adds_a_key_and_removes_a_factor_with_per_operation_proofs() {
    let s = server("fa-add-key", &[]).await;
    let who =
        s.h.create_and_enroll(&s.root, &s.root_token, "factor.owner", &[APPROVERS])
            .await;
    let mut c = s.session(s.pin);
    c.sign_in(&who.username, secret(support::PASSWORD), totp(&s, &who))
        .await
        .unwrap();
    let factors = c.list_factors().await.unwrap();
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].method, FactorMethod::Totp);

    // The sign-in is the recent step-up BeginAddFactor needs.
    let (nonce, offer) = c.begin_add_factor(FactorMethod::SecurityKey).await.unwrap();
    let AddOffer::SecurityKey(request) = offer else {
        panic!("creation options for a key");
    };
    let key = SoftKey::new(SoftAuthenticator::es256(21));
    // The new key creates the credential; a fresh code proves the TOTP factor.
    let id = c
        .complete_add_key(nonce, &request, key.clone(), "Desk key", totp(&s, &who))
        .await
        .unwrap();
    assert!(id.starts_with("wa_"), "{id}");
    assert_eq!(s.enrolled("webauthn"), 1);
    let factors = c.list_factors().await.unwrap();
    assert_eq!(factors.len(), 2);
    assert_eq!(factors[1].label, "Desk key");

    // Remove the TOTP factor, proving the key.
    c.remove_factor("totp", Factor::SecurityKey(key.clone()))
        .await
        .unwrap();
    assert_eq!(s.removed(), 1);
    let factors = c.list_factors().await.unwrap();
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].method, FactorMethod::SecurityKey);
    // The last factor is never removed.
    let r = c.remove_factor(&id, Factor::SecurityKey(key)).await;
    assert!(
        matches!(&r, Err(ClientError::Other(e)) if e.reason == "last_factor"),
        "{r:?}"
    );
    assert_eq!(s.removed(), 1);
    // A malformed factor id never leaves the client.
    let r = c
        .remove_factor("../totp\u{1b}", Factor::Totp(secret("123456")))
        .await;
    assert!(matches!(r, Err(ClientError::Other(_))), "{r:?}");
    c.logout().await;
}

#[tokio::test]
async fn a_key_only_account_adds_totp_after_a_step_up() {
    let s = server("fa-add-totp", &[]).await;
    let soft = SoftAuthenticator::es256(22);
    let who =
        s.h.create_and_enroll_key(
            &s.root,
            &s.root_token,
            "key.only",
            &[APPROVERS],
            &soft,
            false,
        )
        .await;
    let key = SoftKey::new(soft);
    let mut c = s.session(s.pin);
    c.sign_in(
        &who.username,
        secret(support::PASSWORD),
        Factor::SecurityKey(key.clone()),
    )
    .await
    .unwrap();
    // Past the step-up window: BeginAddFactor asks for a step-up first.
    s.h.clock.advance(400);
    let r = c.begin_add_factor(FactorMethod::Totp).await;
    assert!(
        matches!(&r, Err(e) if e.needs_step_up()),
        "{:?}",
        r.as_ref().err()
    );
    c.step_up(Factor::SecurityKey(key.clone())).await.unwrap();
    let (nonce, offer) = c.begin_add_factor(FactorMethod::Totp).await.unwrap();
    let AddOffer::Totp(seed) = offer else {
        panic!("a TOTP seed");
    };
    s.h.next_step();
    let raw = support::secret_from_uri(seed.uri());
    let code = support::code(&raw, s.h.clock_now());
    drop(seed);
    c.complete_add_totp(nonce, secret(&code), Factor::SecurityKey(key.clone()))
        .await
        .unwrap();
    assert_eq!(s.enrolled("totp"), 1);
    let methods: Vec<FactorMethod> = c
        .list_factors()
        .await
        .unwrap()
        .iter()
        .map(|f| f.method)
        .collect();
    assert_eq!(methods, vec![FactorMethod::Totp, FactorMethod::SecurityKey]);
    c.logout().await;
}

#[tokio::test]
async fn the_fido2_policy_holds_a_keyless_session_to_registering_a_key() {
    let s = server("fa-policy", &[APPROVERS]).await;
    let who =
        s.h.create_and_enroll(&s.root, &s.root_token, "approver.new", &[APPROVERS])
            .await;
    let mut c = s.session(s.pin);
    let info = c
        .sign_in(&who.username, secret(support::PASSWORD), totp(&s, &who))
        .await
        .unwrap();
    assert!(info.factor_enrollment_required);
    // Only factor enrollment is open to this session.
    let r = c.remove_factor("totp", totp(&s, &who)).await;
    assert!(
        matches!(&r, Err(ClientError::Other(e)) if e.reason == "factor_enrollment_required"),
        "{r:?}"
    );
    let (nonce, offer) = c.begin_add_factor(FactorMethod::SecurityKey).await.unwrap();
    let AddOffer::SecurityKey(request) = offer else {
        panic!("creation options");
    };
    let soft = SoftAuthenticator::ed25519(23);
    let key = SoftKey::new(SoftAuthenticator::ed25519(23));
    c.complete_add_key(nonce, &request, key, "", totp(&s, &who))
        .await
        .unwrap();
    c.logout().await;
    // From now on the tray takes the key only, and the session is full.
    let offered = c.offer(&who.username).await.unwrap();
    assert_eq!(
        offered,
        Methods {
            totp: false,
            security_key: true
        }
    );
    let info = c
        .sign_in(
            &who.username,
            secret(support::PASSWORD),
            Factor::SecurityKey(SoftKey::new(soft)),
        )
        .await
        .unwrap();
    assert!(!info.factor_enrollment_required);
    let factors = c.list_factors().await.unwrap();
    assert_eq!(
        factors[1].label, "Security key",
        "the server's default label"
    );
    c.logout().await;
}

#[tokio::test]
async fn a_lock_during_the_new_key_prompt_sends_no_complete() {
    let s = server("fa-lock", &[]).await;
    let who =
        s.h.create_and_enroll(&s.root, &s.root_token, "lock.owner", &[APPROVERS])
            .await;
    let mut c = s.session(s.pin);
    c.sign_in(&who.username, secret(support::PASSWORD), totp(&s, &who))
        .await
        .unwrap();
    let (nonce, offer) = c.begin_add_factor(FactorMethod::SecurityKey).await.unwrap();
    let AddOffer::SecurityKey(request) = offer else {
        panic!("creation options");
    };
    let (logout_tx, _logout_rx) = tokio::sync::mpsc::unbounded_channel();
    let handle: Arc<SessionHandle> = Arc::new(c.session_handle(logout_tx));
    let locker = Arc::clone(&handle);
    let key = Arc::new(SoftKey {
        key: Mutex::new(SoftAuthenticator::es256(26)),
        during: Some(Box::new(move || locker.end())),
        fail: None,
    });
    let r = c
        .complete_add_key(nonce, &request, key, "Desk key", totp(&s, &who))
        .await;
    assert_eq!(r, Err(ClientError::SessionEnded));
    assert!(!c.has_session());
    assert_eq!(
        s.enrolled("webauthn"),
        0,
        "no CompleteAddFactor after the lock"
    );
}

#[tokio::test]
async fn nothing_is_sent_without_a_session_or_with_a_foreign_rp_id() {
    let s = server("fa-none", &[]).await;
    let mut c = s.session(s.pin);
    assert_eq!(c.list_factors().await, Err(ClientError::SessionEnded));
    assert_eq!(
        c.begin_add_factor(FactorMethod::Totp).await.err(),
        Some(ClientError::SessionEnded)
    );
    // A creation request for another site never reaches the key.
    let token = s.create_account("rp.person", &[APPROVERS]).await;
    let offer = c.begin_enrollment(&secret(&token)).await.unwrap();
    let mut request = offer.key.clone().unwrap();
    request.rp_id = "accounts.google.com".into();
    let key = SoftKey::new(SoftAuthenticator::es256(27));
    let r = register_key(key, &request, "x").await;
    assert!(
        matches!(
            r,
            Err(ClientError::Authenticator(
                ferrogate_admin_client::webauthn::AuthenticatorError::BadRequest
            ))
        ),
        "{r:?}"
    );
}
