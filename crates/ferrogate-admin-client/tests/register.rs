//! `ferrogate-admin-client` end to end for the single-step "add
//! application" (F19 §7, F22 §5), as the tray (client kind 2) over the
//! pinned admin listener of an in-process CMIS: a fresh second factor on
//! every add even inside the step-up window, a wrong code that changes
//! nothing and a retry with the same idempotency key, strict separation of
//! duties, and a key touch (a lock during it sends nothing).

#![allow(clippy::large_futures, clippy::missing_panics_doc)]

#[path = "../../cmis/tests/support/mod.rs"]
mod support;

mod common;

use std::sync::{Arc, Mutex};

use ferro_audit::AuditEvent;
use ferrogate_admin_client::approvals::filters::RequestFilters;
use ferrogate_admin_client::approvals::register::{self, Registered, Registration};
use ferrogate_admin_client::approvals::rules::{self, Terms};
use ferrogate_admin_client::client::{AdminSession, Factor};
use ferrogate_admin_client::error::ClientError;
use ferrogate_admin_client::session::SessionHandle;
use support::hosts::{approvals_mode, mint_host, Host};
use support::soft_authenticator::SoftAuthenticator;
use support::Admin1;

use common::{secret, server, server_with, totp, Server, SoftKey, APPROVERS};

const PATH: &str = "/opt/tool/bin/tool";

impl Server {
    /// A signed-in tray session of `who` (TOTP).
    async fn tray(&self, who: &Admin1) -> AdminSession {
        let mut c = self.session(self.pin);
        c.sign_in(&who.username, secret(support::PASSWORD), totp(self, who))
            .await
            .unwrap();
        c
    }

    fn same_actor(&self) -> usize {
        self.count(|e| matches!(e, AuditEvent::AppApprovedBySameActor { .. }))
    }

    fn queued(&self) -> usize {
        self.count(|e| matches!(e, AuditEvent::AdminDirectRegistration { .. }))
    }
}

/// What the administrator types for `host`, the hash made of `sha`.
fn facts(host: &Host, sha: u8) -> Registration {
    Registration {
        host_uuid: host.uuid.to_ascii_uppercase(),
        canonical_path: PATH.into(),
        sha384: hex::encode_upper([sha; 48]),
        uid: "1000".into(),
        user_name: "alice".into(),
        version: "2.1.0".into(),
        ..Registration::default()
    }
}

fn request(s: &Server, host: &Host, sha: u8) -> register::AdminRegisterApplicationRequest {
    let terms = Terms::safe_defaults(false).to_proto(s.h.clock_now());
    let facts = facts(host, sha);
    assert_eq!(facts.problems(), vec![]);
    facts.request(terms, rules::new_idempotency_key())
}

#[tokio::test]
async fn an_add_takes_a_fresh_code_even_after_a_step_up_and_a_wrong_one_changes_nothing() {
    let s = server("reg-add", &[]).await;
    approvals_mode(&s.h.cmis).await;
    let approver =
        s.h.create_and_enroll(&s.root, &s.root_token, "approver.one", &[APPROVERS])
            .await;
    let host = mint_host(&s.h.cmis.issuer, 0x72, "p1");
    let mut c = s.tray(&approver).await;
    // Inside the step-up window: the add still carries its own proof.
    c.step_up(totp(&s, &approver)).await.unwrap();
    let req = request(&s, &host, 7);

    let good = s.h.fresh_code(&approver);
    let wrong = if good == "000000" { "000001" } else { "000000" };
    let refused = c
        .register_application(req.clone(), Factor::Totp(secret(wrong)))
        .await;
    assert_eq!(refused, Err(ClientError::Rejected));
    assert!(c.has_session(), "a wrong code does not end the session");
    assert_eq!(s.same_actor(), 0, "nothing registered");
    let none = c
        .list_requests(RequestFilters::default().to_request(false, ""))
        .await
        .unwrap();
    assert!(none.items.is_empty(), "no request either");

    // The retry: the same request, so the same idempotency key.
    let done = c
        .register_application(req.clone(), totp(&s, &approver))
        .await
        .unwrap();
    let Registered::Approved {
        approval,
        generation,
        ..
    } = register::outcome(&done)
    else {
        panic!("registered and approved: {done:?}");
    };
    assert!(generation > 0);
    assert_eq!(s.same_actor(), 1, "audited as approved by the same person");
    let active = done.approval.unwrap();
    assert_eq!(
        (active.origin, active.state),
        (3, 1),
        "admin_direct, active"
    );
    assert_eq!(active.bin_sha, hex::encode([7u8; 48]), "lowercased");

    // Sent once more (a lost answer): the stored outcome, nothing new.
    let again = c
        .register_application(req, totp(&s, &approver))
        .await
        .unwrap();
    assert!(matches!(
        register::outcome(&again),
        Registered::Approved { approval: ref same, .. } if *same == approval
    ));
    assert_eq!(s.same_actor(), 1, "no second approval");
}

#[tokio::test]
async fn under_strict_sod_the_add_is_queued_for_another_approver() {
    let s = server_with("reg-strict", |c| c.strict_sod = true).await;
    approvals_mode(&s.h.cmis).await;
    let approver =
        s.h.create_and_enroll(&s.root, &s.root_token, "approver.two", &[APPROVERS])
            .await;
    let host = mint_host(&s.h.cmis.issuer, 0x73, "p1");
    let mut c = s.tray(&approver).await;
    let done = c
        .register_application(request(&s, &host, 9), totp(&s, &approver))
        .await
        .unwrap();
    assert!(
        matches!(register::outcome(&done), Registered::Queued { .. }),
        "{done:?}"
    );
    assert_eq!((s.same_actor(), s.queued()), (0, 1));
    let pending = c
        .list_requests(RequestFilters::default().to_request(false, ""))
        .await
        .unwrap();
    assert_eq!(pending.items.len(), 1, "PENDING for a different approver");
    assert_eq!(pending.items[0].origin, 3, "admin_direct");
}

#[tokio::test]
async fn a_key_touch_proves_the_add_and_a_lock_during_it_sends_nothing() {
    let s = server("reg-key", &[]).await;
    approvals_mode(&s.h.cmis).await;
    let soft = SoftAuthenticator::es256(21);
    let who = s.key_holder("key.adder", &[APPROVERS], &soft).await;
    let host = mint_host(&s.h.cmis.issuer, 0x74, "p1");
    let mut c = s.tray(&who).await;

    // Locked while the key is touched: no AdminRegisterApplication.
    let (logout_tx, _logout_rx) = tokio::sync::mpsc::unbounded_channel();
    let handle: Arc<SessionHandle> = Arc::new(c.session_handle(logout_tx));
    let locker = Arc::clone(&handle);
    let locking = Arc::new(SoftKey {
        // The same deterministic credential as the registered one.
        key: Mutex::new(SoftAuthenticator::es256(21)),
        during: Some(Box::new(move || locker.end())),
        fail: None,
    });
    let r = c
        .register_application(request(&s, &host, 3), Factor::SecurityKey(locking))
        .await;
    assert_eq!(r, Err(ClientError::SessionEnded));
    assert!(!c.has_session());
    assert_eq!((s.same_actor(), s.queued()), (0, 0), "nothing was sent");

    // Signed in again: the key's assertion over a fresh challenge proves it.
    let mut c = s.tray(&who).await;
    let done = c
        .register_application(
            request(&s, &host, 4),
            Factor::SecurityKey(SoftKey::new(soft)),
        )
        .await
        .unwrap();
    assert!(
        matches!(register::outcome(&done), Registered::Approved { .. }),
        "{done:?}"
    );
    assert_eq!(s.same_actor(), 1);
}
