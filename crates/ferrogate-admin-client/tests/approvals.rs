//! `ferrogate-admin-client` end to end for request and approval
//! administration (F19 §7, F22 §4), as the tray (client kind 2) over the
//! pinned admin listener of an in-process CMIS: list and read, approve after
//! a forced step-up (the retry reuses the idempotency key), deny, edit
//! against a concurrent edit (`ABORTED`, then reload), revoke and freeze.

#![allow(clippy::large_futures, clippy::missing_panics_doc)]

#[path = "../../cmis/tests/support/mod.rs"]
mod support;

mod common;

use ferro_audit::AuditEvent;
use ferro_proto::v1::machine_identity_server::MachineIdentity as _;
use ferrogate_admin_client::approvals::filters::{ApprovalFilters, RequestFilters};
use ferrogate_admin_client::approvals::proto::ApprovalInfo;
use ferrogate_admin_client::approvals::rules::{self, Edit, EditExpiry, Terms};
use ferrogate_admin_client::approvals::{Mutated, Mutation};
use ferrogate_admin_client::client::AdminSession;
use ferrogate_admin_client::error::ClientError;
use support::hosts::{approvals_mode, mint_host, Host};
use support::Admin1;

use common::{secret, server, totp, Server, APPROVERS};

const NOW_SLACK: i64 = 3_600;

impl Server {
    /// A host-submitted pending request for `path` (as MIA would send it).
    async fn submit(&self, host: &Host, path: &str, sha: u8) -> String {
        let doc = host.app_doc(path, [sha; 48], 1000, "alice", 0);
        self.h
            .mi
            .submit_app_request(tonic::Request::new(host.submit(&doc)))
            .await
            .unwrap()
            .into_inner()
            .request_id
    }

    /// A signed-in tray session of `who` (TOTP).
    async fn tray(&self, who: &Admin1) -> AdminSession {
        let mut c = self.session(self.pin);
        c.sign_in(&who.username, secret(support::PASSWORD), totp(self, who))
            .await
            .unwrap();
        c
    }
}

#[tokio::test]
async fn a_tray_approves_after_a_step_up_with_the_same_key_and_denies() {
    let s = server("ap-decide", &[]).await;
    approvals_mode(&s.h.cmis).await;
    let approver =
        s.h.create_and_enroll(&s.root, &s.root_token, "approver.one", &[APPROVERS])
            .await;
    let host = mint_host(&s.h.cmis.issuer, 0x71, "p1");
    let to_approve = s.submit(&host, "/opt/tool/bin/tool", 1).await;
    let to_deny = s.submit(&host, "/opt/other/bin/other", 2).await;
    let mut c = s.tray(&approver).await;

    let pending = c
        .list_requests(RequestFilters::default().to_request(false, ""))
        .await
        .unwrap();
    assert_eq!(pending.items.len(), 2);
    let detail = c.get_request(&to_approve).await.unwrap();
    assert!(
        !rules::auto_update_preselected(&detail),
        "manual by default"
    );
    let request = detail.request.unwrap();

    // Past the step-up window: the server asks for a fresh factor first.
    s.h.clock.advance(301);
    let terms = Terms::safe_defaults(false).to_proto(s.h.clock_now());
    let approve = Mutation::Approve(rules::approve_request(
        &request.request_id,
        terms,
        Vec::new(),
        rules::REVOKE_REPLACED,
        rules::new_idempotency_key(),
    ));
    let first = c.mutate(approve.clone()).await.unwrap_err();
    assert!(first.needs_step_up(), "{first:?}");
    let audited = |s: &Server| s.count(|e| matches!(e, AuditEvent::AppRequestApproved { .. }));
    assert_eq!(audited(&s), 0);
    c.step_up(totp(&s, &approver)).await.unwrap();
    // The one retry: the same request, so the same idempotency key.
    let Mutated::Approved(done) = c.mutate(approve.clone()).await.unwrap() else {
        panic!("approved");
    };
    assert!(done.allowlist_generation > 0);
    assert_eq!(audited(&s), 1, "exactly one approval audited");
    // Sending it again never approves twice: the request is decided.
    let again = c.mutate(approve).await.unwrap_err();
    assert!(
        matches!(&again, ClientError::Other(e) if e.reason == "invalid_state"),
        "{again:?}"
    );
    assert_eq!(audited(&s), 1, "no second approval");

    let deny = Mutation::Deny(rules::deny_request(
        &to_deny,
        4,
        "Not on the software list.",
        rules::new_idempotency_key(),
    ));
    assert!(matches!(c.mutate(deny).await, Ok(Mutated::Denied(_))));
    let denied = c.get_request(&to_deny).await.unwrap().request.unwrap();
    assert_eq!((denied.state, denied.decision_reason_code), (4, 5));
    let left = c
        .list_requests(RequestFilters::default().to_request(false, ""))
        .await
        .unwrap();
    assert!(left.items.is_empty(), "nothing pending any more");
}

/// Approve `request_id` with the safe defaults, then read the one active
/// approval back through the list and `GetApproval`.
async fn approve_and_read(c: &mut AdminSession, request_id: &str, now: i64) -> ApprovalInfo {
    c.mutate(Mutation::Approve(rules::approve_request(
        request_id,
        Terms::safe_defaults(false).to_proto(now),
        Vec::new(),
        0,
        rules::new_idempotency_key(),
    )))
    .await
    .unwrap();
    let list = c
        .list_approvals(ApprovalFilters::default().to_request(now, false, ""))
        .await
        .unwrap();
    assert_eq!(list.items.len(), 1);
    c.get_approval(&list.items[0].approval_id)
        .await
        .unwrap()
        .approval
        .unwrap()
}

#[tokio::test]
async fn a_tray_edits_through_a_concurrent_change_then_revokes_and_freezes() {
    let s = server("ap-edit", &[]).await;
    approvals_mode(&s.h.cmis).await;
    let approver =
        s.h.create_and_enroll(&s.root, &s.root_token, "approver.two", &[APPROVERS])
            .await;
    let host = mint_host(&s.h.cmis.issuer, 0x72, "p1");
    let request_id = s.submit(&host, "/opt/tool/bin/tool", 3).await;
    let mut c = s.tray(&approver).await;
    let now = s.h.clock_now();
    let approval = approve_and_read(&mut c, &request_id, now).await;

    // Another session edits it first: our edit at the old row version is
    // refused as ABORTED and changes nothing.
    let mut other = s.tray(&approver).await;
    let theirs = Edit {
        note: "set by someone else".into(),
        ..Edit::unchanged(&approval)
    };
    other
        .mutate(Mutation::Update(
            theirs
                .request(&approval, now, rules::new_idempotency_key())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mine = Edit {
        expiry: EditExpiry::Days(30),
        ..Edit::unchanged(&approval)
    };
    let stale = c
        .mutate(Mutation::Update(
            mine.request(&approval, now, rules::new_idempotency_key())
                .unwrap(),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(&stale, ClientError::Other(e) if e.code == tonic::Code::Aborted),
        "{stale:?}"
    );
    let reloaded = c
        .get_approval(&approval.approval_id)
        .await
        .unwrap()
        .approval
        .unwrap();
    assert_eq!(
        rules::approval_changes(&approval, &reloaded),
        vec![rules::ApprovalChange::Note]
    );
    let Mutated::Updated(updated) = c
        .mutate(Mutation::Update(
            mine.request(&reloaded, now, rules::new_idempotency_key())
                .unwrap(),
        ))
        .await
        .unwrap()
    else {
        panic!("updated");
    };
    let updated = updated.approval.unwrap();
    assert!((updated.expires_at - (now + 30 * 86_400)).abs() < NOW_SLACK);

    // Freeze the lineage, then revoke at the current row version.
    assert_eq!(
        c.mutate(Mutation::Freeze(rules::freeze_request(
            &updated.lineage_id,
            true,
            rules::new_idempotency_key(),
        )))
        .await,
        Ok(Mutated::Frozen(true))
    );
    assert!(rules::revoke_confirmed(
        &updated.approval_id,
        &rules::short_id("A", &updated.approval_id).to_lowercase()
    ));
    let Mutated::Revoked(revoked) = c
        .mutate(Mutation::Revoke(rules::revoke_request(
            &updated,
            0,
            rules::new_idempotency_key(),
        )))
        .await
        .unwrap()
    else {
        panic!("revoked");
    };
    assert_eq!(revoked.approval.unwrap().state, 3);
    assert_eq!(
        s.count(|e| matches!(e, AuditEvent::ApprovalRevoked { .. })),
        1
    );
    assert_eq!(
        s.count(|e| matches!(e, AuditEvent::LineageAutoUpdateFrozen { .. })),
        1
    );

    // After a logout nothing more is sent.
    c.logout().await;
    assert_eq!(
        c.get_approval(&updated.approval_id).await.unwrap_err(),
        ClientError::SessionEnded
    );
}
