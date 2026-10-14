//! F19 administrator operations (T267): approve, deny, edit, revoke, the
//! lineage freeze and the single-step direct registration, through the
//! F20 authorization (`METHOD_ACCESS`, step-up, per-operation MFA).
//!
//! Each mutation must emit exactly one F19 audit event, only after the
//! ledger committed; refusals change nothing.

#![allow(clippy::large_futures, clippy::too_many_lines, clippy::assert_is_empty)]

mod support;

use cmis::admin::authz::paths;
use cmis::apps::compile::{serve, Served};
use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::{
    approve_app_request_request::Choice, AdminRegisterApplicationRequest, AppBinaryDesc, AppUser,
    ApprovalTerms, ApproveAppRequestRequest, DenyAppRequestRequest, GetApprovalRequest,
    ListAppRequestsRequest, ListApprovalsRequest, PageRequest, RevokeApprovalRequest,
    SetLineageAutoUpdateFrozenRequest, UpdateApprovalRequest,
};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::{AppRequestState, SubmitAppRequestResponse};
use ferro_raft::apps::{
    ApprovalState, IntakeChecks, RequestOrigin, RequestState, FLAG_PATH_PROTECTED,
};
use support::hosts::{approvals_mode, mint_host, now_unix, open_v2, Host};
use support::{Admin1, Harness};
use tonic::Code;

const PATH: &str = "/opt/tool/bin/tool";

struct World {
    h: Harness,
    root: Admin1,
    root_token: String,
    approver: Admin1,
    token: String,
    host: Host,
}

async fn world(tag: &str, strict: bool) -> World {
    let h = support::harness_with(tag, |c| c.strict_sod = strict).await;
    approvals_mode(&h.cmis).await;
    let root = support::bootstrap(&h, "root-admin").await;
    let root_token = h.login(&root).await;
    let approver = h
        .create_and_enroll(&root, &root_token, "approver.one", &["ferrogate-approvers"])
        .await;
    let token = h.login(&approver).await;
    let host = mint_host(&h.cmis.issuer, 0x61, "p1");
    World {
        h,
        root,
        root_token,
        approver,
        token,
        host,
    }
}

async fn submit(w: &World, sha: u8, uid: u32, name: &str, flags: u32) -> SubmitAppRequestResponse {
    let doc = w.host.app_doc(PATH, [sha; 48], uid, name, flags);
    w.h.mi
        .submit_app_request(tonic::Request::new(w.host.submit(&doc)))
        .await
        .unwrap()
        .into_inner()
}

fn app_events(h: &Harness) -> Vec<AuditEvent> {
    h.audit_events()
        .into_iter()
        .filter(|e| {
            !matches!(
                e,
                AuditEvent::AdminCallAuthorized { .. }
                    | AuditEvent::AdminLoginSucceeded { .. }
                    | AuditEvent::AdminStepUp { .. }
                    | AuditEvent::AdminAccountCreated { .. }
                    | AuditEvent::AdminEnrollmentCompleted { .. }
                    | AuditEvent::AdminBootstrapCompleted { .. }
                    | AuditEvent::AdminSodModeChanged { .. }
                    | AuditEvent::AdminMfaEnrolled { .. }
                    | AuditEvent::AppRequestSubmitted { .. }
                    | AuditEvent::AllowlistCompiled { .. }
            )
        })
        .collect()
}

fn manual_terms() -> ApprovalTerms {
    ApprovalTerms::default()
}

fn approve_req(request_id: &str, terms: ApprovalTerms) -> ApproveAppRequestRequest {
    ApproveAppRequestRequest {
        idempotency_key: uuid::Uuid::now_v7().to_string(),
        request_id: request_id.into(),
        choice: Some(Choice::Terms(terms)),
        also_revoke_approval_ids: vec![],
        also_revoke_reason_code: 0,
        proof: None,
    }
}

async fn approve(
    w: &World,
    token: &str,
    req: ApproveAppRequestRequest,
) -> Result<ferro_proto::admin_v1::ApproveAppRequestResponse, tonic::Status> {
    w.h.call(token, paths::APPROVE_APP_REQUEST, req, |svc, r| {
        Box::pin(async move { svc.approve_app_request(r).await })
    })
    .await
}

fn register_req(
    w: &World,
    key: &str,
    sha: u8,
    terms: ApprovalTerms,
) -> AdminRegisterApplicationRequest {
    AdminRegisterApplicationRequest {
        idempotency_key: key.into(),
        proof: None,
        host_uuid: w.host.uuid.clone(),
        binary: Some(AppBinaryDesc {
            canonical_path: PATH.into(),
            platform: 1,
            sha384: hex::encode([sha; 48]),
            size: 1024,
            format: 1,
            declared_version: "2.1.0".into(),
            ..AppBinaryDesc::default()
        }),
        target_user: Some(AppUser {
            kind: 1,
            uid: Some(1000),
            sid: String::new(),
            name: "alice".into(),
        }),
        reason: "line-of-business tool".into(),
        terms: Some(terms),
    }
}

async fn register(
    w: &World,
    token: &str,
    req: AdminRegisterApplicationRequest,
) -> Result<ferro_proto::admin_v1::AdminRegisterApplicationResponse, tonic::Status> {
    w.h.call(token, paths::ADMIN_REGISTER_APPLICATION, req, |svc, r| {
        Box::pin(async move { svc.admin_register_application(r).await })
    })
    .await
}

#[tokio::test]
async fn app_rpcs_refuse_callers_without_a_session_permission_or_step_up() {
    let w = world("apps-authz", false).await;
    let r = submit(&w, 1, 1000, "alice", 0).await;

    // No session context at all: the handler guard fails closed.
    let e =
        w.h.svc
            .approve_app_request(tonic::Request::new(approve_req(
                &r.request_id,
                manual_terms(),
            )))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "session_invalid")
    );

    // A viewer may list but not decide.
    let viewer =
        w.h.create_and_enroll(&w.root, &w.root_token, "viewer.one", &["ferrogate-viewers"])
            .await;
    let vt = w.h.login(&viewer).await;
    let listed =
        w.h.call(
            &vt,
            paths::LIST_APP_REQUESTS,
            ListAppRequestsRequest::default(),
            |svc, r| Box::pin(async move { svc.list_app_requests(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 1);
    let e = approve(&w, &vt, approve_req(&r.request_id, manual_terms()))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::PermissionDenied, "permission_denied")
    );
    let e = register(&w, &vt, register_req(&w, "k-viewer", 9, manual_terms()))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);

    // An approver whose step-up window lapsed must re-verify.
    w.h.clock.advance(400);
    let e = approve(&w, &w.token, approve_req(&r.request_id, manual_terms()))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "step_up_required")
    );

    let row =
        w.h.cmis
            .cluster()
            .app_request(&r.request_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, RequestState::Pending, "nothing changed");
    assert!(app_events(&w.h)
        .iter()
        .all(|e| matches!(e, AuditEvent::AdminAccessDenied { .. })));
}

#[tokio::test]
async fn approve_and_deny_emit_one_event_each_and_reach_the_host() {
    let w = world("apps-decide", false).await;
    let a = submit(&w, 1, 1000, "alice", 0).await;
    let d = submit(&w, 2, 1001, "bob", 0).await;
    let before = app_events(&w.h).len();

    let ok = approve(&w, &w.token, approve_req(&a.request_id, manual_terms()))
        .await
        .unwrap();
    assert!(!ok.same_actor);
    let approval = ok.approval.unwrap();
    assert_eq!(approval.state, 1);
    assert_eq!(approval.canonical_path, PATH);
    let ttl = w.h.cmis.config.apps.approval_default_ttl_secs;
    assert_eq!(
        approval.expires_at,
        w.h.clock_now() + ttl,
        "default TTL applied"
    );

    let denied =
        w.h.call(
            &w.token,
            paths::DENY_APP_REQUEST,
            DenyAppRequestRequest {
                idempotency_key: String::new(),
                request_id: d.request_id.clone(),
                reason_code: 4,
                message: "use the packaged build".into(),
            },
            |svc, r| Box::pin(async move { svc.deny_app_request(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(denied.request.unwrap().state, 4);

    let events = app_events(&w.h);
    assert_eq!(events.len(), before + 2, "{events:?}");
    assert!(
        matches!(&events[before], AuditEvent::AppRequestApproved { admin_id, .. } if *admin_id == w.approver.admin_id)
    );
    assert!(matches!(
        &events[before + 1],
        AuditEvent::AppRequestDenied { reason_code: 4, .. }
    ));

    // A retried decision changes nothing.
    let e = approve(&w, &w.token, approve_req(&a.request_id, manual_terms()))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "invalid_state")
    );
    assert_eq!(app_events(&w.h).len(), before + 2);

    // The host sees both outcomes, and the next sync serves the approval.
    let Served::Body { signed, .. } = serve(&w.h.cmis, &w.host.uuid, 0, now_unix()).await.unwrap()
    else {
        panic!("expected a body");
    };
    assert_eq!(open_v2(&w.h.cmis, &signed).entries.len(), 1);
}

#[tokio::test]
async fn single_step_registration_needs_a_fresh_second_factor() {
    let w = world("apps-direct", false).await;
    let before = app_events(&w.h).len();

    // No proof, then a wrong one: refused, nothing recorded.
    let e = register(&w, &w.token, register_req(&w, "k-1", 7, manual_terms()))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "invalid_credentials")
    );
    let mut bad = register_req(&w, "k-1", 7, manual_terms());
    bad.proof = Some(ferro_proto::admin_v1::MfaProof {
        f: Some(ferro_proto::admin_v1::mfa_proof::F::TotpCode(
            "000000".into(),
        )),
        nonce: vec![],
    });
    assert!(register(&w, &w.token, bad).await.is_err());
    assert!(w
        .h
        .cmis
        .cluster()
        .app_lineage_by_path(&w.host.uuid, PATH.as_bytes())
        .await
        .unwrap()
        .is_none());
    assert_eq!(app_events(&w.h).len(), before);

    // With a fresh code: registered and approved in one transaction.
    let mut req = register_req(&w, "k-1", 7, manual_terms());
    req.proof = w.h.proof(&w.approver);
    let done = register(&w, &w.token, req.clone()).await.unwrap();
    let request = done.request.clone().unwrap();
    let approval = done.approval.clone().unwrap();
    assert!(!done.queued && !done.deduplicated);
    assert_eq!(request.state, 2);
    assert!(request.same_actor_approved);
    assert_eq!(request.requested_by_admin_id, w.approver.admin_id);
    assert_eq!(request.decided_by_admin_id, w.approver.admin_id);
    assert_eq!(request.origin, 3);
    assert_eq!(approval.origin, 3);
    let events = app_events(&w.h);
    assert_eq!(events.len(), before + 1, "exactly one event: {events:?}");
    assert!(matches!(&events[before],
        AuditEvent::AppApprovedBySameActor { admin_id, mfa_method, origin: 3, .. }
            if *admin_id == w.approver.admin_id && mfa_method == "totp"));

    // A retry with the same key returns the stored outcome, unaudited.
    let again = register(&w, &w.token, req).await.unwrap();
    assert_eq!(again.request.unwrap().request_id, request.request_id);
    assert!(again.deduplicated);
    assert_eq!(app_events(&w.h).len(), before + 1);

    // The host is covered and the next sync serves the entry.
    let covered = submit(&w, 7, 1000, "alice", 0).await;
    assert_eq!(covered.state, AppRequestState::Approved as i32);
    assert_eq!(covered.approval_id, approval.approval_id);
}

#[tokio::test]
async fn strict_sod_queues_direct_registration_and_forbids_self_approval() {
    let w = world("apps-strict", true).await;
    let mut req = register_req(&w, "k-strict", 8, manual_terms());
    req.proof = w.h.proof(&w.approver);
    let queued = register(&w, &w.token, req).await.unwrap();
    assert!(queued.queued && queued.approval.is_none());
    let request = queued.request.unwrap();
    assert_eq!(request.state, 1);
    assert!(app_events(&w.h)
        .iter()
        .any(|e| matches!(e, AuditEvent::AdminDirectRegistration { .. })));

    let e = approve(
        &w,
        &w.token,
        approve_req(&request.request_id, manual_terms()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::PermissionDenied, "sod_self_approval")
    );

    let second =
        w.h.create_and_enroll(
            &w.root,
            &w.root_token,
            "approver.two",
            &["ferrogate-approvers"],
        )
        .await;
    let t2 = w.h.login(&second).await;
    let ok = approve(&w, &t2, approve_req(&request.request_id, manual_terms()))
        .await
        .unwrap();
    assert!(!ok.same_actor);
    let events = app_events(&w.h);
    assert!(events.iter().any(|e| matches!(e, AuditEvent::AppRequestApproved { admin_id, .. } if *admin_id == second.admin_id)));
    assert!(!events
        .iter()
        .any(|e| matches!(e, AuditEvent::AppApprovedBySameActor { .. })));
}

#[tokio::test]
async fn approving_ones_own_request_with_the_policy_off_needs_mfa_and_is_flagged() {
    let w = world("apps-self", false).await;
    // A pending direct registration (as queued while the strict policy was on).
    let p = cmis::apps::intake::prepare(cmis::apps::intake::Submission {
        host_uuid: w.host.uuid.clone(),
        client_request_id: "adm:self-1".into(),
        origin: RequestOrigin::AdminDirect,
        target: ferro_raft::apps::UserIdentity {
            kind: ferro_raft::apps::UserKind::Unix,
            uid: Some(1000),
            sid: None,
            user_name: Some("alice".into()),
        },
        requester_uid: None,
        requester_user_name: None,
        requested_by_admin_id: Some(w.approver.admin_id.clone()),
        reason: None,
        host_tier: "tpm".into(),
        proposer_spiffe_id: w.host.spiffe_id.clone(),
        binary: cmis::apps::intake::BinaryFacts {
            platform: 1,
            canonical_path: PATH.into(),
            sha384: [5; 48],
            size: 1,
            format: 1,
            declared_version: None,
            version_source: 0,
            product_name: None,
            bundle_id: None,
            package_name: None,
            signer_kind: 0,
            signer_id: None,
            signer_subject: None,
            signer_valid: false,
            flags: 0,
        },
    })
    .unwrap();
    let cluster = w.h.cmis.cluster();
    let now = w.h.clock_now();
    let (_l, b) = cmis::apps::intake::observe(cluster, &p, now).await.unwrap();
    let nr = cmis::apps::intake::new_request(&p, &b, 0, &w.h.cmis.config.apps, now);
    cluster
        .app_submit_pending(
            &nr,
            &IntakeChecks {
                now,
                denied_cooldown_since: None,
            },
        )
        .await
        .unwrap();

    let e = approve(&w, &w.token, approve_req(&nr.request_id, manual_terms()))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "invalid_credentials")
    );
    let mut req = approve_req(&nr.request_id, manual_terms());
    req.proof = w.h.proof(&w.approver);
    let ok = approve(&w, &w.token, req).await.unwrap();
    assert!(ok.same_actor);
    let events = app_events(&w.h);
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, AuditEvent::AppApprovedBySameActor { .. }))
            .count(),
        1
    );
    assert!(!events
        .iter()
        .any(|e| matches!(e, AuditEvent::AppRequestApproved { .. })));
}

#[tokio::test]
async fn wide_scope_and_expiry_caps_are_enforced_before_any_write() {
    let w = world("apps-caps", false).await;
    let cases = [
        (
            ApprovalTerms {
                user_scope: 2,
                ..ApprovalTerms::default()
            },
            "confirmation_required",
        ),
        (
            ApprovalTerms {
                user_scope: 2,
                confirm_any_user: true,
                update_policy: 2,
                ..ApprovalTerms::default()
            },
            "any_user_needs_protected_path",
        ),
        (
            ApprovalTerms {
                expires_at: w.h.clock_now() + 400 * 86_400,
                ..ApprovalTerms::default()
            },
            "expiry_too_far",
        ),
        (
            ApprovalTerms {
                no_expiry: true,
                ..ApprovalTerms::default()
            },
            "no_expiry_not_allowed",
        ),
    ];
    for (n, (terms, reason)) in cases.into_iter().enumerate() {
        let mut req = register_req(&w, &format!("k-cap-{n}"), 3, terms);
        req.proof = w.h.proof(&w.approver);
        let e = register(&w, &w.token, req).await.unwrap_err();
        assert_eq!((e.code(), e.message()), (Code::InvalidArgument, reason));
    }
    assert!(w
        .h
        .cmis
        .cluster()
        .app_lineage_by_path(&w.host.uuid, PATH.as_bytes())
        .await
        .unwrap()
        .is_none());
    assert!(!app_events(&w.h)
        .iter()
        .any(|e| matches!(e, AuditEvent::AppApprovedBySameActor { .. })));
}

#[tokio::test]
async fn revoke_update_and_freeze_are_audited_and_change_the_served_allowlist() {
    let w = world("apps-edit", false).await;
    let r = submit(&w, 1, 1000, "alice", FLAG_PATH_PROTECTED).await;
    let ok = approve(
        &w,
        &w.token,
        approve_req(
            &r.request_id,
            ApprovalTerms {
                update_policy: 2,
                ..ApprovalTerms::default()
            },
        ),
    )
    .await
    .unwrap();
    let approval = ok.approval.unwrap();
    let before = app_events(&w.h).len();

    // Edit the expiry (and the note).
    let new_expiry = w.h.clock_now() + 30 * 86_400;
    let updated =
        w.h.call(
            &w.token,
            paths::UPDATE_APPROVAL,
            UpdateApprovalRequest {
                idempotency_key: String::new(),
                approval_id: approval.approval_id.clone(),
                expected_row_version: approval.row_version,
                expires_at: Some(new_expiry),
                note: Some("reviewed".into()),
                ..UpdateApprovalRequest::default()
            },
            |svc, r| Box::pin(async move { svc.update_approval(r).await }),
        )
        .await
        .unwrap();
    let edited = updated.approval.unwrap();
    assert_eq!(edited.expires_at, new_expiry);
    assert_eq!(edited.row_version, approval.row_version + 1);
    // A stale row version is refused.
    let e =
        w.h.call(
            &w.token,
            paths::UPDATE_APPROVAL,
            UpdateApprovalRequest {
                approval_id: approval.approval_id.clone(),
                expected_row_version: approval.row_version,
                note: Some("again".into()),
                ..UpdateApprovalRequest::default()
            },
            |svc, r| Box::pin(async move { svc.update_approval(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Aborted, "row_version_mismatch")
    );

    // Freeze the lineage: the next update is not auto-approved.
    w.h.call(
        &w.token,
        paths::SET_LINEAGE_AUTO_UPDATE_FROZEN,
        SetLineageAutoUpdateFrozenRequest {
            idempotency_key: String::new(),
            lineage_id: approval.lineage_id.clone(),
            frozen: true,
        },
        |svc, r| Box::pin(async move { svc.set_lineage_auto_update_frozen(r).await }),
    )
    .await
    .unwrap();
    let frozen = submit(&w, 2, 1000, "alice", FLAG_PATH_PROTECTED).await;
    assert_eq!(frozen.auto_downgrade_reason, "lineage_frozen");

    // Revoke ("delete"): the record stays, the next sync drops the entry.
    let revoked =
        w.h.call(
            &w.token,
            paths::REVOKE_APPROVAL,
            RevokeApprovalRequest {
                idempotency_key: String::new(),
                approval_id: approval.approval_id.clone(),
                reason_code: 2,
                expected_row_version: 0,
            },
            |svc, r| Box::pin(async move { svc.revoke_approval(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(revoked.approval.unwrap().state, 3);
    let Served::Body { signed, .. } = serve(&w.h.cmis, &w.host.uuid, 0, now_unix()).await.unwrap()
    else {
        panic!("expected a body");
    };
    assert!(open_v2(&w.h.cmis, &signed).entries.is_empty());
    let detail =
        w.h.call(
            &w.token,
            paths::GET_APPROVAL,
            GetApprovalRequest {
                approval_id: approval.approval_id.clone(),
            },
            |svc, r| Box::pin(async move { svc.get_approval(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(detail.revisions.len(), 3, "created, updated, revoked");
    assert_eq!(
        detail.approval.unwrap().state,
        u32::try_from(ApprovalState::Revoked.code()).unwrap()
    );

    let events = app_events(&w.h);
    let new: Vec<_> = events[before..].iter().collect();
    assert_eq!(new.len(), 3, "{new:?}");
    assert!(
        matches!(new[0], AuditEvent::ApprovalUpdated { changed_fields, .. }
        if changed_fields.contains(&"expires_at".to_string()) && changed_fields.contains(&"note".to_string()))
    );
    assert!(matches!(
        new[1],
        AuditEvent::LineageAutoUpdateFrozen { frozen: true, .. }
    ));
    assert!(matches!(
        new[2],
        AuditEvent::ApprovalRevoked { reason_code: 2, .. }
    ));
    // No personal data in any F19 event.
    for e in &events {
        let text = format!("{e:?}");
        assert!(
            !text.contains("alice") && !text.contains("/opt/tool") && !text.contains("reviewed"),
            "{text}"
        );
    }
}

#[tokio::test]
async fn listings_page_with_integrity_protected_tokens() {
    let w = world("apps-list", false).await;
    for n in 1..=3 {
        submit(&w, n, 1000 + u32::from(n), "user", 0).await;
    }
    let page = |token: String| ListAppRequestsRequest {
        page: Some(PageRequest {
            page_size: 2,
            page_token: token,
        }),
        ..ListAppRequestsRequest::default()
    };
    let first =
        w.h.call(
            &w.token,
            paths::LIST_APP_REQUESTS,
            page(String::new()),
            |svc, r| Box::pin(async move { svc.list_app_requests(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(first.items.len(), 2);
    assert!(!first.next_page_token.is_empty());
    let second =
        w.h.call(
            &w.token,
            paths::LIST_APP_REQUESTS,
            page(first.next_page_token.clone()),
            |svc, r| Box::pin(async move { svc.list_app_requests(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_page_token.is_empty());

    let mut forged = first.next_page_token.clone();
    forged.push('0');
    let e =
        w.h.call(
            &w.token,
            paths::LIST_APP_REQUESTS,
            page(forged),
            |svc, r| Box::pin(async move { svc.list_app_requests(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    // A requests token is not an approvals token.
    let e =
        w.h.call(
            &w.token,
            paths::LIST_APPROVALS,
            ListApprovalsRequest {
                page: Some(PageRequest {
                    page_size: 2,
                    page_token: first.next_page_token,
                }),
                ..ListApprovalsRequest::default()
            },
            |svc, r| Box::pin(async move { svc.list_approvals(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn an_admin_store_failure_answers_unavailable_and_audits_nothing() {
    let w = world("apps-admin-store", false).await;
    let r = submit(&w, 1, 1000, "alice", 0).await;
    w.h.cmis
        .cluster()
        .client()
        .execute(
            "CREATE TRIGGER fail_insert_app_approvals BEFORE INSERT ON app_approvals \
             BEGIN SELECT RAISE(ABORT, 'injected store failure'); END"
                .to_string(),
            vec![],
        )
        .await
        .unwrap();
    let before = app_events(&w.h).len();
    let e = approve(&w, &w.token, approve_req(&r.request_id, manual_terms()))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unavailable, "store_unavailable")
    );
    assert_eq!(app_events(&w.h).len(), before);
    let row =
        w.h.cmis
            .cluster()
            .app_request(&r.request_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, RequestState::Pending);
}
