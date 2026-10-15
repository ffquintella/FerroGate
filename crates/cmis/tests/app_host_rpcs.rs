//! F19 host RPCs (T265, T266, T268, T271): `SubmitAppRequest`,
//! `GetAppRequestStatus` and `SyncAllowlist` against an in-process CMIS.
//!
//! Covers the host proof (unsigned, wrong host, revoked, replayed, stale,
//! wrong context), the legacy-mode refusal, deduplication and the
//! non-replacement invariant through the RPCs, the auto-update policy and
//! its refusals, host-scoped status, the signed v2 allowlist with monotonic
//! generations, the sweepers, and store failures.

#![allow(clippy::large_futures, clippy::too_many_lines, clippy::assert_is_empty)]

mod support;

use std::sync::Arc;

use cmis::apps::compile::{serve, Served};
use cmis::CmisState;
use ferro_audit::AuditEvent;
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::sync_allowlist_response::Result as SyncResult;
use ferro_proto::v1::{AppRequestState, SubmitAppRequestResponse};
use ferro_raft::apps::{
    ApprovalState, Deny, RequestFilter, RequestState, Revoke, UpdatePolicy, FLAG_PATH_PROTECTED,
};
use ferro_svid::app_docs::APP_STATUS_CONTEXT;
use ferro_svid::RevocationTarget;
use support::hosts::{
    approvals_mode, client_id, ledger_approve, mint_host, now_unix, open_v2, terms, Host,
};
use support::Harness;
use tonic::Code;

const PATH: &str = "/opt/tool/bin/tool";
const DAY: i64 = 86_400;

fn sha(n: u8) -> [u8; 48] {
    [n; 48]
}

async fn setup(tag: &str) -> (Harness, Host, Host) {
    setup_with(tag, |_| {}).await
}

async fn setup_with(tag: &str, tweak: impl FnOnce(&mut cmis::CmisConfig)) -> (Harness, Host, Host) {
    let h = support::harness_cfg(tag, tweak, |_| {}).await;
    let a = mint_host(&h.cmis.issuer, 0x41, "p1");
    let b = mint_host(&h.cmis.issuer, 0x42, "p1");
    (h, a, b)
}

async fn submit(
    h: &Harness,
    host: &Host,
    doc: &ferro_svid::app_docs::AppRequestDoc,
) -> Result<SubmitAppRequestResponse, tonic::Status> {
    h.mi.submit_app_request(tonic::Request::new(host.submit(doc)))
        .await
        .map(tonic::Response::into_inner)
}

fn events_of(h: &Harness, pred: impl Fn(&AuditEvent) -> bool) -> usize {
    h.audit_events().iter().filter(|e| pred(e)).count()
}

async fn request_count(state: &CmisState) -> usize {
    state
        .cluster()
        .app_list_requests(&RequestFilter {
            page_size: 200,
            ..RequestFilter::default()
        })
        .await
        .unwrap()
        .len()
}

fn id_bytes(id: &str) -> [u8; 16] {
    *uuid::Uuid::parse_str(id).unwrap().as_bytes()
}

#[tokio::test]
async fn host_auth_negatives_change_nothing() {
    let (h, a, b) = setup("hostneg").await;
    approvals_mode(&h.cmis).await;
    let before = h.cmis.audit.len();

    // Unsigned.
    let mut req = a.submit(&a.app_doc(PATH, sha(1), 1000, "alice", 0));
    req.auth = None;
    let e =
        h.mi.submit_app_request(tonic::Request::new(req))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "host_auth_failed")
    );

    // A document naming another host, signed by this one.
    let mut doc = a.app_doc(PATH, sha(1), 1000, "alice", 0);
    doc.host_uuid = b.uuid.clone();
    let e = submit(&h, &a, &doc).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::PermissionDenied, "host_mismatch")
    );

    // Stale and future documents.
    for skew in [-301, 301] {
        let mut doc = a.app_doc(PATH, sha(1), 1000, "alice", 0);
        doc.issued_at = now_unix() + skew;
        let e = submit(&h, &a, &doc).await.unwrap_err();
        assert_eq!(e.code(), Code::Unauthenticated, "skew {skew}");
    }

    // Signed under another RPC's context.
    let doc = a.app_doc(PATH, sha(1), 1000, "alice", 0);
    let mut req = a.submit(&doc);
    req.auth = Some(a.auth(APP_STATUS_CONTEXT, &req.doc));
    let e =
        h.mi.submit_app_request(tonic::Request::new(req))
            .await
            .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);

    // Signed by a key the SVID is not bound to.
    let mut req = a.submit(&a.app_doc(PATH, sha(1), 1000, "alice", 0));
    let forged = b.auth(ferro_svid::app_docs::APP_REQUEST_CONTEXT, &req.doc);
    req.auth.as_mut().unwrap().sig = forged.sig;
    let e =
        h.mi.submit_app_request(tonic::Request::new(req))
            .await
            .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);

    // A replayed status / sync document is dropped.
    let status = a.status(&[]);
    h.mi.get_app_request_status(tonic::Request::new(status.clone()))
        .await
        .unwrap();
    let e =
        h.mi.get_app_request_status(tonic::Request::new(status))
            .await
            .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated, "replayed status nonce");

    // A revoked host is refused everywhere.
    h.cmis.revoke(
        RevocationTarget::Host {
            spiffe_id: a.spiffe_id.clone(),
        },
        "test",
        now_unix(),
    );
    let e = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);
    let e =
        h.mi.sync_allowlist(tonic::Request::new(a.sync(0)))
            .await
            .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);

    assert_eq!(request_count(&h.cmis).await, 0, "no request recorded");
    assert_eq!(h.cmis.audit.len(), before, "nothing audited");
}

/// Log capture for one test thread (`tracing::subscriber::set_default`).
#[derive(Clone, Default)]
struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A signed document that does not decode is refused with stable codes and
/// logged without the decoder's message, which quotes the document (here an
/// unknown key holding a home path): F19 §8 "I", no PII in logs.
#[tokio::test]
async fn a_malformed_document_is_logged_without_its_contents() {
    let (h, a, _) = setup("malformed-log").await;
    approvals_mode(&h.cmis).await;
    let secret = "/home/zelda-private/secret-tool";
    let mut value =
        ciborium::Value::serialized(&a.app_doc(PATH, sha(1), 1000, "alice", 0)).unwrap();
    let ciborium::Value::Map(fields) = &mut value else {
        panic!("a document is a map")
    };
    fields.push((
        ciborium::Value::Text(secret.into()),
        ciborium::Value::Integer(1.into()),
    ));
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    let req = ferro_proto::v1::SubmitAppRequestRequest {
        auth: Some(a.auth(ferro_svid::app_docs::APP_REQUEST_CONTEXT, &bytes)),
        doc: bytes,
    };

    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let e = {
        let _guard = tracing::subscriber::set_default(subscriber);
        h.mi.submit_app_request(tonic::Request::new(req))
            .await
            .unwrap_err()
    };
    assert_eq!(e.code(), Code::InvalidArgument);
    assert!(!e.message().contains("zelda"));
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("host_auth.malformed_doc"), "{logs}");
    assert!(logs.contains("reason=\"malformed\""), "{logs}");
    assert!(!logs.contains("zelda"), "{logs}");
    assert_eq!(request_count(&h.cmis).await, 0);
}

#[tokio::test]
async fn submission_is_refused_in_legacy_mode() {
    let (h, a, _) = setup("legacy").await;
    let e = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "mode_legacy")
    );
    assert_eq!(request_count(&h.cmis).await, 0);
}

#[tokio::test]
async fn retries_and_duplicates_return_the_stored_request_unchanged() {
    let (h, a, _) = setup("dedup").await;
    approvals_mode(&h.cmis).await;
    let doc = a.app_doc(PATH, sha(1), 1000, "alice", 0);
    let first = submit(&h, &a, &doc).await.unwrap();
    assert_eq!(first.state, AppRequestState::Pending as i32);
    assert!(!first.deduplicated);
    assert_eq!(first.revision, 1);
    assert_eq!(first.auto_downgrade_reason, "no_auto_parent");
    let row = h
        .cmis
        .cluster()
        .app_request(&first.request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        events_of(&h, |e| matches!(e, AuditEvent::AppRequestSubmitted { .. })),
        1
    );

    // The same document again (MIA retry): the stored outcome.
    let retry = submit(&h, &a, &doc).await.unwrap();
    assert_eq!(retry.request_id, first.request_id);
    assert!(retry.deduplicated);

    // A new ask for the same binary and user: the open request.
    let mut again = a.app_doc(PATH, sha(1), 1000, "alice", 0);
    again.client_request_id = client_id();
    let dup = submit(&h, &a, &again).await.unwrap();
    assert_eq!(dup.request_id, first.request_id);
    assert!(dup.deduplicated);

    let after = h
        .cmis
        .cluster()
        .app_request(&first.request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row, after, "deduplication never rewrites the request");
    assert_eq!(request_count(&h.cmis).await, 1);
    assert_eq!(
        events_of(&h, |e| matches!(e, AuditEvent::AppRequestSubmitted { .. })),
        1,
        "retries are not audited again"
    );
}

#[tokio::test]
async fn requests_never_replace_or_remove_an_approval() {
    let (h, a, _) = setup("noreplace").await;
    approvals_mode(&h.cmis).await;
    let first = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();
    let approval = ledger_approve(
        &h.cmis,
        &first.request_id,
        "admin-x",
        terms(UpdatePolicy::ManualEachTime, Some(now_unix() + 10 * DAY)),
    )
    .await;
    let generation = h
        .cmis
        .cluster()
        .app_allowlist_state(&a.uuid)
        .await
        .unwrap()
        .unwrap()
        .generation;

    // The approved binary again: APPROVED, no new request row.
    let covered = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();
    assert_eq!(covered.state, AppRequestState::Approved as i32);
    assert_eq!(covered.approval_id, approval.approval_id);
    assert!(covered.request_id.is_empty() && covered.deduplicated);
    assert_eq!(covered.allowlist_generation, generation);

    // An update at the same path (manual policy) and an ask for another
    // user: new pending requests; the approval is untouched.
    let update = submit(&h, &a, &a.app_doc(PATH, sha(2), 1000, "alice", 0))
        .await
        .unwrap();
    assert_eq!(update.state, AppRequestState::Pending as i32);
    assert_eq!(update.revision, 2);
    let other_user = submit(&h, &a, &a.app_doc(PATH, sha(1), 1001, "bob", 0))
        .await
        .unwrap();
    assert_eq!(other_user.state, AppRequestState::Pending as i32);
    let update_row = h
        .cmis
        .cluster()
        .app_request(&update.request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        update_row.kind,
        ferro_raft::apps::RequestKind::Update,
        "classified by CMIS"
    );

    let now_row = h
        .cmis
        .cluster()
        .app_approval(&approval.approval_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        now_row, approval,
        "INV-1: no host operation changed the approval"
    );
    let state = h
        .cmis
        .cluster()
        .app_allowlist_state(&a.uuid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        state.generation, generation,
        "the served set did not change"
    );
}

#[tokio::test]
async fn a_protected_path_update_is_auto_approved_with_the_parent_expiry() {
    let (h, a, _) = setup("auto").await;
    approvals_mode(&h.cmis).await;
    let expiry = now_unix() + 20 * DAY;
    let first = submit(
        &h,
        &a,
        &a.app_doc(PATH, sha(1), 1000, "alice", FLAG_PATH_PROTECTED),
    )
    .await
    .unwrap();
    let parent = ledger_approve(
        &h.cmis,
        &first.request_id,
        "admin-x",
        terms(UpdatePolicy::AutoSamePathUser, Some(expiry)),
    )
    .await;
    let before = h
        .cmis
        .cluster()
        .app_allowlist_state(&a.uuid)
        .await
        .unwrap()
        .unwrap()
        .generation;

    let update = submit(
        &h,
        &a,
        &a.app_doc(PATH, sha(2), 1000, "alice", FLAG_PATH_PROTECTED),
    )
    .await
    .unwrap();
    assert_eq!(update.state, AppRequestState::AutoApproved as i32);
    assert!(update.allowlist_generation > before, "sync sees a change");
    let child = h
        .cmis
        .cluster()
        .app_approval(&update.approval_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        child.expires_at,
        Some(expiry),
        "expiry inherited, never extended"
    );
    assert_eq!(
        child.parent_approval_id.as_deref(),
        Some(parent.approval_id.as_str())
    );
    let parent_now = h
        .cmis
        .cluster()
        .app_approval(&parent.approval_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        parent_now.state,
        ApprovalState::Active,
        "the parent stays active"
    );
    let audit = h.audit_events();
    assert!(audit.iter().any(|e| matches!(e,
        AuditEvent::AppRequestAutoApproved { continuity_basis, .. } if continuity_basis == "protected_path")));
}

#[tokio::test]
async fn auto_update_never_reapproves_revoked_or_denied_hashes() {
    let (h, a, _) = setup_with("autoneg", |c| c.apps.denied_cooldown_secs = 0).await;
    approvals_mode(&h.cmis).await;
    let cluster = h.cmis.cluster();
    let flags = FLAG_PATH_PROTECTED;
    let far = Some(now_unix() + 30 * DAY);

    // Hash 1 approved under auto-update, hash 2 auto-approved, then revoked.
    let r1 = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", flags))
        .await
        .unwrap();
    ledger_approve(
        &h.cmis,
        &r1.request_id,
        "admin-x",
        terms(UpdatePolicy::AutoSamePathUser, far),
    )
    .await;
    let r2 = submit(&h, &a, &a.app_doc(PATH, sha(2), 1000, "alice", flags))
        .await
        .unwrap();
    assert_eq!(r2.state, AppRequestState::AutoApproved as i32);
    let now = now_unix();
    cluster
        .app_revoke_approval(
            &Revoke {
                approval_id: r2.approval_id.clone(),
                admin_id: "admin-x".into(),
                reason_code: 1,
                expected_row_version: None,
            },
            now,
            now * 1000,
        )
        .await
        .unwrap();
    let again = submit(&h, &a, &a.app_doc(PATH, sha(2), 1000, "alice", flags))
        .await
        .unwrap();
    assert_eq!(again.state, AppRequestState::Pending as i32);
    assert_eq!(again.auto_downgrade_reason, "hash_previously_revoked");
    let row = cluster
        .app_request(&again.request_id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        row.flags & ferro_appid::RiskFlags::HASH_PREVIOUSLY_REVOKED,
        0
    );

    // Hash 3 denied by an administrator; asking again is not auto-approved.
    let r3 = submit(
        &h,
        &a,
        &a.app_doc("/opt/other/bin/x", sha(3), 1000, "alice", flags),
    )
    .await
    .unwrap();
    cluster
        .app_deny_request(&Deny {
            request_id: r3.request_id.clone(),
            admin_id: "admin-x".into(),
            now: now_unix(),
            reason_code: 7,
            message: Some("not allowed here".into()),
            forbid_self_approval: false,
        })
        .await
        .unwrap();
    // Approve hash 4 at that path with auto-update, then retry hash 3.
    let r4 = submit(
        &h,
        &a,
        &a.app_doc("/opt/other/bin/x", sha(4), 1000, "alice", flags),
    )
    .await
    .unwrap();
    ledger_approve(
        &h.cmis,
        &r4.request_id,
        "admin-x",
        terms(UpdatePolicy::AutoSamePathUser, far),
    )
    .await;
    let retry = submit(
        &h,
        &a,
        &a.app_doc("/opt/other/bin/x", sha(3), 1000, "alice", flags),
    )
    .await
    .unwrap();
    assert_eq!(retry.state, AppRequestState::Pending as i32);
    assert_eq!(retry.auto_downgrade_reason, "hash_previously_denied");

    // Without the protected-path anchor (and no signer) nothing is automatic.
    let unanchored = submit(&h, &a, &a.app_doc(PATH, sha(5), 1000, "alice", 0))
        .await
        .unwrap();
    assert_eq!(unanchored.auto_downgrade_reason, "no_continuity_anchor");
    // Another user is not the parent's user.
    let other = submit(&h, &a, &a.app_doc(PATH, sha(6), 1001, "bob", flags))
        .await
        .unwrap();
    assert_eq!(other.auto_downgrade_reason, "user_mismatch");
}

#[tokio::test]
async fn configuration_gates_come_first() {
    let (h, a, _) = setup_with("autocfg", |c| c.apps.auto_update = false).await;
    approvals_mode(&h.cmis).await;
    let r = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();
    assert_eq!(r.auto_downgrade_reason, "auto_disabled");

    let (h, _, _) = setup_with("autotier", |c| c.apps.auto_update_tiers = vec!["tpm"]).await;
    approvals_mode(&h.cmis).await;
    let soft = mint_host(&h.cmis.issuer, 0x51, "host-key");
    let r = submit(&h, &soft, &soft.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();
    assert_eq!(r.auto_downgrade_reason, "tier_not_allowed");
    let row = h
        .cmis
        .cluster()
        .app_request(&r.request_id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        row.flags & ferro_appid::RiskFlags::HOST_TIER_B,
        0,
        "tier B is flagged"
    );
    assert_eq!(row.host_tier, "host-key");
}

#[tokio::test]
async fn pending_caps_and_the_submission_budget_are_enforced() {
    let (h, a, _) = setup_with("caps", |c| {
        c.apps.max_pending_per_user = 2;
        c.host_calls.app_submit_per_hour = 4;
    })
    .await;
    approvals_mode(&h.cmis).await;
    for n in 1..=2 {
        submit(&h, &a, &a.app_doc(PATH, sha(n), 1000, "alice", 0))
            .await
            .unwrap();
    }
    let e = submit(&h, &a, &a.app_doc(PATH, sha(3), 1000, "alice", 0))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::ResourceExhausted, "too_many_pending")
    );
    assert!(e.metadata().get("retry-after").is_some());
    submit(&h, &a, &a.app_doc(PATH, sha(4), 1001, "bob", 0))
        .await
        .unwrap();
    let e = submit(&h, &a, &a.app_doc(PATH, sha(5), 1001, "bob", 0))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::ResourceExhausted, "rate_limited")
    );
}

#[tokio::test]
async fn status_reveals_only_the_callers_own_requests() {
    let (h, a, b) = setup("status").await;
    approvals_mode(&h.cmis).await;
    let mine = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();
    let id = id_bytes(&mine.request_id);
    let unknown = [0xEE; 16];

    let theirs =
        h.mi.get_app_request_status(tonic::Request::new(b.status(&[id, unknown])))
            .await
            .unwrap()
            .into_inner();
    assert!(theirs.items.is_empty(), "no cross-host oracle");

    h.cmis
        .cluster()
        .app_deny_request(&Deny {
            request_id: mine.request_id.clone(),
            admin_id: "admin-x".into(),
            now: now_unix(),
            reason_code: 3,
            message: Some("use the packaged build".into()),
            forbid_self_approval: false,
        })
        .await
        .unwrap();
    let own =
        h.mi.get_app_request_status(tonic::Request::new(a.status(&[id, unknown])))
            .await
            .unwrap()
            .into_inner();
    assert_eq!(own.items.len(), 1);
    assert_eq!(own.items[0].state, AppRequestState::Denied as i32);
    assert_eq!(own.items[0].deny_reason_code, 3);
    assert_eq!(own.items[0].deny_message, "use the packaged build");
}

#[tokio::test]
async fn sync_serves_signed_v2_bodies_with_monotonic_generations() {
    let (h, a, b) = setup("sync").await;
    approvals_mode(&h.cmis).await;

    // First sync over the RPC: an empty, signed, host-bound body.
    let resp =
        h.mi.sync_allowlist(tonic::Request::new(a.sync(0)))
            .await
            .unwrap()
            .into_inner();
    let Some(SyncResult::SignedAllowlistV2(body)) = resp.result else {
        panic!("expected a body: {resp:?}");
    };
    let doc = open_v2(&h.cmis, &body);
    assert_eq!(doc.host_uuid, a.uuid);
    assert_eq!(doc.generation, resp.generation);
    assert!(doc.entries.is_empty());
    let g1 = resp.generation;
    assert!(g1 > 0);
    // A v2 body never verifies as v1 (old agents fail closed).
    let signed = ferro_svid::allowlist::decode(&body).unwrap();
    assert!(ferro_svid::allowlist::verify(&signed, h.cmis.issuer.public_key()).is_err());

    // One sync per host per interval.
    let err =
        h.mi.sync_allowlist(tonic::Request::new(a.sync(g1)))
            .await
            .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::ResourceExhausted, "rate_limited")
    );
    assert!(err.metadata().get("retry-after").is_some());

    // An approval appears in the next body, at a higher generation, with
    // hashes only (no path or user name in the signed body).
    let r = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();
    let approval = ledger_approve(
        &h.cmis,
        &r.request_id,
        "admin-x",
        terms(UpdatePolicy::ManualEachTime, Some(now_unix() + DAY)),
    )
    .await;
    let Served::Body {
        generation: g2,
        signed,
        ..
    } = serve(&h.cmis, &a.uuid, g1, now_unix()).await.unwrap()
    else {
        panic!("expected a body");
    };
    assert!(g2 > g1);
    let doc = open_v2(&h.cmis, &signed);
    assert_eq!(doc.entries.len(), 1);
    let entry = &doc.entries[0];
    assert_eq!(entry.approval_id, id_bytes(&approval.approval_id));
    assert_eq!(entry.uid, Some(1000));
    assert_eq!(
        entry.path_hash,
        Some(ferro_svid::allowlist_v2::path_hash(
            &a.uuid,
            PATH.as_bytes()
        ))
    );
    assert_eq!(entry.expires_at, approval.expires_at);
    let text = String::from_utf8_lossy(&signed.clone()).to_string();
    assert!(
        !text.contains("alice") && !text.contains("/opt/tool"),
        "no personal data in the body"
    );
    assert!(h.audit_events().iter().any(|ev| matches!(ev,
        AuditEvent::AllowlistCompiled { host_uuid, generation, entry_count: 1, .. } if *host_uuid == a.uuid && *generation == g2)));

    // Unchanged: not modified. Another host gets its own (empty) body.
    assert_eq!(
        serve(&h.cmis, &a.uuid, g2, now_unix()).await.unwrap(),
        Served::NotModified {
            generation: g2,
            not_after: doc.not_after
        }
    );
    let Served::Body { signed: other, .. } = serve(&h.cmis, &b.uuid, 0, now_unix()).await.unwrap()
    else {
        panic!("expected a body");
    };
    assert!(open_v2(&h.cmis, &other).entries.is_empty());

    // Revocation: a higher generation without the entry.
    let now = now_unix();
    h.cmis
        .cluster()
        .app_revoke_approval(
            &Revoke {
                approval_id: approval.approval_id.clone(),
                admin_id: "admin-x".into(),
                reason_code: 1,
                expected_row_version: None,
            },
            now,
            now * 1000,
        )
        .await
        .unwrap();
    let Served::Body {
        generation: g3,
        signed,
        ..
    } = serve(&h.cmis, &a.uuid, g2, now_unix()).await.unwrap()
    else {
        panic!("expected a body");
    };
    assert!(g3 > g2);
    assert!(open_v2(&h.cmis, &signed).entries.is_empty());

    // Rollback protection: the store refuses a lower generation.
    let lowered = h
        .cmis
        .cluster()
        .client()
        .execute(
            format!(
                "UPDATE host_allowlist_state SET generation = 1 WHERE host_uuid = '{}'",
                a.uuid
            ),
            vec![],
        )
        .await;
    assert!(lowered.is_err(), "generation never decreases");

    // A document that does not accept v2 is refused.
    let mut doc = ferro_svid::app_docs::decode_allowlist_sync(&b.sync(0).doc).unwrap();
    doc.accept_formats = vec![1];
    let bytes = ferro_svid::app_docs::encode_allowlist_sync(&doc).unwrap();
    let req = ferro_proto::v1::SyncAllowlistRequest {
        auth: Some(b.auth(ferro_svid::app_docs::ALLOWLIST_SYNC_CONTEXT, &bytes)),
        doc: bytes,
    };
    let err =
        h.mi.sync_allowlist(tonic::Request::new(req))
            .await
            .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::InvalidArgument, "unsupported_format")
    );
}

#[tokio::test]
async fn legacy_mode_sync_serves_the_legacy_entries() {
    let (h, a, _) = setup("legacysync").await;
    let put = |entries: Vec<ferro_svid::AllowEntry>| {
        let now = now_unix();
        let signed = h
            .cmis
            .issuer
            .sign_allowlist(entries, now, now + DAY)
            .unwrap();
        ferro_svid::allowlist::encode(&signed).unwrap()
    };
    h.cmis
        .put_allowlist(
            &a.uuid,
            put(vec![ferro_svid::AllowEntry {
                uid: Some(1000),
                bin_sha: hex::encode(sha(9)),
            }]),
            now_unix(),
        )
        .await
        .unwrap();
    let Served::Body {
        generation: g1,
        signed,
        ..
    } = serve(&h.cmis, &a.uuid, 0, now_unix()).await.unwrap()
    else {
        panic!("expected a body");
    };
    let doc = open_v2(&h.cmis, &signed);
    assert_eq!(doc.entries.len(), 1);
    assert_eq!(doc.entries[0].approval_id, [0; 16]);
    assert_eq!(doc.entries[0].uid, Some(1000));
    assert_eq!(doc.entries[0].path_hash, None);

    // A changed legacy body moves the generation on.
    h.cmis
        .put_allowlist(&a.uuid, put(vec![]), now_unix())
        .await
        .unwrap();
    let Served::Body {
        generation: g2,
        signed,
        ..
    } = serve(&h.cmis, &a.uuid, g1, now_unix()).await.unwrap()
    else {
        panic!("expected a body");
    };
    assert!(g2 > g1);
    assert!(open_v2(&h.cmis, &signed).entries.is_empty());
}

#[tokio::test]
async fn the_sweeper_expires_stale_requests_and_approvals() {
    let (h, a, _) = setup("sweep").await;
    approvals_mode(&h.cmis).await;
    let cluster = h.cmis.cluster();
    let pending = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();
    let approved = submit(&h, &a, &a.app_doc(PATH, sha(2), 1001, "bob", 0))
        .await
        .unwrap();
    let approval = ledger_approve(
        &h.cmis,
        &approved.request_id,
        "admin-x",
        terms(UpdatePolicy::ManualEachTime, Some(now_unix() + DAY)),
    )
    .await;
    let before = cluster
        .app_allowlist_state(&a.uuid)
        .await
        .unwrap()
        .unwrap()
        .generation;

    // Nothing is due yet.
    let report = cmis::apps::sweep::run_once(&h.cmis, now_unix())
        .await
        .unwrap();
    assert_eq!(report, cmis::apps::sweep::SweepReport::default());

    let later = now_unix() + 31 * DAY;
    let report = cmis::apps::sweep::run_once(&h.cmis, later).await.unwrap();
    assert_eq!((report.requests_expired, report.approvals_expired), (1, 1));
    let r = cluster
        .app_request(&pending.request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.state, RequestState::Expired);
    let ap = cluster
        .app_approval(&approval.approval_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ap.state, ApprovalState::Expired);
    let revisions = cluster
        .app_approval_revisions(&approval.approval_id)
        .await
        .unwrap();
    assert_eq!(revisions.len(), 2, "creation and expiry");
    assert!(
        cluster
            .app_allowlist_state(&a.uuid)
            .await
            .unwrap()
            .unwrap()
            .generation
            > before
    );
    let audit = h.audit_events();
    assert_eq!(
        audit
            .iter()
            .filter(|e| matches!(e, AuditEvent::AppRequestExpired { .. }))
            .count(),
        1
    );
    assert_eq!(
        audit
            .iter()
            .filter(|e| matches!(e, AuditEvent::ApprovalExpired { .. }))
            .count(),
        1
    );

    // A second pass finds nothing.
    let report = cmis::apps::sweep::run_once(&h.cmis, later).await.unwrap();
    assert_eq!(report, cmis::apps::sweep::SweepReport::default());
}

async fn fail_writes(state: &Arc<CmisState>, table: &str, op: &str) {
    state
        .cluster()
        .client()
        .execute(
            format!(
                "CREATE TRIGGER fail_{op}_{table} BEFORE {op} ON {table} \
                 BEGIN SELECT RAISE(ABORT, 'injected store failure'); END"
            ),
            vec![],
        )
        .await
        .expect("trigger installed");
}

#[tokio::test]
async fn store_failures_answer_unavailable_and_audit_nothing() {
    let (h, a, _) = setup("storefail").await;
    approvals_mode(&h.cmis).await;
    let pending = submit(&h, &a, &a.app_doc(PATH, sha(1), 1000, "alice", 0))
        .await
        .unwrap();

    fail_writes(&h.cmis, "app_requests", "INSERT").await;
    let before = h.cmis.audit.len();
    let e = submit(&h, &a, &a.app_doc(PATH, sha(2), 1000, "alice", 0))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unavailable, "store_unavailable")
    );
    assert_eq!(h.cmis.audit.len(), before, "nothing audited");

    fail_writes(&h.cmis, "app_requests", "UPDATE").await;
    let e = cmis::apps::sweep::run_once(&h.cmis, now_unix() + 31 * DAY).await;
    assert!(e.is_err(), "the sweep reports the failure");
    assert_eq!(h.cmis.audit.len(), before, "nothing audited");
    let r = h
        .cmis
        .cluster()
        .app_request(&pending.request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.state, RequestState::Pending);
}
