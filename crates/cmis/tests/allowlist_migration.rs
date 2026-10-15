//! F19 §11 allowlist migration (M38, T272 and T273): the legacy import
//! (`ImportLegacyAllowlists`), the mode switch and rollback
//! (`SetAllowlistMode`), and what `approvals` mode changes for the legacy
//! RPCs — `SetAllowlist`/`DeleteAllowlist` refused, the lossy-safe v1
//! `GetAllowlist`, `ProposeAllowlist` as `observed` requests — against an
//! in-process CMIS through the F20 authorization (`METHOD_ACCESS`, step-up).
//!
//! Every write must emit its F19 event only after it committed; refusals and
//! dry runs change nothing and record no F19 event.

#![allow(clippy::large_futures, clippy::too_many_lines, clippy::assert_is_empty)]

mod support;

use std::sync::Arc;

use cmis::admin::authz::paths;
use cmis::CmisState;
use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::{
    approve_app_request_request::Choice, ApprovalTerms as WireTerms, ApproveAppRequestRequest,
    GetAllowlistModeRequest, GetAllowlistModeResponse, ImportLegacyAllowlistsRequest,
    ImportLegacyAllowlistsResponse, SetAllowlistModeRequest, SetAllowlistModeResponse,
};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::propose_allowlist_response::Outcome;
use ferro_proto::v1::sync_allowlist_response::Result as SyncResult;
use ferro_proto::v1::{
    AllowEntryMsg, AppRequestState, DeleteAllowlistRequest, GetAllowlistRequest,
    ProposeAllowlistRequest, SetAllowlistRequest,
};
use ferro_raft::apps::{
    legacy_approval_id, ApprovalChoice, ApprovalOrigin, ApprovalState, ApprovalTerms, Approve,
    Continuity, LegacyEntry, PathMatch, RequestFilter, RequestOrigin, RequestState, Revoke,
    UpdatePolicy, UserScope,
};
use ferro_sep::MachineKey as _;
use ferro_svid::allowlist::{self, AllowEntry, ProposalDoc};
use support::hosts::{mint_host, now_unix, open_v2, Host};
use support::{Admin1, Harness};
use tonic::Code;

const DAY: i64 = 86_400;
const PATH: &str = "/opt/tool/bin/tool";

fn sha(n: u8) -> String {
    hex::encode([n; 48])
}

fn entry(uid: Option<u32>, bin_sha: &str) -> AllowEntry {
    AllowEntry {
        uid,
        bin_sha: bin_sha.into(),
    }
}

struct World {
    h: Harness,
    root: Admin1,
    token: String,
    a: Host,
    b: Host,
}

async fn world(tag: &str) -> World {
    world_cfg(tag, |_| {}).await
}

async fn world_cfg(tag: &str, tweak: impl FnOnce(&mut cmis::CmisConfig)) -> World {
    let h = support::harness_cfg(tag, tweak, |_| {}).await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let a = mint_host(&h.cmis.issuer, 0x71, "p1");
    let b = mint_host(&h.cmis.issuer, 0x72, "p1");
    World {
        h,
        root,
        token,
        a,
        b,
    }
}

/// Store a signed legacy v1 body for `host_uuid`, as `SetAllowlist` does.
async fn put_legacy(state: &CmisState, host_uuid: &str, entries: Vec<AllowEntry>) -> Vec<u8> {
    let now = now_unix();
    let signed = state
        .issuer
        .sign_allowlist(entries, now, now + DAY)
        .unwrap();
    let bytes = allowlist::encode(&signed).unwrap();
    state
        .put_allowlist(host_uuid, bytes.clone(), now)
        .await
        .unwrap();
    bytes
}

async fn legacy_row(state: &CmisState, host_uuid: &str) -> Option<Vec<u8>> {
    state
        .cluster()
        .fetch_allowlist_consistent(host_uuid)
        .await
        .unwrap()
}

async fn import(
    w: &World,
    token: &str,
    dry_run: bool,
) -> Result<ImportLegacyAllowlistsResponse, tonic::Status> {
    w.h.call(
        token,
        paths::IMPORT_LEGACY_ALLOWLISTS,
        ImportLegacyAllowlistsRequest {
            idempotency_key: String::new(),
            dry_run,
        },
        |svc, r| Box::pin(async move { svc.import_legacy_allowlists(r).await }),
    )
    .await
}

#[derive(Default, Clone, Copy)]
struct Switch {
    dry_run: bool,
    confirm_rollback: bool,
    allow_unimported: bool,
}

async fn set_mode(
    w: &World,
    token: &str,
    mode: u32,
    s: Switch,
) -> Result<SetAllowlistModeResponse, tonic::Status> {
    w.h.call(
        token,
        paths::SET_ALLOWLIST_MODE,
        SetAllowlistModeRequest {
            idempotency_key: String::new(),
            mode,
            dry_run: s.dry_run,
            confirm_rollback: s.confirm_rollback,
            allow_unimported: s.allow_unimported,
        },
        |svc, r| Box::pin(async move { svc.set_allowlist_mode(r).await }),
    )
    .await
}

async fn get_mode(w: &World, token: &str) -> GetAllowlistModeResponse {
    w.h.call(
        token,
        paths::GET_ALLOWLIST_MODE,
        GetAllowlistModeRequest {},
        |svc, r| Box::pin(async move { svc.get_allowlist_mode(r).await }),
    )
    .await
    .unwrap()
}

/// The F19 §11 events recorded so far.
fn migration_events(h: &Harness) -> Vec<AuditEvent> {
    h.audit_events()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                AuditEvent::AllowlistImported { .. } | AuditEvent::AllowlistModeChanged { .. }
            )
        })
        .collect()
}

async fn v1_body(h: &Harness, host_uuid: &str) -> Result<Vec<u8>, tonic::Status> {
    h.mi.get_allowlist(tonic::Request::new(GetAllowlistRequest {
        host_uuid: host_uuid.into(),
        accept_formats: Vec::new(),
    }))
    .await
    .map(|r| r.into_inner().signed_allowlist)
}

/// The verified entries of a served v1 body, sorted.
fn v1_entries(h: &Harness, body: &[u8]) -> Vec<(Option<u32>, String)> {
    let signed = allowlist::decode(body).unwrap();
    let doc = allowlist::verify(&signed, h.cmis.issuer.public_key()).unwrap();
    let mut out: Vec<_> = doc
        .entries
        .into_iter()
        .map(|e| (e.uid, e.bin_sha))
        .collect();
    out.sort();
    out
}

async fn approve_ledger(
    state: &CmisState,
    request_id: &str,
    path_match: PathMatch,
    expires_at: Option<i64>,
) {
    let now = now_unix();
    state
        .cluster()
        .app_approve_request(&Approve {
            request_id: request_id.into(),
            admin_id: "admin-x".into(),
            now,
            choice: ApprovalChoice::New {
                approval_id: uuid::Uuid::now_v7().to_string(),
                terms: ApprovalTerms {
                    user_scope: UserScope::ExactUser,
                    path_match,
                    update_policy: UpdatePolicy::ManualEachTime,
                    continuity: Continuity::Anchored,
                    expires_at,
                    note: None,
                },
            },
            forbid_self_approval: false,
            also_revoke: vec![],
            generation_millis: now * 1000,
        })
        .await
        .unwrap();
}

async fn submit(w: &World, host: &Host, path: &str, n: u8, uid: u32) -> String {
    let doc = host.app_doc(path, [n; 48], uid, "alice", 0);
    let r =
        w.h.mi
            .submit_app_request(tonic::Request::new(host.submit(&doc)))
            .await
            .unwrap()
            .into_inner();
    assert_eq!(r.state, AppRequestState::Pending as i32);
    r.request_id
}

/// The legacy fleet of the tests: two hosts and a row under a key that is
/// not a host UUID.
async fn legacy_fleet(w: &World) -> (Vec<u8>, Vec<u8>) {
    let a = put_legacy(
        &w.h.cmis,
        &w.a.uuid,
        vec![
            entry(Some(1000), &sha(1)),
            entry(None, &sha(2)),
            entry(Some(1001), "*"),
            entry(Some(1000), &sha(1)),
        ],
    )
    .await;
    let b = put_legacy(&w.h.cmis, &w.b.uuid, vec![entry(Some(2000), &sha(3))]).await;
    put_legacy(&w.h.cmis, "not-a-host", vec![entry(None, "*")]).await;
    (a, b)
}

#[tokio::test]
async fn a_dry_run_reports_the_import_and_writes_nothing() {
    let w = world("mig-dry").await;
    let (body_a, body_b) = legacy_fleet(&w).await;
    let audit_before = w.h.cmis.audit.len();

    let r = import(&w, &w.token, true).await.unwrap();
    assert!(r.dry_run);
    assert_eq!(r.approvals_created, 0);
    assert_eq!(r.entries_to_create, 4, "duplicates are one entry");
    assert_eq!(r.entries_already_imported, 0);
    assert_eq!(r.hosts_skipped, 1);
    let host = |uuid: &str| r.hosts.iter().find(|h| h.host_uuid == uuid).unwrap();
    let a = host(&w.a.uuid);
    assert_eq!((a.entries_to_create, a.entries_already_imported), (3, 0));
    assert!(a.skipped.is_empty());
    let mut listed: Vec<_> = a
        .entries
        .iter()
        .map(|e| (e.uid, e.bin_sha.clone()))
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            (None, sha(2)),
            (Some(1000), sha(1)),
            (Some(1001), "*".to_string())
        ],
        "uid and the wildcard exactly as stored"
    );
    assert!(a.entries.iter().all(|e| !e.already_imported));
    assert_eq!(host("not-a-host").skipped, "not_a_host_uuid");

    // Nothing was written: no approval, no generation, legacy rows as they were.
    let cluster = w.h.cmis.cluster();
    for uuid in [&w.a.uuid, &w.b.uuid] {
        assert!(!cluster.app_host_has_approvals(uuid).await.unwrap());
        assert_eq!(cluster.app_allowlist_state(uuid).await.unwrap(), None);
    }
    assert_eq!(legacy_row(&w.h.cmis, &w.a.uuid).await, Some(body_a));
    assert_eq!(legacy_row(&w.h.cmis, &w.b.uuid).await, Some(body_b));
    assert!(migration_events(&w.h).is_empty());
    // Only the layer's record of the authorized call.
    let new: Vec<_> = w.h.audit_events().into_iter().skip(audit_before).collect();
    assert!(
        new.iter()
            .all(|e| matches!(e, AuditEvent::AdminCallAuthorized { .. })),
        "{new:?}"
    );
}

#[tokio::test]
async fn the_import_creates_the_approvals_once_and_keeps_the_legacy_rows() {
    let w = world("mig-import").await;
    let (body_a, body_b) = legacy_fleet(&w).await;

    let r = import(&w, &w.token, false).await.unwrap();
    assert!(!r.dry_run);
    assert_eq!(r.approvals_created, 4);
    let a = r.hosts.iter().find(|h| h.host_uuid == w.a.uuid).unwrap();
    assert_eq!(a.approvals_created, 3);
    assert!(
        a.allowlist_generation > 0,
        "the host's compile is invalidated"
    );

    let cluster = w.h.cmis.cluster();
    let live = cluster
        .app_live_approvals(&w.a.uuid, now_unix())
        .await
        .unwrap();
    assert_eq!(live.len(), 3);
    for l in &live {
        let ap = &l.approval;
        assert_eq!(ap.origin, ApprovalOrigin::LegacyImport);
        assert_eq!(ap.path_match, PathMatch::Any);
        assert_eq!(ap.update_policy, UpdatePolicy::ManualEachTime);
        assert_eq!(ap.expires_at, None);
        assert_eq!(ap.approved_by_admin_id, None);
    }
    let wildcard = cluster
        .app_approval(&legacy_approval_id(
            &w.a.uuid,
            &LegacyEntry::new(Some(1001), "*").unwrap(),
        ))
        .await
        .unwrap()
        .expect("the wildcard entry is imported");
    assert_eq!((wildcard.bin_sha.as_str(), wildcard.uid), ("*", Some(1001)));

    // One event per host that gained approvals, naming the importer.
    let events = migration_events(&w.h);
    assert_eq!(events.len(), 2, "{events:?}");
    for e in &events {
        let AuditEvent::AllowlistImported {
            host_uuid,
            approvals_created,
            admin_id,
        } = e
        else {
            panic!("{e:?}");
        };
        assert_eq!(admin_id, &w.root.admin_id);
        let want = if host_uuid == &w.a.uuid { 3 } else { 1 };
        assert_eq!(*approvals_created, want);
    }

    // The legacy rows are kept, untouched, for a rollback.
    assert_eq!(legacy_row(&w.h.cmis, &w.a.uuid).await, Some(body_a));
    assert_eq!(legacy_row(&w.h.cmis, &w.b.uuid).await, Some(body_b));

    // Idempotent: a re-run creates nothing and records nothing.
    let generation = cluster
        .app_allowlist_state(&w.a.uuid)
        .await
        .unwrap()
        .unwrap()
        .generation;
    let again = import(&w, &w.token, false).await.unwrap();
    assert_eq!(again.approvals_created, 0);
    assert_eq!(again.entries_to_create, 0);
    assert_eq!(again.entries_already_imported, 4);
    assert_eq!(migration_events(&w.h).len(), 2);
    assert_eq!(
        cluster
            .app_allowlist_state(&w.a.uuid)
            .await
            .unwrap()
            .unwrap()
            .generation,
        generation
    );
    let dry = import(&w, &w.token, true).await.unwrap();
    assert!(dry.hosts.iter().all(|h| h.entries_to_create == 0));
}

#[tokio::test]
async fn only_platform_operators_with_a_fresh_step_up_import_or_switch() {
    let w = world("mig-authz").await;
    put_legacy(&w.h.cmis, &w.a.uuid, vec![entry(Some(1000), &sha(1))]).await;

    // No session context at all: the handler guard fails closed.
    let e =
        w.h.svc
            .import_legacy_allowlists(tonic::Request::new(ImportLegacyAllowlistsRequest::default()))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "session_invalid")
    );
    let e =
        w.h.svc
            .set_allowlist_mode(tonic::Request::new(SetAllowlistModeRequest {
                mode: 2,
                ..SetAllowlistModeRequest::default()
            }))
            .await
            .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);

    // An approver may read the mode, but neither import nor switch.
    let approver =
        w.h.create_and_enroll(&w.root, &w.token, "approver.one", &["ferrogate-approvers"])
            .await;
    let at = w.h.login(&approver).await;
    assert_eq!(get_mode(&w, &at).await.mode, 1);
    for e in [
        import(&w, &at, true).await.unwrap_err(),
        import(&w, &at, false).await.unwrap_err(),
        set_mode(&w, &at, 2, Switch::default()).await.unwrap_err(),
    ] {
        assert_eq!(
            (e.code(), e.message()),
            (Code::PermissionDenied, "permission_denied")
        );
    }

    // A platform operator whose second factor is not recent must step up.
    w.h.clock.advance(400);
    for e in [
        import(&w, &w.token, false).await.unwrap_err(),
        set_mode(
            &w,
            &w.token,
            2,
            Switch {
                allow_unimported: true,
                ..Switch::default()
            },
        )
        .await
        .unwrap_err(),
    ] {
        assert_eq!(
            (e.code(), e.message()),
            (Code::FailedPrecondition, "step_up_required")
        );
    }

    // Nothing changed.
    assert!(!w
        .h
        .cmis
        .cluster()
        .app_host_has_approvals(&w.a.uuid)
        .await
        .unwrap());
    assert_eq!(
        cmis::apps::mode::current(w.h.cmis.cluster()).await.unwrap(),
        cmis::apps::AllowlistMode::Legacy
    );
    assert!(migration_events(&w.h).is_empty());
}

#[tokio::test]
async fn approvals_mode_needs_the_import_and_retires_the_legacy_writes() {
    let w = world("mig-switch").await;
    let body = put_legacy(&w.h.cmis, &w.a.uuid, vec![entry(Some(1000), &sha(1))]).await;

    // Not imported yet: refused, unless the operator explicitly allows it.
    let e = set_mode(&w, &w.token, 2, Switch::default())
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "import_incomplete")
    );
    let dry = set_mode(
        &w,
        &w.token,
        2,
        Switch {
            dry_run: true,
            ..Switch::default()
        },
    )
    .await
    .unwrap();
    assert_eq!((dry.entries_not_imported, dry.hosts_not_imported), (1, 1));
    assert!(!dry.changed);
    assert_eq!(get_mode(&w, &w.token).await.mode, 1);

    import(&w, &w.token, false).await.unwrap();
    let r = set_mode(&w, &w.token, 2, Switch::default()).await.unwrap();
    assert!(r.changed);
    assert_eq!((r.previous_mode, r.mode), (1, 2));
    assert_eq!(r.entries_not_imported, 0);
    assert_eq!(get_mode(&w, &w.token).await.mode, 2);
    let switched = |h: &Harness| {
        migration_events(h)
            .into_iter()
            .filter(|e| matches!(e, AuditEvent::AllowlistModeChanged { .. }))
            .collect::<Vec<_>>()
    };
    let events = switched(&w.h);
    assert_eq!(events.len(), 1);
    let AuditEvent::AllowlistModeChanged {
        old_mode,
        new_mode,
        admin_id,
        ..
    } = &events[0]
    else {
        unreachable!();
    };
    assert_eq!(
        (old_mode.as_str(), new_mode.as_str(), admin_id),
        ("legacy", "approvals", &w.root.admin_id)
    );

    // The same mode again is a no-op, not audited.
    let same = set_mode(&w, &w.token, 2, Switch::default()).await.unwrap();
    assert!(!same.changed);
    assert_eq!(switched(&w.h).len(), 1);

    // The legacy writes are refused; the legacy body stays for a rollback.
    let req =
        w.h.authorized(
            &w.token,
            paths::SET_ALLOWLIST,
            SetAllowlistRequest {
                host_uuid: w.a.uuid.clone(),
                entries: vec![AllowEntryMsg {
                    uid: Some(7),
                    bin_sha: "*".into(),
                }],
                ttl_secs: 0,
            },
            support::local_ip(),
        )
        .await
        .unwrap();
    let e = w.h.mi.set_allowlist(req).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "mode_approvals")
    );
    let req =
        w.h.authorized(
            &w.token,
            paths::DELETE_ALLOWLIST,
            DeleteAllowlistRequest {
                host_uuid: w.a.uuid.clone(),
            },
            support::local_ip(),
        )
        .await
        .unwrap();
    let e = w.h.mi.delete_allowlist(req).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "mode_approvals")
    );
    assert_eq!(legacy_row(&w.h.cmis, &w.a.uuid).await, Some(body));

    // F19 intake is open, and SyncAllowlist serves the imported approvals.
    submit(&w, &w.a, PATH, 9, 1000).await;
    let resp =
        w.h.mi
            .sync_allowlist(tonic::Request::new(w.a.sync(0)))
            .await
            .unwrap()
            .into_inner();
    let Some(SyncResult::SignedAllowlistV2(envelope)) = resp.result else {
        panic!("expected a body: {resp:?}");
    };
    let doc = open_v2(&w.h.cmis, &envelope);
    assert_eq!(doc.entries.len(), 1);
    let e = &doc.entries[0];
    let id = legacy_approval_id(&w.a.uuid, &LegacyEntry::new(Some(1000), &sha(1)).unwrap());
    assert_eq!(
        e.approval_id,
        *uuid::Uuid::parse_str(&id).unwrap().as_bytes()
    );
    assert_eq!((e.uid, e.bin_sha.as_str()), (Some(1000), sha(1).as_str()));
    assert_eq!(
        (e.path_hash, e.user_sid_hash, e.expires_at),
        (None, None, None)
    );
}

#[tokio::test]
async fn v1_get_allowlist_serves_the_lossy_safe_compile_of_the_approvals() {
    let w = world("mig-v1").await;
    put_legacy(&w.h.cmis, &w.a.uuid, vec![entry(Some(1000), &sha(1))]).await;
    import(&w, &w.token, false).await.unwrap();
    set_mode(&w, &w.token, 2, Switch::default()).await.unwrap();

    let now = now_unix();
    // Exact path: an old agent cannot enforce it, so it is omitted.
    let exact = submit(&w, &w.a, "/opt/a", 2, 1001).await;
    approve_ledger(&w.h.cmis, &exact, PathMatch::Exact, Some(now + 180 * DAY)).await;
    // Any path, valid past the document's not_after: included.
    let any = submit(&w, &w.a, "/opt/b", 3, 1002).await;
    approve_ledger(&w.h.cmis, &any, PathMatch::Any, Some(now + 180 * DAY)).await;
    // Any path but expiring before the document would: omitted.
    let soon = submit(&w, &w.a, "/opt/c", 4, 1003).await;
    approve_ledger(&w.h.cmis, &soon, PathMatch::Any, Some(now + 3600)).await;

    let body = v1_body(&w.h, &w.a.uuid).await.unwrap();
    assert_eq!(
        v1_entries(&w.h, &body),
        vec![(Some(1000), sha(1)), (Some(1002), sha(3))],
        "the legacy import and the any-path approval only"
    );
    assert_eq!(
        v1_body(&w.h, &w.a.uuid).await.unwrap(),
        body,
        "an unchanged entry set is served from the cache"
    );

    // A revocation reaches old agents at once (a new, signed body).
    let id = legacy_approval_id(&w.a.uuid, &LegacyEntry::new(Some(1000), &sha(1)).unwrap());
    w.h.cmis
        .cluster()
        .app_revoke_approval(
            &Revoke {
                approval_id: id,
                admin_id: "admin-x".into(),
                reason_code: 3,
                expected_row_version: None,
            },
            now,
            now * 1000,
        )
        .await
        .unwrap();
    let body = v1_body(&w.h, &w.a.uuid).await.unwrap();
    assert_eq!(v1_entries(&w.h, &body), vec![(Some(1002), sha(3))]);

    // A host nothing is known about still gets "not provisioned".
    assert!(v1_body(&w.h, &w.b.uuid).await.unwrap().is_empty());
    let e = v1_body(&w.h, &"x".repeat(65)).await.unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn v1_get_allowlist_is_refused_once_turned_off() {
    let w = world_cfg("mig-v1-off", |c| c.apps.legacy_get_allowlist = false).await;
    put_legacy(&w.h.cmis, &w.a.uuid, vec![entry(Some(1000), &sha(1))]).await;
    let refused = |e: tonic::Status| {
        assert_eq!(
            (e.code(), e.message()),
            (Code::FailedPrecondition, "legacy_getallowlist_disabled")
        );
    };
    refused(v1_body(&w.h, &w.a.uuid).await.unwrap_err());
    import(&w, &w.token, false).await.unwrap();
    set_mode(&w, &w.token, 2, Switch::default()).await.unwrap();
    refused(v1_body(&w.h, &w.a.uuid).await.unwrap_err());
    assert!(!get_mode(&w, &w.token).await.legacy_get_allowlist);
}

#[tokio::test]
async fn a_rollback_reports_what_changes_and_serves_the_preserved_legacy_body() {
    let w = world("mig-rollback").await;
    let body = put_legacy(&w.h.cmis, &w.a.uuid, vec![entry(Some(1000), &sha(1))]).await;
    import(&w, &w.token, false).await.unwrap();
    set_mode(&w, &w.token, 2, Switch::default()).await.unwrap();

    // After the switch: one new approval, and the import revoked.
    let req = submit(&w, &w.a, PATH, 5, 1000).await;
    approve_ledger(
        &w.h.cmis,
        &req,
        PathMatch::Exact,
        Some(now_unix() + 180 * DAY),
    )
    .await;
    let id = legacy_approval_id(&w.a.uuid, &LegacyEntry::new(Some(1000), &sha(1)).unwrap());
    w.h.cmis
        .cluster()
        .app_revoke_approval(
            &Revoke {
                approval_id: id,
                admin_id: "admin-x".into(),
                reason_code: 3,
                expected_row_version: None,
            },
            now_unix(),
            now_unix() * 1000,
        )
        .await
        .unwrap();

    // Without confirmation nothing changes.
    let e = set_mode(&w, &w.token, 1, Switch::default())
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "confirmation_required")
    );
    let dry = set_mode(
        &w,
        &w.token,
        1,
        Switch {
            dry_run: true,
            ..Switch::default()
        },
    )
    .await
    .unwrap();
    assert!(!dry.changed);
    assert_eq!((dry.previous_mode, dry.mode), (2, 2));
    assert_eq!(dry.approvals_not_reflected, 1);
    assert_eq!(dry.imports_readmitted, 1);
    assert_eq!(get_mode(&w, &w.token).await.mode, 2);

    let r = set_mode(
        &w,
        &w.token,
        1,
        Switch {
            confirm_rollback: true,
            ..Switch::default()
        },
    )
    .await
    .unwrap();
    assert!(r.changed);
    assert_eq!((r.previous_mode, r.mode), (2, 1));
    let last = migration_events(&w.h).pop().unwrap();
    assert_eq!(
        last,
        AuditEvent::AllowlistModeChanged {
            old_mode: "approvals".into(),
            new_mode: "legacy".into(),
            admin_id: w.root.admin_id.clone(),
            session_ref: match &last {
                AuditEvent::AllowlistModeChanged { session_ref, .. } => session_ref.clone(),
                _ => unreachable!(),
            },
            approvals_not_reflected: 1,
            imports_readmitted: 1,
            entries_not_imported: 0,
        }
    );

    // The preserved legacy body is served again, byte for byte, and the
    // legacy writes work again.
    assert_eq!(v1_body(&w.h, &w.a.uuid).await.unwrap(), body);
    let req =
        w.h.authorized(
            &w.token,
            paths::DELETE_ALLOWLIST,
            DeleteAllowlistRequest {
                host_uuid: w.b.uuid.clone(),
            },
            support::local_ip(),
        )
        .await
        .unwrap();
    assert!(
        !w.h.mi
            .delete_allowlist(req)
            .await
            .unwrap()
            .into_inner()
            .existed
    );
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
    let w = world("mig-store").await;
    let body = put_legacy(&w.h.cmis, &w.a.uuid, vec![entry(Some(1000), &sha(1))]).await;

    fail_writes(&w.h.cmis, "app_approvals", "INSERT").await;
    let e = import(&w, &w.token, false).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unavailable, "store_unavailable")
    );
    assert!(!w
        .h
        .cmis
        .cluster()
        .app_host_has_approvals(&w.a.uuid)
        .await
        .unwrap());
    assert_eq!(legacy_row(&w.h.cmis, &w.a.uuid).await, Some(body));

    fail_writes(&w.h.cmis, "cmis_settings", "INSERT").await;
    fail_writes(&w.h.cmis, "cmis_settings", "UPDATE").await;
    let e = set_mode(
        &w,
        &w.token,
        2,
        Switch {
            allow_unimported: true,
            ..Switch::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unavailable, "store_unavailable")
    );
    assert_eq!(get_mode(&w, &w.token).await.mode, 1);
    assert!(migration_events(&w.h).is_empty(), "nothing audited");
}

/// A pre-F19 agent's `ProposeAllowlist` from host `host`.
fn proposal(host: &Host, entries: Vec<AllowEntry>) -> ProposeAllowlistRequest {
    let doc = ProposalDoc {
        host_uuid: host.uuid.clone(),
        issued_at: now_unix(),
        entries,
    };
    let body = allowlist::encode_proposal(&doc).unwrap();
    let sig = host
        .key
        .sign(&allowlist::proposal_signing_input(&body))
        .unwrap();
    ProposeAllowlistRequest {
        signed_proposal: body,
        proposal_sig: sig,
        svid_jws: host.jws.clone(),
        sep_pub: host.key.public_spki_der(),
    }
}

#[tokio::test]
async fn proposals_become_observed_requests_and_are_never_adopted() {
    let w = world("mig-propose").await;
    support::hosts::approvals_mode(&w.h.cmis).await;
    let cluster = w.h.cmis.cluster();
    // Covered already: a legacy import of (1002, sha 3).
    cluster
        .app_import_legacy(
            &w.a.uuid,
            &[LegacyEntry::new(Some(1002), &sha(3)).unwrap()],
            "admin-x",
            now_unix(),
            now_unix() * 1000,
        )
        .await
        .unwrap();
    let entries = vec![
        entry(Some(1000), &sha(1)),
        entry(None, &sha(2)),   // MIA's own self-registration entry
        entry(Some(1001), "*"), // a wildcard is never a request
        entry(Some(1002), &sha(3)),
    ];

    let r =
        w.h.mi
            .propose_allowlist(tonic::Request::new(proposal(&w.a, entries.clone())))
            .await
            .unwrap()
            .into_inner();
    assert_eq!(r.outcome, Outcome::Pending as i32);
    let requests = || async {
        cluster
            .app_list_requests(&RequestFilter {
                host_uuids: vec![w.a.uuid.clone()],
                ..RequestFilter::default()
            })
            .await
            .unwrap()
    };
    let listed = requests().await;
    assert_eq!(
        listed.len(),
        1,
        "one observed request, for the one new entry"
    );
    let req = &listed[0].request;
    assert_eq!(req.origin, RequestOrigin::Observed);
    assert_eq!(req.state, RequestState::Pending);
    assert_eq!(
        (req.bin_sha.as_str(), req.target.uid),
        (sha(1).as_str(), Some(1000))
    );
    assert_eq!(
        listed[0].canonical_path,
        cmis::apps::proposals::UNKNOWN_PATH
    );

    // No TOFU adoption, no legacy body, no queued proposal.
    assert_eq!(legacy_row(&w.h.cmis, &w.a.uuid).await, None);
    assert!(w.h.cmis.list_proposals().await.is_empty());
    let events = w.h.audit_events();
    assert!(!events.iter().any(|e| matches!(
        e,
        AuditEvent::AllowlistAutoAdopted { .. } | AuditEvent::AllowlistProposed { .. }
    )));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, AuditEvent::AppRequestSubmitted { .. }))
            .count(),
        1
    );

    // The same proposal again is deduplicated onto the open request.
    let r =
        w.h.mi
            .propose_allowlist(tonic::Request::new(proposal(&w.a, entries.clone())))
            .await
            .unwrap()
            .into_inner();
    assert_eq!(r.outcome, Outcome::Pending as i32);
    assert_eq!(requests().await.len(), 1);

    // The path is unknown: an approver must choose an any-path scope.
    let approve = |path_match: u32| ApproveAppRequestRequest {
        idempotency_key: String::new(),
        request_id: req.request_id.clone(),
        choice: Some(Choice::Terms(WireTerms {
            path_match,
            ..WireTerms::default()
        })),
        also_revoke_approval_ids: vec![],
        also_revoke_reason_code: 0,
        proof: None,
    };
    let call = |msg: ApproveAppRequestRequest| {
        w.h.call(&w.token, paths::APPROVE_APP_REQUEST, msg, |svc, r| {
            Box::pin(async move { svc.approve_app_request(r).await })
        })
    };
    let e = call(approve(1)).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::InvalidArgument, "path_unknown")
    );
    let approved = call(approve(2)).await.unwrap();
    let approval = approved.approval.unwrap();
    assert_eq!(approval.path_match, 2);
    assert_eq!(
        cluster
            .app_approval(&approval.approval_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ApprovalState::Active
    );

    // Now every entry is admitted: nothing new is asked for.
    let r =
        w.h.mi
            .propose_allowlist(tonic::Request::new(proposal(&w.a, entries)))
            .await
            .unwrap()
            .into_inner();
    assert_eq!(r.outcome, Outcome::Unchanged as i32);
    assert_eq!(requests().await.len(), 1);
}

#[tokio::test]
async fn an_oversized_proposal_is_refused_before_any_work() {
    let w = world("mig-propose-big").await;
    support::hosts::approvals_mode(&w.h.cmis).await;
    let n = cmis::apps::proposals::MAX_PROPOSAL_ENTRIES + 1;
    let entries = (0..n)
        .map(|i| entry(Some(u32::try_from(i).unwrap()), &sha(1)))
        .collect();
    let e =
        w.h.mi
            .propose_allowlist(tonic::Request::new(proposal(&w.a, entries)))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::InvalidArgument, "too_many_entries")
    );
    let listed =
        w.h.cmis
            .cluster()
            .app_list_requests(&RequestFilter::default())
            .await
            .unwrap();
    assert!(listed.is_empty());
}

/// Security review (M38): a binary an operator removes from a legacy body
/// after the import must not come back in approvals mode. The switch refuses
/// while such a stale import is open, and the import revokes it.
#[tokio::test]
async fn imports_whose_entry_left_the_legacy_body_are_revoked_before_the_switch() {
    let w = world("mig-stale").await;
    put_legacy(
        &w.h.cmis,
        &w.a.uuid,
        vec![entry(Some(1000), &sha(1)), entry(Some(1001), &sha(2))],
    )
    .await;
    put_legacy(&w.h.cmis, &w.b.uuid, vec![entry(Some(2000), &sha(3))]).await;
    import(&w, &w.token, false).await.unwrap();

    // Still in legacy mode: drop sha 2 from host A, and host B's body.
    let req =
        w.h.authorized(
            &w.token,
            paths::SET_ALLOWLIST,
            SetAllowlistRequest {
                host_uuid: w.a.uuid.clone(),
                entries: vec![AllowEntryMsg {
                    uid: Some(1000),
                    bin_sha: sha(1),
                }],
                ttl_secs: 0,
            },
            support::local_ip(),
        )
        .await
        .unwrap();
    w.h.mi.set_allowlist(req).await.unwrap();
    let req =
        w.h.authorized(
            &w.token,
            paths::DELETE_ALLOWLIST,
            DeleteAllowlistRequest {
                host_uuid: w.b.uuid.clone(),
            },
            support::local_ip(),
        )
        .await
        .unwrap();
    assert!(
        w.h.mi
            .delete_allowlist(req)
            .await
            .unwrap()
            .into_inner()
            .existed
    );

    // The switch refuses, even when unimported entries are allowed.
    let dry = set_mode(
        &w,
        &w.token,
        2,
        Switch {
            dry_run: true,
            ..Switch::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(dry.stale_imports, 2);
    let e = set_mode(
        &w,
        &w.token,
        2,
        Switch {
            allow_unimported: true,
            ..Switch::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "import_stale")
    );

    // The dry run shows what the import will revoke; the import revokes it.
    let plan = import(&w, &w.token, true).await.unwrap();
    assert_eq!(plan.stale_imports, 2);
    let line = |r: &ImportLegacyAllowlistsResponse, uuid: &str| {
        r.hosts
            .iter()
            .find(|h| h.host_uuid == uuid)
            .cloned()
            .unwrap()
    };
    assert_eq!(line(&plan, &w.a.uuid).stale_imports, 1);
    assert_eq!(
        line(&plan, &w.b.uuid).stale_imports,
        1,
        "a deleted body too"
    );
    let before = w.h.audit_events().len();
    let r = import(&w, &w.token, false).await.unwrap();
    assert_eq!(
        (r.imports_revoked, r.approvals_created, r.stale_imports),
        (2, 0, 0)
    );
    let revoked: Vec<_> =
        w.h.audit_events()
            .into_iter()
            .skip(before)
            .filter_map(|e| match e {
                AuditEvent::ApprovalRevoked {
                    admin_id,
                    reason_code,
                    ..
                } => Some((admin_id, reason_code)),
                _ => None,
            })
            .collect();
    assert_eq!(
        revoked,
        vec![(w.root.admin_id.clone(), 1000); 2],
        "one event per revoked import, naming the importer"
    );
    let removed = legacy_approval_id(&w.a.uuid, &LegacyEntry::new(Some(1001), &sha(2)).unwrap());
    let row =
        w.h.cmis
            .cluster()
            .app_approval(&removed)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, ApprovalState::Revoked);
    assert_eq!(
        row.revoke_reason_code,
        Some(cmis::apps::migration::LEGACY_ENTRY_REMOVED)
    );
    // Idempotent: nothing left to revoke.
    let again = import(&w, &w.token, false).await.unwrap();
    assert_eq!(again.imports_revoked, 0);

    // Now the switch goes through, and the removed binary stays out.
    set_mode(&w, &w.token, 2, Switch::default()).await.unwrap();
    let body = v1_body(&w.h, &w.a.uuid).await.unwrap();
    assert_eq!(v1_entries(&w.h, &body), vec![(Some(1000), sha(1))]);
    let body = v1_body(&w.h, &w.b.uuid).await.unwrap();
    assert_eq!(
        v1_entries(&w.h, &body),
        vec![],
        "a known host gets a signed empty body"
    );
}
