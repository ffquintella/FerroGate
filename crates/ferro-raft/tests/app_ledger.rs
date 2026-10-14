//! The F19 app approval ledger on a real single-node cluster: sequential
//! revisions, the non-replacement invariant (ADR-0004 INV-1 to INV-3) in the
//! store API **and** in the database triggers, auto-update eligibility,
//! decisions, versioned approval edits, the allowlist generation and search.

#![allow(clippy::too_many_lines)] // each test walks one scenario end to end.

use ferro_raft::apps::{
    dedup_key, ApprovalChoice, ApprovalEdit, ApprovalFilter, ApprovalSnapshot, ApprovalState,
    ApprovalTerms, Approve, AutoChecks, AutoDowngradeReason, AutoIntake, Continuity, Cursor, Deny,
    Intake, IntakeChecks, LineageRow, NewRequest, ObservedBinary, PathMatch, RequestFilter,
    RequestOrigin, RequestState, RevisionChange, Revoke, UpdatePolicy, UserIdentity, UserKind,
    UserScope, FLAG_PATH_PROTECTED,
};
use ferro_raft::{Cluster, LedgerError};
use hiqlite::Param;

const HOST: &str = "8d5e0000-0000-4000-8000-000000000001";
const OTHER_HOST: &str = "8d5e0000-0000-4000-8000-000000000002";
const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

struct Dir(std::path::PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn cluster(tag: &str) -> (Cluster, Dir) {
    let dir =
        std::env::temp_dir().join(format!("ferrogate-raft-apps-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let c = Cluster::start_single_node(dir.to_string_lossy().into_owned())
        .await
        .unwrap();
    (c, Dir(dir))
}

fn sha(n: u8) -> String {
    format!("{n:02x}").repeat(48)
}

fn user(uid: i64, name: &str) -> UserIdentity {
    UserIdentity {
        kind: UserKind::Unix,
        uid: Some(uid),
        sid: None,
        user_name: Some(name.into()),
    }
}

fn observed(host: &str, path: &str, n: u8) -> ObservedBinary {
    ObservedBinary {
        host_uuid: host.into(),
        platform: 1,
        canonical_path: path.into(),
        path_key: path.as_bytes().to_vec(),
        new_lineage_id: format!("lin-{host}-{path}"),
        bin_sha: sha(n),
        file_size: 1000 + i64::from(n),
        format: 1,
        declared_version: Some(format!("1.{n}")),
        version_source: 5,
        product_name: Some("Tool".into()),
        bundle_id: None,
        package_name: Some("tool".into()),
        signer_kind: 0,
        signer_id: None,
        signer_subject: None,
        signer_valid: false,
        seen_at: NOW,
    }
}

/// Observe `(path, n)` and build a request for it from `who`.
async fn request(
    c: &Cluster,
    id: &str,
    path: &str,
    n: u8,
    who: &UserIdentity,
    flags: u32,
) -> NewRequest {
    let (lineage, binary) = c
        .app_observe_binary(&observed(HOST, path, n))
        .await
        .unwrap();
    request_for(id, &lineage, binary.revision, &binary.bin_sha, who, flags)
}

fn request_for(
    id: &str,
    lineage: &LineageRow,
    revision: i64,
    bin_sha: &str,
    who: &UserIdentity,
    flags: u32,
) -> NewRequest {
    NewRequest {
        request_id: format!("req-{id}"),
        host_uuid: lineage.host_uuid.clone(),
        client_request_id: format!("cid-{id}"),
        lineage_id: lineage.lineage_id.clone(),
        bin_sha: bin_sha.into(),
        revision,
        origin: RequestOrigin::SelfRegistration,
        target: who.clone(),
        requester_uid: who.uid,
        requester_user_name: who.user_name.clone(),
        requested_by_admin_id: None,
        reason: Some("please".into()),
        flags,
        host_tier: "tpm".into(),
        proposer_spiffe_id: "spiffe://ferrogate.test/host/x".into(),
        dedup_key: dedup_key(&lineage.host_uuid, &lineage.path_key, who, bin_sha),
        submitted_at: NOW,
        pending_expires_at: NOW + 30 * DAY,
        auto_downgrade_reason: None,
    }
}

fn checks() -> IntakeChecks {
    IntakeChecks {
        now: NOW,
        denied_cooldown_since: Some(NOW - DAY),
    }
}

fn terms(policy: UpdatePolicy, continuity: Continuity) -> ApprovalTerms {
    ApprovalTerms {
        user_scope: UserScope::ExactUser,
        path_match: PathMatch::Exact,
        update_policy: policy,
        continuity,
        expires_at: Some(NOW + 180 * DAY),
        note: Some("reviewed".into()),
    }
}

async fn approve(c: &Cluster, request_id: &str, approval_id: &str, t: ApprovalTerms) {
    c.app_approve_request(&Approve {
        request_id: request_id.into(),
        admin_id: "admin-1".into(),
        now: NOW,
        choice: ApprovalChoice::New {
            approval_id: approval_id.into(),
            terms: t,
        },
        forbid_self_approval: false,
        also_revoke: Vec::new(),
        generation_millis: NOW * 1000,
    })
    .await
    .unwrap();
}

fn auto_checks(max_per_day: i64) -> AutoChecks {
    AutoChecks {
        now: NOW,
        denied_cooldown_since: Some(NOW - DAY),
        max_per_day,
        generation_millis: NOW * 1000 + 1,
    }
}

async fn raw(c: &Cluster, sql: &'static str, params: Vec<Param>) -> Result<usize, hiqlite::Error> {
    c.client().execute(sql, params).await
}

fn p(s: &str) -> Param {
    Param::from(s.to_string())
}

#[tokio::test]
async fn the_ledger_is_schema_migration_1() {
    let (c, _d) = cluster("migr").await;
    assert_eq!(c.applied_migrations().await.unwrap(), vec![1]);
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn revisions_are_sequential_stable_and_never_reused() {
    let (c, _d) = cluster("revs").await;
    let mut revisions = Vec::new();
    for n in [10, 20, 30] {
        let (lineage, binary) = c
            .app_observe_binary(&observed(HOST, "/opt/tool/bin/tool", n))
            .await
            .unwrap();
        revisions.push((lineage.lineage_id, binary.revision));
    }
    assert_eq!(revisions.iter().map(|r| r.1).collect::<Vec<_>>(), [1, 2, 3]);
    assert!(
        revisions.iter().all(|r| r.0 == revisions[0].0),
        "one lineage"
    );

    // Seeing a known hash again keeps its revision and first-sight metadata.
    let mut again = observed(HOST, "/opt/tool/bin/tool", 20);
    again.declared_version = Some("9.9".into());
    let (lineage, binary) = c.app_observe_binary(&again).await.unwrap();
    assert_eq!(binary.revision, 2);
    assert_eq!(binary.declared_version.as_deref(), Some("1.20"));
    assert_eq!(lineage.next_revision, 4);

    // Another path is another lineage, starting at 1; another host too.
    let (other, b) = c
        .app_observe_binary(&observed(HOST, "/opt/other", 20))
        .await
        .unwrap();
    assert_ne!(other.lineage_id, lineage.lineage_id);
    assert_eq!(b.revision, 1);
    let (_, b) = c
        .app_observe_binary(&observed(OTHER_HOST, "/opt/tool/bin/tool", 10))
        .await
        .unwrap();
    assert_eq!(b.revision, 1);

    // The database refuses gaps, reuse and edits.
    let lid = || p(&lineage.lineage_id);
    assert!(raw(
        &c,
        "INSERT INTO app_binaries (lineage_id, bin_sha, revision, file_size, format, \
         version_source, first_seen_at) VALUES (?1, ?2, 9, 1, 1, 0, 1)",
        vec![lid(), p(&sha(40))],
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "UPDATE app_lineages SET next_revision = 10 WHERE lineage_id = ?1",
        vec![lid()]
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "UPDATE app_lineages SET next_revision = next_revision + 1 WHERE lineage_id = ?1",
        vec![lid()]
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "UPDATE app_binaries SET revision = 7 WHERE lineage_id = ?1",
        vec![lid()]
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "DELETE FROM app_binaries WHERE lineage_id = ?1",
        vec![lid()]
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "DELETE FROM app_lineages WHERE lineage_id = ?1",
        vec![lid()]
    )
    .await
    .is_err());
    let all = c.app_binaries_of(&lineage.lineage_id).await.unwrap();
    assert_eq!(
        all.iter().map(|b| b.revision).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_request_never_overwrites_an_approval() {
    let (c, _d) = cluster("noreplace").await;
    let alice = user(1000, "alice");
    let r1 = request(&c, "1", "/opt/tool", 1, &alice, 0).await;
    assert!(matches!(
        c.app_submit_pending(&r1, &checks()).await.unwrap(),
        Intake::Recorded(_)
    ));
    approve(
        &c,
        &r1.request_id,
        "appr-1",
        terms(UpdatePolicy::ManualEachTime, Continuity::Anchored),
    )
    .await;
    let a1 = c.app_approval("appr-1").await.unwrap().unwrap();
    assert_eq!(a1.state, ApprovalState::Active);
    assert_eq!(a1.uid, Some(1000));

    // The same binary for the same user is covered: no request row at all.
    let mut again = request(&c, "2", "/opt/tool", 1, &alice, 0).await;
    match c.app_submit_pending(&again, &checks()).await.unwrap() {
        Intake::Covered(a) => assert_eq!(a.approval_id, "appr-1"),
        other => panic!("expected Covered, got {other:?}"),
    }
    assert!(c.app_request(&again.request_id).await.unwrap().is_none());

    // A new hash at the same path is a new pending *update* request.
    let r3 = request(&c, "3", "/opt/tool", 2, &alice, 0).await;
    let Intake::Recorded(row3) = c.app_submit_pending(&r3, &checks()).await.unwrap() else {
        panic!("expected Recorded");
    };
    assert_eq!(row3.state, RequestState::Pending);
    assert_eq!(row3.kind, ferro_raft::apps::RequestKind::Update);
    assert_eq!(row3.revision, 2);

    // A retry is replayed; a duplicate returns the open request unchanged.
    assert!(matches!(
        c.app_submit_pending(&r3, &checks()).await.unwrap(),
        Intake::Replayed(r) if r == row3
    ));
    again = request(&c, "4", "/opt/tool", 2, &alice, 0).await;
    assert!(matches!(
        c.app_submit_pending(&again, &checks()).await.unwrap(),
        Intake::DuplicatePending(r) if r == row3
    ));

    // A denial leaves A1 alone, and a re-ask within the cool-down returns it.
    c.app_deny_request(&Deny {
        request_id: r3.request_id.clone(),
        admin_id: "admin-1".into(),
        now: NOW,
        reason_code: 3,
        message: Some("not this one".into()),
        forbid_self_approval: false,
    })
    .await
    .unwrap();
    assert!(matches!(
        c.app_submit_pending(&again, &checks()).await.unwrap(),
        Intake::RecentlyDenied(r) if r.request_id == r3.request_id
    ));
    assert_eq!(c.app_approval("appr-1").await.unwrap().unwrap(), a1);

    // The database refuses every way of rewriting or dropping an approval or
    // a request record, whatever the caller.
    let id = || p("appr-1");
    let refused: [(&'static str, Vec<Param>); 9] = [
        (
            "UPDATE app_approvals SET bin_sha = ?2 WHERE approval_id = ?1",
            vec![id(), p(&sha(2))],
        ),
        (
            "UPDATE app_approvals SET lineage_id = 'x' WHERE approval_id = ?1",
            vec![id()],
        ),
        (
            "DELETE FROM app_approvals WHERE approval_id = ?1",
            vec![id()],
        ),
        (
            "UPDATE app_approvals SET user_scope = 2, uid = NULL, user_name = NULL, \
             user_kind = NULL, row_version = row_version + 1 WHERE approval_id = ?1",
            vec![id()],
        ),
        (
            "UPDATE app_approvals SET expires_at = expires_at + 1000 WHERE approval_id = ?1",
            vec![id()],
        ),
        (
            "UPDATE app_approvals SET state = 3, revoked_at = 1, revoked_by_admin_id = 'x', \
             revoke_reason_code = 1, row_version = row_version + 1 WHERE approval_id = ?1",
            vec![id()],
        ),
        (
            "UPDATE app_requests SET bin_sha = ?2 WHERE request_id = ?1",
            vec![p(&r1.request_id), p(&sha(9))],
        ),
        (
            "UPDATE app_requests SET state = 1, decided_at = NULL, decided_by_admin_id = NULL, \
             decision_reason_code = NULL WHERE request_id = ?1",
            vec![p(&r3.request_id)],
        ),
        (
            "DELETE FROM app_requests WHERE request_id = ?1",
            vec![p(&r1.request_id)],
        ),
    ];
    for (sql, params) in refused {
        assert!(
            raw(&c, sql, params).await.is_err(),
            "must be refused: {sql}"
        );
    }
    assert_eq!(c.app_approval("appr-1").await.unwrap().unwrap(), a1);
    assert_eq!(
        c.app_approval_revisions("appr-1").await.unwrap().len(),
        1,
        "only the creation revision"
    );

    // The one later change a request admits: pseudonymising its personal
    // data once it is terminal (F19 §10) — never while it is pending.
    assert_eq!(
        raw(
            &c,
            "UPDATE app_requests SET target_user_name = 'p:1', requester_user_name = 'p:1', \
             reason = NULL WHERE request_id = ?1",
            vec![p(&r3.request_id)],
        )
        .await
        .unwrap(),
        1
    );
    let r5 = request(&c, "5", "/opt/tool", 3, &alice, 0).await;
    c.app_submit_pending(&r5, &checks()).await.unwrap();
    assert!(raw(
        &c,
        "UPDATE app_requests SET target_user_name = 'p:1' WHERE request_id = ?1",
        vec![p(&r5.request_id)],
    )
    .await
    .is_err());
    c.shutdown().await.unwrap();
}

/// Deterministic pseudo-random interleaving of host and administrator
/// operations (ADR-0004 property): host operations never change or remove an
/// existing approval (only the informational `superseded_by` may be set), and
/// an administrator operation changes only the approvals it names.
#[tokio::test]
async fn host_operations_never_change_existing_approvals() {
    let (c, _d) = cluster("interleave").await;
    let users = [user(1000, "alice"), user(1001, "bob")];
    let mut seed: u64 = 0x05ee_df19;
    let mut next = |n: u64| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) % n
    };
    let (mut auto_ok, mut approved, mut revoked) = (0, 0, 0);
    for step in 0..100u32 {
        let before = list_all(&c).await;
        let op = next(8);
        let who = &users[usize::try_from(next(2)).unwrap()];
        let path = if next(2) == 0 {
            "/usr/bin/a"
        } else {
            "/usr/bin/b"
        };
        let hash = u8::try_from(next(8)).unwrap() + 1;
        let id = format!("s{step}");
        let mut named: Option<String> = None;
        match op {
            0 | 1 => {
                let r = request(&c, &id, path, hash, who, FLAG_PATH_PROTECTED).await;
                c.app_submit_pending(&r, &checks()).await.unwrap();
            }
            2..=4 => {
                let r = request(&c, &id, path, hash, who, FLAG_PATH_PROTECTED).await;
                let out = c
                    .app_try_auto_approve(&r, &format!("auto-{step}"), &auto_checks(50))
                    .await
                    .unwrap();
                if let AutoIntake::AutoApproved(_) = out {
                    auto_ok += 1;
                }
            }
            5 => {
                let pending = c
                    .app_list_requests(&RequestFilter {
                        states: vec![RequestState::Pending],
                        ..RequestFilter::default()
                    })
                    .await
                    .unwrap();
                if let Some(item) = pending.first() {
                    let policy = if next(2) == 0 {
                        UpdatePolicy::AutoSamePathUser
                    } else {
                        UpdatePolicy::ManualEachTime
                    };
                    approve(
                        &c,
                        &item.request.request_id,
                        &format!("man-{step}"),
                        terms(policy, Continuity::Anchored),
                    )
                    .await;
                    approved += 1;
                }
            }
            6 => {
                let pending = c
                    .app_list_requests(&RequestFilter {
                        states: vec![RequestState::Pending],
                        ..RequestFilter::default()
                    })
                    .await
                    .unwrap();
                if let Some(item) = pending.last() {
                    c.app_deny_request(&Deny {
                        request_id: item.request.request_id.clone(),
                        admin_id: "admin-1".into(),
                        now: NOW,
                        reason_code: 1,
                        message: None,
                        forbid_self_approval: false,
                    })
                    .await
                    .unwrap();
                }
            }
            _ => {
                let live: Vec<_> = before
                    .iter()
                    .filter(|a| a.state == ApprovalState::Active)
                    .collect();
                if !live.is_empty() {
                    let a = live[usize::try_from(next(live.len() as u64)).unwrap()];
                    c.app_revoke_approval(
                        &Revoke {
                            approval_id: a.approval_id.clone(),
                            admin_id: "admin-1".into(),
                            reason_code: 1,
                            expected_row_version: Some(a.row_version),
                        },
                        NOW,
                        NOW * 1000 + i64::from(step),
                    )
                    .await
                    .unwrap();
                    named = Some(a.approval_id.clone());
                    revoked += 1;
                }
            }
        }
        let after = list_all(&c).await;
        for old in &before {
            let now = after
                .iter()
                .find(|a| a.approval_id == old.approval_id)
                .expect("approvals are never removed");
            if named.as_deref() != Some(old.approval_id.as_str()) {
                assert_eq!(
                    now, old,
                    "step {step} op {op} changed an approval it did not name"
                );
            }
        }
    }
    assert!(
        auto_ok > 0 && approved > 0 && revoked > 0,
        "the run exercised every path: auto {auto_ok}, approved {approved}, revoked {revoked}"
    );
    c.shutdown().await.unwrap();
}

/// Every approval, sorted by id, with the informational `superseded_by`
/// cleared.
async fn list_all(c: &Cluster) -> Vec<ferro_raft::apps::ApprovalRow> {
    let mut rows: Vec<_> = c
        .app_list_approvals(&ApprovalFilter {
            include_superseded: true,
            page_size: 200,
            ..ApprovalFilter::default()
        })
        .await
        .unwrap()
        .into_iter()
        .map(|i| {
            let mut a = i.approval;
            a.superseded_by = None;
            a
        })
        .collect();
    rows.sort_by(|x, y| x.approval_id.cmp(&y.approval_id));
    rows
}

#[tokio::test]
async fn auto_update_copies_its_parent_and_leaves_it_active() {
    let (c, _d) = cluster("auto").await;
    let alice = user(1000, "alice");
    let r1 = request(&c, "1", "/usr/bin/tool", 1, &alice, FLAG_PATH_PROTECTED).await;
    c.app_submit_pending(&r1, &checks()).await.unwrap();
    approve(
        &c,
        &r1.request_id,
        "parent",
        terms(UpdatePolicy::AutoSamePathUser, Continuity::Anchored),
    )
    .await;
    let parent = c.app_approval("parent").await.unwrap().unwrap();
    let gen_before = c
        .app_allowlist_state(HOST)
        .await
        .unwrap()
        .unwrap()
        .generation;

    let r2 = request(&c, "2", "/usr/bin/tool", 2, &alice, FLAG_PATH_PROTECTED).await;
    let AutoIntake::AutoApproved(done) = c
        .app_try_auto_approve(&r2, "child", &auto_checks(3))
        .await
        .unwrap()
    else {
        panic!("expected an auto-approval");
    };
    assert_eq!(done.request.state, RequestState::AutoApproved);
    assert_eq!(done.request.resulting_approval_id.as_deref(), Some("child"));
    assert_eq!(done.approval.parent_approval_id.as_deref(), Some("parent"));
    assert_eq!(
        done.approval.expires_at, parent.expires_at,
        "expiry inherited"
    );
    assert_eq!(done.approval.uid, parent.uid);
    assert_eq!(done.approval.approved_by_admin_id, None);
    assert!(done.generation > gen_before);
    let parent_now = c.app_approval("parent").await.unwrap().unwrap();
    assert_eq!(
        parent_now.state,
        ApprovalState::Active,
        "INV-1: parent stays"
    );
    assert_eq!(parent_now.superseded_by.as_deref(), Some("child"));
    assert_eq!(parent_now.row_version, parent.row_version);

    // Not eligible: another user, an unanchored path, a frozen lineage.
    let bob = user(1001, "bob");
    let rb = request(&c, "b", "/usr/bin/tool", 3, &bob, FLAG_PATH_PROTECTED).await;
    assert_eq!(
        c.app_try_auto_approve(&rb, "x1", &auto_checks(3))
            .await
            .unwrap(),
        AutoIntake::NotEligible(AutoDowngradeReason::UserMismatch)
    );
    let same_uid_other_name = user(1000, "mallory");
    let rm = request(&c, "m", "/usr/bin/tool", 3, &same_uid_other_name, 1).await;
    assert_eq!(
        c.app_try_auto_approve(&rm, "x2", &auto_checks(3))
            .await
            .unwrap(),
        AutoIntake::NotEligible(AutoDowngradeReason::UserMismatch)
    );
    let ru = request(&c, "u", "/usr/bin/tool", 3, &alice, 0).await;
    assert_eq!(
        c.app_try_auto_approve(&ru, "x3", &auto_checks(3))
            .await
            .unwrap(),
        AutoIntake::NotEligible(AutoDowngradeReason::NoContinuityAnchor)
    );
    let rr = request(&c, "r", "/usr/bin/tool", 3, &alice, FLAG_PATH_PROTECTED).await;
    assert_eq!(
        c.app_try_auto_approve(&rr, "x4", &auto_checks(1))
            .await
            .unwrap(),
        AutoIntake::NotEligible(AutoDowngradeReason::AutoRateExceeded)
    );
    assert!(c
        .app_set_lineage_frozen(&r1.lineage_id, true)
        .await
        .unwrap());
    assert_eq!(
        c.app_try_auto_approve(&rr, "x5", &auto_checks(3))
            .await
            .unwrap(),
        AutoIntake::NotEligible(AutoDowngradeReason::LineageFrozen)
    );
    c.app_set_lineage_frozen(&r1.lineage_id, false)
        .await
        .unwrap();

    // A revoked hash is never auto-approved again in its lineage.
    c.app_revoke_approval(
        &Revoke {
            approval_id: "child".into(),
            admin_id: "admin-1".into(),
            reason_code: 2,
            expected_row_version: Some(1),
        },
        NOW,
        NOW * 1000 + 2,
    )
    .await
    .unwrap();
    let again = request(&c, "again", "/usr/bin/tool", 2, &alice, FLAG_PATH_PROTECTED).await;
    assert_eq!(
        c.app_try_auto_approve(&again, "x6", &auto_checks(3))
            .await
            .unwrap(),
        AutoIntake::NotEligible(AutoDowngradeReason::HashPreviouslyRevoked)
    );
    assert!(
        c.app_approval("x6").await.unwrap().is_none(),
        "nothing written"
    );

    // The database also refuses an auto-update that would widen the window.
    let widen = raw(
        &c,
        "INSERT INTO app_approvals (approval_id, host_uuid, lineage_id, bin_sha, revision, \
         source_request_id, origin, parent_approval_id, user_scope, user_kind, uid, user_name, \
         path_match, update_policy, continuity, created_at, expires_at, state, row_version) \
         SELECT 'forged', host_uuid, lineage_id, ?2, 3, 'req-x', 2, approval_id, user_scope, \
            user_kind, uid, user_name, path_match, update_policy, continuity, created_at, \
            expires_at + 1, 1, 1 FROM app_approvals WHERE approval_id = ?1",
        vec![p("parent"), p(&sha(3))],
    )
    .await;
    assert!(
        widen.is_err(),
        "an auto-update cannot extend its parent's expiry"
    );
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn decisions_follow_the_state_machine() {
    let (c, _d) = cluster("decide").await;
    let alice = user(1000, "alice");
    let r1 = request(&c, "1", "/opt/a", 1, &alice, 0).await;
    c.app_submit_pending(&r1, &checks()).await.unwrap();
    c.app_deny_request(&Deny {
        request_id: r1.request_id.clone(),
        admin_id: "admin-1".into(),
        now: NOW,
        reason_code: 1,
        message: None,
        forbid_self_approval: false,
    })
    .await
    .unwrap();
    let late = c
        .app_approve_request(&Approve {
            request_id: r1.request_id.clone(),
            admin_id: "admin-1".into(),
            now: NOW,
            choice: ApprovalChoice::New {
                approval_id: "late".into(),
                terms: terms(UpdatePolicy::ManualEachTime, Continuity::Anchored),
            },
            forbid_self_approval: false,
            also_revoke: Vec::new(),
            generation_millis: NOW * 1000,
        })
        .await;
    assert!(matches!(late, Err(LedgerError::InvalidState)));
    assert!(c.app_approval("late").await.unwrap().is_none());
    assert!(matches!(
        c.app_deny_request(&Deny {
            request_id: "req-missing".into(),
            admin_id: "admin-1".into(),
            now: NOW,
            reason_code: 1,
            message: None,
            forbid_self_approval: false,
        })
        .await,
        Err(LedgerError::NotFound)
    ));

    // Single-step direct add: one transaction, same actor.
    let (lineage, bin) = c
        .app_observe_binary(&observed(HOST, "/opt/direct", 5))
        .await
        .unwrap();
    let mut direct = request_for("d", &lineage, bin.revision, &bin.bin_sha, &alice, 0);
    direct.origin = RequestOrigin::AdminDirect;
    direct.requested_by_admin_id = Some("admin-7".into());
    let done = c
        .app_register_and_approve(
            &direct,
            "direct-appr",
            &terms(UpdatePolicy::ManualEachTime, Continuity::Anchored),
            NOW * 1000,
        )
        .await
        .unwrap();
    assert!(done.same_actor);
    assert_eq!(done.request.state, RequestState::Approved);
    assert_eq!(done.request.decided_by_admin_id.as_deref(), Some("admin-7"));
    assert_eq!(
        done.approval.origin,
        ferro_raft::apps::ApprovalOrigin::AdminDirect
    );

    // Strict separation of duties: the requester cannot approve their own
    // `admin_direct` request; another administrator can.
    let (lineage, bin) = c
        .app_observe_binary(&observed(HOST, "/opt/strict", 6))
        .await
        .unwrap();
    let mut strict = request_for("s", &lineage, bin.revision, &bin.bin_sha, &alice, 0);
    strict.origin = RequestOrigin::AdminDirect;
    strict.requested_by_admin_id = Some("admin-7".into());
    c.app_submit_pending(&strict, &checks()).await.unwrap();
    let mut approve_own = Approve {
        request_id: strict.request_id.clone(),
        admin_id: "admin-7".into(),
        now: NOW,
        choice: ApprovalChoice::New {
            approval_id: "strict-appr".into(),
            terms: terms(UpdatePolicy::ManualEachTime, Continuity::Anchored),
        },
        forbid_self_approval: true,
        also_revoke: Vec::new(),
        generation_millis: NOW * 1000,
    };
    assert!(matches!(
        c.app_approve_request(&approve_own).await,
        Err(LedgerError::SelfApproval)
    ));
    approve_own.admin_id = "admin-8".into();
    let decided = c.app_approve_request(&approve_own).await.unwrap();
    assert!(!decided.same_actor);
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn approval_changes_are_versioned_and_revocation_is_final() {
    let (c, _d) = cluster("versions").await;
    let alice = user(1000, "alice");
    let r1 = request(&c, "1", "/opt/v", 1, &alice, 0).await;
    c.app_submit_pending(&r1, &checks()).await.unwrap();
    let mut t = terms(UpdatePolicy::ManualEachTime, Continuity::Anchored);
    t.user_scope = UserScope::AnyUser;
    t.path_match = PathMatch::Any;
    t.expires_at = Some(NOW + 10);
    approve(&c, &r1.request_id, "v1", t).await;

    let edit = |version: i64| ApprovalEdit {
        approval_id: "v1".into(),
        admin_id: "admin-2".into(),
        expected_row_version: version,
        now: NOW,
        update_policy: Some(UpdatePolicy::AutoSamePathUser),
        continuity: None,
        expires_at: None,
        note: Some(Some("tightened".into())),
        narrow_to_exact_user: true,
        narrow_to_exact_path: true,
        generation_millis: NOW * 1000 + 5,
    };
    assert!(matches!(
        c.app_update_approval(&edit(7)).await,
        Err(LedgerError::RowVersionMismatch)
    ));
    let v2 = c.app_update_approval(&edit(1)).await.unwrap();
    assert_eq!(v2.row_version, 2);
    assert_eq!(v2.user_scope, UserScope::ExactUser);
    assert_eq!(v2.uid, Some(1000), "narrowed to the request's user");
    assert_eq!(v2.path_match, PathMatch::Exact);

    // Expiry by the sweeper, then renewal with a future expiry.
    assert!(
        !c.app_expire_approval("v1", NOW, 1).await.unwrap(),
        "not due"
    );
    assert!(c
        .app_expire_approval("v1", NOW + 20, NOW * 1000 + 6)
        .await
        .unwrap());
    let expired = c.app_approval("v1").await.unwrap().unwrap();
    assert_eq!(expired.state, ApprovalState::Expired);
    let mut renew = edit(3);
    renew.update_policy = None;
    renew.note = None;
    renew.narrow_to_exact_user = false;
    renew.narrow_to_exact_path = false;
    renew.now = NOW + 30;
    renew.expires_at = Some(Some(NOW + 90 * DAY));
    let renewed = c.app_update_approval(&renew).await.unwrap();
    assert_eq!(renewed.state, ApprovalState::Active);

    let revoked = c
        .app_revoke_approval(
            &Revoke {
                approval_id: "v1".into(),
                admin_id: "admin-2".into(),
                reason_code: 9,
                expected_row_version: None,
            },
            NOW + 40,
            NOW * 1000 + 7,
        )
        .await
        .unwrap();
    assert_eq!(revoked.state, ApprovalState::Revoked);
    assert_eq!(revoked.row_version, 5);
    assert!(matches!(
        c.app_revoke_approval(
            &Revoke {
                approval_id: "v1".into(),
                admin_id: "admin-2".into(),
                reason_code: 9,
                expected_row_version: None,
            },
            NOW + 50,
            NOW * 1000 + 8,
        )
        .await,
        Err(LedgerError::InvalidState)
    ));
    let mut late_edit = renew.clone();
    late_edit.expected_row_version = 5;
    assert!(matches!(
        c.app_update_approval(&late_edit).await,
        Err(LedgerError::InvalidState)
    ));

    let kinds: Vec<_> = c
        .app_approval_revisions("v1")
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.row_version, r.change_kind))
        .collect();
    assert_eq!(
        kinds,
        [
            (1, RevisionChange::Created),
            (2, RevisionChange::Updated),
            (3, RevisionChange::Expired),
            (4, RevisionChange::Renewed),
            (5, RevisionChange::Revoked),
        ]
    );
    // Revision records are append-only and carry no personal data.
    for rev in c.app_approval_revisions("v1").await.unwrap() {
        let text = String::from_utf8_lossy(&rev.after_cbor);
        assert!(!text.contains("alice") && !text.contains("tightened"));
        ApprovalSnapshot::from_cbor(&rev.after_cbor).unwrap();
    }
    assert!(raw(
        &c,
        "UPDATE app_approval_revisions SET changed_at = 0 WHERE approval_id = ?1",
        vec![p("v1")]
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "DELETE FROM app_approval_revisions WHERE approval_id = ?1",
        vec![p("v1")]
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "UPDATE app_approvals SET note = 'x', row_version = 6 WHERE approval_id = ?1",
        vec![p("v1")]
    )
    .await
    .is_err());
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_generation_never_goes_backwards() {
    let (c, _d) = cluster("gen").await;
    let g1 = c.app_bump_generation(HOST, 5_000, 5).await.unwrap();
    assert_eq!(g1, 5_000);
    let g2 = c.app_bump_generation(HOST, 1, 6).await.unwrap();
    assert_eq!(g2, 5_001, "monotonic even when the clock goes back");
    let g3 = c.app_bump_generation(HOST, 9_000, 7).await.unwrap();
    assert_eq!(g3, 9_000);

    // The first compile records its digest; the same digest keeps the
    // generation; a different one for the same generation bumps it.
    assert_eq!(
        c.app_record_compiled_digest(HOST, g3, &[1; 48], 9_000, 8)
            .await
            .unwrap(),
        Some(g3)
    );
    assert!(c
        .app_cache_signed_allowlist(HOST, g3, b"body", 100)
        .await
        .unwrap());
    assert_eq!(
        c.app_record_compiled_digest(HOST, g3, &[1; 48], 9_000, 8)
            .await
            .unwrap(),
        Some(g3)
    );
    let state = c.app_allowlist_state(HOST).await.unwrap().unwrap();
    assert_eq!(state.cached_v2.as_deref(), Some(&b"body"[..]));
    let g4 = c
        .app_record_compiled_digest(HOST, g3, &[2; 48], 9_000, 9)
        .await
        .unwrap()
        .unwrap();
    assert!(g4 > g3);
    assert_eq!(
        c.app_record_compiled_digest(HOST, g3, &[3; 48], 9_000, 9)
            .await
            .unwrap(),
        None,
        "a stale compile is not recorded"
    );
    assert!(!c
        .app_cache_signed_allowlist(HOST, g3, b"stale", 100)
        .await
        .unwrap());
    assert!(raw(
        &c,
        "UPDATE host_allowlist_state SET generation = 1 WHERE host_uuid = ?1",
        vec![p(HOST)]
    )
    .await
    .is_err());
    assert!(raw(
        &c,
        "DELETE FROM host_allowlist_state WHERE host_uuid = ?1",
        vec![p(HOST)]
    )
    .await
    .is_err());
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn listing_filters_pages_and_scopes_status_to_the_host() {
    let (c, _d) = cluster("list").await;
    let alice = user(1000, "alice");
    for (i, path) in ["/opt/a_b/tool", "/opt/axb/tool", "/home/alice/bin/x"]
        .iter()
        .enumerate()
    {
        let n = u8::try_from(i + 1).unwrap();
        let mut r = request(&c, &format!("{i}"), path, n, &alice, u32::from(n)).await;
        r.submitted_at = NOW + i64::from(n);
        c.app_submit_pending(&r, &checks()).await.unwrap();
    }

    // `_` is matched literally, not as a wildcard.
    let hits = c
        .app_list_requests(&RequestFilter {
            path_contains: Some("a_b".into()),
            ..RequestFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].canonical_path, "/opt/a_b/tool");

    // Newest first, one per page, continued by cursor.
    let page1 = c
        .app_list_requests(&RequestFilter {
            states: vec![RequestState::Pending],
            page_size: 1,
            ..RequestFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page1[0].request.request_id, "req-2");
    let page2 = c
        .app_list_requests(&RequestFilter {
            states: vec![RequestState::Pending],
            page_size: 1,
            after: Some(Cursor {
                at: page1[0].request.submitted_at,
                id: page1[0].request.request_id.clone(),
            }),
            ..RequestFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page2[0].request.request_id, "req-1");

    let flagged = c
        .app_list_requests(&RequestFilter {
            flags_any: 2,
            bin_sha_prefix: Some(sha(2)[..8].to_string()),
            ..RequestFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(flagged.len(), 1);
    let text = c
        .app_list_requests(&RequestFilter {
            text: Some("ALICE".into()),
            ..RequestFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(text.len(), 3, "user name matches every request");
    assert!(matches!(
        c.app_list_requests(&RequestFilter {
            page_size: 1000,
            ..RequestFilter::default()
        })
        .await,
        Err(LedgerError::Invalid("page_size"))
    ));

    approve(
        &c,
        "req-0",
        "list-appr",
        terms(UpdatePolicy::AutoSamePathUser, Continuity::Anchored),
    )
    .await;
    let approvals = c
        .app_list_approvals(&ApprovalFilter {
            policies: vec![UpdatePolicy::AutoSamePathUser],
            host_uuids: vec![HOST.into()],
            ..ApprovalFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].product_name.as_deref(), Some("Tool"));

    // Status lookups only ever see the asking host's own requests.
    let ids = vec!["req-0".to_string(), "req-1".to_string()];
    assert_eq!(c.app_requests_of_host(HOST, &ids).await.unwrap().len(), 2);
    assert_eq!(
        c.app_requests_of_host(OTHER_HOST, &ids).await.unwrap(),
        Vec::new()
    );

    // Stale pending requests expire, and only once.
    let due = c.app_pending_past_expiry(NOW + 31 * DAY, 10).await.unwrap();
    assert_eq!(due.len(), 2);
    for r in &due {
        assert!(c
            .app_expire_request(&r.request_id, NOW + 31 * DAY)
            .await
            .unwrap());
        assert!(!c
            .app_expire_request(&r.request_id, NOW + 31 * DAY)
            .await
            .unwrap());
    }
    c.shutdown().await.unwrap();
}
