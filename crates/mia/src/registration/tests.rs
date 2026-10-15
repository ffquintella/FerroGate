//! Registrar tests against a scripted CMIS.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ferro_proto::v1::{
    AppRequestState, AppRequestStatus, GetAppRequestStatusRequest, GetAppRequestStatusResponse,
    SubmitAppRequestRequest, SubmitAppRequestResponse, SyncAllowlistRequest, SyncAllowlistResponse,
};
use ferro_svid::app_docs::{decode_app_request, decode_app_status, AppRequestDoc};
use futures::future::BoxFuture;
use mia_helper_proto::{format_id, HelperOp, LocalState, RegErrorCode, RegistrationResp, UserSel};
use tonic::Status;

use super::*;
use crate::host_api::HostCredentials;

const HOST: &str = "1b4e28ba-2fa1-4d2a-883f-0016d3cca427";
const NOW: i64 = 1_800_000_000;

#[derive(Default)]
struct FakeCmis {
    submits: Mutex<VecDeque<Result<SubmitAppRequestResponse, Status>>>,
    statuses: Mutex<VecDeque<GetAppRequestStatusResponse>>,
    submitted: Mutex<Vec<AppRequestDoc>>,
    polled: Mutex<Vec<Vec<[u8; 16]>>>,
}

impl FakeCmis {
    fn will_submit(&self, r: Result<SubmitAppRequestResponse, Status>) {
        self.submits.lock().unwrap().push_back(r);
    }

    fn submitted(&self) -> Vec<AppRequestDoc> {
        self.submitted.lock().unwrap().clone()
    }
}

impl HostApi for FakeCmis {
    fn submit_app_request(
        &self,
        req: SubmitAppRequestRequest,
    ) -> BoxFuture<'_, Result<SubmitAppRequestResponse, Status>> {
        let doc = decode_app_request(&req.doc).unwrap();
        // The proof covers exactly these bytes under the request context.
        let auth = req.auth.unwrap();
        ferro_sep::verify_p256(
            &auth.sep_pub,
            &ferro_svid::host_call::signing_input(APP_REQUEST_CONTEXT, &req.doc),
            &auth.sig,
        )
        .unwrap();
        self.submitted.lock().unwrap().push(doc);
        let r = self
            .submits
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(Status::unavailable("down")));
        Box::pin(async move { r })
    }

    fn app_request_status(
        &self,
        req: GetAppRequestStatusRequest,
    ) -> BoxFuture<'_, Result<GetAppRequestStatusResponse, Status>> {
        let doc = decode_app_status(&req.doc).unwrap();
        self.polled.lock().unwrap().push(doc.request_ids);
        let r = self
            .statuses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default();
        Box::pin(async move { Ok(r) })
    }

    fn sync_allowlist(
        &self,
        _req: SyncAllowlistRequest,
    ) -> BoxFuture<'_, Result<SyncAllowlistResponse, Status>> {
        Box::pin(async { Err(Status::unimplemented("")) })
    }

    fn get_allowlist(&self, _host: String) -> BoxFuture<'_, Result<Option<Vec<u8>>, Status>> {
        Box::pin(async { Ok(None) })
    }
}

struct Rig {
    dir: std::path::PathBuf,
    cmis: Arc<FakeCmis>,
    creds: CredentialSlot,
    trigger: SyncTrigger,
    registrar: Registrar,
    tool: std::path::PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config(dir: &std::path::Path) -> RegistrarConfig {
    RegistrarConfig {
        enable: true,
        assisted: true,
        max_per_uid_per_hour: 10,
        max_open_per_uid: 50,
        ledger_path: dir.join("app-requests.cbor"),
        identify: IdentifyConfig {
            max_file_size: 1024 * 1024,
            sources: ferro_appid::VersionSources::default(),
            ima_enforced: true,
        },
    }
}

fn rig_with(tag: &str, tweak: impl FnOnce(&mut RegistrarConfig)) -> Rig {
    let dir = std::env::temp_dir().join(format!("mia-reg-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let tool = dir.join("tool");
    std::fs::write(&tool, b"#!/bin/true\ntool").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cmis = Arc::new(FakeCmis::default());
    let creds = CredentialSlot::new();
    creds.set(HostCredentials::new(
        Arc::new(ferro_sep::SoftwareMachineKey::generate().unwrap()),
        "h.c.s".into(),
        &format!("spiffe://ferrogate.test/host/{HOST}"),
        NOW + 100_000,
    ));
    let trigger = SyncTrigger::new();
    let mut cfg = config(&dir);
    tweak(&mut cfg);
    let registrar = Registrar::new(
        cfg,
        Arc::clone(&cmis) as Arc<dyn HostApi>,
        creds.clone(),
        trigger.clone(),
        Arc::new(|| NOW),
    );
    Rig {
        dir,
        cmis,
        creds,
        trigger,
        registrar,
        tool,
    }
}

fn rig(tag: &str) -> Rig {
    rig_with(tag, |_| {})
}

fn caller(uid: u32) -> CallerIdentity {
    CallerIdentity::new(4242, uid, uid, [0x11; 48])
}

fn register_file(r: &Rig, id: u8) -> HelperOp {
    HelperOp::RegisterFile {
        client_request_id: [id; 16],
        path: r.tool.display().to_string(),
        for_user: None,
        reason: Some("needs a token".into()),
    }
}

fn open_tool(r: &Rig) -> Option<std::fs::File> {
    Some(std::fs::File::open(&r.tool).unwrap())
}

fn uuid_text(b: u8) -> String {
    format_id(&[b; 16])
}

fn pending(request: u8) -> Result<SubmitAppRequestResponse, Status> {
    Ok(SubmitAppRequestResponse {
        request_id: uuid_text(request),
        state: AppRequestState::Pending.into(),
        revision: 1,
        ..SubmitAppRequestResponse::default()
    })
}

fn submitted_state(resp: &RegistrationResp) -> (LocalState, [u8; 16]) {
    match resp {
        RegistrationResp::Submitted {
            state, local_id, ..
        } => (*state, *local_id),
        other => panic!("unexpected {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_file_is_identified_signed_submitted_and_recorded() {
    let r = rig("submit");
    r.cmis.will_submit(pending(0xA1));
    let resp = r
        .registrar
        .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
        .await;
    let RegistrationResp::Submitted {
        request_id,
        state,
        revision,
        ..
    } = resp
    else {
        panic!("unexpected {resp:?}")
    };
    assert_eq!(state, LocalState::Pending);
    assert_eq!(request_id, Some([0xA1; 16]));
    assert_eq!(revision, Some(1));
    let doc = &r.cmis.submitted()[0];
    assert_eq!(doc.host_uuid, HOST);
    assert_eq!(doc.origin, 2, "a file is an assisted request");
    assert_eq!(doc.target_user.uid, Some(1000));
    assert_eq!(doc.requested_by.uid, 1000);
    assert_eq!(
        doc.binary.sha384,
        crate::helper::auth::bin_sha384(b"#!/bin/true\ntool")
    );
    assert_ne!(
        doc.client_request_id, [1; 16],
        "never the requester's idempotency id"
    );

    // The same idempotency id returns the same request without a new submit.
    let again = r
        .registrar
        .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
        .await;
    assert_eq!(submitted_state(&again).0, LocalState::Pending);
    assert_eq!(r.cmis.submitted().len(), 1);
    // A new id for the same open binary is answered by the open request.
    let dup = r
        .registrar
        .handle_op(caller(1000), register_file(&r, 2), open_tool(&r))
        .await;
    assert_eq!(submitted_state(&dup), submitted_state(&again));
    assert_eq!(r.cmis.submitted().len(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn legacy_mode_keeps_requests_queued_until_the_outbox_succeeds() {
    let r = rig("legacy");
    r.cmis
        .will_submit(Err(Status::failed_precondition("mode_legacy")));
    let resp = r
        .registrar
        .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
        .await;
    let (state, local_id) = submitted_state(&resp);
    assert_eq!(state, LocalState::Queued);

    // Still legacy on the next tick: still queued.
    r.cmis
        .will_submit(Err(Status::failed_precondition("mode_legacy")));
    r.registrar.refresh(NOW + 300).await;
    let status = r
        .registrar
        .handle_op(
            caller(1000),
            HelperOp::RequestStatus {
                request_ids: vec![local_id],
            },
            None,
        )
        .await;
    let RegistrationResp::Status(items) = status else {
        panic!()
    };
    assert_eq!(items[0].state, LocalState::Queued);

    // CMIS switched to approvals: the outbox submits the same request (same
    // client_request_id), then the status poll sees the approval and wakes
    // the sync loop.
    r.cmis.will_submit(pending(0xB2));
    r.cmis
        .statuses
        .lock()
        .unwrap()
        .push_back(GetAppRequestStatusResponse {
            items: vec![AppRequestStatus {
                request_id: uuid_text(0xB2),
                state: AppRequestState::Approved.into(),
                approval_id: uuid_text(0xC3),
                revision: 1,
                decided_at: NOW,
                deny_reason_code: 0,
                deny_message: String::new(),
            }],
        });
    r.registrar.refresh(NOW + 600).await;
    let docs = r.cmis.submitted();
    assert_eq!(docs.len(), 3);
    assert_eq!(docs[0].client_request_id, docs[2].client_request_id);
    assert_eq!(
        r.cmis.polled.lock().unwrap().last().unwrap(),
        &vec![[0xB2; 16]]
    );
    let RegistrationResp::Status(items) = r
        .registrar
        .handle_op(
            caller(1000),
            HelperOp::RequestStatus {
                request_ids: vec![],
            },
            None,
        )
        .await
    else {
        panic!()
    };
    assert_eq!(items[0].state, LocalState::Approved);
    assert_eq!(items[0].approval_id, Some([0xC3; 16]));
}

#[cfg(unix)]
#[tokio::test]
async fn rate_limited_submissions_wait_for_retry_after() {
    let r = rig("retry");
    let mut limited = Status::resource_exhausted("too_many_pending");
    limited
        .metadata_mut()
        .insert("retry-after", "900".parse().unwrap());
    r.cmis.will_submit(Err(limited));
    let (state, _) = submitted_state(
        &r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
    );
    assert_eq!(state, LocalState::Queued);
    // Not due before the retry-after has passed.
    r.registrar.refresh(NOW + 300).await;
    assert_eq!(r.cmis.submitted().len(), 1);
    r.cmis.will_submit(pending(1));
    r.registrar.refresh(NOW + 901).await;
    assert_eq!(r.cmis.submitted().len(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn without_an_svid_requests_are_queued_without_a_call() {
    let r = rig("nosvid");
    r.creds.set(None);
    let (state, _) = submitted_state(
        &r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
    );
    assert_eq!(state, LocalState::Queued);
    assert_eq!(r.cmis.submitted().len(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn an_approval_wakes_the_sync_and_a_covering_approval_is_reported() {
    let r = rig("approved");
    r.cmis.will_submit(Ok(SubmitAppRequestResponse {
        request_id: uuid_text(5),
        state: AppRequestState::AutoApproved.into(),
        approval_id: uuid_text(6),
        revision: 2,
        allowlist_generation: 77,
        ..SubmitAppRequestResponse::default()
    }));
    let resp = r
        .registrar
        .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
        .await;
    assert!(matches!(
        resp,
        RegistrationResp::Submitted {
            state: LocalState::AutoApproved,
            retry_after: Some(5),
            ..
        }
    ));
    assert!(!r.trigger.sync_if_newer(0));

    // An approval already covers the binary (no request row).
    let r = rig("covered");
    r.cmis.will_submit(Ok(SubmitAppRequestResponse {
        state: AppRequestState::Approved.into(),
        approval_id: uuid_text(9),
        deduplicated: true,
        ..SubmitAppRequestResponse::default()
    }));
    assert_eq!(
        r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
        RegistrationResp::AlreadyApproved {
            approval_id: [9; 16]
        }
    );
}

#[cfg(unix)]
#[tokio::test]
async fn permissions_switches_and_budgets_are_enforced() {
    let r = rig("perm");
    // `for_user` needs root.
    let op = HelperOp::RegisterFile {
        client_request_id: [1; 16],
        path: r.tool.display().to_string(),
        for_user: Some(UserSel::Uid(0)),
        reason: None,
    };
    assert_eq!(
        r.registrar.handle_op(caller(1000), op, open_tool(&r)).await,
        RegistrationResp::Error {
            code: RegErrorCode::PermissionDenied,
            retry_after: None
        }
    );
    // `RegisterFile` without a descriptor is not eligible.
    assert!(matches!(
        r.registrar
            .handle_op(caller(1000), register_file(&r, 2), None)
            .await,
        RegistrationResp::Error {
            code: RegErrorCode::FileNotEligible,
            ..
        }
    ));
    // Another user's requests are invisible.
    r.cmis.will_submit(pending(3));
    r.registrar
        .handle_op(caller(1000), register_file(&r, 3), open_tool(&r))
        .await;
    let RegistrationResp::Status(theirs) = r
        .registrar
        .handle_op(
            caller(1001),
            HelperOp::RequestStatus {
                request_ids: vec![],
            },
            None,
        )
        .await
    else {
        panic!()
    };
    assert_eq!(theirs.len(), 0);
    let RegistrationResp::Status(all) = r
        .registrar
        .handle_op(
            caller(0),
            HelperOp::RequestStatus {
                request_ids: vec![],
            },
            None,
        )
        .await
    else {
        panic!()
    };
    assert_eq!(all.len(), 1);

    // The per-uid budget.
    let r = rig_with("budget", |c| c.max_per_uid_per_hour = 1);
    r.cmis.will_submit(pending(1));
    r.registrar
        .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
        .await;
    assert!(matches!(
        r.registrar
            .handle_op(caller(1000), register_file(&r, 2), open_tool(&r))
            .await,
        RegistrationResp::Error {
            code: RegErrorCode::RateLimited,
            retry_after: Some(_)
        }
    ));

    // The switches.
    let r = rig_with("off", |c| c.enable = false);
    assert!(matches!(
        r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
        RegistrationResp::Error {
            code: RegErrorCode::RegistrationDisabled,
            ..
        }
    ));
    let r = rig_with("noassist", |c| c.assisted = false);
    assert!(matches!(
        r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
        RegistrationResp::Error {
            code: RegErrorCode::RegistrationDisabled,
            ..
        }
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn invalid_requests_are_refused_and_never_retried() {
    let r = rig("invalid");
    r.cmis
        .will_submit(Err(Status::invalid_argument("field_too_long")));
    let (state, _) = submitted_state(
        &r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
    );
    assert_eq!(state, LocalState::Refused);
    r.registrar.refresh(NOW + 300).await;
    assert_eq!(r.cmis.submitted().len(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn the_ledger_survives_a_restart() {
    let r = rig("restart");
    r.cmis.will_submit(pending(4));
    let (_, local_id) = submitted_state(
        &r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
    );
    let again = Registrar::new(
        config(&r.dir),
        Arc::clone(&r.cmis) as Arc<dyn HostApi>,
        r.creds.clone(),
        r.trigger.clone(),
        Arc::new(|| NOW),
    );
    let RegistrationResp::Status(items) = again
        .handle_op(
            caller(1000),
            HelperOp::RequestStatus {
                request_ids: vec![[4; 16]],
            },
            None,
        )
        .await
    else {
        panic!()
    };
    assert_eq!(items[0].local_id, local_id);
    assert_eq!(items[0].state, LocalState::Pending);
}

/// A second executable in the rig's directory, distinct from `r.tool`.
#[cfg(unix)]
fn extra_tool(r: &Rig, n: u8) -> std::fs::File {
    use std::os::unix::fs::PermissionsExt as _;
    let path = r.dir.join(format!("tool{n}"));
    std::fs::write(&path, format!("#!/bin/true\ntool {n}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::File::open(&path).unwrap()
}

fn status_of(resp: RegistrationResp) -> Vec<mia_helper_proto::LocalRequestStatus> {
    match resp {
        RegistrationResp::Status(items) => items,
        other => panic!("unexpected {other:?}"),
    }
}

fn status_op() -> HelperOp {
    HelperOp::RequestStatus {
        request_ids: vec![],
    }
}

/// One local user cannot hold more than `max_open_per_uid` open requests;
/// other users are not affected, and retries are still answered.
#[cfg(unix)]
#[tokio::test]
async fn open_requests_are_capped_per_requester() {
    let r = rig_with("opencap", |c| c.max_open_per_uid = 2);
    // CMIS is unreachable: every request stays queued (open).
    for n in 1..=2u8 {
        let (state, _) = submitted_state(
            &r.registrar
                .handle_op(caller(1000), register_file(&r, n), Some(extra_tool(&r, n)))
                .await,
        );
        assert_eq!(state, LocalState::Queued);
    }
    assert_eq!(
        r.registrar
            .handle_op(caller(1000), register_file(&r, 3), Some(extra_tool(&r, 3)))
            .await,
        RegistrationResp::Error {
            code: RegErrorCode::RateLimited,
            retry_after: Some(OPEN_CAP_RETRY_SECS)
        }
    );
    // A retry of an existing request is still answered.
    assert_eq!(
        submitted_state(
            &r.registrar
                .handle_op(caller(1000), register_file(&r, 1), Some(extra_tool(&r, 1)))
                .await
        )
        .0,
        LocalState::Queued
    );
    // Another user registers normally.
    let (state, _) = submitted_state(
        &r.registrar
            .handle_op(caller(1001), register_file(&r, 4), Some(extra_tool(&r, 4)))
            .await,
    );
    assert_eq!(state, LocalState::Queued);
    assert_eq!(
        status_of(r.registrar.handle_op(caller(1000), status_op(), None).await).len(),
        2
    );
}

/// A ledger filled by one user's closed requests makes room by dropping
/// that user's oldest one: other users can still register.
#[cfg(unix)]
#[tokio::test]
async fn a_full_ledger_does_not_block_other_requesters() {
    let r = rig_with("full", |c| {
        let mut l = Ledger::open(&c.ledger_path);
        for i in 0..ledger::MAX_ENTRIES {
            let mut e = ledger::tests::entry(
                0,
                666,
                LocalState::Refused,
                NOW - 100 + i64::try_from(i).unwrap(),
            );
            e.local_id[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
            e.caller_request_id = e.local_id;
            l.insert(e);
        }
        l.save().unwrap();
    });
    let (state, local_id) = submitted_state(
        &r.registrar
            .handle_op(caller(1000), register_file(&r, 1), open_tool(&r))
            .await,
    );
    assert_eq!(state, LocalState::Queued);
    let mine = status_of(r.registrar.handle_op(caller(1000), status_op(), None).await);
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].local_id, local_id);
    let ledger = Ledger::open(&r.dir.join("app-requests.cbor"));
    assert_eq!(ledger.entries().len(), ledger::MAX_ENTRIES);
    let mut oldest = [0u8; 16];
    oldest[..8].copy_from_slice(&0u64.to_be_bytes());
    assert!(ledger.get(&oldest).is_none(), "the flooder's oldest went");
}

fn sid_caller(rid: u32, sid: &str) -> CallerIdentity {
    let mut c = caller(rid);
    c.user_sid = Some(sid.into());
    c
}

/// Windows keys requests by SID: same-RID users of different domains see
/// only their own requests and never collide on idempotency ids.
#[cfg(unix)]
#[tokio::test]
async fn same_rid_users_of_different_domains_get_their_own_requests() {
    let r = rig("sid");
    let a = sid_caller(1104, "S-1-5-21-1111-2222-3333-1104");
    let b = sid_caller(1104, "S-1-5-21-4444-5555-6666-1104");
    let (_, local_a) = submitted_state(
        &r.registrar
            .handle_op(a.clone(), register_file(&r, 1), open_tool(&r))
            .await,
    );
    assert_eq!(
        status_of(r.registrar.handle_op(b.clone(), status_op(), None).await).len(),
        0
    );
    let probe = HelperOp::RequestStatus {
        request_ids: vec![local_a],
    };
    assert_eq!(
        status_of(r.registrar.handle_op(b.clone(), probe, None).await).len(),
        0
    );
    // The same idempotency id (and binary) from B is B's own new request.
    let (_, local_b) = submitted_state(
        &r.registrar
            .handle_op(b.clone(), register_file(&r, 1), open_tool(&r))
            .await,
    );
    assert_ne!(local_a, local_b);
    let theirs: Vec<_> = status_of(r.registrar.handle_op(b, status_op(), None).await)
        .into_iter()
        .map(|s| s.local_id)
        .collect();
    assert_eq!(theirs, vec![local_b]);
    let mine: Vec<_> = status_of(r.registrar.handle_op(a, status_op(), None).await)
        .into_iter()
        .map(|s| s.local_id)
        .collect();
    assert_eq!(mine, vec![local_a]);
    // A Unix caller with the same number is neither of them.
    assert_eq!(
        status_of(r.registrar.handle_op(caller(1104), status_op(), None).await).len(),
        0
    );
}
