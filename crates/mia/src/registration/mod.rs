//! Application registration requests (feature F19 §4.6, §7.6): the helper
//! protocol v2 `RegisterSelf`, `RegisterFile` and `RequestStatus`
//! operations.
//!
//! For each request the [`Registrar`]:
//!
//! 1. checks `[registration]` (`enable`, `assisted`), the requester's
//!    idempotency id, `for_user` (root only) and the per-uid and host
//!    budgets;
//! 2. identifies the binary without executing it ([`identify`]): the
//!    caller's running image, or the descriptor the client passed;
//! 3. records it in the local ledger ([`ledger`]) as `Queued`, with an
//!    `AppRequestDoc` carrying a fresh daemon-generated `client_request_id`;
//! 4. signs it with the host credentials (`ferrogate-app-request-v1`) and
//!    submits it; the answer (pending, approved, auto-approved, denied, …)
//!    is recorded and returned. An approval that names a newer allowlist
//!    generation wakes the sync loop at once.
//!
//! What cannot be submitted now stays `Queued` in the **outbox**: CMIS
//! unreachable, no host SVID yet, CMIS still in legacy allowlist mode
//! (`mode_legacy`), or a `rate_limited`/`too_many_pending` answer (retried
//! after its `retry-after`). The outbox is flushed and pending requests are
//! polled with `GetAppRequestStatus` on every allowlist-sync tick
//! ([`Registrar`] implements [`SyncHook`]).
//!
//! `RequestStatus` answers only the caller's own requests (all for root), so
//! registration never reveals another user's applications.

pub mod identify;
pub mod ledger;
pub mod limiter;
pub mod users;

pub mod flags;

use std::path::PathBuf;
use std::sync::Arc;

use ferro_proto::v1::{
    AppRequestState, GetAppRequestStatusRequest, SubmitAppRequestRequest, SubmitAppRequestResponse,
};
use ferro_svid::app_docs::{
    encode_app_request, encode_app_status, AppRequestDoc, AppStatusDoc, RequestedBy, TargetUser,
    APP_REQUEST_CONTEXT, APP_STATUS_CONTEXT,
};
use futures::future::BoxFuture;
use mia_helper_proto::{
    parse_id, HelperOp, LocalState, RegErrorCode, RegistrationResp, UserSel, ID_LEN,
};
use tokio::sync::{Mutex, Semaphore};
use tonic::Code;

use crate::allowlist_sync::{SyncHook, SyncTrigger};
use crate::helper::auth::CallerIdentity;
use crate::helper::server::{Clock, RegistrationHandler};
use crate::host_api::{CredentialSlot, HostApi};
use crate::status::StatusHandle;
use identify::{Identified, IdentifyConfig, IdentifyFailure};
use ledger::{Ledger, LedgerEntry};
use limiter::Limiter;

/// Host-wide registration budget per hour (F19 §7.4).
const MAX_PER_HOUR: u32 = 60;

/// Concurrent hash computations (F19 §7.4).
const MAX_CONCURRENT_HASHES: usize = 2;

/// Outbox submissions per tick.
const MAX_SUBMISSIONS_PER_TICK: usize = 20;

/// Status ids per `GetAppRequestStatus` call (F19 §7.1).
const MAX_STATUS_IDS_PER_CALL: usize = ferro_svid::app_docs::MAX_STATUS_REQUEST_IDS;

/// The `retry_after` given with an approval: the sync loop has been woken
/// and normally applies the new generation within seconds.
const APPROVED_RETRY_SECS: u32 = 5;

/// Registration settings.
#[derive(Debug, Clone)]
pub struct RegistrarConfig {
    /// `registration.enable`.
    pub enable: bool,
    /// `registration.assisted` (`RegisterFile`).
    pub assisted: bool,
    /// `registration.max_per_uid_per_hour`.
    pub max_per_uid_per_hour: u32,
    /// `registration.ledger_path`.
    pub ledger_path: PathBuf,
    /// How binaries are identified.
    pub identify: IdentifyConfig,
}

impl RegistrarConfig {
    /// The registration settings of `config`; `ima_enforced` says whether
    /// the Linux caller authenticator cross-checks IMA.
    ///
    /// # Errors
    ///
    /// An invalid `registration.version_sources`.
    pub fn from_config(config: &crate::config::Config, ima_enforced: bool) -> anyhow::Result<Self> {
        Ok(Self {
            enable: config.registration_enabled(),
            assisted: config.registration_assisted(),
            max_per_uid_per_hour: config.registration_max_per_uid_per_hour(),
            ledger_path: config.registration_ledger_path(),
            identify: IdentifyConfig {
                max_file_size: config.registration_max_file_size(),
                sources: config.registration_version_sources()?,
                ima_enforced,
            },
        })
    }
}

/// What the binary is registered for.
enum Subject {
    /// The caller's running image.
    RunningImage,
    /// A file the client opened.
    File(Option<std::fs::File>),
}

/// [`Subject`] without its descriptor.
#[derive(Clone, Copy)]
enum SubjectKind {
    RunningImage,
    File,
}

/// The registration service of one environment. Cheap to clone.
#[derive(Clone)]
pub struct Registrar {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: RegistrarConfig,
    api: Arc<dyn HostApi>,
    creds: CredentialSlot,
    trigger: SyncTrigger,
    ledger: Mutex<Ledger>,
    limiter: std::sync::Mutex<Limiter>,
    hashing: Semaphore,
    status: std::sync::OnceLock<StatusHandle>,
    clock: Clock,
}

/// A refusal.
const fn refuse(code: RegErrorCode, retry_after: Option<u32>) -> RegistrationResp {
    RegistrationResp::Error { code, retry_after }
}

impl Registrar {
    /// A registrar submitting through `api`, signed with `creds`, waking
    /// `trigger` on approvals. Opens the ledger.
    #[must_use]
    pub fn new(
        cfg: RegistrarConfig,
        api: Arc<dyn HostApi>,
        creds: CredentialSlot,
        trigger: SyncTrigger,
        clock: Clock,
    ) -> Self {
        let ledger = Ledger::open(&cfg.ledger_path);
        let limiter = Limiter::new(cfg.max_per_uid_per_hour, MAX_PER_HOUR);
        Self {
            inner: Arc::new(Inner {
                cfg,
                api,
                creds,
                trigger,
                ledger: Mutex::new(ledger),
                limiter: std::sync::Mutex::new(limiter),
                hashing: Semaphore::new(MAX_CONCURRENT_HASHES),
                status: std::sync::OnceLock::new(),
                clock,
            }),
        }
    }

    /// Report request counts to `status` (F18).
    #[must_use]
    pub fn with_status(self, status: StatusHandle) -> Self {
        status.set_registrations(
            self.inner
                .ledger
                .try_lock()
                .map(|l| l.counts())
                .unwrap_or_default(),
        );
        let _ = self.inner.status.set(status);
        self
    }

    fn now(&self) -> i64 {
        (self.inner.clock)()
    }

    /// Answer one registration operation for an authenticated `caller`.
    pub async fn handle_op(
        &self,
        caller: CallerIdentity,
        op: HelperOp,
        file: Option<std::fs::File>,
    ) -> RegistrationResp {
        match op {
            HelperOp::RegisterSelf {
                client_request_id,
                reason,
            } => {
                self.register(
                    caller,
                    Subject::RunningImage,
                    client_request_id,
                    None,
                    reason,
                )
                .await
            }
            HelperOp::RegisterFile {
                client_request_id,
                path: _,
                for_user,
                reason,
            } => {
                if !self.inner.cfg.assisted {
                    return refuse(RegErrorCode::RegistrationDisabled, None);
                }
                self.register(
                    caller,
                    Subject::File(file),
                    client_request_id,
                    for_user,
                    reason,
                )
                .await
            }
            HelperOp::RequestStatus { request_ids } => {
                let ledger = self.inner.ledger.lock().await;
                RegistrationResp::Status(ledger.visible(caller.uid, &request_ids))
            }
            HelperOp::Token { .. } => refuse(RegErrorCode::MalformedRequest, None),
        }
    }

    #[allow(clippy::too_many_lines)] // the ordered checks of one request.
    async fn register(
        &self,
        caller: CallerIdentity,
        subject: Subject,
        caller_request_id: [u8; ID_LEN],
        for_user: Option<UserSel>,
        reason: Option<String>,
    ) -> RegistrationResp {
        if !self.inner.cfg.enable {
            return refuse(RegErrorCode::RegistrationDisabled, None);
        }
        let now = self.now();
        // A repeated idempotency id returns the same request, free of charge.
        if let Some(e) = self
            .inner
            .ledger
            .lock()
            .await
            .by_caller_id(caller.uid, &caller_request_id)
        {
            return answer(e, false);
        }
        let target = match self.target(&caller, for_user) {
            Ok(t) => t,
            Err(code) => return refuse(code, None),
        };
        let spent = self
            .inner
            .limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .check(caller.uid, now);
        if let Err(wait) = spent {
            return refuse(RegErrorCode::RateLimited, Some(wait));
        }

        let subject_kind = match subject {
            Subject::RunningImage => SubjectKind::RunningImage,
            Subject::File(_) => SubjectKind::File,
        };
        let identified = match self.identify(&caller, subject).await {
            Ok(i) => i,
            Err(f) => {
                tracing::info!(reason = %f, uid = caller.uid, "registration refused");
                return refuse(f.code(), None);
            }
        };
        let bin_sha = hex::encode(identified.binary.sha384);
        let path = identified.binary.canonical_path.clone();

        let local_id = {
            let mut ledger = self.inner.ledger.lock().await;
            if let Some(e) = ledger.open_duplicate(caller.uid, target.uid, &path, &bin_sha) {
                return answer(e, false);
            }
            if !ledger.has_room() {
                return refuse(RegErrorCode::RateLimited, Some(3600));
            }
            // 1 self (the app's own image), 2 assisted (a file named by a
            // user, root or the tray).
            let origin = match subject_kind {
                SubjectKind::RunningImage => 1,
                SubjectKind::File => 2,
            };
            let doc = AppRequestDoc {
                v: ferro_svid::host_call::DOC_VERSION,
                // Filled from the host credentials at each submission.
                host_uuid: String::new(),
                issued_at: now,
                client_request_id: crate::host_api::random_uuid(),
                origin,
                target_user: target.user.clone(),
                requested_by: RequestedBy {
                    uid: caller.uid,
                    name: users::name_of(caller.uid).unwrap_or_default(),
                },
                reason: reason.filter(|r| !r.trim().is_empty()),
                binary: identified.binary,
            };
            let entry = LedgerEntry {
                local_id: crate::host_api::random_uuid(),
                caller_request_id,
                client_request_id: doc.client_request_id,
                request_id: None,
                approval_id: None,
                requester_uid: caller.uid,
                target_uid: target.uid,
                path,
                bin_sha,
                state: LocalState::Queued,
                revision: None,
                deny_reason_code: None,
                deny_message: None,
                created_at: now,
                updated_at: now,
                next_attempt_at: now,
                doc: Some(doc),
            };
            let local_id = entry.local_id;
            ledger.insert(entry);
            self.save(&ledger);
            local_id
        };
        tracing::info!(
            local_id = %mia_helper_proto::format_id(&local_id),
            uid = caller.uid,
            "registration request recorded"
        );
        let triggered = self.submit(&local_id, now).await;
        let ledger = self.inner.ledger.lock().await;
        ledger.get(&local_id).map_or_else(
            || refuse(RegErrorCode::Internal, None),
            |e| answer(e, triggered),
        )
    }

    /// The user the request is for: the caller, or — for root only — the
    /// `for_user` selection.
    fn target(
        &self,
        caller: &CallerIdentity,
        sel: Option<UserSel>,
    ) -> Result<Target, RegErrorCode> {
        let _ = self;
        let Some(sel) = sel else {
            return Ok(Target::of_caller(caller));
        };
        if caller.uid != 0 {
            return Err(RegErrorCode::PermissionDenied);
        }
        let uid = match sel {
            UserSel::Uid(uid) => uid,
            UserSel::Name(name) => users::uid_of(&name).ok_or(RegErrorCode::MalformedRequest)?,
            // Windows targets need the impersonated open (follow-up).
            UserSel::Sid(_) => return Err(RegErrorCode::ServerUnsupported),
        };
        Ok(Target {
            uid: Some(uid),
            user: TargetUser {
                kind: 1,
                uid: Some(uid),
                sid: None,
                name: users::name_of(uid).unwrap_or_default(),
            },
        })
    }

    /// Identify the subject on the blocking pool, at most two at a time.
    async fn identify(
        &self,
        caller: &CallerIdentity,
        subject: Subject,
    ) -> Result<Identified, IdentifyFailure> {
        let _permit = self
            .inner
            .hashing
            .acquire()
            .await
            .map_err(|e| IdentifyFailure::Internal(e.to_string()))?;
        let cfg = self.inner.cfg.identify.clone();
        let caller = caller.clone();
        tokio::task::spawn_blocking(move || match subject {
            Subject::RunningImage => identify::running_image(&caller, &cfg),
            Subject::File(file) => identify_file(file, &cfg),
        })
        .await
        .map_err(|e| IdentifyFailure::Internal(e.to_string()))?
    }

    fn save(&self, ledger: &Ledger) {
        if let Err(e) = ledger.save() {
            tracing::error!(path = %self.inner.cfg.ledger_path.display(), error = %e, "could not write the app-request ledger");
        }
        if let Some(status) = self.inner.status.get() {
            status.set_registrations(ledger.counts());
        }
    }

    /// Submit the queued entry `local_id` if credentials allow; record the
    /// outcome. Returns whether an approval woke the sync loop.
    async fn submit(&self, local_id: &[u8; ID_LEN], now: i64) -> bool {
        let Some(creds) = self.inner.creds.valid_at(now) else {
            return false; // stays queued until the host holds an SVID
        };
        let doc = {
            let ledger = self.inner.ledger.lock().await;
            match ledger.get(local_id) {
                Some(e) if e.state == LocalState::Queued => e.doc.clone(),
                _ => None,
            }
        };
        let Some(mut doc) = doc else { return false };
        doc.host_uuid.clone_from(&creds.host_uuid);
        doc.issued_at = now;
        let request = match encode_app_request(&doc) {
            Ok(bytes) => match creds.auth(APP_REQUEST_CONTEXT, &bytes) {
                Ok(auth) => SubmitAppRequestRequest {
                    doc: bytes,
                    auth: Some(auth),
                },
                Err(e) => {
                    tracing::error!(error = %e, "could not sign an app request");
                    return false;
                }
            },
            Err(e) => {
                // The document itself is invalid: it can never be accepted.
                tracing::warn!(error = %e, "app request document invalid; refusing it");
                self.update(local_id, now, |entry| {
                    entry.state = LocalState::Refused;
                    entry.doc = None;
                })
                .await;
                return false;
            }
        };
        match self.inner.api.submit_app_request(request).await {
            Ok(resp) => self.record(local_id, &resp, now).await,
            Err(status) => {
                self.on_submit_error(local_id, &status, now).await;
                false
            }
        }
    }

    async fn record(
        &self,
        local_id: &[u8; ID_LEN],
        resp: &SubmitAppRequestResponse,
        now: i64,
    ) -> bool {
        let state = local_state(resp.state);
        self.update(local_id, now, |e| {
            e.state = state;
            e.doc = None;
            e.request_id = parse_id(&resp.request_id);
            e.approval_id = parse_id(&resp.approval_id);
            e.revision = (resp.revision > 0).then_some(resp.revision);
            if state == LocalState::Denied {
                e.deny_reason_code = Some(resp.deny_reason_code);
                e.deny_message = (!resp.deny_message.is_empty()).then(|| resp.deny_message.clone());
                let wait = resp.retry_after_secs.max(0);
                e.next_attempt_at = now.saturating_add(wait);
            }
        })
        .await;
        tracing::info!(
            local_id = %mia_helper_proto::format_id(local_id),
            state = state.as_str(),
            deduplicated = resp.deduplicated,
            "app request submitted"
        );
        state.is_approved()
            && resp.allowlist_generation > 0
            && self.inner.trigger.sync_if_newer(resp.allowlist_generation)
    }

    async fn on_submit_error(&self, local_id: &[u8; ID_LEN], status: &tonic::Status, now: i64) {
        match status.code() {
            // The request itself can never be accepted.
            Code::InvalidArgument | Code::PermissionDenied => {
                tracing::warn!(code = ?status.code(), reason = status.message(), "CMIS refused an app request");
                self.update(local_id, now, |e| {
                    e.state = LocalState::Refused;
                    e.doc = None;
                })
                .await;
            }
            // Over budget: wait as told.
            Code::ResourceExhausted => {
                let wait = crate::host_api::retry_after(status).unwrap_or(60);
                let wait = i64::try_from(wait).unwrap_or(i64::MAX);
                self.update(local_id, now, |e| {
                    e.next_attempt_at = now.saturating_add(wait);
                })
                .await;
            }
            // `mode_legacy`, unreachable, older CMIS, auth trouble: stay
            // queued for the next tick.
            _ => tracing::info!(
                code = ?status.code(),
                reason = status.message(),
                "app request stays queued"
            ),
        }
    }

    async fn update(&self, local_id: &[u8; ID_LEN], now: i64, f: impl FnOnce(&mut LedgerEntry)) {
        let mut ledger = self.inner.ledger.lock().await;
        if let Some(e) = ledger.get_mut(local_id) {
            f(e);
            e.updated_at = now;
        }
        self.save(&ledger);
    }

    /// Flush the outbox, then poll the pending requests (one sync tick).
    pub async fn refresh(&self, now: i64) {
        let due = {
            let mut ledger = self.inner.ledger.lock().await;
            if ledger.prune(now) {
                self.save(&ledger);
            }
            ledger.due(now)
        };
        for local_id in due.iter().take(MAX_SUBMISSIONS_PER_TICK) {
            self.submit(local_id, now).await;
        }
        self.poll(now).await;
    }

    async fn poll(&self, now: i64) {
        let Some(creds) = self.inner.creds.valid_at(now) else {
            return;
        };
        let ids = self.inner.ledger.lock().await.pending_request_ids();
        for chunk in ids.chunks(MAX_STATUS_IDS_PER_CALL) {
            let doc = AppStatusDoc {
                v: ferro_svid::host_call::DOC_VERSION,
                host_uuid: creds.host_uuid.clone(),
                issued_at: now,
                nonce: crate::host_api::random_bytes(),
                request_ids: chunk.to_vec(),
            };
            let Ok(bytes) = encode_app_status(&doc) else {
                return;
            };
            let Ok(auth) = creds.auth(APP_STATUS_CONTEXT, &bytes) else {
                return;
            };
            let resp = match self
                .inner
                .api
                .app_request_status(GetAppRequestStatusRequest {
                    doc: bytes,
                    auth: Some(auth),
                })
                .await
            {
                Ok(r) => r,
                Err(status) => {
                    tracing::info!(code = ?status.code(), "app request status poll failed");
                    return;
                }
            };
            let mut approved = false;
            let mut ledger = self.inner.ledger.lock().await;
            for item in resp.items {
                let Some(request_id) = parse_id(&item.request_id) else {
                    continue;
                };
                let state = local_state(item.state);
                if let Some(e) = ledger
                    .entries()
                    .iter()
                    .find(|e| e.request_id == Some(request_id))
                    .map(|e| e.local_id)
                    .and_then(|id| ledger.get_mut(&id))
                {
                    if e.state == state {
                        continue;
                    }
                    e.state = state;
                    e.updated_at = now;
                    e.approval_id = parse_id(&item.approval_id).or(e.approval_id);
                    if item.revision > 0 {
                        e.revision = Some(item.revision);
                    }
                    if state == LocalState::Denied {
                        e.deny_reason_code = Some(item.deny_reason_code);
                        e.deny_message =
                            (!item.deny_message.is_empty()).then(|| item.deny_message.clone());
                    }
                    approved |= state.is_approved();
                }
            }
            self.save(&ledger);
            drop(ledger);
            if approved {
                // The status answer names no generation: sync now.
                self.inner.trigger.sync_now();
            }
        }
    }
}

/// The resolved target user.
struct Target {
    uid: Option<u32>,
    user: TargetUser,
}

impl Target {
    fn of_caller(caller: &CallerIdentity) -> Self {
        match &caller.user_sid {
            // Windows: the SID is the identity; the RID is kept for
            // compatibility.
            Some(sid) => Self {
                uid: Some(caller.uid),
                user: TargetUser {
                    kind: 2,
                    uid: Some(caller.uid),
                    sid: Some(sid.clone()),
                    name: String::new(),
                },
            },
            None => Self {
                uid: Some(caller.uid),
                user: TargetUser {
                    kind: 1,
                    uid: Some(caller.uid),
                    sid: None,
                    name: users::name_of(caller.uid).unwrap_or_default(),
                },
            },
        }
    }
}

/// Identify a `RegisterFile` subject: the passed descriptor on Unix.
fn identify_file(
    file: Option<std::fs::File>,
    cfg: &IdentifyConfig,
) -> Result<Identified, IdentifyFailure> {
    #[cfg(unix)]
    {
        let file = file.ok_or(IdentifyFailure::NotEligible("no_descriptor"))?;
        identify::passed_file(file, cfg)
    }
    #[cfg(not(unix))]
    {
        // Windows opens the file under the client's impersonated token
        // (ferro-winauth, follow-up); until then assisted registration is not
        // offered there.
        let _ = (file, cfg);
        Err(IdentifyFailure::NotEligible("unsupported_platform"))
    }
}

/// The local state of a CMIS request state.
fn local_state(state: i32) -> LocalState {
    match AppRequestState::try_from(state) {
        Ok(AppRequestState::Pending) => LocalState::Pending,
        Ok(AppRequestState::Approved) => LocalState::Approved,
        Ok(AppRequestState::AutoApproved) => LocalState::AutoApproved,
        Ok(AppRequestState::Denied) => LocalState::Denied,
        Ok(AppRequestState::Expired) => LocalState::Expired,
        _ => LocalState::Refused,
    }
}

/// The reply for a ledger entry. `triggered`: an approval woke the sync.
fn answer(e: &LedgerEntry, triggered: bool) -> RegistrationResp {
    if e.state == LocalState::Approved && e.request_id.is_none() {
        if let Some(approval_id) = e.approval_id {
            return RegistrationResp::AlreadyApproved { approval_id };
        }
    }
    let retry_after = match e.state {
        LocalState::Approved | LocalState::AutoApproved if triggered => Some(APPROVED_RETRY_SECS),
        LocalState::Denied => u32::try_from((e.next_attempt_at - e.updated_at).max(0))
            .ok()
            .filter(|s| *s > 0),
        _ => None,
    };
    RegistrationResp::Submitted {
        request_id: e.request_id,
        local_id: e.local_id,
        state: e.state,
        revision: e.revision,
        approval_id: e.approval_id,
        retry_after,
    }
}

impl RegistrationHandler for Registrar {
    fn handle(
        &self,
        caller: CallerIdentity,
        op: HelperOp,
        file: Option<std::fs::File>,
    ) -> BoxFuture<'_, RegistrationResp> {
        Box::pin(self.handle_op(caller, op, file))
    }
}

impl SyncHook for Registrar {
    fn on_tick(&self, now: i64) -> BoxFuture<'_, ()> {
        Box::pin(self.refresh(now))
    }
}

#[cfg(test)]
mod tests;
