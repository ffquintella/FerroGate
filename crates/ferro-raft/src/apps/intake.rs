//! Request intake (F19 §5.1–§5.3): lineage and revision allocation, pending
//! requests with deduplication, and auto-update approvals.
//!
//! Nothing here updates or removes an existing approval (INV-1): intake
//! inserts a request, and an auto-update inserts one new approval that copies
//! its parent. The only write to an existing approval is the informational
//! `superseded_by` mark on the parent.

use hiqlite::Param;

use super::generation::bump_generation_stmt;
use super::model::{
    is_bin_sha, ApprovalOrigin, ApprovalRow, ApprovalSnapshot, ApprovalState, AutoDowngradeReason,
    BinaryRow, LineageRow, NewRequest, ObservedBinary, RequestOrigin, RequestRow, RequestState,
    RevisionChange,
};
use super::{check_id, check_len, generic_refusal, opt_text, text, LedgerError, TxnOutcome};
use crate::cluster::Cluster;

/// Clock and cool-down inputs of [`Cluster::app_submit_pending`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntakeChecks {
    /// Unix seconds; approvals expiring at or before it do not cover.
    pub now: i64,
    /// A request with the same dedup key denied at or after this time is
    /// returned instead of recording a new one (`CMIS_APP_DENIED_COOLDOWN_SECS`).
    pub denied_cooldown_since: Option<i64>,
}

/// Inputs of [`Cluster::app_try_auto_approve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoChecks {
    /// Unix seconds.
    pub now: i64,
    /// As [`IntakeChecks::denied_cooldown_since`].
    pub denied_cooldown_since: Option<i64>,
    /// `CMIS_APP_AUTO_UPDATE_MAX_PER_DAY`: auto-approvals allowed per lineage
    /// in the past 24 h.
    pub max_per_day: i64,
    /// Unix milliseconds for the hybrid-logical generation bump (F19 §6.2).
    pub generation_millis: i64,
}

/// Outcome of recording a request. Every variant but `Recorded` returns an
/// existing record unchanged (F19 §5.2: deduplication only returns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intake {
    /// A new request was recorded.
    Recorded(RequestRow),
    /// The host retried a request it already sent (same `client_request_id`).
    Replayed(RequestRow),
    /// An active, unexpired approval already covers the binary and user; no
    /// request row was created.
    Covered(ApprovalRow),
    /// An open request with the same dedup key exists.
    DuplicatePending(RequestRow),
    /// A request with the same dedup key was denied within the cool-down.
    RecentlyDenied(RequestRow),
}

/// A committed auto-approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApproval {
    /// The `AUTO_APPROVED` request.
    pub request: RequestRow,
    /// The new approval (`origin = auto_update`).
    pub approval: ApprovalRow,
    /// The host's allowlist generation after the bump.
    pub generation: u64,
}

/// Outcome of [`Cluster::app_try_auto_approve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoIntake {
    /// The request was auto-approved under its parent's policy.
    AutoApproved(Box<AutoApproval>),
    /// The first database-checked §5.3 condition that failed; nothing was
    /// written. The caller records a pending request with this reason.
    NotEligible(AutoDowngradeReason),
    /// The request deduplicated onto an existing record; nothing was written.
    Deduplicated(Box<Intake>),
}

/// Attempts at an auto-approval before giving up on a moving parent.
const AUTO_ATTEMPTS: usize = 3;

/// §5.1 steps 3 and 5.3–5.5, shared by both intake guards. Parameters:
/// ?1 host, ?2 client_request_id, ?3 lineage, ?4 bin_sha, ?5 now,
/// ?6 target_sid, ?7 target_uid, ?8 dedup_key, ?9 denied cool-down start.
macro_rules! intake_checks {
    () => {
        "WHEN EXISTS (SELECT 1 FROM app_requests WHERE host_uuid = ?1 AND client_request_id = ?2) \
            THEN 'replayed' \
         WHEN EXISTS (SELECT 1 FROM app_approvals a WHERE a.host_uuid = ?1 AND a.state = 1 \
            AND (a.expires_at IS NULL OR a.expires_at > ?5) \
            AND (a.bin_sha = ?4 OR a.bin_sha = '*') \
            AND (a.lineage_id = ?3 OR a.path_match = 2) \
            AND (a.user_scope = 2 \
                OR (a.sid IS NOT NULL AND upper(a.sid) = upper(?6)) \
                OR (a.sid IS NULL AND a.uid IS NOT NULL AND a.uid = ?7))) \
            THEN 'covered' \
         WHEN EXISTS (SELECT 1 FROM app_requests WHERE dedup_key = ?8 AND state = 1) \
            THEN 'duplicate_pending' \
         WHEN ?9 IS NOT NULL AND EXISTS (SELECT 1 FROM app_requests \
            WHERE dedup_key = ?8 AND state = 4 AND decided_at >= ?9) \
            THEN 'denied_cooldown' "
    };
}

const PENDING_GUARD: &str = concat!(
    "INSERT INTO app_txn_guard (code) SELECT c FROM (SELECT CASE ",
    intake_checks!(),
    "ELSE 'ok' END AS c) WHERE c <> 'ok'"
);

/// The §5.3 conditions the database can decide (#2 to #7), after the shared
/// intake checks. Extra parameters: ?10 expected parent id, ?11 its
/// row_version, ?12 request flags, ?13 target user name, ?14 max auto
/// approvals per day, ?15 start of the 24 h window.
const AUTO_GUARD: &str = concat!(
    "WITH p AS (SELECT approval_id, row_version, user_scope, uid, sid, user_name, continuity, \
        bin_sha FROM app_approvals \
        WHERE lineage_id = ?3 AND host_uuid = ?1 AND state = 1 AND update_policy = 2 \
        AND (expires_at IS NULL OR expires_at > ?5) \
        ORDER BY revision DESC, created_at DESC, approval_id DESC LIMIT 1) \
     INSERT INTO app_txn_guard (code) SELECT c FROM (SELECT CASE ",
    intake_checks!(),
    "WHEN NOT EXISTS (SELECT 1 FROM p) THEN 'no_auto_parent' \
     WHEN NOT EXISTS (SELECT 1 FROM p WHERE approval_id = ?10 AND row_version = ?11) \
        THEN 'stale' \
     WHEN EXISTS (SELECT 1 FROM app_lineages WHERE lineage_id = ?3 AND auto_update_frozen = 1) \
        THEN 'lineage_frozen' \
     WHEN NOT EXISTS (SELECT 1 FROM p WHERE \
            (p.user_scope = 1 AND ((p.sid IS NOT NULL AND upper(p.sid) = upper(?6)) \
                OR (p.sid IS NULL AND p.uid = ?7 AND p.user_name = ?13))) \
            OR (p.user_scope = 2 AND (?12 & 1) = 1)) \
        THEN 'user_mismatch' \
     WHEN NOT EXISTS (SELECT 1 FROM p WHERE p.continuity = 2 OR (?12 & 1) = 1 \
            OR EXISTS (SELECT 1 FROM app_binaries nb JOIN app_binaries pb \
                ON pb.lineage_id = ?3 AND pb.bin_sha = p.bin_sha \
                WHERE nb.lineage_id = ?3 AND nb.bin_sha = ?4 \
                AND nb.signer_valid = 1 AND pb.signer_valid = 1 AND nb.signer_kind <> 0 \
                AND nb.signer_kind = pb.signer_kind \
                AND nb.signer_id IS NOT NULL AND nb.signer_id = pb.signer_id)) \
        THEN 'no_continuity_anchor' \
     WHEN EXISTS (SELECT 1 FROM app_approvals \
            WHERE lineage_id = ?3 AND bin_sha = ?4 AND state = 3) \
        THEN 'hash_previously_revoked' \
     WHEN EXISTS (SELECT 1 FROM app_requests \
            WHERE lineage_id = ?3 AND bin_sha = ?4 AND state = 4) \
        THEN 'hash_previously_denied' \
     WHEN (SELECT COUNT(*) FROM app_approvals \
            WHERE lineage_id = ?3 AND origin = 2 AND created_at > ?15) >= ?14 \
        THEN 'auto_rate_exceeded' \
     ELSE 'ok' END AS c) WHERE c <> 'ok'"
);

/// Insert one request. The kind is classified here: an update when the
/// lineage has any approval other than the one this request results in.
const INSERT_REQUEST: &str = "INSERT INTO app_requests (request_id, host_uuid, \
    client_request_id, lineage_id, bin_sha, revision, kind, origin, target_user_kind, target_uid, \
    target_sid, target_user_name, requester_uid, requester_user_name, requested_by_admin_id, \
    reason, flags, host_tier, proposer_spiffe_id, dedup_key, submitted_at, pending_expires_at, \
    state, decided_at, decided_by_admin_id, decision_reason_code, decision_message, \
    auto_downgrade_reason, resulting_approval_id, same_actor_approved) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, \
        CASE WHEN EXISTS (SELECT 1 FROM app_approvals \
            WHERE lineage_id = ?4 AND approval_id IS NOT ?26) THEN 2 ELSE 1 END, \
        ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, \
        NULL, NULL, ?25, ?26, ?27)";

/// The decision a request is recorded with.
pub(crate) struct RecordedAs<'a> {
    pub(crate) state: RequestState,
    pub(crate) decided_at: Option<i64>,
    pub(crate) decided_by_admin_id: Option<&'a str>,
    pub(crate) resulting_approval_id: Option<&'a str>,
    pub(crate) same_actor: bool,
}

pub(crate) fn insert_request_stmt(
    r: &NewRequest,
    how: &RecordedAs<'_>,
) -> (&'static str, Vec<Param>) {
    (
        INSERT_REQUEST,
        vec![
            text(&r.request_id),
            text(&r.host_uuid),
            text(&r.client_request_id),
            text(&r.lineage_id),
            text(&r.bin_sha),
            Param::from(r.revision),
            Param::from(r.origin.code()),
            Param::from(r.target.kind.code()),
            Param::from(r.target.uid),
            opt_text(r.target.sid.as_deref()),
            opt_text(r.target.user_name.as_deref()),
            Param::from(r.requester_uid),
            opt_text(r.requester_user_name.as_deref()),
            opt_text(r.requested_by_admin_id.as_deref()),
            opt_text(r.reason.as_deref()),
            Param::from(i64::from(r.flags)),
            text(&r.host_tier),
            text(&r.proposer_spiffe_id),
            Param::from(r.dedup_key.clone()),
            Param::from(r.submitted_at),
            Param::from(r.pending_expires_at),
            Param::from(how.state.code()),
            Param::from(how.decided_at),
            opt_text(how.decided_by_admin_id),
            Param::from(r.auto_downgrade_reason.map(AutoDowngradeReason::code)),
            opt_text(how.resulting_approval_id),
            Param::from(i64::from(how.same_actor)),
        ],
    )
}

pub(crate) fn insert_revision_stmt(
    approval_id: &str,
    row_version: i64,
    changed_at: i64,
    changed_by_admin_id: Option<&str>,
    change: RevisionChange,
    before: Option<Vec<u8>>,
    after: Vec<u8>,
) -> (&'static str, Vec<Param>) {
    (
        "INSERT INTO app_approval_revisions (approval_id, row_version, changed_at, \
         changed_by_admin_id, change_kind, before_cbor, after_cbor) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        vec![
            text(approval_id),
            Param::from(row_version),
            Param::from(changed_at),
            opt_text(changed_by_admin_id),
            Param::from(change.code()),
            Param::from(before),
            Param::from(after),
        ],
    )
}

fn intake_params(r: &NewRequest, now: i64, cooldown: Option<i64>) -> Vec<Param> {
    vec![
        text(&r.host_uuid),
        text(&r.client_request_id),
        text(&r.lineage_id),
        text(&r.bin_sha),
        Param::from(now),
        opt_text(r.target.sid.as_deref()),
        Param::from(r.target.uid),
        Param::from(r.dedup_key.clone()),
        Param::from(cooldown),
    ]
}

/// Validate a request before any write (the CHECK constraints repeat this).
pub(crate) fn validate_request(r: &NewRequest) -> Result<(), LedgerError> {
    check_id(&r.request_id, "request_id")?;
    check_id(&r.host_uuid, "host_uuid")?;
    check_id(&r.client_request_id, "client_request_id")?;
    check_id(&r.lineage_id, "lineage_id")?;
    if !is_bin_sha(&r.bin_sha) {
        return Err(LedgerError::Invalid("bin_sha"));
    }
    if r.revision < 1 {
        return Err(LedgerError::Invalid("revision"));
    }
    if r.dedup_key.len() != 32 {
        return Err(LedgerError::Invalid("dedup_key"));
    }
    match r.target.kind {
        super::model::UserKind::Unix if r.target.uid.is_none() => {
            return Err(LedgerError::Invalid("target_user.uid"));
        }
        super::model::UserKind::Windows if r.target.sid.is_none() => {
            return Err(LedgerError::Invalid("target_user.sid"));
        }
        _ => {}
    }
    check_len(r.target.sid.as_deref(), 184, "target_user.sid")?;
    check_len(r.target.user_name.as_deref(), 256, "target_user.name")?;
    check_len(r.requester_user_name.as_deref(), 256, "requested_by.name")?;
    check_len(r.reason.as_deref(), 200, "reason")?;
    check_len(Some(&r.host_tier), 64, "host_tier")?;
    check_len(Some(&r.proposer_spiffe_id), 2048, "proposer_spiffe_id")?;
    if r.origin == RequestOrigin::AdminDirect && r.requested_by_admin_id.is_none() {
        return Err(LedgerError::Invalid("requested_by_admin_id"));
    }
    Ok(())
}

fn validate_binary(b: &ObservedBinary) -> Result<(), LedgerError> {
    check_id(&b.host_uuid, "host_uuid")?;
    check_id(&b.new_lineage_id, "lineage_id")?;
    if !(1..=3).contains(&b.platform) {
        return Err(LedgerError::Invalid("binary.platform"));
    }
    if b.canonical_path.is_empty() || b.canonical_path.len() > 4096 {
        return Err(LedgerError::Invalid("binary.canonical_path"));
    }
    if b.path_key.is_empty() || b.path_key.len() > 8192 {
        return Err(LedgerError::Invalid("binary.path_key"));
    }
    if !is_bin_sha(&b.bin_sha) {
        return Err(LedgerError::Invalid("binary.sha384"));
    }
    if b.file_size < 0 {
        return Err(LedgerError::Invalid("binary.size"));
    }
    if ![1, 2, 3, 9].contains(&b.format) {
        return Err(LedgerError::Invalid("binary.format"));
    }
    if !(0..=7).contains(&b.version_source) {
        return Err(LedgerError::Invalid("binary.version_source"));
    }
    if !(0..=2).contains(&b.signer_kind) {
        return Err(LedgerError::Invalid("binary.signer.kind"));
    }
    check_len(b.declared_version.as_deref(), 64, "binary.declared_version")?;
    check_len(b.product_name.as_deref(), 128, "binary.product_name")?;
    check_len(b.bundle_id.as_deref(), 255, "binary.bundle_id")?;
    check_len(b.package_name.as_deref(), 128, "binary.package_name")?;
    check_len(b.signer_id.as_deref(), 128, "binary.signer.id")?;
    check_len(b.signer_subject.as_deref(), 256, "binary.signer.subject")?;
    Ok(())
}

impl Cluster {
    /// Find or create the lineage of `(host, path_key)` and find or allocate
    /// the revision of `bin_sha` in it (F19 §5.1 steps 5.1–5.2), atomically
    /// and idempotently.
    ///
    /// A new binary takes the lineage's `next_revision`, which then advances
    /// by one, so revisions are 1, 2, 3, … in first-sight order and never
    /// reused. A binary seen before keeps its revision and its first-sight
    /// metadata (binary rows are immutable).
    pub async fn app_observe_binary(
        &self,
        b: &ObservedBinary,
    ) -> Result<(LineageRow, BinaryRow), LedgerError> {
        validate_binary(b)?;
        let host = || text(&b.host_uuid);
        let key = || Param::from(b.path_key.clone());
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "INSERT INTO app_lineages (lineage_id, host_uuid, platform, canonical_path, \
                 path_key, next_revision, auto_update_frozen, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, ?6) \
                 ON CONFLICT (host_uuid, path_key) DO NOTHING",
                vec![
                    text(&b.new_lineage_id),
                    host(),
                    Param::from(b.platform),
                    text(&b.canonical_path),
                    key(),
                    Param::from(b.seen_at),
                ],
            ),
            (
                "INSERT INTO app_binaries (lineage_id, bin_sha, revision, file_size, format, \
                 declared_version, version_source, product_name, bundle_id, package_name, \
                 signer_kind, signer_id, signer_subject, signer_valid, first_seen_at) \
                 SELECT l.lineage_id, ?3, l.next_revision, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, \
                    ?12, ?13, ?14, ?15 \
                 FROM app_lineages l WHERE l.host_uuid = ?1 AND l.path_key = ?2 \
                 AND NOT EXISTS (SELECT 1 FROM app_binaries x \
                    WHERE x.lineage_id = l.lineage_id AND x.bin_sha = ?3)",
                vec![
                    host(),
                    key(),
                    text(&b.bin_sha),
                    Param::from(b.file_size),
                    Param::from(b.format),
                    opt_text(b.declared_version.as_deref()),
                    Param::from(b.version_source),
                    opt_text(b.product_name.as_deref()),
                    opt_text(b.bundle_id.as_deref()),
                    opt_text(b.package_name.as_deref()),
                    Param::from(b.signer_kind),
                    opt_text(b.signer_id.as_deref()),
                    opt_text(b.signer_subject.as_deref()),
                    Param::from(i64::from(b.signer_valid)),
                    Param::from(b.seen_at),
                ],
            ),
            (
                "UPDATE app_lineages SET next_revision = next_revision + 1 \
                 WHERE host_uuid = ?1 AND path_key = ?2 \
                 AND EXISTS (SELECT 1 FROM app_binaries x \
                    WHERE x.lineage_id = app_lineages.lineage_id \
                    AND x.revision = app_lineages.next_revision)",
                vec![host(), key()],
            ),
        ];
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(generic_refusal(&code)),
        }
        let lineage = self
            .app_lineage_by_path(&b.host_uuid, &b.path_key)
            .await?
            .ok_or(LedgerError::Raced)?;
        let binary = self
            .app_binary(&lineage.lineage_id, &b.bin_sha)
            .await?
            .ok_or(LedgerError::Raced)?;
        Ok((lineage, binary))
    }

    /// Record `req` as a `PENDING` request unless deduplication returns an
    /// existing record (F19 §5.1 steps 3 and 5.3–5.5, §5.2).
    ///
    /// The checks and the insert run in one transaction, and the database
    /// additionally refuses a second open request with the same dedup key, so
    /// concurrent submissions cannot create duplicates. The kind
    /// (register / update) is classified here. Nothing is ever overwritten.
    pub async fn app_submit_pending(
        &self,
        req: &NewRequest,
        checks: &IntakeChecks,
    ) -> Result<Intake, LedgerError> {
        validate_request(req)?;
        let stmts = vec![
            (
                PENDING_GUARD,
                intake_params(req, checks.now, checks.denied_cooldown_since),
            ),
            insert_request_stmt(
                req,
                &RecordedAs {
                    state: RequestState::Pending,
                    decided_at: None,
                    decided_by_admin_id: None,
                    resulting_approval_id: None,
                    same_actor: false,
                },
            ),
        ];
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {
                let row = self
                    .app_request(&req.request_id)
                    .await?
                    .ok_or(LedgerError::Raced)?;
                Ok(Intake::Recorded(row))
            }
            TxnOutcome::Refused(code) => {
                self.dedup_outcome(&code, req, checks.now, checks.denied_cooldown_since)
                    .await
            }
        }
    }

    /// Auto-approve `req` under the auto-update policy of the newest active
    /// `AutoSamePathUser` approval of its lineage (F19 §5.3), or report the
    /// first failing condition.
    ///
    /// The caller has already checked the configuration-level condition #1
    /// (global switch and host tier). Conditions #2 to #7 are decided here,
    /// inside the transaction that writes, so they cannot change between the
    /// check and the write. On success, in one transaction: the new approval
    /// (copying the parent's user, scope, policy, continuity and **expiry**),
    /// its creation revision, the `AUTO_APPROVED` request, the parent's
    /// informational `superseded_by` mark (the parent stays `ACTIVE`), and the
    /// host's generation bump.
    pub async fn app_try_auto_approve(
        &self,
        req: &NewRequest,
        approval_id: &str,
        checks: &AutoChecks,
    ) -> Result<AutoIntake, LedgerError> {
        validate_request(req)?;
        check_id(approval_id, "approval_id")?;
        if req.origin == RequestOrigin::AdminDirect {
            return Err(LedgerError::Invalid("origin"));
        }
        for _ in 0..AUTO_ATTEMPTS {
            let parent = self
                .app_auto_parent(&req.host_uuid, &req.lineage_id, checks.now)
                .await?;
            let stmts = auto_stmts(req, parent.as_ref(), approval_id, checks)?;
            match self.ledger_txn(stmts).await? {
                TxnOutcome::Committed if parent.is_some() => {
                    let request = self
                        .app_request(&req.request_id)
                        .await?
                        .ok_or(LedgerError::Raced)?;
                    let approval = self
                        .app_approval(approval_id)
                        .await?
                        .ok_or(LedgerError::Raced)?;
                    let generation = self
                        .app_allowlist_state(&req.host_uuid)
                        .await?
                        .map_or(0, |s| s.generation);
                    return Ok(AutoIntake::AutoApproved(Box::new(AutoApproval {
                        request,
                        approval,
                        generation,
                    })));
                }
                // No parent was read and the guard found none either.
                TxnOutcome::Committed => {
                    return Ok(AutoIntake::NotEligible(AutoDowngradeReason::NoAutoParent));
                }
                TxnOutcome::Refused(code) if code == "stale" => {}
                TxnOutcome::Refused(code) => {
                    if let Some(reason) = AutoDowngradeReason::from_str_code(&code) {
                        return Ok(AutoIntake::NotEligible(reason));
                    }
                    return self
                        .dedup_outcome(&code, req, checks.now, checks.denied_cooldown_since)
                        .await
                        .map(|i| AutoIntake::Deduplicated(Box::new(i)));
                }
            }
        }
        Err(LedgerError::Raced)
    }

    /// Turn a deduplication guard code into the existing record it names.
    async fn dedup_outcome(
        &self,
        code: &str,
        req: &NewRequest,
        now: i64,
        cooldown: Option<i64>,
    ) -> Result<Intake, LedgerError> {
        let found = match code {
            "replayed" => self
                .app_request_by_client_id(&req.host_uuid, &req.client_request_id)
                .await?
                .map(Intake::Replayed),
            "covered" => self
                .app_covering_approval(
                    &req.host_uuid,
                    &req.lineage_id,
                    &req.bin_sha,
                    &req.target,
                    now,
                )
                .await?
                .map(Intake::Covered),
            "duplicate_pending" => self
                .app_pending_by_dedup(&req.dedup_key)
                .await?
                .map(Intake::DuplicatePending),
            "denied_cooldown" => match cooldown {
                Some(since) => self
                    .app_recent_denial(&req.dedup_key, since)
                    .await?
                    .map(Intake::RecentlyDenied),
                None => None,
            },
            other => return Err(generic_refusal(other)),
        };
        // The record existed when the guard ran; if it is gone now (an
        // approval revoked in between), the caller retries.
        found.ok_or(LedgerError::Raced)
    }
}

/// The guard and, when a parent candidate was read, the writes of one
/// auto-approval attempt.
fn auto_stmts(
    req: &NewRequest,
    parent: Option<&ApprovalRow>,
    approval_id: &str,
    checks: &AutoChecks,
) -> Result<Vec<(&'static str, Vec<Param>)>, LedgerError> {
    let mut params = intake_params(req, checks.now, checks.denied_cooldown_since);
    params.extend([
        opt_text(parent.map(|p| p.approval_id.as_str())),
        Param::from(parent.map(|p| p.row_version)),
        Param::from(i64::from(req.flags)),
        opt_text(req.target.user_name.as_deref()),
        Param::from(checks.max_per_day),
        Param::from(checks.now - 86_400),
    ]);
    let mut stmts: Vec<(&'static str, Vec<Param>)> = vec![(AUTO_GUARD, params)];
    if let Some(parent) = parent {
        let child = child_of(parent, approval_id, req, checks.now);
        stmts.push((
            "INSERT INTO app_approvals (approval_id, host_uuid, lineage_id, bin_sha, \
             revision, source_request_id, origin, parent_approval_id, \
             approved_by_admin_id, user_scope, user_kind, uid, sid, user_name, \
             path_match, update_policy, continuity, created_at, expires_at, state, \
             superseded_by, revoked_at, revoked_by_admin_id, revoke_reason_code, note, \
             row_version) \
             SELECT ?1, p.host_uuid, p.lineage_id, ?2, ?3, ?4, 2, p.approval_id, NULL, \
        p.user_scope, p.user_kind, p.uid, p.sid, p.user_name, p.path_match, \
        p.update_policy, p.continuity, ?5, p.expires_at, 1, NULL, NULL, NULL, \
        NULL, NULL, 1 \
             FROM app_approvals p WHERE p.approval_id = ?6",
            vec![
                text(approval_id),
                text(&req.bin_sha),
                Param::from(req.revision),
                text(&req.request_id),
                Param::from(checks.now),
                text(&parent.approval_id),
            ],
        ));
        stmts.push(insert_revision_stmt(
            approval_id,
            1,
            checks.now,
            None,
            RevisionChange::Created,
            None,
            ApprovalSnapshot::of(&child).to_cbor()?,
        ));
        stmts.push(insert_request_stmt(
            req,
            &RecordedAs {
                state: RequestState::AutoApproved,
                decided_at: Some(checks.now),
                decided_by_admin_id: None,
                resulting_approval_id: Some(approval_id),
                same_actor: false,
            },
        ));
        stmts.push((
            "UPDATE app_approvals SET superseded_by = ?1 \
             WHERE approval_id = ?2 AND superseded_by IS NULL AND state = 1 \
             AND revision < ?3",
            vec![
                text(approval_id),
                text(&parent.approval_id),
                Param::from(req.revision),
            ],
        ));
        stmts.push(bump_generation_stmt(
            &req.host_uuid,
            checks.generation_millis,
            checks.now,
        ));
    }
    Ok(stmts)
}

/// The approval an auto-update creates from `parent`: everything that
/// scopes it is copied, expiry included (auto-update never extends the
/// window a person approved). Used to build the creation snapshot; the
/// insert itself copies the same columns in SQL.
fn child_of(parent: &ApprovalRow, approval_id: &str, req: &NewRequest, now: i64) -> ApprovalRow {
    ApprovalRow {
        approval_id: approval_id.to_string(),
        host_uuid: parent.host_uuid.clone(),
        lineage_id: parent.lineage_id.clone(),
        bin_sha: req.bin_sha.clone(),
        revision: Some(req.revision),
        source_request_id: Some(req.request_id.clone()),
        origin: ApprovalOrigin::AutoUpdate,
        parent_approval_id: Some(parent.approval_id.clone()),
        approved_by_admin_id: None,
        user_scope: parent.user_scope,
        user_kind: parent.user_kind,
        uid: parent.uid,
        sid: parent.sid.clone(),
        user_name: parent.user_name.clone(),
        path_match: parent.path_match,
        update_policy: parent.update_policy,
        continuity: parent.continuity,
        created_at: now,
        expires_at: parent.expires_at,
        state: ApprovalState::Active,
        superseded_by: None,
        revoked_at: None,
        revoked_by_admin_id: None,
        revoke_reason_code: None,
        note: None,
        row_version: 1,
    }
}
