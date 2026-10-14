//! Decisions on requests (F19 §3, §5.4, §5.5): approve, deny, single-step
//! direct registration, and expiry of stale pending requests.
//!
//! Approving request R creates exactly one approval (or reuses one named
//! approval) and alters no other approval unless the administrator lists it
//! in [`Approve::also_revoke`], in which case each listed id is its own
//! revocation with its own revision record (ADR-0004 INV-2).

use hiqlite::Param;

use super::approvals::{revoke_stmts, validate_revoke, Revoke};
use super::generation::bump_generation_stmt;
use super::intake::{insert_request_stmt, insert_revision_stmt, validate_request, RecordedAs};
use super::model::{
    ApprovalOrigin, ApprovalRow, ApprovalSnapshot, ApprovalState, ApprovalTerms, NewRequest,
    RequestOrigin, RequestRow, RequestState, RevisionChange, UserScope,
};
use super::{check_id, check_len, generic_refusal, opt_text, text, LedgerError, TxnOutcome};
use crate::cluster::Cluster;

/// What an approval decision authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalChoice {
    /// Create a new approval with these terms.
    New {
        /// Id of the new approval (UUIDv7).
        approval_id: String,
        /// Terms chosen by the administrator.
        terms: ApprovalTerms,
    },
    /// Point the request at an existing active approval that already covers
    /// it (same host, same or wildcard hash, its user admitted).
    Reuse {
        /// The covering approval.
        approval_id: String,
    },
}

/// `ApproveAppRequest` (F19 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approve {
    /// The pending request.
    pub request_id: String,
    /// The approving administrator (authorized by the caller).
    pub admin_id: String,
    /// Unix seconds.
    pub now: i64,
    /// New or reused approval.
    pub choice: ApprovalChoice,
    /// Strict separation of duties (`CMIS_ADMIN_STRICT_SOD`): refuse when
    /// the approver requested the registration.
    pub forbid_self_approval: bool,
    /// Approvals to revoke in the same call (INV-2: named explicitly).
    pub also_revoke: Vec<Revoke>,
    /// Unix milliseconds for the generation bump.
    pub generation_millis: i64,
}

/// `DenyAppRequest` (F19 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
    /// The pending request.
    pub request_id: String,
    /// The denying administrator.
    pub admin_id: String,
    /// Unix seconds.
    pub now: i64,
    /// Required reason code.
    pub reason_code: i64,
    /// Message shown to the requester (≤ 200 characters).
    pub message: Option<String>,
    /// As [`Approve::forbid_self_approval`].
    pub forbid_self_approval: bool,
}

/// Result of an approval decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    /// The request, now `APPROVED`.
    pub request: RequestRow,
    /// The approval it resulted in.
    pub approval: ApprovalRow,
    /// The requester and the approver were the same administrator (audited
    /// as `AppApprovedBySameActor`).
    pub same_actor: bool,
    /// Approvals revoked by the same call.
    pub revoked: Vec<ApprovalRow>,
    /// The host's allowlist generation after the bump.
    pub generation: u64,
}

const INSERT_APPROVAL: &str = "INSERT INTO app_approvals (approval_id, host_uuid, lineage_id, \
    bin_sha, revision, source_request_id, origin, parent_approval_id, approved_by_admin_id, \
    user_scope, user_kind, uid, sid, user_name, path_match, update_policy, continuity, \
    created_at, expires_at, state, superseded_by, revoked_at, revoked_by_admin_id, \
    revoke_reason_code, note, row_version) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
        ?18, 1, NULL, NULL, NULL, NULL, ?19, 1)";

fn validate_terms(terms: &ApprovalTerms) -> Result<(), LedgerError> {
    check_len(terms.note.as_deref(), 500, "note")
}

/// The approval a decision on `request` creates under `terms`. The user
/// identity is the request's target for an exact-user scope.
fn approval_for(
    request_like: &RequestFacts<'_>,
    approval_id: &str,
    admin_id: &str,
    terms: &ApprovalTerms,
    now: i64,
) -> ApprovalRow {
    let exact = terms.user_scope == UserScope::ExactUser;
    ApprovalRow {
        approval_id: approval_id.to_string(),
        host_uuid: request_like.host_uuid.to_string(),
        lineage_id: request_like.lineage_id.to_string(),
        bin_sha: request_like.bin_sha.to_string(),
        revision: Some(request_like.revision),
        source_request_id: Some(request_like.request_id.to_string()),
        origin: if request_like.origin == RequestOrigin::AdminDirect {
            ApprovalOrigin::AdminDirect
        } else {
            ApprovalOrigin::Manual
        },
        parent_approval_id: None,
        approved_by_admin_id: Some(admin_id.to_string()),
        user_scope: terms.user_scope,
        user_kind: exact.then_some(request_like.target.kind),
        uid: request_like.target.uid.filter(|_| exact),
        sid: request_like.target.sid.clone().filter(|_| exact),
        user_name: request_like.target.user_name.clone().filter(|_| exact),
        path_match: terms.path_match,
        update_policy: terms.update_policy,
        continuity: terms.continuity,
        created_at: now,
        expires_at: terms.expires_at,
        state: ApprovalState::Active,
        superseded_by: None,
        revoked_at: None,
        revoked_by_admin_id: None,
        revoke_reason_code: None,
        note: terms.note.clone(),
        row_version: 1,
    }
}

/// The request facts an approval is built from.
struct RequestFacts<'a> {
    request_id: &'a str,
    host_uuid: &'a str,
    lineage_id: &'a str,
    bin_sha: &'a str,
    revision: i64,
    origin: RequestOrigin,
    target: &'a super::model::UserIdentity,
}

impl<'a> From<&'a RequestRow> for RequestFacts<'a> {
    fn from(r: &'a RequestRow) -> Self {
        Self {
            request_id: &r.request_id,
            host_uuid: &r.host_uuid,
            lineage_id: &r.lineage_id,
            bin_sha: &r.bin_sha,
            revision: r.revision,
            origin: r.origin,
            target: &r.target,
        }
    }
}

impl<'a> From<&'a NewRequest> for RequestFacts<'a> {
    fn from(r: &'a NewRequest) -> Self {
        Self {
            request_id: &r.request_id,
            host_uuid: &r.host_uuid,
            lineage_id: &r.lineage_id,
            bin_sha: &r.bin_sha,
            revision: r.revision,
            origin: r.origin,
            target: &r.target,
        }
    }
}

fn insert_approval_stmt(a: &ApprovalRow) -> (&'static str, Vec<Param>) {
    (
        INSERT_APPROVAL,
        vec![
            text(&a.approval_id),
            text(&a.host_uuid),
            text(&a.lineage_id),
            text(&a.bin_sha),
            Param::from(a.revision),
            opt_text(a.source_request_id.as_deref()),
            Param::from(a.origin.code()),
            opt_text(a.approved_by_admin_id.as_deref()),
            Param::from(a.user_scope.code()),
            Param::from(a.user_kind.map(super::model::UserKind::code)),
            Param::from(a.uid),
            opt_text(a.sid.as_deref()),
            opt_text(a.user_name.as_deref()),
            Param::from(a.path_match.code()),
            Param::from(a.update_policy.code()),
            Param::from(a.continuity.code()),
            Param::from(a.created_at),
            Param::from(a.expires_at),
            opt_text(a.note.as_deref()),
        ],
    )
}

/// Guard of a decision on a request: it exists, is `PENDING`, and — under
/// the strict separation-of-duties policy — was not requested by the
/// deciding administrator.
fn decision_guard_stmt(
    request_id: &str,
    admin_id: &str,
    forbid_self_approval: bool,
) -> (&'static str, Vec<Param>) {
    (
        "INSERT INTO app_txn_guard (code) SELECT c FROM (SELECT CASE \
         WHEN NOT EXISTS (SELECT 1 FROM app_requests WHERE request_id = ?1) THEN 'not_found' \
         WHEN NOT EXISTS (SELECT 1 FROM app_requests WHERE request_id = ?1 AND state = 1) \
            THEN 'invalid_state' \
         WHEN ?3 = 1 AND EXISTS (SELECT 1 FROM app_requests \
            WHERE request_id = ?1 AND requested_by_admin_id = ?2) THEN 'sod_self_approval' \
         ELSE 'ok' END AS c) WHERE c <> 'ok'",
        vec![
            text(request_id),
            text(admin_id),
            Param::from(i64::from(forbid_self_approval)),
        ],
    )
}

/// Mark older active approvals of the lineage for the same user as
/// superseded by `a` (informational only; they stay `ACTIVE`).
fn supersede_stmt(a: &ApprovalRow) -> (&'static str, Vec<Param>) {
    (
        "UPDATE app_approvals SET superseded_by = ?1 \
         WHERE lineage_id = ?2 AND approval_id <> ?1 AND state = 1 AND superseded_by IS NULL \
         AND revision < ?3 AND user_scope = ?4 AND uid IS ?5 AND sid IS ?6",
        vec![
            text(&a.approval_id),
            text(&a.lineage_id),
            Param::from(a.revision),
            Param::from(a.user_scope.code()),
            Param::from(a.uid),
            opt_text(a.sid.as_deref()),
        ],
    )
}

impl Cluster {
    /// Approve a `PENDING` request (`ApproveAppRequest`), atomically: the
    /// new approval and its creation revision (or the reused approval), the
    /// request's decision, each listed revocation, and the generation bump.
    ///
    /// Refusals (nothing written): [`LedgerError::NotFound`],
    /// [`LedgerError::InvalidState`] (not pending, or a listed revocation is
    /// not revocable), [`LedgerError::SelfApproval`],
    /// [`LedgerError::NotCovering`], [`LedgerError::RowVersionMismatch`].
    pub async fn app_approve_request(&self, a: &Approve) -> Result<Decided, LedgerError> {
        check_id(&a.request_id, "request_id")?;
        check_id(&a.admin_id, "admin_id")?;
        for r in &a.also_revoke {
            validate_revoke(r)?;
        }
        let request = self
            .app_request(&a.request_id)
            .await?
            .ok_or(LedgerError::NotFound)?;
        if request.state != RequestState::Pending {
            return Err(LedgerError::InvalidState);
        }
        let mut stmts = vec![decision_guard_stmt(
            &a.request_id,
            &a.admin_id,
            a.forbid_self_approval,
        )];
        let approval_id = match &a.choice {
            ApprovalChoice::New { approval_id, terms } => {
                check_id(approval_id, "approval_id")?;
                validate_terms(terms)?;
                let approval =
                    approval_for(&(&request).into(), approval_id, &a.admin_id, terms, a.now);
                stmts.push(insert_approval_stmt(&approval));
                stmts.push(insert_revision_stmt(
                    approval_id,
                    1,
                    a.now,
                    Some(&a.admin_id),
                    RevisionChange::Created,
                    None,
                    ApprovalSnapshot::of(&approval).to_cbor()?,
                ));
                stmts.push(supersede_stmt(&approval));
                approval_id.clone()
            }
            ApprovalChoice::Reuse { approval_id } => {
                check_id(approval_id, "approval_id")?;
                stmts.push((
                    "INSERT INTO app_txn_guard (code) SELECT 'not_covering' \
                     WHERE NOT EXISTS (SELECT 1 FROM app_approvals a JOIN app_requests r \
                        ON r.request_id = ?2 \
                        WHERE a.approval_id = ?1 AND a.host_uuid = r.host_uuid AND a.state = 1 \
                        AND (a.expires_at IS NULL OR a.expires_at > ?3) \
                        AND (a.bin_sha = r.bin_sha OR a.bin_sha = '*') \
                        AND (a.lineage_id = r.lineage_id OR a.path_match = 2) \
                        AND (a.user_scope = 2 \
                            OR (a.sid IS NOT NULL AND upper(a.sid) = upper(r.target_sid)) \
                            OR (a.sid IS NULL AND a.uid IS NOT NULL AND a.uid = r.target_uid)))",
                    vec![text(approval_id), text(&a.request_id), Param::from(a.now)],
                ));
                approval_id.clone()
            }
        };
        stmts.push((
            "UPDATE app_requests SET state = 2, decided_at = ?2, decided_by_admin_id = ?3, \
             resulting_approval_id = ?4, \
             same_actor_approved = (requested_by_admin_id IS NOT NULL \
                AND requested_by_admin_id = ?3) \
             WHERE request_id = ?1 AND state = 1",
            vec![
                text(&a.request_id),
                Param::from(a.now),
                text(&a.admin_id),
                text(&approval_id),
            ],
        ));
        let mut revoked_ids = Vec::with_capacity(a.also_revoke.len());
        for r in &a.also_revoke {
            let current = self
                .app_approval(&r.approval_id)
                .await?
                .ok_or(LedgerError::NotFound)?;
            if current.host_uuid != request.host_uuid {
                // Only approvals of the same host can be revoked alongside.
                return Err(LedgerError::NotFound);
            }
            stmts.extend(revoke_stmts(&current, r, a.now)?);
            revoked_ids.push(r.approval_id.clone());
        }
        stmts.push(bump_generation_stmt(
            &request.host_uuid,
            a.generation_millis,
            a.now,
        ));
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(generic_refusal(&code)),
        }
        self.decided(
            &a.request_id,
            &approval_id,
            &revoked_ids,
            &request.host_uuid,
        )
        .await
    }

    /// Deny a `PENDING` request (`DenyAppRequest`). The request stays visible
    /// with its decision (INV-3); a later ask is a new request.
    pub async fn app_deny_request(&self, d: &Deny) -> Result<RequestRow, LedgerError> {
        check_id(&d.request_id, "request_id")?;
        check_id(&d.admin_id, "admin_id")?;
        check_len(d.message.as_deref(), 200, "message")?;
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            decision_guard_stmt(&d.request_id, &d.admin_id, d.forbid_self_approval),
            (
                "UPDATE app_requests SET state = 4, decided_at = ?2, decided_by_admin_id = ?3, \
                 decision_reason_code = ?4, decision_message = ?5 \
                 WHERE request_id = ?1 AND state = 1",
                vec![
                    text(&d.request_id),
                    Param::from(d.now),
                    text(&d.admin_id),
                    Param::from(d.reason_code),
                    opt_text(d.message.as_deref()),
                ],
            ),
        ];
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(generic_refusal(&code)),
        }
        self.app_request(&d.request_id)
            .await?
            .ok_or(LedgerError::Raced)
    }

    /// Single-step direct registration (`AdminRegisterApplication` with the
    /// strict separation-of-duties policy off, F19 §5.4): the `admin_direct`
    /// request is recorded `APPROVED` by its own requester together with its
    /// approval, the creation revision and the generation bump, in one
    /// transaction (`same_actor_approved = 1`). It creates exactly one
    /// approval and alters no other.
    ///
    /// With the strict policy on, record the request with
    /// [`Cluster::app_submit_pending`] instead.
    pub async fn app_register_and_approve(
        &self,
        req: &NewRequest,
        approval_id: &str,
        terms: &ApprovalTerms,
        generation_millis: i64,
    ) -> Result<Decided, LedgerError> {
        validate_request(req)?;
        check_id(approval_id, "approval_id")?;
        validate_terms(terms)?;
        let admin_id = match (&req.origin, &req.requested_by_admin_id) {
            (RequestOrigin::AdminDirect, Some(admin)) => admin.clone(),
            _ => return Err(LedgerError::Invalid("origin")),
        };
        let now = req.submitted_at;
        let approval = approval_for(&req.into(), approval_id, &admin_id, terms, now);
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "INSERT INTO app_txn_guard (code) SELECT 'replayed' WHERE EXISTS \
                 (SELECT 1 FROM app_requests WHERE host_uuid = ?1 AND client_request_id = ?2)",
                vec![text(&req.host_uuid), text(&req.client_request_id)],
            ),
            insert_approval_stmt(&approval),
            insert_revision_stmt(
                approval_id,
                1,
                now,
                Some(&admin_id),
                RevisionChange::Created,
                None,
                ApprovalSnapshot::of(&approval).to_cbor()?,
            ),
            insert_request_stmt(
                req,
                &RecordedAs {
                    state: RequestState::Approved,
                    decided_at: Some(now),
                    decided_by_admin_id: Some(&admin_id),
                    resulting_approval_id: Some(approval_id),
                    same_actor: true,
                },
            ),
            supersede_stmt(&approval),
            bump_generation_stmt(&req.host_uuid, generation_millis, now),
        ];
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) if code == "replayed" => {
                return Err(LedgerError::InvalidState);
            }
            TxnOutcome::Refused(code) => return Err(generic_refusal(&code)),
        }
        self.decided(&req.request_id, approval_id, &[], &req.host_uuid)
            .await
    }

    /// Expire a `PENDING` request whose `pending_expires_at` has passed
    /// (sweeper, F19 §5.5). Returns `false` and writes nothing when the
    /// request is not pending or not yet due.
    pub async fn app_expire_request(
        &self,
        request_id: &str,
        now: i64,
    ) -> Result<bool, LedgerError> {
        let n = self
            .client()
            .execute(
                "UPDATE app_requests SET state = 5, decided_at = ?2 \
                 WHERE request_id = ?1 AND state = 1 AND pending_expires_at <= ?2",
                vec![text(request_id), Param::from(now)],
            )
            .await
            .map_err(crate::cluster::ClusterError::from)?;
        Ok(n > 0)
    }

    async fn decided(
        &self,
        request_id: &str,
        approval_id: &str,
        revoked_ids: &[String],
        host_uuid: &str,
    ) -> Result<Decided, LedgerError> {
        let request = self
            .app_request(request_id)
            .await?
            .ok_or(LedgerError::Raced)?;
        let approval = self
            .app_approval(approval_id)
            .await?
            .ok_or(LedgerError::Raced)?;
        let mut revoked = Vec::with_capacity(revoked_ids.len());
        for id in revoked_ids {
            revoked.push(self.app_approval(id).await?.ok_or(LedgerError::Raced)?);
        }
        let generation = self
            .app_allowlist_state(host_uuid)
            .await?
            .map_or(0, |s| s.generation);
        Ok(Decided {
            same_actor: request.same_actor_approved,
            request,
            approval,
            revoked,
            generation,
        })
    }
}
