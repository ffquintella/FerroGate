//! Administrator and sweeper changes to approvals (F19 §3, §5.4, §5.5):
//! edit and renew, revoke, expire, and the lineage auto-update freeze.
//!
//! Each change names one approval by id, is checked against the approval's
//! `row_version`, and appends an `app_approval_revisions` record in the same
//! transaction (ADR-0004 INV-2). The database refuses any approval update
//! that skips the revision record, widens a scope or touches a revoked row.

use hiqlite::Param;

use super::generation::bump_generation_stmt;
use super::intake::insert_revision_stmt;
use super::model::{
    ApprovalRow, ApprovalSnapshot, ApprovalState, Continuity, PathMatch, RevisionChange,
    UpdatePolicy, UserIdentity, UserKind, UserScope,
};
use super::{check_id, check_len, generic_refusal, opt_text, text, LedgerError, TxnOutcome};
use crate::cluster::{Cluster, ClusterError};

/// `RevokeApproval` ("delete"): the record is kept, `REVOKED` is final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoke {
    /// The approval.
    pub approval_id: String,
    /// The revoking administrator.
    pub admin_id: String,
    /// Required reason code.
    pub reason_code: i64,
    /// Optimistic concurrency; `None` revokes whatever the current version is.
    pub expected_row_version: Option<i64>,
}

/// `UpdateApproval` (F19 §5.4). `None` fields are left unchanged. Scope can
/// only be narrowed; widening needs a new request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalEdit {
    /// The approval.
    pub approval_id: String,
    /// The editing administrator.
    pub admin_id: String,
    /// Optimistic concurrency (`ABORTED row_version_mismatch` on a miss).
    pub expected_row_version: i64,
    /// Unix seconds.
    pub now: i64,
    /// New update policy.
    pub update_policy: Option<UpdatePolicy>,
    /// New continuity requirement.
    pub continuity: Option<Continuity>,
    /// New expiry (`Some(None)`: no expiry, where configuration allows it).
    /// A future expiry on an `EXPIRED` approval renews it.
    pub expires_at: Option<Option<i64>>,
    /// New note (`Some(None)` clears it).
    pub note: Option<Option<String>>,
    /// Narrow an any-user approval to the user of its source request.
    pub narrow_to_exact_user: bool,
    /// Narrow an any-path approval to its lineage path.
    pub narrow_to_exact_path: bool,
    /// Unix milliseconds for the generation bump.
    pub generation_millis: i64,
}

pub(crate) fn validate_revoke(r: &Revoke) -> Result<(), LedgerError> {
    check_id(&r.approval_id, "approval_id")?;
    check_id(&r.admin_id, "admin_id")
}

/// Guard, revision record and update that revoke `current` (read just
/// before). The guard pins the row version that the `before` snapshot
/// describes.
pub(crate) fn revoke_stmts(
    current: &ApprovalRow,
    r: &Revoke,
    now: i64,
) -> Result<Vec<(&'static str, Vec<Param>)>, LedgerError> {
    if current.state == ApprovalState::Revoked {
        return Err(LedgerError::InvalidState);
    }
    if r.expected_row_version
        .is_some_and(|v| v != current.row_version)
    {
        return Err(LedgerError::RowVersionMismatch);
    }
    let mut after = current.clone();
    after.state = ApprovalState::Revoked;
    after.revoked_at = Some(now);
    after.revoked_by_admin_id = Some(r.admin_id.clone());
    after.revoke_reason_code = Some(r.reason_code);
    after.row_version += 1;
    Ok(vec![
        (
            "INSERT INTO app_txn_guard (code) SELECT c FROM (SELECT CASE \
             WHEN NOT EXISTS (SELECT 1 FROM app_approvals WHERE approval_id = ?1) \
                THEN 'not_found' \
             WHEN NOT EXISTS (SELECT 1 FROM app_approvals \
                WHERE approval_id = ?1 AND state IN (1, 2)) THEN 'invalid_state' \
             WHEN NOT EXISTS (SELECT 1 FROM app_approvals \
                WHERE approval_id = ?1 AND row_version = ?2) \
                THEN CASE WHEN ?3 = 1 THEN 'row_version_mismatch' ELSE 'stale' END \
             ELSE 'ok' END AS c) WHERE c <> 'ok'",
            vec![
                text(&current.approval_id),
                Param::from(current.row_version),
                Param::from(i64::from(r.expected_row_version.is_some())),
            ],
        ),
        insert_revision_stmt(
            &current.approval_id,
            after.row_version,
            now,
            Some(&r.admin_id),
            RevisionChange::Revoked,
            Some(ApprovalSnapshot::of(current).to_cbor()?),
            ApprovalSnapshot::of(&after).to_cbor()?,
        ),
        (
            "UPDATE app_approvals SET state = 3, revoked_at = ?2, revoked_by_admin_id = ?3, \
             revoke_reason_code = ?4, row_version = row_version + 1 \
             WHERE approval_id = ?1 AND row_version = ?5 AND state IN (1, 2)",
            vec![
                text(&current.approval_id),
                Param::from(now),
                text(&r.admin_id),
                Param::from(r.reason_code),
                Param::from(current.row_version),
            ],
        ),
    ])
}

/// `current` with the edit applied (row version unchanged), and whether the
/// edit renews an expired approval. `source_target` is the user an any-user
/// scope narrows to.
fn edited(
    current: &ApprovalRow,
    e: &ApprovalEdit,
    source_target: Option<UserIdentity>,
) -> (ApprovalRow, bool) {
    let mut after = current.clone();
    if let Some(policy) = e.update_policy {
        after.update_policy = policy;
    }
    if let Some(continuity) = e.continuity {
        after.continuity = continuity;
    }
    if let Some(expires_at) = e.expires_at {
        after.expires_at = expires_at;
    }
    if let Some(note) = &e.note {
        after.note.clone_from(note);
    }
    if e.narrow_to_exact_path {
        after.path_match = PathMatch::Exact;
    }
    if let Some(target) = source_target {
        after.user_scope = UserScope::ExactUser;
        after.user_kind = Some(target.kind);
        after.uid = target.uid;
        after.sid = target.sid;
        after.user_name = target.user_name;
    }
    let renewal = current.state == ApprovalState::Expired
        && e.expires_at.is_some()
        && after.expires_at.is_none_or(|t| t > e.now);
    if renewal {
        after.state = ApprovalState::Active;
    }
    (after, renewal)
}

/// Whether a change alters the compiled allowlist entry of an approval
/// (F19 §6.1: state, user, path constraint, expiry).
fn changes_compiled_entry(before: &ApprovalRow, after: &ApprovalRow) -> bool {
    before.state != after.state
        || before.expires_at != after.expires_at
        || before.user_scope != after.user_scope
        || before.uid != after.uid
        || before.sid != after.sid
        || before.path_match != after.path_match
}

impl Cluster {
    /// Revoke one approval (`RevokeApproval`): `ACTIVE` or `EXPIRED` →
    /// `REVOKED`, with a revision record and a generation bump. The record is
    /// kept; a revoked hash is never auto-approved again in its lineage.
    pub async fn app_revoke_approval(
        &self,
        r: &Revoke,
        now: i64,
        generation_millis: i64,
    ) -> Result<ApprovalRow, LedgerError> {
        validate_revoke(r)?;
        let current = self
            .app_approval(&r.approval_id)
            .await?
            .ok_or(LedgerError::NotFound)?;
        let mut stmts = revoke_stmts(&current, r, now)?;
        stmts.push(bump_generation_stmt(
            &current.host_uuid,
            generation_millis,
            now,
        ));
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(generic_refusal(&code)),
        }
        self.app_approval(&r.approval_id)
            .await?
            .ok_or(LedgerError::Raced)
    }

    /// Edit one approval (`UpdateApproval`), renewing an `EXPIRED` one when
    /// the new expiry is in the future. Bumps the generation when the
    /// compiled entry changes.
    pub async fn app_update_approval(&self, e: &ApprovalEdit) -> Result<ApprovalRow, LedgerError> {
        check_id(&e.approval_id, "approval_id")?;
        check_id(&e.admin_id, "admin_id")?;
        if let Some(note) = &e.note {
            check_len(note.as_deref(), 500, "note")?;
        }
        let current = self
            .app_approval(&e.approval_id)
            .await?
            .ok_or(LedgerError::NotFound)?;
        if current.state == ApprovalState::Revoked {
            return Err(LedgerError::InvalidState);
        }
        if current.row_version != e.expected_row_version {
            return Err(LedgerError::RowVersionMismatch);
        }
        let source_target = if e.narrow_to_exact_user && current.user_scope == UserScope::AnyUser {
            let source = match &current.source_request_id {
                Some(id) => self.app_request(id).await?,
                None => None,
            };
            Some(source.ok_or(LedgerError::Invalid("user_scope"))?.target)
        } else {
            None
        };
        let (mut after, renewal) = edited(&current, e, source_target);
        if after == current {
            return Err(LedgerError::Invalid("edit"));
        }
        after.row_version += 1;
        let compiled_changed = changes_compiled_entry(&current, &after);
        let mut stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "INSERT INTO app_txn_guard (code) SELECT c FROM (SELECT CASE \
                 WHEN NOT EXISTS (SELECT 1 FROM app_approvals WHERE approval_id = ?1) \
                    THEN 'not_found' \
                 WHEN NOT EXISTS (SELECT 1 FROM app_approvals \
                    WHERE approval_id = ?1 AND state IN (1, 2)) THEN 'invalid_state' \
                 WHEN NOT EXISTS (SELECT 1 FROM app_approvals \
                    WHERE approval_id = ?1 AND row_version = ?2) THEN 'row_version_mismatch' \
                 ELSE 'ok' END AS c) WHERE c <> 'ok'",
                vec![text(&e.approval_id), Param::from(e.expected_row_version)],
            ),
            insert_revision_stmt(
                &e.approval_id,
                after.row_version,
                e.now,
                Some(&e.admin_id),
                if renewal {
                    RevisionChange::Renewed
                } else {
                    RevisionChange::Updated
                },
                Some(ApprovalSnapshot::of(&current).to_cbor()?),
                ApprovalSnapshot::of(&after).to_cbor()?,
            ),
            (
                "UPDATE app_approvals SET state = ?3, update_policy = ?4, continuity = ?5, \
                 expires_at = ?6, note = ?7, user_scope = ?8, path_match = ?9, user_kind = ?10, \
                 uid = ?11, sid = ?12, user_name = ?13, row_version = row_version + 1 \
                 WHERE approval_id = ?1 AND row_version = ?2",
                vec![
                    text(&e.approval_id),
                    Param::from(e.expected_row_version),
                    Param::from(after.state.code()),
                    Param::from(after.update_policy.code()),
                    Param::from(after.continuity.code()),
                    Param::from(after.expires_at),
                    opt_text(after.note.as_deref()),
                    Param::from(after.user_scope.code()),
                    Param::from(after.path_match.code()),
                    Param::from(after.user_kind.map(UserKind::code)),
                    Param::from(after.uid),
                    opt_text(after.sid.as_deref()),
                    opt_text(after.user_name.as_deref()),
                ],
            ),
        ];
        if compiled_changed {
            stmts.push(bump_generation_stmt(
                &current.host_uuid,
                e.generation_millis,
                e.now,
            ));
        }
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(generic_refusal(&code)),
        }
        self.app_approval(&e.approval_id)
            .await?
            .ok_or(LedgerError::Raced)
    }

    /// Expire one `ACTIVE` approval whose `expires_at` has passed (sweeper,
    /// F19 §5.5), with a revision record and a generation bump. Returns
    /// `false` and writes nothing when it is not due (or changed meanwhile).
    pub async fn app_expire_approval(
        &self,
        approval_id: &str,
        now: i64,
        generation_millis: i64,
    ) -> Result<bool, LedgerError> {
        let Some(current) = self.app_approval(approval_id).await? else {
            return Ok(false);
        };
        if current.state != ApprovalState::Active || current.expires_at.is_none_or(|t| t > now) {
            return Ok(false);
        }
        let mut after = current.clone();
        after.state = ApprovalState::Expired;
        after.row_version += 1;
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "INSERT INTO app_txn_guard (code) SELECT 'stale' WHERE NOT EXISTS \
                 (SELECT 1 FROM app_approvals WHERE approval_id = ?1 AND state = 1 \
                    AND row_version = ?2 AND expires_at IS NOT NULL AND expires_at <= ?3)",
                vec![
                    text(approval_id),
                    Param::from(current.row_version),
                    Param::from(now),
                ],
            ),
            insert_revision_stmt(
                approval_id,
                after.row_version,
                now,
                None,
                RevisionChange::Expired,
                Some(ApprovalSnapshot::of(&current).to_cbor()?),
                ApprovalSnapshot::of(&after).to_cbor()?,
            ),
            (
                "UPDATE app_approvals SET state = 2, row_version = row_version + 1 \
                 WHERE approval_id = ?1 AND row_version = ?2 AND state = 1",
                vec![text(approval_id), Param::from(current.row_version)],
            ),
            bump_generation_stmt(&current.host_uuid, generation_millis, now),
        ];
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => Ok(true),
            TxnOutcome::Refused(_) => Ok(false),
        }
    }

    /// Freeze or unfreeze auto-update for a lineage
    /// (`SetLineageAutoUpdateFrozen`). Returns `false` if the lineage does
    /// not exist.
    pub async fn app_set_lineage_frozen(
        &self,
        lineage_id: &str,
        frozen: bool,
    ) -> Result<bool, LedgerError> {
        let n = self
            .client()
            .execute(
                "UPDATE app_lineages SET auto_update_frozen = ?2 WHERE lineage_id = ?1",
                vec![text(lineage_id), Param::from(i64::from(frozen))],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(n > 0)
    }
}
