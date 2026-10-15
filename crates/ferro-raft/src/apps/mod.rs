//! Replicated app approval ledger (feature F19, ADR-0004).
//!
//! This module owns the F19 tables — lineages, binaries and their revisions,
//! requests, approvals, approval revisions and the per-host allowlist
//! generation — and a typed accessor surface on [`Cluster`]. The *policy*
//! (host authentication, validation, rate limits, configuration switches,
//! audit, allowlist compilation) lives in CMIS; this layer persists rows and
//! enforces the invariants that must hold whatever the caller does:
//!
//! - **INV-1 / INV-3 (no replacement).** Request intake only ever *inserts*:
//!   a request row, and — for an auto-update — one new approval that copies
//!   its parent. No intake path updates or removes an approval (the only
//!   write to an existing one is the informational `superseded_by` mark).
//!   Deduplication returns existing records and never overwrites them.
//! - **INV-2 (approvals end only by expiry or an administrator).** Approval
//!   changes go through [`Cluster::app_update_approval`],
//!   [`Cluster::app_revoke_approval`] and [`Cluster::app_expire_approval`],
//!   each of which names one approval by id, checks its `row_version` and
//!   appends an `app_approval_revisions` record in the same transaction.
//! - **Sequential revisions.** [`Cluster::app_observe_binary`] allocates
//!   revision `n` of a lineage exactly once; the database refuses gaps and
//!   reuse.
//!
//! The same rules are enforced again by SQLite triggers ([`schema`]), so an
//! application bug cannot break them silently. Multi-statement writes put
//! their preconditions in a *guard* statement first: inside one Raft
//! transaction a failed precondition aborts everything, and the abort names
//! the failed check (see [`LedgerError`]).
//!
//! Reads are strongly consistent (through the leader), like the admin store.
//! All statements are parameterised; searches escape `LIKE` wildcards.

mod approvals;
mod decisions;
mod generation;
mod intake;
mod model;
mod reads;
pub(crate) mod schema;
mod search;

pub use approvals::{ApprovalEdit, Revoke};
pub use decisions::{ApprovalChoice, Approve, Decided, Deny};
pub use generation::GENERATION_UNCOMPILED_DIGEST;
pub use intake::{AutoApproval, AutoChecks, AutoIntake, Intake, IntakeChecks};
pub use model::{
    dedup_key, is_bin_sha, ApprovalOrigin, ApprovalRevisionRow, ApprovalRow, ApprovalSnapshot,
    ApprovalState, ApprovalTerms, AutoDowngradeReason, BinaryRow, Continuity,
    HostAllowlistStateRow, LineageRow, NewRequest, ObservedBinary, PathMatch, RequestKind,
    RequestOrigin, RequestRow, RequestState, RevisionChange, UpdatePolicy, UserIdentity, UserKind,
    UserScope, FLAG_PATH_PROTECTED,
};
pub use reads::{HashHistory, LiveApproval, PendingCounts, MAX_STATUS_IDS};
pub use schema::{is_pseudonym, PSEUDONYM_PREFIX};
pub use search::{
    ApprovalFilter, ApprovalListItem, Cursor, RequestFilter, RequestListItem, MAX_PAGE_SIZE,
};

use hiqlite::Param;

use crate::cluster::{Cluster, ClusterError};
use model::decode;

/// Failures of ledger operations. Variants other than [`LedgerError::Store`]
/// mean nothing was written.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The store failed (Raft not ready, I/O, a constraint the caller should
    /// have prevented). Surfaces as `UNAVAILABLE store_unavailable`.
    #[error(transparent)]
    Store(#[from] ClusterError),
    /// The named record does not exist.
    #[error("not found")]
    NotFound,
    /// The transition is not allowed from the record's current state
    /// (`FAILED_PRECONDITION invalid_state`).
    #[error("invalid state")]
    InvalidState,
    /// `expected_row_version` did not match (`ABORTED row_version_mismatch`).
    #[error("row version mismatch")]
    RowVersionMismatch,
    /// The strict separation-of-duties policy forbids deciding one's own
    /// request (`PERMISSION_DENIED sod_self_approval`).
    #[error("self-approval refused")]
    SelfApproval,
    /// The approval named for reuse does not cover the request.
    #[error("the approval does not cover the request")]
    NotCovering,
    /// The state changed between the read and the write repeatedly; retry.
    #[error("concurrent change, retry")]
    Raced,
    /// An input failed validation before anything was written; names the field.
    #[error("invalid {0}")]
    Invalid(&'static str),
    /// A stored value is outside its enum (the database was altered outside
    /// this crate); names the column.
    #[error("corrupt stored value in {0}")]
    Corrupt(&'static str),
}

/// Outcome of a guarded transaction: committed, or refused by a guard code.
pub(crate) enum TxnOutcome {
    /// Committed.
    Committed,
    /// A guard statement aborted the transaction; nothing was written.
    Refused(String),
}

/// The guard code in an aborted transaction's error, if it was a guard.
fn guard_code(e: &hiqlite::Error) -> Option<String> {
    const PREFIX: &str = "ferrogate-guard:";
    let text = e.to_string();
    let start = text.find(PREFIX)? + PREFIX.len();
    let code: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || *c == '_')
        .collect();
    (!code.is_empty()).then_some(code)
}

/// Map the generic guard codes to errors; others are returned to the caller.
pub(crate) fn generic_refusal(code: &str) -> LedgerError {
    match code {
        "not_found" => LedgerError::NotFound,
        "invalid_state" => LedgerError::InvalidState,
        "row_version_mismatch" => LedgerError::RowVersionMismatch,
        "sod_self_approval" => LedgerError::SelfApproval,
        "not_covering" => LedgerError::NotCovering,
        "stale" => LedgerError::Raced,
        _ => LedgerError::Store(ClusterError::Conflict(format!("guard {code}"))),
    }
}

impl Cluster {
    /// Run `stmts` as one Raft transaction. A guard abort is returned as
    /// [`TxnOutcome::Refused`]; any other failure as an error. Either way a
    /// failed transaction wrote nothing.
    pub(crate) async fn ledger_txn(
        &self,
        stmts: Vec<(&'static str, Vec<Param>)>,
    ) -> Result<TxnOutcome, LedgerError> {
        match self.client().txn(stmts).await {
            Ok(results) => {
                for r in results {
                    r.map_err(ClusterError::from)?;
                }
                Ok(TxnOutcome::Committed)
            }
            Err(e) => match guard_code(&e) {
                Some(code) => Ok(TxnOutcome::Refused(code)),
                None => Err(ClusterError::from(e).into()),
            },
        }
    }
}

// ---- row parsing --------------------------------------------------------------

/// A typed row parsed from a hiqlite row; parsing fails on a corrupt code.
pub(crate) struct Parsed<T>(pub(crate) Result<T, LedgerError>);

/// Collect parsed rows, failing on the first corrupt one.
pub(crate) fn collect<T>(rows: Vec<Parsed<T>>) -> Result<Vec<T>, LedgerError> {
    rows.into_iter().map(|p| p.0).collect()
}

pub(crate) const LINEAGE_COLUMNS: &str = "lineage_id, host_uuid, platform, canonical_path, \
    path_key, next_revision, auto_update_frozen, created_at";

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<LineageRow> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(Ok(LineageRow {
            lineage_id: row.get("lineage_id"),
            host_uuid: row.get("host_uuid"),
            platform: row.get("platform"),
            canonical_path: row.get("canonical_path"),
            path_key: row.get("path_key"),
            next_revision: row.get("next_revision"),
            auto_update_frozen: row.get::<i64>("auto_update_frozen") != 0,
            created_at: row.get("created_at"),
        }))
    }
}

pub(crate) const BINARY_COLUMNS: &str = "lineage_id, bin_sha, revision, file_size, format, \
    declared_version, version_source, product_name, bundle_id, package_name, signer_kind, \
    signer_id, signer_subject, signer_valid, first_seen_at";

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<BinaryRow> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(Ok(BinaryRow {
            lineage_id: row.get("lineage_id"),
            bin_sha: row.get("bin_sha"),
            revision: row.get("revision"),
            file_size: row.get("file_size"),
            format: row.get("format"),
            declared_version: row.get("declared_version"),
            version_source: row.get("version_source"),
            product_name: row.get("product_name"),
            bundle_id: row.get("bundle_id"),
            package_name: row.get("package_name"),
            signer_kind: row.get("signer_kind"),
            signer_id: row.get("signer_id"),
            signer_subject: row.get("signer_subject"),
            signer_valid: row.get::<i64>("signer_valid") != 0,
            first_seen_at: row.get("first_seen_at"),
        }))
    }
}

/// `app_requests` columns, qualified with the alias `r`.
pub(crate) const REQUEST_COLUMNS: &str = "r.request_id, r.host_uuid, r.client_request_id, \
    r.lineage_id, r.bin_sha, r.revision, r.kind, r.origin, r.target_user_kind, r.target_uid, \
    r.target_sid, r.target_user_name, r.requester_uid, r.requester_user_name, \
    r.requested_by_admin_id, r.reason, r.flags, r.host_tier, r.proposer_spiffe_id, r.dedup_key, \
    r.submitted_at, r.pending_expires_at, r.state, r.decided_at, r.decided_by_admin_id, \
    r.decision_reason_code, r.decision_message, r.auto_downgrade_reason, \
    r.resulting_approval_id, r.same_actor_approved";

pub(crate) fn parse_request(row: &mut hiqlite::Row<'_>) -> Result<RequestRow, LedgerError> {
    let auto_downgrade: Option<i64> = row.get("auto_downgrade_reason");
    Ok(RequestRow {
        request_id: row.get("request_id"),
        host_uuid: row.get("host_uuid"),
        client_request_id: row.get("client_request_id"),
        lineage_id: row.get("lineage_id"),
        bin_sha: row.get("bin_sha"),
        revision: row.get("revision"),
        kind: decode(row.get("kind"), "kind", RequestKind::from_code)?,
        origin: decode(row.get("origin"), "origin", RequestOrigin::from_code)?,
        target: UserIdentity {
            kind: decode(
                row.get("target_user_kind"),
                "target_user_kind",
                UserKind::from_code,
            )?,
            uid: row.get("target_uid"),
            sid: row.get("target_sid"),
            user_name: row.get("target_user_name"),
        },
        requester_uid: row.get("requester_uid"),
        requester_user_name: row.get("requester_user_name"),
        requested_by_admin_id: row.get("requested_by_admin_id"),
        reason: row.get("reason"),
        flags: u32::try_from(row.get::<i64>("flags")).map_err(|_| LedgerError::Corrupt("flags"))?,
        host_tier: row.get("host_tier"),
        proposer_spiffe_id: row.get("proposer_spiffe_id"),
        dedup_key: row.get("dedup_key"),
        submitted_at: row.get("submitted_at"),
        pending_expires_at: row.get("pending_expires_at"),
        state: decode(row.get("state"), "state", RequestState::from_code)?,
        decided_at: row.get("decided_at"),
        decided_by_admin_id: row.get("decided_by_admin_id"),
        decision_reason_code: row.get("decision_reason_code"),
        decision_message: row.get("decision_message"),
        auto_downgrade_reason: auto_downgrade
            .map(|c| decode(c, "auto_downgrade_reason", AutoDowngradeReason::from_code))
            .transpose()?,
        resulting_approval_id: row.get("resulting_approval_id"),
        same_actor_approved: row.get::<i64>("same_actor_approved") != 0,
    })
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<RequestRow> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(parse_request(row))
    }
}

/// `app_approvals` columns, qualified with the alias `a`.
pub(crate) const APPROVAL_COLUMNS: &str = "a.approval_id, a.host_uuid, a.lineage_id, \
    a.bin_sha, a.revision, a.source_request_id, a.origin, a.parent_approval_id, \
    a.approved_by_admin_id, a.user_scope, a.user_kind, a.uid, a.sid, a.user_name, a.path_match, \
    a.update_policy, a.continuity, a.created_at, a.expires_at, a.state, a.superseded_by, \
    a.revoked_at, a.revoked_by_admin_id, a.revoke_reason_code, a.note, a.row_version";

pub(crate) fn parse_approval(row: &mut hiqlite::Row<'_>) -> Result<ApprovalRow, LedgerError> {
    let user_kind: Option<i64> = row.get("user_kind");
    Ok(ApprovalRow {
        approval_id: row.get("approval_id"),
        host_uuid: row.get("host_uuid"),
        lineage_id: row.get("lineage_id"),
        bin_sha: row.get("bin_sha"),
        revision: row.get("revision"),
        source_request_id: row.get("source_request_id"),
        origin: decode(row.get("origin"), "origin", ApprovalOrigin::from_code)?,
        parent_approval_id: row.get("parent_approval_id"),
        approved_by_admin_id: row.get("approved_by_admin_id"),
        user_scope: decode(row.get("user_scope"), "user_scope", UserScope::from_code)?,
        user_kind: user_kind
            .map(|c| decode(c, "user_kind", UserKind::from_code))
            .transpose()?,
        uid: row.get("uid"),
        sid: row.get("sid"),
        user_name: row.get("user_name"),
        path_match: decode(row.get("path_match"), "path_match", PathMatch::from_code)?,
        update_policy: decode(
            row.get("update_policy"),
            "update_policy",
            UpdatePolicy::from_code,
        )?,
        continuity: decode(row.get("continuity"), "continuity", Continuity::from_code)?,
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        state: decode(row.get("state"), "state", ApprovalState::from_code)?,
        superseded_by: row.get("superseded_by"),
        revoked_at: row.get("revoked_at"),
        revoked_by_admin_id: row.get("revoked_by_admin_id"),
        revoke_reason_code: row.get("revoke_reason_code"),
        note: row.get("note"),
        row_version: row.get("row_version"),
    })
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<ApprovalRow> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(parse_approval(row))
    }
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<ApprovalRevisionRow> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        let mut parse = || -> Result<ApprovalRevisionRow, LedgerError> {
            Ok(ApprovalRevisionRow {
                approval_id: row.get("approval_id"),
                row_version: row.get("row_version"),
                changed_at: row.get("changed_at"),
                changed_by_admin_id: row.get("changed_by_admin_id"),
                change_kind: decode(
                    row.get("change_kind"),
                    "change_kind",
                    RevisionChange::from_code,
                )?,
                before_cbor: row.get("before_cbor"),
                after_cbor: row.get("after_cbor"),
            })
        };
        Self(parse())
    }
}

/// Shorthand for a text parameter.
pub(crate) fn text(v: &str) -> Param {
    Param::from(v.to_string())
}

/// Shorthand for an optional text parameter.
pub(crate) fn opt_text(v: Option<&str>) -> Param {
    Param::from(v.map(str::to_string))
}

/// Validate a text input's character count before any write.
pub(crate) fn check_len(
    v: Option<&str>,
    max_chars: usize,
    field: &'static str,
) -> Result<(), LedgerError> {
    match v {
        Some(s) if s.chars().count() > max_chars => Err(LedgerError::Invalid(field)),
        _ => Ok(()),
    }
}

/// Validate an id (UUID text): non-empty, at most 64 bytes.
pub(crate) fn check_id(v: &str, field: &'static str) -> Result<(), LedgerError> {
    if v.is_empty() || v.len() > 64 {
        return Err(LedgerError::Invalid(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_codes_are_extracted_from_abort_messages() {
        let e = hiqlite::Error::Transaction(
            "constraint failed: ferrogate-guard:invalid_state (code 1811)".into(),
        );
        assert_eq!(guard_code(&e).as_deref(), Some("invalid_state"));
        let e = hiqlite::Error::Transaction("UNIQUE constraint failed: x".into());
        assert_eq!(guard_code(&e), None);
        let e = hiqlite::Error::Transaction("ferrogate-guard:".into());
        assert_eq!(guard_code(&e), None);
    }

    #[test]
    fn generic_refusals_map_to_typed_errors() {
        assert!(matches!(
            generic_refusal("not_found"),
            LedgerError::NotFound
        ));
        assert!(matches!(
            generic_refusal("row_version_mismatch"),
            LedgerError::RowVersionMismatch
        ));
        assert!(matches!(generic_refusal("stale"), LedgerError::Raced));
        assert!(matches!(
            generic_refusal("whatever"),
            LedgerError::Store(ClusterError::Conflict(_))
        ));
    }
}
