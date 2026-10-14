//! Builders of the F19 audit events (F19 §9) from ledger rows.
//!
//! Only ids, hashes, codes and times leave this module: user names, SIDs,
//! plaintext paths, notes and messages are never put into an event
//! (F19 §10). Each builder takes the row that was just written, so an event
//! always describes a committed change.

use ferro_audit::{AuditEvent, Bytes16, Bytes32, Hash384};
use ferro_raft::apps::{ApprovalRow, Continuity, RequestRow, FLAG_PATH_PROTECTED};

use super::uuid_bytes;

/// A ledger code (always small) as the `u8` the events carry.
fn code8(code: i64) -> u8 {
    u8::try_from(code).unwrap_or(u8::MAX)
}

/// A reason code as the `u32` the events carry (negative codes clamp to 0).
pub(crate) fn code32(code: i64) -> u32 {
    u32::try_from(code).unwrap_or(0)
}

/// The SHA-384 bytes of a lowercase-hex `bin_sha` (zeros for the legacy
/// wildcard, which never reaches these events).
fn sha(bin_sha: &str) -> Hash384 {
    let mut out = [0u8; 48];
    if let Ok(bytes) = hex::decode(bin_sha) {
        if bytes.len() == 48 {
            out.copy_from_slice(&bytes);
        }
    }
    Hash384(out)
}

fn id(v: &str) -> Bytes16 {
    Bytes16(uuid_bytes(v))
}

/// `AppRequestSubmitted` for a recorded request.
#[must_use]
pub fn submitted(r: &RequestRow, path_key: &[u8]) -> AuditEvent {
    AuditEvent::AppRequestSubmitted {
        request_id: id(&r.request_id),
        host_uuid: r.host_uuid.clone(),
        lineage_id: id(&r.lineage_id),
        bin_sha: sha(&r.bin_sha),
        revision: u32::try_from(r.revision).unwrap_or(0),
        kind: code8(r.kind.code()),
        origin: code8(r.origin.code()),
        uid: r.target.uid.and_then(|u| u32::try_from(u).ok()),
        path_hash: Bytes32(ferro_svid::allowlist_v2::path_hash(&r.host_uuid, path_key)),
        flags: r.flags,
    }
}

/// What anchored an auto-approval's continuity (F19 §5.3 #5).
#[must_use]
pub fn continuity_basis(parent: &ApprovalRow, flags: u32) -> &'static str {
    if parent.continuity == Continuity::PathUserOnly {
        "path_user_only"
    } else if flags & FLAG_PATH_PROTECTED != 0 {
        "protected_path"
    } else {
        "same_signer"
    }
}

/// `AppRequestAutoApproved` for a committed auto-approval.
#[must_use]
pub fn auto_approved(r: &RequestRow, child: &ApprovalRow, basis: &str) -> AuditEvent {
    AuditEvent::AppRequestAutoApproved {
        request_id: id(&r.request_id),
        approval_id: id(&child.approval_id),
        parent_approval_id: id(child.parent_approval_id.as_deref().unwrap_or_default()),
        lineage_id: id(&r.lineage_id),
        bin_sha: sha(&r.bin_sha),
        continuity_basis: basis.to_string(),
    }
}

/// `AppRequestApproved` (requester and approver differ).
#[must_use]
pub fn approved(r: &RequestRow, a: &ApprovalRow, admin_id: &str, session_ref: &str) -> AuditEvent {
    AuditEvent::AppRequestApproved {
        request_id: id(&r.request_id),
        approval_id: id(&a.approval_id),
        admin_id: admin_id.to_string(),
        session_ref: session_ref.to_string(),
        update_policy: code8(a.update_policy.code()),
        user_scope: code8(a.user_scope.code()),
        path_match: code8(a.path_match.code()),
        expires_at: a.expires_at,
    }
}

/// `AppApprovedBySameActor` (requester and approver are one administrator).
#[must_use]
pub fn same_actor(
    r: &RequestRow,
    a: &ApprovalRow,
    admin_id: &str,
    session_ref: &str,
    mfa_method: &str,
) -> AuditEvent {
    AuditEvent::AppApprovedBySameActor {
        request_id: id(&r.request_id),
        approval_id: id(&a.approval_id),
        admin_id: admin_id.to_string(),
        session_ref: session_ref.to_string(),
        origin: code8(r.origin.code()),
        mfa_method: mfa_method.to_string(),
        update_policy: code8(a.update_policy.code()),
        user_scope: code8(a.user_scope.code()),
        path_match: code8(a.path_match.code()),
        expires_at: a.expires_at,
    }
}

/// `AppRequestDenied`.
#[must_use]
pub fn denied(r: &RequestRow, admin_id: &str, session_ref: &str) -> AuditEvent {
    AuditEvent::AppRequestDenied {
        request_id: id(&r.request_id),
        admin_id: admin_id.to_string(),
        session_ref: session_ref.to_string(),
        reason_code: code32(r.decision_reason_code.unwrap_or_default()),
    }
}

/// `AppRequestExpired`.
#[must_use]
pub fn request_expired(request_id: &str) -> AuditEvent {
    AuditEvent::AppRequestExpired {
        request_id: id(request_id),
    }
}

/// `ApprovalUpdated`, from the approval before and after the edit.
#[must_use]
pub fn updated(
    before: &ApprovalRow,
    after: &ApprovalRow,
    admin_id: &str,
    session_ref: &str,
) -> AuditEvent {
    let mut changed = Vec::new();
    if before.state != after.state {
        changed.push("state");
    }
    if before.update_policy != after.update_policy {
        changed.push("update_policy");
    }
    if before.continuity != after.continuity {
        changed.push("continuity");
    }
    if before.expires_at != after.expires_at {
        changed.push("expires_at");
    }
    if before.note != after.note {
        changed.push("note");
    }
    if before.user_scope != after.user_scope {
        changed.push("user_scope");
    }
    if before.path_match != after.path_match {
        changed.push("path_match");
    }
    AuditEvent::ApprovalUpdated {
        approval_id: id(&after.approval_id),
        admin_id: admin_id.to_string(),
        session_ref: session_ref.to_string(),
        row_version: u64::try_from(after.row_version).unwrap_or(0),
        changed_fields: changed.into_iter().map(str::to_string).collect(),
        old_expires_at: before.expires_at,
        new_expires_at: after.expires_at,
        old_policy: code8(before.update_policy.code()),
        new_policy: code8(after.update_policy.code()),
    }
}

/// `ApprovalRevoked`.
#[must_use]
pub fn revoked(a: &ApprovalRow, admin_id: &str, session_ref: &str) -> AuditEvent {
    AuditEvent::ApprovalRevoked {
        approval_id: id(&a.approval_id),
        admin_id: admin_id.to_string(),
        session_ref: session_ref.to_string(),
        reason_code: code32(a.revoke_reason_code.unwrap_or_default()),
    }
}

/// `ApprovalExpired`.
#[must_use]
pub fn approval_expired(approval_id: &str) -> AuditEvent {
    AuditEvent::ApprovalExpired {
        approval_id: id(approval_id),
    }
}

/// `LineageAutoUpdateFrozen`.
#[must_use]
pub fn lineage_frozen(lineage_id: &str, admin_id: &str, frozen: bool) -> AuditEvent {
    AuditEvent::LineageAutoUpdateFrozen {
        lineage_id: id(lineage_id),
        admin_id: admin_id.to_string(),
        frozen,
    }
}

/// `AdminDirectRegistration` (strict SoD: queued for another approver).
#[must_use]
pub fn direct_registration(r: &RequestRow, admin_id: &str) -> AuditEvent {
    AuditEvent::AdminDirectRegistration {
        request_id: id(&r.request_id),
        admin_id: admin_id.to_string(),
    }
}

/// `AllowlistCompiled`.
#[must_use]
pub fn compiled(
    host_uuid: &str,
    generation: u64,
    entry_count: usize,
    digest: [u8; 48],
) -> AuditEvent {
    AuditEvent::AllowlistCompiled {
        host_uuid: host_uuid.to_string(),
        generation,
        entry_count: u32::try_from(entry_count).unwrap_or(u32::MAX),
        entries_digest: Hash384(digest),
    }
}
