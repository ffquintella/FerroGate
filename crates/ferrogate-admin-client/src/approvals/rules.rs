//! The decision rules (F21 §6, F22 §4) every front end applies before it
//! sends an approve, deny, edit, revoke or freeze: the safe defaults, the
//! wide-scope and "any user" checks, the narrowing-only edit, the typed
//! revoke confirmation, and the requests built with a fresh idempotency key.

//! The server re-checks every rule; these are here so a mistake is
//! explained before it costs a second factor, and so the TUI and the tray
//! decide alike (shared test vectors).

use std::fmt::Write as _;

use ferro_appid::flags::RiskFlags;
use ferro_proto::admin_v1::{
    approve_app_request_request::Choice, AppUser, ApprovalInfo, ApprovalTerms,
    ApproveAppRequestRequest, DenyAppRequestRequest, GetAppRequestResponse, RevokeApprovalRequest,
    SetLineageAutoUpdateFrozenRequest, UpdateApprovalRequest,
};

use serde::Serialize;

use crate::timefmt::DAY;

/// Deny reason codes (wire codes 1…6, F21 §6 "Deny").
pub const DENY_REASONS: [&str; 6] = [
    "unknown_software",
    "policy_violation",
    "insufficient_justification",
    "duplicate",
    "security_risk",
    "other",
];
/// Revoke reason codes (wire codes 1…5; 1000 is reserved for the legacy
/// import, F19 §11).
pub const REVOKE_REASONS: [&str; 5] = [
    "no_longer_needed",
    "security_risk",
    "policy_violation",
    "replaced",
    "other",
];
/// Index of `replaced` in [`REVOKE_REASONS`] (default for "also revoke").
pub const REVOKE_REPLACED: usize = 3;
/// Expiry choices of a new approval, in days: 0 is the server default
/// (`CMIS_APPROVAL_DEFAULT_TTL_SECS`).
pub const EXPIRY_DAYS: [i64; 5] = [0, 30, 90, 180, 365];
/// Expiry choices of an edit, in days from now (besides "keep" and "no
/// expiry"). A future date on an expired approval renews it.
pub const EDIT_EXPIRY_DAYS: [i64; 4] = [30, 90, 180, 365];
/// Longest approval note, in characters (the server's limit).
pub const MAX_NOTE: usize = 500;
/// Longest deny message, in characters (the server's limit).
pub const MAX_DENY_MESSAGE: usize = 200;
/// Longest typed revoke confirmation, in characters.
pub const MAX_CONFIRM: usize = 16;

/// A fresh idempotency key (a random UUID): one per decision, reused only
/// by the single retry after a step-up.
#[must_use]
pub fn new_idempotency_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The short id an administrator types to confirm a revocation: the prefix,
/// `-`, and the last eight alphanumerics of the id. The tail is used because
/// the head of a time-ordered UUIDv7 is the same for every approval created
/// in the same hours.
#[must_use]
pub fn short_id(prefix: &str, id: &str) -> String {
    let tail: Vec<char> = id.chars().filter(char::is_ascii_alphanumeric).collect();
    let start = tail.len().saturating_sub(8);
    let s: String = tail[start..].iter().collect();
    format!("{prefix}-{}", s.to_ascii_uppercase())
}

/// The first eight characters of a host UUID.
#[must_use]
pub fn short_host(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

/// A display label for an operating-system user (untrusted text: the
/// caller makes it inert before showing it).
#[must_use]
pub fn user_label(u: Option<&AppUser>) -> String {
    let Some(u) = u else {
        return "—".to_string();
    };
    let mut s = if u.name.is_empty() {
        "?".to_string()
    } else {
        u.name.clone()
    };
    if let Some(uid) = u.uid {
        let _ = write!(s, " ({uid})");
    }
    if !u.sid.is_empty() {
        let _ = write!(s, " ({})", u.sid);
    }
    s
}

/// Whether `typed` confirms the revocation of `approval_id` (its
/// [`short_id`], case-insensitive, surrounding blanks ignored).
#[must_use]
pub fn revoke_confirmed(approval_id: &str, typed: &str) -> bool {
    typed
        .trim()
        .eq_ignore_ascii_case(&short_id("A", approval_id))
}

/// The auto-update preselection rule (F21 §6 "Approve", step 1): only when
/// the request is on a protected path, or its binary has a valid signer
/// equal to the signer of the lineage's previous active or expired (never
/// revoked) revision.
#[must_use]
pub fn auto_update_preselected(detail: &GetAppRequestResponse) -> bool {
    let Some(request) = &detail.request else {
        return false;
    };
    if request.flags & RiskFlags::PATH_PROTECTED != 0 {
        return true;
    }
    if request.flags & RiskFlags::SIGNER_CHANGED != 0 {
        return false;
    }
    let Some(bin) = &detail.binary else {
        return false;
    };
    if bin.signer_kind == 0 || !bin.signer_valid || bin.signer_id.is_empty() {
        return false;
    }
    let previous = detail
        .lineage_approvals
        .iter()
        // A revoked revision was withdrawn and vouches for nothing.
        .filter(|a| matches!(a.state, 1 | 2) && a.revision > 0 && a.revision < request.revision)
        .max_by_key(|a| a.revision);
    let Some(prev) = previous else {
        return false;
    };
    detail
        .lineage_binaries
        .iter()
        .find(|b| b.bin_sha == prev.bin_sha)
        .is_some_and(|p| {
            p.signer_valid && p.signer_kind == bin.signer_kind && p.signer_id == bin.signer_id
        })
}

/// The active approvals of the request's lineage, offered for "also revoke".
#[must_use]
pub fn also_revocable(detail: &GetAppRequestResponse) -> Vec<ApprovalInfo> {
    detail
        .lineage_approvals
        .iter()
        .filter(|a| a.state == 1)
        .cloned()
        .collect()
}

/// The terms of a new approval as chosen in a dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag per two-way choice of the dialog.
pub struct Terms {
    /// "Auto-approve updates (same path + same user)" instead of manual.
    pub auto_update: bool,
    /// "Path + user only" continuity instead of anchored (wide).
    pub path_user_continuity: bool,
    /// "Any user" instead of this user only (wide).
    pub any_user: bool,
    /// "Any path" instead of the exact path.
    pub any_path: bool,
    /// Days until expiry; 0 is the server default.
    pub expiry_days: i64,
    /// Note (at most [`MAX_NOTE`] characters).
    pub note: String,
}

impl Terms {
    /// The safe defaults: manual (or auto-update when
    /// [`auto_update_preselected`]), anchored, this user, exact path,
    /// server-default expiry, no note.
    #[must_use]
    pub fn safe_defaults(auto_update: bool) -> Self {
        Self {
            auto_update,
            path_user_continuity: false,
            any_user: false,
            any_path: false,
            expiry_days: 0,
            note: String::new(),
        }
    }

    /// Whether these terms need the extra wide-scope confirmation.
    #[must_use]
    pub fn is_wide(&self) -> bool {
        self.any_user || self.path_user_continuity
    }

    /// The server refuses auto-update for any user unless the path is
    /// protected (`flags` of the request or of the asserted binary).
    #[must_use]
    pub fn breaks_any_user_rule(&self, flags: u32) -> bool {
        self.any_user && self.auto_update && flags & RiskFlags::PATH_PROTECTED == 0
    }

    /// The wire terms at Unix time `now`. `confirm_any_user` follows "any
    /// user": a front end reaches this only after the wide confirmation.
    #[must_use]
    pub fn to_proto(&self, now: i64) -> ApprovalTerms {
        ApprovalTerms {
            user_scope: if self.any_user { 2 } else { 1 },
            path_match: if self.any_path { 2 } else { 1 },
            update_policy: if self.auto_update { 2 } else { 1 },
            continuity: if self.path_user_continuity { 2 } else { 1 },
            expires_at: if self.expiry_days == 0 {
                0
            } else {
                now + self.expiry_days * DAY
            },
            no_expiry: false,
            note: self.note.trim().to_string(),
            confirm_any_user: self.any_user,
        }
    }
}

/// `ApproveAppRequest` with new `terms`; `also` lists approval ids to
/// revoke with it, for the reason at `revoke_reason` in [`REVOKE_REASONS`].
#[must_use]
pub fn approve_request(
    request_id: &str,
    terms: ApprovalTerms,
    also: Vec<String>,
    revoke_reason: usize,
    key: String,
) -> ApproveAppRequestRequest {
    let reason = if also.is_empty() {
        0
    } else {
        reason_code(revoke_reason, REVOKE_REASONS.len())
    };
    ApproveAppRequestRequest {
        idempotency_key: key,
        request_id: request_id.to_string(),
        choice: Some(Choice::Terms(terms)),
        also_revoke_approval_ids: also,
        also_revoke_reason_code: reason,
        proof: None,
    }
}

/// The wire code (1-based) of the reason at `index` among `count`.
fn reason_code(index: usize, count: usize) -> u32 {
    u32::try_from(index.min(count.saturating_sub(1)) + 1).unwrap_or(1)
}

/// `DenyAppRequest` for the reason at `reason` in [`DENY_REASONS`], with
/// `message` shown to the requester (trimmed).
#[must_use]
pub fn deny_request(
    request_id: &str,
    reason: usize,
    message: &str,
    key: String,
) -> DenyAppRequestRequest {
    DenyAppRequestRequest {
        idempotency_key: key,
        request_id: request_id.to_string(),
        reason_code: reason_code(reason, DENY_REASONS.len()),
        message: message.trim().to_string(),
    }
}

/// `RevokeApproval` of `approval` at its row version, for the reason at
/// `reason` in [`REVOKE_REASONS`].
#[must_use]
pub fn revoke_request(
    approval: &ApprovalInfo,
    reason: usize,
    key: String,
) -> RevokeApprovalRequest {
    RevokeApprovalRequest {
        idempotency_key: key,
        approval_id: approval.approval_id.clone(),
        reason_code: reason_code(reason, REVOKE_REASONS.len()),
        expected_row_version: approval.row_version,
    }
}

/// `SetLineageAutoUpdateFrozen`.
#[must_use]
pub fn freeze_request(
    lineage_id: &str,
    frozen: bool,
    key: String,
) -> SetLineageAutoUpdateFrozenRequest {
    SetLineageAutoUpdateFrozenRequest {
        idempotency_key: key,
        lineage_id: lineage_id.to_string(),
        frozen,
    }
}

/// The new expiry an edit asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EditExpiry {
    /// Keep the current expiry.
    Keep,
    /// This many days from now (renews an expired approval).
    Days(i64),
    /// No expiry (if the server allows it).
    NoExpiry,
}

/// An edit of an approval as chosen in a dialog: only narrowing is offered
/// for the user and path scope; continuity may be loosened (wide).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag per two-way choice of the dialog.
pub struct Edit {
    /// Auto-update policy.
    pub auto_update: bool,
    /// "Path + user only" continuity.
    pub path_user_continuity: bool,
    /// New expiry.
    pub expiry: EditExpiry,
    /// The note (at most [`MAX_NOTE`] characters).
    pub note: String,
    /// Narrow "any user" to this user only.
    pub narrow_user: bool,
    /// Narrow "any path" to the exact path.
    pub narrow_path: bool,
}

/// `note` without control characters, trimmed (as the edit compares it).
fn plain_note(note: &str) -> String {
    let clean: String = note.chars().filter(|c| !c.is_control()).collect();
    clean.trim().to_string()
}

impl Edit {
    /// The dialog's starting point: `approval`'s current terms, nothing to
    /// change yet.
    #[must_use]
    pub fn unchanged(approval: &ApprovalInfo) -> Self {
        Self {
            auto_update: approval.update_policy == 2,
            path_user_continuity: approval.continuity == 2,
            expiry: EditExpiry::Keep,
            note: plain_note(&approval.note),
            narrow_user: false,
            narrow_path: false,
        }
    }

    /// Whether the edit loosens continuity to "path + user only" (needs the
    /// extra wide confirmation).
    #[must_use]
    pub fn loosens_continuity(&self, approval: &ApprovalInfo) -> bool {
        self.path_user_continuity && approval.continuity != 2
    }

    /// `UpdateApproval` carrying only what changed, at `approval`'s row
    /// version; `None` when nothing changes.
    #[must_use]
    pub fn request(
        &self,
        approval: &ApprovalInfo,
        now: i64,
        key: String,
    ) -> Option<UpdateApprovalRequest> {
        let policy = if self.auto_update { 2 } else { 1 };
        let continuity = if self.path_user_continuity { 2 } else { 1 };
        let current_policy = if approval.update_policy == 2 { 2 } else { 1 };
        let current_continuity = if approval.continuity == 2 { 2 } else { 1 };
        let mut req = UpdateApprovalRequest {
            idempotency_key: key,
            approval_id: approval.approval_id.clone(),
            expected_row_version: approval.row_version,
            ..UpdateApprovalRequest::default()
        };
        let mut changed = false;
        if policy != current_policy {
            req.update_policy = Some(policy);
            changed = true;
        }
        if continuity != current_continuity {
            req.continuity = Some(continuity);
            changed = true;
        }
        match self.expiry {
            EditExpiry::Keep => {}
            EditExpiry::NoExpiry => {
                req.clear_expiry = true;
                changed = true;
            }
            EditExpiry::Days(days) => {
                req.expires_at = Some(now + days * DAY);
                changed = true;
            }
        }
        let note = self.note.trim().to_string();
        if note != plain_note(&approval.note) {
            if note.is_empty() {
                req.clear_note = true;
            } else {
                req.note = Some(note);
            }
            changed = true;
        }
        if self.narrow_user && approval.user_scope == 2 {
            req.narrow_to_exact_user = true;
            changed = true;
        }
        if self.narrow_path && approval.path_match == 2 {
            req.narrow_to_exact_path = true;
            changed = true;
        }
        changed.then_some(req)
    }
}

/// A term of an approval that changed between two loads of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalChange {
    /// Active, expired, revoked.
    State,
    /// Manual or auto-update.
    UpdatePolicy,
    /// Anchored or path + user only.
    Continuity,
    /// The expiry.
    Expires,
    /// This user or any user.
    UserScope,
    /// Exact or any path.
    PathMatch,
    /// The note.
    Note,
}

/// What changed from `old` to `new` (after an `ABORTED` edit: the reload is
/// shown before the edit is asked again).
#[must_use]
pub fn approval_changes(old: &ApprovalInfo, new: &ApprovalInfo) -> Vec<ApprovalChange> {
    [
        (ApprovalChange::State, old.state != new.state),
        (
            ApprovalChange::UpdatePolicy,
            old.update_policy != new.update_policy,
        ),
        (ApprovalChange::Continuity, old.continuity != new.continuity),
        (ApprovalChange::Expires, old.expires_at != new.expires_at),
        (ApprovalChange::UserScope, old.user_scope != new.user_scope),
        (ApprovalChange::PathMatch, old.path_match != new.path_match),
        (ApprovalChange::Note, old.note != new.note),
    ]
    .into_iter()
    .filter(|(_, changed)| *changed)
    .map(|(what, _)| what)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_proto::admin_v1::{AppBinaryInfo, AppRequestInfo};

    const NOW: i64 = 1_791_936_000;

    fn detail(flags: u32, signer_now: &str, signer_before: &str) -> GetAppRequestResponse {
        let bin = |sha: &str, signer: &str| AppBinaryInfo {
            bin_sha: sha.into(),
            signer_kind: u32::from(!signer.is_empty()),
            signer_id: signer.into(),
            signer_valid: !signer.is_empty(),
            ..AppBinaryInfo::default()
        };
        GetAppRequestResponse {
            request: Some(AppRequestInfo {
                request_id: "req-1".into(),
                revision: 2,
                flags,
                state: 1,
                ..AppRequestInfo::default()
            }),
            binary: Some(bin("b2", signer_now)),
            lineage_binaries: vec![bin("b1", signer_before), bin("b2", signer_now)],
            lineage_approvals: vec![ApprovalInfo {
                approval_id: "0190f0aa-0000-7000-8000-00000000beef".into(),
                bin_sha: "b1".into(),
                revision: 1,
                state: 1,
                ..ApprovalInfo::default()
            }],
            ..GetAppRequestResponse::default()
        }
    }

    fn approval(scope: u32, path: u32) -> ApprovalInfo {
        ApprovalInfo {
            approval_id: "0190f0aa-0000-7000-8000-00000000beef".into(),
            user_scope: scope,
            path_match: path,
            update_policy: 1,
            continuity: 1,
            row_version: 7,
            note: "kept\u{7}".into(),
            ..ApprovalInfo::default()
        }
    }

    #[test]
    fn auto_update_is_preselected_only_on_a_protected_path_or_the_same_signer() {
        assert!(!auto_update_preselected(&detail(0, "", "")));
        assert!(auto_update_preselected(&detail(
            RiskFlags::PATH_PROTECTED,
            "",
            ""
        )));
        assert!(auto_update_preselected(&detail(0, "TEAMID1", "TEAMID1")));
        assert!(!auto_update_preselected(&detail(0, "TEAMID1", "OTHER")));
        assert!(!auto_update_preselected(&detail(
            RiskFlags::SIGNER_CHANGED,
            "TEAMID1",
            "TEAMID1"
        )));
        let mut revoked = detail(0, "TEAMID1", "TEAMID1");
        revoked.lineage_approvals[0].state = 3;
        assert!(!auto_update_preselected(&revoked), "a revoked revision");
        assert_eq!(also_revocable(&revoked).len(), 0);
        assert_eq!(also_revocable(&detail(0, "", "")).len(), 1);
    }

    #[test]
    fn safe_defaults_are_narrow_and_wide_terms_are_flagged() {
        let t = Terms::safe_defaults(false);
        assert!(!t.is_wide());
        let p = t.to_proto(NOW);
        assert_eq!(
            (p.user_scope, p.path_match, p.update_policy, p.continuity),
            (1, 1, 1, 1)
        );
        assert_eq!((p.expires_at, p.confirm_any_user), (0, false));
        let wide = Terms {
            any_user: true,
            auto_update: true,
            expiry_days: 90,
            note: "  why  ".into(),
            ..Terms::safe_defaults(false)
        };
        assert!(wide.is_wide());
        assert!(wide.breaks_any_user_rule(0));
        assert!(!wide.breaks_any_user_rule(RiskFlags::PATH_PROTECTED));
        let p = wide.to_proto(NOW);
        assert_eq!((p.user_scope, p.confirm_any_user), (2, true));
        assert_eq!(p.expires_at, NOW + 90 * DAY);
        assert_eq!(p.note, "why");
        assert!(Terms {
            path_user_continuity: true,
            ..Terms::safe_defaults(false)
        }
        .is_wide());
    }

    #[test]
    fn requests_carry_reason_codes_and_the_key() {
        let a = approve_request(
            "req-1",
            Terms::safe_defaults(false).to_proto(NOW),
            vec!["a1".into()],
            REVOKE_REPLACED,
            "k1".into(),
        );
        assert_eq!(
            (a.also_revoke_reason_code, a.idempotency_key.as_str()),
            (4, "k1")
        );
        let a = approve_request("req-1", ApprovalTerms::default(), Vec::new(), 3, "k".into());
        assert_eq!(a.also_revoke_reason_code, 0, "no reason without ids");
        let d = deny_request("req-1", 4, " risky ", "k2".into());
        assert_eq!((d.reason_code, d.message.as_str()), (5, "risky"));
        assert_eq!(deny_request("r", 99, "", "k".into()).reason_code, 6);
        let r = revoke_request(&approval(1, 1), 0, "k3".into());
        assert_eq!((r.reason_code, r.expected_row_version), (1, 7));
        assert!(freeze_request("lin", true, "k4".into()).frozen);
        assert_ne!(new_idempotency_key(), new_idempotency_key());
    }

    #[test]
    fn an_edit_only_narrows_and_sends_what_changed() {
        let a = approval(1, 1);
        let e = Edit::unchanged(&a);
        assert_eq!(e.note, "kept", "control characters dropped");
        assert!(e.request(&a, NOW, "k".into()).is_none(), "nothing changed");
        let narrow = Edit {
            narrow_user: true,
            narrow_path: true,
            ..Edit::unchanged(&a)
        };
        assert!(
            narrow.request(&a, NOW, "k".into()).is_none(),
            "already narrow: nothing to narrow"
        );
        let wide = approval(2, 2);
        let r = Edit {
            narrow_user: true,
            expiry: EditExpiry::Days(30),
            note: String::new(),
            ..Edit::unchanged(&wide)
        }
        .request(&wide, NOW, "k".into())
        .unwrap();
        assert!(r.narrow_to_exact_user && !r.narrow_to_exact_path);
        assert_eq!(r.expires_at, Some(NOW + 30 * DAY));
        assert!(r.clear_note);
        assert_eq!(r.expected_row_version, 7);
        let loosen = Edit {
            path_user_continuity: true,
            expiry: EditExpiry::NoExpiry,
            ..Edit::unchanged(&a)
        };
        assert!(loosen.loosens_continuity(&a));
        let r = loosen.request(&a, NOW, "k".into()).unwrap();
        assert_eq!((r.continuity, r.clear_expiry), (Some(2), true));
    }

    #[test]
    fn revoke_needs_the_short_id_of_the_tail() {
        let id = "0190f0aa-0000-7000-8000-00000000beef";
        assert_eq!(short_id("A", id), "A-0000BEEF");
        assert!(revoke_confirmed(id, " a-0000beef "));
        assert!(!revoke_confirmed(id, "A-0190F0AA"));
        assert_eq!(short_host("12345678-aaaa"), "12345678");
        let u = AppUser {
            kind: 1,
            uid: Some(1000),
            sid: String::new(),
            name: "alice".into(),
        };
        assert_eq!(user_label(Some(&u)), "alice (1000)");
        assert_eq!(user_label(None), "—");
    }

    #[test]
    fn changes_between_two_loads_are_named() {
        let old = approval(2, 1);
        let mut new = old.clone();
        assert_eq!(approval_changes(&old, &new), Vec::new());
        new.user_scope = 1;
        new.expires_at = NOW;
        assert_eq!(
            approval_changes(&old, &new),
            vec![ApprovalChange::Expires, ApprovalChange::UserScope]
        );
    }
}
