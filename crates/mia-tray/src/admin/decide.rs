//! The decision dialog (F22 §4, the F21 §6 flows), headless: approve, deny,
//! edit (or renew), revoke, freeze, and the single-step "add application"
//! (F22 §5, T284). Each walks the same stages: the **form** with the safe
//! defaults, the extra **wide-scope** confirmation for "any user" or "path +
//! user only", then the **review** of exactly what will be sent. Only
//! "Confirm" on the review builds a request.

//! The rules come from `ferrogate_admin_client::approvals::{rules,
//! register}`, the ones the TUI applies. Every string in [`DecisionView`]
//! is made inert; the dialog holds no secret (the step-up and the add's
//! fresh second factor are the flow's).

use ferrogate_admin_client::approvals::filters::{warning_flags, RiskFlags};
use ferrogate_admin_client::approvals::proto::{
    AppRequestInfo, ApprovalInfo, GetAppRequestResponse,
};
use ferrogate_admin_client::approvals::register::{
    AdminRegisterApplicationRequest, RegisterError, RegisterField, Registration, PLATFORMS,
};
use ferrogate_admin_client::approvals::rules::{
    self, also_revocable, auto_update_preselected, revoke_confirmed, short_host, short_id,
    user_label, ApprovalChange, Edit, EditExpiry, Terms, DENY_REASONS, EDIT_EXPIRY_DAYS,
    EXPIRY_DAYS, MAX_CONFIRM, MAX_DENY_MESSAGE, MAX_NOTE, REVOKE_REASONS, REVOKE_REPLACED,
};
use ferrogate_admin_client::approvals::Mutation;
use ferrogate_admin_client::display::inert;
use serde::Serialize;

/// Longest server string shown in a dialog, in characters (a note is at
/// most 500).
pub const MAX_SHOWN: usize = 600;
/// Longest path shown, in characters: a path is shown whole, so its end
/// (the binary's name) is never cut off.
pub const MAX_PATH: usize = 4096;
/// Most lineage approvals offered for "also revoke".
pub const MAX_ALSO: usize = 16;
/// The "no expiry" choice of an edit (after "keep" and the day counts).
pub const EDIT_NO_EXPIRY: usize = EDIT_EXPIRY_DAYS.len() + 1;

/// Which decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// `ApproveAppRequest`.
    Approve,
    /// `DenyAppRequest`.
    Deny,
    /// `UpdateApproval` (a future expiry renews an expired approval).
    Edit,
    /// `RevokeApproval`.
    Revoke,
    /// `SetLineageAutoUpdateFrozen`.
    Freeze,
    /// `AdminRegisterApplication`: add an application by known hash and
    /// path, registered and approved in one step.
    Register,
}

/// Where the dialog is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStage {
    /// Choosing.
    Form,
    /// Accepting a wider scope.
    WideConfirm,
    /// Reading what will be sent.
    Review,
}

/// A typed field of the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionField {
    /// The approval's note.
    Note,
    /// The message to the requester (deny).
    Message,
    /// The typed short id (revoke).
    Confirm,
    /// The host UUID (add).
    Host,
    /// The canonical path (add).
    Path,
    /// The SHA-384 (add).
    Sha,
    /// The Unix uid or Windows RID (add).
    Uid,
    /// The Windows SID (add).
    Sid,
    /// The user name (add).
    User,
    /// The declared version (add).
    Version,
    /// The reason (add).
    Reason,
}

impl DecisionField {
    /// The add dialog's field this is, if any.
    #[must_use]
    pub fn register_field(self) -> Option<RegisterField> {
        Some(match self {
            Self::Host => RegisterField::Host,
            Self::Path => RegisterField::Path,
            Self::Sha => RegisterField::Sha,
            Self::Uid => RegisterField::Uid,
            Self::Sid => RegisterField::Sid,
            Self::User => RegisterField::User,
            Self::Version => RegisterField::Version,
            Self::Reason => RegisterField::Reason,
            Self::Note | Self::Message | Self::Confirm => return None,
        })
    }

    /// The dialog field of an add dialog's field.
    #[must_use]
    pub fn of_register(field: RegisterField) -> Self {
        match field {
            RegisterField::Host => Self::Host,
            RegisterField::Path => Self::Path,
            RegisterField::Sha => Self::Sha,
            RegisterField::Uid => Self::Uid,
            RegisterField::Sid => Self::Sid,
            RegisterField::User => Self::User,
            RegisterField::Version => Self::Version,
            RegisterField::Reason => Self::Reason,
        }
    }
}

/// Why the form did not move on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionError {
    /// Auto-update for any user needs a protected path (server rule).
    AnyUserNeedsProtectedPath,
    /// The edit changes nothing.
    NothingToChange,
    /// The typed short id does not match.
    ShortIdMismatch,
    /// Fields of the add dialog are refused (see `RegisterView::invalid`).
    FieldsInvalid,
}

/// A choice on the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Auto-approve updates.
    AutoUpdate(bool),
    /// "Path + user only" continuity.
    PathUserContinuity(bool),
    /// Any user.
    AnyUser(bool),
    /// Any path.
    AnyPath(bool),
    /// Expiry of a new approval (index into `EXPIRY_DAYS`).
    Expiry(usize),
    /// Expiry of an edit: 0 keep, then `EDIT_EXPIRY_DAYS`, then no expiry.
    EditExpiry(usize),
    /// Also revoke the lineage approval at this index.
    AlsoRevoke(usize, bool),
    /// Revoke reason (index into `REVOKE_REASONS`).
    RevokeReason(usize),
    /// Deny reason (index into `DENY_REASONS`).
    DenyReason(usize),
    /// Narrow "any user" to this user.
    NarrowUser(bool),
    /// Narrow "any path" to the exact path.
    NarrowPath(bool),
    /// Freeze (true) or unfreeze the lineage's auto-updates.
    Frozen(bool),
    /// The platform at this index of `PLATFORMS` (add).
    Platform(usize),
    /// A Windows user (SID or RID) rather than a Unix uid (add).
    WindowsUser(bool),
    /// "Path writable only by administrators", the administrator's
    /// assertion (add).
    PathProtected(bool),
}

/// One line of the review page (the window words it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLine {
    /// The canonical path (inert).
    Path(String),
    /// The SHA-384 (inert).
    Sha(String),
    /// The operating-system user (inert).
    User(String),
    /// Update policy: auto-update or manual.
    Policy(bool),
    /// Continuity: path + user only, or anchored.
    Continuity(bool),
    /// User scope: any user, or this user only.
    Scope(bool),
    /// Path match: any path, or the exact path.
    PathMatch(bool),
    /// Expiry (Unix seconds); 0 is the server default.
    Expires(i64),
    /// The note (inert), empty for none.
    Note(String),
    /// Approvals revoked with it (short ids) and the reason code name.
    AlsoRevoke(Vec<String>, &'static str),
    /// Risk-flag warnings.
    Warnings(Vec<&'static str>),
    /// The deny reason code name.
    DenyReason(&'static str),
    /// The message to the requester (inert), empty for none.
    Message(String),
    /// The approval's row version the edit is based on.
    RowVersion(u64),
    /// Policy from → to.
    EditPolicy(bool, bool),
    /// Continuity from → to.
    EditContinuity(bool, bool),
    /// Expiry from (0 none) → to (`None`: no expiry).
    EditExpires(i64, Option<i64>),
    /// The new note (inert); `None` when removed.
    EditNote(Option<String>),
    /// User scope narrowed to this user.
    NarrowUser,
    /// Path match narrowed to the exact path.
    NarrowPath,
    /// The revoke reason code name.
    RevokeReason(&'static str),
    /// The lineage (its path, inert).
    Lineage(String),
    /// Freeze (true) or unfreeze.
    Freeze(bool),
    /// The host UUID (inert, lowercased).
    Host(String),
    /// The platform's name.
    Platform(&'static str),
    /// The declared version (inert).
    Version(String),
    /// The reason (inert).
    Reason(String),
    /// "Path protected: yes", the administrator's assertion.
    PathProtectedAsserted,
    /// What the add does: registers and approves in one step (`true`, the
    /// session may approve), or only queues under strict separation of
    /// duties.
    RegisterOutcome(bool),
    /// The hash and the path are the administrator's assertion.
    Assertion,
    /// Confirming asks for a fresh second factor, whatever the step-up
    /// window.
    FreshFactor,
}

/// The add dialog's typed facts (inert) and their checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model.
pub struct RegisterView {
    /// The host UUID typed.
    pub host: String,
    /// Index into `PLATFORMS`.
    pub platform: usize,
    /// The canonical path typed.
    pub path: String,
    /// The SHA-384 typed.
    pub sha: String,
    /// A Windows user.
    pub windows_user: bool,
    /// The uid (or RID) typed.
    pub uid: String,
    /// The SID typed.
    pub sid: String,
    /// The user name typed.
    pub user: String,
    /// The declared version typed.
    pub version: String,
    /// The reason typed.
    pub reason: String,
    /// "Path writable only by administrators" asserted.
    pub path_protected: bool,
    /// The session may approve (single step) rather than only queue.
    pub can_approve: bool,
    /// The refused fields and why.
    pub invalid: Vec<(DecisionField, RegisterError)>,
}

/// An approval offered for "also revoke".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlsoRow {
    /// Its short id.
    pub short_id: String,
    /// Its revision.
    pub revision: u32,
    /// Whether a newer approval superseded it.
    pub superseded: bool,
    /// Checked.
    pub checked: bool,
}

/// What the window draws. Server strings are inert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model: one flag per control.
pub struct DecisionView {
    /// Which decision.
    pub kind: DecisionKind,
    /// Where it is.
    pub stage: DecisionStage,
    /// `R-…` or `A-…` (empty for a lineage).
    pub short_id: String,
    /// The canonical path (or the lineage's).
    pub path: String,
    /// The display version.
    pub version: String,
    /// The host, shortened.
    pub host: String,
    /// The user.
    pub user: String,
    /// Risk-flag warnings of the request.
    pub warnings: Vec<&'static str>,
    /// The request's path is protected (auto-update for any user allowed).
    pub protected_path: bool,
    /// Auto-update chosen.
    pub auto_update: bool,
    /// "Path + user only" chosen.
    pub path_user_continuity: bool,
    /// "Any user" chosen.
    pub any_user: bool,
    /// "Any path" chosen.
    pub any_path: bool,
    /// Expiry choice of an approval.
    pub expiry: usize,
    /// Expiry choice of an edit.
    pub edit_expiry: usize,
    /// The approval's expiry now (0 none).
    pub current_expires_at: i64,
    /// The approval's state (1 active, 2 expired, 3 revoked).
    pub approval_state: u32,
    /// "Also revoke" offers.
    pub also: Vec<AlsoRow>,
    /// Revoke reason chosen.
    pub revoke_reason: usize,
    /// Deny reason chosen.
    pub deny_reason: usize,
    /// "Narrow to this user" is offered (the approval is for any user).
    pub narrow_user_offered: bool,
    /// "Narrow to the exact path" is offered.
    pub narrow_path_offered: bool,
    /// Narrow the user scope.
    pub narrow_user: bool,
    /// Narrow the path match.
    pub narrow_path: bool,
    /// Freeze chosen.
    pub frozen: bool,
    /// The note typed (inert).
    pub note: String,
    /// The message typed (inert).
    pub message: String,
    /// The short id typed (inert).
    pub confirm: String,
    /// The focused field.
    pub focus: Option<DecisionField>,
    /// Why the form did not move on.
    pub error: Option<DecisionError>,
    /// What changed meanwhile (after a concurrent edit).
    pub changed_meanwhile: Option<Vec<ApprovalChange>>,
    /// The review page.
    pub review: Vec<ReviewLine>,
    /// The add dialog's facts, for [`DecisionKind::Register`].
    pub register: Option<RegisterView>,
}

enum Ctx {
    Approve {
        request: Box<AppRequestInfo>,
        also: Vec<ApprovalInfo>,
    },
    Deny {
        request: Box<AppRequestInfo>,
    },
    Edit {
        approval: Box<ApprovalInfo>,
    },
    Revoke {
        approval: Box<ApprovalInfo>,
    },
    Freeze {
        lineage_id: String,
        label: String,
    },
    Register {
        facts: Box<Registration>,
        can_approve: bool,
    },
}

/// An open decision dialog.
pub struct Decision {
    ctx: Ctx,
    stage: DecisionStage,
    terms: Terms,
    expiry: usize,
    also: Vec<bool>,
    revoke_reason: usize,
    deny_reason: usize,
    message: String,
    edit: Option<Edit>,
    edit_expiry: usize,
    confirm: String,
    frozen: bool,
    focus: Option<DecisionField>,
    error: Option<DecisionError>,
    changed_meanwhile: Option<Vec<ApprovalChange>>,
    invalid: Vec<(RegisterField, RegisterError)>,
}

/// Push the printable characters of `text` onto `field`, up to `max`.
fn push_bounded(field: &mut String, text: &str, max: usize) {
    for c in text.chars().filter(|c| !c.is_control()) {
        if field.chars().count() >= max {
            break;
        }
        field.push(c);
    }
}

fn shown(text: &str) -> String {
    inert(text, MAX_SHOWN)
}

fn shown_path(path: &str) -> String {
    inert(path, MAX_PATH)
}

impl Decision {
    fn new(ctx: Ctx, focus: Option<DecisionField>) -> Self {
        Self {
            ctx,
            stage: DecisionStage::Form,
            terms: Terms::safe_defaults(false),
            expiry: 0,
            also: Vec::new(),
            revoke_reason: 0,
            deny_reason: 0,
            message: String::new(),
            edit: None,
            edit_expiry: 0,
            confirm: String::new(),
            frozen: true,
            focus,
            error: None,
            changed_meanwhile: None,
            invalid: Vec::new(),
        }
    }

    /// Approve a pending request, with the safe defaults; `None` unless
    /// the request is pending.
    #[must_use]
    pub fn approve(detail: &GetAppRequestResponse) -> Option<Self> {
        let request = detail.request.clone().filter(|r| r.state == 1)?;
        let mut also = also_revocable(detail);
        also.truncate(MAX_ALSO);
        let mut d = Self::new(
            Ctx::Approve {
                request: Box::new(request),
                also: Vec::new(),
            },
            Some(DecisionField::Note),
        );
        d.terms = Terms::safe_defaults(auto_update_preselected(detail));
        d.also = vec![false; also.len()];
        d.revoke_reason = REVOKE_REPLACED;
        if let Ctx::Approve { also: a, .. } = &mut d.ctx {
            *a = also;
        }
        Some(d)
    }

    /// Deny a pending request; `None` unless it is pending.
    #[must_use]
    pub fn deny(request: &AppRequestInfo) -> Option<Self> {
        (request.state == 1).then(|| {
            Self::new(
                Ctx::Deny {
                    request: Box::new(request.clone()),
                },
                Some(DecisionField::Message),
            )
        })
    }

    /// Edit (or renew) an approval: only narrowing of the scope is offered;
    /// `None` for a revoked one.
    #[must_use]
    pub fn edit(approval: &ApprovalInfo) -> Option<Self> {
        (approval.state != 3).then(|| {
            let mut d = Self::new(
                Ctx::Edit {
                    approval: Box::new(approval.clone()),
                },
                Some(DecisionField::Note),
            );
            d.edit = Some(Edit::unchanged(approval));
            d
        })
    }

    /// Revoke an approval (a reason and the typed short id); `None` for a
    /// revoked one.
    #[must_use]
    pub fn revoke(approval: &ApprovalInfo) -> Option<Self> {
        (approval.state != 3).then(|| {
            Self::new(
                Ctx::Revoke {
                    approval: Box::new(approval.clone()),
                },
                Some(DecisionField::Confirm),
            )
        })
    }

    /// Freeze or unfreeze a lineage's auto-updates; the default is the
    /// opposite of `frozen_now` (freeze when unknown).
    #[must_use]
    pub fn freeze(lineage_id: &str, label: &str, frozen_now: Option<bool>) -> Self {
        let mut d = Self::new(
            Ctx::Freeze {
                lineage_id: lineage_id.to_string(),
                label: label.to_string(),
            },
            None,
        );
        d.frozen = frozen_now != Some(true);
        d
    }

    /// Add an application by known hash and path (`can_approve`: the session
    /// holds `app_request.approve`, so the add is a single step), with the
    /// safe approval defaults.
    #[must_use]
    pub fn register(can_approve: bool) -> Self {
        Self::new(
            Ctx::Register {
                facts: Box::default(),
                can_approve,
            },
            Some(DecisionField::Host),
        )
    }

    /// The edit re-asked after a concurrent change, on the reloaded row.
    #[must_use]
    pub fn reask_edit(old: &ApprovalInfo, new: &ApprovalInfo) -> Option<Self> {
        let mut d = Self::edit(new)?;
        d.changed_meanwhile = Some(rules::approval_changes(old, new));
        Some(d)
    }

    /// Which decision.
    #[must_use]
    pub fn kind(&self) -> DecisionKind {
        match self.ctx {
            Ctx::Approve { .. } => DecisionKind::Approve,
            Ctx::Deny { .. } => DecisionKind::Deny,
            Ctx::Edit { .. } => DecisionKind::Edit,
            Ctx::Revoke { .. } => DecisionKind::Revoke,
            Ctx::Freeze { .. } => DecisionKind::Freeze,
            Ctx::Register { .. } => DecisionKind::Register,
        }
    }

    /// The approval an edit is based on (for an `ABORTED` reload).
    #[must_use]
    pub fn edited(&self) -> Option<&ApprovalInfo> {
        match &self.ctx {
            Ctx::Edit { approval } => Some(approval),
            _ => None,
        }
    }

    /// The typed fields of this dialog, in `Tab` order.
    #[must_use]
    pub fn fields(&self) -> Vec<DecisionField> {
        match self.ctx {
            Ctx::Approve { .. } | Ctx::Edit { .. } => vec![DecisionField::Note],
            Ctx::Deny { .. } => vec![DecisionField::Message],
            Ctx::Revoke { .. } => vec![DecisionField::Confirm],
            Ctx::Freeze { .. } => Vec::new(),
            Ctx::Register { .. } => RegisterField::ALL
                .iter()
                .map(|f| DecisionField::of_register(*f))
                .chain([DecisionField::Note])
                .collect(),
        }
    }

    /// `Tab` / `Shift-Tab`: the next (previous) typed field (form only).
    pub fn tab(&mut self, back: bool) {
        let fields = self.fields();
        if self.stage != DecisionStage::Form || fields.is_empty() {
            return;
        }
        let at = self
            .focus
            .and_then(|f| fields.iter().position(|x| *x == f))
            .unwrap_or(0);
        let n = fields.len();
        self.focus = Some(fields[if back { (at + n - 1) % n } else { (at + 1) % n }]);
    }

    /// Whether typing goes to a field now.
    #[must_use]
    pub fn editing(&self) -> bool {
        self.stage == DecisionStage::Form && self.focus.is_some()
    }

    /// Focus `field` when the dialog has it.
    pub fn focus(&mut self, field: DecisionField) {
        if self.fields().contains(&field) {
            self.focus = Some(field);
        }
    }

    /// Typed or pasted text, for the focused field (form stage only).
    pub fn type_text(&mut self, text: &str) {
        if self.stage != DecisionStage::Form {
            return;
        }
        self.error = None;
        match self.focus {
            Some(DecisionField::Note) => {
                if let Some(e) = &mut self.edit {
                    push_bounded(&mut e.note, text, MAX_NOTE);
                } else {
                    push_bounded(&mut self.terms.note, text, MAX_NOTE);
                }
            }
            Some(DecisionField::Message) => push_bounded(&mut self.message, text, MAX_DENY_MESSAGE),
            Some(DecisionField::Confirm) => push_bounded(&mut self.confirm, text, MAX_CONFIRM),
            Some(field) => {
                let (Some(f), Ctx::Register { facts, .. }) =
                    (field.register_field(), &mut self.ctx)
                else {
                    return;
                };
                // A pasted hash or id keeps no spaces or line breaks.
                let text: String = match f {
                    RegisterField::Host | RegisterField::Sha | RegisterField::Uid => {
                        text.chars().filter(|c| !c.is_whitespace()).collect()
                    }
                    _ => text.to_string(),
                };
                push_bounded(facts.text_mut(f), &text, f.max_chars());
                self.invalid.retain(|(x, _)| *x != f);
            }
            None => {}
        }
    }

    /// `Backspace` in the focused field.
    pub fn backspace(&mut self) {
        if self.stage != DecisionStage::Form {
            return;
        }
        self.error = None;
        match self.focus {
            Some(DecisionField::Note) => {
                if let Some(e) = &mut self.edit {
                    e.note.pop();
                } else {
                    self.terms.note.pop();
                }
            }
            Some(DecisionField::Message) => {
                self.message.pop();
            }
            Some(DecisionField::Confirm) => {
                self.confirm.pop();
            }
            Some(field) => {
                if let (Some(f), Ctx::Register { facts, .. }) =
                    (field.register_field(), &mut self.ctx)
                {
                    facts.text_mut(f).pop();
                }
            }
            None => {}
        }
    }

    /// A choice on the form (ignored past it, or when it does not apply).
    pub fn choose(&mut self, choice: Choice) {
        if self.stage != DecisionStage::Form {
            return;
        }
        self.error = None;
        if let Ctx::Register { facts, .. } = &mut self.ctx {
            match choice {
                Choice::Platform(i) => facts.platform = i.min(PLATFORMS.len() - 1),
                Choice::WindowsUser(on) => facts.windows_user = on,
                Choice::PathProtected(on) => facts.path_protected = on,
                _ => {}
            }
        }
        let edit = self.edit.as_mut();
        match (choice, edit) {
            (Choice::AutoUpdate(on), Some(e)) => e.auto_update = on,
            (Choice::PathUserContinuity(on), Some(e)) => e.path_user_continuity = on,
            (Choice::EditExpiry(i), Some(e)) => {
                self.edit_expiry = i.min(EDIT_NO_EXPIRY);
                e.expiry = match self.edit_expiry {
                    0 => EditExpiry::Keep,
                    i if i == EDIT_NO_EXPIRY => EditExpiry::NoExpiry,
                    i => EditExpiry::Days(EDIT_EXPIRY_DAYS[i - 1]),
                };
            }
            (Choice::NarrowUser(on), Some(e)) => e.narrow_user = on,
            (Choice::NarrowPath(on), Some(e)) => e.narrow_path = on,
            (Choice::AutoUpdate(on), None) => self.terms.auto_update = on,
            (Choice::PathUserContinuity(on), None) => self.terms.path_user_continuity = on,
            (Choice::AnyUser(on), None) => self.terms.any_user = on,
            (Choice::AnyPath(on), None) => self.terms.any_path = on,
            (Choice::Expiry(i), None) => {
                self.expiry = i.min(EXPIRY_DAYS.len() - 1);
                self.terms.expiry_days = EXPIRY_DAYS[self.expiry];
            }
            (Choice::AlsoRevoke(i, on), None) => {
                if let Some(c) = self.also.get_mut(i) {
                    *c = on;
                }
            }
            (Choice::RevokeReason(i), _) => self.revoke_reason = i.min(REVOKE_REASONS.len() - 1),
            (Choice::DenyReason(i), _) => self.deny_reason = i.min(DENY_REASONS.len() - 1),
            (Choice::Frozen(on), _) => self.frozen = on,
            _ => {}
        }
    }

    fn validate(&self) -> Option<DecisionError> {
        match &self.ctx {
            Ctx::Approve { request, .. } if self.terms.breaks_any_user_rule(request.flags) => {
                Some(DecisionError::AnyUserNeedsProtectedPath)
            }
            Ctx::Edit { approval } => self
                .edit
                .as_ref()
                .and_then(|e| e.request(approval, 0, String::new()))
                .is_none()
                .then_some(DecisionError::NothingToChange),
            Ctx::Revoke { approval } if !revoke_confirmed(&approval.approval_id, &self.confirm) => {
                Some(DecisionError::ShortIdMismatch)
            }
            Ctx::Register { facts, .. } if !facts.problems().is_empty() => {
                Some(DecisionError::FieldsInvalid)
            }
            Ctx::Register { facts, .. } if self.terms.breaks_any_user_rule(facts.flags()) => {
                Some(DecisionError::AnyUserNeedsProtectedPath)
            }
            _ => None,
        }
    }

    /// Whether the choices need the extra wide-scope confirmation.
    #[must_use]
    pub fn is_wide(&self) -> bool {
        match &self.ctx {
            Ctx::Approve { .. } | Ctx::Register { .. } => self.terms.is_wide(),
            Ctx::Edit { approval } => self
                .edit
                .as_ref()
                .is_some_and(|e| e.loosens_continuity(approval)),
            _ => false,
        }
    }

    /// "Continue" on the form (to the wide confirmation or the review), or
    /// "Accept" on the wide confirmation.
    pub fn next(&mut self) {
        match self.stage {
            DecisionStage::Form => {
                self.error = self.validate();
                self.invalid = match &self.ctx {
                    Ctx::Register { facts, .. } => facts.problems(),
                    _ => Vec::new(),
                };
                if let Some((f, _)) = self.invalid.first() {
                    self.focus = Some(DecisionField::of_register(*f));
                }
                if self.error.is_none() {
                    self.stage = if self.is_wide() {
                        DecisionStage::WideConfirm
                    } else {
                        DecisionStage::Review
                    };
                }
            }
            DecisionStage::WideConfirm => self.stage = DecisionStage::Review,
            DecisionStage::Review => {}
        }
    }

    /// "Back": to the form.
    pub fn back(&mut self) {
        self.stage = DecisionStage::Form;
    }

    fn also_ids(&self) -> Vec<String> {
        match &self.ctx {
            Ctx::Approve { also, .. } => self
                .also
                .iter()
                .zip(also)
                .filter(|(on, _)| **on)
                .map(|(_, a)| a.approval_id.clone())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// "Confirm" on the review page: the request to send, with a fresh
    /// idempotency key (`now` fixes expiry dates). `None` elsewhere.
    #[must_use]
    pub fn confirm(&self, now: i64) -> Option<Mutation> {
        if self.stage != DecisionStage::Review || self.validate().is_some() {
            return None;
        }
        let key = rules::new_idempotency_key();
        Some(match &self.ctx {
            Ctx::Approve { request, .. } => Mutation::Approve(rules::approve_request(
                &request.request_id,
                self.terms.to_proto(now),
                self.also_ids(),
                self.revoke_reason,
                key,
            )),
            Ctx::Deny { request } => Mutation::Deny(rules::deny_request(
                &request.request_id,
                self.deny_reason,
                &self.message,
                key,
            )),
            Ctx::Edit { approval } => {
                Mutation::Update(self.edit.as_ref()?.request(approval, now, key)?)
            }
            Ctx::Revoke { approval } => {
                Mutation::Revoke(rules::revoke_request(approval, self.revoke_reason, key))
            }
            Ctx::Freeze { lineage_id, .. } => {
                Mutation::Freeze(rules::freeze_request(lineage_id, self.frozen, key))
            }
            // Not a step-up decision: see `Decision::confirm_register`.
            Ctx::Register { .. } => return None,
        })
    }

    /// "Confirm" on the review page of an add: the request to send with a
    /// fresh second factor, with a new idempotency key (`now` fixes the
    /// expiry). `None` elsewhere. It carries no proof and no secret.
    #[must_use]
    pub fn confirm_register(&self, now: i64) -> Option<AdminRegisterApplicationRequest> {
        let Ctx::Register { facts, .. } = &self.ctx else {
            return None;
        };
        if self.stage != DecisionStage::Review || self.validate().is_some() {
            return None;
        }
        Some(facts.request(self.terms.to_proto(now), rules::new_idempotency_key()))
    }

    fn review(&self, now: i64) -> Vec<ReviewLine> {
        let mut out = Vec::new();
        match &self.ctx {
            Ctx::Approve { request, also } => {
                out.push(ReviewLine::Path(shown_path(&request.canonical_path)));
                out.push(ReviewLine::Sha(shown(&request.bin_sha)));
                out.push(ReviewLine::User(shown(&user_label(
                    request.target_user.as_ref(),
                ))));
                let t = self.terms.to_proto(now);
                out.push(ReviewLine::Policy(self.terms.auto_update));
                out.push(ReviewLine::Continuity(self.terms.path_user_continuity));
                out.push(ReviewLine::Scope(self.terms.any_user));
                out.push(ReviewLine::PathMatch(self.terms.any_path));
                out.push(ReviewLine::Expires(t.expires_at));
                out.push(ReviewLine::Note(shown(&t.note)));
                let ids = self.also_ids();
                if !ids.is_empty() {
                    let names = also
                        .iter()
                        .filter(|a| ids.contains(&a.approval_id))
                        .map(|a| short_id("A", &a.approval_id))
                        .collect();
                    out.push(ReviewLine::AlsoRevoke(
                        names,
                        REVOKE_REASONS[self.revoke_reason],
                    ));
                }
                let w = warning_flags(request.flags);
                if !w.is_empty() {
                    out.push(ReviewLine::Warnings(w));
                }
            }
            Ctx::Deny { request } => {
                out.push(ReviewLine::Path(shown_path(&request.canonical_path)));
                out.push(ReviewLine::DenyReason(DENY_REASONS[self.deny_reason]));
                out.push(ReviewLine::Message(shown(self.message.trim())));
            }
            Ctx::Edit { approval } => {
                out.push(ReviewLine::Path(shown_path(&approval.canonical_path)));
                out.push(ReviewLine::RowVersion(approval.row_version));
                let req = self
                    .edit
                    .as_ref()
                    .and_then(|e| e.request(approval, now, String::new()));
                if let Some(req) = req {
                    if let Some(p) = req.update_policy {
                        out.push(ReviewLine::EditPolicy(approval.update_policy == 2, p == 2));
                    }
                    if let Some(c) = req.continuity {
                        out.push(ReviewLine::EditContinuity(approval.continuity == 2, c == 2));
                    }
                    if let Some(e) = req.expires_at {
                        out.push(ReviewLine::EditExpires(approval.expires_at, Some(e)));
                    }
                    if req.clear_expiry {
                        out.push(ReviewLine::EditExpires(approval.expires_at, None));
                    }
                    if let Some(n) = &req.note {
                        out.push(ReviewLine::EditNote(Some(shown(n))));
                    }
                    if req.clear_note {
                        out.push(ReviewLine::EditNote(None));
                    }
                    if req.narrow_to_exact_user {
                        out.push(ReviewLine::NarrowUser);
                    }
                    if req.narrow_to_exact_path {
                        out.push(ReviewLine::NarrowPath);
                    }
                }
            }
            Ctx::Revoke { approval } => {
                out.push(ReviewLine::Path(shown_path(&approval.canonical_path)));
                out.push(ReviewLine::User(shown(&user_label(approval.user.as_ref()))));
                out.push(ReviewLine::RevokeReason(REVOKE_REASONS[self.revoke_reason]));
            }
            Ctx::Freeze { label, .. } => {
                out.push(ReviewLine::Lineage(shown_path(label)));
                out.push(ReviewLine::Freeze(self.frozen));
            }
            Ctx::Register { facts, can_approve } => {
                self.register_review(facts, *can_approve, now, &mut out);
            }
        }
        out
    }

    /// The add's review: exactly what goes on the wire (trimmed,
    /// lowercased), what it does and what it rests on.
    fn register_review(
        &self,
        facts: &Registration,
        can_approve: bool,
        now: i64,
        out: &mut Vec<ReviewLine>,
    ) {
        let terms = self.terms.to_proto(now);
        let r = facts.request(terms.clone(), String::new());
        let b = r.binary.unwrap_or_default();
        out.push(ReviewLine::Host(shown(&r.host_uuid)));
        out.push(ReviewLine::Platform(
            PLATFORMS[facts.platform.min(PLATFORMS.len() - 1)],
        ));
        out.push(ReviewLine::Path(shown_path(&b.canonical_path)));
        out.push(ReviewLine::Sha(shown(&b.sha384)));
        out.push(ReviewLine::User(shown(&user_label(r.target_user.as_ref()))));
        if !b.declared_version.is_empty() {
            out.push(ReviewLine::Version(shown(&b.declared_version)));
        }
        if !r.reason.is_empty() {
            out.push(ReviewLine::Reason(shown(&r.reason)));
        }
        if facts.path_protected {
            out.push(ReviewLine::PathProtectedAsserted);
        }
        out.push(ReviewLine::Policy(self.terms.auto_update));
        out.push(ReviewLine::Continuity(self.terms.path_user_continuity));
        out.push(ReviewLine::Scope(self.terms.any_user));
        out.push(ReviewLine::PathMatch(self.terms.any_path));
        out.push(ReviewLine::Expires(terms.expires_at));
        out.push(ReviewLine::Note(shown(&terms.note)));
        out.push(ReviewLine::RegisterOutcome(can_approve));
        out.push(ReviewLine::Assertion);
        out.push(ReviewLine::FreshFactor);
    }

    fn register_view(&self) -> Option<RegisterView> {
        let Ctx::Register { facts, can_approve } = &self.ctx else {
            return None;
        };
        Some(RegisterView {
            host: shown(&facts.host_uuid),
            platform: facts.platform,
            path: shown_path(&facts.canonical_path),
            sha: shown(&facts.sha384),
            windows_user: facts.windows_user,
            uid: shown(&facts.uid),
            sid: shown(&facts.sid),
            user: shown(&facts.user_name),
            version: shown(&facts.version),
            reason: shown(&facts.reason),
            path_protected: facts.path_protected,
            can_approve: *can_approve,
            invalid: self
                .invalid
                .iter()
                .map(|(f, e)| (DecisionField::of_register(*f), *e))
                .collect(),
        })
    }

    /// What the window draws at Unix time `now`.
    #[must_use]
    pub fn view(&self, now: i64) -> DecisionView {
        let (short, path, version, host, user, flags) = match &self.ctx {
            Ctx::Approve { request, .. } | Ctx::Deny { request } => (
                short_id("R", &request.request_id),
                shown_path(&request.canonical_path),
                shown(&request.display_version),
                shown(&short_host(&request.host_uuid)),
                shown(&user_label(request.target_user.as_ref())),
                request.flags,
            ),
            Ctx::Edit { approval } | Ctx::Revoke { approval } => (
                short_id("A", &approval.approval_id),
                shown_path(&approval.canonical_path),
                shown(&approval.declared_version),
                shown(&short_host(&approval.host_uuid)),
                shown(&user_label(approval.user.as_ref())),
                0,
            ),
            Ctx::Freeze { label, .. } => (
                String::new(),
                shown_path(label),
                String::new(),
                String::new(),
                String::new(),
                0,
            ),
            // The facts are shown by their own fields (`register`).
            Ctx::Register { facts, .. } => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                facts.flags(),
            ),
        };
        let also = match &self.ctx {
            Ctx::Approve { also, .. } => also
                .iter()
                .zip(&self.also)
                .map(|(a, on)| AlsoRow {
                    short_id: short_id("A", &a.approval_id),
                    revision: a.revision,
                    superseded: !a.superseded_by.is_empty(),
                    checked: *on,
                })
                .collect(),
            _ => Vec::new(),
        };
        let approval = self.edited().or(match &self.ctx {
            Ctx::Revoke { approval } => Some(approval),
            _ => None,
        });
        let (auto_update, path_user_continuity, note) = match &self.edit {
            Some(e) => (e.auto_update, e.path_user_continuity, &e.note),
            None => (
                self.terms.auto_update,
                self.terms.path_user_continuity,
                &self.terms.note,
            ),
        };
        DecisionView {
            kind: self.kind(),
            stage: self.stage,
            short_id: short,
            path,
            version,
            host,
            user,
            warnings: warning_flags(flags),
            protected_path: flags & RiskFlags::PATH_PROTECTED != 0,
            auto_update,
            path_user_continuity,
            any_user: self.terms.any_user,
            any_path: self.terms.any_path,
            expiry: self.expiry,
            edit_expiry: self.edit_expiry,
            current_expires_at: approval.map_or(0, |a| a.expires_at),
            approval_state: approval.map_or(0, |a| a.state),
            also,
            revoke_reason: self.revoke_reason,
            deny_reason: self.deny_reason,
            narrow_user_offered: approval.is_some_and(|a| a.user_scope == 2) && self.edit.is_some(),
            narrow_path_offered: approval.is_some_and(|a| a.path_match == 2) && self.edit.is_some(),
            narrow_user: self.edit.as_ref().is_some_and(|e| e.narrow_user),
            narrow_path: self.edit.as_ref().is_some_and(|e| e.narrow_path),
            frozen: self.frozen,
            note: shown(note),
            message: shown(&self.message),
            confirm: shown(&self.confirm),
            focus: self.focus,
            error: self.error,
            changed_meanwhile: self.changed_meanwhile.clone(),
            review: if self.stage == DecisionStage::Review {
                self.review(now)
            } else {
                Vec::new()
            },
            register: self.register_view(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ferrogate_admin_client::approvals::proto::{
        approve_app_request_request::Choice as Chosen, AppBinaryInfo, AppUser,
    };

    pub(crate) const NOW: i64 = 1_791_936_000;
    pub(crate) const APPROVAL_ID: &str = "0190f0aa-0000-7000-8000-00000000beef";

    pub(crate) fn request(flags: u32) -> AppRequestInfo {
        AppRequestInfo {
            request_id: "0192a9f1-0000-7000-8000-00000000a1b2".into(),
            host_uuid: "11111111-2222-3333-4444-555555555555".into(),
            lineage_id: "lin".into(),
            canonical_path: "/usr/local/bin/backup\u{202e}gpj.exe".into(),
            bin_sha: "ab".repeat(48),
            revision: 2,
            state: 1,
            flags,
            display_version: "r2".into(),
            target_user: Some(AppUser {
                kind: 1,
                uid: Some(993),
                sid: String::new(),
                name: "backup\u{1b}[2J".into(),
            }),
            ..AppRequestInfo::default()
        }
    }

    pub(crate) fn detail(flags: u32) -> GetAppRequestResponse {
        GetAppRequestResponse {
            request: Some(request(flags)),
            binary: Some(AppBinaryInfo::default()),
            lineage_approvals: vec![approval(1, 1)],
            ..GetAppRequestResponse::default()
        }
    }

    pub(crate) fn approval(scope: u32, path: u32) -> ApprovalInfo {
        ApprovalInfo {
            approval_id: APPROVAL_ID.into(),
            host_uuid: "11111111-2222-3333-4444-555555555555".into(),
            lineage_id: "lin".into(),
            canonical_path: "/usr/local/bin/backup".into(),
            revision: 1,
            state: 1,
            user_scope: scope,
            path_match: path,
            update_policy: 1,
            continuity: 1,
            row_version: 7,
            ..ApprovalInfo::default()
        }
    }

    #[test]
    fn approve_starts_with_the_safe_defaults_and_sends_after_the_review() {
        let mut d = Decision::approve(&detail(RiskFlags::UNSIGNED)).unwrap();
        let v = d.view(NOW);
        assert_eq!(
            (v.kind, v.stage),
            (DecisionKind::Approve, DecisionStage::Form)
        );
        assert!(!v.auto_update && !v.any_user && !v.any_path && !v.path_user_continuity);
        assert_eq!((v.expiry, v.also.len(), v.also[0].checked), (0, 1, false));
        assert_eq!(v.warnings, vec!["unsigned"]);
        assert!(!v.path.contains('\u{202e}') && !v.user.contains('\u{1b}'));
        assert!(d.confirm(NOW).is_none(), "nothing before the review");
        d.type_text("ticket 42");
        d.choose(Choice::Expiry(2));
        d.choose(Choice::AlsoRevoke(0, true));
        d.next();
        assert_eq!(d.view(NOW).stage, DecisionStage::Review);
        d.type_text("ignored on the review");
        let review = d.view(NOW).review;
        assert!(review.contains(&ReviewLine::Expires(NOW + 90 * 86_400)));
        assert!(review.contains(&ReviewLine::Note("ticket 42".into())));
        assert!(review.contains(&ReviewLine::AlsoRevoke(
            vec!["A-0000BEEF".into()],
            "replaced"
        )));
        let Some(Mutation::Approve(a)) = d.confirm(NOW) else {
            panic!("an approval");
        };
        let Some(Chosen::Terms(terms)) = a.choice else {
            panic!("terms");
        };
        assert_eq!((terms.user_scope, terms.update_policy), (1, 1));
        assert_eq!(terms.note, "ticket 42");
        assert_eq!(a.also_revoke_approval_ids, vec![APPROVAL_ID.to_string()]);
        assert_eq!(a.also_revoke_reason_code, 4);
        let again = d.confirm(NOW).unwrap();
        assert_ne!(
            again.idempotency_key(),
            a.idempotency_key,
            "each confirmation is a new decision"
        );
    }

    #[test]
    fn a_wide_scope_needs_its_own_confirmation_and_the_any_user_rule_holds() {
        let mut d = Decision::approve(&detail(0)).unwrap();
        d.choose(Choice::AnyUser(true));
        d.choose(Choice::AutoUpdate(true));
        d.next();
        let v = d.view(NOW);
        assert_eq!(
            (v.stage, v.error),
            (
                DecisionStage::Form,
                Some(DecisionError::AnyUserNeedsProtectedPath)
            )
        );
        d.choose(Choice::AutoUpdate(false));
        d.next();
        assert_eq!(d.view(NOW).stage, DecisionStage::WideConfirm);
        d.back();
        assert_eq!(d.view(NOW).stage, DecisionStage::Form);
        d.next();
        d.next();
        assert_eq!(d.view(NOW).stage, DecisionStage::Review);
        let Some(Mutation::Approve(a)) = d.confirm(NOW) else {
            panic!("an approval");
        };
        assert!(matches!(
            a.choice,
            Some(Chosen::Terms(t)) if t.confirm_any_user && t.user_scope == 2
        ));
    }

    #[test]
    fn deny_takes_a_reason_and_a_bounded_message() {
        assert!(
            Decision::deny(&AppRequestInfo::default()).is_none(),
            "not pending"
        );
        let mut d = Decision::deny(&request(0)).unwrap();
        d.choose(Choice::DenyReason(4));
        d.type_text(&"x".repeat(MAX_DENY_MESSAGE + 50));
        assert_eq!(d.view(NOW).message.chars().count(), MAX_DENY_MESSAGE);
        d.next();
        let Some(Mutation::Deny(r)) = d.confirm(NOW) else {
            panic!("a denial");
        };
        assert_eq!(r.reason_code, 5);
    }

    #[test]
    fn an_edit_only_narrows_and_loosening_continuity_is_wide() {
        let mut d = Decision::edit(&approval(1, 1)).unwrap();
        let v = d.view(NOW);
        assert!(!v.narrow_user_offered && !v.narrow_path_offered);
        d.next();
        assert_eq!(d.view(NOW).error, Some(DecisionError::NothingToChange));
        d.choose(Choice::PathUserContinuity(true));
        d.next();
        assert_eq!(d.view(NOW).stage, DecisionStage::WideConfirm);
        d.next();
        assert!(d
            .view(NOW)
            .review
            .contains(&ReviewLine::EditContinuity(false, true)));
        let Some(Mutation::Update(u)) = d.confirm(NOW) else {
            panic!("an update");
        };
        assert_eq!((u.continuity, u.expected_row_version), (Some(2), 7));

        let mut renew = Decision::edit(&ApprovalInfo {
            state: 2,
            ..approval(2, 2)
        })
        .unwrap();
        assert!(renew.view(NOW).narrow_user_offered);
        renew.choose(Choice::EditExpiry(1));
        renew.choose(Choice::NarrowUser(true));
        renew.next();
        let Some(Mutation::Update(u)) = renew.confirm(NOW) else {
            panic!("a renewal");
        };
        assert_eq!(u.expires_at, Some(NOW + 30 * 86_400));
        assert!(u.narrow_to_exact_user && !u.narrow_to_exact_path);
        assert!(Decision::edit(&ApprovalInfo {
            state: 3,
            ..approval(1, 1)
        })
        .is_none());
    }

    #[test]
    fn revoke_needs_the_typed_short_id() {
        let mut d = Decision::revoke(&approval(1, 1)).unwrap();
        d.type_text("A-0190F0AA");
        d.next();
        assert_eq!(d.view(NOW).error, Some(DecisionError::ShortIdMismatch));
        for _ in 0..10 {
            d.backspace();
        }
        d.type_text("a-0000beef");
        d.next();
        let Some(Mutation::Revoke(r)) = d.confirm(NOW) else {
            panic!("a revocation");
        };
        assert_eq!((r.reason_code, r.expected_row_version), (1, 7));
    }

    pub(crate) const HOST: &str = "11111111-2222-3333-4444-555555555555";

    /// Type the add dialog's facts (the hash one character short).
    pub(crate) fn typed_add(d: &mut Decision) {
        for (field, text) in [
            (DecisionField::Host, HOST.to_ascii_uppercase()),
            (
                DecisionField::Path,
                "/opt/tool/bin/tool\u{202e}gpj".to_string(),
            ),
            // Pasted with spaces and a line break, one character short.
            (
                DecisionField::Sha,
                format!("{} {}\n", "AB".repeat(24), "A".repeat(47)),
            ),
            (DecisionField::Uid, "1000".to_string()),
            (DecisionField::User, "alice".to_string()),
            (DecisionField::Version, "2.1.0".to_string()),
        ] {
            d.focus(field);
            d.type_text(&text);
        }
    }

    #[test]
    fn an_add_is_checked_states_its_outcome_and_asks_a_fresh_factor() {
        let mut d = Decision::register(true);
        let v = d.view(NOW);
        assert_eq!(
            (v.kind, v.stage),
            (DecisionKind::Register, DecisionStage::Form)
        );
        assert_eq!(v.focus, Some(DecisionField::Host));
        // The approval terms start at the same safe defaults as an approve.
        assert!(!v.auto_update && !v.any_user && !v.any_path && !v.path_user_continuity);
        assert_eq!(v.expiry, 0);
        d.tab(false);
        assert_eq!(d.view(NOW).focus, Some(DecisionField::Path));
        typed_add(&mut d);
        d.next();
        let v = d.view(NOW);
        assert_eq!(
            (v.stage, v.error),
            (DecisionStage::Form, Some(DecisionError::FieldsInvalid))
        );
        let r = v.register.unwrap();
        assert_eq!(r.invalid, vec![(DecisionField::Sha, RegisterError::Sha384)]);
        assert_eq!(v.focus, Some(DecisionField::Sha), "the first refused field");
        assert!(
            !r.path.contains('\u{202e}'),
            "typed text is shown inert too"
        );
        assert_eq!(r.sha.len(), 95, "spaces and line breaks were dropped");
        d.type_text("B");
        assert_eq!(d.view(NOW).register.unwrap().invalid, vec![]);
        d.next();
        assert_eq!(d.view(NOW).stage, DecisionStage::Review);
        let review = d.view(NOW).review;
        for line in [
            ReviewLine::Host(HOST.into()),
            ReviewLine::Platform("Linux"),
            ReviewLine::Sha(format!("{}{}b", "ab".repeat(24), "a".repeat(47))),
            ReviewLine::User("alice (1000)".into()),
            ReviewLine::Version("2.1.0".into()),
            ReviewLine::RegisterOutcome(true),
            ReviewLine::Assertion,
            ReviewLine::FreshFactor,
        ] {
            assert!(review.contains(&line), "{line:?} in {review:?}");
        }
        assert!(d.confirm(NOW).is_none(), "an add is not a step-up decision");
        let req = d.confirm_register(NOW).unwrap();
        assert!(req.proof.is_none(), "the fresh factor is added when sent");
        assert_ne!(req.idempotency_key, "");
        assert_eq!(req.host_uuid, HOST);
        let again = d.confirm_register(NOW).unwrap();
        assert_ne!(
            again.idempotency_key, req.idempotency_key,
            "a new add, a new key"
        );
        // Without `app_request.approve` only the strict-SoD queue is possible.
        let mut q = Decision::register(false);
        typed_add(&mut q);
        q.focus(DecisionField::Sha);
        q.type_text("b");
        q.next();
        assert!(q
            .view(NOW)
            .review
            .contains(&ReviewLine::RegisterOutcome(false)));
    }

    #[test]
    fn an_add_for_any_user_needs_the_asserted_protected_path_and_its_own_confirmation() {
        let mut d = Decision::register(true);
        typed_add(&mut d);
        d.focus(DecisionField::Sha);
        d.type_text("b");
        d.choose(Choice::AnyUser(true));
        d.choose(Choice::AutoUpdate(true));
        d.next();
        assert_eq!(
            d.view(NOW).error,
            Some(DecisionError::AnyUserNeedsProtectedPath)
        );
        d.choose(Choice::PathProtected(true));
        d.choose(Choice::Platform(9));
        d.next();
        assert_eq!(d.view(NOW).stage, DecisionStage::WideConfirm);
        assert!(d.confirm_register(NOW).is_none(), "not before the review");
        d.next();
        let v = d.view(NOW);
        assert!(v.review.contains(&ReviewLine::PathProtectedAsserted));
        assert!(
            v.review.contains(&ReviewLine::Platform("Windows")),
            "clamped"
        );
        let req = d.confirm_register(NOW).unwrap();
        let t = req.terms.unwrap();
        assert_eq!(
            (t.user_scope, t.confirm_any_user, t.update_policy),
            (2, true, 2)
        );
        assert_eq!(req.binary.unwrap().flags, RiskFlags::PATH_PROTECTED);
        // A Windows user needs its SID (or the RID).
        let mut w = Decision::register(true);
        typed_add(&mut w);
        w.choose(Choice::WindowsUser(true));
        w.focus(DecisionField::Uid);
        for _ in 0..4 {
            w.backspace();
        }
        w.focus(DecisionField::Sha);
        w.type_text("b");
        w.next();
        assert_eq!(
            w.view(NOW).register.unwrap().invalid,
            vec![(DecisionField::Sid, RegisterError::WindowsNeedsSid)]
        );
    }

    #[test]
    fn freeze_defaults_to_the_opposite_and_a_reask_names_the_changes() {
        let d = Decision::freeze("lin", "/opt/tool", Some(true));
        assert!(!d.view(NOW).frozen);
        let mut d = Decision::freeze("lin", "/opt/tool", None);
        d.next();
        assert!(matches!(d.confirm(NOW), Some(Mutation::Freeze(f)) if f.frozen));
        let old = approval(1, 1);
        let new = ApprovalInfo {
            note: "someone else".into(),
            row_version: 8,
            ..old.clone()
        };
        let d = Decision::reask_edit(&old, &new).unwrap();
        assert_eq!(
            d.view(NOW).changed_meanwhile,
            Some(vec![ApprovalChange::Note])
        );
        assert_eq!(d.edited().unwrap().row_version, 8);
    }
}
