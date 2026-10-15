//! The decision dialogs (F21 §6): approve, deny, edit, revoke, freeze and the
//! single-step "add application".
//!
//! Every dialog walks the same stages: the **form** (pre-filled with the safe
//! defaults), an extra **wide-scope confirmation** when the administrator
//! picked "Any user" or "Path + user only", then the **review** page that
//! summarises exactly what will be sent. Only `y` on the review page builds a
//! request, with a fresh `idempotency_key`; `Esc` cancels at any stage and
//! sends nothing. The server re-checks every rule; the client-side checks are
//! there so a mistake is explained before it costs a TOTP code.

use std::fmt::Write as _;

use ferro_appid::flags::RiskFlags;
use ferro_proto::admin_v1::{
    approve_app_request_request::Choice, AdminRegisterApplicationRequest, AppBinaryDesc,
    AppRequestInfo, AppUser, ApprovalInfo, ApprovalTerms, ApproveAppRequestRequest,
    DenyAppRequestRequest, GetAppRequestResponse, RevokeApprovalRequest,
    SetLineageAutoUpdateFrozenRequest, UpdateApprovalRequest,
};

use super::filters::warning_flags;
use super::form::{Field, Form, FormEvent};
use crate::client::Mutation;
use crate::input::Key;
use crate::timefmt::{self, DAY};

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
const REPLACED: usize = 3;

const POLICY_OPTIONS: [&str; 2] = [
    "Manual approval for every new binary",
    "Auto-approve updates (same path + same user)",
];
const CONTINUITY_OPTIONS: [&str; 2] = [
    "Anchored: protected path or same signer",
    "Path + user only ⚠",
];
const SCOPE_OPTIONS: [&str; 2] = ["This user only", "Any user ⚠"];
const PATH_OPTIONS: [&str; 2] = ["Exact path", "Any path"];
/// Expiry choices of a new approval: 0 days is the server default
/// (`CMIS_APPROVAL_DEFAULT_TTL_SECS`).
const EXPIRY_DAYS: [i64; 5] = [0, 30, 90, 180, 365];
const EXPIRY_OPTIONS: [&str; 5] = [
    "Server default",
    "30 days",
    "90 days",
    "180 days",
    "365 days",
];
/// Expiry choices of an edit: keep, a new date, or no expiry.
const EDIT_EXPIRY_OPTIONS: [&str; 6] = [
    "Keep",
    "30 days from now",
    "90 days from now",
    "180 days from now",
    "365 days from now",
    "No expiry (if the server allows it)",
];
const PLATFORMS: [&str; 3] = ["Linux", "macOS", "Windows"];
const USER_KINDS: [&str; 2] = ["Unix", "Windows"];

/// The short id an administrator types to confirm a revocation: `A-` and the
/// last eight characters of the approval id. The tail is used because the
/// head of a time-ordered UUIDv7 is the same for every approval created in the
/// same hours.
#[must_use]
pub fn short_id(prefix: &str, id: &str) -> String {
    let tail: Vec<char> = id.chars().filter(char::is_ascii_alphanumeric).collect();
    let start = tail.len().saturating_sub(8);
    let s: String = tail[start..].iter().collect();
    format!("{prefix}-{}", s.to_ascii_uppercase())
}

/// A display label for an operating-system user.
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

fn policy_name(code: u32) -> &'static str {
    if code == 2 {
        "auto-update (same path + same user)"
    } else {
        "manual each time"
    }
}

fn continuity_name(code: u32) -> &'static str {
    if code == 2 {
        "path + user only"
    } else {
        "anchored"
    }
}

fn scope_name(code: u32) -> &'static str {
    if code == 2 {
        "any user"
    } else {
        "this user only"
    }
}

fn path_name(code: u32) -> &'static str {
    if code == 2 {
        "any path"
    } else {
        "exact path"
    }
}

fn expiry_name(t: i64) -> String {
    if t == 0 {
        "no expiry".to_string()
    } else {
        timefmt::date(t)
    }
}

/// Which dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogKind {
    /// `ApproveAppRequest`.
    Approve,
    /// `DenyAppRequest`.
    Deny,
    /// `UpdateApproval`.
    Edit,
    /// `RevokeApproval`.
    Revoke,
    /// `SetLineageAutoUpdateFrozen`.
    Freeze,
    /// `AdminRegisterApplication`.
    Register,
}

/// Where a dialog is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Editing the fields.
    Form,
    /// The extra `y` for a wide scope.
    WideConfirm,
    /// The review page; `y` sends.
    Review,
}

/// What the dialog is about.
pub enum Ctx {
    /// A pending request.
    Approve {
        /// The request.
        request: Box<AppRequestInfo>,
        /// Active approvals of the lineage offered for "also revoke".
        also: Vec<ApprovalInfo>,
    },
    /// A pending request.
    Deny {
        /// The request.
        request: Box<AppRequestInfo>,
    },
    /// An approval.
    Edit {
        /// The approval as loaded.
        approval: Box<ApprovalInfo>,
    },
    /// An approval.
    Revoke {
        /// The approval as loaded.
        approval: Box<ApprovalInfo>,
    },
    /// A lineage.
    Freeze {
        /// Lineage id.
        lineage_id: String,
        /// What the lineage is (path).
        label: String,
    },
    /// A direct add.
    Register {
        /// The session holds `app_request.approve` (single step possible).
        can_approve: bool,
    },
}

/// What a key did to the dialog.
pub enum Outcome {
    /// Still open.
    Stay,
    /// Closed, nothing sent.
    Cancel,
    /// Send this mutation.
    Send(Box<Mutation>),
    /// Ask for a fresh TOTP code, then send this registration.
    Register(Box<AdminRegisterApplicationRequest>),
}

/// An open dialog.
pub struct Dialog {
    /// Which dialog.
    pub kind: DialogKind,
    /// Where it is.
    pub stage: Stage,
    /// Title (may contain server text; sanitised when drawn).
    pub title: String,
    /// The fields.
    pub form: Form,
    /// What it is about.
    pub ctx: Ctx,
    /// A notice above the fields (for example what changed concurrently).
    pub notice: Option<String>,
    /// Scroll offset of the review page.
    pub scroll: u16,
}

fn new_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The approval-terms fields shared by approve and add.
fn terms_fields(auto: bool) -> Vec<Field> {
    vec![
        Field::choice(
            "policy",
            "Update policy",
            &POLICY_OPTIONS,
            usize::from(auto),
        ),
        Field::choice("continuity", "Continuity", &CONTINUITY_OPTIONS, 0),
        Field::choice("scope", "User scope", &SCOPE_OPTIONS, 0),
        Field::choice("path", "Path match", &PATH_OPTIONS, 0),
        Field::choice("expires", "Expires", &EXPIRY_OPTIONS, 0),
        Field::text("note", "Note", "", 500).with_hint("≤ 500"),
    ]
}

/// The auto-update preselection rule (F21 §6 "Approve", step 1): only when
/// the request is on a protected path, or its binary has a valid signer equal
/// to the signer of the lineage's previous approved revision.
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
        // Active or expired approvals only: a revoked revision was withdrawn
        // and vouches for nothing.
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

impl Dialog {
    fn new(kind: DialogKind, title: String, form: Form, ctx: Ctx) -> Self {
        Self {
            kind,
            stage: Stage::Form,
            title,
            form,
            ctx,
            notice: None,
            scroll: 0,
        }
    }

    /// The approve dialog for a loaded request, with the safe defaults.
    #[must_use]
    pub fn approve(detail: &GetAppRequestResponse) -> Option<Self> {
        let request = detail.request.clone()?;
        let auto = auto_update_preselected(detail);
        let also: Vec<ApprovalInfo> = detail
            .lineage_approvals
            .iter()
            .filter(|a| a.state == 1)
            .cloned()
            .collect();
        let mut fields = terms_fields(auto);
        if !also.is_empty() {
            let labels = also
                .iter()
                .map(|a| {
                    format!(
                        "r{} {}{}",
                        a.revision,
                        short_id("A", &a.approval_id),
                        if a.superseded_by.is_empty() {
                            ""
                        } else {
                            " (superseded)"
                        }
                    )
                })
                .collect();
            fields.push(Field::multi_owned("also", "Also revoke", labels));
            fields.push(Field::choice(
                "revoke_reason",
                "Revoke reason",
                &REVOKE_REASONS,
                REPLACED,
            ));
        }
        let title = format!(
            "Approve {} · {} · {} · host {} · user {}",
            short_id("R", &request.request_id),
            request.canonical_path,
            request.display_version,
            short_host(&request.host_uuid),
            user_label(request.target_user.as_ref()),
        );
        Some(Self::new(
            DialogKind::Approve,
            title,
            Form::new(fields),
            Ctx::Approve {
                request: Box::new(request),
                also,
            },
        ))
    }

    /// The deny dialog for a request.
    #[must_use]
    pub fn deny(request: &AppRequestInfo) -> Self {
        let form = Form::new(vec![
            Field::choice("reason", "Reason", &DENY_REASONS, 0),
            Field::text("message", "Message to the requester", "", 200)
                .with_hint("≤ 200 · Do not include personal data"),
        ]);
        Self::new(
            DialogKind::Deny,
            format!(
                "Deny {} · {}",
                short_id("R", &request.request_id),
                request.canonical_path
            ),
            form,
            Ctx::Deny {
                request: Box::new(request.clone()),
            },
        )
    }

    /// The edit dialog for an approval: only narrowing is offered.
    #[must_use]
    pub fn edit(approval: &ApprovalInfo) -> Self {
        let mut fields = vec![
            Field::choice(
                "policy",
                "Update policy",
                &POLICY_OPTIONS,
                usize::from(approval.update_policy == 2),
            ),
            Field::choice(
                "continuity",
                "Continuity",
                &CONTINUITY_OPTIONS,
                usize::from(approval.continuity == 2),
            ),
            Field::choice("expires", "Expires", &EDIT_EXPIRY_OPTIONS, 0)
                .with_hint(&format!("now: {}", expiry_name(approval.expires_at))),
            Field::text("note", "Note", approval.note.trim(), 500).with_hint("≤ 500"),
        ];
        if approval.user_scope == 2 {
            fields.push(Field::toggle(
                "narrow_user",
                "Narrow to this user only",
                false,
            ));
        }
        if approval.path_match == 2 {
            fields.push(Field::toggle(
                "narrow_path",
                "Narrow to the exact path",
                false,
            ));
        }
        Self::new(
            DialogKind::Edit,
            format!(
                "Edit {} · {}",
                short_id("A", &approval.approval_id),
                approval.canonical_path
            ),
            Form::new(fields),
            Ctx::Edit {
                approval: Box::new(approval.clone()),
            },
        )
    }

    /// The revoke dialog: a reason and the typed short id.
    #[must_use]
    pub fn revoke(approval: &ApprovalInfo) -> Self {
        let sid = short_id("A", &approval.approval_id);
        let form = Form::new(vec![
            Field::choice("reason", "Reason", &REVOKE_REASONS, 0),
            Field::text("confirm", "Type the short id", "", 16).with_hint(&sid),
        ]);
        Self::new(
            DialogKind::Revoke,
            format!("Revoke {sid} · {}", approval.canonical_path),
            form,
            Ctx::Revoke {
                approval: Box::new(approval.clone()),
            },
        )
    }

    /// The freeze dialog for a lineage; `frozen` is the current state when
    /// known.
    #[must_use]
    pub fn freeze(lineage_id: &str, label: &str, frozen: Option<bool>) -> Self {
        let form = Form::new(vec![Field::choice(
            "action",
            "Auto-update",
            &["Freeze (every update goes to manual review)", "Unfreeze"],
            usize::from(frozen == Some(true)),
        )]);
        Self::new(
            DialogKind::Freeze,
            format!("Freeze or unfreeze lineage · {label}"),
            form,
            Ctx::Freeze {
                lineage_id: lineage_id.to_string(),
                label: label.to_string(),
            },
        )
    }

    /// The "add application" dialog (known hash and path).
    #[must_use]
    pub fn register(can_approve: bool) -> Self {
        let mut fields = vec![
            Field::text("host", "Host UUID", "", 36),
            Field::choice("platform", "Platform", &PLATFORMS, 0),
            Field::text("path", "Canonical path", "", 4096),
            Field::text("sha", "SHA-384", "", 96).with_hint("96 hex, typed or pasted"),
            Field::choice("user_kind", "User kind", &USER_KINDS, 0),
            Field::text("uid", "uid (or RID)", "", 10),
            Field::text("sid", "SID (Windows)", "", 184),
            Field::text("user", "User name", "", 256),
            Field::text("version", "Declared version", "", 128).with_hint("optional"),
            Field::text("reason", "Reason", "", 200).with_hint("optional, ≤ 200"),
            Field::toggle("protected", "Path writable only by administrators", false)
                .with_hint("your assertion"),
        ];
        fields.extend(terms_fields(false));
        Self::new(
            DialogKind::Register,
            "Add application by known hash and path".to_string(),
            Form::new(fields),
            Ctx::Register { can_approve },
        )
    }

    /// Risk-flag warnings of the request this dialog is about.
    #[must_use]
    pub fn warnings(&self) -> Vec<&'static str> {
        match &self.ctx {
            Ctx::Approve { request, .. } | Ctx::Deny { request } => warning_flags(request.flags),
            _ => Vec::new(),
        }
    }

    fn flags(&self) -> u32 {
        match &self.ctx {
            Ctx::Approve { request, .. } => request.flags,
            Ctx::Register { .. } if self.form.toggled("protected") => RiskFlags::PATH_PROTECTED,
            _ => 0,
        }
    }

    /// Whether the chosen terms need the extra wide-scope `y`.
    #[must_use]
    pub fn is_wide(&self) -> bool {
        match &self.ctx {
            Ctx::Approve { .. } | Ctx::Register { .. } => {
                self.form.choice("scope") == 1 || self.form.choice("continuity") == 1
            }
            // An edit can only narrow the user and path scope, but it can
            // loosen continuity: that needs the same extra `y`.
            Ctx::Edit { approval } => {
                self.form.choice("continuity") == 1 && approval.continuity != 2
            }
            _ => false,
        }
    }

    /// The warning shown on the wide-scope confirmation.
    #[must_use]
    pub fn wide_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.form.choice("scope") == 1 && self.kind != DialogKind::Edit {
            out.push(
                "⚠ Any user: every account on the host may run this binary, not only the requester."
                    .to_string(),
            );
        }
        if self.form.choice("continuity") == 1 {
            out.push(
                "⚠ Path + user only: an update is accepted from whoever can write that path, without a protected path or the same signer."
                    .to_string(),
            );
        }
        out.push("Press y to accept this wider scope, Backspace to go back, Esc to cancel.".into());
        out
    }

    fn validate(&mut self) -> bool {
        self.form.clear_errors();
        match self.kind {
            DialogKind::Approve | DialogKind::Register => {
                if self.kind == DialogKind::Register {
                    self.validate_register();
                }
                if self.form.choice("scope") == 1
                    && self.form.choice("policy") == 1
                    && self.flags() & RiskFlags::PATH_PROTECTED == 0
                {
                    self.form.set_error(
                        "scope",
                        "auto-update for any user needs a protected path (server rule)",
                    );
                }
            }
            DialogKind::Edit => {
                if self.edit_request(0, String::new()).is_none() {
                    self.form.set_error("policy", "nothing to change");
                }
            }
            DialogKind::Revoke => {
                if let Ctx::Revoke { approval } = &self.ctx {
                    let want = short_id("A", &approval.approval_id);
                    let typed = self.form.text("confirm").trim().to_string();
                    if !typed.eq_ignore_ascii_case(&want) {
                        self.form
                            .set_error("confirm", &format!("type {want} to confirm"));
                    }
                }
            }
            DialogKind::Deny | DialogKind::Freeze => {}
        }
        if self.form.has_errors() {
            self.form.focus_first_error();
            return false;
        }
        true
    }

    fn validate_register(&mut self) {
        let host = self.form.text("host").trim().to_string();
        if uuid::Uuid::parse_str(&host).is_err() {
            self.form.set_error("host", "a host UUID (8-4-4-4-12 hex)");
        }
        if self.form.text("path").trim().is_empty() {
            self.form.set_error("path", "required");
        }
        let sha = self.form.text("sha").trim().to_string();
        if sha.len() != 96 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            self.form
                .set_error("sha", "exactly 96 hex characters (SHA-384)");
        }
        let uid = self.form.text("uid").trim().to_string();
        if !uid.is_empty() && uid.parse::<u32>().is_err() {
            self.form.set_error("uid", "a number (0–4294967295)");
        }
        let sid = self.form.text("sid").trim().to_string();
        if !sid.bytes().all(|b| b.is_ascii_graphic()) {
            self.form.set_error("sid", "printable ASCII only");
        }
        let windows = self.form.choice("user_kind") == 1;
        if !windows && uid.is_empty() {
            self.form.set_error("uid", "required for a Unix user");
        }
        if windows && uid.is_empty() && sid.is_empty() {
            self.form
                .set_error("sid", "a Windows user needs a SID (or the RID)");
        }
        if self.form.text("user").trim().is_empty() {
            self.form.set_error("user", "required");
        }
    }

    /// Apply a key; `now` (Unix seconds) fixes expiry dates on `y`.
    pub fn on_key(&mut self, key: Key, now: i64) -> Outcome {
        if key == Key::Esc {
            return Outcome::Cancel;
        }
        match self.stage {
            Stage::Form => match self.form.handle(key) {
                FormEvent::Submit => {
                    if self.validate() {
                        self.scroll = 0;
                        self.stage = if self.is_wide() {
                            Stage::WideConfirm
                        } else {
                            Stage::Review
                        };
                    }
                    Outcome::Stay
                }
                FormEvent::Cancel => Outcome::Cancel,
                FormEvent::Edited | FormEvent::Ignored => Outcome::Stay,
            },
            Stage::WideConfirm => {
                match key {
                    Key::Char('y' | 'Y') => self.stage = Stage::Review,
                    Key::Backspace => self.stage = Stage::Form,
                    _ => {}
                }
                Outcome::Stay
            }
            Stage::Review => match key {
                Key::Char('y' | 'Y') => self.build(now),
                Key::Backspace => {
                    self.stage = Stage::Form;
                    Outcome::Stay
                }
                Key::Up | Key::Char('k') => {
                    self.scroll = self.scroll.saturating_sub(1);
                    Outcome::Stay
                }
                Key::Down | Key::Char('j') => {
                    self.scroll = self.scroll.saturating_add(1).min(200);
                    Outcome::Stay
                }
                _ => Outcome::Stay,
            },
        }
    }

    fn terms(&self, now: i64) -> ApprovalTerms {
        let days = EXPIRY_DAYS
            .get(self.form.choice("expires"))
            .copied()
            .unwrap_or(0);
        ApprovalTerms {
            user_scope: if self.form.choice("scope") == 1 { 2 } else { 1 },
            path_match: if self.form.choice("path") == 1 { 2 } else { 1 },
            update_policy: if self.form.choice("policy") == 1 {
                2
            } else {
                1
            },
            continuity: if self.form.choice("continuity") == 1 {
                2
            } else {
                1
            },
            expires_at: if days == 0 { 0 } else { now + days * DAY },
            no_expiry: false,
            note: self.form.text("note").trim().to_string(),
            // Only reachable after the extra `y` of the wide confirmation.
            confirm_any_user: self.form.choice("scope") == 1,
        }
    }

    fn also_revoke(&self) -> Vec<String> {
        match &self.ctx {
            Ctx::Approve { also, .. } => self
                .form
                .checked("also")
                .iter()
                .zip(also)
                .filter(|(on, _)| **on)
                .map(|(_, a)| a.approval_id.clone())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn edit_request(&self, now: i64, key: String) -> Option<UpdateApprovalRequest> {
        let Ctx::Edit { approval } = &self.ctx else {
            return None;
        };
        let policy = if self.form.choice("policy") == 1 {
            2
        } else {
            1
        };
        let continuity = if self.form.choice("continuity") == 1 {
            2
        } else {
            1
        };
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
        match self.form.choice("expires") {
            0 => {}
            5 => {
                req.clear_expiry = true;
                changed = true;
            }
            i => {
                let days = [30, 90, 180, 365].get(i - 1).copied().unwrap_or(30);
                req.expires_at = Some(now + days * DAY);
                changed = true;
            }
        }
        let note = self.form.text("note").trim().to_string();
        let current: String = approval.note.chars().filter(|c| !c.is_control()).collect();
        if note != current.trim() {
            if note.is_empty() {
                req.clear_note = true;
            } else {
                req.note = Some(note);
            }
            changed = true;
        }
        if self.form.toggled("narrow_user") {
            req.narrow_to_exact_user = true;
            changed = true;
        }
        if self.form.toggled("narrow_path") {
            req.narrow_to_exact_path = true;
            changed = true;
        }
        changed.then_some(req)
    }

    fn register_request(&self, now: i64, key: String) -> AdminRegisterApplicationRequest {
        let platform = u32::try_from(self.form.choice("platform") + 1).unwrap_or(1);
        let windows_user = self.form.choice("user_kind") == 1;
        let uid = self.form.text("uid").trim().parse::<i64>().ok();
        AdminRegisterApplicationRequest {
            idempotency_key: key,
            proof: None,
            host_uuid: self.form.text("host").trim().to_ascii_lowercase(),
            binary: Some(AppBinaryDesc {
                canonical_path: self.form.text("path").trim().to_string(),
                platform,
                sha384: self.form.text("sha").trim().to_ascii_lowercase(),
                size: 0,
                // elf, macho, pe by platform.
                format: platform,
                declared_version: self.form.text("version").trim().to_string(),
                flags: if self.form.toggled("protected") {
                    RiskFlags::PATH_PROTECTED
                } else {
                    0
                },
                ..AppBinaryDesc::default()
            }),
            target_user: Some(AppUser {
                kind: if windows_user { 2 } else { 1 },
                uid,
                sid: if windows_user {
                    self.form.text("sid").trim().to_string()
                } else {
                    String::new()
                },
                name: self.form.text("user").trim().to_string(),
            }),
            reason: self.form.text("reason").trim().to_string(),
            terms: Some(self.terms(now)),
        }
    }

    fn build(&self, now: i64) -> Outcome {
        let key = new_key();
        match &self.ctx {
            Ctx::Approve { request, .. } => {
                let also = self.also_revoke();
                let reason = if also.is_empty() {
                    0
                } else {
                    u32::try_from(self.form.choice("revoke_reason") + 1).unwrap_or(4)
                };
                Outcome::Send(Box::new(Mutation::Approve(ApproveAppRequestRequest {
                    idempotency_key: key,
                    request_id: request.request_id.clone(),
                    choice: Some(Choice::Terms(self.terms(now))),
                    also_revoke_approval_ids: also,
                    also_revoke_reason_code: reason,
                    proof: None,
                })))
            }
            Ctx::Deny { request } => {
                Outcome::Send(Box::new(Mutation::Deny(DenyAppRequestRequest {
                    idempotency_key: key,
                    request_id: request.request_id.clone(),
                    reason_code: u32::try_from(self.form.choice("reason") + 1).unwrap_or(6),
                    message: self.form.text("message").trim().to_string(),
                })))
            }
            Ctx::Edit { .. } => match self.edit_request(now, key) {
                Some(req) => Outcome::Send(Box::new(Mutation::Update(req))),
                None => Outcome::Stay,
            },
            Ctx::Revoke { approval } => {
                Outcome::Send(Box::new(Mutation::Revoke(RevokeApprovalRequest {
                    idempotency_key: key,
                    approval_id: approval.approval_id.clone(),
                    reason_code: u32::try_from(self.form.choice("reason") + 1).unwrap_or(5),
                    expected_row_version: approval.row_version,
                })))
            }
            Ctx::Freeze { lineage_id, .. } => Outcome::Send(Box::new(Mutation::Freeze(
                SetLineageAutoUpdateFrozenRequest {
                    idempotency_key: key,
                    lineage_id: lineage_id.clone(),
                    frozen: self.form.choice("action") == 0,
                },
            ))),
            Ctx::Register { .. } => Outcome::Register(Box::new(self.register_request(now, key))),
        }
    }

    fn terms_review(&self, now: i64, out: &mut Vec<String>) {
        let t = self.terms(now);
        out.push(format!("Update policy:  {}", policy_name(t.update_policy)));
        out.push(format!("Continuity:     {}", continuity_name(t.continuity)));
        out.push(format!("User scope:     {}", scope_name(t.user_scope)));
        out.push(format!("Path match:     {}", path_name(t.path_match)));
        let days = EXPIRY_DAYS
            .get(self.form.choice("expires"))
            .copied()
            .unwrap_or(0);
        out.push(if days == 0 {
            "Expires:        server default (CMIS_APPROVAL_DEFAULT_TTL_SECS)".to_string()
        } else {
            format!(
                "Expires:        {} ({days} days)",
                timefmt::date(t.expires_at)
            )
        });
        out.push(format!(
            "Note:           {}",
            if t.note.is_empty() { "(none)" } else { &t.note }
        ));
    }

    /// The review page: everything that will be sent, in plain words.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one section per dialog kind.
    pub fn review_lines(&self, now: i64) -> Vec<String> {
        let mut out = vec![self.title.clone(), String::new()];
        match &self.ctx {
            Ctx::Approve { request, also } => {
                out.push(format!("Path:           {}", request.canonical_path));
                out.push(format!("SHA-384:        {}", request.bin_sha));
                self.terms_review(now, &mut out);
                let ids = self.also_revoke();
                if ids.is_empty() {
                    out.push("Also revoke:    none".to_string());
                } else {
                    let names: Vec<String> = also
                        .iter()
                        .filter(|a| ids.contains(&a.approval_id))
                        .map(|a| short_id("A", &a.approval_id))
                        .collect();
                    out.push(format!(
                        "Also revoke:    {} (reason {})",
                        names.join(", "),
                        REVOKE_REASONS
                            .get(self.form.choice("revoke_reason"))
                            .unwrap_or(&"replaced")
                    ));
                }
                let w = self.warnings();
                if !w.is_empty() {
                    out.push(format!("Warnings:       ⚠ {}", w.join(" · ")));
                }
                out.push(String::new());
                out.push(
                    "y sends ApproveAppRequest. The host picks the approval up within 5 minutes."
                        .into(),
                );
            }
            Ctx::Deny { request } => {
                out.push(format!("Path:           {}", request.canonical_path));
                out.push(format!(
                    "Reason:         {}",
                    DENY_REASONS
                        .get(self.form.choice("reason"))
                        .unwrap_or(&"other")
                ));
                let m = self.form.text("message").trim().to_string();
                out.push(format!(
                    "Message:        {}",
                    if m.is_empty() { "(none)" } else { &m }
                ));
                out.push(String::new());
                out.push(
                    "y sends DenyAppRequest; the requester sees the reason and message.".into(),
                );
            }
            Ctx::Edit { approval } => {
                out.push(format!("Row version:    {}", approval.row_version));
                if let Some(req) = self.edit_request(now, String::new()) {
                    if let Some(p) = req.update_policy {
                        out.push(format!(
                            "Update policy:  {} → {}{}",
                            policy_name(approval.update_policy),
                            policy_name(p),
                            if p == 2 {
                                "  ⚠ later binaries at this path are approved without review"
                            } else {
                                ""
                            }
                        ));
                    }
                    if let Some(c) = req.continuity {
                        out.push(format!(
                            "Continuity:     {} → {}{}",
                            continuity_name(approval.continuity),
                            continuity_name(c),
                            if c == 2 {
                                "  ⚠ no protected path or same signer required"
                            } else {
                                ""
                            }
                        ));
                    }
                    if let Some(e) = req.expires_at {
                        out.push(format!(
                            "Expires:        {} → {}",
                            expiry_name(approval.expires_at),
                            timefmt::date(e)
                        ));
                    }
                    if req.clear_expiry {
                        out.push(format!(
                            "Expires:        {} → no expiry",
                            expiry_name(approval.expires_at)
                        ));
                    }
                    if let Some(n) = &req.note {
                        out.push(format!("Note:           → {n}"));
                    }
                    if req.clear_note {
                        out.push("Note:           → (removed)".to_string());
                    }
                    if req.narrow_to_exact_user {
                        out.push("User scope:     any user → this user only".to_string());
                    }
                    if req.narrow_to_exact_path {
                        out.push("Path match:     any path → exact path".to_string());
                    }
                }
                out.push(String::new());
                out.push("y sends UpdateApproval for this row version.".into());
            }
            Ctx::Revoke { approval } => {
                out.push(format!("Path:           {}", approval.canonical_path));
                out.push(format!(
                    "User:           {}",
                    user_label(approval.user.as_ref())
                ));
                out.push(format!(
                    "Reason:         {}",
                    REVOKE_REASONS
                        .get(self.form.choice("reason"))
                        .unwrap_or(&"other")
                ));
                out.push(String::new());
                out.push(
                    "The approval stays in history; the host loses access at its next sync (within 5 minutes)."
                        .into(),
                );
                out.push("y sends RevokeApproval.".into());
            }
            Ctx::Freeze { label, .. } => {
                let freeze = self.form.choice("action") == 0;
                out.push(format!("Lineage:        {label}"));
                out.push(if freeze {
                    "Freeze auto-updates: every update request in this lineage goes to manual review."
                        .to_string()
                } else {
                    "Unfreeze auto-updates: approvals with an auto-update policy apply again."
                        .to_string()
                });
                out.push(String::new());
                out.push("y sends SetLineageAutoUpdateFrozen.".into());
            }
            Ctx::Register { can_approve } => {
                let r = self.register_request(now, String::new());
                let b = r.binary.unwrap_or_default();
                out.push(format!("Host:           {}", r.host_uuid));
                out.push(format!(
                    "Platform:       {}",
                    PLATFORMS[self.form.choice("platform").min(2)]
                ));
                out.push(format!("Path:           {}", b.canonical_path));
                out.push(format!("SHA-384:        {}", b.sha384));
                out.push(format!(
                    "User:           {}",
                    user_label(r.target_user.as_ref())
                ));
                if !b.declared_version.is_empty() {
                    out.push(format!("Version:        {}", b.declared_version));
                }
                if b.flags & RiskFlags::PATH_PROTECTED != 0 {
                    out.push("Path protected: yes (your assertion)".to_string());
                }
                self.terms_review(now, &mut out);
                out.push(String::new());
                if *can_approve {
                    out.push(
                        "Outcome: this registers AND approves the application now (single step, the server default). It is recorded as approved by the same person who requested it (audited as AppApprovedBySameActor)."
                            .into(),
                    );
                    out.push(
                        "If the server enforces strict separation of duties (CMIS_ADMIN_STRICT_SOD), it instead queues a request for a different approver."
                            .into(),
                    );
                } else {
                    out.push(
                        "Outcome: you cannot approve, so this only queues a request for a different approver, and only when the server enforces strict separation of duties (CMIS_ADMIN_STRICT_SOD); otherwise the server refuses it and nothing is registered."
                            .into(),
                    );
                }
                out.push(
                    "The hash and path are YOUR ASSERTION: they are not checked against the host. The approval pins this exact hash and MIA re-hashes the binary at every mint, so a wrong hash grants nothing."
                        .into(),
                );
                out.push(
                    "y asks for a fresh TOTP code: every direct add needs one, even within the step-up window."
                        .into(),
                );
            }
        }
        out
    }
}

/// The first eight characters of a host UUID.
#[must_use]
pub fn short_host(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_proto::admin_v1::AppBinaryInfo;

    fn request(flags: u32, revision: u32) -> AppRequestInfo {
        AppRequestInfo {
            request_id: "0192a9f1-0000-7000-8000-00000000a1b2".into(),
            host_uuid: "11111111-2222-3333-4444-555555555555".into(),
            lineage_id: "lin".into(),
            canonical_path: "/usr/local/bin/backup-agent".into(),
            bin_sha: "ab".repeat(48),
            revision,
            state: 1,
            flags,
            display_version: format!("r{revision}"),
            target_user: Some(AppUser {
                kind: 1,
                uid: Some(993),
                sid: String::new(),
                name: "backup".into(),
            }),
            ..AppRequestInfo::default()
        }
    }

    fn binary(sha: &str, signer: &str, valid: bool) -> AppBinaryInfo {
        AppBinaryInfo {
            bin_sha: sha.into(),
            signer_kind: u32::from(!signer.is_empty()),
            signer_id: signer.into(),
            signer_valid: valid,
            ..AppBinaryInfo::default()
        }
    }

    fn detail(flags: u32, signer_now: &str, signer_before: &str) -> GetAppRequestResponse {
        let prev = ApprovalInfo {
            approval_id: "0191c2aa-0000-7000-8000-0000000000c3".into(),
            bin_sha: "cd".repeat(48),
            revision: 3,
            state: 1,
            ..ApprovalInfo::default()
        };
        GetAppRequestResponse {
            request: Some(request(flags, 4)),
            binary: Some(binary(&"ab".repeat(48), signer_now, true)),
            lineage_binaries: vec![
                binary(&"cd".repeat(48), signer_before, true),
                binary(&"ab".repeat(48), signer_now, true),
            ],
            lineage_approvals: vec![prev],
            ..GetAppRequestResponse::default()
        }
    }

    fn sent(o: Outcome) -> Mutation {
        match o {
            Outcome::Send(m) => *m,
            _ => panic!("expected a request to send"),
        }
    }

    fn type_into(d: &mut Dialog, key: &str, text: &str) {
        d.form.focus_on(key);
        d.form.paste(text);
    }

    #[test]
    fn auto_update_is_preselected_only_per_the_spec_rule() {
        // Unsigned, unprotected: manual.
        let d = detail(RiskFlags::UNSIGNED, "", "");
        assert!(!auto_update_preselected(&d));
        assert_eq!(Dialog::approve(&d).unwrap().form.choice("policy"), 0);
        // Protected path: auto.
        let d = detail(RiskFlags::PATH_PROTECTED, "", "");
        assert!(auto_update_preselected(&d));
        assert_eq!(Dialog::approve(&d).unwrap().form.choice("policy"), 1);
        // Same valid signer as the previous approved revision: auto.
        let d = detail(0, "TEAMID1", "TEAMID1");
        assert!(auto_update_preselected(&d));
        // A different signer, or the signer-changed flag: manual.
        assert!(!auto_update_preselected(&detail(0, "TEAMID1", "OTHER")));
        assert!(!auto_update_preselected(&detail(
            RiskFlags::SIGNER_CHANGED,
            "TEAMID1",
            "TEAMID1"
        )));
    }

    #[test]
    fn the_approve_dialog_starts_with_the_safe_defaults() {
        let d = Dialog::approve(&detail(RiskFlags::UNSIGNED, "", "")).unwrap();
        assert_eq!(d.stage, Stage::Form);
        for key in ["policy", "continuity", "scope", "path", "expires"] {
            assert_eq!(d.form.choice(key), 0, "{key}");
        }
        assert_eq!(
            d.form.checked("also"),
            vec![false],
            "nothing revoked by default"
        );
        assert_eq!(d.warnings(), vec!["unsigned"]);
        assert!(d.title.contains("/usr/local/bin/backup-agent"));
        assert!(d.title.contains("backup (993)"));
    }

    #[test]
    fn wide_scope_needs_the_extra_y_and_the_review_sends_once() {
        let mut d = Dialog::approve(&detail(RiskFlags::PATH_PROTECTED, "", "")).unwrap();
        d.form.focus_on("scope");
        d.form.handle(Key::Char(' '));
        assert!(matches!(d.on_key(Key::Enter, 1000), Outcome::Stay));
        assert_eq!(d.stage, Stage::WideConfirm);
        assert!(d.wide_lines()[0].contains("Any user"));
        assert!(matches!(d.on_key(Key::Enter, 1000), Outcome::Stay));
        assert_eq!(d.stage, Stage::WideConfirm, "Enter is not y");
        assert!(matches!(d.on_key(Key::Char('y'), 1000), Outcome::Stay));
        assert_eq!(d.stage, Stage::Review);
        let review = d.review_lines(1000).join("\n");
        assert!(review.contains("User scope:     any user"), "{review}");
        assert!(review.contains("server default"), "{review}");
        assert!(review.contains("Also revoke:    none"), "{review}");
        let Mutation::Approve(req) = sent(d.on_key(Key::Char('y'), 1000)) else {
            panic!("y on the review page sends");
        };
        assert_ne!(req.idempotency_key, "");
        let Some(Choice::Terms(t)) = req.choice else {
            panic!("terms")
        };
        assert_eq!((t.user_scope, t.confirm_any_user), (2, true));
        assert_eq!(t.update_policy, 2, "auto preselected on a protected path");
        assert_eq!(t.expires_at, 0, "server default");
    }

    #[test]
    fn any_user_auto_update_on_an_unprotected_path_is_flagged_inline() {
        let mut d = Dialog::approve(&detail(0, "", "")).unwrap();
        d.form.set_choice("policy", 1);
        d.form.set_choice("scope", 1);
        assert!(matches!(d.on_key(Key::Enter, 1), Outcome::Stay));
        assert_eq!(d.stage, Stage::Form);
        assert!(d.form.field("scope").unwrap().error.is_some());
        // Esc sends nothing.
        assert!(matches!(d.on_key(Key::Esc, 1), Outcome::Cancel));
    }

    #[test]
    fn approve_can_also_revoke_older_revisions_with_a_reason() {
        let mut d = Dialog::approve(&detail(0, "", "")).unwrap();
        d.form.set_choice("expires", 3);
        d.form.focus_on("also");
        d.form.handle(Key::Char(' '));
        d.on_key(Key::Enter, 1_000_000);
        assert_eq!(d.stage, Stage::Review);
        let review = d.review_lines(1_000_000).join("\n");
        assert!(
            review.contains("Also revoke:    A-000000C3 (reason replaced)"),
            "{review}"
        );
        assert!(review.contains("(180 days)"), "{review}");
        let Mutation::Approve(req) = sent(d.on_key(Key::Char('y'), 1_000_000)) else {
            panic!()
        };
        assert_eq!(req.also_revoke_approval_ids.len(), 1);
        assert_eq!(req.also_revoke_reason_code, 4);
        let Some(Choice::Terms(t)) = req.choice else {
            panic!()
        };
        assert_eq!(t.expires_at, 1_000_000 + 180 * DAY);
    }

    #[test]
    fn deny_sends_a_reason_code_and_the_message() {
        let mut d = Dialog::deny(&request(0, 1));
        d.form.set_choice("reason", 4);
        type_into(&mut d, "message", "not approved software");
        d.on_key(Key::Enter, 0);
        let review = d.review_lines(0).join("\n");
        assert!(review.contains("security_risk"));
        let Mutation::Deny(r) = sent(d.on_key(Key::Char('y'), 0)) else {
            panic!()
        };
        assert_eq!(
            (r.reason_code, r.message.as_str()),
            (5, "not approved software")
        );
    }

    fn approval(scope: u32, path: u32) -> ApprovalInfo {
        ApprovalInfo {
            approval_id: "0191c2aa-0000-7000-8000-00000000beef".into(),
            canonical_path: "/opt/tool".into(),
            user_scope: scope,
            path_match: path,
            update_policy: 1,
            continuity: 1,
            expires_at: 2_000_000,
            note: "old".into(),
            row_version: 7,
            lineage_id: "lin".into(),
            state: 1,
            ..ApprovalInfo::default()
        }
    }

    #[test]
    fn edit_only_narrows_and_sends_the_row_version() {
        let d = Dialog::edit(&approval(1, 1));
        assert!(d.form.field("narrow_user").is_none(), "no widening offered");
        assert!(d.form.field("narrow_path").is_none());
        let mut d = Dialog::edit(&approval(2, 2));
        d.on_key(Key::Enter, 0);
        assert_eq!(d.stage, Stage::Form, "nothing to change");
        d.form.focus_on("narrow_user");
        d.form.handle(Key::Char(' '));
        d.form.set_choice("expires", 2);
        d.form.focus_on("note");
        d.form.handle(Key::Backspace);
        d.form.handle(Key::Backspace);
        d.form.handle(Key::Backspace);
        d.on_key(Key::Enter, 100);
        let review = d.review_lines(100).join("\n");
        assert!(review.contains("any user → this user only"), "{review}");
        assert!(review.contains("(removed)"), "{review}");
        let Mutation::Update(r) = sent(d.on_key(Key::Char('y'), 100)) else {
            panic!()
        };
        assert_eq!(r.expected_row_version, 7);
        assert!(r.narrow_to_exact_user && !r.narrow_to_exact_path);
        assert!(r.clear_note);
        assert_eq!(r.expires_at, Some(100 + 90 * DAY));
        assert_eq!(r.update_policy, None, "unchanged fields stay unset");
    }

    #[test]
    fn loosening_continuity_in_an_edit_needs_the_extra_y_and_is_flagged() {
        let mut d = Dialog::edit(&approval(1, 1));
        d.form.set_choice("continuity", 1);
        d.form.set_choice("policy", 1);
        d.on_key(Key::Enter, 0);
        assert_eq!(d.stage, Stage::WideConfirm);
        let wide = d.wide_lines().join(" ");
        assert!(wide.contains("Path + user only"), "{wide}");
        assert!(!wide.contains("Any user"), "{wide}");
        d.on_key(Key::Char('y'), 0);
        assert_eq!(d.stage, Stage::Review);
        let review = d.review_lines(0).join("\n");
        assert!(
            review.contains("⚠ no protected path or same signer required"),
            "{review}"
        );
        assert!(review.contains("⚠ later binaries"), "{review}");
        // A note with control characters or padding is not "changed" by an
        // unrelated edit.
        let mut a = approval(1, 1);
        a.note = "  keep\u{7}me ".into();
        let mut d = Dialog::edit(&a);
        d.form.set_choice("policy", 1);
        d.on_key(Key::Enter, 0);
        let Mutation::Update(r) = sent(d.on_key(Key::Char('y'), 0)) else {
            panic!()
        };
        assert_eq!((r.note, r.clear_note), (None, false));
    }

    #[test]
    fn a_revoked_previous_revision_does_not_preselect_auto_update() {
        let mut d = detail(0, "TEAMID1", "TEAMID1");
        d.lineage_approvals[0].state = 3;
        assert!(!auto_update_preselected(&d));
    }

    #[test]
    fn revoke_needs_the_typed_short_id() {
        let a = approval(1, 1);
        assert_eq!(short_id("A", &a.approval_id), "A-0000BEEF");
        let mut d = Dialog::revoke(&a);
        type_into(&mut d, "confirm", "A-0000BEEX");
        d.on_key(Key::Enter, 0);
        assert_eq!(d.stage, Stage::Form);
        assert!(d.form.field("confirm").unwrap().error.is_some());
        d.form.focus_on("confirm");
        d.form.handle(Key::Backspace);
        d.form.paste("f");
        d.on_key(Key::Enter, 0);
        assert_eq!(d.stage, Stage::Review, "case-insensitive match");
        assert!(d.review_lines(0).join(" ").contains("stays in history"));
        let Mutation::Revoke(r) = sent(d.on_key(Key::Char('y'), 0)) else {
            panic!()
        };
        assert_eq!((r.reason_code, r.expected_row_version), (1, 7));
    }

    #[test]
    fn freeze_defaults_to_the_opposite_of_the_current_state() {
        let mut d = Dialog::freeze("lin", "/opt/tool", Some(true));
        assert_eq!(d.form.choice("action"), 1);
        d.on_key(Key::Enter, 0);
        let Mutation::Freeze(r) = sent(d.on_key(Key::Char('y'), 0)) else {
            panic!()
        };
        assert!(!r.frozen);
    }

    #[test]
    fn the_add_dialog_validates_the_hash_and_states_the_outcome() {
        let mut d = Dialog::register(true);
        type_into(&mut d, "host", "11111111-2222-3333-4444-555555555555");
        type_into(&mut d, "path", "/opt/tool/bin/tool");
        type_into(&mut d, "sha", &"A".repeat(95));
        type_into(&mut d, "uid", "1000");
        type_into(&mut d, "user", "alice");
        d.on_key(Key::Enter, 0);
        assert_eq!(d.stage, Stage::Form);
        assert!(
            d.form.field("sha").unwrap().error.is_some(),
            "95 hex refused"
        );
        type_into(&mut d, "sha", "B");
        d.on_key(Key::Enter, 0);
        assert_eq!(d.stage, Stage::Review);
        let review = d.review_lines(0).join("\n");
        assert!(review.contains("registers AND approves"), "{review}");
        assert!(review.contains("CMIS_ADMIN_STRICT_SOD"), "{review}");
        assert!(review.contains("YOUR ASSERTION"), "{review}");
        assert!(review.contains("fresh TOTP"), "{review}");
        let Outcome::Register(r) = d.on_key(Key::Char('y'), 0) else {
            panic!()
        };
        let b = r.binary.unwrap();
        assert_eq!(b.sha384, format!("{}b", "a".repeat(95)), "lowercased");
        assert!(r.proof.is_none(), "the proof is added with the fresh code");
        assert_eq!(r.target_user.unwrap().uid, Some(1000));

        let d = Dialog::register(false);
        let review = d.review_lines(0).join(" ");
        assert!(review.contains("you cannot approve"), "{review}");
        assert!(
            review.contains("otherwise the server refuses it"),
            "{review}"
        );
    }
}
