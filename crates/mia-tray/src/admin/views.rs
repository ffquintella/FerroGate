//! Requests and Approvals (F22 §4, F21 §3–§6), headless: the two lists with
//! search, filters and paging, the request and approval details, and the
//! decision dialog ([`super::decide`]). Calls go in as [`ViewAction`]s and
//! worker replies through the `on_*` methods; out come worker commands.

//! A decision waits in [`AdminViews`] for its outcome: a `step_up_required`
//! answer asks the flow for a step-up, after which the same request (same
//! idempotency key) is sent once more; an `ABORTED` edit reloads the
//! approval, shows what changed and asks again. "Add application" (T284)
//! hands its confirmed request to the flow, which always asks a fresh
//! second factor for it.

//! Every server string in [`ViewsView`] is made inert; failures are shown
//! by kind only (the reason goes to the log). The views hold no secret.

use ferrogate_admin_client::approvals::filters::{
    max_chars, warning_flags, ApprovalFilters, RequestFilters, RiskFlags, APPROVAL_ORIGINS,
    APPROVAL_STATES, POLICIES, PRESETS, REQUEST_KINDS, REQUEST_ORIGINS, REQUEST_STATES,
};
use ferrogate_admin_client::approvals::proto::{
    AppRequestInfo, ApprovalInfo, GetAppRequestResponse, GetApprovalResponse,
    ListAppRequestsResponse, ListApprovalsResponse,
};
use ferrogate_admin_client::approvals::register::{
    self, AdminRegisterApplicationRequest, AdminRegisterApplicationResponse, Registered,
};
use ferrogate_admin_client::approvals::rules::{short_host, short_id, user_label};
use ferrogate_admin_client::approvals::{Mutated, Mutation};
use ferrogate_admin_client::display::inert;
use ferrogate_admin_client::error::{ClientError, Code};
use ferrogate_admin_client::perm;
use serde::Serialize;

use super::decide::{Choice, Decision, DecisionField, DecisionKind, DecisionView};
use super::session::Cmd;

/// Most rows kept from one page (the server's page maximum).
pub const MAX_ROWS: usize = 200;
/// Most lineage approvals shown on a request.
pub const MAX_LINEAGE: usize = 20;
/// Longest server string shown in a list or a detail, in characters (a
/// note is at most 500).
pub const MAX_SHOWN: usize = 600;
/// Longest path shown, in characters: a path is shown whole, so its end
/// (the binary's name) is never cut off.
pub const MAX_PATH: usize = 4096;

/// Which list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tab {
    /// Registration requests.
    Requests,
    /// Approvals.
    Approvals,
}

/// What the panel shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Screen {
    /// The list of the tab.
    List,
    /// One request.
    Request,
    /// One approval.
    Approval,
}

/// A typed field of the filter panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterField {
    /// Free text.
    Text,
    /// Path contains.
    Path,
    /// Product contains.
    Product,
    /// Declared version (requests).
    Version,
    /// Host UUID.
    Host,
    /// User name.
    User,
    /// Hash prefix.
    Sha,
    /// Submitted from / expires after (`YYYY-MM-DD`).
    From,
    /// Submitted to / expires before (`YYYY-MM-DD`).
    To,
    /// Lineage id (approvals).
    Lineage,
}

impl FilterField {
    /// The shared filters' key of this field on `tab`.
    #[must_use]
    pub fn key(self, tab: Tab) -> &'static str {
        match (self, tab) {
            (Self::Text, _) => "text",
            (Self::Path, _) => "path",
            (Self::Product, _) => "product",
            (Self::Version, _) => "version",
            (Self::Host, _) => "host",
            (Self::User, _) => "user",
            (Self::Sha, _) => "sha",
            (Self::From, Tab::Requests) => "from",
            (Self::From, Tab::Approvals) => "after",
            (Self::To, Tab::Requests) => "to",
            (Self::To, Tab::Approvals) => "before",
            (Self::Lineage, _) => "lineage",
        }
    }

    /// The typed fields of `tab`'s panel, in `Tab` order.
    #[must_use]
    pub fn of(tab: Tab) -> &'static [Self] {
        match tab {
            Tab::Requests => &[
                Self::Text,
                Self::Path,
                Self::Product,
                Self::Version,
                Self::Host,
                Self::User,
                Self::Sha,
                Self::From,
                Self::To,
            ],
            Tab::Approvals => &[
                Self::Text,
                Self::Path,
                Self::Product,
                Self::Host,
                Self::User,
                Self::Sha,
                Self::From,
                Self::To,
                Self::Lineage,
            ],
        }
    }
}

/// A choice on the filter panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterChoice {
    /// The state at this index (wire order).
    State(usize, bool),
    /// The origin at this index (wire order).
    Origin(usize, bool),
    /// The request kind (0 any).
    Kind(usize),
    /// The approval policy at this index (wire order).
    Policy(usize, bool),
    /// The approval preset.
    Preset(usize),
    /// Include superseded approvals.
    Superseded(bool),
    /// Oldest first.
    Ascending(bool),
}

/// Something the administrator did on the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewAction {
    /// Show this list.
    Tab(Tab),
    /// Reload what is shown.
    Refresh,
    /// The next page.
    NextPage,
    /// The previous page.
    PrevPage,
    /// Open the filter panel.
    OpenFilters,
    /// Apply the filter panel.
    ApplyFilters,
    /// Back to the default filters.
    ResetFilters,
    /// Close the filter panel unapplied.
    CloseFilters,
    /// A choice on the filter panel.
    Filter(FilterChoice),
    /// Focus a typed filter field.
    FocusFilter(FilterField),
    /// Open the request at this row.
    OpenRequest(usize),
    /// Open the approval at this row.
    OpenApproval(usize),
    /// Open the lineage approval at this index of the request shown.
    OpenLineageApproval(usize),
    /// The approvals of the request's lineage.
    LineageApprovals,
    /// Back to the list.
    Back,
    /// Open a decision dialog on what is shown.
    Decide(DecisionKind),
    /// A choice in the dialog.
    Choose(Choice),
    /// Focus a typed dialog field.
    FocusDecision(DecisionField),
    /// An application chosen on this machine fills the add dialog.
    FillLocalApp(super::local::LocalApp),
    /// The application chosen on this machine could not be read.
    LocalAppFailed,
    /// "Continue" / "Accept".
    DecisionNext,
    /// "Back" to the dialog's form.
    DecisionBack,
    /// "Confirm" on the review page.
    DecisionConfirm,
    /// Close the dialog; nothing is sent.
    CancelDecision,
    /// Dismiss the outcome message.
    DismissOutcome,
}

/// Why something was refused, by kind only (the reason is logged).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// The account's groups do not grant it.
    NotAllowed,
    /// The server found a value invalid.
    Invalid,
    /// Not possible in the record's current state.
    NotPossibleNow,
    /// Changed concurrently.
    ChangedConcurrently,
    /// Not found.
    NotFound,
    /// The server could not be reached or did not answer in time.
    Unreachable,
    /// Another server error.
    ServerError,
}

fn refusal(e: &ClientError) -> Refusal {
    match e {
        ClientError::Connect(_) => Refusal::Unreachable,
        ClientError::Other(r) => match r.code {
            Code::PermissionDenied => Refusal::NotAllowed,
            Code::InvalidArgument | Code::OutOfRange => Refusal::Invalid,
            Code::FailedPrecondition => Refusal::NotPossibleNow,
            Code::Aborted => Refusal::ChangedConcurrently,
            Code::NotFound => Refusal::NotFound,
            Code::Unavailable | Code::DeadlineExceeded => Refusal::Unreachable,
            _ => Refusal::ServerError,
        },
        _ => Refusal::ServerError,
    }
}

/// The outcome of the last decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Approved: the new approval's short id, the host generation, what was
    /// revoked with it, and whether it was approved by its own requester.
    Approved {
        /// Short id of the approval.
        approval: String,
        /// Allowlist generation of the host.
        generation: u64,
        /// Short ids revoked with it.
        revoked: Vec<String>,
        /// Audited as approved by the same person who requested it.
        same_actor: bool,
    },
    /// Denied.
    Denied,
    /// Updated (or renewed), at this host generation.
    Updated(u64),
    /// Revoked, at this host generation.
    Revoked(u64),
    /// Frozen (true) or unfrozen.
    Frozen(bool),
    /// Refused by the server; nothing changed.
    Refused(Refusal),
    /// The server asked for a step-up again right after one; nothing more
    /// was sent.
    StepUpAgain,
    /// The step-up was cancelled; nothing more was sent.
    NotSent,
    /// The approval was revoked by someone else meanwhile.
    RevokedMeanwhile,
    /// An application was added (registered and approved, queued, or
    /// already covered).
    Added(Registered),
}

/// A request row (inert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestRow {
    /// `R-…`.
    pub short_id: String,
    /// 1 pending … 5 expired.
    pub state: u32,
    /// Origin code.
    pub origin: u32,
    /// Canonical path.
    pub path: String,
    /// Display version.
    pub version: String,
    /// Host, shortened.
    pub host: String,
    /// Target user.
    pub user: String,
    /// Submitted (Unix seconds).
    pub submitted_at: i64,
    /// Number of risk warnings.
    pub warnings: usize,
}

/// An approval row (inert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalRow {
    /// `A-…`.
    pub short_id: String,
    /// 1 active, 2 expired, 3 revoked.
    pub state: u32,
    /// Canonical path.
    pub path: String,
    /// Revision.
    pub revision: u32,
    /// Host, shortened.
    pub host: String,
    /// User (or "any user").
    pub user: String,
    /// Any user.
    pub any_user: bool,
    /// Auto-update policy.
    pub auto_update: bool,
    /// Expiry (Unix seconds; 0 none).
    pub expires_at: i64,
    /// Superseded by a newer revision.
    pub superseded: bool,
}

/// One request in full (inert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model.
pub struct RequestDetail {
    /// The row fields.
    pub row: RequestRow,
    /// 1 register, 2 update.
    pub kind: u32,
    /// SHA-384.
    pub sha: String,
    /// Product name.
    pub product: String,
    /// The requester's own reason.
    pub reason: String,
    /// The requesting OS user.
    pub requester: String,
    /// Pending until (Unix seconds).
    pub pending_expires_at: i64,
    /// Decided (Unix seconds; 0 not yet).
    pub decided_at: i64,
    /// Decision reason code.
    pub decision_reason_code: u32,
    /// Message given with a denial.
    pub decision_message: String,
    /// Risk-flag warnings.
    pub warnings: Vec<&'static str>,
    /// The path is writable only by administrators.
    pub path_protected: bool,
    /// The binary's signer (empty when unsigned).
    pub signer: String,
    /// The signature is valid.
    pub signer_valid: bool,
    /// Auto-updates of the lineage are frozen.
    pub lineage_frozen: bool,
    /// Approved by its own requester.
    pub same_actor: bool,
    /// Approvals of the lineage.
    pub lineage: Vec<ApprovalRow>,
}

/// One approval in full (inert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model.
pub struct ApprovalDetail {
    /// The row fields.
    pub row: ApprovalRow,
    /// SHA-384 (`*` for a legacy import).
    pub sha: String,
    /// Product name.
    pub product: String,
    /// Any path.
    pub any_path: bool,
    /// "Path + user only" continuity.
    pub path_user_continuity: bool,
    /// Origin code.
    pub origin: u32,
    /// Created (Unix seconds).
    pub created_at: i64,
    /// Revoked (Unix seconds; 0 not).
    pub revoked_at: i64,
    /// Revoke reason code.
    pub revoke_reason_code: u32,
    /// The note.
    pub note: String,
    /// Row version (optimistic concurrency).
    pub row_version: u64,
    /// Revisions of its terms recorded.
    pub revisions: usize,
}

/// The filter panel (inert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FiltersView {
    /// States checked.
    pub states: Vec<bool>,
    /// Origins checked.
    pub origins: Vec<bool>,
    /// Request kind.
    pub kind: usize,
    /// Approval policies checked.
    pub policies: Vec<bool>,
    /// Approval preset.
    pub preset: usize,
    /// Include superseded approvals.
    pub superseded: bool,
    /// Oldest first.
    pub ascending: bool,
    /// The typed fields and their values (inert).
    pub fields: Vec<(FilterField, String)>,
    /// The focused field.
    pub focus: Option<FilterField>,
    /// Fields whose value would be refused.
    pub invalid: Vec<FilterField>,
}

/// What the window draws. Holds no secret; server strings are inert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model: one flag per control.
pub struct ViewsView {
    /// The list shown.
    pub tab: Tab,
    /// List or detail.
    pub screen: Screen,
    /// Requests of the page.
    pub requests: Vec<RequestRow>,
    /// Approvals of the page.
    pub approvals: Vec<ApprovalRow>,
    /// Whether the list arrived.
    pub loaded: bool,
    /// The page number (from 1).
    pub page: usize,
    /// A further page exists.
    pub has_next: bool,
    /// The filters in one line (inert).
    pub summary: String,
    /// The filter panel, when open.
    pub filters: Option<FiltersView>,
    /// The request shown.
    pub request: Option<RequestDetail>,
    /// The approval shown.
    pub approval: Option<ApprovalDetail>,
    /// The decision dialog, when open.
    pub decision: Option<DecisionView>,
    /// The last decision's outcome.
    pub outcome: Option<Outcome>,
    /// Why the last read failed.
    pub error: Option<Refusal>,
    /// A decision waits for its outcome (or for a step-up).
    pub pending: bool,
    /// May approve.
    pub can_approve: bool,
    /// May deny.
    pub can_deny: bool,
    /// May edit approvals and freeze lineages.
    pub can_update: bool,
    /// May revoke.
    pub can_revoke: bool,
    /// May add an application directly (`app.direct_register`).
    pub can_register: bool,
}

/// What the flow must do after a reply.
pub enum ViewsEvent {
    /// Nothing.
    None,
    /// Send this command to the worker.
    Send(Cmd),
    /// The decision needs a step-up first; then [`AdminViews::resend`].
    StepUp,
    /// The server ended the session.
    SessionEnded,
}

static_assertions::assert_not_impl_any!(ViewsEvent: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(AdminViews: std::fmt::Debug, std::fmt::Display, Clone);

struct List<T> {
    items: Vec<T>,
    next_token: String,
    /// The tokens of the pages before this one.
    back: Vec<String>,
    token: String,
    loaded: bool,
}

impl<T> List<T> {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            next_token: String::new(),
            back: Vec::new(),
            token: String::new(),
            loaded: false,
        }
    }

    fn first_page(&mut self) {
        self.back.clear();
        self.token.clear();
        self.next_token.clear();
    }
}

struct FilterDraft {
    requests: RequestFilters,
    approvals: ApprovalFilters,
    focus: Option<FilterField>,
    invalid: Vec<FilterField>,
}

struct Pending {
    mutation: Mutation,
    stepped_up: bool,
    /// The approval an edit was based on.
    edit_base: Option<Box<ApprovalInfo>>,
}

/// The panel's state.
pub struct AdminViews {
    tab: Tab,
    screen: Screen,
    permissions: Option<Vec<String>>,
    request_filters: RequestFilters,
    approval_filters: ApprovalFilters,
    ascending: bool,
    draft: Option<FilterDraft>,
    requests: List<AppRequestInfo>,
    approvals: List<ApprovalInfo>,
    request: Option<Box<GetAppRequestResponse>>,
    approval: Option<Box<GetApprovalResponse>>,
    decision: Option<Decision>,
    outcome: Option<Outcome>,
    error: Option<Refusal>,
    /// The edit to re-ask when the approval arrives (after `ABORTED`), and
    /// the approval it was based on.
    reask: Option<Box<ApprovalInfo>>,
    pending: Option<Pending>,
    /// A confirmed add waits for its fresh second factor or its outcome.
    registering: bool,
}

fn shown(text: &str) -> String {
    inert(text, MAX_SHOWN)
}

fn shown_path(path: &str) -> String {
    inert(path, MAX_PATH)
}

fn request_row(r: &AppRequestInfo) -> RequestRow {
    RequestRow {
        short_id: short_id("R", &r.request_id),
        state: r.state,
        origin: r.origin,
        path: shown_path(&r.canonical_path),
        version: shown(&r.display_version),
        host: shown(&short_host(&r.host_uuid)),
        user: shown(&user_label(r.target_user.as_ref())),
        submitted_at: r.submitted_at,
        warnings: warning_flags(r.flags).len(),
    }
}

fn approval_row(a: &ApprovalInfo) -> ApprovalRow {
    ApprovalRow {
        short_id: short_id("A", &a.approval_id),
        state: a.state,
        path: shown_path(&a.canonical_path),
        revision: a.revision,
        host: shown(&short_host(&a.host_uuid)),
        user: shown(&user_label(a.user.as_ref())),
        any_user: a.user_scope == 2,
        auto_update: a.update_policy == 2,
        expires_at: a.expires_at,
        superseded: !a.superseded_by.is_empty(),
    }
}

/// The text of `field` in the filters of `tab`.
fn field_mut<'a>(
    requests: &'a mut RequestFilters,
    approvals: &'a mut ApprovalFilters,
    tab: Tab,
    field: FilterField,
) -> Option<&'a mut String> {
    Some(match (tab, field) {
        (Tab::Requests, FilterField::Text) => &mut requests.text,
        (Tab::Requests, FilterField::Path) => &mut requests.path,
        (Tab::Requests, FilterField::Product) => &mut requests.product,
        (Tab::Requests, FilterField::Version) => &mut requests.version,
        (Tab::Requests, FilterField::Host) => &mut requests.host,
        (Tab::Requests, FilterField::User) => &mut requests.user,
        (Tab::Requests, FilterField::Sha) => &mut requests.sha_prefix,
        (Tab::Requests, FilterField::From) => &mut requests.from,
        (Tab::Requests, FilterField::To) => &mut requests.to,
        (Tab::Approvals, FilterField::Text) => &mut approvals.text,
        (Tab::Approvals, FilterField::Path) => &mut approvals.path,
        (Tab::Approvals, FilterField::Product) => &mut approvals.product,
        (Tab::Approvals, FilterField::Host) => &mut approvals.host,
        (Tab::Approvals, FilterField::User) => &mut approvals.user,
        (Tab::Approvals, FilterField::Sha) => &mut approvals.sha_prefix,
        (Tab::Approvals, FilterField::From) => &mut approvals.expires_after,
        (Tab::Approvals, FilterField::To) => &mut approvals.expires_before,
        (Tab::Approvals, FilterField::Lineage) => &mut approvals.lineage,
        _ => return None,
    })
}

fn set_flag(flags: &mut [bool], i: usize, on: bool) {
    if let Some(f) = flags.get_mut(i) {
        *f = on;
    }
}

impl AdminViews {
    /// An empty panel on `tab` (nothing loaded yet).
    #[must_use]
    pub fn new(tab: Tab) -> Self {
        Self {
            tab,
            screen: Screen::List,
            permissions: None,
            request_filters: RequestFilters::default(),
            approval_filters: ApprovalFilters::default(),
            ascending: false,
            draft: None,
            requests: List::new(),
            approvals: List::new(),
            request: None,
            approval: None,
            decision: None,
            outcome: None,
            error: None,
            reask: None,
            pending: None,
            registering: false,
        }
    }

    /// Whether the session's permissions arrived.
    #[must_use]
    pub fn knows_permissions(&self) -> bool {
        self.permissions.is_some()
    }

    /// Whether the session may use `permission`. When `WhoAmI` failed the
    /// permissions are unknown and every action is offered (the server
    /// decides either way).
    #[must_use]
    pub fn can(&self, permission: &str) -> bool {
        self.permissions
            .as_ref()
            .is_none_or(|p| p.iter().any(|x| x == permission))
    }

    /// Whether a decision waits for its outcome or its step-up, or an add
    /// for its second factor or its outcome.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending.is_some() || self.registering
    }

    /// Whether typing goes to a field of the panel now.
    #[must_use]
    pub fn editing(&self) -> bool {
        self.decision.as_ref().is_some_and(Decision::editing)
            || self.draft.as_ref().is_some_and(|d| d.focus.is_some())
    }

    /// The command that loads what is shown.
    #[must_use]
    pub fn reload(&mut self, now: i64) -> Cmd {
        self.error = None;
        match self.screen {
            Screen::Request => {
                if let Some(r) = self.request.as_ref().and_then(|d| d.request.as_ref()) {
                    return Cmd::GetRequest(r.request_id.clone());
                }
            }
            Screen::Approval => {
                if let Some(a) = self.approval.as_ref().and_then(|d| d.approval.as_ref()) {
                    return Cmd::GetApproval(a.approval_id.clone());
                }
            }
            Screen::List => {}
        }
        self.screen = Screen::List;
        self.load_list(now)
    }

    fn load_list(&self, now: i64) -> Cmd {
        match self.tab {
            Tab::Requests => Cmd::ListRequests(Box::new(
                self.request_filters
                    .to_request(self.ascending, &self.requests.token),
            )),
            Tab::Approvals => Cmd::ListApprovals(Box::new(self.approval_filters.to_request(
                now,
                self.ascending,
                &self.approvals.token,
            ))),
        }
    }

    /// Typed or pasted text, for the focused field.
    pub fn type_text(&mut self, text: &str) {
        if let Some(d) = &mut self.decision {
            d.type_text(text);
            return;
        }
        let tab = self.tab;
        if let Some(draft) = &mut self.draft {
            let Some(field) = draft.focus else { return };
            let max = max_chars(field.key(tab));
            if let Some(v) = field_mut(&mut draft.requests, &mut draft.approvals, tab, field) {
                for c in text.chars().filter(|c| !c.is_control()) {
                    if v.chars().count() >= max {
                        break;
                    }
                    v.push(c);
                }
            }
            draft.invalid.retain(|f| *f != field);
        }
    }

    /// `Backspace` in the focused field.
    pub fn backspace(&mut self) {
        if let Some(d) = &mut self.decision {
            d.backspace();
            return;
        }
        let tab = self.tab;
        if let Some(draft) = &mut self.draft {
            let Some(field) = draft.focus else { return };
            if let Some(v) = field_mut(&mut draft.requests, &mut draft.approvals, tab, field) {
                v.pop();
            }
        }
    }

    /// `Tab` / `Shift-Tab` between the typed fields of the dialog or the
    /// filter panel.
    pub fn tab_key(&mut self, back: bool) {
        if let Some(d) = &mut self.decision {
            d.tab(back);
            return;
        }
        let tab = self.tab;
        if let Some(draft) = &mut self.draft {
            let fields = FilterField::of(tab);
            let at = draft
                .focus
                .and_then(|f| fields.iter().position(|x| *x == f))
                .unwrap_or(0);
            let n = fields.len();
            let next = if back { (at + n - 1) % n } else { (at + 1) % n };
            draft.focus = Some(fields[next]);
        }
    }

    /// `Esc`: close the dialog (nothing sent), the filter panel, or a
    /// detail.
    pub fn escape(&mut self) {
        if self.decision.take().is_some() {
            return;
        }
        if self.draft.take().is_some() {
            return;
        }
        if self.outcome.take().is_some() {
            return;
        }
        if self.screen != Screen::List {
            self.screen = Screen::List;
            self.request = None;
            self.approval = None;
        }
    }

    /// `Enter`: apply the filter panel, or move a dialog's form on.
    #[must_use]
    pub fn enter(&mut self, now: i64) -> Option<Cmd> {
        if let Some(d) = &mut self.decision {
            // Never confirms: the review page needs its own click.
            if d.view(now).stage == super::decide::DecisionStage::Form {
                d.next();
            }
            return None;
        }
        if self.draft.is_some() {
            return self.act(ViewAction::ApplyFilters, now);
        }
        None
    }

    /// Carry out `action` at Unix time `now`; the command to send, if any.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one arm per action.
    pub fn act(&mut self, action: ViewAction, now: i64) -> Option<Cmd> {
        match action {
            ViewAction::Tab(tab) => {
                self.decision = None;
                self.draft = None;
                self.tab = tab;
                self.screen = Screen::List;
                self.request = None;
                self.approval = None;
                Some(self.reload(now))
            }
            ViewAction::Refresh => {
                self.decision = None;
                Some(self.reload(now))
            }
            ViewAction::NextPage => self.page(true, now),
            ViewAction::PrevPage => self.page(false, now),
            ViewAction::OpenFilters => {
                self.decision = None;
                self.draft = Some(FilterDraft {
                    requests: self.request_filters.clone(),
                    approvals: self.approval_filters.clone(),
                    focus: Some(FilterField::Text),
                    invalid: Vec::new(),
                });
                None
            }
            ViewAction::CloseFilters => {
                self.draft = None;
                None
            }
            ViewAction::ResetFilters => {
                if let Some(d) = &mut self.draft {
                    match self.tab {
                        Tab::Requests => d.requests = RequestFilters::default(),
                        Tab::Approvals => d.approvals = ApprovalFilters::default(),
                    }
                    d.invalid.clear();
                }
                None
            }
            ViewAction::ApplyFilters => self.apply_filters(now),
            ViewAction::Filter(choice) => {
                self.filter_choice(choice);
                None
            }
            ViewAction::FocusFilter(field) => {
                if let Some(d) = &mut self.draft {
                    if FilterField::of(self.tab).contains(&field) {
                        d.focus = Some(field);
                    }
                }
                None
            }
            ViewAction::OpenRequest(i) => {
                let id = self.requests.items.get(i)?.request_id.clone();
                self.reask = None;
                Some(Cmd::GetRequest(id))
            }
            ViewAction::OpenApproval(i) => {
                let id = self.approvals.items.get(i)?.approval_id.clone();
                self.reask = None;
                Some(Cmd::GetApproval(id))
            }
            ViewAction::OpenLineageApproval(i) => {
                let id = self
                    .request
                    .as_ref()?
                    .lineage_approvals
                    .get(i)?
                    .approval_id
                    .clone();
                self.reask = None;
                Some(Cmd::GetApproval(id))
            }
            ViewAction::LineageApprovals => {
                let lineage = self.request.as_ref()?.request.as_ref()?.lineage_id.clone();
                self.approval_filters = ApprovalFilters::lineage(&lineage);
                self.approvals.first_page();
                self.tab = Tab::Approvals;
                self.screen = Screen::List;
                self.request = None;
                Some(self.load_list(now))
            }
            ViewAction::Back => {
                self.decision = None;
                self.screen = Screen::List;
                self.request = None;
                self.approval = None;
                Some(self.load_list(now))
            }
            ViewAction::Decide(kind) => {
                self.open_decision(kind);
                None
            }
            ViewAction::Choose(choice) => {
                if let Some(d) = &mut self.decision {
                    d.choose(choice);
                }
                None
            }
            ViewAction::FocusDecision(field) => {
                if let Some(d) = &mut self.decision {
                    d.focus(field);
                }
                None
            }
            ViewAction::FillLocalApp(app) => {
                if let Some(d) = &mut self.decision {
                    d.fill_app(&app);
                }
                None
            }
            ViewAction::LocalAppFailed => {
                if let Some(d) = &mut self.decision {
                    d.pick_failed();
                }
                None
            }
            ViewAction::DecisionNext => {
                if let Some(d) = &mut self.decision {
                    d.next();
                }
                None
            }
            ViewAction::DecisionBack => {
                if let Some(d) = &mut self.decision {
                    d.back();
                }
                None
            }
            ViewAction::DecisionConfirm => self.confirm(now),
            ViewAction::CancelDecision => {
                self.decision = None;
                None
            }
            ViewAction::DismissOutcome => {
                self.outcome = None;
                None
            }
        }
    }

    fn page(&mut self, forward: bool, now: i64) -> Option<Cmd> {
        let (token, next, back) = match self.tab {
            Tab::Requests => (
                &mut self.requests.token,
                &mut self.requests.next_token,
                &mut self.requests.back,
            ),
            Tab::Approvals => (
                &mut self.approvals.token,
                &mut self.approvals.next_token,
                &mut self.approvals.back,
            ),
        };
        if forward {
            if next.is_empty() {
                return None;
            }
            let old = std::mem::replace(token, std::mem::take(next));
            back.push(old);
        } else {
            *token = back.pop()?;
        }
        Some(self.load_list(now))
    }

    fn filter_choice(&mut self, choice: FilterChoice) {
        let Some(d) = &mut self.draft else { return };
        match (self.tab, choice) {
            (Tab::Requests, FilterChoice::State(i, on)) => set_flag(&mut d.requests.states, i, on),
            (Tab::Requests, FilterChoice::Origin(i, on)) => {
                set_flag(&mut d.requests.origins, i, on);
            }
            (Tab::Requests, FilterChoice::Kind(k)) => {
                d.requests.kind = k.min(REQUEST_KINDS.len() - 1);
            }
            (Tab::Approvals, FilterChoice::State(i, on)) => {
                set_flag(&mut d.approvals.states, i, on);
            }
            (Tab::Approvals, FilterChoice::Origin(i, on)) => {
                set_flag(&mut d.approvals.origins, i, on);
            }
            (Tab::Approvals, FilterChoice::Policy(i, on)) => {
                set_flag(&mut d.approvals.policies, i, on);
            }
            (Tab::Approvals, FilterChoice::Preset(p)) => {
                d.approvals.preset = p.min(PRESETS.len() - 1);
            }
            (Tab::Approvals, FilterChoice::Superseded(on)) => d.approvals.include_superseded = on,
            (_, FilterChoice::Ascending(on)) => self.ascending = on,
            _ => {}
        }
    }

    fn apply_filters(&mut self, now: i64) -> Option<Cmd> {
        let draft = self.draft.as_mut()?;
        let bad = match self.tab {
            Tab::Requests => {
                draft.requests.normalize();
                draft.requests.invalid_fields()
            }
            Tab::Approvals => {
                draft.approvals.normalize();
                draft.approvals.invalid_fields()
            }
        };
        let tab = self.tab;
        draft.invalid = FilterField::of(tab)
            .iter()
            .copied()
            .filter(|f| bad.contains(&f.key(tab)))
            .collect();
        if !draft.invalid.is_empty() {
            draft.focus = draft.invalid.first().copied();
            return None;
        }
        let draft = self.draft.take()?;
        match tab {
            Tab::Requests => {
                self.request_filters = draft.requests;
                self.requests.first_page();
            }
            Tab::Approvals => {
                self.approval_filters = draft.approvals;
                self.approvals.first_page();
            }
        }
        self.screen = Screen::List;
        Some(self.load_list(now))
    }

    fn open_decision(&mut self, kind: DecisionKind) {
        if self.has_pending() {
            return;
        }
        self.outcome = None;
        let request = self.request.as_deref();
        let approval = self.approval.as_ref().and_then(|d| d.approval.as_ref());
        let allowed = match kind {
            DecisionKind::Approve => self.can(perm::APPROVE),
            DecisionKind::Deny => self.can(perm::DENY),
            DecisionKind::Edit | DecisionKind::Freeze => self.can(perm::UPDATE),
            DecisionKind::Revoke => self.can(perm::REVOKE),
            DecisionKind::Register => self.can(perm::DIRECT_REGISTER),
        };
        if !allowed {
            self.outcome = Some(Outcome::Refused(Refusal::NotAllowed));
            return;
        }
        self.decision = match (self.screen, kind) {
            // From any screen: the add is about no record shown.
            (_, DecisionKind::Register) => Some(Decision::register_for(
                self.can(perm::APPROVE),
                super::local::LocalHost::cached(),
            )),
            (Screen::Request, DecisionKind::Approve) => request.and_then(Decision::approve),
            (Screen::Request, DecisionKind::Deny) => request
                .and_then(|d| d.request.as_ref())
                .and_then(Decision::deny),
            (Screen::Request, DecisionKind::Freeze) => request.and_then(|d| {
                d.request.as_ref().map(|r| {
                    Decision::freeze(
                        &r.lineage_id,
                        &r.canonical_path,
                        Some(d.lineage_auto_update_frozen),
                    )
                })
            }),
            (Screen::Approval, DecisionKind::Edit) => approval.and_then(Decision::edit),
            (Screen::Approval, DecisionKind::Revoke) => approval.and_then(Decision::revoke),
            (Screen::Approval, DecisionKind::Freeze) => {
                approval.map(|a| Decision::freeze(&a.lineage_id, &a.canonical_path, None))
            }
            _ => None,
        };
        if self.decision.is_none() {
            self.outcome = Some(Outcome::Refused(Refusal::NotPossibleNow));
        }
    }

    fn confirm(&mut self, now: i64) -> Option<Cmd> {
        if self.has_pending() {
            return None;
        }
        let d = self.decision.as_ref()?;
        let mutation = d.confirm(now)?;
        let edit_base = d.edited().map(|a| Box::new(a.clone()));
        self.decision = None;
        self.outcome = None;
        self.pending = Some(Pending {
            mutation: mutation.clone(),
            stepped_up: false,
            edit_base,
        });
        Some(Cmd::Mutate(Box::new(mutation)))
    }

    /// After a successful step-up: the waiting decision once more, with the
    /// same idempotency key.
    #[must_use]
    pub fn resend(&mut self) -> Option<Cmd> {
        let p = self.pending.as_mut()?;
        p.stepped_up = true;
        Some(Cmd::Mutate(Box::new(p.mutation.clone())))
    }

    /// The step-up was cancelled: the waiting decision is dropped unsent.
    pub fn drop_pending(&mut self) {
        if self.pending.take().is_some() {
            self.outcome = Some(Outcome::NotSent);
        }
    }

    /// "Confirm" on an add's review page: the request (no proof, no secret)
    /// the flow sends once a fresh second factor is given, whatever the
    /// step-up window. The dialog stays on its review meanwhile. `None`
    /// unless an add is confirmable now.
    #[must_use]
    pub fn confirm_register(&mut self, now: i64) -> Option<Box<AdminRegisterApplicationRequest>> {
        if self.has_pending() {
            return None;
        }
        let req = self.decision.as_ref()?.confirm_register(now)?;
        self.registering = true;
        self.outcome = None;
        Some(Box::new(req))
    }

    /// The add's second-factor prompt was closed: nothing was sent.
    pub fn register_cancelled(&mut self) {
        if std::mem::take(&mut self.registering) {
            self.outcome = Some(Outcome::NotSent);
        }
    }

    /// An add's outcome. A refusal leaves the dialog on its review
    /// (nothing was registered); success closes it and reloads the list.
    pub fn on_registered(
        &mut self,
        result: Result<Box<AdminRegisterApplicationResponse>, ClientError>,
        now: i64,
    ) -> ViewsEvent {
        if !std::mem::take(&mut self.registering) {
            return ViewsEvent::None;
        }
        match result {
            Ok(r) => {
                self.decision = None;
                self.outcome = Some(Outcome::Added(register::outcome(&r)));
                // Refresh after every decision (stale-data mitigation).
                ViewsEvent::Send(self.reload(now))
            }
            Err(ClientError::SessionEnded) => ViewsEvent::SessionEnded,
            Err(e) => {
                self.outcome = Some(Outcome::Refused(refusal(&e)));
                ViewsEvent::None
            }
        }
    }

    /// `WhoAmI`'s permissions; then the list.
    #[must_use]
    pub fn on_permissions(
        &mut self,
        result: Result<Vec<String>, ClientError>,
        now: i64,
    ) -> ViewsEvent {
        match result {
            Ok(p) => self.permissions = Some(p),
            Err(ClientError::SessionEnded) => return ViewsEvent::SessionEnded,
            // Unknown: every action is offered and the server decides.
            Err(_) => {}
        }
        ViewsEvent::Send(self.reload(now))
    }

    fn read_failed(&mut self, e: &ClientError) -> ViewsEvent {
        if matches!(e, ClientError::SessionEnded) {
            return ViewsEvent::SessionEnded;
        }
        self.reask = None;
        self.error = Some(refusal(e));
        ViewsEvent::None
    }

    /// A page of requests.
    pub fn on_requests(
        &mut self,
        result: Result<ListAppRequestsResponse, ClientError>,
    ) -> ViewsEvent {
        match result {
            Ok(mut r) => {
                r.items.truncate(MAX_ROWS);
                self.requests.items = r.items;
                self.requests.next_token = r.next_page_token;
                self.requests.loaded = true;
                self.error = None;
                ViewsEvent::None
            }
            Err(e) => self.read_failed(&e),
        }
    }

    /// A page of approvals.
    pub fn on_approvals(
        &mut self,
        result: Result<ListApprovalsResponse, ClientError>,
    ) -> ViewsEvent {
        match result {
            Ok(mut r) => {
                r.items.truncate(MAX_ROWS);
                self.approvals.items = r.items;
                self.approvals.next_token = r.next_page_token;
                self.approvals.loaded = true;
                self.error = None;
                ViewsEvent::None
            }
            Err(e) => self.read_failed(&e),
        }
    }

    /// One request: shown, and a decision opened when one waited for it.
    pub fn on_request(
        &mut self,
        result: Result<Box<GetAppRequestResponse>, ClientError>,
    ) -> ViewsEvent {
        match result {
            Ok(d) => {
                self.request = Some(d);
                self.approval = None;
                self.screen = Screen::Request;
                self.error = None;
                ViewsEvent::None
            }
            Err(e) => self.read_failed(&e),
        }
    }

    /// One approval: shown, and an edit re-asked after a concurrent change.
    pub fn on_approval(
        &mut self,
        result: Result<Box<GetApprovalResponse>, ClientError>,
    ) -> ViewsEvent {
        match result {
            Ok(d) => {
                let reask = self.reask.take();
                self.approval = Some(d);
                self.request = None;
                self.screen = Screen::Approval;
                self.error = None;
                if let Some(old) = reask {
                    let new = self.approval.as_ref().and_then(|d| d.approval.as_ref());
                    match new {
                        Some(n) if n.state == 3 => self.outcome = Some(Outcome::RevokedMeanwhile),
                        Some(n) => self.decision = Decision::reask_edit(&old, n),
                        None => {}
                    }
                }
                ViewsEvent::None
            }
            Err(e) => self.read_failed(&e),
        }
    }

    /// A decision's outcome.
    pub fn on_mutated(
        &mut self,
        result: Result<Box<Mutated>, ClientError>,
        now: i64,
    ) -> ViewsEvent {
        let Some(pending) = self.pending.take() else {
            return ViewsEvent::None;
        };
        let e = match result {
            Ok(done) => {
                self.outcome = Some(match *done {
                    Mutated::Approved(r) => Outcome::Approved {
                        approval: r
                            .approval
                            .as_ref()
                            .map(|a| short_id("A", &a.approval_id))
                            .unwrap_or_default(),
                        generation: r.allowlist_generation,
                        revoked: r
                            .revoked_approval_ids
                            .iter()
                            .take(MAX_LINEAGE)
                            .map(|i| short_id("A", i))
                            .collect(),
                        same_actor: r.same_actor,
                    },
                    Mutated::Denied(_) => Outcome::Denied,
                    Mutated::Updated(r) => Outcome::Updated(r.allowlist_generation),
                    Mutated::Revoked(r) => Outcome::Revoked(r.allowlist_generation),
                    Mutated::Frozen(f) => Outcome::Frozen(f),
                });
                // Refresh after every decision (stale-data mitigation).
                return ViewsEvent::Send(self.reload(now));
            }
            Err(e) => e,
        };
        match &e {
            ClientError::SessionEnded => return ViewsEvent::SessionEnded,
            _ if e.needs_step_up() && !pending.stepped_up => {
                // Kept: the retry reuses its idempotency key.
                self.pending = Some(pending);
                return ViewsEvent::StepUp;
            }
            _ if e.needs_step_up() => {
                self.outcome = Some(Outcome::StepUpAgain);
                return ViewsEvent::None;
            }
            ClientError::Other(r) if r.code == Code::Aborted => {
                if let (Mutation::Update(u), Some(base)) = (&pending.mutation, pending.edit_base) {
                    // Reload, show what changed, and ask again.
                    self.reask = Some(base);
                    return ViewsEvent::Send(Cmd::GetApproval(u.approval_id.clone()));
                }
            }
            _ => {}
        }
        self.outcome = Some(Outcome::Refused(refusal(&e)));
        ViewsEvent::Send(self.reload(now))
    }

    fn filters_view(&self) -> Option<FiltersView> {
        let d = self.draft.as_ref()?;
        let tab = self.tab;
        let mut requests = d.requests.clone();
        let mut approvals = d.approvals.clone();
        let fields = FilterField::of(tab)
            .iter()
            .map(|f| {
                let v = field_mut(&mut requests, &mut approvals, tab, *f)
                    .map(|v| shown(v))
                    .unwrap_or_default();
                (*f, v)
            })
            .collect();
        Some(match tab {
            Tab::Requests => FiltersView {
                states: d.requests.states.clone(),
                origins: d.requests.origins.clone(),
                kind: d.requests.kind,
                policies: Vec::new(),
                preset: 0,
                superseded: false,
                ascending: self.ascending,
                fields,
                focus: d.focus,
                invalid: d.invalid.clone(),
            },
            Tab::Approvals => FiltersView {
                states: d.approvals.states.clone(),
                origins: d.approvals.origins.clone(),
                kind: 0,
                policies: d.approvals.policies.clone(),
                preset: d.approvals.preset,
                superseded: d.approvals.include_superseded,
                ascending: self.ascending,
                fields,
                focus: d.focus,
                invalid: d.invalid.clone(),
            },
        })
    }

    fn request_detail(&self) -> Option<RequestDetail> {
        let d = self.request.as_ref()?;
        let r = d.request.as_ref()?;
        let bin = d.binary.clone().unwrap_or_default();
        Some(RequestDetail {
            row: request_row(r),
            kind: r.kind,
            sha: shown(&r.bin_sha),
            product: shown(&r.product_name),
            reason: shown(&r.reason),
            requester: shown(&r.requester_user_name),
            pending_expires_at: r.pending_expires_at,
            decided_at: r.decided_at,
            decision_reason_code: r.decision_reason_code,
            decision_message: shown(&r.decision_message),
            warnings: warning_flags(r.flags),
            path_protected: r.flags & RiskFlags::PATH_PROTECTED != 0,
            signer: shown(if bin.signer_subject.is_empty() {
                &bin.signer_id
            } else {
                &bin.signer_subject
            }),
            signer_valid: bin.signer_valid,
            lineage_frozen: d.lineage_auto_update_frozen,
            same_actor: r.same_actor_approved,
            lineage: d
                .lineage_approvals
                .iter()
                .take(MAX_LINEAGE)
                .map(approval_row)
                .collect(),
        })
    }

    fn approval_detail(&self) -> Option<ApprovalDetail> {
        let d = self.approval.as_ref()?;
        let a = d.approval.as_ref()?;
        Some(ApprovalDetail {
            row: approval_row(a),
            sha: shown(&a.bin_sha),
            product: shown(&a.product_name),
            any_path: a.path_match == 2,
            path_user_continuity: a.continuity == 2,
            origin: a.origin,
            created_at: a.created_at,
            revoked_at: a.revoked_at,
            revoke_reason_code: a.revoke_reason_code,
            note: shown(&a.note),
            row_version: a.row_version,
            revisions: d.revisions.len(),
        })
    }

    /// What the window draws at Unix time `now`.
    #[must_use]
    pub fn view(&self, now: i64) -> ViewsView {
        let (loaded, page, has_next, summary) = match self.tab {
            Tab::Requests => (
                self.requests.loaded,
                self.requests.back.len() + 1,
                !self.requests.next_token.is_empty(),
                self.request_filters.summary(),
            ),
            Tab::Approvals => (
                self.approvals.loaded,
                self.approvals.back.len() + 1,
                !self.approvals.next_token.is_empty(),
                self.approval_filters.summary(),
            ),
        };
        ViewsView {
            tab: self.tab,
            screen: self.screen,
            requests: self.requests.items.iter().map(request_row).collect(),
            approvals: self.approvals.items.iter().map(approval_row).collect(),
            loaded,
            page,
            has_next,
            summary: shown(&summary),
            filters: self.filters_view(),
            request: self.request_detail(),
            approval: self.approval_detail(),
            decision: self.decision.as_ref().map(|d| d.view(now)),
            outcome: self.outcome.clone(),
            error: self.error,
            pending: self.has_pending(),
            can_approve: self.can(perm::APPROVE),
            can_deny: self.can(perm::DENY),
            can_update: self.can(perm::UPDATE),
            can_revoke: self.can(perm::REVOKE),
            can_register: self.can(perm::DIRECT_REGISTER),
        }
    }
}

/// The names of the state codes of `tab`'s rows, in wire order.
#[must_use]
pub fn state_names(tab: Tab) -> &'static [&'static str] {
    match tab {
        Tab::Requests => &REQUEST_STATES,
        Tab::Approvals => &APPROVAL_STATES,
    }
}

/// The names of the origin codes of `tab`'s rows, in wire order.
#[must_use]
pub fn origin_names(tab: Tab) -> &'static [&'static str] {
    match tab {
        Tab::Requests => &REQUEST_ORIGINS,
        Tab::Approvals => &APPROVAL_ORIGINS,
    }
}

/// The approval policies' names, in wire order.
#[must_use]
pub fn policy_names() -> &'static [&'static str] {
    &POLICIES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::decide::tests::{approval, detail, request, APPROVAL_ID, NOW};
    use crate::admin::decide::{DecisionStage, ReviewLine};
    use ferrogate_admin_client::approvals::proto::{
        ApproveAppRequestResponse, UpdateApprovalResponse,
    };
    use ferrogate_admin_client::error::RpcError;

    fn list_of(items: Vec<AppRequestInfo>, next: &str) -> ListAppRequestsResponse {
        ListAppRequestsResponse {
            items,
            next_page_token: next.into(),
        }
    }

    fn server(code: Code, reason: &str) -> ClientError {
        ClientError::Other(RpcError::local(code, reason))
    }

    /// Every permission the decisions need.
    const ALL: &[&str] = &[perm::APPROVE, perm::DENY, perm::UPDATE, perm::REVOKE];

    /// The panel on the requests list with one pending request loaded and
    /// opened.
    fn on_request(permissions: &[&str]) -> AdminViews {
        let mut v = AdminViews::new(Tab::Requests);
        let perms = permissions.iter().map(|p| (*p).to_string()).collect();
        assert!(matches!(
            v.on_permissions(Ok(perms), NOW),
            ViewsEvent::Send(Cmd::ListRequests(_))
        ));
        let _ = v.on_requests(Ok(list_of(vec![request(0)], "")));
        assert!(matches!(
            v.act(ViewAction::OpenRequest(0), NOW),
            Some(Cmd::GetRequest(id)) if id.ends_with("a1b2")
        ));
        let _ = v.on_request(Ok(Box::new(detail(0))));
        v
    }

    #[test]
    fn lists_are_inert_paged_and_filtered_with_checked_values() {
        let mut v = AdminViews::new(Tab::Requests);
        let _ = v.on_requests(Ok(list_of(vec![request(RiskFlags::UNSIGNED)], "tok-2")));
        let view = v.view(NOW);
        assert!(view.loaded && view.has_next && view.page == 1);
        let row = &view.requests[0];
        assert!(!row.path.contains('\u{202e}') && !row.user.contains('\u{1b}'));
        assert_eq!((row.short_id.as_str(), row.warnings), ("R-0000A1B2", 1));
        let Some(Cmd::ListRequests(r)) = v.act(ViewAction::NextPage, NOW) else {
            panic!("the next page");
        };
        assert_eq!(r.page.unwrap().page_token, "tok-2");
        assert_eq!(v.view(NOW).page, 2);
        let Some(Cmd::ListRequests(r)) = v.act(ViewAction::PrevPage, NOW) else {
            panic!("the first page");
        };
        assert_eq!(r.page.unwrap().page_token, "");

        assert!(v.act(ViewAction::OpenFilters, NOW).is_none());
        v.type_text("zoom");
        let _ = v.act(ViewAction::FocusFilter(FilterField::Sha), NOW);
        v.type_text("ABC");
        let _ = v.act(ViewAction::Filter(FilterChoice::State(3, true)), NOW);
        assert!(
            v.act(ViewAction::ApplyFilters, NOW).is_none(),
            "a short hash"
        );
        assert_eq!(v.view(NOW).filters.unwrap().invalid, vec![FilterField::Sha]);
        v.type_text("DEF0123");
        let Some(Cmd::ListRequests(r)) = v.enter(NOW) else {
            panic!("the filtered list");
        };
        assert_eq!(
            (r.text.as_str(), r.bin_sha_prefix.as_str()),
            ("zoom", "abcdef0123")
        );
        assert_eq!(r.states, vec![1, 4]);
        assert!(v.view(NOW).filters.is_none());
        // A field never takes more than its limit.
        let _ = v.act(ViewAction::OpenFilters, NOW);
        let _ = v.act(ViewAction::FocusFilter(FilterField::Host), NOW);
        v.type_text(&"a".repeat(100));
        let f = v.view(NOW).filters.unwrap();
        assert_eq!(
            f.fields
                .iter()
                .find(|(k, _)| *k == FilterField::Host)
                .unwrap()
                .1
                .len(),
            36
        );
    }

    #[test]
    fn a_decision_steps_up_once_and_resends_the_same_key() {
        let mut v = on_request(&[perm::APPROVE, perm::DENY]);
        assert!(v.view(NOW).request.is_some());
        let _ = v.act(ViewAction::Decide(DecisionKind::Approve), NOW);
        assert_eq!(v.view(NOW).decision.unwrap().stage, DecisionStage::Form);
        let _ = v.act(ViewAction::DecisionNext, NOW);
        let Some(Cmd::Mutate(m)) = v.act(ViewAction::DecisionConfirm, NOW) else {
            panic!("sent after the review");
        };
        let key = m.idempotency_key().to_string();
        assert!(v.view(NOW).pending && v.view(NOW).decision.is_none());
        assert!(matches!(
            v.on_mutated(
                Err(server(Code::FailedPrecondition, "step_up_required")),
                NOW
            ),
            ViewsEvent::StepUp
        ));
        let Some(Cmd::Mutate(again)) = v.resend() else {
            panic!("the one retry");
        };
        assert_eq!(again.idempotency_key(), key);
        // A second step_up_required is not looped.
        assert!(matches!(
            v.on_mutated(
                Err(server(Code::FailedPrecondition, "step_up_required")),
                NOW
            ),
            ViewsEvent::None
        ));
        assert_eq!(v.view(NOW).outcome, Some(Outcome::StepUpAgain));
        assert!(!v.has_pending());
    }

    #[test]
    fn an_outcome_is_shown_and_the_record_reloaded() {
        let mut v = on_request(ALL);
        let _ = v.act(ViewAction::Decide(DecisionKind::Approve), NOW);
        let _ = v.act(ViewAction::DecisionNext, NOW);
        let _ = v.act(ViewAction::DecisionConfirm, NOW);
        let done = Mutated::Approved(ApproveAppRequestResponse {
            approval: Some(approval(1, 1)),
            allowlist_generation: 12,
            same_actor: false,
            revoked_approval_ids: Vec::new(),
            request: None,
        });
        assert!(matches!(
            v.on_mutated(Ok(Box::new(done)), NOW),
            ViewsEvent::Send(Cmd::GetRequest(_))
        ));
        assert!(matches!(
            v.view(NOW).outcome,
            Some(Outcome::Approved { generation: 12, ref approval, .. }) if approval == "A-0000BEEF"
        ));
        let _ = v.act(ViewAction::DismissOutcome, NOW);
        assert_eq!(v.view(NOW).outcome, None);
    }

    #[test]
    fn a_cancelled_step_up_sends_nothing_more() {
        let mut v = on_request(ALL);
        let _ = v.act(ViewAction::Decide(DecisionKind::Deny), NOW);
        let _ = v.act(ViewAction::DecisionNext, NOW);
        let _ = v.act(ViewAction::DecisionConfirm, NOW);
        let _ = v.on_mutated(
            Err(server(Code::FailedPrecondition, "step_up_required")),
            NOW,
        );
        v.drop_pending();
        assert!(v.resend().is_none());
        assert_eq!(v.view(NOW).outcome, Some(Outcome::NotSent));
    }

    #[test]
    fn missing_permissions_refuse_the_dialog_and_viewers_see_no_buttons() {
        let mut v = on_request(&[perm::REQUEST_LIST]);
        let view = v.view(NOW);
        assert!(!view.can_approve && !view.can_deny);
        let _ = v.act(ViewAction::Decide(DecisionKind::Approve), NOW);
        let view = v.view(NOW);
        assert!(view.decision.is_none());
        assert_eq!(view.outcome, Some(Outcome::Refused(Refusal::NotAllowed)));
    }

    #[test]
    fn an_aborted_edit_reloads_shows_the_change_and_asks_again() {
        let mut v = AdminViews::new(Tab::Approvals);
        let _ = v.on_approvals(Ok(ListApprovalsResponse {
            items: vec![approval(1, 1)],
            next_page_token: String::new(),
        }));
        assert!(matches!(
            v.act(ViewAction::OpenApproval(0), NOW),
            Some(Cmd::GetApproval(id)) if id == APPROVAL_ID
        ));
        let _ = v.on_approval(Ok(Box::new(GetApprovalResponse {
            approval: Some(approval(1, 1)),
            ..GetApprovalResponse::default()
        })));
        let _ = v.act(ViewAction::Decide(DecisionKind::Edit), NOW);
        let _ = v.act(ViewAction::Choose(Choice::EditExpiry(2)), NOW);
        let _ = v.act(ViewAction::DecisionNext, NOW);
        let Some(Cmd::Mutate(_)) = v.act(ViewAction::DecisionConfirm, NOW) else {
            panic!("an update");
        };
        assert!(matches!(
            v.on_mutated(Err(server(Code::Aborted, "row_version_mismatch")), NOW),
            ViewsEvent::Send(Cmd::GetApproval(id)) if id == APPROVAL_ID
        ));
        let newer = ApprovalInfo {
            note: "by someone else".into(),
            row_version: 8,
            ..approval(1, 1)
        };
        let _ = v.on_approval(Ok(Box::new(GetApprovalResponse {
            approval: Some(newer),
            ..GetApprovalResponse::default()
        })));
        let d = v.view(NOW).decision.expect("the edit is asked again");
        assert_eq!(
            d.changed_meanwhile,
            Some(vec![
                ferrogate_admin_client::approvals::rules::ApprovalChange::Note
            ])
        );
        assert!(d.note.contains("someone else"));
        // A successful edit then reloads the approval.
        let _ = v.act(ViewAction::Choose(Choice::EditExpiry(1)), NOW);
        let _ = v.act(ViewAction::DecisionNext, NOW);
        let Some(Cmd::Mutate(m)) = v.act(ViewAction::DecisionConfirm, NOW) else {
            panic!("the update again");
        };
        assert!(matches!(*m, Mutation::Update(ref u) if u.expected_row_version == 8));
        let done = Mutated::Updated(UpdateApprovalResponse {
            approval: None,
            allowlist_generation: 3,
        });
        assert!(matches!(
            v.on_mutated(Ok(Box::new(done)), NOW),
            ViewsEvent::Send(Cmd::GetApproval(_))
        ));
        assert_eq!(v.view(NOW).outcome, Some(Outcome::Updated(3)));
    }

    /// The add dialog on its review page, typed through the panel.
    fn add_reviewed(v: &mut AdminViews) {
        use crate::admin::decide::tests::HOST;
        assert!(v
            .act(ViewAction::Decide(DecisionKind::Register), NOW)
            .is_none());
        for (field, text) in [
            (DecisionField::Host, HOST.to_string()),
            (DecisionField::Path, "/opt/tool/bin/tool".to_string()),
            (DecisionField::Sha, "ab".repeat(48)),
            (DecisionField::Uid, "1000".to_string()),
            (DecisionField::User, "alice".to_string()),
        ] {
            let _ = v.act(ViewAction::FocusDecision(field), NOW);
            v.type_text(&text);
        }
        let _ = v.act(ViewAction::DecisionNext, NOW);
        assert_eq!(v.view(NOW).decision.unwrap().stage, DecisionStage::Review);
    }

    #[test]
    fn an_add_is_gated_handed_to_the_flow_and_its_outcome_reloads_the_list() {
        let mut v = AdminViews::new(Tab::Requests);
        let _ = v.on_permissions(Ok(vec![perm::REQUEST_LIST.to_string()]), NOW);
        assert!(!v.view(NOW).can_register);
        let _ = v.act(ViewAction::Decide(DecisionKind::Register), NOW);
        assert_eq!(
            v.view(NOW).outcome,
            Some(Outcome::Refused(Refusal::NotAllowed))
        );
        assert!(v.view(NOW).decision.is_none());

        // `app.direct_register` without `app_request.approve`: queue only.
        let mut v = AdminViews::new(Tab::Requests);
        let perms = vec![perm::DIRECT_REGISTER.to_string()];
        let _ = v.on_permissions(Ok(perms), NOW);
        assert!(v.view(NOW).can_register);
        add_reviewed(&mut v);
        let d = v.view(NOW).decision.unwrap();
        assert!(!d.register.unwrap().can_approve);
        assert!(d.review.contains(&ReviewLine::RegisterOutcome(false)));
        // "Confirm" sends nothing itself: the flow asks the fresh factor.
        assert!(v.act(ViewAction::DecisionConfirm, NOW).is_none());
        let first = v.confirm_register(NOW).expect("the request to prove");
        assert!(first.proof.is_none());
        assert!(v.has_pending() && v.view(NOW).pending);
        assert!(v.confirm_register(NOW).is_none(), "one at a time");
        // A refusal leaves the review open; nothing was registered.
        assert!(matches!(
            v.on_registered(Err(server(Code::InvalidArgument, "bad_value")), NOW),
            ViewsEvent::None
        ));
        let view = v.view(NOW);
        assert_eq!(view.outcome, Some(Outcome::Refused(Refusal::Invalid)));
        assert_eq!(view.decision.unwrap().stage, DecisionStage::Review);
        assert!(!v.has_pending());
        // A closed prompt sends nothing.
        let second = v.confirm_register(NOW).unwrap();
        assert_ne!(second.idempotency_key, first.idempotency_key);
        v.register_cancelled();
        assert_eq!(v.view(NOW).outcome, Some(Outcome::NotSent));
        // Queued under strict separation of duties: shown, list reloaded.
        let _ = v.confirm_register(NOW).unwrap();
        let queued = AdminRegisterApplicationResponse {
            request: Some(AppRequestInfo {
                request_id: "0192a9f1-0000-7000-8000-00000000a1b2".into(),
                ..AppRequestInfo::default()
            }),
            queued: true,
            ..AdminRegisterApplicationResponse::default()
        };
        assert!(matches!(
            v.on_registered(Ok(Box::new(queued)), NOW),
            ViewsEvent::Send(Cmd::ListRequests(_))
        ));
        let view = v.view(NOW);
        assert!(view.decision.is_none());
        assert_eq!(
            view.outcome,
            Some(Outcome::Added(Registered::Queued {
                request: "R-0000A1B2".into()
            }))
        );
        // A late answer with nothing waiting changes nothing.
        assert!(matches!(
            v.on_registered(Err(ClientError::SessionEnded), NOW),
            ViewsEvent::None
        ));
    }

    #[test]
    fn a_dead_session_or_a_refusal_is_reported_by_kind_only() {
        let mut v = AdminViews::new(Tab::Requests);
        assert!(matches!(
            v.on_requests(Err(ClientError::SessionEnded)),
            ViewsEvent::SessionEnded
        ));
        let _ = v.on_requests(Err(server(Code::PermissionDenied, "forbidden\u{1b}[2J")));
        assert_eq!(v.view(NOW).error, Some(Refusal::NotAllowed));
        let json = serde_json::to_string(&v.view(NOW)).unwrap();
        assert!(!json.contains("forbidden"), "{json}");
        // Esc closes a detail, then the lineage jump lists its approvals.
        let mut v = on_request(ALL);
        assert!(matches!(
            v.act(ViewAction::LineageApprovals, NOW),
            Some(Cmd::ListApprovals(r)) if r.lineage_id == "lin" && r.include_superseded
        ));
        assert_eq!(v.view(NOW).tab, Tab::Approvals);
    }
}
