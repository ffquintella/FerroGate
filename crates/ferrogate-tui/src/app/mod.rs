//! The headless state machine (F21 §2 "Model, update, view").
//!
//! [`App::update`] takes one [`Msg`] (a key, a paste, a clock tick or a reply
//! from the client task) and returns the [`Cmd`]s to send. It does no I/O and
//! reads no clock, so every transition is tested without a terminal or a
//! server. The views in [`crate::screens`] only read it.
//!
//! Session rules (F21 §8):
//!
//! - the client locks itself at the server idle timeout minus 30 s of no key
//!   press (`Ctrl-L` locks at once): every displayed record is dropped, the
//!   screen is cleared, the session is logged out and the token wiped;
//! - a `session_invalid` reply ends the session the same way with the
//!   message "Session ended", whatever the cause;
//! - while not signed in, replies to earlier reads are dropped, so nothing
//!   from a previous session can reappear;
//! - keys that need a permission the session lacks are refused with an
//!   explanation (a convenience only: the server enforces permissions).

pub mod dialogs;
pub mod filters;
pub mod form;

use ferro_proto::admin_v1::{
    AdminAccountInfo, AdminRegisterApplicationRequest, AdminRegisterApplicationResponse,
    AppRequestInfo, ApprovalInfo, GetAppRequestResponse, GetApprovalResponse, SessionInfo,
};

use crate::client::{
    Cmd, DashboardCounts, LoginError, LoginInfo, Mutated, Mutation, Op, Query, Reply, RpcError,
};
use crate::input::Key;
use crate::secret::Secret;
use crate::timefmt;
use dialogs::{short_id, Dialog, Outcome};
use filters::{ApprovalFilters, RequestFilters, MAX_TEXT};
use form::{Field, Form, FormEvent};

/// Permission names (F20 §7) the key map checks.
pub mod perm {
    /// List requests.
    pub const REQUEST_LIST: &str = "app_request.list";
    /// Approve a request.
    pub const APPROVE: &str = "app_request.approve";
    /// Deny a request.
    pub const DENY: &str = "app_request.deny";
    /// List approvals.
    pub const APPROVAL_LIST: &str = "approval.list";
    /// Edit an approval or freeze a lineage.
    pub const UPDATE: &str = "approval.update";
    /// Revoke an approval.
    pub const REVOKE: &str = "approval.revoke";
    /// Add an application directly.
    pub const DIRECT_REGISTER: &str = "app.direct_register";
    /// List accounts.
    pub const ACCOUNT_LIST: &str = "account.list";
}

/// Seconds before the server idle timeout at which the client locks itself.
pub const LOCK_MARGIN_SECS: i64 = 30;
/// Range the server's idle timeout is clamped to before the margin is taken
/// (the server allows 60…900 s; 1800 s is the AAL2 ceiling).
pub const MIN_IDLE_SECS: i64 = 40;
/// See [`MIN_IDLE_SECS`].
pub const MAX_IDLE_SECS: i64 = 1_800;
/// Longest throttle countdown honoured from a `retry-after`.
const MAX_THROTTLE_SECS: u64 = 3_600;

/// A message into the state machine.
pub enum Msg {
    /// A key press.
    Key(Key),
    /// Pasted text (bracketed paste), already wrapped so a pasted password is
    /// wiped after use.
    Paste(Secret),
    /// The clock: monotonic seconds since start, and Unix seconds.
    Tick {
        /// Monotonic seconds (idle lock, throttle countdown, refresh).
        mono: u64,
        /// Unix seconds (dates shown and sent).
        unix: i64,
    },
    /// A reply from the client task.
    Reply(Reply),
}

/// The screens of F21 §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Counts and session information.
    Dashboard,
    /// The request list.
    Requests,
    /// One request.
    RequestDetail,
    /// The approval list.
    Approvals,
    /// One approval.
    ApprovalDetail,
    /// Hosts (not available: no `ListHosts` RPC yet).
    Hosts,
    /// Administrator accounts.
    Accounts,
    /// The administrator's sessions.
    Sessions,
}

impl Screen {
    /// The tab a screen belongs to (0-based, keys `1`–`6`).
    #[must_use]
    pub fn tab(self) -> usize {
        match self {
            Self::Dashboard => 0,
            Self::Requests | Self::RequestDetail => 1,
            Self::Approvals | Self::ApprovalDetail => 2,
            Self::Hosts => 3,
            Self::Accounts => 4,
            Self::Sessions => 5,
        }
    }

    fn of_tab(i: usize) -> Self {
        match i {
            1 => Self::Requests,
            2 => Self::Approvals,
            3 => Self::Hosts,
            4 => Self::Accounts,
            5 => Self::Sessions,
            _ => Self::Dashboard,
        }
    }
}

/// Tab labels, in key order.
pub const TABS: [&str; 6] = [
    "Dashboard",
    "Requests",
    "Approvals",
    "Hosts",
    "Accounts",
    "Sessions",
];

/// The sign-in screen.
pub struct LoginScreen {
    /// Username, password, TOTP.
    pub form: Form,
    /// Generic error after a failed attempt.
    pub error: Option<String>,
    /// Why the previous session ended (lock, session ended, signed out).
    pub notice: Option<String>,
    /// Throttled until this monotonic second.
    pub throttled_until: Option<u64>,
    /// A login is in flight.
    pub busy: bool,
}

impl LoginScreen {
    fn new(notice: Option<String>) -> Self {
        Self {
            form: Form::new(vec![
                Field::text("username", "Username", "", 64),
                Field::secret("password", "Password", false, 256),
                Field::secret("totp", "TOTP code", true, 8),
            ]),
            error: None,
            notice,
            throttled_until: None,
            busy: false,
        }
    }
}

/// The forced password change.
pub struct PasswordScreen {
    /// Current, new, repeat, TOTP.
    pub form: Form,
    /// Error of the last attempt.
    pub error: Option<String>,
    /// A change is in flight.
    pub busy: bool,
}

impl PasswordScreen {
    fn new() -> Self {
        Self {
            form: Form::new(vec![
                Field::secret("current", "Current password", false, 256),
                Field::secret("new", "New password", false, 256)
                    .with_hint("at least 24 characters"),
                Field::secret("repeat", "Repeat new password", false, 256),
                Field::secret("totp", "TOTP code", true, 8),
            ]),
            error: None,
            busy: false,
        }
    }
}

/// Where the application is.
pub enum Phase {
    /// Signed out.
    Login(LoginScreen),
    /// Signed in with an expired password: only the change is allowed.
    ChangePassword(PasswordScreen),
    /// Signed in.
    Main,
}

/// What the status bar knows about the session (no secret).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionView {
    /// Username as typed at sign-in.
    pub username: String,
    /// Display name (untrusted text).
    pub display_name: String,
    /// Group names.
    pub groups: Vec<String>,
    /// Permissions from `WhoAmI` (empty until it answers).
    pub permissions: Vec<String>,
    /// Assurance level.
    pub aal: u32,
    /// Server idle timeout.
    pub idle_timeout_secs: i64,
    /// Step-up valid until (Unix), when known.
    pub step_up_until: Option<i64>,
}

impl SessionView {
    /// A short role label from the groups.
    #[must_use]
    pub fn role(&self) -> String {
        let roles: Vec<&str> = self
            .groups
            .iter()
            .map(|g| match g.as_str() {
                "ferrogate-viewers" => "viewer",
                "ferrogate-approvers" => "approver",
                "ferrogate-account-admins" => "account admin",
                "ferrogate-platform-operators" => "operator",
                other => other,
            })
            .collect();
        if roles.is_empty() {
            "no group".to_string()
        } else {
            roles.join(", ")
        }
    }
}

/// One server-paged list.
pub struct ListView<T> {
    /// Rows of the current page.
    pub items: Vec<T>,
    /// Selected row.
    pub selected: usize,
    /// Token of the current page ("" for the first).
    pub page_token: String,
    /// Tokens of the previous pages.
    pub previous: Vec<String>,
    /// Token of the next page ("" when none).
    pub next_token: String,
    /// Oldest first instead of newest first.
    pub ascending: bool,
    /// A load is in flight.
    pub loading: bool,
    /// Loaded at least once.
    pub loaded: bool,
    /// Error of the last load.
    pub error: Option<String>,
    /// Sequence number of the newest query.
    pub seq: u64,
}

impl<T> Default for ListView<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            page_token: String::new(),
            previous: Vec::new(),
            next_token: String::new(),
            ascending: false,
            loading: false,
            loaded: false,
            error: None,
            seq: 0,
        }
    }
}

impl<T> ListView<T> {
    /// 1-based page number.
    #[must_use]
    pub fn page(&self) -> usize {
        self.previous.len() + 1
    }

    fn reset_paging(&mut self) {
        self.page_token.clear();
        self.previous.clear();
        self.next_token.clear();
        self.selected = 0;
    }

    fn move_by(&mut self, delta: isize) {
        if self.items.is_empty() {
            self.selected = 0;
            return;
        }
        let last = self.items.len() - 1;
        self.selected = self.selected.saturating_add_signed(delta).min(last);
    }
}

/// Which list a panel belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// Requests.
    Requests,
    /// Approvals.
    Approvals,
}

/// A modal over the current screen.
pub enum Modal {
    /// Key map and glossary.
    Help,
    /// "Quit? y/n".
    ConfirmQuit,
    /// The free-text search (`/`).
    Search {
        /// One text field.
        form: Form,
        /// Which list.
        list: ListKind,
    },
    /// The filter panel (`f`).
    Filters {
        /// The panel.
        form: Form,
        /// Which list.
        list: ListKind,
    },
    /// A decision dialog.
    Dialog(Box<Dialog>),
    /// The step-up prompt before replaying an operation.
    StepUp {
        /// The TOTP field.
        form: Form,
        /// Error of the previous attempt.
        error: Option<String>,
    },
    /// The fresh TOTP code for a direct add (always asked).
    RegisterTotp {
        /// The TOTP field.
        form: Form,
        /// Error of the previous attempt.
        error: Option<String>,
    },
    /// An outcome or an error.
    Message {
        /// Title.
        title: String,
        /// Lines (may contain server text; sanitised when drawn).
        lines: Vec<String>,
    },
}

/// Severity of the status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Information.
    Info,
    /// Something was refused or needs attention.
    Warn,
}

/// A mutation waiting for its outcome (kept for the single step-up retry).
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    /// The request as sent (its idempotency key is reused on the retry).
    pub mutation: Mutation,
    /// A step-up already happened for it: a second `step_up_required` is
    /// not looped.
    pub stepped_up: bool,
}

/// What to do when a detail arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterLoad {
    Approve,
    Deny,
}

/// The whole UI state.
#[allow(clippy::struct_excessive_bools)] // independent flags (display, quit, clear), not states.
pub struct App {
    /// Signed out, changing the password, or signed in.
    pub phase: Phase,
    /// The current screen (when signed in).
    pub screen: Screen,
    /// The open modal, if any.
    pub modal: Option<Modal>,
    /// The session (no secret), when signed in.
    pub session: Option<SessionView>,
    /// The endpoint, for the header and the login screen.
    pub endpoint: String,
    /// The first pin, abbreviated, for the login screen.
    pub pin_hint: String,
    /// Draw without colours.
    pub monochrome: bool,
    /// Requests list and filters.
    pub requests: ListView<AppRequestInfo>,
    /// Request filters.
    pub request_filters: RequestFilters,
    /// Approvals list.
    pub approvals: ListView<ApprovalInfo>,
    /// Approval filters.
    pub approval_filters: ApprovalFilters,
    /// The open request.
    pub request_detail: Option<Box<GetAppRequestResponse>>,
    /// The open approval.
    pub approval_detail: Option<Box<GetApprovalResponse>>,
    /// Dashboard figures.
    pub dashboard: Option<DashboardCounts>,
    /// Accounts (when permitted and loaded).
    pub accounts: Option<Vec<AdminAccountInfo>>,
    /// Own sessions.
    pub sessions: Option<Vec<SessionInfo>>,
    /// Show the full hash in detail views.
    pub full_hash: bool,
    /// Scroll offset of detail views.
    pub scroll: u16,
    /// Status line.
    pub status: Option<(Level, String)>,
    /// Commands awaiting their reply.
    pub in_flight: u32,
    /// Monotonic seconds now.
    pub mono: u64,
    /// Unix seconds now.
    pub unix: i64,
    last_activity: u64,
    last_refresh: u64,
    refresh_secs: u64,
    seq: u64,
    detail_seq: u64,
    after_load: Option<AfterLoad>,
    /// The edit to re-ask after an `ABORTED` reload, and the approval it was
    /// based on.
    edit_retry: Option<Box<ApprovalInfo>>,
    /// The approval the last edit sent was based on.
    edit_base: Option<Box<ApprovalInfo>>,
    /// The mutation awaiting its outcome.
    pub pending: Option<Pending>,
    /// The direct add awaiting its fresh TOTP code (the key is kept for the
    /// retry after a wrong code).
    pub pending_register: Option<Box<AdminRegisterApplicationRequest>>,
    quitting: bool,
    quit: bool,
    clear: bool,
}

// Everything that can hold a typed password or TOTP code (through a form's
// `Secret` field) is unprintable and uncopyable.
static_assertions::assert_not_impl_any!(App: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(Msg: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(Phase: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(LoginScreen: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(PasswordScreen: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(Modal: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(Form: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(Field: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(form::FieldKind: std::fmt::Debug, std::fmt::Display, Clone);

impl App {
    /// A signed-out application for `endpoint`, showing the first pin.
    #[must_use]
    pub fn new(endpoint: &str, pin_hex: &str, refresh_secs: u64, monochrome: bool) -> Self {
        let chars: Vec<char> = pin_hex.chars().collect();
        let pin_hint = if chars.len() > 16 {
            let head: String = chars[..8].iter().collect();
            let tail: String = chars[chars.len() - 8..].iter().collect();
            format!("{head}…{tail}")
        } else {
            pin_hex.to_string()
        };
        Self {
            phase: Phase::Login(LoginScreen::new(None)),
            screen: Screen::Dashboard,
            modal: None,
            session: None,
            endpoint: endpoint.to_string(),
            pin_hint,
            monochrome,
            requests: ListView::default(),
            request_filters: RequestFilters::default(),
            approvals: ListView::default(),
            approval_filters: ApprovalFilters::default(),
            request_detail: None,
            approval_detail: None,
            dashboard: None,
            accounts: None,
            sessions: None,
            full_hash: false,
            scroll: 0,
            status: None,
            in_flight: 0,
            mono: 0,
            unix: 0,
            last_activity: 0,
            last_refresh: 0,
            refresh_secs,
            seq: 0,
            detail_seq: 0,
            after_load: None,
            edit_retry: None,
            edit_base: None,
            pending: None,
            pending_register: None,
            quitting: false,
            quit: false,
            clear: false,
        }
    }

    /// The UI may exit (after the logout of a quit).
    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// A quit was requested and the logout is in flight.
    #[must_use]
    pub fn is_quitting(&self) -> bool {
        self.quitting
    }

    /// Whether the terminal must be cleared (lock, session end); resets the
    /// request.
    pub fn take_clear(&mut self) -> bool {
        std::mem::take(&mut self.clear)
    }

    /// A command could not be queued (the client task is saturated): forget
    /// it and say so.
    pub fn command_dropped(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.warn("Too many requests in flight; that one was not sent. Try again.");
    }

    /// Whether the session holds `permission`.
    #[must_use]
    pub fn can(&self, permission: &str) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.permissions.iter().any(|p| p == permission))
    }

    /// Seconds left before the idle lock (when signed in).
    #[must_use]
    pub fn idle_left(&self) -> Option<i64> {
        let s = self.session.as_ref()?;
        // The server caps its idle timeout (F20 §7); a missing or hostile
        // value can neither disable nor overflow the client lock.
        let server_idle = s.idle_timeout_secs.clamp(MIN_IDLE_SECS, MAX_IDLE_SECS);
        let lock_after = server_idle - LOCK_MARGIN_SECS;
        let idle = i64::try_from(self.mono.saturating_sub(self.last_activity)).unwrap_or(i64::MAX);
        Some(lock_after.saturating_sub(idle))
    }

    fn info(&mut self, text: impl Into<String>) {
        self.status = Some((Level::Info, text.into()));
    }

    fn warn(&mut self, text: impl Into<String>) {
        self.status = Some((Level::Warn, text.into()));
    }

    fn send(&mut self, cmds: &mut Vec<Cmd>, cmd: Cmd) {
        self.in_flight += 1;
        cmds.push(cmd);
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Apply one message; returns the commands for the client task.
    pub fn update(&mut self, msg: Msg) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        match msg {
            Msg::Tick { mono, unix } => self.tick(mono, unix, &mut cmds),
            Msg::Key(key) => {
                self.last_activity = self.mono;
                self.key(key, &mut cmds);
            }
            Msg::Paste(text) => {
                self.last_activity = self.mono;
                self.paste(&text);
            }
            Msg::Reply(reply) => {
                if !matches!(reply, Reply::SteppedUp(_)) {
                    self.in_flight = self.in_flight.saturating_sub(1);
                }
                self.reply(reply, &mut cmds);
            }
        }
        cmds
    }

    fn tick(&mut self, mono: u64, unix: i64, cmds: &mut Vec<Cmd>) {
        self.mono = mono;
        self.unix = unix;
        if let Phase::Login(l) = &mut self.phase {
            if l.throttled_until.is_some_and(|t| t <= mono) {
                l.throttled_until = None;
            }
        }
        if matches!(self.phase, Phase::ChangePassword(_))
            && !self.quitting
            && self.idle_left().is_some_and(|left| left <= 0)
        {
            self.lock("Locked after inactivity. Sign in again.", cmds);
            return;
        }
        if !matches!(self.phase, Phase::Main) || self.quitting {
            return;
        }
        if self.idle_left().is_some_and(|left| left <= 0) {
            self.lock("Locked after inactivity. Sign in again.", cmds);
            return;
        }
        if self.refresh_secs > 0
            && self.modal.is_none()
            && self.in_flight == 0
            && mono.saturating_sub(self.last_refresh) >= self.refresh_secs
        {
            match self.screen {
                Screen::Dashboard | Screen::Requests | Screen::Approvals => self.refresh(cmds),
                _ => self.last_refresh = mono,
            }
        }
    }

    fn paste(&mut self, text: &Secret) {
        let form = match (&mut self.phase, &mut self.modal) {
            (Phase::Login(l), _) => Some(&mut l.form),
            (Phase::ChangePassword(p), _) => Some(&mut p.form),
            (Phase::Main, Some(Modal::Dialog(d))) => Some(&mut d.form),
            (
                Phase::Main,
                Some(
                    Modal::Search { form, .. }
                    | Modal::Filters { form, .. }
                    | Modal::StepUp { form, .. }
                    | Modal::RegisterTotp { form, .. },
                ),
            ) => Some(form),
            _ => None,
        };
        if let Some(form) = form {
            form.paste(text.expose());
        }
    }

    /// Drop everything shown and go back to the sign-in screen.
    fn wipe(&mut self, notice: &str) {
        let refresh = self.refresh_secs;
        let (endpoint, pin, mono, unix, in_flight, quitting) = (
            std::mem::take(&mut self.endpoint),
            std::mem::take(&mut self.pin_hint),
            self.mono,
            self.unix,
            self.in_flight,
            self.quitting,
        );
        let monochrome = self.monochrome;
        let seq = self.seq;
        *self = Self::new(&endpoint, "", refresh, monochrome);
        self.pin_hint = pin;
        self.mono = mono;
        self.unix = unix;
        self.in_flight = in_flight;
        self.quitting = quitting;
        // Keep the sequence moving so no earlier reply matches.
        self.seq = seq + 1;
        self.phase = Phase::Login(LoginScreen::new(Some(notice.to_string())));
        self.clear = true;
    }

    /// Lock now: wipe the display, log out (token wiped by the client task).
    fn lock(&mut self, notice: &str, cmds: &mut Vec<Cmd>) {
        self.wipe(notice);
        self.send(cmds, Cmd::Logout);
    }

    fn start_quit(&mut self, cmds: &mut Vec<Cmd>) {
        self.quitting = true;
        self.modal = None;
        if matches!(self.phase, Phase::Login(_)) {
            // No session to end; still let the client wipe anything left.
            self.send(cmds, Cmd::Logout);
        } else {
            self.wipe("Signing out…");
            self.send(cmds, Cmd::Logout);
        }
    }

    // ---- keys -----------------------------------------------------------------

    fn key(&mut self, key: Key, cmds: &mut Vec<Cmd>) {
        if self.quitting {
            return;
        }
        if key == Key::CtrlC {
            self.start_quit(cmds);
            return;
        }
        match &mut self.phase {
            Phase::Login(_) => self.login_key(key, cmds),
            Phase::ChangePassword(_) => self.password_key(key, cmds),
            Phase::Main => {
                if key == Key::CtrlL {
                    self.lock("Locked. Sign in again.", cmds);
                    return;
                }
                if self.modal.is_some() {
                    self.modal_key(key, cmds);
                } else {
                    self.screen_key(key, cmds);
                }
            }
        }
    }

    fn login_key(&mut self, key: Key, cmds: &mut Vec<Cmd>) {
        let Phase::Login(l) = &mut self.phase else {
            return;
        };
        if l.busy {
            return;
        }
        match l.form.handle(key) {
            FormEvent::Submit => {
                if l.throttled_until.is_some() {
                    return;
                }
                // Enter moves on until the last field, then submits.
                if l.form.focus + 1 < l.form.fields.len() {
                    l.form.focus += 1;
                    return;
                }
                let username = l.form.text("username").trim().to_string();
                let password_empty = l.form.secret("password").is_none_or(Secret::is_empty);
                let totp_ok = l.form.secret("totp").is_some_and(Secret::is_totp_code);
                if username.is_empty() || password_empty || !totp_ok {
                    l.error = Some("Enter the username, the password and a 6-digit code.".into());
                    return;
                }
                let password = l.form.take_secret("password");
                let totp = l.form.take_secret("totp");
                l.busy = true;
                l.error = None;
                self.session = Some(SessionView {
                    username: username.clone(),
                    ..SessionView::default()
                });
                self.send(
                    cmds,
                    Cmd::Login {
                        username,
                        password,
                        totp,
                    },
                );
            }
            FormEvent::Cancel => self.start_quit(cmds),
            FormEvent::Edited | FormEvent::Ignored => {}
        }
    }

    fn password_key(&mut self, key: Key, cmds: &mut Vec<Cmd>) {
        if key == Key::CtrlL {
            self.lock("Locked. Sign in again.", cmds);
            return;
        }
        let Phase::ChangePassword(p) = &mut self.phase else {
            return;
        };
        if p.busy {
            return;
        }
        match p.form.handle(key) {
            FormEvent::Submit => {
                if p.form.focus + 1 < p.form.fields.len() {
                    p.form.focus += 1;
                    return;
                }
                let new_len = p.form.secret("new").map_or(0, Secret::char_count);
                let same = match (p.form.secret("new"), p.form.secret("repeat")) {
                    (Some(a), Some(b)) => a.expose() == b.expose(),
                    _ => false,
                };
                let totp_ok = p.form.secret("totp").is_some_and(Secret::is_totp_code);
                p.error = if p.form.secret("current").is_none_or(Secret::is_empty) {
                    Some("Enter your current password.".into())
                } else if new_len < 24 {
                    Some("The new password needs at least 24 characters.".into())
                } else if !same {
                    Some("The two new passwords differ.".into())
                } else if !totp_ok {
                    Some("Enter a 6-digit TOTP code.".into())
                } else {
                    None
                };
                if p.error.is_some() {
                    return;
                }
                let current = p.form.take_secret("current");
                let new = p.form.take_secret("new");
                let totp = p.form.take_secret("totp");
                // The repeated password is not sent; wipe it now.
                p.form.clear_secrets();
                p.busy = true;
                self.send(cmds, Cmd::ChangePassword { current, new, totp });
            }
            FormEvent::Cancel => self.start_quit(cmds),
            FormEvent::Edited | FormEvent::Ignored => {}
        }
    }

    fn switch(&mut self, screen: Screen, cmds: &mut Vec<Cmd>) {
        self.screen = screen;
        self.scroll = 0;
        match screen {
            Screen::Dashboard => self.load_dashboard(cmds),
            Screen::Requests if !self.requests.loaded => self.load_requests(cmds),
            Screen::Approvals if !self.approvals.loaded => self.load_approvals(cmds),
            Screen::Accounts => {
                if self.can(perm::ACCOUNT_LIST) {
                    self.send(cmds, Cmd::Query(Query::Accounts));
                }
            }
            Screen::Sessions => self.send(cmds, Cmd::Query(Query::Sessions)),
            _ => {}
        }
    }

    fn refresh(&mut self, cmds: &mut Vec<Cmd>) {
        self.last_refresh = self.mono;
        match self.screen {
            Screen::Dashboard => self.load_dashboard(cmds),
            Screen::Requests => self.load_requests(cmds),
            Screen::Approvals => self.load_approvals(cmds),
            Screen::RequestDetail => {
                if let Some(id) = self
                    .request_detail
                    .as_ref()
                    .and_then(|d| d.request.as_ref())
                    .map(|r| r.request_id.clone())
                {
                    self.load_request(id, cmds);
                }
            }
            Screen::ApprovalDetail => {
                if let Some(id) = self
                    .approval_detail
                    .as_ref()
                    .and_then(|d| d.approval.as_ref())
                    .map(|a| a.approval_id.clone())
                {
                    self.load_approval(id, cmds);
                }
            }
            Screen::Accounts | Screen::Sessions => {
                let s = self.screen;
                self.switch(s, cmds);
            }
            Screen::Hosts => {}
        }
    }

    fn load_dashboard(&mut self, cmds: &mut Vec<Cmd>) {
        self.last_refresh = self.mono;
        let now = self.unix;
        self.send(cmds, Cmd::Query(Query::Dashboard { now }));
    }

    fn load_requests(&mut self, cmds: &mut Vec<Cmd>) {
        if !self.can(perm::REQUEST_LIST)
            && self
                .session
                .as_ref()
                .is_some_and(|s| !s.permissions.is_empty())
        {
            self.requests.error = Some("Requires app_request.list.".into());
            return;
        }
        self.last_refresh = self.mono;
        let seq = self.next_seq();
        self.requests.seq = seq;
        self.requests.loading = true;
        let req = self
            .request_filters
            .to_request(self.requests.ascending, &self.requests.page_token);
        self.send(cmds, Cmd::Query(Query::Requests { seq, req }));
    }

    fn load_approvals(&mut self, cmds: &mut Vec<Cmd>) {
        if !self.can(perm::APPROVAL_LIST)
            && self
                .session
                .as_ref()
                .is_some_and(|s| !s.permissions.is_empty())
        {
            self.approvals.error = Some("Requires approval.list.".into());
            return;
        }
        self.last_refresh = self.mono;
        let seq = self.next_seq();
        self.approvals.seq = seq;
        self.approvals.loading = true;
        let req = self.approval_filters.to_request(
            self.unix,
            self.approvals.ascending,
            &self.approvals.page_token,
        );
        self.send(cmds, Cmd::Query(Query::Approvals { seq, req }));
    }

    fn load_request(&mut self, id: String, cmds: &mut Vec<Cmd>) {
        let seq = self.next_seq();
        self.detail_seq = seq;
        self.send(cmds, Cmd::Query(Query::Request { seq, id }));
    }

    fn load_approval(&mut self, id: String, cmds: &mut Vec<Cmd>) {
        let seq = self.next_seq();
        self.detail_seq = seq;
        self.send(cmds, Cmd::Query(Query::Approval { seq, id }));
    }

    /// Refuse a key the session may not use, saying why.
    fn gate(&mut self, permission: &str, label: &str) -> bool {
        if self.can(permission) {
            return true;
        }
        self.warn(format!(
            "{label}: requires {permission} (your groups do not grant it)"
        ));
        false
    }

    #[allow(clippy::too_many_lines)] // one arm per key of the F21 §4 key map.
    fn screen_key(&mut self, key: Key, cmds: &mut Vec<Cmd>) {
        // Screen-specific keys first.
        match (self.screen, key) {
            (Screen::Requests | Screen::Approvals, Key::Up | Key::Char('k')) => {
                self.list_move(-1);
                return;
            }
            (Screen::Requests | Screen::Approvals, Key::Down | Key::Char('j')) => {
                self.list_move(1);
                return;
            }
            (Screen::Requests | Screen::Approvals, Key::PageUp) => {
                self.list_move(-10);
                return;
            }
            (Screen::Requests | Screen::Approvals, Key::PageDown) => {
                self.list_move(10);
                return;
            }
            (Screen::Requests | Screen::Approvals, Key::Char('g') | Key::Home) => {
                self.list_move(isize::MIN / 2);
                return;
            }
            (Screen::Requests | Screen::Approvals, Key::Char('G') | Key::End) => {
                self.list_move(isize::MAX / 2);
                return;
            }
            (Screen::Requests, Key::Enter) => {
                if let Some(id) = self.selected_request_id() {
                    self.after_load = None;
                    self.load_request(id, cmds);
                }
                return;
            }
            (Screen::Approvals, Key::Enter) => {
                if let Some(id) = self
                    .approvals
                    .items
                    .get(self.approvals.selected)
                    .map(|a| a.approval_id.clone())
                {
                    self.load_approval(id, cmds);
                }
                return;
            }
            (Screen::Requests | Screen::RequestDetail, Key::Char('a')) => {
                if self.gate(perm::APPROVE, "a approve") {
                    self.decide(AfterLoad::Approve, cmds);
                }
                return;
            }
            (Screen::Requests | Screen::RequestDetail, Key::Char('d')) => {
                if self.gate(perm::DENY, "d deny") {
                    self.decide(AfterLoad::Deny, cmds);
                }
                return;
            }
            (Screen::Requests | Screen::Approvals, Key::Char('A')) => {
                if self.gate(perm::DIRECT_REGISTER, "A add application") {
                    let d = Dialog::register(self.can(perm::APPROVE));
                    self.modal = Some(Modal::Dialog(Box::new(d)));
                }
                return;
            }
            (Screen::Requests | Screen::Approvals, Key::Char('/')) => {
                let (text, list) = if self.screen == Screen::Requests {
                    (self.request_filters.text.clone(), ListKind::Requests)
                } else {
                    (self.approval_filters.text.clone(), ListKind::Approvals)
                };
                self.modal = Some(Modal::Search {
                    form: Form::new(vec![Field::text("text", "Search", &text, MAX_TEXT)
                        .with_hint("≤ 128, Enter to search")]),
                    list,
                });
                return;
            }
            (Screen::Requests, Key::Char('f')) => {
                self.modal = Some(Modal::Filters {
                    form: self.request_filters.form(),
                    list: ListKind::Requests,
                });
                return;
            }
            (Screen::Approvals, Key::Char('f')) => {
                self.modal = Some(Modal::Filters {
                    form: self.approval_filters.form(),
                    list: ListKind::Approvals,
                });
                return;
            }
            (Screen::Requests, Key::Char('s')) => {
                self.requests.ascending = !self.requests.ascending;
                self.requests.reset_paging();
                self.load_requests(cmds);
                return;
            }
            (Screen::Approvals, Key::Char('s')) => {
                self.approvals.ascending = !self.approvals.ascending;
                self.approvals.reset_paging();
                self.load_approvals(cmds);
                return;
            }
            (Screen::Requests, Key::Char('n')) => {
                if !self.requests.next_token.is_empty() {
                    let next = std::mem::take(&mut self.requests.next_token);
                    let cur = std::mem::replace(&mut self.requests.page_token, next);
                    self.requests.previous.push(cur);
                    self.requests.selected = 0;
                    self.load_requests(cmds);
                }
                return;
            }
            (Screen::Approvals, Key::Char('n')) => {
                if !self.approvals.next_token.is_empty() {
                    let next = std::mem::take(&mut self.approvals.next_token);
                    let cur = std::mem::replace(&mut self.approvals.page_token, next);
                    self.approvals.previous.push(cur);
                    self.approvals.selected = 0;
                    self.load_approvals(cmds);
                }
                return;
            }
            (Screen::Requests, Key::Char('p')) => {
                if let Some(prev) = self.requests.previous.pop() {
                    self.requests.page_token = prev;
                    self.requests.selected = 0;
                    self.load_requests(cmds);
                }
                return;
            }
            (Screen::Approvals, Key::Char('p')) => {
                if let Some(prev) = self.approvals.previous.pop() {
                    self.approvals.page_token = prev;
                    self.approvals.selected = 0;
                    self.load_approvals(cmds);
                }
                return;
            }
            (Screen::Requests, Key::Char('c')) => {
                self.request_filters = RequestFilters::default();
                self.requests.reset_paging();
                self.load_requests(cmds);
                return;
            }
            (Screen::Approvals, Key::Char('c')) => {
                self.approval_filters = ApprovalFilters::default();
                self.approvals.reset_paging();
                self.load_approvals(cmds);
                return;
            }
            (Screen::RequestDetail | Screen::ApprovalDetail, Key::Char('h')) => {
                self.full_hash = !self.full_hash;
                return;
            }
            (Screen::RequestDetail | Screen::ApprovalDetail, Key::Up | Key::Char('k')) => {
                self.scroll = self.scroll.saturating_sub(1);
                return;
            }
            (Screen::RequestDetail | Screen::ApprovalDetail, Key::Down | Key::Char('j')) => {
                self.scroll = self.scroll.saturating_add(1).min(500);
                return;
            }
            // Back to the list; reloaded when a mutation made it stale.
            (Screen::RequestDetail, Key::Esc | Key::Backspace) => {
                self.screen = Screen::Requests;
                if !self.requests.loaded && !self.requests.loading {
                    self.load_requests(cmds);
                }
                return;
            }
            (Screen::ApprovalDetail, Key::Esc | Key::Backspace) => {
                self.screen = Screen::Approvals;
                if !self.approvals.loaded && !self.approvals.loading {
                    self.load_approvals(cmds);
                }
                return;
            }
            (Screen::RequestDetail, Key::Char('l')) => {
                if let Some(lineage) = self
                    .request_detail
                    .as_ref()
                    .and_then(|d| d.request.as_ref())
                    .map(|r| r.lineage_id.clone())
                {
                    self.approval_filters = ApprovalFilters::lineage(&lineage);
                    self.approvals.reset_paging();
                    self.screen = Screen::Approvals;
                    self.load_approvals(cmds);
                }
                return;
            }
            (Screen::ApprovalDetail, Key::Char('e')) => {
                if self.gate(perm::UPDATE, "e edit") {
                    if let Some(a) = self.current_approval() {
                        self.modal = Some(Modal::Dialog(Box::new(Dialog::edit(&a))));
                    }
                }
                return;
            }
            (Screen::ApprovalDetail, Key::Char('x')) => {
                if self.gate(perm::REVOKE, "x revoke") {
                    if let Some(a) = self.current_approval() {
                        if a.state == 3 {
                            self.warn("This approval is already revoked.");
                        } else {
                            self.modal = Some(Modal::Dialog(Box::new(Dialog::revoke(&a))));
                        }
                    }
                }
                return;
            }
            (Screen::ApprovalDetail | Screen::RequestDetail, Key::Char('z')) => {
                if self.gate(perm::UPDATE, "z freeze") {
                    self.open_freeze();
                }
                return;
            }
            _ => {}
        }
        // Global keys.
        match key {
            Key::Char(c @ '1'..='6') => {
                let i = (c as usize) - ('1' as usize);
                self.switch(Screen::of_tab(i), cmds);
            }
            Key::Tab => {
                let i = (self.screen.tab() + 1) % TABS.len();
                self.switch(Screen::of_tab(i), cmds);
            }
            Key::BackTab => {
                let i = (self.screen.tab() + TABS.len() - 1) % TABS.len();
                self.switch(Screen::of_tab(i), cmds);
            }
            Key::Char('?') => self.modal = Some(Modal::Help),
            Key::Char('q') => self.modal = Some(Modal::ConfirmQuit),
            Key::Char('r') => self.refresh(cmds),
            _ => {}
        }
    }

    fn list_move(&mut self, delta: isize) {
        if self.screen == Screen::Requests {
            self.requests.move_by(delta);
        } else {
            self.approvals.move_by(delta);
        }
    }

    fn selected_request_id(&self) -> Option<String> {
        self.requests
            .items
            .get(self.requests.selected)
            .map(|r| r.request_id.clone())
    }

    fn current_approval(&self) -> Option<ApprovalInfo> {
        self.approval_detail
            .as_ref()
            .and_then(|d| d.approval.clone())
    }

    fn open_freeze(&mut self) {
        let (lineage, label, frozen) = if self.screen == Screen::RequestDetail {
            let Some(d) = &self.request_detail else {
                return;
            };
            let Some(r) = &d.request else { return };
            (
                r.lineage_id.clone(),
                r.canonical_path.clone(),
                Some(d.lineage_auto_update_frozen),
            )
        } else {
            let Some(a) = self.current_approval() else {
                return;
            };
            (a.lineage_id.clone(), a.canonical_path.clone(), None)
        };
        self.modal = Some(Modal::Dialog(Box::new(Dialog::freeze(
            &lineage, &label, frozen,
        ))));
    }

    /// `a` / `d`: open the dialog on the loaded request, loading it first
    /// from the list.
    fn decide(&mut self, what: AfterLoad, cmds: &mut Vec<Cmd>) {
        if self.screen == Screen::RequestDetail {
            self.open_decision(what);
            return;
        }
        if let Some(id) = self.selected_request_id() {
            self.after_load = Some(what);
            self.load_request(id, cmds);
        }
    }

    fn open_decision(&mut self, what: AfterLoad) {
        let Some(detail) = &self.request_detail else {
            return;
        };
        let Some(request) = &detail.request else {
            return;
        };
        if request.state != 1 {
            self.warn("Only a pending request can be approved or denied.");
            return;
        }
        let dialog = match what {
            AfterLoad::Approve => Dialog::approve(detail),
            AfterLoad::Deny => Some(Dialog::deny(request)),
        };
        if let Some(d) = dialog {
            self.modal = Some(Modal::Dialog(Box::new(d)));
        }
    }

    #[allow(clippy::too_many_lines)] // one arm per modal.
    fn modal_key(&mut self, key: Key, cmds: &mut Vec<Cmd>) {
        let Some(modal) = self.modal.take() else {
            return;
        };
        let unix = self.unix;
        self.modal = match modal {
            Modal::Help => match key {
                Key::Esc | Key::Char('?' | 'q') | Key::Enter => None,
                _ => Some(Modal::Help),
            },
            Modal::Message { title, lines } => match key {
                Key::Esc | Key::Enter | Key::Char(' ' | 'q') => None,
                _ => Some(Modal::Message { title, lines }),
            },
            Modal::ConfirmQuit => match key {
                Key::Char('y' | 'Y') => {
                    self.start_quit(cmds);
                    None
                }
                Key::Char('n' | 'N') | Key::Esc => None,
                _ => Some(Modal::ConfirmQuit),
            },
            Modal::Search { mut form, list } => match form.handle(key) {
                FormEvent::Submit => {
                    let text = form.text("text").trim().to_string();
                    if list == ListKind::Requests {
                        self.request_filters.text = text;
                        self.requests.reset_paging();
                        self.load_requests(cmds);
                    } else {
                        self.approval_filters.text = text;
                        self.approvals.reset_paging();
                        self.load_approvals(cmds);
                    }
                    None
                }
                FormEvent::Cancel => None,
                _ => Some(Modal::Search { form, list }),
            },
            Modal::Filters { mut form, list } => match form.handle(key) {
                FormEvent::Submit => {
                    if list == ListKind::Requests {
                        match RequestFilters::from_form(&mut form) {
                            Some(f) => {
                                self.request_filters = f;
                                self.requests.reset_paging();
                                self.load_requests(cmds);
                                None
                            }
                            None => Some(Modal::Filters { form, list }),
                        }
                    } else {
                        match ApprovalFilters::from_form(&mut form) {
                            Some(f) => {
                                self.approval_filters = f;
                                self.approvals.reset_paging();
                                self.load_approvals(cmds);
                                None
                            }
                            None => Some(Modal::Filters { form, list }),
                        }
                    }
                }
                FormEvent::Cancel => None,
                _ => Some(Modal::Filters { form, list }),
            },
            Modal::Dialog(mut d) => match d.on_key(key, unix) {
                Outcome::Stay => Some(Modal::Dialog(d)),
                Outcome::Cancel => {
                    self.info("Cancelled; nothing was sent.");
                    None
                }
                Outcome::Send(m) => {
                    // An edit remembers the approval it was based on, so an
                    // `ABORTED` answer is diffed against that, whatever the
                    // screen shows by then.
                    self.edit_base = match &d.ctx {
                        dialogs::Ctx::Edit { approval } => Some(approval.clone()),
                        _ => None,
                    };
                    self.pending = Some(Pending {
                        mutation: (*m).clone(),
                        stepped_up: false,
                    });
                    self.info("Sending…");
                    self.send(cmds, Cmd::Mutate(*m));
                    None
                }
                Outcome::Register(req) => {
                    self.pending_register = Some(req);
                    Some(totp_modal(true, None))
                }
            },
            Modal::StepUp { mut form, error } => match form.handle(key) {
                FormEvent::Submit => {
                    let ok = form.secret("totp").is_some_and(Secret::is_totp_code);
                    match (&mut self.pending, ok) {
                        (Some(p), true) => {
                            let totp = form.take_secret("totp");
                            p.stepped_up = true;
                            let retry = p.mutation.clone();
                            self.info("Verifying the code…");
                            self.send(cmds, Cmd::StepUp { totp, retry });
                            None
                        }
                        (Some(_), false) => Some(Modal::StepUp {
                            form,
                            error: Some("Enter the 6-digit code.".into()),
                        }),
                        (None, _) => None,
                    }
                }
                FormEvent::Cancel => {
                    self.pending = None;
                    self.info("Cancelled; nothing more was sent.");
                    None
                }
                _ => Some(Modal::StepUp { form, error }),
            },
            Modal::RegisterTotp { mut form, error } => match form.handle(key) {
                FormEvent::Submit => {
                    let ok = form.secret("totp").is_some_and(Secret::is_totp_code);
                    match (&self.pending_register, ok) {
                        (Some(req), true) => {
                            let totp = form.take_secret("totp");
                            let req = req.clone();
                            self.info("Sending the registration…");
                            self.send(cmds, Cmd::Register { req, totp });
                            None
                        }
                        (Some(_), false) => Some(Modal::RegisterTotp {
                            form,
                            error: Some("Enter the 6-digit code.".into()),
                        }),
                        (None, _) => None,
                    }
                }
                FormEvent::Cancel => {
                    self.pending_register = None;
                    self.info("Cancelled; nothing was sent.");
                    None
                }
                _ => Some(Modal::RegisterTotp { form, error }),
            },
        };
    }

    // ---- replies --------------------------------------------------------------

    #[allow(clippy::too_many_lines)] // one arm per reply.
    fn reply(&mut self, reply: Reply, cmds: &mut Vec<Cmd>) {
        match reply {
            Reply::LoggedOut => {
                if self.quitting {
                    self.quit = true;
                }
            }
            Reply::LoggedIn(info) => self.logged_in(info, cmds),
            Reply::LoginFailed(e) => {
                if let Phase::Login(l) = &mut self.phase {
                    l.busy = false;
                    l.form.clear_secrets();
                    l.form.focus_on("password");
                    l.error = Some(match e {
                        LoginError::Connect(why) => {
                            format!("Cannot reach the admin listener (nothing was sent): {why}")
                        }
                        LoginError::Rejected => {
                            "Sign-in failed. Check the username, password and code.".into()
                        }
                        LoginError::Throttled(secs) => {
                            l.throttled_until =
                                Some(self.mono.saturating_add(secs.min(MAX_THROTTLE_SECS)));
                            "Too many attempts. Wait for the countdown.".into()
                        }
                        LoginError::Other(e) => format!("Sign-in failed: {}", e.describe()),
                    });
                    self.session = None;
                } else if let Phase::ChangePassword(p) = &mut self.phase {
                    p.busy = false;
                    p.error = Some("Cannot reach the admin listener.".into());
                }
            }
            Reply::SessionEnded => {
                if !matches!(self.phase, Phase::Login(_)) {
                    self.wipe("Session ended. Sign in again.");
                }
            }
            Reply::PasswordChanged(_) => {
                if matches!(self.phase, Phase::ChangePassword(_)) {
                    self.phase = Phase::Main;
                    self.info("Password changed; your other sessions were ended.");
                    self.enter_main(cmds);
                }
            }
            Reply::Failed(op, e) if *op == Op::ChangePassword => {
                if let Phase::ChangePassword(p) = &mut self.phase {
                    p.busy = false;
                    p.form.clear_secrets();
                    p.form.focus = 0;
                    p.error = Some(match e.reason.as_str() {
                        "password_policy" => {
                            "The new password does not meet the policy (length, history, common passwords).".into()
                        }
                        "invalid_credentials" => {
                            "The current password or the code was not accepted.".into()
                        }
                        _ => e.describe(),
                    });
                }
            }
            // Below: only while signed in. Replies to reads sent before a
            // lock or a session end are dropped here.
            _ if !matches!(self.phase, Phase::Main) => {}
            Reply::WhoAmI(w) => {
                if let Some(s) = &mut self.session {
                    s.permissions = w.permissions;
                    s.groups = w.groups;
                    s.display_name = w.display_name;
                    s.aal = w.aal;
                }
            }
            Reply::SteppedUp(until) => {
                if let Some(s) = &mut self.session {
                    s.step_up_until = Some(until);
                }
                self.info("Step-up accepted; sending again with the same idempotency key.");
            }
            Reply::Requests(seq, resp) => {
                if seq == self.requests.seq {
                    self.requests.loading = false;
                    self.requests.loaded = true;
                    self.requests.error = None;
                    self.requests.items = resp.items;
                    self.requests.next_token = resp.next_page_token;
                    self.requests.move_by(0);
                }
            }
            Reply::Approvals(seq, resp) => {
                if seq == self.approvals.seq {
                    self.approvals.loading = false;
                    self.approvals.loaded = true;
                    self.approvals.error = None;
                    self.approvals.items = resp.items;
                    self.approvals.next_token = resp.next_page_token;
                    self.approvals.move_by(0);
                }
            }
            Reply::Request(seq, detail) => {
                if seq == self.detail_seq {
                    self.request_detail = Some(detail);
                    self.screen = Screen::RequestDetail;
                    self.scroll = 0;
                    if let Some(what) = self.after_load.take() {
                        self.open_decision(what);
                    }
                }
            }
            Reply::Approval(seq, detail) => {
                if seq == self.detail_seq {
                    let before = self.edit_retry.take();
                    self.approval_detail = Some(detail);
                    self.screen = Screen::ApprovalDetail;
                    self.scroll = 0;
                    if let Some(old) = before {
                        self.reask_edit(&old);
                    }
                }
            }
            Reply::Dashboard(c) => self.dashboard = Some(c),
            Reply::Accounts(a) => self.accounts = Some(a),
            Reply::Sessions(s) => self.sessions = Some(s),
            Reply::Mutated(done) => self.mutated(*done, cmds),
            Reply::Registered(r) => self.registered(&r, cmds),
            Reply::Failed(op, e) => self.failed(*op, &e, cmds),
        }
    }

    fn logged_in(&mut self, info: LoginInfo, cmds: &mut Vec<Cmd>) {
        // A quit while the sign-in was in flight: the `Logout` queued behind
        // it ends the new session; show nothing of it meanwhile.
        if self.quitting {
            return;
        }
        let Phase::Login(l) = &mut self.phase else {
            return;
        };
        l.busy = false;
        let username = self
            .session
            .as_ref()
            .map(|s| s.username.clone())
            .unwrap_or_default();
        self.session = Some(SessionView {
            username,
            display_name: info.display_name,
            groups: info.groups,
            permissions: Vec::new(),
            aal: info.aal,
            idle_timeout_secs: info.idle_timeout_secs,
            step_up_until: None,
        });
        self.last_activity = self.mono;
        self.clear = true;
        if info.password_change_required {
            self.phase = Phase::ChangePassword(PasswordScreen::new());
            return;
        }
        self.phase = Phase::Main;
        self.enter_main(cmds);
    }

    fn enter_main(&mut self, cmds: &mut Vec<Cmd>) {
        self.screen = Screen::Dashboard;
        self.send(cmds, Cmd::Query(Query::WhoAmI));
        self.load_dashboard(cmds);
    }

    fn after_mutation(&mut self, cmds: &mut Vec<Cmd>) {
        // Refresh after every mutation (stale-data mitigation).
        self.requests.loaded = false;
        self.approvals.loaded = false;
        match self.screen {
            Screen::RequestDetail | Screen::ApprovalDetail => self.refresh(cmds),
            Screen::Requests => self.load_requests(cmds),
            Screen::Approvals => self.load_approvals(cmds),
            _ => {}
        }
    }

    fn mutated(&mut self, done: Mutated, cmds: &mut Vec<Cmd>) {
        self.pending = None;
        let (title, lines) = match done {
            Mutated::Approved(r) => {
                let id = r
                    .approval
                    .as_ref()
                    .map(|a| short_id("A", &a.approval_id))
                    .unwrap_or_default();
                let mut lines = vec![
                    format!(
                        "Approval {id} created; host generation {}.",
                        r.allowlist_generation
                    ),
                    "The host picks it up within 5 minutes.".to_string(),
                ];
                if !r.revoked_approval_ids.is_empty() {
                    lines.push(format!(
                        "Also revoked: {}",
                        r.revoked_approval_ids
                            .iter()
                            .map(|i| short_id("A", i))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if r.same_actor {
                    lines.push("Audited as approved by the same person who requested it.".into());
                }
                ("Approved".to_string(), lines)
            }
            Mutated::Denied(_) => (
                "Denied".to_string(),
                vec!["The request was denied; the requester sees the reason.".to_string()],
            ),
            Mutated::Updated(r) => (
                "Updated".to_string(),
                vec![format!(
                    "Approval updated; host generation {}.",
                    r.allowlist_generation
                )],
            ),
            Mutated::Revoked(r) => (
                "Revoked".to_string(),
                vec![
                    format!("Revoked; host generation {}.", r.allowlist_generation),
                    "The host loses access at its next sync (within 5 minutes).".to_string(),
                ],
            ),
            Mutated::Frozen(f) => (
                if f { "Frozen" } else { "Unfrozen" }.to_string(),
                vec![if f {
                    "Auto-updates of this lineage now go to manual review.".to_string()
                } else {
                    "Auto-updates of this lineage apply again.".to_string()
                }],
            ),
        };
        self.info(format!("{title}."));
        self.modal = Some(Modal::Message { title, lines });
        self.after_mutation(cmds);
    }

    fn registered(&mut self, r: &AdminRegisterApplicationResponse, cmds: &mut Vec<Cmd>) {
        self.pending_register = None;
        let req = r
            .request
            .as_ref()
            .map_or_else(|| "—".into(), |q| short_id("R", &q.request_id));
        let apr = r
            .approval
            .as_ref()
            .map_or_else(|| "—".into(), |a| short_id("A", &a.approval_id));
        let (title, lines) = if r.queued {
            (
                "Queued for another approver",
                vec![
                    format!("Request {req} is PENDING: strict separation of duties is on."),
                    "A different approver must decide it.".to_string(),
                ],
            )
        } else if r.deduplicated && r.request.is_none() {
            (
                "Already approved",
                vec![format!(
                    "An active approval ({apr}) already covers this binary; nothing was added."
                )],
            )
        } else {
            (
                "Registered and approved",
                vec![
                    format!(
                        "Request {req}, approval {apr}; host generation {}.",
                        r.allowlist_generation
                    ),
                    "The host picks it up within 5 minutes.".to_string(),
                    "Audited as AppApprovedBySameActor.".to_string(),
                ],
            )
        };
        self.info(format!("{title}."));
        self.modal = Some(Modal::Message {
            title: title.to_string(),
            lines,
        });
        self.after_mutation(cmds);
    }

    fn failed(&mut self, op: Op, e: &RpcError, cmds: &mut Vec<Cmd>) {
        match op {
            Op::Query(q) => {
                let text = e.describe();
                match q {
                    Query::Requests { seq, .. } if seq == self.requests.seq => {
                        self.requests.loading = false;
                        self.requests.error = Some(text);
                    }
                    Query::Approvals { seq, .. } if seq == self.approvals.seq => {
                        self.approvals.loading = false;
                        self.approvals.error = Some(text);
                    }
                    Query::Request { .. } | Query::Approval { .. } => {
                        self.after_load = None;
                        self.edit_retry = None;
                        self.warn(text);
                    }
                    _ => self.warn(text),
                }
            }
            Op::Mutation(m) => {
                let stepped = self.pending.as_ref().is_some_and(|p| p.stepped_up);
                if e.is_step_up_required() && !stepped {
                    // Keep the pending mutation: the retry reuses its key.
                    self.pending = Some(Pending {
                        mutation: m,
                        stepped_up: false,
                    });
                    self.modal = Some(totp_modal(false, None));
                    self.warn("This operation needs a fresh TOTP code (step-up).");
                    return;
                }
                self.pending = None;
                if e.is_step_up_required() {
                    self.modal = Some(Modal::Message {
                        title: "Not sent".into(),
                        lines: vec![
                            "The server asked for a step-up again right after one; nothing more was sent.".into(),
                        ],
                    });
                    return;
                }
                if e.code == tonic::Code::Aborted {
                    if let Mutation::Update(u) = &m {
                        // Reload, show what changed, and ask again.
                        if let Some(old) = self
                            .edit_base
                            .take()
                            .filter(|b| b.approval_id == u.approval_id)
                        {
                            self.edit_retry = Some(old);
                            self.load_approval(u.approval_id.clone(), cmds);
                            self.warn("The approval changed meanwhile; reloading.");
                            return;
                        }
                    }
                }
                self.modal = Some(Modal::Message {
                    title: "Refused".into(),
                    lines: vec![e.describe(), "Nothing was changed.".into()],
                });
                self.after_mutation(cmds);
            }
            Op::StepUp(m) => {
                // A wrong code: ask again for the same operation.
                self.pending = Some(Pending {
                    mutation: m,
                    stepped_up: false,
                });
                let why = if e.code == tonic::Code::Unauthenticated {
                    "The code was not accepted.".to_string()
                } else {
                    e.describe()
                };
                self.modal = Some(totp_modal(false, Some(why)));
            }
            Op::Register(req) => {
                if e.code == tonic::Code::Unauthenticated {
                    // A wrong code changes nothing; the retry reuses the key.
                    self.pending_register = Some(req);
                    self.modal = Some(totp_modal(
                        true,
                        Some("The code was not accepted; nothing was registered.".into()),
                    ));
                } else {
                    self.pending_register = None;
                    self.modal = Some(Modal::Message {
                        title: "Refused".into(),
                        lines: vec![e.describe(), "Nothing was registered.".into()],
                    });
                }
            }
            Op::ChangePassword => {}
        }
    }

    /// After `ABORTED` on an edit: show what changed and reopen the dialog on
    /// the new row version.
    fn reask_edit(&mut self, old: &ApprovalInfo) {
        let Some(new) = self.current_approval() else {
            return;
        };
        let mut changes = Vec::new();
        let mut diff = |what: &str, a: String, b: String| {
            if a != b {
                changes.push(format!("{what}: {a} → {b}"));
            }
        };
        diff("state", old.state.to_string(), new.state.to_string());
        diff(
            "update policy",
            old.update_policy.to_string(),
            new.update_policy.to_string(),
        );
        diff(
            "continuity",
            old.continuity.to_string(),
            new.continuity.to_string(),
        );
        diff(
            "expires",
            timefmt::datetime(old.expires_at),
            timefmt::datetime(new.expires_at),
        );
        diff(
            "user scope",
            old.user_scope.to_string(),
            new.user_scope.to_string(),
        );
        diff(
            "path match",
            old.path_match.to_string(),
            new.path_match.to_string(),
        );
        diff("note", old.note.clone(), new.note.clone());
        if new.state == 3 {
            self.modal = Some(Modal::Message {
                title: "Changed meanwhile".into(),
                lines: vec!["The approval was revoked by someone else; nothing was sent.".into()],
            });
            return;
        }
        let mut d = Dialog::edit(&new);
        d.notice = Some(if changes.is_empty() {
            "Changed meanwhile (row version moved). Review your edit again.".to_string()
        } else {
            format!(
                "Changed meanwhile: {}. Review your edit again.",
                changes.join("; ")
            )
        });
        self.modal = Some(Modal::Dialog(Box::new(d)));
    }
}

/// The TOTP prompt (step-up, or the fresh code of a direct add).
fn totp_modal(register: bool, error: Option<String>) -> Modal {
    let form = Form::new(vec![Field::secret("totp", "TOTP code", true, 8)]);
    if register {
        Modal::RegisterTotp { form, error }
    } else {
        Modal::StepUp { form, error }
    }
}

#[cfg(test)]
mod tests;
