//! The admin window's state machine (F22 §3), headless: sign-in on one
//! screen (F23: leaving the user name asks `BeginLogin` which factors it may
//! use, then the password with a TOTP code or a security key appear below;
//! the F20 calls and their order are unchanged), token enrollment, the
//! signed-in summary, second-factor management, the request and approval
//! views (a decision that asks for a step-up is sent once more after it),
//! the step-up prompt (which also takes the fresh second factor every
//! "add application" needs, T284), sign-out and the idle lock. Input goes in as calls,
//! [`Reply`]s from the worker through [`Flow::on_reply`], and out come
//! [`Effect`]s.

//! The models hold the typed secrets; [`FlowView`] holds none (masks are
//! lengths) and never the session token, which only the worker has. Every
//! server string in a view is escaped first (`crate::text::display_safe`).

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use ferrogate_admin_client::approvals::register::{
    AdminRegisterApplicationRequest, AdminRegisterApplicationResponse,
};
use ferrogate_admin_client::client::{LoginInfo, Methods};
use ferrogate_admin_client::error::{ClientError, Code};
use ferrogate_admin_client::factors::{AddNonce, AddOffer, FactorInfo, FactorMethod};
use ferrogate_admin_client::webauthn::AuthenticatorError;
use serde::Serialize;

use super::enroll::{EnrollField, EnrollStage, EnrollView, EnrollWizard};
use super::factors::{FactorField, FactorsPanel, FactorsView};
use super::login::{Field, LoginModel, LoginView, Stage, Submission};
use super::secret::Secret;
use super::seed::SeedDisplay;
use super::session::{Cmd, FactorChoice, Reply};
use super::views::{AdminViews, Tab, ViewAction, ViewsEvent, ViewsView};
use crate::text::display_safe;

/// Idle limit before the server's timeout is known (F20 §7: 15 min).
pub const DEFAULT_IDLE: Duration = Duration::from_mins(15);
/// The client locks this long before the server's idle timeout (F22 §3).
pub const IDLE_MARGIN: Duration = Duration::from_secs(30);
/// Bounds applied to the server's idle timeout, in seconds (a hostile or
/// broken value can neither disable nor shorten the lock to nothing).
pub const SERVER_IDLE_BOUNDS: (i64, i64) = (60, 15 * 60);
/// Longest display name or group name shown, in characters.
pub const MAX_SHOWN: usize = 64;
/// How long a `BeginLogin` answer is trusted (F20: a login nonce lives
/// 2 min). An older one is asked again before a submit. The nonce itself
/// never reaches the window: the worker's sign-in takes a fresh one right
/// before `Login`.
pub const OFFER_TTL: Duration = Duration::from_mins(2);

/// Something the window must do.
pub enum Effect {
    /// Hand this command to the worker.
    Send(Cmd),
    /// End the session now (the worker logs it out).
    EndSession,
}

static_assertions::assert_not_impl_any!(Effect: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(Flow: std::fmt::Debug, std::fmt::Display, Clone);

/// What the worker is doing for the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Busy {
    /// Asking which factors the account may use.
    Offer,
    /// Signing in (`key`: waiting for a key touch first).
    SignIn {
        /// A security key was chosen.
        key: bool,
    },
    /// Stepping up (`key`: waiting for a key touch first).
    StepUp {
        /// A security key was chosen.
        key: bool,
    },
    /// Enrolling with a token (`key`: waiting for a key touch).
    Enroll {
        /// The platform's key is prompting.
        key: bool,
    },
    /// Managing second factors (`key`: waiting for a key touch).
    Factors {
        /// The platform's key is prompting.
        key: bool,
    },
    /// Loading requests or approvals, or sending a decision.
    Views,
    /// Adding an application (`key`: waiting for a key touch first).
    Register {
        /// A security key was chosen.
        key: bool,
    },
}

/// Why something did not work, as the window words it (generic, F20 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Problem {
    /// The server could not be reached or failed the pin; nothing was sent.
    Unreachable,
    /// Sign-in or step-up failed (any credential).
    Rejected,
    /// Too many attempts; see `throttle_secs_left`.
    Throttled,
    /// That factor is not accepted for this account here; nothing was sent.
    NotOffered,
    /// No security-key support in this build on this platform.
    KeyUnavailable,
    /// The key prompt was cancelled or timed out; nothing was sent.
    KeyCancelled,
    /// The key did not answer properly; nothing was sent.
    KeyFailed,
    /// Another server error.
    ServerError,
    /// The code is not 6 to 8 digits, or a field is missing.
    Incomplete,
    /// The worker is busy or gone.
    NotSent,
    /// Enrollment refused: an unknown, spent or expired token, or a wrong
    /// code or key (one generic message).
    EnrollmentRejected,
    /// The new password breaks the server's policy.
    PasswordPolicy,
    /// A factor change was refused: a wrong code or proof, or the offer
    /// expired; nothing changed (start again).
    FactorRejected,
    /// The account's last factor is never removed.
    LastFactor,
}

/// A message above the form or the summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Notice {
    /// Something failed.
    Problem(Problem),
    /// Signed out.
    SignedOut,
    /// Locked after inactivity; everything was wiped.
    Locked,
    /// The server ended the session.
    SessionEnded,
    /// The password expired: change it elsewhere, then sign in again.
    PasswordExpired,
    /// The FIDO2 policy requires registering a key first.
    KeyRegistrationRequired,
    /// The step-up succeeded.
    SteppedUp,
    /// The step-up is needed first (then the action goes on).
    StepUpFirst,
    /// Enrollment completed: sign in with the new password and factor.
    Enrolled,
    /// A factor was added.
    FactorAdded,
    /// A factor was removed (the account's other sessions ended).
    FactorRemoved,
    /// The required key was registered: sign in again with it.
    KeyRegistered,
}

/// The signed-in summary (server strings escaped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    /// Display name.
    pub display_name: String,
    /// Group names.
    pub groups: Vec<String>,
    /// Assurance level (2 TOTP, 3 device-bound key).
    pub aal: u32,
    /// Seconds without activity before the client locks.
    pub idle_lock_secs: u64,
    /// End of the step-up window (Unix seconds), after a step-up.
    pub step_up_until: Option<i64>,
    /// The factors the account may use (for the step-up prompt).
    pub methods: Methods,
    /// The FIDO2 policy holds this session to registering a key.
    pub restricted: bool,
}

/// The step-up prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepUpView {
    /// Characters in the code (mask).
    pub code_len: usize,
    /// Why the last attempt failed.
    pub error: Option<Problem>,
    /// Whether the code can be submitted.
    pub can_submit_code: bool,
    /// Whether a key can be used.
    pub can_submit_key: bool,
    /// The fresh second factor of an "add application", not a step-up.
    pub for_add: bool,
}

/// Everything the window draws. Holds no secret and no token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowView {
    /// The sign-in form (meaningful while not signed in).
    pub login: LoginView,
    /// What the worker is doing.
    pub busy: Option<Busy>,
    /// Whether this build has a security-key backend here.
    pub key_available: bool,
    /// The message to show.
    pub notice: Option<Notice>,
    /// Seconds left of a throttle lock.
    pub throttle_secs_left: Option<u64>,
    /// The session, once signed in.
    pub session: Option<SessionView>,
    /// The step-up prompt, when open.
    pub step_up: Option<StepUpView>,
    /// The enrollment wizard, when open (signed out).
    pub enroll: Option<EnrollView>,
    /// The second-factor panel, when open (signed in).
    pub factors: Option<FactorsView>,
    /// The request and approval views, when open (signed in).
    pub views: Option<ViewsView>,
}

struct Session {
    info: LoginInfo,
    step_up_until: Option<i64>,
    /// Held to registering a key (FIDO2 policy).
    restricted: bool,
    /// Whether sign-in offered a code (the policy may forbid one).
    signin_totp: bool,
}

struct StepUpForm {
    code: Secret,
    error: Option<Problem>,
    /// The add this factor proves (sent with it, never a step-up).
    register: Option<Box<AdminRegisterApplicationRequest>>,
}

/// What goes on after a successful step-up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AfterStepUp {
    /// The factor add that asked for it.
    AddFactor(FactorMethod),
    /// The decision that asked for it, once more with the same key.
    Resend,
}

/// The window's state.
pub struct Flow {
    login: LoginModel,
    key_available: bool,
    busy: Option<Busy>,
    notice: Option<Notice>,
    throttled_until: Option<Instant>,
    session: Option<Session>,
    step_up: Option<StepUpForm>,
    enroll: Option<EnrollWizard>,
    factors: Option<FactorsPanel>,
    views: Option<AdminViews>,
    /// The factor being added (resent after a required step-up).
    adding: Option<FactorMethod>,
    after_step_up: Option<AfterStepUp>,
    /// The methods last offered for the form's user name.
    offered: Methods,
    /// When they were offered (`None`: no answer for the name shown).
    offer_at: Option<Instant>,
    /// The name of the `BeginLogin` in flight.
    asking: Option<Zeroizing<String>>,
    /// The name was left or Enter pressed for another name while a
    /// `BeginLogin` was in flight: ask again when it lands.
    want_offer: bool,
    /// A submit waiting for a fresh answer (the old one was too old).
    queued_submit: Option<Submission>,
    last_activity: Instant,
    idle_limit: Duration,
    /// Commands sent and replies received: the worker answers each command
    /// once and in order, so a reply is current only when it answers the
    /// command the flow waits for.
    sent: u64,
    received: u64,
    awaiting: Option<u64>,
}

fn idle_limit(server_secs: i64) -> Duration {
    let secs = server_secs.clamp(SERVER_IDLE_BOUNDS.0, SERVER_IDLE_BOUNDS.1);
    Duration::from_secs(u64::try_from(secs).unwrap_or(900)).saturating_sub(IDLE_MARGIN)
}

fn problem(e: &ClientError) -> Problem {
    match e {
        ClientError::Connect(_) => Problem::Unreachable,
        ClientError::Rejected | ClientError::SessionEnded => Problem::Rejected,
        ClientError::Throttled(_) => Problem::Throttled,
        ClientError::FactorNotOffered => Problem::NotOffered,
        ClientError::Authenticator(AuthenticatorError::Unavailable) => Problem::KeyUnavailable,
        ClientError::Authenticator(AuthenticatorError::Cancelled | AuthenticatorError::Timeout) => {
            Problem::KeyCancelled
        }
        ClientError::Authenticator(_) => Problem::KeyFailed,
        ClientError::Other(_) => Problem::ServerError,
    }
}

/// [`problem`] for enrollment: a refusal names the enrollment.
fn enroll_problem(e: &ClientError) -> Problem {
    match e {
        ClientError::Rejected => Problem::EnrollmentRejected,
        ClientError::Other(r) if r.reason == "password_policy" => Problem::PasswordPolicy,
        _ => problem(e),
    }
}

/// [`problem`] for factor changes.
fn factor_problem(e: &ClientError) -> Problem {
    match e {
        ClientError::Rejected => Problem::FactorRejected,
        ClientError::Other(r) if r.reason == "last_factor" => Problem::LastFactor,
        _ => problem(e),
    }
}

impl Flow {
    /// The empty sign-in form; `key_available` when this build has a
    /// security-key backend on this platform.
    #[must_use]
    pub fn new(key_available: bool, now: Instant) -> Self {
        Self {
            login: LoginModel::new(),
            key_available,
            busy: None,
            notice: None,
            throttled_until: None,
            session: None,
            step_up: None,
            enroll: None,
            factors: None,
            views: None,
            adding: None,
            after_step_up: None,
            offered: Methods::default(),
            offer_at: None,
            asking: None,
            want_offer: false,
            queued_submit: None,
            last_activity: now,
            idle_limit: DEFAULT_IDLE.saturating_sub(IDLE_MARGIN),
            sent: 0,
            received: 0,
            awaiting: None,
        }
    }

    /// Whether a session is shown.
    #[must_use]
    pub fn signed_in(&self) -> bool {
        self.session.is_some()
    }

    fn send(&mut self, cmd: Cmd, busy: Busy) -> Vec<Effect> {
        self.sent += 1;
        self.awaiting = Some(self.sent);
        self.busy = Some(busy);
        vec![Effect::Send(cmd)]
    }

    /// The window could not queue the last command (dropped and wiped).
    pub fn send_failed(&mut self) {
        self.sent = self.sent.saturating_sub(1);
        self.awaiting = None;
        self.busy = None;
        self.notice = Some(Notice::Problem(Problem::NotSent));
    }

    /// Any input: the idle clock restarts.
    pub fn activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Whether the sign-in form takes input now: signed out, no wizard,
    /// and nothing in flight but a `BeginLogin` (the name may still be
    /// edited while it runs; its answer is then stale and dropped).
    fn login_open(&self) -> bool {
        self.session.is_none()
            && self.enroll.is_none()
            && self.step_up.is_none()
            && matches!(self.busy, None | Some(Busy::Offer))
    }

    /// The user name changed: its answer, its age and a waiting submit go.
    fn name_edited(&mut self) {
        self.offer_at = None;
        self.queued_submit = None;
    }

    /// Typed or pasted text, for the focused field (or the step-up code).
    pub fn type_text(&mut self, text: &str) {
        if self.login_open() {
            if self.login.type_text(text) {
                self.name_edited();
            }
            return;
        }
        if self.busy.is_some() {
            return;
        }
        if let Some(form) = &mut self.step_up {
            form.error = None;
            form.code.push_str(text);
        } else if self.session.is_some() {
            if let Some(p) = &mut self.factors {
                p.type_text(text);
            } else if let Some(v) = &mut self.views {
                v.type_text(text);
            }
        } else if let Some(w) = &mut self.enroll {
            w.type_text(text);
        }
    }

    /// `Backspace`.
    pub fn backspace(&mut self) {
        if self.login_open() {
            if self.login.backspace() {
                self.name_edited();
            }
            return;
        }
        if self.busy.is_some() {
            return;
        }
        if let Some(form) = &mut self.step_up {
            form.error = None;
            form.code.pop();
        } else if self.session.is_some() {
            if let Some(p) = &mut self.factors {
                p.backspace();
            } else if let Some(v) = &mut self.views {
                v.backspace();
            }
        } else if let Some(w) = &mut self.enroll {
            w.backspace();
        }
    }

    /// `Tab` / `Shift-Tab`; leaving the user name asks the server about it.
    pub fn tab(&mut self, back: bool) -> Vec<Effect> {
        if self.step_up.is_some() {
            return Vec::new();
        }
        if self.session.is_some() {
            if let Some(p) = &mut self.factors {
                p.tab(back);
            } else if let Some(v) = &mut self.views {
                v.tab_key(back);
            }
        } else if let Some(w) = &mut self.enroll {
            w.tab(back);
        } else {
            let leaving = self.login.focused() == Field::Username;
            self.login.tab(back);
            if leaving {
                return self.continue_with();
            }
        }
        Vec::new()
    }

    /// A click on a field.
    pub fn focus(&mut self, field: Field) {
        if self.session.is_none() && self.enroll.is_none() {
            self.login.focus(field);
        }
    }

    /// A click on a wizard field.
    pub fn focus_enroll(&mut self, field: EnrollField) {
        if let (None, Some(w)) = (&self.session, &mut self.enroll) {
            w.focus(field);
        }
    }

    /// A click on a factor-form field.
    pub fn focus_factor(&mut self, field: FactorField) {
        if let (Some(_), Some(p)) = (&self.session, &mut self.factors) {
            p.focus(field);
        }
    }

    /// `Esc`: close the step-up prompt or a factor form, or wipe the typed
    /// secrets.
    pub fn escape(&mut self) {
        if self.busy.is_some() {
            return;
        }
        if self.step_up.is_some() {
            self.step_up_abandoned();
        } else if self.session.is_some() {
            if let Some(p) = &mut self.factors {
                p.cancel();
            } else if let Some(v) = &mut self.views {
                v.escape();
            }
        } else if let Some(w) = &mut self.enroll {
            w.escape();
            self.notice = None;
        } else {
            self.login.escape();
            self.notice = None;
        }
    }

    /// `Enter`: the default action of what is shown.
    pub fn enter(&mut self) -> Vec<Effect> {
        if let Some(session) = &self.session {
            if self.step_up.is_some() {
                let how = if session.info.methods.totp {
                    Submission::Code
                } else {
                    Submission::SecurityKey
                };
                return self.submit_step_up(how);
            }
            if let Some(p) = self.factors.as_ref().filter(|p| p.editing()) {
                let how = p.default_submission();
                return self.submit_factor(how);
            }
            if self.busy.is_none() {
                let cmd = self.views.as_mut().and_then(|v| v.enter(crate::unix_now()));
                if let Some(cmd) = cmd {
                    return self.send(cmd, Busy::Views);
                }
            }
            return Vec::new();
        }
        if let Some(w) = &self.enroll {
            return match w.view().stage {
                EnrollStage::Token => self.enroll_continue(),
                EnrollStage::Details => self.enroll_finish(),
            };
        }
        if self.login.focused() == Field::Username
            && (self.login.name_to_offer().is_some() || self.busy == Some(Busy::Offer))
        {
            return self.continue_with();
        }
        let how = match self.login.view().stage {
            Stage::Username => return self.continue_with(),
            Stage::Secrets(m) if m.totp => Submission::Code,
            Stage::Secrets(_) => Submission::SecurityKey,
        };
        // Enter before the last field moves on, unless the form is complete.
        if self.login.next_field().is_some() && !self.login.complete(how) {
            self.login.tab(false);
            return Vec::new();
        }
        self.submit(how)
    }

    /// The user name was left (`Tab`, `Enter`): ask which factors it may
    /// use (`BeginLogin`). One call at a time: a repeat for the name in
    /// flight is dropped; another name is asked when the answer lands. A
    /// name already answered is not asked again.
    pub fn continue_with(&mut self) -> Vec<Effect> {
        if self.session.is_some() || self.enroll.is_some() || self.throttled() {
            return Vec::new();
        }
        if self.busy == Some(Busy::Offer) {
            let same = self
                .asking
                .as_ref()
                .is_some_and(|a| a.as_str() == self.login.name());
            self.want_offer |= !same;
            return Vec::new();
        }
        if self.busy.is_some() {
            return Vec::new();
        }
        if self.login.name().is_empty() {
            let _ = self.login.continue_with(); // records "type a name"
            return Vec::new();
        }
        let Some(username) = self.login.name_to_offer() else {
            return Vec::new();
        };
        self.ask_offer(username)
    }

    fn ask_offer(&mut self, username: String) -> Vec<Effect> {
        self.notice = None;
        self.asking = Some(Zeroizing::new(username.clone()));
        self.send(Cmd::Offer { username }, Busy::Offer)
    }

    /// "Change user": the answer and the secrets go, the name stays.
    pub fn change_user(&mut self) {
        if self.busy.is_none() {
            self.login.back();
            self.name_edited();
            self.notice = None;
        }
    }

    /// Whether the answer shown is younger than a login nonce lives.
    fn offer_fresh(&self, now: Instant) -> bool {
        self.offer_at
            .is_some_and(|t| now.saturating_duration_since(t) < OFFER_TTL)
    }

    fn throttled(&self) -> bool {
        self.throttled_until.is_some_and(|t| Instant::now() < t)
    }

    /// Sign in with the code or a key.
    pub fn submit(&mut self, how: Submission) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_some() || self.throttled() {
            return Vec::new();
        }
        if how == Submission::SecurityKey && !self.key_available {
            self.notice = Some(Notice::Problem(Problem::KeyUnavailable));
            return Vec::new();
        }
        if self.login.ready(how).is_err() {
            return Vec::new();
        }
        if !self.offer_fresh(Instant::now()) {
            // The answer shown is older than a nonce lives: ask again (the
            // secrets stay typed) and sign in when the same name's answer
            // lands. The worker's sign-in still takes its own fresh nonce.
            self.queued_submit = Some(how);
            let username = self.login.name().to_string();
            return self.ask_offer(username);
        }
        let Ok(creds) = self.login.submit(how) else {
            return Vec::new();
        };
        let username = creds.username.to_string();
        let factor = match creds.code {
            Some(code) => FactorChoice::Code(code),
            None => FactorChoice::SecurityKey,
        };
        self.notice = None;
        self.send(
            Cmd::SignIn {
                username,
                password: creds.password,
                factor,
            },
            Busy::SignIn {
                key: how == Submission::SecurityKey,
            },
        )
    }

    /// Open the step-up prompt (not in a restricted session, where the
    /// server allows no step-up).
    pub fn open_step_up(&mut self) {
        if self.session.as_ref().is_some_and(|s| !s.restricted) && self.busy.is_none() {
            self.step_up = Some(StepUpForm {
                code: Secret::new(),
                error: None,
                register: None,
            });
            self.notice = None;
        }
    }

    /// The prompt for the fresh second factor of an add: opened for every
    /// add, even inside the step-up window (F20 §7 "M").
    fn open_add_proof(&mut self, req: Box<AdminRegisterApplicationRequest>) {
        self.step_up = Some(StepUpForm {
            code: Secret::new(),
            error: None,
            register: Some(req),
        });
        self.notice = None;
    }

    /// Step up with the code or a key.
    pub fn submit_step_up(&mut self, how: Submission) -> Vec<Effect> {
        let (Some(session), Some(form)) = (&self.session, &mut self.step_up) else {
            return Vec::new();
        };
        if self.busy.is_some() {
            return Vec::new();
        }
        let methods = session.info.methods;
        let factor = match how {
            Submission::Code if !methods.totp => None,
            Submission::Code if !form.code.is_totp_code() => {
                form.error = Some(Problem::Incomplete);
                return Vec::new();
            }
            Submission::Code => Some(FactorChoice::Code(form.code.take())),
            Submission::SecurityKey if !methods.security_key => None,
            Submission::SecurityKey if !self.key_available => {
                form.error = Some(Problem::KeyUnavailable);
                return Vec::new();
            }
            Submission::SecurityKey => {
                form.code.clear();
                Some(FactorChoice::SecurityKey)
            }
        };
        let Some(factor) = factor else {
            form.error = Some(Problem::NotOffered);
            return Vec::new();
        };
        let key = how == Submission::SecurityKey;
        if let Some(req) = &form.register {
            // The same request each time: a retry reuses its key.
            let req = req.clone();
            return self.send(Cmd::Register { req, proof: factor }, Busy::Register { key });
        }
        self.send(Cmd::StepUp { factor }, Busy::StepUp { key })
    }

    /// Close the step-up prompt (its code is wiped).
    pub fn cancel_step_up(&mut self) {
        if self.busy.is_none() {
            self.step_up_abandoned();
        }
    }

    /// The step-up prompt closes unconfirmed (its code is wiped): what
    /// waited for it is dropped, unsent.
    fn step_up_abandoned(&mut self) {
        let add = self
            .step_up
            .take()
            .is_some_and(|form| form.register.is_some());
        if let Some(v) = &mut self.views {
            if add {
                v.register_cancelled();
            }
            if self.after_step_up.take() == Some(AfterStepUp::Resend) {
                v.drop_pending();
            }
        } else {
            self.after_step_up = None;
        }
    }

    /// "Enroll with a token…" (signed out): the wizard replaces the form,
    /// whose typed secrets are wiped.
    pub fn open_enrollment(&mut self) {
        if self.session.is_none() && self.busy.is_none() && self.enroll.is_none() {
            self.login.wipe();
            self.enroll = Some(EnrollWizard::new(self.key_available));
            self.notice = None;
        }
    }

    /// Close the wizard (everything it holds is wiped).
    pub fn close_enrollment(&mut self) {
        if self.busy.is_none() && self.enroll.take().is_some() {
            self.notice = None;
        }
    }

    /// "Continue" with the token: `BeginEnrollment`.
    pub fn enroll_continue(&mut self) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_some() || self.throttled() {
            return Vec::new();
        }
        let Some(token) = self.enroll.as_mut().and_then(|w| w.continue_with().ok()) else {
            return Vec::new();
        };
        self.notice = None;
        self.send(Cmd::BeginEnrollment { token }, Busy::Enroll { key: false })
    }

    /// "Register security key" in the wizard.
    pub fn enroll_register_key(&mut self) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_some() {
            return Vec::new();
        }
        let Some(Ok((request, label))) = self.enroll.as_mut().map(EnrollWizard::register_key)
        else {
            return Vec::new();
        };
        self.notice = None;
        self.send(
            Cmd::EnrollKey { request, label },
            Busy::Enroll { key: true },
        )
    }

    /// "Finish": `CompleteEnrollment`.
    pub fn enroll_finish(&mut self) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_some() || self.throttled() {
            return Vec::new();
        }
        let Some(Ok(done)) = self.enroll.as_mut().map(EnrollWizard::finish) else {
            return Vec::new();
        };
        self.notice = None;
        self.send(
            Cmd::CompleteEnrollment {
                token: done.token,
                password: done.password,
                code: done.code,
                key: done.key,
            },
            Busy::Enroll { key: false },
        )
    }

    /// "Second factors" (signed in): open the panel and list the factors.
    pub fn open_factors(&mut self) -> Vec<Effect> {
        let Some(s) = &self.session else {
            return Vec::new();
        };
        if self.busy.is_some() || self.step_up.is_some() || s.restricted {
            return Vec::new();
        }
        if self.views.as_ref().is_some_and(AdminViews::has_pending) {
            return Vec::new();
        }
        self.views = None;
        self.factors = Some(FactorsPanel::new(false, s.info.methods, self.key_available));
        self.notice = None;
        self.send(Cmd::ListFactors, Busy::Factors { key: false })
    }

    /// "Requests" / "Approvals" (signed in): open the views on `tab`. The
    /// session's permissions are read first (they gate the buttons).
    pub fn open_views(&mut self, tab: Tab) -> Vec<Effect> {
        let Some(s) = &self.session else {
            return Vec::new();
        };
        if self.busy.is_some() || self.step_up.is_some() || s.restricted {
            return Vec::new();
        }
        self.factors = None;
        self.notice = None;
        let views = self.views.get_or_insert_with(|| AdminViews::new(tab));
        let cmd = if views.knows_permissions() {
            match views.act(ViewAction::Tab(tab), crate::unix_now()) {
                Some(cmd) => cmd,
                None => return Vec::new(),
            }
        } else {
            Cmd::Permissions
        };
        self.send(cmd, Busy::Views)
    }

    /// Close the views (every record shown is dropped); not while a
    /// decision waits for its outcome.
    pub fn close_views(&mut self) {
        if self.busy.is_none() && !self.views.as_ref().is_some_and(AdminViews::has_pending) {
            self.views = None;
        }
    }

    /// Something done on the views.
    pub fn views_action(&mut self, action: ViewAction) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_none() || self.step_up.is_some() {
            return Vec::new();
        }
        if action == ViewAction::DecisionConfirm {
            let now = crate::unix_now();
            if let Some(req) = self.views.as_mut().and_then(|v| v.confirm_register(now)) {
                // Always a fresh second factor, whatever the step-up window.
                self.open_add_proof(req);
                return Vec::new();
            }
        }
        let cmd = self
            .views
            .as_mut()
            .and_then(|v| v.act(action, crate::unix_now()));
        match cmd {
            Some(cmd) => {
                self.notice = None;
                self.send(cmd, Busy::Views)
            }
            None => Vec::new(),
        }
    }

    /// Close the panel (not in a restricted session, which is only it).
    pub fn close_factors(&mut self) {
        if self.busy.is_none() && self.factors.as_ref().is_some_and(|p| !p.restricted()) {
            self.factors = None;
        }
    }

    /// "Add an authenticator app" / "Add a security key": `BeginAddFactor`.
    pub fn add_factor(&mut self, method: FactorMethod) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_none() || self.step_up.is_some() {
            return Vec::new();
        }
        if !self.factors.as_ref().is_some_and(|p| p.can_add(method)) {
            return Vec::new();
        }
        self.adding = Some(method);
        self.notice = None;
        self.send(Cmd::BeginAddFactor { method }, Busy::Factors { key: false })
    }

    /// "Remove" on a factor: its confirmation form.
    pub fn remove_factor(&mut self, factor_id: &str) {
        if self.busy.is_none() {
            if let Some(p) = &mut self.factors {
                let _ = p.start_remove(factor_id);
            }
        }
    }

    /// "Cancel" on a factor form (wiped).
    pub fn cancel_factor_form(&mut self) {
        if self.busy.is_none() {
            if let Some(p) = &mut self.factors {
                p.cancel();
            }
        }
    }

    /// Submit the factor form shown, proving the account with `how`.
    pub fn submit_factor(&mut self, how: Submission) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_none() {
            return Vec::new();
        }
        let Some(Ok(cmd)) = self.factors.as_mut().map(|p| p.submit(how)) else {
            return Vec::new();
        };
        let key = how == Submission::SecurityKey || matches!(cmd, Cmd::CompleteAddKey { .. });
        self.notice = None;
        self.send(cmd, Busy::Factors { key })
    }

    /// Show or hide the seed shown (wizard or panel) as text.
    pub fn toggle_seed_text(&mut self) {
        if self.session.is_some() {
            if let Some(p) = &mut self.factors {
                p.toggle_seed_text();
            }
        } else if let Some(w) = &mut self.enroll {
            w.toggle_seed_text();
        }
    }

    /// The TOTP seed to paint, while one is shown. It never enters
    /// [`FlowView`].
    #[must_use]
    pub fn seed_display(&self) -> Option<SeedDisplay<'_>> {
        if self.session.is_some() {
            self.factors.as_ref().and_then(FactorsPanel::seed_display)
        } else {
            self.enroll.as_ref().and_then(EnrollWizard::seed_display)
        }
    }

    /// Wipe everything the window holds and end the session.
    fn end(&mut self, notice: Option<Notice>) -> Vec<Effect> {
        self.login.wipe();
        self.session = None;
        self.step_up = None;
        self.enroll = None;
        self.factors = None;
        self.views = None;
        self.adding = None;
        self.after_step_up = None;
        self.busy = None;
        self.awaiting = None;
        self.notice = notice;
        self.idle_limit = DEFAULT_IDLE.saturating_sub(IDLE_MARGIN);
        vec![Effect::EndSession]
    }

    /// "Sign out".
    pub fn sign_out(&mut self) -> Vec<Effect> {
        self.end(Some(Notice::SignedOut))
    }

    /// The window is closing.
    pub fn close(&mut self) -> Vec<Effect> {
        self.end(None)
    }

    /// Time passes: lock after the idle limit (also on a half-typed form).
    pub fn tick(&mut self, now: Instant) -> Vec<Effect> {
        if now.saturating_duration_since(self.last_activity) < self.idle_limit {
            return Vec::new();
        }
        self.last_activity = now;
        let view = self.login.view();
        let typed = !view.username.is_empty()
            || view.password_len > 0
            || view.code_len > 0
            || self
                .enroll
                .as_ref()
                .is_some_and(EnrollWizard::holds_anything);
        if self.session.is_some() || self.busy.is_some() || typed {
            return self.end(Some(Notice::Locked));
        }
        Vec::new()
    }

    /// A reply from the worker.
    pub fn on_reply(&mut self, reply: Reply, now: Instant) -> Vec<Effect> {
        self.received += 1;
        if self.awaiting != Some(self.received) {
            // Answers a command the window gave up on (a lock, a sign-out):
            // a session it reports must not survive.
            // Anything else it carried (a seed included) is dropped, wiped.
            return match reply {
                Reply::SignedIn { result: Ok(_), .. } | Reply::SteppedUp(Ok(_)) => {
                    vec![Effect::EndSession]
                }
                _ => Vec::new(),
            };
        }
        self.awaiting = None;
        self.busy = None;
        match reply {
            Reply::Offered { username, result } => self.offered_reply(&username, result, now),
            Reply::SignedIn { username, result } => self.signed_in_reply(&username, result, now),
            Reply::SteppedUp(result) => self.stepped_up_reply(result, now),
            Reply::EnrollmentBegun(result) => {
                match result {
                    Ok(offer) => {
                        if let Some(w) = &mut self.enroll {
                            w.offered(*offer);
                        }
                    }
                    Err(e) => self.fail_as(&e, enroll_problem(&e), now),
                }
                Vec::new()
            }
            Reply::EnrollKeyMade(result) => {
                match result {
                    Ok(attestation) => {
                        if let Some(w) = &mut self.enroll {
                            w.key_registered(attestation);
                        }
                    }
                    Err(e) => self.fail(&e, now),
                }
                Vec::new()
            }
            Reply::Enrolled(result) => {
                match result {
                    Ok(_) => {
                        self.enroll = None;
                        self.notice = Some(Notice::Enrolled);
                    }
                    Err(e) => self.fail_as(&e, enroll_problem(&e), now),
                }
                Vec::new()
            }
            Reply::Factors(result) => self.factors_reply(result, now),
            Reply::AddFactorBegun(result) => self.add_begun_reply(result, now),
            Reply::FactorAdded(result) => self.factor_changed_reply(result.map(|_| ()), true, now),
            Reply::FactorRemoved(result) => self.factor_changed_reply(result, false, now),
            Reply::Registered(result) => self.registered_reply(result, now),
            other => self.views_reply(other),
        }
    }

    /// An add's answer. A wrong or missing factor, or no answer at all,
    /// keeps the prompt with the same request (a retry reuses its key);
    /// the code is wiped either way.
    fn registered_reply(
        &mut self,
        result: Result<Box<AdminRegisterApplicationResponse>, ClientError>,
        now: Instant,
    ) -> Vec<Effect> {
        let retry = match &result {
            Err(ClientError::SessionEnded) => return self.end(Some(Notice::SessionEnded)),
            Err(
                ClientError::Rejected
                | ClientError::Throttled(_)
                | ClientError::FactorNotOffered
                | ClientError::Authenticator(_)
                | ClientError::Connect(_),
            ) => true,
            Err(ClientError::Other(e)) => {
                matches!(e.code, Code::DeadlineExceeded | Code::Unavailable)
            }
            Ok(_) => false,
        };
        if retry {
            if let Err(e) = &result {
                if let ClientError::Throttled(_) = e {
                    self.fail(e, now);
                }
                if let Some(form) = &mut self.step_up {
                    form.code.clear();
                    form.error = Some(match e {
                        ClientError::Other(_) => Problem::Unreachable,
                        other => problem(other),
                    });
                }
            }
            return Vec::new();
        }
        self.step_up = None;
        let event = match &mut self.views {
            Some(v) => v.on_registered(result, crate::unix_now()),
            None => ViewsEvent::None,
        };
        self.views_event(event)
    }

    /// A reply for the request and approval views.
    fn views_reply(&mut self, reply: Reply) -> Vec<Effect> {
        let unix = crate::unix_now();
        let Some(v) = &mut self.views else {
            return Vec::new();
        };
        let event = match reply {
            Reply::Permissions(r) => v.on_permissions(r, unix),
            Reply::Requests(r) => v.on_requests(r),
            Reply::Request(r) => v.on_request(r),
            Reply::Approvals(r) => v.on_approvals(r),
            Reply::Approval(r) => v.on_approval(r),
            Reply::Mutated(r) => v.on_mutated(r, unix),
            _ => ViewsEvent::None,
        };
        self.views_event(event)
    }

    /// Carry out what the views asked for after a reply.
    fn views_event(&mut self, event: ViewsEvent) -> Vec<Effect> {
        match event {
            ViewsEvent::None => Vec::new(),
            ViewsEvent::Send(cmd) => self.send(cmd, Busy::Views),
            ViewsEvent::SessionEnded => self.end(Some(Notice::SessionEnded)),
            ViewsEvent::StepUp => {
                // Confirm first, then the same decision goes once more.
                self.open_step_up();
                if self.step_up.is_some() {
                    self.after_step_up = Some(AfterStepUp::Resend);
                    self.notice = Some(Notice::StepUpFirst);
                } else if let Some(v) = &mut self.views {
                    v.drop_pending();
                }
                Vec::new()
            }
        }
    }

    fn fail(&mut self, e: &ClientError, now: Instant) {
        self.fail_as(e, problem(e), now);
    }

    fn fail_as(&mut self, e: &ClientError, p: Problem, now: Instant) {
        if let ClientError::Throttled(secs) = e {
            self.throttled_until = Some(now + Duration::from_secs((*secs).min(24 * 3600)));
        }
        self.notice = Some(Notice::Problem(p));
    }

    fn factors_reply(
        &mut self,
        result: Result<Vec<FactorInfo>, ClientError>,
        now: Instant,
    ) -> Vec<Effect> {
        let list = match result {
            Ok(list) => list,
            Err(ClientError::SessionEnded) => return self.end(Some(Notice::SessionEnded)),
            Err(e) => {
                self.fail_as(&e, factor_problem(&e), now);
                return Vec::new();
            }
        };
        // The proofs the session may use now: a key once one is held, a
        // code only if sign-in offered one (the FIDO2 policy may not).
        let has = |m: FactorMethod| list.iter().any(|f| f.method == m);
        let (totp, key) = (has(FactorMethod::Totp), has(FactorMethod::SecurityKey));
        if let Some(s) = &mut self.session {
            s.info.methods = Methods {
                totp: s.signin_totp && totp,
                security_key: key,
            };
            if let Some(p) = &mut self.factors {
                p.set_methods(s.info.methods);
                p.loaded(list);
            }
        }
        Vec::new()
    }

    fn add_begun_reply(
        &mut self,
        result: Result<(AddNonce, AddOffer), ClientError>,
        now: Instant,
    ) -> Vec<Effect> {
        match result {
            Ok((nonce, offer)) => {
                if let Some(p) = &mut self.factors {
                    p.offered(nonce, offer);
                }
                Vec::new()
            }
            Err(e) if e.needs_step_up() && self.session.as_ref().is_some_and(|s| !s.restricted) => {
                // Confirm first, then the add goes on by itself.
                self.after_step_up = self.adding.map(AfterStepUp::AddFactor);
                self.open_step_up();
                self.notice = Some(Notice::StepUpFirst);
                Vec::new()
            }
            Err(ClientError::SessionEnded) => self.end(Some(Notice::SessionEnded)),
            Err(e) => {
                self.fail_as(&e, factor_problem(&e), now);
                Vec::new()
            }
        }
    }

    fn factor_changed_reply(
        &mut self,
        result: Result<(), ClientError>,
        added: bool,
        now: Instant,
    ) -> Vec<Effect> {
        match result {
            Ok(()) if self.session.as_ref().is_some_and(|s| s.restricted) => {
                // The key the policy requires is in: sign in again with it.
                self.end(Some(Notice::KeyRegistered))
            }
            Ok(()) => {
                self.notice = Some(if added {
                    Notice::FactorAdded
                } else {
                    Notice::FactorRemoved
                });
                self.send(Cmd::ListFactors, Busy::Factors { key: false })
            }
            Err(ClientError::SessionEnded) => self.end(Some(Notice::SessionEnded)),
            Err(e) => {
                self.fail_as(&e, factor_problem(&e), now);
                Vec::new()
            }
        }
    }

    /// A `BeginLogin` answer. For the name shown it reveals the fields (and
    /// sends a submit that waited for it); for an edited name it is stale
    /// and dropped, and the new name is asked if it was left meanwhile.
    /// Real and decoy answers are handled alike.
    fn offered_reply(
        &mut self,
        username: &str,
        result: Result<Methods, ClientError>,
        now: Instant,
    ) -> Vec<Effect> {
        self.asking = None;
        let ask_again = std::mem::take(&mut self.want_offer);
        match result {
            Ok(methods) => {
                if self.login.offered(username, methods) {
                    self.offered = methods;
                    // The same clock as `offer_fresh`.
                    self.offer_at = Some(Instant::now());
                    if let Some(how) = self.queued_submit.take() {
                        return self.submit(how);
                    }
                } else if ask_again {
                    return self.continue_with();
                }
            }
            Err(e) => {
                self.queued_submit = None;
                self.fail(&e, now);
            }
        }
        Vec::new()
    }

    fn signed_in_reply(
        &mut self,
        username: &str,
        result: Result<LoginInfo, ClientError>,
        now: Instant,
    ) -> Vec<Effect> {
        let info = match result {
            Ok(info) => info,
            Err(e) => {
                // The secrets were wiped at submit; ask for them again.
                self.fail(&e, now);
                if let ClientError::FactorNotOffered = e {
                    self.login.back();
                    self.offer_at = None;
                } else {
                    self.login.retry(username, self.offered);
                }
                return Vec::new();
            }
        };
        if info.password_change_required {
            return self.end(Some(Notice::PasswordExpired));
        }
        // The FIDO2 policy holds a key-less session to registering a key:
        // possible only with a key backend here.
        let restricted = info.factor_enrollment_required;
        if restricted && !self.key_available {
            return self.end(Some(Notice::KeyRegistrationRequired));
        }
        self.login.wipe();
        self.notice = None;
        self.throttled_until = None;
        self.idle_limit = idle_limit(info.idle_timeout_secs);
        self.last_activity = now;
        self.factors =
            restricted.then(|| FactorsPanel::new(true, info.methods, self.key_available));
        self.session = Some(Session {
            signin_totp: info.methods.totp,
            info,
            step_up_until: None,
            restricted,
        });
        Vec::new()
    }

    fn stepped_up_reply(&mut self, result: Result<i64, ClientError>, now: Instant) -> Vec<Effect> {
        match result {
            Ok(until) => {
                if let Some(s) = &mut self.session {
                    s.step_up_until = Some(until);
                }
                self.step_up = None;
                self.notice = Some(Notice::SteppedUp);
                match self.after_step_up.take() {
                    // The add that asked for it goes on.
                    Some(AfterStepUp::AddFactor(method)) => self.add_factor(method),
                    // The decision that asked for it goes once more.
                    Some(AfterStepUp::Resend) => {
                        match self.views.as_mut().and_then(AdminViews::resend) {
                            Some(cmd) => self.send(cmd, Busy::Views),
                            None => Vec::new(),
                        }
                    }
                    None => Vec::new(),
                }
            }
            Err(ClientError::SessionEnded) => self.end(Some(Notice::SessionEnded)),
            Err(e) => {
                if let ClientError::Throttled(_) = e {
                    self.fail(&e, now);
                }
                if let Some(form) = &mut self.step_up {
                    form.code.clear();
                    form.error = Some(problem(&e));
                }
                Vec::new()
            }
        }
    }

    /// What the window draws at `now`.
    #[must_use]
    pub fn view(&self, now: Instant) -> FlowView {
        let mut login = self.login.view();
        login.can_submit_key &= self.key_available;
        let throttle_secs_left = self
            .throttled_until
            .map(|t| t.saturating_duration_since(now).as_secs())
            .filter(|s| *s > 0);
        if throttle_secs_left.is_some() {
            login.can_continue = false;
            login.can_submit_code = false;
            login.can_submit_key = false;
        }
        let session = self.session.as_ref().map(|s| SessionView {
            display_name: display_safe(&s.info.display_name, MAX_SHOWN),
            groups: s
                .info
                .groups
                .iter()
                .take(16)
                .map(|g| display_safe(g, MAX_SHOWN))
                .collect(),
            aal: s.info.aal,
            idle_lock_secs: self.idle_limit.as_secs(),
            step_up_until: s.step_up_until,
            methods: s.info.methods,
            restricted: s.restricted,
        });
        let step_up = match (&self.step_up, &self.session) {
            (Some(form), Some(s)) => Some(StepUpView {
                code_len: form.code.char_count(),
                error: form.error,
                can_submit_code: s.info.methods.totp && form.code.is_totp_code(),
                can_submit_key: s.info.methods.security_key && self.key_available,
                for_add: form.register.is_some(),
            }),
            _ => None,
        };
        let signed_in = self.session.is_some();
        FlowView {
            login,
            busy: self.busy,
            key_available: self.key_available,
            notice: self.notice,
            throttle_secs_left,
            session,
            step_up,
            enroll: self
                .enroll
                .as_ref()
                .filter(|_| !signed_in)
                .map(EnrollWizard::view),
            factors: self
                .factors
                .as_ref()
                .filter(|_| signed_in)
                .map(FactorsPanel::view),
            views: self
                .views
                .as_ref()
                .filter(|_| signed_in)
                .map(|v| v.view(crate::unix_now())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::login::LoginError;

    const PASSWORD: &str = "c0rrect-horse-Battery-staple";
    const CODE: &str = "123456";
    const BOTH: Methods = Methods {
        totp: true,
        security_key: true,
    };

    fn info(methods: Methods, idle: i64) -> LoginInfo {
        LoginInfo {
            idle_timeout_secs: idle,
            absolute_expires_at: 0,
            aal: 2,
            password_change_required: false,
            factor_enrollment_required: false,
            admin_id: "adm_1".into(),
            display_name: "Alice".into(),
            groups: vec!["ferrogate-approvers".into()],
            methods,
        }
    }

    /// The one command in `effects`, or a panic.
    fn cmd(effects: Vec<Effect>) -> Cmd {
        let mut it = effects.into_iter();
        match (it.next(), it.next()) {
            (Some(Effect::Send(c)), None) => c,
            _ => panic!("expected exactly one command"),
        }
    }

    fn ends(effects: &[Effect]) -> bool {
        matches!(effects, [Effect::EndSession])
    }

    /// No secret in the serialised view.
    fn clean(f: &Flow, now: Instant) {
        let json = serde_json::to_string(&f.view(now)).unwrap();
        for secret in [PASSWORD, CODE, "654321"] {
            assert!(!json.contains(secret), "{secret} in {json}");
        }
    }

    /// Up to the secrets stage for `alice`, offered `methods`.
    fn offered(f: &mut Flow, now: Instant, methods: Methods) {
        f.type_text("alice");
        let Cmd::Offer { username } = cmd(f.enter()) else {
            panic!("BeginLogin first");
        };
        assert_eq!(username, "alice");
        assert_eq!(f.view(now).busy, Some(Busy::Offer));
        f.on_reply(
            Reply::Offered {
                username,
                result: Ok(methods),
            },
            now,
        );
    }

    fn signed_in(now: Instant, methods: Methods, idle: i64) -> Flow {
        let mut f = Flow::new(true, now);
        offered(&mut f, now, methods);
        f.type_text(PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        let _ = cmd(f.submit(Submission::Code));
        f.on_reply(
            Reply::SignedIn {
                username: "alice".into(),
                result: Ok(info(methods, idle)),
            },
            now,
        );
        assert!(f.signed_in());
        f
    }

    const KEY_ONLY: Methods = Methods {
        totp: false,
        security_key: true,
    };

    fn offer_reply(f: &mut Flow, name: &str, methods: Methods, now: Instant) -> Vec<Effect> {
        f.on_reply(
            Reply::Offered {
                username: name.into(),
                result: Ok(methods),
            },
            now,
        )
    }

    /// F23 single screen: leaving the name (`Tab`) asks `BeginLogin` once;
    /// a second `Tab` or `Enter` for the same name sends nothing more; the
    /// answer reveals its fields on the same screen, the name still there.
    #[test]
    fn leaving_the_name_asks_once_and_reveals_the_fields_below_it() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        assert!(f.tab(false).is_empty(), "no name, nothing asked");
        assert!(f.enter().is_empty());
        assert_eq!(f.view(now).login.error, Some(LoginError::MissingUsername));
        f.type_text("alice");
        let Cmd::Offer { username } = cmd(f.tab(false)) else {
            panic!("BeginLogin when the name is left");
        };
        assert_eq!(username, "alice");
        assert!(f.enter().is_empty(), "double Enter: one call");
        assert!(f.tab(false).is_empty(), "Tab again: one call");
        let v = f.view(now);
        assert_eq!(v.busy, Some(Busy::Offer));
        assert_eq!(v.login.stage, Stage::Username, "no field guessed early");
        assert!(
            offer_reply(&mut f, "alice", BOTH, now).is_empty(),
            "no repeat"
        );
        let v = f.view(now);
        assert_eq!(v.login.stage, Stage::Secrets(BOTH));
        assert_eq!(
            (v.login.username.as_str(), v.login.focus),
            ("alice", Field::Password)
        );
        assert_eq!(v.busy, None);
        // Back on the name, unchanged: Tab moves on, nothing is asked.
        f.focus(Field::Username);
        assert!(f.tab(false).is_empty());
        assert_eq!(f.view(now).login.focus, Field::Password);
    }

    /// Editing the name after the reveal drops the answer, its age and the
    /// typed secrets; leaving it asks again for the new name.
    #[test]
    fn editing_the_name_drops_the_answer_and_asks_again() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        offered(&mut f, now, BOTH);
        f.type_text(PASSWORD);
        assert!(f.offer_at.is_some());
        f.focus(Field::Username);
        f.backspace();
        let v = f.view(now);
        assert_eq!((v.login.stage, v.login.password_len), (Stage::Username, 0));
        assert!(f.offer_at.is_none(), "the old answer is gone");
        f.type_text("e");
        let Cmd::Offer { username } = cmd(f.enter()) else {
            panic!("asked again");
        };
        assert_eq!(username, "alice");
        // The submit is refused until the new answer: nothing to send.
        assert!(f.submit(Submission::Code).is_empty());
    }

    /// The name edited while `BeginLogin` runs: its answer is stale and
    /// dropped; if the name was left meanwhile, the new one is asked then.
    #[test]
    fn a_stale_answer_is_dropped_and_the_new_name_asked() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        f.type_text("alice");
        let _ = cmd(f.enter());
        f.type_text("2"); // typing goes on while the call runs
        assert!(offer_reply(&mut f, "alice", BOTH, now).is_empty());
        let v = f.view(now);
        assert_eq!(
            (v.login.stage, v.login.username.as_str()),
            (Stage::Username, "alice2")
        );
        assert!(f.offer_at.is_none());
        // Left meanwhile: asked as soon as the stale answer lands.
        let Cmd::Offer { .. } = cmd(f.enter()) else {
            panic!("asked for alice2");
        };
        f.backspace();
        f.type_text("3");
        assert!(f.enter().is_empty(), "one call at a time");
        let Cmd::Offer { username } = cmd(offer_reply(&mut f, "alice2", BOTH, now)) else {
            panic!("the stale answer brings the next question");
        };
        assert_eq!(username, "alice3");
        assert!(offer_reply(&mut f, "alice3", BOTH, now).is_empty());
        assert_eq!(f.view(now).login.stage, Stage::Secrets(BOTH));
    }

    /// An answer older than a login nonce lives is asked again before the
    /// submit (secrets kept), and the sign-in then goes by itself.
    #[test]
    fn an_old_answer_is_refreshed_before_the_submit() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        offered(&mut f, now, BOTH);
        f.type_text(PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        f.offer_at = Instant::now().checked_sub(OFFER_TTL + Duration::from_secs(1));
        assert!(f.offer_at.is_some(), "the clock is past two minutes");
        let Cmd::Offer { username } = cmd(f.enter()) else {
            panic!("BeginLogin again first");
        };
        assert_eq!(username, "alice");
        let v = f.view(now);
        assert_eq!(
            (v.login.password_len, v.login.code_len),
            (PASSWORD.len(), 6)
        );
        let Cmd::SignIn {
            password,
            factor: FactorChoice::Code(code),
            ..
        } = cmd(offer_reply(&mut f, "alice", BOTH, now))
        else {
            panic!("the waiting sign-in goes");
        };
        assert_eq!((password.expose(), code.expose()), (PASSWORD, CODE));
        assert_eq!(f.view(now).login.password_len, 0, "wiped at submit");
        // A failed refresh sends nothing and keeps nothing waiting.
        let mut g = Flow::new(true, now);
        offered(&mut g, now, BOTH);
        g.type_text(PASSWORD);
        g.tab(false);
        g.type_text(CODE);
        g.offer_at = None;
        let _ = cmd(g.enter());
        assert!(g
            .on_reply(
                Reply::Offered {
                    username: "alice".into(),
                    result: Err(ClientError::Connect("down".into())),
                },
                now
            )
            .is_empty());
        assert!(g.queued_submit.is_none());
    }

    /// An unknown name gets the server's plausible decoy answer; the window
    /// treats it exactly like a real one (same calls, same view).
    #[test]
    fn an_unknown_name_looks_exactly_like_a_known_one() {
        let now = Instant::now();
        let run = |name: &str| {
            let mut f = Flow::new(true, now);
            f.type_text(name);
            let Cmd::Offer { username } = cmd(f.enter()) else {
                panic!("BeginLogin");
            };
            assert!(offer_reply(&mut f, &username, BOTH, now).is_empty());
            f.type_text(PASSWORD);
            f.tab(false);
            f.type_text(CODE);
            let mut v = serde_json::to_value(f.view(now)).unwrap();
            v["login"]["username"] = serde_json::Value::Null;
            let sent = matches!(cmd(f.enter()), Cmd::SignIn { .. });
            (v, sent)
        };
        assert_eq!(run("alice"), run("nobody-at-all"));
    }

    /// A WebAuthn-only account: the password and the key button, no code
    /// field; `Enter` in the password (the last field) uses the key.
    #[test]
    fn a_key_only_account_shows_no_code_field() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        offered(&mut f, now, KEY_ONLY);
        let v = f.view(now);
        assert_eq!(v.login.stage, Stage::Secrets(KEY_ONLY));
        assert!(!v.login.can_submit_code && !v.login.can_submit_key);
        f.type_text(PASSWORD);
        let v = f.view(now);
        assert!(!v.login.can_submit_code && v.login.can_submit_key);
        f.tab(false);
        assert_eq!(f.view(now).login.focus, Field::Username, "no code field");
        f.tab(false);
        let Cmd::SignIn {
            factor: FactorChoice::SecurityKey,
            ..
        } = cmd(f.enter())
        else {
            panic!("the key");
        };
    }

    /// `Enter` in the password with an empty code moves to the code; a
    /// complete form submits from any field.
    #[test]
    fn enter_moves_on_until_the_form_is_complete() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        offered(&mut f, now, BOTH);
        f.type_text(PASSWORD);
        assert!(f.enter().is_empty());
        assert_eq!(f.view(now).login.focus, Field::Code);
        f.type_text(CODE);
        f.focus(Field::Password);
        let Cmd::SignIn { .. } = cmd(f.enter()) else {
            panic!("complete: Enter signs in");
        };
    }

    #[test]
    fn sign_in_with_a_code_asks_for_the_offer_first() {
        let now = Instant::now();
        let mut f = Flow::new(false, now);
        offered(&mut f, now, BOTH);
        let v = f.view(now);
        assert_eq!(v.login.stage, Stage::Secrets(BOTH));
        assert!(!v.login.can_submit_key, "no key backend in this build");
        f.type_text(PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        clean(&f, now);
        let Cmd::SignIn {
            username,
            password,
            factor: FactorChoice::Code(code),
        } = cmd(f.enter())
        else {
            panic!("a code sign-in");
        };
        assert_eq!((username.as_str(), password.expose()), ("alice", PASSWORD));
        assert_eq!(code.expose(), CODE);
        let v = f.view(now);
        assert_eq!(v.busy, Some(Busy::SignIn { key: false }));
        assert_eq!(
            (v.login.password_len, v.login.code_len),
            (0, 0),
            "wiped at submit"
        );
        f.on_reply(
            Reply::SignedIn {
                username,
                result: Ok(info(BOTH, 600)),
            },
            now,
        );
        let s = f.view(now).session.expect("signed in");
        assert_eq!((s.display_name.as_str(), s.aal), ("Alice", 2));
        assert_eq!(s.idle_lock_secs, 570, "server idle minus 30 s");
        clean(&f, now);
    }

    #[test]
    fn a_key_sign_in_needs_a_key_backend_and_sends_no_code() {
        let now = Instant::now();
        let mut without = Flow::new(false, now);
        offered(&mut without, now, BOTH);
        without.type_text(PASSWORD);
        assert!(without.submit(Submission::SecurityKey).is_empty());
        let v = without.view(now);
        assert_eq!(v.notice, Some(Notice::Problem(Problem::KeyUnavailable)));
        assert_eq!(v.login.password_len, PASSWORD.chars().count(), "kept");

        let mut with = Flow::new(true, now);
        offered(&mut with, now, BOTH);
        with.type_text(PASSWORD);
        with.tab(false);
        with.type_text(CODE);
        let Cmd::SignIn {
            factor: FactorChoice::SecurityKey,
            ..
        } = cmd(with.submit(Submission::SecurityKey))
        else {
            panic!("a key sign-in");
        };
        assert_eq!(with.view(now).busy, Some(Busy::SignIn { key: true }));
        assert_eq!(with.view(now).login.code_len, 0, "the typed code is wiped");
    }

    #[test]
    fn under_the_fido2_policy_enter_uses_the_key() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        let key_only = Methods {
            totp: false,
            security_key: true,
        };
        offered(&mut f, now, key_only);
        f.type_text(PASSWORD);
        let Cmd::SignIn {
            factor: FactorChoice::SecurityKey,
            ..
        } = cmd(f.enter())
        else {
            panic!("the key is the only factor offered");
        };
    }

    #[test]
    fn a_refused_sign_in_asks_again_for_the_same_user() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        offered(&mut f, now, BOTH);
        f.type_text(PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        let _ = cmd(f.enter());
        f.on_reply(
            Reply::SignedIn {
                username: "alice".into(),
                result: Err(ClientError::Rejected),
            },
            now,
        );
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::Problem(Problem::Rejected)));
        assert_eq!(
            (v.login.username.as_str(), v.login.stage),
            ("alice", Stage::Secrets(BOTH))
        );
        assert_eq!((v.login.password_len, v.login.code_len), (0, 0));
        assert!(v.session.is_none());
    }

    #[test]
    fn a_throttle_counts_down_and_blocks_the_form() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        f.type_text("alice");
        let _ = cmd(f.enter());
        f.on_reply(
            Reply::Offered {
                username: "alice".into(),
                result: Err(ClientError::Throttled(90)),
            },
            now,
        );
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::Problem(Problem::Throttled)));
        assert_eq!(v.throttle_secs_left, Some(90));
        assert!(!v.login.can_continue);
        assert!(f.enter().is_empty(), "nothing is sent while throttled");
        assert_eq!(
            f.view(now + Duration::from_secs(91)).throttle_secs_left,
            None
        );
    }

    #[test]
    fn an_expired_password_or_a_missing_key_ends_the_session_at_once() {
        let now = Instant::now();
        // A key-less session under the FIDO2 policy ends at once only when
        // this build cannot register a key here.
        for (expired, enroll, notice) in [
            (true, false, Notice::PasswordExpired),
            (false, true, Notice::KeyRegistrationRequired),
        ] {
            let mut f = Flow::new(false, now);
            offered(&mut f, now, BOTH);
            f.type_text(PASSWORD);
            f.tab(false);
            f.type_text(CODE);
            let _ = cmd(f.enter());
            let mut i = info(BOTH, 900);
            i.password_change_required = expired;
            i.factor_enrollment_required = enroll;
            let effects = f.on_reply(
                Reply::SignedIn {
                    username: "alice".into(),
                    result: Ok(i),
                },
                now,
            );
            assert!(ends(&effects));
            let v = f.view(now);
            assert_eq!(v.notice, Some(notice));
            assert!(v.session.is_none());
        }
    }

    #[test]
    fn step_up_with_a_code_then_with_a_key() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 900);
        f.open_step_up();
        f.type_text("12");
        assert!(f.enter().is_empty(), "an incomplete code is not sent");
        assert_eq!(
            f.view(now).step_up.unwrap().error,
            Some(Problem::Incomplete)
        );
        f.backspace();
        f.backspace();
        f.type_text("654321");
        clean(&f, now);
        let Cmd::StepUp {
            factor: FactorChoice::Code(code),
        } = cmd(f.enter())
        else {
            panic!("a code step-up");
        };
        assert_eq!(code.expose(), "654321");
        // A refused code keeps the prompt open, the code wiped.
        f.on_reply(Reply::SteppedUp(Err(ClientError::Rejected)), now);
        let su = f.view(now).step_up.expect("still open");
        assert_eq!((su.code_len, su.error), (0, Some(Problem::Rejected)));
        let Cmd::StepUp {
            factor: FactorChoice::SecurityKey,
        } = cmd(f.submit_step_up(Submission::SecurityKey))
        else {
            panic!("a key step-up");
        };
        f.on_reply(Reply::SteppedUp(Ok(1_800_000_000)), now);
        let v = f.view(now);
        assert!(v.step_up.is_none());
        assert_eq!(v.notice, Some(Notice::SteppedUp));
        assert_eq!(v.session.unwrap().step_up_until, Some(1_800_000_000));
    }

    #[test]
    fn a_session_the_server_ended_during_a_step_up_is_wiped() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 900);
        f.open_step_up();
        let _ = cmd(f.submit_step_up(Submission::SecurityKey));
        let effects = f.on_reply(Reply::SteppedUp(Err(ClientError::SessionEnded)), now);
        assert!(ends(&effects));
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::SessionEnded));
        assert!(v.session.is_none() && v.step_up.is_none());
    }

    #[test]
    fn the_idle_lock_ends_the_session_and_resists_a_hostile_timeout() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 600);
        assert!(f.tick(now + Duration::from_secs(569)).is_empty());
        f.activity(now + Duration::from_secs(569));
        assert!(
            f.tick(now + Duration::from_secs(1100)).is_empty(),
            "activity restarts it"
        );
        let effects = f.tick(now + Duration::from_secs(1139));
        assert!(ends(&effects));
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::Locked));
        assert!(v.session.is_none());
        assert_eq!(v.login.username, "", "everything wiped");

        assert_eq!(idle_limit(0), Duration::from_secs(30), "never disabled");
        assert_eq!(
            idle_limit(i64::MAX),
            Duration::from_secs(870),
            "never above 15 min"
        );
        // A half-typed form is wiped too.
        let mut g = Flow::new(true, now);
        g.type_text("alice");
        assert!(ends(&g.tick(now + DEFAULT_IDLE)));
        assert_eq!(g.view(now).login.username, "");
    }

    #[test]
    fn a_late_reply_after_a_sign_out_never_shows_a_session() {
        let now = Instant::now();
        let mut f = Flow::new(true, now);
        offered(&mut f, now, BOTH);
        f.type_text(PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        let _ = cmd(f.enter());
        assert!(ends(&f.sign_out()), "locked while signing in");
        // A new sign-in starts before the old answer arrives.
        f.type_text("bob");
        let _ = cmd(f.enter());
        let late = f.on_reply(
            Reply::SignedIn {
                username: "alice".into(),
                result: Ok(info(BOTH, 900)),
            },
            now,
        );
        assert!(ends(&late), "the late session is ended, not shown");
        assert!(!f.signed_in());
        assert_eq!(f.view(now).busy, Some(Busy::Offer), "still waiting for bob");
        f.on_reply(
            Reply::Offered {
                username: "bob".into(),
                result: Ok(BOTH),
            },
            now,
        );
        assert_eq!(f.view(now).login.stage, Stage::Secrets(BOTH));
    }

    fn key_request() -> Box<ferrogate_admin_client::webauthn::CreationRequest> {
        use ferrogate_admin_client::webauthn::{creation_request, CreationOptions};
        Box::new(
            creation_request(&CreationOptions {
                challenge: vec![3; 32],
                rp_id: "ferrogate-admin.ferrogate.test".into(),
                rp_name: "FerroGate".into(),
                user_id: vec![4; 32],
                user_name: "alice".into(),
                display_name: "Alice".into(),
                pub_key_cred_params: vec![-7],
                exclude_credential_ids: Vec::new(),
                user_verification: 1,
                attestation: 1,
            })
            .unwrap(),
        )
    }

    fn nonce() -> AddNonce {
        AddNonce::from_bytes(vec![7; 32])
    }

    fn totp_row() -> FactorInfo {
        FactorInfo {
            factor_id: "totp".into(),
            method: FactorMethod::Totp,
            label: "TOTP authenticator".into(),
            created_at: 0,
            last_used_at: 0,
        }
    }

    #[test]
    fn a_restricted_session_registers_a_key_and_then_ends() {
        let now = Instant::now();
        let code_only = Methods {
            totp: true,
            security_key: false,
        };
        let mut f = Flow::new(true, now);
        offered(&mut f, now, code_only);
        f.type_text(PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        let _ = cmd(f.enter());
        let mut i = info(code_only, 900);
        i.factor_enrollment_required = true;
        assert!(f
            .on_reply(
                Reply::SignedIn {
                    username: "alice".into(),
                    result: Ok(i),
                },
                now,
            )
            .is_empty());
        let v = f.view(now);
        assert!(v.session.as_ref().unwrap().restricted);
        assert!(v.factors.as_ref().unwrap().restricted);
        f.open_step_up();
        assert!(f.view(now).step_up.is_none(), "no step-up here");
        assert!(
            f.open_factors().is_empty(),
            "the panel is already all there is"
        );
        let Cmd::BeginAddFactor {
            method: FactorMethod::SecurityKey,
        } = cmd(f.add_factor(FactorMethod::SecurityKey))
        else {
            panic!("a key is added");
        };
        f.on_reply(
            Reply::AddFactorBegun(Ok((nonce(), AddOffer::SecurityKey(key_request())))),
            now,
        );
        f.type_text("Desk key");
        f.tab(false);
        f.type_text(CODE);
        clean(&f, now);
        let Cmd::CompleteAddKey {
            label,
            proof: FactorChoice::Code(code),
            ..
        } = cmd(f.enter())
        else {
            panic!("the key, proven with the code");
        };
        assert_eq!((label.as_str(), code.expose()), ("Desk key", CODE));
        assert_eq!(f.view(now).busy, Some(Busy::Factors { key: true }));
        let effects = f.on_reply(Reply::FactorAdded(Ok("wa_1".into())), now);
        assert!(ends(&effects), "sign in again, with the key");
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::KeyRegistered));
        assert!(v.session.is_none() && v.factors.is_none());
    }

    #[test]
    fn adding_a_factor_steps_up_first_when_asked_and_then_goes_on() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 900);
        let Cmd::ListFactors = cmd(f.open_factors()) else {
            panic!("the list first");
        };
        f.on_reply(Reply::Factors(Ok(vec![totp_row()])), now);
        let v = f.view(now);
        assert_eq!(v.factors.as_ref().unwrap().rows.len(), 1);
        assert_eq!(
            v.session.unwrap().methods,
            Methods {
                totp: true,
                security_key: false
            },
            "no key held yet"
        );
        let _ = cmd(f.add_factor(FactorMethod::SecurityKey));
        let stale = ferrogate_admin_client::error::RpcError::local(
            ferrogate_admin_client::error::Code::FailedPrecondition,
            "step_up_required",
        );
        f.on_reply(Reply::AddFactorBegun(Err(ClientError::Other(stale))), now);
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::StepUpFirst));
        assert!(v.step_up.is_some());
        f.type_text("654321");
        let Cmd::StepUp { .. } = cmd(f.enter()) else {
            panic!("the step-up");
        };
        let Cmd::BeginAddFactor {
            method: FactorMethod::SecurityKey,
        } = cmd(f.on_reply(Reply::SteppedUp(Ok(1_800_000_000)), now))
        else {
            panic!("the add goes on by itself");
        };
    }

    #[test]
    fn a_totp_add_shows_the_seed_once_and_relists_after() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 900);
        let _ = cmd(f.open_factors());
        let key_row = FactorInfo {
            factor_id: "wa_1".into(),
            method: FactorMethod::SecurityKey,
            label: "Desk".into(),
            created_at: 0,
            last_used_at: 0,
        };
        f.on_reply(Reply::Factors(Ok(vec![key_row])), now);
        assert!(f.view(now).factors.unwrap().can_add_totp);
        let _ = cmd(f.add_factor(FactorMethod::Totp));
        f.on_reply(
            Reply::AddFactorBegun(Ok((
                nonce(),
                AddOffer::Totp(crate::admin::seed::tests::seed()),
            ))),
            now,
        );
        assert!(f.seed_display().is_some());
        f.toggle_seed_text();
        assert!(f.seed_display().unwrap().text.is_some());
        let json = serde_json::to_string(&f.view(now)).unwrap();
        assert!(!json.contains(crate::admin::seed::tests::SECRET));
        assert!(!json.contains("JBSW"));
        f.type_text(CODE);
        let Cmd::CompleteAddTotp {
            proof: FactorChoice::SecurityKey,
            ..
        } = cmd(f.enter())
        else {
            panic!("proven by the key");
        };
        assert!(f.seed_display().is_none(), "gone once used");
        let Cmd::ListFactors = cmd(f.on_reply(Reply::FactorAdded(Ok("totp".into())), now)) else {
            panic!("the list is read again");
        };
        assert_eq!(f.view(now).notice, Some(Notice::FactorAdded));
    }

    #[test]
    fn a_lock_or_a_sign_out_drops_a_late_seed_and_the_wizard() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 900);
        let _ = cmd(f.open_factors());
        f.on_reply(Reply::Factors(Ok(vec![totp_row()])), now);
        let _ = cmd(f.add_factor(FactorMethod::SecurityKey));
        assert!(ends(&f.sign_out()));
        let late = f.on_reply(
            Reply::AddFactorBegun(Ok((
                nonce(),
                AddOffer::Totp(crate::admin::seed::tests::seed()),
            ))),
            now,
        );
        assert!(late.is_empty());
        assert!(f.seed_display().is_none() && f.view(now).factors.is_none());

        // A wizard holding a seed is wiped by the idle lock.
        let mut g = Flow::new(false, now);
        g.open_enrollment();
        g.type_text("fgae_token");
        let _ = cmd(g.enter());
        g.on_reply(
            Reply::EnrollmentBegun(Ok(Box::new(enrollment_offer()))),
            now,
        );
        assert!(g.seed_display().is_some());
        assert!(ends(&g.tick(now + DEFAULT_IDLE)));
        assert!(g.seed_display().is_none() && g.view(now).enroll.is_none());
        assert_eq!(g.view(now).notice, Some(Notice::Locked));
    }

    fn enrollment_offer() -> ferrogate_admin_client::enroll::EnrollmentOffer {
        ferrogate_admin_client::enroll::EnrollmentOffer {
            username: "new.person".into(),
            username_choosable: false,
            display_name: "New Person".into(),
            password_min_len: 24,
            totp: Some(crate::admin::seed::tests::seed()),
            key: None,
        }
    }

    #[test]
    fn enrollment_runs_through_the_flow_and_ends_on_the_sign_in_form() {
        const NEW_PASSWORD: &str = "Tr0ub4dor&3-Correct!Horse_Battery";
        let now = Instant::now();
        let mut f = Flow::new(false, now);
        f.type_text("half-typed");
        f.open_enrollment();
        assert_eq!(f.view(now).login.username, "", "the form is wiped");
        f.type_text("fgae_token");
        let Cmd::BeginEnrollment { token } = cmd(f.enter()) else {
            panic!("BeginEnrollment");
        };
        assert_eq!(token.expose(), "fgae_token");
        assert_eq!(f.view(now).busy, Some(Busy::Enroll { key: false }));
        f.on_reply(
            Reply::EnrollmentBegun(Ok(Box::new(enrollment_offer()))),
            now,
        );
        let v = f.view(now).enroll.unwrap();
        assert!(v.totp_offered && v.stage == EnrollStage::Details);
        f.type_text(NEW_PASSWORD);
        f.tab(false);
        f.type_text(NEW_PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        let json = serde_json::to_string(&f.view(now)).unwrap();
        for secret in [NEW_PASSWORD, CODE, "fgae_token", "JBSW"] {
            assert!(!json.contains(secret), "{secret}");
        }
        let Cmd::CompleteEnrollment {
            password,
            code,
            key,
            ..
        } = cmd(f.enter())
        else {
            panic!("CompleteEnrollment");
        };
        assert_eq!(password.expose(), NEW_PASSWORD);
        assert_eq!(code.as_ref().map(Secret::expose), Some(CODE));
        assert!(key.is_none());
        // A refused attempt keeps the wizard and says so generically.
        f.on_reply(Reply::Enrolled(Err(ClientError::Rejected)), now);
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::Problem(Problem::EnrollmentRejected)));
        assert_eq!(v.enroll.unwrap().password_len, 0, "typed again");
        f.type_text(NEW_PASSWORD);
        f.tab(false);
        f.type_text(NEW_PASSWORD);
        f.tab(false);
        f.type_text(CODE);
        let _ = cmd(f.enter());
        f.on_reply(Reply::Enrolled(Ok("adm_2".into())), now);
        let v = f.view(now);
        assert_eq!(v.notice, Some(Notice::Enrolled));
        assert!(v.enroll.is_none() && f.seed_display().is_none());
        assert_eq!(v.login.stage, Stage::Username);
    }

    #[test]
    fn server_strings_are_shown_inert() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 900);
        if let Some(s) = &mut f.session {
            s.info.display_name = "Mallory\u{1b}]52;c;x\u{7}\u{202e}".into();
            s.info.groups = vec!["g\u{1b}[2J".into()];
        }
        let s = f.view(now).session.unwrap();
        assert!(!s.display_name.contains('\u{1b}') && !s.display_name.contains('\u{202e}'));
        assert!(!s.groups[0].contains('\u{1b}'));
    }

    // ---- request and approval views (T283) ------------------------------

    use crate::admin::decide::tests::{detail, request};
    use crate::admin::decide::DecisionKind;
    use crate::admin::views::Outcome;
    use ferrogate_admin_client::approvals::proto::{
        ApproveAppRequestResponse, ListAppRequestsResponse,
    };
    use ferrogate_admin_client::approvals::Mutated;
    use ferrogate_admin_client::error::{Code, RpcError};

    /// Signed in, the Requests view open on one loaded and opened request.
    fn on_a_request(now: Instant) -> Flow {
        let mut f = signed_in(now, BOTH, 900);
        let Cmd::Permissions = cmd(f.open_views(Tab::Requests)) else {
            panic!("the permissions are read first");
        };
        assert_eq!(f.view(now).busy, Some(Busy::Views));
        let perms = vec![
            "app_request.approve".to_string(),
            "app_request.deny".to_string(),
        ];
        let Cmd::ListRequests(_) = cmd(f.on_reply(Reply::Permissions(Ok(perms)), now)) else {
            panic!("then the list");
        };
        let none = f.on_reply(
            Reply::Requests(Ok(ListAppRequestsResponse {
                items: vec![request(0)],
                next_page_token: String::new(),
            })),
            now,
        );
        assert!(none.is_empty());
        let Cmd::GetRequest(_) = cmd(f.views_action(ViewAction::OpenRequest(0))) else {
            panic!("the request");
        };
        f.on_reply(Reply::Request(Ok(Box::new(detail(0)))), now);
        assert!(f.view(now).views.unwrap().request.is_some());
        f
    }

    fn step_up_required() -> ClientError {
        ClientError::Other(RpcError::local(
            Code::FailedPrecondition,
            "step_up_required",
        ))
    }

    #[test]
    fn a_decision_steps_up_then_goes_once_more_with_the_same_key() {
        let now = Instant::now();
        let mut f = on_a_request(now);
        assert!(f
            .views_action(ViewAction::Decide(DecisionKind::Approve))
            .is_empty());
        f.type_text("ticket 42");
        assert_eq!(
            f.view(now).views.unwrap().decision.unwrap().note,
            "ticket 42"
        );
        assert!(
            f.enter().is_empty(),
            "Enter moves the form on, never confirms"
        );
        let Cmd::Mutate(m) = cmd(f.views_action(ViewAction::DecisionConfirm)) else {
            panic!("the approval");
        };
        let key = m.idempotency_key().to_string();
        assert!(f
            .on_reply(Reply::Mutated(Err(step_up_required())), now)
            .is_empty());
        let v = f.view(now);
        assert!(v.step_up.is_some(), "the step-up prompt opens");
        assert_eq!(v.notice, Some(Notice::StepUpFirst));
        f.type_text(CODE);
        let Cmd::StepUp { .. } = cmd(f.enter()) else {
            panic!("the step-up");
        };
        clean(&f, now);
        let Cmd::Mutate(again) = cmd(f.on_reply(Reply::SteppedUp(Ok(1)), now)) else {
            panic!("the same decision once more");
        };
        assert_eq!(again.idempotency_key(), key);
        let done = Mutated::Approved(ApproveAppRequestResponse {
            allowlist_generation: 9,
            ..ApproveAppRequestResponse::default()
        });
        let Cmd::GetRequest(_) = cmd(f.on_reply(Reply::Mutated(Ok(Box::new(done))), now)) else {
            panic!("the request is reloaded");
        };
        assert!(matches!(
            f.view(now).views.unwrap().outcome,
            Some(Outcome::Approved { generation: 9, .. })
        ));
    }

    #[test]
    fn a_cancelled_step_up_sends_nothing_and_a_lock_drops_every_record() {
        let now = Instant::now();
        let mut f = on_a_request(now);
        f.views_action(ViewAction::Decide(DecisionKind::Deny));
        f.views_action(ViewAction::DecisionNext);
        let Cmd::Mutate(_) = cmd(f.views_action(ViewAction::DecisionConfirm)) else {
            panic!("the denial");
        };
        f.on_reply(Reply::Mutated(Err(step_up_required())), now);
        f.cancel_step_up();
        let v = f.view(now).views.unwrap();
        assert_eq!(v.outcome, Some(Outcome::NotSent));
        assert!(!v.pending);
        assert!(f.view(now).step_up.is_none());

        let later = now + Duration::from_secs(2000);
        assert!(ends(&f.tick(later)));
        assert!(f.view(later).views.is_none(), "every record is dropped");
        // A list answered after the lock is never shown.
        let late = f.on_reply(
            Reply::Requests(Ok(ListAppRequestsResponse {
                items: vec![request(0)],
                next_page_token: String::new(),
            })),
            later,
        );
        assert!(late.is_empty() && f.view(later).views.is_none());
    }

    #[test]
    fn the_views_close_the_factor_panel_and_a_dead_session_ends() {
        let now = Instant::now();
        let mut f = signed_in(now, BOTH, 900);
        let _ = cmd(f.open_factors());
        f.on_reply(Reply::Factors(Ok(Vec::new())), now);
        let _ = cmd(f.open_views(Tab::Approvals));
        assert!(f.view(now).factors.is_none());
        let effects = f.on_reply(Reply::Permissions(Err(ClientError::SessionEnded)), now);
        assert!(ends(&effects));
        assert_eq!(f.view(now).notice, Some(Notice::SessionEnded));
        assert!(!f.signed_in());
    }

    // ---- add application (T284) ------------------------------------------

    use crate::admin::decide::tests::HOST;
    use crate::admin::decide::DecisionField;
    use ferrogate_admin_client::approvals::register::{
        AdminRegisterApplicationResponse, Registered,
    };

    /// Signed in and stepped up (the window is open), the Requests view
    /// loaded with `permissions`, the add dialog typed and on its review.
    fn add_reviewed(now: Instant, permissions: &[&str]) -> Flow {
        let mut f = signed_in(now, BOTH, 900);
        f.open_step_up();
        f.type_text(CODE);
        let Cmd::StepUp { .. } = cmd(f.enter()) else {
            panic!("the step-up");
        };
        f.on_reply(Reply::SteppedUp(Ok(crate::unix_now() + 300)), now);
        assert!(f.view(now).session.unwrap().step_up_until.is_some());
        let _ = cmd(f.open_views(Tab::Requests));
        let perms = permissions.iter().map(|p| (*p).to_string()).collect();
        let _ = cmd(f.on_reply(Reply::Permissions(Ok(perms)), now));
        f.on_reply(Reply::Requests(Ok(ListAppRequestsResponse::default())), now);
        assert!(f
            .views_action(ViewAction::Decide(DecisionKind::Register))
            .is_empty());
        for (field, text) in [
            (DecisionField::Host, HOST.to_string()),
            (DecisionField::Path, "/opt/tool/bin/tool".to_string()),
            (DecisionField::Sha, "ab".repeat(48)),
            (DecisionField::Uid, "1000".to_string()),
            (DecisionField::User, "alice".to_string()),
        ] {
            assert!(f.views_action(ViewAction::FocusDecision(field)).is_empty());
            f.type_text(&text);
        }
        f.tab(false);
        assert!(
            f.enter().is_empty(),
            "Enter moves the form on, never confirms"
        );
        let d = f.view(now).views.unwrap().decision.unwrap();
        assert_eq!(d.stage, crate::admin::decide::DecisionStage::Review);
        f
    }

    #[test]
    fn an_add_always_asks_a_fresh_factor_and_a_wrong_code_reuses_the_key() {
        let now = Instant::now();
        let mut f = add_reviewed(now, &["app.direct_register", "app_request.approve"]);
        // Inside the step-up window, yet nothing goes before a fresh factor.
        assert!(f.views_action(ViewAction::DecisionConfirm).is_empty());
        let v = f.view(now);
        let prompt = v.step_up.expect("the fresh-factor prompt");
        assert!(prompt.for_add && prompt.code_len == 0);
        assert!(v.views.unwrap().pending);
        assert!(f.views_action(ViewAction::Refresh).is_empty(), "held");
        assert!(f.open_factors().is_empty(), "held");
        f.type_text("654321");
        clean(&f, now);
        let Cmd::Register {
            req,
            proof: FactorChoice::Code(code),
        } = cmd(f.enter())
        else {
            panic!("the add with its code");
        };
        assert_eq!(code.expose(), "654321");
        assert!(req.proof.is_none(), "the worker adds the proof");
        assert_eq!(f.view(now).busy, Some(Busy::Register { key: false }));
        let key = req.idempotency_key.clone();
        // A wrong code: nothing changed, the prompt asks again.
        assert!(f
            .on_reply(Reply::Registered(Err(ClientError::Rejected)), now)
            .is_empty());
        let prompt = f.view(now).step_up.expect("asked again");
        assert_eq!(
            (prompt.error, prompt.code_len),
            (Some(Problem::Rejected), 0)
        );
        assert!(f.view(now).views.unwrap().outcome.is_none());
        f.type_text(CODE);
        let Cmd::Register { req: again, .. } = cmd(f.enter()) else {
            panic!("the retry");
        };
        assert_eq!(again.idempotency_key, key, "the retry reuses the key");
        // No answer either: the same request may go once more.
        f.on_reply(
            Reply::Registered(Err(ClientError::Other(RpcError::local(
                Code::DeadlineExceeded,
                "deadline",
            )))),
            now,
        );
        assert_eq!(
            f.view(now).step_up.unwrap().error,
            Some(Problem::Unreachable)
        );
        f.type_text(CODE);
        let Cmd::Register { req: third, .. } = cmd(f.enter()) else {
            panic!("the retry");
        };
        assert_eq!(third.idempotency_key, key);
        let done = AdminRegisterApplicationResponse {
            allowlist_generation: 5,
            ..AdminRegisterApplicationResponse::default()
        };
        let Cmd::ListRequests(_) = cmd(f.on_reply(Reply::Registered(Ok(Box::new(done))), now))
        else {
            panic!("the list is reloaded");
        };
        let v = f.view(now);
        assert!(v.step_up.is_none());
        let views = v.views.unwrap();
        assert!(views.decision.is_none() && !views.pending);
        assert!(matches!(
            views.outcome,
            Some(Outcome::Added(Registered::Approved { generation: 5, .. }))
        ));
    }

    #[test]
    fn a_cancelled_or_refused_add_sends_nothing_more_and_a_lock_drops_it() {
        let now = Instant::now();
        let mut f = add_reviewed(now, &["app.direct_register"]);
        assert!(f.views_action(ViewAction::DecisionConfirm).is_empty());
        f.type_text("12");
        f.escape();
        let v = f.view(now);
        assert!(v.step_up.is_none());
        let views = v.views.unwrap();
        assert_eq!(views.outcome, Some(Outcome::NotSent));
        assert!(!views.pending && views.decision.is_some());
        // Refused by the server: the review stays, nothing registered.
        assert!(f.views_action(ViewAction::DecisionConfirm).is_empty());
        f.type_text(CODE);
        let _ = cmd(f.enter());
        let refused = ClientError::Other(RpcError::local(Code::PermissionDenied, "denied"));
        assert!(f.on_reply(Reply::Registered(Err(refused)), now).is_empty());
        let v = f.view(now);
        assert!(v.step_up.is_none());
        assert_eq!(
            v.views.unwrap().outcome,
            Some(Outcome::Refused(crate::admin::views::Refusal::NotAllowed))
        );
        // A lock with the prompt open wipes it with the session.
        assert!(f.views_action(ViewAction::DecisionConfirm).is_empty());
        f.type_text("1234");
        let later = now + Duration::from_secs(2000);
        assert!(ends(&f.tick(later)));
        let v = f.view(later);
        assert!(v.step_up.is_none() && v.views.is_none() && v.session.is_none());
        // Its late answer shows nothing.
        let late = f.on_reply(Reply::Registered(Ok(Box::default())), later);
        assert!(late.is_empty() && f.view(later).views.is_none());
    }
}
