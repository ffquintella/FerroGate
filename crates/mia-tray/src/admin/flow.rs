//! The admin window's state machine (F22 §3), headless: sign-in (user name,
//! then password with a TOTP code or a security key), the signed-in summary,
//! the step-up prompt, sign-out and the idle lock. Input goes in as calls,
//! [`Reply`]s from the worker go in through [`Flow::on_reply`], and out come
//! [`Effect`]s for the window to carry out.

//! The models hold the typed secrets; [`FlowView`] holds none (masks are
//! lengths) and never the session token, which only the worker has. Every
//! server string in a view is escaped first (`crate::text::display_safe`).

use std::time::{Duration, Instant};

use ferrogate_admin_client::client::{LoginInfo, Methods};
use ferrogate_admin_client::error::ClientError;
use ferrogate_admin_client::webauthn::AuthenticatorError;
use serde::Serialize;

use super::login::{Field, LoginModel, LoginView, Stage, Submission};
use super::secret::Secret;
use super::session::{Cmd, FactorChoice, Reply};
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
}

struct Session {
    info: LoginInfo,
    step_up_until: Option<i64>,
}

struct StepUpForm {
    code: Secret,
    error: Option<Problem>,
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
    /// The methods last offered for the form's user name.
    offered: Methods,
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
            offered: Methods::default(),
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

    /// Typed or pasted text, for the focused field (or the step-up code).
    pub fn type_text(&mut self, text: &str) {
        if self.busy.is_some() {
            return;
        }
        if let Some(form) = &mut self.step_up {
            form.error = None;
            form.code.push_str(text);
        } else if self.session.is_none() {
            self.login.type_text(text);
        }
    }

    /// `Backspace`.
    pub fn backspace(&mut self) {
        if self.busy.is_some() {
            return;
        }
        if let Some(form) = &mut self.step_up {
            form.error = None;
            form.code.pop();
        } else if self.session.is_none() {
            self.login.backspace();
        }
    }

    /// `Tab` / `Shift-Tab`.
    pub fn tab(&mut self, back: bool) {
        if self.session.is_none() {
            self.login.tab(back);
        }
    }

    /// A click on a field.
    pub fn focus(&mut self, field: Field) {
        if self.session.is_none() {
            self.login.focus(field);
        }
    }

    /// `Esc`: close the step-up prompt, or wipe the typed secrets.
    pub fn escape(&mut self) {
        if self.busy.is_some() {
            return;
        }
        if self.step_up.is_some() {
            self.step_up = None;
        } else if self.session.is_none() {
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
            return Vec::new();
        }
        match self.login.view().stage {
            Stage::Username => self.continue_with(),
            Stage::Secrets(m) if m.totp => self.submit(Submission::Code),
            Stage::Secrets(_) => self.submit(Submission::SecurityKey),
        }
    }

    /// "Continue": ask which factors the user name may use.
    pub fn continue_with(&mut self) -> Vec<Effect> {
        if self.busy.is_some() || self.session.is_some() || self.throttled() {
            return Vec::new();
        }
        match self.login.continue_with() {
            Ok(username) => {
                self.notice = None;
                self.send(Cmd::Offer { username }, Busy::Offer)
            }
            Err(_) => Vec::new(),
        }
    }

    /// "Change user".
    pub fn change_user(&mut self) {
        if self.busy.is_none() {
            self.login.back();
            self.notice = None;
        }
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

    /// Open the step-up prompt.
    pub fn open_step_up(&mut self) {
        if self.session.is_some() && self.busy.is_none() {
            self.step_up = Some(StepUpForm {
                code: Secret::new(),
                error: None,
            });
            self.notice = None;
        }
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
        self.send(
            Cmd::StepUp { factor },
            Busy::StepUp {
                key: how == Submission::SecurityKey,
            },
        )
    }

    /// Close the step-up prompt (its code is wiped).
    pub fn cancel_step_up(&mut self) {
        if self.busy.is_none() {
            self.step_up = None;
        }
    }

    /// Wipe everything the window holds and end the session.
    fn end(&mut self, notice: Option<Notice>) -> Vec<Effect> {
        self.login.wipe();
        self.session = None;
        self.step_up = None;
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
        let typed = !view.username.is_empty() || view.password_len > 0 || view.code_len > 0;
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
            Reply::Offered { username, result } => {
                match result {
                    Ok(methods) => {
                        self.offered = methods;
                        self.login.offered(&username, methods);
                    }
                    Err(e) => self.fail(&e, now),
                }
                Vec::new()
            }
            Reply::SignedIn { username, result } => self.signed_in_reply(&username, result, now),
            Reply::SteppedUp(result) => self.stepped_up_reply(result, now),
        }
    }

    fn fail(&mut self, e: &ClientError, now: Instant) {
        if let ClientError::Throttled(secs) = e {
            self.throttled_until = Some(now + Duration::from_secs((*secs).min(24 * 3600)));
        }
        self.notice = Some(Notice::Problem(problem(e)));
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
                } else {
                    self.login.retry(username, self.offered);
                }
                return Vec::new();
            }
        };
        if info.password_change_required {
            return self.end(Some(Notice::PasswordExpired));
        }
        if info.factor_enrollment_required {
            return self.end(Some(Notice::KeyRegistrationRequired));
        }
        self.login.wipe();
        self.notice = None;
        self.throttled_until = None;
        self.idle_limit = idle_limit(info.idle_timeout_secs);
        self.last_activity = now;
        self.session = Some(Session {
            info,
            step_up_until: None,
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
                Vec::new()
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
        });
        let step_up = match (&self.step_up, &self.session) {
            (Some(form), Some(s)) => Some(StepUpView {
                code_len: form.code.char_count(),
                error: form.error,
                can_submit_code: s.info.methods.totp && form.code.is_totp_code(),
                can_submit_key: s.info.methods.security_key && self.key_available,
            }),
            _ => None,
        };
        FlowView {
            login,
            busy: self.busy,
            key_available: self.key_available,
            notice: self.notice,
            throttle_secs_left,
            session,
            step_up,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for (expired, enroll, notice) in [
            (true, false, Notice::PasswordExpired),
            (false, true, Notice::KeyRegistrationRequired),
        ] {
            let mut f = Flow::new(true, now);
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
}
