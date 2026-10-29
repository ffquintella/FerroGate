//! The administrator window (feature `admin`, F22 §3).
//!
//! One `eframe` window, native `egui` only, drawn from the headless
//! [`Flow`]'s [`FlowView`]. Nothing typed is ever given to an `egui` text
//! widget: fields are painted by hand (a masked field shows dots, from a
//! length) and keystrokes go straight from the input events to the flow, so
//! `egui`'s text-edit state, undo history and galley cache never hold the
//! password or the code (the per-frame input queue is the residual F22 risk).

//! The CMIS link is a worker thread ([`crate::admin::session`]) that alone
//! holds the session token. Nothing is persisted: no `persistence` feature,
//! [`eframe::NativeOptions::persist_window`] off, no `save`, no
//! `persist_egui_memory`.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::admin::flow::{Busy, Effect, Flow, FlowView, Notice, Problem};
use crate::admin::login::{Field, Stage, Submission};
use crate::admin::session::{self, Link, SHUTDOWN_WAIT};
use crate::i18n::{fill, Lang, Msg};
use crate::text::{display_safe, display_safe_block, human_duration};

/// Run the administrator window until it is closed.
#[must_use]
pub fn run(lang: Lang) -> ExitCode {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            // Never the user name or any record data (F22 §3).
            .with_title(Msg::AdminAppName.text(lang))
            .with_inner_size([540.0, 480.0])
            .with_min_inner_size([440.0, 380.0]),
        persist_window: false,
        ..Default::default()
    };
    match eframe::run_native(
        "mia-tray-admin",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            Ok(Box::new(AdminApp::connect(lang, &ctx)))
        }),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "the window could not be shown");
            ExitCode::FAILURE
        }
    }
}

/// Where the window signs in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Server {
    /// The pinned endpoint (escaped) and a short pin fingerprint.
    Ready { endpoint: String, pin: String },
    /// No usable configuration (escaped reason).
    Missing(String),
}

struct AdminApp {
    lang: Lang,
    flow: Flow,
    link: Option<Box<dyn Link>>,
    server: Server,
}

/// Whether `event` is the administrator's own input (a key, typed or pasted
/// text, a click): only that restarts the idle clock. Pointer moves, focus
/// changes and other window events arrive with nobody at the keyboard.
fn is_user_input(event: &egui::Event) -> bool {
    matches!(
        event,
        egui::Event::Key { .. }
            | egui::Event::Text(_)
            | egui::Event::Paste(_)
            | egui::Event::PointerButton { .. }
    )
}

/// `abcd1234…89ef` of a hex pin.
fn fingerprint(hex: &str) -> String {
    match (hex.get(..8), hex.get(hex.len().saturating_sub(8)..)) {
        (Some(head), Some(tail)) if hex.len() > 16 => format!("{head}…{tail}"),
        _ => hex.to_string(),
    }
}

impl AdminApp {
    /// Load `admin.toml` and start the worker; repaint on each reply.
    fn connect(lang: Lang, ctx: &egui::Context) -> Self {
        let key = crate::admin::webauthn::platform();
        let key_available = key.is_some();
        match crate::admin::config::load() {
            Ok(cfg) => {
                let server = Server::Ready {
                    endpoint: display_safe(&cfg.endpoint, 80),
                    pin: cfg
                        .pins
                        .first()
                        .map(|p| fingerprint(&p.to_hex()))
                        .unwrap_or_default(),
                };
                let ctx = ctx.clone();
                let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || ctx.request_repaint());
                match session::spawn(cfg, key, wake) {
                    Ok(worker) => Self::new(lang, server, Some(Box::new(worker)), key_available),
                    Err(e) => {
                        tracing::error!(error = %e, "the admin client worker could not start");
                        Self::new(lang, Server::Missing(String::new()), None, key_available)
                    }
                }
            }
            Err(e) => {
                let why = format!("{e}\n\n{}", crate::admin::config::SETUP_HELP);
                Self::new(
                    lang,
                    Server::Missing(display_safe_block(&why, 2000)),
                    None,
                    false,
                )
            }
        }
    }

    fn new(lang: Lang, server: Server, link: Option<Box<dyn Link>>, key_available: bool) -> Self {
        Self {
            lang,
            flow: Flow::new(key_available, Instant::now()),
            link,
            server,
        }
    }

    /// Carry out the flow's effects. A command that cannot be queued is
    /// dropped (and wiped) and the flow told.
    fn apply(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Send(cmd) => {
                    let sent = self.link.as_mut().is_some_and(|l| l.send(cmd));
                    if !sent {
                        self.flow.send_failed();
                    }
                }
                Effect::EndSession => {
                    if let Some(l) = self.link.as_mut() {
                        l.end_session();
                    }
                }
            }
        }
    }

    /// The idle clock, replies that arrived, and this frame's keystrokes
    /// (borrowed from the input events, never cloned).
    fn read_input(&mut self, ctx: &egui::Context, now: Instant) {
        // The clock first: after a long idle the window locks before this
        // frame's replies or events can count as activity or reach the form.
        let effects = self.flow.tick(now);
        self.apply(effects);
        while let Some(reply) = self.link.as_mut().and_then(|l| l.try_recv()) {
            let effects = self.flow.on_reply(reply, now);
            self.apply(effects);
        }
        let mut effects = Vec::new();
        let flow = &mut self.flow;
        ctx.input(|input| {
            if input.events.iter().any(is_user_input) {
                flow.activity(now);
            }
            for event in &input.events {
                match event {
                    egui::Event::Text(text) | egui::Event::Paste(text) => flow.type_text(text),
                    egui::Event::Key {
                        key,
                        pressed: true,
                        modifiers,
                        ..
                    } => match key {
                        egui::Key::Backspace => flow.backspace(),
                        egui::Key::Escape => flow.escape(),
                        egui::Key::Tab => flow.tab(modifiers.shift),
                        egui::Key::Enter => effects.extend(flow.enter()),
                        _ => {}
                    },
                    _ => {}
                }
            }
        });
        self.apply(effects);
    }

    fn notice_text(&self, view: &FlowView) -> Option<String> {
        let lang = self.lang;
        let problem = |p: Problem| match p {
            Problem::Unreachable => Msg::AdminUnreachable.text(lang).to_string(),
            Problem::Rejected => Msg::AdminRejected.text(lang).to_string(),
            Problem::Throttled => fill(
                Msg::AdminThrottled.text(lang),
                &[(
                    "time",
                    &human_duration(
                        i64::try_from(view.throttle_secs_left.unwrap_or(0)).unwrap_or(0),
                    ),
                )],
            ),
            Problem::NotOffered => Msg::AdminNotOffered.text(lang).to_string(),
            Problem::KeyUnavailable => Msg::AdminKeyUnavailable.text(lang).to_string(),
            Problem::KeyCancelled => Msg::AdminKeyCancelled.text(lang).to_string(),
            Problem::KeyFailed => Msg::AdminKeyFailed.text(lang).to_string(),
            Problem::ServerError => Msg::AdminServerError.text(lang).to_string(),
            Problem::Incomplete => Msg::AdminMissingFields.text(lang).to_string(),
            Problem::NotSent => Msg::AdminNotSent.text(lang).to_string(),
        };
        if view.login.error.is_some() && view.session.is_none() {
            // Generic on purpose (F20): never says which part was wrong.
            return Some(Msg::AdminMissingFields.text(lang).to_string());
        }
        let text = match view.notice? {
            Notice::Problem(p) => problem(p),
            Notice::SignedOut => Msg::AdminSignedOut.text(lang).to_string(),
            Notice::Locked => Msg::AdminLocked.text(lang).to_string(),
            Notice::SessionEnded => Msg::AdminSessionEnded.text(lang).to_string(),
            Notice::PasswordExpired => Msg::AdminPasswordExpired.text(lang).to_string(),
            Notice::KeyRegistrationRequired => Msg::AdminKeyRequired.text(lang).to_string(),
            Notice::SteppedUp => {
                let left = view
                    .session
                    .as_ref()
                    .and_then(|s| s.step_up_until)
                    .map_or(0, |until| until - crate::unix_now());
                fill(
                    Msg::AdminSteppedUp.text(lang),
                    &[("time", &human_duration(left))],
                )
            }
        };
        Some(text)
    }

    /// Draw one frame at `now`.
    fn show(&mut self, ui: &mut egui::Ui, now: Instant) {
        let ctx = ui.ctx().clone();
        self.read_input(&ctx, now);
        let view = self.flow.view(now);
        let lang = self.lang;
        let mut clicked: Option<Field> = None;
        let mut actions: Vec<Action> = Vec::new();
        egui::CentralPanel::default().show(ui, |ui| {
            match &self.server {
                Server::Ready { endpoint, pin } => {
                    ui.weak(fill(
                        Msg::AdminServerLine.text(lang),
                        &[("endpoint", endpoint), ("pin", pin)],
                    ));
                }
                Server::Missing(why) => {
                    ui.colored_label(ui.visuals().warn_fg_color, Msg::AdminNoServer.text(lang));
                    ui.weak(why);
                }
            }
            ui.add_space(6.0);
            if view.session.is_some() {
                signed_in(ui, lang, &view, &mut actions);
            } else {
                sign_in(ui, lang, &view, &mut actions, &mut clicked);
            }
            ui.add_space(8.0);
            if let Some(busy) = view.busy {
                let msg = match busy {
                    Busy::Offer => Msg::AdminChecking,
                    Busy::SignIn { key: true } | Busy::StepUp { key: true } => Msg::AdminTouchKey,
                    Busy::SignIn { key: false } => Msg::AdminSigningIn,
                    Busy::StepUp { key: false } => Msg::AdminConfirming,
                };
                ui.label(msg.text(lang));
            } else if let Some(text) = self.notice_text(&view) {
                ui.label(text);
            }
            ui.add_space(12.0);
            ui.weak(Msg::AdminMemoryOnly.text(lang));
        });
        if let Some(field) = clicked {
            self.flow.focus(field);
        }
        for action in actions {
            let effects = match action {
                Action::Continue => self.flow.continue_with(),
                Action::ChangeUser => {
                    self.flow.change_user();
                    Vec::new()
                }
                Action::Submit(how) => self.flow.submit(how),
                Action::OpenStepUp => {
                    self.flow.open_step_up();
                    Vec::new()
                }
                Action::StepUp(how) => self.flow.submit_step_up(how),
                Action::CancelStepUp => {
                    self.flow.cancel_step_up();
                    Vec::new()
                }
                Action::SignOut => self.flow.sign_out(),
            };
            self.apply(effects);
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            let effects = self.flow.close();
            self.apply(effects);
        }
        // The idle lock and the throttle countdown need a clock.
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

/// A button the administrator pressed this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Continue,
    ChangeUser,
    Submit(Submission),
    OpenStepUp,
    StepUp(Submission),
    CancelStepUp,
    SignOut,
}

fn sign_in(
    ui: &mut egui::Ui,
    lang: Lang,
    view: &FlowView,
    actions: &mut Vec<Action>,
    clicked: &mut Option<Field>,
) {
    let login = &view.login;
    let idle = view.busy.is_none();
    ui.heading(Msg::AdminSignInTitle.text(lang));
    ui.add_space(8.0);
    match login.stage {
        Stage::Username => {
            ui.label(Msg::AdminUsername.text(lang));
            if field_box(
                ui,
                &display_safe(&login.username, 128),
                login.focus == Field::Username,
            )
            .clicked()
            {
                *clicked = Some(Field::Username);
            }
            ui.add_space(8.0);
            if ui
                .add_enabled(
                    login.can_continue && idle,
                    egui::Button::new(Msg::AdminContinue.text(lang)),
                )
                .clicked()
            {
                actions.push(Action::Continue);
            }
        }
        Stage::Secrets(methods) => {
            ui.horizontal(|ui| {
                ui.label(fill(
                    Msg::AdminUserLine.text(lang),
                    &[("name", &display_safe(&login.username, 128))],
                ));
                if ui
                    .add_enabled(
                        idle,
                        egui::Button::new(Msg::AdminChangeUser.text(lang)).small(),
                    )
                    .clicked()
                {
                    actions.push(Action::ChangeUser);
                }
            });
            ui.add_space(4.0);
            ui.label(Msg::AdminPassword.text(lang));
            if field_box(
                ui,
                &"•".repeat(login.password_len),
                login.focus == Field::Password,
            )
            .clicked()
            {
                *clicked = Some(Field::Password);
            }
            if methods.totp {
                ui.add_space(4.0);
                ui.label(Msg::AdminCode.text(lang));
                if field_box(ui, &"•".repeat(login.code_len), login.focus == Field::Code).clicked()
                {
                    *clicked = Some(Field::Code);
                }
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if methods.totp
                    && ui
                        .add_enabled(
                            login.can_submit_code && idle,
                            egui::Button::new(Msg::AdminSignIn.text(lang)),
                        )
                        .clicked()
                {
                    actions.push(Action::Submit(Submission::Code));
                }
                if methods.security_key
                    && ui
                        .add_enabled(
                            login.can_submit_key && idle,
                            egui::Button::new(Msg::AdminUseKey.text(lang)),
                        )
                        .clicked()
                {
                    actions.push(Action::Submit(Submission::SecurityKey));
                }
            });
            if methods.security_key && !view.key_available {
                ui.weak(Msg::AdminKeyUnavailable.text(lang));
            }
        }
    }
}

fn signed_in(ui: &mut egui::Ui, lang: Lang, view: &FlowView, actions: &mut Vec<Action>) {
    let Some(s) = &view.session else {
        return;
    };
    let idle = view.busy.is_none();
    ui.heading(fill(
        Msg::AdminSignedInAs.text(lang),
        &[("name", &s.display_name)],
    ));
    ui.label(fill(
        Msg::AdminGroups.text(lang),
        &[("groups", &s.groups.join(", "))],
    ));
    ui.label(fill(
        Msg::AdminAssurance.text(lang),
        &[("n", &s.aal.to_string())],
    ));
    ui.weak(fill(
        Msg::AdminIdleLock.text(lang),
        &[(
            "time",
            &human_duration(i64::try_from(s.idle_lock_secs).unwrap_or(0)),
        )],
    ));
    ui.add_space(8.0);
    if let Some(su) = &view.step_up {
        ui.group(|ui| {
            ui.label(Msg::AdminStepUpTitle.text(lang));
            if s.methods.totp {
                ui.label(Msg::AdminCode.text(lang));
                field_box(ui, &"•".repeat(su.code_len), true);
            }
            ui.horizontal(|ui| {
                if s.methods.totp
                    && ui
                        .add_enabled(
                            su.can_submit_code && idle,
                            egui::Button::new(Msg::AdminStepUpConfirm.text(lang)),
                        )
                        .clicked()
                {
                    actions.push(Action::StepUp(Submission::Code));
                }
                if s.methods.security_key
                    && ui
                        .add_enabled(
                            su.can_submit_key && idle,
                            egui::Button::new(Msg::AdminUseKey.text(lang)),
                        )
                        .clicked()
                {
                    actions.push(Action::StepUp(Submission::SecurityKey));
                }
                if ui
                    .add_enabled(idle, egui::Button::new(Msg::AdminCancel.text(lang)))
                    .clicked()
                {
                    actions.push(Action::CancelStepUp);
                }
            });
            if s.methods.security_key && !view.key_available {
                ui.weak(Msg::AdminKeyUnavailable.text(lang));
            }
            if su.error.is_some() {
                ui.colored_label(ui.visuals().error_fg_color, Msg::AdminRejected.text(lang));
            }
        });
    } else {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(idle, egui::Button::new(Msg::AdminStepUp.text(lang)))
                .clicked()
            {
                actions.push(Action::OpenStepUp);
            }
            if ui.button(Msg::AdminSignOut.text(lang)).clicked() {
                actions.push(Action::SignOut);
            }
        });
    }
}

impl eframe::App for AdminApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui, Instant::now());
    }

    // Nothing the administrator typed is ever written down.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn on_exit(&mut self) {
        let effects = self.flow.close();
        self.apply(effects);
        if let Some(link) = self.link.take() {
            link.shutdown(SHUTDOWN_WAIT);
        }
    }
}

/// A read-only box showing `text` (dots for a secret), focusable by click.
fn field_box(ui: &mut egui::Ui, text: &str, focused: bool) -> egui::Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 28.0), egui::Sense::click());
    let visuals = ui.visuals();
    let stroke = if focused {
        visuals.selection.stroke
    } else {
        visuals.widgets.inactive.bg_stroke
    };
    ui.painter().rect(
        rect,
        4.0,
        visuals.extreme_bg_color,
        stroke,
        egui::StrokeKind::Inside,
    );
    let mut caret = text.to_string();
    if focused {
        caret.push('|');
    }
    ui.painter().text(
        rect.left_center() + egui::vec2(6.0, 0.0),
        egui::Align2::LEFT_CENTER,
        caret,
        egui::TextStyle::Body.resolve(ui.style()),
        visuals.text_color(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use crate::admin::session::{Cmd, FactorChoice, Reply};
    use ferrogate_admin_client::client::{LoginInfo, Methods};

    const PASSWORD: &str = "c0rrect-horse-Battery-staple";
    const BOTH: Methods = Methods {
        totp: true,
        security_key: true,
    };

    /// What the fake worker saw.
    #[derive(Default)]
    struct Seen {
        cmds: Vec<&'static str>,
        /// Whether the sign-in carried exactly the typed secrets.
        secrets_ok: bool,
        ends: usize,
        replies: VecDeque<Reply>,
    }

    struct FakeLink(Rc<RefCell<Seen>>);

    impl Link for FakeLink {
        fn send(&mut self, cmd: Cmd) -> bool {
            let mut seen = self.0.borrow_mut();
            match cmd {
                Cmd::Offer { .. } => seen.cmds.push("offer"),
                Cmd::SignIn {
                    password, factor, ..
                } => {
                    seen.cmds.push("sign_in");
                    seen.secrets_ok = password.expose() == PASSWORD
                        && matches!(factor, FactorChoice::Code(c) if c.expose() == "123456");
                }
                Cmd::StepUp { .. } => seen.cmds.push("step_up"),
            }
            true
        }

        fn try_recv(&mut self) -> Option<Reply> {
            self.0.borrow_mut().replies.pop_front()
        }

        fn end_session(&mut self) {
            self.0.borrow_mut().ends += 1;
        }
    }

    fn app() -> (AdminApp, Rc<RefCell<Seen>>) {
        let seen = Rc::new(RefCell::new(Seen::default()));
        let server = Server::Ready {
            endpoint: "https://cmis:8444".into(),
            pin: fingerprint(&"ab".repeat(48)),
        };
        let app = AdminApp::new(
            Lang::En,
            server,
            Some(Box::new(FakeLink(Rc::clone(&seen)))),
            false,
        );
        (app, seen)
    }

    fn key(key: egui::Key) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }

    /// Run one frame with `events`; return every text the frame painted.
    fn frame(ctx: &egui::Context, app: &mut AdminApp, events: Vec<egui::Event>) -> Vec<String> {
        frame_at(ctx, app, events, Instant::now())
    }

    /// [`frame`] with the clock at `now`.
    fn frame_at(
        ctx: &egui::Context,
        app: &mut AdminApp,
        events: Vec<egui::Event>,
        now: Instant,
    ) -> Vec<String> {
        let input = egui::RawInput {
            events,
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |ui| app.show(ui, now));
        output.textures_delta.clear();
        output
            .shapes
            .iter()
            .filter_map(|s| match &s.shape {
                egui::epaint::Shape::Text(t) => Some(t.galley.text().to_string()),
                _ => None,
            })
            .collect()
    }

    /// Type the user name and receive the offer.
    fn to_secrets(ctx: &egui::Context, app: &mut AdminApp, seen: &Rc<RefCell<Seen>>) {
        frame(ctx, app, vec![egui::Event::Text("alice".into())]);
        frame(ctx, app, vec![key(egui::Key::Enter)]);
        seen.borrow_mut().replies.push_back(Reply::Offered {
            username: "alice".into(),
            result: Ok(BOTH),
        });
        frame(ctx, app, Vec::new());
    }

    #[test]
    fn typing_and_submitting_leave_no_copy_in_the_toolkit() {
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        to_secrets(&ctx, &mut app, &seen);
        let mut painted = Vec::new();
        painted.extend(frame(
            &ctx,
            &mut app,
            vec![egui::Event::Text(PASSWORD.into())],
        ));
        painted.extend(frame(&ctx, &mut app, vec![key(egui::Key::Tab)]));
        painted.extend(frame(
            &ctx,
            &mut app,
            vec![egui::Event::Paste("123456".into())],
        ));
        let memory = ctx.memory(|m| format!("{m:?}"));
        for secret in [PASSWORD, "123456"] {
            assert!(painted.iter().all(|t| !t.contains(secret)));
            assert!(!memory.contains(secret));
        }
        assert!(
            painted.iter().any(|t| t.contains("••")),
            "the mask is drawn"
        );
        // Submitted: the worker got the secrets, the form and egui hold none.
        painted.extend(frame(&ctx, &mut app, vec![key(egui::Key::Enter)]));
        assert_eq!(seen.borrow().cmds, vec!["offer", "sign_in"]);
        assert!(seen.borrow().secrets_ok);
        let view = app.flow.view(Instant::now()).login;
        assert_eq!((view.password_len, view.code_len), (0, 0));
        let memory = ctx.memory(|m| format!("{m:?}"));
        assert!(painted.iter().all(|t| !t.contains(PASSWORD)));
        assert!(!memory.contains(PASSWORD));
    }

    /// Sign in as `display_name`; return what the signed-in frame painted.
    fn signed_in_as(
        ctx: &egui::Context,
        app: &mut AdminApp,
        seen: &Rc<RefCell<Seen>>,
        display_name: &str,
    ) -> String {
        to_secrets(ctx, app, seen);
        frame(ctx, app, vec![egui::Event::Text(PASSWORD.into())]);
        frame(ctx, app, vec![key(egui::Key::Tab)]);
        frame(ctx, app, vec![egui::Event::Text("123456".into())]);
        frame(ctx, app, vec![key(egui::Key::Enter)]);
        seen.borrow_mut().replies.push_back(Reply::SignedIn {
            username: "alice".into(),
            result: Ok(LoginInfo {
                idle_timeout_secs: 900,
                absolute_expires_at: 0,
                aal: 3,
                password_change_required: false,
                factor_enrollment_required: false,
                admin_id: "adm_1".into(),
                display_name: display_name.into(),
                groups: vec!["ferrogate-approvers".into()],
                methods: BOTH,
            }),
        });
        frame(ctx, app, Vec::new()).join("\n")
    }

    #[test]
    fn a_signed_in_window_shows_inert_server_text_and_signs_out() {
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        let painted = signed_in_as(&ctx, &mut app, &seen, "Alice\u{1b}[2J\u{202e}");
        assert!(painted.contains("Signed in as Alice"), "{painted}");
        assert!(!painted.contains('\u{1b}') && !painted.contains('\u{202e}'));
        assert!(painted.contains("AAL3"));
        let effects = app.flow.sign_out();
        app.apply(effects);
        assert_eq!(seen.borrow().ends, 1, "the session ends at once");
        assert!(!app.flow.signed_in());
    }

    #[test]
    fn escape_and_close_wipe_the_secrets_and_end_the_session() {
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        to_secrets(&ctx, &mut app, &seen);
        frame(&ctx, &mut app, vec![egui::Event::Text(PASSWORD.into())]);
        frame(&ctx, &mut app, vec![key(egui::Key::Escape)]);
        let view = app.flow.view(Instant::now()).login;
        assert_eq!((view.username.as_str(), view.password_len), ("alice", 0));
        frame(&ctx, &mut app, vec![egui::Event::Text(PASSWORD.into())]);
        eframe::App::on_exit(&mut app);
        let view = app.flow.view(Instant::now()).login;
        assert_eq!((view.username.as_str(), view.password_len), ("", 0));
        assert!(seen.borrow().ends >= 1, "the session is ended (idempotent)");
        assert!(app.link.is_none(), "the worker is shut down");
    }

    #[test]
    fn without_a_configuration_nothing_is_sent() {
        let ctx = egui::Context::default();
        let mut app = AdminApp::new(Lang::En, Server::Missing("no pin".into()), None, false);
        let painted = frame(&ctx, &mut app, vec![egui::Event::Text("alice".into())]).join("\n");
        assert!(
            painted.contains("No admin server is configured"),
            "{painted}"
        );
        frame(&ctx, &mut app, vec![key(egui::Key::Enter)]);
        let view = app.flow.view(Instant::now());
        assert_eq!(view.notice, Some(Notice::Problem(Problem::NotSent)));
        assert_eq!(view.busy, None);
    }

    /// Longer than any idle lock (at most 15 min − 30 s).
    const LONG_IDLE: Duration = Duration::from_secs(1000);

    /// Events that arrive without anyone at the keyboard, and real input.
    fn wake_events() -> Vec<(&'static str, egui::Event)> {
        vec![
            (
                "pointer move",
                egui::Event::PointerMoved(egui::pos2(5.0, 5.0)),
            ),
            ("focus", egui::Event::WindowFocused(true)),
            ("text", egui::Event::Text("x".into())),
            ("key", key(egui::Key::Backspace)),
        ]
    }

    #[test]
    fn a_long_idle_locks_before_the_frames_own_events_count() {
        for (what, event) in wake_events() {
            // A half-typed password.
            let ctx = egui::Context::default();
            let (mut app, seen) = app();
            to_secrets(&ctx, &mut app, &seen);
            frame(&ctx, &mut app, vec![egui::Event::Text(PASSWORD.into())]);
            let later = Instant::now() + LONG_IDLE;
            let painted = frame_at(&ctx, &mut app, vec![event], later).join("\n");
            let view = app.flow.view(later);
            assert_eq!(view.notice, Some(Notice::Locked), "{what}: {painted}");
            assert_eq!(view.login.password_len, 0, "{what}");
            assert_eq!(view.login.stage, Stage::Username, "{what}");
            assert!(!painted.contains('•'), "{what}: {painted}");
            assert_eq!(seen.borrow().ends, 1, "{what}");
        }
        for (what, event) in wake_events() {
            // A signed-in session summary.
            let ctx = egui::Context::default();
            let (mut app, seen) = app();
            let shown = signed_in_as(&ctx, &mut app, &seen, "Alice");
            assert!(shown.contains("Signed in as Alice"), "{shown}");
            let later = Instant::now() + LONG_IDLE;
            let painted = frame_at(&ctx, &mut app, vec![event], later).join("\n");
            assert!(!app.flow.signed_in(), "{what}");
            assert!(!painted.contains("Alice"), "{what}: {painted}");
            assert_eq!(seen.borrow().ends, 1, "{what}");
        }
    }

    #[test]
    fn only_keys_text_and_clicks_restart_the_idle_clock() {
        let start = Instant::now();
        let half = start + LONG_IDLE / 2;
        let click = egui::Event::PointerButton {
            pos: egui::pos2(5.0, 5.0),
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        };
        let passive = [
            egui::Event::PointerMoved(egui::pos2(5.0, 5.0)),
            egui::Event::WindowFocused(true),
        ];
        // A password typed at `start`, `halfway` events, a frame at the end.
        let run = |halfway: Vec<egui::Event>| {
            let ctx = egui::Context::default();
            let (mut a, seen) = app();
            to_secrets(&ctx, &mut a, &seen);
            let typed = vec![egui::Event::Text(PASSWORD.into())];
            frame_at(&ctx, &mut a, typed, start);
            frame_at(&ctx, &mut a, halfway, half);
            frame_at(&ctx, &mut a, Vec::new(), start + LONG_IDLE);
            let ends = seen.borrow().ends;
            (ends, a.flow.view(start + LONG_IDLE).login.password_len)
        };
        // Moves and focus changes halfway: the window still locks on time.
        assert_eq!(run(passive.into()), (1, 0), "a passive event kept it open");
        // A click halfway does restart it.
        let (ends, password_len) = run(vec![click]);
        assert_eq!(ends, 0, "a click is activity");
        assert!(password_len > 0);
    }

    #[test]
    fn nothing_is_persisted() {
        let (app, _) = app();
        assert!(!eframe::App::persist_egui_memory(&app));
    }

    #[test]
    fn the_pin_is_shown_as_a_short_fingerprint() {
        assert_eq!(fingerprint(&"ab".repeat(48)), "abababab…abababab");
        assert_eq!(fingerprint("abcd"), "abcd");
    }
}
