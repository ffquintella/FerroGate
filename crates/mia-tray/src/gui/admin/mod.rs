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
//! `persist_egui_memory`. Enrollment and second factors: [`enroll`],
//! [`factors`]; a TOTP seed is painted by [`seed`], never as a string.
//! Requests, approvals and their decisions: [`views`].

mod enroll;
mod factors;
mod seed;
mod views;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use ferrogate_admin_client::factors::FactorMethod;

use crate::admin::enroll::EnrollField;
use crate::admin::factors::FactorField;
use crate::admin::flow::{Busy, Effect, Flow, FlowView, Notice, Problem};
use crate::admin::login::{Field, Stage, Submission};
use crate::admin::session::{self, Link, SHUTDOWN_WAIT};
use crate::admin::views::{Tab, ViewAction};
use crate::i18n::{fill, Lang, Msg};
use crate::text::{display_safe, display_safe_block, human_duration};

/// Run the administrator window until it is closed.
#[must_use]
pub fn run(lang: Lang) -> ExitCode {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            // Never the user name or any record data (F22 §3).
            .with_title(Msg::AdminAppName.text(lang))
            .with_inner_size([820.0, 700.0])
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
            Problem::EnrollmentRejected => Msg::AdminEnrollRejected.text(lang).to_string(),
            Problem::PasswordPolicy => Msg::AdminPasswordPolicy.text(lang).to_string(),
            Problem::FactorRejected => Msg::AdminFactorRejected.text(lang).to_string(),
            Problem::LastFactor => Msg::AdminLastFactor.text(lang).to_string(),
        };
        if view.login.error.is_some() && view.session.is_none() && view.enroll.is_none() {
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
            Notice::StepUpFirst => Msg::AdminStepUpFirst.text(lang).to_string(),
            Notice::Enrolled => Msg::AdminEnrolled.text(lang).to_string(),
            Notice::FactorAdded => Msg::AdminFactorAdded.text(lang).to_string(),
            Notice::FactorRemoved => Msg::AdminFactorRemoved.text(lang).to_string(),
            Notice::KeyRegistered => Msg::AdminKeyRegistered.text(lang).to_string(),
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

    /// The window's content for `view` (buttons pressed go to `actions`).
    fn body(
        &self,
        ui: &mut egui::Ui,
        view: &FlowView,
        actions: &mut Vec<Action>,
        clicked: &mut Option<Field>,
    ) {
        let lang = self.lang;
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
        let idle = view.busy.is_none();
        // Borrowed for this frame only; never copied into a view model.
        let shown = self.flow.seed_display();
        if view.session.is_some() {
            signed_in(ui, lang, view, actions);
            if let Some(f) = &view.factors {
                ui.separator();
                factors::panel(ui, lang, f, shown.as_ref(), idle, actions);
            }
            if let Some(v) = &view.views {
                ui.separator();
                views::panel(ui, lang, v, idle, actions);
            }
        } else if let Some(w) = &view.enroll {
            enroll::wizard(ui, lang, w, shown.as_ref(), idle, actions);
        } else {
            sign_in(ui, lang, view, actions, clicked);
            ui.add_space(6.0);
            if ui
                .add_enabled(
                    idle,
                    egui::Button::new(Msg::AdminEnrollOpen.text(lang)).small(),
                )
                .clicked()
            {
                actions.push(Action::OpenEnrollment);
            }
        }
        ui.add_space(8.0);
        if let Some(busy) = view.busy {
            let msg = match busy {
                Busy::Offer => Msg::AdminChecking,
                Busy::SignIn { key: true }
                | Busy::StepUp { key: true }
                | Busy::Enroll { key: true }
                | Busy::Factors { key: true }
                | Busy::Register { key: true } => Msg::AdminTouchKey,
                Busy::Register { key: false } => Msg::AdminRegistering,
                Busy::SignIn { key: false } => Msg::AdminSigningIn,
                Busy::StepUp { key: false } => Msg::AdminConfirming,
                Busy::Enroll { key: false } | Busy::Factors { key: false } | Busy::Views => {
                    Msg::AdminWorking
                }
            };
            ui.label(msg.text(lang));
        } else if let Some(text) = self.notice_text(view) {
            ui.label(text);
        }
        ui.add_space(12.0);
        ui.weak(Msg::AdminMemoryOnly.text(lang));
    }

    /// Draw one frame at `now`.
    fn show(&mut self, ui: &mut egui::Ui, now: Instant) {
        let ctx = ui.ctx().clone();
        self.read_input(&ctx, now);
        let view = self.flow.view(now);
        let mut clicked: Option<Field> = None;
        let mut actions: Vec<Action> = Vec::new();
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.body(ui, &view, &mut actions, &mut clicked);
            });
        });
        if let Some(field) = clicked {
            self.flow.focus(field);
        }
        self.act(actions);
        if ctx.input(|i| i.viewport().close_requested()) {
            let effects = self.flow.close();
            self.apply(effects);
        }
        // The idle lock and the throttle countdown need a clock.
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    /// Carry out the buttons pressed this frame.
    fn act(&mut self, actions: Vec<Action>) {
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
                Action::OpenEnrollment => {
                    self.flow.open_enrollment();
                    Vec::new()
                }
                Action::CloseEnrollment => {
                    self.flow.close_enrollment();
                    Vec::new()
                }
                Action::FocusEnroll(field) => {
                    self.flow.focus_enroll(field);
                    Vec::new()
                }
                Action::EnrollContinue => self.flow.enroll_continue(),
                Action::EnrollRegisterKey => self.flow.enroll_register_key(),
                Action::EnrollFinish => self.flow.enroll_finish(),
                Action::ToggleSeedText => {
                    self.flow.toggle_seed_text();
                    Vec::new()
                }
                Action::OpenFactors => self.flow.open_factors(),
                Action::CloseFactors => {
                    self.flow.close_factors();
                    Vec::new()
                }
                Action::FocusFactor(field) => {
                    self.flow.focus_factor(field);
                    Vec::new()
                }
                Action::AddFactor(method) => self.flow.add_factor(method),
                Action::RemoveFactor(id) => {
                    self.flow.remove_factor(&id);
                    Vec::new()
                }
                Action::CancelFactorForm => {
                    self.flow.cancel_factor_form();
                    Vec::new()
                }
                Action::SubmitFactor(how) => self.flow.submit_factor(how),
                Action::OpenViews(tab) => self.flow.open_views(tab),
                Action::CloseViews => {
                    self.flow.close_views();
                    Vec::new()
                }
                Action::View(action) => self.flow.views_action(action),
            };
            self.apply(effects);
        }
    }
}

/// A button the administrator pressed this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Continue,
    ChangeUser,
    Submit(Submission),
    OpenStepUp,
    StepUp(Submission),
    CancelStepUp,
    SignOut,
    OpenEnrollment,
    CloseEnrollment,
    FocusEnroll(EnrollField),
    EnrollContinue,
    EnrollRegisterKey,
    EnrollFinish,
    ToggleSeedText,
    OpenFactors,
    CloseFactors,
    FocusFactor(FactorField),
    AddFactor(FactorMethod),
    RemoveFactor(String),
    CancelFactorForm,
    SubmitFactor(Submission),
    OpenViews(Tab),
    CloseViews,
    View(ViewAction),
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
    if s.restricted {
        // Held to registering a key: nothing else is offered.
        ui.label(fill(
            Msg::AdminSignedInAs.text(lang),
            &[("name", &s.display_name)],
        ));
        if ui.button(Msg::AdminSignOut.text(lang)).clicked() {
            actions.push(Action::SignOut);
        }
        return;
    }
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
            // The fresh factor of an add is not a step-up (F20 §7 "M").
            ui.label(if su.for_add {
                Msg::AdminAddProofTitle.text(lang)
            } else {
                Msg::AdminStepUpTitle.text(lang)
            });
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
            match (su.error, su.for_add) {
                (None, _) => {}
                (Some(p), true) => {
                    ui.colored_label(ui.visuals().error_fg_color, add_problem(lang, view, p));
                }
                (Some(_), false) => {
                    ui.colored_label(ui.visuals().error_fg_color, Msg::AdminRejected.text(lang));
                }
            }
        });
    } else {
        ui.horizontal(|ui| session_buttons(ui, lang, view, idle, actions));
    }
}

/// Why an add's fresh factor did not go through (nothing was registered).
fn add_problem(lang: Lang, view: &FlowView, p: Problem) -> String {
    match p {
        Problem::Rejected => Msg::AdminAddRejected.text(lang).to_string(),
        Problem::Throttled => fill(
            Msg::AdminThrottled.text(lang),
            &[(
                "time",
                &human_duration(i64::try_from(view.throttle_secs_left.unwrap_or(0)).unwrap_or(0)),
            )],
        ),
        Problem::Unreachable => Msg::AdminUnreachable.text(lang).to_string(),
        Problem::NotOffered => Msg::AdminNotOffered.text(lang).to_string(),
        Problem::KeyUnavailable => Msg::AdminKeyUnavailable.text(lang).to_string(),
        Problem::KeyCancelled => Msg::AdminKeyCancelled.text(lang).to_string(),
        Problem::KeyFailed => Msg::AdminKeyFailed.text(lang).to_string(),
        _ => Msg::AdminServerError.text(lang).to_string(),
    }
}

/// The signed-in summary's buttons: step up, the views, second factors,
/// sign out.
fn session_buttons(
    ui: &mut egui::Ui,
    lang: Lang,
    view: &FlowView,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    if ui
        .add_enabled(idle, egui::Button::new(Msg::AdminStepUp.text(lang)))
        .clicked()
    {
        actions.push(Action::OpenStepUp);
    }
    if view.views.is_none() {
        for (tab, msg) in [
            (Tab::Requests, Msg::AdminRequestsOpen),
            (Tab::Approvals, Msg::AdminApprovalsOpen),
        ] {
            if ui
                .add_enabled(idle, egui::Button::new(msg.text(lang)))
                .clicked()
            {
                actions.push(Action::OpenViews(tab));
            }
        }
    }
    let deciding = view.views.as_ref().is_some_and(|v| v.pending);
    if view.factors.is_none()
        && ui
            .add_enabled(
                idle && !deciding,
                egui::Button::new(Msg::AdminFactorsOpen.text(lang)),
            )
            .clicked()
    {
        actions.push(Action::OpenFactors);
    }
    if ui.button(Msg::AdminSignOut.text(lang)).clicked() {
        actions.push(Action::SignOut);
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
        /// Idempotency keys of the decisions sent.
        keys: Vec<String>,
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
                Cmd::BeginEnrollment { .. } => seen.cmds.push("begin_enrollment"),
                Cmd::EnrollKey { .. } => seen.cmds.push("enroll_key"),
                Cmd::CompleteEnrollment { .. } => seen.cmds.push("complete_enrollment"),
                Cmd::ListFactors => seen.cmds.push("list_factors"),
                Cmd::BeginAddFactor { .. } => seen.cmds.push("begin_add_factor"),
                Cmd::CompleteAddTotp { .. } | Cmd::CompleteAddKey { .. } => {
                    seen.cmds.push("complete_add_factor");
                }
                Cmd::RemoveFactor { .. } => seen.cmds.push("remove_factor"),
                Cmd::Permissions => seen.cmds.push("permissions"),
                Cmd::ListRequests(_) => seen.cmds.push("list_requests"),
                Cmd::GetRequest(_) => seen.cmds.push("get_request"),
                Cmd::ListApprovals(_) => seen.cmds.push("list_approvals"),
                Cmd::GetApproval(_) => seen.cmds.push("get_approval"),
                Cmd::Mutate(m) => {
                    seen.cmds.push("mutate");
                    seen.keys.push(m.idempotency_key().to_string());
                }
                Cmd::Register { req, proof } => {
                    seen.cmds.push("register");
                    seen.keys.push(req.idempotency_key.clone());
                    seen.secrets_ok = req.proof.is_none()
                        && matches!(proof, FactorChoice::Code(c) if c.expose() == "123456");
                }
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

    /// Run one frame; count the filled rectangles it painted and return
    /// its texts.
    fn frame_rects(
        ctx: &egui::Context,
        app: &mut AdminApp,
        events: Vec<egui::Event>,
    ) -> (usize, Vec<String>) {
        let input = egui::RawInput {
            events,
            ..Default::default()
        };
        let now = Instant::now();
        let mut output = ctx.run_ui(input, |ui| app.show(ui, now));
        output.textures_delta.clear();
        let mut rects = 0;
        let mut texts = Vec::new();
        for s in &output.shapes {
            match &s.shape {
                egui::epaint::Shape::Rect(_) => rects += 1,
                egui::epaint::Shape::Text(t) => texts.push(t.galley.text().to_string()),
                _ => {}
            }
        }
        (rects, texts)
    }

    fn enrollment_offer() -> ferrogate_admin_client::enroll::EnrollmentOffer {
        ferrogate_admin_client::enroll::EnrollmentOffer {
            username: "new.person".into(),
            username_choosable: false,
            display_name: "New\u{1b}[2J Person".into(),
            password_min_len: 24,
            totp: Some(crate::admin::seed::tests::seed()),
            key: None,
        }
    }

    #[test]
    fn the_seed_is_painted_as_squares_and_single_glyphs_only() {
        use crate::admin::seed::tests::SECRET;
        const TOKEN: &str = "fgae_0123456789abcdef";
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        app.flow.open_enrollment();
        let mut painted = frame(&ctx, &mut app, vec![egui::Event::Paste(TOKEN.into())]);
        painted.extend(frame(&ctx, &mut app, vec![key(egui::Key::Enter)]));
        assert_eq!(seen.borrow().cmds, vec!["begin_enrollment"]);
        seen.borrow_mut()
            .replies
            .push_back(Reply::EnrollmentBegun(Ok(Box::new(enrollment_offer()))));
        let (rects, texts) = frame_rects(&ctx, &mut app, Vec::new());
        assert!(rects > 200, "the QR modules are painted: {rects}");
        painted.extend(texts);
        app.flow.toggle_seed_text();
        let (_, texts) = frame_rects(&ctx, &mut app, Vec::new());
        let glyphs: String = texts
            .iter()
            .filter(|t| t.chars().count() == 1)
            .map(String::as_str)
            .collect();
        assert!(
            glyphs.contains(&SECRET[..16]),
            "the text is shown: {glyphs}"
        );
        painted.extend(texts);
        let joined = painted.join("\n");
        assert!(joined.contains("new.person") && !joined.contains('\u{1b}'));
        // No galley ever held three characters of the seed in a row, or the
        // token; neither did egui's memory.
        for window in SECRET.as_bytes().windows(3) {
            let run = std::str::from_utf8(window).unwrap();
            assert!(
                painted.iter().all(|t| !t.contains(run)),
                "{run} painted in one galley"
            );
        }
        assert!(painted
            .iter()
            .all(|t| !t.contains(SECRET) && !t.contains(TOKEN)));
        let memory = ctx.memory(|m| format!("{m:?}"));
        assert!(!memory.contains(&SECRET[..8]) && !memory.contains(TOKEN));
        // Closing the wizard wipes it: nothing of the seed is painted again.
        app.flow.close_enrollment();
        let (rects, _) = frame_rects(&ctx, &mut app, Vec::new());
        assert!(rects < 50, "{rects}");
        assert!(app.flow.seed_display().is_none());
    }

    #[test]
    fn the_factors_panel_shows_inert_labels_and_sends_a_removal() {
        use ferrogate_admin_client::factors::FactorInfo;
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        signed_in_as(&ctx, &mut app, &seen, "Alice");
        let effects = app.flow.open_factors();
        app.apply(effects);
        let row = |id: &str, method, label: &str| FactorInfo {
            factor_id: id.into(),
            method,
            label: label.into(),
            created_at: 1_790_000_000,
            last_used_at: 0,
        };
        seen.borrow_mut().replies.push_back(Reply::Factors(Ok(vec![
            row("totp", FactorMethod::Totp, "TOTP authenticator"),
            row("wa_1", FactorMethod::SecurityKey, "Desk\u{1b}[2J\u{202e}"),
        ])));
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(painted.contains("Your second factors"), "{painted}");
        assert!(painted.contains("Security key: Desk"), "{painted}");
        assert!(!painted.contains('\u{1b}') && !painted.contains('\u{202e}'));
        assert!(painted.contains("2026-09-21"), "{painted}");
        assert!(painted.contains("Remove"));
        app.flow.remove_factor("wa_1");
        frame(&ctx, &mut app, vec![egui::Event::Text("123456".into())]);
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(!painted.contains("123456"), "masked");
        frame(&ctx, &mut app, vec![key(egui::Key::Enter)]);
        assert_eq!(
            seen.borrow().cmds,
            vec!["offer", "sign_in", "list_factors", "remove_factor"]
        );
    }

    #[test]
    fn a_restricted_session_shows_only_key_registration() {
        let ctx = egui::Context::default();
        let seen = Rc::new(RefCell::new(Seen::default()));
        let server = Server::Ready {
            endpoint: "https://cmis:8444".into(),
            pin: fingerprint(&"ab".repeat(48)),
        };
        let mut app = AdminApp::new(
            Lang::En,
            server,
            Some(Box::new(FakeLink(Rc::clone(&seen)))),
            true,
        );
        to_secrets(&ctx, &mut app, &seen);
        frame(&ctx, &mut app, vec![egui::Event::Text(PASSWORD.into())]);
        frame(&ctx, &mut app, vec![key(egui::Key::Tab)]);
        frame(&ctx, &mut app, vec![egui::Event::Text("123456".into())]);
        frame(&ctx, &mut app, vec![key(egui::Key::Enter)]);
        seen.borrow_mut().replies.push_back(Reply::SignedIn {
            username: "alice".into(),
            result: Ok(LoginInfo {
                idle_timeout_secs: 900,
                absolute_expires_at: 0,
                aal: 2,
                password_change_required: false,
                factor_enrollment_required: true,
                admin_id: "adm_1".into(),
                display_name: "Alice".into(),
                groups: vec!["ferrogate-approvers".into()],
                methods: Methods {
                    totp: true,
                    security_key: false,
                },
            }),
        });
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(
            painted.contains("Register a security key to continue"),
            "{painted}"
        );
        assert!(!painted.contains("Confirm it is you"), "{painted}");
        assert!(!painted.contains("Second factors"), "{painted}");
        assert!(painted.contains("Register security key"), "{painted}");
    }

    fn push(seen: &Rc<RefCell<Seen>>, reply: Reply) {
        seen.borrow_mut().replies.push_back(reply);
    }

    /// Signed in with `permissions`, the Requests view on one hostile
    /// pending request; returns what the list frame painted.
    fn on_the_requests(
        ctx: &egui::Context,
        app: &mut AdminApp,
        seen: &Rc<RefCell<Seen>>,
        permissions: &[&str],
    ) -> String {
        use crate::admin::decide::tests::request;
        use ferrogate_admin_client::approvals::filters::RiskFlags;
        use ferrogate_admin_client::approvals::proto::ListAppRequestsResponse;
        signed_in_as(ctx, app, seen, "Alice");
        app.act(vec![Action::OpenViews(Tab::Requests)]);
        let perms = permissions.iter().map(|p| (*p).to_string()).collect();
        push(seen, Reply::Permissions(Ok(perms)));
        frame(ctx, app, Vec::new());
        push(
            seen,
            Reply::Requests(Ok(ListAppRequestsResponse {
                items: vec![request(RiskFlags::UNSIGNED)],
                next_page_token: String::new(),
            })),
        );
        frame(ctx, app, Vec::new()).join("\n")
    }

    #[test]
    fn the_views_show_inert_text_and_resend_a_decision_once_after_a_step_up() {
        use crate::admin::decide::tests::detail;
        use crate::admin::decide::DecisionKind;
        use ferrogate_admin_client::approvals::proto::ApproveAppRequestResponse;
        use ferrogate_admin_client::approvals::Mutated;
        use ferrogate_admin_client::error::{ClientError, Code, RpcError};
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        let painted = on_the_requests(
            &ctx,
            &mut app,
            &seen,
            &["app_request.approve", "app_request.deny"],
        );
        assert!(painted.contains("R-0000A1B2"), "{painted}");
        assert!(!painted.contains('\u{202e}') && !painted.contains('\u{1b}'));
        assert!(painted.contains("⚠1"), "the risk flag is counted");
        app.act(vec![Action::View(ViewAction::OpenRequest(0))]);
        push(&seen, Reply::Request(Ok(Box::new(detail(0)))));
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(painted.contains("Request R-0000A1B2"), "{painted}");
        assert!(painted.contains("Approve…") && painted.contains("Deny…"));

        app.act(vec![Action::View(ViewAction::Decide(
            DecisionKind::Approve,
        ))]);
        let painted = frame(&ctx, &mut app, vec![egui::Event::Text("ticket 42".into())]);
        assert!(painted
            .join("\n")
            .contains("Manual approval for every new binary"));
        app.act(vec![Action::View(ViewAction::DecisionNext)]);
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(painted.contains("Review what will be sent"), "{painted}");
        assert!(painted.contains("Note: ticket 42"), "{painted}");
        app.act(vec![Action::View(ViewAction::DecisionConfirm)]);
        let step_up = ClientError::Other(RpcError::local(
            Code::FailedPrecondition,
            "step_up_required",
        ));
        push(&seen, Reply::Mutated(Err(step_up)));
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(
            painted.contains("Confirm with your second factor"),
            "{painted}"
        );
        frame(&ctx, &mut app, vec![egui::Event::Text("123456".into())]);
        frame(&ctx, &mut app, vec![key(egui::Key::Enter)]);
        push(&seen, Reply::SteppedUp(Ok(crate::unix_now() + 300)));
        frame(&ctx, &mut app, Vec::new());
        {
            let s = seen.borrow();
            assert!(
                s.cmds.ends_with(&["mutate", "step_up", "mutate"]),
                "{:?}",
                s.cmds
            );
            assert_eq!(s.keys.len(), 2);
            assert_eq!(s.keys[0], s.keys[1], "the retry reuses the key");
        }
        let done = Mutated::Approved(ApproveAppRequestResponse {
            allowlist_generation: 9,
            ..ApproveAppRequestResponse::default()
        });
        push(&seen, Reply::Mutated(Ok(Box::new(done))));
        frame(&ctx, &mut app, Vec::new());
        assert_eq!(seen.borrow().cmds.last(), Some(&"get_request"), "reloaded");
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(painted.contains("host generation 9"), "{painted}");
        let memory = ctx.memory(|m| format!("{m:?}"));
        assert!(!memory.contains("123456"));
    }

    #[test]
    fn a_viewer_sees_no_decision_buttons_and_a_lock_clears_the_views() {
        use crate::admin::decide::tests::detail;
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        on_the_requests(&ctx, &mut app, &seen, &["app_request.list"]);
        app.act(vec![Action::View(ViewAction::OpenRequest(0))]);
        push(&seen, Reply::Request(Ok(Box::new(detail(0)))));
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(painted.contains("Request R-0000A1B2"), "{painted}");
        assert!(!painted.contains("Approve…") && !painted.contains("Deny…"));
        let later = Instant::now() + LONG_IDLE;
        let painted = frame_at(&ctx, &mut app, Vec::new(), later).join("\n");
        assert!(!painted.contains("R-0000A1B2"), "{painted}");
        assert!(app.flow.view(later).views.is_none());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one frame per step of the add.
    fn an_add_shows_its_outcome_and_assertion_and_always_asks_a_fresh_masked_code() {
        use crate::admin::decide::tests::HOST;
        use crate::admin::decide::{DecisionField, DecisionKind};
        use ferrogate_admin_client::approvals::proto::{AppRequestInfo, ApprovalInfo};
        use ferrogate_admin_client::approvals::register::AdminRegisterApplicationResponse;
        use ferrogate_admin_client::error::ClientError;
        let ctx = egui::Context::default();
        let (mut app, seen) = app();
        let painted = on_the_requests(
            &ctx,
            &mut app,
            &seen,
            &["app.direct_register", "app_request.approve"],
        );
        assert!(painted.contains("Add application…"), "{painted}");
        app.act(vec![Action::View(ViewAction::Decide(
            DecisionKind::Register,
        ))]);
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(
            painted.contains("Add an application by known hash and path"),
            "{painted}"
        );
        assert!(painted.contains("(your assertion)"), "{painted}");
        for (field, text) in [
            (DecisionField::Host, HOST.to_string()),
            (
                DecisionField::Path,
                "/opt/tool/bin/tool\u{202e}gpj".to_string(),
            ),
            (DecisionField::Sha, "ab".repeat(48)),
            (DecisionField::Uid, "1000".to_string()),
            (DecisionField::User, "alice".to_string()),
        ] {
            app.act(vec![Action::View(ViewAction::FocusDecision(field))]);
            frame(&ctx, &mut app, vec![egui::Event::Paste(text)]);
        }
        app.act(vec![Action::View(ViewAction::DecisionNext)]);
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        for want in [
            "Review what will be sent",
            "registers AND approves",
            "recorded as approved by the same person",
            "YOUR ASSERTION",
            "fresh second factor",
            "Confirm with a fresh second factor…",
        ] {
            assert!(painted.contains(want), "{want}: {painted}");
        }
        assert!(!painted.contains('\u{202e}'), "typed text is drawn inert");

        // Just stepped up at sign-in? Irrelevant: the add asks a code.
        app.act(vec![Action::View(ViewAction::DecisionConfirm)]);
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(
            painted.contains("Confirm this addition with a fresh second factor"),
            "{painted}"
        );
        assert!(
            !seen.borrow().cmds.contains(&"register"),
            "nothing sent yet"
        );
        let mut typed = frame(&ctx, &mut app, vec![egui::Event::Text("123456".into())]);
        typed.extend(frame(&ctx, &mut app, Vec::new()));
        assert!(typed.iter().all(|t| !t.contains("123456")), "masked");
        frame(&ctx, &mut app, vec![key(egui::Key::Enter)]);
        assert_eq!(seen.borrow().cmds.last(), Some(&"register"));
        assert!(seen.borrow().secrets_ok, "the code went with the request");
        push(&seen, Reply::Registered(Err(ClientError::Rejected)));
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert!(
            painted.contains("The code was not accepted; nothing was registered."),
            "{painted}"
        );
        frame(&ctx, &mut app, vec![egui::Event::Text("123456".into())]);
        frame(&ctx, &mut app, vec![key(egui::Key::Enter)]);
        {
            let s = seen.borrow();
            assert_eq!(s.keys.len(), 2);
            assert_eq!(s.keys[0], s.keys[1], "the retry reuses the key");
        }
        let done = AdminRegisterApplicationResponse {
            request: Some(AppRequestInfo {
                request_id: "0192a9f1-0000-7000-8000-00000000a1b2".into(),
                ..AppRequestInfo::default()
            }),
            approval: Some(ApprovalInfo {
                approval_id: "0190f0aa-0000-7000-8000-00000000beef".into(),
                ..ApprovalInfo::default()
            }),
            allowlist_generation: 7,
            ..AdminRegisterApplicationResponse::default()
        };
        push(&seen, Reply::Registered(Ok(Box::new(done))));
        let painted = frame(&ctx, &mut app, Vec::new()).join("\n");
        assert_eq!(
            seen.borrow().cmds.last(),
            Some(&"list_requests"),
            "reloaded"
        );
        assert!(
            painted.contains("Registered and approved: request R-0000A1B2, approval A-0000BEEF"),
            "{painted}"
        );
        let memory = ctx.memory(|m| format!("{m:?}"));
        assert!(!memory.contains("123456"));
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
