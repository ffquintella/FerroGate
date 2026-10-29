//! The administrator window (feature `admin`, F22 §3).
//!
//! One `eframe` window, native `egui` only. Nothing the administrator types is
//! ever given to an `egui` text widget: the fields below are drawn by hand
//! from the [`LoginView`] (a masked field shows dots, from a length), and the
//! keystrokes that reach the focused field are read straight from the input
//! events and handed to the [`LoginModel`] by reference. So `egui`'s text-edit
//! state, its undo history and its galley cache never hold the password or the
//! code. What remains is the toolkit's own per-frame input queue, which holds
//! a typed character until the frame ends (the residual risk F22 documents).
//!
//! Nothing is persisted: `eframe`'s `persistence` feature is not enabled, the
//! window state is not saved ([`eframe::NativeOptions::persist_window`] is off)
//! and the app implements neither `save` nor `persist_egui_memory`.

use std::process::ExitCode;

use eframe::egui;

use crate::admin::login::{Field, LoginModel};
use crate::admin::secret::SessionToken;
use crate::i18n::{Lang, Msg};

/// Run the administrator window until it is closed.
#[must_use]
pub fn run(lang: Lang) -> ExitCode {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            // Never the user name or any record data (F22 §3).
            .with_title(Msg::AdminAppName.text(lang))
            .with_inner_size([520.0, 420.0])
            .with_min_inner_size([420.0, 340.0]),
        persist_window: false,
        ..Default::default()
    };
    match eframe::run_native(
        "mia-tray-admin",
        options,
        Box::new(move |_cc| Ok(Box::new(AdminApp::new(lang)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "the window could not be shown");
            ExitCode::FAILURE
        }
    }
}

/// What the window shows besides the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Notice {
    /// Nothing.
    None,
    /// The credentials were wiped without being sent (no server link yet).
    NotConnected,
}

struct AdminApp {
    lang: Lang,
    login: LoginModel,
    /// The session token; empty until the sign-in is wired to CMIS.
    token: SessionToken,
    notice: Notice,
}

impl AdminApp {
    fn new(lang: Lang) -> Self {
        Self {
            lang,
            login: LoginModel::new(),
            token: SessionToken::none(),
            notice: Notice::None,
        }
    }

    /// Wipe every secret the window holds.
    fn wipe(&mut self) {
        self.login.wipe();
        self.token.clear();
    }

    fn submit(&mut self) {
        match self.login.submit() {
            // The CMIS link arrives with the sign-in task; until then the
            // credentials are dropped (wiped) unsent.
            Ok(credentials) => {
                drop(credentials);
                self.notice = Notice::NotConnected;
            }
            // The model keeps the reason; the view shows it.
            Err(_) => self.notice = Notice::None,
        }
    }

    /// Route this frame's keystrokes to the model. Borrowed, never cloned.
    fn read_keys(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        ctx.input(|input| {
            for event in &input.events {
                match event {
                    egui::Event::Text(text) | egui::Event::Paste(text) => {
                        self.login.type_text(text);
                    }
                    egui::Event::Key {
                        key,
                        pressed: true,
                        modifiers,
                        ..
                    } => match key {
                        egui::Key::Backspace => self.login.backspace(),
                        egui::Key::Escape => {
                            self.login.escape();
                            self.notice = Notice::None;
                        }
                        egui::Key::Tab => {
                            let view = self.login.view();
                            let next = if modifiers.shift {
                                // Two steps forward is one step back in a cycle of three.
                                view.focus.next().next()
                            } else {
                                view.focus.next()
                            };
                            self.login.focus(next);
                        }
                        egui::Key::Enter => submit = true,
                        _ => {}
                    },
                    _ => {}
                }
            }
        });
        if submit {
            self.submit();
        }
    }
}

impl AdminApp {
    /// Draw one frame.
    fn show(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.read_keys(&ctx);
        let view = self.login.view();
        let lang = self.lang;
        let mut clicked = None;
        let mut submit = false;
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading(Msg::AdminSignInTitle.text(lang));
            ui.add_space(8.0);
            for (field, label, masked, len) in [
                (Field::Username, Msg::AdminUsername, false, 0),
                (Field::Password, Msg::AdminPassword, true, view.password_len),
                (Field::Code, Msg::AdminCode, true, view.code_len),
            ] {
                ui.label(label.text(lang));
                let shown = if masked {
                    "•".repeat(len)
                } else {
                    view.username.clone()
                };
                if field_box(ui, &shown, view.focus == field).clicked() {
                    clicked = Some(field);
                }
                ui.add_space(4.0);
            }
            ui.add_space(8.0);
            if ui
                .add_enabled(
                    view.can_submit,
                    egui::Button::new(Msg::AdminSignIn.text(lang)),
                )
                .clicked()
            {
                submit = true;
            }
            ui.add_space(8.0);
            if self.notice == Notice::NotConnected {
                ui.label(Msg::AdminNotConnected.text(lang));
            } else if view.error.is_some() {
                // Generic on purpose (F20): never says which part was wrong.
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    Msg::AdminMissingFields.text(lang),
                );
            }
            ui.add_space(12.0);
            ui.weak(Msg::AdminMemoryOnly.text(lang));
        });
        if let Some(field) = clicked {
            self.login.focus(field);
        }
        if submit {
            self.submit();
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            self.wipe();
        }
    }
}

impl eframe::App for AdminApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }

    // Nothing the administrator typed is ever written down.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn on_exit(&mut self) {
        self.wipe();
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

    const PASSWORD: &str = "c0rrect-horse-Battery-staple";

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
        let input = egui::RawInput {
            events,
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |ui| app.show(ui));
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

    #[test]
    fn typing_and_submitting_leave_no_copy_in_the_toolkit() {
        let ctx = egui::Context::default();
        let mut app = AdminApp::new(Lang::En);
        let mut painted = Vec::new();
        painted.extend(frame(
            &ctx,
            &mut app,
            vec![egui::Event::Text("alice".into())],
        ));
        painted.extend(frame(&ctx, &mut app, vec![key(egui::Key::Tab)]));
        painted.extend(frame(
            &ctx,
            &mut app,
            vec![egui::Event::Text(PASSWORD.into())],
        ));
        assert_eq!(app.login.view().password_len, PASSWORD.chars().count());
        painted.extend(frame(
            &ctx,
            &mut app,
            vec![egui::Event::Paste("123456".into())],
        ));
        // Typed, the secrets reach neither a painted text nor egui's memory.
        let memory = ctx.memory(|m| format!("{m:?}"));
        for secret in [PASSWORD, "123456"] {
            assert!(painted.iter().all(|t| !t.contains(secret)));
            assert!(!memory.contains(secret));
        }
        assert!(
            painted.iter().any(|t| t.contains("••")),
            "the mask is drawn"
        );
        // Submitted, the form is empty and still no copy anywhere.
        painted.extend(frame(&ctx, &mut app, vec![key(egui::Key::Enter)]));
        let view = app.login.view();
        assert_eq!((view.password_len, view.code_len), (0, 0));
        assert_eq!(app.notice, Notice::NotConnected);
        let memory = ctx.memory(|m| format!("{m:?}"));
        assert!(painted.iter().all(|t| !t.contains(PASSWORD)));
        assert!(!memory.contains(PASSWORD));
    }

    #[test]
    fn escape_and_close_wipe_the_secrets() {
        let ctx = egui::Context::default();
        let mut app = AdminApp::new(Lang::En);
        frame(
            &ctx,
            &mut app,
            vec![egui::Event::Text("alice".into()), key(egui::Key::Tab)],
        );
        frame(&ctx, &mut app, vec![egui::Event::Text(PASSWORD.into())]);
        frame(&ctx, &mut app, vec![key(egui::Key::Escape)]);
        let view = app.login.view();
        assert_eq!((view.username.as_str(), view.password_len), ("alice", 0));
        frame(&ctx, &mut app, vec![egui::Event::Text(PASSWORD.into())]);
        app.wipe();
        let view = app.login.view();
        assert_eq!((view.username.as_str(), view.password_len), ("", 0));
    }

    #[test]
    fn nothing_is_persisted() {
        let app = AdminApp::new(Lang::En);
        assert!(!eframe::App::persist_egui_memory(&app));
    }
}
