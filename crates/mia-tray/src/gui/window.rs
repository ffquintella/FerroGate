//! The main window (F23 §3): a header with the state badge, the next step
//! and the language selector; tabs Status · Recovery · Setup · Logs; a
//! status bar mirroring notices. One process, raised through its control
//! pipe; native `egui` only, and every daemon or `mia` string is drawn as
//! plain text after [`crate::text`] escaping.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use eframe::egui::{self, RichText};

use super::logs_view::LogsView;
use super::recovery_view::RecoveryView;
use super::setup_view::SetupView;
use super::status_view::{badge, recovery_button};
use super::{start_poller, Shared};
use crate::actions::{self, Action, ActionError, Doc, EnvName};
use crate::client::{Observation, Source};
use crate::control::Command;
use crate::i18n::{fill, Lang, Msg};
use crate::model::{snapshot_explanation, tray_view, WindowKind, WizardStep};
use crate::notice::{Notice, NoticeCenter, NoticeKind};
use crate::poll::Poller;
use crate::prefs::Prefs;
use crate::text::human_duration;

/// Default and minimum window sizes (points).
const SIZE: [f32; 2] = [900.0, 680.0];
const MIN_SIZE: [f32; 2] = [380.0, 300.0];

/// The tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    Status,
    Recovery,
    Setup,
    Logs,
}

impl Tab {
    const ALL: [Self; 4] = [Self::Status, Self::Recovery, Self::Setup, Self::Logs];

    fn title(self) -> Msg {
        match self {
            Self::Status => Msg::TabStatus,
            Self::Recovery => Msg::TabRecovery,
            Self::Setup => Msg::TabSetup,
            Self::Logs => Msg::TabLogs,
        }
    }
}

/// Something a view asks the window to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Intent {
    /// Run an action (switches to the recovery tab).
    Run(Action, Option<EnvName>),
    /// Copy the machine identifiers.
    CopyIds,
    /// Open the wizard at a step.
    Setup(WizardStep),
    /// Open documentation.
    Read(Doc),
    /// Poll now.
    Refresh,
    /// Use this language from now on (`None`: follow the system).
    Language(Option<Lang>),
}

/// Open `doc` in the browser (fixed URL table), logging failures.
pub(crate) fn open_doc(shared: &Shared, doc: Doc) {
    let opened = shared
        .os
        .ok_or(ActionError::Unsupported)
        .and_then(|os| actions::open_doc_spec(doc, os))
        .and_then(|spec| actions::spawn_detached(&spec));
    if let Err(e) = opened {
        tracing::warn!(error = %e, ?doc, "could not open the documentation");
    }
}

struct WindowApp {
    shared: Shared,
    tab: Tab,
    obs: Option<Observation>,
    /// When the shown observation arrived (Unix seconds).
    obs_at: i64,
    obs_rx: mpsc::Receiver<Observation>,
    poller: Option<Poller>,
    control_rx: mpsc::Receiver<Command>,
    notices: NoticeCenter,
    /// The language chosen here (`None`: the system's).
    chosen: Option<Lang>,
    prefs_path: Option<PathBuf>,
    recovery: RecoveryView,
    setup: SetupView,
    logs: LogsView,
}

impl WindowApp {
    /// The window on `ctx`; `live` starts the poller and the control-pipe
    /// reader (tests inject both instead).
    fn new(ctx: &egui::Context, kind: WindowKind, lang: Lang, live: bool) -> Self {
        super::apply_style(ctx);
        let shared = Shared::new(lang);
        let (obs_tx, obs_rx) = mpsc::channel();
        let (control_tx, control_rx) = mpsc::channel();
        let poller = live.then(|| {
            let wake = ctx.clone();
            super::spawn_control_reader(ctx, control_tx);
            start_poller(&shared, obs_tx, move || wake.request_repaint())
        });
        let prefs_path = crate::prefs::user_path();
        let chosen = prefs_path
            .as_deref()
            .map(crate::prefs::load)
            .and_then(|p| p.language);
        let mut app = Self {
            tab: Tab::Status,
            obs: None,
            obs_at: 0,
            obs_rx,
            poller,
            control_rx,
            notices: NoticeCenter::default(),
            chosen,
            prefs_path,
            recovery: RecoveryView::default(),
            setup: SetupView::default(),
            logs: LogsView::default(),
            shared,
        };
        app.show_kind(ctx, kind);
        app
    }

    /// Switch to the tab `kind` names (and start what it implies).
    fn show_kind(&mut self, ctx: &egui::Context, kind: WindowKind) {
        match kind {
            WindowKind::Status => self.tab = Tab::Status,
            WindowKind::Recovery => self.tab = Tab::Recovery,
            WindowKind::SelfTest => {
                self.tab = Tab::Recovery;
                self.recovery
                    .run(ctx, &self.shared, Action::RunSelfTest, None);
            }
            WindowKind::Setup => self.open_setup(ctx, None),
            WindowKind::SetupPins => self.open_setup(ctx, Some(WizardStep::Pins)),
            WindowKind::SetupAttestation => self.open_setup(ctx, Some(WizardStep::Attestation)),
            WindowKind::Logs => self.tab = Tab::Logs,
        }
    }

    fn open_setup(&mut self, ctx: &egui::Context, focus: Option<WizardStep>) {
        self.tab = Tab::Setup;
        self.setup.focus(focus);
        self.setup.ensure_loaded(ctx, &self.shared);
    }

    fn apply(&mut self, ctx: &egui::Context, intent: Intent) {
        match intent {
            Intent::Run(action, env) => {
                self.tab = Tab::Recovery;
                self.recovery.run(ctx, &self.shared, action, env);
            }
            Intent::CopyIds => {
                self.tab = Tab::Recovery;
                self.recovery.copy_ids(ctx, &self.shared);
            }
            Intent::Setup(step) => self.open_setup(ctx, Some(step)),
            Intent::Read(doc) => open_doc(&self.shared, doc),
            Intent::Refresh => {
                if let Some(p) = &self.poller {
                    p.poke();
                }
            }
            Intent::Language(choice) => self.set_language(choice),
        }
    }

    /// Use `choice` now and remember it; the tray follows the file.
    fn set_language(&mut self, choice: Option<Lang>) {
        self.chosen = choice;
        let prefs = Prefs { language: choice };
        self.shared.lang =
            crate::prefs::resolve_lang(&prefs, |k| std::env::var(k).ok(), sys_locale::get_locale());
        if let Some(path) = &self.prefs_path {
            if let Err(e) = crate::prefs::save(path, &prefs) {
                tracing::warn!(error = %e, "could not save the language preference");
            }
        }
    }

    /// Observations, control commands and finished work since last frame.
    fn read_input(&mut self, ctx: &egui::Context) {
        while let Ok(obs) = self.obs_rx.try_recv() {
            self.obs = Some(obs);
            self.obs_at = crate::unix_now();
        }
        while let Ok(cmd) = self.control_rx.try_recv() {
            match cmd {
                Command::Show(kind) => {
                    self.show_kind(ctx, kind);
                    super::raise(ctx);
                }
                Command::Focus => super::raise(ctx),
                Command::Notice(n) => {
                    self.notices.push(n, false);
                }
            }
        }
        // A finished action or apply may have changed the agent's state.
        let acted = self.recovery.poll(ctx);
        for n in self.recovery.take_notices(self.shared.lang) {
            self.notices.push(n, false);
        }
        let applied = self.setup.poll(ctx, &self.shared);
        if acted || applied {
            if let Some(p) = &self.poller {
                p.poke();
            }
        }
        self.logs.poll(ctx, &self.shared, self.tab == Tab::Logs);
    }

    /// The header: badge, explanation, freshness, next step, language.
    fn header(&mut self, ui: &mut egui::Ui) -> Option<Intent> {
        let lang = self.shared.lang;
        let mut out = None;
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            match &self.obs {
                None => {
                    ui.spinner();
                    ui.label(Msg::StatusNoData.text(lang));
                }
                Some(obs) => {
                    let view = tray_view(obs, crate::unix_now(), lang);
                    let worst = crate::model::worst(&obs.snapshots);
                    let title = worst.map_or(Msg::StatusNoData, crate::model::snapshot_title);
                    badge(ui, view.presentation, title.text(lang));
                    if view.envs.len() > 1 {
                        if let Some(s) = worst {
                            ui.label(RichText::new(crate::model::env_label(s, lang)).strong());
                        }
                    }
                }
            }
            ui.add_space(12.0);
            if ui.button(Msg::ButtonRefresh.text(lang)).clicked() {
                out = Some(Intent::Refresh);
            }
            ui.label(Msg::HeaderLanguage.text(lang));
            let shown = self
                .chosen
                .map_or(Msg::HeaderLanguageSystem.text(lang), Lang::native_name);
            let mut choice = self.chosen;
            egui::ComboBox::from_id_salt("language")
                .selected_text(shown)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut choice, None, Msg::HeaderLanguageSystem.text(lang));
                    for l in Lang::ALL {
                        ui.selectable_value(&mut choice, Some(l), l.native_name());
                    }
                });
            if choice != self.chosen {
                out = Some(Intent::Language(choice));
            }
        });
        if let Some(obs) = &self.obs {
            let view = tray_view(obs, crate::unix_now(), lang);
            if let Some(s) = crate::model::worst(&obs.snapshots) {
                ui.add(egui::Label::new(snapshot_explanation(s).text(lang)).wrap());
            }
            let source = match view.source {
                Source::Endpoint => Msg::SourceEndpoint,
                Source::Cli => Msg::SourceCli,
                Source::Synthesised => Msg::SourceSynthesised,
            };
            let ago = fill(
                Msg::DetailAgo.text(lang),
                &[("d", &human_duration(crate::unix_now() - self.obs_at))],
            );
            ui.horizontal_wrapped(|ui| {
                ui.weak(fill(Msg::HeaderUpdated.text(lang), &[("when", &ago)]));
                ui.weak("·");
                ui.weak(fill(
                    Msg::HeaderSource.text(lang),
                    &[("source", source.text(lang))],
                ));
            });
            // The next step: the worst environment's recoveries.
            if let Some(env) = view
                .envs
                .iter()
                .filter(|e| e.state == view.worst)
                .find(|e| !e.recoveries.is_empty())
            {
                ui.horizontal_wrapped(|ui| {
                    for r in &env.recoveries {
                        if let Some(i) = recovery_button(ui, &self.shared, *r, env.env.as_ref()) {
                            out = Some(i);
                        }
                    }
                });
            }
        }
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            for tab in Tab::ALL {
                ui.selectable_value(&mut self.tab, tab, tab.title().text(lang));
            }
        });
        ui.add_space(2.0);
        out
    }

    /// The status bar: the newest notice, its age, Dismiss, and the earlier
    /// ones folded away — the same text as the OS notification.
    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let lang = self.shared.lang;
        let Some(latest) = self.notices.latest().cloned() else {
            return;
        };
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            notice_label(ui, lang, &latest);
            ui.weak(fill(
                Msg::DetailAgo.text(lang),
                &[("d", &human_duration(crate::unix_now() - latest.at))],
            ));
            if ui.small_button(Msg::NoticeDismiss.text(lang)).clicked() {
                self.notices.dismiss_latest();
            }
        });
        let older: Vec<Notice> = self.notices.history().skip(1).cloned().collect();
        if !older.is_empty() {
            egui::CollapsingHeader::new(Msg::NoticeHistory.text(lang))
                .id_salt("notice-history")
                .show(ui, |ui| {
                    for n in &older {
                        ui.horizontal_wrapped(|ui| notice_label(ui, lang, n));
                    }
                });
        }
        ui.add_space(2.0);
    }

    /// Draw one frame.
    fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.read_input(&ctx);
        let mut intent = egui::Panel::top("header")
            .show(ui, |ui| self.header(ui))
            .inner;
        if self.notices.latest().is_some() {
            egui::Panel::bottom("status-bar").show(ui, |ui| self.status_bar(ui));
        }
        egui::CentralPanel::default().show(ui, |ui| {
            let from_tab = match self.tab {
                Tab::Status => super::status_view::ui(ui, &self.shared, self.obs.as_ref()),
                Tab::Recovery => self.recovery.ui(ui, &self.shared, self.obs.as_ref()),
                Tab::Setup => {
                    self.setup.ui(ui, &self.shared, self.obs.as_ref());
                    None
                }
                Tab::Logs => {
                    self.logs
                        .ui(ui, &self.shared, self.obs.as_ref(), &self.recovery);
                    None
                }
            };
            intent = intent.take().or(from_tab);
        });
        if let Some(intent) = intent {
            self.apply(&ctx, intent);
        }
        // Background results arrive with a repaint request; this keeps the
        // relative times and the log follow moving otherwise.
        ctx.request_repaint_after(Duration::from_millis(1000));
    }
}

/// One notice: kind glyph and name (never colour alone), then its line.
pub(crate) fn notice_label(ui: &mut egui::Ui, lang: Lang, n: &Notice) {
    let color = match n.kind {
        NoticeKind::Success => ui.visuals().text_color(),
        NoticeKind::Info => ui.visuals().weak_text_color(),
        NoticeKind::Warning | NoticeKind::ApprovalPending => ui.visuals().warn_fg_color,
        NoticeKind::Error => ui.visuals().error_fg_color,
    };
    ui.label(
        RichText::new(format!("{} {}", n.kind.glyph(), n.kind.label().text(lang)))
            .color(color)
            .strong(),
    );
    ui.add(egui::Label::new(n.line()).wrap());
}

impl eframe::App for WindowApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

pub(crate) fn run(kind: WindowKind, lang: Lang) -> ExitCode {
    let options = eframe::NativeOptions {
        viewport: super::viewport(Msg::AppName.text(lang), SIZE, MIN_SIZE),
        ..Default::default()
    };
    match eframe::run_native(
        "mia-tray",
        options,
        Box::new(move |cc| Ok(Box::new(WindowApp::new(&cc.egui_ctx, kind, lang, true)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "the window could not be shown");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::synthesised;
    use mia_status_proto::AgentState;

    /// A window with no poller, no control reader and no preference file.
    fn app(ctx: &egui::Context, kind: WindowKind, lang: Lang) -> WindowApp {
        let mut a = WindowApp::new(ctx, kind, lang, false);
        a.prefs_path = None;
        a.chosen = None;
        a
    }

    fn observe(a: &mut WindowApp, state: AgentState) {
        a.obs = Some(Observation {
            snapshots: vec![synthesised(state, "not_running", "m", 0)],
            source: Source::Synthesised,
        });
        a.obs_at = crate::unix_now();
    }

    /// One frame of `size`; every text it painted.
    fn frame(ctx: &egui::Context, a: &mut WindowApp, size: egui::Vec2) -> String {
        // Twice: panels size themselves from the previous frame.
        frame_checked(ctx, a, size);
        frame_checked(ctx, a, size).0
    }

    /// [`frame`], plus the texts that run past the window's right edge
    /// outside any narrower (scrolling) clip.
    fn frame_checked(
        ctx: &egui::Context,
        a: &mut WindowApp,
        size: egui::Vec2,
    ) -> (String, Vec<String>) {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |ui| a.draw(ui));
        output.textures_delta.clear();
        let mut texts = Vec::new();
        let mut overflow = Vec::new();
        for clipped in &output.shapes {
            if let egui::epaint::Shape::Text(t) = &clipped.shape {
                let text = t.galley.text().to_string();
                let right = clipped.shape.visual_bounding_rect().max.x;
                if right > size.x + 1.0 && clipped.clip_rect.max.x >= size.x - 1.0 {
                    overflow.push(text.clone());
                }
                texts.push(text);
            }
        }
        (texts.join("\n"), overflow)
    }

    #[test]
    fn the_header_shows_the_state_with_a_glyph_and_the_fix() {
        let ctx = egui::Context::default();
        let mut a = app(&ctx, WindowKind::Status, Lang::En);
        observe(&mut a, AgentState::NotRunning);
        let painted = frame(&ctx, &mut a, egui::vec2(900.0, 680.0));
        assert!(painted.contains("– The agent is not running"), "{painted}");
        assert!(
            painted.contains(Action::ServiceStart.label().text(Lang::En)),
            "{painted}"
        );
        assert!(painted.contains("Updated"), "{painted}");
        for tab in Tab::ALL {
            assert!(painted.contains(tab.title().text(Lang::En)), "{tab:?}");
        }
    }

    #[test]
    fn a_control_command_switches_the_tab_and_a_notice_shows_in_the_status_bar() {
        let ctx = egui::Context::default();
        let mut a = app(&ctx, WindowKind::Status, Lang::En);
        let (tx, rx) = mpsc::channel();
        a.control_rx = rx;
        tx.send(Command::Show(WindowKind::Logs)).unwrap();
        tx.send(Command::Notice(Notice::action(
            "Restart the service",
            "done",
            Some(true),
            Some("prod"),
            Lang::En,
            crate::unix_now(),
        )))
        .unwrap();
        let painted = frame(&ctx, &mut a, egui::vec2(900.0, 680.0));
        assert_eq!(a.tab, Tab::Logs);
        assert!(
            painted.contains("prod · Restart the service — done"),
            "{painted}"
        );
        assert!(painted.contains("✔ Done"), "{painted}");
    }

    #[test]
    fn every_language_renders_and_nothing_overflows_a_small_window() {
        for lang in Lang::ALL {
            let ctx = egui::Context::default();
            let mut a = app(&ctx, WindowKind::Status, lang);
            observe(&mut a, AgentState::CrlStale);
            a.notices.push(Notice::pending_approvals(2, lang, 0), false);
            for size in [egui::vec2(380.0, 300.0), egui::vec2(1600.0, 1000.0)] {
                // Twice: panels size themselves from the previous frame.
                frame_checked(&ctx, &mut a, size);
                let (painted, overflow) = frame_checked(&ctx, &mut a, size);
                assert!(
                    painted.contains(Msg::StateCrlStale.text(lang)),
                    "{lang:?} {size:?}: {painted}"
                );
                assert!(overflow.is_empty(), "{lang:?} {size:?}: {overflow:?}");
            }
        }
    }

    #[test]
    fn choosing_a_language_applies_at_once() {
        let ctx = egui::Context::default();
        let mut a = app(&ctx, WindowKind::Status, Lang::En);
        observe(&mut a, AgentState::Healthy);
        a.apply(&ctx, Intent::Language(Some(Lang::Es)));
        assert_eq!(a.shared.lang, Lang::Es);
        let painted = frame(&ctx, &mut a, egui::vec2(900.0, 680.0));
        assert!(painted.contains(Msg::TabLogs.text(Lang::Es)), "{painted}");
        assert!(painted.contains("Español"), "{painted}");
    }
}
