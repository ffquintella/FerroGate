//! The window process: one `eframe` window with Status / Recovery / Setup /
//! Logs tabs. Rendering is native `egui` — no web view, and every string
//! from the daemon or from `mia` is drawn as plain text after
//! [`crate::text`] escaping.

use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use eframe::egui;

use super::logs_view::LogsView;
use super::recovery_view::RecoveryView;
use super::setup_view::SetupView;
use super::{start_poller, Shared};
use crate::actions::{self, Action, ActionError, Doc, EnvName};
use crate::client::Observation;
use crate::i18n::{Lang, Msg};
use crate::model::{WindowKind, WizardStep};
use crate::poll::Poller;

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
    obs_rx: mpsc::Receiver<Observation>,
    poller: Poller,
    recovery: RecoveryView,
    setup: SetupView,
    logs: LogsView,
}

impl WindowApp {
    fn new(cc: &eframe::CreationContext<'_>, kind: WindowKind, lang: Lang) -> Self {
        let shared = Shared::new(lang);
        let (tx, obs_rx) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        let poller = start_poller(&shared, tx, move || ctx.request_repaint());
        let mut app = Self {
            tab: Tab::Status,
            obs: None,
            obs_rx,
            poller,
            recovery: RecoveryView::default(),
            setup: SetupView::default(),
            logs: LogsView::default(),
            shared,
        };
        let ctx = &cc.egui_ctx;
        match kind {
            WindowKind::Status => {}
            WindowKind::Recovery => app.tab = Tab::Recovery,
            WindowKind::SelfTest => {
                app.tab = Tab::Recovery;
                app.recovery
                    .run(ctx, &app.shared, Action::RunSelfTest, None);
            }
            WindowKind::Setup => app.open_setup(ctx, None),
            WindowKind::SetupPins => app.open_setup(ctx, Some(WizardStep::Pins)),
            WindowKind::SetupAttestation => app.open_setup(ctx, Some(WizardStep::Attestation)),
            WindowKind::Logs => app.tab = Tab::Logs,
        }
        app
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
            Intent::Refresh => self.poller.poke(),
        }
    }
}

impl eframe::App for WindowApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(obs) = self.obs_rx.try_recv() {
            self.obs = Some(obs);
        }
        // A finished action or apply may have changed the agent's state.
        let acted = self.recovery.poll(ctx);
        let applied = self.setup.poll(ctx, &self.shared);
        if acted || applied {
            self.poller.poke();
        }
        self.logs.poll(ctx, &self.shared, self.tab == Tab::Logs);

        let lang = self.shared.lang;
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                for tab in Tab::ALL {
                    ui.selectable_value(&mut self.tab, tab, tab.title().text(lang));
                }
            });
        });
        let mut intent = None;
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Status => intent = super::status_view::ui(ui, &self.shared, self.obs.as_ref()),
            Tab::Recovery => intent = self.recovery.ui(ui, &self.shared, self.obs.as_ref()),
            Tab::Setup => self.setup.ui(ui, &self.shared, self.obs.as_ref()),
            Tab::Logs => self
                .logs
                .ui(ui, &self.shared, self.obs.as_ref(), &self.recovery),
        });
        if let Some(intent) = intent {
            self.apply(ctx, intent);
        }
        // Background results arrive with a repaint request; this keeps the
        // relative times and the log follow moving otherwise.
        ctx.request_repaint_after(Duration::from_millis(1000));
    }
}

pub(crate) fn run(kind: WindowKind, lang: Lang) -> ExitCode {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(Msg::AppName.text(lang))
            .with_inner_size([880.0, 640.0])
            .with_min_inner_size([560.0, 380.0]),
        ..Default::default()
    };
    match eframe::run_native(
        "mia-tray",
        options,
        Box::new(move |cc| Ok(Box::new(WindowApp::new(cc, kind, lang)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "the window could not be shown");
            ExitCode::FAILURE
        }
    }
}
