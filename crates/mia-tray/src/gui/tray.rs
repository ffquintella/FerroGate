//! The tray icon, its menu and the effects it carries out.
//!
//! [`TrayController::tick`] is driven by the platform loop (`tray_loop`)
//! every few hundred milliseconds: it drains observations, finished
//! actions, menu and icon clicks and notification clicks, then updates the
//! icon and menu. Decisions come from [`crate::model`] (menu, [`plan`]),
//! [`crate::alerts`] and [`crate::notice`]; this module only executes them.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;

use tray_icon::menu::{IsMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::{notify, start_poller, Shared};
use crate::actions::{self, invocation, Action, ActionError, ActionResult, EnvName, Outcome};
use crate::alerts::{Alerter, Policy};
use crate::client::{Observation, Source};
use crate::control::{self, Command as Ctl};
use crate::i18n::{Lang, Msg};
use crate::locate::locate_admin_client;
use crate::model::{
    menu_model, plan, plan_target, snapshot_title, title, tray_view, MenuCommand, MenuNode,
    Presentation, TrayEffect, TrayView, WindowKind,
};
use crate::notice::{Notice, NoticeCenter, Tag, Target};
use crate::poll::Poller;

/// Whether the loop should keep going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Quit,
}

/// Ticks between two looks at the preference file (about 2 s).
const PREFS_EVERY: u32 = 8;

/// A native menu entry kept so its text can be updated in place.
enum Handle {
    Item(MenuItem),
    Sub(Submenu, Vec<Handle>),
    Sep(PredefinedMenuItem),
}

impl Handle {
    fn as_item(&self) -> &dyn IsMenuItem {
        match self {
            Self::Item(i) => i,
            Self::Sub(s, _) => s,
            Self::Sep(p) => p,
        }
    }
}

/// A menu's structure without its texts: equal shapes can be updated in
/// place (no flicker, an open menu stays open).
#[derive(PartialEq)]
enum Shape {
    Label,
    Item(MenuCommand),
    Sub(Vec<Shape>),
    Sep,
}

fn shape(nodes: &[MenuNode]) -> Vec<Shape> {
    nodes
        .iter()
        .map(|n| match n {
            MenuNode::Label(_) => Shape::Label,
            MenuNode::Item(_, c) => Shape::Item(c.clone()),
            MenuNode::Submenu(_, kids) => Shape::Sub(shape(kids)),
            MenuNode::Separator => Shape::Sep,
        })
        .collect()
}

/// Menu text: bounded, and `&` doubled where it would be a mnemonic.
fn menu_text(text: &str) -> String {
    let t = crate::text::display_safe(text, 120);
    if cfg!(windows) {
        t.replace('&', "&&")
    } else {
        t
    }
}

/// A finished background action.
struct Done {
    action: Action,
    env: Option<EnvName>,
    copy_ids: bool,
    result: Result<ActionResult, ActionError>,
}

/// A child process the tray talks to through its stdin.
struct Piped {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl Piped {
    /// Start `cmd` with a piped stdin.
    fn spawn(mut cmd: Command) -> std::io::Result<Self> {
        let mut child = cmd.stdin(Stdio::piped()).spawn()?;
        let stdin = child.stdin.take();
        Ok(Self { child, stdin })
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Send one command; `false` when the pipe is gone.
    fn send(&mut self, cmd: &Ctl) -> bool {
        self.stdin.as_mut().is_some_and(|s| {
            s.write_all(control::encode(cmd).as_bytes())
                .and_then(|()| s.flush())
                .is_ok()
        })
    }
}

pub(crate) struct TrayController {
    shared: Shared,
    tray: TrayIcon,
    obs_rx: mpsc::Receiver<Observation>,
    poller: Poller,
    alerter: Alerter,
    notices: NoticeCenter,
    activate_tx: mpsc::Sender<Target>,
    activate_rx: mpsc::Receiver<Target>,
    view: TrayView,
    last_obs: Option<Observation>,
    look: Presentation,
    handles: Vec<Handle>,
    model: Vec<MenuNode>,
    commands: HashMap<MenuId, MenuCommand>,
    next_id: usize,
    done_tx: mpsc::Sender<Done>,
    done_rx: mpsc::Receiver<Done>,
    running: Vec<Action>,
    main_window: Option<Piped>,
    admin_client: Option<Piped>,
    clipboard: Option<arboard::Clipboard>,
    logged_state: Option<mia_status_proto::AgentState>,
    prefs_path: Option<PathBuf>,
    prefs_stamp: Option<std::time::SystemTime>,
    ticks: u32,
}

impl TrayController {
    /// Create the icon and start polling. Must run on the UI thread.
    pub(crate) fn new(lang: Lang) -> Result<Self, String> {
        let shared = Shared::new(lang);
        let (obs_tx, obs_rx) = mpsc::channel();
        let poller = start_poller(&shared, obs_tx, || {});
        let empty = Observation {
            snapshots: Vec::new(),
            source: Source::Synthesised,
        };
        let view = tray_view(&empty, crate::unix_now(), lang);
        let look = view.presentation;
        let model = menu_model(&view, lang, None, admin_client_path().is_some());
        let mut commands = HashMap::new();
        let mut next_id = 0;
        let handles: Vec<Handle> = model
            .iter()
            .map(|n| make(n, &mut commands, &mut next_id))
            .collect();
        let menu = Menu::new();
        for h in &handles {
            menu.append(h.as_item()).map_err(|e| e.to_string())?;
        }
        let tray = TrayIconBuilder::new()
            .with_tooltip(menu_text(&view.headline))
            .with_icon(icon(look)?)
            .with_menu(Box::new(menu))
            // Left click opens the window; the menu stays on right click
            // (Linux status icons always show the menu).
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| e.to_string())?;
        let (done_tx, done_rx) = mpsc::channel();
        let (activate_tx, activate_rx) = mpsc::channel();
        let prefs_path = crate::prefs::user_path();
        let prefs_stamp = prefs_path.as_deref().and_then(crate::prefs::stamp);
        Ok(Self {
            shared,
            tray,
            obs_rx,
            poller,
            alerter: Alerter::new(Policy::default()),
            notices: NoticeCenter::default(),
            activate_tx,
            activate_rx,
            view,
            last_obs: None,
            look,
            handles,
            model,
            commands,
            next_id,
            done_tx,
            done_rx,
            running: Vec::new(),
            main_window: None,
            admin_client: None,
            clipboard: None,
            logged_state: None,
            prefs_path,
            prefs_stamp,
            ticks: 0,
        })
    }

    /// One turn of the loop.
    pub(crate) fn tick(&mut self) -> Flow {
        let mut latest = None;
        while let Ok(obs) = self.obs_rx.try_recv() {
            latest = Some(obs);
        }
        if let Some(obs) = latest {
            self.on_observation(obs);
        }
        while let Ok(done) = self.done_rx.try_recv() {
            self.on_done(done);
        }
        let mut effects = Vec::new();
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if let Some(cmd) = self.commands.get(&ev.id) {
                effects.push(plan(cmd));
            }
        }
        while let Ok(ev) = tray_icon::TrayIconEvent::receiver().try_recv() {
            if let tray_icon::TrayIconEvent::Click {
                button: tray_icon::MouseButton::Left,
                button_state: tray_icon::MouseButtonState::Up,
                ..
            } = ev
            {
                effects.push(TrayEffect::ShowWindow(WindowKind::Status));
            }
        }
        while let Ok(target) = self.activate_rx.try_recv() {
            effects.push(plan_target(target));
        }
        for effect in effects {
            if self.execute(effect) == Flow::Quit {
                return Flow::Quit;
            }
        }
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks.is_multiple_of(PREFS_EVERY) {
            self.watch_language();
        }
        if self.main_window.as_mut().is_some_and(|w| !w.alive()) {
            self.main_window = None;
        }
        if self.admin_client.as_mut().is_some_and(|c| !c.alive()) {
            self.admin_client = None;
        }
        Flow::Continue
    }

    /// Follow a language chosen in the window (it writes the preference
    /// file): rebuild the view, the tooltip and the menu.
    fn watch_language(&mut self) {
        let Some(path) = self.prefs_path.as_deref() else {
            return;
        };
        let stamp = crate::prefs::stamp(path);
        if stamp == self.prefs_stamp {
            return;
        }
        self.prefs_stamp = stamp;
        let lang = crate::prefs::effective_lang();
        if lang != self.shared.lang {
            tracing::info!(lang = lang.code(), "UI language changed");
            self.shared.lang = lang;
            let obs = self.last_obs.clone().unwrap_or(Observation {
                snapshots: Vec::new(),
                source: Source::Synthesised,
            });
            self.view = tray_view(&obs, crate::unix_now(), lang);
            self.refresh();
        }
    }

    fn on_observation(&mut self, obs: Observation) {
        let now = crate::unix_now();
        let lang = self.shared.lang;
        for alert in self.alerter.observe(now, &obs.snapshots) {
            // A validated name, or the escaped raw one (never markup).
            let env = alert.environment.as_deref().map_or_else(
                || Msg::DefaultEnvironment.text(lang).to_string(),
                |e| {
                    EnvName::parse(e).map_or_else(
                        |_| crate::text::display_safe(e, 64),
                        |n| n.as_str().to_string(),
                    )
                },
            );
            let state = obs
                .snapshots
                .iter()
                .find(|s| s.environment == alert.environment)
                .map_or_else(|| title(alert.state), snapshot_title);
            self.raise_notice(Notice::from_alert(&alert, &env, state, lang, now), true);
        }
        let view = tray_view(&obs, now, lang);
        if self.logged_state != Some(view.worst) {
            tracing::info!(state = view.worst.as_str(), source = ?view.source, "agent state");
            self.logged_state = Some(view.worst);
        }
        self.view = view;
        self.last_obs = Some(obs);
        self.refresh();
    }

    /// Record a notice, deliver it to the OS when `os` and the rate limit
    /// allow, and mirror it in the open window.
    fn raise_notice(&mut self, notice: Notice, os: bool) {
        if self.notices.push(notice.clone(), os) {
            notify::deliver(&notice, self.shared.lang, self.activate_tx.clone());
        }
        if let Some(w) = self.main_window.as_mut() {
            w.send(&Ctl::Notice(notice));
        }
    }

    fn refresh(&mut self) {
        if self.view.presentation != self.look {
            self.look = self.view.presentation;
            match icon(self.look) {
                Ok(i) => {
                    if let Err(e) = self.tray.set_icon(Some(i)) {
                        tracing::warn!(error = %e, "could not update the tray icon");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "could not draw the tray icon"),
            }
        }
        if let Err(e) = self.tray.set_tooltip(Some(menu_text(&self.view.headline))) {
            tracing::debug!(error = %e, "tooltip not supported here");
        }
        // The latest action result replaces the old "Last action" line.
        let line = self
            .notices
            .history()
            .find(|n| n.tag == Tag::Action)
            .map(Notice::line);
        // Looked up on every refresh, so installing or removing the optional
        // package shows or hides the entry without restarting the tray.
        let model = menu_model(
            &self.view,
            self.shared.lang,
            line.as_deref(),
            admin_client_path().is_some(),
        );
        if model == self.model {
            return;
        }
        if shape(&model) == shape(&self.model) {
            update_texts(&self.handles, &model);
        } else {
            self.commands.clear();
            self.handles = model
                .iter()
                .map(|n| make(n, &mut self.commands, &mut self.next_id))
                .collect();
            let menu = Menu::new();
            for h in &self.handles {
                if let Err(e) = menu.append(h.as_item()) {
                    tracing::warn!(error = %e, "could not build the tray menu");
                }
            }
            self.tray.set_menu(Some(Box::new(menu)));
        }
        self.model = model;
    }

    fn execute(&mut self, effect: TrayEffect) -> Flow {
        match effect {
            TrayEffect::Quit => return Flow::Quit,
            TrayEffect::ShowWindow(kind) => self.open_window(kind),
            TrayEffect::OpenAdminClient => self.open_admin_client(),
            TrayEffect::RunAction {
                action,
                env,
                copy_ids,
            } => self.run_action(action, env, copy_ids),
            TrayEffect::OpenDoc(doc) => super::window::open_doc(&self.shared, doc),
        }
        Flow::Continue
    }

    /// Show the main window at `kind`: raise the open one through its pipe,
    /// or start `<this exe> --window <kind>`.
    fn open_window(&mut self, kind: WindowKind) {
        if let Some(w) = self.main_window.as_mut() {
            if w.alive() && w.send(&Ctl::Show(kind)) {
                return;
            }
        }
        let started = std::env::current_exe().and_then(|exe| {
            let mut cmd = Command::new(exe);
            cmd.arg("--window").arg(kind.as_arg());
            Piped::spawn(cmd)
        });
        match started {
            Ok(mut w) => {
                // The window shows what happened before it opened.
                if let Some(n) = self.notices.latest() {
                    w.send(&Ctl::Notice(n.clone()));
                }
                self.main_window = Some(w);
            }
            Err(e) => tracing::error!(error = %e, ?kind, "could not open the window"),
        }
    }

    /// Start the separate administrator client (F22), or raise the open
    /// one. The trust rule runs again right before a launch (the file may
    /// have been replaced since the menu was built); the child gets a fixed
    /// command line and no elevation.
    fn open_admin_client(&mut self) {
        if let Some(c) = self.admin_client.as_mut() {
            if c.alive() && c.send(&Ctl::Focus) {
                return;
            }
        }
        let Some(program) = admin_client_path() else {
            tracing::warn!("the admin client is gone or no longer trusted");
            self.refresh();
            return;
        };
        match Piped::spawn(actions::admin_client_spec(&program).command()) {
            Ok(c) => self.admin_client = Some(c),
            Err(e) => tracing::error!(error = %e, "could not open the admin client"),
        }
    }

    fn run_action(&mut self, action: Action, env: Option<EnvName>, copy_ids: bool) {
        if self.running.contains(&action) {
            return;
        }
        let lang = self.shared.lang;
        let env_label = env.as_ref().map(EnvName::as_str).map(str::to_string);
        let Some(os) = self.shared.os else {
            let n = Notice::action(
                action.label().text(lang),
                Msg::ErrorUnsupported.text(lang),
                Some(false),
                env_label.as_deref(),
                lang,
                crate::unix_now(),
            );
            self.raise_notice(n, true);
            self.refresh();
            return;
        };
        self.running.push(action);
        let tools = std::sync::Arc::clone(&self.shared.tools);
        let tx = self.done_tx.clone();
        let for_thread = env.clone();
        std::thread::spawn(move || {
            let result = actions::run(&invocation(action, for_thread.as_ref(), os), os, &tools);
            let _ = tx.send(Done {
                action,
                env: for_thread,
                copy_ids,
                result,
            });
        });
        let running = Notice::action(
            action.label().text(lang),
            Msg::OutcomeRunning.text(lang),
            None,
            env_label.as_deref(),
            lang,
            crate::unix_now(),
        );
        self.raise_notice(running, false);
        self.refresh();
    }

    fn on_done(&mut self, done: Done) {
        self.running.retain(|a| *a != done.action);
        let lang = self.shared.lang;
        let (text, ok) = match &done.result {
            Ok(r) if done.copy_ids && r.outcome == Outcome::Succeeded => {
                match actions::parse_machine_id(&r.captured.stdout) {
                    Some(id) => {
                        if self.copy(&format!("mia machine-id: {id}")) {
                            (Msg::CopiedIds.text(lang).to_string(), true)
                        } else {
                            (Msg::OutcomeFailed.text(lang).to_string(), false)
                        }
                    }
                    None => (Msg::ErrorUnexpectedOutput.text(lang).to_string(), false),
                }
            }
            Ok(r) => crate::notice::outcome_text(done.action, r.outcome, lang),
            Err(e) => (e.message().text(lang).to_string(), false),
        };
        let env_label = done.env.as_ref().map(EnvName::as_str);
        let n = Notice::action(
            done.action.label().text(lang),
            &text,
            Some(ok),
            env_label,
            lang,
            crate::unix_now(),
        );
        self.raise_notice(n, true);
        self.refresh();
        self.poller.poke();
    }

    fn copy(&mut self, text: &str) -> bool {
        if self.clipboard.is_none() {
            // Kept alive for the tray's lifetime: on X11 the copied text
            // lives only as long as its owner.
            self.clipboard = arboard::Clipboard::new()
                .map_err(|e| tracing::warn!(error = %e, "clipboard unavailable"))
                .ok();
        }
        self.clipboard.as_mut().is_some_and(|c| {
            c.set_text(text.to_string())
                .map_err(|e| tracing::warn!(error = %e, "could not copy"))
                .is_ok()
        })
    }
}

/// The administrator client beside this tray executable, when it passes the
/// trust rule ([`locate_admin_client`]).
fn admin_client_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| locate_admin_client(&exe))
}

fn icon(look: Presentation) -> Result<Icon, String> {
    Icon::from_rgba(
        crate::icon::rgba(look),
        crate::icon::SIZE,
        crate::icon::SIZE,
    )
    .map_err(|e| e.to_string())
}

fn make(node: &MenuNode, commands: &mut HashMap<MenuId, MenuCommand>, next: &mut usize) -> Handle {
    match node {
        MenuNode::Label(t) => Handle::Item(MenuItem::new(menu_text(t), false, None)),
        MenuNode::Item(t, cmd) => {
            *next += 1;
            let id = MenuId::new(format!("mia-tray-{next}"));
            commands.insert(id.clone(), cmd.clone());
            Handle::Item(MenuItem::with_id(id, menu_text(t), true, None))
        }
        MenuNode::Submenu(t, kids) => {
            let sub = Submenu::new(menu_text(t), true);
            let handles: Vec<Handle> = kids.iter().map(|k| make(k, commands, next)).collect();
            for h in &handles {
                if let Err(e) = sub.append(h.as_item()) {
                    tracing::warn!(error = %e, "could not build a submenu");
                }
            }
            Handle::Sub(sub, handles)
        }
        MenuNode::Separator => Handle::Sep(PredefinedMenuItem::separator()),
    }
}

fn update_texts(handles: &[Handle], nodes: &[MenuNode]) {
    for (h, n) in handles.iter().zip(nodes) {
        match (h, n) {
            (Handle::Item(i), MenuNode::Label(t) | MenuNode::Item(t, _)) => {
                i.set_text(menu_text(t));
            }
            (Handle::Sub(s, kids), MenuNode::Submenu(t, nodes)) => {
                s.set_text(menu_text(t));
                update_texts(kids, nodes);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_ignore_texts() {
        let a = vec![
            MenuNode::Label("x".into()),
            MenuNode::Item("a".into(), MenuCommand::Quit),
        ];
        let b = vec![
            MenuNode::Label("y".into()),
            MenuNode::Item("b".into(), MenuCommand::Quit),
        ];
        assert!(shape(&a) == shape(&b));
        let c = vec![MenuNode::Label("y".into())];
        assert!(shape(&a) != shape(&c));
    }

    #[test]
    fn menu_text_is_bounded_and_single_line() {
        let t = menu_text(&format!("a\nb{}", "c".repeat(500)));
        assert!(!t.contains('\n'));
        assert!(t.chars().count() <= 125);
    }

    /// A piped child receives exactly the encoded control lines.
    #[cfg(unix)]
    #[test]
    fn a_piped_child_receives_control_lines() {
        let mut cmd = Command::new("cat");
        cmd.stdout(Stdio::piped());
        let mut child = Piped::spawn(cmd).unwrap();
        assert!(child.send(&Ctl::Show(WindowKind::Logs)));
        assert!(child.send(&Ctl::Focus));
        drop(child.stdin.take());
        let out = child.child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "show logs\nfocus\n");
    }
}
