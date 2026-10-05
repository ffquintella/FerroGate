//! The tray icon, its menu and the actions it dispatches.
//!
//! [`TrayController::tick`] is driven by the platform loop (`tray_loop`)
//! every few hundred milliseconds: it drains observations from the poller,
//! finished actions and menu clicks, then updates the icon and menu. All
//! decisions come from [`crate::model`] / [`crate::alerts`]; this module only
//! maps [`MenuNode`]s to native items and [`MenuCommand`]s to effects.

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

use tray_icon::menu::{IsMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::{notify, start_poller, Shared};
use crate::actions::{self, invocation, Action, ActionError, ActionResult, EnvName, Outcome};
use crate::alerts::{AlertKind, Alerter, Policy};
use crate::client::{Observation, Source};
use crate::i18n::{fill, Lang, Msg};
use crate::model::{
    menu_model, snapshot_title, title, tray_view, MenuCommand, MenuNode, Presentation, Recovery,
    TrayView, WindowKind,
};
use crate::poll::Poller;

/// Whether the loop should keep going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Quit,
}

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
    copy_ids: bool,
    result: Result<ActionResult, ActionError>,
}

pub(crate) struct TrayController {
    shared: Shared,
    tray: TrayIcon,
    obs_rx: mpsc::Receiver<Observation>,
    poller: Poller,
    alerter: Alerter,
    view: TrayView,
    look: Presentation,
    frame: u32,
    handles: Vec<Handle>,
    model: Vec<MenuNode>,
    commands: HashMap<MenuId, MenuCommand>,
    next_id: usize,
    done_tx: mpsc::Sender<Done>,
    done_rx: mpsc::Receiver<Done>,
    running: Vec<Action>,
    last_action: Option<String>,
    windows: HashMap<WindowKind, Child>,
    clipboard: Option<arboard::Clipboard>,
    logged_state: Option<mia_status_proto::AgentState>,
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
        let model = menu_model(&view, lang, None);
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
            .with_icon(icon(look, 0)?)
            .with_menu(Box::new(menu))
            .build()
            .map_err(|e| e.to_string())?;
        let (done_tx, done_rx) = mpsc::channel();
        Ok(Self {
            shared,
            tray,
            obs_rx,
            poller,
            alerter: Alerter::new(Policy::default()),
            view,
            look,
            frame: 0,
            handles,
            model,
            commands,
            next_id,
            done_tx,
            done_rx,
            running: Vec::new(),
            last_action: None,
            windows: HashMap::new(),
            clipboard: None,
            logged_state: None,
        })
    }

    /// One turn of the loop.
    pub(crate) fn tick(&mut self) -> Flow {
        let mut latest = None;
        while let Ok(obs) = self.obs_rx.try_recv() {
            latest = Some(obs);
        }
        if let Some(obs) = latest {
            self.on_observation(&obs);
        }
        while let Ok(done) = self.done_rx.try_recv() {
            self.on_done(done);
        }
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if let Some(cmd) = self.commands.get(&ev.id).cloned() {
                if self.dispatch(cmd) == Flow::Quit {
                    return Flow::Quit;
                }
            }
        }
        if self.look.animated {
            self.frame = self.frame.wrapping_add(1);
            if self.frame.is_multiple_of(2) {
                self.set_icon();
            }
        }
        self.windows
            .retain(|_, child| matches!(child.try_wait(), Ok(None)));
        Flow::Continue
    }

    fn on_observation(&mut self, obs: &Observation) {
        let now = crate::unix_now();
        let lang = self.shared.lang;
        for alert in self.alerter.observe(now, &obs.snapshots) {
            let heading = match alert.kind {
                AlertKind::BecameUnhealthy => Msg::NotifyAttentionTitle,
                AlertKind::SvidExpiring => Msg::NotifySvidExpiringTitle,
                AlertKind::CrlStale => Msg::NotifyCrlStaleTitle,
            };
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
            notify::show(
                heading.text(lang),
                &fill(
                    Msg::NotifyBody.text(lang),
                    &[("env", &env), ("state", state.text(lang))],
                ),
            );
        }
        let view = tray_view(obs, now, lang);
        if self.logged_state != Some(view.worst) {
            tracing::info!(state = view.worst.as_str(), source = ?view.source, "agent state");
            self.logged_state = Some(view.worst);
        }
        self.view = view;
        self.refresh();
    }

    fn refresh(&mut self) {
        if self.view.presentation != self.look {
            self.look = self.view.presentation;
            self.frame = 0;
            self.set_icon();
        }
        if let Err(e) = self.tray.set_tooltip(Some(menu_text(&self.view.headline))) {
            tracing::debug!(error = %e, "tooltip not supported here");
        }
        let model = menu_model(&self.view, self.shared.lang, self.last_action.as_deref());
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

    fn set_icon(&self) {
        match icon(self.look, self.frame / 2) {
            Ok(i) => {
                if let Err(e) = self.tray.set_icon(Some(i)) {
                    tracing::warn!(error = %e, "could not update the tray icon");
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not draw the tray icon"),
        }
    }

    fn dispatch(&mut self, cmd: MenuCommand) -> Flow {
        match cmd {
            MenuCommand::Quit => return Flow::Quit,
            MenuCommand::Open(kind) => self.open_window(kind),
            MenuCommand::Recover(Recovery::Run(action), env) => self.run_action(action, env, false),
            MenuCommand::Recover(Recovery::CopyMachineIds, _) => {
                self.run_action(Action::ShowMachineId, None, true);
            }
            MenuCommand::Recover(Recovery::Read(doc), _) => {
                let opened = self
                    .shared
                    .os
                    .ok_or(ActionError::Unsupported)
                    .and_then(|os| actions::open_doc_spec(doc, os))
                    .and_then(|spec| actions::spawn_detached(&spec));
                if let Err(e) = opened {
                    tracing::warn!(error = %e, ?doc, "could not open the documentation");
                }
            }
            MenuCommand::Recover(Recovery::OpenWizard(_), _) => {
                self.open_window(WindowKind::Setup);
            }
        }
        Flow::Continue
    }

    /// Start (at most one of) each window kind as `<this exe> --window <kind>`.
    fn open_window(&mut self, kind: WindowKind) {
        if let Some(child) = self.windows.get_mut(&kind) {
            if matches!(child.try_wait(), Ok(None)) {
                tracing::debug!(?kind, "window already open");
                return;
            }
        }
        let started = std::env::current_exe().and_then(|exe| {
            Command::new(exe)
                .arg("--window")
                .arg(kind.as_arg())
                .stdin(Stdio::null())
                .spawn()
        });
        match started {
            Ok(child) => {
                self.windows.insert(kind, child);
            }
            Err(e) => tracing::error!(error = %e, ?kind, "could not open the window"),
        }
    }

    fn run_action(&mut self, action: Action, env: Option<EnvName>, copy_ids: bool) {
        if self.running.contains(&action) {
            return;
        }
        let Some(os) = self.shared.os else {
            self.finish_line(action, Msg::ErrorUnsupported.text(self.shared.lang));
            return;
        };
        self.running.push(action);
        let tools = std::sync::Arc::clone(&self.shared.tools);
        let tx = self.done_tx.clone();
        std::thread::spawn(move || {
            let result = actions::run(&invocation(action, env.as_ref(), os), os, &tools);
            let _ = tx.send(Done {
                action,
                copy_ids,
                result,
            });
        });
        let lang = self.shared.lang;
        self.last_action = Some(fill(
            Msg::MenuLastAction.text(lang),
            &[
                ("action", action.label().text(lang)),
                ("outcome", Msg::OutcomeRunning.text(lang)),
            ],
        ));
        self.refresh();
    }

    fn finish_line(&mut self, action: Action, outcome: &str) {
        let lang = self.shared.lang;
        let line = fill(
            Msg::MenuLastAction.text(lang),
            &[("action", action.label().text(lang)), ("outcome", outcome)],
        );
        notify::show(Msg::AppName.text(lang), &line);
        self.last_action = Some(line);
        self.refresh();
    }

    fn on_done(&mut self, done: Done) {
        self.running.retain(|a| *a != done.action);
        let lang = self.shared.lang;
        let outcome_text = match &done.result {
            Ok(r) if done.copy_ids && r.outcome == Outcome::Succeeded => {
                match actions::parse_machine_id(&r.captured.stdout) {
                    Some(id) => {
                        if self.copy(&format!("mia machine-id: {id}")) {
                            Msg::CopiedIds.text(lang).to_string()
                        } else {
                            Msg::OutcomeFailed.text(lang).to_string()
                        }
                    }
                    None => Msg::ErrorUnexpectedOutput.text(lang).to_string(),
                }
            }
            Ok(r) if r.outcome == Outcome::Succeeded && done.action.applies_on_restart() => {
                format!(
                    "{}. {}",
                    r.outcome.label().text(lang),
                    Msg::NoteRestartToApply.text(lang)
                )
            }
            Ok(r) => r.outcome.label().text(lang).to_string(),
            Err(e) => e.message().text(lang).to_string(),
        };
        self.finish_line(done.action, &outcome_text);
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

fn icon(look: Presentation, frame: u32) -> Result<Icon, String> {
    Icon::from_rgba(
        crate::icon::rgba(look, frame),
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
}
