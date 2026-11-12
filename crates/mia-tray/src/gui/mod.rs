//! The desktop front end (feature `gui`).
//!
//! Two kinds of process run the same binary:
//!
//! - the **tray process** (`mia-tray`) owns the icon, the menu and the
//!   desktop notifications ([`run_tray`]);
//! - the **main window** is one process, started by the tray as
//!   `mia-tray --window <kind>` — a closed set, see [`crate::cli`]
//!   ([`run_window`]) — and raised afterwards through its control pipe
//!   ([`crate::control`]) instead of being started again.
//!
//! Separate processes keep the long-lived tray small, give the window a
//! plain `eframe` event loop (winit allows one per process), and stop a
//! misbehaving window from taking the icon down. Every decision is made by
//! the headless modules; this layer only draws and dispatches.

#[cfg(feature = "admin")]
pub mod admin;
mod job;
mod logs_view;
mod notify;
mod recovery_view;
mod setup_view;
mod status_view;
mod tray;
mod tray_loop;
mod window;

use std::process::ExitCode;
use std::sync::{mpsc, Arc};

use eframe::egui;

use crate::actions::{Os, Tools};
use crate::client::{observe_with_service, LocalEndpoint, MiaStatusCli, Observation, StatusCli};
use crate::control::Command;
use crate::i18n::Lang;
use crate::model::WindowKind;
use crate::poll::Poller;

/// Run the tray icon until "Quit".
#[must_use]
pub fn run_tray() -> ExitCode {
    tray_loop::run(crate::prefs::effective_lang())
}

/// Run the main window until it is closed.
#[must_use]
pub fn run_window(kind: WindowKind) -> ExitCode {
    window::run(kind, crate::prefs::effective_lang())
}

/// A resizable viewport with a default and a minimum size (F23: every
/// window reflows; nothing is fixed-size).
pub(crate) fn viewport(title: &str, size: [f32; 2], min: [f32; 2]) -> egui::ViewportBuilder {
    egui::ViewportBuilder::default()
        .with_title(title)
        .with_resizable(true)
        .with_inner_size(size)
        .with_min_inner_size(min)
}

/// The shared look: roomier spacing, larger headings, rounded frames and a
/// clearly visible keyboard focus.
pub(crate) fn apply_style(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.interact_size.y = 26.0;
        if let Some(h) = style.text_styles.get_mut(&egui::TextStyle::Heading) {
            h.size = 20.0;
        }
        for s in [egui::TextStyle::Body, egui::TextStyle::Button] {
            if let Some(f) = style.text_styles.get_mut(&s) {
                f.size = 14.0;
            }
        }
        style.visuals.selection.stroke.width = 2.0;
        style.visuals.widgets.hovered.bg_stroke.width = 1.5;
    });
}

/// Read control commands from this process's stdin (the tray's pipe) on a
/// helper thread; each goes to `tx`, then `ctx` repaints.
pub(crate) fn spawn_control_reader(ctx: &egui::Context, tx: mpsc::Sender<Command>) {
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        crate::control::read_commands(stdin.lock(), |cmd| {
            if tx.send(cmd).is_ok() {
                ctx.request_repaint();
            }
        });
    });
}

/// Raise the window (from a control command).
pub(crate) fn raise(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
}

/// Per-process context shared by the views.
#[derive(Clone)]
pub(crate) struct Shared {
    pub(crate) lang: Lang,
    pub(crate) os: Option<Os>,
    pub(crate) tools: Arc<Tools>,
    pub(crate) endpoint: Arc<LocalEndpoint>,
}

impl Shared {
    pub(crate) fn new(lang: Lang) -> Self {
        Self {
            lang,
            os: Os::current(),
            tools: Arc::new(Tools::discover()),
            endpoint: Arc::new(LocalEndpoint::from_env()),
        }
    }
}

/// Start the status poller (endpoint → `mia status --json` → synthesised),
/// delivering observations to `tx`; `wake` is called after each delivery.
pub(crate) fn start_poller(
    shared: &Shared,
    tx: mpsc::Sender<Observation>,
    wake: impl Fn() + Send + 'static,
) -> Poller {
    let endpoint = Arc::clone(&shared.endpoint);
    let cli = shared
        .tools
        .mia
        .as_ref()
        .map(|m| MiaStatusCli::new(m.path.clone()));
    crate::poll::spawn(
        move || {
            observe_with_service(
                endpoint.as_ref(),
                cli.as_ref().map(|c| c as &dyn StatusCli),
                &crate::client::service_running,
                crate::unix_now(),
            )
            .map_err(|e| tracing::debug!(error = %e, "transient status refusal"))
            .ok()
        },
        move |obs| {
            let delivered = tx.send(obs).is_ok();
            wake();
            delivered
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewports_are_resizable_with_a_small_minimum() {
        let v = viewport("x", [900.0, 680.0], [380.0, 300.0]);
        assert_eq!(v.resizable, Some(true));
        assert_eq!(v.inner_size, Some(egui::vec2(900.0, 680.0)));
        assert_eq!(v.min_inner_size, Some(egui::vec2(380.0, 300.0)));
    }
}
