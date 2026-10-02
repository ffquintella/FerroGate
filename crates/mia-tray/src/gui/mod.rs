//! The desktop front end (feature `gui`).
//!
//! Two kinds of process run the same binary:
//!
//! - the **tray process** (`mia-tray`) owns the icon, the menu and the
//!   desktop notifications ([`run_tray`]);
//! - each **window** (status, recovery, setup, logs) is its own process,
//!   started by the tray as `mia-tray --window <kind>` — a closed set, see
//!   [`crate::cli`] ([`run_window`]).
//!
//! Separate processes keep the long-lived tray small, give every window a
//! plain `eframe` event loop (winit allows one per process), and stop a
//! misbehaving window from taking the icon down. Every decision is made by
//! the headless modules; this layer only draws and dispatches.

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

use crate::actions::{Os, Tools};
use crate::client::{observe, LocalEndpoint, MiaStatusCli, Observation, StatusCli};
use crate::i18n::Lang;
use crate::model::WindowKind;
use crate::poll::Poller;

/// Run the tray icon until "Quit".
#[must_use]
pub fn run_tray() -> ExitCode {
    tray_loop::run(Lang::detect())
}

/// Run one window until it is closed.
#[must_use]
pub fn run_window(kind: WindowKind) -> ExitCode {
    window::run(kind, Lang::detect())
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
            observe(
                endpoint.as_ref(),
                cli.as_ref().map(|c| c as &dyn StatusCli),
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
