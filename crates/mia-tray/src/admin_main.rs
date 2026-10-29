//! `mia-tray-admin` — the FerroGate administrator client (feature F22).
//!
//! Thin entry point: logging, argument parsing, then the window from the
//! library (see `mia_tray::gui::admin`). A separate binary from `mia-tray`:
//! the tray links none of this.

#![forbid(unsafe_code)]
// A GUI-subsystem binary on Windows: it must not open a console window.
// `--help` / `--version` then print only when stdout is redirected.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

use mia_tray::admin::cli::{self, Mode};
use mia_tray::i18n::Lang;

fn main() -> ExitCode {
    // Diagnostics go to stderr; `MIA_TRAY_LOG` takes a tracing directive.
    // Nothing logged is a credential: the client never formats one.
    let filter = tracing_subscriber::EnvFilter::try_from_env("MIA_TRAY_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    match cli::parse(std::env::args().skip(1)) {
        Ok(Mode::Run { environment }) => {
            // The environment picks the CMIS endpoint once the sign-in lands.
            tracing::debug!(
                environment = environment.as_ref().map(mia_tray::actions::EnvName::as_str),
                "starting"
            );
            mia_tray::gui::admin::run(Lang::detect())
        }
        Ok(Mode::Help) => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Ok(Mode::Version) => {
            println!("mia-tray-admin {}", mia_tray::VERSION);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mia-tray-admin: {e}");
            ExitCode::from(2)
        }
    }
}
