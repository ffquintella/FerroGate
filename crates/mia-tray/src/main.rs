//! `mia-tray` — the FerroGate MIA desktop companion (feature F18).
//!
//! Thin entry point: logging, argument parsing, then the tray or one window
//! from the library (see `mia_tray::gui`).

#![forbid(unsafe_code)]

use std::process::ExitCode;

use mia_tray::cli::{self, Mode};

fn main() -> ExitCode {
    // The tray's own diagnostics (never key material: it holds none) go to
    // stderr; `MIA_TRAY_LOG` takes a tracing directive (default `info`).
    let filter = tracing_subscriber::EnvFilter::try_from_env("MIA_TRAY_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    match cli::parse(std::env::args().skip(1)) {
        Ok(Mode::Tray) => mia_tray::gui::run_tray(),
        Ok(Mode::Window(kind)) => mia_tray::gui::run_window(kind),
        Ok(Mode::Help) => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Ok(Mode::Version) => {
            println!("mia-tray {}", mia_tray::VERSION);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mia-tray: {e}");
            ExitCode::from(2)
        }
    }
}
