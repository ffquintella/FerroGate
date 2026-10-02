//! `mia-tray` — the FerroGate MIA desktop companion (feature F18).
//!
//! A small, **unprivileged** front end for capabilities `mia` already has: a
//! tray icon whose colour reflects the agent's state, desktop notifications on
//! transitions that need a human, a setup wizard, guided recovery and a
//! redacted log viewer. It adds no trust: it holds no key material, never sends
//! a helper-API `HelperReq`, never shows or copies SVIDs, tokens or keys, and
//! every privileged step is a one-shot, fixed `mia` (or service-manager)
//! command behind the operating system's own consent prompt.
//!
//! # Layout — one concern per module
//!
//! The library is the **headless core**; it builds and is tested without any
//! GUI system library:
//!
//! - [`client`] — the status endpoint (`StatusReq` / `LogTailReq`) and the
//!   fallback chain endpoint → `mia status --json` → `NotRunning`;
//! - [`locate`] — finding the `mia` binary and deciding whether it may be run
//!   elevated;
//! - [`process`] — running a child with bounded output and a deadline;
//! - [`actions`] — the closed set of recovery actions, their fixed command
//!   lines, the per-OS elevation wrappers and outcome classification;
//! - [`model`] — pure state → presentation mapping (icon colour, menu,
//!   per-environment details, recovery suggestions);
//! - [`alerts`] — notification de-duplication and rate limiting;
//! - [`wizard`] — the setup draft: `mia setup --dump` parsing, local field
//!   validation, TOML rendering and the private `0600` draft file;
//! - [`logview`] — following the daemon's log ring buffer and filtering it;
//! - [`selftest`] — reading `mia test --json`;
//! - [`bundle`] — the diagnostics bundle;
//! - [`poll`] — the background status poller and its backoff;
//! - [`icon`] — the tray icon bitmaps;
//! - [`i18n`] — the English / Portuguese string table;
//! - [`text`] — escaping untrusted text for display;
//! - [`cli`] — the binary's own (tiny) argument parser.
//!
//! The `gui` feature adds the `gui` module (tray icon, menus, windows); see the crate
//! manifest for why it is off by default.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod actions;
pub mod alerts;
pub mod bundle;
pub mod cli;
pub mod client;
pub mod i18n;
pub mod icon;
pub mod locate;
pub mod logview;
pub mod model;
pub mod poll;
pub mod process;
pub mod selftest;
pub mod text;
pub mod wizard;

#[cfg(feature = "gui")]
pub mod gui;

/// The tray's own version, shown in the diagnostics bundle.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Current Unix time in whole seconds (`0` if the clock is before 1970).
#[must_use]
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Current Unix time in milliseconds (`0` if the clock is before 1970).
#[must_use]
pub fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
