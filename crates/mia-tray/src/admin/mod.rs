//! The administrator client's headless core (feature F22, `admin-core`).
//!
//! `mia-tray-admin` is a **separate binary and process** from the tray: the
//! always-running tray holds no credentials and links none of this. Secrets
//! live only in memory, in wiped buffers, and the session token only in the
//! worker's `ferrogate-admin-client` session (shared with the TUI).

//! - [`secret`] — wiped buffers (re-exported from `ferrogate-admin-client`);
//! - [`login`] — the sign-in form: user name, then password with a code or a key;
//! - [`flow`] — the window's state machine: offer, sign-in, step-up, idle lock;
//! - [`session`] — the worker thread that talks to CMIS for the window;
//! - [`config`] — `admin.toml` (endpoint and SPKI pin, no secrets);
//! - [`webauthn`] — the platform's security-key backend (none built yet);
//! - [`cli`] — the binary's own (tiny) argument parser.

pub mod cli;
pub mod config;
pub mod flow;
pub mod login;
pub mod secret;
pub mod session;
pub mod webauthn;
