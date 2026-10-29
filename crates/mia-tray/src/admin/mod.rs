//! The administrator client's headless core (feature F22, `admin-core`).
//!
//! `mia-tray-admin` is a **separate binary and process** from the tray: the
//! always-running tray holds no credentials and links none of this. What the
//! administrator types lives only here, in memory, in wiped buffers:
//!
//! - [`secret`] — [`secret::Secret`] (a password or a TOTP code) and
//!   [`secret::SessionToken`]: fixed capacity, wiped on drop, no `Debug`,
//!   `Display` or `Clone`;
//! - [`login`] — the login model: the typing events, the wipe on submit, `Esc`,
//!   close and lock, and the serialisable view the window draws from;
//! - [`cli`] — the binary's own (tiny) argument parser.
//!
//! The model reaches the window only through [`login::LoginView`], which has
//! no field that could hold a secret, and the window feeds it plain
//! calls on [`login::LoginModel`] instead of handing a secret to a text widget, so
//! the GUI toolkit's text-edit state (its undo history, its galley cache)
//! never holds a copy.

pub mod cli;
pub mod login;
pub mod secret;
