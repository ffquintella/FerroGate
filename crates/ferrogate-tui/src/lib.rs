//! `ferrogate-tui` — the FerroGate server administration TUI (feature F21).
//!
//! A full-screen, keyboard-driven terminal UI for administrators: sign in with
//! password and TOTP, list and search registration requests and approvals,
//! approve, deny, edit, revoke, freeze lineages, and add an application by
//! known hash and path in one step. It holds **no authority of its own**:
//! every action is a gRPC call to the `ferrogate.admin.v1.Admin` service on
//! the CMIS admin listener, checked by the server's `AdminAuthz` exactly like
//! the CLI's, and it has no database code at all (FGV NRM §5.4.2).
//!
//! # Layout — one concern per module
//!
//! The library is the headless core; the binary (`src/main.rs`) only owns the
//! terminal:
//!
//! - [`config`] — `admin.toml` and the environment; refuses to start without
//!   an SPKI pin; the `0600` device-token file;
//! - [`fatal`] — the panic flag that stops the UI loop;
//! - [`client`] — the tokio task that owns the pinned hybrid-PQC channel and
//!   the session token, behind bounded command and reply channels;
//! - [`app`] — the state machine (`Msg` in, `Cmd` out): screens, modals,
//!   filters, dialogs, the idle lock and the step-up retry;
//! - [`screens`] — pure view functions over the state;
//! - [`input`] — terminal keys reduced to the key map's vocabulary;
//! - [`sanitize`] — every server-supplied string is made inert before it is
//!   drawn (C0/C1, escape sequences, bidi and zero-width characters);
//! - [`secret`] — zeroized buffers for passwords, TOTP codes and the token;
//! - [`timefmt`] — dates and durations without a date library.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod app;
pub mod client;
pub mod config;
pub mod fatal;
pub mod input;
pub mod sanitize;
pub mod screens;
pub mod secret;
pub mod timefmt;
