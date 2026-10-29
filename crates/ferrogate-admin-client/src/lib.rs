//! `ferrogate-admin-client` — the client side every FerroGate administrator
//! front end shares (F20 §12): `ferrogate-tui` and the tray admin client
//! `mia-tray-admin` (F22). Entry point: [`client::AdminSession`] (sign-in and
//! step-up with a TOTP code or a FIDO2 key, logout, `WhoAmI`), with token
//! enrollment in [`enroll`], second-factor management in [`factors`], and
//! request and approval administration in [`approvals`].

//! Secrets never implement `Debug`, `Display` or `Clone`, nothing here logs,
//! and `unsafe` is forbidden.

#![forbid(unsafe_code)]

pub mod approvals;
pub mod client;
pub mod config;
pub mod display;
pub mod endpoint;
pub mod enroll;
pub mod error;
pub mod factors;
pub mod files;
pub mod perm;
pub mod secret;
pub mod session;
pub mod timefmt;
pub mod totp;
pub mod transport;
pub mod webauthn;

/// `ClientInfo.kind` values (`admin.proto`).
pub mod client_kind {
    /// `ferrogate-tui`.
    pub const TUI: u32 = 1;
    /// The tray admin client `mia-tray-admin`.
    pub const TRAY: u32 = 2;
    /// The `ferrogate` CLI.
    pub const CLI: u32 = 3;
}
