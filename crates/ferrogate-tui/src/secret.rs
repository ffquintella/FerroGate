//! Buffers for the administrator's secrets (F20 §12, F21 §8), shared with the
//! tray admin client: [`Secret`] (a password or a TOTP code, fixed capacity,
//! wiped on drop and on `pop`) and [`SessionToken`] (memory only, wiped on
//! logout, lock and exit). Neither implements `Debug`, `Display` or `Clone`
//! (compile-time assertions in `ferrogate_admin_client::secret`).

pub use ferrogate_admin_client::secret::{Secret, SessionToken};

// Compile-time secret hygiene (F21 "Secret hygiene"), restated where the TUI
// uses the types.
static_assertions::assert_not_impl_any!(Secret: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(SessionToken: std::fmt::Debug, std::fmt::Display, Clone);
