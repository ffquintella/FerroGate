//! Buffers for the administrator's secrets (F22 §3, F20 §12), shared with the
//! TUI through `ferrogate-admin-client`: [`Secret`] (a password or a TOTP
//! code: fixed capacity, wiped on drop and on `pop`) and [`SessionToken`]
//! (memory only; it lives in the client's session slot, never in a view
//! model, a file, the clipboard or a log).

pub use ferrogate_admin_client::secret::{Secret, SessionToken};

// Compile-time secret hygiene, restated where the tray uses the types.
static_assertions::assert_not_impl_any!(Secret: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(SessionToken: std::fmt::Debug, std::fmt::Display, Clone);
