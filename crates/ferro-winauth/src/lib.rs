//! `ferro-winauth` — Windows caller-attestation FFI for the MIA helper API.
//!
//! `mia` is `#![forbid(unsafe_code)]`; this crate is the **only** place the
//! Windows FFI lives. It exposes safe wrappers the named-pipe helper server
//! needs:
//!
//! - [`client_process_id`] — the PID of the process at the other end of a
//!   connected named-pipe instance (`GetNamedPipeClientProcessId`);
//! - [`process_image_path`] — the on-disk image path of a PID
//!   (`QueryFullProcessImageNameW`);
//! - [`process_user_rid`] — the RID of the process token's user SID, used as
//!   the Windows analogue of a Unix uid in the allowlist;
//! - [`verify_authenticode`] — an Authenticode trust check on the image
//!   (`WinVerifyTrust`), the Code-Integrity analogue of the IMA cross-check;
//! - [`create_server_pipe`] — create a named-pipe server instance, optionally
//!   with a DACL restricting access to one local group (which may connect but
//!   not create pipe instances — see [`pipe_acl`]);
//! - [`open_client_pipe`] — open a pipe client with exactly the access that
//!   DACL grants and `SECURITY_IDENTIFICATION`;
//! - [`open_no_follow`], [`object_info`], [`security_of`], [`read_security`],
//!   [`create_admin_only_dir`], [`set_admin_only`] and
//!   [`set_administrators_owner`] — read and set, through one handle that never
//!   follows a reparse point, the owner and DACL of the MIA's
//!   administrator-only system configuration directory and the files in it,
//!   judged by the pure policy in [`file_acl`].
//!
//! Everything except the pure [`pipe_acl`] and [`file_acl`] modules is
//! `#[cfg(windows)]`; on other platforms the crate is otherwise empty so it can
//! sit in the workspace and be a `cfg(windows)` dependency of `mia`.

#![allow(unsafe_code)]
// this crate is the Windows FFI boundary by design
// FFI-idiom lints: passing `&mut x` as a `*mut` out-parameter and narrowing
// sizes to the `u32` the Win32 ABI expects are unavoidable and idiomatic here.
#![allow(clippy::borrow_as_ptr, clippy::cast_possible_truncation)]

#[cfg(windows)]
mod imp;
#[cfg(windows)]
pub use imp::{
    client_process_id, create_server_pipe, open_client_pipe, process_image_path, process_user_rid,
    verify_authenticode,
};

pub mod pipe_acl;

pub mod file_acl;

#[cfg(windows)]
mod file_security;
#[cfg(windows)]
pub use file_security::{
    create_admin_only_dir, object_info, open_no_follow, read_security, security_of, set_admin_only,
    set_administrators_owner,
};

// Windows Service Control Manager integration for the `mia` daemon. Lives here
// because `windows-service`'s service-main macro expands to `unsafe` glue and
// `mia` is `#![forbid(unsafe_code)]`.
#[cfg(windows)]
pub mod service;
