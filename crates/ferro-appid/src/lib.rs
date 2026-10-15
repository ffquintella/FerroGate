//! `ferro-appid` — identify an application binary **without executing it**
//! (feature F19 §4).
//!
//! MIA (and the admin clients) use this crate to describe a binary for an
//! app-registration request: its SHA-384, size and format, a declared version
//! when the binary or its package declares one, a summary of its embedded
//! signature, and the risk flags `ferro-appid` can decide by itself. Reading
//! bytes and parsing headers is the only operation: nothing is executed, no
//! interpreter or system tool is spawned (enforced by a `clippy.toml`
//! `disallowed-methods` lint and a source test), and package metadata is read
//! from database files.
//!
//! - [`identify`] — hash and metadata from **one** open file, so both
//!   describe the same bytes (F19 §4.1).
//! - [`path`] — canonical path rules and the `path_key` per platform (§4.2).
//! - [`version`] — the version sources in order and string cleaning (§4.3).
//! - [`signer`] — the signer summary shape (§4.4; verification itself is
//!   platform code in `ferro-winauth`).
//! - [`flags`] — the risk-flag bitmask (§4.5).
//!
//! Every parser is bounded (F19 §4.1): at most 2 GiB per file, at most 16 MiB
//! of metadata read, nesting depth 16, a 2 s wall-clock budget. Malformed or
//! hostile input yields an error, never a panic, and a failed metadata
//! source simply contributes no version ("none"; the lineage revision is then
//! the displayed version). The declared version, product, bundle and package
//! names are **display data, never policy inputs**.

#![forbid(unsafe_code)]

mod bytes;
pub mod dpkg;
mod elf;
pub mod flags;
pub mod format;
pub mod identify;
pub mod limits;
mod macho;
pub mod path;
mod pe;
pub mod platform;
pub mod plist_bundle;
pub mod signer;
pub mod version;

pub use bytes::ParseError;
pub use flags::{is_interpreter, RiskFlags};
pub use format::{detect, BinaryFormat};
pub use identify::{identify, Identification, IdentifyError, IdentifyOptions, VersionSources};
pub use limits::Limits;
pub use path::{path_key, CanonicalPath, PathError};
pub use platform::Platform;
pub use signer::{SignerKind, SignerSummary};
pub use version::{display_version, VersionInfo, VersionSource};
