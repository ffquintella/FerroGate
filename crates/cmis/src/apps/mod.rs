//! Application registration and approval (feature F19, ADR-0004): the CMIS
//! policy layer over the replicated ledger in [`ferro_raft::apps`].
//!
//! The ledger owns the rows and the invariants that must hold whatever the
//! caller does (INV-1 to INV-3: a request never replaces or removes an
//! approval). This module owns everything that is policy:
//!
//! - [`intake`]: `SubmitAppRequest` — validation, deduplication before any
//!   write, rate limits and pending caps, CMIS-set risk flags, and the
//!   `AutoSamePathUser` auto-approval (F19 §5.1–§5.3);
//! - [`status`]: `GetAppRequestStatus`, scoped to the calling host;
//! - [`compile`]: the per-host signed allowlist v2 with its generation and
//!   cache, served by `SyncAllowlist` (F19 §6.1–§6.3);
//! - [`sweep`]: the leader-only sweepers that expire stale requests and
//!   approvals (F19 §5.5);
//! - [`mode`]: the replicated `allowlist_mode` switch (F19 §11);
//! - [`migration`]: the legacy-allowlist import plan and import (F19 §11
//!   step 4);
//! - [`v1`]: the lossy-safe v1 `GetAllowlist` body in `approvals` mode
//!   (F19 §6.4);
//! - [`proposals`]: a pre-F19 agent's `ProposeAllowlist` in `approvals`
//!   mode, as `observed` requests (F19 §11 step 5);
//! - [`config`]: the `CMIS_APP_*` / `CMIS_APPROVAL_*` /
//!   `CMIS_LEGACY_GETALLOWLIST` settings.
//!
//! The host RPC handlers in [`crate::service`] and the administrator handlers
//! in [`crate::admin::apps`] are thin wrappers over these functions.
//!
//! Personal data (user names, SIDs, paths) stays in the access-controlled
//! ledger: audit events carry ids, hashes and codes only ([`events`]), and
//! logs at `info` and below carry ids only (F19 §10).

pub mod compile;
pub mod config;
pub mod events;
pub mod intake;
pub mod migration;
pub mod mode;
pub mod proposals;
pub mod status;
pub mod sweep;
pub mod v1;

pub use config::AppConfig;
pub use mode::AllowlistMode;

use ferro_raft::apps::LedgerError;
use tonic::Status;

use crate::host_auth::invalid_field;

/// The answer to a ledger failure (F19 §7.4). Store failures are logged and
/// answered `UNAVAILABLE (store_unavailable)`; nothing was written for any
/// other variant, which maps to its stable reason code.
#[must_use]
pub fn ledger_status(e: LedgerError) -> Status {
    match e {
        LedgerError::Store(e) => {
            tracing::error!(event = "apps.store.error", error = %e, "app ledger operation failed");
            Status::unavailable("store_unavailable")
        }
        LedgerError::NotFound => Status::not_found("not_found"),
        LedgerError::InvalidState => Status::failed_precondition("invalid_state"),
        LedgerError::RowVersionMismatch => Status::aborted("row_version_mismatch"),
        LedgerError::SelfApproval => Status::permission_denied("sod_self_approval"),
        LedgerError::NotCovering => Status::failed_precondition("not_covering"),
        LedgerError::Raced => Status::aborted("concurrent_change"),
        LedgerError::Invalid(field) => invalid_field("bad_value", Some(field)),
        LedgerError::Corrupt(column) => {
            tracing::error!(
                event = "apps.store.corrupt",
                column,
                "corrupt value in the app ledger"
            );
            Status::internal("internal")
        }
    }
}

/// The 16 bytes of a ledger id (UUID text). Ids are minted by CMIS as
/// UUIDv7; a value that does not parse maps to all zeros (and is logged),
/// so an audit event is still written.
#[must_use]
pub fn uuid_bytes(id: &str) -> [u8; 16] {
    uuid::Uuid::parse_str(id).map_or_else(
        |_| {
            tracing::error!(event = "apps.id.malformed", "ledger id is not a UUID");
            [0; 16]
        },
        |u| *u.as_bytes(),
    )
}

/// A fresh ledger id (UUIDv7 text).
#[must_use]
pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// The current Unix time in milliseconds (the hybrid-logical generation of
/// F19 §6.2), never below `now_secs * 1000`.
#[must_use]
pub fn now_millis(now_secs: i64) -> i64 {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    wall.max(now_secs.saturating_mul(1000))
}
