//! Leader-only sweepers (F19 §5.5), every 60 s:
//!
//! - a `PENDING` request past `pending_expires_at` becomes `EXPIRED`
//!   (`AppRequestExpired`);
//! - an `ACTIVE` approval past `expires_at` becomes `EXPIRED`, with a
//!   revision record and a generation bump in the same transaction
//!   (`ApprovalExpired`). The bump clears the host's cached body, so its next
//!   `SyncAllowlist` recompiles; MIA also enforces each entry's `expires_at`
//!   locally, so the sweeper only tidies the list and moves the generation.
//!
//! Each item is one guarded transaction: a row that changed meanwhile (an
//! approval renewed, a request decided) is skipped, never overwritten. A
//! store failure ends the pass and is retried on the next tick; nothing is
//! audited for a change that was not written. Only the Raft leader sweeps,
//! so a cluster runs one pass at a time.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use super::{events, now_millis};
use crate::service::audit_record;
use crate::state::CmisState;

/// The sweep cadence (F19 §5.5).
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Most rows of each kind one pass handles (the rest wait for the next).
pub const BATCH: u32 = 500;

/// What one pass changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SweepReport {
    /// Pending requests expired.
    pub requests_expired: u32,
    /// Approvals expired.
    pub approvals_expired: u32,
}

/// Run one sweep pass at `now`. Errors are store failures; whatever was
/// committed before the failure stays committed and audited.
pub async fn run_once(
    state: &CmisState,
    now: i64,
) -> Result<SweepReport, ferro_raft::apps::LedgerError> {
    let cluster = state.cluster();
    let mut report = SweepReport::default();
    for r in cluster.app_pending_past_expiry(now, BATCH).await? {
        if cluster.app_expire_request(&r.request_id, now).await? {
            audit_record(state, events::request_expired(&r.request_id), now);
            report.requests_expired += 1;
        }
    }
    for a in cluster.app_approvals_past_expiry(now, BATCH).await? {
        if cluster
            .app_expire_approval(&a.approval_id, now, now_millis(now))
            .await?
        {
            audit_record(state, events::approval_expired(&a.approval_id), now);
            report.approvals_expired += 1;
        }
    }
    Ok(report)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Spawn the periodic sweeper. Each tick it sweeps only if this node is the
/// Raft leader; failures are logged and retried on the next tick.
#[must_use = "the sweeper stops when the join handle is dropped"]
pub fn spawn(state: Arc<CmisState>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if !state.cluster().is_leader().await {
                continue;
            }
            match run_once(&state, unix_now()).await {
                Ok(r) if r != SweepReport::default() => tracing::info!(
                    event = "apps.sweep",
                    requests_expired = r.requests_expired,
                    approvals_expired = r.approvals_expired,
                    "app ledger swept"
                ),
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(event = "apps.sweep.failed", error = %e, "app ledger sweep failed");
                }
            }
        }
    })
}
