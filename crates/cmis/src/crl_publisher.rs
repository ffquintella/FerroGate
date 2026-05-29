//! Background CRL publisher (feature F11).
//!
//! [`spawn`] runs a small tokio task that re-signs and republishes the CRL on a
//! fixed cadence (60 s by default). Each cycle refreshes the CRL's `issued_at`
//! and bumps its sequence number even when no revocations changed, so a MIA's
//! freshness check (`age <= 300 s`) distinguishes a live publisher from a
//! stalled one and refuses to mint against a stale CRL.
//!
//! Revocations published through the `RevokeSvid` / `RevokeHost` admin RPCs are
//! reflected immediately (the RPC handler publishes inline); this loop is the
//! steady-state heartbeat that keeps the cached CRL fresh between revocations.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;

use crate::state::CmisState;

/// The default publish cadence from `docs/operations.md` §"Revocation".
pub const DEFAULT_PUBLISH_INTERVAL: Duration = Duration::from_secs(60);

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Spawn the periodic CRL publisher. Publishes once immediately so the `JWKS`
/// RPC carries a signed CRL from the first request, then every `interval`.
/// Returns the join handle so the caller can shut it down if needed.
#[must_use = "the publisher stops when the join handle is dropped"]
pub fn spawn(state: Arc<CmisState>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match state.publish_crl(unix_now()) {
                Ok(number) => tracing::debug!(crl_number = number, "CRL published"),
                Err(e) => {
                    // A signing failure must not take CMIS down; keep retrying
                    // on the next tick. The cached CRL goes stale and consumers
                    // fail closed, which is the intended safety posture.
                    tracing::error!(error = %e, "CRL publish failed");
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}
