//! Background RIM watcher (feature F10).
//!
//! [`spawn`] runs a small tokio task that periodically calls
//! [`ferro_attest::RimLoader::try_reload`]. The store is hot-swapped under a
//! single write lock inside the loader, so in-flight `Attest` handlers always
//! see a consistent generation set; no synchronisation is required here.
//!
//! Production deployments may replace this poll with a `notify`-style
//! filesystem watch; the seam is small enough that the swap is local to this
//! module. Native S3 sourcing is dropped (see docs/roadmap.md "Dropped scope")
//! — a deployment keeping the bundle in object storage syncs it to the watched
//! path out of band.

use std::sync::Arc;
use std::time::Duration;

use ferro_attest::{ReloadOutcome, RimLoader};
use tokio::task::JoinHandle;

/// Spawn a background reload loop. Returns the join handle so the caller can
/// shut it down if needed.
#[must_use = "the watcher stops when the join handle is dropped"]
pub fn spawn(loader: Arc<RimLoader>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match loader.try_reload() {
                Ok(ReloadOutcome::Applied(o)) => {
                    tracing::info!(
                        version = o.version,
                        retained = o.retained,
                        pruned = o.pruned,
                        "RIM hot-reloaded"
                    );
                }
                Ok(ReloadOutcome::UpToDate { version }) => {
                    tracing::debug!(version, "RIM unchanged");
                }
                Err(err) => {
                    // Keep going — a transient parse or signature error on a
                    // half-written bundle must not take CMIS down.
                    tracing::warn!(error = %err, "RIM reload failed");
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}
