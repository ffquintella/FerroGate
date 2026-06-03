//! Background fleet-manifest watcher (feature F13).
//!
//! [`spawn`] runs a small tokio task that periodically calls
//! [`FleetManifestLoader::try_reload`]. The enrolment set is hot-swapped under a
//! single write lock inside the [`FleetStore`], so in-flight `Attest` handlers
//! that took a snapshot always see a consistent set; no synchronisation is
//! required here.
//!
//! The manifest is read from a local file. Native S3 sourcing is dropped (see
//! `docs/roadmap.md` "Dropped scope"); a deployment keeping the manifest in
//! object storage syncs it to the watched path out of band. Because the loader
//! verifies the composite signature before applying anything, that sync path is
//! untrusted — only the signature gates what is admitted.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::fleet_manifest::{FleetManifestLoader, FleetReloadOutcome};

/// Default poll interval for the manifest watcher.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Spawn a background reload loop. Returns the join handle so the caller can
/// shut it down by dropping it.
#[must_use = "the watcher stops when the join handle is dropped"]
pub fn spawn(loader: Arc<FleetManifestLoader>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match loader.try_reload() {
                Ok(FleetReloadOutcome::Applied { version, enrolled }) => {
                    tracing::info!(version, enrolled, "fleet manifest hot-reloaded");
                }
                Ok(FleetReloadOutcome::UpToDate { version }) => {
                    tracing::debug!(version, "fleet manifest unchanged");
                }
                Err(err) => {
                    // Keep going — a transient parse or signature error on a
                    // half-written manifest must not take CMIS down, and the
                    // last good enrolment set stays in force.
                    tracing::warn!(error = %err, "fleet manifest reload failed");
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}
