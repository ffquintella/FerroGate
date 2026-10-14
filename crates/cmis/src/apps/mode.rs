//! The replicated allowlist mode (F19 §11): `legacy` until an operator
//! switches the cluster to `approvals`.
//!
//! - **legacy** (default, and the value of any missing or unknown setting):
//!   behaviour is unchanged. `SubmitAppRequest` answers `FAILED_PRECONDITION
//!   (mode_legacy)` and MIA keeps the request queued; `SyncAllowlist` serves
//!   a v2 body compiled from the host's legacy v1 allowlist, so new agents can
//!   sync on the 5-minute cadence before the import.
//! - **approvals**: `SubmitAppRequest` is accepted and `SyncAllowlist` serves
//!   the v2 body compiled from the host's active approvals.
//!
//! The value lives in `cmis_settings` so every node agrees. The switch itself
//! (`SetAllowlistMode`, `ferrogate admin set-allowlist-mode`) and the legacy
//! import ship with M38 (T272, T273).

use ferro_raft::{Cluster, ClusterError};

/// `cmis_settings` key of the mode.
pub const ALLOWLIST_MODE_KEY: &str = "allowlist_mode";

/// Which source the served allowlist and the request intake follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistMode {
    /// Hand-provisioned v1 allowlists; F19 intake refused.
    Legacy,
    /// The F19 approval ledger.
    Approvals,
}

impl AllowlistMode {
    /// The stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Approvals => "approvals",
        }
    }

    /// Parse a stored value; anything unknown is `None`.
    #[must_use]
    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "legacy" => Some(Self::Legacy),
            "approvals" => Some(Self::Approvals),
            _ => None,
        }
    }
}

/// The mode in force. A missing setting is `Legacy`; an unknown value is
/// logged and treated as `Legacy` (the behaviour that changes nothing).
pub async fn current(cluster: &Cluster) -> Result<AllowlistMode, ClusterError> {
    let stored = cluster.setting(ALLOWLIST_MODE_KEY).await?;
    Ok(match stored.as_deref() {
        None => AllowlistMode::Legacy,
        Some(v) => AllowlistMode::parse(v).unwrap_or_else(|| {
            tracing::error!(
                event = "apps.mode.unknown",
                "unknown allowlist_mode setting; treating it as legacy"
            );
            AllowlistMode::Legacy
        }),
    })
}

/// Store the mode (used by the M38 switch and by tests).
pub async fn set(cluster: &Cluster, mode: AllowlistMode) -> Result<(), ClusterError> {
    cluster.put_setting(ALLOWLIST_MODE_KEY, mode.as_str()).await
}
