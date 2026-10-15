//! The replicated allowlist mode (F19 §11): `legacy` until an operator
//! switches the cluster to `approvals`.
//!
//! - **legacy** (default, and the value of any missing or unknown setting):
//!   behaviour is unchanged. `SubmitAppRequest` answers `FAILED_PRECONDITION
//!   (mode_legacy)` and MIA keeps the request queued; `SyncAllowlist` serves
//!   a v2 body compiled from the host's legacy v1 allowlist, so new agents can
//!   sync on the 5-minute cadence before the import; `GetAllowlist` serves the
//!   stored v1 body; `SetAllowlist`, `DeleteAllowlist` and the
//!   `ProposeAllowlist` TOFU adoption (`CMIS_ALLOWLIST_PROPOSALS`) work as
//!   before.
//! - **approvals**: `SubmitAppRequest` is accepted and `SyncAllowlist` serves
//!   the v2 body compiled from the host's active approvals. `SetAllowlist`
//!   and `DeleteAllowlist` answer `FAILED_PRECONDITION (mode_approvals)` —
//!   the legacy bodies stay as they were, read-only, for a rollback;
//!   `ProposeAllowlist` turns each new entry into an `observed` request
//!   ([`super::proposals`]) and never adopts anything; `GetAllowlist`
//!   serves the lossy-safe v1 compile of the approvals ([`super::v1`]) while
//!   `CMIS_LEGACY_GETALLOWLIST` is on.
//!
//! The value lives in `cmis_settings` so every node agrees. The switch is the
//! platform-operator RPC `SetAllowlistMode` (`ferrogate admin
//! set-allowlist-mode`, step-up, audited as `AllowlistModeChanged`), after the
//! legacy import (`ImportLegacyAllowlists`, [`super::migration`]); see
//! [`crate::admin::migration`].

use ferro_raft::{Cluster, ClusterError};

/// `cmis_settings` key of the mode.
pub const ALLOWLIST_MODE_KEY: &str = "allowlist_mode";

/// The refusal of a legacy-only allowlist write in `approvals` mode
/// (`FAILED_PRECONDITION`).
pub const MODE_APPROVALS: &str = "mode_approvals";

/// The refusal of an F19 intake call in `legacy` mode (`FAILED_PRECONDITION`).
pub const MODE_LEGACY: &str = "mode_legacy";

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

    /// The wire code of the admin RPCs (1 legacy, 2 approvals).
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Legacy => 1,
            Self::Approvals => 2,
        }
    }

    /// The mode of a wire code; `0` and unknown codes are `None`.
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::Legacy),
            2 => Some(Self::Approvals),
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

/// The mode as this node's replica holds it, without a leader round trip:
/// for the public `GetAllowlist`, which must stay cheap and may follow a
/// switch a few milliseconds late. Same fallback as [`current`].
pub async fn current_local(cluster: &Cluster) -> Result<AllowlistMode, ClusterError> {
    let stored = cluster.setting_local(ALLOWLIST_MODE_KEY).await?;
    Ok(stored
        .as_deref()
        .and_then(AllowlistMode::parse)
        .unwrap_or(AllowlistMode::Legacy))
}

/// Store `mode` only if the legacy store still has `fingerprint` (see
/// [`ferro_raft::Cluster::put_setting_if_legacy_unchanged`]). `Ok(false)`:
/// a legacy body changed since the caller's plan; nothing was written.
pub async fn set_if_legacy_unchanged(
    cluster: &Cluster,
    mode: AllowlistMode,
    fingerprint: (i64, i64),
) -> Result<bool, ferro_raft::LedgerError> {
    cluster
        .put_setting_if_legacy_unchanged(ALLOWLIST_MODE_KEY, mode.as_str(), fingerprint)
        .await
}

/// Store the mode. Callers other than tests go through `SetAllowlistMode`,
/// which authorizes, checks the import and audits the switch.
pub async fn set(cluster: &Cluster, mode: AllowlistMode) -> Result<(), ClusterError> {
    cluster.put_setting(ALLOWLIST_MODE_KEY, mode.as_str()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_round_trip_through_storage_and_wire() {
        for m in [AllowlistMode::Legacy, AllowlistMode::Approvals] {
            assert_eq!(AllowlistMode::parse(m.as_str()), Some(m));
            assert_eq!(AllowlistMode::from_code(m.code()), Some(m));
        }
        assert_eq!(AllowlistMode::parse("Approvals"), None);
        assert_eq!(AllowlistMode::from_code(0), None);
        assert_eq!(AllowlistMode::from_code(3), None);
    }
}
