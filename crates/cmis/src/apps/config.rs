//! F19 policy settings (`CMIS_APP_*`, `CMIS_APPROVAL_*`,
//! `CMIS_LEGACY_GETALLOWLIST`).
//!
//! Every value is read once at start. A malformed, zero or out-of-range
//! value is an error, never silently replaced: a typo in a security setting
//! must stop CMIS rather than run with a default the operator did not choose.

use crate::host_auth::{TIER_HOST_KEY, TIER_TPM};

/// One day in seconds.
const DAY: i64 = 86_400;

/// Default approval lifetime (`CMIS_APPROVAL_DEFAULT_TTL_SECS`, 180 days: the
/// semiannual grant review of G-002).
pub const DEFAULT_APPROVAL_TTL_SECS: i64 = 180 * DAY;
/// Default longest approval lifetime (`CMIS_APPROVAL_MAX_TTL_SECS`).
pub const DEFAULT_APPROVAL_MAX_TTL_SECS: i64 = 365 * DAY;
/// Hard ceiling on `CMIS_APPROVAL_MAX_TTL_SECS` (five years).
pub const APPROVAL_TTL_CEILING_SECS: i64 = 5 * 365 * DAY;
/// Default time a request may stay pending (`CMIS_APP_PENDING_TTL_SECS`).
pub const DEFAULT_PENDING_TTL_SECS: i64 = 30 * DAY;
/// Default denial cool-down (`CMIS_APP_DENIED_COOLDOWN_SECS`).
pub const DEFAULT_DENIED_COOLDOWN_SECS: i64 = DAY;
/// Default auto-approvals per lineage per 24 h
/// (`CMIS_APP_AUTO_UPDATE_MAX_PER_DAY`).
pub const DEFAULT_AUTO_UPDATE_MAX_PER_DAY: i64 = 3;
/// Default cap on open requests per host (`CMIS_APP_MAX_PENDING_PER_HOST`).
pub const DEFAULT_MAX_PENDING_PER_HOST: u64 = 50;
/// Default cap on open requests per host and user
/// (`CMIS_APP_MAX_PENDING_PER_USER`).
pub const DEFAULT_MAX_PENDING_PER_USER: u64 = 10;

/// The F19 application-approval settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    /// Global auto-update switch (`CMIS_APP_AUTO_UPDATE`, default on). Off
    /// sends every update to an administrator (F19 §5.3 #1).
    pub auto_update: bool,
    /// Host tiers whose requests may be auto-approved
    /// (`CMIS_APP_AUTO_UPDATE_TIERS`, comma-separated `tpm`, `host-key`;
    /// default both — `host-key` requests carry the `host_tier_b` flag).
    pub auto_update_tiers: Vec<&'static str>,
    /// Auto-approvals allowed per lineage in 24 h.
    pub auto_update_max_per_day: i64,
    /// A request equal to one denied this recently is answered with the
    /// denial (`0` disables the cool-down).
    pub denied_cooldown_secs: i64,
    /// Lifetime of a pending request before the sweeper expires it.
    pub pending_ttl_secs: i64,
    /// Open requests allowed per host.
    pub max_pending_per_host: u64,
    /// Open requests allowed per host and target user.
    pub max_pending_per_user: u64,
    /// Expiry applied when an approver leaves it at 0.
    pub approval_default_ttl_secs: i64,
    /// Longest expiry an approver may choose.
    pub approval_max_ttl_secs: i64,
    /// Whether approvals without expiry may be created
    /// (`CMIS_APPROVAL_ALLOW_NO_EXPIRY`, default false).
    pub allow_no_expiry: bool,
    /// Whether the unauthenticated v1 `GetAllowlist` is served
    /// (`CMIS_LEGACY_GETALLOWLIST`, default on; F19 §6.4, §11 step 7). Off
    /// answers `FAILED_PRECONDITION legacy_getallowlist_disabled` in both
    /// modes; set it once no pre-F19 agent remains (deprecated).
    pub legacy_get_allowlist: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_update: true,
            auto_update_tiers: vec![TIER_TPM, TIER_HOST_KEY],
            auto_update_max_per_day: DEFAULT_AUTO_UPDATE_MAX_PER_DAY,
            denied_cooldown_secs: DEFAULT_DENIED_COOLDOWN_SECS,
            pending_ttl_secs: DEFAULT_PENDING_TTL_SECS,
            max_pending_per_host: DEFAULT_MAX_PENDING_PER_HOST,
            max_pending_per_user: DEFAULT_MAX_PENDING_PER_USER,
            approval_default_ttl_secs: DEFAULT_APPROVAL_TTL_SECS,
            approval_max_ttl_secs: DEFAULT_APPROVAL_MAX_TTL_SECS,
            allow_no_expiry: false,
            legacy_get_allowlist: true,
        }
    }
}

fn int_in(
    get: &impl Fn(&str) -> Option<String>,
    var: &str,
    min: i64,
    max: i64,
) -> anyhow::Result<Option<i64>> {
    let Some(v) = get(var) else {
        return Ok(None);
    };
    let n: i64 = v
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("{var}: not an integer: {v:?}"))?;
    if !(min..=max).contains(&n) {
        anyhow::bail!("{var}: must be between {min} and {max}, got {n}");
    }
    Ok(Some(n))
}

fn flag(get: &impl Fn(&str) -> Option<String>, var: &str) -> anyhow::Result<Option<bool>> {
    let Some(v) = get(var) else {
        return Ok(None);
    };
    match v.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "yes" => Ok(Some(true)),
        "off" | "false" | "0" | "no" => Ok(Some(false)),
        _ => anyhow::bail!("{var}: expected on/off, got {v:?}"),
    }
}

impl AppConfig {
    /// Read the settings from the process environment.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    /// Read the settings through `get` (testable form of [`Self::from_env`]).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut c = Self::default();
        if let Some(b) = flag(&get, "CMIS_APP_AUTO_UPDATE")? {
            c.auto_update = b;
        }
        if let Some(v) = get("CMIS_APP_AUTO_UPDATE_TIERS") {
            let mut tiers = Vec::new();
            for t in v.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                let tier = match t {
                    TIER_TPM => TIER_TPM,
                    TIER_HOST_KEY => TIER_HOST_KEY,
                    other => anyhow::bail!(
                        "CMIS_APP_AUTO_UPDATE_TIERS: unknown tier {other:?} (tpm, host-key)"
                    ),
                };
                if !tiers.contains(&tier) {
                    tiers.push(tier);
                }
            }
            c.auto_update_tiers = tiers;
        }
        if let Some(n) = int_in(&get, "CMIS_APP_AUTO_UPDATE_MAX_PER_DAY", 1, 100)? {
            c.auto_update_max_per_day = n;
        }
        if let Some(n) = int_in(&get, "CMIS_APP_DENIED_COOLDOWN_SECS", 0, 365 * DAY)? {
            c.denied_cooldown_secs = n;
        }
        if let Some(n) = int_in(&get, "CMIS_APP_PENDING_TTL_SECS", 3600, 365 * DAY)? {
            c.pending_ttl_secs = n;
        }
        if let Some(n) = int_in(&get, "CMIS_APP_MAX_PENDING_PER_HOST", 1, 10_000)? {
            c.max_pending_per_host = n.unsigned_abs();
        }
        if let Some(n) = int_in(&get, "CMIS_APP_MAX_PENDING_PER_USER", 1, 10_000)? {
            c.max_pending_per_user = n.unsigned_abs();
        }
        if let Some(n) = int_in(
            &get,
            "CMIS_APPROVAL_MAX_TTL_SECS",
            3600,
            APPROVAL_TTL_CEILING_SECS,
        )? {
            c.approval_max_ttl_secs = n;
        }
        if let Some(n) = int_in(
            &get,
            "CMIS_APPROVAL_DEFAULT_TTL_SECS",
            3600,
            APPROVAL_TTL_CEILING_SECS,
        )? {
            c.approval_default_ttl_secs = n;
        }
        if c.approval_default_ttl_secs > c.approval_max_ttl_secs {
            anyhow::bail!(
                "CMIS_APPROVAL_DEFAULT_TTL_SECS ({}) exceeds CMIS_APPROVAL_MAX_TTL_SECS ({})",
                c.approval_default_ttl_secs,
                c.approval_max_ttl_secs
            );
        }
        if let Some(b) = flag(&get, "CMIS_APPROVAL_ALLOW_NO_EXPIRY")? {
            c.allow_no_expiry = b;
        }
        if let Some(b) = flag(&get, "CMIS_LEGACY_GETALLOWLIST")? {
            c.legacy_get_allowlist = b;
        }
        Ok(c)
    }

    /// Whether requests from hosts of `tier` may be auto-approved.
    #[must_use]
    pub fn tier_allowed(&self, tier: &str) -> bool {
        self.auto_update_tiers.contains(&tier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(vars: &[(&str, &str)]) -> anyhow::Result<AppConfig> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        AppConfig::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_follow_the_spec() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c, AppConfig::default());
        assert!(c.auto_update);
        assert_eq!(c.auto_update_max_per_day, 3);
        assert_eq!(c.approval_default_ttl_secs, 180 * DAY);
        assert_eq!(c.approval_max_ttl_secs, 365 * DAY);
        assert_eq!(c.pending_ttl_secs, 30 * DAY);
        assert!(!c.allow_no_expiry);
        assert!(
            c.legacy_get_allowlist,
            "v1 GetAllowlist is on until turned off"
        );
        assert!(c.tier_allowed("tpm") && c.tier_allowed("host-key"));
    }

    #[test]
    fn values_are_parsed_and_bad_ones_refused() {
        let c = cfg(&[
            ("CMIS_APP_AUTO_UPDATE", "off"),
            ("CMIS_APP_AUTO_UPDATE_TIERS", "tpm"),
            ("CMIS_APPROVAL_ALLOW_NO_EXPIRY", "true"),
            ("CMIS_APP_DENIED_COOLDOWN_SECS", "0"),
            ("CMIS_LEGACY_GETALLOWLIST", "off"),
        ])
        .unwrap();
        assert!(!c.legacy_get_allowlist);
        assert!(cfg(&[("CMIS_LEGACY_GETALLOWLIST", "sometimes")]).is_err());
        assert!(!c.auto_update);
        assert!(c.tier_allowed("tpm") && !c.tier_allowed("host-key"));
        assert!(c.allow_no_expiry);
        assert_eq!(c.denied_cooldown_secs, 0);
        assert!(cfg(&[("CMIS_APP_AUTO_UPDATE", "maybe")]).is_err());
        assert!(cfg(&[("CMIS_APP_AUTO_UPDATE_TIERS", "tpm,sgx")]).is_err());
        assert!(cfg(&[("CMIS_APP_AUTO_UPDATE_MAX_PER_DAY", "0")]).is_err());
        assert!(cfg(&[("CMIS_APPROVAL_MAX_TTL_SECS", "60")]).is_err());
        assert!(cfg(&[
            ("CMIS_APPROVAL_DEFAULT_TTL_SECS", "7200"),
            ("CMIS_APPROVAL_MAX_TTL_SECS", "3600"),
        ])
        .is_err());
    }
}
