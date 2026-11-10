//! Operator-set Raft timing for the CMIS cluster (rationale and the variable
//! table: `docs/features/raft-timeout-tuning.md`).
//!
//! Absent values keep hiqlite's defaults; every invalid value is a startup
//! error, never a silent clamp. Only liveness depends on these, not safety.

use crate::cluster::ClusterError;

/// Smallest accepted heartbeat (ms).
pub const MIN_HEARTBEAT_MS: u64 = 100;
/// Largest accepted heartbeat (ms): one minute.
pub const MAX_HEARTBEAT_MS: u64 = 60_000;
/// Largest accepted election timeout (ms): five minutes.
pub const MAX_ELECTION_MS: u64 = 300_000;
/// Minimum heartbeats the election minimum must span.
pub const MIN_ELECTION_HEARTBEATS: u64 = 3;

/// The three effective timings, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaftTiming {
    /// Leader heartbeat period and `AppendEntries` time-to-live.
    pub heartbeat_ms: u64,
    /// Shortest follower election timeout.
    pub election_min_ms: u64,
    /// Longest follower election timeout.
    pub election_max_ms: u64,
}

/// Operator overrides for [`RaftTiming`]; `None` keeps hiqlite's default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RaftTimingOverrides {
    /// Override for the heartbeat (ms).
    pub heartbeat_ms: Option<u64>,
    /// Override for the election minimum (ms).
    pub election_min_ms: Option<u64>,
    /// Override for the election maximum (ms).
    pub election_max_ms: Option<u64>,
    /// Accept values shorter than the defaults (more quorum loss, not less).
    pub allow_aggressive: bool,
}

impl RaftTimingOverrides {
    /// True when no timing override is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heartbeat_ms.is_none()
            && self.election_min_ms.is_none()
            && self.election_max_ms.is_none()
    }

    /// Read the `CMIS_RAFT_*` variables through `lookup`; empty means unset.
    ///
    /// # Errors
    /// [`ClusterError::Config`] naming a variable that is present but is not a
    /// whole number of milliseconds (or `true`/`false` for the flag).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ClusterError> {
        let ms = |var: &str| -> Result<Option<u64>, ClusterError> {
            match lookup(var).map(|v| v.trim().to_string()) {
                None => Ok(None),
                Some(v) if v.is_empty() => Ok(None),
                Some(v) => v.parse::<u64>().map(Some).map_err(|_| {
                    config_error(format!("`{var}` must be a whole number of milliseconds"))
                }),
            }
        };
        let allow_aggressive = match lookup("CMIS_RAFT_ALLOW_AGGRESSIVE_TIMEOUTS")
            .map(|v| v.trim().to_ascii_lowercase())
        {
            None => false,
            Some(v) if v.is_empty() || v == "false" || v == "0" => false,
            Some(v) if v == "true" || v == "1" => true,
            Some(_) => {
                return Err(config_error(
                    "`CMIS_RAFT_ALLOW_AGGRESSIVE_TIMEOUTS` must be true or false".to_string(),
                ));
            }
        };
        Ok(Self {
            heartbeat_ms: ms("CMIS_RAFT_HEARTBEAT_MS")?,
            election_min_ms: ms("CMIS_RAFT_ELECTION_MIN_MS")?,
            election_max_ms: ms("CMIS_RAFT_ELECTION_MAX_MS")?,
            allow_aggressive,
        })
    }

    /// Apply the overrides on top of `defaults` and validate the result.
    ///
    /// # Errors
    /// [`ClusterError::Config`] for an out-of-range value, an election window
    /// inconsistent with the heartbeat, or a value below the default without
    /// `allow_aggressive`.
    pub fn resolve(&self, defaults: RaftTiming) -> Result<RaftTiming, ClusterError> {
        let t = RaftTiming {
            heartbeat_ms: self.heartbeat_ms.unwrap_or(defaults.heartbeat_ms),
            election_min_ms: self.election_min_ms.unwrap_or(defaults.election_min_ms),
            election_max_ms: self.election_max_ms.unwrap_or(defaults.election_max_ms),
        };

        if !(MIN_HEARTBEAT_MS..=MAX_HEARTBEAT_MS).contains(&t.heartbeat_ms) {
            return Err(config_error(format!(
                "heartbeat {} ms is outside {MIN_HEARTBEAT_MS}..={MAX_HEARTBEAT_MS}",
                t.heartbeat_ms
            )));
        }
        if t.election_max_ms > MAX_ELECTION_MS {
            return Err(config_error(format!(
                "election maximum {} ms is above {MAX_ELECTION_MS}",
                t.election_max_ms
            )));
        }
        let floor = t.heartbeat_ms.saturating_mul(MIN_ELECTION_HEARTBEATS);
        if t.election_min_ms < floor {
            return Err(config_error(format!(
                "election minimum {} ms must be at least {MIN_ELECTION_HEARTBEATS} x heartbeat \
                 ({floor} ms); raising the heartbeat means raising the election timeouts too",
                t.election_min_ms
            )));
        }
        if t.election_max_ms <= t.election_min_ms {
            return Err(config_error(format!(
                "election maximum {} ms must be greater than the minimum {} ms",
                t.election_max_ms, t.election_min_ms
            )));
        }
        let below_default =
            t.heartbeat_ms < defaults.heartbeat_ms || t.election_min_ms < defaults.election_min_ms;
        if below_default && !self.allow_aggressive {
            return Err(config_error(format!(
                "timeouts shorter than the defaults (heartbeat {} ms, election minimum {} ms) make \
                 quorum loss more likely; set CMIS_RAFT_ALLOW_AGGRESSIVE_TIMEOUTS=true to accept that",
                defaults.heartbeat_ms, defaults.election_min_ms
            )));
        }
        Ok(t)
    }
}

fn config_error(msg: String) -> ClusterError {
    ClusterError::Config(format!("raft timing: {msg}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const DEFAULTS: RaftTiming = RaftTiming {
        heartbeat_ms: 500,
        election_min_ms: 1500,
        election_max_ms: 3000,
    };

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    fn resolve(pairs: &[(&str, &str)]) -> Result<RaftTiming, ClusterError> {
        RaftTimingOverrides::from_lookup(env(pairs))?.resolve(DEFAULTS)
    }

    #[test]
    fn absent_values_keep_the_defaults_exactly() {
        assert_eq!(resolve(&[]).unwrap(), DEFAULTS);
        assert!(RaftTimingOverrides::from_lookup(env(&[]))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn empty_strings_count_as_unset() {
        assert_eq!(
            resolve(&[("CMIS_RAFT_HEARTBEAT_MS", " ")]).unwrap(),
            DEFAULTS
        );
    }

    #[test]
    fn a_longer_heartbeat_with_matching_election_window_is_accepted() {
        let t = resolve(&[
            ("CMIS_RAFT_HEARTBEAT_MS", "2000"),
            ("CMIS_RAFT_ELECTION_MIN_MS", "6000"),
            ("CMIS_RAFT_ELECTION_MAX_MS", "12000"),
        ])
        .unwrap();
        assert_eq!(
            t,
            RaftTiming {
                heartbeat_ms: 2000,
                election_min_ms: 6000,
                election_max_ms: 12000
            }
        );
    }

    #[test]
    fn raising_only_the_heartbeat_is_refused() {
        let e = resolve(&[("CMIS_RAFT_HEARTBEAT_MS", "2000")])
            .unwrap_err()
            .to_string();
        assert!(e.contains("at least 3 x heartbeat"), "{e}");
    }

    #[test]
    fn election_window_must_be_ordered() {
        assert!(resolve(&[
            ("CMIS_RAFT_ELECTION_MIN_MS", "4000"),
            ("CMIS_RAFT_ELECTION_MAX_MS", "4000"),
        ])
        .is_err());
    }

    #[test]
    fn values_below_the_defaults_need_the_opt_in() {
        let pairs = [
            ("CMIS_RAFT_HEARTBEAT_MS", "200"),
            ("CMIS_RAFT_ELECTION_MIN_MS", "1000"),
        ];
        assert!(resolve(&pairs)
            .unwrap_err()
            .to_string()
            .contains("ALLOW_AGGRESSIVE"));
        let mut with_flag = pairs.to_vec();
        with_flag.push(("CMIS_RAFT_ALLOW_AGGRESSIVE_TIMEOUTS", "true"));
        assert_eq!(resolve(&with_flag).unwrap().heartbeat_ms, 200);
    }

    #[test]
    fn out_of_range_values_are_errors_not_clamped() {
        assert!(resolve(&[("CMIS_RAFT_HEARTBEAT_MS", "99")]).is_err());
        assert!(resolve(&[("CMIS_RAFT_HEARTBEAT_MS", "60001")]).is_err());
        assert!(resolve(&[("CMIS_RAFT_ELECTION_MAX_MS", "300001")]).is_err());
    }

    #[test]
    fn garbage_values_are_errors() {
        for (k, v) in [
            ("CMIS_RAFT_HEARTBEAT_MS", "fast"),
            ("CMIS_RAFT_ELECTION_MIN_MS", "-1"),
            ("CMIS_RAFT_ELECTION_MAX_MS", "1.5"),
            ("CMIS_RAFT_ALLOW_AGGRESSIVE_TIMEOUTS", "maybe"),
        ] {
            let e = RaftTimingOverrides::from_lookup(env(&[(k, v)]))
                .unwrap_err()
                .to_string();
            assert!(e.contains(k), "{e}");
        }
    }
}
