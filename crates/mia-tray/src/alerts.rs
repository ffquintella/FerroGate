//! Desktop-notification policy: which transitions need a human, without
//! spamming them.
//!
//! Alerts fire on **transitions** only (never for the state the tray starts
//! up in):
//!
//! - [`AlertKind::BecameUnhealthy`] — an environment that was healthy is now
//!   degraded, broken or absent (passing through `Attesting` does not hide
//!   the transition);
//! - [`AlertKind::SvidExpiring`] — entering `SvidExpiring` (past the renewal
//!   point, renewal failing);
//! - [`AlertKind::CrlStale`] — entering `CrlStale` (minting refused).
//!
//! Each (environment, kind) pair is de-duplicated for [`Policy::dedup_secs`],
//! and at most [`Policy::burst`] alerts are sent per
//! [`Policy::window_secs`] overall; suppressed alerts are logged.

use std::collections::{HashMap, VecDeque};

use mia_status_proto::{AgentState, StatusSnapshot};

/// Why an alert fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertKind {
    /// Healthy → anything at least degraded.
    BecameUnhealthy,
    /// Entered `SvidExpiring`.
    SvidExpiring,
    /// Entered `CrlStale`.
    CrlStale,
}

/// One notification to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// Why.
    pub kind: AlertKind,
    /// Which environment (`None` = default).
    pub environment: Option<String>,
    /// The new state.
    pub state: AgentState,
}

/// Rate-limit settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Seconds before the same (environment, kind) may alert again.
    pub dedup_secs: i64,
    /// Global budget: at most this many alerts…
    pub burst: usize,
    /// …per this many seconds.
    pub window_secs: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            dedup_secs: 30 * 60,
            burst: 3,
            window_secs: 10 * 60,
        }
    }
}

/// The stateful filter.
#[derive(Debug, Clone, Default)]
pub struct Alerter {
    policy: Policy,
    /// Last state seen per environment, ignoring `Attesting`.
    settled: HashMap<Option<String>, AgentState>,
    last_sent: HashMap<(Option<String>, AlertKind), i64>,
    recent: VecDeque<i64>,
}

impl Alerter {
    /// A filter with `policy`.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Feed one observation; returns the alerts to show now.
    pub fn observe(&mut self, now: i64, snapshots: &[StatusSnapshot]) -> Vec<Alert> {
        let mut candidates = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for s in snapshots {
            let env = s.environment.clone();
            seen.insert(env.clone());
            if s.state == AgentState::Attesting {
                continue; // transient: keep the previous settled state
            }
            let prev = self.settled.insert(env.clone(), s.state);
            let Some(prev) = prev else {
                continue; // first sighting: no transition
            };
            if prev == s.state {
                continue;
            }
            let kind = match s.state {
                AgentState::SvidExpiring => Some(AlertKind::SvidExpiring),
                AgentState::CrlStale => Some(AlertKind::CrlStale),
                st if prev == AgentState::Healthy && st.severity() >= 2 => {
                    Some(AlertKind::BecameUnhealthy)
                }
                _ => None,
            };
            if let Some(kind) = kind {
                candidates.push(Alert {
                    kind,
                    environment: env,
                    state: s.state,
                });
            }
        }
        // Forget environments that disappeared (so a re-appearing one counts
        // as a first sighting).
        self.settled.retain(|k, _| seen.contains(k));

        let mut out = Vec::new();
        for alert in candidates {
            let key = (alert.environment.clone(), alert.kind);
            if self
                .last_sent
                .get(&key)
                .is_some_and(|t| now - t < self.policy.dedup_secs)
            {
                tracing::debug!(?alert, "notification de-duplicated");
                continue;
            }
            while self
                .recent
                .front()
                .is_some_and(|t| now - t >= self.policy.window_secs)
            {
                self.recent.pop_front();
            }
            if self.recent.len() >= self.policy.burst {
                tracing::info!(?alert, "notification suppressed by the rate limit");
                continue;
            }
            self.recent.push_back(now);
            self.last_sent.insert(key, now);
            out.push(alert);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::synthesised;

    fn snaps(states: &[(Option<&str>, AgentState)]) -> Vec<StatusSnapshot> {
        states
            .iter()
            .map(|(env, st)| {
                let mut s = synthesised(*st, "x", "y", 0);
                s.environment = env.map(str::to_string);
                s
            })
            .collect()
    }

    #[test]
    fn startup_state_never_alerts() {
        let mut a = Alerter::new(Policy::default());
        assert!(a
            .observe(0, &snaps(&[(None, AgentState::CrlStale)]))
            .is_empty());
        assert!(a
            .observe(5, &snaps(&[(None, AgentState::CrlStale)]))
            .is_empty());
    }

    #[test]
    fn transitions_that_need_a_human_alert() {
        let mut a = Alerter::new(Policy::default());
        a.observe(0, &snaps(&[(None, AgentState::Healthy)]));
        // Healthy → Attesting → CmisUnreachable still counts.
        assert!(a
            .observe(5, &snaps(&[(None, AgentState::Attesting)]))
            .is_empty());
        let got = a.observe(10, &snaps(&[(None, AgentState::CmisUnreachable)]));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, AlertKind::BecameUnhealthy);
        // Degraded → SvidExpiring alerts (entering it).
        let got = a.observe(20, &snaps(&[(None, AgentState::SvidExpiring)]));
        assert_eq!(got[0].kind, AlertKind::SvidExpiring);
        // Back to healthy is silent.
        assert!(a
            .observe(30, &snaps(&[(None, AgentState::Healthy)]))
            .is_empty());
        // Healthy → CrlStale is a CRL alert, not a generic one.
        let got = a.observe(40, &snaps(&[(None, AgentState::CrlStale)]));
        assert_eq!(got[0].kind, AlertKind::CrlStale);
    }

    #[test]
    fn flapping_is_deduplicated() {
        let mut a = Alerter::new(Policy::default());
        a.observe(0, &snaps(&[(None, AgentState::Healthy)]));
        assert_eq!(
            a.observe(1, &snaps(&[(None, AgentState::CrlStale)])).len(),
            1
        );
        a.observe(2, &snaps(&[(None, AgentState::Healthy)]));
        assert!(a
            .observe(3, &snaps(&[(None, AgentState::CrlStale)]))
            .is_empty());
        // After the dedup window it may alert again.
        a.observe(4000, &snaps(&[(None, AgentState::Healthy)]));
        assert_eq!(
            a.observe(4001, &snaps(&[(None, AgentState::CrlStale)]))
                .len(),
            1
        );
    }

    #[test]
    fn a_global_burst_limit_applies() {
        let mut a = Alerter::new(Policy {
            dedup_secs: 0,
            burst: 2,
            window_secs: 600,
        });
        let envs = ["a", "b", "c", "d"];
        let healthy: Vec<_> = envs
            .iter()
            .map(|e| (Some(*e), AgentState::Healthy))
            .collect();
        let broken: Vec<_> = envs
            .iter()
            .map(|e| (Some(*e), AgentState::NotEnrolled))
            .collect();
        a.observe(0, &snaps(&healthy));
        assert_eq!(a.observe(1, &snaps(&broken)).len(), 2);
        a.observe(700, &snaps(&healthy));
        assert_eq!(a.observe(701, &snaps(&broken)).len(), 2);
    }

    #[test]
    fn vanished_environments_are_forgotten() {
        let mut a = Alerter::new(Policy::default());
        a.observe(0, &snaps(&[(Some("p"), AgentState::Healthy)]));
        a.observe(1, &snaps(&[(None, AgentState::NotRunning)]));
        // "p" re-appears broken: a first sighting, not a transition.
        assert!(a
            .observe(2, &snaps(&[(Some("p"), AgentState::PinMismatch)]))
            .is_empty());
    }
}
