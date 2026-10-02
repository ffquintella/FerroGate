//! The background status poller.
//!
//! Polls every [`BASE_INTERVAL`] while the agent answers and backs off
//! exponentially (up to [`MAX_INTERVAL`]) while it does not — so a stopped
//! agent costs one cheap socket attempt (plus, on the fallback path, one
//! bounded `mia status` run) a minute, not one every few seconds. A "poke"
//! wakes it immediately (after an action, or "Refresh"). Dropping the
//! [`Poller`] stops the thread.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use crate::client::Observation;

/// Interval while the agent answers.
pub const BASE_INTERVAL: Duration = Duration::from_secs(5);

/// Longest interval while it does not.
pub const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// Exponential backoff between [`BASE_INTERVAL`] and [`MAX_INTERVAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    current: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            current: BASE_INTERVAL,
        }
    }
}

impl Backoff {
    /// The agent answered: back to the base interval.
    pub fn success(&mut self) -> Duration {
        self.current = BASE_INTERVAL;
        self.current
    }

    /// It did not: double, capped.
    pub fn failure(&mut self) -> Duration {
        self.current = (self.current * 2).min(MAX_INTERVAL);
        self.current
    }
}

/// A running poller.
#[derive(Debug)]
pub struct Poller {
    poke: mpsc::Sender<()>,
}

impl Poller {
    /// Poll now.
    pub fn poke(&self) {
        let _ = self.poke.send(());
    }
}

/// Start polling with `observe` (`None` = transient refusal: keep the last
/// observation) and deliver each result through `deliver`. The thread exits
/// when the [`Poller`] is dropped or `deliver` returns `false`.
pub fn spawn(
    mut observe: impl FnMut() -> Option<Observation> + Send + 'static,
    mut deliver: impl FnMut(Observation) -> bool + Send + 'static,
) -> Poller {
    let (tx, rx) = mpsc::channel::<()>();
    let started = std::thread::Builder::new()
        .name("mia-tray-poller".into())
        .spawn(move || {
            let mut backoff = Backoff::default();
            loop {
                let wait = match observe() {
                    Some(obs) => {
                        let reached = obs.reached_agent();
                        if !deliver(obs) {
                            return;
                        }
                        if reached {
                            backoff.success()
                        } else {
                            backoff.failure()
                        }
                    }
                    None => backoff.failure(),
                };
                match rx.recv_timeout(wait) {
                    Ok(()) => {
                        // Coalesce a burst of pokes into one poll.
                        while rx.try_recv().is_ok() {}
                        backoff.success();
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
        });
    if let Err(e) = started {
        tracing::error!(error = %e, "could not start the status poller");
    }
    Poller { poke: tx }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{synthesised, Source};
    use mia_status_proto::AgentState;

    #[test]
    fn backoff_doubles_and_resets() {
        let mut b = Backoff::default();
        assert_eq!(b.failure(), Duration::from_secs(10));
        assert_eq!(b.failure(), Duration::from_secs(20));
        for _ in 0..10 {
            b.failure();
        }
        assert_eq!(b.failure(), MAX_INTERVAL);
        assert_eq!(b.success(), BASE_INTERVAL);
    }

    #[test]
    fn the_poller_delivers_wakes_on_poke_and_stops() {
        let (tx, rx) = mpsc::channel();
        let poller = spawn(
            || {
                Some(Observation {
                    snapshots: vec![synthesised(AgentState::Healthy, "x", "y", 0)],
                    source: Source::Endpoint,
                })
            },
            move |obs| tx.send(obs).is_ok(),
        );
        let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(first.snapshots[0].state, AgentState::Healthy);
        poller.poke();
        // The poke beats the 5 s interval.
        assert!(rx.recv_timeout(Duration::from_secs(3)).is_ok());
        drop(poller);
        // After the poller is dropped no further observations arrive (one
        // may already be in flight).
        let _ = rx.recv_timeout(Duration::from_millis(200));
        assert!(rx.recv_timeout(Duration::from_secs(6)).is_err());
    }
}
