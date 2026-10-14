//! Per-requester and host-wide registration budgets (F19 §7.4: 10 per uid
//! per hour, 60 per hour in total), as sliding one-hour windows. The
//! requester key is the uid on Unix and the full SID on Windows
//! ([`super::ledger::Requester`]).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// The window, in seconds.
const WINDOW_SECS: i64 = 3600;

/// Sliding-window counters, per requester key `K`.
#[derive(Debug)]
pub struct Limiter<K> {
    per_key: u32,
    total: u32,
    by_key: HashMap<K, VecDeque<i64>>,
    all: VecDeque<i64>,
}

impl<K: Hash + Eq> Limiter<K> {
    /// At most `per_key` requests per requester and `total` overall per hour.
    #[must_use]
    pub fn new(per_key: u32, total: u32) -> Self {
        Self {
            per_key,
            total,
            by_key: HashMap::new(),
            all: VecDeque::new(),
        }
    }

    /// Spend one request for `key` at `now`, or return the seconds until one
    /// is available.
    pub fn check(&mut self, key: K, now: i64) -> Result<(), u32> {
        let since = now - WINDOW_SECS;
        prune(&mut self.all, since);
        let mine = self.by_key.entry(key).or_default();
        prune(mine, since);
        let wait = |q: &VecDeque<i64>| {
            q.front().map_or(1, |t| {
                u32::try_from((t + WINDOW_SECS - now).max(1)).unwrap_or(1)
            })
        };
        if mine.len() >= self.per_key as usize {
            return Err(wait(mine));
        }
        if self.all.len() >= self.total as usize {
            return Err(wait(&self.all));
        }
        mine.push_back(now);
        self.all.push_back(now);
        // Forget idle requesters so the map stays bounded by the active ones.
        self.by_key.retain(|_, q| !q.is_empty());
        Ok(())
    }
}

fn prune(q: &mut VecDeque<i64>, since: i64) {
    while q.front().is_some_and(|t| *t <= since) {
        q.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_per_uid_and_total_and_slide() {
        let mut l = Limiter::<u32>::new(2, 3);
        assert!(l.check(1, 0).is_ok());
        assert!(l.check(1, 10).is_ok());
        assert_eq!(l.check(1, 20), Err(3580));
        assert!(l.check(2, 30).is_ok());
        // Total spent (3): uid 3 waits for the oldest to leave the window.
        assert_eq!(l.check(3, 40), Err(3560));
        // An hour later the window has slid.
        assert!(l.check(1, 3601).is_ok());
    }
}
