//! Host SVID renewal in the running daemon (T294, feature F04).
//!
//! One long-lived task per environment renews at the jittered 60 % point —
//! `Rotate` while the host-key tier is inside CMIS's re-attestation window, a
//! full attestation otherwise — retries with a bounded back-off, fails closed
//! at expiry and stops the daemon if CMIS issues another identity.

use std::future::Future;
use std::time::Duration;

use futures::future::BoxFuture;
use tonic::Status;

use crate::status::{AttestFailure, StatusHandle};

pub mod schedule;
mod swap;

pub use swap::{rotate_host_svid, HostSvid, MinterSink, SvidCell, Swap};

use schedule::{secs, Next, REATTEST_INTERVAL};

#[cfg(test)]
mod tests;

/// The identity and lifetime of an SVID: what the schedule needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvidInfo {
    /// The SPIFFE id it names.
    pub spiffe_id: String,
    /// Issue time, Unix seconds.
    pub issued_at: i64,
    /// Expiry, Unix seconds.
    pub expires_at: i64,
    /// Whether it may renew with `Rotate`: host-key tier with a host-call key.
    pub rotatable: bool,
}

/// A newly issued SVID and the credential to put in force with it.
#[derive(Debug)]
pub struct Issued<C> {
    /// What the schedule needs about it.
    pub info: SvidInfo,
    /// What [`Renewer::install`] puts in force.
    pub credential: C,
}

/// How a new SVID was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalPath {
    /// A host-signed `Rotate` (short path, same key).
    Rotate,
    /// A full attestation.
    FullAttest,
}

impl RenewalPath {
    /// Stable name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rotate => "rotate",
            Self::FullAttest => "full_attestation",
        }
    }
}

/// The daemon side of a renewal: obtain a new SVID, put it in force, take
/// an expired one out. Boxed futures keep the trait object-safe.
pub trait Renewer: Send {
    /// What a successful renewal puts in force.
    type Credential: Send;

    /// Renew the SVID in force with a host-signed `Rotate`.
    fn rotate(&mut self) -> BoxFuture<'_, Result<Issued<Self::Credential>, Status>>;

    /// Run a full attestation with the configured backend.
    fn full_attest(&mut self) -> BoxFuture<'_, Result<Issued<Self::Credential>, AttestFailure>>;

    /// Put `credential` in force: host-call credentials, then the minter.
    fn install(&mut self, credential: Self::Credential, path: RenewalPath) -> BoxFuture<'_, ()>;

    /// After the status reports the new SVID: refresh what depends on it
    /// (allowlist sync, proposals).
    fn after_install(&mut self, path: RenewalPath) -> BoxFuture<'_, ()>;

    /// Fail closed: minting and host calls off.
    fn disable(&mut self) -> BoxFuture<'_, ()>;
}

/// Why the renewal loop stopped the daemon.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Fatal {
    /// A full attestation returned another SPIFFE id: what this run bound to
    /// the old one (allowlist, held state) must not serve the new one.
    #[error("CMIS issued an SVID for {issued}, but this agent runs as {held}")]
    IdentityChanged {
        /// The identity this run holds.
        held: String,
        /// The identity CMIS issued.
        issued: String,
    },
}

/// How [`Renewal::run`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// Asked to stop.
    Shutdown,
    /// The daemon must stop (its supervisor restarts it).
    Fatal(Fatal),
}

/// Longest single sleep of [`Renewal::run`]: the wall clock is re-read at
/// least this often, so a suspended host or a clock jump still switches
/// minting off within a minute of expiry.
pub const MAX_SLEEP: Duration = Duration::from_secs(60);

/// The SVID held and when it is next renewed.
struct Held {
    info: SvidInfo,
    /// The last full attestation (Unix seconds); `Rotate` does not move it.
    last_full_attest_at: i64,
}

/// The renewal state machine of one environment.
pub struct Renewal<R: Renewer> {
    renewer: R,
    status: StatusHandle,
    held: Option<Held>,
    /// The identity this run is bound to (first SVID held).
    identity: Option<String>,
    failures: u32,
    /// Minting was switched off at expiry and not yet back on.
    disabled: bool,
    /// The earliest time the next attempt runs.
    next_at: i64,
    jitter: Box<dyn FnMut() -> f64 + Send>,
}

impl<R: Renewer> Renewal<R> {
    /// A renewal with no SVID yet: the first step attests.
    #[must_use]
    pub fn new(renewer: R, status: StatusHandle) -> Self {
        Self {
            renewer,
            status,
            held: None,
            identity: None,
            failures: 0,
            disabled: false,
            next_at: i64::MIN,
            jitter: Box::new(crate::scheduler::random_jitter),
        }
    }

    /// Draw jitter samples from `jitter` (uniform in `[0, 1)`) instead of the
    /// OS RNG. Call before [`Self::with_current`].
    #[must_use]
    pub fn with_jitter(mut self, jitter: impl FnMut() -> f64 + Send + 'static) -> Self {
        self.jitter = Box::new(jitter);
        self
    }

    /// Make the first attempt no earlier than `at` (Unix seconds): the daemon
    /// counts its failed inline start-up attestation as the first one.
    #[must_use]
    pub fn with_first_attempt_at(mut self, at: i64) -> Self {
        self.next_at = at;
        self
    }

    /// Hold `info`, obtained by a full attestation at `attested_at`.
    #[must_use]
    pub fn with_current(mut self, info: SvidInfo, attested_at: i64) -> Self {
        self.identity = Some(info.spiffe_id.clone());
        self.next_at = self.rotation_point(&info);
        self.held = Some(Held {
            info,
            last_full_attest_at: attested_at,
        });
        self
    }

    /// The jittered renewal point of `info`, drawn once per SVID.
    fn rotation_point(&mut self, info: &SvidInfo) -> i64 {
        ferro_svid::rotation_at(info.issued_at, info.expires_at, (self.jitter)())
    }

    /// One decision at `now`: renew, retry, fail closed or wait. Returns how
    /// long to wait before the next step.
    ///
    /// # Errors
    ///
    /// [`Fatal`] when the daemon must stop.
    pub async fn step(&mut self, now: i64) -> Result<Duration, Fatal> {
        let Some(held) = &self.held else {
            if now < self.next_at {
                return Ok(secs(self.next_at - now));
            }
            return self.full_attest(now, false).await;
        };
        let expires_at = held.info.expires_at;
        if now >= expires_at {
            if !self.disabled {
                tracing::warn!(
                    spiffe_id = %held.info.spiffe_id,
                    expired_at = expires_at,
                    "host SVID expired before it was renewed; token minting and host calls are off \
                     until a full attestation succeeds"
                );
                self.renewer.disable().await;
                self.disabled = true;
            } else if now < self.next_at {
                // Off already; wait out the re-attestation interval.
                return Ok(secs(self.next_at - now));
            }
            return self.full_attest(now, false).await;
        }
        if now < self.next_at {
            // Woken early (the loop re-reads the clock every minute).
            return Ok(secs(self.next_at.min(expires_at) - now));
        }
        self.status.renewal_started();
        if held.info.rotatable && schedule::rotate_allowed(now, held.last_full_attest_at) {
            match self.renewer.rotate().await {
                Ok(issued) => return self.accept(issued, now, RenewalPath::Rotate, true).await,
                Err(refusal) => {
                    let failure = rotate_failure(&refusal);
                    match schedule::classify(&refusal) {
                        Next::FullAttest => tracing::info!(
                            code = ?refusal.code(),
                            reason = refusal.message(),
                            "CMIS refused the Rotate renewal; renewing with a full attestation"
                        ),
                        Next::Retry => {
                            tracing::warn!(
                                code = ?refusal.code(),
                                reason = refusal.message(),
                                "host SVID renewal (Rotate) failed; retrying"
                            );
                            self.status.renewal_failed(failure);
                            return Ok(self.failed(now, None));
                        }
                        Next::RetryAfter(after) => {
                            tracing::warn!(
                                retry_after_secs = after.as_secs(),
                                "host SVID renewal (Rotate) rate limited; retrying later"
                            );
                            self.status.renewal_failed(failure);
                            return Ok(self.failed(now, Some(after)));
                        }
                    }
                }
            }
        }
        self.full_attest(now, true).await
    }

    /// Run a full attestation; `renewing` while the SVID held is still valid
    /// (the status keeps its phase then).
    async fn full_attest(&mut self, now: i64, renewing: bool) -> Result<Duration, Fatal> {
        if !renewing {
            self.status.attest_started();
        }
        match self.renewer.full_attest().await {
            Ok(issued) => {
                self.accept(issued, now, RenewalPath::FullAttest, renewing)
                    .await
            }
            Err(failure) => {
                // The backend logged the cause; report and back off.
                self.report_failure(failure, renewing);
                Ok(self.failed(now, None))
            }
        }
    }

    fn report_failure(&self, failure: AttestFailure, renewing: bool) {
        if renewing {
            self.status.renewal_failed(failure);
        } else {
            self.status.attest_failed(failure);
        }
    }

    /// Put `issued` in force unless it names another identity (fatal) or is
    /// not valid now (a failed attempt).
    async fn accept(
        &mut self,
        issued: Issued<R::Credential>,
        now: i64,
        path: RenewalPath,
        renewing: bool,
    ) -> Result<Duration, Fatal> {
        let info = issued.info;
        if let Some(held) = self.identity.as_ref().filter(|id| **id != info.spiffe_id) {
            tracing::error!(
                held = %held,
                issued = %info.spiffe_id,
                "CMIS issued an SVID for another host identity; it is not put in force. Token \
                 minting and host calls are off and the agent stops, so its supervisor restarts \
                 it under the new identity"
            );
            let fatal = Fatal::IdentityChanged {
                held: held.clone(),
                issued: info.spiffe_id,
            };
            self.renewer.disable().await;
            self.disabled = true;
            self.status.attest_failed(AttestFailure::Other);
            return Err(fatal);
        }
        if info.expires_at <= now || info.expires_at <= info.issued_at {
            tracing::error!(
                spiffe_id = %info.spiffe_id,
                issued_at = info.issued_at,
                expires_at = info.expires_at,
                now,
                path = path.as_str(),
                "CMIS issued an SVID that is not valid now (check the host clock); keeping the \
                 current one"
            );
            self.report_failure(AttestFailure::Other, renewing);
            return Ok(self.failed(now, None));
        }
        let expires_at = info.expires_at;
        self.renewer.install(issued.credential, path).await;
        self.status
            .attest_succeeded(&info.spiffe_id, info.issued_at, info.expires_at);
        self.renewer.after_install(path).await;

        let last_full_attest_at = match (path, &self.held) {
            (RenewalPath::Rotate, Some(held)) => held.last_full_attest_at,
            _ => now,
        };
        let due = self.rotation_point(&info);
        tracing::info!(
            spiffe_id = %info.spiffe_id,
            path = path.as_str(),
            expires_at = info.expires_at,
            next_renewal_in_secs = due.saturating_sub(now).max(0),
            "host SVID renewed; token minting and host calls use it"
        );
        self.identity = Some(info.spiffe_id.clone());
        self.held = Some(Held {
            info,
            last_full_attest_at,
        });
        self.failures = 0;
        self.disabled = false;
        // Never renew again at once, even when the new SVID's own point has
        // passed on this clock (host clock ahead of CMIS): no tight loop.
        let wait = secs(due - now)
            .max(schedule::RETRY_BASE)
            .min(secs(expires_at - now));
        self.next_at = now.saturating_add(i64::try_from(wait.as_secs()).unwrap_or(i64::MAX));
        Ok(wait)
    }

    /// Count a failed attempt; the wait before the next one.
    fn failed(&mut self, now: i64, retry_after: Option<Duration>) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let wait = match (&self.held, retry_after) {
            (Some(held), Some(after)) if now < held.info.expires_at => {
                schedule::retry_after_wait(now, held.info.expires_at, after)
            }
            (Some(held), _) => {
                let unit = (self.jitter)();
                schedule::next_wait(
                    now,
                    held.info.issued_at,
                    held.info.expires_at,
                    self.failures,
                    unit,
                )
            }
            (None, _) => REATTEST_INTERVAL,
        };
        let wait_secs = i64::try_from(wait.as_secs()).unwrap_or(i64::MAX);
        self.next_at = now.saturating_add(wait_secs);
        wait
    }

    /// Step until `shutdown` resolves or a [`Fatal`] stops the loop, the
    /// first step after `first`; wall time from `clock` (Unix seconds).
    /// Sleeps at most [`MAX_SLEEP`] at a time.
    pub async fn run(
        mut self,
        clock: impl Fn() -> i64,
        first: Duration,
        shutdown: impl Future<Output = ()>,
    ) -> Exit {
        tokio::pin!(shutdown);
        let mut wait = first;
        loop {
            // A long wait is slept in slices; each wake is a cheap step that
            // re-checks expiry against the wall clock.
            tokio::select! {
                biased;
                () = &mut shutdown => return Exit::Shutdown,
                () = tokio::time::sleep(wait.min(MAX_SLEEP)) => {}
            }
            match self.step(clock()).await {
                Ok(next) => wait = next,
                Err(fatal) => return Exit::Fatal(fatal),
            }
        }
    }
}

/// The status reason of a failed `Rotate` (stable codes only).
fn rotate_failure(refusal: &Status) -> AttestFailure {
    AttestFailure::from_attest_error(
        &crate::client::AttestClientError::Transport(refusal.clone()),
        false,
    )
}
