//! The allowlist sync loop (feature F19 §6.5): poll CMIS `SyncAllowlist`
//! every `allowlist.sync_interval_secs` (default 300 s) ± jitter, verify the
//! signed v2 body, and swap it into the running helper API atomically — no
//! restart, no `SIGHUP`.
//!
//! Each [`AllowlistSync::tick`]:
//!
//! 1. needs a valid host SVID whose machine key signs host calls; without
//!    one it reports `no_svid` and keeps the current allowlist;
//! 2. sends a host-signed `AllowlistSyncDoc {host_uuid, issued_at, nonce,
//!    have_generation, accept_formats: [2]}` — `have_generation` is 0 when
//!    nothing is held or the held body is past half its lifetime, so CMIS
//!    sends a freshly signed body;
//! 3. on `not_modified`, records success; on a body, checks the v2
//!    signature, freshness, host binding, trust domain and generation
//!    ([`verify`]), then writes the body and `allowlist.state` atomically,
//!    swaps the in-memory allowlist and emits `AllowlistSyncApplied`; any
//!    refusal keeps the current allowlist and emits `AllowlistSyncRejected`;
//! 4. on `UNIMPLEMENTED` (a CMIS older than F19) falls back to the legacy
//!    `GetAllowlist` v1 body at the same cadence — unless a v2 generation is
//!    held, which a v1 body could only roll back.
//!
//! Between ticks the loop sleeps the jittered interval, backs off
//! (`min(interval, 2^n × 5 s)`) after transport failures, honours a server
//! `retry-after`, and wakes early when [`SyncTrigger::sync_now`] is called (an
//! approved app request, `SIGHUP`).
//!
//! **Where the synced body lives.** The daemon writes the synced body and
//! its state into its own state directory (`allowlist[-<env>].synced.cbor`
//! and `allowlist[-<env>].state`, see [`SyncConfig`]), never over
//! `allowlist.path`: the hardened Linux daemon cannot write the root-owned
//! configuration directory after its privilege drop, and an operator-provided
//! body must not be overwritten. With the sync on, a start or reload prefers
//! the synced body ([`load_in_force`]).
//!
//! **Offline.** The last verified body stays in force until its `not_after`;
//! per-entry expiry is enforced on every check; after `not_after` every
//! caller is denied (fail closed).

pub mod schedule;
pub mod state;
pub mod verify;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ferro_audit::AuditEvent;
use ferro_crypto::composite::CompositePublicKey;
use ferro_proto::v1::sync_allowlist_response::Result as SyncResult;
use ferro_proto::v1::SyncAllowlistRequest;
use ferro_svid::app_docs::{encode_allowlist_sync, AllowlistSyncDoc, ALLOWLIST_SYNC_CONTEXT};
use futures::future::BoxFuture;
use tokio::sync::{mpsc, Notify};
use tonic::Code;

use crate::helper::allowlist::{Allowlist, AllowlistLoad};
use crate::host_api::{CredentialSlot, HostApi, HostCredentials};
use crate::status::StatusHandle;

pub use state::SyncState;
pub use verify::{RejectReason, Rejection};

/// Mode of the synced body (signed, not secret; readable by the status group
/// like `allowlist.path`).
const BODY_MODE: u32 = 0o640;

/// Where and how often to sync.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Poll interval, clamped to `60..=3600` s.
    pub interval: Duration,
    /// ± jitter in percent, clamped to `0..=50`.
    pub jitter_pct: u8,
    /// The daemon-managed synced body.
    pub body_path: PathBuf,
    /// The held-generation state file.
    pub state_path: PathBuf,
    /// `allowlist.key`, the CMIS enrollment key; `None` ⇒ nothing can be
    /// verified and the sync refuses every body (`no_key`).
    pub key_path: Option<PathBuf>,
    /// `allowlist.max_age_secs`.
    pub max_age_secs: i64,
}

impl SyncConfig {
    /// The sync settings of `config`.
    #[must_use]
    pub fn from_config(config: &crate::config::Config) -> Self {
        let state_path = config.allowlist_state_path();
        Self {
            interval: config.allowlist_sync_interval(),
            jitter_pct: config.allowlist_sync_jitter_pct(),
            body_path: synced_body_path(&state_path),
            state_path,
            key_path: config.allowlist_key().map(Path::to_path_buf),
            max_age_secs: config.allowlist_max_age(),
        }
    }
}

/// The synced body kept beside `state_path` (`allowlist.state` →
/// `allowlist.synced.cbor`).
#[must_use]
pub fn synced_body_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("synced.cbor")
}

/// Wakes the sync loop early, and publishes the generation it holds so a
/// caller can tell whether a sync would bring anything new.
#[derive(Debug, Clone, Default)]
pub struct SyncTrigger {
    notify: Arc<Notify>,
    held: Arc<AtomicU64>,
}

impl SyncTrigger {
    /// A trigger for a loop not started yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask for a sync as soon as possible (the server's minimum interval
    /// still applies).
    pub fn sync_now(&self) {
        self.notify.notify_one();
    }

    /// Ask for a sync when `generation` is above the held one (an approval
    /// answer names the generation that carries it). Returns whether it did.
    #[must_use]
    pub fn sync_if_newer(&self, generation: u64) -> bool {
        let newer = generation > self.held_generation();
        if newer {
            self.sync_now();
        }
        newer
    }

    /// The v2 generation in force (0 when none).
    #[must_use]
    pub fn held_generation(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    fn publish(&self, generation: u64) {
        self.held.store(generation, Ordering::Relaxed);
    }
}

/// Where a verified allowlist goes: the running helper API.
pub trait AllowlistSink: Send + Sync {
    /// Put `allowlist` in force.
    fn apply(&self, allowlist: Allowlist) -> BoxFuture<'_, ()>;
}

impl<A: crate::helper::auth::CallerAuth> AllowlistSink for crate::helper::AllowlistReloader<A> {
    fn apply(&self, allowlist: Allowlist) -> BoxFuture<'_, ()> {
        Box::pin(self.set(Some(allowlist)))
    }
}

/// Work the loop runs after every tick (the registration outbox and status
/// poll, F19 §6.5).
pub trait SyncHook: Send + Sync {
    /// Run once per tick at `now`.
    fn on_tick(&self, now: i64) -> BoxFuture<'_, ()>;
}

/// What one tick did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// A newer (or refreshed) v2 body is in force.
    Applied {
        /// Its generation.
        generation: u64,
        /// Its entry count.
        entries: usize,
    },
    /// CMIS has nothing newer.
    NotModified,
    /// The body was refused; the current allowlist stays.
    Rejected(Rejection),
    /// Legacy CMIS: a v1 body was fetched and put in force.
    LegacyApplied {
        /// Its entry count.
        entries: usize,
    },
    /// Legacy CMIS: nothing new (same body, or none stored).
    LegacyUnchanged,
    /// No valid host SVID (or none whose key signs host calls).
    NoCredentials,
    /// The call failed (unreachable, refused, rate-limited).
    Failed {
        /// The server's `retry-after`, when it sent one.
        retry_after: Option<u64>,
        /// Stable code for status and logs.
        reason: &'static str,
    },
}

impl TickOutcome {
    /// Whether the tick ended well (the allowlist in force is current).
    #[must_use]
    pub const fn ok(&self) -> bool {
        matches!(
            self,
            Self::Applied { .. }
                | Self::NotModified
                | Self::LegacyApplied { .. }
                | Self::LegacyUnchanged
        )
    }
}

/// The sync engine of one environment.
pub struct AllowlistSync {
    cfg: SyncConfig,
    api: Arc<dyn HostApi>,
    creds: CredentialSlot,
    sink: Arc<dyn AllowlistSink>,
    trigger: SyncTrigger,
    audit: Option<mpsc::Sender<AuditEvent>>,
    status: Option<StatusHandle>,
    hook: Option<Arc<dyn SyncHook>>,
    held: Option<SyncState>,
    last_legacy: Option<[u8; 48]>,
    failures: u32,
}

impl AllowlistSync {
    /// An engine syncing into `sink`. `held` is the generation already in
    /// force (from `allowlist.state` or the loaded body).
    #[must_use]
    pub fn new(
        cfg: SyncConfig,
        api: Arc<dyn HostApi>,
        creds: CredentialSlot,
        sink: Arc<dyn AllowlistSink>,
        held: Option<SyncState>,
    ) -> Self {
        let trigger = SyncTrigger::new();
        trigger.publish(held.as_ref().map_or(0, |h| h.generation));
        Self {
            cfg,
            api,
            creds,
            sink,
            trigger,
            audit: None,
            status: None,
            hook: None,
            held,
            last_legacy: None,
            failures: 0,
        }
    }

    /// Emit `AllowlistSyncApplied` / `AllowlistSyncRejected` on `audit`.
    #[must_use]
    pub fn with_audit(mut self, audit: mpsc::Sender<AuditEvent>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Report counters and outcomes to `status` (F18).
    #[must_use]
    pub fn with_status(mut self, status: StatusHandle) -> Self {
        self.status = Some(status);
        self
    }

    /// Run `hook` after every tick.
    #[must_use]
    pub fn with_hook(mut self, hook: Arc<dyn SyncHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Use `trigger` (shared with the registration service) to wake the loop.
    #[must_use]
    pub fn with_trigger(mut self, trigger: SyncTrigger) -> Self {
        trigger.publish(self.held.as_ref().map_or(0, |h| h.generation));
        self.trigger = trigger;
        self
    }

    /// The trigger that wakes this engine's loop.
    #[must_use]
    pub fn trigger(&self) -> SyncTrigger {
        self.trigger.clone()
    }

    /// The held state, if a v2 body is in force.
    #[must_use]
    pub fn held(&self) -> Option<&SyncState> {
        self.held.as_ref()
    }

    /// Run forever: the first tick after `uniform(0, interval)` (or at once
    /// when `start_now`, e.g. nothing is in force yet), then every jittered
    /// interval, earlier when triggered.
    pub async fn run(mut self, start_now: bool) {
        let first = if start_now {
            Duration::ZERO
        } else {
            schedule::initial_delay(self.cfg.interval, schedule::unit_random())
        };
        self.wait(first).await;
        loop {
            let now = unix_now();
            let outcome = self.tick(now).await;
            if let Some(hook) = &self.hook {
                hook.on_tick(now).await;
            }
            let delay = self.next_delay(&outcome, schedule::unit_random());
            self.wait(delay).await;
        }
    }

    async fn wait(&self, delay: Duration) {
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = self.trigger.notify.notified() => {}
        }
    }

    /// The delay before the next tick after `outcome`; `unit` is a uniform
    /// random number in `[0, 1)` for the jitter.
    pub fn next_delay(&mut self, outcome: &TickOutcome, unit: f64) -> Duration {
        if let TickOutcome::Failed { retry_after, .. } = outcome {
            self.failures = self.failures.saturating_add(1);
            retry_after.map_or_else(
                || schedule::backoff(self.cfg.interval, self.failures),
                |secs| schedule::retry_after(self.cfg.interval, secs),
            )
        } else {
            self.failures = 0;
            schedule::jittered(self.cfg.interval, self.cfg.jitter_pct, unit)
        }
    }

    /// One sync at `now`.
    pub async fn tick(&mut self, now: i64) -> TickOutcome {
        let outcome = self.tick_inner(now).await;
        self.report(&outcome, now);
        outcome
    }

    async fn tick_inner(&mut self, now: i64) -> TickOutcome {
        let Some(creds) = self.creds.valid_at(now) else {
            return TickOutcome::NoCredentials;
        };
        // A held state of another host identity (re-enrolled machine) is no
        // rollback floor for this one.
        if self
            .held
            .as_ref()
            .is_some_and(|h| h.host_uuid != creds.host_uuid)
        {
            tracing::warn!("allowlist.state names another host; ignoring it as a rollback floor");
            self.held = None;
        }
        let Some(key) = self.trusted_key() else {
            // A local misconfiguration, logged by `trusted_key`; not a body
            // CMIS sent, so no `AllowlistSyncRejected` event.
            return TickOutcome::Rejected(Rejection {
                reason: RejectReason::NoKey,
                generation: 0,
            });
        };
        let have = match &self.held {
            Some(h) if !h.past_half_life(now) => h.generation,
            _ => 0,
        };
        let doc = AllowlistSyncDoc {
            v: ferro_svid::host_call::DOC_VERSION,
            host_uuid: creds.host_uuid.clone(),
            issued_at: now,
            nonce: crate::host_api::random_bytes(),
            have_generation: have,
            accept_formats: vec![ferro_svid::allowlist_v2::ALLOWLIST_V2_FORMAT],
        };
        let request = match encode_allowlist_sync(&doc)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                creds
                    .auth(ALLOWLIST_SYNC_CONTEXT, &bytes)
                    .map(|auth| (bytes, auth))
                    .map_err(|e| e.to_string())
            }) {
            Ok((doc, auth)) => SyncAllowlistRequest {
                doc,
                auth: Some(auth),
            },
            Err(e) => {
                tracing::error!(error = %e, "could not sign the allowlist sync request");
                return TickOutcome::Failed {
                    retry_after: None,
                    reason: "sign_failed",
                };
            }
        };
        match self.api.sync_allowlist(request).await {
            Ok(resp) => match resp.result {
                Some(SyncResult::NotModified(_)) => TickOutcome::NotModified,
                Some(SyncResult::SignedAllowlistV2(envelope)) => {
                    self.on_body(&creds, &key, &envelope, resp.generation, now)
                        .await
                }
                None => self.reject(
                    &creds,
                    Rejection {
                        reason: RejectReason::Malformed,
                        generation: resp.generation,
                    },
                ),
            },
            Err(s) if s.code() == Code::Unimplemented => self.legacy(&creds, &key, now).await,
            Err(s) => failed(&s),
        }
    }

    /// The trusted CMIS key, re-read every tick so `mia allowlist-key fetch
    /// --rotate` takes effect without a restart.
    fn trusted_key(&self) -> Option<CompositePublicKey> {
        let path = self.cfg.key_path.as_ref()?;
        match crate::system_dir::read_trusted(path)
            .map_err(|e| e.to_string())
            .and_then(|b| CompositePublicKey::from_concat_bytes(&b).map_err(|e| e.to_string()))
        {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::error!(key = %path.display(), error = %e, "allowlist key unusable; refusing synced bodies");
                None
            }
        }
    }

    async fn on_body(
        &mut self,
        creds: &HostCredentials,
        key: &CompositePublicKey,
        envelope: &[u8],
        served_generation: u64,
        now: i64,
    ) -> TickOutcome {
        let expect = verify::Expectations {
            host_uuid: Some(&creds.host_uuid),
            trust_domain: Some(&creds.trust_domain),
            held: self.held.as_ref(),
        };
        let allowlist = match verify::verify_synced(
            envelope,
            key,
            &expect,
            served_generation,
            now,
            self.cfg.max_age_secs,
        ) {
            Ok(al) => al,
            Err(rejection) => return self.reject(creds, rejection),
        };
        let Some(state) = SyncState::of(&allowlist) else {
            return self.reject(
                creds,
                Rejection {
                    reason: RejectReason::Malformed,
                    generation: served_generation,
                },
            );
        };
        let entries = allowlist.entry_count();
        let generation = state.generation;
        let load = AllowlistLoad::of(&allowlist);
        // Persist the body first and the state only after it, so a crash in
        // between leaves a state no newer than the body on disk.
        match crate::atomic_file::write(&self.cfg.body_path, envelope, BODY_MODE) {
            Ok(()) => {
                if let Err(e) = state.store(&self.cfg.state_path) {
                    tracing::error!(path = %self.cfg.state_path.display(), error = %e, "could not record the allowlist state");
                }
            }
            Err(e) => tracing::error!(
                path = %self.cfg.body_path.display(),
                error = %e,
                "could not write the synced allowlist; it is in force until restart"
            ),
        }
        self.sink.apply(allowlist).await;
        if let Some(status) = &self.status {
            status.set_allowlist(load);
        }
        self.held = Some(state);
        self.trigger.publish(generation);
        self.audit(AuditEvent::AllowlistSyncApplied {
            host_uuid: creds.host_uuid.clone(),
            generation,
        });
        tracing::info!(generation, entries, "applied synced allowlist v2");
        TickOutcome::Applied {
            generation,
            entries,
        }
    }

    /// The legacy `GetAllowlist` path of a CMIS without `SyncAllowlist`.
    async fn legacy(
        &mut self,
        creds: &HostCredentials,
        key: &CompositePublicKey,
        now: i64,
    ) -> TickOutcome {
        if self.held.is_some() {
            // A v1 body could only roll the held v2 generation back.
            tracing::warn!(
                "CMIS does not serve SyncAllowlist but a v2 allowlist is held; keeping it"
            );
            return TickOutcome::Failed {
                retry_after: None,
                reason: "sync_unimplemented",
            };
        }
        let bytes = match self.api.get_allowlist(creds.host_uuid.clone()).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return TickOutcome::LegacyUnchanged,
            Err(s) => return failed(&s),
        };
        let digest = sha384(&bytes);
        if self.last_legacy == Some(digest) {
            return TickOutcome::LegacyUnchanged;
        }
        let allowlist = match Allowlist::load_v1(&bytes, key, now, self.cfg.max_age_secs) {
            Ok(al) => al,
            Err(e) => {
                let reason = RejectReason::of_load(&e);
                tracing::warn!(
                    reason = reason.as_str(),
                    "refused the legacy allowlist body"
                );
                return TickOutcome::Rejected(Rejection {
                    reason,
                    generation: 0,
                });
            }
        };
        if let Err(e) = crate::atomic_file::write(&self.cfg.body_path, &bytes, BODY_MODE) {
            tracing::error!(path = %self.cfg.body_path.display(), error = %e, "could not write the fetched allowlist");
        }
        let entries = allowlist.entry_count();
        let load = AllowlistLoad::of(&allowlist);
        self.sink.apply(allowlist).await;
        if let Some(status) = &self.status {
            status.set_allowlist(load);
        }
        self.last_legacy = Some(digest);
        tracing::info!(
            entries,
            "applied legacy allowlist v1 (CMIS has no SyncAllowlist)"
        );
        TickOutcome::LegacyApplied { entries }
    }

    fn reject(&self, creds: &HostCredentials, rejection: Rejection) -> TickOutcome {
        tracing::error!(
            reason = rejection.reason.as_str(),
            generation = rejection.generation,
            "refused a synced allowlist; keeping the current one"
        );
        self.audit(AuditEvent::AllowlistSyncRejected {
            host_uuid: creds.host_uuid.clone(),
            generation: rejection.generation,
            reason: rejection.reason.as_str().to_string(),
        });
        TickOutcome::Rejected(rejection)
    }

    fn audit(&self, event: AuditEvent) {
        if let Some(tx) = &self.audit {
            if tx.try_send(event).is_err() {
                tracing::warn!("audit sink full or closed; allowlist sync event dropped");
            }
        }
    }

    fn report(&self, outcome: &TickOutcome, now: i64) {
        let Some(status) = &self.status else { return };
        let held = self.held.as_ref().map_or(0, |h| h.generation);
        status.update_sync(|s| {
            s.last_attempt_at = Some(now);
            s.generation = held;
            match outcome {
                TickOutcome::Applied { .. } => {
                    s.applied += 1;
                    s.legacy = false;
                }
                TickOutcome::NotModified => {
                    s.not_modified += 1;
                    s.legacy = false;
                }
                TickOutcome::Rejected(_) => s.rejected += 1,
                TickOutcome::LegacyApplied { .. } | TickOutcome::LegacyUnchanged => {
                    s.legacy = true;
                }
                TickOutcome::NoCredentials | TickOutcome::Failed { .. } => s.failures += 1,
            }
            if matches!(
                outcome,
                TickOutcome::Failed {
                    reason: "rate_limited",
                    ..
                }
            ) {
                // An early sync (approval, reload) inside CMIS's minimum
                // interval: retried after `retry-after`, not a failure.
            } else if outcome.ok() {
                s.last_ok_at = Some(now);
                s.consecutive_failures = 0;
                s.failing = false;
            } else {
                s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                s.failing = true;
                s.last_reason = Some(
                    match outcome {
                        TickOutcome::Rejected(r) => r.reason.as_str(),
                        TickOutcome::NoCredentials => "no_svid",
                        TickOutcome::Failed { reason, .. } => reason,
                        _ => "unknown",
                    }
                    .to_string(),
                );
            }
        });
    }
}

/// The outcome of a failed call.
fn failed(status: &tonic::Status) -> TickOutcome {
    let reason = match status.code() {
        Code::ResourceExhausted => "rate_limited",
        Code::Unauthenticated => "host_auth_failed",
        Code::PermissionDenied => "permission_denied",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "timeout",
        _ => "cmis_unreachable",
    };
    tracing::warn!(code = ?status.code(), reason, "allowlist sync failed; keeping the current allowlist");
    TickOutcome::Failed {
        retry_after: crate::host_api::retry_after(status),
        reason,
    }
}

fn sha384(bytes: &[u8]) -> [u8; 48] {
    use sha2::{Digest as _, Sha384};
    Sha384::digest(bytes).into()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// What a start or reload puts in force when the sync is on.
#[derive(Debug)]
pub struct InForce {
    /// The allowlist, or `None` (deny every caller).
    pub allowlist: Option<Allowlist>,
    /// Why, for the status endpoint.
    pub outcome: AllowlistLoad,
    /// The held generation the loop starts from.
    pub held: Option<SyncState>,
}

/// The allowlist to put in force at a start or reload with the sync on: the
/// synced body when there is one that verifies and passes [`verify::admit`]
/// against `allowlist.state` and this host, else the `allowlist.path` body
/// (`fallback`, already verified by the usual startup policy), subject to the
/// same admission — a v1 body is refused while a v2 generation is held.
///
/// `host` is this host's identity from its SVID, when attested; otherwise the
/// held state's host binds the body.
pub fn load_in_force(
    cfg: &SyncConfig,
    fallback: (Option<Allowlist>, AllowlistLoad),
    host: Option<(&str, &str)>,
    now: i64,
) -> InForce {
    let held = match SyncState::load(&cfg.state_path) {
        Ok(held) => held,
        Err(e) => {
            tracing::error!(path = %cfg.state_path.display(), error = %e, "allowlist.state unreadable; no rollback floor until the next sync");
            None
        }
    };
    let host_uuid = host
        .map(|(uuid, _)| uuid)
        .or_else(|| held.as_ref().map(|h| h.host_uuid.as_str()));
    let expect = verify::Expectations {
        host_uuid,
        trust_domain: host.map(|(_, td)| td),
        held: held.as_ref(),
    };
    let admitted = |al: &Allowlist, source: &Path| match verify::admit(al, &expect, true) {
        Ok(()) => true,
        Err(r) => {
            tracing::error!(path = %source.display(), reason = r.reason.as_str(), "allowlist not admitted on this host");
            false
        }
    };
    if cfg.body_path.exists() {
        if let Some(key) = &cfg.key_path {
            if let Ok((Some(al), _)) = crate::helper::allowlist::load_classified(
                &cfg.body_path,
                key,
                now,
                cfg.max_age_secs,
            ) {
                if admitted(&al, &cfg.body_path) {
                    let outcome = AllowlistLoad::of(&al);
                    return InForce {
                        allowlist: Some(al),
                        outcome,
                        held,
                    };
                }
            }
        }
    }
    match fallback {
        (Some(al), outcome) => {
            if admitted(&al, Path::new("allowlist.path")) {
                InForce {
                    allowlist: Some(al),
                    outcome,
                    held,
                }
            } else {
                InForce {
                    allowlist: None,
                    outcome: AllowlistLoad::Invalid,
                    held,
                }
            }
        }
        (None, outcome) => InForce {
            allowlist: None,
            outcome,
            held,
        },
    }
}

#[cfg(test)]
mod tests;
