//! The daemon's audit forwarder (feature F07, T291). Every audit event the
//! daemon emits (helper-API `LocalGrant`/`LocalDenied`, allowlist-sync
//! `AllowlistSyncApplied`/`AllowlistSyncRejected`) is logged locally, spooled
//! to disk ([`spool`]) and forwarded in order to CMIS `AppendAuditEvent`,
//! host-signed afresh on every attempt. Behaviour and limits: `docs/audit.md`.

pub mod spool;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use ferro_audit::AuditEvent;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::AppendAuditRequest;
use futures::future::BoxFuture;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tonic::transport::Channel;
use tonic::{Code, Status};

use crate::audit_client::HostProofSigner;
use crate::host_api::{CredentialSlot, HostCredentials, CALL_TIMEOUT};

pub use spool::{Spool, SpoolLimits};

/// Capacity of the channel the helper API and the allowlist sync push onto.
pub const CHANNEL_CAPACITY: usize = 256;

/// Shortest pause between two repeats of a warning (still failing, events
/// dropped over the cap, spool write errors, rate limited).
const WARN_INTERVAL: Duration = Duration::from_secs(600);

/// Delays and limits of the forwarder.
#[derive(Debug, Clone, Copy)]
pub struct ForwarderConfig {
    /// What the spool may hold.
    pub limits: SpoolLimits,
    /// First retry delay after a failure (doubled per failure, jittered).
    pub backoff_min: Duration,
    /// Longest retry delay.
    pub backoff_max: Duration,
    /// How often missing or refused credentials are looked at again.
    pub creds_poll: Duration,
}

impl Default for ForwarderConfig {
    fn default() -> Self {
        Self {
            limits: SpoolLimits::default(),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            creds_poll: Duration::from_secs(5),
        }
    }
}

/// CMIS `AppendAuditEvent` behind a trait, so the forwarder runs against
/// CMIS ([`ResolverAuditApi`]), a connected channel ([`ChannelAuditApi`]) or
/// a test double. Answers the leaf index the event was appended at.
pub trait AuditApi: Send + Sync {
    /// Send one host-signed `AppendAuditEvent`.
    fn append_audit_event(&self, req: AppendAuditRequest) -> BoxFuture<'_, Result<u64, Status>>;
}

/// Run one call under [`CALL_TIMEOUT`].
async fn timed<T>(
    fut: impl std::future::Future<Output = Result<tonic::Response<T>, Status>>,
) -> Result<T, Status> {
    match tokio::time::timeout(CALL_TIMEOUT, fut).await {
        Ok(r) => r.map(tonic::Response::into_inner),
        Err(_) => Err(Status::deadline_exceeded("host call timed out")),
    }
}

/// `AppendAuditEvent` over an already-connected channel (tests, tools).
#[derive(Clone)]
pub struct ChannelAuditApi {
    client: MachineIdentityClient<Channel>,
}

impl ChannelAuditApi {
    /// Calls over `client`.
    #[must_use]
    pub fn new(client: MachineIdentityClient<Channel>) -> Self {
        Self { client }
    }
}

impl AuditApi for ChannelAuditApi {
    fn append_audit_event(&self, req: AppendAuditRequest) -> BoxFuture<'_, Result<u64, Status>> {
        let mut c = self.client.clone();
        Box::pin(async move { timed(c.append_audit_event(req)).await.map(|r| r.leaf_index) })
    }
}

/// `AppendAuditEvent` through the configured CMIS endpoint(s). Unlike
/// [`crate::host_api::ResolverApi`] it keeps the pinned channel between calls
/// (a busy host forwards many events) and re-resolves, with fail-over, after
/// a transport failure.
pub struct ResolverAuditApi {
    resolver: crate::endpoint::CmisResolver,
    client: tokio::sync::Mutex<Option<MachineIdentityClient<Channel>>>,
}

impl ResolverAuditApi {
    /// Calls through `resolver`.
    #[must_use]
    pub fn new(resolver: crate::endpoint::CmisResolver) -> Self {
        Self {
            resolver,
            client: tokio::sync::Mutex::new(None),
        }
    }

    async fn client(&self) -> Result<MachineIdentityClient<Channel>, Status> {
        let mut cached = self.client.lock().await;
        if let Some(c) = cached.as_ref() {
            return Ok(c.clone());
        }
        match tokio::time::timeout(CALL_TIMEOUT, self.resolver.connect()).await {
            Ok(Ok((_, c))) => {
                *cached = Some(c.clone());
                Ok(c)
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "could not reach CMIS to forward audit events");
                Err(Status::unavailable("cmis_unreachable"))
            }
            Err(_) => Err(Status::unavailable("cmis_unreachable")),
        }
    }
}

impl AuditApi for ResolverAuditApi {
    fn append_audit_event(&self, req: AppendAuditRequest) -> BoxFuture<'_, Result<u64, Status>> {
        Box::pin(async move {
            let mut client = self.client().await?;
            let result = timed(client.append_audit_event(req))
                .await
                .map(|r| r.leaf_index);
            if let Err(s) = &result {
                if matches!(
                    s.code(),
                    Code::Unavailable
                        | Code::DeadlineExceeded
                        | Code::Unknown
                        | Code::Internal
                        | Code::Cancelled
                ) {
                    // Dial again (and fail over) on the next call.
                    *self.client.lock().await = None;
                }
            }
            result
        })
    }
}

/// Where spooled events are forwarded, and the credentials that sign them.
pub struct Forwarding {
    /// CMIS.
    pub api: Arc<dyn AuditApi>,
    /// The host credentials (filled now or by a later re-attestation).
    pub creds: CredentialSlot,
}

/// Counts since start, for logs, tests and diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardStats {
    /// Events waiting in the spool.
    pub pending: usize,
    /// Events accepted into the spool.
    pub spooled: u64,
    /// Events CMIS acknowledged.
    pub forwarded: u64,
    /// Events CMIS refused for good and that were dropped.
    pub rejected: u64,
    /// Oldest events dropped because the spool was full (load included).
    pub dropped_over_cap: u64,
    /// Events never spooled (too large, or not encodable): local log only.
    pub not_spooled: u64,
}

#[derive(Debug, Default)]
struct Counters {
    spooled: AtomicU64,
    forwarded: AtomicU64,
    rejected: AtomicU64,
    not_spooled: AtomicU64,
}

struct Shared {
    spool: Mutex<Spool>,
    wake: Notify,
    counters: Counters,
}

fn lock(spool: &Mutex<Spool>) -> MutexGuard<'_, Spool> {
    spool.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Run `f` on the spool on the blocking pool (it may touch the disk), so a
/// runtime worker never waits on an `fsync`. `None` if `f` panicked.
async fn with_spool<T: Send + 'static>(
    shared: &Arc<Shared>,
    f: impl FnOnce(&mut Spool) -> T + Send + 'static,
) -> Option<T> {
    let shared = Arc::clone(shared);
    tokio::task::spawn_blocking(move || f(&mut lock(&shared.spool)))
        .await
        .ok()
}

/// The running forwarder. Dropping it leaves its tasks running.
pub struct AuditForwarder {
    /// Set once the spool is open; never without CMIS.
    shared: Arc<OnceLock<Arc<Shared>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl AuditForwarder {
    /// Counts since start (all zero when CMIS is not configured, or until
    /// the spool is open). May wait briefly for a spool write in progress.
    #[must_use]
    pub fn stats(&self) -> ForwardStats {
        let Some(shared) = self.shared.get() else {
            return ForwardStats::default();
        };
        // Counters move under the spool lock with the spool itself, so a
        // snapshot taken under it is consistent.
        let s = lock(&shared.spool);
        let c = &shared.counters;
        ForwardStats {
            pending: s.len(),
            spooled: c.spooled.load(Ordering::Relaxed),
            forwarded: c.forwarded.load(Ordering::Relaxed),
            rejected: c.rejected.load(Ordering::Relaxed),
            dropped_over_cap: s.dropped_total(),
            not_spooled: c.not_spooled.load(Ordering::Relaxed),
        }
    }

    /// Stop the forwarder's tasks (an append already on disk completes).
    pub fn abort(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Start the forwarder on `rx`. With `forwarding`, events are spooled at
/// `spool_path` (replaying what an earlier run left) and sent to CMIS;
/// without it (CMIS not configured) they are only logged and the spool,
/// which nothing could drain, is neither created nor grown.
pub fn spawn(
    rx: mpsc::Receiver<AuditEvent>,
    forwarding: Option<Forwarding>,
    spool_path: &Path,
    cfg: ForwarderConfig,
) -> AuditForwarder {
    let Some(forwarding) = forwarding else {
        if std::fs::metadata(spool_path).is_ok_and(|m| m.len() > 0) {
            tracing::warn!(
                spool = %spool_path.display(),
                "CMIS is not configured: audit events spooled by an earlier run are kept, not forwarded"
            );
        }
        return AuditForwarder {
            shared: Arc::default(),
            tasks: vec![tokio::spawn(log_only(rx))],
        };
    };
    let slot = Arc::new(OnceLock::new());
    let task = tokio::spawn(run(
        rx,
        forwarding,
        spool_path.to_path_buf(),
        cfg,
        Arc::clone(&slot),
    ));
    AuditForwarder {
        shared: slot,
        tasks: vec![task],
    }
}

/// Aborts its tasks when dropped (the supervisor was aborted or dropped).
struct AbortOnDrop(Vec<JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

/// Open the spool on the blocking pool (it may read and rewrite megabytes),
/// then run the intake and the sender until aborted.
async fn run(
    rx: mpsc::Receiver<AuditEvent>,
    fwd: Forwarding,
    path: PathBuf,
    cfg: ForwarderConfig,
    slot: Arc<OnceLock<Arc<Shared>>>,
) {
    let limits = cfg.limits;
    let Ok((spool, report)) = tokio::task::spawn_blocking(move || Spool::open(&path, limits)).await
    else {
        tracing::error!("opening the audit spool failed; audit events are only logged locally");
        return log_only(rx).await;
    };
    log_open(&spool, &report);
    let shared = Arc::new(Shared {
        spool: Mutex::new(spool),
        wake: Notify::new(),
        counters: Counters::default(),
    });
    let _ = slot.set(Arc::clone(&shared));
    let mut tasks = AbortOnDrop(vec![
        tokio::spawn(intake(rx, Arc::clone(&shared), limits)),
        tokio::spawn(send_loop(shared, fwd, cfg)),
    ]);
    for t in &mut tasks.0 {
        let _ = t.await;
    }
}

fn log_open(spool: &Spool, report: &spool::OpenReport) {
    let path = spool.path().display();
    if let Some(e) = &report.error {
        tracing::error!(spool = %path, error = %e, "audit spool unusable; events are held in memory until it can be written");
    }
    if report.skipped_lines > 0 {
        tracing::warn!(spool = %path, skipped = report.skipped_lines, "skipped unreadable audit spool records");
    }
    if report.dropped_over_cap > 0 {
        tracing::warn!(spool = %path, dropped = report.dropped_over_cap, "audit spool held more than its cap; oldest events dropped");
    }
    if report.loaded > 0 {
        tracing::info!(spool = %path, pending = report.loaded, "replaying audit events spooled by an earlier run");
    }
}

/// The local audit trail: one record per event, forwarded or not. Its own
/// target keeps it out of the status endpoint's log buffer (events carry
/// caller pids, uids, binary hashes and token `jti`s).
fn log_locally(event: &AuditEvent) {
    tracing::info!(target: crate::logbuf::AUDIT_TARGET, ?event, "helper-api audit event");
}

/// CMIS not configured: log every event, keep nothing.
async fn log_only(mut rx: mpsc::Receiver<AuditEvent>) {
    while let Some(event) = rx.recv().await {
        log_locally(&event);
    }
}

/// The variant name (`LocalGrant`, …): safe to log, unlike the event.
fn event_type(event: &AuditEvent) -> String {
    serde_json::to_value(event)
        .ok()
        .and_then(|v| v.get("type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn event_type_of(cbor: &[u8]) -> String {
    ferro_audit::event::decode(cbor).map_or_else(|_| "unknown".to_owned(), |e| event_type(&e))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Rate-limits a repeated warning, counting what it suppressed.
struct LogGate {
    every: Duration,
    last: Option<Instant>,
    pending: u64,
}

impl LogGate {
    fn new(every: Duration) -> Self {
        Self {
            every,
            last: None,
            pending: 0,
        }
    }

    /// Note `n` occurrences; `Some(total since the last admitted log)` when
    /// a log is due now.
    fn admit(&mut self, n: u64) -> Option<u64> {
        self.pending = self.pending.saturating_add(n);
        if self.last.is_none_or(|t| t.elapsed() >= self.every) {
            self.last = Some(Instant::now());
            Some(std::mem::take(&mut self.pending))
        } else {
            None
        }
    }
}

/// Wait for the in-flight spool write, if any.
async fn join_flight(
    flight: &mut Option<JoinHandle<spool::PushReport>>,
) -> Result<spool::PushReport, tokio::task::JoinError> {
    match flight {
        Some(h) => h.await,
        None => std::future::pending().await,
    }
}

/// Drain the channel: log each event, stage it and append staged events to
/// the spool, one flushed write at a time on the blocking pool. Receiving
/// never waits on that write (nor ever on CMIS), so producers only feel
/// back-pressure once a whole spool's worth of events is staged.
async fn intake(mut rx: mpsc::Receiver<AuditEvent>, shared: Arc<Shared>, limits: SpoolLimits) {
    let mut staged: Vec<(i64, Vec<u8>)> = Vec::new();
    let mut staged_bytes = 0u64;
    let mut flight: Option<JoinHandle<spool::PushReport>> = None;
    let mut open = true;
    let mut drop_gate = LogGate::new(WARN_INTERVAL);
    let mut io_gate = LogGate::new(WARN_INTERVAL);
    loop {
        let room = staged.len() < limits.max_entries && staged_bytes < limits.max_bytes;
        tokio::select! {
            done = join_flight(&mut flight) => {
                flight = None;
                note_push(done, &mut drop_gate, &mut io_gate);
                shared.wake.notify_one();
            }
            event = rx.recv(), if open && room => match event {
                Some(event) => {
                    stage(&shared, &event, &mut staged, &mut staged_bytes);
                    while staged.len() < limits.max_entries && staged_bytes < limits.max_bytes {
                        let Ok(event) = rx.try_recv() else { break };
                        stage(&shared, &event, &mut staged, &mut staged_bytes);
                    }
                }
                None => open = false,
            },
        }
        if flight.is_none() && !staged.is_empty() {
            let batch = std::mem::take(&mut staged);
            staged_bytes = 0;
            let shared = Arc::clone(&shared);
            flight = Some(tokio::task::spawn_blocking(move || {
                let mut spool = lock(&shared.spool);
                let report = spool.push(batch);
                shared
                    .counters
                    .spooled
                    .fetch_add(report.spooled as u64, Ordering::Relaxed);
                report
            }));
        }
        if !open && flight.is_none() && staged.is_empty() {
            return;
        }
    }
}

fn stage(shared: &Shared, event: &AuditEvent, staged: &mut Vec<(i64, Vec<u8>)>, bytes: &mut u64) {
    log_locally(event);
    match ferro_audit::event::encode(event) {
        Ok(cbor) if cbor.len() <= spool::MAX_EVENT_CBOR_BYTES => {
            *bytes = bytes.saturating_add(cbor.len() as u64);
            staged.push((unix_now(), cbor));
        }
        Ok(_) => {
            shared.counters.not_spooled.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(event_type = %event_type(event), "audit event too large to forward; kept in the local log only");
        }
        Err(_) => {
            shared.counters.not_spooled.fetch_add(1, Ordering::Relaxed);
            tracing::error!(event_type = %event_type(event), "audit event could not be encoded; kept in the local log only");
        }
    }
}

fn note_push(
    done: Result<spool::PushReport, tokio::task::JoinError>,
    drop_gate: &mut LogGate,
    io_gate: &mut LogGate,
) {
    let Ok(report) = done else {
        tracing::error!("audit spool write task failed; its events are not spooled");
        return;
    };
    if report.dropped > 0 {
        if let Some(dropped) = drop_gate.admit(report.dropped) {
            tracing::warn!(
                dropped,
                dropped_total = report.dropped_total,
                "audit spool full; oldest events dropped (they remain in the local log)"
            );
        }
    }
    if let Some(e) = report.error {
        if io_gate.admit(1).is_some() {
            tracing::error!(error = %e, "could not write the audit spool; events are held in memory until it can be written");
        }
    }
}

/// What one forward attempt means for the event at the front of the spool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Appended at this leaf index: finish it.
    Forwarded(u64),
    /// Refused for good (this event, not the host): drop it so the queue
    /// moves on.
    Rejected(&'static str),
    /// Over the host's rate limit: wait (`retry-after` when given).
    RateLimited(Option<Duration>),
    /// The host proof was refused (expired or revoked SVID, clock skew, a
    /// proof document CMIS cannot decode, a host mismatch, …): keep the
    /// event and wait for the credentials to change or the backoff.
    AuthRefused(&'static str),
    /// CMIS unreachable or failing: keep the event, back off and retry.
    Transient(&'static str),
}

/// Classify a CMIS answer. Only the answers `AppendAuditEvent` gives about
/// the event itself drop it; anything else keeps it (bounded by the cap).
fn classify(result: Result<u64, Status>) -> Outcome {
    let status = match result {
        Ok(leaf) => return Outcome::Forwarded(leaf),
        Err(s) => s,
    };
    match status.code() {
        // Oversized, or not an `AuditEvent` CMIS can decode.
        Code::InvalidArgument => match status.message() {
            "field_too_long" => Outcome::Rejected("field_too_long"),
            "malformed audit event" => Outcome::Rejected("malformed_event"),
            // CMIS could not decode the signed proof document (version
            // skew): part of the host proof, not of the event.
            "malformed_doc" => Outcome::AuthRefused("malformed_doc"),
            _ => Outcome::AuthRefused("invalid_argument"),
        },
        // `event_not_forwardable`: a CMIS-side event type. `host_mismatch`
        // is also the proof check's answer (document host ≠ SVID host), so
        // it holds the event like any other proof refusal.
        Code::PermissionDenied => match status.message() {
            "event_not_forwardable" => Outcome::Rejected("event_not_forwardable"),
            "host_mismatch" => Outcome::AuthRefused("host_mismatch"),
            _ => Outcome::AuthRefused("permission_denied"),
        },
        Code::Unauthenticated => Outcome::AuthRefused("host_auth_failed"),
        Code::ResourceExhausted => {
            Outcome::RateLimited(crate::host_api::retry_after(&status).map(Duration::from_secs))
        }
        Code::Unavailable => Outcome::Transient("unavailable"),
        Code::DeadlineExceeded => Outcome::Transient("deadline_exceeded"),
        Code::Unimplemented => Outcome::Transient("unimplemented"),
        _ => Outcome::Transient("unexpected_answer"),
    }
}

/// Exponential backoff with equal jitter: the n-th delay is drawn from
/// `[d/2, d]` with `d = min(max, min·2ⁿ)`.
struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    fn new(min: Duration, max: Duration) -> Self {
        let min = min.max(Duration::from_millis(1));
        Self {
            min,
            max: max.max(min),
            next: min,
        }
    }

    fn reset(&mut self) {
        self.next = self.min;
    }

    fn next_delay(&mut self) -> Duration {
        let d = self.next;
        self.next = d.saturating_mul(2).min(self.max);
        jitter(d)
    }
}

/// A random duration in `[d/2, d]`.
fn jitter(d: Duration) -> Duration {
    let half = d / 2;
    let span = u64::try_from(d.saturating_sub(half).as_nanos()).unwrap_or(u64::MAX - 1);
    let bytes = crate::host_api::random_bytes();
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[..8]);
    half + Duration::from_nanos(u64::from_le_bytes(word) % (span + 1))
}

/// Sleep `delay`, returning early when the credential slot holds credentials
/// other than `refused` (a re-attestation replaced them).
async fn sleep_or_new_creds(
    delay: Duration,
    slot: &CredentialSlot,
    refused: &Arc<HostCredentials>,
    poll: Duration,
) {
    let deadline = Instant::now() + delay;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        tokio::time::sleep(deadline.saturating_duration_since(now).min(poll)).await;
        if slot.get().is_some_and(|c| !Arc::ptr_eq(&c, refused)) {
            return;
        }
    }
}

/// Why no call can be signed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredsWait {
    /// No credentials yet (attestation pending or failed).
    Missing,
    /// The host SVID expired; MIA does not renew it while running.
    Expired,
}

/// The credentials that can sign a call at `now`, or why there are none.
fn usable_creds(slot: &CredentialSlot, now: i64) -> Result<Arc<HostCredentials>, CredsWait> {
    match slot.get() {
        Some(c) if c.valid_at(now) => Ok(c),
        Some(_) => Err(CredsWait::Expired),
        None => Err(CredsWait::Missing),
    }
}

/// Record why forwarding waits; `true` when the reason changed (log once).
fn wait_changed(state: &mut Option<CredsWait>, why: CredsWait) -> bool {
    state.replace(why) != Some(why)
}

fn log_creds_wait(why: CredsWait, pending: usize) {
    match why {
        CredsWait::Missing => tracing::info!(
            pending,
            "audit forwarding waits for a valid host SVID whose key signs host calls"
        ),
        CredsWait::Expired => tracing::warn!(
            pending,
            "host SVID expired; audit events are held in the spool until the daemon re-attests (restart it), the oldest dropped beyond the cap"
        ),
    }
}

/// Tracks whether forwarding is failing, to log transitions once and
/// repeats rarely.
struct Health {
    failing_since: Option<Instant>,
    gate: LogGate,
}

impl Health {
    fn failed(&mut self, reason: &str, pending: usize, dropped_total: u64) {
        match self.failing_since {
            None => {
                self.failing_since = Some(Instant::now());
                self.gate = LogGate::new(WARN_INTERVAL);
                self.gate.admit(1);
                tracing::warn!(
                    reason,
                    pending,
                    "audit forwarding to CMIS failing; events stay in the spool and are retried"
                );
            }
            Some(since) => {
                if self.gate.admit(1).is_some() {
                    tracing::warn!(
                        reason,
                        pending,
                        dropped_total,
                        failing_secs = since.elapsed().as_secs(),
                        "audit forwarding to CMIS still failing"
                    );
                } else {
                    tracing::debug!(reason, pending, "audit forward attempt failed");
                }
            }
        }
    }

    fn succeeded(&mut self, pending: usize) {
        if let Some(since) = self.failing_since.take() {
            tracing::info!(
                pending,
                failing_secs = since.elapsed().as_secs(),
                "audit forwarding to CMIS recovered"
            );
        }
    }
}

/// The front of the spool and the counts the logs report.
struct Front {
    next: Option<(u64, Vec<u8>)>,
    pending: usize,
    dropped_total: u64,
}

/// Forward the spool's front event until the spool is empty, then wait for
/// the intake; never more than one call in flight, so CMIS sees spool order.
async fn send_loop(shared: Arc<Shared>, fwd: Forwarding, cfg: ForwarderConfig) {
    let mut backoff = Backoff::new(cfg.backoff_min, cfg.backoff_max);
    let mut rate_gate = LogGate::new(WARN_INTERVAL);
    let mut health = Health {
        failing_since: None,
        gate: LogGate::new(WARN_INTERVAL),
    };
    let mut creds_wait = None;
    loop {
        let Some(front) = with_spool(&shared, |s| Front {
            next: s.front().map(|e| (e.seq, e.cbor.clone())),
            pending: s.len(),
            dropped_total: s.dropped_total(),
        })
        .await
        else {
            tokio::time::sleep(cfg.backoff_max).await;
            continue;
        };
        let Some((seq, cbor)) = front.next else {
            shared.wake.notified().await;
            continue;
        };
        let creds = match usable_creds(&fwd.creds, unix_now()) {
            Ok(creds) => creds,
            Err(why) => {
                if wait_changed(&mut creds_wait, why) {
                    log_creds_wait(why, front.pending);
                }
                tokio::time::sleep(cfg.creds_poll).await;
                continue;
            }
        };
        creds_wait = None;

        let signer = HostProofSigner {
            key: &*creds.key,
            svid_jws: &creds.svid_jws,
            host_uuid: &creds.host_uuid,
        };
        let request = match crate::audit_client::signed_request_now(cbor.clone(), &signer) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "could not sign an audit forward");
                health.failed("sign_failed", front.pending, front.dropped_total);
                tokio::time::sleep(backoff.next_delay()).await;
                continue;
            }
        };
        match classify(fwd.api.append_audit_event(request).await) {
            Outcome::Forwarded(leaf_index) => {
                tracing::debug!(leaf_index, "audit event forwarded to CMIS");
                finish(&shared, seq, true).await;
                backoff.reset();
                health.succeeded(front.pending.saturating_sub(1));
            }
            Outcome::Rejected(reason) => {
                tracing::warn!(
                    reason,
                    event_type = %event_type_of(&cbor),
                    "CMIS refused an audit event for good; dropped it from the spool (it remains in the local log)"
                );
                finish(&shared, seq, false).await;
                backoff.reset();
                health.succeeded(front.pending.saturating_sub(1));
            }
            Outcome::RateLimited(wait) => {
                let wait = wait.unwrap_or_else(|| backoff.next_delay());
                if rate_gate.admit(1).is_some() {
                    tracing::info!(
                        wait_secs = wait.as_secs(),
                        pending = front.pending,
                        "audit forwarding over the CMIS rate limit (CMIS_AUDIT_FORWARD_MAX_PER_MIN); waiting"
                    );
                }
                tokio::time::sleep(wait.min(cfg.backoff_max)).await;
            }
            Outcome::AuthRefused(reason) => {
                health.failed(reason, front.pending, front.dropped_total);
                sleep_or_new_creds(backoff.next_delay(), &fwd.creds, &creds, cfg.creds_poll).await;
            }
            Outcome::Transient(reason) => {
                health.failed(reason, front.pending, front.dropped_total);
                tokio::time::sleep(backoff.next_delay()).await;
            }
        }
    }
}

/// Finish event `seq` in the spool (on disk too), counting it as forwarded
/// or rejected.
async fn finish(shared: &Arc<Shared>, seq: u64, forwarded: bool) {
    let owner = Arc::clone(shared);
    let done = with_spool(shared, move |s| {
        let result = s.complete_through(seq);
        let c = &owner.counters;
        let tally = if forwarded { &c.forwarded } else { &c.rejected };
        tally.fetch_add(1, Ordering::Relaxed);
        result
    });
    match done.await {
        Some(Ok(())) => {}
        Some(Err(e)) => tracing::error!(
            error = %e,
            "could not record a finished audit event in the spool; it may be sent again after a restart"
        ),
        None => tracing::error!("audit spool update failed"),
    }
}

#[cfg(test)]
mod tests;
