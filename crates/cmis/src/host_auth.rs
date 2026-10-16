//! Host call authentication — F19 §7.1 `HostCallAuth`, reusable by every
//! host-facing RPC that carries a signed document.
//!
//! Consumers: `AppendAuditEvent` (F20 Phase 0, context
//! `ferrogate-audit-forward-v1`), F19's `SubmitAppRequest`,
//! `GetAppRequestStatus` and `SyncAllowlist`, and `Rotate` (T293, context
//! `ferrogate-rotate-v1`), each with its own context, document type, size
//! bound and rate limiter.
//!
//! [`authenticate`] runs the checks in a fixed order and stops at the first
//! failure:
//!
//! 1. the proof is present and every field is within its size bound;
//! 2. the SVID was issued by this CMIS, is currently valid, names a host and
//!    is not on the revocation working set (by SVID digest or host id);
//! 3. `base64url(SHA-256(sep_pub))` equals the SVID's `cnf.jkt`;
//! 4. the signature verifies under `sep_pub` over `context ‖ doc`;
//! 5. the document decodes (strict, versioned);
//! 6. the document names the SVID's host UUID;
//! 7. `|issued_at − now| ≤ 300 s`;
//! 8. the caller's own binding check (for `AppendAuditEvent`: the event bytes
//!    hash to the signed digest);
//! 9. the `(host_uuid, nonce)` pair was not seen in the last 600 s;
//! 10. the host is within the RPC's rate limit;
//! 11. the nonce is recorded (atomically, so a concurrent duplicate loses).
//!
//! Every authentication failure answers `UNAUTHENTICATED (host_auth_failed)`
//! — one code, so a prober learns nothing about which check tripped — except
//! a document naming another host (`PERMISSION_DENIED (host_mismatch)`), an
//! authenticated but malformed document (`INVALID_ARGUMENT` with the
//! document's reason code and, when known, the `x-ferrogate-field` it names)
//! and the rate limit (`RESOURCE_EXHAUSTED (rate_limited)` with
//! `retry-after`). The precise reason is logged, never returned (NRM §5.3.5).
//!
//! The replay cache and the rate limiters are **per node**, like the
//! revocation working set they sit beside: a cluster of N nodes admits each
//! nonce at most once per node and up to N times the per-host rate.

use std::collections::{HashMap, HashSet, VecDeque};

use base64::Engine as _;
use parking_lot::Mutex;
use sha2::{Digest, Sha256, Sha384};
use tonic::Status;

use ferro_crypto::composite::CompositeSignature;
use ferro_proto::v1::HostCallAuth;
use ferro_svid::app_docs::AppDocError;
use ferro_svid::host_call::{HostCallDoc, HostCallDocError, NONCE_LEN};

use crate::state::CmisState;

/// Maximum distance between a document's `issued_at` and the CMIS clock.
pub const MAX_SKEW_SECS: i64 = 300;
/// How long a `(host_uuid, nonce)` pair is remembered. Covers the whole
/// window in which a document stays acceptable (`issued_at` up to
/// [`MAX_SKEW_SECS`] in the future, then [`MAX_SKEW_SECS`] of age).
pub const REPLAY_TTL_SECS: i64 = 2 * MAX_SKEW_SECS;
/// Default replay-cache capacity (entries, per node).
pub const DEFAULT_REPLAY_CAPACITY: usize = 262_144;
/// Default `AppendAuditEvent` budget per host per minute.
pub const DEFAULT_AUDIT_FORWARD_PER_MIN: u32 = 600;
/// Upper bound on `CMIS_AUDIT_FORWARD_MAX_PER_MIN`.
pub const MAX_AUDIT_FORWARD_PER_MIN: u32 = 60_000;
/// Default `SubmitAppRequest` budget per host per hour (F19 §7.4).
pub const DEFAULT_APP_SUBMIT_PER_HOUR: u32 = 30;
/// Default `GetAppRequestStatus` budget per host per hour (F19 §7.4).
pub const DEFAULT_APP_STATUS_PER_HOUR: u32 = 60;
/// Default minimum seconds between two `SyncAllowlist` calls of one host
/// (`CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS`, F19 §6.3).
pub const DEFAULT_SYNC_MIN_INTERVAL_SECS: u32 = 30;
/// Upper bound on the per-hour app budgets.
pub const MAX_APP_PER_HOUR: u32 = 100_000;
/// Default `Rotate` budget per host per hour (`CMIS_ROTATE_MAX_PER_HOUR`,
/// T293). A healthy host renews about once per SVID lifetime; the budget
/// only leaves room for retries.
pub const DEFAULT_ROTATE_PER_HOUR: u32 = 6;
/// Upper bound on `CMIS_ROTATE_MAX_PER_HOUR`.
pub const MAX_ROTATE_PER_HOUR: u32 = 3600;
/// Upper bound on `CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS`.
pub const MAX_SYNC_MIN_INTERVAL_SECS: u32 = 3600;

/// The SVID tier of a host with the software host-key profile (F15/F16);
/// every other host attested with a TPM.
pub const TIER_HOST_KEY: &str = "host-key";
/// The SVID tier of a TPM-attested host.
pub const TIER_TPM: &str = "tpm";

/// Size bound on `HostCallAuth.svid_jws`.
pub const MAX_SVID_JWS_BYTES: usize = 16 * 1024;
/// Size bound on `HostCallAuth.sep_pub` (a P-256 SPKI is 91 bytes).
pub const MAX_SEP_PUB_BYTES: usize = 256;
/// Size bound on `HostCallAuth.sig` (a DER P-256 signature is at most 72).
pub const MAX_SIG_BYTES: usize = 80;

/// Host-call settings (`CMIS_AUDIT_FORWARD_MAX_PER_MIN`,
/// `CMIS_APP_SUBMIT_MAX_PER_HOUR`, `CMIS_APP_STATUS_MAX_PER_HOUR`,
/// `CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS`, `CMIS_ROTATE_MAX_PER_HOUR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCallConfig {
    /// `AppendAuditEvent` calls each host may make per minute (token bucket
    /// with a burst of one minute's budget).
    pub audit_forward_per_min: u32,
    /// `SubmitAppRequest` calls each host may make per hour (a retry of an
    /// already recorded request is answered before the budget is spent).
    pub app_submit_per_hour: u32,
    /// `GetAppRequestStatus` calls each host may make per hour.
    pub app_status_per_hour: u32,
    /// Minimum seconds between two `SyncAllowlist` calls of one host.
    pub sync_min_interval_secs: u32,
    /// `Rotate` calls each host may make per hour (T293). Every
    /// authenticated call spends one, refused or not.
    pub rotate_per_hour: u32,
    /// Replay-cache capacity.
    pub replay_capacity: usize,
}

impl Default for HostCallConfig {
    fn default() -> Self {
        Self {
            audit_forward_per_min: DEFAULT_AUDIT_FORWARD_PER_MIN,
            app_submit_per_hour: DEFAULT_APP_SUBMIT_PER_HOUR,
            app_status_per_hour: DEFAULT_APP_STATUS_PER_HOUR,
            sync_min_interval_secs: DEFAULT_SYNC_MIN_INTERVAL_SECS,
            rotate_per_hour: DEFAULT_ROTATE_PER_HOUR,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
        }
    }
}

/// Parse a positive integer setting; zero and garbage are errors, values
/// above `max` are capped (with a warning).
fn positive(
    get: &impl Fn(&str) -> Option<String>,
    var: &str,
    max: u32,
) -> anyhow::Result<Option<u32>> {
    let Some(v) = get(var) else {
        return Ok(None);
    };
    let n: u32 = v
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("{var}: not a positive integer: {v:?}"))?;
    if n == 0 {
        anyhow::bail!("{var}: must be at least 1");
    }
    if n > max {
        tracing::warn!(var, value = n, max, "capped to the maximum");
    }
    Ok(Some(n.min(max)))
}

impl HostCallConfig {
    /// Read the configuration from the process environment.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    /// Read the configuration through `get` (testable form of
    /// [`Self::from_env`]). A malformed or zero value is an error, never
    /// silently replaced; a value above [`MAX_AUDIT_FORWARD_PER_MIN`] is
    /// capped.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut c = Self::default();
        if let Some(n) = positive(
            &get,
            "CMIS_AUDIT_FORWARD_MAX_PER_MIN",
            MAX_AUDIT_FORWARD_PER_MIN,
        )? {
            c.audit_forward_per_min = n;
        }
        if let Some(n) = positive(&get, "CMIS_APP_SUBMIT_MAX_PER_HOUR", MAX_APP_PER_HOUR)? {
            c.app_submit_per_hour = n;
        }
        if let Some(n) = positive(&get, "CMIS_APP_STATUS_MAX_PER_HOUR", MAX_APP_PER_HOUR)? {
            c.app_status_per_hour = n;
        }
        if let Some(n) = positive(
            &get,
            "CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS",
            MAX_SYNC_MIN_INTERVAL_SECS,
        )? {
            c.sync_min_interval_secs = n;
        }
        if let Some(n) = positive(&get, "CMIS_ROTATE_MAX_PER_HOUR", MAX_ROTATE_PER_HOUR)? {
            c.rotate_per_hour = n;
        }
        Ok(c)
    }
}

/// The per-node mutable state of host-call authentication: the nonce replay
/// cache and the per-RPC rate limiters. Owned by [`CmisState`].
#[derive(Debug)]
pub struct HostCallGuard {
    replay: Mutex<ReplayCache>,
    audit_forward: HostRateLimiter,
    app_submit: HostRateLimiter,
    app_status: HostRateLimiter,
    allowlist_sync: HostRateLimiter,
    rotate: HostRateLimiter,
}

impl HostCallGuard {
    /// Fresh guard state for `cfg`.
    #[must_use]
    pub fn new(cfg: HostCallConfig) -> Self {
        Self {
            replay: Mutex::new(ReplayCache::new(cfg.replay_capacity)),
            audit_forward: HostRateLimiter::per_minute(cfg.audit_forward_per_min),
            app_submit: HostRateLimiter::per_hour(cfg.app_submit_per_hour),
            app_status: HostRateLimiter::per_hour(cfg.app_status_per_hour),
            allowlist_sync: HostRateLimiter::new(1, cfg.sync_min_interval_secs),
            rotate: HostRateLimiter::per_hour(cfg.rotate_per_hour),
        }
    }

    /// The `Rotate` rate limiter (T293).
    #[must_use]
    pub fn rotate_limiter(&self) -> &HostRateLimiter {
        &self.rotate
    }

    /// The `AppendAuditEvent` rate limiter.
    #[must_use]
    pub fn audit_forward_limiter(&self) -> &HostRateLimiter {
        &self.audit_forward
    }

    /// The `SubmitAppRequest` rate limiter (F19 §7.4).
    #[must_use]
    pub fn app_submit_limiter(&self) -> &HostRateLimiter {
        &self.app_submit
    }

    /// The `GetAppRequestStatus` rate limiter (F19 §7.4).
    #[must_use]
    pub fn app_status_limiter(&self) -> &HostRateLimiter {
        &self.app_status
    }

    /// The `SyncAllowlist` minimum-interval limiter (F19 §6.3).
    #[must_use]
    pub fn allowlist_sync_limiter(&self) -> &HostRateLimiter {
        &self.allowlist_sync
    }
}

/// The verified identity facts of a host SVID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSvid {
    /// The host UUID (last path segment of the SPIFFE id).
    pub host_uuid: String,
    /// The SVID's `cnf.jkt` (base64url SHA-256 of the machine key SPKI).
    pub cnf_jkt: String,
    /// The SVID subject SPIFFE id.
    pub spiffe_id: String,
    /// The attestation tier: [`TIER_HOST_KEY`] or [`TIER_TPM`].
    pub tier: &'static str,
}

/// A host whose call was authenticated by [`authenticate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHost {
    /// The host UUID (equal in the SVID and the signed document).
    pub host_uuid: String,
    /// The SVID subject SPIFFE id.
    pub spiffe_id: String,
    /// The attestation tier of the SVID ([`TIER_HOST_KEY`] or [`TIER_TPM`]).
    pub tier: &'static str,
}

/// A host call document that decoded but failed validation: the stable
/// reason code (`x-ferrogate-reason`) and, when known, the field it names
/// (`x-ferrogate-field`). The `Display` text can quote the document (paths,
/// user names): log only [`DocError::reason`] and [`DocError::field`].
pub trait DocError: std::fmt::Display {
    /// The stable reason code returned to the (authenticated) host.
    fn reason(&self) -> &'static str;
    /// The failing field, if one was named.
    fn field(&self) -> Option<&'static str>;
}

impl DocError for HostCallDocError {
    fn reason(&self) -> &'static str {
        "malformed_doc"
    }

    fn field(&self) -> Option<&'static str> {
        None
    }
}

impl DocError for AppDocError {
    fn reason(&self) -> &'static str {
        AppDocError::reason(self)
    }

    fn field(&self) -> Option<&'static str> {
        AppDocError::field(self)
    }
}

/// `INVALID_ARGUMENT (reason)` with `x-ferrogate-field: field` when named.
#[must_use]
pub fn invalid_field(reason: &'static str, field: Option<&str>) -> Status {
    let mut s = Status::invalid_argument(reason);
    if let Some(v) = field.and_then(|f| f.parse().ok()) {
        s.metadata_mut().insert("x-ferrogate-field", v);
    }
    s
}

/// `RESOURCE_EXHAUSTED (reason)` with `retry-after: wait` seconds.
#[must_use]
pub fn exhausted(reason: &'static str, wait: u64) -> Status {
    let mut s = Status::resource_exhausted(reason);
    if let Ok(v) = wait.max(1).to_string().parse() {
        s.metadata_mut().insert("retry-after", v);
    }
    s
}

/// One host call to authenticate.
pub struct HostCall<'a, D, E> {
    /// The proof from the request (`None` when the client sent none).
    pub auth: Option<&'a HostCallAuth>,
    /// The RPC's signing context, e.g.
    /// [`ferro_svid::host_call::AUDIT_FORWARD_CONTEXT`].
    pub context: &'static [u8],
    /// The exact document bytes the host signed.
    pub doc: &'a [u8],
    /// Size bound on `doc`, checked before any parsing or crypto.
    pub max_doc_bytes: usize,
    /// Strict decoder of the RPC's document type.
    pub decode: fn(&[u8]) -> Result<D, E>,
    /// RPC-specific binding between the document and the rest of the request
    /// (checked before the nonce is consumed). `false` is an authentication
    /// failure.
    pub bind: &'a dyn Fn(&D) -> bool,
    /// The RPC's per-host rate limiter, if it has one.
    pub limiter: Option<&'a HostRateLimiter>,
}

/// The single host-authentication failure answer.
fn host_auth_failed(reason: &'static str, host_uuid: Option<&str>) -> Status {
    tracing::warn!(
        event = "host_auth.failed",
        reason,
        host_uuid = host_uuid.unwrap_or("-"),
        "host call authentication failed"
    );
    Status::unauthenticated("host_auth_failed")
}

fn sha384_hex(bytes: &[u8]) -> String {
    hex::encode(Sha384::digest(bytes))
}

/// Verify that `svid_jws` was issued by this CMIS, is valid at `now`, names a
/// host and is not revoked. Every failure is `UNAUTHENTICATED
/// (host_auth_failed)`; the reason is logged.
///
/// Verifies only against the current issuer key: a host holding a
/// rotated/cross-signed SVID re-attests first.
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
pub fn verify_host_svid(state: &CmisState, svid_jws: &str, now: i64) -> Result<HostSvid, Status> {
    let decoded = ferro_svid::envelope::decode(svid_jws)
        .map_err(|_| host_auth_failed("svid_malformed", None))?;
    let sig = CompositeSignature::from_concat_bytes(&decoded.signature)
        .map_err(|_| host_auth_failed("svid_signature_malformed", None))?;
    state
        .issuer
        .public_key()
        .verify(
            ferro_svid::SVID_SIGNING_CONTEXT,
            decoded.signing_input.as_bytes(),
            &sig,
        )
        .map_err(|_| host_auth_failed("svid_not_issued_here", None))?;
    let claims = decoded.claims;
    if now < claims.nbf || now > claims.exp {
        return Err(host_auth_failed("svid_not_valid_now", None));
    }
    let host_uuid = claims
        .sub
        .rsplit_once("/host/")
        .map(|(_, u)| u.to_string())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| host_auth_failed("svid_not_a_host", None))?;
    if state.is_revoked(&claims.sub, &sha384_hex(svid_jws.as_bytes())) {
        return Err(host_auth_failed("svid_revoked", Some(&host_uuid)));
    }
    let tier = if claims.attest.policy_id == TIER_HOST_KEY {
        TIER_HOST_KEY
    } else {
        TIER_TPM
    };
    Ok(HostSvid {
        host_uuid,
        cnf_jkt: claims.cnf.jkt,
        spiffe_id: claims.sub,
        tier,
    })
}

/// Authenticate one host call; see the module docs for the order of checks.
/// On success the nonce (if any) is consumed and one unit of the rate limit
/// is spent.
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
pub fn authenticate<D: HostCallDoc, E: DocError>(
    state: &CmisState,
    call: HostCall<'_, D, E>,
    now: i64,
) -> Result<(AuthenticatedHost, D), Status> {
    // 1. Presence and size bounds, before any parsing or crypto.
    let auth = call
        .auth
        .ok_or_else(|| host_auth_failed("proof_missing", None))?;
    if auth.svid_jws.is_empty()
        || auth.svid_jws.len() > MAX_SVID_JWS_BYTES
        || auth.sep_pub.is_empty()
        || auth.sep_pub.len() > MAX_SEP_PUB_BYTES
        || auth.sig.is_empty()
        || auth.sig.len() > MAX_SIG_BYTES
        || call.doc.is_empty()
        || call.doc.len() > call.max_doc_bytes
    {
        return Err(host_auth_failed("proof_field_size", None));
    }

    // 2. The SVID: issued here, valid now, a host, not revoked.
    let svid = verify_host_svid(state, &auth.svid_jws, now)?;
    let host = Some(svid.host_uuid.as_str());

    // 3. The presented machine key is the one the SVID is bound to.
    let jkt =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&auth.sep_pub));
    if jkt != svid.cnf_jkt {
        return Err(host_auth_failed("key_not_bound_to_svid", host));
    }

    // 4. The signature over `context ‖ doc`.
    let input = ferro_svid::host_call::signing_input(call.context, call.doc);
    ferro_sep::verify_p256(&auth.sep_pub, &input, &auth.sig)
        .map_err(|_| host_auth_failed("bad_signature", host))?;

    // 5. The document (authenticated from here on). Only the stable codes
    // are logged: the decoder's message can quote the document's strings
    // (an unknown key, an unknown variant), and the document carries paths
    // and user names (F19 §8 "I", §10).
    let doc = (call.decode)(call.doc).map_err(|e| {
        tracing::warn!(
            event = "host_auth.malformed_doc",
            reason = e.reason(),
            field = e.field().unwrap_or(""),
            host_uuid = %svid.host_uuid,
            "signed host document did not decode"
        );
        invalid_field(e.reason(), e.field())
    })?;

    // 6. The document speaks for the SVID's host.
    if doc.host_uuid() != svid.host_uuid {
        tracing::warn!(
            event = "host_auth.host_mismatch",
            host_uuid = %svid.host_uuid,
            "signed document names another host"
        );
        return Err(Status::permission_denied("host_mismatch"));
    }

    // 7. Freshness.
    if doc.issued_at().abs_diff(now) > MAX_SKEW_SECS.unsigned_abs() {
        return Err(host_auth_failed("stale_or_future", host));
    }

    // 8. RPC-specific binding.
    if !(call.bind)(&doc) {
        return Err(host_auth_failed("binding_mismatch", host));
    }

    // 9. Replays are dropped without spending the host's budget.
    let nonce = doc.nonce().copied();
    if let Some(n) = &nonce {
        if state
            .host_calls
            .replay
            .lock()
            .seen(&svid.host_uuid, n, doc.issued_at(), now)
        {
            return Err(host_auth_failed("replayed_nonce", host));
        }
    }

    // 10. Per-host rate limit.
    if let Some(limiter) = call.limiter {
        if let Err(wait) = limiter.check(&svid.host_uuid, now) {
            tracing::warn!(
                event = "host_auth.rate_limited",
                host_uuid = %svid.host_uuid,
                retry_after = wait,
                "host call over its rate limit"
            );
            return Err(exhausted("rate_limited", wait));
        }
    }

    // 11. Consume the nonce; a concurrent duplicate that passed step 9 loses
    //     here.
    if let Some(n) = nonce {
        if !state
            .host_calls
            .replay
            .lock()
            .insert(&svid.host_uuid, n, doc.issued_at(), now)
        {
            return Err(host_auth_failed("replayed_nonce", host));
        }
    }

    Ok((
        AuthenticatedHost {
            host_uuid: svid.host_uuid,
            spiffe_id: svid.spiffe_id,
            tier: svid.tier,
        },
        doc,
    ))
}

type ReplayKey = (String, [u8; NONCE_LEN]);

/// Bounded `(host_uuid, nonce)` replay cache.
///
/// Every entry lives [`REPLAY_TTL_SECS`] from insertion, so insertion order is
/// expiry order and a queue suffices. When the cache is full of live entries
/// the oldest is evicted and the **floor** rises to its `issued_at`: any
/// document issued at or before the floor is then treated as a possible
/// replay. Replay protection therefore stays exact under eviction; the cost
/// of an overflow is refusing some older (but still fresh) documents, never
/// accepting a replay.
#[derive(Debug)]
struct ReplayCache {
    order: VecDeque<(ReplayKey, i64, i64)>,
    seen: HashSet<ReplayKey>,
    floor: i64,
    capacity: usize,
}

impl ReplayCache {
    fn new(capacity: usize) -> Self {
        Self {
            order: VecDeque::new(),
            seen: HashSet::new(),
            floor: i64::MIN,
            capacity: capacity.max(1),
        }
    }

    fn prune(&mut self, now: i64) {
        while let Some((key, expires_at, _)) = self.order.front() {
            if *expires_at > now {
                break;
            }
            self.seen.remove(key);
            self.order.pop_front();
        }
    }

    fn seen(&mut self, host: &str, nonce: &[u8; NONCE_LEN], issued_at: i64, now: i64) -> bool {
        self.prune(now);
        issued_at <= self.floor || self.seen.contains(&(host.to_string(), *nonce))
    }

    /// Record the pair; `false` if it was already present (a replay).
    fn insert(&mut self, host: &str, nonce: [u8; NONCE_LEN], issued_at: i64, now: i64) -> bool {
        self.prune(now);
        if issued_at <= self.floor {
            return false;
        }
        let key = (host.to_string(), nonce);
        if self.seen.contains(&key) {
            return false;
        }
        while self.order.len() >= self.capacity {
            if let Some((old, _, old_issued_at)) = self.order.pop_front() {
                self.seen.remove(&old);
                self.floor = self.floor.max(old_issued_at);
            }
        }
        self.seen.insert(key.clone());
        self.order
            .push_back((key, now.saturating_add(REPLAY_TTL_SECS), issued_at));
        true
    }
}

/// Per-host token bucket: a burst of one period's budget, refilled
/// continuously. Keyed by the **authenticated** host UUID, so one host cannot
/// spend another's budget.
#[derive(Debug)]
pub struct HostRateLimiter {
    /// Bucket size in units (`cost` per call).
    capacity: u64,
    /// Refill in units per second (exact: `calls` calls per period).
    refill_per_sec: u64,
    /// Units one call costs: the period in seconds, so one call's worth
    /// accrues every `period / calls` seconds with no rounding.
    cost: u64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    units: u64,
    last: i64,
}

/// Above this many tracked hosts, idle (full) buckets are dropped.
const MAX_TRACKED_HOSTS: usize = 65_536;

impl HostRateLimiter {
    /// A limiter allowing `calls` calls per host per `period_secs` (both at
    /// least 1), with a burst of the whole budget.
    #[must_use]
    pub fn new(calls: u32, period_secs: u32) -> Self {
        let calls = u64::from(calls.max(1));
        let period = u64::from(period_secs.max(1));
        Self {
            capacity: calls * period,
            refill_per_sec: calls,
            cost: period,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// A limiter allowing `per_min` calls per host per minute (minimum 1).
    #[must_use]
    pub fn per_minute(per_min: u32) -> Self {
        Self::new(per_min, 60)
    }

    /// A limiter allowing `per_hour` calls per host per hour (minimum 1).
    #[must_use]
    pub fn per_hour(per_hour: u32) -> Self {
        Self::new(per_hour, 3600)
    }

    fn refilled(&self, b: Bucket, now: i64) -> u64 {
        let elapsed = u64::try_from(now.saturating_sub(b.last)).unwrap_or(0);
        b.units
            .saturating_add(elapsed.saturating_mul(self.refill_per_sec))
            .min(self.capacity)
    }

    /// Spend one call for `host` at `now`. `Err(secs)` is the wait before
    /// the next call would be admitted (at least 1).
    pub fn check(&self, host: &str, now: i64) -> Result<(), u64> {
        let mut buckets = self.buckets.lock();
        if buckets.len() >= MAX_TRACKED_HOSTS && !buckets.contains_key(host) {
            let cap = self.capacity;
            buckets.retain(|_, b| self.refilled(*b, now) < cap);
        }
        let b = buckets.entry(host.to_string()).or_insert(Bucket {
            units: self.capacity,
            last: now,
        });
        let units = self.refilled(*b, now);
        b.last = now.max(b.last);
        if units >= self.cost {
            b.units = units - self.cost;
            Ok(())
        } else {
            b.units = units;
            Err((self.cost - units).div_ceil(self.refill_per_sec).max(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(vars: &[(&str, &str)]) -> anyhow::Result<HostCallConfig> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        HostCallConfig::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn config_defaults_and_env() {
        assert_eq!(cfg(&[]).unwrap(), HostCallConfig::default());
        assert_eq!(cfg(&[]).unwrap().audit_forward_per_min, 600);
        let c = cfg(&[("CMIS_AUDIT_FORWARD_MAX_PER_MIN", "120")]).unwrap();
        assert_eq!(c.audit_forward_per_min, 120);
        let c = cfg(&[("CMIS_AUDIT_FORWARD_MAX_PER_MIN", "999999")]).unwrap();
        assert_eq!(c.audit_forward_per_min, MAX_AUDIT_FORWARD_PER_MIN);
        assert!(cfg(&[("CMIS_AUDIT_FORWARD_MAX_PER_MIN", "0")]).is_err());
        assert!(cfg(&[("CMIS_AUDIT_FORWARD_MAX_PER_MIN", "-5")]).is_err());
        assert!(cfg(&[("CMIS_AUDIT_FORWARD_MAX_PER_MIN", "lots")]).is_err());
        let c = cfg(&[
            ("CMIS_APP_SUBMIT_MAX_PER_HOUR", "5"),
            ("CMIS_APP_STATUS_MAX_PER_HOUR", "7"),
            ("CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS", "99999"),
        ])
        .unwrap();
        assert_eq!(
            (
                c.app_submit_per_hour,
                c.app_status_per_hour,
                c.sync_min_interval_secs
            ),
            (5, 7, MAX_SYNC_MIN_INTERVAL_SECS)
        );
        assert!(cfg(&[("CMIS_APP_SUBMIT_MAX_PER_HOUR", "0")]).is_err());
        assert!(cfg(&[("CMIS_ALLOWLIST_SYNC_MIN_INTERVAL_SECS", "x")]).is_err());
    }

    #[test]
    fn from_lookup_reads_rotate_limit() {
        assert_eq!(cfg(&[]).unwrap().rotate_per_hour, DEFAULT_ROTATE_PER_HOUR);
        assert_eq!(DEFAULT_ROTATE_PER_HOUR, 6);
        let c = cfg(&[("CMIS_ROTATE_MAX_PER_HOUR", "2")]).unwrap();
        assert_eq!(c.rotate_per_hour, 2);
        let c = cfg(&[("CMIS_ROTATE_MAX_PER_HOUR", "999999")]).unwrap();
        assert_eq!(c.rotate_per_hour, MAX_ROTATE_PER_HOUR);
        assert!(cfg(&[("CMIS_ROTATE_MAX_PER_HOUR", "0")]).is_err());
        assert!(cfg(&[("CMIS_ROTATE_MAX_PER_HOUR", "-1")]).is_err());
        assert!(cfg(&[("CMIS_ROTATE_MAX_PER_HOUR", "often")]).is_err());
        // The guard enforces it per host and hour.
        let guard = HostCallGuard::new(cfg(&[("CMIS_ROTATE_MAX_PER_HOUR", "1")]).unwrap());
        assert!(guard.rotate_limiter().check("h", 0).is_ok());
        assert_eq!(guard.rotate_limiter().check("h", 0), Err(3600));
        assert!(guard.rotate_limiter().check("other", 0).is_ok());
    }

    #[test]
    fn a_minimum_interval_limiter_admits_one_call_per_interval() {
        let l = HostRateLimiter::new(1, 30);
        assert!(l.check("h", 1_000).is_ok());
        assert_eq!(l.check("h", 1_010), Err(20));
        assert!(l.check("h", 1_030).is_ok());
        let hourly = HostRateLimiter::per_hour(2);
        assert!(hourly.check("h", 0).is_ok());
        assert!(hourly.check("h", 0).is_ok());
        assert_eq!(hourly.check("h", 0), Err(1800));
    }

    #[test]
    fn the_rate_limiter_allows_a_burst_then_refills() {
        let l = HostRateLimiter::per_minute(3);
        let t = 1_000;
        assert!(l.check("h", t).is_ok());
        assert!(l.check("h", t).is_ok());
        assert!(l.check("h", t).is_ok());
        let wait = l.check("h", t).unwrap_err();
        assert_eq!(wait, 20, "3 per minute refills one call every 20 s");
        // Other hosts have their own bucket.
        assert!(l.check("other", t).is_ok());
        // A refused call spends nothing; one call is back after the wait.
        assert!(l.check("h", t + 19).is_err());
        assert!(l.check("h", t + 20).is_ok());
        assert!(l.check("h", t + 20).is_err());
        // Long idle refills to the burst size, not beyond it.
        let later = t + 3600;
        for _ in 0..3 {
            assert!(l.check("h", later).is_ok());
        }
        assert!(l.check("h", later).is_err());
    }

    #[test]
    fn a_clock_step_backwards_does_not_refill() {
        let l = HostRateLimiter::per_minute(1);
        assert!(l.check("h", 1_000).is_ok());
        assert!(l.check("h", 900).is_err());
        assert!(l.check("h", 1_000).is_err());
        assert!(l.check("h", 1_060).is_ok());
    }

    #[test]
    fn the_replay_cache_remembers_nonces_until_they_expire() {
        let mut c = ReplayCache::new(16);
        let n = [1u8; 16];
        let t = 10_000;
        assert!(!c.seen("h", &n, t, t));
        assert!(c.insert("h", n, t, t));
        assert!(c.seen("h", &n, t, t + 1));
        assert!(!c.insert("h", n, t, t + 1), "second insert is a replay");
        assert!(!c.seen("other", &n, t, t + 1), "keyed by host too");
        // Still remembered at the end of the window, gone after it.
        assert!(c.seen("h", &n, t, t + REPLAY_TTL_SECS - 1));
        assert!(!c.seen("h", &n, t, t + REPLAY_TTL_SECS));
    }

    #[test]
    fn overflow_raises_the_floor_instead_of_forgetting_replays() {
        let mut c = ReplayCache::new(2);
        let t = 10_000;
        assert!(c.insert("h", [1; 16], t - 10, t));
        assert!(c.insert("h", [2; 16], t - 5, t));
        // Full: the oldest entry is evicted and the floor rises to t-10.
        assert!(c.insert("h", [3; 16], t, t));
        assert_eq!(c.order.len(), 2);
        // A replay of the evicted nonce is still refused.
        assert!(c.seen("h", &[1; 16], t - 10, t));
        assert!(!c.insert("h", [1; 16], t - 10, t));
        // Newer documents are unaffected.
        assert!(!c.seen("h", &[4; 16], t - 9, t));
    }
}
