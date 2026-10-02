//! The per-environment status model behind the status endpoint (feature F18).
//!
//! The daemon owns one [`StatusHandle`] per environment it knows about and
//! updates it at the points where the inputs change — attestation start,
//! success and (classified) failure, the CMIS node selected, the CRL cache,
//! the allowlist load/reload, the X.509-SVID store backend. A
//! [`StatusRegistry`] groups the handles for the endpoint.
//!
//! The [`AgentState`] is *derived* on demand ([`derive`]) from those inputs and
//! the current time, so time-driven transitions (a CRL ageing past 5 minutes,
//! an SVID passing its renewal point) need no timer. The function is pure and
//! unit-tested for every state the daemon can reach.
//!
//! **Nothing sensitive is stored here.** A handle holds identifiers and
//! timestamps only — never the SVID, its key, the CMIS pin, or allowlist
//! entries — so a snapshot cannot leak them, and [`ErrorSummary`] messages are
//! fixed strings chosen from a closed set, never remote or caller text.

use std::sync::{Arc, Mutex};

use mia_status_proto::{
    error_codes, AgentState, AllowlistState, AttestBackend, ErrorSummary, StatusSnapshot,
    StoreBackend, SvidSummary,
};

use crate::helper::allowlist::AllowlistLoad;
use crate::helper::crl::{CrlCache, CRL_FRESHNESS_LEEWAY_SECS};

/// The label the daemon uses for the default (`mia.toml`) environment.
pub const DEFAULT_ENVIRONMENT_LABEL: &str = "default";

/// Longest CMIS node string kept (`host:port`).
const MAX_NODE_LEN: usize = 255;

/// Why the last attestation attempt failed — a closed classification of the
/// errors the bootstrap paths see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestFailure {
    /// CMIS could not be reached (DNS, TCP, TLS other than a pin mismatch,
    /// RPC unavailable / timed out).
    CmisUnreachable,
    /// CMIS answered and refused the host (`PermissionDenied`: not enrolled,
    /// key rebind, not pre-registered — CMIS deliberately does not say which).
    NotEnrolled,
    /// The CMIS certificate did not match the configured SPKI pin.
    PinMismatch,
    /// The TPM-class backend is selected but unusable (no TPM, no EK cert,
    /// device busy, evidence failure, backend not built in).
    TpmUnavailable,
    /// Anything else (protocol error, local key problem).
    Other,
}

/// The text the transport layer puts on an SPKI pin mismatch
/// (`ferro_crypto::pin`).
const PIN_MISMATCH_MARKER: &str = "SPKI pin mismatch";

impl AttestFailure {
    /// Classify a failure to dial CMIS ([`crate::endpoint::CmisResolver::connect`]).
    #[must_use]
    pub fn from_connect_error(e: &anyhow::Error) -> Self {
        if e.chain()
            .any(|c| c.to_string().contains(PIN_MISMATCH_MARKER))
            || format!("{e:?}").contains(PIN_MISMATCH_MARKER)
        {
            Self::PinMismatch
        } else {
            Self::CmisUnreachable
        }
    }

    /// Classify a failed attestation handshake. `tpm_class` is true for the
    /// TPM and virtual-TPM backends, where an evidence error is a TPM problem.
    #[must_use]
    pub fn from_attest_error(e: &crate::client::AttestClientError, tpm_class: bool) -> Self {
        use crate::client::AttestClientError as E;
        if format!("{e:?}").contains(PIN_MISMATCH_MARKER) {
            return Self::PinMismatch;
        }
        match e {
            E::Transport(status) => match status.code() {
                tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => Self::NotEnrolled,
                tonic::Code::Unavailable
                | tonic::Code::DeadlineExceeded
                | tonic::Code::Cancelled
                | tonic::Code::Unknown => Self::CmisUnreachable,
                _ => Self::Other,
            },
            E::Evidence(_) if tpm_class => Self::TpmUnavailable,
            _ => Self::Other,
        }
    }
}

/// Where attestation stands for one environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestPhase {
    /// Nothing attempted yet (the daemon is starting).
    Starting,
    /// An attempt is in flight.
    Attesting,
    /// The last attempt failed.
    Failed(AttestFailure),
    /// An attempt succeeded (see the SVID for its lifetime).
    Attested,
}

/// The inputs [`derive`] reads, gathered from a [`StatusHandle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// `None` when the environment is fully configured; otherwise the
    /// [`error_codes`] value naming what is missing.
    pub not_configured: Option<&'static str>,
    /// Where attestation stands.
    pub phase: AttestPhase,
    /// The SVID held, if any.
    pub svid: Option<SvidSummary>,
    /// When the cached CRL was produced, if one is cached.
    pub crl_issued_at: Option<i64>,
    /// The allowlist's load outcome.
    pub allowlist: AllowlistLoad,
}

/// Derive the state (and the error behind it) from `obs` at time `now`.
///
/// Precedence: configuration first; then, without a valid SVID, the
/// attestation phase; with one, the minting gates in the order the helper API
/// applies them (CRL, allowlist) and finally the SVID's own renewal point.
#[must_use]
pub fn derive(obs: &Observed, now: i64) -> (AgentState, Option<ErrorSummary>) {
    if let Some(code) = obs.not_configured {
        return (AgentState::NotConfigured, Some(summary(code)));
    }
    let valid_svid = obs.svid.as_ref().filter(|s| now < s.not_after);
    let Some(svid) = valid_svid else {
        // An expired SVID only explains the state when nothing more specific
        // does: a failed re-attestation names the real cause (and recovery).
        if obs.svid.is_some() && matches!(obs.phase, AttestPhase::Attested | AttestPhase::Starting)
        {
            return (
                AgentState::SvidExpiring,
                Some(summary(error_codes::SVID_EXPIRED)),
            );
        }
        return match obs.phase {
            AttestPhase::Starting | AttestPhase::Attesting | AttestPhase::Attested => {
                (AgentState::Attesting, None)
            }
            AttestPhase::Failed(f) => failure_state(f),
        };
    };

    let crl_fresh = obs.crl_issued_at.is_some_and(|issued| {
        let age = now - issued;
        (-CRL_FRESHNESS_LEEWAY_SECS..=ferro_svid::CRL_MAX_AGE_SECS).contains(&age)
    });
    if !crl_fresh {
        return (AgentState::CrlStale, Some(summary(error_codes::CRL_STALE)));
    }
    match obs.allowlist {
        AllowlistLoad::Missing => {
            return (
                AgentState::AllowlistMissing,
                Some(summary(error_codes::ALLOWLIST_MISSING)),
            );
        }
        AllowlistLoad::Invalid => {
            return (
                AgentState::AllowlistInvalid,
                Some(summary(error_codes::ALLOWLIST_INVALID)),
            );
        }
        AllowlistLoad::Loaded { not_after, .. } if now >= not_after => {
            return (
                AgentState::AllowlistInvalid,
                Some(summary(error_codes::ALLOWLIST_EXPIRED)),
            );
        }
        AllowlistLoad::Loaded { .. } => {}
    }
    if now >= svid.renew_at {
        return (
            AgentState::SvidExpiring,
            Some(summary(error_codes::SVID_RENEWAL_DUE)),
        );
    }
    (AgentState::Healthy, None)
}

/// The state and error for a failed attestation.
fn failure_state(f: AttestFailure) -> (AgentState, Option<ErrorSummary>) {
    let (state, code) = match f {
        AttestFailure::CmisUnreachable => {
            (AgentState::CmisUnreachable, error_codes::CMIS_UNREACHABLE)
        }
        AttestFailure::NotEnrolled => (AgentState::NotEnrolled, error_codes::HOST_REJECTED),
        AttestFailure::PinMismatch => (AgentState::PinMismatch, error_codes::PIN_MISMATCH),
        AttestFailure::TpmUnavailable => (AgentState::TpmUnavailable, error_codes::TPM_UNAVAILABLE),
        // Retrying forever, like an unreachable CMIS; the code says why.
        AttestFailure::Other => (AgentState::CmisUnreachable, error_codes::ATTESTATION_FAILED),
    };
    (state, Some(summary(code)))
}

/// The fixed message for an [`error_codes`] value. Never interpolates
/// anything: the status payload must not carry remote or caller text.
#[must_use]
pub fn message_for(code: &str) -> &'static str {
    match code {
        error_codes::CMIS_NOT_CONFIGURED => {
            "no CMIS source is configured (cmis.endpoint or cmis.srv)"
        }
        error_codes::CMIS_MISCONFIGURED => {
            "the CMIS configuration is unusable; check cmis.endpoint, cmis.srv and cmis.spki_pin"
        }
        error_codes::HELPER_NOT_CONFIGURED => "no helper socket is configured (helper.socket)",
        error_codes::CMIS_UNREACHABLE => "CMIS cannot be reached; the agent keeps retrying",
        error_codes::ATTESTATION_FAILED => "attestation failed; the agent keeps retrying",
        error_codes::HOST_REJECTED => {
            "CMIS refused this host; send its machine identifiers (mia machine-id) to an operator"
        }
        error_codes::PIN_MISMATCH => "the CMIS certificate does not match the configured SPKI pin",
        error_codes::TPM_UNAVAILABLE => "the selected TPM attestation backend is unavailable",
        error_codes::IMA_DISABLED => {
            "IMA appraisal is required but not enforced; the agent refuses to start"
        }
        error_codes::CRL_STALE => {
            "the cached CRL is missing or older than 5 minutes; token minting is refused"
        }
        error_codes::ALLOWLIST_MISSING => "no caller allowlist is loaded; callers are denied",
        error_codes::ALLOWLIST_INVALID => {
            "the caller allowlist failed verification; callers are denied"
        }
        error_codes::ALLOWLIST_EXPIRED => "the caller allowlist has expired; callers are denied",
        error_codes::SVID_RENEWAL_DUE => {
            "the host SVID is past its renewal point and has not been renewed"
        }
        error_codes::SVID_EXPIRED => "the host SVID has expired",
        error_codes::NOT_RUNNING => "the mia service is not running (no status endpoint)",
        _ => "unexpected condition",
    }
}

fn summary(code: &'static str) -> ErrorSummary {
    ErrorSummary {
        code: code.to_string(),
        message: message_for(code).to_string(),
    }
}

/// Map the configured backend onto the wire enum.
#[must_use]
pub fn wire_backend(b: crate::config::AttestBackend) -> AttestBackend {
    use crate::config::AttestBackend as C;
    match b {
        C::Auto => AttestBackend::Auto,
        C::Tpm => AttestBackend::Tpm,
        C::HostKey => AttestBackend::HostKey,
        C::VirtualTpm => AttestBackend::VirtualTpm,
    }
}

/// Reduce a dialed CMIS endpoint (`https://host:port[/...]`) to `host:port`,
/// bounded in length. Credentials in a URL authority (`user@`) are dropped.
#[must_use]
pub fn node_of(endpoint: &str) -> String {
    let rest = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    authority
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NODE_LEN)
        .collect()
}

struct EnvStatus {
    environment: Option<String>,
    not_configured: Option<&'static str>,
    attest_backend: AttestBackend,
    phase: AttestPhase,
    svid: Option<SvidSummary>,
    cmis_node: Option<String>,
    crl: Option<Arc<CrlCache>>,
    allowlist: AllowlistLoad,
    x509_store: Option<StoreBackend>,
    last_state: Option<AgentState>,
    since: i64,
}

/// One environment's live status. Cheap to clone; every update takes a short
/// lock and never logs while holding it.
#[derive(Clone)]
pub struct StatusHandle {
    inner: Arc<Mutex<EnvStatus>>,
}

impl std::fmt::Debug for StatusHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusHandle")
            .field("environment", &self.environment())
            .finish_non_exhaustive()
    }
}

impl StatusHandle {
    /// A fresh handle for the environment labelled `label` (`"default"` maps
    /// to the unnamed default environment), created at `now`.
    #[must_use]
    pub fn new(label: &str, now: i64) -> Self {
        let environment = (label != DEFAULT_ENVIRONMENT_LABEL).then(|| label.to_string());
        Self {
            inner: Arc::new(Mutex::new(EnvStatus {
                environment,
                not_configured: None,
                attest_backend: AttestBackend::Auto,
                phase: AttestPhase::Starting,
                svid: None,
                cmis_node: None,
                crl: None,
                allowlist: AllowlistLoad::Missing,
                x509_store: None,
                last_state: None,
                since: now,
            })),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut EnvStatus) -> R) -> R {
        // A poisoned lock means a panic mid-update; the data is still a
        // consistent set of plain values, so keep reporting.
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    /// The environment name (`None` for the default environment).
    #[must_use]
    pub fn environment(&self) -> Option<String> {
        self.with(|s| s.environment.clone())
    }

    /// Mark the environment unconfigured, naming what is missing with an
    /// [`error_codes`] value (`CMIS_NOT_CONFIGURED`, `CMIS_MISCONFIGURED`,
    /// `HELPER_NOT_CONFIGURED`).
    pub fn set_not_configured(&self, code: &'static str) {
        self.with(|s| s.not_configured = Some(code));
    }

    /// Record the backend actually used (after `auto` is resolved).
    pub fn set_attest_backend(&self, backend: crate::config::AttestBackend) {
        self.with(|s| s.attest_backend = wire_backend(backend));
    }

    /// An attestation attempt started.
    pub fn attest_started(&self) {
        self.with(|s| s.phase = AttestPhase::Attesting);
    }

    /// An attestation attempt failed for `why`.
    pub fn attest_failed(&self, why: AttestFailure) {
        self.with(|s| s.phase = AttestPhase::Failed(why));
    }

    /// An attestation attempt succeeded with an SVID for `spiffe_id` valid
    /// `issued_at..expires_at` (Unix seconds). The renewal point is the
    /// un-jittered 60% of the TTL.
    pub fn attest_succeeded(&self, spiffe_id: &str, issued_at: i64, expires_at: i64) {
        let renew_at = ferro_svid::rotation_at(issued_at, expires_at, 0.5);
        self.with(|s| {
            s.phase = AttestPhase::Attested;
            s.svid = Some(SvidSummary {
                spiffe_id: spiffe_id.chars().take(MAX_NODE_LEN * 2).collect(),
                not_after: expires_at,
                renew_at,
            });
        });
    }

    /// The CMIS node a dial selected (`https://host:port` or `host:port`).
    pub fn set_cmis_node(&self, endpoint: &str) {
        let node = node_of(endpoint);
        self.with(|s| s.cmis_node = Some(node));
    }

    /// The CRL cache whose freshness this environment's minting depends on.
    pub fn set_crl_cache(&self, cache: Arc<CrlCache>) {
        self.with(|s| s.crl = Some(cache));
    }

    /// The outcome of the latest allowlist load or reload.
    pub fn set_allowlist(&self, load: AllowlistLoad) {
        self.with(|s| s.allowlist = load);
    }

    /// The X.509-SVID store backend (a `credstore` sealer name). Unknown names
    /// are ignored.
    pub fn set_x509_store(&self, backend_name: &str) {
        if let Some(b) = StoreBackend::from_name(backend_name) {
            self.with(|s| s.x509_store = Some(b));
        }
    }

    /// The inputs [`derive`] needs, with the CRL age read from the cache.
    pub async fn observe(&self) -> Observed {
        let crl = self.with(|s| s.crl.clone());
        let crl_issued_at = match crl {
            Some(c) => c.issued_at().await,
            None => None,
        };
        self.with(|s| Observed {
            not_configured: s.not_configured,
            phase: s.phase,
            svid: s.svid.clone(),
            crl_issued_at,
            allowlist: s.allowlist,
        })
    }

    /// The snapshot at `now`. Records when the derived state was first
    /// observed, so `since` survives repeated polling.
    pub async fn snapshot(&self, now: i64) -> StatusSnapshot {
        let obs = self.observe().await;
        let (state, last_error) = derive(&obs, now);
        self.with(|s| {
            if s.last_state != Some(state) {
                if s.last_state.is_some() {
                    s.since = now;
                }
                s.last_state = Some(state);
            }
            StatusSnapshot {
                environment: s.environment.clone(),
                state,
                since: s.since,
                svid: s.svid.clone(),
                attest_backend: s.attest_backend,
                cmis_node: s.cmis_node.clone(),
                crl_age_secs: obs
                    .crl_issued_at
                    .map(|issued| u32::try_from((now - issued).max(0)).unwrap_or(u32::MAX)),
                allowlist: match s.allowlist {
                    AllowlistLoad::Missing => AllowlistState::Missing,
                    AllowlistLoad::Invalid => AllowlistState::Invalid,
                    AllowlistLoad::Loaded { entries, not_after } => AllowlistState::Loaded {
                        entries: u32::try_from(entries).unwrap_or(u32::MAX),
                        not_after,
                    },
                },
                x509_store: s.x509_store,
                last_error,
                version: env!("CARGO_PKG_VERSION").to_string(),
            }
        })
    }
}

/// Every environment's [`StatusHandle`], in serve order. Built once at
/// startup; cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct StatusRegistry {
    handles: Arc<Vec<StatusHandle>>,
}

/// A [`StatusRegistry::snapshots`] filter named an environment this daemon
/// does not serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown environment")]
pub struct UnknownEnvironment;

impl StatusRegistry {
    /// A registry over `handles`.
    #[must_use]
    pub fn new(handles: Vec<StatusHandle>) -> Self {
        Self {
            handles: Arc::new(handles),
        }
    }

    /// The handles, in serve order.
    #[must_use]
    pub fn handles(&self) -> &[StatusHandle] {
        &self.handles
    }

    /// Snapshots at `now` for every environment, or only the one named by
    /// `environment` (`"default"` names the default environment).
    pub async fn snapshots(
        &self,
        environment: Option<&str>,
        now: i64,
    ) -> Result<Vec<StatusSnapshot>, UnknownEnvironment> {
        let mut out = Vec::new();
        for h in self.handles.iter() {
            let matches = match environment {
                None => true,
                Some(want) => {
                    let env = h.environment();
                    env.as_deref() == Some(want)
                        || (env.is_none() && want == DEFAULT_ENVIRONMENT_LABEL)
                }
            };
            if matches {
                out.push(h.snapshot(now).await);
            }
        }
        if environment.is_some() && out.is_empty() {
            return Err(UnknownEnvironment);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn healthy_obs() -> Observed {
        Observed {
            not_configured: None,
            phase: AttestPhase::Attested,
            svid: Some(SvidSummary {
                spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
                not_after: NOW + 3600,
                renew_at: NOW + 1000,
            }),
            crl_issued_at: Some(NOW - 30),
            allowlist: AllowlistLoad::Loaded {
                entries: 2,
                not_after: NOW + 86_400,
            },
        }
    }

    fn state(obs: &Observed, now: i64) -> AgentState {
        derive(obs, now).0
    }

    #[test]
    fn every_daemon_reachable_state_is_derived() {
        let mut reached = std::collections::HashSet::new();

        let h = healthy_obs();
        reached.insert(state(&h, NOW));
        assert_eq!(state(&h, NOW), AgentState::Healthy);
        assert!(derive(&h, NOW).1.is_none());

        let mut o = h.clone();
        o.not_configured = Some(error_codes::CMIS_NOT_CONFIGURED);
        reached.insert(state(&o, NOW));

        for phase in [AttestPhase::Starting, AttestPhase::Attesting] {
            let mut o = h.clone();
            o.svid = None;
            o.phase = phase;
            assert_eq!(state(&o, NOW), AgentState::Attesting);
            reached.insert(state(&o, NOW));
        }
        for (f, want) in [
            (AttestFailure::CmisUnreachable, AgentState::CmisUnreachable),
            (AttestFailure::NotEnrolled, AgentState::NotEnrolled),
            (AttestFailure::PinMismatch, AgentState::PinMismatch),
            (AttestFailure::TpmUnavailable, AgentState::TpmUnavailable),
            (AttestFailure::Other, AgentState::CmisUnreachable),
        ] {
            let mut o = h.clone();
            o.svid = None;
            o.phase = AttestPhase::Failed(f);
            assert_eq!(state(&o, NOW), want, "{f:?}");
            reached.insert(want);
        }

        let mut o = h.clone();
        o.crl_issued_at = None;
        assert_eq!(state(&o, NOW), AgentState::CrlStale);
        o.crl_issued_at = Some(NOW - 301);
        assert_eq!(state(&o, NOW), AgentState::CrlStale);
        reached.insert(AgentState::CrlStale);

        let mut o = h.clone();
        o.allowlist = AllowlistLoad::Missing;
        reached.insert(state(&o, NOW));
        o.allowlist = AllowlistLoad::Invalid;
        reached.insert(state(&o, NOW));
        o.allowlist = AllowlistLoad::Loaded {
            entries: 1,
            not_after: NOW - 1,
        };
        assert_eq!(state(&o, NOW), AgentState::AllowlistInvalid);
        assert_eq!(
            derive(&o, NOW).1.unwrap().code,
            error_codes::ALLOWLIST_EXPIRED
        );

        // Past the renewal point (still valid) and past expiry.
        assert_eq!(state(&h, NOW + 1500), AgentState::CrlStale); // CRL aged too
        let mut o = h.clone();
        o.crl_issued_at = Some(NOW + 1500);
        assert_eq!(state(&o, NOW + 1500), AgentState::SvidExpiring);
        assert_eq!(state(&o, NOW + 3600), AgentState::SvidExpiring);
        assert_eq!(
            derive(&o, NOW + 3600).1.unwrap().code,
            error_codes::SVID_EXPIRED
        );
        reached.insert(AgentState::SvidExpiring);
        // Expired *and* the re-attestation failed: the failure wins.
        let mut o = h.clone();
        o.phase = AttestPhase::Failed(AttestFailure::PinMismatch);
        assert_eq!(state(&o, NOW + 3600), AgentState::PinMismatch);

        // Everything the daemon can report itself. NotInstalled / NotRunning /
        // ImaDisabled are client-side by definition (no daemon to ask).
        for s in AgentState::ALL {
            let client_side = matches!(
                s,
                AgentState::NotInstalled | AgentState::NotRunning | AgentState::ImaDisabled
            );
            assert_eq!(reached.contains(&s), !client_side, "{s:?}");
        }
    }

    #[test]
    fn failures_are_classified() {
        use crate::client::AttestClientError as E;
        let pin = anyhow::anyhow!("invalid peer certificate: Other(SPKI pin mismatch)")
            .context("dialing https://cmis:8443");
        assert_eq!(
            AttestFailure::from_connect_error(&pin),
            AttestFailure::PinMismatch
        );
        let down = anyhow::anyhow!("connection refused").context("dialing https://cmis:8443");
        assert_eq!(
            AttestFailure::from_connect_error(&down),
            AttestFailure::CmisUnreachable
        );
        let rejected = E::Transport(tonic::Status::permission_denied("attestation failed"));
        assert_eq!(
            AttestFailure::from_attest_error(&rejected, false),
            AttestFailure::NotEnrolled
        );
        let unavailable = E::Transport(tonic::Status::unavailable("down"));
        assert_eq!(
            AttestFailure::from_attest_error(&unavailable, false),
            AttestFailure::CmisUnreachable
        );
        let evidence = E::Evidence(anyhow::anyhow!("TPM busy"));
        assert_eq!(
            AttestFailure::from_attest_error(&evidence, true),
            AttestFailure::TpmUnavailable
        );
        assert_eq!(
            AttestFailure::from_attest_error(&evidence, false),
            AttestFailure::Other
        );
    }

    #[test]
    fn node_is_reduced_to_host_port() {
        assert_eq!(
            node_of("https://cmis1.example.com:8443"),
            "cmis1.example.com:8443"
        );
        assert_eq!(node_of("https://user:pw@h:1/path?q"), "h:1");
        assert_eq!(node_of("h:2"), "h:2");
        assert!(node_of(&format!("https://{}", "a".repeat(1000))).len() <= 255);
    }

    #[tokio::test]
    async fn handle_tracks_events_and_since() {
        let h = StatusHandle::new("staging", NOW);
        let s = h.snapshot(NOW).await;
        assert_eq!(s.environment.as_deref(), Some("staging"));
        assert_eq!(s.state, AgentState::Attesting);
        assert_eq!(s.since, NOW);

        h.attest_failed(AttestFailure::PinMismatch);
        let s = h.snapshot(NOW + 5).await;
        assert_eq!(s.state, AgentState::PinMismatch);
        assert_eq!(s.since, NOW + 5);
        // Polling again keeps `since`.
        assert_eq!(h.snapshot(NOW + 9).await.since, NOW + 5);

        let crl = Arc::new(CrlCache::seeded(ferro_svid::CrlBody {
            issued_at: NOW + 10,
            number: 1,
            entries: vec![],
        }));
        h.set_crl_cache(crl);
        h.set_cmis_node("https://cmis1:8443");
        h.set_attest_backend(crate::config::AttestBackend::HostKey);
        h.set_x509_store("machine-key");
        h.set_allowlist(AllowlistLoad::Loaded {
            entries: 4,
            not_after: NOW + 86_400,
        });
        h.attest_succeeded("spiffe://ferrogate.test/host/abc", NOW + 10, NOW + 3610);
        let s = h.snapshot(NOW + 20).await;
        assert_eq!(s.state, AgentState::Healthy);
        assert_eq!(s.crl_age_secs, Some(10));
        assert_eq!(s.cmis_node.as_deref(), Some("cmis1:8443"));
        assert_eq!(s.attest_backend, AttestBackend::HostKey);
        assert_eq!(s.x509_store, Some(StoreBackend::MachineKey));
        assert_eq!(s.svid.as_ref().unwrap().renew_at, NOW + 10 + 2160);
        assert!(s.last_error.is_none());
    }

    #[tokio::test]
    #[allow(clippy::items_after_statements)]
    async fn status_snapshot_has_no_secret_fields() {
        // Drive a handle through every setter with realistic inputs and
        // serialise the snapshot. The handle has no field that could even hold
        // a JWS, key, pin or jti; this pins that down from the daemon side
        // (the proto crate pins the exact key set).
        let h = StatusHandle::new(DEFAULT_ENVIRONMENT_LABEL, NOW);
        // A URL with userinfo must not leak it into `cmis_node`.
        h.set_cmis_node("https://operator:s3cr3t-pw@cmis1.example.com:8443/v1?token=abc");
        h.set_attest_backend(crate::config::AttestBackend::Tpm);
        h.attest_succeeded("spiffe://ferrogate.test/host/abc", NOW, NOW + 3600);
        h.set_x509_store("tpm");
        h.set_allowlist(AllowlistLoad::Loaded {
            entries: 3,
            not_after: NOW + 10,
        });
        let snap = h.snapshot(NOW).await;
        let json = serde_json::to_value(&snap).unwrap();
        let text = json.to_string();
        for leaked in ["s3cr3t-pw", "operator", "token=abc", "/v1"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        fn keys(v: &serde_json::Value, out: &mut Vec<String>) {
            if let serde_json::Value::Object(m) = v {
                for (k, child) in m {
                    out.push(k.to_ascii_lowercase());
                    keys(child, out);
                }
            }
        }
        let mut names = Vec::new();
        keys(&json, &mut names);
        for name in &names {
            for banned in [
                "jws", "token", "key", "secret", "pin", "jti", "sig", "bin_sha", "pid", "uid",
                "seed", "der",
            ] {
                assert!(
                    !name.contains(banned),
                    "snapshot key {name:?} looks sensitive"
                );
            }
        }
    }

    #[tokio::test]
    async fn registry_filters_by_environment() {
        let reg = StatusRegistry::new(vec![
            StatusHandle::new(DEFAULT_ENVIRONMENT_LABEL, NOW),
            StatusHandle::new("prod", NOW),
        ]);
        assert_eq!(reg.snapshots(None, NOW).await.unwrap().len(), 2);
        let d = reg.snapshots(Some("default"), NOW).await.unwrap();
        assert_eq!(d.len(), 1);
        assert!(d[0].environment.is_none());
        assert_eq!(
            reg.snapshots(Some("prod"), NOW).await.unwrap()[0]
                .environment
                .as_deref(),
            Some("prod")
        );
        assert_eq!(
            reg.snapshots(Some("nope"), NOW).await,
            Err(UnknownEnvironment)
        );
    }
}
