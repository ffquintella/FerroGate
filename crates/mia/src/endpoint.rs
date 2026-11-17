//! CMIS endpoint discovery, selection, and fail-over for the MIA client.
//!
//! A MIA reaches CMIS either by a single static `cmis.endpoint`, or — for high
//! availability — by a DNS **SRV record** (`cmis.srv`) that advertises one or
//! more CMIS nodes. [`CmisResolver`] unifies both:
//!
//! 1. it resolves the configured source to an ordered list of
//!    `https://host:port` candidates (SRV records sorted by RFC 2782 — ascending
//!    priority, then descending weight); then
//! 2. it dials them **best-first**, skipping any node that is unreachable, and
//!    returns the first that completes the pinned hybrid-PQC TLS handshake.
//!
//! A successful pinned handshake doubles as the health check: an unreachable,
//! non-hybrid, or wrong-identity node is rejected and the next candidate is
//! tried. Long-running tasks (the CRL puller and the allowlist-propose loop)
//! call [`CmisResolver::connect`] on every reconnect, so a node that goes down
//! is transparently replaced by the next live one — re-resolving SRV each time,
//! so DNS changes (a scaled-out or drained cluster) are picked up without a
//! restart.
//!
//! The SPKI pin authenticates *every* candidate: a CMIS HA cluster shares one
//! pinned identity, so a single pin covers all nodes.
//!
//! # Detecting a down, slow or silent node
//!
//! - **Down / refusing / black-holed:** the dial fails or exceeds the connect
//!   timeout, and the node is skipped.
//! - **Slow or hung after connecting** (accepts the connection but stops
//!   answering — a paused process, a saturated host): [`CmisResolver::call`]
//!   bounds every RPC by an RPC timeout, and a timeout or transport-class error
//!   fails the call over to the next candidate.
//! - **Memory:** a node that failed is *penalised* for a cool-down, so later
//!   connects try the healthy nodes first instead of paying the timeout on the
//!   dead one every time. A penalised node is still tried last, as a last
//!   resort, and a success clears its penalty — so a recovered preferred node
//!   takes traffic back once the cool-down lapses.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use ferro_crypto::pin::SpkiPin;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use tonic::transport::Channel;

use crate::config::CmisConfig;

/// Default per-candidate connect timeout, so one black-holed node cannot stall
/// the whole fail-over sweep.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default bound on one RPC made through [`CmisResolver::call`]; a node that
/// accepts the connection but does not answer in time is failed over.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Default time a failed node is deprioritised before it is tried first again.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(30);

/// Timeout for the SRV DNS lookup itself.
const SRV_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// How MIA discovers CMIS: a fixed endpoint, or an SRV record to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// A single `https://host:port` authority.
    Static(String),
    /// A DNS SRV owner name (e.g. `_cmis._tcp.example.com`).
    Srv(String),
    /// A fixed, ordered candidate list (embedding and tests; no DNS).
    Fixed(Vec<String>),
}

/// Timeouts and penalty window of a [`CmisResolver`].
#[derive(Debug, Clone, Copy)]
struct Tuning {
    connect_timeout: Duration,
    rpc_timeout: Duration,
    cooldown: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
            cooldown: FAILURE_COOLDOWN,
        }
    }
}

/// Whether `err` says the *node* (not the request) is at fault: a timeout, a
/// transport/IO failure, or a gRPC status meaning the server is unavailable.
/// Application errors (permission, not-found, invalid argument…) are the
/// answer of a healthy node and must not trigger fail-over.
fn is_node_failure(err: &anyhow::Error) -> bool {
    use tonic::Code;
    err.chain().any(|cause| {
        if let Some(status) = cause.downcast_ref::<tonic::Status>() {
            matches!(
                status.code(),
                Code::Unavailable | Code::DeadlineExceeded | Code::Unknown | Code::Cancelled
            )
        } else {
            cause.is::<tonic::transport::Error>() || cause.is::<std::io::Error>()
        }
    })
}

/// Resolves the configured CMIS source to live, pinned connections, with
/// best-first selection and automatic fail-over. Cheap to [`Clone`] (a string
/// and the parsed pins), so a long-running task can own its own copy.
#[derive(Clone, Debug)]
pub struct CmisResolver {
    source: Source,
    pins: Vec<SpkiPin>,
    tuning: Tuning,
    /// Endpoint → instant until which it is deprioritised. Shared by clones.
    penalties: Arc<Mutex<HashMap<String, Instant>>>,
}

impl CmisResolver {
    /// Build a resolver from `[cmis]` configuration.
    ///
    /// Returns `Ok(None)` when CMIS is not configured at all (neither `endpoint`
    /// nor `srv`), and `Err` when it is configured but unusable: both sources set
    /// at once, or a missing/invalid SPKI pin. The pin is parsed once here and
    /// reused for every dial.
    pub fn from_config(cfg: &CmisConfig) -> anyhow::Result<Option<Self>> {
        let source = match (cfg.endpoint.as_deref(), cfg.srv.as_deref()) {
            (None, None) => return Ok(None),
            (Some(_), Some(_)) => anyhow::bail!(
                "set either cmis.endpoint or cmis.srv, not both: endpoint is a single static \
                 server, srv discovers one or more CMIS nodes from a DNS SRV record"
            ),
            (Some(ep), None) => Source::Static(ep.to_string()),
            (None, Some(srv)) => Source::Srv(srv.to_string()),
        };
        let pin_hex = cfg.spki_pin.as_deref().context(
            "cmis is configured but cmis.spki_pin is missing; CMIS is authenticated by SPKI pin",
        )?;
        let pin = SpkiPin::from_hex(pin_hex.trim())
            .map_err(|e| anyhow::anyhow!("cmis.spki_pin is not a valid SHA-384 SPKI pin: {e}"))?;
        Ok(Some(Self {
            source,
            pins: vec![pin],
            tuning: Tuning::default(),
            penalties: Arc::default(),
        }))
    }

    /// A resolver over a fixed, ordered list of `https://host:port` candidates
    /// (most-preferred first), with no DNS involved. For embedding and tests.
    #[must_use]
    pub fn with_candidates(candidates: Vec<String>, pins: Vec<SpkiPin>) -> Self {
        Self {
            source: Source::Fixed(candidates),
            pins,
            tuning: Tuning::default(),
            penalties: Arc::default(),
        }
    }

    /// Override the connect timeout, RPC timeout and failure cool-down.
    #[must_use]
    pub fn with_timeouts(
        mut self,
        connect_timeout: Duration,
        rpc_timeout: Duration,
        cooldown: Duration,
    ) -> Self {
        self.tuning = Tuning {
            connect_timeout,
            rpc_timeout,
            cooldown,
        };
        self
    }

    /// A short human label for logs and diagnostics: the static endpoint, or the
    /// SRV owner name.
    #[must_use]
    pub fn describe(&self) -> &str {
        match &self.source {
            Source::Static(e) => e,
            Source::Srv(n) => n,
            Source::Fixed(c) => c.first().map_or("(no candidates)", String::as_str),
        }
    }

    /// Whether candidates are discovered dynamically (an SRV source).
    #[must_use]
    pub fn is_srv(&self) -> bool {
        matches!(self.source, Source::Srv(_))
    }

    /// The accepted SPKI pins (shared by every candidate).
    #[must_use]
    pub fn pins(&self) -> &[SpkiPin] {
        &self.pins
    }

    /// Resolve the source to an ordered list of `https://host:port` candidates,
    /// most-preferred first. A static source yields exactly one; an SRV source
    /// yields its records sorted by ascending priority then descending weight.
    /// Errors only if SRV resolution fails outright (a DNS error or an SRV record
    /// with no usable targets).
    pub async fn candidates(&self) -> anyhow::Result<Vec<String>> {
        match &self.source {
            Source::Static(ep) => Ok(vec![ep.clone()]),
            Source::Srv(name) => resolve_srv(name).await,
            Source::Fixed(c) => Ok(c.clone()),
        }
    }

    /// Record that `endpoint` failed: it is tried after the healthy nodes for the
    /// cool-down. Callers that hold a long-lived connection use this when an RPC
    /// on it fails.
    pub fn mark_failed(&self, endpoint: &str) {
        let until = Instant::now() + self.tuning.cooldown;
        if let Ok(mut p) = self.penalties.lock() {
            p.insert(endpoint.to_string(), until);
        }
    }

    /// Record that `endpoint` served successfully, clearing any penalty.
    pub fn mark_ok(&self, endpoint: &str) {
        if let Ok(mut p) = self.penalties.lock() {
            p.remove(endpoint);
        }
    }

    /// Stable-reorder `candidates`: nodes not under penalty first (keeping their
    /// preference order), then penalised ones (also in preference order). Expired
    /// penalties are dropped.
    fn order_by_health(&self, candidates: Vec<String>) -> Vec<String> {
        let now = Instant::now();
        let Ok(mut p) = self.penalties.lock() else {
            return candidates;
        };
        p.retain(|_, until| *until > now);
        let (healthy, penalised): (Vec<_>, Vec<_>) =
            candidates.into_iter().partition(|c| !p.contains_key(c));
        healthy.into_iter().chain(penalised).collect()
    }

    /// Dial one candidate under the connect timeout, updating its health.
    async fn dial(&self, ep: &str) -> anyhow::Result<MachineIdentityClient<Channel>> {
        let res = match tokio::time::timeout(
            self.tuning.connect_timeout,
            crate::client::connect_pinned(ep, self.pins.clone()),
        )
        .await
        {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => Err(e.context(format!("dialing {ep}"))),
            Err(_) => Err(anyhow::anyhow!(
                "dialing {ep}: timed out after {:?}",
                self.tuning.connect_timeout
            )),
        };
        match &res {
            Ok(_) => self.mark_ok(ep),
            Err(_) => self.mark_failed(ep),
        }
        res
    }

    /// Run one RPC against a live node, failing over to the next candidate when
    /// the node is down, too slow, or erroring at the transport level.
    ///
    /// `op` receives a connected client (cheap to clone) and returns the RPC's
    /// result; it may be invoked once per candidate tried, so it must be safe to
    /// repeat (all the read-only MIA→CMIS calls are). Each attempt is bounded by
    /// the RPC timeout. An *application* error from a healthy node (permission,
    /// not-found…) is returned at once without trying another node. On success
    /// returns the serving endpoint and the value.
    pub async fn call<T, F, Fut>(&self, mut op: F) -> anyhow::Result<(String, T)>
    where
        F: FnMut(MachineIdentityClient<Channel>) -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        let candidates = self.order_by_health(self.candidates().await?);
        let mut last_err: Option<anyhow::Error> = None;
        for ep in candidates {
            let client = match self.dial(&ep).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(endpoint = %ep, error = %e, "CMIS candidate unreachable; trying next");
                    last_err = Some(e);
                    continue;
                }
            };
            match tokio::time::timeout(self.tuning.rpc_timeout, op(client)).await {
                Ok(Ok(v)) => return Ok((ep, v)),
                Ok(Err(e)) if is_node_failure(&e) => {
                    tracing::warn!(endpoint = %ep, error = %e, "CMIS node failed mid-call; trying next");
                    self.mark_failed(&ep);
                    last_err = Some(e.context(format!("calling {ep}")));
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    tracing::warn!(endpoint = %ep, timeout = ?self.tuning.rpc_timeout, "CMIS node too slow; trying next");
                    self.mark_failed(&ep);
                    last_err = Some(anyhow::anyhow!(
                        "calling {ep}: no answer within {:?}",
                        self.tuning.rpc_timeout
                    ));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no CMIS candidates to call")))
            .with_context(|| format!("no responsive CMIS endpoint via {}", self.describe()))
    }

    /// Dial CMIS with fail-over: resolve candidates, then try each in preference
    /// order until one completes the pinned hybrid-PQC handshake. Returns the
    /// chosen `https://host:port` and a ready client.
    ///
    /// The successful handshake is the health check — an unreachable, non-hybrid,
    /// or wrong-identity node is skipped. Per-candidate dials are bounded by
    /// the connect timeout so a black-holed node cannot stall the sweep; failed
    /// nodes are deprioritised for the cool-down.
    pub async fn connect(&self) -> anyhow::Result<(String, MachineIdentityClient<Channel>)> {
        let candidates = self.order_by_health(self.candidates().await?);
        let multi = candidates.len() > 1;
        let mut last_err: Option<anyhow::Error> = None;
        for ep in candidates {
            match self.dial(&ep).await {
                Ok(client) => {
                    if multi {
                        tracing::debug!(endpoint = %ep, "selected live CMIS endpoint");
                    }
                    return Ok((ep, client));
                }
                Err(e) => {
                    if multi {
                        tracing::warn!(endpoint = %ep, error = %e, "CMIS candidate unreachable; trying next");
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no CMIS candidates to connect to")))
            .with_context(|| format!("no reachable CMIS endpoint via {}", self.describe()))
    }
}

/// Look up an SRV record and return `https://host:port` candidates ordered by
/// RFC 2782 preference (ascending priority, then descending weight, then target
/// for a stable order). Uses the platform's configured DNS resolver.
async fn resolve_srv(name: &str) -> anyhow::Result<Vec<String>> {
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_tokio()
        .context("initialising the system DNS resolver for the SRV lookup")?
        .build()
        .context("building the system DNS resolver for the SRV lookup")?;
    let lookup = tokio::time::timeout(SRV_LOOKUP_TIMEOUT, resolver.srv_lookup(name))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "SRV lookup for {name:?} timed out after {}s",
                SRV_LOOKUP_TIMEOUT.as_secs()
            )
        })?
        .with_context(|| format!("SRV lookup for {name:?}"))?;

    // (priority, weight, port, target) tuples; a "." target means "service
    // explicitly not available here" (RFC 2782) and is dropped.
    let records: Vec<(u16, u16, u16, String)> = lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::SRV(srv) => {
                let target = srv.target.to_utf8();
                let target = target.trim_end_matches('.').to_string();
                Some((srv.priority, srv.weight, srv.port, target))
            }
            _ => None,
        })
        .filter(|(.., target)| !target.is_empty())
        .collect();
    let ordered = order_candidates(records);
    if ordered.is_empty() {
        anyhow::bail!("SRV record {name:?} resolved to no usable targets");
    }
    Ok(ordered)
}

/// Order `(priority, weight, port, target)` SRV records into `https://host:port`
/// candidates by RFC 2782 preference: ascending priority, then descending
/// weight, then target name for a stable, deterministic result.
fn order_candidates(mut records: Vec<(u16, u16, u16, String)>) -> Vec<String> {
    records.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(a.3.cmp(&b.3)));
    records
        .into_iter()
        .map(|(_, _, port, target)| format!("https://{target}:{port}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin_hex() -> String {
        // A syntactically valid lowercase-hex SHA-384 (96 chars).
        "a".repeat(96)
    }

    #[test]
    fn from_config_none_when_unconfigured() {
        let cfg = CmisConfig::default();
        assert!(CmisResolver::from_config(&cfg).unwrap().is_none());
    }

    #[test]
    fn from_config_rejects_both_sources() {
        let cfg = CmisConfig {
            endpoint: Some("https://a:8443".into()),
            srv: Some("_cmis._tcp.example.com".into()),
            spki_pin: Some(pin_hex()),
        };
        let err = CmisResolver::from_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("not both"));
    }

    #[test]
    fn from_config_requires_a_pin() {
        let cfg = CmisConfig {
            endpoint: Some("https://a:8443".into()),
            srv: None,
            spki_pin: None,
        };
        let err = CmisResolver::from_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("spki_pin"));
    }

    #[test]
    fn from_config_rejects_a_bad_pin() {
        let cfg = CmisConfig {
            endpoint: Some("https://a:8443".into()),
            srv: None,
            spki_pin: Some("not-hex".into()),
        };
        assert!(CmisResolver::from_config(&cfg)
            .unwrap_err()
            .to_string()
            .contains("SPKI pin"));
    }

    #[tokio::test]
    async fn static_source_yields_one_candidate() {
        let cfg = CmisConfig {
            endpoint: Some("https://cmis.example.com:8443".into()),
            srv: None,
            spki_pin: Some(pin_hex()),
        };
        let r = CmisResolver::from_config(&cfg).unwrap().unwrap();
        assert!(!r.is_srv());
        assert_eq!(r.describe(), "https://cmis.example.com:8443");
        assert_eq!(
            r.candidates().await.unwrap(),
            vec!["https://cmis.example.com:8443".to_string()]
        );
    }

    #[test]
    fn order_candidates_follows_rfc2782() {
        // Lower priority wins; within a priority, higher weight first; ties by
        // target name. Input deliberately unsorted.
        let records = vec![
            (20, 0, 8443, "dr.example.com".to_string()),
            (10, 50, 8443, "b.example.com".to_string()),
            (10, 50, 8443, "a.example.com".to_string()),
            (10, 100, 9443, "c.example.com".to_string()),
        ];
        assert_eq!(
            order_candidates(records),
            vec![
                "https://c.example.com:9443".to_string(), // pri 10, weight 100
                "https://a.example.com:8443".to_string(), // pri 10, weight 50, name a
                "https://b.example.com:8443".to_string(), // pri 10, weight 50, name b
                "https://dr.example.com:8443".to_string(), // pri 20 (fallback)
            ]
        );
    }

    #[test]
    fn srv_source_is_marked_dynamic() {
        let cfg = CmisConfig {
            endpoint: None,
            srv: Some("_cmis._tcp.example.com".into()),
            spki_pin: Some(pin_hex()),
        };
        let r = CmisResolver::from_config(&cfg).unwrap().unwrap();
        assert!(r.is_srv());
        assert_eq!(r.describe(), "_cmis._tcp.example.com");
    }

    fn fixed(c: &[&str]) -> CmisResolver {
        CmisResolver::with_candidates(
            c.iter().map(|s| (*s).to_string()).collect(),
            vec![SpkiPin::from_hex(&pin_hex()).unwrap()],
        )
    }

    #[test]
    fn failed_node_is_tried_last_then_recovers() {
        let r = fixed(&["https://a:1", "https://b:1", "https://c:1"]).with_timeouts(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(50),
        );
        let all = || {
            vec![
                "https://a:1".into(),
                "https://b:1".into(),
                "https://c:1".into(),
            ]
        };
        assert_eq!(r.order_by_health(all()), all());
        r.mark_failed("https://a:1");
        assert_eq!(
            r.order_by_health(all()),
            vec!["https://b:1", "https://c:1", "https://a:1"]
        );
        // Cool-down lapses → the preferred node is first again.
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(r.order_by_health(all()), all());
        // An explicit success clears the penalty immediately.
        r.mark_failed("https://b:1");
        r.mark_ok("https://b:1");
        assert_eq!(r.order_by_health(all()), all());
    }

    #[test]
    fn penalties_are_shared_by_clones() {
        let r = fixed(&["https://a:1", "https://b:1"]);
        let c = r.clone();
        c.mark_failed("https://a:1");
        assert_eq!(
            r.order_by_health(vec!["https://a:1".into(), "https://b:1".into()]),
            vec!["https://b:1", "https://a:1"]
        );
    }

    #[test]
    fn only_node_level_errors_trigger_failover() {
        use tonic::{Code, Status};
        for code in [Code::Unavailable, Code::DeadlineExceeded, Code::Unknown] {
            assert!(is_node_failure(&anyhow::Error::from(Status::new(
                code, "x"
            ))));
        }
        for code in [
            Code::PermissionDenied,
            Code::NotFound,
            Code::InvalidArgument,
        ] {
            assert!(!is_node_failure(&anyhow::Error::from(Status::new(
                code, "x"
            ))));
        }
        assert!(is_node_failure(&anyhow::Error::from(
            std::io::Error::other("reset")
        )));
        assert!(!is_node_failure(&anyhow::anyhow!("empty enrollment key")));
        // The status is found through added context.
        let wrapped = anyhow::Error::from(Status::unavailable("down")).context("calling");
        assert!(is_node_failure(&wrapped));
    }
}
