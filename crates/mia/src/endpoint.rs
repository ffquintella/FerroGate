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

use std::time::Duration;

use anyhow::Context as _;
use ferro_crypto::pin::SpkiPin;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use tonic::transport::Channel;

use crate::config::CmisConfig;

/// Per-candidate connect timeout, so one black-holed node cannot stall the whole
/// fail-over sweep.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the SRV DNS lookup itself.
const SRV_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// How MIA discovers CMIS: a fixed endpoint, or an SRV record to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// A single `https://host:port` authority.
    Static(String),
    /// A DNS SRV owner name (e.g. `_cmis._tcp.example.com`).
    Srv(String),
}

/// Resolves the configured CMIS source to live, pinned connections, with
/// best-first selection and automatic fail-over. Cheap to [`Clone`] (a string
/// and the parsed pins), so a long-running task can own its own copy.
#[derive(Clone, Debug)]
pub struct CmisResolver {
    source: Source,
    pins: Vec<SpkiPin>,
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
        }))
    }

    /// A short human label for logs and diagnostics: the static endpoint, or the
    /// SRV owner name.
    #[must_use]
    pub fn describe(&self) -> &str {
        match &self.source {
            Source::Static(e) => e,
            Source::Srv(n) => n,
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
        }
    }

    /// Dial CMIS with fail-over: resolve candidates, then try each in preference
    /// order until one completes the pinned hybrid-PQC handshake. Returns the
    /// chosen `https://host:port` and a ready client.
    ///
    /// The successful handshake is the health check — an unreachable, non-hybrid,
    /// or wrong-identity node is skipped. Per-candidate dials are bounded by
    /// [`CONNECT_TIMEOUT`] so a black-holed node cannot stall the sweep.
    pub async fn connect(&self) -> anyhow::Result<(String, MachineIdentityClient<Channel>)> {
        let candidates = self.candidates().await?;
        let multi = candidates.len() > 1;
        let mut last_err: Option<anyhow::Error> = None;
        for ep in candidates {
            match tokio::time::timeout(
                CONNECT_TIMEOUT,
                crate::client::connect_pinned(&ep, self.pins.clone()),
            )
            .await
            {
                Ok(Ok(client)) => {
                    if multi {
                        tracing::debug!(endpoint = %ep, "selected live CMIS endpoint");
                    }
                    return Ok((ep, client));
                }
                Ok(Err(e)) => {
                    if multi {
                        tracing::warn!(endpoint = %ep, error = %e, "CMIS candidate unreachable; trying next");
                    }
                    last_err = Some(e.context(format!("dialing {ep}")));
                }
                Err(_) => {
                    if multi {
                        tracing::warn!(endpoint = %ep, timeout_secs = CONNECT_TIMEOUT.as_secs(), "CMIS candidate timed out; trying next");
                    }
                    last_err = Some(anyhow::anyhow!(
                        "dialing {ep}: timed out after {}s",
                        CONNECT_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| anyhow::anyhow!("no CMIS candidates to connect to")))
        .with_context(|| format!("no reachable CMIS endpoint via {}", self.describe()))
    }
}

/// Look up an SRV record and return `https://host:port` candidates ordered by
/// RFC 2782 preference (ascending priority, then descending weight, then target
/// for a stable order). Uses the platform's configured DNS resolver.
async fn resolve_srv(name: &str) -> anyhow::Result<Vec<String>> {
    use hickory_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("initialising the system DNS resolver for the SRV lookup")?;
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
        .iter()
        .map(|srv| {
            let target = srv.target().to_utf8();
            let target = target.trim_end_matches('.').to_string();
            (srv.priority(), srv.weight(), srv.port(), target)
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
        assert!(CmisResolver::from_config(&cfg).unwrap_err().to_string().contains("SPKI pin"));
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
}
