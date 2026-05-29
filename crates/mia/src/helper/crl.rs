//! MIA-side CRL cache, puller, and freshness gate (feature F11).
//!
//! The MIA pulls the composite-signed CRL from the CMIS `JWKS` RPC (carried in
//! the `x-ferrogate-crl` extension), verifies its signature against the
//! published issuer key, and caches the authenticated body. Every child-token
//! mint consults the cache through [`CrlCache::gate`]:
//!
//! - if the cached CRL is older than [`ferro_svid::CRL_MAX_AGE_SECS`] (or no CRL
//!   has ever been pulled), the mint is **refused** — fail closed;
//! - if the CRL revokes this host (by parent SVID `cert_sha` or by SPIFFE id),
//!   the mint is refused;
//! - otherwise minting proceeds.
//!
//! Verification is fail-closed: a CRL whose signature does not verify, whose
//! `signer_kid` is unknown, or that is absent from the JWKS leaves the cache
//! **unchanged**. The cached entry then ages out and minting halts — a forged
//! or missing CRL can never unblock minting.

use std::sync::Arc;
use std::time::Duration;

use ferro_svid::{CrlBody, JwkSet};
use tokio::sync::RwLock;

/// Clock skew tolerance applied to CRL freshness (seconds).
pub const CRL_FRESHNESS_LEEWAY_SECS: i64 = 60;

/// The decision the CRL gate returns for one mint attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlGate {
    /// A fresh CRL is cached and does not revoke this host — proceed.
    Ok,
    /// No fresh CRL is cached — refuse (fail closed).
    Stale,
    /// A fresh CRL revokes this host's SVID or SPIFFE id — refuse.
    Revoked,
}

/// A thread-safe cache holding the most recently verified CRL body.
///
/// Only **authenticated** bodies are ever stored here (see [`ingest`]); the gate
/// therefore trusts whatever it finds and only has to check freshness and
/// membership.
#[derive(Default)]
pub struct CrlCache {
    inner: RwLock<Option<CrlBody>>,
}

impl CrlCache {
    /// An empty cache. With nothing cached, [`CrlGate::Stale`] is returned until
    /// the first successful pull — minting is refused (fail closed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache pre-seeded with an already-verified body (tests and bring-up).
    #[must_use]
    pub fn seeded(body: CrlBody) -> Self {
        Self {
            inner: RwLock::new(Some(body)),
        }
    }

    /// Replace the cached body. Pass an authenticated body only.
    pub async fn store(&self, body: CrlBody) {
        *self.inner.write().await = Some(body);
    }

    /// The cached body's sequence number, if any (diagnostics / tests).
    pub async fn number(&self) -> Option<u64> {
        self.inner.read().await.as_ref().map(|b| b.number)
    }

    /// Decide whether a mint may proceed for the host identified by
    /// `parent_cert_sha_hex` (lowercase hex SHA-384 of the host SVID) and
    /// `host_spiffe_id`, at reference time `now`.
    pub async fn gate(&self, parent_cert_sha_hex: &str, host_spiffe_id: &str, now: i64) -> CrlGate {
        let guard = self.inner.read().await;
        let Some(body) = guard.as_ref() else {
            return CrlGate::Stale;
        };
        if !body.is_fresh(now, CRL_FRESHNESS_LEEWAY_SECS) {
            return CrlGate::Stale;
        }
        if body.revokes_svid(parent_cert_sha_hex) || body.revokes_host(host_spiffe_id) {
            return CrlGate::Revoked;
        }
        CrlGate::Ok
    }
}

/// Why a CRL pull could not be ingested into the cache.
#[derive(Debug, thiserror::Error)]
pub enum CrlIngestError {
    /// The JWKS JSON was malformed.
    #[error("malformed jwks: {0}")]
    MalformedJwks(String),
    /// The JWKS carried no `x-ferrogate-crl` extension.
    #[error("jwks has no x-ferrogate-crl extension")]
    Absent,
    /// The CRL signature did not verify against the published keys.
    #[error("crl verification failed: {0}")]
    Verify(#[from] ferro_svid::CrlError),
}

/// Parse a JWKS JSON document, verify the embedded CRL signature against the
/// keys it publishes, and return the authenticated [`CrlBody`].
///
/// Fail-closed: any error means the caller must leave the cache untouched.
pub fn ingest(jwks_json: &str) -> Result<CrlBody, CrlIngestError> {
    let jwks: JwkSet = serde_json::from_str(jwks_json)
        .map_err(|e| CrlIngestError::MalformedJwks(e.to_string()))?;
    let signed = jwks.crl.as_ref().ok_or(CrlIngestError::Absent)?;
    let body = signed.verify(&jwks)?;
    Ok(body.clone())
}

/// Fetch the JWKS once, verify the embedded CRL, and update `cache` on success.
///
/// On any error the cache is left unchanged and the error is returned so the
/// caller can log it; the cached CRL then ages out and the gate fails closed.
pub async fn refresh_once(
    client: &mut ferro_proto::v1::machine_identity_client::MachineIdentityClient<
        tonic::transport::Channel,
    >,
    cache: &CrlCache,
) -> Result<u64, CrlRefreshError> {
    let jwks_json = client
        .jwks(tonic::Request::new(ferro_proto::v1::JwksRequest {}))
        .await?
        .into_inner()
        .jwks_json;
    let body = ingest(&jwks_json)?;
    let number = body.number;
    cache.store(body).await;
    Ok(number)
}

/// Failure modes for a CRL refresh.
#[derive(Debug, thiserror::Error)]
pub enum CrlRefreshError {
    /// The `JWKS` RPC failed.
    #[error("transport: {0}")]
    Transport(#[from] tonic::Status),
    /// The fetched JWKS could not be ingested.
    #[error(transparent)]
    Ingest(#[from] CrlIngestError),
}

/// Spawn a background task that refreshes `cache` from `client` every
/// `interval`. The task pulls immediately, then on each tick; a failed pull is
/// logged and retried next tick, leaving the cache to age out (fail closed).
#[must_use = "the puller stops when the join handle is dropped"]
pub fn spawn_puller(
    mut client: ferro_proto::v1::machine_identity_client::MachineIdentityClient<
        tonic::transport::Channel,
    >,
    cache: Arc<CrlCache>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match refresh_once(&mut client, &cache).await {
                Ok(number) => tracing::debug!(crl_number = number, "CRL refreshed"),
                Err(e) => tracing::warn!(error = %e, "CRL refresh failed; cache left stale"),
            }
            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_crypto::composite::CompositeSecretKey;
    use ferro_svid::{CrlEntry, Issuer, Jwk, RevocationTarget, SignedCrl};

    fn issuer() -> Issuer {
        Issuer::generate("cmis-1", "ferrogate.test").unwrap()
    }

    /// Build a JWKS JSON document carrying a CRL signed by `iss`.
    fn jwks_json_with_crl(iss: &Issuer, body: CrlBody) -> String {
        let mut set = iss.jwks();
        set.crl = Some(iss.sign_crl(body).unwrap());
        serde_json::to_string(&set).unwrap()
    }

    fn fresh_body(now: i64, entries: Vec<CrlEntry>) -> CrlBody {
        CrlBody {
            issued_at: now,
            number: 7,
            entries,
        }
    }

    #[tokio::test]
    async fn gate_refuses_when_empty() {
        let cache = CrlCache::new();
        assert_eq!(
            cache.gate("ab", "spiffe://x/host/y", 1_000).await,
            CrlGate::Stale
        );
    }

    #[tokio::test]
    async fn gate_refuses_when_stale() {
        let cache = CrlCache::seeded(fresh_body(0, vec![]));
        // 0 + 300 + 60 leeway window; 1_000 is well past.
        assert_eq!(
            cache.gate("ab", "spiffe://x/host/y", 1_000).await,
            CrlGate::Stale
        );
    }

    #[tokio::test]
    async fn gate_allows_fresh_clean_crl() {
        let cache = CrlCache::seeded(fresh_body(1_000, vec![]));
        assert_eq!(
            cache.gate("ab", "spiffe://x/host/y", 1_000).await,
            CrlGate::Ok
        );
    }

    #[tokio::test]
    async fn gate_blocks_revoked_svid_and_host() {
        let cache = CrlCache::seeded(fresh_body(
            1_000,
            vec![CrlEntry::new(
                RevocationTarget::Svid {
                    cert_sha: "ab".repeat(48),
                },
                "key-compromise",
                1_000,
            )],
        ));
        assert_eq!(
            cache
                .gate(&"ab".repeat(48), "spiffe://x/host/y", 1_000)
                .await,
            CrlGate::Revoked
        );

        let cache = CrlCache::seeded(fresh_body(
            1_000,
            vec![CrlEntry::new(
                RevocationTarget::Host {
                    spiffe_id: "spiffe://x/host/bad".into(),
                },
                "decommissioned",
                1_000,
            )],
        ));
        assert_eq!(
            cache.gate("00", "spiffe://x/host/bad", 1_000).await,
            CrlGate::Revoked
        );
    }

    #[test]
    fn ingest_accepts_well_signed_crl() {
        let iss = issuer();
        let json = jwks_json_with_crl(&iss, fresh_body(500, vec![]));
        let body = ingest(&json).unwrap();
        assert_eq!(body.number, 7);
    }

    #[test]
    fn ingest_rejects_absent_crl() {
        let iss = issuer();
        let json = serde_json::to_string(&iss.jwks()).unwrap();
        assert!(matches!(ingest(&json), Err(CrlIngestError::Absent)));
    }

    #[test]
    fn ingest_fails_closed_on_tampered_signature() {
        let iss = issuer();
        let json = jwks_json_with_crl(&iss, fresh_body(500, vec![]));
        // Replace the CRL with one signed by a *different* issuer but keep the
        // published key — the signature must not verify.
        let mut set: JwkSet = serde_json::from_str(&json).unwrap();
        let other = issuer();
        let mut forged = other.sign_crl(fresh_body(500, vec![])).unwrap();
        // Keep the kid the verifier will look up, but the bytes are wrong key.
        forged.signer_kid = "cmis-1".to_string();
        set.crl = Some(forged);
        let tampered = serde_json::to_string(&set).unwrap();
        assert!(matches!(ingest(&tampered), Err(CrlIngestError::Verify(_))));
    }

    #[test]
    fn ingest_fails_closed_on_unknown_kid() {
        let iss = issuer();
        let body = fresh_body(500, vec![]);
        // Sign with a kid that isn't in the published JWKS.
        let (sk, _pk) = CompositeSecretKey::generate().unwrap();
        let signed = SignedCrl::sign(body, "ghost-kid", &sk).unwrap();
        let mut set = iss.jwks();
        // Ensure the published key id differs from the signer kid.
        set.keys = vec![Jwk::from_public_key("cmis-1", iss.public_key())];
        set.crl = Some(signed);
        let json = serde_json::to_string(&set).unwrap();
        assert!(matches!(
            ingest(&json),
            Err(CrlIngestError::Verify(ferro_svid::CrlError::UnknownKid(_)))
        ));
    }
}
