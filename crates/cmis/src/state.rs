//! Shared CMIS issuance state: the composite issuer, the quote verifier, the
//! credential-activation seam, and the store of issued SVIDs used to gate
//! `Rotate`.
//!
//! Two backends are supported behind a single API:
//!
//! - **Single-replica** (M2 default): a process-local `HashMap`.
//! - **Clustered** (F05): a hiqlite-backed Raft cluster shared by all CMIS
//!   replicas. Writes go through the leader; reads on followers are strongly
//!   consistent so a freshly-issued SVID is visible on the next hop.
//!
//! The backend is chosen at construction time and stays fixed for the lifetime
//! of the state. Callers never branch on the backend — they call the async
//! `record` / `lookup` / `update_bundle` methods and the implementation routes.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

use ferro_attest::TpmQuoteVerifier;
use ferro_audit::AuditLog;
use ferro_crypto::composite::CompositePublicKey;
use ferro_raft::{Cluster, NodeRole};
use ferro_svid::{
    child_signing_kid, IssueParams, IssuedSvid, Issuer, Jwk, JwkSet, LastAttestation,
};
use parking_lot::RwLock;

use crate::cluster_store;
use crate::credential::CredentialMaker;

/// Static issuance policy for a CMIS instance.
#[derive(Debug, Clone)]
pub struct CmisConfig {
    /// SPIFFE trust domain, e.g. `ferrogate.prod`.
    pub trust_domain: String,
    /// SVID lifetime in seconds (clamped to one hour by the issuer).
    pub svid_ttl_secs: u64,
    /// The live RIM policy epoch. A bump forces re-attestation on `Rotate`.
    pub policy_epoch: u64,
}

impl Default for CmisConfig {
    fn default() -> Self {
        Self {
            trust_domain: "ferrogate.dev".to_string(),
            svid_ttl_secs: 3600,
            policy_epoch: 1,
        }
    }
}

/// Everything needed to re-issue and gate renewals for one host.
#[derive(Debug, Clone)]
pub struct IssuedRecord {
    /// Parameters captured at the last full attestation, replayed on renewal.
    pub params: IssueParams,
    /// State gating renewal-vs-re-attestation.
    pub last_attestation: LastAttestation,
    /// The most recently issued bundle.
    pub bundle: IssuedSvid,
}

/// Process-wide CMIS state behind an `Arc`.
pub struct CmisState {
    /// The composite SVID issuer.
    pub issuer: Issuer,
    /// The TPM quote verifier (vendor roots + RIM allowlist).
    pub verifier: TpmQuoteVerifier,
    /// Phase-3 credential wrapper.
    pub credential_maker: Box<dyn CredentialMaker>,
    /// Static issuance policy.
    pub config: CmisConfig,
    /// Append-only audit log (Merkle tree + WORM store + STH signer).
    pub audit: AuditLog,
    /// Verification keys published over the `JWKS` RPC: the issuer's SVID key
    /// plus the per-host child-token signing keys registered at attestation
    /// time (feature F09). Process-local — see [`CmisState::register_child_key`].
    published_keys: RwLock<Vec<Jwk>>,
    backend: Backend,
}

enum Backend {
    Local(Mutex<HashMap<String, IssuedRecord>>),
    Cluster(Arc<Cluster>),
}

impl CmisState {
    /// Assemble single-replica CMIS state from its parts.
    #[must_use]
    pub fn new(
        issuer: Issuer,
        verifier: TpmQuoteVerifier,
        credential_maker: Box<dyn CredentialMaker>,
        config: CmisConfig,
        audit: AuditLog,
    ) -> Self {
        let published_keys = RwLock::new(issuer.jwks().keys);
        Self {
            issuer,
            verifier,
            credential_maker,
            config,
            audit,
            published_keys,
            backend: Backend::Local(Mutex::new(HashMap::new())),
        }
    }

    /// Assemble clustered CMIS state — the issued-SVID store is mediated by
    /// the provided `cluster` handle. All other fields behave the same.
    #[must_use]
    pub fn new_clustered(
        issuer: Issuer,
        verifier: TpmQuoteVerifier,
        credential_maker: Box<dyn CredentialMaker>,
        config: CmisConfig,
        audit: AuditLog,
        cluster: Arc<Cluster>,
    ) -> Self {
        let published_keys = RwLock::new(issuer.jwks().keys);
        Self {
            issuer,
            verifier,
            credential_maker,
            config,
            audit,
            published_keys,
            backend: Backend::Cluster(cluster),
        }
    }

    /// The JWK set published over the `JWKS` RPC: the issuer's SVID signing key
    /// (always first) followed by the host child-token signing keys seen so
    /// far. Downstream verifiers resolve a child token's header `kid` here.
    #[must_use]
    pub fn published_jwks(&self) -> JwkSet {
        JwkSet {
            keys: self.published_keys.read().clone(),
        }
    }

    /// Publish a host's composite child-token signing key so verifiers can find
    /// it by `kid`. Idempotent — a key already present (by kid) is left alone,
    /// so repeated attestations by the same host do not grow the set.
    ///
    /// The registry is **process-local**: a verifier must query a replica that
    /// has witnessed the host's attestation. Persisting `composite_pub` into the
    /// clustered issued-SVID store so any replica can publish it is a deployment
    /// seam left for a later slice.
    pub fn register_child_key(&self, pk: &CompositePublicKey) {
        let kid = child_signing_kid(pk);
        let mut keys = self.published_keys.write();
        if keys.iter().any(|k| k.kid == kid) {
            return;
        }
        keys.push(Jwk::from_public_key(kid, pk));
    }

    /// Borrow the local Raft cluster handle, if this state is clustered.
    #[must_use]
    pub fn cluster(&self) -> Option<&Arc<Cluster>> {
        match &self.backend {
            Backend::Cluster(c) => Some(c),
            Backend::Local(_) => None,
        }
    }

    /// Fill an N-byte buffer from the OS CSPRNG (nonces, phase-3 secrets).
    #[must_use]
    pub fn random_bytes<const N: usize>(&self) -> [u8; N] {
        let mut buf = [0u8; N];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    /// Record a freshly attested+issued SVID, keyed by subject SPIFFE ID.
    pub async fn record(&self, record: IssuedRecord) {
        match &self.backend {
            Backend::Local(map) => {
                map.lock().insert(record.bundle.spiffe_id.clone(), record);
            }
            Backend::Cluster(c) => {
                let spiffe_id = record.bundle.spiffe_id.clone();
                match cluster_store::encode(&record) {
                    Ok(payload) => {
                        if let Err(e) = c.upsert_svid(&spiffe_id, &payload, record.bundle.iat).await
                        {
                            tracing::error!(error = %e, %spiffe_id, "cluster upsert failed");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, %spiffe_id, "cluster encode failed");
                    }
                }
            }
        }
    }

    /// Look up the stored record for a subject. Cluster reads are
    /// strongly-consistent so a follower never serves a stale record after a
    /// successful `record` on the leader.
    pub async fn lookup(&self, spiffe_id: &str) -> Option<IssuedRecord> {
        match &self.backend {
            Backend::Local(map) => map.lock().get(spiffe_id).cloned(),
            Backend::Cluster(c) => match c.fetch_svid_consistent(spiffe_id).await {
                Ok(Some(bytes)) => match cluster_store::decode(&bytes) {
                    Ok(rec) => Some(rec),
                    Err(e) => {
                        tracing::error!(error = %e, %spiffe_id, "cluster decode failed");
                        None
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    tracing::error!(error = %e, %spiffe_id, "cluster fetch failed");
                    None
                }
            },
        }
    }

    /// Replace the stored bundle for a subject after a renewal (the
    /// `last_attestation` window is intentionally left unchanged).
    pub async fn update_bundle(&self, spiffe_id: &str, bundle: IssuedSvid) {
        match &self.backend {
            Backend::Local(map) => {
                if let Some(rec) = map.lock().get_mut(spiffe_id) {
                    rec.bundle = bundle;
                }
            }
            Backend::Cluster(_) => {
                // Read-modify-write through the cluster. Two concurrent
                // rotations for the same subject would race; CMIS serialises
                // them per-subject upstream (`Rotate` decides off the looked-up
                // record before issuance), so the loss window is small and
                // benign — the later writer wins and both bundles are valid.
                if let Some(mut rec) = self.lookup(spiffe_id).await {
                    rec.bundle = bundle;
                    self.record(rec).await;
                }
            }
        }
    }

    /// Coarse health summary for the `Health` gRPC. Local-only states are
    /// always healthy and always report `Unknown` for role.
    pub async fn health(&self) -> (bool, NodeRole) {
        match &self.backend {
            Backend::Local(_) => (true, NodeRole::Unknown),
            Backend::Cluster(c) => {
                let healthy = c.is_healthy().await;
                let role = if healthy {
                    c.role().await
                } else {
                    NodeRole::Unknown
                };
                (healthy, role)
            }
        }
    }
}
