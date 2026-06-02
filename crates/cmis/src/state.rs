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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

use ferro_attest::TpmQuoteVerifier;
use ferro_audit::AuditLog;
use ferro_crypto::composite::CompositePublicKey;
use ferro_raft::{Cluster, NodeRole};
use ferro_svid::{
    child_signing_kid, CrlBody, CrlEntry, IssueParams, IssuedSvid, Issuer, Jwk, JwkSet,
    LastAttestation, RevocationTarget, SignedCrl,
};
use parking_lot::RwLock;

use crate::cluster_store;
use crate::credential::CredentialMaker;
use crate::fleet_manifest::{EnrollmentDecision, FleetStore};

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
    /// Static issuance policy. Note that `config.policy_epoch` is only the
    /// *seed* value; the live epoch is held in [`policy_epoch`] so the
    /// `BumpEpoch` admin RPC can advance it at runtime.
    ///
    /// [`policy_epoch`]: CmisState::current_epoch
    pub config: CmisConfig,
    /// The live RIM policy epoch (feature F10), seeded from
    /// `config.policy_epoch` and advanced by [`CmisState::bump_epoch`]. Read it
    /// via [`CmisState::current_epoch`] — never `config.policy_epoch` directly,
    /// which is frozen at construction.
    policy_epoch: AtomicU64,
    /// Append-only audit log (Merkle tree + WORM store + STH signer).
    pub audit: AuditLog,
    /// Verification keys published over the `JWKS` RPC: the issuer's SVID key
    /// plus the per-host child-token signing keys registered at attestation
    /// time (feature F09). Process-local — see [`CmisState::register_child_key`].
    published_keys: RwLock<Vec<Jwk>>,
    /// Additional **root** verification keys published alongside the issuer's
    /// own root during a cross-sign rotation window (feature F14). These plus
    /// the issuer key are served ahead of the per-host child keys, ordered
    /// newest-first by [`Jwk::created`] so a verifier prefers the incoming root.
    /// Process-local — populated by [`CmisState::register_root_key`].
    extra_roots: RwLock<Vec<Jwk>>,
    /// Revocation state (feature F11). `entries` is the working set of active
    /// revocations; `crl` is the most recently published composite-signed CRL
    /// served in the `x-ferrogate-crl` JWKS extension. Both are process-local —
    /// replicating revocations across the cluster is a documented seam (see
    /// [`CmisState::revoke`]).
    revocations: Mutex<Revocations>,
    published_crl: RwLock<Option<SignedCrl>>,
    /// The live fleet-enrolment set consulted at the start of `Attest`
    /// (feature F13). Defaults to *unenforced* — every host is admitted — until
    /// a signed manifest is loaded via the [`FleetStore`] handle, so a CMIS with
    /// no manifest configured behaves exactly as it did pre-F13.
    fleet: FleetStore,
    backend: Backend,
}

/// The mutable revocation working set.
#[derive(Default)]
struct Revocations {
    entries: Vec<CrlEntry>,
    /// Monotonic CRL sequence number; bumped on every publish.
    number: u64,
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
            policy_epoch: AtomicU64::new(config.policy_epoch),
            config,
            audit,
            published_keys,
            extra_roots: RwLock::new(Vec::new()),
            revocations: Mutex::new(Revocations::default()),
            published_crl: RwLock::new(None),
            fleet: FleetStore::unenforced(),
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
            policy_epoch: AtomicU64::new(config.policy_epoch),
            config,
            audit,
            published_keys,
            extra_roots: RwLock::new(Vec::new()),
            revocations: Mutex::new(Revocations::default()),
            published_crl: RwLock::new(None),
            fleet: FleetStore::unenforced(),
            backend: Backend::Cluster(cluster),
        }
    }

    /// Borrow the fleet-enrolment store handle (feature F13). Clone it to hand
    /// to a [`crate::fleet_manifest::FleetManifestLoader`]; a manifest applied
    /// through that loader is immediately visible to [`check_enrollment`].
    ///
    /// [`check_enrollment`]: CmisState::check_enrollment
    #[must_use]
    pub fn fleet(&self) -> &FleetStore {
        &self.fleet
    }

    /// Decide whether a host presenting EK-cert hash `ek_sha` is admitted to the
    /// attestation handshake. With no manifest configured this is always
    /// [`EnrollmentDecision::NotEnforced`]; once a signed manifest is loaded an
    /// un-enrolled host is [`EnrollmentDecision::Rejected`] before any TPM
    /// verification work runs.
    #[must_use]
    pub fn check_enrollment(&self, ek_sha: &[u8; 48]) -> EnrollmentDecision {
        self.fleet.decide(ek_sha)
    }

    /// The JWK set published over the `JWKS` RPC.
    ///
    /// Ordering is **roots first, newest-first, then child keys**: the issuer's
    /// own root key together with any cross-sign-window roots registered via
    /// [`register_root_key`] lead the set sorted by [`Jwk::created`] descending,
    /// followed by the per-host child-token signing keys seen so far. The
    /// newest-first root ordering is the "newer preferred" rule of feature F14;
    /// downstream verifiers still resolve a token's header `kid` by exact match
    /// (see [`JwkSet::find`]), so the ordering only affects trust-anchor choice.
    ///
    /// [`register_root_key`]: CmisState::register_root_key
    #[must_use]
    pub fn published_jwks(&self) -> JwkSet {
        let published = self.published_keys.read();
        // By construction the issuer's root key is `published_keys[0]`; every
        // key appended by `register_child_key` follows it.
        let (issuer_root, child_keys) = published
            .split_first()
            .map_or((None, &[][..]), |(head, tail)| (Some(head.clone()), tail));

        let mut roots: Vec<Jwk> = issuer_root.into_iter().collect();
        roots.extend(self.extra_roots.read().iter().cloned());
        // Stable sort by creation time, newest first; an absent timestamp (the
        // bare issuer key) sorts oldest.
        roots.sort_by(|a, b| {
            b.created
                .unwrap_or(i64::MIN)
                .cmp(&a.created.unwrap_or(i64::MIN))
        });

        let mut keys = roots;
        keys.extend(child_keys.iter().cloned());
        JwkSet {
            keys,
            crl: self.published_crl.read().clone(),
        }
    }

    /// Publish an additional **root** verification key during a cross-sign
    /// rotation window (feature F14). The incoming root is stamped with a
    /// `created` time so [`published_jwks`] orders it ahead of the outgoing root
    /// under the "newer preferred" rule, while both remain resolvable by `kid`
    /// so SVIDs signed by either validate through the window. Idempotent by
    /// `kid`; re-registering a known root refreshes its `created` stamp.
    ///
    /// Process-local, mirroring [`register_child_key`]: replicating the window's
    /// root set across the cluster is a deployment seam left for a later slice.
    ///
    /// [`published_jwks`]: CmisState::published_jwks
    /// [`register_child_key`]: CmisState::register_child_key
    pub fn register_root_key(&self, pk: &CompositePublicKey, kid: impl Into<String>, created: i64) {
        let kid = kid.into();
        let mut roots = self.extra_roots.write();
        if let Some(existing) = roots.iter_mut().find(|k| k.kid == kid) {
            existing.created = Some(created);
            return;
        }
        roots.push(Jwk::from_public_key_at(kid, pk, created));
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

    /// Add a revocation to the working set (feature F11). Idempotent per target:
    /// re-revoking the same SVID or host refreshes the reason/timestamp rather
    /// than appending a duplicate. The caller publishes a fresh CRL afterwards
    /// (see [`CmisState::publish_crl`]) so the change reaches consumers within
    /// one publish cycle.
    ///
    /// The working set is **process-local**: replicating revocations through the
    /// Raft store so any replica's CRL reflects them is a deployment seam left
    /// for a later slice, mirroring the per-host JWKS registry note above.
    pub fn revoke(&self, target: RevocationTarget, reason: impl Into<String>, now: i64) {
        let entry = CrlEntry::new(target, reason, now);
        let mut revs = self.revocations.lock();
        if let Some(existing) = revs.entries.iter_mut().find(|e| e.target == entry.target) {
            *existing = entry;
        } else {
            revs.entries.push(entry);
        }
    }

    /// Build, sign, and publish a fresh CRL from the current working set.
    ///
    /// Expired entries (`expires_at <= now`) are pruned first — once an SVID's
    /// max TTL has elapsed it can never reappear, so dropping the entry bounds
    /// CRL growth (the F11 "CRL bloat" mitigation). `issued_at` is set to `now`
    /// and the sequence number is bumped on every call, so a stalled publisher
    /// is detectable by a consumer's freshness check even when the entry set is
    /// unchanged. Returns the published CRL's sequence number.
    pub fn publish_crl(&self, now: i64) -> Result<u64, ferro_svid::IssueError> {
        let (entries, number) = {
            let mut revs = self.revocations.lock();
            revs.entries.retain(|e| e.expires_at > now);
            revs.number += 1;
            (revs.entries.clone(), revs.number)
        };
        let body = CrlBody {
            issued_at: now,
            number,
            entries,
        };
        let signed = self.issuer.sign_crl(body)?;
        *self.published_crl.write() = Some(signed);
        Ok(number)
    }

    /// Borrow the local Raft cluster handle, if this state is clustered.
    #[must_use]
    pub fn cluster(&self) -> Option<&Arc<Cluster>> {
        match &self.backend {
            Backend::Cluster(c) => Some(c),
            Backend::Local(_) => None,
        }
    }

    /// The live RIM policy epoch (feature F10). Read this — not
    /// `config.policy_epoch` — wherever the current epoch gates a decision
    /// (issuance stamping, `Rotate` renewal), so a runtime `BumpEpoch` is seen.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.policy_epoch.load(Ordering::SeqCst)
    }

    /// Bump the live RIM policy epoch by one and return `(old, new)`.
    ///
    /// After this returns, every host whose stored `last_attestation.policy_epoch`
    /// is the old value is forced through a full re-attestation on its next
    /// `Rotate` (see `ferro_svid::decide_renewal`). The bump is process-local,
    /// mirroring the revocation working set: replicating it through the Raft
    /// store so every replica advances together is a documented deployment seam.
    pub fn bump_epoch(&self) -> (u64, u64) {
        let old = self.policy_epoch.fetch_add(1, Ordering::SeqCst);
        (old, old + 1)
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

    /// Enumerate every issued-SVID record this node knows about.
    ///
    /// On a single replica this is the process-local store; on a clustered
    /// deployment it is the full replicated set (an ordinary, eventually
    /// consistent read — an operator inventory does not need a leader round
    /// trip). A record whose clustered payload fails to decode is logged and
    /// skipped rather than failing the whole listing.
    pub async fn list_svids(&self) -> Vec<IssuedRecord> {
        match &self.backend {
            Backend::Local(map) => map.lock().values().cloned().collect(),
            Backend::Cluster(c) => match c.list_svids().await {
                Ok(rows) => rows
                    .into_iter()
                    .filter_map(|(spiffe_id, payload)| match cluster_store::decode(&payload) {
                        Ok(rec) => Some(rec),
                        Err(e) => {
                            tracing::error!(error = %e, %spiffe_id, "cluster decode failed");
                            None
                        }
                    })
                    .collect(),
                Err(e) => {
                    tracing::error!(error = %e, "cluster list_svids failed");
                    Vec::new()
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
