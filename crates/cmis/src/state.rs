//! Shared CMIS issuance state: the composite issuer, the quote verifier, the
//! credential-activation seam, and the store of issued SVIDs used to gate
//! `Rotate`.
//!
//! All durable state (issued SVIDs, host allowlists, pending allowlist
//! proposals) lives in the hiqlite-backed Raft cluster (F05), so it survives
//! restarts. A single-replica deployment runs a one-node cluster — same code
//! path, same SQLite persistence, no peer discovery (see
//! [`ferro_raft::ClusterConfig::single_node`]). Writes go through the leader;
//! reads on followers are strongly consistent so a freshly-issued SVID is
//! visible on the next hop.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use getrandom::SysRng;
use parking_lot::Mutex;
use rand_core::{Rng as _, UnwrapErr};

use ferro_attest::TpmQuoteVerifier;
use ferro_audit::AuditLog;
use ferro_crypto::composite::CompositePublicKey;
use ferro_raft::{Cluster, ClusterError, NodeRole};
use ferro_svid::{
    child_signing_kid, CrlBody, CrlEntry, IssueParams, IssuedSvid, Issuer, Jwk, JwkSet,
    LastAttestation, RevocationTarget, SignedCrl,
};
use parking_lot::RwLock;
use sha2::{Digest as _, Sha384};

use crate::cluster_store;
use crate::credential::CredentialMaker;
use crate::fleet_manifest::{EnrollmentDecision, FleetStore};
use crate::host_auth::{HostCallConfig, HostCallGuard};

/// How CMIS treats a host-driven allowlist proposal (see `ProposeAllowlist`).
/// All variants still verify the proposal's SVID + signature first; this only
/// governs whether an accepted proposal becomes the live allowlist on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProposalPolicy {
    /// Never auto-adopt: every proposal queues for operator review.
    Off,
    /// Auto-adopt only when the host has no allowlist yet (first-use bootstrap,
    /// TOFU); any change to an existing allowlist queues for review.
    #[default]
    BootstrapOnly,
    /// Auto-adopt every accepted proposal, including changes to an existing
    /// allowlist. Most convenient, weakest — see docs/mia.md.
    Always,
}

impl ProposalPolicy {
    /// Parse the `CMIS_ALLOWLIST_PROPOSALS` env value; unknown/empty ⇒ default.
    #[must_use]
    pub fn from_env_value(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" => Self::Off,
            "always" => Self::Always,
            _ => Self::BootstrapOnly,
        }
    }
}

/// Static issuance policy for a CMIS instance.
#[derive(Debug, Clone)]
pub struct CmisConfig {
    /// SPIFFE trust domain, e.g. `ferrogate.prod`.
    pub trust_domain: String,
    /// SVID lifetime in seconds. Floored at [`ferro_svid::MIN_TTL_SECS`] (96 h)
    /// and clamped to [`ferro_svid::MAX_TTL_SECS`] (30 days) by the issuer.
    pub svid_ttl_secs: u64,
    /// Caller-allowlist signature lifetime in seconds — the validity window
    /// stamped on each served allowlist. `GetAllowlist` auto-renews an aging
    /// allowlist (re-signs with a fresh window once it is past half-life), so a
    /// host that keeps fetching never sees its allowlist rot into a `TooOld`/
    /// `Expired` rejection. Should be ≤ the MIA's `allowlist.max_age_secs` so the
    /// served window and the MIA's staleness bound agree (both default 72 h).
    /// Capped at 30 days and floored at 1 h when loaded from the environment.
    pub allowlist_ttl_secs: i64,
    /// The live RIM policy epoch. A bump forces re-attestation on `Rotate`.
    pub policy_epoch: u64,
    /// How host-driven allowlist proposals are handled (`ProposeAllowlist`).
    pub allowlist_proposal_policy: ProposalPolicy,
    /// Require software **host-key** nodes (F15/F16) to be pre-registered in the
    /// fleet manifest, refusing trust-on-first-use. The software host-key tier
    /// has no hardware root of trust, so TOFU means the first attester for a
    /// fingerprint defines the identity; enabling this closes that window.
    /// Defaults to `false` (TOFU) for backward compatibility; production
    /// deployments that use the software tier should enable it.
    pub require_preregistered_host_key: bool,
    /// Optional shorter SVID lifetime (seconds) for the software host-key tier.
    /// `None` ⇒ use [`Self::svid_ttl_secs`]. A shorter TTL makes the
    /// lower-assurance software identities re-attest more often.
    pub host_key_svid_ttl_secs: Option<u64>,
    /// Host call authentication limits (F19 §7.1; `AppendAuditEvent` rate,
    /// `CMIS_AUDIT_FORWARD_MAX_PER_MIN`, and the F19 host RPC budgets).
    pub host_calls: HostCallConfig,
    /// F19 application-approval policy (`CMIS_APP_*`, `CMIS_APPROVAL_*`).
    pub apps: crate::apps::AppConfig,
}

impl Default for CmisConfig {
    fn default() -> Self {
        Self {
            trust_domain: "ferrogate.dev".to_string(),
            svid_ttl_secs: 30 * 24 * 3600,
            // 72 h served window; auto-renewed past half-life on each fetch.
            allowlist_ttl_secs: 72 * 3600,
            policy_epoch: 1,
            allowlist_proposal_policy: ProposalPolicy::default(),
            require_preregistered_host_key: false,
            host_key_svid_ttl_secs: None,
            host_calls: HostCallConfig::default(),
            apps: crate::apps::AppConfig::default(),
        }
    }
}

/// The outcome of [`CmisState::replace_bundle_if_current`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleSwap {
    /// The new bundle is stored.
    Replaced,
    /// The stored record no longer holds the expected SVID (another renewal
    /// or a re-attestation won), or is gone; nothing was written.
    Superseded,
    /// The replicated store failed; nothing was written (cause logged).
    StoreFailed,
}

/// A stored issued-SVID record could not be read: the replicated store failed
/// or the row did not decode. The cause is logged by the state layer, never
/// returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("issued-SVID store unavailable")]
pub struct RecordUnavailable;

/// Everything needed to re-issue and gate renewals for one host.
#[derive(Debug, Clone)]
pub struct IssuedRecord {
    /// Parameters captured at the last full attestation, replayed on renewal.
    pub params: IssueParams,
    /// State gating renewal-vs-re-attestation.
    pub last_attestation: LastAttestation,
    /// The most recently issued bundle.
    pub bundle: IssuedSvid,
    /// The host's self-reported hostname at the last full attestation.
    /// Display-only operator convenience — never identity, never verified.
    pub hostname: Option<String>,
    /// The host's composite child-token signing key (F09) as concat bytes, when
    /// the attestation CSR carried a well-formed one. Persisted so any replica —
    /// and any restarted instance — can republish it into the JWKS by `kid` (see
    /// [`CmisState::rehydrate_child_keys`]); `None` for records written before
    /// this field existed or whose CSR key failed to parse.
    pub child_pub: Option<Vec<u8>>,
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
    /// Trust-on-first-use bindings for the TPM-less host-key profile (F15):
    /// `fingerprint → machine key (DER SPKI)`. The first attestation for a
    /// fingerprint pins its key; later attestations must present the same key.
    /// A pre-registered key in the fleet manifest overrides this (no TOFU).
    ///
    /// Process-local, like the revocation and child-key registries: replicating
    /// the pin through the Raft store so every replica enforces the same binding
    /// is a documented deployment seam.
    host_key_pins: Mutex<HashMap<[u8; 48], Vec<u8>>>,
    /// Host call authentication state (F19 §7.1): the per-node nonce replay
    /// cache and per-host rate limiters used by [`crate::host_auth`].
    pub host_calls: HostCallGuard,
    /// Signed v1 bodies served by `GetAllowlist` in `approvals` mode (F19
    /// §6.4), per node; see [`crate::apps::v1`].
    legacy_v1: crate::apps::v1::V1Cache,
    /// The Raft cluster mediating all durable state: issued SVIDs
    /// (`issued_svids`), per-host signed allowlists (`host_allowlists`), and
    /// pending allowlist proposals (`pending_allowlist_proposals`). A
    /// single-replica deployment passes a one-node cluster.
    cluster: Arc<Cluster>,
}

/// One pending allowlist proposal as CMIS holds it for review.
#[derive(Debug, Clone)]
pub struct ProposalRecord {
    /// Proposed entries as opaque CBOR `Vec<ferro_svid::AllowEntry>`.
    pub entries_cbor: Vec<u8>,
    /// SVID subject (SPIFFE id) that submitted the proposal.
    pub proposer_spiffe_id: String,
    /// Unix seconds CMIS recorded the proposal.
    pub proposed_at: i64,
}

/// The outcome of binding a host fingerprint to its presented machine key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyBinding {
    /// First time this fingerprint was seen; its key is now pinned (TOFU).
    FirstSeen,
    /// The presented key matches the previously pinned (TOFU) key.
    Pinned,
    /// The presented key matches the operator pre-registered key.
    PreRegistered,
    /// The presented key does not match the bound key — reject and audit.
    Mismatch,
    /// Strict mode ([`CmisConfig::require_preregistered_host_key`]) is on and
    /// this fingerprint has no pre-registered key — reject without TOFU-pinning.
    RejectedNotPreRegistered,
}

/// The mutable revocation working set.
#[derive(Default)]
struct Revocations {
    entries: Vec<CrlEntry>,
    /// Monotonic CRL sequence number; bumped on every publish.
    number: u64,
}

impl CmisState {
    /// Assemble CMIS state — all durable stores are mediated by the provided
    /// `cluster` handle (a one-node cluster on a single-replica deployment).
    #[must_use]
    pub fn new(
        issuer: Issuer,
        verifier: TpmQuoteVerifier,
        credential_maker: Box<dyn CredentialMaker>,
        config: CmisConfig,
        audit: AuditLog,
        cluster: Arc<Cluster>,
    ) -> Self {
        let published_keys = RwLock::new(issuer.jwks().keys);
        let host_calls = HostCallGuard::new(config.host_calls);
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
            host_key_pins: Mutex::new(HashMap::new()),
            host_calls,
            legacy_v1: crate::apps::v1::V1Cache::new(),
            cluster,
        }
    }

    /// The per-node cache of signed lossy-safe v1 bodies (F19 §6.4).
    #[must_use]
    pub fn legacy_v1_cache(&self) -> &crate::apps::v1::V1Cache {
        &self.legacy_v1
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

    /// Bind a TPM-less host's fingerprint to its presented machine key (feature
    /// F15). If the active fleet manifest pre-registers a key for this
    /// fingerprint, require an exact match. Otherwise trust the key on first use
    /// and pin it for every later attestation. A presented key that differs
    /// from the bound one returns [`HostKeyBinding::Mismatch`] and is rejected
    /// by the caller.
    ///
    /// When `require_preregistered` is set, a fingerprint with no pre-registered
    /// key is refused ([`HostKeyBinding::RejectedNotPreRegistered`]) instead of
    /// being TOFU-pinned.
    pub fn bind_host_key(
        &self,
        fingerprint: &[u8; 48],
        sep_pub: &[u8],
        require_preregistered: bool,
    ) -> HostKeyBinding {
        // Operator pre-registration takes precedence over TOFU.
        if let Some(expected) = self.fleet.preregistered(fingerprint) {
            return if expected == sep_pub {
                HostKeyBinding::PreRegistered
            } else {
                HostKeyBinding::Mismatch
            };
        }
        // Strict mode: with no pre-registered key, refuse *without* pinning — a
        // TOFU pin here would let the next attempt appear `Pinned` and slip past
        // the requirement.
        if require_preregistered {
            return HostKeyBinding::RejectedNotPreRegistered;
        }
        let mut pins = self.host_key_pins.lock();
        match pins.get(fingerprint) {
            Some(existing) if existing.as_slice() == sep_pub => HostKeyBinding::Pinned,
            Some(_) => HostKeyBinding::Mismatch,
            None => {
                pins.insert(*fingerprint, sep_pub.to_vec());
                HostKeyBinding::FirstSeen
            }
        }
    }

    /// The JWK set published over the `JWKS` RPC.
    ///
    /// The set also carries the X.509-SVID trust bundle in its
    /// `x-ferrogate-x509-bundle` member, so a verifier arms both profiles from
    /// one fetch.
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
        let set = JwkSet {
            keys,
            crl: self.published_crl.read().clone(),
            x509_bundle: None,
        };
        // Publish the X.509-SVID trust anchor beside the JWS keys, so one JWKS
        // fetch arms a verifier for both profiles. A bundle this issuer cannot
        // build is a bug, not a runtime condition: log it and keep serving the
        // JWS profile rather than failing the whole RPC.
        match self.issuer.x509_ca() {
            Ok(der) => set.with_x509_bundle(der),
            Err(e) => {
                tracing::error!(error = %e, "could not build the X.509-SVID trust bundle");
                set
            }
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

    /// Repopulate the in-memory child-key registry from the replicated
    /// issued-SVID store. Called once at startup so a freshly restarted (or
    /// never-attested-to) replica still publishes every host's child-token
    /// signing key by `kid` — without this, a child token minted before the
    /// restart fails verification with `no key for kid host-…` until its host
    /// happens to re-attest. Counterpart to [`register_child_key`], which only
    /// updates the live process at attestation time.
    ///
    /// A record with no stored `child_pub` (written before the field existed)
    /// or an unparseable one is skipped — it simply will not be republished
    /// until that host next attests, the same as the pre-persistence behaviour.
    ///
    /// [`register_child_key`]: CmisState::register_child_key
    pub async fn rehydrate_child_keys(&self) {
        let records = self.list_svids().await;
        let mut restored = 0usize;
        for rec in records {
            let Some(bytes) = rec.child_pub.as_deref() else {
                continue;
            };
            match CompositePublicKey::from_concat_bytes(bytes) {
                Ok(pk) => {
                    self.register_child_key(&pk);
                    restored += 1;
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    spiffe_id = %rec.bundle.spiffe_id,
                    "stored child key did not parse; skipping JWKS rehydration"
                ),
            }
        }
        if restored > 0 {
            tracing::info!(restored, "rehydrated host child-token keys into the JWKS");
        }
    }

    /// On-miss rehydrate for a single requested `kid` (the `JWKS` RPC's
    /// `kid_hint`). `register_child_key` is process-local, so a replica that
    /// never witnessed a host's attestation — and has been up since before it,
    /// missing the startup [`rehydrate_child_keys`] pass — serves a JWKS
    /// without that host's key and every cross-node verification fails with
    /// `no key for kid host-…`. When a verifier names the kid it needs and the
    /// published set misses it, re-read the replicated store (where the
    /// attesting node persisted `child_pub`) before answering.
    ///
    /// Only `host-…` kids trigger the store read: issuer root kids are never
    /// in the issued-SVID store, so rescanning for them is pure waste. The
    /// full rehydrate (not a single-record fetch) is deliberate — it costs the
    /// same one store listing and heals every other missing host at once.
    /// Returns whether the kid is published after the attempt; the caller
    /// serves the (possibly refreshed) set either way, so an unknown kid
    /// still yields the verifier's normal `no key for kid` — just no longer
    /// spuriously.
    ///
    /// [`rehydrate_child_keys`]: CmisState::rehydrate_child_keys
    pub async fn ensure_child_key_published(&self, kid: &str) -> bool {
        let published = |keys: &[Jwk]| keys.iter().any(|k| k.kid == kid);
        if published(&self.published_keys.read()) {
            return true;
        }
        if !kid.starts_with("host-") {
            return false;
        }
        self.rehydrate_child_keys().await;
        let found = published(&self.published_keys.read());
        if found {
            tracing::info!(kid, "on-miss rehydrate published the requested child key");
        } else {
            tracing::warn!(
                kid,
                "kid requested via JWKS hint is not in the issued-SVID store"
            );
        }
        found
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

    /// Whether the revocation working set names the host `spiffe_id` or the
    /// SVID whose compact-JWS digest is `svid_cert_sha` (lowercase-hex
    /// SHA-384). Consulted by host call authentication ([`crate::host_auth`])
    /// so a revoked host cannot keep using its still-unexpired SVID.
    ///
    /// Process-local like the working set itself (see [`CmisState::revoke`]).
    #[must_use]
    pub fn is_revoked(&self, spiffe_id: &str, svid_cert_sha: &str) -> bool {
        self.revocations
            .lock()
            .entries
            .iter()
            .any(|e| match &e.target {
                RevocationTarget::Host { spiffe_id: s } => s == spiffe_id,
                RevocationTarget::Svid { cert_sha } => cert_sha.eq_ignore_ascii_case(svid_cert_sha),
            })
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

    /// Borrow the local Raft cluster handle.
    #[must_use]
    pub fn cluster(&self) -> &Arc<Cluster> {
        &self.cluster
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
        UnwrapErr(SysRng).fill_bytes(&mut buf);
        buf
    }

    /// Record a freshly attested+issued SVID, keyed by subject SPIFFE ID.
    pub async fn record(&self, record: IssuedRecord) {
        let spiffe_id = record.bundle.spiffe_id.clone();
        match cluster_store::encode(&record) {
            Ok(payload) => {
                if let Err(e) = self
                    .cluster
                    .upsert_svid(&spiffe_id, &payload, record.bundle.iat)
                    .await
                {
                    tracing::error!(error = %e, %spiffe_id, "cluster upsert failed");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, %spiffe_id, "cluster encode failed");
            }
        }
    }

    /// Look up the stored record for a subject. Reads are strongly-consistent
    /// so a follower never serves a stale record after a successful `record`
    /// on the leader. A store or decode failure reads as `None` (logged); a
    /// caller that must tell them apart uses [`Self::lookup_checked`].
    pub async fn lookup(&self, spiffe_id: &str) -> Option<IssuedRecord> {
        self.lookup_checked(spiffe_id).await.ok().flatten()
    }

    /// [`Self::lookup`], telling a missing record (`Ok(None)`) from a store
    /// that could not be read (`Err`, cause logged here).
    pub async fn lookup_checked(
        &self,
        spiffe_id: &str,
    ) -> Result<Option<IssuedRecord>, RecordUnavailable> {
        match self.cluster.fetch_svid_consistent(spiffe_id).await {
            Ok(Some(bytes)) => match cluster_store::decode(&bytes) {
                Ok(rec) => Ok(Some(rec)),
                Err(e) => {
                    tracing::error!(error = %e, %spiffe_id, "cluster decode failed");
                    Err(RecordUnavailable)
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                tracing::error!(error = %e, %spiffe_id, "cluster fetch failed");
                Err(RecordUnavailable)
            }
        }
    }

    /// Enumerate every issued-SVID record in the replicated store (an
    /// ordinary, eventually consistent read — an operator inventory does not
    /// need a leader round trip). A record whose payload fails to decode is
    /// logged and skipped rather than failing the whole listing.
    pub async fn list_svids(&self) -> Vec<IssuedRecord> {
        match self.cluster.list_svids().await {
            Ok(rows) => rows
                .into_iter()
                .filter_map(
                    |(spiffe_id, payload)| match cluster_store::decode(&payload) {
                        Ok(rec) => Some(rec),
                        Err(e) => {
                            tracing::error!(error = %e, %spiffe_id, "cluster decode failed");
                            None
                        }
                    },
                )
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "cluster list_svids failed");
                Vec::new()
            }
        }
    }

    /// Replace the stored bundle for a subject, unconditionally (the
    /// `last_attestation` window is left unchanged). Racy read-modify-write:
    /// a concurrent renewal is silently overwritten.
    #[deprecated(
        since = "0.30.0",
        note = "use `replace_bundle_if_current`, which re-checks the stored SVID inside the write"
    )]
    pub async fn update_bundle(&self, spiffe_id: &str, bundle: IssuedSvid) {
        if let Some(mut rec) = self.lookup(spiffe_id).await {
            rec.bundle = bundle;
            self.record(rec).await;
        }
    }

    /// Replace the stored bundle of `spiffe_id` with `bundle` only while the
    /// stored record still holds the SVID whose compact-JWS SHA-384 is
    /// `expected_jws_sha384` — checked by a compare-and-swap on the stored
    /// payload, so of two renewals racing from one SVID at most one lands
    /// (T293). `last_attestation` is left unchanged. Store failures are
    /// logged here and answered as [`BundleSwap::StoreFailed`].
    pub async fn replace_bundle_if_current(
        &self,
        spiffe_id: &str,
        expected_jws_sha384: &[u8; 48],
        bundle: IssuedSvid,
    ) -> BundleSwap {
        let current = match self.cluster.fetch_svid_consistent(spiffe_id).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return BundleSwap::Superseded,
            Err(e) => {
                tracing::error!(error = %e, %spiffe_id, "cluster fetch failed");
                return BundleSwap::StoreFailed;
            }
        };
        let mut rec = match cluster_store::decode(&current) {
            Ok(rec) => rec,
            Err(e) => {
                tracing::error!(error = %e, %spiffe_id, "cluster decode failed");
                return BundleSwap::StoreFailed;
            }
        };
        if Sha384::digest(rec.bundle.jws.as_bytes()).as_slice() != expected_jws_sha384 {
            return BundleSwap::Superseded;
        }
        let updated_at = bundle.iat;
        rec.bundle = bundle;
        let payload = match cluster_store::encode(&rec) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, %spiffe_id, "cluster encode failed");
                return BundleSwap::StoreFailed;
            }
        };
        match self
            .cluster
            .replace_svid_if_unchanged(spiffe_id, &current, &payload, updated_at)
            .await
        {
            Ok(true) => BundleSwap::Replaced,
            Ok(false) => BundleSwap::Superseded,
            Err(e) => {
                tracing::error!(error = %e, %spiffe_id, "cluster svid swap failed");
                BundleSwap::StoreFailed
            }
        }
    }

    /// Store or replace a host's signed caller allowlist, keyed by its
    /// EK-derived host UUID. `signed_bytes` is the opaque CBOR `SignedAllowlist`
    /// the issuer minted; the cluster treats it as a blob.
    ///
    /// A failed write is logged **and returned** — the caller must not report
    /// the change as made (F19 §7.4).
    pub async fn put_allowlist(
        &self,
        host_uuid: &str,
        signed_bytes: Vec<u8>,
        now: i64,
    ) -> Result<(), ClusterError> {
        self.cluster
            .upsert_allowlist(host_uuid, &signed_bytes, now)
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, %host_uuid, "cluster allowlist upsert failed");
            })
    }

    /// Store or replace a host's legacy allowlist only while the cluster is
    /// in `legacy` mode, checked in the write's own transaction (F19 §11:
    /// no legacy write lands after the switch to `approvals`). `Ok(false)`:
    /// refused, nothing written. Failures are logged and returned.
    pub async fn put_allowlist_in_legacy_mode(
        &self,
        host_uuid: &str,
        signed_bytes: &[u8],
        now: i64,
    ) -> Result<bool, ferro_raft::LedgerError> {
        self.cluster
            .upsert_allowlist_unless_setting(
                host_uuid,
                signed_bytes,
                now,
                crate::apps::mode::ALLOWLIST_MODE_KEY,
                crate::apps::AllowlistMode::Approvals.as_str(),
            )
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, %host_uuid, "cluster allowlist upsert failed");
            })
    }

    /// Delete a host's legacy allowlist only while the cluster is in
    /// `legacy` mode, checked in the same transaction. `Ok(None)`: refused;
    /// `Ok(Some(existed))` otherwise.
    pub async fn delete_allowlist_in_legacy_mode(
        &self,
        host_uuid: &str,
    ) -> Result<Option<bool>, ferro_raft::LedgerError> {
        self.cluster
            .delete_allowlist_unless_setting(
                host_uuid,
                crate::apps::mode::ALLOWLIST_MODE_KEY,
                crate::apps::AllowlistMode::Approvals.as_str(),
            )
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, %host_uuid, "cluster allowlist delete failed");
            })
    }

    /// Fetch a host's stored signed allowlist bytes, if any. Reads are
    /// strongly-consistent, mirroring [`CmisState::lookup`].
    pub async fn get_allowlist(&self, host_uuid: &str) -> Option<Vec<u8>> {
        match self.cluster.fetch_allowlist_consistent(host_uuid).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(error = %e, %host_uuid, "cluster allowlist fetch failed");
                None
            }
        }
    }

    /// Delete a host's stored allowlist. Returns whether one existed; a failed
    /// write is logged and returned, never reported as "absent".
    pub async fn delete_allowlist(&self, host_uuid: &str) -> Result<bool, ClusterError> {
        self.cluster
            .delete_allowlist(host_uuid)
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, %host_uuid, "cluster allowlist delete failed");
            })
    }

    /// Enumerate every stored `(host_uuid, signed_bytes)` allowlist, mirroring
    /// [`CmisState::list_svids`].
    pub async fn list_allowlists(&self) -> Vec<(String, Vec<u8>)> {
        match self.cluster.list_allowlists().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "cluster list_allowlists failed");
                Vec::new()
            }
        }
    }

    /// Store or replace a host's pending allowlist proposal. `entries_cbor` is
    /// the opaque CBOR `Vec<AllowEntry>` the host proposed; CMIS stamps the
    /// proposer SPIFFE id and time so an operator can review it later.
    ///
    /// A failed write is logged **and returned** (F19 §7.4).
    pub async fn put_proposal(
        &self,
        host_uuid: &str,
        rec: ProposalRecord,
    ) -> Result<(), ClusterError> {
        self.cluster
            .upsert_proposal(
                host_uuid,
                &rec.entries_cbor,
                &rec.proposer_spiffe_id,
                rec.proposed_at,
            )
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, %host_uuid, "cluster proposal upsert failed");
            })
    }

    /// Enumerate every pending `(host_uuid, ProposalRecord)`, mirroring
    /// [`CmisState::list_allowlists`].
    pub async fn list_proposals(&self) -> Vec<(String, ProposalRecord)> {
        match self.cluster.list_proposals().await {
            Ok(rows) => rows
                .into_iter()
                .map(
                    |(host_uuid, entries_cbor, proposer_spiffe_id, proposed_at)| {
                        (
                            host_uuid,
                            ProposalRecord {
                                entries_cbor,
                                proposer_spiffe_id,
                                proposed_at,
                            },
                        )
                    },
                )
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "cluster list_proposals failed");
                Vec::new()
            }
        }
    }

    /// Delete a host's pending proposal. Returns whether one existed; a failed
    /// write is logged and returned, never reported as "absent".
    pub async fn delete_proposal(&self, host_uuid: &str) -> Result<bool, ClusterError> {
        self.cluster
            .delete_proposal(host_uuid)
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, %host_uuid, "cluster proposal delete failed");
            })
    }

    /// Coarse health summary for the `Health` gRPC.
    pub async fn health(&self) -> (bool, NodeRole) {
        let healthy = self.cluster.is_healthy().await;
        let role = if healthy {
            self.cluster.role().await
        } else {
            NodeRole::Unknown
        };
        (healthy, role)
    }
}
