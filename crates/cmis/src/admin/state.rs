//! Shared admin-subsystem state: configuration, keys, the password hasher, the
//! clock, and the helpers every flow uses (sessions, throttling, TOTP checks,
//! nonces, device tokens, audit and the security log).
//!
//! Durable state lives in the replicated store ([`ferro_raft::admin`]). Two
//! small, bounded, per-node in-memory structures remain: the set of redeemed
//! login/step-up nonces (single use within their two-minute life) and the
//! per-IP `BeginLogin` rate window (10 per minute, F20 §8).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use subtle::ConstantTimeEq;
use tonic::Status;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use ferro_audit::AuditEvent;
use ferro_raft::admin::{AdminAccountRow, AdminSessionRow, ThrottleRow};
use ferro_raft::{Cluster, ClusterError};

use super::authz::{AdminContext, PeerInfo};
use super::clock::Clock;
use super::codec::{b64url, b64url_decode};
use super::config::AdminConfig;
use super::factors::Verified;
use super::keys::{read_or_create_key, AdminKeys, KeyFile};
use super::password::{Blocklist, PasswordHasher, Pepper};
use super::session::{self, Liveness, RevokeReason};
use super::throttle::{self, KeyKind};
use super::totp;
use super::webauthn::RelyingParty;
use crate::state::CmisState;

/// Lifetime of login and step-up nonces.
pub const NONCE_TTL_SECS: i64 = 120;
/// `BeginLogin` calls allowed per source IP per minute.
pub const BEGIN_LOGIN_PER_MINUTE: u32 = 10;
/// Device-token validity (F20 §6).
pub const DEVICE_TOKEN_TTL_SECS: i64 = 180 * 86_400;
/// Device-token prefix.
pub const DEVICE_TOKEN_PREFIX: &str = "fgdt_";
/// Failures across all keys in ten minutes that raise `AdminLoginAnomaly`.
pub const ANOMALY_FAILURES_10M: u64 = 20;

/// Length of a login, step-up or enrollment nonce (issued time, random, MAC).
pub(crate) const NONCE_LEN: usize = 8 + 16 + 16;
const USED_NONCE_SOFT_CAP: usize = 10_000;
const USED_NONCE_HARD_CAP: usize = 200_000;
const RATE_WINDOW_CAP: usize = 65_536;

/// Why the admin subsystem refused to start.
#[derive(Debug, thiserror::Error)]
pub enum AdminInitError {
    /// A key file could not be loaded.
    #[error(transparent)]
    Key(#[from] super::keys::KeyError),
    /// The blocklist file could not be read.
    #[error("password blocklist: {0}")]
    Blocklist(std::io::Error),
    /// The password hasher could not be built.
    #[error(transparent)]
    Password(#[from] super::password::PasswordError),
    /// The replicated store failed.
    #[error(transparent)]
    Store(#[from] ClusterError),
    /// This node's admin keys differ from the ones the cluster recorded.
    #[error("admin key files differ from the ones this cluster was set up with; copy the cluster's key files to this node")]
    KeyMismatch,
}

/// Admin-subsystem state shared by the layer, the service and the bootstrap.
pub struct AdminState {
    config: AdminConfig,
    keys: AdminKeys,
    hasher: PasswordHasher,
    clock: Arc<dyn Clock>,
    cmis: Arc<CmisState>,
    blocklist: Blocklist,
    relying_party: RelyingParty,
    used_nonces: Mutex<HashMap<[u8; 16], i64>>,
    begin_login: Mutex<HashMap<IpAddr, (i64, u32)>>,
    key_locks: Mutex<HashMap<Vec<u8>, Arc<tokio::sync::Mutex<()>>>>,
    last_anomaly_at: AtomicI64,
}

/// Holds the per-key serialisation locks of one credential attempt until
/// dropped.
pub struct KeyGuards {
    _guards: Vec<tokio::sync::OwnedMutexGuard<()>>,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AdminState {
    /// Load the pepper and blocklist named by `config`, check the keys against
    /// the cluster's key-check record, record the separation-of-duties mode,
    /// and build the state.
    pub async fn new(
        cmis: Arc<CmisState>,
        config: AdminConfig,
        keys: AdminKeys,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, AdminInitError> {
        let pepper = if let Some(path) = &config.pepper_file {
            let key = read_or_create_key(&KeyFile {
                path: path.clone(),
                generate_if_missing: false,
            })?;
            Some(Pepper::new(1, *key))
        } else {
            tracing::warn!(
                "CMIS_ADMIN_PEPPER_FILE unset: admin passwords are hashed without a pepper"
            );
            None
        };
        if super::password::PasswordParams::default().stronger_than(&config.password_params) {
            tracing::warn!(
                "admin password hashing runs with reduced Argon2 parameters (tests only)"
            );
        }
        let hasher = PasswordHasher::new(config.password_params, pepper)?;
        let blocklist = if let Some(path) = &config.blocklist_file {
            Blocklist::from_file(path).map_err(AdminInitError::Blocklist)?
        } else {
            tracing::warn!(
                "CMIS_ADMIN_PASSWORD_BLOCKLIST_FILE unset: only the small embedded password blocklist is checked"
            );
            Blocklist::embedded()
        };

        let cluster = cmis.cluster();
        let recorded = cluster
            .setting_set_once("admin_key_check", keys.key_check())
            .await?;
        if recorded != keys.key_check() {
            return Err(AdminInitError::KeyMismatch);
        }

        let relying_party = RelyingParty::new(&config.webauthn_rp_id(), config.webauthn_origins());
        let state = Arc::new(Self {
            config,
            keys,
            hasher,
            clock,
            cmis,
            blocklist,
            relying_party,
            used_nonces: Mutex::new(HashMap::new()),
            begin_login: Mutex::new(HashMap::new()),
            key_locks: Mutex::new(HashMap::new()),
            last_anomaly_at: AtomicI64::new(i64::MIN),
        });

        let strict = if state.config.strict_sod { "1" } else { "0" };
        let last = state.cluster().setting("admin_strict_sod").await?;
        if last.as_deref().unwrap_or("0") != strict {
            state
                .cluster()
                .put_setting("admin_strict_sod", strict)
                .await?;
            tracing::warn!(
                event = "admin.sod.changed",
                strict = state.config.strict_sod,
                "separation-of-duties policy changed"
            );
            state.audit(AuditEvent::AdminSodModeChanged {
                strict: state.config.strict_sod,
            });
        }
        Ok(state)
    }

    /// Current Unix time.
    #[must_use]
    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &AdminConfig {
        &self.config
    }

    /// The keys.
    #[must_use]
    pub fn keys(&self) -> &AdminKeys {
        &self.keys
    }

    /// The password hasher.
    #[must_use]
    pub fn hasher(&self) -> &PasswordHasher {
        &self.hasher
    }

    /// The password blocklist.
    #[must_use]
    pub fn blocklist(&self) -> &Blocklist {
        &self.blocklist
    }

    /// The WebAuthn relying party (RP ID and accepted origins).
    #[must_use]
    pub fn relying_party(&self) -> &RelyingParty {
        &self.relying_party
    }

    /// The replicated store.
    #[must_use]
    pub fn cluster(&self) -> &Cluster {
        self.cmis.cluster()
    }

    /// The CMIS state (audit log, cluster).
    #[must_use]
    pub fn cmis(&self) -> &Arc<CmisState> {
        &self.cmis
    }

    /// Append one audit event (failures are logged at `error`, never silent).
    pub fn audit(&self, event: AuditEvent) {
        crate::service::audit_record(&self.cmis, event, self.now());
    }

    /// Log a store failure and map it to `UNAVAILABLE (store_unavailable)`.
    #[must_use]
    pub fn store_error(&self, e: &ClusterError) -> Status {
        tracing::error!(event = "admin.store.error", error = %e, "admin store operation failed");
        Status::unavailable("store_unavailable")
    }

    /// Keyed pseudonym of a source IP for audit events.
    #[must_use]
    pub fn src_ip_hmac(&self, ip: Option<IpAddr>) -> String {
        self.keys
            .pseudonym("src-ip-v1", canonical_ip(ip).as_bytes())
    }

    /// Keyed pseudonym of an attempted (normalised) username.
    #[must_use]
    pub fn account_ref_hmac(&self, username_key: &str) -> String {
        self.keys.pseudonym("username-v1", username_key.as_bytes())
    }

    /// Append to the INSERT-only security log (clear values, DPO retention).
    pub async fn security_log(
        &self,
        event: &str,
        admin_id: Option<&str>,
        username_key: Option<&str>,
        ip: Option<IpAddr>,
        detail: Option<&str>,
    ) {
        let hmac = username_key.map(|u| self.keys.pseudonym_raw("username-v1", u.as_bytes()));
        let ip = ip.map(|i| canonical_ip(Some(i)));
        if let Err(e) = self
            .cluster()
            .admin_security_log(
                self.now(),
                event,
                admin_id,
                hmac.as_ref().map(<[u8; 32]>::as_slice),
                ip.as_deref(),
                detail,
            )
            .await
        {
            tracing::error!(error = %e, event, "admin security log append failed");
        }
    }

    // ---- nonces --------------------------------------------------------------

    /// A single-use, two-minute nonce bound to `binding` under `label`.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random source fails.
    #[must_use]
    pub fn issue_nonce(&self, label: &str, binding: &[&[u8]]) -> Vec<u8> {
        let issued = self.now().to_be_bytes();
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).expect("OS random source");
        let mut parts: Vec<&[u8]> = vec![&issued, &random];
        parts.extend_from_slice(binding);
        let mac = self.keys.mac(label, &parts);
        let mut out = Vec::with_capacity(NONCE_LEN);
        out.extend_from_slice(&issued);
        out.extend_from_slice(&random);
        out.extend_from_slice(&mac[..16]);
        out
    }

    /// Redeem a nonce issued by [`Self::issue_nonce`] with the same `label`
    /// and `binding`. `false` for a malformed, forged, expired, rebound or
    /// already-redeemed nonce.
    pub fn redeem_nonce(&self, label: &str, nonce: &[u8], binding: &[&[u8]]) -> bool {
        self.redeem_nonce_within(label, nonce, binding, NONCE_TTL_SECS)
    }

    /// [`Self::redeem_nonce`] with a lifetime of `ttl_secs` instead of two
    /// minutes (WebAuthn creation ceremonies, which wait for a person to
    /// register a key).
    pub fn redeem_nonce_within(
        &self,
        label: &str,
        nonce: &[u8],
        binding: &[&[u8]],
        ttl_secs: i64,
    ) -> bool {
        if nonce.len() != NONCE_LEN {
            return false;
        }
        let now = self.now();
        let issued_bytes: [u8; 8] = nonce[..8].try_into().unwrap_or_default();
        let issued = i64::from_be_bytes(issued_bytes);
        let age = now.saturating_sub(issued);
        if !(-5..=ttl_secs).contains(&age) {
            return false;
        }
        let random: [u8; 16] = nonce[8..24].try_into().unwrap_or_default();
        let mut parts: Vec<&[u8]> = vec![&issued_bytes, &random];
        parts.extend_from_slice(binding);
        let mac = self.keys.mac(label, &parts);
        if !bool::from(mac[..16].ct_eq(&nonce[24..])) {
            return false;
        }
        let mut used = self.used_nonces.lock();
        if used.len() >= USED_NONCE_SOFT_CAP {
            used.retain(|_, expiry| *expiry > now);
        }
        if used.len() >= USED_NONCE_HARD_CAP {
            tracing::warn!("admin nonce table full; refusing until entries expire");
            return false;
        }
        if used.contains_key(&random) {
            return false;
        }
        used.insert(random, issued.saturating_add(ttl_secs));
        true
    }

    /// Per-IP `BeginLogin` flood limit (10 per minute).
    pub fn allow_begin_login(&self, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip else { return false };
        let now = self.now();
        let mut windows = self.begin_login.lock();
        if windows.len() >= RATE_WINDOW_CAP {
            windows.retain(|_, (start, _)| now.saturating_sub(*start) < 60);
            if windows.len() >= RATE_WINDOW_CAP {
                return false;
            }
        }
        let entry = windows.entry(ip).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= 60 {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= BEGIN_LOGIN_PER_MINUTE
    }

    // ---- device tokens ---------------------------------------------------------

    /// Issue a device token for `admin_id` (the norm's "cookie": selects the
    /// throttle bucket, never authenticates).
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random source fails.
    #[must_use]
    pub fn issue_device_token(&self, admin_id: &str) -> String {
        let issued = self.now().to_be_bytes();
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).expect("OS random source");
        let mac = self
            .keys
            .mac("device-v1", &[admin_id.as_bytes(), &issued, &random]);
        let mut raw = Vec::with_capacity(40);
        raw.extend_from_slice(&issued);
        raw.extend_from_slice(&random);
        raw.extend_from_slice(&mac[..16]);
        format!("{DEVICE_TOKEN_PREFIX}{}", b64url(&raw))
    }

    /// Whether `token` is a live device token issued to `admin_id`.
    #[must_use]
    pub fn device_token_valid(&self, token: &str, admin_id: &str) -> bool {
        let Some(raw) = token
            .strip_prefix(DEVICE_TOKEN_PREFIX)
            .filter(|t| t.len() <= 64)
            .and_then(b64url_decode)
        else {
            return false;
        };
        if raw.len() != 40 {
            return false;
        }
        let issued_bytes: [u8; 8] = raw[..8].try_into().unwrap_or_default();
        let age = self.now().saturating_sub(i64::from_be_bytes(issued_bytes));
        if !(0..DEVICE_TOKEN_TTL_SECS).contains(&age) {
            return false;
        }
        let mac = self
            .keys
            .mac("device-v1", &[admin_id.as_bytes(), &raw[..8], &raw[8..24]]);
        bool::from(mac[..16].ct_eq(&raw[24..]))
    }

    // ---- throttling ------------------------------------------------------------

    /// Stored hash of a throttle key.
    #[must_use]
    pub fn throttle_key(&self, kind: KeyKind, value: &[u8]) -> Vec<u8> {
        self.keys
            .mac("throttle-v1", &[&kind.code().to_be_bytes(), value])
            .to_vec()
    }

    /// The longest lock among `keys` at `now`, if any.
    pub async fn throttle_wait(&self, keys: &[(KeyKind, Vec<u8>)]) -> Result<Option<u64>, Status> {
        let now = self.now();
        let mut wait = None;
        for (_, hash) in keys {
            let row = self
                .cluster()
                .admin_throttle(hash)
                .await
                .map_err(|e| self.store_error(&e))?;
            if let Some(w) = row.as_ref().and_then(|r| throttle::locked_for(r, now)) {
                wait = Some(wait.map_or(w, |cur: u64| cur.max(w)));
            }
        }
        Ok(wait)
    }

    /// Count one failure on every key; return the longest lock applied by
    /// this failure (0 when none). Applied locks are audited.
    pub async fn throttle_failure(&self, keys: &[(KeyKind, Vec<u8>)]) -> u64 {
        let now = self.now();
        let mut applied = 0u64;
        for (kind, hash) in keys {
            // One atomic increment in the replicated store: concurrent
            // failures (on this or another node) are never lost.
            let next: ThrottleRow = match self
                .cluster()
                .admin_throttle_increment(hash, kind.code(), now, throttle::RESET_AFTER_SECS)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "throttle increment failed");
                    continue;
                }
            };
            let lock = throttle::lock_secs(*kind, next.failures);
            if lock > 0 {
                let until = now.saturating_add(i64::try_from(lock).unwrap_or(i64::MAX));
                if let Err(e) = self.cluster().admin_throttle_lock(hash, until).await {
                    tracing::error!(error = %e, "throttle lock write failed");
                }
            }
            if lock > 0 {
                applied = applied.max(lock);
                tracing::warn!(
                    event = "admin.login.lockout",
                    key_kind = kind.label(),
                    lock_secs = lock,
                    "login lock applied"
                );
                self.audit(AuditEvent::AdminLockoutApplied {
                    key_kind: kind.label().to_string(),
                    lock_secs: lock,
                });
            }
        }
        applied
    }

    /// Forget `keys` (after a success).
    pub async fn throttle_clear(&self, keys: &[(KeyKind, Vec<u8>)]) {
        for (_, hash) in keys {
            if let Err(e) = self.cluster().admin_clear_throttle(hash).await {
                tracing::error!(error = %e, "throttle clear failed");
            }
        }
    }

    /// Serialise credential attempts that share a throttle key on this node:
    /// the lock check, the credential verification and the failure count of
    /// one attempt complete before the next attempt on the same key starts,
    /// so a burst of parallel guesses cannot all pass the check before any
    /// failure is recorded. Locks are taken in a fixed order (no deadlock).
    pub async fn serialize(&self, keys: &[(KeyKind, Vec<u8>)]) -> KeyGuards {
        let mut hashes: Vec<Vec<u8>> = keys.iter().map(|(_, h)| h.clone()).collect();
        hashes.sort();
        hashes.dedup();
        let mutexes: Vec<Arc<tokio::sync::Mutex<()>>> = {
            let mut map = self.key_locks.lock();
            if map.len() > 4096 {
                map.retain(|_, m| Arc::strong_count(m) > 1);
            }
            hashes
                .into_iter()
                .map(|h| Arc::clone(map.entry(h).or_default()))
                .collect()
        };
        let mut guards = Vec::with_capacity(mutexes.len());
        for m in mutexes {
            guards.push(m.lock_owned().await);
        }
        KeyGuards { _guards: guards }
    }

    /// Raise `AdminLoginAnomaly` when failures in the last ten minutes cross
    /// the threshold (at most once a minute per node).
    pub async fn check_anomaly(&self) {
        let now = self.now();
        let Ok(count) = self
            .cluster()
            .admin_security_log_count("login.failed", now - 600)
            .await
        else {
            return;
        };
        if count > ANOMALY_FAILURES_10M
            && now.saturating_sub(self.last_anomaly_at.load(Ordering::Relaxed)) >= 60
        {
            self.last_anomaly_at.store(now, Ordering::Relaxed);
            tracing::warn!(
                event = "admin.login.anomaly",
                failures_10m = count,
                "login failure spike"
            );
            self.audit(AuditEvent::AdminLoginAnomaly {
                failures_10m: u32::try_from(count).unwrap_or(u32::MAX),
            });
        }
    }

    // ---- second factor -----------------------------------------------------------

    /// Verify a TOTP code for `account` and advance its replay guard. `false`
    /// for a wrong, replayed or concurrently used code, or an account with no
    /// TOTP secret.
    pub async fn check_totp(&self, account: &AdminAccountRow, code: &str) -> Result<bool, Status> {
        let Some(sealed) = &account.totp_secret_enc else {
            return Ok(false);
        };
        let secret = self
            .keys
            .open_totp(&account.admin_id, sealed)
            .map_err(|e| {
                tracing::error!(event = "admin.totp.unseal_failed", error = %e, "TOTP secret did not open");
                Status::unavailable("store_unavailable")
            })?;
        let Some(step) = totp::verify(&secret, code, self.now(), account.totp_last_step) else {
            return Ok(false);
        };
        self.cluster()
            .admin_advance_totp_step(&account.admin_id, step)
            .await
            .map_err(|e| self.store_error(&e))
    }

    /// Per-operation MFA (F20 §7 "M"): a fresh second factor from the
    /// caller, TOTP or WebAuthn as the session's policy allows (see
    /// [`Self::verify_factor`]). Failures count toward the session's step-up
    /// failure limit.
    pub async fn verify_proof(
        &self,
        ctx: &AdminContext,
        proof: Option<ferro_proto::admin_v1::MfaProof>,
    ) -> Result<(), Status> {
        self.verify_factor(ctx, proof, None).await.map(|_| ())
    }

    /// Count a failed in-session second-factor check; revoke the session at
    /// the limit.
    pub async fn second_factor_failed(&self, ctx: &AdminContext) {
        if ctx.session_hash.is_empty() {
            return;
        }
        match self
            .cluster()
            .admin_session_stepup_failed(&ctx.session_hash)
            .await
        {
            Ok(n) if n >= session::MAX_STEP_UP_FAILURES => {
                if let Ok(Some(row)) = self.cluster().admin_session(&ctx.session_hash).await {
                    self.revoke_session(&row, RevokeReason::StepUpFailures, None)
                        .await;
                }
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "step-up failure counter update failed"),
        }
    }

    /// Offer a fresh random TOTP seed for an enrollment token: sealed into the
    /// token row, replacing any seed an earlier `BeginEnrollment` offered, so
    /// a copy taken by anyone else who saw the token stops working once the
    /// holder begins their own enrollment. `None` if the token is no longer
    /// live.
    pub async fn offer_enrollment_secret(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<Zeroizing<[u8; totp::SECRET_LEN]>>, Status> {
        let secret = totp::generate_secret();
        let sealed = self
            .keys
            .seal_totp(&pending_aad(token_hash), secret.as_ref())
            .map_err(|e| {
                tracing::error!(error = %e, "TOTP sealing failed");
                Status::internal("internal_error")
            })?;
        let stored = self
            .cluster()
            .admin_set_pending_secret(token_hash, &sealed, self.now())
            .await
            .map_err(|e| self.store_error(&e))?;
        Ok(stored.then_some(secret))
    }

    /// The seed the latest `BeginEnrollment` offered for this token.
    #[must_use]
    pub fn pending_enrollment_secret(
        &self,
        token_hash: &[u8],
        sealed: Option<&[u8]>,
    ) -> Option<Zeroizing<Vec<u8>>> {
        self.keys.open_totp(&pending_aad(token_hash), sealed?).ok()
    }

    // ---- sessions ---------------------------------------------------------------

    /// Open a session for `account`, verified by `verified`, evicting the
    /// oldest live sessions beyond the per-account cap. Returns the token
    /// (shown once) and the stored row.
    pub async fn open_session(
        &self,
        account: &AdminAccountRow,
        peer: &PeerInfo,
        client: (i64, Option<String>),
        verified: Verified,
        restricted: bool,
    ) -> Result<(Zeroizing<String>, AdminSessionRow), Status> {
        let now = self.now();
        let live = self
            .cluster()
            .admin_live_sessions(&account.admin_id)
            .await
            .map_err(|e| self.store_error(&e))?;
        let mut live: Vec<_> = live
            .into_iter()
            .filter(|r| session::liveness(r, now) == Liveness::Live)
            .collect();
        while live.len() >= session::MAX_SESSIONS_PER_ACCOUNT {
            let oldest = live.remove(0);
            self.revoke_session(&oldest, RevokeReason::Evicted, None)
                .await;
        }
        let (token, hash) = session::new_token();
        let row = AdminSessionRow {
            session_hash: hash,
            admin_id: account.admin_id.clone(),
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: now.saturating_add(self.config.absolute_lifetime_secs),
            idle_timeout_secs: self.config.idle_timeout_secs,
            aal: verified.aal,
            mfa_at: now,
            mfa_method: verified.method.code(),
            source_ip: canonical_ip(peer.ip),
            client_cert_sha256: peer.client_cert_sha256.map(|c| c.to_vec()),
            client_kind: client.0,
            client_version: client.1,
            restricted: i64::from(restricted),
            revoked_at: None,
            revoked_reason: None,
            stepup_failures: 0,
        };
        self.cluster()
            .admin_insert_session(&row)
            .await
            .map_err(|e| self.store_error(&e))?;
        Ok((token, row))
    }

    /// Revoke one session and audit it (`AdminSessionRevoked`).
    pub async fn revoke_session(
        &self,
        row: &AdminSessionRow,
        reason: RevokeReason,
        by_admin_id: Option<&str>,
    ) {
        match self
            .cluster()
            .admin_revoke_session(&row.session_hash, self.now(), reason.code())
            .await
        {
            Ok(true) => {
                let session_ref = session::session_ref(&row.session_hash);
                tracing::info!(
                    event = "admin.session.revoked",
                    admin_id = %row.admin_id,
                    session_ref = %session_ref,
                    reason = reason.label(),
                    "admin session revoked"
                );
                self.audit(AuditEvent::AdminSessionRevoked {
                    admin_id: row.admin_id.clone(),
                    session_ref,
                    by_admin_id: by_admin_id.map(str::to_string),
                    reason: reason.label().to_string(),
                });
            }
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e, "admin session revoke failed"),
        }
    }

    /// Revoke every live session of `admin_id` except `keep`.
    pub async fn revoke_all_sessions(
        &self,
        admin_id: &str,
        keep: Option<&[u8]>,
        reason: RevokeReason,
        by_admin_id: Option<&str>,
    ) -> Result<(), Status> {
        let live = self
            .cluster()
            .admin_live_sessions(admin_id)
            .await
            .map_err(|e| self.store_error(&e))?;
        for row in live
            .iter()
            .filter(|r| keep.is_none_or(|k| r.session_hash.as_slice() != k))
        {
            self.revoke_session(row, reason, by_admin_id).await;
        }
        Ok(())
    }
}

/// AAD binding a pending enrollment seed to its token.
fn pending_aad(token_hash: &[u8]) -> String {
    format!("enroll:{}", hex::encode(token_hash))
}

/// Canonical text form of a peer address (IPv4-mapped IPv6 → IPv4), so a
/// session made over IPv4 matches the same client seen by a dual-stack
/// listener. Empty when unknown.
#[must_use]
pub fn canonical_ip(ip: Option<IpAddr>) -> String {
    ip.map(|i| i.to_canonical().to_string()).unwrap_or_default()
}

/// Normalise a username: NFKC, trimmed, lower-cased, `[a-z0-9._-]{3,64}`.
#[must_use]
pub fn normalize_username(raw: &str) -> Option<String> {
    if raw.len() > 256 {
        return None;
    }
    let n: String = raw.trim().nfkc().collect::<String>().to_lowercase();
    let ok = (3..=64).contains(&n.len())
        && n.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
    ok.then_some(n)
}

/// The throttle key for an attempted username, valid or not (bounded).
#[must_use]
pub fn username_throttle_key(raw: &str) -> String {
    normalize_username(raw).unwrap_or_else(|| {
        raw.trim()
            .chars()
            .take(128)
            .collect::<String>()
            .to_lowercase()
    })
}

/// Clean a display name: NFKC, trimmed, control and bidi-override characters
/// removed. `None` when longer than 128 characters.
#[must_use]
pub fn clean_display_name(raw: &str) -> Option<String> {
    if raw.len() > 1024 {
        return None;
    }
    let cleaned: String = raw
        .nfkc()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .collect::<String>()
        .trim()
        .to_string();
    (cleaned.chars().count() <= 128).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_normalised_and_constrained() {
        assert_eq!(normalize_username("  Alice.Ops "), Some("alice.ops".into()));
        assert_eq!(
            normalize_username("ＢＯＢ_1"),
            Some("bob_1".into()),
            "NFKC folds width"
        );
        assert_eq!(normalize_username("ab"), None);
        assert_eq!(normalize_username(&"a".repeat(65)), None);
        assert_eq!(normalize_username("alice ops"), None);
        assert_eq!(normalize_username("álvaro"), None);
        assert_eq!(normalize_username("r00t;drop"), None);
    }

    #[test]
    fn display_names_lose_control_and_bidi_characters() {
        assert_eq!(
            clean_display_name(" Ana\u{202E}Souza\u{7} "),
            Some("AnaSouza".into())
        );
        assert_eq!(clean_display_name(&"x".repeat(129)), None);
        assert_eq!(
            clean_display_name("José da Silva"),
            Some("José da Silva".into())
        );
    }
}
