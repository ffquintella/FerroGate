//! Replicated storage for administrator authentication (feature F20 §3).
//!
//! This module owns the admin tables (schema, triggers, built-in groups) and a
//! typed accessor surface on [`Cluster`]. The *policy* — password hashing,
//! TOTP, throttling decisions, session lifetimes, RBAC — lives in
//! `cmis::admin`; this layer only persists rows and keeps hiqlite types out of
//! the rest of the tree, like the rest of `ferro-raft`.
//!
//! Every read here is **strongly consistent** (read through the leader):
//! authentication decisions must never act on a stale replica, for example a
//! session revoked a moment ago on another node.
//!
//! Immutability is enforced by the database, not the application (NRM §5.3.1):
//! triggers make `admin_password_history`, `admin_security_log` and redeemed
//! `admin_enrollment_tokens` rows immutable, and forbid deleting
//! `admin_accounts` rows, so `admin_id` attribution in the audit log stays
//! resolvable. All statements are parameterised.

use hiqlite::Param;

use crate::cluster::{Cluster, ClusterError};

/// Account state: created, waiting for its holder to enroll.
pub const ACCOUNT_PENDING: i64 = 1;
/// Account state: usable.
pub const ACCOUNT_ACTIVE: i64 = 2;
/// Account state: disabled (accounts are never deleted).
pub const ACCOUNT_DISABLED: i64 = 3;

/// Enrollment-token purpose: first-account bootstrap.
pub const TOKEN_BOOTSTRAP: i64 = 1;
/// Enrollment-token purpose: enrollment of a created account.
pub const TOKEN_ENROLL: i64 = 2;
/// Enrollment-token purpose: credential reset.
pub const TOKEN_RESET: i64 = 3;
/// Enrollment-token purpose: break-glass recovery.
pub const TOKEN_RECOVERY: i64 = 4;

/// Most FIDO2 / WebAuthn credentials one account may hold (F20 §5).
pub const MAX_WEBAUTHN_CREDENTIALS: i64 = 8;

/// Built-in groups and their permissions (F20 §7 permission table). Groups are
/// the only way a permission reaches an account; built-in groups cannot be
/// edited.
pub const BUILTIN_GROUPS: &[(&str, &[&str])] = &[
    (
        "ferrogate-viewers",
        &[
            "app_request.list",
            "app_request.read",
            "approval.list",
            "approval.read",
            "host.list",
        ],
    ),
    (
        "ferrogate-approvers",
        &[
            "app_request.list",
            "app_request.read",
            "approval.list",
            "approval.read",
            "host.list",
            "app_request.approve",
            "app_request.deny",
            "approval.update",
            "approval.revoke",
            "app.direct_register",
        ],
    ),
    (
        "ferrogate-account-admins",
        &[
            "account.list",
            "account.create",
            "account.update",
            "account.disable",
            "account.reset",
            "session.revoke_any",
        ],
    ),
    (
        "ferrogate-platform-operators",
        &[
            "host.list",
            "legacy.allowlist.read",
            "legacy.allowlist.write",
            "svid.list",
            "svid.revoke",
            "policy.epoch_bump",
            "settings.allowlist_mode",
            "allowlist.import",
        ],
    ),
];

/// DDL for the admin tables, applied idempotently at cluster start.
///
/// Matches F20 §3, plus three additive items: `admin_sessions.stepup_failures`
/// (F20 §7 "five failed step-ups revoke the session" needs a replicated
/// counter), `admin_enrollment_tokens.pending_secret_enc` (the sealed TOTP
/// seed offered by the latest `BeginEnrollment`, rotated on every call), and
/// the `cmis_settings` key/value table (F20 §9
/// `cmis_settings.admin_bootstrapped`).
pub(crate) const ADMIN_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS admin_accounts ( \
        admin_id TEXT PRIMARY KEY, \
        username TEXT NOT NULL UNIQUE, \
        display_name TEXT, \
        state INTEGER NOT NULL, \
        created_at INTEGER NOT NULL, \
        created_by_admin_id TEXT, \
        password_phc TEXT, \
        pepper_id INTEGER, \
        password_changed_at INTEGER, \
        password_expires_at INTEGER, \
        totp_secret_enc BLOB, \
        totp_last_step INTEGER, \
        last_login_at INTEGER, \
        disabled_at INTEGER, \
        disabled_by_admin_id TEXT, \
        row_version INTEGER NOT NULL DEFAULT 1 \
    )",
    "CREATE TABLE IF NOT EXISTS admin_password_history ( \
        admin_id TEXT NOT NULL, \
        password_phc TEXT NOT NULL, \
        pepper_id INTEGER, \
        set_at INTEGER NOT NULL, \
        PRIMARY KEY (admin_id, set_at) \
    )",
    "CREATE TABLE IF NOT EXISTS admin_webauthn_credentials ( \
        credential_id BLOB PRIMARY KEY, \
        admin_id TEXT NOT NULL, \
        cose_public_key BLOB NOT NULL, \
        sign_count INTEGER NOT NULL, \
        aaguid BLOB, \
        label TEXT, \
        created_at INTEGER NOT NULL, \
        last_used_at INTEGER \
    )",
    "CREATE TABLE IF NOT EXISTS admin_groups ( \
        group_id TEXT PRIMARY KEY, \
        name TEXT NOT NULL UNIQUE, \
        builtin INTEGER NOT NULL \
    )",
    "CREATE TABLE IF NOT EXISTS admin_group_permissions ( \
        group_id TEXT NOT NULL, \
        permission TEXT NOT NULL, \
        PRIMARY KEY (group_id, permission) \
    )",
    "CREATE TABLE IF NOT EXISTS admin_group_members ( \
        admin_id TEXT NOT NULL, \
        group_id TEXT NOT NULL, \
        granted_by_admin_id TEXT, \
        granted_at INTEGER NOT NULL, \
        PRIMARY KEY (admin_id, group_id) \
    )",
    "CREATE TABLE IF NOT EXISTS admin_sessions ( \
        session_hash BLOB PRIMARY KEY, \
        admin_id TEXT NOT NULL, \
        created_at INTEGER NOT NULL, \
        last_seen_at INTEGER NOT NULL, \
        absolute_expires_at INTEGER NOT NULL, \
        idle_timeout_secs INTEGER NOT NULL, \
        aal INTEGER NOT NULL, \
        mfa_at INTEGER NOT NULL, \
        mfa_method INTEGER NOT NULL, \
        source_ip TEXT NOT NULL, \
        client_cert_sha256 BLOB, \
        client_kind INTEGER NOT NULL, \
        client_version TEXT, \
        restricted INTEGER NOT NULL DEFAULT 0, \
        revoked_at INTEGER, \
        revoked_reason INTEGER, \
        stepup_failures INTEGER NOT NULL DEFAULT 0 \
    )",
    "CREATE INDEX IF NOT EXISTS admin_sessions_admin ON admin_sessions(admin_id)",
    "CREATE TABLE IF NOT EXISTS admin_enrollment_tokens ( \
        token_hash BLOB PRIMARY KEY, \
        admin_id TEXT, \
        purpose INTEGER NOT NULL, \
        created_by_admin_id TEXT, \
        created_at INTEGER NOT NULL, \
        expires_at INTEGER NOT NULL, \
        used_at INTEGER, \
        pending_secret_enc BLOB \
    )",
    "CREATE TABLE IF NOT EXISTS admin_login_throttle ( \
        key_hash BLOB PRIMARY KEY, \
        key_kind INTEGER NOT NULL, \
        failures INTEGER NOT NULL, \
        locked_until INTEGER NOT NULL, \
        last_failure_at INTEGER NOT NULL \
    )",
    "CREATE TABLE IF NOT EXISTS admin_idempotency ( \
        admin_id TEXT NOT NULL, \
        rpc TEXT NOT NULL, \
        key TEXT NOT NULL, \
        response BLOB NOT NULL, \
        created_at INTEGER NOT NULL, \
        PRIMARY KEY (admin_id, rpc, key) \
    )",
    "CREATE TABLE IF NOT EXISTS admin_security_log ( \
        id INTEGER PRIMARY KEY AUTOINCREMENT, \
        at INTEGER NOT NULL, \
        event TEXT NOT NULL, \
        admin_id TEXT, \
        username_attempted_hmac BLOB, \
        source_ip TEXT, \
        detail TEXT \
    )",
    "CREATE TABLE IF NOT EXISTS cmis_settings ( \
        key TEXT PRIMARY KEY, \
        value TEXT NOT NULL \
    )",
    // ---- Database-enforced immutability (NRM §5.3.1) ----
    "CREATE TRIGGER IF NOT EXISTS admin_accounts_no_delete \
        BEFORE DELETE ON admin_accounts \
        BEGIN SELECT RAISE(ABORT, 'admin accounts are disabled, never deleted'); END",
    "CREATE TRIGGER IF NOT EXISTS admin_password_history_no_update \
        BEFORE UPDATE ON admin_password_history \
        BEGIN SELECT RAISE(ABORT, 'admin_password_history is insert-only'); END",
    "CREATE TRIGGER IF NOT EXISTS admin_password_history_no_delete \
        BEFORE DELETE ON admin_password_history \
        BEGIN SELECT RAISE(ABORT, 'admin_password_history is insert-only'); END",
    "CREATE TRIGGER IF NOT EXISTS admin_security_log_no_update \
        BEFORE UPDATE ON admin_security_log \
        BEGIN SELECT RAISE(ABORT, 'admin_security_log is insert-only'); END",
    "CREATE TRIGGER IF NOT EXISTS admin_security_log_no_delete \
        BEFORE DELETE ON admin_security_log \
        BEGIN SELECT RAISE(ABORT, 'admin_security_log is insert-only'); END",
    "CREATE TRIGGER IF NOT EXISTS admin_enrollment_tokens_used_immutable \
        BEFORE UPDATE ON admin_enrollment_tokens WHEN OLD.used_at IS NOT NULL \
        BEGIN SELECT RAISE(ABORT, 'redeemed enrollment tokens are immutable'); END",
    "CREATE TRIGGER IF NOT EXISTS admin_enrollment_tokens_used_no_delete \
        BEFORE DELETE ON admin_enrollment_tokens WHEN OLD.used_at IS NOT NULL \
        BEGIN SELECT RAISE(ABORT, 'redeemed enrollment tokens are immutable'); END",
];

/// One `admin_accounts` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAccountRow {
    /// UUIDv7; the pseudonym used in audit events.
    pub admin_id: String,
    /// Normalised username (personal data).
    pub username: String,
    /// Display name (personal data).
    pub display_name: Option<String>,
    /// [`ACCOUNT_PENDING`], [`ACCOUNT_ACTIVE`] or [`ACCOUNT_DISABLED`].
    pub state: i64,
    /// Unix seconds.
    pub created_at: i64,
    /// Creator; `None` for bootstrap and recovery.
    pub created_by_admin_id: Option<String>,
    /// Argon2id PHC string; `None` until enrollment or after a reset.
    pub password_phc: Option<String>,
    /// Pepper generation the hash was computed with.
    pub pepper_id: Option<i64>,
    /// Unix seconds of the last password change.
    pub password_changed_at: Option<i64>,
    /// Unix seconds after which the password must change.
    pub password_expires_at: Option<i64>,
    /// AEAD-encrypted TOTP secret.
    pub totp_secret_enc: Option<Vec<u8>>,
    /// Highest TOTP time step accepted so far (replay guard).
    pub totp_last_step: Option<i64>,
    /// Unix seconds of the last successful login.
    pub last_login_at: Option<i64>,
    /// Unix seconds the account was disabled.
    pub disabled_at: Option<i64>,
    /// Administrator who disabled the account.
    pub disabled_by_admin_id: Option<String>,
    /// Optimistic-concurrency version.
    pub row_version: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for AdminAccountRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            admin_id: row.get("admin_id"),
            username: row.get("username"),
            display_name: row.get("display_name"),
            state: row.get("state"),
            created_at: row.get("created_at"),
            created_by_admin_id: row.get("created_by_admin_id"),
            password_phc: row.get("password_phc"),
            pepper_id: row.get("pepper_id"),
            password_changed_at: row.get("password_changed_at"),
            password_expires_at: row.get("password_expires_at"),
            totp_secret_enc: row.get("totp_secret_enc"),
            totp_last_step: row.get("totp_last_step"),
            last_login_at: row.get("last_login_at"),
            disabled_at: row.get("disabled_at"),
            disabled_by_admin_id: row.get("disabled_by_admin_id"),
            row_version: row.get("row_version"),
        }
    }
}

const ACCOUNT_COLUMNS: &str = "admin_id, username, display_name, state, created_at, \
    created_by_admin_id, password_phc, pepper_id, password_changed_at, password_expires_at, \
    totp_secret_enc, totp_last_step, last_login_at, disabled_at, disabled_by_admin_id, row_version";

/// One `admin_sessions` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSessionRow {
    /// SHA-256 of the session token (the token itself is never stored).
    pub session_hash: Vec<u8>,
    /// Session owner.
    pub admin_id: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; written at most once per minute.
    pub last_seen_at: i64,
    /// Hard expiry, Unix seconds.
    pub absolute_expires_at: i64,
    /// Idle timeout in seconds.
    pub idle_timeout_secs: i64,
    /// Authenticator assurance level (2 TOTP, 3 FIDO2 / hardware mTLS).
    pub aal: i64,
    /// Unix seconds of the last second-factor verification (step-up marker).
    pub mfa_at: i64,
    /// Method of the last verification (1 totp, 2 webauthn).
    pub mfa_method: i64,
    /// Login source IP (personal data).
    pub source_ip: String,
    /// SHA-256 of the client certificate when mTLS is on.
    pub client_cert_sha256: Option<Vec<u8>>,
    /// 1 tui, 2 tray, 3 cli.
    pub client_kind: i64,
    /// Client-reported version string.
    pub client_version: Option<String>,
    /// Restricted session flag (password expired at login).
    pub restricted: i64,
    /// Unix seconds of revocation.
    pub revoked_at: Option<i64>,
    /// Revocation reason code.
    pub revoked_reason: Option<i64>,
    /// Consecutive failed step-ups.
    pub stepup_failures: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for AdminSessionRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            session_hash: row.get("session_hash"),
            admin_id: row.get("admin_id"),
            created_at: row.get("created_at"),
            last_seen_at: row.get("last_seen_at"),
            absolute_expires_at: row.get("absolute_expires_at"),
            idle_timeout_secs: row.get("idle_timeout_secs"),
            aal: row.get("aal"),
            mfa_at: row.get("mfa_at"),
            mfa_method: row.get("mfa_method"),
            source_ip: row.get("source_ip"),
            client_cert_sha256: row.get("client_cert_sha256"),
            client_kind: row.get("client_kind"),
            client_version: row.get("client_version"),
            restricted: row.get("restricted"),
            revoked_at: row.get("revoked_at"),
            revoked_reason: row.get("revoked_reason"),
            stepup_failures: row.get("stepup_failures"),
        }
    }
}

const SESSION_COLUMNS: &str = "session_hash, admin_id, created_at, last_seen_at, \
    absolute_expires_at, idle_timeout_secs, aal, mfa_at, mfa_method, source_ip, \
    client_cert_sha256, client_kind, client_version, restricted, revoked_at, revoked_reason, \
    stepup_failures";

/// A second-factor verification recorded on a session (step-up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfaVerification {
    /// Unix seconds of the verification.
    pub at: i64,
    /// Method used (1 totp, 2 webauthn).
    pub method: i64,
    /// Assurance level that verification reached.
    pub aal: i64,
}

/// One `admin_webauthn_credentials` row (a registered FIDO2 credential).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnCredentialRow {
    /// Credential id chosen by the authenticator (at most 1023 bytes).
    pub credential_id: Vec<u8>,
    /// Owning account.
    pub admin_id: String,
    /// COSE_Key of the credential, as the authenticator encoded it.
    pub cose_public_key: Vec<u8>,
    /// Last signature counter accepted (clone detection).
    pub sign_count: i64,
    /// Authenticator model id (16 bytes), as reported at registration.
    pub aaguid: Option<Vec<u8>>,
    /// Holder-chosen label (bounded, cleaned by the caller).
    pub label: Option<String>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds of the last accepted assertion.
    pub last_used_at: Option<i64>,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for WebAuthnCredentialRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            credential_id: row.get("credential_id"),
            admin_id: row.get("admin_id"),
            cose_public_key: row.get("cose_public_key"),
            sign_count: row.get("sign_count"),
            aaguid: row.get("aaguid"),
            label: row.get("label"),
            created_at: row.get("created_at"),
            last_used_at: row.get("last_used_at"),
        }
    }
}

const WEBAUTHN_COLUMNS: &str = "credential_id, admin_id, cose_public_key, sign_count, aaguid, \
    label, created_at, last_used_at";

/// One `admin_enrollment_tokens` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTokenRow {
    /// SHA-256 of the token (the token itself is never stored).
    pub token_hash: Vec<u8>,
    /// Target account; `None` for bootstrap and recovery tokens.
    pub admin_id: Option<String>,
    /// [`TOKEN_BOOTSTRAP`], [`TOKEN_ENROLL`], [`TOKEN_RESET`] or [`TOKEN_RECOVERY`].
    pub purpose: i64,
    /// Issuing administrator, when any.
    pub created_by_admin_id: Option<String>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
    /// Unix seconds of redemption (or supersession); such rows are immutable.
    pub used_at: Option<i64>,
    /// Sealed TOTP seed offered by the latest `BeginEnrollment`, if any.
    pub pending_secret_enc: Option<Vec<u8>>,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for EnrollmentTokenRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            token_hash: row.get("token_hash"),
            admin_id: row.get("admin_id"),
            purpose: row.get("purpose"),
            created_by_admin_id: row.get("created_by_admin_id"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            used_at: row.get("used_at"),
            pending_secret_enc: row.get("pending_secret_enc"),
        }
    }
}

/// One `admin_login_throttle` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrottleRow {
    /// Keyed hash of the throttle key (IP, IP+device, or account).
    pub key_hash: Vec<u8>,
    /// 1 ip, 2 ip+device, 3 account.
    pub key_kind: i64,
    /// Failures counted in the current window.
    pub failures: i64,
    /// Unix seconds until which attempts are refused.
    pub locked_until: i64,
    /// Unix seconds of the last failure.
    pub last_failure_at: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for ThrottleRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            key_hash: row.get("key_hash"),
            key_kind: row.get("key_kind"),
            failures: row.get("failures"),
            locked_until: row.get("locked_until"),
            last_failure_at: row.get("last_failure_at"),
        }
    }
}

/// A group with its permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminGroupRow {
    /// Stable id (equal to the name for built-in groups).
    pub group_id: String,
    /// Unique name.
    pub name: String,
    /// Built-in groups cannot be edited.
    pub builtin: bool,
    /// Permission strings granted by the group.
    pub permissions: Vec<String>,
}

/// A password-history entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHistoryRow {
    /// Argon2id PHC string of an earlier password.
    pub password_phc: String,
    /// Pepper generation it was computed with.
    pub pepper_id: Option<i64>,
}

/// Input for a password change: the new hash and its lifetime.
#[derive(Debug, Clone)]
pub struct PasswordUpdate {
    /// Argon2id PHC string.
    pub password_phc: String,
    /// Pepper generation.
    pub pepper_id: Option<i64>,
    /// Unix seconds.
    pub changed_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
}

/// Input for redeeming an enrollment, reset or bootstrap token.
#[derive(Debug, Clone)]
pub struct EnrollmentCompletion {
    /// SHA-256 of the token being redeemed.
    pub token_hash: Vec<u8>,
    /// Account the token activates.
    pub admin_id: String,
    /// New password, when the token covers it.
    pub password: Option<PasswordUpdate>,
    /// Encrypted TOTP secret and the step of the proving code, when the token
    /// covers the second factor.
    pub totp: Option<(Vec<u8>, i64)>,
    /// A FIDO2 credential registered with the token, when one was.
    pub webauthn: Option<WebAuthnCredentialRow>,
    /// Unix seconds of redemption.
    pub now: i64,
}

#[derive(Debug)]
struct StringRow(String);
impl<'r> From<&'r mut hiqlite::Row<'_>> for StringRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("v"))
    }
}

#[derive(Debug)]
struct CountRow(i64);
impl<'r> From<&'r mut hiqlite::Row<'_>> for CountRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("n"))
    }
}

#[derive(Debug)]
struct GroupPermRow {
    group_id: String,
    name: String,
    builtin: i64,
    permission: Option<String>,
}
impl<'r> From<&'r mut hiqlite::Row<'_>> for GroupPermRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            group_id: row.get("group_id"),
            name: row.get("name"),
            builtin: row.get("builtin"),
            permission: row.get("permission"),
        }
    }
}

#[derive(Debug)]
struct HistoryRow {
    password_phc: String,
    pepper_id: Option<i64>,
}
impl<'r> From<&'r mut hiqlite::Row<'_>> for HistoryRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            password_phc: row.get("password_phc"),
            pepper_id: row.get("pepper_id"),
        }
    }
}

/// `true` if every statement of a transaction affected at least one row.
fn txn_ok(results: Vec<Result<usize, hiqlite::Error>>) -> Result<Vec<usize>, ClusterError> {
    results
        .into_iter()
        .map(|r| r.map_err(ClusterError::from))
        .collect()
}

/// Map a UNIQUE-constraint failure (for example a taken username) to
/// [`ClusterError::Conflict`]; other errors pass through.
fn unique_as_conflict(e: ClusterError) -> ClusterError {
    match e {
        ClusterError::Hiqlite(inner) if inner.to_string().contains("UNIQUE constraint failed") => {
            ClusterError::Conflict("unique constraint".into())
        }
        other => other,
    }
}

fn s(v: &str) -> Param {
    Param::from(v.to_string())
}

impl Cluster {
    /// Create the admin tables, triggers and built-in groups (idempotent).
    pub(crate) async fn init_admin_schema(&self) -> Result<(), ClusterError> {
        for ddl in ADMIN_SCHEMA {
            self.client().execute(*ddl, Vec::<Param>::new()).await?;
        }
        for (name, perms) in BUILTIN_GROUPS {
            self.client()
                .execute(
                    "INSERT OR IGNORE INTO admin_groups (group_id, name, builtin) VALUES (?1, ?2, 1)",
                    vec![s(name), s(name)],
                )
                .await?;
            for perm in *perms {
                self.client()
                    .execute(
                        "INSERT OR IGNORE INTO admin_group_permissions (group_id, permission) \
                         VALUES (?1, ?2)",
                        vec![s(name), s(perm)],
                    )
                    .await?;
            }
        }
        Ok(())
    }

    // ---- accounts ----------------------------------------------------------

    /// Number of admin accounts in any state.
    pub async fn admin_account_count(&self) -> Result<u64, ClusterError> {
        let rows: Vec<CountRow> = self
            .client()
            .query_consistent_map("SELECT COUNT(*) AS n FROM admin_accounts", Vec::new())
            .await?;
        Ok(rows.first().map_or(0, |r| u64::try_from(r.0).unwrap_or(0)))
    }

    /// One account by id.
    pub async fn admin_account(
        &self,
        admin_id: &str,
    ) -> Result<Option<AdminAccountRow>, ClusterError> {
        let rows: Vec<AdminAccountRow> = self
            .client()
            .query_consistent_map(
                format!("SELECT {ACCOUNT_COLUMNS} FROM admin_accounts WHERE admin_id = ?1"),
                vec![s(admin_id)],
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// One account by normalised username.
    pub async fn admin_account_by_username(
        &self,
        username: &str,
    ) -> Result<Option<AdminAccountRow>, ClusterError> {
        let rows: Vec<AdminAccountRow> = self
            .client()
            .query_consistent_map(
                format!("SELECT {ACCOUNT_COLUMNS} FROM admin_accounts WHERE username = ?1"),
                vec![s(username)],
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Every account, ordered by creation.
    pub async fn admin_accounts(&self) -> Result<Vec<AdminAccountRow>, ClusterError> {
        Ok(self
            .client()
            .query_consistent_map(
                format!(
                    "SELECT {ACCOUNT_COLUMNS} FROM admin_accounts ORDER BY created_at, admin_id"
                ),
                Vec::new(),
            )
            .await?)
    }

    /// Refuse group names that do not exist, before any write. (hiqlite
    /// commits a transaction even when one of its statements affects no row,
    /// so referential checks must happen up front or inside each statement.)
    async fn check_groups_exist(&self, groups: &[String]) -> Result<(), ClusterError> {
        let known: Vec<String> = self
            .admin_groups()
            .await?
            .into_iter()
            .map(|g| g.name)
            .collect();
        if let Some(bad) = groups.iter().find(|g| !known.contains(g)) {
            return Err(ClusterError::Conflict(format!("unknown group {bad:?}")));
        }
        Ok(())
    }

    /// Insert a `pending_enrollment` account with its groups and its
    /// single-use enrollment token, atomically. A taken username fails with
    /// [`ClusterError::Conflict`] and writes nothing.
    pub async fn admin_create_account(
        &self,
        account: &AdminAccountRow,
        groups: &[String],
        token: &EnrollmentTokenRow,
    ) -> Result<(), ClusterError> {
        self.check_groups_exist(groups).await?;
        let mut stmts: Vec<(&'static str, Vec<Param>)> = vec![(
            "INSERT INTO admin_accounts (admin_id, username, display_name, state, created_at, \
             created_by_admin_id, row_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            vec![
                s(&account.admin_id),
                s(&account.username),
                Param::from(account.display_name.clone()),
                Param::from(account.state),
                Param::from(account.created_at),
                Param::from(account.created_by_admin_id.clone()),
            ],
        )];
        for g in groups {
            stmts.push((
                "INSERT INTO admin_group_members (admin_id, group_id, granted_by_admin_id, granted_at) \
                 SELECT ?1, group_id, ?3, ?4 FROM admin_groups WHERE name = ?2",
                vec![
                    s(&account.admin_id),
                    s(g),
                    Param::from(account.created_by_admin_id.clone()),
                    Param::from(account.created_at),
                ],
            ));
        }
        stmts.push(insert_token_stmt(token));
        // A UNIQUE violation aborts and rolls back the whole transaction.
        match self.client().txn(stmts).await {
            Ok(results) => {
                txn_ok(results).map_err(unique_as_conflict)?;
                Ok(())
            }
            Err(e) => Err(unique_as_conflict(e.into())),
        }
    }

    /// Bootstrap (or recovery): create an **active** account with its groups,
    /// first password and TOTP secret, record `settings`, and redeem the token
    /// — atomically. Every write is conditional on the token still being live
    /// and the redemption runs last, so a lost race (token already redeemed or
    /// expired) writes nothing and fails with [`ClusterError::Conflict`], as
    /// does a taken username.
    pub async fn admin_bootstrap_account(
        &self,
        account: &AdminAccountRow,
        groups: &[String],
        completion: &EnrollmentCompletion,
        settings: &[(&str, &str)],
    ) -> Result<(), ClusterError> {
        self.check_groups_exist(groups).await?;
        let pw = completion
            .password
            .as_ref()
            .ok_or_else(|| ClusterError::Conflict("bootstrap needs a password".into()))?;
        let (totp_enc, totp_step) = completion
            .totp
            .clone()
            .ok_or_else(|| ClusterError::Conflict("bootstrap needs a second factor".into()))?;
        if completion.webauthn.is_some() {
            // F20 §9: the first account is bootstrapped with TOTP only.
            return Err(ClusterError::Conflict("bootstrap enrolls TOTP only".into()));
        }
        let tok = || Param::from(completion.token_hash.clone());
        let now = || Param::from(completion.now);
        let mut stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "INSERT INTO admin_accounts (admin_id, username, display_name, state, created_at, \
                 created_by_admin_id, password_phc, pepper_id, password_changed_at, \
                 password_expires_at, totp_secret_enc, totp_last_step, row_version) \
                 SELECT ?1, ?2, ?3, 2, ?4, NULL, ?5, ?6, ?7, ?8, ?9, ?10, 1 \
                 WHERE EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?11 AND used_at IS NULL AND expires_at > ?12)",
                vec![
                    s(&account.admin_id),
                    s(&account.username),
                    Param::from(account.display_name.clone()),
                    Param::from(account.created_at),
                    s(&pw.password_phc),
                    Param::from(pw.pepper_id),
                    Param::from(pw.changed_at),
                    Param::from(pw.expires_at),
                    Param::from(totp_enc),
                    Param::from(totp_step),
                    tok(),
                    now(),
                ],
            ),
            (
                "INSERT INTO admin_password_history (admin_id, password_phc, pepper_id, set_at) \
                 SELECT ?1, ?2, ?3, ?4 \
                 WHERE EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?5 AND used_at IS NULL AND expires_at > ?6)",
                vec![
                    s(&account.admin_id),
                    s(&pw.password_phc),
                    Param::from(pw.pepper_id),
                    Param::from(pw.changed_at),
                    tok(),
                    now(),
                ],
            ),
        ];
        for g in groups {
            stmts.push((
                "INSERT INTO admin_group_members (admin_id, group_id, granted_by_admin_id, granted_at) \
                 SELECT ?1, group_id, NULL, ?3 FROM admin_groups WHERE name = ?2 \
                 AND EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?4 AND used_at IS NULL AND expires_at > ?3)",
                vec![s(&account.admin_id), s(g), now(), tok()],
            ));
        }
        for (k, v) in settings {
            stmts.push((
                "INSERT INTO cmis_settings (key, value) SELECT ?1, ?2 \
                 WHERE EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?3 AND used_at IS NULL AND expires_at > ?4) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                vec![s(k), s(v), tok(), now()],
            ));
        }
        // Redemption last: every statement above saw the token still live.
        stmts.push((
            "UPDATE admin_enrollment_tokens SET used_at = ?2, admin_id = ?3 \
             WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
            vec![tok(), now(), s(&account.admin_id)],
        ));
        let affected = match self.client().txn(stmts).await {
            Ok(results) => txn_ok(results).map_err(unique_as_conflict)?,
            Err(e) => return Err(unique_as_conflict(e.into())),
        };
        if affected.last().copied() != Some(1) {
            return Err(ClusterError::Conflict("token not live".into()));
        }
        Ok(())
    }

    /// Redeem an enroll/reset token for an existing account: set the password
    /// and/or TOTP secret it covers, activate the account and mark the token
    /// used — atomically. Every write is conditional on the token still being
    /// live for this account and the redemption runs last, so a replayed or
    /// expired token writes nothing and fails with [`ClusterError::Conflict`].
    pub async fn admin_complete_enrollment(
        &self,
        completion: &EnrollmentCompletion,
    ) -> Result<(), ClusterError> {
        let id = || s(&completion.admin_id);
        let tok = || Param::from(completion.token_hash.clone());
        let now = || Param::from(completion.now);
        let mut stmts: Vec<(&'static str, Vec<Param>)> = Vec::new();
        if let Some(pw) = &completion.password {
            stmts.push((
                "UPDATE admin_accounts SET password_phc = ?2, pepper_id = ?3, \
                 password_changed_at = ?4, password_expires_at = ?5, row_version = row_version + 1 \
                 WHERE admin_id = ?1 AND EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?6 AND used_at IS NULL AND expires_at > ?7 AND admin_id = ?1)",
                vec![
                    id(),
                    s(&pw.password_phc),
                    Param::from(pw.pepper_id),
                    Param::from(pw.changed_at),
                    Param::from(pw.expires_at),
                    tok(),
                    now(),
                ],
            ));
            stmts.push((
                "INSERT INTO admin_password_history (admin_id, password_phc, pepper_id, set_at) \
                 SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?5 AND used_at IS NULL AND expires_at > ?6 AND admin_id = ?1)",
                vec![
                    id(),
                    s(&pw.password_phc),
                    Param::from(pw.pepper_id),
                    Param::from(pw.changed_at),
                    tok(),
                    now(),
                ],
            ));
        }
        if let Some((enc, step)) = &completion.totp {
            stmts.push((
                "UPDATE admin_accounts SET totp_secret_enc = ?2, totp_last_step = ?3, \
                 row_version = row_version + 1 \
                 WHERE admin_id = ?1 AND EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?4 AND used_at IS NULL AND expires_at > ?5 AND admin_id = ?1)",
                vec![id(), Param::from(enc.clone()), Param::from(*step), tok(), now()],
            ));
        }
        if let Some(cred) = &completion.webauthn {
            stmts.push((
                "INSERT INTO admin_webauthn_credentials (credential_id, admin_id, cose_public_key, \
                 sign_count, aaguid, label, created_at, last_used_at) \
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL \
                 WHERE EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                    WHERE token_hash = ?8 AND used_at IS NULL AND expires_at > ?9 AND admin_id = ?2) \
                 AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id = ?2) < ?10",
                vec![
                    Param::from(cred.credential_id.clone()),
                    id(),
                    Param::from(cred.cose_public_key.clone()),
                    Param::from(cred.sign_count),
                    Param::from(cred.aaguid.clone()),
                    Param::from(cred.label.clone()),
                    Param::from(cred.created_at),
                    tok(),
                    now(),
                    Param::from(MAX_WEBAUTHN_CREDENTIALS),
                ],
            ));
        }
        stmts.push((
            "UPDATE admin_accounts SET state = 2, row_version = row_version + 1 \
             WHERE admin_id = ?1 AND state IN (1, 2) AND EXISTS (SELECT 1 FROM admin_enrollment_tokens \
                WHERE token_hash = ?2 AND used_at IS NULL AND expires_at > ?3 AND admin_id = ?1)",
            vec![id(), tok(), now()],
        ));
        // Redemption last: every statement above saw the token still live.
        stmts.push((
            "UPDATE admin_enrollment_tokens SET used_at = ?2 \
             WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2 AND admin_id = ?3",
            vec![tok(), now(), id()],
        ));
        // A credential id that is already registered aborts the whole
        // transaction (UNIQUE), so nothing is written.
        let affected = match self.client().txn(stmts).await {
            Ok(results) => txn_ok(results).map_err(unique_as_conflict)?,
            Err(e) => return Err(unique_as_conflict(e.into())),
        };
        if affected.last().copied() != Some(1) {
            return Err(ClusterError::Conflict("token not live".into()));
        }
        Ok(())
    }

    /// Accept TOTP time step `step` for `admin_id` only if it is newer than
    /// every step accepted before (compare-and-set replay guard). Returns
    /// `false` if the step was already used, so a concurrent replay of the
    /// same code on another node also fails.
    pub async fn admin_advance_totp_step(
        &self,
        admin_id: &str,
        step: i64,
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "UPDATE admin_accounts SET totp_last_step = ?2 \
                 WHERE admin_id = ?1 AND (totp_last_step IS NULL OR totp_last_step < ?2)",
                vec![s(admin_id), Param::from(step)],
            )
            .await?;
        Ok(n > 0)
    }

    /// Record a successful login.
    pub async fn admin_set_last_login(&self, admin_id: &str, now: i64) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "UPDATE admin_accounts SET last_login_at = ?2 WHERE admin_id = ?1",
                vec![s(admin_id), Param::from(now)],
            )
            .await?;
        Ok(())
    }

    /// Replace the password hash after a successful login with stronger
    /// parameters (rehash on upgrade). The password itself is unchanged, so
    /// no history row is written and the expiry is kept.
    pub async fn admin_rehash_password(
        &self,
        admin_id: &str,
        password_phc: &str,
        pepper_id: Option<i64>,
    ) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "UPDATE admin_accounts SET password_phc = ?2, pepper_id = ?3 WHERE admin_id = ?1",
                vec![s(admin_id), s(password_phc), Param::from(pepper_id)],
            )
            .await?;
        Ok(())
    }

    /// Change an account's password, append the new hash to the history, and
    /// bump the row version — atomically.
    pub async fn admin_change_password(
        &self,
        admin_id: &str,
        update: &PasswordUpdate,
    ) -> Result<(), ClusterError> {
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "UPDATE admin_accounts SET password_phc = ?2, pepper_id = ?3, \
                 password_changed_at = ?4, password_expires_at = ?5, row_version = row_version + 1 \
                 WHERE admin_id = ?1",
                vec![
                    s(admin_id),
                    s(&update.password_phc),
                    Param::from(update.pepper_id),
                    Param::from(update.changed_at),
                    Param::from(update.expires_at),
                ],
            ),
            history_stmt(admin_id, update),
        ];
        txn_ok(self.client().txn(stmts).await?)?;
        Ok(())
    }

    /// Every earlier password hash of an account (reuse is forbidden).
    pub async fn admin_password_history(
        &self,
        admin_id: &str,
    ) -> Result<Vec<PasswordHistoryRow>, ClusterError> {
        let rows: Vec<HistoryRow> = self
            .client()
            .query_consistent_map(
                "SELECT password_phc, pepper_id FROM admin_password_history \
                 WHERE admin_id = ?1 ORDER BY set_at",
                vec![s(admin_id)],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| PasswordHistoryRow {
                password_phc: r.password_phc,
                pepper_id: r.pepper_id,
            })
            .collect())
    }

    /// Set an account's state, guarded by `expected_row_version` when given.
    /// Returns the new row version, or `None` on a version mismatch.
    ///
    /// With `require_other_account_admin` the write only applies while another
    /// active member of `ferrogate-account-admins` exists — checked inside the
    /// statement, so two administrators disabling each other concurrently
    /// cannot leave none (F20 §7 rule 4). Disabling also supersedes every
    /// unredeemed enrollment or reset token of the account.
    pub async fn admin_set_account_state(
        &self,
        admin_id: &str,
        state: i64,
        by_admin_id: &str,
        now: i64,
        expected_row_version: Option<i64>,
        require_other_account_admin: bool,
    ) -> Result<Option<i64>, ClusterError> {
        let (disabled_at, disabled_by) = if state == ACCOUNT_DISABLED {
            (Some(now), Some(by_admin_id.to_string()))
        } else {
            (None, None)
        };
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "UPDATE admin_accounts SET state = ?2, disabled_at = ?3, disabled_by_admin_id = ?4, \
                 row_version = row_version + 1 \
                 WHERE admin_id = ?1 AND (?5 IS NULL OR row_version = ?5) \
                 AND (?6 = 0 OR (SELECT COUNT(*) FROM admin_accounts a2 \
                    JOIN admin_group_members m2 ON m2.admin_id = a2.admin_id \
                    JOIN admin_groups g2 ON g2.group_id = m2.group_id \
                    WHERE g2.name = 'ferrogate-account-admins' AND a2.state = 2 \
                    AND a2.admin_id <> ?1) >= 1)",
                vec![
                    s(admin_id),
                    Param::from(state),
                    Param::from(disabled_at),
                    Param::from(disabled_by),
                    Param::from(expected_row_version),
                    Param::from(i64::from(require_other_account_admin)),
                ],
            ),
            (
                "UPDATE admin_enrollment_tokens SET used_at = ?2 \
                 WHERE admin_id = ?1 AND used_at IS NULL \
                 AND EXISTS (SELECT 1 FROM admin_accounts WHERE admin_id = ?1 AND state = 3)",
                vec![s(admin_id), Param::from(now)],
            ),
        ];
        let affected = txn_ok(self.client().txn(stmts).await?)?;
        if affected.first().copied() != Some(1) {
            return Ok(None);
        }
        Ok(self.admin_account(admin_id).await?.map(|a| a.row_version))
    }

    /// Update the display name and/or replace the group set, guarded by
    /// `expected_row_version`. Returns the new row version, or `None` on a
    /// version mismatch (in which case nothing was written: every statement
    /// is conditional on the expected version and the version bump runs last).
    ///
    /// With `require_other_account_admin` every statement also requires
    /// another active member of `ferrogate-account-admins` (F20 §7 rule 4,
    /// race-free); a refusal then also returns `None`.
    #[allow(clippy::too_many_arguments)]
    pub async fn admin_update_account(
        &self,
        admin_id: &str,
        display_name: Option<Option<String>>,
        groups: Option<&[String]>,
        by_admin_id: &str,
        now: i64,
        expected_row_version: i64,
        require_other_account_admin: bool,
    ) -> Result<Option<i64>, ClusterError> {
        if let Some(groups) = groups {
            self.check_groups_exist(groups).await?;
        }
        let id = || s(admin_id);
        let ver = || Param::from(expected_row_version);
        let need = || Param::from(i64::from(require_other_account_admin));
        let mut stmts: Vec<(&'static str, Vec<Param>)> = Vec::new();
        if let Some(name) = display_name {
            stmts.push((
                "UPDATE admin_accounts SET display_name = ?2 WHERE admin_id = ?1 AND row_version = ?3 \
                 AND (?4 = 0 OR (SELECT COUNT(*) FROM admin_accounts a2 \
                    JOIN admin_group_members m2 ON m2.admin_id = a2.admin_id \
                    JOIN admin_groups g2 ON g2.group_id = m2.group_id \
                    WHERE g2.name = 'ferrogate-account-admins' AND a2.state = 2 \
                    AND a2.admin_id <> ?1) >= 1)",
                vec![id(), Param::from(name), ver(), need()],
            ));
        }
        if let Some(groups) = groups {
            stmts.push((
                "DELETE FROM admin_group_members WHERE admin_id = ?1 AND EXISTS \
                 (SELECT 1 FROM admin_accounts WHERE admin_id = ?1 AND row_version = ?2) \
                 AND (?3 = 0 OR (SELECT COUNT(*) FROM admin_accounts a2 \
                    JOIN admin_group_members m2 ON m2.admin_id = a2.admin_id \
                    JOIN admin_groups g2 ON g2.group_id = m2.group_id \
                    WHERE g2.name = 'ferrogate-account-admins' AND a2.state = 2 \
                    AND a2.admin_id <> ?1) >= 1)",
                vec![id(), ver(), need()],
            ));
            for g in groups {
                // After the DELETE the guard must not count the target, which
                // it never does (`a2.admin_id <> ?1`), so it is stable here.
                stmts.push((
                    "INSERT INTO admin_group_members (admin_id, group_id, granted_by_admin_id, granted_at) \
                     SELECT ?1, group_id, ?3, ?4 FROM admin_groups WHERE name = ?2 AND EXISTS \
                     (SELECT 1 FROM admin_accounts WHERE admin_id = ?1 AND row_version = ?5) \
                     AND (?6 = 0 OR (SELECT COUNT(*) FROM admin_accounts a2 \
                    JOIN admin_group_members m2 ON m2.admin_id = a2.admin_id \
                    JOIN admin_groups g2 ON g2.group_id = m2.group_id \
                    WHERE g2.name = 'ferrogate-account-admins' AND a2.state = 2 \
                    AND a2.admin_id <> ?1) >= 1)",
                    vec![id(), s(g), s(by_admin_id), Param::from(now), ver(), need()],
                ));
            }
        }
        stmts.push((
            "UPDATE admin_accounts SET row_version = row_version + 1 \
             WHERE admin_id = ?1 AND row_version = ?2 AND (?3 = 0 OR (SELECT COUNT(*) FROM admin_accounts a2 \
                    JOIN admin_group_members m2 ON m2.admin_id = a2.admin_id \
                    JOIN admin_groups g2 ON g2.group_id = m2.group_id \
                    WHERE g2.name = 'ferrogate-account-admins' AND a2.state = 2 \
                    AND a2.admin_id <> ?1) >= 1)",
            vec![id(), ver(), need()],
        ));
        let affected = txn_ok(self.client().txn(stmts).await?)?;
        if affected.last().copied() != Some(1) {
            return Ok(None);
        }
        Ok(self.admin_account(admin_id).await?.map(|a| a.row_version))
    }

    /// Clear the password and/or TOTP secret of an account and store a reset
    /// token for it — atomically.
    pub async fn admin_reset_credentials(
        &self,
        admin_id: &str,
        reset_password: bool,
        reset_mfa: bool,
        token: &EnrollmentTokenRow,
    ) -> Result<(), ClusterError> {
        // Any earlier enrollment or reset token of the account is superseded:
        // only the token issued now can be redeemed.
        let mut stmts: Vec<(&'static str, Vec<Param>)> = vec![(
            "UPDATE admin_enrollment_tokens SET used_at = ?2 WHERE admin_id = ?1 AND used_at IS NULL",
            vec![s(admin_id), Param::from(token.created_at)],
        )];
        if reset_password {
            stmts.push((
                "UPDATE admin_accounts SET password_phc = NULL, pepper_id = NULL, \
                 row_version = row_version + 1 WHERE admin_id = ?1",
                vec![s(admin_id)],
            ));
        }
        if reset_mfa {
            stmts.push((
                "UPDATE admin_accounts SET totp_secret_enc = NULL, totp_last_step = NULL, \
                 row_version = row_version + 1 WHERE admin_id = ?1",
                vec![s(admin_id)],
            ));
            stmts.push((
                "DELETE FROM admin_webauthn_credentials WHERE admin_id = ?1",
                vec![s(admin_id)],
            ));
        }
        stmts.push(insert_token_stmt(token));
        txn_ok(self.client().txn(stmts).await?)?;
        Ok(())
    }

    // ---- second factors ----------------------------------------------------

    /// Store a TOTP secret for an active account that has none. Returns
    /// `false` when the account already holds one (or is not active).
    pub async fn admin_add_totp(
        &self,
        admin_id: &str,
        totp_secret_enc: &[u8],
        step: i64,
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "UPDATE admin_accounts SET totp_secret_enc = ?2, totp_last_step = ?3, \
                 row_version = row_version + 1 \
                 WHERE admin_id = ?1 AND state = 2 AND totp_secret_enc IS NULL",
                vec![
                    s(admin_id),
                    Param::from(totp_secret_enc.to_vec()),
                    Param::from(step),
                ],
            )
            .await?;
        Ok(n > 0)
    }

    /// Remove an account's TOTP secret, but only while it keeps at least one
    /// FIDO2 credential (checked inside the statement, so concurrent removals
    /// can never leave the account without a factor). Returns `false` when
    /// nothing was removed.
    pub async fn admin_remove_totp(&self, admin_id: &str) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "UPDATE admin_accounts SET totp_secret_enc = NULL, totp_last_step = NULL, \
                 row_version = row_version + 1 \
                 WHERE admin_id = ?1 AND totp_secret_enc IS NOT NULL \
                 AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id = ?1) >= 1",
                vec![s(admin_id)],
            )
            .await?;
        Ok(n > 0)
    }

    /// The FIDO2 credentials of an account, oldest first.
    pub async fn admin_webauthn_credentials(
        &self,
        admin_id: &str,
    ) -> Result<Vec<WebAuthnCredentialRow>, ClusterError> {
        Ok(self
            .client()
            .query_consistent_map(
                format!(
                    "SELECT {WEBAUTHN_COLUMNS} FROM admin_webauthn_credentials \
                     WHERE admin_id = ?1 ORDER BY created_at, credential_id"
                ),
                vec![s(admin_id)],
            )
            .await?)
    }

    /// One credential, only if it belongs to `admin_id`.
    pub async fn admin_webauthn_credential(
        &self,
        admin_id: &str,
        credential_id: &[u8],
    ) -> Result<Option<WebAuthnCredentialRow>, ClusterError> {
        let rows: Vec<WebAuthnCredentialRow> = self
            .client()
            .query_consistent_map(
                format!(
                    "SELECT {WEBAUTHN_COLUMNS} FROM admin_webauthn_credentials \
                     WHERE admin_id = ?1 AND credential_id = ?2"
                ),
                vec![s(admin_id), Param::from(credential_id.to_vec())],
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Register a credential while the account holds fewer than
    /// [`MAX_WEBAUTHN_CREDENTIALS`] (checked inside the statement). Returns
    /// `false` at the cap; a credential id that is already registered, to any
    /// account, fails with [`ClusterError::Conflict`].
    pub async fn admin_add_webauthn_credential(
        &self,
        row: &WebAuthnCredentialRow,
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "INSERT INTO admin_webauthn_credentials (credential_id, admin_id, cose_public_key, \
                 sign_count, aaguid, label, created_at, last_used_at) \
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL \
                 WHERE (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id = ?2) < ?8",
                vec![
                    Param::from(row.credential_id.clone()),
                    s(&row.admin_id),
                    Param::from(row.cose_public_key.clone()),
                    Param::from(row.sign_count),
                    Param::from(row.aaguid.clone()),
                    Param::from(row.label.clone()),
                    Param::from(row.created_at),
                    Param::from(MAX_WEBAUTHN_CREDENTIALS),
                ],
            )
            .await
            .map_err(|e| unique_as_conflict(e.into()))?;
        Ok(n > 0)
    }

    /// Accept an assertion's signature counter (compare-and-set): the new
    /// value must be greater than the stored one, unless both are zero (an
    /// authenticator without a counter). Returns `false` on a regression —
    /// a possible cloned authenticator — or a concurrent use of the same
    /// value on any node.
    pub async fn admin_webauthn_used(
        &self,
        admin_id: &str,
        credential_id: &[u8],
        sign_count: i64,
        now: i64,
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "UPDATE admin_webauthn_credentials SET sign_count = ?3, last_used_at = ?4 \
                 WHERE admin_id = ?1 AND credential_id = ?2 \
                 AND (sign_count < ?3 OR (sign_count = 0 AND ?3 = 0))",
                vec![
                    s(admin_id),
                    Param::from(credential_id.to_vec()),
                    Param::from(sign_count),
                    Param::from(now),
                ],
            )
            .await?;
        Ok(n > 0)
    }

    /// Remove one credential of `admin_id`, but only while the account keeps
    /// another factor (another credential or a TOTP secret), checked inside
    /// the statement. Returns `false` when nothing was removed.
    pub async fn admin_remove_webauthn_credential(
        &self,
        admin_id: &str,
        credential_id: &[u8],
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "DELETE FROM admin_webauthn_credentials \
                 WHERE admin_id = ?1 AND credential_id = ?2 \
                 AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id = ?1) \
                   + (SELECT COUNT(*) FROM admin_accounts \
                      WHERE admin_id = ?1 AND totp_secret_enc IS NOT NULL) > 1",
                vec![s(admin_id), Param::from(credential_id.to_vec())],
            )
            .await?;
        Ok(n > 0)
    }

    // ---- groups ------------------------------------------------------------

    /// Group names of an account.
    pub async fn admin_groups_of(&self, admin_id: &str) -> Result<Vec<String>, ClusterError> {
        let rows: Vec<StringRow> = self
            .client()
            .query_consistent_map(
                "SELECT g.name AS v FROM admin_group_members m \
                 JOIN admin_groups g ON g.group_id = m.group_id \
                 WHERE m.admin_id = ?1 ORDER BY g.name",
                vec![s(admin_id)],
            )
            .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Permission strings an account holds through its groups.
    pub async fn admin_permissions_of(&self, admin_id: &str) -> Result<Vec<String>, ClusterError> {
        let rows: Vec<StringRow> = self
            .client()
            .query_consistent_map(
                "SELECT DISTINCT p.permission AS v FROM admin_group_members m \
                 JOIN admin_group_permissions p ON p.group_id = m.group_id \
                 WHERE m.admin_id = ?1 ORDER BY p.permission",
                vec![s(admin_id)],
            )
            .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Every group with its permissions.
    pub async fn admin_groups(&self) -> Result<Vec<AdminGroupRow>, ClusterError> {
        let rows: Vec<GroupPermRow> = self
            .client()
            .query_consistent_map(
                "SELECT g.group_id AS group_id, g.name AS name, g.builtin AS builtin, \
                 p.permission AS permission FROM admin_groups g \
                 LEFT JOIN admin_group_permissions p ON p.group_id = g.group_id \
                 ORDER BY g.name, p.permission",
                Vec::new(),
            )
            .await?;
        let mut out: Vec<AdminGroupRow> = Vec::new();
        for r in rows {
            if out.last().is_none_or(|g| g.group_id != r.group_id) {
                out.push(AdminGroupRow {
                    group_id: r.group_id.clone(),
                    name: r.name.clone(),
                    builtin: r.builtin != 0,
                    permissions: Vec::new(),
                });
            }
            if let (Some(p), Some(g)) = (r.permission, out.last_mut()) {
                g.permissions.push(p);
            }
        }
        Ok(out)
    }

    /// Ids of the **active** accounts that are members of group `name`.
    pub async fn admin_active_members_of(&self, name: &str) -> Result<Vec<String>, ClusterError> {
        let rows: Vec<StringRow> = self
            .client()
            .query_consistent_map(
                "SELECT a.admin_id AS v FROM admin_accounts a \
                 JOIN admin_group_members m ON m.admin_id = a.admin_id \
                 JOIN admin_groups g ON g.group_id = m.group_id \
                 WHERE g.name = ?1 AND a.state = 2 ORDER BY a.admin_id",
                vec![s(name)],
            )
            .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    // ---- sessions ----------------------------------------------------------

    /// Store a new session.
    pub async fn admin_insert_session(&self, row: &AdminSessionRow) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "INSERT INTO admin_sessions (session_hash, admin_id, created_at, last_seen_at, \
                 absolute_expires_at, idle_timeout_secs, aal, mfa_at, mfa_method, source_ip, \
                 client_cert_sha256, client_kind, client_version, restricted, revoked_at, \
                 revoked_reason, stepup_failures) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, NULL, 0)",
                vec![
                    Param::from(row.session_hash.clone()),
                    s(&row.admin_id),
                    Param::from(row.created_at),
                    Param::from(row.last_seen_at),
                    Param::from(row.absolute_expires_at),
                    Param::from(row.idle_timeout_secs),
                    Param::from(row.aal),
                    Param::from(row.mfa_at),
                    Param::from(row.mfa_method),
                    s(&row.source_ip),
                    Param::from(row.client_cert_sha256.clone()),
                    Param::from(row.client_kind),
                    Param::from(row.client_version.clone()),
                    Param::from(row.restricted),
                ],
            )
            .await?;
        Ok(())
    }

    /// One session by token hash (revoked sessions included).
    pub async fn admin_session(
        &self,
        session_hash: &[u8],
    ) -> Result<Option<AdminSessionRow>, ClusterError> {
        let rows: Vec<AdminSessionRow> = self
            .client()
            .query_consistent_map(
                format!("SELECT {SESSION_COLUMNS} FROM admin_sessions WHERE session_hash = ?1"),
                vec![Param::from(session_hash.to_vec())],
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// The non-revoked sessions of an account, oldest first.
    pub async fn admin_live_sessions(
        &self,
        admin_id: &str,
    ) -> Result<Vec<AdminSessionRow>, ClusterError> {
        Ok(self
            .client()
            .query_consistent_map(
                format!(
                    "SELECT {SESSION_COLUMNS} FROM admin_sessions \
                     WHERE admin_id = ?1 AND revoked_at IS NULL ORDER BY created_at, session_hash"
                ),
                vec![s(admin_id)],
            )
            .await?)
    }

    /// Record activity on a session.
    pub async fn admin_touch_session(
        &self,
        session_hash: &[u8],
        now: i64,
    ) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "UPDATE admin_sessions SET last_seen_at = ?2 WHERE session_hash = ?1",
                vec![Param::from(session_hash.to_vec()), Param::from(now)],
            )
            .await?;
        Ok(())
    }

    /// Revoke one session. Returns `false` if it was already revoked or absent.
    pub async fn admin_revoke_session(
        &self,
        session_hash: &[u8],
        now: i64,
        reason: i64,
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "UPDATE admin_sessions SET revoked_at = ?2, revoked_reason = ?3 \
                 WHERE session_hash = ?1 AND revoked_at IS NULL",
                vec![
                    Param::from(session_hash.to_vec()),
                    Param::from(now),
                    Param::from(reason),
                ],
            )
            .await?;
        Ok(n > 0)
    }

    /// Replace a session's token hash (rotation on step-up or password change)
    /// and, after a step-up, record the verification (time, method and the
    /// assurance level it reached). Returns `false` if the old session is gone
    /// or revoked.
    pub async fn admin_rotate_session(
        &self,
        old_hash: &[u8],
        new_hash: &[u8],
        mfa: Option<MfaVerification>,
        restricted: i64,
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "UPDATE admin_sessions SET session_hash = ?2, \
                 mfa_at = COALESCE(?3, mfa_at), mfa_method = COALESCE(?4, mfa_method), \
                 aal = COALESCE(?6, aal), restricted = ?5, stepup_failures = 0 \
                 WHERE session_hash = ?1 AND revoked_at IS NULL",
                vec![
                    Param::from(old_hash.to_vec()),
                    Param::from(new_hash.to_vec()),
                    Param::from(mfa.map(|m| m.at)),
                    Param::from(mfa.map(|m| m.method)),
                    Param::from(restricted),
                    Param::from(mfa.map(|m| m.aal)),
                ],
            )
            .await?;
        Ok(n > 0)
    }

    /// Count one failed step-up on a session and return the new total.
    pub async fn admin_session_stepup_failed(
        &self,
        session_hash: &[u8],
    ) -> Result<i64, ClusterError> {
        self.client()
            .execute(
                "UPDATE admin_sessions SET stepup_failures = stepup_failures + 1 \
                 WHERE session_hash = ?1",
                vec![Param::from(session_hash.to_vec())],
            )
            .await?;
        Ok(self
            .admin_session(session_hash)
            .await?
            .map_or(0, |r| r.stepup_failures))
    }

    // ---- enrollment tokens -------------------------------------------------

    /// One enrollment token by hash.
    pub async fn admin_enrollment_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<EnrollmentTokenRow>, ClusterError> {
        let rows: Vec<EnrollmentTokenRow> = self
            .client()
            .query_consistent_map(
                "SELECT token_hash, admin_id, purpose, created_by_admin_id, created_at, \
                 expires_at, used_at, pending_secret_enc FROM admin_enrollment_tokens \
                 WHERE token_hash = ?1",
                vec![Param::from(token_hash.to_vec())],
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Replace the pending TOTP seed of a live token (each `BeginEnrollment`
    /// rotates it). Returns `false` if the token is redeemed or expired.
    pub async fn admin_set_pending_secret(
        &self,
        token_hash: &[u8],
        sealed: &[u8],
        now: i64,
    ) -> Result<bool, ClusterError> {
        let n = self
            .client()
            .execute(
                "UPDATE admin_enrollment_tokens SET pending_secret_enc = ?2 \
                 WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?3",
                vec![
                    Param::from(token_hash.to_vec()),
                    Param::from(sealed.to_vec()),
                    Param::from(now),
                ],
            )
            .await?;
        Ok(n > 0)
    }

    /// Store a new enrollment token.
    pub async fn admin_insert_enrollment_token(
        &self,
        token: &EnrollmentTokenRow,
    ) -> Result<(), ClusterError> {
        let (sql, params) = insert_token_stmt(token);
        self.client().execute(sql, params).await?;
        Ok(())
    }

    /// Whether an unredeemed, unexpired token of `purpose` exists.
    pub async fn admin_live_token_exists(
        &self,
        purpose: i64,
        now: i64,
    ) -> Result<bool, ClusterError> {
        let rows: Vec<CountRow> = self
            .client()
            .query_consistent_map(
                "SELECT COUNT(*) AS n FROM admin_enrollment_tokens \
                 WHERE purpose = ?1 AND used_at IS NULL AND expires_at > ?2",
                vec![Param::from(purpose), Param::from(now)],
            )
            .await?;
        Ok(rows.first().is_some_and(|r| r.0 > 0))
    }

    // ---- throttle ----------------------------------------------------------

    /// One throttle row.
    pub async fn admin_throttle(
        &self,
        key_hash: &[u8],
    ) -> Result<Option<ThrottleRow>, ClusterError> {
        let rows: Vec<ThrottleRow> = self
            .client()
            .query_consistent_map(
                "SELECT key_hash, key_kind, failures, locked_until, last_failure_at \
                 FROM admin_login_throttle WHERE key_hash = ?1",
                vec![Param::from(key_hash.to_vec())],
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Insert or replace one throttle row.
    pub async fn admin_put_throttle(&self, row: &ThrottleRow) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "INSERT INTO admin_login_throttle (key_hash, key_kind, failures, locked_until, \
                 last_failure_at) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (key_hash) DO UPDATE SET key_kind = excluded.key_kind, \
                 failures = excluded.failures, locked_until = excluded.locked_until, \
                 last_failure_at = excluded.last_failure_at",
                vec![
                    Param::from(row.key_hash.clone()),
                    Param::from(row.key_kind),
                    Param::from(row.failures),
                    Param::from(row.locked_until),
                    Param::from(row.last_failure_at),
                ],
            )
            .await?;
        Ok(())
    }

    /// Count one failure on a throttle key **atomically** (a single upsert,
    /// serialised by Raft, so concurrent failures on any node are never lost)
    /// and return the row after the increment. A counter idle for
    /// `reset_after_secs` starts over at 1, and its old lock is dropped.
    pub async fn admin_throttle_increment(
        &self,
        key_hash: &[u8],
        key_kind: i64,
        now: i64,
        reset_after_secs: i64,
    ) -> Result<ThrottleRow, ClusterError> {
        Ok(self
            .client()
            .execute_returning_map_one(
                "INSERT INTO admin_login_throttle (key_hash, key_kind, failures, locked_until, \
                 last_failure_at) VALUES (?1, ?2, 1, 0, ?3) \
                 ON CONFLICT (key_hash) DO UPDATE SET \
                 failures = CASE WHEN admin_login_throttle.last_failure_at <= ?3 - ?4 THEN 1 \
                    ELSE admin_login_throttle.failures + 1 END, \
                 locked_until = CASE WHEN admin_login_throttle.last_failure_at <= ?3 - ?4 THEN 0 \
                    ELSE admin_login_throttle.locked_until END, \
                 last_failure_at = ?3 \
                 RETURNING key_hash, key_kind, failures, locked_until, last_failure_at",
                vec![
                    Param::from(key_hash.to_vec()),
                    Param::from(key_kind),
                    Param::from(now),
                    Param::from(reset_after_secs),
                ],
            )
            .await?)
    }

    /// Extend a key's lock to at least `until` (never shortens it).
    pub async fn admin_throttle_lock(
        &self,
        key_hash: &[u8],
        until: i64,
    ) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "UPDATE admin_login_throttle SET locked_until = MAX(locked_until, ?2) \
                 WHERE key_hash = ?1",
                vec![Param::from(key_hash.to_vec()), Param::from(until)],
            )
            .await?;
        Ok(())
    }

    /// Forget one throttle key (after a successful login).
    pub async fn admin_clear_throttle(&self, key_hash: &[u8]) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "DELETE FROM admin_login_throttle WHERE key_hash = ?1",
                vec![Param::from(key_hash.to_vec())],
            )
            .await?;
        Ok(())
    }

    // ---- security log & settings --------------------------------------------

    /// Append one row to the INSERT-only operational security log.
    pub async fn admin_security_log(
        &self,
        at: i64,
        event: &str,
        admin_id: Option<&str>,
        username_attempted_hmac: Option<&[u8]>,
        source_ip: Option<&str>,
        detail: Option<&str>,
    ) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "INSERT INTO admin_security_log (at, event, admin_id, username_attempted_hmac, \
                 source_ip, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                vec![
                    Param::from(at),
                    s(event),
                    Param::from(admin_id.map(str::to_string)),
                    Param::from(username_attempted_hmac.map(<[u8]>::to_vec)),
                    Param::from(source_ip.map(str::to_string)),
                    Param::from(detail.map(str::to_string)),
                ],
            )
            .await?;
        Ok(())
    }

    /// Number of security-log rows of `event` at or after `since`.
    pub async fn admin_security_log_count(
        &self,
        event: &str,
        since: i64,
    ) -> Result<u64, ClusterError> {
        let rows: Vec<CountRow> = self
            .client()
            .query_consistent_map(
                "SELECT COUNT(*) AS n FROM admin_security_log WHERE event = ?1 AND at >= ?2",
                vec![s(event), Param::from(since)],
            )
            .await?;
        Ok(rows.first().map_or(0, |r| u64::try_from(r.0).unwrap_or(0)))
    }

    /// Read one `cmis_settings` value.
    pub async fn setting(&self, key: &str) -> Result<Option<String>, ClusterError> {
        let rows: Vec<StringRow> = self
            .client()
            .query_consistent_map(
                "SELECT value AS v FROM cmis_settings WHERE key = ?1",
                vec![s(key)],
            )
            .await?;
        Ok(rows.into_iter().next().map(|r| r.0))
    }

    /// Write one `cmis_settings` value.
    pub async fn put_setting(&self, key: &str, value: &str) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "INSERT INTO cmis_settings (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                vec![s(key), s(value)],
            )
            .await?;
        Ok(())
    }

    /// Store `value` under `key` only if the key is absent. Returns the value
    /// now stored (the existing one when the key was already set).
    pub async fn setting_set_once(&self, key: &str, value: &str) -> Result<String, ClusterError> {
        self.client()
            .execute(
                "INSERT OR IGNORE INTO cmis_settings (key, value) VALUES (?1, ?2)",
                vec![s(key), s(value)],
            )
            .await?;
        Ok(self.setting(key).await?.unwrap_or_default())
    }
}

fn insert_token_stmt(token: &EnrollmentTokenRow) -> (&'static str, Vec<Param>) {
    (
        "INSERT INTO admin_enrollment_tokens (token_hash, admin_id, purpose, created_by_admin_id, \
         created_at, expires_at, used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        vec![
            Param::from(token.token_hash.clone()),
            Param::from(token.admin_id.clone()),
            Param::from(token.purpose),
            Param::from(token.created_by_admin_id.clone()),
            Param::from(token.created_at),
            Param::from(token.expires_at),
        ],
    )
}

fn history_stmt(admin_id: &str, pw: &PasswordUpdate) -> (&'static str, Vec<Param>) {
    (
        "INSERT INTO admin_password_history (admin_id, password_phc, pepper_id, set_at) \
         VALUES (?1, ?2, ?3, ?4)",
        vec![
            s(admin_id),
            s(&pw.password_phc),
            Param::from(pw.pepper_id),
            Param::from(pw.changed_at),
        ],
    )
}
