//! The migration from hand-provisioned v1 allowlists to approvals (F19 §11).
//!
//! **Import (step 4).** Every `(uid, bin_sha)` entry of a host's legacy
//! `host_allowlists` body becomes one `ACTIVE` approval with origin
//! `legacy_import`, `path_match = any`, `update_policy = manual_each_time`,
//! no expiry, no revision, no approving administrator, and the uid and the
//! `"*"` wildcard exactly as stored. The approval id is derived from the
//! entry ([`legacy_approval_id`]), so the import is idempotent by
//! construction: an entry whose approval exists — in any state, a revoked one
//! included — is "already imported" and is never created again, and the
//! primary key refuses a duplicate even if two imports race. The legacy
//! `host_allowlists` rows are only read, never changed, so a rollback to
//! `legacy` mode serves them as before.
//!
//! A legacy import names a per-host lineage id ([`legacy_lineage_id`]) that
//! has no `app_lineages` row: the path of a v1 entry is unknown. Migration 3
//! (`schema::LEGACY_IMPORT_GUARDS`) refuses any other shape in SQL.
//!
//! **Mode switch (steps 5 and 6).** [`Cluster::app_mode_rollback_counts`]
//! is what a switch back to `legacy` would change, and
//! [`Cluster::app_legacy_imports_of`] lets the caller find imports whose
//! entry has since left the legacy body (they must not come back to life
//! in `approvals` mode). The legacy writes that race a switch are guarded
//! in the same transaction as the write
//! ([`Cluster::upsert_allowlist_unless_setting`],
//! [`Cluster::delete_allowlist_unless_setting`]).

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use hiqlite::Param;
use ring::digest::{digest, SHA256};

use super::decisions::insert_approval_stmt;
use super::generation::bump_generation_stmt;
use super::intake::insert_revision_stmt;
use super::model::{
    is_bin_sha, ApprovalOrigin, ApprovalRow, ApprovalSnapshot, ApprovalState, Continuity,
    PathMatch, RevisionChange, UpdatePolicy, UserScope,
};
use super::{check_id, generic_refusal, guard_code, text, LedgerError, TxnOutcome};
use crate::cluster::{Cluster, ClusterError};

/// Most entries one [`Cluster::app_import_legacy`] call writes (one Raft
/// transaction of three statements per entry). Larger bodies are imported
/// in batches by the caller.
pub const MAX_IMPORT_BATCH: usize = 256;

/// Attempts of one import batch when a concurrent import created some of its
/// approvals between the read and the write.
const IMPORT_ATTEMPTS: usize = 3;

/// The v1 `bin_sha` wildcard (any binary), allowed only in legacy imports.
pub const LEGACY_BIN_WILDCARD: &str = "*";

/// One entry of a legacy v1 allowlist body, validated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LegacyEntry {
    /// The admitted Unix uid (or Windows RID); `None` admits every user.
    pub uid: Option<i64>,
    /// Lowercase-hex SHA-384, or [`LEGACY_BIN_WILDCARD`].
    pub bin_sha: String,
}

impl LegacyEntry {
    /// An entry as a v1 body stores it. Refuses a `bin_sha` that is neither
    /// a lowercase-hex SHA-384 nor the wildcard.
    pub fn new(uid: Option<u32>, bin_sha: &str) -> Result<Self, LedgerError> {
        if bin_sha != LEGACY_BIN_WILDCARD && !is_bin_sha(bin_sha) {
            return Err(LedgerError::Invalid("bin_sha"));
        }
        Ok(Self {
            uid: uid.map(i64::from),
            bin_sha: bin_sha.to_string(),
        })
    }
}

/// One stored legacy import of a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyImportRow {
    /// The approval id ([`legacy_approval_id`] of the entry).
    pub approval_id: String,
    /// The entry it was imported from.
    pub entry: LegacyEntry,
    /// The approval's state now.
    pub state: ApprovalState,
}

/// What one import batch did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyImport {
    /// The approvals this call created, in entry order.
    pub created: Vec<ApprovalRow>,
    /// Entries whose approval already existed (in any state).
    pub already_imported: usize,
    /// The host's allowlist generation after the call (bumped only when
    /// something was created).
    pub generation: u64,
}

/// What switching back to `legacy` mode would change (F19 §11 step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModeRollbackCounts {
    /// Live approvals other than legacy imports: the preserved legacy bodies
    /// do not carry them, so they stop admitting callers.
    pub approvals_not_reflected: u64,
    /// Legacy imports that are no longer live (revoked or expired since the
    /// import): the legacy bodies still list them and admit them again.
    pub imports_readmitted: u64,
}

/// A UUIDv8 (RFC 9562 custom layout) from the first 16 bytes of
/// `SHA-256(parts joined by NUL)`.
fn derived_uuid(parts: &[&str]) -> String {
    let joined = parts.join("\0");
    let hash = digest(&SHA256, joined.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&hash.as_ref()[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex_lower(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// The lineage id every legacy import of `host_uuid` names. No
/// `app_lineages` row has it: a v1 entry has no path.
#[must_use]
pub fn legacy_lineage_id(host_uuid: &str) -> String {
    derived_uuid(&["ferrogate-legacy-import-lineage-v1", host_uuid])
}

/// The approval id of the legacy import of `entry` on `host_uuid`: the same
/// entry always maps to the same id, which makes the import idempotent.
#[must_use]
pub fn legacy_approval_id(host_uuid: &str, entry: &LegacyEntry) -> String {
    let uid = entry
        .uid
        .map_or_else(|| "any".to_string(), |u| format!("u{u}"));
    derived_uuid(&[
        "ferrogate-legacy-import-v1",
        host_uuid,
        &uid,
        &entry.bin_sha,
    ])
}

/// The approval a legacy import of `entry` creates (F19 §11 step 4).
fn legacy_approval(host_uuid: &str, entry: &LegacyEntry, now: i64) -> ApprovalRow {
    ApprovalRow {
        approval_id: legacy_approval_id(host_uuid, entry),
        host_uuid: host_uuid.to_string(),
        lineage_id: legacy_lineage_id(host_uuid),
        bin_sha: entry.bin_sha.clone(),
        revision: None,
        source_request_id: None,
        origin: ApprovalOrigin::LegacyImport,
        parent_approval_id: None,
        approved_by_admin_id: None,
        user_scope: if entry.uid.is_some() {
            UserScope::ExactUser
        } else {
            UserScope::AnyUser
        },
        user_kind: None,
        uid: entry.uid,
        sid: None,
        user_name: None,
        path_match: PathMatch::Any,
        update_policy: UpdatePolicy::ManualEachTime,
        continuity: Continuity::Anchored,
        created_at: now,
        expires_at: None,
        state: ApprovalState::Active,
        superseded_by: None,
        revoked_at: None,
        revoked_by_admin_id: None,
        revoke_reason_code: None,
        note: None,
        row_version: 1,
    }
}

#[derive(Debug)]
struct IdRow(String);
impl<'r> From<&'r mut hiqlite::Row<'_>> for IdRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("approval_id"))
    }
}

struct ImportRow(Result<LegacyImportRow, LedgerError>);
impl<'r> From<&'r mut hiqlite::Row<'_>> for ImportRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        let state: i64 = row.get("state");
        Self(
            ApprovalState::from_code(state)
                .ok_or(LedgerError::Corrupt("state"))
                .map(|state| LegacyImportRow {
                    approval_id: row.get("approval_id"),
                    entry: LegacyEntry {
                        uid: row.get("uid"),
                        bin_sha: row.get("bin_sha"),
                    },
                    state,
                }),
        )
    }
}

#[derive(Debug)]
struct HostRow(String);
impl<'r> From<&'r mut hiqlite::Row<'_>> for HostRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("host_uuid"))
    }
}

#[derive(Debug)]
struct CountsRow(i64, i64);
impl<'r> From<&'r mut hiqlite::Row<'_>> for CountsRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("x"), row.get("y"))
    }
}

#[derive(Debug)]
struct FlagRow(i64);
impl<'r> From<&'r mut hiqlite::Row<'_>> for FlagRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("n"))
    }
}

impl Cluster {
    /// The ids of every legacy import of `host_uuid`, in any state.
    async fn legacy_import_ids(&self, host_uuid: &str) -> Result<BTreeSet<String>, LedgerError> {
        let rows: Vec<IdRow> = self
            .client()
            .query_consistent_map(
                "SELECT approval_id FROM app_approvals WHERE host_uuid = ?1 AND origin = 4",
                vec![text(host_uuid)],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// For each of `entries`, whether its legacy import already exists on
    /// `host_uuid` (in any state). Writes nothing (the import dry run).
    pub async fn app_legacy_imported(
        &self,
        host_uuid: &str,
        entries: &[LegacyEntry],
    ) -> Result<Vec<bool>, LedgerError> {
        check_id(host_uuid, "host_uuid")?;
        let existing = self.legacy_import_ids(host_uuid).await?;
        Ok(entries
            .iter()
            .map(|e| existing.contains(&legacy_approval_id(host_uuid, e)))
            .collect())
    }

    /// Every legacy import of `host_uuid`, in any state, by approval id.
    pub async fn app_legacy_imports_of(
        &self,
        host_uuid: &str,
    ) -> Result<Vec<LegacyImportRow>, LedgerError> {
        check_id(host_uuid, "host_uuid")?;
        let rows: Vec<ImportRow> = self
            .client()
            .query_consistent_map(
                "SELECT approval_id, uid, bin_sha, state FROM app_approvals \
                 WHERE host_uuid = ?1 AND origin = 4 ORDER BY approval_id",
                vec![text(host_uuid)],
            )
            .await
            .map_err(ClusterError::from)?;
        rows.into_iter().map(|r| r.0).collect()
    }

    /// The hosts that have a legacy import that is not revoked (`ACTIVE`, or
    /// `EXPIRED` and so renewable), ordered.
    pub async fn app_hosts_with_open_legacy_imports(&self) -> Result<Vec<String>, LedgerError> {
        let rows: Vec<HostRow> = self
            .client()
            .query_consistent_map(
                "SELECT DISTINCT host_uuid FROM app_approvals \
                 WHERE origin = 4 AND state IN (1, 2) ORDER BY host_uuid",
                Vec::new(),
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Store or replace `host_uuid`'s legacy allowlist body unless the
    /// `cmis_settings` value of `key` is `refused_value`, checked in the same
    /// Raft transaction as the write (so a write cannot slip in after a mode
    /// switch). Returns `false`, having written nothing, when refused.
    pub async fn upsert_allowlist_unless_setting(
        &self,
        host_uuid: &str,
        payload: &[u8],
        now_unix: i64,
        key: &str,
        refused_value: &str,
    ) -> Result<bool, LedgerError> {
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            setting_guard_stmt(key, refused_value),
            (
                "INSERT INTO host_allowlists (host_uuid, payload, updated_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT (host_uuid) DO UPDATE SET payload = excluded.payload, \
                    updated_at = excluded.updated_at",
                vec![
                    text(host_uuid),
                    Param::from(payload.to_vec()),
                    Param::from(now_unix),
                ],
            ),
        ];
        Ok(self.guarded_txn(stmts).await?.is_some())
    }

    /// Delete `host_uuid`'s legacy allowlist body unless the `cmis_settings`
    /// value of `key` is `refused_value`, checked in the same transaction.
    /// `None` when refused; otherwise whether a body existed.
    pub async fn delete_allowlist_unless_setting(
        &self,
        host_uuid: &str,
        key: &str,
        refused_value: &str,
    ) -> Result<Option<bool>, LedgerError> {
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            setting_guard_stmt(key, refused_value),
            (
                "DELETE FROM host_allowlists WHERE host_uuid = ?1",
                vec![text(host_uuid)],
            ),
        ];
        Ok(self
            .guarded_txn(stmts)
            .await?
            .map(|counts| counts.get(1).is_some_and(|n| *n > 0)))
    }

    /// Run `stmts` in one transaction: the affected-row counts, or `None`
    /// when the leading setting guard refused it (nothing written).
    async fn guarded_txn(
        &self,
        stmts: Vec<(&'static str, Vec<Param>)>,
    ) -> Result<Option<Vec<usize>>, LedgerError> {
        match self.client().txn(stmts).await {
            Ok(results) => {
                let mut counts = Vec::with_capacity(results.len());
                for r in results {
                    counts.push(r.map_err(ClusterError::from)?);
                }
                Ok(Some(counts))
            }
            Err(e) if guard_code(&e).as_deref() == Some("invalid_state") => Ok(None),
            Err(e) => Err(ClusterError::from(e).into()),
        }
    }

    /// A fingerprint of the legacy store: the number of `host_allowlists`
    /// rows and their latest `updated_at` (strongly consistent).
    pub async fn legacy_allowlists_fingerprint(&self) -> Result<(i64, i64), LedgerError> {
        let rows: Vec<CountsRow> = self
            .client()
            .query_consistent_map(
                "SELECT COUNT(*) AS x, COALESCE(MAX(updated_at), 0) AS y FROM host_allowlists",
                Vec::new(),
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows.first().map_or((0, 0), |r| (r.0, r.1)))
    }

    /// Store the `cmis_settings` value `key = value` only if the legacy store
    /// still has `fingerprint` ([`Cluster::legacy_allowlists_fingerprint`]),
    /// checked in the same transaction: a mode switch decided on a plan of the
    /// legacy bodies cannot commit after one of them changed. Returns
    /// `false`, having written nothing, when the store moved on.
    pub async fn put_setting_if_legacy_unchanged(
        &self,
        key: &str,
        value: &str,
        fingerprint: (i64, i64),
    ) -> Result<bool, LedgerError> {
        let stmts: Vec<(&'static str, Vec<Param>)> = vec![
            (
                "INSERT INTO app_txn_guard (code) SELECT 'invalid_state' \
                 WHERE (SELECT COUNT(*) FROM host_allowlists) <> ?1 \
                    OR (SELECT COALESCE(MAX(updated_at), 0) FROM host_allowlists) <> ?2",
                vec![Param::from(fingerprint.0), Param::from(fingerprint.1)],
            ),
            (
                "INSERT INTO cmis_settings (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                vec![text(key), text(value)],
            ),
        ];
        Ok(self.guarded_txn(stmts).await?.is_some())
    }

    /// Whether this node's replica knows `host_uuid` at all: an approval in
    /// any state, or a legacy body. A local read (no leader round trip), for
    /// the unauthenticated v1 `GetAllowlist`; a host that appeared a few
    /// milliseconds ago may read as unknown, which only delays its first body.
    pub async fn app_host_known_local(&self, host_uuid: &str) -> Result<bool, LedgerError> {
        let rows: Vec<FlagRow> = self
            .client()
            .query_map(
                "SELECT (EXISTS (SELECT 1 FROM app_approvals WHERE host_uuid = ?1) \
                    OR EXISTS (SELECT 1 FROM host_allowlists WHERE host_uuid = ?1)) AS n",
                vec![text(host_uuid)],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows.first().is_some_and(|r| r.0 != 0))
    }

    /// Import `entries` of `host_uuid`'s legacy allowlist as approvals, in one
    /// transaction: each entry not imported yet gets its approval and the
    /// creation revision (recording the importing administrator), and the
    /// host's generation is bumped once when anything was created. Entries
    /// already imported — in any state, so a revoked import stays revoked —
    /// and duplicates within `entries` are skipped. At most
    /// [`MAX_IMPORT_BATCH`] entries per call.
    ///
    /// A concurrent import of the same entries makes the transaction abort on
    /// its guard; the batch is then re-read and retried, so the outcome is
    /// the same as one serial import. Nothing else is read or written: the
    /// legacy `host_allowlists` row stays as it is.
    pub async fn app_import_legacy(
        &self,
        host_uuid: &str,
        entries: &[LegacyEntry],
        admin_id: &str,
        now: i64,
        generation_millis: i64,
    ) -> Result<LegacyImport, LedgerError> {
        check_id(host_uuid, "host_uuid")?;
        check_id(admin_id, "admin_id")?;
        if entries.len() > MAX_IMPORT_BATCH {
            return Err(LedgerError::Invalid("entries"));
        }
        for e in entries {
            if e.bin_sha != LEGACY_BIN_WILDCARD && !is_bin_sha(&e.bin_sha) {
                return Err(LedgerError::Invalid("bin_sha"));
            }
            if e.uid.is_some_and(|u| u32::try_from(u).is_err()) {
                return Err(LedgerError::Invalid("uid"));
            }
        }
        // One approval per distinct entry, in a stable order.
        let unique: BTreeMap<String, &LegacyEntry> = entries
            .iter()
            .map(|e| (legacy_approval_id(host_uuid, e), e))
            .collect();
        for _ in 0..IMPORT_ATTEMPTS {
            let existing = self.legacy_import_ids(host_uuid).await?;
            let to_create: Vec<ApprovalRow> = unique
                .iter()
                .filter(|(id, _)| !existing.contains(*id))
                .map(|(_, e)| legacy_approval(host_uuid, e, now))
                .collect();
            let already_imported = entries.len() - to_create.len();
            if to_create.is_empty() {
                return Ok(LegacyImport {
                    created: Vec::new(),
                    already_imported,
                    generation: self.generation_of(host_uuid).await?,
                });
            }
            let mut stmts: Vec<(&'static str, Vec<Param>)> =
                Vec::with_capacity(to_create.len() * 3 + 1);
            for a in &to_create {
                stmts.push((
                    "INSERT INTO app_txn_guard (code) SELECT 'stale' \
                     WHERE EXISTS (SELECT 1 FROM app_approvals WHERE approval_id = ?1)",
                    vec![text(&a.approval_id)],
                ));
                stmts.push(insert_approval_stmt(a));
                stmts.push(insert_revision_stmt(
                    &a.approval_id,
                    1,
                    now,
                    Some(admin_id),
                    RevisionChange::Created,
                    None,
                    ApprovalSnapshot::of(a).to_cbor()?,
                ));
            }
            stmts.push(bump_generation_stmt(host_uuid, generation_millis, now));
            match self.ledger_txn(stmts).await? {
                TxnOutcome::Committed => {
                    return Ok(LegacyImport {
                        created: to_create,
                        already_imported,
                        generation: self.generation_of(host_uuid).await?,
                    });
                }
                TxnOutcome::Refused(code) if code == "stale" => {}
                TxnOutcome::Refused(code) => return Err(generic_refusal(&code)),
            }
        }
        Err(LedgerError::Raced)
    }

    async fn generation_of(&self, host_uuid: &str) -> Result<u64, LedgerError> {
        Ok(self
            .app_allowlist_state(host_uuid)
            .await?
            .map_or(0, |s| s.generation))
    }

    /// What a switch back to `legacy` mode would change at `now`
    /// ([`ModeRollbackCounts`]). Read-only.
    pub async fn app_mode_rollback_counts(
        &self,
        now: i64,
    ) -> Result<ModeRollbackCounts, LedgerError> {
        let rows: Vec<CountsRow> = self
            .client()
            .query_consistent_map(
                "SELECT \
                    COALESCE(SUM(CASE WHEN origin <> 4 AND state = 1 \
                        AND (expires_at IS NULL OR expires_at > ?1) THEN 1 ELSE 0 END), 0) AS x, \
                    COALESCE(SUM(CASE WHEN origin = 4 AND NOT (state = 1 \
                        AND (expires_at IS NULL OR expires_at > ?1)) THEN 1 ELSE 0 END), 0) AS y \
                 FROM app_approvals",
                vec![Param::from(now)],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows
            .first()
            .map_or_else(ModeRollbackCounts::default, |r| ModeRollbackCounts {
                approvals_not_reflected: u64::try_from(r.0).unwrap_or(0),
                imports_readmitted: u64::try_from(r.1).unwrap_or(0),
            }))
    }

    /// Whether `host_uuid` has any approval, in any state (a host the ledger
    /// knows, F19 §6.4).
    pub async fn app_host_has_approvals(&self, host_uuid: &str) -> Result<bool, LedgerError> {
        let rows: Vec<FlagRow> = self
            .client()
            .query_consistent_map(
                "SELECT EXISTS (SELECT 1 FROM app_approvals WHERE host_uuid = ?1) AS n",
                vec![text(host_uuid)],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows.first().is_some_and(|r| r.0 != 0))
    }

    /// Whether a live approval of `host_uuid` admits `bin_sha` run by `uid`
    /// on **some** path: the same or the wildcard hash, and an any-user
    /// scope or the same uid without a SID. Used for the entries of a
    /// pre-F19 agent's `ProposeAllowlist`, which carry no path.
    pub async fn app_admits_on_some_path(
        &self,
        host_uuid: &str,
        bin_sha: &str,
        uid: i64,
        now: i64,
    ) -> Result<bool, LedgerError> {
        let rows: Vec<FlagRow> = self
            .client()
            .query_consistent_map(
                "SELECT EXISTS (SELECT 1 FROM app_approvals a \
                    WHERE a.host_uuid = ?1 AND a.state = 1 \
                    AND (a.expires_at IS NULL OR a.expires_at > ?4) \
                    AND (a.bin_sha = ?2 OR a.bin_sha = '*') \
                    AND (a.user_scope = 2 \
                        OR (a.sid IS NULL AND a.uid IS NOT NULL AND a.uid = ?3))) AS n",
                vec![
                    text(host_uuid),
                    text(bin_sha),
                    Param::from(uid),
                    Param::from(now),
                ],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows.first().is_some_and(|r| r.0 != 0))
    }
}

/// The guard of a legacy write: abort (`invalid_state`) while the setting
/// `key` holds `refused_value`.
fn setting_guard_stmt(key: &str, refused_value: &str) -> (&'static str, Vec<Param>) {
    (
        "INSERT INTO app_txn_guard (code) SELECT 'invalid_state' \
         WHERE EXISTS (SELECT 1 FROM cmis_settings WHERE key = ?1 AND value = ?2)",
        vec![text(key), text(refused_value)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_ids_are_stable_v8_uuids_and_separate_entries() {
        let host = "8d5e0000-0000-4000-8000-000000000001";
        let a = LegacyEntry::new(Some(1000), &"ab".repeat(48)).unwrap();
        let b = LegacyEntry::new(None, &"ab".repeat(48)).unwrap();
        let w = LegacyEntry::new(Some(1000), LEGACY_BIN_WILDCARD).unwrap();
        let id = legacy_approval_id(host, &a);
        assert_eq!(id, legacy_approval_id(host, &a));
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "8", "version 8: {id}");
        assert!(
            matches!(&id[19..20], "8" | "9" | "a" | "b"),
            "variant: {id}"
        );
        assert_ne!(id, legacy_approval_id(host, &b));
        assert_ne!(id, legacy_approval_id(host, &w));
        assert_ne!(
            id,
            legacy_approval_id("8d5e0000-0000-4000-8000-000000000002", &a)
        );
        assert_ne!(legacy_lineage_id(host), id);
        assert_eq!(legacy_lineage_id(host), legacy_lineage_id(host));
    }

    #[test]
    fn entries_are_validated_like_the_v1_body() {
        assert!(LegacyEntry::new(None, "*").is_ok());
        assert!(LegacyEntry::new(Some(0), &"0f".repeat(48)).is_ok());
        assert!(LegacyEntry::new(None, &"0F".repeat(48)).is_err());
        assert!(LegacyEntry::new(None, "abc").is_err());
        assert!(LegacyEntry::new(None, "").is_err());
    }

    #[test]
    fn a_legacy_import_has_the_f19_terms() {
        let e = LegacyEntry::new(Some(7), "*").unwrap();
        let a = legacy_approval("h", &e, 5);
        assert_eq!(a.origin, ApprovalOrigin::LegacyImport);
        assert_eq!(a.path_match, PathMatch::Any);
        assert_eq!(a.update_policy, UpdatePolicy::ManualEachTime);
        assert_eq!((a.expires_at, a.revision), (None, None));
        assert_eq!((a.user_scope, a.uid), (UserScope::ExactUser, Some(7)));
        assert_eq!(a.approved_by_admin_id, None);
        let any = legacy_approval("h", &LegacyEntry::new(None, "*").unwrap(), 5);
        assert_eq!((any.user_scope, any.uid), (UserScope::AnyUser, None));
    }
}
