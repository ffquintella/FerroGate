//! Per-host allowlist generation and compile cache (F19 §6.2).
//!
//! Every transaction that changes a host's compiled entry set bumps the
//! host's generation to `max(generation + 1, unix_millis_now)` and clears the
//! cached signed body. The hybrid-logical value keeps increasing across a
//! restore from backup as long as clocks are sane; a trigger refuses any
//! decrease.

use hiqlite::Param;

use super::{text, LedgerError, TxnOutcome};
use crate::cluster::{Cluster, ClusterError};

/// `entries_digest` of a host whose entry set has not been compiled since
/// the last change.
pub const GENERATION_UNCOMPILED_DIGEST: &[u8] = &[];

/// The generation bump, for use inside a ledger transaction.
pub(crate) fn bump_generation_stmt(
    host_uuid: &str,
    now_millis: i64,
    now: i64,
) -> (&'static str, Vec<Param>) {
    (
        "INSERT INTO host_allowlist_state (host_uuid, generation, entries_digest, changed_at, \
         cached_v2, cached_not_after) VALUES (?1, MAX(?2, 1), ?3, ?4, NULL, NULL) \
         ON CONFLICT (host_uuid) DO UPDATE SET \
            generation = MAX(host_allowlist_state.generation + 1, excluded.generation), \
            entries_digest = excluded.entries_digest, changed_at = excluded.changed_at, \
            cached_v2 = NULL, cached_not_after = NULL",
        vec![
            text(host_uuid),
            Param::from(now_millis),
            Param::from(GENERATION_UNCOMPILED_DIGEST.to_vec()),
            Param::from(now),
        ],
    )
}

#[derive(Debug)]
struct GenerationRow(i64);
impl<'r> From<&'r mut hiqlite::Row<'_>> for GenerationRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("generation"))
    }
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for super::HostAllowlistStateRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            host_uuid: row.get("host_uuid"),
            generation: u64::try_from(row.get::<i64>("generation")).unwrap_or(0),
            entries_digest: row.get("entries_digest"),
            changed_at: row.get("changed_at"),
            cached_v2: row.get("cached_v2"),
            cached_not_after: row.get("cached_not_after"),
        }
    }
}

impl Cluster {
    /// The allowlist state of `host_uuid`, if its entry set ever changed.
    pub async fn app_allowlist_state(
        &self,
        host_uuid: &str,
    ) -> Result<Option<super::HostAllowlistStateRow>, LedgerError> {
        let rows: Vec<super::HostAllowlistStateRow> = self
            .client()
            .query_consistent_map(
                "SELECT host_uuid, generation, entries_digest, changed_at, cached_v2, \
                 cached_not_after FROM host_allowlist_state WHERE host_uuid = ?1",
                vec![text(host_uuid)],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows.into_iter().next())
    }

    /// Bump the generation of `host_uuid` on its own (for changes made
    /// outside the ledger, such as legacy `SetAllowlist` in `legacy` mode,
    /// F19 §11 step 2). Returns the new generation.
    pub async fn app_bump_generation(
        &self,
        host_uuid: &str,
        now_millis: i64,
        now: i64,
    ) -> Result<u64, LedgerError> {
        super::check_id(host_uuid, "host_uuid")?;
        match self
            .ledger_txn(vec![bump_generation_stmt(host_uuid, now_millis, now)])
            .await?
        {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(super::generic_refusal(&code)),
        }
        Ok(self
            .app_allowlist_state(host_uuid)
            .await?
            .map_or(0, |s| s.generation))
    }

    /// Record the digest of the entry set compiled at `expected_generation`.
    ///
    /// The first compile after a change stores its digest under the current
    /// generation. A later compile of the same generation that yields a
    /// **different** digest (for example because an entry expired by time in
    /// between) bumps the generation, so MIA never sees two bodies with one
    /// generation and different entries (`generation_conflict`, F19 §6.2).
    /// Returns the generation the digest now belongs to, or `None` when the
    /// generation moved on concurrently (recompile).
    pub async fn app_record_compiled_digest(
        &self,
        host_uuid: &str,
        expected_generation: u64,
        entries_digest: &[u8],
        now_millis: i64,
        now: i64,
    ) -> Result<Option<u64>, LedgerError> {
        if entries_digest.is_empty() {
            return Err(LedgerError::Invalid("entries_digest"));
        }
        let expected =
            i64::try_from(expected_generation).map_err(|_| LedgerError::Invalid("generation"))?;
        let rows: Vec<Result<GenerationRow, hiqlite::Error>> = self
            .client()
            .execute_returning_map(
                "UPDATE host_allowlist_state SET \
                    generation = CASE WHEN length(entries_digest) = 0 OR entries_digest = ?3 \
                        THEN generation ELSE MAX(generation + 1, ?4) END, \
                    changed_at = CASE WHEN length(entries_digest) = 0 OR entries_digest = ?3 \
                        THEN changed_at ELSE ?5 END, \
                    cached_v2 = CASE WHEN entries_digest = ?3 THEN cached_v2 ELSE NULL END, \
                    cached_not_after = CASE WHEN entries_digest = ?3 \
                        THEN cached_not_after ELSE NULL END, \
                    entries_digest = ?3 \
                 WHERE host_uuid = ?1 AND generation = ?2 \
                 RETURNING generation",
                vec![
                    text(host_uuid),
                    Param::from(expected),
                    Param::from(entries_digest.to_vec()),
                    Param::from(now_millis),
                    Param::from(now),
                ],
            )
            .await
            .map_err(ClusterError::from)?;
        match rows.into_iter().next() {
            Some(row) => {
                let generation = row.map_err(ClusterError::from)?.0;
                Ok(Some(u64::try_from(generation).unwrap_or(0)))
            }
            None => Ok(None),
        }
    }

    /// Cache the signed v2 body of `generation`. Returns `false` (nothing
    /// cached) when the generation moved on concurrently.
    pub async fn app_cache_signed_allowlist(
        &self,
        host_uuid: &str,
        generation: u64,
        signed_body: &[u8],
        not_after: i64,
    ) -> Result<bool, LedgerError> {
        let generation =
            i64::try_from(generation).map_err(|_| LedgerError::Invalid("generation"))?;
        let n = self
            .client()
            .execute(
                "UPDATE host_allowlist_state SET cached_v2 = ?3, cached_not_after = ?4 \
                 WHERE host_uuid = ?1 AND generation = ?2 AND length(entries_digest) > 0",
                vec![
                    text(host_uuid),
                    Param::from(generation),
                    Param::from(signed_body.to_vec()),
                    Param::from(not_after),
                ],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(n > 0)
    }
}
