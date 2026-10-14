//! Point reads of the ledger: single records, lineage history, the inputs
//! CMIS needs for policy and rate limits, the host-scoped status lookup, the
//! compile input, and the sweeper queues. All strongly consistent.

use hiqlite::Param;

use super::model::{
    ApprovalRevisionRow, ApprovalRow, BinaryRow, LineageRow, RequestRow, UserIdentity,
};
use super::{
    collect, opt_text, parse_approval, text, LedgerError, Parsed, APPROVAL_COLUMNS, BINARY_COLUMNS,
    LINEAGE_COLUMNS, REQUEST_COLUMNS,
};
use crate::cluster::{Cluster, ClusterError};

/// Most request ids one host status lookup may name (F19 §7.1).
pub const MAX_STATUS_IDS: usize = 100;

/// Whether a hash was ever revoked or denied in a lineage (F19 §4.5 bits 10
/// and 11, §5.3 #6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HashHistory {
    /// An approval of the hash in the lineage is `REVOKED`.
    pub revoked: bool,
    /// A request for the hash in the lineage is `DENIED`.
    pub denied: bool,
}

/// Open `PENDING` requests of a host, for the F19 §7.4 caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingCounts {
    /// All open requests of the host.
    pub host: u64,
    /// Open requests of the host for one target user.
    pub user: u64,
}

/// A live approval with the lineage data its v2 entry needs (F19 §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveApproval {
    /// The approval.
    pub approval: ApprovalRow,
    /// Platform of the lineage (1 linux, 2 macos, 3 windows), if it has one.
    pub platform: Option<i64>,
    /// `path_key` of the lineage, for `path_hash`, if it has one.
    pub path_key: Option<Vec<u8>>,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<LiveApproval> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        let mut parse = || -> Result<LiveApproval, LedgerError> {
            let approval = parse_approval(row)?;
            Ok(LiveApproval {
                approval,
                platform: row.get("l_platform"),
                path_key: row.get("l_path_key"),
            })
        };
        Self(parse())
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
struct PairRow(i64, i64);
impl<'r> From<&'r mut hiqlite::Row<'_>> for PairRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("x"), row.get("y"))
    }
}

fn count(rows: &[CountRow]) -> u64 {
    rows.first().map_or(0, |r| u64::try_from(r.0).unwrap_or(0))
}

impl Cluster {
    async fn one<T>(&self, sql: String, params: Vec<Param>) -> Result<Option<T>, LedgerError>
    where
        T: Send + 'static,
        Parsed<T>: for<'a, 'r> From<&'a mut hiqlite::Row<'r>> + Send + 'static,
    {
        let rows: Vec<Parsed<T>> = self
            .client()
            .query_consistent_map(sql, params)
            .await
            .map_err(ClusterError::from)?;
        Ok(collect(rows)?.into_iter().next())
    }

    async fn many<T>(&self, sql: String, params: Vec<Param>) -> Result<Vec<T>, LedgerError>
    where
        T: Send + 'static,
        Parsed<T>: for<'a, 'r> From<&'a mut hiqlite::Row<'r>> + Send + 'static,
    {
        let rows: Vec<Parsed<T>> = self
            .client()
            .query_consistent_map(sql, params)
            .await
            .map_err(ClusterError::from)?;
        collect(rows)
    }

    async fn count(&self, sql: &'static str, params: Vec<Param>) -> Result<u64, LedgerError> {
        let rows: Vec<CountRow> = self
            .client()
            .query_consistent_map(sql, params)
            .await
            .map_err(ClusterError::from)?;
        Ok(count(&rows))
    }

    // ---- lineages and binaries ------------------------------------------------

    /// One lineage by id.
    pub async fn app_lineage(&self, lineage_id: &str) -> Result<Option<LineageRow>, LedgerError> {
        self.one(
            format!("SELECT {LINEAGE_COLUMNS} FROM app_lineages WHERE lineage_id = ?1"),
            vec![text(lineage_id)],
        )
        .await
    }

    /// The lineage of `(host, path_key)`.
    pub async fn app_lineage_by_path(
        &self,
        host_uuid: &str,
        path_key: &[u8],
    ) -> Result<Option<LineageRow>, LedgerError> {
        self.one(
            format!(
                "SELECT {LINEAGE_COLUMNS} FROM app_lineages WHERE host_uuid = ?1 AND path_key = ?2"
            ),
            vec![text(host_uuid), Param::from(path_key.to_vec())],
        )
        .await
    }

    /// One binary of a lineage.
    pub async fn app_binary(
        &self,
        lineage_id: &str,
        bin_sha: &str,
    ) -> Result<Option<BinaryRow>, LedgerError> {
        self.one(
            format!(
                "SELECT {BINARY_COLUMNS} FROM app_binaries WHERE lineage_id = ?1 AND bin_sha = ?2"
            ),
            vec![text(lineage_id), text(bin_sha)],
        )
        .await
    }

    /// Every binary of a lineage, by revision.
    pub async fn app_binaries_of(&self, lineage_id: &str) -> Result<Vec<BinaryRow>, LedgerError> {
        self.many(
            format!(
                "SELECT {BINARY_COLUMNS} FROM app_binaries WHERE lineage_id = ?1 ORDER BY revision"
            ),
            vec![text(lineage_id)],
        )
        .await
    }

    // ---- requests ---------------------------------------------------------------

    /// One request by id.
    pub async fn app_request(&self, request_id: &str) -> Result<Option<RequestRow>, LedgerError> {
        self.one(
            format!("SELECT {REQUEST_COLUMNS} FROM app_requests r WHERE r.request_id = ?1"),
            vec![text(request_id)],
        )
        .await
    }

    /// The request a host sent with `client_request_id` (idempotency).
    pub async fn app_request_by_client_id(
        &self,
        host_uuid: &str,
        client_request_id: &str,
    ) -> Result<Option<RequestRow>, LedgerError> {
        self.one(
            format!(
                "SELECT {REQUEST_COLUMNS} FROM app_requests r \
                 WHERE r.host_uuid = ?1 AND r.client_request_id = ?2"
            ),
            vec![text(host_uuid), text(client_request_id)],
        )
        .await
    }

    /// The requests among `request_ids` that belong to `host_uuid`
    /// (`GetAppRequestStatus`): ids of other hosts are silently omitted, so
    /// the lookup is no cross-host oracle. At most [`MAX_STATUS_IDS`] ids.
    pub async fn app_requests_of_host(
        &self,
        host_uuid: &str,
        request_ids: &[String],
    ) -> Result<Vec<RequestRow>, LedgerError> {
        if request_ids.len() > MAX_STATUS_IDS {
            return Err(LedgerError::Invalid("request_ids"));
        }
        if request_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut params = vec![text(host_uuid)];
        let mut marks = Vec::with_capacity(request_ids.len());
        for id in request_ids {
            params.push(text(id));
            marks.push(format!("?{}", params.len()));
        }
        self.many(
            format!(
                "SELECT {REQUEST_COLUMNS} FROM app_requests r \
                 WHERE r.host_uuid = ?1 AND r.request_id IN ({}) ORDER BY r.submitted_at",
                marks.join(", ")
            ),
            params,
        )
        .await
    }

    /// Every request of a lineage, oldest first (lineage history).
    pub async fn app_requests_of_lineage(
        &self,
        lineage_id: &str,
    ) -> Result<Vec<RequestRow>, LedgerError> {
        self.many(
            format!(
                "SELECT {REQUEST_COLUMNS} FROM app_requests r WHERE r.lineage_id = ?1 \
                 ORDER BY r.submitted_at, r.request_id"
            ),
            vec![text(lineage_id)],
        )
        .await
    }

    /// The open request with `dedup_key`, if any (at most one exists).
    pub async fn app_pending_by_dedup(
        &self,
        dedup_key: &[u8],
    ) -> Result<Option<RequestRow>, LedgerError> {
        self.one(
            format!(
                "SELECT {REQUEST_COLUMNS} FROM app_requests r \
                 WHERE r.dedup_key = ?1 AND r.state = 1"
            ),
            vec![Param::from(dedup_key.to_vec())],
        )
        .await
    }

    /// The newest request with `dedup_key` denied at or after `since`.
    pub async fn app_recent_denial(
        &self,
        dedup_key: &[u8],
        since: i64,
    ) -> Result<Option<RequestRow>, LedgerError> {
        self.one(
            format!(
                "SELECT {REQUEST_COLUMNS} FROM app_requests r \
                 WHERE r.dedup_key = ?1 AND r.state = 4 AND r.decided_at >= ?2 \
                 ORDER BY r.decided_at DESC LIMIT 1"
            ),
            vec![Param::from(dedup_key.to_vec()), Param::from(since)],
        )
        .await
    }

    /// Open requests of a host, in total and for one target user.
    pub async fn app_pending_counts(
        &self,
        host_uuid: &str,
        target: &UserIdentity,
    ) -> Result<PendingCounts, LedgerError> {
        let rows: Vec<PairRow> = self
            .client()
            .query_consistent_map(
                "SELECT COUNT(*) AS x, \
                    COALESCE(SUM(CASE WHEN target_user_kind = ?2 AND target_uid IS ?3 \
                        AND upper(target_sid) IS upper(?4) THEN 1 ELSE 0 END), 0) AS y \
                 FROM app_requests WHERE host_uuid = ?1 AND state = 1",
                vec![
                    text(host_uuid),
                    Param::from(target.kind.code()),
                    Param::from(target.uid),
                    opt_text(target.sid.as_deref()),
                ],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows
            .first()
            .map_or_else(PendingCounts::default, |r| PendingCounts {
                host: u64::try_from(r.0).unwrap_or(0),
                user: u64::try_from(r.1).unwrap_or(0),
            }))
    }

    /// Requests a host submitted at or after `since` (per-host hourly cap).
    pub async fn app_submissions_since(
        &self,
        host_uuid: &str,
        since: i64,
    ) -> Result<u64, LedgerError> {
        self.count(
            "SELECT COUNT(*) AS n FROM app_requests WHERE host_uuid = ?1 AND submitted_at >= ?2",
            vec![text(host_uuid), Param::from(since)],
        )
        .await
    }

    /// Pending requests past `pending_expires_at` (sweeper queue), oldest
    /// first.
    pub async fn app_pending_past_expiry(
        &self,
        now: i64,
        limit: u32,
    ) -> Result<Vec<RequestRow>, LedgerError> {
        self.many(
            format!(
                "SELECT {REQUEST_COLUMNS} FROM app_requests r \
                 WHERE r.state = 1 AND r.pending_expires_at <= ?1 \
                 ORDER BY r.pending_expires_at, r.request_id LIMIT ?2"
            ),
            vec![Param::from(now), Param::from(i64::from(limit))],
        )
        .await
    }

    // ---- approvals --------------------------------------------------------------

    /// One approval by id.
    pub async fn app_approval(
        &self,
        approval_id: &str,
    ) -> Result<Option<ApprovalRow>, LedgerError> {
        self.one(
            format!("SELECT {APPROVAL_COLUMNS} FROM app_approvals a WHERE a.approval_id = ?1"),
            vec![text(approval_id)],
        )
        .await
    }

    /// The revision history of an approval, oldest first.
    pub async fn app_approval_revisions(
        &self,
        approval_id: &str,
    ) -> Result<Vec<ApprovalRevisionRow>, LedgerError> {
        self.many(
            "SELECT approval_id, row_version, changed_at, changed_by_admin_id, change_kind, \
             before_cbor, after_cbor FROM app_approval_revisions WHERE approval_id = ?1 \
             ORDER BY row_version"
                .to_string(),
            vec![text(approval_id)],
        )
        .await
    }

    /// Every approval of a lineage, by creation (lineage tree).
    pub async fn app_approvals_of_lineage(
        &self,
        lineage_id: &str,
    ) -> Result<Vec<ApprovalRow>, LedgerError> {
        self.many(
            format!(
                "SELECT {APPROVAL_COLUMNS} FROM app_approvals a WHERE a.lineage_id = ?1 \
                 ORDER BY a.created_at, a.approval_id"
            ),
            vec![text(lineage_id)],
        )
        .await
    }

    /// The active, unexpired approval that already admits `(bin_sha, user)`
    /// on the host, in this lineage or with an any-path scope (F19 §5.1 step
    /// 5.3). Matching follows the compiled allowlist: an any-user scope, the
    /// same SID, or (without a SID) the same uid. Same-lineage approvals are
    /// preferred, then the newest.
    pub async fn app_covering_approval(
        &self,
        host_uuid: &str,
        lineage_id: &str,
        bin_sha: &str,
        user: &UserIdentity,
        now: i64,
    ) -> Result<Option<ApprovalRow>, LedgerError> {
        self.one(
            format!(
                "SELECT {APPROVAL_COLUMNS} FROM app_approvals a \
                 WHERE a.host_uuid = ?1 AND a.state = 1 \
                 AND (a.expires_at IS NULL OR a.expires_at > ?4) \
                 AND (a.bin_sha = ?3 OR a.bin_sha = '*') \
                 AND (a.lineage_id = ?2 OR a.path_match = 2) \
                 AND (a.user_scope = 2 \
                    OR (a.sid IS NOT NULL AND upper(a.sid) = upper(?5)) \
                    OR (a.sid IS NULL AND a.uid IS NOT NULL AND a.uid = ?6)) \
                 ORDER BY (a.lineage_id = ?2) DESC, a.created_at DESC, a.approval_id DESC \
                 LIMIT 1"
            ),
            vec![
                text(host_uuid),
                text(lineage_id),
                text(bin_sha),
                Param::from(now),
                opt_text(user.sid.as_deref()),
                Param::from(user.uid),
            ],
        )
        .await
    }

    /// The auto-update parent candidate of a lineage at `now` (F19 §5.3 #2):
    /// the active, unexpired `AutoSamePathUser` approval with the highest
    /// revision.
    pub async fn app_auto_parent(
        &self,
        host_uuid: &str,
        lineage_id: &str,
        now: i64,
    ) -> Result<Option<ApprovalRow>, LedgerError> {
        self.one(
            format!(
                "SELECT {APPROVAL_COLUMNS} FROM app_approvals a \
                 WHERE a.lineage_id = ?1 AND a.host_uuid = ?2 AND a.state = 1 \
                 AND a.update_policy = 2 AND (a.expires_at IS NULL OR a.expires_at > ?3) \
                 ORDER BY a.revision DESC, a.created_at DESC, a.approval_id DESC LIMIT 1"
            ),
            vec![text(lineage_id), text(host_uuid), Param::from(now)],
        )
        .await
    }

    /// Whether `bin_sha` was ever revoked or denied in a lineage.
    pub async fn app_hash_history(
        &self,
        lineage_id: &str,
        bin_sha: &str,
    ) -> Result<HashHistory, LedgerError> {
        let rows: Vec<PairRow> = self
            .client()
            .query_consistent_map(
                "SELECT \
                    EXISTS (SELECT 1 FROM app_approvals \
                        WHERE lineage_id = ?1 AND bin_sha = ?2 AND state = 3) AS x, \
                    EXISTS (SELECT 1 FROM app_requests \
                        WHERE lineage_id = ?1 AND bin_sha = ?2 AND state = 4) AS y",
                vec![text(lineage_id), text(bin_sha)],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(rows
            .first()
            .map_or_else(HashHistory::default, |r| HashHistory {
                revoked: r.0 != 0,
                denied: r.1 != 0,
            }))
    }

    /// Auto-update approvals created in a lineage after `since`.
    pub async fn app_auto_approvals_since(
        &self,
        lineage_id: &str,
        since: i64,
    ) -> Result<u64, LedgerError> {
        self.count(
            "SELECT COUNT(*) AS n FROM app_approvals \
             WHERE lineage_id = ?1 AND origin = 2 AND created_at > ?2",
            vec![text(lineage_id), Param::from(since)],
        )
        .await
    }

    /// Every approval of a host that admits callers at `now` — the input of
    /// the v2 compile (F19 §6.1) — with its lineage platform and `path_key`.
    pub async fn app_live_approvals(
        &self,
        host_uuid: &str,
        now: i64,
    ) -> Result<Vec<LiveApproval>, LedgerError> {
        self.many(
            format!(
                "SELECT {APPROVAL_COLUMNS}, l.platform AS l_platform, l.path_key AS l_path_key \
                 FROM app_approvals a LEFT JOIN app_lineages l ON l.lineage_id = a.lineage_id \
                 WHERE a.host_uuid = ?1 AND a.state = 1 \
                 AND (a.expires_at IS NULL OR a.expires_at > ?2) \
                 ORDER BY a.bin_sha, a.approval_id"
            ),
            vec![text(host_uuid), Param::from(now)],
        )
        .await
    }

    /// Active approvals past `expires_at` (sweeper queue), oldest first.
    pub async fn app_approvals_past_expiry(
        &self,
        now: i64,
        limit: u32,
    ) -> Result<Vec<ApprovalRow>, LedgerError> {
        self.many(
            format!(
                "SELECT {APPROVAL_COLUMNS} FROM app_approvals a \
                 WHERE a.state = 1 AND a.expires_at IS NOT NULL AND a.expires_at <= ?1 \
                 ORDER BY a.expires_at, a.approval_id LIMIT ?2"
            ),
            vec![Param::from(now), Param::from(i64::from(limit))],
        )
        .await
    }
}
