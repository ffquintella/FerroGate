//! Paged listing and search for the admin `ListAppRequests` and
//! `ListApprovals` RPCs (F19 §7.5).
//!
//! Queries are assembled from fixed SQL fragments; every value is bound as a
//! parameter (NRM §5.3.5), and `LIKE` needles escape `%`, `_` and `\` under
//! `ESCAPE '\'`. Paging is keyset-based on `(time, id)`; CMIS wraps the
//! [`Cursor`] in its HMAC-protected page token. Host *names* are not stored
//! in the ledger: CMIS resolves `hostname_contains` to host UUIDs and passes
//! them in `host_uuids`.

use hiqlite::Param;

use super::model::{
    is_bin_sha, ApprovalOrigin, ApprovalRow, ApprovalState, RequestKind, RequestOrigin, RequestRow,
    RequestState, UpdatePolicy,
};
use super::{
    collect, parse_approval, parse_request, LedgerError, Parsed, APPROVAL_COLUMNS, REQUEST_COLUMNS,
};
use crate::cluster::{Cluster, ClusterError};

/// Largest page a listing returns.
pub const MAX_PAGE_SIZE: u32 = 200;
/// Page size when the caller asks for 0.
const DEFAULT_PAGE_SIZE: u32 = 50;
/// Longest free-text query (F19 §7.5 `text`).
const MAX_TEXT_CHARS: usize = 128;
/// Longest value of the other text filters.
const MAX_FILTER_CHARS: usize = 256;
/// Most host UUIDs one filter may name.
const MAX_HOSTS: usize = 100;

/// Keyset position: the sort time and id of the last row of the previous page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// `submitted_at` (requests) or `created_at` (approvals) of the last row.
    pub at: i64,
    /// `request_id` or `approval_id` of the last row.
    pub id: String,
}

/// `ListAppRequests` filters. Empty lists and `None` do not filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestFilter {
    /// Request states.
    pub states: Vec<RequestState>,
    /// Hosts (CMIS maps `hostname_contains` here).
    pub host_uuids: Vec<String>,
    /// Substring of the canonical path.
    pub path_contains: Option<String>,
    /// Substring of the product name.
    pub product_contains: Option<String>,
    /// Exact target user name.
    pub user_name: Option<String>,
    /// Exact declared version.
    pub declared_version: Option<String>,
    /// Prefix of the hash (8 to 96 hex characters).
    pub bin_sha_prefix: Option<String>,
    /// Request origins.
    pub origins: Vec<RequestOrigin>,
    /// Request kinds.
    pub kinds: Vec<RequestKind>,
    /// Requests with any of these risk flags (0: no filter).
    pub flags_any: u32,
    /// Submitted at or after (Unix seconds).
    pub submitted_after: Option<i64>,
    /// Submitted before (Unix seconds).
    pub submitted_before: Option<i64>,
    /// Free text matched against path, product, user, host and version.
    pub text: Option<String>,
    /// Oldest first instead of newest first.
    pub ascending: bool,
    /// Rows per page (0: default 50; at most [`MAX_PAGE_SIZE`]).
    pub page_size: u32,
    /// Continue after this row.
    pub after: Option<Cursor>,
}

/// `ListApprovals` filters. Empty lists and `None` do not filter.
// The flags mirror the RPC's boolean filter fields one to one (F19 §7.5).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalFilter {
    /// Approval states.
    pub states: Vec<ApprovalState>,
    /// Hosts.
    pub host_uuids: Vec<String>,
    /// One lineage.
    pub lineage_id: Option<String>,
    /// Substring of the canonical path.
    pub path_contains: Option<String>,
    /// Substring of the product name.
    pub product_contains: Option<String>,
    /// Exact user name.
    pub user_name: Option<String>,
    /// Exact declared version.
    pub declared_version: Option<String>,
    /// Prefix of the hash (8 to 96 hex characters).
    pub bin_sha_prefix: Option<String>,
    /// Update policies.
    pub policies: Vec<UpdatePolicy>,
    /// Approval origins.
    pub approval_origins: Vec<ApprovalOrigin>,
    /// Expiring before (Unix seconds).
    pub expires_before: Option<i64>,
    /// Expiring at or after (Unix seconds).
    pub expires_after: Option<i64>,
    /// Created at or after (Unix seconds).
    pub created_after: Option<i64>,
    /// Created before (Unix seconds).
    pub created_before: Option<i64>,
    /// Include approvals marked superseded (hidden by default).
    pub include_superseded: bool,
    /// Only legacy imports.
    pub legacy_only: bool,
    /// Only approvals without an expiry.
    pub no_expiry_only: bool,
    /// Free text matched against path, product, user, host and version.
    pub text: Option<String>,
    /// Oldest first instead of newest first.
    pub ascending: bool,
    /// Rows per page (0: default 50; at most [`MAX_PAGE_SIZE`]).
    pub page_size: u32,
    /// Continue after this row.
    pub after: Option<Cursor>,
}

/// A request with the display data of its lineage and binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestListItem {
    /// The request.
    pub request: RequestRow,
    /// Canonical path of the lineage.
    pub canonical_path: String,
    /// Declared version of the binary.
    pub declared_version: Option<String>,
    /// Product name of the binary.
    pub product_name: Option<String>,
}

/// An approval with the display data of its lineage and binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalListItem {
    /// The approval.
    pub approval: ApprovalRow,
    /// Canonical path of the lineage (absent for some legacy imports).
    pub canonical_path: Option<String>,
    /// Declared version of the binary.
    pub declared_version: Option<String>,
    /// Product name of the binary.
    pub product_name: Option<String>,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<RequestListItem> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        let mut parse = || -> Result<RequestListItem, LedgerError> {
            Ok(RequestListItem {
                request: parse_request(row)?,
                canonical_path: row.get("l_canonical_path"),
                declared_version: row.get("b_declared_version"),
                product_name: row.get("b_product_name"),
            })
        };
        Self(parse())
    }
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<ApprovalListItem> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        let mut parse = || -> Result<ApprovalListItem, LedgerError> {
            Ok(ApprovalListItem {
                approval: parse_approval(row)?,
                canonical_path: row.get("l_canonical_path"),
                declared_version: row.get("b_declared_version"),
                product_name: row.get("b_product_name"),
            })
        };
        Self(parse())
    }
}

/// Escape `LIKE` wildcards and wrap the needle for a substring match.
pub(crate) fn like_needle(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('%');
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// WHERE clauses and their bound parameters. Column names come only from
/// this module; values only ever become parameters.
#[derive(Default)]
struct Where {
    clauses: Vec<String>,
    params: Vec<Param>,
}

impl Where {
    fn bind(&mut self, p: Param) -> String {
        self.params.push(p);
        format!("?{}", self.params.len())
    }

    fn clause(&mut self, c: String) {
        self.clauses.push(c);
    }

    fn any_of(&mut self, column: &str, codes: impl IntoIterator<Item = i64>) {
        let marks: Vec<String> = codes
            .into_iter()
            .map(|c| self.bind(Param::from(c)))
            .collect();
        if !marks.is_empty() {
            self.clause(format!("{column} IN ({})", marks.join(", ")));
        }
    }

    fn hosts(&mut self, column: &str, hosts: &[String]) -> Result<(), LedgerError> {
        if hosts.len() > MAX_HOSTS {
            return Err(LedgerError::Invalid("host_uuids"));
        }
        let marks: Vec<String> = hosts
            .iter()
            .map(|h| self.bind(Param::from(h.clone())))
            .collect();
        if !marks.is_empty() {
            self.clause(format!("{column} IN ({})", marks.join(", ")));
        }
        Ok(())
    }

    fn contains(
        &mut self,
        columns: &[&str],
        needle: Option<&str>,
        max: usize,
        field: &'static str,
    ) -> Result<(), LedgerError> {
        let Some(needle) = needle else { return Ok(()) };
        if needle.is_empty() || needle.chars().count() > max {
            return Err(LedgerError::Invalid(field));
        }
        let mark = self.bind(Param::from(like_needle(needle)));
        let ors: Vec<String> = columns
            .iter()
            .map(|c| format!("{c} LIKE {mark} ESCAPE '\\'"))
            .collect();
        self.clause(format!("({})", ors.join(" OR ")));
        Ok(())
    }

    fn equals(
        &mut self,
        column: &str,
        value: Option<&str>,
        field: &'static str,
    ) -> Result<(), LedgerError> {
        let Some(value) = value else { return Ok(()) };
        if value.chars().count() > MAX_FILTER_CHARS {
            return Err(LedgerError::Invalid(field));
        }
        let mark = self.bind(Param::from(value.to_string()));
        self.clause(format!("{column} = {mark}"));
        Ok(())
    }

    fn sha_prefix(&mut self, column: &str, prefix: Option<&str>) -> Result<(), LedgerError> {
        let Some(prefix) = prefix else { return Ok(()) };
        let prefix = prefix.to_ascii_lowercase();
        // Pad to a full hash only to reuse the hex check.
        let padded = format!("{prefix:0<96}");
        if prefix.len() < 8 || prefix.len() > 96 || !is_bin_sha(&padded) {
            return Err(LedgerError::Invalid("bin_sha_prefix"));
        }
        let len = self.bind(Param::from(i64::try_from(prefix.len()).unwrap_or(96)));
        let mark = self.bind(Param::from(prefix));
        self.clause(format!("substr({column}, 1, {len}) = {mark}"));
        Ok(())
    }

    fn time(&mut self, column: &str, op: &str, value: Option<i64>) {
        if let Some(v) = value {
            let mark = self.bind(Param::from(v));
            self.clause(format!("{column} {op} {mark}"));
        }
    }

    /// Keyset paging and ordering; returns the ORDER BY / LIMIT tail.
    fn page(
        &mut self,
        time_col: &str,
        id_col: &str,
        ascending: bool,
        after: Option<&Cursor>,
        page_size: u32,
    ) -> Result<String, LedgerError> {
        let size = match page_size {
            0 => DEFAULT_PAGE_SIZE,
            n if n <= MAX_PAGE_SIZE => n,
            _ => return Err(LedgerError::Invalid("page_size")),
        };
        let (cmp, dir) = if ascending {
            (">", "ASC")
        } else {
            ("<", "DESC")
        };
        if let Some(c) = after {
            let at = self.bind(Param::from(c.at));
            let id = self.bind(Param::from(c.id.clone()));
            self.clause(format!(
                "({time_col} {cmp} {at} OR ({time_col} = {at} AND {id_col} {cmp} {id}))"
            ));
        }
        let limit = self.bind(Param::from(i64::from(size)));
        Ok(format!(
            " ORDER BY {time_col} {dir}, {id_col} {dir} LIMIT {limit}"
        ))
    }

    fn sql(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.clauses.join(" AND "))
        }
    }
}

impl Cluster {
    /// One page of requests matching `f` (`ListAppRequests`).
    pub async fn app_list_requests(
        &self,
        f: &RequestFilter,
    ) -> Result<Vec<RequestListItem>, LedgerError> {
        let mut w = Where::default();
        w.any_of("r.state", f.states.iter().map(|s| s.code()));
        w.hosts("r.host_uuid", &f.host_uuids)?;
        w.contains(
            &["l.canonical_path"],
            f.path_contains.as_deref(),
            MAX_FILTER_CHARS,
            "path_contains",
        )?;
        w.contains(
            &["b.product_name"],
            f.product_contains.as_deref(),
            MAX_FILTER_CHARS,
            "product_contains",
        )?;
        w.equals("r.target_user_name", f.user_name.as_deref(), "user_name")?;
        w.equals(
            "b.declared_version",
            f.declared_version.as_deref(),
            "declared_version",
        )?;
        w.sha_prefix("r.bin_sha", f.bin_sha_prefix.as_deref())?;
        w.any_of("r.origin", f.origins.iter().map(|o| o.code()));
        w.any_of("r.kind", f.kinds.iter().map(|k| k.code()));
        if f.flags_any != 0 {
            let mark = w.bind(Param::from(i64::from(f.flags_any)));
            w.clause(format!("(r.flags & {mark}) <> 0"));
        }
        w.time("r.submitted_at", ">=", f.submitted_after);
        w.time("r.submitted_at", "<", f.submitted_before);
        w.contains(
            &[
                "l.canonical_path",
                "b.product_name",
                "r.target_user_name",
                "r.requester_user_name",
                "r.host_uuid",
                "b.declared_version",
            ],
            f.text.as_deref(),
            MAX_TEXT_CHARS,
            "text",
        )?;
        let tail = w.page(
            "r.submitted_at",
            "r.request_id",
            f.ascending,
            f.after.as_ref(),
            f.page_size,
        )?;
        let sql = format!(
            "SELECT {REQUEST_COLUMNS}, l.canonical_path AS l_canonical_path, \
             b.declared_version AS b_declared_version, b.product_name AS b_product_name \
             FROM app_requests r \
             JOIN app_lineages l ON l.lineage_id = r.lineage_id \
             LEFT JOIN app_binaries b ON b.lineage_id = r.lineage_id AND b.bin_sha = r.bin_sha\
             {}{tail}",
            w.sql()
        );
        let rows: Vec<Parsed<RequestListItem>> = self
            .client()
            .query_consistent_map(sql, w.params)
            .await
            .map_err(ClusterError::from)?;
        collect(rows)
    }

    /// One page of approvals matching `f` (`ListApprovals`).
    pub async fn app_list_approvals(
        &self,
        f: &ApprovalFilter,
    ) -> Result<Vec<ApprovalListItem>, LedgerError> {
        let mut w = Where::default();
        w.any_of("a.state", f.states.iter().map(|s| s.code()));
        w.hosts("a.host_uuid", &f.host_uuids)?;
        w.equals("a.lineage_id", f.lineage_id.as_deref(), "lineage_id")?;
        w.contains(
            &["l.canonical_path"],
            f.path_contains.as_deref(),
            MAX_FILTER_CHARS,
            "path_contains",
        )?;
        w.contains(
            &["b.product_name"],
            f.product_contains.as_deref(),
            MAX_FILTER_CHARS,
            "product_contains",
        )?;
        w.equals("a.user_name", f.user_name.as_deref(), "user_name")?;
        w.equals(
            "b.declared_version",
            f.declared_version.as_deref(),
            "declared_version",
        )?;
        w.sha_prefix("a.bin_sha", f.bin_sha_prefix.as_deref())?;
        w.any_of("a.update_policy", f.policies.iter().map(|p| p.code()));
        w.any_of("a.origin", f.approval_origins.iter().map(|o| o.code()));
        w.time("a.expires_at", "<", f.expires_before);
        w.time("a.expires_at", ">=", f.expires_after);
        w.time("a.created_at", ">=", f.created_after);
        w.time("a.created_at", "<", f.created_before);
        if !f.include_superseded {
            w.clause("a.superseded_by IS NULL".to_string());
        }
        if f.legacy_only {
            w.clause(format!(
                "a.origin = {}",
                ApprovalOrigin::LegacyImport.code()
            ));
        }
        if f.no_expiry_only {
            w.clause("a.expires_at IS NULL".to_string());
        }
        w.contains(
            &[
                "l.canonical_path",
                "b.product_name",
                "a.user_name",
                "a.host_uuid",
                "b.declared_version",
            ],
            f.text.as_deref(),
            MAX_TEXT_CHARS,
            "text",
        )?;
        let tail = w.page(
            "a.created_at",
            "a.approval_id",
            f.ascending,
            f.after.as_ref(),
            f.page_size,
        )?;
        let sql = format!(
            "SELECT {APPROVAL_COLUMNS}, l.canonical_path AS l_canonical_path, \
             b.declared_version AS b_declared_version, b.product_name AS b_product_name \
             FROM app_approvals a \
             LEFT JOIN app_lineages l ON l.lineage_id = a.lineage_id \
             LEFT JOIN app_binaries b ON b.lineage_id = a.lineage_id AND b.bin_sha = a.bin_sha\
             {}{tail}",
            w.sql()
        );
        let rows: Vec<Parsed<ApprovalListItem>> = self
            .client()
            .query_consistent_map(sql, w.params)
            .await
            .map_err(ClusterError::from)?;
        collect(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_needles_escape_wildcards() {
        assert_eq!(like_needle("abc"), "%abc%");
        assert_eq!(like_needle("50%_off\\"), "%50\\%\\_off\\\\%");
    }

    #[test]
    fn filters_bind_values_and_never_inline_them() {
        let mut w = Where::default();
        w.contains(&["l.canonical_path"], Some("x' OR 1=1 --"), 256, "path")
            .unwrap();
        w.equals("r.target_user_name", Some("bob'; DROP TABLE x"), "user")
            .unwrap();
        let sql = w.sql();
        assert!(!sql.contains("OR 1=1"));
        assert!(!sql.contains("DROP"));
        assert_eq!(w.params.len(), 2);
    }

    #[test]
    fn bad_filters_are_rejected() {
        let mut w = Where::default();
        assert!(w.sha_prefix("r.bin_sha", Some("abc")).is_err());
        assert!(w.sha_prefix("r.bin_sha", Some("zzzzzzzz")).is_err());
        assert!(w.sha_prefix("r.bin_sha", Some("ABCDEF01")).is_ok());
        assert!(w
            .contains(&["c"], Some(&"x".repeat(129)), MAX_TEXT_CHARS, "text")
            .is_err());
        assert!(w.page("t", "i", false, None, MAX_PAGE_SIZE + 1).is_err());
        assert!(w.hosts("h", &vec!["h".to_string(); MAX_HOSTS + 1]).is_err());
    }
}
