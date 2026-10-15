//! The legacy-allowlist import and the mode-switch report (F19 §11 steps 4
//! to 6): the policy over [`ferro_raft::apps`]'s import and the legacy
//! `host_allowlists` store. The administrator RPCs that drive it are in
//! [`crate::admin::migration`].
//!
//! - [`plan`] reads every stored legacy body and every host with an open
//!   legacy import (strongly consistent) and reports per host which entries
//!   still need their `legacy_import` approval, which are imported, which
//!   were imported and later revoked (never recreated), and which open
//!   imports are **stale**: their entry has left the legacy body since the
//!   import (an operator removed the binary, or deleted the body, while still
//!   in `legacy` mode). It writes nothing: it is the dry run.
//! - [`import_host`] creates the missing approvals of one host, in batches
//!   of at most [`MAX_IMPORT_BATCH`] entries, each batch one Raft
//!   transaction that also bumps the host's allowlist generation.
//! - [`revoke_stale`] revokes a host's stale imports (reason
//!   [`LEGACY_ENTRY_REMOVED`]), so a binary removed from a legacy body can
//!   never come back to life when the cluster switches to `approvals`; the
//!   switch refuses while any stale import is open.
//!
//! A legacy body that does not decode, holds an entry the v1 validator would
//! not accept, or is stored under a key that is not a host UUID is skipped as
//! a whole and reported (fail closed: nothing of it is imported, and its open
//! imports count as stale until the body is fixed or deleted). The decoder's
//! message is not logged: it can quote the body.

use std::collections::{BTreeMap, BTreeSet};

use ferro_raft::apps::{
    legacy_approval_id, ApprovalRow, ApprovalState, LedgerError, LegacyEntry, Revoke,
    MAX_IMPORT_BATCH,
};
use tonic::Status;

use super::{ledger_status, now_millis};
use crate::state::CmisState;

/// Revocation reason code of a legacy import whose entry was removed from
/// the legacy body (import reconciliation).
pub const LEGACY_ENTRY_REMOVED: i64 = 1000;

/// Why a host's legacy body is not imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// The stored body does not decode, or holds an invalid entry.
    Undecodable,
    /// The body is stored under a key that is not a host UUID.
    NotAHostUuid,
}

impl Skipped {
    /// Stable reason code for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undecodable => "undecodable",
            Self::NotAHostUuid => "not_a_host_uuid",
        }
    }
}

/// Where one entry of a legacy body stands in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStatus {
    /// No approval yet: the import creates it.
    ToCreate,
    /// Imported, and not revoked.
    Imported,
    /// Imported and later revoked: never recreated (an administrator's
    /// revocation stands).
    Revoked,
}

/// One host's legacy body, against the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlan {
    /// The key the legacy body is stored under (the host UUID).
    pub host_uuid: String,
    /// Whether a legacy body is stored for the host.
    pub has_body: bool,
    /// The distinct entries of the body and where each stands.
    pub entries: Vec<(LegacyEntry, EntryStatus)>,
    /// Ids of open (not revoked) imports whose entry is not in the body.
    pub stale: Vec<String>,
    /// Set when the body is not imported at all.
    pub skipped: Option<Skipped>,
}

impl HostPlan {
    fn count(&self, status: EntryStatus) -> usize {
        self.entries.iter().filter(|(_, s)| *s == status).count()
    }

    /// Entries an import would create.
    #[must_use]
    pub fn to_create(&self) -> usize {
        self.count(EntryStatus::ToCreate)
    }

    /// Entries imported and still open.
    #[must_use]
    pub fn already_imported(&self) -> usize {
        self.count(EntryStatus::Imported)
    }

    /// Entries of the body whose import was revoked.
    #[must_use]
    pub fn revoked_in_body(&self) -> usize {
        self.count(EntryStatus::Revoked)
    }

    /// Whether an import revokes this host's stale imports (only when the
    /// body could be read, or there is none).
    #[must_use]
    pub fn revokes_stale(&self) -> bool {
        self.skipped.is_none() && !self.stale.is_empty()
    }
}

/// The distinct, validated entries of a stored legacy body.
fn decode_entries(stored: &[u8]) -> Option<Vec<LegacyEntry>> {
    let doc = ferro_svid::allowlist::decode(stored)
        .and_then(|s| ferro_svid::allowlist::decode_body(&s.body))
        .ok()?;
    let mut set = BTreeSet::new();
    for e in doc.entries {
        set.insert(LegacyEntry::new(e.uid, e.bin_sha.trim()).ok()?);
    }
    Some(set.into_iter().collect())
}

/// Hosts look their body up by the canonical (lowercase, hyphenated) UUID
/// text; a row under any other key was never served to a host.
fn is_canonical_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s)
}

/// The open imports of `host_uuid` (id → entry) and the ids of all its
/// imports with their state.
async fn imports_of(
    state: &CmisState,
    host_uuid: &str,
) -> Result<BTreeMap<String, ApprovalState>, Status> {
    Ok(state
        .cluster()
        .app_legacy_imports_of(host_uuid)
        .await
        .map_err(ledger_status)?
        .into_iter()
        .map(|r| (r.approval_id, r.state))
        .collect())
}

fn open_ids(imports: &BTreeMap<String, ApprovalState>) -> impl Iterator<Item = &String> {
    imports
        .iter()
        .filter(|(_, s)| **s != ApprovalState::Revoked)
        .map(|(id, _)| id)
}

/// The import plan of every stored legacy body and of every host with an
/// open legacy import, ordered by host (the dry run; nothing is written).
/// Store failures answer `UNAVAILABLE`.
pub async fn plan(state: &CmisState) -> Result<Vec<HostPlan>, Status> {
    let cluster = state.cluster();
    let rows = cluster
        .list_allowlists_consistent()
        .await
        .map_err(|e| ledger_status(e.into()))?;
    let mut plans = Vec::with_capacity(rows.len());
    let mut with_body = BTreeSet::new();
    for (host_uuid, payload) in rows {
        with_body.insert(host_uuid.clone());
        if !is_canonical_uuid(&host_uuid) {
            tracing::warn!(
                event = "apps.migration.skipped",
                reason = Skipped::NotAHostUuid.as_str(),
                "legacy allowlist stored under a key that is not a host UUID; not imported"
            );
            plans.push(HostPlan {
                host_uuid,
                has_body: true,
                entries: Vec::new(),
                stale: Vec::new(),
                skipped: Some(Skipped::NotAHostUuid),
            });
            continue;
        }
        let imports = imports_of(state, &host_uuid).await?;
        let Some(entries) = decode_entries(&payload) else {
            tracing::error!(
                event = "apps.migration.skipped",
                %host_uuid,
                reason = Skipped::Undecodable.as_str(),
                "legacy allowlist does not decode; not imported"
            );
            plans.push(HostPlan {
                stale: open_ids(&imports).cloned().collect(),
                host_uuid,
                has_body: true,
                entries: Vec::new(),
                skipped: Some(Skipped::Undecodable),
            });
            continue;
        };
        let in_body: BTreeSet<String> = entries
            .iter()
            .map(|e| legacy_approval_id(&host_uuid, e))
            .collect();
        let entries = entries
            .into_iter()
            .map(|e| {
                let status = match imports.get(&legacy_approval_id(&host_uuid, &e)) {
                    None => EntryStatus::ToCreate,
                    Some(ApprovalState::Revoked) => EntryStatus::Revoked,
                    Some(_) => EntryStatus::Imported,
                };
                (e, status)
            })
            .collect();
        plans.push(HostPlan {
            stale: open_ids(&imports)
                .filter(|id| !in_body.contains(*id))
                .cloned()
                .collect(),
            host_uuid,
            has_body: true,
            entries,
            skipped: None,
        });
    }
    // Hosts whose legacy body was deleted after the import.
    for host_uuid in cluster
        .app_hosts_with_open_legacy_imports()
        .await
        .map_err(ledger_status)?
    {
        if with_body.contains(&host_uuid) {
            continue;
        }
        let imports = imports_of(state, &host_uuid).await?;
        plans.push(HostPlan {
            stale: open_ids(&imports).cloned().collect(),
            host_uuid,
            has_body: false,
            entries: Vec::new(),
            skipped: None,
        });
    }
    plans.sort_by(|a, b| a.host_uuid.cmp(&b.host_uuid));
    Ok(plans)
}

/// What importing one host did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostImported {
    /// Approvals created.
    pub created: u32,
    /// The host's allowlist generation afterwards.
    pub generation: u64,
}

/// A failed import of one host: the batches before the failure committed.
#[derive(Debug)]
pub struct ImportFailed {
    /// Approvals the committed batches created (to be audited).
    pub committed: u32,
    /// The answer to the caller (`UNAVAILABLE store_unavailable` for a store
    /// failure).
    pub status: Status,
}

/// Create the approvals `plan` lists as missing, recording `admin_id` as
/// the importer, in batches of at most [`MAX_IMPORT_BATCH`] entries.
pub async fn import_host(
    state: &CmisState,
    plan: &HostPlan,
    admin_id: &str,
    now: i64,
) -> Result<HostImported, ImportFailed> {
    let missing: Vec<LegacyEntry> = plan
        .entries
        .iter()
        .filter(|(_, s)| *s == EntryStatus::ToCreate)
        .map(|(e, _)| e.clone())
        .collect();
    let mut out = HostImported::default();
    for batch in missing.chunks(MAX_IMPORT_BATCH) {
        match state
            .cluster()
            .app_import_legacy(&plan.host_uuid, batch, admin_id, now, now_millis(now))
            .await
        {
            Ok(done) => {
                out.created = out
                    .created
                    .saturating_add(u32::try_from(done.created.len()).unwrap_or(u32::MAX));
                out.generation = done.generation;
            }
            Err(e) => {
                return Err(ImportFailed {
                    committed: out.created,
                    status: ledger_status(e),
                });
            }
        }
    }
    Ok(out)
}

/// A failed reconciliation of one host: the revocations before it committed.
#[derive(Debug)]
pub struct RevokeFailed {
    /// Approvals revoked before the failure (to be audited).
    pub revoked: Vec<ApprovalRow>,
    /// The answer to the caller.
    pub status: Status,
}

/// Revoke `plan`'s stale imports as `admin_id` (reason
/// [`LEGACY_ENTRY_REMOVED`]), each with its revision record and a generation
/// bump. An import revoked meanwhile is skipped. Returns the revoked rows.
pub async fn revoke_stale(
    state: &CmisState,
    plan: &HostPlan,
    admin_id: &str,
    now: i64,
) -> Result<Vec<ApprovalRow>, RevokeFailed> {
    let mut revoked = Vec::with_capacity(plan.stale.len());
    if !plan.revokes_stale() {
        return Ok(revoked);
    }
    for approval_id in &plan.stale {
        match state
            .cluster()
            .app_revoke_approval(
                &Revoke {
                    approval_id: approval_id.clone(),
                    admin_id: admin_id.to_string(),
                    reason_code: LEGACY_ENTRY_REMOVED,
                    expected_row_version: None,
                },
                now,
                now_millis(now),
            )
            .await
        {
            Ok(row) => revoked.push(row),
            Err(LedgerError::InvalidState | LedgerError::NotFound) => {}
            Err(e) => {
                return Err(RevokeFailed {
                    revoked,
                    status: ledger_status(e),
                });
            }
        }
    }
    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_count_what_an_import_would_do() {
        let e = |u: u32| LegacyEntry::new(Some(u), "*").unwrap();
        let p = HostPlan {
            host_uuid: "h".into(),
            has_body: true,
            entries: vec![
                (e(1), EntryStatus::Imported),
                (e(2), EntryStatus::ToCreate),
                (e(3), EntryStatus::ToCreate),
                (e(4), EntryStatus::Revoked),
            ],
            stale: vec!["s".into()],
            skipped: None,
        };
        assert_eq!(
            (p.to_create(), p.already_imported(), p.revoked_in_body()),
            (2, 1, 1)
        );
        assert!(p.revokes_stale());
        let unreadable = HostPlan {
            skipped: Some(Skipped::Undecodable),
            ..p
        };
        assert!(
            !unreadable.revokes_stale(),
            "an unreadable body decides nothing"
        );
        assert_eq!(Skipped::Undecodable.as_str(), "undecodable");
        assert_eq!(Skipped::NotAHostUuid.as_str(), "not_a_host_uuid");
    }

    #[test]
    fn garbage_bodies_decode_to_nothing_and_keys_must_be_canonical() {
        assert_eq!(decode_entries(b"not cbor"), None);
        assert_eq!(decode_entries(&[]), None);
        assert!(is_canonical_uuid("8d5e0000-0000-4000-8000-000000000001"));
        assert!(!is_canonical_uuid("8D5E0000-0000-4000-8000-000000000001"));
        assert!(!is_canonical_uuid("{8d5e0000-0000-4000-8000-000000000001}"));
        assert!(!is_canonical_uuid("not-a-host"));
    }
}
