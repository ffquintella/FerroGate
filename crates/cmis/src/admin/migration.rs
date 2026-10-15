//! Administrator operations of the allowlist migration (F19 §11, F20 §7):
//! `GetAllowlistMode`, `SetAllowlistMode` and `ImportLegacyAllowlists`.
//!
//! The switch and the import are platform-operator methods
//! (`settings.allowlist_mode`, `allowlist.import`) behind a recent step-up,
//! classified in [`super::authz::METHOD_ACCESS`] and re-checked here
//! ([`require`], deny by default).
//!
//! - **Import.** Every legacy entry without its `legacy_import` approval
//!   gets one, and every open import whose entry has left the legacy body is
//!   revoked ([`crate::apps::migration`]), so the ledger follows the legacy
//!   bodies; a dry run writes nothing and returns the same report. One
//!   `AllowlistImported` event per host that gained approvals and one
//!   `ApprovalRevoked` per revoked import, each written after its write
//!   committed; a store failure answers `UNAVAILABLE store_unavailable` and
//!   audits nothing for the write that failed (hosts handled before it stay
//!   handled and audited; a re-run is idempotent).
//! - **Switch.** `approvals` is refused while a stale import is open
//!   (`FAILED_PRECONDITION import_stale`, no override: it would re-admit a
//!   binary an operator removed) and while a legacy entry has no approval
//!   (`import_incomplete`, unless the operator explicitly allows it);
//!   switching back to `legacy` needs `confirm_rollback`, after a dry run
//!   showed what the rollback changes (`FAILED_PRECONDITION
//!   confirmation_required` otherwise). The switch is audited as
//!   `AllowlistModeChanged`; a dry run or a switch to the mode in force
//!   writes nothing and records no event of its own (the layer's
//!   `AdminCallAuthorized` still records the call). Legacy writes check the
//!   mode inside their own transaction, so none lands after the switch, and
//!   the switch to `approvals` commits only if no legacy body changed since
//!   its plan (`ABORTED concurrent_change` otherwise: re-run).
//!
//! Reports carry host UUIDs, uids and hashes for the operator; audit events
//! and logs carry ids and counts only.

use tonic::{Request, Response, Status};

use ferro_proto::admin_v1::{
    GetAllowlistModeRequest, GetAllowlistModeResponse, ImportLegacyAllowlistsRequest,
    ImportLegacyAllowlistsResponse, LegacyImportEntry, LegacyImportHost, SetAllowlistModeRequest,
    SetAllowlistModeResponse,
};

use super::authz::{paths, require, AdminAuthz, AdminContext};
use super::state::AdminState;
use crate::apps::events::{self, ModeSwitchCounts};
use crate::apps::ledger_status;
use crate::apps::migration::{self, EntryStatus, HostPlan};
use crate::apps::mode::{self, AllowlistMode};
use crate::host_auth::invalid_field;

/// Longest `idempotency_key` accepted.
const MAX_IDEMPOTENCY_KEY: usize = 128;

/// Most entries an import report lists (the totals stay complete).
pub const MAX_REPORT_ENTRIES: usize = 10_000;

/// Most hosts an import report lists (the totals stay complete), which
/// keeps the response well below the 4 MiB gRPC message limit.
pub const MAX_REPORT_HOSTS: usize = 10_000;

fn check_idempotency(key: &str) -> Result<(), Status> {
    if key.len() > MAX_IDEMPOTENCY_KEY || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid_field("bad_value", Some("idempotency_key")));
    }
    Ok(())
}

fn store_unavailable(e: ferro_raft::ClusterError) -> Status {
    ledger_status(e.into())
}

fn count32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn count64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `GetAllowlistMode` (any session): the mode in force.
pub async fn get_allowlist_mode(
    authz: &AdminAuthz,
    request: Request<GetAllowlistModeRequest>,
) -> Result<Response<GetAllowlistModeResponse>, Status> {
    require(&request, paths::GET_ALLOWLIST_MODE)?;
    let st = authz.state();
    let current = mode::current(st.cluster())
        .await
        .map_err(store_unavailable)?;
    Ok(Response::new(GetAllowlistModeResponse {
        mode: current.code(),
        legacy_get_allowlist: st.cmis().config.apps.legacy_get_allowlist,
    }))
}

/// What the plans leave undone for a switch to `approvals`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Undone {
    /// Legacy entries without an approval.
    entries_not_imported: u64,
    /// Hosts holding them, or whose body was skipped.
    hosts_not_imported: u32,
    /// Open imports whose entry left the legacy body.
    stale_imports: u64,
}

fn undone(plans: &[HostPlan]) -> Undone {
    Undone {
        entries_not_imported: count64(plans.iter().map(HostPlan::to_create).sum()),
        hosts_not_imported: count32(
            plans
                .iter()
                .filter(|p| p.skipped.is_some() || p.to_create() > 0)
                .count(),
        ),
        stale_imports: count64(plans.iter().map(|p| p.stale.len()).sum()),
    }
}

/// `SetAllowlistMode` (`settings.allowlist_mode`, step-up).
pub async fn set_allowlist_mode(
    authz: &AdminAuthz,
    request: Request<SetAllowlistModeRequest>,
) -> Result<Response<SetAllowlistModeResponse>, Status> {
    let ctx = require(&request, paths::SET_ALLOWLIST_MODE)?;
    let st = authz.state();
    let now = st.now();
    let req = request.into_inner();
    check_idempotency(&req.idempotency_key)?;
    let target = AllowlistMode::from_code(req.mode)
        .ok_or_else(|| invalid_field("bad_value", Some("mode")))?;
    let cluster = st.cluster();
    let current = mode::current(cluster).await.map_err(store_unavailable)?;

    let mut counts = ModeSwitchCounts::default();
    let mut left = Undone::default();
    // Taken before the plan: the switch commits only if no legacy body
    // changed since (checked in the switch's own transaction).
    let fingerprint = cluster
        .legacy_allowlists_fingerprint()
        .await
        .map_err(ledger_status)?;
    match target {
        AllowlistMode::Legacy => {
            let c = cluster
                .app_mode_rollback_counts(now)
                .await
                .map_err(ledger_status)?;
            counts.approvals_not_reflected = c.approvals_not_reflected;
            counts.imports_readmitted = c.imports_readmitted;
        }
        AllowlistMode::Approvals => {
            left = undone(&migration::plan(st.cmis()).await?);
            counts.entries_not_imported = left.entries_not_imported;
        }
    }
    let mut resp = SetAllowlistModeResponse {
        previous_mode: current.code(),
        mode: current.code(),
        changed: false,
        approvals_not_reflected: counts.approvals_not_reflected,
        imports_readmitted: counts.imports_readmitted,
        entries_not_imported: left.entries_not_imported,
        hosts_not_imported: left.hosts_not_imported,
        stale_imports: left.stale_imports,
    };
    if req.dry_run || target == current {
        tracing::info!(
            event = "apps.mode.unchanged",
            admin_id = %ctx.admin_id,
            mode = current.as_str(),
            requested = target.as_str(),
            dry_run = req.dry_run,
            "allowlist mode not changed"
        );
        return Ok(Response::new(resp));
    }
    if target == AllowlistMode::Approvals {
        if left.stale_imports > 0 {
            return Err(Status::failed_precondition("import_stale"));
        }
        if left.hosts_not_imported > 0 && !req.allow_unimported {
            return Err(Status::failed_precondition("import_incomplete"));
        }
    }
    if target == AllowlistMode::Legacy && !req.confirm_rollback {
        return Err(Status::failed_precondition("confirmation_required"));
    }
    if target == AllowlistMode::Approvals {
        if !mode::set_if_legacy_unchanged(cluster, target, fingerprint)
            .await
            .map_err(ledger_status)?
        {
            return Err(Status::aborted("concurrent_change"));
        }
    } else {
        mode::set(cluster, target)
            .await
            .map_err(store_unavailable)?;
    }
    st.audit(events::mode_changed(
        current.as_str(),
        target.as_str(),
        &ctx.admin_id,
        &ctx.session_ref,
        counts,
    ));
    tracing::warn!(
        event = "apps.mode.changed",
        admin_id = %ctx.admin_id,
        from = current.as_str(),
        to = target.as_str(),
        approvals_not_reflected = counts.approvals_not_reflected,
        imports_readmitted = counts.imports_readmitted,
        entries_not_imported = counts.entries_not_imported,
        "allowlist mode switched"
    );
    resp.mode = target.code();
    resp.changed = true;
    Ok(Response::new(resp))
}

/// What the import did for one host.
#[derive(Debug, Clone, Copy, Default)]
struct HostDone {
    created: u32,
    revoked: u32,
    generation: u64,
}

/// The report line of one host, with up to `budget` entries listed.
fn host_report(
    p: &HostPlan,
    done: HostDone,
    dry_run: bool,
    budget: &mut usize,
    truncated: &mut bool,
) -> LegacyImportHost {
    let mut entries = Vec::new();
    for (e, status) in &p.entries {
        if *budget == 0 {
            *truncated = true;
            break;
        }
        *budget -= 1;
        entries.push(LegacyImportEntry {
            uid: e.uid.and_then(|u| u32::try_from(u).ok()),
            bin_sha: e.bin_sha.clone(),
            already_imported: *status == EntryStatus::Imported,
            revoked: *status == EntryStatus::Revoked,
        });
    }
    LegacyImportHost {
        host_uuid: p.host_uuid.clone(),
        entries_to_create: count32(p.to_create()),
        entries_already_imported: count32(p.already_imported()),
        approvals_created: done.created,
        skipped: p
            .skipped
            .map(|s| s.as_str().to_string())
            .unwrap_or_default(),
        entries,
        allowlist_generation: done.generation,
        stale_imports: if dry_run || !p.revokes_stale() {
            count32(p.stale.len())
        } else {
            0
        },
        imports_revoked: done.revoked,
        entries_revoked: count32(p.revoked_in_body()),
    }
}

/// Import and reconcile one host, auditing each committed write.
async fn import_one(
    st: &AdminState,
    ctx: &AdminContext,
    p: &HostPlan,
    now: i64,
) -> Result<HostDone, Status> {
    let mut done = HostDone::default();
    if p.skipped.is_none() && p.to_create() > 0 {
        match migration::import_host(st.cmis(), p, &ctx.admin_id, now).await {
            Ok(imported) => {
                if imported.created > 0 {
                    st.audit(events::imported(
                        &p.host_uuid,
                        imported.created,
                        &ctx.admin_id,
                    ));
                }
                done.created = imported.created;
                done.generation = imported.generation;
            }
            Err(failed) => {
                if failed.committed > 0 {
                    st.audit(events::imported(
                        &p.host_uuid,
                        failed.committed,
                        &ctx.admin_id,
                    ));
                }
                tracing::error!(
                    event = "apps.migration.failed",
                    host_uuid = %p.host_uuid,
                    committed = failed.committed,
                    "legacy allowlist import stopped; re-run to continue"
                );
                return Err(failed.status);
            }
        }
    }
    if p.revokes_stale() {
        let revoked = match migration::revoke_stale(st.cmis(), p, &ctx.admin_id, now).await {
            Ok(rows) => rows,
            Err(failed) => {
                for row in &failed.revoked {
                    st.audit(events::revoked(row, &ctx.admin_id, &ctx.session_ref));
                }
                tracing::error!(
                    event = "apps.migration.failed",
                    host_uuid = %p.host_uuid,
                    revoked = failed.revoked.len(),
                    "stale legacy import revocation stopped; re-run to continue"
                );
                return Err(failed.status);
            }
        };
        for row in &revoked {
            st.audit(events::revoked(row, &ctx.admin_id, &ctx.session_ref));
        }
        done.revoked = count32(revoked.len());
        if !revoked.is_empty() {
            done.generation = st
                .cluster()
                .app_allowlist_state(&p.host_uuid)
                .await
                .map_err(ledger_status)?
                .map_or(0, |s| s.generation);
        }
    }
    if done.created > 0 || done.revoked > 0 {
        tracing::info!(
            event = "apps.migration.imported",
            host_uuid = %p.host_uuid,
            approvals_created = done.created,
            imports_revoked = done.revoked,
            generation = done.generation,
            admin_id = %ctx.admin_id,
            "legacy allowlist imported"
        );
    }
    Ok(done)
}

/// `ImportLegacyAllowlists` (`allowlist.import`, step-up).
pub async fn import_legacy_allowlists(
    authz: &AdminAuthz,
    request: Request<ImportLegacyAllowlistsRequest>,
) -> Result<Response<ImportLegacyAllowlistsResponse>, Status> {
    let ctx = require(&request, paths::IMPORT_LEGACY_ALLOWLISTS)?;
    let st = authz.state();
    let now = st.now();
    let req = request.into_inner();
    check_idempotency(&req.idempotency_key)?;
    let plans = migration::plan(st.cmis()).await?;

    let mut done = vec![HostDone::default(); plans.len()];
    if !req.dry_run {
        for (p, d) in plans.iter().zip(done.iter_mut()) {
            *d = import_one(st, &ctx, p, now).await?;
        }
    }

    let mut resp = ImportLegacyAllowlistsResponse {
        dry_run: req.dry_run,
        ..ImportLegacyAllowlistsResponse::default()
    };
    let mut budget = MAX_REPORT_ENTRIES;
    for (i, (p, d)) in plans.iter().zip(done.iter()).enumerate() {
        resp.entries_to_create += count64(p.to_create());
        resp.entries_already_imported += count64(p.already_imported());
        resp.approvals_created += u64::from(d.created);
        resp.imports_revoked += u64::from(d.revoked);
        if req.dry_run || !p.revokes_stale() {
            resp.stale_imports += count64(p.stale.len());
        }
        if p.skipped.is_some() {
            resp.hosts_skipped += 1;
        }
        if i < MAX_REPORT_HOSTS {
            let line = host_report(p, *d, req.dry_run, &mut budget, &mut resp.entries_truncated);
            resp.hosts.push(line);
        } else {
            resp.hosts_truncated = true;
        }
    }
    tracing::info!(
        event = "apps.migration.report",
        admin_id = %ctx.admin_id,
        dry_run = req.dry_run,
        hosts = plans.len(),
        entries_to_create = resp.entries_to_create,
        approvals_created = resp.approvals_created,
        imports_revoked = resp.imports_revoked,
        stale_imports = resp.stale_imports,
        "legacy allowlist import"
    );
    Ok(Response::new(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::migration::Skipped;
    use ferro_raft::apps::LegacyEntry;

    fn plan(entries: &[(u32, EntryStatus)], stale: usize, skipped: Option<Skipped>) -> HostPlan {
        HostPlan {
            host_uuid: "h".into(),
            has_body: true,
            entries: entries
                .iter()
                .map(|(u, s)| (LegacyEntry::new(Some(*u), "*").unwrap(), *s))
                .collect(),
            stale: (0..stale).map(|i| format!("s{i}")).collect(),
            skipped,
        }
    }

    #[test]
    fn what_is_left_undone_counts_skipped_hosts_and_stale_imports() {
        use EntryStatus::{Imported, Revoked, ToCreate};
        let plans = vec![
            plan(&[(1, Imported), (2, ToCreate)], 0, None),
            plan(&[(1, Imported), (2, Revoked)], 2, None),
            plan(&[], 1, Some(Skipped::Undecodable)),
        ];
        assert_eq!(
            undone(&plans),
            Undone {
                entries_not_imported: 1,
                hosts_not_imported: 2,
                stale_imports: 3,
            }
        );
        assert_eq!(
            undone(&plans[1..2]).hosts_not_imported,
            0,
            "a revoked entry is no gap"
        );
    }

    #[test]
    fn reports_are_bounded() {
        use EntryStatus::{Imported, Revoked, ToCreate};
        let p = plan(&[(1, ToCreate), (2, Imported), (3, Revoked)], 1, None);
        let (mut budget, mut truncated) = (2, false);
        let line = host_report(&p, HostDone::default(), true, &mut budget, &mut truncated);
        assert_eq!(line.entries.len(), 2);
        assert!(truncated);
        assert_eq!(
            (
                line.entries_to_create,
                line.entries_already_imported,
                line.entries_revoked
            ),
            (1, 1, 1)
        );
        assert_eq!(
            line.stale_imports, 1,
            "a dry run reports what it would revoke"
        );
        assert_eq!(line.skipped, "");
        let done = HostDone {
            created: 1,
            revoked: 1,
            generation: 7,
        };
        let line = host_report(&p, done, false, &mut 10, &mut false);
        assert_eq!((line.stale_imports, line.imports_revoked), (0, 1));
    }

    #[test]
    fn idempotency_keys_are_bounded_printable_ascii() {
        assert!(check_idempotency("").is_ok());
        assert!(check_idempotency("0190-abc").is_ok());
        assert!(check_idempotency(&"k".repeat(129)).is_err());
        assert!(check_idempotency("a b").is_err());
    }
}
