//! `ProposeAllowlist` from a pre-F19 agent in `approvals` mode (F19 §11
//! step 5): each new `(uid, bin_sha)` entry of the proposal becomes one
//! `observed` request for an administrator. Nothing is adopted (the
//! `CMIS_ALLOWLIST_PROPOSALS` trust-on-first-use is off in this mode), no
//! legacy body or pending proposal is written, and no approval is touched.
//!
//! A v1 proposal carries no path and no binary metadata, so its requests
//! live in a per-hash placeholder lineage whose path is
//! [`UNKNOWN_PATH`] and whose `path_key` starts with a NUL byte (no real
//! canonical path contains one, so it never meets a lineage a new agent
//! reports). An approver must choose an any-path scope for such a request
//! (enforced by `ApproveAppRequest`); the request is never auto-approved.
//!
//! Entries are skipped when they cannot be a request (the `"*"` hash, or no
//! uid — MIA's self-registration entry) or are already admitted by a live
//! approval of the host on some path. The host's live approvals and open
//! requests are read once per proposal, not once per entry. Deduplication, the denial cool-down,
//! the per-host submission budget (`CMIS_APP_SUBMIT_MAX_PER_HOUR`) and the
//! pending caps apply as for `SubmitAppRequest`; an entry over budget is
//! left for the agent's next proposal. A proposal of more than
//! [`MAX_PROPOSAL_ENTRIES`] distinct entries is refused before any read.

use std::collections::{BTreeSet, HashSet};

use ferro_raft::apps::{
    dedup_key, Cursor, Intake, IntakeChecks, LineageRow, LiveApproval, NewRequest, ObservedBinary,
    RequestFilter, RequestOrigin, RequestState, UserIdentity, UserKind, UserScope, MAX_PAGE_SIZE,
};
use ferro_svid::AllowEntry;
use tonic::Status;

use super::intake::{cmis_flags, cooldown_since};
use super::{events, ledger_status, new_id};
use crate::service::audit_record;
use crate::state::CmisState;

/// The display path of a request proposed by a pre-F19 agent.
pub const UNKNOWN_PATH: &str = "(unknown path: proposed by a pre-F19 agent)";

/// Prefix of the placeholder `path_key`; the NUL byte keeps it apart from
/// every real `ferro_appid::path_key`.
const UNKNOWN_PATH_KEY_PREFIX: &[u8] = b"\0ferrogate-unknown-path-v1\0";

/// Platform code stored on a placeholder lineage. The ledger has no
/// "unknown" platform; the value is never shown and never used, because
/// such a lineage has no real path to match.
const PLACEHOLDER_PLATFORM: i64 = 1;

/// Format code "other" of a binary nothing is known about.
const FORMAT_OTHER: i64 = 9;

/// New requests one proposal may create; the rest wait for the next one.
pub const MAX_NEW_REQUESTS_PER_PROPOSAL: usize = 50;

/// Distinct entries one proposal may carry in `approvals` mode: each costs
/// ledger reads, so a larger proposal is refused before any
/// (`INVALID_ARGUMENT too_many_entries`).
pub const MAX_PROPOSAL_ENTRIES: usize = 4096;

/// The requester's note shown to approvers.
const PROPOSAL_REASON: &str =
    "Observed by a pre-F19 agent (ProposeAllowlist): path and binary details unknown";

/// The placeholder `path_key` of `bin_sha`'s lineage on a proposing host.
#[must_use]
pub fn unknown_path_key(bin_sha: &str) -> Vec<u8> {
    let mut key = UNKNOWN_PATH_KEY_PREFIX.to_vec();
    key.extend_from_slice(bin_sha.as_bytes());
    key
}

/// Whether `lineage` is a placeholder of a pre-F19 proposal (no real path).
#[must_use]
pub fn is_unknown_path(lineage: &LineageRow) -> bool {
    lineage.path_key.starts_with(UNKNOWN_PATH_KEY_PREFIX)
}

/// The authenticated proposer.
#[derive(Debug, Clone)]
pub struct Proposer {
    /// Host UUID from the SVID.
    pub host_uuid: String,
    /// SVID subject.
    pub spiffe_id: String,
    /// Attestation tier of the SVID.
    pub tier: &'static str,
}

/// What a proposal did, entry by entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProposalOutcome {
    /// New `observed` requests recorded.
    pub recorded: usize,
    /// Entries that have an open request (new or earlier).
    pub pending: usize,
    /// Entries a live approval already admits.
    pub covered: usize,
    /// Entries that cannot be requests (`"*"`, no uid) or were recently
    /// denied.
    pub skipped: usize,
    /// Entries left for a later proposal (budget, caps).
    pub deferred: usize,
}

/// Whether a live approval admits `bin_sha` run by `uid` on some path: the
/// same or the wildcard hash, and an any-user scope or the same uid without
/// a SID (a pre-F19 agent matches uids only).
fn admits_on_some_path(live: &[LiveApproval], bin_sha: &str, uid: i64) -> bool {
    live.iter().any(|l| {
        let a = &l.approval;
        (a.bin_sha == bin_sha || a.bin_sha == ferro_svid::allowlist::BIN_SHA_WILDCARD)
            && (a.user_scope == UserScope::AnyUser || (a.sid.is_none() && a.uid == Some(uid)))
    })
}

/// Pages of open requests read for one proposal (bounded by the pending
/// caps, at most 10 000 per host).
const MAX_OPEN_PAGES: usize = 60;

/// The dedup keys of `host_uuid`'s open requests.
async fn open_dedup_keys(state: &CmisState, host_uuid: &str) -> Result<HashSet<Vec<u8>>, Status> {
    let mut keys = HashSet::new();
    let mut after: Option<Cursor> = None;
    for _ in 0..MAX_OPEN_PAGES {
        let page = state
            .cluster()
            .app_list_requests(&RequestFilter {
                states: vec![RequestState::Pending],
                host_uuids: vec![host_uuid.to_string()],
                ascending: true,
                page_size: MAX_PAGE_SIZE,
                after: after.clone(),
                ..RequestFilter::default()
            })
            .await
            .map_err(ledger_status)?;
        let full = page.len() >= usize::try_from(MAX_PAGE_SIZE).unwrap_or(usize::MAX);
        after = page.last().map(|i| Cursor {
            at: i.request.submitted_at,
            id: i.request.request_id.clone(),
        });
        keys.extend(page.into_iter().map(|i| i.request.dedup_key));
        if !full {
            break;
        }
    }
    Ok(keys)
}

/// Turn a verified proposal's entries into `observed` requests (see the
/// module docs). Store failures answer `UNAVAILABLE`; requests recorded
/// before the failure stay recorded and audited.
#[allow(clippy::too_many_lines)] // one ordered check sequence per entry.
pub async fn observe(
    state: &CmisState,
    proposer: &Proposer,
    entries: &[AllowEntry],
    now: i64,
) -> Result<ProposalOutcome, Status> {
    let cluster = state.cluster();
    let cfg = &state.config.apps;
    let mut out = ProposalOutcome::default();
    let distinct: BTreeSet<(Option<u32>, &str)> = entries
        .iter()
        .map(|e| (e.uid, e.bin_sha.as_str()))
        .collect();
    if distinct.len() > MAX_PROPOSAL_ENTRIES {
        return Err(crate::host_auth::invalid_field(
            "too_many_entries",
            Some("entries"),
        ));
    }
    // Two reads for the whole proposal, not two per entry: the host's live
    // approvals and its open requests.
    let live = cluster
        .app_live_approvals(&proposer.host_uuid, now)
        .await
        .map_err(ledger_status)?;
    let mut open = open_dedup_keys(state, &proposer.host_uuid).await?;
    for (uid, bin_sha) in distinct {
        let Some(uid) = uid.filter(|_| bin_sha != ferro_svid::allowlist::BIN_SHA_WILDCARD) else {
            out.skipped += 1;
            continue;
        };
        let uid = i64::from(uid);
        if admits_on_some_path(&live, bin_sha, uid) {
            out.covered += 1;
            continue;
        }
        let path_key = unknown_path_key(bin_sha);
        let target = UserIdentity {
            kind: UserKind::Unix,
            uid: Some(uid),
            sid: None,
            user_name: None,
        };
        let dedup = dedup_key(&proposer.host_uuid, &path_key, &target, bin_sha);
        if open.contains(&dedup) {
            out.pending += 1;
            continue;
        }
        if out.recorded >= MAX_NEW_REQUESTS_PER_PROPOSAL {
            out.deferred += 1;
            continue;
        }
        if state
            .host_calls
            .app_submit_limiter()
            .check(&proposer.host_uuid, now)
            .is_err()
        {
            out.deferred += 1;
            continue;
        }
        let counts = cluster
            .app_pending_counts(&proposer.host_uuid, &target)
            .await
            .map_err(ledger_status)?;
        if counts.host >= cfg.max_pending_per_host || counts.user >= cfg.max_pending_per_user {
            out.deferred += 1;
            continue;
        }
        let (_lineage, binary) = cluster
            .app_observe_binary(&ObservedBinary {
                host_uuid: proposer.host_uuid.clone(),
                platform: PLACEHOLDER_PLATFORM,
                canonical_path: UNKNOWN_PATH.to_string(),
                path_key: path_key.clone(),
                new_lineage_id: new_id(),
                bin_sha: bin_sha.to_string(),
                file_size: 0,
                format: FORMAT_OTHER,
                declared_version: None,
                version_source: 0,
                product_name: None,
                bundle_id: None,
                package_name: None,
                signer_kind: 0,
                signer_id: None,
                signer_subject: None,
                signer_valid: false,
                seen_at: now,
            })
            .await
            .map_err(ledger_status)?;
        let flags = cmis_flags(cluster, &binary, proposer.tier)
            .await
            .map_err(ledger_status)?;
        let req = NewRequest {
            request_id: new_id(),
            host_uuid: proposer.host_uuid.clone(),
            client_request_id: format!("prop:{}", new_id()),
            lineage_id: binary.lineage_id.clone(),
            bin_sha: bin_sha.to_string(),
            revision: binary.revision,
            origin: RequestOrigin::Observed,
            target,
            requester_uid: None,
            requester_user_name: None,
            requested_by_admin_id: None,
            reason: Some(PROPOSAL_REASON.to_string()),
            flags,
            host_tier: proposer.tier.to_string(),
            proposer_spiffe_id: proposer.spiffe_id.clone(),
            dedup_key: dedup,
            submitted_at: now,
            pending_expires_at: now.saturating_add(cfg.pending_ttl_secs),
            auto_downgrade_reason: None,
        };
        match cluster
            .app_submit_pending(
                &req,
                &IntakeChecks {
                    now,
                    denied_cooldown_since: cooldown_since(cfg, now),
                },
            )
            .await
            .map_err(ledger_status)?
        {
            Intake::Recorded(row) => {
                open.insert(row.dedup_key.clone());
                audit_record(state, events::submitted(&row, &path_key), now);
                tracing::info!(
                    event = "apps.request.observed",
                    request_id = %row.request_id,
                    host_uuid = %proposer.host_uuid,
                    "pre-F19 proposal entry recorded as an observed request"
                );
                out.recorded += 1;
                out.pending += 1;
            }
            Intake::DuplicatePending(_) => out.pending += 1,
            Intake::Covered(_) => out.covered += 1,
            Intake::Replayed(_) | Intake::RecentlyDenied(_) => out.skipped += 1,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_keys_never_meet_real_paths() {
        let sha = "ab".repeat(48);
        let key = unknown_path_key(&sha);
        assert_eq!(key[0], 0, "a NUL byte no real path_key has");
        assert!(key.ends_with(sha.as_bytes()));
        assert_ne!(unknown_path_key(&"cd".repeat(48)), key);
        let lineage = |path_key: Vec<u8>| LineageRow {
            lineage_id: "l".into(),
            host_uuid: "h".into(),
            platform: 1,
            canonical_path: UNKNOWN_PATH.into(),
            path_key,
            next_revision: 2,
            auto_update_frozen: false,
            created_at: 0,
        };
        assert!(is_unknown_path(&lineage(key)));
        assert!(!is_unknown_path(&lineage(b"/opt/tool".to_vec())));
        assert!(PROPOSAL_REASON.chars().count() <= 200);
    }
}
