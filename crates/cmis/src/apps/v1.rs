//! The legacy v1 `GetAllowlist` in `approvals` mode (F19 §6.4).
//!
//! Pre-F19 agents fetch the unauthenticated v1 body and match `(uid,
//! bin_sha)` only. In `approvals` mode that body is compiled "lossy-safe"
//! from the host's live approvals: an approval is included only when an old
//! agent can enforce all of it —
//!
//! - it needs no v2 constraint: `path_match = any`, and either an any-user
//!   scope, a Unix exact-user scope (its uid), or a legacy import (its uid,
//!   Windows RID included, exactly as stored);
//! - it is live, and has no expiry or expires at or after the document's
//!   `not_after` (an old agent cannot enforce a per-entry expiry).
//!
//! Everything else is left out, which fails closed for that application on
//! old agents only. The body is the ordinary `ferrogate-allowlist-v1`
//! document, byte-compatible with the legacy one. A host the ledger and the
//! legacy store do not know gets an empty answer (as in `legacy` mode, "not
//! provisioned"); a known host always gets a signed body, possibly empty, so
//! a revocation reaches old agents instead of leaving their last file in
//! force.
//!
//! The RPC is public, so signed bodies are cached per host (per node, in
//! memory) and re-signed only when the entry set changes or the body is past
//! half its lifetime, and an unknown or malformed host is answered from this
//! node's replica without a leader round trip (NRM §5.3.5: no heavy work on
//! a public surface).
//! `CMIS_LEGACY_GETALLOWLIST=off` refuses the RPC in both modes
//! (`FAILED_PRECONDITION legacy_getallowlist_disabled`): an old agent keeps
//! its current file until that file's `not_after` and then fails closed.

use std::collections::HashMap;

use ferro_raft::apps::{ApprovalOrigin, LiveApproval, PathMatch, UserKind, UserScope};
use ferro_svid::AllowEntry;
use parking_lot::Mutex;
use tonic::Status;

use super::ledger_status;
use crate::state::CmisState;

/// The refusal while `CMIS_LEGACY_GETALLOWLIST` is off.
pub const LEGACY_GETALLOWLIST_DISABLED: &str = "legacy_getallowlist_disabled";

/// Longest `host_uuid` looked up (a UUID is 36 characters).
const MAX_HOST_UUID: usize = 64;

/// Hosts whose signed v1 body is cached; the cache is cleared when full.
const MAX_CACHED_HOSTS: usize = 16_384;

/// The v1 entry of one live approval for a body valid until `not_after`, or
/// `None` when an old agent could not enforce the approval (see the module
/// docs).
#[must_use]
pub fn v1_entry(live: &LiveApproval, not_after: i64) -> Option<AllowEntry> {
    let a = &live.approval;
    if a.path_match != PathMatch::Any {
        return None;
    }
    if a.expires_at.is_some_and(|t| t < not_after) {
        return None;
    }
    let uid = if a.origin == ApprovalOrigin::LegacyImport {
        match a.uid {
            Some(u) => Some(u32::try_from(u).ok()?),
            None => None,
        }
    } else {
        match (a.user_scope, a.user_kind) {
            (UserScope::AnyUser, _) => None,
            (UserScope::ExactUser, Some(UserKind::Unix)) => Some(u32::try_from(a.uid?).ok()?),
            (UserScope::ExactUser, _) => return None,
        }
    };
    Some(AllowEntry {
        uid,
        bin_sha: a.bin_sha.clone(),
    })
}

/// The lossy-safe v1 entries of a host's live approvals for a body valid
/// until `not_after`, sorted and without duplicates.
#[must_use]
pub fn compile_v1(live: &[LiveApproval], not_after: i64) -> Vec<AllowEntry> {
    let mut entries: Vec<AllowEntry> = live.iter().filter_map(|l| v1_entry(l, not_after)).collect();
    entries.sort_by(|a, b| (a.uid, &a.bin_sha).cmp(&(b.uid, &b.bin_sha)));
    entries.dedup();
    entries
}

#[derive(Debug, Clone)]
struct CachedV1 {
    entries: Vec<AllowEntry>,
    issued_at: i64,
    signed: Vec<u8>,
}

/// Per-node cache of signed v1 bodies (see the module docs).
#[derive(Debug, Default)]
pub struct V1Cache {
    hosts: Mutex<HashMap<String, CachedV1>>,
}

impl V1Cache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached body of `host_uuid` if it carries exactly `entries` and
    /// was signed at most `half_life` seconds ago.
    fn get(
        &self,
        host_uuid: &str,
        entries: &[AllowEntry],
        now: i64,
        half_life: i64,
    ) -> Option<Vec<u8>> {
        let hosts = self.hosts.lock();
        let c = hosts.get(host_uuid)?;
        (c.entries == entries && now >= c.issued_at && now - c.issued_at <= half_life)
            .then(|| c.signed.clone())
    }

    fn put(&self, host_uuid: &str, entries: Vec<AllowEntry>, issued_at: i64, signed: Vec<u8>) {
        let mut hosts = self.hosts.lock();
        if hosts.len() >= MAX_CACHED_HOSTS && !hosts.contains_key(host_uuid) {
            hosts.clear();
        }
        hosts.insert(
            host_uuid.to_string(),
            CachedV1 {
                entries,
                issued_at,
                signed,
            },
        );
    }
}

fn internal(what: &'static str, e: &dyn std::fmt::Display) -> Status {
    tracing::error!(event = "apps.v1.error", what, error = %e, "legacy v1 allowlist compile failed");
    Status::internal("internal")
}

/// The v1 `GetAllowlist` answer for `host_uuid` in `approvals` mode: the
/// signed lossy-safe body, or empty bytes for a host nothing is known about.
///
/// The RPC is public, so an unknown or malformed host costs no leader round
/// trip: a key that is not a canonical host UUID is answered at once, and
/// the "known host" probe reads this node's replica. Only a known host's
/// approvals are read through the leader. Store failures answer
/// `UNAVAILABLE`.
pub async fn serve(state: &CmisState, host_uuid: &str, now: i64) -> Result<Vec<u8>, Status> {
    if host_uuid.len() > MAX_HOST_UUID {
        return Err(Status::invalid_argument("host_uuid too long"));
    }
    // Hosts ask with the canonical (lowercase, hyphenated) UUID; nothing is
    // ever stored under another key in approvals mode.
    if uuid::Uuid::parse_str(host_uuid)
        .map(|u| u.to_string())
        .as_deref()
        != Ok(host_uuid)
    {
        return Ok(Vec::new());
    }
    let cluster = state.cluster();
    if !cluster
        .app_host_known_local(host_uuid)
        .await
        .map_err(ledger_status)?
    {
        return Ok(Vec::new());
    }
    let live = cluster
        .app_live_approvals(host_uuid, now)
        .await
        .map_err(ledger_status)?;
    let ttl = state.config.allowlist_ttl_secs;
    let not_after = now.saturating_add(ttl);
    let entries = compile_v1(&live, not_after);
    let cache = state.legacy_v1_cache();
    if let Some(body) = cache.get(host_uuid, &entries, now, ttl / 2) {
        return Ok(body);
    }
    let signed = state
        .issuer
        .sign_allowlist(entries.clone(), now, not_after)
        .map_err(|e| internal("sign", &e))?;
    let bytes = ferro_svid::allowlist::encode(&signed).map_err(|e| internal("encode", &e))?;
    cache.put(host_uuid, entries, now, bytes.clone());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_raft::apps::{ApprovalRow, ApprovalState, Continuity, UpdatePolicy};

    const NOT_AFTER: i64 = 1_000_000;

    fn live(
        origin: ApprovalOrigin,
        scope: UserScope,
        kind: Option<UserKind>,
        uid: Option<i64>,
        path: PathMatch,
        expires_at: Option<i64>,
    ) -> LiveApproval {
        LiveApproval {
            approval: ApprovalRow {
                approval_id: "00000000-0000-7000-8000-000000000001".into(),
                host_uuid: "h".into(),
                lineage_id: "l".into(),
                bin_sha: "ab".repeat(48),
                revision: Some(1),
                source_request_id: None,
                origin,
                parent_approval_id: None,
                approved_by_admin_id: None,
                user_scope: scope,
                user_kind: kind,
                uid,
                sid: (kind == Some(UserKind::Windows)).then(|| "S-1-5-21-1-2-3-1001".into()),
                user_name: None,
                path_match: path,
                update_policy: UpdatePolicy::ManualEachTime,
                continuity: Continuity::Anchored,
                created_at: 0,
                expires_at,
                state: ApprovalState::Active,
                superseded_by: None,
                revoked_at: None,
                revoked_by_admin_id: None,
                revoke_reason_code: None,
                note: None,
                row_version: 1,
            },
            platform: Some(1),
            path_key: Some(b"/opt/tool".to_vec()),
        }
    }

    #[test]
    fn only_approvals_an_old_agent_can_enforce_are_compiled() {
        use ApprovalOrigin::{LegacyImport, Manual};
        use PathMatch::{Any, Exact};
        use UserScope::{AnyUser, ExactUser};
        let unix = Some(UserKind::Unix);
        let win = Some(UserKind::Windows);
        let sha = "ab".repeat(48);
        let e = |uid: Option<u32>| {
            Some(AllowEntry {
                uid,
                bin_sha: sha.clone(),
            })
        };
        // Included: any path, and a uid an old agent matches (or none).
        assert_eq!(
            v1_entry(
                &live(Manual, ExactUser, unix, Some(1000), Any, None),
                NOT_AFTER
            ),
            e(Some(1000))
        );
        assert_eq!(
            v1_entry(&live(Manual, AnyUser, None, None, Any, None), NOT_AFTER),
            e(None)
        );
        assert_eq!(
            v1_entry(
                &live(LegacyImport, ExactUser, None, Some(1001), Any, None),
                NOT_AFTER
            ),
            e(Some(1001))
        );
        assert_eq!(
            v1_entry(
                &live(LegacyImport, AnyUser, None, None, Any, None),
                NOT_AFTER
            ),
            e(None)
        );
        // Expiring at or after not_after is enforceable by the document itself.
        assert_eq!(
            v1_entry(
                &live(Manual, ExactUser, unix, Some(1), Any, Some(NOT_AFTER)),
                NOT_AFTER
            ),
            e(Some(1))
        );
        // Omitted: a path constraint, a Windows SID, an earlier expiry.
        assert_eq!(
            v1_entry(
                &live(Manual, ExactUser, unix, Some(1000), Exact, None),
                NOT_AFTER
            ),
            None
        );
        assert_eq!(
            v1_entry(
                &live(Manual, ExactUser, win, Some(1001), Any, None),
                NOT_AFTER
            ),
            None
        );
        assert_eq!(
            v1_entry(
                &live(
                    Manual,
                    ExactUser,
                    unix,
                    Some(1000),
                    Any,
                    Some(NOT_AFTER - 1)
                ),
                NOT_AFTER
            ),
            None
        );
        assert_eq!(
            v1_entry(
                &live(Manual, ExactUser, unix, Some(-1), Any, None),
                NOT_AFTER
            ),
            None
        );
    }

    #[test]
    fn the_compile_is_sorted_and_deduplicated() {
        let a = live(
            ApprovalOrigin::Manual,
            UserScope::ExactUser,
            Some(UserKind::Unix),
            Some(2),
            PathMatch::Any,
            None,
        );
        let b = live(
            ApprovalOrigin::Manual,
            UserScope::AnyUser,
            None,
            None,
            PathMatch::Any,
            None,
        );
        let entries = compile_v1(&[a.clone(), b, a], NOT_AFTER);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].uid, None);
        assert_eq!(entries[1].uid, Some(2));
    }

    #[test]
    fn the_cache_serves_only_the_same_entries_within_half_life() {
        let cache = V1Cache::new();
        let entries = vec![AllowEntry {
            uid: Some(1),
            bin_sha: "*".into(),
        }];
        cache.put("h", entries.clone(), 100, vec![1, 2, 3]);
        assert_eq!(cache.get("h", &entries, 150, 50), Some(vec![1, 2, 3]));
        assert_eq!(cache.get("h", &entries, 151, 50), None, "past half-life");
        assert_eq!(cache.get("h", &[], 120, 50), None, "other entries");
        assert_eq!(cache.get("other", &entries, 120, 50), None);
    }
}
