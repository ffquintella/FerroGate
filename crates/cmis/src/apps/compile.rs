//! Per-host allowlist v2: compile, generation and cache, serve (F19 §6.1–§6.3).
//!
//! **Compile.** In `approvals` mode every active, unexpired approval of the
//! host becomes one `AllowEntryV2`: the approval id, the hash, the uid
//! (Unix exact-user, and legacy imports), the `sid_hash` (Windows
//! exact-user), the `path_hash` (exact path) and the expiry. In `legacy` mode
//! the entries come from the host's stored v1 body, with a zero approval id.
//! No personal data enters the body: paths and SIDs only as host-salted
//! hashes.
//!
//! **Generation.** The ledger bumps a host's generation to
//! `max(generation + 1, unix_millis)` in every transaction that changes its
//! approvals, and clears the cached body. Serving compiles the entry set
//! anew on every call (a cheap read) and compares its digest with the one
//! recorded for the current generation; a different digest — an approval
//! that expired by time, a changed legacy body — moves the generation on
//! before anything is signed. Two bodies with one generation therefore
//! always carry the same entries, and generations never go backwards (a
//! database trigger refuses a decrease), which is what MIA's rollback and
//! `generation_conflict` checks rely on.
//!
//! **Serve.** A host that already holds the current generation gets
//! `not_modified` while the cached body has more than half its lifetime
//! left. Otherwise it gets the cached body, or a body signed now (at the
//! same generation when only the window moved) and cached for the next
//! caller. Every node holds the replicated issuer key, so any node can sign;
//! the compare-and-set on the generation keeps concurrent signers
//! consistent.

use ferro_raft::apps::{ApprovalOrigin, LiveApproval, PathMatch, UserKind, UserScope};
use ferro_svid::allowlist_v2::{entries_digest, path_hash, sid_hash, sort_entries, AllowEntryV2};
use tonic::Status;

use super::mode::{self, AllowlistMode};
use super::{events, ledger_status, now_millis};
use crate::service::audit_record;
use crate::state::CmisState;

/// Attempts before giving up on a generation that keeps moving.
const ATTEMPTS: usize = 4;

/// What `SyncAllowlist` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Served {
    /// The host already holds `generation`.
    NotModified {
        /// Current generation.
        generation: u64,
        /// `not_after` of the cached body.
        not_after: i64,
    },
    /// A signed v2 body (CBOR `SignedAllowlist` envelope).
    Body {
        /// Generation of the body.
        generation: u64,
        /// The envelope bytes.
        signed: Vec<u8>,
        /// `not_after` of the body.
        not_after: i64,
    },
}

fn internal(what: &'static str, e: &dyn std::fmt::Display) -> Status {
    tracing::error!(event = "apps.compile.error", what, error = %e, "allowlist v2 compile failed");
    Status::internal("internal")
}

/// The v2 entry of one live approval, or `None` (logged) when the approval
/// lacks what its scope needs — the entry is left out, which fails closed
/// for that application only.
#[must_use]
pub fn entry_of(host_uuid: &str, live: &LiveApproval) -> Option<AllowEntryV2> {
    let a = &live.approval;
    let skip = |why: &'static str| {
        tracing::error!(event = "apps.compile.entry_skipped", approval_id = %a.approval_id, why, "approval left out of the allowlist");
    };
    let Ok(id) = uuid::Uuid::parse_str(&a.approval_id) else {
        skip("approval_id");
        return None;
    };
    let uid_u32 = |uid: Option<i64>| uid.and_then(|u| u32::try_from(u).ok());
    let (uid, user_sid_hash) = if a.origin == ApprovalOrigin::LegacyImport {
        (uid_u32(a.uid), None)
    } else if a.user_scope == UserScope::ExactUser {
        match a.user_kind {
            Some(UserKind::Unix) => {
                let Some(u) = uid_u32(a.uid) else {
                    skip("uid");
                    return None;
                };
                (Some(u), None)
            }
            Some(UserKind::Windows) => match a.sid.as_deref() {
                Some(sid) if !sid.is_empty() => (None, Some(sid_hash(host_uuid, sid))),
                _ => {
                    skip("sid");
                    return None;
                }
            },
            None => {
                skip("user_kind");
                return None;
            }
        }
    } else {
        (None, None)
    };
    let path_hash = match a.path_match {
        PathMatch::Any => None,
        PathMatch::Exact => match live.path_key.as_deref() {
            Some(key) if !key.is_empty() => Some(path_hash(host_uuid, key)),
            _ => {
                skip("path_key");
                return None;
            }
        },
    };
    Some(AllowEntryV2 {
        approval_id: *id.as_bytes(),
        bin_sha: a.bin_sha.clone(),
        uid,
        user_sid_hash,
        path_hash,
        expires_at: a.expires_at,
    })
}

/// The v2 entries of a host's live approvals, in canonical order.
#[must_use]
pub fn compile_approvals(host_uuid: &str, live: &[LiveApproval]) -> Vec<AllowEntryV2> {
    let mut entries: Vec<AllowEntryV2> =
        live.iter().filter_map(|l| entry_of(host_uuid, l)).collect();
    sort_entries(&mut entries);
    entries
}

/// The v2 entries of a stored legacy v1 body (F19 §11 step 2): one entry per
/// v1 entry, approval id zero, no path, SID or expiry constraint.
pub fn compile_legacy(stored: &[u8]) -> Result<Vec<AllowEntryV2>, Status> {
    let doc = ferro_svid::allowlist::decode(stored)
        .and_then(|s| ferro_svid::allowlist::decode_body(&s.body))
        .map_err(|e| internal("legacy_body", &e))?;
    let mut entries: Vec<AllowEntryV2> = doc
        .entries
        .into_iter()
        .map(|e| AllowEntryV2 {
            approval_id: [0; 16],
            bin_sha: e.bin_sha,
            uid: e.uid,
            user_sid_hash: None,
            path_hash: None,
            expires_at: None,
        })
        .collect();
    sort_entries(&mut entries);
    Ok(entries)
}

/// The entry set of `host_uuid` at `now` under `mode`.
pub async fn entries(
    state: &CmisState,
    mode: AllowlistMode,
    host_uuid: &str,
    now: i64,
) -> Result<Vec<AllowEntryV2>, Status> {
    match mode {
        AllowlistMode::Approvals => {
            let live = state
                .cluster()
                .app_live_approvals(host_uuid, now)
                .await
                .map_err(ledger_status)?;
            Ok(compile_approvals(host_uuid, &live))
        }
        AllowlistMode::Legacy => {
            let stored = state
                .cluster()
                .fetch_allowlist_consistent(host_uuid)
                .await
                .map_err(|e| ledger_status(e.into()))?;
            stored.map_or_else(|| Ok(Vec::new()), |b| compile_legacy(&b))
        }
    }
}

/// Sign `entries` for `host_uuid` at `generation` with a fresh window and
/// cache the body. A failed cache write is logged; the signed body is still
/// correct and is served.
async fn sign_and_cache(
    state: &CmisState,
    host_uuid: &str,
    generation: u64,
    entries: Vec<AllowEntryV2>,
    now: i64,
) -> Result<Served, Status> {
    let not_after = now.saturating_add(state.config.allowlist_ttl_secs);
    let signed = state
        .issuer
        .sign_allowlist_v2(host_uuid, generation, entries, now, not_after)
        .map_err(|e| internal("sign", &e))?;
    let bytes = ferro_svid::allowlist::encode(&signed).map_err(|e| internal("encode", &e))?;
    match state
        .cluster()
        .app_cache_signed_allowlist(host_uuid, generation, &bytes, not_after)
        .await
    {
        Ok(true) => {}
        Ok(false) => tracing::debug!(%host_uuid, generation, "generation moved; body not cached"),
        Err(e) => {
            tracing::error!(event = "apps.compile.cache_failed", error = %e, %host_uuid, "allowlist cache write failed");
        }
    }
    Ok(Served::Body {
        generation,
        signed: bytes,
        not_after,
    })
}

/// Serve `host_uuid`'s allowlist v2 to a host holding `have_generation`
/// (see the module docs).
pub async fn serve(
    state: &CmisState,
    host_uuid: &str,
    have_generation: u64,
    now: i64,
) -> Result<Served, Status> {
    let cluster = state.cluster();
    let mode = mode::current(cluster)
        .await
        .map_err(|e| ledger_status(e.into()))?;
    let half_life = state.config.allowlist_ttl_secs / 2;
    for _ in 0..ATTEMPTS {
        let Some(st) = cluster
            .app_allowlist_state(host_uuid)
            .await
            .map_err(ledger_status)?
        else {
            // First sync of a host that never had a change: start its
            // generation, then compile.
            cluster
                .app_bump_generation(host_uuid, now_millis(now), now)
                .await
                .map_err(ledger_status)?;
            continue;
        };
        let entries = entries(state, mode, host_uuid, now).await?;
        let digest = entries_digest(&entries).map_err(|e| internal("digest", &e))?;
        if st.entries_digest == digest {
            if let (Some(body), Some(not_after)) = (&st.cached_v2, st.cached_not_after) {
                if not_after.saturating_sub(now) > half_life {
                    if have_generation == st.generation {
                        return Ok(Served::NotModified {
                            generation: st.generation,
                            not_after,
                        });
                    }
                    return Ok(Served::Body {
                        generation: st.generation,
                        signed: body.clone(),
                        not_after,
                    });
                }
            }
            // Same entries, no fresh body: only the window moves.
            return sign_and_cache(state, host_uuid, st.generation, entries, now).await;
        }
        // The entry set differs from the one recorded for this generation.
        // `None`: the generation moved concurrently; compile again.
        if let Some(generation) = cluster
            .app_record_compiled_digest(host_uuid, st.generation, &digest, now_millis(now), now)
            .await
            .map_err(ledger_status)?
        {
            audit_record(
                state,
                events::compiled(host_uuid, generation, entries.len(), digest),
                now,
            );
            tracing::info!(event = "apps.allowlist.compiled", %host_uuid, generation, entry_count = entries.len(), "allowlist v2 compiled");
            return sign_and_cache(state, host_uuid, generation, entries, now).await;
        }
    }
    tracing::warn!(%host_uuid, "allowlist generation kept moving; giving up for now");
    Err(Status::aborted("concurrent_change"))
}
