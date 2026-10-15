//! Administrator operations on application requests and approvals (F19 §5.4,
//! §7.5), served by the `Admin` service.
//!
//! Every handler first re-checks the [`AdminContext`] the layer inserted
//! ([`require`], deny by default); decisions and edits also passed the
//! layer's step-up check. On top of that:
//!
//! - **Separation of duties.** With `CMIS_ADMIN_STRICT_SOD` on nobody
//!   decides a request they registered (`PERMISSION_DENIED
//!   sod_self_approval`, also enforced in the ledger transaction). With it
//!   off, approving one's own `admin_direct` request needs a fresh second
//!   factor and is audited as `AppApprovedBySameActor`.
//! - **Single-step direct registration** needs `app.direct_register` and
//!   `app_request.approve` (strict policy off) and a per-operation `MfaProof`
//!   verified before anything is written; a missing or wrong proof changes
//!   nothing.
//! - **Terms.** Expiry defaults to `CMIS_APPROVAL_DEFAULT_TTL_SECS`, may not
//!   exceed `CMIS_APPROVAL_MAX_TTL_SECS`, and "no expiry" needs
//!   `CMIS_APPROVAL_ALLOW_NO_EXPIRY`. `any_user` needs an explicit
//!   confirmation and combines with `AutoSamePathUser` only for a binary on
//!   a protected path.
//! - **Audit.** Each mutation emits exactly one F19 §9 event (plus one
//!   `ApprovalRevoked` per approval revoked alongside an approval), only
//!   after the ledger committed; a store failure answers `UNAVAILABLE
//!   store_unavailable` and audits nothing.
//!
//! Free text (notes, denial messages, reasons) is bounded and may not carry
//! control characters, so it cannot smuggle terminal escapes into the admin
//! clients. Retries are safe: a repeated decision finds the request no
//! longer pending (`invalid_state`), a repeated edit a moved `row_version`,
//! and a repeated direct registration (same `idempotency_key`) returns the
//! stored outcome.

use subtle::ConstantTimeEq;
use tonic::{Request, Response, Status};

use ferro_proto::admin_v1::{
    approve_app_request_request::Choice, AdminRegisterApplicationRequest,
    AdminRegisterApplicationResponse, AppBinaryDesc, AppBinaryInfo, AppRequestInfo, AppUser,
    ApprovalInfo, ApprovalRevisionInfo, ApprovalTerms as WireTerms, ApprovalTermsSnapshot,
    ApproveAppRequestRequest, ApproveAppRequestResponse, DenyAppRequestRequest,
    DenyAppRequestResponse, GetAppRequestRequest, GetAppRequestResponse, GetApprovalRequest,
    GetApprovalResponse, ListAppRequestsRequest, ListAppRequestsResponse, ListApprovalsRequest,
    ListApprovalsResponse, PageRequest, RevokeApprovalRequest, RevokeApprovalResponse,
    SetLineageAutoUpdateFrozenRequest, SetLineageAutoUpdateFrozenResponse, UpdateApprovalRequest,
    UpdateApprovalResponse,
};
use ferro_raft::apps::{
    ApprovalChoice, ApprovalEdit, ApprovalFilter, ApprovalOrigin, ApprovalRevisionRow, ApprovalRow,
    ApprovalSnapshot, ApprovalState, ApprovalTerms, Approve, BinaryRow, Continuity, Cursor, Deny,
    Intake, IntakeChecks, PathMatch, RequestFilter, RequestKind, RequestOrigin, RequestRow,
    RequestState, Revoke, UpdatePolicy, UserIdentity, UserKind, UserScope, FLAG_PATH_PROTECTED,
    MAX_PAGE_SIZE,
};
use ferro_raft::Cluster;

use super::authz::{access_for, paths, require, Access, AdminAuthz, AdminContext, Permission};
use super::codec::{b64url, b64url_decode};
use super::state::AdminState;
use crate::apps::intake::{self, BinaryFacts, Submission};
use crate::apps::{events, ledger_status, new_id, now_millis, AppConfig};
use crate::host_auth::{invalid_field, TIER_HOST_KEY, TIER_TPM};

/// Default page size of the listings (the ledger's default).
const DEFAULT_PAGE_SIZE: u32 = 50;
/// Longest page token accepted.
const MAX_PAGE_TOKEN: usize = 512;
/// Longest `idempotency_key` accepted.
const MAX_IDEMPOTENCY_KEY: usize = 128;
/// Prefix of the `client_request_id` of a direct registration, so it can
/// never collide with a host's UUID ids.
const ADMIN_CLIENT_ID_PREFIX: &str = "adm:";

// ---- validation ------------------------------------------------------------------

/// An id from the wire: non-empty, at most 64 printable ASCII characters.
fn check_id(v: &str, field: &'static str) -> Result<(), Status> {
    if v.is_empty() || v.len() > 64 || !v.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid_field("bad_value", Some(field)));
    }
    Ok(())
}

fn check_idempotency(key: &str) -> Result<(), Status> {
    if key.len() > MAX_IDEMPOTENCY_KEY {
        return Err(invalid_field("field_too_long", Some("idempotency_key")));
    }
    Ok(())
}

/// Bounded free text without control characters; empty is `None`.
fn free_text(v: &str, max_chars: usize, field: &'static str) -> Result<Option<String>, Status> {
    if v.chars().any(char::is_control) {
        return Err(invalid_field("bad_value", Some(field)));
    }
    if v.chars().count() > max_chars {
        return Err(invalid_field("field_too_long", Some(field)));
    }
    Ok((!v.is_empty()).then(|| v.to_string()))
}

fn code_of<T>(
    v: u32,
    default: T,
    from: fn(i64) -> Option<T>,
    field: &'static str,
) -> Result<T, Status> {
    if v == 0 {
        return Ok(default);
    }
    from(i64::from(v)).ok_or_else(|| invalid_field("bad_value", Some(field)))
}

fn codes<T>(vs: &[u32], from: fn(i64) -> Option<T>, field: &'static str) -> Result<Vec<T>, Status> {
    vs.iter()
        .map(|v| from(i64::from(*v)).ok_or_else(|| invalid_field("bad_value", Some(field))))
        .collect()
}

fn nonzero_reason(code: u32, field: &'static str) -> Result<i64, Status> {
    if code == 0 {
        return Err(invalid_field("missing", Some(field)));
    }
    Ok(i64::from(code))
}

fn opt_str(v: &str) -> Option<String> {
    (!v.is_empty()).then(|| v.to_string())
}

fn opt_time(v: i64) -> Option<i64> {
    (v != 0).then_some(v)
}

/// Resolve an approver's expiry choice (F19 §5.4 "Expiry rules").
pub fn resolve_expiry(
    expires_at: i64,
    no_expiry: bool,
    cfg: &AppConfig,
    now: i64,
) -> Result<Option<i64>, Status> {
    if no_expiry {
        if !cfg.allow_no_expiry {
            return Err(invalid_field("no_expiry_not_allowed", Some("expires_at")));
        }
        return Ok(None);
    }
    if expires_at == 0 {
        return Ok(Some(now.saturating_add(cfg.approval_default_ttl_secs)));
    }
    if expires_at <= now {
        return Err(invalid_field("expiry_in_past", Some("expires_at")));
    }
    if expires_at > now.saturating_add(cfg.approval_max_ttl_secs) {
        return Err(invalid_field("expiry_too_far", Some("expires_at")));
    }
    Ok(Some(expires_at))
}

/// The `any_user` + `AutoSamePathUser` rule (F19 §5.3 #4, §5.4): auto-update
/// for every user of the host only for a binary on a protected path.
fn check_wide_auto(scope: UserScope, policy: UpdatePolicy, flags: u32) -> Result<(), Status> {
    if scope == UserScope::AnyUser
        && policy == UpdatePolicy::AutoSamePathUser
        && flags & FLAG_PATH_PROTECTED == 0
    {
        return Err(invalid_field(
            "any_user_needs_protected_path",
            Some("terms.user_scope"),
        ));
    }
    Ok(())
}

/// The ledger terms of an approver's choice for a request with `flags`.
fn terms(t: &WireTerms, flags: u32, cfg: &AppConfig, now: i64) -> Result<ApprovalTerms, Status> {
    let user_scope = code_of(
        t.user_scope,
        UserScope::ExactUser,
        UserScope::from_code,
        "terms.user_scope",
    )?;
    let path_match = code_of(
        t.path_match,
        PathMatch::Exact,
        PathMatch::from_code,
        "terms.path_match",
    )?;
    let update_policy = code_of(
        t.update_policy,
        UpdatePolicy::ManualEachTime,
        UpdatePolicy::from_code,
        "terms.update_policy",
    )?;
    let continuity = code_of(
        t.continuity,
        Continuity::Anchored,
        Continuity::from_code,
        "terms.continuity",
    )?;
    if user_scope == UserScope::AnyUser && !t.confirm_any_user {
        return Err(invalid_field(
            "confirmation_required",
            Some("terms.confirm_any_user"),
        ));
    }
    check_wide_auto(user_scope, update_policy, flags)?;
    Ok(ApprovalTerms {
        user_scope,
        path_match,
        update_policy,
        continuity,
        expires_at: resolve_expiry(t.expires_at, t.no_expiry, cfg, now)?,
        note: free_text(&t.note, 500, "terms.note")?,
    })
}

// ---- wire conversions -------------------------------------------------------------

fn code32(c: i64) -> u32 {
    u32::try_from(c).unwrap_or(0)
}

fn user(
    kind: Option<UserKind>,
    uid: Option<i64>,
    sid: Option<&str>,
    name: Option<&str>,
) -> AppUser {
    AppUser {
        kind: kind.map_or(0, |k| code32(k.code())),
        uid,
        sid: sid.unwrap_or_default().to_string(),
        name: name.unwrap_or_default().to_string(),
    }
}

fn display_version(declared: Option<&str>, revision: i64) -> String {
    ferro_appid::display_version(declared, u32::try_from(revision).unwrap_or(0))
}

fn request_info(
    r: &RequestRow,
    path: Option<&str>,
    declared_version: Option<&str>,
    product_name: Option<&str>,
) -> AppRequestInfo {
    AppRequestInfo {
        request_id: r.request_id.clone(),
        host_uuid: r.host_uuid.clone(),
        lineage_id: r.lineage_id.clone(),
        canonical_path: path.unwrap_or_default().to_string(),
        bin_sha: r.bin_sha.clone(),
        revision: code32(r.revision),
        kind: code32(r.kind.code()),
        origin: code32(r.origin.code()),
        target_user: Some(user(
            Some(r.target.kind),
            r.target.uid,
            r.target.sid.as_deref(),
            r.target.user_name.as_deref(),
        )),
        requester_uid: r.requester_uid,
        requester_user_name: r.requester_user_name.clone().unwrap_or_default(),
        requested_by_admin_id: r.requested_by_admin_id.clone().unwrap_or_default(),
        reason: r.reason.clone().unwrap_or_default(),
        flags: r.flags,
        host_tier: r.host_tier.clone(),
        submitted_at: r.submitted_at,
        pending_expires_at: r.pending_expires_at,
        state: code32(r.state.code()),
        decided_at: r.decided_at.unwrap_or_default(),
        decided_by_admin_id: r.decided_by_admin_id.clone().unwrap_or_default(),
        decision_reason_code: code32(r.decision_reason_code.unwrap_or_default()),
        decision_message: r.decision_message.clone().unwrap_or_default(),
        auto_downgrade_reason: r
            .auto_downgrade_reason
            .map(|a| a.as_str().to_string())
            .unwrap_or_default(),
        resulting_approval_id: r.resulting_approval_id.clone().unwrap_or_default(),
        same_actor_approved: r.same_actor_approved,
        declared_version: declared_version.unwrap_or_default().to_string(),
        product_name: product_name.unwrap_or_default().to_string(),
        display_version: display_version(declared_version, r.revision),
    }
}

fn approval_info(
    a: &ApprovalRow,
    path: Option<&str>,
    declared_version: Option<&str>,
    product_name: Option<&str>,
) -> ApprovalInfo {
    ApprovalInfo {
        approval_id: a.approval_id.clone(),
        host_uuid: a.host_uuid.clone(),
        lineage_id: a.lineage_id.clone(),
        canonical_path: path.unwrap_or_default().to_string(),
        bin_sha: a.bin_sha.clone(),
        revision: code32(a.revision.unwrap_or_default()),
        source_request_id: a.source_request_id.clone().unwrap_or_default(),
        origin: code32(a.origin.code()),
        parent_approval_id: a.parent_approval_id.clone().unwrap_or_default(),
        approved_by_admin_id: a.approved_by_admin_id.clone().unwrap_or_default(),
        user_scope: code32(a.user_scope.code()),
        user: Some(user(
            a.user_kind,
            a.uid,
            a.sid.as_deref(),
            a.user_name.as_deref(),
        )),
        path_match: code32(a.path_match.code()),
        update_policy: code32(a.update_policy.code()),
        continuity: code32(a.continuity.code()),
        created_at: a.created_at,
        expires_at: a.expires_at.unwrap_or_default(),
        state: code32(a.state.code()),
        superseded_by: a.superseded_by.clone().unwrap_or_default(),
        revoked_at: a.revoked_at.unwrap_or_default(),
        revoked_by_admin_id: a.revoked_by_admin_id.clone().unwrap_or_default(),
        revoke_reason_code: code32(a.revoke_reason_code.unwrap_or_default()),
        note: a.note.clone().unwrap_or_default(),
        row_version: u64::try_from(a.row_version).unwrap_or(0),
        declared_version: declared_version.unwrap_or_default().to_string(),
        product_name: product_name.unwrap_or_default().to_string(),
    }
}

fn binary_info(b: &BinaryRow) -> AppBinaryInfo {
    AppBinaryInfo {
        bin_sha: b.bin_sha.clone(),
        revision: code32(b.revision),
        file_size: u64::try_from(b.file_size).unwrap_or(0),
        format: code32(b.format),
        declared_version: b.declared_version.clone().unwrap_or_default(),
        version_source: code32(b.version_source),
        product_name: b.product_name.clone().unwrap_or_default(),
        bundle_id: b.bundle_id.clone().unwrap_or_default(),
        package_name: b.package_name.clone().unwrap_or_default(),
        signer_kind: code32(b.signer_kind),
        signer_id: b.signer_id.clone().unwrap_or_default(),
        signer_subject: b.signer_subject.clone().unwrap_or_default(),
        signer_valid: b.signer_valid,
        first_seen_at: b.first_seen_at,
        display_version: display_version(b.declared_version.as_deref(), b.revision),
    }
}

fn snapshot(bytes: Option<&[u8]>) -> Option<ApprovalTermsSnapshot> {
    let s = ApprovalSnapshot::from_cbor(bytes?).ok()?;
    Some(ApprovalTermsSnapshot {
        state: code32(s.state),
        update_policy: code32(s.update_policy),
        continuity: code32(s.continuity),
        expires_at: s.expires_at.unwrap_or_default(),
        user_scope: code32(s.user_scope),
        path_match: code32(s.path_match),
        revoke_reason_code: code32(s.revoke_reason_code.unwrap_or_default()),
    })
}

fn revision_info(r: &ApprovalRevisionRow) -> ApprovalRevisionInfo {
    ApprovalRevisionInfo {
        row_version: u64::try_from(r.row_version).unwrap_or(0),
        changed_at: r.changed_at,
        changed_by_admin_id: r.changed_by_admin_id.clone().unwrap_or_default(),
        change_kind: code32(r.change_kind.code()),
        before: snapshot(r.before_cbor.as_deref()),
        after: snapshot(Some(&r.after_cbor)),
    }
}

/// An approval with its lineage path and binary metadata.
async fn approval_full(cluster: &Cluster, a: &ApprovalRow) -> Result<ApprovalInfo, Status> {
    let path = cluster
        .app_lineage(&a.lineage_id)
        .await
        .map_err(ledger_status)?
        .map(|l| l.canonical_path);
    let binary = cluster
        .app_binary(&a.lineage_id, &a.bin_sha)
        .await
        .map_err(ledger_status)?;
    Ok(approval_info(
        a,
        path.as_deref(),
        binary.as_ref().and_then(|b| b.declared_version.as_deref()),
        binary.as_ref().and_then(|b| b.product_name.as_deref()),
    ))
}

/// A request with its lineage path and binary metadata.
async fn request_full(cluster: &Cluster, r: &RequestRow) -> Result<AppRequestInfo, Status> {
    let path = cluster
        .app_lineage(&r.lineage_id)
        .await
        .map_err(ledger_status)?
        .map(|l| l.canonical_path);
    let binary = cluster
        .app_binary(&r.lineage_id, &r.bin_sha)
        .await
        .map_err(ledger_status)?;
    Ok(request_info(
        r,
        path.as_deref(),
        binary.as_ref().and_then(|b| b.declared_version.as_deref()),
        binary.as_ref().and_then(|b| b.product_name.as_deref()),
    ))
}

/// An exact-path scope needs a lineage with a real path: a legacy import has
/// no lineage, and a pre-F19 proposal only a placeholder
/// ([`crate::apps::proposals`]); an exact path there would never match
/// (`INVALID_ARGUMENT path_unknown` on `field`).
async fn require_known_path(
    cluster: &Cluster,
    lineage_id: &str,
    field: &'static str,
) -> Result<(), Status> {
    match cluster
        .app_lineage(lineage_id)
        .await
        .map_err(ledger_status)?
    {
        Some(l) if !crate::apps::proposals::is_unknown_path(&l) => Ok(()),
        _ => Err(invalid_field("path_unknown", Some(field))),
    }
}

async fn generation(cluster: &Cluster, host_uuid: &str) -> Result<u64, Status> {
    Ok(cluster
        .app_allowlist_state(host_uuid)
        .await
        .map_err(ledger_status)?
        .map_or(0, |s| s.generation))
}

// ---- page tokens -------------------------------------------------------------------

/// An opaque cursor: `b64url(kind|order|at|id) . mac`, the MAC keyed with the
/// deployment's pseudonymisation key, so a client can neither forge a
/// position nor reuse a token across listings or orders.
fn page_token(st: &AdminState, kind: &str, ascending: bool, c: &Cursor) -> String {
    let payload = format!("{kind}|{}|{}|{}", u8::from(ascending), c.at, c.id);
    let mac = st.keys().pseudonym("app-page-token-v1", payload.as_bytes());
    format!("{}.{mac}", b64url(payload.as_bytes()))
}

fn page_cursor(
    st: &AdminState,
    kind: &str,
    ascending: bool,
    page: Option<&PageRequest>,
) -> Result<(u32, Option<Cursor>), Status> {
    let bad = || invalid_field("bad_value", Some("page.page_token"));
    let size = page.map_or(0, |p| p.page_size);
    if size > MAX_PAGE_SIZE {
        return Err(invalid_field("bad_value", Some("page.page_size")));
    }
    let token = page.map_or("", |p| p.page_token.as_str());
    if token.is_empty() {
        return Ok((size, None));
    }
    if token.len() > MAX_PAGE_TOKEN {
        return Err(bad());
    }
    let (body, mac) = token.split_once('.').ok_or_else(bad)?;
    let payload = String::from_utf8(b64url_decode(body).ok_or_else(bad)?).map_err(|_| bad())?;
    let want = st.keys().pseudonym("app-page-token-v1", payload.as_bytes());
    if !bool::from(want.as_bytes().ct_eq(mac.as_bytes())) {
        return Err(bad());
    }
    let mut parts = payload.splitn(4, '|');
    let (Some(k), Some(order), Some(at), Some(id)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    if k != kind || order != (if ascending { "1" } else { "0" }) {
        return Err(bad());
    }
    let at: i64 = at.parse().map_err(|_| bad())?;
    Ok((
        size,
        Some(Cursor {
            at,
            id: id.to_string(),
        }),
    ))
}

fn next_token<T>(
    st: &AdminState,
    kind: &str,
    ascending: bool,
    size: u32,
    items: &[T],
    cursor_of: impl Fn(&T) -> Cursor,
) -> String {
    let effective = if size == 0 { DEFAULT_PAGE_SIZE } else { size };
    match items.last() {
        Some(last) if items.len() >= effective as usize => {
            page_token(st, kind, ascending, &cursor_of(last))
        }
        _ => String::new(),
    }
}

// ---- listings and reads -----------------------------------------------------------

/// `ListAppRequests` (`app_request.list`).
pub async fn list_app_requests(
    authz: &AdminAuthz,
    request: Request<ListAppRequestsRequest>,
) -> Result<Response<ListAppRequestsResponse>, Status> {
    require(&request, paths::LIST_APP_REQUESTS)?;
    let st = authz.state();
    let r = request.into_inner();
    let (page_size, after) = page_cursor(st, "req", r.ascending, r.page.as_ref())?;
    let filter = RequestFilter {
        states: codes(&r.states, RequestState::from_code, "states")?,
        host_uuids: opt_str(&r.host_uuid).into_iter().collect(),
        path_contains: opt_str(&r.path_contains),
        product_contains: opt_str(&r.product_contains),
        user_name: opt_str(&r.user_name),
        declared_version: opt_str(&r.declared_version),
        bin_sha_prefix: opt_str(&r.bin_sha_prefix),
        origins: codes(&r.origins, RequestOrigin::from_code, "origins")?,
        kinds: codes(&r.kinds, RequestKind::from_code, "kinds")?,
        flags_any: r.flags_any,
        submitted_after: opt_time(r.submitted_after),
        submitted_before: opt_time(r.submitted_before),
        text: opt_str(&r.text),
        ascending: r.ascending,
        page_size,
        after,
    };
    let rows = st
        .cluster()
        .app_list_requests(&filter)
        .await
        .map_err(ledger_status)?;
    let next_page_token = next_token(st, "req", r.ascending, page_size, &rows, |i| Cursor {
        at: i.request.submitted_at,
        id: i.request.request_id.clone(),
    });
    let items = rows
        .iter()
        .map(|i| {
            request_info(
                &i.request,
                Some(&i.canonical_path),
                i.declared_version.as_deref(),
                i.product_name.as_deref(),
            )
        })
        .collect();
    Ok(Response::new(ListAppRequestsResponse {
        items,
        next_page_token,
    }))
}

/// `GetAppRequest` (`app_request.read`): the request, its binary, and the
/// lineage history.
pub async fn get_app_request(
    authz: &AdminAuthz,
    request: Request<GetAppRequestRequest>,
) -> Result<Response<GetAppRequestResponse>, Status> {
    require(&request, paths::GET_APP_REQUEST)?;
    let st = authz.state();
    let id = request.into_inner().request_id;
    check_id(&id, "request_id")?;
    let cluster = st.cluster();
    let r = cluster
        .app_request(&id)
        .await
        .map_err(ledger_status)?
        .ok_or_else(|| Status::not_found("not_found"))?;
    let lineage = cluster
        .app_lineage(&r.lineage_id)
        .await
        .map_err(ledger_status)?;
    let path = lineage.as_ref().map(|l| l.canonical_path.as_str());
    let binaries = cluster
        .app_binaries_of(&r.lineage_id)
        .await
        .map_err(ledger_status)?;
    let meta = |sha: &str| binaries.iter().find(|b| b.bin_sha == sha);
    let info = |row: &RequestRow| {
        let b = meta(&row.bin_sha);
        request_info(
            row,
            path,
            b.and_then(|b| b.declared_version.as_deref()),
            b.and_then(|b| b.product_name.as_deref()),
        )
    };
    let requests = cluster
        .app_requests_of_lineage(&r.lineage_id)
        .await
        .map_err(ledger_status)?;
    let approvals = cluster
        .app_approvals_of_lineage(&r.lineage_id)
        .await
        .map_err(ledger_status)?;
    Ok(Response::new(GetAppRequestResponse {
        request: Some(info(&r)),
        binary: meta(&r.bin_sha).map(binary_info),
        lineage_binaries: binaries.iter().map(binary_info).collect(),
        lineage_requests: requests.iter().map(info).collect(),
        lineage_approvals: approvals
            .iter()
            .map(|a| {
                let b = meta(&a.bin_sha);
                approval_info(
                    a,
                    path,
                    b.and_then(|b| b.declared_version.as_deref()),
                    b.and_then(|b| b.product_name.as_deref()),
                )
            })
            .collect(),
        lineage_auto_update_frozen: lineage.is_some_and(|l| l.auto_update_frozen),
    }))
}

/// `ListApprovals` (`approval.list`).
pub async fn list_approvals(
    authz: &AdminAuthz,
    request: Request<ListApprovalsRequest>,
) -> Result<Response<ListApprovalsResponse>, Status> {
    require(&request, paths::LIST_APPROVALS)?;
    let st = authz.state();
    let r = request.into_inner();
    let (page_size, after) = page_cursor(st, "apr", r.ascending, r.page.as_ref())?;
    let filter = ApprovalFilter {
        states: codes(&r.states, ApprovalState::from_code, "states")?,
        host_uuids: opt_str(&r.host_uuid).into_iter().collect(),
        lineage_id: opt_str(&r.lineage_id),
        path_contains: opt_str(&r.path_contains),
        product_contains: opt_str(&r.product_contains),
        user_name: opt_str(&r.user_name),
        declared_version: opt_str(&r.declared_version),
        bin_sha_prefix: opt_str(&r.bin_sha_prefix),
        policies: codes(&r.policies, UpdatePolicy::from_code, "policies")?,
        approval_origins: codes(
            &r.approval_origins,
            ApprovalOrigin::from_code,
            "approval_origins",
        )?,
        expires_before: opt_time(r.expires_before),
        expires_after: opt_time(r.expires_after),
        created_after: opt_time(r.created_after),
        created_before: opt_time(r.created_before),
        include_superseded: r.include_superseded,
        legacy_only: r.legacy_only,
        no_expiry_only: r.no_expiry_only,
        text: opt_str(&r.text),
        ascending: r.ascending,
        page_size,
        after,
    };
    let rows = st
        .cluster()
        .app_list_approvals(&filter)
        .await
        .map_err(ledger_status)?;
    let next_page_token = next_token(st, "apr", r.ascending, page_size, &rows, |i| Cursor {
        at: i.approval.created_at,
        id: i.approval.approval_id.clone(),
    });
    let items = rows
        .iter()
        .map(|i| {
            approval_info(
                &i.approval,
                i.canonical_path.as_deref(),
                i.declared_version.as_deref(),
                i.product_name.as_deref(),
            )
        })
        .collect();
    Ok(Response::new(ListApprovalsResponse {
        items,
        next_page_token,
    }))
}

/// `GetApproval` (`approval.read`): the approval, its revision history and
/// the lineage tree.
pub async fn get_approval(
    authz: &AdminAuthz,
    request: Request<GetApprovalRequest>,
) -> Result<Response<GetApprovalResponse>, Status> {
    require(&request, paths::GET_APPROVAL)?;
    let st = authz.state();
    let id = request.into_inner().approval_id;
    check_id(&id, "approval_id")?;
    let cluster = st.cluster();
    let a = cluster
        .app_approval(&id)
        .await
        .map_err(ledger_status)?
        .ok_or_else(|| Status::not_found("not_found"))?;
    let revisions = cluster
        .app_approval_revisions(&id)
        .await
        .map_err(ledger_status)?;
    let lineage = cluster
        .app_approvals_of_lineage(&a.lineage_id)
        .await
        .map_err(ledger_status)?;
    let binary = cluster
        .app_binary(&a.lineage_id, &a.bin_sha)
        .await
        .map_err(ledger_status)?;
    let mut lineage_approvals = Vec::with_capacity(lineage.len());
    for l in &lineage {
        lineage_approvals.push(approval_full(cluster, l).await?);
    }
    Ok(Response::new(GetApprovalResponse {
        approval: Some(approval_full(cluster, &a).await?),
        revisions: revisions.iter().map(revision_info).collect(),
        lineage_approvals,
        binary: binary.as_ref().map(binary_info),
    }))
}

// ---- decisions ----------------------------------------------------------------------

/// `ApproveAppRequest` (`app_request.approve`, step-up).
#[allow(clippy::too_many_lines)] // one linear validate → MFA → write → audit flow.
pub async fn approve_app_request(
    authz: &AdminAuthz,
    request: Request<ApproveAppRequestRequest>,
) -> Result<Response<ApproveAppRequestResponse>, Status> {
    let ctx = require(&request, paths::APPROVE_APP_REQUEST)?;
    let st = authz.state();
    let cfg = &st.cmis().config.apps;
    let strict = st.config().strict_sod;
    let now = st.now();
    let req = request.into_inner();
    // Revoking alongside the approval is a revocation: it needs
    // `approval.revoke` as well, checked before anything is read or written.
    if !req.also_revoke_approval_ids.is_empty() {
        require_also(
            authz,
            &ctx,
            paths::APPROVE_APP_REQUEST,
            Permission::ApprovalRevoke,
        )?;
    }
    check_idempotency(&req.idempotency_key)?;
    check_id(&req.request_id, "request_id")?;
    let cluster = st.cluster();
    let pending = cluster
        .app_request(&req.request_id)
        .await
        .map_err(ledger_status)?
        .ok_or_else(|| Status::not_found("not_found"))?;
    if pending.state != RequestState::Pending {
        return Err(Status::failed_precondition("invalid_state"));
    }
    let own = pending.requested_by_admin_id.as_deref() == Some(ctx.admin_id.as_str());
    if strict && own {
        return Err(Status::permission_denied("sod_self_approval"));
    }
    let choice = match &req.choice {
        Some(Choice::Terms(t)) => {
            let terms = terms(t, pending.flags, cfg, now)?;
            if terms.path_match == PathMatch::Exact {
                require_known_path(cluster, &pending.lineage_id, "terms.path_match").await?;
            }
            ApprovalChoice::New {
                approval_id: new_id(),
                terms,
            }
        }
        Some(Choice::ReuseApprovalId(id)) => {
            check_id(id, "reuse_approval_id")?;
            ApprovalChoice::Reuse {
                approval_id: id.clone(),
            }
        }
        None => return Err(invalid_field("missing", Some("terms"))),
    };
    let mut also_revoke = Vec::with_capacity(req.also_revoke_approval_ids.len());
    if !req.also_revoke_approval_ids.is_empty() {
        let reason = nonzero_reason(req.also_revoke_reason_code, "also_revoke_reason_code")?;
        if req.also_revoke_approval_ids.len() > 100 {
            return Err(invalid_field("too_many", Some("also_revoke_approval_ids")));
        }
        for id in &req.also_revoke_approval_ids {
            check_id(id, "also_revoke_approval_ids")?;
            also_revoke.push(Revoke {
                approval_id: id.clone(),
                admin_id: ctx.admin_id.clone(),
                reason_code: reason,
                expected_row_version: None,
            });
        }
    }
    // Approving one's own direct registration (policy off) needs a fresh
    // second factor (F20 §7 "M"), verified before anything is written.
    let mfa = if own {
        Some(st.verify_factor(&ctx, req.proof, None).await?.method)
    } else {
        None
    };
    let decided = cluster
        .app_approve_request(&Approve {
            request_id: req.request_id.clone(),
            admin_id: ctx.admin_id.clone(),
            now,
            choice,
            forbid_self_approval: strict,
            also_revoke,
            generation_millis: now_millis(now),
        })
        .await
        .map_err(ledger_status)?;
    if decided.same_actor {
        st.audit(events::same_actor(
            &decided.request,
            &decided.approval,
            &ctx.admin_id,
            &ctx.session_ref,
            mfa.map_or("", |m| m.label()),
        ));
    } else {
        st.audit(events::approved(
            &decided.request,
            &decided.approval,
            &ctx.admin_id,
            &ctx.session_ref,
        ));
    }
    for r in &decided.revoked {
        st.audit(events::revoked(r, &ctx.admin_id, &ctx.session_ref));
    }
    tracing::info!(
        event = "apps.request.approved",
        request_id = %decided.request.request_id,
        approval_id = %decided.approval.approval_id,
        admin_id = %ctx.admin_id,
        same_actor = decided.same_actor,
        generation = decided.generation,
        "app request approved"
    );
    Ok(Response::new(ApproveAppRequestResponse {
        request: Some(request_full(cluster, &decided.request).await?),
        approval: Some(approval_full(cluster, &decided.approval).await?),
        same_actor: decided.same_actor,
        revoked_approval_ids: decided
            .revoked
            .iter()
            .map(|a| a.approval_id.clone())
            .collect(),
        allowlist_generation: decided.generation,
    }))
}

/// `DenyAppRequest` (`app_request.deny`, step-up).
pub async fn deny_app_request(
    authz: &AdminAuthz,
    request: Request<DenyAppRequestRequest>,
) -> Result<Response<DenyAppRequestResponse>, Status> {
    let ctx = require(&request, paths::DENY_APP_REQUEST)?;
    let st = authz.state();
    let req = request.into_inner();
    check_idempotency(&req.idempotency_key)?;
    check_id(&req.request_id, "request_id")?;
    let reason_code = nonzero_reason(req.reason_code, "reason_code")?;
    let message = free_text(&req.message, 200, "message")?;
    let row = st
        .cluster()
        .app_deny_request(&Deny {
            request_id: req.request_id,
            admin_id: ctx.admin_id.clone(),
            now: st.now(),
            reason_code,
            message,
            forbid_self_approval: st.config().strict_sod,
        })
        .await
        .map_err(ledger_status)?;
    st.audit(events::denied(&row, &ctx.admin_id, &ctx.session_ref));
    tracing::info!(event = "apps.request.denied", request_id = %row.request_id, admin_id = %ctx.admin_id, "app request denied");
    Ok(Response::new(DenyAppRequestResponse {
        request: Some(request_full(st.cluster(), &row).await?),
    }))
}

/// `UpdateApproval` (`approval.update`, step-up): edit, narrow or renew.
pub async fn update_approval(
    authz: &AdminAuthz,
    request: Request<UpdateApprovalRequest>,
) -> Result<Response<UpdateApprovalResponse>, Status> {
    let ctx = require(&request, paths::UPDATE_APPROVAL)?;
    let st = authz.state();
    let cfg = &st.cmis().config.apps;
    let now = st.now();
    let req = request.into_inner();
    check_idempotency(&req.idempotency_key)?;
    check_id(&req.approval_id, "approval_id")?;
    let cluster = st.cluster();
    let current = cluster
        .app_approval(&req.approval_id)
        .await
        .map_err(ledger_status)?
        .ok_or_else(|| Status::not_found("not_found"))?;
    let update_policy = req
        .update_policy
        .map(|v| {
            code_of(
                v,
                UpdatePolicy::ManualEachTime,
                UpdatePolicy::from_code,
                "update_policy",
            )
        })
        .transpose()?;
    let continuity = req
        .continuity
        .map(|v| code_of(v, Continuity::Anchored, Continuity::from_code, "continuity"))
        .transpose()?;
    let expires_at = if req.clear_expiry {
        Some(resolve_expiry(0, true, cfg, now)?)
    } else {
        req.expires_at
            .map(|t| resolve_expiry(t, false, cfg, now))
            .transpose()?
    };
    let note = if req.clear_note {
        Some(None)
    } else {
        req.note
            .as_deref()
            .map(|n| free_text(n, 500, "note"))
            .transpose()?
    };
    // Wide auto-update stays tied to a protected path (§5.3 #4).
    let scope = if req.narrow_to_exact_user {
        UserScope::ExactUser
    } else {
        current.user_scope
    };
    let policy = update_policy.unwrap_or(current.update_policy);
    if scope == UserScope::AnyUser && policy == UpdatePolicy::AutoSamePathUser {
        let flags = match &current.source_request_id {
            Some(id) => cluster
                .app_request(id)
                .await
                .map_err(ledger_status)?
                .map_or(0, |r| r.flags),
            None => 0,
        };
        check_wide_auto(scope, policy, flags)?;
    }
    if req.narrow_to_exact_path {
        require_known_path(cluster, &current.lineage_id, "narrow_to_exact_path").await?;
    }
    let expected_row_version = i64::try_from(req.expected_row_version)
        .map_err(|_| invalid_field("bad_value", Some("expected_row_version")))?;
    let after = cluster
        .app_update_approval(&ApprovalEdit {
            approval_id: req.approval_id.clone(),
            admin_id: ctx.admin_id.clone(),
            expected_row_version,
            now,
            update_policy,
            continuity,
            expires_at,
            note,
            narrow_to_exact_user: req.narrow_to_exact_user,
            narrow_to_exact_path: req.narrow_to_exact_path,
            generation_millis: now_millis(now),
        })
        .await
        .map_err(ledger_status)?;
    st.audit(events::updated(
        &current,
        &after,
        &ctx.admin_id,
        &ctx.session_ref,
    ));
    tracing::info!(event = "apps.approval.updated", approval_id = %after.approval_id, admin_id = %ctx.admin_id, row_version = after.row_version, "approval updated");
    Ok(Response::new(UpdateApprovalResponse {
        approval: Some(approval_full(cluster, &after).await?),
        allowlist_generation: generation(cluster, &after.host_uuid).await?,
    }))
}

/// `RevokeApproval` (`approval.revoke`, step-up): "delete" — the record is
/// kept and `REVOKED` is final.
pub async fn revoke_approval(
    authz: &AdminAuthz,
    request: Request<RevokeApprovalRequest>,
) -> Result<Response<RevokeApprovalResponse>, Status> {
    let ctx = require(&request, paths::REVOKE_APPROVAL)?;
    let st = authz.state();
    let now = st.now();
    let req = request.into_inner();
    check_idempotency(&req.idempotency_key)?;
    check_id(&req.approval_id, "approval_id")?;
    let reason_code = nonzero_reason(req.reason_code, "reason_code")?;
    let expected_row_version = match req.expected_row_version {
        0 => None,
        v => Some(
            i64::try_from(v)
                .map_err(|_| invalid_field("bad_value", Some("expected_row_version")))?,
        ),
    };
    let cluster = st.cluster();
    let row = cluster
        .app_revoke_approval(
            &Revoke {
                approval_id: req.approval_id,
                admin_id: ctx.admin_id.clone(),
                reason_code,
                expected_row_version,
            },
            now,
            now_millis(now),
        )
        .await
        .map_err(ledger_status)?;
    st.audit(events::revoked(&row, &ctx.admin_id, &ctx.session_ref));
    tracing::info!(event = "apps.approval.revoked", approval_id = %row.approval_id, admin_id = %ctx.admin_id, "approval revoked");
    Ok(Response::new(RevokeApprovalResponse {
        approval: Some(approval_full(cluster, &row).await?),
        allowlist_generation: generation(cluster, &row.host_uuid).await?,
    }))
}

/// `SetLineageAutoUpdateFrozen` (`approval.update`, step-up): the per-lineage
/// auto-update kill switch.
pub async fn set_lineage_auto_update_frozen(
    authz: &AdminAuthz,
    request: Request<SetLineageAutoUpdateFrozenRequest>,
) -> Result<Response<SetLineageAutoUpdateFrozenResponse>, Status> {
    let ctx = require(&request, paths::SET_LINEAGE_AUTO_UPDATE_FROZEN)?;
    let st = authz.state();
    let req = request.into_inner();
    check_idempotency(&req.idempotency_key)?;
    check_id(&req.lineage_id, "lineage_id")?;
    let found = st
        .cluster()
        .app_set_lineage_frozen(&req.lineage_id, req.frozen)
        .await
        .map_err(ledger_status)?;
    if !found {
        return Err(Status::not_found("not_found"));
    }
    st.audit(events::lineage_frozen(
        &req.lineage_id,
        &ctx.admin_id,
        req.frozen,
    ));
    tracing::info!(event = "apps.lineage.frozen", lineage_id = %req.lineage_id, frozen = req.frozen, admin_id = %ctx.admin_id, "lineage auto-update switch set");
    Ok(Response::new(SetLineageAutoUpdateFrozenResponse {}))
}

// ---- direct registration ---------------------------------------------------------------

/// The binary of a direct registration, validated.
fn binary_facts(d: &AppBinaryDesc) -> Result<BinaryFacts, Status> {
    let small = |v: u32, field: &'static str| {
        u8::try_from(v).map_err(|_| invalid_field("bad_value", Some(field)))
    };
    let sha = hex::decode(&d.sha384)
        .ok()
        .filter(|b| b.len() == 48 && d.sha384.bytes().all(|c| !c.is_ascii_uppercase()))
        .ok_or_else(|| invalid_field("bad_sha", Some("binary.sha384")))?;
    let mut sha384 = [0u8; 48];
    sha384.copy_from_slice(&sha);
    Ok(BinaryFacts {
        platform: small(d.platform, "binary.platform")?,
        canonical_path: d.canonical_path.clone(),
        sha384,
        size: d.size,
        format: small(d.format, "binary.format")?,
        declared_version: opt_str(&d.declared_version),
        version_source: small(d.version_source, "binary.version_source")?,
        product_name: opt_str(&d.product_name),
        bundle_id: opt_str(&d.bundle_id),
        package_name: opt_str(&d.package_name),
        signer_kind: small(d.signer_kind, "binary.signer.kind")?,
        signer_id: opt_str(&d.signer_id),
        signer_subject: opt_str(&d.signer_subject),
        signer_valid: d.signer_valid,
        flags: d.flags,
    })
}

/// The target user of a direct registration, validated.
fn target_user(u: Option<&AppUser>) -> Result<UserIdentity, Status> {
    let u = u.ok_or_else(|| invalid_field("missing", Some("target_user")))?;
    let kind = UserKind::from_code(i64::from(u.kind))
        .ok_or_else(|| invalid_field("bad_value", Some("target_user.kind")))?;
    if u.name.chars().any(char::is_control) || u.name.chars().count() > 256 {
        return Err(invalid_field("bad_value", Some("target_user.name")));
    }
    if u.sid.len() > 184 || !u.sid.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid_field("bad_value", Some("target_user.sid")));
    }
    if let Some(uid) = u.uid {
        if u32::try_from(uid).is_err() {
            return Err(invalid_field("bad_value", Some("target_user.uid")));
        }
    }
    Ok(UserIdentity {
        kind,
        uid: u.uid,
        sid: opt_str(&u.sid).map(|s| s.to_ascii_uppercase()),
        user_name: opt_str(&u.name),
    })
}

/// The stored outcome of a direct registration (a retry).
async fn registration_outcome(
    cluster: &Cluster,
    row: &RequestRow,
) -> Result<AdminRegisterApplicationResponse, Status> {
    let approval = match &row.resulting_approval_id {
        Some(id) => cluster.app_approval(id).await.map_err(ledger_status)?,
        None => None,
    };
    let approval = match &approval {
        Some(a) => Some(approval_full(cluster, a).await?),
        None => None,
    };
    Ok(AdminRegisterApplicationResponse {
        request: Some(request_full(cluster, row).await?),
        queued: row.state == RequestState::Pending,
        deduplicated: true,
        allowlist_generation: if approval.is_some() {
            generation(cluster, &row.host_uuid).await?
        } else {
            0
        },
        approval,
    })
}

/// Refuse a single-step registration from a caller without
/// `app_request.approve`, recording the refusal like the layer does.
fn require_approve(authz: &AdminAuthz, ctx: &AdminContext) -> Result<(), Status> {
    require_also(
        authz,
        ctx,
        paths::ADMIN_REGISTER_APPLICATION,
        Permission::AppRequestApprove,
    )
}

/// Refuse a call to `path` that also needs `permission` beyond the one its
/// `METHOD_ACCESS` rule names (`PERMISSION_DENIED permission_denied`),
/// recording the refusal like the layer does.
fn require_also(
    authz: &AdminAuthz,
    ctx: &AdminContext,
    path: &str,
    permission: Permission,
) -> Result<(), Status> {
    if ctx.has(permission) {
        return Ok(());
    }
    if let Some(Access::Session(mut rule)) = access_for(path) {
        rule.permission = Some(permission);
        authz.deny(Some(ctx), path, rule, "permission_denied");
    }
    Err(Status::permission_denied("permission_denied"))
}

/// `AdminRegisterApplication` (`app.direct_register` + `app_request.approve`,
/// per-operation MFA): register and approve in one step, or — with the
/// strict policy on — queue the request for a different approver.
#[allow(clippy::too_many_lines)] // one linear validate → MFA → write → audit flow.
pub async fn admin_register_application(
    authz: &AdminAuthz,
    request: Request<AdminRegisterApplicationRequest>,
) -> Result<Response<AdminRegisterApplicationResponse>, Status> {
    let ctx = require(&request, paths::ADMIN_REGISTER_APPLICATION)?;
    let st = authz.state();
    let strict = st.config().strict_sod;
    if !strict {
        require_approve(authz, &ctx)?;
    }
    let cfg = &st.cmis().config.apps;
    let now = st.now();
    let req = request.into_inner();
    let key = &req.idempotency_key;
    if key.is_empty()
        || key.len() > 60
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(invalid_field("bad_value", Some("idempotency_key")));
    }
    let host_uuid = uuid::Uuid::parse_str(&req.host_uuid)
        .map_err(|_| invalid_field("bad_value", Some("host_uuid")))?
        .to_string();
    let client_request_id = format!("{ADMIN_CLIENT_ID_PREFIX}{key}");
    let cluster = st.cluster();

    // A retry of the same registration returns the stored outcome.
    if let Some(row) = cluster
        .app_request_by_client_id(&host_uuid, &client_request_id)
        .await
        .map_err(ledger_status)?
    {
        if row.requested_by_admin_id.as_deref() != Some(ctx.admin_id.as_str()) {
            return Err(Status::already_exists("idempotency_key_reused"));
        }
        return Ok(Response::new(registration_outcome(cluster, &row).await?));
    }

    let binary = binary_facts(
        req.binary
            .as_ref()
            .ok_or_else(|| invalid_field("missing", Some("binary")))?,
    )?;
    let target = target_user(req.target_user.as_ref())?;
    let reason = free_text(&req.reason, 200, "reason")?;
    let spiffe_id = format!("spiffe://{}/host/{host_uuid}", st.config().trust_domain);
    let host_tier = match st.cmis().lookup(&spiffe_id).await {
        Some(rec) if rec.params.policy_id == TIER_HOST_KEY => TIER_HOST_KEY,
        Some(_) => TIER_TPM,
        None => "unknown",
    };
    let p = intake::prepare(Submission {
        host_uuid: host_uuid.clone(),
        client_request_id,
        origin: RequestOrigin::AdminDirect,
        target,
        requester_uid: None,
        requester_user_name: None,
        requested_by_admin_id: Some(ctx.admin_id.clone()),
        reason,
        host_tier: host_tier.to_string(),
        proposer_spiffe_id: spiffe_id,
        binary,
    })?;
    let terms = terms(
        req.terms
            .as_ref()
            .ok_or_else(|| invalid_field("missing", Some("terms")))?,
        p.submission.binary.flags,
        cfg,
        now,
    )?;

    // A fresh second factor for this call (F20 §7 "M"): a recent step-up
    // does not substitute, and nothing is written without it.
    let verified = st.verify_factor(&ctx, req.proof, None).await?;

    // Already covered by an active approval: nothing to add.
    if let Some(lineage) = cluster
        .app_lineage_by_path(&host_uuid, &p.path_key)
        .await
        .map_err(ledger_status)?
    {
        if let Some(a) = cluster
            .app_covering_approval(
                &host_uuid,
                &lineage.lineage_id,
                &p.bin_sha,
                &p.submission.target,
                now,
            )
            .await
            .map_err(ledger_status)?
        {
            return Ok(Response::new(AdminRegisterApplicationResponse {
                request: None,
                approval: Some(approval_full(cluster, &a).await?),
                queued: false,
                deduplicated: true,
                allowlist_generation: generation(cluster, &host_uuid).await?,
            }));
        }
    }

    let (_lineage, observed) = intake::observe(cluster, &p, now).await?;
    let flags = intake::cmis_flags(cluster, &observed, host_tier)
        .await
        .map_err(ledger_status)?;
    let new_request = intake::new_request(&p, &observed, flags, cfg, now);

    if strict {
        // A different approver decides (F20 §7 rule 1).
        let outcome = cluster
            .app_submit_pending(
                &new_request,
                &IntakeChecks {
                    now,
                    denied_cooldown_since: None,
                },
            )
            .await
            .map_err(ledger_status)?;
        return match outcome {
            Intake::Recorded(row) => {
                st.audit(events::direct_registration(&row, &ctx.admin_id));
                tracing::info!(event = "apps.request.direct_queued", request_id = %row.request_id, admin_id = %ctx.admin_id, "direct registration queued for another approver");
                Ok(Response::new(AdminRegisterApplicationResponse {
                    request: Some(request_full(cluster, &row).await?),
                    approval: None,
                    queued: true,
                    deduplicated: false,
                    allowlist_generation: 0,
                }))
            }
            Intake::Covered(a) => Ok(Response::new(AdminRegisterApplicationResponse {
                request: None,
                approval: Some(approval_full(cluster, &a).await?),
                queued: false,
                deduplicated: true,
                allowlist_generation: generation(cluster, &host_uuid).await?,
            })),
            Intake::Replayed(row) | Intake::DuplicatePending(row) | Intake::RecentlyDenied(row) => {
                Ok(Response::new(registration_outcome(cluster, &row).await?))
            }
        };
    }

    let decided = cluster
        .app_register_and_approve(&new_request, &new_id(), &terms, now_millis(now))
        .await
        .map_err(ledger_status)?;
    st.audit(events::same_actor(
        &decided.request,
        &decided.approval,
        &ctx.admin_id,
        &ctx.session_ref,
        verified.method.label(),
    ));
    tracing::info!(
        event = "apps.request.direct_approved",
        request_id = %decided.request.request_id,
        approval_id = %decided.approval.approval_id,
        admin_id = %ctx.admin_id,
        generation = decided.generation,
        "application registered and approved in one step"
    );
    Ok(Response::new(AdminRegisterApplicationResponse {
        request: Some(request_full(cluster, &decided.request).await?),
        approval: Some(approval_full(cluster, &decided.approval).await?),
        queued: false,
        deduplicated: false,
        allowlist_generation: decided.generation,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_rules_follow_f19_5_4() {
        let cfg = AppConfig::default();
        let now = 1_000_000;
        assert_eq!(
            resolve_expiry(0, false, &cfg, now).unwrap(),
            Some(now + cfg.approval_default_ttl_secs)
        );
        assert_eq!(
            resolve_expiry(now + 10, false, &cfg, now).unwrap(),
            Some(now + 10)
        );
        let e = resolve_expiry(now, false, &cfg, now).unwrap_err();
        assert_eq!(e.message(), "expiry_in_past");
        let e = resolve_expiry(now + cfg.approval_max_ttl_secs + 1, false, &cfg, now).unwrap_err();
        assert_eq!(e.message(), "expiry_too_far");
        let e = resolve_expiry(0, true, &cfg, now).unwrap_err();
        assert_eq!(e.message(), "no_expiry_not_allowed");
        let open = AppConfig {
            allow_no_expiry: true,
            ..AppConfig::default()
        };
        assert_eq!(resolve_expiry(0, true, &open, now).unwrap(), None);
    }

    #[test]
    fn any_user_needs_confirmation_and_a_protected_path_for_auto_update() {
        let cfg = AppConfig::default();
        let mut t = WireTerms {
            user_scope: 2,
            ..WireTerms::default()
        };
        assert_eq!(
            terms(&t, 0, &cfg, 1).unwrap_err().message(),
            "confirmation_required"
        );
        t.confirm_any_user = true;
        assert!(terms(&t, 0, &cfg, 1).is_ok());
        t.update_policy = 2;
        assert_eq!(
            terms(&t, 0, &cfg, 1).unwrap_err().message(),
            "any_user_needs_protected_path"
        );
        assert!(terms(&t, FLAG_PATH_PROTECTED, &cfg, 1).is_ok());
        t.user_scope = 9;
        assert_eq!(terms(&t, 0, &cfg, 1).unwrap_err().message(), "bad_value");
    }

    #[test]
    fn free_text_refuses_control_characters_and_overlong_values() {
        assert_eq!(free_text("", 5, "f").unwrap(), None);
        assert_eq!(free_text("ok", 5, "f").unwrap().as_deref(), Some("ok"));
        assert!(free_text("a\u{1b}[31m", 50, "f").is_err());
        assert!(free_text("abcdef", 5, "f").is_err());
    }
}
