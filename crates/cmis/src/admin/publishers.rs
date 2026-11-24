//! Trusted publishers (ADR-0006), served by the `Admin` service: list, add
//! and remove. The layer already authorized the call against
//! [`super::authz::METHOD_ACCESS`]; each handler re-checks it ([`require`]).

//! Display strings (label, subject, issuer) are bounded and may not carry
//! control characters; they are never used for matching. Hosts pick the
//! change up on their next sync: the compiled digest moves (format 3).

//! - **Add** needs `publisher.manage` and a fresh second factor for this
//!   call (F20 §7 "M"), verified after validation and before any write.
//! - **Remove** needs `publisher.manage` and a recent step-up (layer).
//! - **Audit.** Each mutation emits exactly one event, after the store
//!   committed: `TrustedPublisherAdded` or `TrustedPublisherRemoved`.

use tonic::{Request, Response, Status};

use ferro_audit::{AuditEvent, Bytes16, Bytes32};
use ferro_proto::admin_v1::{
    AddTrustedPublisherRequest, AddTrustedPublisherResponse, ListTrustedPublishersRequest,
    ListTrustedPublishersResponse, RemoveTrustedPublisherRequest, RemoveTrustedPublisherResponse,
    TrustedPublisherInfo,
};
use ferro_raft::publishers::{NewPublisher, PublisherRow, PUBLISHER_REMOVED};
use ferro_raft::LedgerError;

use super::authz::{paths, require, AdminAuthz};
use crate::apps::{ledger_status, new_id, uuid_bytes};
use crate::host_auth::invalid_field;

/// Longest `idempotency_key` accepted.
const MAX_IDEMPOTENCY_KEY: usize = 128;
/// Longest label, in characters.
const MAX_LABEL: usize = 128;
/// Longest subject or issuer, in characters.
const MAX_DISPLAY: usize = 512;

fn publisher_status(e: LedgerError) -> Status {
    match e {
        LedgerError::Invalid("publisher_exists") => Status::already_exists("publisher_exists"),
        LedgerError::Invalid("too_many_publishers") => {
            Status::resource_exhausted("too_many_publishers")
        }
        other => ledger_status(other),
    }
}

/// Bounded display text without control characters.
fn display(v: &str, max_chars: usize, field: &'static str) -> Result<String, Status> {
    if v.chars().any(char::is_control) {
        return Err(invalid_field("bad_value", Some(field)));
    }
    if v.chars().count() > max_chars {
        return Err(invalid_field("field_too_long", Some(field)));
    }
    Ok(v.to_string())
}

fn digest(v: &[u8], field: &'static str) -> Result<[u8; 32], Status> {
    v.try_into()
        .map_err(|_| invalid_field("bad_value", Some(field)))
}

fn opt_bytes(v: Option<[u8; 32]>) -> Vec<u8> {
    v.map(|d| d.to_vec()).unwrap_or_default()
}

/// The wire form of a stored record.
fn info(r: &PublisherRow) -> TrustedPublisherInfo {
    let p = &r.record;
    TrustedPublisherInfo {
        publisher_id: p.publisher_id.clone(),
        kind: u32::try_from(p.kind).unwrap_or(0),
        anchor_sha256: p.anchor_sha256.to_vec(),
        pin_kind: u32::try_from(p.pin_kind).unwrap_or(0),
        pin: p.pin.to_vec(),
        require_timestamp: p.require_timestamp,
        label: p.label.clone(),
        subject: p.subject.clone(),
        issuer: p.issuer.clone(),
        leaf_cert_sha256: opt_bytes(p.leaf_cert_sha256),
        created_at: p.created_at,
        created_by_admin_id: p.created_by_admin_id.clone(),
        expires_at: p.expires_at.unwrap_or(0),
        state: u32::try_from(r.state).unwrap_or(0),
        removed_at: r.removed_at.unwrap_or(0),
        removed_by_admin_id: r.removed_by_admin_id.clone().unwrap_or_default(),
    }
}

/// The record `req` asks for, validated (no I/O, nothing written).
fn new_publisher(
    req: &AddTrustedPublisherRequest,
    admin_id: &str,
    now: i64,
) -> Result<NewPublisher, Status> {
    if req.idempotency_key.len() > MAX_IDEMPOTENCY_KEY {
        return Err(invalid_field("field_too_long", Some("idempotency_key")));
    }
    if !matches!(req.kind, 1 | 2) {
        return Err(invalid_field("bad_value", Some("kind")));
    }
    if !matches!(req.pin_kind, 1..=3) {
        return Err(invalid_field("bad_value", Some("pin_kind")));
    }
    let label = display(req.label.trim(), MAX_LABEL, "label")?;
    if label.is_empty() {
        return Err(invalid_field("missing", Some("label")));
    }
    let leaf_cert_sha256 = if req.leaf_cert_sha256.is_empty() {
        None
    } else {
        Some(digest(&req.leaf_cert_sha256, "leaf_cert_sha256")?)
    };
    let expires_at = match req.expires_at {
        0 => None,
        t if t > now => Some(t),
        _ => return Err(invalid_field("bad_value", Some("expires_at"))),
    };
    Ok(NewPublisher {
        publisher_id: new_id(),
        kind: i64::from(req.kind),
        anchor_sha256: digest(&req.anchor_sha256, "anchor_sha256")?,
        pin_kind: i64::from(req.pin_kind),
        pin: digest(&req.pin, "pin")?,
        require_timestamp: req.require_timestamp,
        label,
        subject: display(&req.subject, MAX_DISPLAY, "subject")?,
        issuer: display(&req.issuer, MAX_DISPLAY, "issuer")?,
        leaf_cert_sha256,
        created_at: now,
        created_by_admin_id: admin_id.to_string(),
        expires_at,
    })
}

fn same_pin(a: &NewPublisher, b: &NewPublisher) -> bool {
    a.kind == b.kind
        && a.anchor_sha256 == b.anchor_sha256
        && a.pin_kind == b.pin_kind
        && a.pin == b.pin
}

/// `ListTrustedPublishers` (`publisher.list`).
pub async fn list_trusted_publishers(
    authz: &AdminAuthz,
    request: Request<ListTrustedPublishersRequest>,
) -> Result<Response<ListTrustedPublishersResponse>, Status> {
    require(&request, paths::LIST_TRUSTED_PUBLISHERS)?;
    let rows = authz
        .state()
        .cluster()
        .publishers(request.get_ref().include_removed)
        .await
        .map_err(publisher_status)?;
    Ok(Response::new(ListTrustedPublishersResponse {
        publishers: rows.iter().map(info).collect(),
    }))
}

/// `AddTrustedPublisher` (`publisher.manage`, per-operation second factor).
pub async fn add_trusted_publisher(
    authz: &AdminAuthz,
    request: Request<AddTrustedPublisherRequest>,
) -> Result<Response<AddTrustedPublisherResponse>, Status> {
    let ctx = require(&request, paths::ADD_TRUSTED_PUBLISHER)?;
    let st = authz.state();
    let now = st.now();
    let mut req = request.into_inner();
    let new = new_publisher(&req, &ctx.admin_id, now)?;
    let cluster = st.cluster();
    // Refuse a duplicate before it costs a second factor; the store's
    // unique index is the atomic backstop.
    let active = cluster.publishers(false).await.map_err(publisher_status)?;
    if active.iter().any(|r| same_pin(&r.record, &new)) {
        return Err(Status::already_exists("publisher_exists"));
    }
    let verified = st.verify_factor(&ctx, req.proof.take(), None).await?;
    let row = cluster
        .publisher_add(&new)
        .await
        .map_err(publisher_status)?;
    let p = &row.record;
    st.audit(AuditEvent::TrustedPublisherAdded {
        publisher_id: Bytes16(uuid_bytes(&p.publisher_id)),
        admin_id: ctx.admin_id.clone(),
        session_ref: ctx.session_ref.clone(),
        kind: u8::try_from(p.kind).unwrap_or(0),
        anchor_sha256: Bytes32(p.anchor_sha256),
        pin_kind: u8::try_from(p.pin_kind).unwrap_or(0),
        pin: Bytes32(p.pin),
        require_timestamp: p.require_timestamp,
        mfa_method: verified.method.label().to_string(),
        expires_at: p.expires_at,
    });
    tracing::info!(event = "publishers.added", publisher_id = %p.publisher_id, admin_id = %ctx.admin_id, kind = p.kind, pin_kind = p.pin_kind, "trusted publisher added");
    Ok(Response::new(AddTrustedPublisherResponse {
        publisher: Some(info(&row)),
    }))
}

/// `RemoveTrustedPublisher` (`publisher.manage`, step-up).
pub async fn remove_trusted_publisher(
    authz: &AdminAuthz,
    request: Request<RemoveTrustedPublisherRequest>,
) -> Result<Response<RemoveTrustedPublisherResponse>, Status> {
    let ctx = require(&request, paths::REMOVE_TRUSTED_PUBLISHER)?;
    let st = authz.state();
    let req = request.into_inner();
    if req.idempotency_key.len() > MAX_IDEMPOTENCY_KEY {
        return Err(invalid_field("field_too_long", Some("idempotency_key")));
    }
    let id = &req.publisher_id;
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid_field("bad_value", Some("publisher_id")));
    }
    let row = st
        .cluster()
        .publisher_remove(id, &ctx.admin_id, st.now())
        .await
        .map_err(publisher_status)?;
    debug_assert_eq!(row.state, PUBLISHER_REMOVED);
    st.audit(AuditEvent::TrustedPublisherRemoved {
        publisher_id: Bytes16(uuid_bytes(&row.record.publisher_id)),
        admin_id: ctx.admin_id.clone(),
        session_ref: ctx.session_ref.clone(),
    });
    tracing::info!(event = "publishers.removed", publisher_id = %row.record.publisher_id, admin_id = %ctx.admin_id, "trusted publisher removed");
    Ok(Response::new(RemoveTrustedPublisherResponse {
        publisher: Some(info(&row)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> AddTrustedPublisherRequest {
        AddTrustedPublisherRequest {
            kind: 1,
            anchor_sha256: vec![1; 32],
            pin_kind: 2,
            pin: vec![2; 32],
            label: " ACME ".into(),
            ..AddTrustedPublisherRequest::default()
        }
    }

    #[test]
    fn requests_are_validated_before_anything_else() {
        let ok = new_publisher(&req(), "admin", 100).unwrap();
        assert_eq!(ok.label, "ACME");
        assert_eq!(ok.expires_at, None);
        assert_eq!(ok.leaf_cert_sha256, None);
        let bad = |f: fn(&mut AddTrustedPublisherRequest)| {
            let mut r = req();
            f(&mut r);
            new_publisher(&r, "admin", 100).unwrap_err().code()
        };
        let invalid = tonic::Code::InvalidArgument;
        assert_eq!(bad(|r| r.kind = 3), invalid);
        assert_eq!(bad(|r| r.pin_kind = 0), invalid);
        assert_eq!(bad(|r| r.pin = vec![0; 31]), invalid);
        assert_eq!(bad(|r| r.anchor_sha256.clear()), invalid);
        assert_eq!(bad(|r| r.leaf_cert_sha256 = vec![0; 20]), invalid);
        assert_eq!(bad(|r| r.label = "  ".into()), invalid);
        assert_eq!(bad(|r| r.label = "a\u{1b}[2J".into()), invalid);
        assert_eq!(bad(|r| r.subject = "x".repeat(513)), invalid);
        assert_eq!(bad(|r| r.expires_at = 100), invalid);
        assert_eq!(bad(|r| r.idempotency_key = "k".repeat(129)), invalid);
    }

    #[test]
    fn duplicates_and_the_cap_have_their_own_codes() {
        assert_eq!(
            publisher_status(LedgerError::Invalid("publisher_exists")).code(),
            tonic::Code::AlreadyExists
        );
        assert_eq!(
            publisher_status(LedgerError::Invalid("too_many_publishers")).code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            publisher_status(LedgerError::NotFound).code(),
            tonic::Code::NotFound
        );
    }
}
