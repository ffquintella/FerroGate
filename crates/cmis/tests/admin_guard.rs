//! F20 Phase 0, handler side: every legacy admin RPC fails closed when called
//! without the `AdminContext` the authorization layer inserts, and refuses a
//! context that lacks the method's permission — even if the layer were absent.

#![allow(clippy::large_futures)]

mod support;

use cmis::admin::{AdminContext, Permission};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::{
    BumpEpochRequest, DeleteAllowlistRequest, DeleteProposalRequest, ListAllowlistsRequest,
    ListProposalsRequest, ListSvidsRequest, RevokeHostRequest, RevokeSvidRequest,
    SetAllowlistRequest,
};
use tonic::{Code, Request};

/// Calls every legacy admin handler with `ctx` (or none) and returns the
/// status code each produced (`Ok` when the call succeeded).
#[allow(clippy::too_many_lines)] // one call per legacy admin RPC.
async fn call_all(
    mi: &cmis::MachineIdentitySvc,
    ctx: Option<AdminContext>,
) -> Vec<(&'static str, Code)> {
    fn req<T>(msg: T, ctx: Option<&AdminContext>) -> Request<T> {
        let mut r = Request::new(msg);
        if let Some(c) = ctx {
            r.extensions_mut().insert(c.clone());
        }
        r
    }
    let code = |r: Result<(), tonic::Status>| r.err().map_or(Code::Ok, |s| s.code());
    vec![
        (
            "SetAllowlist",
            code(
                mi.set_allowlist(req(
                    SetAllowlistRequest {
                        host_uuid: "h".into(),
                        entries: vec![],
                        ttl_secs: 3600,
                    },
                    ctx.as_ref(),
                ))
                .await
                .map(|_| ()),
            ),
        ),
        (
            "DeleteAllowlist",
            code(
                mi.delete_allowlist(req(
                    DeleteAllowlistRequest {
                        host_uuid: "h".into(),
                    },
                    ctx.as_ref(),
                ))
                .await
                .map(|_| ()),
            ),
        ),
        (
            "ListAllowlists",
            code(
                mi.list_allowlists(req(ListAllowlistsRequest {}, ctx.as_ref()))
                    .await
                    .map(|_| ()),
            ),
        ),
        (
            "ListProposals",
            code(
                mi.list_proposals(req(ListProposalsRequest {}, ctx.as_ref()))
                    .await
                    .map(|_| ()),
            ),
        ),
        (
            "DeleteProposal",
            code(
                mi.delete_proposal(req(
                    DeleteProposalRequest {
                        host_uuid: "h".into(),
                    },
                    ctx.as_ref(),
                ))
                .await
                .map(|_| ()),
            ),
        ),
        (
            "RevokeSvid",
            code(
                mi.revoke_svid(req(
                    RevokeSvidRequest {
                        cert_sha: "a".repeat(96),
                        reason: String::new(),
                    },
                    ctx.as_ref(),
                ))
                .await
                .map(|_| ()),
            ),
        ),
        (
            "RevokeHost",
            code(
                mi.revoke_host(req(
                    RevokeHostRequest {
                        spiffe_id: "spiffe://t/h".into(),
                        reason: String::new(),
                    },
                    ctx.as_ref(),
                ))
                .await
                .map(|_| ()),
            ),
        ),
        (
            "BumpEpoch",
            code(
                mi.bump_epoch(req(
                    BumpEpochRequest {
                        reason: String::new(),
                    },
                    ctx.as_ref(),
                ))
                .await
                .map(|_| ()),
            ),
        ),
        (
            "ListSvids",
            code(
                mi.list_svids(req(ListSvidsRequest {}, ctx.as_ref()))
                    .await
                    .map(|_| ()),
            ),
        ),
    ]
}

#[tokio::test]
async fn every_legacy_admin_handler_fails_closed_without_a_session() {
    let h = support::harness("guard-none").await;
    let audit_before = h.cmis.audit.len();
    for (m, code) in call_all(&h.mi, None).await {
        assert_eq!(code, Code::Unauthenticated, "{m}");
    }
    assert_eq!(h.cmis.audit.len(), audit_before, "no mutation happened");
    assert_eq!(h.cmis.current_epoch(), 1, "epoch untouched");
}

#[tokio::test]
async fn a_context_without_the_permission_is_refused() {
    let h = support::harness("guard-viewer").await;
    let viewer =
        AdminContext::synthetic("viewer", [Permission::HostList, Permission::AppRequestList]);
    for (m, code) in call_all(&h.mi, Some(viewer)).await {
        assert_eq!(code, Code::PermissionDenied, "{m}");
    }
}

#[tokio::test]
async fn an_operator_context_reaches_every_handler() {
    let h = support::harness("guard-op").await;
    let op = AdminContext::synthetic(
        "operator",
        [
            Permission::LegacyAllowlistRead,
            Permission::LegacyAllowlistWrite,
            Permission::SvidList,
            Permission::SvidRevoke,
            Permission::PolicyEpochBump,
        ],
    );
    for (m, code) in call_all(&h.mi, Some(op)).await {
        assert_eq!(code, Code::Ok, "{m}");
    }
    assert_eq!(h.cmis.current_epoch(), 2);
    // Mutations are attributed to the administrator.
    let attributed = h.audit_events().into_iter().any(|e| {
        matches!(e, ferro_audit::AuditEvent::PolicyEpochBumped { by_admin_id: Some(ref id), .. } if id == "operator")
    });
    assert!(attributed, "PolicyEpochBumped carries by_admin_id");
}
