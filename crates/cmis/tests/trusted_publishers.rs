//! Trusted publishers (ADR-0006) through the F20 admin path: who may list,
//! add and remove; the per-operation second factor; exactly one audit event
//! per mutation; and the publisher list a capable host receives (format 3)
//! while an older host keeps getting the unchanged v2 body.

#![allow(clippy::large_futures, clippy::too_many_lines, clippy::assert_is_empty)]

mod support;

use cmis::admin::authz::paths;
use cmis::apps::compile::{serve, Served};
use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::{
    AddTrustedPublisherRequest, AddTrustedPublisherResponse, ListTrustedPublishersRequest,
    RemoveTrustedPublisherRequest,
};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::sync_allowlist_response::Result as SyncResult;
use ferro_svid::allowlist_v2::{ALLOWLIST_V2_FORMAT, ALLOWLIST_V3_FORMAT};
use support::hosts::{approvals_mode, mint_host, now_unix, open_v2};
use support::{Admin1, Harness};
use tonic::Code;

struct World {
    h: Harness,
    operator: Admin1,
    operator_token: String,
    approver_token: String,
    viewer_token: String,
}

async fn world(tag: &str) -> World {
    let h = support::harness(tag).await;
    approvals_mode(&h.cmis).await;
    let root = support::bootstrap(&h, "root-admin").await;
    let root_token = h.login(&root).await;
    let operator = h
        .create_and_enroll(
            &root,
            &root_token,
            "operator.one",
            &["ferrogate-platform-operators"],
        )
        .await;
    let approver = h
        .create_and_enroll(&root, &root_token, "approver.one", &["ferrogate-approvers"])
        .await;
    let viewer = h
        .create_and_enroll(&root, &root_token, "viewer.one", &["ferrogate-viewers"])
        .await;
    let operator_token = h.login(&operator).await;
    let approver_token = h.login(&approver).await;
    let viewer_token = h.login(&viewer).await;
    World {
        h,
        operator,
        operator_token,
        approver_token,
        viewer_token,
    }
}

fn add_req(pin: u8) -> AddTrustedPublisherRequest {
    AddTrustedPublisherRequest {
        idempotency_key: uuid::Uuid::now_v7().to_string(),
        proof: None,
        kind: 1,
        anchor_sha256: vec![0xa0; 32],
        pin_kind: 2,
        pin: vec![pin; 32],
        require_timestamp: true,
        label: "ACME".into(),
        subject: "CN=ACME Corp, O=ACME".into(),
        issuer: "CN=ACME Issuing CA".into(),
        leaf_cert_sha256: vec![0x11; 32],
        expires_at: 0,
    }
}

async fn add(
    w: &World,
    token: &str,
    req: AddTrustedPublisherRequest,
) -> Result<AddTrustedPublisherResponse, tonic::Status> {
    w.h.call(token, paths::ADD_TRUSTED_PUBLISHER, req, |svc, r| {
        Box::pin(async move { svc.add_trusted_publisher(r).await })
    })
    .await
}

async fn list(w: &World, token: &str, include_removed: bool) -> Result<usize, tonic::Status> {
    w.h.call(
        token,
        paths::LIST_TRUSTED_PUBLISHERS,
        ListTrustedPublishersRequest { include_removed },
        |svc, r| Box::pin(async move { svc.list_trusted_publishers(r).await }),
    )
    .await
    .map(|r| r.publishers.len())
}

fn publisher_events(h: &Harness) -> Vec<AuditEvent> {
    h.audit_events()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                AuditEvent::TrustedPublisherAdded { .. }
                    | AuditEvent::TrustedPublisherRemoved { .. }
            )
        })
        .collect()
}

#[tokio::test]
async fn only_publisher_managers_add_with_a_fresh_factor_and_each_change_is_audited() {
    let w = world("pub-admin").await;

    // Viewers and approvers may list; nobody but a manager may add.
    assert_eq!(list(&w, &w.viewer_token, false).await.unwrap(), 0);
    assert_eq!(list(&w, &w.approver_token, false).await.unwrap(), 0);
    let mut req = add_req(1);
    req.proof = w.h.proof(&w.operator);
    let e = add(&w, &w.approver_token, req).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);

    // No second factor, or a malformed request: nothing written or audited.
    let e = add(&w, &w.operator_token, add_req(1)).await.unwrap_err();
    assert_ne!(e.code(), Code::Ok);
    let mut bad = add_req(1);
    bad.pin = vec![1; 31];
    bad.proof = w.h.proof(&w.operator);
    let e = add(&w, &w.operator_token, bad).await.unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    assert_eq!(list(&w, &w.operator_token, true).await.unwrap(), 0);
    assert!(publisher_events(&w.h).is_empty());

    // With a fresh factor: added, and audited once with the pins only.
    let mut req = add_req(1);
    req.proof = w.h.proof(&w.operator);
    let added = add(&w, &w.operator_token, req)
        .await
        .unwrap()
        .publisher
        .unwrap();
    assert_eq!(added.state, 1);
    assert_eq!(added.created_by_admin_id, w.operator.admin_id);
    let events = publisher_events(&w.h);
    assert_eq!(events.len(), 1, "{events:?}");
    let AuditEvent::TrustedPublisherAdded {
        admin_id,
        kind,
        pin_kind,
        pin,
        mfa_method,
        ..
    } = &events[0]
    else {
        panic!("{events:?}");
    };
    assert_eq!(admin_id, &w.operator.admin_id);
    assert_eq!((*kind, *pin_kind, pin.0), (1, 2, [1; 32]));
    assert_eq!(mfa_method, "totp");

    // The same pin again is refused before a factor is asked for.
    let e = add(&w, &w.operator_token, add_req(1)).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::AlreadyExists, "publisher_exists")
    );

    // Removal (step-up from the fresh login) is audited once and is final.
    let remove = |id: String| RemoveTrustedPublisherRequest {
        idempotency_key: String::new(),
        publisher_id: id,
    };
    let e =
        w.h.call(
            &w.approver_token,
            paths::REMOVE_TRUSTED_PUBLISHER,
            remove(added.publisher_id.clone()),
            |svc, r| Box::pin(async move { svc.remove_trusted_publisher(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    let removed =
        w.h.call(
            &w.operator_token,
            paths::REMOVE_TRUSTED_PUBLISHER,
            remove(added.publisher_id.clone()),
            |svc, r| Box::pin(async move { svc.remove_trusted_publisher(r).await }),
        )
        .await
        .unwrap()
        .publisher
        .unwrap();
    assert_eq!(removed.state, 2);
    let e =
        w.h.call(
            &w.operator_token,
            paths::REMOVE_TRUSTED_PUBLISHER,
            remove(added.publisher_id.clone()),
            |svc, r| Box::pin(async move { svc.remove_trusted_publisher(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert_eq!(publisher_events(&w.h).len(), 2);
    assert_eq!(list(&w, &w.viewer_token, false).await.unwrap(), 0);
    assert_eq!(list(&w, &w.viewer_token, true).await.unwrap(), 1);
}

#[tokio::test]
async fn capable_hosts_get_format_3_and_older_hosts_the_unchanged_v2_body() {
    let w = world("pub-sync").await;
    let host = mint_host(&w.h.cmis.issuer, 0x71, "p1");
    let now = now_unix();

    // Before any publisher: both kinds of host get format 2.
    let Served::Body {
        generation: g0,
        signed,
        ..
    } = serve(&w.h.cmis, &host.uuid, 0, true, now).await.unwrap()
    else {
        panic!("expected a body");
    };
    assert_eq!(open_v2(&w.h.cmis, &signed).format, ALLOWLIST_V2_FORMAT);

    let mut req = add_req(5);
    req.proof = w.h.proof(&w.operator);
    let added = add(&w, &w.operator_token, req)
        .await
        .unwrap()
        .publisher
        .unwrap();

    // A capable host's generation moves and its body carries the publisher.
    let Served::Body {
        generation: g1,
        signed,
        ..
    } = serve(&w.h.cmis, &host.uuid, g0, true, now).await.unwrap()
    else {
        panic!("expected a new body");
    };
    assert!(g1 > g0);
    let doc = open_v2(&w.h.cmis, &signed);
    assert_eq!(doc.format, ALLOWLIST_V3_FORMAT);
    assert_eq!(doc.publishers.len(), 1);
    let p = &doc.publishers[0];
    assert_eq!((p.kind, p.pin_kind, p.pin), (1, 2, [5; 32]));
    assert_eq!(
        p.publisher_id,
        *uuid::Uuid::parse_str(&added.publisher_id)
            .unwrap()
            .as_bytes()
    );

    // The RPC accepts [2, 3] and serves the same format-3 body.
    let resp =
        w.h.mi
            .sync_allowlist(tonic::Request::new(host.sync_accepting(0, &[2, 3])))
            .await
            .unwrap()
            .into_inner();
    let Some(SyncResult::SignedAllowlistV2(body)) = resp.result else {
        panic!("expected a body: {resp:?}");
    };
    assert_eq!(open_v2(&w.h.cmis, &body).publishers.len(), 1);

    // An older host (format 2 only) never receives publishers.
    let old = mint_host(&w.h.cmis.issuer, 0x72, "p1");
    let Served::Body { signed, .. } = serve(&w.h.cmis, &old.uuid, 0, false, now).await.unwrap()
    else {
        panic!("expected a body");
    };
    let doc = open_v2(&w.h.cmis, &signed);
    assert_eq!(doc.format, ALLOWLIST_V2_FORMAT);
    assert!(doc.publishers.is_empty());

    // Removal takes the publisher out at the next generation.
    w.h.call(
        &w.operator_token,
        paths::REMOVE_TRUSTED_PUBLISHER,
        RemoveTrustedPublisherRequest {
            idempotency_key: String::new(),
            publisher_id: added.publisher_id.clone(),
        },
        |svc, r| Box::pin(async move { svc.remove_trusted_publisher(r).await }),
    )
    .await
    .unwrap();
    let Served::Body {
        generation: g2,
        signed,
        ..
    } = serve(&w.h.cmis, &host.uuid, resp.generation, true, now)
        .await
        .unwrap()
    else {
        panic!("expected a new body");
    };
    assert!(g2 > resp.generation);
    assert!(open_v2(&w.h.cmis, &signed).publishers.is_empty());
}
