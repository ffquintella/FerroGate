//! F20 Phase 0, layer side: the tower layer in front of every listener
//! enforces the method access table. These tests drive the layer directly
//! with HTTP/2-shaped gRPC requests, enumerating `METHOD_ACCESS` so a new
//! method cannot slip past them.

#![allow(clippy::large_futures)]

mod support;

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cmis::admin::authz::{access_for, paths, Access, METHOD_ACCESS};
use cmis::admin::{AdminAuthLayer, ListenerKind};
use cmis::transport::PeerConnectInfo;
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::{mfa_proof, BeginStepUpRequest, MfaProof, StepUpRequest};
use tonic::codegen::http;
use tonic::Code;
use tower::{Layer, ServiceExt};

/// Run one request through `layer` in front of a handler that always answers
/// OK. Returns the gRPC status the client would see.
async fn through(
    layer: &AdminAuthLayer,
    path: &str,
    token: Option<&str>,
    ip: IpAddr,
) -> (Code, String) {
    let inner = tower::service_fn(|_req: http::Request<tonic::body::Body>| async {
        Ok::<_, Infallible>(http::Response::new(tonic::body::Body::default()))
    });
    let svc = layer.layer(inner);
    let mut req = http::Request::builder()
        .method("POST")
        .uri(format!("http://cmis{path}"))
        .header("content-type", "application/grpc");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let mut req = req.body(tonic::body::Body::default()).unwrap();
    req.extensions_mut().insert(PeerConnectInfo {
        remote_addr: Some(SocketAddr::new(ip, 40_000)),
        client_cert_sha256: None,
    });
    let resp = svc.oneshot(req).await.unwrap();
    match tonic::Status::from_header_map(resp.headers()) {
        Some(s) => (s.code(), s.message().to_string()),
        None => (Code::Ok, String::new()),
    }
}

fn lo() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn legacy_admin_paths() -> Vec<&'static str> {
    METHOD_ACCESS
        .iter()
        .filter(|(p, a)| p.starts_with(paths::MI) && matches!(a, Access::Session(_)))
        .map(|(p, _)| *p)
        .collect()
}

#[tokio::test]
async fn plaintext_listener_refuses_admin_methods_with_tls_required() {
    let h = support::harness("layer-plain").await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, false, true);
    let legacy = legacy_admin_paths();
    assert_eq!(legacy.len(), 9, "the nine legacy admin RPCs: {legacy:?}");
    for path in legacy {
        assert_eq!(
            through(&layer, path, None, lo()).await,
            (Code::FailedPrecondition, "tls_required".into()),
            "{path}"
        );
    }
    // Host-facing methods are unchanged in plaintext mode.
    for (path, access) in METHOD_ACCESS {
        if matches!(access, Access::Public | Access::Host) {
            assert_eq!(
                through(&layer, path, None, lo()).await.0,
                Code::Ok,
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn unclassified_methods_are_denied_by_default() {
    let h = support::harness("layer-deny").await;
    for (kind, tls) in [
        (ListenerKind::Main, true),
        (ListenerKind::Admin, true),
        (ListenerKind::Main, false),
    ] {
        let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), kind, tls, true);
        for path in [
            "/ferrogate.v1.MachineIdentity/NotARealMethod",
            "/ferrogate.admin.v1.Admin/Backdoor",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        ] {
            assert_eq!(
                through(&layer, path, None, lo()).await,
                (Code::PermissionDenied, "method_not_classified".into()),
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn every_session_method_without_a_token_is_unauthenticated() {
    let h = support::harness("layer-notoken").await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Admin, true, true);
    let mut n = 0;
    for (path, access) in METHOD_ACCESS {
        if matches!(access, Access::Session(_)) {
            n += 1;
            assert_eq!(
                through(&layer, path, None, lo()).await,
                (Code::Unauthenticated, "session_invalid".into()),
                "{path}"
            );
            assert_eq!(
                through(
                    &layer,
                    path,
                    Some("fgas_not-a-real-token-at-all-but-43-chars-long"),
                    lo()
                )
                .await
                .0,
                Code::Unauthenticated,
                "{path} with a bogus token"
            );
        }
    }
    assert!(
        n >= 9 + 14,
        "all legacy and admin session methods were checked ({n})"
    );
}

#[tokio::test]
async fn the_admin_service_is_served_only_on_the_admin_listener() {
    let h = support::harness("layer-split").await;
    let main = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    for (path, _) in METHOD_ACCESS
        .iter()
        .filter(|(p, _)| p.starts_with(paths::ADMIN))
    {
        assert_eq!(
            through(&main, path, None, lo()).await.0,
            Code::Unimplemented,
            "{path}"
        );
    }
    // With CMIS_LEGACY_ADMIN_ON_MAIN=false the legacy admin RPCs leave the
    // main listener too, while host-facing methods stay.
    let main_only_hosts =
        AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, false);
    for path in legacy_admin_paths() {
        assert_eq!(
            through(&main_only_hosts, path, None, lo()).await.0,
            Code::Unimplemented,
            "{path}"
        );
    }
    assert_eq!(
        through(
            &main_only_hosts,
            "/ferrogate.v1.MachineIdentity/Health",
            None,
            lo()
        )
        .await
        .0,
        Code::Ok
    );
}

#[tokio::test]
async fn without_the_admin_subsystem_admin_methods_are_unavailable() {
    let layer = AdminAuthLayer::new(None, ListenerKind::Main, true, true);
    for path in legacy_admin_paths() {
        assert_eq!(
            through(&layer, path, None, lo()).await.0,
            Code::Unavailable,
            "{path}"
        );
    }
    assert_eq!(
        through(&layer, "/ferrogate.v1.MachineIdentity/Health", None, lo())
            .await
            .0,
        Code::Ok
    );
}

#[tokio::test]
async fn a_viewer_session_is_refused_every_legacy_admin_rpc() {
    let h = support::harness("layer-viewer").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let root_token = h.login(&root).await;
    let viewer = h
        .create_and_enroll(&root, &root_token, "viewer.one", &["ferrogate-viewers"])
        .await;
    let token = h.login(&viewer).await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    for path in legacy_admin_paths() {
        assert_eq!(
            through(&layer, path, Some(&token), lo()).await,
            (Code::PermissionDenied, "permission_denied".into()),
            "{path}"
        );
    }
    // The denials are audited for the SIEM.
    let denied = h
        .audit_events()
        .into_iter()
        .filter(|e| matches!(e, ferro_audit::AuditEvent::AdminAccessDenied { .. }))
        .count();
    assert_eq!(denied, 9);
}

#[tokio::test]
async fn an_operator_session_passes_and_writes_need_a_fresh_step_up() {
    let h = support::harness("layer-stepup").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    for path in legacy_admin_paths() {
        assert_eq!(
            through(&layer, path, Some(&token), lo()).await.0,
            Code::Ok,
            "{path}"
        );
    }
    // Five minutes later reads still pass but writes need a step-up.
    h.clock.advance(301);
    assert_eq!(
        through(&layer, paths::LIST_SVIDS, Some(&token), lo())
            .await
            .0,
        Code::Ok
    );
    assert_eq!(
        through(&layer, paths::SET_ALLOWLIST, Some(&token), lo()).await,
        (Code::FailedPrecondition, "step_up_required".into())
    );

    let begin = h
        .call(
            &token,
            paths::BEGIN_STEP_UP,
            BeginStepUpRequest {},
            |svc, req| Box::pin(async move { svc.begin_step_up(req).await }),
        )
        .await
        .unwrap();
    let code = h.fresh_code(&root);
    let stepped = h
        .call(
            &token,
            paths::STEP_UP,
            StepUpRequest {
                stepup_nonce: begin.stepup_nonce,
                proof: Some(MfaProof {
                    f: Some(mfa_proof::F::TotpCode(code)),
                    nonce: Vec::new(),
                }),
            },
            |svc, req| Box::pin(async move { svc.step_up(req).await }),
        )
        .await
        .unwrap();
    assert_ne!(stepped.session_token, token, "the token rotates on step-up");
    assert_eq!(
        through(&layer, paths::SET_ALLOWLIST, Some(&token), lo())
            .await
            .0,
        Code::Unauthenticated,
        "the pre-rotation token is dead"
    );
    assert_eq!(
        through(
            &layer,
            paths::SET_ALLOWLIST,
            Some(&stepped.session_token),
            lo()
        )
        .await
        .0,
        Code::Ok
    );
}

#[tokio::test]
async fn a_session_used_from_another_ip_is_revoked() {
    let h = support::harness("layer-ip").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    let other: IpAddr = "10.9.9.9".parse().unwrap();
    for path in legacy_admin_paths() {
        let (code, msg) = through(&layer, path, Some(&token), other).await;
        assert_eq!(
            (code, msg.as_str()),
            (Code::Unauthenticated, "session_invalid"),
            "{path}"
        );
    }
    // The mismatch revoked the session: it is dead from the original IP too.
    assert_eq!(
        through(&layer, paths::LIST_SVIDS, Some(&token), lo())
            .await
            .0,
        Code::Unauthenticated
    );
    assert!(h.audit_events().iter().any(|e| matches!(
        e,
        ferro_audit::AuditEvent::AdminSessionRevoked { reason, .. } if reason == "ip_mismatch"
    )));
}

#[tokio::test]
async fn idle_and_absolute_expiry_end_the_session() {
    // Idle: 15 minutes without a call.
    let h = support::harness("layer-idle").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    h.clock.advance(901);
    for path in legacy_admin_paths() {
        assert_eq!(
            through(&layer, path, Some(&token), lo()).await.0,
            Code::Unauthenticated,
            "{path}"
        );
    }

    // Absolute: activity keeps the session from idling, the lifetime still ends it.
    let h = support::harness_with("layer-absolute", |c| {
        c.idle_timeout_secs = 900;
        c.absolute_lifetime_secs = 900;
    })
    .await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    h.clock.advance(600);
    assert_eq!(
        through(&layer, paths::LIST_SVIDS, Some(&token), lo())
            .await
            .0,
        Code::Ok
    );
    h.clock.advance(400);
    for path in legacy_admin_paths() {
        assert_eq!(
            through(&layer, path, Some(&token), lo()).await.0,
            Code::Unauthenticated,
            "{path}"
        );
    }
    let _ = access_for(paths::LIST_SVIDS);
}

/// Review fix: anyone can probe unknown paths, so those denials reach the WORM
/// audit log at most once a minute (every one is still logged).
#[tokio::test]
async fn unclassified_probes_are_audited_at_most_once_a_minute() {
    let h = support::harness("layer-flood").await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    let denied = |h: &support::Harness| {
        h.audit_events()
            .iter()
            .filter(|e| matches!(e, ferro_audit::AuditEvent::AdminAccessDenied { .. }))
            .count()
    };
    for i in 0..20 {
        let path = format!("/ferrogate.v1.MachineIdentity/Probe{i}");
        assert_eq!(
            through(&layer, &path, None, lo()).await.0,
            Code::PermissionDenied
        );
    }
    assert_eq!(denied(&h), 1);
    h.clock.advance(60);
    through(&layer, "/x.Y/Z", None, lo()).await;
    assert_eq!(denied(&h), 2);
}

/// Review fix: a session made over IPv4 is the same client when a dual-stack
/// listener reports the IPv4-mapped IPv6 address.
#[tokio::test]
async fn an_ipv4_mapped_peer_is_the_same_client() {
    let h = support::harness("layer-mapped").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let layer = AdminAuthLayer::new(Some(Arc::clone(&h.authz)), ListenerKind::Main, true, true);
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert_eq!(
        through(&layer, paths::LIST_SVIDS, Some(&token), mapped)
            .await
            .0,
        Code::Ok
    );
}
