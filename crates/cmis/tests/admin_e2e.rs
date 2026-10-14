//! F20 Phase 0 end to end, over the real listeners: hybrid-PQC TLS, the
//! authorization layer, the `Admin` service and the legacy admin RPCs, driven
//! by tonic clients exactly as the `ferrogate` CLI does.
//!
//! bootstrap → login → authorized `SetAllowlist` → logout → rejected.

#![allow(clippy::large_futures, clippy::too_many_lines)] // one end-to-end scenario.

mod support;

use std::sync::Arc;

use cmis::server::{serve_admin, serve_main};
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferro_proto::admin_v1::admin_client::AdminClient;
use ferro_proto::admin_v1::{
    login_request::SecondFactor, BeginEnrollmentRequest, BeginLoginRequest, ClientInfo,
    CompleteEnrollmentRequest, LoginRequest, LogoutRequest, WhoAmIRequest,
};
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    AllowEntryMsg, AppendAuditRequest, GetAllowlistRequest, HealthRequest, SetAllowlistRequest,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tonic::metadata::MetadataValue;
use tonic::Code;

fn identity() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    SpkiPin,
) {
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .unwrap();
    let cert = ck.cert.der().clone();
    let pin = SpkiPin::from_certificate_der(cert.as_ref()).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    (vec![cert], key, pin)
}

fn bearer<T>(msg: T, token: &str) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    let v: MetadataValue<_> = format!("Bearer {token}").parse().unwrap();
    r.metadata_mut().insert("authorization", v);
    r
}

fn allowlist(host: &str) -> SetAllowlistRequest {
    SetAllowlistRequest {
        host_uuid: host.into(),
        entries: vec![AllowEntryMsg {
            uid: Some(1000),
            bin_sha: hex::encode([0xAB; 48]),
        }],
        ttl_secs: 3600,
    }
}

#[tokio::test]
async fn bootstrap_login_set_allowlist_logout_then_rejected() {
    let h = support::harness("e2e").await;
    let (chain, key, pin) = identity();
    let tls = ferro_crypto::transport::server_config(ProviderMode::HybridOnly, chain, key).unwrap();

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    tokio::spawn(serve_admin(
        admin_listener,
        Arc::clone(&tls),
        Arc::clone(&h.cmis),
        Arc::clone(&h.authz),
    ));
    let main_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let main_addr = main_listener.local_addr().unwrap();
    tokio::spawn(serve_main(
        main_listener,
        Some(Arc::clone(&tls)),
        Arc::clone(&h.cmis),
        Some(Arc::clone(&h.authz)),
        true,
    ));
    let plain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_addr = plain_listener.local_addr().unwrap();
    tokio::spawn(serve_main(
        plain_listener,
        None,
        Arc::clone(&h.cmis),
        Some(Arc::clone(&h.authz)),
        true,
    ));

    let admin_ch = ferro_transport::connect_pinned(&format!("https://{admin_addr}"), vec![pin])
        .await
        .unwrap();
    let mut admin = AdminClient::new(admin_ch.clone());
    let mut mi_admin = MachineIdentityClient::new(admin_ch);
    let main_pin = pin;
    let mut mi_main = MachineIdentityClient::new(
        ferro_transport::connect_pinned(&format!("https://{main_addr}"), vec![pin])
            .await
            .unwrap(),
    );

    // Before anyone signs in, the legacy admin surface is closed.
    let e = mi_main
        .set_allowlist(allowlist("host-a"))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "session_invalid")
    );

    // 1. Bootstrap the first account from the root-only token file.
    cmis::admin::bootstrap::arm(&h.admin).await.unwrap();
    let token_file = std::fs::read_to_string(&h.bootstrap_file).unwrap();
    let begin = admin
        .begin_enrollment(BeginEnrollmentRequest {
            enrollment_token: token_file.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let secret = support::secret_from_uri(&begin.totp_provisioning_uri);
    admin
        .complete_enrollment(CompleteEnrollmentRequest {
            enrollment_token: token_file,
            username: "first.operator".into(),
            display_name: "First Operator".into(),
            password: support::PASSWORD.into(),
            totp_code: support::code(&secret, h.clock_now()),
            webauthn_attestation: None,
        })
        .await
        .unwrap();

    // 2. Log in over the admin listener.
    let nonce = admin
        .begin_login(BeginLoginRequest {
            username: "first.operator".into(),
            device_token: String::new(),
            client: Some(ClientInfo {
                kind: 3,
                version: "e2e".into(),
            }),
        })
        .await
        .unwrap()
        .into_inner()
        .login_nonce;
    h.next_step();
    let login = admin
        .login(LoginRequest {
            login_nonce: nonce,
            username: "first.operator".into(),
            password: support::PASSWORD.into(),
            second_factor: Some(SecondFactor::TotpCode(support::code(
                &secret,
                h.clock_now(),
            ))),
            device_token: String::new(),
            client: Some(ClientInfo {
                kind: 3,
                version: "e2e".into(),
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(login.session_token.starts_with("fgas_"));
    assert_eq!(login.aal, 2);
    assert!(login
        .groups
        .contains(&"ferrogate-platform-operators".to_string()));
    let token = login.session_token;
    let who = admin
        .who_am_i(bearer(WhoAmIRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(who.username, "first.operator");

    // 3. Authorized SetAllowlist, on the admin listener and on the main one.
    mi_admin
        .set_allowlist(bearer(allowlist("host-a"), &token))
        .await
        .expect("operator may set an allowlist");
    mi_main
        .set_allowlist(bearer(allowlist("host-b"), &token))
        .await
        .expect("legacy admin RPCs stay on the main listener (CMIS_LEGACY_ADMIN_ON_MAIN)");
    let got = mi_main
        .get_allowlist(GetAllowlistRequest {
            host_uuid: "host-a".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_ne!(
        got.signed_allowlist,
        Vec::<u8>::new(),
        "an allowlist was stored"
    );

    // 4. Logout; the same token is now rejected everywhere.
    admin
        .logout(bearer(LogoutRequest {}, &token))
        .await
        .unwrap();
    for client in [&mut mi_admin, &mut mi_main] {
        let e = client
            .set_allowlist(bearer(allowlist("host-c"), &token))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (Code::Unauthenticated, "session_invalid")
        );
    }
    let e = admin
        .who_am_i(bearer(WhoAmIRequest {}, &token))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);

    // 5. The plaintext bring-up listener serves hosts but refuses admin RPCs.
    let mut plain = MachineIdentityClient::connect(format!("http://{plain_addr}"))
        .await
        .unwrap();
    plain
        .health(HealthRequest {})
        .await
        .expect("host-facing RPCs unchanged");
    let e = plain.set_allowlist(allowlist("host-d")).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "tls_required")
    );

    // 6. `AppendAuditEvent` is a host method: it reaches the handler on
    //    every listener, and without a host proof it appends nothing.
    let event_cbor = ferro_audit::event::encode(&ferro_audit::AuditEvent::LocalGrant {
        pid: 1,
        uid: 1000,
        bin_sha: ferro_audit::Hash384([0xAA; 48]),
        jti: ferro_audit::Bytes16([0x55; 16]),
    })
    .unwrap();
    let before = h.cmis.audit.len();
    for (listener, e) in [
        (
            "main",
            mi_main
                .append_audit_event(AppendAuditRequest {
                    event_cbor: event_cbor.clone(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
        ),
        (
            "plaintext",
            plain
                .append_audit_event(AppendAuditRequest {
                    event_cbor: event_cbor.clone(),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
        ),
    ] {
        assert_eq!(
            (e.code(), e.message()),
            (Code::Unauthenticated, "host_auth_failed"),
            "{listener}"
        );
    }
    assert_eq!(h.cmis.audit.len(), before, "nothing was appended");

    // The admin service is not exposed on the main listener.
    let mut admin_on_main = AdminClient::new(
        ferro_transport::connect_pinned(&format!("https://{main_addr}"), vec![main_pin])
            .await
            .unwrap(),
    );
    let e = admin_on_main.who_am_i(WhoAmIRequest {}).await.unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented);
}
