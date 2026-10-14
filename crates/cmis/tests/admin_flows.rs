//! F20 wave A flows on the `Admin` service: login throttling (NRM §5.3.5),
//! TOTP replay, password policy and reuse, nonces, enrollment tokens,
//! separation of duties, restricted sessions, and the audit trail.

#![allow(clippy::large_futures, clippy::too_many_lines)]

mod support;

use std::net::IpAddr;

use cmis::admin::authz::paths;
use cmis::admin::bootstrap::{self, BootstrapOutcome};
use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::{
    login_request::SecondFactor, BeginEnrollmentRequest, BeginLoginRequest, ChangePasswordRequest,
    ClientInfo, CompleteEnrollmentRequest, CreateAdminAccountRequest, ListAdminAccountsRequest,
    ListMySessionsRequest, LoginRequest, ResetAdminCredentialsRequest, SetAdminAccountStateRequest,
    UpdateAdminAccountRequest, WhoAmIRequest,
};
use support::{from_ip, local_ip, Admin1, Harness, PASSWORD, PASSWORD2};
use tonic::Code;

/// One login attempt with an explicit password and code.
async fn attempt(
    h: &Harness,
    username: &str,
    password: &str,
    code: &str,
    ip: IpAddr,
) -> Result<String, tonic::Status> {
    let nonce = h
        .svc
        .begin_login(from_ip(
            BeginLoginRequest {
                username: username.into(),
                device_token: String::new(),
                client: None,
            },
            ip,
        ))
        .await?
        .into_inner()
        .login_nonce;
    h.svc
        .login(from_ip(
            LoginRequest {
                login_nonce: nonce,
                username: username.into(),
                password: password.into(),
                second_factor: Some(SecondFactor::TotpCode(code.into())),
                device_token: String::new(),
                client: Some(ClientInfo {
                    kind: 3,
                    version: String::new(),
                }),
            },
            ip,
        ))
        .await
        .map(|r| r.into_inner().session_token)
}

fn retry_after(s: &tonic::Status) -> u64 {
    s.metadata()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap()
}

fn policy_failures(s: &tonic::Status) -> String {
    s.metadata()
        .get("x-ferrogate-policy-failures")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn login_locks_the_source_ip_as_nrm_5_3_5_prescribes() {
    let h = support::harness("flow-lockout").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let ip: IpAddr = "192.0.2.10".parse().unwrap();

    // Failures 1 and 2: generic error, no lock.
    for _ in 0..2 {
        let e = attempt(&h, "root-admin", "wrong-password", "000000", ip)
            .await
            .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (Code::Unauthenticated, "invalid_credentials")
        );
    }
    // Failure 3 (an unknown user counts the same on the IP key) → 1 minute.
    let e = attempt(&h, "nobody-here", "wrong-password", "000000", ip)
        .await
        .unwrap_err();
    assert_eq!(
        e.message(),
        "invalid_credentials",
        "unknown users look identical"
    );
    let e = attempt(
        &h,
        "root-admin",
        PASSWORD,
        &support::code(&root.secret, h.clock_now() + 30),
        ip,
    )
    .await
    .unwrap_err();
    assert_eq!(
        (e.code(), retry_after(&e)),
        (Code::ResourceExhausted, 60),
        "locked even with the right password"
    );

    // After the minute: two more failures → 15 minutes.
    h.clock.advance(60);
    for _ in 0..2 {
        assert_eq!(
            attempt(&h, "root-admin", "wrong", "000000", ip)
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
    }
    let e = attempt(&h, "root-admin", "wrong", "000000", ip)
        .await
        .unwrap_err();
    assert_eq!((e.code(), retry_after(&e)), (Code::ResourceExhausted, 900));

    // After 15 minutes: two more → 1 hour.
    h.clock.advance(900);
    for _ in 0..2 {
        attempt(&h, "root-admin", "wrong", "000000", ip)
            .await
            .unwrap_err();
    }
    let e = attempt(&h, "root-admin", "wrong", "000000", ip)
        .await
        .unwrap_err();
    assert_eq!((e.code(), retry_after(&e)), (Code::ResourceExhausted, 3600));

    // Another address is not affected by this IP's lock.
    h.login(&root).await;
    assert!(h.audit_events().iter().any(|e| matches!(
        e,
        AuditEvent::AdminLockoutApplied { key_kind, lock_secs: 3600 } if key_kind == "ip"
    )));
}

#[tokio::test]
async fn a_totp_code_is_accepted_once() {
    let h = support::harness("flow-replay").await;
    let root = support::bootstrap(&h, "root-admin").await;
    h.next_step();
    let code = support::code(&root.secret, h.clock_now());
    attempt(&h, "root-admin", PASSWORD, &code, local_ip())
        .await
        .unwrap();
    let e = attempt(&h, "root-admin", PASSWORD, &code, local_ip())
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "invalid_credentials")
    );
    // An older code (an earlier step) is refused too.
    let older = support::code(&root.secret, h.clock_now() - 30);
    assert!(attempt(&h, "root-admin", PASSWORD, &older, local_ip())
        .await
        .is_err());
    // The next step works.
    h.next_step();
    let next = support::code(&root.secret, h.clock_now());
    attempt(&h, "root-admin", PASSWORD, &next, local_ip())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_login_nonce_is_single_use_and_bound_to_the_caller() {
    let h = support::harness("flow-nonce").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let nonce = h
        .svc
        .begin_login(from_ip(
            BeginLoginRequest {
                username: "root-admin".into(),
                device_token: String::new(),
                client: None,
            },
            local_ip(),
        ))
        .await
        .unwrap()
        .into_inner()
        .login_nonce;
    let login = |nonce: Vec<u8>, code: String, ip: IpAddr| {
        h.svc.login(from_ip(
            LoginRequest {
                login_nonce: nonce,
                username: "root-admin".into(),
                password: PASSWORD.into(),
                second_factor: Some(SecondFactor::TotpCode(code)),
                device_token: String::new(),
                client: None,
            },
            ip,
        ))
    };
    // From another IP the nonce does not verify.
    let other: IpAddr = "198.51.100.7".parse().unwrap();
    assert!(login(nonce.clone(), h.fresh_code(&root), other)
        .await
        .is_err());
    login(nonce.clone(), h.fresh_code(&root), local_ip())
        .await
        .unwrap();
    let e = login(nonce, h.fresh_code(&root), local_ip())
        .await
        .unwrap_err();
    assert_eq!(e.message(), "invalid_credentials", "replayed nonce");
}

#[tokio::test]
async fn change_password_enforces_policy_and_forbids_reuse() {
    let h = support::harness("flow-passwd").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let other_session = h.login(&root).await;

    let change = |token: String, current: &str, new: &str, proof| {
        let req = ChangePasswordRequest {
            current_password: current.into(),
            new_password: new.into(),
            proof,
        };
        let h = &h;
        async move {
            h.call(&token, paths::CHANGE_PASSWORD, req, |svc, r| {
                Box::pin(async move { svc.change_password(r).await })
            })
            .await
        }
    };

    // Too short, and names the product: refused with rule ids, never the password.
    let e = change(token.clone(), PASSWORD, "Ferrogate1!", h.proof(&root))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert_eq!(
        policy_failures(&e),
        "password_too_short,forbidden_content",
        "rule ids only"
    );
    // Same as the current password: reuse.
    let e = change(token.clone(), PASSWORD, PASSWORD, h.proof(&root))
        .await
        .unwrap_err();
    assert_eq!(policy_failures(&e), "reused");

    let changed = change(token.clone(), PASSWORD, PASSWORD2, h.proof(&root))
        .await
        .unwrap();
    assert_ne!(changed.session_token, token, "token rotated");
    // Other sessions were revoked; the rotated one works.
    let mine = h
        .call(
            &changed.session_token,
            paths::WHO_AM_I,
            WhoAmIRequest {},
            |svc, r| Box::pin(async move { svc.who_am_i(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(mine.admin_id, root.admin_id);
    let e = h
        .call(
            &other_session,
            paths::WHO_AM_I,
            WhoAmIRequest {},
            |svc, r| Box::pin(async move { svc.who_am_i(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);

    // Back to the first password: any earlier password is reuse.
    h.clock.advance(1);
    let e = change(
        changed.session_token.clone(),
        PASSWORD2,
        PASSWORD,
        h.proof(&root),
    )
    .await
    .unwrap_err();
    assert_eq!(policy_failures(&e), "reused");
    // Old password no longer logs in; the new one does.
    assert!(h.login_from(&root, PASSWORD, local_ip()).await.is_err());
    h.login_from(&root, PASSWORD2, local_ip()).await.unwrap();
}

#[tokio::test]
async fn enrollment_tokens_are_single_use_and_bootstrap_never_re_arms() {
    let h = support::harness("flow-tokens").await;
    let root = support::bootstrap(&h, "root-admin").await;
    assert!(!h.bootstrap_file.exists(), "bootstrap token file removed");
    assert_eq!(
        bootstrap::arm(&h.admin).await.unwrap(),
        BootstrapOutcome::AlreadyBootstrapped
    );

    let token = h.login(&root).await;
    let created = h
        .call(
            &token,
            paths::CREATE_ADMIN_ACCOUNT,
            CreateAdminAccountRequest {
                idempotency_key: String::new(),
                username: "second.admin".into(),
                display_name: "Second".into(),
                groups: vec!["ferrogate-viewers".into()],
                proof: h.proof(&root),
                enrollment_ttl_secs: 0,
            },
            |svc, r| Box::pin(async move { svc.create_admin_account(r).await }),
        )
        .await
        .unwrap();
    let begin = h
        .svc
        .begin_enrollment(from_ip(
            BeginEnrollmentRequest {
                enrollment_token: created.enrollment_token.clone(),
            },
            local_ip(),
        ))
        .await
        .unwrap()
        .into_inner();
    let secret = support::secret_from_uri(&begin.totp_provisioning_uri);
    let complete = |code: String| {
        h.svc.complete_enrollment(from_ip(
            CompleteEnrollmentRequest {
                enrollment_token: created.enrollment_token.clone(),
                username: String::new(),
                display_name: String::new(),
                password: PASSWORD.into(),
                totp_code: code,
                webauthn_attestation: None,
            },
            local_ip(),
        ))
    };
    // A wrong code does not burn the token.
    assert_eq!(
        complete("000000".into()).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    complete(support::code(&secret, h.clock_now()))
        .await
        .unwrap();
    h.next_step();
    let e = complete(support::code(&secret, h.clock_now()))
        .await
        .unwrap_err();
    assert_eq!(e.message(), "invalid_credentials", "used twice");

    // An expired token is refused.
    let late = h
        .call(
            &token,
            paths::CREATE_ADMIN_ACCOUNT,
            CreateAdminAccountRequest {
                idempotency_key: String::new(),
                username: "late.admin".into(),
                display_name: String::new(),
                groups: vec!["ferrogate-viewers".into()],
                proof: h.proof(&root),
                enrollment_ttl_secs: 3600,
            },
            |svc, r| Box::pin(async move { svc.create_admin_account(r).await }),
        )
        .await
        .unwrap();
    h.clock.advance(3601);
    let e = h
        .svc
        .begin_enrollment(from_ip(
            BeginEnrollmentRequest {
                enrollment_token: late.enrollment_token,
            },
            local_ip(),
        ))
        .await
        .unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
}

#[tokio::test]
async fn separation_of_duties_rules_three_and_four_always_hold() {
    let h = support::harness("flow-sod").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;

    // Rule 3: nobody changes their own groups or state, or resets themself.
    let e = h
        .call(
            &token,
            paths::UPDATE_ADMIN_ACCOUNT,
            UpdateAdminAccountRequest {
                idempotency_key: String::new(),
                admin_id: root.admin_id.clone(),
                expected_row_version: 1,
                display_name: None,
                replace_groups: true,
                groups: vec!["ferrogate-viewers".into()],
                proof: h.proof(&root),
            },
            |svc, r| Box::pin(async move { svc.update_admin_account(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::PermissionDenied, "sod_violation")
    );
    let e = h
        .call(
            &token,
            paths::SET_ADMIN_ACCOUNT_STATE,
            SetAdminAccountStateRequest {
                idempotency_key: String::new(),
                admin_id: root.admin_id.clone(),
                state: 3,
                proof: h.proof(&root),
            },
            |svc, r| Box::pin(async move { svc.set_admin_account_state(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.message(), "sod_violation");
    let e = h
        .call(
            &token,
            paths::RESET_ADMIN_CREDENTIALS,
            ResetAdminCredentialsRequest {
                idempotency_key: String::new(),
                admin_id: root.admin_id.clone(),
                reset_password: true,
                reset_mfa: false,
                proof: h.proof(&root),
            },
            |svc, r| Box::pin(async move { svc.reset_admin_credentials(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.message(), "sod_violation");

    // Rule 4: a second account admin cannot disable the last *other* one
    // once it would leave none; first create the second admin.
    let second = h
        .create_and_enroll(&root, &token, "second.admin", &["ferrogate-account-admins"])
        .await;
    let second_token = h.login(&second).await;
    // `second` disables `root`: allowed (one active account admin remains).
    h.call(
        &second_token,
        paths::SET_ADMIN_ACCOUNT_STATE,
        SetAdminAccountStateRequest {
            idempotency_key: String::new(),
            admin_id: root.admin_id.clone(),
            state: 3,
            proof: h.proof(&second),
        },
        |svc, r| Box::pin(async move { svc.set_admin_account_state(r).await }),
    )
    .await
    .unwrap();
    // Disabling revoked every session of root.
    let e = h
        .call(&token, paths::WHO_AM_I, WhoAmIRequest {}, |svc, r| {
            Box::pin(async move { svc.who_am_i(r).await })
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);
    // And root can no longer sign in.
    assert!(h.login_from(&root, PASSWORD, local_ip()).await.is_err());
}

#[tokio::test]
async fn strict_separation_of_duties_is_off_by_default_and_enforceable() {
    let make = |strict: bool, tag: &'static str| async move {
        let h = support::harness_with(tag, |c| c.strict_sod = strict).await;
        let root = support::bootstrap(&h, "root-admin").await;
        let token = h.login(&root).await;
        let r = h
            .call(
                &token,
                paths::CREATE_ADMIN_ACCOUNT,
                CreateAdminAccountRequest {
                    idempotency_key: String::new(),
                    username: "dual.role".into(),
                    display_name: String::new(),
                    groups: vec![
                        "ferrogate-account-admins".into(),
                        "ferrogate-approvers".into(),
                    ],
                    proof: h.proof(&root),
                    enrollment_ttl_secs: 0,
                },
                |svc, r| Box::pin(async move { svc.create_admin_account(r).await }),
            )
            .await;
        (r.map(|_| ()), h)
    };
    let (default_result, _h) = make(false, "flow-sod-off").await;
    default_result.expect("default policy allows the combination");
    let (strict_result, h) = make(true, "flow-sod-on").await;
    let e = strict_result.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::PermissionDenied, "sod_violation")
    );
    // Under the strict policy bootstrap grants account administration only.
    let groups = h.cmis.cluster().admin_accounts().await.unwrap();
    let root_groups = h
        .cmis
        .cluster()
        .admin_groups_of(&groups[0].admin_id)
        .await
        .unwrap();
    assert_eq!(root_groups, ["ferrogate-account-admins"]);
    assert!(h
        .audit_events()
        .iter()
        .any(|e| matches!(e, AuditEvent::AdminSodModeChanged { strict: true })));
}

#[tokio::test]
async fn a_group_change_takes_effect_on_the_next_call() {
    let h = support::harness("flow-groups").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let ops = h
        .create_and_enroll(
            &root,
            &token,
            "ops.person",
            &["ferrogate-platform-operators"],
        )
        .await;
    let ops_token = h.login(&ops).await;
    let list = |t: String| {
        let h = &h;
        async move {
            h.authorized(&t, paths::LIST_SVIDS, (), local_ip())
                .await
                .map(|_| ())
        }
    };
    list(ops_token.clone()).await.unwrap();
    let accounts = h
        .call(
            &token,
            paths::LIST_ADMIN_ACCOUNTS,
            ListAdminAccountsRequest {},
            |svc, r| Box::pin(async move { svc.list_admin_accounts(r).await }),
        )
        .await
        .unwrap();
    let row_version = accounts
        .accounts
        .iter()
        .find(|a| a.admin_id == ops.admin_id)
        .unwrap()
        .row_version;
    h.call(
        &token,
        paths::UPDATE_ADMIN_ACCOUNT,
        UpdateAdminAccountRequest {
            idempotency_key: String::new(),
            admin_id: ops.admin_id.clone(),
            expected_row_version: row_version,
            display_name: None,
            replace_groups: true,
            groups: vec!["ferrogate-viewers".into()],
            proof: h.proof(&root),
        },
        |svc, r| Box::pin(async move { svc.update_admin_account(r).await }),
    )
    .await
    .unwrap();
    // The old session was revoked; a new one lacks the permission.
    assert_eq!(
        list(ops_token).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    let new_token = h.login(&ops).await;
    assert_eq!(
        list(new_token).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    // A stale row version is refused.
    let e = h
        .call(
            &token,
            paths::UPDATE_ADMIN_ACCOUNT,
            UpdateAdminAccountRequest {
                idempotency_key: String::new(),
                admin_id: ops.admin_id.clone(),
                expected_row_version: row_version,
                display_name: Some("Renamed".into()),
                replace_groups: false,
                groups: vec![],
                proof: h.proof(&root),
            },
            |svc, r| Box::pin(async move { svc.update_admin_account(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::Aborted, "row_version_mismatch")
    );
}

#[tokio::test]
async fn an_expired_password_restricts_the_session_until_it_changes() {
    let h = support::harness("flow-expired").await;
    let root = support::bootstrap(&h, "root-admin").await;
    h.clock.advance(181 * 86_400);
    let token = h.login(&root).await;
    let who = h
        .call(&token, paths::WHO_AM_I, WhoAmIRequest {}, |svc, r| {
            Box::pin(async move { svc.who_am_i(r).await })
        })
        .await
        .unwrap();
    assert!(who.restricted);
    let e = h
        .call(
            &token,
            paths::LIST_MY_SESSIONS,
            ListMySessionsRequest {},
            |svc, r| Box::pin(async move { svc.list_my_sessions(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "password_expired")
    );
    assert_eq!(
        h.authorized(&token, paths::LIST_SVIDS, (), local_ip())
            .await
            .unwrap_err()
            .message(),
        "password_expired"
    );
    let changed = h
        .call(
            &token,
            paths::CHANGE_PASSWORD,
            ChangePasswordRequest {
                current_password: PASSWORD.into(),
                new_password: PASSWORD2.into(),
                proof: h.proof(&root),
            },
            |svc, r| Box::pin(async move { svc.change_password(r).await }),
        )
        .await
        .unwrap();
    h.call(
        &changed.session_token,
        paths::LIST_MY_SESSIONS,
        ListMySessionsRequest {},
        |svc, r| Box::pin(async move { svc.list_my_sessions(r).await }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn five_failed_proofs_revoke_the_session() {
    let h = support::harness("flow-proofs").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    for i in 0..5 {
        let e = h
            .call(
                &token,
                paths::CREATE_ADMIN_ACCOUNT,
                CreateAdminAccountRequest {
                    idempotency_key: String::new(),
                    username: format!("x{i}-user"),
                    display_name: String::new(),
                    groups: vec!["ferrogate-viewers".into()],
                    proof: Some(ferro_proto::admin_v1::MfaProof {
                        f: Some(ferro_proto::admin_v1::mfa_proof::F::TotpCode(
                            "000000".into(),
                        )),
                        nonce: Vec::new(),
                    }),
                    enrollment_ttl_secs: 0,
                },
                |svc, r| Box::pin(async move { svc.create_admin_account(r).await }),
            )
            .await
            .unwrap_err();
        assert_eq!(e.message(), "invalid_credentials");
    }
    let e = h
        .call(&token, paths::WHO_AM_I, WhoAmIRequest {}, |svc, r| {
            Box::pin(async move { svc.who_am_i(r).await })
        })
        .await
        .unwrap_err();
    assert_eq!(
        e.code(),
        Code::Unauthenticated,
        "revoked after five failures"
    );
}

/// Every mutation records exactly one event of its kind, and no event carries
/// personal data or secrets.
#[tokio::test]
async fn admin_audit_events_are_exactly_once_and_pii_free() {
    let h = support::harness("flow-audit").await;
    let root: Admin1 = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let second = h
        .create_and_enroll(&root, &token, "second.person", &["ferrogate-viewers"])
        .await;
    let second_token = h.login(&second).await;
    let events = h.audit_events();
    let count = |f: &dyn Fn(&AuditEvent) -> bool| events.iter().filter(|e| f(e)).count();
    assert_eq!(
        count(&|e| matches!(e, AuditEvent::AdminBootstrapCompleted { .. })),
        1
    );
    assert_eq!(
        count(&|e| matches!(e, AuditEvent::AdminAccountCreated { .. })),
        1
    );
    assert_eq!(
        count(&|e| matches!(e, AuditEvent::AdminEnrollmentCompleted { .. })),
        1
    );
    assert_eq!(
        count(&|e| matches!(e, AuditEvent::AdminLoginSucceeded { .. })),
        2
    );

    let json = serde_json::to_string(&events).unwrap();
    for secret_or_pii in [
        "root-admin",
        "second.person",
        "First Operator",
        "Second Person",
        "127.0.0.1",
        PASSWORD,
        &token,
        &second_token,
    ] {
        assert!(
            !json.contains(secret_or_pii),
            "audit log leaks {secret_or_pii:?}"
        );
    }
}

#[tokio::test]
async fn a_sixth_login_evicts_the_oldest_session() {
    let h = support::harness("flow-evict").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let mut tokens = Vec::new();
    for _ in 0..6 {
        tokens.push(h.login(&root).await);
    }
    let who = |t: String| {
        let h = &h;
        async move {
            h.call(&t, paths::WHO_AM_I, WhoAmIRequest {}, |svc, r| {
                Box::pin(async move { svc.who_am_i(r).await })
            })
            .await
        }
    };
    assert_eq!(
        who(tokens[0].clone()).await.unwrap_err().code(),
        Code::Unauthenticated,
        "oldest evicted"
    );
    for t in &tokens[1..] {
        who(t.clone()).await.unwrap();
    }
    assert!(h.audit_events().iter().any(|e| matches!(
        e,
        AuditEvent::AdminSessionRevoked { reason, .. } if reason == "evicted"
    )));
}

#[tokio::test]
async fn begin_login_floods_are_limited_per_ip() {
    let h = support::harness("flow-flood").await;
    let ip: IpAddr = "203.0.113.5".parse().unwrap();
    let begin = |ip: IpAddr| {
        h.svc.begin_login(from_ip(
            BeginLoginRequest {
                username: "anyone".into(),
                device_token: String::new(),
                client: None,
            },
            ip,
        ))
    };
    for _ in 0..10 {
        begin(ip).await.unwrap();
    }
    let e = begin(ip).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::ResourceExhausted, "login_throttled")
    );
    begin("203.0.113.6".parse().unwrap())
        .await
        .expect("other addresses unaffected");
    h.clock.advance(60);
    begin(ip).await.expect("the window resets after a minute");
}

/// Review fix: a burst of parallel guesses cannot all pass the lock check
/// before the first failure is counted.
#[tokio::test]
async fn parallel_guesses_cannot_outrun_the_lock() {
    let h = support::harness("flow-parallel").await;
    support::bootstrap(&h, "root-admin").await;
    let ip: IpAddr = "192.0.2.77".parse().unwrap();
    let mut nonces = Vec::new();
    for _ in 0..10 {
        nonces.push(
            h.svc
                .begin_login(from_ip(
                    BeginLoginRequest {
                        username: "root-admin".into(),
                        device_token: String::new(),
                        client: None,
                    },
                    ip,
                ))
                .await
                .unwrap()
                .into_inner()
                .login_nonce,
        );
    }
    let attempts = nonces.into_iter().map(|nonce| {
        h.svc.login(from_ip(
            LoginRequest {
                login_nonce: nonce,
                username: "root-admin".into(),
                password: "Wrong-Password#0123456789x".into(),
                second_factor: Some(SecondFactor::TotpCode("000000".into())),
                device_token: String::new(),
                client: None,
            },
            ip,
        ))
    });
    let results = futures::future::join_all(attempts).await;
    let evaluated = results
        .iter()
        .filter(|r| r.as_ref().is_err_and(|e| e.code() == Code::Unauthenticated))
        .count();
    let throttled = results
        .iter()
        .filter(|r| {
            r.as_ref()
                .is_err_and(|e| e.code() == Code::ResourceExhausted)
        })
        .count();
    assert_eq!(
        (evaluated, throttled),
        (3, 7),
        "only three guesses before the lock"
    );
}

/// Review fix: every BeginEnrollment offers a fresh seed, so a copy taken by
/// someone else who saw the token stops working.
#[tokio::test]
async fn begin_enrollment_rotates_the_offered_seed() {
    let h = support::harness("flow-seed").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let created = h
        .call(
            &token,
            paths::CREATE_ADMIN_ACCOUNT,
            CreateAdminAccountRequest {
                idempotency_key: String::new(),
                username: "new.person".into(),
                display_name: String::new(),
                groups: vec!["ferrogate-viewers".into()],
                proof: h.proof(&root),
                enrollment_ttl_secs: 0,
            },
            |svc, r| Box::pin(async move { svc.create_admin_account(r).await }),
        )
        .await
        .unwrap();
    let begin = || {
        h.svc.begin_enrollment(from_ip(
            BeginEnrollmentRequest {
                enrollment_token: created.enrollment_token.clone(),
            },
            local_ip(),
        ))
    };
    let early =
        support::secret_from_uri(&begin().await.unwrap().into_inner().totp_provisioning_uri);
    let late = support::secret_from_uri(&begin().await.unwrap().into_inner().totp_provisioning_uri);
    assert_ne!(early, late, "each call offers a new seed");
    let complete = |secret: Vec<u8>| {
        let code = support::code(&secret, h.clock_now());
        h.svc.complete_enrollment(from_ip(
            CompleteEnrollmentRequest {
                enrollment_token: created.enrollment_token.clone(),
                username: String::new(),
                display_name: String::new(),
                password: PASSWORD.into(),
                totp_code: code,
                webauthn_attestation: None,
            },
            local_ip(),
        ))
    };
    assert_eq!(
        complete(early).await.unwrap_err().message(),
        "invalid_credentials"
    );
    complete(late).await.unwrap();
}

/// Review fix: a reset supersedes every earlier token of the account.
#[tokio::test]
async fn a_reset_supersedes_earlier_tokens() {
    let h = support::harness("flow-supersede").await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let created = h
        .call(
            &token,
            paths::CREATE_ADMIN_ACCOUNT,
            CreateAdminAccountRequest {
                idempotency_key: String::new(),
                username: "pending.person".into(),
                display_name: String::new(),
                groups: vec!["ferrogate-viewers".into()],
                proof: h.proof(&root),
                enrollment_ttl_secs: 0,
            },
            |svc, r| Box::pin(async move { svc.create_admin_account(r).await }),
        )
        .await
        .unwrap();
    let reset = h
        .call(
            &token,
            paths::RESET_ADMIN_CREDENTIALS,
            ResetAdminCredentialsRequest {
                idempotency_key: String::new(),
                admin_id: created.admin_id.clone(),
                reset_password: true,
                reset_mfa: true,
                proof: h.proof(&root),
            },
            |svc, r| Box::pin(async move { svc.reset_admin_credentials(r).await }),
        )
        .await
        .unwrap();
    let begin = |t: String| {
        h.svc.begin_enrollment(from_ip(
            BeginEnrollmentRequest {
                enrollment_token: t,
            },
            local_ip(),
        ))
    };
    assert_eq!(
        begin(created.enrollment_token).await.unwrap_err().message(),
        "invalid_credentials",
        "the original enrollment token no longer works"
    );
    begin(reset.enrollment_token).await.unwrap();
}

/// Review fix: requests without a valid nonce never reach the account and
/// count against their source only, so junk traffic cannot lock out a known
/// administrator through the account counter.
#[tokio::test]
async fn junk_logins_without_a_nonce_do_not_lock_the_account() {
    let h = support::harness("flow-junk").await;
    let root = support::bootstrap(&h, "root-admin").await;
    for i in 1..=5u8 {
        let ip: IpAddr = format!("198.51.100.{i}").parse().unwrap();
        for _ in 0..2 {
            let e = h
                .svc
                .login(from_ip(
                    LoginRequest {
                        login_nonce: vec![0; 40],
                        username: "root-admin".into(),
                        password: "junk".into(),
                        second_factor: Some(SecondFactor::TotpCode("000000".into())),
                        device_token: String::new(),
                        client: None,
                    },
                    ip,
                ))
                .await
                .unwrap_err();
            assert_eq!(e.message(), "invalid_credentials");
        }
    }
    // Ten junk attempts (> the 9 that lock K_acct) — the real admin still signs in.
    h.login_from(&root, PASSWORD, "198.51.100.200".parse().unwrap())
        .await
        .expect("account counter untouched by nonce-less junk");
}
