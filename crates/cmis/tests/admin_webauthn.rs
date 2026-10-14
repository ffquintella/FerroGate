//! F20 wave B: the FIDO2 / WebAuthn second factor on the `Admin` service,
//! driven by a software authenticator that produces real ES256 / EdDSA
//! attestations and assertions: enrollment, login, step-up, per-operation
//! proofs, factor management, clone detection and the
//! `CMIS_ADMIN_TRAY_FIDO2_GROUPS` policy.

#![allow(clippy::large_futures, clippy::too_many_lines)]

mod support;

use cmis::admin::authz::paths;
use ferro_audit::AuditEvent;
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::login_request::SecondFactor;
use ferro_proto::admin_v1::{
    BeginAddFactorRequest, BeginEnrollmentRequest, BeginStepUpRequest, ChangePasswordRequest,
    CompleteAddFactorRequest, CompleteEnrollmentRequest, CreateAdminAccountRequest,
    ListMyFactorsRequest, ListMySessionsRequest, MfaProof, RemoveFactorRequest,
    ResetAdminCredentialsRequest, StepUpRequest, WhoAmIRequest,
};
use support::soft_authenticator::{SoftAuthenticator, UP};
use support::{
    assertion, attestation, from_ip, local_ip, webauthn_proof, Admin1, Harness, CLI, ORIGIN, RP_ID,
    TRAY, TUI,
};
use tonic::Code;

const VIEWERS: &str = "ferrogate-viewers";
const APPROVERS: &str = "ferrogate-approvers";

async fn who_am_i(
    h: &Harness,
    token: &str,
) -> Result<ferro_proto::admin_v1::WhoAmIResponse, tonic::Status> {
    h.call(token, paths::WHO_AM_I, WhoAmIRequest {}, |svc, r| {
        Box::pin(async move { svc.who_am_i(r).await })
    })
    .await
}

async fn factors(h: &Harness, token: &str) -> Vec<ferro_proto::admin_v1::FactorInfo> {
    h.call(
        token,
        paths::LIST_MY_FACTORS,
        ListMyFactorsRequest {},
        |svc, r| Box::pin(async move { svc.list_my_factors(r).await }),
    )
    .await
    .unwrap()
    .factors
}

/// Begin and complete adding `key` to the account of `token`, proving an
/// existing factor with `proof`.
async fn add_key(
    h: &Harness,
    token: &str,
    key: &SoftAuthenticator,
    proof: Option<MfaProof>,
) -> Result<String, tonic::Status> {
    let begin = h
        .call(
            token,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 2 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await?;
    let options = begin.webauthn_creation_options.expect("creation options");
    let reg = key.make_credential(&options.rp_id, ORIGIN, &options.challenge);
    h.call(
        token,
        paths::COMPLETE_ADD_FACTOR,
        CompleteAddFactorRequest {
            idempotency_key: String::new(),
            enroll_nonce: begin.enroll_nonce,
            label: "Backup key".into(),
            totp_code: String::new(),
            webauthn_attestation: Some(attestation(&reg, "")),
            proof,
        },
        |svc, r| Box::pin(async move { svc.complete_add_factor(r).await }),
    )
    .await
    .map(|r| r.factor_id)
}

async fn remove(
    h: &Harness,
    token: &str,
    factor_id: &str,
    proof: Option<MfaProof>,
) -> Result<(), tonic::Status> {
    h.call(
        token,
        paths::REMOVE_FACTOR,
        RemoveFactorRequest {
            idempotency_key: String::new(),
            factor_id: factor_id.into(),
            proof,
        },
        |svc, r| Box::pin(async move { svc.remove_factor(r).await }),
    )
    .await
    .map(|_| ())
}

async fn with_root(tag: &str) -> (Harness, Admin1, String) {
    let h = support::harness(tag).await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    (h, root, token)
}

/// F20 Testing strategy, "FIDO2 enrollment and login flow": enrollment with
/// TOTP **and** a key (both stored), login and step-up with the key, and the
/// same account still signing in with TOTP from the CLI.
#[tokio::test]
async fn enroll_both_factors_then_log_in_and_step_up_with_the_key() {
    let (h, root, token) = with_root("wa-flow").await;
    let mut key = SoftAuthenticator::es256(3);

    // The creation options follow the spec.
    let created = h
        .call(
            &token,
            paths::CREATE_ADMIN_ACCOUNT,
            CreateAdminAccountRequest {
                idempotency_key: String::new(),
                username: "key.holder".into(),
                display_name: "Key Holder".into(),
                groups: vec![VIEWERS.into()],
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
    let options = begin.webauthn_creation_options.clone().unwrap();
    assert_eq!(options.rp_id, RP_ID);
    assert_eq!(options.user_name, "key.holder");
    assert_eq!(options.pub_key_cred_params, [-7, -8]);
    assert_eq!((options.user_verification, options.attestation), (1, 1));
    assert!(options.challenge.len() >= 32);
    assert!(
        !options.user_id.is_empty() && options.user_id != created.admin_id.as_bytes(),
        "the user handle is opaque"
    );
    let secret = support::secret_from_uri(&begin.totp_provisioning_uri);
    let reg = key.make_credential(RP_ID, ORIGIN, &options.challenge);
    h.svc
        .complete_enrollment(from_ip(
            CompleteEnrollmentRequest {
                enrollment_token: created.enrollment_token,
                username: String::new(),
                display_name: String::new(),
                password: support::PASSWORD.into(),
                totp_code: support::code(&secret, h.clock_now()),
                webauthn_attestation: Some(attestation(&reg, "YubiKey 5\u{202E}")),
            },
            local_ip(),
        ))
        .await
        .unwrap();
    let holder = Admin1 {
        admin_id: created.admin_id.clone(),
        username: "key.holder".into(),
        secret,
    };

    // The tray offers both methods, with the real credential id.
    let offer = h.begin_login_as("key.holder", TRAY).await;
    assert_eq!(offer.methods, [1, 2]);
    let challenge = offer.webauthn.clone().unwrap();
    assert_eq!(challenge.rp_id, RP_ID);
    assert_eq!(
        challenge.allow_credential_ids,
        std::slice::from_ref(&key.credential_id)
    );
    assert_eq!(challenge.user_verification, 1);
    // The TUI and CLI are offered TOTP only (no CTAP over SSH).
    for kind in [TUI, CLI] {
        let offer = h.begin_login_as("key.holder", kind).await;
        assert_eq!(offer.methods, [1]);
        assert!(offer.webauthn.is_none());
    }

    // Login with the key: AAL3.
    let session = h.login_key(&holder, &mut key).await.unwrap();
    assert_eq!(session.aal, 3);
    assert!(!session.factor_enrollment_required);
    let listed = factors(&h, &session.session_token).await;
    assert_eq!(listed.len(), 2, "TOTP and the key are both stored");
    let key_factor = listed.iter().find(|f| f.method == 2).unwrap();
    assert_eq!(key_factor.label, "YubiKey 5", "the label is cleaned");
    assert!(key_factor.last_used_at > 0);

    // Step-up with the key rotates the token.
    let begin = h
        .call(
            &session.session_token,
            paths::BEGIN_STEP_UP,
            BeginStepUpRequest {},
            |svc, r| Box::pin(async move { svc.begin_step_up(r).await }),
        )
        .await
        .unwrap();
    let a = key.get_assertion(RP_ID, ORIGIN, &begin.webauthn.unwrap().challenge);
    let stepped = h
        .call(
            &session.session_token,
            paths::STEP_UP,
            StepUpRequest {
                stepup_nonce: begin.stepup_nonce,
                proof: Some(MfaProof {
                    f: Some(ferro_proto::admin_v1::mfa_proof::F::WebauthnAssertion(
                        assertion(&a),
                    )),
                    nonce: Vec::new(),
                }),
            },
            |svc, r| Box::pin(async move { svc.step_up(r).await }),
        )
        .await
        .unwrap();
    assert_ne!(stepped.session_token, session.session_token);
    assert_eq!(who_am_i(&h, &stepped.session_token).await.unwrap().aal, 3);
    assert_eq!(
        who_am_i(&h, &session.session_token)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated,
        "the old token is gone"
    );

    // An account holding both factors can use either: TOTP from the CLI.
    let cli = h.login_totp_as(&holder, CLI).await.unwrap();
    assert_eq!(cli.aal, 2);

    let events = h.audit_events();
    let enrolled: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::AdminMfaEnrolled { admin_id, method } if *admin_id == created.admin_id => {
                Some(method.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        enrolled,
        ["totp", "webauthn"],
        "F20 §5: each enrolled factor is audited"
    );
    assert!(events.iter().any(|e| matches!(
        e,
        AuditEvent::AdminLoginSucceeded { admin_id, aal: 3, mfa_method, client_kind: 2, .. }
            if *admin_id == created.admin_id && mfa_method == "webauthn"
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        AuditEvent::AdminStepUp { mfa_method, success: true, .. } if mfa_method == "webauthn"
    )));
    let json = serde_json::to_string(&events).unwrap();
    for leak in [
        hex::encode(&key.credential_id),
        hex::encode(&a.signature),
        "YubiKey".to_string(),
        "key.holder".to_string(),
    ] {
        assert!(!json.contains(&leak), "audit leaks {leak}");
    }
}

/// Wrong origin, wrong RP ID, a missing user-verification flag and a
/// different challenge are all the same generic failure.
#[tokio::test]
async fn a_wrong_origin_rp_id_or_missing_uv_is_refused_at_login() {
    let (h, root, token) = with_root("wa-bad").await;
    let mut key = SoftAuthenticator::es256(4);
    let holder = h
        .create_and_enroll_key(&root, &token, "key.holder", &[VIEWERS], &key, false)
        .await;

    let tries: Vec<(&str, &str, u8, bool)> = vec![
        (RP_ID, "https://evil.example", 0x05, false),
        ("evil.example", ORIGIN, 0x05, false),
        (RP_ID, ORIGIN, UP, false),
        (RP_ID, ORIGIN, 0x05, true),
    ];
    for (rp_id, origin, flags, other_challenge) in tries {
        let begin = h.begin_login_as("key.holder", TRAY).await;
        let mut challenge = begin.webauthn.unwrap().challenge;
        if other_challenge {
            challenge[0] ^= 1;
        }
        key.counter += 1;
        let a = key.get_assertion_with(rp_id, origin, &challenge, flags, key.counter);
        let e = h
            .login_with(
                &holder,
                TRAY,
                begin.login_nonce,
                SecondFactor::WebauthnAssertion(assertion(&a)),
            )
            .await
            .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (Code::Unauthenticated, "invalid_credentials"),
            "{rp_id} {origin} {flags:#x}"
        );
        h.clock.advance(61); // stay clear of the IP lock
    }
    // The right ceremony still works.
    assert_eq!(h.login_key(&holder, &mut key).await.unwrap().aal, 3);
}

/// A challenge is single use: replaying an assertion, with its nonce or
/// with a fresh one, fails.
#[tokio::test]
async fn a_replayed_assertion_is_refused() {
    let (h, root, token) = with_root("wa-replay").await;
    let mut key = SoftAuthenticator::ed25519(5);
    let holder = h
        .create_and_enroll_key(&root, &token, "key.holder", &[VIEWERS], &key, false)
        .await;
    let begin = h.begin_login_as("key.holder", TRAY).await;
    let a = key.get_assertion(RP_ID, ORIGIN, &begin.webauthn.unwrap().challenge);
    h.login_with(
        &holder,
        TRAY,
        begin.login_nonce.clone(),
        SecondFactor::WebauthnAssertion(assertion(&a)),
    )
    .await
    .unwrap();
    // Same nonce, same assertion.
    let e = h
        .login_with(
            &holder,
            TRAY,
            begin.login_nonce,
            SecondFactor::WebauthnAssertion(assertion(&a)),
        )
        .await
        .unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
    // A fresh nonce cannot adopt the old assertion.
    let fresh = h.begin_login_as("key.holder", TRAY).await;
    let e = h
        .login_with(
            &holder,
            TRAY,
            fresh.login_nonce,
            SecondFactor::WebauthnAssertion(assertion(&a)),
        )
        .await
        .unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
}

/// A valid signature with a counter that went backwards is refused and
/// raises the clone-detection audit event.
#[tokio::test]
async fn a_counter_regression_is_refused_as_a_possible_clone() {
    let (h, root, token) = with_root("wa-clone").await;
    let mut key = SoftAuthenticator::es256(6);
    let holder = h
        .create_and_enroll_key(&root, &token, "key.holder", &[VIEWERS], &key, false)
        .await;
    key.counter = 40;
    h.login_key(&holder, &mut key).await.unwrap();
    let mut clone = SoftAuthenticator::es256(6);
    clone.counter = 10;
    let e = h.login_key(&holder, &mut clone).await.unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
    let clones: Vec<_> = h
        .audit_events()
        .into_iter()
        .filter(|e| matches!(e, AuditEvent::AdminWebAuthnCloneDetected { admin_id, .. } if *admin_id == holder.admin_id))
        .collect();
    assert_eq!(clones.len(), 1);
    // The genuine key, still ahead, keeps working.
    h.clock.advance(61);
    h.login_key(&holder, &mut key).await.unwrap();
}

/// An assertion made with someone else's registered key is refused.
#[tokio::test]
async fn another_accounts_credential_is_refused() {
    let (h, root, token) = with_root("wa-other").await;
    let mine = SoftAuthenticator::es256(7);
    let mut theirs = SoftAuthenticator::es256(8);
    let me = h
        .create_and_enroll_key(&root, &token, "first.holder", &[VIEWERS], &mine, false)
        .await;
    h.create_and_enroll_key(&root, &token, "second.holder", &[VIEWERS], &theirs, false)
        .await;
    let e = h.login_key(&me, &mut theirs).await.unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
}

/// FIDO2 is offered only to the tray: an assertion from a TUI or CLI
/// client is refused.
#[tokio::test]
async fn an_assertion_from_the_tui_or_cli_is_refused() {
    let (h, root, token) = with_root("wa-kind").await;
    let mut key = SoftAuthenticator::es256(9);
    let holder = h
        .create_and_enroll_key(&root, &token, "key.holder", &[VIEWERS], &key, true)
        .await;
    for kind in [TUI, CLI] {
        let tray = h.begin_login_as("key.holder", TRAY).await;
        let a = key.get_assertion(RP_ID, ORIGIN, &tray.webauthn.unwrap().challenge);
        // Same nonce binding (IP + username); only the declared client differs.
        let e = h
            .login_with(
                &holder,
                kind,
                tray.login_nonce,
                SecondFactor::WebauthnAssertion(assertion(&a)),
            )
            .await
            .unwrap_err();
        assert_eq!(e.message(), "invalid_credentials", "kind {kind}");
    }
}

/// Unknown usernames get a plausible tray offer: the shapes real accounts
/// produce (TOTP only, both, or keys only), stable per username,
/// with decoy credential ids that do not reveal real ones. A TOTP-only
/// account is therefore not told apart from an unknown name.
#[tokio::test]
async fn unknown_usernames_get_plausible_offers_with_decoys() {
    let (h, root, token) = with_root("wa-decoy").await;
    let key = SoftAuthenticator::es256(10);
    h.create_and_enroll_key(&root, &token, "key.holder", &[VIEWERS], &key, true)
        .await;
    let totp_only = h.begin_login_as("root-admin", TRAY).await;
    assert_eq!(totp_only.methods, [1]);
    assert!(totp_only.webauthn.is_none());

    let mut shapes = std::collections::BTreeSet::new();
    let mut decoy_lengths = std::collections::BTreeSet::new();
    for i in 0..12 {
        h.clock.advance(61); // BeginLogin is limited to 10 a minute per IP
        let name = format!("ghost-{i}");
        let a = h.begin_login_as(&name, TRAY).await;
        let b = h.begin_login_as(&name, TRAY).await;
        assert_eq!(a.methods, b.methods, "stable per username");
        assert!(
            a.methods == [1] || a.methods == [1, 2] || a.methods == [2],
            "{:?}",
            a.methods
        );
        assert_eq!(a.webauthn.is_some(), a.methods.contains(&2));
        if let (Some(x), Some(y)) = (a.webauthn, b.webauthn) {
            assert_ne!(x.allow_credential_ids.len(), 0);
            assert_eq!(
                x.allow_credential_ids, y.allow_credential_ids,
                "decoys are stable"
            );
            assert_ne!(x.challenge, y.challenge, "challenges are fresh");
            assert!(!x.allow_credential_ids.contains(&key.credential_id));
            decoy_lengths.extend(x.allow_credential_ids.iter().map(Vec::len));
        }
        shapes.insert(a.methods);
    }
    assert!(shapes.len() >= 2, "unknown names do not share one shape");
    assert!(
        decoy_lengths.len() >= 2,
        "decoy ids vary in length like real ones: {decoy_lengths:?}"
    );
}

/// F20 §5 policy: a tray login of a CMIS_ADMIN_TRAY_FIDO2_GROUPS member
/// accepts only a key; without a key, TOTP gives an enrollment-only
/// session. TUI and CLI sessions keep TOTP.
#[tokio::test]
async fn the_tray_fido2_policy_holds_listed_groups_to_their_keys() {
    let h = support::harness_with("wa-policy", |c| {
        c.tray_fido2_groups = vec![APPROVERS.to_string()];
    })
    .await;
    let root = support::bootstrap(&h, "root-admin").await;
    let token = h.login(&root).await;
    let approver = h
        .create_and_enroll(&root, &token, "an.approver", &[APPROVERS])
        .await;
    let viewer = h
        .create_and_enroll(&root, &token, "a.viewer", &[VIEWERS])
        .await;

    // Not listed: a plain TOTP tray session.
    let v = h.login_totp_as(&viewer, TRAY).await.unwrap();
    assert!(!v.factor_enrollment_required);

    // Listed, no key yet: TOTP from the tray gives an enrollment-only session.
    let offer = h.begin_login_as("an.approver", TRAY).await;
    assert_eq!(offer.methods, [1]);
    let restricted = h.login_totp_as(&approver, TRAY).await.unwrap();
    assert!(restricted.factor_enrollment_required);
    assert_eq!(restricted.aal, 2);
    let who = who_am_i(&h, &restricted.session_token).await.unwrap();
    assert!(who.factor_enrollment_required);
    let e = h
        .call(
            &restricted.session_token,
            paths::LIST_MY_SESSIONS,
            ListMySessionsRequest {},
            |svc, r| Box::pin(async move { svc.list_my_sessions(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "factor_enrollment_required")
    );
    assert_eq!(
        h.authorized(&restricted.session_token, paths::LIST_SVIDS, (), local_ip())
            .await
            .unwrap_err()
            .message(),
        "factor_enrollment_required"
    );
    // ... but may register a key, proving possession of the TOTP factor.
    let mut key = SoftAuthenticator::es256(11);
    add_key(&h, &restricted.session_token, &key, h.proof(&approver))
        .await
        .unwrap();
    assert!(
        who_am_i(&h, &restricted.session_token)
            .await
            .unwrap()
            .factor_enrollment_required,
        "the TOTP session stays restricted; the holder signs in with the key"
    );

    // Listed, with a key: the tray offers and accepts only the key.
    let offer = h.begin_login_as("an.approver", TRAY).await;
    assert_eq!(offer.methods, [2]);
    let e = h.login_totp_as(&approver, TRAY).await.unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
    let full = h.login_key(&approver, &mut key).await.unwrap();
    assert_eq!(full.aal, 3);
    assert!(!full.factor_enrollment_required);
    h.call(
        &full.session_token,
        paths::LIST_MY_SESSIONS,
        ListMySessionsRequest {},
        |svc, r| Box::pin(async move { svc.list_my_sessions(r).await }),
    )
    .await
    .unwrap();
    // Step-up and proofs from that tray session are key-only too.
    let e = h
        .call(
            &full.session_token,
            paths::CHANGE_PASSWORD,
            ChangePasswordRequest {
                current_password: support::PASSWORD.into(),
                new_password: "Another-Valid#Passphrase_2049xyz".into(),
                proof: h.proof(&approver),
            },
            |svc, r| Box::pin(async move { svc.change_password(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");

    // The TUI and CLI keep TOTP (AAL2), unrestricted.
    for kind in [TUI, CLI] {
        let s = h.login_totp_as(&approver, kind).await.unwrap();
        assert_eq!(s.aal, 2);
        assert!(!s.factor_enrollment_required);
    }
}

/// Adding and removing factors: a recent step-up to begin, a per-operation
/// proof of an existing factor to complete, never the last factor, one audit
/// event each, and removal ends the other sessions.
#[tokio::test]
async fn factor_management_needs_step_up_proofs_and_keeps_one_factor() {
    let (h, root, _) = with_root("wa-manage").await;
    let token = h.login(&root).await;
    let mut key = SoftAuthenticator::es256(12);

    // Without a recent step-up, BeginAddFactor is refused.
    h.clock.advance(400);
    let stale = h
        .call(
            &token,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 2 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (stale.code(), stale.message()),
        (Code::FailedPrecondition, "step_up_required")
    );

    // A fresh login (tray, TOTP) can begin; completing needs the proof.
    let tray = h.login_totp_as(&root, TRAY).await.unwrap().session_token;
    let e = add_key(&h, &tray, &key, None).await.unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
    let key_id = add_key(&h, &tray, &key, h.proof(&root)).await.unwrap();
    assert!(key_id.starts_with("wa_"));
    let listed = factors(&h, &tray).await;
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed.iter().find(|f| f.factor_id == key_id).unwrap().label,
        "Backup key"
    );

    // The CLI cannot begin a FIDO2 registration (no authenticator there).
    let cli = h.login_totp_as(&root, CLI).await.unwrap().session_token;
    let e = h
        .call(
            &cli,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 2 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);

    // Removing needs a proof; a recent step-up does not substitute.
    let e = remove(&h, &tray, "totp", None).await.unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
    // Remove TOTP with a key proof: the key is now the only factor.
    let proof = webauthn_proof(&h, &tray, &mut key).await;
    remove(&h, &tray, "totp", proof).await.unwrap();
    assert_eq!(
        who_am_i(&h, &cli).await.unwrap_err().code(),
        Code::Unauthenticated,
        "removing a factor ends the other sessions"
    );
    let left = factors(&h, &tray).await;
    assert_eq!(left.len(), 1);
    let proof = webauthn_proof(&h, &tray, &mut key).await;
    let e = remove(&h, &tray, &key_id, proof).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "last_factor")
    );
    let e = remove(&h, &tray, "wa_doesnotexist", None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);

    // Add TOTP back to the key-only account (proof by the key).
    let begin = h
        .call(
            &tray,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 1 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await
        .unwrap();
    let secret = support::secret_from_uri(&begin.totp_provisioning_uri);
    let proof = webauthn_proof(&h, &tray, &mut key).await;
    h.call(
        &tray,
        paths::COMPLETE_ADD_FACTOR,
        CompleteAddFactorRequest {
            idempotency_key: String::new(),
            enroll_nonce: begin.enroll_nonce,
            label: String::new(),
            totp_code: support::code(&secret, h.clock_now()),
            webauthn_attestation: None,
            proof,
        },
        |svc, r| Box::pin(async move { svc.complete_add_factor(r).await }),
    )
    .await
    .unwrap();
    assert_eq!(factors(&h, &tray).await.len(), 2);

    let events = h.audit_events();
    let enrolled = events
        .iter()
        .filter(|e| matches!(e, AuditEvent::AdminMfaEnrolled { .. }))
        .count();
    let removed = events
        .iter()
        .filter(|e| matches!(e, AuditEvent::AdminMfaRemoved { method, by_admin_id: None, .. } if method == "totp"))
        .count();
    assert_eq!((enrolled, removed), (2, 1));
}

/// An attestation replayed against a new add-factor challenge is refused,
/// and so is a credential already registered.
#[tokio::test]
async fn a_replayed_attestation_or_registered_key_is_refused() {
    let (h, root, _) = with_root("wa-att-replay").await;
    let tray = h.login_totp_as(&root, TRAY).await.unwrap().session_token;
    let key = SoftAuthenticator::es256(13);
    let first = h
        .call(
            &tray,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 2 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await
        .unwrap();
    let reg = key.make_credential(
        RP_ID,
        ORIGIN,
        &first.webauthn_creation_options.unwrap().challenge,
    );
    let second = h
        .call(
            &tray,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 2 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await
        .unwrap();
    let complete = |nonce: Vec<u8>, proof| CompleteAddFactorRequest {
        idempotency_key: String::new(),
        enroll_nonce: nonce,
        label: String::new(),
        totp_code: String::new(),
        webauthn_attestation: Some(attestation(&reg, "k")),
        proof,
    };
    let e = h
        .call(
            &tray,
            paths::COMPLETE_ADD_FACTOR,
            complete(second.enroll_nonce.clone(), h.proof(&root)),
            |svc, r| Box::pin(async move { svc.complete_add_factor(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        e.message(),
        "invalid_credentials",
        "challenge of another nonce"
    );
    h.call(
        &tray,
        paths::COMPLETE_ADD_FACTOR,
        complete(first.enroll_nonce.clone(), h.proof(&root)),
        |svc, r| Box::pin(async move { svc.complete_add_factor(r).await }),
    )
    .await
    .unwrap();
    let e = h
        .call(
            &tray,
            paths::COMPLETE_ADD_FACTOR,
            complete(first.enroll_nonce, h.proof(&root)),
            |svc, r| Box::pin(async move { svc.complete_add_factor(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        e.message(),
        "invalid_credentials",
        "the nonce is single use"
    );
    // The same key again, on a fresh challenge: already registered.
    let third = h
        .call(
            &tray,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 2 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await
        .unwrap();
    let options = third.webauthn_creation_options.unwrap();
    assert_eq!(
        options.exclude_credential_ids,
        std::slice::from_ref(&key.credential_id)
    );
    let again = key.make_credential(RP_ID, ORIGIN, &options.challenge);
    let e = h
        .call(
            &tray,
            paths::COMPLETE_ADD_FACTOR,
            CompleteAddFactorRequest {
                idempotency_key: String::new(),
                enroll_nonce: third.enroll_nonce,
                label: String::new(),
                totp_code: String::new(),
                webauthn_attestation: Some(attestation(&again, "")),
                proof: h.proof(&root),
            },
            |svc, r| Box::pin(async move { svc.complete_add_factor(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::AlreadyExists);
}

/// A password-only reset of an account without TOTP could never be
/// completed (no proof of an enrolled factor): it is refused up front. A
/// full reset clears the keys.
#[tokio::test]
async fn resets_of_key_only_accounts_must_include_the_second_factor() {
    let (h, root, token) = with_root("wa-reset").await;
    let mut key = SoftAuthenticator::es256(14);
    let holder = h
        .create_and_enroll_key(&root, &token, "key.holder", &[VIEWERS], &key, false)
        .await;
    let reset = |mfa: bool| ResetAdminCredentialsRequest {
        idempotency_key: String::new(),
        admin_id: holder.admin_id.clone(),
        reset_password: true,
        reset_mfa: mfa,
        proof: h.proof(&root),
    };
    let e = h
        .call(
            &token,
            paths::RESET_ADMIN_CREDENTIALS,
            reset(false),
            |svc, r| Box::pin(async move { svc.reset_admin_credentials(r).await }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "reset_mfa_required")
    );
    h.call(
        &token,
        paths::RESET_ADMIN_CREDENTIALS,
        reset(true),
        |svc, r| Box::pin(async move { svc.reset_admin_credentials(r).await }),
    )
    .await
    .unwrap();
    assert!(
        h.login_key(&holder, &mut key).await.is_err(),
        "the key is gone"
    );
}

/// A call that carries no proof at all is refused without counting toward
/// the five-failures revocation (as in wave A): only wrong proofs count.
#[tokio::test]
async fn a_missing_proof_is_refused_without_counting_as_a_failure() {
    let (h, _root, token) = with_root("wa-noproof").await;
    for _ in 0..6 {
        let e = remove(&h, &token, "totp", None).await.unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition, "last_factor first");
        let e = h
            .call(
                &token,
                paths::CHANGE_PASSWORD,
                ChangePasswordRequest {
                    current_password: support::PASSWORD.into(),
                    new_password: "Another-Valid#Passphrase_2049xyz".into(),
                    proof: None,
                },
                |svc, r| Box::pin(async move { svc.change_password(r).await }),
            )
            .await
            .unwrap_err();
        assert_eq!(e.message(), "invalid_credentials");
    }
    who_am_i(&h, &token).await.unwrap();
}

/// A refused key registration during token enrollment can be retried on the
/// same offer, so the TOTP seed the person already scanned stays valid; an
/// over-long label is an argument error, not a credential failure. Only a
/// verified attestation consumes the challenge.
#[tokio::test]
async fn a_failed_enrollment_registration_can_be_retried_on_the_same_offer() {
    let (h, root, token) = with_root("wa-enroll-retry").await;
    let key = SoftAuthenticator::es256(15);
    let created = h
        .call(
            &token,
            paths::CREATE_ADMIN_ACCOUNT,
            CreateAdminAccountRequest {
                idempotency_key: String::new(),
                username: "key.holder".into(),
                display_name: String::new(),
                groups: vec![VIEWERS.into()],
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
    let challenge = begin.webauthn_creation_options.unwrap().challenge;
    let secret = support::secret_from_uri(&begin.totp_provisioning_uri);
    let complete =
        |reg: &support::soft_authenticator::Registration, label: &str| CompleteEnrollmentRequest {
            enrollment_token: created.enrollment_token.clone(),
            username: String::new(),
            display_name: String::new(),
            password: support::PASSWORD.into(),
            totp_code: support::code(&secret, h.clock_now()),
            webauthn_attestation: Some(attestation(reg, label)),
        };
    let good = key.make_credential(RP_ID, ORIGIN, &challenge);
    let e = h
        .svc
        .complete_enrollment(from_ip(complete(&good, &"k".repeat(65)), local_ip()))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    let bad = key.make_credential(RP_ID, "https://evil.example", &challenge);
    let e = h
        .svc
        .complete_enrollment(from_ip(complete(&bad, "k"), local_ip()))
        .await
        .unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");
    h.svc
        .complete_enrollment(from_ip(complete(&good, "k"), local_ip()))
        .await
        .unwrap();
}

/// A per-operation WebAuthn proof is single use even from an authenticator
/// without a signature counter (the counter cannot catch the replay; the
/// step-up nonce does), and is bound to the session that asked for it.
#[tokio::test]
async fn a_webauthn_proof_is_single_use_and_session_bound() {
    let (h, root, _) = with_root("wa-proof-once").await;
    let tray = h.login_totp_as(&root, TRAY).await.unwrap().session_token;
    let mut no_counter = SoftAuthenticator::ed25519(16);
    assert_eq!(no_counter.counter, 0);
    let other = SoftAuthenticator::es256(17);
    add_key(&h, &tray, &no_counter, h.proof(&root))
        .await
        .unwrap();
    let other_id = add_key(&h, &tray, &other, h.proof(&root)).await.unwrap();

    // Bound to the session: another session of the same account cannot use it.
    let second = h.login_totp_as(&root, TRAY).await.unwrap().session_token;
    let foreign = webauthn_proof(&h, &second, &mut no_counter).await;
    let e = remove(&h, &tray, &other_id, foreign).await.unwrap_err();
    assert_eq!(e.message(), "invalid_credentials");

    let proof = webauthn_proof(&h, &tray, &mut no_counter).await;
    remove(&h, &tray, &other_id, proof.clone()).await.unwrap();
    let e = remove(&h, &tray, "totp", proof).await.unwrap_err();
    assert_eq!(e.message(), "invalid_credentials", "a replayed proof fails");
}
