//! F20 §11: capture every log line (all levels, all targets) of a full
//! bootstrap → login → step-up → password change → logout run, then a FIDO2
//! key registration → key login → key step-up, and assert that no secret
//! value appears: passwords, TOTP secrets and codes, bootstrap, enrollment,
//! session and device tokens, and WebAuthn attestations and assertions.
//!
//! This file holds a single test because it installs a process-global
//! subscriber.

#![allow(clippy::large_futures)]

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use cmis::admin::authz::paths;
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::{
    login_request::SecondFactor, mfa_proof, BeginAddFactorRequest, BeginEnrollmentRequest,
    BeginLoginRequest, BeginStepUpRequest, ChangePasswordRequest, ClientInfo,
    CompleteAddFactorRequest, CompleteEnrollmentRequest, LoginRequest, LogoutRequest, MfaProof,
    StepUpRequest,
};
use support::soft_authenticator::SoftAuthenticator;
use support::{from_ip, local_ip};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn no_secret_reaches_the_logs() {
    let capture = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .with_ansi(false)
            // The formatter's own timestamp carries a 6-digit microsecond
            // fraction on every line, which would randomly equal a TOTP code
            // (~1 run in 20). It is not application output, so drop it.
            .without_time()
            .finish(),
    )
    .unwrap();

    let h = support::harness("logscan").await;
    let mut secrets: Vec<String> = vec![support::PASSWORD.into(), support::PASSWORD2.into()];

    // Bootstrap.
    cmis::admin::bootstrap::arm(&h.admin).await.unwrap();
    let bootstrap_token = std::fs::read_to_string(&h.bootstrap_file)
        .unwrap()
        .trim()
        .to_string();
    secrets.push(bootstrap_token.clone());
    let begin = h
        .svc
        .begin_enrollment(from_ip(
            BeginEnrollmentRequest {
                enrollment_token: bootstrap_token.clone(),
            },
            local_ip(),
        ))
        .await
        .unwrap()
        .into_inner();
    let uri_secret = begin
        .totp_provisioning_uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    secrets.push(uri_secret);
    let secret = support::secret_from_uri(&begin.totp_provisioning_uri);
    secrets.push(hex::encode(&secret));
    let mut codes = Vec::new();
    let c = support::code(&secret, h.clock_now());
    codes.push(c.clone());
    h.svc
        .complete_enrollment(from_ip(
            CompleteEnrollmentRequest {
                enrollment_token: bootstrap_token,
                username: "log.scan".into(),
                display_name: String::new(),
                password: support::PASSWORD.into(),
                totp_code: c,
                webauthn_attestation: None,
            },
            local_ip(),
        ))
        .await
        .unwrap();

    // A failed then a successful login.
    for (password, good) in [
        ("Wrong-Password#123456789x", false),
        (support::PASSWORD, true),
    ] {
        let nonce = h
            .svc
            .begin_login(from_ip(
                BeginLoginRequest {
                    username: "log.scan".into(),
                    device_token: String::new(),
                    client: None,
                },
                local_ip(),
            ))
            .await
            .unwrap()
            .into_inner()
            .login_nonce;
        h.next_step();
        let c = support::code(&secret, h.clock_now());
        codes.push(c.clone());
        secrets.push(password.to_string());
        let r = h
            .svc
            .login(from_ip(
                LoginRequest {
                    login_nonce: nonce,
                    username: "log.scan".into(),
                    password: password.into(),
                    second_factor: Some(SecondFactor::TotpCode(c)),
                    device_token: String::new(),
                    client: Some(ClientInfo {
                        kind: 3,
                        version: String::new(),
                    }),
                },
                local_ip(),
            ))
            .await;
        assert_eq!(r.is_ok(), good);
        if let Ok(resp) = r {
            let resp = resp.into_inner();
            secrets.push(resp.session_token.clone());
            secrets.push(resp.device_token.clone());
            secrets.push(resp.session_token.clone());
            secrets.retain(|s| !s.is_empty());
            // Step-up.
            let token = resp.session_token;
            let nonce = h
                .call(
                    &token,
                    paths::BEGIN_STEP_UP,
                    BeginStepUpRequest {},
                    |svc, r| Box::pin(async move { svc.begin_step_up(r).await }),
                )
                .await
                .unwrap()
                .stepup_nonce;
            let c = h.fresh_code(&support::Admin1 {
                admin_id: String::new(),
                username: String::new(),
                secret: secret.clone(),
            });
            codes.push(c.clone());
            let stepped = h
                .call(
                    &token,
                    paths::STEP_UP,
                    StepUpRequest {
                        stepup_nonce: nonce,
                        proof: Some(MfaProof {
                            f: Some(mfa_proof::F::TotpCode(c)),
                            nonce: Vec::new(),
                        }),
                    },
                    |svc, r| Box::pin(async move { svc.step_up(r).await }),
                )
                .await
                .unwrap();
            secrets.push(stepped.session_token.clone());
            // Password change.
            h.next_step();
            let c = support::code(&secret, h.clock_now());
            codes.push(c.clone());
            let changed = h
                .call(
                    &stepped.session_token,
                    paths::CHANGE_PASSWORD,
                    ChangePasswordRequest {
                        current_password: support::PASSWORD.into(),
                        new_password: support::PASSWORD2.into(),
                        proof: Some(MfaProof {
                            f: Some(mfa_proof::F::TotpCode(c)),
                            nonce: Vec::new(),
                        }),
                    },
                    |svc, r| Box::pin(async move { svc.change_password(r).await }),
                )
                .await
                .unwrap();
            secrets.push(changed.session_token.clone());
            // Logout.
            h.call(
                &changed.session_token,
                paths::LOGOUT,
                LogoutRequest {},
                |svc, r| Box::pin(async move { svc.logout(r).await }),
            )
            .await
            .unwrap();
        }
    }

    // FIDO2: register a key from a tray session, sign in and step up with it.
    let tray_login = |nonce: Vec<u8>, second: SecondFactor| LoginRequest {
        login_nonce: nonce,
        username: "log.scan".into(),
        password: support::PASSWORD2.into(),
        second_factor: Some(second),
        device_token: String::new(),
        client: Some(ClientInfo {
            kind: support::TRAY,
            version: String::new(),
        }),
    };
    let begin = h.begin_login_as("log.scan", support::TRAY).await;
    h.next_step();
    let c = support::code(&secret, h.clock_now());
    codes.push(c.clone());
    let tray = h
        .svc
        .login(from_ip(
            tray_login(begin.login_nonce, SecondFactor::TotpCode(c)),
            local_ip(),
        ))
        .await
        .unwrap()
        .into_inner();
    secrets.push(tray.session_token.clone());
    secrets.push(tray.device_token.clone());
    let mut key = SoftAuthenticator::es256(77);
    let add = h
        .call(
            &tray.session_token,
            paths::BEGIN_ADD_FACTOR,
            BeginAddFactorRequest { method: 2 },
            |svc, r| Box::pin(async move { svc.begin_add_factor(r).await }),
        )
        .await
        .unwrap();
    let reg = key.make_credential(
        support::RP_ID,
        support::ORIGIN,
        &add.webauthn_creation_options.unwrap().challenge,
    );
    secrets.push(hex::encode(&reg.attestation_object));
    secrets.push(support::soft_authenticator::b64url(&reg.attestation_object));
    h.next_step();
    let c = support::code(&secret, h.clock_now());
    codes.push(c.clone());
    h.call(
        &tray.session_token,
        paths::COMPLETE_ADD_FACTOR,
        CompleteAddFactorRequest {
            idempotency_key: String::new(),
            enroll_nonce: add.enroll_nonce,
            label: "scan key".into(),
            totp_code: String::new(),
            webauthn_attestation: Some(support::attestation(&reg, "")),
            proof: Some(MfaProof {
                f: Some(mfa_proof::F::TotpCode(c)),
                nonce: Vec::new(),
            }),
        },
        |svc, r| Box::pin(async move { svc.complete_add_factor(r).await }),
    )
    .await
    .unwrap();
    let begin = h.begin_login_as("log.scan", support::TRAY).await;
    let a = key.get_assertion(
        support::RP_ID,
        support::ORIGIN,
        &begin.webauthn.unwrap().challenge,
    );
    for material in [&a.signature, &a.authenticator_data, &a.client_data_json] {
        secrets.push(hex::encode(material));
        secrets.push(support::soft_authenticator::b64url(material));
    }
    let keyed = h
        .svc
        .login(from_ip(
            tray_login(
                begin.login_nonce,
                SecondFactor::WebauthnAssertion(support::assertion(&a)),
            ),
            local_ip(),
        ))
        .await
        .unwrap()
        .into_inner();
    secrets.push(keyed.session_token.clone());
    let proof = support::webauthn_proof(&h, &keyed.session_token, &mut key).await;
    if let Some(mfa_proof::F::WebauthnAssertion(p)) = proof.as_ref().and_then(|p| p.f.as_ref()) {
        secrets.push(hex::encode(&p.signature));
        secrets.push(support::soft_authenticator::b64url(&p.signature));
    }
    let begin = h
        .call(
            &keyed.session_token,
            paths::BEGIN_STEP_UP,
            BeginStepUpRequest {},
            |svc, r| Box::pin(async move { svc.begin_step_up(r).await }),
        )
        .await
        .unwrap();
    let a = key.get_assertion(
        support::RP_ID,
        support::ORIGIN,
        &begin.webauthn.unwrap().challenge,
    );
    secrets.push(hex::encode(&a.signature));
    let stepped = h
        .call(
            &keyed.session_token,
            paths::STEP_UP,
            StepUpRequest {
                stepup_nonce: begin.stepup_nonce,
                proof: Some(MfaProof {
                    f: Some(mfa_proof::F::WebauthnAssertion(support::assertion(&a))),
                    nonce: Vec::new(),
                }),
            },
            |svc, r| Box::pin(async move { svc.step_up(r).await }),
        )
        .await
        .unwrap();
    secrets.push(stepped.session_token.clone());
    // A refused assertion (wrong origin) is logged by reason only.
    let begin = h.begin_login_as("log.scan", support::TRAY).await;
    let bad = key.get_assertion(
        support::RP_ID,
        "https://evil.example",
        &begin.webauthn.unwrap().challenge,
    );
    secrets.push(hex::encode(&bad.signature));
    assert!(h
        .svc
        .login(from_ip(
            tray_login(
                begin.login_nonce,
                SecondFactor::WebauthnAssertion(support::assertion(&bad)),
            ),
            local_ip(),
        ))
        .await
        .is_err());

    let logs = String::from_utf8_lossy(&capture.0.lock().unwrap()).to_string();
    assert!(
        logs.contains("admin.webauthn.assertion_rejected") && logs.contains("reason=\"origin\""),
        "the refusal reason is logged:\n{logs}"
    );
    assert!(
        logs.contains("admin.login.succeeded"),
        "the run was captured:\n{logs}"
    );
    assert!(logs.contains("admin.login.failed"));
    for s in &secrets {
        assert!(
            !logs.contains(s.as_str()),
            "a secret reached the logs: {}…",
            &s[..s.len().min(6)]
        );
    }
    // TOTP codes are short; look for them only as standalone tokens. A token
    // is a maximal alphanumeric run, so digits inside hex or base64 material
    // (ids, hashes, tokens) cannot match by chance, while a code logged as a
    // value (`code=123456`, `"123456"`, `TotpCode(123456)`) still does.
    for c in &codes {
        if let Some(line) = logs.lines().find(|l| {
            l.split(|ch: char| !ch.is_ascii_alphanumeric())
                .any(|w| w == c)
        }) {
            panic!(
                "a TOTP code reached the logs: {}",
                line.replace(c.as_str(), "<code>")
            );
        }
    }
}
