//! Shared harness for the F20 admin tests: an in-process single-node CMIS, the
//! admin subsystem on a controlled clock, and helpers that drive the `Admin`
//! service the way a client would.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc)]

pub mod soft_authenticator;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cmis::admin::authz::AdminAuthz;
use cmis::admin::clock::ManualClock;
use cmis::admin::keys::AdminKeys;
use cmis::admin::password::PasswordParams;
use cmis::admin::{AdminConfig, AdminState, AdminSvc};
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::transport::PeerConnectInfo;
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditEvent, AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_proto::admin_v1::admin_server::Admin;
use ferro_proto::admin_v1::{
    login_request::SecondFactor, mfa_proof, BeginEnrollmentRequest, BeginLoginRequest,
    BeginLoginResponse, BeginStepUpRequest, ClientInfo, CompleteEnrollmentRequest,
    CreateAdminAccountRequest, LoginRequest, LoginResponse, MfaProof, WebAuthnAssertion,
    WebAuthnAttestation,
};
use ferro_raft::Cluster;
use ferro_svid::Issuer;
use soft_authenticator::{Assertion, Registration, SoftAuthenticator};

/// A password that satisfies the administrative policy.
pub const PASSWORD: &str = "Tr0ub4dor&3-Correct!Horse_Battery";
/// A second valid password.
pub const PASSWORD2: &str = "Second-Valid#Passphrase_2049x";
/// Start of the controlled clock (2026-10-14T00:00:00Z), aligned to a TOTP step.
pub const T0: i64 = 1_791_936_000;
/// The WebAuthn RP ID of the test deployment (trust domain `ferrogate.test`).
pub const RP_ID: &str = "ferrogate-admin.ferrogate.test";
/// The default WebAuthn origin of the test deployment.
pub const ORIGIN: &str = "https://ferrogate-admin.ferrogate.test";
/// `ClientInfo.kind` values.
pub const TUI: u32 = 1;
/// The tray admin client.
pub const TRAY: u32 = 2;
/// The CLI.
pub const CLI: u32 = 3;

/// A registration response as the proto message.
pub fn attestation(reg: &Registration, label: &str) -> WebAuthnAttestation {
    WebAuthnAttestation {
        credential_id: reg.credential_id.clone(),
        attestation_object: reg.attestation_object.clone(),
        client_data_json: reg.client_data_json.clone(),
        transports: vec!["usb".into()],
        label: label.into(),
    }
}

/// An assertion as the proto message.
pub fn assertion(a: &Assertion) -> WebAuthnAssertion {
    WebAuthnAssertion {
        credential_id: a.credential_id.clone(),
        authenticator_data: a.authenticator_data.clone(),
        client_data_json: a.client_data_json.clone(),
        signature: a.signature.clone(),
        user_handle: a.user_handle.clone(),
    }
}

/// A per-operation proof carrying a WebAuthn assertion over a fresh
/// `BeginStepUp` challenge.
pub async fn webauthn_proof(
    h: &Harness,
    token: &str,
    key: &mut SoftAuthenticator,
) -> Option<MfaProof> {
    let begin = h
        .call(
            token,
            cmis::admin::authz::paths::BEGIN_STEP_UP,
            BeginStepUpRequest {},
            |svc, r| Box::pin(async move { svc.begin_step_up(r).await }),
        )
        .await
        .unwrap();
    let challenge = begin.webauthn.expect("a WebAuthn challenge").challenge;
    let a = key.get_assertion(RP_ID, ORIGIN, &challenge);
    Some(MfaProof {
        f: Some(mfa_proof::F::WebauthnAssertion(assertion(&a))),
        nonce: begin.stepup_nonce,
    })
}

struct NoCredentialMaker;
impl CredentialMaker for NoCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap("unused".to_string()))
    }
}

/// Removes its directories on drop.
pub struct TmpDirs(pub Vec<std::path::PathBuf>);
impl Drop for TmpDirs {
    fn drop(&mut self) {
        for dir in &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Everything a test needs.
pub struct Harness {
    pub cmis: Arc<CmisState>,
    pub admin: Arc<AdminState>,
    pub authz: Arc<AdminAuthz>,
    pub svc: AdminSvc,
    pub mi: MachineIdentitySvc,
    pub clock: Arc<ManualClock>,
    pub audit_store: Arc<dyn AuditStore>,
    pub bootstrap_file: std::path::PathBuf,
    _dirs: TmpDirs,
}

fn unique(tag: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("ferrogate-admin-{tag}-{}-{nanos}-{n}", std::process::id())
}

/// Cheap Argon2 parameters so tests stay fast (production never uses them).
pub fn cheap_params() -> PasswordParams {
    PasswordParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    }
}

pub async fn harness(tag: &str) -> Harness {
    harness_with(tag, |_| {}).await
}

pub async fn harness_with(tag: &str, tweak: impl FnOnce(&mut AdminConfig)) -> Harness {
    let base = std::env::temp_dir().join(unique(tag));
    let audit_dir = base.join("audit");
    let raft_dir = base.join("raft");
    let issuer = Issuer::generate("cmis-admin-test", "ferrogate.test").unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let audit_store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_dir).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-admin-test").unwrap();
    let audit = AuditLog::new(Arc::clone(&audit_store), Arc::new(signer)).unwrap();
    let cluster = Arc::new(
        Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    let cmis = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(NoCredentialMaker),
        CmisConfig::default(),
        audit,
        cluster,
    ));
    let bootstrap_file = base.join("bootstrap.token");
    let mut config = AdminConfig {
        password_params: cheap_params(),
        trust_domain: "ferrogate.test".into(),
        bootstrap_token_file: bootstrap_file.clone(),
        ..AdminConfig::default()
    };
    tweak(&mut config);
    let clock = Arc::new(ManualClock::new(T0));
    let keys = AdminKeys::from_material(&[0x11; 32], &[0x22; 32]);
    let admin = AdminState::new(
        Arc::clone(&cmis),
        config,
        keys,
        Arc::clone(&clock) as Arc<dyn cmis::admin::clock::Clock>,
    )
    .await
    .unwrap();
    let authz = Arc::new(AdminAuthz::new(Arc::clone(&admin)));
    Harness {
        mi: MachineIdentitySvc::new(Arc::clone(&cmis)),
        svc: AdminSvc::new(Arc::clone(&authz)),
        cmis,
        admin,
        authz,
        clock,
        audit_store,
        bootstrap_file,
        _dirs: TmpDirs(vec![base]),
    }
}

/// The loopback address tests connect from.
pub fn local_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Attach connect info for `ip` to a request, as the TLS listener would.
pub fn from_ip<T>(msg: T, ip: IpAddr) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.extensions_mut().insert(PeerConnectInfo {
        remote_addr: Some(SocketAddr::new(ip, 50_000)),
        client_cert_sha256: None,
    });
    req
}

/// TOTP code for `secret` at Unix time `t`.
pub fn code(secret: &[u8], t: i64) -> String {
    cmis::admin::totp::code_at(secret, cmis::admin::totp::step_at(t))
}

/// Base32 secret from an `otpauth://` URI.
pub fn secret_from_uri(uri: &str) -> Vec<u8> {
    let start = uri.find("secret=").unwrap() + "secret=".len();
    let end = uri[start..].find('&').map_or(uri.len(), |i| start + i);
    base32_decode(&uri[start..end])
}

fn base32_decode(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = u32::try_from(A.iter().position(|&x| x == c).unwrap()).unwrap();
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

/// One administrator: id, username, TOTP secret.
#[derive(Debug, Clone)]
pub struct Admin1 {
    pub admin_id: String,
    pub username: String,
    pub secret: Vec<u8>,
}

/// Arm and redeem the bootstrap token as the first operator.
pub async fn bootstrap(h: &Harness, username: &str) -> Admin1 {
    let outcome = cmis::admin::bootstrap::arm(&h.admin).await.unwrap();
    assert!(
        matches!(outcome, cmis::admin::bootstrap::BootstrapOutcome::Armed(_)),
        "{outcome:?}"
    );
    let token = std::fs::read_to_string(&h.bootstrap_file).unwrap();
    let begin = h
        .svc
        .begin_enrollment(from_ip(
            BeginEnrollmentRequest {
                enrollment_token: token.clone(),
            },
            local_ip(),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(begin.username_choosable);
    let secret = secret_from_uri(&begin.totp_provisioning_uri);
    let done = h
        .svc
        .complete_enrollment(from_ip(
            CompleteEnrollmentRequest {
                enrollment_token: token,
                username: username.into(),
                display_name: "First Operator".into(),
                password: PASSWORD.into(),
                totp_code: code(&secret, h.clock_now()),
                webauthn_attestation: None,
            },
            local_ip(),
        ))
        .await
        .unwrap()
        .into_inner();
    Admin1 {
        admin_id: done.admin_id,
        username: username.into(),
        secret,
    }
}

impl Harness {
    pub fn clock_now(&self) -> i64 {
        use cmis::admin::clock::Clock as _;
        self.clock.now()
    }

    /// Advance the clock by one TOTP step so the next code is fresh.
    pub fn next_step(&self) {
        self.clock.advance(30);
    }

    /// A fresh TOTP code for `who` (advances the clock one step first).
    pub fn fresh_code(&self, who: &Admin1) -> String {
        self.next_step();
        code(&who.secret, self.clock_now())
    }

    /// A per-operation proof carrying a fresh TOTP code.
    pub fn proof(&self, who: &Admin1) -> Option<MfaProof> {
        Some(MfaProof {
            f: Some(mfa_proof::F::TotpCode(self.fresh_code(who))),
            nonce: Vec::new(),
        })
    }

    /// Log `who` in from `ip`; returns the session token.
    pub async fn login_from(
        &self,
        who: &Admin1,
        password: &str,
        ip: IpAddr,
    ) -> Result<String, tonic::Status> {
        let nonce = self
            .svc
            .begin_login(from_ip(
                BeginLoginRequest {
                    username: who.username.clone(),
                    device_token: String::new(),
                    client: Some(ClientInfo {
                        kind: 3,
                        version: "test".into(),
                    }),
                },
                ip,
            ))
            .await?
            .into_inner()
            .login_nonce;
        let code = self.fresh_code(who);
        self.svc
            .login(from_ip(
                LoginRequest {
                    login_nonce: nonce,
                    username: who.username.clone(),
                    password: password.into(),
                    second_factor: Some(SecondFactor::TotpCode(code)),
                    device_token: String::new(),
                    client: Some(ClientInfo {
                        kind: 3,
                        version: "test".into(),
                    }),
                },
                ip,
            ))
            .await
            .map(|r| r.into_inner().session_token)
    }

    pub async fn login(&self, who: &Admin1) -> String {
        self.login_from(who, PASSWORD, local_ip()).await.unwrap()
    }

    /// `BeginLogin` for `username` as client `kind`.
    pub async fn begin_login_as(&self, username: &str, kind: u32) -> BeginLoginResponse {
        self.svc
            .begin_login(from_ip(
                BeginLoginRequest {
                    username: username.into(),
                    device_token: String::new(),
                    client: Some(ClientInfo {
                        kind,
                        version: "test".into(),
                    }),
                },
                local_ip(),
            ))
            .await
            .unwrap()
            .into_inner()
    }

    /// Log in as client `kind` with a fresh TOTP code.
    pub async fn login_totp_as(
        &self,
        who: &Admin1,
        kind: u32,
    ) -> Result<LoginResponse, tonic::Status> {
        let nonce = self.begin_login_as(&who.username, kind).await.login_nonce;
        let code = self.fresh_code(who);
        self.login_with(who, kind, nonce, SecondFactor::TotpCode(code))
            .await
    }

    /// Log in from the tray with an assertion from `key`.
    pub async fn login_key(
        &self,
        who: &Admin1,
        key: &mut SoftAuthenticator,
    ) -> Result<LoginResponse, tonic::Status> {
        let begin = self.begin_login_as(&who.username, TRAY).await;
        let challenge = begin.webauthn.expect("a WebAuthn challenge").challenge;
        let a = key.get_assertion(RP_ID, ORIGIN, &challenge);
        self.login_with(
            who,
            TRAY,
            begin.login_nonce,
            SecondFactor::WebauthnAssertion(assertion(&a)),
        )
        .await
    }

    /// `Login` with an explicit nonce and second factor.
    pub async fn login_with(
        &self,
        who: &Admin1,
        kind: u32,
        nonce: Vec<u8>,
        second: SecondFactor,
    ) -> Result<LoginResponse, tonic::Status> {
        self.svc
            .login(from_ip(
                LoginRequest {
                    login_nonce: nonce,
                    username: who.username.clone(),
                    password: PASSWORD.into(),
                    second_factor: Some(second),
                    device_token: String::new(),
                    client: Some(ClientInfo {
                        kind,
                        version: "test".into(),
                    }),
                },
                local_ip(),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    /// Create an account in `groups` (as `by`) and enroll it with `key`,
    /// plus TOTP when `with_totp` (the returned secret is empty otherwise).
    pub async fn create_and_enroll_key(
        &self,
        by: &Admin1,
        by_token: &str,
        username: &str,
        groups: &[&str],
        key: &SoftAuthenticator,
        with_totp: bool,
    ) -> Admin1 {
        let created = self
            .call(
                by_token,
                cmis::admin::authz::paths::CREATE_ADMIN_ACCOUNT,
                CreateAdminAccountRequest {
                    idempotency_key: String::new(),
                    username: username.into(),
                    display_name: "Key Holder".into(),
                    groups: groups.iter().map(|g| (*g).to_string()).collect(),
                    proof: self.proof(by),
                    enrollment_ttl_secs: 0,
                },
                |svc, req| Box::pin(async move { svc.create_admin_account(req).await }),
            )
            .await
            .unwrap();
        let begin = self
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
        let options = begin
            .webauthn_creation_options
            .expect("creation options for a new account");
        let reg = key.make_credential(&options.rp_id, ORIGIN, &options.challenge);
        let secret = if with_totp {
            secret_from_uri(&begin.totp_provisioning_uri)
        } else {
            Vec::new()
        };
        self.svc
            .complete_enrollment(from_ip(
                CompleteEnrollmentRequest {
                    enrollment_token: created.enrollment_token,
                    username: String::new(),
                    display_name: String::new(),
                    password: PASSWORD.into(),
                    totp_code: if with_totp {
                        code(&secret, self.clock_now())
                    } else {
                        String::new()
                    },
                    webauthn_attestation: Some(attestation(&reg, "YubiKey 5")),
                },
                local_ip(),
            ))
            .await
            .unwrap();
        Admin1 {
            admin_id: created.admin_id,
            username: username.into(),
            secret,
        }
    }

    /// Create an account in `groups` (as `by`) and enroll it with TOTP.
    pub async fn create_and_enroll(
        &self,
        by: &Admin1,
        by_token: &str,
        username: &str,
        groups: &[&str],
    ) -> Admin1 {
        let created = self
            .call(
                by_token,
                cmis::admin::authz::paths::CREATE_ADMIN_ACCOUNT,
                CreateAdminAccountRequest {
                    idempotency_key: String::new(),
                    username: username.into(),
                    display_name: "Second Person".into(),
                    groups: groups.iter().map(|g| (*g).to_string()).collect(),
                    proof: self.proof(by),
                    enrollment_ttl_secs: 0,
                },
                |svc, req| Box::pin(async move { svc.create_admin_account(req).await }),
            )
            .await
            .unwrap();
        let begin = self
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
        assert!(!begin.username_choosable);
        let secret = secret_from_uri(&begin.totp_provisioning_uri);
        self.svc
            .complete_enrollment(from_ip(
                CompleteEnrollmentRequest {
                    enrollment_token: created.enrollment_token,
                    username: String::new(),
                    display_name: String::new(),
                    password: PASSWORD.into(),
                    totp_code: code(&secret, self.clock_now()),
                    webauthn_attestation: None,
                },
                local_ip(),
            ))
            .await
            .unwrap();
        Admin1 {
            admin_id: created.admin_id,
            username: username.into(),
            secret,
        }
    }

    /// Run `f` on a request authenticated as the session `token` from
    /// loopback: the layer's authorization, then the handler.
    pub async fn call<Req, Resp>(
        &self,
        token: &str,
        path: &str,
        msg: Req,
        f: impl FnOnce(
            &AdminSvc,
            tonic::Request<Req>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<tonic::Response<Resp>, tonic::Status>>
                    + Send
                    + '_,
            >,
        >,
    ) -> Result<Resp, tonic::Status> {
        let req = self.authorized(token, path, msg, local_ip()).await?;
        f(&self.svc, req).await.map(tonic::Response::into_inner)
    }

    /// Authenticate `token` for `path` from `ip` exactly as the layer does and
    /// return the request carrying the resulting `AdminContext`.
    pub async fn authorized<Req>(
        &self,
        token: &str,
        path: &str,
        msg: Req,
        ip: IpAddr,
    ) -> Result<tonic::Request<Req>, tonic::Status> {
        let Some(cmis::admin::authz::Access::Session(rule)) = cmis::admin::authz::access_for(path)
        else {
            panic!("{path} is not a session method");
        };
        let header = format!("Bearer {token}");
        let peer = cmis::admin::authz::PeerInfo {
            ip: Some(ip),
            client_cert_sha256: None,
        };
        let ctx = self
            .authz
            .authorize(path, rule, Some(header.as_bytes()), &peer)
            .await?;
        let mut req = from_ip(msg, ip);
        req.extensions_mut().insert(ctx);
        Ok(req)
    }

    /// Every audit event recorded so far.
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        let mut out = Vec::new();
        for i in 0..self.cmis.audit.len() as u64 {
            let raw = self.audit_store.read_leaf(i).unwrap();
            out.push(ferro_audit::event::decode(&raw).unwrap());
        }
        out
    }
}
