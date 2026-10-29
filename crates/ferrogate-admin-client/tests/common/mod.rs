//! Fixtures shared by the `ferrogate-admin-client` integration tests: an
//! in-process CMIS (the harness of `crates/cmis/tests/support`, which each
//! test crate includes by path as `support`) behind a real pinned TLS admin
//! listener, and that harness's software FIDO2 authenticator behind the
//! client's [`Authenticator`] trait. The server verifies every signature and
//! every registration.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc)]

use std::sync::{Arc, Mutex};

use ferro_audit::AuditEvent;
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferrogate_admin_client::client::{AdminSession, ClientConfig, Factor};
use ferrogate_admin_client::secret::Secret;
use ferrogate_admin_client::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};
use ferrogate_admin_client::webauthn::{
    AssertionRequest, Authenticator, AuthenticatorAssertion, AuthenticatorAttestation,
    AuthenticatorError, CreationRequest,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;

use crate::support::soft_authenticator::{Fmt, SoftAuthenticator, UP, UV};
use crate::support::{self, Admin1, Harness};

/// The approvers group (the FIDO2 tray policy's usual target).
pub const APPROVERS: &str = "ferrogate-approvers";

/// The harness's software key behind the client's trait: it signs the
/// `clientDataJSON` hash the client built, and registers over the
/// `clientDataJSON` the client built, as a CTAP2 device would.
pub struct SoftKey {
    pub key: Mutex<SoftAuthenticator>,
    /// Runs inside the "prompt" (to lock the client meanwhile).
    pub during: Option<Box<dyn Fn() + Send + Sync>>,
    /// Answer with this error instead (a cancelled prompt).
    pub fail: Option<AuthenticatorError>,
}

impl SoftKey {
    pub fn new(key: SoftAuthenticator) -> Arc<Self> {
        Arc::new(Self {
            key: Mutex::new(key),
            during: None,
            fail: None,
        })
    }

    fn prompt(&self) -> Result<(), AuthenticatorError> {
        if let Some(f) = &self.during {
            f();
        }
        self.fail.clone().map_or(Ok(()), Err)
    }
}

impl Authenticator for SoftKey {
    fn get_assertion(
        &self,
        req: &AssertionRequest,
    ) -> Result<AuthenticatorAssertion, AuthenticatorError> {
        self.prompt()?;
        let mut k = self.key.lock().unwrap();
        if !req.allow_credential_ids.is_empty()
            && !req.allow_credential_ids.contains(&k.credential_id)
        {
            return Err(AuthenticatorError::NoCredential);
        }
        if k.counter != 0 {
            k.counter += 1;
        }
        let authenticator_data = k.auth_data(&req.rp_id, UP | UV, k.counter, false);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&req.client_data_hash);
        Ok(AuthenticatorAssertion {
            credential_id: k.credential_id.clone(),
            signature: k.sign(&signed),
            authenticator_data,
            user_handle: Vec::new(),
        })
    }

    fn make_credential(
        &self,
        req: &CreationRequest,
    ) -> Result<AuthenticatorAttestation, AuthenticatorError> {
        self.prompt()?;
        let k = self.key.lock().unwrap();
        if req.exclude_credential_ids.contains(&k.credential_id) {
            return Err(AuthenticatorError::Failed("already registered".into()));
        }
        let auth_data = k.auth_data(&req.rp_id, UP | UV, k.counter, true);
        Ok(AuthenticatorAttestation {
            credential_id: k.credential_id.clone(),
            attestation_object: k.attestation_object(Fmt::None, &auth_data, &req.client_data_json),
            transports: vec!["usb".into()],
        })
    }
}

/// An in-process CMIS behind a real TLS admin listener.
pub struct Server {
    pub h: Harness,
    pub endpoint: String,
    pub pin: SpkiPin,
    pub root: Admin1,
    pub root_token: String,
}

/// Start a server whose FIDO2 tray policy binds `fido2_groups`.
pub async fn server(tag: &str, fido2_groups: &[&str]) -> Server {
    let groups: Vec<String> = fido2_groups.iter().map(|g| (*g).to_string()).collect();
    let h = support::harness_with(tag, |c| c.tray_fido2_groups = groups).await;
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .unwrap();
    let pin = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
    let tls = ferro_crypto::transport::server_config(
        ProviderMode::HybridOnly,
        vec![ck.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(cmis::server::serve_admin(
        listener,
        tls,
        Arc::clone(&h.cmis),
        Arc::clone(&h.authz),
    ));
    let root = support::bootstrap(&h, "root-admin").await;
    let root_token = h.login(&root).await;
    Server {
        h,
        endpoint: format!("https://{addr}"),
        pin,
        root,
        root_token,
    }
}

impl Server {
    /// A tray client of this server, pinned to `pin`.
    pub fn session(&self, pin: SpkiPin) -> AdminSession {
        AdminSession::new(ClientConfig {
            endpoint: self.endpoint.clone(),
            pins: vec![pin],
            device_token_path: None,
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
            client_kind: ferrogate_admin_client::client_kind::TRAY,
        })
    }

    /// An account in `groups` enrolled with `key` and a TOTP factor.
    pub async fn key_holder(&self, name: &str, groups: &[&str], key: &SoftAuthenticator) -> Admin1 {
        self.h
            .create_and_enroll_key(&self.root, &self.root_token, name, groups, key, true)
            .await
    }

    /// Audit events matching `want`.
    pub fn count(&self, want: impl Fn(&AuditEvent) -> bool) -> usize {
        self.h.audit_events().iter().filter(|e| want(e)).count()
    }

    /// Failed sign-ins recorded so far.
    pub fn failed_logins(&self) -> usize {
        self.count(|e| matches!(e, AuditEvent::AdminLoginFailed { .. }))
    }
}

/// A secret buffer holding `text`.
pub fn secret(text: &str) -> Secret {
    let mut s = Secret::new();
    s.push_str(text);
    s
}

/// A fresh TOTP code of `who` (the clock moves one step first).
pub fn totp(s: &Server, who: &Admin1) -> Factor {
    Factor::Totp(secret(&s.h.fresh_code(who)))
}
