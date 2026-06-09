//! End-to-end test of the TPM-less **host-key** attestation profile (F15) over
//! a real in-process tonic gRPC channel.
//!
//! A [`SoftwareMachineKey`] stands in for the Secure Enclave (the SEP backend
//! needs real hardware and is exercised by `ferro-sep`'s ignored live test), so
//! the full 3-phase handshake runs anywhere. We assert that:
//!
//! - an **enrolled** host completes `Attest` and is issued a JWS the
//!   independent reference verifier accepts against the published JWKS; and
//! - an **un-enrolled** host (whose fingerprint is not in the fleet manifest) is
//!   refused.

#![allow(clippy::large_futures)]

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::fleet_manifest::MachinePubkey;
use cmis::{CmisConfig, CmisState, FleetManifest, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_machineid::MachineFacts;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_sep::{MachineKey, SoftwareMachineKey};
use ferro_svid::Issuer;
use ferro_svid_verify::{verify, JwkSet};
use mia::client::{run_attest_host_key, AttestClientError};

/// The host-key profile never reaches credential activation, so this is unused.
struct UnusedCredentialMaker;
impl CredentialMaker for UnusedCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        unreachable!("host-key profile does not activate a credential")
    }
}

/// Synthetic but realistically-shaped Apple-Silicon hardware identifiers.
fn sample_facts() -> MachineFacts {
    MachineFacts {
        board_serial: "WT3QF2J3YL".to_string(),
        platform_uuid: "38D33B14-6DDD-51DD-B8CD-9854CAF977D5".to_string(),
        disk_serial: "0ba0206164386025".to_string(),
    }
}

/// A CMIS state with an empty TPM verifier (the host-key path never consults
/// it) and a fresh audit log.
fn build_state() -> Arc<CmisState> {
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::new(), RimStore::new());
    let issuer = Issuer::generate("kid-hostkey", "ferrogate.test").unwrap();
    let audit_root = {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-hostkey-audit-{nanos}"));
        p
    };
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, _audit_pk) = InProcessSigner::generate("audit-test").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer));
    Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnusedCredentialMaker),
        CmisConfig {
            trust_domain: "ferrogate.test".to_string(),
            svid_ttl_secs: 3600,
            policy_epoch: 1,
        },
        audit,
    ))
}

/// Apply an enforcing fleet manifest enrolling exactly `machine_ids` (hex H).
fn enroll_machines(state: &CmisState, machine_ids: &[String]) {
    let manifest = FleetManifest {
        version: 1,
        trust_domain: "ferrogate.test".to_string(),
        issued_at: 0,
        enrolled_ek_sha384: Vec::new(),
        enrolled_machine_id: machine_ids.to_vec(),
        enrolled_machine_pubkey: Vec::new(),
    };
    state.fleet().apply(manifest.to_enrolled().unwrap());
}

async fn spawn_server(state: Arc<CmisState>) -> MachineIdentityClient<tonic::transport::Channel> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MachineIdentitySvc::new(state).into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap();
    MachineIdentityClient::new(endpoint.connect_lazy())
}

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[tokio::test]
async fn enrolled_host_key_attests_end_to_end() {
    let state = build_state();
    let facts = sample_facts();
    enroll_machines(&state, &[facts.fingerprint().to_hex()]);
    let mut client = spawn_server(state).await;

    let key = SoftwareMachineKey::generate().unwrap();
    let attested = run_attest_host_key(&mut client, &facts, &key, "dpop-thumb".to_string())
        .await
        .expect("host-key attestation succeeds");

    assert!(attested
        .bundle
        .spiffe_id
        .starts_with("spiffe://ferrogate.test/host/"));
    assert_eq!(attested.bundle.expires_at - attested.bundle.issued_at, 3600);

    // The issued JWS verifies under the JWKS the server publishes.
    let jwks_json = client
        .jwks(ferro_proto::v1::JwksRequest {})
        .await
        .unwrap()
        .into_inner()
        .jwks_json;
    let jwks = JwkSet::from_json(&jwks_json).unwrap();
    verify(&attested.bundle.jws, &jwks, now_secs(), 60).expect("reference verifier accepts SVID");
}

#[tokio::test]
async fn unenrolled_host_key_is_rejected() {
    let state = build_state();
    // Enroll a *different* host's fingerprint, so the manifest is enforcing but
    // our host is not on it.
    let other = MachineFacts {
        board_serial: "OTHER-MACHINE".to_string(),
        platform_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
        disk_serial: "deadbeef".to_string(),
    };
    enroll_machines(&state, &[other.fingerprint().to_hex()]);
    let mut client = spawn_server(state).await;

    let key = SoftwareMachineKey::generate().unwrap();
    // The server returns permission_denied; it reaches the client as a transport
    // status error on the response stream.
    match run_attest_host_key(&mut client, &sample_facts(), &key, "dpop".to_string()).await {
        Err(AttestClientError::Transport(_)) => {}
        Ok(_) => panic!("un-enrolled host must be refused"),
        Err(other) => panic!("expected transport/permission error, got {other:?}"),
    }
}

#[tokio::test]
async fn forged_facts_are_rejected() {
    // Enroll the genuine fingerprint, but present facts that don't hash to it:
    // the signature is over the claimed H, yet CMIS recomputes H from the facts
    // and the mismatch trips verification.
    let state = build_state();
    let genuine = sample_facts();
    enroll_machines(&state, &[genuine.fingerprint().to_hex()]);
    let mut client = spawn_server(state).await;

    // Hand the client *different* facts than were enrolled. Its fingerprint
    // won't be enrolled, so this also exercises the gate — but the point is the
    // server independently recomputes H rather than trusting the wire value.
    let tampered = MachineFacts {
        board_serial: "SPOOFED".to_string(),
        ..genuine
    };
    let key = SoftwareMachineKey::generate().unwrap();
    match run_attest_host_key(&mut client, &tampered, &key, "dpop".to_string()).await {
        Err(AttestClientError::Transport(_)) => {}
        Ok(_) => panic!("forged facts must be refused"),
        Err(other) => panic!("expected transport/permission error, got {other:?}"),
    }
}

#[tokio::test]
async fn tofu_pin_rejects_a_rebind_with_a_different_key() {
    let state = build_state();
    let facts = sample_facts();
    enroll_machines(&state, &[facts.fingerprint().to_hex()]);
    let mut client = spawn_server(state).await;

    // First attestation pins key A on first use.
    let key_a = SoftwareMachineKey::generate().unwrap();
    run_attest_host_key(&mut client, &facts, &key_a, "dpop".to_string())
        .await
        .expect("first attestation pins the key");

    // A second attestation for the same fingerprint with a *different* key is a
    // rebind attempt and must be refused.
    let key_b = SoftwareMachineKey::generate().unwrap();
    match run_attest_host_key(&mut client, &facts, &key_b, "dpop".to_string()).await {
        Err(AttestClientError::Transport(_)) => {}
        Ok(_) => panic!("rebind with a new key must be refused"),
        Err(other) => panic!("expected transport/permission error, got {other:?}"),
    }

    // The original key still attests — the pin binds the fingerprint to it.
    run_attest_host_key(&mut client, &facts, &key_a, "dpop".to_string())
        .await
        .expect("the originally pinned key still attests");
}

/// Apply a manifest that pre-registers `fingerprint → sep_pub` (closes the TOFU
/// window: only this exact key is accepted, even on the very first attestation).
fn enroll_prereg(state: &CmisState, fingerprint_hex: &str, sep_pub: &[u8]) {
    let manifest = FleetManifest {
        version: 1,
        trust_domain: "ferrogate.test".to_string(),
        issued_at: 0,
        enrolled_ek_sha384: Vec::new(),
        enrolled_machine_id: Vec::new(),
        enrolled_machine_pubkey: vec![MachinePubkey {
            fingerprint: fingerprint_hex.to_string(),
            sep_pub_b64: URL_SAFE_NO_PAD.encode(sep_pub),
        }],
    };
    state.fleet().apply(manifest.to_enrolled().unwrap());
}

#[tokio::test]
async fn preregistered_key_is_required_from_first_attestation() {
    let state = build_state();
    let facts = sample_facts();
    let expected = SoftwareMachineKey::generate().unwrap();
    enroll_prereg(&state, &facts.fingerprint().to_hex(), &expected.public_spki_der());
    let mut client = spawn_server(state).await;

    // A different key is rejected even though the fingerprint is enrolled —
    // there is no trust-on-first-use when a key is pre-registered.
    let wrong = SoftwareMachineKey::generate().unwrap();
    match run_attest_host_key(&mut client, &facts, &wrong, "dpop".to_string()).await {
        Err(AttestClientError::Transport(_)) => {}
        Ok(_) => panic!("a non-pre-registered key must be refused"),
        Err(other) => panic!("expected transport/permission error, got {other:?}"),
    }

    // The pre-registered key attests.
    run_attest_host_key(&mut client, &facts, &expected, "dpop".to_string())
        .await
        .expect("the pre-registered key attests");
}
