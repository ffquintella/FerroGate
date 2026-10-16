//! End-to-end F04 integration test over a real in-process tonic gRPC channel.
//!
//! A software [`AttestEvidence`] mints wire-correct synthetic TPM structures
//! (the same approach as `ferro-attest`'s verifier tests) so the full
//! four-phase handshake runs without a TPM. We assert that:
//!
//! - `Attest` issues a JWS that the independent reference verifier accepts
//!   against the JWKS the server publishes;
//! - a host-key host renews with a host-signed `Rotate` on the short path
//!   (T293), and an epoch bump forces it back through `Attest`;
//! - a TPM-tier host is always sent back to a full `Attest`;
//! - the daemon's renewal loop renews before expiry and keeps minting and
//!   forwarding under the renewed SVID (T294);
//! - a host revoked by SPIFFE id cannot re-attest on the TPM tier (T295).

#![allow(clippy::cast_possible_truncation)]
// The handshake future holds a composite key (incl. a ~4 KB ML-DSA secret)
// across awaits; that is inherent, not a bug.
#![allow(clippy::large_futures)]

use std::sync::Arc;

use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{PolicyId, RimStore, TpmQuoteVerifier, Vendor, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{BumpEpochRequest, RotateRequest};
use ferro_sep::{MachineKey as _, SoftwareMachineKey};
use ferro_svid::Issuer;
use mia::audit_client::HostProofSigner;
use mia::client::{run_attest, run_attest_host_key, AttestedSvid, RotateClientError};
use mia::host_api::split_host_spiffe_id;
use mia::virtual_tpm::{expected_pcr_digest, software_credential_blob, VirtualTpm};

use sha2::{Digest, Sha256, Sha384};

// --- software credential channel --------------------------------------------

/// Software-only credential channel matching [`mia::virtual_tpm::VirtualTpm`]'s
/// `activate`. NOT TPM-faithful — it only exercises the phase-3 plumbing so the
/// handshake completes without a real `TPM2_MakeCredential`.
struct SoftwareCredentialMaker;

impl CredentialMaker for SoftwareCredentialMaker {
    fn make_credential(
        &self,
        ek_pub: &[u8],
        aik_pub: &[u8],
        secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Ok(WrappedCredential {
            credential_blob: software_credential_blob(ek_pub, aik_pub, secret),
            secret_blob: Vec::new(),
        })
    }
}

// --- server harness ---------------------------------------------------------

async fn build_state(evidence: &VirtualTpm) -> Arc<CmisState> {
    // Trust the synthetic EK root and approve the synthetic PCR digest.
    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(evidence.ek_root_der(), Vendor::Infineon)
        .unwrap();
    let pcr_digest = expected_pcr_digest();
    let rim = RimStore::new();
    rim.approve(pcr_digest, PolicyId("test-fleet".into()))
        .unwrap();
    let verifier = TpmQuoteVerifier::new(trust, rim);
    state_with_verifier(verifier).await
}

async fn state_with_verifier(verifier: TpmQuoteVerifier) -> Arc<CmisState> {
    state_with_verifier_capturing_audit(verifier).await.0
}

/// Same as [`state_with_verifier`] but also hands back the audit signer's
/// public key so a verifier in the test can authenticate STHs offline.
async fn state_with_verifier_capturing_audit(
    verifier: TpmQuoteVerifier,
) -> (Arc<CmisState>, ferro_crypto::composite::CompositePublicKey) {
    // Parallel tests can land on the same SystemTime nanos; a counter keeps the
    // per-state temp dirs (and hiqlite's WAL lock) from colliding.
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let issuer = Issuer::generate("kid-e2e", "ferrogate.test").unwrap();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let nanos = format!("{nanos}-{n}");
    let audit_root = {
        let mut p = std::env::temp_dir();
        p.push(format!("ferrogate-e2e-audit-{nanos}"));
        p
    };
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, audit_pk) = InProcessSigner::generate("audit-test").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!("ferrogate-e2e-raft-{nanos}"));
    let _ = std::fs::remove_dir_all(&raft_dir);
    let cluster = Arc::new(
        ferro_raft::Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(SoftwareCredentialMaker),
        CmisConfig {
            trust_domain: "ferrogate.test".to_string(),
            svid_ttl_secs: 3600,
            ..CmisConfig::default()
        },
        audit,
        cluster,
    ));
    (state, audit_pk)
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

async fn fetch_jwks(client: &mut MachineIdentityClient<tonic::transport::Channel>) -> String {
    client
        .jwks(ferro_proto::v1::JwksRequest::default())
        .await
        .unwrap()
        .into_inner()
        .jwks_json
}

// --- tests -------------------------------------------------------------------

#[tokio::test]
async fn attest_issues_svid_that_reference_verifier_accepts() {
    let mut evidence = VirtualTpm::ephemeral().unwrap();
    let state = build_state(&evidence).await;
    let mut client = spawn_server(state).await;

    let attested = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string())
        .await
        .expect("attestation succeeds");

    assert!(attested
        .bundle
        .spiffe_id
        .starts_with("spiffe://ferrogate.test/host/"));
    assert_eq!(attested.bundle.expires_at - attested.bundle.issued_at, 3600);

    let jwks = ferro_svid_verify::JwkSet::from_json(&fetch_jwks(&mut client).await).unwrap();
    let now = attested.bundle.issued_at + 10;
    let verified = ferro_svid_verify::verify(&attested.bundle.jws, &jwks, now, 0).unwrap();
    assert_eq!(verified.kid, "kid-e2e");
    assert_eq!(verified.claims.sub, attested.bundle.spiffe_id);
    assert_eq!(verified.claims.cnf.jkt, "dpop-thumb");
    assert_eq!(verified.claims.attest.policy_id, "test-fleet");

    // F09 multi-key JWKS: attestation also published the host's composite
    // child-token signing key alongside the issuer key, so a downstream child
    // token verifier can find it by kid.
    assert!(jwks.keys.len() >= 2, "issuer + host child-signing key");
    assert!(
        jwks.keys.iter().any(|k| k.kid.starts_with("host-")),
        "host child-signing key published"
    );
}

// --- T293: host-signed Rotate --------------------------------------------------

/// `base64url(SHA-256(SPKI))`: the `cnf.jkt` binding an SVID to `key`.
fn jkt_of(key: &SoftwareMachineKey) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(key.public_spki_der()))
}

/// Synthetic hardware identifiers for the host-key tier.
fn sample_facts() -> ferro_machineid::MachineFacts {
    ferro_machineid::MachineFacts {
        board_serial: "WT3QF2J3YL".to_string(),
        platform_uuid: "38D33B14-6DDD-51DD-B8CD-9854CAF977D5".to_string(),
        disk_serial: "0ba0206164386025".to_string(),
    }
}

/// A CMIS for the host-key tier (its path never consults the TPM verifier).
async fn host_key_state() -> Arc<CmisState> {
    state_with_verifier(TpmQuoteVerifier::new(
        VendorTrustStore::new(),
        RimStore::new(),
    ))
    .await
}

/// Attest a host-key host whose SVID is bound to `key`.
async fn attest_host_key(
    client: &mut MachineIdentityClient<tonic::transport::Channel>,
    facts: &ferro_machineid::MachineFacts,
    key: &SoftwareMachineKey,
) -> AttestedSvid {
    run_attest_host_key(client, facts, key, jkt_of(key), None)
        .await
        .expect("host-key attestation succeeds")
}

/// One host-signed `Rotate` of `svid`, made with `key`.
async fn signed_rotate(
    client: &mut MachineIdentityClient<tonic::transport::Channel>,
    key: &SoftwareMachineKey,
    svid: &ferro_proto::v1::SvidBundle,
    state_digest: &[u8; 48],
) -> Result<ferro_proto::v1::SvidBundle, RotateClientError> {
    let (_, host_uuid) = split_host_spiffe_id(&svid.spiffe_id).expect("a host SVID");
    let signer = HostProofSigner {
        key,
        svid_jws: &svid.jws,
        host_uuid,
    };
    mia::client::rotate(client, &signer, state_digest).await
}

fn refused_code(err: RotateClientError) -> tonic::Code {
    match err {
        RotateClientError::Transport(s) => s.code(),
        other => panic!("expected an RPC refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn rotate_short_path_for_host_key_tier() {
    let mut client = spawn_server(host_key_state().await).await;
    let facts = sample_facts();
    let key = SoftwareMachineKey::generate().unwrap();
    let attested = attest_host_key(&mut client, &facts, &key).await;
    let fingerprint = facts.fingerprint();

    // Same fingerprint, same epoch, inside the window: short path, no
    // re-attestation, proven with the machine key.
    let rotated = signed_rotate(&mut client, &key, &attested.bundle, fingerprint.as_bytes())
        .await
        .expect("short-path rotate succeeds");
    assert_eq!(rotated.spiffe_id, attested.bundle.spiffe_id);
    assert_ne!(rotated.jws, attested.bundle.jws);
    let jwks = ferro_svid_verify::JwkSet::from_json(&fetch_jwks(&mut client).await).unwrap();
    let verified =
        ferro_svid_verify::verify(&rotated.jws, &jwks, rotated.issued_at + 10, 0).unwrap();
    assert_eq!(
        verified.claims.cnf.jkt,
        jkt_of(&key),
        "still bound to the key"
    );
    assert_eq!(verified.claims.attest.policy_id, "host-key");

    // The renewed SVID renews again; the one it replaced no longer does.
    signed_rotate(&mut client, &key, &rotated, fingerprint.as_bytes())
        .await
        .expect("the latest SVID renews");
    let err = signed_rotate(&mut client, &key, &attested.bundle, fingerprint.as_bytes())
        .await
        .expect_err("a superseded SVID must not renew");
    assert_eq!(refused_code(err), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn rotate_refused_for_tpm_tier() {
    let mut evidence = VirtualTpm::ephemeral().unwrap();
    let state = build_state(&evidence).await;
    let mut client = spawn_server(state).await;
    // Bind the TPM-tier SVID to a machine key so the host can sign the proof.
    let key = SoftwareMachineKey::generate().unwrap();
    let attested = run_attest(&mut client, &mut evidence, jkt_of(&key))
        .await
        .unwrap();

    // The pre-T293 request (an SVID and the deprecated unsigned fields) is
    // not even considered.
    #[allow(deprecated)]
    let legacy = RotateRequest {
        current_svid: attested.bundle.jws.clone(),
        known_epoch: 1,
        ..Default::default()
    };
    let status = client
        .rotate(legacy)
        .await
        .expect_err("an unauthenticated rotate must be refused");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    // A valid host proof still renews nothing on the TPM tier: its PCRs
    // need a fresh quote, so it is sent back to a full Attest.
    let err = signed_rotate(&mut client, &key, &attested.bundle, &expected_pcr_digest())
        .await
        .expect_err("the TPM tier must re-attest");
    assert_eq!(refused_code(err), tonic::Code::FailedPrecondition);
}

// --- F10: RIM bundle / loader / status mapping ------------------------------

#[tokio::test]
async fn attest_returns_failed_precondition_when_digest_not_in_rim() {
    let mut evidence = VirtualTpm::ephemeral().unwrap();

    // Verifier with the EK root trusted but an *empty* RIM — the verifier will
    // accept everything up to step 7 (RIM lookup), then reject with NotInRim
    // which the service maps to FAILED_PRECONDITION (`docs/cmis.md` error model).
    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(evidence.ek_root_der(), Vendor::Infineon)
        .unwrap();
    let verifier = TpmQuoteVerifier::new(trust, RimStore::new());
    let state = state_with_verifier(verifier).await;
    let mut client = spawn_server(state).await;

    let Err(err) = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string()).await else {
        panic!("attestation must be refused when the digest is not in any RIM");
    };
    let status = match err {
        mia::client::AttestClientError::Transport(s) => s,
        other => panic!("expected transport error, got {other:?}"),
    };
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn rim_loader_hot_swap_admits_a_freshly_published_generation() {
    use ferro_attest::{ReloadOutcome, RimBundle};
    use ferro_attest::{RimLoader, RimStore, SignedRimBundle, TrustedKeys};
    use ferro_crypto::composite::CompositeSecretKey;

    let mut evidence = VirtualTpm::ephemeral().unwrap();
    let pcr_digest = expected_pcr_digest();

    // Publisher keypair and a temp-file bundle approving the test's PCR digest.
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    let mut trusted = TrustedKeys::new();
    trusted.add("test-pub", pk);

    let bundle_path = {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-e2e-rim-{nanos}.json"));
        p
    };
    let bundle = RimBundle {
        version: 1,
        policy_id: "loader-fleet".to_string(),
        not_before: 0,
        not_after: i64::MAX / 2,
        approved_digests_hex: vec![hex::encode(pcr_digest)],
    };
    std::fs::write(
        &bundle_path,
        serde_json::to_vec(&SignedRimBundle::sign(bundle, "test-pub", &sk).unwrap()).unwrap(),
    )
    .unwrap();

    // Build the verifier around a shared RimStore; the loader holds a clone.
    let store = RimStore::new();
    let loader = RimLoader::new(&bundle_path, trusted, store.clone());
    let outcome = loader.try_reload().expect("reload");
    assert!(matches!(outcome, ReloadOutcome::Applied(_)));

    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(evidence.ek_root_der(), Vendor::Infineon)
        .unwrap();
    let verifier = TpmQuoteVerifier::new(trust, store);
    let state = state_with_verifier(verifier).await;
    let mut client = spawn_server(state).await;

    let attested = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string())
        .await
        .expect("attestation succeeds against the loaded RIM");
    let jwks = ferro_svid_verify::JwkSet::from_json(
        &client
            .jwks(ferro_proto::v1::JwksRequest::default())
            .await
            .unwrap()
            .into_inner()
            .jwks_json,
    )
    .unwrap();
    let result = ferro_svid_verify::verify(
        &attested.bundle.jws,
        &jwks,
        attested.bundle.issued_at + 10,
        0,
    )
    .unwrap();
    assert_eq!(result.claims.attest.policy_id, "loader-fleet");

    std::fs::remove_file(bundle_path).ok();
}

// --- F07: audit log RPCs ----------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // step-by-step exposition of the audit RPC contract.
async fn audit_log_records_attest_events_and_proofs_verify_offline() {
    use base64::Engine as _;
    use ferro_audit::{event as audit_event, verify_sth, AuditEvent, Hash384};
    use ferro_proto::v1::{ConsistencyProofRequest, InclusionProofRequest, LatestSthRequest};

    let mut evidence = VirtualTpm::ephemeral().unwrap();
    let (state, audit_pk) = state_with_verifier_capturing_audit({
        let mut trust = VendorTrustStore::new();
        trust
            .add_root_der(evidence.ek_root_der(), Vendor::Infineon)
            .unwrap();
        let pcr_digest = expected_pcr_digest();
        let rim = RimStore::new();
        rim.approve(pcr_digest, PolicyId("test-fleet".into()))
            .unwrap();
        TpmQuoteVerifier::new(trust, rim)
    })
    .await;
    let mut client = spawn_server(state).await;

    // The host machine key: the SVID binds it through `cnf.jkt`, and it
    // signs the `AppendAuditEvent` host proof (F20 Phase 0).
    let machine_key = ferro_sep::SoftwareMachineKey::generate().unwrap();
    let jkt = {
        use ferro_sep::MachineKey as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(machine_key.public_spki_der()))
    };

    // Drive a successful attestation. CMIS appends AttestStart + SvidIssued.
    let attested = run_attest(&mut client, &mut evidence, jkt).await.unwrap();
    let svid = attested.bundle;
    let host_uuid = svid
        .spiffe_id
        .rsplit_once("/host/")
        .map(|(_, u)| u.to_string())
        .expect("a host SPIFFE id");

    // The latest STH must verify under the audit publisher key and report a
    // size of at least 2 leaves (AttestStart + SvidIssued).
    let sth_resp = client
        .latest_sth(LatestSthRequest {})
        .await
        .unwrap()
        .into_inner();
    let proto_sth = sth_resp.sth.expect("server returned an STH");
    let sth = ferro_audit::SignedTreeHead {
        body_cbor: proto_sth.body_cbor,
        signer_kid: proto_sth.signer_kid,
        signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&proto_sth.signature),
    };
    let body = verify_sth(&sth, &audit_pk).expect("STH must verify under audit publisher key");
    assert!(body.tree_size >= 2);

    // Fetch and verify an inclusion proof for the AttestStart leaf (index 0).
    let inc_resp = client
        .inclusion_proof(InclusionProofRequest { leaf_index: 0 })
        .await
        .unwrap()
        .into_inner();
    let mut leaf = [0u8; 48];
    leaf.copy_from_slice(&inc_resp.leaf_hash);
    let mut root = [0u8; 48];
    root.copy_from_slice(&inc_resp.root_hash);
    let path: Vec<[u8; 48]> = inc_resp
        .audit_path
        .iter()
        .map(|h| {
            let mut a = [0u8; 48];
            a.copy_from_slice(h);
            a
        })
        .collect();
    assert!(
        ferro_audit::verify_inclusion(
            &leaf,
            inc_resp.leaf_index as usize,
            inc_resp.tree_size as usize,
            &root,
            &path,
        ),
        "inclusion proof must verify offline"
    );
    // The published STH must agree with the proof's root.
    assert_eq!(body.root_hash.0, root);

    // Forward a MIA-side event, host-signed; the tree grows; consistency from
    // the old size back to the new size verifies.
    let old_size = body.tree_size;
    let signer = mia::audit_client::HostProofSigner {
        key: &machine_key,
        svid_jws: &svid.jws,
        host_uuid: &host_uuid,
    };
    let leaf_idx = mia::audit_client::forward(
        &mut client,
        &AuditEvent::LocalGrant {
            pid: 4242,
            uid: 1000,
            bin_sha: Hash384([0xAA; 48]),
            jti: ferro_audit::Bytes16([0x55; 16]),
        },
        &signer,
    )
    .await
    .expect("audit forward succeeds");
    assert_eq!(leaf_idx, old_size);

    // A key the SVID does not bind cannot forward in this host's name.
    let impostor = ferro_sep::SoftwareMachineKey::generate().unwrap();
    let refused = mia::audit_client::forward(
        &mut client,
        &AuditEvent::LocalGrant {
            pid: 1,
            uid: 0,
            bin_sha: Hash384([0xBB; 48]),
            jti: ferro_audit::Bytes16([0x66; 16]),
        },
        &mia::audit_client::HostProofSigner {
            key: &impostor,
            svid_jws: &svid.jws,
            host_uuid: &host_uuid,
        },
    )
    .await
    .expect_err("an unbound key is refused");
    assert!(
        matches!(&refused, mia::audit_client::AuditForwardError::Transport(s) if s.code() == tonic::Code::Unauthenticated),
        "{refused:?}"
    );

    // Inclusion of the new leaf, then consistency back to the previous STH.
    let inc2 = client
        .inclusion_proof(InclusionProofRequest {
            leaf_index: leaf_idx,
        })
        .await
        .unwrap()
        .into_inner();
    let mut new_root = [0u8; 48];
    new_root.copy_from_slice(&inc2.root_hash);
    let event_bytes = audit_event::encode(&AuditEvent::LocalGrant {
        pid: 4242,
        uid: 1000,
        bin_sha: Hash384([0xAA; 48]),
        jti: ferro_audit::Bytes16([0x55; 16]),
    })
    .unwrap();
    let expected_leaf = ferro_audit::leaf_hash(&event_bytes);
    assert_eq!(inc2.leaf_hash, expected_leaf.to_vec());

    let cons = client
        .consistency_proof(ConsistencyProofRequest { old_size })
        .await
        .unwrap()
        .into_inner();
    let cons_path: Vec<[u8; 48]> = cons
        .audit_path
        .iter()
        .map(|h| {
            let mut a = [0u8; 48];
            a.copy_from_slice(h);
            a
        })
        .collect();
    assert!(ferro_audit::verify_consistency(
        old_size as usize,
        cons.new_size as usize,
        &root,
        &new_root,
        &cons_path,
    ));

    // T291: the daemon's forwarder spools an event and delivers it through
    // the same RPC, host-signed with the host credentials; CMIS appends it.
    let spool_dir =
        std::env::temp_dir().join(format!("mia-e2e-audit-spool-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&spool_dir);
    let _cleanup = RemoveOnDrop(spool_dir.clone());
    let creds = mia::host_api::CredentialSlot::new();
    creds.set(mia::host_api::HostCredentials::new(
        Arc::new(machine_key),
        svid.jws.clone(),
        &svid.spiffe_id,
        svid.expires_at,
    ));
    let (tx, rx) = tokio::sync::mpsc::channel(mia::audit_forward::CHANNEL_CAPACITY);
    let forwarder = mia::audit_forward::spawn(
        rx,
        Some(mia::audit_forward::Forwarding {
            api: Arc::new(mia::audit_forward::ChannelAuditApi::new(client.clone())),
            creds,
        }),
        &spool_dir.join("audit-spool.jsonl"),
        mia::audit_forward::ForwarderConfig::default(),
    );
    tx.send(AuditEvent::LocalDenied {
        pid: 77,
        uid: 1000,
        bin_sha: Hash384([0xCC; 48]),
        reason: "not_allowlisted".into(),
    })
    .await
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while forwarder.stats().forwarded == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the forwarder did not deliver: {:?}",
            forwarder.stats()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(forwarder.stats().pending, 0);
    let latest = client
        .latest_sth(LatestSthRequest {})
        .await
        .unwrap()
        .into_inner()
        .sth
        .expect("server returned an STH");
    let latest = verify_sth(
        &ferro_audit::SignedTreeHead {
            body_cbor: latest.body_cbor,
            signer_kid: latest.signer_kid,
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&latest.signature),
        },
        &audit_pk,
    )
    .expect("STH must verify under audit publisher key");
    assert_eq!(latest.tree_size, cons.new_size + 1);
    forwarder.abort();
}

/// Removes a scratch directory when dropped, a failed test included.
struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// --- F10: bump_epoch forces full re-attestation -----------------------------

#[tokio::test]
async fn bump_epoch_forces_full_reattestation_on_next_rotate() {
    let state = host_key_state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let facts = sample_facts();
    let fingerprint = facts.fingerprint();
    let key = SoftwareMachineKey::generate().unwrap();

    // Attest under epoch 1, then confirm a same-epoch, host-signed rotate
    // takes the short path — the control for the assertion below.
    let attested = attest_host_key(&mut client, &facts, &key).await;
    let renewed = signed_rotate(&mut client, &key, &attested.bundle, fingerprint.as_bytes())
        .await
        .expect("short-path rotate succeeds before the bump");

    // A host cannot bump the epoch: BumpEpoch is an admin RPC and, since
    // F20 Phase 0, needs an authenticated admin session.
    let refused = client
        .bump_epoch(BumpEpochRequest {
            reason: "rim-policy-change".into(),
        })
        .await
        .expect_err("an unauthenticated caller must not bump the epoch");
    assert_eq!(refused.code(), tonic::Code::Unauthenticated);
    assert_eq!(state.current_epoch(), 1, "the refused call changed nothing");

    // The operator bumps the live policy epoch (the authenticated admin path
    // is covered in crates/cmis/tests/admin_*.rs).
    let (_old, new_epoch) = state.bump_epoch();
    assert_eq!(new_epoch, 2, "epoch advanced 1 -> 2");

    // The host was attested under epoch 1; with the live epoch now 2, its
    // next rotate (from its latest SVID) must be refused so it is driven back
    // through a full Attest.
    let err = signed_rotate(&mut client, &key, &renewed, fingerprint.as_bytes())
        .await
        .expect_err("rotate must be refused after an epoch bump");
    assert_eq!(refused_code(err), tonic::Code::FailedPrecondition);

    // A full re-attestation under the new epoch makes renewal possible again.
    let reattested = attest_host_key(&mut client, &facts, &key).await;
    signed_rotate(
        &mut client,
        &key,
        &reattested.bundle,
        fingerprint.as_bytes(),
    )
    .await
    .expect("renewal works again after re-attesting under epoch 2");
}

// --- T295: a revoked host cannot re-attest ------------------------------------

#[tokio::test]
async fn attest_refuses_revoked_host_tpm_tier() {
    let mut evidence = VirtualTpm::ephemeral().unwrap();
    let state = build_state(&evidence).await;
    let mut client = spawn_server(Arc::clone(&state)).await;

    let attested = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string())
        .await
        .expect("an unrevoked TPM host attests");
    state.revoke(
        ferro_svid::RevocationTarget::Host {
            spiffe_id: attested.bundle.spiffe_id.clone(),
        },
        "compromised",
        attested.bundle.issued_at,
    );

    // The full four-phase handshake runs (the quote and credential are
    // genuine), but no SVID is issued to the revoked SPIFFE id and its new
    // child key is not published.
    let keys_before = state.published_jwks().keys.len();
    let Err(mia::client::AttestClientError::Transport(status)) =
        run_attest(&mut client, &mut evidence, "dpop-thumb".to_string()).await
    else {
        panic!("a revoked host must be refused by the RPC");
    };
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), cmis::service::HOST_REVOKED);
    let stored = state
        .lookup(&attested.bundle.spiffe_id)
        .await
        .expect("record kept");
    assert_eq!(stored.bundle.jws, attested.bundle.jws, "nothing new stored");
    assert_eq!(state.published_jwks().keys.len(), keys_before);
}

// --- F13: fleet enrolment pre-admission -------------------------------------

/// Apply an enforcing fleet manifest to `state` enrolling exactly the given EK
/// certificates (by their SHA-384).
fn enroll_eks(state: &CmisState, ek_certs: &[&[u8]]) {
    let manifest = cmis::FleetManifest {
        version: 1,
        trust_domain: "ferrogate.test".to_string(),
        issued_at: 0,
        enrolled_ek_sha384: ek_certs
            .iter()
            .map(|c| hex::encode(Sha384::digest(c)))
            .collect(),
        enrolled_machine_id: Vec::new(),
        enrolled_machine_pubkey: Vec::new(),
    };
    state.fleet().apply(manifest.to_enrolled().unwrap());
}

#[tokio::test]
async fn enrolled_host_attests_end_to_end() {
    let mut evidence = VirtualTpm::ephemeral().unwrap();
    let state = build_state(&evidence).await;
    // The host's EK is in the manifest — admission passes, attestation runs.
    enroll_eks(&state, &[evidence.ek_cert_der()]);
    let mut client = spawn_server(state).await;

    let attested = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string())
        .await
        .expect("enrolled host attests end-to-end");
    assert!(attested
        .bundle
        .spiffe_id
        .starts_with("spiffe://ferrogate.test/host/"));
}

#[tokio::test]
async fn unenrolled_host_is_rejected_before_quote_verification() {
    let mut evidence = VirtualTpm::ephemeral().unwrap();
    // `build_state` trusts this EK and approves the PCR digest, so absent a
    // manifest this exact host attests successfully (see the test above). The
    // *only* change here is enforcing a manifest that omits its EK, so any
    // failure is attributable to the F13 pre-admission gate.
    let state = build_state(&evidence).await;
    enroll_eks(&state, &[b"a-different-host-ek-cert"]);
    let audit_before = state.audit.len();
    let mut client = spawn_server(Arc::clone(&state)).await;

    let Err(err) = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string()).await else {
        panic!("un-enrolled host must be refused");
    };
    let status = match err {
        mia::client::AttestClientError::Transport(s) => s,
        other => panic!("expected transport error, got {other:?}"),
    };
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    // Exactly one leaf (HostRejected) was appended: the handshake stopped at
    // pre-admission, before any AttestStart or quote-verification work — which
    // would otherwise have written two or more leaves.
    assert_eq!(
        state.audit.len(),
        audit_before + 1,
        "only a HostRejected event should be recorded"
    );
}

// --- T294: the daemon renews its host SVID while running -------------------

/// The host-key backend against the in-process CMIS, as the daemon's
/// attestor: records the key policy of every call; `facts` can be switched
/// to make CMIS issue another identity.
struct E2eAttestor {
    client: MachineIdentityClient<tonic::transport::Channel>,
    facts: std::sync::Mutex<ferro_machineid::MachineFacts>,
    key: Arc<SoftwareMachineKey>,
    seed: [u8; 32],
    policies: Arc<std::sync::Mutex<Vec<mia::renewal::KeyPolicy>>>,
}

/// The [`mia::renewal::Attested`] a seeded host-key attestation yields.
fn attested_of(attested: AttestedSvid, key: &Arc<SoftwareMachineKey>) -> mia::renewal::Attested {
    let kid = ferro_svid::child_signing_kid(&attested.svid_public);
    let key: Arc<dyn ferro_sep::MachineKey + Send + Sync> = key.clone();
    mia::renewal::Attested {
        svid: mia::renewal::HostSvid::new(
            attested.bundle,
            Arc::new(attested.svid_secret),
            kid,
            Some(key),
        ),
        seeded: true,
    }
}

impl mia::renewal::HostAttestor for E2eAttestor {
    fn attest(
        &self,
        policy: mia::renewal::KeyPolicy,
    ) -> futures::future::BoxFuture<'_, Result<mia::renewal::Attested, mia::status::AttestFailure>>
    {
        self.policies.lock().unwrap().push(policy);
        let facts = self.facts.lock().unwrap().clone();
        let mut client = self.client.clone();
        Box::pin(async move {
            let attested = run_attest_host_key(
                &mut client,
                &facts,
                &*self.key,
                jkt_of(&self.key),
                Some(&self.seed),
            )
            .await
            .map_err(|e| mia::status::AttestFailure::from_attest_error(&e, false))?;
            Ok(attested_of(attested, &self.key))
        })
    }
}

/// Records the SVIDs the refresh after a swap saw.
#[derive(Clone, Default)]
struct RecordingHooks(Arc<std::sync::Mutex<Vec<String>>>);

impl mia::renewal::RenewalHooks for RecordingHooks {
    fn after_install<'a>(
        &'a mut self,
        svid: &'a mia::renewal::HostSvid,
    ) -> futures::future::BoxFuture<'a, ()> {
        self.0.lock().unwrap().push(svid.jws.clone());
        Box::pin(async {})
    }
}

/// The helper API's minter, as the swap sees it.
#[derive(Default)]
struct LiveMinter(std::sync::Mutex<Option<mia::helper::ChildTokenMinter>>);

impl mia::renewal::MinterSink for LiveMinter {
    fn set(
        &self,
        minter: Option<mia::helper::ChildTokenMinter>,
    ) -> futures::future::BoxFuture<'_, ()> {
        *self.0.lock().unwrap() = minter;
        Box::pin(async {})
    }
}

/// Mint one child token with the live minter; its `(kid, parent_svid)`.
fn mint_with(live: &LiveMinter, now: i64) -> (String, String) {
    use mia::helper::token::{ChildClaims, ChildHeader};
    let minter = live.0.lock().unwrap().clone().expect("minting is on");
    let actor = mia::helper::CallerIdentity::new(4321, 1000, 1000, [0xAB; 48]);
    let token = minter
        .mint("https://api.test", "jkt", 60, &actor, now)
        .unwrap();
    let mut parts = token.jws.split('.');
    let decode = |p: Option<&str>| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p.unwrap())
            .unwrap()
    };
    let header: ChildHeader = serde_json::from_slice(&decode(parts.next())).unwrap();
    let claims: ChildClaims = serde_json::from_slice(&decode(parts.next())).unwrap();
    (header.kid, claims.ferrogate.parent_svid)
}

/// The sealed X.509 leaf at `path`, opened with `fingerprint`.
fn sealed_leaf(path: &std::path::Path, fingerprint: &[u8], now: i64) -> Vec<u8> {
    mia::credstore::with_sealer(Some(fingerprint), |sealer| {
        mia::credstore::load(path, sealer, now)
    })
    .expect("a sealer")
    .expect("the store opens")
    .expect("a credential is stored")
    .credential
    .leaf_der
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one renewal lifecycle, step by step.
async fn daemon_renews_host_svid_before_expiry() {
    use ferro_audit::{AuditEvent, Hash384};
    use mia::renewal::{KeyPolicy, RenewalPath, X509Sealer as _};

    let state = host_key_state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let facts = sample_facts();
    let fingerprint = facts.fingerprint().as_bytes().to_vec();
    let key = Arc::new(SoftwareMachineKey::generate().unwrap());
    let seed = [7u8; 32];
    let dir = std::env::temp_dir().join(format!("mia-e2e-renew-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    let store_path = dir.join("x509-svid.sealed");

    // Start-up, as `serve` does it: attest, seal, swap in.
    let attested = run_attest_host_key(&mut client, &facts, &*key, jkt_of(&key), Some(&seed))
        .await
        .unwrap();
    let first = attested_of(attested, &key);
    let store = mia::renewal::X509Store::new(store_path.clone(), Some(fingerprint.clone()));
    store.seal(&first.svid).expect("sealed at start");
    let creds = mia::host_api::CredentialSlot::new();
    let live = Arc::new(LiveMinter::default());
    let cell = mia::renewal::SvidCell::new();
    let swap = mia::renewal::Swap::new(
        creds.clone(),
        Arc::clone(&live) as Arc<dyn mia::renewal::MinterSink>,
        cell.clone(),
    );
    swap.install(&first.svid).await;
    let (start_kid, _) = mint_with(&live, first.svid.issued_at);

    // Audit forwarding signs with whatever the slot holds.
    let spool_dir = dir.join("spool");
    let (tx, rx) = tokio::sync::mpsc::channel(mia::audit_forward::CHANNEL_CAPACITY);
    let forwarder = mia::audit_forward::spawn(
        rx,
        Some(mia::audit_forward::Forwarding {
            api: Arc::new(mia::audit_forward::ChannelAuditApi::new(client.clone())),
            creds: creds.clone(),
        }),
        &spool_dir.join("audit-spool.jsonl"),
        mia::audit_forward::ForwarderConfig::default(),
    );

    // The daemon's renewer over the real Rotate, swap and X.509 store.
    let policies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hooks = RecordingHooks::default();
    let status = mia::status::StatusHandle::new("default", first.svid.issued_at);
    let (iat, exp) = (first.svid.issued_at, first.svid.expires_at);
    let attestor = E2eAttestor {
        client: client.clone(),
        facts: std::sync::Mutex::new(facts.clone()),
        key: Arc::clone(&key),
        seed,
        policies: Arc::clone(&policies),
    };
    let host_renewer = mia::renewal::HostRenewer::new(
        attestor,
        client.clone(),
        mia::renewal::X509Store::new(store_path.clone(), Some(fingerprint.clone())),
        hooks.clone(),
        swap.clone(),
        status.clone(),
        Some(*facts.fingerprint().as_bytes()),
    )
    .with_current(&first);
    let mut renewal = mia::renewal::Renewal::new(host_renewer, status.clone())
        .with_jitter(|| 0.5)
        .with_current(first.svid.info(), iat);

    // The daemon's clock reaches the renewal point (60 % of a 1 h test TTL)
    // well before expiry: inside the 24 h window it renews with Rotate.
    let due = iat + (exp - iat) * 6 / 10;
    let wait = renewal.step(due).await.expect("renewal succeeds");
    let renewed = creds.get().expect("credentials stay in force");
    assert_ne!(renewed.svid_jws, first.svid.jws, "a new SVID is in force");
    assert!(renewed.valid_at(due));
    assert!(wait >= mia::renewal::schedule::RETRY_BASE, "{wait:?}");
    assert!(policies.lock().unwrap().is_empty(), "no full attestation");
    assert_eq!(
        *hooks.0.lock().unwrap(),
        std::slice::from_ref(&renewed.svid_jws)
    );
    let jwks = ferro_svid_verify::JwkSet::from_json(&fetch_jwks(&mut client).await).unwrap();
    let verified = ferro_svid_verify::verify(&renewed.svid_jws, &jwks, iat + 10, 0).unwrap();
    assert_eq!(verified.claims.sub, first.svid.spiffe_id);
    assert_eq!(verified.claims.cnf.jkt, jkt_of(&key));

    // Minting continues under the same key (kid), parented on the new SVID.
    let (kid_after, parent_after) = mint_with(&live, due);
    assert_eq!(kid_after, start_kid);
    assert_eq!(
        parent_after,
        hex::encode(Sha384::digest(renewed.svid_jws.as_bytes()))
    );
    assert!(jwks.keys.iter().any(|k| k.kid == kid_after));
    assert_eq!(
        cell.jws_valid_at(due).as_deref(),
        Some(renewed.svid_jws.as_str())
    );
    // The sealed X.509-SVID was replaced by the renewed leaf.
    let leaf = sealed_leaf(&store_path, &fingerprint, iat + 10);
    assert_ne!(leaf, first.svid.x509_svid, "re-sealed after Rotate");

    // Forwarding signs with the renewed credentials and CMIS accepts them.
    tx.send(AuditEvent::LocalDenied {
        pid: 77,
        uid: 1000,
        bin_sha: Hash384([0xCC; 48]),
        reason: "not_allowlisted".into(),
    })
    .await
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while forwarder.stats().forwarded == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the forwarder did not deliver with the renewed SVID: {:?}",
            forwarder.stats()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    forwarder.abort();

    // An operator epoch bump makes CMIS refuse the next Rotate: the same step
    // falls back to a full attestation that only reopens the seeded key, and
    // keeps the same identity and kid.
    state.bump_epoch();
    let next_due = due + i64::try_from(wait.as_secs()).unwrap();
    renewal.step(next_due).await.expect("fallback succeeds");
    assert_eq!(
        *policies.lock().unwrap(),
        [KeyPolicy::OpenOnly {
            seed_required: true,
            kid: Some(start_kid.clone())
        }]
    );
    let reattested = creds.get().unwrap();
    assert_ne!(reattested.svid_jws, renewed.svid_jws);
    assert_eq!(mint_with(&live, next_due).0, start_kid);
    assert_eq!(hooks.0.lock().unwrap().len(), 2);
    assert_eq!(
        status.observe().await.phase,
        mia::status::AttestPhase::Attested
    );
    let _ = RenewalPath::FullAttest;
}

#[tokio::test]
async fn an_identity_change_stops_the_daemon_and_minting() {
    // A re-enrolled host: CMIS issues an SVID for another SPIFFE id. The
    // renewal task stops with a fatal exit (`serve` then returns an error)
    // and minting is off; nothing is sealed.
    let state = host_key_state().await;
    let mut client = spawn_server(Arc::clone(&state)).await;
    let facts = sample_facts();
    let key = Arc::new(SoftwareMachineKey::generate().unwrap());
    let seed = [9u8; 32];
    let attested = run_attest_host_key(&mut client, &facts, &*key, jkt_of(&key), Some(&seed))
        .await
        .unwrap();
    let first = attested_of(attested, &key);
    let creds = mia::host_api::CredentialSlot::new();
    let live = Arc::new(LiveMinter::default());
    let swap = mia::renewal::Swap::new(
        creds.clone(),
        Arc::clone(&live) as Arc<dyn mia::renewal::MinterSink>,
        mia::renewal::SvidCell::new(),
    );
    swap.install(&first.svid).await;
    let mut other = facts.clone();
    other.board_serial = "ANOTHER-BOARD".into();
    let attestor = E2eAttestor {
        client: client.clone(),
        facts: std::sync::Mutex::new(other),
        key: Arc::new(SoftwareMachineKey::generate().unwrap()),
        seed,
        policies: Arc::default(),
    };
    let status = mia::status::StatusHandle::new("default", first.svid.issued_at);
    // No fingerprint: no Rotate, straight to the full attestation.
    let renewer = mia::renewal::HostRenewer::new(
        attestor,
        client.clone(),
        (),
        (),
        swap.clone(),
        status.clone(),
        None,
    )
    .with_current(&first);
    let due = first.svid.issued_at + 2160;
    let renewal = mia::renewal::Renewal::new(renewer, status.clone())
        .with_jitter(|| 0.5)
        .with_current(first.svid.info(), first.svid.issued_at);
    let rx = mia::renewal::spawn(renewal, swap, move || due, std::future::pending::<()>());
    let fatal = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        mia::renewal::next_fatal(Some(rx)),
    )
    .await
    .expect("the renewal stops the daemon");
    assert!(matches!(fatal, mia::renewal::Fatal::IdentityChanged { .. }));
    assert!(live.0.lock().unwrap().is_none(), "minting is off");
    assert!(creds.get().is_none(), "host calls are off");
    assert_eq!(
        status.observe().await.phase,
        mia::status::AttestPhase::Failed(mia::status::AttestFailure::IdentityChanged)
    );
}
