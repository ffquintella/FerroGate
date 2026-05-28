//! End-to-end F04 integration test over a real in-process tonic gRPC channel.
//!
//! A software [`AttestEvidence`] mints wire-correct synthetic TPM structures
//! (the same approach as `ferro-attest`'s verifier tests) so the full
//! four-phase handshake runs without a TPM. We assert that:
//!
//! - `Attest` issues a JWS that the independent reference verifier accepts
//!   against the JWKS the server publishes;
//! - `Rotate` takes the short path (no re-attestation) when PCRs and the policy
//!   epoch are unchanged;
//! - `Rotate` is refused (full re-attestation required) when the reported PCRs
//!   drift.

#![allow(clippy::cast_possible_truncation)]
// The handshake future holds a composite key (incl. a ~4 KB ML-DSA secret)
// across awaits; that is inherent, not a bug.
#![allow(clippy::large_futures)]

use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::tpm::{
    TPMA_FIXED_PARENT, TPMA_FIXED_TPM, TPMA_RESTRICTED, TPMA_SENSITIVE_DATA_ORIGIN, TPMA_SIGN,
    TPMA_USER_WITH_AUTH, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_ECC_NIST_P256, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use ferro_attest::{PolicyId, RimStore, TpmQuoteVerifier, Vendor, VendorTrustStore};
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{PcrValue, RotateRequest};
use ferro_svid::Issuer;
use mia::client::{run_attest, AttestEvidence, QuoteEvidence};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};

// --- wire builders (mirror of ferro-attest's verifier-test helpers) ---------

const PCR_INDICES: [u8; 11] = [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 14];

fn push_u16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_be_bytes());
}
fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}
fn push_tpm2b(b: &mut Vec<u8>, data: &[u8]) {
    push_u16(b, data.len() as u16);
    b.extend_from_slice(data);
}

fn marshal_aik_public(vk: &VerifyingKey) -> Vec<u8> {
    let pt = vk.to_encoded_point(false);
    let (x, y) = (pt.x().unwrap(), pt.y().unwrap());
    let attrs = TPMA_FIXED_TPM
        | TPMA_FIXED_PARENT
        | TPMA_SENSITIVE_DATA_ORIGIN
        | TPMA_USER_WITH_AUTH
        | TPMA_RESTRICTED
        | TPMA_SIGN;
    let mut b = Vec::new();
    push_u16(&mut b, TPM_ALG_ECC);
    push_u16(&mut b, TPM_ALG_SHA256);
    push_u32(&mut b, attrs);
    push_tpm2b(&mut b, &[]);
    push_u16(&mut b, 0x0010); // symmetric NULL
    push_u16(&mut b, TPM_ALG_ECDSA);
    push_u16(&mut b, TPM_ALG_SHA256); // scheme hash
    push_u16(&mut b, TPM_ECC_NIST_P256);
    push_u16(&mut b, 0x0010); // kdf NULL
    push_tpm2b(&mut b, x);
    push_tpm2b(&mut b, y);
    b
}

fn pcr_bitmap() -> Vec<u8> {
    let mut bm = vec![0u8; 3];
    for &i in &PCR_INDICES {
        bm[(i / 8) as usize] |= 1 << (i % 8);
    }
    bm
}

fn pcr_values() -> Vec<(u8, Vec<u8>)> {
    PCR_INDICES.iter().map(|&i| (i, vec![i; 48])).collect()
}

fn build_quote(nonce: &[u8]) -> (Vec<u8>, [u8; 48]) {
    let mut agg = Sha384::new();
    for &i in &PCR_INDICES {
        agg.update([i; 48]);
    }
    let mut pcr_digest = [0u8; 48];
    pcr_digest.copy_from_slice(&agg.finalize());

    let mut b = Vec::new();
    push_u32(&mut b, TPM_GENERATED_VALUE);
    push_u16(&mut b, TPM_ST_ATTEST_QUOTE);
    push_tpm2b(&mut b, b"qualified-signer");
    push_tpm2b(&mut b, nonce);
    b.extend_from_slice(&0u64.to_be_bytes());
    push_u32(&mut b, 1);
    push_u32(&mut b, 0);
    b.push(1);
    b.extend_from_slice(&0u64.to_be_bytes());
    push_u32(&mut b, 1); // pcrSelect.count
    push_u16(&mut b, TPM_ALG_SHA384);
    let bm = pcr_bitmap();
    b.push(bm.len() as u8);
    b.extend_from_slice(&bm);
    push_tpm2b(&mut b, &pcr_digest);
    (b, pcr_digest)
}

fn marshal_signature(hash_alg: u16, r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    push_u16(&mut b, TPM_ALG_ECDSA);
    push_u16(&mut b, hash_alg);
    push_tpm2b(&mut b, r);
    push_tpm2b(&mut b, s);
    b
}

fn build_ek_chain() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.not_before = date_time_ymd(2020, 1, 1);
    ca.not_after = date_time_ymd(2035, 1, 1);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["ek.host".to_string()]).unwrap();
    leaf.not_before = date_time_ymd(2020, 1, 1);
    leaf.not_after = date_time_ymd(2035, 1, 1);
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    (leaf_cert.der().to_vec(), ca_cert.der().to_vec())
}

// --- software evidence + credential channel ---------------------------------

fn activation_keystream(ek_cert: &[u8], aik_pub: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ek_cert);
    h.update(aik_pub);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

/// Software-only credential channel matching [`SoftwareEvidence::activate`].
/// NOT TPM-faithful — it only exercises the phase-3 plumbing for the test.
struct SoftwareCredentialMaker;

impl CredentialMaker for SoftwareCredentialMaker {
    fn make_credential(
        &self,
        ek_pub: &[u8],
        aik_pub: &[u8],
        secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        let ks = activation_keystream(ek_pub, aik_pub);
        let blob: Vec<u8> = secret.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        Ok(WrappedCredential {
            credential_blob: blob,
            secret_blob: Vec::new(),
        })
    }
}

struct SoftwareEvidence {
    aik: SigningKey,
    aik_pub: Vec<u8>,
    ek_cert: Vec<u8>,
    ek_root: Vec<u8>,
}

impl SoftwareEvidence {
    fn new() -> Self {
        let aik = SigningKey::random(&mut rand_core::OsRng);
        let aik_pub = marshal_aik_public(aik.verifying_key());
        let (ek_cert, ek_root) = build_ek_chain();
        Self {
            aik,
            aik_pub,
            ek_cert,
            ek_root,
        }
    }
}

impl AttestEvidence for SoftwareEvidence {
    fn ek_cert(&self) -> Vec<u8> {
        self.ek_cert.clone()
    }
    fn aik_pub(&self) -> Vec<u8> {
        self.aik_pub.clone()
    }
    fn quote(&mut self, nonce: &[u8]) -> anyhow::Result<QuoteEvidence> {
        let (blob, _digest) = build_quote(nonce);
        let sig: Signature = self.aik.sign_prehash(&Sha256::digest(&blob)).unwrap();
        let bytes = sig.to_bytes();
        Ok(QuoteEvidence {
            attest_blob: blob,
            signature: marshal_signature(TPM_ALG_SHA256, &bytes[..32], &bytes[32..]),
            pcr_values: pcr_values(),
        })
    }
    fn activate(&mut self, credential_blob: &[u8], _secret_blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ks = activation_keystream(&self.ek_cert, &self.aik_pub);
        Ok(credential_blob
            .iter()
            .zip(ks.iter())
            .map(|(a, b)| a ^ b)
            .collect())
    }
    fn sign_aik(&mut self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Real AIK hashes with SHA-384 internally; mirror that here.
        let sig: Signature = self.aik.sign_prehash(&Sha384::digest(message)).unwrap();
        let bytes = sig.to_bytes();
        Ok(marshal_signature(
            TPM_ALG_SHA384,
            &bytes[..32],
            &bytes[32..],
        ))
    }
}

// --- server harness ---------------------------------------------------------

fn build_state(evidence: &SoftwareEvidence) -> Arc<CmisState> {
    // Trust the synthetic EK root and approve the synthetic PCR digest.
    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(&evidence.ek_root, Vendor::Infineon)
        .unwrap();
    let (_blob, pcr_digest) = build_quote(&[0u8; 32]);
    let rim = RimStore::new();
    rim.approve(pcr_digest, PolicyId("test-fleet".into()));
    let verifier = TpmQuoteVerifier::new(trust, rim);
    state_with_verifier(verifier)
}

fn state_with_verifier(verifier: TpmQuoteVerifier) -> Arc<CmisState> {
    let issuer = Issuer::generate("kid-e2e", "ferrogate.test").unwrap();
    Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(SoftwareCredentialMaker),
        CmisConfig {
            trust_domain: "ferrogate.test".to_string(),
            svid_ttl_secs: 3600,
            policy_epoch: 1,
        },
    ))
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
        .jwks(ferro_proto::v1::JwksRequest {})
        .await
        .unwrap()
        .into_inner()
        .jwks_json
}

// --- tests -------------------------------------------------------------------

#[tokio::test]
async fn attest_issues_svid_that_reference_verifier_accepts() {
    let mut evidence = SoftwareEvidence::new();
    let state = build_state(&evidence);
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
}

#[tokio::test]
async fn rotate_short_path_when_pcrs_unchanged() {
    let mut evidence = SoftwareEvidence::new();
    let state = build_state(&evidence);
    let mut client = spawn_server(state).await;

    let attested = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string())
        .await
        .unwrap();

    // Same PCRs, same epoch, inside the window: short path succeeds, no TPM.
    let rotated = client
        .rotate(RotateRequest {
            current_svid: attested.bundle.jws.clone(),
            pcr_values: pcr_values()
                .into_iter()
                .map(|(index, value)| PcrValue {
                    index: u32::from(index),
                    value,
                })
                .collect(),
            known_epoch: 1,
        })
        .await
        .expect("short-path rotate succeeds")
        .into_inner();

    assert_eq!(rotated.spiffe_id, attested.bundle.spiffe_id);
    let jwks = ferro_svid_verify::JwkSet::from_json(&fetch_jwks(&mut client).await).unwrap();
    ferro_svid_verify::verify(&rotated.jws, &jwks, rotated.issued_at + 10, 0).unwrap();
}

#[tokio::test]
async fn rotate_refused_on_pcr_drift() {
    let mut evidence = SoftwareEvidence::new();
    let state = build_state(&evidence);
    let mut client = spawn_server(state).await;

    let attested = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string())
        .await
        .unwrap();

    // Tamper one PCR value -> drift -> server forces full re-attestation.
    let mut drifted = pcr_values();
    drifted[0].1[0] ^= 0xFF;
    let status = client
        .rotate(RotateRequest {
            current_svid: attested.bundle.jws.clone(),
            pcr_values: drifted
                .into_iter()
                .map(|(index, value)| PcrValue {
                    index: u32::from(index),
                    value,
                })
                .collect(),
            known_epoch: 1,
        })
        .await
        .expect_err("rotate must be refused on drift");

    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}

// --- F10: RIM bundle / loader / status mapping ------------------------------

#[tokio::test]
async fn attest_returns_failed_precondition_when_digest_not_in_rim() {
    let mut evidence = SoftwareEvidence::new();

    // Verifier with the EK root trusted but an *empty* RIM — the verifier will
    // accept everything up to step 7 (RIM lookup), then reject with NotInRim
    // which the service maps to FAILED_PRECONDITION (`docs/cmis.md` error model).
    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(&evidence.ek_root, Vendor::Infineon)
        .unwrap();
    let verifier = TpmQuoteVerifier::new(trust, RimStore::new());
    let state = state_with_verifier(verifier);
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

    let mut evidence = SoftwareEvidence::new();
    let (_blob, pcr_digest) = build_quote(&[0u8; 32]);

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
        .add_root_der(&evidence.ek_root, Vendor::Infineon)
        .unwrap();
    let verifier = TpmQuoteVerifier::new(trust, store);
    let state = state_with_verifier(verifier);
    let mut client = spawn_server(state).await;

    let attested = run_attest(&mut client, &mut evidence, "dpop-thumb".to_string())
        .await
        .expect("attestation succeeds against the loaded RIM");
    let jwks = ferro_svid_verify::JwkSet::from_json(
        &client
            .jwks(ferro_proto::v1::JwksRequest {})
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
