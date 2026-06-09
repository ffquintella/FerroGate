//! F05 Part 2 acceptance: clustered CMIS issuance is visible on followers.
//!
//! Three CMIS instances are each backed by one node of a 3-node hiqlite
//! cluster. A full `Attest` runs against one CMIS instance; the resulting
//! SVID must then be observable through `FetchSVID` on a different CMIS
//! instance (i.e. one talking to a different cluster node). The point of
//! the test is to prove the issued-record path is genuinely cluster-mediated.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::large_futures
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::tpm::{
    TPMA_FIXED_PARENT, TPMA_FIXED_TPM, TPMA_RESTRICTED, TPMA_SENSITIVE_DATA_ORIGIN, TPMA_SIGN,
    TPMA_USER_WITH_AUTH, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_ECC_NIST_P256, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use ferro_attest::{PolicyId, RimStore, TpmQuoteVerifier, Vendor, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{FetchRequest, HealthRequest, NodeRole as ProtoNodeRole};
use ferro_raft::{Cluster, ClusterConfig, PeerNode};
use ferro_svid::Issuer;
use mia::client::{run_attest, AttestEvidence, QuoteEvidence};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};
use tokio::time::sleep;

// --- wire builders (same shape as crates/mia/tests/e2e_attest.rs) -----------

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
    push_u16(&mut b, 0x0010);
    push_u16(&mut b, TPM_ALG_ECDSA);
    push_u16(&mut b, TPM_ALG_SHA256);
    push_u16(&mut b, TPM_ECC_NIST_P256);
    push_u16(&mut b, 0x0010);
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

fn pcr_values_vec() -> Vec<(u8, Vec<u8>)> {
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
    push_u32(&mut b, 1);
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
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, Issuer, IsCa, KeyPair};
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
    let ca_issuer = Issuer::from_params(&ca, &ca_key);
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_issuer).unwrap();
    (leaf_cert.der().to_vec(), ca_cert.der().to_vec())
}

fn activation_keystream(ek_cert: &[u8], aik_pub: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ek_cert);
    h.update(aik_pub);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

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
            pcr_values: pcr_values_vec(),
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
        let sig: Signature = self.aik.sign_prehash(&Sha384::digest(message)).unwrap();
        let bytes = sig.to_bytes();
        Ok(marshal_signature(
            TPM_ALG_SHA384,
            &bytes[..32],
            &bytes[32..],
        ))
    }
}

// --- cluster + CMIS scaffolding --------------------------------------------

fn temp_root(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("ferrogate-cmis-cluster-{tag}-{nanos}"));
    p
}

fn free_ports() -> Vec<(u16, u16)> {
    let mut ports = Vec::with_capacity(3);
    let mut listeners = Vec::with_capacity(6);
    for _ in 0..3 {
        let raft = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push((
            raft.local_addr().unwrap().port(),
            api.local_addr().unwrap().port(),
        ));
        listeners.push(raft);
        listeners.push(api);
    }
    drop(listeners);
    ports
}

fn peers_for(ports: &[(u16, u16)]) -> Vec<PeerNode> {
    ports
        .iter()
        .enumerate()
        .map(|(i, (raft, api))| PeerNode {
            id: (i as u64) + 1,
            addr_raft: format!("127.0.0.1:{raft}"),
            addr_api: format!("127.0.0.1:{api}"),
        })
        .collect()
}

fn node_cfg(node_id: u64, peers: &[PeerNode], root: &std::path::Path) -> ClusterConfig {
    ClusterConfig::for_node(
        node_id,
        peers.to_vec(),
        root.join(format!("n{node_id}"))
            .to_string_lossy()
            .into_owned(),
    )
}

fn build_clustered_state(
    cluster: Arc<Cluster>,
    evidence: &SoftwareEvidence,
    kid: &str,
) -> Arc<CmisState> {
    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(&evidence.ek_root, Vendor::Infineon)
        .unwrap();
    let (_blob, pcr_digest) = build_quote(&[0u8; 32]);
    let rim = RimStore::new();
    rim.approve(pcr_digest, PolicyId("test-fleet".into()));
    let verifier = TpmQuoteVerifier::new(trust, rim);

    let issuer = Issuer::generate(kid, "ferrogate.test").unwrap();
    let audit_root = {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-cluster-audit-{kid}-{nanos}"));
        p
    };
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(&audit_root).unwrap());
    let (signer, _audit_pk) = InProcessSigner::generate(format!("audit-{kid}")).unwrap();
    let audit = AuditLog::new(store, Arc::new(signer));

    Arc::new(CmisState::new_clustered(
        issuer,
        verifier,
        Box::new(SoftwareCredentialMaker),
        CmisConfig {
            trust_domain: "ferrogate.test".to_string(),
            svid_ttl_secs: 3600,
            policy_epoch: 1,
        },
        audit,
        cluster,
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

async fn wait_for_leader(nodes: &[Arc<Cluster>]) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(id) = nodes[0].leader_id().await {
            let agree = futures::future::join_all(nodes.iter().map(|n| n.leader_id())).await;
            if agree.iter().all(|x| *x == Some(id)) {
                return id;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("cluster did not elect a leader within 20s");
}

// --- the test --------------------------------------------------------------

#[tokio::test]
async fn attest_on_one_node_is_visible_via_fetch_svid_on_a_follower() {
    let root = temp_root("attest-replicates");
    let ports = free_ports();
    let peers = peers_for(&ports);

    // Bring up three hiqlite nodes concurrently.
    let mut starts = Vec::with_capacity(3);
    for id in 1..=3u64 {
        starts.push(Cluster::start(node_cfg(id, &peers, &root)));
    }
    let nodes_vec: Vec<Cluster> = futures::future::try_join_all(starts).await.unwrap();
    let nodes: Vec<Arc<Cluster>> = nodes_vec.into_iter().map(Arc::new).collect();
    let leader_id = wait_for_leader(&nodes).await;

    // Wrap each cluster node in a CMIS instance with its own gRPC server.
    let evidence_template = SoftwareEvidence::new(); // shared EK chain + AIK
    let mut servers = Vec::with_capacity(3);
    for (i, n) in nodes.iter().enumerate() {
        let kid = format!("kid-cluster-{}", i + 1);
        let state = build_clustered_state(n.clone(), &evidence_template, &kid);
        let client = spawn_server(state).await;
        servers.push((n.node_id(), client));
    }

    // Pick the leader's gRPC client to drive Attest, and a follower's gRPC
    // client to verify FetchSVID sees the replicated record.
    let (leader_idx, follower_idx) = {
        let l = servers.iter().position(|(id, _)| *id == leader_id).unwrap();
        let f = servers.iter().position(|(id, _)| *id != leader_id).unwrap();
        (l, f)
    };
    let mut leader_client = servers[leader_idx].1.clone();
    let mut follower_client = servers[follower_idx].1.clone();

    // Drive a full four-phase attestation through the leader.
    let mut evidence = SoftwareEvidence {
        // Use the trust roots that all three nodes were configured with.
        aik: evidence_template.aik.clone(),
        aik_pub: evidence_template.aik_pub.clone(),
        ek_cert: evidence_template.ek_cert.clone(),
        ek_root: evidence_template.ek_root.clone(),
    };
    let attested = run_attest(&mut leader_client, &mut evidence, "dpop-thumb".to_string())
        .await
        .expect("clustered attestation succeeds");

    // FetchSVID on the follower must see the same bundle (consistent read).
    let bundle = follower_client
        .fetch_svid(FetchRequest {
            spiffe_id: attested.bundle.spiffe_id.clone(),
        })
        .await
        .expect("follower returns replicated SVID")
        .into_inner();

    assert_eq!(bundle.spiffe_id, attested.bundle.spiffe_id);
    assert_eq!(bundle.jws, attested.bundle.jws);
    assert_eq!(bundle.issued_at, attested.bundle.issued_at);

    // Health probes report the expected roles.
    let leader_health = leader_client
        .health(HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(leader_health.healthy);
    assert_eq!(leader_health.role, ProtoNodeRole::Leader as i32);

    let follower_health = follower_client
        .health(HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(follower_health.healthy);
    // Follower may report Follower or, very briefly, Unknown during transitions.
    assert!(
        follower_health.role == ProtoNodeRole::Follower as i32
            || follower_health.role == ProtoNodeRole::Unknown as i32
    );

    // Shut down all three nodes. Drop the servers' Arc<Cluster> handles first
    // by dropping the clients; hiqlite's shutdown is per-Arc.
    drop(servers);
    for n in nodes {
        if let Ok(c) = Arc::try_unwrap(n) {
            let _ = c.shutdown().await;
        }
    }
    std::fs::remove_dir_all(root).ok();
}
