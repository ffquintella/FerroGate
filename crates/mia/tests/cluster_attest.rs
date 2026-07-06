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
use ferro_attest::{PolicyId, RimStore, TpmQuoteVerifier, Vendor, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{FetchRequest, HealthRequest, NodeRole as ProtoNodeRole};
use ferro_raft::{Cluster, ClusterConfig, PeerNode};
use ferro_svid::Issuer;
use mia::client::run_attest;
use mia::virtual_tpm::{expected_pcr_digest, software_credential_blob, VirtualTpm};

use tokio::time::sleep;

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
    evidence: &VirtualTpm,
    kid: &str,
) -> Arc<CmisState> {
    let mut trust = VendorTrustStore::new();
    trust
        .add_root_der(evidence.ek_root_der(), Vendor::Infineon)
        .unwrap();
    let pcr_digest = expected_pcr_digest();
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
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();

    Arc::new(CmisState::new(
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
    let evidence_template = VirtualTpm::ephemeral().unwrap(); // shared EK chain + AIK
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
    let mut evidence = evidence_template.clone();
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
