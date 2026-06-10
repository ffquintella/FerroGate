//! `cmis` — Central Machine Identity Service binary.
//!
//! A thin wrapper: assemble [`cmis::CmisState`] and serve the
//! [`cmis::MachineIdentitySvc`] gRPC surface. The listener terminates
//! hybrid-PQC TLS (F01, `X25519MLKEM768`-only) when `CMIS_TLS_CERT` +
//! `CMIS_TLS_KEY` are configured, falling back to a plaintext bring-up server
//! for local development otherwise. A TEE-resident issuance key (F06) and a
//! configured phase-3 credential maker are layered on in later milestones;
//! until then `JWKS` is fully functional and `Attest` will report the
//! credential service as unavailable.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::fleet_manifest::FleetManifestLoader;
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimLoader, RimStore, TpmQuoteVerifier, TrustedKeys, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore, SthSigner};
use ferro_crypto::composite::CompositePublicKey;
use ferro_crypto::tls::ProviderMode;
use ferro_raft::{Cluster, ClusterConfig, PeerNode};
use ferro_svid::Issuer;
use tracing_subscriber::EnvFilter;

/// Placeholder phase-3 maker for the unconfigured bring-up server. A real
/// deployment injects a TCG `MakeCredential` implementation; this one refuses
/// so no half-configured node can appear to attest hosts.
struct UnconfiguredCredentialMaker;

impl CredentialMaker for UnconfiguredCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap(
            "credential maker not configured on this node".to_string(),
        ))
    }
}

/// Build a single-publisher composite trust set from a pair of environment
/// variables: `<kid_var>` selects the key id artefacts are signed under and
/// `<pub_var>` carries that publisher's composite public key as lowercase hex
/// of its `ed25519(32) || ml-dsa-65(1952)` concat form. Used for both the F13
/// fleet manifest and the F10 RIM bundle; production sources these from the
/// F14 ceremony's published root key.
fn load_single_key_trust(kid_var: &str, pub_var: &str) -> anyhow::Result<TrustedKeys> {
    let kid = std::env::var(kid_var).map_err(|_| anyhow::anyhow!("{kid_var} missing"))?;
    let pub_hex = std::env::var(pub_var).map_err(|_| anyhow::anyhow!("{pub_var} missing"))?;
    let pub_bytes =
        hex::decode(pub_hex.trim()).map_err(|e| anyhow::anyhow!("{pub_var} hex: {e}"))?;
    let pk = CompositePublicKey::from_concat_bytes(&pub_bytes)
        .map_err(|e| anyhow::anyhow!("{pub_var}: {e}"))?;
    let mut trust = TrustedKeys::new();
    trust.add(kid, pk);
    Ok(trust)
}

/// Load the issuer's composite signing key from persistent storage, generating
/// and persisting a fresh one on first run.
///
/// The issuer key signs every SVID, the CRL, and host allowlists. If it were
/// regenerated on each boot (as the bring-up path did), a restart would rotate
/// the JWKS key out from under every consumer: previously-minted SVIDs, the
/// allowlist a MIA already adopted, and the published CRL would all fail
/// signature verification, and the MIA would deny callers (`crl-stale` /
/// invalid signature). To keep the issuer's identity stable across restarts we
/// persist a 32-byte master seed (not the expanded private key) and rebuild the
/// keypair deterministically with [`Issuer::from_seed`].
///
/// Path: `CMIS_ISSUER_KEY` (default `<CMIS_RAFT_DIR-sibling>/issuer/issuer.seed`,
/// i.e. `/var/lib/ferrogate/issuer/issuer.seed`). The file is created `0600`.
/// `CMIS_ISSUER_KID` / `CMIS_TRUST_DOMAIN` override the defaults but must stay
/// constant for a given seed, since the `kid` is how consumers resolve the key.
fn load_or_create_issuer() -> anyhow::Result<Issuer> {
    use rand_core::{OsRng, RngCore};

    let kid = std::env::var("CMIS_ISSUER_KID").unwrap_or_else(|_| "cmis-dev-1".to_string());
    let trust_domain =
        std::env::var("CMIS_TRUST_DOMAIN").unwrap_or_else(|_| "ferrogate.dev".to_string());
    let path = PathBuf::from(
        std::env::var("CMIS_ISSUER_KEY")
            .unwrap_or_else(|_| "/var/lib/ferrogate/issuer/issuer.seed".to_string()),
    );

    if path.exists() {
        let bytes = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("reading issuer seed {}: {e}", path.display()))?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "issuer seed {} is {} bytes, expected 32",
                path.display(),
                bytes.len()
            )
        })?;
        tracing::info!(kid = %kid, path = %path.display(), "loaded persisted issuer key");
        return Ok(Issuer::from_seed(&seed, kid, trust_domain));
    }

    // First run: mint a fresh seed and persist it before use so a crash between
    // here and serving doesn't leave us with an in-memory-only key.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("creating issuer key dir {}: {e}", parent.display()))?;
    }
    write_secret_file(&path, &seed)
        .map_err(|e| anyhow::anyhow!("writing issuer seed {}: {e}", path.display()))?;
    tracing::warn!(
        kid = %kid,
        path = %path.display(),
        "no persisted issuer key found — generated a new one and stored it"
    );
    Ok(Issuer::from_seed(&seed, kid, trust_domain))
}

/// Write `data` to `path`, creating it `0600` (owner read/write only) so the
/// issuer seed is never group/world-readable.
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Assemble the Raft cluster every durable CMIS store lives in (issued SVIDs,
/// host allowlists, pending allowlist proposals — all in SQLite under
/// `CMIS_RAFT_DIR`, so they survive restarts).
///
/// With no `CMIS_CLUSTER_PEERS` configured this is a **single-node** cluster:
/// the node is its own only peer, elects itself leader, and never looks for
/// other nodes. Multi-node deployments list every peer (including this one) in
/// `CMIS_CLUSTER_PEERS` as `id=raft_addr,api_addr` entries separated by `;`,
/// pick which entry is "this node" with `CMIS_NODE_ID`, and must share real
/// `CMIS_RAFT_SECRET` / `CMIS_API_SECRET` values across the fleet.
async fn start_cluster() -> anyhow::Result<Arc<Cluster>> {
    let data_dir =
        std::env::var("CMIS_RAFT_DIR").unwrap_or_else(|_| "/var/lib/ferrogate/raft".to_string());

    let peers = match std::env::var("CMIS_CLUSTER_PEERS") {
        Ok(spec) if !spec.trim().is_empty() => parse_peers(&spec)?,
        _ => Vec::new(),
    };

    let mut cfg = if peers.is_empty() {
        let addr_raft =
            std::env::var("CMIS_RAFT_ADDR").unwrap_or_else(|_| "127.0.0.1:9601".to_string());
        let addr_api =
            std::env::var("CMIS_API_ADDR").unwrap_or_else(|_| "127.0.0.1:9602".to_string());
        tracing::info!(
            %data_dir, %addr_raft, %addr_api,
            "no CMIS_CLUSTER_PEERS configured — single-node cluster (no peer discovery)"
        );
        ClusterConfig::single_node(data_dir, addr_raft, addr_api)
    } else {
        let node_id: u64 = std::env::var("CMIS_NODE_ID")
            .map_err(|_| anyhow::anyhow!("CMIS_CLUSTER_PEERS is set but CMIS_NODE_ID is missing"))?
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("CMIS_NODE_ID: {e}"))?;
        if !peers.iter().any(|p| p.id == node_id) {
            return Err(anyhow::anyhow!(
                "CMIS_NODE_ID {node_id} is not listed in CMIS_CLUSTER_PEERS"
            ));
        }
        tracing::info!(node_id, peers = peers.len(), %data_dir, "joining CMIS cluster");
        ClusterConfig::for_node(node_id, peers, data_dir)
    };

    match (
        std::env::var("CMIS_RAFT_SECRET"),
        std::env::var("CMIS_API_SECRET"),
    ) {
        (Ok(raft), Ok(api)) => {
            cfg.secret_raft = raft;
            cfg.secret_api = api;
        }
        _ if cfg.is_single_node() => {
            // Loopback-only transports on a single node; the built-in dev
            // secrets are acceptable because nothing remote shares them.
        }
        _ => {
            return Err(anyhow::anyhow!(
                "multi-node cluster requires CMIS_RAFT_SECRET and CMIS_API_SECRET"
            ));
        }
    }

    let cluster = Cluster::start(cfg)
        .await
        .map_err(|e| anyhow::anyhow!("cluster start: {e}"))?;
    Ok(Arc::new(cluster))
}

/// Parse `CMIS_CLUSTER_PEERS`: `;`-separated `id=raft_addr,api_addr` entries,
/// e.g. `1=10.0.0.1:9601,10.0.0.1:9602;2=10.0.0.2:9601,10.0.0.2:9602`.
fn parse_peers(spec: &str) -> anyhow::Result<Vec<PeerNode>> {
    let mut peers = Vec::new();
    for entry in spec.split(';').filter(|s| !s.trim().is_empty()) {
        let (id, addrs) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("CMIS_CLUSTER_PEERS entry {entry:?}: missing '='"))?;
        let (addr_raft, addr_api) = addrs.split_once(',').ok_or_else(|| {
            anyhow::anyhow!("CMIS_CLUSTER_PEERS entry {entry:?}: expected raft_addr,api_addr")
        })?;
        peers.push(PeerNode {
            id: id
                .trim()
                .parse()
                .map_err(|e| anyhow::anyhow!("CMIS_CLUSTER_PEERS entry {entry:?}: id: {e}"))?,
            addr_raft: addr_raft.trim().to_string(),
            addr_api: addr_api.trim().to_string(),
        });
    }
    if peers.is_empty() {
        return Err(anyhow::anyhow!("CMIS_CLUSTER_PEERS is set but empty"));
    }
    Ok(peers)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let addr = std::env::var("CMIS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8443".to_string())
        .parse()?;

    let issuer = load_or_create_issuer()?;
    // The verifier and the RIM loader share one `RimStore` handle so a signed
    // bundle applied by the loader is immediately visible to quote verification.
    let rim_store = RimStore::new();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), rim_store.clone());

    // M3 audit log: local-disk WORM store + in-process composite signer. The
    // production swap to a TEE threshold signer lands with the hardware TEE
    // driver work. `LocalDiskWormStore` is the shipped WORM tier; a native S3
    // Object Lock store is dropped (see docs/roadmap.md "Dropped scope").
    let worm_root =
        std::env::var("CMIS_AUDIT_ROOT").unwrap_or_else(|_| "/var/lib/ferrogate/audit".to_string());
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(worm_root)?);
    let (signer, _audit_pk) = InProcessSigner::generate("cmis-dev-audit-1")
        .map_err(|e| anyhow::anyhow!("audit signer: {e}"))?;
    tracing::info!(audit_kid = signer.kid(), "audit signer ready");
    // Resumes the Merkle tree from the leaves already in the WORM store, so a
    // restart keeps appending at the right index instead of wedging on leaf 0.
    let audit = AuditLog::new(store, Arc::new(signer))
        .map_err(|e| anyhow::anyhow!("audit log resume: {e}"))?;

    // Host-driven allowlist proposal policy (see docs/mia.md). Default is
    // bootstrap-only TOFU: auto-adopt a host's first proposal when it has no
    // allowlist yet, queue every later change for operator review.
    let mut cmis_config = CmisConfig::default();
    if let Ok(v) = std::env::var("CMIS_ALLOWLIST_PROPOSALS") {
        cmis_config.allowlist_proposal_policy =
            cmis::state::ProposalPolicy::from_env_value(&v);
    }
    tracing::info!(
        proposal_policy = ?cmis_config.allowlist_proposal_policy,
        "allowlist proposal policy"
    );

    // All durable CMIS state (issued SVIDs, allowlists, proposals) lives in
    // the Raft-replicated SQLite store — a one-node Raft when no peers are
    // configured — so it survives restarts.
    let cluster = start_cluster().await?;

    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnconfiguredCredentialMaker),
        cmis_config,
        audit,
        cluster,
    ));

    // F13 zero-touch enrolment. If a signed fleet manifest is configured, load
    // it now (fail-closed: a configured-but-unloadable manifest aborts startup
    // rather than admitting every host) and spawn a watcher to hot-reload it.
    // With no manifest configured CMIS stays unenforced — every host that can
    // attest is admitted, exactly as before F13.
    let _fleet_watcher = match std::env::var("CMIS_FLEET_MANIFEST") {
        Ok(path) if !path.is_empty() => {
            let trust = load_single_key_trust("CMIS_FLEET_SIGNER_KID", "CMIS_FLEET_SIGNER_PUB")?;
            let loader = Arc::new(FleetManifestLoader::new(path, trust, state.fleet().clone()));
            match loader.try_reload() {
                Ok(outcome) => tracing::info!(?outcome, "fleet manifest loaded"),
                Err(e) => return Err(anyhow::anyhow!("fleet manifest load failed: {e}")),
            }
            Some(cmis::fleet_watcher::spawn(
                loader,
                cmis::fleet_watcher::DEFAULT_REFRESH_INTERVAL,
            ))
        }
        _ => {
            tracing::warn!("no CMIS_FLEET_MANIFEST configured — fleet enrolment unenforced");
            None
        }
    };

    // F10 RIM refresh. If a signed RIM bundle file is configured, load it now
    // (fail-closed: a configured-but-unloadable bundle aborts startup) and spawn
    // a watcher that hot-swaps a strictly-newer signed bundle into the shared
    // store. With nothing configured the RIM allowlist stays empty and every
    // quote fails the RIM lookup (FAILED_PRECONDITION) — fail-closed by default.
    //
    // The bundle is read from a local file. Native S3 sourcing is dropped (see
    // docs/roadmap.md "Dropped scope"); a deployment that stores the bundle in
    // object storage syncs it to this path out of band. Because the bundle is
    // composite-signed and verified before apply, that sync path is untrusted —
    // only the signature gates what is admitted.
    let _rim_watcher = match std::env::var("CMIS_RIM_BUNDLE") {
        Ok(path) if !path.is_empty() => {
            let trust = load_single_key_trust("CMIS_RIM_SIGNER_KID", "CMIS_RIM_SIGNER_PUB")?;
            let loader = Arc::new(RimLoader::new(path, trust, rim_store.clone()));
            match loader.try_reload() {
                Ok(outcome) => tracing::info!(?outcome, "RIM bundle loaded"),
                Err(e) => return Err(anyhow::anyhow!("RIM bundle load failed: {e}")),
            }
            // 60 s steady-state poll, matching the fleet-manifest watcher.
            Some(cmis::rim_watcher::spawn(loader, Duration::from_secs(60)))
        }
        _ => {
            tracing::warn!("no CMIS_RIM_BUNDLE configured — RIM allowlist empty (all quotes fail)");
            None
        }
    };

    // Keep the published CRL fresh (feature F11). Revocations publish inline on
    // the admin RPC; this heartbeat republishes every 60 s so consumers' 5-min
    // freshness check keeps passing in steady state.
    let _crl_publisher = cmis::crl_publisher::spawn(
        Arc::clone(&state),
        cmis::crl_publisher::DEFAULT_PUBLISH_INTERVAL,
    );

    serve_grpc(addr, state).await
}

/// Serve the `MachineIdentity` gRPC surface on `addr`.
///
/// F01 transport: with `CMIS_TLS_CERT` + `CMIS_TLS_KEY` configured the
/// listener terminates hybrid-PQC TLS (`X25519MLKEM768`-only) via the shared
/// `ferro-crypto` provider, so a legacy / non-PQC client fails the handshake
/// and never reaches the gRPC layer. With neither set, the plaintext bring-up
/// server is kept for local development (loud warning). Setting only one of
/// the pair is a configuration error and aborts startup.
async fn serve_grpc(addr: std::net::SocketAddr, state: Arc<CmisState>) -> anyhow::Result<()> {
    let svc = MachineIdentitySvc::new(state).into_server();
    let tls = match (
        std::env::var_os("CMIS_TLS_CERT"),
        std::env::var_os("CMIS_TLS_KEY"),
    ) {
        (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
        (None, None) => None,
        _ => {
            return Err(anyhow::anyhow!(
                "CMIS_TLS_CERT and CMIS_TLS_KEY must be set together"
            ))
        }
    };

    if let Some((cert_path, key_path)) = tls {
        let (cert_chain, key) = cmis::transport::load_pem_identity(&cert_path, &key_path)?;
        let server_config =
            ferro_crypto::transport::server_config(ProviderMode::HybridOnly, cert_chain, key)?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            %addr,
            "FerroGate CMIS — hybrid-PQC TLS gRPC server (X25519MLKEM768-only)"
        );
        let incoming = cmis::transport::tls_incoming(listener, server_config);
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await?;
    } else {
        tracing::warn!(
            version = env!("CARGO_PKG_VERSION"),
            %addr,
            "FerroGate CMIS — PLAINTEXT gRPC bring-up server (set CMIS_TLS_CERT + \
             CMIS_TLS_KEY for hybrid-PQC TLS)"
        );
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve(addr)
            .await?;
    }
    Ok(())
}
