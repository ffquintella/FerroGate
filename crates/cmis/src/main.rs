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
use ferro_raft::{Cluster, ClusterConfig, PeerNode, PeerTls};
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

/// Load the issuer's composite signing key, sourcing its 32-byte master seed
/// from the **Raft-replicated cluster** so every node behind the deployment's
/// SRV name signs under one identity.
///
/// The issuer key signs every SVID, the CRL, and host allowlists. Two hazards
/// shape this:
///
/// 1. *Restart stability.* If the key were regenerated on each boot, a restart
///    would rotate the JWKS key out from under every consumer: previously-minted
///    SVIDs, the allowlist a MIA already adopted, and the published CRL would
///    all fail signature verification and the MIA would deny callers
///    (`crl-stale` / invalid signature). So the seed is persisted, not minted
///    per boot, and the keypair is rebuilt deterministically with
///    [`Issuer::from_seed`].
/// 2. *Cluster identity.* The seed previously lived in a per-node local file.
///    On an HA cluster that file is **not** replicated, so each node minted its
///    own seed and a client load-balanced across the SRV name would fetch an
///    allowlist signed by one node yet verify it against another node's
///    enrollment key — a spurious `bad signature`. Storing the seed in the
///    replicated store fixes this at the root: there is one seed, cluster-wide.
///
/// First-boot establishment is **leader-wins** (see [`resolve_cluster_seed`]):
/// the leader promotes its on-disk seed (preserving a pre-replication identity)
/// or a fresh one, and followers adopt it.
///
/// `CMIS_ISSUER_KEY` (default `/var/lib/ferrogate/issuer/issuer.seed`) is now
/// only a migration source and a `0600` disaster-recovery mirror of the
/// canonical seed — never the source of truth on an established cluster.
/// `CMIS_ISSUER_KID` / `CMIS_TRUST_DOMAIN` override the defaults but must stay
/// constant for a given seed, since the `kid` is how consumers resolve the key.
async fn load_or_create_issuer(cluster: &Cluster) -> anyhow::Result<Issuer> {
    let kid = std::env::var("CMIS_ISSUER_KID").unwrap_or_else(|_| "cmis-dev-1".to_string());
    let trust_domain =
        std::env::var("CMIS_TRUST_DOMAIN").unwrap_or_else(|_| "ferrogate.dev".to_string());
    let path = PathBuf::from(
        std::env::var("CMIS_ISSUER_KEY")
            .unwrap_or_else(|_| "/var/lib/ferrogate/issuer/issuer.seed".to_string()),
    );

    let seed = resolve_cluster_seed(cluster, &path).await?;

    // Mirror the canonical seed to disk for disaster recovery and as the
    // migration source on a future bootstrap. It is identical on every node (it
    // is the one cluster seed), so the mirror can never reintroduce divergence;
    // it also *heals* a node whose stale on-disk seed differed. Best-effort: a
    // read-only or full filesystem must not take the issuer down.
    if let Err(e) = mirror_seed_file(&path, &seed) {
        tracing::warn!(
            path = %path.display(), error = %e,
            "could not mirror issuer seed to disk (continuing — the cluster copy is authoritative)"
        );
    }
    tracing::info!(kid = %kid, "issuer key ready (seed sourced from the cluster)");
    Ok(Issuer::from_seed(&seed, kid, trust_domain))
}

/// Resolve the cluster's canonical 32-byte issuer seed, establishing it on the
/// first boot of a fresh cluster.
///
/// **Leader-wins.** Only the Raft leader promotes a seed into the replicated
/// store — its existing on-disk seed if present (so an existing single-node /
/// leader identity is preserved and already-enrolled hosts keep working), else
/// a freshly minted one. Followers wait for the leader's seed to appear and
/// adopt it. A bounded fallback ([`FOLLOWER_SEED_WAIT`]) keeps a follower from
/// wedging forever if no leader ever publishes (e.g. a botched rolling
/// upgrade): past the deadline it offers its own candidate through the same
/// compare-and-set, so the cluster still converges on exactly one seed.
async fn resolve_cluster_seed(
    cluster: &Cluster,
    path: &std::path::Path,
) -> anyhow::Result<[u8; 32]> {
    use rand_core::{OsRng, RngCore};

    let started = tokio::time::Instant::now();
    loop {
        if let Some(bytes) = cluster.fetch_issuer_seed().await? {
            return parse_seed(&bytes, "cluster issuer_seed");
        }

        let past_deadline = started.elapsed() >= FOLLOWER_SEED_WAIT;
        if cluster.is_leader().await || past_deadline {
            let candidate = if let Some(seed) = read_seed_file(path)? {
                tracing::info!(
                    path = %path.display(),
                    "promoting on-disk issuer seed into the replicated cluster store"
                );
                seed
            } else {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                tracing::warn!("no issuer seed on disk or in the cluster — minting a fresh one");
                seed
            };
            if cluster.try_store_issuer_seed(&candidate, now_unix()).await? {
                if past_deadline && !cluster.is_leader().await {
                    tracing::warn!(
                        wait = ?FOLLOWER_SEED_WAIT,
                        "no leader published an issuer seed in time — this follower established it"
                    );
                }
                return Ok(candidate);
            }
            // Lost the compare-and-set: another node established the seed first.
            // Loop to read and adopt the winning value.
            tracing::info!("another node established the issuer seed first — adopting it");
            continue;
        }

        // Follower still within the wait window: give the leader time to publish.
        tokio::time::sleep(SEED_POLL_INTERVAL).await;
    }
}

/// How long a non-leader waits for the leader to publish the issuer seed before
/// it falls back to establishing one itself (liveness backstop only — the
/// leader normally wins this comfortably).
const FOLLOWER_SEED_WAIT: Duration = Duration::from_secs(20);
/// Poll cadence while a follower waits for the seed to appear.
const SEED_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Read a 32-byte seed from `path` if present. A missing file is `Ok(None)`;
/// a present-but-malformed file (wrong length / unreadable) is an error so a
/// corrupt mirror is surfaced rather than silently regenerating an identity.
fn read_seed_file(path: &std::path::Path) -> anyhow::Result<Option<[u8; 32]>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading issuer seed {}: {e}", path.display()))?;
    Ok(Some(parse_seed(&bytes, &path.display().to_string())?))
}

/// Interpret raw bytes as a 32-byte Ed25519/composite master seed.
fn parse_seed(bytes: &[u8], src: &str) -> anyhow::Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| anyhow::anyhow!("issuer seed from {src} is {} bytes, expected 32", bytes.len()))
}

/// Write the canonical seed to `path` as `0600`, creating parent dirs. Writes
/// to a temp sibling and renames so a concurrent reader never sees a short
/// file, and overwrites an existing file so a node whose mirror had diverged is
/// healed. A no-op when the on-disk bytes already match.
fn mirror_seed_file(path: &std::path::Path, seed: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if std::fs::read(path).is_ok_and(|existing| existing == seed) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("seed.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(seed)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Current Unix time in whole seconds (saturating at 0 before the epoch).
fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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
        // Multi-node peers live on other hosts/containers, so the inter-node
        // transports must bind a routable interface — the `127.0.0.1` default
        // would make this node unreachable to its peers. `CMIS_RAFT_LISTEN`
        // overrides the bind interface; `0.0.0.0` (all interfaces) is the
        // container-friendly default. The *advertised* address each peer dials
        // is still its `CMIS_CLUSTER_PEERS` entry.
        let listen = std::env::var("CMIS_RAFT_LISTEN").unwrap_or_else(|_| "0.0.0.0".to_string());
        tracing::info!(
            node_id, peers = peers.len(), %data_dir, %listen,
            "joining CMIS cluster"
        );
        ClusterConfig::for_node(node_id, peers, data_dir).with_listen_interface(listen)
    };

    // Inter-node TLS. Without it the Raft + management transports are cleartext
    // and the cluster must be pinned to a trusted private network (the historic
    // F05 limitation). `CMIS_PEER_TLS=1` turns on rustls for the peer transport
    // with a shared certificate each node derives deterministically from the
    // cluster secret (the shared secret authenticates the peers, and the derived
    // cert is what lets hiqlite's split-brain check verify them — see
    // `ferro_raft::peer_cert`); supplying `CMIS_PEER_TLS_CERT` +
    // `CMIS_PEER_TLS_KEY` uses an operator-provided PEM pair instead. Single-node
    // loopback stays cleartext.
    if !cfg.is_single_node() {
        cfg.peer_tls = resolve_peer_tls()?;
    }

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

/// Resolve the inter-node TLS mode from the environment.
///
/// - `CMIS_PEER_TLS_CERT` + `CMIS_PEER_TLS_KEY` set → operator PEM pair.
/// - else `CMIS_PEER_TLS` truthy (`1`/`true`/`yes`/`on`) → self-signed.
/// - else `None` (cleartext; cluster must sit on a trusted private network).
fn resolve_peer_tls() -> anyhow::Result<Option<PeerTls>> {
    let cert = std::env::var("CMIS_PEER_TLS_CERT").ok().filter(|s| !s.is_empty());
    let key = std::env::var("CMIS_PEER_TLS_KEY").ok().filter(|s| !s.is_empty());
    match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            tracing::info!(%cert_path, "inter-node TLS: operator-supplied certificate");
            return Ok(Some(PeerTls::Certs {
                cert_path,
                key_path,
            }));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(anyhow::anyhow!(
                "CMIS_PEER_TLS_CERT and CMIS_PEER_TLS_KEY must be set together"
            ));
        }
        (None, None) => {}
    }
    let enabled = std::env::var("CMIS_PEER_TLS")
        .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"));
    if enabled {
        tracing::info!("inter-node TLS: shared cert derived from secret (secret-authenticated)");
        Ok(Some(PeerTls::SelfSigned))
    } else {
        tracing::warn!(
            "inter-node transport is cleartext (CMIS_PEER_TLS unset) — pin the cluster to a \
             trusted private network or set CMIS_PEER_TLS=1"
        );
        Ok(None)
    }
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

/// Read a TTL (seconds) from `var`, clamped to `[min, max]`. Returns `None`
/// when the variable is unset (caller keeps its default) or holds a
/// non-integer (logged, default kept), so a fat-finger can't shorten a TTL.
fn ttl_from_env(var: &str, min: u64, max: u64) -> Option<u64> {
    let raw = std::env::var(var).ok()?;
    let Ok(n) = raw.parse::<u64>() else {
        tracing::warn!(var, value = %raw, "TTL env var is not an integer; keeping default");
        return None;
    };
    Some(n.clamp(min, max))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let addr = std::env::var("CMIS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8443".to_string())
        .parse()?;

    // All durable CMIS state (issued SVIDs, allowlists, proposals, and the
    // issuer's master signing seed) lives in the Raft-replicated SQLite store —
    // a one-node Raft when no peers are configured — so it survives restarts and
    // is identical on every node. Start it before loading the issuer: the seed
    // is sourced from (and, on first boot, promoted into) the cluster, so the
    // whole HA cluster signs under one identity behind its SRV name.
    let cluster = start_cluster().await?;
    let issuer = load_or_create_issuer(&cluster).await?;
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

    // Signature lifetimes. Both floor at 96 h (`ferro_svid::MIN_TTL_SECS`) and
    // cap at the issuer's hard ceiling (30 days) so a misconfigured value can
    // mint neither a near-expired nor an unbounded artefact.
    if let Some(n) = ttl_from_env(
        "CMIS_SVID_TTL_SECS",
        ferro_svid::MIN_TTL_SECS,
        ferro_svid::MAX_TTL_SECS,
    ) {
        cmis_config.svid_ttl_secs = n;
    }
    if let Some(n) = ttl_from_env(
        "CMIS_ALLOWLIST_TTL_SECS",
        ferro_svid::MIN_TTL_SECS,
        30 * 24 * 3600,
    ) {
        cmis_config.allowlist_ttl_secs = i64::try_from(n).unwrap_or(96 * 3600);
    }
    tracing::info!(
        svid_ttl_secs = cmis_config.svid_ttl_secs,
        allowlist_ttl_secs = cmis_config.allowlist_ttl_secs,
        "signature lifetimes"
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_seed_requires_exactly_32_bytes() {
        assert!(parse_seed(&[0u8; 32], "x").is_ok());
        assert!(parse_seed(&[0u8; 31], "x").is_err());
        assert!(parse_seed(&[0u8; 33], "x").is_err());
        assert!(parse_seed(&[], "x").is_err());
    }

    #[test]
    fn read_seed_file_is_none_when_absent_and_round_trips_when_present() {
        let dir = std::env::temp_dir().join(format!("ferrogate-seedfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("issuer/issuer.seed");

        assert!(read_seed_file(&path).unwrap().is_none());

        let seed = [0x7eu8; 32];
        mirror_seed_file(&path, &seed).unwrap();
        assert_eq!(read_seed_file(&path).unwrap(), Some(seed));

        // Mode is 0600 — the seed is never group/world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mirror must be 0600, got {mode:o}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirror_heals_a_diverged_on_disk_seed() {
        let dir = std::env::temp_dir().join(format!("ferrogate-seedheal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("issuer.seed");

        mirror_seed_file(&path, &[0x01u8; 32]).unwrap();
        // A later canonical seed overwrites the stale one in place.
        mirror_seed_file(&path, &[0x02u8; 32]).unwrap();
        assert_eq!(read_seed_file(&path).unwrap(), Some([0x02u8; 32]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On a fresh single-node cluster (always leader) with an existing on-disk
    /// seed, `resolve_cluster_seed` adopts that seed — preserving a
    /// pre-replication identity so already-enrolled hosts keep working — and
    /// promotes it into the cluster so subsequent reads return it.
    #[tokio::test]
    async fn resolve_adopts_existing_on_disk_seed() {
        let dir = std::env::temp_dir().join(format!("ferrogate-adopt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("issuer/issuer.seed");
        let existing = [0x42u8; 32];
        mirror_seed_file(&path, &existing).unwrap();

        let raft_dir = dir.join("raft");
        let cluster = Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap();

        let resolved = resolve_cluster_seed(&cluster, &path).await.unwrap();
        assert_eq!(resolved, existing, "must adopt the on-disk seed");
        // It is now the cluster's canonical seed.
        assert_eq!(
            cluster.fetch_issuer_seed().await.unwrap().as_deref(),
            Some(&existing[..]),
        );

        cluster.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no seed on disk and none in the cluster, the leader mints a fresh
    /// one and stores it; a second resolve returns the same established seed
    /// (never a second identity).
    #[tokio::test]
    async fn resolve_mints_and_then_reuses_a_fresh_seed() {
        let dir = std::env::temp_dir().join(format!("ferrogate-mint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("issuer/issuer.seed");
        let raft_dir = dir.join("raft");

        let cluster = Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap();

        let first = resolve_cluster_seed(&cluster, &path).await.unwrap();
        let second = resolve_cluster_seed(&cluster, &path).await.unwrap();
        assert_eq!(first, second, "an established seed is stable across resolves");

        cluster.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
