//! The CMIS Raft cluster, wrapping hiqlite.
//!
//! Hiqlite owns the openraft engine, the SQLite state machine, and the peer
//! transport; this module exposes a typed surface so the rest of CMIS does
//! not depend on hiqlite types directly. Concretely:
//!
//! - Schema is created once at startup with idempotent `CREATE TABLE
//!   IF NOT EXISTS` statements; no migration manager (the hiqlite migration
//!   workflow requires `RustEmbed` and is overkill for two tables).
//! - Writes go through the Raft leader; hiqlite's `Client` transparently
//!   forwards from follower nodes, so callers do not need to dispatch.
//! - Reads can be strongly consistent (leader-only) or eventually consistent;
//!   `fetch_svid` uses [`hiqlite::Client::query_map_optional`] which is the
//!   local-read path on followers. CMIS uses the strongly-consistent variant
//!   when a fresh SVID must be returned right after issuance.

use std::borrow::Cow;
use std::time::Duration;

use hiqlite::tls::{ServerTlsConfig, ServerTlsConfigCerts};
use hiqlite::{Client, Node, NodeConfig, Param};
use tokio::time::timeout;

/// TLS for the inter-node Raft + management transports.
///
/// Hiqlite encrypts the peer transport with rustls and authenticates the two
/// ends with a shared-secret three-way handshake (the secret never crosses the
/// wire). Enabling this is what lets a cluster span an untrusted network rather
/// than being pinned to a private one — see `docs/features/F05-cmis-ha.md`.
/// PQC peer TLS specifically remains an upstream-hiqlite concern; this is
/// classical rustls.
#[derive(Debug, Clone)]
pub enum PeerTls {
    /// Zero-config peer TLS: each node derives the *same* CA + leaf certificate
    /// deterministically from the cluster's shared API secret (see
    /// [`crate::peer_cert`]) and advertises the CA via `SSL_CERT_FILE`. No cert
    /// distribution is needed — the secret is already shared.
    ///
    /// Peer *identity* is still authenticated by the shared-secret handshake;
    /// the derived cert exists so that hiqlite's platform-verifying
    /// `split_brain_check` client can actually verify the peers it connects to
    /// (a stock self-signed-per-node cert would be rejected as `UnknownIssuer`,
    /// silently disabling split-brain detection). See
    /// `docs/features/F05-cmis-ha.md`.
    SelfSigned,
    /// Operator-supplied PEM certificate + private key, the same pair on every
    /// node. Use when you want a stable certificate across restarts (e.g. for
    /// external pinning) rather than the per-process ephemeral one `SelfSigned`
    /// mints. As with `SelfSigned`, peer *identity* is authenticated by the
    /// shared secret, not the certificate, so the cert is not chain-validated.
    Certs {
        /// Path to the PEM certificate (chain).
        cert_path: String,
        /// Path to the PEM private key.
        key_path: String,
    },
}

/// Serialize concurrent `SSL_CERT_FILE` mutation. Real deployments run one node
/// per process, but the in-process e2e tests start several nodes at once, and
/// `std::env::set_var` is process-global.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Append `anchor_pem` to a trust bundle under `data_dir` and point
/// `SSL_CERT_FILE` at it, so this process's platform-verifying TLS clients
/// (notably hiqlite's `split_brain_check`) accept the peer cert. Existing roots
/// — an operator-set `SSL_CERT_FILE`, else the common system bundle — are
/// preserved so ordinary outbound TLS in the process still works.
fn install_trust_anchor(data_dir: &str, anchor_pem: &str) -> Result<(), ClusterError> {
    let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let dir = std::path::Path::new(data_dir).join("peer-tls");
    std::fs::create_dir_all(&dir)?;
    let bundle_path = dir.join("trust-bundle.pem");

    let mut bundle = anchor_pem.to_string();
    if !bundle.ends_with('\n') {
        bundle.push('\n');
    }
    let preserved = std::env::var("SSL_CERT_FILE")
        .ok()
        .filter(|p| std::path::Path::new(p) != bundle_path)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| {
            [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/cert.pem",
            ]
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
        });
    if let Some(extra) = preserved {
        bundle.push_str(&extra);
    }

    std::fs::write(&bundle_path, bundle)?;
    std::env::set_var("SSL_CERT_FILE", &bundle_path);
    Ok(())
}

impl ClusterConfig {
    /// Materialize this node's inter-node TLS into a hiqlite [`ServerTlsConfig`],
    /// performing any on-disk/`SSL_CERT_FILE` side effects the mode needs.
    ///
    /// `SelfSigned` derives the shared cert from [`Self::secret_api`], writes the
    /// chain + key under `data_dir`, and installs the CA as a trust anchor.
    /// `Certs` uses the operator pair as-is and also installs it as a trust
    /// anchor (so the split-brain client trusts it even when it is self-signed).
    /// Both keep `danger_tls_no_verify` set: peer identity is the shared
    /// secret's job, and that flag governs hiqlite's *own* peer clients.
    fn materialize_peer_tls(&self) -> Result<Option<ServerTlsConfig>, ClusterError> {
        let Some(peer_tls) = self.peer_tls.as_ref() else {
            return Ok(None);
        };
        let specific = match peer_tls {
            PeerTls::Certs {
                cert_path,
                key_path,
            } => {
                if let Ok(pem) = std::fs::read_to_string(cert_path) {
                    install_trust_anchor(&self.data_dir, &pem)?;
                }
                ServerTlsConfigCerts {
                    cert: Cow::Owned(cert_path.clone()),
                    key: Cow::Owned(key_path.clone()),
                    danger_tls_no_verify: true,
                }
            }
            PeerTls::SelfSigned => {
                let sans = crate::peer_cert::sans_from_addrs(
                    self.peers
                        .iter()
                        .flat_map(|p| [p.addr_api.as_str(), p.addr_raft.as_str()]),
                );
                let derived = crate::peer_cert::derive_shared_peer_cert(&self.secret_api, &sans)
                    .map_err(|e| ClusterError::PeerCert(e.to_string()))?;

                let dir = std::path::Path::new(&self.data_dir).join("peer-tls");
                std::fs::create_dir_all(&dir)?;
                let cert_path = dir.join("peer-chain.pem");
                let key_path = dir.join("peer-key.pem");
                std::fs::write(&cert_path, &derived.server_chain_pem)?;
                write_private_key(&key_path, &derived.key_pem)?;
                install_trust_anchor(&self.data_dir, &derived.ca_pem)?;

                ServerTlsConfigCerts {
                    cert: Cow::Owned(cert_path.to_string_lossy().into_owned()),
                    key: Cow::Owned(key_path.to_string_lossy().into_owned()),
                    danger_tls_no_verify: true,
                }
            }
        };
        Ok(Some(ServerTlsConfig::Specific(specific)))
    }
}

/// Write a PEM private key, best-effort `0600` on unix.
fn write_private_key(path: &std::path::Path, pem: &str) -> Result<(), ClusterError> {
    std::fs::write(path, pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// One peer in the cluster — its id and the two addresses hiqlite needs.
#[derive(Debug, Clone)]
pub struct PeerNode {
    /// Node id (1..). Hiqlite requires a node with id `1` to bootstrap.
    pub id: u64,
    /// `host:port` the Raft inter-node transport binds on this peer.
    pub addr_raft: String,
    /// `host:port` the management / forwarding API binds on this peer.
    pub addr_api: String,
}

/// Configuration for one node of the cluster.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Which peer in `peers` is "this node".
    pub node_id: u64,
    /// All peers, including this one. Same list on every node.
    pub peers: Vec<PeerNode>,
    /// On-disk data directory (Raft logs + snapshots).
    pub data_dir: String,
    /// Raft inter-node secret. Must be ≥ 16 chars.
    pub secret_raft: String,
    /// Management API secret. Must be ≥ 16 chars.
    pub secret_api: String,
    /// Listen interface for the Raft port (e.g. `127.0.0.1`).
    pub listen_addr_raft: String,
    /// Listen interface for the API port (e.g. `127.0.0.1`).
    pub listen_addr_api: String,
    /// SQLite filename inside `data_dir`. `hiqlite.db` is the default.
    pub filename_db: String,
    /// TLS for the inter-node transports. `None` leaves the peer transport in
    /// cleartext (fine for loopback single-node and pinned private networks);
    /// `Some(_)` encrypts and secret-authenticates it so the cluster can span
    /// an untrusted network. Must be the same variant on every node.
    pub peer_tls: Option<PeerTls>,
}

impl ClusterConfig {
    /// Build a minimal config for one node. Secrets default to 32-byte
    /// random-looking strings derived from `node_id` — fine for tests, never
    /// for production. Operators must supply real shared secrets.
    #[must_use]
    pub fn for_node(node_id: u64, peers: Vec<PeerNode>, data_dir: impl Into<String>) -> Self {
        Self {
            node_id,
            peers,
            data_dir: data_dir.into(),
            secret_raft: "ferrogate-raft-shared-secret".to_string(),
            secret_api: "ferrogate-api-shared-secret-ok".to_string(),
            listen_addr_raft: "127.0.0.1".to_string(),
            listen_addr_api: "127.0.0.1".to_string(),
            filename_db: "hiqlite.db".to_string(),
            peer_tls: None,
        }
    }

    /// Set the inter-node TLS mode and return `self` (builder-style).
    #[must_use]
    pub fn with_peer_tls(mut self, peer_tls: Option<PeerTls>) -> Self {
        self.peer_tls = peer_tls;
        self
    }

    /// Set the bind interface for both inter-node transports and return `self`.
    /// Multi-node clusters that span hosts/containers must bind a routable
    /// interface (e.g. `0.0.0.0`) rather than the `127.0.0.1` default, or peers
    /// cannot reach this node.
    #[must_use]
    pub fn with_listen_interface(mut self, listen: impl Into<String>) -> Self {
        let listen = listen.into();
        self.listen_addr_raft.clone_from(&listen);
        self.listen_addr_api = listen;
        self
    }

    /// Build a single-node config: node 1 is the only peer, so the Raft
    /// bootstraps alone (it elects itself leader and never looks for other
    /// nodes). Both transports bind loopback addresses — nothing external
    /// talks to them on a single-node deployment.
    #[must_use]
    pub fn single_node(
        data_dir: impl Into<String>,
        addr_raft: impl Into<String>,
        addr_api: impl Into<String>,
    ) -> Self {
        let peer = PeerNode {
            id: 1,
            addr_raft: addr_raft.into(),
            addr_api: addr_api.into(),
        };
        Self::for_node(1, vec![peer], data_dir)
    }

    /// True iff this config describes a single-node cluster.
    #[must_use]
    pub fn is_single_node(&self) -> bool {
        self.peers.len() == 1
    }
}

/// Coarse-grained classification of a node's Raft role at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    /// This node is the current leader.
    Leader,
    /// Voting follower of an elected leader.
    Follower,
    /// Non-voting learner.
    Learner,
    /// Candidate, transitioning, or otherwise not yet in a steady role.
    Unknown,
}

/// Failure modes from the cluster wrapper.
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    /// Hiqlite returned an error.
    #[error("hiqlite: {0}")]
    Hiqlite(#[from] hiqlite::Error),
    /// Cluster never became healthy within the supplied timeout.
    #[error("cluster did not become healthy within {0:?}")]
    HealthTimeout(Duration),
    /// Local socket setup failed (single-node ephemeral port allocation).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Deriving the deterministic shared peer-TLS certificate failed.
    #[error("peer-tls cert derivation: {0}")]
    PeerCert(String),
}

/// One CMIS Raft node, talking to its peers through hiqlite.
pub struct Cluster {
    client: Client,
    node_id: u64,
}

impl Cluster {
    /// Start (or rejoin) the cluster node, initialise the schema, and return
    /// the handle.
    ///
    /// All nodes must call [`Self::start`] roughly concurrently — the first
    /// startup waits for peers to come up before the Raft can elect a leader.
    pub async fn start(cfg: ClusterConfig) -> Result<Self, ClusterError> {
        let node_id = cfg.node_id;
        if cfg.is_single_node() {
            tracing::info!(
                data_dir = %cfg.data_dir,
                "single-node cluster: this node is the only peer and will not look for others"
            );
        }
        let nodes: Vec<Node> = cfg
            .peers
            .iter()
            .map(|p| Node {
                id: p.id,
                addr_raft: p.addr_raft.clone(),
                addr_api: p.addr_api.clone(),
            })
            .collect();

        let peer_tls = cfg.materialize_peer_tls()?;
        if peer_tls.is_some() {
            tracing::info!(node_id, "inter-node transport: rustls (secret-authenticated)");
        }
        let node_config = NodeConfig {
            node_id,
            nodes,
            listen_addr_api: Cow::Owned(cfg.listen_addr_api.clone()),
            listen_addr_raft: Cow::Owned(cfg.listen_addr_raft.clone()),
            data_dir: Cow::Owned(cfg.data_dir.clone()),
            filename_db: Cow::Owned(cfg.filename_db.clone()),
            secret_raft: cfg.secret_raft.clone(),
            secret_api: cfg.secret_api.clone(),
            tls_raft: peer_tls.clone(),
            tls_api: peer_tls,
            health_check_delay_secs: 0,
            ..NodeConfig::default()
        };

        let client = hiqlite::start_node(node_config).await?;

        // Wait for the local node to be healthy before issuing DDL. The
        // leader takes a few hundred milliseconds on a fresh cluster.
        let wait = client.wait_until_healthy_db();
        if timeout(Duration::from_secs(30), wait).await.is_err() {
            return Err(ClusterError::HealthTimeout(Duration::from_secs(30)));
        }

        let cluster = Self { client, node_id };
        cluster.init_schema().await?;
        Ok(cluster)
    }

    /// Start a single-node cluster on kernel-assigned loopback ports.
    ///
    /// Convenience for tests and zero-config single-replica deployments: the
    /// two transports are internal-only on a single node, so the exact ports
    /// do not matter and ephemeral ones avoid collisions between concurrent
    /// processes. Deployments that pin ports use [`ClusterConfig::single_node`]
    /// with [`Self::start`] instead.
    pub async fn start_single_node(data_dir: impl Into<String>) -> Result<Self, ClusterError> {
        // Bind both sockets before reading the ports so the kernel cannot hand
        // the same port out twice; the listeners drop just before hiqlite
        // rebinds them (a small race window, reliable in practice).
        let raft = std::net::TcpListener::bind("127.0.0.1:0")?;
        let api = std::net::TcpListener::bind("127.0.0.1:0")?;
        let cfg = ClusterConfig::single_node(
            data_dir,
            format!("127.0.0.1:{}", raft.local_addr()?.port()),
            format!("127.0.0.1:{}", api.local_addr()?.port()),
        );
        drop((raft, api));
        Self::start(cfg).await
    }

    async fn init_schema(&self) -> Result<(), ClusterError> {
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS issued_svids ( \
                    spiffe_id TEXT PRIMARY KEY, \
                    payload BLOB NOT NULL, \
                    updated_at INTEGER NOT NULL \
                )",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS host_allowlists ( \
                    host_uuid TEXT PRIMARY KEY, \
                    payload BLOB NOT NULL, \
                    updated_at INTEGER NOT NULL \
                )",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS pending_allowlist_proposals ( \
                    host_uuid TEXT PRIMARY KEY, \
                    entries BLOB NOT NULL, \
                    proposer_spiffe_id TEXT NOT NULL, \
                    proposed_at INTEGER NOT NULL \
                )",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS rim_state ( \
                    id INTEGER PRIMARY KEY CHECK (id = 1), \
                    version INTEGER NOT NULL DEFAULT 0 \
                )",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        self.client
            .execute(
                "INSERT OR IGNORE INTO rim_state (id, version) VALUES (1, 0)",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        // The issuer's 32-byte master signing seed, replicated so every node
        // signs SVIDs / CRLs / allowlists under one identity. A single row
        // (`id = 1`); CMIS seeds it once at bootstrap (see `try_store_issuer_seed`)
        // rather than here, because the seed value is CMIS's to choose.
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS issuer_seed ( \
                    id INTEGER PRIMARY KEY CHECK (id = 1), \
                    seed BLOB NOT NULL, \
                    created_at INTEGER NOT NULL \
                )",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        Ok(())
    }

    /// Borrow the underlying hiqlite client (escape hatch for advanced uses).
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The local node's id.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// True if hiqlite reports the local node is healthy enough to serve.
    pub async fn is_healthy(&self) -> bool {
        self.client.is_healthy_db().await.is_ok()
    }

    /// Block until the local node is healthy or `deadline` elapses.
    pub async fn wait_until_healthy(&self, deadline: Duration) -> Result<(), ClusterError> {
        if timeout(deadline, self.client.wait_until_healthy_db())
            .await
            .is_err()
        {
            return Err(ClusterError::HealthTimeout(deadline));
        }
        Ok(())
    }

    /// Classify the local node's current Raft role.
    ///
    /// The mapping is coarse on purpose — distinguishing voting and learner
    /// followers would tie ferro-raft to openraft's `ServerState` enum; the
    /// caller only ever needs "am I the leader" for health gating today.
    pub async fn role(&self) -> NodeRole {
        if !self.is_healthy().await {
            return NodeRole::Unknown;
        }
        if self.client.is_leader_db().await {
            NodeRole::Leader
        } else {
            NodeRole::Follower
        }
    }

    /// The current leader's node id, if the cluster is steady.
    pub async fn leader_id(&self) -> Option<u64> {
        self.client.metrics_db().await.ok()?.current_leader
    }

    /// True iff `metrics.state == Leader` *and* the local node is healthy.
    pub async fn is_leader(&self) -> bool {
        self.client.is_leader_db().await
    }

    /// Insert or replace one issued-SVID record. Payload bytes are opaque to
    /// the cluster — CMIS owns the schema.
    pub async fn upsert_svid(
        &self,
        spiffe_id: &str,
        payload: &[u8],
        now_unix: i64,
    ) -> Result<(), ClusterError> {
        self.client
            .execute(
                "INSERT INTO issued_svids (spiffe_id, payload, updated_at) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (spiffe_id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at",
                vec![
                    Param::from(spiffe_id.to_string()),
                    Param::from(payload.to_vec()),
                    Param::from(now_unix),
                ],
            )
            .await?;
        Ok(())
    }

    /// Fetch one issued-SVID payload by SPIFFE id.
    pub async fn fetch_svid(&self, spiffe_id: &str) -> Result<Option<Vec<u8>>, ClusterError> {
        let row: Option<RawSvidRow> = self
            .client
            .query_map_optional(
                "SELECT spiffe_id, payload, updated_at FROM issued_svids WHERE spiffe_id = $1",
                vec![Param::from(spiffe_id.to_string())],
            )
            .await?;
        Ok(row.map(|r| r.payload))
    }

    /// Strongly-consistent fetch (forces a read through the leader).
    pub async fn fetch_svid_consistent(
        &self,
        spiffe_id: &str,
    ) -> Result<Option<Vec<u8>>, ClusterError> {
        let rows: Vec<RawSvidRow> = self
            .client
            .query_consistent_map(
                "SELECT spiffe_id, payload, updated_at FROM issued_svids WHERE spiffe_id = $1",
                vec![Param::from(spiffe_id.to_string())],
            )
            .await?;
        Ok(rows.into_iter().next().map(|r| r.payload))
    }

    /// All issued-SVID `(spiffe_id, payload)` pairs.
    pub async fn list_svids(&self) -> Result<Vec<(String, Vec<u8>)>, ClusterError> {
        let rows: Vec<RawSvidRow> = self
            .client
            .query_map(
                "SELECT spiffe_id, payload, updated_at FROM issued_svids",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        Ok(rows.into_iter().map(|r| (r.spiffe_id, r.payload)).collect())
    }

    /// Delete one issued-SVID record by SPIFFE id. Returns whether a row was
    /// removed.
    pub async fn delete_svid(&self, spiffe_id: &str) -> Result<bool, ClusterError> {
        let affected = self
            .client
            .execute(
                "DELETE FROM issued_svids WHERE spiffe_id = $1",
                vec![Param::from(spiffe_id.to_string())],
            )
            .await?;
        Ok(affected > 0)
    }

    /// Insert or replace one host's signed caller allowlist. Payload bytes are
    /// opaque to the cluster — CMIS owns the CBOR `SignedAllowlist` schema.
    pub async fn upsert_allowlist(
        &self,
        host_uuid: &str,
        payload: &[u8],
        now_unix: i64,
    ) -> Result<(), ClusterError> {
        self.client
            .execute(
                "INSERT INTO host_allowlists (host_uuid, payload, updated_at) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (host_uuid) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at",
                vec![
                    Param::from(host_uuid.to_string()),
                    Param::from(payload.to_vec()),
                    Param::from(now_unix),
                ],
            )
            .await?;
        Ok(())
    }

    /// Strongly-consistent fetch of one host's allowlist payload (forces a read
    /// through the leader, so a follower never serves a stale allowlist after a
    /// successful upsert on the leader).
    pub async fn fetch_allowlist_consistent(
        &self,
        host_uuid: &str,
    ) -> Result<Option<Vec<u8>>, ClusterError> {
        let rows: Vec<RawAllowlistRow> = self
            .client
            .query_consistent_map(
                "SELECT host_uuid, payload, updated_at FROM host_allowlists WHERE host_uuid = $1",
                vec![Param::from(host_uuid.to_string())],
            )
            .await?;
        Ok(rows.into_iter().next().map(|r| r.payload))
    }

    /// All stored `(host_uuid, payload)` allowlist pairs.
    pub async fn list_allowlists(&self) -> Result<Vec<(String, Vec<u8>)>, ClusterError> {
        let rows: Vec<RawAllowlistRow> = self
            .client
            .query_map(
                "SELECT host_uuid, payload, updated_at FROM host_allowlists",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        Ok(rows.into_iter().map(|r| (r.host_uuid, r.payload)).collect())
    }

    /// Delete one host's allowlist. Returns whether a row was removed.
    pub async fn delete_allowlist(&self, host_uuid: &str) -> Result<bool, ClusterError> {
        let affected = self
            .client
            .execute(
                "DELETE FROM host_allowlists WHERE host_uuid = $1",
                vec![Param::from(host_uuid.to_string())],
            )
            .await?;
        Ok(affected > 0)
    }

    /// Insert or replace one host's pending allowlist proposal. `entries` bytes
    /// are opaque to the cluster — CMIS owns the CBOR `Vec<AllowEntry>` schema. A
    /// host has at most one pending proposal; a newer one replaces the older.
    pub async fn upsert_proposal(
        &self,
        host_uuid: &str,
        entries: &[u8],
        proposer_spiffe_id: &str,
        proposed_at: i64,
    ) -> Result<(), ClusterError> {
        self.client
            .execute(
                "INSERT INTO pending_allowlist_proposals (host_uuid, entries, proposer_spiffe_id, proposed_at) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (host_uuid) DO UPDATE SET entries = excluded.entries, \
                    proposer_spiffe_id = excluded.proposer_spiffe_id, proposed_at = excluded.proposed_at",
                vec![
                    Param::from(host_uuid.to_string()),
                    Param::from(entries.to_vec()),
                    Param::from(proposer_spiffe_id.to_string()),
                    Param::from(proposed_at),
                ],
            )
            .await?;
        Ok(())
    }

    /// All pending proposals as `(host_uuid, entries, proposer_spiffe_id,
    /// proposed_at)` tuples. `entries` is the opaque CBOR CMIS stored.
    pub async fn list_proposals(
        &self,
    ) -> Result<Vec<(String, Vec<u8>, String, i64)>, ClusterError> {
        let rows: Vec<RawProposalRow> = self
            .client
            .query_map(
                "SELECT host_uuid, entries, proposer_spiffe_id, proposed_at FROM pending_allowlist_proposals",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.host_uuid, r.entries, r.proposer_spiffe_id, r.proposed_at))
            .collect())
    }

    /// Delete one host's pending proposal. Returns whether a row was removed.
    pub async fn delete_proposal(&self, host_uuid: &str) -> Result<bool, ClusterError> {
        let affected = self
            .client
            .execute(
                "DELETE FROM pending_allowlist_proposals WHERE host_uuid = $1",
                vec![Param::from(host_uuid.to_string())],
            )
            .await?;
        Ok(affected > 0)
    }

    /// Current RIM policy epoch.
    pub async fn current_rim_version(&self) -> Result<u64, ClusterError> {
        let row: RimRow = self
            .client
            .query_map_one(
                "SELECT version FROM rim_state WHERE id = 1",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        Ok(u64::try_from(row.version).unwrap_or(0))
    }

    /// Bump the RIM policy epoch by one and return the new value. Forces a
    /// re-attestation on every host's next rotation (see F10 / F04).
    pub async fn bump_rim_version(&self) -> Result<u64, ClusterError> {
        self.client
            .execute(
                "UPDATE rim_state SET version = version + 1 WHERE id = 1",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        self.current_rim_version().await
    }

    /// Fetch the cluster's issuer master seed, if one has been established.
    ///
    /// Strongly-consistent (read through the leader) so a node never bootstraps
    /// its issuer from a stale local view and mints a second signing identity:
    /// the whole point of replicating the seed is that every node signs under
    /// one key behind the cluster's SRV name.
    pub async fn fetch_issuer_seed(&self) -> Result<Option<Vec<u8>>, ClusterError> {
        let rows: Vec<RawSeedRow> = self
            .client
            .query_consistent_map(
                "SELECT id, seed, created_at FROM issuer_seed WHERE id = 1",
                Vec::<hiqlite::Param>::new(),
            )
            .await?;
        Ok(rows.into_iter().next().map(|r| r.seed))
    }

    /// Store the issuer master seed, but only if none is set yet. Returns `true`
    /// if this call established the seed, `false` if another node had already
    /// done so (the existing seed is left untouched).
    ///
    /// `INSERT OR IGNORE` on the `id = 1` singleton makes this a cluster-wide
    /// compare-and-set: concurrent bootstrappers race through the Raft log and
    /// exactly one wins, so the cluster converges on a single seed. Callers that
    /// lose (`false`) must re-read [`Self::fetch_issuer_seed`] to learn the
    /// winning value.
    pub async fn try_store_issuer_seed(
        &self,
        seed: &[u8],
        now_unix: i64,
    ) -> Result<bool, ClusterError> {
        let affected = self
            .client
            .execute(
                "INSERT OR IGNORE INTO issuer_seed (id, seed, created_at) VALUES (1, $1, $2)",
                vec![Param::from(seed.to_vec()), Param::from(now_unix)],
            )
            .await?;
        Ok(affected > 0)
    }

    /// Gracefully shut down the local Raft node.
    pub async fn shutdown(self) -> Result<(), ClusterError> {
        self.client.shutdown().await?;
        Ok(())
    }
}

// ---- internal row mapping --------------------------------------------------

#[derive(Debug)]
struct RawSvidRow {
    spiffe_id: String,
    payload: Vec<u8>,
    #[allow(dead_code)]
    updated_at: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for RawSvidRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            spiffe_id: row.get("spiffe_id"),
            payload: row.get("payload"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Debug)]
struct RawAllowlistRow {
    host_uuid: String,
    payload: Vec<u8>,
    #[allow(dead_code)]
    updated_at: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for RawAllowlistRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            host_uuid: row.get("host_uuid"),
            payload: row.get("payload"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Debug)]
struct RawProposalRow {
    host_uuid: String,
    entries: Vec<u8>,
    proposer_spiffe_id: String,
    proposed_at: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for RawProposalRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            host_uuid: row.get("host_uuid"),
            entries: row.get("entries"),
            proposer_spiffe_id: row.get("proposer_spiffe_id"),
            proposed_at: row.get("proposed_at"),
        }
    }
}

#[derive(Debug)]
struct RawSeedRow {
    #[allow(dead_code)]
    id: i64,
    seed: Vec<u8>,
    #[allow(dead_code)]
    created_at: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for RawSeedRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            seed: row.get("seed"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Debug)]
struct RimRow {
    version: i64,
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for RimRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self {
            version: row.get("version"),
        }
    }
}
