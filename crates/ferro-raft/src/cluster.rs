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

use hiqlite::{Client, Node, NodeConfig, Param};
use tokio::time::timeout;

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
        }
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
        let nodes: Vec<Node> = cfg
            .peers
            .iter()
            .map(|p| Node {
                id: p.id,
                addr_raft: p.addr_raft.clone(),
                addr_api: p.addr_api.clone(),
            })
            .collect();

        let node_config = NodeConfig {
            node_id,
            nodes,
            listen_addr_api: Cow::Owned(cfg.listen_addr_api.clone()),
            listen_addr_raft: Cow::Owned(cfg.listen_addr_raft.clone()),
            data_dir: Cow::Owned(cfg.data_dir.clone()),
            filename_db: Cow::Owned(cfg.filename_db.clone()),
            secret_raft: cfg.secret_raft.clone(),
            secret_api: cfg.secret_api.clone(),
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
