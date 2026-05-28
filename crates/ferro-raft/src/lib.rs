//! `ferro-raft` — CMIS high-availability cluster layer (feature F05).
//!
//! CMIS runs as a Raft-replicated set so issued SVID metadata and the active
//! RIM version are point-in-time consistent across replicas, and a leader
//! crash never costs operator attention. The Raft implementation is
//! `hiqlite` — a SQLite + openraft engine that owns its own log, snapshot,
//! and peer transport. This crate hides hiqlite behind a typed
//! [`Cluster`] API so the rest of FerroGate (and a future M5 switch to a
//! different store) is unaffected by hiqlite's specifics.
//!
//! Acceptance criteria touched by this crate (see
//! `docs/features/F05-cmis-ha.md`):
//!
//! - 3-node Raft cluster forms, elects a leader, and replicates a write.
//! - Killing the leader produces a new leader; the cluster continues serving.
//! - A follower restart rejoins without data loss.
//! - Health: [`Cluster::is_healthy`] / [`Cluster::role`] gate the LB endpoints.
//! - Chaos: random kills over a window with zero client-visible errors while
//!   a quorum remains.
//!
//! ### Design notes
//!
//! - **Transport is hiqlite's.** F05 originally specified a custom QUIC peer
//!   transport with hybrid-PQC TLS; that is now an upstream-hiqlite concern.
//!   Operators that need PQC peer TLS today pin the peers to a private
//!   network; the design point is tracked in the F05 doc.
//! - **Schema is SQL.** Issued-SVID rows are JSON blobs keyed by SPIFFE id; a
//!   one-row `rim_state` table tracks the active policy epoch. Migrations
//!   are inline `CREATE TABLE IF NOT EXISTS` — small enough not to need a
//!   migration manager yet.

#![forbid(unsafe_code)]

pub mod cluster;

pub use cluster::{Cluster, ClusterConfig, ClusterError, NodeRole, PeerNode};
