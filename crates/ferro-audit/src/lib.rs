//! `ferro-audit` — append-only, Merkle-chained, externally-anchored audit log
//! (feature F07, milestone M3).
//!
//! The M3 surface lands the pieces every later iteration of the log will
//! depend on:
//!
//! - [`event`] — the typed audit-event enum, CBOR-encoded, hashes-and-counters
//!   only (no PII; see `docs/audit.md`).
//! - [`merkle`] — an RFC 6962-style Merkle hash tree with SHA3-384 leaves and
//!   nodes, plus standalone inclusion / consistency proof verifiers.
//! - [`sth`] — `SignedTreeHead { tree_size, root_hash, timestamp }` signed
//!   with a composite Ed25519 + ML-DSA-65 key under domain context
//!   `ferrogate-sth-v1`. The signer is a trait; the in-process implementation
//!   is the M3 stub, replaced by the TEE-resident threshold signer in M4.
//! - [`store`] — backing-store abstraction with a local-disk WORM
//!   implementation ([`store::LocalDiskWormStore`]), the shipped WORM tier.
//!   A native S3 Object Lock store is dropped (see `docs/roadmap.md`
//!   "Dropped scope"); the trait seam stays open for an out-of-tree adapter.
//! - [`log`] — the [`log::AuditLog`] facade tying tree + store + signer
//!   together with a thread-safe append API.
//! - [`anchor`] — the M4 external-transparency anchor publisher: an
//!   [`anchor::Anchor`] trait abstracts Sigsum / Rekor / etc.; an
//!   [`anchor::AnchorQueue`] persists pending STHs on disk so a publisher
//!   restart never drops anchors during an upstream outage; and
//!   [`anchor::AnchorPublisher::drain_once`] drives a single pass with
//!   transient-vs-permanent failure handling and backlog-age reporting.
//! - [`cosign`] — the M4 surface for STHs co-signed by a Raft majority:
//!   [`cosign::QuorumSigner`] aggregates per-replica composite signatures
//!   over the same canonical body, and [`cosign::verify_cosigned`] accepts
//!   the artefact iff at least the configured threshold of distinct
//!   signatures verify.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod bytes;
pub mod cosign;
pub mod event;
pub mod log;
pub mod merkle;
pub mod sth;
pub mod store;

pub use anchor::{
    Anchor, AnchorError, AnchorPublisher, AnchorQueue, AnchorQueueError, AnchorReceipt,
    DrainOutcome, PendingEntry,
};
pub use bytes::{Bytes16, Hash384};

pub use cosign::{
    verify_cosigned, CoSignature, CoSignedTreeHead, QuorumError, QuorumSigner, VerifyingKeyset,
};
pub use event::{AuditEvent, EventCodecError};
pub use log::{AuditLog, AuditLogError};
pub use merkle::{
    leaf_hash, node_hash, verify_consistency, verify_inclusion, MerkleTree, HASH_LEN,
};
pub use sth::{
    verify_sth, InProcessSigner, SignedTreeHead, SthBody, SthError, SthSigner, STH_SIGNING_CONTEXT,
};
pub use store::{AuditStore, AuditStoreError, LocalDiskWormStore};
