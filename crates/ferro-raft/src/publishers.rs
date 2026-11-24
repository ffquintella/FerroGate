//! Replicated trusted publishers (ADR-0006): the records an administrator
//! adds and removes, from which CMIS compiles the publisher list of the
//! signed allowlist (format 3). Policy (authorization, MFA, audit) lives in
//! CMIS; this layer persists rows and enforces, in SQLite triggers too:

//! - rows are never deleted, and what a record trusts never changes;
//! - removal is the only change, it happens once and is final;
//! - at most one active record per (kind, anchor, pin kind, pin), and at
//!   most [`MAX_ACTIVE_PUBLISHERS`] active records.

use hiqlite::Param;

use crate::apps::{collect, generic_refusal, Parsed, TxnOutcome};
use crate::cluster::{Cluster, ClusterError};
use crate::LedgerError;

/// Most active trusted publishers (the signed body's limit).
pub const MAX_ACTIVE_PUBLISHERS: i64 = 256;
/// `state` of an active record.
pub const PUBLISHER_ACTIVE: i64 = 1;
/// `state` of a removed record.
pub const PUBLISHER_REMOVED: i64 = 2;

/// Schema migration 4 (ADR-0006).
pub(crate) const PUBLISHER_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS trusted_publishers ( \
        publisher_id TEXT PRIMARY KEY, \
        kind INTEGER NOT NULL CHECK (kind IN (1, 2)), \
        anchor_sha256 BLOB NOT NULL CHECK (length(anchor_sha256) = 32), \
        pin_kind INTEGER NOT NULL CHECK (pin_kind IN (1, 2, 3)), \
        pin BLOB NOT NULL CHECK (length(pin) = 32), \
        require_timestamp INTEGER NOT NULL CHECK (require_timestamp IN (0, 1)), \
        label TEXT NOT NULL, \
        subject TEXT NOT NULL, \
        issuer TEXT NOT NULL, \
        leaf_cert_sha256 BLOB CHECK (leaf_cert_sha256 IS NULL OR length(leaf_cert_sha256) = 32), \
        created_at INTEGER NOT NULL, \
        created_by_admin_id TEXT NOT NULL, \
        expires_at INTEGER, \
        state INTEGER NOT NULL CHECK (state IN (1, 2)), \
        removed_at INTEGER, \
        removed_by_admin_id TEXT \
    )",
    "CREATE UNIQUE INDEX IF NOT EXISTS trusted_publishers_active_pin \
        ON trusted_publishers(kind, anchor_sha256, pin_kind, pin) WHERE state = 1",
    "CREATE TRIGGER IF NOT EXISTS trusted_publishers_exists BEFORE INSERT ON trusted_publishers \
        WHEN EXISTS (SELECT 1 FROM trusted_publishers t WHERE t.state = 1 \
            AND t.kind = NEW.kind AND t.anchor_sha256 = NEW.anchor_sha256 \
            AND t.pin_kind = NEW.pin_kind AND t.pin = NEW.pin) \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:publisher_exists'); END",
    "CREATE TRIGGER IF NOT EXISTS trusted_publishers_cap BEFORE INSERT ON trusted_publishers \
        WHEN (SELECT COUNT(*) FROM trusted_publishers WHERE state = 1) >= 256 \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:too_many_publishers'); END",
    "CREATE TRIGGER IF NOT EXISTS trusted_publishers_new_active BEFORE INSERT ON trusted_publishers \
        WHEN NEW.state IS NOT 1 OR NEW.removed_at IS NOT NULL OR NEW.removed_by_admin_id IS NOT NULL \
        BEGIN SELECT RAISE(ABORT, 'trusted_publishers: a new record is active'); END",
    "CREATE TRIGGER IF NOT EXISTS trusted_publishers_no_delete BEFORE DELETE ON trusted_publishers \
        BEGIN SELECT RAISE(ABORT, 'trusted_publishers: records are never deleted'); END",
    "CREATE TRIGGER IF NOT EXISTS trusted_publishers_remove_only BEFORE UPDATE ON trusted_publishers \
        WHEN OLD.state IS NOT 1 OR NEW.state IS NOT 2 OR NEW.removed_at IS NULL \
            OR NEW.removed_by_admin_id IS NULL \
            OR NEW.publisher_id IS NOT OLD.publisher_id OR NEW.kind IS NOT OLD.kind \
            OR NEW.anchor_sha256 IS NOT OLD.anchor_sha256 OR NEW.pin_kind IS NOT OLD.pin_kind \
            OR NEW.pin IS NOT OLD.pin OR NEW.require_timestamp IS NOT OLD.require_timestamp \
            OR NEW.label IS NOT OLD.label OR NEW.subject IS NOT OLD.subject \
            OR NEW.issuer IS NOT OLD.issuer OR NEW.leaf_cert_sha256 IS NOT OLD.leaf_cert_sha256 \
            OR NEW.created_at IS NOT OLD.created_at \
            OR NEW.created_by_admin_id IS NOT OLD.created_by_admin_id \
            OR NEW.expires_at IS NOT OLD.expires_at \
        BEGIN SELECT RAISE(ABORT, 'trusted_publishers: only a single removal changes a record'); END",
];

/// A trusted publisher to add (validated by CMIS first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPublisher {
    /// New id (UUIDv7).
    pub publisher_id: String,
    /// 1 authenticode, 2 apple.
    pub kind: i64,
    /// SHA-256 of the pinned CA certificate.
    pub anchor_sha256: [u8; 32],
    /// 1 leaf certificate, 2 leaf SPKI, 3 leaf subject.
    pub pin_kind: i64,
    /// The pinned leaf digest.
    pub pin: [u8; 32],
    /// Signatures must carry a trusted timestamp.
    pub require_timestamp: bool,
    /// Display label.
    pub label: String,
    /// Leaf subject at add time (display only).
    pub subject: String,
    /// Leaf issuer at add time (display only).
    pub issuer: String,
    /// Leaf thumbprint at add time (display only).
    pub leaf_cert_sha256: Option<[u8; 32]>,
    /// Unix seconds.
    pub created_at: i64,
    /// Adding administrator.
    pub created_by_admin_id: String,
    /// Unix seconds; `None` for no expiry.
    pub expires_at: Option<i64>,
}

/// A stored trusted publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherRow {
    /// The record as added.
    pub record: NewPublisher,
    /// [`PUBLISHER_ACTIVE`] or [`PUBLISHER_REMOVED`].
    pub state: i64,
    /// Unix seconds of the removal.
    pub removed_at: Option<i64>,
    /// Removing administrator.
    pub removed_by_admin_id: Option<String>,
}

const COLUMNS: &str = "publisher_id, kind, anchor_sha256, pin_kind, pin, require_timestamp, \
    label, subject, issuer, leaf_cert_sha256, created_at, created_by_admin_id, expires_at, state, \
    removed_at, removed_by_admin_id";

fn fixed32(v: &[u8], column: &'static str) -> Result<[u8; 32], LedgerError> {
    v.try_into().map_err(|_| LedgerError::Corrupt(column))
}

impl<'r> From<&'r mut hiqlite::Row<'_>> for Parsed<PublisherRow> {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        let anchor: Vec<u8> = row.get("anchor_sha256");
        let pin: Vec<u8> = row.get("pin");
        let leaf: Option<Vec<u8>> = row.get("leaf_cert_sha256");
        let parsed = (|| {
            Ok(PublisherRow {
                record: NewPublisher {
                    publisher_id: row.get("publisher_id"),
                    kind: row.get("kind"),
                    anchor_sha256: fixed32(&anchor, "anchor_sha256")?,
                    pin_kind: row.get("pin_kind"),
                    pin: fixed32(&pin, "pin")?,
                    require_timestamp: row.get::<i64>("require_timestamp") != 0,
                    label: row.get("label"),
                    subject: row.get("subject"),
                    issuer: row.get("issuer"),
                    leaf_cert_sha256: leaf
                        .as_deref()
                        .map(|l| fixed32(l, "leaf_cert_sha256"))
                        .transpose()?,
                    created_at: row.get("created_at"),
                    created_by_admin_id: row.get("created_by_admin_id"),
                    expires_at: row.get("expires_at"),
                },
                state: row.get("state"),
                removed_at: row.get("removed_at"),
                removed_by_admin_id: row.get("removed_by_admin_id"),
            })
        })();
        Self(parsed)
    }
}

fn text(v: &str) -> Param {
    Param::from(v.to_string())
}

/// Bounds the store checks again whatever CMIS validated.
fn validate(p: &NewPublisher) -> Result<(), LedgerError> {
    let id_ok = |v: &str| !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_graphic());
    if !id_ok(&p.publisher_id) {
        return Err(LedgerError::Invalid("publisher_id"));
    }
    if !id_ok(&p.created_by_admin_id) {
        return Err(LedgerError::Invalid("admin_id"));
    }
    if !matches!(p.kind, 1 | 2) {
        return Err(LedgerError::Invalid("kind"));
    }
    if !matches!(p.pin_kind, 1..=3) {
        return Err(LedgerError::Invalid("pin_kind"));
    }
    for (v, max, field) in [
        (&p.label, 128, "label"),
        (&p.subject, 512, "subject"),
        (&p.issuer, 512, "issuer"),
    ] {
        if v.chars().count() > max {
            return Err(LedgerError::Invalid(field));
        }
    }
    Ok(())
}

/// Map a refused publisher transaction.
fn refusal(code: &str) -> LedgerError {
    match code {
        "publisher_exists" => LedgerError::Invalid("publisher_exists"),
        "too_many_publishers" => LedgerError::Invalid("too_many_publishers"),
        other => generic_refusal(other),
    }
}

impl Cluster {
    /// Add a trusted publisher. Refused with `Invalid("publisher_exists")`
    /// when an active one pins the same thing, `Invalid("too_many_publishers")`
    /// at the cap; nothing is written then.
    pub async fn publisher_add(&self, p: &NewPublisher) -> Result<PublisherRow, LedgerError> {
        validate(p)?;
        let stmts = vec![(
            "INSERT INTO trusted_publishers (publisher_id, kind, anchor_sha256, pin_kind, pin, \
             require_timestamp, label, subject, issuer, leaf_cert_sha256, created_at, \
             created_by_admin_id, expires_at, state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1)",
            vec![
                text(&p.publisher_id),
                Param::from(p.kind),
                Param::from(p.anchor_sha256.to_vec()),
                Param::from(p.pin_kind),
                Param::from(p.pin.to_vec()),
                Param::from(i64::from(p.require_timestamp)),
                text(&p.label),
                text(&p.subject),
                text(&p.issuer),
                Param::from(p.leaf_cert_sha256.map(|l| l.to_vec())),
                Param::from(p.created_at),
                text(&p.created_by_admin_id),
                Param::from(p.expires_at),
            ],
        )];
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(refusal(&code)),
        }
        self.publisher(&p.publisher_id)
            .await?
            .ok_or(LedgerError::Raced)
    }

    /// Remove an active trusted publisher (once, final). `NotFound` for an
    /// unknown id, `InvalidState` when it was already removed.
    pub async fn publisher_remove(
        &self,
        publisher_id: &str,
        admin_id: &str,
        now: i64,
    ) -> Result<PublisherRow, LedgerError> {
        let stmts = vec![
            (
                "INSERT INTO app_txn_guard (code) SELECT c FROM (SELECT CASE \
                 WHEN NOT EXISTS (SELECT 1 FROM trusted_publishers WHERE publisher_id = ?1) \
                    THEN 'not_found' \
                 WHEN NOT EXISTS (SELECT 1 FROM trusted_publishers \
                    WHERE publisher_id = ?1 AND state = 1) THEN 'invalid_state' \
                 ELSE 'ok' END AS c) WHERE c <> 'ok'",
                vec![text(publisher_id)],
            ),
            (
                "UPDATE trusted_publishers SET state = 2, removed_at = ?2, \
                 removed_by_admin_id = ?3 WHERE publisher_id = ?1 AND state = 1",
                vec![text(publisher_id), Param::from(now), text(admin_id)],
            ),
        ];
        match self.ledger_txn(stmts).await? {
            TxnOutcome::Committed => {}
            TxnOutcome::Refused(code) => return Err(refusal(&code)),
        }
        self.publisher(publisher_id)
            .await?
            .ok_or(LedgerError::Raced)
    }

    /// One trusted publisher by id.
    pub async fn publisher(&self, publisher_id: &str) -> Result<Option<PublisherRow>, LedgerError> {
        let rows: Vec<Parsed<PublisherRow>> = self
            .client()
            .query_consistent_map(
                format!("SELECT {COLUMNS} FROM trusted_publishers WHERE publisher_id = ?1"),
                vec![text(publisher_id)],
            )
            .await
            .map_err(ClusterError::from)?;
        Ok(collect(rows)?.into_iter().next())
    }

    /// Every trusted publisher (only active ones unless `include_removed`),
    /// oldest first.
    pub async fn publishers(
        &self,
        include_removed: bool,
    ) -> Result<Vec<PublisherRow>, LedgerError> {
        let filter = if include_removed {
            ""
        } else {
            "WHERE state = 1"
        };
        let rows: Vec<Parsed<PublisherRow>> = self
            .client()
            .query_consistent_map(
                format!(
                    "SELECT {COLUMNS} FROM trusted_publishers {filter} \
                     ORDER BY created_at, publisher_id"
                ),
                Vec::new(),
            )
            .await
            .map_err(ClusterError::from)?;
        collect(rows)
    }

    /// The publishers a compiled allowlist carries at `now`: active and
    /// unexpired, at most [`MAX_ACTIVE_PUBLISHERS`].
    pub async fn publishers_in_force(&self, now: i64) -> Result<Vec<PublisherRow>, LedgerError> {
        let rows: Vec<Parsed<PublisherRow>> = self
            .client()
            .query_consistent_map(
                format!(
                    "SELECT {COLUMNS} FROM trusted_publishers WHERE state = 1 \
                     AND (expires_at IS NULL OR expires_at > ?1) \
                     ORDER BY publisher_id LIMIT ?2"
                ),
                vec![Param::from(now), Param::from(MAX_ACTIVE_PUBLISHERS)],
            )
            .await
            .map_err(ClusterError::from)?;
        collect(rows)
    }
}
