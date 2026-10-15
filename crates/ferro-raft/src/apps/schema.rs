//! DDL of the app approval ledger (F19 §2), applied as schema migrations 1
//! ([`LEDGER_SCHEMA`]), 2 ([`APPROVAL_USER_GUARDS`]) and 3
//! ([`LEGACY_IMPORT_GUARDS`], the terms of a legacy import, F19 §11).
//!
//! Tables first, then indexes, then triggers (trigger bodies name tables
//! created earlier in the same migration). Every statement is idempotent.
//! Migration 1 is kept exactly as first applied; migration 2 replaces three
//! of its `app_approvals` triggers (`DROP TRIGGER IF EXISTS`, then `CREATE`,
//! in one transaction), so databases created by migration 1 and new ones end
//! with the same guards.
//!
//! The triggers are the **database half** of the non-replacement invariant
//! (ADR-0004 INV-1 to INV-3). They guard against application bugs; the audit
//! trail of record stays ferro-audit:
//!
//! - `app_lineages`, `app_binaries`, `app_requests`, `app_approvals`,
//!   `app_approval_revisions` and `host_allowlist_state` rows are never
//!   deleted.
//! - Revisions are dense and never reused: a binary takes its lineage's
//!   `next_revision`, which then advances by exactly one; binaries are
//!   immutable.
//! - A request keeps every non-decision column; a `PENDING` request moves
//!   once, to `APPROVED`, `DENIED` or `EXPIRED`, and terminal states are
//!   final. Only its personal-data columns may later be pseudonymised
//!   (F19 §10), and only once it is terminal.
//! - What an approval authorizes (host, lineage, hash, revision, origin,
//!   parent, approver) never changes. Scope only narrows, `REVOKED` is final,
//!   every policy or user change (`uid`, `user_kind`, `sid`, `user_name`
//!   included) advances `row_version` by one and must have its
//!   `app_approval_revisions` row, and an auto-update approval must copy an
//!   active, unfrozen auto-update parent of its lineage, expiry included,
//!   and never re-approve a revoked or denied hash.
//! - The user of an approval changes only when an any-user scope is
//!   narrowed (versioned), or — the one unversioned change — when the
//!   `sid`/`user_name` of a `REVOKED` (final) approval is pseudonymised
//!   (F19 §10): replaced by a value in the [`PSEUDONYM_PREFIX`] format. An
//!   `EXPIRED` approval can be renewed, so its user is never rewritten in
//!   place.
//! - A host's allowlist generation never decreases.

/// Prefix of a pseudonymised personal value (F19 §10): `pseudonym:v1:`
/// followed by 64 lowercase hex characters (a keyed SHA-256). A `:` appears
/// in neither a Unix nor a Windows user name, nor in a SID, so a pseudonym
/// never collides with a real identity.
pub const PSEUDONYM_PREFIX: &str = "pseudonym:v1:";

/// Whether `value` is in the pseudonym format the ledger triggers accept for
/// the pseudonymisation of a revoked approval ([`PSEUDONYM_PREFIX`] + 64
/// lowercase hex characters).
#[must_use]
pub fn is_pseudonym(value: &str) -> bool {
    value.strip_prefix(PSEUDONYM_PREFIX).is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// SQL: `$col` holds a pseudonym ([`is_pseudonym`]); `0` for `NULL`.
macro_rules! pseudonym_sql {
    ($col:literal) => {
        concat!(
            "coalesce((",
            $col,
            " GLOB 'pseudonym:v1:*' AND length(",
            $col,
            ") = 77 AND substr(",
            $col,
            ", 14) NOT GLOB '*[^0-9a-f]*'), 0)"
        )
    };
}

/// SQL: this update of a `REVOKED` approval changes `sid` and `user_name`
/// only to pseudonyms (or not at all).
macro_rules! pseudonymises_revoked_sql {
    () => {
        concat!(
            "(OLD.state = 3 AND (NEW.sid IS OLD.sid OR ",
            pseudonym_sql!("NEW.sid"),
            ") AND (NEW.user_name IS OLD.user_name OR ",
            pseudonym_sql!("NEW.user_name"),
            "))"
        )
    };
}

/// Statements of schema migration 2, in order: the `app_approvals` user
/// guards of migration 1, replaced (F19 security review). Migration 1 let
/// `sid` and `user_name` change without a `row_version` bump on any approval
/// that was not `ACTIVE`, so the user of an `EXPIRED` approval could be
/// rewritten and the approval then renewed for someone else; nor did its
/// versioned and `REVOKED`-final checks cover those two columns.
pub(crate) const APPROVAL_USER_GUARDS: &[&str] = &[
    "DROP TRIGGER IF EXISTS app_approvals_user_changes_on_narrowing",
    concat!(
        "CREATE TRIGGER IF NOT EXISTS app_approvals_user_changes_on_narrowing \
            BEFORE UPDATE ON app_approvals \
            WHEN (NEW.uid IS NOT OLD.uid OR NEW.user_kind IS NOT OLD.user_kind \
                    OR NEW.sid IS NOT OLD.sid OR NEW.user_name IS NOT OLD.user_name) \
                AND NOT (OLD.user_scope = 2 AND NEW.user_scope = 1) \
                AND NOT (NEW.state = 3 AND NEW.uid IS OLD.uid \
                    AND NEW.user_kind IS OLD.user_kind AND NEW.row_version = OLD.row_version \
                    AND ",
        pseudonymises_revoked_sql!(),
        ") \
            BEGIN SELECT RAISE(ABORT, 'app_approvals: the user of an approval changes only when an \
                any-user scope is narrowed, or is pseudonymised once revoked'); END"
    ),
    "DROP TRIGGER IF EXISTS app_approvals_revoked_final",
    concat!(
        "CREATE TRIGGER IF NOT EXISTS app_approvals_revoked_final \
            BEFORE UPDATE ON app_approvals \
            WHEN OLD.state = 3 AND (NEW.state IS NOT 3 OR NEW.row_version IS NOT OLD.row_version \
                OR NEW.expires_at IS NOT OLD.expires_at \
                OR NEW.update_policy IS NOT OLD.update_policy \
                OR NEW.continuity IS NOT OLD.continuity OR NEW.user_scope IS NOT OLD.user_scope \
                OR NEW.path_match IS NOT OLD.path_match OR NEW.user_kind IS NOT OLD.user_kind \
                OR NEW.uid IS NOT OLD.uid OR NEW.note IS NOT OLD.note \
                OR NEW.superseded_by IS NOT OLD.superseded_by OR NEW.revoked_at IS NOT OLD.revoked_at \
                OR NEW.revoked_by_admin_id IS NOT OLD.revoked_by_admin_id \
                OR NEW.revoke_reason_code IS NOT OLD.revoke_reason_code \
                OR (NEW.sid IS NOT OLD.sid AND NOT ",
        pseudonym_sql!("NEW.sid"),
        ") OR (NEW.user_name IS NOT OLD.user_name AND NOT ",
        pseudonym_sql!("NEW.user_name"),
        ")) \
            BEGIN SELECT RAISE(ABORT, 'app_approvals: REVOKED is final'); END"
    ),
    "DROP TRIGGER IF EXISTS app_approvals_changes_are_versioned",
    concat!(
        "CREATE TRIGGER IF NOT EXISTS app_approvals_changes_are_versioned \
            BEFORE UPDATE ON app_approvals \
            WHEN (NEW.state IS NOT OLD.state OR NEW.update_policy IS NOT OLD.update_policy \
                    OR NEW.continuity IS NOT OLD.continuity OR NEW.expires_at IS NOT OLD.expires_at \
                    OR NEW.note IS NOT OLD.note OR NEW.user_scope IS NOT OLD.user_scope \
                    OR NEW.path_match IS NOT OLD.path_match OR NEW.user_kind IS NOT OLD.user_kind \
                    OR NEW.uid IS NOT OLD.uid OR NEW.revoked_at IS NOT OLD.revoked_at \
                    OR NEW.revoked_by_admin_id IS NOT OLD.revoked_by_admin_id \
                    OR NEW.revoke_reason_code IS NOT OLD.revoke_reason_code \
                    OR NEW.row_version IS NOT OLD.row_version \
                    OR ((NEW.sid IS NOT OLD.sid OR NEW.user_name IS NOT OLD.user_name) \
                        AND NOT ",
        pseudonymises_revoked_sql!(),
        ")) \
                AND (NEW.row_version IS NOT OLD.row_version + 1 \
                    OR NOT EXISTS (SELECT 1 FROM app_approval_revisions v \
                        WHERE v.approval_id = OLD.approval_id AND v.row_version = NEW.row_version)) \
            BEGIN SELECT RAISE(ABORT, 'app_approvals: every change advances row_version by one and \
                has a revision record'); END"
    ),
];

/// Statements of schema migration 3 (F19 §11, M38): the terms of a legacy
/// import. A `legacy_import` approval is created exactly as F19 §11 step 4
/// describes it — any path, manual each time, no expiry, no revision, no
/// parent, no Windows identity — and never names a real lineage, so it can
/// never become the auto-update parent of a binary a host reported. Later
/// edits (expiry, narrowing, revocation) go through the ordinary guards.
pub(crate) const LEGACY_IMPORT_GUARDS: &[&str] = &[
    "CREATE TRIGGER IF NOT EXISTS app_approvals_legacy_import_terms \
        BEFORE INSERT ON app_approvals \
        WHEN NEW.origin = 4 AND (NEW.path_match IS NOT 2 OR NEW.update_policy IS NOT 1 \
            OR NEW.expires_at IS NOT NULL OR NEW.revision IS NOT NULL \
            OR NEW.parent_approval_id IS NOT NULL OR NEW.sid IS NOT NULL \
            OR NEW.user_name IS NOT NULL OR NEW.user_kind IS NOT NULL \
            OR EXISTS (SELECT 1 FROM app_lineages l WHERE l.lineage_id = NEW.lineage_id)) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: a legacy import is any-path, manual each time, \
            without expiry, revision, parent, Windows identity or lineage'); END",
];

/// Statements of schema migration 1, in order. Kept exactly as first
/// applied; three of its triggers are replaced by migration 2
/// ([`APPROVAL_USER_GUARDS`]).
pub(crate) const LEDGER_SCHEMA: &[&str] = &[
    // ---- tables -------------------------------------------------------------
    "CREATE TABLE IF NOT EXISTS app_lineages ( \
        lineage_id TEXT PRIMARY KEY CHECK (length(lineage_id) BETWEEN 1 AND 64), \
        host_uuid TEXT NOT NULL CHECK (length(host_uuid) BETWEEN 1 AND 64), \
        platform INTEGER NOT NULL CHECK (platform IN (1, 2, 3)), \
        canonical_path TEXT NOT NULL \
            CHECK (length(CAST(canonical_path AS BLOB)) BETWEEN 1 AND 4096), \
        path_key BLOB NOT NULL CHECK (length(path_key) BETWEEN 1 AND 8192), \
        next_revision INTEGER NOT NULL DEFAULT 1 CHECK (next_revision >= 1), \
        auto_update_frozen INTEGER NOT NULL DEFAULT 0 CHECK (auto_update_frozen IN (0, 1)), \
        created_at INTEGER NOT NULL, \
        UNIQUE (host_uuid, path_key) \
    )",
    "CREATE TABLE IF NOT EXISTS app_binaries ( \
        lineage_id TEXT NOT NULL REFERENCES app_lineages(lineage_id), \
        bin_sha TEXT NOT NULL CHECK (length(bin_sha) = 96 AND bin_sha NOT GLOB '*[^0-9a-f]*'), \
        revision INTEGER NOT NULL CHECK (revision >= 1), \
        file_size INTEGER NOT NULL CHECK (file_size >= 0), \
        format INTEGER NOT NULL CHECK (format IN (1, 2, 3, 9)), \
        declared_version TEXT CHECK (declared_version IS NULL OR length(declared_version) <= 64), \
        version_source INTEGER NOT NULL CHECK (version_source BETWEEN 0 AND 7), \
        product_name TEXT CHECK (product_name IS NULL OR length(product_name) <= 128), \
        bundle_id TEXT CHECK (bundle_id IS NULL OR length(bundle_id) <= 255), \
        package_name TEXT CHECK (package_name IS NULL OR length(package_name) <= 128), \
        signer_kind INTEGER NOT NULL DEFAULT 0 CHECK (signer_kind IN (0, 1, 2)), \
        signer_id TEXT CHECK (signer_id IS NULL OR length(signer_id) <= 128), \
        signer_subject TEXT CHECK (signer_subject IS NULL OR length(signer_subject) <= 256), \
        signer_valid INTEGER NOT NULL DEFAULT 0 CHECK (signer_valid IN (0, 1)), \
        first_seen_at INTEGER NOT NULL, \
        PRIMARY KEY (lineage_id, bin_sha), \
        UNIQUE (lineage_id, revision) \
    )",
    "CREATE TABLE IF NOT EXISTS app_requests ( \
        request_id TEXT PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 64), \
        host_uuid TEXT NOT NULL CHECK (length(host_uuid) BETWEEN 1 AND 64), \
        client_request_id TEXT NOT NULL CHECK (length(client_request_id) BETWEEN 1 AND 64), \
        lineage_id TEXT NOT NULL, \
        bin_sha TEXT NOT NULL CHECK (length(bin_sha) = 96 AND bin_sha NOT GLOB '*[^0-9a-f]*'), \
        revision INTEGER NOT NULL CHECK (revision >= 1), \
        kind INTEGER NOT NULL CHECK (kind IN (1, 2)), \
        origin INTEGER NOT NULL CHECK (origin IN (1, 2, 3, 4)), \
        target_user_kind INTEGER NOT NULL CHECK (target_user_kind IN (1, 2)), \
        target_uid INTEGER, \
        target_sid TEXT CHECK (target_sid IS NULL OR length(target_sid) <= 184), \
        target_user_name TEXT CHECK (target_user_name IS NULL OR length(target_user_name) <= 256), \
        requester_uid INTEGER, \
        requester_user_name TEXT \
            CHECK (requester_user_name IS NULL OR length(requester_user_name) <= 256), \
        requested_by_admin_id TEXT, \
        reason TEXT CHECK (reason IS NULL OR length(reason) <= 200), \
        flags INTEGER NOT NULL CHECK (flags BETWEEN 0 AND 4294967295), \
        host_tier TEXT NOT NULL CHECK (length(host_tier) <= 64), \
        proposer_spiffe_id TEXT NOT NULL CHECK (length(proposer_spiffe_id) <= 2048), \
        dedup_key BLOB NOT NULL CHECK (length(dedup_key) = 32), \
        submitted_at INTEGER NOT NULL, \
        pending_expires_at INTEGER NOT NULL, \
        state INTEGER NOT NULL CHECK (state IN (1, 2, 3, 4, 5)), \
        decided_at INTEGER, \
        decided_by_admin_id TEXT, \
        decision_reason_code INTEGER, \
        decision_message TEXT CHECK (decision_message IS NULL OR length(decision_message) <= 200), \
        auto_downgrade_reason INTEGER, \
        resulting_approval_id TEXT, \
        same_actor_approved INTEGER NOT NULL DEFAULT 0 CHECK (same_actor_approved IN (0, 1)), \
        UNIQUE (host_uuid, client_request_id), \
        CHECK ((state = 1) = (decided_at IS NULL)), \
        CHECK ((state IN (2, 3)) = (resulting_approval_id IS NOT NULL)), \
        CHECK (state <> 4 OR decision_reason_code IS NOT NULL), \
        CHECK (origin <> 3 OR requested_by_admin_id IS NOT NULL), \
        CHECK (target_user_kind <> 1 OR target_uid IS NOT NULL), \
        CHECK (target_user_kind <> 2 OR target_sid IS NOT NULL) \
    )",
    "CREATE TABLE IF NOT EXISTS app_approvals ( \
        approval_id TEXT PRIMARY KEY CHECK (length(approval_id) BETWEEN 1 AND 64), \
        host_uuid TEXT NOT NULL CHECK (length(host_uuid) BETWEEN 1 AND 64), \
        lineage_id TEXT NOT NULL, \
        bin_sha TEXT NOT NULL, \
        revision INTEGER, \
        source_request_id TEXT, \
        origin INTEGER NOT NULL CHECK (origin IN (1, 2, 3, 4)), \
        parent_approval_id TEXT, \
        approved_by_admin_id TEXT, \
        user_scope INTEGER NOT NULL CHECK (user_scope IN (1, 2)), \
        user_kind INTEGER CHECK (user_kind IS NULL OR user_kind IN (1, 2)), \
        uid INTEGER, \
        sid TEXT CHECK (sid IS NULL OR length(sid) <= 184), \
        user_name TEXT CHECK (user_name IS NULL OR length(user_name) <= 256), \
        path_match INTEGER NOT NULL CHECK (path_match IN (1, 2)), \
        update_policy INTEGER NOT NULL CHECK (update_policy IN (1, 2)), \
        continuity INTEGER NOT NULL CHECK (continuity IN (1, 2)), \
        created_at INTEGER NOT NULL, \
        expires_at INTEGER, \
        state INTEGER NOT NULL CHECK (state IN (1, 2, 3)), \
        superseded_by TEXT, \
        revoked_at INTEGER, \
        revoked_by_admin_id TEXT, \
        revoke_reason_code INTEGER, \
        note TEXT CHECK (note IS NULL OR length(note) <= 500), \
        row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version >= 1), \
        CHECK ((bin_sha = '*' AND origin = 4) \
            OR (length(bin_sha) = 96 AND bin_sha NOT GLOB '*[^0-9a-f]*')), \
        CHECK (revision IS NOT NULL OR origin = 4), \
        CHECK ((origin = 2) = (parent_approval_id IS NOT NULL)), \
        CHECK ((origin IN (2, 4)) = (approved_by_admin_id IS NULL)), \
        CHECK ((origin = 4) = (source_request_id IS NULL)), \
        CHECK (user_scope = 1 OR (uid IS NULL AND sid IS NULL AND user_name IS NULL)), \
        CHECK (user_scope = 2 OR uid IS NOT NULL OR sid IS NOT NULL), \
        CHECK ((state = 3) = (revoked_at IS NOT NULL)), \
        CHECK (state <> 3 OR (revoked_by_admin_id IS NOT NULL AND revoke_reason_code IS NOT NULL)), \
        CHECK (state <> 2 OR expires_at IS NOT NULL) \
    )",
    "CREATE TABLE IF NOT EXISTS app_approval_revisions ( \
        approval_id TEXT NOT NULL, \
        row_version INTEGER NOT NULL CHECK (row_version >= 1), \
        changed_at INTEGER NOT NULL, \
        changed_by_admin_id TEXT, \
        change_kind INTEGER NOT NULL CHECK (change_kind BETWEEN 1 AND 5), \
        before_cbor BLOB, \
        after_cbor BLOB NOT NULL, \
        PRIMARY KEY (approval_id, row_version), \
        CHECK ((change_kind = 1) = (row_version = 1)), \
        CHECK ((change_kind = 1) = (before_cbor IS NULL)), \
        CHECK (change_kind NOT IN (2, 4, 5) OR changed_by_admin_id IS NOT NULL) \
    )",
    "CREATE TABLE IF NOT EXISTS host_allowlist_state ( \
        host_uuid TEXT PRIMARY KEY CHECK (length(host_uuid) BETWEEN 1 AND 64), \
        generation INTEGER NOT NULL CHECK (generation >= 0), \
        entries_digest BLOB NOT NULL, \
        changed_at INTEGER NOT NULL, \
        cached_v2 BLOB, \
        cached_not_after INTEGER \
    )",
    // Precondition guard for multi-statement transactions: inserting a code
    // other than 'ok' aborts the whole transaction with a recognisable
    // message (see `apps::guard`). The table always stays empty.
    "CREATE TABLE IF NOT EXISTS app_txn_guard (code TEXT NOT NULL)",
    // ---- indexes -------------------------------------------------------------
    "CREATE INDEX IF NOT EXISTS app_requests_state_time ON app_requests(state, submitted_at)",
    "CREATE INDEX IF NOT EXISTS app_requests_host_state ON app_requests(host_uuid, state)",
    "CREATE INDEX IF NOT EXISTS app_requests_dedup ON app_requests(dedup_key, state)",
    "CREATE INDEX IF NOT EXISTS app_requests_lineage ON app_requests(lineage_id, bin_sha)",
    // At most one open request per dedup key (F19 §5.2): a duplicate pending
    // request cannot be stored even if two submissions race.
    "CREATE UNIQUE INDEX IF NOT EXISTS app_requests_one_pending \
        ON app_requests(dedup_key) WHERE state = 1",
    "CREATE INDEX IF NOT EXISTS app_approvals_host_state ON app_approvals(host_uuid, state)",
    "CREATE INDEX IF NOT EXISTS app_approvals_lineage_state ON app_approvals(lineage_id, state)",
    "CREATE INDEX IF NOT EXISTS app_approvals_expiry ON app_approvals(state, expires_at)",
    "CREATE INDEX IF NOT EXISTS app_approvals_lineage_sha ON app_approvals(lineage_id, bin_sha)",
    // ---- app_lineages --------------------------------------------------------
    "CREATE TRIGGER IF NOT EXISTS app_lineages_identity_immutable \
        BEFORE UPDATE ON app_lineages \
        WHEN NEW.lineage_id IS NOT OLD.lineage_id OR NEW.host_uuid IS NOT OLD.host_uuid \
            OR NEW.platform IS NOT OLD.platform OR NEW.path_key IS NOT OLD.path_key \
            OR NEW.created_at IS NOT OLD.created_at \
        BEGIN SELECT RAISE(ABORT, 'app_lineages: identity columns are immutable'); END",
    "CREATE TRIGGER IF NOT EXISTS app_lineages_revisions_sequential \
        BEFORE UPDATE ON app_lineages \
        WHEN NEW.next_revision IS NOT OLD.next_revision \
            AND (NEW.next_revision IS NOT OLD.next_revision + 1 \
                OR NOT EXISTS (SELECT 1 FROM app_binaries \
                    WHERE lineage_id = OLD.lineage_id AND revision = OLD.next_revision)) \
        BEGIN SELECT RAISE(ABORT, 'app_lineages: revisions advance one at a time, never reused'); END",
    "CREATE TRIGGER IF NOT EXISTS app_lineages_path_kept_while_active \
        BEFORE UPDATE ON app_lineages \
        WHEN NEW.canonical_path IS NOT OLD.canonical_path \
            AND EXISTS (SELECT 1 FROM app_approvals \
                WHERE lineage_id = OLD.lineage_id AND state = 1) \
        BEGIN SELECT RAISE(ABORT, 'app_lineages: the path of a lineage with active approvals is kept'); END",
    "CREATE TRIGGER IF NOT EXISTS app_lineages_no_delete \
        BEFORE DELETE ON app_lineages \
        BEGIN SELECT RAISE(ABORT, 'app_lineages rows are never deleted'); END",
    // ---- app_binaries --------------------------------------------------------
    "CREATE TRIGGER IF NOT EXISTS app_binaries_take_next_revision \
        BEFORE INSERT ON app_binaries \
        WHEN NOT EXISTS (SELECT 1 FROM app_lineages \
            WHERE lineage_id = NEW.lineage_id AND next_revision = NEW.revision) \
        BEGIN SELECT RAISE(ABORT, 'app_binaries: a new binary takes its lineage next_revision'); END",
    "CREATE TRIGGER IF NOT EXISTS app_binaries_no_update \
        BEFORE UPDATE ON app_binaries \
        BEGIN SELECT RAISE(ABORT, 'app_binaries rows are immutable'); END",
    "CREATE TRIGGER IF NOT EXISTS app_binaries_no_delete \
        BEFORE DELETE ON app_binaries \
        BEGIN SELECT RAISE(ABORT, 'app_binaries rows are immutable'); END",
    // ---- app_requests --------------------------------------------------------
    "CREATE TRIGGER IF NOT EXISTS app_requests_insert_state \
        BEFORE INSERT ON app_requests \
        WHEN NEW.state NOT IN (1, 2, 3) \
            OR (NEW.state = 2 AND NEW.origin <> 3) OR (NEW.state = 3 AND NEW.origin = 3) \
        BEGIN SELECT RAISE(ABORT, 'app_requests: a request starts PENDING, AUTO_APPROVED, \
            or APPROVED by a direct administrator add'); END",
    "CREATE TRIGGER IF NOT EXISTS app_requests_insert_binary \
        BEFORE INSERT ON app_requests \
        WHEN NOT EXISTS (SELECT 1 FROM app_binaries b \
            JOIN app_lineages l ON l.lineage_id = b.lineage_id \
            WHERE b.lineage_id = NEW.lineage_id AND b.bin_sha = NEW.bin_sha \
            AND b.revision = NEW.revision AND l.host_uuid = NEW.host_uuid) \
        BEGIN SELECT RAISE(ABORT, 'app_requests: the binary must be a revision of a lineage \
            of this host'); END",
    "CREATE TRIGGER IF NOT EXISTS app_requests_insert_approval \
        BEFORE INSERT ON app_requests \
        WHEN NEW.resulting_approval_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM app_approvals a \
            WHERE a.approval_id = NEW.resulting_approval_id AND a.host_uuid = NEW.host_uuid \
            AND (a.bin_sha = NEW.bin_sha OR a.bin_sha = '*')) \
        BEGIN SELECT RAISE(ABORT, 'app_requests: a decision names an approval of this binary \
            on this host'); END",
    "CREATE TRIGGER IF NOT EXISTS app_requests_columns_immutable \
        BEFORE UPDATE ON app_requests \
        WHEN NEW.request_id IS NOT OLD.request_id OR NEW.host_uuid IS NOT OLD.host_uuid \
            OR NEW.client_request_id IS NOT OLD.client_request_id \
            OR NEW.lineage_id IS NOT OLD.lineage_id OR NEW.bin_sha IS NOT OLD.bin_sha \
            OR NEW.revision IS NOT OLD.revision OR NEW.kind IS NOT OLD.kind \
            OR NEW.origin IS NOT OLD.origin OR NEW.target_user_kind IS NOT OLD.target_user_kind \
            OR NEW.target_uid IS NOT OLD.target_uid OR NEW.requester_uid IS NOT OLD.requester_uid \
            OR NEW.requested_by_admin_id IS NOT OLD.requested_by_admin_id \
            OR NEW.flags IS NOT OLD.flags OR NEW.host_tier IS NOT OLD.host_tier \
            OR NEW.proposer_spiffe_id IS NOT OLD.proposer_spiffe_id \
            OR NEW.dedup_key IS NOT OLD.dedup_key OR NEW.submitted_at IS NOT OLD.submitted_at \
            OR NEW.pending_expires_at IS NOT OLD.pending_expires_at \
            OR NEW.auto_downgrade_reason IS NOT OLD.auto_downgrade_reason \
        BEGIN SELECT RAISE(ABORT, 'app_requests: only the decision of a request changes'); END",
    "CREATE TRIGGER IF NOT EXISTS app_requests_pending_decides_once \
        BEFORE UPDATE ON app_requests \
        WHEN OLD.state = 1 AND (NEW.state NOT IN (2, 4, 5) \
            OR NEW.target_sid IS NOT OLD.target_sid \
            OR NEW.target_user_name IS NOT OLD.target_user_name \
            OR NEW.requester_user_name IS NOT OLD.requester_user_name \
            OR NEW.reason IS NOT OLD.reason) \
        BEGIN SELECT RAISE(ABORT, 'app_requests: a pending request only moves to APPROVED, \
            DENIED or EXPIRED'); END",
    "CREATE TRIGGER IF NOT EXISTS app_requests_terminal_final \
        BEFORE UPDATE ON app_requests \
        WHEN OLD.state <> 1 AND (NEW.state IS NOT OLD.state \
            OR NEW.decided_at IS NOT OLD.decided_at \
            OR NEW.decided_by_admin_id IS NOT OLD.decided_by_admin_id \
            OR NEW.decision_reason_code IS NOT OLD.decision_reason_code \
            OR NEW.resulting_approval_id IS NOT OLD.resulting_approval_id \
            OR NEW.same_actor_approved IS NOT OLD.same_actor_approved) \
        BEGIN SELECT RAISE(ABORT, 'app_requests: terminal request states are final'); END",
    "CREATE TRIGGER IF NOT EXISTS app_requests_decision_names_approval \
        BEFORE UPDATE ON app_requests \
        WHEN NEW.resulting_approval_id IS NOT NULL \
            AND NEW.resulting_approval_id IS NOT OLD.resulting_approval_id \
            AND NOT EXISTS (SELECT 1 FROM app_approvals a \
                WHERE a.approval_id = NEW.resulting_approval_id AND a.host_uuid = NEW.host_uuid \
                AND (a.bin_sha = NEW.bin_sha OR a.bin_sha = '*')) \
        BEGIN SELECT RAISE(ABORT, 'app_requests: a decision names an approval of this binary \
            on this host'); END",
    "CREATE TRIGGER IF NOT EXISTS app_requests_no_delete \
        BEFORE DELETE ON app_requests \
        BEGIN SELECT RAISE(ABORT, 'app_requests rows are append-only'); END",
    // ---- app_approvals -------------------------------------------------------
    "CREATE TRIGGER IF NOT EXISTS app_approvals_insert_fresh \
        BEFORE INSERT ON app_approvals \
        WHEN NEW.state <> 1 OR NEW.row_version <> 1 OR NEW.superseded_by IS NOT NULL \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: an approval starts ACTIVE at row_version 1'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_insert_binary \
        BEFORE INSERT ON app_approvals \
        WHEN NEW.origin <> 4 AND NOT EXISTS (SELECT 1 FROM app_binaries b \
            JOIN app_lineages l ON l.lineage_id = b.lineage_id \
            WHERE b.lineage_id = NEW.lineage_id AND b.bin_sha = NEW.bin_sha \
            AND b.revision = NEW.revision AND l.host_uuid = NEW.host_uuid) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: the approved binary must be a revision of a \
            lineage of this host'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_insert_auto_update \
        BEFORE INSERT ON app_approvals \
        WHEN NEW.origin = 2 AND NOT EXISTS (SELECT 1 FROM app_approvals p \
            JOIN app_lineages l ON l.lineage_id = p.lineage_id \
            WHERE p.approval_id = NEW.parent_approval_id AND p.state = 1 \
            AND p.update_policy = 2 AND p.host_uuid = NEW.host_uuid \
            AND p.lineage_id = NEW.lineage_id AND l.auto_update_frozen = 0 \
            AND p.user_scope = NEW.user_scope AND p.user_kind IS NEW.user_kind \
            AND p.uid IS NEW.uid AND p.sid IS NEW.sid AND p.user_name IS NEW.user_name \
            AND p.path_match = NEW.path_match AND p.update_policy = NEW.update_policy \
            AND p.continuity = NEW.continuity AND p.expires_at IS NEW.expires_at \
            AND (p.expires_at IS NULL OR p.expires_at > NEW.created_at)) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: an auto-update approval copies an active, \
            unfrozen auto-update parent of its lineage'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_insert_never_reapprove \
        BEFORE INSERT ON app_approvals \
        WHEN NEW.origin = 2 AND (EXISTS (SELECT 1 FROM app_approvals r \
                WHERE r.lineage_id = NEW.lineage_id AND r.bin_sha = NEW.bin_sha AND r.state = 3) \
            OR EXISTS (SELECT 1 FROM app_requests d \
                WHERE d.lineage_id = NEW.lineage_id AND d.bin_sha = NEW.bin_sha AND d.state = 4)) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: auto-update never re-approves a revoked or \
            denied hash'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_identity_immutable \
        BEFORE UPDATE ON app_approvals \
        WHEN NEW.approval_id IS NOT OLD.approval_id OR NEW.host_uuid IS NOT OLD.host_uuid \
            OR NEW.lineage_id IS NOT OLD.lineage_id OR NEW.bin_sha IS NOT OLD.bin_sha \
            OR NEW.revision IS NOT OLD.revision \
            OR NEW.source_request_id IS NOT OLD.source_request_id \
            OR NEW.origin IS NOT OLD.origin \
            OR NEW.parent_approval_id IS NOT OLD.parent_approval_id \
            OR NEW.approved_by_admin_id IS NOT OLD.approved_by_admin_id \
            OR NEW.created_at IS NOT OLD.created_at \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: what an approval authorizes is immutable'); END",
    // Replaced by migration 2 (`APPROVAL_USER_GUARDS`): sid and user_name.
    "CREATE TRIGGER IF NOT EXISTS app_approvals_revoked_final \
        BEFORE UPDATE ON app_approvals \
        WHEN OLD.state = 3 AND (NEW.state IS NOT 3 OR NEW.row_version IS NOT OLD.row_version \
            OR NEW.expires_at IS NOT OLD.expires_at \
            OR NEW.update_policy IS NOT OLD.update_policy \
            OR NEW.continuity IS NOT OLD.continuity OR NEW.user_scope IS NOT OLD.user_scope \
            OR NEW.path_match IS NOT OLD.path_match OR NEW.user_kind IS NOT OLD.user_kind \
            OR NEW.uid IS NOT OLD.uid OR NEW.note IS NOT OLD.note \
            OR NEW.superseded_by IS NOT OLD.superseded_by OR NEW.revoked_at IS NOT OLD.revoked_at \
            OR NEW.revoked_by_admin_id IS NOT OLD.revoked_by_admin_id \
            OR NEW.revoke_reason_code IS NOT OLD.revoke_reason_code) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: REVOKED is final'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_scope_only_narrows \
        BEFORE UPDATE ON app_approvals \
        WHEN (OLD.user_scope = 1 AND NEW.user_scope = 2) \
            OR (OLD.path_match = 1 AND NEW.path_match = 2) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: scope only narrows; widening needs a new \
            request'); END",
    // Replaced by migration 2: its carve-out let sid and user_name change
    // unversioned on any non-ACTIVE approval.
    "CREATE TRIGGER IF NOT EXISTS app_approvals_user_changes_on_narrowing \
        BEFORE UPDATE ON app_approvals \
        WHEN (NEW.uid IS NOT OLD.uid OR NEW.user_kind IS NOT OLD.user_kind \
                OR NEW.sid IS NOT OLD.sid OR NEW.user_name IS NOT OLD.user_name) \
            AND NOT (OLD.user_scope = 2 AND NEW.user_scope = 1) \
            AND NOT (OLD.state <> 1 AND NEW.state = OLD.state AND NEW.uid IS OLD.uid \
                AND NEW.user_kind IS OLD.user_kind AND NEW.row_version = OLD.row_version) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: the user of an approval changes only when an \
            any-user scope is narrowed'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_state_transitions \
        BEFORE UPDATE ON app_approvals \
        WHEN NEW.state IS NOT OLD.state AND NOT ( \
            (OLD.state = 1 AND NEW.state = 2 AND OLD.expires_at IS NOT NULL) \
            OR (OLD.state IN (1, 2) AND NEW.state = 3) \
            OR (OLD.state = 2 AND NEW.state = 1 \
                AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at))) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: invalid state transition'); END",
    // Replaced by migration 2: sid and user_name.
    "CREATE TRIGGER IF NOT EXISTS app_approvals_changes_are_versioned \
        BEFORE UPDATE ON app_approvals \
        WHEN (NEW.state IS NOT OLD.state OR NEW.update_policy IS NOT OLD.update_policy \
                OR NEW.continuity IS NOT OLD.continuity OR NEW.expires_at IS NOT OLD.expires_at \
                OR NEW.note IS NOT OLD.note OR NEW.user_scope IS NOT OLD.user_scope \
                OR NEW.path_match IS NOT OLD.path_match OR NEW.user_kind IS NOT OLD.user_kind \
                OR NEW.uid IS NOT OLD.uid OR NEW.revoked_at IS NOT OLD.revoked_at \
                OR NEW.revoked_by_admin_id IS NOT OLD.revoked_by_admin_id \
                OR NEW.revoke_reason_code IS NOT OLD.revoke_reason_code \
                OR NEW.row_version IS NOT OLD.row_version) \
            AND (NEW.row_version IS NOT OLD.row_version + 1 \
                OR NOT EXISTS (SELECT 1 FROM app_approval_revisions v \
                    WHERE v.approval_id = OLD.approval_id AND v.row_version = NEW.row_version)) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: every change advances row_version by one and \
            has a revision record'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_superseded_once \
        BEFORE UPDATE ON app_approvals \
        WHEN NEW.superseded_by IS NOT OLD.superseded_by \
            AND (OLD.superseded_by IS NOT NULL OR NOT EXISTS (SELECT 1 FROM app_approvals c \
                WHERE c.approval_id = NEW.superseded_by AND c.lineage_id = OLD.lineage_id \
                AND c.revision > OLD.revision)) \
        BEGIN SELECT RAISE(ABORT, 'app_approvals: superseded_by is set once, to a newer \
            revision of the same lineage'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approvals_no_delete \
        BEFORE DELETE ON app_approvals \
        BEGIN SELECT RAISE(ABORT, 'app_approvals rows are never deleted; revoke instead'); END",
    // ---- app_approval_revisions ---------------------------------------------
    "CREATE TRIGGER IF NOT EXISTS app_approval_revisions_follow_the_row \
        BEFORE INSERT ON app_approval_revisions \
        WHEN NOT EXISTS (SELECT 1 FROM app_approvals a WHERE a.approval_id = NEW.approval_id \
            AND a.row_version = CASE WHEN NEW.change_kind = 1 THEN 1 ELSE NEW.row_version - 1 END) \
        BEGIN SELECT RAISE(ABORT, 'app_approval_revisions: a revision follows the approval row \
            it describes'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approval_revisions_no_update \
        BEFORE UPDATE ON app_approval_revisions \
        BEGIN SELECT RAISE(ABORT, 'app_approval_revisions is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS app_approval_revisions_no_delete \
        BEFORE DELETE ON app_approval_revisions \
        BEGIN SELECT RAISE(ABORT, 'app_approval_revisions is append-only'); END",
    // ---- host_allowlist_state -------------------------------------------------
    "CREATE TRIGGER IF NOT EXISTS host_allowlist_state_generation_monotonic \
        BEFORE UPDATE ON host_allowlist_state \
        WHEN NEW.generation < OLD.generation OR NEW.host_uuid IS NOT OLD.host_uuid \
        BEGIN SELECT RAISE(ABORT, 'host_allowlist_state: the generation never decreases'); END",
    "CREATE TRIGGER IF NOT EXISTS host_allowlist_state_no_delete \
        BEFORE DELETE ON host_allowlist_state \
        BEGIN SELECT RAISE(ABORT, 'host_allowlist_state rows are never deleted'); END",
    // ---- transaction guard ------------------------------------------------------
    // One trigger per code so the abort message names the failed precondition.
    // The final trigger catches any code without a trigger of its own.
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_not_found BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'not_found' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:not_found'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_invalid_state BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'invalid_state' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:invalid_state'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_row_version BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'row_version_mismatch' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:row_version_mismatch'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_replayed BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'replayed' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:replayed'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_covered BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'covered' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:covered'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_duplicate BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'duplicate_pending' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:duplicate_pending'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_denied_cooldown BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'denied_cooldown' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:denied_cooldown'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_sod BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'sod_self_approval' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:sod_self_approval'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_not_covering BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'not_covering' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:not_covering'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_no_auto_parent BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'no_auto_parent' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:no_auto_parent'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_lineage_frozen BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'lineage_frozen' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:lineage_frozen'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_user_mismatch BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'user_mismatch' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:user_mismatch'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_no_anchor BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'no_continuity_anchor' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:no_continuity_anchor'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_revoked BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'hash_previously_revoked' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:hash_previously_revoked'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_denied BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'hash_previously_denied' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:hash_previously_denied'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_auto_rate BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'auto_rate_exceeded' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:auto_rate_exceeded'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_stale BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code = 'stale' \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:stale'); END",
    "CREATE TRIGGER IF NOT EXISTS app_txn_guard_other BEFORE INSERT ON app_txn_guard \
        WHEN NEW.code NOT IN ('not_found', 'invalid_state', 'row_version_mismatch', 'replayed', \
            'covered', 'duplicate_pending', 'denied_cooldown', 'sod_self_approval', \
            'not_covering', 'no_auto_parent', 'lineage_frozen', 'user_mismatch', \
            'no_continuity_anchor', 'hash_previously_revoked', 'hash_previously_denied', \
            'auto_rate_exceeded', 'stale') \
        BEGIN SELECT RAISE(ABORT, 'ferrogate-guard:failed'); END",
];
