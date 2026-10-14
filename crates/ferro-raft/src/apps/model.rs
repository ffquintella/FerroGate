//! Row types, enums and inputs of the app approval ledger (F19 §2–§3).
//!
//! Enum discriminants are the integer codes stored in the tables. Values
//! that describe the binary rather than the ledger (platform, format, version
//! source, signer kind) are kept as the raw integers F19 §2 lists; their
//! meaning is owned by `ferro-appid`, and CHECK constraints keep them in range.

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use super::LedgerError;

macro_rules! code_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $code:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The integer code stored in the ledger.
            #[must_use]
            pub const fn code(self) -> i64 {
                match self { $( Self::$variant => $code ),+ }
            }

            /// The variant for a stored code, if the code is known.
            #[must_use]
            pub const fn from_code(code: i64) -> Option<Self> {
                match code { $( $code => Some(Self::$variant), )+ _ => None }
            }
        }
    };
}

code_enum! {
    /// Request kind, classified by CMIS (never taken from the client).
    RequestKind {
        /// The lineage has no approval yet.
        Register = 1,
        /// The lineage already has an approval.
        Update = 2,
    }
}

code_enum! {
    /// Who asked for the request.
    RequestOrigin {
        /// The application itself, through the helper socket (`RegisterSelf`).
        SelfRegistration = 1,
        /// A user on the host, through `mia app register` or the tray (`RegisterFile`).
        Assisted = 2,
        /// An administrator, through `AdminRegisterApplication`.
        AdminDirect = 3,
        /// MIA observed a denied caller (`allowlist.propose` in approvals mode).
        Observed = 4,
    }
}

code_enum! {
    /// Operating-system user namespace of an identity.
    UserKind {
        /// Unix uid and user name.
        Unix = 1,
        /// Windows SID (and RID for compatibility).
        Windows = 2,
    }
}

code_enum! {
    /// Request state (F19 §3). Every state but `Pending` is terminal.
    RequestState {
        /// Waiting for an administrator.
        Pending = 1,
        /// Approved by an administrator.
        Approved = 2,
        /// Approved by the auto-update policy of an earlier approval.
        AutoApproved = 3,
        /// Denied by an administrator.
        Denied = 4,
        /// Pending past its time-to-live.
        Expired = 5,
    }
}

impl RequestState {
    /// Whether the state is final.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

code_enum! {
    /// How an approval came to exist.
    ApprovalOrigin {
        /// An administrator approved a request.
        Manual = 1,
        /// The auto-update policy of a parent approval approved a request.
        AutoUpdate = 2,
        /// An administrator registered and approved in one step.
        AdminDirect = 3,
        /// Imported from a legacy `host_allowlists` body (F19 §11).
        LegacyImport = 4,
    }
}

code_enum! {
    /// Which users an approval admits.
    UserScope {
        /// Only the approved user.
        ExactUser = 1,
        /// Any user of the host.
        AnyUser = 2,
    }
}

code_enum! {
    /// Which paths an approval admits.
    PathMatch {
        /// Only the lineage path.
        Exact = 1,
        /// Any path on the host.
        Any = 2,
    }
}

code_enum! {
    /// Update policy, chosen at approval time (F19 §5.3).
    UpdatePolicy {
        /// Every new hash needs an administrator.
        ManualEachTime = 1,
        /// Same path and same user updates are approved automatically.
        AutoSamePathUser = 2,
    }
}

code_enum! {
    /// Continuity requirement of an auto-update policy (F19 §5.3 #5).
    Continuity {
        /// Protected path or same signer required (default).
        Anchored = 1,
        /// Same path and user suffice (approvers are warned).
        PathUserOnly = 2,
    }
}

code_enum! {
    /// Approval state (F19 §3). `Revoked` is final.
    ApprovalState {
        /// Admits callers.
        Active = 1,
        /// Past `expires_at`; can be renewed.
        Expired = 2,
        /// Removed by an administrator.
        Revoked = 3,
    }
}

code_enum! {
    /// Kind of an `app_approval_revisions` record.
    RevisionChange {
        /// The approval was created.
        Created = 1,
        /// An administrator edited it.
        Updated = 2,
        /// The sweeper expired it.
        Expired = 3,
        /// An administrator revoked it.
        Revoked = 4,
        /// An administrator renewed an expired approval.
        Renewed = 5,
    }
}

code_enum! {
    /// Why an update was not auto-approved (F19 §5.3, first failing condition).
    AutoDowngradeReason {
        /// `CMIS_APP_AUTO_UPDATE` is off.
        AutoDisabled = 1,
        /// The host tier is not in `CMIS_APP_AUTO_UPDATE_TIERS`.
        TierNotAllowed = 2,
        /// No active, unexpired auto-update approval in the lineage.
        NoAutoParent = 3,
        /// The lineage is frozen.
        LineageFrozen = 4,
        /// The user does not match the parent's.
        UserMismatch = 5,
        /// Neither a protected path nor the parent's signer.
        NoContinuityAnchor = 6,
        /// The hash was revoked in this lineage before.
        HashPreviouslyRevoked = 7,
        /// The hash was denied in this lineage before.
        HashPreviouslyDenied = 8,
        /// Too many auto-approvals in this lineage in 24 h.
        AutoRateExceeded = 9,
    }
}

impl AutoDowngradeReason {
    /// The stable reason string of `SubmitAppRequestResponse.auto_downgrade_reason`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoDisabled => "auto_disabled",
            Self::TierNotAllowed => "tier_not_allowed",
            Self::NoAutoParent => "no_auto_parent",
            Self::LineageFrozen => "lineage_frozen",
            Self::UserMismatch => "user_mismatch",
            Self::NoContinuityAnchor => "no_continuity_anchor",
            Self::HashPreviouslyRevoked => "hash_previously_revoked",
            Self::HashPreviouslyDenied => "hash_previously_denied",
            Self::AutoRateExceeded => "auto_rate_exceeded",
        }
    }

    /// The reason for a stable reason string, if known.
    #[must_use]
    pub fn from_str_code(code: &str) -> Option<Self> {
        (1..=9)
            .filter_map(Self::from_code)
            .find(|r| r.as_str() == code)
    }
}

/// Bit 0 of the request `flags` (F19 §4.5): the file and every ancestor are
/// writable only by administrators. The ledger reads it for auto-update
/// eligibility; the full bit table is owned by `ferro-appid`.
pub const FLAG_PATH_PROTECTED: u32 = 1;

/// Decode a stored code into its enum, or report the column as corrupt.
pub(crate) fn decode<T>(
    code: i64,
    column: &'static str,
    from: fn(i64) -> Option<T>,
) -> Result<T, LedgerError> {
    from(code).ok_or(LedgerError::Corrupt(column))
}

/// An operating-system user, as a request names it (F19 §7.2 `target_user`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    /// Namespace of the identity.
    pub kind: UserKind,
    /// Unix uid, or the Windows RID (compatibility only).
    pub uid: Option<i64>,
    /// Full Windows SID, upper-cased by the caller. **Personal data.**
    pub sid: Option<String>,
    /// User name. **Personal data.**
    pub user_name: Option<String>,
}

impl UserIdentity {
    /// The `user_key` of the deduplication key (F19 §5.2):
    /// `"u:" ‖ uid ‖ ":" ‖ user_name` on Unix, `"s:" ‖ upper(SID)` on Windows.
    #[must_use]
    pub fn user_key(&self) -> String {
        match self.kind {
            UserKind::Unix => format!(
                "u:{}:{}",
                self.uid.unwrap_or_default(),
                self.user_name.as_deref().unwrap_or_default()
            ),
            UserKind::Windows => {
                format!(
                    "s:{}",
                    self.sid.as_deref().unwrap_or_default().to_ascii_uppercase()
                )
            }
        }
    }
}

/// `dedup_key = SHA-256(host_uuid ‖ 0 ‖ path_key ‖ 0 ‖ user_key ‖ 0 ‖ bin_sha)`
/// (F19 §5.2), with `bin_sha` as its 96 lowercase hex characters.
#[must_use]
pub fn dedup_key(host_uuid: &str, path_key: &[u8], user: &UserIdentity, bin_sha: &str) -> Vec<u8> {
    let user_key = user.user_key();
    let mut input =
        Vec::with_capacity(host_uuid.len() + path_key.len() + user_key.len() + bin_sha.len() + 3);
    input.extend_from_slice(host_uuid.as_bytes());
    input.push(0);
    input.extend_from_slice(path_key);
    input.push(0);
    input.extend_from_slice(user_key.as_bytes());
    input.push(0);
    input.extend_from_slice(bin_sha.as_bytes());
    digest(&SHA256, &input).as_ref().to_vec()
}

/// Whether `s` is a lowercase-hex SHA-384 (96 characters).
#[must_use]
pub fn is_bin_sha(s: &str) -> bool {
    s.len() == 96 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ---- rows ---------------------------------------------------------------------

/// One `app_lineages` row: every binary seen at one `(host, path)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageRow {
    /// UUIDv7.
    pub lineage_id: String,
    /// Host the path is on.
    pub host_uuid: String,
    /// 1 linux, 2 macos, 3 windows (`ferro_appid::Platform`).
    pub platform: i64,
    /// Canonical path for display. **Personal data** under a home directory.
    pub canonical_path: String,
    /// `ferro_appid::path_key(platform, path)`; the lineage key with `host_uuid`.
    pub path_key: Vec<u8>,
    /// Revision the next new binary takes.
    pub next_revision: i64,
    /// Administrator kill switch for auto-update in this lineage.
    pub auto_update_frozen: bool,
    /// Unix seconds.
    pub created_at: i64,
}

/// One `app_binaries` row: a distinct hash in a lineage and its revision.
/// Rows are immutable; the metadata is what the host reported at first sight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryRow {
    /// Owning lineage.
    pub lineage_id: String,
    /// Lowercase hex SHA-384.
    pub bin_sha: String,
    /// Sequential version in the lineage (1, 2, 3, …), never reused.
    pub revision: i64,
    /// File size in bytes.
    pub file_size: i64,
    /// 1 elf, 2 macho, 3 pe, 9 other.
    pub format: i64,
    /// Self-declared version (untrusted, display only).
    pub declared_version: Option<String>,
    /// Where the declared version came from (`ferro_appid::VersionSource`).
    pub version_source: i64,
    /// Product name (display only).
    pub product_name: Option<String>,
    /// macOS bundle identifier (display only).
    pub bundle_id: Option<String>,
    /// dpkg package name (display only).
    pub package_name: Option<String>,
    /// 0 none, 1 authenticode, 2 apple.
    pub signer_kind: i64,
    /// Leaf certificate SHA-256 hex or Apple Team ID.
    pub signer_id: Option<String>,
    /// Signer subject (display).
    pub signer_subject: Option<String>,
    /// Whether the signature verified on the host.
    pub signer_valid: bool,
    /// Unix seconds.
    pub first_seen_at: i64,
}

/// One `app_requests` row (immutable but for its decision).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRow {
    /// UUIDv7.
    pub request_id: String,
    /// Requesting host.
    pub host_uuid: String,
    /// MIA's idempotency key.
    pub client_request_id: String,
    /// Lineage of the binary.
    pub lineage_id: String,
    /// Lowercase hex SHA-384.
    pub bin_sha: String,
    /// Revision of `bin_sha` in the lineage.
    pub revision: i64,
    /// Server-classified kind.
    pub kind: RequestKind,
    /// Who asked.
    pub origin: RequestOrigin,
    /// The user the request is for.
    pub target: UserIdentity,
    /// Who invoked the request on the host.
    pub requester_uid: Option<i64>,
    /// Requester user name. **Personal data.**
    pub requester_user_name: Option<String>,
    /// Requesting administrator (`origin = AdminDirect`).
    pub requested_by_admin_id: Option<String>,
    /// Requester's note (free text, at most 200 characters).
    pub reason: Option<String>,
    /// Risk-flag bitmask (F19 §4.5).
    pub flags: u32,
    /// SVID policy id of the host (tpm / host-key / …).
    pub host_tier: String,
    /// SPIFFE id of the presenting SVID.
    pub proposer_spiffe_id: String,
    /// [`dedup_key`].
    pub dedup_key: Vec<u8>,
    /// Unix seconds.
    pub submitted_at: i64,
    /// Unix seconds after which a pending request expires.
    pub pending_expires_at: i64,
    /// Current state.
    pub state: RequestState,
    /// Unix seconds of the decision.
    pub decided_at: Option<i64>,
    /// Deciding administrator; `None` for auto-approval and expiry.
    pub decided_by_admin_id: Option<String>,
    /// Denial reason code.
    pub decision_reason_code: Option<i64>,
    /// Message shown to the requester (at most 200 characters).
    pub decision_message: Option<String>,
    /// Why auto-update was not applied.
    pub auto_downgrade_reason: Option<AutoDowngradeReason>,
    /// Approval created or reused by the decision.
    pub resulting_approval_id: Option<String>,
    /// Requester and approver were the same administrator.
    pub same_actor_approved: bool,
}

/// One `app_approvals` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    /// UUIDv7.
    pub approval_id: String,
    /// Host the approval applies to.
    pub host_uuid: String,
    /// Lineage of the approved binary.
    pub lineage_id: String,
    /// Lowercase hex SHA-384, or `"*"` for legacy imports only.
    pub bin_sha: String,
    /// Revision of `bin_sha`; `None` for legacy imports.
    pub revision: Option<i64>,
    /// Request the approval came from; `None` for legacy imports.
    pub source_request_id: Option<String>,
    /// How the approval came to exist.
    pub origin: ApprovalOrigin,
    /// Parent approval of an auto-update.
    pub parent_approval_id: Option<String>,
    /// Approving administrator; `None` for auto-update and legacy imports.
    pub approved_by_admin_id: Option<String>,
    /// Which users are admitted.
    pub user_scope: UserScope,
    /// Namespace of the admitted user.
    pub user_kind: Option<UserKind>,
    /// Admitted Unix uid (or legacy RID).
    pub uid: Option<i64>,
    /// Admitted Windows SID. **Personal data.**
    pub sid: Option<String>,
    /// Admitted user name (auto-update matching). **Personal data.**
    pub user_name: Option<String>,
    /// Which paths are admitted.
    pub path_match: PathMatch,
    /// Update policy.
    pub update_policy: UpdatePolicy,
    /// Continuity requirement of the update policy.
    pub continuity: Continuity,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; `None` only where configuration or a legacy import allows.
    pub expires_at: Option<i64>,
    /// Current state.
    pub state: ApprovalState,
    /// Newer approval of the same lineage (informational, not a state).
    pub superseded_by: Option<String>,
    /// Unix seconds of revocation.
    pub revoked_at: Option<i64>,
    /// Revoking administrator.
    pub revoked_by_admin_id: Option<String>,
    /// Revocation reason code.
    pub revoke_reason_code: Option<i64>,
    /// Administrator note (at most 500 characters).
    pub note: Option<String>,
    /// Optimistic-concurrency version; every change advances it by one.
    pub row_version: i64,
}

impl ApprovalRow {
    /// Whether the approval admits callers at `now` (active and unexpired).
    #[must_use]
    pub fn is_live(&self, now: i64) -> bool {
        self.state == ApprovalState::Active && self.expires_at.is_none_or(|t| t > now)
    }
}

/// One `app_approval_revisions` row (append-only history of an approval).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRevisionRow {
    /// Approval the revision belongs to.
    pub approval_id: String,
    /// The approval's `row_version` after the change.
    pub row_version: i64,
    /// Unix seconds.
    pub changed_at: i64,
    /// Administrator; `None` for the sweeper and policy-created approvals.
    pub changed_by_admin_id: Option<String>,
    /// What happened.
    pub change_kind: RevisionChange,
    /// CBOR [`ApprovalSnapshot`] before the change; `None` on creation.
    pub before_cbor: Option<Vec<u8>>,
    /// CBOR [`ApprovalSnapshot`] after the change.
    pub after_cbor: Vec<u8>,
}

/// One `host_allowlist_state` row (F19 §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAllowlistStateRow {
    /// Host.
    pub host_uuid: String,
    /// Hybrid-logical generation of the compiled entry set.
    pub generation: u64,
    /// SHA-384 of the canonical CBOR entries; empty until the first compile.
    pub entries_digest: Vec<u8>,
    /// Unix seconds of the last change.
    pub changed_at: i64,
    /// Cached signed v2 body, cleared on every change.
    pub cached_v2: Option<Vec<u8>>,
    /// `not_after` of the cached body.
    pub cached_not_after: Option<i64>,
}

/// The policy view of an approval stored in `app_approval_revisions`.
///
/// It deliberately carries **no personal data and no free text** (no user
/// name, SID or note text): revision rows are immutable, so anything stored
/// in them could never be pseudonymised (F19 §10). The note is represented
/// by a short digest so a reader can still see that it changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSnapshot {
    /// [`ApprovalState`] code.
    pub state: i64,
    /// [`UpdatePolicy`] code.
    pub update_policy: i64,
    /// [`Continuity`] code.
    pub continuity: i64,
    /// Unix seconds.
    pub expires_at: Option<i64>,
    /// [`UserScope`] code.
    pub user_scope: i64,
    /// [`PathMatch`] code.
    pub path_match: i64,
    /// [`UserKind`] code.
    pub user_kind: Option<i64>,
    /// Unix uid or legacy RID.
    pub uid: Option<i64>,
    /// First 8 bytes of SHA-256 of the note, if any.
    pub note_digest: Option<Vec<u8>>,
    /// Revocation reason code.
    pub revoke_reason_code: Option<i64>,
}

impl ApprovalSnapshot {
    /// Snapshot of `row`.
    #[must_use]
    pub fn of(row: &ApprovalRow) -> Self {
        Self {
            state: row.state.code(),
            update_policy: row.update_policy.code(),
            continuity: row.continuity.code(),
            expires_at: row.expires_at,
            user_scope: row.user_scope.code(),
            path_match: row.path_match.code(),
            user_kind: row.user_kind.map(UserKind::code),
            uid: row.uid,
            note_digest: row
                .note
                .as_deref()
                .map(|n| digest(&SHA256, n.as_bytes()).as_ref()[..8].to_vec()),
            revoke_reason_code: row.revoke_reason_code,
        }
    }

    /// Canonical CBOR of the snapshot.
    pub fn to_cbor(&self) -> Result<Vec<u8>, LedgerError> {
        let mut out = Vec::with_capacity(96);
        ciborium::into_writer(self, &mut out)
            .map_err(|_| LedgerError::Invalid("approval snapshot"))?;
        Ok(out)
    }

    /// Parse a snapshot from its CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LedgerError> {
        ciborium::from_reader(bytes).map_err(|_| LedgerError::Corrupt("approval snapshot"))
    }
}

// ---- inputs -------------------------------------------------------------------

/// A binary as the host identified it (F19 §4), at one path on one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedBinary {
    /// Host the binary is on.
    pub host_uuid: String,
    /// 1 linux, 2 macos, 3 windows.
    pub platform: i64,
    /// Canonical path (display).
    pub canonical_path: String,
    /// `ferro_appid::path_key(platform, canonical_path)`.
    pub path_key: Vec<u8>,
    /// Id used only when the lineage does not exist yet (UUIDv7).
    pub new_lineage_id: String,
    /// Lowercase hex SHA-384.
    pub bin_sha: String,
    /// File size in bytes.
    pub file_size: i64,
    /// 1 elf, 2 macho, 3 pe, 9 other.
    pub format: i64,
    /// Declared version (≤ 64 characters, display only).
    pub declared_version: Option<String>,
    /// Version source code (0–7).
    pub version_source: i64,
    /// Product name (≤ 128).
    pub product_name: Option<String>,
    /// Bundle id (≤ 255).
    pub bundle_id: Option<String>,
    /// Package name (≤ 128).
    pub package_name: Option<String>,
    /// 0 none, 1 authenticode, 2 apple.
    pub signer_kind: i64,
    /// Signer id (≤ 128).
    pub signer_id: Option<String>,
    /// Signer subject (≤ 256).
    pub signer_subject: Option<String>,
    /// Whether the signature verified.
    pub signer_valid: bool,
    /// Unix seconds.
    pub seen_at: i64,
}

/// A request to record. The kind is classified by the ledger (an update when
/// the lineage already has an approval), never taken from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRequest {
    /// UUIDv7.
    pub request_id: String,
    /// Requesting host (already authenticated by the caller).
    pub host_uuid: String,
    /// MIA's idempotency key.
    pub client_request_id: String,
    /// Lineage from [`crate::Cluster::app_observe_binary`].
    pub lineage_id: String,
    /// Lowercase hex SHA-384.
    pub bin_sha: String,
    /// Revision from [`crate::Cluster::app_observe_binary`].
    pub revision: i64,
    /// Who asked.
    pub origin: RequestOrigin,
    /// The user the request is for.
    pub target: UserIdentity,
    /// Who invoked the request on the host.
    pub requester_uid: Option<i64>,
    /// Requester user name.
    pub requester_user_name: Option<String>,
    /// Requesting administrator (`AdminDirect` only).
    pub requested_by_admin_id: Option<String>,
    /// Requester's note (≤ 200).
    pub reason: Option<String>,
    /// Risk flags, already masked by CMIS.
    pub flags: u32,
    /// SVID policy id of the host.
    pub host_tier: String,
    /// SPIFFE id of the presenting SVID.
    pub proposer_spiffe_id: String,
    /// [`dedup_key`].
    pub dedup_key: Vec<u8>,
    /// Unix seconds.
    pub submitted_at: i64,
    /// Unix seconds after which a pending request expires.
    pub pending_expires_at: i64,
    /// Why auto-update was not applied, for a pending request.
    pub auto_downgrade_reason: Option<AutoDowngradeReason>,
}

/// The terms an administrator chooses when approving (F19 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTerms {
    /// Exact user (copied from the request) or any user.
    pub user_scope: UserScope,
    /// Exact path or any path.
    pub path_match: PathMatch,
    /// Update policy.
    pub update_policy: UpdatePolicy,
    /// Continuity requirement.
    pub continuity: Continuity,
    /// Unix seconds; CMIS applies the default / maximum TTL rules first.
    pub expires_at: Option<i64>,
    /// Administrator note (≤ 500).
    pub note: Option<String>,
}
