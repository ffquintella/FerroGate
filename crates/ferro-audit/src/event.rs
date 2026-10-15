//! Audit event schema.
//!
//! Every event recorded in FerroGate's audit log is one of these variants.
//! Fields are restricted to hashes, counters, and small identifiers — there
//! is deliberately **no PII** so the log can be replicated and anchored
//! externally without leaking subject information. See `docs/audit.md`.
//!
//! Events are CBOR-encoded for the on-the-wire form and as the input to the
//! Merkle leaf hash. CBOR encoding via `ciborium` is deterministic for a
//! given Rust value, so the same event always hashes to the same leaf — the
//! invariant the inclusion / consistency proofs rely on.

use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes16, Bytes32, Hash384};

/// One audit event.
///
/// The `serde` tag is the variant name under a `"type"` field so an event's
/// type is self-describing inside the CBOR blob (and any JSON dumps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuditEvent {
    /// Phase 2 of a four-phase attestation began.
    AttestStart {
        /// SHA-384 of the EK certificate.
        ek_sha: Hash384,
        /// SHA-384 of the marshaled AIK public area.
        aik_sha: Hash384,
        /// RIM policy generation the boot state was approved under.
        policy_id: String,
    },
    /// An attestation was refused. The reason is a stable opcode string,
    /// never user input — there is no oracle surface here.
    AttestFail {
        /// Short, stable opcode describing why (e.g. `"quote-nonce-mismatch"`).
        reason: String,
    },
    /// An SVID was successfully issued.
    SvidIssued {
        /// SHA-384 of the composite certificate / JWS body.
        cert_sha: Hash384,
        /// Subject SPIFFE ID.
        spiffe_id: String,
    },
    /// An SVID was revoked (admin RPC).
    SvidRevoked {
        /// SHA-384 of the revoked artefact.
        cert_sha: Hash384,
        /// Stable opcode for the revocation reason.
        reason: String,
        /// Pseudonymous id (UUIDv7) of the administrator whose authenticated
        /// session made the call (F20). Absent on events written before F20.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by_admin_id: Option<String>,
    },
    /// Every SVID and child token for a host was revoked (admin RPC).
    HostRevoked {
        /// The revoked host SPIFFE ID.
        spiffe_id: String,
        /// Stable opcode for the revocation reason.
        reason: String,
        /// Pseudonymous id (UUIDv7) of the administrator whose authenticated
        /// session made the call (F20). Absent on events written before F20.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by_admin_id: Option<String>,
    },
    /// A host passed the F13 fleet-manifest pre-admission check at the start
    /// of `Attest` — its EK certificate hash is enrolled — and was allowed to
    /// proceed to TPM quote verification.
    HostEnrolled {
        /// SHA-384 of the EK certificate presented in phase 2.
        ek_sha: Hash384,
    },
    /// A host was refused at the F13 pre-admission check before any TPM
    /// verification work ran: its EK certificate hash is not in the active
    /// fleet manifest.
    HostRejected {
        /// SHA-384 of the EK certificate presented in phase 2.
        ek_sha: Hash384,
        /// Short, stable opcode (e.g. `"not-enrolled"`).
        reason: String,
    },
    /// The live RIM policy epoch was bumped by an admin RPC (feature F10).
    /// Every host attested under `old_epoch` is forced to fully re-attest on
    /// its next `Rotate`.
    PolicyEpochBumped {
        /// The epoch in force before the bump.
        old_epoch: u64,
        /// The epoch in force after the bump.
        new_epoch: u64,
        /// Short, stable opcode for why (e.g. `"rim-policy-change"`).
        reason: String,
        /// Pseudonymous id (UUIDv7) of the administrator whose authenticated
        /// session made the call (F20). Absent on events written before F20.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by_admin_id: Option<String>,
    },
    /// A host's signed caller allowlist was stored or replaced (admin RPC).
    AllowlistSet {
        /// EK-derived host UUID the allowlist is keyed by.
        host_uuid: String,
        /// Number of permitted callers in the new allowlist.
        entry_count: u32,
        /// Hard expiry CMIS stamped, Unix seconds.
        not_after: i64,
        /// Pseudonymous id (UUIDv7) of the administrator whose authenticated
        /// session made the call (F20). Absent on events written before F20.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by_admin_id: Option<String>,
    },
    /// A host's stored allowlist was deleted (admin RPC).
    AllowlistDeleted {
        /// EK-derived host UUID whose allowlist was removed.
        host_uuid: String,
        /// Pseudonymous id (UUIDv7) of the administrator whose authenticated
        /// session made the call (F20). Absent on events written before F20.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by_admin_id: Option<String>,
    },
    /// A host proposed a caller allowlist that was queued for operator review
    /// (an allowlist already exists, or policy declines to auto-adopt).
    AllowlistProposed {
        /// EK-derived host UUID the proposal is for.
        host_uuid: String,
        /// Number of proposed callers.
        entry_count: u32,
        /// SVID subject (SPIFFE id) that submitted the proposal.
        proposer_spiffe_id: String,
    },
    /// A host's proposal was signed and stored immediately as the live allowlist
    /// (first-use bootstrap, TOFU) under the configured proposal policy.
    AllowlistAutoAdopted {
        /// EK-derived host UUID the allowlist is keyed by.
        host_uuid: String,
        /// Number of permitted callers in the adopted allowlist.
        entry_count: u32,
        /// Hard expiry CMIS stamped, Unix seconds.
        not_after: i64,
    },
    /// An operator rejected a host's pending allowlist proposal (admin RPC).
    AllowlistProposalRejected {
        /// EK-derived host UUID whose pending proposal was dropped.
        host_uuid: String,
        /// Pseudonymous id (UUIDv7) of the administrator whose authenticated
        /// session made the call (F20). Absent on events written before F20.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by_admin_id: Option<String>,
    },
    /// A threshold key share was used to reconstruct the issuance key.
    KeyShareUsed {
        /// Which share (0..=4 in the 3-of-5 scheme).
        share_idx: u8,
        /// MRENCLAVE-equivalent of the consuming CMIS replica.
        mrenclave: Hash384,
    },
    /// MIA helper API granted a token to a local process.
    LocalGrant {
        /// Calling process id.
        pid: u32,
        /// Calling user id.
        uid: u32,
        /// IMA SHA-384 of the calling binary.
        bin_sha: Hash384,
        /// Token `jti` (RFC 7519, 128 bits).
        jti: Bytes16,
    },
    /// MIA helper API refused a request.
    LocalDenied {
        /// Calling process id.
        pid: u32,
        /// Calling user id.
        uid: u32,
        /// IMA SHA-384 of the calling binary.
        bin_sha: Hash384,
        /// Short, stable opcode for the refusal.
        reason: String,
    },
    /// A MIA configuration file was rewritten non-interactively by
    /// `mia setup --apply` (feature F18) — typically on behalf of the tray
    /// wizard, behind an OS consent prompt. Carries key *names* only, never
    /// values.
    ConfigChanged {
        /// The configuration file that was written.
        path: String,
        /// The invoking (pre-elevation) user id (Windows: the user RID).
        by_uid: u32,
        /// Dotted names of the keys whose value changed (e.g. `cmis.endpoint`).
        keys: Vec<String>,
    },
    // ---- Administrator authentication (F20 §10) -------------------------
    //
    // Administrators appear only as an opaque `admin_id` (UUIDv7) and a
    // `session_ref` (a short digest of the session hash, never the token).
    // Source addresses and attempted usernames are keyed HMACs under the
    // per-deployment audit pseudonymisation key. No username, display name,
    // password, TOTP code or token is ever recorded.
    /// An administrator signed in.
    AdminLoginSucceeded {
        /// Pseudonymous administrator id.
        admin_id: String,
        /// Reference to the new session.
        session_ref: String,
        /// Authenticator assurance level of the session (2 TOTP or a synced
        /// passkey, 3 a device-bound FIDO2 credential).
        aal: u8,
        /// Second-factor method used (`"totp"` or `"webauthn"`).
        mfa_method: String,
        /// Client kind (1 tui, 2 tray, 3 cli).
        client_kind: u8,
        /// Keyed HMAC of the source IP.
        src_ip_hmac: String,
    },
    /// A sign-in attempt failed. The client always sees the same generic
    /// error; the reason here is a stable opcode.
    AdminLoginFailed {
        /// Keyed HMAC of the normalised username that was attempted.
        account_ref_hmac: String,
        /// `invalid_credentials`, `disabled`, `nonce`, or
        /// `method_not_allowed` (a second factor the F20 §5 policy refuses
        /// for this client, e.g. TOTP from the tray for a FIDO2-bound group).
        reason: String,
        /// Keyed HMAC of the source IP.
        src_ip_hmac: String,
        /// Lock applied by this failure, in seconds (0 when none).
        lock_secs: u64,
    },
    /// A progressive login lock (NRM §5.3.5) was applied to a throttle key.
    AdminLockoutApplied {
        /// `ip`, `ip_device` or `account`.
        key_kind: String,
        /// Lock duration in seconds.
        lock_secs: u64,
    },
    /// Login failures crossed the alerting threshold (F20 §8).
    AdminLoginAnomaly {
        /// Failures recorded across all keys in the last 10 minutes.
        failures_10m: u32,
    },
    /// An administrator ended their own session.
    AdminLogout {
        /// Pseudonymous administrator id.
        admin_id: String,
        /// Reference to the ended session.
        session_ref: String,
    },
    /// A session was revoked by the server or by an administrator.
    AdminSessionRevoked {
        /// Owner of the revoked session.
        admin_id: String,
        /// Reference to the revoked session.
        session_ref: String,
        /// Administrator who revoked it, when not the server itself.
        by_admin_id: Option<String>,
        /// Stable opcode (`ip_mismatch`, `evicted`, `password_changed`, ...).
        reason: String,
    },
    /// A step-up (fresh second factor) was attempted on a session.
    AdminStepUp {
        /// Pseudonymous administrator id.
        admin_id: String,
        /// Reference to the session (before rotation).
        session_ref: String,
        /// Second-factor method used (`"totp"` or `"webauthn"`).
        mfa_method: String,
        /// Whether the step-up succeeded.
        success: bool,
    },
    /// An administrator password was changed.
    AdminPasswordChanged {
        /// Account whose password changed.
        admin_id: String,
        /// True when the account holder changed it themself.
        by_self: bool,
    },
    /// An administrator account was created (pending enrollment).
    AdminAccountCreated {
        /// New account id.
        admin_id: String,
        /// Creating administrator.
        by_admin_id: String,
        /// Group names granted at creation.
        groups: Vec<String>,
    },
    /// An administrator account was updated.
    AdminAccountUpdated {
        /// Updated account id.
        admin_id: String,
        /// Updating administrator.
        by_admin_id: String,
        /// Names of the changed fields (never their values).
        changed_fields: Vec<String>,
        /// The new group set, when it changed.
        groups: Option<Vec<String>>,
    },
    /// An administrator account changed state.
    AdminAccountStateChanged {
        /// Account id.
        admin_id: String,
        /// Administrator who changed it.
        by_admin_id: String,
        /// `active` or `disabled`.
        state: String,
    },
    /// An administrator's credentials were reset and a reset token issued.
    AdminCredentialsReset {
        /// Account id.
        admin_id: String,
        /// Administrator who reset them.
        by_admin_id: String,
        /// Whether the password was cleared.
        password: bool,
        /// Whether the second factor was cleared.
        mfa: bool,
    },
    /// An enrollment or reset token was redeemed.
    AdminEnrollmentCompleted {
        /// Account id.
        admin_id: String,
        /// `enroll` or `reset`.
        purpose: String,
        /// True when the redeeming IP matches an active session of the
        /// account's creator (F20 §9 residual-risk flag).
        same_ip_as_creator: bool,
    },
    /// An administrator added a second factor to their own account from a
    /// signed-in session (F20 §5 enrollment, item 2).
    AdminMfaEnrolled {
        /// Account that gained the factor.
        admin_id: String,
        /// `totp` or `webauthn`.
        method: String,
    },
    /// A second factor was removed from an account.
    AdminMfaRemoved {
        /// Account that lost the factor.
        admin_id: String,
        /// `totp` or `webauthn`.
        method: String,
        /// Administrator who removed it, when not the account holder.
        by_admin_id: Option<String>,
    },
    /// A FIDO2 assertion carried a valid signature but a signature counter
    /// that did not advance: the authenticator may have been cloned. The
    /// assertion was refused.
    AdminWebAuthnCloneDetected {
        /// Account whose credential reported the regression.
        admin_id: String,
        /// Opaque factor reference (a digest of the credential id, never the
        /// credential or its key).
        factor_id: String,
    },
    /// The first administrator account was bootstrapped.
    AdminBootstrapCompleted {
        /// The bootstrapped account id.
        admin_id: String,
    },
    /// The strict separation-of-duties policy differs from the value last
    /// recorded.
    AdminSodModeChanged {
        /// The policy now in force.
        strict: bool,
    },
    /// An admin method call was refused after authentication.
    AdminAccessDenied {
        /// Caller, when a session was established.
        admin_id: Option<String>,
        /// Full gRPC method path.
        method: String,
        /// Permission the method needs (empty when none).
        permission: String,
        /// Stable opcode (`permission_denied`, `method_not_classified`, ...).
        reason: String,
    },
    /// An admin method call passed authentication and authorization and was
    /// handed to its handler. Mutations additionally record their own event.
    AdminCallAuthorized {
        /// Caller.
        admin_id: String,
        /// Reference to the caller's session.
        session_ref: String,
        /// Full gRPC method path.
        method: String,
    },
    // ---- Application registration and approval (F19 §9) -----------------
    //
    // Requests, approvals and lineages appear as their UUID bytes, binaries
    // as their SHA-384, paths only as the host-salted `path_hash`. User
    // names, SIDs, plaintext paths and free-text messages are never recorded
    // (F19 §10); `uid` is the numeric Unix uid (or Windows RID) only.
    // Enumerations carry the ledger's integer codes (F19 §2).
    /// A host submitted an application request that was recorded.
    AppRequestSubmitted {
        /// Request id.
        request_id: Bytes16,
        /// Requesting host.
        host_uuid: String,
        /// Lineage (host + path) of the binary.
        lineage_id: Bytes16,
        /// SHA-384 of the binary.
        bin_sha: Hash384,
        /// Sequential version of the binary in its lineage.
        revision: u32,
        /// 1 register, 2 update (classified by CMIS).
        kind: u8,
        /// 1 self, 2 assisted, 3 admin_direct, 4 observed.
        origin: u8,
        /// Target Unix uid or Windows RID, when the request names one.
        uid: Option<u32>,
        /// `ferro_svid::allowlist_v2::path_hash` of the canonical path.
        path_hash: Bytes32,
        /// Risk-flag bitmask (F19 §4.5).
        flags: u32,
    },
    /// A request was approved by the auto-update policy of a parent approval.
    AppRequestAutoApproved {
        /// Request id.
        request_id: Bytes16,
        /// The new approval.
        approval_id: Bytes16,
        /// The approval whose policy approved it.
        parent_approval_id: Bytes16,
        /// Lineage.
        lineage_id: Bytes16,
        /// SHA-384 of the approved binary.
        bin_sha: Hash384,
        /// What anchored continuity: `protected_path`, `same_signer` or
        /// `path_user_only`.
        continuity_basis: String,
    },
    /// An administrator approved another person's request.
    AppRequestApproved {
        /// Request id.
        request_id: Bytes16,
        /// The approval created or reused.
        approval_id: Bytes16,
        /// Approving administrator.
        admin_id: String,
        /// Reference to the approver's session.
        session_ref: String,
        /// 1 manual_each_time, 2 auto_same_path_user.
        update_policy: u8,
        /// 1 exact_user, 2 any_user.
        user_scope: u8,
        /// 1 exact, 2 any.
        path_match: u8,
        /// Unix seconds; `None` for no expiry.
        expires_at: Option<i64>,
    },
    /// An administrator denied a request.
    AppRequestDenied {
        /// Request id.
        request_id: Bytes16,
        /// Denying administrator.
        admin_id: String,
        /// Reference to the session.
        session_ref: String,
        /// Reason code (the message shown to the requester is not recorded).
        reason_code: u32,
    },
    /// A pending request passed its time-to-live (sweeper).
    AppRequestExpired {
        /// Request id.
        request_id: Bytes16,
    },
    /// An administrator edited or renewed an approval.
    ApprovalUpdated {
        /// Approval id.
        approval_id: Bytes16,
        /// Editing administrator.
        admin_id: String,
        /// Reference to the session.
        session_ref: String,
        /// `row_version` after the edit.
        row_version: u64,
        /// Names of the changed fields (`expires_at`, `update_policy`, …).
        changed_fields: Vec<String>,
        /// Expiry before the edit.
        old_expires_at: Option<i64>,
        /// Expiry after the edit.
        new_expires_at: Option<i64>,
        /// Update policy before the edit.
        old_policy: u8,
        /// Update policy after the edit.
        new_policy: u8,
    },
    /// An administrator revoked ("deleted") an approval; the record is kept.
    ApprovalRevoked {
        /// Approval id.
        approval_id: Bytes16,
        /// Revoking administrator.
        admin_id: String,
        /// Reference to the session.
        session_ref: String,
        /// Reason code.
        reason_code: u32,
    },
    /// An approval passed its expiry (sweeper).
    ApprovalExpired {
        /// Approval id.
        approval_id: Bytes16,
    },
    /// An administrator froze or unfroze auto-update for a lineage.
    LineageAutoUpdateFrozen {
        /// Lineage id.
        lineage_id: Bytes16,
        /// Administrator.
        admin_id: String,
        /// The new value.
        frozen: bool,
    },
    /// The requester and the approver of an approval were the same
    /// administrator: every single-step direct registration, and a
    /// self-approval while the strict separation-of-duties policy is off.
    AppApprovedBySameActor {
        /// Request id.
        request_id: Bytes16,
        /// The approval.
        approval_id: Bytes16,
        /// The administrator (requester and approver).
        admin_id: String,
        /// Reference to the session.
        session_ref: String,
        /// Request origin (3 admin_direct).
        origin: u8,
        /// Second-factor method of the per-operation proof (`totp`,
        /// `webauthn`).
        mfa_method: String,
        /// 1 manual_each_time, 2 auto_same_path_user.
        update_policy: u8,
        /// 1 exact_user, 2 any_user.
        user_scope: u8,
        /// 1 exact, 2 any.
        path_match: u8,
        /// Unix seconds; `None` for no expiry.
        expires_at: Option<i64>,
    },
    /// Strict separation of duties: an administrator's direct registration
    /// was queued as a pending request for a different approver.
    AdminDirectRegistration {
        /// Request id.
        request_id: Bytes16,
        /// Requesting administrator.
        admin_id: String,
    },
    /// A host's compiled allowlist entry set changed (logged once per change,
    /// at the first compile after it).
    AllowlistCompiled {
        /// Host.
        host_uuid: String,
        /// Generation the entry set was compiled at.
        generation: u64,
        /// Number of entries.
        entry_count: u32,
        /// SHA-384 of the canonical CBOR entries.
        entries_digest: Hash384,
    },
    /// MIA verified and applied a synced allowlist v2 (forwarded by the host).
    AllowlistSyncApplied {
        /// The forwarding host (must be the authenticated host).
        host_uuid: String,
        /// Generation applied.
        generation: u64,
    },
    /// MIA refused a synced allowlist v2 and kept its current one (forwarded
    /// by the host).
    AllowlistSyncRejected {
        /// The forwarding host (must be the authenticated host).
        host_uuid: String,
        /// Generation of the refused body (0 when it did not parse).
        generation: u64,
        /// Stable opcode (`rollback`, `wrong_host`, `generation_conflict`,
        /// `bad_signature`, …).
        reason: String,
    },
    /// An administrator imported a host's legacy v1 allowlist as
    /// `legacy_import` approvals (F19 §11 step 4). One event per host that
    /// gained at least one approval; a dry run or a re-run that creates
    /// nothing records none.
    AllowlistImported {
        /// The host whose legacy allowlist was imported.
        host_uuid: String,
        /// Approvals created by this import.
        approvals_created: u32,
        /// Importing administrator.
        admin_id: String,
    },
    /// An administrator switched the replicated allowlist mode (F19 §11
    /// steps 5 and 6). Switching to the mode already in force changes
    /// nothing and records no event.
    AllowlistModeChanged {
        /// The mode before the switch (`legacy` or `approvals`).
        old_mode: String,
        /// The mode now in force.
        new_mode: String,
        /// Administrator.
        admin_id: String,
        /// Reference to the session.
        session_ref: String,
        /// Switching to `legacy`: live approvals the preserved legacy bodies
        /// do not carry (they stop admitting callers).
        approvals_not_reflected: u64,
        /// Switching to `legacy`: legacy imports revoked or expired since the
        /// import that the legacy bodies admit again.
        imports_readmitted: u64,
        /// Switching to `approvals`: legacy entries not imported (only when
        /// the administrator explicitly allowed it).
        entries_not_imported: u64,
    },
}

/// Failure modes for event codec.
#[derive(Debug, thiserror::Error)]
pub enum EventCodecError {
    /// CBOR encoding failed.
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding failed.
    #[error("cbor decode: {0}")]
    Decode(String),
}

/// Encode an event to canonical CBOR bytes.
pub fn encode(event: &AuditEvent) -> Result<Vec<u8>, EventCodecError> {
    let mut out = Vec::with_capacity(128);
    ciborium::into_writer(event, &mut out).map_err(|e| EventCodecError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode an event from CBOR bytes.
pub fn decode(bytes: &[u8]) -> Result<AuditEvent, EventCodecError> {
    ciborium::from_reader(bytes).map_err(|e| EventCodecError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditEvent {
        AuditEvent::SvidIssued {
            cert_sha: Hash384([0xAB; 48]),
            spiffe_id: "spiffe://ferrogate.test/host/abc".to_string(),
        }
    }

    #[test]
    fn cbor_roundtrip_preserves_event() {
        let e = sample();
        let bytes = encode(&e).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn encoding_is_deterministic() {
        let e = sample();
        let a = encode(&e).unwrap();
        let b = encode(&e).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_variants_have_different_encodings() {
        let a = encode(&AuditEvent::AttestFail {
            reason: "rim".into(),
        })
        .unwrap();
        let b = encode(&AuditEvent::SvidRevoked {
            cert_sha: Hash384([0u8; 48]),
            reason: "rim".into(),
            by_admin_id: None,
        })
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(&[0xFF, 0xFF, 0xFF]).is_err());
    }

    /// Attributing a legacy admin mutation to an administrator must not change
    /// the encoding of an unattributed event, so leaf hashes of events written
    /// before F20 stay reproducible.
    #[test]
    fn unattributed_legacy_event_encodes_as_before_f20() {
        // A pre-F20 encoder produced exactly the tag plus `host_uuid`.
        #[derive(serde::Serialize)]
        #[serde(tag = "type")]
        enum Old {
            AllowlistDeleted { host_uuid: String },
        }
        let e = AuditEvent::AllowlistDeleted {
            host_uuid: "h".into(),
            by_admin_id: None,
        };
        let bytes = encode(&e).unwrap();
        let mut old = Vec::new();
        ciborium::into_writer(
            &Old::AllowlistDeleted {
                host_uuid: "h".into(),
            },
            &mut old,
        )
        .unwrap();
        assert_eq!(bytes, old);
        assert_eq!(decode(&old).unwrap(), e);
    }

    #[test]
    fn admin_events_round_trip() {
        let events = vec![
            AuditEvent::AdminLoginSucceeded {
                admin_id: "0190".into(),
                session_ref: "ab".into(),
                aal: 2,
                mfa_method: "totp".into(),
                client_kind: 3,
                src_ip_hmac: "cd".into(),
            },
            AuditEvent::AdminAccessDenied {
                admin_id: None,
                method: "/ferrogate.v1.MachineIdentity/SetAllowlist".into(),
                permission: "legacy.allowlist.write".into(),
                reason: "permission_denied".into(),
            },
            AuditEvent::AllowlistSet {
                host_uuid: "h".into(),
                entry_count: 1,
                not_after: 2,
                by_admin_id: Some("0190".into()),
            },
            AuditEvent::AdminMfaEnrolled {
                admin_id: "0190".into(),
                method: "webauthn".into(),
            },
            AuditEvent::AdminMfaRemoved {
                admin_id: "0190".into(),
                method: "totp".into(),
                by_admin_id: None,
            },
            AuditEvent::AdminWebAuthnCloneDetected {
                admin_id: "0190".into(),
                factor_id: "wa_00".into(),
            },
            AuditEvent::AppRequestSubmitted {
                request_id: Bytes16([1; 16]),
                host_uuid: "h".into(),
                lineage_id: Bytes16([2; 16]),
                bin_sha: Hash384([3; 48]),
                revision: 2,
                kind: 2,
                origin: 1,
                uid: Some(1000),
                path_hash: Bytes32([4; 32]),
                flags: 1,
            },
            AuditEvent::AppApprovedBySameActor {
                request_id: Bytes16([1; 16]),
                approval_id: Bytes16([5; 16]),
                admin_id: "0190".into(),
                session_ref: "ab".into(),
                origin: 3,
                mfa_method: "totp".into(),
                update_policy: 1,
                user_scope: 1,
                path_match: 1,
                expires_at: Some(9),
            },
            AuditEvent::AllowlistCompiled {
                host_uuid: "h".into(),
                generation: 7,
                entry_count: 1,
                entries_digest: Hash384([6; 48]),
            },
            AuditEvent::AllowlistImported {
                host_uuid: "h".into(),
                approvals_created: 3,
                admin_id: "0190".into(),
            },
            AuditEvent::AllowlistModeChanged {
                old_mode: "approvals".into(),
                new_mode: "legacy".into(),
                admin_id: "0190".into(),
                session_ref: "ab".into(),
                approvals_not_reflected: 2,
                imports_readmitted: 1,
                entries_not_imported: 0,
            },
        ];
        for e in events {
            assert_eq!(decode(&encode(&e).unwrap()).unwrap(), e);
        }
    }
}
