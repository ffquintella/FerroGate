//! Request intake (F19 §5.1–§5.3): `SubmitAppRequest`, and the preparation
//! shared with `AdminRegisterApplication`.
//!
//! Order of a host submission, after the host proof ([`crate::host_auth`]):
//!
//! 1. validate the document and derive the lineage key (`path_key`) and the
//!    dedup key — nothing is written for an invalid request;
//! 2. idempotency: a `client_request_id` seen before returns the stored
//!    outcome, before any budget is spent;
//! 3. the per-host submission budget (`RESOURCE_EXHAUSTED rate_limited`);
//! 4. deduplication **before any write**: an active approval that already
//!    covers the binary and user (`APPROVED`, no request row), or an open
//!    request with the same dedup key;
//! 5. record the lineage and the binary's revision;
//! 6. the CMIS-set risk flags (signer change, version collision or downgrade,
//!    hash previously revoked or denied, software host tier);
//! 7. the auto-update policy (§5.3): the configuration gates (#1) here, the
//!    ledger conditions (#2–#7) inside the transaction that writes;
//! 8. otherwise the pending caps (`RESOURCE_EXHAUSTED too_many_pending`) and
//!    a `PENDING` request carrying the first failed condition.
//!
//! Nothing here updates or removes an approval (ADR-0004 INV-1); the ledger
//! enforces that again in SQL.

use ferro_appid::version::clean;
use ferro_appid::{Platform, RiskFlags};
use ferro_proto::v1::{AppRequestState, SubmitAppRequestResponse};
use ferro_raft::apps::{
    dedup_key, AutoChecks, AutoDowngradeReason, AutoIntake, BinaryRow, Intake, IntakeChecks,
    LedgerError, LineageRow, NewRequest, ObservedBinary, RequestOrigin, RequestRow, RequestState,
    UserIdentity, UserKind,
};
use ferro_raft::Cluster;
use ferro_svid::app_docs::{AppRequestDoc, HOST_SETTABLE_FLAGS};
use tonic::Status;

use super::{events, ledger_status, new_id, now_millis, AppConfig};
use crate::host_auth::{exhausted, invalid_field, AuthenticatedHost, TIER_HOST_KEY};
use crate::service::audit_record;
use crate::state::CmisState;

/// Seconds a host is told to wait after hitting a pending cap.
const PENDING_CAP_RETRY_SECS: u64 = 3600;

/// The binary of a submission, as the host (or the admin client) identified
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFacts {
    /// 1 linux, 2 macos, 3 windows.
    pub platform: u8,
    /// Canonical path (personal data under a home directory).
    pub canonical_path: String,
    /// SHA-384 of the file.
    pub sha384: [u8; 48],
    /// File size in bytes.
    pub size: u64,
    /// 1 elf, 2 macho, 3 pe, 9 other.
    pub format: u8,
    /// Declared version (display only).
    pub declared_version: Option<String>,
    /// Version source code (0–7).
    pub version_source: u8,
    /// Product name (display only).
    pub product_name: Option<String>,
    /// macOS bundle id (display only).
    pub bundle_id: Option<String>,
    /// dpkg package name (display only).
    pub package_name: Option<String>,
    /// 0 none, 1 authenticode, 2 apple.
    pub signer_kind: u8,
    /// Leaf certificate SHA-256 hex or Apple Team ID (continuity input).
    pub signer_id: Option<String>,
    /// Signer subject (display).
    pub signer_subject: Option<String>,
    /// Whether the signature verified on the host.
    pub signer_valid: bool,
    /// Risk flags as submitted; only [`HOST_SETTABLE_FLAGS`] are kept.
    pub flags: u32,
}

/// A request in neutral form: from a host document or from an
/// administrator's direct registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// Host the binary is on.
    pub host_uuid: String,
    /// Idempotency key (UUID text, `adm:`-prefixed for administrators).
    pub client_request_id: String,
    /// Who asked.
    pub origin: RequestOrigin,
    /// The user the request is for.
    pub target: UserIdentity,
    /// Who invoked the request on the host.
    pub requester_uid: Option<i64>,
    /// Requester user name (personal data).
    pub requester_user_name: Option<String>,
    /// Requesting administrator (`AdminDirect` only).
    pub requested_by_admin_id: Option<String>,
    /// Requester's note.
    pub reason: Option<String>,
    /// Attestation tier of the host.
    pub host_tier: String,
    /// SPIFFE id of the host the request is about.
    pub proposer_spiffe_id: String,
    /// The binary.
    pub binary: BinaryFacts,
}

fn opt(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// A display-only string from a host: control and invisible characters
/// removed (the same cleaning `ferro-appid` applies on the host), bounded.
fn display(s: Option<String>, max: usize) -> Option<String> {
    s.and_then(|v| clean(&v, max))
}

impl Submission {
    /// The submission a host's authenticated `AppRequestDoc` describes. The
    /// document was decoded and validated by `ferro_svid::app_docs`; the
    /// host identity and tier come from its SVID, never from the document.
    #[must_use]
    pub fn from_doc(doc: AppRequestDoc, host: &AuthenticatedHost) -> Self {
        let t = doc.target_user;
        let target = match t.kind {
            2 => UserIdentity {
                kind: UserKind::Windows,
                uid: t.uid.map(i64::from),
                sid: t.sid.map(|s| s.to_ascii_uppercase()),
                user_name: opt(t.name),
            },
            _ => UserIdentity {
                kind: UserKind::Unix,
                uid: t.uid.map(i64::from),
                sid: None,
                user_name: opt(t.name),
            },
        };
        let b = doc.binary;
        let (signer_kind, signer_id, signer_subject, signer_valid) = match b.signer {
            Some(s) => (s.kind, opt(s.id), opt(s.subject), s.valid),
            None => (0, None, None, false),
        };
        Self {
            host_uuid: host.host_uuid.clone(),
            client_request_id: uuid::Uuid::from_bytes(doc.client_request_id).to_string(),
            // `ferro_svid::app_docs` admits only 1, 2 and 4 here.
            origin: RequestOrigin::from_code(i64::from(doc.origin))
                .unwrap_or(RequestOrigin::Observed),
            target,
            requester_uid: Some(i64::from(doc.requested_by.uid)),
            requester_user_name: opt(doc.requested_by.name),
            requested_by_admin_id: None,
            reason: doc.reason.filter(|r| !r.is_empty()),
            host_tier: host.tier.to_string(),
            proposer_spiffe_id: host.spiffe_id.clone(),
            binary: BinaryFacts {
                platform: b.platform,
                canonical_path: b.canonical_path,
                sha384: b.sha384,
                size: b.size,
                format: b.format,
                declared_version: b.declared_version,
                version_source: b.version_source,
                product_name: b.product_name,
                bundle_id: b.bundle_id,
                package_name: b.package_name,
                signer_kind,
                signer_id,
                signer_subject,
                signer_valid,
                flags: b.flags,
            },
        }
    }
}

/// A validated submission keyed for the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The submission.
    pub submission: Submission,
    /// `ferro_appid::path_key` of the canonical path.
    pub path_key: Vec<u8>,
    /// Lowercase hex SHA-384.
    pub bin_sha: String,
    /// The F19 §5.2 dedup key.
    pub dedup_key: Vec<u8>,
}

/// Validate the parts the document codec cannot (the path for its
/// platform, the user identity) and derive the lineage and dedup keys.
pub fn prepare(mut s: Submission) -> Result<Prepared, Status> {
    let platform = Platform::from_code(s.binary.platform)
        .ok_or_else(|| invalid_field("bad_value", Some("binary.platform")))?;
    let path_key = ferro_appid::path_key(platform, &s.binary.canonical_path)
        .map_err(|e| invalid_field(e.reason(), Some("binary.canonical_path")))?;
    match s.target.kind {
        UserKind::Unix if s.target.uid.is_none() => {
            return Err(invalid_field("missing", Some("target_user.uid")));
        }
        UserKind::Windows if s.target.sid.as_deref().is_none_or(str::is_empty) => {
            return Err(invalid_field("missing", Some("target_user.sid")));
        }
        _ => {}
    }
    // The requester's note is shown to approvers: no control characters.
    s.reason = display(s.reason.take(), 200);
    let b = &mut s.binary;
    b.declared_version = display(b.declared_version.take(), 64);
    b.product_name = display(b.product_name.take(), 128);
    b.bundle_id = display(b.bundle_id.take(), 255);
    b.package_name = display(b.package_name.take(), 128);
    b.signer_subject = display(b.signer_subject.take(), 256);
    b.flags &= HOST_SETTABLE_FLAGS;
    let bin_sha = hex::encode(s.binary.sha384);
    let dedup_key = dedup_key(&s.host_uuid, &path_key, &s.target, &bin_sha);
    Ok(Prepared {
        submission: s,
        path_key,
        bin_sha,
        dedup_key,
    })
}

/// Record the lineage of the prepared binary and its revision.
pub async fn observe(
    cluster: &Cluster,
    p: &Prepared,
    now: i64,
) -> Result<(LineageRow, BinaryRow), Status> {
    let s = &p.submission;
    let b = &s.binary;
    let observed = ObservedBinary {
        host_uuid: s.host_uuid.clone(),
        platform: i64::from(b.platform),
        canonical_path: b.canonical_path.clone(),
        path_key: p.path_key.clone(),
        new_lineage_id: new_id(),
        bin_sha: p.bin_sha.clone(),
        file_size: i64::try_from(b.size)
            .map_err(|_| invalid_field("bad_value", Some("binary.size")))?,
        format: i64::from(b.format),
        declared_version: b.declared_version.clone(),
        version_source: i64::from(b.version_source),
        product_name: b.product_name.clone(),
        bundle_id: b.bundle_id.clone(),
        package_name: b.package_name.clone(),
        signer_kind: i64::from(b.signer_kind),
        signer_id: b.signer_id.clone(),
        signer_subject: b.signer_subject.clone(),
        signer_valid: b.signer_valid,
        seen_at: now,
    };
    cluster
        .app_observe_binary(&observed)
        .await
        .map_err(ledger_status)
}

/// Dotted numeric version (`1.2.10`), or `None` when it is not one.
fn dotted(v: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = v.split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|p| !p.is_empty())
}

/// `a < b` for dotted versions, missing components counting as 0.
fn lower(a: &[u64], b: &[u64]) -> bool {
    let n = a.len().max(b.len());
    let at = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
    for i in 0..n {
        match at(a, i).cmp(&at(b, i)) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

/// The risk flags CMIS sets itself (F19 §4.5 bits 7–11 and 14), from the
/// lineage history. Hosts cannot set these bits.
pub async fn cmis_flags(
    cluster: &Cluster,
    binary: &BinaryRow,
    host_tier: &str,
) -> Result<u32, LedgerError> {
    let mut flags = 0;
    if host_tier == TIER_HOST_KEY {
        flags |= RiskFlags::HOST_TIER_B;
    }
    let history = cluster
        .app_hash_history(&binary.lineage_id, &binary.bin_sha)
        .await?;
    if history.revoked {
        flags |= RiskFlags::HASH_PREVIOUSLY_REVOKED;
    }
    if history.denied {
        flags |= RiskFlags::HASH_PREVIOUSLY_DENIED;
    }
    let binaries = cluster.app_binaries_of(&binary.lineage_id).await?;
    if binary.declared_version.is_some()
        && binaries
            .iter()
            .any(|b| b.bin_sha != binary.bin_sha && b.declared_version == binary.declared_version)
    {
        flags |= RiskFlags::VERSION_COLLISION;
    }
    // The newest approved revision of the lineage other than this binary.
    let approvals = cluster.app_approvals_of_lineage(&binary.lineage_id).await?;
    let newest = approvals
        .iter()
        .filter(|a| a.bin_sha != binary.bin_sha)
        .filter_map(|a| a.revision.map(|r| (r, a.bin_sha.as_str())))
        .max_by_key(|(r, _)| *r);
    if let Some(parent) = newest.and_then(|(_, sha)| binaries.iter().find(|b| b.bin_sha == sha)) {
        let signed = parent.signer_kind != 0 || binary.signer_kind != 0;
        if signed
            && (parent.signer_kind, parent.signer_id.as_deref())
                != (binary.signer_kind, binary.signer_id.as_deref())
        {
            flags |= RiskFlags::SIGNER_CHANGED;
        }
        if let (Some(new), Some(old)) = (
            binary.declared_version.as_deref().and_then(dotted),
            parent.declared_version.as_deref().and_then(dotted),
        ) {
            if lower(&new, &old) {
                flags |= RiskFlags::VERSION_DOWNGRADE;
            }
        }
    }
    Ok(flags)
}

/// The ledger request for a prepared, observed submission.
#[must_use]
pub fn new_request(
    p: &Prepared,
    binary: &BinaryRow,
    cmis_flags: u32,
    cfg: &AppConfig,
    now: i64,
) -> NewRequest {
    let s = &p.submission;
    NewRequest {
        request_id: new_id(),
        host_uuid: s.host_uuid.clone(),
        client_request_id: s.client_request_id.clone(),
        lineage_id: binary.lineage_id.clone(),
        bin_sha: p.bin_sha.clone(),
        revision: binary.revision,
        origin: s.origin,
        target: s.target.clone(),
        requester_uid: s.requester_uid,
        requester_user_name: s.requester_user_name.clone(),
        requested_by_admin_id: s.requested_by_admin_id.clone(),
        reason: s.reason.clone(),
        flags: s.binary.flags | cmis_flags,
        host_tier: s.host_tier.clone(),
        proposer_spiffe_id: s.proposer_spiffe_id.clone(),
        dedup_key: p.dedup_key.clone(),
        submitted_at: now,
        pending_expires_at: now.saturating_add(cfg.pending_ttl_secs),
        auto_downgrade_reason: None,
    }
}

/// Start of the denial cool-down window at `now`, if the cool-down is on.
#[must_use]
pub fn cooldown_since(cfg: &AppConfig, now: i64) -> Option<i64> {
    (cfg.denied_cooldown_secs > 0).then(|| now - cfg.denied_cooldown_secs)
}

/// The wire form of a request state.
#[must_use]
pub fn wire_state(s: RequestState) -> AppRequestState {
    match s {
        RequestState::Pending => AppRequestState::Pending,
        RequestState::Approved => AppRequestState::Approved,
        RequestState::AutoApproved => AppRequestState::AutoApproved,
        RequestState::Denied => AppRequestState::Denied,
        RequestState::Expired => AppRequestState::Expired,
    }
}

async fn generation(cluster: &Cluster, host_uuid: &str) -> Result<u64, Status> {
    Ok(cluster
        .app_allowlist_state(host_uuid)
        .await
        .map_err(ledger_status)?
        .map_or(0, |s| s.generation))
}

/// The answer for an existing request row (a retry, a duplicate, a recent
/// denial, or a freshly recorded one).
async fn row_answer(
    cluster: &Cluster,
    cfg: &AppConfig,
    row: &RequestRow,
    deduplicated: bool,
    now: i64,
) -> Result<SubmitAppRequestResponse, Status> {
    let approved = matches!(
        row.state,
        RequestState::Approved | RequestState::AutoApproved
    );
    let denied = row.state == RequestState::Denied;
    let retry_after_secs = match (denied, row.decided_at) {
        (true, Some(at)) if cfg.denied_cooldown_secs > 0 => {
            (at + cfg.denied_cooldown_secs - now).max(0)
        }
        _ => 0,
    };
    Ok(SubmitAppRequestResponse {
        request_id: row.request_id.clone(),
        state: wire_state(row.state).into(),
        approval_id: row.resulting_approval_id.clone().unwrap_or_default(),
        revision: u32::try_from(row.revision).unwrap_or(0),
        deduplicated,
        allowlist_generation: if approved {
            generation(cluster, &row.host_uuid).await?
        } else {
            0
        },
        auto_downgrade_reason: row
            .auto_downgrade_reason
            .map(|r| r.as_str().to_string())
            .unwrap_or_default(),
        deny_reason_code: if denied {
            u32::try_from(row.decision_reason_code.unwrap_or_default()).unwrap_or(0)
        } else {
            0
        },
        deny_message: if denied {
            row.decision_message.clone().unwrap_or_default()
        } else {
            String::new()
        },
        retry_after_secs,
    })
}

/// The answer when an active approval already covers the submission.
async fn covered_answer(
    cluster: &Cluster,
    host_uuid: &str,
    approval_id: &str,
    revision: i64,
) -> Result<SubmitAppRequestResponse, Status> {
    Ok(SubmitAppRequestResponse {
        request_id: String::new(),
        state: AppRequestState::Approved.into(),
        approval_id: approval_id.to_string(),
        revision: u32::try_from(revision).unwrap_or(0),
        deduplicated: true,
        allowlist_generation: generation(cluster, host_uuid).await?,
        ..SubmitAppRequestResponse::default()
    })
}

/// The answer for a deduplicated intake outcome (nothing was written).
async fn intake_answer(
    cluster: &Cluster,
    cfg: &AppConfig,
    intake: Intake,
    revision: i64,
    now: i64,
) -> Result<SubmitAppRequestResponse, Status> {
    match intake {
        Intake::Recorded(row) => row_answer(cluster, cfg, &row, false, now).await,
        Intake::Replayed(row) | Intake::DuplicatePending(row) | Intake::RecentlyDenied(row) => {
            row_answer(cluster, cfg, &row, true, now).await
        }
        Intake::Covered(a) => covered_answer(cluster, &a.host_uuid, &a.approval_id, revision).await,
    }
}

/// `SubmitAppRequest` for an authenticated host (see the module docs for
/// the order of checks). Store failures answer `UNAVAILABLE` and record no
/// audit event.
#[allow(clippy::too_many_lines)] // the one ordered intake sequence of F19 §5.1.
pub async fn submit(
    state: &CmisState,
    host: &AuthenticatedHost,
    doc: AppRequestDoc,
    now: i64,
) -> Result<SubmitAppRequestResponse, Status> {
    let cluster = state.cluster();
    let cfg = &state.config.apps;
    let p = prepare(Submission::from_doc(doc, host))?;
    let s = &p.submission;

    // 2. Idempotency: a retry returns the stored outcome, free of charge.
    if let Some(row) = cluster
        .app_request_by_client_id(&s.host_uuid, &s.client_request_id)
        .await
        .map_err(ledger_status)?
    {
        return row_answer(cluster, cfg, &row, true, now).await;
    }

    // 3. Per-host submission budget.
    if let Err(wait) = state
        .host_calls
        .app_submit_limiter()
        .check(&host.host_uuid, now)
    {
        tracing::warn!(event = "apps.submit.rate_limited", host_uuid = %host.host_uuid, retry_after = wait, "app submissions over budget");
        return Err(exhausted("rate_limited", wait));
    }

    // 4. Deduplicate before writing anything.
    if let Some(lineage) = cluster
        .app_lineage_by_path(&s.host_uuid, &p.path_key)
        .await
        .map_err(ledger_status)?
    {
        if let Some(a) = cluster
            .app_covering_approval(
                &s.host_uuid,
                &lineage.lineage_id,
                &p.bin_sha,
                &s.target,
                now,
            )
            .await
            .map_err(ledger_status)?
        {
            let revision = cluster
                .app_binary(&lineage.lineage_id, &p.bin_sha)
                .await
                .map_err(ledger_status)?
                .map_or(0, |b| b.revision);
            return covered_answer(cluster, &s.host_uuid, &a.approval_id, revision).await;
        }
    }
    if let Some(row) = cluster
        .app_pending_by_dedup(&p.dedup_key)
        .await
        .map_err(ledger_status)?
    {
        return row_answer(cluster, cfg, &row, true, now).await;
    }

    // 5–6. Lineage, revision, CMIS-set flags.
    let (_lineage, binary) = observe(cluster, &p, now).await?;
    let flags = cmis_flags(cluster, &binary, &s.host_tier)
        .await
        .map_err(ledger_status)?;
    let mut req = new_request(&p, &binary, flags, cfg, now);
    let cooldown = cooldown_since(cfg, now);

    // 7. Auto-update policy (§5.3): configuration first, then the ledger.
    let reason = if !cfg.auto_update {
        AutoDowngradeReason::AutoDisabled
    } else if !cfg.tier_allowed(host.tier) {
        AutoDowngradeReason::TierNotAllowed
    } else {
        let checks = AutoChecks {
            now,
            denied_cooldown_since: cooldown,
            max_per_day: cfg.auto_update_max_per_day,
            generation_millis: now_millis(now),
        };
        match cluster
            .app_try_auto_approve(&req, &new_id(), &checks)
            .await
            .map_err(ledger_status)?
        {
            AutoIntake::AutoApproved(auto) => {
                let basis = events::continuity_basis(&auto.approval, auto.request.flags);
                audit_record(state, events::submitted(&auto.request, &p.path_key), now);
                audit_record(
                    state,
                    events::auto_approved(&auto.request, &auto.approval, basis),
                    now,
                );
                tracing::info!(
                    event = "apps.request.auto_approved",
                    request_id = %auto.request.request_id,
                    approval_id = %auto.approval.approval_id,
                    host_uuid = %host.host_uuid,
                    generation = auto.generation,
                    "app request auto-approved"
                );
                return Ok(SubmitAppRequestResponse {
                    request_id: auto.request.request_id.clone(),
                    state: AppRequestState::AutoApproved.into(),
                    approval_id: auto.approval.approval_id.clone(),
                    revision: u32::try_from(auto.request.revision).unwrap_or(0),
                    deduplicated: false,
                    allowlist_generation: auto.generation,
                    ..SubmitAppRequestResponse::default()
                });
            }
            AutoIntake::NotEligible(reason) => reason,
            AutoIntake::Deduplicated(intake) => {
                return intake_answer(cluster, cfg, *intake, binary.revision, now).await;
            }
        }
    };
    req.auto_downgrade_reason = Some(reason);

    // 8. Pending caps, then the pending request.
    let counts = cluster
        .app_pending_counts(&s.host_uuid, &s.target)
        .await
        .map_err(ledger_status)?;
    if counts.host >= cfg.max_pending_per_host || counts.user >= cfg.max_pending_per_user {
        tracing::warn!(event = "apps.submit.pending_cap", host_uuid = %host.host_uuid, "too many open requests");
        return Err(exhausted("too_many_pending", PENDING_CAP_RETRY_SECS));
    }
    let intake = cluster
        .app_submit_pending(
            &req,
            &IntakeChecks {
                now,
                denied_cooldown_since: cooldown,
            },
        )
        .await
        .map_err(ledger_status)?;
    if let Intake::Recorded(row) = &intake {
        audit_record(state, events::submitted(row, &p.path_key), now);
        tracing::info!(
            event = "apps.request.recorded",
            request_id = %row.request_id,
            host_uuid = %host.host_uuid,
            auto_downgrade_reason = reason.as_str(),
            "app request pending"
        );
    }
    intake_answer(cluster, cfg, intake, binary.revision, now).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_versions_compare_numerically() {
        let v = |s: &str| dotted(s).unwrap();
        assert!(lower(&v("1.2.9"), &v("1.2.10")));
        assert!(!lower(&v("1.2.10"), &v("1.2.9")));
        assert!(!lower(&v("1.2"), &v("1.2.0")));
        assert!(lower(&v("1.2"), &v("1.2.1")));
        assert_eq!(dotted("1.2-beta"), None);
        assert_eq!(dotted(""), None);
    }

    fn submission() -> Submission {
        Submission {
            host_uuid: "h".into(),
            client_request_id: "c".into(),
            origin: RequestOrigin::SelfRegistration,
            target: UserIdentity {
                kind: UserKind::Unix,
                uid: Some(1000),
                sid: None,
                user_name: Some("alice".into()),
            },
            requester_uid: Some(1000),
            requester_user_name: Some("alice".into()),
            requested_by_admin_id: None,
            reason: None,
            host_tier: "tpm".into(),
            proposer_spiffe_id: "spiffe://t/host/h".into(),
            binary: BinaryFacts {
                platform: 1,
                canonical_path: "/usr/bin/tool".into(),
                sha384: [0xAB; 48],
                size: 10,
                format: 1,
                declared_version: Some("1.0\u{1b}[31m".into()),
                version_source: 5,
                product_name: None,
                bundle_id: None,
                package_name: None,
                signer_kind: 0,
                signer_id: None,
                signer_subject: None,
                signer_valid: false,
                flags: u32::MAX,
            },
        }
    }

    #[test]
    fn preparation_masks_flags_cleans_display_data_and_checks_the_path() {
        let p = prepare(submission()).unwrap();
        assert_eq!(p.submission.binary.flags, HOST_SETTABLE_FLAGS);
        assert_eq!(
            p.submission.binary.declared_version.as_deref(),
            Some("1.0[31m")
        );
        assert_eq!(p.path_key, b"/usr/bin/tool");
        assert_eq!(p.bin_sha.len(), 96);

        let mut s = submission();
        s.binary.canonical_path = "relative/tool".into();
        let e = prepare(s).unwrap_err();
        assert_eq!(e.message(), "path_not_absolute");
        assert_eq!(
            e.metadata().get("x-ferrogate-field").unwrap(),
            "binary.canonical_path"
        );

        let mut s = submission();
        s.binary.canonical_path = "/usr/../etc/shadow".into();
        assert_eq!(prepare(s).unwrap_err().message(), "bad_path");

        let mut s = submission();
        s.target.uid = None;
        assert_eq!(prepare(s).unwrap_err().message(), "missing");
    }
}
