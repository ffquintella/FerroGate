//! Attested test hosts for the F19 host RPCs: a machine key, an SVID bound
//! to it, and helpers that build the signed documents exactly as MIA does.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use cmis::CmisState;
use ferro_proto::v1::{
    GetAppRequestStatusRequest, HostCallAuth, SubmitAppRequestRequest, SyncAllowlistRequest,
};
use ferro_raft::apps::{
    ApprovalChoice, ApprovalRow, ApprovalTerms, Approve, Continuity, PathMatch, UpdatePolicy,
    UserScope,
};
use ferro_sep::{MachineKey, SoftwareMachineKey};
use ferro_svid::allowlist_v2::{verify_v2, AllowlistDocV2};
use ferro_svid::app_docs::{
    encode_allowlist_sync, encode_app_request, encode_app_status, AllowlistSyncDoc, AppRequestDoc,
    AppStatusDoc, BinaryDesc, RequestedBy, TargetUser, ALLOWLIST_SYNC_CONTEXT, APP_REQUEST_CONTEXT,
    APP_STATUS_CONTEXT,
};
use ferro_svid::host_call::{signing_input, DOC_VERSION};
use ferro_svid::{host_uuid_from_ek_digest, IssueParams, Issuer};
use sha2::{Digest, Sha256};

/// Real Unix time (the host RPC handlers use the system clock).
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// One attested host.
pub struct Host {
    pub key: SoftwareMachineKey,
    pub jws: String,
    pub uuid: String,
    pub spiffe_id: String,
}

/// Mint a host with EK digest byte `ek_byte` under SVID policy `policy_id`
/// (`"host-key"` for the software tier, anything else for TPM).
pub fn mint_host(issuer: &Issuer, ek_byte: u8, policy_id: &str) -> Host {
    let key = SoftwareMachineKey::generate().unwrap();
    let jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(key.public_spki_der()));
    let ek_sha = [ek_byte; 48];
    let minted = issuer
        .issue(
            &IssueParams {
                ek_cert_sha384: ek_sha,
                pcr_digest: [0u8; 48],
                policy_id: policy_id.into(),
                dpop_jkt: jkt,
                ttl_secs: 3600,
                tee_evidence_id: None,
                subject_pub: None,
            },
            now_unix(),
        )
        .unwrap();
    Host {
        key,
        jws: minted.jws,
        uuid: host_uuid_from_ek_digest(&ek_sha).to_string(),
        spiffe_id: minted.spiffe_id,
    }
}

/// A fresh nonce (unique within the test process).
pub fn nonce() -> [u8; 16] {
    static N: AtomicU64 = AtomicU64::new(1);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&N.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    out[8..].copy_from_slice(&std::process::id().to_le_bytes().repeat(2));
    out
}

/// A distinct `client_request_id`.
pub fn client_id() -> [u8; 16] {
    let mut id = nonce();
    id[15] ^= 0x5A;
    id
}

impl Host {
    /// The proof over `doc` under `context`.
    pub fn auth(&self, context: &[u8], doc: &[u8]) -> HostCallAuth {
        HostCallAuth {
            svid_jws: self.jws.clone(),
            sep_pub: self.key.public_spki_der(),
            sig: self.key.sign(&signing_input(context, doc)).unwrap(),
        }
    }

    /// A signed `SubmitAppRequest`.
    pub fn submit(&self, doc: &AppRequestDoc) -> SubmitAppRequestRequest {
        let bytes = encode_app_request(doc).unwrap();
        SubmitAppRequestRequest {
            auth: Some(self.auth(APP_REQUEST_CONTEXT, &bytes)),
            doc: bytes,
        }
    }

    /// A signed `GetAppRequestStatus` for `ids`.
    pub fn status(&self, ids: &[[u8; 16]]) -> GetAppRequestStatusRequest {
        let doc = AppStatusDoc {
            v: DOC_VERSION,
            host_uuid: self.uuid.clone(),
            issued_at: now_unix(),
            nonce: nonce(),
            request_ids: ids.to_vec(),
        };
        let bytes = encode_app_status(&doc).unwrap();
        GetAppRequestStatusRequest {
            auth: Some(self.auth(APP_STATUS_CONTEXT, &bytes)),
            doc: bytes,
        }
    }

    /// A signed `SyncAllowlist` holding `have_generation`.
    pub fn sync(&self, have_generation: u64) -> SyncAllowlistRequest {
        let doc = AllowlistSyncDoc {
            v: DOC_VERSION,
            host_uuid: self.uuid.clone(),
            issued_at: now_unix(),
            nonce: nonce(),
            have_generation,
            accept_formats: vec![2],
        };
        let bytes = encode_allowlist_sync(&doc).unwrap();
        SyncAllowlistRequest {
            auth: Some(self.auth(ALLOWLIST_SYNC_CONTEXT, &bytes)),
            doc: bytes,
        }
    }

    /// An `AppRequestDoc` for `path`/`sha` as Unix user `uid`/`name`.
    pub fn app_doc(
        &self,
        path: &str,
        sha: [u8; 48],
        uid: u32,
        name: &str,
        flags: u32,
    ) -> AppRequestDoc {
        AppRequestDoc {
            v: DOC_VERSION,
            host_uuid: self.uuid.clone(),
            issued_at: now_unix(),
            client_request_id: client_id(),
            origin: 1,
            target_user: TargetUser {
                kind: 1,
                uid: Some(uid),
                sid: None,
                name: name.into(),
            },
            requested_by: RequestedBy {
                uid,
                name: name.into(),
            },
            reason: Some("needs a token".into()),
            binary: BinaryDesc {
                canonical_path: path.into(),
                platform: 1,
                sha384: sha,
                size: 4096,
                format: 1,
                declared_version: Some("1.0.0".into()),
                version_source: 5,
                product_name: Some("Tool".into()),
                bundle_id: None,
                package_name: None,
                signer: None,
                flags,
            },
        }
    }
}

/// Switch the cluster to `approvals` mode (the M38 switch, done directly).
pub async fn approvals_mode(state: &CmisState) {
    cmis::apps::mode::set(state.cluster(), cmis::apps::AllowlistMode::Approvals)
        .await
        .unwrap();
}

/// Verify a served v2 envelope under the issuer key and the v2 context.
pub fn open_v2(state: &CmisState, envelope: &[u8]) -> AllowlistDocV2 {
    let signed = ferro_svid::allowlist::decode(envelope).unwrap();
    verify_v2(&signed, state.issuer.public_key()).unwrap()
}

/// Approval terms: exact user and path, `policy`, `expires_at`.
pub fn terms(policy: UpdatePolicy, expires_at: Option<i64>) -> ApprovalTerms {
    ApprovalTerms {
        user_scope: UserScope::ExactUser,
        path_match: PathMatch::Exact,
        update_policy: policy,
        continuity: Continuity::Anchored,
        expires_at,
        note: None,
    }
}

/// Approve `request_id` directly in the ledger as administrator `admin`.
pub async fn ledger_approve(
    state: &CmisState,
    request_id: &str,
    admin: &str,
    terms: ApprovalTerms,
) -> ApprovalRow {
    let now = now_unix();
    state
        .cluster()
        .app_approve_request(&Approve {
            request_id: request_id.into(),
            admin_id: admin.into(),
            now,
            choice: ApprovalChoice::New {
                approval_id: uuid::Uuid::now_v7().to_string(),
                terms,
            },
            forbid_self_approval: false,
            also_revoke: vec![],
            generation_millis: now * 1000,
        })
        .await
        .unwrap()
        .approval
}
