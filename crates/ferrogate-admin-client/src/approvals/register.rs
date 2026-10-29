//! The single-step "add application" (F19 §7, F21 §6, F22 §5), shared by
//! the TUI and the tray admin client: the typed facts of a binary whose
//! hash and path the administrator already knows, their checks, the
//! `AdminRegisterApplication` request, its outcome, and the call itself.

//! The hash, the path and the "writable only by administrators" flag are
//! the **administrator's assertion**: nothing here checks them against the
//! host. The approval pins the exact hash and MIA re-hashes the binary at
//! every mint, so a wrong hash grants nothing.

//! The call always carries a **fresh** per-operation second factor (F20 §7
//! "M"): a recent step-up does not substitute, a wrong proof changes
//! nothing on the server, and a retry with the same request reuses its
//! idempotency key.

use std::time::Duration;

use ferro_appid::flags::RiskFlags;
use ferro_proto::admin_v1::{AppBinaryDesc, AppUser, ApprovalTerms};
use serde::Serialize;

pub use ferro_proto::admin_v1::{
    AdminRegisterApplicationRequest, AdminRegisterApplicationResponse,
};

use crate::client::{Admin, AdminSession, Factor};
use crate::error::ClientError;
use crate::transport::within;

use super::rules::short_id;

/// The platforms a binary is registered for, in wire order (codes 1…3,
/// which are also the binary formats elf, macho and pe).
pub const PLATFORMS: [&str; 3] = ["Linux", "macOS", "Windows"];
/// Characters of a SHA-384 in hex.
pub const SHA384_HEX: usize = 96;
/// Longest host UUID typed (8-4-4-4-12).
pub const MAX_HOST: usize = 36;
/// Longest canonical path typed.
pub const MAX_PATH: usize = 4096;
/// Longest uid (or Windows RID) typed: `4294967295`.
pub const MAX_UID: usize = 10;
/// Longest Windows SID typed.
pub const MAX_SID: usize = 184;
/// Longest operating-system user name typed.
pub const MAX_USER: usize = 256;
/// Longest declared version typed.
pub const MAX_VERSION: usize = 128;
/// Longest reason typed (the server's limit).
pub const MAX_REASON: usize = 200;

/// A typed field of the registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterField {
    /// The host UUID.
    Host,
    /// The canonical path.
    Path,
    /// The SHA-384.
    Sha,
    /// The Unix uid, or a Windows RID.
    Uid,
    /// The Windows SID.
    Sid,
    /// The user name.
    User,
    /// The declared version (optional).
    Version,
    /// The reason (optional).
    Reason,
}

impl RegisterField {
    /// Every field, in form order.
    pub const ALL: [Self; 8] = [
        Self::Host,
        Self::Path,
        Self::Sha,
        Self::Uid,
        Self::Sid,
        Self::User,
        Self::Version,
        Self::Reason,
    ];

    /// The most characters the field takes.
    #[must_use]
    pub fn max_chars(self) -> usize {
        match self {
            Self::Host => MAX_HOST,
            Self::Path => MAX_PATH,
            Self::Sha => SHA384_HEX,
            Self::Uid => MAX_UID,
            Self::Sid => MAX_SID,
            Self::User => MAX_USER,
            Self::Version => MAX_VERSION,
            Self::Reason => MAX_REASON,
        }
    }
}

/// Why a field is refused before anything is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterError {
    /// Not a host UUID (8-4-4-4-12 hex).
    HostUuid,
    /// Required.
    Required,
    /// Not exactly 96 hex characters.
    Sha384,
    /// Not a number from 0 to 4294967295.
    UidNumber,
    /// Not printable ASCII.
    SidPrintable,
    /// A Unix user needs its uid.
    UnixNeedsUid,
    /// A Windows user needs its SID (or the RID).
    WindowsNeedsSid,
    /// Longer than the field takes.
    TooLong,
}

/// What the administrator typed (untrusted until [`Registration::problems`]
/// is empty). Holds no secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registration {
    /// The host UUID.
    pub host_uuid: String,
    /// Index into [`PLATFORMS`].
    pub platform: usize,
    /// The canonical path on that host.
    pub canonical_path: String,
    /// The SHA-384, hex (any case).
    pub sha384: String,
    /// A Windows user (SID or RID) rather than a Unix uid.
    pub windows_user: bool,
    /// The Unix uid, or a Windows RID.
    pub uid: String,
    /// The Windows SID.
    pub sid: String,
    /// The user name.
    pub user_name: String,
    /// The declared version (optional).
    pub version: String,
    /// Why (optional).
    pub reason: String,
    /// "Path writable only by administrators" (the administrator's
    /// assertion).
    pub path_protected: bool,
}

impl Registration {
    /// The text of `field`.
    #[must_use]
    pub fn text(&self, field: RegisterField) -> &str {
        match field {
            RegisterField::Host => &self.host_uuid,
            RegisterField::Path => &self.canonical_path,
            RegisterField::Sha => &self.sha384,
            RegisterField::Uid => &self.uid,
            RegisterField::Sid => &self.sid,
            RegisterField::User => &self.user_name,
            RegisterField::Version => &self.version,
            RegisterField::Reason => &self.reason,
        }
    }

    /// The text of `field`, to edit.
    pub fn text_mut(&mut self, field: RegisterField) -> &mut String {
        match field {
            RegisterField::Host => &mut self.host_uuid,
            RegisterField::Path => &mut self.canonical_path,
            RegisterField::Sha => &mut self.sha384,
            RegisterField::Uid => &mut self.uid,
            RegisterField::Sid => &mut self.sid,
            RegisterField::User => &mut self.user_name,
            RegisterField::Version => &mut self.version,
            RegisterField::Reason => &mut self.reason,
        }
    }

    /// Every refused field and why, in form order (empty: it may be sent).
    /// The server checks everything again.
    #[must_use]
    pub fn problems(&self) -> Vec<(RegisterField, RegisterError)> {
        let mut out = Vec::new();
        if uuid::Uuid::parse_str(self.host_uuid.trim()).is_err() {
            out.push((RegisterField::Host, RegisterError::HostUuid));
        }
        if self.canonical_path.trim().is_empty() {
            out.push((RegisterField::Path, RegisterError::Required));
        }
        let sha = self.sha384.trim();
        if sha.len() != SHA384_HEX || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.push((RegisterField::Sha, RegisterError::Sha384));
        }
        let uid = self.uid.trim();
        if !uid.is_empty() && uid.parse::<u32>().is_err() {
            out.push((RegisterField::Uid, RegisterError::UidNumber));
        }
        let sid = self.sid.trim();
        if !sid.bytes().all(|b| b.is_ascii_graphic()) {
            out.push((RegisterField::Sid, RegisterError::SidPrintable));
        }
        if !self.windows_user && uid.is_empty() {
            out.push((RegisterField::Uid, RegisterError::UnixNeedsUid));
        }
        if self.windows_user && uid.is_empty() && sid.is_empty() {
            out.push((RegisterField::Sid, RegisterError::WindowsNeedsSid));
        }
        if self.user_name.trim().is_empty() {
            out.push((RegisterField::User, RegisterError::Required));
        }
        for field in RegisterField::ALL {
            let flagged = out.iter().any(|(f, _)| *f == field);
            if !flagged && self.text(field).chars().count() > field.max_chars() {
                out.push((field, RegisterError::TooLong));
            }
        }
        out
    }

    /// The risk flags the administrator asserts (only `path_protected`).
    #[must_use]
    pub fn flags(&self) -> u32 {
        if self.path_protected {
            RiskFlags::PATH_PROTECTED
        } else {
            0
        }
    }

    /// The platform's wire code (1 Linux, 2 macOS, 3 Windows).
    #[must_use]
    pub fn platform_code(&self) -> u32 {
        u32::try_from(self.platform.min(PLATFORMS.len() - 1) + 1).unwrap_or(1)
    }

    /// The operating-system user it is for.
    #[must_use]
    pub fn target_user(&self) -> AppUser {
        AppUser {
            kind: if self.windows_user { 2 } else { 1 },
            uid: self.uid.trim().parse::<i64>().ok(),
            sid: if self.windows_user {
                self.sid.trim().to_string()
            } else {
                String::new()
            },
            name: self.user_name.trim().to_string(),
        }
    }

    /// `AdminRegisterApplication` with these facts, `terms` and the
    /// idempotency `key`; the host UUID and the hash lowercased, every text
    /// trimmed. The proof is left out: it is added, fresh, when sent.
    #[must_use]
    pub fn request(&self, terms: ApprovalTerms, key: String) -> AdminRegisterApplicationRequest {
        let platform = self.platform_code();
        AdminRegisterApplicationRequest {
            idempotency_key: key,
            proof: None,
            host_uuid: self.host_uuid.trim().to_ascii_lowercase(),
            binary: Some(AppBinaryDesc {
                canonical_path: self.canonical_path.trim().to_string(),
                platform,
                sha384: self.sha384.trim().to_ascii_lowercase(),
                size: 0,
                // elf, macho, pe by platform.
                format: platform,
                declared_version: self.version.trim().to_string(),
                flags: self.flags(),
                ..AppBinaryDesc::default()
            }),
            target_user: Some(self.target_user()),
            reason: self.reason.trim().to_string(),
            terms: Some(terms),
        }
    }
}

/// What an `AdminRegisterApplication` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Registered {
    /// Registered and approved in one step (audited as
    /// `AppApprovedBySameActor`).
    Approved {
        /// Short id of the request (`R-…`, "—" when absent).
        request: String,
        /// Short id of the approval (`A-…`, "—" when absent).
        approval: String,
        /// The host's allowlist generation.
        generation: u64,
    },
    /// Strict separation of duties: queued for a different approver.
    Queued {
        /// Short id of the pending request.
        request: String,
    },
    /// An active approval already covers this binary; nothing was added.
    AlreadyApproved {
        /// Short id of that approval.
        approval: String,
    },
}

/// What the server answered, in short ids.
#[must_use]
pub fn outcome(r: &AdminRegisterApplicationResponse) -> Registered {
    let request = r
        .request
        .as_ref()
        .map_or_else(|| "—".to_string(), |q| short_id("R", &q.request_id));
    let approval = r
        .approval
        .as_ref()
        .map_or_else(|| "—".to_string(), |a| short_id("A", &a.approval_id));
    if r.queued {
        Registered::Queued { request }
    } else if r.deduplicated && r.request.is_none() {
        Registered::AlreadyApproved { approval }
    } else {
        Registered::Approved {
            request,
            approval,
            generation: r.allowlist_generation,
        }
    }
}

/// `AdminRegisterApplication` on `admin` within `timeout`, as `req` is
/// (with its proof).
///
/// # Errors
/// The server's status.
pub async fn send(
    admin: &mut Admin,
    timeout: Duration,
    req: AdminRegisterApplicationRequest,
) -> Result<AdminRegisterApplicationResponse, tonic::Status> {
    within(timeout, admin.admin_register_application(req))
        .await
        .map(tonic::Response::into_inner)
}

impl AdminSession {
    /// Register and approve `req` in one step (queued under strict SoD)
    /// with a fresh `proof`, a TOTP code or a key's assertion: a step-up
    /// window never replaces it; a lock during the key prompt sends nothing.
    ///
    /// # Errors
    /// [`ClientError::Rejected`] for a wrong proof (nothing changed; resend
    /// the same `req`, same key), or as [`AdminSession::step_up`].
    pub async fn register_application(
        &mut self,
        mut req: AdminRegisterApplicationRequest,
        proof: Factor,
    ) -> Result<AdminRegisterApplicationResponse, ClientError> {
        let epoch = self.require_session()?;
        let r = async {
            req.proof = Some(self.proof(epoch, proof).await?);
            self.still(epoch)?;
            let timeout = self.config().rpc_timeout;
            let mut admin = self.admin().await.map_err(ClientError::Connect)?;
            send(&mut admin, timeout, req)
                .await
                .map_err(|s| ClientError::from_credential_status(&s))
        }
        .await;
        self.finish(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use crate::secret::Secret;
    use crate::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};
    use ferro_crypto::pin::SpkiPin;
    use ferro_proto::admin_v1::{AppRequestInfo, ApprovalInfo};

    const HOST: &str = "11111111-2222-3333-4444-555555555555";

    fn unix() -> Registration {
        Registration {
            host_uuid: HOST.to_ascii_uppercase(),
            canonical_path: " /opt/tool/bin/tool ".into(),
            sha384: "AB".repeat(48),
            uid: "1000".into(),
            user_name: "alice".into(),
            ..Registration::default()
        }
    }

    #[test]
    fn the_facts_are_checked_and_named_by_field() {
        assert_eq!(unix().problems(), vec![]);
        let empty = Registration::default().problems();
        assert_eq!(
            empty,
            vec![
                (RegisterField::Host, RegisterError::HostUuid),
                (RegisterField::Path, RegisterError::Required),
                (RegisterField::Sha, RegisterError::Sha384),
                (RegisterField::Uid, RegisterError::UnixNeedsUid),
                (RegisterField::User, RegisterError::Required),
            ]
        );
        for sha in [
            "a".repeat(95),
            "a".repeat(97),
            format!("{}g", "a".repeat(95)),
        ] {
            let r = Registration {
                sha384: sha,
                ..unix()
            };
            assert_eq!(
                r.problems(),
                vec![(RegisterField::Sha, RegisterError::Sha384)]
            );
        }
        let r = Registration {
            uid: "-1".into(),
            ..unix()
        };
        assert_eq!(
            r.problems(),
            vec![(RegisterField::Uid, RegisterError::UidNumber)]
        );
        // A Windows user: a SID or the RID, printable ASCII only.
        let mut w = Registration {
            windows_user: true,
            uid: String::new(),
            ..unix()
        };
        assert_eq!(
            w.problems(),
            vec![(RegisterField::Sid, RegisterError::WindowsNeedsSid)]
        );
        w.sid = "S-1-5-21-1\u{1b}[2J".into();
        assert_eq!(
            w.problems(),
            vec![(RegisterField::Sid, RegisterError::SidPrintable)]
        );
        w.sid = "S-1-5-21-1-2-3-1001".into();
        assert_eq!(w.problems(), vec![]);
        let long = Registration {
            reason: "x".repeat(MAX_REASON + 1),
            ..unix()
        };
        assert_eq!(
            long.problems(),
            vec![(RegisterField::Reason, RegisterError::TooLong)]
        );
    }

    #[test]
    fn the_request_is_trimmed_lowercased_and_carries_no_proof() {
        let r = Registration {
            platform: 1,
            path_protected: true,
            version: " 2.1.0 ".into(),
            ..unix()
        };
        let req = r.request(ApprovalTerms::default(), "k-1".into());
        assert_eq!(req.idempotency_key, "k-1");
        assert!(req.proof.is_none(), "the proof is added fresh when sent");
        assert_eq!(req.host_uuid, HOST);
        let b = req.binary.unwrap();
        assert_eq!(b.sha384, "ab".repeat(48));
        assert_eq!(b.canonical_path, "/opt/tool/bin/tool");
        assert_eq!((b.platform, b.format), (2, 2));
        assert_eq!(b.declared_version, "2.1.0");
        assert_eq!(b.flags, RiskFlags::PATH_PROTECTED);
        let u = req.target_user.unwrap();
        assert_eq!((u.kind, u.uid, u.sid.as_str()), (1, Some(1000), ""));
        // A Windows user keeps its SID; a Unix one never sends one.
        let w = Registration {
            windows_user: true,
            sid: "S-1-5-21-1-2-3-1001".into(),
            uid: String::new(),
            sha384: "cd".repeat(48),
            platform: 9,
            ..unix()
        };
        let req = w.request(ApprovalTerms::default(), "k-2".into());
        assert_eq!(req.binary.unwrap().platform, 3, "clamped to Windows");
        let u = req.target_user.unwrap();
        assert_eq!(
            (u.kind, u.uid, u.sid.as_str()),
            (2, None, "S-1-5-21-1-2-3-1001")
        );
    }

    #[test]
    fn the_outcome_names_approved_queued_and_already_approved() {
        let request = Some(AppRequestInfo {
            request_id: "0192a9f1-0000-7000-8000-00000000a1b2".into(),
            ..AppRequestInfo::default()
        });
        let approval = Some(ApprovalInfo {
            approval_id: "0190f0aa-0000-7000-8000-00000000beef".into(),
            ..ApprovalInfo::default()
        });
        let approved = AdminRegisterApplicationResponse {
            request: request.clone(),
            approval: approval.clone(),
            allowlist_generation: 4,
            ..AdminRegisterApplicationResponse::default()
        };
        assert_eq!(
            outcome(&approved),
            Registered::Approved {
                request: "R-0000A1B2".into(),
                approval: "A-0000BEEF".into(),
                generation: 4
            }
        );
        let queued = AdminRegisterApplicationResponse {
            request,
            queued: true,
            ..AdminRegisterApplicationResponse::default()
        };
        assert_eq!(
            outcome(&queued),
            Registered::Queued {
                request: "R-0000A1B2".into()
            }
        );
        let dedup = AdminRegisterApplicationResponse {
            approval,
            deduplicated: true,
            ..AdminRegisterApplicationResponse::default()
        };
        assert_eq!(
            outcome(&dedup),
            Registered::AlreadyApproved {
                approval: "A-0000BEEF".into()
            }
        );
    }

    #[tokio::test]
    async fn without_a_session_nothing_is_sent() {
        let mut s = AdminSession::new(ClientConfig {
            endpoint: "https://127.0.0.1:1".into(),
            pins: vec![SpkiPin::from_hex(&"a".repeat(96)).unwrap()],
            device_token_path: None,
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
            client_kind: crate::client_kind::TRAY,
        });
        let mut code = Secret::new();
        code.push_str("123456");
        let req = unix().request(ApprovalTerms::default(), "k".into());
        assert_eq!(
            s.register_application(req, Factor::Totp(code)).await,
            Err(ClientError::SessionEnded)
        );
    }
}
