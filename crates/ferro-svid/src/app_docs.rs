//! Signed documents of the host-facing app-registration RPCs (F19 §7.1–§7.2):
//! `SubmitAppRequest` ([`AppRequestDoc`]), `GetAppRequestStatus`
//! ([`AppStatusDoc`]) and `SyncAllowlist` ([`AllowlistSyncDoc`]).
//!
//! Like [`crate::host_call::AuditForwardDoc`], each document is canonical
//! CBOR that the host signs with its machine key under its own context
//! ([`APP_REQUEST_CONTEXT`], [`APP_STATUS_CONTEXT`],
//! [`ALLOWLIST_SYNC_CONTEXT`]); CMIS verifies the proof with the shared
//! `HostCallAuth` verifier. Every struct is `deny_unknown_fields`, and the
//! decoders enforce the F19 §7.2 limits and enum ranges, naming the failing
//! field so CMIS can answer `INVALID_ARGUMENT` with `x-ferrogate-field`.
//!
//! The request document carries personal data (user names, the path, the
//! SID); CMIS stores it only in the access-controlled ledger and never in
//! audit events or logs (F19 §10).

use serde::{Deserialize, Serialize};

use crate::cbor_bytes::{fixed, vec_fixed};
use crate::host_call::{HostCallDoc, DOC_VERSION, MAX_HOST_UUID_LEN, NONCE_LEN};

/// Signing context of `SubmitAppRequest`.
pub const APP_REQUEST_CONTEXT: &[u8] = b"ferrogate-app-request-v1";
/// Signing context of `GetAppRequestStatus`.
pub const APP_STATUS_CONTEXT: &[u8] = b"ferrogate-app-status-v1";
/// Signing context of `SyncAllowlist`.
pub const ALLOWLIST_SYNC_CONTEXT: &[u8] = b"ferrogate-allowlist-sync-v1";

/// Largest encoded [`AppRequestDoc`] (F19 §7.2).
pub const MAX_APP_REQUEST_BYTES: usize = 16 * 1024;
/// Largest encoded [`AppStatusDoc`].
pub const MAX_APP_STATUS_BYTES: usize = 4 * 1024;
/// Largest encoded [`AllowlistSyncDoc`].
pub const MAX_ALLOWLIST_SYNC_BYTES: usize = 1024;
/// Most request ids one status document may ask about.
pub const MAX_STATUS_REQUEST_IDS: usize = 100;
/// Most formats one sync document may accept.
pub const MAX_ACCEPT_FORMATS: usize = 8;

/// Risk-flag bits a host may set (F19 §4.5: the MIA- and appid-set bits
/// 0–6, 12 and 13). CMIS clears every other bit of `binary.flags`.
pub const HOST_SETTABLE_FLAGS: u32 = 0b0011_0000_0111_1111;

/// Request origins a host may claim: 1 self, 2 assisted, 4 observed
/// (`admin_direct` is the admin RPC's).
const HOST_ORIGINS: [u8; 3] = [1, 2, 4];

/// The user an app request is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetUser {
    /// 1 Unix, 2 Windows.
    pub kind: u8,
    /// Unix uid, or the Windows RID (compatibility).
    pub uid: Option<u32>,
    /// Full Windows SID (≤ 184).
    pub sid: Option<String>,
    /// User name (≤ 256).
    pub name: String,
}

/// Who invoked the request on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedBy {
    /// Invoking uid.
    pub uid: u32,
    /// Invoking user name (≤ 256).
    pub name: String,
}

/// The binary's signer summary, when the host has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerDesc {
    /// 0 none, 1 authenticode, 2 apple.
    pub kind: u8,
    /// Leaf SHA-256 hex or Team ID (≤ 128).
    pub id: String,
    /// Subject, for display (≤ 256).
    pub subject: String,
    /// Whether the signature verified on the host.
    pub valid: bool,
}

/// The binary as `ferro-appid` identified it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryDesc {
    /// Canonical path (≤ 4096 bytes).
    pub canonical_path: String,
    /// 1 linux, 2 macos, 3 windows.
    pub platform: u8,
    /// SHA-384 of the file.
    #[serde(with = "fixed")]
    pub sha384: [u8; 48],
    /// File size in bytes.
    pub size: u64,
    /// 1 elf, 2 macho, 3 pe, 9 other.
    pub format: u8,
    /// Declared version (≤ 64, untrusted).
    pub declared_version: Option<String>,
    /// Version source (0–7).
    pub version_source: u8,
    /// Product name (≤ 128).
    pub product_name: Option<String>,
    /// Bundle id (≤ 255).
    pub bundle_id: Option<String>,
    /// Package name (≤ 128).
    pub package_name: Option<String>,
    /// Signer summary.
    pub signer: Option<SignerDesc>,
    /// Risk flags (CMIS masks with [`HOST_SETTABLE_FLAGS`]).
    pub flags: u32,
}

/// The `SubmitAppRequest` document (F19 §7.2). Replay-safe through
/// `client_request_id`, so it carries no nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRequestDoc {
    /// Document version, [`DOC_VERSION`].
    pub v: u8,
    /// Requesting host; must equal the SVID's.
    pub host_uuid: String,
    /// Unix seconds the host signed the document.
    pub issued_at: i64,
    /// MIA's idempotency key (UUIDv4 bytes).
    #[serde(with = "fixed")]
    pub client_request_id: [u8; 16],
    /// 1 self, 2 assisted, 4 observed.
    pub origin: u8,
    /// The user the request is for.
    pub target_user: TargetUser,
    /// Who invoked it.
    pub requested_by: RequestedBy,
    /// Requester's note (≤ 200).
    pub reason: Option<String>,
    /// The binary.
    pub binary: BinaryDesc,
}

/// The `GetAppRequestStatus` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppStatusDoc {
    /// Document version, [`DOC_VERSION`].
    pub v: u8,
    /// Asking host.
    pub host_uuid: String,
    /// Unix seconds.
    pub issued_at: i64,
    /// Replay-protection nonce.
    #[serde(with = "fixed")]
    pub nonce: [u8; NONCE_LEN],
    /// Request ids (UUID bytes), at most [`MAX_STATUS_REQUEST_IDS`].
    #[serde(with = "vec_fixed")]
    pub request_ids: Vec<[u8; 16]>,
}

/// The `SyncAllowlist` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistSyncDoc {
    /// Document version, [`DOC_VERSION`].
    pub v: u8,
    /// Asking host.
    pub host_uuid: String,
    /// Unix seconds.
    pub issued_at: i64,
    /// Replay-protection nonce.
    #[serde(with = "fixed")]
    pub nonce: [u8; NONCE_LEN],
    /// Generation of the allowlist the host holds (0: none).
    pub have_generation: u64,
    /// Allowlist formats the host accepts (`[2]`).
    pub accept_formats: Vec<u32>,
}

impl HostCallDoc for AppRequestDoc {
    fn host_uuid(&self) -> &str {
        &self.host_uuid
    }

    fn issued_at(&self) -> i64 {
        self.issued_at
    }

    fn nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        None
    }
}

impl HostCallDoc for AppStatusDoc {
    fn host_uuid(&self) -> &str {
        &self.host_uuid
    }

    fn issued_at(&self) -> i64 {
        self.issued_at
    }

    fn nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        Some(&self.nonce)
    }
}

impl HostCallDoc for AllowlistSyncDoc {
    fn host_uuid(&self) -> &str {
        &self.host_uuid
    }

    fn issued_at(&self) -> i64 {
        self.issued_at
    }

    fn nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        Some(&self.nonce)
    }
}

/// Why an app document was refused. [`AppDocError::field`] names the field
/// for `x-ferrogate-field`; [`AppDocError::reason`] is the F19 §7.4 code.
#[derive(Debug, thiserror::Error)]
pub enum AppDocError {
    /// CBOR encoding failed.
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding failed or a field is unknown or mistyped.
    #[error("cbor decode: {0}")]
    Decode(String),
    /// The encoded document exceeds its size limit.
    #[error("document too large ({0} bytes)")]
    TooLarge(usize),
    /// The document version is not [`DOC_VERSION`].
    #[error("unsupported document version {0}")]
    Version(u8),
    /// A field failed validation.
    #[error("invalid {field}: {reason}")]
    Field {
        /// Dotted field name, e.g. `binary.canonical_path`.
        field: &'static str,
        /// Stable reason code (`field_too_long`, `bad_value`, …).
        reason: &'static str,
    },
}

impl AppDocError {
    /// The failing field, if one was named.
    #[must_use]
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::Field { field, .. } => Some(field),
            _ => None,
        }
    }

    /// The stable `x-ferrogate-reason` code.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Field { reason, .. } => reason,
            Self::TooLarge(_) => "field_too_long",
            Self::Encode(_) | Self::Decode(_) | Self::Version(_) => "malformed",
        }
    }
}

fn bad(field: &'static str, reason: &'static str) -> AppDocError {
    AppDocError::Field { field, reason }
}

fn max_chars(v: Option<&str>, max: usize, field: &'static str) -> Result<(), AppDocError> {
    match v {
        Some(s) if s.chars().count() > max => Err(bad(field, "field_too_long")),
        _ => Ok(()),
    }
}

fn one_of(v: u8, allowed: &[u8], field: &'static str) -> Result<(), AppDocError> {
    if allowed.contains(&v) {
        Ok(())
    } else {
        Err(bad(field, "bad_value"))
    }
}

fn check_host(host_uuid: &str) -> Result<(), AppDocError> {
    if host_uuid.is_empty() || host_uuid.len() > MAX_HOST_UUID_LEN {
        return Err(bad("host_uuid", "field_too_long"));
    }
    Ok(())
}

fn encode<T: Serialize>(doc: &T, max: usize) -> Result<Vec<u8>, AppDocError> {
    let mut out = Vec::with_capacity(256);
    ciborium::into_writer(doc, &mut out).map_err(|e| AppDocError::Encode(e.to_string()))?;
    if out.len() > max {
        return Err(AppDocError::TooLarge(out.len()));
    }
    Ok(out)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8], max: usize) -> Result<T, AppDocError> {
    if bytes.len() > max {
        return Err(AppDocError::TooLarge(bytes.len()));
    }
    ciborium::from_reader(bytes).map_err(|e| AppDocError::Decode(e.to_string()))
}

/// Check every F19 §7.2 limit of an [`AppRequestDoc`].
pub fn validate_app_request(doc: &AppRequestDoc) -> Result<(), AppDocError> {
    if doc.v != DOC_VERSION {
        return Err(AppDocError::Version(doc.v));
    }
    check_host(&doc.host_uuid)?;
    one_of(doc.origin, &HOST_ORIGINS, "origin")?;
    let t = &doc.target_user;
    one_of(t.kind, &[1, 2], "target_user.kind")?;
    if t.kind == 1 && t.uid.is_none() {
        return Err(bad("target_user.uid", "missing"));
    }
    if t.kind == 2 && t.sid.as_deref().is_none_or(str::is_empty) {
        return Err(bad("target_user.sid", "missing"));
    }
    max_chars(t.sid.as_deref(), 184, "target_user.sid")?;
    max_chars(Some(&t.name), 256, "target_user.name")?;
    max_chars(Some(&doc.requested_by.name), 256, "requested_by.name")?;
    max_chars(doc.reason.as_deref(), 200, "reason")?;
    let b = &doc.binary;
    if b.canonical_path.is_empty() || b.canonical_path.contains('\0') {
        return Err(bad("binary.canonical_path", "bad_value"));
    }
    if b.canonical_path.len() > 4096 {
        return Err(bad("binary.canonical_path", "field_too_long"));
    }
    one_of(b.platform, &[1, 2, 3], "binary.platform")?;
    one_of(b.format, &[1, 2, 3, 9], "binary.format")?;
    if b.version_source > 7 {
        return Err(bad("binary.version_source", "bad_value"));
    }
    max_chars(b.declared_version.as_deref(), 64, "binary.declared_version")?;
    max_chars(b.product_name.as_deref(), 128, "binary.product_name")?;
    max_chars(b.bundle_id.as_deref(), 255, "binary.bundle_id")?;
    max_chars(b.package_name.as_deref(), 128, "binary.package_name")?;
    if let Some(s) = &b.signer {
        one_of(s.kind, &[0, 1, 2], "binary.signer.kind")?;
        max_chars(Some(&s.id), 128, "binary.signer.id")?;
        max_chars(Some(&s.subject), 256, "binary.signer.subject")?;
    }
    Ok(())
}

/// Canonical CBOR of an [`AppRequestDoc`] (validated first).
pub fn encode_app_request(doc: &AppRequestDoc) -> Result<Vec<u8>, AppDocError> {
    validate_app_request(doc)?;
    encode(doc, MAX_APP_REQUEST_BYTES)
}

/// Decode and validate an [`AppRequestDoc`].
pub fn decode_app_request(bytes: &[u8]) -> Result<AppRequestDoc, AppDocError> {
    let doc: AppRequestDoc = decode(bytes, MAX_APP_REQUEST_BYTES)?;
    validate_app_request(&doc)?;
    Ok(doc)
}

fn validate_status(doc: &AppStatusDoc) -> Result<(), AppDocError> {
    if doc.v != DOC_VERSION {
        return Err(AppDocError::Version(doc.v));
    }
    check_host(&doc.host_uuid)?;
    if doc.request_ids.len() > MAX_STATUS_REQUEST_IDS {
        return Err(bad("request_ids", "too_many"));
    }
    Ok(())
}

/// Canonical CBOR of an [`AppStatusDoc`] (validated first).
pub fn encode_app_status(doc: &AppStatusDoc) -> Result<Vec<u8>, AppDocError> {
    validate_status(doc)?;
    encode(doc, MAX_APP_STATUS_BYTES)
}

/// Decode and validate an [`AppStatusDoc`].
pub fn decode_app_status(bytes: &[u8]) -> Result<AppStatusDoc, AppDocError> {
    let doc: AppStatusDoc = decode(bytes, MAX_APP_STATUS_BYTES)?;
    validate_status(&doc)?;
    Ok(doc)
}

fn validate_sync(doc: &AllowlistSyncDoc) -> Result<(), AppDocError> {
    if doc.v != DOC_VERSION {
        return Err(AppDocError::Version(doc.v));
    }
    check_host(&doc.host_uuid)?;
    if doc.accept_formats.len() > MAX_ACCEPT_FORMATS {
        return Err(bad("accept_formats", "too_many"));
    }
    Ok(())
}

/// Canonical CBOR of an [`AllowlistSyncDoc`] (validated first).
pub fn encode_allowlist_sync(doc: &AllowlistSyncDoc) -> Result<Vec<u8>, AppDocError> {
    validate_sync(doc)?;
    encode(doc, MAX_ALLOWLIST_SYNC_BYTES)
}

/// Decode and validate an [`AllowlistSyncDoc`].
pub fn decode_allowlist_sync(bytes: &[u8]) -> Result<AllowlistSyncDoc, AppDocError> {
    let doc: AllowlistSyncDoc = decode(bytes, MAX_ALLOWLIST_SYNC_BYTES)?;
    validate_sync(&doc)?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AppRequestDoc {
        AppRequestDoc {
            v: 1,
            host_uuid: "5376139b-0117-8e2d-8049-1ab7b32e7d9a".into(),
            issued_at: 1_800_000_000,
            client_request_id: [7; 16],
            origin: 1,
            target_user: TargetUser {
                kind: 1,
                uid: Some(1000),
                sid: None,
                name: "alice".into(),
            },
            requested_by: RequestedBy {
                uid: 1000,
                name: "alice".into(),
            },
            reason: Some("need it".into()),
            binary: BinaryDesc {
                canonical_path: "/usr/bin/tool".into(),
                platform: 1,
                sha384: [0xaa; 48],
                size: 4096,
                format: 1,
                declared_version: Some("1.2.3".into()),
                version_source: 5,
                product_name: None,
                bundle_id: None,
                package_name: Some("tool".into()),
                signer: Some(SignerDesc {
                    kind: 0,
                    id: String::new(),
                    subject: String::new(),
                    valid: false,
                }),
                flags: 1,
            },
        }
    }

    #[test]
    fn documents_round_trip() {
        let r = request();
        assert_eq!(
            decode_app_request(&encode_app_request(&r).unwrap()).unwrap(),
            r
        );
        let s = AppStatusDoc {
            v: 1,
            host_uuid: "h".into(),
            issued_at: 5,
            nonce: [1; 16],
            request_ids: vec![[2; 16], [3; 16]],
        };
        let bytes = encode_app_status(&s).unwrap();
        assert_eq!(decode_app_status(&bytes).unwrap(), s);
        // Request ids travel as 16-byte byte strings (0x50).
        assert!(bytes.windows(17).any(|w| w[0] == 0x50 && w[1..] == [2; 16]));
        let y = AllowlistSyncDoc {
            v: 1,
            host_uuid: "h".into(),
            issued_at: 5,
            nonce: [1; 16],
            have_generation: 1_800_000_000_000,
            accept_formats: vec![2],
        };
        assert_eq!(
            decode_allowlist_sync(&encode_allowlist_sync(&y).unwrap()).unwrap(),
            y
        );
        assert_eq!(HostCallDoc::nonce(&r), None);
        assert_eq!(HostCallDoc::nonce(&y), Some(&[1; 16]));
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        #[derive(Serialize)]
        struct SyncPlus<'a> {
            #[serde(flatten)]
            d: &'a AllowlistSyncDoc,
            push: bool,
        }
        // A nested unknown field (inside `binary`).
        #[derive(Serialize)]
        struct BinaryPlus<'a> {
            #[serde(flatten)]
            b: &'a BinaryDesc,
            executable_bit: bool,
        }
        #[derive(Serialize)]
        struct RequestWith<'a> {
            v: u8,
            host_uuid: &'a str,
            issued_at: i64,
            #[serde(with = "fixed")]
            client_request_id: [u8; 16],
            origin: u8,
            target_user: &'a TargetUser,
            requested_by: &'a RequestedBy,
            reason: Option<&'a str>,
            binary: BinaryPlus<'a>,
        }
        let r = request();
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &RequestWith {
                v: 1,
                host_uuid: &r.host_uuid,
                issued_at: r.issued_at,
                client_request_id: r.client_request_id,
                origin: 1,
                target_user: &r.target_user,
                requested_by: &r.requested_by,
                reason: None,
                binary: BinaryPlus {
                    b: &r.binary,
                    executable_bit: true,
                },
            },
            &mut bytes,
        )
        .unwrap();
        assert!(matches!(
            decode_app_request(&bytes),
            Err(AppDocError::Decode(_))
        ));

        // A top-level unknown field.
        let y = AllowlistSyncDoc {
            v: 1,
            host_uuid: "h".into(),
            issued_at: 5,
            nonce: [1; 16],
            have_generation: 0,
            accept_formats: vec![2],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&SyncPlus { d: &y, push: true }, &mut bytes).unwrap();
        assert!(matches!(
            decode_allowlist_sync(&bytes),
            Err(AppDocError::Decode(_))
        ));
    }

    #[test]
    fn limits_and_enums_are_enforced_by_field() {
        let field = |doc: AppRequestDoc| {
            encode_app_request(&doc)
                .unwrap_err()
                .field()
                .unwrap_or("none")
        };
        let mut d = request();
        d.origin = 3;
        assert_eq!(field(d), "origin", "admin_direct is not a host origin");
        let mut d = request();
        d.binary.canonical_path = format!("/{}", "a".repeat(4096));
        assert_eq!(field(d), "binary.canonical_path");
        let mut d = request();
        d.binary.declared_version = Some("9".repeat(65));
        assert_eq!(field(d), "binary.declared_version");
        let mut d = request();
        d.reason = Some("x".repeat(201));
        assert_eq!(field(d), "reason");
        let mut d = request();
        d.target_user = TargetUser {
            kind: 2,
            uid: Some(1001),
            sid: None,
            name: "bob".into(),
        };
        assert_eq!(field(d), "target_user.sid");
        let mut d = request();
        d.binary.format = 4;
        assert_eq!(field(d), "binary.format");
        let mut d = request();
        d.binary.platform = 0;
        assert_eq!(field(d), "binary.platform");
        let mut d = request();
        d.host_uuid = "h".repeat(65);
        assert_eq!(field(d), "host_uuid");
        let mut d = request();
        d.v = 2;
        assert!(matches!(
            encode_app_request(&d),
            Err(AppDocError::Version(2))
        ));
        assert!(matches!(
            decode_app_request(&vec![0u8; MAX_APP_REQUEST_BYTES + 1]),
            Err(AppDocError::TooLarge(_))
        ));
        let too_many = AppStatusDoc {
            v: 1,
            host_uuid: "h".into(),
            issued_at: 5,
            nonce: [1; 16],
            request_ids: vec![[0; 16]; MAX_STATUS_REQUEST_IDS + 1],
        };
        assert!(encode_app_status(&too_many).is_err());
    }

    #[test]
    fn wrong_length_ids_are_rejected() {
        #[derive(Serialize)]
        struct Short {
            v: u8,
            host_uuid: String,
            issued_at: i64,
            #[serde(with = "fixed")]
            nonce: [u8; 16],
            #[serde(with = "vec_fixed")]
            request_ids: Vec<[u8; 8]>,
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &Short {
                v: 1,
                host_uuid: "h".into(),
                issued_at: 1,
                nonce: [0; 16],
                request_ids: vec![[1; 8]],
            },
            &mut bytes,
        )
        .unwrap();
        assert!(matches!(
            decode_app_status(&bytes),
            Err(AppDocError::Decode(_))
        ));
    }
}
