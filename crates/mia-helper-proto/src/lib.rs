//! `mia-helper-proto` — the MIA helper-API wire types (features F08, F19).
//!
//! Local applications talk to the MIA over a Unix Domain Socket (Linux,
//! macOS) or a Named Pipe (Windows). Each connection carries **one** request
//! and **one** response, each a single CBOR value behind a 4-byte big-endian
//! length, bounded by [`MAX_FRAME_LEN`].
//!
//! Two request shapes share the socket:
//!
//! - **v1** — a bare [`HelperReq`] map (`{audience, dpop_jkt, ttl_secs}`),
//!   answered with a [`HelperResp`]. Every SDK released before F19 sends it,
//!   and the daemon keeps accepting it unchanged.
//! - **v2** — a [`HelperFrame`] `{v: 2, op}` envelope (F19 §7.6). Its
//!   [`HelperOp::Token`] is the v1 request in the envelope (answered with a
//!   [`HelperResp`]); the registration operations
//!   ([`HelperOp::RegisterSelf`], [`HelperOp::RegisterFile`],
//!   [`HelperOp::RequestStatus`]) are answered with a [`RegistrationResp`].
//!
//! The daemon decodes a frame with [`decode_request`]: a frame that is a v2
//! envelope is a v2 request, anything else is tried as v1. An agent that
//! predates v2 cannot decode an envelope and drops the connection without a
//! reply; a client reports that as "agent too old".
//!
//! Requests come from untrusted local processes. Every v2 struct is
//! `deny_unknown_fields`, and [`HelperFrame::validate`] bounds every string
//! and list, so the daemon never acts on a field it does not understand.
//!
//! Like `mia-status-proto` this crate is deliberately tiny — serde types and
//! `std::io` framing only — so an application's helper client never depends
//! on the daemon crate.

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Largest frame either side reads or writes, in bytes. Requests are tiny; a
/// minted child token is a few KiB of composite signature, so 64 KiB is
/// generous while still bounding per-connection memory.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// The `v` of a [`HelperFrame`].
pub const PROTOCOL_V2: u8 = 2;

/// Length of every 128-bit identifier on the wire (local ids, request ids,
/// approval ids, client request ids).
pub const ID_LEN: usize = 16;

/// Longest requester note, in characters (F19 §7.2 `reason`).
pub const MAX_REASON_CHARS: usize = 200;

/// Longest path a client may name, in bytes (F19 §4.2).
pub const MAX_PATH_BYTES: usize = 4096;

/// Most ids in one [`HelperOp::RequestStatus`] (F19 §7.6).
pub const MAX_STATUS_IDS: usize = 50;

/// Longest user name or SID in a [`UserSel`], in characters.
pub const MAX_USER_SEL_CHARS: usize = 256;

/// Longest audience or DPoP thumbprint in a token request, in bytes.
pub const MAX_TOKEN_FIELD_BYTES: usize = 2048;

/// The platform's well-known helper address: the listener the host's default
/// environment serves when `helper.socket` is unset. Kept equal to `mia`'s
/// `config::default_helper_socket(None)` by a test in the daemon crate.
#[cfg(target_os = "linux")]
pub const DEFAULT_ENDPOINT: &str = "/run/ferrogate/mia.sock";
/// The platform's well-known helper address (macOS).
#[cfg(target_os = "macos")]
pub const DEFAULT_ENDPOINT: &str = "/Library/Application Support/FerroGate/run/mia.sock";
/// The platform's well-known helper address (Windows named pipe).
#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\ferrogate-mia";
/// The platform's well-known helper address (other Unix).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub const DEFAULT_ENDPOINT: &str = "/run/ferrogate/mia.sock";

// ── v1 ───────────────────────────────────────────────────────────────────────

/// A token request from a local caller (the v1 request body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperReq {
    /// Target audience the token is minted for, e.g. `https://api.example.com`.
    pub audience: String,
    /// Base64url SHA-256 thumbprint of the caller's DPoP public JWK.
    pub dpop_jkt: String,
    /// Requested lifetime in seconds; clamped by the daemon to its maximum
    /// child-token lifetime.
    pub ttl_secs: u32,
}

/// A minted child token plus the metadata a caller needs to schedule renewal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildToken {
    /// The compact JWS child token.
    pub jws: String,
    /// Expiry, Unix seconds.
    pub exp: i64,
}

/// Stable refusal opcodes of the token path. These are a closed set — never
/// caller input — so the channel exposes no oracle surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Caller failed authentication or is not on the allowlist.
    PermissionDenied,
    /// The MIA holds no valid host SVID, so it cannot mint.
    NoHostSvid,
    /// The cached CRL is missing or stale (> 5 min), so the MIA fails closed
    /// and refuses to mint until a fresh CRL is pulled (feature F11).
    CrlStale,
    /// The request was malformed (bad fields).
    MalformedRequest,
    /// The server is shedding load; retry later.
    RateLimited,
    /// An unexpected internal error.
    Internal,
}

/// The server's reply to a token request (v1, or a v2 [`HelperOp::Token`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelperResp {
    /// A successfully minted token.
    Token(ChildToken),
    /// A refusal, optionally with a retry hint (seconds).
    Error {
        /// The refusal opcode.
        code: ErrorCode,
        /// Suggested seconds to wait before retrying, if applicable.
        retry_after: Option<u32>,
    },
}

// ── v2 ───────────────────────────────────────────────────────────────────────

/// The v2 request envelope (F19 §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperFrame {
    /// Protocol version, [`PROTOCOL_V2`].
    pub v: u8,
    /// The operation.
    pub op: HelperOp,
}

impl HelperFrame {
    /// A v2 frame carrying `op`.
    #[must_use]
    pub const fn new(op: HelperOp) -> Self {
        Self { v: PROTOCOL_V2, op }
    }

    /// Check every bound of the frame. The daemon calls this on every decoded
    /// frame before acting on it.
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.v != PROTOCOL_V2 {
            return Err(ProtoError::Invalid("v"));
        }
        match &self.op {
            HelperOp::Token {
                audience, dpop_jkt, ..
            } => {
                bounded_bytes(audience, MAX_TOKEN_FIELD_BYTES, "audience")?;
                bounded_bytes(dpop_jkt, MAX_TOKEN_FIELD_BYTES, "dpop_jkt")
            }
            HelperOp::RegisterSelf { reason, .. } => check_reason(reason.as_deref()),
            HelperOp::RegisterFile {
                path,
                for_user,
                reason,
                ..
            } => {
                if path.is_empty() || path.contains('\0') {
                    return Err(ProtoError::Invalid("path"));
                }
                bounded_bytes(path, MAX_PATH_BYTES, "path")?;
                if let Some(sel) = for_user {
                    sel.validate()?;
                }
                check_reason(reason.as_deref())
            }
            HelperOp::RequestStatus { request_ids } => {
                if request_ids.len() > MAX_STATUS_IDS {
                    return Err(ProtoError::Invalid("request_ids"));
                }
                Ok(())
            }
        }
    }
}

/// One v2 operation, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum HelperOp {
    /// A token request with the v1 semantics, answered with a [`HelperResp`].
    Token {
        /// Target audience.
        audience: String,
        /// Base64url SHA-256 thumbprint of the caller's DPoP public JWK.
        dpop_jkt: String,
        /// Requested lifetime in seconds.
        ttl_secs: u32,
    },
    /// Ask for the calling application's own binary to be approved. The
    /// daemon identifies the binary from the kernel-attested caller; the
    /// target user is the caller.
    RegisterSelf {
        /// Caller-chosen idempotency id: repeating it returns the same local
        /// request.
        client_request_id: [u8; ID_LEN],
        /// A note shown to the approver (≤ [`MAX_REASON_CHARS`]; never put
        /// personal data in it).
        reason: Option<String>,
    },
    /// Ask for a file to be approved (`mia app register --exe`, the tray).
    /// On Unix the client opens the file itself and passes the descriptor
    /// with `SCM_RIGHTS` alongside this frame; the daemon hashes only that
    /// descriptor, never a path it opens with its own privileges.
    RegisterFile {
        /// Caller-chosen idempotency id.
        client_request_id: [u8; ID_LEN],
        /// The path the client opened (display and diagnostics only: the
        /// daemon resolves the path from the descriptor).
        path: String,
        /// Register for another user. Only root or an administrator may.
        for_user: Option<UserSel>,
        /// A note shown to the approver.
        reason: Option<String>,
    },
    /// The state of the caller's own requests (all requests for root). An
    /// empty list asks for every request the caller may see.
    RequestStatus {
        /// Local ids or CMIS request ids (≤ [`MAX_STATUS_IDS`]).
        request_ids: Vec<[u8; ID_LEN]>,
    },
}

/// A user named by a privileged `RegisterFile` caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSel {
    /// A Unix uid.
    Uid(u32),
    /// A user name.
    Name(String),
    /// A Windows SID (`S-1-5-…`).
    Sid(String),
}

impl UserSel {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::Uid(_) => Ok(()),
            Self::Name(s) | Self::Sid(s) => {
                if s.is_empty()
                    || s.chars().count() > MAX_USER_SEL_CHARS
                    || s.chars().any(char::is_control)
                {
                    Err(ProtoError::Invalid("for_user"))
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Where a local registration request stands (F19 §7.6 `LocalState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalState {
    /// Recorded locally and waiting in the outbox: CMIS was unreachable, the
    /// host had no SVID yet, or CMIS is still in legacy allowlist mode.
    Queued,
    /// Submitted; waiting for an administrator.
    Pending,
    /// Approved by an administrator (or already covered by an approval).
    Approved,
    /// Approved automatically under an update policy.
    AutoApproved,
    /// Denied by an administrator.
    Denied,
    /// Expired before anyone decided.
    Expired,
    /// CMIS refused the request itself (invalid or not permitted). Terminal:
    /// the outbox never retries it.
    Refused,
}

impl LocalState {
    /// Whether the state can still change.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Queued | Self::Pending)
    }

    /// Whether the binary is approved.
    #[must_use]
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::Approved | Self::AutoApproved)
    }

    /// The stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::AutoApproved => "auto_approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Refused => "refused",
        }
    }
}

/// Stable refusal opcodes of the registration operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegErrorCode {
    /// The caller may not do this (unauthenticated caller, or `for_user`
    /// without administrator rights).
    PermissionDenied,
    /// Registration (or assisted registration) is switched off on this host.
    RegistrationDisabled,
    /// This agent or its CMIS does not support the operation here.
    ServerUnsupported,
    /// The file cannot be registered: not a regular executable file, not
    /// readable through the passed descriptor, or not the caller's binary.
    FileNotEligible,
    /// The file is larger than `registration.max_file_size_mib`.
    FileTooLarge,
    /// Too many registrations; retry after `retry_after` seconds.
    RateLimited,
    /// The request was malformed.
    MalformedRequest,
    /// An unexpected internal error.
    Internal,
}

impl RegErrorCode {
    /// The stable snake_case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::RegistrationDisabled => "registration_disabled",
            Self::ServerUnsupported => "server_unsupported",
            Self::FileNotEligible => "file_not_eligible",
            Self::FileTooLarge => "file_too_large",
            Self::RateLimited => "rate_limited",
            Self::MalformedRequest => "malformed_request",
            Self::Internal => "internal",
        }
    }
}

/// One request in a [`RegistrationResp::Status`] reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRequestStatus {
    /// The daemon's local id.
    pub local_id: [u8; ID_LEN],
    /// The CMIS request id, once submitted (absent when an existing approval
    /// already covered the binary).
    pub request_id: Option<[u8; ID_LEN]>,
    /// Where it stands.
    pub state: LocalState,
    /// The binary's revision in its lineage, once known.
    pub revision: Option<u32>,
    /// The approval, when approved.
    pub approval_id: Option<[u8; ID_LEN]>,
    /// The canonical path of the binary.
    pub path: String,
    /// When the daemon last changed this entry, Unix seconds.
    pub updated_at: i64,
    /// The administrator's reason code, when denied.
    pub deny_reason_code: Option<u32>,
    /// The administrator's message to the requester, when denied.
    pub deny_message: Option<String>,
}

/// The daemon's reply to a registration operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationResp {
    /// The request was recorded (and submitted, unless `state` is
    /// [`LocalState::Queued`]).
    Submitted {
        /// The CMIS request id, once submitted.
        request_id: Option<[u8; ID_LEN]>,
        /// The daemon's local id (use it with `RequestStatus`).
        local_id: [u8; ID_LEN],
        /// Where it stands.
        state: LocalState,
        /// The binary's revision, once known.
        revision: Option<u32>,
        /// The approval, when approved.
        approval_id: Option<[u8; ID_LEN]>,
        /// Seconds to wait before retrying the token request (approved: the
        /// daemon is syncing the allowlist) or before asking again (a denial
        /// cool-down).
        retry_after: Option<u32>,
    },
    /// An active approval already covers the binary; retry the token
    /// request.
    AlreadyApproved {
        /// The covering approval.
        approval_id: [u8; ID_LEN],
    },
    /// The requested statuses.
    Status(Vec<LocalRequestStatus>),
    /// A refusal.
    Error {
        /// The refusal opcode.
        code: RegErrorCode,
        /// Suggested seconds to wait before retrying, if applicable.
        retry_after: Option<u32>,
    },
}

// ── decoding, validation and framing ─────────────────────────────────────────

/// A decoded request, v1 or v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// A bare v1 token request.
    Legacy(HelperReq),
    /// A validated v2 envelope.
    V2(HelperFrame),
}

/// Decoding, validation and framing failures.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// Underlying I/O failed (including a peer closing early).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The frame exceeds [`MAX_FRAME_LEN`].
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    /// CBOR encoding failed.
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding failed or a field is unknown or mistyped.
    #[error("cbor decode: {0}")]
    Decode(String),
    /// A decoded field is out of bounds; names the field.
    #[error("invalid field {0}")]
    Invalid(&'static str),
}

fn bounded_bytes(s: &str, max: usize, field: &'static str) -> Result<(), ProtoError> {
    if s.len() > max {
        Err(ProtoError::Invalid(field))
    } else {
        Ok(())
    }
}

fn check_reason(reason: Option<&str>) -> Result<(), ProtoError> {
    match reason {
        Some(r) if r.chars().count() > MAX_REASON_CHARS => Err(ProtoError::Invalid("reason")),
        _ => Ok(()),
    }
}

/// Decode one request body (the frame without its length prefix). A frame
/// that decodes as a v2 envelope must also pass [`HelperFrame::validate`];
/// anything else is tried as a v1 [`HelperReq`]. Fails when neither shape
/// decodes.
pub fn decode_request(body: &[u8]) -> Result<Request, ProtoError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtoError::TooLarge(body.len()));
    }
    match ciborium::from_reader::<HelperFrame, _>(body) {
        Ok(frame) => {
            frame.validate()?;
            Ok(Request::V2(frame))
        }
        Err(v2) => ciborium::from_reader::<HelperReq, _>(body)
            .map(Request::Legacy)
            .map_err(|_| ProtoError::Decode(v2.to_string())),
    }
}

/// Encode `value` as one frame: the 4-byte big-endian length, then the CBOR.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let mut out = vec![0u8; 4];
    ciborium::into_writer(value, &mut out).map_err(|e| ProtoError::Encode(e.to_string()))?;
    let body_len = out.len() - 4;
    if body_len > MAX_FRAME_LEN {
        return Err(ProtoError::TooLarge(body_len));
    }
    let len = u32::try_from(body_len).map_err(|_| ProtoError::TooLarge(body_len))?;
    out[..4].copy_from_slice(&len.to_be_bytes());
    Ok(out)
}

/// Decode a frame body (without its length prefix).
pub fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, ProtoError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtoError::TooLarge(body.len()));
    }
    ciborium::from_reader(body).map_err(|e| ProtoError::Decode(e.to_string()))
}

/// Validate a length prefix against [`MAX_FRAME_LEN`].
pub fn frame_len(prefix: [u8; 4]) -> Result<usize, ProtoError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_LEN {
        Err(ProtoError::TooLarge(len))
    } else {
        Ok(len)
    }
}

/// Write `value` as one frame (blocking).
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<(), ProtoError> {
    w.write_all(&encode_frame(value)?)?;
    w.flush()?;
    Ok(())
}

/// Read one frame body (blocking), without decoding it.
pub fn read_frame_body<R: Read>(r: &mut R) -> Result<Vec<u8>, ProtoError> {
    let mut prefix = [0u8; 4];
    r.read_exact(&mut prefix)?;
    let len = frame_len(prefix)?;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Read one frame and decode it (blocking).
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, ProtoError> {
    decode_body(&read_frame_body(r)?)
}

// ── identifiers ──────────────────────────────────────────────────────────────

/// Format a 128-bit id as lowercase hyphenated UUID text
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`), the form CMIS uses.
#[must_use]
pub fn format_id(id: &[u8; ID_LEN]) -> String {
    let mut out = String::with_capacity(36);
    for (i, b) in id.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Parse UUID text — hyphenated (`8-4-4-4-12`) or 32 bare hex digits, either
/// case — into its 16 bytes. Anything else is `None`.
#[must_use]
pub fn parse_id(text: &str) -> Option<[u8; ID_LEN]> {
    let bytes = text.as_bytes();
    let digits: Vec<u8> = match bytes.len() {
        32 => bytes.to_vec(),
        36 => {
            if [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
                return None;
            }
            bytes.iter().copied().filter(|&b| b != b'-').collect()
        }
        _ => return None,
    };
    if digits.len() != 32 {
        return None;
    }
    let mut out = [0u8; ID_LEN];
    for (slot, pair) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Turn 16 random bytes into a UUIDv4 (RFC 9562: version 4, variant `10`).
#[must_use]
pub fn uuid_v4(mut random: [u8; ID_LEN]) -> [u8; ID_LEN] {
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    random
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    #[test]
    fn a_legacy_request_still_decodes_as_v1() {
        let req = HelperReq {
            audience: "https://api.example.com".into(),
            dpop_jkt: "abc".into(),
            ttl_secs: 300,
        };
        assert_eq!(
            decode_request(&cbor(&req)).unwrap(),
            Request::Legacy(req.clone())
        );
        // The framing round-trips.
        let frame = encode_frame(&req).unwrap();
        let back: HelperReq = read_frame(&mut &frame[..]).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn every_v2_operation_round_trips() {
        let ops = [
            HelperOp::Token {
                audience: "aud".into(),
                dpop_jkt: "jkt".into(),
                ttl_secs: 60,
            },
            HelperOp::RegisterSelf {
                client_request_id: [7; ID_LEN],
                reason: Some("needs a token".into()),
            },
            HelperOp::RegisterFile {
                client_request_id: [8; ID_LEN],
                path: "/opt/tool/bin/tool".into(),
                for_user: Some(UserSel::Name("alice".into())),
                reason: None,
            },
            HelperOp::RequestStatus {
                request_ids: vec![[1; ID_LEN], [2; ID_LEN]],
            },
        ];
        for op in ops {
            let frame = HelperFrame::new(op);
            assert_eq!(
                decode_request(&cbor(&frame)).unwrap(),
                Request::V2(frame.clone())
            );
        }
    }

    #[test]
    fn responses_round_trip() {
        let resps = [
            RegistrationResp::Submitted {
                request_id: Some([3; ID_LEN]),
                local_id: [4; ID_LEN],
                state: LocalState::Pending,
                revision: Some(2),
                approval_id: None,
                retry_after: None,
            },
            RegistrationResp::AlreadyApproved {
                approval_id: [5; ID_LEN],
            },
            RegistrationResp::Status(vec![LocalRequestStatus {
                local_id: [4; ID_LEN],
                request_id: None,
                state: LocalState::Queued,
                revision: None,
                approval_id: None,
                path: "/usr/bin/tool".into(),
                updated_at: 1_700_000_000,
                deny_reason_code: None,
                deny_message: None,
            }]),
            RegistrationResp::Error {
                code: RegErrorCode::RateLimited,
                retry_after: Some(60),
            },
        ];
        for r in resps {
            let frame = encode_frame(&r).unwrap();
            let back: RegistrationResp = read_frame(&mut &frame[..]).unwrap();
            assert_eq!(back, r);
        }
    }

    /// A map with one extra key, built from `value`'s CBOR map.
    fn with_extra_key<T: Serialize>(value: &T, at_op: bool) -> Vec<u8> {
        let mut v: ciborium::Value =
            ciborium::from_reader(&cbor(value)[..]).expect("value is a map");
        let target = if at_op {
            let ciborium::Value::Map(top) = &mut v else {
                panic!("frame is a map")
            };
            &mut top
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some("op"))
                .expect("op")
                .1
        } else {
            &mut v
        };
        let ciborium::Value::Map(entries) = target else {
            panic!("a map")
        };
        entries.push((
            ciborium::Value::Text("smuggled".into()),
            ciborium::Value::Bool(true),
        ));
        cbor(&v)
    }

    #[test]
    fn unknown_fields_are_rejected_in_the_envelope_and_the_operation() {
        let frame = HelperFrame::new(HelperOp::RegisterSelf {
            client_request_id: [1; ID_LEN],
            reason: None,
        });
        assert!(matches!(
            decode_request(&with_extra_key(&frame, false)),
            Err(ProtoError::Decode(_))
        ));
        assert!(matches!(
            decode_request(&with_extra_key(&frame, true)),
            Err(ProtoError::Decode(_))
        ));
        let token = HelperFrame::new(HelperOp::Token {
            audience: "a".into(),
            dpop_jkt: "b".into(),
            ttl_secs: 1,
        });
        assert!(decode_request(&with_extra_key(&token, true)).is_err());
    }

    #[test]
    fn out_of_bounds_fields_are_rejected() {
        let long_reason = HelperFrame::new(HelperOp::RegisterSelf {
            client_request_id: [1; ID_LEN],
            reason: Some("x".repeat(MAX_REASON_CHARS + 1)),
        });
        assert!(matches!(
            decode_request(&cbor(&long_reason)),
            Err(ProtoError::Invalid("reason"))
        ));
        let long_path = HelperFrame::new(HelperOp::RegisterFile {
            client_request_id: [1; ID_LEN],
            path: format!("/{}", "a".repeat(MAX_PATH_BYTES)),
            for_user: None,
            reason: None,
        });
        assert!(matches!(
            decode_request(&cbor(&long_path)),
            Err(ProtoError::Invalid("path"))
        ));
        let nul_path = HelperFrame::new(HelperOp::RegisterFile {
            client_request_id: [1; ID_LEN],
            path: "/bin/a\0b".into(),
            for_user: None,
            reason: None,
        });
        assert!(decode_request(&cbor(&nul_path)).is_err());
        let too_many = HelperFrame::new(HelperOp::RequestStatus {
            request_ids: vec![[0; ID_LEN]; MAX_STATUS_IDS + 1],
        });
        assert!(matches!(
            decode_request(&cbor(&too_many)),
            Err(ProtoError::Invalid("request_ids"))
        ));
        let bad_user = HelperFrame::new(HelperOp::RegisterFile {
            client_request_id: [1; ID_LEN],
            path: "/bin/tool".into(),
            for_user: Some(UserSel::Name("bad\nname".into())),
            reason: None,
        });
        assert!(decode_request(&cbor(&bad_user)).is_err());
        let wrong_version = HelperFrame {
            v: 3,
            op: HelperOp::RequestStatus {
                request_ids: vec![],
            },
        };
        assert!(matches!(
            decode_request(&cbor(&wrong_version)),
            Err(ProtoError::Invalid("v"))
        ));
    }

    #[test]
    fn oversized_frames_are_rejected_without_reading_the_body() {
        let huge = (u32::try_from(MAX_FRAME_LEN).unwrap() + 1).to_be_bytes();
        assert!(matches!(
            read_frame_body(&mut &huge[..]),
            Err(ProtoError::TooLarge(_))
        ));
        assert!(matches!(
            decode_request(&vec![0u8; MAX_FRAME_LEN + 1]),
            Err(ProtoError::TooLarge(_))
        ));
        // Encoding refuses to produce one too.
        let big = HelperReq {
            audience: "a".repeat(MAX_FRAME_LEN),
            dpop_jkt: String::new(),
            ttl_secs: 1,
        };
        assert!(matches!(encode_frame(&big), Err(ProtoError::TooLarge(_))));
    }

    #[test]
    fn garbage_is_neither_v1_nor_v2() {
        assert!(decode_request(b"\xff\x00garbage").is_err());
        assert!(decode_request(&cbor(&42u32)).is_err());
    }

    #[test]
    fn ids_format_and_parse() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let text = format_id(&id);
        assert_eq!(text, "01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(parse_id(&text), Some(id));
        assert_eq!(parse_id(&text.to_ascii_uppercase()), Some(id));
        assert_eq!(parse_id(&text.replace('-', "")), Some(id));
        for bad in [
            "",
            "01234567-89ab-cdef-0123-456789abcde",
            "0123456789ab-cdef-0123-456789abcdef-",
            "01234567-89ab-cdef-0123-456789abcdeg",
        ] {
            assert_eq!(parse_id(bad), None, "{bad}");
        }
        let v4 = uuid_v4([0xff; ID_LEN]);
        assert_eq!(v4[6] >> 4, 4);
        assert_eq!(v4[8] >> 6, 0b10);
    }
}
