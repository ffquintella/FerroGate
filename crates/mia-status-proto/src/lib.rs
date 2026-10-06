//! `mia-status-proto` — wire types for the MIA **status endpoint** (feature
//! F18).
//!
//! The status endpoint is a read-only local IPC channel, separate from the
//! token-minting helper socket (F08), that answers two questions for the
//! `mia-tray` companion and for `mia status`:
//!
//! - *what state is each environment in?* — [`StatusReq`] →
//!   [`StatusResponse::Status`] (one [`StatusSnapshot`] per environment);
//! - *what did the daemon log recently?* — [`LogTailReq`] →
//!   [`StatusResponse::LogTail`] (redacted [`LogRecord`]s from the daemon's
//!   ring buffer).
//!
//! Framing is identical to the helper protocol: one CBOR value preceded by a
//! 4-byte big-endian length, bounded by [`MAX_FRAME_LEN`], one exchange per
//! connection. This crate carries the types and a blocking codec over
//! `std::io::{Read, Write}` so a GUI client needs no async runtime; the daemon
//! drives the same codec from its async listener.
//!
//! **What is never on this wire.** The snapshot is non-sensitive by
//! construction: no SVID or token bytes, no signatures, no key material
//! (private or public), no SPKI pins, no `jti` values, no helper-audit caller
//! pid/uid/binary hashes, no allowlist contents. The
//! `status_snapshot_has_no_secret_fields` test pins the exact field set, so
//! adding a field is a visible, reviewed change.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Largest frame either side reads or writes, in bytes. Identical to the
/// helper protocol's bound (`mia::helper::proto::MAX_FRAME_LEN`); `mia`
/// asserts the two stay equal at compile time.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Upper bound the daemon applies to [`LogTailReq::max`]: a single reply never
/// carries more records than this, whatever the client asks for.
pub const MAX_TAIL_RECORDS: u16 = 500;

/// Longest environment name accepted in a [`StatusReq`] filter. Environment
/// names are config-file name components, so anything longer is malformed.
pub const MAX_ENVIRONMENT_LEN: usize = 64;

/// Why [`validate_environment`] rejected an environment name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvironmentNameError {
    /// The name is empty.
    #[error("the environment name must not be empty")]
    Empty,
    /// The name is `.` or `..`.
    #[error("`.` and `..` are not valid environment names")]
    DotName,
    /// The name uses a character other than ASCII letters, digits, `.`, `-`
    /// and `_`.
    #[error("environment names may use only letters, digits, '.', '-' and '_'")]
    InvalidCharacter,
}

/// Validate an environment name: the `<env>` in `mia-<env>.toml`, so a
/// config-file name component. Non-empty, not `.`/`..`, and only ASCII
/// letters, digits, `.`, `-` and `_` — so it can never introduce a path
/// separator or traversal.
///
/// The single implementation shared by `mia` (`config::validate_environment`,
/// which adds its CLI wording) and every status client (`mia-tray` validates
/// an environment with it before passing `-e <env>` to a `mia` command). It
/// does not bound the length; the status endpoint additionally caps names at
/// [`MAX_ENVIRONMENT_LEN`].
pub fn validate_environment(name: &str) -> Result<(), EnvironmentNameError> {
    if name.is_empty() {
        return Err(EnvironmentNameError::Empty);
    }
    if name == "." || name == ".." {
        return Err(EnvironmentNameError::DotName);
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(EnvironmentNameError::InvalidCharacter);
    }
    Ok(())
}

/// Default status endpoint on Linux: a Unix socket under the systemd
/// `RuntimeDirectory`.
#[cfg(all(unix, not(target_os = "macos")))]
pub const DEFAULT_ENDPOINT: &str = "/run/ferrogate/mia-status.sock";

/// Default status endpoint on macOS.
#[cfg(target_os = "macos")]
pub const DEFAULT_ENDPOINT: &str = "/var/run/ferrogate/mia-status.sock";

/// Default status endpoint on Windows: a named pipe.
#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\ferrogate-mia-status";

/// Default status endpoint on other platforms (no daemon support; kept so the
/// crate builds everywhere).
#[cfg(not(any(unix, windows)))]
pub const DEFAULT_ENDPOINT: &str = "mia-status.sock";

// ── Requests ─────────────────────────────────────────────────────────────────

/// Every request the status endpoint accepts. The set is closed and
/// read-only: anything that does not decode as one of these variants (a
/// helper-API `HelperReq`, garbage, a future write request) is rejected with
/// [`StatusErrorCode::UnsupportedRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusRequest {
    /// Ask for the per-environment status snapshots.
    Status(StatusReq),
    /// Ask for recent log records from the daemon's ring buffer.
    LogTail(LogTailReq),
}

/// `StatusReq { environment }` — snapshot request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReq {
    /// Restrict the reply to one environment (`None` ⇒ every environment the
    /// daemon serves). `"default"` names the default `mia.toml` environment.
    pub environment: Option<String>,
}

/// `LogTailReq { since_seq, min_level, max }` — log-tail request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogTailReq {
    /// Return records with `seq >= since_seq` (use the previous reply's
    /// [`LogTailResp::next_seq`] to follow without duplicates).
    pub since_seq: u64,
    /// Least severe level to return.
    pub min_level: Level,
    /// Maximum records to return; clamped to [`MAX_TAIL_RECORDS`].
    pub max: u16,
}

// ── Responses ────────────────────────────────────────────────────────────────

/// The daemon's reply to a [`StatusRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusResponse {
    /// One snapshot per (matching) environment.
    Status(Vec<StatusSnapshot>),
    /// A slice of the log ring buffer.
    LogTail(LogTailResp),
    /// A refusal.
    Error {
        /// Stable refusal code.
        code: StatusErrorCode,
        /// Suggested seconds to wait before retrying, if applicable.
        retry_after: Option<u32>,
    },
}

/// Stable refusal codes for the status endpoint. A closed set, never caller
/// input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusErrorCode {
    /// The frame decoded as CBOR but is not a request this endpoint serves
    /// (including every helper-API request).
    UnsupportedRequest,
    /// A recognised request with invalid fields (e.g. a bad environment name).
    MalformedRequest,
    /// The requested environment is not served by this daemon.
    UnknownEnvironment,
    /// The caller exceeded its per-uid request budget; retry later.
    RateLimited,
    /// An unexpected internal error.
    Internal,
}

/// The state of one environment the daemon serves, as computed by the
/// daemon. The tray only maps it to presentation.
///
/// Never add a field carrying key material, tokens, SVID bytes, signatures,
/// SPKI pins, `jti` values, helper-audit caller identities or allowlist
/// contents (see the crate docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusSnapshot {
    /// The environment name; `None` for the default `mia.toml` environment.
    pub environment: Option<String>,
    /// The derived state.
    pub state: AgentState,
    /// Unix seconds at which the daemon first observed `state`.
    pub since: i64,
    /// The host SVID's identity and lifetime, if one is held.
    pub svid: Option<SvidSummary>,
    /// The attestation backend in effect.
    pub attest_backend: AttestBackend,
    /// The CMIS node (`host:port`) last selected, SRV-aware.
    pub cmis_node: Option<String>,
    /// Age of the cached CRL in seconds (`None` ⇒ none pulled yet).
    pub crl_age_secs: Option<u32>,
    /// The caller allowlist's state.
    pub allowlist: AllowlistState,
    /// The X.509-SVID store backend, if a credential is sealed.
    pub x509_store: Option<StoreBackend>,
    /// The failure behind a non-healthy `state`: a stable code plus a short,
    /// fixed message (never free text from a remote or a caller).
    pub last_error: Option<ErrorSummary>,
    /// The daemon's version string.
    pub version: String,
    /// This environment serves the helper API's well-known default address
    /// (`mia.sock` / `\\.\pipe\ferrogate-mia`): it is the host's default
    /// environment — `mia.toml` unless `environments.toml` /
    /// `FERROGATE_DEFAULT_ENVIRONMENT` selects another — and binds that
    /// address. Absent from older daemons ⇒ `false`.
    #[serde(default)]
    pub default_address: bool,
}

/// Every state an environment can be in. Ordered by [`AgentState::severity`]
/// for "worst state wins" aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    /// The client cannot find `mia` at all (client-side only).
    NotInstalled,
    /// The status endpoint is absent: the service is stopped (client-side).
    NotRunning,
    /// No CMIS source is configured, or the helper API is not served (switched
    /// off with `helper.enable = false`, or a socket duplicating another
    /// environment's).
    NotConfigured,
    /// Startup or re-attestation is in progress.
    Attesting,
    /// CMIS cannot be reached; the daemon keeps retrying.
    CmisUnreachable,
    /// CMIS refused this host (not enrolled / rejected).
    NotEnrolled,
    /// The CMIS certificate did not match the configured SPKI pin.
    PinMismatch,
    /// The TPM backend is selected but the TPM is missing or unusable.
    TpmUnavailable,
    /// Linux IMA appraisal is required but not enforced (client-side: the
    /// daemon refuses to start in this state).
    ImaDisabled,
    /// The cached CRL is older than 5 minutes; minting is refused.
    CrlStale,
    /// No allowlist is loaded; every caller (other than `mia`) is denied.
    AllowlistMissing,
    /// The allowlist failed verification or expired; every caller is denied.
    AllowlistInvalid,
    /// The SVID is past its renewal point (or expired) and has not been
    /// renewed.
    SvidExpiring,
    /// SVID valid, CRL fresh, allowlist loaded.
    Healthy,
}

impl AgentState {
    /// Every state, in declaration order (for exhaustive tests and UIs).
    pub const ALL: [Self; 14] = [
        Self::NotInstalled,
        Self::NotRunning,
        Self::NotConfigured,
        Self::Attesting,
        Self::CmisUnreachable,
        Self::NotEnrolled,
        Self::PinMismatch,
        Self::TpmUnavailable,
        Self::ImaDisabled,
        Self::CrlStale,
        Self::AllowlistMissing,
        Self::AllowlistInvalid,
        Self::SvidExpiring,
        Self::Healthy,
    ];

    /// Whether this is [`AgentState::Healthy`].
    #[must_use]
    pub fn is_healthy(self) -> bool {
        self == Self::Healthy
    }

    /// Severity for "worst state wins": `0` healthy, `1` transient
    /// (attesting), `2` degraded (yellow), `3` broken (red), `4` absent /
    /// unconfigured (grey).
    #[must_use]
    pub fn severity(self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Attesting => 1,
            Self::CmisUnreachable
            | Self::CrlStale
            | Self::AllowlistMissing
            | Self::AllowlistInvalid
            | Self::SvidExpiring => 2,
            Self::NotEnrolled | Self::PinMismatch | Self::TpmUnavailable | Self::ImaDisabled => 3,
            Self::NotInstalled | Self::NotRunning | Self::NotConfigured => 4,
        }
    }

    /// The stable snake_case name used on the wire and in `mia status`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::NotRunning => "not_running",
            Self::NotConfigured => "not_configured",
            Self::Attesting => "attesting",
            Self::CmisUnreachable => "cmis_unreachable",
            Self::NotEnrolled => "not_enrolled",
            Self::PinMismatch => "pin_mismatch",
            Self::TpmUnavailable => "tpm_unavailable",
            Self::ImaDisabled => "ima_disabled",
            Self::CrlStale => "crl_stale",
            Self::AllowlistMissing => "allowlist_missing",
            Self::AllowlistInvalid => "allowlist_invalid",
            Self::SvidExpiring => "svid_expiring",
            Self::Healthy => "healthy",
        }
    }
}

/// The host SVID's public identity and lifetime. Never the SVID itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvidSummary {
    /// The SVID subject (`spiffe://<td>/host/<uuid>`).
    pub spiffe_id: String,
    /// Expiry, Unix seconds.
    pub not_after: i64,
    /// The proactive renewal point (60% of the TTL), Unix seconds.
    pub renew_at: i64,
}

/// The attestation backend an environment uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestBackend {
    /// `auto`, not resolved yet (no attestation attempted so far).
    Auto,
    /// The genuine TPM 2.0 path.
    Tpm,
    /// The TPM-less host-key profile.
    HostKey,
    /// The INSECURE dev/test software TPM.
    VirtualTpm,
}

/// The caller allowlist's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistState {
    /// Not configured, or no file present: every caller is denied.
    Missing,
    /// A verified allowlist is loaded. Counts only — never the entries.
    Loaded {
        /// Number of distinct allowlist entries (binary hashes plus any
        /// binary wildcard).
        entries: u32,
        /// Hard expiry CMIS stamped, Unix seconds.
        not_after: i64,
    },
    /// Present but failed verification, or expired: every caller is denied.
    Invalid,
}

/// Where the machine-bound X.509-SVID store is sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoreBackend {
    /// Sealed to the TPM.
    Tpm,
    /// Sealed under the fingerprint-derived machine key.
    MachineKey,
    /// Sealed to a macOS Secure Enclave key.
    SecureEnclave,
}

impl StoreBackend {
    /// Map the credential store's backend name (`credstore` `Sealer::name`)
    /// to the wire enum; `None` for a name this version does not know.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "tpm" => Some(Self::Tpm),
            "machine-key" => Some(Self::MachineKey),
            "secure-enclave" => Some(Self::SecureEnclave),
            _ => None,
        }
    }
}

/// A stable error code plus a short, fixed human message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorSummary {
    /// Stable code (see [`error_codes`]); unknown codes must be rendered
    /// generically by clients.
    pub code: String,
    /// Short, fixed message.
    pub message: String,
}

/// The stable [`ErrorSummary::code`] values the daemon emits today. Clients
/// must tolerate codes not listed here (newer daemons).
pub mod error_codes {
    /// No CMIS source (`cmis.endpoint` / `cmis.srv`) is configured.
    pub const CMIS_NOT_CONFIGURED: &str = "cmis_not_configured";
    /// The CMIS configuration is unusable (both sources, or a bad pin).
    pub const CMIS_MISCONFIGURED: &str = "cmis_misconfigured";
    /// The helper API is not served for this environment: switched off
    /// (`helper.enable = false`), or its socket duplicates another
    /// environment's. (An unset `helper.socket` no longer causes this — it
    /// falls back to the platform default.) The wire value is unchanged.
    pub const HELPER_NOT_CONFIGURED: &str = "helper_not_configured";
    /// CMIS could not be reached.
    pub const CMIS_UNREACHABLE: &str = "cmis_unreachable";
    /// Attestation failed for a reason other than the ones below.
    pub const ATTESTATION_FAILED: &str = "attestation_failed";
    /// CMIS refused this host (`HostRejected`).
    pub const HOST_REJECTED: &str = "host_rejected";
    /// The CMIS certificate did not match the SPKI pin.
    pub const PIN_MISMATCH: &str = "pin_mismatch";
    /// The TPM (or the selected TPM-class backend) is unavailable.
    pub const TPM_UNAVAILABLE: &str = "tpm_unavailable";
    /// The host's machine key (or SVID seed) exists but cannot be used —
    /// wrong owner or mode, unreadable, not a regular file, refused by the
    /// Windows trust check, or not openable on this host — and the agent
    /// refuses to replace it. An operator must repair or restore the file; the
    /// daemon log names the file and the fix.
    pub const MACHINE_KEY_REFUSED: &str = "machine_key_refused";
    /// IMA appraisal is required but not enforced.
    pub const IMA_DISABLED: &str = "ima_disabled";
    /// The cached CRL is stale or absent.
    pub const CRL_STALE: &str = "crl_stale";
    /// No allowlist is loaded.
    pub const ALLOWLIST_MISSING: &str = "allowlist_missing";
    /// The allowlist failed verification.
    pub const ALLOWLIST_INVALID: &str = "allowlist_invalid";
    /// The allowlist has expired.
    pub const ALLOWLIST_EXPIRED: &str = "allowlist_expired";
    /// The SVID is past its renewal point.
    pub const SVID_RENEWAL_DUE: &str = "svid_renewal_due";
    /// The SVID has expired.
    pub const SVID_EXPIRED: &str = "svid_expired";
    /// The status endpoint is absent (client-side).
    pub const NOT_RUNNING: &str = "not_running";
}

// ── Logs ─────────────────────────────────────────────────────────────────────

/// A log level. Ordered from most to least severe, so `a <= b` means "`a` is
/// at least as severe as `b`".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Errors.
    Error,
    /// Warnings.
    Warn,
    /// Informational.
    Info,
    /// Debug detail.
    Debug,
    /// Trace detail.
    Trace,
}

impl Level {
    /// Whether a record at `self` passes a `min_level` filter (is at least as
    /// severe as `min_level`).
    #[must_use]
    pub fn passes(self, min_level: Self) -> bool {
        self <= min_level
    }

    /// The lowercase level name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// One redacted log record from the daemon's ring buffer. Redaction happens
/// in the daemon *before* a record is buffered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// Monotonic sequence number (per daemon run; see
    /// [`LogTailResp::buffer_id`]).
    pub seq: u64,
    /// Wall-clock timestamp, Unix milliseconds.
    pub ts_ms: i64,
    /// Severity.
    pub level: Level,
    /// The `tracing` target (module path).
    pub target: String,
    /// The environment the record was logged under, if any.
    pub environment: Option<String>,
    /// The (redacted, escaped, truncated) message.
    pub message: String,
    /// The (redacted, escaped, truncated) structured fields.
    pub fields: Vec<LogField>,
}

/// One structured field of a [`LogRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogField {
    /// The field name.
    pub name: String,
    /// The rendered value (or a redaction marker).
    pub value: String,
}

/// A slice of the log ring buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogTailResp {
    /// Matching records, oldest first.
    pub records: Vec<LogRecord>,
    /// The `since_seq` to send next to continue without duplicates.
    pub next_seq: u64,
    /// Records between the requested `since_seq` and the oldest record still
    /// buffered that were evicted before this read — a gap to report.
    pub dropped: u64,
    /// Identifies this daemon run's buffer. A change means the daemon
    /// restarted and `seq` started over: reset `since_seq` to `0`.
    pub buffer_id: u64,
}

// ── Framing ──────────────────────────────────────────────────────────────────

/// Framing / codec failures.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A frame exceeded [`MAX_FRAME_LEN`].
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    /// CBOR encoding failed.
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding failed (or decoded to an unexpected shape).
    #[error("cbor decode: {0}")]
    Decode(String),
}

/// Encode `value` as one complete frame (4-byte big-endian length + CBOR).
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let mut body = Vec::with_capacity(256);
    ciborium::into_writer(value, &mut body).map_err(|e| FrameError::Encode(e.to_string()))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len()))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a frame *body* (the bytes after the length prefix). Rejects bodies
/// larger than [`MAX_FRAME_LEN`] before parsing.
pub fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len()));
    }
    ciborium::from_reader(body).map_err(|e| FrameError::Decode(e.to_string()))
}

/// Decode a request body. This is the status endpoint's entire untrusted-input
/// parser (the fuzz/property-test target): it never panics, rejects oversize
/// input up front, and accepts only the closed [`StatusRequest`] set.
pub fn decode_request(body: &[u8]) -> Result<StatusRequest, FrameError> {
    decode_body(body)
}

/// Parse the 4-byte big-endian length prefix, rejecting a declared length over
/// [`MAX_FRAME_LEN`] (so a hostile peer cannot make the reader allocate).
pub fn frame_len(prefix: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

/// Serialize `value` and write it as one frame (blocking).
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<(), FrameError> {
    let frame = encode_frame(value)?;
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

/// Read one frame and decode it (blocking).
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let mut prefix = [0u8; 4];
    r.read_exact(&mut prefix)?;
    let len = frame_len(prefix)?;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    decode_body(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_snapshot() -> StatusSnapshot {
        StatusSnapshot {
            environment: Some("staging".into()),
            state: AgentState::Healthy,
            since: 1_700_000_000,
            svid: Some(SvidSummary {
                spiffe_id: "spiffe://ferrogate.test/host/11111111-1111-8111-8111-111111111111"
                    .into(),
                not_after: 1_700_003_600,
                renew_at: 1_700_002_160,
            }),
            attest_backend: AttestBackend::HostKey,
            cmis_node: Some("cmis1.example.com:8443".into()),
            crl_age_secs: Some(42),
            allowlist: AllowlistState::Loaded {
                entries: 3,
                not_after: 1_700_086_400,
            },
            x509_store: Some(StoreBackend::MachineKey),
            last_error: Some(ErrorSummary {
                code: error_codes::CRL_STALE.into(),
                message: "the cached CRL is stale".into(),
            }),
            version: "0.0.0-test".into(),
            default_address: true,
        }
    }

    /// Collect every object key in a JSON value, recursively, as dotted paths.
    fn keys(v: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
        if let serde_json::Value::Object(map) = v {
            for (k, child) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                out.push(path.clone());
                keys(child, &path, out);
            }
        }
    }

    #[test]
    fn status_snapshot_has_no_secret_fields() {
        // Serialise a fully-populated snapshot and pin its exact key set. A new
        // field fails this test until it is added here — the review point the
        // F18 spec asks for.
        let json = serde_json::to_value(full_snapshot()).unwrap();
        let mut found = Vec::new();
        keys(&json, "", &mut found);
        found.sort();
        let mut expected = vec![
            "allowlist",
            "allowlist.loaded",
            "allowlist.loaded.entries",
            "allowlist.loaded.not_after",
            "attest_backend",
            "cmis_node",
            "crl_age_secs",
            "default_address",
            "environment",
            "last_error",
            "last_error.code",
            "last_error.message",
            "since",
            "state",
            "svid",
            "svid.not_after",
            "svid.renew_at",
            "svid.spiffe_id",
            "version",
            "x509_store",
        ];
        expected.sort_unstable();
        assert_eq!(found, expected);

        // And no key anywhere names secret material.
        for k in &found {
            let leaf = k.rsplit('.').next().unwrap().to_ascii_lowercase();
            for banned in [
                "jws", "token", "key", "secret", "pin", "jti", "sig", "pid", "uid", "bin_sha",
                "dpop", "jwk", "pkcs8", "der", "seed",
            ] {
                assert!(
                    !leaf.contains(banned),
                    "snapshot field {k:?} looks sensitive ({banned})"
                );
            }
        }
    }

    #[test]
    fn requests_and_responses_roundtrip() {
        for req in [
            StatusRequest::Status(StatusReq { environment: None }),
            StatusRequest::Status(StatusReq {
                environment: Some("prod".into()),
            }),
            StatusRequest::LogTail(LogTailReq {
                since_seq: 7,
                min_level: Level::Warn,
                max: 100,
            }),
        ] {
            let frame = encode_frame(&req).unwrap();
            let back: StatusRequest = read_frame(&mut &frame[..]).unwrap();
            assert_eq!(req, back);
        }
        let resp = StatusResponse::Status(vec![full_snapshot()]);
        let frame = encode_frame(&resp).unwrap();
        let back: StatusResponse = read_frame(&mut &frame[..]).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn snapshot_from_an_older_daemon_has_no_default_address() {
        // A daemon predating `default_address` omits it; it decodes as false.
        let mut json = serde_json::to_value(full_snapshot()).unwrap();
        json.as_object_mut().unwrap().remove("default_address");
        let mut body = Vec::new();
        ciborium::into_writer(&json, &mut body).unwrap();
        let old: StatusSnapshot = decode_body(&body).unwrap();
        assert!(!old.default_address);
    }

    #[test]
    fn helper_request_shape_is_rejected() {
        // A helper-API `HelperReq` (a bare map) sent to the status endpoint
        // must not decode as any status request.
        #[derive(Serialize)]
        struct HelperReq {
            audience: String,
            dpop_jkt: String,
            ttl_secs: u32,
        }
        let mut body = Vec::new();
        ciborium::into_writer(
            &HelperReq {
                audience: "https://api.example.com".into(),
                dpop_jkt: "abc".into(),
                ttl_secs: 60,
            },
            &mut body,
        )
        .unwrap();
        assert!(matches!(decode_request(&body), Err(FrameError::Decode(_))));
        // Nor does an unknown variant or an extra field.
        let mut body = Vec::new();
        ciborium::into_writer(
            &std::collections::BTreeMap::from([("set_config", 1u8)]),
            &mut body,
        )
        .unwrap();
        assert!(decode_request(&body).is_err());
    }

    #[test]
    fn oversize_frames_are_rejected() {
        let huge = u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
        assert!(matches!(
            read_frame::<_, StatusRequest>(&mut &huge[..]),
            Err(FrameError::TooLarge(_))
        ));
        assert!(matches!(
            decode_request(&vec![0u8; MAX_FRAME_LEN + 1]),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn state_names_and_severity_are_stable() {
        for s in AgentState::ALL {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
        assert!(AgentState::Healthy.is_healthy());
        assert!(AgentState::PinMismatch.severity() > AgentState::CrlStale.severity());
        assert!(AgentState::NotRunning.severity() > AgentState::PinMismatch.severity());
    }

    #[test]
    fn level_filter_orders_by_severity() {
        assert!(Level::Error.passes(Level::Warn));
        assert!(Level::Warn.passes(Level::Warn));
        assert!(!Level::Info.passes(Level::Warn));
        assert!(Level::Debug.passes(Level::Trace));
    }

    #[test]
    fn environment_names_are_validated() {
        for ok in ["prod", "staging-eu", "a.b_c", "X1", "-x"] {
            assert_eq!(validate_environment(ok), Ok(()), "{ok:?}");
        }
        assert_eq!(validate_environment(""), Err(EnvironmentNameError::Empty));
        assert_eq!(
            validate_environment("."),
            Err(EnvironmentNameError::DotName)
        );
        assert_eq!(
            validate_environment(".."),
            Err(EnvironmentNameError::DotName)
        );
        for bad in ["../x", "a/b", "a b", "é", "a\\b", "a\0", "a\n"] {
            assert_eq!(
                validate_environment(bad),
                Err(EnvironmentNameError::InvalidCharacter),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn store_backend_names_map() {
        assert_eq!(StoreBackend::from_name("tpm"), Some(StoreBackend::Tpm));
        assert_eq!(
            StoreBackend::from_name("machine-key"),
            Some(StoreBackend::MachineKey)
        );
        assert_eq!(StoreBackend::from_name("nope"), None);
    }

    proptest::proptest! {
        /// The request decoder is the endpoint's untrusted-input parser: it
        /// must never panic on arbitrary bytes, and must reject oversize input.
        #[test]
        fn decode_request_never_panics(body in proptest::collection::vec(proptest::num::u8::ANY, 0..2048)) {
            let _ = decode_request(&body);
        }

        /// Arbitrary length prefixes are either accepted (≤ MAX_FRAME_LEN) or
        /// rejected without allocating.
        #[test]
        fn frame_len_is_bounded(prefix in proptest::array::uniform4(proptest::num::u8::ANY)) {
            match frame_len(prefix) {
                Ok(n) => proptest::prop_assert!(n <= MAX_FRAME_LEN),
                Err(FrameError::TooLarge(n)) => proptest::prop_assert!(n > MAX_FRAME_LEN),
                Err(e) => proptest::prop_assert!(false, "unexpected error {e}"),
            }
        }
    }
}
