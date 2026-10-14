//! Admin session primitives (F20 §7): opaque bearer tokens, their at-rest
//! hash, lifetimes and revocation reasons.
//!
//! A token is `fgas_` followed by base64url of 32 CSPRNG bytes. Only
//! `SHA-256(token)` is stored; the token travels only in the `authorization:
//! Bearer` metadata of the admin TLS channel and is never logged.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use ferro_raft::admin::AdminSessionRow;

use super::codec::b64url;

/// Session-token prefix.
pub const TOKEN_PREFIX: &str = "fgas_";
/// Length of a well-formed token: prefix plus 43 base64url characters.
pub const TOKEN_LEN: usize = TOKEN_PREFIX.len() + 43;
/// Idle timeout ceiling (15 min); configurable lower, never higher.
pub const MAX_IDLE_SECS: i64 = 900;
/// Absolute lifetime ceiling (12 h); configurable lower, never higher.
pub const MAX_ABSOLUTE_SECS: i64 = 12 * 3600;
/// `last_seen_at` is written at most this often.
pub const TOUCH_INTERVAL_SECS: i64 = 60;
/// Live sessions per account; a new login evicts the oldest.
pub const MAX_SESSIONS_PER_ACCOUNT: usize = 5;
/// Failed step-ups (or per-operation proofs) that revoke the session.
pub const MAX_STEP_UP_FAILURES: i64 = 5;

/// `ClientInfo.kind` of the server TUI (F21).
pub const CLIENT_TUI: i64 = 1;
/// `ClientInfo.kind` of the tray admin client (F22), the only client with
/// local access to a FIDO2 authenticator.
pub const CLIENT_TRAY: i64 = 2;
/// `ClientInfo.kind` of the `ferrogate` CLI.
pub const CLIENT_CLI: i64 = 3;

/// Second-factor method of a verification (`admin_sessions.mfa_method`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaMethod {
    /// RFC 6238 TOTP (AAL2).
    Totp = 1,
    /// FIDO2 / WebAuthn (AAL3 when device-bound, AAL2 for a synced passkey).
    WebAuthn = 2,
}

impl MfaMethod {
    /// Stored integer.
    #[must_use]
    pub fn code(self) -> i64 {
        self as i64
    }

    /// Stable label for audit events.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::WebAuthn => "webauthn",
        }
    }

    /// Highest authenticator assurance level a verification this way can
    /// reach (a backup-eligible WebAuthn credential reaches only AAL2; see
    /// [`super::webauthn::aal`]).
    #[must_use]
    pub fn aal(self) -> i64 {
        match self {
            Self::Totp => 2,
            Self::WebAuthn => 3,
        }
    }
}

/// Why a session ended (`admin_sessions.revoked_reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeReason {
    /// The holder logged out.
    Logout = 1,
    /// The holder revoked it from another session.
    ByUser = 2,
    /// An account administrator revoked it.
    ByAdmin = 3,
    /// A call arrived from another IP.
    IpMismatch = 4,
    /// Idle timeout.
    Idle = 5,
    /// Absolute lifetime.
    Absolute = 6,
    /// Evicted by a newer login beyond the per-account cap.
    Evicted = 7,
    /// The password changed.
    PasswordChanged = 8,
    /// The account was disabled.
    AccountDisabled = 9,
    /// The account's credentials were reset.
    CredentialsReset = 10,
    /// The account's groups changed.
    GroupsChanged = 11,
    /// Too many failed step-ups.
    StepUpFailures = 12,
    /// The mTLS client certificate changed.
    CertMismatch = 13,
    /// The account is no longer active.
    AccountInactive = 14,
    /// The holder removed a second factor (other sessions end).
    FactorRemoved = 15,
}

impl RevokeReason {
    /// Stored integer.
    #[must_use]
    pub fn code(self) -> i64 {
        self as i64
    }

    /// Stable label for audit events and logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Logout => "logout",
            Self::ByUser => "revoked_by_user",
            Self::ByAdmin => "revoked_by_admin",
            Self::IpMismatch => "ip_mismatch",
            Self::Idle => "idle_timeout",
            Self::Absolute => "absolute_timeout",
            Self::Evicted => "evicted",
            Self::PasswordChanged => "password_changed",
            Self::AccountDisabled => "account_disabled",
            Self::CredentialsReset => "credentials_reset",
            Self::GroupsChanged => "groups_changed",
            Self::StepUpFailures => "step_up_failures",
            Self::CertMismatch => "client_cert_mismatch",
            Self::AccountInactive => "account_inactive",
            Self::FactorRemoved => "factor_removed",
        }
    }
}

/// A new random session token and its stored hash.
///
/// # Panics
///
/// Panics if the operating system's random source fails.
#[must_use]
pub fn new_token() -> (Zeroizing<String>, Vec<u8>) {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut()).expect("OS random source");
    let token = Zeroizing::new(format!("{TOKEN_PREFIX}{}", b64url(raw.as_ref())));
    let hash = hash_token(&token);
    (token, hash)
}

/// The at-rest form of a token.
#[must_use]
pub fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Extract a well-formed session token from an `authorization` header value
/// (`Bearer fgas_…`). Anything else is `None` and is treated exactly like a
/// missing token.
#[must_use]
pub fn bearer_token(header: &[u8]) -> Option<Zeroizing<String>> {
    let text = std::str::from_utf8(header).ok()?;
    let token = text.strip_prefix("Bearer ")?;
    let well_formed = token.len() == TOKEN_LEN
        && token.starts_with(TOKEN_PREFIX)
        && token[TOKEN_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    well_formed.then(|| Zeroizing::new(token.to_string()))
}

/// Short, non-secret reference to a session for audit events and session
/// lists: the first 12 bytes of the token hash, hex.
#[must_use]
pub fn session_ref(session_hash: &[u8]) -> String {
    hex::encode(&session_hash[..session_hash.len().min(12)])
}

/// Whether a stored session may still be used at `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Usable.
    Live,
    /// Already revoked.
    Revoked,
    /// Idle too long.
    Idle,
    /// Past its absolute lifetime.
    Absolute,
}

/// Classify a stored session at `now`.
#[must_use]
pub fn liveness(row: &AdminSessionRow, now: i64) -> Liveness {
    if row.revoked_at.is_some() {
        Liveness::Revoked
    } else if now >= row.absolute_expires_at {
        Liveness::Absolute
    } else if now.saturating_sub(row.last_seen_at) > row.idle_timeout_secs {
        Liveness::Idle
    } else {
        Liveness::Live
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(last_seen: i64, absolute: i64) -> AdminSessionRow {
        AdminSessionRow {
            session_hash: vec![1; 32],
            admin_id: "a".into(),
            created_at: 0,
            last_seen_at: last_seen,
            absolute_expires_at: absolute,
            idle_timeout_secs: 900,
            aal: 2,
            mfa_at: 0,
            mfa_method: 1,
            source_ip: "127.0.0.1".into(),
            client_cert_sha256: None,
            client_kind: 3,
            client_version: None,
            restricted: 0,
            revoked_at: None,
            revoked_reason: None,
            stepup_failures: 0,
        }
    }

    #[test]
    fn tokens_are_prefixed_random_and_only_their_hash_is_kept() {
        let (a, ha) = new_token();
        let (b, hb) = new_token();
        assert!(a.starts_with(TOKEN_PREFIX) && a.len() == TOKEN_LEN);
        assert_ne!(*a, *b);
        assert_eq!(ha, hash_token(&a));
        assert_ne!(ha, hb);
        assert_eq!(ha.len(), 32);
    }

    #[test]
    fn bearer_parsing_is_strict() {
        let (tok, _) = new_token();
        let header = format!("Bearer {}", tok.as_str());
        assert_eq!(
            bearer_token(header.as_bytes()).as_ref().map(|t| t.as_str()),
            Some(tok.as_str())
        );
        for bad in [
            String::new(),
            tok.to_string(),
            format!("bearer {}", tok.as_str()),
            format!("Bearer  {}", tok.as_str()),
            format!("Bearer {}x", tok.as_str()),
            format!("Bearer fgxx_{}", &tok[5..]),
            format!("Bearer {}!", &tok[..TOKEN_LEN - 1]),
        ] {
            assert!(bearer_token(bad.as_bytes()).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn idle_and_absolute_expiry() {
        let r = row(1_000, 5_000);
        assert_eq!(liveness(&r, 1_000 + 900), Liveness::Live);
        assert_eq!(liveness(&r, 1_000 + 901), Liveness::Idle);
        let r = row(4_999, 5_000);
        assert_eq!(liveness(&r, 5_000), Liveness::Absolute);
        let mut r = row(1_000, 5_000);
        r.revoked_at = Some(1_001);
        assert_eq!(liveness(&r, 1_002), Liveness::Revoked);
    }

    #[test]
    fn session_refs_do_not_reveal_the_hash() {
        let (_, h) = new_token();
        let r = session_ref(&h);
        assert_eq!(r.len(), 24);
        assert_ne!(r, hex::encode(&h));
    }
}
