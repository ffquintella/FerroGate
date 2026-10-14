//! Single-use enrollment tokens and first-account bootstrap (F20 §9).
//!
//! A token is a prefix (`fgbt_` bootstrap, `fget_` enrollment/reset) followed
//! by base32 of 32 CSPRNG bytes and a 4-byte checksum, so a mistyped token is
//! recognised before it costs a throttle failure. Only `SHA-256` of the 32
//! random bytes is stored.
//!
//! **Bootstrap.** At start, when no account exists, bootstrap never completed
//! and no unexpired bootstrap token exists, the Raft leader writes a fresh
//! token to `CMIS_ADMIN_BOOTSTRAP_TOKEN_FILE` (`O_EXCL`, `0400`) valid for 24
//! hours and logs **only the path**. Redeeming it (`ferrogate admin bootstrap`
//! on that node) creates the first account; CMIS then records
//! `cmis_settings.admin_bootstrapped = 1`, removes the file and never re-arms.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use ferro_raft::admin::{EnrollmentTokenRow, TOKEN_BOOTSTRAP};

use super::codec::{base32_decode, base32_encode};
use super::keys::write_new_secret_file;
use super::state::AdminState;

/// Bootstrap-token prefix.
pub const BOOTSTRAP_PREFIX: &str = "fgbt_";
/// Enrollment and reset token prefix.
pub const ENROLLMENT_PREFIX: &str = "fget_";
/// Bootstrap token lifetime.
pub const BOOTSTRAP_TTL_SECS: i64 = 24 * 3600;
/// Default enrollment-token lifetime.
pub const ENROLLMENT_DEFAULT_TTL_SECS: i64 = 24 * 3600;
/// Longest enrollment-token lifetime.
pub const ENROLLMENT_MAX_TTL_SECS: i64 = 72 * 3600;
/// `cmis_settings` key recording a completed bootstrap.
pub const BOOTSTRAPPED_KEY: &str = "admin_bootstrapped";

fn checksum(raw: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"ferrogate-admin-token-v1");
    h.update(raw);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// A new token with `prefix`, and the hash stored for it.
///
/// # Panics
///
/// Panics if the operating system's random source fails.
#[must_use]
pub fn new_token(prefix: &str) -> (Zeroizing<String>, Vec<u8>) {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut()).expect("OS random source");
    let mut body = Zeroizing::new(raw.to_vec());
    body.extend_from_slice(&checksum(raw.as_ref()));
    let token = Zeroizing::new(format!("{prefix}{}", base32_encode(&body)));
    (token, Sha256::digest(raw.as_ref()).to_vec())
}

/// The stored hash of a well-formed token (either prefix); `None` when
/// malformed or the checksum fails.
#[must_use]
pub fn token_hash(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() > 128 {
        return None;
    }
    let body = text
        .strip_prefix(BOOTSTRAP_PREFIX)
        .or_else(|| text.strip_prefix(ENROLLMENT_PREFIX))?;
    let bytes = Zeroizing::new(base32_decode(body)?);
    if bytes.len() != 36 || checksum(&bytes[..32]) != bytes[32..] {
        return None;
    }
    Some(Sha256::digest(&bytes[..32]).to_vec())
}

/// What arming the bootstrap did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// A token was written to this path.
    Armed(PathBuf),
    /// Bootstrap already completed; it never re-arms.
    AlreadyBootstrapped,
    /// Accounts exist.
    AccountsExist,
    /// An unexpired bootstrap token already exists.
    TokenLive,
    /// This node is not the Raft leader.
    NotLeader,
}

/// Arm the first-account bootstrap if the cluster needs one (see the module
/// docs). Logs the token path only, never the token.
pub async fn arm(state: &AdminState) -> anyhow::Result<BootstrapOutcome> {
    let cluster = state.cluster();
    if cluster.setting(BOOTSTRAPPED_KEY).await?.as_deref() == Some("1") {
        return Ok(BootstrapOutcome::AlreadyBootstrapped);
    }
    if cluster.admin_account_count().await? > 0 {
        return Ok(BootstrapOutcome::AccountsExist);
    }
    if !cluster.is_leader().await {
        return Ok(BootstrapOutcome::NotLeader);
    }
    let now = state.now();
    if cluster
        .admin_live_token_exists(TOKEN_BOOTSTRAP, now)
        .await?
    {
        return Ok(BootstrapOutcome::TokenLive);
    }
    let path = state.config().bootstrap_token_file.clone();
    let (token, hash) = new_token(BOOTSTRAP_PREFIX);
    // No live token exists, so a file at the path is stale: replace it.
    remove_token_file(&path);
    let mut contents = Zeroizing::new(token.as_bytes().to_vec());
    contents.push(b'\n');
    write_new_secret_file(&path, &contents)
        .map_err(|e| anyhow::anyhow!("writing bootstrap token file {}: {e}", path.display()))?;
    let row = EnrollmentTokenRow {
        token_hash: hash,
        admin_id: None,
        purpose: TOKEN_BOOTSTRAP,
        created_by_admin_id: None,
        created_at: now,
        expires_at: now + BOOTSTRAP_TTL_SECS,
        used_at: None,
        pending_secret_enc: None,
    };
    if let Err(e) = cluster.admin_insert_enrollment_token(&row).await {
        remove_token_file(&path);
        return Err(e.into());
    }
    tracing::warn!(
        event = "admin.bootstrap.armed",
        path = %path.display(),
        "no administrator exists: a single-use bootstrap token was written (valid 24 h); \
         run `ferrogate admin bootstrap --token-file <path>` on this node"
    );
    Ok(BootstrapOutcome::Armed(path))
}

/// Remove a bootstrap token file, ignoring absence.
pub fn remove_token_file(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "could not remove bootstrap token file");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_and_reject_typos() {
        let (tok, hash) = new_token(ENROLLMENT_PREFIX);
        assert!(tok.starts_with(ENROLLMENT_PREFIX));
        assert_eq!(token_hash(&tok), Some(hash.clone()));
        assert_eq!(
            token_hash(&format!("  {}\n", tok.as_str())),
            Some(hash),
            "file whitespace"
        );
        // Flip one base32 character: the checksum catches it.
        let mut chars: Vec<char> = tok.chars().collect();
        let i = ENROLLMENT_PREFIX.len() + 3;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(token_hash(&typo), None);
        assert_eq!(token_hash("fget_"), None);
        assert_eq!(
            token_hash("fgas_abc"),
            None,
            "session tokens are not enrollment tokens"
        );
    }

    #[test]
    fn bootstrap_and_enrollment_tokens_differ() {
        let (a, ha) = new_token(BOOTSTRAP_PREFIX);
        let (b, hb) = new_token(BOOTSTRAP_PREFIX);
        assert_ne!(*a, *b);
        assert_ne!(ha, hb);
    }
}
