//! Administrator passwords (F20 §4): the FGV administrative password policy
//! and Argon2id hashing with an optional pepper.
//!
//! - **Policy** ([`check_policy`]): at least 24 and at most 256 Unicode scalar
//!   values after NFKC (never truncated), all four character classes, no
//!   control characters, none of the forbidden substrings (username,
//!   display-name tokens, product and organisation names, the trust domain,
//!   the current year), and not on the blocklist. Reuse of any earlier
//!   password is checked separately against the history hashes.
//! - **Hashing** ([`PasswordHasher`]): Argon2id, `m = 64 MiB, t = 3, p = 4`, a
//!   16-byte salt from the OS CSPRNG and a 32-byte output in a PHC string (RFC
//!   9106 §4, second recommended option). With a pepper configured the Argon2
//!   input is `HMAC-SHA-256(pepper, NFKC(password))`. Parameters are read back
//!   from the PHC string, and a hash weaker than the configured parameters is
//!   flagged for rehash on the next successful login. At most four
//!   verifications run at once; waiting longer than five seconds fails with
//!   [`PasswordError::Busy`]. Unknown accounts verify against a dummy hash so
//!   the timing does not reveal whether the account exists.
//!
//! Passwords are held in [`Zeroizing`] buffers and never logged.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{KeyInit, Mac};
use tokio::sync::Semaphore;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Minimum password length for administrative credentials (G-002).
pub const MIN_LEN: usize = 24;
/// Maximum accepted password length; longer is rejected, never truncated.
pub const MAX_LEN: usize = 256;
/// Password lifetime (NRM §5.3.8: rotation every six months).
pub const LIFETIME_SECS: i64 = 180 * 86_400;
/// Concurrent Argon2 verifications (64 MiB each, 256 MiB peak).
pub const MAX_CONCURRENT: usize = 4;
/// Longest wait for a verification slot before answering `auth_busy`.
pub const MAX_WAIT: Duration = Duration::from_secs(5);

/// Substrings no administrative password may contain (case-insensitive).
const FORBIDDEN: &[&str] = &["ferrogate", "fgv", "senha", "password", "cmis"];

/// A small embedded blocklist of long, policy-shaped passwords that appear in
/// public breach corpora and password-manager "examples". The operator
/// supplies the full corpus (≥ 100k entries) through
/// `CMIS_ADMIN_PASSWORD_BLOCKLIST_FILE`; see [`Blocklist::from_file`].
const EMBEDDED_BLOCKLIST: &[&str] = &[
    "Password1234567890!@#$%^",
    "P@ssw0rdP@ssw0rdP@ssw0rd",
    "Qwertyuiop1234567890!@#$",
    "Qwerty123456789!Qwerty123456789!",
    "Correct-Horse-Battery-Staple-1",
    "CorrectHorseBatteryStaple1!",
    "Abcdefghijklmnopqrstuvwxyz1!",
    "Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!",
    "Admin123456789012345678!",
    "Administrator1234567890!",
    "Changeme!Changeme!Changeme1",
    "Welcome1!Welcome1!Welcome1!",
];

/// Why a candidate password was refused. The ids travel to the client in
/// `x-ferrogate-policy-failures`; the password itself is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyFailure {
    /// Fewer than [`MIN_LEN`] characters.
    TooShort,
    /// More than [`MAX_LEN`] characters.
    TooLong,
    /// Contains control characters.
    ControlCharacters,
    /// Missing one of upper case, lower case, digit, symbol.
    CharacterClasses,
    /// Contains a forbidden substring.
    ForbiddenContent,
    /// On the blocklist.
    Blocklisted,
    /// Equal to an earlier password of the account.
    Reused,
}

impl PolicyFailure {
    /// Stable rule id.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::TooShort => "password_too_short",
            Self::TooLong => "password_too_long",
            Self::ControlCharacters => "control_characters",
            Self::CharacterClasses => "character_classes",
            Self::ForbiddenContent => "forbidden_content",
            Self::Blocklisted => "blocklisted",
            Self::Reused => "reused",
        }
    }
}

/// Case-insensitive set of forbidden whole passwords.
#[derive(Debug, Clone)]
pub struct Blocklist(HashSet<String>);

impl Blocklist {
    /// The small embedded list only.
    #[must_use]
    pub fn embedded() -> Self {
        Self(
            EMBEDDED_BLOCKLIST
                .iter()
                .map(|p| normalize(p).to_lowercase())
                .collect(),
        )
    }

    /// The embedded list plus one password per line of `path` (blank lines
    /// ignored). Used for the operator-supplied breach corpus.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut list = Self::embedded();
        for line in text.lines().map(str::trim_end).filter(|l| !l.is_empty()) {
            list.0.insert(normalize(line).to_lowercase());
        }
        Ok(list)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn contains(&self, normalized_lower: &str) -> bool {
        self.0.contains(normalized_lower)
    }
}

/// What the policy compares a candidate against.
#[derive(Debug, Clone, Copy)]
pub struct PolicyContext<'a> {
    /// Normalised username of the account.
    pub username: &'a str,
    /// Display name, if any.
    pub display_name: Option<&'a str>,
    /// SPIFFE trust domain of the deployment.
    pub trust_domain: &'a str,
    /// Current calendar year.
    pub year: i32,
    /// Forbidden whole passwords.
    pub blocklist: &'a Blocklist,
}

/// NFKC-normalise a password (the form that is counted, checked and hashed).
#[must_use]
pub fn normalize(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.nfkc().collect())
}

/// Check `password` against the policy. Returns every failed rule, sorted.
pub fn check_policy(password: &str, ctx: &PolicyContext<'_>) -> Result<(), Vec<PolicyFailure>> {
    let normalized = normalize(password);
    let lower = Zeroizing::new(normalized.to_lowercase());
    let mut failures = Vec::new();

    let len = normalized.chars().count();
    if len < MIN_LEN {
        failures.push(PolicyFailure::TooShort);
    }
    if len > MAX_LEN {
        failures.push(PolicyFailure::TooLong);
    }
    if normalized.chars().any(char::is_control) {
        failures.push(PolicyFailure::ControlCharacters);
    }

    let upper = normalized.chars().any(char::is_uppercase);
    let lower_case = normalized.chars().any(char::is_lowercase);
    let digit = normalized.chars().any(char::is_numeric);
    let symbol = normalized
        .chars()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace() && !c.is_control());
    if !(upper && lower_case && digit && symbol) {
        failures.push(PolicyFailure::CharacterClasses);
    }

    let mut forbidden: Vec<String> = FORBIDDEN.iter().map(|f| (*f).to_string()).collect();
    forbidden.push(ctx.year.to_string());
    for value in [ctx.username, ctx.trust_domain] {
        let v = value.trim().to_lowercase();
        if v.chars().count() >= 3 {
            forbidden.push(v);
        }
    }
    if let Some(name) = ctx.display_name {
        forbidden.extend(
            name.nfkc()
                .collect::<String>()
                .to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|t| t.chars().count() >= 3)
                .map(str::to_string),
        );
    }
    if forbidden.iter().any(|f| lower.contains(f.as_str())) {
        failures.push(PolicyFailure::ForbiddenContent);
    }

    if ctx.blocklist.contains(&lower) {
        failures.push(PolicyFailure::Blocklisted);
    }

    failures.sort_unstable();
    failures.dedup();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// The Gregorian calendar year containing Unix time `now` (UTC).
#[must_use]
pub fn year_of(now: i64) -> i32 {
    // Civil-from-days (Howard Hinnant), valid for the proleptic Gregorian
    // calendar.
    let days = now.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    i32::try_from(year).unwrap_or(i32::MAX)
}

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl Default for PasswordParams {
    /// RFC 9106 §4 second recommended option: 64 MiB, 3 passes, 4 lanes.
    /// Production always uses these; only tests construct cheaper values.
    fn default() -> Self {
        Self {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl PasswordParams {
    /// Whether `other` is weaker than `self` in any dimension.
    #[must_use]
    pub fn stronger_than(&self, other: &Self) -> bool {
        self.m_cost_kib > other.m_cost_kib
            || self.t_cost > other.t_cost
            || self.p_cost > other.p_cost
    }
}

/// A server-side pepper and its generation id.
pub struct Pepper {
    /// Generation id stored next to each hash.
    pub id: i64,
    key: Zeroizing<[u8; 32]>,
}

impl Pepper {
    /// Wrap a 32-byte pepper.
    #[must_use]
    pub fn new(id: i64, key: [u8; 32]) -> Self {
        Self {
            id,
            key: Zeroizing::new(key),
        }
    }
}

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pepper")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Failures of the hashing service (never "wrong password", which is
/// [`Verified::ok`] = false).
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// No verification slot within [`MAX_WAIT`].
    #[error("auth_busy")]
    Busy,
    /// Argon2 or the stored hash failed in a way that is not a mismatch.
    #[error("password hashing failed: {0}")]
    Internal(String),
}

/// Outcome of a verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// The password matched.
    pub ok: bool,
    /// The stored hash uses weaker parameters or an older pepper than the
    /// configured ones; rehash after a successful login.
    pub needs_rehash: bool,
}

/// Argon2id hashing behind a concurrency limit.
#[derive(Debug, Clone)]
pub struct PasswordHasher {
    inner: Arc<HasherInner>,
}

#[derive(Debug)]
struct HasherInner {
    params: PasswordParams,
    pepper: Option<Pepper>,
    permits: Semaphore,
    wait: Duration,
    dummy_phc: String,
}

impl PasswordHasher {
    /// Build a hasher. Computes the dummy hash used for unknown accounts once,
    /// with the configured parameters, so its cost matches a real hash.
    pub fn new(params: PasswordParams, pepper: Option<Pepper>) -> Result<Self, PasswordError> {
        let mut random = Zeroizing::new([0u8; 32]);
        getrandom::fill(random.as_mut()).map_err(|e| PasswordError::Internal(e.to_string()))?;
        let dummy_input = Zeroizing::new(crate::admin::codec::b64url(random.as_ref()));
        let mut inner = HasherInner {
            params,
            pepper,
            permits: Semaphore::new(MAX_CONCURRENT),
            wait: MAX_WAIT,
            dummy_phc: String::new(),
        };
        inner.dummy_phc = inner.hash_sync(&dummy_input)?.0;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The configured parameters.
    #[must_use]
    pub fn params(&self) -> PasswordParams {
        self.inner.params
    }

    /// Hash a new password. Returns the PHC string and the pepper id used.
    pub async fn hash(
        &self,
        password: Zeroizing<String>,
    ) -> Result<(String, Option<i64>), PasswordError> {
        let inner = Arc::clone(&self.inner);
        self.run(move || inner.hash_sync(&password)).await
    }

    /// Verify `password` against a stored hash.
    pub async fn verify(
        &self,
        password: Zeroizing<String>,
        phc: String,
        pepper_id: Option<i64>,
    ) -> Result<Verified, PasswordError> {
        let inner = Arc::clone(&self.inner);
        self.run(move || inner.verify_sync(&password, &phc, pepper_id))
            .await
    }

    /// Spend the same work as a real verification and fail (unknown, disabled
    /// or credential-less accounts).
    pub async fn verify_dummy(&self, password: Zeroizing<String>) -> Result<(), PasswordError> {
        let inner = Arc::clone(&self.inner);
        let pepper_id = inner.pepper.as_ref().map(|p| p.id);
        self.run(move || {
            let phc = inner.dummy_phc.clone();
            inner.verify_sync(&password, &phc, pepper_id).map(|_| ())
        })
        .await
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, PasswordError> + Send + 'static,
    ) -> Result<T, PasswordError> {
        let permit = tokio::time::timeout(self.inner.wait, self.inner.permits.acquire())
            .await
            .map_err(|_| PasswordError::Busy)?
            .map_err(|_| PasswordError::Busy)?;
        let out = tokio::task::spawn_blocking(work)
            .await
            .map_err(|e| PasswordError::Internal(e.to_string()))?;
        drop(permit);
        out
    }
}

impl HasherInner {
    fn argon(params: PasswordParams) -> Result<Argon2<'static>, PasswordError> {
        let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| PasswordError::Internal(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
    }

    /// The Argon2 input: NFKC bytes, or their HMAC under the pepper.
    fn prehash(
        &self,
        password: &str,
        pepper_id: Option<i64>,
    ) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
        let normalized = normalize(password);
        match pepper_id {
            None => Ok(Zeroizing::new(normalized.as_bytes().to_vec())),
            Some(id) => {
                let pepper =
                    self.pepper.as_ref().filter(|p| p.id == id).ok_or_else(|| {
                        PasswordError::Internal(format!("pepper id {id} not loaded"))
                    })?;
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(pepper.key.as_ref())
                    .map_err(|e| PasswordError::Internal(e.to_string()))?;
                mac.update(normalized.as_bytes());
                Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
            }
        }
    }

    fn hash_sync(&self, password: &str) -> Result<(String, Option<i64>), PasswordError> {
        let pepper_id = self.pepper.as_ref().map(|p| p.id);
        let input = self.prehash(password, pepper_id)?;
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| PasswordError::Internal(e.to_string()))?;
        let hash = Self::argon(self.params)?
            .hash_password_with_salt(&input, &salt)
            .map_err(|e| PasswordError::Internal(e.to_string()))?;
        Ok((hash.to_string(), pepper_id))
    }

    fn verify_sync(
        &self,
        password: &str,
        phc: &str,
        pepper_id: Option<i64>,
    ) -> Result<Verified, PasswordError> {
        let parsed = argon2::password_hash::phc::PasswordHash::new(phc)
            .map_err(|e| PasswordError::Internal(format!("stored hash: {e}")))?;
        let stored = Params::try_from(&parsed)
            .map_err(|e| PasswordError::Internal(format!("stored params: {e}")))?;
        let stored = PasswordParams {
            m_cost_kib: stored.m_cost(),
            t_cost: stored.t_cost(),
            p_cost: stored.p_cost(),
        };
        let input = self.prehash(password, pepper_id)?;
        // Parameters come from the PHC string, not from `self.params`.
        let ok = Argon2::default().verify_password(&input, &parsed).is_ok();
        let current_pepper = self.pepper.as_ref().map(|p| p.id);
        Ok(Verified {
            ok,
            needs_rehash: self.params.stronger_than(&stored) || current_pepper != pepper_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "Tr0ub4dor&3-Correct!Horse_Battery";

    fn ctx(blocklist: &Blocklist) -> PolicyContext<'_> {
        PolicyContext {
            username: "alice.ops",
            display_name: Some("Alice Wonder"),
            trust_domain: "prod.example.org",
            year: 2026,
            blocklist,
        }
    }

    fn fails(pw: &str) -> Vec<PolicyFailure> {
        let bl = Blocklist::embedded();
        check_policy(pw, &ctx(&bl)).err().unwrap_or_default()
    }

    #[test]
    fn a_long_four_class_password_passes() {
        assert_eq!(fails(GOOD), []);
        // Spaces and non-ASCII letters are welcome.
        assert_eq!(fails("Ação rápida 2025 é 100% segura!"), []);
    }

    #[test]
    fn length_is_counted_in_scalar_values_after_nfkc() {
        assert_eq!(fails("Short1!Short1!Short1!Sh"), [PolicyFailure::TooShort]);
        // 24 characters exactly.
        assert_eq!(fails("Abcdefghij1!Abcdefghij1!"), []);
        // 'ﬁ' (one scalar) normalises to "fi" (two): 23 → 24 characters.
        assert_eq!(fails("ﬁ-Abcdefghij1!Abcdefgh9"), []);
        let at_max = format!("Aa1!{}", "x".repeat(MAX_LEN - 4));
        assert_eq!(fails(&at_max), []);
        let over = format!("Aa1!{}", "x".repeat(MAX_LEN - 3));
        assert_eq!(fails(&over), [PolicyFailure::TooLong], "never truncated");
    }

    #[test]
    fn every_class_is_required() {
        assert_eq!(
            fails("abcdefghijklmnopqrstuv1!"),
            [PolicyFailure::CharacterClasses]
        );
        assert_eq!(
            fails("ABCDEFGHIJKLMNOPQRSTUV1!"),
            [PolicyFailure::CharacterClasses]
        );
        assert_eq!(
            fails("Abcdefghijklmnopqrstuvw!"),
            [PolicyFailure::CharacterClasses]
        );
        assert_eq!(
            fails("Abcdefghijklmnopqrstuv12"),
            [PolicyFailure::CharacterClasses]
        );
        assert_eq!(
            fails("Abcdefghijk lmnopqrstu12"),
            [PolicyFailure::CharacterClasses],
            "a space is not a symbol"
        );
    }

    #[test]
    fn control_characters_are_refused() {
        assert_eq!(
            fails("Abcdefghij1!Abcdefghij1!\u{7}"),
            [PolicyFailure::ControlCharacters]
        );
    }

    #[test]
    fn forbidden_substrings_are_refused_case_insensitively() {
        for pw in [
            "Xx1!-ALICE.OPS-Yy2@-Zz3#-",  // username
            "Xx1!-WONDERland-Yy2@-Zz3#-", // display-name token
            "Xx1!-FerroGate-Yy2@-Zz3#-W", // product
            "Xx1!-fGv-Yy2@-Zz3#-Wwww-",   // organisation
            "Xx1!-Senha-Yy2@-Zz3#-Wwww",
            "Xx1!-PassWord-Yy2@-Zz3#-W",
            "Xx1!-cmis-Yy2@-Zz3#-Wwwww",
            "Xx1!-prod.example.org-Yy2@", // trust domain
            "Xx1!-2026-Yy2@-Zz3#-Wwwww",  // current year
        ] {
            assert_eq!(fails(pw), [PolicyFailure::ForbiddenContent], "{pw}");
        }
        // Display-name tokens shorter than three characters do not count.
        let bl = Blocklist::embedded();
        let mut c = ctx(&bl);
        c.display_name = Some("Al Bo");
        assert!(check_policy("Xx1!-al-bo-Yy2@-Zz3#-Wwww", &c).is_ok());
    }

    #[test]
    fn blocklisted_passwords_are_refused_whole_and_case_insensitively() {
        assert_eq!(
            fails("Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!"),
            [PolicyFailure::Blocklisted]
        );
        assert_eq!(
            fails("aA1!aA1!aA1!aA1!aA1!aA1!"),
            [PolicyFailure::Blocklisted],
            "case-insensitive"
        );
        assert_eq!(
            fails("aA1!aA1!aA1!aA1!aA1!aA1!x"),
            [],
            "whole-password match only"
        );
    }

    #[test]
    fn several_failures_are_all_reported() {
        assert_eq!(
            fails("fgv"),
            [
                PolicyFailure::TooShort,
                PolicyFailure::CharacterClasses,
                PolicyFailure::ForbiddenContent
            ]
        );
    }

    #[test]
    fn year_of_matches_known_dates() {
        assert_eq!(year_of(0), 1970);
        assert_eq!(year_of(1_767_225_599), 2025); // 2025-12-31T23:59:59Z
        assert_eq!(year_of(1_767_225_600), 2026); // 2026-01-01T00:00:00Z
        assert_eq!(year_of(951_782_400), 2000); // 2000-02-29
    }

    fn cheap() -> PasswordParams {
        PasswordParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[tokio::test]
    async fn default_parameters_are_the_rfc9106_second_option() {
        let h = PasswordHasher::new(PasswordParams::default(), None).unwrap();
        let (phc, pepper) = h.hash(Zeroizing::new(GOOD.into())).await.unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"), "{phc}");
        assert_eq!(pepper, None);
        let v = h
            .verify(Zeroizing::new(GOOD.into()), phc, None)
            .await
            .unwrap();
        assert_eq!(
            v,
            Verified {
                ok: true,
                needs_rehash: false
            }
        );
    }

    #[tokio::test]
    async fn round_trip_and_mismatch() {
        let h = PasswordHasher::new(cheap(), None).unwrap();
        let (phc, _) = h.hash(Zeroizing::new(GOOD.into())).await.unwrap();
        assert!(
            h.verify(Zeroizing::new(GOOD.into()), phc.clone(), None)
                .await
                .unwrap()
                .ok
        );
        assert!(
            !h.verify(Zeroizing::new(format!("{GOOD}x")), phc, None)
                .await
                .unwrap()
                .ok
        );
    }

    #[tokio::test]
    async fn nfkc_equivalent_passwords_verify() {
        let h = PasswordHasher::new(cheap(), None).unwrap();
        let (phc, _) = h
            .hash(Zeroizing::new("ﬁle-Abcdefghij1!Abcdefgh".into()))
            .await
            .unwrap();
        assert!(
            h.verify(
                Zeroizing::new("file-Abcdefghij1!Abcdefgh".into()),
                phc,
                None
            )
            .await
            .unwrap()
            .ok
        );
    }

    #[tokio::test]
    async fn weaker_stored_parameters_ask_for_a_rehash() {
        let old = PasswordHasher::new(cheap(), None).unwrap();
        let (phc, _) = old.hash(Zeroizing::new(GOOD.into())).await.unwrap();
        let stronger = PasswordHasher::new(
            PasswordParams {
                m_cost_kib: 128,
                ..cheap()
            },
            None,
        )
        .unwrap();
        let v = stronger
            .verify(Zeroizing::new(GOOD.into()), phc, None)
            .await
            .unwrap();
        assert_eq!(
            v,
            Verified {
                ok: true,
                needs_rehash: true
            }
        );
    }

    #[tokio::test]
    async fn the_pepper_is_part_of_the_hash_input() {
        let peppered = PasswordHasher::new(cheap(), Some(Pepper::new(1, [7; 32]))).unwrap();
        let (phc, id) = peppered.hash(Zeroizing::new(GOOD.into())).await.unwrap();
        assert_eq!(id, Some(1));
        assert!(
            peppered
                .verify(Zeroizing::new(GOOD.into()), phc.clone(), Some(1))
                .await
                .unwrap()
                .ok
        );
        // Without the pepper the same hash does not verify.
        let plain = PasswordHasher::new(cheap(), None).unwrap();
        assert!(
            !plain
                .verify(Zeroizing::new(GOOD.into()), phc.clone(), None)
                .await
                .unwrap()
                .ok
        );
        // A different pepper under the same id does not verify either.
        let other = PasswordHasher::new(cheap(), Some(Pepper::new(1, [8; 32]))).unwrap();
        assert!(
            !other
                .verify(Zeroizing::new(GOOD.into()), phc, Some(1))
                .await
                .unwrap()
                .ok
        );
        // A hash made without pepper asks for a rehash once one is configured.
        let (bare, _) = plain.hash(Zeroizing::new(GOOD.into())).await.unwrap();
        let v = peppered
            .verify(Zeroizing::new(GOOD.into()), bare, None)
            .await
            .unwrap();
        assert_eq!(
            v,
            Verified {
                ok: true,
                needs_rehash: true
            }
        );
    }

    #[tokio::test]
    async fn dummy_verification_runs_and_never_succeeds() {
        let h = PasswordHasher::new(cheap(), None).unwrap();
        h.verify_dummy(Zeroizing::new(GOOD.into())).await.unwrap();
    }
}
