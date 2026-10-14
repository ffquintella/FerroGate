//! The signed caller allowlist — MIA-side runtime verifier.
//!
//! Only callers an entry of the allowlist admits may obtain a token. The
//! allowlist is signed by CMIS (see [`ferro_svid::Issuer::sign_allowlist`])
//! and re-verified here before use; verification **fails closed** — any decode,
//! signature, or freshness error yields no usable allowlist, so the server
//! denies every caller rather than fall back to an unauthenticated state.
//!
//! Two signed formats are accepted, each under its own signature context:
//!
//! - **v1** (`ferrogate-allowlist-v1`): `(uid, bin_sha384)` pairs, with `None`
//!   and `"*"` wildcards (ADR-0002). Hand-provisioned and served by the
//!   unauthenticated `GetAllowlist`.
//! - **v2** (`ferrogate-allowlist-v2`, feature F19 §6): a host-bound compiled
//!   view of the host's approvals, with a generation and per-entry uid,
//!   Windows SID, path and expiry constraints. Served by the authenticated
//!   `SyncAllowlist` and kept current by [`crate::allowlist_sync`], which also
//!   enforces the host binding and the generation (rollback) rules.
//!
//! The wire model ([`AllowlistDoc`], [`SignedAllowlist`], `sign`/`encode`) lives
//! in `ferro-svid` so CMIS and the MIA share one definition; it is re-exported
//! here for convenience. This module owns the freshness-checked, indexed
//! [`Allowlist`] that the helper API consults.

use std::collections::{HashMap, HashSet};

use ferro_crypto::composite::CompositePublicKey;
use ferro_svid::allowlist_v2::{self, AllowlistV2Error};

// Re-export the shared wire model so existing `mia::helper::allowlist::*` users
// (and tests) keep working unchanged.
pub use ferro_svid::allowlist::{
    decode, encode, sign, AllowEntry, AllowlistDoc, AllowlistError, SignedAllowlist,
    ALLOWLIST_SIGNING_CONTEXT, BIN_SHA_WILDCARD,
};
pub use ferro_svid::allowlist_v2::{AllowEntryV2, AllowlistDocV2, ALLOWLIST_V2_FORMAT};

/// Clock-skew tolerance applied to the allowlist not-before (`issued_at`)
/// check (seconds).
///
/// CMIS timestamps the allowlist from its own clock; if that clock runs a
/// hair ahead of this host, a freshly fetched allowlist can carry an
/// `issued_at` a fraction of a second in the future, and a strict
/// `now < issued_at` test would reject it as `NotYetValid` and fail closed
/// (deny every caller) until the next re-attestation. Tolerating a small
/// future skew here mirrors [`crate::helper::crl::CRL_FRESHNESS_LEEWAY_SECS`]
/// on the CRL freshness gate.
pub const ALLOWLIST_NOT_BEFORE_LEEWAY_SECS: i64 = 60;

/// How an allowlisted binary is gated on the caller's uid (ADR-0002).
#[derive(Debug, Clone)]
enum UidScope {
    /// Any user may run the binary (a wildcard `uid = None` entry).
    Any,
    /// Only these uids may run the binary (one or more pinned `uid = Some`
    /// entries for the same hash).
    Only(HashSet<u32>),
}

/// The constraints of one v2 entry (F19 §6.1). Every constraint present must
/// match.
#[derive(Debug, Clone)]
struct Constraint {
    uid: Option<u32>,
    sid_hash: Option<[u8; 32]>,
    path_hash: Option<[u8; 32]>,
    expires_at: Option<i64>,
}

/// A v2 body indexed for the hot path: a map lookup by binary hash, then a
/// scan of that hash's few constraint sets.
#[derive(Debug, Clone)]
struct V2Index {
    host_uuid: String,
    generation: u64,
    entries_digest: [u8; 48],
    by_sha: HashMap<[u8; 48], Vec<Constraint>>,
    /// Legacy `bin_sha = "*"` entries (legacy imports only).
    any_bin: Vec<Constraint>,
    /// The verified entries, for listing (`mia app list`).
    entries: Vec<AllowEntryV2>,
}

#[derive(Debug, Clone)]
enum Body {
    /// Keyed by binary hash; `any_bin` is the binary-side wildcard.
    V1 {
        members: HashMap<[u8; 48], UidScope>,
        any_bin: Option<UidScope>,
    },
    V2(V2Index),
}

/// A verified, in-memory allowlist ready for membership checks.
///
/// **v1** is keyed by binary hash: a caller is permitted when its hash is
/// present and the hash's uid scope admits the caller's uid. `Any` wins if a
/// hash appears as both a wildcard and a pinned entry. A binary-side wildcard
/// (`bin_sha = "*"`) is folded the same way, so `(uid = None, bin_sha = "*")`
/// admits everyone while `(uid = Some(n), bin_sha = "*")` admits uid `n`
/// running any binary.
///
/// **v2** keeps each entry's constraint set; see [`Self::permits_caller`].
#[derive(Debug, Clone)]
pub struct Allowlist {
    trust_domain: String,
    issued_at: i64,
    not_after: i64,
    body: Body,
}

/// A caller as the helper API authenticated it, for [`Allowlist::permits_caller`].
#[derive(Debug, Clone, Copy)]
pub struct CallerFacts<'a> {
    /// Calling uid (Windows: the token user's RID).
    pub uid: u32,
    /// `SHA-384` of the calling binary.
    pub bin_sha: &'a [u8; 48],
    /// Canonical path of the calling executable, when resolved.
    pub exe_path: Option<&'a str>,
    /// Windows: the caller's full user SID, when resolved.
    pub user_sid: Option<&'a str>,
}

impl<'a> CallerFacts<'a> {
    /// The facts of an authenticated caller.
    #[must_use]
    pub fn of(id: &'a crate::helper::auth::CallerIdentity) -> Self {
        Self {
            uid: id.uid,
            bin_sha: &id.bin_sha,
            exe_path: id.exe_path.as_deref(),
            user_sid: id.user_sid.as_deref(),
        }
    }
}

/// Widen `scope` to also admit `uid` (`None` is the wildcard, subsuming every
/// uid). Shared by the per-hash and any-binary folds so both treat a later
/// wildcard as subsuming earlier pins and accumulate distinct pinned uids.
fn admit(scope: &mut UidScope, uid: Option<u32>) {
    match (scope, uid) {
        // A wildcard entry subsumes any uid pins for the same key.
        (slot, None) => *slot = UidScope::Any,
        // Once a key is wildcard, a later uid pin can't narrow it.
        (UidScope::Any, Some(_)) => {}
        (UidScope::Only(uids), Some(uid)) => {
            uids.insert(uid);
        }
    }
}

/// Seed a fresh [`UidScope`] for the first entry seen for a key.
fn seed(uid: Option<u32>) -> UidScope {
    match uid {
        None => UidScope::Any,
        Some(uid) => UidScope::Only(HashSet::from([uid])),
    }
}

/// Which uids a folded allowlist rule admits — the read-only form of a rule's
/// uid gate, as exposed by [`Allowlist::rules`] for operator diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleUids {
    /// Any uid (an entry with `uid = None`, ADR-0002).
    Any,
    /// Only these uids, ascending and distinct.
    Only(Vec<u32>),
}

impl RuleUids {
    /// Does this rule admit `uid`?
    #[must_use]
    pub fn admits(&self, uid: u32) -> bool {
        match self {
            Self::Any => true,
            Self::Only(uids) => uids.binary_search(&uid).is_ok(),
        }
    }
}

impl From<&UidScope> for RuleUids {
    fn from(scope: &UidScope) -> Self {
        match scope {
            UidScope::Any => Self::Any,
            UidScope::Only(uids) => {
                let mut uids: Vec<u32> = uids.iter().copied().collect();
                uids.sort_unstable();
                Self::Only(uids)
            }
        }
    }
}

/// One folded rule of a verified allowlist: a binary (or any binary) and the
/// uids allowed to run it. Several entries for the same binary fold into one
/// rule, exactly as [`Allowlist::permits`] sees them for v1. For a v2 body
/// the fold ignores the path, SID and expiry constraints (display only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    /// The binary hash the rule pins, or `None` for the any-binary wildcard
    /// (`bin_sha = "*"`).
    pub bin_sha: Option<[u8; 48]>,
    /// The uids the rule admits.
    pub uids: RuleUids,
}

/// Does `scope` admit `uid`?
fn scope_admits(scope: Option<&UidScope>, uid: u32) -> bool {
    match scope {
        Some(UidScope::Any) => true,
        Some(UidScope::Only(uids)) => uids.contains(&uid),
        None => false,
    }
}

/// Map a v2 verification failure onto the shared error type.
fn v2_error(e: AllowlistV2Error) -> AllowlistError {
    match e {
        AllowlistV2Error::MalformedEntry => AllowlistError::MalformedEntry,
        AllowlistV2Error::MalformedSignature => AllowlistError::MalformedSignature,
        AllowlistV2Error::BadSignature => AllowlistError::BadSignature,
        other => AllowlistError::Cbor(other.to_string()),
    }
}

/// The freshness window shared by both formats. The not-before check
/// tolerates [`ALLOWLIST_NOT_BEFORE_LEEWAY_SECS`] of forward clock skew.
fn check_window(
    issued_at: i64,
    not_after: i64,
    now: i64,
    max_age_secs: i64,
) -> Result<(), AllowlistError> {
    if now < issued_at - ALLOWLIST_NOT_BEFORE_LEEWAY_SECS {
        return Err(AllowlistError::NotYetValid);
    }
    if now > not_after {
        return Err(AllowlistError::Expired);
    }
    if now - issued_at > max_age_secs {
        return Err(AllowlistError::TooOld);
    }
    Ok(())
}

/// A lowercase-hex SHA-384 as bytes.
fn sha_bytes(hex_sha: &str) -> Result<[u8; 48], AllowlistError> {
    let raw = hex::decode(hex_sha).map_err(|_| AllowlistError::MalformedEntry)?;
    raw.try_into().map_err(|_| AllowlistError::MalformedEntry)
}

impl Constraint {
    /// Whether this constraint set admits `caller` at `now`. `path_hash` and
    /// `sid_hash` are the caller's hashes, computed at most once per request.
    fn admits(
        &self,
        caller: &CallerFacts<'_>,
        now: i64,
        path_hash: &mut impl FnMut() -> Option<[u8; 32]>,
        sid_hash: &mut impl FnMut() -> Option<[u8; 32]>,
    ) -> bool {
        self.uid.is_none_or(|u| u == caller.uid)
            && self.expires_at.is_none_or(|exp| now < exp)
            && self.sid_hash.is_none_or(|want| sid_hash() == Some(want))
            && self.path_hash.is_none_or(|want| path_hash() == Some(want))
    }
}

/// Compute `f()` once and remember it.
fn memo<T: Copy>(slot: &mut Option<T>, f: impl FnOnce() -> T) -> T {
    *slot.get_or_insert_with(f)
}

impl Allowlist {
    /// Verify and load a [`SignedAllowlist`] from its CBOR bytes, v1 or v2.
    ///
    /// `trusted` is the CMIS enrollment public key; `now` is the reference
    /// clock; `max_age_secs` bounds how stale the file may be (`issued_at`).
    /// The not-before check tolerates up to
    /// [`ALLOWLIST_NOT_BEFORE_LEEWAY_SECS`] of forward clock skew so a freshly
    /// signed allowlist is not spuriously rejected. Any failure is fatal and
    /// fails closed.
    ///
    /// A v2 body is accepted on its signature and freshness only; its host
    /// binding and generation are checked by the caller against what this
    /// host holds (see [`crate::allowlist_sync`]).
    pub fn load(
        bytes: &[u8],
        trusted: &CompositePublicKey,
        now: i64,
        max_age_secs: i64,
    ) -> Result<Self, AllowlistError> {
        let signed = ferro_svid::allowlist::decode(bytes)?;
        // Signature is checked before the body is parsed/trusted. A v2 body
        // is signed under its own context, so it fails the v1 check as a bad
        // signature and is then tried as v2.
        match ferro_svid::allowlist::verify(&signed, trusted) {
            Ok(doc) => Self::from_v1(doc, now, max_age_secs),
            Err(AllowlistError::BadSignature) => {
                let doc = allowlist_v2::verify_v2(&signed, trusted).map_err(v2_error)?;
                Self::from_v2(doc, now, max_age_secs)
            }
            Err(e) => Err(e),
        }
    }

    /// Verify and load a **v1** body only (the legacy `GetAllowlist` path).
    pub fn load_v1(
        bytes: &[u8],
        trusted: &CompositePublicKey,
        now: i64,
        max_age_secs: i64,
    ) -> Result<Self, AllowlistError> {
        let signed = ferro_svid::allowlist::decode(bytes)?;
        let doc = ferro_svid::allowlist::verify(&signed, trusted)?;
        Self::from_v1(doc, now, max_age_secs)
    }

    /// Verify and load a **v2** body only (the `SyncAllowlist` path), under
    /// the v2 signature context.
    pub fn load_v2(
        bytes: &[u8],
        trusted: &CompositePublicKey,
        now: i64,
        max_age_secs: i64,
    ) -> Result<Self, AllowlistError> {
        let signed = ferro_svid::allowlist::decode(bytes)?;
        let doc = allowlist_v2::verify_v2(&signed, trusted).map_err(v2_error)?;
        Self::from_v2(doc, now, max_age_secs)
    }

    fn from_v1(doc: AllowlistDoc, now: i64, max_age_secs: i64) -> Result<Self, AllowlistError> {
        // Tolerate a small clock skew: CMIS may stamp `issued_at` a fraction
        // of a second ahead of this host's clock, and a strict check would
        // reject the fresh allowlist and fail closed. See
        // `ALLOWLIST_NOT_BEFORE_LEEWAY_SECS`.
        check_window(doc.issued_at, doc.not_after, now, max_age_secs)?;

        let mut members: HashMap<[u8; 48], UidScope> = HashMap::with_capacity(doc.entries.len());
        let mut any_bin: Option<UidScope> = None;
        for e in &doc.entries {
            // A `bin_sha = "*"` entry permits any binary; fold it into the
            // any-binary scope rather than a per-hash one.
            if e.bin_is_wildcard() {
                match &mut any_bin {
                    Some(scope) => admit(scope, e.uid),
                    None => any_bin = Some(seed(e.uid)),
                }
                continue;
            }
            let arr = sha_bytes(&e.bin_sha)?;
            match members.get_mut(&arr) {
                Some(scope) => admit(scope, e.uid),
                None => {
                    members.insert(arr, seed(e.uid));
                }
            }
        }

        Ok(Self {
            trust_domain: doc.trust_domain,
            issued_at: doc.issued_at,
            not_after: doc.not_after,
            body: Body::V1 { members, any_bin },
        })
    }

    fn from_v2(doc: AllowlistDocV2, now: i64, max_age_secs: i64) -> Result<Self, AllowlistError> {
        check_window(doc.issued_at, doc.not_after, now, max_age_secs)?;
        let entries_digest = allowlist_v2::entries_digest(&doc.entries).map_err(v2_error)?;
        let mut by_sha: HashMap<[u8; 48], Vec<Constraint>> =
            HashMap::with_capacity(doc.entries.len());
        let mut any_bin = Vec::new();
        for e in &doc.entries {
            let c = Constraint {
                uid: e.uid,
                sid_hash: e.user_sid_hash,
                path_hash: e.path_hash,
                expires_at: e.expires_at,
            };
            if e.bin_sha == BIN_SHA_WILDCARD {
                any_bin.push(c);
            } else {
                by_sha.entry(sha_bytes(&e.bin_sha)?).or_default().push(c);
            }
        }
        Ok(Self {
            trust_domain: doc.trust_domain,
            issued_at: doc.issued_at,
            not_after: doc.not_after,
            body: Body::V2(V2Index {
                host_uuid: doc.host_uuid,
                generation: doc.generation,
                entries_digest,
                by_sha,
                any_bin,
                entries: doc.entries,
            }),
        })
    }

    /// Is the caller `(uid, bin_sha)` permitted? The v1 check; kept for
    /// diagnostics. It ignores the hard expiry and, for a v2 body, the entry
    /// expiry, and an entry with a path or SID constraint admits nobody here
    /// (fail closed). The helper API decides with [`Self::permits_caller`].
    #[must_use]
    pub fn permits(&self, uid: u32, bin_sha: &[u8; 48]) -> bool {
        let caller = CallerFacts {
            uid,
            bin_sha,
            exe_path: None,
            user_sid: None,
        };
        self.permits_caller(&caller, i64::MIN)
    }

    /// Is `caller` permitted at `now`? After the hard expiry (`not_after`)
    /// nobody is (fail closed).
    ///
    /// - **v1**: a binary-side wildcard admits the caller regardless of its
    ///   hash; otherwise the hash must be listed and its uid scope must admit
    ///   the caller's uid.
    /// - **v2** (F19 §6.1): some entry with the caller's hash (or `"*"`) whose
    ///   `uid` is absent or equal, `user_sid_hash` absent or equal to the hash
    ///   of the caller's SID, `path_hash` absent or equal to the hash of the
    ///   caller's canonical path, and `expires_at` absent or after `now`. A
    ///   constraint the caller cannot be checked against (no path, no SID)
    ///   does not match.
    #[must_use]
    pub fn permits_caller(&self, caller: &CallerFacts<'_>, now: i64) -> bool {
        if now > self.not_after {
            return false;
        }
        match &self.body {
            Body::V1 { members, any_bin } => {
                scope_admits(any_bin.as_ref(), caller.uid)
                    || scope_admits(members.get(caller.bin_sha), caller.uid)
            }
            Body::V2(ix) => {
                let (mut path_slot, mut sid_slot) = (None, None);
                let mut path_hash = || {
                    memo(&mut path_slot, || {
                        let path = caller.exe_path?;
                        let key =
                            ferro_appid::path_key(ferro_appid::Platform::current(), path).ok()?;
                        Some(allowlist_v2::path_hash(&ix.host_uuid, &key))
                    })
                };
                let mut sid_hash = || {
                    memo(&mut sid_slot, || {
                        caller
                            .user_sid
                            .map(|sid| allowlist_v2::sid_hash(&ix.host_uuid, sid))
                    })
                };
                ix.by_sha
                    .get(caller.bin_sha)
                    .into_iter()
                    .flatten()
                    .chain(&ix.any_bin)
                    .any(|c| c.admits(caller, now, &mut path_hash, &mut sid_hash))
            }
        }
    }

    /// The trust domain the allowlist was issued for.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Issuance time, Unix seconds.
    #[must_use]
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Hard expiry of the allowlist, Unix seconds.
    #[must_use]
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    /// The signed format: 1 or 2.
    #[must_use]
    pub fn format(&self) -> u32 {
        match self.body {
            Body::V1 { .. } => 1,
            Body::V2(_) => ALLOWLIST_V2_FORMAT,
        }
    }

    /// A v2 body's host UUID (`None` for v1).
    #[must_use]
    pub fn host_uuid(&self) -> Option<&str> {
        match &self.body {
            Body::V1 { .. } => None,
            Body::V2(ix) => Some(&ix.host_uuid),
        }
    }

    /// A v2 body's generation (`None` for v1).
    #[must_use]
    pub fn generation(&self) -> Option<u64> {
        match &self.body {
            Body::V1 { .. } => None,
            Body::V2(ix) => Some(ix.generation),
        }
    }

    /// A v2 body's `entries_digest` (`None` for v1).
    #[must_use]
    pub fn entries_digest(&self) -> Option<[u8; 48]> {
        match &self.body {
            Body::V1 { .. } => None,
            Body::V2(ix) => Some(ix.entries_digest),
        }
    }

    /// A v2 body's verified entries, for listing (`None` for v1).
    #[must_use]
    pub fn entries_v2(&self) -> Option<&[AllowEntryV2]> {
        match &self.body {
            Body::V1 { .. } => None,
            Body::V2(ix) => Some(&ix.entries),
        }
    }

    /// Number of distinct entries — v1: binary hashes, plus one for a
    /// binary-side wildcard; v2: entries — a count for status reporting,
    /// never the entries themselves.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        match &self.body {
            Body::V1 { members, any_bin } => members.len() + usize::from(any_bin.is_some()),
            Body::V2(ix) => ix.entries.len(),
        }
    }

    /// The folded rules this allowlist enforces: the any-binary wildcard (if
    /// any) first, then one rule per pinned binary hash in ascending hash
    /// order. A read-only view for operator diagnostics (`mia
    /// allowlist-diagnose`); the helper API decides with
    /// [`Self::permits_caller`].
    #[must_use]
    pub fn rules(&self) -> Vec<AllowRule> {
        let (members, any_bin) = match &self.body {
            Body::V1 { members, any_bin } => (members.clone(), any_bin.clone()),
            Body::V2(ix) => {
                let fold = |cs: &[Constraint], scope: &mut Option<UidScope>| {
                    for c in cs {
                        match scope {
                            Some(s) => admit(s, c.uid),
                            None => *scope = Some(seed(c.uid)),
                        }
                    }
                };
                let mut members = HashMap::new();
                for (sha, cs) in &ix.by_sha {
                    let mut scope = None;
                    fold(cs, &mut scope);
                    if let Some(scope) = scope {
                        members.insert(*sha, scope);
                    }
                }
                let mut any_bin = None;
                fold(&ix.any_bin, &mut any_bin);
                (members, any_bin)
            }
        };
        let mut pinned: Vec<AllowRule> = members
            .iter()
            .map(|(sha, scope)| AllowRule {
                bin_sha: Some(*sha),
                uids: scope.into(),
            })
            .collect();
        pinned.sort_unstable_by_key(|rule| rule.bin_sha);
        any_bin
            .as_ref()
            .map(|scope| AllowRule {
                bin_sha: None,
                uids: scope.into(),
            })
            .into_iter()
            .chain(pinned)
            .collect()
    }
}

/// How a startup/reload allowlist load ended, for the status endpoint
/// (feature F18). Carries counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistLoad {
    /// No allowlist configured, or no body file present.
    Missing,
    /// A body (or its key) is present but unusable: missing/unparseable key,
    /// bad signature, expired, or not yet valid.
    Invalid,
    /// A verified allowlist is in force.
    Loaded {
        /// Distinct entries ([`Allowlist::entry_count`]).
        entries: usize,
        /// Hard expiry, Unix seconds.
        not_after: i64,
    },
}

impl AllowlistLoad {
    /// Classify an already-verified allowlist.
    #[must_use]
    pub fn of(allowlist: &Allowlist) -> Self {
        Self::Loaded {
            entries: allowlist.entry_count(),
            not_after: allowlist.not_after(),
        }
    }
}

/// [`load_at_startup`], also reporting *why* no allowlist is in force so the
/// status endpoint can tell a missing allowlist from an invalid one. Logging
/// and fail-closed behaviour are identical.
pub fn load_classified(
    path: &std::path::Path,
    key_path: &std::path::Path,
    now: i64,
    max_age_secs: i64,
) -> std::io::Result<(Option<Allowlist>, AllowlistLoad)> {
    let present = path.exists();
    let loaded = load_at_startup(path, key_path, now, max_age_secs)?;
    let outcome = match (&loaded, present) {
        (Some(al), _) => AllowlistLoad::of(al),
        (None, false) => AllowlistLoad::Missing,
        (None, true) => AllowlistLoad::Invalid,
    };
    Ok((loaded, outcome))
}

/// Load the configured allowlist from disk at daemon startup, failing closed.
///
/// `Ok(Some)` is a verified allowlist; `Ok(None)` means the helper API must
/// serve in deny-all mode. Trust problems — a missing body or key file, an
/// unparseable key, a signature/freshness failure — all yield `Ok(None)` with
/// a loud log line rather than an error: crashing here would put the daemon in
/// a supervisor restart loop that unbinds the helper socket, so callers see
/// `ECONNREFUSED` instead of a diagnosable deny, and the stale pinned key that
/// commonly causes this (CMIS enrollment-key change) needs operator
/// re-provisioning either way. Only an unexpected I/O failure (not
/// `NotFound`) reading either file is returned as an error — including, on
/// Windows, a file in the system configuration directory that a
/// non-administrator could have written (`PermissionDenied`, see
/// [`crate::system_dir::check_trusted_file`]).
pub fn load_at_startup(
    path: &std::path::Path,
    key_path: &std::path::Path,
    now: i64,
    max_age_secs: i64,
) -> std::io::Result<Option<Allowlist>> {
    // Both files are refused (an I/O error, `PermissionDenied`) when they sit
    // in the system configuration directory and a non-administrator could
    // have written them (Windows; see `crate::system_dir`).
    let bytes = match crate::system_dir::read_trusted(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // CMIS may have no allowlist for this host and none was ever
            // written, so the path (configured or the per-environment
            // default) can legitimately be empty.
            tracing::warn!(
                path = %path.display(),
                "no allowlist file present (allowlist.path or its default); helper API denies \
                 all callers (fail closed)"
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let key_bytes = match crate::system_dir::read_trusted(key_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::error!(
                key = %key_path.display(),
                "allowlist key file missing; helper API denies all callers (fail closed) — \
                 fetch the CMIS enrollment key (`mia setup`) and restart"
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let trusted = match CompositePublicKey::from_concat_bytes(&key_bytes) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(
                key = %key_path.display(),
                error = %e,
                "allowlist key file unparseable; helper API denies all callers (fail closed) — \
                 fetch the CMIS enrollment key (`mia setup`) and restart"
            );
            return Ok(None);
        }
    };
    match Allowlist::load(&bytes, &trusted, now, max_age_secs) {
        Ok(al) => {
            tracing::info!(trust_domain = al.trust_domain(), "loaded signed allowlist");
            Ok(Some(al))
        }
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "allowlist verification failed; helper API denies all callers (fail closed) — \
                 if CMIS was redeployed its signing key may have changed: re-fetch the \
                 enrollment key (`mia setup`) and the allowlist, then restart"
            );
            Ok(None)
        }
    }
}

/// The daemon-start policy for the allowlist `config` resolves to: the body
/// at [`Config::allowlist_path`](crate::config::Config::allowlist_path) (the
/// explicit `allowlist.path`, else the per-environment default), verified with
/// [`Config::allowlist_key`](crate::config::Config::allowlist_key).
///
/// Every trust problem fails closed — no allowlist (deny every caller), with
/// the [`AllowlistLoad`] saying why — and only an *explicitly* configured
/// allowlist can make the daemon refuse to start (`Err`), exactly as before
/// the default existed:
///
/// - **no `allowlist.key`**: with an explicit `allowlist.path` that is a
///   misconfiguration and an error; with the default path it is simply the
///   unconfigured state — deny all, logged (the key, the trust anchor, has no
///   default);
/// - **an unexpected I/O error** (not `NotFound`) reading the body or key: an
///   error for an explicit path; at the default location — which the operator
///   never named — it is logged and served as deny-all, so an unreadable
///   well-known path can never keep the daemon from starting;
/// - a missing, unsigned, stale or non-verifying body: deny all
///   ([`load_at_startup`]).
pub fn load_for_startup(
    config: &crate::config::Config,
    now: i64,
) -> anyhow::Result<(Option<Allowlist>, AllowlistLoad)> {
    startup_policy(
        &config.allowlist_path(),
        config.allowlist_path_is_default(),
        config.allowlist_key(),
        now,
        config.allowlist_max_age(),
    )
}

/// The core of [`load_for_startup`] over already-resolved inputs (`is_default`
/// ⇒ `path` is the built-in default, not an operator's choice), split out so
/// the I/O-error branch can be exercised against a scratch directory.
fn startup_policy(
    path: &std::path::Path,
    is_default: bool,
    key: Option<&std::path::Path>,
    now: i64,
    max_age_secs: i64,
) -> anyhow::Result<(Option<Allowlist>, AllowlistLoad)> {
    use anyhow::Context as _;
    let Some(key) = key else {
        anyhow::ensure!(
            is_default,
            "allowlist.path is set but allowlist.key (FERROGATE_ALLOWLIST_KEY) is missing"
        );
        warn_no_key(path);
        return Ok((None, AllowlistLoad::Missing));
    };
    match load_classified(path, key, now, max_age_secs) {
        Ok(loaded) => Ok(loaded),
        Err(e) if is_default => {
            tracing::error!(
                path = %path.display(),
                key = %key.display(),
                error = %e,
                "cannot read the allowlist (default location) or its key; helper API denies \
                 all callers (fail closed)"
            );
            let outcome = if path.exists() {
                AllowlistLoad::Invalid
            } else {
                AllowlistLoad::Missing
            };
            Ok((None, outcome))
        }
        Err(e) => {
            Err(e).with_context(|| format!("reading allowlist (allowlist.path) {}", path.display()))
        }
    }
}

/// The live-reload (`SIGHUP`) and post-re-attestation policy for an already
/// resolved allowlist `path` (see
/// [`Config::allowlist_path`](crate::config::Config::allowlist_path)) and
/// verification `key`. Never fatal: with no key every caller is denied (fail
/// closed, logged); otherwise [`load_classified`], whose `Err` (an unexpected
/// I/O error) tells the caller to keep the allowlist currently in force.
pub fn load_for_reload(
    path: &std::path::Path,
    key: Option<&std::path::Path>,
    now: i64,
    max_age_secs: i64,
) -> std::io::Result<(Option<Allowlist>, AllowlistLoad)> {
    let Some(key) = key else {
        warn_no_key(path);
        return Ok((None, AllowlistLoad::Missing));
    };
    load_classified(path, key, now, max_age_secs)
}

/// Log the "no verification key" deny-all state.
fn warn_no_key(path: &std::path::Path) {
    tracing::warn!(
        path = %path.display(),
        "no allowlist verification key configured (allowlist.key / FERROGATE_ALLOWLIST_KEY); \
         helper API denies all callers (fail closed)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_crypto::composite::CompositeSecretKey;

    fn keypair() -> (CompositeSecretKey, CompositePublicKey) {
        CompositeSecretKey::generate().unwrap()
    }

    fn doc(now: i64) -> AllowlistDoc {
        AllowlistDoc {
            trust_domain: "ferrogate.test".into(),
            issued_at: now,
            not_after: now + 3600,
            entries: vec![AllowEntry {
                uid: Some(1001),
                bin_sha: hex::encode([0xAA; 48]),
            }],
        }
    }

    fn signed_bytes(doc: &AllowlistDoc, sk: &CompositeSecretKey) -> Vec<u8> {
        encode(&sign(doc, sk).unwrap()).unwrap()
    }

    #[test]
    fn valid_allowlist_loads_and_permits_listed_caller() {
        let (sk, pk) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        let al = Allowlist::load(&bytes, &pk, 1000, 86_400).unwrap();
        assert!(al.permits(1001, &[0xAA; 48]));
        assert!(!al.permits(1001, &[0xBB; 48]));
        assert!(!al.permits(2002, &[0xAA; 48]));
        assert_eq!(al.trust_domain(), "ferrogate.test");
    }

    /// A wildcard (`uid = None`) entry permits the binary under any uid, but
    /// still only that exact binary hash (ADR-0002).
    #[test]
    fn wildcard_entry_permits_any_uid_for_that_binary() {
        let (sk, pk) = keypair();
        let mut d = doc(1000);
        d.entries[0].uid = None;
        let al = Allowlist::load(&signed_bytes(&d, &sk), &pk, 1000, 86_400).unwrap();
        assert!(al.permits(1001, &[0xAA; 48]));
        assert!(al.permits(2002, &[0xAA; 48]));
        assert!(al.permits(0, &[0xAA; 48]));
        // A different binary is still rejected regardless of uid.
        assert!(!al.permits(1001, &[0xBB; 48]));
    }

    /// Mixed entries for the same hash: a wildcard subsumes a uid pin, and
    /// distinct pinned uids for one hash both match.
    #[test]
    fn mixed_scopes_fold_correctly() {
        let (sk, pk) = keypair();
        // Hash AA pinned to 1001 AND wildcard ⇒ Any wins.
        // Hash BB pinned to both 7 and 8 ⇒ both match, others don't.
        let mut d = doc(1000);
        d.entries = vec![
            AllowEntry {
                uid: Some(1001),
                bin_sha: hex::encode([0xAA; 48]),
            },
            AllowEntry {
                uid: None,
                bin_sha: hex::encode([0xAA; 48]),
            },
            AllowEntry {
                uid: Some(7),
                bin_sha: hex::encode([0xBB; 48]),
            },
            AllowEntry {
                uid: Some(8),
                bin_sha: hex::encode([0xBB; 48]),
            },
        ];
        let al = Allowlist::load(&signed_bytes(&d, &sk), &pk, 1000, 86_400).unwrap();
        assert!(al.permits(42, &[0xAA; 48])); // wildcard wins for AA
        assert!(al.permits(7, &[0xBB; 48]));
        assert!(al.permits(8, &[0xBB; 48]));
        assert!(!al.permits(9, &[0xBB; 48])); // not a pinned uid for BB
    }

    /// A `bin_sha = "*"` entry pinned to a uid permits that uid running ANY
    /// binary, but no other uid.
    #[test]
    fn bin_wildcard_pinned_to_uid_permits_any_binary_for_that_uid() {
        let (sk, pk) = keypair();
        let mut d = doc(1000);
        d.entries = vec![AllowEntry {
            uid: Some(1001),
            bin_sha: BIN_SHA_WILDCARD.to_string(),
        }];
        let al = Allowlist::load(&signed_bytes(&d, &sk), &pk, 1000, 86_400).unwrap();
        assert!(al.permits(1001, &[0xAA; 48]));
        assert!(al.permits(1001, &[0xBB; 48])); // any binary for uid 1001
        assert!(!al.permits(2002, &[0xAA; 48])); // but not another uid
    }

    /// A fully-open entry (`uid = None, bin_sha = "*"`) permits any binary under
    /// any uid.
    #[test]
    fn full_wildcard_permits_everyone() {
        let (sk, pk) = keypair();
        let mut d = doc(1000);
        d.entries = vec![AllowEntry {
            uid: None,
            bin_sha: BIN_SHA_WILDCARD.to_string(),
        }];
        let al = Allowlist::load(&signed_bytes(&d, &sk), &pk, 1000, 86_400).unwrap();
        assert!(al.permits(0, &[0x00; 48]));
        assert!(al.permits(4242, &[0xFF; 48]));
    }

    /// A binary-side wildcard coexists with hash-pinned entries: the wildcard's
    /// uids plus any hash-specific uids both match.
    #[test]
    fn bin_wildcard_coexists_with_pinned_hashes() {
        let (sk, pk) = keypair();
        let mut d = doc(1000);
        d.entries = vec![
            // uid 7 may run anything.
            AllowEntry {
                uid: Some(7),
                bin_sha: BIN_SHA_WILDCARD.to_string(),
            },
            // uid 9 may run only binary AA.
            AllowEntry {
                uid: Some(9),
                bin_sha: hex::encode([0xAA; 48]),
            },
        ];
        let al = Allowlist::load(&signed_bytes(&d, &sk), &pk, 1000, 86_400).unwrap();
        assert!(al.permits(7, &[0xCC; 48])); // wildcard uid, any binary
        assert!(al.permits(9, &[0xAA; 48])); // pinned uid+hash
        assert!(!al.permits(9, &[0xBB; 48])); // uid 9 not wildcard
        assert!(!al.permits(8, &[0xAA; 48])); // uid 8 listed nowhere
    }

    /// `rules()` folds entries exactly as `permits()` does: a caller passes
    /// precisely when some rule covers its binary and admits its uid.
    #[test]
    fn rules_mirror_permits() {
        let (sk, pk) = keypair();
        let mut d = doc(1000);
        d.entries = vec![
            AllowEntry {
                uid: Some(8),
                bin_sha: hex::encode([0xBB; 48]),
            },
            AllowEntry {
                uid: Some(7),
                bin_sha: hex::encode([0xBB; 48]),
            },
            AllowEntry {
                uid: None,
                bin_sha: hex::encode([0xAA; 48]),
            },
            AllowEntry {
                uid: Some(5),
                bin_sha: BIN_SHA_WILDCARD.to_string(),
            },
        ];
        let al = Allowlist::load(&signed_bytes(&d, &sk), &pk, 1000, 86_400).unwrap();
        assert_eq!(
            al.rules(),
            vec![
                AllowRule {
                    bin_sha: None,
                    uids: RuleUids::Only(vec![5]),
                },
                AllowRule {
                    bin_sha: Some([0xAA; 48]),
                    uids: RuleUids::Any,
                },
                AllowRule {
                    bin_sha: Some([0xBB; 48]),
                    uids: RuleUids::Only(vec![7, 8]),
                },
            ]
        );
        let rules = al.rules();
        for uid in [0, 5, 7, 8, 9] {
            for sha in [[0xAA; 48], [0xBB; 48], [0xCC; 48]] {
                let by_rules = rules
                    .iter()
                    .any(|r| r.bin_sha.is_none_or(|pinned| pinned == sha) && r.uids.admits(uid));
                assert_eq!(by_rules, al.permits(uid, &sha), "uid {uid}");
            }
        }
    }

    #[test]
    fn wrong_key_fails_closed() {
        let (sk, _pk) = keypair();
        let (_sk2, pk2) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        let err = Allowlist::load(&bytes, &pk2, 1000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::BadSignature));
    }

    #[test]
    fn tampered_body_fails_closed() {
        let (sk, pk) = keypair();
        let mut signed = sign(&doc(1000), &sk).unwrap();
        // Flip a byte in the signed body; the signature no longer matches.
        signed.body[0] ^= 0xFF;
        let bytes = encode(&signed).unwrap();
        let err = Allowlist::load(&bytes, &pk, 1000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::BadSignature));
    }

    #[test]
    fn expired_allowlist_is_rejected() {
        let (sk, pk) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        // not_after = 4600; now past it.
        let err = Allowlist::load(&bytes, &pk, 5000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::Expired));
    }

    #[test]
    fn too_old_allowlist_is_rejected() {
        let (sk, pk) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        // within not_after (issued 1000, not_after 4600) but issued long ago.
        let err = Allowlist::load(&bytes, &pk, 4000, 60).unwrap_err();
        assert!(matches!(err, AllowlistError::TooOld));
    }

    /// A freshly signed allowlist whose `issued_at` is a hair in the future
    /// (CMIS clock slightly ahead of this host) is accepted within the skew
    /// leeway, rather than failing closed as `NotYetValid`.
    #[test]
    fn small_future_skew_is_tolerated() {
        let (sk, pk) = keypair();
        // issued_at = 1000, verified at 999 (1s before) — inside the leeway.
        let bytes = signed_bytes(&doc(1000), &sk);
        let al = Allowlist::load(&bytes, &pk, 999, 86_400).unwrap();
        assert!(al.permits(1001, &[0xAA; 48]));
        // At exactly the leeway boundary it is still accepted.
        let al =
            Allowlist::load(&bytes, &pk, 1000 - ALLOWLIST_NOT_BEFORE_LEEWAY_SECS, 86_400).unwrap();
        assert!(al.permits(1001, &[0xAA; 48]));
    }

    /// A `issued_at` further in the future than the skew leeway is still
    /// rejected as `NotYetValid` (a genuinely not-yet-valid file).
    #[test]
    fn large_future_skew_is_rejected() {
        let (sk, pk) = keypair();
        let bytes = signed_bytes(&doc(1000), &sk);
        let err = Allowlist::load(
            &bytes,
            &pk,
            1000 - ALLOWLIST_NOT_BEFORE_LEEWAY_SECS - 1,
            86_400,
        )
        .unwrap_err();
        assert!(matches!(err, AllowlistError::NotYetValid));
    }

    #[test]
    fn garbage_bytes_fail_closed() {
        let (_sk, pk) = keypair();
        let err = Allowlist::load(&[0xFF, 0x00, 0x42], &pk, 1000, 86_400).unwrap_err();
        assert!(matches!(err, AllowlistError::Cbor(_)));
    }

    /// A scratch directory with an optional allowlist body and key file, for
    /// exercising `load_at_startup`.
    fn startup_dir(tag: &str, body: Option<&[u8]>, key: Option<&[u8]>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mia-allowlist-startup-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(bytes) = body {
            std::fs::write(dir.join("allowlist.cbor"), bytes).unwrap();
        }
        if let Some(bytes) = key {
            std::fs::write(dir.join("allowlist.pub"), bytes).unwrap();
        }
        dir
    }

    fn load_startup(dir: &std::path::Path) -> std::io::Result<Option<Allowlist>> {
        load_at_startup(
            &dir.join("allowlist.cbor"),
            &dir.join("allowlist.pub"),
            1000,
            86_400,
        )
    }

    #[test]
    fn startup_loads_valid_allowlist() {
        let (sk, pk) = keypair();
        let dir = startup_dir(
            "valid",
            Some(&signed_bytes(&doc(1000), &sk)),
            Some(&pk.to_concat_bytes()),
        );
        let al = load_startup(&dir).unwrap().expect("allowlist loaded");
        assert!(al.permits(1001, &[0xAA; 48]));
    }

    #[test]
    fn startup_missing_body_denies_all_without_crashing() {
        let (_sk, pk) = keypair();
        let dir = startup_dir("no-body", None, Some(&pk.to_concat_bytes()));
        assert!(load_startup(&dir).unwrap().is_none());
    }

    #[test]
    fn startup_bad_signature_denies_all_without_crashing() {
        // A stale pinned key (CMIS re-keyed) must not abort startup: the
        // daemon serves deny-all so the socket stays diagnosable.
        let (sk, _pk) = keypair();
        let (_sk2, pk2) = keypair();
        let dir = startup_dir(
            "bad-sig",
            Some(&signed_bytes(&doc(1000), &sk)),
            Some(&pk2.to_concat_bytes()),
        );
        assert!(load_startup(&dir).unwrap().is_none());
    }

    #[test]
    fn startup_missing_key_file_denies_all_without_crashing() {
        let (sk, _pk) = keypair();
        let dir = startup_dir("no-key", Some(&signed_bytes(&doc(1000), &sk)), None);
        assert!(load_startup(&dir).unwrap().is_none());
    }

    #[test]
    fn startup_unparseable_key_denies_all_without_crashing() {
        let (sk, _pk) = keypair();
        let dir = startup_dir(
            "bad-key",
            Some(&signed_bytes(&doc(1000), &sk)),
            Some(&[0x42; 7]),
        );
        assert!(load_startup(&dir).unwrap().is_none());
    }

    #[test]
    fn classified_load_distinguishes_missing_invalid_and_loaded() {
        let (sk, pk) = keypair();
        let (_sk2, pk2) = keypair();
        let classify = |dir: &std::path::Path| {
            load_classified(
                &dir.join("allowlist.cbor"),
                &dir.join("allowlist.pub"),
                1000,
                86_400,
            )
            .unwrap()
            .1
        };
        let ok = startup_dir(
            "class-ok",
            Some(&signed_bytes(&doc(1000), &sk)),
            Some(&pk.to_concat_bytes()),
        );
        assert_eq!(
            classify(&ok),
            AllowlistLoad::Loaded {
                entries: 1,
                not_after: 4600
            }
        );
        let missing = startup_dir("class-missing", None, Some(&pk.to_concat_bytes()));
        assert_eq!(classify(&missing), AllowlistLoad::Missing);
        let invalid = startup_dir(
            "class-invalid",
            Some(&signed_bytes(&doc(1000), &sk)),
            Some(&pk2.to_concat_bytes()),
        );
        assert_eq!(classify(&invalid), AllowlistLoad::Invalid);
        for d in [ok, missing, invalid] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// A configuration whose allowlist body resolves to the per-environment
    /// default of an environment no host has, so the default file is absent.
    fn default_path_config(toml: &str) -> crate::config::Config {
        let c = crate::config::Config::from_toml(toml)
            .unwrap()
            .with_environment("zz-mia-unit-test-absent");
        assert!(c.allowlist_path_is_default());
        assert!(
            !c.allowlist_path().exists(),
            "{}",
            c.allowlist_path().display()
        );
        c
    }

    /// `key = '<dir>/allowlist.pub'`, plus `extra` TOML lines.
    fn key_toml(dir: &std::path::Path, extra: &str) -> String {
        format!(
            "[allowlist]\nkey = '{}'\n{extra}",
            dir.join("allowlist.pub").display()
        )
    }

    #[test]
    fn startup_without_a_key_denies_all_at_the_default_path() {
        // The unconfigured state: the body defaults, the trust anchor does
        // not, so every caller is denied — and the daemon still starts.
        let (al, outcome) = load_for_startup(&default_path_config(""), 1000).unwrap();
        assert!(al.is_none());
        assert_eq!(outcome, AllowlistLoad::Missing);
    }

    #[test]
    fn startup_with_a_nonexistent_default_file_denies_all_without_crashing() {
        let (_sk, pk) = keypair();
        let dir = startup_dir("default-absent", None, Some(&pk.to_concat_bytes()));
        let c = default_path_config(&key_toml(&dir, ""));
        let (al, outcome) = load_for_startup(&c, 1000).unwrap();
        assert!(al.is_none());
        assert_eq!(outcome, AllowlistLoad::Missing);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn startup_with_an_explicit_path_but_no_key_still_refuses_to_start() {
        let c =
            crate::config::Config::from_toml("[allowlist]\npath = '/nonexistent/al.cbor'").unwrap();
        let err = load_for_startup(&c, 1000).unwrap_err();
        assert!(err.to_string().contains("allowlist.key"), "{err}");
    }

    #[test]
    fn startup_loads_and_verifies_an_explicit_allowlist() {
        let (sk, pk) = keypair();
        let dir = startup_dir(
            "explicit-ok",
            Some(&signed_bytes(&doc(1000), &sk)),
            Some(&pk.to_concat_bytes()),
        );
        let path = format!("path = '{}'", dir.join("allowlist.cbor").display());
        let c = crate::config::Config::from_toml(&key_toml(&dir, &path)).unwrap();
        let (al, outcome) = load_for_startup(&c, 1000).unwrap();
        assert!(al.expect("verified").permits(1001, &[0xAA; 48]));
        assert!(matches!(outcome, AllowlistLoad::Loaded { entries: 1, .. }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn startup_unreadable_body_is_fatal_only_when_explicit() {
        // A directory where the body should be: reading it is an I/O error
        // other than NotFound.
        let (_sk, pk) = keypair();
        let dir = startup_dir("unreadable", None, Some(&pk.to_concat_bytes()));
        let body = dir.join("allowlist.cbor");
        std::fs::create_dir_all(&body).unwrap();
        let key = dir.join("allowlist.pub");
        // An operator-named path keeps the loud failure ...
        assert!(startup_policy(&body, false, Some(&key), 1000, 86_400).is_err());
        // ... the default location fails closed instead of stopping the daemon.
        let (al, outcome) = startup_policy(&body, true, Some(&key), 1000, 86_400).unwrap();
        assert!(al.is_none());
        assert_eq!(outcome, AllowlistLoad::Invalid);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reload_without_a_key_denies_all_and_never_fails() {
        let (sk, _pk) = keypair();
        let dir = startup_dir("reload-no-key", Some(&signed_bytes(&doc(1000), &sk)), None);
        let (al, outcome) = load_for_reload(&dir.join("allowlist.cbor"), None, 1000, 86_400)
            .expect("no key is not an I/O error");
        assert!(al.is_none());
        assert_eq!(outcome, AllowlistLoad::Missing);
        let _ = std::fs::remove_dir_all(dir);
    }

    // ── v2 (F19 §6.1) ───────────────────────────────────────────────────────

    const HOST: &str = "1b4e28ba-2fa1-4d2a-883f-0016d3cca427";
    const PATH: &str = "/opt/tool/bin/tool";

    fn v2_entry(sha: u8) -> AllowEntryV2 {
        AllowEntryV2 {
            approval_id: [sha; 16],
            bin_sha: hex::encode([sha; 48]),
            uid: None,
            user_sid_hash: None,
            path_hash: None,
            expires_at: None,
        }
    }

    fn v2_bytes(entries: Vec<AllowEntryV2>, now: i64, sk: &CompositeSecretKey) -> Vec<u8> {
        let doc = AllowlistDocV2 {
            format: ALLOWLIST_V2_FORMAT,
            trust_domain: "ferrogate.test".into(),
            host_uuid: HOST.into(),
            generation: 7,
            issued_at: now,
            not_after: now + 3600,
            entries,
        };
        encode(&allowlist_v2::sign_v2(&doc, sk).unwrap()).unwrap()
    }

    fn path_hash_of(path: &str) -> [u8; 32] {
        let key = ferro_appid::path_key(ferro_appid::Platform::current(), path).unwrap();
        allowlist_v2::path_hash(HOST, &key)
    }

    fn caller<'a>(
        uid: u32,
        sha: &'a [u8; 48],
        path: Option<&'a str>,
        sid: Option<&'a str>,
    ) -> CallerFacts<'a> {
        CallerFacts {
            uid,
            bin_sha: sha,
            exe_path: path,
            user_sid: sid,
        }
    }

    #[test]
    fn v2_loads_under_its_own_context_and_carries_its_binding() {
        let (sk, pk) = keypair();
        let al = Allowlist::load(
            &v2_bytes(vec![v2_entry(0xAA)], 1000, &sk),
            &pk,
            1000,
            86_400,
        )
        .unwrap();
        assert_eq!(al.format(), 2);
        assert_eq!(al.host_uuid(), Some(HOST));
        assert_eq!(al.generation(), Some(7));
        assert_eq!(
            al.entries_digest(),
            Some(allowlist_v2::entries_digest(&[v2_entry(0xAA)]).unwrap())
        );
        assert_eq!(al.entry_count(), 1);
        assert!(al.permits_caller(&caller(5, &[0xAA; 48], None, None), 1000));
        // `load_v1` refuses a v2 body (wrong context) and `load_v2` a v1 one.
        let v2 = v2_bytes(vec![v2_entry(0xAA)], 1000, &sk);
        assert!(matches!(
            Allowlist::load_v1(&v2, &pk, 1000, 86_400),
            Err(AllowlistError::BadSignature)
        ));
        let v1 = signed_bytes(&doc(1000), &sk);
        assert!(matches!(
            Allowlist::load_v2(&v1, &pk, 1000, 86_400),
            Err(AllowlistError::BadSignature)
        ));
        // Another key verifies neither.
        let (_, other) = keypair();
        assert!(Allowlist::load(&v2, &other, 1000, 86_400).is_err());
    }

    #[test]
    fn v2_matcher_checks_uid_path_sid_and_expiry() {
        let (sk, pk) = keypair();
        let sid = "S-1-5-21-1-2-3-1001";
        let entries = vec![
            // 0xA1: uid 1001 at PATH only.
            AllowEntryV2 {
                uid: Some(1001),
                path_hash: Some(path_hash_of(PATH)),
                ..v2_entry(0xA1)
            },
            // 0xA2: one Windows user (by SID), any path.
            AllowEntryV2 {
                user_sid_hash: Some(allowlist_v2::sid_hash(HOST, sid)),
                ..v2_entry(0xA2)
            },
            // 0xA3: anyone until t = 1500.
            AllowEntryV2 {
                expires_at: Some(1500),
                ..v2_entry(0xA3)
            },
        ];
        let al = Allowlist::load(&v2_bytes(entries, 1000, &sk), &pk, 1000, 86_400).unwrap();
        let a1 = [0xA1; 48];
        assert!(al.permits_caller(&caller(1001, &a1, Some(PATH), None), 1000));
        // Path mismatch, unknown path, uid mismatch, unknown hash.
        assert!(!al.permits_caller(&caller(1001, &a1, Some("/tmp/tool"), None), 1000));
        assert!(!al.permits_caller(&caller(1001, &a1, None, None), 1000));
        assert!(!al.permits_caller(&caller(1002, &a1, Some(PATH), None), 1000));
        assert!(!al.permits_caller(&caller(1001, &[0xEE; 48], Some(PATH), None), 1000));
        // SID: equal (case-insensitive, as `sid_hash` upper-cases), other, none.
        let a2 = [0xA2; 48];
        assert!(al.permits_caller(&caller(7, &a2, None, Some(sid)), 1000));
        assert!(al.permits_caller(&caller(7, &a2, None, Some(&sid.to_lowercase())), 1000));
        assert!(!al.permits_caller(&caller(7, &a2, None, Some("S-1-5-21-9-9-9-1001")), 1000));
        assert!(!al.permits_caller(&caller(7, &a2, None, None), 1000));
        // Expiry is enforced on every check, before the document's not_after.
        let a3 = [0xA3; 48];
        assert!(al.permits_caller(&caller(7, &a3, None, None), 1499));
        assert!(!al.permits_caller(&caller(7, &a3, None, None), 1500));
        // The legacy `permits` fails closed on path and SID constraints.
        assert!(!al.permits(1001, &a1));
        assert!(!al.permits(7, &a2));
    }

    #[test]
    fn v2_legacy_wildcards_and_the_hard_expiry() {
        let (sk, pk) = keypair();
        let entries = vec![AllowEntryV2 {
            approval_id: [0; 16],
            bin_sha: BIN_SHA_WILDCARD.into(),
            uid: Some(42),
            user_sid_hash: None,
            path_hash: None,
            expires_at: None,
        }];
        let al = Allowlist::load(&v2_bytes(entries, 1000, &sk), &pk, 1000, 86_400).unwrap();
        assert!(al.permits_caller(&caller(42, &[0x01; 48], None, None), 1000));
        assert!(!al.permits_caller(&caller(43, &[0x01; 48], None, None), 1000));
        // After not_after nobody is admitted, whatever the entries say.
        assert!(!al.permits_caller(&caller(42, &[0x01; 48], None, None), 1000 + 3601));
        assert_eq!(
            al.rules(),
            vec![AllowRule {
                bin_sha: None,
                uids: RuleUids::Only(vec![42])
            }]
        );
    }

    #[test]
    fn v1_bodies_also_stop_admitting_after_not_after() {
        let (sk, pk) = keypair();
        let al = Allowlist::load(&signed_bytes(&doc(1000), &sk), &pk, 1000, 86_400).unwrap();
        let facts = caller(1001, &[0xAA; 48], None, None);
        assert!(al.permits_caller(&facts, 4600));
        assert!(!al.permits_caller(&facts, 4601));
    }
}
