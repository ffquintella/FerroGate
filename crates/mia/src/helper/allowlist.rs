//! The signed caller allowlist — MIA-side runtime verifier.
//!
//! Only `(uid, bin_sha384)` pairs present in the allowlist may obtain a token.
//! The allowlist is signed by CMIS (see [`ferro_svid::Issuer::sign_allowlist`])
//! and re-verified here before use; verification **fails closed** — any decode,
//! signature, or freshness error yields no usable allowlist, so the server
//! denies every caller rather than fall back to an unauthenticated state.
//!
//! The wire model ([`AllowlistDoc`], [`SignedAllowlist`], `sign`/`encode`) lives
//! in `ferro-svid` so CMIS and the MIA share one definition; it is re-exported
//! here for convenience. This module owns the freshness-checked, membership-set
//! [`Allowlist`] that the helper API consults.

use std::collections::{HashMap, HashSet};

use ferro_crypto::composite::CompositePublicKey;

// Re-export the shared wire model so existing `mia::helper::allowlist::*` users
// (and tests) keep working unchanged.
pub use ferro_svid::allowlist::{
    decode, encode, sign, AllowEntry, AllowlistDoc, AllowlistError, SignedAllowlist,
    ALLOWLIST_SIGNING_CONTEXT, BIN_SHA_WILDCARD,
};

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

/// A verified, in-memory allowlist ready for `O(1)` membership checks.
///
/// Keyed by binary hash: a caller is permitted when its hash is present and the
/// hash's [`UidScope`] admits the caller's uid. `Any` wins if a hash appears as
/// both a wildcard and a pinned entry.
///
/// `any_bin` captures the binary-side wildcard (`bin_sha = "*"`): when set, its
/// [`UidScope`] admits a caller regardless of its binary hash. It is folded the
/// same way as a per-hash scope, so `(uid = None, bin_sha = "*")` becomes
/// `Any` (admit everyone) while `(uid = Some(n), bin_sha = "*")` admits uid `n`
/// running any binary.
#[derive(Debug, Clone)]
pub struct Allowlist {
    trust_domain: String,
    not_after: i64,
    members: HashMap<[u8; 48], UidScope>,
    any_bin: Option<UidScope>,
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

/// Does `scope` admit `uid`?
fn scope_admits(scope: Option<&UidScope>, uid: u32) -> bool {
    match scope {
        Some(UidScope::Any) => true,
        Some(UidScope::Only(uids)) => uids.contains(&uid),
        None => false,
    }
}

impl Allowlist {
    /// Verify and load a [`SignedAllowlist`] from its CBOR bytes.
    ///
    /// `trusted` is the CMIS enrollment public key; `now` is the reference
    /// clock; `max_age_secs` bounds how stale the file may be (`issued_at`).
    /// The not-before check tolerates up to
    /// [`ALLOWLIST_NOT_BEFORE_LEEWAY_SECS`] of forward clock skew so a freshly
    /// signed allowlist is not spuriously rejected. Any failure is fatal and
    /// fails closed.
    pub fn load(
        bytes: &[u8],
        trusted: &CompositePublicKey,
        now: i64,
        max_age_secs: i64,
    ) -> Result<Self, AllowlistError> {
        let signed = ferro_svid::allowlist::decode(bytes)?;
        // Signature is checked before the body is parsed/trusted.
        let doc = ferro_svid::allowlist::verify(&signed, trusted)?;

        // Tolerate a small clock skew: CMIS may stamp `issued_at` a fraction
        // of a second ahead of this host's clock, and a strict check would
        // reject the fresh allowlist and fail closed. See
        // `ALLOWLIST_NOT_BEFORE_LEEWAY_SECS`.
        if now < doc.issued_at - ALLOWLIST_NOT_BEFORE_LEEWAY_SECS {
            return Err(AllowlistError::NotYetValid);
        }
        if now > doc.not_after {
            return Err(AllowlistError::Expired);
        }
        if now - doc.issued_at > max_age_secs {
            return Err(AllowlistError::TooOld);
        }

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
            let raw = hex::decode(&e.bin_sha).map_err(|_| AllowlistError::MalformedEntry)?;
            let arr: [u8; 48] = raw.try_into().map_err(|_| AllowlistError::MalformedEntry)?;
            match members.get_mut(&arr) {
                Some(scope) => admit(scope, e.uid),
                None => {
                    members.insert(arr, seed(e.uid));
                }
            }
        }

        Ok(Self {
            trust_domain: doc.trust_domain,
            not_after: doc.not_after,
            members,
            any_bin,
        })
    }

    /// Is the caller `(uid, bin_sha)` permitted? A binary-side wildcard
    /// (`any_bin`) admits the caller regardless of its hash; otherwise the
    /// binary hash must be listed and its [`UidScope`] must admit this `uid`.
    #[must_use]
    pub fn permits(&self, uid: u32, bin_sha: &[u8; 48]) -> bool {
        scope_admits(self.any_bin.as_ref(), uid) || scope_admits(self.members.get(bin_sha), uid)
    }

    /// The trust domain the allowlist was issued for.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Hard expiry of the allowlist, Unix seconds.
    #[must_use]
    pub fn not_after(&self) -> i64 {
        self.not_after
    }
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
/// `NotFound`) reading either file is returned as an error.
pub fn load_at_startup(
    path: &std::path::Path,
    key_path: &std::path::Path,
    now: i64,
    max_age_secs: i64,
) -> std::io::Result<Option<Allowlist>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // CMIS may have no allowlist for this host and none was ever
            // written, so the configured path can legitimately be empty.
            tracing::warn!(
                path = %path.display(),
                "allowlist.path configured but no file present; helper API denies all callers (fail closed)"
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let key_bytes = match std::fs::read(key_path) {
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
        let al = Allowlist::load(
            &bytes,
            &pk,
            1000 - ALLOWLIST_NOT_BEFORE_LEEWAY_SECS,
            86_400,
        )
        .unwrap();
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
}
