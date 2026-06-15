//! Certificate Revocation List (feature F11).
//!
//! CMIS publishes a composite-signed [`SignedCrl`] as a JWKS extension
//! (`x-ferrogate-crl`) every 60 s. The CRL names the SVIDs and hosts that have
//! been revoked and is the only revocation mechanism FerroGate ships — there is
//! deliberately no OCSP-style live lookup, so the CRL is cacheable and
//! observable (see `docs/operations.md` §"Revocation").
//!
//! Two kinds of entry are supported:
//!
//! - **per-SVID** by `cert_sha` — the lowercase hex `SHA-384` of the compact
//!   JWS bytes, the same value stamped into the [`SvidIssued`]/[`SvidRevoked`]
//!   audit events;
//! - **per-host** by SPIFFE ID — revokes every SVID and child token issued for
//!   that host.
//!
//! The signature covers the **canonical JSON** of the [`CrlBody`] (struct field
//! declaration order, which `serde_json` honours) under the domain-separation
//! context [`CRL_SIGNING_CONTEXT`], so a CRL signature can never be
//! reinterpreted as an SVID, RIM, STH, or child-token signature.
//!
//! [`SvidIssued`]: ferro_audit
//! [`SvidRevoked`]: ferro_audit

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::{CompositeError, CompositeSecretKey, CompositeSignature};
use serde::{Deserialize, Serialize};

use crate::jwks::JwkSet;

/// Domain-separation context for CRL signatures. Distinct from the SVID, RIM,
/// STH, and child-token contexts.
pub const CRL_SIGNING_CONTEXT: &[u8] = b"ferrogate-crl-v1";

/// Maximum age (seconds) of a cached CRL a consumer will trust. A MIA refuses
/// to mint child tokens once the cached CRL is older than this; verifiers treat
/// an older CRL as absent. Matches the 5-minute bound in `docs/operations.md`.
pub const CRL_MAX_AGE_SECS: i64 = 300;

/// How long a revocation entry is retained past its `revoked_at` time. SVIDs
/// live at most [`crate::MAX_TTL_SECS`]; once that elapses a revoked artefact
/// can never reappear, so the entry can be pruned to bound CRL growth. (Set
/// equal to the max SVID TTL — see the F11 "CRL bloat" risk note.)
#[allow(clippy::cast_possible_wrap)] // MAX_TTL_SECS is ~2.6M — far inside i64.
pub const CRL_ENTRY_TTL_SECS: i64 = crate::MAX_TTL_SECS as i64;

/// What a single revocation targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevocationTarget {
    /// A single SVID, identified by the lowercase hex `SHA-384` of its compact
    /// JWS bytes.
    Svid {
        /// Lowercase hex `SHA-384(jws_bytes)`.
        cert_sha: String,
    },
    /// Every SVID and child token issued for a host SPIFFE ID.
    Host {
        /// The revoked host SPIFFE ID.
        spiffe_id: String,
    },
}

/// One revocation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlEntry {
    /// What is revoked.
    pub target: RevocationTarget,
    /// Stable opcode for the revocation reason (never user free-text in a way
    /// that creates an oracle — operators choose from a documented set).
    pub reason: String,
    /// Unix seconds the revocation took effect.
    pub revoked_at: i64,
    /// Unix seconds after which this entry may be pruned (see
    /// [`CRL_ENTRY_TTL_SECS`]).
    pub expires_at: i64,
}

impl CrlEntry {
    /// Build an entry revoked at `now`, expiring [`CRL_ENTRY_TTL_SECS`] later.
    #[must_use]
    pub fn new(target: RevocationTarget, reason: impl Into<String>, now: i64) -> Self {
        Self {
            target,
            reason: reason.into(),
            revoked_at: now,
            expires_at: now.saturating_add(CRL_ENTRY_TTL_SECS),
        }
    }
}

/// The signable contents of one CRL.
///
/// `issued_at` is refreshed on every publish cycle (even when the entry set is
/// unchanged) so a freshness consumer can distinguish a live publisher from a
/// stalled one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlBody {
    /// Unix seconds the CRL was produced. Drives freshness.
    pub issued_at: i64,
    /// Monotonic publish sequence number.
    pub number: u64,
    /// The active (unexpired) revocation entries.
    pub entries: Vec<CrlEntry>,
}

impl CrlBody {
    /// Encode to the canonical JSON form the signature covers. Field
    /// declaration order is the canonical key order.
    pub fn canonical_json(&self) -> Result<Vec<u8>, CrlError> {
        serde_json::to_vec(self).map_err(|e| CrlError::Json(e.to_string()))
    }

    /// Age in seconds at reference time `now` (negative if `now` precedes
    /// issuance, which a small clock skew can produce).
    #[must_use]
    pub fn age(&self, now: i64) -> i64 {
        now - self.issued_at
    }

    /// Whether the CRL is fresh enough to trust at `now`: not produced in the
    /// future beyond `leeway`, and no older than [`CRL_MAX_AGE_SECS`].
    #[must_use]
    pub fn is_fresh(&self, now: i64, leeway_secs: i64) -> bool {
        let age = self.age(now);
        age <= CRL_MAX_AGE_SECS && age >= -leeway_secs
    }

    /// Whether an SVID with the given lowercase-hex `SHA-384` is revoked.
    #[must_use]
    pub fn revokes_svid(&self, cert_sha_hex: &str) -> bool {
        self.entries.iter().any(|e| {
            matches!(&e.target, RevocationTarget::Svid { cert_sha } if cert_sha.eq_ignore_ascii_case(cert_sha_hex))
        })
    }

    /// Whether the given host SPIFFE ID is revoked.
    #[must_use]
    pub fn revokes_host(&self, spiffe_id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(&e.target, RevocationTarget::Host { spiffe_id: s } if s == spiffe_id))
    }
}

/// A [`CrlBody`] paired with a composite signature and the issuer key id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCrl {
    /// The CRL contents.
    pub body: CrlBody,
    /// Key id selecting the issuer key in the published JWK set.
    pub signer_kid: String,
    /// base64url of the concatenated composite signature.
    pub signature_b64: String,
}

impl SignedCrl {
    /// Sign `body` with the composite issuance key.
    pub fn sign(
        body: CrlBody,
        signer_kid: impl Into<String>,
        signer: &CompositeSecretKey,
    ) -> Result<Self, CrlError> {
        let bytes = body.canonical_json()?;
        let sig = signer
            .sign(CRL_SIGNING_CONTEXT, &bytes)
            .map_err(CrlError::Sign)?;
        Ok(Self {
            body,
            signer_kid: signer_kid.into(),
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_concat_bytes()),
        })
    }

    /// Verify the composite signature against the keys published in `jwks`.
    ///
    /// Fail-closed: an unknown `signer_kid`, a malformed key or signature, or a
    /// signature that does not verify all return an error and never yield the
    /// body. Returns a borrow of the authenticated body on success.
    pub fn verify<'a>(&'a self, jwks: &JwkSet) -> Result<&'a CrlBody, CrlError> {
        let jwk = jwks
            .find(&self.signer_kid)
            .ok_or_else(|| CrlError::UnknownKid(self.signer_kid.clone()))?;
        let pk = jwk.to_public_key().map_err(CrlError::BadKey)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(self.signature_b64.as_bytes())
            .map_err(|e| CrlError::BadSignature(format!("base64url: {e}")))?;
        let sig = CompositeSignature::from_concat_bytes(&sig_bytes)
            .map_err(|e| CrlError::BadSignature(e.to_string()))?;
        let payload = self.body.canonical_json()?;
        pk.verify(CRL_SIGNING_CONTEXT, &payload, &sig)
            .map_err(|e| CrlError::BadSignature(e.to_string()))?;
        Ok(&self.body)
    }
}

/// Failure modes for CRL codec / signing / verification.
#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(String),
    /// The composite signer failed.
    #[error("composite sign: {0}")]
    Sign(CompositeError),
    /// No published key matched `signer_kid`.
    #[error("unknown signer kid: {0}")]
    UnknownKid(String),
    /// The published key could not be reconstructed.
    #[error("signer key: {0}")]
    BadKey(String),
    /// The signature was malformed or did not verify.
    #[error("signature did not verify: {0}")]
    BadSignature(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::{Jwk, JwkSet};

    fn body(now: i64) -> CrlBody {
        CrlBody {
            issued_at: now,
            number: 1,
            entries: vec![
                CrlEntry::new(
                    RevocationTarget::Svid {
                        cert_sha: "ab".repeat(48),
                    },
                    "key-compromise",
                    now,
                ),
                CrlEntry::new(
                    RevocationTarget::Host {
                        spiffe_id: "spiffe://ferrogate.test/host/bad".into(),
                    },
                    "decommissioned",
                    now,
                ),
            ],
        }
    }

    fn keypair_jwks(kid: &str) -> (CompositeSecretKey, JwkSet) {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let jwks = JwkSet::single(Jwk::from_public_key(kid, &pk));
        (sk, jwks)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, jwks) = keypair_jwks("cmis-1");
        let signed = SignedCrl::sign(body(1_000), "cmis-1", &sk).unwrap();
        let verified = signed.verify(&jwks).unwrap();
        assert_eq!(verified.number, 1);
        assert!(verified.revokes_svid(&"AB".repeat(48))); // case-insensitive
        assert!(verified.revokes_host("spiffe://ferrogate.test/host/bad"));
        assert!(!verified.revokes_host("spiffe://ferrogate.test/host/good"));
    }

    #[test]
    fn tampered_body_fails_closed() {
        let (sk, jwks) = keypair_jwks("cmis-1");
        let mut signed = SignedCrl::sign(body(1_000), "cmis-1", &sk).unwrap();
        // Flip a revocation target after signing.
        signed.body.entries[0] = CrlEntry::new(
            RevocationTarget::Svid {
                cert_sha: "cd".repeat(48),
            },
            "key-compromise",
            1_000,
        );
        assert!(matches!(
            signed.verify(&jwks),
            Err(CrlError::BadSignature(_))
        ));
    }

    #[test]
    fn unknown_kid_is_refused_before_crypto() {
        let (sk, _jwks) = keypair_jwks("cmis-1");
        let other = keypair_jwks("cmis-2").1;
        let signed = SignedCrl::sign(body(1_000), "cmis-1", &sk).unwrap();
        assert!(matches!(
            signed.verify(&other),
            Err(CrlError::UnknownKid(k)) if k == "cmis-1"
        ));
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let (sk, _jwks) = keypair_jwks("cmis-1");
        // A JWK set that lists `cmis-1` but with a *different* public key.
        let (_sk2, pk2) = CompositeSecretKey::generate().unwrap();
        let wrong = JwkSet::single(Jwk::from_public_key("cmis-1", &pk2));
        let signed = SignedCrl::sign(body(1_000), "cmis-1", &sk).unwrap();
        assert!(matches!(
            signed.verify(&wrong),
            Err(CrlError::BadSignature(_))
        ));
    }

    #[test]
    fn freshness_window() {
        let b = body(1_000);
        assert!(b.is_fresh(1_000, 60));
        assert!(b.is_fresh(1_000 + CRL_MAX_AGE_SECS, 60));
        assert!(!b.is_fresh(1_000 + CRL_MAX_AGE_SECS + 1, 60));
        // Future-dated beyond leeway is not fresh.
        assert!(!b.is_fresh(1_000 - 61, 60));
    }

    #[test]
    fn entry_expiry_is_one_svid_ttl_out() {
        let e = CrlEntry::new(
            RevocationTarget::Host {
                spiffe_id: "spiffe://x/host/y".into(),
            },
            "r",
            500,
        );
        assert_eq!(e.expires_at, 500 + CRL_ENTRY_TTL_SECS);
    }
}
