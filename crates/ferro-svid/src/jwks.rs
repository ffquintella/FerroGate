//! Composite JWK / JWK-set.
//!
//! JOSE has no registered representation for a composite Ed25519 + ML-DSA-65
//! key, so FerroGate defines a minimal one: `kty = "FERROGATE-COMPOSITE"` with
//! the concatenated public key (`ed25519(32) || mldsa65(1952)`) carried
//! base64url in the `pub` member. The reference verifier reconstructs a
//! [`ferro_crypto::composite::CompositePublicKey`] from it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::CompositePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Key type marker for FerroGate composite keys.
pub const COMPOSITE_KTY: &str = "FERROGATE-COMPOSITE";

/// Stable key id for a host's child-token signing key.
///
/// The MIA signs child tokens (feature F09) with its host composite SVID key
/// and stamps this kid into the token header; CMIS publishes the same host key
/// under the same kid in its JWKS. Deriving the kid deterministically from the
/// public key — `host-<first 8 bytes of SHA-256(pk_concat) in hex>` — means the
/// two sides never have to coordinate a name out of band. A divergence between
/// the minter's `kid` and this function is a bug.
#[must_use]
pub fn child_signing_kid(pk: &CompositePublicKey) -> String {
    let digest = Sha256::digest(pk.to_concat_bytes());
    format!("host-{}", hex::encode(&digest[..8]))
}

/// A single composite verification key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type — always [`COMPOSITE_KTY`].
    pub kty: String,
    /// Algorithm — [`crate::SVID_ALG`].
    pub alg: String,
    /// Key id matching the SVID header `kid`.
    pub kid: String,
    /// Intended use — `"sig"`.
    #[serde(rename = "use")]
    pub use_: String,
    /// base64url of the concatenated composite public key.
    #[serde(rename = "pub")]
    pub public: String,
    /// Unix-seconds creation time of the key, used by consumers to prefer the
    /// **newer** of several roots during a cross-sign rotation window (feature
    /// F14). Omitted on the wire when unset; an absent value sorts oldest.
    #[serde(
        rename = "x-ferrogate-created",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub created: Option<i64>,
}

impl Jwk {
    /// Build a JWK from a composite public key and a key id, with no creation
    /// time stamped (sorts oldest under "newer preferred").
    #[must_use]
    pub fn from_public_key(kid: impl Into<String>, pk: &CompositePublicKey) -> Self {
        Self {
            kty: COMPOSITE_KTY.to_string(),
            alg: crate::SVID_ALG.to_string(),
            kid: kid.into(),
            use_: "sig".to_string(),
            public: URL_SAFE_NO_PAD.encode(pk.to_concat_bytes()),
            created: None,
        }
    }

    /// Build a JWK stamped with a creation time (Unix seconds). Used when
    /// publishing more than one root key so verifiers can pick the newer one.
    #[must_use]
    pub fn from_public_key_at(
        kid: impl Into<String>,
        pk: &CompositePublicKey,
        created: i64,
    ) -> Self {
        let mut jwk = Self::from_public_key(kid, pk);
        jwk.created = Some(created);
        jwk
    }

    /// Reconstruct the composite public key carried by this JWK.
    pub fn to_public_key(&self) -> Result<CompositePublicKey, String> {
        let bytes = URL_SAFE_NO_PAD
            .decode(self.public.as_bytes())
            .map_err(|e| format!("jwk pub base64url: {e}"))?;
        CompositePublicKey::from_concat_bytes(&bytes).map_err(|e| format!("jwk pub: {e}"))
    }
}

/// A JWK set as served by the CMIS `JWKS` RPC.
///
/// Besides the verification keys, the set may carry FerroGate's revocation list
/// in the `x-ferrogate-crl` extension member (feature F11). The member is
/// omitted entirely when no CRL has been published yet, keeping a stock JWKS
/// parser happy; consumers that understand revocation pull it from here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    /// The verification keys, newest-preferred ordering left to the caller.
    pub keys: Vec<Jwk>,
    /// The composite-signed CRL, when published (feature F11).
    #[serde(
        rename = "x-ferrogate-crl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub crl: Option<crate::crl::SignedCrl>,
}

impl JwkSet {
    /// A set containing a single key and no CRL.
    #[must_use]
    pub fn single(jwk: Jwk) -> Self {
        Self {
            keys: vec![jwk],
            crl: None,
        }
    }

    /// Find a key by `kid`.
    #[must_use]
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// The preferred verification key under "newer preferred" ordering: the key
    /// with the greatest [`Jwk::created`] timestamp (an absent timestamp counts
    /// as oldest). Ties — and the all-unstamped case — resolve to the first key
    /// in publication order, which CMIS keeps newest-first. Returns `None` only
    /// for an empty set.
    ///
    /// SVID verification still resolves by the token's header `kid`; this is for
    /// consumers choosing a trust anchor across a cross-sign window (feature
    /// F14), where both the outgoing and incoming roots are published at once.
    #[must_use]
    pub fn preferred(&self) -> Option<&Jwk> {
        self.keys
            .iter()
            .enumerate()
            .max_by_key(|(i, k)| (k.created.unwrap_or(i64::MIN), std::cmp::Reverse(*i)))
            .map(|(_, k)| k)
    }
}
