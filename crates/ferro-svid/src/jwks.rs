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

/// Key type marker for FerroGate composite keys.
pub const COMPOSITE_KTY: &str = "FERROGATE-COMPOSITE";

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
}

impl Jwk {
    /// Build a JWK from a composite public key and a key id.
    #[must_use]
    pub fn from_public_key(kid: impl Into<String>, pk: &CompositePublicKey) -> Self {
        Self {
            kty: COMPOSITE_KTY.to_string(),
            alg: crate::SVID_ALG.to_string(),
            kid: kid.into(),
            use_: "sig".to_string(),
            public: URL_SAFE_NO_PAD.encode(pk.to_concat_bytes()),
        }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    /// The verification keys, newest-preferred ordering left to the caller.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// A set containing a single key.
    #[must_use]
    pub fn single(jwk: Jwk) -> Self {
        Self { keys: vec![jwk] }
    }

    /// Find a key by `kid`.
    #[must_use]
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}
