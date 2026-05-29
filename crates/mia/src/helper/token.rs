//! Child-token minter (feature F09, consumed by the F08 helper API).
//!
//! A child token is a compact JWS signed with the host's composite SVID key.
//! It is audience-bound (`aud`), DPoP-bound (`cnf.jkt`), short-lived
//! (TTL ≤ [`MAX_CHILD_TTL_SECS`]), and carries a `ferrogate` block naming the
//! parent SVID and the local actor. See `docs/helper-api.md` §"Token shape".
//!
//! The layout mirrors the SVID envelope (`ferro_svid::envelope`) — header and
//! payload are base64url(JSON), the composite signature covers
//! `BASE64URL(header) "." BASE64URL(payload)` — but under a distinct signing
//! context and `typ` so an SVID and a child token can never be confused.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::{CompositeError, CompositeSecretKey, COMPOSITE_JOSE_ALG};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::helper::auth::CallerIdentity;

/// Hard cap on child-token lifetime (seconds). Requests above this are clamped.
pub const MAX_CHILD_TTL_SECS: u32 = 600;

/// JOSE `typ` marking the child-token profile.
pub const CHILD_TOKEN_TYP: &str = "ferrogate-child+jwt";

/// Domain-separation context the composite signature covers. Distinct from the
/// SVID and allowlist contexts.
pub const CHILD_TOKEN_SIGNING_CONTEXT: &[u8] = b"ferrogate-child-token-v1";

/// JOSE header of a child token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildHeader {
    /// Signature algorithm — always [`COMPOSITE_JOSE_ALG`].
    pub alg: String,
    /// Token type — always [`CHILD_TOKEN_TYP`].
    pub typ: String,
    /// Key id selecting the host SVID key in the published JWKS.
    pub kid: String,
}

/// DPoP confirmation claim (RFC 9449).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    /// Base64url SHA-256 thumbprint of the caller's DPoP public JWK.
    pub jkt: String,
}

/// FerroGate-specific provenance block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FerrogateClaim {
    /// Lowercase hex `SHA-384` of the parent host SVID.
    pub parent_svid: String,
    /// Local actor process id.
    pub actor_pid: u32,
    /// Local actor user id.
    pub actor_uid: u32,
    /// Lowercase hex `SHA-384` (IMA) of the actor binary.
    pub actor_bin: String,
}

/// Child-token claims (RFC 7519 plus the `ferrogate` block).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildClaims {
    /// Issuer — the host SPIFFE id.
    pub iss: String,
    /// Subject — `<host-spiffe-id>#app:<bin_sha[:16-hex]>`.
    pub sub: String,
    /// Audience the token is valid for.
    pub aud: String,
    /// Expiry, Unix seconds.
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// 128-bit token id, lowercase hex.
    pub jti: String,
    /// DPoP binding.
    pub cnf: Cnf,
    /// FerroGate provenance.
    pub ferrogate: FerrogateClaim,
}

/// Static configuration the minter stamps into every token.
#[derive(Debug, Clone)]
pub struct MinterConfig {
    /// The host SPIFFE id (becomes `iss` and the `sub` prefix).
    pub host_spiffe_id: String,
    /// `SHA-384` of the parent host SVID.
    pub parent_svid_sha384: [u8; 48],
    /// Key id of the host SVID signing key in the published JWKS.
    pub kid: String,
}

/// A minted token plus the bits the helper server needs for audit and reply.
#[derive(Debug, Clone)]
pub struct MintedToken {
    /// The compact JWS.
    pub jws: String,
    /// Raw 128-bit `jti` (for the `LocalGrant` audit event).
    pub jti: [u8; 16],
    /// Expiry, Unix seconds.
    pub exp: i64,
}

/// Mints child tokens with the host composite SVID key.
pub struct ChildTokenMinter {
    secret: CompositeSecretKey,
    cfg: MinterConfig,
}

impl ChildTokenMinter {
    /// Build a minter from the host SVID secret key and its config.
    #[must_use]
    pub fn new(secret: CompositeSecretKey, cfg: MinterConfig) -> Self {
        Self { secret, cfg }
    }

    /// The host SPIFFE id this minter issues under (used by the F11 CRL gate to
    /// check whether the host itself has been revoked).
    #[must_use]
    pub fn host_spiffe_id(&self) -> &str {
        &self.cfg.host_spiffe_id
    }

    /// Lowercase hex `SHA-384` of the parent host SVID — the `cert_sha` a CMIS
    /// operator would use to revoke this specific SVID (feature F11).
    #[must_use]
    pub fn parent_cert_sha_hex(&self) -> String {
        hex::encode(self.cfg.parent_svid_sha384)
    }

    /// Mint a token for `actor`, bound to `audience` and `dpop_jkt`.
    ///
    /// `ttl_secs` is clamped to [`MAX_CHILD_TTL_SECS`]; `now` is the reference
    /// clock in Unix seconds. The `jti` is freshly drawn from the OS CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics only if JSON-serializing the fixed-shape header/claims structs
    /// fails, which cannot happen for these plain `serde` types.
    pub fn mint(
        &self,
        audience: &str,
        dpop_jkt: &str,
        ttl_secs: u32,
        actor: &CallerIdentity,
        now: i64,
    ) -> Result<MintedToken, CompositeError> {
        let ttl = ttl_secs.min(MAX_CHILD_TTL_SECS);
        let exp = now + i64::from(ttl);

        let mut jti = [0u8; 16];
        OsRng.fill_bytes(&mut jti);

        let actor_bin = hex::encode(actor.bin_sha);
        // `bin_sha[:16]` in the design note is the first 16 hex chars (8 bytes).
        let sub = format!("{}#app:{}", self.cfg.host_spiffe_id, &actor_bin[..16]);

        let claims = ChildClaims {
            iss: self.cfg.host_spiffe_id.clone(),
            sub,
            aud: audience.to_string(),
            exp,
            iat: now,
            jti: hex::encode(jti),
            cnf: Cnf {
                jkt: dpop_jkt.to_string(),
            },
            ferrogate: FerrogateClaim {
                parent_svid: hex::encode(self.cfg.parent_svid_sha384),
                actor_pid: actor.pid,
                actor_uid: actor.uid,
                actor_bin,
            },
        };

        let header = ChildHeader {
            alg: COMPOSITE_JOSE_ALG.to_string(),
            typ: CHILD_TOKEN_TYP.to_string(),
            kid: self.cfg.kid.clone(),
        };

        // JSON serialization of plain structs cannot fail here, but propagate
        // rather than unwrap to keep the minter total.
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims json"));
        let signing_input = format!("{h}.{p}");

        let sig = self
            .secret
            .sign(CHILD_TOKEN_SIGNING_CONTEXT, signing_input.as_bytes())?;
        let s = URL_SAFE_NO_PAD.encode(sig.to_concat_bytes());
        let jws = format!("{signing_input}.{s}");

        Ok(MintedToken { jws, jti, exp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_crypto::composite::{CompositePublicKey, CompositeSignature};

    fn minter() -> (ChildTokenMinter, CompositePublicKey) {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let cfg = MinterConfig {
            host_spiffe_id: "spiffe://ferrogate.test/host/abc".into(),
            parent_svid_sha384: [0x33; 48],
            kid: "host-kid-1".into(),
        };
        (ChildTokenMinter::new(sk, cfg), pk)
    }

    fn actor() -> CallerIdentity {
        CallerIdentity {
            pid: 1234,
            uid: 1001,
            gid: 1001,
            bin_sha: [0xAB; 48],
        }
    }

    /// Decode a compact JWS into (header, claims, signing_input, sig_bytes).
    fn split(jws: &str) -> (ChildHeader, ChildClaims, String, Vec<u8>) {
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: ChildHeader =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: ChildClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        (header, claims, format!("{}.{}", parts[0], parts[1]), sig)
    }

    #[test]
    fn minted_token_self_verifies_under_host_key() {
        let (m, pk) = minter();
        let t = m
            .mint(
                "https://api.example.com",
                "jkt-xyz",
                300,
                &actor(),
                1_000_000,
            )
            .unwrap();
        let (header, claims, si, sig_bytes) = split(&t.jws);

        assert_eq!(header.alg, COMPOSITE_JOSE_ALG);
        assert_eq!(header.typ, CHILD_TOKEN_TYP);
        assert_eq!(header.kid, "host-kid-1");
        assert_eq!(claims.aud, "https://api.example.com");
        assert_eq!(claims.cnf.jkt, "jkt-xyz");
        assert_eq!(claims.exp - claims.iat, 300);
        assert_eq!(claims.ferrogate.actor_pid, 1234);
        assert_eq!(claims.ferrogate.actor_uid, 1001);
        assert_eq!(
            claims.sub,
            "spiffe://ferrogate.test/host/abc#app:abababababababab"
        );

        let sig = CompositeSignature::from_concat_bytes(&sig_bytes).unwrap();
        pk.verify(CHILD_TOKEN_SIGNING_CONTEXT, si.as_bytes(), &sig)
            .expect("child token verifies under host key");
    }

    #[test]
    fn ttl_is_clamped_to_max() {
        let (m, _pk) = minter();
        let t = m.mint("aud", "jkt", 100_000, &actor(), 0).unwrap();
        assert_eq!(t.exp, i64::from(MAX_CHILD_TTL_SECS));
    }

    #[test]
    fn jti_is_unique_per_mint() {
        let (m, _pk) = minter();
        let a = m.mint("aud", "jkt", 60, &actor(), 0).unwrap();
        let b = m.mint("aud", "jkt", 60, &actor(), 0).unwrap();
        assert_ne!(a.jti, b.jti);
    }

    #[test]
    fn wrong_context_does_not_verify() {
        // A child token must not verify under the SVID context — domain sep.
        let (m, pk) = minter();
        let t = m.mint("aud", "jkt", 60, &actor(), 0).unwrap();
        let (_h, _c, si, sig_bytes) = split(&t.jws);
        let sig = CompositeSignature::from_concat_bytes(&sig_bytes).unwrap();
        assert!(pk
            .verify(ferro_svid::SVID_SIGNING_CONTEXT, si.as_bytes(), &sig)
            .is_err());
    }
}
