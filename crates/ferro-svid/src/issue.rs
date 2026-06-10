//! SVID issuance: turn verified attestation evidence into a signed compact JWS.

use ferro_crypto::composite::{CompositeError, CompositePublicKey, CompositeSecretKey};

use crate::allowlist::{self, AllowEntry, AllowlistDoc, AllowlistError, SignedAllowlist};
use crate::claims::{AttestClaims, Cnf, SvidClaims};
use crate::crl::{CrlBody, CrlError, SignedCrl};
use crate::envelope::{self, EnvelopeError, JwsHeader};
use crate::jwks::{Jwk, JwkSet};
use crate::spiffe::{self, SpiffeError};

/// Inputs CMIS supplies to mint one SVID. All hardware/boot fields come from a
/// verified [`ferro_attest::VerifiedQuote`]; the DPoP thumbprint comes from the
/// phase-4 CSR.
#[derive(Debug, Clone)]
pub struct IssueParams {
    /// `SHA-384(ek_cert_der)` — drives both the subject UUID and the `attest`
    /// claim.
    pub ek_cert_sha384: [u8; 48],
    /// Aggregate PCR digest the RIM approved.
    pub pcr_digest: [u8; 48],
    /// RIM policy generation identifier.
    pub policy_id: String,
    /// DPoP key thumbprint to bind via `cnf.jkt`.
    pub dpop_jkt: String,
    /// Requested lifetime; clamped to [`crate::MAX_TTL_SECS`].
    pub ttl_secs: u64,
    /// Optional TEE evidence id (`None` in the M2 single-replica config).
    pub tee_evidence_id: Option<String>,
}

/// A freshly issued SVID and its salient metadata.
#[derive(Debug, Clone)]
pub struct IssuedSvid {
    /// The compact JWS.
    pub jws: String,
    /// Subject SPIFFE ID.
    pub spiffe_id: String,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Expiry, Unix seconds.
    pub exp: i64,
}

/// Failure modes for issuance.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// The trust domain or derived SPIFFE ID was invalid.
    #[error("spiffe: {0}")]
    Spiffe(#[from] SpiffeError),
    /// JWS encoding failed.
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    /// The composite signer failed.
    #[error("composite sign: {0}")]
    Composite(#[from] CompositeError),
    /// CRL signing failed.
    #[error("crl: {0}")]
    Crl(#[from] CrlError),
    /// Allowlist signing/encoding failed.
    #[error("allowlist: {0}")]
    Allowlist(#[from] AllowlistError),
}

/// The CMIS issuance authority: a composite signing key plus the trust-domain
/// identity it stamps into every SVID.
pub struct Issuer {
    secret: CompositeSecretKey,
    public: CompositePublicKey,
    kid: String,
    trust_domain: String,
}

impl Issuer {
    /// Build an issuer from a composite keypair, a key id, and a trust domain.
    #[must_use]
    pub fn new(
        secret: CompositeSecretKey,
        public: CompositePublicKey,
        kid: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Self {
        Self {
            secret,
            public,
            kid: kid.into(),
            trust_domain: trust_domain.into(),
        }
    }

    /// Generate a brand-new issuer with a random composite key.
    pub fn generate(
        kid: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Result<Self, IssueError> {
        let (secret, public) = CompositeSecretKey::generate()?;
        Ok(Self::new(secret, public, kid, trust_domain))
    }

    /// Rebuild an issuer **deterministically** from a 32-byte master seed.
    ///
    /// The same seed always yields the same composite key (and therefore the
    /// same JWKS public key under `kid`), so persisting the 32-byte seed across
    /// restarts keeps the issuer's identity — and the CRL / allowlist / SVID
    /// signatures that consumers have already pinned — stable. Only the seed is
    /// secret material at rest; the expanded private key never touches disk.
    #[must_use]
    pub fn from_seed(
        seed: &[u8; 32],
        kid: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Self {
        let (secret, public) = CompositeSecretKey::from_seed(seed);
        Self::new(secret, public, kid, trust_domain)
    }

    /// The signing key id.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The composite public key (for JWKS / verification).
    #[must_use]
    pub fn public_key(&self) -> &CompositePublicKey {
        &self.public
    }

    /// The JWK set this issuer publishes (currently a single key).
    #[must_use]
    pub fn jwks(&self) -> JwkSet {
        JwkSet::single(Jwk::from_public_key(self.kid.clone(), &self.public))
    }

    /// Sign a [`CrlBody`] with the composite issuance key, stamping this
    /// issuer's `kid` so consumers resolve the verification key from the same
    /// published JWK set (feature F11).
    pub fn sign_crl(&self, body: CrlBody) -> Result<SignedCrl, IssueError> {
        Ok(SignedCrl::sign(body, self.kid.clone(), &self.secret)?)
    }

    /// Sign a caller allowlist for a host. Stamps this issuer's `trust_domain`
    /// into the body (so it always matches the SVIDs the same key issues) and
    /// the supplied validity window, then signs with the composite issuance key
    /// under the allowlist domain-separation context. The MIA verifies the
    /// result with the public half published over `GetEnrollmentKey`.
    pub fn sign_allowlist(
        &self,
        entries: Vec<AllowEntry>,
        issued_at: i64,
        not_after: i64,
    ) -> Result<SignedAllowlist, IssueError> {
        let doc = AllowlistDoc {
            trust_domain: self.trust_domain.clone(),
            issued_at,
            not_after,
            entries,
        };
        Ok(allowlist::sign(&doc, &self.secret)?)
    }

    /// Mint an SVID. `now` is the reference clock in Unix seconds.
    pub fn issue(&self, params: &IssueParams, now: i64) -> Result<IssuedSvid, IssueError> {
        let ttl = params.ttl_secs.min(crate::MAX_TTL_SECS);
        let iat = now;
        let nbf = iat - crate::NBF_LOOKBACK_SECS;
        let exp = iat + i64::try_from(ttl).unwrap_or(i64::from(u32::MAX));

        let sub = spiffe::spiffe_host_id(&self.trust_domain, &params.ek_cert_sha384)?;
        let iss = spiffe::spiffe_issuer_id(&self.trust_domain)?;

        let claims = SvidClaims {
            iss,
            sub: sub.clone(),
            iat,
            nbf,
            exp,
            cnf: Cnf {
                jkt: params.dpop_jkt.clone(),
            },
            attest: AttestClaims {
                ek_cert_sha384: hex::encode(params.ek_cert_sha384),
                pcr_digest_sha384: hex::encode(params.pcr_digest),
                policy_id: params.policy_id.clone(),
                tee_evidence_id: params.tee_evidence_id.clone(),
            },
        };

        let header = JwsHeader::new(self.kid.clone());
        let signing_input = envelope::signing_input(&header, &claims)?;
        let sig = self
            .secret
            .sign(crate::SVID_SIGNING_CONTEXT, signing_input.as_bytes())?;
        let jws = envelope::compact(&signing_input, &sig.to_concat_bytes());

        Ok(IssuedSvid {
            jws,
            spiffe_id: sub,
            iat,
            exp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> IssueParams {
        IssueParams {
            ek_cert_sha384: [0x11; 48],
            pcr_digest: [0x22; 48],
            policy_id: "rim-gen-5".to_string(),
            dpop_jkt: "abc123".to_string(),
            ttl_secs: 3600,
            tee_evidence_id: None,
        }
    }

    #[test]
    fn issue_roundtrips_through_envelope_and_self_verifies() {
        let issuer = Issuer::generate("kid-1", "ferrogate.test").unwrap();
        let svid = issuer.issue(&params(), 1_000_000).unwrap();

        let decoded = envelope::decode(&svid.jws).unwrap();
        assert_eq!(decoded.header.kid, "kid-1");
        assert_eq!(decoded.claims.iss, "spiffe://ferrogate.test/cmis");
        assert_eq!(decoded.claims.sub, svid.spiffe_id);
        assert_eq!(decoded.claims.exp - decoded.claims.iat, 3600);
        assert_eq!(decoded.claims.nbf, decoded.claims.iat - 60);

        let sig =
            ferro_crypto::composite::CompositeSignature::from_concat_bytes(&decoded.signature)
                .unwrap();
        issuer
            .public_key()
            .verify(
                crate::SVID_SIGNING_CONTEXT,
                decoded.signing_input.as_bytes(),
                &sig,
            )
            .expect("signature verifies under issuer key");
    }

    #[test]
    fn ttl_is_clamped_to_one_hour() {
        let issuer = Issuer::generate("kid-1", "ferrogate.test").unwrap();
        let mut p = params();
        p.ttl_secs = 999_999;
        let svid = issuer.issue(&p, 0).unwrap();
        assert_eq!(svid.exp - svid.iat, 3600);
    }

    #[test]
    fn from_seed_is_deterministic_across_restarts() {
        let seed = [0x42u8; 32];
        // Two issuers built from the same seed (a "restart") must publish the
        // same JWKS key, so the CRL/allowlist/SVID signatures a consumer pinned
        // before the restart still verify after it.
        let a = Issuer::from_seed(&seed, "cmis-dev-1", "ferrogate.dev");
        let b = Issuer::from_seed(&seed, "cmis-dev-1", "ferrogate.dev");
        assert_eq!(
            a.public_key().to_concat_bytes(),
            b.public_key().to_concat_bytes()
        );

        // A signature minted by the "old" process verifies under the "new" one.
        let svid = a.issue(&params(), 1_000_000).unwrap();
        let decoded = envelope::decode(&svid.jws).unwrap();
        let sig =
            ferro_crypto::composite::CompositeSignature::from_concat_bytes(&decoded.signature)
                .unwrap();
        b.public_key()
            .verify(
                crate::SVID_SIGNING_CONTEXT,
                decoded.signing_input.as_bytes(),
                &sig,
            )
            .expect("signature from the same seed verifies after restart");
    }

    #[test]
    fn jwks_contains_issuer_key() {
        let issuer = Issuer::generate("kid-xyz", "ferrogate.test").unwrap();
        let set = issuer.jwks();
        let jwk = set.find("kid-xyz").expect("kid present");
        let pk = jwk.to_public_key().unwrap();
        assert_eq!(pk.to_concat_bytes(), issuer.public_key().to_concat_bytes());
    }
}
