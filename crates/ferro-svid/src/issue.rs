//! SVID issuance: turn verified attestation evidence into a signed compact JWS.

use std::sync::OnceLock;

use ferro_crypto::composite::{CompositeError, CompositePublicKey, CompositeSecretKey};

use crate::allowlist::{self, AllowEntry, AllowlistDoc, AllowlistError, SignedAllowlist};
use crate::claims::{AttestClaims, Cnf, SvidClaims};
use crate::crl::{CrlBody, CrlError, SignedCrl};
use crate::envelope::{self, EnvelopeError, JwsHeader};
use crate::jwks::{Jwk, JwkSet};
use crate::spiffe::{self, SpiffeError};
use crate::x509::{self, X509Error, X509Svid};

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
    /// The host's composite CSR key (`Csr::composite_pub`) in **concat wire
    /// form** — the key the X.509-SVID profile binds its leaf certificate to.
    ///
    /// Held as bytes rather than a parsed [`CompositePublicKey`] deliberately:
    /// FIPS-204 keeps the expanded ML-DSA matrix in memory, so a parsed key is
    /// tens of kilobytes, and these params are cloned per issuance and stored
    /// per host. Issuance parses it once, next to work that dwarfs the cost.
    ///
    /// `None` suppresses the X.509 profile for this issuance; the JWS SVID is
    /// still minted. That is the case for issued-SVID records written before the
    /// profile existed, and for a malformed CSR key.
    pub subject_pub: Option<Vec<u8>>,
}

/// A freshly issued SVID and its salient metadata.
///
/// One attestation yields **both** profiles: the compact JWS in [`Self::jws`]
/// and, when the CSR key was recorded, the X.509-SVID in [`Self::x509`]. They
/// carry the same SPIFFE ID, the same validity window, and the same issuer key;
/// a consumer picks whichever its stack can verify.
#[derive(Debug, Clone)]
pub struct IssuedSvid {
    /// The compact JWS.
    pub jws: String,
    /// The X.509-SVID leaf, when [`IssueParams::subject_pub`] was supplied.
    pub x509: Option<X509Svid>,
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
    /// X.509-SVID issuance failed.
    #[error("x509: {0}")]
    X509(#[from] X509Error),
}

/// The CMIS issuance authority: a composite signing key plus the trust-domain
/// identity it stamps into every SVID.
pub struct Issuer {
    secret: CompositeSecretKey,
    public: CompositePublicKey,
    kid: String,
    trust_domain: String,
    /// Memoised X.509-SVID trust bundle. Deterministic in the key and the trust
    /// domain, so it is built once and handed out by reference thereafter.
    x509_ca: OnceLock<Vec<u8>>,
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
            x509_ca: OnceLock::new(),
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

    /// The X.509-SVID trust bundle: this issuer's self-signed signing
    /// certificate, DER-encoded.
    ///
    /// Consumers install it as the trust anchor for the X.509 profile, exactly
    /// as they install the JWK set for the JWS profile. It is deterministic in
    /// `(issuer key, trust domain)` — see [`crate::x509::issue_ca`] — so every
    /// replica of a cluster serves identical bytes, and it is built at most once
    /// per process.
    pub fn x509_ca(&self) -> Result<&[u8], IssueError> {
        if let Some(der) = self.x509_ca.get() {
            return Ok(der);
        }
        let der = x509::issue_ca(&self.secret, &self.public, &self.trust_domain)?;
        Ok(self.x509_ca.get_or_init(|| der))
    }

    /// The JWK set this issuer publishes: its single composite key plus, in the
    /// `x-ferrogate-x509-bundle` member, the X.509-SVID trust anchor — so one
    /// fetch arms a verifier for both profiles.
    #[must_use]
    pub fn jwks(&self) -> JwkSet {
        let set = JwkSet::single(Jwk::from_public_key(self.kid.clone(), &self.public));
        match self.x509_ca() {
            Ok(der) => set.with_x509_bundle(der),
            // A trust bundle this issuer cannot build is a bug, not a runtime
            // condition. Publishing the keys without it keeps the JWS profile
            // serving rather than taking the whole JWKS down.
            Err(_) => set,
        }
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

    /// Mint an SVID in **both** profiles. `now` is the reference clock in Unix
    /// seconds.
    ///
    /// The X.509 leaf mirrors the JWS exactly: same subject SPIFFE ID, and a
    /// validity window of `[nbf, exp]` so the two credentials expire together.
    /// It is omitted when [`IssueParams::subject_pub`] is `None`, since there is
    /// then no subject key to bind a certificate to.
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

        let x509 = match &params.subject_pub {
            Some(bytes) => {
                let subject_pub = CompositePublicKey::from_concat_bytes(bytes)?;
                Some(x509::issue_leaf(
                    &self.secret,
                    &self.public,
                    &self.trust_domain,
                    &x509::LeafParams {
                        subject_pub: &subject_pub,
                        spiffe_id: &sub,
                        not_before: nbf,
                        not_after: exp,
                    },
                )?)
            }
            None => None,
        };

        Ok(IssuedSvid {
            jws,
            x509,
            spiffe_id: sub,
            iat,
            exp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_key() -> Vec<u8> {
        CompositeSecretKey::from_seed(&[0x5a; 32])
            .1
            .to_concat_bytes()
    }

    fn params() -> IssueParams {
        IssueParams {
            ek_cert_sha384: [0x11; 48],
            pcr_digest: [0x22; 48],
            policy_id: "rim-gen-5".to_string(),
            dpop_jkt: "abc123".to_string(),
            ttl_secs: 3600,
            tee_evidence_id: None,
            subject_pub: Some(host_key()),
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
    fn ttl_is_clamped_to_max() {
        let issuer = Issuer::generate("kid-1", "ferrogate.test").unwrap();
        let mut p = params();
        p.ttl_secs = crate::MAX_TTL_SECS + 999_999;
        let svid = issuer.issue(&p, 1_000_000).unwrap();
        assert_eq!(svid.exp - svid.iat, crate::MAX_TTL_SECS as i64);
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
    fn issue_mints_both_profiles_over_the_same_identity_and_window() {
        let issuer = Issuer::generate("kid-1", "ferrogate.test").unwrap();
        let svid = issuer.issue(&params(), 1_000_000).unwrap();

        let x509 = svid.x509.as_ref().expect("the X.509 profile is issued too");
        assert_eq!(x509.spiffe_id, svid.spiffe_id, "same SPIFFE ID");
        assert_eq!(
            x509.not_after, svid.exp,
            "the two credentials expire together"
        );
        assert_eq!(
            x509.not_before,
            svid.iat - crate::NBF_LOOKBACK_SECS,
            "the certificate honours the same clock-skew lookback as `nbf`"
        );

        // The JWS profile is untouched by the addition.
        let decoded = envelope::decode(&svid.jws).unwrap();
        assert_eq!(decoded.claims.sub, svid.spiffe_id);
        assert_eq!(decoded.header.typ, crate::SVID_TYP);
    }

    #[test]
    fn x509_profile_is_skipped_without_a_subject_key() {
        let issuer = Issuer::generate("kid-1", "ferrogate.test").unwrap();
        let mut p = params();
        p.subject_pub = None;
        let svid = issuer.issue(&p, 1_000_000).unwrap();
        assert!(svid.x509.is_none());
        // The JWS is still minted, so an old record still renews.
        assert!(envelope::decode(&svid.jws).is_ok());
    }

    #[test]
    fn x509_ca_is_memoised_and_stable() {
        let issuer = Issuer::generate("kid-1", "ferrogate.test").unwrap();
        let a = issuer.x509_ca().unwrap().to_vec();
        let b = issuer.x509_ca().unwrap().to_vec();
        assert_eq!(a, b);
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
