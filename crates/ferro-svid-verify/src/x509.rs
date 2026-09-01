//! Reference verifier for FerroGate's **X.509-SVID** profile (the certificate
//! profile issued beside the JWS one by `ferro_svid::x509`).
//!
//! Like the rest of this crate the ASN.1 is re-declared locally rather than
//! imported from the issuer, so this file doubles as a copy-pasteable reference
//! for a third-party verifier.
//!
//! ## What "verified" means here
//!
//! The whole point of the profile is that a *stock* TLS stack can already
//! validate the chain — it checks the native Ed25519 signature and ignores the
//! rest. This verifier is for consumers who want the post-quantum half too, so
//! it is strictly stronger and fail-closed. In order it checks:
//!
//! 1. the trust bundle is a `CA:TRUE`, `keyCertSign` certificate, and both
//!    halves of its own self-signature hold;
//! 2. the leaf's `issuer` equals the bundle's `subject`, byte for byte;
//! 3. the leaf's native Ed25519 signature verifies under the bundle key;
//! 4. the leaf's ML-DSA-65 alternative signature verifies under the same key,
//!    over the body re-encoded without the `altSignatureValue` extension;
//! 5. the leaf is a `CA:FALSE`, `digitalSignature` end entity;
//! 6. it carries exactly one URI SAN, a SPIFFE ID inside the bundle's trust
//!    domain;
//! 7. `notBefore` / `notAfter` bracket `now`, within the supplied leeway.
//!
//! A missing or unparseable alternative signature is a verification *failure*,
//! not a downgrade: a caller reaching for this module has asked for both halves.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString, Uint, UtcTime};
use der::{Any, Choice, Decode, Encode, Sequence, Tag, TagNumber, Tagged};
use ferro_crypto::composite::{CompositePublicKey, ED25519_PK_LEN, ED25519_SIG_LEN};
use sha2::{Digest, Sha384};

use crate::{JwkSet, VerifyError};

/// FIPS-204 context string the alternative signature is computed under.
pub const ALT_SIGNATURE_CONTEXT: &[u8] = b"ferrogate-x509-svid-v1";

/// `id-Ed25519` (RFC 8410).
pub const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// `id-ml-dsa-65` (NIST CSOR).
pub const OID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// `id-ce-keyUsage`.
pub const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `id-ce-subjectAltName`.
pub const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
/// `id-ce-basicConstraints`.
pub const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// `id-ce-subjectAltPublicKeyInfo`, ITU-T X.509 (2019) §9.8.
pub const OID_SUBJECT_ALT_PUBLIC_KEY_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.72");
/// `id-ce-altSignatureAlgorithm`, ITU-T X.509 (2019) §9.8.
pub const OID_ALT_SIGNATURE_ALGORITHM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.73");
/// `id-ce-altSignatureValue`, ITU-T X.509 (2019) §9.8.
pub const OID_ALT_SIGNATURE_VALUE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.74");

/// `keyUsage` bit 0 — `digitalSignature`.
const KU_DIGITAL_SIGNATURE: u8 = 0b1000_0000;
/// `keyUsage` bit 5 — `keyCertSign`.
const KU_KEY_CERT_SIGN: u8 = 0b0000_0100;

fn bool_false() -> bool {
    false
}

// ---------------------------------------------------------------------------
// ASN.1 (RFC 5280 subset)
// ---------------------------------------------------------------------------

/// `AlgorithmIdentifier`, `parameters` absent.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID.
    pub algorithm: ObjectIdentifier,
}

/// `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct SubjectPublicKeyInfo {
    /// Key algorithm.
    pub algorithm: AlgorithmIdentifier,
    /// The key.
    pub subject_public_key: BitString,
}

/// `BasicConstraints`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
struct BasicConstraints {
    #[asn1(default = "bool_false")]
    ca: bool,
}

/// The `Time` CHOICE (RFC 5280 §4.1.2.5).
#[derive(Debug, Clone, PartialEq, Eq, Choice)]
pub enum Asn1Time {
    /// Through 2049.
    #[asn1(type = "UTCTime")]
    Utc(UtcTime),
    /// From 2050.
    #[asn1(type = "GeneralizedTime")]
    General(GeneralizedTime),
}

impl Asn1Time {
    /// The instant as Unix seconds.
    #[must_use]
    pub fn to_unix(&self) -> i64 {
        let secs = match self {
            Self::Utc(t) => t.to_unix_duration().as_secs(),
            Self::General(t) => t.to_unix_duration().as_secs(),
        };
        i64::try_from(secs).unwrap_or(i64::MAX)
    }
}

/// `Validity`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Validity {
    /// Start of the window.
    pub not_before: Asn1Time,
    /// End of the window.
    pub not_after: Asn1Time,
}

/// One `Extension`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Extension {
    /// Extension OID.
    pub extn_id: ObjectIdentifier,
    /// Criticality; DER omits it when false.
    #[asn1(default = "bool_false")]
    pub critical: bool,
    /// DER extension value.
    pub extn_value: OctetString,
}

/// `TBSCertificate`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct TbsCertificate {
    /// Version, `[0] EXPLICIT`.
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub version: u8,
    /// Serial number.
    pub serial_number: Uint,
    /// Signature algorithm, repeated from the enclosing certificate.
    pub signature: AlgorithmIdentifier,
    /// Issuer DN, kept opaque for byte-exact comparison.
    pub issuer: Vec<Any>,
    /// Validity window.
    pub validity: Validity,
    /// Subject DN.
    pub subject: Vec<Any>,
    /// Subject public key.
    pub subject_public_key_info: SubjectPublicKeyInfo,
    /// Extensions, `[3] EXPLICIT`.
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<Vec<Extension>>,
}

/// A `Certificate`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Certificate {
    /// The signed body, opaque so the signed bytes are recoverable exactly.
    pub tbs_certificate: Any,
    /// Native signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier,
    /// Native signature value.
    pub signature: BitString,
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// A verified X.509-SVID.
#[derive(Debug, Clone)]
pub struct VerifiedX509 {
    /// The SPIFFE ID from the leaf's URI SAN.
    pub spiffe_id: String,
    /// The trust domain the issuing bundle claims.
    pub trust_domain: String,
    /// `notBefore`, Unix seconds.
    pub not_before: i64,
    /// `notAfter`, Unix seconds.
    pub not_after: i64,
    /// The subject's composite public key, reassembled from the standard SPKI
    /// (Ed25519) and `subjectAltPublicKeyInfo` (ML-DSA-65). This is the host's
    /// CSR key, so it is also the key that signs its child tokens.
    pub subject_pub: CompositePublicKey,
    /// Lowercase-hex `SHA-384` of the leaf DER — the certificate's revocation
    /// key, mirroring `cert_sha` in the JWS profile.
    pub cert_sha: String,
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn malformed(what: &str, e: impl core::fmt::Display) -> VerifyError {
    VerifyError::Malformed(format!("x509 {what}: {e}"))
}

fn header(what: impl Into<String>) -> VerifyError {
    VerifyError::UnexpectedHeader(what.into())
}

/// A parsed certificate: the decoded body plus the exact bytes it was signed
/// over.
struct Parsed {
    tbs: TbsCertificate,
    tbs_der: Vec<u8>,
    native_sig: [u8; ED25519_SIG_LEN],
}

fn parse(der_bytes: &[u8], what: &str) -> Result<Parsed, VerifyError> {
    let cert = Certificate::from_der(der_bytes).map_err(|e| malformed(what, e))?;
    if cert.signature_algorithm.algorithm != OID_ED25519 {
        return Err(header(format!(
            "{what} signatureAlgorithm={}",
            cert.signature_algorithm.algorithm
        )));
    }
    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| malformed(what, e))?;
    let tbs = TbsCertificate::from_der(&tbs_der).map_err(|e| malformed(what, e))?;
    if tbs.signature.algorithm != cert.signature_algorithm.algorithm {
        return Err(header(format!(
            "{what} inner/outer signature algorithm differ"
        )));
    }
    let native_sig: [u8; ED25519_SIG_LEN] = cert
        .signature
        .as_bytes()
        .ok_or_else(|| malformed(what, "signature is not octet-aligned"))?
        .try_into()
        .map_err(|_| malformed(what, "signature is not 64 bytes"))?;
    Ok(Parsed {
        tbs,
        tbs_der,
        native_sig,
    })
}

fn find_ext(tbs: &TbsCertificate, oid: ObjectIdentifier) -> Option<&Extension> {
    tbs.extensions.as_ref()?.iter().find(|e| e.extn_id == oid)
}

fn require_ext<'a>(
    tbs: &'a TbsCertificate,
    oid: ObjectIdentifier,
    what: &str,
) -> Result<&'a Extension, VerifyError> {
    find_ext(tbs, oid).ok_or_else(|| header(format!("{what} is missing extension {oid}")))
}

fn is_ca(tbs: &TbsCertificate) -> Result<bool, VerifyError> {
    match find_ext(tbs, OID_BASIC_CONSTRAINTS) {
        // RFC 5280: an absent basicConstraints means "not a CA".
        None => Ok(false),
        Some(e) => Ok(BasicConstraints::from_der(e.extn_value.as_bytes())
            .map_err(|err| malformed("basicConstraints", err))?
            .ca),
    }
}

fn key_usage_has(tbs: &TbsCertificate, bit: u8, what: &str) -> Result<(), VerifyError> {
    let ext = require_ext(tbs, OID_KEY_USAGE, what)?;
    let bits =
        BitString::from_der(ext.extn_value.as_bytes()).map_err(|e| malformed("keyUsage", e))?;
    let first = bits.raw_bytes().first().copied().unwrap_or(0);
    if first & bit == 0 {
        return Err(header(format!(
            "{what} keyUsage lacks bit mask {bit:#010b}"
        )));
    }
    Ok(())
}

/// The single `uniformResourceIdentifier` in a `subjectAltName`.
///
/// More than one URI SAN is a hard failure: the SPIFFE X509-SVID specification
/// allows exactly one, and accepting the first of several would let an issuer
/// smuggle in a second identity.
fn sole_uri_san(tbs: &TbsCertificate, what: &str) -> Result<String, VerifyError> {
    let ext = require_ext(tbs, OID_SUBJECT_ALT_NAME, what)?;
    let names = Vec::<Any>::from_der(ext.extn_value.as_bytes())
        .map_err(|e| malformed("subjectAltName", e))?;
    let uri_tag = Tag::ContextSpecific {
        constructed: false,
        number: TagNumber(6),
    };
    let mut found: Option<String> = None;
    for name in &names {
        if name.tag() != uri_tag {
            continue;
        }
        if found.is_some() {
            return Err(header(format!("{what} carries more than one URI SAN")));
        }
        let bytes = name.value();
        found = Some(
            core::str::from_utf8(bytes)
                .map_err(|e| malformed("URI SAN", e))?
                .to_string(),
        );
    }
    found.ok_or_else(|| header(format!("{what} has no URI SAN")))
}

/// Reassemble the composite public key of a certificate's subject from its
/// standard SPKI and its `subjectAltPublicKeyInfo`.
fn subject_composite_key(
    tbs: &TbsCertificate,
    what: &str,
) -> Result<CompositePublicKey, VerifyError> {
    if tbs.subject_public_key_info.algorithm.algorithm != OID_ED25519 {
        return Err(header(format!(
            "{what} subject key algorithm={}",
            tbs.subject_public_key_info.algorithm.algorithm
        )));
    }
    let classical = tbs
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| malformed(what, "subject key is not octet-aligned"))?;
    if classical.len() != ED25519_PK_LEN {
        return Err(malformed(what, "subject key is not 32 bytes"));
    }

    let ext = require_ext(tbs, OID_SUBJECT_ALT_PUBLIC_KEY_INFO, what)?;
    let alt = SubjectPublicKeyInfo::from_der(ext.extn_value.as_bytes())
        .map_err(|e| malformed("subjectAltPublicKeyInfo", e))?;
    if alt.algorithm.algorithm != OID_ML_DSA_65 {
        return Err(header(format!(
            "{what} subjectAltPublicKeyInfo algorithm={}",
            alt.algorithm.algorithm
        )));
    }
    let pqc = alt
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| malformed(what, "alternative subject key is not octet-aligned"))?;

    let mut concat = Vec::with_capacity(classical.len() + pqc.len());
    concat.extend_from_slice(classical);
    concat.extend_from_slice(pqc);
    CompositePublicKey::from_concat_bytes(&concat).map_err(|e| malformed(what, e))
}

/// Verify both halves of the signature on `cert` under `issuer_pub`.
///
/// The alternative signature covers the body **without** `altSignatureValue`
/// (ITU-T X.509 (2019) §9.8), which this reproduces by dropping that extension
/// and re-encoding. DER is canonical, so the result is the issuer's original
/// pre-signature encoding byte for byte.
fn verify_hybrid_signature(
    cert: &Parsed,
    issuer_pub: &CompositePublicKey,
    what: &str,
) -> Result<(), VerifyError> {
    issuer_pub
        .verify_interop_ed25519(&cert.tbs_der, &cert.native_sig)
        .map_err(|_| VerifyError::BadSignature)?;

    // The alternative-signature machinery must be complete before it is used;
    // a certificate that simply omits it does not verify here.
    let alg_ext = require_ext(&cert.tbs, OID_ALT_SIGNATURE_ALGORITHM, what)?;
    let alg = AlgorithmIdentifier::from_der(alg_ext.extn_value.as_bytes())
        .map_err(|e| malformed("altSignatureAlgorithm", e))?;
    if alg.algorithm != OID_ML_DSA_65 {
        return Err(header(format!(
            "{what} altSignatureAlgorithm={}",
            alg.algorithm
        )));
    }

    let value_ext = require_ext(&cert.tbs, OID_ALT_SIGNATURE_VALUE, what)?;
    let alt_sig = BitString::from_der(value_ext.extn_value.as_bytes())
        .map_err(|e| malformed("altSignatureValue", e))?;
    let alt_sig_bytes = alt_sig
        .as_bytes()
        .ok_or_else(|| malformed("altSignatureValue", "not octet-aligned"))?;

    let mut pre = cert.tbs.clone();
    let exts = pre
        .extensions
        .as_mut()
        .ok_or_else(|| malformed(what, "no extensions"))?;
    let idx = exts
        .iter()
        .position(|e| e.extn_id == OID_ALT_SIGNATURE_VALUE)
        .ok_or_else(|| malformed(what, "altSignatureValue vanished"))?;
    exts.remove(idx);
    let pre_der = pre.to_der().map_err(|e| malformed(what, e))?;

    issuer_pub
        .verify_interop_mldsa65(ALT_SIGNATURE_CONTEXT, &pre_der, alt_sig_bytes)
        .map_err(|_| VerifyError::BadSignature)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// A trust bundle that has checked out: it is a CA, it signs, and it attested to
/// itself under both algorithms.
struct Anchor {
    trust_domain: String,
    key: CompositePublicKey,
    /// The bundle's `subject`, which a leaf's `issuer` must equal.
    subject: Vec<Any>,
}

/// Validate a trust bundle. Parsing and the self-signature check happen exactly
/// once here, so a caller verifying many leaves under one anchor does not pay
/// for them repeatedly.
fn parse_anchor(bundle_der: &[u8]) -> Result<Anchor, VerifyError> {
    let ca = parse(bundle_der, "trust bundle")?;
    if !is_ca(&ca.tbs)? {
        return Err(header("trust bundle is not a CA certificate"));
    }
    key_usage_has(&ca.tbs, KU_KEY_CERT_SIGN, "trust bundle")?;
    let key = subject_composite_key(&ca.tbs, "trust bundle")?;
    // Self-signed: the bundle must attest to itself under both algorithms.
    verify_hybrid_signature(&ca, &key, "trust bundle")?;

    let uri = sole_uri_san(&ca.tbs, "trust bundle")?;
    let trust_domain = uri
        .strip_prefix("spiffe://")
        .filter(|td| !td.is_empty() && !td.contains('/'))
        .ok_or_else(|| header(format!("trust bundle SAN {uri} is not a trust domain ID")))?
        .to_string();

    Ok(Anchor {
        trust_domain,
        key,
        subject: ca.tbs.subject,
    })
}

/// The trust domain a bundle certificate speaks for, plus its composite key.
///
/// Exposed so a consumer can inspect an anchor before pinning it. Fails closed
/// on a bundle that is not a self-consistent FerroGate signing certificate.
pub fn parse_trust_bundle(bundle_der: &[u8]) -> Result<(String, CompositePublicKey), VerifyError> {
    let anchor = parse_anchor(bundle_der)?;
    Ok((anchor.trust_domain, anchor.key))
}

/// Verify an X.509-SVID leaf against a trust bundle at reference time `now`
/// (Unix seconds), allowing `leeway_secs` of clock skew.
pub fn verify_x509(
    leaf_der: &[u8],
    bundle_der: &[u8],
    now: i64,
    leeway_secs: i64,
) -> Result<VerifiedX509, VerifyError> {
    verify_under_anchor(&parse_anchor(bundle_der)?, leaf_der, now, leeway_secs)
}

fn verify_under_anchor(
    anchor: &Anchor,
    leaf_der: &[u8],
    now: i64,
    leeway_secs: i64,
) -> Result<VerifiedX509, VerifyError> {
    let leaf = parse(leaf_der, "leaf")?;

    if leaf.tbs.issuer != anchor.subject {
        return Err(header(
            "leaf issuer does not match the trust bundle subject",
        ));
    }
    verify_hybrid_signature(&leaf, &anchor.key, "leaf")?;

    // Signatures hold; the body can now be trusted enough to interpret.
    if is_ca(&leaf.tbs)? {
        return Err(header("leaf is a CA certificate"));
    }
    key_usage_has(&leaf.tbs, KU_DIGITAL_SIGNATURE, "leaf")?;

    let spiffe_id = sole_uri_san(&leaf.tbs, "leaf")?;
    let trust_domain = &anchor.trust_domain;
    if !spiffe_id.starts_with(&format!("spiffe://{trust_domain}/")) {
        return Err(header(format!(
            "leaf SPIFFE ID {spiffe_id} is outside trust domain {trust_domain}"
        )));
    }
    let subject_pub = subject_composite_key(&leaf.tbs, "leaf")?;

    let not_before = leaf.tbs.validity.not_before.to_unix();
    let not_after = leaf.tbs.validity.not_after.to_unix();
    if now + leeway_secs < not_before {
        return Err(VerifyError::NotYetValid);
    }
    if now - leeway_secs >= not_after {
        return Err(VerifyError::Expired);
    }

    Ok(VerifiedX509 {
        spiffe_id,
        trust_domain: anchor.trust_domain.clone(),
        not_before,
        not_after,
        subject_pub,
        cert_sha: hex::encode(Sha384::digest(leaf_der)),
    })
}

/// Verify an X.509-SVID against the anchors published in a JWK set, and check it
/// against the CRL carried there (feature F11).
///
/// The bundle comes from the set's `x-ferrogate-x509-bundle` member, and its key
/// must equal one of the set's published composite keys — so the certificate
/// profile and the JWS profile provably share a root, and rotating the root
/// rotates both. Revocation is fail-closed exactly as in
/// [`crate::verify_unrevoked`]: a decision requires a fresh, signature-valid
/// CRL. A certificate is revoked by its own `cert_sha` (lowercase-hex
/// `SHA-384` of the leaf DER) or by its host SPIFFE ID.
pub fn verify_x509_unrevoked(
    leaf_der: &[u8],
    jwks: &JwkSet,
    now: i64,
    leeway_secs: i64,
) -> Result<VerifiedX509, VerifyError> {
    let bundle_der = jwks
        .x509_bundle_der()?
        .ok_or_else(|| header("JWK set publishes no X.509 trust bundle"))?;
    let anchor = parse_anchor(&bundle_der)?;
    let verified = verify_under_anchor(&anchor, leaf_der, now, leeway_secs)?;

    let anchor_key = anchor.key.to_concat_bytes();
    let published = jwks.keys.iter().any(|k| {
        k.to_public_key()
            .is_ok_and(|pk| pk.to_concat_bytes() == anchor_key)
    });
    if !published {
        return Err(header(
            "the X.509 trust bundle key is not among the published JWKS keys",
        ));
    }

    let signed = jwks.crl.as_ref().ok_or(VerifyError::CrlStale)?;
    let body = signed.verify(jwks)?;
    if !body.is_fresh(now, leeway_secs) {
        return Err(VerifyError::CrlStale);
    }
    if body.revokes_svid(&verified.cert_sha) || body.revokes_host(&verified.spiffe_id) {
        return Err(VerifyError::Revoked);
    }
    Ok(verified)
}

impl JwkSet {
    /// The DER trust bundle published in the `x-ferrogate-x509-bundle` member,
    /// if any.
    pub fn x509_bundle_der(&self) -> Result<Option<Vec<u8>>, VerifyError> {
        match &self.x509_bundle {
            None => Ok(None),
            Some(b64) => URL_SAFE_NO_PAD
                .decode(b64.as_bytes())
                .map(Some)
                .map_err(|e| malformed("trust bundle base64url", e)),
        }
    }
}
