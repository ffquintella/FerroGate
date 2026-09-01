//! The **X.509-SVID** profile: a SPIFFE X509-SVID leaf certificate issued
//! beside the JWS SVID from the same attestation and the same issuer key.
//!
//! ## Why a second profile
//!
//! The JWS profile ([`crate::envelope`]) is FerroGate-native: its signature is
//! a composite Ed25519 + ML-DSA-65 value over a FerroGate transcript hash, so
//! only [`ferro_svid_verify`](https://docs.rs/ferro-svid-verify) can check it.
//! Workloads that want mTLS need a credential an off-the-shelf TLS stack
//! understands. This profile issues one, without giving up the PQ half.
//!
//! ## Hybrid signature
//!
//! Each certificate carries **two** signatures over the same body:
//!
//! - the native `signatureAlgorithm` / `signatureValue` is a standard RFC 8410
//!   Ed25519 signature over the DER `TBSCertificate`, so rustls, OpenSSL, or
//!   Envoy validate the chain unaided;
//! - the ML-DSA-65 half travels in the ITU-T X.509 (2019) §9.8 *alternative
//!   signature* extensions — [`OID_SUBJECT_ALT_PUBLIC_KEY_INFO`],
//!   [`OID_ALT_SIGNATURE_ALGORITHM`], and [`OID_ALT_SIGNATURE_VALUE`] — all
//!   non-critical, so a stack that does not know them ignores them and a
//!   FerroGate-aware verifier requires them.
//!
//! Per §9.8 the alternative signature covers the `TBSCertificate` **with the
//! `altSignatureValue` extension absent** (the other two present); the native
//! signature then covers the complete body. A verifier reproduces the first
//! encoding by dropping that one extension and re-encoding — DER is canonical,
//! so the bytes match exactly.
//!
//! A consumer that checks only the native signature gets classical assurance;
//! one that checks both gets the same AND-combined assurance as the JWS
//! profile. Neither certificate is verifiable *without* the classical half, so
//! there is no downgrade to the PQ-only case.
//!
//! ## Shape
//!
//! The leaf follows the SPIFFE X509-SVID specification: the SPIFFE ID is the
//! single URI SAN, `basicConstraints` is `CA:FALSE`, `keyUsage` is
//! `digitalSignature`, and the subject DN is informational only. The subject
//! public key is the Ed25519 half of the host's composite CSR key (the
//! ML-DSA-65 half is in `subjectAltPublicKeyInfo`), so the same key that mints
//! child tokens terminates mTLS.
//!
//! The signing certificate returned by [`issue_ca`] is the trust bundle. It is
//! **deterministic**: nothing but the issuer key and the trust domain feeds
//! into it — its validity window is the fixed [`CA_NOT_BEFORE`] …
//! [`CA_NOT_AFTER`] anchor — so every CMIS replica in a cluster publishes
//! byte-identical bundle DER.

use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString, Uint, UtcTime};
use der::{Any, Choice, Decode, Encode, Sequence, Tag, TagNumber};
use ferro_crypto::composite::{
    CompositeError, CompositePublicKey, CompositeSecretKey, ED25519_PK_LEN,
};
use sha2::{Digest, Sha256, Sha384};

// ---------------------------------------------------------------------------
// Profile constants
// ---------------------------------------------------------------------------

/// FIPS-204 context string the alternative (ML-DSA-65) signature is computed
/// under. It is a constant of the profile rather than a wire field: a verifier
/// that used a different context would simply fail.
pub const ALT_SIGNATURE_CONTEXT: &[u8] = b"ferrogate-x509-svid-v1";

/// `id-Ed25519` (RFC 8410) — the native signature and subject-key algorithm.
/// `parameters` is absent, as RFC 8410 §3 requires.
pub const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// `id-ml-dsa-65` (NIST CSOR) — the alternative signature and alternative
/// subject-key algorithm.
pub const OID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// `id-at-commonName`.
pub const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// `id-at-organizationName`.
pub const OID_ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

/// `id-ce-subjectKeyIdentifier`.
pub const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
/// `id-ce-keyUsage`.
pub const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `id-ce-subjectAltName`.
pub const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
/// `id-ce-basicConstraints`.
pub const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// `id-ce-authorityKeyIdentifier`.
pub const OID_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");
/// `id-ce-extKeyUsage`.
pub const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// `id-ce-subjectAltPublicKeyInfo`, ITU-T X.509 (2019) §9.8.
pub const OID_SUBJECT_ALT_PUBLIC_KEY_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.72");
/// `id-ce-altSignatureAlgorithm`, ITU-T X.509 (2019) §9.8.
pub const OID_ALT_SIGNATURE_ALGORITHM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.73");
/// `id-ce-altSignatureValue`, ITU-T X.509 (2019) §9.8.
pub const OID_ALT_SIGNATURE_VALUE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.74");

/// `id-kp-serverAuth`.
pub const OID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
/// `id-kp-clientAuth`.
pub const OID_KP_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// Organization stamped into every FerroGate certificate DN.
pub const DN_ORGANIZATION: &str = "FerroGate";

/// `notBefore` on the signing certificate: 2020-01-01T00:00:00Z.
///
/// A fixed anchor, not a clock read, so the bundle is reproducible on every
/// replica and across restarts — the certificate's identity is its key, not its
/// window.
pub const CA_NOT_BEFORE: i64 = 1_577_836_800;

/// `notAfter` on the signing certificate: 2049-12-31T23:59:59Z — the last
/// instant RFC 5280 still encodes as `UTCTime`.
pub const CA_NOT_AFTER: i64 = 2_524_607_999;

/// First Unix second RFC 5280 requires to be encoded as `GeneralizedTime`
/// (2050-01-01T00:00:00Z).
const GENERALIZED_TIME_FROM: i64 = 2_524_608_000;

/// X.509 version 3, zero-indexed as the ASN.1 `Version` enumeration is.
const X509_V3: u8 = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for X.509-SVID issuance.
#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    /// DER encoding or decoding failed.
    #[error("der: {0}")]
    Der(String),
    /// A signing operation failed.
    #[error("composite: {0}")]
    Composite(#[from] CompositeError),
    /// The requested validity window was empty, inverted, or outside the range
    /// ASN.1 can represent.
    #[error("invalid validity window: not_before={not_before}, not_after={not_after}")]
    Validity {
        /// Requested `notBefore`, Unix seconds.
        not_before: i64,
        /// Requested `notAfter`, Unix seconds.
        not_after: i64,
    },
    /// An instant fell outside the range ASN.1 time can represent — in
    /// practice, before the Unix epoch.
    #[error("timestamp {0} is not representable as an ASN.1 Time")]
    Timestamp(i64),
    /// A SPIFFE ID was empty or not a `spiffe://` URI.
    #[error("invalid SPIFFE ID for a URI SAN: {0}")]
    SpiffeId(String),
}

impl From<der::Error> for X509Error {
    fn from(e: der::Error) -> Self {
        Self::Der(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// ASN.1 (RFC 5280 subset)
// ---------------------------------------------------------------------------

/// Supplies the ASN.1 `DEFAULT FALSE` used by `critical` and `cA`.
fn bool_false() -> bool {
    false
}

/// `AlgorithmIdentifier` with `parameters` absent — the only shape this profile
/// emits, since both Ed25519 (RFC 8410 §3) and ML-DSA-65 forbid parameters.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AlgorithmIdentifier {
    /// The algorithm OID.
    pub algorithm: ObjectIdentifier,
}

/// `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct SubjectPublicKeyInfo {
    /// Key algorithm.
    pub algorithm: AlgorithmIdentifier,
    /// The key itself.
    pub subject_public_key: BitString,
}

/// `AttributeTypeAndValue` — one component of a distinguished name.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
struct AttributeTypeAndValue {
    attr_type: ObjectIdentifier,
    attr_value: Any,
}

/// `BasicConstraints`. `pathLenConstraint` is never emitted.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
struct BasicConstraints {
    #[asn1(default = "bool_false")]
    ca: bool,
}

/// `AuthorityKeyIdentifier`, `keyIdentifier` form only.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
struct AuthorityKeyIdentifier {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    key_identifier: Option<OctetString>,
}

/// The `Time` CHOICE. RFC 5280 §4.1.2.5 pins the encoding to the year: through
/// 2049 `UTCTime`, from 2050 `GeneralizedTime`.
#[derive(Debug, Clone, PartialEq, Eq, Choice)]
pub enum Asn1Time {
    /// Two-digit-year form, mandatory through 2049.
    #[asn1(type = "UTCTime")]
    Utc(UtcTime),
    /// Four-digit-year form, mandatory from 2050.
    #[asn1(type = "GeneralizedTime")]
    General(GeneralizedTime),
}

impl Asn1Time {
    /// Encode a Unix-seconds instant in the form RFC 5280 mandates for its year.
    pub fn from_unix(secs: i64) -> Result<Self, X509Error> {
        let d = u64::try_from(secs)
            .map(core::time::Duration::from_secs)
            .map_err(|_| X509Error::Timestamp(secs))?;
        if secs < GENERALIZED_TIME_FROM {
            Ok(Self::Utc(UtcTime::from_unix_duration(d)?))
        } else {
            Ok(Self::General(GeneralizedTime::from_unix_duration(d)?))
        }
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

/// One X.509 `Extension`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Extension {
    /// Extension OID.
    pub extn_id: ObjectIdentifier,
    /// Criticality. DER omits this when false, so a re-encode is canonical.
    #[asn1(default = "bool_false")]
    pub critical: bool,
    /// The DER-encoded extension value, wrapped in an OCTET STRING.
    pub extn_value: OctetString,
}

/// `TBSCertificate`.
///
/// `issuer` and `subject` are `RDNSequence`s modelled as `SEQUENCE OF` opaque
/// `SET`s, which is enough to emit and to compare them byte-for-byte without a
/// full X.500 name implementation.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct TbsCertificate {
    /// Version, `[0] EXPLICIT`; always [`X509_V3`].
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub version: u8,
    /// Serial number; positive, 16 bytes.
    pub serial_number: Uint,
    /// Must equal the enclosing certificate's `signatureAlgorithm`.
    pub signature: AlgorithmIdentifier,
    /// Issuer DN.
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

/// A complete `Certificate`.
///
/// `tbs_certificate` is held as opaque [`Any`] so the bytes that were signed
/// and the bytes that are emitted are the same bytes by construction.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Certificate {
    /// The signed body.
    pub tbs_certificate: Any,
    /// Native signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier,
    /// Native signature value.
    pub signature: BitString,
}

// ---------------------------------------------------------------------------
// Issued material
// ---------------------------------------------------------------------------

/// An issued X.509-SVID leaf certificate.
///
/// The trust bundle it chains to is not repeated here: it is deterministic in
/// the issuer key, so [`issue_ca`] reproduces it on demand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Svid {
    /// The leaf certificate, DER.
    pub leaf_der: Vec<u8>,
    /// Subject SPIFFE ID, as carried in the URI SAN.
    pub spiffe_id: String,
    /// `notBefore`, Unix seconds.
    pub not_before: i64,
    /// `notAfter`, Unix seconds.
    pub not_after: i64,
}

/// Inputs for one leaf certificate.
#[derive(Debug, Clone, Copy)]
pub struct LeafParams<'a> {
    /// The host's composite CSR key. Its Ed25519 half becomes the subject
    /// public key; its ML-DSA-65 half goes in `subjectAltPublicKeyInfo`.
    pub subject_pub: &'a CompositePublicKey,
    /// The subject SPIFFE ID — the certificate's only URI SAN.
    pub spiffe_id: &'a str,
    /// `notBefore`, Unix seconds.
    pub not_before: i64,
    /// `notAfter`, Unix seconds.
    pub not_after: i64,
}

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

/// Build an `RDNSequence` from `(type, value)` pairs, one attribute per RDN.
fn rdn_sequence(attrs: &[(ObjectIdentifier, &str)]) -> Result<Vec<Any>, X509Error> {
    let mut out = Vec::with_capacity(attrs.len());
    for (attr_type, value) in attrs {
        let atv = AttributeTypeAndValue {
            attr_type: *attr_type,
            attr_value: Any::new(Tag::Utf8String, value.as_bytes())?,
        };
        // One attribute per RDN, so the `SET OF` ordering rule is trivially met.
        out.push(Any::new(Tag::Set, atv.to_der()?)?);
    }
    Ok(out)
}

/// The DN of the FerroGate issuer for a trust domain. The leaf's `issuer` and
/// the signing certificate's `subject` are both built here so they are equal
/// byte-for-byte, as RFC 5280 chain building requires.
fn issuer_dn(trust_domain: &str) -> Result<Vec<Any>, X509Error> {
    rdn_sequence(&[
        (OID_ORGANIZATION_NAME, DN_ORGANIZATION),
        (OID_COMMON_NAME, trust_domain),
    ])
}

/// The leaf's informational DN. SPIFFE treats the URI SAN as the only identity,
/// so this carries just the host UUID — short enough to stay inside the X.520
/// 64-character upper bound that the full SPIFFE ID would breach.
fn subject_dn(spiffe_id: &str) -> Result<Vec<Any>, X509Error> {
    let cn = spiffe_id.rsplit('/').next().unwrap_or(spiffe_id);
    rdn_sequence(&[
        (OID_ORGANIZATION_NAME, DN_ORGANIZATION),
        (OID_COMMON_NAME, cn),
    ])
}

/// `SubjectPublicKeyInfo` for the Ed25519 half of a composite key.
fn ed25519_spki(pk: &CompositePublicKey) -> Result<SubjectPublicKeyInfo, X509Error> {
    Ok(SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: OID_ED25519,
        },
        subject_public_key: BitString::new(0, pk.ed25519().as_bytes().to_vec())?,
    })
}

/// The ML-DSA-65 half of a composite public key, taken from the concat wire
/// form so this crate needs no direct FIPS-204 dependency.
fn mldsa65_pub_bytes(pk: &CompositePublicKey) -> Vec<u8> {
    pk.to_concat_bytes()[ED25519_PK_LEN..].to_vec()
}

/// `SubjectPublicKeyInfo` for the ML-DSA-65 half, carried in
/// `subjectAltPublicKeyInfo`.
fn mldsa65_spki(pk: &CompositePublicKey) -> Result<SubjectPublicKeyInfo, X509Error> {
    Ok(SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: OID_ML_DSA_65,
        },
        subject_public_key: BitString::new(0, mldsa65_pub_bytes(pk))?,
    })
}

/// The key identifier for a public key: the leftmost 160 bits of
/// `SHA-256(key bytes)` — RFC 7093 §2 method 1, avoiding SHA-1.
#[must_use]
pub fn key_identifier(pk: &CompositePublicKey) -> [u8; 20] {
    let digest = Sha256::digest(pk.ed25519().as_bytes());
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// Derive a deterministic 16-byte positive serial number.
///
/// Determinism keeps re-issuance auditable — the same host at the same `iat`
/// always gets the same serial — and needs no RNG in the issuance path. The top
/// bit is cleared so the `INTEGER` is positive, and bit 6 is set so the leading
/// octet is never zero.
fn serial_number(domain: &[u8], parts: &[&[u8]]) -> Result<Uint, X509Error> {
    let mut h = Sha384::new();
    h.update(domain);
    for p in parts {
        h.update(u64::try_from(p.len()).unwrap_or(u64::MAX).to_be_bytes());
        h.update(p);
    }
    let digest = h.finalize();
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&digest[..16]);
    serial[0] = (serial[0] & 0x3f) | 0x40;
    Ok(Uint::new(&serial)?)
}

fn extension(
    extn_id: ObjectIdentifier,
    critical: bool,
    value_der: Vec<u8>,
) -> Result<Extension, X509Error> {
    Ok(Extension {
        extn_id,
        critical,
        extn_value: OctetString::new(value_der)?,
    })
}

fn basic_constraints_ext(ca: bool) -> Result<Extension, X509Error> {
    extension(
        OID_BASIC_CONSTRAINTS,
        true,
        BasicConstraints { ca }.to_der()?,
    )
}

/// `keyUsage` from an already-packed bit string. Bit 0 is the most significant
/// bit of the first octet (RFC 5280 §4.2.1.3).
fn key_usage_ext(bits: u8, unused: u8) -> Result<Extension, X509Error> {
    extension(
        OID_KEY_USAGE,
        true,
        BitString::new(unused, vec![bits])?.to_der()?,
    )
}

fn ext_key_usage_ext() -> Result<Extension, X509Error> {
    let usages = vec![OID_KP_SERVER_AUTH, OID_KP_CLIENT_AUTH];
    extension(OID_EXT_KEY_USAGE, false, usages.to_der()?)
}

/// `subjectAltName` holding exactly one `uniformResourceIdentifier`
/// (`[6] IMPLICIT IA5String`) — the SPIFFE ID.
fn san_uri_ext(uri: &str) -> Result<Extension, X509Error> {
    if !uri.starts_with("spiffe://") || !uri.is_ascii() {
        return Err(X509Error::SpiffeId(uri.to_string()));
    }
    let name = Any::new(
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(6),
        },
        uri.as_bytes(),
    )?;
    // The subject DN is non-empty, so RFC 5280 leaves this non-critical.
    extension(OID_SUBJECT_ALT_NAME, false, vec![name].to_der()?)
}

fn ski_ext(pk: &CompositePublicKey) -> Result<Extension, X509Error> {
    let id = key_identifier(pk);
    extension(
        OID_SUBJECT_KEY_IDENTIFIER,
        false,
        OctetString::new(id.to_vec())?.to_der()?,
    )
}

fn aki_ext(issuer_pub: &CompositePublicKey) -> Result<Extension, X509Error> {
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(key_identifier(issuer_pub).to_vec())?),
    };
    extension(OID_AUTHORITY_KEY_IDENTIFIER, false, aki.to_der()?)
}

fn alt_public_key_ext(pk: &CompositePublicKey) -> Result<Extension, X509Error> {
    extension(
        OID_SUBJECT_ALT_PUBLIC_KEY_INFO,
        false,
        mldsa65_spki(pk)?.to_der()?,
    )
}

fn alt_signature_algorithm_ext() -> Result<Extension, X509Error> {
    extension(
        OID_ALT_SIGNATURE_ALGORITHM,
        false,
        AlgorithmIdentifier {
            algorithm: OID_ML_DSA_65,
        }
        .to_der()?,
    )
}

fn alt_signature_value_ext(sig: &[u8]) -> Result<Extension, X509Error> {
    extension(
        OID_ALT_SIGNATURE_VALUE,
        false,
        BitString::new(0, sig.to_vec())?.to_der()?,
    )
}

fn validity(not_before: i64, not_after: i64) -> Result<Validity, X509Error> {
    if not_before >= not_after {
        return Err(X509Error::Validity {
            not_before,
            not_after,
        });
    }
    Ok(Validity {
        not_before: Asn1Time::from_unix(not_before)?,
        not_after: Asn1Time::from_unix(not_after)?,
    })
}

/// Whether the ML-DSA-65 half is signed with FIPS-204's hedged (randomised) or
/// deterministic variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AltSigning {
    /// The FIPS-204 default. Every issuance produces fresh bytes.
    Hedged,
    /// `rnd = 0`, so the certificate is reproducible. Used only for the trust
    /// bundle, which every replica must publish identically.
    Deterministic,
}

/// Two-pass hybrid signing, per ITU-T X.509 (2019) §9.8.
///
/// `tbs` arrives carrying `subjectAltPublicKeyInfo` and `altSignatureAlgorithm`
/// but **not** `altSignatureValue`. The ML-DSA-65 signature covers that
/// encoding; the extension is then appended and the Ed25519 signature covers
/// the completed body.
fn sign_hybrid(
    secret: &CompositeSecretKey,
    mut tbs: TbsCertificate,
    alt: AltSigning,
) -> Result<Vec<u8>, X509Error> {
    let pre_der = tbs.to_der()?;
    let alt_sig = match alt {
        AltSigning::Hedged => secret.sign_interop_mldsa65(ALT_SIGNATURE_CONTEXT, &pre_der)?,
        AltSigning::Deterministic => {
            secret.sign_interop_mldsa65_deterministic(ALT_SIGNATURE_CONTEXT, &pre_der)?
        }
    };

    tbs.extensions
        .as_mut()
        .ok_or_else(|| X509Error::Der("TBSCertificate has no extensions".to_string()))?
        .push(alt_signature_value_ext(&alt_sig)?);

    let final_der = tbs.to_der()?;
    let native_sig = secret.sign_interop_ed25519(&final_der)?;

    let cert = Certificate {
        tbs_certificate: Any::from_der(&final_der)?,
        signature_algorithm: AlgorithmIdentifier {
            algorithm: OID_ED25519,
        },
        signature: BitString::new(0, native_sig.to_vec())?,
    };
    Ok(cert.to_der()?)
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// Build the signing (trust-bundle) certificate for a trust domain.
///
/// Self-signed, `CA:TRUE`, `keyCertSign` + `cRLSign`, with the trust domain ID
/// `spiffe://<trust_domain>` as its URI SAN. Deterministic in
/// `(issuer key, trust_domain)`: two replicas sharing an issuer seed emit
/// identical DER, so a client that pinned one replica's bundle is not surprised
/// by another's.
pub fn issue_ca(
    secret: &CompositeSecretKey,
    public: &CompositePublicKey,
    trust_domain: &str,
) -> Result<Vec<u8>, X509Error> {
    let dn = issuer_dn(trust_domain)?;
    let tbs = TbsCertificate {
        version: X509_V3,
        serial_number: serial_number(
            b"ferrogate-x509-ca-serial-v1",
            &[trust_domain.as_bytes(), &public.to_concat_bytes()],
        )?,
        signature: AlgorithmIdentifier {
            algorithm: OID_ED25519,
        },
        issuer: dn.clone(),
        validity: validity(CA_NOT_BEFORE, CA_NOT_AFTER)?,
        subject: dn,
        subject_public_key_info: ed25519_spki(public)?,
        extensions: Some(vec![
            basic_constraints_ext(true)?,
            // keyCertSign (bit 5) | cRLSign (bit 6); 7 bits significant.
            key_usage_ext(0b0000_0110, 1)?,
            san_uri_ext(&format!("spiffe://{trust_domain}"))?,
            ski_ext(public)?,
            alt_public_key_ext(public)?,
            alt_signature_algorithm_ext()?,
        ]),
    };
    sign_hybrid(secret, tbs, AltSigning::Deterministic)
}

/// Issue one X.509-SVID leaf.
///
/// `secret`/`public` are the CMIS issuer key; `trust_domain` must be the same
/// one [`issue_ca`] was called with, so the leaf's `issuer` matches the
/// bundle's `subject`.
pub fn issue_leaf(
    secret: &CompositeSecretKey,
    public: &CompositePublicKey,
    trust_domain: &str,
    params: &LeafParams<'_>,
) -> Result<X509Svid, X509Error> {
    let tbs = TbsCertificate {
        version: X509_V3,
        serial_number: serial_number(
            b"ferrogate-x509-leaf-serial-v1",
            &[
                params.spiffe_id.as_bytes(),
                &params.not_before.to_be_bytes(),
                &params.subject_pub.to_concat_bytes(),
            ],
        )?,
        signature: AlgorithmIdentifier {
            algorithm: OID_ED25519,
        },
        issuer: issuer_dn(trust_domain)?,
        validity: validity(params.not_before, params.not_after)?,
        subject: subject_dn(params.spiffe_id)?,
        subject_public_key_info: ed25519_spki(params.subject_pub)?,
        extensions: Some(vec![
            basic_constraints_ext(false)?,
            // digitalSignature (bit 0); 1 bit significant.
            key_usage_ext(0b1000_0000, 7)?,
            ext_key_usage_ext()?,
            san_uri_ext(params.spiffe_id)?,
            ski_ext(params.subject_pub)?,
            aki_ext(public)?,
            alt_public_key_ext(params.subject_pub)?,
            alt_signature_algorithm_ext()?,
        ]),
    };
    Ok(X509Svid {
        leaf_der: sign_hybrid(secret, tbs, AltSigning::Hedged)?,
        spiffe_id: params.spiffe_id.to_string(),
        not_before: params.not_before,
        not_after: params.not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (CompositeSecretKey, CompositePublicKey) {
        CompositeSecretKey::from_seed(&[0x33; 32])
    }

    fn host_keys() -> (CompositeSecretKey, CompositePublicKey) {
        CompositeSecretKey::from_seed(&[0x77; 32])
    }

    fn leaf() -> (Vec<u8>, CompositePublicKey) {
        let (sk, pk) = keys();
        let (_, host_pk) = host_keys();
        let svid = issue_leaf(
            &sk,
            &pk,
            "ferrogate.test",
            &LeafParams {
                subject_pub: &host_pk,
                spiffe_id: "spiffe://ferrogate.test/host/0192b0d0-0000-8000-8000-000000000000",
                not_before: 1_700_000_000,
                not_after: 1_700_003_600,
            },
        )
        .unwrap();
        (svid.leaf_der, pk)
    }

    fn tbs_of(cert_der: &[u8]) -> TbsCertificate {
        let cert = Certificate::from_der(cert_der).unwrap();
        TbsCertificate::from_der(cert.tbs_certificate.to_der().unwrap().as_slice()).unwrap()
    }

    fn ext(tbs: &TbsCertificate, oid: ObjectIdentifier) -> Option<&Extension> {
        tbs.extensions.as_ref()?.iter().find(|e| e.extn_id == oid)
    }

    #[test]
    fn leaf_decodes_and_has_the_spiffe_profile_shape() {
        let (der, _) = leaf();
        let tbs = tbs_of(&der);

        assert_eq!(tbs.version, X509_V3);
        assert_eq!(tbs.signature.algorithm, OID_ED25519);
        assert_eq!(tbs.subject_public_key_info.algorithm.algorithm, OID_ED25519);

        let bc = ext(&tbs, OID_BASIC_CONSTRAINTS).expect("basicConstraints");
        assert!(bc.critical, "basicConstraints must be critical");
        // CA:FALSE is the ASN.1 DEFAULT, so the value is an empty SEQUENCE.
        assert_eq!(bc.extn_value.as_bytes(), &[0x30, 0x00]);

        let ku = ext(&tbs, OID_KEY_USAGE).expect("keyUsage");
        assert!(ku.critical, "keyUsage must be critical");

        let san = ext(&tbs, OID_SUBJECT_ALT_NAME).expect("subjectAltName");
        assert!(
            !san.critical,
            "subject DN is non-empty, so SAN is not critical"
        );
        let uri = b"spiffe://ferrogate.test/host/0192b0d0-0000-8000-8000-000000000000";
        assert!(
            san.extn_value
                .as_bytes()
                .windows(uri.len())
                .any(|w| w == uri),
            "the SPIFFE ID must appear as the URI SAN"
        );

        assert!(ext(&tbs, OID_EXT_KEY_USAGE).is_some());
        assert!(ext(&tbs, OID_SUBJECT_KEY_IDENTIFIER).is_some());
        assert!(ext(&tbs, OID_AUTHORITY_KEY_IDENTIFIER).is_some());
    }

    #[test]
    fn serial_number_is_positive_and_deterministic() {
        let (a, _) = leaf();
        let (b, _) = leaf();
        // The leaf's ML-DSA half is hedged, so the DER differs run to run — but
        // the serial is derived, not random, so re-issuing the same identity at
        // the same instant names the same certificate.
        assert_ne!(a, b, "leaf issuance uses hedged ML-DSA signing");
        assert_eq!(tbs_of(&a).serial_number, tbs_of(&b).serial_number);

        let serial = tbs_of(&a).serial_number;
        let bytes = serial.as_bytes();
        assert_eq!(bytes.len(), 16, "no leading zero stripped, none prepended");
        assert_eq!(bytes[0] & 0x80, 0, "serial must encode as positive");
        assert_ne!(bytes[0], 0);
    }

    #[test]
    fn native_signature_verifies_over_the_whole_body() {
        let (der, issuer_pub) = leaf();
        let cert = Certificate::from_der(&der).unwrap();
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let sig: [u8; 64] = cert
            .signature
            .as_bytes()
            .unwrap()
            .try_into()
            .expect("64-byte Ed25519 signature");

        issuer_pub
            .verify_interop_ed25519(&tbs_der, &sig)
            .expect("the native Ed25519 signature covers the emitted TBSCertificate");
    }

    #[test]
    fn alt_signature_covers_the_body_without_the_alt_signature_extension() {
        let (der, issuer_pub) = leaf();
        let mut tbs = tbs_of(&der);

        let exts = tbs.extensions.as_mut().unwrap();
        let alt = exts
            .iter()
            .position(|e| e.extn_id == OID_ALT_SIGNATURE_VALUE)
            .expect("altSignatureValue present");
        assert_eq!(alt, exts.len() - 1, "altSignatureValue is encoded last");
        let alt_ext = exts.remove(alt);
        let alt_sig = BitString::from_der(alt_ext.extn_value.as_bytes()).unwrap();

        let pre_der = tbs.to_der().unwrap();
        issuer_pub
            .verify_interop_mldsa65(ALT_SIGNATURE_CONTEXT, &pre_der, alt_sig.as_bytes().unwrap())
            .expect("dropping altSignatureValue and re-encoding reproduces the signed bytes");
    }

    #[test]
    fn tampering_with_the_body_breaks_both_signatures() {
        let (der, issuer_pub) = leaf();
        let cert = Certificate::from_der(&der).unwrap();
        let mut tbs_der = cert.tbs_certificate.to_der().unwrap();
        // Flip a byte inside the validity window.
        let idx = tbs_der.len() / 2;
        tbs_der[idx] ^= 0x01;
        let sig: [u8; 64] = cert.signature.as_bytes().unwrap().try_into().unwrap();
        assert!(issuer_pub.verify_interop_ed25519(&tbs_der, &sig).is_err());
    }

    #[test]
    fn ca_is_byte_identical_across_issuers_sharing_a_seed() {
        let (sk_a, pk_a) = keys();
        let (sk_b, pk_b) = keys();
        let a = issue_ca(&sk_a, &pk_a, "ferrogate.test").unwrap();
        let b = issue_ca(&sk_b, &pk_b, "ferrogate.test").unwrap();
        assert_eq!(
            a, b,
            "replicas sharing an issuer seed publish the same bundle"
        );
    }

    #[test]
    fn ca_is_a_signing_certificate_and_leaf_chains_to_it() {
        let (sk, pk) = keys();
        let ca_der = issue_ca(&sk, &pk, "ferrogate.test").unwrap();
        let ca = tbs_of(&ca_der);

        let bc = ext(&ca, OID_BASIC_CONSTRAINTS).unwrap();
        assert!(bc.critical);
        assert_eq!(
            bc.extn_value.as_bytes(),
            &[0x30, 0x03, 0x01, 0x01, 0xff],
            "CA:TRUE"
        );
        assert_eq!(ca.issuer, ca.subject, "the bundle is self-signed");

        let (leaf_der, _) = leaf();
        let leaf = tbs_of(&leaf_der);
        assert_eq!(
            leaf.issuer, ca.subject,
            "the leaf's issuer must match the bundle's subject byte-for-byte"
        );

        let ca_ski = ext(&ca, OID_SUBJECT_KEY_IDENTIFIER).unwrap();
        let leaf_aki = ext(&leaf, OID_AUTHORITY_KEY_IDENTIFIER).unwrap();
        let ski = OctetString::from_der(ca_ski.extn_value.as_bytes()).unwrap();
        assert!(
            leaf_aki
                .extn_value
                .as_bytes()
                .windows(20)
                .any(|w| w == ski.as_bytes()),
            "the leaf's AKI must name the bundle's SKI"
        );
    }

    #[test]
    fn ca_validity_window_is_the_documented_anchor() {
        let (sk, pk) = keys();
        let ca = tbs_of(&issue_ca(&sk, &pk, "ferrogate.test").unwrap());
        assert_eq!(
            ca.validity.not_before,
            Asn1Time::from_unix(CA_NOT_BEFORE).unwrap()
        );
        assert_eq!(
            ca.validity.not_after,
            Asn1Time::from_unix(CA_NOT_AFTER).unwrap()
        );
        // Both anchors are still in the UTCTime era RFC 5280 mandates.
        assert!(matches!(ca.validity.not_after, Asn1Time::Utc(_)));
    }

    #[test]
    fn time_switches_to_generalized_time_in_2050() {
        assert!(matches!(
            Asn1Time::from_unix(GENERALIZED_TIME_FROM - 1).unwrap(),
            Asn1Time::Utc(_)
        ));
        assert!(matches!(
            Asn1Time::from_unix(GENERALIZED_TIME_FROM).unwrap(),
            Asn1Time::General(_)
        ));
    }

    #[test]
    fn inverted_or_empty_validity_is_refused() {
        let (sk, pk) = keys();
        let (_, host_pk) = host_keys();
        let err = issue_leaf(
            &sk,
            &pk,
            "ferrogate.test",
            &LeafParams {
                subject_pub: &host_pk,
                spiffe_id: "spiffe://ferrogate.test/host/x",
                not_before: 1_700_000_000,
                not_after: 1_700_000_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, X509Error::Validity { .. }));
    }

    #[test]
    fn a_non_spiffe_san_is_refused() {
        let (sk, pk) = keys();
        let (_, host_pk) = host_keys();
        let err = issue_leaf(
            &sk,
            &pk,
            "ferrogate.test",
            &LeafParams {
                subject_pub: &host_pk,
                spiffe_id: "https://ferrogate.test/host/x",
                not_before: 1_700_000_000,
                not_after: 1_700_003_600,
            },
        )
        .unwrap_err();
        assert!(matches!(err, X509Error::SpiffeId(_)));
    }

    #[test]
    fn subject_key_is_the_hosts_key_not_the_issuers() {
        let (der, _) = leaf();
        let tbs = tbs_of(&der);
        let (_, host_pk) = host_keys();
        assert_eq!(
            tbs.subject_public_key_info.subject_public_key.raw_bytes(),
            host_pk.ed25519().as_bytes(),
        );

        let alt = ext(&tbs, OID_SUBJECT_ALT_PUBLIC_KEY_INFO).expect("subjectAltPublicKeyInfo");
        let spki = SubjectPublicKeyInfo::from_der(alt.extn_value.as_bytes()).unwrap();
        assert_eq!(spki.algorithm.algorithm, OID_ML_DSA_65);
        assert_eq!(
            spki.subject_public_key.raw_bytes(),
            mldsa65_pub_bytes(&host_pk).as_slice(),
        );
    }

    #[test]
    fn oids_match_their_specifications() {
        assert_eq!(OID_ED25519.to_string(), "1.3.101.112");
        assert_eq!(OID_ML_DSA_65.to_string(), "2.16.840.1.101.3.4.3.18");
        assert_eq!(OID_SUBJECT_ALT_PUBLIC_KEY_INFO.to_string(), "2.5.29.72");
        assert_eq!(OID_ALT_SIGNATURE_ALGORITHM.to_string(), "2.5.29.73");
        assert_eq!(OID_ALT_SIGNATURE_VALUE.to_string(), "2.5.29.74");
    }
}
