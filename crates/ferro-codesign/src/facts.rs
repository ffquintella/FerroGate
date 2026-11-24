//! What is read from certificates: from the chain an OS verifier returns
//! ([`SignerFacts`]) and from a certificate file an administrator picks
//! ([`cert_facts`], [`certificate_der`]).

//! Parsing is bounded ([`MAX_CERTIFICATE_BYTES`], [`MAX_CHAIN_LEN`]) and
//! strict: trailing bytes, a non-certificate PEM block or an unparsable
//! certificate are errors, and every caller treats an error as "no match".

use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::model::{PinKind, SignatureKind};
use crate::verifier::VerifiedSignature;

/// Largest certificate (DER, or PEM file) accepted, in bytes.
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Most certificates read from one signer chain.
pub const MAX_CHAIN_LEN: usize = 16;
/// Longest display string kept (subject, issuer), in characters.
pub const MAX_DISPLAY_CHARS: usize = 512;
/// Domain-separation tag of [`subject_pin`].
pub const SUBJECT_PIN_TAG: &[u8] = b"ferrogate-publisher-subject-v1";

/// Why certificate bytes could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FactsError {
    /// More bytes than [`MAX_CERTIFICATE_BYTES`], or a chain longer than
    /// [`MAX_CHAIN_LEN`].
    #[error("too large")]
    TooLarge,
    /// The signer chain is empty.
    #[error("empty chain")]
    EmptyChain,
    /// Not a DER certificate, or a PEM file without exactly one
    /// `CERTIFICATE` block.
    #[error("not a certificate")]
    NotACertificate,
}

/// The digests and display strings of one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFacts {
    /// SHA-256 of the DER certificate (its thumbprint).
    pub cert_sha256: [u8; 32],
    /// SHA-256 of its DER `SubjectPublicKeyInfo`.
    pub spki_sha256: [u8; 32],
    /// [`subject_pin`] of its DER subject.
    pub subject_sha256: [u8; 32],
    /// Subject, for display only (cleaned, bounded).
    pub subject: String,
    /// Issuer, for display only (cleaned, bounded).
    pub issuer: String,
    /// `notBefore`, Unix seconds.
    pub not_before: i64,
    /// `notAfter`, Unix seconds.
    pub not_after: i64,
    /// Basic constraints say CA.
    pub is_ca: bool,
}

impl CertFacts {
    /// The leaf digest a rule of `kind` compares.
    #[must_use]
    pub fn pin(&self, kind: PinKind) -> [u8; 32] {
        match kind {
            PinKind::LeafCertSha256 => self.cert_sha256,
            PinKind::LeafSpkiSha256 => self.spki_sha256,
            PinKind::SubjectSha256 => self.subject_sha256,
        }
    }
}

/// `SHA-256("ferrogate-publisher-subject-v1" ‖ 0x00 ‖ subject DER)`: the
/// subject pin, over the exact DER name (no string normalisation).
#[must_use]
pub fn subject_pin(subject_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SUBJECT_PIN_TAG);
    h.update([0]);
    h.update(subject_der);
    h.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `s` without control or bidi-override characters, at most
/// [`MAX_DISPLAY_CHARS`] characters.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_DISPLAY_CHARS)
        .collect()
}

/// Parse one DER certificate (no trailing bytes) into its [`CertFacts`].
pub fn cert_facts(der: &[u8]) -> Result<CertFacts, FactsError> {
    if der.len() > MAX_CERTIFICATE_BYTES {
        return Err(FactsError::TooLarge);
    }
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| FactsError::NotACertificate)?;
    if !rest.is_empty() {
        return Err(FactsError::NotACertificate);
    }
    let validity = cert.validity();
    Ok(CertFacts {
        cert_sha256: sha256(der),
        spki_sha256: sha256(cert.public_key().raw),
        subject_sha256: subject_pin(cert.subject().as_raw()),
        subject: clean(&cert.subject().to_string()),
        issuer: clean(&cert.issuer().to_string()),
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
        is_ca: cert.is_ca(),
    })
}

/// The DER certificate in a file an administrator picked: DER as is, or a
/// PEM file holding exactly one `CERTIFICATE` block.
pub fn certificate_der(file: &[u8]) -> Result<Vec<u8>, FactsError> {
    if file.len() > MAX_CERTIFICATE_BYTES {
        return Err(FactsError::TooLarge);
    }
    if !file.trim_ascii_start().starts_with(b"-----BEGIN") {
        return Ok(file.to_vec());
    }
    let mut blocks = x509_parser::pem::Pem::iter_from_buffer(file);
    let first = blocks
        .next()
        .and_then(Result::ok)
        .filter(|p| p.label == "CERTIFICATE")
        .ok_or(FactsError::NotACertificate)?;
    if blocks.next().is_some() {
        return Err(FactsError::NotACertificate);
    }
    Ok(first.contents)
}

/// What a verified signature says about its signer: the leaf, the
/// certificates above it, and whether a trusted timestamp was present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerFacts {
    /// Signature technology.
    pub kind: SignatureKind,
    /// The signing (leaf) certificate.
    pub leaf: CertFacts,
    /// The certificates above the leaf, nearest issuer first.
    pub issuers: Vec<CertFacts>,
    /// The signature carries a timestamp the OS verified.
    pub timestamped: bool,
}

impl SignerFacts {
    /// Parse the chain of `sig` (leaf first). Any certificate that does not
    /// parse fails the whole chain.
    pub fn of(sig: &VerifiedSignature) -> Result<Self, FactsError> {
        if sig.chain_der.len() > MAX_CHAIN_LEN {
            return Err(FactsError::TooLarge);
        }
        let mut certs = sig.chain_der.iter().map(|d| cert_facts(d));
        let leaf = certs.next().ok_or(FactsError::EmptyChain)??;
        let issuers = certs.collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            kind: sig.kind,
            leaf,
            issuers,
            timestamped: sig.timestamped,
        })
    }

    /// Whether a certificate above the leaf has SHA-256 `anchor`.
    #[must_use]
    pub fn chain_contains(&self, anchor: &[u8; 32]) -> bool {
        self.issuers.iter().any(|c| &c.cert_sha256 == anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestChain;

    fn fixture(name: &str) -> Vec<u8> {
        let chain = TestChain::new("FerroGate Test Publisher");
        match name {
            "leaf" => chain.leaf_der,
            "ca" => chain.ca_der,
            _ => unreachable!(),
        }
    }

    #[test]
    fn leaf_facts_carry_three_distinct_digests() {
        let der = fixture("leaf");
        let f = cert_facts(&der).unwrap();
        assert_eq!(f.cert_sha256, sha256(&der));
        assert_ne!(f.cert_sha256, f.spki_sha256);
        assert_ne!(f.spki_sha256, f.subject_sha256);
        assert!(
            f.subject.contains("FerroGate Test Publisher"),
            "{}",
            f.subject
        );
        assert!(f.issuer.contains("FerroGate Test CA"), "{}", f.issuer);
        assert!(!f.is_ca);
        assert!(f.not_before < f.not_after);
        assert!(cert_facts(&fixture("ca")).unwrap().is_ca);
    }

    #[test]
    fn trailing_bytes_and_garbage_are_refused() {
        let mut der = fixture("leaf");
        der.push(0);
        assert_eq!(cert_facts(&der), Err(FactsError::NotACertificate));
        assert_eq!(cert_facts(b"nope"), Err(FactsError::NotACertificate));
        assert_eq!(
            cert_facts(&vec![0x30; MAX_CERTIFICATE_BYTES + 1]),
            Err(FactsError::TooLarge)
        );
    }

    #[test]
    fn pem_files_need_exactly_one_certificate_block() {
        let der = fixture("leaf");
        let pem = |label: &str, body: &[u8]| {
            let b64 = base64_lines(body);
            format!("-----BEGIN {label}-----\n{b64}-----END {label}-----\n")
        };
        let one = pem("CERTIFICATE", &der);
        assert_eq!(certificate_der(one.as_bytes()).unwrap(), der);
        assert_eq!(certificate_der(&der).unwrap(), der);
        let two = format!("{one}{one}");
        assert_eq!(
            certificate_der(two.as_bytes()),
            Err(FactsError::NotACertificate)
        );
        let key = pem("PRIVATE KEY", &der);
        assert_eq!(
            certificate_der(key.as_bytes()),
            Err(FactsError::NotACertificate)
        );
    }

    #[test]
    fn signer_facts_split_leaf_and_issuers() {
        let chain = TestChain::new("FerroGate Test Publisher");
        let sig = chain.signature(SignatureKind::Apple, true);
        let f = SignerFacts::of(&sig).unwrap();
        let ca = cert_facts(&chain.ca_der).unwrap();
        assert!(f.chain_contains(&ca.cert_sha256));
        assert!(!f.chain_contains(&cert_facts(&fixture("ca")).unwrap().cert_sha256));
        assert!(
            !f.chain_contains(&f.leaf.cert_sha256),
            "the leaf is not an anchor"
        );
        let empty = VerifiedSignature {
            chain_der: Vec::new(),
            ..sig.clone()
        };
        assert_eq!(SignerFacts::of(&empty), Err(FactsError::EmptyChain));
        let bad = VerifiedSignature {
            chain_der: vec![fixture("leaf"), b"junk".to_vec()],
            ..sig
        };
        assert_eq!(SignerFacts::of(&bad), Err(FactsError::NotACertificate));
    }

    #[test]
    fn display_strings_are_cleaned() {
        assert_eq!(clean("ACME\u{202e}\u{0}Corp\n"), "ACMECorp");
        assert_eq!(clean(&"x".repeat(600)).chars().count(), MAX_DISPLAY_CHARS);
    }

    /// Base64 with 64-character lines (PEM body), without a dependency.
    fn base64_lines(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk.len();
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= n {
                    out.push(char::from(A[((v >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        let mut lines = String::new();
        for line in out.as_bytes().chunks(64) {
            lines.push_str(std::str::from_utf8(line).unwrap());
            lines.push('\n');
        }
        lines
    }
}
