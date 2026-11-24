//! Reading a publisher's identity on the administrator's machine, before
//! anything is sent: from a signed executable (the OS verifies it) or from
//! certificate files. The result is shown for confirmation; it is never
//! trusted by CMIS or by a MIA, which verify signatures themselves.

use std::path::Path;

use ferro_codesign::{
    cert_facts, certificate_der, CertFacts, SignatureKind, SignatureVerifier, SignerFacts,
    VerifyError,
};

/// Where a [`Candidate`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A signed executable the local OS verified.
    Executable,
    /// A leaf certificate file and a CA certificate file.
    Certificates,
}

/// A publisher identity read locally: the signing certificate and the CA
/// certificates above it, among which the administrator picks the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Signature technology.
    pub kind: SignatureKind,
    /// The signing (leaf) certificate.
    pub leaf: CertFacts,
    /// CA certificates above the leaf, nearest first: the anchor choices.
    pub issuers: Vec<CertFacts>,
    /// The verified signature carried a trusted timestamp (executables).
    pub timestamped: bool,
    /// Where it came from.
    pub source: Source,
}

/// Why an identity could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InspectError {
    /// The local OS refused or could not verify the executable's signature.
    #[error("the executable's signature did not verify ({})", .0.reason())]
    Signature(VerifyError),
    /// A file was unreadable, too large, or not a certificate.
    #[error("not a readable certificate")]
    Certificate,
    /// The chain has no CA certificate above the leaf to pin.
    #[error("no CA certificate above the signing certificate")]
    NoIssuer,
}

/// Read the signer of the executable at `path` with this platform's
/// verifier (Authenticode on Windows, Apple code signature on macOS;
/// unsupported elsewhere).
pub fn inspect_executable(path: &Path) -> Result<Candidate, InspectError> {
    inspect_executable_with(ferro_codesign::platform_verifier().as_ref(), path)
}

/// [`inspect_executable`] with an explicit verifier (tests use a fake).
pub fn inspect_executable_with(
    verifier: &dyn SignatureVerifier,
    path: &Path,
) -> Result<Candidate, InspectError> {
    let sig = verifier
        .verify_file(path)
        .map_err(InspectError::Signature)?;
    let facts = SignerFacts::of(&sig).map_err(|_| InspectError::Certificate)?;
    if facts.issuers.is_empty() {
        return Err(InspectError::NoIssuer);
    }
    Ok(Candidate {
        kind: facts.kind,
        leaf: facts.leaf,
        issuers: facts.issuers,
        timestamped: facts.timestamped,
        source: Source::Executable,
    })
}

/// Read a publisher from certificate files: the signing certificate (`leaf`)
/// and the CA certificate to pin (`anchor`), each DER or single-block PEM.
pub fn inspect_certificates(
    kind: SignatureKind,
    leaf: &[u8],
    anchor: &[u8],
) -> Result<Candidate, InspectError> {
    let read = |bytes: &[u8]| {
        certificate_der(bytes)
            .and_then(|der| cert_facts(&der))
            .map_err(|_| InspectError::Certificate)
    };
    let leaf = read(leaf)?;
    let anchor = read(anchor)?;
    if !anchor.is_ca {
        return Err(InspectError::NoIssuer);
    }
    Ok(Candidate {
        kind,
        leaf,
        issuers: vec![anchor],
        timestamped: false,
        source: Source::Certificates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_codesign::testing::{FakeVerifier, TestChain};

    #[test]
    fn an_executable_yields_its_chain() {
        let chain = TestChain::new("ACME Corp");
        let fake = FakeVerifier::new(Ok(chain.signature(SignatureKind::Authenticode, true)));
        let c = inspect_executable_with(&fake, Path::new("/opt/acme/tool")).unwrap();
        assert_eq!(c.kind, SignatureKind::Authenticode);
        assert!(c.leaf.subject.contains("ACME Corp"));
        assert_eq!(c.issuers.len(), 1);
        assert!(c.timestamped);
        assert_eq!(c.source, Source::Executable);
    }

    #[test]
    fn an_unsigned_executable_is_refused() {
        let fake = FakeVerifier::new(Err(VerifyError::Unsigned));
        assert_eq!(
            inspect_executable_with(&fake, Path::new("/tmp/x")),
            Err(InspectError::Signature(VerifyError::Unsigned))
        );
    }

    #[test]
    fn certificate_files_need_a_ca_anchor() {
        let chain = TestChain::new("ACME Corp");
        let c = inspect_certificates(SignatureKind::Apple, &chain.leaf_der, &chain.ca_der).unwrap();
        assert_eq!(c.source, Source::Certificates);
        assert_eq!(
            inspect_certificates(SignatureKind::Apple, &chain.leaf_der, &chain.leaf_der),
            Err(InspectError::NoIssuer)
        );
        assert_eq!(
            inspect_certificates(SignatureKind::Apple, b"junk", &chain.ca_der),
            Err(InspectError::Certificate)
        );
    }
}
