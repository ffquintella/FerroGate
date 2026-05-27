//! SPIFFE-ID derivation.
//!
//! The host identity is deterministic in the TPM Endorsement Key: the path
//! component is a UUID derived from `SHA-384(ek_cert_der)`, so the same machine
//! always maps to the same SPIFFE ID across re-attestations.

use uuid::Uuid;

/// Failure modes for SPIFFE-ID construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpiffeError {
    /// The trust domain was empty or contained a path/scheme separator.
    #[error("invalid trust domain: {0}")]
    InvalidTrustDomain(String),
}

fn check_trust_domain(td: &str) -> Result<(), SpiffeError> {
    if td.is_empty() || td.contains('/') || td.contains(':') {
        return Err(SpiffeError::InvalidTrustDomain(td.to_string()));
    }
    Ok(())
}

/// Derive the host UUID from the EK certificate digest.
///
/// Takes the first 16 bytes of the SHA-384 digest and stamps RFC 4122
/// version-8 (custom) and variant bits, yielding a stable, well-formed UUID.
#[must_use]
pub fn host_uuid_from_ek_digest(ek_cert_sha384: &[u8; 48]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&ek_cert_sha384[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

/// The CMIS issuer SPIFFE ID for a trust domain: `spiffe://<td>/cmis`.
pub fn spiffe_issuer_id(trust_domain: &str) -> Result<String, SpiffeError> {
    check_trust_domain(trust_domain)?;
    Ok(format!("spiffe://{trust_domain}/cmis"))
}

/// The host SPIFFE ID: `spiffe://<td>/host/<uuid>`.
pub fn spiffe_host_id(
    trust_domain: &str,
    ek_cert_sha384: &[u8; 48],
) -> Result<String, SpiffeError> {
    check_trust_domain(trust_domain)?;
    let uuid = host_uuid_from_ek_digest(ek_cert_sha384);
    Ok(format!("spiffe://{trust_domain}/host/{uuid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_id_is_deterministic_in_ek_digest() {
        let d = [7u8; 48];
        let a = spiffe_host_id("ferrogate.prod", &d).unwrap();
        let b = spiffe_host_id("ferrogate.prod", &d).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("spiffe://ferrogate.prod/host/"));
    }

    #[test]
    fn different_ek_yields_different_host() {
        let a = spiffe_host_id("ferrogate.prod", &[1u8; 48]).unwrap();
        let b = spiffe_host_id("ferrogate.prod", &[2u8; 48]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn issuer_id_shape() {
        assert_eq!(
            spiffe_issuer_id("ferrogate.test").unwrap(),
            "spiffe://ferrogate.test/cmis"
        );
    }

    #[test]
    fn rejects_bad_trust_domain() {
        assert!(spiffe_issuer_id("").is_err());
        assert!(spiffe_issuer_id("a/b").is_err());
        assert!(spiffe_host_id("a:b", &[0u8; 48]).is_err());
    }

    #[test]
    fn uuid_has_version_8() {
        let u = host_uuid_from_ek_digest(&[0xABu8; 48]);
        assert_eq!(u.get_version_num(), 8);
    }
}
