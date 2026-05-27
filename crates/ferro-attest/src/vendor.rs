//! TPM vendor trust store and EK-certificate chain verification (step 1).
//!
//! The Endorsement Key certificate is burned in at manufacture and signed by
//! the TPM vendor. We anchor host identity by requiring the EK cert to chain,
//! by signature, to a root we trust for that vendor. Roots are bundled per
//! vendor under `vendor-roots/` and are independently selectable, so an
//! operator can, say, trust only Infineon and Nuvoton in a given fleet.

use x509_parser::prelude::*;

/// A supported TPM vendor whose EK-signing root(s) we can trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vendor {
    /// Infineon OPTIGA.
    Infineon,
    /// Nuvoton.
    Nuvoton,
    /// STMicroelectronics.
    St,
    /// Intel PTT (firmware TPM).
    IntelPtt,
}

impl Vendor {
    /// All vendors, for `bundled()`.
    pub const ALL: [Vendor; 4] = [
        Vendor::Infineon,
        Vendor::Nuvoton,
        Vendor::St,
        Vendor::IntelPtt,
    ];

    /// Human-readable name (also used in audit records).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Vendor::Infineon => "infineon",
            Vendor::Nuvoton => "nuvoton",
            Vendor::St => "st",
            Vendor::IntelPtt => "intel-ptt",
        }
    }

    /// The PEM root bundle compiled in for this vendor.
    ///
    /// `build.rs` concatenates every `*.pem` under `vendor-roots/<dir>/` into
    /// `OUT_DIR/<dir>.pem`, which is embedded here. Dropping a root into that
    /// directory and rebuilding is all that's needed to trust it — see
    /// `scripts/ferrogate-ca.sh` and `vendor-roots/README.md`. The bundle is
    /// empty until an operator provisions roots, so nothing is trusted by
    /// default.
    // The arms embed different files; they only look identical while every
    // bundle is empty (no roots provisioned yet).
    #[allow(clippy::match_same_arms)]
    const fn bundled_pem(self) -> &'static str {
        match self {
            Vendor::Infineon => include_str!(concat!(env!("OUT_DIR"), "/infineon.pem")),
            Vendor::Nuvoton => include_str!(concat!(env!("OUT_DIR"), "/nuvoton.pem")),
            Vendor::St => include_str!(concat!(env!("OUT_DIR"), "/st.pem")),
            Vendor::IntelPtt => include_str!(concat!(env!("OUT_DIR"), "/intel.pem")),
        }
    }
}

/// Why an EK certificate failed to chain to a trusted vendor root.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// The EK certificate (or an intermediate) could not be parsed.
    #[error("malformed certificate: {0}")]
    Malformed(String),
    /// No issuer for some certificate in the path could be found among the
    /// supplied intermediates or trusted roots.
    #[error("incomplete chain: no issuer found for subject")]
    NoIssuer,
    /// A signature in the path did not verify.
    #[error("signature verification failed in chain")]
    BadSignature,
    /// A certificate in the path was outside its validity window.
    #[error("certificate not valid at the reference time")]
    Expired,
    /// The path exceeded the maximum allowed length (loop guard).
    #[error("chain exceeds maximum depth")]
    TooDeep,
    /// The trust store holds no roots at all.
    #[error("trust store is empty")]
    EmptyStore,
}

/// A trusted root, tagged with the vendor it belongs to.
struct Root {
    der: Vec<u8>,
    vendor: Vendor,
}

/// A set of trusted vendor roots against which EK chains are validated.
#[derive(Default)]
pub struct VendorTrustStore {
    roots: Vec<Root>,
}

/// The successful result of a chain check: which vendor anchored the EK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorMatch {
    /// The vendor whose root terminated the chain.
    pub vendor: Vendor,
}

const MAX_CHAIN_DEPTH: usize = 8;

impl VendorTrustStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store pre-loaded with every vendor's bundled roots.
    pub fn bundled() -> Result<Self, ChainError> {
        let mut store = Self::new();
        for v in Vendor::ALL {
            store.load_vendor(v)?;
        }
        Ok(store)
    }

    /// A store loaded with a single vendor's bundled roots.
    pub fn with_vendor(vendor: Vendor) -> Result<Self, ChainError> {
        let mut store = Self::new();
        store.load_vendor(vendor)?;
        Ok(store)
    }

    /// Load the compiled-in roots for one vendor into this store.
    pub fn load_vendor(&mut self, vendor: Vendor) -> Result<(), ChainError> {
        for pem in Pem::iter_from_buffer(vendor.bundled_pem().as_bytes()) {
            let pem = pem.map_err(|e| ChainError::Malformed(e.to_string()))?;
            self.add_root_der(&pem.contents, vendor)?;
        }
        Ok(())
    }

    /// Add a single PEM-encoded root, attributing it to `vendor`. Useful for
    /// test rigs (e.g. an `swtpm` CA) and for out-of-band provisioning.
    pub fn add_root_pem(&mut self, pem: &[u8], vendor: Vendor) -> Result<(), ChainError> {
        for pem in Pem::iter_from_buffer(pem) {
            let pem = pem.map_err(|e| ChainError::Malformed(e.to_string()))?;
            self.add_root_der(&pem.contents, vendor)?;
        }
        Ok(())
    }

    /// Add a single DER-encoded root.
    pub fn add_root_der(&mut self, der: &[u8], vendor: Vendor) -> Result<(), ChainError> {
        // Parse once to reject garbage early.
        X509Certificate::from_der(der).map_err(|e| ChainError::Malformed(e.to_string()))?;
        self.roots.push(Root {
            der: der.to_vec(),
            vendor,
        });
        Ok(())
    }

    /// Number of trusted roots currently loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the store holds no roots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Verify that `ek_der` chains, by signature, to one of the trusted roots,
    /// using `intermediates` (DER) to bridge gaps. `now` is the reference time
    /// for validity checks (seconds since the Unix epoch).
    ///
    /// Returns the vendor whose root terminated the chain.
    pub fn verify_ek_chain(
        &self,
        ek_der: &[u8],
        intermediates: &[Vec<u8>],
        now: i64,
    ) -> Result<VendorMatch, ChainError> {
        if self.roots.is_empty() {
            return Err(ChainError::EmptyStore);
        }

        let mut current = ek_der.to_vec();
        for _ in 0..MAX_CHAIN_DEPTH {
            let (subject_raw, issuer_raw, is_self_issued) = parse_names(&current)?;
            check_validity(&current, now)?;

            // If this cert is one of our trusted roots (matched by full bytes),
            // and self-issued, the chain terminates.
            if is_self_issued {
                if let Some(vendor) = self.matching_root_vendor(&current)? {
                    return Ok(VendorMatch { vendor });
                }
            }

            // Find an issuer (a trusted root first, then an intermediate) whose
            // subject equals our issuer and whose key verifies our signature.
            if let Some(vendor) = self.issuer_root_for(&issuer_raw, &current)? {
                return Ok(VendorMatch { vendor });
            }
            match issuer_intermediate_for(&issuer_raw, &current, intermediates)? {
                Some(next) => {
                    // Guard against a cert that issues itself but is not a
                    // trusted root (would loop forever otherwise).
                    if subject_raw == issuer_raw {
                        return Err(ChainError::NoIssuer);
                    }
                    current = next;
                }
                None => return Err(ChainError::NoIssuer),
            }
        }
        Err(ChainError::TooDeep)
    }

    /// If `der` byte-for-byte matches a trusted root, return its vendor.
    fn matching_root_vendor(&self, der: &[u8]) -> Result<Option<Vendor>, ChainError> {
        Ok(self.roots.iter().find(|r| r.der == der).map(|r| r.vendor))
    }

    /// If a trusted root has `subject == issuer_raw` and verifies `child`'s
    /// signature, return its vendor.
    fn issuer_root_for(
        &self,
        issuer_raw: &[u8],
        child_der: &[u8],
    ) -> Result<Option<Vendor>, ChainError> {
        for root in &self.roots {
            let (root_subject, _, _) = parse_names(&root.der)?;
            if root_subject == issuer_raw && verify_signed_by(child_der, &root.der)? {
                return Ok(Some(root.vendor));
            }
        }
        Ok(None)
    }
}

/// Parse subject/issuer raw DER and whether the cert is self-issued.
fn parse_names(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), ChainError> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| ChainError::Malformed(e.to_string()))?;
    let subject = cert.tbs_certificate.subject.as_raw().to_vec();
    let issuer = cert.tbs_certificate.issuer.as_raw().to_vec();
    let self_issued = subject == issuer;
    Ok((subject, issuer, self_issued))
}

/// Check that `der` is within its validity window at `now` (Unix seconds).
fn check_validity(der: &[u8], now: i64) -> Result<(), ChainError> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| ChainError::Malformed(e.to_string()))?;
    let nb = cert.validity().not_before.timestamp();
    let na = cert.validity().not_after.timestamp();
    if now < nb || now > na {
        return Err(ChainError::Expired);
    }
    Ok(())
}

/// Verify that `child_der`'s signature was produced by the key in `issuer_der`.
fn verify_signed_by(child_der: &[u8], issuer_der: &[u8]) -> Result<bool, ChainError> {
    let (_, child) =
        X509Certificate::from_der(child_der).map_err(|e| ChainError::Malformed(e.to_string()))?;
    let (_, issuer) =
        X509Certificate::from_der(issuer_der).map_err(|e| ChainError::Malformed(e.to_string()))?;
    Ok(child.verify_signature(Some(issuer.public_key())).is_ok())
}

/// Find an intermediate whose subject equals `issuer_raw` and that signed
/// `child_der`; return its DER.
fn issuer_intermediate_for(
    issuer_raw: &[u8],
    child_der: &[u8],
    intermediates: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, ChainError> {
    for inter in intermediates {
        let (inter_subject, _, _) = parse_names(inter)?;
        if inter_subject == issuer_raw && verify_signed_by(child_der, inter)? {
            return Ok(Some(inter.clone()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_rejects_any_chain() {
        let store = VendorTrustStore::new();
        let err = store.verify_ek_chain(&[0u8; 4], &[], 0).unwrap_err();
        assert_eq!(err, ChainError::EmptyStore);
    }

    #[test]
    fn bundled_store_loads_without_error() {
        // No roots are committed, so the bundle is currently empty — but the
        // loader must still succeed (it just yields zero anchors).
        let store = VendorTrustStore::bundled().unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn vendor_names_are_stable() {
        assert_eq!(Vendor::Infineon.name(), "infineon");
        assert_eq!(Vendor::IntelPtt.name(), "intel-ptt");
    }

    #[test]
    fn rejects_garbage_root() {
        let mut store = VendorTrustStore::new();
        assert!(matches!(
            store.add_root_der(&[1, 2, 3], Vendor::St),
            Err(ChainError::Malformed(_))
        ));
    }
}
