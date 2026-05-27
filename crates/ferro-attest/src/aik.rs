//! AIK attribute-mask validation (step 2 of the quote-verification algorithm).
//!
//! A restricted signing key can only sign TPM-internal structures (quotes,
//! certifies), so it cannot be coerced into signing attacker-chosen messages.
//! The verifier therefore insists on the exact attribute profile from
//! `docs/protocol.md` before trusting any quote the AIK signed.

use crate::tpm::{
    EccPublic, TPMA_DECRYPT, TPMA_FIXED_PARENT, TPMA_FIXED_TPM, TPMA_RESTRICTED,
    TPMA_SENSITIVE_DATA_ORIGIN, TPMA_SIGN, TPM_ALG_ECDSA, TPM_ECC_NIST_P256,
};

/// Why an AIK public area failed the required-attribute check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AikRejection {
    /// A required attribute bit was clear.
    #[error("AIK missing required attribute: {0}")]
    MissingAttribute(&'static str),
    /// A forbidden attribute bit was set.
    #[error("AIK has forbidden attribute: {0}")]
    ForbiddenAttribute(&'static str),
    /// The key is not on the NIST P-256 curve.
    #[error("AIK is not on curve NIST P-256")]
    WrongCurve,
    /// The signing scheme is not ECDSA.
    #[error("AIK signing scheme is not ECDSA")]
    WrongScheme,
}

/// Verify the AIK public area carries exactly the attributes an attestation
/// key must have: `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`,
/// `restricted`, `sign` all set, and `decrypt` clear; on curve P-256 with the
/// ECDSA scheme.
pub fn check_aik(pub_area: &EccPublic) -> Result<(), AikRejection> {
    let attrs = pub_area.attributes;

    for (bit, name) in [
        (TPMA_FIXED_TPM, "fixedTPM"),
        (TPMA_FIXED_PARENT, "fixedParent"),
        (TPMA_SENSITIVE_DATA_ORIGIN, "sensitiveDataOrigin"),
        (TPMA_RESTRICTED, "restricted"),
        (TPMA_SIGN, "sign"),
    ] {
        if attrs & bit == 0 {
            return Err(AikRejection::MissingAttribute(name));
        }
    }

    if attrs & TPMA_DECRYPT != 0 {
        return Err(AikRejection::ForbiddenAttribute("decrypt"));
    }

    if pub_area.curve_id != TPM_ECC_NIST_P256 {
        return Err(AikRejection::WrongCurve);
    }
    if pub_area.scheme != TPM_ALG_ECDSA {
        return Err(AikRejection::WrongScheme);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::{TPMA_USER_WITH_AUTH, TPM_ALG_SHA256};

    fn good_aik() -> EccPublic {
        EccPublic {
            attributes: TPMA_FIXED_TPM
                | TPMA_FIXED_PARENT
                | TPMA_SENSITIVE_DATA_ORIGIN
                | TPMA_USER_WITH_AUTH
                | TPMA_RESTRICTED
                | TPMA_SIGN,
            curve_id: TPM_ECC_NIST_P256,
            scheme: TPM_ALG_ECDSA,
            scheme_hash: TPM_ALG_SHA256,
            x: vec![1u8; 32],
            y: vec![2u8; 32],
        }
    }

    #[test]
    fn accepts_well_formed_aik() {
        check_aik(&good_aik()).expect("valid AIK");
    }

    #[test]
    fn rejects_non_restricted_aik() {
        let mut aik = good_aik();
        aik.attributes &= !TPMA_RESTRICTED;
        assert_eq!(
            check_aik(&aik),
            Err(AikRejection::MissingAttribute("restricted"))
        );
    }

    #[test]
    fn rejects_decrypt_aik() {
        let mut aik = good_aik();
        aik.attributes |= TPMA_DECRYPT;
        assert_eq!(
            check_aik(&aik),
            Err(AikRejection::ForbiddenAttribute("decrypt"))
        );
    }

    #[test]
    fn rejects_wrong_curve() {
        let mut aik = good_aik();
        aik.curve_id = 0x0004; // NIST P-384
        assert_eq!(check_aik(&aik), Err(AikRejection::WrongCurve));
    }
}
