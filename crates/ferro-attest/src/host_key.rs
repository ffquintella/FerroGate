//! Host-key (TPM-less) evidence verification — feature F15.
//!
//! The TPM profile proves hardware identity with an EK-rooted, PCR-bound quote
//! ([`crate::verify`]). A TPM-less host instead presents:
//!
//! - a hardware fingerprint `H` (see `ferro-machineid`),
//! - the raw [`MachineFacts`] `H` was derived from,
//! - the DER `SubjectPublicKeyInfo` of its machine key (`sep_pub`), and
//! - an ECDSA-P256 signature over `nonce ‖ H` by that key.
//!
//! Verification here is the cryptographic core; the *enrollment* gate (is `H`
//! in the offline-signed fleet manifest?) and the `H ↔ sep_pub` pin live in
//! CMIS, exactly as the EK-hash gate does for the TPM path. This profile proves
//! continuity of a key bound to specific hardware — **not** measured boot — so
//! CMIS marks the resulting SVID at a lower assurance level.

use ferro_machineid::MachineFacts;
use ferro_sep::{host_key_binding, verify_p256};

/// Audit-only reasons host-key evidence was rejected. Never shown to the peer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostKeyRejection {
    /// The recomputed fingerprint did not match the one the host claimed — the
    /// supplied facts do not hash to the presented `H`.
    #[error("fingerprint does not match the supplied hardware facts")]
    FingerprintMismatch,
    /// The claimed fingerprint was not a 48-byte SHA-384.
    #[error("claimed fingerprint is not 48 bytes")]
    BadFingerprintLen,
    /// The phase-2 signature over `nonce ‖ H` did not verify under `sep_pub`.
    #[error("host-key nonce signature did not verify")]
    NonceSignatureInvalid,
    /// The phase-4 CSR binding signature did not verify under `sep_pub`.
    #[error("CSR binding signature did not verify")]
    CsrSignatureInvalid,
}

/// What a successful host-key verification establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHostKey {
    /// The hardware fingerprint, recomputed and confirmed against the facts.
    pub fingerprint: [u8; 48],
}

/// Verify phase-2 host-key evidence: recompute the fingerprint from the facts,
/// confirm it equals the claimed value, and check the nonce signature under the
/// presented public key.
///
/// The caller still must (a) confirm the returned fingerprint is enrolled and
/// (b) pin it to `sep_pub` — neither is a cryptographic property this function
/// can decide alone.
///
/// # Errors
/// Returns [`HostKeyRejection`] on any mismatch or invalid signature.
pub fn verify_host_key_evidence(
    board_serial: &str,
    platform_uuid: &str,
    disk_serial: &str,
    claimed_fingerprint: &[u8],
    sep_pub: &[u8],
    nonce: &[u8],
    signature: &[u8],
) -> Result<VerifiedHostKey, HostKeyRejection> {
    if claimed_fingerprint.len() != 48 {
        return Err(HostKeyRejection::BadFingerprintLen);
    }
    let facts = MachineFacts {
        board_serial: board_serial.to_string(),
        platform_uuid: platform_uuid.to_string(),
        disk_serial: disk_serial.to_string(),
    };
    let fp = facts.fingerprint();
    // Constant-time-ish equality is unnecessary here: the fingerprint is public
    // (it is enrolled in the manifest), so a timing oracle reveals nothing.
    if fp.as_bytes() != claimed_fingerprint {
        return Err(HostKeyRejection::FingerprintMismatch);
    }

    let message = host_key_binding(nonce, fp.as_bytes());
    verify_p256(sep_pub, &message, signature)
        .map_err(|_| HostKeyRejection::NonceSignatureInvalid)?;

    Ok(VerifiedHostKey {
        fingerprint: *fp.as_bytes(),
    })
}

/// Verify the phase-4 CSR binding: an ECDSA-P256 signature over `composite_pub`
/// by the same machine key, proving the host that owns the key authorised this
/// composite SVID.
///
/// # Errors
/// Returns [`HostKeyRejection::CsrSignatureInvalid`] if it does not verify.
pub fn verify_host_key_csr(
    sep_pub: &[u8],
    composite_pub: &[u8],
    signature: &[u8],
) -> Result<(), HostKeyRejection> {
    verify_p256(sep_pub, composite_pub, signature)
        .map_err(|_| HostKeyRejection::CsrSignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_sep::{MachineKey, SoftwareMachineKey};

    fn facts() -> (String, String, String) {
        (
            "WT3QF2J3YL".to_string(),
            "38D33B14-6DDD-51DD-B8CD-9854CAF977D5".to_string(),
            "0ba0206164386025".to_string(),
        )
    }

    fn fingerprint_of(b: &str, p: &str, d: &str) -> [u8; 48] {
        *MachineFacts {
            board_serial: b.to_string(),
            platform_uuid: p.to_string(),
            disk_serial: d.to_string(),
        }
        .fingerprint()
        .as_bytes()
    }

    #[test]
    fn accepts_valid_evidence() {
        let (b, p, d) = facts();
        let fp = fingerprint_of(&b, &p, &d);
        let key = SoftwareMachineKey::generate().unwrap();
        let nonce = [7u8; 32];
        let sig = key.sign(&host_key_binding(&nonce, &fp)).unwrap();
        let v = verify_host_key_evidence(
            &b,
            &p,
            &d,
            &fp,
            &key.public_spki_der(),
            &nonce,
            &sig,
        )
        .expect("valid");
        assert_eq!(v.fingerprint, fp);
    }

    #[test]
    fn rejects_forged_fingerprint() {
        let (b, p, d) = facts();
        let key = SoftwareMachineKey::generate().unwrap();
        let nonce = [7u8; 32];
        // Claim a fingerprint the facts do not hash to.
        let bogus = [0xAAu8; 48];
        let sig = key.sign(&host_key_binding(&nonce, &bogus)).unwrap();
        let err =
            verify_host_key_evidence(&b, &p, &d, &bogus, &key.public_spki_der(), &nonce, &sig)
                .unwrap_err();
        assert_eq!(err, HostKeyRejection::FingerprintMismatch);
    }

    #[test]
    fn rejects_replayed_nonce() {
        let (b, p, d) = facts();
        let fp = fingerprint_of(&b, &p, &d);
        let key = SoftwareMachineKey::generate().unwrap();
        // Signed over a different nonce than the one presented.
        let sig = key.sign(&host_key_binding(&[1u8; 32], &fp)).unwrap();
        let err = verify_host_key_evidence(
            &b,
            &p,
            &d,
            &fp,
            &key.public_spki_der(),
            &[2u8; 32],
            &sig,
        )
        .unwrap_err();
        assert_eq!(err, HostKeyRejection::NonceSignatureInvalid);
    }

    #[test]
    fn rejects_wrong_key() {
        let (b, p, d) = facts();
        let fp = fingerprint_of(&b, &p, &d);
        let signer = SoftwareMachineKey::generate().unwrap();
        let impostor = SoftwareMachineKey::generate().unwrap();
        let nonce = [9u8; 32];
        let sig = signer.sign(&host_key_binding(&nonce, &fp)).unwrap();
        let err = verify_host_key_evidence(
            &b,
            &p,
            &d,
            &fp,
            &impostor.public_spki_der(),
            &nonce,
            &sig,
        )
        .unwrap_err();
        assert_eq!(err, HostKeyRejection::NonceSignatureInvalid);
    }

    #[test]
    fn csr_binding_roundtrips() {
        let key = SoftwareMachineKey::generate().unwrap();
        let composite = vec![0x42u8; 1984];
        let sig = key.sign(&composite).unwrap();
        verify_host_key_csr(&key.public_spki_der(), &composite, &sig).expect("csr ok");
        // A different composite key fails.
        assert!(verify_host_key_csr(&key.public_spki_der(), &[0u8; 1984], &sig).is_err());
    }
}
