//! `TpmQuoteVerifier` — the fail-closed quote-verification algorithm from
//! `docs/tpm.md` and `docs/protocol.md` phase 2.
//!
//! Every step terminates the handshake on failure with a precise, *audit-only*
//! [`RejectReason`]. The reason is recorded for operators but never surfaced to
//! the peer, which always sees a generic `permission_denied` — so a probing
//! client learns nothing about which check tripped.

use std::collections::BTreeMap;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

use crate::aik::{check_aik, AikRejection};
use crate::rim::{PolicyId, RimStore};
use crate::tpm::{
    EccPublic, EcdsaSignature, ParseError, QuoteInfo, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use crate::vendor::{ChainError, Vendor, VendorTrustStore};

/// The actual PCR values the MIA reported alongside the quote, indexed by PCR
/// number. The verifier recomputes the aggregate digest from these and checks
/// it against the (signed) digest inside the quote.
#[derive(Debug, Default, Clone)]
pub struct PcrSet {
    values: BTreeMap<u8, Vec<u8>>,
}

impl PcrSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the value of one PCR.
    pub fn insert(&mut self, index: u8, value: impl Into<Vec<u8>>) {
        self.values.insert(index, value.into());
    }

    /// Borrow a PCR value.
    #[must_use]
    pub fn get(&self, index: u8) -> Option<&[u8]> {
        self.values.get(&index).map(Vec::as_slice)
    }
}

/// All inputs to a single quote verification.
pub struct QuoteVerification<'a> {
    /// EK certificate, DER.
    pub ek_cert_der: &'a [u8],
    /// Any intermediate CA certs (DER) bridging the EK cert to a root.
    pub ek_intermediates: &'a [Vec<u8>],
    /// Marshaled `TPMT_PUBLIC` for the AIK.
    pub aik_pub: &'a [u8],
    /// Marshaled `TPMS_ATTEST` (the signed quote body).
    pub quote_blob: &'a [u8],
    /// Marshaled `TPMT_SIGNATURE` over the quote body.
    pub signature: &'a [u8],
    /// The server nonce that must appear as `qualifyingData`.
    pub nonce: &'a [u8],
    /// The raw PCR values the MIA reported.
    pub pcrs: &'a PcrSet,
    /// Reference time (Unix seconds) for certificate validity.
    pub now: i64,
}

/// A quote that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    /// The vendor whose root anchored the EK certificate.
    pub vendor: Vendor,
    /// The policy generation the boot state was approved under.
    pub policy_id: PolicyId,
    /// The aggregate PCR digest (SHA-384) that matched the RIM.
    pub pcr_digest: [u8; 48],
}

/// Precise, audit-only reasons a quote was rejected. The peer never sees these.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RejectReason {
    /// Step 1 — EK certificate did not chain to a trusted vendor root.
    #[error("EK chain: {0}")]
    EkChain(ChainError),
    /// Step 2 — the AIK public area failed the required-attribute check.
    #[error("AIK attributes: {0}")]
    AikAttributes(AikRejection),
    /// A TPM structure (quote, AIK pub, or signature) failed to parse.
    #[error("malformed TPM structure: {0}")]
    Malformed(ParseError),
    /// Step 3 — `magic != TPM_GENERATED_VALUE`.
    #[error("quote magic is not TPM_GENERATED_VALUE")]
    BadMagic,
    /// Step 3 — `type != TPM_ST_ATTEST_QUOTE`.
    #[error("attestation type is not a quote")]
    NotAQuote,
    /// Step 4 — `extraData` did not equal the issued nonce.
    #[error("quote nonce mismatch")]
    NonceMismatch,
    /// Step 5 — the quote signature did not verify under the AIK.
    #[error("quote signature did not verify")]
    SignatureInvalid,
    /// Step 5 — the signature used an unsupported digest algorithm.
    #[error("unsupported signature hash algorithm: {0:#06x}")]
    UnsupportedSigHash(u16),
    /// Step 6 — a selected PCR's value was not supplied by the MIA.
    #[error("missing PCR value for index {0}")]
    MissingPcr(u8),
    /// Step 6 — recomputed aggregate digest != the quote's `pcrDigest`.
    #[error("recomputed PCR digest does not match the quote")]
    PcrDigestMismatch,
    /// Step 6 — the quote's `pcrDigest` was not 48 bytes (not a SHA-384 bank).
    #[error("quote pcrDigest is not SHA-384 sized")]
    PcrDigestNotSha384,
    /// Step 7 — the aggregate digest was not in the active RIM allowlist.
    #[error("PCR state not found in RIM allowlist")]
    NotInRim,
}

/// Verifies TPM quotes against a vendor trust store and a RIM allowlist.
pub struct TpmQuoteVerifier {
    trust: VendorTrustStore,
    rim: RimStore,
}

impl TpmQuoteVerifier {
    /// Build a verifier over a trust store and RIM allowlist.
    #[must_use]
    pub fn new(trust: VendorTrustStore, rim: RimStore) -> Self {
        Self { trust, rim }
    }

    /// Borrow the RIM allowlist (e.g. to approve digests in a test rig).
    /// [`RimStore`] uses interior mutability, so callers can mutate via the
    /// returned reference without needing `&mut self`.
    #[must_use]
    pub fn rim_mut(&mut self) -> &mut RimStore {
        &mut self.rim
    }

    /// Borrow the RIM allowlist by shared reference. Useful when a loader
    /// needs to hot-swap generations while a verifier is in use.
    #[must_use]
    pub fn rim(&self) -> &RimStore {
        &self.rim
    }

    /// Borrow the trust store (e.g. to add an `swtpm` CA in a test rig).
    #[must_use]
    pub fn trust_mut(&mut self) -> &mut VendorTrustStore {
        &mut self.trust
    }

    /// Run the full fail-closed verification. Returns the issued
    /// [`VerifiedQuote`] on success, or the precise [`RejectReason`].
    pub fn verify_quote(&self, v: &QuoteVerification<'_>) -> Result<VerifiedQuote, RejectReason> {
        // Step 1 — EK certificate chains to a trusted vendor root.
        let vendor_match = self
            .trust
            .verify_ek_chain(v.ek_cert_der, v.ek_intermediates, v.now)
            .map_err(RejectReason::EkChain)?;

        // Step 2 — AIK satisfies the required attribute mask.
        let aik = EccPublic::parse(v.aik_pub).map_err(RejectReason::Malformed)?;
        check_aik(&aik).map_err(RejectReason::AikAttributes)?;

        // Parse the quote body (contents authenticated by the signature below).
        let quote = QuoteInfo::parse(v.quote_blob).map_err(RejectReason::Malformed)?;

        // Step 3 — magic and type.
        if quote.magic != TPM_GENERATED_VALUE {
            return Err(RejectReason::BadMagic);
        }
        if quote.attest_type != TPM_ST_ATTEST_QUOTE {
            return Err(RejectReason::NotAQuote);
        }

        // Step 4 — nonce / qualifyingData (constant-time; length-safe).
        if !ct_eq(&quote.extra_data, v.nonce) {
            return Err(RejectReason::NonceMismatch);
        }

        // Step 5 — signature over the marshaled quote body verifies under the
        // AIK. Done before trusting any field inside the blob.
        verify_quote_signature(&aik, v.quote_blob, v.signature)?;

        // Step 6 — recompute the aggregate PCR digest from MIA-reported values
        // and match the (now-authenticated) digest in the quote.
        if quote.pcr_digest.len() != 48 {
            return Err(RejectReason::PcrDigestNotSha384);
        }
        let computed = recompute_pcr_digest(&quote, v.pcrs)?;
        if !ct_eq(&computed, &quote.pcr_digest) {
            return Err(RejectReason::PcrDigestMismatch);
        }

        // Step 7 — RIM allowlist lookup (windowed by `now`) -> policy_id.
        let policy_id = self
            .rim
            .lookup_at(&computed, v.now)
            .ok_or(RejectReason::NotInRim)?;

        Ok(VerifiedQuote {
            vendor: vendor_match.vendor,
            policy_id,
            pcr_digest: computed,
        })
    }
}

/// Verify an AIK signature over an arbitrary `message`, as produced by the
/// MIA's restricted AIK in phase 4 (the TPM hashes `message` internally, then
/// signs the digest). CMIS calls this over the marshaled composite public key
/// to bind the in-software SVID key to the attested hardware.
///
/// `aik_pub_marshaled` is the `TPMT_PUBLIC` of the AIK; `signature` is the
/// marshaled `TPMT_SIGNATURE`. The digest algorithm is taken from the
/// signature structure (SHA-256 or SHA-384).
pub fn verify_aik_signature(
    aik_pub_marshaled: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), RejectReason> {
    let aik = EccPublic::parse(aik_pub_marshaled).map_err(RejectReason::Malformed)?;
    verify_quote_signature(&aik, message, signature)
}

/// Recompute `SHA-384( concat(pcr_i for i in selection) )` over the selected
/// PCRs, in ascending index order across the listed selections.
fn recompute_pcr_digest(quote: &QuoteInfo, pcrs: &PcrSet) -> Result<[u8; 48], RejectReason> {
    let mut h = Sha384::new();
    for selection in &quote.pcr_selection {
        // We only quote the SHA-384 bank; ignore any other bank's selection.
        if selection.hash_alg != TPM_ALG_SHA384 {
            continue;
        }
        for idx in selection.selected_indices() {
            let value = pcrs.get(idx).ok_or(RejectReason::MissingPcr(idx))?;
            h.update(value);
        }
    }
    let out = h.finalize();
    let mut digest = [0u8; 48];
    digest.copy_from_slice(&out);
    Ok(digest)
}

/// Verify the ECDSA-P256 quote signature over `H(quote_blob)`, where `H` is the
/// digest algorithm declared in the signature.
fn verify_quote_signature(
    aik: &EccPublic,
    quote_blob: &[u8],
    signature: &[u8],
) -> Result<(), RejectReason> {
    let sig = EcdsaSignature::parse(signature).map_err(RejectReason::Malformed)?;

    let prehash: Vec<u8> = match sig.hash_alg {
        TPM_ALG_SHA256 => Sha256::digest(quote_blob).to_vec(),
        TPM_ALG_SHA384 => Sha384::digest(quote_blob).to_vec(),
        other => return Err(RejectReason::UnsupportedSigHash(other)),
    };

    let point = EncodedPoint::from_affine_coordinates(&pad32(&aik.x), &pad32(&aik.y), false);
    let vk =
        VerifyingKey::from_encoded_point(&point).map_err(|_| RejectReason::SignatureInvalid)?;
    let ecdsa_sig = Signature::from_scalars(pad32(&sig.r), pad32(&sig.s))
        .map_err(|_| RejectReason::SignatureInvalid)?;

    vk.verify_prehash(&prehash, &ecdsa_sig)
        .map_err(|_| RejectReason::SignatureInvalid)
}

/// Left-pad (or trim leading zeros from) a big-endian scalar to 32 bytes.
fn pad32(input: &[u8]) -> p256::FieldBytes {
    let trimmed = {
        let mut s = input;
        while s.len() > 32 && s[0] == 0 {
            s = &s[1..];
        }
        s
    };
    let mut out = p256::FieldBytes::default();
    let n = trimmed.len().min(32);
    out[32 - n..].copy_from_slice(&trimmed[trimmed.len() - n..]);
    out
}

/// Length-independent constant-time byte comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison for the phase-3 credential-activation secret.
///
/// CMIS compares the MIA-returned `secret` against the value it wrapped under
/// the EK; a match proves the AIK lives in the same TPM as the EK. The compare
/// must not leak position-of-difference timing, hence constant time.
#[must_use]
pub fn credential_secret_matches(expected: &[u8], got: &[u8]) -> bool {
    ct_eq(expected, got)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad32_left_pads_short_scalar() {
        let p = pad32(&[0xAB, 0xCD]);
        assert_eq!(p[30], 0xAB);
        assert_eq!(p[31], 0xCD);
        assert!(p[..30].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad32_trims_leading_zero_of_oversized() {
        let mut oversized = vec![0u8; 33];
        oversized[1] = 0xFF;
        let p = pad32(&oversized);
        assert_eq!(p[0], 0xFF);
    }

    #[test]
    fn credential_compare_is_value_correct() {
        assert!(credential_secret_matches(b"abc", b"abc"));
        assert!(!credential_secret_matches(b"abc", b"abd"));
        assert!(!credential_secret_matches(b"abc", b"ab"));
    }
}
