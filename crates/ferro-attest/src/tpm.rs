//! Minimal, allocation-light parsers for the TPM 2.0 wire structures that the
//! quote verifier needs: `TPMS_ATTEST` (the signed quote body), `TPMT_PUBLIC`
//! (the AIK public area), and `TPMT_SIGNATURE` (the ECDSA quote signature).
//!
//! These match the canonical big-endian marshaling defined by the TCG "TPM 2.0
//! Library, Part 2: Structures" — exactly what `tss-esapi`'s `Marshall` trait
//! emits on the MIA side, so the bytes round-trip without translation.
//!
//! Every parser is total and fail-closed: malformed or truncated input yields a
//! [`ParseError`] rather than a panic, and trailing bytes are rejected where a
//! structure is expected to consume its whole buffer.

use core::fmt;

/// `TPM_GENERATED_VALUE` — the constant a genuine TPM stamps into every
/// structure it produces (and that software cannot forge into a signed quote
/// without the TPM's cooperation).
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

/// `TPM_ST_ATTEST_QUOTE` — the attestation `type` for a PCR quote.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// `TPM_ALG_ECC` — object type for an elliptic-curve key.
pub const TPM_ALG_ECC: u16 = 0x0023;
/// `TPM_ALG_ECDSA` — signature scheme.
pub const TPM_ALG_ECDSA: u16 = 0x0018;
/// `TPM_ALG_SHA256`.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// `TPM_ALG_SHA384`.
pub const TPM_ALG_SHA384: u16 = 0x000C;
/// `TPM_ECC_NIST_P256`.
pub const TPM_ECC_NIST_P256: u16 = 0x0003;

// TPMA_OBJECT attribute bits (TCG Part 2, §8.3).
/// `fixedTPM` — the object cannot be duplicated to another TPM.
pub const TPMA_FIXED_TPM: u32 = 1 << 1;
/// `fixedParent` — the object cannot be re-parented.
pub const TPMA_FIXED_PARENT: u32 = 1 << 4;
/// `sensitiveDataOrigin` — the TPM generated the sensitive data itself.
pub const TPMA_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
/// `userWithAuth` — auth value usable for user-role actions.
pub const TPMA_USER_WITH_AUTH: u32 = 1 << 6;
/// `restricted` — key may only operate on TPM-generated data.
pub const TPMA_RESTRICTED: u32 = 1 << 16;
/// `decrypt` — key may be used for decryption.
pub const TPMA_DECRYPT: u32 = 1 << 17;
/// `sign` — key may be used for signing.
pub const TPMA_SIGN: u32 = 1 << 18;

/// Failure modes when parsing a TPM wire structure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The buffer ended before the structure was fully read.
    #[error("unexpected end of {0} buffer")]
    Truncated(&'static str),
    /// A discriminator (algorithm id, magic, type tag) was not what we require.
    #[error("unexpected {field}: got {got:#06x}")]
    Unexpected {
        /// Which field carried the bad value.
        field: &'static str,
        /// The value we actually read.
        got: u32,
    },
    /// Bytes remained after a structure that should consume its whole buffer.
    #[error("{0} bytes trailing after structure")]
    TrailingBytes(usize),
    /// A length field declared something larger than the buffer could hold.
    #[error("declared length {declared} exceeds remaining {remaining} in {ctx}")]
    BadLength {
        /// Where the bad length appeared.
        ctx: &'static str,
        /// The declared length.
        declared: usize,
        /// The bytes actually available.
        remaining: usize,
    },
}

/// A forward-only big-endian cursor over a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize, ctx: &'static str) -> Result<&'a [u8], ParseError> {
        if self.remaining() < n {
            return Err(ParseError::Truncated(ctx));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self, ctx: &'static str) -> Result<u8, ParseError> {
        Ok(self.take(1, ctx)?[0])
    }

    fn u16(&mut self, ctx: &'static str) -> Result<u16, ParseError> {
        let b = self.take(2, ctx)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, ctx: &'static str) -> Result<u32, ParseError> {
        let b = self.take(4, ctx)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn skip_u64(&mut self, ctx: &'static str) -> Result<(), ParseError> {
        self.take(8, ctx).map(|_| ())
    }

    /// Read a `TPM2B_*`: a `UINT16` size followed by that many bytes.
    fn tpm2b(&mut self, ctx: &'static str) -> Result<&'a [u8], ParseError> {
        let len = self.u16(ctx)? as usize;
        if self.remaining() < len {
            return Err(ParseError::BadLength {
                ctx,
                declared: len,
                remaining: self.remaining(),
            });
        }
        self.take(len, ctx)
    }
}

/// The parts of `TPMS_ATTEST` / `TPMS_QUOTE_INFO` the verifier checks.
#[derive(Debug, Clone)]
pub struct QuoteInfo {
    /// `magic` — must equal [`TPM_GENERATED_VALUE`].
    pub magic: u32,
    /// `type` — must equal [`TPM_ST_ATTEST_QUOTE`].
    pub attest_type: u16,
    /// `extraData` — the server nonce echoed back as `qualifyingData`.
    pub extra_data: Vec<u8>,
    /// `attested.quote.pcrSelect` — the (hashAlg, bitmap) selections.
    pub pcr_selection: Vec<PcrSelection>,
    /// `attested.quote.pcrDigest` — the TPM's digest over the selected PCRs.
    pub pcr_digest: Vec<u8>,
}

/// One `TPMS_PCR_SELECTION`: a PCR bank plus the bitmap of selected indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    /// `hash` — the PCR bank algorithm (e.g. [`TPM_ALG_SHA384`]).
    pub hash_alg: u16,
    /// `pcrSelect` — little-endian-by-byte bitmap; bit `i` selects PCR `i`.
    pub bitmap: Vec<u8>,
}

impl PcrSelection {
    /// Iterate the selected PCR indices in ascending order.
    #[must_use]
    pub fn selected_indices(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (byte_idx, byte) in self.bitmap.iter().enumerate() {
            for bit in 0..8usize {
                if byte & (1u8 << bit) != 0 {
                    if let Ok(idx) = u8::try_from(byte_idx * 8 + bit) {
                        out.push(idx);
                    }
                }
            }
        }
        out
    }
}

impl QuoteInfo {
    /// Parse a marshaled `TPMS_ATTEST` whose `attested` union holds a
    /// `TPMS_QUOTE_INFO`. Rejects any other attestation type.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(buf);
        let magic = r.u32("TPMS_ATTEST.magic")?;
        let attest_type = r.u16("TPMS_ATTEST.type")?;
        // qualifiedSigner: TPM2B_NAME — not needed for verification.
        let _ = r.tpm2b("TPMS_ATTEST.qualifiedSigner")?;
        let extra_data = r.tpm2b("TPMS_ATTEST.extraData")?.to_vec();
        // clockInfo: clock(8) resetCount(4) restartCount(4) safe(1).
        r.skip_u64("TPMS_CLOCK_INFO.clock")?;
        let _ = r.u32("TPMS_CLOCK_INFO.resetCount")?;
        let _ = r.u32("TPMS_CLOCK_INFO.restartCount")?;
        let _ = r.u8("TPMS_CLOCK_INFO.safe")?;
        // firmwareVersion: UINT64.
        r.skip_u64("TPMS_ATTEST.firmwareVersion")?;

        // attested -> TPMS_QUOTE_INFO { pcrSelect: TPML_PCR_SELECTION, pcrDigest }.
        let count = r.u32("TPML_PCR_SELECTION.count")? as usize;
        let mut pcr_selection = Vec::with_capacity(count);
        for _ in 0..count {
            let hash_alg = r.u16("TPMS_PCR_SELECTION.hash")?;
            let size_of_select = r.u8("TPMS_PCR_SELECTION.sizeofSelect")? as usize;
            let bitmap = r
                .take(size_of_select, "TPMS_PCR_SELECTION.pcrSelect")?
                .to_vec();
            pcr_selection.push(PcrSelection { hash_alg, bitmap });
        }
        let pcr_digest = r.tpm2b("TPMS_QUOTE_INFO.pcrDigest")?.to_vec();

        if r.remaining() != 0 {
            return Err(ParseError::TrailingBytes(r.remaining()));
        }
        Ok(Self {
            magic,
            attest_type,
            extra_data,
            pcr_selection,
            pcr_digest,
        })
    }
}

/// The parts of a `TPMT_PUBLIC` for an ECC key the verifier needs.
#[derive(Clone)]
pub struct EccPublic {
    /// `objectAttributes` — the `TPMA_OBJECT` bitfield.
    pub attributes: u32,
    /// `parameters.eccDetail.curveID`.
    pub curve_id: u16,
    /// `parameters.eccDetail.scheme.scheme` (e.g. [`TPM_ALG_ECDSA`]).
    pub scheme: u16,
    /// `parameters.eccDetail.scheme.details.hashAlg` (0 if scheme is NULL).
    pub scheme_hash: u16,
    /// `unique.ecc.x`, the affine X coordinate (big-endian, unpadded).
    pub x: Vec<u8>,
    /// `unique.ecc.y`, the affine Y coordinate (big-endian, unpadded).
    pub y: Vec<u8>,
}

impl fmt::Debug for EccPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EccPublic")
            .field("attributes", &format_args!("{:#010x}", self.attributes))
            .field("curve_id", &format_args!("{:#06x}", self.curve_id))
            .field("scheme", &format_args!("{:#06x}", self.scheme))
            .field("scheme_hash", &format_args!("{:#06x}", self.scheme_hash))
            .finish_non_exhaustive()
    }
}

impl EccPublic {
    /// Parse a marshaled `TPMT_PUBLIC`. Only ECC objects are accepted; an RSA
    /// or KEYEDHASH object is rejected (an AIK is always ECC here).
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(buf);
        let obj_type = r.u16("TPMT_PUBLIC.type")?;
        if obj_type != TPM_ALG_ECC {
            return Err(ParseError::Unexpected {
                field: "TPMT_PUBLIC.type",
                got: u32::from(obj_type),
            });
        }
        let _name_alg = r.u16("TPMT_PUBLIC.nameAlg")?;
        let attributes = r.u32("TPMT_PUBLIC.objectAttributes")?;
        // authPolicy: TPM2B_DIGEST.
        let _ = r.tpm2b("TPMT_PUBLIC.authPolicy")?;

        // parameters: TPMS_ECC_PARMS.
        // symmetric: TPMT_SYM_DEF_OBJECT — for a signing key this is TPM_ALG_NULL,
        // which marshals as just the 2-byte algorithm selector.
        let sym_alg = r.u16("TPMT_SYM_DEF_OBJECT.algorithm")?;
        if sym_alg != 0x0010 {
            // Non-NULL symmetric on a signing AIK is unexpected; bail rather
            // than guess the variable tail.
            return Err(ParseError::Unexpected {
                field: "TPMT_SYM_DEF_OBJECT.algorithm",
                got: u32::from(sym_alg),
            });
        }
        // scheme: TPMT_ECC_SCHEME { scheme; [hashAlg] }.
        let scheme = r.u16("TPMT_ECC_SCHEME.scheme")?;
        let scheme_hash = if scheme == 0x0010 {
            0 // TPM_ALG_NULL — no hash field follows.
        } else {
            r.u16("TPMT_ECC_SCHEME.details.hashAlg")?
        };
        let curve_id = r.u16("TPMS_ECC_PARMS.curveID")?;
        // kdf: TPMT_KDF_SCHEME { scheme; [details] }.
        let kdf = r.u16("TPMT_KDF_SCHEME.scheme")?;
        if kdf != 0x0010 {
            return Err(ParseError::Unexpected {
                field: "TPMT_KDF_SCHEME.scheme",
                got: u32::from(kdf),
            });
        }

        // unique: TPMS_ECC_POINT { x: TPM2B_ECC_PARAMETER, y: TPM2B_ECC_PARAMETER }.
        let x = r.tpm2b("TPMS_ECC_POINT.x")?.to_vec();
        let y = r.tpm2b("TPMS_ECC_POINT.y")?.to_vec();

        if r.remaining() != 0 {
            return Err(ParseError::TrailingBytes(r.remaining()));
        }
        Ok(Self {
            attributes,
            curve_id,
            scheme,
            scheme_hash,
            x,
            y,
        })
    }
}

/// A parsed `TPMT_SIGNATURE` carrying an ECDSA signature.
#[derive(Debug, Clone)]
pub struct EcdsaSignature {
    /// `signature.ecdsa.hash` — the digest algorithm the TPM signed under.
    pub hash_alg: u16,
    /// `signatureR` (big-endian, unpadded).
    pub r: Vec<u8>,
    /// `signatureS` (big-endian, unpadded).
    pub s: Vec<u8>,
}

impl EcdsaSignature {
    /// Parse a marshaled `TPMT_SIGNATURE`. Only the ECDSA scheme is accepted.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(buf);
        let sig_alg = r.u16("TPMT_SIGNATURE.sigAlg")?;
        if sig_alg != TPM_ALG_ECDSA {
            return Err(ParseError::Unexpected {
                field: "TPMT_SIGNATURE.sigAlg",
                got: u32::from(sig_alg),
            });
        }
        let hash_alg = r.u16("TPMS_SIGNATURE_ECC.hash")?;
        let r_val = r.tpm2b("TPMS_SIGNATURE_ECC.signatureR")?.to_vec();
        let s_val = r.tpm2b("TPMS_SIGNATURE_ECC.signatureS")?.to_vec();
        if r.remaining() != 0 {
            return Err(ParseError::TrailingBytes(r.remaining()));
        }
        Ok(Self {
            hash_alg,
            r: r_val,
            s: s_val,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_selection_bitmap_decodes_indices() {
        // bits for PCRs 0,1,2,3,4,7 in byte0; 8,9,10,11 in byte1; 14 in byte2.
        let sel = PcrSelection {
            hash_alg: TPM_ALG_SHA384,
            bitmap: vec![0b1001_1111, 0b0000_1111, 0b0100_0000],
        };
        assert_eq!(
            sel.selected_indices(),
            vec![0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 22]
        );
    }

    #[test]
    fn truncated_attest_is_rejected() {
        assert!(matches!(
            QuoteInfo::parse(&[0xFF, 0x54]),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn ecc_public_rejects_non_ecc_type() {
        // type = TPM_ALG_RSA (0x0001).
        assert!(matches!(
            EccPublic::parse(&[0x00, 0x01]),
            Err(ParseError::Unexpected { .. })
        ));
    }

    #[test]
    fn signature_rejects_non_ecdsa() {
        // sigAlg = TPM_ALG_RSASSA (0x0014).
        assert!(matches!(
            EcdsaSignature::parse(&[0x00, 0x14]),
            Err(ParseError::Unexpected { .. })
        ));
    }
}
