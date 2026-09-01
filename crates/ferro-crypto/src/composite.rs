//! Composite Ed25519 + ML-DSA-65 signatures for FerroGate (feature F03).
//!
//! Every identity-bearing artefact in FerroGate — SVIDs, STHs, CRL deltas,
//! child tokens, CMIS server certificates — carries a **composite**
//! signature: an Ed25519 signature *and* an ML-DSA-65 (FIPS 204)
//! signature over the same domain-separated message hash. Verification
//! requires **both** to succeed (AND-combiner), so a break in either
//! primitive alone does not forge.
//!
//! Both signatures cover the SAME 48-byte transcript hash:
//!
//! ```text
//! H = SHA3-384( "FERROGATE-COMPOSITE-v1"
//!               || len_be64(ctx)
//!               || ctx
//!               || msg )
//! ```
//!
//! The context string `ctx` provides domain separation between SVIDs,
//! STHs, child tokens, and CSR-bound material — see `docs/crypto.md`.
//!
//! ## Wire forms
//!
//! - **Concat bytes** — `classical(64) || pqc(3309)` = 3373 bytes.
//!   Used in JWS (base64url-without-padding).
//! - **DER** — `SEQUENCE { OID, OCTET STRING classical, OCTET STRING pqc }`
//!   with `algorithm = 2.16.840.1.114027.80.8.1.7`
//!   (id-composite-MLDSA65-Ed25519). Used in X.509 certificates.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode, Sequence};
use ed25519_dalek::Signer as _;
use ed25519_dalek::{SigningKey as EdSk, VerifyingKey as EdVk};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};
use rand_core::OsRng;
use sha3::{Digest, Sha3_256, Sha3_384};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// JOSE `alg` value for the composite signature.
pub const COMPOSITE_JOSE_ALG: &str = "MLDSA65+Ed25519";

/// ASN.1 OID `id-composite-MLDSA65-Ed25519`, draft-ietf-lamps-pq-composite-sigs.
pub const COMPOSITE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.7");

/// Domain-separation tag mixed into the transcript hash.
pub const DOMAIN_TAG: &[u8] = b"FERROGATE-COMPOSITE-v1";

/// Length of an Ed25519 public key (RFC 8032).
pub const ED25519_PK_LEN: usize = 32;
/// Length of an Ed25519 signature (RFC 8032).
pub const ED25519_SIG_LEN: usize = 64;

/// Length of an ML-DSA-65 public key (FIPS 204).
pub const MLDSA65_PK_LEN: usize = ml_dsa_65::PK_LEN;
/// Length of an ML-DSA-65 signature (FIPS 204).
pub const MLDSA65_SIG_LEN: usize = ml_dsa_65::SIG_LEN;

/// Length of the concat composite public key on the wire.
pub const COMPOSITE_PK_LEN: usize = ED25519_PK_LEN + MLDSA65_PK_LEN;
/// Length of the concat composite signature on the wire.
pub const COMPOSITE_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN;

/// Length of the [`transcript_hash`] output — the *only* message a composite
/// signature ever covers.
pub const TRANSCRIPT_HASH_LEN: usize = 48;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for composite-signature operations.
#[derive(Debug, thiserror::Error)]
pub enum CompositeError {
    /// The classical (Ed25519) component of a signature did not verify.
    #[error("classical signature did not verify")]
    ClassicalFailed,
    /// The PQC (ML-DSA-65) component of a signature did not verify.
    #[error("pqc signature did not verify")]
    PqcFailed,
    /// `fips204` returned an error during key generation.
    #[error("ML-DSA keygen failed: {0}")]
    KeyGen(&'static str),
    /// `fips204` returned an error during signing.
    #[error("ML-DSA sign failed: {0}")]
    Sign(&'static str),
    /// A serialized form failed to decode.
    #[error("malformed encoded form: {0}")]
    Decode(String),
    /// An encoder produced an error (extremely unusual).
    #[error("encoder failed: {0}")]
    Encode(String),
    /// An interop (standard-format) sign or verify was attempted over a message
    /// the length of a composite transcript hash. See
    /// [`CompositeSecretKey::sign_interop_ed25519`] for why the two message
    /// spaces are kept disjoint.
    #[error("interop signing refused: message is {0} bytes, the composite transcript-hash length")]
    InteropDomainCollision(usize),
    /// A PKCS#8 blob was not the RFC 8410 Ed25519 v1 form this crate emits.
    #[error("malformed Ed25519 PKCS#8: {0}")]
    Pkcs8(String),
}

// ---------------------------------------------------------------------------
// Transcript hashing
// ---------------------------------------------------------------------------

/// Compute the 48-byte transcript hash that both primitives sign.
#[must_use]
pub fn transcript_hash(ctx: &[u8], msg: &[u8]) -> [u8; 48] {
    let mut h = Sha3_384::new();
    h.update(DOMAIN_TAG);
    // Length-prefix the context so different (ctx, msg) pairs cannot
    // collide by being rearranged.
    let ctx_len: u64 = ctx.len() as u64;
    h.update(ctx_len.to_be_bytes());
    h.update(ctx);
    h.update(msg);
    let out = h.finalize();
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&out);
    arr
}

/// Derive a 32-byte sub-seed from a master seed and a domain tag.
/// Used by [`CompositeSecretKey::from_seed`] to key the two halves
/// independently.
fn derive_subseed(seed: &[u8; 32], tag: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(tag);
    h.update(seed);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Reject a message that could be a composite transcript hash.
///
/// Composite signatures always cover exactly [`TRANSCRIPT_HASH_LEN`] bytes, so
/// refusing that one length in the interop (raw) path makes the two message
/// spaces disjoint by construction.
fn reject_transcript_sized(msg: &[u8]) -> Result<(), CompositeError> {
    if msg.len() == TRANSCRIPT_HASH_LEN {
        return Err(CompositeError::InteropDomainCollision(msg.len()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ed25519 PKCS#8 (RFC 8410 §7)
// ---------------------------------------------------------------------------

/// The fixed DER prefix of a PKCS#8 v1 `OneAsymmetricKey` wrapping an Ed25519
/// seed, per RFC 8410 §7: `SEQUENCE { INTEGER 0, AlgorithmIdentifier
/// { id-Ed25519 }, OCTET STRING { OCTET STRING seed } }`. Everything before the
/// 32-byte seed is constant, so the whole encoding is this prefix plus the seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Total length of the PKCS#8 v1 encoding of an Ed25519 private key.
pub const ED25519_PKCS8_LEN: usize = ED25519_PKCS8_PREFIX.len() + ED25519_PK_LEN;

/// Wrap a raw Ed25519 seed as PKCS#8 v1 DER.
///
/// This is the format TLS stacks load a private key from, so it is how an
/// X.509-SVID's key reaches a workload.
#[must_use]
pub fn ed25519_pkcs8_from_seed(seed: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut der = Vec::with_capacity(ED25519_PKCS8_LEN);
    der.extend_from_slice(&ED25519_PKCS8_PREFIX);
    der.extend_from_slice(seed);
    Zeroizing::new(der)
}

/// Recover the public key of a PKCS#8 v1 Ed25519 private key, without exposing
/// the private half.
///
/// A store that holds a certificate and its key uses this to prove the two
/// belong together before trusting either.
pub fn ed25519_public_from_pkcs8(der: &[u8]) -> Result<[u8; ED25519_PK_LEN], CompositeError> {
    if der.len() != ED25519_PKCS8_LEN {
        return Err(CompositeError::Pkcs8(format!(
            "expected {ED25519_PKCS8_LEN} bytes, got {}",
            der.len()
        )));
    }
    if der[..ED25519_PKCS8_PREFIX.len()] != ED25519_PKCS8_PREFIX {
        return Err(CompositeError::Pkcs8(
            "not an RFC 8410 Ed25519 PKCS#8 v1 header".to_string(),
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&der[ED25519_PKCS8_PREFIX.len()..]);
    Ok(EdSk::from_bytes(&seed).verifying_key().to_bytes())
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

/// Composite public key (Ed25519 || ML-DSA-65).
#[derive(Clone)]
pub struct CompositePublicKey {
    ed25519: EdVk,
    mldsa65: ml_dsa_65::PublicKey,
}

/// Composite secret key (Ed25519 || ML-DSA-65).
///
/// Both halves are kept private and never serialized in the FerroGate
/// surface. `ed25519_dalek::SigningKey` zeroizes on drop; the ML-DSA
/// private key is held opaque by `fips204` which does the same.
pub struct CompositeSecretKey {
    ed25519: EdSk,
    mldsa65: ml_dsa_65::PrivateKey,
}

impl CompositePublicKey {
    /// Build a composite public key from its two parts.
    #[must_use]
    pub const fn from_parts(ed25519: EdVk, mldsa65: ml_dsa_65::PublicKey) -> Self {
        Self { ed25519, mldsa65 }
    }

    /// Borrow the classical (Ed25519) half.
    #[must_use]
    pub const fn ed25519(&self) -> &EdVk {
        &self.ed25519
    }

    /// Borrow the PQC (ML-DSA-65) half.
    #[must_use]
    pub const fn mldsa65(&self) -> &ml_dsa_65::PublicKey {
        &self.mldsa65
    }

    /// Encode the public key as `ed25519(32) || mldsa65(1952)`.
    #[must_use]
    pub fn to_concat_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COMPOSITE_PK_LEN);
        out.extend_from_slice(self.ed25519.as_bytes());
        out.extend_from_slice(&self.mldsa65.clone().into_bytes());
        out
    }

    /// Parse a public key from `ed25519(32) || mldsa65(1952)`.
    pub fn from_concat_bytes(bytes: &[u8]) -> Result<Self, CompositeError> {
        if bytes.len() != COMPOSITE_PK_LEN {
            return Err(CompositeError::Decode(format!(
                "composite public key must be {COMPOSITE_PK_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut ed_arr = [0u8; ED25519_PK_LEN];
        ed_arr.copy_from_slice(&bytes[..ED25519_PK_LEN]);
        let classical_vk = EdVk::from_bytes(&ed_arr)
            .map_err(|e| CompositeError::Decode(format!("ed25519 pk: {e}")))?;
        let mut pqc_arr = [0u8; MLDSA65_PK_LEN];
        pqc_arr.copy_from_slice(&bytes[ED25519_PK_LEN..]);
        let pqc_public = ml_dsa_65::PublicKey::try_from_bytes(pqc_arr)
            .map_err(|e| CompositeError::Decode(format!("ml-dsa-65 pk: {e}")))?;
        Ok(Self {
            ed25519: classical_vk,
            mldsa65: pqc_public,
        })
    }

    /// Verify a composite signature under this public key.
    ///
    /// Both the classical and the PQC half must verify; the AND-combiner
    /// is intentional. Returns `Ok(())` only when both succeed.
    pub fn verify(
        &self,
        ctx: &[u8],
        msg: &[u8],
        sig: &CompositeSignature,
    ) -> Result<(), CompositeError> {
        let h = transcript_hash(ctx, msg);

        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.classical);
        // `verify_strict` rejects non-canonical encodings and small-order
        // public keys; we want that.
        self.ed25519
            .verify_strict(&h, &ed_sig)
            .map_err(|_| CompositeError::ClassicalFailed)?;

        if sig.pqc.len() != MLDSA65_SIG_LEN {
            return Err(CompositeError::PqcFailed);
        }
        let mut pqc_arr = [0u8; MLDSA65_SIG_LEN];
        pqc_arr.copy_from_slice(&sig.pqc);
        if !self.mldsa65.verify(&h, &pqc_arr, &[]) {
            return Err(CompositeError::PqcFailed);
        }
        Ok(())
    }

    /// Verify a **standard-format** RFC 8032 Ed25519 signature over `msg`.
    ///
    /// The counterpart to [`CompositeSecretKey::sign_interop_ed25519`]; see that
    /// method for why interoperable artefacts sign the message directly rather
    /// than the composite transcript hash.
    pub fn verify_interop_ed25519(
        &self,
        msg: &[u8],
        sig: &[u8; ED25519_SIG_LEN],
    ) -> Result<(), CompositeError> {
        reject_transcript_sized(msg)?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(sig);
        self.ed25519
            .verify_strict(msg, &ed_sig)
            .map_err(|_| CompositeError::ClassicalFailed)
    }

    /// Verify a **standard-format** FIPS-204 ML-DSA-65 signature over `msg`
    /// under the FIPS-204 context string `ctx`.
    ///
    /// The counterpart to [`CompositeSecretKey::sign_interop_mldsa65`].
    pub fn verify_interop_mldsa65(
        &self,
        ctx: &[u8],
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), CompositeError> {
        reject_transcript_sized(msg)?;
        if sig.len() != MLDSA65_SIG_LEN {
            return Err(CompositeError::PqcFailed);
        }
        let mut arr = [0u8; MLDSA65_SIG_LEN];
        arr.copy_from_slice(sig);
        if !self.mldsa65.verify(msg, &arr, ctx) {
            return Err(CompositeError::PqcFailed);
        }
        Ok(())
    }
}

impl core::fmt::Debug for CompositePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompositePublicKey")
            .field("ed25519", &"<32 bytes>")
            .field("mldsa65", &"<1952 bytes>")
            .finish()
    }
}

impl CompositeSecretKey {
    /// Generate a fresh composite keypair using the OS RNG.
    #[allow(clippy::similar_names)] // sk/vk is the established Ed25519 convention.
    pub fn generate() -> Result<(Self, CompositePublicKey), CompositeError> {
        let classical_sk = EdSk::generate(&mut OsRng);
        let classical_vk = classical_sk.verifying_key();
        let (pqc_public, pqc_secret) = ml_dsa_65::try_keygen().map_err(CompositeError::KeyGen)?;
        let sk = Self {
            ed25519: classical_sk,
            mldsa65: pqc_secret,
        };
        let pk = CompositePublicKey {
            ed25519: classical_vk,
            mldsa65: pqc_public,
        };
        Ok((sk, pk))
    }

    /// Derive a composite keypair **deterministically** from a 32-byte master
    /// seed.
    ///
    /// The same seed always yields the same keypair, so an operator who holds
    /// the seed offline can reproduce a publisher key across machines without
    /// ever writing the expanded private key to disk — only the 32-byte seed
    /// is secret material at rest. This backs the F13 fleet-manifest signing
    /// tool; production root-key handling (sealing / Shamir split) is the F14
    /// ceremony's job.
    ///
    /// The two halves are keyed from **independent** sub-seeds derived by
    /// SHA3-256 over the master seed with distinct domain tags, so a weakness
    /// in one keygen cannot leak the other half's seed.
    #[must_use]
    #[allow(clippy::similar_names)] // sk/vk is the established Ed25519 convention.
    pub fn from_seed(seed: &[u8; 32]) -> (Self, CompositePublicKey) {
        let ed_seed = derive_subseed(seed, b"ferrogate-composite-seed/ed25519");
        let ml_seed = derive_subseed(seed, b"ferrogate-composite-seed/ml-dsa-65");

        let classical_sk = EdSk::from_bytes(&ed_seed);
        let classical_vk = classical_sk.verifying_key();
        let (pqc_public, pqc_secret) =
            <ml_dsa_65::KG as fips204::traits::KeyGen>::keygen_from_seed(&ml_seed);

        let sk = Self {
            ed25519: classical_sk,
            mldsa65: pqc_secret,
        };
        let pk = CompositePublicKey {
            ed25519: classical_vk,
            mldsa65: pqc_public,
        };
        (sk, pk)
    }

    /// Sign `msg` under domain-separation context `ctx`.
    pub fn sign(&self, ctx: &[u8], msg: &[u8]) -> Result<CompositeSignature, CompositeError> {
        let h = transcript_hash(ctx, msg);

        let classical = self.ed25519.sign(&h).to_bytes();
        let pqc_arr = self
            .mldsa65
            .try_sign(&h, &[])
            .map_err(CompositeError::Sign)?;
        Ok(CompositeSignature {
            classical,
            pqc: pqc_arr.to_vec(),
        })
    }

    /// Export the **Ed25519 half** as PKCS#8 v1 DER (RFC 8410 §7).
    ///
    /// ## This hands out private key material
    ///
    /// Everything else in this type keeps the private key inside; this does not.
    /// It exists for one reason: an X.509-SVID names the Ed25519 half as its
    /// subject public key, and a TLS stack cannot use the certificate without
    /// the matching private key in a format it understands. Anything that calls
    /// this is responsible for what happens to the bytes — MIA seals them under
    /// a TPM- or machine-bound key and never writes them out in the clear.
    ///
    /// The ML-DSA-65 half is **not** exported: it is not needed to use the
    /// certificate, and leaving it here keeps the blast radius to the classical
    /// key alone. The returned buffer zeroes itself on drop.
    #[must_use]
    pub fn to_ed25519_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let seed = Zeroizing::new(self.ed25519.to_bytes());
        ed25519_pkcs8_from_seed(&seed)
    }

    /// Sign `msg` as a **standard-format** RFC 8032 Ed25519 signature: the raw
    /// message, with no FerroGate transcript hash and no context string.
    ///
    /// This exists for artefacts a third party must be able to verify with an
    /// off-the-shelf stack. The hybrid X.509-SVID profile
    /// (`ferro_svid::x509`) signs its `TBSCertificate` this way so rustls,
    /// OpenSSL, or Envoy validate the chain unaided, and carries the ML-DSA-65
    /// half of the same logical signature in a certificate extension.
    ///
    /// ## Domain separation
    ///
    /// Every *composite* signature this key produces covers exactly one thing:
    /// the [`TRANSCRIPT_HASH_LEN`]-byte [`transcript_hash`] output. Interop
    /// signing therefore refuses a message of that length, keeping the two
    /// message spaces disjoint so an interop signature can never be replayed as
    /// a composite one, or the reverse.
    pub fn sign_interop_ed25519(
        &self,
        msg: &[u8],
    ) -> Result<[u8; ED25519_SIG_LEN], CompositeError> {
        reject_transcript_sized(msg)?;
        Ok(self.ed25519.sign(msg).to_bytes())
    }

    /// Sign `msg` as a **standard-format** FIPS-204 ML-DSA-65 signature under
    /// the FIPS-204 context string `ctx`.
    ///
    /// The PQ half of the hybrid X.509-SVID signature. `ctx` carries the domain
    /// separation the composite transcript would otherwise provide, and the
    /// same length guard as [`Self::sign_interop_ed25519`] applies.
    pub fn sign_interop_mldsa65(&self, ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>, CompositeError> {
        reject_transcript_sized(msg)?;
        let sig = self
            .mldsa65
            .try_sign(msg, ctx)
            .map_err(CompositeError::Sign)?;
        Ok(sig.to_vec())
    }

    /// As [`Self::sign_interop_mldsa65`], but using FIPS-204's **deterministic**
    /// variant: the hedging value `rnd` is all-zero, so the same key and message
    /// always produce the same signature.
    ///
    /// FIPS 204 §3.4 approves both the hedged (default, randomised) and the
    /// deterministic variant. Hedged is the better default — it is more robust
    /// against fault and side-channel attacks — so this is reserved for the one
    /// artefact whose bytes must be reproducible: the X.509-SVID trust bundle,
    /// which every CMIS replica sharing an issuer seed has to publish
    /// identically. Never reach for it to make a *leaf* credential reproducible.
    pub fn sign_interop_mldsa65_deterministic(
        &self,
        ctx: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, CompositeError> {
        reject_transcript_sized(msg)?;
        let sig = self
            .mldsa65
            .try_sign_with_seed(&[0u8; 32], msg, ctx)
            .map_err(CompositeError::Sign)?;
        Ok(sig.to_vec())
    }
}

impl core::fmt::Debug for CompositeSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material — not even a prefix.
        f.write_str("CompositeSecretKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Signature type
// ---------------------------------------------------------------------------

/// Composite signature value.
#[derive(Clone, PartialEq, Eq)]
pub struct CompositeSignature {
    /// Ed25519 signature, 64 bytes.
    pub classical: [u8; ED25519_SIG_LEN],
    /// ML-DSA-65 signature, [`MLDSA65_SIG_LEN`] bytes.
    pub pqc: Vec<u8>,
}

impl CompositeSignature {
    /// Encode as `classical(64) || pqc(3309)`.
    #[must_use]
    pub fn to_concat_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COMPOSITE_SIG_LEN);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.pqc);
        out
    }

    /// Decode `classical(64) || pqc(3309)`.
    pub fn from_concat_bytes(bytes: &[u8]) -> Result<Self, CompositeError> {
        if bytes.len() != COMPOSITE_SIG_LEN {
            return Err(CompositeError::Decode(format!(
                "composite signature must be {COMPOSITE_SIG_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut classical = [0u8; ED25519_SIG_LEN];
        classical.copy_from_slice(&bytes[..ED25519_SIG_LEN]);
        let pqc = bytes[ED25519_SIG_LEN..].to_vec();
        Ok(Self { classical, pqc })
    }

    /// Encode as ASN.1 DER `SEQUENCE { OID, OCTET STRING, OCTET STRING }`.
    pub fn to_der(&self) -> Result<Vec<u8>, CompositeError> {
        let asn = CompositeSigAsn {
            algorithm: COMPOSITE_OID,
            classical: OctetString::new(self.classical.to_vec())
                .map_err(|e| CompositeError::Encode(e.to_string()))?,
            pqc: OctetString::new(self.pqc.clone())
                .map_err(|e| CompositeError::Encode(e.to_string()))?,
        };
        asn.to_der()
            .map_err(|e| CompositeError::Encode(e.to_string()))
    }

    /// Decode ASN.1 DER `SEQUENCE { OID, OCTET STRING, OCTET STRING }`.
    pub fn from_der(der: &[u8]) -> Result<Self, CompositeError> {
        let asn = CompositeSigAsn::from_der(der)
            .map_err(|e| CompositeError::Decode(format!("der: {e}")))?;
        if asn.algorithm != COMPOSITE_OID {
            return Err(CompositeError::Decode(format!(
                "unexpected algorithm OID: {}",
                asn.algorithm
            )));
        }
        if asn.classical.as_bytes().len() != ED25519_SIG_LEN {
            return Err(CompositeError::Decode(format!(
                "classical OCTET STRING must be {ED25519_SIG_LEN} bytes"
            )));
        }
        if asn.pqc.as_bytes().len() != MLDSA65_SIG_LEN {
            return Err(CompositeError::Decode(format!(
                "pqc OCTET STRING must be {MLDSA65_SIG_LEN} bytes"
            )));
        }
        let mut classical = [0u8; ED25519_SIG_LEN];
        classical.copy_from_slice(asn.classical.as_bytes());
        Ok(Self {
            classical,
            pqc: asn.pqc.as_bytes().to_vec(),
        })
    }

    /// Encode for JOSE / JWS as base64url-without-padding of the concat form.
    #[must_use]
    pub fn to_jws_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.to_concat_bytes())
    }

    /// Decode from base64url-without-padding JWS form.
    pub fn from_jws_base64url(s: &str) -> Result<Self, CompositeError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| CompositeError::Decode(format!("base64url: {e}")))?;
        Self::from_concat_bytes(&bytes)
    }
}

impl core::fmt::Debug for CompositeSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompositeSignature")
            .field("classical_len", &self.classical.len())
            .field("pqc_len", &self.pqc.len())
            .finish()
    }
}

/// ASN.1 representation for DER encoding/decoding.
#[derive(Debug, Sequence)]
struct CompositeSigAsn {
    algorithm: ObjectIdentifier,
    classical: OctetString,
    pqc: OctetString,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> &'static [u8] {
        b"ferrogate-svid-v1"
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let sig = sk.sign(ctx(), b"hello world").unwrap();
        pk.verify(ctx(), b"hello world", &sig).expect("verify ok");
    }

    #[test]
    fn from_seed_is_deterministic_and_usable() {
        let seed = [7u8; 32];
        let (sk_a, pk_a) = CompositeSecretKey::from_seed(&seed);
        let (_sk_b, pk_b) = CompositeSecretKey::from_seed(&seed);
        // Same seed ⇒ identical public key on the wire.
        assert_eq!(pk_a.to_concat_bytes(), pk_b.to_concat_bytes());
        // A signature from one derivation verifies under the other's pubkey.
        let sig = sk_a.sign(ctx(), b"manifest").unwrap();
        pk_b.verify(ctx(), b"manifest", &sig).expect("verify ok");
    }

    #[test]
    fn from_seed_differs_by_seed() {
        let (_sk_a, pk_a) = CompositeSecretKey::from_seed(&[1u8; 32]);
        let (_sk_b, pk_b) = CompositeSecretKey::from_seed(&[2u8; 32]);
        assert_ne!(pk_a.to_concat_bytes(), pk_b.to_concat_bytes());
    }

    #[test]
    fn signature_has_expected_lengths() {
        let (sk, _pk) = CompositeSecretKey::generate().unwrap();
        let sig = sk.sign(ctx(), b"any").unwrap();
        assert_eq!(sig.classical.len(), ED25519_SIG_LEN);
        assert_eq!(sig.pqc.len(), MLDSA65_SIG_LEN);
        assert_eq!(sig.to_concat_bytes().len(), COMPOSITE_SIG_LEN);
    }

    #[test]
    fn changing_message_breaks_verify() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let sig = sk.sign(ctx(), b"original").unwrap();
        // Different message must fail one of the two halves (both, in fact).
        let res = pk.verify(ctx(), b"tampered", &sig);
        assert!(res.is_err());
    }

    #[test]
    fn changing_context_breaks_verify() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let sig = sk.sign(b"ctx-a", b"msg").unwrap();
        assert!(pk.verify(b"ctx-b", b"msg", &sig).is_err());
    }

    #[test]
    fn flipping_classical_byte_breaks_verify_with_classical_error() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let mut sig = sk.sign(ctx(), b"msg").unwrap();
        sig.classical[0] ^= 0x01;
        let err = pk.verify(ctx(), b"msg", &sig).unwrap_err();
        assert!(matches!(err, CompositeError::ClassicalFailed));
    }

    #[test]
    fn flipping_pqc_byte_breaks_verify_with_pqc_error() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let mut sig = sk.sign(ctx(), b"msg").unwrap();
        // ML-DSA verify checks the whole signature; flip a byte near the
        // start to be sure we land inside its signing payload.
        sig.pqc[0] ^= 0x01;
        let err = pk.verify(ctx(), b"msg", &sig).unwrap_err();
        assert!(matches!(err, CompositeError::PqcFailed));
    }

    #[test]
    fn truncated_pqc_is_rejected_as_pqc_failure() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let mut sig = sk.sign(ctx(), b"msg").unwrap();
        sig.pqc.truncate(MLDSA65_SIG_LEN - 1);
        assert!(matches!(
            pk.verify(ctx(), b"msg", &sig),
            Err(CompositeError::PqcFailed)
        ));
    }

    #[test]
    fn concat_bytes_roundtrip() {
        let (sk, _) = CompositeSecretKey::generate().unwrap();
        let sig = sk.sign(ctx(), b"msg").unwrap();
        let bytes = sig.to_concat_bytes();
        let back = CompositeSignature::from_concat_bytes(&bytes).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn der_roundtrip_preserves_signature() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let sig = sk.sign(ctx(), b"hello").unwrap();
        let der_bytes = sig.to_der().unwrap();
        let back = CompositeSignature::from_der(&der_bytes).unwrap();
        assert_eq!(sig, back);
        pk.verify(ctx(), b"hello", &back).unwrap();
    }

    #[test]
    fn der_rejects_wrong_oid() {
        // Build a SEQUENCE that uses a different (but valid) OID.
        let bogus = CompositeSigAsn {
            algorithm: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), // ecdsa-with-SHA384
            classical: OctetString::new(vec![0u8; ED25519_SIG_LEN]).unwrap(),
            pqc: OctetString::new(vec![0u8; MLDSA65_SIG_LEN]).unwrap(),
        };
        let der_bytes = bogus.to_der().unwrap();
        let err = CompositeSignature::from_der(&der_bytes).unwrap_err();
        assert!(matches!(err, CompositeError::Decode(_)));
    }

    #[test]
    fn jws_base64url_roundtrip() {
        let (sk, _) = CompositeSecretKey::generate().unwrap();
        let sig = sk.sign(ctx(), b"jose").unwrap();
        let s = sig.to_jws_base64url();
        // No padding character; URL-safe alphabet only.
        assert!(!s.contains('='));
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let back = CompositeSignature::from_jws_base64url(&s).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn public_key_concat_roundtrip() {
        let (_, pk) = CompositeSecretKey::generate().unwrap();
        let bytes = pk.to_concat_bytes();
        assert_eq!(bytes.len(), COMPOSITE_PK_LEN);
        let back = CompositePublicKey::from_concat_bytes(&bytes).unwrap();
        assert_eq!(back.to_concat_bytes(), bytes);
    }

    #[test]
    fn public_key_concat_rejects_wrong_length() {
        assert!(matches!(
            CompositePublicKey::from_concat_bytes(&[0u8; 64]),
            Err(CompositeError::Decode(_))
        ));
    }

    #[test]
    fn transcript_hash_is_length_prefixed() {
        // (ctx="a", msg="bc") MUST hash differently to (ctx="ab", msg="c"),
        // even though the concatenation ctx||msg is identical. This is the
        // whole point of the length prefix.
        let h1 = transcript_hash(b"a", b"bc");
        let h2 = transcript_hash(b"ab", b"c");
        assert_ne!(h1, h2);
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let (sk, _) = CompositeSecretKey::generate().unwrap();
        let s = format!("{sk:?}");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn oid_string_matches_design_doc() {
        assert_eq!(COMPOSITE_OID.to_string(), "2.16.840.1.114027.80.8.1.7");
    }

    #[test]
    fn jose_alg_matches_design_doc() {
        assert_eq!(COMPOSITE_JOSE_ALG, "MLDSA65+Ed25519");
    }

    // --- Ed25519 PKCS#8 export --------------------------------------------

    #[test]
    fn exported_pkcs8_matches_the_certificate_subject_key() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let der = sk.to_ed25519_pkcs8_der();

        assert_eq!(der.len(), ED25519_PKCS8_LEN);
        // The public key recovered from the export is the one an X.509-SVID
        // carries in its SubjectPublicKeyInfo.
        assert_eq!(
            ed25519_public_from_pkcs8(&der).unwrap(),
            pk.ed25519().to_bytes(),
        );
    }

    #[test]
    fn exported_pkcs8_loads_in_a_stock_tls_stack() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let der = sk.to_ed25519_pkcs8_der();

        // ring is what rustls uses to load a private key; if it accepts this
        // blob and its signature verifies under the certificate's subject key,
        // the exported key is usable for mTLS.
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
            .expect("a stock PKCS#8 loader accepts the export");
        let msg = b"handshake transcript";
        let sig = ring::signature::KeyPair::public_key(&pair);
        assert_eq!(sig.as_ref(), pk.ed25519().as_bytes());

        let signature = pair.sign(msg);
        pk.verify_interop_ed25519(msg, &signature.as_ref().try_into().unwrap())
            .expect("a signature from the exported key verifies under the subject key");
    }

    #[test]
    fn malformed_pkcs8_is_rejected() {
        let (sk, _) = CompositeSecretKey::generate().unwrap();
        let der = sk.to_ed25519_pkcs8_der();

        assert!(matches!(
            ed25519_public_from_pkcs8(&der[..40]),
            Err(CompositeError::Pkcs8(_))
        ));
        let mut wrong = der.to_vec();
        wrong[5] ^= 0xff; // corrupt the AlgorithmIdentifier
        assert!(matches!(
            ed25519_public_from_pkcs8(&wrong),
            Err(CompositeError::Pkcs8(_))
        ));
    }

    // --- interop (standard-format) signatures ------------------------------

    #[test]
    fn interop_ed25519_verifies_under_a_stock_verifier() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let msg = b"not a transcript hash, just some TBSCertificate-ish bytes";
        let sig = sk.sign_interop_ed25519(msg).unwrap();

        pk.verify_interop_ed25519(msg, &sig).unwrap();

        // The point of the interop path: a verifier that knows nothing about
        // FerroGate — here ed25519-dalek used directly, exactly as rustls or
        // OpenSSL would — validates the same bytes.
        let stock_sig = ed25519_dalek::Signature::from_bytes(&sig);
        pk.ed25519()
            .verify_strict(msg, &stock_sig)
            .expect("a stock RFC 8032 verifier accepts the interop signature");
    }

    #[test]
    fn interop_mldsa65_roundtrips_and_is_context_bound() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let msg = b"some certificate body bytes";
        let sig = sk.sign_interop_mldsa65(b"ctx-a", msg).unwrap();

        pk.verify_interop_mldsa65(b"ctx-a", msg, &sig).unwrap();
        assert!(pk.verify_interop_mldsa65(b"ctx-b", msg, &sig).is_err());
        assert!(pk.verify_interop_mldsa65(b"ctx-a", b"other", &sig).is_err());
    }

    #[test]
    fn deterministic_mldsa65_is_reproducible_and_hedged_is_not() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let msg = b"a trust bundle body";

        let a = sk.sign_interop_mldsa65_deterministic(b"ctx", msg).unwrap();
        let b = sk.sign_interop_mldsa65_deterministic(b"ctx", msg).unwrap();
        assert_eq!(a, b, "the deterministic variant must be byte-stable");
        pk.verify_interop_mldsa65(b"ctx", msg, &a).unwrap();

        let h1 = sk.sign_interop_mldsa65(b"ctx", msg).unwrap();
        let h2 = sk.sign_interop_mldsa65(b"ctx", msg).unwrap();
        assert_ne!(h1, h2, "the default variant is hedged, so it varies");
        pk.verify_interop_mldsa65(b"ctx", msg, &h1).unwrap();
    }

    #[test]
    fn interop_signing_refuses_transcript_sized_messages() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        // A composite signature covers exactly this message space; the interop
        // path must not overlap it, in either direction.
        let h = transcript_hash(ctx(), b"payload");
        assert!(matches!(
            sk.sign_interop_ed25519(&h),
            Err(CompositeError::InteropDomainCollision(48))
        ));
        assert!(matches!(
            sk.sign_interop_mldsa65(b"any", &h),
            Err(CompositeError::InteropDomainCollision(48))
        ));

        // And the classical half of a real composite signature cannot be
        // re-presented as a valid interop signature over the transcript hash.
        let composite = sk.sign(ctx(), b"payload").unwrap();
        assert!(matches!(
            pk.verify_interop_ed25519(&h, &composite.classical),
            Err(CompositeError::InteropDomainCollision(48))
        ));
    }
}
