//! Signed Tree Heads (STHs).
//!
//! An STH publishes the state of the audit log at a point in time:
//! `{ tree_size, root_hash, timestamp }`. The body is encoded as canonical
//! CBOR, then composite-signed (Ed25519 + ML-DSA-65, see [`ferro_crypto`])
//! under the domain-separation context [`STH_SIGNING_CONTEXT`]. The on-wire
//! [`SignedTreeHead`] carries the CBOR body verbatim alongside the signature
//! so verifiers reproduce exactly the bytes the signer covered without
//! re-encoding from a struct.
//!
//! The signer is abstracted behind [`SthSigner`]. The M3 in-process
//! implementation ([`InProcessSigner`]) is the documented stub; the M4
//! threshold/TEE-resident signer slots in behind the same trait.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::{
    CompositeError, CompositePublicKey, CompositeSecretKey, CompositeSignature,
};
use serde::{Deserialize, Serialize};

use crate::bytes::Hash384;

/// Domain-separation context for STH signatures.
pub const STH_SIGNING_CONTEXT: &[u8] = b"ferrogate-sth-v1";

/// The signed body. Anything not in this struct is not authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SthBody {
    /// Number of leaves in the tree when this STH was produced.
    pub tree_size: u64,
    /// Root hash of the Merkle tree (SHA3-384).
    pub root_hash: Hash384,
    /// Issuance Unix seconds.
    pub timestamp: i64,
}

/// A complete signed tree head. `body_cbor` is the exact bytes the signature
/// covers; verifiers re-decode to inspect fields and re-verify by feeding
/// `body_cbor` to [`CompositePublicKey::verify`] under [`STH_SIGNING_CONTEXT`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Canonical CBOR encoding of an [`SthBody`].
    pub body_cbor: Vec<u8>,
    /// Key id selecting the verification key.
    pub signer_kid: String,
    /// base64url of the concatenated composite signature.
    pub signature_b64: String,
}

impl SignedTreeHead {
    /// Decode the embedded [`SthBody`]. This does **not** verify the
    /// signature; callers should always pair it with [`verify_sth`].
    pub fn body(&self) -> Result<SthBody, SthError> {
        ciborium::from_reader(self.body_cbor.as_slice())
            .map_err(|e| SthError::Decode(e.to_string()))
    }
}

/// Failure modes for STH signing / verification.
#[derive(Debug, thiserror::Error)]
pub enum SthError {
    /// CBOR encoding of the body failed (very unlikely).
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding of the body failed.
    #[error("cbor decode: {0}")]
    Decode(String),
    /// The composite signer failed.
    #[error("composite: {0}")]
    Composite(#[from] CompositeError),
    /// The base64url of the signature did not decode.
    #[error("signature base64: {0}")]
    SignatureB64(String),
    /// The signature did not verify.
    #[error("signature invalid")]
    SignatureInvalid,
}

/// Encode an [`SthBody`] to canonical CBOR.
pub fn encode_body(body: &SthBody) -> Result<Vec<u8>, SthError> {
    let mut out = Vec::with_capacity(96);
    ciborium::into_writer(body, &mut out).map_err(|e| SthError::Encode(e.to_string()))?;
    Ok(out)
}

/// Produce an [`SthBody`]-only signature value (handy for tests).
pub fn sign_body(body: &SthBody, sk: &CompositeSecretKey) -> Result<CompositeSignature, SthError> {
    let bytes = encode_body(body)?;
    Ok(sk.sign(STH_SIGNING_CONTEXT, &bytes)?)
}

/// Verify a [`SignedTreeHead`] under `pk`. On success returns the decoded body
/// (already authenticated).
pub fn verify_sth(sth: &SignedTreeHead, pk: &CompositePublicKey) -> Result<SthBody, SthError> {
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sth.signature_b64.as_bytes())
        .map_err(|e| SthError::SignatureB64(e.to_string()))?;
    let sig = CompositeSignature::from_concat_bytes(&sig_bytes)
        .map_err(|_| SthError::SignatureInvalid)?;
    pk.verify(STH_SIGNING_CONTEXT, &sth.body_cbor, &sig)
        .map_err(|_| SthError::SignatureInvalid)?;
    sth.body()
}

/// Signers of STHs. Production deployments will use a TEE-resident threshold
/// signer (M4); the [`InProcessSigner`] below is the documented M3 stub.
pub trait SthSigner: Send + Sync {
    /// Sign `body` and produce the on-wire [`SignedTreeHead`].
    fn sign(&self, body: SthBody) -> Result<SignedTreeHead, SthError>;
    /// The publisher key id this signer stamps into each STH.
    fn kid(&self) -> &str;
}

/// In-process composite signer. Holds the private key in memory; only
/// appropriate for development and the M3 single-replica configuration.
pub struct InProcessSigner {
    kid: String,
    sk: CompositeSecretKey,
}

impl InProcessSigner {
    /// Build an in-process signer from an existing keypair.
    #[must_use]
    pub fn new(kid: impl Into<String>, sk: CompositeSecretKey) -> Self {
        Self {
            kid: kid.into(),
            sk,
        }
    }

    /// Generate a fresh signer with a random composite key. Useful for tests.
    pub fn generate(kid: impl Into<String>) -> Result<(Self, CompositePublicKey), SthError> {
        let (sk, pk) = CompositeSecretKey::generate()?;
        Ok((Self::new(kid, sk), pk))
    }
}

impl SthSigner for InProcessSigner {
    fn sign(&self, body: SthBody) -> Result<SignedTreeHead, SthError> {
        let body_cbor = encode_body(&body)?;
        let sig = self.sk.sign(STH_SIGNING_CONTEXT, &body_cbor)?;
        Ok(SignedTreeHead {
            body_cbor,
            signer_kid: self.kid.clone(),
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_concat_bytes()),
        })
    }

    fn kid(&self) -> &str {
        &self.kid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (signer, pk) = InProcessSigner::generate("sth-1").unwrap();
        let body = SthBody {
            tree_size: 42,
            root_hash: Hash384([0x7E; 48]),
            timestamp: 1_770_000_000,
        };
        let sth = signer.sign(body.clone()).unwrap();
        let verified = verify_sth(&sth, &pk).unwrap();
        assert_eq!(verified, body);
        assert_eq!(sth.signer_kid, "sth-1");
    }

    #[test]
    fn tampered_body_fails_verify() {
        let (signer, pk) = InProcessSigner::generate("k").unwrap();
        let mut sth = signer
            .sign(SthBody {
                tree_size: 1,
                root_hash: Hash384([1u8; 48]),
                timestamp: 0,
            })
            .unwrap();
        // Flip a byte in the CBOR body.
        sth.body_cbor[0] ^= 0x01;
        assert!(matches!(
            verify_sth(&sth, &pk),
            Err(SthError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let (signer, pk) = InProcessSigner::generate("k").unwrap();
        let mut sth = signer
            .sign(SthBody {
                tree_size: 1,
                root_hash: Hash384([1u8; 48]),
                timestamp: 0,
            })
            .unwrap();
        let last = sth.signature_b64.pop().unwrap();
        sth.signature_b64.push(if last == 'A' { 'B' } else { 'A' });
        assert!(verify_sth(&sth, &pk).is_err());
    }

    #[test]
    fn wrong_key_fails_verify() {
        let (signer, _pk) = InProcessSigner::generate("k").unwrap();
        let (_, other_pk) = ferro_crypto::composite::CompositeSecretKey::generate().unwrap();
        let sth = signer
            .sign(SthBody {
                tree_size: 1,
                root_hash: Hash384([1u8; 48]),
                timestamp: 0,
            })
            .unwrap();
        assert!(matches!(
            verify_sth(&sth, &other_pk),
            Err(SthError::SignatureInvalid)
        ));
    }
}
