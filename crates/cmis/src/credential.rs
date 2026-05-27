//! Phase-3 credential-activation seam.
//!
//! CMIS proves an AIK shares a TPM with the certified EK by wrapping a random
//! secret under the EK public key with the TCG `MakeCredential` construction
//! (`docs/protocol.md` §"Phase 3"). The MIA can only recover the secret via
//! `TPM2_ActivateCredential` if the AIK truly resides in that TPM.
//!
//! The wrapping itself is abstracted behind [`CredentialMaker`] so the
//! production TCG/EK implementation, a software stand-in for tests, and any
//! future HSM-backed variant can be injected without touching the handshake
//! state machine. This crate ships no software implementation — that would be
//! fake crypto in the issuance path — so callers must supply one.

/// Failure modes for credential wrapping.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The EK public area could not be used to wrap the secret.
    #[error("could not wrap credential: {0}")]
    Wrap(String),
}

/// The output of `MakeCredential`: the encrypted credential and the wrapped
/// seed (`secret_blob`), both sent to the MIA in the phase-3 challenge.
#[derive(Debug, Clone)]
pub struct WrappedCredential {
    /// `TPM2B_ID_OBJECT` — the encrypted credential.
    pub credential_blob: Vec<u8>,
    /// `TPM2B_ENCRYPTED_SECRET` — the wrapped seed.
    pub secret_blob: Vec<u8>,
}

/// Wraps a phase-3 secret under a TPM EK public key.
pub trait CredentialMaker: Send + Sync + 'static {
    /// Wrap `secret` for the TPM identified by `ek_pub` (marshaled
    /// `TPMT_PUBLIC`) and the AIK whose marshaled public area is `aik_pub`.
    /// The implementation derives the AIK Name it needs from `aik_pub`.
    fn make_credential(
        &self,
        ek_pub: &[u8],
        aik_pub: &[u8],
        secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError>;
}
