//! PCR-bound local sealing of the SVID cache (feature F04, Linux-only).
//!
//! The SVID and its composite private key are too large to seal directly in a
//! TPM object, so we seal a 256-bit data-protection key to a `PolicyPCR` over
//! PCRs `{0, 4, 7, 8}` (SHA-384 bank) and use it to AEAD-encrypt the cache blob
//! (ChaCha20-Poly1305). On reboot the key only unseals if those PCRs match the
//! state at sealing time; any boot-state change (firmware, boot chain, secure
//! boot policy, the IMA aggregate) makes the TPM refuse to release it, so a
//! stale cache silently fails to decrypt and the MIA re-attests.
//!
//! This module is exercised by `tests/swtpm_seal.rs` against a software TPM; it
//! is not compiled on non-Linux hosts.

use anyhow::{anyhow, Context as _, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, PcrSelectionList,
    PcrSlot, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
    SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;

use crate::tpm::TpmEngine;

/// The PCRs the cache is sealed against (boot firmware, boot manager, secure
/// boot policy, and the boot loader / IMA aggregate).
pub const SEAL_PCRS: [PcrSlot; 4] = [
    PcrSlot::Slot0,
    PcrSlot::Slot4,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
];

/// The bank sealed against (matches the quote bank, `docs/tpm.md`).
const SEAL_BANK: HashingAlgorithm = HashingAlgorithm::Sha384;

/// A TPM-sealed data-protection key: the marshaled public and private halves
/// of the keyedhash object created under the storage primary.
#[derive(Debug, Clone)]
pub struct SealedKey {
    /// Marshaled `TPM2B_PUBLIC`.
    pub public: Vec<u8>,
    /// Marshaled `TPM2B_PRIVATE`.
    pub private: Vec<u8>,
}

/// A sealed SVID cache: the PCR-bound key plus the AEAD-protected payload.
#[derive(Debug, Clone)]
pub struct SealedSvid {
    /// The PCR-sealed data-protection key.
    pub key: SealedKey,
    /// ChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with appended authentication tag.
    pub ciphertext: Vec<u8>,
}

fn seal_selection() -> Result<PcrSelectionList> {
    PcrSelectionList::builder()
        .with_selection(SEAL_BANK, &SEAL_PCRS)
        .build()
        .context("build seal PCR selection")
}

/// Create a restricted ECC storage primary in the owner hierarchy to parent
/// the sealed object. Deterministic template, so re-deriving it across boots
/// yields the same parent.
fn storage_primary(ctx: &mut Context) -> Result<KeyHandle> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .context("storage primary attributes")?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_restricted(true)
        .with_is_decryption_key(true)
        .build()
        .context("storage primary ECC params")?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("storage primary public")?;

    let primary = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .context("create storage primary")?;
    Ok(primary.key_handle)
}

/// Start a fresh PCR policy session over [`SEAL_PCRS`]. With an empty expected
/// digest the TPM binds the session to the *current* PCR values.
fn pcr_policy_session(ctx: &mut Context, trial: bool) -> Result<PolicySession> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            if trial {
                SessionType::Trial
            } else {
                SessionType::Policy
            },
            SymmetricDefinition::AES_128_CFB,
            // The session hash must match the sealed object's nameAlg so the
            // resulting policy digest is the right size (else TPM_RC_SIZE).
            SEAL_BANK,
        )
        .context("start policy session")?
        .ok_or_else(|| anyhow!("policy session was None"))?;
    let policy_session =
        PolicySession::try_from(session).context("session is not a policy session")?;
    ctx.policy_pcr(policy_session, Digest::default(), seal_selection()?)
        .context("policy_pcr")?;
    Ok(policy_session)
}

/// Compute the authPolicy digest for the current PCR state via a trial session.
fn pcr_policy_digest(ctx: &mut Context) -> Result<Digest> {
    let trial = pcr_policy_session(ctx, true)?;
    let digest = ctx.policy_get_digest(trial).context("policy_get_digest")?;
    ctx.flush_context(tss_esapi::handles::SessionHandle::from(trial).into())
        .ok();
    Ok(digest)
}

/// Seal `secret` (≤ keyedhash sensitive limit) to the current PCR state.
pub fn seal_secret(engine: &mut TpmEngine, secret: &[u8]) -> Result<SealedKey> {
    let ctx = engine.context_mut();
    let parent = storage_primary(ctx)?;
    let policy = pcr_policy_digest(ctx)?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_admin_with_policy(true)
        .with_no_da(true)
        .build()
        .context("sealed object attributes")?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(SEAL_BANK)
        .with_object_attributes(attrs)
        .with_auth_policy(policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .context("sealed object public")?;

    let sensitive = SensitiveData::try_from(secret.to_vec()).context("secret too long to seal")?;

    let created = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create(parent, public, None, Some(sensitive), None, None)
        })
        .context("create sealed object")?;

    let key = SealedKey {
        public: created
            .out_public
            .marshall()
            .context("marshal sealed public")?,
        private: created.out_private.value().to_vec(),
    };
    let _ = ctx.flush_context(parent.into());
    Ok(key)
}

/// Unseal a [`SealedKey`]. Fails (policy error) if the PCRs no longer match.
pub fn unseal_secret(engine: &mut TpmEngine, sealed: &SealedKey) -> Result<Vec<u8>> {
    let ctx = engine.context_mut();
    let parent = storage_primary(ctx)?;

    let public = Public::unmarshall(&sealed.public).context("unmarshal sealed public")?;
    let private =
        tss_esapi::structures::Private::try_from(sealed.private.clone()).context("private")?;

    let loaded = ctx
        .execute_with_nullauth_session(|ctx| ctx.load(parent, private, public))
        .context("load sealed object")?;

    let policy = pcr_policy_session(ctx, false)?;
    let unsealed = ctx
        .execute_with_session(Some(policy.into()), |ctx| ctx.unseal(loaded.into()))
        .context("unseal")?;

    let _ = ctx.flush_context(loaded.into());
    let _ = ctx.flush_context(parent.into());
    let _ = ctx.flush_context(tss_esapi::handles::SessionHandle::from(policy).into());
    Ok(unsealed.value().to_vec())
}

/// Seal an SVID cache blob: generate a fresh AEAD key, seal it to the PCRs, and
/// encrypt `plaintext` (the serialized SVID + composite key) under it.
pub fn seal_svid(engine: &mut TpmEngine, plaintext: &[u8]) -> Result<SealedSvid> {
    let rng = SystemRandom::new();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes).map_err(|_| anyhow!("rng"))?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| anyhow!("rng"))?;

    let sealed_key = seal_secret(engine, &key_bytes)?;

    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).map_err(|_| anyhow!("aead key"))?;
    let aead = LessSafeKey::new(unbound);
    let mut buf = plaintext.to_vec();
    aead.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
        .map_err(|_| anyhow!("aead seal"))?;

    Ok(SealedSvid {
        key: sealed_key,
        nonce,
        ciphertext: buf,
    })
}

/// Recover an SVID cache blob. Returns an error if the PCRs changed (the key
/// will not unseal) or if the ciphertext fails authentication.
pub fn unseal_svid(engine: &mut TpmEngine, sealed: &SealedSvid) -> Result<Vec<u8>> {
    let key_bytes = unseal_secret(engine, &sealed.key)?;
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).map_err(|_| anyhow!("aead key"))?;
    let aead = LessSafeKey::new(unbound);
    let mut buf = sealed.ciphertext.clone();
    let plaintext = aead
        .open_in_place(
            Nonce::assume_unique_for_key(sealed.nonce),
            Aad::empty(),
            &mut buf,
        )
        .map_err(|_| anyhow!("aead open"))?;
    Ok(plaintext.to_vec())
}
