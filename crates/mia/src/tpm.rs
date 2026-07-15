//! `mia::tpm` — TPM 2.0 glue for the Machine Identity Agent (feature F02).
//!
//! Drives a TPM 2.0 device (the kernel resource manager `/dev/tpmrm0` in
//! production, an `swtpm` socket under test) to produce the evidence CMIS
//! verifies: a freshly-created Attestation Identity Key, a PCR quote over the
//! policy PCR set, an `ActivateCredential` response proving the AIK shares the
//! EK's TPM, and an AIK signature binding the in-software composite SVID key to
//! the hardware.
//!
//! Only compiled on Linux, where a TSS2 ESAPI implementation exists; on other
//! hosts the daemon is built without TPM support.
//!
//! Every sensitive command runs under an HMAC-bound session
//! ([`TpmEngine::hmac_session`]) so a bus interposer cannot tamper with command
//! parameters undetected. The Esys layer salts and binds the session to the
//! TPM, defeating replay and substitution on the wire to the chip.

use anyhow::{Context as _, Result};

use tss_esapi::{
    abstraction::{ak, ek, pcr},
    attributes::SessionAttributesBuilder,
    constants::SessionType,
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm},
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Data, Digest, EncryptedSecret, HashScheme, IdObject, MaxBuffer, Nonce, PcrSelectionList,
        PcrSlot, SignatureScheme, SymmetricDefinition,
    },
    tcti_ldr::TctiNameConf,
    traits::Marshall,
    Context,
};

use crate::client::{AttestEvidence, QuoteEvidence};

/// The policy PCR set quoted on every attestation (see `docs/tpm.md`).
const POLICY_PCRS: [PcrSlot; 11] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot14,
];

/// The PCR bank we quote and seal against.
const PCR_BANK: HashingAlgorithm = HashingAlgorithm::Sha384;

/// A handle to a created TPM object plus its marshaled public area.
pub struct LoadedKey {
    /// The live Esys handle.
    pub handle: KeyHandle,
    /// The marshaled `TPMT_PUBLIC` for the key (wire form for CMIS).
    pub public_marshaled: Vec<u8>,
    /// The structured public area, retained for re-loading / activation.
    pub public: tss_esapi::structures::Public,
}

/// A produced PCR quote, ready to send to CMIS.
pub struct QuoteResult {
    /// Marshaled `TPMS_ATTEST` (the bytes the signature covers).
    pub attest_marshaled: Vec<u8>,
    /// Marshaled `TPMT_SIGNATURE`.
    pub signature_marshaled: Vec<u8>,
    /// The raw PCR values read back (index, value), for CMIS to recompute the
    /// aggregate digest.
    pub pcr_values: Vec<(u8, Vec<u8>)>,
}

/// Drives a single TPM device.
pub struct TpmEngine {
    ctx: Context,
}

impl TpmEngine {
    /// Open the TPM described by `tcti` (e.g. the device TCTI for
    /// `/dev/tpmrm0`, or an `swtpm`/`mssim` socket under test).
    pub fn new(tcti: TctiNameConf) -> Result<Self> {
        let ctx = Context::new(tcti).context("open TPM context")?;
        Ok(Self { ctx })
    }

    /// Open the resource-manager device (`/dev/tpmrm0`) — never the raw
    /// `/dev/tpm0`, so other host consumers don't get their objects evicted.
    pub fn open_device() -> Result<Self> {
        let tcti = TctiNameConf::from_environment_variable()
            .or_else(|_| "device:/dev/tpmrm0".parse())
            .context("resolve TPM TCTI")?;
        Self::new(tcti)
    }

    /// Start a fresh HMAC session with parameter encryption, suitable for
    /// authorizing a sensitive command. The caller installs it for the next
    /// call(s) via [`Context::execute_with_session`].
    fn hmac_session(&mut self) -> Result<AuthSession> {
        let session = self
            .ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .context("start HMAC session")?
            .context("HMAC session was None")?;
        let (attrs, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        self.ctx
            .tr_sess_set_attributes(session, attrs, mask)
            .context("set HMAC session attributes")?;
        Ok(session)
    }

    /// Flush a session out of the TPM so its context slot is freed. TPMs hold
    /// only a few session slots; leaking them yields `TPM_RC_SESSION_MEMORY`.
    fn flush_session(&mut self, session: impl Into<SessionHandle>) {
        let handle: SessionHandle = session.into();
        let _ = self.ctx.flush_context(handle.into());
    }

    /// Create the Endorsement Key in the endorsement hierarchy using the
    /// TCG-default ECC-P256 template.
    pub fn load_ek(&mut self) -> Result<LoadedKey> {
        let handle = ek::create_ek_object(&mut self.ctx, AsymmetricAlgorithm::Ecc, None)
            .context("create EK object")?;
        let (public, _, _) = self.ctx.read_public(handle).context("read EK public")?;
        let public_marshaled = public.marshall().context("marshal EK public")?;
        Ok(LoadedKey {
            handle,
            public_marshaled,
            public,
        })
    }

    /// Create an AIK as a restricted, signing-only ECDSA child of the EK and
    /// load it. The `ak` abstraction builds the required attribute mask
    /// (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `restricted`,
    /// `sign`; `decrypt` clear) on curve NIST P-256.
    pub fn create_aik(&mut self, ek: &LoadedKey) -> Result<LoadedKey> {
        let created = ak::create_ak(
            &mut self.ctx,
            ek.handle,
            PCR_BANK,
            SignatureSchemeAlgorithm::EcDsa,
            None,
            None,
        )
        .context("create AIK")?;

        let handle = ak::load_ak(
            &mut self.ctx,
            ek.handle,
            None,
            created.out_private,
            created.out_public.clone(),
        )
        .context("load AIK")?;

        let public_marshaled = created
            .out_public
            .marshall()
            .context("marshal AIK public")?;
        Ok(LoadedKey {
            handle,
            public_marshaled,
            public: created.out_public,
        })
    }

    /// Quote the policy PCR set with `nonce` as `qualifyingData`, signed by the
    /// AIK. Also reads back the raw PCR values so CMIS can recompute the digest.
    pub fn quote(&mut self, aik: &LoadedKey, nonce: &[u8]) -> Result<QuoteResult> {
        let pcr_selection = PcrSelectionList::builder()
            .with_selection(PCR_BANK, &POLICY_PCRS)
            .build()
            .context("build PCR selection")?;

        let qualifying_data = Data::try_from(nonce.to_vec()).context("nonce too long")?;
        let scheme = SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(PCR_BANK),
        };

        let session = self.hmac_session()?;
        let quote_res = self
            .ctx
            .execute_with_session(Some(session), |ctx| {
                ctx.quote(aik.handle, qualifying_data, scheme, pcr_selection.clone())
            })
            .context("TPM2_Quote");
        self.flush_session(session);
        let (attest, signature) = quote_res?;

        let pcr_values = self.read_pcrs(&pcr_selection)?;

        Ok(QuoteResult {
            attest_marshaled: attest.marshall().context("marshal attest")?,
            signature_marshaled: signature.marshall().context("marshal signature")?,
            pcr_values,
        })
    }

    /// Read back the current values of the selected PCRs.
    ///
    /// `TPM2_PCR_Read` returns at most a handful of PCRs per call, so we use
    /// the looping `read_all` abstraction and then pull each policy slot's
    /// digest out of the SHA-384 bank in ascending index order.
    fn read_pcrs(&mut self, selection: &PcrSelectionList) -> Result<Vec<(u8, Vec<u8>)>> {
        let data = pcr::read_all(&mut self.ctx, selection.clone()).context("PCR_Read (all)")?;
        let bank = data
            .pcr_bank(PCR_BANK)
            .context("no SHA-384 PCR bank in read result")?;
        let mut out = Vec::with_capacity(POLICY_PCRS.len());
        for slot in POLICY_PCRS {
            let digest = bank
                .get_digest(slot)
                .with_context(|| format!("missing PCR {}", pcr_slot_index(slot)))?;
            out.push((pcr_slot_index(slot), digest.value().to_vec()));
        }
        Ok(out)
    }

    /// Run `TPM2_ActivateCredential`: the TPM releases the wrapped `secret`
    /// only if the AIK truly resides in the same TPM whose EK unwrapped the
    /// credential blob. The EK is authorized with an endorsement-hierarchy
    /// policy session; the AIK with an HMAC session.
    pub fn activate_credential(
        &mut self,
        aik: &LoadedKey,
        ek: &LoadedKey,
        credential_blob: IdObject,
        secret: EncryptedSecret,
    ) -> Result<Vec<u8>> {
        let aik_session = self.hmac_session()?;
        let ek_policy = self.endorsement_policy_session()?;

        let result = self
            .ctx
            .execute_with_sessions((Some(aik_session), Some(ek_policy.into()), None), |ctx| {
                ctx.activate_credential(aik.handle, ek.handle, credential_blob, secret)
            })
            .context("TPM2_ActivateCredential");
        self.flush_session(aik_session);
        self.flush_session(ek_policy);
        let digest = result?;
        Ok(digest.value().to_vec())
    }

    /// Build a policy session satisfying the EK's `PolicySecret(endorsement)`
    /// authorization (the standard TCG EK auth policy).
    fn endorsement_policy_session(&mut self) -> Result<PolicySession> {
        let session = self
            .ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .context("start EK policy session")?
            .context("EK policy session was None")?;
        let policy_session =
            PolicySession::try_from(session).context("session is not a policy session")?;
        let _ = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.policy_secret(
                    policy_session,
                    AuthHandle::Endorsement,
                    Nonce::default(),
                    Digest::default(),
                    Nonce::default(),
                    None,
                )
            })
            .context("PolicySecret(endorsement)")?;
        Ok(policy_session)
    }

    /// Sign `message` with the AIK, binding it to the hardware.
    ///
    /// The AIK is *restricted*, so it will only sign data the TPM itself
    /// hashed and certified did not begin with `TPM_GENERATED_VALUE`. We
    /// therefore hash `message` inside the TPM (obtaining a validation ticket)
    /// and pass that ticket to `Sign`. CMIS uses this over `composite_pub` in
    /// phase 4.
    pub fn sign_aik(&mut self, aik: &LoadedKey, message: &[u8]) -> Result<Vec<u8>> {
        let buffer = MaxBuffer::try_from(message.to_vec()).context("message too long")?;
        let (digest, ticket) = self
            .ctx
            .hash(buffer, PCR_BANK, Hierarchy::Endorsement)
            .context("TPM2_Hash")?;

        let scheme = SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(PCR_BANK),
        };
        let session = self.hmac_session()?;
        let sign_res = self
            .ctx
            .execute_with_session(Some(session), |ctx| {
                ctx.sign(aik.handle, digest, scheme, ticket)
            })
            .context("TPM2_Sign");
        self.flush_session(session);
        let signature = sign_res?;
        signature.marshall().context("marshal AIK signature")
    }

    /// Borrow the underlying context (escape hatch for advanced callers/tests).
    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.ctx
    }
}

/// A [`TpmEngine`] driven through the shared [`AttestEvidence`] handshake
/// (`client::run_attest`), so the genuine TPM backend uses exactly the same
/// 4-phase state machine as the dev-only virtual TPM.
///
/// Construction creates the EK and a fresh restricted AIK; the EK certificate
/// (and any intermediates) are supplied by the caller — read from operator
/// configuration, since mia does not read the EK cert out of NV.
pub struct TpmEvidence {
    engine: TpmEngine,
    ek: LoadedKey,
    aik: LoadedKey,
    ek_cert: Vec<u8>,
    ek_intermediates: Vec<Vec<u8>>,
}

impl TpmEvidence {
    /// Open the resource-manager device, create the EK + AIK, and bind the
    /// operator-supplied EK certificate chain.
    ///
    /// # Errors
    /// Propagates any TPM error creating the EK or AIK.
    pub fn new(
        mut engine: TpmEngine,
        ek_cert: Vec<u8>,
        ek_intermediates: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let ek = engine.load_ek().context("load EK")?;
        let aik = engine.create_aik(&ek).context("create AIK")?;
        Ok(Self {
            engine,
            ek,
            aik,
            ek_cert,
            ek_intermediates,
        })
    }
}

impl AttestEvidence for TpmEvidence {
    fn ek_cert(&self) -> Vec<u8> {
        self.ek_cert.clone()
    }

    fn ek_intermediates(&self) -> Vec<Vec<u8>> {
        self.ek_intermediates.clone()
    }

    fn aik_pub(&self) -> Vec<u8> {
        self.aik.public_marshaled.clone()
    }

    fn quote(&mut self, nonce: &[u8]) -> Result<QuoteEvidence> {
        let q = self.engine.quote(&self.aik, nonce)?;
        Ok(QuoteEvidence {
            attest_blob: q.attest_marshaled,
            signature: q.signature_marshaled,
            pcr_values: q.pcr_values,
        })
    }

    fn activate(&mut self, credential_blob: &[u8], secret_blob: &[u8]) -> Result<Vec<u8>> {
        // The wire blobs are the `TPM2B_ID_OBJECT` / `TPM2B_ENCRYPTED_SECRET`
        // buffer contents (see `cmis::credential::WrappedCredential`); rebuild the
        // ESAPI buffer types `TPM2_ActivateCredential` expects.
        let id_object =
            IdObject::try_from(credential_blob.to_vec()).context("parse credential_blob")?;
        let secret =
            EncryptedSecret::try_from(secret_blob.to_vec()).context("parse secret_blob")?;
        self.engine
            .activate_credential(&self.aik, &self.ek, id_object, secret)
    }

    fn sign_aik(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.engine.sign_aik(&self.aik, message)
    }
}

/// Map a `PcrSlot` to its numeric PCR index. The slot's `u32` form is the bit
/// `1 << index`, so the index is its trailing-zero count.
fn pcr_slot_index(slot: PcrSlot) -> u8 {
    // The index is 0..=31, so the trailing-zero count always fits a u8.
    u8::try_from(u32::from(slot).trailing_zeros()).unwrap_or(0)
}
