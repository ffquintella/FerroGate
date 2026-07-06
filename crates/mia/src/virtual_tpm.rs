//! `mia::virtual_tpm` — an **in-process software virtual TPM** for environments
//! where no real TPM 2.0 device (and no `swtpm` emulator) is available: macOS
//! and Windows dev machines, CI runners, and any Linux host without a TSS2
//! stack. It lets the full four-phase TPM attestation handshake ([`crate::client::run_attest`])
//! run on any platform, unlike [`crate::tpm::TpmEngine`] which is Linux-only and
//! needs real hardware.
//!
//! # Security — read this
//!
//! This is **NOT a TPM**. It has no hardware root of trust, its keys live in
//! ordinary process memory (and, when persisted, an ordinary `0600` file), and
//! its `TPM_GENERATED_VALUE`-stamped "quotes" are minted by software that also
//! holds the signing key. It exists solely to exercise the *protocol* off-box.
//! It is gated behind the off-by-default `virtual-tpm` cargo feature and, in the
//! daemon, an off-by-default `attestation.backend = "virtual-tpm"` config switch,
//! precisely so it can never be mistaken for a real attestation path in a release
//! build.
//!
//! A CMIS instance only accepts this evidence if it is configured to (a) trust
//! the synthetic EK root ([`VirtualTpm::ek_root_der`]), (b) approve the synthetic
//! PCR aggregate ([`expected_pcr_digest`]) in its RIM allowlist, and (c) use a
//! software credential channel matching [`software_credential_blob`]. A real,
//! production CMIS will reject it — as it should.
//!
//! # What it produces
//!
//! Wire-correct TCG "TPM 2.0 Library, Part 2" structures — `TPMT_PUBLIC` (the
//! AIK public area), `TPMS_ATTEST` (the quote body) and `TPMT_SIGNATURE` — that
//! the CMIS-side [`ferro_attest::TpmQuoteVerifier`] parses and verifies exactly
//! as it would a hardware quote. The AIK is a software P-256 ECDSA key.

// The wire builders below emit `UINT16`/`UINT8`-prefixed TPM structures; the
// lengths involved (curve points, a nonce, a short PCR bitmap) are all far
// below those bounds, so the narrowing casts cannot truncate in practice.
#![allow(clippy::cast_possible_truncation)]

use anyhow::{Context as _, Result};
use ferro_attest::tpm::{
    TPMA_FIXED_PARENT, TPMA_FIXED_TPM, TPMA_RESTRICTED, TPMA_SENSITIVE_DATA_ORIGIN, TPMA_SIGN,
    TPMA_USER_WITH_AUTH, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_ECC_NIST_P256, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

use crate::client::{AttestEvidence, QuoteEvidence};

/// The policy PCR set the quote covers, matching [`crate::tpm`]'s `POLICY_PCRS`
/// (`docs/tpm.md`). The values are synthetic but deterministic (see
/// [`pcr_values`]), so [`expected_pcr_digest`] is stable across runs.
pub const PCR_INDICES: [u8; 11] = [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 14];

fn push_u16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

/// Append a `TPM2B_*`: a `UINT16` length followed by the bytes.
fn push_tpm2b(b: &mut Vec<u8>, data: &[u8]) {
    push_u16(b, data.len() as u16);
    b.extend_from_slice(data);
}

/// Marshal a `TPMT_PUBLIC` for the AIK: a restricted, signing-only ECC-P256 key
/// with the attribute mask [`ferro_attest`]'s verifier requires. The scheme hash
/// is SHA-256 (matching the quote signature); the PCR bank quoted is SHA-384.
fn marshal_aik_public(vk: &VerifyingKey) -> Vec<u8> {
    let pt = vk.to_encoded_point(false);
    let (x, y) = (
        pt.x().expect("uncompressed point has X"),
        pt.y().expect("uncompressed point has Y"),
    );
    let attrs = TPMA_FIXED_TPM
        | TPMA_FIXED_PARENT
        | TPMA_SENSITIVE_DATA_ORIGIN
        | TPMA_USER_WITH_AUTH
        | TPMA_RESTRICTED
        | TPMA_SIGN;
    let mut b = Vec::new();
    push_u16(&mut b, TPM_ALG_ECC);
    push_u16(&mut b, TPM_ALG_SHA256); // nameAlg
    push_u32(&mut b, attrs);
    push_tpm2b(&mut b, &[]); // authPolicy (empty)
    push_u16(&mut b, 0x0010); // symmetric = TPM_ALG_NULL
    push_u16(&mut b, TPM_ALG_ECDSA); // scheme
    push_u16(&mut b, TPM_ALG_SHA256); // scheme hash
    push_u16(&mut b, TPM_ECC_NIST_P256); // curveID
    push_u16(&mut b, 0x0010); // kdf = TPM_ALG_NULL
    push_tpm2b(&mut b, x);
    push_tpm2b(&mut b, y);
    b
}

/// The `pcrSelect` bitmap selecting [`PCR_INDICES`] in the SHA-384 bank.
fn pcr_bitmap() -> Vec<u8> {
    let mut bm = vec![0u8; 3];
    for &i in &PCR_INDICES {
        bm[(i / 8) as usize] |= 1 << (i % 8);
    }
    bm
}

/// The synthetic raw PCR values backing the quote: each selected index `i`
/// reports the constant digest `[i; 48]`. Deterministic so a dev CMIS can
/// pre-approve [`expected_pcr_digest`].
#[must_use]
pub fn pcr_values() -> Vec<(u8, Vec<u8>)> {
    PCR_INDICES.iter().map(|&i| (i, vec![i; 48])).collect()
}

/// The SHA-384 aggregate over the selected PCRs, in ascending index order — the
/// digest a CMIS RIM allowlist must contain for this virtual TPM's quotes to be
/// accepted.
#[must_use]
pub fn expected_pcr_digest() -> [u8; 48] {
    let mut agg = Sha384::new();
    for &i in &PCR_INDICES {
        agg.update([i; 48]);
    }
    let mut digest = [0u8; 48];
    digest.copy_from_slice(&agg.finalize());
    digest
}

/// Build a marshaled `TPMS_ATTEST`/`TPMS_QUOTE_INFO` over the policy PCRs with
/// `nonce` echoed as `extraData`.
fn build_quote(nonce: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    push_u32(&mut b, TPM_GENERATED_VALUE);
    push_u16(&mut b, TPM_ST_ATTEST_QUOTE);
    push_tpm2b(&mut b, b"qualified-signer");
    push_tpm2b(&mut b, nonce);
    b.extend_from_slice(&0u64.to_be_bytes()); // clock
    push_u32(&mut b, 0); // resetCount
    push_u32(&mut b, 0); // restartCount
    b.push(1); // safe
    b.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
    push_u32(&mut b, 1); // pcrSelect.count
    push_u16(&mut b, TPM_ALG_SHA384);
    let bm = pcr_bitmap();
    b.push(bm.len() as u8);
    b.extend_from_slice(&bm);
    push_tpm2b(&mut b, &expected_pcr_digest());
    b
}

/// Marshal a `TPMT_SIGNATURE` carrying an ECDSA signature `(r, s)`.
fn marshal_signature(hash_alg: u16, r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    push_u16(&mut b, TPM_ALG_ECDSA);
    push_u16(&mut b, hash_alg);
    push_tpm2b(&mut b, r);
    push_tpm2b(&mut b, s);
    b
}

/// Mint a throwaway "vendor" root plus an EK leaf chaining to it. The verifier's
/// EK-chain step is independent of the TPM's own EK key, so any well-formed
/// chain anchors it — a dev CMIS trusts [`VirtualTpm::ek_root_der`].
fn build_ek_chain() -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().context("generate EK root key")?;
    let mut ca = CertificateParams::new(Vec::<String>::new()).context("EK root params")?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.not_before = date_time_ymd(2020, 1, 1);
    ca.not_after = date_time_ymd(2035, 1, 1);
    let ca_cert = ca.self_signed(&ca_key).context("self-sign EK root")?;

    let leaf_key = KeyPair::generate().context("generate EK leaf key")?;
    let mut leaf =
        CertificateParams::new(vec!["ek.virtual-tpm".to_string()]).context("EK leaf params")?;
    leaf.not_before = date_time_ymd(2020, 1, 1);
    leaf.not_after = date_time_ymd(2035, 1, 1);
    let ca_issuer = Issuer::from_params(&ca, &ca_key);
    let leaf_cert = leaf
        .signed_by(&leaf_key, &ca_issuer)
        .context("sign EK leaf")?;
    Ok((leaf_cert.der().to_vec(), ca_cert.der().to_vec()))
}

/// Derive the one-time-pad keystream the software credential channel uses. This
/// is the *only* shared secret between [`software_credential_blob`] (the CMIS
/// side) and [`VirtualTpm::activate`] (the MIA side); it is emphatically not
/// how a real `TPM2_MakeCredential`/`ActivateCredential` works.
fn activation_keystream(ek_cert: &[u8], aik_pub: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ek_cert);
    h.update(aik_pub);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

/// Wrap a 32-byte phase-3 `secret` into a `credential_blob` the virtual TPM can
/// unwrap in [`VirtualTpm::activate`]. A dev CMIS calls this from its
/// `CredentialMaker` in place of the hardware `TPM2_MakeCredential`.
///
/// This is a plain one-time-pad XOR keyed by the EK cert and AIK public — it
/// proves nothing about key residency and must never be used outside dev/test.
#[must_use]
pub fn software_credential_blob(ek_cert: &[u8], aik_pub: &[u8], secret: &[u8]) -> Vec<u8> {
    let ks = activation_keystream(ek_cert, aik_pub);
    secret.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect()
}

/// The on-disk form of a virtual TPM's persistent identity.
#[derive(Serialize, Deserialize)]
struct Persisted {
    /// The 32-byte P-256 AIK private scalar.
    aik_scalar: Vec<u8>,
    /// The synthetic EK leaf certificate (DER).
    ek_cert: Vec<u8>,
    /// The synthetic EK root certificate (DER).
    ek_root: Vec<u8>,
}

/// A software virtual TPM: a persistent (or ephemeral) synthetic EK chain and
/// software AIK that together satisfy the [`AttestEvidence`] contract.
///
/// [`Clone`] yields a handle to the *same* synthetic identity (same EK chain
/// and AIK) — useful for driving one host's attestation against several CMIS
/// endpoints, e.g. the nodes of a cluster.
#[derive(Clone)]
pub struct VirtualTpm {
    aik: SigningKey,
    aik_pub: Vec<u8>,
    ek_cert: Vec<u8>,
    ek_root: Vec<u8>,
}

impl VirtualTpm {
    /// Create a fresh, in-memory-only virtual TPM. Its identity is lost on drop;
    /// use [`VirtualTpm::open_or_create`] to persist it across restarts.
    pub fn ephemeral() -> Result<Self> {
        let aik = SigningKey::random(&mut rand_core::OsRng);
        let (ek_cert, ek_root) = build_ek_chain()?;
        Ok(Self::assemble(aik, ek_cert, ek_root))
    }

    fn assemble(aik: SigningKey, ek_cert: Vec<u8>, ek_root: Vec<u8>) -> Self {
        let aik_pub = marshal_aik_public(aik.verifying_key());
        Self {
            aik,
            aik_pub,
            ek_cert,
            ek_root,
        }
    }

    /// Load the virtual TPM's identity from `path`, creating and persisting a
    /// fresh one (`0600` on Unix) if the file is absent. A malformed file is an
    /// error rather than a silent regeneration, so a corrupt state is noticed.
    pub fn open_or_create(path: &std::path::Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let p: Persisted = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse virtual-TPM state at {}", path.display()))?;
                let aik = SigningKey::from_slice(&p.aik_scalar)
                    .context("virtual-TPM AIK scalar is not a valid P-256 key")?;
                Ok(Self::assemble(aik, p.ek_cert, p.ek_root))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let me = Self::ephemeral()?;
                me.persist(path)?;
                Ok(me)
            }
            Err(e) => {
                Err(e).with_context(|| format!("read virtual-TPM state at {}", path.display()))
            }
        }
    }

    fn persist(&self, path: &std::path::Path) -> Result<()> {
        let p = Persisted {
            aik_scalar: self.aik.to_bytes().to_vec(),
            ek_cert: self.ek_cert.clone(),
            ek_root: self.ek_root.clone(),
        };
        let bytes = serde_json::to_vec(&p).context("serialize virtual-TPM state")?;
        std::fs::write(path, bytes)
            .with_context(|| format!("write virtual-TPM state at {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restrict virtual-TPM state at {}", path.display()))?;
        }
        Ok(())
    }

    /// The synthetic EK root certificate (DER) a CMIS must trust to accept this
    /// virtual TPM's evidence.
    #[must_use]
    pub fn ek_root_der(&self) -> &[u8] {
        &self.ek_root
    }

    /// The synthetic EK leaf certificate (DER).
    #[must_use]
    pub fn ek_cert_der(&self) -> &[u8] {
        &self.ek_cert
    }

    /// The marshaled AIK public area (`TPMT_PUBLIC`).
    #[must_use]
    pub fn aik_public_marshaled(&self) -> &[u8] {
        &self.aik_pub
    }
}

impl AttestEvidence for VirtualTpm {
    fn ek_cert(&self) -> Vec<u8> {
        self.ek_cert.clone()
    }

    fn aik_pub(&self) -> Vec<u8> {
        self.aik_pub.clone()
    }

    fn quote(&mut self, nonce: &[u8]) -> Result<QuoteEvidence> {
        let blob = build_quote(nonce);
        let sig: Signature = self
            .aik
            .sign_prehash(&Sha256::digest(&blob))
            .context("virtual-TPM quote signature")?;
        let bytes = sig.to_bytes();
        Ok(QuoteEvidence {
            attest_blob: blob,
            signature: marshal_signature(TPM_ALG_SHA256, &bytes[..32], &bytes[32..]),
            pcr_values: pcr_values(),
        })
    }

    fn activate(&mut self, credential_blob: &[u8], _secret_blob: &[u8]) -> Result<Vec<u8>> {
        // Reverse the CMIS-side one-time-pad from `software_credential_blob`.
        Ok(software_credential_blob(
            &self.ek_cert,
            &self.aik_pub,
            credential_blob,
        ))
    }

    fn sign_aik(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        // A restricted hardware AIK hashes the message internally (SHA-384 here)
        // then signs; mirror that so the phase-4 verifier accepts the signature.
        let sig: Signature = self
            .aik
            .sign_prehash(&Sha384::digest(message))
            .context("virtual-TPM AIK signature")?;
        let bytes = sig.to_bytes();
        Ok(marshal_signature(
            TPM_ALG_SHA384,
            &bytes[..32],
            &bytes[32..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_attest::tpm::{EccPublic, EcdsaSignature, QuoteInfo};

    #[test]
    fn aik_public_parses_as_restricted_signing_ecc_p256() {
        let vtpm = VirtualTpm::ephemeral().unwrap();
        let pubk = EccPublic::parse(vtpm.aik_public_marshaled()).expect("AIK public parses");
        assert_eq!(pubk.curve_id, TPM_ECC_NIST_P256);
        assert_eq!(pubk.scheme, TPM_ALG_ECDSA);
        assert_ne!(pubk.attributes & TPMA_RESTRICTED, 0);
        assert_ne!(pubk.attributes & TPMA_SIGN, 0);
    }

    #[test]
    fn quote_echoes_nonce_and_matches_expected_digest() {
        let mut vtpm = VirtualTpm::ephemeral().unwrap();
        let nonce = [0x42u8; 32];
        let ev = vtpm.quote(&nonce).unwrap();
        let info = QuoteInfo::parse(&ev.attest_blob).expect("quote parses");
        assert_eq!(info.magic, TPM_GENERATED_VALUE);
        assert_eq!(info.attest_type, TPM_ST_ATTEST_QUOTE);
        assert_eq!(info.extra_data, nonce);
        assert_eq!(info.pcr_digest, expected_pcr_digest());
        // Signature marshals and parses as ECDSA.
        assert!(EcdsaSignature::parse(&ev.signature).is_ok());
    }

    #[test]
    fn credential_channel_round_trips() {
        let mut vtpm = VirtualTpm::ephemeral().unwrap();
        let secret = [0x9Cu8; 32];
        let blob =
            software_credential_blob(vtpm.ek_cert_der(), vtpm.aik_public_marshaled(), &secret);
        let recovered = vtpm.activate(&blob, &[]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn persistence_preserves_identity() {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("ferrogate-vtpm-test-{nanos}.json"));

        let first = VirtualTpm::open_or_create(&path).unwrap();
        let aik_pub = first.aik_public_marshaled().to_vec();
        let ek_root = first.ek_root_der().to_vec();
        drop(first);

        let second = VirtualTpm::open_or_create(&path).unwrap();
        assert_eq!(second.aik_public_marshaled(), aik_pub);
        assert_eq!(second.ek_root_der(), ek_root);
        let _ = std::fs::remove_file(&path);
    }
}
