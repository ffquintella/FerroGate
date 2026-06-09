//! End-to-end verifier tests using wire-correct synthetic TPM structures.
//!
//! These exercise the full [`TpmQuoteVerifier::verify_quote`] path without a
//! TPM: we mint a P-256 "AIK", marshal a `TPMT_PUBLIC` / `TPMS_ATTEST` /
//! `TPMT_SIGNATURE` exactly as a TPM would, build an EK cert chain with
//! `rcgen`, and feed it all through the verifier. The `swtpm` integration test
//! covers the real MIA-produced bytes; this covers the algorithm and every
//! negative branch the acceptance criteria call for.

// Test-only wire builders cast small, bounded lengths into TPM2B size fields.
#![allow(clippy::cast_possible_truncation)]

use ferro_attest::tpm::{
    TPMA_FIXED_PARENT, TPMA_FIXED_TPM, TPMA_RESTRICTED, TPMA_SENSITIVE_DATA_ORIGIN, TPMA_SIGN,
    TPMA_USER_WITH_AUTH, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_ECC_NIST_P256, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use ferro_attest::verify::{PcrSet, QuoteVerification, RejectReason};
use ferro_attest::{PolicyId, RimStore, TpmQuoteVerifier, Vendor, VendorTrustStore};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256, Sha384};

// --- wire-structure builders -------------------------------------------------

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn push_tpm2b(buf: &mut Vec<u8>, data: &[u8]) {
    push_u16(buf, data.len() as u16);
    buf.extend_from_slice(data);
}

const PCR_INDICES: [u8; 11] = [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 14];

fn marshal_aik_public(x: &[u8], y: &[u8], attributes: u32, scheme: u16) -> Vec<u8> {
    let mut b = Vec::new();
    push_u16(&mut b, TPM_ALG_ECC);
    push_u16(&mut b, TPM_ALG_SHA256); // nameAlg
    push_u32(&mut b, attributes);
    push_tpm2b(&mut b, &[]); // authPolicy
    push_u16(&mut b, 0x0010); // symmetric = TPM_ALG_NULL
    push_u16(&mut b, scheme); // scheme
    if scheme != 0x0010 {
        push_u16(&mut b, TPM_ALG_SHA256); // scheme hashAlg
    }
    push_u16(&mut b, TPM_ECC_NIST_P256); // curveID
    push_u16(&mut b, 0x0010); // kdf = TPM_ALG_NULL
    push_tpm2b(&mut b, x);
    push_tpm2b(&mut b, y);
    b
}

/// Build the SHA-384 PCR-selection bitmap for [`PCR_INDICES`].
fn pcr_bitmap() -> Vec<u8> {
    let mut bm = vec![0u8; 3];
    for &i in &PCR_INDICES {
        bm[(i / 8) as usize] |= 1 << (i % 8);
    }
    bm
}

struct QuoteParts {
    blob: Vec<u8>,
    pcrs: PcrSet,
    pcr_digest: [u8; 48],
}

fn build_quote(nonce: &[u8]) -> QuoteParts {
    // Deterministic per-PCR values, and the aggregate SHA-384 over them.
    let mut pcrs = PcrSet::new();
    let mut agg = Sha384::new();
    for &i in &PCR_INDICES {
        let value = [i; 48];
        pcrs.insert(i, value.to_vec());
        agg.update(value);
    }
    let mut pcr_digest = [0u8; 48];
    pcr_digest.copy_from_slice(&agg.finalize());

    let mut b = Vec::new();
    push_u32(&mut b, TPM_GENERATED_VALUE);
    push_u16(&mut b, TPM_ST_ATTEST_QUOTE);
    push_tpm2b(&mut b, b"qualified-signer-name"); // qualifiedSigner
    push_tpm2b(&mut b, nonce); // extraData
                               // clockInfo
    b.extend_from_slice(&0u64.to_be_bytes()); // clock
    push_u32(&mut b, 1); // resetCount
    push_u32(&mut b, 0); // restartCount
    b.push(1); // safe
    b.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
                                              // attested: TPMS_QUOTE_INFO
    push_u32(&mut b, 1); // pcrSelect.count
    push_u16(&mut b, TPM_ALG_SHA384); // hash
    let bm = pcr_bitmap();
    b.push(bm.len() as u8); // sizeofSelect
    b.extend_from_slice(&bm);
    push_tpm2b(&mut b, &pcr_digest);

    QuoteParts {
        blob: b,
        pcrs,
        pcr_digest,
    }
}

fn marshal_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    push_u16(&mut b, TPM_ALG_ECDSA); // sigAlg
    push_u16(&mut b, TPM_ALG_SHA256); // hash
    push_tpm2b(&mut b, r);
    push_tpm2b(&mut b, s);
    b
}

fn sign_quote(key: &SigningKey, blob: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(blob);
    let sig: Signature = key.sign_prehash(&digest).expect("sign prehash");
    let bytes = sig.to_bytes();
    marshal_signature(&bytes[..32], &bytes[32..])
}

const GOOD_AIK_ATTRS: u32 = TPMA_FIXED_TPM
    | TPMA_FIXED_PARENT
    | TPMA_SENSITIVE_DATA_ORIGIN
    | TPMA_USER_WITH_AUTH
    | TPMA_RESTRICTED
    | TPMA_SIGN;

// --- EK cert chain via rcgen -------------------------------------------------

struct Ek {
    leaf_der: Vec<u8>,
    root_der: Vec<u8>,
}

fn build_ek_chain() -> Ek {
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, Issuer, IsCa, KeyPair};

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.not_before = date_time_ymd(2020, 1, 1);
    ca_params.not_after = date_time_ymd(2035, 1, 1);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["ek.host".to_string()]).unwrap();
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2035, 1, 1);
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_issuer).unwrap();

    Ek {
        leaf_der: leaf_cert.der().to_vec(),
        root_der: ca_cert.der().to_vec(),
    }
}

/// Reference time inside the cert validity window (2026-ish, Unix seconds).
const NOW: i64 = 1_770_000_000;

/// Assemble a verifier whose trust store and RIM accept the supplied evidence.
fn verifier_for(ek: &Ek, pcr_digest: [u8; 48]) -> TpmQuoteVerifier {
    let mut trust = VendorTrustStore::new();
    trust.add_root_der(&ek.root_der, Vendor::Infineon).unwrap();
    let rim = RimStore::new();
    rim.approve(pcr_digest, PolicyId("test-fleet".into()));
    TpmQuoteVerifier::new(trust, rim)
}

// --- the happy path ----------------------------------------------------------

#[test]
fn full_quote_verifies_end_to_end() {
    let nonce = [0x5Au8; 32];
    let aik = SigningKey::random(&mut rand_core::OsRng);
    let vk = aik.verifying_key();
    let pt = vk.to_encoded_point(false);

    let aik_pub = marshal_aik_public(
        pt.x().unwrap(),
        pt.y().unwrap(),
        GOOD_AIK_ATTRS,
        TPM_ALG_ECDSA,
    );
    let q = build_quote(&nonce);
    let sig = sign_quote(&aik, &q.blob);
    let ek = build_ek_chain();
    let verifier = verifier_for(&ek, q.pcr_digest);

    let v = QuoteVerification {
        ek_cert_der: &ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &aik_pub,
        quote_blob: &q.blob,
        signature: &sig,
        nonce: &nonce,
        pcrs: &q.pcrs,
        now: NOW,
    };
    let result = verifier.verify_quote(&v).expect("quote must verify");
    assert_eq!(result.vendor, Vendor::Infineon);
    assert_eq!(result.policy_id.as_str(), "test-fleet");
    assert_eq!(result.pcr_digest, q.pcr_digest);
}

// --- negative tests (acceptance criteria) ------------------------------------

/// Common fixture returning the pieces so each negative test can corrupt one.
struct Fixture {
    aik: SigningKey,
    aik_pub: Vec<u8>,
    quote: QuoteParts,
    ek: Ek,
    nonce: [u8; 32],
}

fn fixture() -> Fixture {
    let nonce = [0x5Au8; 32];
    let aik = SigningKey::random(&mut rand_core::OsRng);
    let pt = aik.verifying_key().to_encoded_point(false);
    let aik_pub = marshal_aik_public(
        pt.x().unwrap(),
        pt.y().unwrap(),
        GOOD_AIK_ATTRS,
        TPM_ALG_ECDSA,
    );
    let quote = build_quote(&nonce);
    let ek = build_ek_chain();
    Fixture {
        aik,
        aik_pub,
        quote,
        ek,
        nonce,
    }
}

#[test]
fn tampered_quote_is_rejected() {
    let f = fixture();
    let sig = sign_quote(&f.aik, &f.quote.blob);
    // Flip a byte in the quote body *after* signing: signature no longer covers it.
    let mut blob = f.quote.blob.clone();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    let verifier = verifier_for(&f.ek, f.quote.pcr_digest);
    let v = QuoteVerification {
        ek_cert_der: &f.ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &f.aik_pub,
        quote_blob: &blob,
        signature: &sig,
        nonce: &f.nonce,
        pcrs: &f.quote.pcrs,
        now: NOW,
    };
    // Tampering the pcrDigest tail breaks the signature check.
    assert_eq!(
        verifier.verify_quote(&v),
        Err(RejectReason::SignatureInvalid)
    );
}

#[test]
fn wrong_nonce_is_rejected() {
    let f = fixture();
    let sig = sign_quote(&f.aik, &f.quote.blob);
    let verifier = verifier_for(&f.ek, f.quote.pcr_digest);
    let bad_nonce = [0x00u8; 32];
    let v = QuoteVerification {
        ek_cert_der: &f.ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &f.aik_pub,
        quote_blob: &f.quote.blob,
        signature: &sig,
        nonce: &bad_nonce,
        pcrs: &f.quote.pcrs,
        now: NOW,
    };
    assert_eq!(verifier.verify_quote(&v), Err(RejectReason::NonceMismatch));
}

#[test]
fn missing_pcr_value_is_rejected() {
    let f = fixture();
    let sig = sign_quote(&f.aik, &f.quote.blob);
    let verifier = verifier_for(&f.ek, f.quote.pcr_digest);
    // Drop PCR 7 from the reported set; the quote still selects it.
    let mut pcrs = PcrSet::new();
    for &i in &PCR_INDICES {
        if i != 7 {
            pcrs.insert(i, [i; 48].to_vec());
        }
    }
    let v = QuoteVerification {
        ek_cert_der: &f.ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &f.aik_pub,
        quote_blob: &f.quote.blob,
        signature: &sig,
        nonce: &f.nonce,
        pcrs: &pcrs,
        now: NOW,
    };
    assert_eq!(verifier.verify_quote(&v), Err(RejectReason::MissingPcr(7)));
}

#[test]
fn non_restricted_aik_is_rejected() {
    let f = fixture();
    // Re-marshal the AIK pub with the restricted bit cleared.
    let pt = f.aik.verifying_key().to_encoded_point(false);
    let attrs = GOOD_AIK_ATTRS & !TPMA_RESTRICTED;
    let aik_pub = marshal_aik_public(pt.x().unwrap(), pt.y().unwrap(), attrs, TPM_ALG_ECDSA);
    let sig = sign_quote(&f.aik, &f.quote.blob);
    let verifier = verifier_for(&f.ek, f.quote.pcr_digest);
    let v = QuoteVerification {
        ek_cert_der: &f.ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &aik_pub,
        quote_blob: &f.quote.blob,
        signature: &sig,
        nonce: &f.nonce,
        pcrs: &f.quote.pcrs,
        now: NOW,
    };
    assert!(matches!(
        verifier.verify_quote(&v),
        Err(RejectReason::AikAttributes(_))
    ));
}

#[test]
fn untrusted_ek_root_is_rejected() {
    let f = fixture();
    let sig = sign_quote(&f.aik, &f.quote.blob);
    // Trust store has a *different* root than the one that signed the EK.
    let other_ek = build_ek_chain();
    let verifier = verifier_for(&other_ek, f.quote.pcr_digest);
    let v = QuoteVerification {
        ek_cert_der: &f.ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &f.aik_pub,
        quote_blob: &f.quote.blob,
        signature: &sig,
        nonce: &f.nonce,
        pcrs: &f.quote.pcrs,
        now: NOW,
    };
    assert!(matches!(
        verifier.verify_quote(&v),
        Err(RejectReason::EkChain(_))
    ));
}

#[test]
fn unknown_pcr_state_not_in_rim_is_rejected() {
    let f = fixture();
    let sig = sign_quote(&f.aik, &f.quote.blob);
    // Trust the EK root, but approve a *different* digest in the RIM.
    let mut trust = VendorTrustStore::new();
    trust.add_root_der(&f.ek.root_der, Vendor::Nuvoton).unwrap();
    let rim = RimStore::new();
    rim.approve([0xEE; 48], PolicyId("other".into()));
    let verifier = TpmQuoteVerifier::new(trust, rim);
    let v = QuoteVerification {
        ek_cert_der: &f.ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &f.aik_pub,
        quote_blob: &f.quote.blob,
        signature: &sig,
        nonce: &f.nonce,
        pcrs: &f.quote.pcrs,
        now: NOW,
    };
    assert_eq!(verifier.verify_quote(&v), Err(RejectReason::NotInRim));
}

#[test]
fn signature_from_wrong_key_is_rejected() {
    let f = fixture();
    let attacker = SigningKey::random(&mut rand_core::OsRng);
    let sig = sign_quote(&attacker, &f.quote.blob);
    let verifier = verifier_for(&f.ek, f.quote.pcr_digest);
    let v = QuoteVerification {
        ek_cert_der: &f.ek.leaf_der,
        ek_intermediates: &[],
        aik_pub: &f.aik_pub,
        quote_blob: &f.quote.blob,
        signature: &sig,
        nonce: &f.nonce,
        pcrs: &f.quote.pcrs,
        now: NOW,
    };
    assert_eq!(
        verifier.verify_quote(&v),
        Err(RejectReason::SignatureInvalid)
    );
}

#[test]
fn credential_activation_mismatch_is_rejected() {
    use ferro_attest::credential_secret_matches;
    let secret = [0x11u8; 32];
    assert!(credential_secret_matches(&secret, &secret));
    let mut tampered = secret;
    tampered[31] ^= 0x01;
    assert!(!credential_secret_matches(&secret, &tampered));
}
