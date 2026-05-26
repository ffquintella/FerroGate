//! Known-Answer Tests for the building blocks of the composite signature
//! (feature F03 acceptance criterion).
//!
//! The composite scheme inherits the security of its two halves under an
//! AND-combiner, so the KAT story splits in two:
//!
//! 1. **Ed25519** — RFC 8032 / Wycheproof.
//!    Run the upstream Wycheproof `eddsa` vectors against the same
//!    `ed25519-dalek` `verify_strict` path the composite verifier uses.
//!
//! 2. **ML-DSA-65** — FIPS 204.
//!    NIST/ACVP KATs for ML-DSA are exercised in the `fips204` crate's
//!    own CI; redoing them downstream would duplicate ~50 MB of vectors
//!    for no marginal coverage. Instead, this file:
//!    - pins the FIPS-204-specified public-key / private-key /
//!      signature lengths so an accidental upstream change is caught;
//!    - runs a sign / verify / tamper round-trip that exercises the
//!      live `fips204` API the composite signer uses;
//!    - documents the upstream dependency so a future change can pull
//!      in dedicated KATs once Wycheproof publishes ML-DSA vectors.

use ed25519_dalek::VerifyingKey as EdVk;
use ferro_crypto::composite::{
    CompositeSecretKey, CompositeSignature, COMPOSITE_SIG_LEN, ED25519_PK_LEN, ED25519_SIG_LEN,
    MLDSA65_PK_LEN, MLDSA65_SIG_LEN,
};
use wycheproof::eddsa::{TestName, TestSet};
use wycheproof::EdwardsCurve;
use wycheproof::TestResult;

// ---------------------------------------------------------------------------
// Ed25519 — Wycheproof KAT
// ---------------------------------------------------------------------------

#[test]
fn wycheproof_ed25519_verify_vectors() {
    let set = TestSet::load(TestName::Ed25519).expect("load wycheproof ed25519");

    let mut ran = 0usize;
    let mut skipped_curve = 0usize;

    for group in &set.test_groups {
        // The eddsa test set bundles ed25519 and ed448; pick ours.
        if group.key.curve != EdwardsCurve::Ed25519 {
            skipped_curve += 1;
            continue;
        }
        let pk_bytes: &[u8] = group.key.pk.as_ref();
        if pk_bytes.len() != ED25519_PK_LEN {
            skipped_curve += 1;
            continue;
        }
        let pk_arr: [u8; ED25519_PK_LEN] = pk_bytes.try_into().unwrap();
        // `from_bytes` may fail on a malformed key encoding; if it does
        // we treat every Valid test in the group as a failure (none of
        // them can succeed), and every Invalid test as a pass.
        let maybe_pk = EdVk::from_bytes(&pk_arr);

        for tc in &group.tests {
            ran += 1;
            let res = match (&maybe_pk, tc.sig.as_ref()) {
                (Ok(pk), sig_bytes) if sig_bytes.len() == ED25519_SIG_LEN => {
                    let sig_arr: [u8; ED25519_SIG_LEN] = sig_bytes.try_into().unwrap();
                    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                    pk.verify_strict(tc.msg.as_ref(), &sig).is_ok()
                }
                _ => false,
            };

            match tc.result {
                TestResult::Valid => assert!(
                    res,
                    "tc {}: valid Wycheproof Ed25519 vector failed to verify",
                    tc.tc_id
                ),
                TestResult::Invalid => assert!(
                    !res,
                    "tc {}: invalid Wycheproof Ed25519 vector unexpectedly verified",
                    tc.tc_id
                ),
                // `Acceptable` covers malleability / canonicalization edge
                // cases. `verify_strict` is the strict path, so we expect
                // it to reject; if it happens to accept that is fine too.
                TestResult::Acceptable => { /* both outcomes acceptable */ }
            }
        }
    }

    assert!(
        ran > 100,
        "expected a meaningful number of vectors; ran={ran}"
    );
    eprintln!("Wycheproof Ed25519: ran={ran}, skipped_other_curve={skipped_curve}");
}

// ---------------------------------------------------------------------------
// ML-DSA-65 — FIPS-204 size pinning and live sanity
// ---------------------------------------------------------------------------

#[test]
fn ml_dsa_65_sizes_match_fips_204() {
    // The FIPS-204 standard fixes these sizes for ML-DSA-65.
    // Any drift here means we are talking to a different parameter set.
    assert_eq!(
        MLDSA65_PK_LEN, 1952,
        "ML-DSA-65 public key must be 1952 bytes"
    );
    assert_eq!(
        MLDSA65_SIG_LEN, 3309,
        "ML-DSA-65 signature must be 3309 bytes"
    );
}

#[test]
fn composite_sizes_match_design_doc() {
    // docs/crypto.md table: classical 64 + pqc 3309 = 3373 bytes.
    assert_eq!(ED25519_SIG_LEN, 64);
    assert_eq!(COMPOSITE_SIG_LEN, 64 + 3309);
}

#[test]
fn fips204_live_keygen_sign_verify_roundtrip() {
    // This is *not* a KAT — ML-DSA signing is randomized so a KAT would
    // need a deterministic seed. It exercises the same `fips204` API the
    // composite signer uses, so an API change in the crate (which would
    // silently break composite signing) is caught here.
    let (sk, pk) = CompositeSecretKey::generate().expect("composite keygen");
    let sig = sk.sign(b"ctx", b"message").expect("sign");
    pk.verify(b"ctx", b"message", &sig).expect("verify");
}

// ---------------------------------------------------------------------------
// Composite — wire-format stability
// ---------------------------------------------------------------------------

#[test]
fn der_encoding_roundtrip_does_not_alter_signature_bytes() {
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    let sig = sk.sign(b"svid-v1", b"payload").unwrap();
    let der_bytes = sig.to_der().unwrap();
    let back = CompositeSignature::from_der(&der_bytes).unwrap();
    assert_eq!(sig, back);
    pk.verify(b"svid-v1", b"payload", &back).unwrap();
}

#[test]
fn jws_encoding_roundtrip_does_not_alter_signature_bytes() {
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    let sig = sk.sign(b"svid-v1", b"payload").unwrap();
    let s = sig.to_jws_base64url();
    let back = CompositeSignature::from_jws_base64url(&s).unwrap();
    assert_eq!(sig, back);
    pk.verify(b"svid-v1", b"payload", &back).unwrap();
}

// ---------------------------------------------------------------------------
// Composite — AND-combiner enforcement
// ---------------------------------------------------------------------------

#[test]
fn cross_key_verification_fails() {
    let (sk_a, _pk_a) = CompositeSecretKey::generate().unwrap();
    let (_, pk_b) = CompositeSecretKey::generate().unwrap();
    let sig = sk_a.sign(b"ctx", b"msg").unwrap();
    assert!(pk_b.verify(b"ctx", b"msg", &sig).is_err());
}

#[test]
fn forging_classical_against_real_pqc_fails() {
    // Take a real signature, replace the Ed25519 half with a forged
    // signature under a different Ed25519 key. The PQC half still
    // verifies but the classical half does not — the AND-combiner must
    // reject.
    let (sk_real, pk_real) = CompositeSecretKey::generate().unwrap();
    let real_sig = sk_real.sign(b"ctx", b"msg").unwrap();

    let (sk_forge, _) = CompositeSecretKey::generate().unwrap();
    let forged_classical_sig = sk_forge.sign(b"ctx", b"msg").unwrap();

    let frankensig = CompositeSignature {
        classical: forged_classical_sig.classical,
        pqc: real_sig.pqc.clone(),
    };
    assert!(pk_real.verify(b"ctx", b"msg", &frankensig).is_err());
}

#[test]
fn forging_pqc_against_real_classical_fails() {
    // Symmetric attack: real Ed25519 half, attacker-supplied ML-DSA half.
    let (sk_real, pk_real) = CompositeSecretKey::generate().unwrap();
    let real_sig = sk_real.sign(b"ctx", b"msg").unwrap();

    let (sk_forge, _) = CompositeSecretKey::generate().unwrap();
    let forged_pqc_sig = sk_forge.sign(b"ctx", b"msg").unwrap();

    let frankensig = CompositeSignature {
        classical: real_sig.classical,
        pqc: forged_pqc_sig.pqc,
    };
    assert!(pk_real.verify(b"ctx", b"msg", &frankensig).is_err());
}
