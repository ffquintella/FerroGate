//! Wycheproof AEAD vectors against the FerroGate AEAD primitives
//! (feature F01 acceptance criterion).
//!
//! FerroGate fixes TLS 1.3 cipher suites to ChaCha20-Poly1305 and
//! AES-256-GCM (see `docs/crypto.md`). This test runs the upstream
//! Wycheproof JSON test vectors for both algorithms through the
//! `aws-lc-rs` AEAD API — the same primitives rustls uses under the
//! hood — and asserts:
//!
//! - `result = "valid"` vectors decrypt successfully and encrypt to the
//!   exact expected ciphertext+tag.
//! - `result = "invalid"` vectors fail to decrypt.
//! - `result = "acceptable"` vectors are skipped (these flag edge-case
//!   behaviour that the spec leaves implementation-defined).
//!
//! Non-standard IV lengths (≠ 12 bytes) are skipped: aws-lc-rs requires
//! 12-byte nonces for both algorithms, matching the TLS 1.3 record
//! layer, so non-standard-nonce vectors are not in scope for the
//! FerroGate transport.

use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305,
};
use wycheproof::aead::{TestName, TestSet};
use wycheproof::TestResult;

const TLS_NONCE_LEN: usize = 12;

struct VectorStats {
    ran: usize,
    skipped_nonce: usize,
    skipped_acceptable: usize,
}

fn run(name: TestName, algo: &'static Algorithm) -> VectorStats {
    let set = TestSet::load(name).expect("load wycheproof vectors");
    let mut stats = VectorStats {
        ran: 0,
        skipped_nonce: 0,
        skipped_acceptable: 0,
    };

    let expected_key_len = algo.key_len();

    for group in &set.test_groups {
        // Wycheproof's AES-GCM file bundles 128/192/256-bit groups; pick
        // the one that matches the algorithm under test.
        if group.key_size / 8 != expected_key_len {
            continue;
        }
        for tc in &group.tests {
            // Skip non-standard nonce lengths; out of scope for TLS 1.3.
            if tc.nonce.len() != TLS_NONCE_LEN {
                stats.skipped_nonce += 1;
                continue;
            }
            if matches!(tc.result, TestResult::Acceptable) {
                stats.skipped_acceptable += 1;
                continue;
            }
            stats.ran += 1;

            // Build the key. If the key length is wrong for the algorithm,
            // wycheproof marks the test invalid; reflect that by treating
            // construction failure as the test outcome.
            let key = if let Ok(k) = UnboundKey::new(algo, &tc.key) {
                LessSafeKey::new(k)
            } else {
                assert!(
                    matches!(tc.result, TestResult::Invalid),
                    "tc {}: unexpected key-load failure for a valid vector",
                    tc.tc_id
                );
                continue;
            };

            let mut nonce_bytes = [0u8; TLS_NONCE_LEN];
            nonce_bytes.copy_from_slice(&tc.nonce);

            // --- Decryption check (works for both Valid and Invalid). ---
            let mut combined = tc.ct.to_vec();
            combined.extend_from_slice(&tc.tag);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let aad = Aad::from(tc.aad.as_ref());
            let dec_res = key.open_in_place(nonce, aad, &mut combined);

            match tc.result {
                TestResult::Valid => {
                    let pt = dec_res.unwrap_or_else(|_| {
                        panic!("tc {}: valid vector failed to decrypt", tc.tc_id)
                    });
                    assert_eq!(
                        pt,
                        tc.pt.as_slice(),
                        "tc {}: decrypted plaintext mismatch",
                        tc.tc_id
                    );

                    // --- Encryption check: re-encrypt and compare. ---
                    let key2 = LessSafeKey::new(UnboundKey::new(algo, &tc.key).unwrap());
                    let nonce2 = Nonce::assume_unique_for_key(nonce_bytes);
                    let aad2 = Aad::from(tc.aad.as_ref());
                    let mut in_out = tc.pt.to_vec();
                    key2.seal_in_place_append_tag(nonce2, aad2, &mut in_out)
                        .expect("seal");
                    let mut expected = tc.ct.to_vec();
                    expected.extend_from_slice(&tc.tag);
                    assert_eq!(
                        in_out, expected,
                        "tc {}: re-encryption produced different ct||tag",
                        tc.tc_id
                    );
                }
                TestResult::Invalid => {
                    assert!(
                        dec_res.is_err(),
                        "tc {}: invalid vector unexpectedly decrypted",
                        tc.tc_id
                    );
                }
                TestResult::Acceptable => unreachable!("already filtered"),
            }
        }
    }

    stats
}

#[test]
fn wycheproof_chacha20_poly1305() {
    let stats = run(TestName::ChaCha20Poly1305, &CHACHA20_POLY1305);
    assert!(
        stats.ran > 50,
        "expected a meaningful number of vectors; got ran={}",
        stats.ran
    );
    eprintln!(
        "ChaCha20-Poly1305: ran={}, skipped_nonce={}, skipped_acceptable={}",
        stats.ran, stats.skipped_nonce, stats.skipped_acceptable
    );
}

#[test]
fn wycheproof_aes_256_gcm() {
    let stats = run(TestName::AesGcm, &AES_256_GCM);
    assert!(
        stats.ran > 50,
        "expected a meaningful number of vectors; got ran={}",
        stats.ran
    );
    eprintln!(
        "AES-256-GCM: ran={}, skipped_nonce={}, skipped_acceptable={}",
        stats.ran, stats.skipped_nonce, stats.skipped_acceptable
    );
}
