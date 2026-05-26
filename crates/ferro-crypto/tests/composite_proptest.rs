//! Property tests for the composite signature (feature F03).
//!
//! Generates random `(ctx, msg, sig_corruption)` tuples and asserts:
//!
//! - A signature produced by [`CompositeSecretKey::sign`] always verifies
//!   under the matching public key.
//! - Flipping any single bit anywhere in the signature always breaks
//!   verification.
//! - Verification errors classify correctly: flips in the first 64 bytes
//!   surface as `ClassicalFailed`; flips in the remaining 3309 bytes
//!   surface as `PqcFailed`.

use ferro_crypto::composite::{
    CompositeError, CompositePublicKey, CompositeSecretKey, CompositeSignature, COMPOSITE_SIG_LEN,
    ED25519_SIG_LEN,
};
use proptest::prelude::*;

/// Build a fresh keypair once per test case. Keygen is fast enough
/// (~milliseconds) that doing it per case keeps each shrink case
/// independent.
fn keypair() -> (CompositeSecretKey, CompositePublicKey) {
    CompositeSecretKey::generate().expect("keygen")
}

proptest! {
    // Keep case counts modest — keygen + sign + verify dominates runtime.
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn sign_then_verify_always_succeeds(
        ctx in proptest::collection::vec(any::<u8>(), 0..64),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let (sk, pk) = keypair();
        let sig = sk.sign(&ctx, &msg).expect("sign");
        pk.verify(&ctx, &msg, &sig).expect("verify");
    }

    #[test]
    fn flipping_any_bit_breaks_verify(
        msg in proptest::collection::vec(any::<u8>(), 1..128),
        bit_index in 0usize..(COMPOSITE_SIG_LEN * 8),
    ) {
        let ctx = b"proptest-v1";
        let (sk, pk) = keypair();
        let sig = sk.sign(ctx, &msg).expect("sign");

        // Flip one bit in the concat representation, decode back, and
        // assert the AND-combiner rejects.
        let mut bytes = sig.to_concat_bytes();
        let byte = bit_index / 8;
        let bit = bit_index % 8;
        bytes[byte] ^= 1u8 << bit;
        let tampered = CompositeSignature::from_concat_bytes(&bytes).expect("decode");
        let res = pk.verify(ctx, &msg, &tampered);

        prop_assert!(res.is_err(), "tampered signature unexpectedly verified");

        // Classify the error: flips in the classical 64 bytes must yield
        // a ClassicalFailed error; flips beyond yield a PqcFailed error.
        // (verify_strict on ed25519-dalek runs first, so a classical
        // tamper is reported before the pqc check.)
        if byte < ED25519_SIG_LEN {
            prop_assert!(
                matches!(res, Err(CompositeError::ClassicalFailed)),
                "expected ClassicalFailed for byte index {byte}, got {res:?}"
            );
        } else {
            prop_assert!(
                matches!(res, Err(CompositeError::PqcFailed)),
                "expected PqcFailed for byte index {byte}, got {res:?}"
            );
        }
    }

    #[test]
    fn distinct_contexts_yield_unrelated_signatures(
        msg in proptest::collection::vec(any::<u8>(), 1..64),
        ctx_a in proptest::collection::vec(any::<u8>(), 0..16),
        ctx_b in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        prop_assume!(ctx_a != ctx_b);
        let (sk, pk) = keypair();
        let sig_a = sk.sign(&ctx_a, &msg).unwrap();
        prop_assert!(pk.verify(&ctx_a, &msg, &sig_a).is_ok());
        prop_assert!(
            pk.verify(&ctx_b, &msg, &sig_a).is_err(),
            "signature under ctx_a was accepted under ctx_b"
        );
    }
}
