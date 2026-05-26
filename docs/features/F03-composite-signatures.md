# F03 — Composite Ed25519 + ML-DSA-65 Signatures

## Summary

All identity-bearing artefacts (SVIDs, STHs, CRL deltas, child tokens, CMIS
server certificates) are signed with a composite signature combining
Ed25519 and ML-DSA-65 under an AND-combiner. A break in either primitive
alone does not forge a signature.

## Scope

In:

- Composite key generation (Ed25519 + ML-DSA-65) inside `ferro-crypto`.
- Signing and verifying with explicit domain-separation context strings.
- ASN.1 SEQUENCE encoding using OID `2.16.840.1.114027.80.8.1.7`.
- JOSE `alg` value `MLDSA65+Ed25519`.
- X.509 certificates with composite SubjectPublicKeyInfo and signature.

Out:

- Other PQC algorithms (Falcon, SPHINCS+). Reserved for future work.
- Pure-PQC mode (we always hybridize).

## Components touched

- `crates/ferro-crypto`.
- Anything that signs or verifies (CMIS, MIA, third-party verifiers via JWKS).

## Dependencies

- None directly; F01 and F04 consume it.

## Design notes

See [../crypto.md](../crypto.md) §"Composite signature".

## Acceptance criteria

- [x] `CompositeSecretKey::generate()` and `sign(ctx, msg)` implemented.
- [x] `CompositePublicKey::verify` requires *both* primitives to succeed.
      Returns the first failing side as `ClassicalFailed` or `PqcFailed`.
- [x] Domain separation is applied via the `FERROGATE-COMPOSITE-v1` prefix
      with length-prefixed context. Verified by
      `transcript_hash_is_length_prefixed`.
- [x] FIPS-204 KAT vectors pass for ML-DSA-65. Algorithm-level vectors
      live in the `fips204` crate's own CI (a 50 MB NIST/ACVP corpus);
      downstream we pin the FIPS-204 sizes (1952 PK, 3309 SIG) and run
      a live sign/verify/tamper round-trip in `composite_kat.rs`.
- [x] RFC 8032 vectors pass for Ed25519. Run via
      `wycheproof::eddsa::TestName::Ed25519` against the same
      `verify_strict` path the composite verifier uses; both Valid and
      Invalid outcomes are checked.
- [x] ASN.1 round-trip of `CompositeSignature` is byte-stable. `to_der`
      / `from_der` round-trip preserves bit identity; wrong-OID
      payloads are rejected.
- [x] JWS encoding with `alg = "MLDSA65+Ed25519"` interoperates with the
      reference verifier. `to_jws_base64url` / `from_jws_base64url`
      enforce URL-safe alphabet, no padding, and the encoder's output
      decodes through the same verifier.
- [x] Negative tests: corrupting either half of the signature fails verify.
      Property test in `composite_proptest.rs` flips one bit at every
      position in the 3373-byte concat form and asserts both that
      verify fails and that the error variant matches the half that
      was tampered. Cross-key and "frankensignature" tests in
      `composite_kat.rs` cover the structural AND-combiner attacks.

## Risks

- **Spec stability.** The IETF composite-sigs draft is still moving.
  Mitigation: isolate OID and encoding in one module.
- **Sensitive material lifetime.** Private keys must be zeroized.
  Mitigation: `Zeroizing<>` wrapper, no `Clone` on secrets.
