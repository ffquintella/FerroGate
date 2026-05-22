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

- [ ] `CompositeSecretKey::generate()` and `sign(ctx, msg)` implemented.
- [ ] `CompositePublicKey::verify` requires *both* primitives to succeed.
- [ ] Domain separation is applied via the `FERROGATE-COMPOSITE-v1` prefix
      with length-prefixed context.
- [ ] FIPS-204 KAT vectors pass for ML-DSA-65.
- [ ] RFC 8032 vectors pass for Ed25519.
- [ ] ASN.1 round-trip of `CompositeSignature` is byte-stable.
- [ ] JWS encoding with `alg = "MLDSA65+Ed25519"` interoperates with the
      reference verifier.
- [ ] Negative tests: corrupting either half of the signature fails verify.

## Risks

- **Spec stability.** The IETF composite-sigs draft is still moving.
  Mitigation: isolate OID and encoding in one module.
- **Sensitive material lifetime.** Private keys must be zeroized.
  Mitigation: `Zeroizing<>` wrapper, no `Clone` on secrets.
