# Cryptographic Design

## Primitive matrix

| Function | Classical | PQC | Combiner |
|----------|-----------|-----|----------|
| Key exchange (TLS 1.3) | X25519 | ML-KEM-768 (FIPS 203) | HKDF-SHA384 concat-KDF |
| Signature (SVID, STH, child tokens) | Ed25519 | ML-DSA-65 (FIPS 204) | Composite, AND-combiner |
| Signature (X.509-SVID) | Ed25519 (RFC 8410) | ML-DSA-65 in `altSignatureValue` | Side-by-side; see below |
| AEAD | ChaCha20-Poly1305 | — | — |
| Hash | SHA3-384 | — | — |
| TPM attestation | ECDSA-P256 over SHA-384 | — | — |

## Why hybrid

The system must survive both:

- a classical break of one of the primitives (e.g. an implementation flaw in
  ML-DSA discovered before quantum hardware exists), and
- a quantum break of ECC.

We therefore combine classical and PQC under an **AND-combiner**: both
signatures must verify, both KEMs must agree on the session secret. A break
in either side alone does not forge a signature or recover a session key.

## Composite signature

```
CompositeSignature ::= SEQUENCE {
    algorithm    OID,           -- id-composite-MLDSA65-Ed25519
                                --   = 2.16.840.1.114027.80.8.1.7
    classical    OCTET STRING,  -- Ed25519, 64 bytes
    pqc          OCTET STRING   -- ML-DSA-65, 3309 bytes
}
```

The message hashed by both primitives is:

```
H = SHA3-384( "FERROGATE-COMPOSITE-v1" || len(ctx) || ctx || msg )
```

The context string `ctx` provides domain separation between SVIDs, STHs, child
tokens, and CSR-bound material so signatures cannot be reinterpreted across
contexts.

## Standard-format signatures for X.509

The composite form above is FerroGate-native: no deployed TLS stack can verify
it. The X.509-SVID profile (see [features/F17](features/F17-x509-svid.md))
therefore carries the two primitives **side by side** rather than combined, so
an off-the-shelf verifier can validate the certificate chain:

| Field | Algorithm | Covers |
|---|---|---|
| `signatureAlgorithm` / `signatureValue` | `id-Ed25519` (1.3.101.112), RFC 8410 | the complete DER `TBSCertificate` |
| `altSignatureValue` (2.5.29.74) | `id-ml-dsa-65` (2.16.840.1.101.3.4.3.18) | the `TBSCertificate` with that extension absent, ITU-T X.509 (2019) §9.8 |

Both are *raw* signatures over the message — no `FERROGATE-COMPOSITE-v1`
transcript. The ML-DSA-65 half instead uses the FIPS-204 context string
`ferrogate-x509-svid-v1`, and the Ed25519 half relies on a length invariant for
its domain separation: a composite signature always covers exactly the 48-byte
transcript hash `H`, so `ferro_crypto::composite`'s standard-format signers
**refuse** a 48-byte message. The two message spaces are disjoint, and a
signature from one can never be replayed as the other.

The trust bundle's ML-DSA half uses FIPS-204's *deterministic* variant (`rnd = 0`,
approved by §3.4) so every CMIS replica publishes byte-identical anchor DER.
Everything else — leaf certificates included — uses the hedged default.

## Hybrid TLS key exchange

We use the IETF draft `X25519MLKEM768` named group (codepoint `0x11EC`). The
shared secret is:

```
ss = HKDF-SHA384(
        salt = "ferrogate-hybrid-v1",
        ikm  = ss_x25519 || ss_mlkem768,
        info = transcript_hash )
```

Concatenation order is fixed: classical first, PQC second, matching the
IETF hybrid-design draft. The classical secret is included so a flaw in
ML-KEM cannot weaken the session, and vice versa.

In production CMIS refuses any other named group; falling back to pure-X25519
is a configuration-only escape hatch for dev environments.

For the live wiring — how the CMIS listener terminates this transport, how the
MIA pins the server, and how to configure both — see
[transport-tls.md](transport-tls.md).

## Key sizes and wire impact

| Object | Bytes | Notes |
|--------|-------|-------|
| Ed25519 public key | 32 | |
| ML-DSA-65 public key | 1952 | |
| Composite public key | 1984 | |
| Ed25519 signature | 64 | |
| ML-DSA-65 signature | 3309 | |
| Composite signature | 3373 | |
| ML-KEM-768 ciphertext | 1088 | per TLS handshake |
| ML-KEM-768 public key | 1184 | |

SVID JWS payloads are therefore noticeably larger than classical equivalents
(~4 KB vs ~200 B). This is acceptable for machine-to-machine use, where tokens
are short-lived and traffic is amortised over many requests.

## Library choices

- `rustls` ≥ 0.23 with `aws_lc_rs` backend and `rustls-post-quantum` ≥ 0.2 for
  hybrid groups.
- `fips204` and `fips203` from RustCrypto for ML-DSA / ML-KEM.
- `ed25519-dalek` for classical signatures (strict verification).
- `sha3` for SHA3-384.
- `ring` for system RNG; `zeroize` for sensitive material.

No `unsafe` is permitted in FerroGate crates (see
[`AGENTS.md`](../AGENTS.md)); cryptographic primitives are taken from audited
upstreams only.
