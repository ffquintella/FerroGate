# Attestation Protocol

A host obtains an SVID through a four-phase streaming gRPC handshake. All
phases run over a hybrid post-quantum TLS 1.3 channel (see [crypto.md](crypto.md)).

## Sequence

```
MIA                                           CMIS
 │                                             │
 │── ClientHello (X25519 + ML-KEM-768) ───────▶│   Phase 1
 │◀──────────────── ServerHello ───────────────│   PQC TLS established
 │                                             │
 │── AttestRequest::Init                       │   Phase 2
 │    { ek_cert, aik_pub, pcr_quote, nonce } ─▶│   verify quote,
 │                                             │   match PCRs to RIM,
 │                                             │   append audit
 │                                             │
 │◀── AttestResponse::Challenge                │   Phase 3
 │    { credential_blob, secret_blob } ────────│   (cred-activation)
 │                                             │
 │── AttestRequest::ChallengeResp              │
 │    { decrypted_secret } ───────────────────▶│   constant-time compare
 │                                             │
 │── AttestRequest::Csr                        │   Phase 4
 │    { composite_pub, dpop_jkt, aik_sig } ───▶│   verify TPM-bound CSR,
 │                                             │   issue composite-signed SVID,
 │                                             │   append audit
 │◀── AttestResponse::Svid { bundle } ─────────│
```

## Phase 1 — Transport

- ClientHello advertises `X25519MLKEM768` (IANA codepoint `0x11EC`) as the only
  acceptable named group in production.
- The MIA pins CMIS SPKI hashes (SHA-384 of the SubjectPublicKeyInfo) from
  `/etc/ferrogate/mia.toml`. A mismatch aborts before any TPM operation.
- The CMIS certificate itself is a composite (Ed25519 + ML-DSA-65) X.509.

## Phase 2 — Hardware and boot attestation

The MIA sends:

- **`ek_cert`** — the TPM Endorsement Key certificate as burned in at
  manufacture. Must chain to one of the configured vendor roots.
- **`aik_pub`** — an Attestation Identity Key freshly generated as a restricted
  signing child of the EK. Required attributes: `fixedTPM=1`, `fixedParent=1`,
  `sensitiveDataOrigin=1`, `restricted=1`, `sign=1`, `decrypt=0`.
- **`pcr_quote`** — a `TPM2_Quote` over the policy PCR set (see
  [tpm.md](tpm.md)) with the server-supplied 32-byte nonce as `qualifyingData`.

CMIS verification (in order, fail-closed):

1. `ek_cert` chains to a vendor root.
2. `aik_pub` satisfies the required attribute mask.
3. `quote.magic == TPM_GENERATED_VALUE` and `type == TPM_ST_ATTEST_QUOTE`.
4. `quote.extraData == nonce`.
5. Recomputed PCR digest equals `quote.pcrDigest`.
6. ECDSA signature over `SHA-384(quote_blob)` verifies under `aik_pub`.
7. PCR digest is found in the active RIM allowlist; record the resulting
   `policy_id`.

## Phase 3 — Credential activation (proof of residency)

A signed quote alone proves only that *some* TPM signed the blob. To prove the
AIK lives in the *same* TPM as the certified EK, CMIS:

1. Generates a random 32-byte `secret`.
2. Wraps it under the EK public key using the TCG-defined `MakeCredential`
   construction, producing `(credential_blob, secret_blob)`.
3. Sends both to the MIA.

The MIA calls `TPM2_ActivateCredential` with the AIK and EK handles. The TPM
will only release `secret` if the AIK truly resides in the TPM whose EK
unwrapped the blob. The MIA returns `secret` to CMIS, which compares in
constant time.

## Phase 4 — CSR and issuance

The MIA generates a fresh composite keypair (Ed25519 + ML-DSA-65) and submits:

- `composite_pub` — the public key.
- `dpop_jkt` — thumbprint of the DPoP public key (binds the SVID).
- `aik_sig` — a TPM signature over `SHA-384(composite_pub)` using the AIK,
  proving the composite key is bound to this hardware.

CMIS verifies `aik_sig` and issues a JWS SVID with:

- `iss = spiffe://ferrogate.<env>/cmis`
- `sub = spiffe://ferrogate.<env>/host/<uuid>` where `uuid` is derived from
  the EK cert SHA-384.
- `cnf.jkt = dpop_jkt`
- `attest = { ek_cert_sha384, pcr_digest_sha384, policy_id, tee_evidence_id }`
- Signature = composite (Ed25519 + ML-DSA-65), AND-combined.
- `exp - iat ≤ 3600 s`.

## Renewal vs re-attestation

- **Renewal** (≤24 h since last full attestation, PCRs unchanged): a single
  `Rotate` RPC over the existing PQC TLS channel returns a fresh SVID.
- **Re-attestation** (>24 h, or PCRs changed, or `policy_id` epoch bumped):
  full four-phase handshake required.
