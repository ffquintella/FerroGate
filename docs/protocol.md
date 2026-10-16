# Attestation Protocol

A host obtains an SVID through a four-phase streaming gRPC handshake. All
phases run over a hybrid post-quantum TLS 1.3 channel (see [crypto.md](crypto.md)).
The choice of streaming gRPC for this handshake is recorded in
[ADR-0001](adr/0001-grpc-over-http-transport.md).

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

CMIS verifies `aik_sig` and issues **both SVID profiles** from this one
attestation. The JWS SVID carries:

- `iss = spiffe://ferrogate.<env>/cmis`
- `sub = spiffe://ferrogate.<env>/host/<uuid>` where `uuid` is derived from
  the EK cert SHA-384.
- `cnf.jkt = dpop_jkt`
- `attest = { ek_cert_sha384, pcr_digest_sha384, policy_id, tee_evidence_id }`
- Signature = composite (Ed25519 + ML-DSA-65), AND-combined.
- `exp - iat ≤ 3600 s`.

Alongside it, in the same `SVIDBundle`, comes the **X.509-SVID** (feature
[F17](features/F17-x509-svid.md)): a certificate with the same `sub` as its sole
URI SAN, the same validity window, `composite_pub`'s Ed25519 half as its subject
key and the ML-DSA-65 half in `subjectAltPublicKeyInfo`. Its native signature is
standard Ed25519, so a stock TLS stack can use the credential for mTLS; the
ML-DSA-65 half travels in `altSignatureValue`. The trust bundle to validate it
under is in `SVIDBundle.x509_bundle` and in the JWKS
`x-ferrogate-x509-bundle` member.

A client may use either profile or both; they name the same identity and expire
together.

### Revoked hosts (T295)

On both tiers, once the CSR signature has verified (the host has proven
possession of its keys) and before its child key is published or anything is
signed, CMIS derives the subject SPIFFE id exactly as it would stamp it and
refuses the attestation when the revocation working set holds a `RevokeHost`
entry for it:

- the stream ends with `PERMISSION_DENIED host_revoked`;
- the refusal is audited as `AttestFail { reason: "attest-host-revoked" }`;
- nothing is issued and the stored record is left as it was.

The reason code is returned, unlike other quote failures, because the host has
already authenticated and the CRL that names it is public. A `RevokeSvid`
entry does not block re-attestation: that is how a host recovers from one
leaked SVID. The SPIFFE id comes from the EK certificate digest (TPM tier) or
the machine fingerprint (host-key tier), so re-imaging or re-enrolling the same
hardware keeps the same id, and the host stays refused.

Known limits:

- **Per node.** The revocation working set is in memory on each CMIS node
  (`CmisState::revoke`; replication is T223). A replica that did not receive
  the `RevokeHost` still issues to the host, and a node restart clears its
  set. Until T223 lands, issue `RevokeHost` on every replica, and again on a
  replica after it restarts.
- **Expiry.** A host entry expires `CRL_ENTRY_TTL_SECS` (30 days, the maximum
  SVID lifetime) after its `revoked_at` and is pruned at the next CRL publish.
  The host can attest again after that. Issuing `RevokeHost` again refreshes
  `revoked_at`.
- **No un-revoke.** No RPC lifts a host revocation (follow-up T296). See
  `docs/operations.md` §"Revocation" for the operator procedure.
- **Client retries.** The MIA treats `PERMISSION_DENIED` from `Attest` as
  "not enrolled" and keeps trying; each attempt is refused and audited.
  While its revoked SVID is still valid, the renewal loop backs off from 30 s,
  doubling up to 15 minutes and never more than a quarter of the time left
  (`Rotate` is refused by host authentication, which sends it to `Attest`).
  Once the SVID has expired it retries about every 5 minutes (±10 %).

## Renewal vs re-attestation

- **Renewal** (host-key tier only, ≤24 h since the last full attestation,
  state digest and policy epoch unchanged): a single `Rotate` RPC over the
  existing PQC TLS channel returns a fresh SVID.
- **Re-attestation** (>24 h, or state changed, or `policy_id` epoch bumped,
  or any TPM-tier host): full four-phase handshake required.

`Rotate` is a host method (T293). The request carries the F19 §7.1 host proof
(`HostCallAuth`) over a canonical-CBOR `RotateDoc`:

```text
RotateDoc = { v: 1, host_uuid, issued_at, nonce[16],
              svid_sha384 = SHA-384(svid_jws), state_digest[48] }
sig       = ECDSA-P256(machine key, "ferrogate-rotate-v1" ‖ doc)
```

CMIS refuses, in order:

1. a missing or invalid proof — an SVID not issued by this CMIS, expired or
   revoked (by SVID digest or host), a key not matching `cnf.jkt`, a bad
   signature, a document naming another SVID or host, `issued_at` more than
   300 s off, a replayed nonce, or a host over `CMIS_ROTATE_MAX_PER_HOUR`
   (`UNAUTHENTICATED host_auth_failed`, `PERMISSION_DENIED host_mismatch`,
   `RESOURCE_EXHAUSTED rate_limited`); nothing is audited, the reason is
   logged;
2. a TPM-tier SVID: PCRs cannot be proven without a fresh quote, so the host
   re-attests (`FAILED_PRECONDITION`, audited `rotate-tier-requires-attest`);
3. an SVID that is not the latest one stored for the host
   (`rotate-superseded`), re-checked inside the store write so two racing
   renewals cannot both land;
4. a signed `state_digest` (the machine fingerprint) different from the last
   attestation, a bumped epoch or an expired window
   (`rotate-reattest-state-drift|epoch-bump|window-expired`).

A renewal is audited as `SvidIssued` and keeps the 24 h window anchored at the
last full attestation. `RotateRequest.pcr_values` and `known_epoch` are
deprecated and ignored: they are unsigned.

The nonce replay cache is per CMIS node, so a captured, still-fresh `Rotate`
replayed to another node can win the store swap before the real host's call:
the attacker gains only public material bound to the host's key (`cnf.jkt`),
and the real host gets `FAILED_PRECONDITION` and re-attests.

Because every SVID lifetime, the host-key one included, is floored at 96 h
(`MIN_TTL_SECS`) while the window is 24 h, a host that rotates at 60 % of its
TTL is past the window: renewal is then normally a full re-attestation, and
the short path only serves renewals inside the first 24 h after an `Attest`.

**Client behaviour (MIA, T294).** The daemon renews at 60 % of the TTL ±10 %
jitter. It sends `Rotate` only on the host-key tier and only while its own
record of the last full attestation is more than 10 minutes inside the 24 h
window; otherwise it runs `Attest` directly. `FAILED_PRECONDITION`,
`NOT_FOUND`, `UNAUTHENTICATED`, `PERMISSION_DENIED` and any undocumented code
send it to `Attest` at once; `UNAVAILABLE` and time-outs retry with a capped,
jittered back-off (30 s doubling, ≤ 15 min, never later than 60 s before
expiry); `RESOURCE_EXHAUSTED` waits `retry-after`. After 3 consecutive
transient failures, or in the last quarter of the SVID's lifetime, it runs
`Attest` instead. A `Rotate` gets 60 s and an `Attest` 2 minutes, both cut
short at expiry. It never retries the superseded SVID and never sends
`current_svid`.
