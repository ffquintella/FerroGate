# TPM 2.0 Attestation Engine

## Roles of the TPM in FerroGate

The TPM 2.0 is used for three things and nothing else:

1. **Endorsement.** The factory-provisioned EK certificate, signed by the TPM
   vendor, anchors host identity in hardware.
2. **Quoting.** PCR state is signed by a freshly-created Attestation Identity
   Key (AIK) so CMIS can verify boot integrity.
3. **Credential activation.** `TPM2_ActivateCredential` proves the AIK lives
   in the same TPM as the EK.

The TPM does **not** perform PQC operations (TPM 2.0 has no ML-DSA or
ML-KEM support). The composite SVID keypair is generated in software inside
MIA and *bound* to the hardware by an AIK signature over its public key.

## PCR policy

| PCR | Measures | Allowed values |
|-----|----------|----------------|
| 0   | CRTM, BIOS firmware | vendor-pinned digest set |
| 1   | BIOS configuration (UEFI vars) | hash of expected vars |
| 2–3 | Option ROMs | empty or vendor-pinned |
| 4   | Bootloader (shim) | distro-signed |
| 5   | GPT / partition table | per-image |
| 7   | Secure Boot state, db / dbx | must indicate SB=ON |
| 8–9 | Kernel cmdline, initrd | signed manifest hash |
| 10  | IMA runtime measurement | rolling, signature-checked |
| 11  | LUKS unlock | indicates disk-encrypted boot |
| 14  | MOK list | enterprise CA only |

Approved PCR digests are bundled into **Reference Integrity Measurements
(RIM)**. CMIS keeps the current RIM plus the six prior generations to allow
in-flight rollouts; an explicit `policy_id` epoch bump can mass-invalidate
older measurements.

## AIK creation

```
template := {
    type:        TPM_ALG_ECC,
    nameAlg:     TPM_ALG_SHA256,
    objectAttributes: {
        fixedTPM:             1,
        fixedParent:          1,
        sensitiveDataOrigin:  1,
        userWithAuth:         1,
        restricted:           1,
        sign:                 1,
        decrypt:              0,
    },
    parameters: {
        symmetric:  TPM_ALG_NULL,
        scheme:     TPM_ALG_ECDSA with TPM_ALG_SHA256,
        curveID:    TPM_ECC_NIST_P256,
    }
}
```

The `restricted` flag is critical: a restricted signing key can only sign
TPM-generated structures (quotes, certifies), so it cannot be tricked into
signing attacker-chosen messages.

## Quote verification algorithm

CMIS implements `verify_quote(ek_cert, aik_pub, quote_blob, sig, nonce, rim)`:

1. Verify `ek_cert` chains to a configured vendor root.
2. Verify `aik_pub` satisfies the required attribute mask.
3. Verify `quote_blob.magic == TPM_GENERATED_VALUE` (`0xFF544347`).
4. Verify `quote_blob.type == TPM_ST_ATTEST_QUOTE`.
5. Verify `quote_blob.extraData == nonce`.
6. Compute `pcr_digest = SHA-384( concat(pcr_i for i in selection) )`.
7. Verify `pcr_digest == quote_blob.attested.quote.pcrDigest`.
8. Verify `sig` over `SHA-384(quote_blob)` with `aik_pub` (ECDSA-P256).
9. Look up `pcr_digest` in the RIM allowlist; obtain `policy_id`, else REJECT.
10. Proceed to credential activation (phase 3 of the protocol).

Each step is fail-closed: any failure terminates the handshake with a generic
`permission_denied` and an audit entry recording the precise reason.

## Sealing on the host

The MIA seals the issued SVID and its private key material to PCRs
`{0, 4, 7, 8}`. If the host boots into a different state, the unseal silently
fails and the MIA falls back to full re-attestation. There is no escape hatch:
sealed material cannot be recovered out-of-band.

## Session hygiene

All TPM commands the MIA issues use **HMAC-bound sessions** to defeat bus
interposer attacks. Sensitive commands (key creation, activation) additionally
use **policy sessions** with `TPM2_PolicySecret` against the endorsement
hierarchy where required.

`/dev/tpmrm0` (the kernel resource manager) is used in preference to raw
`/dev/tpm0` so multiple TPM consumers on the host can coexist without object
eviction races.
