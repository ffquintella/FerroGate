# Runbook: CRL stale

**Alert.** `ferrogate_crl_age_seconds > 300` (the CRL a MIA holds is older than
5 minutes), or a spike in MIA helper-token denials with reason `CrlStale`.

**Severity.** High and **customer-facing**: a stale CRL makes the MIA refuse to
mint helper/child tokens (fail-closed). Applications relying on the helper API
stop getting tokens.

## What it means

CMIS publishes a composite-signed CRL delta as the `x-ferrogate-crl` JWKS
extension every **60 s** (`crates/cmis/src/crl_publisher.rs`), and republishes
immediately on every revoke. Each MIA caches the latest CRL and **fail-closed
gates** token minting on its freshness: if the cached CRL's `issued_at` is more
than **300 s** old (`CRL_MAX_AGE_SECS`, `crates/ferro-svid/src/crl.rs`), plus a
**60 s** clock-skew leeway (`CRL_FRESHNESS_LEEWAY_SECS`,
`crates/mia/src/helper/crl.rs`), the MIA refuses to mint (`CrlStale`).

So the alert means a MIA has not received a fresh, signature-valid CRL in over
5 minutes. Causes:

1. CMIS stopped publishing (publisher task dead, or CMIS down).
2. The MIA cannot reach CMIS to pull the JWKS+CRL.
3. CRLs are arriving but failing verification (unknown `kid`, wrong key,
   tampered body) — the MIA refuses to ingest them, so the cache goes stale.
4. Clock skew between MIA and CMIS larger than the 60 s leeway.

## Impact

- Affected MIAs deny new helper-token requests (`CrlStale`). Existing,
  unexpired child tokens keep working until they expire (≤ 600 s child TTL).
- SVID issuance/rotation via `Attest`/`Rotate` is **not** gated on CRL
  freshness — this affects the helper API, not core attestation.

## Diagnose

1. **Is CMIS publishing?**
   ```sh
   grpcurl -d '{}' cmis-a:8443 ferrogate.MachineIdentity/JWKS
   # Inspect x-ferrogate-crl: issued_at should be within the last 60 s,
   # number should advance over successive calls.
   ```
   If `issued_at` is old on CMIS itself, the publisher is stuck → roll the
   replica; it republishes immediately on startup.
2. **Can the MIA reach CMIS?** From the host: check connectivity to the CMIS
   endpoint and the SPKI pin (a rotated server cert with an un-updated pin would
   break the TLS handshake — see `crates/ferro-crypto/src/pin.rs`).
3. **Is the CRL verifying?** A CRL signed under a `kid` the MIA does not trust,
   or with a tampered body, is rejected by `SignedCrl::verify` and never
   ingested. Check MIA logs for verification failures. This typically follows a
   root-key rotation where JWKS has the new key but the CRL was signed by the
   old one (or vice versa).
4. **Clock skew.** Compare MIA and CMIS clocks; skew > 60 s past the max age
   trips the gate even with fresh CRLs. Confirm NTP health on both.

## Remediate

- **Publisher stuck / CMIS down** → restore CMIS (roll the replica; it
  republishes on startup). Within ~60 s MIAs see a fresh CRL and resume minting.
- **MIA→CMIS unreachable** → fix routing/LB; confirm the SPKI pin matches the
  served cert if a cert rotation just happened.
- **CRL fails verification** → reconcile the signing key with the JWKS. After a
  root rotation, ensure the CRL is signed under a key present in the published
  JWKS during the cross-sign window (F14 "newer preferred").
- **Clock skew** → fix NTP; do **not** widen the leeway as a workaround (the
  fail-closed gate is intentional).

## Escalate

If CRLs are arriving but failing verification fleet-wide, page security: a
signing-key/JWKS mismatch can indicate a botched or malicious key change.
Preserve a sample failing CRL for analysis.

## Verify recovery

On an affected host, confirm a helper-token mint succeeds and MIA logs show a
freshly ingested CRL (`issued_at` within the last minute, `CrlGate` open).
Denials with `CrlStale` should drop to zero.
