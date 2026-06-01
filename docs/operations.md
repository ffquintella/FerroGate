# Operations

## Bootstrapping a new host (zero-touch)

1. **Factory.** TPM vendor provisions and signs the EK certificate at
   manufacture, burning it into TPM NV storage.
2. **Fleet manifest.** The fleet owner publishes an offline-signed manifest
   listing the SHA-384 of every accepted EK certificate. CMIS loads this
   manifest on startup and refreshes it from a signed S3 object.
3. **First boot.** The MIA reads the EK certificate and connects to CMIS
   over hybrid-PQC TLS (server-auth only; the client has no identity yet).
4. **Pre-admission check.** CMIS looks up `SHA-384(ek_cert)` in the active
   fleet manifest *before* any TPM verification work runs. Unknown hosts are
   rejected immediately (`HostRejected` audit event); enrolled hosts are logged
   (`HostEnrolled`) and proceed. The EK chain to a vendor root is then verified
   as part of phase 2 quote validation.
5. **Attestation.** Protocol phases 2–4 run; on success the SVID is delivered
   and the MIA seals it to PCRs `{0, 4, 7, 8}`.

There is no shared secret or pre-distributed credential between the host and
CMIS at any point. The whole bootstrap is anchored in the vendor signature
on the EK cert.

### Operating the fleet manifest

- **Build and sign** with the offline `fleet-manifest` tool. `keygen` derives a
  publisher keypair from a 32-byte master seed (keep the seed air-gapped; only
  it is secret). `new` / `add` / `remove` edit an unsigned manifest; `sign`
  emits the composite-signed bundle; `verify` / `show` inspect it.
- **Configure CMIS** with `CMIS_FLEET_MANIFEST` (path to the signed bundle),
  `CMIS_FLEET_SIGNER_KID`, and `CMIS_FLEET_SIGNER_PUB` (the publisher public key
  as concat-bytes hex, printed by `keygen`). With `CMIS_FLEET_MANIFEST` unset,
  enrolment is **unenforced** and every host that can attest is admitted. A
  configured-but-unloadable manifest aborts startup (fail-closed).
- **Refreshes are atomic.** A newer manifest is verified and hot-swapped under a
  write lock, so in-flight attestations see a consistent enrolment snapshot. The
  current file-watcher stands in for the signed-S3 refresh (M5 follow-on), which
  reuses the same verify-then-swap path.

## SVID rotation

- At 60% of TTL the MIA performs a `Rotate` RPC. If PCRs and `policy_id` are
  unchanged and the previous full attestation was less than 24 h ago, no TPM
  interaction is required.
- At 24 h since last full attestation, the next rotation forces the full
  four-phase handshake regardless of PCR drift.
- Any PCR change detected at boot invalidates the cached SVID (sealing breaks)
  and forces full re-attestation.

## Revocation

- CMIS publishes a composite-signed CRL delta every 60 s as a JWKS extension
  (`x-ferrogate-crl`). The CRL is signed with the composite issuance key under
  the `ferrogate-crl-v1` domain context and verified against the issuer key the
  same JWKS publishes.
- Operators revoke through the `MachineIdentity` admin RPCs (authenticated as
  operator actions at the transport):
  - `RevokeSvid(cert_sha, reason)` — revoke one SVID by the lowercase-hex
    `SHA-384` of its compact JWS.
  - `RevokeHost(spiffe_id, reason)` — revoke every SVID and child token for a
    host.
  Each revocation is recorded in the audit log (`SvidRevoked` / `HostRevoked`,
  with the reason opcode) and republishes the CRL immediately, so the change
  reaches consumers within one publish cycle rather than after the next tick.
- The MIA refuses to mint helper tokens if the cached CRL is missing or more
  than 5 minutes old (fail closed), and refuses if the CRL revokes its own
  host. The independent reference verifier (`ferro-svid-verify`) likewise
  rejects a revoked SVID, requiring a fresh, signature-valid CRL to make the
  decision.
- CRL entries are pruned once they age past the 1 h max SVID TTL: a revoked
  artefact can never reappear after expiry, so dropping the entry bounds CRL
  growth.
- For mass revocation (compromised RIM generation, vulnerable kernel image),
  the operator increments the `policy_id` epoch. All SVIDs whose
  `attest.policy_id` does not match the active epoch become invalid at next
  rotation; the global audit log records the epoch bump.

## Root key rotation

The composite issuance key is rotated annually in an air-gapped ceremony:

1. Quorum of 3-of-5 trusted operators assembles in a Faraday-shielded room.
2. The offline signer device produces a new composite root keypair inside an
   attested enclave; participants are video-recorded.
3. The new root signs the old root, and the old root signs the new root, for
   a 90-day cross-sign window.
4. JWKS publishes both roots during the cross-sign window with the new root
   listed first; verifiers prefer the newer key.
5. After the window, the old key is destroyed by zeroising all five Shamir
   shares simultaneously.

## Adding a CMIS replica

1. Provision a node in a supported TEE (SEV-SNP or TDX).
2. The new node generates an attestation report and presents it to the
   existing Raft quorum.
3. Quorum members verify the report against the approved CMIS measurement
   allowlist; on success they sealed-deliver a key share to the new node.
4. The new node joins the Raft cluster and begins serving traffic after
   one heartbeat interval.

## Removing a CMIS replica

1. Operator decommissions the node via the operations API (signed command).
2. Remaining quorum issues a `KeyShareRevoked` event and reissues fresh
   shares to the survivors. The departing node's share is no longer one of
   the valid 5; it cannot participate even if its enclave is preserved.

## Disaster recovery

- Loss of any single region: traffic shifts to the remaining regions via
  anycast; no operational action required.
- Loss of all but one region: the surviving region continues issuing SVIDs as
  long as a 3-of-5 share quorum is reachable. If quorum is lost, issuance
  halts; existing SVIDs remain valid until expiry, providing a graceful
  degradation window of up to one TTL (1 hour).
- Loss of quorum permanently: the offline root key ceremony provisions a
  new composite issuance key and re-seeds shares. All hosts must re-attest
  at next rotation.

## Day-2 SRE concerns

- **Metrics.** Issuance latency p50/p99, attestation failure breakdown,
  CRL freshness, Raft commit lag, STH publish lag.
- **Alerts.** STH publish lag > 5 min, key-share reconstruction failure,
  RIM allowlist age > 24 h since last refresh, helper API denial rate spike.
- **Capacity.** The dominant cost is ML-DSA-65 signing (~1 ms on modern
  cores). A single CMIS replica handles ~1000 full attestations / second
  before saturating one core.
