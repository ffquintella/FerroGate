# Operations

## Bootstrapping a new host (zero-touch)

1. **Factory.** TPM vendor provisions and signs the EK certificate at
   manufacture, burning it into TPM NV storage.
2. **Fleet manifest.** The fleet owner publishes an offline-signed manifest
   listing the SHA-384 of every accepted EK certificate. CMIS loads this
   manifest on startup and hot-reloads it from a local file (a deployment that
   keeps it in object storage syncs it to that path out of band; the composite
   signature, not the transport, gates what is admitted).
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
  manifest is read from a local file; native S3 sourcing is dropped (see
  [roadmap.md](roadmap.md) §"Dropped scope") — sync from object storage to the
  watched path out of band if needed.

## Transport security (hybrid-PQC TLS)

All MIA→CMIS control-plane traffic runs over TLS 1.3 using the hybrid
`X25519MLKEM768` group only (feature F01). The shared rustls configs are built
by `ferro_crypto::transport::{server_config, client_config}`; the server
listener glue is `cmis::transport`, the client dialer is
`mia::client::connect_pinned`. See [transport-tls.md](transport-tls.md) for the
full how-it-works, the OpenSSL pin recipe, and troubleshooting.

- **CMIS server identity.** Configure the listener with `CMIS_TLS_CERT` (PEM
  certificate chain: end-entity first, then any intermediates) and
  `CMIS_TLS_KEY` (PEM private key — PKCS#8 / PKCS#1 / SEC1). Both must be set
  together; setting only one aborts startup, and setting neither falls back to
  a **plaintext** bring-up server (development only, logged as a warning). With
  TLS on, the listener advertises only `X25519MLKEM768`, so a non-PQC client
  fails the handshake before reaching the gRPC layer.
- **MIA pin provisioning.** The MIA does not trust a CA hierarchy; it pins the
  SHA-384 of the CMIS certificate's `SubjectPublicKeyInfo`. Compute the pin
  from the deployed cert with `ferro_crypto::pin::SpkiPin::from_certificate_der`
  (or its `to_hex`/`from_hex` round-trip) and hand the pin set to
  `connect_pinned`. A server whose SPKI hash is not pinned — or that does not
  speak the hybrid group — is rejected before any RPC.
- **Telemetry.** Every accepted connection logs `kx_group = X25519MLKEM768`.
  Operators confirm post-quantum coverage by asserting no accepted connection
  ever logs a non-hybrid group (which, under the hybrid-only provider, cannot
  occur — a downgrade attempt fails the handshake instead).
- **Certificate rotation.** Replace the cert/key files and restart (or
  hot-reload, when wired); update the MIA pin set to include the new SPKI pin
  ahead of the cutover so both old and new certificates verify during the
  overlap window.

## SVID rotation

- At 60% of TTL the MIA performs a `Rotate` RPC. If PCRs and `policy_id` are
  unchanged and the previous full attestation was less than 24 h ago, no TPM
  interaction is required.
- At 24 h since last full attestation, the next rotation forces the full
  four-phase handshake regardless of PCR drift.
- Any PCR change detected at boot invalidates the cached SVID (sealing breaks)
  and forces full re-attestation.

## RIM policy and epoch bump

- **RIM bundle.** CMIS maps attested PCR digests to a `policy_id` via a
  versioned, composite-signed RIM bundle (the active generation plus six prior).
  Configure it with `CMIS_RIM_BUNDLE` (path to the signed bundle file),
  `CMIS_RIM_SIGNER_KID`, and `CMIS_RIM_SIGNER_PUB` (publisher composite pubkey
  as concat-bytes hex). CMIS loads it fail-closed at startup and a watcher
  hot-swaps any strictly-newer signed bundle (verified before apply, atomic).
  With `CMIS_RIM_BUNDLE` unset the allowlist is empty and every quote fails the
  RIM lookup (`FAILED_PRECONDITION`) — fail-closed by default.
- **Native S3 sourcing is dropped** (see [roadmap.md](roadmap.md) §"Dropped
  scope"). The bundle is read from a local file; a deployment that keeps it in
  object storage syncs it to that path out of band. Because the bundle is
  composite-signed and verified before apply, that sync path is untrusted —
  only the signature gates what is admitted.
- **Epoch bump (mass re-attestation).** For a compromised RIM generation or a
  vulnerable kernel image, the operator calls the `BumpEpoch(reason)` admin RPC
  (authenticated as an operator action at the transport). It advances the live
  policy epoch and records a `PolicyEpochBumped` audit event. Every host whose
  last full attestation was under the previous epoch is refused at its next
  `Rotate` (`FAILED_PRECONDITION`) and driven back through a full four-phase
  `Attest`. The bump is process-local; replicating it across a cluster is a
  documented deployment seam.

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
  the operator bumps the policy epoch via `BumpEpoch` — see "RIM policy and
  epoch bump" above. Every host attested under the old epoch re-attests at its
  next rotation; the global audit log records the bump (`PolicyEpochBumped`).

## Caller allowlists

Each MIA host gates its helper API with a **signed caller allowlist** — the
`(uid, binary-SHA-384)` pairs allowed to mint child tokens. CMIS stores, signs,
and serves these per host; operators manage them with the `ferrogate allowlist`
commands. The issuer secret never leaves CMIS — the CLI submits entries and CMIS
signs them with the enrollment key.

- Allowlists are keyed by the host's **EK-derived UUID**
  (`ferro_svid::host_uuid_from_ek_digest`), so a host can be provisioned before
  it attests. Name the host with `--host <uuid>`, `--ek-cert <pem>`, or
  `--ek-sha384 <hex>`.
- Provision and edit:
  - `ferrogate allowlist set --host <uuid> --bin <uid>:<path>` — replace a host's
    allowlist (the CLI hashes the binary; `--entry <uid>:<sha384>` takes a
    precomputed hash).
  - `ferrogate allowlist add/remove …` — read-modify-write a single entry; CMIS
    re-signs.
- Inspect and retrieve:
  - `ferrogate allowlist show --host <uuid>` / `ferrogate allowlist list`.
  - `ferrogate allowlist get --host <uuid> --out allowlist.cbor` — fetch the raw
    signed CBOR to place at a host's `allowlist.path` (a MIA with `GetAllowlist`
    reachability can fetch it directly instead).
- `Set`/`Delete`/`ListAllowlists` are admin RPCs authenticated as operator
  actions at the transport, exactly like revocation; `GetAllowlist` is
  unauthenticated (the body is signature-protected and not secret). Each set or
  delete records an audit event (`AllowlistSet` / `AllowlistDeleted`). CMIS
  stamps a validity window (default one day, capped at 30); re-issue rather than
  mint long-lived lists. Full workflow: [allowlist-provisioning.md](allowlist-provisioning.md).

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

The step-by-step operator procedure — the `offline-signer` commands for each
step, the sealed-share/cross-sign/minutes formats, the destruction read-back,
and the staging dry-run — is in
[operations/root-key-ceremony.md](operations/root-key-ceremony.md) (feature F14).

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

The step-by-step drill procedures — with pre-flight, pass criteria, abort
paths, a runnable local rehearsal harness, and the drill log — are in
[operations/drills/](operations/drills/):
[region-loss](operations/drills/region-loss.md),
[mass-revocation](operations/drills/mass-revocation.md), and
[quorum-loss recovery](operations/drills/quorum-loss-recovery.md).

## Day-2 SRE concerns

- **Metrics.** Issuance latency p50/p99, attestation failure breakdown,
  CRL freshness, Raft commit lag, STH publish lag.
- **Alerts.** STH publish lag > 5 min, key-share reconstruction failure,
  RIM allowlist age > 24 h since last refresh, helper API denial rate spike.
  Per-alert response procedures are in [operations/runbooks/](operations/runbooks/):
  [STH lag](operations/runbooks/sth-lag.md),
  [CRL stale](operations/runbooks/crl-stale.md), and
  [key-share failure](operations/runbooks/key-share-failure.md).
- **Capacity.** The dominant cost is ML-DSA-65 signing (~1 ms on modern
  cores). A single CMIS replica handles ~1000 full attestations / second
  before saturating one core.
