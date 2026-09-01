# F17 — X.509-SVID Profile

## Summary

CMIS issues a **second SVID profile** beside the JWS one: a SPIFFE X509-SVID
certificate, minted from the same attestation, bound to the same host key, and
signed by the same issuer key. Its native signature is a standard RFC 8410
Ed25519 signature over the `TBSCertificate`, so rustls, OpenSSL, Envoy, or any
other stock TLS stack validates the chain unaided — which is the point: the JWS
profile cannot be used for mTLS. The ML-DSA-65 half of the signature is not
given up: it rides in the ITU-T X.509 (2019) §9.8 *alternative signature*
extensions, and `ferro-svid-verify` requires it.

Both profiles are always issued together and both are always served. Nothing
about the JWS profile changes.

## Scope

In:

- `ferro_svid::x509` — leaf and signing-certificate issuance.
- Hybrid signing: native Ed25519 plus ML-DSA-65 in `subjectAltPublicKeyInfo`
  (2.5.29.72), `altSignatureAlgorithm` (2.5.29.73), `altSignatureValue`
  (2.5.29.74), all non-critical.
- SPIFFE X509-SVID shape: SPIFFE ID as the sole URI SAN, `CA:FALSE`,
  `keyUsage = digitalSignature`, `extKeyUsage = serverAuth, clientAuth`.
- Subject key = the Ed25519 half of the host's phase-4 composite CSR key, with
  the ML-DSA-65 half in `subjectAltPublicKeyInfo`.
- Trust bundle: a self-signed CMIS signing certificate, published in the JWKS
  `x-ferrogate-x509-bundle` member, so one JWKS fetch arms a verifier for both
  profiles.
- `SVIDBundle.x509_svid` / `.x509_bundle` on the wire.
- `ferro_svid_verify::x509` — fail-closed reference verifier requiring **both**
  signature halves, plus the F11 CRL gate.
- Revocation parity: `RevokeSvid` on a JWS digest also revokes the certificate
  issued with it; `RevokeHost` already covers both.
- **Machine-bound storage on the host** (`mia::credstore`): the leaf, the
  bundle, and the Ed25519 private key sealed in `<state-dir>/x509-svid.sealed`
  under a key that only this machine can recover — TPM-sealed to PCRs
  `{0,4,7,8}` where there is a TPM, wrapped to a macOS Secure Enclave key where
  there is one, and derived from the hardware fingerprint otherwise.
  Fail-closed load, and `mia x509-svid` to inspect it.

Out:

- **Serving the credential to a workload.** The certificate and key are stored
  and can be inspected, but nothing hands them to a local application yet. That
  belongs to the helper API (F08), which already authenticates callers — writing
  an unsealed PEM pair to disk for anyone to read would undo the sealing. Until
  then a workload cannot do mTLS with the host's X.509-SVID.
- **Reusing the stored credential to skip attestation.** The store never decides
  whether to attest; the daemon attests on every start and overwrites the file.
  Short-circuiting that is F04's dormant SVID-cache work, with its own
  re-attestation-window rules.
- **Cross-sign windows.** During an F14 root rotation the JWKS publishes both
  roots' JWKs but only the live root's X.509 anchor, because a CMIS node cannot
  build a signing certificate for a root whose private key it does not hold.
  Certificates minted under the outgoing root must be re-issued (a rotation
  already forces re-attestation) rather than cross-validated. Emitting the
  incoming root's anchor from the offline ceremony would close this.
- Intermediate CAs. The bundle signs leaves directly.
- SPIFFE Workload API / SDS surface.

## Components touched

- `crates/ferro-crypto` — `sign_interop_*` / `verify_interop_*`: standard-format
  Ed25519 and ML-DSA-65 signatures, outside the composite transcript.
- `crates/ferro-svid` — the `x509` module; `Issuer::issue` mints both profiles;
  `Issuer::x509_ca`; `JwkSet::with_x509_bundle`.
- `crates/ferro-svid-verify` — the `x509` module.
- `crates/ferro-proto` — `SVIDBundle` fields 5 and 6.
- `crates/cmis` — issuance wiring, JWKS publication, replicated-store fields,
  paired revocation.
- `crates/ferro-sep` — `seal_bytes` / `unseal_bytes`: the machine-key AEAD
  envelope, generalised from the machine-key scalar to arbitrary payloads with a
  purpose tag (the old format is a purpose-empty envelope, so existing key files
  still open).
- `crates/mia` — `credstore` (the sealed store), `x509_svid` (the inspection
  subcommand), and the persist/report hooks in the daemon.
- `crates/ferro-sep` — `enclave::SecureEnclaveSealKey`: the macOS Secure Enclave
  used as a wrapping root, behind the `secure-enclave` feature.
- `Makefile` / `crates/mia/dist/mia.entitlements` — `make pkg-macos` builds with
  `secure-enclave` and codesigns the binary when `CODESIGN_ID` is set.

## Dependencies

- F03 (composite signatures), F04 (SVID issuance and lifecycle), F11
  (revocation, for the CRL gate).

## Design notes

### Why the signature is hybrid rather than composite

Every other FerroGate artefact carries a composite signature under
`id-composite-MLDSA65-Ed25519` over a FerroGate transcript hash. A certificate
signed that way would be unverifiable by every deployed TLS stack, which would
defeat the only reason to want an X509-SVID. So the certificate carries the two
primitives side by side instead of combined:

| Consumer | Verifies | Assurance |
|---|---|---|
| Stock TLS stack | native Ed25519 | classical |
| `ferro-svid-verify::x509` | both halves | classical **and** post-quantum |

There is no PQ-only path, and no way to strip the classical half — so this is
never weaker than a plain Ed25519 certificate, and is stronger for consumers
that opt in.

### Two-pass signing

ITU-T X.509 (2019) §9.8 fixes the order: the alternative signature covers the
`TBSCertificate` with `altSignatureValue` **absent** (the other two extensions
present); the native signature then covers the completed body. A verifier
reproduces the first encoding by dropping that one extension and re-encoding —
DER is canonical, so the bytes match exactly.

### Domain separation

`ferro_crypto::composite` only ever signs a 48-byte transcript hash. The
standard-format signers refuse a message of exactly that length, so the interop
and composite message spaces are disjoint by construction and a signature from
one can never be replayed as the other. The ML-DSA-65 half additionally uses the
FIPS-204 context string `ferrogate-x509-svid-v1`.

### A reproducible trust bundle

The signing certificate takes nothing from the clock: its window is the fixed
2020-01-01 … 2049-12-31 anchor, its serial is derived from the issuer key and
trust domain, and its ML-DSA half uses FIPS-204's *deterministic* variant. So
every replica sharing an issuer seed publishes byte-identical bundle DER, and a
client that pinned one replica's anchor is not surprised by another's. Leaves
keep the hedged (randomised) variant — there is nothing to reproduce, and hedged
signing is more robust.

### Storing the credential on the host

The certificate is public; the private key is not, and a credential lying in a
file is a credential that walks off on a cloned disk. So the whole credential
goes into one AEAD-sealed file whose data-protection key cannot be recovered
elsewhere:

| Backend | Data-protection key | Opens only |
|---|---|---|
| `tpm` | random, sealed by the TPM to PCRs `{0,4,7,8}` | on this TPM, in this boot state |
| `secure-enclave` | random, ECIES-wrapped to a non-exportable macOS Secure Enclave key | on this Mac's Enclave |
| `machine-key` | HKDF over the hardware fingerprint `H` (F16) | on a host with this fingerprint |

A hardware root wins even on a host that attests through the software tier, in
the order above. A host with none of them gets no store at all — writing the key
in the clear is worse than re-attesting. All three share one envelope
(`ferro_sep::seal_bytes`) under distinct purpose tags, so a blob sealed for one
use cannot be presented as another.

**The Secure Enclave is the Mac's TPM.** `mia` generates a P-256 key inside the
Enclave (non-exportable, root included) and encrypts the store's key to its
public half; only the Enclave can decrypt. Two constraints shape the design:

- The Enclave *crypto* needs no privileges — generating a key and doing
  ECIES wrap/unwrap works on an ordinary unsigned build, which is what the live
  tests exercise.
- **Persisting** the key does. macOS returns `errSecMissingEntitlement` (-34018)
  to any binary without a keychain-access-group entitlement, for both the
  data-protection and the file keychain, and with Apple's canonical
  private-key-only-permanent recipe as well. Ad-hoc signing does not help: the
  entitlement is restricted, so AMFI kills the process at launch. A production
  `mia` must therefore be signed by a real Apple Developer team —
  `make pkg-macos CODESIGN_ID=...` does this, using
  `crates/mia/dist/mia.entitlements`.

Because a non-persistent Enclave key would leave the next start unable to open
its own store, `with_sealer` only selects this backend when it can actually
persist the key; otherwise it falls through to `machine-key` and says so.

Only the Ed25519 half of the host's composite key is stored, as PKCS#8: it is
the half the certificate names and the only one a TLS stack needs. Loading is
fail-closed — unseal, then re-verify the certificate against its bundle, its
expiry, and the stored key — and a store that fails is deleted rather than
retried forever. On a TPM host a firmware update therefore invalidates the
stored credential, exactly as it invalidates the F04 SVID cache.

## Acceptance criteria

- [x] One attestation yields both profiles with the same SPIFFE ID and the same
      validity window.
      (`ferro-svid::issue::tests::issue_mints_both_profiles_over_the_same_identity_and_window`.)
- [x] A leaf validates under the reference verifier against the published
      bundle. (`ferro-svid/tests/x509_profile.rs::issued_certificate_validates_against_the_published_bundle`.)
- [x] Both profiles verify from a single JWKS fetch.
      (`both_profiles_verify_from_the_same_jwks_fetch`.)
- [x] A stack that shares no code with the issuer parses the leaf, matches the
      chain, and verifies the native signature.
      (`a_stock_x509_parser_reads_the_leaf_and_checks_its_chain`, using
      `x509-parser` with its own `ring`-backed verifier.)
- [x] Removing or corrupting either signature half fails verification.
      (`stripping_the_post_quantum_signature_is_refused`,
      `tampering_with_the_certificate_is_caught`.)
- [x] A certificate from another issuer or another trust domain is refused.
      (`a_certificate_from_another_issuer_is_refused`,
      `a_bundle_from_another_trust_domain_is_refused`.)
- [x] Expiry and not-yet-valid are enforced, with leeway.
      (`expired_certificate_is_refused`, `certificate_not_yet_valid_is_refused`.)
- [x] Revocation is fail-closed and covers both profiles.
      (`a_missing_crl_fails_closed`, `revoking_the_host_revokes_the_certificate_too`,
      `cmis/tests/revocation.rs::revoking_an_svid_also_revokes_the_x509_certificate_issued_with_it`.)
- [x] Every replica publishes the same trust bundle bytes.
      (`x509::tests::ca_is_byte_identical_across_issuers_sharing_a_seed`.)
- [x] A replicated record written before this feature still decodes, and renews
      with the JWS profile only.
      (`cluster_store::tests::a_record_written_before_the_x509_profile_still_decodes`,
      `issue::tests::x509_profile_is_skipped_without_a_subject_key`.)
- [x] The stored credential round-trips on the machine that wrote it and is
      unreadable anywhere else.
      (`mia::credstore::tests::roundtrips_on_the_same_machine`,
      `does_not_open_on_another_machine`.)
- [x] The sealed file never holds the certificate or key in the clear, and is
      `0600`. (`the_file_never_holds_the_key_in_the_clear`,
      `the_file_is_owner_only`.)
- [x] A store that unseals but no longer verifies — expired, wrong bundle, or a
      key that is not the certificate's — is refused.
      (`an_expired_credential_is_refused`,
      `a_credential_from_another_trust_domain_is_refused`,
      `a_key_that_does_not_match_the_certificate_is_refused`.)
- [x] On the TPM backend, a boot-state change makes the store unreadable on the
      machine that wrote it.
      (`mia/tests/swtpm_seal.rs::x509_credential_store_opens_only_in_the_boot_state_it_was_sealed_in`,
      against `swtpm`; Linux-only.)
- [x] On the Secure Enclave backend, a credential round-trips through real
      Enclave hardware and does not open under a different Enclave key.
      (`mia::credstore::tests::secure_enclave::*` and
      `ferro_sep::enclave::seal_tests::*`, run unsigned on an Apple Silicon Mac.)
- [x] An Enclave-sealed store is refused outright when opened with a weaker
      backend, rather than silently downgraded.
      (`an_enclave_sealed_store_does_not_open_with_the_machine_key`.)
- [ ] Enclave key persistence across processes. Needs a codesigned binary, so it
      cannot run in an ordinary build:
      `ferro_sep::enclave::seal_tests::persistent_seal_key_round_trips` is
      `#[ignore]`d and documented.
- [x] The exported PKCS#8 key loads in a stock TLS stack and matches the
      certificate's subject key.
      (`ferro-crypto::composite::tests::exported_pkcs8_loads_in_a_stock_tls_stack`.)

## Risks

- **A stock stack only checks the classical half.** Mitigation: this is stated,
  not hidden — the table above is the contract. A deployment that needs PQ
  assurance on the certificate path verifies with `ferro-svid-verify::x509`, or
  keeps using the JWS profile.
- **Re-encoding drift.** The alternative signature depends on the verifier
  reproducing the issuer's pre-signature DER. Mitigation: the `Any`-preserving
  ASN.1 types make the roundtrip byte-exact, and
  `alt_signature_covers_the_body_without_the_alt_signature_extension` asserts it
  against real issued bytes.
- **Certificate size.** Both halves of an ML-DSA-65 key and signature push a
  leaf to roughly 5.5 KB, which lands in the TLS handshake and in every
  replicated issued-SVID row. Mitigation: measured and accepted; the JWS profile
  remains the smaller option for consumers that do not need mTLS.
- **Private key material at rest.** Sealing moves the risk rather than removing
  it: on the `machine-key` backend anyone who can read both the store and the
  host's hardware identifiers can open it, and on any backend root on a running
  host can ask the daemon's own machinery to unseal. Mitigation: the
  TPM backend is preferred wherever available, the file is `0600`, only the
  classical half is stored, and nothing writes an unsealed copy — `mia
  x509-svid` deliberately refuses to print the key.
- **The 2049 cliff.** `UTCTime` ends there; the encoder switches to
  `GeneralizedTime` past it, but the bundle anchor stops at 2049-12-31 and would
  need re-anchoring. Mitigation: `time_switches_to_generalized_time_in_2050`
  pins the encoder behaviour; the anchor is a one-constant change.
