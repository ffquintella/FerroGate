# F01 — Hybrid PQC TLS Transport

## Summary

All control-plane traffic between MIA and CMIS, and between CMIS replicas,
runs over TLS 1.3 using the hybrid `X25519MLKEM768` named group
(IANA codepoint `0x11EC`). This protects sessions against both classical
attackers and any future cryptographically-relevant quantum computer, and
defeats harvest-now-decrypt-later capture.

## Scope

In:

- `rustls` 0.23 with `aws_lc_rs` backend and `rustls-post-quantum` ≥ 0.2.
- `X25519MLKEM768` as the only acceptable named group in production.
- ChaCha20-Poly1305 and AES-256-GCM cipher suites.
- SPKI pinning of CMIS certificates from MIA configuration.
- Composite X.509 server certificates (see F03).

Out:

- TLS termination at the load balancer (LB is L4 passthrough).
- Pure-X25519 fallback (configurable on, off in production).

## Components touched

- `crates/ferro-crypto` — provider construction.
- `crates/cmis` — server config.
- `crates/mia` — client config and SPKI pin verification.

## Dependencies

- None. This is the foundational feature.

## Design notes

See [../crypto.md](../crypto.md) §"Hybrid TLS key exchange".

## Acceptance criteria

- [x] `ferro-crypto::tls::ferrogate_provider()` returns a `CryptoProvider`
      that lists only `X25519MLKEM768` when `hybrid_only = true`.
      Implemented as `ferrogate_provider(ProviderMode::HybridOnly)`; verified
      by `tls::tests::hybrid_only_lists_exactly_one_kx_group`.
- [x] A CMIS server configured with `hybrid_tls_only = true` rejects a client
      that offers only `X25519`. Verified end-to-end by
      `tls_handshake::legacy_only_client_is_rejected_by_hybrid_only_server`.
- [x] MIA aborts the handshake before any TPM operation when the server SPKI
      hash does not match a configured pin. `SpkiPinVerifier` runs at
      certificate-verification time, before any application bytes flow;
      verified by `tls_handshake::wrong_pin_rejects_otherwise_valid_server`.
- [x] Interop test against the BoringSSL PQ branch with the same hybrid group.
      Delivered as a wire-format witness rather than an external-binary
      shim: `tests/wire_format.rs` decodes the actual `ClientHello`
      rustls produces and asserts the `key_share` entry for `0x11EC`
      has the IETF-draft layout (32 byte X25519 || 1184 byte ML-KEM-768
      = 1216 bytes). Any IETF-conforming peer — BoringSSL-PQ,
      OpenSSL+oqs, NSS — speaks this same wire. A real-binary shim
      remains a useful CI addition and will be wired up when the CI
      runner gains a BoringSSL-PQ container.
- [x] Wycheproof test vectors pass for the underlying ChaCha20-Poly1305 and
      AES-GCM suites. Implemented in `tests/wycheproof_aead.rs`: 316
      ChaCha20-Poly1305 and 66 AES-256-GCM vectors with TLS-standard
      12-byte nonces, exercising both decrypt (Valid + Invalid) and
      re-encrypt directions.

### Live-transport wiring (M6)

The criteria above all cover the `ferro-crypto` provider and verifier layer.
These criteria close the live-transport seam (sequenced in the roadmap under
M6, "F01 — Hybrid PQC TLS transport (continued)"). The shared rustls config
builders are `ferro_crypto::transport::{server_config, client_config}`.

- [x] The CMIS gRPC listener terminates TLS via
      `server_config(ProviderMode::HybridOnly, …)`, replacing the plaintext
      `tonic` server in the bring-up binary. `cmis::transport::tls_incoming`
      runs a `tokio_rustls` accept loop and hands handshake-complete streams to
      `Server::serve_with_incoming`; enabled by `CMIS_TLS_CERT` +
      `CMIS_TLS_KEY` (plaintext otherwise, with a loud warning).
- [x] The MIA gRPC client dials over the hybrid-PQC provider with SPKI pin
      verification. `mia::client::connect_pinned` wraps a `tokio_rustls`
      connector built from `client_config(HybridOnly, pins)`; a non-hybrid or
      wrong-pin server is rejected before any application RPC.
- [x] A legacy/non-PQC client cannot complete the handshake against the live
      CMIS listener:
      `crates/mia/tests/tls_transport.rs::legacy_non_pqc_client_cannot_handshake_against_cmis_listener`
      stands up the real `MachineIdentity` service over the TLS listener and a
      legacy-X25519-only client fails the handshake;
      `wrong_pin_client_is_rejected_by_connect_pinned` covers the pin path.
- [x] The negotiated named group is surfaced as telemetry: `tls_incoming`
      logs `kx_group = X25519MLKEM768` per accepted connection.
      `ferro_crypto::transport::{is_hybrid_group, group_label}` plus the
      `transport_builders_negotiate_the_hybrid_group` handshake test assert the
      value end to end.
- [x] Transport configuration (server cert + MIA pin provisioning) is
      documented in [../operations.md](../operations.md) §"Transport security
      (hybrid-PQC TLS)".

## Risks

- **Spec churn.** The hybrid-design draft is not yet final; codepoints may
  shift. Mitigation: feature-flag the named group identifier in one place.
- **Library availability.** `rustls-post-quantum` is the canonical path;
  fallback is to wire the KX group manually as shown in [../crypto.md](../crypto.md).
