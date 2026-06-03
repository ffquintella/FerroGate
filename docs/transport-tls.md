# Transport security — hybrid-PQC TLS (F01)

All MIA→CMIS control-plane traffic (attestation, rotation, JWKS, audit, admin
RPCs) runs over **TLS 1.3 with the hybrid `X25519MLKEM768` key-exchange group
only**. This defeats *harvest-now-decrypt-later*: a recorded session cannot be
decrypted later even by an attacker with a cryptographically-relevant quantum
computer, as long as ML-KEM-768 holds — and it is no weaker than classical
X25519 if ML-KEM is ever broken, because the two secrets are AND-combined.

This page covers **how the transport works** and **how to configure it**. The
key-exchange math is in [crypto.md](crypto.md) §"Hybrid TLS key exchange"; the
ports and connection directions are in [networking.md](networking.md).

## How it works

### The handshake

- **TLS 1.3 only.** No TLS 1.2; a downgrade is refused.
- **One named group: `X25519MLKEM768`** (IANA codepoint `0x11EC`). The CMIS
  listener advertises *only* this group, so a client that cannot speak it —
  any legacy, non-PQC client — fails the handshake outright. There is no silent
  fallback to pure X25519 in production.
- **Two AEAD suites:** `TLS13_CHACHA20_POLY1305_SHA256` and
  `TLS13_AES_256_GCM_SHA384`.
- **ALPN `h2`.** gRPC runs over HTTP/2; both peers advertise exactly `h2`.

### Authentication: SPKI pinning, not a CA

The MIA does **not** trust a public CA hierarchy to authenticate CMIS. Instead
it pins the **SHA-384 of the CMIS certificate's `SubjectPublicKeyInfo`** (SPKI).
At certificate-verification time — *before any application byte flows* — the
client compares the presented end-entity certificate's SPKI hash (constant-time)
against its configured pin set. A mismatch aborts the handshake. Intermediate
certificates are intentionally not chain-validated: the pin is the trust anchor.

This means the server certificate's hostname / SAN is irrelevant to trust — it
is used only for SNI/routing. You can use a self-signed certificate; what
matters is that the MIA pins its SPKI.

### Code map

| Concern | Where |
|---------|-------|
| Shared rustls config builders | [`ferro_crypto::transport`](../crates/ferro-crypto/src/transport.rs) — `server_config` / `client_config`, plus `is_hybrid_group` / `group_label` |
| The hybrid provider (groups + suites) | [`ferro_crypto::tls`](../crates/ferro-crypto/src/tls.rs) — `ferrogate_provider(ProviderMode::HybridOnly)` |
| SPKI pin + verifier | [`ferro_crypto::pin`](../crates/ferro-crypto/src/pin.rs) — `SpkiPin`, `SpkiPinVerifier` |
| CMIS server listener | [`cmis::transport::tls_incoming`](../crates/cmis/src/transport.rs) + `load_pem_identity`; wired in `cmis` `main` |
| Shared client dialer | [`ferro_transport::connect_pinned`](../crates/ferro-transport/src/lib.rs) — dials TCP + upgrades to pinned hybrid TLS, returns a bare `Channel` |
| MIA client dialer | [`mia::client::connect_pinned`](../crates/mia/src/client.rs) — wraps the shared dialer in `MachineIdentityClient` |
| Operator CLI | [`ferrogate`](../crates/ferrogate-cli/src/main.rs) — `https://` endpoints use the shared dialer, pin from `--spki-pin`/`--tls-cert` |

The server runs a `tokio_rustls` accept loop: each TCP connection is handshaked
on its own task (so a slow peer cannot block others), the negotiated group is
logged, and the completed TLS stream is handed to tonic's
`serve_with_incoming`. A connection that fails the handshake is logged and
dropped — it never reaches the gRPC layer. The client builds a tonic `Channel`
over a custom connector that dials TCP and upgrades to TLS with the pinned
client config.

## Configuring the CMIS server

The listener terminates hybrid-PQC TLS when **both** of these environment
variables are set:

| Variable | Meaning |
|----------|---------|
| `CMIS_TLS_CERT` | Path to a PEM certificate chain: end-entity first, then any intermediates. |
| `CMIS_TLS_KEY`  | Path to the matching PEM private key (PKCS#8, PKCS#1, or SEC1). |
| `CMIS_LISTEN`   | Listen address (default `127.0.0.1:8443`). |

Rules:

- **Both or neither.** Setting only one of `CMIS_TLS_CERT` / `CMIS_TLS_KEY`
  aborts startup with a configuration error.
- **Neither set ⇒ plaintext bring-up server**, intended for local development
  only. It logs a loud warning. Never run a production node without TLS.
- With TLS on, the listener advertises `X25519MLKEM768` only, so a non-PQC
  client fails the handshake before reaching gRPC.

```bash
# Production-style start with TLS:
export CMIS_LISTEN=0.0.0.0:8443
export CMIS_TLS_CERT=/var/lib/ferrogate/cmis.crt
export CMIS_TLS_KEY=/var/lib/ferrogate/cmis.key
cmis
# → "FerroGate CMIS — hybrid-PQC TLS gRPC server (X25519MLKEM768-only)"
```

### Generating a server certificate (dev / self-signed)

Any TLS certificate works — the MIA trusts it by SPKI pin, not by CA chain — so
a self-signed cert is fine for development:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout cmis.key -out cmis.crt -days 365 -nodes \
  -subj "/CN=cmis.ferrogate.internal"
```

For production, issue the certificate from your own PKI as usual; only the SPKI
hash is pinned, so routine renewals are handled by the pin-rotation flow below.

## Configuring the MIA client

The dialer is [`mia::client::connect_pinned`]:

```rust
use ferro_crypto::pin::SpkiPin;

let pins = vec![SpkiPin::from_hex("<sha384-hex>")?];
let mut client = mia::client::connect_pinned(
    "https://cmis.ferrogate.internal:8443",
    pins,
).await?;
// `client` is a MachineIdentityClient<Channel> over hybrid-PQC TLS.
```

`mia::client::connect_pinned` wraps the shared
[`ferro_transport::connect_pinned`](../crates/ferro-transport/src/lib.rs) dialer
(which returns a bare `Channel`) in a `MachineIdentityClient`. The dialer builds
the `HybridOnly` client config with the supplied pin set. A server that is not
pinned — or that cannot negotiate the hybrid group — is rejected before any RPC.
Multiple pins may be supplied so a new certificate's pin can be added ahead of a
rotation (see below).

> **Status:** `connect_pinned` is the production dialing API and is covered by
> live-transport tests. The standalone `mia` daemon does not yet open a CMIS
> connection on its own — the attestation loop that calls `connect_pinned`
> lands with the remaining F04 binary wiring. The configuration sketch in
> [mia.md](mia.md) (`[cmis] endpoint` / `spki_pins_sha384`) is the intended
> file-config surface for that loop.

## Configuring the operator CLI (`ferrogate`)

The `ferrogate` operator CLI speaks the same transport. Its endpoint scheme
selects it:

- **`http://…` (or a bare authority)** — plaintext gRPC, the dev/bring-up path.
- **`https://…`** — hybrid-PQC TLS over the shared `connect_pinned` dialer,
  authenticated by SPKI pin. The pin is resolved in this order:

  1. `--spki-pin <hex>` (repeatable) or `$FERROGATE_CMIS_SPKI_PIN`
     (comma-separated lowercase-hex SHA-384) — highest precedence;
  2. otherwise the **first certificate** of the PEM at `--tls-cert <path>` or
     `$FERROGATE_CMIS_TLS_CERT`, defaulting to `/etc/ferrogate/tls/cmis.crt`;
  3. otherwise the CLI errors, explaining how to supply a pin or cert path.

Step 2's default is the path the [`puppet-ferrogate`](https://github.com/ffquintella/puppet-ferrogate)
module mounts the CMIS server certificate at inside the cmis container. Because
the in-container CLI dials the very cert CMIS serves over loopback, deriving the
pin from that mounted cert "just works" with no extra flags — trust is by pin,
so the `127.0.0.1` SNI name is irrelevant:

```bash
# Inside the cmis container, against the loopback TLS listener — zero config:
ferrogate --endpoint https://127.0.0.1:8443 status

# Anywhere else, pin explicitly (compute the hex with the OpenSSL recipe below):
ferrogate --endpoint https://cmis.ferrogate.internal:8443 \
  --spki-pin <sha384-hex> status
```

> **Earlier caveat resolved.** Before F01 landed in the CLI, `ferrogate` was
> plaintext-only and broke whenever CMIS terminated TLS. It now dials `https://`
> endpoints natively; that limitation no longer applies.

### Computing the SPKI pin

The pin is the lowercase-hex SHA-384 over the DER of the certificate's
`SubjectPublicKeyInfo` — the same construction as RFC 7469 / HPKP, but SHA-384.
Compute it from the deployed certificate with OpenSSL:

```bash
openssl x509 -in cmis.crt -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha384 -binary \
  | xxd -p -c 256
```

That hex string is what you pass to `SpkiPin::from_hex` (or
`spki_pins_sha384` in the config file). In Rust you can also derive it directly
from the DER bytes with
[`SpkiPin::from_certificate_der`](../crates/ferro-crypto/src/pin.rs) and print
it with `to_hex()`.

## Telemetry — confirming PQC coverage

Every connection the CMIS listener accepts logs its negotiated key-exchange
group:

```
INFO tls connection established (hybrid PQC) peer=10.0.0.7:51234 kx_group=X25519MLKEM768
```

Because the provider advertises the hybrid group only, an accepted connection
*always* used `X25519MLKEM768` — a downgrade attempt fails the handshake and is
logged at debug as a dropped connection instead. Operators confirm fleet-wide
PQC coverage by asserting that **no accepted connection ever logs a non-hybrid
group** (the listener emits a loud `WARN` if one ever does, which is
unreachable under `HybridOnly`).

The helpers `ferro_crypto::transport::is_hybrid_group(group)` and
`group_label(group)` classify a negotiated group for logs and audit fields.

## Certificate and pin rotation

1. Issue / generate the new certificate and key.
2. Compute the **new** SPKI pin (OpenSSL recipe above).
3. Add the new pin to every MIA's pin set **alongside** the current pin, so
   both the old and new certificates verify during the overlap window.
4. Roll the new cert/key onto the CMIS nodes (`CMIS_TLS_CERT` / `CMIS_TLS_KEY`)
   and restart them.
5. Once all CMIS nodes serve the new certificate, drop the old pin from the MIA
   pin sets.

This staged overlap means a rotation never strands a client: there is always at
least one pin that matches a live certificate.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Client error *"Connecting to HTTPS without TLS enabled"* | Endpoint built with the wrong scheme — `connect_pinned` handles this; if calling tonic directly, hand the `Endpoint` an `http://` authority and do TLS in the connector. |
| Handshake fails for every client | Server advertises `X25519MLKEM768` only and the client cannot speak it. Confirm the client uses the FerroGate provider (a stock TLS client will fail — that is by design). |
| `SPKI pin mismatch` / connect fails before any RPC | The pin does not match the served certificate. Recompute the pin from the *current* cert; check you rolled certs and pins in the right order. |
| CMIS exits at startup with *"CMIS_TLS_CERT and CMIS_TLS_KEY must be set together"* | Only one of the pair was set. Set both (TLS) or neither (dev plaintext). |
| CMIS logs *"PLAINTEXT gRPC bring-up server"* | No cert/key configured. Expected in dev; never acceptable in production. |
| `ferrogate` errors *"no SPKI pin available for the https:// endpoint"* | The `https://` endpoint has no resolvable pin: no `--spki-pin`/`$FERROGATE_CMIS_SPKI_PIN`, and the default/`--tls-cert` server cert could not be read. Pass `--spki-pin <hex>`, or point `--tls-cert` at the CMIS server certificate. |
| `ferrogate status` against `http://` connects but CMIS terminates TLS | The endpoint scheme is plaintext while CMIS serves TLS. Use an `https://` endpoint so the CLI dials the pinned hybrid transport. |

## Tests

- `crates/ferro-crypto/tests/tls_handshake.rs` — handshake over an in-memory
  duplex: hybrid succeeds, legacy-only client is rejected, wrong pin is
  rejected, and `transport_builders_negotiate_the_hybrid_group` asserts the
  negotiated group is `X25519MLKEM768`.
- `crates/mia/tests/tls_transport.rs` — the **real** `MachineIdentity` service
  behind the TLS listener: a pinned hybrid client runs `JWKS` over TLS; a
  legacy non-PQC client cannot handshake against the listener; a wrong-pin
  client is refused by `connect_pinned`.
- `crates/ferrogate-cli/tests/smoke.rs` — runs the compiled `ferrogate` binary
  against a real CMIS listener: `status` over `https://` succeeds with a
  cert-derived pin and with an explicit `--spki-pin`; a wrong pin is refused
  before any RPC; `--spki-pin` takes precedence over `--tls-cert`; an `https://`
  endpoint with no resolvable pin errors clearly; and the plaintext `http://`
  path still works.

See [F01 — Hybrid PQC TLS transport](features/F01-hybrid-pqc-tls.md) for the
full acceptance criteria.
