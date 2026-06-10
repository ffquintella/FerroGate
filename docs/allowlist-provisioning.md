# Allowlist provisioning & the enrollment key

This page documents the workflow that provisions a MIA host with the key it
needs to trust its caller **allowlist**: the `GetEnrollmentKey` RPC and the
`mia setup` fetch that writes `allowlist.key`. It covers what the workflow is
for, its security properties, and how to operate it.

## What it serves

The MIA [helper API](helper-api.md) mints DPoP-bound child tokens only for
callers on a **signed allowlist** — a list of entries keyed on the **binary's
SHA-384**, each optionally pinned to a uid: an entry with a uid permits that
binary run by that user, an entry without one (a *uid wildcard*) permits it run
by *any* user. Wildcard entries are the restart-stable choice for callers with
an ephemeral uid — systemd `DynamicUser=yes`, sandboxes — whose binary is
constant but whose uid changes on every launch (see [ADR-0002](adr/0002-allowlist-optional-uid.md)).

The binary hash supports a symmetric **wildcard** too: a `bin_sha` of `"*"`
permits **any** binary. The two wildcards combine — `(uid 1000, bin_sha "*")`
admits any program run by uid 1000, and `(any uid, bin_sha "*")` admits any
program run by any user. The any-binary wildcard is a coarse, high-trust grant
(it removes the per-binary measurement check); prefer hash-pinned entries and
reach for `"*"` only for a tightly-scoped uid, or a host you fully trust.
The allowlist is a CBOR document signed by CMIS; the MIA re-verifies the
signature before trusting it and **fails closed** (denies every caller) on any
error.

Verification needs two files on the host:

| File (config key) | What it is | Secret? |
|-------------------|------------|---------|
| `allowlist.key` (`FERROGATE_ALLOWLIST_KEY`) | the **CMIS enrollment public key** — the composite (hybrid-PQC) public key whose private half signs allowlists | No — public key material |
| `allowlist.path` (`FERROGATE_ALLOWLIST`) | the **signed allowlist body** (CBOR) issued by CMIS for this host | No — integrity-protected by its signature |

This workflow provisions the first one. The MIA verifies the allowlist with
`allowlist.key` under the domain-separation context `ferrogate-allowlist-v1`,
checks freshness (`issued_at`/`not_after` and the `max_age_secs` bound), then
loads the members — keyed by binary hash, each carrying its uid rule (a specific
uid, a set of uids, or "any") — for O(1) caller checks.

### The pieces

```
CMIS                                   MIA host
─────                                  ────────
issuer composite key                   mia setup
  ├─ signs SVIDs (ctx: svid)            └─ fetch_enrollment_key()
  └─ signs allowlists (ctx: allowlist)        │  over pinned hybrid-PQC TLS
         │                                     ▼
   GetEnrollmentKey RPC  ───────────────►  writes allowlist.key
   (public key, concat bytes)                  (CompositePublicKey concat bytes)
                                               │
   SetAllowlist (admin: ferrogate CLI)         │
     └─ issuer signs + stores per host         │
   GetAllowlist RPC  ───────────────────►    allowlist.path
   (signed CBOR body, by host UUID)             │
                                          daemon: Allowlist::load(body, key)
                                               └─ verify → permit listed callers
```

- **Enrollment key = the CMIS issuer key.** CMIS holds one composite signing
  key (the SVID `Issuer`). Allowlist signatures use a *distinct* signing context
  (`ferrogate-allowlist-v1`) from SVID signatures, so reusing the key is safe —
  a signature minted for one purpose cannot be replayed as the other.
- **`GetEnrollmentKey`** is an unauthenticated unary RPC returning the issuer's
  public key as `classical || pqc` concat bytes (`CompositePublicKey::from_concat_bytes`).
  It is public key material, so no authentication is required to read it.
- **`mia setup`** fetches it over the **SPKI-pinned** hybrid-PQC TLS channel and
  writes `allowlist.key`.
- **The allowlist body is served by CMIS too.** An operator stores a host's
  allowlist with `ferrogate allowlist set` (the `SetAllowlist` admin RPC): CMIS
  stamps its trust domain + validity window, signs the entries with the issuer
  key, and persists the signed CBOR keyed by the host's **EK-derived UUID**
  (`ferro_svid::host_uuid_from_ek_digest`). The body is fetched with
  `GetAllowlist` — unauthenticated, because it is integrity-protected by its
  signature and is not secret, and keying by EK-UUID lets a host be provisioned
  *before* it has attested (no SPIFFE id needed).

## Security implications

- **The SPKI pin is the trust anchor for the fetch.** `GetEnrollmentKey` is
  unauthenticated, so the *only* thing that makes the fetched key trustworthy is
  that it came from the genuinely-pinned CMIS. If an attacker could MITM the
  fetch and substitute their own key, the host would later accept allowlists
  *they* signed — i.e. authorize arbitrary callers. **Never fetch without a
  correct SPKI pin**, and obtain that pin out of band (see "How to operate").
- **`allowlist.key` integrity matters, not its secrecy.** It is a public key;
  exposure is harmless. But its *integrity* anchors the whole allowlist trust
  chain: a wrong/tampered key means either accepting forged allowlists or
  rejecting the real one (a denial of service). Protect the file from tampering
  (it is written `0644`, owned by the installing user/root).
- **Fail-closed everywhere.** A missing/expired/too-old/bad-signature allowlist
  yields *no* usable allowlist, so the helper API denies every caller rather than
  fall open. A missing `allowlist.key` while `allowlist.path` is set makes the
  daemon **refuse to start** (loud), rather than silently run unprotected.
- **Key reuse couples rotation.** Because the enrollment key *is* the issuer
  key, rotating the issuer (root key ceremony, compromise) also rotates the
  allowlist trust root: every host must re-fetch `allowlist.key` and CMIS must
  re-sign outstanding allowlists. Plan rotations accordingly.
- **Post-quantum.** The key and allowlist signature are composite
  (Ed25519 ⊕ ML-DSA-65), so allowlist trust is hybrid-PQC like the rest of
  FerroGate.
- **The allowlist body needs no confidential channel** — its signature provides
  integrity and authenticity. It does, however, need to be the *right* signed
  artefact for this host's trust domain; a stale or wrong-domain body fails
  verification and denies all callers.

## How to operate it

### Prerequisites

1. A reachable CMIS `https://` endpoint.
2. Its **SPKI pin** (lowercase-hex SHA-384), obtained out of band — e.g. from the
   server certificate the `puppet-ferrogate` module mounts, or printed by the
   `ferrogate` operator CLI (`--tls-cert <pem>` derives it; `--spki-pin` prints
   the accepted value). Verify it through a trusted channel, not over the same
   connection you are about to pin.

### Interactive (recommended): `mia setup`

```console
$ sudo mia setup           # writes the OS system config path
```

In the wizard:

1. **CMIS server** — enter the endpoint and the hex SPKI pin (the wizard
   validates the pin format).
2. **Caller allowlist** — answer **Yes**, accept/enter the `allowlist.key` path,
   then answer **Yes** to *"Fetch this key from `<endpoint>` now?"*. The wizard
   dials CMIS over the pinned channel, calls `GetEnrollmentKey`, and writes the
   key. A fetch failure is non-fatal — it warns and continues so you can retry
   or place the file out of band.

Then provide the signed allowlist body at `allowlist.path` (issued by CMIS for
this host — see "Managing allowlists" below) and restart the agent:

| OS | restart |
|----|---------|
| Linux | `sudo systemctl restart mia` |
| macOS | `sudo launchctl kickstart -k system/com.ferrogate.mia` |
| Windows | `Restart-Service mia` |

### Managing allowlists: the `ferrogate allowlist` commands

An operator creates, edits, inspects, and removes per-host allowlists with the
`ferrogate` CLI. CMIS does the signing — the issuer secret never leaves the
server. A host is named by its EK-derived UUID; pass it directly with `--host`,
or let the CLI derive it from the EK certificate (`--ek-cert <pem>`) or that
cert's SHA-384 (`--ek-sha384 <hex>`).

```console
# Replace a host's allowlist with exactly these callers. `--bin` hashes the
# binary for you; `--entry` takes a precomputed SHA-384 (or `*` for any binary).
# Prefix `uid:` to pin to a user, or omit it for a wildcard (any user).
$ ferrogate allowlist set --host <uuid> --bin 1000:/usr/bin/foo --ttl 86400
$ ferrogate allowlist set --host <uuid> --bin /usr/bin/foo       # uid wildcard (any uid)
$ ferrogate allowlist set --host <uuid> --entry 1000:'*'         # any binary run by uid 1000
$ ferrogate allowlist set --host <uuid> --entry '*'              # any binary, any uid

# Add/remove callers in place (read-modify-write, re-signed by CMIS):
$ ferrogate allowlist add    --host <uuid> --entry 1001:<sha384hex>  # pin to uid 1001
$ ferrogate allowlist add    --host <uuid> --entry <sha384hex>       # uid wildcard
$ ferrogate allowlist remove --host <uuid> --uid 1001               # drop uid-1001 pins
$ ferrogate allowlist remove --host <uuid> --bin-sha <sha384hex>    # drop a binary (any scope)
$ ferrogate allowlist remove --host <uuid> --bin-sha '*'            # drop any-binary wildcards

# Inspect:
$ ferrogate allowlist show <…> --host <uuid>   # decoded entries + validity
$ ferrogate allowlist list                     # every provisioned host

# Retrieve the raw signed CBOR to place at a host's allowlist.path, then delete:
$ ferrogate allowlist get --host <uuid> --out allowlist.cbor
$ ferrogate allowlist delete --host <uuid>
```

A MIA host can also fetch its own body automatically instead of having it
delivered out of band: set **`allowlist.fetch = true`** (or
`FERROGATE_ALLOWLIST_FETCH=true`, or answer the `mia setup` prompt). At each
start — once attestation has supplied the host's identity — the daemon calls
`GetAllowlist` keyed by its own EK-derived UUID and writes `allowlist.path`
before loading it. A fetch failure is non-fatal: the daemon falls back to
whatever is already at `path` (or fails closed if nothing is).

### Verifying

On restart the daemon logs `loaded signed allowlist` with the trust domain when
both files verify. If the allowlist is absent, or either file fails to verify
or parse, the daemon stays up but logs a fail-closed line ending in
`helper API denies all callers (fail closed)` — it never crashes over trust
problems, so the helper socket remains bound and the deny is diagnosable.

### Unattended / configuration management

`mia setup` requires a TTY. For automated provisioning, either deliver
`allowlist.key` (and the allowlist body) to the host through your
configuration-management channel and point the TOML/`FERROGATE_*` config at them
— the key is public, so any integrity-preserving channel is fine — or, once the
`[cmis]` endpoint and pin are configured, run the non-interactive **`mia
refresh-key`** to fetch `allowlist.key` and **`mia resync-allowlist`** to fetch
the signed body, then restart. Both are TTY-free and exit non-zero on failure,
so they gate cleanly in provisioning scripts.

When only the allowlist body changed (not the enrollment key), pass **`mia
resync-allowlist --reload`**: after writing and verifying the new body it
signals the running agent (`SIGHUP`) to swap it in live, so the helper socket
never goes down — no restart needed. (Windows has no `SIGHUP`; restart there.
`refresh-key` still needs a restart, since the daemon reads the key only at
startup.)

## Troubleshooting

| Symptom | Cause | Remedy |
|---------|-------|--------|
| `allowlist key file missing` / `unparseable` (daemon serves deny-all) | `allowlist.path`/`key` set but the key file is missing or corrupt | Fetch it with `mia refresh-key` (or `mia setup`), deliver it out of band, or remove the `[allowlist]` keys to start fail-closed |
| `allowlist verification failed: bad signature` (daemon serves deny-all) | wrong `allowlist.key`, or an allowlist signed by a different/rotated issuer (e.g. a CMIS redeploy changed the enrollment key) | `mia refresh-key` to re-fetch the key, then `mia resync-allowlist` to pull a body signed by it; restart the daemon |
| `allowlist verification failed: expired` / `too old` (daemon serves deny-all) | `not_after` passed, or older than `max_age_secs` | Re-issue a fresh allowlist; check clock skew; restart the daemon |
| fetch fails with a TLS/pin error | wrong or missing SPKI pin, unreachable endpoint | Re-verify the pin out of band; confirm the endpoint |

## Storage & authorization

- **Persistence.** CMIS stores allowlists in the same backend as issued SVIDs:
  the Raft-replicated `host_allowlists` keyspace (strongly-consistent reads, so
  a follower never serves a stale body after a leader upsert). A single replica
  runs a one-node Raft, so the SQLite store under `CMIS_RAFT_DIR` (default
  `/var/lib/ferrogate/raft`) survives restarts.
- **Validity.** `SetAllowlist` stamps `issued_at = now` and
  `not_after = now + ttl` (default one day, capped at 30 days). Re-issue rather
  than mint long-lived lists so the MIA's freshness check stays meaningful.
- **Admin authorization.** `SetAllowlist`/`DeleteAllowlist`/`ListAllowlists` are
  admin RPCs, authenticated out of band as operator actions exactly like
  `RevokeSvid`/`BumpEpoch` (transport-level: SPKI-pinned TLS + network/proxy
  controls). `GetAllowlist` is deliberately unauthenticated. Every set/delete is
  recorded in the audit log (`AllowlistSet`/`AllowlistDeleted`, host UUID + entry
  count only — no PII).

## Limitations (current)

- **No dedicated enrollment key.** The issuer key doubles as the allowlist
  signer (safe via context separation); a separate, independently-rotatable
  enrollment key is a possible future hardening.

## See also

- [Helper API](helper-api.md) — what the allowlist gates.
- [MIA agent](mia.md) — configuration file, `mia setup`, per-OS paths.
- [Transport security (TLS)](transport-tls.md) — SPKI pinning and how to compute a pin.
