# Root key ceremony — operations runbook (F14)

The composite issuance root is rotated annually in an air-gapped ceremony driven
by the [`offline-signer`](../../tools/offline-signer) tool and the
[`ferro-ceremony`](../../crates/ferro-ceremony) library. This runbook is the
step-by-step operator procedure; the design rationale is in
[operations.md](../operations.md) §"Root key rotation" and the feature contract
is in [features/F14-root-key-ceremony.md](../features/F14-root-key-ceremony.md).

> **Scope.** This covers the *planned* annual rotation and periodic share
> refresh. Online emergency rotation is a separate, off-the-happy-path runbook
> and is explicitly out of scope here.

## Trust model in one paragraph

The root is a 32-byte master seed; the composite Ed25519 + ML-DSA-65 keypair is
derived from it deterministically (`CompositeSecretKey::from_seed`). The seed is
Shamir-split **3-of-5** over GF(2⁸) (`ferro-tee`), and each share is written to a
distinct tamper-evident medium held by one operator. **Confidentiality rests on
the threshold plus physical custody** — fewer than three media reveal nothing.
The sealed-share envelope adds integrity (a `SHA3-256` tag) and labelling, not
encryption; measurement-bound *encryption* of shares against a CMIS enclave is
the online F06 path (`ferro_tee::seal`), used when shares are delivered to a
running replica, not in this offline ceremony.

## Roles

- **Ceremony lead** — runs `offline-signer`, reads each step aloud, drives the
  video record.
- **Share holders ×5** — each takes custody of one sealed medium; any 3 can
  reconstruct.
- **Witness(es)** — verify the procedure, co-sign the minutes.

Separation of duties: no single person holds three shares; the lead is not a
share holder beyond their own one share.

## Pre-flight

1. Faraday-shielded room; the signing laptop is the hardened, **network-less**
   offline-signer image. Verify no network interfaces are up.
2. Start the video recording. Everything below is on camera.
3. Each participant generates (or brings) their **personal** signing key and
   states its `kid` and public key for the minutes:

   ```sh
   offline-signer keygen --kid op-1            # prints kid / seed / pubkey
   ```

   The personal seed never leaves its holder; only the public key is recorded.

## Rotation procedure

Let `root-OLD` be the outgoing root (its seed reconstructed from the previous
ceremony's shares) and `root-NEW` the incoming root.

### 1. Reconstruct the outgoing root (if rotating, not bootstrapping)

Bring ≥3 of the current shares together and reconstruct:

```sh
offline-signer combine --in-dir ./old-shares      # or repeated --share @file
# prints: recovered N share(s) -> root root-OLD ; seed … ; pubkey …
```

### 2. Generate the new root

```sh
offline-signer keygen --kid root-2026             # the new root seed + pubkey
```

Record `root-NEW`'s public key in the minutes.

### 3. Split the new root into sealed media (3-of-5)

```sh
offline-signer split \
  --seed @new-root.seed --root-kid root-2026 --threshold 3 \
  --holder operator-1 --holder operator-2 --holder operator-3 \
  --holder operator-4 --holder operator-5 \
  --out-dir ./new-shares
```

Each `share-<index>-<holder>.json` is written to its holder's tamper-evident
medium. A sealed share looks like:

```json
{
  "format": "ferrogate-sealed-share",
  "version": 1,
  "root_kid": "root-2026",
  "threshold": 3,
  "total": 5,
  "index": 1,
  "holder": "operator-1",
  "created_at": 1780000000,
  "share": "<base64 of the per-byte Shamir evaluations>",
  "tag": "<SHA3-256 integrity tag over the canonical fields>"
}
```

### 4. Cross-sign old ↔ new for the 90-day window

```sh
offline-signer cross-sign \
  --old-seed @old-root.seed --old-kid root-2025 \
  --new-seed @new-root.seed --new-kid root-2026 \
  --window-days 90 \
  --out cross-sign.json

offline-signer verify-cross --bundle cross-sign.json
# OK  both directions verify  ...  window [start, end)
```

The bundle contains **both** `old_signs_new` and `new_signs_old`; verification
requires both. This is the bridge that keeps SVIDs signed under `root-OLD` valid
while the fleet migrates to `root-NEW`.

### 5. Publish the JWKS (both roots, newer preferred)

```sh
offline-signer jwks --bundle cross-sign.json --out jwks.json
```

This emits a `ferro-svid` JWK set listing `root-NEW` first with the newer
`x-ferrogate-created` stamp. Load it into CMIS for the window: CMIS keeps its
running issuer (`root-OLD`) as a root key and registers `root-NEW` via
`CmisState::register_root_key`, so `published_jwks` serves roots newest-first
ahead of the per-host child keys. A reference verifier picks the trust anchor
with `JwkSet::preferred()` (→ `root-NEW`), while SVIDs from either root still
resolve by `kid`. At the window cutover CMIS is reconfigured to *issue* under
`root-NEW`.

### 6. Sign the minutes (all participants)

```sh
offline-signer minutes-new \
  --ceremony-id rotation-2026 --kind rotation \
  --location "Faraday room B, DC-1" --trust-domain ferrogate.prod \
  --old-root-kid root-2025 --new-root-kid root-2026 \
  --threshold 3 --total 5 \
  --participant 'Alice|share-holder|op-1|@op1.pub' \
  --participant 'Bob|share-holder|op-2|@op2.pub' \
  --participant 'Carol|share-holder|op-3|@op3.pub' \
  --participant 'Dan|witness|op-4|@op4.pub' \
  --participant 'Erin|ceremony-lead|op-5|@op5.pub' \
  --artefact 'cross-sign-bundle|@cross-sign.json' \
  --out minutes.json

# Each participant signs in turn (updates minutes.json in place):
offline-signer minutes-sign --minutes minutes.json --kid op-1 --seed @op1.seed
# … op-2 … op-3 … op-4 … op-5 …

offline-signer minutes-verify --minutes minutes.json
# OK  rotation-2026  all 5 participant(s) signed
```

`minutes-verify` fails unless **every** listed participant has signed. Anchor the
verified `minutes.json` to the audit **WORM** medium (and, per the threat model,
to the transparency anchor).

## End-of-window destruction (≥90 days later)

When the cross-sign window closes, all five holders convene and destroy the
**outgoing** root's media simultaneously. For each medium:

```sh
offline-signer destroy --share @old-shares/share-1.json --out destruction.json
# destroyed share 1 (operator-1): 319 bytes zeroized, read-back verified
```

`destroy` overwrites the file in place with zeros, `fsync`s it, and **reads it
back** — failing unless every byte is zero and the bytes no longer parse as a
usable share. It emits an auditable `DestructionRecord` per medium:

```json
{
  "path": ".../old-shares/share-1.json",
  "root_kid": "root-2025",
  "holder": "operator-1",
  "index": 1,
  "bytes_zeroized": 319,
  "verified": true,
  "destroyed_at": 1787776000
}
```

Re-audit any medium later with:

```sh
offline-signer verify-destruction --share @old-shares/share-1.json
```

Record the destruction as its own `--kind destruction` minutes set, signed by all
participants and stored to WORM.

## Staging dry-run

Before any production ceremony, run the full eight-step flow end to end against a
scratch directory — five synthetic operators, both roots, cross-sign, JWKS,
reconstruct, signed minutes, and destruction:

```sh
offline-signer dry-run --work-dir ./staging-ceremony
```

```text
== FerroGate root-key ceremony dry-run ==
[1/8] 5 operators provisioned (3-of-5 quorum)
[2/8] outgoing root root-2025 and incoming root root-2026 derived
[3/8] both roots Shamir-split 3-of-5 into sealed media
[4/8] cross-sign bundle validates in BOTH directions
[5/8] JWKS publishes both roots; preferred = root-2026 (the newer)
[6/8] new root reconstructed from a 3-of-5 subset; pubkey matches
[7/8] ceremony minutes signed by all 5 participants (WORM-ready)
[8/8] all 5 outgoing-root media zeroized; post-zeroization read-back verified

== dry-run complete: all F14 ceremony steps passed ==
```

The dry-run leaves `cross-sign.json`, `jwks.json`, `minutes.json`,
`destruction.json`, and the (now zeroized) `old-shares/` and live `new-shares/`
directories under the work dir for inspection. It is also driven in CI by the
`offline-signer` integration test `dry_run_produces_all_verifiable_artefacts`,
which re-verifies every artefact through the `ferro-ceremony` and `ferro-svid`
library types.

## Failure / recovery notes

- **Lost ≤2 shares:** reconstruct from the remaining ≥3; schedule a share
  refresh (`--kind share-refresh`) to re-split the *same* root across fresh
  media.
- **Lost ≥3 shares:** the root is unrecoverable. Provision a new root and
  re-seed (this is the quorum-loss path in [operations.md](../operations.md)
  §"Disaster recovery"); all hosts re-attest at next rotation.
- **Integrity tag mismatch on a medium:** treat the medium as compromised; do
  not use the share. Reconstruct from the others and refresh.
