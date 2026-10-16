# Drill: mass revocation (`policy_id` epoch bump)

**Goal.** Prove that the operator can invalidate every SVID issued under a
compromised RIM generation — a vulnerable kernel image, a leaked measurement —
in one action, and that the whole fleet re-attests on its next rotation without
a flag day.

**Frequency.** Semi-annually, and as a fire-drill after any RIM policy change.

**Roles.** One incident commander (authorizes and issues the bump), one
observer (watches re-attestation and audit), one verifier (confirms the audit
leaf and a sample host).

**Maps to.** `docs/operations.md` §"RIM policy and epoch bump" and §"Revocation";
features F10 (`bump_epoch`) and F11 (revocation / CRL).

---

## Background: the two levers

| Lever | RPC | Blast radius | When |
|-------|-----|--------------|------|
| **Epoch bump** | `BumpEpoch(reason)` | Every host attested under the old epoch | Compromised RIM generation / kernel image — the *mass* case |
| **Targeted revoke** | `RevokeSvid(cert_sha, reason)` / `RevokeHost(spiffe_id, reason)` | One SVID / one host | A single leaked credential |

This drill rehearses the **epoch bump** as the primary exercise and confirms
targeted revocation as the secondary path.

## How the epoch bump propagates

- `BumpEpoch` advances the live `AtomicU64` policy epoch and records a
  `PolicyEpochBumped { old_epoch, new_epoch, reason }` audit event.
- On the next `Rotate`, any host whose last full attestation carried the old
  epoch is refused with `FAILED_PRECONDITION` (`decide_renewal` → `EpochBump`
  branch) and is driven back through the full four-phase `Attest`.
- Hosts rotate at 60% ±10% of their ≤1 h TTL, so the fleet fully re-attests
  within roughly one TTL (≤ ~1 h) of the bump — no SVID outlives its expiry.
- The bump is process-local today; in a cluster, issue it to each replica (or
  through the replicated admin path once wired). Record this in the run.

---

## Pre-flight

1. Confirm a healthy issuance baseline and note the **current epoch** (from the
   most recent `PolicyEpochBumped` leaf, or 0 if never bumped).
2. Confirm the audit log is publishing fresh STHs (so the bump leaf will be
   anchored — see the STH-lag runbook).
3. Have the `reason` opcode agreed and recorded (it lands verbatim in the audit
   leaf; never put free-form PII there).

## Procedure

1. **Authorize.** Incident commander records the decision and the `reason`.
2. **Bump the epoch** on every CMIS replica. The admin RPCs need a
   signed-in administrator with a fresh step-up (F20) and go to the admin
   listener, so use the CLI rather than a bare `grpcurl`:
   ```sh
   ferrogate admin login --session-file "$XDG_RUNTIME_DIR/drill.session"
   for n in cmis-a cmis-b cmis-c; do
     ferrogate --admin-endpoint "https://$n:8444" \
       --session-file "$XDG_RUNTIME_DIR/drill.session" \
       bump-epoch DRILL-rim-gen-7-revoked
   done
   # Each answer carries new_epoch; confirm it advanced by 1 on each.
   ```
3. **Verify the audit leaf.** Fetch the latest STH and an inclusion proof for
   the `PolicyEpochBumped` event; verify the proof offline.
4. **Watch re-attestation.** On the dashboard, attestation volume rises as
   hosts hit their rotation point and are bounced from short-path `Rotate`
   (`FAILED_PRECONDITION`) into full `Attest`. Confirm the rate returns to
   baseline within ~one TTL.
5. **Spot-check a host.** Pick one host; confirm its pre-bump `Rotate` is
   refused and its subsequent full `Attest` issues an SVID carrying the new
   `policy_id`.

## Secondary path: targeted revocation

```sh
ferrogate --admin-endpoint https://cmis-a:8444 \
  --session-file "$XDG_RUNTIME_DIR/drill.session" \
  revoke-svid <96-hex-sha384-of-jws> DRILL-leaked
```

Confirm: the CRL number advances, the entry appears in the `x-ferrogate-crl`
JWKS extension within one 60 s publish cycle (it republishes immediately on
revoke), and the reference verifier (`ferro-svid-verify`) rejects the artefact.

Then revoke a drill host and confirm it cannot come back by re-attesting
(T295):

```sh
for n in cmis-a cmis-b cmis-c; do   # the working set is per node until T223
  ferrogate --admin-endpoint "https://$n:8444" \
    --session-file "$XDG_RUNTIME_DIR/drill.session" \
    revoke-host spiffe://<td>/host/<uuid> DRILL-host
done
# On the drill host: force a re-attestation (restart the MIA daemon, or wait
# for its next renewal).
```

Confirm: the host's `Attest` ends with `PERMISSION_DENIED host_revoked` on
every replica, an `AttestFail { reason: "attest-host-revoked" }` leaf is
appended for each attempt, and no `SvidIssued` leaf for that SPIFFE id follows
the `HostRevoked` leaf. **Use a host you can retire or re-key**: there is no
un-revoke RPC (T296), and the same hardware stays refused until the entry
expires 30 days after the last `RevokeHost` (see `docs/operations.md`
§"Revocation", "Bringing back a revoked host").

## Pass criteria

- `new_epoch == old_epoch + 1` on every replica.
- Exactly one `PolicyEpochBumped` leaf, inclusion-proven against a fresh STH.
- A pre-bump host's `Rotate` returns `FAILED_PRECONDITION`; its full re-attest
  succeeds with the new `policy_id`.
- Fleet attestation rate returns to baseline within ~one TTL.
- (Secondary) revoked artefact appears in the CRL within one cycle and is
  rejected by the verifier.
- (Secondary) a revoked host's re-attestation is refused with
  `PERMISSION_DENIED host_revoked` on every replica and audited
  `attest-host-revoked`; no new SVID is issued to it.

## Abort / rollback

An epoch bump is **not reversible** — there is no "un-bump". If issued in
error, the only remedy is to let the fleet re-attest (it will, under the new
epoch) and to publish a corrected RIM bundle if the bump was triggered by a
false alarm. This is why the authorize step is mandatory.

A `RevokeHost` is not reversible either (T296 tracks an un-revoke RPC): the
host stays refused at `Attest` until the entry expires. Revoke only hosts
named in the authorize step.

---

## Local rehearsal harness

```sh
scripts/drills/mass-revocation.sh
```

Drives `bump_epoch_forces_full_reattestation_on_next_rotate` (mia e2e) and the
`cmis` `revocation` integration tests, proving both levers end to end. The
revoked-host refusal is covered by `cmis` `attest_revocation` (host-key tier)
and `attest_refuses_revoked_host_tpm_tier` (mia e2e).

## Drill log

| Date | Environment | Result | Evidence |
|------|-------------|--------|----------|
| 2026-06-01 | Local rehearsal harness (`scripts/drills/mass-revocation.sh`) | **PASS** (see CI `test` job) | `bump_epoch_forces_full_reattestation_on_next_rotate` + `cmis::revocation` |

> Staging execution: append a row each half-year with the `BumpEpoch`
> transcripts, the inclusion-proof verification, and the re-attestation
> dashboard.
