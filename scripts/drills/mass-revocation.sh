#!/usr/bin/env bash
# Mass-revocation drill harness (feature: M6 operational drills).
#
# Exercises the two mass-revocation levers:
#   1. policy_id epoch bump  -> BumpEpoch advances the live epoch and every host
#      attested under the old epoch is forced through full re-attestation on its
#      next Rotate (FAILED_PRECONDITION). This is the drill the roadmap names.
#   2. targeted revocation   -> RevokeSvid / RevokeHost land in the CRL within
#      one publish cycle and the reference verifier rejects the artefact; a
#      revoked host is refused at Attest (T295).
#
# Locally this drives the cmis/mia integration tests that prove both levers; in
# staging the operator issues the real admin RPCs, see
# docs/operations/drills/mass-revocation.md.
#
# Usage:  scripts/drills/mass-revocation.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "== FerroGate mass-revocation drill =="
echo
echo "-- Lever 1: policy_id epoch bump forces fleet-wide re-attestation --"
cargo test -p mia --test e2e_attest \
    bump_epoch_forces_full_reattestation_on_next_rotate -- --nocapture

echo
echo "-- Lever 2: targeted revocation propagates through the CRL --"
cargo test -p cmis --test revocation -- --nocapture
cargo test -p cmis --test attest_revocation -- --nocapture
cargo test -p mia --test e2e_attest \
    attest_refuses_revoked_host_tpm_tier -- --nocapture

echo
echo "PASS: epoch bump drove a short-path rotate to FAILED_PRECONDITION and"
echo "recorded one PolicyEpochBumped leaf; revoked artefacts appear in the CRL"
echo "and are rejected by the reference verifier; a revoked host is refused at"
echo "Attest (host_revoked). Capture this in the drill log."
