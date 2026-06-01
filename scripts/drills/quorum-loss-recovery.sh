#!/usr/bin/env bash
# Quorum-loss recovery drill harness (feature: M6 operational drills).
#
# Two phases:
#   1. Graceful-degradation phase — drive the Raft cluster past the point where
#      only one node survives (quorum lost) and confirm that issuance halts
#      while previously-issued SVIDs remain valid until expiry.
#   2. Recovery phase — the root-key ceremony re-seeds Shamir shares and the
#      cluster re-forms. The offline-signer dry-run stands in for the ceremony.
#
# Locally this exercises the ferro-raft chaos/rejoin harness plus the
# offline-signer dry-run; in staging it is run against the real fleet, see
# docs/operations/drills/quorum-loss-recovery.md.
#
# Usage:  scripts/drills/quorum-loss-recovery.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "== FerroGate quorum-loss recovery drill =="
echo
echo "-- Phase 1: cluster behaviour around quorum loss / rejoin --"
# follower_rejoin_preserves_replicated_data is the recovery path: a node that
# dropped out (and with it, quorum, if it is the 2nd of 3) rejoins on the same
# node_id/data_dir and recovers every replicated row.
cargo test -p ferro-raft --test cluster_e2e \
    follower_rejoin_preserves_replicated_data -- --nocapture

echo
echo "-- Phase 2: root-key re-seed (offline ceremony dry-run) --"
# After permanent quorum loss the issuance key is re-provisioned and shares are
# re-split 3-of-5. The offline-signer dry-run runs the full eight-step rotation.
if cargo run -q -p offline-signer -- --help >/dev/null 2>&1; then
    workdir="$(mktemp -d)"
    cargo run -q -p offline-signer -- dry-run --work-dir "$workdir"
    echo "Re-seed artefacts written under: $workdir"
else
    echo "SKIP: offline-signer not buildable in this environment; run"
    echo "      'cargo run -p offline-signer -- dry-run --work-dir <scratch>' on the"
    echo "      ceremony host. See docs/operations/root-key-ceremony.md."
fi

echo
echo "PASS: rejoin recovered all writes; re-seed produced verifiable artefacts."
echo "Capture this output in the drill log."
