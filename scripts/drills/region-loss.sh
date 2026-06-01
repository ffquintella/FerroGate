#!/usr/bin/env bash
# Region-loss drill harness (feature: M6 operational drills).
#
# Simulates the loss of a region by killing a CMIS replica out of a 3-node
# Raft cluster while quorum (2/3) holds, and asserts the survivors keep
# electing a leader, replicating, and serving issuance. Locally this drives the
# in-process ferro-raft cluster harness; in staging the same assertions are run
# against the real anycast fleet (see docs/operations/drills/region-loss.md).
#
# Usage:  scripts/drills/region-loss.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "== FerroGate region-loss drill =="
echo "Exercising: leader election, non-leader kill (region loss), replication,"
echo "follower rejoin, and a randomized kill/revive chaos run while quorum holds."
echo

# These four tests collectively model a region going dark and recovering:
#   three_node_cluster_elects_a_leader_and_replicates  -> baseline quorum
#   killing_a_non_leader_keeps_the_cluster_issuing      -> single-region loss
#   follower_rejoin_preserves_replicated_data           -> region recovery
#   short_chaos_run_keeps_serving_while_quorum_holds     -> repeated flapping
cargo test -p ferro-raft --test cluster_e2e -- --nocapture

echo
echo "PASS: cluster kept serving with one replica down; the recovered replica"
echo "re-synced all writes. Capture this output in the drill log."
