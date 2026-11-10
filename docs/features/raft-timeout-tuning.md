# Raft timeout tuning

## Problem

hiqlite's `heartbeat_interval` (default 500 ms) is also the time-to-live of every
`AppendEntries` RPC. On a link that drops or delays packets, two TCP
retransmissions exceed it and openraft logs `timeout while confirming leadership
... CheckIsLeaderError: not enough for a quorum` while both nodes are healthy.
With two voters, quorum is both nodes, so each blip fails admin logins and SVID
issuance. The admin client shows this as "O servidor nao concluiu o pedido".

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `CMIS_RAFT_HEARTBEAT_MS` | `500` | Leader heartbeat and `AppendEntries` time-to-live |
| `CMIS_RAFT_ELECTION_MIN_MS` | `1500` | Shortest follower election timeout |
| `CMIS_RAFT_ELECTION_MAX_MS` | `3000` | Longest follower election timeout |
| `CMIS_RAFT_ALLOW_AGGRESSIVE_TIMEOUTS` | `false` | Accept values below the defaults |

Absent variables keep hiqlite's values. Invalid values stop startup; nothing is
clamped. Heartbeat range 100..=60000 ms, election maximum at most 300000 ms, the
election minimum at least 3 x heartbeat, and the maximum above the minimum.

## Suggested setting for a cross-site pair

`CMIS_RAFT_HEARTBEAT_MS=2000`, `CMIS_RAFT_ELECTION_MIN_MS=6000`,
`CMIS_RAFT_ELECTION_MAX_MS=12000`, set identically on every node. A longer
heartbeat means a dead leader is noticed later (up to the election minimum).

## Not covered

The two-voter topology still tolerates no node failure; a third voter is the
real fix. Only liveness depends on these values, never Raft safety.
