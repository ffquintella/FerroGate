# SRE runbooks

One runbook per alert. Each follows the same shape: **alert → what it means →
impact → diagnose → remediate → escalate**. Thresholds are quoted from the
code so the runbook and the alert rule cannot drift.

| Alert | Threshold | Fail mode | Runbook |
|-------|-----------|-----------|---------|
| STH publish lag | > 5 min since last STH | Audit log not advancing; tamper-evidence gap | [sth-lag.md](sth-lag.md) |
| CRL stale | CRL age > 5 min (+60 s leeway) | MIA refuses to mint helper tokens (fail-closed) | [crl-stale.md](crl-stale.md) |
| Key-share failure | reconstruction fails, or anchor backlog > 5 min | Issuance halts / transparency anchoring stalls | [key-share-failure.md](key-share-failure.md) |

These complement `docs/operations.md` §"Day-2 SRE concerns", which lists the
metrics and alert set; the runbooks are the response procedures behind them.
