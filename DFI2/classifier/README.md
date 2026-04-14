# Classifier

The classifier assigns behavioral group labels to attacker IPs based on their network flow patterns and evidence. It turns raw flow statistics into human-readable attack categories (e.g., "SSH_BRUTE", "PORT_SCAN", "PIVOT_CHAIN") and manages the watchlist that drives downstream capture and blocking decisions.

## How It Works

Every 5 minutes (configurable), the classifier:

1. Queries flow aggregates across three time windows (15 minutes, 1 hour, 6 hours).
2. Enriches with fanout data (lateral movement hops across targets/VLANs) and evidence counts.
3. Applies a rule-based classification tree to assign a group, sub-group, confidence, and priority.
4. Writes results to `dfi.group_assignments`, computes capture depth changes, and pushes to the watchlist.

## Key Files

### `classifier.py`

The main classification engine. Runs as a long-lived service.

**Classification groups and sub-groups:**

| Group | Sub-Groups | Priority |
|-------|------------|----------|
| CAMPAIGN_PROGRESSION | PIVOT_CHAIN, RETURN_AND_DEEPEN, VERTICAL_ESCALATION, HORIZONTAL_SWEEP | P1-P2 |
| EXPLOIT_DELIVERY | SERVICE_EXPLOIT, WEB_EXPLOIT, PHASED_ATTACK | P1 |
| CREDENTIAL_ATTACK | SSH_BRUTE, MYSQL_BRUTE, RDP_BRUTE, HTTP_AUTH_SPRAY, CROSS_SERVICE_ROT | P1 |
| INFRASTRUCTURE_ABUSE | SIP_FRAUD, DNS_TUNNEL, AMPLIFICATION | P2 |
| RECON | PORT_SCAN, SERVICE_SWEEP, BANNER_GRAB | P3 |
| UNCLASSIFIED | ONE_SHOT_NOISE, LOW_AND_SLOW, EMERGING | P3 |

**Multi-window classification:** Queries 15-minute, 1-hour, and 6-hour windows, then picks the highest-priority (lowest number) classification for each IP. Ties are broken by confidence.

**Features used:** Total flows, unique ports/targets/protocols, top port, average packets forward, per-service flow counts (SSH, MySQL, RDP, HTTP, SIP, DNS), TCP/UDP ratio, average entropy, time span, fanout metrics (unique targets, ports, VLANs, max session gap), and evidence counts (auth failures, auth successes, suspicious commands).

**Capture depth:** Computed based on priority and sub-group. P1 PIVOT_CHAIN/RETURN_AND_DEEPEN gets depth 3 (full packet capture). P1/P2 get depth 2. P3 with confidence >= 0.7 gets depth 1. ONE_SHOT_NOISE gets depth 0.

**Watchlist TTL:** P1 = 72 hours, P2 = 48 hours, P3 = 24 hours.

### `watchlist_push.py`

Manages writes to the local SQLite watchlist and logs sync events to ClickHouse.

- **`push_local(entries)`:** Upserts into the local `watchlist.db` with conflict resolution (max capture_depth, min priority, source preservation for `xgb_scorer`).
- **`push_aio(entries)`:** Pushes the watchlist to a remote host via SSH/SFTP (transfers a JSON file, runs a Python one-liner remotely to upsert).
- **`_log_syncs(entries)`:** Writes watchlist update events to `dfi.watchlist_syncs` for audit trail.
- **`push_watchlist(entries, push_remote=False)`:** Entry point called by the classifier. Always pushes local + logs to CH.

### `watchlist_pull.py`

Runs on a secondary host to pull the watchlist from the primary host (PV1) via SSH. Dumps the remote watchlist as JSON, parses it locally, and upserts into the local `watchlist.db`.

## Pipeline Position

```
dfi.flows (aggregated) + dfi.fanout_hops + dfi.evidence_events
                              |
                              v
                      classifier.py
                              |
              +---------------+----------------+
              |               |                |
              v               v                v
    dfi.group_assignments  dfi.depth_changes  watchlist.db
                                                  |
                                                  v
                                    Capture engine + MikroTik blocking
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CH_HOST` | `localhost` | ClickHouse host |
| `CH_PORT` | `9000` | ClickHouse native port |
| `CLASSIFY_INTERVAL` | `300` | Seconds between classification runs |
| `WATCHLIST_DB` | `/opt/dfi-hunter/watchlist.db` | Local SQLite watchlist path |
| `AIO_HOST` | `192.168.0.113` | Remote host for watchlist push |
| `AIO_SSH_PORT` | `2222` | Remote SSH port |
| `AIO_USER` | `colo8gent` | Remote SSH user |
| `AIO_PASS` | *(required)* | Remote SSH password (env var) |
| `PV1_HOST` | `192.168.0.100` | Primary host for watchlist pull |
| `PV1_SSH_PORT` | `22` | Primary host SSH port |
| `PV1_USER` | `root` | Primary host SSH user |
| `PV1_PASS` | `CHANGE_ME` | Primary host SSH password |
| `PULL_INTERVAL` | `300` | Seconds between watchlist pulls |

## Dependencies

- `clickhouse-driver` -- ClickHouse native protocol client
- `paramiko` -- SSH/SFTP for remote watchlist push/pull
