# Session Detection Rules — Threshold-Based Kill Chain Classifier

**Deployed:** 2026-03-10 on PV1
**Cron:** `2-57/5 * * * *`
**Script:** `/opt/dfi2/ml/session_rules.py`
**Log:** `/var/log/session_rules.log`

## Overview

Pure threshold rules — no ML model. Classifies sessions `(src_ip, dst_ip, dst_port)` into kill chain stages and promotes high-activity source IPs to the AIO watchlist.

Sessions are aggregated in ClickHouse via `dfi.session_stats` (AggregatingMergeTree) fed by `dfi.mv_session_stats` (MV on `dfi.flows`). Features are computed in `dfi.v_session_features`.

**Does NOT replace per-flow scoring** — runs as second layer alongside CNN v3 + evil_02_tcp.

## Industry Sources

| Source | Threshold |
|--------|-----------|
| Elastic | >= 25 unique ports = port scan |
| Snort/Suricata | 5+ SYN in 120s = scan, 200 SSH attempts/min = brute |
| SSH flow research | PPF 11-51 for brute phase, >5 same-PPF flows = brute |
| Active Countermeasures | Low IAT variance, session >300s, periodic reconnect = C2 beacon |
| MITRE ATT&CK T1059 | Bidirectional deep sessions = command execution |
| FortiGuard | 5+ auth attempts in 120s = brute force |

---

## Kill Chain Stages

### Stage 1 — RECON (Port/Host Scanning)

#### `horiz_scan` — Horizontal SYN Scan
Thin SYN-only sessions with no reply. Classic port sweep.

| Feature | Threshold |
|---------|-----------|
| `sess_flow_count` | >= 3 |
| `sess_syn_only_ratio` | >= 0.8 (80%+ SYN-only) |
| `sess_reply_ratio` | <= 0.1 (almost no responses) |
| `sess_bidirectional_ratio` | <= 0.05 (unidirectional) |

**Confidence:** 0.90

#### `wide_scan` — Source-Wide Scanning
IP hitting many ports across many destinations. Evaluated at source level (not per-session).

| Feature | Threshold |
|---------|-----------|
| `src_total_sessions` | >= 20 (unique dst_ip:dst_port pairs) |
| `src_total_ports` | >= 10 (unique ports) |
| `src_single_flow_pct` | >= 0.7 (70%+ single-flow probes) |

*Used for watchlist evaluation, not per-session classification.*

---

### Stage 2 — BRUTE FORCE (Repeated Auth Attempts)

#### `auth_brute` — Authentication Brute Force
Repeated connections to same service with partial responses (auth failures).

| Feature | Threshold |
|---------|-----------|
| `sess_flow_count` | >= 10 |
| `sess_reply_ratio` | 0.3 – 0.7 (server responding but not interactive) |
| `sess_bidirectional_ratio` | <= 0.4 (limited data exchange) |
| `sess_completed_ratio` | >= 0.1 (some handshakes complete) |

**Confidence:** 0.80

#### `heavy_brute` — High-Volume Brute Force
Very high flow count to single service. Definite brute force.

| Feature | Threshold |
|---------|-----------|
| `sess_flow_count` | >= 50 |
| `sess_reply_ratio` | >= 0.1 (at least some replies) |
| `sess_bidirectional_ratio` | <= 0.5 (not interactive) |

**Confidence:** 0.90

---

### Stage 3 — EXPLOIT (Interactive / Data Transfer)

#### `interactive` — Interactive Shell Session
Bidirectional session with long flows and significant reverse data. Indicates command execution.

| Feature | Threshold |
|---------|-----------|
| `sess_bidirectional_ratio` | >= 0.5 (50%+ bidirectional) |
| `sess_max_flow_dur` | >= 30,000 ms (>30s flow) |
| `sess_max_bytes_rev` | >= 1,024 bytes (>1KB reverse) |
| `sess_flow_count` | >= 2 (not a single probe) |

**Confidence:** 0.75

#### `data_exfil` — Data Exfiltration
Large sustained data transfer. Deep session with significant payload.

| Feature | Threshold |
|---------|-----------|
| `sess_bidirectional_ratio` | >= 0.3 |
| `sess_avg_bytes_per_flow` | >= 5,000 (>5KB avg) |
| `sess_max_bytes_rev` | >= 10,240 (>10KB reverse) |
| `sess_duration` | >= 60 seconds |

**Confidence:** 0.80

---

### Stage 4 — C2 (Command & Control Beacon)

#### `persistent` — Persistent Reconnection
Session spanning 5+ minutes with multiple completed TCP connections. Beacon behavior.

| Feature | Threshold |
|---------|-----------|
| `sess_duration` | >= 300 seconds (5 min) |
| `sess_flow_count` | >= 5 (multiple reconnections) |
| `sess_bidirectional_ratio` | >= 0.3 |
| `sess_completed_ratio` | >= 0.3 (TCP handshakes complete) |

**Confidence:** 0.85

#### `long_lived` — Long-Lived Session
Session spanning 1+ hour with periodic connections.

| Feature | Threshold |
|---------|-----------|
| `sess_duration` | >= 3,600 seconds (1 hour) |
| `sess_flow_count` | >= 3 |
| `sess_bidirectional_ratio` | >= 0.2 |

**Confidence:** 0.75

---

## Evaluation Order

Rules are evaluated **highest stage first** (C2 → EXPLOIT → BRUTE → RECON). First match wins.

```
C2 persistent → C2 long_lived → EXPLOIT data_exfil → EXPLOIT interactive
→ BRUTE heavy → BRUTE auth → RECON horiz_scan → BENIGN
```

---

## Watchlist Promotion

Source IPs meeting aggregate thresholds across all their sessions are pushed to the AIO watchlist (`/opt/dfi-hunter/watchlist.db`).

### `scanner`
| Feature | Threshold |
|---------|-----------|
| Sessions | >= 50 |
| Unique ports | >= 10 |
| Single-flow sessions | >= 50% |

**Action:** priority=2, capture_depth=2, reason=`session_scanner`

### `brute_forcer`
| Feature | Threshold |
|---------|-----------|
| Sessions | >= 5 |
| Total flows | >= 100 |
| Avg reply rate | <= 0.5 |

**Action:** priority=2, capture_depth=2, reason=`session_brute`

### `heavy_hitter`
| Feature | Threshold |
|---------|-----------|
| Sessions | >= 100 |
| Total flows | >= 500 |

**Action:** priority=3, capture_depth=1, reason=`session_heavy_hitter`

### Conflict Resolution

`ON CONFLICT(src_ip) DO UPDATE`:
- `capture_depth` = MAX (keep deeper capture)
- `priority` = MIN (keep higher priority)
- `source` = preserve existing if `xgb_scorer` or `classifier` (don't downgrade)

---

## Noise Filtering

Skipped IPs (before classification):
- `224.x.x.x` — Multicast
- `239.x.x.x` — Multicast
- `255.x.x.x` — Broadcast
- `0.x.x.x` — Invalid
- `169.254.x.x` — Link-local

---

## Session Features Used

| # | Feature | Description |
|---|---------|-------------|
| 1 | `sess_flow_count` | Total flows in session |
| 2 | `sess_bytes_fwd` | Total forward bytes |
| 3 | `sess_bytes_rev` | Total reverse bytes |
| 4 | `sess_pkts_fwd` | Total forward packets |
| 5 | `sess_pkts_rev` | Total reverse packets |
| 6 | `sess_reply_ratio` | pkts_rev / pkts_fwd |
| 7 | `sess_duration` | Seconds from first to last flow |
| 8 | `sess_avg_flow_dur` | Avg flow duration (ms) |
| 9 | `sess_max_flow_dur` | Max flow duration (ms) |
| 10 | `sess_max_bytes_rev` | Max reverse bytes in any flow |
| 11 | `sess_avg_bytes_per_flow` | (bytes_fwd + bytes_rev) / flow_count |
| 12 | `sess_payload_ratio` | bytes_rev / (bytes_fwd + bytes_rev) |
| 13 | `sess_bidirectional_ratio` | Fraction of flows with pkts_rev > 0 |
| 14 | `sess_syn_only_ratio` | Fraction of flows with conn_state=0 |
| 15 | `sess_rst_ratio` | rst_count / flow_count |
| 16 | `sess_completed_ratio` | Fraction of flows with conn_state=4 |
| 17 | `sess_avg_tcp_flags` | (syn+fin+rst+psh) / flow_count |

Source-level features (for watchlist evaluation):
- `src_total_sessions` — unique (dst_ip, dst_port) pairs
- `src_total_ports` — unique destination ports
- `src_total_flows` — total flow count across all sessions
- `src_single_flow_sessions` — sessions with exactly 1 flow
- `src_reply_rate` — average reply ratio across sessions

---

## 24-Hour Production Results (2026-03-10)

| Stage | Sessions | % |
|-------|----------|---|
| BENIGN | ~21K | ~95% |
| RECON | 3 | <0.1% |
| BRUTE | 10 | <0.1% |
| EXPLOIT | 35 | 0.2% |
| C2 | 995 | 4.5% |

**Watchlist pushed:** 11 IPs

C2 count is expected — honeypot environment attracts persistent RDP/SSH brute force campaigns that meet the duration + bidirectional thresholds.
