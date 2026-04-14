# Phase 7: Labeler Daemon

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 6 (evidence events flowing into ClickHouse)

## Objective

Correlate flows with evidence events within a ±120-second window to assign 5-class kill-chain labels, label confidence, and evidence bitmask. Write results to the `labels` table in ClickHouse.

## Reference Files

| File | What to read |
|------|-------------|
| `~/ai-shared/DFI2/DFI2_XGB_v1_Spec.md` | Labels section (lines 15-51): 5-class kill-chain, label_confidence, evidence_mask bits |
| `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` | `labels` table schema (lines 314-344): ReplacingMergeTree, flow_id key |
| `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` | `evidence_events` table (lines 353-382): event types, evidence_mask_bit |
| `~/ai-shared/DFI2/DFI2_Behavioral_Architecture_Spec.md` | Labeling design principles (lines 1-7): ClickHouse is the ledger, store atoms |

## Output Files

```
~/DFI2/labeler/
├── __init__.py
├── labeler.py             # Correlation daemon: flows + evidence → labels
└── evidence_ingest.py     # Already created in Phase 6
```

---

## Step 1: Label Definitions

From the XGB spec — 5-class kill-chain labels derived entirely from host-side evidence:

| Code | Name | Criteria |
|------|------|----------|
| 0 | **RECON** | No host-side events for this source IP in ±120s window |
| 1 | **KNOCK** | Connection reached a service (host log mentions src_ip) but zero auth attempts |
| 2 | **BRUTEFORCE** | ≥3 authentication failures from this src_ip |
| 3 | **EXPLOIT** | Suspicious command detected in logs (wget, curl, chmod, nc, reverse shell, certutil, etc.) |
| 4 | **COMPROMISE** | Auth success + any post-exploitation signal (process_create, service_install, file_download) |

**evidence_mask bits:**

| Bit | Signal |
|-----|--------|
| 0 | auth_failure |
| 1 | auth_success |
| 2 | process_create |
| 3 | service_install |
| 4 | suspicious_command |
| 5 | file_download |
| 6 | privilege_escalation |
| 7 | lateral_movement |

---

## Step 2: labeler.py — Correlation Daemon

```python
#!/usr/bin/env python3
"""labeler.py — Correlate flows with evidence events → labels table.

Runs on PV1. Every LABEL_INTERVAL seconds:
1. Find flows without labels (or with stale labels)
2. For each flow: query evidence_events within ±120s, matching src_ip
3. Apply label hierarchy → write to dfi.labels (ReplacingMergeTree)
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta

from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)s %(levelname)s %(message)s'
)
log = logging.getLogger('labeler')

# Configuration
CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
LABEL_INTERVAL = int(os.environ.get('LABEL_INTERVAL', '300'))  # 5 minutes
CORRELATION_WINDOW = int(os.environ.get('CORRELATION_WINDOW', '120'))  # ±120 seconds
BATCH_SIZE = int(os.environ.get('LABEL_BATCH', '10000'))
LOOKBACK_HOURS = int(os.environ.get('LABEL_LOOKBACK', '24'))  # Only label recent flows

# Label codes
RECON = 0
KNOCK = 1
BRUTEFORCE = 2
EXPLOIT = 3
COMPROMISE = 4


def correlate_and_label(ch: Client):
    """Main labeling pass: find unlabeled flows, correlate with evidence, assign labels."""

    # Find flows from the last LOOKBACK_HOURS that don't have labels yet
    # Use LEFT ANTI JOIN pattern: flows not in labels
    unlabeled = ch.execute(f"""
        SELECT f.flow_id, f.src_ip, f.dst_ip, f.first_ts
        FROM dfi.flows f
        LEFT JOIN dfi.labels l FINAL ON l.flow_id = f.flow_id
        WHERE f.first_ts >= now() - INTERVAL {LOOKBACK_HOURS} HOUR
          AND l.flow_id = ''
        ORDER BY f.first_ts
        LIMIT {BATCH_SIZE}
    """)

    if not unlabeled:
        # Fallback: try IS NULL approach
        unlabeled = ch.execute(f"""
            SELECT f.flow_id, f.src_ip, f.dst_ip, f.first_ts
            FROM dfi.flows f
            WHERE f.first_ts >= now() - INTERVAL {LOOKBACK_HOURS} HOUR
              AND f.flow_id NOT IN (
                  SELECT flow_id FROM dfi.labels FINAL
                  WHERE labeled_at >= now() - INTERVAL {LOOKBACK_HOURS + 1} HOUR
              )
            ORDER BY f.first_ts
            LIMIT {BATCH_SIZE}
        """)

    if not unlabeled:
        return 0

    log.info(f"Labeling {len(unlabeled)} flows")

    # Pre-fetch evidence events for the time range of these flows
    # Get time bounds
    min_ts = min(row[3] for row in unlabeled)
    max_ts = max(row[3] for row in unlabeled)

    # Expand by correlation window
    window_start = min_ts - timedelta(seconds=CORRELATION_WINDOW)
    window_end = max_ts + timedelta(seconds=CORRELATION_WINDOW)

    # Get all src_ips we need to check
    src_ips = list(set(str(row[1]) for row in unlabeled))

    # Fetch evidence events in bulk (much faster than per-flow queries)
    evidence = ch.execute("""
        SELECT src_ip, ts, event_type, evidence_mask_bit, event_detail
        FROM dfi.evidence_events
        WHERE ts BETWEEN %(start)s AND %(end)s
          AND src_ip IN %(ips)s
        ORDER BY src_ip, ts
    """, {
        'start': window_start,
        'end': window_end,
        'ips': src_ips,
    })

    # Index evidence by src_ip for fast lookup
    evidence_by_ip = {}
    for ev in evidence:
        ip = str(ev[0])
        if ip not in evidence_by_ip:
            evidence_by_ip[ip] = []
        evidence_by_ip[ip].append({
            'ts': ev[1],
            'event_type': ev[2],
            'mask_bit': ev[3],
            'detail': ev[4],
        })

    # Label each flow
    labels = []
    for flow_id, src_ip, dst_ip, first_ts in unlabeled:
        src_ip_str = str(src_ip)
        ip_evidence = evidence_by_ip.get(src_ip_str, [])

        # Filter to ±120s window around this flow
        flow_window = [
            ev for ev in ip_evidence
            if abs((ev['ts'] - first_ts).total_seconds()) <= CORRELATION_WINDOW
        ]

        label, confidence, mask, detail = assign_label(flow_window)

        labels.append({
            'flow_id': flow_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'flow_first_ts': first_ts,
            'label': label,
            'label_confidence': confidence,
            'evidence_mask': mask,
            'evidence_detail': detail,
        })

    # Batch insert to labels table
    if labels:
        ch.execute("INSERT INTO dfi.labels VALUES", labels)
        log.info(f"Labeled {len(labels)} flows: "
                 f"RECON={sum(1 for l in labels if l['label']==0)}, "
                 f"KNOCK={sum(1 for l in labels if l['label']==1)}, "
                 f"BRUTEFORCE={sum(1 for l in labels if l['label']==2)}, "
                 f"EXPLOIT={sum(1 for l in labels if l['label']==3)}, "
                 f"COMPROMISE={sum(1 for l in labels if l['label']==4)}")

    return len(labels)


def assign_label(evidence_events: list) -> tuple:
    """Apply label hierarchy to evidence events.

    Returns: (label, confidence, evidence_mask, evidence_detail)
    """
    if not evidence_events:
        return RECON, 0.5, 0, 'No evidence events in window'

    # Build evidence mask and count events by type
    mask = 0
    type_counts = {}
    details = []

    for ev in evidence_events:
        mask |= (1 << ev['mask_bit'])
        et = ev['event_type']
        type_counts[et] = type_counts.get(et, 0) + 1
        details.append(f"{et}({ev.get('detail', '')[:50]})")

    # Apply label hierarchy (highest wins)
    label = RECON
    reasons = []

    # Check COMPROMISE: auth_success (bit 1) + post-exploitation (bits 2-6)
    has_auth_success = mask & (1 << 1)
    has_post_exploit = mask & ((1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6))
    if has_auth_success and has_post_exploit:
        label = COMPROMISE
        reasons.append('auth_success + post_exploit')

    # Check EXPLOIT: suspicious_command (bit 4) or privilege_escalation (bit 6)
    elif mask & ((1 << 4) | (1 << 6)):
        label = EXPLOIT
        reasons.append('suspicious_command or privilege_escalation')

    # Check BRUTEFORCE: ≥3 auth failures
    elif type_counts.get('auth_failure', 0) >= 3:
        label = BRUTEFORCE
        reasons.append(f"auth_failure x{type_counts['auth_failure']}")

    # Check KNOCK: any evidence at all (connection reached service)
    elif evidence_events:
        label = KNOCK
        reasons.append('connection reached service')

    # Compute confidence
    confidence = compute_confidence(label, evidence_events, type_counts, mask)

    detail_str = '; '.join(reasons) + ' | ' + '; '.join(details[:10])
    return label, confidence, mask, detail_str[:4096]


def compute_confidence(label: int, events: list, type_counts: dict, mask: int) -> float:
    """Compute label confidence from evidence agreement.

    Higher confidence when:
    - More evidence signals agree
    - Multiple evidence types confirm the same label
    - Events are close in time to the flow
    """
    if label == RECON:
        # No evidence = moderate confidence (could be true recon or missing evidence)
        return 0.5

    n_events = len(events)
    n_types = bin(mask).count('1')  # Number of distinct evidence types

    if label == COMPROMISE:
        # Both auth_success and post-exploit signals → high confidence
        base = 0.85
        bonus = min(0.15, n_events * 0.01)  # More events = more confidence
        return min(1.0, base + bonus)

    elif label == EXPLOIT:
        # Suspicious command alone is moderate; multiple signals = higher
        base = 0.7
        bonus = min(0.2, (n_types - 1) * 0.1)
        return min(1.0, base + bonus)

    elif label == BRUTEFORCE:
        # More auth failures = higher confidence
        auth_fails = type_counts.get('auth_failure', 0)
        if auth_fails >= 10:
            return 0.95
        elif auth_fails >= 5:
            return 0.85
        else:
            return 0.7

    elif label == KNOCK:
        # Single connection event = lower confidence
        return 0.4 + min(0.3, n_events * 0.05)

    return 0.5


# --- Main Loop ---

def main():
    ch = Client(CH_HOST, port=CH_PORT)
    log.info(f"Labeler started: ch={CH_HOST}:{CH_PORT}, "
             f"interval={LABEL_INTERVAL}s, window=±{CORRELATION_WINDOW}s")

    while True:
        try:
            count = correlate_and_label(ch)
            if count > 0:
                log.info(f"Labeling pass complete: {count} flows labeled")
            else:
                log.debug("No unlabeled flows found")
        except Exception as e:
            log.error(f"Labeling error: {e}", exc_info=True)

        time.sleep(LABEL_INTERVAL)


if __name__ == '__main__':
    main()
```

---

## Step 3: Systemd Unit for Labeler (PV1)

```ini
# /etc/systemd/system/dfi-labeler.service
[Unit]
Description=DFI2 Labeler — Flow/Evidence Correlation → Labels
After=network-online.target clickhouse-server.service dfi-evidence-ingest.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/dfi2/labeler/labeler.py
Environment=CH_HOST=localhost
Environment=CH_PORT=9000
Environment=LABEL_INTERVAL=300
Environment=CORRELATION_WINDOW=120
Environment=LABEL_LOOKBACK=24
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now dfi-labeler
```

---

## Step 4: Re-labeling (Labels Table Uses ReplacingMergeTree)

The `labels` table uses `ReplacingMergeTree(labeled_at)` — when a flow gets re-labeled (e.g., new evidence arrives), the newer row wins after OPTIMIZE or FINAL query. This means:

- The labeler can safely re-label flows if evidence changes
- Add a periodic re-label pass for recent flows (last 2 hours) where new evidence may have arrived
- Export queries should use `FROM dfi.labels FINAL` to get the latest label per flow

```python
def relabel_recent(ch: Client):
    """Re-label flows from last 2 hours that might have gained new evidence."""
    recent = ch.execute("""
        SELECT l.flow_id, f.src_ip, f.dst_ip, f.first_ts
        FROM dfi.labels l FINAL
        INNER JOIN dfi.flows f ON f.flow_id = l.flow_id
        WHERE l.labeled_at >= now() - INTERVAL 2 HOUR
          AND f.first_ts >= now() - INTERVAL 3 HOUR
        LIMIT 5000
    """)
    # ... same correlation logic as correlate_and_label() ...
    # Only write if label changed
```

---

## Verification

1. **Labels populated:**
   ```bash
   clickhouse-client --query "SELECT count() FROM dfi.labels FINAL"
   # Should be > 0 after labeler runs
   ```

2. **Label distribution:**
   ```bash
   clickhouse-client --query "
       SELECT label, count() as cnt
       FROM dfi.labels FINAL
       GROUP BY label
       ORDER BY label
   "
   # Expected: mostly 0 (RECON), then 2 (BRUTEFORCE), some 1 (KNOCK), few 3-4
   ```

3. **Evidence correlation check:**
   ```bash
   clickhouse-client --query "
       SELECT l.flow_id, l.label, l.label_confidence, l.evidence_mask, l.evidence_detail
       FROM dfi.labels l FINAL
       WHERE l.label >= 2
       ORDER BY l.labeled_at DESC
       LIMIT 10
   "
   ```

4. **Confidence distribution:**
   ```bash
   clickhouse-client --query "
       SELECT label,
              avg(label_confidence) as avg_conf,
              min(label_confidence) as min_conf,
              max(label_confidence) as max_conf
       FROM dfi.labels FINAL
       GROUP BY label
       ORDER BY label
   "
   ```

5. **Evidence mask verification:**
   ```bash
   clickhouse-client --query "
       SELECT evidence_mask,
              bitAnd(evidence_mask, 1) as auth_fail,
              bitAnd(evidence_mask, 2) as auth_success,
              bitAnd(evidence_mask, 4) as process_create,
              count() as cnt
       FROM dfi.labels FINAL
       WHERE label >= 2
       GROUP BY evidence_mask
       ORDER BY cnt DESC
       LIMIT 10
   "
   ```

6. **Cross-check: labeled flow has matching evidence:**
   ```bash
   clickhouse-client --query "
       SELECT l.flow_id, l.label, l.evidence_detail,
              count(e.event_id) as evidence_count
       FROM dfi.labels l FINAL
       INNER JOIN dfi.flows f ON f.flow_id = l.flow_id
       LEFT JOIN dfi.evidence_events e
           ON e.src_ip = f.src_ip
           AND e.ts BETWEEN f.first_ts - INTERVAL 120 SECOND
                       AND f.first_ts + INTERVAL 120 SECOND
       WHERE l.label >= 2
       GROUP BY l.flow_id, l.label, l.evidence_detail
       ORDER BY evidence_count DESC
       LIMIT 10
   "
   ```

---

## Acceptance Criteria

- [ ] Labeler daemon running on PV1, processing flows every 5 minutes
- [ ] All 5 label classes assigned correctly based on evidence criteria
- [ ] RECON (0): flows with no matching evidence get label=0, confidence=0.5
- [ ] KNOCK (1): flows where src_ip appears in evidence but no auth attempts
- [ ] BRUTEFORCE (2): flows with ≥3 auth_failure events in ±120s
- [ ] EXPLOIT (3): flows with suspicious_command or privilege_escalation evidence
- [ ] COMPROMISE (4): flows with auth_success + post-exploitation signals
- [ ] evidence_mask correctly aggregates all evidence types per flow
- [ ] label_confidence varies appropriately (0.4-0.95 range)
- [ ] ReplacingMergeTree: re-labeling works (FINAL returns latest label)
- [ ] Labels table growing — `SELECT count() FROM dfi.labels FINAL` increasing
- [ ] No duplicate labels per flow (ReplacingMergeTree deduplication)
- [ ] Labeler handles empty evidence gracefully (RECON label)
- [ ] Performance: labeling 10K flows per pass completes in < 60 seconds

## Important Notes

- **The ±120s window is critical.** Evidence events are timestamped from host logs. Network flows are timestamped from PCAP capture. Clock skew between hosts and capture point can be 1-2 seconds. The 120-second window is generous enough to catch all correlated events while being narrow enough to avoid false correlations.
- **RECON is the default label, not "unknown".** If an attacker sends a SYN scan and there's no evidence on the host, RECON is the correct label — the wire shows reconnaissance behavior. Only flows where evidence contradicts the RECON interpretation should be upgraded.
- **ReplacingMergeTree ordering matters.** Use `FINAL` in queries or `OPTIMIZE TABLE dfi.labels FINAL` to get deduplicated results. The `labeled_at` version column ensures the newest label wins.
- **Bulk evidence fetch is essential.** Querying evidence per-flow is too slow. The labeler fetches all evidence for the batch's IP set and time range in one query, then indexes it in Python for fast per-flow correlation.
