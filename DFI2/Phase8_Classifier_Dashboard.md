# Phase 8: Classifier + Dashboard

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 7 (labels exist in ClickHouse)

## Objective

Build the periodic behavior classifier (20 subgroups across 6 intents), capture depth promotion/demotion logic, watchlist push, and Streamlit v2 dashboard reading ClickHouse.

## Reference Files

| File | What to read |
|------|-------------|
| `~/ai-shared/DFI2/DFI2_Behavioral_Architecture_Spec.md` | Behavior Group Hierarchy (lines 121-205): full 6-intent × 20-subgroup hierarchy, key indicators, priority response model |
| `~/ai-shared/DFI2/DFI2_Behavioral_Architecture_Spec.md` | Analyst Workflow (lines 360-403): single IP lookup, analyst actions, automated vs manual path |
| `~/ai-shared/DFI2/DFI2_Behavioral_Architecture_Spec.md` | Temporal Analysis (lines 406-432): rolling windows, fanout shape features |
| `~/ai-shared/DFI2/DFI2_Behavioral_Architecture_Spec.md` | Capture Depth Promotion/Demotion (lines 72-89) |
| `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` | `group_assignments` table (lines 465-487), `depth_changes` table (lines 492-510), `analyst_actions` table (lines 514-535) |
| `~/DFI2/sync/push_watchlist.py` | Phase 1 push mechanism (PV1 → AIO SQLite) |

## Output Files

```
~/DFI2/
├── classifier/
│   ├── __init__.py
│   ├── classifier.py         # Periodic behavior group assignment
│   └── watchlist_push.py     # Classifier → SQLite watchlist (local + AIO)
├── dashboard/
│   ├── __init__.py
│   └── dashboard.py          # Streamlit v2 (ClickHouse-backed)
```

---

## Step 1: classifier.py — Behavior Group Hierarchy

### Group Definitions

```python
#!/usr/bin/env python3
"""classifier.py — Periodic attacker behavior classification.

Runs on PV1 every 5-10 minutes.
Queries CH for per-attacker aggregates in rolling windows (15min, 1h, 6h).
Assigns behavior groups from the 6-intent × 20-subgroup hierarchy.
Computes capture depth promotions/demotions.
Pushes updated watchlist to SQLite (local + AIO).
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
log = logging.getLogger('classifier')

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
CLASSIFY_INTERVAL = int(os.environ.get('CLASSIFY_INTERVAL', '300'))  # 5 minutes

# Priority levels
P1 = 1  # Immediate: CREDENTIAL_ATTACK, EXPLOIT_DELIVERY, PIVOT_CHAIN, RETURN_AND_DEEPEN
P2 = 2  # Short-TTL watch: INFRASTRUCTURE_ABUSE, HORIZONTAL_SWEEP, VERTICAL_ESCALATION
P3 = 3  # Monitor: RECON, UNCLASSIFIED


# --- Per-Attacker Aggregate Queries ---

ATTACKER_AGGREGATES_SQL = """
SELECT
    src_ip AS attacker_ip,

    -- Flow counts
    count() AS total_flows,
    countIf(first_ts >= now() - INTERVAL 15 MINUTE) AS flows_15m,
    countIf(first_ts >= now() - INTERVAL 1 HOUR) AS flows_1h,
    countIf(first_ts >= now() - INTERVAL 6 HOUR) AS flows_6h,

    -- Port/target diversity
    uniq(dst_port) AS unique_ports,
    uniq(dst_ip) AS unique_targets,
    uniq(app_proto) AS unique_protos,
    uniq(vlan_id) AS unique_vlans,

    -- Top port
    topK(1)(dst_port)[1] AS top_port,

    -- Volume stats
    avg(pkts_fwd) AS avg_pkts_fwd,
    avg(pkts_rev) AS avg_pkts_rev,
    avg(duration_ms) AS avg_duration,
    avg(n_events) AS avg_n_events,

    -- TCP behavior
    avgIf(psh_count, ip_proto = 6) AS avg_psh_count,
    sumIf(syn_count, ip_proto = 6) AS total_syns,
    avgIf(conn_state, ip_proto = 6) AS avg_conn_state,

    -- Payload
    avgIf(entropy_first, entropy_first IS NOT NULL) AS avg_entropy,

    -- Protocol distribution
    countIf(ip_proto = 6) AS tcp_flows,
    countIf(ip_proto = 17) AS udp_flows,

    -- Time span
    dateDiff('minute', min(first_ts), max(first_ts)) AS span_minutes,

    -- Auth-related ports
    countIf(dst_port = 22) AS ssh_flows,
    countIf(dst_port = 3306) AS mysql_flows,
    countIf(dst_port = 3389) AS rdp_flows,
    countIf(dst_port IN (80, 443, 8080)) AS http_flows,
    countIf(dst_port = 5060) AS sip_flows,
    countIf(dst_port = 53) AS dns_flows

FROM dfi.flows
WHERE first_ts >= now() - INTERVAL 6 HOUR
GROUP BY src_ip
HAVING total_flows >= 2
ORDER BY total_flows DESC
LIMIT 50000
"""

FANOUT_AGGREGATES_SQL = """
SELECT
    attacker_ip,
    count() AS hop_count,
    uniq(target_ip) AS unique_targets,
    uniq(dst_port) AS unique_ports,
    uniq(vlan_id) AS unique_vlans,
    max(session_gap_sec) AS max_gap_sec,
    avg(session_gap_sec) AS avg_gap_sec
FROM dfi.fanout_hops
WHERE first_ts >= now() - INTERVAL 6 HOUR
GROUP BY attacker_ip
"""

EVIDENCE_COUNTS_SQL = """
SELECT
    src_ip AS attacker_ip,
    countIf(event_type = 'auth_failure') AS auth_failures,
    countIf(event_type = 'auth_success') AS auth_successes,
    countIf(event_type = 'suspicious_command') AS suspicious_cmds,
    countIf(event_type = 'process_create') AS process_creates
FROM dfi.evidence_events
WHERE ts >= now() - INTERVAL 6 HOUR
GROUP BY src_ip
"""


def classify_attacker(agg: dict, fanout: dict, evidence: dict) -> tuple:
    """Classify a single attacker into (group_id, sub_group_id, confidence, priority).

    Returns tuple: (group_id, sub_group_id, confidence, priority)
    """
    flows = agg['total_flows']
    ports = agg['unique_ports']
    targets = agg['unique_targets']
    top_port = agg['top_port']
    avg_pkts = agg['avg_pkts_fwd']
    avg_psh = agg.get('avg_psh_count', 0) or 0
    ssh = agg['ssh_flows']
    mysql = agg['mysql_flows']
    rdp = agg['rdp_flows']
    http = agg['http_flows']
    sip = agg['sip_flows']
    dns = agg['dns_flows']
    tcp = agg['tcp_flows']
    udp = agg['udp_flows']
    avg_entropy = agg.get('avg_entropy') or 0
    vlans = fanout.get('unique_vlans', 1)
    fan_targets = fanout.get('unique_targets', targets)
    fan_ports = fanout.get('unique_ports', ports)
    auth_fails = evidence.get('auth_failures', 0)
    auth_success = evidence.get('auth_successes', 0)
    susp_cmds = evidence.get('suspicious_cmds', 0)

    # --- CAMPAIGN_PROGRESSION (check first — highest threat) ---

    # PIVOT_CHAIN: both target and port change across hops, multiple VLANs
    if fan_targets >= 3 and fan_ports >= 3 and vlans >= 2:
        return ('CAMPAIGN_PROGRESSION', 'PIVOT_CHAIN', 0.85, P1)

    # RETURN_AND_DEEPEN: revisits previous target with deeper interaction
    # (detected by gap analysis + increasing pkts — simplified heuristic)
    max_gap = fanout.get('max_gap_sec') or 0
    if fan_targets >= 2 and max_gap > 1800 and auth_fails > 0:
        return ('CAMPAIGN_PROGRESSION', 'RETURN_AND_DEEPEN', 0.75, P1)

    # VERTICAL_ESCALATION: same target, multiple ports/services
    if targets <= 2 and ports >= 4 and flows >= 5:
        return ('CAMPAIGN_PROGRESSION', 'VERTICAL_ESCALATION', 0.7, P2)

    # HORIZONTAL_SWEEP: same port, many targets
    if ports <= 3 and targets >= 10 and flows >= 20:
        return ('CAMPAIGN_PROGRESSION', 'HORIZONTAL_SWEEP', 0.8, P2)

    # --- EXPLOIT_DELIVERY ---

    if susp_cmds > 0:
        return ('EXPLOIT_DELIVERY', 'SERVICE_EXPLOIT', 0.8, P1)

    if http > 0 and avg_entropy > 6.0 and avg_psh > 5:
        return ('EXPLOIT_DELIVERY', 'WEB_EXPLOIT', 0.7, P1)

    # --- CREDENTIAL_ATTACK ---

    if auth_fails >= 3:
        # Determine sub-group by service
        if ssh > mysql and ssh > rdp and ssh > http:
            return ('CREDENTIAL_ATTACK', 'SSH_BRUTE', 0.9, P1)
        elif mysql >= ssh and mysql > rdp:
            return ('CREDENTIAL_ATTACK', 'MYSQL_BRUTE', 0.9, P1)
        elif rdp >= ssh and rdp >= mysql:
            return ('CREDENTIAL_ATTACK', 'RDP_BRUTE', 0.9, P1)
        elif http > 0:
            return ('CREDENTIAL_ATTACK', 'HTTP_AUTH_SPRAY', 0.85, P1)
        else:
            # Multiple auth services
            auth_services = sum(1 for x in [ssh, mysql, rdp, http] if x > 0)
            if auth_services >= 2:
                return ('CREDENTIAL_ATTACK', 'CROSS_SERVICE_ROT', 0.8, P1)
            return ('CREDENTIAL_ATTACK', 'SSH_BRUTE', 0.75, P1)  # default

    # High session count on auth port without evidence (evidence may be delayed)
    if ssh > 50 and avg_pkts > 8:
        return ('CREDENTIAL_ATTACK', 'SSH_BRUTE', 0.6, P1)
    if mysql > 20 and avg_pkts > 4:
        return ('CREDENTIAL_ATTACK', 'MYSQL_BRUTE', 0.6, P1)
    if rdp > 10:
        return ('CREDENTIAL_ATTACK', 'RDP_BRUTE', 0.6, P1)

    # --- INFRASTRUCTURE_ABUSE ---

    if sip > 10 and udp > tcp:
        return ('INFRASTRUCTURE_ABUSE', 'SIP_FRAUD', 0.8, P2)

    if dns > 20 and avg_pkts < 5:
        return ('INFRASTRUCTURE_ABUSE', 'DNS_TUNNEL', 0.6, P2)

    if udp > 50 and avg_pkts <= 2 and targets > 5:
        return ('INFRASTRUCTURE_ABUSE', 'AMPLIFICATION', 0.7, P2)

    # --- RECON ---

    if ports > 20 and avg_pkts < 8 and tcp > udp:
        return ('RECON', 'PORT_SCAN', 0.85, P3)

    if targets > 100 and ports <= 3:
        return ('RECON', 'SERVICE_SWEEP', 0.8, P3)

    if ports <= 5 and avg_pkts >= 4 and avg_pkts <= 8 and tcp > 0:
        return ('RECON', 'BANNER_GRAB', 0.6, P3)

    # --- UNCLASSIFIED ---

    span = agg.get('span_minutes', 0) or 0
    if flows <= 2 and avg_pkts < 5:
        return ('UNCLASSIFIED', 'ONE_SHOT_NOISE', 0.5, P3)

    if span > 60 and flows < 10:
        return ('UNCLASSIFIED', 'LOW_AND_SLOW', 0.5, P3)

    return ('UNCLASSIFIED', 'EMERGING', 0.4, P3)


# --- Depth Promotion/Demotion ---

def compute_depth(current_depth: int, group_id: str, sub_group_id: str,
                  priority: int, confidence: float) -> int:
    """Compute target capture depth from classification.

    Promotion rules:
        D1 → D2: classified into real group with confidence > threshold
        D2 → D3: CAMPAIGN_PROGRESSION, per-flow model predicts EXPLOIT/COMPROMISE
        Any → D3: analyst push (handled separately)

    Demotion rules:
        D3 → D2: TTL expires, no new interesting activity
        D2 → D1: reclassified to low-priority, no return behavior
        D1 → D0: confirmed repetitive noise
    """
    # P1 groups → minimum D2, promote to D3 for campaign progression
    if priority == P1:
        if sub_group_id in ('PIVOT_CHAIN', 'RETURN_AND_DEEPEN'):
            return 3  # D3 for highest-threat patterns
        return max(current_depth, 2)  # At least D2

    # P2 groups → minimum D2
    if priority == P2:
        return max(current_depth, 2)

    # P3 with high confidence → stay D1
    if priority == P3 and confidence >= 0.7:
        if group_id == 'UNCLASSIFIED' and sub_group_id == 'ONE_SHOT_NOISE':
            return 0  # D0 for confirmed noise
        return max(current_depth, 1)

    # Default: D1
    return max(current_depth, 1)


# --- Main Classification Loop ---

def run_classification(ch: Client):
    """Run one classification pass."""

    # Fetch aggregates
    log.info("Fetching attacker aggregates...")
    agg_rows = ch.execute(ATTACKER_AGGREGATES_SQL)
    agg_cols = ['attacker_ip', 'total_flows', 'flows_15m', 'flows_1h', 'flows_6h',
                'unique_ports', 'unique_targets', 'unique_protos', 'unique_vlans',
                'top_port', 'avg_pkts_fwd', 'avg_pkts_rev', 'avg_duration', 'avg_n_events',
                'avg_psh_count', 'total_syns', 'avg_conn_state', 'avg_entropy',
                'tcp_flows', 'udp_flows', 'span_minutes',
                'ssh_flows', 'mysql_flows', 'rdp_flows', 'http_flows', 'sip_flows', 'dns_flows']
    aggs = {str(row[0]): dict(zip(agg_cols, row)) for row in agg_rows}

    fanout_rows = ch.execute(FANOUT_AGGREGATES_SQL)
    fanout_cols = ['attacker_ip', 'hop_count', 'unique_targets', 'unique_ports',
                   'unique_vlans', 'max_gap_sec', 'avg_gap_sec']
    fanouts = {str(row[0]): dict(zip(fanout_cols, row)) for row in fanout_rows}

    evidence_rows = ch.execute(EVIDENCE_COUNTS_SQL)
    evidence_cols = ['attacker_ip', 'auth_failures', 'auth_successes',
                     'suspicious_cmds', 'process_creates']
    evidence = {str(row[0]): dict(zip(evidence_cols, row)) for row in evidence_rows}

    log.info(f"Classifying {len(aggs)} attackers...")

    # Get current depth from watchlist (for demotion logic)
    current_depths = {}
    try:
        depth_rows = ch.execute("""
            SELECT attacker_ip, argMax(new_depth, changed_at) AS current_depth
            FROM dfi.depth_changes
            WHERE changed_at >= now() - INTERVAL 7 DAY
            GROUP BY attacker_ip
        """)
        current_depths = {str(row[0]): row[1] for row in depth_rows}
    except Exception:
        pass  # No depth changes yet

    # Classify each attacker
    group_assignments = []
    depth_changes = []
    watchlist_entries = []
    now = datetime.utcnow()

    for ip, agg in aggs.items():
        fanout = fanouts.get(ip, {})
        ev = evidence.get(ip, {})

        group_id, sub_group_id, confidence, priority = classify_attacker(agg, fanout, ev)

        # Group assignment event
        group_assignments.append({
            'attacker_ip': ip,
            'group_id': group_id,
            'sub_group_id': sub_group_id,
            'confidence': confidence,
            'priority': priority,
            'window_start': now - timedelta(hours=6),
            'window_end': now,
            'feature_summary': json.dumps({
                'flows': agg['total_flows'],
                'ports': agg['unique_ports'],
                'targets': agg['unique_targets'],
                'top_port': agg['top_port'],
            }),
        })

        # Depth computation
        old_depth = current_depths.get(ip, 1)
        new_depth = compute_depth(old_depth, group_id, sub_group_id, priority, confidence)

        if new_depth != old_depth:
            depth_changes.append({
                'attacker_ip': ip,
                'old_depth': old_depth,
                'new_depth': new_depth,
                'trigger_reason': f'{group_id}/{sub_group_id} conf={confidence:.2f}',
                'triggered_by': 'classifier',
            })

        # Watchlist entry
        # Set expiry based on priority
        if priority == P1:
            expires_hours = 72
        elif priority == P2:
            expires_hours = 48
        else:
            expires_hours = 24

        watchlist_entries.append({
            'src_ip': ip,
            'capture_depth': new_depth,
            'priority': priority,
            'group_id': group_id,
            'sub_group_id': sub_group_id,
            'top_port': agg['top_port'],
            'reason': f'{group_id}/{sub_group_id}',
            'source': 'classifier',
            'expires_at': time.time() + (expires_hours * 3600),
        })

    # Write to ClickHouse
    if group_assignments:
        ch.execute("INSERT INTO dfi.group_assignments VALUES", group_assignments)
        log.info(f"Wrote {len(group_assignments)} group assignments")

    if depth_changes:
        ch.execute("INSERT INTO dfi.depth_changes VALUES", depth_changes)
        log.info(f"Wrote {len(depth_changes)} depth changes")

    # Push to watchlist
    if watchlist_entries:
        push_watchlist(watchlist_entries)
        log.info(f"Pushed {len(watchlist_entries)} entries to watchlist")

    # Log group distribution
    groups = {}
    for ga in group_assignments:
        g = ga['group_id']
        groups[g] = groups.get(g, 0) + 1
    log.info(f"Group distribution: {groups}")

    return len(group_assignments)


def push_watchlist(entries: list):
    """Push watchlist entries to local SQLite and trigger AIO push."""
    import sqlite3

    # Local PV1 watchlist
    local_db = os.environ.get('WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')
    try:
        conn = sqlite3.connect(local_db, timeout=10)
        for entry in entries:
            conn.execute("""
                INSERT OR REPLACE INTO watchlist
                (src_ip, capture_depth, priority, group_id, sub_group_id,
                 top_port, reason, source, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry['src_ip'], entry['capture_depth'], entry['priority'],
                entry['group_id'], entry['sub_group_id'], entry['top_port'],
                entry['reason'], entry['source'], entry['expires_at'],
                time.time(),
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Local watchlist push failed: {e}")

    # AIO push via push_watchlist.py (cron handles this, but trigger immediately too)
    # The sync/push_watchlist.py cron job will pick up the changes


def main():
    ch = Client(CH_HOST, port=CH_PORT)
    log.info(f"Classifier started: ch={CH_HOST}:{CH_PORT}, interval={CLASSIFY_INTERVAL}s")

    while True:
        try:
            count = run_classification(ch)
            log.info(f"Classification pass complete: {count} attackers classified")
        except Exception as e:
            log.error(f"Classification error: {e}", exc_info=True)

        time.sleep(CLASSIFY_INTERVAL)


if __name__ == '__main__':
    main()
```

---

## Step 2: Systemd Unit for Classifier (PV1)

```ini
# /etc/systemd/system/dfi-classifier.service
[Unit]
Description=DFI2 Classifier — Behavior Group Assignment
After=network-online.target clickhouse-server.service dfi-labeler.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/dfi2/classifier/classifier.py
Environment=CH_HOST=localhost
Environment=CH_PORT=9000
Environment=CLASSIFY_INTERVAL=300
Environment=WATCHLIST_DB=/opt/dfi-hunter/watchlist.db
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

---

## Step 3: dashboard.py — Streamlit v2

```python
#!/usr/bin/env python3
"""dashboard.py — Streamlit v2 dashboard backed by ClickHouse.

Run with: streamlit run dashboard.py --server.port 8501
"""

import json
import os
import time

import streamlit as st
from clickhouse_driver import Client

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
WATCHLIST_DB = os.environ.get('WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')


@st.cache_resource
def get_ch():
    return Client(CH_HOST, port=CH_PORT)


def main():
    st.set_page_config(page_title="DFI2 Dashboard", layout="wide")
    st.title("DFI2 — Attacker Intelligence Dashboard")
    ch = get_ch()

    # Sidebar navigation
    page = st.sidebar.radio("View", [
        "Overview",
        "IP Lookup",
        "Top Attackers",
        "Label Distribution",
        "Ingest Monitor",
        "Storage Stats",
    ])

    if page == "Overview":
        render_overview(ch)
    elif page == "IP Lookup":
        render_ip_lookup(ch)
    elif page == "Top Attackers":
        render_top_attackers(ch)
    elif page == "Label Distribution":
        render_label_distribution(ch)
    elif page == "Ingest Monitor":
        render_ingest_monitor(ch)
    elif page == "Storage Stats":
        render_storage_stats(ch)


# --- Overview ---

def render_overview(ch):
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        total_flows = ch.execute("SELECT count() FROM dfi.flows")[0][0]
        st.metric("Total Flows", f"{total_flows:,}")

    with col2:
        flows_1h = ch.execute(
            "SELECT count() FROM dfi.flows WHERE first_ts >= now() - INTERVAL 1 HOUR"
        )[0][0]
        st.metric("Flows (1h)", f"{flows_1h:,}")

    with col3:
        unique_ips = ch.execute(
            "SELECT uniq(src_ip) FROM dfi.flows WHERE first_ts >= now() - INTERVAL 24 HOUR"
        )[0][0]
        st.metric("Unique Attackers (24h)", f"{unique_ips:,}")

    with col4:
        labels_count = ch.execute("SELECT count() FROM dfi.labels FINAL")[0][0]
        st.metric("Labeled Flows", f"{labels_count:,}")

    # Recent group assignments
    st.subheader("Recent Group Assignments")
    groups = ch.execute("""
        SELECT group_id, sub_group_id, count() as cnt
        FROM dfi.group_assignments
        WHERE assigned_at >= now() - INTERVAL 1 HOUR
        GROUP BY group_id, sub_group_id
        ORDER BY cnt DESC
        LIMIT 20
    """)
    if groups:
        st.dataframe(
            [{'Group': r[0], 'Subgroup': r[1], 'Count': r[2]} for r in groups],
            use_container_width=True
        )


# --- IP Lookup ---

def render_ip_lookup(ch):
    ip = st.text_input("Attacker IP Address", placeholder="e.g., 85.11.167.12")

    if not ip:
        st.info("Enter an IP address to look up its full profile.")
        return

    # Current classification
    st.subheader("Classification")
    group = ch.execute("""
        SELECT group_id, sub_group_id, confidence, priority, assigned_at
        FROM dfi.group_assignments
        WHERE attacker_ip = %(ip)s
        ORDER BY assigned_at DESC
        LIMIT 1
    """, {'ip': ip})

    if group:
        g = group[0]
        col1, col2, col3 = st.columns(3)
        col1.metric("Group", f"{g[0]} / {g[1]}")
        col2.metric("Confidence", f"{g[2]:.2f}")
        col3.metric("Priority", f"P{g[3]}")

    # Movement timeline
    st.subheader("Movement Timeline")
    hops = ch.execute("""
        SELECT first_ts, target_ip, dst_port, app_proto, vlan_id,
               pkts_fwd, pkts_rev, conn_state, duration_ms, session_gap_sec
        FROM dfi.fanout_hops
        WHERE attacker_ip = %(ip)s
          AND first_ts >= now() - INTERVAL 24 HOUR
        ORDER BY first_ts DESC
        LIMIT 100
    """, {'ip': ip})

    if hops:
        st.dataframe(
            [{'Time': r[0], 'Target': str(r[1]), 'Port': r[2], 'Proto': r[3],
              'VLAN': r[4], 'Pkts Fwd': r[5], 'Pkts Rev': r[6],
              'State': r[7], 'Duration': r[8], 'Gap(s)': r[9]}
             for r in hops],
            use_container_width=True
        )

    # Evidence events
    st.subheader("Evidence Events")
    evidence = ch.execute("""
        SELECT ts, event_type, event_detail, source_program, target_ip
        FROM dfi.evidence_events
        WHERE src_ip = %(ip)s
          AND ts >= now() - INTERVAL 24 HOUR
        ORDER BY ts DESC
        LIMIT 50
    """, {'ip': ip})

    if evidence:
        st.dataframe(
            [{'Time': r[0], 'Type': r[1], 'Detail': r[2][:100],
              'Source': r[3], 'Target': str(r[4])}
             for r in evidence],
            use_container_width=True
        )

    # Labels
    st.subheader("Flow Labels")
    labels = ch.execute("""
        SELECT l.label, l.label_confidence, l.evidence_mask, l.evidence_detail,
               f.dst_port, f.first_ts
        FROM dfi.labels l FINAL
        INNER JOIN dfi.flows f ON f.flow_id = l.flow_id
        WHERE l.src_ip = %(ip)s
          AND f.first_ts >= now() - INTERVAL 24 HOUR
        ORDER BY f.first_ts DESC
        LIMIT 50
    """, {'ip': ip})

    LABEL_NAMES = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTEFORCE', 3: 'EXPLOIT', 4: 'COMPROMISE'}
    if labels:
        st.dataframe(
            [{'Label': LABEL_NAMES.get(r[0], '?'), 'Confidence': f"{r[1]:.2f}",
              'Mask': r[2], 'Port': r[4], 'Time': r[5]}
             for r in labels],
            use_container_width=True
        )

    # Group trajectory
    st.subheader("Group Trajectory")
    trajectory = ch.execute("""
        SELECT assigned_at, group_id, sub_group_id, confidence
        FROM dfi.group_assignments
        WHERE attacker_ip = %(ip)s
        ORDER BY assigned_at DESC
        LIMIT 20
    """, {'ip': ip})

    if trajectory:
        st.dataframe(
            [{'Time': r[0], 'Group': r[1], 'Subgroup': r[2], 'Confidence': f"{r[3]:.2f}"}
             for r in trajectory],
            use_container_width=True
        )

    # --- Analyst Actions ---
    st.subheader("Actions")
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Promote to D3"):
            _analyst_action(ch, ip, 'promote', capture_depth=3)
            st.success(f"Promoted {ip} to D3")

    with col2:
        if st.button("Push to Block"):
            _analyst_action(ch, ip, 'block', capture_depth=0, priority=1)
            st.success(f"Pushed {ip} to block list")

    with col3:
        if st.button("Watch 72h"):
            _analyst_action(ch, ip, 'watch', capture_depth=2,
                           expires_hours=72)
            st.success(f"Watching {ip} for 72h at D2")


def _analyst_action(ch, ip, action_type, capture_depth=None, priority=None,
                    expires_hours=None):
    """Record analyst action in CH and update SQLite watchlist."""
    import sqlite3

    # Log to ClickHouse
    ch.execute("INSERT INTO dfi.analyst_actions VALUES", [{
        'attacker_ip': ip,
        'action_type': action_type,
        'capture_depth': capture_depth,
        'priority': priority,
        'reason': f'analyst_{action_type}',
        'analyst_id': 'dashboard',
        'expires_at': (time.time() + expires_hours * 3600) if expires_hours else None,
    }])

    # Log depth change if applicable
    if capture_depth is not None:
        ch.execute("INSERT INTO dfi.depth_changes VALUES", [{
            'attacker_ip': ip,
            'old_depth': 1,  # unknown, but logged
            'new_depth': capture_depth,
            'trigger_reason': f'analyst_{action_type}',
            'triggered_by': 'analyst',
        }])

    # Update local SQLite watchlist
    try:
        conn = sqlite3.connect(WATCHLIST_DB, timeout=10)
        conn.execute("""
            INSERT OR REPLACE INTO watchlist
            (src_ip, capture_depth, priority, reason, source, expires_at, updated_at)
            VALUES (?, ?, ?, ?, 'analyst', ?, ?)
        """, (
            ip, capture_depth or 2, priority or 2,
            f'analyst_{action_type}',
            (time.time() + expires_hours * 3600) if expires_hours else None,
            time.time(),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        st.error(f"Watchlist update failed: {e}")


# --- Top Attackers ---

def render_top_attackers(ch):
    st.subheader("Top Attackers (24h)")

    rows = ch.execute("""
        SELECT src_ip, count() as flows, uniq(dst_port) as ports,
               uniq(dst_ip) as targets,
               min(first_ts) as first_seen, max(first_ts) as last_seen
        FROM dfi.flows
        WHERE first_ts >= now() - INTERVAL 24 HOUR
        GROUP BY src_ip
        ORDER BY flows DESC
        LIMIT 100
    """)

    if rows:
        st.dataframe(
            [{'IP': str(r[0]), 'Flows': r[1], 'Ports': r[2], 'Targets': r[3],
              'First Seen': r[4], 'Last Seen': r[5]}
             for r in rows],
            use_container_width=True
        )


# --- Label Distribution ---

def render_label_distribution(ch):
    st.subheader("Label Distribution")
    LABEL_NAMES = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTEFORCE', 3: 'EXPLOIT', 4: 'COMPROMISE'}

    labels = ch.execute("""
        SELECT label, count() as cnt
        FROM dfi.labels FINAL
        GROUP BY label
        ORDER BY label
    """)

    if labels:
        st.dataframe(
            [{'Label': LABEL_NAMES.get(r[0], f'Unknown({r[0]})'), 'Count': r[1]}
             for r in labels],
            use_container_width=True
        )


# --- Ingest Monitor ---

def render_ingest_monitor(ch):
    st.subheader("Ingest Rate")

    rates = ch.execute("""
        SELECT toStartOfMinute(first_ts) AS minute,
               count() AS flows_per_min
        FROM dfi.flows
        WHERE first_ts >= now() - INTERVAL 1 HOUR
        GROUP BY minute
        ORDER BY minute
    """)

    if rates:
        import pandas as pd
        df = pd.DataFrame(rates, columns=['Minute', 'Flows/min'])
        st.line_chart(df.set_index('Minute'))


# --- Storage Stats ---

def render_storage_stats(ch):
    st.subheader("Storage Stats")

    tables = ch.execute("""
        SELECT table, formatReadableSize(sum(bytes_on_disk)) as size,
               sum(rows) as rows
        FROM system.parts
        WHERE database = 'dfi' AND active
        GROUP BY table
        ORDER BY sum(bytes_on_disk) DESC
    """)

    if tables:
        st.dataframe(
            [{'Table': r[0], 'Size': r[1], 'Rows': f"{r[2]:,}"}
             for r in tables],
            use_container_width=True
        )


if __name__ == '__main__':
    main()
```

---

## Step 4: Deploy Dashboard

```bash
# Install Streamlit on PV1
pip install streamlit clickhouse-driver pandas

# Create systemd unit
cat > /etc/systemd/system/dfi-dashboard.service <<'EOF'
[Unit]
Description=DFI2 Dashboard — Streamlit v2
After=network-online.target clickhouse-server.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -m streamlit run /opt/dfi2/dashboard/dashboard.py --server.port 8501 --server.headless true
Environment=CH_HOST=localhost
Environment=CH_PORT=9000
Environment=WATCHLIST_DB=/opt/dfi-hunter/watchlist.db
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now dfi-dashboard
```

---

## Verification

1. **Classifier running:**
   ```bash
   systemctl status dfi-classifier
   journalctl -u dfi-classifier -n 20
   ```

2. **Group assignments in CH:**
   ```bash
   clickhouse-client --query "
       SELECT group_id, sub_group_id, count() as cnt
       FROM dfi.group_assignments
       WHERE assigned_at >= now() - INTERVAL 1 HOUR
       GROUP BY group_id, sub_group_id
       ORDER BY cnt DESC
   "
   ```

3. **Depth changes logged:**
   ```bash
   clickhouse-client --query "
       SELECT attacker_ip, old_depth, new_depth, trigger_reason, triggered_by
       FROM dfi.depth_changes
       ORDER BY changed_at DESC
       LIMIT 10
   "
   ```

4. **Watchlist populated:**
   ```bash
   sqlite3 /opt/dfi-hunter/watchlist.db "SELECT count(*) FROM watchlist"
   sqlite3 /opt/dfi-hunter/watchlist.db "SELECT capture_depth, count(*) FROM watchlist GROUP BY capture_depth"
   ```

5. **AIO watchlist pushed:**
   ```bash
   # Run push manually
   python3 /opt/dfi2/sync/push_watchlist.py

   # Verify on AIO
   ssh -p 2222 colo8gent@172.16.3.113 "sqlite3 /opt/dfi-hunter/watchlist.db 'SELECT count(*) FROM watchlist'"
   ```

6. **Dashboard loads:**
   ```bash
   curl -s http://192.168.0.100:8501 | head -5
   # Should return Streamlit HTML
   ```

7. **Analyst action works:**
   - Open dashboard → IP Lookup → enter known attacker IP
   - Click "Watch 72h" → verify analyst_actions in CH and watchlist.db updated

---

## Acceptance Criteria

- [ ] Classifier daemon running, classifying attackers every 5 minutes
- [ ] All 20 subgroups from the hierarchy can be assigned
- [ ] Group assignments written to `dfi.group_assignments` table
- [ ] Depth promotions/demotions written to `dfi.depth_changes` table
- [ ] P1 groups auto-promote to D2+, PIVOT_CHAIN/RETURN_AND_DEEPEN to D3
- [ ] ONE_SHOT_NOISE demoted to D0
- [ ] Watchlist pushed to local SQLite after each classification pass
- [ ] Dashboard loads at http://192.168.0.100:8501
- [ ] IP Lookup shows: classification, movement timeline, evidence, labels, trajectory
- [ ] Analyst actions (Promote D3, Block, Watch 72h) write to CH + SQLite
- [ ] Top Attackers view shows correct data
- [ ] Ingest rate chart renders
- [ ] Storage stats show per-table disk usage

## Important Notes

- **Classifier queries hit CH for 6-hour rolling windows.** These queries scan significant data. They run every 5 minutes, which is fine for PV1's 472GB RAM. Do NOT run classifier on AIO.
- **Watchlist push is eventual consistency.** The classifier updates local SQLite immediately, but AIO gets the update via the cron-based `push_watchlist.py` (every 10 minutes). New attackers may spend up to 10 minutes at D1 on AIO before being promoted.
- **Dashboard is read-only except for analyst actions.** Analyst actions are the only writes from the dashboard. All other data comes from CH queries.
- **Group assignment is stateless per pass.** Each classification pass re-evaluates all active attackers from scratch. The trajectory is preserved in CH (append-only events), but the current classification can change every pass as behavior evolves.
