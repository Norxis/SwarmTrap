#!/usr/bin/env python3
"""
ip_reputation_builder.py — Builds the IP reputation table from multiple sources.

Reads:
  - dfi.evidence_events (host-side observations)
  - dfi.session_predictions (session-level classifications)
  - dfi.conversation_labels (conversation archetypes)
  - dfi.source_stats (per-IP flow aggregates)

Writes:
  - dfi.ip_reputation (ReplacingMergeTree, keyed by src_ip)

Runs as PV1 cron every 5 minutes.

Usage:
    python3 ip_reputation_builder.py [--window-hours 1] [--dry-run]
"""

import sys
import time
import argparse
import logging
from datetime import datetime, timedelta
from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('ip_reputation')

# IP reputation states
STATE_UNKNOWN = 0
STATE_DIRTY = 1
STATE_EVIDENCE = 2
STATE_RESEARCH_BENIGN = 3
STATE_CLEAN = 4

# Label sources
LABEL_EVIDENCE = 1
LABEL_PROPAGATED = 2
LABEL_MODEL = 3
LABEL_HEURISTIC = 4

# Evidence event types that confirm attacker interaction
ATTACK_EVIDENCE = {
    'auth_failure', 'auth_success', 'credential_capture',
    'suspicious_command', 'privilege_escalation', 'lateral_movement',
    'bind_attempt', 'search_request', 'prelogin_info',
}

# Benign/noise events (not counted as attack evidence)
BENIGN_EVENTS = {
    'name_query', 'banner_exchange', 'negotiation', 'http_request',
}

# Service mapping from evidence target ports
PORT_TO_SERVICE_BIT = {
    22: 0, 2222: 0,          # SSH → bit 0
    80: 1, 443: 1, 8080: 1,  # HTTP → bit 1
    3389: 2,                   # RDP → bit 2
    3306: 3, 1433: 3,         # MySQL/MSSQL → bit 3
    445: 4, 139: 4,           # SMB → bit 4
    6379: 5,                   # Redis → bit 5
    21: 6,                     # FTP → bit 6
    23: 7,                     # Telnet → bit 7
}

# Known research scanner rDNS domains
RESEARCH_DOMAINS = {
    'shodan.io', 'censys.io', 'binaryedge.io', 'shadowserver.org',
    'internet-census.org', 'stretchoid.com', 'internet-measurement.com',
    'recyber.net', 'alphastrike.io', 'onyphe.io', 'criminalip.io',
    'natlas.io', 'leakix.net', 'rapid7.com',
}


def compute_capture_score(state, has_evidence, evidence_mask, total_flows,
                           unique_ports, unique_dsts, pkts_rev_ratio=0):
    """Compute 4-factor capture value score (0-100)."""

    # Factor 1: Source Reputation (0-40)
    f1 = 0
    if state == STATE_EVIDENCE:
        popcount = bin(evidence_mask).count('1')
        f1 = 40 if popcount > 2 else 35
    elif state == STATE_DIRTY:
        f1 = 15  # model-classified dirty (conservative)
    elif state == STATE_RESEARCH_BENIGN:
        f1 = -15
    elif state == STATE_CLEAN:
        f1 = -40
    elif state == STATE_UNKNOWN:
        f1 = 5  # first-seen unknown

    # Campaign behavior bonus
    if unique_ports > 3 and total_flows > 5:
        f1 = min(40, f1 + 20)

    f1 = max(-40, min(40, f1))

    # Factor 2: Service Relevance (0-25) — simplified
    f2 = 10 if unique_ports > 0 else 3

    # Factor 3: Direction & Behavior (0-20)
    f3 = 10 if pkts_rev_ratio > 0 else 2

    # Factor 4: Novelty (0-15) — simplified for now
    f4 = 5 if total_flows < 100 else 2

    return max(0, min(100, f1 + f2 + f3 + f4))


def build_reputation(ch: Client, window_hours: int = 1, dry_run: bool = False):
    """Main builder: query sources, compute reputation, write to ip_reputation."""

    now = datetime.utcnow()
    window_start = now - timedelta(hours=window_hours)

    log.info("Building IP reputation (window: %s → %s)", window_start, now)

    # 1. Get evidence-confirmed IPs (attack evidence only)
    evidence_query = """
    SELECT
        src_ip,
        count() AS evidence_count,
        countIf(event_type IN ('auth_failure')) AS auth_failures,
        countIf(event_type IN ('auth_success', 'credential_capture')) AS auth_successes,
        countIf(event_type IN ('suspicious_command', 'privilege_escalation',
                                'lateral_movement')) AS post_exploit,
        groupBitOr(evidence_mask_bit) AS evidence_mask,
        min(ts) AS first_seen,
        max(ts) AS last_seen
    FROM dfi.evidence_events
    WHERE ts >= %(start)s
      AND event_type IN ('auth_failure', 'auth_success', 'credential_capture',
                         'suspicious_command', 'privilege_escalation',
                         'lateral_movement', 'bind_attempt',
                         'search_request', 'prelogin_info')
      AND src_ip != toIPv4('127.0.0.1')
      AND src_ip != toIPv4('0.0.0.0')
    GROUP BY src_ip
    HAVING evidence_count >= 1
    """

    evidence_ips = ch.execute(evidence_query, {'start': window_start})
    log.info("Evidence IPs: %d", len(evidence_ips))

    # 2. Get source stats for flow context
    stats_query = """
    SELECT
        src_ip,
        countMerge(flow_count) AS total_flows,
        uniqMerge(unique_ports) AS unique_ports,
        uniqMerge(unique_dsts) AS unique_dsts
    FROM dfi.source_stats
    GROUP BY src_ip
    HAVING total_flows > 0
    """
    stats_rows = ch.execute(stats_query)
    stats_map = {str(r[0]): {'flows': r[1], 'ports': r[2], 'dsts': r[3]}
                 for r in stats_rows}
    log.info("Source stats IPs: %d", len(stats_map))

    # 3. Get session predictions (recent)
    session_query = """
    SELECT
        src_ip,
        argMax(label, scored_at) AS latest_label,
        argMax(confidence, scored_at) AS latest_confidence,
        argMax(kill_chain_stage, scored_at) AS latest_stage
    FROM dfi.session_predictions
    WHERE scored_at >= %(start)s
    GROUP BY src_ip
    """
    session_rows = ch.execute(session_query, {'start': window_start})
    session_map = {str(r[0]): {'label': r[1], 'conf': r[2], 'stage': r[3]}
                   for r in session_rows}
    log.info("Session prediction IPs: %d", len(session_map))

    # 4. Build reputation rows
    rows = []
    seen_ips = set()

    for r in evidence_ips:
        ip = str(r[0])
        seen_ips.add(ip)
        evidence_count = r[1]
        auth_failures = r[2]
        auth_successes = r[3]
        post_exploit = r[4]
        evidence_mask = r[5]
        first_seen = r[6]
        last_seen = r[7]

        # Determine state
        state = STATE_EVIDENCE

        # Label confidence from evidence quality
        if post_exploit > 0:
            label_conf = 0.98
        elif auth_successes > 0:
            label_conf = 0.95
        elif auth_failures >= 5:
            label_conf = 0.95
        elif auth_failures >= 3:
            label_conf = 0.85
        else:
            label_conf = 0.70

        stats = stats_map.get(ip, {'flows': 0, 'ports': 0, 'dsts': 0})

        score = compute_capture_score(
            state, True, evidence_mask,
            stats['flows'], stats['ports'], stats['dsts']
        )

        # Capture depth from score
        if score >= 51:
            depth = 3  # D3
        elif score >= 21:
            depth = 2  # D2
        elif score >= 1:
            depth = 1  # D1
        else:
            depth = 0  # D0

        rows.append({
            'src_ip': ip,
            'state': state,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'updated_at': now,
            'has_any_evidence': 1,
            'evidence_mask_union': evidence_mask,
            'capture_score': score,
            'score_reputation': min(40, 35 + (5 if bin(evidence_mask).count('1') > 2 else 0)),
            'label_source': LABEL_EVIDENCE,
            'label_confidence': label_conf,
            'total_flows': stats['flows'],
            'unique_ports': stats['ports'],
            'unique_dsts': stats['dsts'],
            'capture_depth': min(2, depth),  # evidence = max D2 (D3 manual only)
            'priority': 1,
            'watchlist_source': 'evidence_ingest',
            'expires_at': now + timedelta(days=30),
        })

    # 5. Add session-predicted IPs not already in evidence
    for ip, s in session_map.items():
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        stats = stats_map.get(ip, {'flows': 0, 'ports': 0, 'dsts': 0})

        state = STATE_DIRTY if s['conf'] >= 0.7 else STATE_UNKNOWN
        score = compute_capture_score(
            state, False, 0,
            stats['flows'], stats['ports'], stats['dsts']
        )

        rows.append({
            'src_ip': ip,
            'state': state,
            'first_seen': now,
            'last_seen': now,
            'updated_at': now,
            'has_any_evidence': 0,
            'capture_score': score,
            'label_source': LABEL_MODEL,
            'label_confidence': s['conf'],
            'total_flows': stats['flows'],
            'unique_ports': stats['ports'],
            'unique_dsts': stats['dsts'],
            'capture_depth': 2 if s['conf'] >= 0.7 else 1,
            'priority': 2,
            'watchlist_source': 'session_rules',
            'expires_at': now + timedelta(days=30),
        })

    log.info("Total reputation rows to write: %d (%d evidence, %d model)",
             len(rows), len(evidence_ips), len(rows) - len(evidence_ips))

    if dry_run:
        log.info("DRY RUN — not writing to ClickHouse")
        for r in rows[:5]:
            log.info("  %s: state=%d score=%d depth=%d conf=%.2f",
                     r['src_ip'], r['state'], r['capture_score'],
                     r['capture_depth'], r['label_confidence'])
        return len(rows)

    # 6. Write to ip_reputation
    if rows:
        columns = list(rows[0].keys())
        values = [[r[c] for c in columns] for r in rows]
        ch.execute(
            f"INSERT INTO dfi.ip_reputation ({','.join(columns)}) VALUES",
            values
        )
        log.info("Wrote %d rows to dfi.ip_reputation", len(rows))

    # 7. Publish updates to NATS for ARM control plane
    try:
        import asyncio
        import nats as nats_mod

        async def _publish_updates():
            nc = await nats_mod.connect("nats://localhost:4222")
            import json as _json
            for r in rows:
                msg = _json.dumps({
                    'src_ip': r['src_ip'],
                    'state': r['state'],
                    'capture_score': r['capture_score'],
                    'capture_depth': r['capture_depth'],
                    'has_any_evidence': r.get('has_any_evidence', 0),
                    'label_confidence': r['label_confidence'],
                }).encode()
                await nc.publish("dfi.reputation.update", msg)
            await nc.flush()
            await nc.close()
            log.info("Published %d reputation updates to NATS", len(rows))

        asyncio.run(_publish_updates())
    except Exception as e:
        log.warning("NATS publish failed (non-fatal): %s", e)

    return len(rows)


def main():
    parser = argparse.ArgumentParser(description='IP Reputation Builder')
    parser.add_argument('--window-hours', type=int, default=1,
                        help='Lookback window in hours (default: 1)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print what would be written without writing')
    parser.add_argument('--ch-host', default='localhost',
                        help='ClickHouse host')
    parser.add_argument('--ch-port', type=int, default=9000,
                        help='ClickHouse port')
    args = parser.parse_args()

    ch = Client(host=args.ch_host, port=args.ch_port)

    start = time.time()
    count = build_reputation(ch, args.window_hours, args.dry_run)
    elapsed = time.time() - start

    log.info("Done in %.1fs. %d IPs processed.", elapsed, count)


if __name__ == '__main__':
    main()
