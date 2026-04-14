#!/usr/bin/env python3
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from clickhouse_driver import Client

try:
    from .watchlist_push import push_watchlist
except ImportError:
    from watchlist_push import push_watchlist


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('classifier')

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
CLASSIFY_INTERVAL = int(os.environ.get('CLASSIFY_INTERVAL', '300'))

P1, P2, P3 = 1, 2, 3

WINDOWS = [
    ('15m', '15 MINUTE'),
    ('1h', '1 HOUR'),
    ('6h', '6 HOUR'),
]

_AGG_SQL_TEMPLATE = """
SELECT
    src_ip AS attacker_ip,
    count() AS total_flows,
    uniq(dst_port) AS unique_ports,
    uniq(dst_ip) AS unique_targets,
    uniq(app_proto) AS unique_protos,
    topK(1)(dst_port)[1] AS top_port,
    avg(pkts_fwd) AS avg_pkts_fwd,
    countIf(dst_port = 22) AS ssh_flows,
    countIf(dst_port = 3306) AS mysql_flows,
    countIf(dst_port = 3389) AS rdp_flows,
    countIf(dst_port IN (80, 443, 8080)) AS http_flows,
    countIf(dst_port = 5060) AS sip_flows,
    countIf(dst_port = 53) AS dns_flows,
    countIf(ip_proto = 6) AS tcp_flows,
    countIf(ip_proto = 17) AS udp_flows,
    avgIf(entropy_first, entropy_first IS NOT NULL) AS avg_entropy,
    dateDiff('minute', min(first_ts), max(first_ts)) AS span_minutes
FROM dfi.flows
WHERE first_ts >= now() - INTERVAL {window}
GROUP BY src_ip
HAVING total_flows >= 2
LIMIT 50000
"""

_FANOUT_SQL_TEMPLATE = """
SELECT attacker_ip, uniq(target_ip), uniq(dst_port), uniq(vlan_id), max(session_gap_sec)
FROM dfi.fanout_hops
WHERE first_ts >= now() - INTERVAL {window}
GROUP BY attacker_ip
"""

_EVIDENCE_SQL_TEMPLATE = """
SELECT src_ip, countIf(event_type='auth_failure'), countIf(event_type='auth_success'), countIf(event_type='suspicious_command')
FROM dfi.evidence_events
WHERE ts >= now() - INTERVAL {window}
  AND src_ip != '0.0.0.0'
GROUP BY src_ip
"""

A_COLS = [
    'attacker_ip', 'total_flows', 'unique_ports', 'unique_targets', 'unique_protos',
    'top_port', 'avg_pkts_fwd', 'ssh_flows', 'mysql_flows', 'rdp_flows',
    'http_flows', 'sip_flows', 'dns_flows', 'tcp_flows', 'udp_flows',
    'avg_entropy', 'span_minutes',
]


def classify(agg: dict, fan: dict, ev: dict):
    flows = agg['total_flows']
    ports = agg['unique_ports']
    targets = agg['unique_targets']
    ssh = agg['ssh_flows']
    mysql = agg['mysql_flows']
    rdp = agg['rdp_flows']
    http = agg['http_flows']
    sip = agg['sip_flows']
    dns = agg['dns_flows']
    tcp = agg['tcp_flows']
    udp = agg['udp_flows']
    avg_pkts = agg['avg_pkts_fwd'] or 0
    entropy = agg.get('avg_entropy') or 0
    span_min = agg.get('span_minutes') or 0

    f_targets = fan.get('unique_targets', targets)
    f_ports = fan.get('unique_ports', ports)
    f_vlans = fan.get('unique_vlans', 1)
    max_gap = fan.get('max_gap_sec') or 0

    auth_fail = ev.get('auth_failures', 0)
    auth_success = ev.get('auth_successes', 0)
    susp = ev.get('suspicious_cmds', 0)

    # CAMPAIGN_PROGRESSION
    if f_targets >= 3 and f_ports >= 3 and f_vlans >= 2:
        return 'CAMPAIGN_PROGRESSION', 'PIVOT_CHAIN', 1.0, P1   # was 0.85: multi-VLAN lateral = definitive
    if f_targets >= 2 and max_gap > 1800 and auth_fail > 0:
        return 'CAMPAIGN_PROGRESSION', 'RETURN_AND_DEEPEN', 0.75, P1
    if targets <= 2 and ports >= 4 and flows >= 5:
        return 'CAMPAIGN_PROGRESSION', 'VERTICAL_ESCALATION', 0.7, P2
    if ports <= 3 and targets >= 10 and flows >= 20:
        return 'CAMPAIGN_PROGRESSION', 'HORIZONTAL_SWEEP', 0.8, P2

    # EXPLOIT_DELIVERY
    if susp > 0:
        conf = 1.0 if targets >= 2 else 0.9                     # was flat 0.8; exploit ≥2 peers = certain
        return 'EXPLOIT_DELIVERY', 'SERVICE_EXPLOIT', conf, P1
    if http > 0 and entropy > 6.0:
        conf = 1.0 if targets >= 2 else 0.7                     # was flat 0.7; exploit ≥2 peers = certain
        return 'EXPLOIT_DELIVERY', 'WEB_EXPLOIT', conf, P1
    if auth_success > 0 and susp == 0 and flows >= 3:
        return 'EXPLOIT_DELIVERY', 'PHASED_ATTACK', 0.65, P1

    # CREDENTIAL_ATTACK
    # ≥5 auth failures → 1.0 (honeypot certainty threshold)
    if auth_fail >= 5:
        if ssh >= mysql and ssh >= rdp and ssh >= http:
            return 'CREDENTIAL_ATTACK', 'SSH_BRUTE', 1.0, P1
        if mysql >= ssh and mysql >= rdp:
            return 'CREDENTIAL_ATTACK', 'MYSQL_BRUTE', 1.0, P1
        if rdp >= ssh and rdp >= mysql:
            return 'CREDENTIAL_ATTACK', 'RDP_BRUTE', 1.0, P1
        if http >= ssh and http >= mysql and http >= rdp:
            return 'CREDENTIAL_ATTACK', 'HTTP_AUTH_SPRAY', 1.0, P1
        svc_count = sum(1 for s in (ssh, mysql, rdp, http) if s > 0)
        if svc_count >= 2:
            return 'CREDENTIAL_ATTACK', 'CROSS_SERVICE_ROT', 1.0, P1
        return 'CREDENTIAL_ATTACK', 'SSH_BRUTE', 1.0, P1

    # 3–4 failures → existing confidence values
    if auth_fail >= 3:
        if ssh >= mysql and ssh >= rdp and ssh >= http:
            return 'CREDENTIAL_ATTACK', 'SSH_BRUTE', 0.9, P1
        if mysql >= ssh and mysql >= rdp:
            conf = 1.0 if targets >= 2 else 0.9   # SQL 2-peer rule
            return 'CREDENTIAL_ATTACK', 'MYSQL_BRUTE', conf, P1
        if rdp >= ssh and rdp >= mysql:
            return 'CREDENTIAL_ATTACK', 'RDP_BRUTE', 0.9, P1
        if http >= ssh and http >= mysql and http >= rdp:
            return 'CREDENTIAL_ATTACK', 'HTTP_AUTH_SPRAY', 0.85, P1
        # Multi-service rotation
        svc_count = sum(1 for s in (ssh, mysql, rdp, http) if s > 0)
        if svc_count >= 2:
            return 'CREDENTIAL_ATTACK', 'CROSS_SERVICE_ROT', 0.8, P1
        return 'CREDENTIAL_ATTACK', 'SSH_BRUTE', 0.9, P1

    # INFRASTRUCTURE_ABUSE
    if sip > 10 and udp > tcp:
        return 'INFRASTRUCTURE_ABUSE', 'SIP_FRAUD', 0.8, P2
    if dns > 20 and avg_pkts < 5:
        return 'INFRASTRUCTURE_ABUSE', 'DNS_TUNNEL', 0.6, P2
    if udp > tcp and flows > 50 and targets >= 5 and avg_pkts <= 2:
        return 'INFRASTRUCTURE_ABUSE', 'AMPLIFICATION', 0.7, P2

    # RECON
    if ports > 20 and avg_pkts < 8 and tcp > udp:
        conf = 1.0 if f_targets > 10 else 0.85   # fanout > 10 peers = certain
        return 'RECON', 'PORT_SCAN', conf, P3
    if targets > 10 and ports <= 3:               # sweep: >10 targets = certain
        return 'RECON', 'SERVICE_SWEEP', 1.0, P3  # covers both >100 (was 0.8) and >10 (new)
    if flows <= 5 and avg_pkts <= 3 and ports <= 3:
        return 'RECON', 'BANNER_GRAB', 0.6, P3

    # UNCLASSIFIED
    if flows <= 2 and avg_pkts < 5:
        return 'UNCLASSIFIED', 'ONE_SHOT_NOISE', 0.5, P3
    if span_min > 120 and flows < 10 and avg_pkts < 5:
        return 'UNCLASSIFIED', 'LOW_AND_SLOW', 0.45, P3
    return 'UNCLASSIFIED', 'EMERGING', 0.4, P3


def compute_depth(current, group_id, sub_group_id, priority, confidence):
    if priority == P1:
        if sub_group_id in ('PIVOT_CHAIN', 'RETURN_AND_DEEPEN'):
            return 3
        return max(current, 2)
    if priority == P2:
        return max(current, 2)
    if priority == P3 and confidence >= 0.7:
        if group_id == 'UNCLASSIFIED' and sub_group_id == 'ONE_SHOT_NOISE':
            return 0
        return max(current, 1)
    return max(current, 1)


def _query_window(ch: Client, window_sql: str):
    rows = ch.execute(_AGG_SQL_TEMPLATE.format(window=window_sql))
    aggs = {str(r[0]): dict(zip(A_COLS, r)) for r in rows}

    fan_rows = ch.execute(_FANOUT_SQL_TEMPLATE.format(window=window_sql))
    fans = {str(r[0]): {'unique_targets': r[1], 'unique_ports': r[2], 'unique_vlans': r[3], 'max_gap_sec': r[4]} for r in fan_rows}

    ev_rows = ch.execute(_EVIDENCE_SQL_TEMPLATE.format(window=window_sql))
    evs = {str(r[0]): {'auth_failures': r[1], 'auth_successes': r[2], 'suspicious_cmds': r[3]} for r in ev_rows}

    return aggs, fans, evs


def run_classification(ch: Client):
    # Multi-window: query 15m, 1h, 6h and merge (highest-priority classification wins)
    best = {}  # ip -> (gid, sgid, conf, pri, agg)
    for wname, wsql in WINDOWS:
        aggs, fans, evs = _query_window(ch, wsql)
        for ip, agg in aggs.items():
            fan = fans.get(ip, {})
            ev = evs.get(ip, {})
            gid, sgid, conf, pri = classify(agg, fan, ev)

            prev = best.get(ip)
            if prev is None or pri < prev[3] or (pri == prev[3] and conf > prev[2]):
                best[ip] = (gid, sgid, conf, pri, agg)

    current_depths = {}
    try:
        rows = ch.execute("SELECT attacker_ip, argMax(new_depth, changed_at) FROM dfi.depth_changes WHERE changed_at >= now() - INTERVAL 7 DAY GROUP BY attacker_ip")
        current_depths = {str(r[0]): int(r[1]) for r in rows}
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    ga_rows, dc_rows, wl_rows = [], [], []
    for ip, (gid, sgid, conf, pri, agg) in best.items():
        ga_rows.append(
            {
                'attacker_ip': ip,
                'group_id': gid,
                'sub_group_id': sgid,
                'confidence': conf,
                'priority': pri,
                'window_start': now - timedelta(hours=6),
                'window_end': now,
                'feature_summary': json.dumps({'flows': agg['total_flows'], 'ports': agg['unique_ports'], 'targets': agg['unique_targets'], 'top_port': agg['top_port']}),
                'assigned_at': now,
            }
        )

        old_d = int(current_depths.get(ip, 1))
        new_d = int(compute_depth(old_d, gid, sgid, pri, conf))
        if new_d != old_d:
            dc_rows.append(
                {
                    'attacker_ip': ip,
                    'old_depth': old_d,
                    'new_depth': new_d,
                    'trigger_reason': f'{gid}/{sgid} conf={conf:.2f}',
                    'triggered_by': 'classifier',
                    'changed_at': now,
                    'request_id': '',
                }
            )

        exp_h = 72 if pri == P1 else (48 if pri == P2 else 24)
        wl_rows.append(
            {
                'src_ip': ip,
                'capture_depth': new_d,
                'priority': pri,
                'group_id': gid,
                'sub_group_id': sgid,
                'top_port': agg['top_port'],
                'reason': f'{gid}/{sgid}',
                'source': 'classifier',
                'expires_at': time.time() + exp_h * 3600,
            }
        )

    if ga_rows:
        ch.execute('INSERT INTO dfi.group_assignments VALUES', ga_rows)
    if dc_rows:
        ch.execute('INSERT INTO dfi.depth_changes VALUES', dc_rows)
    if wl_rows:
        push_watchlist(wl_rows, push_remote=True)
    return len(ga_rows)


def main():
    ch = Client(CH_HOST, port=CH_PORT)
    while True:
        try:
            n = run_classification(ch)
            log.info('classified attackers=%d', n)
        except Exception as exc:
            log.error('classification_error err=%s', exc, exc_info=True)
        time.sleep(CLASSIFY_INTERVAL)


if __name__ == '__main__':
    main()
