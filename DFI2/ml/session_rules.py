#!/usr/bin/env python3
"""Session-level threshold rules — detects RECON/BRUTE/EXPLOIT/C2 from session_stats.

Runs on PV1 as cron (2-57/5 * * * *). Queries v_session_features for recent
sessions, applies threshold rules, writes to session_predictions, pushes
high-confidence hits to AIO watchlist.

No ML model needed — pure threshold logic based on industry standards:
  - Elastic: ≥25 unique ports = port scan
  - Snort/Suricata: 5+ SYN in 120s = scan, 200 SSH attempts/min = brute
  - SSH flow research: PPF 11-51 for brute phase, >5 same-PPF flows = brute
  - C2 beacon: low IAT variance, session duration >300s, periodic reconnect

Thresholds are conservative (high-confidence only) for watchlist promotion.

Usage:
    python3 session_rules.py                    # score last 10 min (PV1)
    python3 session_rules.py --minutes 60       # score last hour
    python3 session_rules.py --hours 24         # score last 24h
    python3 session_rules.py --backfill         # score ALL sessions
    python3 session_rules.py --dirty-clean       # also score local dfi_dirty + dfi_clean
"""
import argparse
import json
import logging
import os
import tempfile
import time
from ipaddress import IPv4Address, IPv4Network

from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
WATCHLIST_DB = os.environ.get('WATCHLIST_DB_PATH', '/opt/dfi-hunter/watchlist.db')

# ---------------------------------------------------------------------------
# THRESHOLD RULES — tuned for honeypot environment (high recall, moderate FP)
# ---------------------------------------------------------------------------

# RECON (Stage 1): Port/host scanning
# Sources: Elastic ≥25 unique ports, Snort 5+ SYN in 120s
RECON_RULES = {
    # Horizontal scan: thin SYN-only sessions, no reply
    'horiz_scan': {
        'min_flow_count': 3,        # at least 3 flows in session
        'min_syn_only_ratio': 0.8,  # 80%+ are SYN-only (no handshake)
        'max_reply_ratio': 0.1,     # almost no responses
        'max_bidir_ratio': 0.05,    # essentially unidirectional
    },
    # Source-wide: IP hitting many ports or many destinations
    'wide_scan': {
        'min_src_total_sessions': 20,   # ≥20 different (dst_ip, dst_port) pairs
        'min_src_total_ports': 10,      # ≥10 unique ports across all sessions
        'min_src_single_flow_pct': 0.7, # 70%+ sessions are single-flow (probes)
    },
}

# BRUTE FORCE (Stage 2): Repeated auth attempts on single service
# Sources: SSH research PPF 11-51, Snort 200/10s, FortiGuard 5+ in 120s
BRUTE_RULES = {
    'auth_brute': {
        'min_flow_count': 10,       # ≥10 flows to same (dst_ip, dst_port)
        'min_reply_ratio': 0.3,     # server is responding (auth failures)
        'max_reply_ratio': 0.7,     # but not fully interactive
        'max_bidir_ratio': 0.4,     # limited data exchange
        'min_completed_ratio': 0.1, # some TCP handshakes complete
    },
    # Heavy brute: very high flow count
    'heavy_brute': {
        'min_flow_count': 50,       # ≥50 flows = definite brute
        'min_reply_ratio': 0.1,     # at least some replies
        'max_bidir_ratio': 0.5,     # not interactive
    },
}

# EXPLOIT (Stage 3): Interactive session with significant data transfer
# Sources: MITRE T1059 (Command and Scripting), bidirectional deep sessions
EXPLOIT_RULES = {
    'interactive': {
        'min_bidir_ratio': 0.5,     # 50%+ flows are bidirectional
        'min_max_flow_dur': 30000,  # at least one flow > 30 seconds
        'min_max_bytes_rev': 1024,  # at least 1KB reverse data
        'min_flow_count': 2,        # not a single scan probe
    },
    # Deep session: large data transfer
    'data_exfil': {
        'min_bidir_ratio': 0.3,
        'min_avg_bytes_per_flow': 5000,  # >5KB avg per flow
        'min_max_bytes_rev': 10240,      # >10KB reverse payload
        'min_duration': 60,              # >60 seconds
    },
}

# C2 BEACON (Stage 4): Persistent, periodic reconnection
# Sources: Active Countermeasures beacon detection, Elastic beaconing
C2_RULES = {
    'persistent': {
        'min_duration': 300,        # session spans ≥5 minutes
        'min_flow_count': 5,        # multiple reconnections
        'min_bidir_ratio': 0.3,     # some bidirectional
        'min_completed_ratio': 0.3, # TCP connections complete
    },
    'long_lived': {
        'min_duration': 3600,       # session spans ≥1 hour
        'min_flow_count': 3,        # periodic
        'min_bidir_ratio': 0.2,
    },
}

# Watchlist promotion: source-level thresholds (aggregate across all sessions)
WATCHLIST_RULES = {
    'scanner': {
        'min_sessions': 50,            # ≥50 unique sessions from this IP
        'min_ports': 10,               # ≥10 unique ports
        'min_single_flow_pct': 0.5,    # 50%+ are single-flow probes
        'max_avg_reply': 0.3,          # real scanners get few replies; services reply to everything
        'reason': 'session_scanner',
        'priority': 2,
        'capture_depth': 2,
    },
    'brute_forcer': {
        'min_sessions': 5,
        'min_total_flows': 100,        # ≥100 total flows
        'max_reply_rate': 0.5,         # low overall reply rate
        'reason': 'session_brute',
        'priority': 2,
        'capture_depth': 2,
    },
    'heavy_hitter': {
        'min_sessions': 100,           # ≥100 sessions = significant activity
        'min_total_flows': 500,
        'max_avg_reply': 0.5,          # exclude responsive services (DNS/CDN/NTP)
        'reason': 'session_heavy_hitter',
        'priority': 3,
        'capture_depth': 1,
    },
}


# ---------------------------------------------------------------------------
# HONEYPOT IP DATABASE — loaded from config file
# ---------------------------------------------------------------------------
# Only IPs in this DB are honeypots. Everything else is a potential attacker.
# Config: /opt/dfi2/honeypot_ips.conf (one IP or CIDR per line, # comments)
HONEYPOT_CONF = os.environ.get('HONEYPOT_CONF', '/opt/dfi2/honeypot_ips.conf')

# Infrastructure IPs that should never be classified as attackers
INFRA_IPS = frozenset({
    '1.1.1.1', '1.0.0.1',                      # Cloudflare DNS
    '8.8.8.8', '8.8.4.4',                      # Google DNS
    '208.67.222.222', '208.67.220.220',         # OpenDNS
    '9.9.9.9', '149.112.112.112',              # Quad9
    '76.76.2.0', '76.76.10.0',                 # Control D
})

# Watchlist rule for compromised honeypots attacking external targets
COMPROMISED_HONEYPOT_RULE = {
    'min_sessions': 1,          # any outbound attack = alert
    'reason': 'compromised_honeypot',
    'priority': 1,              # highest priority
    'capture_depth': 3,         # full capture
}


def _load_honeypot_db(path):
    """Load honeypot IPs and networks from config file.

    Returns (ip_set, network_list). File format: one IP or CIDR per line,
    # comments, blank lines ignored.
    """
    ips = set()
    nets = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split('#')[0].strip()
                if not line:
                    continue
                if '/' in line:
                    nets.append(IPv4Network(line, strict=False))
                else:
                    ips.add(line)
    except FileNotFoundError:
        log.warning('Honeypot config not found: %s — no honeypot filtering', path)
    except Exception as exc:
        log.error('Failed to load honeypot config %s: %s', path, exc)
    log.info('Loaded honeypot DB: %d IPs, %d networks from %s', len(ips), len(nets), path)
    return frozenset(ips), nets


# Load once at import time
HONEYPOT_IPS, HONEYPOT_NETWORKS = _load_honeypot_db(HONEYPOT_CONF)


def _is_noise_ip(ip_str):
    """Filter multicast, broadcast, link-local, infrastructure DNS."""
    if ip_str is None:
        return True
    s = str(ip_str)
    if (s.startswith('224.') or s.startswith('239.') or s.startswith('255.')
            or s.startswith('0.') or s.startswith('169.254.')):
        return True
    if s in INFRA_IPS:
        return True
    return False


def _is_honeypot_ip(ip_str):
    """Check if IP is in the honeypot DB (loaded from config file)."""
    if ip_str is None:
        return False
    s = str(ip_str)
    if s in HONEYPOT_IPS:
        return True
    if HONEYPOT_NETWORKS:
        try:
            addr = IPv4Address(s)
            for net in HONEYPOT_NETWORKS:
                if addr in net:
                    return True
        except ValueError:
            pass
    return False


def _is_reflection(s):
    """Detect DNS reflection/amplification and other one-directional noise.

    Purely one-directional sessions (zero fwd OR zero rev) are either:
    - Reflected responses (DNS/NTP/memcached amplification): fwd=0, rev>0
    - Spoofed outbound probes captured on SPAN: rev=0, fwd>0
    Neither represents genuine interactive attack behavior.
    Skip classification to avoid C2/EXPLOIT false positives and watchlist pollution.
    """
    fwd_bytes = s.get('sess_bytes_fwd', 0) or 0
    rev_bytes = s.get('sess_bytes_rev', 0) or 0
    fwd_pkts = s.get('sess_pkts_fwd', 0) or 0
    rev_pkts = s.get('sess_pkts_rev', 0) or 0

    # Purely inbound: reflected responses (DNS amplification, etc.)
    if fwd_bytes == 0 and fwd_pkts == 0 and rev_pkts > 0:
        return True
    # Purely outbound: spoofed queries or unanswered probes
    if rev_bytes == 0 and rev_pkts == 0 and fwd_pkts > 0:
        return True
    return False



def classify_session(s, max_stage=4):
    """Apply threshold rules to classify a session. Returns (stage, rule_name, confidence).

    max_stage: highest stage to evaluate (2=RECON+BRUTE only, 4=all).
    """
    # Skip multicast/broadcast/infra noise
    if _is_noise_ip(s.get('src_ip')) or _is_noise_ip(s.get('dst_ip')):
        return 0, 'noise_filtered', 0.0

    # Skip DNS reflection / amplification (one-directional sessions)
    if _is_reflection(s):
        return 0, 'reflection_filtered', 0.0

    # Honeypot src_ip handling (VLAN 101 egress capture)
    src_hp = _is_honeypot_ip(s.get('src_ip'))
    dst_hp = _is_honeypot_ip(s.get('dst_ip'))
    if src_hp and dst_hp:
        # Honeypot → honeypot: VLAN 101 reply traffic, ignore
        return 0, 'honeypot_internal', 0.0
    # Honeypot → external: run normal rules. Replies classify as benign.
    # Only flag as compromised if pkt patterns match attack (RECON/BRUTE/EXPLOIT/C2).

    fc = s.get('sess_flow_count', 0) or 0
    syn_r = s.get('sess_syn_only_ratio', 0) or 0
    reply_r = s.get('sess_reply_ratio', 0) or 0
    bidir_r = s.get('sess_bidirectional_ratio', 0) or 0
    comp_r = s.get('sess_completed_ratio', 0) or 0
    dur = s.get('sess_duration', 0) or 0
    max_fd = s.get('sess_max_flow_dur', 0) or 0
    max_br = s.get('sess_max_bytes_rev', 0) or 0
    avg_bpf = s.get('sess_avg_bytes_per_flow', 0) or 0

    # C2 first (highest stage, most specific)
    if max_stage >= 4:
        r = C2_RULES['persistent']
        if (dur >= r['min_duration'] and fc >= r['min_flow_count']
                and bidir_r >= r['min_bidir_ratio'] and comp_r >= r['min_completed_ratio']):
            return 4, 'c2_persistent', 0.85

        r = C2_RULES['long_lived']
        if dur >= r['min_duration'] and fc >= r['min_flow_count'] and bidir_r >= r['min_bidir_ratio']:
            return 4, 'c2_long_lived', 0.75

    # EXPLOIT
    if max_stage >= 3:
        r = EXPLOIT_RULES['data_exfil']
        if (bidir_r >= r['min_bidir_ratio'] and avg_bpf >= r['min_avg_bytes_per_flow']
                and max_br >= r['min_max_bytes_rev'] and dur >= r['min_duration']):
            return 3, 'exploit_data_exfil', 0.80

        r = EXPLOIT_RULES['interactive']
        if (bidir_r >= r['min_bidir_ratio'] and max_fd >= r['min_max_flow_dur']
                and max_br >= r['min_max_bytes_rev'] and fc >= r['min_flow_count']):
            return 3, 'exploit_interactive', 0.75

    # BRUTE
    r = BRUTE_RULES['heavy_brute']
    if fc >= r['min_flow_count'] and reply_r >= r['min_reply_ratio'] and bidir_r <= r['max_bidir_ratio']:
        return 2, 'brute_heavy', 0.90

    r = BRUTE_RULES['auth_brute']
    if (fc >= r['min_flow_count'] and r['min_reply_ratio'] <= reply_r <= r['max_reply_ratio']
            and bidir_r <= r['max_bidir_ratio'] and comp_r >= r['min_completed_ratio']):
        return 2, 'brute_auth', 0.80

    # RECON
    r = RECON_RULES['horiz_scan']
    if (fc >= r['min_flow_count'] and syn_r >= r['min_syn_only_ratio']
            and reply_r <= r['max_reply_ratio'] and bidir_r <= r['max_bidir_ratio']):
        return 1, 'recon_horiz_scan', 0.90

    return 0, 'benign', 0.0


def classify_source(src_ip, sessions):
    """Check if a source IP qualifies for watchlist promotion.

    Protocol-aware reply-rate filtering:
      - TCP (6):  No reply filter — SYN-ACK replies are normal for scanners.
      - UDP (17): Reply filter active — high reply = reflector (DNS/NTP), not attacker.
      - ICMP (1): No reply filter — echo-reply is normal for ping sweeps.
      - OSPF/EIGRP/IGMP/VRRP (89/88/2/112): Infrastructure noise — filtered out.
      - Other:    No reply filter — monitor everything.
    """
    if _is_noise_ip(src_ip):
        return None

    # Filter infrastructure routing protocols (never attackers)
    INFRA_PROTOS = {2, 88, 89, 112}  # IGMP, EIGRP, OSPF, VRRP
    sessions = [s for s in sessions
                if not _is_noise_ip(s.get('dst_ip'))
                and not _is_reflection(s)
                and s.get('ip_proto', 0) not in INFRA_PROTOS]
    n_sessions = len(sessions)
    if n_sessions == 0:
        return None

    # Honeypot as source: filter out honeypot→honeypot sessions (VLAN 101 noise),
    # then score remaining with normal rules. If attack patterns found → compromised.
    if _is_honeypot_ip(src_ip):
        sessions = [s for s in sessions if not _is_honeypot_ip(s.get('dst_ip'))]
        n_sessions = len(sessions)
        if n_sessions == 0:
            return None  # All traffic is honeypot→honeypot noise
        # Check if any sessions were classified as attacks (stage > 0)
        attack_sessions = [s for s in sessions
                           if classify_session(s, max_stage=4)[0] > 0]
        if attack_sessions:
            log.warning('COMPROMISED HONEYPOT %s — %d attack sessions to %d external targets',
                        src_ip, len(attack_sessions), n_sessions)
            return COMPROMISED_HONEYPOT_RULE
        return None  # Outbound traffic but no attack patterns — normal replies

    unique_ports = len(set(s['dst_port'] for s in sessions))
    total_flows = sum(s.get('sess_flow_count', 0) or 0 for s in sessions)
    single_flow_sessions = sum(1 for s in sessions if (s.get('sess_flow_count', 0) or 0) == 1)
    single_flow_pct = single_flow_sessions / n_sessions if n_sessions > 0 else 0
    reply_rates = [s.get('sess_reply_ratio', 0) or 0 for s in sessions]
    avg_reply = sum(reply_rates) / len(reply_rates) if reply_rates else 0

    # Reply-rate anomaly: if this IP receives far more than it sends,
    # it's likely a honeypot appearing as src due to VLAN 101 egress capture.
    total_pkts_fwd = sum(s.get('sess_pkts_fwd', 0) or 0 for s in sessions)
    total_pkts_rev = sum(s.get('sess_pkts_rev', 0) or 0 for s in sessions)
    if total_pkts_fwd > 0 and total_pkts_rev / total_pkts_fwd > 3.0:
        return None  # Receiving 3x more than sending = honeypot reply traffic

    # UDP-only reply rate — only protocol where high reply signals reflector
    udp_sessions = [s for s in sessions if s.get('ip_proto') == 17]
    udp_reply_rates = [s.get('sess_reply_ratio', 0) or 0 for s in udp_sessions]
    avg_reply_udp = sum(udp_reply_rates) / len(udp_reply_rates) if udp_reply_rates else 0

    # Check scanner rule
    r = WATCHLIST_RULES['scanner']
    if (n_sessions >= r['min_sessions'] and unique_ports >= r['min_ports']
            and single_flow_pct >= r['min_single_flow_pct']
            and avg_reply_udp <= r['max_avg_reply']):
        return r

    # Check brute forcer rule (TCP-specific, overall reply is fine)
    r = WATCHLIST_RULES['brute_forcer']
    if (n_sessions >= r['min_sessions'] and total_flows >= r['min_total_flows']
            and avg_reply <= r['max_reply_rate']):
        return r

    # Check heavy hitter rule
    r = WATCHLIST_RULES['heavy_hitter']
    if (n_sessions >= r['min_sessions'] and total_flows >= r['min_total_flows']
            and avg_reply_udp <= r['max_avg_reply']):
        return r

    return None


def _session_query(db, having=''):
    """Build session feature query for any db with session_stats table."""
    return f"""
    SELECT
        src_ip, dst_ip, dst_port, ip_proto,
        countMerge(flow_count)  AS sess_flow_count,
        sumMerge(sum_bytes_fwd) AS sess_bytes_fwd,
        sumMerge(sum_bytes_rev) AS sess_bytes_rev,
        sumMerge(sum_pkts_fwd)  AS sess_pkts_fwd,
        sumMerge(sum_pkts_rev)  AS sess_pkts_rev,
        if(sumMerge(sum_pkts_fwd) > 0,
           sumMerge(sum_pkts_rev) / sumMerge(sum_pkts_fwd), 0) AS sess_reply_ratio,
        dateDiff('second', minMerge(first_seen), maxMerge(last_seen)) AS sess_duration,
        if(countMerge(flow_count) > 0,
           sumMerge(sum_duration) / countMerge(flow_count), 0) AS sess_avg_flow_dur,
        maxMerge(max_duration) AS sess_max_flow_dur,
        maxMerge(max_bytes_rev) AS sess_max_bytes_rev,
        if(countMerge(flow_count) > 0,
           (sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)) / countMerge(flow_count), 0) AS sess_avg_bytes_per_flow,
        if((sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)) > 0,
           sumMerge(sum_bytes_rev) / (sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)), 0) AS sess_payload_ratio,
        if(countMerge(flow_count) > 0,
           sumIfMerge(sum_bidir) / countMerge(flow_count), 0) AS sess_bidirectional_ratio,
        if(countMerge(flow_count) > 0,
           sumIfMerge(sum_conn_state_0) / countMerge(flow_count), 0) AS sess_syn_only_ratio,
        if(countMerge(flow_count) > 0,
           sumMerge(sum_rst) / countMerge(flow_count), 0) AS sess_rst_ratio,
        if(countMerge(flow_count) > 0,
           sumIfMerge(sum_conn_state_4) / countMerge(flow_count), 0) AS sess_completed_ratio,
        if(countMerge(flow_count) > 0,
           (sumMerge(sum_syn) + sumMerge(sum_fin) + sumMerge(sum_rst) + sumMerge(sum_psh))
               / countMerge(flow_count), 0) AS sess_avg_tcp_flags
    FROM {db}.session_stats
    GROUP BY src_ip, dst_ip, dst_port, ip_proto
    {having}
    """


def fetch_sessions(ch, minutes=10, backfill=False):
    """Fetch recent sessions from dfi.session_stats."""
    having = '' if backfill else f'HAVING maxMerge(last_seen) >= now() - INTERVAL {minutes} MINUTE'
    query = _session_query('dfi', having)
    rows = ch.execute(query, with_column_types=True)
    cols = [c[0] for c in rows[1]]
    return [dict(zip(cols, r)) for r in rows[0]]


def _fetch_local_db_sessions(ch, db, minutes=10, backfill=False):
    """Fetch sessions from a local CH database (dfi_dirty or dfi_clean)."""
    aio_ch = ch  # same local client
    having = '' if backfill else f'HAVING maxMerge(last_seen) >= now() - INTERVAL {minutes} MINUTE'
    query = _session_query(db, having)
    rows = aio_ch.execute(query, with_column_types=True)
    cols = [c[0] for c in rows[1]]
    return [dict(zip(cols, r)) for r in rows[0]]


def write_predictions(ch, predictions):
    """Write session predictions to ClickHouse."""
    if not predictions:
        return
    ch.execute(
        'INSERT INTO dfi.session_predictions '
        '(src_ip, dst_ip, dst_port, model_name, model_version, label, confidence, kill_chain_stage) '
        'VALUES',
        predictions,
    )


def push_watchlist_local(watchlist_entries):
    """Push IPs directly to local watchlist.db (for --local mode on AIO/ARM)."""
    if not watchlist_entries:
        return 0
    import sqlite3
    now = time.time()
    TTL_DAYS = 30
    expires_at = now + TTL_DAYS * 86400
    con = sqlite3.connect(WATCHLIST_DB)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=NORMAL')
    sql = '''INSERT INTO watchlist (src_ip, capture_depth, priority, reason, source, expires_at, updated_at)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(src_ip) DO UPDATE SET
capture_depth=MAX(watchlist.capture_depth, excluded.capture_depth),
priority=MIN(watchlist.priority, excluded.priority),
reason=excluded.reason,
source=CASE WHEN watchlist.source IN ('xgb_scorer','classifier') THEN watchlist.source ELSE excluded.source END,
expires_at=excluded.expires_at,
updated_at=excluded.updated_at'''
    rows = [(str(ip), rule['capture_depth'], rule['priority'],
             rule['reason'], 'session_rules', expires_at, now)
            for ip, rule in watchlist_entries.items()]
    con.executemany(sql, rows)
    n_expired = con.execute('DELETE FROM watchlist WHERE expires_at IS NOT NULL AND expires_at < ?', (now,)).rowcount
    con.commit()
    con.close()
    if n_expired:
        log.info('Purged %d expired watchlist entries', n_expired)
    log.info('Pushed %d IPs to local watchlist', len(rows))
    return len(rows)


## push_watchlist() removed — was SSH to AIO. All pushes now use push_watchlist_local().


def _classify_and_collect(sessions, model_name='session_rules_v1', max_stage=4):
    """Classify sessions, return (predictions, stage_counts, src_sessions)."""
    predictions = []
    stage_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    src_sessions = {}

    for s in sessions:
        stage, rule_name, confidence = classify_session(s, max_stage=max_stage)
        stage_counts[stage] += 1

        src = str(s['src_ip'])
        if src not in src_sessions:
            src_sessions[src] = []
        src_sessions[src].append(s)

        if stage > 0:
            predictions.append({
                'src_ip': src,
                'dst_ip': str(s['dst_ip']),
                'dst_port': int(s['dst_port']),
                'model_name': model_name,
                'model_version': 'threshold_v1',
                'label': 1,
                'confidence': float(confidence),
                'kill_chain_stage': stage,
            })

    return predictions, stage_counts, src_sessions


def _log_summary(label, sessions, stage_counts, predictions):
    """Log scoring summary."""
    stage_names = {0: 'BENIGN', 1: 'RECON', 2: 'BRUTE', 3: 'EXPLOIT', 4: 'C2'}
    log.info('[%s] Scored %s sessions:', label, f'{len(sessions):,}')
    for stage_id in sorted(stage_counts):
        cnt = stage_counts[stage_id]
        if cnt > 0:
            pct = 100 * cnt / len(sessions)
            log.info('  %s: %s (%.1f%%)', stage_names[stage_id], f'{cnt:,}', pct)
    log.info('[%s] Predictions: %s', label, f'{len(predictions):,}')


def _ensure_predictions_table(ch, db):
    """Create session_predictions table if it doesn't exist."""
    ch.execute(f"""
    CREATE TABLE IF NOT EXISTS {db}.session_predictions (
        src_ip         String,
        dst_ip         String,
        dst_port       UInt16,
        model_name     String,
        model_version  String,
        label          UInt8,
        confidence     Float32,
        kill_chain_stage UInt8,
        created_at     DateTime DEFAULT now()
    ) ENGINE = MergeTree()
    ORDER BY (src_ip, dst_ip, dst_port, created_at)
    """)


def write_predictions_local(ch, db, predictions):
    """Write session predictions to local ClickHouse database."""
    if not predictions:
        return
    _ensure_predictions_table(ch, db)
    ch.execute(
        f'INSERT INTO {db}.session_predictions '
        '(src_ip, dst_ip, dst_port, model_name, model_version, label, confidence, kill_chain_stage) '
        'VALUES',
        predictions,
    )


def run_local(minutes=10, backfill=False, test_mode=False):
    """Local scoring loop for AIO/ARM — queries local CH, writes locally, pushes to local watchlist."""
    t0 = time.time()
    ch = Client('localhost', port=9000)

    all_watchlist = {}
    BATCH = 100000

    if test_mode:
        dbs = [('dfi', 'TEST', 4)]
    else:
        dbs = [('dfi_dirty', 'DIRTY', 4), ('dfi_clean', 'CLEAN', 2)]

    for db, label, stage_cap in dbs:
        try:
            having = '' if backfill else f'HAVING maxMerge(last_seen) >= now() - INTERVAL {minutes} MINUTE'
            query = _session_query(db, having)
            rows = ch.execute(query, with_column_types=True)
            cols = [c[0] for c in rows[1]]
            sessions = [dict(zip(cols, r)) for r in rows[0]]

            if not sessions:
                log.info('[%s] No sessions to score', label)
                continue
            log.info('[%s] Sessions to score: %s', label, f'{len(sessions):,}')

            model_name = f'session_rules_v1_{db}'
            preds, stage_counts, src_sessions = _classify_and_collect(sessions, model_name, max_stage=stage_cap)

            # Write predictions to local CH
            for i in range(0, len(preds), BATCH):
                write_predictions_local(ch, db, preds[i:i + BATCH])

            # Collect watchlist candidates
            for src_ip, sess_list in src_sessions.items():
                rule = classify_source(src_ip, sess_list)
                if rule is not None and src_ip not in all_watchlist:
                    all_watchlist[src_ip] = rule

            _log_summary(label, sessions, stage_counts, preds)
        except Exception as exc:
            log.error('[%s] Failed: %s', label, exc)

    # Push to local watchlist.db
    n_pushed = 0
    if all_watchlist:
        log.info('Watchlist candidates: %d IPs', len(all_watchlist))
        n_pushed = push_watchlist_local(all_watchlist)

    elapsed = time.time() - t0
    log.info('Total elapsed: %.1fs, watchlist pushed: %d IPs', elapsed, n_pushed)


def run(minutes=10, backfill=False, score_dirty_clean=False):
    """Main scoring loop — all local (PV1 consolidated)."""
    t0 = time.time()
    ch = Client(CH_HOST, port=CH_PORT)

    # 1. Fetch sessions from local PV1 dfi
    sessions = fetch_sessions(ch, minutes=minutes, backfill=backfill)
    if not sessions:
        log.info('No PV1 sessions to score')
    else:
        log.info('PV1 sessions to score: %s', f'{len(sessions):,}')

    # 2. Classify PV1 sessions
    all_watchlist = {}
    BATCH = 100000
    if sessions:
        predictions, stage_counts, src_sessions = _classify_and_collect(sessions, 'session_rules_v1')

        # Write predictions to local CH
        for i in range(0, len(predictions), BATCH):
            write_predictions(ch, predictions[i:i + BATCH])

        # Collect watchlist candidates
        for src_ip, sess_list in src_sessions.items():
            rule = classify_source(src_ip, sess_list)
            if rule is not None:
                all_watchlist[src_ip] = rule

        _log_summary('PV1', sessions, stage_counts, predictions)

    # 3. Score local dirty/clean sessions (all on PV1 now)
    if score_dirty_clean:
        for db_name, label, stage_cap in [('dfi_dirty', 'DIRTY', 4), ('dfi_clean', 'CLEAN', 2)]:
            try:
                local_sessions = _fetch_local_db_sessions(ch, db_name, minutes=minutes, backfill=backfill)
                if not local_sessions:
                    log.info('[%s] No sessions to score', label)
                    continue
                log.info('[%s] Sessions to score: %s', label, f'{len(local_sessions):,}')

                model_name = f'session_rules_v1_{db_name}'
                dc_preds, dc_stages, dc_src = _classify_and_collect(local_sessions, model_name, max_stage=stage_cap)

                for i in range(0, len(dc_preds), BATCH):
                    write_predictions(ch, dc_preds[i:i + BATCH])

                for src_ip, sess_list in dc_src.items():
                    rule = classify_source(src_ip, sess_list)
                    if rule is not None and src_ip not in all_watchlist:
                        all_watchlist[src_ip] = rule

                _log_summary(label, local_sessions, dc_stages, dc_preds)
            except Exception as exc:
                log.error('[%s] Failed: %s', label, exc)

    # 4. Push to LOCAL watchlist (no more SSH to AIO)
    n_pushed = 0
    if all_watchlist:
        log.info('Watchlist candidates: %d IPs', len(all_watchlist))
        n_pushed = push_watchlist_local(all_watchlist)

    # 5. Final summary
    elapsed = time.time() - t0
    log.info('Total elapsed: %.1fs, watchlist pushed: %d IPs', elapsed, n_pushed)


def main():
    ap = argparse.ArgumentParser(description='Session threshold rules scorer.')
    ap.add_argument('--minutes', type=int, default=10, help='Score sessions active in last N minutes (default: 10)')
    ap.add_argument('--hours', type=int, default=0, help='Override: last N hours')
    ap.add_argument('--backfill', action='store_true', help='Score ALL sessions (no time filter)')
    ap.add_argument('--dirty-clean', action='store_true', help='Also score local dfi_dirty + dfi_clean')
    ap.add_argument('--test', action='store_true', help='Test mode: query dfi database instead of dfi_dirty/dfi_clean (ARM model testing)')
    args = ap.parse_args()

    minutes = args.hours * 60 if args.hours > 0 else args.minutes
    if args.test:
        run_local(minutes=minutes, backfill=args.backfill, test_mode=True)
    else:
        run(minutes=minutes, backfill=args.backfill, score_dirty_clean=args.dirty_clean)


if __name__ == '__main__':
    main()
