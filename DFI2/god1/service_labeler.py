#!/usr/bin/env python3
"""
service_labeler.py — Maps evidence_events to per-service behavioral class labels.

Reads evidence_events (2-hour window), groups by (src_ip, service_id),
classifies each group into a behavioral class, writes to dfi.ip_service_labels.

Service classes:
  SSH(1):  SCAN=0, PROBE=1, BRUTE=2, CREDENTIAL=3, COMMAND=4, PERSIST=5
  HTTP(2): SCAN=0, CRAWL=1, FUZZ=2, EXPLOIT=3, WEBSHELL=4, EXFIL=5
  RDP(3):  SCAN=0, PROBE=1, BRUTE=2, CREDENTIAL=3, COMMAND=4, PERSIST=5
  SQL(4):  SCAN=0, PROBE=1, BRUTE=2, INJECTION=3, EXFIL=4
  SMB(5):  SCAN=0, NEGOTIATE=1, ENUM=2, BRUTE=3, EXPLOIT=4, LATERAL=5

Key fix (2026-04-07): resolve_services() now returns a LIST of service_ids.
Events like auth_success/credential_capture route to the correct service based on
source_program, not a hardcoded default. sql_injection routes to BOTH HTTP and SQL.

Runs as PV1 cron every 5 minutes at :10-:59/5.

Usage:
    python3 service_labeler.py [--window-hours 2] [--dry-run]
"""

import sys
import time
import json
import argparse
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('service_labeler')

# ── Service IDs ──────────────────────────────────────────────────────────
SVC_SSH  = 1
SVC_HTTP = 2
SVC_RDP  = 3
SVC_SQL  = 4
SVC_SMB  = 5

SERVICE_NAMES = {1: 'SSH', 2: 'HTTP', 3: 'RDP', 4: 'SQL', 5: 'SMB'}

# ── Class names per service (for logging) ────────────────────────────────
CLASS_NAMES = {
    SVC_SSH:  {0: 'SCAN', 1: 'PROBE', 2: 'BRUTE', 3: 'CREDENTIAL', 4: 'COMMAND', 5: 'PERSIST'},
    SVC_HTTP: {0: 'SCAN', 1: 'CRAWL', 2: 'FUZZ', 3: 'EXPLOIT', 4: 'WEBSHELL', 5: 'EXFIL'},
    SVC_RDP:  {0: 'SCAN', 1: 'PROBE', 2: 'BRUTE', 3: 'CREDENTIAL', 4: 'COMMAND', 5: 'PERSIST'},
    SVC_SQL:  {0: 'SCAN', 1: 'PROBE', 2: 'BRUTE', 3: 'INJECTION', 4: 'EXFIL'},
    SVC_SMB:  {0: 'SCAN', 1: 'NEGOTIATE', 2: 'ENUM', 3: 'BRUTE', 4: 'EXPLOIT', 5: 'LATERAL'},
}

# ── Source program → service mapping ────────────────────────────────────
# Routes generic events (auth_failure, auth_success, credential_capture,
# privilege_escalation, suspicious_command) to the correct service.
SOURCE_PROGRAM_SERVICE = {
    'sshd':              SVC_SSH,
    'winlure_conn_ssh':  SVC_SSH,
    'winlure_ssh_win':   SVC_SSH,
    'winlure_conn_http': SVC_HTTP,
    'winlure_http_iis':  SVC_HTTP,
    'winlure_conn_rdp':  SVC_RDP,
    'winlure_conn_smb':  SVC_SMB,
    'winlure_smb':       SVC_SMB,
    'winlure_netbios':   SVC_SMB,
    'winlure_conn_mssql': SVC_SQL,
    'winlure_mssql':     SVC_SQL,
    'winlure_conn_winrm': SVC_HTTP,
    # Windows event IDs → service context
    'windows_4625':  SVC_RDP,    # Logon failure
    'windows_4624':  SVC_RDP,    # Successful logon
    'windows_4648':  SVC_RDP,    # Explicit credential logon
    'windows_4634':  SVC_RDP,    # Logoff
    'windows_18456': SVC_SQL,    # SQL Server login failure
    'windows_4672':  SVC_RDP,    # Special privileges assigned
    'windows_4718':  SVC_RDP,    # Audit policy changed
    'windows_4717':  SVC_RDP,    # Audit policy changed
    'windows_53504': SVC_RDP,    # PowerShell activity
    'windows_4688':  SVC_RDP,    # Process creation
    'windows_7045':  SVC_RDP,    # Service installed
    'windows_4104':  SVC_RDP,    # PowerShell script block
    'windows_4724':  SVC_RDP,    # Password reset
    'windows_7040':  SVC_RDP,    # Service start type changed
    'windows_4740':  SVC_RDP,    # Account locked out
    'windows_4799':  SVC_RDP,    # Group membership enumerated
    'windows_4776':  SVC_RDP,    # NTLM auth
    'windows_4738':  SVC_RDP,    # User account changed
    'windows_18452': SVC_SQL,    # SQL login failure
    'windows_17836': SVC_SQL,    # SQL trace
    'windows_17832': SVC_SQL,    # SQL login failed
    'windows_17806': SVC_SQL,    # SSPI handshake
}

# ── Event types fixed to a specific service ─────────────────────────────
EVENT_FIXED_SERVICE = {
    'banner_exchange':   [SVC_SSH],
    'http_request':      [SVC_HTTP],
    'search_request':    [SVC_HTTP],
    'path_traversal':    [SVC_HTTP],
    'wsman_identify':    [SVC_HTTP],
    'negotiation':       [SVC_RDP],
    'prelogin_info':     [SVC_SQL],
    'login_attempt':     [SVC_SQL],
    'name_query':        [SVC_SMB],
    'negotiate_dialect': [SVC_SMB],
    'bind_attempt':      [SVC_SMB],
    'dns_query':         [],
    'connection':        [],
    'unknown':           [],
}

# ── Event types that route based on source_program ──────────────────────
EVENT_ROUTED = {
    'auth_failure', 'auth_success', 'auth_attempt',
    'credential_capture', 'suspicious_command', 'privilege_escalation',
    'process_create', 'service_install', 'file_download',
    'sql_injection',
}

# ── Port-based override ──────────────────────────────────────────────────
PORT_SERVICE = {
    22: SVC_SSH, 2222: SVC_SSH,
    80: SVC_HTTP, 443: SVC_HTTP, 8080: SVC_HTTP, 8443: SVC_HTTP, 8888: SVC_HTTP,
    3389: SVC_RDP,
    3306: SVC_SQL, 1433: SVC_SQL, 5432: SVC_SQL,
    445: SVC_SMB, 139: SVC_SMB, 137: SVC_SMB,
    389: SVC_SMB,
}

DETAIL_SERVICE_MAP = {
    'ssh': SVC_SSH,
    'http': SVC_HTTP, 'https': SVC_HTTP,
    'rdp': SVC_RDP,
    'mssql': SVC_SQL, 'mysql': SVC_SQL, 'postgres': SVC_SQL,
    'smb': SVC_SMB, 'netbios': SVC_SMB, 'ldap': SVC_SMB,
}


def resolve_services(event_type, event_detail_str, source_program):
    """Determine service_id(s) for an evidence event.

    Returns a list of service_ids (may be empty, one, or multiple).
    """
    # 1. Fixed service events
    if event_type in EVENT_FIXED_SERVICE:
        return EVENT_FIXED_SERVICE[event_type]

    # 2. Multi-service events BEFORE detail parsing (detail has single-service bias)
    if event_type == 'sql_injection':
        return [SVC_HTTP, SVC_SQL]

    # 3. Try event_detail JSON for specific routing
    try:
        detail = json.loads(event_detail_str) if event_detail_str else {}
    except (json.JSONDecodeError, TypeError):
        detail = {}

    svc_name = detail.get('service', '')
    if svc_name and svc_name in DETAIL_SERVICE_MAP:
        return [DETAIL_SERVICE_MAP[svc_name]]

    dst_port = detail.get('dst_port')
    if dst_port and dst_port in PORT_SERVICE:
        return [PORT_SERVICE[dst_port]]

    # 4. Routed events — use source_program
    if event_type in EVENT_ROUTED:

        # Direct source_program match
        if source_program in SOURCE_PROGRAM_SERVICE:
            return [SOURCE_PROGRAM_SERVICE[source_program]]

        # Winlure container prefix — default to SSH for auth events
        if source_program and source_program.startswith('winlure:'):
            return [SVC_SSH]

        return []

    return []


# ── Classifiers (unchanged logic, same thresholds) ──────────────────────

def classify_ssh(events):
    """Classify SSH behavioral stage."""
    counts = defaultdict(int)
    for et, cnt in events.items():
        counts[et] += cnt
    mask = 0
    if counts.get('service_install', 0) > 0 or counts.get('privilege_escalation', 0) > 0:
        mask |= 0x20; return 5, 0.95, mask
    if counts.get('suspicious_command', 0) > 0 or counts.get('process_create', 0) > 0:
        mask |= 0x10; return 4, 0.90, mask
    if counts.get('auth_success', 0) > 0 or counts.get('credential_capture', 0) > 0:
        mask |= 0x08; return 3, 0.90, mask
    af = counts.get('auth_failure', 0) + counts.get('auth_attempt', 0)
    if af >= 3:
        mask |= 0x04; return 2, min(0.95, 0.70 + af / 100.0), mask
    if counts.get('banner_exchange', 0) > 0:
        mask |= 0x02; return 1, 0.80, mask
    return 0, 0.60, mask


def classify_http(events):
    """Classify HTTP behavioral stage."""
    counts = defaultdict(int)
    for et, cnt in events.items():
        counts[et] += cnt
    mask = 0
    if counts.get('suspicious_command', 0) > 0:
        mask |= 0x10; return 4, 0.95, mask
    if counts.get('sql_injection', 0) > 0 or counts.get('path_traversal', 0) > 0:
        mask |= 0x08; return 3, 0.90, mask
    sr = counts.get('search_request', 0)
    hr = counts.get('http_request', 0)
    if sr > 0 or hr > 10:
        mask |= 0x04; return 2, 0.80, mask
    if hr > 0:
        mask |= 0x02; return 1, 0.70, mask
    return 0, 0.60, mask


def classify_rdp(events):
    """Classify RDP behavioral stage."""
    counts = defaultdict(int)
    for et, cnt in events.items():
        counts[et] += cnt
    mask = 0
    if counts.get('service_install', 0) > 0 or counts.get('privilege_escalation', 0) > 0:
        mask |= 0x20; return 5, 0.95, mask
    if counts.get('suspicious_command', 0) > 0 or counts.get('process_create', 0) > 0:
        mask |= 0x10; return 4, 0.90, mask
    if counts.get('auth_success', 0) > 0 or counts.get('credential_capture', 0) > 0:
        mask |= 0x08; return 3, 0.90, mask
    af = counts.get('auth_failure', 0) + counts.get('auth_attempt', 0)
    if af >= 3:
        mask |= 0x04; return 2, min(0.95, 0.70 + af / 100.0), mask
    if counts.get('negotiation', 0) > 0:
        mask |= 0x02; return 1, 0.80, mask
    return 0, 0.60, mask


def classify_sql(events):
    """Classify SQL behavioral stage."""
    counts = defaultdict(int)
    for et, cnt in events.items():
        counts[et] += cnt
    mask = 0
    if counts.get('suspicious_command', 0) > 0:
        mask |= 0x10; return 4, 0.95, mask
    if counts.get('sql_injection', 0) > 0:
        mask |= 0x08; return 3, 0.90, mask
    la = counts.get('login_attempt', 0)
    af = counts.get('auth_failure', 0) + counts.get('auth_attempt', 0)
    if la >= 3 or af >= 3:
        mask |= 0x04; return 2, min(0.95, 0.70 + max(la, af) / 100.0), mask
    if counts.get('prelogin_info', 0) > 0:
        mask |= 0x02; return 1, 0.80, mask
    return 0, 0.60, mask


def classify_smb(events):
    """Classify SMB behavioral stage."""
    counts = defaultdict(int)
    for et, cnt in events.items():
        counts[et] += cnt
    mask = 0
    if counts.get('credential_capture', 0) > 0 and counts.get('service_install', 0) > 0:
        mask |= 0x20; return 5, 0.95, mask
    if counts.get('suspicious_command', 0) > 0:
        mask |= 0x10; return 4, 0.90, mask
    af = counts.get('auth_failure', 0) + counts.get('auth_attempt', 0)
    if af >= 3:
        mask |= 0x04; return 3, min(0.95, 0.70 + af / 100.0), mask
    if (counts.get('name_query', 0) > 0 or counts.get('bind_attempt', 0) > 0 or
            counts.get('search_request', 0) > 0):
        mask |= 0x02; return 2, 0.80, mask
    if counts.get('negotiate_dialect', 0) > 0:
        mask |= 0x01; return 1, 0.75, mask
    return 0, 0.60, mask


CLASSIFIERS = {
    SVC_SSH:  classify_ssh,
    SVC_HTTP: classify_http,
    SVC_RDP:  classify_rdp,
    SVC_SQL:  classify_sql,
    SVC_SMB:  classify_smb,
}


def run_labeler(ch, window_hours=2, dry_run=False):
    """Query evidence_events, classify per (src_ip, service), write ip_service_labels."""

    log.info("Querying evidence_events (window: %d hours)", window_hours)

    query = """
    SELECT
        toString(src_ip) AS ip,
        event_type,
        event_detail,
        source_program,
        count() AS cnt,
        min(ts) AS first_ts,
        max(ts) AS last_ts
    FROM dfi.evidence_events
    WHERE ts >= now() - INTERVAL %(window)d HOUR
    GROUP BY src_ip, event_type, event_detail, source_program
    """
    rows = ch.execute(query, {'window': window_hours})
    log.info("Evidence rows: %d", len(rows))

    if not rows:
        log.info("No evidence in window, exiting.")
        return 0

    # Group by (src_ip, service_id) — one event can route to MULTIPLE services
    groups = defaultdict(lambda: {'events': defaultdict(int),
                                   'first': None, 'last': None, 'total': 0})

    routed = 0
    skipped = 0
    multi = 0
    for ip, event_type, event_detail, source_program, cnt, first_ts, last_ts in rows:
        svc_ids = resolve_services(event_type, event_detail, source_program)
        if not svc_ids:
            skipped += cnt
            continue
        if len(svc_ids) > 1:
            multi += cnt
        for svc_id in svc_ids:
            key = (ip, svc_id)
            g = groups[key]
            g['events'][event_type] += cnt
            g['total'] += cnt
            if g['first'] is None or first_ts < g['first']:
                g['first'] = first_ts
            if g['last'] is None or last_ts > g['last']:
                g['last'] = last_ts
            routed += cnt

    log.info("Routed %d events (%d multi-service, %d skipped)", routed, multi, skipped)
    log.info("Unique (ip, service) groups: %d", len(groups))

    # Classify each group
    labels = []
    for (ip, svc_id), g in groups.items():
        classifier = CLASSIFIERS.get(svc_id)
        if not classifier:
            continue
        svc_class, confidence, ev_mask = classifier(g['events'])
        labels.append({
            'src_ip': ip,
            'service_id': svc_id,
            'service_class': svc_class,
            'label_confidence': round(confidence, 4),
            'label_source': 'service_labeler',
            'evidence_mask': ev_mask,
            'event_count': g['total'],
            'first_seen': g['first'],
            'last_seen': g['last'],
        })

    log.info("Labels to write: %d", len(labels))

    # Log distribution
    dist = defaultdict(lambda: defaultdict(int))
    for lb in labels:
        svc_name = SERVICE_NAMES.get(lb['service_id'], '?')
        cls_name = CLASS_NAMES.get(lb['service_id'], {}).get(lb['service_class'], '?')
        dist[svc_name][cls_name] += 1

    for svc_name in sorted(dist.keys()):
        parts = ', '.join(f"{cn}={ct}" for cn, ct in sorted(dist[svc_name].items()))
        log.info("  %s: %s", svc_name, parts)

    if dry_run:
        log.info("DRY RUN — not writing to ClickHouse")
        return len(labels)

    # Write to ip_service_labels
    if labels:
        columns = ['src_ip', 'service_id', 'service_class', 'label_confidence',
                    'label_source', 'evidence_mask', 'event_count',
                    'first_seen', 'last_seen']
        values = [[lb[c] for c in columns] for lb in labels]
        ch.execute(
            f"INSERT INTO dfi.ip_service_labels ({','.join(columns)}) VALUES",
            values
        )
        log.info("Wrote %d rows to dfi.ip_service_labels", len(labels))

    return len(labels)


def main():
    parser = argparse.ArgumentParser(description='Per-Service Evidence Labeler')
    parser.add_argument('--window-hours', type=int, default=2,
                        help='Lookback window in hours (default: 2)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print what would be written without writing')
    parser.add_argument('--ch-host', default='localhost',
                        help='ClickHouse host')
    args = parser.parse_args()

    ch = Client(host=args.ch_host)

    start = time.time()
    count = run_labeler(ch, args.window_hours, args.dry_run)
    elapsed = time.time() - start

    log.info("Done in %.1fs. %d labels written.", elapsed, count)


if __name__ == '__main__':
    main()
