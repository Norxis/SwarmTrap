#!/usr/bin/env python3
"""
service_label_mapper.py — Maps universal labels to per-service behavioral classes.

Reads dfi.flows (label, dst_port, pkts_rev, conn_state) + dfi.evidence_events,
computes per-service behavioral label (unified vocabulary 1-99),
writes service_label to dfi.flows.

Per-service behavioral classes (from BF2 Pre-Processor Proposal):
  SSH  (1-6):  SCAN, PROBE, BRUTE, CREDENTIAL, COMMAND, PERSIST
  HTTP (10-15): SCAN, CRAWL, FUZZ, EXPLOIT, WEBSHELL, EXFIL
  RDP  (20-25): SCAN, PROBE, BRUTE, CREDENTIAL, COMMAND, PERSIST
  MySQL(30-34): SCAN, PROBE, BRUTE, INJECTION, EXFIL
  Redis(40-44): SCAN, ENUM, AUTH_BYPASS, COMMAND, RANSOM
  SMB  (50-55): SCAN, NEGOTIATE, ENUM, BRUTE, EXPLOIT, LATERAL
  99 = Unknown service/class, 0 = padding

Runs as PV1 cron every 5 minutes (after labeler).

Usage:
    python3 service_label_mapper.py [--window-minutes 15] [--dry-run]
"""

import sys
import time
import argparse
import logging
from datetime import datetime, timedelta, timezone
from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('service_label')

# Universal labels (existing)
RECON, KNOCK, BRUTEFORCE, EXPLOIT, COMPROMISE = 0, 1, 2, 3, 4

# Per-service behavioral class vocabulary
# SSH classes
SSH_SCAN       = 1
SSH_PROBE      = 2
SSH_BRUTE      = 3
SSH_CREDENTIAL = 4
SSH_COMMAND    = 5
SSH_PERSIST    = 6

# HTTP classes
HTTP_SCAN      = 10
HTTP_CRAWL     = 11
HTTP_FUZZ      = 12
HTTP_EXPLOIT   = 13
HTTP_WEBSHELL  = 14
HTTP_EXFIL     = 15

# RDP classes
RDP_SCAN       = 20
RDP_PROBE      = 21
RDP_BRUTE      = 22
RDP_CREDENTIAL = 23
RDP_COMMAND    = 24
RDP_PERSIST    = 25

# MySQL/MSSQL classes
MYSQL_SCAN      = 30
MYSQL_PROBE     = 31
MYSQL_BRUTE     = 32
MYSQL_INJECTION = 33
MYSQL_EXFIL     = 34

# Redis classes
REDIS_SCAN       = 40
REDIS_ENUM       = 41
REDIS_AUTH_BYPASS = 42
REDIS_COMMAND    = 43
REDIS_RANSOM     = 44

# SMB classes
SMB_SCAN       = 50
SMB_NEGOTIATE  = 51
SMB_ENUM       = 52
SMB_BRUTE      = 53
SMB_EXPLOIT    = 54
SMB_LATERAL    = 55

SVC_UNKNOWN    = 99

# Port → service mapping
PORT_SERVICE = {
    22: 'ssh', 2222: 'ssh',
    80: 'http', 443: 'http', 8080: 'http', 8443: 'http', 8888: 'http',
    3389: 'rdp',
    3306: 'mysql', 1433: 'mysql',  # MSSQL uses same classes
    6379: 'redis',
    445: 'smb', 139: 'smb',
    21: 'ftp', 23: 'telnet',
    5432: 'postgres', 27017: 'mongodb',
}


def map_ssh(label, pkts_rev, conn_state, evidence_mask):
    """Map universal label to SSH behavioral class."""
    if pkts_rev == 0:
        return SSH_SCAN
    if label == RECON:
        return SSH_PROBE if pkts_rev > 0 else SSH_SCAN
    if label == KNOCK:
        return SSH_PROBE
    if label == BRUTEFORCE:
        return SSH_BRUTE
    if label == EXPLOIT:
        # Check evidence for post-auth activity
        if evidence_mask & 0x10:  # suspicious_command
            return SSH_COMMAND
        return SSH_CREDENTIAL
    if label == COMPROMISE:
        if evidence_mask & 0x80:  # lateral_movement
            return SSH_PERSIST
        if evidence_mask & 0x10:  # suspicious_command
            return SSH_COMMAND
        return SSH_CREDENTIAL
    return SSH_SCAN


def map_http(label, pkts_rev, conn_state, evidence_mask):
    """Map universal label to HTTP behavioral class."""
    if pkts_rev == 0:
        return HTTP_SCAN
    if label == RECON:
        return HTTP_CRAWL if pkts_rev > 0 else HTTP_SCAN
    if label == KNOCK:
        return HTTP_CRAWL
    if label == BRUTEFORCE:
        return HTTP_FUZZ
    if label == EXPLOIT:
        if evidence_mask & 0x10:  # suspicious command
            return HTTP_WEBSHELL
        return HTTP_EXPLOIT
    if label == COMPROMISE:
        if evidence_mask & 0x20:  # file_download
            return HTTP_EXFIL
        return HTTP_WEBSHELL
    return HTTP_SCAN


def map_rdp(label, pkts_rev, conn_state, evidence_mask):
    """Map universal label to RDP behavioral class."""
    if pkts_rev == 0:
        return RDP_SCAN
    if label == RECON:
        return RDP_PROBE if pkts_rev > 0 else RDP_SCAN
    if label == KNOCK:
        return RDP_PROBE
    if label == BRUTEFORCE:
        return RDP_BRUTE
    if label == EXPLOIT:
        return RDP_CREDENTIAL
    if label == COMPROMISE:
        if evidence_mask & 0x80:
            return RDP_PERSIST
        if evidence_mask & 0x10:
            return RDP_COMMAND
        return RDP_CREDENTIAL
    return RDP_SCAN


def map_mysql(label, pkts_rev, conn_state, evidence_mask):
    """Map universal label to MySQL behavioral class."""
    if pkts_rev == 0:
        return MYSQL_SCAN
    if label == RECON:
        return MYSQL_PROBE if pkts_rev > 0 else MYSQL_SCAN
    if label == KNOCK:
        return MYSQL_PROBE
    if label == BRUTEFORCE:
        return MYSQL_BRUTE
    if label == EXPLOIT:
        return MYSQL_INJECTION
    if label == COMPROMISE:
        return MYSQL_EXFIL
    return MYSQL_SCAN


def map_smb(label, pkts_rev, conn_state, evidence_mask):
    """Map universal label to SMB behavioral class."""
    if pkts_rev == 0:
        return SMB_SCAN
    if label == RECON:
        return SMB_NEGOTIATE if pkts_rev > 0 else SMB_SCAN
    if label == KNOCK:
        return SMB_ENUM
    if label == BRUTEFORCE:
        return SMB_BRUTE
    if label == EXPLOIT:
        return SMB_EXPLOIT
    if label == COMPROMISE:
        if evidence_mask & 0x80:
            return SMB_LATERAL
        return SMB_EXPLOIT
    return SMB_SCAN


def map_redis(label, pkts_rev, conn_state, evidence_mask):
    """Map universal label to Redis behavioral class."""
    if pkts_rev == 0:
        return REDIS_SCAN
    if label in (RECON, KNOCK):
        return REDIS_ENUM
    if label == BRUTEFORCE:
        return REDIS_AUTH_BYPASS
    if label == EXPLOIT:
        return REDIS_COMMAND
    if label == COMPROMISE:
        return REDIS_RANSOM
    return REDIS_SCAN


SERVICE_MAPPER = {
    'ssh': map_ssh,
    'http': map_http,
    'rdp': map_rdp,
    'mysql': map_mysql,
    'smb': map_smb,
    'redis': map_redis,
}


def run_mapper(ch: Client, window_minutes: int = 15, dry_run: bool = False):
    """Map service labels for recently labeled flows."""

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_minutes)

    # Get flows that have a label but no service_label
    query = """
    SELECT flow_id, src_ip, dst_port, label, pkts_rev, conn_state
    FROM dfi.flows
    WHERE ingested_at >= %(start)s
      AND label > 0
      AND service_label = 0
    LIMIT 100000
    """

    rows = ch.execute(query, {'start': window_start})
    log.info("Flows to label: %d", len(rows))

    if not rows:
        return 0

    # Get evidence masks for these src_ips
    src_ips = list(set(str(r[1]) for r in rows))
    evidence_query = """
    SELECT src_ip, groupBitOr(evidence_mask_bit) AS mask
    FROM dfi.evidence_events
    WHERE src_ip IN %(ips)s
      AND ts >= %(start)s - INTERVAL 2 MINUTE
    GROUP BY src_ip
    """
    ev_rows = ch.execute(evidence_query, {'ips': src_ips, 'start': window_start})
    evidence_map = {str(r[0]): r[1] for r in ev_rows}

    # Compute service labels
    updates = []
    for r in rows:
        flow_id = r[0]
        src_ip = str(r[1])
        dst_port = r[2]
        label = r[3]
        pkts_rev = r[4]
        conn_state = r[5]

        service = PORT_SERVICE.get(dst_port, None)
        mapper = SERVICE_MAPPER.get(service, None) if service else None
        ev_mask = evidence_map.get(src_ip, 0)

        if mapper:
            svc_label = mapper(label, pkts_rev, conn_state, ev_mask)
        else:
            svc_label = SVC_UNKNOWN

        updates.append((flow_id, svc_label))

    log.info("Computed %d service labels", len(updates))

    if dry_run:
        # Show distribution
        from collections import Counter
        dist = Counter(u[1] for u in updates)
        for k in sorted(dist.keys()):
            log.info("  class %d: %d flows", k, dist[k])
        return len(updates)

    # Use ClickHouse ALTER TABLE UPDATE with multiIf expression
    # Computes service_label from dst_port + label in a single mutation
    mutation = """
    ALTER TABLE dfi.flows UPDATE service_label = multiIf(
        /* SSH (ports 22, 2222) */
        dst_port IN (22, 2222) AND pkts_rev = 0, 1,
        dst_port IN (22, 2222) AND label = 0, 2,
        dst_port IN (22, 2222) AND label = 1, 2,
        dst_port IN (22, 2222) AND label = 2, 3,
        dst_port IN (22, 2222) AND label = 3, 5,
        dst_port IN (22, 2222) AND label = 4, 5,
        dst_port IN (22, 2222), 1,

        /* HTTP (ports 80, 443, 8080, 8443, 8888) */
        dst_port IN (80, 443, 8080, 8443, 8888) AND pkts_rev = 0, 10,
        dst_port IN (80, 443, 8080, 8443, 8888) AND label IN (0,1), 11,
        dst_port IN (80, 443, 8080, 8443, 8888) AND label = 2, 12,
        dst_port IN (80, 443, 8080, 8443, 8888) AND label = 3, 13,
        dst_port IN (80, 443, 8080, 8443, 8888) AND label = 4, 14,
        dst_port IN (80, 443, 8080, 8443, 8888), 10,

        /* RDP (port 3389) */
        dst_port = 3389 AND pkts_rev = 0, 20,
        dst_port = 3389 AND label IN (0,1), 21,
        dst_port = 3389 AND label = 2, 22,
        dst_port = 3389 AND label IN (3,4), 23,
        dst_port = 3389, 20,

        /* MySQL/MSSQL (ports 3306, 1433) */
        dst_port IN (3306, 1433) AND pkts_rev = 0, 30,
        dst_port IN (3306, 1433) AND label IN (0,1), 31,
        dst_port IN (3306, 1433) AND label = 2, 32,
        dst_port IN (3306, 1433) AND label = 3, 33,
        dst_port IN (3306, 1433) AND label = 4, 34,
        dst_port IN (3306, 1433), 30,

        /* Redis (port 6379) */
        dst_port = 6379 AND pkts_rev = 0, 40,
        dst_port = 6379 AND label IN (0,1), 41,
        dst_port = 6379 AND label = 2, 42,
        dst_port = 6379 AND label IN (3,4), 43,
        dst_port = 6379, 40,

        /* SMB (ports 445, 139) */
        dst_port IN (445, 139) AND pkts_rev = 0, 50,
        dst_port IN (445, 139) AND label = 0, 51,
        dst_port IN (445, 139) AND label = 1, 52,
        dst_port IN (445, 139) AND label = 2, 53,
        dst_port IN (445, 139) AND label = 3, 54,
        dst_port IN (445, 139) AND label = 4, 55,
        dst_port IN (445, 139), 50,

        /* Unknown service */
        99
    )
    WHERE ingested_at >= %(start)s
      AND label > 0
      AND service_label = 0
    """

    ch.execute(mutation, {'start': window_start})
    total_updated = len(updates)
    log.info("Mutation submitted for %d flows", total_updated)
    return total_updated


def main():
    parser = argparse.ArgumentParser(description='Per-Service Label Mapper')
    parser.add_argument('--window-minutes', type=int, default=15)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--ch-host', default='localhost')
    args = parser.parse_args()

    ch = Client(host=args.ch_host)

    start = time.time()
    count = run_mapper(ch, args.window_minutes, args.dry_run)
    elapsed = time.time() - start

    log.info("Done in %.1fs. %d flows processed.", elapsed, count)


if __name__ == '__main__':
    main()
