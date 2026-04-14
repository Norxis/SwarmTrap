#!/usr/bin/env python3
"""GOD 2 Brain — builds per-IP attacker profiles, assigns verdict groups, writes ip_profile.

Replaces: conversation_brain.py, god2_verdict.py, ip_reputation_builder.py,
          service_labeler.py, service_label_mapper.py

Reads:
  - dfi.ip_score_log (2h) — active IPs, services, XGB scores, flow stats
  - dfi.evidence_events (30d) — honeypot evidence per IP
  - dfi.ip_service_labels — behavioral class per IP per service
  - dfi.ip_capture_d2 — current capture counts per verdict_group

Writes:
  - dfi.ip_profile — one row per IP (full profile + verdict)
  - /opt/dfi-hunter/watchlist.db — DROP IPs for MikroTik sync

Runs on PV1 as cron every 5 minutes.
Usage:
    python3 god2_brain.py [--window-hours 2] [--dry-run]
"""
import argparse
import fnmatch
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('god2_brain')

CH_HOST = os.environ.get('CH_HOST', '127.0.0.1')
BUDGET_PATH = os.environ.get('GOD2_BUDGETS', '/opt/dfi2/god2_budgets.json')
WATCHLIST_DB = '/opt/dfi-hunter/watchlist.db'
DROP_TTL_DAYS = 7

# Import shared constants
import sys
sys.path.insert(0, os.path.dirname(__file__))
from constants import (
    SERVICE_MAP, SVC_NAMES, CLASS_NAMES, BCLASS_NAMES, bclass_name,
    RB_ALLOWLIST, V_NONE, V_CAPTURE, V_DONE, V_DROP,
)

# Reverse port→service for quick lookup
PORT_TO_SVC = SERVICE_MAP


# ══════════════════════════════════════════════════════════════════════
# Phase 1: Build Profiles
# ══════════════════════════════════════════════════════════════════════

def query_score_aggregates(ch, window_hours):
    """Per-IP aggregates from ip_score_log."""
    rows = ch.execute(f"""
        SELECT
            toString(src_ip),
            count() as n_flows,
            groupUniqArrayIf(dst_port, vlan_id = 100) as ing_ports,
            uniqIf(dst_ip, vlan_id = 100) as unique_dsts,
            uniqIf(dst_port, vlan_id = 100) as unique_ports,
            countIf(vlan_id = 100) as n_ingress,
            countIf(vlan_id = 100 AND xgb_class = 0) as ing_recon,
            countIf(vlan_id = 100 AND xgb_class = 1) as ing_knock,
            countIf(vlan_id = 100 AND xgb_class = 2) as ing_brute,
            countIf(vlan_id = 100 AND xgb_class = 3) as ing_exploit,
            countIf(vlan_id = 100 AND xgb_class = 4) as ing_clean,
            min(first_ts) as first_seen,
            max(first_ts) as last_seen
        FROM dfi.ip_score_log
        WHERE ingested_at >= now() - INTERVAL {window_hours} HOUR
        GROUP BY src_ip
        HAVING n_flows >= 2
    """)
    result = {}
    for r in rows:
        ip = r[0]
        ing_ports = r[2]  # Array of dst_ports on ingress
        # Derive services from ingress ports
        svcs = set()
        for port in ing_ports:
            svc = PORT_TO_SVC.get(port)
            if svc:
                svcs.add(svc)

        n_ingress = r[5]
        ing_clean = r[10]
        clean_ratio = ing_clean / max(n_ingress, 1)

        # Best XGB class: most common non-clean ingress class
        class_counts = {0: r[6], 1: r[7], 2: r[8], 3: r[9]}
        attack_classes = {k: v for k, v in class_counts.items() if v > 0}
        if attack_classes:
            best_xgb = max(attack_classes, key=attack_classes.get)
        elif ing_clean > 0:
            best_xgb = 4
        else:
            best_xgb = 255

        result[ip] = {
            'n_flows': r[1],
            'services': sorted(svcs),
            'unique_dsts': r[3],
            'unique_ports': r[4],
            'n_ingress': n_ingress,
            'best_xgb_class': best_xgb,
            'clean_ratio': clean_ratio,
            'first_seen': r[11],
            'last_seen': r[12],
        }
    log.info('Score aggregates: %d IPs in %dh window', len(result), window_hours)
    return result


def query_evidence_aggregates(ch):
    """Per-IP evidence aggregates from evidence_events (30d)."""
    rows = ch.execute("""
        SELECT
            toString(src_ip),
            count() as total,
            uniq(target_ip) as unique_targets,
            groupUniqArray(source_program) as programs,
            countIf(event_type = 'auth_failure') as auth_fails,
            countIf(event_type = 'auth_success') as auth_success,
            countIf(event_type = 'credential_capture') as cred_capture,
            countIf(event_type = 'suspicious_command') as sus_command,
            countIf(event_type = 'privilege_escalation') as priv_esc,
            countIf(event_type = 'lateral_movement') as lateral,
            countIf(event_type = 'bind_attempt') as bind,
            countIf(event_type = 'sql_injection') as sql_inject
        FROM dfi.evidence_events
        WHERE ts >= now() - INTERVAL 30 DAY
          AND src_ip NOT IN (
            SELECT toIPv4(arrayJoin(['172.16.3.110', '172.16.208.2', '172.16.208.3']))
          )
        GROUP BY src_ip
    """)
    result = {}
    for r in rows:
        ip = r[0]
        # Build evidence type bitmask
        mask = 0
        if r[4] > 0: mask |= 1    # auth_fail
        if r[5] > 0: mask |= 2    # auth_success
        if r[6] > 0: mask |= 4    # cred_capture
        if r[7] > 0: mask |= 8    # sus_command
        if r[8] > 0: mask |= 16   # priv_esc
        if r[9] > 0: mask |= 32   # lateral
        if r[10] > 0: mask |= 64  # bind
        if r[11] > 0: mask |= 128 # sql_inject

        # Derive evidence services from source_program
        programs = r[3]
        evd_svcs = set()
        for prog in programs:
            p = prog.lower()
            if 'ssh' in p or 'sshd' in p: evd_svcs.add(1)
            if 'http' in p or 'apache' in p or 'nginx' in p or 'web' in p: evd_svcs.add(2)
            if 'rdp' in p or 'xrdp' in p or 'termsrv' in p: evd_svcs.add(3)
            if 'sql' in p or 'mysql' in p or 'mssql' in p or 'postgres' in p: evd_svcs.add(4)
            if 'smb' in p or 'samba' in p or 'cifs' in p: evd_svcs.add(5)

        result[ip] = {
            'total': r[1],
            'unique_targets': r[2],
            'type_mask': mask,
            'services': sorted(evd_svcs),
            'auth_fails': r[4],
            'auth_success': r[5],
            'cred_capture': r[6],
            'sus_command': r[7],
            'priv_esc': r[8],
        }
    log.info('Evidence aggregates: %d IPs (30d)', len(result))
    return result


def query_service_labels(ch):
    """Per-IP per-service behavioral class from ip_service_labels."""
    rows = ch.execute("""
        SELECT toString(src_ip), service_id, service_class
        FROM dfi.ip_service_labels FINAL
        WHERE service_class < 255
    """)
    result = {}  # ip -> {service_id: class}
    for ip, svc, cls in rows:
        if ip not in result:
            result[ip] = {}
        result[ip][svc] = cls
    log.info('Service labels: %d IPs', len(result))
    return result


def build_profiles(scores, evidence, svc_labels):
    """Merge all sources into per-IP profiles."""
    all_ips = set(scores) | set(evidence)
    profiles = {}
    for ip in all_ips:
        s = scores.get(ip, {})
        e = evidence.get(ip, {})
        sl = svc_labels.get(ip, {})

        # Merge services from ALL sources (scores + evidence + ip_service_labels)
        svcs_from_scores = s.get('services', [])
        svcs_from_evidence = e.get('services', [])
        svcs_from_labels = list(sl.keys()) if sl else []
        all_svcs = sorted(set(svcs_from_scores) | set(svcs_from_evidence) | set(svcs_from_labels))

        # Build parallel service_classes array
        svc_classes = []
        for svc in all_svcs:
            cls = sl.get(svc, 255)
            svc_classes.append(cls)

        profiles[ip] = {
            'src_ip': ip,
            'services': all_svcs,
            'service_classes': svc_classes,
            'evidence_count': e.get('total', 0),
            'evidence_services': e.get('services', []),
            'evidence_types': e.get('type_mask', 0),
            'unique_dsts': s.get('unique_dsts', 0),
            'unique_ports': s.get('unique_ports', 0),
            'total_flows': s.get('n_flows', 0),
            'first_seen': s.get('first_seen'),
            'last_seen': s.get('last_seen'),
            'best_xgb_class': s.get('best_xgb_class', 255),
            'xgb_clean_ratio': s.get('clean_ratio', 0.0),
            # Verdict fields (filled in Phase 2+3)
            'verdict': V_NONE,
            'verdict_group': '',
            'verdict_expires': None,
        }
    log.info('Profiles built: %d IPs', len(profiles))
    return profiles


# ══════════════════════════════════════════════════════════════════════
# Phase 2: Assign Verdict Groups
# ══════════════════════════════════════════════════════════════════════

def assign_groups(profiles):
    """Assign a verdict_group to each profile based on priority."""
    group_counts = defaultdict(int)

    for ip, p in profiles.items():
        has_evidence = p['evidence_count'] > 0
        services = p['services']
        best_xgb = p['best_xgb_class']
        clean_ratio = p['xgb_clean_ratio']
        evd_types = p['evidence_types']

        # --- RB: known infrastructure / research ---
        if ip in RB_ALLOWLIST:
            p['verdict_group'] = 'RB'
            group_counts['RB'] += 1
            continue

        # --- Priority 1: Discrepancy (model wrong) ---
        # False negative: model says clean, evidence says attack
        if best_xgb == 4 and has_evidence:
            svc = services[0] if services else 0
            p['verdict_group'] = f"DIS_FN_{SVC_NAMES.get(svc, 'UNK')}_EVD"
            group_counts[p['verdict_group']] += 1
            continue

        # False positive: model says attack, but no evidence + clean ratio > 80%
        # GUARD: scanners (>=100 unique ports or >=50 dsts) are NOT false positives
        if best_xgb < 4 and not has_evidence and clean_ratio > 0.80 \
                and p['unique_ports'] < 100 and p['unique_dsts'] < 50:
            svc = services[0] if services else 0
            p['verdict_group'] = f"DIS_FP_{SVC_NAMES.get(svc, 'UNK')}"
            group_counts[p['verdict_group']] += 1
            continue

        # Misclassification: XGB class != evidence class for a service
        if has_evidence and services:
            for i, svc in enumerate(services):
                evd_class = p['service_classes'][i] if i < len(p['service_classes']) else 255
                if evd_class < 255 and best_xgb < 4 and best_xgb != evd_class:
                    cls_name = bclass_name(svc, evd_class)
                    p['verdict_group'] = f"DIS_MISCLASS_{SVC_NAMES.get(svc, 'UNK')}_{cls_name}"
                    group_counts[p['verdict_group']] += 1
                    break
            if p['verdict_group']:
                continue

        # --- Priority 2: Evidence-backed ---
        if has_evidence:
            if len(services) >= 2:
                svc_str = '_'.join(SVC_NAMES.get(s, str(s)) for s in services[:3])
                p['verdict_group'] = f"MULTI_{svc_str}_EVD"
            elif services:
                svc = services[0]
                cls = p['service_classes'][0] if p['service_classes'] else 255
                cls_name = bclass_name(svc, cls) if cls < 255 else 'SCAN'
                p['verdict_group'] = f"{SVC_NAMES.get(svc, 'UNK')}_{cls_name}_EVD"
            else:
                p['verdict_group'] = 'UNK_EVD'
            group_counts[p['verdict_group']] += 1
            continue

        # --- Priority 3: DIR (dirty — no evidence, attack signal) ---
        # Scanners first: high port/dst count = recon regardless of service mapping
        if p['unique_ports'] >= 100 or p['unique_dsts'] >= 50:
            p['verdict_group'] = 'SCAN_DIR'
            group_counts['SCAN_DIR'] += 1
            continue

        # Service-targeted dirty flows
        if best_xgb < 4 and services:
            if len(services) >= 2:
                svc_str = '_'.join(SVC_NAMES.get(s, str(s)) for s in services[:3])
                p['verdict_group'] = f"MULTI_{svc_str}_DIR"
            else:
                svc = services[0]
                p['verdict_group'] = f"{SVC_NAMES.get(svc, 'UNK')}_DIR"
            group_counts[p['verdict_group']] += 1
            continue

        # Non-service dirty (attack XGB class, no mapped service, few ports)
        if best_xgb < 4:
            p['verdict_group'] = 'UNK_DIR'
            group_counts['UNK_DIR'] += 1
            continue

        # --- Clean ---
        if not has_evidence and clean_ratio > 0.90:
            p['verdict_group'] = 'CLN'
            group_counts['CLN'] += 1
            continue

        # --- Unknown ---
        p['verdict_group'] = 'UNK'
        group_counts['UNK'] += 1

    log.info('Groups assigned: %s', dict(sorted(group_counts.items(), key=lambda x: -x[1])[:20]))
    return profiles


# ══════════════════════════════════════════════════════════════════════
# Phase 3: Decide Verdicts
# ══════════════════════════════════════════════════════════════════════

def load_budgets():
    """Load per-group capture targets from JSON config."""
    try:
        with open(BUDGET_PATH) as f:
            budgets = json.load(f)
        # Remove comments
        return {k: v for k, v in budgets.items() if not k.startswith('_comment')}
    except Exception as e:
        log.warning('Failed to load budgets from %s: %s — using defaults', BUDGET_PATH, e)
        return {'_DEFAULT': 1000000}


def get_budget_target(group, budgets):
    """Get target for a group. Exact match first, then wildcard, then _DEFAULT."""
    if group in budgets:
        return budgets[group]
    # Wildcard match
    for pattern, target in budgets.items():
        if '*' in pattern and fnmatch.fnmatch(group, pattern):
            return target
    return budgets.get('_DEFAULT', 100000)


def query_capture_counts(ch):
    """Current row counts per verdict_group in ip_capture_d2."""
    rows = ch.execute("""
        SELECT discrepancy_type, count()
        FROM dfi.ip_capture_d2
        GROUP BY discrepancy_type
    """)
    return {r[0]: r[1] for r in rows}


# Per-IP capture cap — prevents heavy hitters from dominating the dataset
IP_CAPTURE_CAP = int(os.environ.get('GOD2_IP_CAP', '10000'))


def query_ip_capture_counts(ch):
    """Current row counts per src_ip in ip_capture_d2. Only IPs over half the cap."""
    rows = ch.execute(f"""
        SELECT toString(src_ip), count() AS n
        FROM dfi.ip_capture_d2
        GROUP BY src_ip
        HAVING n >= {IP_CAPTURE_CAP // 2}
    """)
    return {r[0]: r[1] for r in rows}


def decide_verdicts(profiles, budgets, current_counts, ip_counts):
    """Set verdict=CAPTURE or DROP based on budget + per-IP cap."""
    now = datetime.now(tz=timezone.utc)
    expires = now + timedelta(days=DROP_TTL_DAYS)
    verdict_summary = defaultdict(int)
    ip_capped = 0

    for ip, p in profiles.items():
        group = p['verdict_group']
        if not group or group == 'UNK':
            p['verdict'] = V_NONE
            continue

        target = get_budget_target(group, budgets)
        current = current_counts.get(group, 0)

        # Groups that should NEVER be dropped (clean/FP/research — not attackers)
        never_drop = group.startswith('DIS_FP') or group in ('CLN', 'RB')

        if target == 0 and not never_drop:
            # Explicitly disabled — DROP (attackers only)
            p['verdict'] = V_DROP
            p['verdict_expires'] = expires
        elif current < target:
            # Budget allows capture — check per-IP cap
            ip_d2 = ip_counts.get(ip, 0)
            if ip_d2 >= IP_CAPTURE_CAP:
                # Enough samples from this IP — stop capturing, keep scoring
                p['verdict'] = V_DONE
                p['verdict_expires'] = expires
                ip_capped += 1
            else:
                p['verdict'] = V_CAPTURE
                p['verdict_expires'] = expires
        elif never_drop:
            # Budget full but NOT an attacker — just stop capturing, don't drop
            p['verdict'] = V_NONE
        else:
            # Budget full, attacker — DROP
            p['verdict'] = V_DROP
            p['verdict_expires'] = expires

        verdict_summary[f"{p['verdict']}:{group}"] += 1

    caps = sum(1 for p in profiles.values() if p['verdict'] == V_CAPTURE)
    dones = sum(1 for p in profiles.values() if p['verdict'] == V_DONE)
    drops = sum(1 for p in profiles.values() if p['verdict'] == V_DROP)
    nones = sum(1 for p in profiles.values() if p['verdict'] == V_NONE)
    log.info('Verdicts: CAPTURE=%d DONE=%d DROP=%d NONE=%d (ip_capped=%d, cap=%d)',
             caps, dones, drops, nones, ip_capped, IP_CAPTURE_CAP)
    # Log top groups
    for key in sorted(verdict_summary, key=verdict_summary.get, reverse=True)[:15]:
        log.info('  %s: %d', key, verdict_summary[key])
    return profiles


# ══════════════════════════════════════════════════════════════════════
# Phase 4: Write
# ══════════════════════════════════════════════════════════════════════

def write_ip_profile(ch, profiles, dry_run=False):
    """Write all profiles with verdict != NONE to ip_profile.
    Also writes NONE for never_drop groups to overwrite stale DROP rows."""
    now = datetime.now(tz=timezone.utc)
    rows = []
    for ip, p in profiles.items():
        if p['verdict'] == V_NONE:
            # Still write NONE for never_drop groups to clear stale DROPs
            grp = p.get('verdict_group', '')
            if not (grp.startswith('DIS_FP') or grp in ('CLN', 'RB')):
                continue
        rows.append({
            'src_ip': ip,
            'services': p['services'],
            'service_classes': p['service_classes'],
            'evidence_count': p['evidence_count'],
            'evidence_services': p['evidence_services'],
            'evidence_types': p['evidence_types'],
            'unique_dsts': p['unique_dsts'],
            'unique_ports': p['unique_ports'],
            'total_flows': p['total_flows'],
            'first_seen': p['first_seen'] or now,
            'last_seen': p['last_seen'] or now,
            'best_xgb_class': p['best_xgb_class'],
            'xgb_clean_ratio': float(p['xgb_clean_ratio']),
            'verdict': p['verdict'],
            'verdict_group': p['verdict_group'],
            'verdict_expires': p['verdict_expires'] or now,
            'updated_at': now,
        })

    if dry_run:
        log.info('[DRY RUN] Would write %d ip_profile rows', len(rows))
        return

    if not rows:
        log.info('No profiles to write')
        return

    try:
        ch.execute('INSERT INTO dfi.ip_profile VALUES', rows)
        log.info('ip_profile: wrote %d rows', len(rows))
    except Exception as e:
        log.error('ip_profile write failed: %s', e)


def write_edge_drops(profiles, dry_run=False):
    """Edge blocking: write CONFIRMED ATTACKERS to watchlist.db → MikroTik.

    COMPLETELY INDEPENDENT of capture budgets.
    Criteria: has honeypot evidence + attacker group (not CLN/RB/DIS_FP).
    This runs every cycle — confirmed attackers get blocked immediately.
    """
    attackers = []
    for p in profiles.values():
        if p['evidence_count'] <= 0:
            continue  # No evidence = not confirmed = don't block
        grp = p.get('verdict_group', '')
        if not grp:
            continue
        # Never block clean/research/false-positive IPs
        if grp.startswith('DIS_FP') or grp in ('CLN', 'RB', 'UNK'):
            continue
        attackers.append(p)

    if not attackers:
        log.info('Edge drops: 0 confirmed attackers')
        return

    if dry_run:
        log.info('[DRY RUN] Edge drops: %d confirmed attackers → watchlist', len(attackers))
        return

    try:
        con = sqlite3.connect(WATCHLIST_DB)
        now_ts = time.time()
        expires = now_ts + DROP_TTL_DAYS * 86400
        rows = [
            (p['src_ip'], 1, 2, 'god2', f"GOD2:{p['verdict_group']}:evd={p['evidence_count']}", expires, now_ts)
            for p in attackers
        ]
        con.executemany(
            '''INSERT INTO watchlist (src_ip, capture_depth, priority, source, reason, expires_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(src_ip) DO UPDATE SET
                 capture_depth = excluded.capture_depth,
                 priority = excluded.priority,
                 source = excluded.source,
                 reason = excluded.reason,
                 expires_at = excluded.expires_at,
                 updated_at = excluded.updated_at''',
            rows
        )
        con.commit()
        con.close()
        log.info('Edge drops: %d confirmed attackers → watchlist (evidence-based, budget-independent)', len(rows))
    except Exception as e:
        log.error('Edge drops write failed: %s', e)


# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='GOD 2 Brain')
    parser.add_argument('--window-hours', type=int, default=2)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    ch = Client(CH_HOST)
    start = time.time()

    # Phase 1: Build profiles
    scores = query_score_aggregates(ch, args.window_hours)
    evidence = query_evidence_aggregates(ch)
    svc_labels = query_service_labels(ch)
    profiles = build_profiles(scores, evidence, svc_labels)

    # Phase 2: Assign groups
    profiles = assign_groups(profiles)

    # Phase 3: Decide verdicts
    budgets = load_budgets()
    current_counts = query_capture_counts(ch)
    ip_counts = query_ip_capture_counts(ch)
    log.info('Per-IP counts: %d IPs over %d threshold', len(ip_counts), IP_CAPTURE_CAP // 2)
    profiles = decide_verdicts(profiles, budgets, current_counts, ip_counts)

    # Phase 4: Write
    write_ip_profile(ch, profiles, dry_run=args.dry_run)

    # Edge blocking: confirmed attackers → watchlist → MikroTik
    # INDEPENDENT of capture budgets. Evidence = attacker = block.
    write_edge_drops(profiles, dry_run=args.dry_run)

    elapsed = time.time() - start
    log.info('Done in %.1fs — %d IPs profiled', elapsed, len(profiles))


if __name__ == '__main__':
    main()
