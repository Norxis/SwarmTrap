#!/usr/bin/env python3
"""Conversation Brain — VLAN-aware IP judge. Sees all fruits, judges correctly.

Reads:
  - dfi.ip_score_log (GOD 1 XGB scores, split by VLAN 100=ingress / 101=egress)
  - dfi.evidence_events (honeypot host-side evidence)

Writes:
  - dfi.ip_reputation (FINAL judgment per IP — archetype + evidence + confidence)

Rule order:
  1. Tier 0: CONFIRMED_INTRUDER (sus_commands + priv_escalation = proven breach)
  2. Tier 1: Evidence (auth_success, cred_capture, heavy brute)
  3. Guard 1: Clean ingress majority (>50% clean on VLAN 100 → CLEAN_BASELINE)
  4. Guard 2: Infrastructure indicator (>50% egress → CLEAN_BASELINE)
  5. Tier 2: Model + behavioral (ingress-only, RATIO thresholds)
  6. Tier 3: Clean baseline / research
  7. Default: UNKNOWN

Spec: ai-shared/GOD_BRAIN.md (2026-04-05)

Runs on PV1 as cron :05 every 5 minutes.
Usage:
    python3 conversation_brain.py [--window-hours 2] [--dry-run]
"""
import argparse
import logging
import os
import socket
import time
from datetime import datetime
from collections import defaultdict

from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('conversation_brain')

CH_HOST = os.environ.get('CH_HOST', '127.0.0.1')

# Archetypes (matches dfi.ip_reputation conversation_archetype column)
UNKNOWN = 0
COMMODITY_BOT = 1
COORDINATED_CAMPAIGN = 2
HUMAN_OPERATOR = 3
RESEARCH_BENIGN = 4
CLEAN_BASELINE = 5
CONFIRMED_INTRUDER = 6

ARCHETYPE_NAMES = {
    0: 'UNKNOWN', 1: 'COMMODITY_BOT', 2: 'COORDINATED_CAMPAIGN',
    3: 'HUMAN_OPERATOR', 4: 'RESEARCH_BENIGN', 5: 'CLEAN_BASELINE',
    6: 'CONFIRMED_INTRUDER',
}

# Known research scanner rDNS domains
RESEARCH_DOMAINS = {
    'shodan.io', 'censys.io', 'binaryedge.io', 'shadowserver.org',
    'internet-census.org', 'stretchoid.com', 'internet-measurement.com',
    'recyber.net', 'alphastrike.io', 'onyphe.io', 'criminalip.io',
    'natlas.io', 'leakix.net', 'rapid7.com',
}

# IP reputation states
STATE_UNKNOWN = 0
STATE_DIRTY = 1
STATE_EVIDENCE = 2
STATE_RESEARCH = 3
STATE_CLEAN = 4


def is_research_scanner(ip: str) -> bool:
    """Check if IP has research scanner rDNS."""
    try:
        hostname = socket.getfqdn(ip)
        if hostname == ip:
            return False
        return any(domain in hostname.lower() for domain in RESEARCH_DOMAINS)
    except Exception:
        return False


def fetch_score_data(ch, window_hours: int) -> dict:
    """Fetch VLAN-aware aggregated score data per src_ip from ip_score_log.

    Splits counts by VLAN:
      - VLAN 100 (ingress): external → our network. XGB scores reliable. Attack signal.
      - VLAN 101 (egress):  our network → external. XGB scores unreliable. Infrastructure signal.
    """
    query = f"""
    SELECT
        toString(src_ip) as src_ip,
        count() as n_flows,

        -- VLAN 100 (ingress) — ATTACK SIGNAL, XGB reliable
        countIf(vlan_id = 100) as n_ingress,
        countIf(vlan_id = 100 AND xgb_class = 0) as ing_recon,
        countIf(vlan_id = 100 AND xgb_class = 1) as ing_knock,
        countIf(vlan_id = 100 AND xgb_class = 2) as ing_brute,
        countIf(vlan_id = 100 AND xgb_class = 3) as ing_exploit,
        countIf(vlan_id = 100 AND xgb_class = 4) as ing_clean,
        countIf(vlan_id = 100 AND xgb_class < 4) as ing_attacks,
        countIf(vlan_id = 100 AND pkts_rev > 0) as ing_replied,
        uniqIf(dst_port, vlan_id = 100) as ing_unique_ports,
        uniqIf(dst_ip, vlan_id = 100) as ing_unique_dsts,
        avgIf(xgb_confidence, vlan_id = 100) as ing_avg_conf,
        maxIf(xgb_confidence, vlan_id = 100) as ing_max_conf,

        -- VLAN 101 (egress) — INFRASTRUCTURE SIGNAL, XGB unreliable
        countIf(vlan_id = 101) as n_egress,
        countIf(vlan_id = 101 AND xgb_class = 4) as egr_clean,

        -- Timing
        min(first_ts) as first_seen,
        max(first_ts) as last_seen,
        (toUnixTimestamp(max(first_ts)) - toUnixTimestamp(min(first_ts))) / 60.0 as span_min
    FROM dfi.ip_score_log
    WHERE ingested_at >= now() - INTERVAL {window_hours} HOUR
    GROUP BY src_ip
    HAVING count() >= 2
    """
    rows = ch.execute(query, with_column_types=True)
    cols = [c[0] for c in rows[1]]
    result = {}
    for r in rows[0]:
        d = dict(zip(cols, r))
        result[d['src_ip']] = d
    log.info('Score data: %d IPs with 2+ flows in %dh window', len(result), window_hours)
    return result


def fetch_evidence(ch, window_hours: int) -> dict:
    """Fetch aggregated evidence per src_ip from evidence_events."""
    query = f"""
    SELECT
        toString(src_ip) as src_ip,
        countIf(event_type = 'auth_failure') as auth_fails,
        countIf(event_type = 'auth_success') as auth_success,
        countIf(event_type = 'credential_capture') as cred_captures,
        countIf(event_type = 'suspicious_command') as sus_commands,
        countIf(event_type = 'privilege_escalation') as priv_escalations,
        countIf(event_type = 'lateral_movement') as lateral_movements,
        countIf(event_type = 'bind_attempt') as bind_attempts,
        count() as total_events,
        uniq(target_ip) as unique_targets
    FROM dfi.evidence_events
    WHERE ts >= now() - INTERVAL {window_hours} HOUR
      AND src_ip NOT IN (
        SELECT toIPv4(arrayJoin(['172.16.3.110', '172.16.208.2', '172.16.208.3']))
      )
    GROUP BY src_ip
    """
    rows = ch.execute(query, with_column_types=True)
    cols = [c[0] for c in rows[1]]
    result = {}
    for r in rows[0]:
        d = dict(zip(cols, r))
        result[d['src_ip']] = d
    log.info('Evidence data: %d IPs with events in %dh window', len(result), window_hours)
    return result


def judge_ip(ip: str, scores: dict, evidence: dict, evidence_ip_set: set = None) -> tuple:
    """Judge an IP from all its fruits. VLAN-aware, ratio-based.

    Returns (archetype, confidence, state, reason).

    Rule order: min-flow → evidence → clean guard → infra guard → Tier 2 → Tier 3 → unknown
    """
    s = scores.get(ip, {})
    ev = evidence.get(ip, {})

    # ── Extract VLAN-aware ingress counts ────────────────────────────────
    n_flows = s.get('n_flows', 0)
    n_ingress = s.get('n_ingress', 0)
    n_egress = s.get('n_egress', 0)
    ing_recon = s.get('ing_recon', 0)
    ing_knock = s.get('ing_knock', 0)
    ing_brute = s.get('ing_brute', 0)
    ing_exploit = s.get('ing_exploit', 0)
    ing_clean = s.get('ing_clean', 0)
    ing_attacks = s.get('ing_attacks', 0)
    ing_replied = s.get('ing_replied', 0)
    ing_unique_ports = s.get('ing_unique_ports', 0)
    ing_unique_dsts = s.get('ing_unique_dsts', 0)

    # Evidence (VLAN-independent — host logs prove the attack)
    auth_fails = ev.get('auth_fails', 0)
    auth_success = ev.get('auth_success', 0)
    cred_captures = ev.get('cred_captures', 0)
    sus_commands = ev.get('sus_commands', 0)
    priv_escalations = ev.get('priv_escalations', 0)
    lateral_movements = ev.get('lateral_movements', 0)
    total_events = ev.get('total_events', 0)
    has_evidence = total_events > 0

    # Ratios (ingress only — egress XGB is unreliable)
    ingress_attack_ratio = ing_attacks / max(n_ingress, 1)
    ingress_clean_ratio = ing_clean / max(n_ingress, 1)
    egress_ratio = n_egress / max(n_flows, 1)

    # ── Tier 0: CONFIRMED INTRUDER — the real catches ─────────────────
    # Post-exploitation evidence: they got in AND did something.
    # sus_commands (service install, PowerShell, etc) + priv_escalation = proven breach.
    # This is the highest classification. XGB may score flows as clean — doesn't matter.
    if sus_commands > 0 and priv_escalations > 0:
        return (CONFIRMED_INTRUDER, 1.00, STATE_EVIDENCE,
                f"T0:INTRUDER sus_cmd={sus_commands} priv_esc={priv_escalations} "
                f"auth_fails={auth_fails}")

    if sus_commands > 0 and auth_fails > 0:
        return (CONFIRMED_INTRUDER, 0.99, STATE_EVIDENCE,
                f"T0:INTRUDER sus_cmd={sus_commands} auth_fails={auth_fails}")

    if sus_commands > 0 and lateral_movements > 0:
        return (CONFIRMED_INTRUDER, 0.99, STATE_EVIDENCE,
                f"T0:INTRUDER sus_cmd={sus_commands} lateral={lateral_movements}")

    if priv_escalations > 0 and auth_fails > 10:
        return (CONFIRMED_INTRUDER, 0.98, STATE_EVIDENCE,
                f"T0:INTRUDER priv_esc={priv_escalations} auth_fails={auth_fails}")

    # ── Tier 1: Evidence-confirmed (strong but not post-exploit) ────────
    # Evidence always wins — a confirmed breach overrides any clean ratio
    if auth_success > 0 or sus_commands > 0:
        return (COORDINATED_CAMPAIGN, 0.99, STATE_EVIDENCE,
                f"T1:confirmed breach auth_success={auth_success} sus_cmd={sus_commands}")

    if cred_captures > 0 and ing_brute > 0:
        return (COORDINATED_CAMPAIGN, 0.97, STATE_EVIDENCE,
                f"T1:cred_capture={cred_captures} ing_brute={ing_brute}")

    if auth_fails > 50 and ing_brute > 5:
        return (COMMODITY_BOT, 0.95, STATE_EVIDENCE,
                f"T1:heavy_brute auth_fails={auth_fails} ing_brute={ing_brute}")

    if auth_fails > 10 and (ing_brute > 0 or ing_knock > 5):
        return (COMMODITY_BOT, 0.93, STATE_EVIDENCE,
                f"T1:brute_evidence auth_fails={auth_fails} ing_knock={ing_knock} ing_brute={ing_brute}")

    # ── Guard 1: Clean ingress majority ──────────────────────────────────
    # If >50% of INGRESS flows are clean AND no evidence (2h OR 30d), not an attacker.
    # Evidence always wins — an IP with auth_failures is an attacker even if XGB says clean.
    has_any_evidence = has_evidence or (evidence_ip_set and ip in evidence_ip_set)
    if n_ingress >= 3 and ingress_clean_ratio > 0.50 and not has_any_evidence:
        return (CLEAN_BASELINE, 0.85, STATE_CLEAN,
                f"clean_guard: ingress {ing_clean}/{n_ingress}={ingress_clean_ratio:.1%} clean")

    # ── Guard 2: Infrastructure indicator (high egress ratio) ───────────
    # If >50% of ALL flows are egress (VLAN 101) and low ingress AND no evidence
    if egress_ratio > 0.50 and n_ingress < 100 and not has_any_evidence:
        return (CLEAN_BASELINE, 0.80, STATE_CLEAN,
                f"infra_guard: egress_ratio={egress_ratio:.1%} n_ingress={n_ingress}")

    # ── Tier 2: Model + behavioral (INGRESS ONLY, RATIO thresholds) ────
    # All counts from VLAN 100. No raw-count thresholds without ratios.
    if n_ingress < 3:
        # Not enough ingress data for model-based judgment
        if has_evidence:
            # Has some evidence but didn't meet Tier 1 thresholds
            return (UNKNOWN, 0.50, STATE_UNKNOWN,
                    f"low_ingress_with_evidence: n_ingress={n_ingress} events={total_events}")
        return (UNKNOWN, 0.50, STATE_UNKNOWN,
                f"insufficient_ingress: n_ingress={n_ingress}")

    if ing_exploit > 0 and ing_replied > 0 and ingress_attack_ratio > 0.10:
        return (COORDINATED_CAMPAIGN, 0.90, STATE_DIRTY,
                f"T2:exploit={ing_exploit} replied={ing_replied} ratio={ingress_attack_ratio:.2f}")

    if ing_unique_ports > 20 and n_ingress > 0 and ing_recon / n_ingress > 0.30:
        return (COMMODITY_BOT, 0.90, STATE_DIRTY,
                f"T2:wide_scan ports={ing_unique_ports} recon_ratio={ing_recon / n_ingress:.2f}")

    if ing_unique_dsts > 5 and ing_attacks > 10 and ingress_attack_ratio > 0.50:
        return (COMMODITY_BOT, 0.88, STATE_DIRTY,
                f"T2:multi_target dsts={ing_unique_dsts} attacks={ing_attacks} ratio={ingress_attack_ratio:.2f}")

    if ing_brute > 3 and ing_replied > 0 and ingress_attack_ratio > 0.30:
        return (COMMODITY_BOT, 0.85, STATE_DIRTY,
                f"T2:brute_active brute={ing_brute} replied={ing_replied} ratio={ingress_attack_ratio:.2f}")

    if ing_unique_ports > 10 and n_ingress > 0 and ing_recon / n_ingress > 0.20:
        return (COMMODITY_BOT, 0.82, STATE_DIRTY,
                f"T2:scanner ports={ing_unique_ports} recon_ratio={ing_recon / n_ingress:.2f}")

    if ing_attacks > 5 and ingress_attack_ratio > 0.70 and ing_replied == 0:
        return (COMMODITY_BOT, 0.80, STATE_DIRTY,
                f"T2:blind_scanner attacks={ing_attacks} ratio={ingress_attack_ratio:.2f} no_reply")

    # ── Tier 3: Clean (no ingress attacks, no evidence) ─────────────────
    if ing_attacks == 0 and total_events == 0 and n_ingress >= 5:
        return (CLEAN_BASELINE, 0.85, STATE_CLEAN,
                f"T3:clean ingress={n_ingress} zero_attacks zero_evidence")

    # Mostly clean egress IP with very few ingress
    if ing_attacks == 0 and total_events == 0 and n_egress >= 5:
        return (CLEAN_BASELINE, 0.80, STATE_CLEAN,
                f"T3:clean_egress egress={n_egress} zero_ing_attacks")

    # ── Tier 3: Research scanners (rDNS check — only for remaining unknowns) ──
    if os.environ.get('GOD2_RDNS') == '1' and ing_attacks > 0 and ing_attacks < 10:
        if is_research_scanner(ip):
            return (RESEARCH_BENIGN, 0.95, STATE_RESEARCH, "T3:research_rdns")

    # ── Unknown ────────────────────────────────────────────────────────
    return (UNKNOWN, 0.50, STATE_UNKNOWN,
            f"insufficient: flows={n_flows} ing={n_ingress} egr={n_egress} "
            f"ing_attacks={ing_attacks} evidence={total_events}")


# IP group → state mapping
GROUP_STATE = {
    'dirty': STATE_DIRTY,    # 1
    'clean': STATE_CLEAN,    # 4
    'unknown': STATE_UNKNOWN, # 0
}
# score_direction: 1=dirty (attack>50%), 2=clean (clean>50%), 0=unknown
GROUP_DIRECTION = {'dirty': 1, 'clean': 2, 'unknown': 0}


def write_reputation(ch, judgments: list, allowlist_ips: set = None, research_ips: set = None, dry_run: bool = False):
    """Write conversation-brain judgments to ip_reputation."""
    if not judgments:
        return
    if allowlist_ips is None:
        allowlist_ips = set()
    if research_ips is None:
        research_ips = set()

    rows = []
    now = datetime.utcnow()
    for ip, archetype, confidence, state, reason, scores_data, ev_data, ip_group in judgments:
        s = scores_data or {}
        ev = ev_data or {}

        # State: evidence overrides group, group overrides archetype default
        if ev.get('total_events', 0) > 0:
            final_state = STATE_EVIDENCE
        else:
            final_state = GROUP_STATE.get(ip_group, state)

        # Best XGB class from INGRESS score distribution (not egress noise)
        if s.get('ing_recon', 0) > 0: best_class = 0
        elif s.get('ing_knock', 0) > 0: best_class = 1
        elif s.get('ing_brute', 0) > 0: best_class = 2
        elif s.get('ing_exploit', 0) > 0: best_class = 3
        else: best_class = 4

        rows.append({
            'src_ip': ip,
            'state': final_state,
            'last_seen': now,
            'updated_at': now,
            'has_any_evidence': 1 if ev.get('total_events', 0) > 0 else 0,
            'best_xgb_class': best_class,
            'best_xgb_confidence': float(s.get('ing_max_conf', 0) or 0),
            'conversation_archetype': archetype,
            'label_source': 4,  # HEURISTIC
            'label_confidence': confidence,
            'total_flows': s.get('n_flows', 0),
            'unique_ports': s.get('ing_unique_ports', 0),
            'unique_dsts': s.get('ing_unique_dsts', 0),
            'score_direction': GROUP_DIRECTION.get(ip_group, 0),
            'is_clean_allowlist': 1 if ip in allowlist_ips else 0,
            'is_research_benign': 1 if ip in research_ips else 0,
            'watchlist_source': 'conversation_brain',
        })

    if dry_run:
        log.info('[DRY RUN] Would write %d ip_reputation rows', len(rows))
        for ip, arch, conf, state, reason, _, _, grp in judgments[:20]:
            log.info('  %s → %s (%.2f) [%s] %s',
                     ip, ARCHETYPE_NAMES.get(arch, '?'), conf, grp, reason)
        return

    try:
        ch.execute(
            '''INSERT INTO dfi.ip_reputation
               (src_ip, state, last_seen, updated_at, has_any_evidence,
                best_xgb_class, best_xgb_confidence, conversation_archetype,
                label_source, label_confidence, total_flows,
                unique_ports, unique_dsts, score_direction, is_clean_allowlist,
                is_research_benign, watchlist_source)
               VALUES''',
            rows
        )
        log.info('ip_reputation: wrote %d rows (source=conversation_brain)', len(rows))
    except Exception as e:
        log.error('CH write failed: %s', e)


def main():
    parser = argparse.ArgumentParser(description='Conversation Brain (VLAN-aware)')
    parser.add_argument('--window-hours', type=int, default=2, help='Lookback window (hours)')
    parser.add_argument('--dry-run', action='store_true', help='Log judgments without writing')
    args = parser.parse_args()

    ch = Client(CH_HOST)
    start = time.time()

    # Fetch existing allowlist + research IPs so we preserve flags through writes
    allowlist_ips = set()
    research_ips = set()
    try:
        rows = ch.execute("SELECT toString(src_ip) FROM dfi.ip_reputation FINAL WHERE is_clean_allowlist = 1")
        allowlist_ips = {r[0] for r in rows}
        rows = ch.execute("SELECT toString(src_ip) FROM dfi.ip_reputation FINAL WHERE is_research_benign = 1")
        research_ips = {r[0] for r in rows}
        if allowlist_ips or research_ips:
            log.info('Preserved flags: allowlist=%d research=%d', len(allowlist_ips), len(research_ips))
    except Exception as e:
        log.warning('Failed to fetch preserved flags: %s', e)

    # Fetch all fruits
    scores = fetch_score_data(ch, args.window_hours)
    evidence = fetch_evidence(ch, args.window_hours)

    # 30-day evidence IP set — for clean guard only (blocks clean label on old attackers)
    evidence_ip_set = set()
    try:
        rows = ch.execute("SELECT DISTINCT toString(src_ip) FROM dfi.evidence_events WHERE ts >= now() - INTERVAL 30 DAY")
        evidence_ip_set = {r[0] for r in rows}
        log.info('Evidence IP set (30d): %d IPs', len(evidence_ip_set))
    except Exception as e:
        log.warning('Failed to fetch evidence IP set: %s', e)

    # All IPs from both sources
    all_ips = set(scores.keys()) | set(evidence.keys())
    log.info('Total unique IPs to judge: %d', len(all_ips))

    # Judge each IP
    judgments = []
    archetype_counts = defaultdict(int)
    group_counts = defaultdict(int)
    for ip in all_ips:
        archetype, confidence, state, reason = judge_ip(ip, scores, evidence, evidence_ip_set)
        archetype_counts[archetype] += 1

        # Dirty/Clean group — based on INGRESS attack ratio
        s = scores.get(ip)
        ip_group = 'unknown'
        if s and s['n_ingress'] >= 3:
            ing_attack_ratio = s['ing_attacks'] / s['n_ingress']
            if ing_attack_ratio > 0.5:
                ip_group = 'dirty'
            else:
                ip_group = 'clean'
        group_counts[ip_group] += 1

        # Write all judged IPs (not just non-UNKNOWN)
        if archetype != UNKNOWN or ip_group != 'unknown':
            judgments.append((ip, archetype, confidence, state, reason,
                              scores.get(ip), evidence.get(ip), ip_group))

    # Log summary
    for arch, count in sorted(archetype_counts.items()):
        log.info('  %s: %d IPs', ARCHETYPE_NAMES.get(arch, '?'), count)
    log.info('  Groups: dirty=%d clean=%d unknown=%d',
             group_counts['dirty'], group_counts['clean'], group_counts['unknown'])

    # Write to ip_reputation
    write_reputation(ch, judgments, allowlist_ips=allowlist_ips, research_ips=research_ips, dry_run=args.dry_run)

    elapsed = time.time() - start
    log.info('Done in %.1fs — %d IPs judged, %d written to ip_reputation',
             elapsed, len(all_ips), len(judgments))


if __name__ == '__main__':
    main()
