#!/usr/bin/env python3
"""GOD 2 — Verdict Writer + Discrepancy Capture.

Runs on PV1 via cron at :08 (every 5min).
Two verdict types:
  DROP    → commodity bots, coordinated campaigns (archetypes 1,2,3)
  CAPTURE → discrepancy IPs for D2 training data (3 types: ATK, FP, RB)

Writes verdicts to ClickHouse (ip_reputation) and watchlist.db.
GOD 1 reads verdicts directly from ClickHouse — no NATS needed.

Spec: ai-shared/GOD_BRAIN.md
"""
import logging
import os
import time
from datetime import datetime

from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('god2_verdict')

CH_HOST = os.environ.get('CH_HOST', '127.0.0.1')

MIN_CONFIDENCE = float(os.environ.get('GOD2_MIN_CONF', '0.80'))
WINDOW_HOURS = int(os.environ.get('GOD2_WINDOW', '1'))

# ── DROP: commodity bots + coordinated campaigns (NOT confirmed intruders) ──
# IMPORTANT: score_direction is owned by conversation_brain.py ONLY.
# Values: 0=unknown, 1=dirty (attack>50%), 2=clean (clean>50%).
# Never write score_direction from god2_verdict or other scripts.
# The != 2 check below prevents dropping clean-group IPs.
SETTLED_QUERY = """
SELECT
    src_ip, best_xgb_class, best_xgb_confidence, total_flows,
    has_any_evidence, state, conversation_archetype
FROM dfi.ip_reputation FINAL
WHERE updated_at >= now() - INTERVAL {window} HOUR
  AND is_clean_allowlist = 0
  AND is_research_benign = 0
  AND score_direction != 2
  AND watchlist_source = 'conversation_brain'
  AND conversation_archetype IN (1, 2, 3)
  AND label_confidence >= {min_conf}
ORDER BY has_any_evidence DESC, label_confidence DESC
"""

# ── D2-ATK: confirmed intruders (model=clean, truth=attack) ────────────────
CAPTURE_ATK_QUERY = """
SELECT
    src_ip, best_xgb_class, best_xgb_confidence, total_flows,
    has_any_evidence, conversation_archetype
FROM dfi.ip_reputation FINAL
WHERE updated_at >= now() - INTERVAL {window} HOUR
  AND watchlist_source = 'conversation_brain'
  AND conversation_archetype = 6
  AND label_confidence >= 0.98
"""

# ── D2-FP: known clean IPs with attack scores (model=attack, truth=clean) ──
CAPTURE_FP_QUERY = """
SELECT
    src_ip, best_xgb_class, best_xgb_confidence, total_flows,
    conversation_archetype
FROM dfi.ip_reputation FINAL
WHERE updated_at >= now() - INTERVAL {window} HOUR
  AND is_clean_allowlist = 1
  AND best_xgb_class < 4
"""

# ── D2-RB: research scanners (model=attack, truth=research benign) ─────────
CAPTURE_RB_QUERY = """
SELECT
    src_ip, best_xgb_class, best_xgb_confidence, total_flows,
    conversation_archetype
FROM dfi.ip_reputation FINAL
WHERE updated_at >= now() - INTERVAL {window} HOUR
  AND (is_research_benign = 1 OR conversation_archetype = 4)
  AND best_xgb_class < 4
"""

RECENT_VERDICTS_QUERY = """
SELECT DISTINCT src_ip
FROM dfi.ip_reputation
WHERE capture_depth = 0
  AND updated_at >= now() - INTERVAL 1 DAY
"""

RECENT_CAPTURES_QUERY = """
SELECT DISTINCT toString(src_ip)
FROM dfi.ip_capture_d2
WHERE captured_at >= now() - INTERVAL 1 HOUR
  AND discrepancy_type IN ('PRI', 'CLN', 'RB')
"""

SERVICE_NAMES = {1: 'SSH', 2: 'HTTP', 3: 'RDP', 4: 'SQL', 5: 'SMB'}

ARCHETYPE_NAMES = {
    1: 'COMMODITY_BOT', 2: 'COORDINATED_CAMPAIGN', 3: 'HUMAN_OPERATOR',
    6: 'CONFIRMED_INTRUDER',
}

# ── Budget Manager ────────────────────────────────────────────────────────────
GROUP_TARGET = 100_000   # 100K flows per service×class group

# Budget limits per archetype per service  {archetype: {service_id: limit}}
BUDGET_LIMITS = {
    6: {1: 1000, 2: 1000, 3: 1000, 4: 1000, 5: 1000},   # CONFIRMED_INTRUDER
    3: {1: 500,  2: 2000, 3: 500,  4: 1000, 5: 1000},    # HUMAN_OPERATOR
    2: {1: 200,  2: 500,  3: 200,  4: 300,  5: 300},      # COORDINATED_CAMPAIGN
    1: {1: 50,   2: 50,   3: 50,   4: 50,   5: 50},       # COMMODITY_BOT
    4: {1: 20,   2: 20,   3: 20,   4: 20,   5: 20},       # RESEARCH_BENIGN
    0: {1: 10,   2: 10,   3: 10,   4: 10,   5: 10},       # UNKNOWN
}


def main():
    ch = Client(CH_HOST)

    # Dedup: already-dropped IPs
    try:
        already_dropped = {str(r[0]) for r in ch.execute(RECENT_VERDICTS_QUERY)}
    except Exception:
        already_dropped = set()
    log.info('Already dropped: %d IPs', len(already_dropped))

    # Pre-fetch type_counts for cap enforcement
    try:
        _tc_rows = ch.execute("SELECT discrepancy_type, count() FROM dfi.ip_capture_d2 WHERE discrepancy_type IN ('PRI', 'CLN', 'RB') GROUP BY discrepancy_type")
        type_counts = {r[0]: r[1] for r in _tc_rows}
    except Exception:
        type_counts = {}
    log.info('Type counts: %s', type_counts)

    # Dedup: already-captured IPs (within last hour)
    try:
        already_captured = {r[0] for r in ch.execute(RECENT_CAPTURES_QUERY)}
    except Exception:
        already_captured = set()
    log.info('Already captured (1h): %d IPs', len(already_captured))

    # ══════════════════════════════════════════════════════════════════
    # DROP verdicts (archetypes 1, 2, 3)
    # ══════════════════════════════════════════════════════════════════
    query = SETTLED_QUERY.format(window=WINDOW_HOURS, min_conf=MIN_CONFIDENCE)
    rows = ch.execute(query)
    log.info('Settled attacker IPs for DROP: %d', len(rows))

    new_verdicts = []
    for src_ip, xgb_class, xgb_conf, total_flows, has_evidence, state, archetype in rows:
        ip = str(src_ip)
        if ip in already_dropped:
            continue
        arch_name = ARCHETYPE_NAMES.get(archetype, '?')
        tier = 'T1:evidence' if has_evidence else 'T2:brain'
        new_verdicts.append({
            'ip': ip,
            'action': 'DROP',
            'reason': f"{tier}:{arch_name}:flows={total_flows}",
            'xgb_class': xgb_class,
            'xgb_confidence': round(float(xgb_conf), 4),
            'total_flows': total_flows,
            'has_evidence': has_evidence,
            'archetype': archetype,
            'ts': time.time(),
        })

    # ══════════════════════════════════════════════════════════════════
    # CAPTURE verdicts — discrepancy capture for D2 training
    # ══════════════════════════════════════════════════════════════════
    capture_verdicts = []

    # D2-ATK: confirmed intruders (model=clean, truth=attack)
    atk_rows = ch.execute(CAPTURE_ATK_QUERY.format(window=WINDOW_HOURS))
    log.info('D2-ATK confirmed intruders: %d', len(atk_rows))
    for src_ip, xgb_class, xgb_conf, total_flows, has_evidence, archetype in atk_rows:
        ip = str(src_ip)
        if ip in already_dropped or ip in already_captured:
            continue
        capture_verdicts.append({
            'ip': ip,
            'action': 'CAPTURE',
            'discrepancy_type': 'ATK',
            'truth_label': 3,
            'reason': f"D2-ATK:CONFIRMED_INTRUDER:flows={total_flows}",
            'xgb_class': xgb_class,
            'xgb_confidence': round(float(xgb_conf), 4),
            'total_flows': total_flows,
            'has_evidence': has_evidence,
            'archetype': 6,
            'ts': time.time(),
        })

    # D2-FP: clean allowlist with attack scores (model=attack, truth=clean)
    # Skip if FP already capped (type_counts checked)
    fp_capped = type_counts.get('FP', 0) >= 1_000_000
    if not fp_capped:
        fp_rows = ch.execute(CAPTURE_FP_QUERY.format(window=WINDOW_HOURS))
    else:
        fp_rows = []
    log.info('D2-FP clean allowlist FPs: %d%s', len(fp_rows), ' (CAPPED)' if fp_capped else '')
    for src_ip, xgb_class, xgb_conf, total_flows, archetype in fp_rows:
        ip = str(src_ip)
        if ip in already_captured:
            continue
        capture_verdicts.append({
            'ip': ip,
            'action': 'CAPTURE',
            'discrepancy_type': 'FP',
            'truth_label': 4,
            'reason': f"D2-FP:ALLOWLIST:xgb_class={xgb_class}:flows={total_flows}",
            'xgb_class': xgb_class,
            'xgb_confidence': round(float(xgb_conf), 4),
            'total_flows': total_flows,
            'has_evidence': 0,
            'archetype': archetype,
            'ts': time.time(),
        })

    # D2-RB: research scanners (model=attack, truth=research benign)
    rb_rows = ch.execute(CAPTURE_RB_QUERY.format(window=WINDOW_HOURS))
    log.info('D2-RB research scanners: %d', len(rb_rows))
    for src_ip, xgb_class, xgb_conf, total_flows, archetype in rb_rows:
        ip = str(src_ip)
        if ip in already_captured:
            continue
        capture_verdicts.append({
            'ip': ip,
            'action': 'CAPTURE',
            'discrepancy_type': 'RB',
            'truth_label': 5,
            'reason': f"D2-RB:RESEARCH:xgb_class={xgb_class}:flows={total_flows}",
            'xgb_class': xgb_class,
            'xgb_confidence': round(float(xgb_conf), 4),
            'total_flows': total_flows,
            'has_evidence': 0,
            'archetype': archetype,
            'ts': time.time(),
        })

    if capture_verdicts:
        n_atk = sum(1 for v in capture_verdicts if v['discrepancy_type'] == 'ATK')
        n_fp = sum(1 for v in capture_verdicts if v['discrepancy_type'] == 'FP')
        n_rb = sum(1 for v in capture_verdicts if v['discrepancy_type'] == 'RB')
        log.info('CAPTURE verdicts: %d (ATK=%d FP=%d RB=%d)', len(capture_verdicts), n_atk, n_fp, n_rb)

    # ══════════════════════════════════════════════════════════════════
    # Mark DROP IPs in CH (capture_depth=0)  — only if we have DROP verdicts
    # ══════════════════════════════════════════════════════════════════
    if new_verdicts:
        now = datetime.utcnow()
        ch_rows = [{
            'src_ip': v['ip'],
            'capture_depth': 0,
            'best_xgb_class': v['xgb_class'],
            'best_xgb_confidence': v['xgb_confidence'],
            'total_flows': v['total_flows'],
            'has_any_evidence': v['has_evidence'],
            'conversation_archetype': v['archetype'],
            'updated_at': now,
            'last_seen': now,
            'watchlist_source': 'god2_verdict',
        } for v in new_verdicts]
        try:
            ch.execute(
                '''INSERT INTO dfi.ip_reputation
                   (src_ip, capture_depth, best_xgb_class, best_xgb_confidence,
                    total_flows, has_any_evidence, conversation_archetype,
                    updated_at, last_seen, watchlist_source)
                   VALUES''',
                ch_rows
            )
            log.info('CH: marked %d IPs as DROP (capture_depth=0)', len(ch_rows))
        except Exception as e:
            log.error('CH DROP write failed: %s', e)

    # ══════════════════════════════════════════════════════════════════
    # Watchlist: DROP IPs (depth=1, priority=2) + CAPTURE IPs (depth=2, priority=1)
    # ══════════════════════════════════════════════════════════════════
    import sqlite3
    WATCHLIST_DB = '/opt/dfi-hunter/watchlist.db'
    try:
        con = sqlite3.connect(WATCHLIST_DB)
        now_ts = time.time()
        expires = now_ts + 30 * 86400

        # DROP entries
        if new_verdicts:
            drop_rows = [(v['ip'], 1, 2, 'god2', f"GOD2:{v['reason']}", expires, now_ts)
                         for v in new_verdicts]
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
                drop_rows
            )
            log.info('Watchlist: %d DROP IPs (depth=1)', len(drop_rows))

        # CAPTURE entries — ONLY D2-ATK goes to watchlist (confirmed intruders to track)
        # D2-FP and D2-RB are clean/research IPs — capture for training only, NOT for watchlist/MikroTik
        atk_captures = [v for v in capture_verdicts if v.get('discrepancy_type') == 'ATK']
        if atk_captures:
            cap_rows = [(v['ip'], 2, 1, 'god2', f"GOD2:D2:{v['reason']}", expires, now_ts)
                        for v in atk_captures]
            con.executemany(
                '''INSERT INTO watchlist (src_ip, capture_depth, priority, source, reason, expires_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(src_ip) DO UPDATE SET
                     capture_depth = MAX(excluded.capture_depth, watchlist.capture_depth),
                     priority = MIN(excluded.priority, watchlist.priority),
                     source = excluded.source,
                     reason = excluded.reason,
                     expires_at = excluded.expires_at,
                     updated_at = excluded.updated_at''',
                cap_rows
            )
            log.info('Watchlist: %d D2-ATK IPs (depth=2, priority=1)', len(cap_rows))

        con.commit()
        con.close()
    except Exception as e:
        log.error('Watchlist write failed: %s', e)

    # ══════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════
    log.info('Done: DROP=%d CAPTURE=%d (ATK=%d FP=%d RB=%d)',
             len(new_verdicts), len(capture_verdicts),
             sum(1 for v in capture_verdicts if v.get('discrepancy_type') == 'ATK'),
             sum(1 for v in capture_verdicts if v.get('discrepancy_type') == 'FP'),
             sum(1 for v in capture_verdicts if v.get('discrepancy_type') == 'RB'))


if __name__ == '__main__':
    main()
