#!/usr/bin/env python3
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from clickhouse_driver import Client


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('labeler')

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
LABEL_INTERVAL = int(os.environ.get('LABEL_INTERVAL', '30'))
CORRELATION_WINDOW = int(os.environ.get('CORRELATION_WINDOW', '120'))
BATCH_SIZE = int(os.environ.get('LABEL_BATCH', '50000'))
LOOKBACK_HOURS = int(os.environ.get('LABEL_LOOKBACK', '4'))

RECON, KNOCK, BRUTEFORCE, EXPLOIT, COMPROMISE = 0, 1, 2, 3, 4
NORM = 5


def _compute_conf(label, counts, mask, n):
    """
    Honeypot confidence rules:
      - Any correlated host-side evidence -> 1.0 (honeypot interaction = confirmed hostile)
      - BRUTEFORCE >=5 auth failures -> 1.0 (explicit threshold)
      - BRUTEFORCE 3-4 failures -> 0.85 (high but below threshold)
      - RECON (no evidence) -> 0.5 (network-only observation, no host confirmation)
    """
    if label == RECON:
        return 0.5

    if label == BRUTEFORCE:
        auth_fail = counts.get('auth_failure', 0)
        if auth_fail >= 5:
            return 1.0
        return 0.85  # 3-4 attempts: high but below certainty threshold

    # EXPLOIT, COMPROMISE, KNOCK: any evidence on a honeypot = confirmed hostile
    return 1.0


def _update_flows_labels(ch, rows):
    """Batch-update label + label_confidence in dfi.flows for JOIN-free export.

    Groups by (label, label_confidence) to minimize mutations.
    """
    from collections import defaultdict
    groups = defaultdict(list)
    for r in rows:
        groups[(r['label'], r['label_confidence'])].append(r['flow_id'])
    for (label, conf), fids in groups.items():
        fid_list = "','".join(fids)
        ch.execute(
            f"ALTER TABLE dfi.flows UPDATE label = {label}, "
            f"label_confidence = {conf} "
            f"WHERE flow_id IN ('{fid_list}')"
        )


def _assign(events):
    if not events:
        return RECON, 0.5, 0, 'No evidence events in window'
    mask = 0
    counts = {}
    details = []
    for ev in events:
        mb = int(ev.get('mask_bit', 0))
        if 0 <= mb <= 7:
            mask |= (1 << mb)
        et = ev['event_type']
        counts[et] = counts.get(et, 0) + 1
        details.append(et)

    has_auth_success = bool(mask & (1 << 1))
    has_post = bool(mask & ((1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7)))

    if has_auth_success and has_post:
        label = COMPROMISE
    elif mask & ((1 << 4) | (1 << 6)):
        label = EXPLOIT
    elif counts.get('auth_failure', 0) >= 3:
        label = BRUTEFORCE
    else:
        label = KNOCK

    conf = _compute_conf(label, counts, mask, len(events))
    return label, conf, mask, ';'.join(details)[:4096]


def correlate_and_label(ch: Client):
    # dfi_norm dropped 2026-03-09 — only label attack flows in dfi
    unlabeled = ch.execute(f"""
        SELECT f.flow_id, f.src_ip, f.dst_ip, f.first_ts, f.actor_id
        FROM dfi.flows f
        WHERE f.first_ts >= now() - INTERVAL {LOOKBACK_HOURS} HOUR
          AND f.actor_id != 'norm'
          AND f.flow_id NOT IN (
              SELECT flow_id FROM dfi.labels
              WHERE labeled_at >= now() - INTERVAL {LOOKBACK_HOURS + 1} HOUR
          )
        ORDER BY f.first_ts
        LIMIT {BATCH_SIZE}
    """)

    if not unlabeled:
        return 0
    return _label_attack_flows(ch, unlabeled)


def _label_attack_flows(ch: Client, unlabeled: list) -> int:
    """Label attack-related flows using evidence correlation."""
    min_ts = min(r[3] for r in unlabeled)
    max_ts = max(r[3] for r in unlabeled)
    start = min_ts - timedelta(seconds=CORRELATION_WINDOW)
    end = max_ts + timedelta(seconds=CORRELATION_WINDOW)
    ips = sorted({str(r[1]) for r in unlabeled})

    evidence = ch.execute(
        """
        SELECT src_ip, ts, event_type, evidence_mask_bit, event_detail
        FROM dfi.evidence_events
        WHERE ts BETWEEN %(start)s AND %(end)s
          AND src_ip IN %(ips)s
        ORDER BY src_ip, ts
        """,
        {'start': start, 'end': end, 'ips': ips},
    )

    by_ip = {}
    for ip, ts, et, bit, det in evidence:
        by_ip.setdefault(str(ip), []).append({'ts': ts, 'event_type': et, 'mask_bit': bit, 'detail': det})

    # IP-level reputation: aggregate evidence across full lookback window
    ip_rep = {}
    rep_rows = ch.execute(
        f"""
        SELECT src_ip,
               countIf(event_type = 'auth_failure') AS af,
               countIf(event_type = 'auth_success') AS as_,
               countIf(event_type = 'suspicious_command') AS sc,
               countIf(event_type = 'service_install') AS si,
               countIf(event_type = 'file_download') AS fd,
               count() AS total
        FROM dfi.evidence_events
        WHERE ts >= now() - INTERVAL {LOOKBACK_HOURS} HOUR
          AND src_ip IN %(ips)s
          AND src_ip != '0.0.0.0'
        GROUP BY src_ip
        """,
        {'ips': ips},
    )
    for ip, af, as_, sc, si, fd, total in rep_rows:
        ip_rep[str(ip)] = {'af': af, 'as': as_, 'sc': sc, 'si': si, 'fd': fd, 'total': total}

    rows = []
    for flow_id, src_ip, dst_ip, first_ts, _actor_id in unlabeled:
        ip_events = by_ip.get(str(src_ip), [])
        wnd = [ev for ev in ip_events if abs((ev['ts'] - first_ts).total_seconds()) <= CORRELATION_WINDOW]
        label, conf, mask, detail = _assign(wnd)

        # IP reputation upgrade
        if label == RECON:
            rep = ip_rep.get(str(src_ip))
            if rep:
                if rep['sc'] > 0 or rep['si'] > 0 or rep['fd'] > 0:
                    label, conf, detail = EXPLOIT, 0.85, f"ip_rep:sc={rep['sc']},si={rep['si']},fd={rep['fd']}"
                elif rep['af'] >= 5:
                    label, conf, detail = BRUTEFORCE, 0.85, f"ip_rep:af={rep['af']}"
                elif rep['af'] >= 3:
                    label, conf, detail = BRUTEFORCE, 0.7, f"ip_rep:af={rep['af']}"
                elif rep['as'] > 0:
                    label, conf, detail = KNOCK, 0.7, f"ip_rep:as={rep['as']}"
                elif rep['total'] > 0:
                    label, conf, detail = KNOCK, 0.6, f"ip_rep:ev={rep['total']}"

        rows.append(
            {
                'flow_id': flow_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'flow_first_ts': first_ts,
                'label': label,
                'label_confidence': conf,
                'evidence_mask': mask,
                'evidence_detail': detail,
                'labeled_at': datetime.now(timezone.utc),
            }
        )

    ch.execute('INSERT INTO dfi.labels VALUES', rows)
    # Inline labels in flows table for JOIN-free export
    _update_flows_labels(ch, rows)
    log.info('labeled attack flows=%d', len(rows))
    return len(rows)


RELABEL_LOOKBACK = int(os.environ.get('RELABEL_LOOKBACK', '2'))


def relabel_recent(ch: Client):
    """Re-label flows that were labeled RECON/KNOCK but now have new evidence."""
    candidates = ch.execute(f"""
        SELECT l.flow_id, f.src_ip, f.dst_ip, f.first_ts, l.label
        FROM (SELECT * FROM dfi.labels FINAL) AS l
        INNER JOIN dfi.flows f ON f.flow_id = l.flow_id
        WHERE l.label IN (0, 1)
          AND f.first_ts >= now() - INTERVAL {RELABEL_LOOKBACK} HOUR
          AND f.src_ip IN (
              SELECT DISTINCT src_ip FROM dfi.evidence_events
              WHERE ts >= now() - INTERVAL {RELABEL_LOOKBACK + 1} HOUR
                AND event_type IN ('auth_failure', 'auth_success', 'suspicious_command')
                AND src_ip != '0.0.0.0'
          )
        LIMIT {BATCH_SIZE}
    """)
    if not candidates:
        return 0

    min_ts = min(r[3] for r in candidates)
    max_ts = max(r[3] for r in candidates)
    start = min_ts - timedelta(seconds=CORRELATION_WINDOW)
    end = max_ts + timedelta(seconds=CORRELATION_WINDOW)
    ips = sorted({str(r[1]) for r in candidates})

    evidence = ch.execute(
        """
        SELECT src_ip, ts, event_type, evidence_mask_bit, event_detail
        FROM dfi.evidence_events
        WHERE ts BETWEEN %(start)s AND %(end)s
          AND src_ip IN %(ips)s
        ORDER BY src_ip, ts
        """,
        {'start': start, 'end': end, 'ips': ips},
    )

    by_ip = {}
    for ip, ts, et, bit, det in evidence:
        by_ip.setdefault(str(ip), []).append({'ts': ts, 'event_type': et, 'mask_bit': bit, 'detail': det})

    # IP-level reputation for relabeling
    ip_rep = {}
    rep_rows = ch.execute(
        f"""
        SELECT src_ip,
               countIf(event_type = 'auth_failure') AS af,
               countIf(event_type = 'auth_success') AS as_,
               countIf(event_type = 'suspicious_command') AS sc,
               countIf(event_type = 'service_install') AS si,
               countIf(event_type = 'file_download') AS fd,
               count() AS total
        FROM dfi.evidence_events
        WHERE ts >= now() - INTERVAL {RELABEL_LOOKBACK + 1} HOUR
          AND src_ip IN %(ips)s
          AND src_ip != '0.0.0.0'
        GROUP BY src_ip
        """,
        {'ips': ips},
    )
    for ip, af, as_, sc, si, fd, total in rep_rows:
        ip_rep[str(ip)] = {'af': af, 'as': as_, 'sc': sc, 'si': si, 'fd': fd, 'total': total}

    rows = []
    for flow_id, src_ip, dst_ip, first_ts, old_label in candidates:
        ip_events = by_ip.get(str(src_ip), [])
        wnd = [ev for ev in ip_events if abs((ev['ts'] - first_ts).total_seconds()) <= CORRELATION_WINDOW]
        label, conf, mask, detail = _assign(wnd)

        # IP reputation upgrade for relabeling
        if label <= KNOCK:
            rep = ip_rep.get(str(src_ip))
            if rep:
                if (rep['sc'] > 0 or rep['si'] > 0 or rep['fd'] > 0) and label < EXPLOIT:
                    label, conf, detail = EXPLOIT, 0.85, f"ip_rep:sc={rep['sc']},si={rep['si']},fd={rep['fd']}"
                elif rep['af'] >= 5 and label < BRUTEFORCE:
                    label, conf, detail = BRUTEFORCE, 0.85, f"ip_rep:af={rep['af']}"
                elif rep['af'] >= 3 and label < BRUTEFORCE:
                    label, conf, detail = BRUTEFORCE, 0.7, f"ip_rep:af={rep['af']}"
                elif rep['as'] > 0 and label < KNOCK:
                    label, conf, detail = KNOCK, 0.7, f"ip_rep:as={rep['as']}"

        if label > old_label:
            rows.append(
                {
                    'flow_id': flow_id,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'flow_first_ts': first_ts,
                    'label': label,
                    'label_confidence': conf,
                    'evidence_mask': mask,
                    'evidence_detail': detail,
                    'labeled_at': datetime.now(timezone.utc),
                }
            )

    if rows:
        ch.execute('INSERT INTO dfi.labels VALUES', rows)
        _update_flows_labels(ch, rows)
    return len(rows)


def main():
    ch = Client(CH_HOST, port=CH_PORT)
    while True:
        try:
            n = correlate_and_label(ch)
            if n:
                log.info('labeled flows=%d', n)
            rn = relabel_recent(ch)
            if rn:
                log.info('relabeled flows=%d', rn)
        except Exception as exc:
            log.error('labeler_error err=%s', exc, exc_info=True)
        time.sleep(LABEL_INTERVAL)


if __name__ == '__main__':
    main()
