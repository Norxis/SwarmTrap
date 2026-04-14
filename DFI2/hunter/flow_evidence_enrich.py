#!/usr/bin/env python3
"""
Flow evidence enrichment — AIO local job.

Joins dfi.model_predictions with dfi.evidence_events to produce
dfi.flow_evidence: one row per scored flow with XGB label/confidence
AND aggregated honeypot evidence for that attacker IP within ±1h.

Runs every minute via cron on AIO.
"""
import json
import logging
import os

from clickhouse_driver import Client

WATERMARK_FILE = '/var/lib/dfi2/flow_evidence_wm.json'
BATCH_SIZE = 50000
DEFAULT_TS = '1970-01-01 00:00:00.000'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)


def load_watermark(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_watermark(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f'{path}.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


# SELECT column order:
#  0  flow_id
#  1  flow_ts
#  2  attacker_ip
#  3  dst_ip
#  4  dst_port
#  5  ip_proto
#  6  scored_at        <-- watermark only, NOT inserted
#  7  xgb_label
#  8  xgb_conf
#  9  xgb_probs
# 10  evidence_count
# 11  evidence_types
# 12  source_programs
# 13  first_evidence_ts
ENRICH_QUERY = """
SELECT
    p.flow_id,
    p.flow_first_ts                                              AS flow_ts,
    p.src_ip                                                     AS attacker_ip,
    p.dst_ip,
    p.dst_port,
    f.ip_proto,
    max(p.scored_at)                                             AS scored_at,
    p.label                                                      AS xgb_label,
    p.confidence                                                 AS xgb_conf,
    p.class_probs                                                AS xgb_probs,
    countIf(e.src_ip != toIPv4('0.0.0.0'))                      AS evidence_count,
    groupUniqArrayIf(e.event_type,
        e.src_ip != toIPv4('0.0.0.0'))                          AS evidence_types,
    groupUniqArrayIf(e.source_program,
        e.src_ip != toIPv4('0.0.0.0'))                          AS source_programs,
    minIf(e.ts, e.src_ip != toIPv4('0.0.0.0'))                  AS first_evidence_ts
FROM dfi.model_predictions p
LEFT JOIN dfi.flows f ON f.flow_id = p.flow_id
LEFT JOIN dfi.evidence_events e ON (
    e.src_ip = p.src_ip
    AND abs(toUnixTimestamp(e.ts) - toUnixTimestamp(toDateTime(p.flow_first_ts))) < 3600
)
WHERE p.scored_at > toDateTime64(%(since)s, 3)
  AND p.scored_at <= now64(3) - INTERVAL 10 SECOND
GROUP BY p.flow_id, p.flow_first_ts, p.src_ip, p.dst_ip, p.dst_port,
         f.ip_proto, p.label, p.confidence, p.class_probs
ORDER BY scored_at
LIMIT %(limit)s
"""

# Insert columns (scored_at excluded — it's only used for watermark)
INSERT_COLS = [
    'flow_id', 'flow_ts', 'attacker_ip', 'dst_ip', 'dst_port', 'ip_proto',
    'xgb_label', 'xgb_conf', 'xgb_probs',
    'evidence_count', 'evidence_types', 'source_programs', 'first_evidence_ts',
]
SCORED_AT_IDX = 6  # position in SELECT result


def main() -> int:
    ch = Client('localhost')
    try:
        ch.execute('SELECT 1')
    except Exception:
        logging.exception('ClickHouse unavailable')
        return 1

    wm = load_watermark(WATERMARK_FILE)
    since_ts = wm.get('scored_at', DEFAULT_TS)

    rows = ch.execute(ENRICH_QUERY, {'since': since_ts, 'limit': BATCH_SIZE})
    if not rows:
        logging.info('no new scored flows since=%s', since_ts)
        return 0

    # Strip scored_at (index 6) before inserting
    insert_rows = [r[:SCORED_AT_IDX] + r[SCORED_AT_IDX + 1:] for r in rows]
    ch.execute(
        f"INSERT INTO dfi.flow_evidence ({','.join(INSERT_COLS)}) VALUES",
        insert_rows,
    )

    # Advance watermark to max scored_at in batch
    new_ts_raw = max(r[SCORED_AT_IDX] for r in rows)
    if hasattr(new_ts_raw, 'strftime'):
        new_ts = new_ts_raw.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    else:
        new_ts = str(new_ts_raw)

    wm['scored_at'] = new_ts
    save_watermark(WATERMARK_FILE, wm)

    logging.info('inserted=%d watermark=%s', len(rows), new_ts)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
