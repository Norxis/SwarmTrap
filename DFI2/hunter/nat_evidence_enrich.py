#!/usr/bin/env python3
"""
NAT evidence enrichment — AIO local job.

Joins dfi.evidence_events (winlure:ct110) with dfi.flows to recover the
original pre-NAT destination (38.247.143.x) for each attacker session.
Inserts results into dfi.nat_evidence.

Runs every minute via cron on AIO.
"""
import json
import logging
import os
import sys

from clickhouse_driver import Client

WATERMARK_FILE = '/var/lib/dfi2/nat_evidence_wm.json'
BATCH_SIZE = 10000
NAT_PREFIX = '38.247.143.'
SOURCE_PROGRAM = 'winlure:ct110'
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


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS dfi.nat_evidence (
    evidence_ts     DateTime64(3),
    attacker_ip     IPv4,
    attacker_sport  UInt16,
    svc_port        UInt16,
    original_target IPv4,
    flow_ts         DateTime64(3),
    flow_id         String,
    event_type      LowCardinality(String),
    event_detail    String,
    source_program  LowCardinality(String),
    enriched_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (attacker_ip, evidence_ts)
TTL toDateTime(evidence_ts) + INTERVAL 90 DAY
"""

# Proven JOIN query — validated in session
ENRICH_QUERY = """
SELECT
    e.ts                                                        AS evidence_ts,
    e.src_ip                                                    AS attacker_ip,
    toUInt16(JSONExtractInt(e.event_detail, 'src_port'))        AS attacker_sport,
    toUInt16(JSONExtractInt(e.event_detail, 'dst_port'))        AS svc_port,
    if(like(toString(f.src_ip), '38.247.143.%%'), f.src_ip, f.dst_ip)  AS original_target,
    f.first_ts                                                  AS flow_ts,
    f.flow_id,
    e.event_type,
    e.event_detail,
    e.source_program
FROM dfi.evidence_events e
JOIN dfi.flows f ON (
    (toString(f.src_ip) = toString(e.src_ip) OR toString(f.dst_ip) = toString(e.src_ip))
    AND (like(toString(f.src_ip), '38.247.143.%%') OR like(toString(f.dst_ip), '38.247.143.%%'))
    AND f.dst_port = toUInt16(JSONExtractInt(e.event_detail, 'dst_port'))
    AND abs(toUnixTimestamp(f.first_ts) - toUnixTimestamp(toDateTime(e.ts))) < 3600
)
WHERE e.source_program = %(source)s
  AND e.ts > toDateTime64(%(since)s, 3)
  AND e.ts <= now64(3) - INTERVAL 10 SECOND
ORDER BY e.ts
LIMIT %(limit)s
"""

INSERT_COLS = [
    'evidence_ts', 'attacker_ip', 'attacker_sport', 'svc_port',
    'original_target', 'flow_ts', 'flow_id', 'event_type', 'event_detail',
    'source_program',
]


def main() -> int:
    ch = Client('localhost')
    try:
        ch.execute('SELECT 1')
    except Exception:
        logging.exception('ClickHouse unavailable')
        return 1

    # Ensure table exists
    ch.execute(CREATE_TABLE_SQL)

    wm = load_watermark(WATERMARK_FILE)
    since_ts = wm.get('evidence_ts', DEFAULT_TS)

    rows = ch.execute(ENRICH_QUERY, {
        'source': SOURCE_PROGRAM,
        'since': since_ts,
        'limit': BATCH_SIZE,
    })

    if not rows:
        logging.info('no new enrichable evidence events since=%s', since_ts)
        return 0

    ch.execute(
        f"INSERT INTO dfi.nat_evidence ({','.join(INSERT_COLS)}) VALUES",
        rows,
    )

    # Advance watermark to last evidence_ts in batch
    new_ts_raw = rows[-1][0]  # evidence_ts is column 0
    if hasattr(new_ts_raw, 'strftime'):
        new_ts = new_ts_raw.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    else:
        new_ts = str(new_ts_raw)

    wm['evidence_ts'] = new_ts
    save_watermark(WATERMARK_FILE, wm)

    logging.info('inserted=%d watermark=%s', len(rows), new_ts)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
