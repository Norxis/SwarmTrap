#!/usr/bin/env python3
import json
import logging
import os
from datetime import datetime, timezone

from clickhouse_driver import Client

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import AIO_CH_PORT, AIO_HOST, WATERMARK_FILE

TABLE_TS_MAP = {
    'flows': 'first_ts',
    'packets': 'ts',
    'fingerprints': 'first_ts',
    'fanout_hops': 'first_ts',
    'evidence_events': 'ts',
    'model_predictions': 'scored_at',
}

DEFAULT_TS = '1970-01-01 00:00:00.000'


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)


def ensure_watermark_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def load_watermark(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_watermark(path: str, data: dict) -> None:
    ensure_watermark_dir(path)
    tmp = f'{path}.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def pull_table(local: Client, table: str, ts_col: str, since_ts: str) -> tuple[int, str]:
    max_ts_q = (
        f"SELECT max({ts_col}) FROM remote('{AIO_HOST}:{AIO_CH_PORT}', 'dfi', '{table}') "
        f"WHERE {ts_col} > toDateTime64(%(since)s, 3)"
    )
    cnt_q = (
        f"SELECT count() FROM remote('{AIO_HOST}:{AIO_CH_PORT}', 'dfi', '{table}') "
        f"WHERE {ts_col} > toDateTime64(%(since)s, 3)"
    )
    insert_q = (
        f"INSERT INTO dfi.{table} "
        f"SELECT * FROM remote('{AIO_HOST}:{AIO_CH_PORT}', 'dfi', '{table}') "
        f"WHERE {ts_col} > toDateTime64(%(since)s, 3)"
    )

    params = {'since': since_ts}
    row_count = int(local.execute(cnt_q, params)[0][0])
    if row_count == 0:
        return 0, since_ts

    new_max_raw = local.execute(max_ts_q, params)[0][0]
    local.execute(insert_q, params)

    if hasattr(new_max_raw, 'strftime'):
        new_max = new_max_raw.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    else:
        new_max = str(new_max_raw)

    return row_count, new_max


def main() -> int:
    wm = load_watermark(WATERMARK_FILE)
    local = Client('localhost')

    try:
        local.execute('SELECT 1')
    except Exception:
        logging.exception('Local ClickHouse unavailable on localhost:9000')
        return 1

    for table, ts_col in TABLE_TS_MAP.items():
        since_ts = wm.get(table, DEFAULT_TS)
        try:
            rows, new_ts = pull_table(local, table, ts_col, since_ts)
            if rows > 0:
                wm[table] = new_ts
            logging.info('table=%s pulled_rows=%s watermark=%s', table, rows, wm.get(table, since_ts))
        except Exception as exc:
            logging.warning('table=%s pull_failed=%s', table, exc)

    wm['last_run_utc'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    save_watermark(WATERMARK_FILE, wm)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
