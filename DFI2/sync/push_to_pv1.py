#!/usr/bin/env python3
"""
AIO -> PV1 data push.

Runs on AIO via cron every 5 minutes. Reads new rows from local ClickHouse,
inserts them into PV1 ClickHouse at 172.16.3.2:9000.
"""
import json
import logging
import os
import sys

from clickhouse_driver import Client

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import PV1_HOST, PV1_CH_PORT

WATERMARK_FILE = os.environ.get(
    'PUSH_WATERMARK_FILE', '/var/lib/dfi2/push_watermark.json'
)

TABLE_TS_MAP = {
    'flows': 'first_ts',
    'packets': 'ts',
    'fingerprints': 'first_ts',
    'fanout_hops': 'first_ts',
    'evidence_events': 'ts',
    'labels': 'labeled_at',
    'model_predictions': 'scored_at',
}

# dfi_norm DB dropped 2026-03-09 — dirty/clean replace it
DIRTY_TABLE_TS_MAP = {
    'flows': 'first_ts',
}
CLEAN_TABLE_TS_MAP = {
    'flows': 'first_ts',
}

RECON_TABLE_TS_MAP = {
    'recon_flows': 'scored_at',
    'flow_features': 'scored_at',
}

DEFAULT_TS = '1970-01-01 00:00:00.000'
BATCH_SIZE = 1000000

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)


def ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def load_watermark(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_watermark(path: str, data: dict) -> None:
    ensure_dir(path)
    tmp = f'{path}.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def push_table(local: Client, remote: Client, table: str,
               ts_col: str, since_ts: str, database: str = 'dfi') -> tuple:
    q = (
        f"SELECT * FROM {database}.{table} "
        f"WHERE {ts_col} > toDateTime64(%(since)s, 3) "
        f"ORDER BY {ts_col} LIMIT {BATCH_SIZE}"
    )
    rows = local.execute(q, {'since': since_ts})
    if not rows:
        return 0, since_ts

    # Get column names for the insert
    cols = local.execute(
        f"SELECT name FROM system.columns WHERE database='{database}' AND table='{table}' ORDER BY position"
    )
    col_names = [c[0] for c in cols]

    remote.execute(
        f"INSERT INTO {database}.{table} ({','.join(col_names)}) VALUES",
        rows,
    )

    # Find max timestamp of the pushed batch (last row, since ordered by ts_col)
    new_max_raw = rows[-1][col_names.index(ts_col)]
    if hasattr(new_max_raw, 'strftime'):
        new_max = new_max_raw.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    else:
        new_max = str(new_max_raw)

    return len(rows), new_max


def main() -> int:
    wm = load_watermark(WATERMARK_FILE)

    local = Client('localhost')
    try:
        local.execute('SELECT 1')
    except Exception:
        logging.exception('Local ClickHouse unavailable')
        return 1

    remote = Client(PV1_HOST, port=PV1_CH_PORT)
    try:
        remote.execute('SELECT 1')
    except Exception:
        logging.exception(f'PV1 ClickHouse unavailable at {PV1_HOST}:{PV1_CH_PORT}')
        return 1

    from datetime import datetime, timezone
    total = 0

    # Push dfi tables
    for table, ts_col in TABLE_TS_MAP.items():
        since_ts = wm.get(table, DEFAULT_TS)
        try:
            rows, new_ts = push_table(local, remote, table, ts_col, since_ts)
            if rows > 0:
                wm[table] = new_ts
                total += rows
            logging.info('table=dfi.%s pushed_rows=%s watermark=%s', table, rows,
                         wm.get(table, since_ts))
        except Exception as exc:
            logging.warning('table=dfi.%s push_failed=%s', table, exc)

    # Push dfi_dirty tables
    for table, ts_col in DIRTY_TABLE_TS_MAP.items():
        wm_key = f'dfi_dirty.{table}'
        since_ts = wm.get(wm_key, DEFAULT_TS)
        try:
            rows, new_ts = push_table(local, remote, table, ts_col, since_ts, database='dfi_dirty')
            if rows > 0:
                wm[wm_key] = new_ts
                total += rows
            logging.info('table=dfi_dirty.%s pushed_rows=%s watermark=%s', table, rows,
                         wm.get(wm_key, since_ts))
        except Exception as exc:
            logging.warning('table=dfi_dirty.%s push_failed=%s', table, exc)

    # Push dfi_clean tables
    for table, ts_col in CLEAN_TABLE_TS_MAP.items():
        wm_key = f'dfi_clean.{table}'
        since_ts = wm.get(wm_key, DEFAULT_TS)
        try:
            rows, new_ts = push_table(local, remote, table, ts_col, since_ts, database='dfi_clean')
            if rows > 0:
                wm[wm_key] = new_ts
                total += rows
            logging.info('table=dfi_clean.%s pushed_rows=%s watermark=%s', table, rows,
                         wm.get(wm_key, since_ts))
        except Exception as exc:
            logging.warning('table=dfi_clean.%s push_failed=%s', table, exc)

    # Push dfi_recon tables
    for table, ts_col in RECON_TABLE_TS_MAP.items():
        wm_key = f'dfi_recon.{table}'
        since_ts = wm.get(wm_key, DEFAULT_TS)
        try:
            rows, new_ts = push_table(local, remote, table, ts_col, since_ts, database='dfi_recon')
            if rows > 0:
                wm[wm_key] = new_ts
                total += rows
            logging.info('table=dfi_recon.%s pushed_rows=%s watermark=%s', table, rows,
                         wm.get(wm_key, since_ts))
        except Exception as exc:
            logging.warning('table=dfi_recon.%s push_failed=%s', table, exc)

    wm['last_run_utc'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    save_watermark(WATERMARK_FILE, wm)
    logging.info('push complete total_rows=%s', total)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
