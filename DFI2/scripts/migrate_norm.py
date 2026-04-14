#!/usr/bin/env python3
"""Migrate high-conf norm flows from dfi to dfi_norm, day by day."""
import logging
import time
from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('migrate_norm')

CONF_THRESHOLD = 0.8
ch = Client('localhost')


def get_norm_days():
    rows = ch.execute("""
        SELECT toYYYYMMDD(first_ts) AS d, count() AS c
        FROM dfi.flows WHERE actor_id = 'norm'
        GROUP BY d ORDER BY d
    """)
    return [(int(r[0]), int(r[1])) for r in rows]


def migrate_day(day: int):
    t0 = time.time()

    # 1. Flows with high-conf XGB prediction (use IN to avoid JOIN duplication)
    n = ch.execute(f"""
        INSERT INTO dfi_norm.flows
        SELECT * FROM dfi.flows
        WHERE actor_id = 'norm'
          AND toYYYYMMDD(first_ts) = {day}
          AND flow_id IN (
              SELECT DISTINCT flow_id FROM dfi.model_predictions
              WHERE model_name = 'xgb_v6' AND label = 0 AND confidence > {CONF_THRESHOLD}
          )
    """, settings={'max_threads': 0, 'max_memory_usage': 0, 'max_insert_threads': 8})
    flows_count = ch.execute(f"SELECT count() FROM dfi_norm.flows WHERE toYYYYMMDD(first_ts) = {day}")[0][0]
    log.info('day=%d flows=%d (%.1fs)', day, flows_count, time.time() - t0)

    if flows_count == 0:
        return

    # 2. Labels for migrated flows
    t1 = time.time()
    ch.execute(f"""
        INSERT INTO dfi_norm.labels
        SELECT l.* FROM dfi.labels l
        WHERE l.flow_id IN (
            SELECT flow_id FROM dfi_norm.flows WHERE toYYYYMMDD(first_ts) = {day}
        ) AND l.label = 5
    """, settings={'max_threads': 0, 'max_memory_usage': 0, 'max_insert_threads': 8})
    labels_count = ch.execute(f"SELECT count() FROM dfi_norm.labels WHERE toYYYYMMDD(flow_first_ts) = {day}")[0][0]
    log.info('day=%d labels=%d (%.1fs)', day, labels_count, time.time() - t1)

    # 3. Model predictions for migrated flows
    t2 = time.time()
    ch.execute(f"""
        INSERT INTO dfi_norm.model_predictions
        SELECT mp.* FROM dfi.model_predictions mp
        WHERE mp.flow_id IN (
            SELECT flow_id FROM dfi_norm.flows WHERE toYYYYMMDD(first_ts) = {day}
        )
    """, settings={'max_threads': 0, 'max_memory_usage': 0, 'max_insert_threads': 8})
    preds_count = ch.execute(f"""
        SELECT count() FROM dfi_norm.model_predictions
        WHERE flow_id IN (SELECT flow_id FROM dfi_norm.flows WHERE toYYYYMMDD(first_ts) = {day})
    """)[0][0]
    log.info('day=%d predictions=%d (%.1fs)', day, preds_count, time.time() - t2)

    # 4. Packets for migrated flows
    t3 = time.time()
    ch.execute(f"""
        INSERT INTO dfi_norm.packets
        SELECT p.* FROM dfi.packets p
        WHERE p.flow_id IN (
            SELECT flow_id FROM dfi_norm.flows WHERE toYYYYMMDD(first_ts) = {day}
        ) AND toYYYYMMDD(p.ts) = {day}
    """, settings={'max_threads': 0, 'max_memory_usage': 0, 'max_insert_threads': 8})
    pkts_count = ch.execute(f"SELECT count() FROM dfi_norm.packets WHERE toYYYYMMDD(ts) = {day}")[0][0]
    log.info('day=%d packets=%d (%.1fs)', day, pkts_count, time.time() - t3)

    log.info('day=%d COMPLETE total_time=%.1fs', day, time.time() - t0)


def main():
    # Clear test data first
    log.info('Truncating existing dfi_norm test data...')
    for tbl in ['flows', 'labels', 'packets', 'model_predictions']:
        ch.execute(f'TRUNCATE TABLE dfi_norm.{tbl}')
    log.info('Truncated.')

    days = get_norm_days()
    log.info('Found %d days with norm data: %s', len(days), [(d, f'{c:,}') for d, c in days])

    for day, total in days:
        log.info('=== Starting day %d (%s total norm flows) ===', day, f'{total:,}')
        migrate_day(day)

    # Final counts
    for tbl in ['flows', 'labels', 'packets', 'model_predictions']:
        cnt = ch.execute(f'SELECT count() FROM dfi_norm.{tbl}')[0][0]
        log.info('FINAL dfi_norm.%s = %s', tbl, f'{cnt:,}')

    v_cnt = ch.execute('SELECT count() FROM dfi_norm.v_xgb_norm')[0][0]
    log.info('FINAL dfi_norm.v_xgb_norm = %s', f'{v_cnt:,}')


if __name__ == '__main__':
    main()
