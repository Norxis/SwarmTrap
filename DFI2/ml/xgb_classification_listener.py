#!/usr/bin/env python3
"""
xgb_classification_listener.py — Receives ARM XGB classifications via NATS,
writes to dfi.ip_reputation in ClickHouse.

This closes the loop: ARM classifies → NATS → host CH → training data has labels.

Runs as a long-lived daemon on PV1.

Usage:
    python3 xgb_classification_listener.py [--nats nats://localhost:4222]
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta, timezone

import nats
from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('xgb_listener')

STATE_DIRTY = 1
LABEL_MODEL = 3


async def run(nats_url='nats://localhost:4222', ch_host='localhost'):
    ch = Client(host=ch_host)
    nc = await nats.connect(nats_url)
    log.info("Connected to NATS %s", nats_url)

    total = 0
    batch = []

    async def on_message(msg):
        nonlocal total, batch
        try:
            data = json.loads(msg.data.decode())
            ips = data.get('ips', [])
            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=7)

            for ip_data in ips:
                batch.append({
                    'src_ip': ip_data['src_ip'],
                    'state': ip_data.get('state', STATE_DIRTY),
                    'label_source': ip_data.get('label_source', LABEL_MODEL),
                    'label_confidence': ip_data.get('label_confidence', 0.5),
                    'capture_depth': ip_data.get('capture_depth', 2),
                    'has_any_evidence': ip_data.get('has_any_evidence', 0),
                    'updated_at': now,
                    'expires_at': expires,
                    'watchlist_source': 'arm_xgb',
                })
                total += 1

            # Flush batch to CH every 100 IPs
            if len(batch) >= 100:
                flush_batch(ch, batch)
                batch = []

        except Exception as e:
            log.warning("Message parse error: %s", e)

    def flush_batch(ch, rows):
        if not rows:
            return
        columns = list(rows[0].keys())
        values = [[r[c] for c in columns] for r in rows]
        try:
            ch.execute(
                f"INSERT INTO dfi.ip_reputation ({','.join(columns)}) VALUES",
                values
            )
            log.info("Wrote %d ARM XGB classifications to CH (total: %d)", len(rows), total)
        except Exception as e:
            log.warning("CH write failed: %s", e)

    sub = await nc.subscribe("dfi.xgb.classifications", cb=on_message)
    log.info("Subscribed to dfi.xgb.classifications — waiting for ARM data")

    # Flush remaining batch periodically
    while True:
        await asyncio.sleep(10)
        if batch:
            flush_batch(ch, batch)
            batch = []


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--nats', default='nats://localhost:4222')
    parser.add_argument('--ch-host', default='localhost')
    args = parser.parse_args()

    asyncio.run(run(args.nats, args.ch_host))


if __name__ == '__main__':
    main()
