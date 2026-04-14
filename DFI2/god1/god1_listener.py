#!/usr/bin/env python3
"""GOD 1 NATS Listener — receives XGB scores + D2 discrepancy captures from AIO GOD 1.

Subscribes to:
  dfi.xgb.score   → writes to ip_score_log
  dfi.capture.d2   → writes to ip_capture_d2 (discrepancy capture, no TTL)

Runs on PV1. Conversation brain owns ip_reputation.
D2 rows are enriched with service labels from ip_service_labels at write time.
"""
import asyncio
import json
import logging
import os
import time
from datetime import datetime

from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('god1_listener')

NATS_URL = os.environ.get('NATS_URL', 'nats://127.0.0.1:4222')
NATS_SUBJECT = 'dfi.xgb.score'
NATS_D2_SUBJECT = 'dfi.capture.d2'
CH_HOST = os.environ.get('CH_HOST', '127.0.0.1')
FLUSH_INTERVAL = 5
BATCH_SIZE = 5000

# Port → service_id mapping (matches per-service pipeline)
PORT_TO_SERVICE = {
    22: 1,
    80: 2, 443: 2, 8080: 2, 8443: 2, 8090: 2,
    3389: 3,
    1433: 4, 3306: 4, 3307: 4, 5432: 4,
    445: 5,
}


class CHWriter:
    def __init__(self):
        self.client = Client(CH_HOST)
        self._buffer = []
        self._total = 0

    def add(self, scores: list):
        self._buffer.extend(scores)

    def flush(self):
        if not self._buffer:
            return 0
        batch = self._buffer[:BATCH_SIZE]
        self._buffer = self._buffer[BATCH_SIZE:]

        rows = []
        now = datetime.utcnow()
        for s in batch:
            first_ts = datetime.utcfromtimestamp(s['first_ts']) if s.get('first_ts') else now
            last_ts = datetime.utcfromtimestamp(s['last_ts']) if s.get('last_ts') else now

            rows.append({
                'src_ip': s['src_ip'],
                'dst_ip': s.get('dst_ip', '0.0.0.0'),
                'dst_port': s.get('dst_port', 0),
                'ip_proto': s.get('ip_proto', 0),
                'first_ts': first_ts,
                'last_ts': last_ts,
                'xgb_class': s['label'],
                'xgb_confidence': s['confidence'],
                'pkts_rev': s.get('pkts_rev', 0),
                'src_flow_count': s.get('src_flow_count', 0),
                'src_unique_ports': s.get('src_unique_ports', 0),
                'src_unique_dsts': s.get('src_unique_dsts', 0),
                'vlan_id': s.get('vlan_id', 0),
                'sensor': s.get('sensor', 'god1'),
                'ingested_at': now,
            })

        try:
            self.client.execute(
                '''INSERT INTO dfi.ip_score_log
                   (src_ip, dst_ip, dst_port, ip_proto, first_ts, last_ts,
                    xgb_class, xgb_confidence, pkts_rev,
                    src_flow_count, src_unique_ports, src_unique_dsts,
                    vlan_id, sensor, ingested_at)
                   VALUES''',
                rows
            )
            self._total += len(rows)
            return len(rows)
        except Exception as e:
            log.error('CH write failed: %s', e)
            try:
                self.client.disconnect()
            except:
                pass
            return 0


class D2Writer:
    """Writes D2 discrepancy capture records to ip_capture_d2.

    Enriches service_id (from dst_port if missing) and service_class
    (from ip_service_labels) at write time so rows land pre-labeled.
    """

    def __init__(self):
        self.client = Client(CH_HOST)
        self._buffer = []
        self._total = 0
        self._label_cache = {}       # (src_ip, service_id) → service_class
        self._cache_ts = 0
        self._CACHE_TTL = 300        # refresh every 5 min

    def add(self, records: list):
        self._buffer.extend(records)

    def _resolve_service_id(self, r):
        """Return service_id: use message value if >0, else derive from dst_port."""
        sid = int(r.get('service_id', 0))
        if sid > 0:
            return sid
        return PORT_TO_SERVICE.get(int(r.get('dst_port', 0)), 0)

    def _enrich_labels(self, batch):
        """Batch-lookup ip_service_labels for (src_ip, service_id) pairs.

        Populates self._label_cache with results.  Only queries pairs
        not already cached (or if cache is stale).
        """
        now = time.time()
        if now - self._cache_ts > self._CACHE_TTL:
            self._label_cache.clear()
            self._cache_ts = now

        # Collect unique (src_ip, service_id) pairs that need lookup
        need = set()
        for r in batch:
            sid = self._resolve_service_id(r)
            if sid > 0:
                key = (r['src_ip'], sid)
                if key not in self._label_cache:
                    need.add(key)

        if not need:
            return

        # Build batch query — get all labels for the src_ips we need
        ips = list({ip for ip, _ in need})
        try:
            rows = self.client.execute(
                "SELECT src_ip, service_id, service_class "
                "FROM dfi.ip_service_labels FINAL "
                "WHERE src_ip IN %(ips)s AND service_class < 255",
                {'ips': ips}
            )
            for src_ip, service_id, service_class in rows:
                self._label_cache[(str(src_ip), int(service_id))] = int(service_class)
        except Exception as e:
            log.warning('D2 label lookup failed: %s', e)

    def flush(self):
        if not self._buffer:
            return 0
        batch = self._buffer[:500]
        self._buffer = self._buffer[500:]

        # Enrich labels from ip_service_labels
        self._enrich_labels(batch)

        rows = []
        enriched = 0
        for r in batch:
            first_ts = datetime.utcfromtimestamp(r['first_ts']) if r.get('first_ts') else datetime.utcnow()
            last_ts = datetime.utcfromtimestamp(r['last_ts']) if r.get('last_ts') else datetime.utcnow()

            # Resolve service_id from port if needed
            sid = self._resolve_service_id(r)

            # Look up service_class from labels; fall back to message value
            sclass = int(r.get('service_class', 255))
            if sid > 0:
                cached = self._label_cache.get((r['src_ip'], sid))
                if cached is not None and cached < 255:
                    sclass = cached
                    enriched += 1

            rows.append({
                'src_ip': r['src_ip'],
                'dst_ip': r.get('dst_ip', '0.0.0.0'),
                'dst_port': r.get('dst_port', 0),
                'ip_proto': r.get('ip_proto', 0),
                'vlan_id': r.get('vlan_id', 0),
                'first_ts': first_ts,
                'last_ts': last_ts,
                'duration_ms': r.get('duration_ms', 0),
                'pkts_fwd': r.get('pkts_fwd', 0),
                'pkts_rev': r.get('pkts_rev', 0),
                'bytes_fwd': r.get('bytes_fwd', 0),
                'bytes_rev': r.get('bytes_rev', 0),
                'xgb_class': r.get('xgb_class', 0),
                'xgb_confidence': r.get('xgb_confidence', 0),
                'xgb_probs': r.get('xgb_probs', []),
                'syn_count': min(r.get('syn_count', 0), 255),
                'fin_count': min(r.get('fin_count', 0), 255),
                'rst_count': min(r.get('rst_count', 0), 255),
                'psh_count': min(r.get('psh_count', 0), 255),
                'conn_state': min(r.get('conn_state', 0), 255),
                'payload_len_first': r.get('payload_len_first', 0),
                'entropy_first': r.get('entropy_first', 0),
                'printable_frac': r.get('printable_frac', 0),
                'null_frac': r.get('null_frac', 0),
                'first_fwd_payload': r.get('first_fwd_payload', ''),
                'rtt_ms': r.get('rtt_ms', 0),
                'iat_fwd_mean_ms': r.get('iat_fwd_mean_ms', 0),
                'pps': r.get('pps', 0),
                'src_flow_count': r.get('src_flow_count', 0),
                'src_unique_ports': r.get('src_unique_ports', 0),
                'src_unique_dsts': r.get('src_unique_dsts', 0),
                'discrepancy_type': r.get('discrepancy_type', 'ATK'),
                'truth_label': r.get('truth_label', 3),
                'service_id': sid,
                'service_class': sclass,
                'capture_value_score': int(r.get('capture_value_score', 0)),
            })

        try:
            self.client.execute(
                '''INSERT INTO dfi.ip_capture_d2
                   (src_ip, dst_ip, dst_port, ip_proto, vlan_id, first_ts, last_ts,
                    duration_ms, pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
                    xgb_class, xgb_confidence, xgb_probs,
                    syn_count, fin_count, rst_count, psh_count, conn_state,
                    payload_len_first, entropy_first, printable_frac, null_frac,
                    first_fwd_payload, rtt_ms, iat_fwd_mean_ms, pps,
                    src_flow_count, src_unique_ports, src_unique_dsts,
                    discrepancy_type, truth_label,
                    service_id, service_class, capture_value_score)
                   VALUES''',
                rows
            )
            self._total += len(rows)
            if enriched:
                log.info('D2 enriched %d/%d rows with service labels', enriched, len(rows))
            return len(rows)
        except Exception as e:
            log.error('D2 CH write failed: %s', e)
            try:
                self.client.disconnect()
            except:
                pass
            return 0


async def main():
    import nats

    ch = CHWriter()
    d2 = D2Writer()
    last_flush = time.time()

    async def on_message(msg):
        nonlocal last_flush
        try:
            scores = json.loads(msg.data)
            if isinstance(scores, list):
                ch.add(scores)
            elif isinstance(scores, dict):
                ch.add([scores])
        except Exception as e:
            log.warning('parse error: %s', e)

        now = time.time()
        if now - last_flush >= FLUSH_INTERVAL or len(ch._buffer) >= BATCH_SIZE:
            written = ch.flush()
            if written:
                log.info('ip_score_log: %d rows (total=%d, buffer=%d)', written, ch._total, len(ch._buffer))
            last_flush = now

    async def on_d2_message(msg):
        try:
            record = json.loads(msg.data)
            if isinstance(record, list):
                d2.add(record)
            elif isinstance(record, dict):
                d2.add([record])
        except Exception as e:
            log.warning('D2 parse error: %s', e)

    log.info('Connecting to NATS %s', NATS_URL)
    nc = await nats.connect(NATS_URL)
    await nc.subscribe(NATS_SUBJECT, cb=on_message)
    log.info('Subscribed: %s → ip_score_log', NATS_SUBJECT)
    await nc.subscribe(NATS_D2_SUBJECT, cb=on_d2_message)
    log.info('Subscribed: %s → ip_capture_d2', NATS_D2_SUBJECT)

    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        written = ch.flush()
        if written:
            log.info('ip_score_log: %d rows (total=%d)', written, ch._total)
        d2_written = d2.flush()
        if d2_written:
            log.info('ip_capture_d2: %d records (total=%d)', d2_written, d2._total)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info('Stopped.')
