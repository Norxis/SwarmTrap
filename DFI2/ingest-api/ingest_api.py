#!/usr/bin/env python3
"""DFI Ingest API — receives evidence, flows, and watchlist entries from honeypot sensors.

Runs on both PV1 and AIO. Same code, different config via env vars.

Usage:
    python3 ingest_api.py                          # default: 0.0.0.0:81
    INGEST_PORT=9201 python3 ingest_api.py         # override to custom port
    INGEST_API_KEY=secret python3 ingest_api.py    # require API key
"""
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from clickhouse_driver import Client
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('ingest_api')

# ---------------------------------------------------------------------------
# Config (env vars, same pattern as backend_api/config.py)
# ---------------------------------------------------------------------------
CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
WATCHLIST_DB = os.environ.get('WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')
INGEST_HOST = os.environ.get('INGEST_HOST', '0.0.0.0')
INGEST_PORT = int(os.environ.get('INGEST_PORT', '81'))
API_KEY = os.environ.get('INGEST_API_KEY', '')

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class EvidenceEvent(BaseModel):
    ts: float
    src_ip: str
    target_ip: str = '0.0.0.0'
    target_vlan: int = 0
    event_type: str = ''
    event_detail: str = ''
    evidence_mask_bit: int = 0
    source_program: str = 'winlure'
    source_log: str = ''

class EvidenceBatch(BaseModel):
    sensor_id: str
    events: List[EvidenceEvent]

class FlowRecord(BaseModel):
    flow_id: str = ''
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    ip_proto: int = 6
    first_ts: str
    last_ts: str
    pkts_fwd: int = 0
    pkts_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    pkt_size_dir: List[int] = []
    pkt_flag: List[int] = []
    pkt_iat_log_ms: List[int] = []
    pkt_iat_rtt: List[int] = []
    pkt_entropy: List[int] = []

class FlowBatch(BaseModel):
    sensor_id: str
    flows: List[FlowRecord]

class WatchlistEntry(BaseModel):
    src_ip: str
    capture_depth: int = 2
    priority: int = 1
    reason: str = ''
    source: str = 'honeypot'

class WatchlistBatch(BaseModel):
    sensor_id: str
    entries: List[WatchlistEntry]

# ---------------------------------------------------------------------------
# ClickHouse client (lazy init, reconnect on failure)
# ---------------------------------------------------------------------------
_ch: Optional[Client] = None

def get_ch() -> Client:
    global _ch
    if _ch is None:
        _ch = Client(CH_HOST, port=CH_PORT)
        log.info('Connected to ClickHouse %s:%d', CH_HOST, CH_PORT)
    return _ch

def reset_ch():
    global _ch
    _ch = None

# ---------------------------------------------------------------------------
# SQLite watchlist (same pattern as backend_api/adapters.py)
# ---------------------------------------------------------------------------
def watchlist_upsert(entries: List[WatchlistEntry], sensor_id: str):
    now = time.time()
    ttl_30d = now + 30 * 86400
    con = sqlite3.connect(WATCHLIST_DB, timeout=10)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=NORMAL')
    sql = """INSERT INTO watchlist
             (src_ip, capture_depth, priority, group_id, sub_group_id, top_port, reason, source, expires_at, updated_at)
             VALUES (?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(src_ip) DO UPDATE SET
                capture_depth = MAX(watchlist.capture_depth, excluded.capture_depth),
                priority = MIN(watchlist.priority, excluded.priority),
                reason = excluded.reason,
                source = CASE WHEN watchlist.source IN ('evidence_ingest','honeypot','research_benign')
                              THEN watchlist.source
                         WHEN watchlist.source = 'cooldown' AND watchlist.expires_at > unixepoch('now')
                              THEN 'cooldown'
                         ELSE excluded.source END,
                expires_at = MAX(watchlist.expires_at, excluded.expires_at),
                updated_at = excluded.updated_at"""
    rows = [
        (e.src_ip, e.capture_depth, e.priority, '', '', 0,
         e.reason or f'honeypot:{sensor_id}', e.source, ttl_30d, now)
        for e in entries
    ]
    con.executemany(sql, rows)
    con.commit()
    con.close()

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def require_api_key(x_dfi_key: str = Header(default='', alias='X-DFI-Key')):
    if API_KEY and x_dfi_key != API_KEY:
        raise HTTPException(status_code=401, detail='invalid API key')

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title='DFI Ingest API', version='1.0.0')

@app.get('/health')
def health():
    try:
        ch = get_ch()
        count = ch.execute('SELECT count() FROM dfi.flows')[0][0]
        wl_count = 0
        try:
            con = sqlite3.connect(WATCHLIST_DB, timeout=5)
            wl_count = con.execute('SELECT count(*) FROM watchlist').fetchone()[0]
            con.close()
        except Exception:
            pass
        return {'status': 'ok', 'ch_flows': count, 'watchlist_size': wl_count}
    except Exception as e:
        reset_ch()
        return {'status': 'error', 'detail': str(e)}

@app.post('/ingest/evidence')
def ingest_evidence(batch: EvidenceBatch, _=Header(default='', alias='X-DFI-Key')):
    if API_KEY and _ != API_KEY:
        raise HTTPException(status_code=401, detail='invalid API key')
    if not batch.events:
        return {'status': 'ok', 'inserted': 0}
    try:
        ch = get_ch()
        rows = [
            {
                'event_id': str(uuid.uuid4()),
                'ts': datetime.fromtimestamp(e.ts, tz=timezone.utc),
                'src_ip': e.src_ip,
                'target_ip': e.target_ip,
                'target_vlan': e.target_vlan,
                'event_type': e.event_type,
                'event_detail': e.event_detail,
                'evidence_mask_bit': e.evidence_mask_bit,
                'source_program': e.source_program or batch.sensor_id,
                'source_log': e.source_log,
            }
            for e in batch.events
        ]
        ch.execute(
            '''INSERT INTO dfi.evidence_events
               (event_id, ts, src_ip, target_ip, target_vlan, event_type,
                event_detail, evidence_mask_bit, source_program, source_log)
               VALUES''',
            rows,
        )
        log.info('Evidence: %d events from %s', len(rows), batch.sensor_id)
        return {'status': 'ok', 'inserted': len(rows)}
    except Exception as e:
        reset_ch()
        log.error('Evidence insert failed: %s', e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/ingest/flows')
def ingest_flows(batch: FlowBatch, _=Header(default='', alias='X-DFI-Key')):
    if API_KEY and _ != API_KEY:
        raise HTTPException(status_code=401, detail='invalid API key')
    if not batch.flows:
        return {'status': 'ok', 'inserted': 0}
    try:
        ch = get_ch()
        rows = [
            {
                'flow_id': f.flow_id or str(uuid.uuid4()),
                'src_ip': f.src_ip,
                'dst_ip': f.dst_ip,
                'src_port': f.src_port,
                'dst_port': f.dst_port,
                'ip_proto': f.ip_proto,
                'first_ts': f.first_ts,
                'last_ts': f.last_ts,
                'pkts_fwd': f.pkts_fwd,
                'pkts_rev': f.pkts_rev,
                'bytes_fwd': f.bytes_fwd,
                'bytes_rev': f.bytes_rev,
                'pkt_size_dir': f.pkt_size_dir,
                'pkt_flag': f.pkt_flag,
                'pkt_iat_log_ms': f.pkt_iat_log_ms,
                'pkt_iat_rtt': f.pkt_iat_rtt,
                'pkt_entropy': f.pkt_entropy,
            }
            for f in batch.flows
        ]
        ch.execute(
            '''INSERT INTO dfi.flows
               (flow_id, src_ip, dst_ip, src_port, dst_port, ip_proto,
                first_ts, last_ts, pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
                pkt_size_dir, pkt_flag, pkt_iat_log_ms, pkt_iat_rtt, pkt_entropy)
               VALUES''',
            rows,
        )
        log.info('Flows: %d from %s', len(rows), batch.sensor_id)
        return {'status': 'ok', 'inserted': len(rows)}
    except Exception as e:
        reset_ch()
        log.error('Flow insert failed: %s', e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/ingest/watchlist')
def ingest_watchlist(batch: WatchlistBatch, _=Header(default='', alias='X-DFI-Key')):
    if API_KEY and _ != API_KEY:
        raise HTTPException(status_code=401, detail='invalid API key')
    if not batch.entries:
        return {'status': 'ok', 'upserted': 0}
    try:
        watchlist_upsert(batch.entries, batch.sensor_id)
        log.info('Watchlist: %d IPs from %s', len(batch.entries), batch.sensor_id)
        return {'status': 'ok', 'upserted': len(batch.entries)}
    except Exception as e:
        log.error('Watchlist upsert failed: %s', e)
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    log.info('Starting DFI Ingest API on %s:%d', INGEST_HOST, INGEST_PORT)
    uvicorn.run(app, host=INGEST_HOST, port=INGEST_PORT, log_level='info')
