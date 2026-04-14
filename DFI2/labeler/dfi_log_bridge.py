#!/usr/bin/env python3
"""
dfi-log-bridge: Listens on UDP 1514 for rsyslog JSON forwarded from honeypot VMs,
writes rows into evidence.db logs table for evidence_ingest.py to consume.

rsyslog 60-dfi-evidence.conf forwards 172.16.3.* as DFIJsonLog to 127.0.0.1:1514.
"""
import json
import logging
import os
import socket
import sqlite3
import time
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('dfi-log-bridge')

EVIDENCE_DB  = os.environ.get('EVIDENCE_DB',  '/mnt/dfi-data/evidence/evidence.db')
BRIDGE_HOST  = os.environ.get('BRIDGE_HOST',  '127.0.0.1')
BRIDGE_PORT  = int(os.environ.get('BRIDGE_PORT',  '1514'))
BATCH_SIZE   = int(os.environ.get('BRIDGE_BATCH', '500'))
FLUSH_SEC    = float(os.environ.get('BRIDGE_FLUSH', '1.0'))

_IP_MAP = {
    '172.16.3.168': ('UBT20',  'Ubuntu 20.04',      'linux'),
    '172.16.3.166': ('UBT22',  'Ubuntu 22.04',      'linux'),
    '172.16.3.167': ('UBT24',  'Ubuntu 24.04',      'linux'),
    '172.16.3.213': ('SRV19',  'Win Server 2019',   'windows'),
    '172.16.3.212': ('SRV22',  'Win Server 2022',   'windows'),
    '172.16.3.170': ('SRV25',  'Win Server 2025',   'windows'),
    '172.16.3.210': ('WIN10',  'Windows 10 Pro',    'windows'),
    '172.16.3.209': ('SQL19',  'MSSQL 2019',        'windows'),
    '172.16.3.208': ('SQL22',  'MSSQL 2022',        'windows'),
    '172.16.3.169': ('SQL25',  'MSSQL 2025',        'windows'),
}


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(EVIDENCE_DB, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        received_at TEXT NOT NULL,
        source_ip   TEXT NOT NULL,
        vm_name     TEXT NOT NULL DEFAULT '',
        vm_os       TEXT NOT NULL DEFAULT '',
        os_type     TEXT NOT NULL DEFAULT '',
        facility    TEXT DEFAULT '',
        severity    TEXT DEFAULT '',
        program     TEXT DEFAULT '',
        pid         TEXT DEFAULT '',
        message     TEXT NOT NULL DEFAULT '',
        attacker_ip TEXT DEFAULT '',
        raw         TEXT DEFAULT ''
    )""")
    conn.commit()
    return conn


def _flush(conn: sqlite3.Connection, batch: list) -> None:
    if not batch:
        return
    conn.executemany(
        """INSERT INTO logs
           (ts, received_at, source_ip, vm_name, vm_os, os_type,
            facility, severity, program, message, attacker_ip, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        batch,
    )
    conn.commit()


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((BRIDGE_HOST, BRIDGE_PORT))
    sock.settimeout(FLUSH_SEC)
    log.info('listening on %s:%d → %s', BRIDGE_HOST, BRIDGE_PORT, EVIDENCE_DB)

    conn = _get_conn()
    batch: list = []
    last_flush = time.time()
    total = 0

    while True:
        try:
            data, _ = sock.recvfrom(65535)
            raw = data.decode('utf-8', errors='replace').strip()
            try:
                d = json.loads(raw)
            except Exception:
                continue

            src_ip  = d.get('fromhost', '')
            prog    = d.get('programname', '')
            msg     = d.get('msg', '')
            ts      = d.get('timestamp', datetime.now(timezone.utc).isoformat())
            now_s   = datetime.now(timezone.utc).isoformat()
            vm_name, vm_os, os_type = _IP_MAP.get(src_ip, ('', '', ''))

            batch.append((
                ts, now_s, src_ip,
                vm_name, vm_os, os_type,
                d.get('facility', ''), d.get('severity', ''),
                prog, msg, '', raw,
            ))

            should_flush = len(batch) >= BATCH_SIZE or (time.time() - last_flush) >= FLUSH_SEC
            if should_flush:
                _flush(conn, batch)
                total += len(batch)
                if total % 10000 < len(batch):
                    log.info('flushed=%d total=%d', len(batch), total)
                batch = []
                last_flush = time.time()

        except socket.timeout:
            if batch:
                _flush(conn, batch)
                total += len(batch)
                batch = []
                last_flush = time.time()
        except Exception as exc:
            log.error('bridge_error err=%s', exc)
            try:
                conn = _get_conn()
            except Exception:
                pass


if __name__ == '__main__':
    main()
