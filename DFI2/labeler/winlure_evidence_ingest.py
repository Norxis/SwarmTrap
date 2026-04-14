#!/usr/bin/env python3
"""Evidence ingest for AIO — reads Winlure credentials.db into ClickHouse evidence_events."""
import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('winlure_evidence_ingest')

CREDENTIALS_DB = os.environ.get('CREDENTIALS_DB', '/opt/winlure/state/credentials.db')
CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '10'))
WATERMARK_FILE = os.environ.get('WATERMARK_FILE', '/opt/dfi2/winlure_evidence_wm.txt')
CONN_WATERMARK_FILE = os.environ.get('CONN_WATERMARK_FILE', '/opt/dfi2/winlure_conn_wm.txt')
HONEYPOT_IP = os.environ.get('HONEYPOT_IP', '216.126.0.206')

# Protocol -> (default_event_type, evidence_mask_bit)
PROTO_MAP = {
    'ssh':     ('auth_failure', 0),
    'rdp':     ('auth_failure', 0),
    'mssql':   ('auth_failure', 0),
    'smb':     ('auth_failure', 0),
    'ldap':    ('auth_failure', 0),
    'http':    ('auth_failure', 0),
    'winrm':   ('auth_failure', 0),
    'netbios': ('connection', 7),
    'nbns':    ('connection', 7),
}

# dst_port -> (protocol_name, event_type, evidence_mask_bit)
CONN_PORT_MAP = {
    22:   ('ssh',   'auth_failure', 0),
    445:  ('smb',   'auth_failure', 0),
    1433: ('mssql', 'auth_failure', 0),
    3389: ('rdp',   'auth_failure', 0),
    5985: ('winrm', 'auth_failure', 0),
    389:  ('ldap',  'auth_failure', 0),
    80:   ('http',  'auth_failure', 0),
}

INTERNAL_PREFIXES = ('172.16.3.', '127.', '0.', '10.')


def _valid_ip(ip):
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _safe_ip(ip):
    return ip if ip and _valid_ip(ip) else '0.0.0.0'


def _is_external(ip):
    if not ip or not _valid_ip(ip):
        return False
    return not any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def _get_wm():
    try:
        return int(open(WATERMARK_FILE, 'r', encoding='utf-8').read().strip())
    except Exception:
        return 0


def _set_wm(v):
    os.makedirs(os.path.dirname(WATERMARK_FILE), exist_ok=True)
    with open(WATERMARK_FILE, 'w', encoding='utf-8') as f:
        f.write(str(v))


def _get_conn_wm():
    try:
        return int(open(CONN_WATERMARK_FILE, 'r', encoding='utf-8').read().strip())
    except Exception:
        return 0


def _set_conn_wm(v):
    os.makedirs(os.path.dirname(CONN_WATERMARK_FILE), exist_ok=True)
    with open(CONN_WATERMARK_FILE, 'w', encoding='utf-8') as f:
        f.write(str(v))


def _parse_credential(row):
    proto = (row.get('proto') or '').lower()
    username = row.get('username', '')
    password = row.get('password', '')

    event_type, mask_bit = PROTO_MAP.get(proto, ('unknown', 0))

    # If we captured a real password/hash, it's a credential capture
    if password and proto not in ('netbios', 'nbns'):
        event_type = 'credential_capture'
        mask_bit = 1

    ts_raw = row.get('ts')
    if isinstance(ts_raw, (int, float)):
        ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
    else:
        ts = datetime.now(tz=timezone.utc)

    detail = {'username': username, 'protocol': proto}
    if row.get('domain'):
        detail['domain'] = row['domain']
    if row.get('hash_type') and row['hash_type'] != 'plaintext':
        detail['hash_type'] = row['hash_type']

    return {
        'event_id': str(uuid.uuid4()),
        'ts': ts,
        'src_ip': _safe_ip(row.get('src_ip')),
        'target_ip': HONEYPOT_IP,
        'target_vlan': 0,
        'event_type': event_type,
        'event_detail': json.dumps(detail),
        'evidence_mask_bit': mask_bit,
        'source_program': f'winlure_{proto}',
        'source_log': json.dumps(
            {k: str(v)[:200] for k, v in row.items() if k != 'raw_data'}
        )[:4096],
        'ingested_at': datetime.now(tz=timezone.utc),
    }


def _parse_connection(row):
    """Parse a connections table row into an evidence event.
    On a honeypot, any TCP connection to an auth port = attack attempt."""
    dst_port = int(row.get('dst_port') or 0)
    if dst_port not in CONN_PORT_MAP:
        return None

    src_ip = str(row.get('src_ip', ''))
    if not _is_external(src_ip):
        return None

    proto, event_type, mask_bit = CONN_PORT_MAP[dst_port]

    ts_raw = row.get('ts')
    if isinstance(ts_raw, (int, float)):
        ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
    else:
        ts = datetime.now(tz=timezone.utc)

    return {
        'event_id': str(uuid.uuid4()),
        'ts': ts,
        'src_ip': src_ip,
        'target_ip': HONEYPOT_IP,
        'target_vlan': 0,
        'event_type': event_type,
        'event_detail': json.dumps({'port': dst_port, 'protocol': proto, 'source': 'connection'}),
        'evidence_mask_bit': mask_bit,
        'source_program': f'winlure_conn_{proto}',
        'source_log': json.dumps({k: str(v)[:200] for k, v in row.items()})[:4096],
        'ingested_at': datetime.now(tz=timezone.utc),
    }


def main():
    ch = Client(CH_HOST, port=CH_PORT)
    log.info('starting winlure_evidence_ingest db=%s honeypot=%s', CREDENTIALS_DB, HONEYPOT_IP)
    while True:
        try:
            db = sqlite3.connect(CREDENTIALS_DB, timeout=10)
            db.row_factory = sqlite3.Row

            # --- credentials table ---
            wm = _get_wm()
            rows = db.execute(
                'SELECT * FROM credentials WHERE id > ? ORDER BY id LIMIT 5000', (wm,)
            ).fetchall()

            cred_events = []
            max_id = wm
            for r in rows:
                d = dict(r)
                max_id = max(max_id, int(d.get('id', 0)))
                ev = _parse_credential(d)
                if ev and ev['src_ip'] != '0.0.0.0':
                    cred_events.append(ev)

            if cred_events:
                ch.execute('INSERT INTO dfi.evidence_events_buffer VALUES', cred_events)
                log.info('cred_events=%d id=%d->%d', len(cred_events), wm, max_id)
            if rows:
                _set_wm(max_id)

            # --- connections table (auth ports → auth_failure evidence) ---
            conn_wm = _get_conn_wm()
            try:
                conn_rows = db.execute(
                    'SELECT * FROM connections WHERE id > ? ORDER BY id LIMIT 10000', (conn_wm,)
                ).fetchall()
            except Exception:
                conn_rows = []

            conn_events = []
            conn_max_id = conn_wm
            for r in conn_rows:
                d = dict(r)
                conn_max_id = max(conn_max_id, int(d.get('id', 0)))
                ev = _parse_connection(d)
                if ev:
                    conn_events.append(ev)

            if conn_events:
                ch.execute('INSERT INTO dfi.evidence_events_buffer VALUES', conn_events)
                log.info('conn_events=%d id=%d->%d', len(conn_events), conn_wm, conn_max_id)
            if conn_rows:
                _set_conn_wm(conn_max_id)

            db.close()
        except Exception as exc:
            log.error('winlure_evidence_error err=%s', exc, exc_info=True)
        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
