#!/usr/bin/env python3
import json
import logging
import os
import sqlite3
import tempfile
import time

import paramiko
from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('watchlist_push')


def _req(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f'missing required env var: {name}')
    return v


AIO_HOST = os.environ.get('AIO_HOST', '192.168.0.113')
AIO_PORT = int(os.environ.get('AIO_SSH_PORT', '2222'))
AIO_USER = os.environ.get('AIO_USER', 'colo8gent')
AIO_WATCHLIST = os.environ.get('AIO_WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')
LOCAL_WATCHLIST = os.environ.get('WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')


def push_local(entries: list):
    conn = sqlite3.connect(LOCAL_WATCHLIST, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute(
        '''CREATE TABLE IF NOT EXISTS watchlist (
           src_ip TEXT PRIMARY KEY,
           capture_depth INTEGER NOT NULL DEFAULT 1,
           priority INTEGER NOT NULL DEFAULT 3,
           group_id TEXT,
           sub_group_id TEXT,
           top_port INTEGER,
           reason TEXT,
           source TEXT NOT NULL DEFAULT 'classifier',
           expires_at REAL,
           updated_at REAL DEFAULT (unixepoch('now')) )'''
    )
    sql = '''INSERT INTO watchlist
             (src_ip,capture_depth,priority,group_id,sub_group_id,top_port,reason,source,expires_at,updated_at)
             VALUES (?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(src_ip) DO UPDATE SET
                capture_depth = MAX(capture_depth, excluded.capture_depth),
                priority = MIN(priority, excluded.priority),
                group_id = excluded.group_id,
                sub_group_id = excluded.sub_group_id,
                top_port = excluded.top_port,
                reason = excluded.reason,
                source = CASE WHEN watchlist.source = 'xgb_scorer' AND excluded.source = 'classifier'
                              THEN 'xgb_scorer' ELSE excluded.source END,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at'''
    now = time.time()
    TTL_DAYS = 30
    default_expires = now + TTL_DAYS * 86400
    conn.executemany(
        sql,
        [
            (
                e.get('src_ip'),
                int(e.get('capture_depth', 1)),
                int(e.get('priority', 3)),
                e.get('group_id'),
                e.get('sub_group_id'),
                e.get('top_port'),
                e.get('reason', 'classifier'),
                e.get('source', 'classifier'),
                e.get('expires_at', default_expires),
                now,
            )
            for e in entries
        ],
    )
    conn.commit()
    conn.close()


def push_aio(entries: list):
    if not entries:
        return
    aio_pass = _req('AIO_PASS')

    with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as fp:
        json.dump(entries, fp)
        src = fp.name

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(AIO_HOST, port=AIO_PORT, username=AIO_USER, password=aio_pass, timeout=20)
    try:
        sftp = ssh.open_sftp()
        sftp.put(src, '/tmp/dfi2_watchlist.json')
        sftp.close()
        py = (
            "import json,sqlite3,time;"
            f"db='{AIO_WATCHLIST}';"
            "rows=json.load(open('/tmp/dfi2_watchlist.json'));"
            "con=sqlite3.connect(db);"
            "con.execute('PRAGMA journal_mode=WAL');"
            "con.execute('PRAGMA synchronous=NORMAL');"
            "con.execute('''CREATE TABLE IF NOT EXISTS watchlist (src_ip TEXT PRIMARY KEY,capture_depth INTEGER NOT NULL DEFAULT 1,priority INTEGER NOT NULL DEFAULT 3,group_id TEXT,sub_group_id TEXT,top_port INTEGER,reason TEXT,source TEXT NOT NULL DEFAULT 'classifier',expires_at REAL,updated_at REAL DEFAULT (unixepoch('now')))''');"
            "sql='''INSERT INTO watchlist (src_ip,capture_depth,priority,group_id,sub_group_id,top_port,reason,source,expires_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(src_ip) DO UPDATE SET capture_depth=MAX(capture_depth,excluded.capture_depth),priority=MIN(priority,excluded.priority),group_id=excluded.group_id,sub_group_id=excluded.sub_group_id,top_port=excluded.top_port,reason=excluded.reason,source=CASE WHEN watchlist.source=\"xgb_scorer\" AND excluded.source=\"classifier\" THEN \"xgb_scorer\" ELSE excluded.source END,expires_at=excluded.expires_at,updated_at=excluded.updated_at''';"
            "now=time.time();dflt=now+30*86400;"
            "con.executemany(sql,[(r.get('src_ip'),int(r.get('capture_depth',1)),int(r.get('priority',3)),r.get('group_id'),r.get('sub_group_id'),r.get('top_port'),r.get('reason','classifier'),r.get('source','classifier'),r.get('expires_at',dflt),now) for r in rows]);"
            "con.commit();print(len(rows));"
        )
        cmd = "sudo -S python3 -c \"" + py + "\""
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=90)
        stdin.write(aio_pass + '\n')
        stdin.flush()
        code = stdout.channel.recv_exit_status()
        err = stderr.read().decode('utf-8', errors='ignore')
        if code != 0:
            raise RuntimeError(f'remote watchlist push failed ({code}): {err.strip()}')
        ssh.exec_command('rm -f /tmp/dfi2_watchlist.json')
    finally:
        ssh.close()


CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))


def _log_syncs(entries: list):
    """Log watchlist updates to ClickHouse watchlist_syncs table."""
    if not entries:
        return
    try:
        ch = Client(CH_HOST, port=CH_PORT)
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        rows = [
            {
                'attacker_ip': e.get('src_ip'),
                'capture_depth': int(e.get('capture_depth', 1)),
                'priority': int(e.get('priority', 3)),
                'group_id': e.get('group_id', ''),
                'sub_group_id': e.get('sub_group_id', ''),
                'source': e.get('source', 'classifier'),
                'reason': e.get('reason', ''),
                'expires_at': datetime.fromtimestamp(e['expires_at'], tz=timezone.utc) if e.get('expires_at') else None,
                'synced_at': now,
                'request_id': '',
            }
            for e in entries
            if e.get('src_ip')
        ]
        if rows:
            ch.execute('INSERT INTO dfi.watchlist_syncs VALUES', rows)
    except Exception as exc:
        log.warning('watchlist_syncs log failed: %s', exc)


def push_watchlist(entries: list, push_remote: bool = False):
    """Push to local watchlist and log sync events to ClickHouse."""
    push_local(entries)
    _log_syncs(entries)
