#!/usr/bin/env python3
"""Runs on AIO — pulls watchlist from PV1 via SSH and merges into local watchlist.db."""
import json
import logging
import os
import sqlite3
import time

import paramiko

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('watchlist_pull')

PV1_HOST = os.environ.get('PV1_HOST', '192.168.0.100')
PV1_PORT = int(os.environ.get('PV1_SSH_PORT', '22'))
PV1_USER = os.environ.get('PV1_USER', 'root')
PV1_PASS = os.environ.get('PV1_PASS', 'CHANGE_ME')
PV1_WATCHLIST = os.environ.get('PV1_WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')
LOCAL_WATCHLIST = os.environ.get('WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')
PULL_INTERVAL = int(os.environ.get('PULL_INTERVAL', '300'))

CREATE_SQL = '''CREATE TABLE IF NOT EXISTS watchlist (
    src_ip TEXT PRIMARY KEY,
    capture_depth INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 3,
    group_id TEXT,
    sub_group_id TEXT,
    top_port INTEGER,
    reason TEXT,
    source TEXT NOT NULL DEFAULT 'classifier',
    expires_at REAL,
    updated_at REAL DEFAULT (unixepoch('now')))'''

UPSERT_SQL = '''INSERT INTO watchlist
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
        expires_at = MAX(expires_at, excluded.expires_at),
        updated_at = excluded.updated_at'''

DUMP_PY = (
    "import json,sqlite3;"
    "con=sqlite3.connect('{db}',timeout=10);"
    "con.row_factory=sqlite3.Row;"
    "rows=[dict(r) for r in con.execute('SELECT * FROM watchlist').fetchall()];"
    "print(json.dumps(rows));"
    "con.close()"
)


def pull_and_merge():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(PV1_HOST, port=PV1_PORT, username=PV1_USER, password=PV1_PASS, timeout=15)
    try:
        cmd = "python3 -c \"" + DUMP_PY.format(db=PV1_WATCHLIST) + "\""
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
        code = stdout.channel.recv_exit_status()
        if code != 0:
            err = stderr.read().decode('utf-8', errors='ignore').strip()
            raise RuntimeError(f'remote dump failed ({code}): {err}')
        raw = stdout.read().decode('utf-8').strip()
    finally:
        ssh.close()

    if not raw:
        log.info('remote watchlist empty')
        return 0

    entries = json.loads(raw)
    if not entries:
        return 0

    conn = sqlite3.connect(LOCAL_WATCHLIST, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute(CREATE_SQL)
    now = time.time()
    conn.executemany(
        UPSERT_SQL,
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
                e.get('expires_at'),
                now,
            )
            for e in entries
        ],
    )
    conn.commit()
    conn.close()
    return len(entries)


def main():
    log.info('starting watchlist_pull pv1=%s:%s interval=%ds', PV1_HOST, PV1_PORT, PULL_INTERVAL)
    while True:
        try:
            n = pull_and_merge()
            if n:
                log.info('pulled watchlist entries=%d', n)
        except Exception as exc:
            log.error('pull_error err=%s', exc, exc_info=True)
        time.sleep(PULL_INTERVAL)


if __name__ == '__main__':
    main()
