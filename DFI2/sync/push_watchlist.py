#!/usr/bin/env python3
import json
import logging
import os
import tempfile
from ipaddress import IPv4Address

import paramiko
from clickhouse_driver import Client

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import AIO_HOST, AIO_SSH_PORT, AIO_USER, WATCHLIST_DB_PATH

AIO_PASS = os.environ.get('AIO_PASS')


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)


def _ip_to_str(v):
    if isinstance(v, IPv4Address):
        return str(v)
    return str(v)


def fetch_group_assignments(ch: Client) -> dict:
    rows = ch.execute(
        """
        SELECT
            attacker_ip,
            argMax(group_id, assigned_at) as group_id,
            argMax(sub_group_id, assigned_at) as sub_group_id,
            argMax(priority, assigned_at) as priority
        FROM dfi.group_assignments
        WHERE assigned_at > now() - INTERVAL 24 HOUR
        GROUP BY attacker_ip
        """
    )

    out = {}
    for ip, group_id, sub_group_id, priority in rows:
        out[_ip_to_str(ip)] = {
            'group_id': group_id,
            'sub_group_id': sub_group_id,
            'priority': int(priority) if priority is not None else 3,
        }
    return out


def fetch_depth_changes(ch: Client) -> dict:
    rows = ch.execute(
        """
        SELECT
            attacker_ip,
            argMax(new_depth, changed_at) as capture_depth
        FROM dfi.depth_changes
        WHERE changed_at > now() - INTERVAL 24 HOUR
        GROUP BY attacker_ip
        """
    )

    out = {}
    for ip, capture_depth in rows:
        out[_ip_to_str(ip)] = int(capture_depth) if capture_depth is not None else 1
    return out


def build_watchlist_payload(groups: dict, depths: dict) -> list[dict]:
    ips = set(groups) | set(depths)
    payload = []
    for ip in sorted(ips):
        g = groups.get(ip, {})
        payload.append(
            {
                'src_ip': ip,
                'capture_depth': int(depths.get(ip, 1)),
                'priority': int(g.get('priority', 3)),
                'group_id': g.get('group_id'),
                'sub_group_id': g.get('sub_group_id'),
                'reason': 'sync_from_pv1_classifier',
                'source': 'classifier',
            }
        )
    return payload


def push_payload(payload: list[dict]) -> None:
    if not AIO_PASS:
        raise RuntimeError('missing required env var: AIO_PASS')

    remote_json = '/tmp/watchlist_push.json'

    with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as fp:
        json.dump(payload, fp)
        local_json = fp.name

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(AIO_HOST, port=AIO_SSH_PORT, username=AIO_USER, password=AIO_PASS, timeout=20)

    try:
        sftp = ssh.open_sftp()
        sftp.put(local_json, remote_json)
        sftp.close()

        remote_py = (
            "import json,sqlite3,sys,time;"
            f"db='{WATCHLIST_DB_PATH}';"
            "src='/tmp/watchlist_push.json';"
            "rows=json.load(open(src));"
            "con=sqlite3.connect(db);"
            "con.execute('PRAGMA journal_mode=WAL');"
            "con.execute('PRAGMA synchronous=NORMAL');"
            "con.execute('''CREATE TABLE IF NOT EXISTS watchlist ("
            "src_ip TEXT PRIMARY KEY, capture_depth INTEGER NOT NULL DEFAULT 1,"
            "priority INTEGER NOT NULL DEFAULT 3, group_id TEXT, sub_group_id TEXT,"
            "top_port INTEGER, reason TEXT, source TEXT NOT NULL DEFAULT \'classifier\',"
            "expires_at REAL, updated_at REAL DEFAULT (unixepoch(\'now\')) )''');"
            "con.execute('CREATE INDEX IF NOT EXISTS idx_wl_depth ON watchlist(capture_depth)');"
            "con.execute('CREATE INDEX IF NOT EXISTS idx_wl_expires ON watchlist(expires_at) WHERE expires_at IS NOT NULL');"
            "now=time.time();"
            "sql='''INSERT OR REPLACE INTO watchlist (src_ip,capture_depth,priority,group_id,sub_group_id,reason,source,updated_at) VALUES (?,?,?,?,?,?,?,?)''';"
            "con.executemany(sql,[(r.get('src_ip'),int(r.get('capture_depth',1)),int(r.get('priority',3)),"
            "r.get('group_id'),r.get('sub_group_id'),r.get('reason','sync_from_pv1_classifier'),"
            "r.get('source','classifier'),now) for r in rows]);"
            "con.commit();"
            "print(len(rows));"
        )

        cmd = f"sudo -S python3 -c \"{remote_py}\""
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
        if AIO_PASS:
            stdin.write(AIO_PASS + '\n')
            stdin.flush()
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if code != 0:
            raise RuntimeError(f'remote watchlist push failed ({code}): {err}')
        if err and 'password for' not in err.lower():
            raise RuntimeError(err)
        logging.info('pushed_watchlist_rows=%s', out or 0)

        ssh.exec_command('rm -f /tmp/watchlist_push.json')
    finally:
        ssh.close()
        try:
            os.unlink(local_json)
        except OSError:
            pass


def main() -> int:
    ch = Client('localhost')
    groups = fetch_group_assignments(ch)
    depths = fetch_depth_changes(ch)
    payload = build_watchlist_payload(groups, depths)
    push_payload(payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
