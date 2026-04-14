#!/usr/bin/env python3
"""
dfi-sensor-agent — Push evidence, attacker IPs, and flows to DFI Ingest API.

Replaces watchlist_pusher.py (SSH/paramiko) with HTTP POST.
Runs on every honeypot (LXC, KVM, VPS).

Reads:
  - trap.log for attacker IPs (CONNECT lines)
  - winlure.log for attacker IPs + evidence
  - winlure evidence.db for structured evidence events
  - (future) flow capture buffer

Pushes to Ingest API:
  - POST /ingest/watchlist — attacker IPs
  - POST /ingest/evidence — evidence events from SQLite

Config: /etc/dfi-sensor/agent.conf (YAML) or env vars.
"""
import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path

import requests
import yaml

LOG_DIR = "/opt/trap"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("sensor_agent")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CONF_PATH = os.environ.get('SENSOR_CONF', '/etc/dfi-sensor/agent.conf')

DEFAULT_CONF = {
    'api_url': 'http://172.16.3.113:81',
    'api_key': '',
    'sensor_id': os.uname().nodename or 'unknown',
    'push_interval': 60,
    'evidence_db': '/opt/winlure/state/evidence.db',
    'trap_log': '/opt/trap/trap.log',
    'winlure_log': '/opt/winlure/winlure.log',
    'dedup_db': '/opt/trap/pushed_ips.db',
    'dedup_hours': 1,
    'self_ip': '',
    'ignore_prefixes': ['192.168.', '172.16.3.', '10.', '169.254.', '127.'],
}


def load_conf():
    conf = dict(DEFAULT_CONF)
    if os.path.exists(CONF_PATH):
        with open(CONF_PATH) as f:
            user = yaml.safe_load(f) or {}
            conf.update(user)
    # Env overrides
    conf['api_url'] = os.environ.get('API_URL', conf['api_url'])
    conf['api_key'] = os.environ.get('API_KEY', conf['api_key'])
    conf['sensor_id'] = os.environ.get('SENSOR_ID', conf['sensor_id'])
    return conf

# ---------------------------------------------------------------------------
# IP extraction from logs (same patterns as watchlist_pusher.py)
# ---------------------------------------------------------------------------
RE_TRAP = re.compile(r'(?:TCP|UDP)\s+\S+\s+:\d+\s+<-\s+(\d+\.\d+\.\d+\.\d+):\d+')
RE_WINLURE = re.compile(r'(?:from|src[=:]|client[=:]|<-)\s*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)


def is_ignored(ip, conf):
    if ip == conf['self_ip'] or ip in ('127.0.0.1', '0.0.0.0'):
        return True
    for prefix in conf['ignore_prefixes']:
        if ip.startswith(prefix):
            return True
    return False


def extract_ips_from_log(path, pattern, conf, seen):
    """Tail-read log and extract new IPs."""
    ips = {}
    if not os.path.exists(path):
        return ips
    try:
        with open(path, 'r', errors='replace') as f:
            f.seek(0, 2)
            size = f.tell()
            # Read last 256KB
            start = max(0, size - 256 * 1024)
            f.seek(start)
            for line in f:
                m = pattern.search(line)
                if m:
                    ip = m.group(1)
                    if not is_ignored(ip, conf) and ip not in seen:
                        # Extract service from trap log
                        svc_m = re.search(r'(?:TCP|UDP)\s+(\S+)', line)
                        svc = svc_m.group(1) if svc_m else ''
                        ips[ip] = svc
    except Exception as e:
        log.warning("Failed to read %s: %s", path, e)
    return ips

# ---------------------------------------------------------------------------
# Dedup DB (same pattern as watchlist_pusher.py)
# ---------------------------------------------------------------------------
def init_dedup(path):
    con = sqlite3.connect(path, timeout=5)
    con.execute("PRAGMA journal_mode=WAL")
    # Handle both old schema (first_seen/last_seen) and new schema (ts)
    cols = [r[1] for r in con.execute("PRAGMA table_info(pushed)").fetchall()]
    if not cols:
        con.execute("CREATE TABLE pushed (ip TEXT PRIMARY KEY, ts REAL)")
    return con, 'last_seen' if 'last_seen' in cols else 'ts'


def is_recently_pushed(con, ip, hours, ts_col):
    cutoff = time.time() - hours * 3600
    row = con.execute(f"SELECT {ts_col} FROM pushed WHERE ip=? AND {ts_col}>?", (ip, cutoff)).fetchone()
    return row is not None


def mark_pushed(con, ips, ts_col):
    now = time.time()
    if ts_col == 'last_seen':
        con.executemany(
            "INSERT OR REPLACE INTO pushed (ip, first_seen, last_seen, hit_count) VALUES (?, ?, ?, 1)",
            [(ip, now, now) for ip in ips],
        )
    else:
        con.executemany(
            "INSERT OR REPLACE INTO pushed (ip, ts) VALUES (?, ?)",
            [(ip, now) for ip in ips],
        )
    con.commit()

# ---------------------------------------------------------------------------
# Evidence DB reader (reads winlure EvidenceCollector SQLite)
# ---------------------------------------------------------------------------
class EvidenceReader:
    def __init__(self, db_path, sensor_id):
        self.db_path = db_path
        self.sensor_id = sensor_id
        self.watermark = 0.0
        self._load_watermark()

    def _wm_path(self):
        return self.db_path + '.wm'

    def _load_watermark(self):
        try:
            if os.path.exists(self._wm_path()):
                self.watermark = float(open(self._wm_path()).read().strip())
        except Exception:
            pass

    def _save_watermark(self):
        try:
            with open(self._wm_path(), 'w') as f:
                f.write(str(self.watermark))
        except Exception:
            pass

    def read_new_events(self, batch_size=1000):
        if not os.path.exists(self.db_path):
            return []
        try:
            con = sqlite3.connect(self.db_path, timeout=5)
            # Check if events table exists
            has_table = con.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'"
            ).fetchone()[0]
            if not has_table:
                con.close()
                return []
            cur = con.execute(
                "SELECT ts, src_ip, src_port, dst_port, service, event_type, "
                "attack_phase, weight, details, tool_signature, persona "
                "FROM events WHERE ts > ? ORDER BY ts LIMIT ?",
                (self.watermark, batch_size),
            )
            rows = cur.fetchall()
            con.close()
            if rows:
                self.watermark = rows[-1][0]
                self._save_watermark()
            return rows
        except Exception as e:
            log.warning("Evidence DB read failed: %s", e)
            return []

# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------
class IngestClient:
    def __init__(self, api_url, api_key, sensor_id):
        self.api_url = api_url.rstrip('/')
        self.headers = {'Content-Type': 'application/json'}
        if api_key:
            self.headers['X-DFI-Key'] = api_key
        self.sensor_id = sensor_id
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def push_watchlist(self, ip_svc_map):
        if not ip_svc_map:
            return
        entries = [
            {
                'src_ip': ip,
                'capture_depth': 2,
                'priority': 1,
                'reason': f'honeypot:{self.sensor_id}:{svc}' if svc else f'honeypot:{self.sensor_id}',
                'source': 'honeypot',
            }
            for ip, svc in ip_svc_map.items()
        ]
        try:
            r = self.session.post(
                f'{self.api_url}/ingest/watchlist',
                json={'sensor_id': self.sensor_id, 'entries': entries},
                timeout=15,
            )
            if r.ok:
                log.info("Watchlist: pushed %d IPs", len(entries))
            else:
                log.warning("Watchlist push failed: %s %s", r.status_code, r.text[:200])
        except Exception as e:
            log.warning("Watchlist push error: %s", e)

    def push_evidence(self, rows):
        if not rows:
            return
        events = [
            {
                'ts': row[0],
                'src_ip': row[1],
                'target_ip': '0.0.0.0',
                'event_type': row[5],
                'event_detail': json.dumps({
                    'src_port': row[2], 'dst_port': row[3],
                    'service': row[4], 'attack_phase': row[6],
                    'weight': row[7], 'details': row[8],
                    'tool_signature': row[9], 'persona': row[10],
                }),
                'evidence_mask_bit': _phase_to_mask(row[6]),
                'source_program': f'winlure:{self.sensor_id}',
            }
            for row in rows
        ]
        try:
            r = self.session.post(
                f'{self.api_url}/ingest/evidence',
                json={'sensor_id': self.sensor_id, 'events': events},
                timeout=30,
            )
            if r.ok:
                log.info("Evidence: pushed %d events", len(events))
            else:
                log.warning("Evidence push failed: %s %s", r.status_code, r.text[:200])
        except Exception as e:
            log.warning("Evidence push error: %s", e)


def _phase_to_mask(phase):
    """Map attack phase to evidence_mask_bit."""
    return {
        'RECON': 0,
        'BRUTE_FORCE': 1,
        'EXPLOIT_ATTEMPT': 4,
        'POST_EXPLOIT': 6,
    }.get(phase, 0)

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main():
    conf = load_conf()
    log.info("=== dfi-sensor-agent starting ===")
    log.info("  API: %s", conf['api_url'])
    log.info("  Sensor: %s", conf['sensor_id'])
    log.info("  Push interval: %ds", conf['push_interval'])

    client = IngestClient(conf['api_url'], conf['api_key'], conf['sensor_id'])
    evidence = EvidenceReader(conf['evidence_db'], conf['sensor_id'])
    dedup_con, ts_col = init_dedup(conf['dedup_db'])

    while True:
        try:
            # 1. Collect attacker IPs from logs
            seen = set()
            ips = {}
            ips.update(extract_ips_from_log(conf['trap_log'], RE_TRAP, conf, seen))
            ips.update(extract_ips_from_log(conf['winlure_log'], RE_WINLURE, conf, seen))

            # 2. Dedup
            new_ips = {
                ip: svc for ip, svc in ips.items()
                if not is_recently_pushed(dedup_con, ip, conf['dedup_hours'], ts_col)
            }

            # 3. Push watchlist
            if new_ips:
                client.push_watchlist(new_ips)
                mark_pushed(dedup_con, new_ips.keys(), ts_col)
                log.info("Batch: %d new IPs, %d total seen", len(new_ips), len(ips))

            # 4. Push evidence
            ev_rows = evidence.read_new_events()
            if ev_rows:
                client.push_evidence(ev_rows)

        except Exception as e:
            log.error("Loop error: %s", e)

        time.sleep(conf['push_interval'])


if __name__ == '__main__':
    main()
