#!/usr/bin/env python3
import logging
import sqlite3
import threading
import time
from pathlib import Path


log = logging.getLogger('hunter.watchlist')


class WatchlistReader:
    def __init__(self, db_path: str, refresh_interval: int = 30):
        self.db_path = db_path
        self.refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self._entries = {}
        self._repromotions = {}
        self._last_refresh = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True, name='watchlist-refresh')

        self.refresh()
        self._thread.start()

    def lookup(self, ip: str) -> dict:
        now = time.time()
        if now - self._last_refresh > self.refresh_interval:
            try:
                self.refresh()
            except Exception as exc:
                log.warning('watchlist_refresh_failed err=%s', exc)

        with self._lock:
            row = self._entries.get(ip)
        if not row:
            return None

        expires_at = row.get('expires_at')
        if expires_at is not None and expires_at < now:
            return None
        return row

    def mark_repromotion(self, ip: str):
        with self._lock:
            self._repromotions[ip] = True

    def is_repromoted(self, ip: str) -> bool:
        with self._lock:
            return bool(self._repromotions.get(ip))

    def refresh(self):
        p = Path(self.db_path)
        if not p.exists():
            with self._lock:
                self._entries = {}
            return

        new_entries = {}
        conn = sqlite3.connect(f'file:{self.db_path}?mode=ro', uri=True, check_same_thread=False, timeout=5)
        try:
            cur = conn.execute(
                """
                SELECT src_ip, capture_depth, priority, group_id, top_port, expires_at
                FROM watchlist
                """
            )
            for src_ip, depth, priority, group_id, top_port, expires_at in cur.fetchall():
                new_entries[src_ip] = {
                    'capture_depth': int(depth or 1),
                    'priority': int(priority or 3),
                    'group_id': group_id,
                    'top_port': int(top_port) if top_port is not None else None,
                    'expires_at': float(expires_at) if expires_at is not None else None,
                }
        except sqlite3.OperationalError:
            # Table may not exist yet.
            new_entries = {}
        finally:
            conn.close()

        with self._lock:
            self._entries = new_entries
            self._repromotions = {}
            self._last_refresh = time.time()

    def promote_ip(self, ip: str, capture_depth: int, reason: str,
                   source: str = 'xgb_scorer', ttl_days: float = 30.0):
        """UPSERT ip into watchlist with given depth. Any new hit resets 30-day TTL."""
        now = time.time()
        expires_at = now + ttl_days * 86400
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            conn.execute("""
                INSERT INTO watchlist (src_ip, capture_depth, reason, source, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_ip) DO UPDATE SET
                    capture_depth = MAX(capture_depth, excluded.capture_depth),
                    reason = excluded.reason,
                    source = excluded.source,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
            """, (ip, capture_depth, reason, source, expires_at, now))
            conn.commit()
            conn.close()
        except Exception as exc:
            log.warning('promote_ip_failed ip=%s err=%s', ip, exc)
            return

        with self._lock:
            self._entries[ip] = {
                'capture_depth': capture_depth,
                'priority': 3,
                'group_id': None,
                'top_port': None,
                'expires_at': expires_at,
            }

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)

    def _refresh_loop(self):
        while not self._stop.is_set():
            if self._stop.wait(self.refresh_interval):
                break
            try:
                self.refresh()
            except Exception as exc:
                log.warning('watchlist_refresh_failed err=%s', exc)
