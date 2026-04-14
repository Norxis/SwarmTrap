import hashlib
import json
import logging
import sqlite3
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clickhouse_driver import Client

log = logging.getLogger("dfi2.adapters")


@dataclass
class IdempotencyRecord:
    request_id: str
    payload_hash: str
    response_json: str


class SQLiteWatchlistAdapter:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS watchlist (
            src_ip          TEXT PRIMARY KEY,
            capture_depth   INTEGER NOT NULL DEFAULT 1,
            priority        INTEGER NOT NULL DEFAULT 3,
            group_id        TEXT,
            sub_group_id    TEXT,
            top_port        INTEGER,
            reason          TEXT,
            source          TEXT NOT NULL DEFAULT 'classifier',
            expires_at      REAL,
            updated_at      REAL DEFAULT (unixepoch('now'))
        )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS control_plane_requests (
            request_id      TEXT PRIMARY KEY,
            action          TEXT NOT NULL,
            payload_hash    TEXT NOT NULL,
            response_json   TEXT NOT NULL,
            created_at      REAL NOT NULL
        )"""
        )
        return conn

    @staticmethod
    def payload_hash(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def load_request(self, conn: sqlite3.Connection, request_id: str) -> IdempotencyRecord | None:
        row = conn.execute(
            "SELECT request_id, payload_hash, response_json FROM control_plane_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if not row:
            return None
        return IdempotencyRecord(request_id=row[0], payload_hash=row[1], response_json=row[2])

    def save_request(
        self,
        conn: sqlite3.Connection,
        *,
        request_id: str,
        action: str,
        payload_hash: str,
        response_json: str,
    ) -> None:
        conn.execute(
            """INSERT INTO control_plane_requests
               (request_id, action, payload_hash, response_json, created_at)
               VALUES (?,?,?,?,?)""",
            (request_id, action, payload_hash, response_json, time.time()),
        )

    def get_current_depth(self, conn: sqlite3.Connection, ip: str) -> int:
        row = conn.execute("SELECT capture_depth FROM watchlist WHERE src_ip=?", (ip,)).fetchone()
        return int(row[0]) if row else 1

    def upsert_watchlist(
        self,
        conn: sqlite3.Connection,
        *,
        ip: str,
        capture_depth: int,
        priority: int,
        group_id: str | None,
        sub_group_id: str | None,
        reason: str,
        source: str,
        expires_at: datetime | None,
    ) -> None:
        exp_ts = self._to_epoch(expires_at)
        conn.execute(
            """INSERT OR REPLACE INTO watchlist
               (src_ip,capture_depth,priority,group_id,sub_group_id,top_port,reason,source,expires_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                ip,
                int(capture_depth),
                int(priority),
                group_id,
                sub_group_id,
                None,
                reason,
                source,
                exp_ts,
                time.time(),
            ),
        )

    def delete_watchlist(self, conn: sqlite3.Connection, *, ip: str) -> bool:
        cur = conn.execute("DELETE FROM watchlist WHERE src_ip=?", (ip,))
        return cur.rowcount > 0

    def list_watchlist(self, conn: sqlite3.Connection, *, limit: int = 500) -> list[dict[str, Any]]:
        rows = conn.execute(
            """SELECT src_ip, capture_depth, priority, group_id, sub_group_id, reason, source, expires_at, updated_at
               FROM watchlist
               ORDER BY updated_at DESC
               LIMIT ?""",
            (int(limit),),
        ).fetchall()
        out = []
        for row in rows:
            out.append(
                {
                    "ip": row[0],
                    "capture_depth": int(row[1]),
                    "priority": int(row[2]),
                    "group_id": row[3],
                    "sub_group_id": row[4],
                    "reason": row[5],
                    "source": row[6],
                    "expires_at_epoch": row[7],
                    "updated_at_epoch": row[8],
                }
            )
        return out

    @staticmethod
    def _to_epoch(ts: datetime | None) -> float | None:
        if not ts:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.timestamp()


class ClickHouseLedgerAdapter:
    def __init__(self, host: str, port: int, recon_host: str = ""):
        self.client = Client(host, port=port)
        self._lock = threading.Lock()
        self._request_id_columns: dict[str, bool] = {}
        # GeoIP reader (lazy init)
        self._geoip_reader = None
        self._geoip_path = "/opt/dfi2/geoip/dbip-city-lite.mmdb"
        self._geoip_cache: dict[str, dict | None] = {}

    def _has_column(self, table: str, column: str) -> bool:
        key = f"{table}.{column}"
        if key in self._request_id_columns:
            return self._request_id_columns[key]
        rows = self.client.execute(
            "SELECT count() FROM system.columns WHERE database='dfi' AND table=%(t)s AND name=%(c)s",
            {"t": table, "c": column},
        )
        has_col = bool(rows and rows[0][0] > 0)
        self._request_id_columns[key] = has_col
        return has_col

    def _reconnect(self):
        """Force reconnect to ClickHouse."""
        try:
            self.client.disconnect()
        except Exception:
            pass

    def is_active(self, ip: str, active_window_sec: int) -> bool:
        rows = self.client.execute(
            """SELECT count()
               FROM dfi.flows
               WHERE src_ip = %(ip)s
                 AND first_ts >= now() - INTERVAL %(sec)s SECOND""",
            {"ip": ip, "sec": int(active_window_sec)},
        )
        return bool(rows and rows[0][0] > 0)

    def log_analyst_action(
        self,
        *,
        ip: str,
        action_type: str,
        capture_depth: int | None,
        priority: int | None,
        reason: str,
        actor: str,
        expires_at: datetime | None,
        request_id: str | None = None,
    ) -> None:
        exp = self._to_utc(expires_at)
        row = {
            "attacker_ip": ip,
            "action_type": action_type,
            "capture_depth": capture_depth,
            "priority": priority,
            "reason": reason,
            "analyst_id": actor,
            "expires_at": exp,
        }
        if request_id and self._has_column("analyst_actions", "request_id"):
            row["request_id"] = request_id
        cols = "attacker_ip, action_type, capture_depth, priority, reason, analyst_id, expires_at, request_id"
        row.setdefault("request_id", "")
        self.client.execute(f"INSERT INTO dfi.analyst_actions ({cols}) VALUES", [row])

    def log_depth_change(
        self,
        *,
        ip: str,
        old_depth: int,
        new_depth: int,
        reason: str,
        triggered_by: str,
        request_id: str | None = None,
    ) -> None:
        row = {
            "attacker_ip": ip,
            "old_depth": int(old_depth),
            "new_depth": int(new_depth),
            "trigger_reason": reason,
            "triggered_by": triggered_by,
        }
        if request_id and self._has_column("depth_changes", "request_id"):
            row["request_id"] = request_id
        cols = "attacker_ip, old_depth, new_depth, trigger_reason, triggered_by, request_id"
        row.setdefault("request_id", "")
        self.client.execute(f"INSERT INTO dfi.depth_changes ({cols}) VALUES", [row])

    def log_watchlist_sync(
        self,
        *,
        ip: str,
        capture_depth: int,
        priority: int,
        group_id: str | None,
        sub_group_id: str | None,
        source: str,
        reason: str,
        expires_at: datetime | None,
        request_id: str | None = None,
    ) -> None:
        exp = self._to_utc(expires_at)
        row = {
            "attacker_ip": ip,
            "capture_depth": int(capture_depth),
            "priority": int(priority),
            "group_id": group_id or "",
            "sub_group_id": sub_group_id or "",
            "source": source,
            "reason": reason,
            "expires_at": exp,
        }
        if request_id and self._has_column("watchlist_syncs", "request_id"):
            row["request_id"] = request_id
        cols = "attacker_ip, capture_depth, priority, group_id, sub_group_id, source, reason, expires_at, request_id"
        row.setdefault("request_id", "")
        self.client.execute(f"INSERT INTO dfi.watchlist_syncs ({cols}) VALUES", [row])

    def resolve_campaign_ips(self, campaign_id: str, max_ips: int) -> list[str]:
        # Preferred source if a campaign table exists.
        table_exists = self.client.execute(
            "SELECT count() FROM system.tables WHERE database='dfi' AND name='campaign_members'"
        )[0][0]
        if table_exists:
            rows = self.client.execute(
                "SELECT DISTINCT attacker_ip FROM dfi.campaign_members WHERE campaign_id=%(cid)s LIMIT %(lim)s",
                {"cid": campaign_id, "lim": int(max_ips)},
            )
            return [str(r[0]) for r in rows]

        # Fallback: parse campaign_id from group_assignments.feature_summary JSON.
        rows = self.client.execute(
            """SELECT DISTINCT attacker_ip
               FROM dfi.group_assignments
               WHERE JSONExtractString(feature_summary, 'campaign_id') = %(cid)s
               ORDER BY assigned_at DESC
               LIMIT %(lim)s""",
            {"cid": campaign_id, "lim": int(max_ips)},
        )
        return [str(r[0]) for r in rows]

    # ---- Read-only data endpoints ----

    def query_audit_log(self, limit: int = 200) -> list[dict]:
        try:
            rows = self.client.execute(
                f"SELECT toInt64(acted_at) AS ts, attacker_ip AS ip,"
                f"       action_type AS action,"
                f"       toString(capture_depth) AS new_val, '' AS old_val,"
                f"       analyst_id AS actor, reason, request_id, 'analyst' AS source"
                f" FROM dfi.analyst_actions"
                f" UNION ALL"
                f" SELECT toInt64(changed_at) AS ts, attacker_ip AS ip,"
                f"       'DEPTH_CHANGE' AS action,"
                f"       toString(new_depth) AS new_val, toString(old_depth) AS old_val,"
                f"       triggered_by AS actor, trigger_reason AS reason, request_id, 'system' AS source"
                f" FROM dfi.depth_changes"
                f" ORDER BY ts DESC LIMIT {limit}"
            )
            return [
                {
                    "timestamp": int(r[0]),
                    "ip": str(r[1]),
                    "action": str(r[2]),
                    "new_val": str(r[3]),
                    "old_val": str(r[4]),
                    "actor": str(r[5]),
                    "reason": str(r[6]),
                    "request_id": str(r[7]) if r[7] else "",
                    "source": str(r[8]),
                }
                for r in rows
            ]
        except Exception as exc:
            log.exception("query_audit_log failed: %s", exc)
            return []

    def query_vm_flows(self, pub_ips: list[str], hours: int = 24) -> dict[str, dict]:
        try:
            if not pub_ips:
                return {}
            ip_list = ", ".join(f"'{ip}'" for ip in pub_ips)
            rows = self.client.execute(
                f"SELECT dst_ip, count() AS flows, uniq(src_ip) AS attackers"
                f" FROM dfi.flows"
                f" WHERE first_ts >= now() - INTERVAL {hours} HOUR"
                f"   AND actor_id != 'norm'"
                f"   AND dst_ip IN ({ip_list})"
                f" GROUP BY dst_ip"
            )
            return {str(r[0]): {"flows_24h": int(r[1]), "attackers_24h": int(r[2])} for r in rows}
        except Exception as exc:
            log.exception("query_vm_flows failed: %s", exc)
            return {}

    def query_vm_events(self, pub_ip: str, limit: int = 100) -> list[dict]:
        try:
            rows = self.client.execute(
                f"SELECT toInt64(ts) AS ts_epoch, src_ip, event_type, event_detail, source_log"
                f" FROM dfi.evidence_events"
                f" WHERE target_ip = %(ip)s AND ts >= now() - INTERVAL 24 HOUR"
                f" ORDER BY ts DESC LIMIT {limit}",
                {"ip": pub_ip},
            )
            return [
                {
                    "ts": int(r[0]),
                    "src_ip": str(r[1]),
                    "event_type": str(r[2]),
                    "event_detail": str(r[3]),
                    "source_log": str(r[4]),
                }
                for r in rows
            ]
        except Exception as exc:
            log.exception("query_vm_events failed: %s", exc)
            return []

    # ---- ML stats ----

    LABEL_MAP = {0: "NORM", 1: "RECON", 2: "KNOCK", 3: "BRUTE", 4: "EXPLOIT", 5: "NORM"}

    def query_ml_stats(self, model_name: str, ml_metrics_dir: str) -> dict:
        try:
            # --- Load model metadata + feature importance from JSON on disk ---
            meta = {
                "model_name": model_name,
                "version": "unknown",
                "trained_at": "",
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "feature_importance": [],
            }
            metrics_path = Path(ml_metrics_dir) / model_name / "metrics.json"
            try:
                with open(metrics_path, "r") as fh:
                    meta.update(json.load(fh))
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            # --- Total predictions in 24h ---
            rows = self.client.execute(
                "SELECT count() FROM dfi.model_predictions"
                " WHERE model_name = %(model_name)s"
                "   AND scored_at >= now() - INTERVAL 24 HOUR",
                {"model_name": model_name},
            )
            total_24h = int(rows[0][0]) if rows else 0

            # --- Attack rate in 24h ---
            rows = self.client.execute(
                "SELECT countIf(predicted_label = 1) FROM dfi.model_predictions"
                " WHERE model_name = %(model_name)s"
                "   AND scored_at >= now() - INTERVAL 24 HOUR",
                {"model_name": model_name},
            )
            attack_count = int(rows[0][0]) if rows else 0
            attack_rate = attack_count / total_24h if total_24h > 0 else 0.0

            # --- Confusion matrix ---
            rows = self.client.execute(
                "SELECT actual_label, predicted_label, count() AS cnt"
                " FROM dfi.model_predictions"
                " WHERE model_name = %(model_name)s"
                "   AND scored_at >= now() - INTERVAL 24 HOUR"
                " GROUP BY actual_label, predicted_label",
                {"model_name": model_name},
            )
            confusion_matrix = [
                {
                    "actual": self.LABEL_MAP.get(int(r[0]), str(r[0])),
                    "predicted": self.LABEL_MAP.get(int(r[1]), str(r[1])),
                    "count": int(r[2]),
                }
                for r in rows
            ]

            # --- Scoring throughput: hourly for last 24h ---
            rows = self.client.execute(
                "SELECT toStartOfHour(scored_at) AS hour,"
                "       count() AS predictions,"
                "       countIf(predicted_label = 1) AS attacks"
                " FROM dfi.model_predictions"
                " WHERE model_name = %(model_name)s"
                "   AND scored_at >= now() - INTERVAL 24 HOUR"
                " GROUP BY hour ORDER BY hour",
                {"model_name": model_name},
            )
            scoring_throughput = [
                {
                    "hour": str(r[0]),
                    "predictions": int(r[1]),
                    "attacks": int(r[2]),
                }
                for r in rows
            ]

            # --- Label distribution ---
            rows = self.client.execute(
                "SELECT predicted_label, count() AS cnt"
                " FROM dfi.model_predictions"
                " WHERE model_name = %(model_name)s"
                "   AND scored_at >= now() - INTERVAL 24 HOUR"
                " GROUP BY predicted_label",
                {"model_name": model_name},
            )
            label_distribution = {
                self.LABEL_MAP.get(int(r[0]), str(r[0])): int(r[1])
                for r in rows
            }

            return {
                "model_name": meta["model_name"],
                "version": meta["version"],
                "trained_at": meta["trained_at"],
                "accuracy": meta["accuracy"],
                "precision": meta["precision"],
                "recall": meta["recall"],
                "f1": meta["f1"],
                "total_predictions_24h": total_24h,
                "attack_rate_24h": attack_rate,
                "confusion_matrix": confusion_matrix,
                "feature_importance": meta.get("feature_importance", []),
                "scoring_throughput": scoring_throughput,
                "label_distribution": label_distribution,
            }
        except Exception as exc:
            log.exception("query_ml_stats(%s) failed: %s", model_name, exc)
            return {
                "model_name": model_name,
                "version": "unknown",
                "trained_at": "",
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "total_predictions_24h": 0,
                "attack_rate_24h": 0.0,
                "confusion_matrix": [],
                "feature_importance": [],
                "scoring_throughput": [],
                "label_distribution": {},
            }

    @staticmethod
    def _to_utc(ts: datetime | None) -> datetime | None:
        if not ts:
            return None
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

    # ---------------------------------------------------------------------------
    # GeoIP + Attack Map
    # ---------------------------------------------------------------------------

    def _geoip_lookup(self, ip: str) -> dict | None:
        """Return {"country": str, "country_code": str, "lat": float, "lng": float} or None."""
        if ip in self._geoip_cache:
            return self._geoip_cache[ip]

        # Lazy-load the GeoIP reader
        if self._geoip_reader is None:
            try:
                import geoip2.database
                self._geoip_reader = geoip2.database.Reader(self._geoip_path)
            except Exception as exc:
                log.warning("GeoIP reader init failed: %s", exc)
                return None

        try:
            resp = self._geoip_reader.city(ip)
            result = {
                "country": resp.country.name or "Unknown",
                "country_code": resp.country.iso_code or "XX",
                "lat": float(resp.location.latitude or 0.0),
                "lng": float(resp.location.longitude or 0.0),
            }
        except Exception:
            result = None

        # Cache with eviction at 10K entries
        if len(self._geoip_cache) >= 10000:
            self._geoip_cache.clear()
        self._geoip_cache[ip] = result
        return result

    def query_map_events(self, hours: int = 1, limit: int = 500) -> dict:
        with self._lock:
            for attempt in range(3):
                try:
                    return self._query_map_events_inner(hours, limit)
                except Exception as exc:
                    log.warning("query_map_events attempt %d/3 failed: %s: %s",
                                attempt + 1, type(exc).__name__, exc)
                    self._reconnect()
                    time.sleep(1)
            return {"attackers": [], "honeypots": [], "total_attacks": 0}

    def _query_map_events_inner(self, hours: int, limit: int) -> dict:
        rows = self.client.execute(
            "SELECT src_ip,"
            "       max(label) AS max_label,"
            "       count() AS flow_count,"
            "       toInt64(min(first_ts)) AS min_ts,"
            "       toInt64(max(first_ts)) AS max_ts,"
            "       groupUniqArray(10)(dst_port) AS top_ports,"
            "       uniqExact(dst_ip) AS target_count"
            " FROM dfi.flows"
            f" WHERE first_ts >= now() - INTERVAL {int(hours)} HOUR"
            "   AND label > 0"
            "   AND NOT isIPAddressInRange(toString(src_ip), '10.0.0.0/8')"
            "   AND NOT isIPAddressInRange(toString(src_ip), '172.16.0.0/12')"
            "   AND NOT isIPAddressInRange(toString(src_ip), '192.168.0.0/16')"
            " GROUP BY src_ip"
            " ORDER BY flow_count DESC"
            f" LIMIT {int(limit)}",
            settings={"max_execution_time": 15},
        )

        attackers = []
        total_attacks = 0
        for r in rows:
            ip_str = str(r[0])
            flow_count = int(r[2])
            total_attacks += flow_count
            geo = self._geoip_lookup(ip_str)
            entry = {
                "src_ip": ip_str,
                "label": int(r[1]),
                "flow_count": flow_count,
                "first_ts": int(r[3]),
                "last_ts": int(r[4]),
                "top_ports": [int(p) for p in (r[5] or [])],
                "target_count": int(r[6]),
                "country": geo["country"] if geo else "Unknown",
                "country_code": geo["country_code"] if geo else "XX",
                "lat": geo["lat"] if geo else 0.0,
                "lng": geo["lng"] if geo else 0.0,
            }
            attackers.append(entry)

        # Honeypot destination IPs — distinct dst_ips from the attack flows
        hp_rows = self.client.execute(
            "SELECT dst_ip, count() AS cnt"
            " FROM dfi.flows"
            f" WHERE first_ts >= now() - INTERVAL {int(hours)} HOUR"
            "   AND label > 0"
            " GROUP BY dst_ip"
            " ORDER BY cnt DESC"
            " LIMIT 50",
            settings={"max_execution_time": 10},
        )
        honeypots = []
        for r in hp_rows:
            hp_ip = str(r[0])
            geo = self._geoip_lookup(hp_ip)
            honeypots.append({
                "ip": hp_ip,
                "flow_count": int(r[1]),
                "country": geo["country"] if geo else "Unknown",
                "country_code": geo["country_code"] if geo else "XX",
                "lat": geo["lat"] if geo else 0.0,
                "lng": geo["lng"] if geo else 0.0,
            })

        return {
            "attackers": attackers,
            "honeypots": honeypots,
            "total_attacks": total_attacks,
        }

    def query_attack_heatmap(self, days: int = 7) -> dict:
        """Return 7x24 attack count matrix (day-of-week x hour-of-day)."""
        with self._lock:
            for _attempt in range(3):
                try:
                    return self._query_attack_heatmap_inner(days)
                except Exception as exc:
                    log.warning("query_attack_heatmap attempt %d/3 failed: %s: %s",
                                _attempt + 1, type(exc).__name__, exc)
                    self._reconnect()
                    time.sleep(0.5)
        return {"heatmap": {}}

    def _query_attack_heatmap_inner(self, days: int) -> dict:
        rows = self.client.execute(
            "SELECT toDayOfWeek(first_ts) - 1 AS dow,"
            "       toHour(first_ts) AS hour,"
            "       count() AS cnt"
            " FROM dfi.flows"
            f" WHERE first_ts >= now() - INTERVAL {int(days)} DAY"
            "   AND label > 0"
            " GROUP BY dow, hour"
            " ORDER BY dow, hour",
            settings={"max_execution_time": 10},
        )
        heatmap: dict[str, int] = {}
        for r in rows:
            key = f"{int(r[0])}:{int(r[1])}"
            heatmap[key] = int(r[2])
        return {"heatmap": heatmap}

    def query_top_countries(self, hours: int = 24, limit: int = 10) -> dict:
        """Return top countries by attack count with GeoIP."""
        with self._lock:
            for _attempt in range(3):
                try:
                    return self._query_top_countries_inner(hours, limit)
                except Exception as exc:
                    log.warning("query_top_countries attempt %d/3 failed: %s: %s",
                                _attempt + 1, type(exc).__name__, exc)
                    self._reconnect()
                    time.sleep(0.5)
        return {"countries": []}

    def _query_top_countries_inner(self, hours: int, limit: int) -> dict:
        rows = self.client.execute(
            "SELECT src_ip, count() AS cnt"
            " FROM dfi.flows"
            f" WHERE first_ts >= now() - INTERVAL {int(hours)} HOUR"
            "   AND label > 0"
            "   AND NOT isIPAddressInRange(toString(src_ip), '10.0.0.0/8')"
            "   AND NOT isIPAddressInRange(toString(src_ip), '172.16.0.0/12')"
            "   AND NOT isIPAddressInRange(toString(src_ip), '192.168.0.0/16')"
            " GROUP BY src_ip"
            " ORDER BY cnt DESC"
            " LIMIT 5000",
            settings={"max_execution_time": 10},
        )
        # Aggregate by country using GeoIP
        country_agg: dict[str, dict] = {}
        for r in rows:
            ip = str(r[0])
            cnt = int(r[1])
            geo = self._geoip_lookup(ip)
            cc = geo["country_code"] if geo else "XX"
            name = geo["country"] if geo else "Unknown"
            if cc not in country_agg:
                country_agg[cc] = {"country": name, "country_code": cc, "attacks": 0, "unique_ips": 0}
            country_agg[cc]["attacks"] += cnt
            country_agg[cc]["unique_ips"] += 1

        countries = sorted(country_agg.values(), key=lambda x: x["attacks"], reverse=True)[:limit]
        return {"countries": countries}
