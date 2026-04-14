"""SQLite WAL buffer — all tables per spec Module 4.

Thread-safe via threading.local() — one connection per thread.
Schema matches spec exactly: individual feature columns, ISO 8601 timestamps.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("winhunt.buffer")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ts_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    vm_id         TEXT NOT NULL,
    source_ip     TEXT,
    source_port   INTEGER DEFAULT 0,
    service       TEXT NOT NULL DEFAULT 'system',
    event_type    TEXT NOT NULL,
    evidence_bits INTEGER NOT NULL DEFAULT 0,
    raw_event_id  INTEGER,
    raw_channel   TEXT,
    detail_json   TEXT,
    pulled        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_pulled ON events (pulled, seq);

CREATE TABLE IF NOT EXISTS pcap_flows (
    flow_id            TEXT PRIMARY KEY,
    session_key        TEXT NOT NULL,
    src_ip             TEXT NOT NULL,
    dst_ip             TEXT NOT NULL,
    src_port           INTEGER NOT NULL,
    dst_port           INTEGER NOT NULL,
    ip_proto           INTEGER NOT NULL,
    app_proto          INTEGER NOT NULL DEFAULT 0,
    first_ts           TEXT NOT NULL,
    last_ts            TEXT NOT NULL,
    pkts_fwd           INTEGER NOT NULL,
    pkts_rev           INTEGER NOT NULL,
    bytes_fwd          INTEGER NOT NULL,
    bytes_rev          INTEGER NOT NULL,
    bytes_per_pkt_fwd  REAL,
    bytes_per_pkt_rev  REAL,
    pkt_ratio          REAL,
    byte_ratio         REAL,
    rtt_ms             REAL,
    duration_ms        INTEGER NOT NULL,
    iat_fwd_mean_ms    REAL,
    iat_fwd_std_ms     REAL,
    think_time_mean_ms REAL,
    think_time_std_ms  REAL,
    iat_to_rtt         REAL,
    pps                REAL NOT NULL,
    bps                REAL NOT NULL,
    payload_rtt_ratio  REAL,
    n_events           INTEGER NOT NULL,
    fwd_size_mean      REAL,
    fwd_size_std       REAL,
    fwd_size_min       INTEGER NOT NULL DEFAULT 0,
    fwd_size_max       INTEGER NOT NULL DEFAULT 0,
    rev_size_mean      REAL,
    rev_size_std       REAL,
    rev_size_max       INTEGER NOT NULL DEFAULT 0,
    hist_tiny          INTEGER NOT NULL DEFAULT 0,
    hist_small         INTEGER NOT NULL DEFAULT 0,
    hist_medium        INTEGER NOT NULL DEFAULT 0,
    hist_large         INTEGER NOT NULL DEFAULT 0,
    hist_full          INTEGER NOT NULL DEFAULT 0,
    frac_full          REAL NOT NULL DEFAULT 0,
    syn_count          INTEGER NOT NULL DEFAULT 0,
    fin_count          INTEGER NOT NULL DEFAULT 0,
    rst_count          INTEGER NOT NULL DEFAULT 0,
    psh_count          INTEGER NOT NULL DEFAULT 0,
    ack_only_count     INTEGER NOT NULL DEFAULT 0,
    conn_state         INTEGER NOT NULL DEFAULT 0,
    rst_frac           REAL,
    syn_to_data        INTEGER NOT NULL DEFAULT 0,
    psh_burst_max      INTEGER NOT NULL DEFAULT 0,
    retransmit_est     INTEGER NOT NULL DEFAULT 0,
    window_size_init   INTEGER NOT NULL DEFAULT 0,
    entropy_first      REAL,
    entropy_fwd_mean   REAL,
    entropy_rev_mean   REAL,
    printable_frac     REAL,
    null_frac          REAL,
    byte_std           REAL,
    high_entropy_frac  REAL,
    payload_len_first  INTEGER NOT NULL DEFAULT 0,
    src_mac            TEXT NOT NULL DEFAULT '',
    dst_mac            TEXT NOT NULL DEFAULT '',
    vlan_id            INTEGER NOT NULL DEFAULT 0,
    capture_source     INTEGER NOT NULL DEFAULT 1,
    emitted_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    pulled             INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_pulled ON pcap_flows (pulled, emitted_at);
CREATE INDEX IF NOT EXISTS idx_flows_src    ON pcap_flows (src_ip, first_ts);

CREATE TABLE IF NOT EXISTS pcap_packets (
    flow_id         TEXT    NOT NULL,
    seq_idx         INTEGER NOT NULL,
    ts              TEXT    NOT NULL,
    direction       INTEGER NOT NULL,
    payload_len     INTEGER NOT NULL,
    pkt_len         INTEGER NOT NULL,
    tcp_flags       INTEGER NOT NULL,
    tcp_window      INTEGER NOT NULL DEFAULT 0,
    size_dir_token  INTEGER NOT NULL,
    flag_token      INTEGER NOT NULL,
    iat_log_ms_bin  INTEGER NOT NULL,
    iat_rtt_bin     INTEGER NOT NULL,
    entropy_bin     INTEGER NOT NULL DEFAULT 0,
    iat_ms          REAL,
    payload_entropy REAL,
    pulled          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (flow_id, seq_idx)
);
CREATE INDEX IF NOT EXISTS idx_pkts_pulled ON pcap_packets (pulled, flow_id);

CREATE TABLE IF NOT EXISTS pcap_fingerprints (
    flow_id          TEXT PRIMARY KEY,
    ja3_hash         TEXT,
    tls_version      INTEGER NOT NULL DEFAULT 0,
    tls_cipher_count INTEGER NOT NULL DEFAULT 0,
    tls_ext_count    INTEGER NOT NULL DEFAULT 0,
    tls_has_sni      INTEGER NOT NULL DEFAULT 0,
    hassh_hash       TEXT,
    ssh_kex_count    INTEGER NOT NULL DEFAULT 0,
    http_method      INTEGER NOT NULL DEFAULT 0,
    http_uri_len     INTEGER NOT NULL DEFAULT 0,
    http_header_count INTEGER NOT NULL DEFAULT 0,
    http_ua_hash     TEXT,
    http_has_body    INTEGER NOT NULL DEFAULT 0,
    http_status      INTEGER NOT NULL DEFAULT 0,
    dns_qtype        INTEGER NOT NULL DEFAULT 0,
    dns_qname_len    INTEGER NOT NULL DEFAULT 0,
    pulled           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS source_stats (
    src_ip       TEXT PRIMARY KEY,
    flow_count   INTEGER NOT NULL DEFAULT 0,
    unique_ports TEXT NOT NULL DEFAULT '[]',
    unique_protos TEXT NOT NULL DEFAULT '[]',
    unique_dsts  TEXT NOT NULL DEFAULT '[]',
    first_seen   TEXT,
    last_seen    TEXT,
    sum_pps      REAL NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS logon_map (
    logon_id   TEXT PRIMARY KEY,
    source_ip  TEXT NOT NULL,
    service    TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    obs_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    vm_id         TEXT NOT NULL,
    obs_type      TEXT NOT NULL,
    session_id    TEXT,
    source_ip     TEXT,
    process_pid   INTEGER,
    evidence_bits INTEGER NOT NULL DEFAULT 0,
    priority      TEXT NOT NULL DEFAULT 'normal',
    detail_json   TEXT,
    pulled        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_obs_pulled ON observations (pulled, obs_id);
CREATE INDEX IF NOT EXISTS idx_obs_session ON observations (session_id, ts);

CREATE TABLE IF NOT EXISTS file_baseline (
    path        TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    mtime       REAL NOT NULL,
    baseline_ts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS breadcrumbs (
    breadcrumb_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_type TEXT NOT NULL,
    planted_path    TEXT NOT NULL,
    target_service  TEXT,
    target_host     TEXT,
    planted_at      TEXT NOT NULL,
    consumed_at     TEXT,
    consumer_ip     TEXT
);

CREATE TABLE IF NOT EXISTS predictions (
    pred_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id             TEXT NOT NULL,
    ts                  TEXT NOT NULL,
    vm_id               TEXT NOT NULL,
    src_ip              TEXT,
    dst_port            INTEGER,
    prediction          INTEGER NOT NULL,
    label_name          TEXT NOT NULL,
    confidence          REAL NOT NULL,
    probabilities       TEXT,
    feature_completeness REAL,
    packets_seen        INTEGER,
    prediction_number   INTEGER NOT NULL DEFAULT 1,
    is_final            INTEGER NOT NULL DEFAULT 0,
    model_version       TEXT,
    pulled              INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pred_pulled ON predictions (pulled, pred_id);
CREATE INDEX IF NOT EXISTS idx_pred_flow ON predictions (flow_id, prediction_number);

CREATE TABLE IF NOT EXISTS corrections (
    corr_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id         TEXT NOT NULL,
    ts              TEXT NOT NULL,
    predicted_label INTEGER NOT NULL,
    evidence_label  INTEGER NOT NULL,
    evidence_bits   INTEGER NOT NULL,
    feature_vector  TEXT
);

CREATE TABLE IF NOT EXISTS model_performance (
    date              TEXT PRIMARY KEY,
    model_version     TEXT,
    predictions_total INTEGER NOT NULL DEFAULT 0,
    confirmed         INTEGER NOT NULL DEFAULT 0,
    contradicted      INTEGER NOT NULL DEFAULT 0,
    per_class_json    TEXT
);
"""

# Flow columns for INSERT (excluding flow_id and emitted_at/pulled which have defaults)
_FLOW_COLS = [
    "flow_id", "session_key", "src_ip", "dst_ip", "src_port", "dst_port",
    "ip_proto", "app_proto", "first_ts", "last_ts",
    "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
    "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
    "rtt_ms", "duration_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
    "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt",
    "pps", "bps", "payload_rtt_ratio",
    "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
    "rev_size_mean", "rev_size_std", "rev_size_max",
    "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count",
    "conn_state", "rst_frac", "syn_to_data", "psh_burst_max",
    "retransmit_est", "window_size_init",
    "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
    "printable_frac", "null_frac", "byte_std", "high_entropy_frac",
    "payload_len_first",
    "src_mac", "dst_mac", "vlan_id",
    "capture_source",
]

_FLOW_INSERT = (
    f"INSERT OR REPLACE INTO pcap_flows ({','.join(_FLOW_COLS)}) "
    f"VALUES ({','.join('?' for _ in _FLOW_COLS)})"
)

_PKT_COLS = [
    "flow_id", "seq_idx", "ts", "direction", "payload_len", "pkt_len",
    "tcp_flags", "tcp_window", "size_dir_token", "flag_token",
    "iat_log_ms_bin", "iat_rtt_bin", "entropy_bin", "iat_ms", "payload_entropy",
]

_PKT_INSERT = (
    f"INSERT OR REPLACE INTO pcap_packets ({','.join(_PKT_COLS)}) "
    f"VALUES ({','.join('?' for _ in _PKT_COLS)})"
)

_FP_COLS = [
    "flow_id", "ja3_hash", "tls_version", "tls_cipher_count", "tls_ext_count",
    "tls_has_sni", "hassh_hash", "ssh_kex_count",
    "http_method", "http_uri_len", "http_header_count", "http_ua_hash",
    "http_has_body", "http_status", "dns_qtype", "dns_qname_len",
]

_FP_INSERT = (
    f"INSERT OR REPLACE INTO pcap_fingerprints ({','.join(_FP_COLS)}) "
    f"VALUES ({','.join('?' for _ in _FP_COLS)})"
)


class AgentBuffer:
    """Thread-safe SQLite buffer using threading.local() for connections."""

    def __init__(self, db_path: str, vm_id: str = ""):
        self.db_path = db_path
        self.vm_id = vm_id
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema(self._get_conn())

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA wal_autocheckpoint=1000")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(_SCHEMA)
        self._migrate_schema(conn)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Forward-only column additions for existing DBs."""
        new_cols = [
            ("pcap_flows", "bytes_per_pkt_fwd", "REAL"),
            ("pcap_flows", "bytes_per_pkt_rev", "REAL"),
            ("pcap_flows", "pkt_ratio",          "REAL"),
            ("pcap_flows", "byte_ratio",          "REAL"),
        ]
        for table, col, typ in new_cols:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # already exists

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn:
            conn.close()
            self._local.conn = None

    # ── Events ──

    def insert_event(self, ts: float, vm_id: str, source_ip: str | None,
                     source_port: int, service: str, event_type: str,
                     evidence_bits: int, raw_event_id: int | None,
                     raw_channel: str | None, detail: dict[str, Any] | None) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute(
                "INSERT INTO events(ts,vm_id,source_ip,source_port,service,event_type,"
                "evidence_bits,raw_event_id,raw_channel,detail_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (_ts_to_iso(ts), vm_id, source_ip, source_port, service,
                 event_type, evidence_bits, raw_event_id, raw_channel,
                 json.dumps(detail, separators=(",", ":")) if detail else None),
            )
            return cur.lastrowid or 0

    def get_events(self, since_seq: int = 0, limit: int = 5000, pulled: int | None = None) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if pulled is not None:
            return conn.execute(
                "SELECT * FROM events WHERE pulled=? AND seq>? ORDER BY seq LIMIT ?",
                (pulled, since_seq, limit),
            ).fetchall()
        return conn.execute(
            "SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?",
            (since_seq, limit),
        ).fetchall()

    def ack_events(self, through_seq: int) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute("UPDATE events SET pulled=1 WHERE seq<=? AND pulled=0", (through_seq,))
            return cur.rowcount

    # ── Flows ──

    def insert_flow(self, flow: dict[str, Any]) -> str:
        conn = self._get_conn()
        vals = [flow.get(c) for c in _FLOW_COLS]
        with conn:
            conn.execute(_FLOW_INSERT, vals)
        return flow.get("flow_id", "")

    def get_flows(self, since_ts: str | None = None, limit: int = 5000, pulled: int = 0) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if since_ts:
            return conn.execute(
                "SELECT * FROM pcap_flows WHERE pulled=? AND emitted_at>? ORDER BY emitted_at LIMIT ?",
                (pulled, since_ts, limit),
            ).fetchall()
        return conn.execute(
            "SELECT * FROM pcap_flows WHERE pulled=? ORDER BY emitted_at LIMIT ?",
            (pulled, limit),
        ).fetchall()

    def get_flow_count(self, pulled: int | None = None) -> int:
        conn = self._get_conn()
        if pulled is not None:
            row = conn.execute("SELECT COUNT(*) FROM pcap_flows WHERE pulled=?", (pulled,)).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM pcap_flows").fetchone()
        return row[0] if row else 0

    def ack_flows(self, flow_ids: list[str]) -> None:
        """Atomic ack: marks flows + packets + fingerprints as pulled."""
        if not flow_ids:
            return
        conn = self._get_conn()
        placeholders = ",".join("?" for _ in flow_ids)
        with conn:
            conn.execute(f"UPDATE pcap_flows SET pulled=1 WHERE flow_id IN ({placeholders})", flow_ids)
            conn.execute(f"UPDATE pcap_packets SET pulled=1 WHERE flow_id IN ({placeholders})", flow_ids)
            conn.execute(f"UPDATE pcap_fingerprints SET pulled=1 WHERE flow_id IN ({placeholders})", flow_ids)

    # ── Packets ──

    def insert_packets(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        conn = self._get_conn()
        vals = [tuple(r.get(c) for c in _PKT_COLS) for r in rows]
        with conn:
            conn.executemany(_PKT_INSERT, vals)

    def get_packets_by_flows(self, flow_ids: list[str], limit: int = 50000) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if not flow_ids:
            return []
        placeholders = ",".join("?" for _ in flow_ids)
        return conn.execute(
            f"SELECT * FROM pcap_packets WHERE flow_id IN ({placeholders}) ORDER BY flow_id, seq_idx LIMIT ?",
            flow_ids + [limit],
        ).fetchall()

    def get_packets(self, pulled: int = 0, limit: int = 50000) -> list[sqlite3.Row]:
        conn = self._get_conn()
        return conn.execute(
            "SELECT * FROM pcap_packets WHERE pulled=? ORDER BY flow_id, seq_idx LIMIT ?",
            (pulled, limit),
        ).fetchall()

    # ── Fingerprints ──

    def insert_fingerprint(self, fp: dict[str, Any]) -> None:
        conn = self._get_conn()
        vals = tuple(fp.get(c) for c in _FP_COLS)
        with conn:
            conn.execute(_FP_INSERT, vals)

    def get_fingerprints_by_flows(self, flow_ids: list[str]) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if not flow_ids:
            return []
        placeholders = ",".join("?" for _ in flow_ids)
        return conn.execute(
            f"SELECT * FROM pcap_fingerprints WHERE flow_id IN ({placeholders})",
            flow_ids,
        ).fetchall()

    def get_fingerprints(self, pulled: int = 0, limit: int = 50000) -> list[sqlite3.Row]:
        conn = self._get_conn()
        return conn.execute(
            "SELECT * FROM pcap_fingerprints WHERE pulled=? LIMIT ?",
            (pulled, limit),
        ).fetchall()

    # ── Source Stats ──

    def upsert_source_stats(self, src_ip: str, dst_port: int, app_proto: int,
                            dst_ip: str, pps: float, first_ts: float) -> None:
        conn = self._get_conn()
        ts_iso = _ts_to_iso(first_ts)
        now_iso = _iso_now()
        with conn:
            existing = conn.execute("SELECT * FROM source_stats WHERE src_ip=?", (src_ip,)).fetchone()
            if existing:
                ports = set(json.loads(existing["unique_ports"]))
                ports.add(dst_port)
                protos = set(json.loads(existing["unique_protos"]))
                protos.add(app_proto)
                dsts = set(json.loads(existing["unique_dsts"]))
                dsts.add(dst_ip)
                conn.execute(
                    "UPDATE source_stats SET flow_count=flow_count+1, "
                    "unique_ports=?, unique_protos=?, unique_dsts=?, "
                    "first_seen=MIN(first_seen,?), last_seen=MAX(last_seen,?), "
                    "sum_pps=sum_pps+?, updated_at=? WHERE src_ip=?",
                    (json.dumps(sorted(ports)), json.dumps(sorted(protos)),
                     json.dumps(sorted(dsts)), ts_iso, ts_iso, pps, now_iso, src_ip),
                )
            else:
                conn.execute(
                    "INSERT INTO source_stats(src_ip,flow_count,unique_ports,unique_protos,"
                    "unique_dsts,first_seen,last_seen,sum_pps,updated_at) "
                    "VALUES(?,1,?,?,?,?,?,?,?)",
                    (src_ip, json.dumps([dst_port]), json.dumps([app_proto]),
                     json.dumps([dst_ip]), ts_iso, ts_iso, pps, now_iso),
                )

    def get_source_stats(self, updated_since: str | None = None) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if updated_since:
            return conn.execute(
                "SELECT * FROM source_stats WHERE updated_at>? ORDER BY last_seen DESC",
                (updated_since,),
            ).fetchall()
        return conn.execute("SELECT * FROM source_stats ORDER BY last_seen DESC").fetchall()

    # ── Logon Map ──

    def upsert_logon(self, logon_id: str, source_ip: str, service: str) -> None:
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO logon_map(logon_id,source_ip,service,created_at) "
                "VALUES(?,?,?,?)",
                (logon_id, source_ip, service, _iso_now()),
            )

    def lookup_logon(self, logon_id: str) -> tuple[str, str] | None:
        conn = self._get_conn()
        row = conn.execute("SELECT source_ip, service FROM logon_map WHERE logon_id=?", (logon_id,)).fetchone()
        if row:
            return (row["source_ip"], row["service"])
        return None

    # ── Observations ──

    def insert_observation(self, ts: float, vm_id: str, obs_type: str,
                           session_id: str | None, source_ip: str | None,
                           process_pid: int | None, evidence_bits: int,
                           priority: str, detail: dict[str, Any] | None) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute(
                "INSERT INTO observations(ts,vm_id,obs_type,session_id,source_ip,"
                "process_pid,evidence_bits,priority,detail_json) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (_ts_to_iso(ts), vm_id, obs_type, session_id, source_ip,
                 process_pid, evidence_bits, priority,
                 json.dumps(detail, separators=(",", ":")) if detail else None),
            )
            return cur.lastrowid or 0

    def get_observations(self, pulled: int = 0, limit: int = 5000) -> list[sqlite3.Row]:
        conn = self._get_conn()
        return conn.execute(
            "SELECT * FROM observations WHERE pulled=? ORDER BY obs_id LIMIT ?",
            (pulled, limit),
        ).fetchall()

    def get_observations_by_session(self, session_id: str) -> list[sqlite3.Row]:
        conn = self._get_conn()
        return conn.execute(
            "SELECT * FROM observations WHERE session_id=? ORDER BY ts",
            (session_id,),
        ).fetchall()

    def get_observations_by_source(self, source_ip: str, since_ts: str | None = None) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if since_ts:
            return conn.execute(
                "SELECT * FROM observations WHERE source_ip=? AND ts>? ORDER BY ts",
                (source_ip, since_ts),
            ).fetchall()
        return conn.execute(
            "SELECT * FROM observations WHERE source_ip=? ORDER BY ts",
            (source_ip,),
        ).fetchall()

    def ack_observations(self, through_id: int) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute("UPDATE observations SET pulled=1 WHERE obs_id<=? AND pulled=0", (through_id,))
            return cur.rowcount

    # ── File Baseline ──

    def upsert_file_baseline(self, path: str, sha256: str, size_bytes: int, mtime: float) -> None:
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_baseline(path,sha256,size_bytes,mtime,baseline_ts) "
                "VALUES(?,?,?,?,?)",
                (path, sha256, size_bytes, mtime, _iso_now()),
            )

    def get_file_baseline(self, path: str | None = None) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if path:
            return conn.execute("SELECT * FROM file_baseline WHERE path=?", (path,)).fetchall()
        return conn.execute("SELECT * FROM file_baseline").fetchall()

    def delete_file_baseline(self, path: str) -> None:
        conn = self._get_conn()
        with conn:
            conn.execute("DELETE FROM file_baseline WHERE path=?", (path,))

    # ── Breadcrumbs ──

    def insert_breadcrumb(self, credential_type: str, planted_path: str,
                          target_service: str | None, target_host: str | None) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute(
                "INSERT INTO breadcrumbs(credential_type,planted_path,target_service,"
                "target_host,planted_at) VALUES(?,?,?,?,?)",
                (credential_type, planted_path, target_service, target_host, _iso_now()),
            )
            return cur.lastrowid or 0

    def get_breadcrumbs(self, consumed: bool | None = None) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if consumed is True:
            return conn.execute("SELECT * FROM breadcrumbs WHERE consumed_at IS NOT NULL").fetchall()
        elif consumed is False:
            return conn.execute("SELECT * FROM breadcrumbs WHERE consumed_at IS NULL").fetchall()
        return conn.execute("SELECT * FROM breadcrumbs").fetchall()

    def consume_breadcrumb(self, breadcrumb_id: int, consumer_ip: str) -> None:
        conn = self._get_conn()
        with conn:
            conn.execute(
                "UPDATE breadcrumbs SET consumed_at=?, consumer_ip=? WHERE breadcrumb_id=?",
                (_iso_now(), consumer_ip, breadcrumb_id),
            )

    # ── Predictions ──

    def insert_prediction(self, flow_id: str, vm_id: str, src_ip: str | None,
                          dst_port: int | None, prediction: int, label_name: str,
                          confidence: float, probabilities: list[float] | None,
                          feature_completeness: float | None, packets_seen: int | None,
                          prediction_number: int, is_final: bool,
                          model_version: str | None) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute(
                "INSERT INTO predictions(flow_id,ts,vm_id,src_ip,dst_port,prediction,"
                "label_name,confidence,probabilities,feature_completeness,packets_seen,"
                "prediction_number,is_final,model_version) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (flow_id, _iso_now(), vm_id, src_ip, dst_port, prediction,
                 label_name, confidence,
                 json.dumps(probabilities) if probabilities else None,
                 feature_completeness, packets_seen, prediction_number,
                 1 if is_final else 0, model_version),
            )
            return cur.lastrowid or 0

    def get_predictions(self, pulled: int = 0, limit: int = 5000) -> list[sqlite3.Row]:
        conn = self._get_conn()
        return conn.execute(
            "SELECT * FROM predictions WHERE pulled=? ORDER BY pred_id LIMIT ?",
            (pulled, limit),
        ).fetchall()

    def get_predictions_by_flow(self, flow_id: str) -> list[sqlite3.Row]:
        conn = self._get_conn()
        return conn.execute(
            "SELECT * FROM predictions WHERE flow_id=? ORDER BY prediction_number",
            (flow_id,),
        ).fetchall()

    def ack_predictions(self, through_id: int) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute("UPDATE predictions SET pulled=1 WHERE pred_id<=? AND pulled=0", (through_id,))
            return cur.rowcount

    # ── Corrections ──

    def insert_correction(self, flow_id: str, predicted_label: int,
                          evidence_label: int, evidence_bits: int,
                          feature_vector: list[float] | None) -> int:
        conn = self._get_conn()
        with conn:
            cur = conn.execute(
                "INSERT INTO corrections(flow_id,ts,predicted_label,evidence_label,"
                "evidence_bits,feature_vector) VALUES(?,?,?,?,?,?)",
                (flow_id, _iso_now(), predicted_label, evidence_label,
                 evidence_bits,
                 json.dumps(feature_vector) if feature_vector else None),
            )
            return cur.lastrowid or 0

    def get_corrections(self, limit: int = 5000) -> list[sqlite3.Row]:
        conn = self._get_conn()
        return conn.execute("SELECT * FROM corrections ORDER BY corr_id LIMIT ?", (limit,)).fetchall()

    # ── Model Performance ──

    def upsert_model_performance(self, date: str, model_version: str | None,
                                 predictions_total: int, confirmed: int,
                                 contradicted: int, per_class: dict | None) -> None:
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO model_performance(date,model_version,"
                "predictions_total,confirmed,contradicted,per_class_json) "
                "VALUES(?,?,?,?,?,?)",
                (date, model_version, predictions_total, confirmed, contradicted,
                 json.dumps(per_class) if per_class else None),
            )

    def get_model_performance(self, date: str | None = None) -> list[sqlite3.Row]:
        conn = self._get_conn()
        if date:
            return conn.execute("SELECT * FROM model_performance WHERE date=?", (date,)).fetchall()
        return conn.execute("SELECT * FROM model_performance ORDER BY date DESC LIMIT 30").fetchall()

    # ── Cleanup ──

    def cleanup(self, retention_days: int) -> None:
        conn = self._get_conn()
        cutoff_ts = time.time() - retention_days * 86400
        cutoff_iso = _ts_to_iso(cutoff_ts)
        with conn:
            conn.execute("DELETE FROM events WHERE pulled=1 AND ts<?", (cutoff_iso,))
            flow_ids = [r[0] for r in conn.execute(
                "SELECT flow_id FROM pcap_flows WHERE pulled=1 AND emitted_at<?", (cutoff_iso,)
            ).fetchall()]
            if flow_ids:
                ph = ",".join("?" for _ in flow_ids)
                conn.execute(f"DELETE FROM pcap_packets WHERE flow_id IN ({ph})", flow_ids)
                conn.execute(f"DELETE FROM pcap_fingerprints WHERE flow_id IN ({ph})", flow_ids)
                conn.execute(f"DELETE FROM pcap_flows WHERE flow_id IN ({ph})", flow_ids)
            # Prune logon_map entries older than TTL
            conn.execute("DELETE FROM logon_map WHERE created_at<?", (cutoff_iso,))
            # Prune pulled observations
            conn.execute("DELETE FROM observations WHERE pulled=1 AND ts<?", (cutoff_iso,))
            # Prune pulled predictions
            conn.execute("DELETE FROM predictions WHERE pulled=1 AND ts<?", (cutoff_iso,))
            # Prune old corrections (keep 30 days regardless)
            conn.execute("DELETE FROM corrections WHERE ts<?", (cutoff_iso,))
        # WAL checkpoint — must be outside transaction
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass  # non-critical, retry next cycle

    # ── Stats helpers for API ──

    def db_size_mb(self) -> float:
        try:
            return Path(self.db_path).stat().st_size / (1024 * 1024)
        except OSError:
            return 0.0

    def wal_size_mb(self) -> float:
        try:
            return Path(self.db_path + "-wal").stat().st_size / (1024 * 1024)
        except OSError:
            return 0.0

    def event_count(self, pulled: int | None = None) -> int:
        conn = self._get_conn()
        if pulled is not None:
            row = conn.execute("SELECT COUNT(*) FROM events WHERE pulled=?", (pulled,)).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0] if row else 0

    def logon_map_size(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) FROM logon_map").fetchone()
        return row[0] if row else 0

    def source_stats_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) FROM source_stats").fetchone()
        return row[0] if row else 0

    def packet_count(self, pulled: int | None = None) -> int:
        conn = self._get_conn()
        if pulled is not None:
            row = conn.execute("SELECT COUNT(*) FROM pcap_packets WHERE pulled=?", (pulled,)).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM pcap_packets").fetchone()
        return row[0] if row else 0

    def fingerprint_count(self, pulled: int | None = None) -> int:
        conn = self._get_conn()
        if pulled is not None:
            row = conn.execute("SELECT COUNT(*) FROM pcap_fingerprints WHERE pulled=?", (pulled,)).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM pcap_fingerprints").fetchone()
        return row[0] if row else 0

    # ── NDJSON export helpers (for exporter.py) ──

    def pull_unexported_flows(self, limit: int) -> list[sqlite3.Row]:
        """Get flows that haven't been pulled yet for NDJSON export."""
        return self.get_flows(pulled=0, limit=limit)

    def pull_unexported_events(self, limit: int) -> list[sqlite3.Row]:
        """Get events that haven't been pulled yet for NDJSON export."""
        return self.get_events(pulled=0, limit=limit)

    def pull_unexported_packets(self, limit: int) -> list[sqlite3.Row]:
        """Get CNN token packets that haven't been pulled yet for NDJSON export."""
        return self.get_packets(pulled=0, limit=limit)

    def pull_unexported_fingerprints(self, limit: int) -> list[sqlite3.Row]:
        """Get fingerprints that haven't been pulled yet for NDJSON export."""
        return self.get_fingerprints(pulled=0, limit=limit)

    def pull_unexported_observations(self, limit: int) -> list[sqlite3.Row]:
        """Get observations that haven't been pulled yet for NDJSON export."""
        return self.get_observations(pulled=0, limit=limit)

    def pull_unexported_predictions(self, limit: int) -> list[sqlite3.Row]:
        """Get predictions that haven't been pulled yet for NDJSON export."""
        return self.get_predictions(pulled=0, limit=limit)
