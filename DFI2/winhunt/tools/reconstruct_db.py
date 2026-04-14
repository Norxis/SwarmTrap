"""Reconstruct agent_buffer.db from staging NDJSON files.

Reads all staging *.ndjson files and inserts into a fresh SQLite DB.
Uses INSERT OR IGNORE so safe to re-run.
"""
import glob, json, os, sqlite3, sys, time
from pathlib import Path

STAGING  = r"C:\Program Files\DFI\staging"
DB_OUT   = r"C:\Program Files\DFI\data\agent_buffer_restored.db"

# ── same schema as buffer.py ─────────────────────────────────────────────────
_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS pcap_flows (
    flow_id TEXT PRIMARY KEY, session_key TEXT NOT NULL,
    src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL,
    ip_proto INTEGER NOT NULL, app_proto INTEGER NOT NULL DEFAULT 0,
    first_ts TEXT NOT NULL, last_ts TEXT NOT NULL,
    pkts_fwd INTEGER NOT NULL, pkts_rev INTEGER NOT NULL,
    bytes_fwd INTEGER NOT NULL, bytes_rev INTEGER NOT NULL,
    bytes_per_pkt_fwd REAL, bytes_per_pkt_rev REAL,
    pkt_ratio REAL, byte_ratio REAL,
    rtt_ms REAL, duration_ms INTEGER NOT NULL,
    iat_fwd_mean_ms REAL, iat_fwd_std_ms REAL,
    think_time_mean_ms REAL, think_time_std_ms REAL,
    iat_to_rtt REAL, pps REAL NOT NULL, bps REAL NOT NULL,
    payload_rtt_ratio REAL, n_events INTEGER NOT NULL,
    fwd_size_mean REAL, fwd_size_std REAL,
    fwd_size_min INTEGER NOT NULL DEFAULT 0, fwd_size_max INTEGER NOT NULL DEFAULT 0,
    rev_size_mean REAL, rev_size_std REAL, rev_size_max INTEGER NOT NULL DEFAULT 0,
    hist_tiny INTEGER NOT NULL DEFAULT 0, hist_small INTEGER NOT NULL DEFAULT 0,
    hist_medium INTEGER NOT NULL DEFAULT 0, hist_large INTEGER NOT NULL DEFAULT 0,
    hist_full INTEGER NOT NULL DEFAULT 0, frac_full REAL NOT NULL DEFAULT 0,
    syn_count INTEGER NOT NULL DEFAULT 0, fin_count INTEGER NOT NULL DEFAULT 0,
    rst_count INTEGER NOT NULL DEFAULT 0, psh_count INTEGER NOT NULL DEFAULT 0,
    ack_only_count INTEGER NOT NULL DEFAULT 0, conn_state INTEGER NOT NULL DEFAULT 0,
    rst_frac REAL, syn_to_data INTEGER NOT NULL DEFAULT 0,
    psh_burst_max INTEGER NOT NULL DEFAULT 0, retransmit_est INTEGER NOT NULL DEFAULT 0,
    window_size_init INTEGER NOT NULL DEFAULT 0,
    entropy_first REAL, entropy_fwd_mean REAL, entropy_rev_mean REAL,
    printable_frac REAL, null_frac REAL, byte_std REAL,
    high_entropy_frac REAL, payload_len_first INTEGER NOT NULL DEFAULT 0,
    src_mac TEXT NOT NULL DEFAULT '', dst_mac TEXT NOT NULL DEFAULT '',
    vlan_id INTEGER NOT NULL DEFAULT 0, capture_source INTEGER NOT NULL DEFAULT 1,
    emitted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    pulled INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_src ON pcap_flows (src_ip, first_ts);

CREATE TABLE IF NOT EXISTS pcap_packets (
    flow_id TEXT NOT NULL, seq_idx INTEGER NOT NULL,
    ts TEXT NOT NULL, direction INTEGER NOT NULL,
    payload_len INTEGER NOT NULL, pkt_len INTEGER NOT NULL,
    tcp_flags INTEGER NOT NULL, tcp_window INTEGER NOT NULL DEFAULT 0,
    size_dir_token INTEGER NOT NULL, flag_token INTEGER NOT NULL,
    iat_log_ms_bin INTEGER NOT NULL, iat_rtt_bin INTEGER NOT NULL,
    entropy_bin INTEGER NOT NULL DEFAULT 0,
    iat_ms REAL, payload_entropy REAL, pulled INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (flow_id, seq_idx)
);

CREATE TABLE IF NOT EXISTS pcap_fingerprints (
    flow_id TEXT PRIMARY KEY, ja3_hash TEXT,
    tls_version INTEGER NOT NULL DEFAULT 0,
    tls_cipher_count INTEGER NOT NULL DEFAULT 0,
    tls_ext_count INTEGER NOT NULL DEFAULT 0,
    tls_has_sni INTEGER NOT NULL DEFAULT 0,
    hassh_hash TEXT, ssh_kex_count INTEGER NOT NULL DEFAULT 0,
    http_method INTEGER NOT NULL DEFAULT 0, http_uri_len INTEGER NOT NULL DEFAULT 0,
    http_header_count INTEGER NOT NULL DEFAULT 0, http_ua_hash TEXT,
    http_has_body INTEGER NOT NULL DEFAULT 0, http_status INTEGER NOT NULL DEFAULT 0,
    dns_qtype INTEGER NOT NULL DEFAULT 0, dns_qname_len INTEGER NOT NULL DEFAULT 0,
    pulled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, vm_id TEXT NOT NULL,
    source_ip TEXT, source_port INTEGER DEFAULT 0,
    service TEXT NOT NULL DEFAULT 'system', event_type TEXT NOT NULL,
    evidence_bits INTEGER NOT NULL DEFAULT 0,
    raw_event_id INTEGER, raw_channel TEXT, detail_json TEXT,
    pulled INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS observations (
    obs_id INTEGER PRIMARY KEY, ts TEXT NOT NULL, vm_id TEXT NOT NULL,
    obs_type TEXT NOT NULL, session_id TEXT, source_ip TEXT,
    process_pid INTEGER, evidence_bits INTEGER NOT NULL DEFAULT 0,
    priority TEXT NOT NULL DEFAULT 'normal', detail_json TEXT,
    pulled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS source_stats (
    src_ip TEXT PRIMARY KEY, flow_count INTEGER NOT NULL DEFAULT 0,
    unique_ports TEXT NOT NULL DEFAULT '[]',
    unique_protos TEXT NOT NULL DEFAULT '[]',
    unique_dsts TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT, last_seen TEXT,
    sum_pps REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""

# ── table routing ─────────────────────────────────────────────────────────────
_FILE_TYPE_TABLE = {
    "flows":        "pcap_flows",
    "packets":      "pcap_packets",
    "fingerprints": "pcap_fingerprints",
    "events":       "events",
    "observations": "observations",
}


def _file_type(fname: str) -> str | None:
    """Extract type from filename: dfi_flows_*.ndjson → 'flows'"""
    parts = Path(fname).stem.split("_")
    return parts[1] if len(parts) >= 2 else None


def _insert_rows(con: sqlite3.Connection, table: str, rows: list[dict]) -> int:
    if not rows:
        return 0
    # Collect all keys seen across rows
    all_keys = list({k for r in rows for k in r.keys() if k != "pulled"})
    cols = ",".join(all_keys)
    placeholders = ",".join("?" for _ in all_keys)
    sql = f"INSERT OR IGNORE INTO {table} ({cols}) VALUES ({placeholders})"
    vals = [tuple(r.get(k) for k in all_keys) for r in rows]
    con.executemany(sql, vals)
    return len(vals)


def main():
    t0 = time.time()

    if os.path.exists(DB_OUT):
        os.remove(DB_OUT)
        print(f"Removed existing {DB_OUT}")

    con = sqlite3.connect(DB_OUT, timeout=60)
    con.executescript(_SCHEMA)
    con.commit()
    print(f"Schema created: {DB_OUT}")

    # Sort files by name (timestamp-ordered)
    all_files = sorted(glob.glob(os.path.join(STAGING, "*.ndjson")))
    print(f"Found {len(all_files)} NDJSON files")

    stats = {}
    BATCH = 5000
    for i, fpath in enumerate(all_files):
        ftype = _file_type(fpath)
        if ftype not in _FILE_TYPE_TABLE:
            continue  # skip heartbeat etc.
        table = _FILE_TYPE_TABLE[ftype]

        rows = []
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
        except Exception as e:
            print(f"  SKIP {os.path.basename(fpath)}: {e}")
            continue

        if rows:
            with con:
                n = _insert_rows(con, table, rows)
            stats[table] = stats.get(table, 0) + n

        if (i + 1) % 1000 == 0:
            elapsed = time.time() - t0
            print(f"  [{i+1}/{len(all_files)}] {elapsed:.0f}s — {stats}")

    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()

    elapsed = time.time() - t0
    db_mb = os.path.getsize(DB_OUT) / 1024 / 1024
    print(f"\nDone in {elapsed:.1f}s")
    print(f"DB size: {db_mb:.1f} MB")
    print("Row counts:")
    for tbl, n in sorted(stats.items()):
        print(f"  {tbl}: {n:,}")


if __name__ == "__main__":
    main()
