# Phase 1: ClickHouse Foundation

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Nothing (foundation phase)

## Objective

Install ClickHouse on both PV1 and AIO, create the full DFI2 schema, and build the sync mechanism (PV1 pulls from AIO, PV1 pushes watchlist to AIO).

## Hosts

| Host | IP | SSH Port | User | Password | Role |
|------|----|----------|------|----------|------|
| PV1 | 192.168.0.100 | 22 | root@pam | CHANGE_ME | Master (472GB RAM) |
| AIO | 172.16.3.113 | 2222 | colo8gent | CHANGE_ME | Satellite (16GB RAM) |

**SSH rule:** Always use Paramiko. `sudo -S` with password `CHANGE_ME` on AIO (colo8gent user). PV1 is root already.

## Output Files

All code goes in `~/DFI2/`:

```
~/DFI2/
├── schema/
│   ├── 01_tables.sql        # Core dataset tables
│   ├── 02_behavioral.sql    # Behavioral event tables
│   ├── 03_buffers.sql       # Buffer tables for high-throughput
│   ├── 04_views.sql         # Materialized views + export views
│   └── 05_watchlist.sql     # SQLite watchlist DDL
├── sync/
│   ├── pull_aio.py          # PV1 pulls CH data from AIO (cron every 5 min)
│   ├── push_watchlist.py    # PV1 pushes attacker IPs → AIO SQLite (cron every 10 min)
│   └── config.py            # Shared config (hosts, ports, credentials)
└── deploy/
    ├── deploy_ch_pv1.py     # Install ClickHouse + schema on PV1
    └── deploy_ch_aio.py     # Install ClickHouse + schema on AIO
```

---

## Step 1: ClickHouse Install Scripts

### deploy_ch_pv1.py

Paramiko script that SSHs to PV1 (192.168.0.100:22, root) and:

1. Installs ClickHouse from official repo:
```bash
apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
    | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] \
    https://packages.clickhouse.com/deb stable main" \
    > /etc/apt/sources.list.d/clickhouse.list
apt-get update && apt-get install -y clickhouse-server clickhouse-client
```

2. Creates config `/etc/clickhouse-server/config.d/dfi.xml`:
```xml
<clickhouse>
    <max_server_memory_usage_to_ram_ratio>0.6</max_server_memory_usage_to_ram_ratio>
    <merge_tree>
        <max_bytes_to_merge_at_max_space_in_pool>10737418240</max_bytes_to_merge_at_max_space_in_pool>
    </merge_tree>
    <listen_host>0.0.0.0</listen_host>
</clickhouse>
```

3. Enables and starts: `systemctl enable --now clickhouse-server`
4. Creates database: `clickhouse-client --query "CREATE DATABASE IF NOT EXISTS dfi"`
5. Runs all SQL files (01-04) against PV1

### deploy_ch_aio.py

Same pattern but SSHs to AIO (172.16.3.113:2222, colo8gent, sudo -S) and:

1. Same install steps
2. Lighter config `/etc/clickhouse-server/config.d/dfi.xml`:
```xml
<clickhouse>
    <max_server_memory_usage_to_ram_ratio>0.25</max_server_memory_usage_to_ram_ratio>
    <merge_tree>
        <max_bytes_to_merge_at_max_space_in_pool>5368709120</max_bytes_to_merge_at_max_space_in_pool>
    </merge_tree>
    <listen_host>0.0.0.0</listen_host>
</clickhouse>
```
3. Same enable/start/database creation
4. Runs SQL files 01-03 only (NO materialized views or export views — those are PV1-only)

**IMPORTANT:** AIO tables must use 48-hour TTL instead of 90-day. Modify the TTL clauses when running on AIO:
- `TTL first_ts + INTERVAL 2 DAY` (instead of 90/180 DAY)

---

## Step 2: Schema SQL Files

### 01_tables.sql — Core Dataset Tables

Copy these CREATE TABLE statements **exactly** from `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md`:
- `dfi.flows` (with all columns, ORDER BY, TTL, skip indexes)
- `dfi.packets`
- `dfi.fingerprints`
- `dfi.labels`

### 02_behavioral.sql — Behavioral Event Tables

Copy from the spec:
- `dfi.evidence_events`
- `dfi.fanout_hops`
- `dfi.model_predictions`
- `dfi.group_assignments`
- `dfi.depth_changes`
- `dfi.analyst_actions`
- `dfi.payload_bytes`

### 03_buffers.sql — Buffer Tables

Copy from the spec:
- `dfi.flows_buffer`
- `dfi.packets_buffer`
- `dfi.fingerprints_buffer`
- `dfi.evidence_events_buffer`
- `dfi.fanout_hops_buffer`
- `dfi.model_predictions_buffer`

### 04_views.sql — Materialized Views + Export Views (PV1 ONLY)

Copy from the spec:
- `dfi.source_stats` + `dfi.mv_source_stats`
- `dfi.fingerprint_freq` + `dfi.mv_ja3_freq` + `dfi.mv_hassh_freq` + `dfi.mv_ua_freq`
- `dfi.fanout_stats` + `dfi.mv_fanout_stats`
- `dfi.v_xgb` (XGBoost export view)
- `dfi.v_cnn_sequences` (CNN sequence view)

### 05_watchlist.sql — SQLite Watchlist DDL

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS watchlist (
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
);

CREATE INDEX IF NOT EXISTS idx_wl_depth ON watchlist(capture_depth);
CREATE INDEX IF NOT EXISTS idx_wl_expires ON watchlist(expires_at) WHERE expires_at IS NOT NULL;
```

---

## Step 3: Sync Scripts

### sync/config.py

```python
PV1_HOST = '192.168.0.100'
PV1_CH_PORT = 9000
AIO_HOST = '172.16.3.113'
AIO_SSH_PORT = 2222
AIO_CH_PORT = 9000
AIO_USER = 'colo8gent'
AIO_PASS = 'CHANGE_ME'
WATCHLIST_DB_PATH = '/opt/dfi-hunter/watchlist.db'
PULL_INTERVAL_SEC = 300   # 5 minutes
PUSH_INTERVAL_SEC = 600   # 10 minutes
WATERMARK_FILE = '/opt/dfi_edge/sync_watermark.json'
```

### sync/pull_aio.py

- Runs on PV1 via cron: `*/5 * * * * /usr/bin/python3 /opt/dfi2/sync/pull_aio.py`
- Uses `clickhouse-driver` Python library (install: `pip install clickhouse-driver`)
- Reads watermark (last-pulled timestamp per table) from JSON file
- For each table (flows, packets, fingerprints, fanout_hops, evidence_events, model_predictions):
  ```python
  from clickhouse_driver import Client
  local = Client('localhost')
  # Use remote() to pull from AIO
  local.execute(f"""
      INSERT INTO dfi.{table}
      SELECT * FROM remote('{AIO_HOST}:{AIO_CH_PORT}', dfi, {table})
      WHERE {ts_col} > '{last_pull_ts}'
  """)
  ```
- Updates watermark after successful pull
- Logs row counts pulled per table
- Error handling: if AIO unreachable, log and retry next cycle

### sync/push_watchlist.py

- Runs on PV1 via cron: `*/10 * * * * /usr/bin/python3 /opt/dfi2/sync/push_watchlist.py`
- Reads latest classifier output from PV1 ClickHouse:
  ```sql
  SELECT attacker_ip, argMax(group_id, assigned_at) as group_id,
         argMax(sub_group_id, assigned_at) as sub_group_id,
         argMax(priority, assigned_at) as priority
  FROM dfi.group_assignments
  WHERE assigned_at > now() - INTERVAL 24 HOUR
  GROUP BY attacker_ip
  ```
- Reads latest depth assignments:
  ```sql
  SELECT attacker_ip, argMax(new_depth, changed_at) as capture_depth
  FROM dfi.depth_changes
  WHERE changed_at > now() - INTERVAL 24 HOUR
  GROUP BY attacker_ip
  ```
- SSHs to AIO via Paramiko (172.16.3.113:2222, colo8gent, CHANGE_ME)
- Writes SQLite watchlist.db on AIO:
  - SFTP the watchlist data as JSON
  - Execute remote Python to parse JSON → SQLite REPLACE INTO
  - OR: use Paramiko to run sqlite3 commands directly
- Logs count of IPs pushed

---

## Step 4: Verification

After deployment, run these checks:

### On PV1:
```bash
clickhouse-client --query "SELECT 1"
clickhouse-client --query "SHOW TABLES FROM dfi"
# Should show all 11 tables + 6 buffer tables + 3 aggregate tables + 2 views
clickhouse-client --query "SELECT count() FROM dfi.flows"  # should be 0

# Test insert
clickhouse-client --query "INSERT INTO dfi.flows_buffer (flow_id, session_key, actor_id, src_ip, dst_ip, src_port, dst_port, ip_proto, first_ts, last_ts, pkts_fwd, pkts_rev, bytes_fwd, bytes_rev, n_events, pps, bps, frac_full) VALUES ('test-001', 'sk-001', 'actor-001', '1.2.3.4', '5.6.7.8', 12345, 22, 6, now(), now(), 10, 5, 1000, 500, 15, 100.0, 80000.0, 0.5)"
sleep 35  # wait for buffer flush
clickhouse-client --query "SELECT * FROM dfi.flows WHERE flow_id = 'test-001'"
```

### On AIO:
```bash
clickhouse-client --query "SELECT 1"
clickhouse-client --query "SHOW TABLES FROM dfi"
# Should show 11 tables + 6 buffer tables (NO views)
```

### Pull test:
```bash
# Insert test row on AIO
ssh -p 2222 colo8gent@172.16.3.113 "clickhouse-client --query \"INSERT INTO dfi.flows_buffer (flow_id, session_key, actor_id, src_ip, dst_ip, src_port, dst_port, ip_proto, first_ts, last_ts, pkts_fwd, pkts_rev, bytes_fwd, bytes_rev, n_events, pps, bps, frac_full) VALUES ('aio-test-001', 'sk-aio-001', 'actor-aio-001', '9.8.7.6', '5.6.7.8', 54321, 80, 6, now(), now(), 20, 10, 2000, 1000, 25, 200.0, 160000.0, 0.3)\""

# Wait for buffer flush, then run pull
sleep 35
python3 /opt/dfi2/sync/pull_aio.py

# Verify on PV1
clickhouse-client --query "SELECT * FROM dfi.flows WHERE flow_id = 'aio-test-001'"
```

### Push test:
```bash
# Run push (will push empty watchlist initially)
python3 /opt/dfi2/sync/push_watchlist.py

# Verify SQLite on AIO
ssh -p 2222 colo8gent@172.16.3.113 "sqlite3 /opt/dfi-hunter/watchlist.db 'SELECT count(*) FROM watchlist'"
```

---

## Acceptance Criteria

- [ ] ClickHouse server running on PV1 (port 9000 + 8123)
- [ ] ClickHouse server running on AIO (port 9000)
- [ ] All 11 tables created on both hosts
- [ ] Buffer tables created on both hosts
- [ ] Materialized views + export views created on PV1 only
- [ ] AIO tables have 48-hour TTL
- [ ] PV1 tables have 90-day/180-day/365-day TTL per spec
- [ ] SQLite watchlist.db created on both hosts
- [ ] pull_aio.py successfully pulls test data from AIO → PV1
- [ ] push_watchlist.py successfully writes to AIO SQLite
- [ ] `clickhouse-driver` Python package installed on PV1
- [ ] Cron entries created for both sync scripts on PV1
- [ ] All SQL files committed to ~/DFI2/schema/
- [ ] All sync scripts committed to ~/DFI2/sync/
- [ ] Deploy scripts committed to ~/DFI2/deploy/
