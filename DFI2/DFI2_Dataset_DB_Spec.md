# DFI Dataset Database — ClickHouse for 40Gbps SPAN

## Why ClickHouse

| Requirement | SQLite | PostgreSQL | ClickHouse |
|---|---|---|---|
| 40Gbps SPAN → 100K+ flows/sec insert | dies | struggles | trivial |
| 3M+ packet rows/sec insert | impossible | 500K max | 10M+ native |
| Columnar compression on token sequences | no | no | 15–25× ratio |
| Analytical export (GROUP BY, JOIN) | slow at scale | decent | built for it |
| Single binary, runs on Proxmox | yes | yes | yes |
| Concurrent read during write | WAL only | MVCC | lock-free |

At 40Gbps worst case: ~60M pps raw, ~100K new flows/sec after filtering,
~3M event packet inserts/sec. ClickHouse MergeTree + Buffer tables absorb
this without breaking a sweat.

---

## Architecture

```
Hunter (AF_PACKET TPACKET_V3, 40Gbps SPAN)
    │
    ├─► reads SQLite watchlist (per-flow capture depth decision)
    │
    ├─► D0: skip entirely (known noise)
    ├─► D1: flows + fingerprints only          ──► ClickHouse
    ├─► D2: D1 + packets (128 event tokens)    ──► ClickHouse
    ├─► D3: D2 + payload bytes                 ──► ClickHouse
    │
    ├─► fanout_hops (every flow, every depth)  ──► ClickHouse
    └─► evidence_events (from honeypot logs)   ──► ClickHouse

Classifier Jobs (every 5-10 min, reads ClickHouse):
    ├─► group_assignments   ──► ClickHouse
    ├─► depth_changes       ──► ClickHouse
    └─► push updated state  ──► SQLite watchlist (disposable cache)

ML Scoring (batch or streaming):
    └─► model_predictions   ──► ClickHouse

Labeler Daemon:
    └─► labels              ──► ClickHouse (from evidence.db correlation)

Streamlit Dashboard:
    ├─► reads ClickHouse (profiles, movement, campaigns)
    └─► analyst_actions     ──► ClickHouse + SQLite watchlist

Exports:
    ├─► v_xgb   → XGBoost CSV (82 cols, flat)
    ├─► v_cnn   → CNN CSV (689 cols, sequences + static)
    └─► v_model3 → future campaign-level export
```

### Dual-Store Roles

| Concern | ClickHouse | SQLite (watchlist.db) |
|---|---|---|
| Role | Analytical store + source of truth | Hot cache for Hunter fast path |
| Data lifetime | 90-day TTL (events), longer for attacker state | Disposable, rebuildable |
| Query pattern | Analytical joins, aggregates, exports | Single-row key-value lookups |
| Write pattern | Batch insert (100K+ rows/sec) | Single-row upsert |
| Read latency | Milliseconds–seconds (columnar scan) | Sub-millisecond (B-tree point) |
| Who writes | Hunter, classifier jobs, analyst actions | Classifier jobs, analyst actions |
| Who reads | Streamlit, export scripts, classifier jobs | Hunter (per-packet/per-flow) |

### Ledger Rule: Every Row Stands Alone

**Every row in every table must carry:**
1. **A timestamp** — when this event occurred or was recorded
2. **IP context** — which attacker, which target (where applicable)
3. **A reference key** — flow_id, event_id, or attacker_ip for traceability

No row should require a JOIN just to answer "who, when, where."
JOINs are for enrichment, not for basic identity.

### Index Strategy

ORDER BY keys are attacker-first (most queries start with "show me this attacker").
Data skipping indexes on target IPs enable the reverse query: "who touched this
honeypot?" ClickHouse `set(0)` indexes record which values exist per granule and
skip granules that can't match — no reordering needed, minimal write overhead.

---

## Install (Proxmox / Debian Bookworm)

```bash
apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
    | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] \
    https://packages.clickhouse.com/deb stable main" \
    > /etc/apt/sources.list.d/clickhouse.list
apt-get update && apt-get install -y clickhouse-server clickhouse-client

# Tune for high ingest
cat >> /etc/clickhouse-server/config.d/dfi.xml <<'EOF'
<clickhouse>
    <max_server_memory_usage_to_ram_ratio>0.6</max_server_memory_usage_to_ram_ratio>
    <merge_tree>
        <max_bytes_to_merge_at_max_space_in_pool>10737418240</max_bytes_to_merge_at_max_space_in_pool>
    </merge_tree>
</clickhouse>
EOF

systemctl enable --now clickhouse-server
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS dfi"
```

---

## Schema — Core Dataset Tables

### Table: `flows`

One row per bidirectional flow. All scalar features pre-computed at ingest.
Written at capture depth D1 and above.

```sql
CREATE TABLE dfi.flows
(
    -- Identity
    flow_id         String,
    session_key     String,
    actor_id        String,
    src_ip          IPv4,
    dst_ip          IPv4,
    src_port        UInt16,
    dst_port        UInt16,
    ip_proto        UInt8,
    app_proto       UInt8,
    vlan_id         UInt16       DEFAULT 0,
    first_ts        DateTime64(3),
    last_ts         DateTime64(3),

    -- Capture context
    capture_depth   UInt8        DEFAULT 1,   -- 1=D1, 2=D2, 3=D3

    -- F2. Volume
    pkts_fwd        UInt32,
    pkts_rev        UInt32,
    bytes_fwd       UInt32,
    bytes_rev       UInt32,

    -- F3. Timing (jitter-robust, RTT-normalized)
    rtt_ms          Nullable(Float32),
    duration_ms     UInt32,
    iat_fwd_mean_ms Nullable(Float32),
    iat_fwd_std_ms  Nullable(Float32),
    think_time_mean_ms Nullable(Float32),
    think_time_std_ms  Nullable(Float32),
    iat_to_rtt      Nullable(Float32),
    pps             Float32,
    bps             Float32,
    payload_rtt_ratio Nullable(Float32),

    -- F4. Size shape
    n_events        UInt16,
    fwd_size_mean   Nullable(Float32),
    fwd_size_std    Nullable(Float32),
    fwd_size_min    UInt16,
    fwd_size_max    UInt16,
    rev_size_mean   Nullable(Float32),
    rev_size_std    Nullable(Float32),
    rev_size_max    UInt16,
    hist_tiny       UInt16,
    hist_small      UInt16,
    hist_medium     UInt16,
    hist_large      UInt16,
    hist_full       UInt16,
    frac_full       Float32,

    -- F5. TCP behavior
    syn_count       UInt8,
    fin_count       UInt8,
    rst_count       UInt8,
    psh_count       UInt16,
    ack_only_count  UInt16,
    conn_state      UInt8,
    rst_frac        Nullable(Float32),
    syn_to_data     UInt8,
    psh_burst_max   UInt8,
    retransmit_est  UInt16,
    window_size_init UInt16,

    -- F6. Payload content
    entropy_first      Nullable(Float32),
    entropy_fwd_mean   Nullable(Float32),
    entropy_rev_mean   Nullable(Float32),
    printable_frac     Nullable(Float32),
    null_frac          Nullable(Float32),
    byte_std           Nullable(Float32),
    high_entropy_frac  Nullable(Float32),
    payload_len_first  UInt16,

    -- Ingest metadata
    ingested_at     DateTime DEFAULT now(),

    -- Skip indexes for target-centric queries
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first_ts)
ORDER BY (dst_port, src_ip, first_ts)
TTL first_ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `packets`

One row per event packet. Written at capture depth D2 and above only.
Denormalized with flow-level IPs and timestamp.

```sql
CREATE TABLE dfi.packets
(
    -- Flow reference + denormalized identity
    flow_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    flow_first_ts   DateTime64(3),

    -- Packet identity
    seq_idx         UInt8,                   -- 0-127
    ts              DateTime64(3),           -- this packet's timestamp
    direction       Int8,                    -- 1=fwd, -1=rev
    payload_len     UInt16,
    pkt_len         UInt16,
    tcp_flags       UInt8,
    tcp_window      UInt16,

    -- Pre-computed CNN tokens
    size_dir_token  Int8,                    -- [-11..+11]
    flag_token      UInt8,                   -- [0..16]
    iat_log_ms_bin  UInt8,                   -- [0..8]
    iat_rtt_bin     UInt8,                   -- [0..9]
    entropy_bin     UInt8,                   -- [0..6]

    -- Raw for re-binning
    iat_ms          Nullable(Float32),
    payload_entropy Nullable(Float32),

    -- Skip indexes
    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (flow_id, seq_idx)
TTL ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `fingerprints`

One row per flow. Written at D1 and above.
Denormalized with IPs and timestamp.

```sql
CREATE TABLE dfi.fingerprints
(
    -- Flow reference + denormalized identity
    flow_id            String,
    src_ip             IPv4,
    dst_ip             IPv4,
    dst_port           UInt16,
    first_ts           DateTime64(3),

    -- TLS
    ja3_hash           Nullable(String),
    tls_version        UInt8        DEFAULT 0,
    tls_cipher_count   UInt8        DEFAULT 0,
    tls_ext_count      UInt8        DEFAULT 0,
    tls_has_sni        UInt8        DEFAULT 0,

    -- SSH
    hassh_hash         Nullable(String),
    ssh_kex_count      UInt8        DEFAULT 0,

    -- HTTP
    http_method        UInt8        DEFAULT 0,
    http_uri_len       UInt16       DEFAULT 0,
    http_header_count  UInt8        DEFAULT 0,
    http_ua_hash       Nullable(String),
    http_has_body      UInt8        DEFAULT 0,
    http_status        UInt16       DEFAULT 0,

    -- DNS
    dns_qtype          UInt8        DEFAULT 0,
    dns_qname_len      UInt16       DEFAULT 0,

    -- Ingest metadata
    ingested_at        DateTime DEFAULT now(),

    -- Skip indexes
    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
ORDER BY (flow_id)
TTL first_ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `labels`

Ground truth from evidence.db. Written by labeler daemon.
Denormalized with IPs and flow timestamp.

```sql
CREATE TABLE dfi.labels
(
    -- Flow reference + denormalized identity
    flow_id            String,
    src_ip             IPv4,
    dst_ip             IPv4,
    flow_first_ts      DateTime64(3),

    -- Label
    label              UInt8,
    label_confidence   Float32,
    evidence_mask      UInt8,
    evidence_detail    String,

    -- When labeled
    labeled_at         DateTime64(3) DEFAULT now64(3),

    -- Skip indexes
    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(labeled_at)
ORDER BY flow_id
SETTINGS index_granularity = 8192;
```

---

## Schema — Behavioral Event Tables

Every state change is a new row. No updates. Full audit trail.
All events carry their own timestamp and IP context.

### Table: `evidence_events`

Raw host-side log events from honeypot VMs.

```sql
CREATE TABLE dfi.evidence_events
(
    event_id        String,                  -- UUID
    ts              DateTime64(3),           -- original log timestamp
    src_ip          IPv4,                    -- attacker IP from log
    target_ip       IPv4,                    -- honeypot VM IP
    target_vlan     UInt16       DEFAULT 0,
    event_type      LowCardinality(String),  -- auth_failure, auth_success, process_create,
                                             -- service_install, suspicious_command,
                                             -- file_download, privilege_escalation
    event_detail    String,                  -- parsed detail (username, command, path)
    evidence_mask_bit UInt8,                 -- which bit this event sets
    source_program  LowCardinality(String),  -- sshd, mysqld, rdp, httpd, etc.
    source_log      String,                  -- raw log line
    ingested_at     DateTime DEFAULT now(),

    -- Skip index
    INDEX idx_target_ip target_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src_ip, ts)
TTL ts + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `fanout_hops`

One row per flow per attacker. Movement tracking.

```sql
CREATE TABLE dfi.fanout_hops
(
    flow_id         String,
    attacker_ip     IPv4,
    target_ip       IPv4,
    dst_port        UInt16,
    app_proto       UInt8,
    vlan_id         UInt16       DEFAULT 0,
    first_ts        DateTime64(3),
    last_ts         DateTime64(3),

    -- Interaction depth
    pkts_fwd        UInt32,
    pkts_rev        UInt32,
    bytes_fwd       UInt32,
    bytes_rev       UInt32,
    duration_ms     UInt32,
    conn_state      UInt8,
    n_events        UInt16,

    -- Gap from this attacker's previous flow
    session_gap_sec Nullable(Float32),

    ingested_at     DateTime DEFAULT now(),

    -- Skip index
    INDEX idx_target_ip target_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first_ts)
ORDER BY (attacker_ip, first_ts)
TTL first_ts + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `model_predictions`

Per-flow predictions from any model. Denormalized with flow IPs + timestamp.

```sql
CREATE TABLE dfi.model_predictions
(
    -- Flow reference + denormalized identity
    flow_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    dst_port        UInt16,
    flow_first_ts   DateTime64(3),

    -- Prediction
    model_name      LowCardinality(String),  -- 'xgb_v1', 'cnn_v1', 'model3_v1'
    model_version   String,                  -- git hash or version tag
    label           UInt8,
    confidence      Float32,
    class_probs     Array(Float32),          -- [p0, p1, p2, p3, p4]

    -- When scored
    scored_at       DateTime64(3) DEFAULT now64(3),

    -- Skip indexes
    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(scored_at)
ORDER BY (flow_id, model_name, scored_at)
TTL scored_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `group_assignments`

Classifier assigns attacker IPs to behavior groups.

```sql
CREATE TABLE dfi.group_assignments
(
    attacker_ip     IPv4,
    group_id        LowCardinality(String),  -- RECON, CREDENTIAL_ATTACK, etc.
    sub_group_id    LowCardinality(String),  -- PORT_SCAN, SSH_BRUTE, etc.
    confidence      Float32,
    priority        UInt8,                   -- 1=P1, 2=P2, 3=P3
    window_start    DateTime64(3),
    window_end      DateTime64(3),
    feature_summary String,                  -- JSON: key features
    assigned_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(assigned_at)
ORDER BY (attacker_ip, assigned_at)
TTL assigned_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `depth_changes`

Every capture depth promotion/demotion.

```sql
CREATE TABLE dfi.depth_changes
(
    attacker_ip     IPv4,
    old_depth       UInt8,
    new_depth       UInt8,
    trigger_reason  String,
    triggered_by    LowCardinality(String),  -- 'classifier', 'analyst', 'rule'
    changed_at      DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(changed_at)
ORDER BY (attacker_ip, changed_at)
TTL changed_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `analyst_actions`

Human actions from Streamlit dashboard.

```sql
CREATE TABLE dfi.analyst_actions
(
    attacker_ip     IPv4,
    action_type     LowCardinality(String),  -- 'promote', 'block', 'watch', 'deprioritize', 'note'
    capture_depth   Nullable(UInt8),
    priority        Nullable(UInt8),
    reason          String,
    analyst_id      String,
    expires_at      Nullable(DateTime64(3)),
    acted_at        DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(acted_at)
ORDER BY (attacker_ip, acted_at)
TTL acted_at + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;
```

---

### Table: `payload_bytes` (D3, future)

```sql
CREATE TABLE dfi.payload_bytes
(
    -- Flow reference + denormalized identity
    flow_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    flow_first_ts   DateTime64(3),

    -- Payload
    seq_idx         UInt8,
    direction       Int8,
    ts              DateTime64(3),
    payload_head    String,                  -- first 512 bytes, hex-encoded
    payload_len     UInt16,

    -- Skip indexes
    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (flow_id, seq_idx)
TTL ts + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
```

---

## Traceability Audit

Every table stands alone — no JOIN needed for who/when/where:

| Table | Event timestamp | Attacker IP | Target IP | Reference key | Skip index |
|---|---|---|---|---|---|
| `flows` | `first_ts`, `last_ts`, `ingested_at` | `src_ip` | `dst_ip` | `flow_id` | dst_ip, src_ip |
| `packets` | `ts`, `flow_first_ts` | `src_ip` | `dst_ip` | `flow_id` + `seq_idx` | dst_ip, src_ip |
| `fingerprints` | `first_ts`, `ingested_at` | `src_ip` | `dst_ip` | `flow_id` | dst_ip, src_ip |
| `labels` | `flow_first_ts`, `labeled_at` | `src_ip` | `dst_ip` | `flow_id` | dst_ip, src_ip |
| `evidence_events` | `ts`, `ingested_at` | `src_ip` | `target_ip` | `event_id` | target_ip |
| `fanout_hops` | `first_ts`, `last_ts`, `ingested_at` | `attacker_ip` | `target_ip` | `flow_id` | target_ip |
| `model_predictions` | `flow_first_ts`, `scored_at` | `src_ip` | `dst_ip` | `flow_id` | dst_ip, src_ip |
| `group_assignments` | `window_start`, `window_end`, `assigned_at` | `attacker_ip` | n/a | `attacker_ip` + ts | — |
| `depth_changes` | `changed_at` | `attacker_ip` | n/a | `attacker_ip` + ts | — |
| `analyst_actions` | `acted_at`, `expires_at` | `attacker_ip` | n/a | `attacker_ip` + ts | — |
| `payload_bytes` | `ts`, `flow_first_ts` | `src_ip` | `dst_ip` | `flow_id` + `seq_idx` | dst_ip, src_ip |

**ORDER BY keys** are attacker-first (fast for "show me attacker X").
**Skip indexes** on target IPs enable "who touched honeypot Y?" without full scan.

---

## Buffer Tables

Hunter writes to buffer tables. Buffer auto-flushes to MergeTree.

```sql
CREATE TABLE dfi.flows_buffer AS dfi.flows
ENGINE = Buffer(dfi, flows,
    16, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE dfi.packets_buffer AS dfi.packets
ENGINE = Buffer(dfi, packets,
    16, 2, 10, 100000, 1000000, 50000000, 500000000);

CREATE TABLE dfi.fingerprints_buffer AS dfi.fingerprints
ENGINE = Buffer(dfi, fingerprints,
    8, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE dfi.evidence_events_buffer AS dfi.evidence_events
ENGINE = Buffer(dfi, evidence_events,
    8, 5, 30, 1000, 50000, 5000000, 50000000);

CREATE TABLE dfi.fanout_hops_buffer AS dfi.fanout_hops
ENGINE = Buffer(dfi, fanout_hops,
    16, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE dfi.model_predictions_buffer AS dfi.model_predictions
ENGINE = Buffer(dfi, model_predictions,
    8, 5, 30, 10000, 100000, 10000000, 100000000);
```

No buffers for `group_assignments`, `depth_changes`, `analyst_actions` —
low-volume writes, direct INSERT is fine.

---

## Materialized Views (auto-aggregates, zero maintenance)

### Source behavior stats (F8 features for ML export)

```sql
CREATE TABLE dfi.source_stats
(
    src_ip          IPv4,
    flow_count      AggregateFunction(count, UInt64),
    unique_ports    AggregateFunction(uniq, UInt16),
    unique_protos   AggregateFunction(uniq, UInt8),
    unique_dsts     AggregateFunction(uniq, IPv4),
    first_seen      AggregateFunction(min, DateTime64(3)),
    last_seen       AggregateFunction(max, DateTime64(3)),
    sum_pps         AggregateFunction(sum, Float32)
)
ENGINE = AggregatingMergeTree()
ORDER BY src_ip;

CREATE MATERIALIZED VIEW dfi.mv_source_stats
TO dfi.source_stats AS
SELECT
    src_ip,
    countState()               AS flow_count,
    uniqState(dst_port)        AS unique_ports,
    uniqState(app_proto)       AS unique_protos,
    uniqState(dst_ip)          AS unique_dsts,
    minState(first_ts)         AS first_seen,
    maxState(first_ts)         AS last_seen,
    sumState(pps)              AS sum_pps
FROM dfi.flows
GROUP BY src_ip;
```

### Fingerprint frequencies

```sql
CREATE TABLE dfi.fingerprint_freq
(
    field       String,
    hash_value  String,
    freq        AggregateFunction(count, UInt64)
)
ENGINE = AggregatingMergeTree()
ORDER BY (field, hash_value);

CREATE MATERIALIZED VIEW dfi.mv_ja3_freq
TO dfi.fingerprint_freq AS
SELECT 'ja3' AS field, ja3_hash AS hash_value, countState() AS freq
FROM dfi.fingerprints WHERE ja3_hash IS NOT NULL
GROUP BY ja3_hash;

CREATE MATERIALIZED VIEW dfi.mv_hassh_freq
TO dfi.fingerprint_freq AS
SELECT 'hassh' AS field, hassh_hash AS hash_value, countState() AS freq
FROM dfi.fingerprints WHERE hassh_hash IS NOT NULL
GROUP BY hassh_hash;

CREATE MATERIALIZED VIEW dfi.mv_ua_freq
TO dfi.fingerprint_freq AS
SELECT 'ua' AS field, http_ua_hash AS hash_value, countState() AS freq
FROM dfi.fingerprints WHERE http_ua_hash IS NOT NULL
GROUP BY http_ua_hash;
```

### Fanout summary (per-attacker movement stats)

```sql
CREATE TABLE dfi.fanout_stats
(
    attacker_ip     IPv4,
    hop_count       AggregateFunction(count, UInt64),
    unique_targets  AggregateFunction(uniq, IPv4),
    unique_ports    AggregateFunction(uniq, UInt16),
    unique_vlans    AggregateFunction(uniq, UInt16),
    first_seen      AggregateFunction(min, DateTime64(3)),
    last_seen       AggregateFunction(max, DateTime64(3)),
    sum_pkts_fwd    AggregateFunction(sum, UInt32),
    sum_bytes_fwd   AggregateFunction(sum, UInt32)
)
ENGINE = AggregatingMergeTree()
ORDER BY attacker_ip;

CREATE MATERIALIZED VIEW dfi.mv_fanout_stats
TO dfi.fanout_stats AS
SELECT
    attacker_ip,
    countState()               AS hop_count,
    uniqState(target_ip)       AS unique_targets,
    uniqState(dst_port)        AS unique_ports,
    uniqState(vlan_id)         AS unique_vlans,
    minState(first_ts)         AS first_seen,
    maxState(first_ts)         AS last_seen,
    sumState(pkts_fwd)         AS sum_pkts_fwd,
    sumState(bytes_fwd)        AS sum_bytes_fwd
FROM dfi.fanout_hops
GROUP BY attacker_ip;
```

---

## SQLite Watchlist (Hunter Hot Cache)

Disposable. Rebuildable from ClickHouse in minutes.

```sql
-- watchlist.db
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE watchlist (
    src_ip          TEXT PRIMARY KEY,
    capture_depth   INTEGER NOT NULL DEFAULT 1,  -- 0/1/2/3
    priority        INTEGER NOT NULL DEFAULT 3,  -- 1=P1, 2=P2, 3=P3
    group_id        TEXT,
    sub_group_id    TEXT,
    top_port        INTEGER,                     -- for D0 re-promotion check
    reason          TEXT,
    source          TEXT NOT NULL DEFAULT 'classifier',
    expires_at      REAL,                        -- epoch, NULL = no expiry
    updated_at      REAL DEFAULT (unixepoch('now'))
);

CREATE INDEX idx_wl_depth ON watchlist(capture_depth);
CREATE INDEX idx_wl_expires ON watchlist(expires_at) WHERE expires_at IS NOT NULL;
```

---

## Hunter Write Paths by Capture Depth

```
D0 — Nothing written. Flow dropped entirely.
     (Hunter still checks dst_port vs top_port for re-promotion)

D1 — flows_buffer        ✓  (capture_depth=1)
     fingerprints_buffer  ✓  (if protocol detected)
     fanout_hops_buffer   ✓  (movement tracking — always)

D2 — Everything in D1, plus:
     packets_buffer       ✓  (128 event packets, all 5 CNN tokens)
     capture_depth=2 on flows row

D3 — Everything in D2, plus:
     payload_bytes table  ✓  (first 512 bytes per packet)
     capture_depth=3 on flows row
```

---

## Incident Response Query: "Who killed 1.2.3.4?"

```sql
-- 1.2.3.4 went down at 14:30. Show me the last 5 minutes of
-- every attacker who touched it — all their traffic, everywhere.

-- Step 1: Who touched 1.2.3.4 in the window?
--         (skip index on target_ip makes this fast)
WITH attackers AS (
    SELECT DISTINCT attacker_ip
    FROM dfi.fanout_hops
    WHERE target_ip = '1.2.3.4'
      AND first_ts BETWEEN '2025-03-15 14:25:00' AND '2025-03-15 14:30:00'
)

-- Step 2: All their flows (to ANY target) in that window
SELECT f.flow_id, f.src_ip, f.dst_ip, f.dst_port, f.app_proto,
       f.vlan_id, f.first_ts, f.last_ts,
       f.pkts_fwd, f.pkts_rev, f.bytes_fwd, f.bytes_rev,
       f.conn_state, f.duration_ms, f.rtt_ms,
       f.entropy_first, f.n_events, f.capture_depth
FROM dfi.flows f
WHERE f.src_ip IN (SELECT attacker_ip FROM attackers)
  AND f.first_ts BETWEEN '2025-03-15 14:25:00' AND '2025-03-15 14:30:00'
ORDER BY f.src_ip, f.first_ts;

-- Step 3: Packet-level detail for those flows (D2+ only)
SELECT p.flow_id, p.src_ip, p.dst_ip, p.seq_idx, p.ts,
       p.direction, p.payload_len, p.tcp_flags,
       p.size_dir_token, p.flag_token, p.iat_log_ms_bin,
       p.iat_rtt_bin, p.entropy_bin, p.payload_entropy
FROM dfi.packets p
WHERE p.flow_id IN (
    SELECT f.flow_id FROM dfi.flows f
    WHERE f.src_ip IN (SELECT attacker_ip FROM attackers)
      AND f.first_ts BETWEEN '2025-03-15 14:25:00' AND '2025-03-15 14:30:00'
)
ORDER BY p.flow_id, p.seq_idx;

-- Step 4: Full movement timeline from fanout_hops
SELECT h.attacker_ip, h.target_ip, h.dst_port, h.app_proto,
       h.vlan_id, h.first_ts, h.last_ts,
       h.pkts_fwd, h.pkts_rev, h.conn_state,
       h.session_gap_sec
FROM dfi.fanout_hops h
WHERE h.attacker_ip IN (SELECT attacker_ip FROM attackers)
  AND h.first_ts BETWEEN '2025-03-15 14:25:00' AND '2025-03-15 14:30:00'
ORDER BY h.attacker_ip, h.first_ts;

-- Step 5: Evidence events on 1.2.3.4
SELECT e.ts, e.src_ip, e.event_type, e.event_detail,
       e.source_program, e.source_log
FROM dfi.evidence_events e
WHERE e.target_ip = '1.2.3.4'
  AND e.ts BETWEEN '2025-03-15 14:25:00' AND '2025-03-15 14:30:00'
ORDER BY e.ts;

-- Step 6: Model predictions for those flows
SELECT mp.flow_id, mp.src_ip, mp.dst_ip, mp.dst_port,
       mp.model_name, mp.label, mp.confidence
FROM dfi.model_predictions mp
WHERE mp.flow_id IN (
    SELECT f.flow_id FROM dfi.flows f
    WHERE f.src_ip IN (SELECT attacker_ip FROM attackers)
      AND f.first_ts BETWEEN '2025-03-15 14:25:00' AND '2025-03-15 14:30:00'
)
ORDER BY mp.src_ip, mp.flow_first_ts;
```

---

## Export: XGBoost (82 columns, flat CSV)

```sql
CREATE VIEW dfi.v_xgb AS
SELECT
    f.flow_id, f.session_key, f.actor_id,

    l.label, l.label_confidence, l.evidence_mask, l.evidence_detail,

    f.dst_port, f.ip_proto, f.app_proto,

    f.pkts_fwd, f.pkts_rev, f.bytes_fwd, f.bytes_rev,
    f.bytes_fwd / greatest(f.pkts_fwd, 1)                   AS bytes_per_pkt_fwd,
    if(f.pkts_rev > 0, f.bytes_rev / f.pkts_rev, NULL)      AS bytes_per_pkt_rev,
    f.pkts_fwd / greatest(f.pkts_rev, 1)                    AS pkt_ratio,
    f.bytes_fwd / greatest(f.bytes_rev, 1)                   AS byte_ratio,

    f.duration_ms, f.rtt_ms,
    f.iat_fwd_mean_ms, f.iat_fwd_std_ms,
    f.think_time_mean_ms, f.think_time_std_ms,
    f.iat_to_rtt, f.pps, f.bps, f.payload_rtt_ratio,

    f.n_events, f.fwd_size_mean, f.fwd_size_std,
    f.fwd_size_min, f.fwd_size_max,
    f.rev_size_mean, f.rev_size_std, f.rev_size_max,
    f.hist_tiny, f.hist_small, f.hist_medium,
    f.hist_large, f.hist_full, f.frac_full,

    f.syn_count, f.fin_count, f.rst_count, f.psh_count,
    f.ack_only_count, f.conn_state, f.rst_frac,
    f.syn_to_data, f.psh_burst_max, f.retransmit_est,
    f.window_size_init,

    f.entropy_first, f.entropy_fwd_mean, f.entropy_rev_mean,
    f.printable_frac, f.null_frac, f.byte_std,
    f.high_entropy_frac, f.payload_len_first,

    coalesce(fq_ja3.freq, 0)   AS ja3_freq,
    fp.tls_version, fp.tls_cipher_count,
    fp.tls_ext_count, fp.tls_has_sni,
    coalesce(fq_hassh.freq, 0) AS hassh_freq,
    fp.ssh_kex_count,
    fp.http_method, fp.http_uri_len, fp.http_header_count,
    coalesce(fq_ua.freq, 0)    AS http_ua_freq,
    fp.http_has_body, fp.http_status,
    fp.dns_qtype, fp.dns_qname_len,

    countMerge(ss.flow_count)         AS src_flow_count,
    uniqMerge(ss.unique_ports)        AS src_unique_ports,
    uniqMerge(ss.unique_protos)       AS src_unique_protos,
    uniqMerge(ss.unique_dsts)         AS src_unique_dsts,
    dateDiff('minute',
        minMerge(ss.first_seen),
        maxMerge(ss.last_seen))       AS src_span_min,
    sumMerge(ss.sum_pps) /
        greatest(countMerge(ss.flow_count), 1) AS src_avg_pps

FROM dfi.flows f
INNER JOIN dfi.labels l FINAL ON l.flow_id = f.flow_id
LEFT JOIN dfi.fingerprints fp ON fp.flow_id = f.flow_id
LEFT JOIN dfi.source_stats ss ON ss.src_ip = f.src_ip
LEFT JOIN (
    SELECT hash_value, countMerge(freq) AS freq
    FROM dfi.fingerprint_freq WHERE field = 'ja3'
    GROUP BY hash_value
) fq_ja3 ON fq_ja3.hash_value = fp.ja3_hash
LEFT JOIN (
    SELECT hash_value, countMerge(freq) AS freq
    FROM dfi.fingerprint_freq WHERE field = 'hassh'
    GROUP BY hash_value
) fq_hassh ON fq_hassh.hash_value = fp.hassh_hash
LEFT JOIN (
    SELECT hash_value, countMerge(freq) AS freq
    FROM dfi.fingerprint_freq WHERE field = 'ua'
    GROUP BY hash_value
) fq_ua ON fq_ua.hash_value = fp.http_ua_hash
GROUP BY
    f.flow_id, f.session_key, f.actor_id, f.src_ip,
    f.dst_port, f.ip_proto, f.app_proto,
    f.pkts_fwd, f.pkts_rev, f.bytes_fwd, f.bytes_rev,
    f.duration_ms, f.rtt_ms, f.iat_fwd_mean_ms, f.iat_fwd_std_ms,
    f.think_time_mean_ms, f.think_time_std_ms,
    f.iat_to_rtt, f.pps, f.bps, f.payload_rtt_ratio,
    f.n_events, f.fwd_size_mean, f.fwd_size_std,
    f.fwd_size_min, f.fwd_size_max,
    f.rev_size_mean, f.rev_size_std, f.rev_size_max,
    f.hist_tiny, f.hist_small, f.hist_medium,
    f.hist_large, f.hist_full, f.frac_full,
    f.syn_count, f.fin_count, f.rst_count, f.psh_count,
    f.ack_only_count, f.conn_state, f.rst_frac,
    f.syn_to_data, f.psh_burst_max, f.retransmit_est,
    f.window_size_init,
    f.entropy_first, f.entropy_fwd_mean, f.entropy_rev_mean,
    f.printable_frac, f.null_frac, f.byte_std,
    f.high_entropy_frac, f.payload_len_first,
    l.label, l.label_confidence, l.evidence_mask, l.evidence_detail,
    fp.tls_version, fp.tls_cipher_count, fp.tls_ext_count, fp.tls_has_sni,
    fp.ssh_kex_count, fp.http_method, fp.http_uri_len,
    fp.http_header_count, fp.http_has_body, fp.http_status,
    fp.dns_qtype, fp.dns_qname_len,
    fp.ja3_hash, fp.hassh_hash, fp.http_ua_hash,
    fq_ja3.freq, fq_hassh.freq, fq_ua.freq;
```

```bash
# Full export
clickhouse-client --query "SELECT * FROM dfi.v_xgb FORMAT CSVWithNames" \
    > dfi_xgb_v1.csv

# High-confidence only
clickhouse-client --query \
    "SELECT * FROM dfi.v_xgb WHERE label_confidence >= 0.8 FORMAT CSVWithNames" \
    > dfi_xgb_highconf.csv

# Balanced sample (1000 per class)
clickhouse-client --query "
    SELECT * FROM (
        SELECT *, row_number() OVER (PARTITION BY label ORDER BY rand()) AS rn
        FROM dfi.v_xgb
    ) WHERE rn <= 1000
    FORMAT CSVWithNames
" > dfi_xgb_balanced.csv

# Last 24 hours only
clickhouse-client --query "
    SELECT * FROM dfi.v_xgb
    WHERE flow_id IN (
        SELECT flow_id FROM dfi.flows
        WHERE first_ts >= now() - INTERVAL 1 DAY
    ) FORMAT CSVWithNames
" > dfi_xgb_24h.csv
```

---

## Export: CNN (689 columns)

ClickHouse `groupArray` pivots packets into arrays natively — no Python loop needed
for the sequence assembly.

```sql
CREATE VIEW dfi.v_cnn_sequences AS
SELECT
    flow_id,
    groupArray(128)(size_dir_token)  AS size_dir_arr,
    groupArray(128)(flag_token)      AS tcp_flags_arr,
    groupArray(128)(iat_log_ms_bin)  AS iat_log_ms_arr,
    groupArray(128)(iat_rtt_bin)     AS iat_rtt_bin_arr,
    groupArray(128)(entropy_bin)     AS entropy_bin_arr
FROM (
    SELECT * FROM dfi.packets ORDER BY flow_id, seq_idx
)
GROUP BY flow_id;
```

```python
#!/usr/bin/env python3
"""export_cnn.py — ClickHouse → CNN CSV (689 columns)"""

import csv, sys
from clickhouse_driver import Client

CH   = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
OUT  = sys.argv[2] if len(sys.argv) > 2 else 'dfi_cnn_v1.csv'
SLEN = 128
CHANNELS = ['size_dir_seq', 'tcp_flags_seq', 'iat_log_ms_seq',
            'iat_rtt_bin_seq', 'entropy_bin_seq']

ch = Client(CH)

# Static features from XGBoost view
meta = ch.execute("SELECT * FROM dfi.v_xgb LIMIT 0", with_column_types=True)
xgb_cols = [c[0] for c in meta[1]]

ID_LABEL = ['flow_id', 'session_key', 'actor_id',
            'label', 'label_confidence', 'evidence_mask', 'evidence_detail']
STATIC = [c for c in xgb_cols if c not in ID_LABEL]

seq_col_names = []
for ch_name in CHANNELS:
    seq_col_names += [f'{ch_name}_{i}' for i in range(1, SLEN + 1)]

header = ID_LABEL + seq_col_names + STATIC

# Fetch sequences
seq_data = ch.execute("SELECT * FROM dfi.v_cnn_sequences")
seq_map = {}
for row in seq_data:
    fid = row[0]
    arrs = {}
    for i, ch_name in enumerate(CHANNELS):
        a = list(row[i + 1])
        a += [0] * (SLEN - len(a))
        arrs[ch_name] = a[:SLEN]
    seq_map[fid] = arrs

# Fetch static
xgb_data = ch.execute("SELECT * FROM dfi.v_xgb")

with open(OUT, 'w', newline='') as fp:
    w = csv.writer(fp)
    w.writerow(header)
    for xgb_row in xgb_data:
        rd = dict(zip(xgb_cols, xgb_row))
        fid = rd['flow_id']
        vals = [rd.get(c, '') for c in ID_LABEL]
        if fid in seq_map:
            for ch_name in CHANNELS:
                vals.extend(seq_map[fid][ch_name])
        else:
            vals.extend([0] * SLEN * len(CHANNELS))
        vals.extend([rd.get(c, '') for c in STATIC])
        w.writerow(vals)

print(f"Exported {len(xgb_data)} rows to {OUT}")
```

---

## Hunter Integration — Batched Insert

```python
"""
Hunter insert module — batch writes to ClickHouse Buffer tables.
Called from your AF_PACKET TPACKET_V3 capture loop after flow reassembly.
"""

from clickhouse_driver import Client
from collections import deque
import threading, time

class DFIWriter:
    FLUSH_INTERVAL = 1.0    # seconds
    FLUSH_SIZE     = 50000  # rows trigger

    def __init__(self, host='localhost'):
        self.ch = Client(host, settings={
            'insert_block_size': 1000000,
            'max_insert_block_size': 1000000,
        })
        self._flow_buf = deque()
        self._pkt_buf  = deque()
        self._fp_buf   = deque()
        self._fanout_buf = deque()
        self._evidence_buf = deque()
        self._pred_buf = deque()
        self._lock     = threading.Lock()
        self._flusher  = threading.Thread(target=self._flush_loop, daemon=True)
        self._flusher.start()

    def insert_flow(self, flow: dict, pkts: list, fp: dict,
                    fanout: dict, depth: int):
        """Queue one flow at appropriate capture depth."""
        with self._lock:
            # D1+: always write flow + fingerprint + fanout
            self._flow_buf.append(flow)
            if fp:
                self._fp_buf.append(fp)
            self._fanout_buf.append(fanout)

            # D2+: write packets
            if depth >= 2 and pkts:
                self._pkt_buf.extend(pkts)

            if len(self._flow_buf) >= self.FLUSH_SIZE:
                self._flush_unlocked()

    def insert_evidence(self, events: list):
        """Queue evidence events from honeypot logs."""
        with self._lock:
            self._evidence_buf.extend(events)

    def insert_predictions(self, preds: list):
        """Queue model prediction results."""
        with self._lock:
            self._pred_buf.extend(preds)

    def _flush_loop(self):
        while True:
            time.sleep(self.FLUSH_INTERVAL)
            with self._lock:
                self._flush_unlocked()

    def _flush_unlocked(self):
        if self._flow_buf:
            self._batch_insert('dfi.flows_buffer', self._flow_buf)
        if self._pkt_buf:
            self._batch_insert('dfi.packets_buffer', self._pkt_buf)
        if self._fp_buf:
            self._batch_insert('dfi.fingerprints_buffer', self._fp_buf)
        if self._fanout_buf:
            self._batch_insert('dfi.fanout_hops_buffer', self._fanout_buf)
        if self._evidence_buf:
            self._batch_insert('dfi.evidence_events_buffer', self._evidence_buf)
        if self._pred_buf:
            self._batch_insert('dfi.model_predictions_buffer', self._pred_buf)

    def _batch_insert(self, table, buf):
        rows = list(buf)
        buf.clear()
        if not rows:
            return
        cols = list(rows[0].keys())
        data = [list(r.values()) for r in rows]
        try:
            self.ch.execute(
                f"INSERT INTO {table} ({','.join(cols)}) VALUES",
                data, types_check=True
            )
        except Exception as e:
            # Re-queue on failure (bounded retry)
            if len(buf) < self.FLUSH_SIZE * 10:
                buf.extend(rows)
            else:
                print(f"DROP {len(rows)} rows for {table}: {e}")
```

---

## Operational Queries

```bash
# Ingest rate — is Hunter keeping up?
clickhouse-client --query "
    SELECT toStartOfMinute(first_ts) AS minute,
           count() AS flows_per_min,
           round(count() / 60, 0) AS flows_per_sec
    FROM dfi.flows
    WHERE first_ts >= now() - INTERVAL 1 HOUR
    GROUP BY minute ORDER BY minute DESC LIMIT 10
"

# Label distribution
clickhouse-client --query "
    SELECT label, count() AS n, round(avg(label_confidence), 2) AS avg_conf
    FROM dfi.labels FINAL GROUP BY label ORDER BY label
"

# Storage per table + compression ratio
clickhouse-client --query "
    SELECT table,
           formatReadableSize(sum(data_uncompressed_bytes)) AS raw,
           formatReadableSize(sum(data_compressed_bytes)) AS compressed,
           round(sum(data_uncompressed_bytes) /
                 greatest(sum(data_compressed_bytes), 1), 1) AS ratio,
           sum(rows) AS rows
    FROM system.parts WHERE database = 'dfi' AND active
    GROUP BY table ORDER BY sum(data_uncompressed_bytes) DESC
"

# Top attacking IPs (from materialized view — instant)
clickhouse-client --query "
    SELECT src_ip,
           countMerge(flow_count) AS flows,
           uniqMerge(unique_ports) AS ports,
           uniqMerge(unique_dsts) AS targets
    FROM dfi.source_stats GROUP BY src_ip
    ORDER BY flows DESC LIMIT 20
"

# Total data volume
clickhouse-client --query "
    SELECT count() AS total_flows,
           formatReadableSize(sum(bytes_fwd + bytes_rev)) AS traffic,
           min(first_ts) AS oldest, max(first_ts) AS newest
    FROM dfi.flows
"
```

---

## Storage Estimates (with ClickHouse columnar compression)

| Component | Per 100K flows | Per 1M flows | Per 10M flows |
|---|---|---|---|
| flows | ~15 MB | ~150 MB | ~1.5 GB |
| packets (~30/flow) | ~50 MB | ~500 MB | ~5 GB |
| fingerprints | ~5 MB | ~50 MB | ~500 MB |
| labels | ~2 MB | ~20 MB | ~200 MB |
| fanout_hops | ~10 MB | ~100 MB | ~1 GB |
| evidence_events | ~2 MB | ~20 MB | ~200 MB |
| model_predictions | ~3 MB | ~30 MB | ~300 MB |
| group_assignments | <1 MB | ~5 MB | ~20 MB |
| depth_changes | <1 MB | <1 MB | ~5 MB |
| analyst_actions | <1 MB | <1 MB | <1 MB |
| materialized views | ~2 MB | ~10 MB | ~40 MB |
| **Total compressed** | **~75 MB** | **~750 MB** | **~7.5 GB** |

Token columns compress 15–25× (small integer vocab, lots of zero padding = LZ4 heaven).

**At 100K flows/sec sustained: ~65 GB/day compressed. 90-day TTL ≈ 6 TB.**

---

## Compared to SQLite

| Metric | SQLite WAL | ClickHouse |
|---|---|---|
| Max sustained flow inserts/sec | ~5,000 | 500,000+ |
| Max packet inserts/sec | ~20,000 | 10,000,000+ |
| XGBoost export (1M flows) | 30+ sec | <2 sec |
| CNN export (1M flows) | minutes | <10 sec |
| Compression | none | 15–25× |
| Concurrent read during write | 1 reader | unlimited |
| Auto-aggregate maintenance | manual cron | materialized views |
| TTL cleanup | manual DELETE + VACUUM | automatic partition drop |
| 40Gbps SPAN | impossible | comfortable |
