# ClickHouse Schema

DDL scripts for all ClickHouse databases and tables used by SwarmTrap. The files are numbered for application order -- run them sequentially on a fresh ClickHouse instance.

## Application Order

```bash
clickhouse-client --multiquery < 01_tables.sql
clickhouse-client --multiquery < 02_behavioral.sql
clickhouse-client --multiquery < 03_buffers.sql
clickhouse-client --multiquery < 04_views.sql
clickhouse-client --multiquery < 05_watchlist.sql        # SQLite, not ClickHouse
clickhouse-client --multiquery < 06_backend_api_audit.sql
clickhouse-client --multiquery < 07_norm_db.sql
clickhouse-client --multiquery < 08_recon_db.sql
clickhouse-client --multiquery < 09_clean_db.sql
clickhouse-client --multiquery < 10_dirty_db.sql
clickhouse-client --multiquery < 11_session_stats.sql
clickhouse-client --multiquery < 12_session_stats_aio.sql
clickhouse-client --multiquery < 13_conversations.sql
clickhouse-client --multiquery < 15_ip_reputation.sql
clickhouse-client --multiquery < ip_profile.sql
```

Note: `05_watchlist.sql` is SQLite DDL (not ClickHouse) -- run it with `sqlite3 /opt/dfi-hunter/watchlist.db < 05_watchlist.sql`.

## Database Layout

| Database | Purpose |
|----------|---------|
| `dfi` | Primary database. Attack/labeled flows, evidence, predictions, sessions, conversations, IP reputation. |
| `dfi_norm` | High-quality norm (clean) traffic. Only flows with XGB confidence > 0.8. No SET indexes, MergeTree labels (immutable). |
| `dfi_clean` | Clean SPAN traffic. Excludes all watchlist and honeypot IPs. Flows + session_stats only. |
| `dfi_dirty` | Dirty SPAN traffic. Only watchlist/honeypot IPs at D2 depth. Flows + session_stats only. |
| `dfi_recon` | Threat intelligence. High-confidence recon/attack detections. 7-day TTL. |

## Table Inventory

### 01_tables.sql -- Core Flow Tables (database: dfi)

| Table | Engine | Order By | TTL | Description |
|-------|--------|----------|-----|-------------|
| `flows` | MergeTree | (dst_port, src_ip, first_ts) | 90 days | Core flow table. 75 features + 5 CNN array columns (128 tokens each) + inline labels. Partitioned by day on first_ts. |
| `packets` | MergeTree | (flow_id, seq_idx) | 90 days | Per-packet records with pre-computed CNN tokens (size_dir_token, flag_token, iat_log_ms_bin, iat_rtt_bin, entropy_bin) and raw values (iat_ms, payload_entropy). |
| `fingerprints` | MergeTree | (flow_id) | 90 days | Protocol fingerprints per flow: JA3 hash, TLS metadata, HASSH hash, SSH kex count, HTTP method/headers/UA hash, DNS qtype/qname. |
| `labels` | ReplacingMergeTree(labeled_at) | (flow_id) | -- | Flow-level labels. ReplacingMergeTree ensures latest label wins on FINAL. Fields: label (UInt8), label_confidence, evidence_mask, evidence_detail. |

### 02_behavioral.sql -- Behavioral Tables (database: dfi)

| Table | Engine | Order By | TTL | Description |
|-------|--------|----------|-----|-------------|
| `evidence_events` | MergeTree | (src_ip, ts) | 180 days | Honeypot evidence events: auth failures, process creation, privilege escalation, lateral movement, etc. Source programs include winlure, trap, sensor-agent. |
| `fanout_hops` | MergeTree | (attacker_ip, first_ts) | 180 days | Per-hop records tracking attacker-to-target connections with volume, duration, and connection state. |
| `model_predictions` | MergeTree | (flow_id, model_name, scored_at) | 180 days | XGBoost and CNN prediction results per flow. Stores label, confidence, and full class probability array. |
| `group_assignments` | MergeTree | (attacker_ip, assigned_at) | 180 days | Attacker group/campaign membership with confidence, priority, and feature summary. |
| `depth_changes` | MergeTree | (attacker_ip, changed_at) | 180 days | Audit log of capture depth changes (D0/D1/D2/D3 transitions) with trigger reason and source. |
| `analyst_actions` | MergeTree | (attacker_ip, acted_at) | 365 days | SOC analyst manual actions: depth changes, priority overrides, with reason and analyst ID. |
| `watchlist_syncs` | MergeTree | (attacker_ip, synced_at) | 180 days | Audit log of watchlist synchronization events. |
| `payload_bytes` | MergeTree | (flow_id, seq_idx) | 30 days | Raw payload hex bytes (D3 depth only). Short 30-day TTL due to storage cost. |

### 03_buffers.sql -- Buffer Tables (database: dfi)

Buffer tables sit in front of the main MergeTree tables and batch inserts for write amplification reduction. Hunter2 writes to `*_buffer` tables; ClickHouse flushes to the backing table automatically.

| Buffer Table | Backing Table | Shards | Min/Max Time | Min/Max Rows | Min/Max Bytes |
|-------------|---------------|--------|--------------|--------------|---------------|
| `flows_buffer` | `flows` | 16 | 5s / 30s | 10K / 100K | 10MB / 100MB |
| `packets_buffer` | `packets` | 16 | 2s / 10s | 100K / 1M | 50MB / 500MB |
| `fingerprints_buffer` | `fingerprints` | 8 | 5s / 30s | 10K / 100K | 10MB / 100MB |
| `evidence_events_buffer` | `evidence_events` | 8 | 5s / 30s | 1K / 50K | 5MB / 50MB |
| `fanout_hops_buffer` | `fanout_hops` | 16 | 5s / 30s | 10K / 100K | 10MB / 100MB |
| `model_predictions_buffer` | `model_predictions` | 8 | 5s / 30s | 10K / 100K | 10MB / 100MB |
| `payload_bytes_buffer` | `payload_bytes` | 8 | 5s / 30s | 10K / 100K | 10MB / 100MB |

### 04_views.sql -- Materialized Views and Views (database: dfi)

| Object | Type | Description |
|--------|------|-------------|
| `source_stats` | AggregatingMergeTree | Per-source-IP aggregated statistics: flow count, unique ports/protocols/destinations, first/last seen, avg PPS. |
| `mv_source_stats` | Materialized View | Auto-populates `source_stats` from `flows` inserts. |
| `fingerprint_freq` | AggregatingMergeTree | Frequency counts for JA3, HASSH, and HTTP User-Agent hashes. |
| `mv_ja3_freq` | Materialized View | Auto-counts JA3 hash frequencies. |
| `mv_hassh_freq` | Materialized View | Auto-counts HASSH hash frequencies. |
| `mv_ua_freq` | Materialized View | Auto-counts User-Agent hash frequencies. |
| `fanout_stats` | AggregatingMergeTree | Per-attacker fanout aggregates: hop count, unique targets/ports/VLANs, total packets/bytes. |
| `mv_fanout_stats` | Materialized View | Auto-populates `fanout_stats` from `fanout_hops` inserts. |
| `v_xgb` | View | Full 75-feature XGB training view. Joins flows + labels + fingerprints + source_stats + fingerprint_freq. Warning: heavy view -- do NOT use for bulk export (causes OOM). Use raw exports + Python joins instead. |
| `v_cnn_sequences` | View | Aggregates packet-level tokens into per-flow arrays (128 tokens per channel). |

### 05_watchlist.sql -- SQLite Watchlist

The watchlist is SQLite (not ClickHouse) because it needs fast single-row reads in the capture hot path.

| Table | Description |
|-------|-------------|
| `watchlist` | Primary key on `src_ip`. Fields: capture_depth (0-3), priority (1-3), group_id, sub_group_id, top_port, reason, source, expires_at (Unix timestamp), updated_at. WAL journal mode. |

### 06_backend_api_audit.sql -- API Audit Extensions

Adds `request_id` columns to `analyst_actions`, `depth_changes`, and `watchlist_syncs` for request correlation. Creates `campaign_members` table (ReplacingMergeTree) for campaign-based bulk actions with 30-day TTL.

### 07_norm_db.sql -- Norm Database (database: dfi_norm)

Mirror of the dfi schema for high-quality norm traffic. Key differences:
- No SET indexes (speed optimization)
- `labels` uses MergeTree (not ReplacingMergeTree -- labels are immutable)
- `v_xgb_norm` view hardcodes fingerprint and source_stats features as 0 (norm traffic has none)
- Includes Buffer tables for flows, packets, and model_predictions

### 08_recon_db.sql -- Recon Database (database: dfi_recon)

Slim operational store for high-confidence reconnaissance and attack detections.

| Table | Engine | TTL | Description |
|-------|--------|-----|-------------|
| `recon_flows` | MergeTree | 7 days | Flow-level recon detections: flow_id, src/dst IPs, port, probability, model version, detection type (recon or attack). |
| `recon_flows_buffer` | Buffer | -- | Write buffer for recon_flows. |

### 09_clean_db.sql -- Clean Database (database: dfi_clean)

Minimal schema for clean (non-attack) SPAN traffic. Contains only `flows` and `flows_buffer`. Same column layout as dfi.flows but without labels, predictions, or fingerprints. 90-day TTL.

### 10_dirty_db.sql -- Dirty Database (database: dfi_dirty)

Same structure as dfi_clean but for dirty (watchlist/honeypot) traffic captured at D2 depth. Contains `flows` and `flows_buffer`. 90-day TTL.

### 11_session_stats.sql -- Session Statistics (database: dfi)

Session-level aggregation for ML: groups flows by (src_ip, dst_ip, dst_port).

| Object | Type | Description |
|--------|------|-------------|
| `session_stats` | AggregatingMergeTree | Per-session aggregates: flow count, bytes/packets forward+reverse, temporal bounds, max duration, max bytes_rev, TCP flag sums, connection state distributions, bidirectional flow ratio. |
| `mv_session_stats` | Materialized View | Auto-populates from `dfi.flows` inserts. |
| `v_session_features` | View | Computes 20 session features from the aggregated state: volume (6), temporal (2), depth (5), TCP behavior (4), plus raw timestamps. |
| `session_predictions` | ReplacingMergeTree | Session-level model scores with kill_chain_stage (0-4). 30-day TTL. |

### 12_session_stats_aio.sql -- Session Statistics for Dirty/Clean

Creates identical `session_stats` tables and materialized views in `dfi_dirty` and `dfi_clean` databases. Includes commented-out backfill INSERT statements.

### 13_conversations.sql -- Conversation Tables (database: dfi)

Multi-turn conversation tracking. Flows are grouped by src_ip with 30-minute gap detection.

| Table | Engine | TTL | Description |
|-------|--------|-----|-------------|
| `conversations` | ReplacingMergeTree(assembled_at) | 90 days | One row per conversation with 42 static features across 8 groups: Scale (6), Rhythm (8), Volume (6), Escalation (8), Service Targeting (6), Model Consensus (4), Actor Context (4). Inline labels with 6-class behavioral archetypes. |
| `conversation_turns` | MergeTree | 90 days | Per-turn features with 12 pre-tokenized channels: service_target, flow_outcome, xgb_prediction, xgb_confidence, cnn_prediction, cnn_confidence, model_agreement, turn_duration, inter_turn_gap, data_volume, data_direction, port_novelty. |
| `conversation_labels` | ReplacingMergeTree(labeled_at) | 90 days | 6-class behavioral labels: COMMODITY_BOT (0), COORDINATED_CAMPAIGN (1), HUMAN_OPERATOR (2), RESEARCH_BENIGN (3), UNKNOWN (4), CLEAN_BASELINE (5). Includes label tier (1=evidence, 2=reputation, 3=cluster, 4=heuristic) and flow-level distribution stats. |
| `conversation_predictions` | MergeTree | 180 days | Conversation-level model scores with class probabilities. |
| `v_conversation_summary` | View | Dashboard view joining conversations with conversation_labels. |

### 15_ip_reputation.sql -- IP Reputation (database: dfi)

Central shared state for capture decisions. Prevents training data contamination.

| Table | Engine | TTL | Description |
|-------|--------|-----|-------------|
| `ip_reputation` | ReplacingMergeTree(updated_at) | expires_at + 7 days | Per-IP reputation record: state (UNKNOWN/DIRTY/EVIDENCE/RESEARCH_BENIGN/CLEAN), evidence aggregates, best model scores across services, 4-factor capture score (reputation 0-40, service 0-25, direction 0-20, novelty 0-15 = total 0-100), watchlist projection, contamination control fields. |
| `mv_ip_reputation_evidence` | Materialized View | -- | Auto-populates ip_reputation from evidence_events. Sets state=EVIDENCE, label_source=EVIDENCE, priority=1, capture_depth=D2. |

### ip_profile.sql -- IP Profile (database: dfi)

| Table | Engine | Description |
|-------|--------|-------------|
| `ip_profile` | ReplacingMergeTree(updated_at) | Compact per-IP profile: services seen, per-service classifications, evidence counts, flow statistics, XGB clean ratio, verdict (NONE/DROP/WATCH/ALLOW), verdict group, verdict expiry. |

## Engine Types Used

| Engine | Purpose | Used By |
|--------|---------|---------|
| `MergeTree` | Standard append-only storage with TTL, partitioning, and skip indexes | flows, packets, evidence_events, fanout_hops, model_predictions, payload_bytes, conversation_turns |
| `ReplacingMergeTree` | Deduplication by ORDER BY key, latest version wins on FINAL | labels, conversations, conversation_labels, ip_reputation, ip_profile, session_predictions, campaign_members |
| `AggregatingMergeTree` | Pre-aggregated state using -State/-Merge combinator functions | source_stats, fingerprint_freq, fanout_stats, session_stats |
| `Buffer` | In-memory write buffer that flushes to backing MergeTree table | All *_buffer tables |

## TTL Policies

| TTL Duration | Tables |
|-------------|--------|
| 7 days | dfi_recon.recon_flows |
| 30 days | payload_bytes, session_predictions, campaign_members |
| 90 days | flows, packets, fingerprints, dfi_norm.*, dfi_clean.flows, dfi_dirty.flows, conversations, conversation_turns, conversation_labels |
| 180 days | evidence_events, fanout_hops, model_predictions, group_assignments, depth_changes, watchlist_syncs, dfi_norm.model_predictions, conversation_predictions |
| 365 days | analyst_actions |
| Dynamic | ip_reputation (expires_at + 7 days) |

## Partitioning

Most tables are partitioned by `toYYYYMMDD(first_ts)` or equivalent timestamp column. This enables efficient time-range queries and TTL-based partition dropping.

## Skip Indexes

Most tables include `SET(0)` skip indexes on `src_ip` and/or `dst_ip` columns with granularity 4. These accelerate IP-based lookups without adding significant write overhead.
