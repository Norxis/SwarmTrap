CREATE TABLE IF NOT EXISTS dfi.evidence_events
(
    event_id        String,
    ts              DateTime64(3),
    src_ip          IPv4,
    target_ip       IPv4,
    target_vlan     UInt16       DEFAULT 0,
    event_type      LowCardinality(String),
    event_detail    String,
    evidence_mask_bit UInt8,
    source_program  LowCardinality(String),
    source_log      String,
    ingested_at     DateTime DEFAULT now(),

    INDEX idx_target_ip target_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src_ip, ts)
TTL ts + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi.fanout_hops
(
    flow_id         String,
    attacker_ip     IPv4,
    target_ip       IPv4,
    dst_port        UInt16,
    app_proto       UInt8,
    vlan_id         UInt16       DEFAULT 0,
    first_ts        DateTime64(3),
    last_ts         DateTime64(3),

    pkts_fwd        UInt32,
    pkts_rev        UInt32,
    bytes_fwd       UInt32,
    bytes_rev       UInt32,
    duration_ms     UInt32,
    conn_state      UInt8,
    n_events        UInt16,

    session_gap_sec Nullable(Float32),

    ingested_at     DateTime DEFAULT now(),

    INDEX idx_target_ip target_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first_ts)
ORDER BY (attacker_ip, first_ts)
TTL first_ts + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi.model_predictions
(
    flow_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    dst_port        UInt16,
    flow_first_ts   DateTime64(3),

    model_name      LowCardinality(String),
    model_version   String,
    label           UInt8,
    confidence      Float32,
    class_probs     Array(Float32),

    scored_at       DateTime64(3) DEFAULT now64(3),

    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(scored_at)
ORDER BY (flow_id, model_name, scored_at)
TTL scored_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi.group_assignments
(
    attacker_ip     IPv4,
    group_id        LowCardinality(String),
    sub_group_id    LowCardinality(String),
    confidence      Float32,
    priority        UInt8,
    window_start    DateTime64(3),
    window_end      DateTime64(3),
    feature_summary String,
    assigned_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(assigned_at)
ORDER BY (attacker_ip, assigned_at)
TTL assigned_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi.depth_changes
(
    attacker_ip     IPv4,
    old_depth       UInt8,
    new_depth       UInt8,
    trigger_reason  String,
    triggered_by    LowCardinality(String),
    changed_at      DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(changed_at)
ORDER BY (attacker_ip, changed_at)
TTL changed_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi.analyst_actions
(
    attacker_ip     IPv4,
    action_type     LowCardinality(String),
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

CREATE TABLE IF NOT EXISTS dfi.watchlist_syncs
(
    attacker_ip     IPv4,
    capture_depth   UInt8,
    priority        UInt8,
    group_id        LowCardinality(String),
    sub_group_id    LowCardinality(String),
    source          LowCardinality(String),
    reason          String,
    expires_at      Nullable(DateTime64(3)),
    synced_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(synced_at)
ORDER BY (attacker_ip, synced_at)
TTL synced_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi.payload_bytes
(
    flow_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    flow_first_ts   DateTime64(3),

    seq_idx         UInt8,
    direction       Int8,
    ts              DateTime64(3),
    payload_head    String,
    payload_len     UInt16,

    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (flow_id, seq_idx)
TTL ts + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
