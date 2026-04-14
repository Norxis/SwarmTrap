-- WinHunt ClickHouse tables — matches agent buffer schema exactly.
-- Run on PV1: clickhouse-client < schema.sql

-- Flows with full XGB feature set
CREATE TABLE IF NOT EXISTS dfi.wh_flows
(
    flow_id            String,
    session_key        String,
    src_ip             String,
    dst_ip             String,
    src_port           UInt16,
    dst_port           UInt16,
    ip_proto           UInt8,
    app_proto          UInt8         DEFAULT 0,
    first_ts           String,
    last_ts            String,

    -- F2. Volume
    pkts_fwd           UInt32,
    pkts_rev           UInt32,
    bytes_fwd          UInt32,
    bytes_rev          UInt32,

    -- F3. Timing
    rtt_ms             Nullable(Float32),
    duration_ms        UInt32,
    iat_fwd_mean_ms    Nullable(Float32),
    iat_fwd_std_ms     Nullable(Float32),
    think_time_mean_ms Nullable(Float32),
    think_time_std_ms  Nullable(Float32),
    iat_to_rtt         Nullable(Float32),
    pps                Float32,
    bps                Float32,
    payload_rtt_ratio  Nullable(Float32),

    -- F4. Size shape
    n_events           UInt16,
    fwd_size_mean      Nullable(Float32),
    fwd_size_std       Nullable(Float32),
    fwd_size_min       UInt16        DEFAULT 0,
    fwd_size_max       UInt16        DEFAULT 0,
    rev_size_mean      Nullable(Float32),
    rev_size_std       Nullable(Float32),
    rev_size_max       UInt16        DEFAULT 0,
    hist_tiny          UInt16        DEFAULT 0,
    hist_small         UInt16        DEFAULT 0,
    hist_medium        UInt16        DEFAULT 0,
    hist_large         UInt16        DEFAULT 0,
    hist_full          UInt16        DEFAULT 0,
    frac_full          Float32       DEFAULT 0,

    -- F5. TCP behavior
    syn_count          UInt8         DEFAULT 0,
    fin_count          UInt8         DEFAULT 0,
    rst_count          UInt8         DEFAULT 0,
    psh_count          UInt16        DEFAULT 0,
    ack_only_count     UInt16        DEFAULT 0,
    conn_state         UInt8         DEFAULT 0,
    rst_frac           Nullable(Float32),
    syn_to_data        UInt8         DEFAULT 0,
    psh_burst_max      UInt8         DEFAULT 0,
    retransmit_est     UInt16        DEFAULT 0,
    window_size_init   UInt16        DEFAULT 0,

    -- F6. Payload content
    entropy_first      Nullable(Float32),
    entropy_fwd_mean   Nullable(Float32),
    entropy_rev_mean   Nullable(Float32),
    printable_frac     Nullable(Float32),
    null_frac          Nullable(Float32),
    byte_std           Nullable(Float32),
    high_entropy_frac  Nullable(Float32),
    payload_len_first  UInt16        DEFAULT 0,

    -- L2 context
    src_mac            String        DEFAULT '',
    dst_mac            String        DEFAULT '',
    vlan_id            UInt16        DEFAULT 0,
    capture_source     UInt8         DEFAULT 1,
    emitted_at         String,

    -- Ingest metadata
    ingested_at        DateTime      DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(parseDateTimeBestEffort(first_ts))
ORDER BY (dst_port, src_ip, first_ts)
TTL parseDateTimeBestEffort(first_ts) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- CNN token packets
CREATE TABLE IF NOT EXISTS dfi.wh_packets
(
    flow_id         String,
    seq_idx         UInt16,
    ts              String,
    direction       Int8,
    payload_len     UInt16,
    pkt_len         UInt16,
    tcp_flags       UInt8,
    tcp_window      UInt16        DEFAULT 0,
    size_dir_token  Int8,
    flag_token      UInt8,
    iat_log_ms_bin  UInt8,
    iat_rtt_bin     UInt8,
    entropy_bin     UInt8         DEFAULT 0,
    iat_ms          Nullable(Float32),
    payload_entropy Nullable(Float32),

    ingested_at     DateTime      DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(parseDateTimeBestEffort(ts))
ORDER BY (flow_id, seq_idx)
TTL parseDateTimeBestEffort(ts) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- TLS/SSH/HTTP fingerprints
CREATE TABLE IF NOT EXISTS dfi.wh_fingerprints
(
    flow_id          String,
    ja3_hash         Nullable(String),
    tls_version      UInt8         DEFAULT 0,
    tls_cipher_count UInt8         DEFAULT 0,
    tls_ext_count    UInt8         DEFAULT 0,
    tls_has_sni      UInt8         DEFAULT 0,
    hassh_hash       Nullable(String),
    ssh_kex_count    UInt8         DEFAULT 0,
    http_method      UInt8         DEFAULT 0,
    http_uri_len     UInt16        DEFAULT 0,
    http_header_count UInt8        DEFAULT 0,
    http_ua_hash     Nullable(String),
    http_has_body    UInt8         DEFAULT 0,
    http_status      UInt16        DEFAULT 0,
    dns_qtype        UInt8         DEFAULT 0,
    dns_qname_len    UInt16        DEFAULT 0,

    ingested_at      DateTime      DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY (flow_id)
SETTINGS index_granularity = 8192;

-- Windows events from evidence collector
CREATE TABLE IF NOT EXISTS dfi.wh_events
(
    seq              UInt64,
    ts               String,
    vm_id            String,
    source_ip        Nullable(String),
    source_port      UInt16        DEFAULT 0,
    service          String        DEFAULT 'system',
    event_type       String,
    evidence_bits    UInt16        DEFAULT 0,
    raw_event_id     Nullable(UInt32),
    raw_channel      Nullable(String),
    detail_json      Nullable(String),

    ingested_at      DateTime      DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(parseDateTimeBestEffort(ts))
ORDER BY (vm_id, ts)
TTL parseDateTimeBestEffort(ts) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- Host observations from eye sensors
CREATE TABLE IF NOT EXISTS dfi.wh_observations
(
    obs_id           UInt64,
    ts               String,
    vm_id            String,
    obs_type         String,
    session_id       Nullable(String),
    source_ip        Nullable(String),
    process_pid      Nullable(UInt32),
    evidence_bits    UInt16        DEFAULT 0,
    priority         String        DEFAULT 'normal',
    detail_json      Nullable(String),

    ingested_at      DateTime      DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(parseDateTimeBestEffort(ts))
ORDER BY (vm_id, ts)
TTL parseDateTimeBestEffort(ts) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- Source IP statistics
CREATE TABLE IF NOT EXISTS dfi.wh_source_stats
(
    src_ip           String,
    flow_count       UInt32        DEFAULT 0,
    unique_ports     String        DEFAULT '[]',
    unique_protos    String        DEFAULT '[]',
    unique_dsts      String        DEFAULT '[]',
    first_seen       Nullable(String),
    last_seen        Nullable(String),
    sum_pps          Float32       DEFAULT 0,
    updated_at       String,

    ingested_at      DateTime      DEFAULT now()
)
ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (src_ip)
SETTINGS index_granularity = 8192;
