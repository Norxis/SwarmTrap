CREATE TABLE IF NOT EXISTS dfi.flows
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
    capture_depth   UInt8        DEFAULT 1,

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

    -- CNN packet sequences (up to 128 tokens per flow, empty [] for D1)
    pkt_size_dir     Array(Int8)   DEFAULT [],
    pkt_flag         Array(Int8)   DEFAULT [],
    pkt_iat_log_ms   Array(Int8)   DEFAULT [],
    pkt_iat_rtt      Array(Int8)   DEFAULT [],
    pkt_entropy      Array(Int8)   DEFAULT [],

    -- Inline labels (255 = unlabeled, populated by labeler or backfill cron)
    label           UInt8        DEFAULT 255,
    label_confidence Float32     DEFAULT 0,

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

CREATE TABLE IF NOT EXISTS dfi.packets
(
    -- Flow reference + denormalized identity
    flow_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    flow_first_ts   DateTime64(3),

    -- Packet identity
    seq_idx         UInt8,
    ts              DateTime64(3),
    direction       Int8,
    payload_len     UInt16,
    pkt_len         UInt16,
    tcp_flags       UInt8,
    tcp_window      UInt16,

    -- Pre-computed CNN tokens
    size_dir_token  Int8,
    flag_token      UInt8,
    iat_log_ms_bin  UInt8,
    iat_rtt_bin     UInt8,
    entropy_bin     UInt8,

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

CREATE TABLE IF NOT EXISTS dfi.fingerprints
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

CREATE TABLE IF NOT EXISTS dfi.labels
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
