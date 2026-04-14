-- dfi_dirty: Dirty (watchlist/honeypot) traffic captured from SPAN at D2
-- Only flows involving watchlist or honeypot IPs are captured
-- Full D2 depth with embedded packet sequences for ML training

CREATE DATABASE IF NOT EXISTS dfi_dirty;

CREATE TABLE IF NOT EXISTS dfi_dirty.flows
(
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

    capture_depth   UInt8        DEFAULT 2,

    pkts_fwd        UInt32,
    pkts_rev        UInt32,
    bytes_fwd       UInt32,
    bytes_rev       UInt32,

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

    entropy_first      Nullable(Float32),
    entropy_fwd_mean   Nullable(Float32),
    entropy_rev_mean   Nullable(Float32),
    printable_frac     Nullable(Float32),
    null_frac          Nullable(Float32),
    byte_std           Nullable(Float32),
    high_entropy_frac  Nullable(Float32),
    payload_len_first  UInt16,

    pkt_size_dir     Array(Int8)   DEFAULT [],
    pkt_flag         Array(Int8)   DEFAULT [],
    pkt_iat_log_ms   Array(Int8)   DEFAULT [],
    pkt_iat_rtt      Array(Int8)   DEFAULT [],
    pkt_entropy      Array(Int8)   DEFAULT [],

    ingested_at     DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first_ts)
ORDER BY (first_ts, flow_id)
TTL first_ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi_dirty.flows_buffer AS dfi_dirty.flows
ENGINE = Buffer(dfi_dirty, flows,
    16, 5, 30, 10000, 100000, 10000000, 100000000);
