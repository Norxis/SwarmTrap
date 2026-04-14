-- dfi_norm: Separated high-quality norm traffic database
-- Only flows with XGB confidence > 0.8 land here.
-- Speed-optimized: no SET indexes, MergeTree labels (immutable, no FINAL).

CREATE DATABASE IF NOT EXISTS dfi_norm;

-- ============================================================
-- TABLES
-- ============================================================

CREATE TABLE IF NOT EXISTS dfi_norm.flows
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

    capture_depth   UInt8        DEFAULT 1,

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

    -- CNN packet sequences (up to 128 tokens per flow, empty [] for D1)
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

CREATE TABLE IF NOT EXISTS dfi_norm.labels
(
    flow_id            String,
    src_ip             IPv4,
    dst_ip             IPv4,
    flow_first_ts      DateTime64(3),

    label              UInt8,
    label_confidence   Float32,
    evidence_mask      UInt8,
    evidence_detail    String,

    labeled_at         DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(flow_first_ts)
ORDER BY (flow_first_ts, flow_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi_norm.packets
(
    flow_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    flow_first_ts   DateTime64(3),

    seq_idx         UInt8,
    ts              DateTime64(3),
    direction       Int8,
    payload_len     UInt16,
    pkt_len         UInt16,
    tcp_flags       UInt8,
    tcp_window      UInt16,

    size_dir_token  Int8,
    flag_token      UInt8,
    iat_log_ms_bin  UInt8,
    iat_rtt_bin     UInt8,
    entropy_bin     UInt8,

    iat_ms          Nullable(Float32),
    payload_entropy Nullable(Float32)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (flow_id, seq_idx)
TTL ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi_norm.model_predictions
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

    scored_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(scored_at)
ORDER BY (flow_id, model_name, scored_at)
TTL scored_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- BUFFERS
-- ============================================================

CREATE TABLE IF NOT EXISTS dfi_norm.flows_buffer AS dfi_norm.flows
ENGINE = Buffer(dfi_norm, flows,
    16, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE IF NOT EXISTS dfi_norm.packets_buffer AS dfi_norm.packets
ENGINE = Buffer(dfi_norm, packets,
    16, 2, 10, 100000, 1000000, 50000000, 500000000);

CREATE TABLE IF NOT EXISTS dfi_norm.model_predictions_buffer AS dfi_norm.model_predictions
ENGINE = Buffer(dfi_norm, model_predictions,
    8, 5, 30, 10000, 100000, 10000000, 100000000);

-- ============================================================
-- VIEWS
-- ============================================================

-- v_xgb_norm: 2-table INNER JOIN (flows + labels).
-- 21 fingerprint/source_stats features hardcoded as 0 (norm has none).
-- No FINAL (MergeTree labels), no LEFT JOINs, no GROUP BY.
CREATE VIEW IF NOT EXISTS dfi_norm.v_xgb_norm AS
SELECT
    f.flow_id, f.session_key, f.actor_id,

    l.label, l.label_confidence, l.evidence_mask, l.evidence_detail,

    f.dst_port, f.ip_proto, f.app_proto,

    f.pkts_fwd, f.pkts_rev, f.bytes_fwd, f.bytes_rev,
    f.bytes_fwd / greatest(f.pkts_fwd, 1)                   AS bytes_per_pkt_fwd,
    if(f.pkts_rev > 0, f.bytes_rev / f.pkts_rev, NULL)      AS bytes_per_pkt_rev,
    f.pkts_fwd / greatest(f.pkts_rev, 1)                    AS pkt_ratio,
    f.bytes_fwd / greatest(f.bytes_rev, 1)                  AS byte_ratio,

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

    -- Fingerprint features: hardcoded 0 for norm (no fingerprint extraction)
    toUInt64(0) AS ja3_freq,
    toUInt8(0)  AS tls_version,
    toUInt8(0)  AS tls_cipher_count,
    toUInt8(0)  AS tls_ext_count,
    toUInt8(0)  AS tls_has_sni,
    toUInt64(0) AS hassh_freq,
    toUInt8(0)  AS ssh_kex_count,
    toUInt8(0)  AS http_method,
    toUInt16(0) AS http_uri_len,
    toUInt8(0)  AS http_header_count,
    toUInt64(0) AS http_ua_freq,
    toUInt8(0)  AS http_has_body,
    toUInt16(0) AS http_status,
    toUInt8(0)  AS dns_qtype,
    toUInt16(0) AS dns_qname_len,

    -- Source stats features: hardcoded 0 for norm
    toUInt64(0) AS src_flow_count,
    toUInt64(0) AS src_unique_ports,
    toUInt64(0) AS src_unique_protos,
    toUInt64(0) AS src_unique_dsts,
    toInt64(0)  AS src_span_min,
    toFloat32(0) AS src_avg_pps

FROM dfi_norm.flows f
INNER JOIN dfi_norm.labels l ON l.flow_id = f.flow_id;

-- v_cnn_sequences: reads from dfi_norm.packets
CREATE VIEW IF NOT EXISTS dfi_norm.v_cnn_sequences AS
SELECT
    flow_id,
    groupArray(128)(size_dir_token)  AS size_dir_arr,
    groupArray(128)(flag_token)      AS tcp_flags_arr,
    groupArray(128)(iat_log_ms_bin)  AS iat_log_ms_arr,
    groupArray(128)(iat_rtt_bin)     AS iat_rtt_bin_arr,
    groupArray(128)(entropy_bin)     AS entropy_bin_arr
FROM (
    SELECT * FROM dfi_norm.packets ORDER BY flow_id, seq_idx
)
GROUP BY flow_id;
