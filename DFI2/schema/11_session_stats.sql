-- Session-based aggregation for ML: group flows by (src_ip, dst_ip, dst_port)
-- Pattern: 04_views.sql (source_stats / mv_source_stats)

-- 1. Aggregate table: one row per (src_ip, dst_ip, dst_port) session
CREATE TABLE IF NOT EXISTS dfi.session_stats
(
    src_ip          IPv4,
    dst_ip          IPv4,
    dst_port        UInt16,

    -- Volume aggregates
    flow_count      AggregateFunction(count, UInt64),
    sum_bytes_fwd   AggregateFunction(sum, UInt32),
    sum_bytes_rev   AggregateFunction(sum, UInt32),
    sum_pkts_fwd    AggregateFunction(sum, UInt32),
    sum_pkts_rev    AggregateFunction(sum, UInt32),

    -- Temporal aggregates
    first_seen      AggregateFunction(min, DateTime64(3)),
    last_seen       AggregateFunction(max, DateTime64(3)),
    max_duration    AggregateFunction(max, UInt32),
    sum_duration    AggregateFunction(sum, UInt32),
    max_bytes_rev   AggregateFunction(max, UInt32),

    -- TCP flag aggregates
    sum_syn         AggregateFunction(sum, UInt8),
    sum_rst         AggregateFunction(sum, UInt8),
    sum_fin         AggregateFunction(sum, UInt8),
    sum_psh         AggregateFunction(sum, UInt16),

    -- Connection state aggregates (conn_state: 0=SYN_ONLY, 4=ESTABLISHED)
    sum_conn_state_0 AggregateFunction(sumIf, UInt8, UInt8),
    sum_conn_state_4 AggregateFunction(sumIf, UInt8, UInt8),

    -- Bidirectional: flows where pkts_rev > 0
    sum_bidir       AggregateFunction(sumIf, UInt8, UInt8)
)
ENGINE = AggregatingMergeTree()
ORDER BY (src_ip, dst_ip, dst_port);


-- 2. Materialized view: auto-populate from dfi.flows inserts
CREATE MATERIALIZED VIEW IF NOT EXISTS dfi.mv_session_stats
TO dfi.session_stats AS
SELECT
    src_ip,
    dst_ip,
    dst_port,
    countState()                AS flow_count,
    sumState(bytes_fwd)         AS sum_bytes_fwd,
    sumState(bytes_rev)         AS sum_bytes_rev,
    sumState(pkts_fwd)          AS sum_pkts_fwd,
    sumState(pkts_rev)          AS sum_pkts_rev,
    minState(first_ts)          AS first_seen,
    maxState(first_ts)          AS last_seen,
    maxState(duration_ms)       AS max_duration,
    sumState(duration_ms)       AS sum_duration,
    maxState(bytes_rev)         AS max_bytes_rev,
    sumState(syn_count)         AS sum_syn,
    sumState(rst_count)         AS sum_rst,
    sumState(fin_count)         AS sum_fin,
    sumState(psh_count)         AS sum_psh,
    sumIfState(toUInt8(1), conn_state = 0) AS sum_conn_state_0,
    sumIfState(toUInt8(1), conn_state = 4) AS sum_conn_state_4,
    sumIfState(toUInt8(1), pkts_rev > 0)   AS sum_bidir
FROM dfi.flows
GROUP BY src_ip, dst_ip, dst_port;


-- 3. Feature view: compute 20 session features from aggregates
--    (IAT features computed in Python — need sorted timestamps)
CREATE VIEW IF NOT EXISTS dfi.v_session_features AS
SELECT
    src_ip,
    dst_ip,
    dst_port,

    -- F1 Volume (6)
    countMerge(flow_count)                          AS sess_flow_count,
    sumMerge(sum_bytes_fwd)                         AS sess_bytes_fwd,
    sumMerge(sum_bytes_rev)                         AS sess_bytes_rev,
    sumMerge(sum_pkts_fwd)                          AS sess_pkts_fwd,
    sumMerge(sum_pkts_rev)                          AS sess_pkts_rev,
    if(sumMerge(sum_pkts_fwd) > 0,
       sumMerge(sum_pkts_rev) / sumMerge(sum_pkts_fwd),
       0)                                           AS sess_reply_ratio,

    -- F2 Temporal (2 of 5 — avg_iat, min_iat, max_iat computed in Python)
    dateDiff('second',
        minMerge(first_seen),
        maxMerge(last_seen))                        AS sess_duration,
    if(countMerge(flow_count) > 0,
       sumMerge(sum_duration) / countMerge(flow_count),
       0)                                           AS sess_avg_flow_dur,

    -- F3 Depth (5)
    maxMerge(max_duration)                          AS sess_max_flow_dur,
    maxMerge(max_bytes_rev)                         AS sess_max_bytes_rev,
    if(countMerge(flow_count) > 0,
       (sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)) / countMerge(flow_count),
       0)                                           AS sess_avg_bytes_per_flow,
    if((sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)) > 0,
       sumMerge(sum_bytes_rev) / (sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)),
       0)                                           AS sess_payload_ratio,
    if(countMerge(flow_count) > 0,
       sumIfMerge(sum_bidir) / countMerge(flow_count),
       0)                                           AS sess_bidirectional_ratio,

    -- F4 TCP Behavior (4)
    if(countMerge(flow_count) > 0,
       sumIfMerge(sum_conn_state_0) / countMerge(flow_count),
       0)                                           AS sess_syn_only_ratio,
    if(countMerge(flow_count) > 0,
       sumMerge(sum_rst) / countMerge(flow_count),
       0)                                           AS sess_rst_ratio,
    if(countMerge(flow_count) > 0,
       sumIfMerge(sum_conn_state_4) / countMerge(flow_count),
       0)                                           AS sess_completed_ratio,
    if(countMerge(flow_count) > 0,
       (sumMerge(sum_syn) + sumMerge(sum_fin) + sumMerge(sum_rst) + sumMerge(sum_psh))
           / countMerge(flow_count),
       0)                                           AS sess_avg_tcp_flags,

    -- Timestamps for Python IAT computation
    minMerge(first_seen)                            AS _first_seen,
    maxMerge(last_seen)                             AS _last_seen

FROM dfi.session_stats
GROUP BY src_ip, dst_ip, dst_port;


-- 4. Predictions table: store session-level model scores
CREATE TABLE IF NOT EXISTS dfi.session_predictions
(
    src_ip          IPv4,
    dst_ip          IPv4,
    dst_port        UInt16,
    model_name      String,
    model_version   String,
    label           UInt8,
    confidence      Float32,
    kill_chain_stage UInt8       DEFAULT 0,
    scored_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(scored_at)
ORDER BY (src_ip, dst_ip, dst_port, model_name)
TTL scored_at + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;


-- 5. Backfill existing flows into session_stats (run once)
-- INSERT INTO dfi.session_stats
-- SELECT
--     src_ip, dst_ip, dst_port,
--     countState()                AS flow_count,
--     sumState(bytes_fwd)         AS sum_bytes_fwd,
--     sumState(bytes_rev)         AS sum_bytes_rev,
--     sumState(pkts_fwd)          AS sum_pkts_fwd,
--     sumState(pkts_rev)          AS sum_pkts_rev,
--     minState(first_ts)          AS first_seen,
--     maxState(first_ts)          AS last_seen,
--     maxState(duration_ms)       AS max_duration,
--     sumState(duration_ms)       AS sum_duration,
--     maxState(bytes_rev)         AS max_bytes_rev,
--     sumState(syn_count)         AS sum_syn,
--     sumState(rst_count)         AS sum_rst,
--     sumState(fin_count)         AS sum_fin,
--     sumState(psh_count)         AS sum_psh,
--     sumIfState(toUInt8(1), conn_state = 0) AS sum_conn_state_0,
--     sumIfState(toUInt8(1), conn_state = 4) AS sum_conn_state_4,
--     sumIfState(toUInt8(1), pkts_rev > 0)   AS sum_bidir
-- FROM dfi.flows
-- GROUP BY src_ip, dst_ip, dst_port;
