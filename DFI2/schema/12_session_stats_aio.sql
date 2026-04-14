-- Session stats for dfi_dirty and dfi_clean on AIO
-- Same structure as 11_session_stats.sql (PV1 dfi.session_stats)

-- ===================== dfi_dirty =====================

CREATE TABLE IF NOT EXISTS dfi_dirty.session_stats
(
    src_ip          IPv4,
    dst_ip          IPv4,
    dst_port        UInt16,
    flow_count      AggregateFunction(count, UInt64),
    sum_bytes_fwd   AggregateFunction(sum, UInt32),
    sum_bytes_rev   AggregateFunction(sum, UInt32),
    sum_pkts_fwd    AggregateFunction(sum, UInt32),
    sum_pkts_rev    AggregateFunction(sum, UInt32),
    first_seen      AggregateFunction(min, DateTime64(3)),
    last_seen       AggregateFunction(max, DateTime64(3)),
    max_duration    AggregateFunction(max, UInt32),
    sum_duration    AggregateFunction(sum, UInt32),
    max_bytes_rev   AggregateFunction(max, UInt32),
    sum_syn         AggregateFunction(sum, UInt8),
    sum_rst         AggregateFunction(sum, UInt8),
    sum_fin         AggregateFunction(sum, UInt8),
    sum_psh         AggregateFunction(sum, UInt16),
    sum_conn_state_0 AggregateFunction(sumIf, UInt8, UInt8),
    sum_conn_state_4 AggregateFunction(sumIf, UInt8, UInt8),
    sum_bidir       AggregateFunction(sumIf, UInt8, UInt8)
)
ENGINE = AggregatingMergeTree()
ORDER BY (src_ip, dst_ip, dst_port);

CREATE MATERIALIZED VIEW IF NOT EXISTS dfi_dirty.mv_session_stats
TO dfi_dirty.session_stats AS
SELECT
    src_ip, dst_ip, dst_port,
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
FROM dfi_dirty.flows
GROUP BY src_ip, dst_ip, dst_port;


-- ===================== dfi_clean =====================

CREATE TABLE IF NOT EXISTS dfi_clean.session_stats
(
    src_ip          IPv4,
    dst_ip          IPv4,
    dst_port        UInt16,
    flow_count      AggregateFunction(count, UInt64),
    sum_bytes_fwd   AggregateFunction(sum, UInt32),
    sum_bytes_rev   AggregateFunction(sum, UInt32),
    sum_pkts_fwd    AggregateFunction(sum, UInt32),
    sum_pkts_rev    AggregateFunction(sum, UInt32),
    first_seen      AggregateFunction(min, DateTime64(3)),
    last_seen       AggregateFunction(max, DateTime64(3)),
    max_duration    AggregateFunction(max, UInt32),
    sum_duration    AggregateFunction(sum, UInt32),
    max_bytes_rev   AggregateFunction(max, UInt32),
    sum_syn         AggregateFunction(sum, UInt8),
    sum_rst         AggregateFunction(sum, UInt8),
    sum_fin         AggregateFunction(sum, UInt8),
    sum_psh         AggregateFunction(sum, UInt16),
    sum_conn_state_0 AggregateFunction(sumIf, UInt8, UInt8),
    sum_conn_state_4 AggregateFunction(sumIf, UInt8, UInt8),
    sum_bidir       AggregateFunction(sumIf, UInt8, UInt8)
)
ENGINE = AggregatingMergeTree()
ORDER BY (src_ip, dst_ip, dst_port);

CREATE MATERIALIZED VIEW IF NOT EXISTS dfi_clean.mv_session_stats
TO dfi_clean.session_stats AS
SELECT
    src_ip, dst_ip, dst_port,
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
FROM dfi_clean.flows
GROUP BY src_ip, dst_ip, dst_port;


-- ===================== Backfill =====================

-- Run once after creating tables:

-- INSERT INTO dfi_dirty.session_stats
-- SELECT src_ip, dst_ip, dst_port,
--     countState(), sumState(bytes_fwd), sumState(bytes_rev),
--     sumState(pkts_fwd), sumState(pkts_rev),
--     minState(first_ts), maxState(first_ts),
--     maxState(duration_ms), sumState(duration_ms), maxState(bytes_rev),
--     sumState(syn_count), sumState(rst_count), sumState(fin_count), sumState(psh_count),
--     sumIfState(toUInt8(1), conn_state = 0),
--     sumIfState(toUInt8(1), conn_state = 4),
--     sumIfState(toUInt8(1), pkts_rev > 0)
-- FROM dfi_dirty.flows GROUP BY src_ip, dst_ip, dst_port;

-- INSERT INTO dfi_clean.session_stats
-- SELECT src_ip, dst_ip, dst_port,
--     countState(), sumState(bytes_fwd), sumState(bytes_rev),
--     sumState(pkts_fwd), sumState(pkts_rev),
--     minState(first_ts), maxState(first_ts),
--     maxState(duration_ms), sumState(duration_ms), maxState(bytes_rev),
--     sumState(syn_count), sumState(rst_count), sumState(fin_count), sumState(psh_count),
--     sumIfState(toUInt8(1), conn_state = 0),
--     sumIfState(toUInt8(1), conn_state = 4),
--     sumIfState(toUInt8(1), pkts_rev > 0)
-- FROM dfi_clean.flows GROUP BY src_ip, dst_ip, dst_port;
