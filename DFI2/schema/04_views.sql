CREATE TABLE IF NOT EXISTS dfi.source_stats
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

CREATE MATERIALIZED VIEW IF NOT EXISTS dfi.mv_source_stats
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

CREATE TABLE IF NOT EXISTS dfi.fingerprint_freq
(
    field       String,
    hash_value  String,
    freq        AggregateFunction(count, UInt64)
)
ENGINE = AggregatingMergeTree()
ORDER BY (field, hash_value);

CREATE MATERIALIZED VIEW IF NOT EXISTS dfi.mv_ja3_freq
TO dfi.fingerprint_freq AS
SELECT 'ja3' AS field, ja3_hash AS hash_value, countState() AS freq
FROM dfi.fingerprints WHERE ja3_hash IS NOT NULL
GROUP BY ja3_hash;

CREATE MATERIALIZED VIEW IF NOT EXISTS dfi.mv_hassh_freq
TO dfi.fingerprint_freq AS
SELECT 'hassh' AS field, hassh_hash AS hash_value, countState() AS freq
FROM dfi.fingerprints WHERE hassh_hash IS NOT NULL
GROUP BY hassh_hash;

CREATE MATERIALIZED VIEW IF NOT EXISTS dfi.mv_ua_freq
TO dfi.fingerprint_freq AS
SELECT 'ua' AS field, http_ua_hash AS hash_value, countState() AS freq
FROM dfi.fingerprints WHERE http_ua_hash IS NOT NULL
GROUP BY http_ua_hash;

CREATE TABLE IF NOT EXISTS dfi.fanout_stats
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

CREATE MATERIALIZED VIEW IF NOT EXISTS dfi.mv_fanout_stats
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

CREATE VIEW IF NOT EXISTS dfi.v_xgb AS
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
WHERE f.actor_id != 'norm'
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

CREATE VIEW IF NOT EXISTS dfi.v_cnn_sequences AS
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
