-- dfi_recon: Threat intelligence — slim operational store.
-- Rows auto-expire after 7 days (TTL on scored_at).
-- High-confidence recon AND attack flows land here (prob >= threshold).
-- detection_type: 'recon' (from RECON v2) or 'attack' (from XGB v6).

CREATE DATABASE IF NOT EXISTS dfi_recon;

CREATE TABLE IF NOT EXISTS dfi_recon.recon_flows
(
    flow_id        String,
    ts             DateTime64(3),
    src_ip         IPv4,
    dst_ip         IPv4,
    dst_port       UInt16,
    protocol       UInt8,
    recon_prob     Float32,
    model_version  String,
    detection_type LowCardinality(String) DEFAULT 'recon',
    scored_at      DateTime64(3) DEFAULT now64(3),

    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(scored_at)
ORDER BY (src_ip, scored_at)
TTL scored_at + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS dfi_recon.recon_flows_buffer AS dfi_recon.recon_flows
ENGINE = Buffer(dfi_recon, recon_flows,
    8, 5, 30, 1000, 50000, 5000000, 50000000);
