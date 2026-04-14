CREATE TABLE IF NOT EXISTS dfi.ip_profile
(
    src_ip             IPv4,
    services           Array(UInt8)  DEFAULT [],
    service_classes    Array(UInt8)  DEFAULT [],
    evidence_count     UInt32 DEFAULT 0,
    evidence_services  Array(UInt8)  DEFAULT [],
    evidence_types     UInt16 DEFAULT 0,
    unique_dsts        UInt16 DEFAULT 0,
    unique_ports       UInt16 DEFAULT 0,
    total_flows        UInt64 DEFAULT 0,
    first_seen         DateTime64(3) DEFAULT now64(),
    last_seen          DateTime64(3) DEFAULT now64(),
    best_xgb_class     UInt8  DEFAULT 255,
    xgb_clean_ratio    Float32 DEFAULT 0,
    verdict            LowCardinality(String) DEFAULT 'NONE',
    verdict_group      LowCardinality(String) DEFAULT '',
    verdict_expires    DateTime64(3) DEFAULT now64(),
    updated_at         DateTime64(3) DEFAULT now64(),
    INDEX idx_verdict verdict TYPE set(3) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY src_ip
SETTINGS index_granularity = 8192;
