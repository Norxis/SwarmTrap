-- IP Reputation Table — Central shared state for capture decisions
-- The proposal's "core" data structure. Prevents training data contamination.
--
-- Populated by: ip_reputation_builder.py (cron 5min)
-- Read by: session_rules.py, watchlist promotion, SOC dashboard, future BF2 ARM
--
-- States: UNKNOWN(0), DIRTY(1), EVIDENCE(2), RESEARCH_BENIGN(3), CLEAN(4)
-- Label sources: NONE(0), EVIDENCE(1), PROPAGATED(2), MODEL(3), HEURISTIC(4)

CREATE TABLE IF NOT EXISTS dfi.ip_reputation
(
    -- Core identity
    src_ip              IPv4,
    state               UInt8        DEFAULT 0,    -- 0=UNKNOWN,1=DIRTY,2=EVIDENCE,3=RESEARCH_BENIGN,4=CLEAN
    first_seen          DateTime64(3) DEFAULT now64(),
    last_seen           DateTime64(3) DEFAULT now64(),
    updated_at          DateTime64(3) DEFAULT now64(),

    -- Cross-service evidence (contamination firewall)
    has_any_evidence    UInt8        DEFAULT 0,     -- ANY service has host-side proof
    evidence_services   UInt16       DEFAULT 0,     -- bitfield: which services have evidence
    evidence_mask_union UInt16       DEFAULT 0,     -- OR of all evidence_masks across services

    -- Aggregate model state (best across all services)
    best_xgb_class      UInt8       DEFAULT 0,
    best_xgb_confidence Float32     DEFAULT 0,
    best_cnn_class      UInt8       DEFAULT 0,
    best_cnn_confidence Float32     DEFAULT 0,

    -- Per-service state (JSON for flexibility — up to 8 services)
    -- Each entry: {service_id, xgb_class, xgb_conf, cnn_class, cnn_conf,
    --              evidence_confirmed, evidence_mask, label_source}
    service_states      String      DEFAULT '[]',

    -- Capture scoring (4-factor, 0-100)
    capture_score       UInt8       DEFAULT 0,
    score_reputation    UInt8       DEFAULT 0,     -- Factor 1: 0-40
    score_service       UInt8       DEFAULT 0,     -- Factor 2: 0-25
    score_direction     UInt8       DEFAULT 0,     -- Factor 3: 0-20
    score_novelty       UInt8       DEFAULT 0,     -- Factor 4: 0-15

    -- Label provenance
    label_source        UInt8       DEFAULT 0,     -- 0=NONE,1=EVIDENCE,2=PROPAGATED,3=MODEL,4=HEURISTIC
    label_confidence    Float32     DEFAULT 0,

    -- Behavioral context
    actor_id            UInt32      DEFAULT 0,     -- fingerprint cluster
    conversation_archetype UInt8    DEFAULT 0,     -- 0=unknown,1=commodity_bot,2=coordinated,3=human_operator,4=research_benign

    -- Flow statistics (from source_stats)
    total_flows         UInt64      DEFAULT 0,
    total_bytes         UInt64      DEFAULT 0,
    unique_ports        UInt16      DEFAULT 0,
    unique_dsts         UInt16      DEFAULT 0,

    -- Watchlist projection
    capture_depth       UInt8       DEFAULT 1,     -- 0=D0_DROP,1=D1_META,2=D2_TOKEN,3=D3_FULL
    priority            UInt8       DEFAULT 3,     -- 1=highest (evidence), 3=lowest
    watchlist_source    LowCardinality(String) DEFAULT '',
    expires_at          DateTime64(3) DEFAULT now64() + INTERVAL 30 DAY,

    -- Contamination control
    is_clean_allowlist  UInt8       DEFAULT 0,
    is_research_benign  UInt8       DEFAULT 0,
    per_actor_flows     UInt32      DEFAULT 0,     -- flows from this actor (budget tracking)
    per_actor_budget    UInt32      DEFAULT 50000  -- max flows per actor
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY src_ip
TTL expires_at + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- Materialized view: auto-populate from evidence_events
-- (Triggered on each new evidence event, merges into ip_reputation)
CREATE MATERIALIZED VIEW IF NOT EXISTS dfi.mv_ip_reputation_evidence
TO dfi.ip_reputation
AS SELECT
    src_ip,
    2 AS state,                                    -- EVIDENCE
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    now64() AS updated_at,
    1 AS has_any_evidence,
    bitOr(
        CASE service
            WHEN 'ssh' THEN 1
            WHEN 'http' THEN 2
            WHEN 'rdp' THEN 4
            WHEN 'mysql' THEN 8
            WHEN 'smb' THEN 16
            WHEN 'redis' THEN 32
            WHEN 'ftp' THEN 64
            WHEN 'telnet' THEN 128
            ELSE 0
        END
    ) AS evidence_services,
    bitOr(evidence_mask) AS evidence_mask_union,
    1 AS label_source,                             -- EVIDENCE
    0.95 AS label_confidence,
    2 AS capture_depth,                            -- D2_TOKEN
    1 AS priority,                                 -- highest
    'evidence_ingest' AS watchlist_source,
    now64() + INTERVAL 30 DAY AS expires_at
FROM dfi.evidence_events
WHERE src_ip NOT IN (
    -- Clean allowlist (RFC1918 + known infrastructure)
    '127.0.0.1', '0.0.0.0'
)
AND event_type IN ('auth_failure', 'auth_success', 'suspicious_command',
                   'process_create', 'service_install', 'file_download',
                   'privilege_escalation', 'lateral_movement')
GROUP BY src_ip, service;

-- Index for dashboard queries
ALTER TABLE dfi.ip_reputation ADD INDEX idx_state (state) TYPE minmax GRANULARITY 4;
ALTER TABLE dfi.ip_reputation ADD INDEX idx_capture_score (capture_score) TYPE minmax GRANULARITY 4;
ALTER TABLE dfi.ip_reputation ADD INDEX idx_has_evidence (has_any_evidence) TYPE minmax GRANULARITY 4;
