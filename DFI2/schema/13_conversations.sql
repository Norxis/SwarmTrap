-- Conversation-level tables for DFI Conversation Dataset v1
-- Groups flows by src_ip with 30-min temporal gap = new conversation
-- Assembled by batch cron (conversation_assembler.py), NOT real-time MVs

-- 1. conversations — 42 static features + metadata (one row per conversation)
CREATE TABLE IF NOT EXISTS dfi.conversations
(
    -- C1: Identity (do not train)
    conversation_id     String,
    src_ip              IPv4,
    actor_id            String,
    first_ts            DateTime64(3),
    last_ts             DateTime64(3),

    -- Meta
    n_turns             UInt16,
    n_turns_used        UInt16,
    is_truncated        UInt8        DEFAULT 0,
    assembled_at        DateTime64(3) DEFAULT now64(3),

    -- C2: Scale (6)
    duration_total_min  Float32,
    unique_services     UInt16,
    unique_dst_ports    UInt16,
    unique_dst_ips      UInt16,
    concurrent_max      UInt16,

    -- C3: Rhythm (8)
    gap_mean_s          Float32,
    gap_std_s           Float32,
    gap_cv              Float32,
    gap_median_s        Float32,
    gap_acceleration    Float32,
    burst_count         UInt16,
    burst_mean_size     Float32,
    pacing_entropy      Float32,

    -- C4: Volume (6)
    bytes_total         UInt64,
    bytes_fwd_total     UInt64,
    bytes_rev_total     UInt64,
    volume_trend        Float32,
    max_single_flow_bytes UInt32,
    volume_gini         Float32,

    -- C5: Escalation (8)
    max_xgb_class       UInt8,
    max_cnn_class       UInt8,
    escalation_turn     UInt16,
    escalation_fraction Float32,
    class_diversity     UInt16,
    deescalation_count  UInt16,
    plateau_length      UInt16,
    has_auth_success    UInt8,

    -- C6: Service Targeting (6)
    dominant_service    UInt8,
    dominant_service_frac Float32,
    service_entropy     Float32,
    service_transition_count UInt16,
    service_breadth_first_half UInt16,
    service_breadth_second_half UInt16,

    -- C7: Model Consensus (4)
    agreement_rate      Float32,
    disagreement_max_delta UInt16,
    agreement_trend     Float32,
    cnn_available_frac  Float32,

    -- C8: Actor Context (4)
    actor_conversation_count UInt16,
    actor_unique_ips    UInt16,
    actor_mean_turns    Float32,
    actor_max_class     UInt8,

    -- Inline labels (4=UNKNOWN default, populated by assembler)
    -- 0=COMMODITY_BOT, 1=COORDINATED_CAMPAIGN, 2=HUMAN_OPERATOR, 3=RESEARCH_BENIGN, 4=UNKNOWN, 5=CLEAN_BASELINE
    label               UInt8        DEFAULT 4,
    label_confidence    Float32      DEFAULT 0,
    label_tier          UInt8        DEFAULT 0,
    max_flow_label      UInt8        DEFAULT 0,
    n_flows_attack      UInt16       DEFAULT 0,
    n_flows_recon       UInt16       DEFAULT 0,
    threat_score        Float32      DEFAULT 0,

    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(assembled_at)
PARTITION BY toYYYYMMDD(first_ts)
ORDER BY (conversation_id)
TTL first_ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- 2. conversation_turns — 12-channel pre-tokenized per-turn features
CREATE TABLE IF NOT EXISTS dfi.conversation_turns
(
    conversation_id     String,
    turn_index          UInt16,
    flow_id             String,
    src_ip              IPv4,
    dst_ip              IPv4,
    dst_port            UInt16,
    first_ts            DateTime64(3),

    -- 12 turn-level token channels (pre-computed vocab indices)
    ch_service_target   UInt8,    -- vocab 13 (0-12)
    ch_flow_outcome     UInt8,    -- vocab 11 (0-10)
    ch_xgb_prediction   UInt8,    -- vocab 6  (0-5)
    ch_xgb_confidence   UInt8,    -- vocab 6  (0-5)
    ch_cnn_prediction   UInt8,    -- vocab 6  (0-5)
    ch_cnn_confidence   UInt8,    -- vocab 6  (0-5)
    ch_model_agreement  UInt8,    -- vocab 6  (0-5)
    ch_turn_duration    UInt8,    -- vocab 8  (0-7)
    ch_inter_turn_gap   UInt8,    -- vocab 7  (0-6)
    ch_data_volume      UInt8,    -- vocab 7  (0-6)
    ch_data_direction   UInt8,    -- vocab 5  (0-4)
    ch_port_novelty     UInt8,    -- vocab 3  (0-2)

    -- Raw values for re-binning / analysis
    duration_ms         UInt32,
    bytes_fwd           UInt32,
    bytes_rev           UInt32,
    inter_turn_gap_ms   UInt32,

    -- Inline flow-level label (from dfi.flows.label)
    label               UInt8        DEFAULT 4,

    assembled_at        DateTime DEFAULT now(),

    INDEX idx_conversation conversation_id TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first_ts)
ORDER BY (conversation_id, turn_index)
TTL first_ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- 3. conversation_labels — 6-class behavioral archetype
--    0=COMMODITY_BOT, 1=COORDINATED_CAMPAIGN, 2=HUMAN_OPERATOR,
--    3=RESEARCH_BENIGN, 4=UNKNOWN, 5=CLEAN_BASELINE
CREATE TABLE IF NOT EXISTS dfi.conversation_labels
(
    conversation_id     String,
    src_ip              IPv4,

    label               UInt8,
    label_confidence    Float32,
    label_tier          UInt8,        -- 1=evidence, 2=reputation, 3=cluster, 4=heuristic
    label_source        LowCardinality(String),
    label_detail        String       DEFAULT '',

    -- Flow-level label distribution
    n_flows_labeled     UInt16,
    n_flows_attack      UInt16,
    n_flows_recon       UInt16,
    n_flows_norm        UInt16,
    max_flow_label      UInt8,
    mean_flow_confidence Float32,

    labeled_at          DateTime64(3) DEFAULT now64(3),

    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(labeled_at)
ORDER BY (conversation_id)
TTL labeled_at + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- 4. conversation_predictions — model scores at conversation level
CREATE TABLE IF NOT EXISTS dfi.conversation_predictions
(
    conversation_id     String,
    src_ip              IPv4,
    model_name          LowCardinality(String),
    model_version       String,
    label               UInt8,
    confidence          Float32,
    class_probs         Array(Float32),
    scored_at           DateTime64(3) DEFAULT now64(3),

    INDEX idx_src_ip src_ip TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(scored_at)
ORDER BY (conversation_id, model_name, scored_at)
TTL scored_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;


-- 5. Summary view for dashboard/debugging (NOT for export — use raw dumps)
CREATE VIEW IF NOT EXISTS dfi.v_conversation_summary AS
SELECT
    c.conversation_id,
    c.src_ip,
    c.first_ts,
    c.last_ts,
    c.duration_total_min,
    c.n_turns,
    c.unique_dst_ips,
    c.unique_dst_ports,
    c.max_xgb_class,
    cl.label,
    cl.label_confidence,
    cl.label_tier,
    cl.max_flow_label,
    cl.n_flows_attack
FROM dfi.conversations c
LEFT JOIN dfi.conversation_labels cl FINAL ON cl.conversation_id = c.conversation_id;
