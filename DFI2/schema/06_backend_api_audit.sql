-- Backend API audit enhancements
-- Adds explicit request correlation and optional campaign membership source.

ALTER TABLE dfi.analyst_actions
    ADD COLUMN IF NOT EXISTS request_id String DEFAULT '';

ALTER TABLE dfi.depth_changes
    ADD COLUMN IF NOT EXISTS request_id String DEFAULT '';

ALTER TABLE dfi.watchlist_syncs
    ADD COLUMN IF NOT EXISTS request_id String DEFAULT '';

-- Optional source for campaign-based bulk actions.
CREATE TABLE IF NOT EXISTS dfi.campaign_members
(
    campaign_id  String,
    attacker_ip  IPv4,
    confidence   Float32 DEFAULT 0,
    source       LowCardinality(String) DEFAULT 'classifier',
    updated_at   DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMMDD(updated_at)
ORDER BY (campaign_id, attacker_ip)
TTL updated_at + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
