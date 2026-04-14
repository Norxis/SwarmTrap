PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS watchlist (
    src_ip          TEXT PRIMARY KEY,
    capture_depth   INTEGER NOT NULL DEFAULT 1,
    priority        INTEGER NOT NULL DEFAULT 3,
    group_id        TEXT,
    sub_group_id    TEXT,
    top_port        INTEGER,
    reason          TEXT,
    source          TEXT NOT NULL DEFAULT 'classifier',
    expires_at      REAL,
    updated_at      REAL DEFAULT (unixepoch('now'))
);

CREATE INDEX IF NOT EXISTS idx_wl_depth ON watchlist(capture_depth);
CREATE INDEX IF NOT EXISTS idx_wl_expires ON watchlist(expires_at) WHERE expires_at IS NOT NULL;
