# Sync

The sync module replicates ClickHouse data and watchlist state between hosts. It enables a multi-host architecture where capture, labeling, and analysis can run on different machines while sharing a unified view of flows, evidence, and watchlist entries.

## How It Works

Data flows between hosts using two mechanisms:
- **ClickHouse tables:** Replicated via watermark-based incremental queries (pull new rows since last sync).
- **Watchlist (SQLite):** Synced via SSH/SFTP with JSON serialization and remote Python execution.

All sync scripts use a persistent JSON watermark file to track the last-synced timestamp for each table, ensuring exactly-once delivery under normal operation.

## Key Files

### `config.py`

Shared configuration for all sync scripts. All values are configurable via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `PV1_HOST` | `172.16.3.2` | Primary host (PV1) IP |
| `PV1_CH_PORT` | `9000` | PV1 ClickHouse native port |
| `AIO_HOST` | `192.168.0.113` | Secondary host (AIO) IP |
| `AIO_SSH_PORT` | `2222` | AIO SSH port |
| `AIO_CH_PORT` | `9000` | AIO ClickHouse native port |
| `AIO_USER` | `colo8gent` | AIO SSH user |
| `AIO_PASS` | *(env var)* | AIO SSH password |
| `WATCHLIST_DB_PATH` | `/opt/dfi-hunter/watchlist.db` | Remote watchlist path |
| `PULL_INTERVAL_SEC` | `300` | Pull interval (seconds) |
| `PUSH_INTERVAL_SEC` | `600` | Push interval (seconds) |
| `WATERMARK_FILE` | `/var/lib/dfi2/sync_watermark.json` | Sync state file |

### `pull_aio.py`

Pulls data from the remote host (AIO) into the local ClickHouse using ClickHouse's `remote()` table function. Intended to run on PV1 via cron (every 5 minutes).

**Tables synced:**
| Table | Timestamp Column |
|-------|-----------------|
| `flows` | `first_ts` |
| `packets` | `ts` |
| `fingerprints` | `first_ts` |
| `fanout_hops` | `first_ts` |
| `evidence_events` | `ts` |
| `model_predictions` | `scored_at` |

For each table, it counts new rows since the watermark, finds the max timestamp, runs `INSERT INTO ... SELECT * FROM remote(...)`, and advances the watermark.

### `push_to_pv1.py`

Pushes data from the local ClickHouse (AIO) to the remote ClickHouse (PV1). Intended to run on AIO via cron (every 5 minutes).

**Databases and tables synced:**
- **`dfi`:** flows, packets, fingerprints, fanout_hops, evidence_events, labels, model_predictions
- **`dfi_dirty`:** flows (attack traffic for ML training)
- **`dfi_clean`:** flows (clean baseline traffic for ML training)
- **`dfi_recon`:** recon_flows, flow_features (reconnaissance scoring data)

Reads rows from local ClickHouse ordered by timestamp, extracts column names from `system.columns`, and inserts into the remote. Batch size is 1,000,000 rows per table per run.

### `push_watchlist.py`

Pushes classifier results (group assignments + capture depths) from PV1 to AIO via SSH/SFTP.

1. Queries `dfi.group_assignments` and `dfi.depth_changes` from local ClickHouse for the last 24 hours.
2. Builds a watchlist payload combining group metadata and capture depths.
3. Writes the payload as JSON, SFTPs it to the remote host, and runs a Python one-liner remotely (via `sudo`) to upsert into the remote SQLite watchlist.

## Pipeline Position

```
AIO (capture host)                    PV1 (analysis host)
  dfi.flows --------push_to_pv1------->  dfi.flows
  dfi.evidence      push_to_pv1          dfi.evidence
  dfi_dirty.flows   push_to_pv1          dfi_dirty.flows
  dfi_clean.flows   push_to_pv1          dfi_clean.flows
                                          |
                  <---pull_aio-----------  dfi.flows (bidirectional)
                                          |
  watchlist.db  <---push_watchlist------  classifier results
```

## Watermark Files

Each script maintains its own watermark JSON file:

- `pull_aio.py`: `/var/lib/dfi2/sync_watermark.json` (from config)
- `push_to_pv1.py`: `/var/lib/dfi2/push_watermark.json`

The watermark file stores per-table timestamps and a `last_run_utc` field. Atomic writes via temp file + `os.replace()` prevent corruption.

## Dependencies

- `clickhouse-driver` -- ClickHouse native protocol client
- `paramiko` -- SSH/SFTP for watchlist push
