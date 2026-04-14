# Deploy

Deployment scripts for provisioning the DFI2 infrastructure. These scripts install ClickHouse, deploy application code, configure systemd services, and set up cron jobs on remote hosts via SSH.

## Key Files

### `deploy_dfi2.py`

Deploys the dashboard and ML pipeline to PV1 (the primary analysis host). Steps:

1. SSH connect to PV1.
2. Create remote directories (`/opt/dfi2/dashboard`, `/opt/dfi2/ml`).
3. Upload dashboard and ML files via SFTP.
4. Install Python dependencies (`streamlit`, `pandas`, `xgboost`, `torch`, `clickhouse-driver`).
5. Create and enable a systemd service (`dfi2-dashboard`) running Streamlit on port 8501.
6. Verify the port is listening.

### `deploy_ch_pv1.py`

Full ClickHouse deployment on PV1. Steps:

1. Install ClickHouse server/client and Python dependencies via apt.
2. Upload schema SQL files (`01_tables.sql` through `05_watchlist.sql`) from the local `schema/` directory.
3. Configure ClickHouse (60% RAM limit, 10GB merge pool, listen on all interfaces).
4. Create the `dfi` database and apply all schema files.
5. Initialize the SQLite watchlist.
6. Set up cron jobs for `pull_aio.py` (every 5 min) and `push_watchlist.py` (every 10 min).
7. Disable NIC hardware offloads (GRO, GSO, TSO, LRO) on the capture interface and install a systemd oneshot service to persist this across reboots.

### `deploy_ch_aio.py`

Full ClickHouse deployment on AIO (the secondary capture host). Similar to PV1 but with:

- Lower memory ratio (25% vs 60%) and smaller merge pool (5GB vs 10GB).
- TTL rewrite: all `INTERVAL N DAY` retention policies in the schema are replaced with `INTERVAL 2 DAY` to limit storage on the capture host.
- All commands run with `sudo` (non-root SSH user).
- Capture interface is `ens192` (vs `v172` on PV1).

### `deploy_dfi2_schema_sync.py`

Deploys the sync, labeler, and classifier code to PV1 along with updated schemas. A more targeted deployment than `deploy_dfi2.py`. Steps:

1. SSH connect to PV1.
2. Create directories for sync, labeler, and classifier.
3. Upload 10 files: schema SQL, sync scripts, labeler scripts, classifier scripts.
4. Apply ClickHouse buffer schema (`03_buffers.sql`).
5. Retire the old `dfi2-log-bridge` service (now merged into `evidence_ingest`).
6. Update the evidence-ingest systemd unit to include `BRIDGE_HOST`/`BRIDGE_PORT` env vars.
7. Restart labeler, classifier, and evidence-ingest services.
8. Ensure cron entries exist for `pull_aio` and `push_watchlist`.
9. Verify ClickHouse is running.

### `env2.example`

Example environment file for the Hunter2 capture engine. This is the config file sourced by the `dfi-hunter2.service` systemd unit.

| Variable | Example Value | Description |
|----------|---------------|-------------|
| `HUNTER_IFACE` | `ens192` | Network interface for packet capture |
| `CAPTURE_MODE` | `honeypot` | Capture mode (honeypot-focused) |
| `HONEYPOT_IPS` | `216.126.0.206` | Comma-separated honeypot IPs to monitor |
| `HONEYPOT_EXCLUDE` | `172.16.0.0/12,...` | CIDRs to exclude from capture |
| `CH_HOST` / `CH_PORT` | `localhost` / `9000` | ClickHouse connection |
| `WATCHLIST_DB` | `/opt/dfi-hunter/watchlist.db` | SQLite watchlist path |
| `FANOUT_WORKERS` | `4` | Number of fanout processing workers |
| `CPU_LIST` | `4,5,6,7` | CPU affinity for workers |
| `SESSION_TIMEOUT` | `120` | Seconds before a flow is considered ended |
| `FLUSH_INTERVAL` | `10` | Seconds between ClickHouse flushes |
| `XGB_MODEL_PATH` | `/opt/dfi2/ml/models/xgb_v6.json` | XGBoost model for early scoring (empty to disable) |
| `XGB_EARLY_PACKETS` | `50` | Packets before running early XGB prediction |
| `XGB_CONFIDENCE_THRESHOLD` | `0.9` | Confidence threshold for early scoring |
| `RECON_MODEL_PATH` | `/opt/dfi2/ml/models/xgb_recon_v2.json` | Recon-specific XGBoost model (empty to disable) |

### `dfi-hunter2.service`

Systemd unit file for the Hunter2 capture engine:

- Runs as root with `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.
- Reads configuration from `/etc/dfi-hunter/env2`.
- Starts after `network-online.target` and `clickhouse-server.service`.
- Restarts on failure with a 5-second delay.

## Pipeline Position

These deployment scripts bootstrap the entire DFI2 stack:

```
deploy_ch_pv1.py / deploy_ch_aio.py
    --> ClickHouse installed + schema applied
    --> NIC offloads disabled
    --> Cron jobs configured

deploy_dfi2.py
    --> Dashboard + ML code deployed

deploy_dfi2_schema_sync.py
    --> Sync, labeler, classifier code deployed
    --> Services restarted

env2.example + dfi-hunter2.service
    --> Capture engine configured and running
```

## Dependencies

- `paramiko` -- SSH/SFTP for remote deployment
- Remote hosts need: `apt-get`, `systemctl`, `clickhouse-client`, `sqlite3`, `pip3`, `ethtool`
