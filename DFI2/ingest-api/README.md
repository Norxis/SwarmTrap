# Ingest API

The ingest API is the centralized HTTP endpoint that receives evidence, flows, and watchlist entries from remote honeypot sensors. It replaces the older SSH/Paramiko-based push mechanism with a simple REST API.

## How It Works

Remote honeypot sensors (LXC containers, KVM VMs, VPS instances) run the sensor agent, which collects attacker IPs and evidence from local logs and pushes them to this API over HTTP. The API writes evidence to ClickHouse and watchlist entries to SQLite.

## Key Files

### `ingest_api.py`

A FastAPI application that exposes three ingest endpoints and a health check. Runs on port 81 by default.

**Endpoints:**

- `GET /health` -- Returns ClickHouse flow count and watchlist size. Used for monitoring.
- `POST /ingest/evidence` -- Accepts a batch of evidence events (auth failures, credential captures, suspicious commands, etc.) and inserts them into `dfi.evidence_events` in ClickHouse.
- `POST /ingest/flows` -- Accepts a batch of network flow records and inserts them into `dfi.flows`. Each flow includes packet-level arrays (sizes, flags, inter-arrival times, entropy).
- `POST /ingest/watchlist` -- Accepts a batch of attacker IPs and upserts them into the local SQLite `watchlist.db`. Uses conflict-resolution logic: capture depth takes the maximum, priority takes the minimum, and protected sources (`evidence_ingest`, `honeypot`, `research_benign`, active `cooldown`) are not overwritten.

**Authentication:** Optional API key via the `X-DFI-Key` header. Set `INGEST_API_KEY` env var to enable.

**Data models** are defined as Pydantic classes: `EvidenceEvent`, `EvidenceBatch`, `FlowRecord`, `FlowBatch`, `WatchlistEntry`, `WatchlistBatch`.

### `sensor_agent.py`

A long-running agent that runs on each honeypot sensor. It collects attacker information from multiple sources and pushes it to the ingest API.

**Data sources:**
- **trap.log:** Extracts attacker IPs from TCP/UDP connection lines using regex.
- **winlure.log:** Extracts attacker IPs from authentication and connection log lines.
- **evidence.db:** Reads structured evidence events from the Winlure SQLite database (the `events` table with columns: ts, src_ip, src_port, dst_port, service, event_type, attack_phase, weight, details, tool_signature, persona).

**Push targets:**
- `POST /ingest/watchlist` -- Attacker IPs extracted from logs, with deduplication (default: 1 hour window).
- `POST /ingest/evidence` -- Structured evidence events from the SQLite database, with watermark tracking.

**Deduplication:** Maintains a local SQLite database (`pushed_ips.db`) to avoid re-pushing the same IP within the dedup window.

**Configuration:** YAML config file at `/etc/dfi-sensor/agent.conf`, with env var overrides (`API_URL`, `API_KEY`, `SENSOR_ID`).

## Pipeline Position

```
Honeypot sensors (LXC/KVM/VPS)
        |
        |  trap.log, winlure.log, evidence.db
        v
  sensor_agent.py  ----HTTP POST---->  ingest_api.py
                                           |
                              +------------+------------+
                              |            |            |
                              v            v            v
                    dfi.evidence_events  dfi.flows  watchlist.db
```

## Configuration

### Ingest API (`ingest_api.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `CH_HOST` | `localhost` | ClickHouse host |
| `CH_PORT` | `9000` | ClickHouse native port |
| `WATCHLIST_DB` | `/opt/dfi-hunter/watchlist.db` | SQLite watchlist path |
| `INGEST_HOST` | `0.0.0.0` | Bind address |
| `INGEST_PORT` | `81` | Listen port |
| `INGEST_API_KEY` | *(empty)* | API key for authentication (disabled if empty) |

### Sensor Agent (`sensor_agent.py`)

| Variable / Config Key | Default | Description |
|------------------------|---------|-------------|
| `api_url` | `http://172.16.3.113:81` | Ingest API base URL |
| `api_key` | *(empty)* | API key |
| `sensor_id` | hostname | Identifier for this sensor |
| `push_interval` | `60` | Seconds between push cycles |
| `evidence_db` | `/opt/winlure/state/evidence.db` | Winlure evidence SQLite path |
| `trap_log` | `/opt/trap/trap.log` | Trap service log path |
| `winlure_log` | `/opt/winlure/winlure.log` | Winlure log path |
| `dedup_db` | `/opt/trap/pushed_ips.db` | Dedup state database |
| `dedup_hours` | `1` | Hours before re-pushing an IP |
| `ignore_prefixes` | `192.168., 172.16.3., 10., 169.254., 127.` | Internal IP prefixes to ignore |

## Dependencies

### Ingest API
- `fastapi` + `uvicorn` -- HTTP framework and ASGI server
- `clickhouse-driver` -- ClickHouse native protocol client
- `pydantic` -- Request/response validation

### Sensor Agent
- `requests` -- HTTP client
- `pyyaml` -- Configuration file parsing
