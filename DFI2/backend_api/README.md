# DFI2 Backend API

FastAPI control-plane for the DFI2 deep-flow intelligence pipeline. Manages attacker watchlists, capture depth, analyst actions, ML model training/rescoring, RECON intelligence, and exposes a 12-page React SOC dashboard. All writes are idempotent. Reads pull from ClickHouse (flows, hops, groups, evidence, RECON, model predictions) and SQLite (watchlist state).

**Port:** `8010` &nbsp;|&nbsp; **Service:** `dfi2-backend-api.service` &nbsp;|&nbsp; **Deployed to:** PV1 (`192.168.0.100`)

---

## Quick Start

```bash
python3 -m venv /opt/dfi2/.venv-backend-api
/opt/dfi2/.venv-backend-api/bin/pip install -r backend_api/requirements.txt
PYTHONPATH=/opt/dfi2 /opt/dfi2/.venv-backend-api/bin/python -m backend_api.main
```

Open `http://192.168.0.100:8010/ui`

## Configuration

All settings are environment variables with sensible defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `CH_HOST` | `localhost` | ClickHouse host |
| `CH_PORT` | `9000` | ClickHouse native TCP port |
| `WATCHLIST_DB` | `/opt/dfi-hunter/watchlist.db` | SQLite watchlist path |
| `BACKEND_API_HOST` | `0.0.0.0` | Bind address |
| `BACKEND_API_PORT` | `8010` | Bind port |
| `BACKEND_API_KEY` | _(none)_ | Require `X-API-Key` header on writes |
| `BACKEND_UI_USER` | `admin` | Basic auth username for `/ui` |
| `BACKEND_UI_PASS` | _(none)_ | Basic auth password for `/ui` (disabled if unset) |
| `ACTIVE_WINDOW_SEC` | `900` | Seconds of recent flow activity that blocks demotion |
| `MAX_BULK_IPS` | `5000` | Max IPs per bulk action |
| `ENABLE_QUIET_DEMOTER` | `0` | Enable background quiet-IP demoter |
| `QUIET_DEMOTE_INTERVAL_SEC` | `300` | Demoter check interval |
| `QUIET_DEMOTE_AFTER_SEC` | `3600` | Demote after this many seconds of inactivity |
| `PVE_HOST` | `https://192.168.0.100:8006` | Proxmox API URL |
| `PVE_USER` | `root@pam` | Proxmox user |
| `PVE_PASS` | _(empty)_ | Proxmox password |

---

## Endpoints

### Health & UI

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Returns `{"ok": "true"}` |
| GET | `/ui` | React SPA SOC dashboard (optional basic auth) |
| GET | `/ui/legacy` | Original vanilla JS dashboard |

### Read Endpoints

| Method | Path | Query Params | Description |
|--------|------|--------------|-------------|
| GET | `/watchlist` | `limit` (1-5000, default 200) | Current watchlist entries from SQLite |
| GET | `/data/overview` | `window` (1-43200 min, default 15) | KPIs: flows/sec, active attackers, new 1h, depth dist, top groups, top-20 attacker table, XGB scoring stats |
| GET | `/data/attackers` | `hours` (1-168), `limit` (1-2000), `group_id` | Attacker list with group classification, depth, session counts, target/port cardinality |
| GET | `/data/attacker/{ip}` | `hours` (1-168, default 24) | IP dossier: lateral movement hops, group trajectory, depth history, fingerprints (JA3/HASSH/HTTP UA) |
| GET | `/data/campaigns` | `limit` (1-500, default 100) | Campaign list with IP counts and activity windows |
| GET | `/data/audit` | `limit` (1-1000, default 200) | Unified audit log (analyst actions + depth changes) |
| GET | `/data/flows` | `label`, `protocol`, `port`, `ip`, `hours`, `limit`, `offset` | Paginated flow list with filters |
| GET | `/data/flows/{flow_id}` | _(none)_ | Single flow detail + packets + fingerprints |
| GET | `/data/killchain/{ip}` | `hours` (1-720, default 168) | Label progression timeline for IP (RECON→KNOCK→BRUTE→EXPLOIT→COMPROMISE) |
| GET | `/data/realtime` | _(none)_ | Live metrics snapshot (PPS, flows/sec, XGB rate, active attackers, drops) |
| GET | `/data/realtime/history` | `hours` (default 1) | Historical realtime metric series |
| GET | `/data/ml/stats` | `model_name` (default "xgb_v6") | ML model stats + confusion matrix + feature importance |
| GET | `/data/ml/models` | _(none)_ | List available model files |
| GET | `/data/ml/models/{filename}/download` | `api_key` | Download model file |
| GET | `/data/ml/rescore-status` | `model_name`, `labels` | Background rescore job status |
| GET | `/data/ml/train-status` | _(none)_ | Background training job status (export + fold progress) |
| GET | `/vms` | _(none)_ | 10-VM grid: Proxmox status (CPU, RAM, uptime) + ClickHouse flow/attacker counts |
| GET | `/vms/{vmid}/events` | _(none)_ | Evidence events for a specific VM's public IP |
| GET | `/hunter-aio/status` | _(none)_ | Hunter-AIO SSH probe: services, capture mode, PPS, ring drops, watchlist count, CH flow/prediction stats |

### Write Endpoints

All writes require `Idempotency-Key` header. Reusing a key with a different payload returns HTTP 409.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/watchlist/upsert` | Add/update IP on watchlist (depth, priority, reason, expiry) |
| POST | `/watchlist/delete` | Remove IP from watchlist |
| POST | `/action/annotate` | Log analyst note + tags for an IP |
| POST | `/action/bulk` | Bulk upsert/delete by `ip_list` or `campaign_id` |
| POST | `/action/demote-quiet` | Trigger quiet-IP demotion (scheduler endpoint) |
| POST | `/action/ml/rescore-norm` | Legacy: rescore unscored label-5 (NORM) flows |
| POST | `/action/ml/rescore` | Rescore flows with configurable model/labels/skip-scored |
| POST | `/action/ml/train` | Train XGB model (type: `attack` or `recon`, configurable folds/hours/balance) |
| DELETE | `/action/ml/models/{filename}` | Delete a saved model file |
| POST | `/vms/{vmid}/reboot` | Reboot a Proxmox VM + log the action |

---

## Architecture

```
                    +------------------+
                    |  /ui React SPA   |  (dark-theme SOC dashboard, 12 pages)
                    +--------+---------+
                             |
                    +--------v---------+
                    |     FastAPI       |  :8010
                    |     app.py        |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
       +------v------+ +----v-----+ +-----v--------+
       | ClickHouse  | |  SQLite  | |  Hunter-AIO  |
       | dfi.*       | | watchlist| |  (SSH probe)  |
       | dfi_recon.* | |          | |  192.168.0.113|
       +-------------+ +----------+ +--------------+

ClickHouse databases/tables read:
  dfi.flows              Flow features (55 cols, src/dst/timing/entropy/TCP)
  dfi.fanout_hops        Lateral movement per attacker
  dfi.group_assignments  Behavioral group + confidence
  dfi.depth_changes      Capture depth audit trail
  dfi.analyst_actions    All API write actions (append-only)
  dfi.campaign_members   Campaign membership
  dfi.fingerprints       JA3, HASSH, HTTP UA per flow
  dfi.evidence_events    Host-log evidence correlated to flows
  dfi.watchlist_syncs    PV1<->AIO sync events
  dfi.model_predictions  XGB scoring results (label, confidence, model version)
  dfi_recon.recon_flows  RECON v2 inline scoring results (7-day TTL)

SQLite tables:
  watchlist                    IP -> depth/priority/reason/expiry
  control_plane_requests       Idempotency records (request_id + payload hash)

Background workers (in-process):
  rescorer.py    Background flow rescoring thread (label-5 NORM or custom)
  trainer.py     Background ML training thread (export → k-fold XGB → save model)
  scheduler.py   QuietDemoter thread (auto-demote inactive IPs)
```

## RECON Intelligence Pipeline

RECON v2 inline scoring runs on Hunter-AIO, detecting reconnaissance IPs and storing them in ClickHouse `dfi_recon.recon_flows` (7-day TTL). The pipeline feeds two consumers:

1. **SOC Dashboard** — Kill Chain page (`/data/killchain/{ip}`) shows RECON as the first stage in the attack progression timeline. ML training supports `model_type=recon` for dedicated RECON classifiers.

2. **MikroTik NAT Trap** — Hourly cron on Hunter-AIO runs `scripts/update_recon_addresslist.py`, which queries `dfi_recon.recon_flows` for distinct scanner IPs and syncs them to MikroTik address-list `recon` via SSH. MikroTik dst-nat rule #0 redirects all traffic from RECON IPs to the honeypot at `216.126.0.206`.

```
Hunter-AIO scorer.py         Hunter-AIO cron (hourly)         MikroTik
  │ score every flow            │ query CH recon_flows          │ NAT rule #0
  │ prob >= 0.9 →               │ sync IPs to address-list      │ src-address-list=recon
  ▼                             ▼                               ▼
dfi_recon.recon_flows ──────► update_recon_addresslist.py ──► /ip/firewall/address-list
  (7-day TTL)                   (SSH to 172.16.3.1:12315)      (dst-nat → 216.126.0.206)
```

## Key Behaviors

**Capture Depth Gating**
- D0: drop (no capture)
- D1: flow metadata + fingerprints only
- D2: flow + 128-token packet sequences
- D3: full capture + payload heads

**Active Attacker Protection** — demotion is blocked while the IP has flows in the last `ACTIVE_WINDOW_SEC` (default 15 min).

**Quiet Demoter** — background thread (opt-in via `ENABLE_QUIET_DEMOTER=1`) auto-demotes one level per cycle: D3 -> D2 -> D1. Never demotes below D1. Skips active IPs and recently-updated entries.

**Campaign Resolution** — `POST /action/bulk` with `campaign_id` resolves IPs from `dfi.campaign_members` first, falls back to `dfi.group_assignments.feature_summary` JSON.

**Idempotency** — every write is keyed by `Idempotency-Key` header + SHA256 of the request payload. Replays with identical payload return the cached response. Replays with different payload return 409.

**XGB Inline Scoring** — Hunter-AIO scores every flow at flush time. High-confidence attack IPs are promoted to D2 via watchlist. RECON IPs (prob >= 0.9) are written to `dfi_recon.recon_flows` and hourly synced to MikroTik for network-edge trapping.

**ML Training** — `POST /action/ml/train` spawns background export + k-fold XGB training. Supports `model_type=attack` (binary ATTACK vs NORM) or `model_type=recon` (dedicated RECON classifier). Status polled via `/data/ml/train-status`.

**ML Rescoring** — `POST /action/ml/rescore` rescores historical flows with a specified model. Useful for backfilling predictions after training a new model version.

---

## SOC Dashboard Pages (12)

| Route | Page | Description |
|-------|------|-------------|
| `/` | **Overview** | KPI tiles, depth pie, top groups bar, top-20 attacker table, XGB scoring stats. 30s auto-refresh. |
| `/explorer` | **Explorer** | Filterable attacker table by group, depth, time window (1h-7d). Inline D3/Watch actions. |
| `/ip/:ip` | **IP Profile** | Single-IP deep-dive: hops, group trajectory, depth history, fingerprint rarity, quick actions. |
| `/campaigns` | **Campaigns** | Campaign list with bulk action dropdowns (Watch 72h, Block 24h, Promote D3). |
| `/control` | **Control Plane** | 5-tab forms: Upsert / Delete / Annotate / Bulk / Watchlist viewer. |
| `/audit` | **Audit Log** | Unified log with IP/request_id search. 30s auto-refresh. |
| `/vms` | **VM Status** | Hunter-AIO banner + 10 VM cards with Proxmox metrics, evidence counts, reboot. |
| `/ml` | **ML Dashboard** | Model stats, confusion matrix, feature importance, scoring throughput. Train (ATTACK/RECON toggle), Rescore. |
| `/flows` | **Flow Explorer** | Paginated flow list with label/protocol/port/IP filters, URL-based state. |
| `/flows/:id` | **Flow Detail** | Flow metadata, label/prediction badges, packet table, fingerprints. |
| `/killchain` | **Kill Chain** | IP search → horizontal timeline: RECON → KNOCK → BRUTE → EXPLOIT → COMPROMISE. |
| `/realtime` | **Real-Time** | 5 metric cards with sparklines (PPS, flows/sec, XGB rate, attackers, drops), 5s poll. |

---

## Request/Response Examples

### Upsert Watchlist

```bash
curl -X POST http://192.168.0.100:8010/watchlist/upsert \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-001' \
  -d '{
    "ip": "78.128.114.126",
    "capture_depth": 3,
    "priority": 1,
    "reason": "horizontal sweep across /24",
    "source": "analyst",
    "actor": "dashboard",
    "expires_at": "2026-03-01T00:00:00Z"
  }'
```

```json
{"ok": true, "request_id": "demo-001", "message": "upserted 78.128.114.126 at depth 3"}
```

### Bulk Action (by campaign)

```bash
curl -X POST http://192.168.0.100:8010/action/bulk \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: bulk-campaign-001' \
  -d '{
    "action": "upsert",
    "campaign_id": "C-2026-0042",
    "capture_depth": 2,
    "priority": 2,
    "reason": "promote campaign members"
  }'
```

```json
{"ok": true, "request_id": "bulk-campaign-001", "message": "bulk upsert done", "processed": 14, "skipped": 2}
```

### Train RECON Model

```bash
curl -X POST http://192.168.0.100:8010/action/ml/train \
  -H 'Content-Type: application/json' \
  -d '{"model_type": "recon", "balanced": true, "folds": 5}'
```

```json
{"ok": true, "request_id": "train", "message": "Training started (recon, 5 folds)"}
```

### IP Profile

```bash
curl http://192.168.0.100:8010/data/attacker/78.128.114.126?hours=24
```

```json
{
  "ip": "78.128.114.126",
  "capture_depth": 3,
  "priority": 1,
  "expires_at": 1772352000,
  "hops": [
    {"target_ip": "216.126.0.218", "dst_port": 445, "app_proto": "6", "vlan_id": 0,
     "first_ts": 1771988434, "pkts_fwd": 3, "pkts_rev": 2, "total_bytes": 420, "conn_state": "5"}
  ],
  "groups": [
    {"group_id": "RECON", "sub_group_id": "PORT_SCAN", "confidence": 1.0,
     "window_start": 1772047706, "window_end": 1772069306, "timestamp": 1772069306}
  ],
  "depth_history": [],
  "fingerprints": [
    {"fp_type": "ja3", "fp_value": "a0e9f5d64349fb13191bc781f81f42e1", "freq": 847}
  ]
}
```

---

## Schema Migration

Run `schema/06_backend_api_audit.sql` to add `request_id` columns and the optional `campaign_members` table.
Run `schema/08_recon_db.sql` to create the `dfi_recon` database and `recon_flows` table.

## File Layout

```
backend_api/
  app.py           Route definitions + middleware (33 endpoints)
  service.py       Business logic (ControlPlaneService)
  adapters.py      ClickHouse + SQLite data access
  models.py        Pydantic request/response schemas
  config.py        Settings from environment
  proxmox.py       Proxmox API client (VM status, reboot)
  rescorer.py      Background flow rescoring worker
  trainer.py       Background ML training worker (export + k-fold XGB)
  scheduler.py     QuietDemoter background thread
  main.py          Uvicorn entry point
  requirements.txt Python dependencies
  ui/
    index.html          Legacy vanilla JS dashboard
    soc-dashboard/      React 18 + TypeScript + Vite SPA (12 pages)
      dist/             Production build (~224KB gzipped)
```
