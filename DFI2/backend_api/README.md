# DFI2 Backend API

FastAPI control-plane for the SwarmTrap threat intelligence pipeline. Manages attacker watchlists, capture depth, analyst actions, ML model training/rescoring, GeoIP-enriched attack maps, and the GOD (Global Offense Detection) pipeline. Exposes an 8-page React SOC dashboard. All writes are idempotent. Reads pull from ClickHouse (flows, IP profiles, scores, evidence, captures, service labels) and SQLite (watchlist state).

**Port:** `8010` &nbsp;|&nbsp; **Service:** `dfi2-backend-api.service`

---

## Quick Start

```bash
# Create a virtual environment and install dependencies
python3 -m venv .venv
.venv/bin/pip install -r backend_api/requirements.txt

# Run the API server
PYTHONPATH=/path/to/project .venv/bin/python -m backend_api.main
```

The SOC dashboard is served at `http://localhost:8010/ui`.

## Configuration

All settings are environment variables with sensible defaults (see `config.py`).

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
| `ML_METRICS_DIR` | `/opt/dfi2/ml_metrics/` | Directory for ML model metrics JSON files |
| `GEOIP_PATH` | `/opt/dfi2/geoip/dbip-city-lite.mmdb` | MaxMind/DBIP GeoIP database path |

---

## Endpoints

### Health & UI

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Returns `{"ok": "true"}` |
| GET | `/ui` | React SPA SOC dashboard (optional basic auth) |
| GET | `/ui/{rest}` | SPA catch-all for client-side routing |
| GET | `/ui/legacy` | Original vanilla JS dashboard |

### Watchlist Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/watchlist` | List current watchlist entries from SQLite (limit 1-5000, default 200) |
| POST | `/watchlist/upsert` | Add/update IP on watchlist (depth, priority, reason, expiry) |
| POST | `/watchlist/delete` | Remove IP from watchlist |

### Action Endpoints

All writes require `Idempotency-Key` header. Reusing a key with a different payload returns HTTP 409.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/action/annotate` | Log analyst note + tags for an IP |
| POST | `/action/bulk` | Bulk upsert/delete by `ip_list` or `campaign_id` |

### Data Read Endpoints

| Method | Path | Query Params | Description |
|--------|------|--------------|-------------|
| GET | `/data/audit` | `limit` (1-1000, default 200) | Unified audit log (analyst actions + depth changes) |
| GET | `/data/ml/stats` | `model_name` (default "xgb_v6") | ML model stats + confusion matrix + feature importance |
| GET | `/data/ml/models` | _(none)_ | List available model files with training metrics |
| GET | `/data/ml/registry` | _(none)_ | Rich model registry: XGB + CNN files, aliases, deploy status, metrics |
| GET | `/data/ml/models/{filename}/download` | `api_key` | Download model file |
| GET | `/data/ml/rescore-status` | `model_name`, `labels` | Background rescore job status |
| GET | `/data/ml/recon-validation` | _(none)_ | RECON model validation results |
| GET | `/data/ml/train-status` | _(none)_ | Background training job status (export + fold progress) |
| GET | `/data/map/events` | `hours`, `limit` | GeoIP-enriched attacker locations for world map |
| GET | `/data/map/heatmap` | `days` (1-30, default 7) | 7x24 attack count matrix (day-of-week x hour-of-day) |
| GET | `/data/map/countries` | `hours`, `limit` | Top attacking countries by flow count |

### ML Action Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/action/ml/rescore` | Rescore flows with configurable model/labels/skip-scored |
| POST | `/action/ml/train` | Train XGB model (type: `attack` or `recon`, configurable folds/hours/balance) |
| DELETE | `/action/ml/models/{filename}` | Delete a saved model file and its metrics sidecar |

### VM Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vms` | 10-VM grid: Proxmox status (CPU, RAM, uptime) + ClickHouse flow/attacker counts |
| GET | `/vms/{vmid}/events` | Evidence events for a specific VM's public IP |
| POST | `/vms/{vmid}/reboot` | Reboot a Proxmox VM + log the action |

### GOD Pipeline Endpoints (15 endpoints)

These endpoints power the GOD-first SOC dashboard, reading from `ip_profile`, `ip_score_log`, `evidence_events`, `ip_capture_d2`, `ip_service_labels`, and `ip_capture_budget`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/data/god/health` | Pipeline health: 4-stage check (GOD1 scores, brain judgments, GOD2 verdicts, profile active) |
| GET | `/data/god/overview` | KPI tiles: total IPs, drops, captures, evidence count, discrepancies, recent drops, score rate, verdict/service breakdowns. 15s cache. |
| GET | `/data/god/catches` | Discrepancy catches (false negatives): IPs with `DIS_FN_*` verdict groups, enriched with evidence + service labels |
| GET | `/data/god/reputation` | Paginated IP reputation table with filters (verdict, verdict_group, evidence, IP search) and sorting |
| GET | `/data/god/ip/{ip}` | Full IP dossier: profile, GeoIP, score timeline, evidence events, per-service labels |
| GET | `/data/god/verdicts` | Two-tab view: DROP verdicts from `ip_profile` / CAPTURE entries from `ip_capture_d2` |
| GET | `/data/god/services` | Per-service class distribution, evidence by source program, capture budgets |
| GET | `/data/god/services/{service_id}` | Drill-down: class distribution, top IPs, budget for one service |
| GET | `/data/god/training` | Training data status: D2 capture counts by discrepancy type, per-service budget deficits |
| GET | `/data/god/map/events` | GeoIP-enriched attacker events from `ip_score_log` |
| GET | `/data/god/map/heatmap` | Day-of-week x hour heatmap from `ip_score_log` |
| GET | `/data/god/map/countries` | Top attacking countries from `ip_score_log` |
| GET | `/data/god/allowlist` | List Research/Benign (RB) IPs that bypass blocking |
| POST | `/data/god/allowlist/add` | Add IP to allowlist (verdict=CAPTURE, verdict_group=RB) |
| POST | `/data/god/allowlist/remove` | Remove IP from allowlist (reset to verdict=NONE) |

---

## Architecture

```
                    +------------------+
                    |  /ui React SPA   |  (dark-theme SOC dashboard, 8 pages)
                    +--------+---------+
                             |
                    +--------v---------+
                    |     FastAPI       |  :8010
                    |  app.py + god_    |
                    |  endpoints.py     |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
       +------v------+ +----v-----+ +-----v--------+
       | ClickHouse  | |  SQLite  | |   Proxmox    |
       | dfi.*       | | watchlist| |   API (:8006)|
       +-------------+ +----------+ +--------------+

ClickHouse tables read:
  dfi.flows              Flow features (55+ cols, src/dst/timing/entropy/TCP)
  dfi.ip_profile         Per-IP reputation: verdict, evidence count, XGB class, services (ReplacingMergeTree)
  dfi.ip_score_log       GOD1 per-flow XGB scores with timestamps
  dfi.ip_service_labels  Per-IP per-service classification (SSH/HTTP/RDP/SQL/SMB)
  dfi.ip_capture_d2      Discrepancy capture records for ML training data
  dfi.ip_capture_budget  Per-service-class capture targets and progress
  dfi.evidence_events    Host-log evidence (Windows events, syslog) correlated to IPs
  dfi.analyst_actions    All API write actions (append-only)
  dfi.depth_changes      Capture depth audit trail
  dfi.campaign_members   Campaign membership
  dfi.model_predictions  XGB scoring results (label, confidence, model version)
  dfi.watchlist_syncs    Watchlist sync events
  dfi.labels             Flow-level label assignments

SQLite tables:
  watchlist                    IP -> depth/priority/reason/expiry
  control_plane_requests       Idempotency records (request_id + payload hash)

Background workers (in-process):
  rescorer.py    Background flow rescoring subprocess (spawns score_norm_flows.py)
  trainer.py     Background ML training subprocess (export.py -> train_xgb.py, k-fold XGB)
  scheduler.py   QuietDemoter thread (auto-demote inactive IPs)
```

## Key Behaviors

**Capture Depth Gating** -- the watchlist assigns each IP a capture depth:
- D0: drop (no capture)
- D1: flow metadata + fingerprints only
- D2: flow + 128-token packet sequences
- D3: full capture + payload heads

**Active Attacker Protection** -- demotion is blocked while the IP has flows in the last `ACTIVE_WINDOW_SEC` (default 15 min).

**Quiet Demoter** -- background thread (opt-in via `ENABLE_QUIET_DEMOTER=1`) auto-demotes one level per cycle: D3 -> D2 -> D1. Never demotes below D1. Skips active IPs and recently-updated entries.

**Campaign Resolution** -- `POST /action/bulk` with `campaign_id` resolves IPs from `dfi.campaign_members` first, falls back to `dfi.group_assignments.feature_summary` JSON.

**Idempotency** -- every write is keyed by `Idempotency-Key` header + SHA256 of the request payload. Replays with identical payload return the cached response. Replays with different payload return 409.

**GeoIP Enrichment** -- the ClickHouse adapter lazily loads a MaxMind/DBIP MMDB database and caches lookups (up to 10K entries) for attack map, country ranking, and IP detail endpoints.

**ML Training** -- `POST /action/ml/train` spawns a background subprocess chain: `export.py` exports training data from ClickHouse, then `train_xgb.py` runs GroupKFold XGBoost training. Supports `model_type=attack` (binary ATTACK vs NORM) or `model_type=recon` (dedicated RECON classifier). Progress is tracked via a JSON status file polled by `/data/ml/train-status`.

**ML Rescoring** -- `POST /action/ml/rescore` spawns a background `score_norm_flows.py` subprocess to backfill predictions after training a new model version.

**Model Registry** -- `GET /data/ml/registry` scans the models directory for `.json` (XGB) and `.pt` (CNN) files, resolves symlink aliases, loads companion `_metrics.json` sidecars, and marks deployed models.

**GOD Pipeline Health** -- `GET /data/god/health` checks 4 pipeline stages in a single request: GOD1 scores (5min/30min windows), brain judgments (10min), GOD2 verdicts (10min), and profile updates. Returns `healthy`, `stale`, or `dead`.

---

## SOC Dashboard Pages (8)

The current SOC dashboard is a React 18 + TypeScript + Vite SPA located in `ui/soc-dashboard/`. It uses React Query for data fetching and has a dark-theme sidebar layout.

| Route | Page | Description |
|-------|------|-------------|
| `/` | **GOD Home** | Pipeline health indicator, KPI tiles (total IPs, drops, captures, evidence, discrepancies), verdict group breakdown, verdict pie chart, service summary, score rate. |
| `/verdicts` | **Verdicts** | Two-tab view: DROP verdicts with expiry and service info / CAPTURE entries (D2 captures) with discrepancy types. Paginated. |
| `/services` | **Services** | Per-service (SSH, HTTP, RDP, SQL, SMB) class distribution, capture budgets, evidence by source program. Drill-down per service. |
| `/map` | **Attack Map** | GeoIP world map of attacker locations, day-of-week/hour heatmap, top attacking countries. |
| `/training` | **Training & Models** | Training data progress (D2 captures vs 1M target), per-service budget deficits, model registry, train/rescore controls. |
| `/control` | **Allowlist** | Research/Benign (RB) IP management: view, add, remove IPs from the allowlist. |
| `/ip/*` | **IP Detail** | Full IP dossier: profile card, GeoIP, score timeline chart, evidence events, per-service labels. |
| `/vms` | **VM Status** | 10-VM grid with Proxmox metrics (CPU, RAM, uptime), attack flow counts, evidence events, reboot button. |

---

## Request/Response Examples

### Upsert Watchlist

```bash
curl -X POST http://localhost:8010/watchlist/upsert \
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
{"ok": true, "request_id": "demo-001", "message": "watchlist upserted"}
```

### Bulk Action (by campaign)

```bash
curl -X POST http://localhost:8010/action/bulk \
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
{"ok": true, "request_id": "bulk-campaign-001", "message": "bulk upsert finished", "processed": 14, "skipped": 2}
```

### Train XGB Model

```bash
curl -X POST http://localhost:8010/action/ml/train \
  -H 'Content-Type: application/json' \
  -d '{"model_type": "recon", "balanced": 500000, "folds": 5}'
```

```json
{"ok": true, "request_id": "train", "message": "Training started"}
```

### GOD Pipeline Health

```bash
curl http://localhost:8010/data/god/health
```

```json
{
  "pipeline_status": "healthy",
  "stages": {
    "god1_scores": {"count_5min": 12340, "count_30min": 74200, "last_ts": 1781234567, "ok": true},
    "brain_judgments": {"count_10min": 580, "last_ts": 1781234500, "ok": true},
    "god2_verdicts": {"count_10min": 42, "last_ts": 1781234490, "ok": true},
    "profile_active": {"count_10min": 622, "last_ts": 1781234500, "ok": true}
  }
}
```

---

## File Layout

```
backend_api/
  __init__.py      Package init, exports create_app()
  app.py           Route definitions + middleware (~45 endpoints)
  god_endpoints.py 15 GOD pipeline endpoints (register_god_routes)
  service.py       Business logic (ControlPlaneService) with port-based DI
  adapters.py      ClickHouse + SQLite data access (GeoIP, maps, ML stats)
  models.py        Pydantic request/response schemas (~35 models)
  config.py        Settings dataclass from environment variables
  proxmox.py       Proxmox VE API client (VM list, status, reboot) + VM_MAP
  rescorer.py      Background flow rescoring (subprocess, model registry)
  trainer.py       Background ML training (export.py -> train_xgb.py orchestration)
  scheduler.py     QuietDemoter background thread
  main.py          Uvicorn entry point
  requirements.txt Python dependencies (fastapi, pydantic, uvicorn, clickhouse-driver, requests)
  ui/
    index.html          Legacy vanilla JS dashboard
    soc-dashboard/      React 18 + TypeScript + Vite SPA
      src/
        App.tsx          Router with 8 lazy-loaded pages
        pages/           GodHome, IpDetail, Verdicts, Services, Training, AttackMap, Allowlist, VMStatus
        components/      Sidebar, Topbar, DataTable, Badge, KpiTile, IpLink, Pagination, etc.
        api/             React Query hooks, client, mutations, types
        lib/             Formatting utilities, toast notifications
      dist/              Production build (served by FastAPI at /ui)
```
