# DFI2 — Deep Flow Intelligence v2

ClickHouse-backed behavioral analytics platform for real-time attacker detection and classification at 40Gbps SPAN rates. Dual-store architecture: ClickHouse append-only ledger for analytics + SQLite hot cache for sub-millisecond per-packet decisions.

---

## Architecture

```
  PV1 (192.168.0.100)                     AIO (172.16.3.113)
  ─────────────────────                   ──────────────────
  10 honeypot VMs                         SPAN mirror / ens192
    → syslog → evidence.db                  → Hunter (D0-D3)
    → labeler → CH evidence_events           → CH (48h TTL)
                                                    │
  Hunter (honeypot mode) ◄─── PV1 pulls CH data ───┘
    → CH (90d TTL)        ─── PV1 pushes watchlist ──►  AIO SQLite

  ┌─────────────────────────────────────────────────────┐
  │  PV1 Analytics Stack                                │
  │  Classifier → group_assignments                     │
  │  Labeler    → evidence correlation → labels         │
  │  ML Score   → model_predictions                     │
  │  Dashboard  → Streamlit :8501                       │
  │  Backend API → FastAPI  :8010                       │
  └─────────────────────────────────────────────────────┘
```

---

## Components

| Directory | Purpose |
|-----------|---------|
| `hunter/` | AF_PACKET TPACKET_V3 capture engine — 75 XGBoost features, 5-channel CNN tokenizer, JA3/HASSH/HTTP/DNS fingerprints, D0–D3 depth gating |
| `backend_api/` | FastAPI control plane (port 8010) — watchlist CRUD, idempotent audit log, dark-theme SOC UI |
| `dashboard/` | Streamlit analyst UI (port 8501) — attacker explorer, IP dossiers, campaign view |
| `classifier/` | Behavioral group assignment daemon — maps IPs to RECON / CREDENTIAL_ATTACK / EXPLOIT_DELIVERY / etc. |
| `labeler/` | Evidence correlation — joins honeypot host logs with flows (±120s) to produce ground-truth labels |
| `ml/` | XGBoost + CNN training and batch scoring pipelines |
| `sync/` | PV1 ↔ AIO data movement — pulls CH flows from AIO, pushes SQLite watchlist |
| `schema/` | ClickHouse DDL (applied in order: 01–06) |
| `deploy/` | Paramiko-based deployment scripts |
| `tests/` | Unit tests for features, tokenizer, fingerprints, service layer |

---

## Capture Depth System (D0–D3)

Hunter reads `/opt/dfi-hunter/watchlist.db` every 30 seconds and applies per-IP depth gating:

| Depth | Stored | Cost | Trigger |
|-------|--------|------|---------|
| **D0** — DROP | Nothing | Zero | Confirmed repetitive noise after classification |
| **D1** — FLOW | `flows` + `fingerprints` | Low | Default for unclassified IPs |
| **D2** — SEQUENCE | D1 + `packets` (128 tokens) | ~30× D1 | Behavior group classified, moderate confidence |
| **D3** — FULL | D2 + `payload_bytes` | Highest | Campaign progression, analyst promotion, EXPLOIT/COMPROMISE prediction |

**Policy:** Never demote while attacker is active. Quiet demoter steps down one level at a time after TTL.

---

## Behavior Groups

```
RECON                       CREDENTIAL_ATTACK           EXPLOIT_DELIVERY
  PORT_SCAN                   SSH_BRUTE                   WEB_EXPLOIT
  SERVICE_SWEEP               MYSQL_BRUTE                 SERVICE_EXPLOIT
  BANNER_GRAB                 RDP_BRUTE                   PHASED_ATTACK
                              HTTP_AUTH_SPRAY
                              CROSS_SERVICE_ROT

INFRASTRUCTURE_ABUSE        CAMPAIGN_PROGRESSION        UNCLASSIFIED
  SIP_FRAUD                   HORIZONTAL_SWEEP            LOW_AND_SLOW
  DNS_TUNNEL                  VERTICAL_ESCALATION         ONE_SHOT_NOISE
  AMPLIFICATION               PIVOT_CHAIN                 EMERGING
                              RETURN_AND_DEEPEN
```

---

## ClickHouse Schema (`dfi` database)

Apply scripts in order:

```bash
clickhouse-client < schema/01_tables.sql       # flows, packets, fingerprints, labels
clickhouse-client < schema/02_behavioral.sql   # evidence_events, fanout_hops, model_predictions,
                                               # group_assignments, depth_changes, analyst_actions,
                                               # watchlist_syncs, payload_bytes
clickhouse-client < schema/03_buffers.sql      # buffer tables (5-min / 100K row flush)
clickhouse-client < schema/04_views.sql        # materialized views + v_xgb / v_cnn export views
clickhouse-client < schema/05_watchlist.sql    # SQLite watchlist schema (reference)
clickhouse-client < schema/06_backend_api_audit.sql  # campaign_members, request log
```

**Key tables:**

| Table | Rows (live) | Purpose |
|-------|-------------|---------|
| `flows` | 5M+ | Flow features — 75 XGBoost columns, TTL 90d |
| `fanout_hops` | 5M+ | Per-attacker movement (target, port, VLAN, gap) |
| `group_assignments` | 433K+ | Behavior group membership + confidence |
| `fingerprints` | 389K+ | JA3, HASSH, HTTP UA, DNS |
| `depth_changes` | 339+ | Capture depth promotion/demotion audit trail |
| `analyst_actions` | — | Every dashboard/API action, append-only |
| `watchlist_syncs` | 33K+ | PV1→AIO sync events |
| `evidence_events` | — | Honeypot host logs correlated to flows |
| `model_predictions` | — | XGBoost + CNN scores per flow |
| `labels` | — | Ground truth from evidence correlation |
| `payload_bytes` | — | D3 payload head (30d TTL) |

---

## Backend API (port 8010)

FastAPI service with idempotent write operations and a built-in SOC dashboard at `/ui`.

### Write Endpoints

All writes require `Idempotency-Key` header. API key via `X-API-Key` if `BACKEND_API_KEY` is set.

```
POST /watchlist/upsert      { ip, capture_depth, priority, reason, expires_at }
POST /watchlist/delete      { ip, reason }
POST /action/annotate       { ip, note, tags }
POST /action/bulk           { action, ip_list|campaign_id, capture_depth, reason }
POST /action/demote-quiet   (scheduler trigger)
```

### Read Endpoints

```
GET  /data/overview?window=15       KPIs: flows/sec, active attackers, depth dist, top groups
GET  /data/attackers?hours=24       Attacker list with group, depth, sessions, targets
GET  /data/attacker/{ip}?hours=24   Full IP dossier: hops, group trajectory, depth history, fingerprints
GET  /data/campaigns                Campaign list with IP counts
GET  /data/audit                    Unified analyst + system audit log
GET  /watchlist                     Current SQLite watchlist entries
GET  /vms                           Proxmox VM status + ClickHouse flow counts merged
GET  /vms/{vmid}/events             Evidence events for a VM's public IP
POST /vms/{vmid}/reboot             Reboot via Proxmox API (logged to analyst_actions)
GET  /health                        { "ok": "true" }
GET  /ui                            Dark-theme SOC SPA (7 pages)
```

### Example

```bash
curl -sS -X POST http://192.168.0.100:8010/watchlist/upsert \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: promote-001' \
  -d '{
    "ip": "77.83.38.211",
    "capture_depth": 3,
    "priority": 1,
    "reason": "CAMPAIGN_PROGRESSION detected",
    "source": "analyst",
    "actor": "soc-ui",
    "expires_at": "2026-02-28T00:00:00Z"
  }'
```

---

## SOC UI (`/ui`)

Dark-theme single-page app. No build step — pure HTML/JS served directly from FastAPI.

| Page | Content |
|------|---------|
| **Overview** | 5 KPI tiles, depth doughnut + group bar chart (Chart.js), top-20 attacker table, activity feed, 30s auto-refresh |
| **Explorer** | Filterable attacker table — IP / group / depth / 1h–7d window |
| **IP Profile** | Movement timeline, group trajectory, depth history, fingerprints with RARE flag |
| **Campaigns** | Bulk action per campaign (Watch 72h / Block 24h / Promote D3) |
| **Control Plane** | Upsert / Delete / Annotate / Bulk tabs + quick templates |
| **Audit Log** | Analyst + system events, filter by source/IP/request-id |
| **VM Status** | 10-VM card grid, Proxmox live CPU/RAM/uptime, evidence events, reboot |

---

## Configuration

### Hunter (`hunter/config.py` / env file)

```bash
HUNTER_IFACE=ens192           # Capture interface
CAPTURE_MODE=honeypot         # 'span' or 'honeypot'
HONEYPOT_IPS=216.126.0.206    # Target IPs (honeypot mode)
CH_HOST=localhost
CH_PORT=9000
WATCHLIST_DB=/opt/dfi-hunter/watchlist.db
FANOUT_WORKERS=4
CPU_LIST=4,5,6,7              # CPU affinity
SENSOR_ID=aio1
SESSION_TIMEOUT=120
FLUSH_INTERVAL=10
```

### Backend API

```bash
CH_HOST=localhost
CH_PORT=9000
WATCHLIST_DB=/opt/dfi-hunter/watchlist.db
BACKEND_API_HOST=0.0.0.0
BACKEND_API_PORT=8010
BACKEND_API_KEY=              # Optional auth token
BACKEND_UI_USER=admin
BACKEND_UI_PASS=              # Optional UI basic auth
ENABLE_QUIET_DEMOTER=1
QUIET_DEMOTE_INTERVAL_SEC=300
QUIET_DEMOTE_AFTER_SEC=3600
PVE_HOST=https://192.168.0.100:8006
PVE_USER=root@pam
PVE_PASS=
```

---

## Deployment

Bottom-up bring-up: raw data first, evidence consolidation second, database/writers third, full audit fourth, API/UI last. Each phase must pass its gate before moving on.

### Phase 1: NIC + PCAP Capture Layer

**Goal:** Raw packets flowing into userspace with correct sizes.

1. Disable all NIC hardware offloads on the capture interface:
   ```bash
   ethtool -K ens192 gro off gso off tso off lro off sg off tx off rx off
   ```
2. Create persistent `dfi-nic-offload.service` so offloads stay off across reboots.
3. Deploy Hunter package to AIO (`/opt/dfi2/hunter/`):
   ```bash
   python3 deploy_hunter_aio.py
   ```
4. Configure env file: `HUNTER_IFACE`, `FANOUT_WORKERS`, `CPU_LIST`, `CAPTURE_MODE`, `HONEYPOT_IPS`.
5. Start `dfi-hunter2.service` (AF_PACKET TPACKET_V3, 4 workers, FANOUT_HASH, 256 MB ring/worker).

**Gate — do not proceed until all pass:**
- `ethtool -k ens192` shows all offloads OFF
- Hunter logs show packets ingested (`journalctl -u dfi-hunter2 -n 20`)
- `tcpdump -c 10 -i ens192` shows real-sized frames (not jumbo)

### Phase 2: Evidence Pipeline

**Goal:** All hard evidence from every source arrives in one place, clearly parsed, with accurate UTC timestamps.

Three evidence daemons:

| Daemon | Role |
|--------|------|
| `dfi_log_bridge.py` | UDP :1514 syslog receiver for honeypot VM logs → SQLite `evidence.db` |
| `evidence_ingest.py` | Polls `evidence.db`, parses Windows Event IDs (4625/4624/4688/7045/…) + SSH patterns → ClickHouse `evidence_events` |
| `winlure_evidence_ingest.py` | Polls Winlure `credentials.db` + `connections`, maps protocols → ClickHouse `evidence_events` |

1. Configure rsyslog forwarding on all 10 honeypot VMs (DFIJsonLog template → UDP 127.0.0.1:1514).
2. Deploy all three daemons as systemd services.
3. Verify timestamp chain: VM syslog (UTC ISO) → bridge `received_at` (UTC) → evidence_ingest DateTime64(3) (UTC ms) → ClickHouse `ts` column.

**Gate — do not proceed until all pass:**
- All 10 VMs forwarding (check `evidence.db` logs table growing)
- `evidence_events` in ClickHouse populated with correct UTC timestamps from all three sources
- Watermark files advancing

### Phase 3: ClickHouse + All Writers

**Goal:** ClickHouse schema deployed, every component writes successfully, data syncs between hosts.

1. Install ClickHouse on PV1 (90 d TTL) and AIO (48 h TTL):
   ```bash
   python3 deploy/deploy_ch_pv1.py
   python3 deploy/deploy_ch_aio.py
   ```
2. Apply schema 01–06 in order (PV1 gets all 6; AIO gets 01–03 with 48 h TTL rewrite):
   ```bash
   python3 deploy/deploy_dfi2_schema_sync.py
   ```
3. Verify buffer tables auto-flushing to main tables.
4. Confirm Hunter writes: `flows_buffer`, `packets_buffer`, `fingerprints_buffer`, `fanout_hops_buffer`, `payload_bytes_buffer`.
5. Confirm evidence ingest writes: `evidence_events_buffer`.
6. Deploy sync crons on PV1:
   ```cron
   */5  * * * *  /opt/dfi2/.venv/bin/python3 -m sync.pull_aio
   */30 * * * *  /opt/dfi2/.venv/bin/python3 -m sync.push_watchlist
   ```
7. Deploy labeler daemon — verify ±120 s evidence/flow correlation → `labels` table.
8. Deploy classifier daemon — verify `group_assignments` + `depth_changes` populating → watchlist push to AIO:
   ```cron
   */5  * * * *  /opt/dfi2/.venv/bin/python3 -m classifier.classifier
   ```
9. Deploy ML scoring (if models trained) — verify `model_predictions` table.

**Gate — do not proceed until all pass:**
- All ClickHouse tables have recent rows
- `pull_aio` watermarks advancing
- `watchlist.db` on AIO updating
- `labels` and `group_assignments` populated with correct evidence correlation

### Phase 4: Full Audit

**Goal:** End-to-end validation before exposing the UI.

1. Run `py_checker.py` — no stuck Python processes, all DFI services active.
2. Run `exec_monitor.py` — 2-min watch, verify no stuck processes > 5 min.
3. Verify ClickHouse row counts growing across all tables.
4. Verify timestamp accuracy: compare `evidence_events.ts` against source syslog timestamps (must match within 1–2 s).
5. Verify label quality: sample 10 flows → check `evidence_mask` bits correct → label matches expected category.
6. Verify classifier output: sample 5 IPs → `group_id`/`sub_group_id` matches observed behavior.
7. Verify watchlist round-trip: PV1 classifier → PV1 `watchlist.db` → AIO `watchlist.db` → Hunter reads correct depth.
8. Verify sync latency: AIO data appears on PV1 within 5 minutes.

**Gate — do not proceed until all pass:**
- All checks above pass
- Zero silent errors in service logs:
  ```bash
  journalctl -u 'dfi-*' --since '1h ago' | grep -i error
  ```

### Phase 5: API + Backend

**Goal:** SOC dashboard and control plane operational.

1. Deploy `dfi2-backend-api.service` (FastAPI :8010):
   ```bash
   python3 deploy/deploy_dfi2.py
   ```
2. Deploy `dfi-dashboard.service` (Streamlit :8501, if used).
3. Configure env: CH connection, watchlist path, Proxmox API credentials, optional auth.
4. Enable quiet demoter if desired (`ENABLE_QUIET_DEMOTER=1`).

**Gate — all must pass:**
- `/health` returns ok:
  ```bash
  curl http://192.168.0.100:8010/health
  ```
- `/data/overview` shows live KPIs
- Click any IP in `/ui` → profile page shows hops, groups, fingerprints
- `/data/audit` shows recent classifier depth changes

### Phase 6: Full Backend Audit

**Goal:** Every page renders, every IP resolves, every evidence record displays correctly. No blank panels, no missing data, no silent query failures.

#### 6a. API Endpoint Sweep

Hit every endpoint and confirm non-empty, correct responses:

| Endpoint | Method | Check |
|----------|--------|-------|
| `/health` | GET | Returns `{"status": "ok"}` |
| `/data/overview` | GET | `total_flows > 0`, `active_attackers > 0`, `groups > 0`, `recent_syncs` non-empty |
| `/data/attackers` | GET | Returns list with at least 1 attacker; each row has `src_ip`, `flow_count`, `group_id` |
| `/data/attacker/{ip}` | GET | Pick 3 known attacker IPs → each returns `hops`, `group_assignments`, `depth_changes`, `fingerprints` (all non-null) |
| `/data/campaigns` | GET | Returns list (may be empty if no campaigns yet — verify no 500 error) |
| `/data/audit` | GET | Returns recent `analyst_actions` + `depth_changes`; timestamps in UTC |
| `/watchlist` | GET | Returns current watchlist entries with `capture_depth`, `priority`, `group_id` |
| `/vms` | GET | Returns all 10 VMs with status, CPU, RAM, and per-VM `flow_count`/`attacker_count` |
| `/vms/{vmid}/events` | GET | Pick 2 VM IDs → returns evidence events with `ts`, `src_ip`, `event_type`, `event_detail` |

```bash
# Quick smoke test
curl -s http://192.168.0.100:8010/health | jq .
curl -s http://192.168.0.100:8010/data/overview | jq '.total_flows, .active_attackers'
curl -s http://192.168.0.100:8010/data/attackers | jq '.[0]'
curl -s http://192.168.0.100:8010/data/audit | jq '.[0:3]'
curl -s http://192.168.0.100:8010/watchlist | jq 'length'
curl -s http://192.168.0.100:8010/vms | jq '.[0]'
```

#### 6b. UI Page Walkthrough

Open `http://192.168.0.100:8010/ui` and verify every page:

| UI Page | What to verify |
|---------|----------------|
| **Overview** | Total flows > 0, flows in 1 h > 0, unique attackers (24 h) > 0, labeled flows count shown |
| **VM Status** | All 10 VMs listed with correct status (running/stopped), CPU/RAM values non-zero for running VMs, flows/attackers per VM populated |
| **Evidence** | Event type breakdown chart renders, top attackers list non-empty, recent events table shows `ts`, `src_ip`, `event_type`, `event_detail` |
| **IP Lookup** | Enter a known attacker IP → group assignments, label distribution, evidence events, and movement timeline all render with data |
| **Top Attackers** | Table shows up to 100 IPs sorted by flow count, each row has `src_ip`, `flow_count`, `dst_port` distribution |
| **Label Distribution** | Chart renders with label categories, counts > 0 for at least `malicious_ssh` or `malicious_rdp` |
| **Ingest Monitor** | Flows-per-minute line chart shows data for last 1 h, no flat-zero gaps longer than 5 min |
| **Storage Stats** | All `dfi.*` tables listed with row counts, compressed size, compression ratio |

#### 6c. IP Profile Deep Check

Pick **5 attacker IPs** (at least 1 SSH-based, 1 RDP-based, 1 multi-protocol):

For each IP verify via `/data/attacker/{ip}`:
1. **Hops** (`fanout_hops`) — target IPs, ports, protocols, timestamps present and in UTC
2. **Group assignments** — `group_id`/`sub_group_id` populated, `confidence` > 0, `window_start`/`window_end` sane
3. **Depth changes** — history shows `old_depth` → `new_depth` transitions with `trigger_reason`
4. **Fingerprints** — at least one of `ja3_hash`, `hassh_hash`, `http_ua_hash` populated (depending on protocol)

Cross-check in the UI: enter the same 5 IPs in IP Lookup page → data matches API response.

#### 6d. Evidence Accuracy Check

1. Pick **10 evidence events** from `/vms/{vmid}/events` across at least 3 different VMs.
2. For each event verify:
   - `event_type` matches source (e.g., Windows Event 4625 → `failed_logon`, SSH auth failure → `ssh_failed`)
   - `src_ip` is a real attacker IP (appears in `flows` table)
   - `ts` is UTC and within 2 s of the original syslog timestamp
   - `event_detail` contains parsed fields (username, service, process name as applicable)
3. Verify evidence → label linkage: events for a given `src_ip` should correlate with labels in `dfi.labels` for that IP's flows.

#### 6e. Write-Path Audit

Test every POST endpoint with a real operation and verify the audit trail:

1. **Annotate:** `POST /action/annotate` for a test IP → confirm row in `/data/audit`
2. **Watchlist upsert:** `POST /watchlist/upsert` → confirm entry in `/watchlist` + depth_change in `/data/audit`
3. **Watchlist delete:** `POST /watchlist/delete` → confirm removal from `/watchlist` + audit logged
4. **Bulk action:** `POST /action/bulk` with 2 IPs → confirm both updated, both audited
5. **Demote quiet:** `POST /action/demote-quiet` → confirm quiet IPs demoted + audit entries
6. **VM reboot:** `POST /vms/{vmid}/reboot` for a test VM → confirm reboot triggered + audit logged

Verify idempotency: replay any POST with the same `Idempotency-Key` → must return same result, no duplicate writes.

**Gate — do not consider deployment complete until all pass:**
- All API endpoints return 200 with correct, non-empty data
- All 8 UI pages render with live data, no blank panels
- 5 IP profiles show complete hops, groups, depth changes, fingerprints
- 10 evidence events verified accurate against source logs
- All 6 write operations produce correct audit trail entries
- Idempotency confirmed on at least 2 POST endpoints
- No 500 errors in API logs: `journalctl -u dfi2-backend-api --since '1h ago' | grep -i 'error\|traceback'`

---

## Services

| Service | Host | Port | Unit file |
|---------|------|------|-----------|
| Hunter (capture) | AIO | — | `dfi-hunter2.service` |
| ClickHouse | PV1, AIO | 9000 / 8123 | `clickhouse-server` |
| Backend API | PV1 | 8010 | `dfi2-backend-api.service` |
| Dashboard | PV1 | 8501 | `dfi-dashboard.service` |

---

## ML Pipeline

```
Flows (v_xgb view, 82 cols)  →  ml/train_xgb.py  →  xgb_model.json
Packets (v_cnn view, 689 cols) →  ml/train_cnn.py  →  cnn_model.pt

ml/score.py  →  model_predictions (ClickHouse)
              →  classifier picks up predictions → group_assignments
              →  classifier updates SQLite watchlist
```

**Classes (both models):** RECONNAISSANCE · CREDENTIAL_ATTACK · EXPLOIT_DELIVERY · INFRASTRUCTURE_ABUSE · CAMPAIGN_PROGRESSION

---

## Tests

```bash
python3 -m pytest tests/ -v
```

| File | Covers |
|------|--------|
| `test_features.py` | 75 XGBoost feature extraction |
| `test_tokenizer.py` | 5-channel CNN packet tokenizer |
| `test_fingerprints.py` | JA3, HASSH, HTTP, DNS parsing |
| `test_backend_api_service.py` | Watchlist service, policy enforcement, idempotency |

---

## Design Principles

- **ClickHouse is the ledger.** All events are append-only and timestamped. No in-place updates.
- **SQLite is disposable.** Hunter needs sub-millisecond point lookups. Watchlist.db can be rebuilt from ClickHouse in minutes.
- **Capture depth controls cost.** D0 skips; D1 stores features; D2 adds sequences; D3 adds payloads. IPs move up and down as evidence accumulates.
- **Analyst actions are auditable.** Every write carries a `request_id` that appears in `analyst_actions`. Retries are idempotent.
- **Evidence rules labels.** Host logs (auth.log, Winlure, syslog) are ground truth. Labels are never inferred from network behavior alone.
