# Backend Dashboard Design (DFI Behavioral Architecture)

This document specifies a practical **backend (analyst/SOC) dashboard** aligned to the DFI Behavioral Architecture Spec, including the dual-store model (**ClickHouse ledger + SQLite hot cache**) and the control-plane workflow (**Streamlit reads ClickHouse; “push to Hunter” writes SQLite + logs an event**).

---

## 1) Users, goals, and one-click actions

### Primary roles
- **SOC Analyst (fast triage):** find top active threats, inspect one IP, promote capture, push block/watch.
- **Threat Researcher (deep dive):** campaign clustering, movement graphs, fingerprints/tooling, exports.
- **Ops/Engineer (keep it running):** ingest health, packet loss, ClickHouse lag/TTL, sensor status.
- **ML/Detection (model governance):** versions, confidence distributions, drift, label/evidence alignment.

### Standard actions (always auditable)
Every UI action should:
1) **Write to SQLite** `watchlist.db` (fast-path state the Hunter reads)
2) **Append an event row in ClickHouse** (e.g., `analyst_action` + optional `depth_change` / `watchlist_sync`)

Actions to support:
- **Promote to D3** (with TTL + reason)
- **Set Watch (D2 / 72h)** (TTL template)
- **Push to Block** (policy flag + TTL)
- **Demote after quiet** (schedule-only; never mid-activity)
- **Bulk apply to campaign/cluster** (apply same action to N IPs)

---

## 2) Information architecture (left nav)

### A. Operations
1. **Overview**
2. **Live Activity**
3. **Sensor & Ingest Health**

### B. Threat Analysis
4. **Attacker Explorer**
5. **IP Profile**
6. **Campaigns & Clusters**
7. **Movement Graph**
8. **Fingerprints & Tooling**
9. **Evidence Timeline**

### C. Control Plane
10. **Watchlist / Policy**
11. **Depth Changes (Audit & Tuning)**
12. **Blocks / Exceptions**

### D. ML & Data
13. **Model Monitor**
14. **Dataset Exports**
15. **Admin (RBAC, API keys, retention)**

---

## 3) Page-by-page design (what you show + what it queries)

### 1) Overview (SOC “NOC wall”)

**Top KPIs (last 15m / 1h / 24h toggle):**
- flows/sec, attackers active, new attackers, D3 active count
- depth distribution (D0/D1/D2/D3)
- top behavior groups (Intent/Subgroup)
- top campaigns (cluster size + activity)
- pipeline lag (ingest delay), packet drop, ClickHouse write rate

**Widgets**
- Time-series: flows/sec, D3 promotions/sec
- Stacked bar: depth distribution over time
- Table: “Top 20 active attackers” (sortable by priority score)

**Primary sources**
- `flows`
- `group_assignment` events
- `depth_change` events
- `model_predictions`

---

### 2) Live Activity (near real-time stream)

**Goal:** “What’s happening right now”
- rolling table of latest suspicious flows (every 2–5s refresh)
- quick buttons: Promote D3 / Watch 72h / Block

**Filters**
- node / VLAN / dst_port / app_proto / current depth / group / confidence

**Performance rule**
- live view uses **thin rows only** (no heavy joins); click-through does the deep query.

---

### 3) Sensor & Ingest Health (Ops)

- per sensor: CPU, RAM, disk, ring buffer fill, packet drop
- per pipeline: ClickHouse insert rate, lag, errors, TTL status
- “Top tables by size” + “TTL deletions last 24h”

---

### 4) Attacker Explorer (main workbench)

**Table columns (default):**
- `src_ip`, `last_seen`, `current_group`, `confidence`, `current_depth`
- sessions (1h/24h), unique_targets, unique_ports
- fanout_ratio, escalation_slope, vlan_cross_flag
- “worst stage reached” (from model-3 later; placeholder now)

**Power features**
- “Compare 2 IPs” (side-by-side)
- “Add to investigation” queue

**Click path**
- row click → **IP Profile**

---

### 5) IP Profile (single attacker dossier)

**Header**
- IP, current group/subgroup + confidence
- current depth + TTL + reason
- “quick actions” buttons

**Panels**
1) **Trajectory (rolling windows):** last 6h group transitions
2) **Movement timeline:** ordered hops (target:port, VLAN, pkts, duration)
3) **Fanout shape:** targets vs sessions, port concentration, target entropy
4) **Fingerprints:** JA3/HASSH frequencies, “rare tooling” indicator
5) **Evidence:** auth failures, process events, malware drops (if present)
6) **Raw artifacts (if D3):** payload snippets / PCAP segment links

**One-click actions**
- Promote to D3 (TTL presets: 48h / 7d)
- Watch 72h (D2)
- Push to block (TTL presets: 24h / 72h / 7d)
- Add annotation (analyst note → ClickHouse event)

---

### 6) Campaigns & Clusters

**Goal:** collapse “one IP” into “one operation”
- campaign list: `campaign_id`, active_count, total_ips, top ports, top fingerprints, first_seen/last_seen
- “cluster story”: common tooling + movement pattern classification

**Actions**
- “Apply action to all members” (watch/block/promote) with safeguards:
  - show count + estimated write impact
  - default TTL shorter for bulk blocks unless explicitly promoted

---

### 7) Movement Graph (kill-chain visualization)

Two modes:
- **IP mode:** hop sequence graph (time gaps, service transitions)
- **Campaign mode:** aggregated pivot chains across targets/services

Visuals:
- Sankey: service transitions
- Sequence chart: time gaps + depth escalation

---

### 8) Fingerprints & Tooling

- “Top rare JA3/HASSH today”
- “Fingerprint → associated groups/campaigns”
- “New fingerprint” alert (first seen in last N hours)

---

### 9) Evidence Timeline

- unified timeline per target or per attacker:
  - host evidence events + correlated flows + predictions
- fast “show me flows around this event (±2m)”

---

### 10) Watchlist / Policy (SQLite projection + templates)

**Tabs**
- **Current Watchlist (SQLite):** `src_ip`, depth, priority, reason, expires
- **Templates:** “Watch 72h”, “Block 24h”, “D3 48h”
- **Default rule:** `(default) → D1`

**Bulk tools**
- import/export CSV
- “expire all from campaign_id” (writes deletes + logs events)

---

### 11) Depth Changes (Audit & tuning)

- histogram: promotions by trigger (classifier vs analyst)
- “what % of D3 produced evidence events?”
- “top demotions that later re-promoted” (demotion threshold issues)

Use this page to continuously tune D0/D1/D2/D3 thresholds.

---

### 12) Blocks / Exceptions

- blocklist view (what’s enforced where)
- exceptions (allowlist) with strict audit
- integration status (if you push blocks to edge firewalls later)

---

### 13) Model Monitor

Per model (XGBoost/CNN now; Model-3 later):
- current model version, last retrain, scoring throughput
- confidence distribution by group
- drift indicators (feature stats shifts)
- “evidence alignment”: how often evidence events agree with predicted intent class

---

### 14) Dataset Exports

- export “learning bundles” for top 1% (by your escalation policy)
- export by: group, campaign_id, fingerprint, date range, depth level
- include: flow rows, packet tokens (D2+), payload refs (D3), evidence events

---

## 4) Backend control-plane contract (clean + safe)

Even if the UI is Streamlit, do **not** let Streamlit write SQLite directly. Put a small internal API in front.

### Write endpoints (examples)
- `POST /watchlist/upsert {ip, depth, priority, reason, expires_at, source}`
- `POST /watchlist/delete {ip, reason}`
- `POST /action/annotate {ip, note, tags}`
- `POST /action/bulk {campaign_id|ip_list, action, ttl, reason}`

### Hard requirements
- **Idempotency key** per request
- **Append-only ClickHouse logging** for every action
- Server-side policy enforcement: **never demote while active**

---

## 5) UI defaults that make this usable at scale

### Global filter bar (top)
- time range, node, VLAN, service/port, group, depth, confidence threshold

### Saved views
- “P1 threats”, “New rare fingerprints”, “VLAN crossing”, “Return-and-deepen”

### Latency rules
- list pages rely on “latest state per IP” materialized view
- deep pages run heavier joins only after click-through

---

## Appendix: Implementation notes (optional but recommended)

### Suggested table/view strategy (high level)
- Maintain a **“latest attacker state”** view/table keyed by `src_ip` containing:
  - last_seen, current_depth, current_group, confidence, counters (1h/24h), fingerprint summaries
- Keep raw event tables append-only; derive dashboards from:
  - latest-state + thin aggregations for list pages
  - raw joins only on profile pages

### Auditability baseline
- Every analyst action produces:
  - a ClickHouse `analyst_action` row with actor, reason, ttl, and request_id
  - a SQLite row mutation (upsert/delete) with the same request_id
