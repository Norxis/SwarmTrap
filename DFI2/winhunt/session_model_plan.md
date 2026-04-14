# Session-Based ML Model with Kill Chain Timeline — Implementation Plan

## Context

Current per-flow scoring (CNN v3 + evil_02_tcp) can't see **conversation shape** or **temporal progression**. A scanner hitting 10K destinations looks the same per-flow as a brute forcer. Worse, a WireGuard session after exploitation looks benign in isolation — only the kill chain context reveals it as C2.

**Goal:** Build a session-based model with per-IP kill chain timeline tracking. Group flows by `(src_ip, dst_ip, dst_port)`, compute 31 features (26 session + 5 history), and score sessions with temporal context. Deploy as batch scorer on PV1 (5-min cron).

---

## Feature Design — 31 Features

### F1 Volume (6)
`sess_flow_count`, `sess_bytes_fwd`, `sess_bytes_rev`, `sess_pkts_fwd`, `sess_pkts_rev`, `sess_reply_ratio`

### F2 Temporal (5)
`sess_duration`, `sess_avg_iat`, `sess_min_iat`, `sess_max_iat`, `sess_avg_flow_dur`

### F3 Depth (5)
`sess_max_flow_dur`, `sess_max_bytes_rev`, `sess_avg_bytes_per_flow`, `sess_payload_ratio`, `sess_bidirectional_ratio`

### F4 TCP Behavior (4)
`sess_syn_only_ratio`, `sess_rst_ratio`, `sess_completed_ratio`, `sess_avg_tcp_flags`

### F5 Source Context (6)
`src_total_sessions`, `src_total_ports`, `src_total_flows`, `src_avg_session_depth`, `src_single_flow_sessions`, `src_reply_rate`

### F6 Kill Chain History (5) — NEW
`prior_scan_count` — # of thin sessions (flow_count≤2, reply_ratio<0.1) from this src_ip before this session
`prior_brute_count` — # of deep single-port sessions (flow_count>20, one dst_port) before this session
`prior_exploit_count` — # of interactive sessions (bidirectional_ratio>0.5, duration>30s) before this session
`time_since_first_seen` — seconds from this IP's first-ever session to current session
`max_prior_stage` — highest kill chain stage reached before this session (0=none, 1=recon, 2=brute, 3=exploit, 4=c2)

**Kill chain stage heuristics (derived from session shape):**
- RECON (1): sess_flow_count≤3, sess_syn_only_ratio>0.5, sess_reply_ratio<0.2
- BRUTE (2): sess_flow_count>20, single dst_port, 0.3<sess_reply_ratio<0.7
- EXPLOIT (3): sess_bidirectional_ratio>0.5, sess_max_flow_dur>30s, sess_max_bytes_rev>1KB
- C2 (4): persistent reconnect pattern (sess_duration>300s or periodic IAT)

---

## Step 1: CH Schema — Session Aggregation

**File:** `DFI2/schema/11_session_stats.sql` — create on PV1

1. **`dfi.session_stats`** — AggregatingMergeTree `ORDER BY (src_ip, dst_ip, dst_port)`
   - Pattern: `schema/04_views.sql:1-13` (source_stats)
   - Aggregate cols: count, sum(bytes/pkts fwd/rev), min/max(ts), max(duration), max(bytes_rev), sum(syn/rst/fin/psh), sum(conn_state_0/4), sum(bidir)

2. **`dfi.mv_session_stats`** — Materialized view fed by `dfi.flows` inserts
   - Pattern: `04_views.sql:15-27` (mv_source_stats)

3. **`dfi.v_session_features`** — View computing 20 features from aggregate state
   - IAT features (3) computed in Python (need sorted timestamps, can't aggregate)

4. **`dfi.session_predictions`** — ReplacingMergeTree, 30-day TTL
   - Key: `(src_ip, dst_ip, dst_port, model_name)`

5. **Backfill** existing flows via one-time `INSERT INTO session_stats SELECT ... FROM dfi.flows GROUP BY ...`

---

## Step 2: Export Training Data

**File:** `DFI2/ml/export_sessions.py` — runs on PV1 (`clickhouse-client` subprocess)

Export via `--max_threads=0 --max_memory_usage=0`:

1. **Session features** — `SELECT * FROM dfi.v_session_features` (all labeled + dirty + clean)
2. **Per-session flow timestamps** — `SELECT src_ip, dst_ip, dst_port, groupArray(first_ts) FROM dfi.flows GROUP BY ...` (for IAT computation)
3. **Source stats** — from `dfi.source_stats` (existing pattern in `export.py`)
4. **Labels** — `SELECT src_ip, dst_ip, dst_port, max(label) FROM dfi.flows JOIN dfi.labels GROUP BY ...`
5. **Dirty sessions** — `SELECT ... FROM dfi_dirty.flows GROUP BY src_ip, dst_ip, dst_port`
6. **Clean sessions** — `SELECT ... FROM dfi_clean.flows GROUP BY src_ip, dst_ip, dst_port`

SCP all to Test.

---

## Step 3: Prep Training Data

**File:** `DFI2/ml/prep_session_v1.py` — runs on Test (polars, 252GB RAM)

1. Load session features + timestamps + source stats + labels
2. Compute IAT features from flow_timestamps arrays (polars list operations)
3. Compute F5 Source Context via `group_by('src_ip')` over all sessions
4. **Compute F6 Kill Chain History:**
   - Sort all sessions per src_ip by timestamp
   - For each session, classify prior sessions into stages using heuristics
   - Count priors per stage, compute time_since_first, max_prior_stage
   - This is a `group_by('src_ip').map_groups()` or rolling window in polars
5. Label mapping (binary):
   - Attack flows (label 1-3) + dirty → 1
   - Clean / norm (label 0,5) → 0
6. Output: `session_v1_training.parquet` (31 features)

---

## Step 4: Train Model

**On Test** (72 cores, A40 GPU)

Extend `train_xgb.py` with `SESSION_FEAT_COLS` (31 features).

- XGBoost binary, GPU hist, 5-fold GroupKFold by `src_ip`
- `max_depth=8, lr=0.05, subsample=0.8, colsample=0.8, nthread=72`
- `scale_pos_weight=5.0`, `early_stopping_rounds=75`
- Output: `session_xgb_v1.json`

---

## Step 5: Benchmark

- Score dirty sessions → detection rate (session-level + IP-level)
- Score clean sessions → FP rate
- Compare with per-flow evil_02_tcp
- Check 38.247.* sessions specifically
- **Check if history features (F6) actually improve over F1-F5 alone** (ablation: train with/without F6)

---

## Step 6: Deploy Batch Scorer on PV1

**File:** `DFI2/ml/score_sessions.py` — cron `2-57/5 * * * *`

1. Query `v_session_features` for sessions with new flows in last 10 min
2. Query flow timestamps for IAT computation
3. Compute F5 source context + F6 kill chain history from recent session_stats
4. Build 31-feature matrix, score with `session_xgb_v1.json` (`nthread=80`)
5. Write to `dfi.session_predictions`
6. High-confidence → insert into `dfi.watchlist_syncs` on AIO

**Does NOT replace per-flow scoring** — runs as second layer alongside CNN v3 + evil_02_tcp.

---

## Step 7: Verify

- [ ] `session_stats` populating via MV
- [ ] `v_session_features` correct feature values
- [ ] Training data shape/label balance sane
- [ ] Model F1 > 0.95 on 5-fold CV
- [ ] F6 history features improve over F1-F5 baseline (ablation test)
- [ ] Dirty detection > 90%, Clean FP < 5%
- [ ] Scorer cron running, `session_predictions` growing
- [ ] 38.247.137.9 flagged with correct kill chain stage
- [ ] Run `py_checker.py`

---

## Key Files

| File | Action | Pattern Source |
|------|--------|---------------|
| `DFI2/schema/11_session_stats.sql` | CREATE | `04_views.sql:1-27` |
| `DFI2/ml/export_sessions.py` | CREATE | `ml/export.py` |
| `DFI2/ml/prep_session_v1.py` | CREATE | `ml/prep_evil_01.py` |
| `DFI2/ml/train_xgb.py` | EXTEND | Add `SESSION_FEAT_COLS` |
| `DFI2/ml/score_sessions.py` | CREATE | `ml/score_dirty_evidence.py` |

---

## Architecture

```
AIO (capture)                    PV1 (scoring + analysis)
─────────────                    ────────────────────────
dfi-hunter2 ──flows──►           dfi.flows
  CNN v3 + evil_02_tcp             │
  (per-flow inline)                ├──► mv_session_stats
                                   │      │
push_to_pv1 (5min) ──────►        │      ▼
                                   │    session_stats (AggregatingMergeTree)
                                   │      │
                                   │    v_session_features (VIEW)
                                   │      │
                                   │    score_sessions.py (cron 5min)
                                   │      │ compute F5 source + F6 history
                                   │      │ score 31 features with XGBoost
                                   │      ▼
                                   │    session_predictions
                                   │      │
                                   │ ┌────┴────┐
                                   │ ▼         ▼
                                   │ watchlist  SOC dashboard
                                   │ (AIO)     (PV1 :8010)

Kill Chain Per-IP:
  time ──────────────────────────────────►
  │ RECON(1)    BRUTE(2)     EXPLOIT(3)   C2(4)
  │ thin SYNs → deep SSH  → interactive → persistent
  │ many dsts   one port    bidirectional  long-lived
  │
  └─► max_prior_stage increases over time
      prior_scan_count, prior_brute_count grow
      time_since_first_seen grows
      ═══► model sees full attack progression
```
