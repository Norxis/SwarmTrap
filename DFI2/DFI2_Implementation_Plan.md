# DFI2 — Full Implementation Plan

## Context

DFI2 replaces the SQLite-based DFI v1 with a ClickHouse-backed analytical platform. Two capture nodes (PV1 + AIO) run the same Hunter code. PV1 is the master — captures its own 10-VM honeypot farm on v172, pulls AIO's SPAN data, runs analytics/ML/dashboard. AIO is a satellite — captures SPAN wire traffic, buffers 48 hours, gets pulled by PV1.

## Architecture

```
PV1 (192.168.0.100, 472GB RAM)              AIO (172.16.3.113, 16GB RAM)
──────────────────────────────              ─────────────────────────────
Hunter on v172 bridge                       Hunter on ens192 (SPAN)
  → local ClickHouse (90-day TTL)             → local ClickHouse (48-hour TTL)
10 honeypot VMs → syslog → evidence.db      Winlure on ens160 (216.126.0.206)
  → labeler daemon → CH evidence_events       → CH evidence_events (local)

PUSHES attacker IPs ──────────────────────► AIO SQLite watchlist
PULLS CH data ◄────────────────────────────  AIO ClickHouse

Dashboard v2, classifier, ML exports
```

## Project Structure

```
~/DFI2/
├── hunter/              # Hunter rewrite (capture + features + CH writer)
│   ├── afpacket.py      # KEEP from Hunter-v7 (verbatim)
│   ├── hunter.py        # Main entry point + session tracker
│   ├── features.py      # 75 XGBoost feature extraction
│   ├── tokenizer.py     # 5-channel CNN packet tokenizer
│   ├── fingerprints.py  # JA3, HASSH, HTTP, DNS parsing
│   ├── writer.py        # DFIWriter (ClickHouse batch inserter)
│   ├── watchlist.py     # SQLite watchlist (capture depth decisions)
│   ├── depth.py         # D0-D3 capture depth logic
│   ├── evidence.py      # Winlure feedback → CH evidence_events
│   └── config.py        # Environment variable config
├── schema/              # ClickHouse DDL
│   ├── 01_tables.sql    # Core tables (flows, packets, fingerprints, labels)
│   ├── 02_behavioral.sql # Behavioral tables (evidence, fanout, predictions, etc.)
│   ├── 03_buffers.sql   # Buffer tables
│   ├── 04_views.sql     # Materialized views + export views
│   └── 05_watchlist.sql # SQLite watchlist schema
├── sync/                # PV1 ↔ AIO data movement
│   ├── pull_aio.py      # PV1 pulls CH data from AIO (cron)
│   ├── push_watchlist.py # PV1 pushes attacker IPs to AIO SQLite (cron)
│   └── config.py
├── labeler/             # evidence.db → CH labels
│   ├── labeler.py       # Correlation daemon (±120s window)
│   └── evidence_ingest.py # evidence.db → CH evidence_events
├── classifier/          # Periodic group assignment
│   ├── classifier.py    # Behavior group hierarchy
│   └── watchlist_push.py # Classifier → SQLite watchlist
├── dashboard/           # Streamlit v2
│   └── dashboard.py     # ClickHouse-backed UI
├── ml/                  # Training pipelines
│   ├── train_xgb.py     # XGBoost (75 features → 5 classes)
│   ├── train_cnn.py     # CNN (5ch × 128pos + 42 static → 5 classes)
│   ├── score.py         # Model predictions → CH
│   └── export.py        # CH → CSV export
├── deploy/              # Deployment scripts (Paramiko)
│   ├── deploy_ch.py     # Install ClickHouse on target host
│   ├── deploy_hunter.py # Deploy Hunter to target host
│   └── deploy_schema.py # Create CH tables on target host
└── CLAUDE.md            # Project instructions
```

## Spec Documents (ai-shared/DFI2/)

| Spec | What it defines |
|------|-----------------|
| DFI2_Behavioral_Architecture_Spec.md | Dual-store design, capture depth D0-D3, behavior groups, 3-model pipeline, movement tracking |
| DFI2_Dataset_DB_Spec.md | 11 ClickHouse tables, buffer tables, materialized views, SQLite watchlist, export views, DFIWriter code |
| DFI2_XGB_v1_Spec.md | 82-column flat dataset — 75 PCAP features + 5-class kill-chain labels |
| DFI2_CNN_v1_Spec.md | 689-column dataset — 5-channel × 128-position sequences + 42 static scalars, PyTorch model |

## Key Files to Reuse from Hunter-v7

| File | Action | Notes |
|------|--------|-------|
| `Hunter-v7/afpacket.py` | Copy verbatim | Solid TPACKET_V3, don't touch |
| `Hunter-v7/hunter.py` | Reference only | SessionTracker pattern, HoneypotFilter, WatchlistManager — adapt concepts |
| `Hunter-v7/bridge.py` | Not needed | Winlure stays separate, unchanged |

---

## Phase 1: ClickHouse Foundation

**Goal:** ClickHouse running on both hosts, full schema created, pull mechanism working with test data.

### 1.1 Install ClickHouse on PV1
- Debian Bookworm packages from clickhouse.com
- Config: `max_server_memory_usage_to_ram_ratio=0.6` (use up to ~280GB)
- `merge_tree.max_bytes_to_merge_at_max_space_in_pool=10737418240`
- Enable on port 9000 (native) + 8123 (HTTP)
- `systemctl enable --now clickhouse-server`

### 1.2 Install ClickHouse on AIO
- Same packages, lighter config
- `max_server_memory_usage_to_ram_ratio=0.25` (~4GB max — leave room for Hunter + Winlure)
- Port 9000 (native)
- `systemctl enable --now clickhouse-server`

### 1.3 Create Schema (both hosts)
- `CREATE DATABASE dfi`
- All 11 tables from DFI2_Dataset_DB_Spec.md
- AIO: 48-hour TTL on all tables (`TTL first_ts + INTERVAL 2 DAY`)
- PV1: 90-day TTL on core tables, 180-day on behavioral, 365-day on analyst_actions
- Buffer tables on both (high-throughput ingest)
- Materialized views on PV1 only (source_stats, fingerprint_freq, fanout_stats)
- Export views on PV1 only (v_xgb, v_cnn)
- SQLite watchlist.db on both hosts

### 1.4 Pull Mechanism (PV1 ← AIO)
- Script: `~/DFI2/sync/pull_aio.py`
- Runs on PV1 via cron every 5 minutes
- Uses ClickHouse `remote()` function:
  ```sql
  INSERT INTO dfi.flows
  SELECT * FROM remote('172.16.3.113:9000', dfi, flows)
  WHERE first_ts > {last_pull_ts}
  ```
- Watermark tracking: store last-pulled timestamp in local file or CH table
- Pull tables: flows, packets, fingerprints, fanout_hops, evidence_events, model_predictions
- Skip: labels, group_assignments, depth_changes, analyst_actions (PV1-only)

### 1.5 Push Mechanism (PV1 → AIO watchlist)
- Script: `~/DFI2/sync/push_watchlist.py`
- Runs on PV1 via cron every 10 minutes
- Reads PV1 CH: latest group_assignments + depth_changes per attacker IP
- SSH/Paramiko to AIO, writes SQLite watchlist.db
- Schema: src_ip, capture_depth, priority, group_id, sub_group_id, top_port, reason, source, expires_at

### 1.6 Verification
- `clickhouse-client --query "SELECT 1"` on both hosts
- Insert test rows into flows_buffer, verify they appear in flows
- Pull test: insert on AIO, run pull, verify on PV1
- Push test: write watchlist row on PV1, push to AIO, verify SQLite

**Complexity:** Medium
**Depends on:** Nothing (foundation)
**Deploy script:** `~/DFI2/deploy/deploy_ch.py` (Paramiko to target, install + schema)

---

## Phase 2: Hunter Core — Get Data Flowing

**Goal:** Hunter writing real SPAN data to local ClickHouse on AIO. Even with partial features — prove the pipeline works end-to-end.

### 2.1 Project Setup
- `mkdir -p ~/DFI2/hunter`
- Copy `afpacket.py` verbatim from Hunter-v7
- New `config.py` — all env vars (HUNTER_IFACE, CAPTURE_MODE, CH_HOST, etc.)

### 2.2 Minimal SessionProfile
- Keep existing fields: 5-tuple, timing, volume (pkts/bytes fwd/rev)
- Add: capture_depth (from watchlist lookup), vlan_id
- Keep: event packet list (up to 128), entropy calculation
- Keep existing size_dir and tcp_flags tokenization

### 2.3 DFIWriter (writer.py)
- Adapted from DFI2_Dataset_DB_Spec.md DFIWriter class
- `Client(CH_HOST)` — localhost on AIO, localhost on PV1
- Buffers: flow_buf, pkt_buf, fp_buf, fanout_buf, evidence_buf, pred_buf
- Flush: every 1 second or 50K rows
- Thread-safe (lock per buffer)
- Writes to buffer tables (*_buffer)

### 2.4 Minimal Hunter Integration
- Worker ingest loop: same AF_PACKET → SessionTracker pattern
- On session flush: extract flow dict with available features → DFIWriter.insert_flow()
- Flow dict maps to `flows` table columns (fill what we have, NULL the rest)
- Packet events → `packets` table (size_dir_token + flag_token, other channels = 0 for now)
- Fanout hops → `fanout_hops` table (already have this data)
- Skip fingerprints for now (Phase 4)

### 2.5 HoneypotFilter + WatchlistManager
- Port from Hunter-v7 with minimal changes
- WatchlistManager reads SQLite watchlist.db (pushed by PV1)
- HoneypotFilter: 2-stage detection (same logic)

### 2.6 Deployment + Test
- Deploy to AIO via Paramiko
- Start dfi-hunter with new code
- Verify: `clickhouse-client --query "SELECT count() FROM dfi.flows"` — rows appearing
- Verify: PV1 pull picks up AIO data
- Verify: real attacker traffic flowing through the full pipeline

**Complexity:** Large (biggest phase)
**Depends on:** Phase 1
**Key risk:** Getting the ingest loop right without breaking capture performance

---

## Phase 3: Full Feature Extraction

**Goal:** All 75 XGBoost scalar features computed per flow.

### 3.1 features.py — Feature Groups

**F1. Protocol (3):** dst_port, ip_proto, app_proto
- app_proto: port-based heuristic (existing) + extend with DPI where possible

**F2. Volume (8):** pkts_fwd/rev, bytes_fwd/rev, bytes_per_pkt_fwd/rev, pkt_ratio, byte_ratio
- Mostly exists, add ratio computations

**F3. Timing (10):** duration_ms, rtt_ms, iat_fwd_mean/std, think_time_mean/std, iat_to_rtt, pps, bps, payload_rtt_ratio
- NEW: RTT estimation from SYN-ACK timing or first reverse packet
- NEW: Per-packet IAT tracking (store timestamps in event list)
- NEW: think_time = iat - rtt (behavioral pace, geography-independent)
- NEW: iat_to_rtt ratio (key normalized feature)

**F4. Size shape (14):** n_events, fwd_size_mean/std/min/max, rev_size_mean/std/max, hist_tiny/small/medium/large/full, frac_full
- NEW: Size histogram bins, running min/max/mean/std

**F5. TCP behavior (11):** syn/fin/rst/psh/ack_only counts, conn_state, rst_frac, syn_to_data, psh_burst_max, retransmit_est, window_size_init
- EXTEND: conn_state classification (8 categories from spec)
- NEW: rst_frac (position of first RST), psh_burst_max, retransmit_est, window_size_init

**F6. Payload content (8):** entropy_first, entropy_fwd/rev_mean, printable_frac, null_frac, byte_std, high_entropy_frac, payload_len_first
- EXTEND: already have entropy_first, add full stats across all payloads

### 3.2 tokenizer.py — All 5 CNN Channels

Already have: Ch1 (size_dir), Ch2 (tcp_flags)
Add:
- **Ch3: iat_log_ms** — absolute IAT in log-binned ms (9 bins)
- **Ch4: iat_rtt_bin** — RTT-normalized IAT (10 bins)
- **Ch5: entropy_bin** — per-packet payload entropy (7 bins)

Requires per-packet timestamp tracking (already in event list, just need IAT computation).

### 3.3 Update DFIWriter
- Flow dicts now have all 75 features populated
- Packet rows now have all 5 CNN token channels

### 3.4 Verification
- Export sample flows, verify all 75 columns populated
- Compare feature distributions against spec expectations
- Validate CNN token ranges match spec vocab sizes

**Complexity:** Large
**Depends on:** Phase 2

---

## Phase 4: Fingerprint Extraction

**Goal:** Protocol-specific handshake parsing → fingerprints table.

### 4.1 fingerprints.py

**TLS (from ClientHello):**
- Parse raw payload for TLS ClientHello (content_type=0x16, handshake_type=0x01)
- Extract: cipher suites list, extensions list, SNI, supported versions
- Compute JA3 hash (MD5 of TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
- Store: ja3_hash, tls_version, tls_cipher_count, tls_ext_count, tls_has_sni

**SSH (from banner + KEXINIT):**
- Parse SSH-2.0 banner string
- Parse KEXINIT packet (msg_type=20) for kex algorithms
- Compute HASSH hash (MD5 of kex_algorithms,encryption_algorithms,mac_algorithms,compression_algorithms)
- Store: hassh_hash, ssh_kex_count

**HTTP (from request):**
- Parse first line: method, URI, version
- Count headers, extract User-Agent, check for body
- Store: http_method, http_uri_len, http_header_count, http_ua_hash, http_has_body, http_status

**DNS (from query):**
- Parse DNS header + first question
- Store: dns_qtype, dns_qname_len

### 4.2 Integration
- Call fingerprint extraction during session flush (when first payload available)
- Write to fingerprints_buffer via DFIWriter
- Frequency encoding (ja3_freq, hassh_freq, http_ua_freq) computed from CH materialized views on PV1

### 4.3 Verification
- SSH to honeypot → verify HASSH extraction
- curl honeypot → verify HTTP + JA3 extraction
- nslookup → verify DNS extraction

**Complexity:** Large (protocol parsing is fiddly)
**Depends on:** Phase 2

---

## Phase 5: Capture Depth System

**Goal:** D0-D3 filtering in Hunter, driven by SQLite watchlist.

### 5.1 depth.py — Capture Depth Logic

**D0 (DROP):** Skip entirely, zero writes. Check dst_port vs top_port for re-promotion.
**D1 (FLOW METADATA):** flows + fingerprints + fanout_hops. Default for unclassified.
**D2 (FLOW + SEQUENCE):** D1 + packets table (128 event packets, all CNN channels).
**D3 (FULL CAPTURE):** D2 + payload_bytes table.

### 5.2 watchlist.py — SQLite Hot Cache
- Schema from DFI2_Dataset_DB_Spec.md (src_ip, capture_depth, priority, group_id, top_port, expires_at)
- Lookup on every flow: `SELECT capture_depth FROM watchlist WHERE src_ip = ?`
- Default: D1 if not in watchlist
- Expiry check: skip expired rows, treat as D1
- Refresh: re-read every 30s (thread-safe)

### 5.3 Hunter Integration
- Ingest: after session key lookup, check watchlist for capture depth
- Flush: DFIWriter.insert_flow() receives depth parameter
  - D0: skip entirely (but check dst_port for re-promotion)
  - D1: write flow + fingerprint + fanout_hop (no packets)
  - D2: write everything including packets
  - D3: write everything including payload_bytes
- Depth change events → depth_changes table in CH

### 5.4 Verification
- Insert test watchlist entries (D0, D2, D3)
- Verify D0 IPs produce zero CH rows
- Verify D2 IPs have packets rows
- Verify D1 (default) IPs have flows but no packets

**Complexity:** Medium
**Depends on:** Phase 2

---

## Phase 6: Evidence Pipeline

**Goal:** Evidence from both AIO (Winlure) and PV1 (syslog) into ClickHouse.

### 6.1 AIO Evidence (evidence.py in hunter/)
- Read Winlure feedback socket (/run/dfi/feedback.sock) — NDJSON messages
- Parse credential events: src_ip, dst_port, proto, username, event_type
- Map to evidence_events schema: event_id (UUID), ts, src_ip, target_ip, event_type, event_detail, evidence_mask_bit, source_program
- Write to local CH via DFIWriter.insert_evidence()

### 6.2 PV1 Evidence (labeler/evidence_ingest.py)
- Daemon that tails evidence.db (SQLite) for new log entries
- Parses Windows EventIDs (4625, 4624, 4648, 4672, etc.) and Linux sshd patterns
- Maps to evidence_events schema
- Writes to PV1 CH evidence_events table
- Runs continuously, checks for new rows every 10s

### 6.3 Verification
- Trigger SSH brute-force against Winlure on AIO → verify evidence_events in AIO CH
- Check PV1 evidence_events populated from syslog pipeline
- Verify PV1 pull picks up AIO evidence_events

**Complexity:** Medium
**Depends on:** Phase 1 (CH running), Phase 2 (Hunter on AIO for feedback socket)

---

## Phase 7: Labeler Daemon

**Goal:** Correlate flows with evidence events → labels table.

### 7.1 labeler/labeler.py
- Runs on PV1 (reads merged evidence from all sources)
- Every 5 minutes: scan recent flows without labels
- For each flow: query evidence_events within ±120s of flow's first_ts, matching src_ip
- Apply label hierarchy:
  - 0=RECON: no evidence events
  - 1=KNOCK: connection reached service, zero auth attempts
  - 2=BRUTEFORCE: ≥3 auth failures
  - 3=EXPLOIT: suspicious command detected
  - 4=COMPROMISE: auth success + post-exploitation
- Compute label_confidence from evidence agreement
- Compute evidence_mask bitmask
- Write to labels table (ReplacingMergeTree — latest label wins)

### 7.2 Verification
- Check labels populated for flows with known attacker IPs
- Verify label distribution makes sense (mostly RECON/BRUTEFORCE)
- Verify label_confidence > 0 when multiple evidence signals agree

**Complexity:** Medium
**Depends on:** Phase 6 (evidence in CH)

---

## Phase 8: Classifier + Dashboard

**Goal:** Periodic behavior classification, watchlist push, Streamlit v2.

### 8.1 classifier/classifier.py
- Runs on PV1 every 5-10 minutes
- Queries CH for per-attacker aggregates (rolling windows: 15min, 1h, 6h)
- Assigns behavior groups from hierarchy:
  - RECON (PORT_SCAN, SERVICE_SWEEP, BANNER_GRAB)
  - CREDENTIAL_ATTACK (SSH_BRUTE, MYSQL_BRUTE, RDP_BRUTE, etc.)
  - EXPLOIT_DELIVERY (WEB_EXPLOIT, SERVICE_EXPLOIT, PHASED_ATTACK)
  - INFRASTRUCTURE_ABUSE (SIP_FRAUD, DNS_TUNNEL, AMPLIFICATION)
  - CAMPAIGN_PROGRESSION (HORIZONTAL_SWEEP, VERTICAL_ESCALATION, PIVOT_CHAIN, RETURN_AND_DEEPEN)
  - UNCLASSIFIED (LOW_AND_SLOW, ONE_SHOT_NOISE, EMERGING)
- Writes group_assignments to CH
- Computes capture depth promotions/demotions → depth_changes to CH
- Pushes updated watchlist to SQLite on PV1 and AIO (via push_watchlist.py)

### 8.2 dashboard/dashboard.py
- Streamlit, reads ClickHouse (not SQLite)
- Single IP lookup with full profile (movement, groups, trajectory)
- Analyst actions: promote to D3, push to block, watch 72h → CH analyst_actions + SQLite watchlist
- Top attackers view (from materialized views — instant)
- Ingest rate monitoring
- Label distribution
- Storage stats

### 8.3 Verification
- Classifier produces group_assignments in CH
- Watchlist pushed to AIO SQLite
- Dashboard loads, shows real attacker profiles
- Analyst push-to-watchlist works end-to-end

**Complexity:** Large
**Depends on:** Phase 7 (labels needed for some classifier features)

---

## Phase 9: ML Pipelines

**Goal:** Train XGBoost + CNN on real data, feed predictions back to CH.

### 9.1 ml/export.py
- Export from CH v_xgb view → CSV (82 columns)
- Export from CH v_cnn view → CSV (689 columns)
- Balanced sampling, high-confidence filtering options

### 9.2 ml/train_xgb.py
- Load CSV, GroupKFold by actor_id
- XGBoost multi:softprob, 5 classes
- Confidence-weighted loss
- Save model + metrics

### 9.3 ml/train_cnn.py
- PyTorch DFI_CNN model from spec
- 5-channel embedding → Conv1D → concat static → Dense → softmax
- Class-weighted CrossEntropyLoss
- Save model + metrics

### 9.4 ml/score.py
- Load trained model, score unscored flows in CH
- Write predictions to model_predictions table

### 9.5 Verification
- Export produces valid CSVs with correct column counts
- XGBoost trains without errors, confusion matrix reasonable
- CNN trains, loss decreases
- Predictions appear in CH model_predictions table

**Complexity:** Medium
**Depends on:** Phase 7 (need labels for training)

---

## Execution Order

```
Phase 1: ClickHouse Foundation          ← START HERE
    ↓
Phase 2: Hunter Core (get data flowing) ← First milestone
    ↓
    ├── Phase 3: Full Features          (can parallel with 4, 5)
    ├── Phase 4: Fingerprints           (can parallel with 3, 5)
    └── Phase 5: Capture Depth          (can parallel with 3, 4)
    ↓
Phase 6: Evidence Pipeline              ← After Hunter works
    ↓
Phase 7: Labeler                        ← After evidence flows
    ↓
Phase 8: Classifier + Dashboard         ← After labels exist
    ↓
Phase 9: ML Pipelines                   ← After enough labeled data
```

## Verification — End-to-End Smoke Test

After Phase 2 completes:
1. AIO Hunter captures SPAN traffic → local CH
2. PV1 pulls from AIO → PV1 CH
3. PV1 Hunter captures v172 traffic → PV1 CH
4. `SELECT count() FROM dfi.flows` growing on both hosts
5. `SELECT count() FROM dfi.fanout_hops` growing
6. Dashboard shows ingest rate and top IPs

After Phase 7 completes:
7. `SELECT label, count() FROM dfi.labels FINAL GROUP BY label` shows distribution
8. Evidence events populated from both AIO and PV1 sources
9. Attacker IP lookup shows flow timeline + evidence correlation

After Phase 9 completes:
10. XGBoost and CNN models trained on real data
11. Model predictions in CH, visible in dashboard
12. Classifier assigns behavior groups, pushes watchlist
