# GOD 1 + GOD 2 Pipeline

The Two Gods architecture is a closed-loop attacker detection and blocking system. GOD 1 is the instant catcher: it captures every packet on a SPAN port, scores each network flow with XGBoost in real time, and writes results to ClickHouse. GOD 2 is the patient hunter: it builds IP profiles from accumulated scores and honeypot evidence over hours and days, assigns verdict groups, decides capture/drop budgets, and sends verdicts back to GOD 1. They feed each other continuously.

## Architecture Overview

```
     SPAN traffic (VLAN 100=ingress, 101=egress)
                    |
              +-----v------+
              |   GOD 1    |  AF_PACKET or DPDK capture
              |  (ARM/AIO) |  XGB 5-class scoring per flow
              +-----+------+
                    |
           writes every 5s
                    v
         dfi.ip_score_log (ClickHouse on PV1)
                    |
     +--------------+---------------+
     |              |               |
     v              v               v
  GOD 2 Brain   Conversation   Service
  (god2_brain)    Brain         Labeler
     |              |               |
     v              v               v
  dfi.ip_profile  dfi.ip_reputation  dfi.ip_service_labels
     |
     | reads every 60s
     v
  GOD 1 (CAPTURE/DROP verdicts)
     |
     v
  Drop Filter (Python set + kernel ipset)
```

## The Two Gods

### GOD 1 -- Instant Catcher (`god1.py`)

GOD 1 is a stateless packet processor. It runs on a BlueField-2 DPU ARM chip (or an AIO server) and does the following:

1. **Captures SPAN traffic** via AF_PACKET raw socket on a mirror port. Packets arrive tagged with VLAN 100 (ingress: attacker to honeypot) or VLAN 101 (egress: honeypot to attacker). Non-SPAN packets are dropped.

2. **Tracks sessions** using 5-tuple flow keys (src_ip, dst_ip, src_port, dst_port, proto). Each session accumulates packet events until idle for 120 seconds (configurable via `GOD1_TIMEOUT`).

3. **Extracts 75 features** per session covering protocol metadata, volume statistics, timing (RTT, inter-arrival times, think times), packet size distributions, TCP behavior (SYN/FIN/RST/PSH patterns, connection state), payload entropy, and per-source behavioral stats.

4. **Scores with XGBoost** using a 5-class model (RECON, KNOCK, BRUTE, EXPLOIT, CLEAN). Scoring happens in batches when sessions expire, using a single DMatrix call for efficiency.

5. **Writes to ClickHouse** directly via a background thread (`CHBridge`). Scores go to `dfi.ip_score_log` every 5 seconds. Discrepancy capture records (full 75 features + CNN token arrays) go to `dfi.ip_capture_d2`.

6. **Reads verdicts** from `dfi.ip_profile` every 60 seconds. CAPTURE verdicts trigger D2 training data collection. DROP verdicts are synced to the `DropFilter`.

7. **Drops known attackers** at two layers: a Python set for O(1) in-process filtering, and a kernel ipset (`god1_drop`) for hardware-assisted filtering.

Key design constraint: GOD 1 never decides DROP on its own. Only GOD 2 can add IPs to the drop filter.

### GOD 2 -- Patient Hunter

GOD 2 runs on PV1 as a set of cron jobs that build attacker profiles and assign verdicts. It consists of three scripts that run in sequence:

#### `god2_brain.py` -- Profile Builder and Verdict Engine

Runs every 5 minutes at `:03`. Four phases:

**Phase 1: Build Profiles** -- Queries three ClickHouse tables:
- `dfi.ip_score_log` (2-hour window): per-IP flow counts, ingress ports, XGB class distribution, clean ratio
- `dfi.evidence_events` (30-day window): honeypot evidence -- auth failures, credential captures, suspicious commands, privilege escalation, lateral movement, SQL injection
- `dfi.ip_service_labels`: behavioral class per IP per service (from the service labeler)

Merges all three sources into a unified profile per IP.

**Phase 2: Assign Verdict Groups** -- Each IP gets a verdict_group string based on priority:
- **RB**: Known infrastructure IPs (DNS resolvers) -- never dropped
- **DIS_FN_***: False negatives (model says clean, evidence says attack) -- highest priority for retraining
- **DIS_FP_***: False positives (model says attack, no evidence, high clean ratio) -- never dropped
- **DIS_MISCLASS_***: Misclassifications (XGB class differs from evidence class)
- **Evidence-backed groups** (e.g., `SSH_BRUTE_EVD`, `MULTI_SSH_HTTP_EVD`): IPs with honeypot evidence, grouped by service and behavioral class
- **DIR groups** (e.g., `SSH_DIR`, `SCAN_DIR`): Dirty IPs with no evidence but attack signal from XGB
- **CLN**: Clean IPs (no evidence, >90% clean ratio)

**Phase 3: Decide Verdicts** -- Uses budget targets from `god2_budgets.json`:
- **CAPTURE**: Budget not full, IP not capped. GOD 1 will collect full training data for this IP.
- **DONE**: Per-IP cap reached (10K flows default). Stop capturing but keep scoring.
- **DROP**: Budget full for an attacker group. GOD 1 will drop all packets from this IP.
- **NONE**: Non-attacker groups (CLN, RB, DIS_FP) when budget is full -- just stops capturing, never drops.

**Phase 4: Write** -- Writes to `dfi.ip_profile` (ClickHouse) and confirmed attackers (evidence-backed only) to `watchlist.db` (SQLite) for MikroTik edge blocking. Edge blocking is completely independent of capture budgets.

#### `conversation_brain.py` -- IP Judge

Runs every 5 minutes at `:05`. VLAN-aware IP classification into behavioral archetypes:

- **Tier 0 CONFIRMED_INTRUDER**: Post-exploitation evidence (suspicious commands + privilege escalation)
- **Tier 1 Evidence-confirmed**: Auth success, credential capture, heavy brute force
- **Guard 1**: Clean ingress majority (>50% clean on VLAN 100, no evidence) prevents false dirty labels
- **Guard 2**: Infrastructure indicator (>50% egress) prevents blocking infra IPs
- **Tier 2 Model-based**: COMMODITY_BOT or COORDINATED_CAMPAIGN from XGB ratios (wide scan, multi-target, brute, blind scanner)
- **Tier 3 Clean/Research**: Zero attacks + zero evidence, or rDNS matches known research scanner domains

Writes archetypes and confidence to `dfi.ip_reputation`. Preserves allowlist and research scanner flags across writes.

#### `god2_verdict.py` -- Verdict Writer

Runs every 5 minutes at `:08`. Reads settled archetypes from `ip_reputation` and writes two types of verdicts:

- **DROP**: Commodity bots, coordinated campaigns, human operators (archetypes 1, 2, 3) with confidence >= 0.80
- **CAPTURE** for discrepancy training data:
  - D2-ATK: Confirmed intruders (archetype 6) -- model was wrong, truth is attack
  - D2-FP: Clean allowlist IPs with attack XGB scores -- model was wrong, truth is clean
  - D2-RB: Research scanners with attack scores -- model was wrong, truth is research benign

Writes to both ClickHouse (`ip_reputation` with `capture_depth=0` for DROP) and `watchlist.db` (only D2-ATK goes to watchlist, not D2-FP/D2-RB).

### `service_labeler.py` -- Per-Service Behavioral Classifier

Runs every 5 minutes at `:10`. Reads `dfi.evidence_events` (2-hour window), routes each event to one or more services based on event type, source program, and destination port, then classifies each (IP, service) pair into a behavioral stage:

| Service | Classes |
|---------|---------|
| SSH | SCAN, PROBE, BRUTE, CREDENTIAL, COMMAND, PERSIST |
| HTTP | SCAN, CRAWL, FUZZ, EXPLOIT, WEBSHELL, EXFIL |
| RDP | SCAN, PROBE, BRUTE, CREDENTIAL, COMMAND, PERSIST |
| SQL | SCAN, PROBE, BRUTE, INJECTION, EXFIL |
| SMB | SCAN, NEGOTIATE, ENUM, BRUTE, EXPLOIT, LATERAL |

Writes results to `dfi.ip_service_labels`, which GOD 2 Brain reads as input for verdict group assignment.

### `god1_listener.py` -- NATS Listener (Legacy/Alternative)

Subscribes to NATS subjects `dfi.xgb.score` and `dfi.capture.d2`, writes to `dfi.ip_score_log` and `dfi.ip_capture_d2` respectively. This was the original data path before GOD 1 gained direct ClickHouse writes. The D2 writer enriches records with service labels from `ip_service_labels` at write time.

## Key Files

| File | Purpose |
|------|---------|
| `god1.py` | Main GOD 1 process: AF_PACKET capture, session tracking, XGB scoring, CH writes, drop filter |
| `god2_brain.py` | GOD 2 brain: builds profiles from scores + evidence + service labels, assigns verdict groups, decides CAPTURE/DROP |
| `god2_verdict.py` | GOD 2 verdict writer: reads archetypes, writes DROP + D2 capture verdicts |
| `conversation_brain.py` | VLAN-aware IP judge: assigns behavioral archetypes (COMMODITY_BOT, CONFIRMED_INTRUDER, etc.) |
| `service_labeler.py` | Per-service behavioral classifier: routes evidence events to services, classifies attack stages |
| `god1_listener.py` | NATS listener: alternative data path from GOD 1 to ClickHouse (legacy) |
| `constants.py` | Shared constants: service map (15 services, 27+ ports), XGB class names, verdict values, behavioral class names |
| `god2_budgets.json` | Per-group capture budget targets (e.g., SSH_BRUTE_EVD: 500K flows, CLN: 0) |
| `god1_test.py` | Earlier proof-of-concept version of GOD 1 (NATS-based instead of direct CH writes) |
| `setup_god1_service.sh` | systemd unit installer for GOD 1 |

## ClickHouse Tables

| Table | Written By | Read By | Purpose |
|-------|-----------|---------|---------|
| `dfi.ip_score_log` | GOD 1 | GOD 2 Brain, Conversation Brain | Per-flow XGB scores with VLAN, timestamps, source stats |
| `dfi.ip_profile` | GOD 2 Brain | GOD 1 | Per-IP verdict (CAPTURE/DROP/DONE/NONE) with verdict_group and expiry |
| `dfi.ip_reputation` | Conversation Brain, GOD 2 Verdict | GOD 2 Verdict | Per-IP archetype, state, confidence, evidence flags |
| `dfi.ip_service_labels` | Service Labeler | GOD 2 Brain, GOD 1 Listener | Per-IP per-service behavioral class |
| `dfi.ip_capture_d2` | GOD 1 | GOD 2 Brain | Discrepancy capture training data (75 XGB features + CNN token arrays) |
| `dfi.evidence_events` | (external honeypots) | GOD 2 Brain, Conversation Brain, Service Labeler | Host-side evidence from honeypots |

## Cron Schedule (PV1)

| Offset | Script | Purpose |
|--------|--------|---------|
| `:03` every 5 min | `god2_brain.py` | Build profiles, assign groups, decide verdicts |
| `:05` every 5 min | `conversation_brain.py` | Judge IPs into archetypes |
| `:08` every 5 min | `god2_verdict.py` | Write DROP + CAPTURE verdicts |
| `:10` every 5 min | `service_labeler.py` | Classify per-service behavioral stages |

GOD 1 runs continuously as a systemd service (`dfi-god1`).

## Configuration

GOD 1 is configured via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `GOD1_IFACE` | `ens192` | Network interface for SPAN capture |
| `GOD1_MODEL` | `/opt/dfi2/ml/models/xgb_5class_v2.json` | XGBoost model path |
| `GOD1_TIMEOUT` | `120` | Session idle timeout in seconds |
| `GOD1_CH_HOST` | `192.168.0.100` | PV1 ClickHouse host for direct reads/writes |
| `GOD1_MAX_SESSIONS` | `500000` | Maximum concurrent tracked sessions |
| `GOD1_DROP_TTL` | `604800` | Drop entry TTL in seconds (7 days) |
| `GOD1_D2_CAP` | `5000000` | Per-type cap for D2 capture |
| `GOD1_CAPTURE` | `1` | Set to 0 to disable D2 capture |
| `GOD1_IPTABLE` | `/opt/dfi2/god1_iptable.json` | IP table persistence path |
| `GOD1_IPTABLE_TTL` | `2592000` | IP table entry TTL in seconds (30 days) |

GOD 2 Brain reads its budget configuration from `GOD2_BUDGETS` (default: `/opt/dfi2/god2_budgets.json`) and respects the per-IP capture cap `GOD2_IP_CAP` (default: 10,000).

## XGB 5-Class Model

The pipeline uses an XGBoost model that classifies flows into five classes:

| Class | ID | Description |
|-------|----|-------------|
| RECON | 0 | Port scanning, service enumeration |
| KNOCK | 1 | Connection attempts, banner grabs |
| BRUTE | 2 | Brute force authentication |
| EXPLOIT | 3 | Exploitation attempts |
| CLEAN | 4 | Legitimate traffic |

The model uses 50-75 features depending on version, organized into 8 feature groups: Protocol (F1), Volume (F2), Timing (F3), Packet Size Shape (F4), TCP Behavior (F5), Payload Content (F6), Protocol Fingerprints (F7), and Source Behavior (F8).

## Data Flow Summary

1. External traffic hits the SPAN port (VLAN-tagged ingress/egress)
2. GOD 1 captures packets, builds sessions, extracts features, scores with XGB
3. Scores flow to `dfi.ip_score_log` on PV1 ClickHouse
4. Every 5 minutes, GOD 2 Brain reads scores + evidence + service labels, builds profiles, assigns verdict groups, decides CAPTURE/DROP based on budgets
5. Verdicts are written to `dfi.ip_profile`
6. GOD 1 reads verdicts every 60 seconds, updates its drop filter and capture set
7. Confirmed attackers (evidence-backed) are written to `watchlist.db` for MikroTik edge blocking (independent of capture budgets)
8. D2 capture records (training data with full features) flow back to `dfi.ip_capture_d2` for model retraining
