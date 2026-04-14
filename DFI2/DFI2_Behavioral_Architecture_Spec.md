# DFI Behavioral Architecture — Data Collection & Attacker Profiling

## Design Principles

1. **ClickHouse is the ledger.** Every event is append-only, timestamped, and referenced. No updates in place. No aggregates stored as source data. Everything traceable.
2. **SQLite is the hot cache.** Hunter needs sub-millisecond point lookups at line rate. SQLite holds the disposable working set — watchlist, current scores, capture depth. Lose it, rebuild from ClickHouse in minutes.
3. **Store atoms, compute patterns.** Raw events go into ClickHouse. Groups, campaigns, trajectories, and aggregates are queries or materialized views — never the source of truth.

---

## System Architecture

```
SPAN packets → Hunter (reads SQLite for instant decisions)
                  │
                  ├─► writes flows/packets/fingerprints → ClickHouse (D1/D2/D3)
                  ├─► writes evidence events            → ClickHouse
                  ├─► writes fanout hops                → ClickHouse
                  └─► writes fast-path state             → SQLite (watchlist.db)

ClickHouse (periodic jobs, every 5-10 min):
    ├─► Recompute attacker groups, fanout shapes, campaign clusters
    ├─► Recompute capture depth promotions/demotions
    └─► Push updated state → SQLite watchlist (disposable cache)

Streamlit Dashboard:
    ├─► Reads ClickHouse for attacker profiles, movement graphs, group history
    └─► Analyst clicks "push to Hunter" → writes to SQLite watchlist
                                        → logs event to ClickHouse
```

### Dual-Store Roles

| Concern | ClickHouse | SQLite |
|---|---|---|
| Role | Analytical store + source of truth | Hot cache for fast path |
| Data lifetime | 90-day TTL (or longer for attacker state) | Disposable, rebuildable |
| Query pattern | Analytical joins, aggregates, exports | Single-row key-value lookups |
| Write pattern | Batch insert (100K+ rows/sec) | Single-row upsert |
| Read latency | Milliseconds–seconds (columnar scan) | Sub-millisecond (B-tree point lookup) |
| Who writes | Hunter, classifier jobs, analyst actions | Classifier jobs, analyst actions |
| Who reads | Streamlit, export scripts, classifier jobs | Hunter (per-packet/per-flow decisions) |

---

## Capture Depth Levels

Not all traffic deserves the same investment. Capture depth controls how much work Hunter does per flow and how much data reaches ClickHouse.

### Level Definitions

| Level | What gets stored | Cost | Use for |
|---|---|---|---|
| **D0 — DROP** | Nothing. Hunter skips entirely. | Zero | Known noise, confirmed repetitive scanners, SIP sweepers after classification. Not stored in ClickHouse at all. |
| **D1 — FLOW METADATA** | `flows` + `fingerprints` tables. Full flow-level features, no per-packet data. | Moderate — flow reassembly + feature extraction | Default for unclassified IPs. Enough for XGBoost classification and behavioral grouping. |
| **D2 — FLOW + SEQUENCE** | D1 + `packets` table (128 event packets, all CNN channels). | ~30× more rows than D1 per flow | IPs that hit interesting thresholds — repeated auth, moderate depth, promoted to a behavior group worth studying. Feeds both XGBoost and CNN. |
| **D3 — FULL CAPTURE** | D2 + payload bytes (first N bytes per packet or full PCAP segment). | Highest — actual payload storage | CAMPAIGN_PROGRESSION targets, VERTICAL_ESCALATION, RETURN_AND_DEEPEN, analyst-pushed IPs. Evidence-grade reconstruction. |

### Resource Impact Estimates (at 100K flows/sec)

| Depth | Est. % of traffic | Storage cost | CPU cost |
|---|---|---|---|
| D0 | ~40% (known noise) | zero | zero |
| D1 | ~45% (default bulk) | flows + fingerprints only | flow reassembly |
| D2 | ~12% (interesting) | + packets table | + per-packet tokenization |
| D3 | ~3% (high value) | + payload storage | + full inspection |

Moving known noise to D0 cuts `packets` table writes nearly in half.

### Promotion and Demotion Rules

**Upward triggers:**

| Transition | Trigger |
|---|---|
| D0 → D1 | D0 IP seen on a port not in its last-known profile (behavior change) |
| D1 → D2 | IP classified into a real behavior group with confidence above threshold |
| D2 → D3 | IP shows movement across targets or services (CAMPAIGN_PROGRESSION), per-flow model predicts EXPLOIT/COMPROMISE, or analyst push |
| Any → D3 | Analyst click in Streamlit |

**Downward triggers:**

| Transition | Trigger |
|---|---|
| D3 → D2 | TTL expires, no new interesting activity in window |
| D2 → D1 | IP reclassified to low-priority group, no return behavior |
| D1 → D0 | Confirmed repetitive noise, same behavior seen N times with no escalation |

**Rule: Never demote while active.** If the IP is still sending flows, hold current depth until a quiet gap. Do not downgrade mid-campaign.

### SQLite Watchlist Schema (Hot Cache)

```
src_ip          capture_depth    reason              expires
────────────────────────────────────────────────────────────
162.217.98.180  D0               G1 repeat sweeper   24h
85.11.167.12    D3               analyst push        7d
103.21.55.206   D3               pivot chain detect  48h
34.158.168.101  D2               G3 high confidence  72h
(default)       D1               unclassified        —
```

Hunter checks this on every flow. One lookup, one integer, instant decision.

### D0 Re-promotion

When an IP is at D0, Hunter still sees its packets — it just doesn't process them. Detection of behavior change is cheap: compare incoming `dst_port` against the last-known `top_port` in the SQLite skip list. Different port → re-promote to D1 immediately.

### Depth Change Events (ClickHouse)

Every depth change is logged as an event:

```
attacker_ip, old_depth, new_depth, trigger_reason, timestamp, triggered_by (classifier | analyst | rule)
```

This provides operational audit and becomes training data for model 3 — promotion history is itself a feature.

---

## Behavior Group Hierarchy

Two-level classification: **Intent** (what they're trying to do) drives response policy. **Method** (how they're doing it) drives honeypot optimization and telemetry collection.

### Full Hierarchy

```
RECON
  ├── PORT_SCAN          Multi-port TCP, low depth per port
  ├── SERVICE_SWEEP      Single port, wide peer spread
  └── BANNER_GRAB        Connect + read response, minimal interaction

CREDENTIAL_ATTACK
  ├── SSH_BRUTE          Port 22, repeated short sessions, auth failures
  ├── MYSQL_BRUTE        Port 3306, repeated auth attempts
  ├── RDP_BRUTE          Port 3389, Windows VLAN targeting
  ├── HTTP_AUTH_SPRAY    Login endpoints, POST-heavy, few paths
  └── CROSS_SERVICE_ROT  Same IP rotates across multiple auth services

EXPLOIT_DELIVERY
  ├── WEB_EXPLOIT        POST with payload, unusual entropy, specific paths
  ├── SERVICE_EXPLOIT    Known port, anomalous packet pattern
  └── PHASED_ATTACK      Recon → credential → exploit progression (model 3)

INFRASTRUCTURE_ABUSE
  ├── SIP_FRAUD          SIP registration + INVITE patterns (port 5060)
  ├── DNS_TUNNEL         Long qnames, high query volume, unusual qtypes
  └── AMPLIFICATION      Small request, expects large response

CAMPAIGN_PROGRESSION
  ├── HORIZONTAL_SWEEP   Same port, different targets, sequential timing
  ├── VERTICAL_ESCALATION Same target, different ports/services, increasing depth
  ├── PIVOT_CHAIN        Target A:X → Target B:Y → Target C:Z (changing both)
  └── RETURN_AND_DEEPEN  Hit lightly, left, came back with deeper interaction

UNCLASSIFIED
  ├── LOW_AND_SLOW       Few sessions, spread over days, moderate depth — watch closely
  ├── ONE_SHOT_NOISE     Single session, low packets, never returns — deprioritize
  └── EMERGING           Shows consistency but doesn't fit a group yet — candidate for promotion
```

### Priority Response Model

| Priority | Groups | Response |
|---|---|---|
| **P1** | CREDENTIAL_ATTACK (all), EXPLOIT_DELIVERY (all), CAMPAIGN_PROGRESSION (PIVOT_CHAIN, RETURN_AND_DEEPEN) | Immediate block candidate or D3 capture. Fastest sync to DFI/Suricata. |
| **P2** | INFRASTRUCTURE_ABUSE (all), CAMPAIGN_PROGRESSION (HORIZONTAL_SWEEP, VERTICAL_ESCALATION) | Short-TTL watch/block (24-72h). Capture at D2 minimum. |
| **P3** | RECON (all), UNCLASSIFIED (all) | Monitor. Default D1. Promote on recurrence or escalation. |

### Group Assignment as Events

Group assignments are **not columns on the attacker row**. They are timestamped events in ClickHouse:

```
attacker_ip, group_id, sub_group_id, confidence, window_start, window_end, timestamp
```

Same IP can change groups over time. The full trajectory of group assignments is preserved. "Show me every IP that transitioned from RECON to CREDENTIAL_ATTACK in the last week" is a simple query.

### Key Indicators Per Subgroup

| Subgroup | Distinguishing features |
|---|---|
| PORT_SCAN | `ports > 20`, `avg_pkts < 8`, TCP-heavy |
| SERVICE_SWEEP | `peers > 1000`, `ports <= 3`, often UDP |
| BANNER_GRAB | `ports <= 5`, `avg_pkts 4-8`, connects + reads, TCP |
| SSH_BRUTE | `top_port = 22`, `sessions > 50`, `avg_pkts > 8` |
| MYSQL_BRUTE | `top_port = 3306` or `app = mysql` |
| RDP_BRUTE | `top_port = 3389`, Windows VLAN targets |
| HTTP_AUTH_SPRAY | `top_port ∈ {80,443,8080}`, POST-heavy, few URI paths |
| CROSS_SERVICE_ROT | Multiple auth-service ports from same IP |
| WEB_EXPLOIT | High `entropy_first`, POST with body, unusual URI length |
| SERVICE_EXPLOIT | Known service port, anomalous packet size/flag pattern |
| PHASED_ATTACK | Per-flow labels escalate over time (model 3 detects) |
| SIP_FRAUD | `port = 5060`, UDP, `short_ratio > 0.9`, `peers > 1000` |
| DNS_TUNNEL | `dns_qname_len` high, `dns_qtype` unusual, high volume |
| AMPLIFICATION | Small fwd bytes, single request, UDP |
| HORIZONTAL_SWEEP | Same port, `peers` increasing, sequential timestamps |
| VERTICAL_ESCALATION | Same target, `ports` increasing over time, depth increasing |
| PIVOT_CHAIN | Both target and port change across hops |
| RETURN_AND_DEEPEN | Revisits previous target with higher packet count/duration |
| LOW_AND_SLOW | Few sessions, large time gaps, moderate per-session depth |
| ONE_SHOT_NOISE | Single session, `avg_pkts < 5`, never returns |
| EMERGING | Consistent behavior across windows, doesn't match other groups |

---

## Attacker Movement Tracking

### The Problem

Per-flow models (XGBoost, CNN) classify individual sessions. They cannot see that the same attacker:

1. Did RECON on target A port 80
2. 12 minutes later tried MySQL auth on target A port 3306
3. 3 minutes later tried MySQL auth on target B port 3306
4. 45 minutes later came back to target B on SSH with credentials

That sequence is a kill-chain playing out across the honeypot farm. The gaps between hops matter — 3 minutes between MySQL targets means automated pivoting; 45 minutes before SSH means they probably got credentials and came back.

### Data Requirements

Store at **per-flow granularity** per attacker. Every individual session gets a row in the fanout table. Do not collapse or aggregate at write time.

Each row must carry:

**Movement signal:**
- Which target IP, which port, which service
- Timestamp (for ordering and gap computation)
- VLAN ID (did they cross from Linux VLAN 20 to Windows VLAN 10?)

**Interaction depth:**
- Packet count, duration, bytes
- Connection state
- Whether credentials were attempted, succeeded

**Per-flow model outputs (when available):**
- XGBoost label + confidence
- CNN label + confidence
- These become input features for model 3

**Derived at query time (not stored):**
- Time gap from previous flow (absolute and relative to attacker's typical pace)
- Whether this is a new target, new port, or return visit
- Delta from previous flow (changed port? changed target? changed protocol?)
- Label escalation (did per-flow labels progress across hops?)

### Movement Patterns

| Pattern | Signal | Threat Level |
|---|---|---|
| **HORIZONTAL_SWEEP** | Same port across targets, sequential timing | Medium — scanning for vulnerable instances |
| **VERTICAL_ESCALATION** | Same target, port/service changes, depth increasing | High — found a target, exploring attack surface |
| **PIVOT_CHAIN** | Both target and service change per hop, each hop informed by previous | Very high — active penetration campaign |
| **RETURN_AND_DEEPEN** | Revisits previous target after gap, with deeper interaction | Very high — likely obtained credentials elsewhere |

### Campaign Boundaries

**Do not decide at ingest time.** Store every flow event with timestamp and attacker reference. Compute `session_gap_sec` (time since this attacker's previous flow) on each row. Let the model or classifier decide what constitutes a campaign boundary.

Options for later:
- Fixed timeout (gap > N hours = new campaign)
- Behavioral break (different target set, fingerprint change, pattern shift)
- Model-learned boundaries

Store the atoms now. The segmentation logic can change without schema changes.

### VLAN Crossing

An attacker that moves from Linux services (VLAN 20) to Windows services (VLAN 10) is doing deliberate cross-platform targeting. This is extremely high signal and should auto-promote to D3 capture. The `vlan_id` field on each fanout row enables this detection.

---

## Three-Model Architecture

### Model Hierarchy

| Model | Scope | Input | Learns | Available |
|---|---|---|---|---|
| **XGBoost** | Single flow | 75 scalar features | "What is this flow?" — static behavioral summary | Now |
| **CNN** | Single flow | 512 tokens + 42 scalars | "What happened inside this flow?" — sequential packet patterns | Now |
| **Model 3** | Attacker campaign | Sequence of flows over time | "What is this attacker doing across flows?" — campaign behavior | Future (collect data now) |

### How They Feed Each Other

```
Individual flows:
    PCAP → XGBoost → per-flow label + confidence
    PCAP → CNN     → per-flow label + confidence

Attacker campaigns (Model 3):
    Sequence of flows from one attacker, ordered by time
    Each step carries:
        ├── Target IP, port, service, VLAN
        ├── XGBoost prediction (label + confidence)
        ├── CNN prediction (label + confidence)
        ├── Interaction depth (packets, duration, bytes, conn_state)
        ├── Time gap since previous hop
        ├── Behavioral shift indicators
        └── Return/revisit flags
    
    Output: Campaign-level classification
        ├── Campaign intent (scan-and-leave, credential harvest, exploitation, manual pentest)
        ├── Threat level (breadth × depth × persistence × progression)
        └── Next action prediction (what will they do next?)
```

### Model 3 Labels

Multiple label targets possible from the same data:

| Label type | Source | Value |
|---|---|---|
| **Worst stage reached** | max(per-flow labels) across campaign | Did this campaign reach COMPROMISE? |
| **Intent classification** | Derived from movement pattern | Scan-and-move-on, credential harvester, exploit delivery, manual pentest |
| **Next action prediction** | Next flow in sequence | Given trajectory so far, what target/port/service next? |
| **Threat level** | Composite score | Breadth × depth × persistence × progression |

Ground truth: join attacker's flow sequence with evidence events across all their targets. "This attacker eventually achieved COMPROMISE on target X" is derivable from per-flow labels + evidence.db.

**Do not define model 3 labels now.** Collect the data. Accumulate several months of attacker campaigns. The label definitions can be refined when there's enough data to train on.

---

## ClickHouse Event Types (The Ledger)

Everything in ClickHouse is an event: timestamped, referenced, append-only.

### Already Specced (Dataset DB Spec)

| Event type | Table | Description |
|---|---|---|
| Flow observed | `flows` | Per-flow features from PCAP |
| Packets captured | `packets` | Per-packet tokens (D2+ only) |
| Fingerprint extracted | `fingerprints` | Protocol-specific handshake features |
| Label assigned | `labels` | Ground truth from evidence.db |

### New Event Types Needed

| Event type | Description | Key fields |
|---|---|---|
| **Evidence event** | Raw host-side log event from evidence.db — auth failure, process create, suspicious command, etc. | `event_id, timestamp, src_ip, target_ip, event_type, event_detail, evidence_mask_bit, source_log` |
| **Fanout hop** | Individual flow from an attacker to a target, with movement context | `flow_id, attacker_ip, target_ip, dst_port, app_proto, vlan_id, first_ts, last_ts, pkts_fwd, pkts_rev, bytes_fwd, bytes_rev, conn_state, session_gap_sec` |
| **Model prediction** | XGBoost or CNN scoring a flow | `flow_id, model_name, model_version, label, confidence, timestamp` |
| **Group assignment** | Classifier assigns an attacker to a behavior group | `attacker_ip, group_id, sub_group_id, confidence, window_start, window_end, timestamp` |
| **Depth change** | Capture depth promoted or demoted | `attacker_ip, old_depth, new_depth, trigger_reason, triggered_by, timestamp` |
| **Analyst action** | Human pushes IP to watchlist or changes priority | `attacker_ip, action_type, capture_depth, priority, reason, analyst_id, timestamp, expires_at` |
| **Watchlist sync** | Record of what was pushed to SQLite | `attacker_ip, capture_depth, priority, source (classifier\|analyst\|rule), timestamp` |

### Key Design Rules

1. **No updates.** Every state change is a new row. "What was this IP's group assignment last Tuesday?" is a query, not a reconstruction.
2. **Every row has a timestamp.** `DateTime64(3)` minimum. This is the ordering key for everything.
3. **Every row references its source.** Flow events reference the flow_id. Model predictions reference the flow_id and model version. Group assignments reference the time window evaluated. Analyst actions reference the analyst. Full audit trail.
4. **Model predictions are events, not columns on the flow.** When you retrain and re-score, both predictions coexist. No data loss.
5. **The SQLite watchlist is a projection.** It's "give me the latest state per IP" — a materialized view of the event log, pushed periodically. Disposable.

---

## Analyst Workflow

### Single IP Lookup (Streamlit)

When you spot an attacker in the honeypot and search the SPAN:

```
┌─ IP: 85.11.167.12 ──────────────────────────────────────────┐
│ Current group: CREDENTIAL_ATTACK / MYSQL_BRUTE (conf: 0.95) │
│ Capture depth: D2                                            │
│ Trajectory: UNCLASSIFIED → RECON → CREDENTIAL_ATTACK (6h)   │
│                                                              │
│ Movement:                                                    │
│   14:02  target_A:80   RECON    4 pkts   (VLAN 20)          │
│   14:14  target_A:3306 BRUTE   47 pkts   (VLAN 20)          │
│   14:17  target_B:3306 BRUTE   52 pkts   (VLAN 20)          │
│   15:02  target_B:22   BRUTE  200 pkts   (VLAN 20)          │
│                                                              │
│ Fanout: 2 targets, 3 ports, fan-ratio 0.04 (focused)        │
│ Campaign: cluster_mysql_0x3a (8 IPs, 4 active today)        │
│ Fingerprint: HASSH freq=2 (rare tool)                        │
│ VLAN crossing: No                                            │
│                                                              │
│ [▲ Promote to D3]  [Push to block]  [Watch 72h]             │
└──────────────────────────────────────────────────────────────┘
```

### Analyst Actions

| Action | Effect on SQLite | Event logged to ClickHouse |
|---|---|---|
| Promote to D3 | `capture_depth = D3`, TTL set | depth_change event |
| Push to block | IP added with block flag | analyst_action event |
| Watch 72h | `capture_depth = D2`, 72h expiry | analyst_action + depth_change events |

### Automated vs Manual Path

Both paths write to the same SQLite table, same schema, same priority system. Hunter doesn't care who put the row there.

- **Automated:** Classifier job runs every 5-10 min, bulk-pushes IPs meeting promotion thresholds.
- **Manual:** Analyst spots something the classifier missed, pushes immediately. Intuition gets a fast lane.

Audit trail in ClickHouse tracks both. Later analysis: "which manual pushes led to interesting captures?" → refine automated thresholds.

---

## Temporal Analysis

### Rolling Window Group Assignment

Compute group membership per attacker in rolling windows (15min, 1h, 6h). The trajectory across windows is the signal, not any single snapshot.

An IP that goes `RECON → RECON → CREDENTIAL_ATTACK → EXPLOIT_DELIVERY` across four 1h windows is a kill-chain progression in your data.

### Fanout Shape Features (Pre-computable)

| Feature | Description | Signal |
|---|---|---|
| Fan-out ratio | `unique_targets / total_sessions` | Near 1.0 = spray. Near 0.0 = focused. |
| Port concentration | Top-3 ports as fraction of sessions | High + many peers = coordinated campaign |
| Temporal density | Peak sessions per minute | Bursty (all at once) vs sustained (steady drip) |
| Target entropy | Shannon entropy of target IP distribution | Low = focused targeting. High = scanning. |
| Service transition count | Number of distinct service changes across hops | High = PIVOT_CHAIN behavior |
| VLAN cross count | Number of VLAN boundary crossings | Any > 0 = deliberate cross-platform targeting |
| Depth escalation slope | Linear fit on packet counts across hops | Positive = increasing engagement |
| Return count | Number of times attacker revisits a previous target | High = RETURN_AND_DEEPEN |

### Cross-IP Campaign Linkage

Attackers sharing infrastructure show the same fingerprints. Group IPs by `(top_port, app_proto, ja3_hash OR hassh_hash, fanout_shape_bucket)` to assign `campaign_id`. When you look up one IP, pull the whole cluster.

Fingerprint frequency tables in ClickHouse (already specced) are halfway there. The missing piece is the clustering step in the periodic classifier job.

---

## Summary: What To Build (In Order)

### Phase 1: Data Collection (Now)
1. Spec and create new ClickHouse tables: evidence events, fanout hops, model predictions, group assignments, depth changes, analyst actions.
2. Get Hunter writing to all new tables at appropriate capture depth.
3. Implement capture depth filtering in Hunter (D0 skip list in SQLite, D1/D2/D3 write paths).
4. Build Streamlit lookup for single-IP profile with push-to-watchlist button.

### Phase 2: Classification (When Data Flows)
1. Implement periodic classifier job (every 5-10 min) with full group hierarchy.
2. Push classifier results to SQLite watchlist.
3. Add group trajectory tracking (rolling window assignments).
4. Add campaign clustering (fingerprint-based IP grouping).

### Phase 3: Model 3 (When Data Accumulates)
1. Define model 3 training dataset export from ClickHouse fanout + model predictions.
2. Define label targets based on observed campaign patterns.
3. Train sequence model on attacker movement trajectories.
4. Integrate model 3 predictions back into the classifier job and depth promotion logic.
