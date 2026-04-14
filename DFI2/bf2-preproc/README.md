# BF2 Preprocessor -- GOD 1 on ARM (C/DPDK)

This is the hardware-accelerated version of GOD 1, written in C using DPDK. It runs on the ARM cores of a NVIDIA BlueField-2 DPU (Data Processing Unit) installed in the host server's PCIe slot. The DPU sits on the SPAN path and processes every packet at wire speed: 6,000 unique IPs per second, 200K+ packets per second.

## What It Does

`ip_god.c` is a single-file C program that performs the entire GOD 1 pipeline in hardware:

1. **Captures packets via DPDK** (`rte_eth_rx_burst`) on the DPU's physical port (p0), which receives SPAN-mirrored traffic from the network switch.

2. **Identifies direction** using a hardcoded honeypot IP table. If the destination is a honeypot, the source is an attacker (ingress). If the source is a honeypot, the destination is the external IP (egress). Both-honeypot traffic is dropped.

3. **Tracks every IP** in a 1M-entry mmap'd hash table (`god2_table.db`). Every external IP seen on the wire gets an entry with state, XGB class, confidence, hit count, and timestamps. The table is memory-mapped for persistence across restarts.

4. **Tracks flows** in a 524K-slot hash table using 5-tuples. Each flow accumulates packet counts, byte counts, inter-arrival time statistics, size distributions, and TCP flag counts. Flows expire after 60 seconds of inactivity.

5. **Scores flows with XGB** after 10 packets. The XGBoost model is loaded from a custom binary format (not JSON) for fast tree traversal in C. The model runs the same 5-class prediction as the Python GOD 1 (RECON, KNOCK, BRUTE, EXPLOIT, CLEAN) but executes entirely on the ARM core with no Python overhead.

6. **Publishes scores via NATS** to PV1 (`192.168.0.100:4222`) in batched JSON messages on subject `dfi.xgb.classifications`. PV1's listener writes these to ClickHouse.

7. **Drops attackers via eSwitch hardware flow rules** using DPDK's `rte_flow_create` API. When a verdict arrives, the IP is both dropped in hardware (packets never reach the ARM CPU) and evicted from the IP table. ICMP is dropped globally in hardware at startup.

## How eSwitch DROP Works

The BlueField-2's embedded switch (eSwitch) can install per-IP flow rules that drop packets before they reach the ARM cores or the host CPU. This is the key advantage over the Python GOD 1: once an IP is convicted, its traffic is eliminated at the NIC hardware level.

```
SPAN traffic
    |
    v
+-------------------+
|  BF2 eSwitch      |
|  (hardware)       |
|                   |
|  Flow rules:      |
|  - ICMP -> DROP   |
|  - 1.2.3.4 -> DROP|  <-- installed by rte_flow_create()
|  - 5.6.7.8 -> DROP|
|                   |
|  Everything else  |
|  passes through   |
+--------+----------+
         |
         v
    ARM cores (ip_god.c)
    parse -> track -> score -> NATS publish
```

The `eswitch_drop()` function creates a flow rule matching `src_ip == X` with action `DROP`. The `eswitch_icmp_drop()` function drops all ICMP at startup (noise reduction). Currently the system can hold ~140K dropped IPs in hardware flow rules.

## Verdict Flow

GOD 2 (running on PV1) sends settled verdicts to the ARM via `verdict_sender.py`:

1. `verdict_sender.py` queries `dfi.ip_reputation` for settled attackers (evidence-confirmed, high-confidence dirty, blind scanners)
2. Writes IP list to a temp file, SCPs it to the ARM at `/tmp/verdicts.txt`
3. SSHs to the ARM and moves it to `/var/lib/dfi-preproc/verdicts.txt`
4. `ip_god.c` checks for the verdict file every second via `process_verdicts()`
5. For each IP: installs an eSwitch DROP rule + evicts the IP from the tracking table
6. Deletes the verdict file after processing

This creates the closed loop: GOD 1 scores -> PV1 judges -> PV1 sends verdicts -> GOD 1 drops in hardware.

## Files

| File | Purpose |
|------|---------|
| `ip_god.c` | Main program: DPDK capture, flow tracking, XGB scoring, NATS publish, eSwitch DROP, verdict processing |
| `feature_map.h` | Auto-generated mapping from XGB model feature indices to ARM feature extraction indices (50 features) |
| `gen_feature_map.py` | Generates `feature_map.h` from a model file. Must be run before deploying any new XGB model to ARM. |
| `verdict_sender.py` | Runs on PV1 via cron. Queries ClickHouse for settled IPs and SCPs the verdict list to the ARM. |

## XGB Model on ARM

The C implementation loads XGB models in a custom binary format (`.bin`, not `.json`). The binary format stores trees as flat arrays of 18-byte nodes:

```
Header: [magic(4)] [n_trees(4)] [n_classes(4)] [n_features(4)]
Per tree: [tree_size(4)] [nodes...]
Per node (18 bytes): [feature(2)] [value(4)] [left(4)] [right(4)] [leaf(4)]
```

Prediction traverses each tree from root to leaf (max depth 32), accumulates class scores, applies softmax, and returns the winning class and confidence. Missing features (NaN) default to the left child, matching XGBoost convention.

## Feature Mapping

The XGB model expects features in training order, but the C code extracts features in a different order (grouped by category). `feature_map.h` bridges this gap with a `FEAT_MAP[]` array:

```c
// model_feat[i] = arm_feat[FEAT_MAP[i]]
float model_feat[MODEL_FEAT_COUNT];
for (int fi = 0; fi < MODEL_FEAT_COUNT; fi++)
    model_feat[fi] = arm_feat[FEAT_MAP[fi]];
```

The `gen_feature_map.py` script reads the model's `feature_names` and maps each to its position in the ARM feature array. The ARM feature order is defined as 75 features across 8 groups (F1-F8), matching the Python GOD 1's `extract_features()`:

- F1: Protocol (3): dst_port, ip_proto, app_proto
- F2: Volume (8): pkts_fwd/rev, bytes_fwd/rev, bytes_per_pkt, ratios
- F3: Timing (10): duration, RTT, IAT stats, think time, PPS, BPS
- F4: Packet Size Shape (14): size stats, histograms
- F5: TCP Behavior (11): SYN/FIN/RST/PSH counts, connection state
- F6: Payload Content (8): entropy, printable fraction, null fraction
- F7: Protocol Fingerprints (15): TLS/SSH/HTTP/DNS (zero-filled on ARM -- no DPI)
- F8: Source Behavior (6): flow count, unique ports/dsts/protos

The current model uses 50 of these 75 features (F7 fingerprints and F8 source behavior are not available in the C implementation).

## IP Table Structure

The mmap'd IP table (`/var/lib/dfi-preproc/god2_table.db`) uses a chained hash table:

- **2M buckets** for hash distribution
- **1M entry slots** (~38 bytes each), total file ~50MB
- **Magic number** `0x474F4432` ("GOD2") for format detection
- **Atomic count** for safe concurrent access
- Per-entry fields: IP, state (0=new, 1=scored, 2=attacker), is_attacker flag, XGB class/confidence, app_proto, hit count, flow count, timestamps, chain pointer

The table persists across restarts via mmap. New instances detect an existing table by the magic number and resume with the existing IP set.

## Flow Tracker

- **524K slots** (power of 2 for mask-based indexing)
- FNV-1a hash on 5-tuple with linear probing (max 64 probes)
- Flows expire after 60 seconds of inactivity
- XGB scoring triggers at 10 packets per flow (configurable via `FLOW_SCORE_PKTS`)
- Expiration runs every 30 seconds

## Building

The program links against DPDK libraries. Typical build on the BF2 ARM:

```bash
gcc -O2 -o ip_god ip_god.c -I/opt/dpdk/include -L/opt/dpdk/lib \
    -lrte_eal -lrte_ethdev -lrte_mbuf -lrte_mempool \
    -lrte_ring -lrte_flow_classify -lm -lpthread
```

Run with DPDK EAL arguments:

```bash
./ip_god -l 0-3 -n 4 --
```

## Relationship to Python GOD 1

Both `ip_god.c` and `god1.py` implement the same logical pipeline (capture -> track -> score -> publish), but they differ in execution environment and capabilities:

| Aspect | `ip_god.c` (ARM) | `god1.py` (AIO/Server) |
|--------|-------------------|------------------------|
| Capture | DPDK (kernel bypass) | AF_PACKET raw socket |
| Scoring | Custom C XGB tree walker | Python xgboost library |
| Drop mechanism | eSwitch hardware flow rules | ipset + Python set |
| Features extracted | 50 (no DPI, no source behavior) | 75 (full feature set) |
| D2 capture | No (scores only) | Yes (full 75 features + CNN tokens) |
| Verdict source | File-based (`verdicts.txt`) | Direct CH read (`ip_profile`) |
| Throughput | 200K+ pkt/s, 6K unique IPs/s | Lower (Python overhead) |
| CH writes | Via NATS to PV1 listener | Direct CH client |

The C version trades feature completeness for raw throughput. It handles the high-volume scoring and hardware-level blocking, while the Python version handles the richer D2 training data capture with full feature extraction and CNN tokenization.
