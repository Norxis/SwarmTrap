# Phase 2: Hunter Core — Get Data Flowing

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 1 (ClickHouse running on both hosts)

## Objective

Rewrite Hunter to write real SPAN traffic to local ClickHouse. Use the existing afpacket.py capture layer and session tracking pattern from Hunter-v7, but replace SQLite writes with ClickHouse batch inserts. Get data flowing end-to-end — even with partial features.

## Reference Files

| File | Location | Purpose |
|------|----------|---------|
| Current Hunter | `~/DFI/Proxmox-V7/Hunter-v7/hunter.py` (1759 lines) | Reference for SessionTracker, HoneypotFilter, WatchlistManager |
| AF_PACKET lib | `~/DFI/Proxmox-V7/Hunter-v7/afpacket.py` (785 lines) | Copy verbatim — do not modify |
| DFIWriter spec | `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` (lines 1070-1165) | Batch insert class template |
| Flow schema | `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` (lines 122-210) | flows table columns |
| Packets schema | `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` (lines 220-257) | packets table columns |
| Fanout schema | `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` (lines 386-424) | fanout_hops table columns |
| XGB features | `~/ai-shared/DFI2/DFI2_XGB_v1_Spec.md` | Full 75-feature spec |
| CNN tokens | `~/ai-shared/DFI2/DFI2_CNN_v1_Spec.md` | 5-channel tokenization spec |

## Output Files

```
~/DFI2/
├── hunter/
│   ├── __init__.py
│   ├── afpacket.py      # COPY from Hunter-v7 (verbatim, no changes)
│   ├── hunter.py        # Main entry: AF_PACKET → SessionTracker → DFIWriter
│   ├── writer.py        # DFIWriter class (ClickHouse batch inserter)
│   ├── watchlist.py     # SQLite watchlist reader (capture depth decisions)
│   ├── config.py        # Environment variable config
│   └── filters.py       # HoneypotFilter + WatchlistManager (ported from v7)
```

---

## Step 1: Copy afpacket.py

Copy `~/DFI/Proxmox-V7/Hunter-v7/afpacket.py` to `~/DFI2/hunter/afpacket.py` **verbatim**. Do not modify a single line. This is a proven TPACKET_V3 implementation with:
- 4 worker processes with FANOUT_HASH
- CPU pinning
- BPF filtering
- Ring buffer management

---

## Step 2: config.py — Environment Variables

```python
import os

# Capture
HUNTER_IFACE = os.environ.get('HUNTER_IFACE', 'ens192')
CAPTURE_MODE = os.environ.get('CAPTURE_MODE', 'honeypot')  # 'span' or 'honeypot'
FANOUT_WORKERS = int(os.environ.get('FANOUT_WORKERS', '4'))
CPU_LIST = os.environ.get('CPU_LIST', '')
BPF_VLAN_AWARE = int(os.environ.get('BPF_VLAN_AWARE', '0'))

# ClickHouse
CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
CH_DATABASE = os.environ.get('CH_DATABASE', 'dfi')

# SQLite watchlist
WATCHLIST_DB = os.environ.get('WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')
WATCHLIST_REFRESH = int(os.environ.get('WATCHLIST_REFRESH', '30'))

# Session management
SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', '120'))
FLUSH_INTERVAL = int(os.environ.get('FLUSH_INTERVAL', '10'))
MAX_SESSIONS = int(os.environ.get('MAX_SESSIONS', '500000'))
MAX_READY_Q = int(os.environ.get('MAX_READY_Q', '200000'))

# Honeypot mode
HONEYPOT_IPS = os.environ.get('HONEYPOT_IPS', '').split(',') if os.environ.get('HONEYPOT_IPS') else []
HONEYPOT_EXCLUDE = os.environ.get('HONEYPOT_EXCLUDE', '172.16.0.0/12,10.0.0.0/8,192.168.0.0/16')

# Identity
SENSOR_ID = os.environ.get('SENSOR_ID', 'aio1')
TAP_POINT = os.environ.get('TAP_POINT', 'SPAN_MIRROR')
DEFAULT_LABEL = os.environ.get('DEFAULT_LABEL', 'HUNTER_OBSERVED')
```

---

## Step 3: writer.py — DFIWriter (ClickHouse Batch Inserter)

Adapt the DFIWriter class from DFI2_Dataset_DB_Spec.md. Key requirements:

- Uses `clickhouse-driver` package (`from clickhouse_driver import Client`)
- Connects to `CH_HOST:CH_PORT`
- 6 independent buffers: flows, packets, fingerprints, fanout_hops, evidence_events, model_predictions
- Each buffer is a `collections.deque`
- Thread-safe: one `threading.Lock` per buffer (or one global lock)
- Flush conditions: every 1 second OR when any buffer hits 50K rows
- Background flusher thread (daemon=True)
- Writes to `*_buffer` tables (e.g., `dfi.flows_buffer`)
- On flush failure: re-queue rows (bounded at 10× FLUSH_SIZE to prevent OOM)
- Log row counts on each flush

**Public API:**
```python
class DFIWriter:
    def __init__(self, host='localhost', port=9000, database='dfi')
    def insert_flow(self, flow: dict, pkts: list, fp: dict, fanout: dict, depth: int)
    def insert_evidence(self, events: list)
    def insert_predictions(self, preds: list)
    def close(self)  # flush remaining + stop thread
```

---

## Step 4: watchlist.py — SQLite Watchlist Reader

Port the watchlist reading logic from Hunter-v7's WatchlistManager. This is the hot cache for capture depth decisions.

```python
class WatchlistReader:
    def __init__(self, db_path: str, refresh_interval: int = 30)
    def lookup(self, ip: str) -> dict  # Returns {capture_depth, priority, group_id, top_port} or None
    def refresh(self)  # Re-read from SQLite, called periodically
```

- On lookup miss: return None (caller defaults to D1)
- Thread-safe: refresh happens in background, lookup uses a snapshot dict
- Expired entries (expires_at < now) treated as missing

---

## Step 5: filters.py — HoneypotFilter + Endpoint Resolution

Port from Hunter-v7's HoneypotFilter. Core logic:

**HoneypotFilter (CAPTURE_MODE=honeypot):**
- Stage 1: If one side of packet matches HONEYPOT_IPS → other side is attacker (direct hit)
- Stage 2: If neither side is honeypot but one is in _known_bad set → track (fanout)
- Exclude: RFC1918 (configurable), loopback, link-local, anycast DNS
- Returns: (bad_ip, peer_ip, direction, is_direct_hit)

**WatchlistManager (CAPTURE_MODE=span):**
- Reads watchlist.db for known-bad IPs
- If src_ip or dst_ip matches watchlist → track
- Returns: (bad_ip, peer_ip, direction, WatchedIP)

---

## Step 6: hunter.py — Main Entry Point

This is the core rewrite. Structure:

### SessionProfile dataclass

```python
@dataclass
class PacketEvent:
    ts: float           # packet timestamp (seconds.nanoseconds)
    direction: int      # 1=fwd, -1=rev
    payload_len: int
    pkt_len: int
    tcp_flags: int      # raw TCP flags byte
    tcp_window: int     # TCP window size
    payload_head: bytes # first 256 bytes of payload (for entropy, fingerprints)

@dataclass
class SessionProfile:
    # Identity
    flow_id: str             # UUID
    src_ip: str              # attacker
    dst_ip: str              # target/honeypot
    src_port: int
    dst_port: int
    ip_proto: int            # 6=TCP, 17=UDP
    vlan_id: int = 0

    # Timing
    first_ts: float = 0.0
    last_ts: float = 0.0

    # Volume
    pkts_fwd: int = 0
    pkts_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0

    # Events
    events: list = field(default_factory=list)  # List[PacketEvent], max 128
    n_events: int = 0

    # Capture context
    capture_depth: int = 1   # D1 default
    app_proto: int = 0       # port-based heuristic

    # State
    flushed: bool = False
```

### SessionTracker

```python
class SessionTracker:
    def __init__(self, writer: DFIWriter, watchlist: WatchlistReader, filter_func)
    def ingest(self, pkt)  # Called from AF_PACKET worker callback
    def expire_idle(self) -> list  # Move idle sessions to ready queue
    def flush_ready(self)  # Extract features + write to ClickHouse
```

**ingest() hot path:**
1. Parse packet (use afpacket's parser output)
2. Resolve endpoints via filter_func → (bad_ip, peer_ip, direction)
3. If None → skip (not interesting)
4. Session key = (bad_ip, peer_ip, src_port, dst_port, proto) — normalized
5. Get or create SessionProfile
6. Update volume counters
7. If event packet (payload > 0 OR SYN/FIN/RST): append PacketEvent (max 128)

**flush_ready():**
1. For each ready session:
2. Generate flow_id (UUID)
3. Look up capture_depth from watchlist
4. Extract available features → flow dict
5. Build packet token list (size_dir + tcp_flags for now, other channels = 0)
6. Build fanout_hop dict
7. Call writer.insert_flow(flow, pkts, fp=None, fanout, depth)

### Feature Extraction (Minimal for Phase 2)

Only extract what we already have from v7:
- **Identity:** flow_id, session_key, actor_id (= src_ip), src_ip, dst_ip, src_port, dst_port, ip_proto, vlan_id, first_ts, last_ts
- **Volume:** pkts_fwd, pkts_rev, bytes_fwd, bytes_rev
- **Timing:** duration_ms (last_ts - first_ts), pps, bps
- **Size:** n_events
- **Tokens (2 of 5):** size_dir_token, flag_token (reuse v7's encoding)
- **Capture depth:** from watchlist lookup

Everything else → NULL/0 (filled in Phase 3-4).

### Worker + Main Process

Same pattern as Hunter-v7:
- Main process: creates DFIWriter, WatchlistReader, filter
- Spawns worker processes via afpacket.py's launch function
- Each worker: gets its own SessionTracker
- Worker flush thread: every FLUSH_INTERVAL seconds, expire_idle + flush_ready
- Main thread: periodic stats logging

### Entry point

```python
if __name__ == '__main__':
    # Parse config
    # Create DFIWriter
    # Create WatchlistReader
    # Create filter (HoneypotFilter or WatchlistManager based on CAPTURE_MODE)
    # Launch AF_PACKET workers
    # Main loop: stats + health checks
```

---

## Step 7: Deployment

### Systemd unit for AIO: `/etc/systemd/system/dfi-hunter2.service`

```ini
[Unit]
Description=DFI2 Hunter — ClickHouse-backed SPAN Tracker
After=network-online.target clickhouse-server.service
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/dfi-hunter/env2
ExecStart=/usr/bin/python3 -m hunter.hunter
WorkingDirectory=/opt/dfi2
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Environment file: `/etc/dfi-hunter/env2`

```bash
HUNTER_IFACE=ens192
CAPTURE_MODE=honeypot
HONEYPOT_IPS=216.126.0.206
HONEYPOT_EXCLUDE=172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
CH_HOST=localhost
CH_PORT=9000
WATCHLIST_DB=/opt/dfi-hunter/watchlist.db
FANOUT_WORKERS=4
CPU_LIST=4,5,6,7
SENSOR_ID=aio1
TAP_POINT=AIO_MON
SESSION_TIMEOUT=120
FLUSH_INTERVAL=10
```

---

## Step 8: Verification

1. **Service starts:** `systemctl status dfi-hunter2` — active
2. **No crash:** `journalctl -u dfi-hunter2 -n 50` — no exceptions
3. **Flows appearing:**
   ```bash
   clickhouse-client --query "SELECT count() FROM dfi.flows"
   # Wait 60s, check again — count should increase
   ```
4. **Fanout hops appearing:**
   ```bash
   clickhouse-client --query "SELECT count() FROM dfi.fanout_hops"
   ```
5. **Real attacker data:**
   ```bash
   clickhouse-client --query "SELECT src_ip, count() as flows FROM dfi.flows GROUP BY src_ip ORDER BY flows DESC LIMIT 10"
   ```
6. **Packets (if any D2+ IPs):**
   ```bash
   clickhouse-client --query "SELECT count() FROM dfi.packets"
   ```
7. **PV1 pull works:** Run pull_aio.py on PV1, verify AIO data appears on PV1

---

## Acceptance Criteria

- [ ] afpacket.py copied verbatim (diff shows zero changes)
- [ ] hunter.py starts, captures packets, creates sessions
- [ ] DFIWriter batches and flushes to ClickHouse buffer tables
- [ ] flows table populating with real SPAN traffic
- [ ] fanout_hops table populating
- [ ] packets table populating (for D2+ IPs, or all by default initially)
- [ ] WatchlistReader reads SQLite and returns capture depth
- [ ] HoneypotFilter correctly identifies attacker IPs
- [ ] No memory leak (stable RSS after 10 minutes of operation)
- [ ] PV1 pull picks up AIO data successfully
- [ ] Worker CPU pinning works (verify with `taskset -p`)

## Important Notes

- **Do NOT modify afpacket.py.** It is battle-tested.
- **Performance matters.** The ingest() hot path must be fast — no allocations, no I/O, no locks on the packet processing path. Only buffer operations should take locks.
- **DFIWriter runs in a background thread.** Workers call insert_flow() which just appends to a deque. The flusher thread does the actual ClickHouse INSERT.
- **NULL is OK.** Most flow columns will be NULL/0 in Phase 2. That's fine — ClickHouse handles NULLs efficiently. Phase 3 fills them in.
- **clickhouse-driver must be installed:** `pip install clickhouse-driver` on AIO.
- **Stop old dfi-hunter first:** `systemctl stop dfi-hunter` before starting dfi-hunter2.
