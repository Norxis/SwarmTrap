# DFI Windows Capture Agent — Implementation Specification

## Purpose

Build a universal Python package that installs on any Windows system (Server 2016+ or Win10+) and turns it into a self-contained honeypot sensor. The agent captures network traffic via Npcap, extracts ML features for two model architectures (XGBoost and 1D-CNN), collects host-side evidence from Windows Event Logs, and exposes everything via a REST API for upstream ingestion or standalone CSV export.

This is the foundation of the AIO (All-In-One) open-source node. No external infrastructure required — no SPAN tap, no ClickHouse, no Linux host. One Windows VM generates complete labeled training datasets.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Windows Honeypot VM                                             │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │   RDP    │  │   SMB    │  │  MSSQL   │  │   IIS    │       │
│  │  :3389   │  │  :445    │  │  :1433   │  │  :80/443 │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       └──────────────┴──────────────┴──────────────┘            │
│                      │                                           │
│              eth0 (honeypot VLAN)                                │
│                      │                                           │
│  ┌───────────────────┴──────────────────────────────────┐      │
│  │              Npcap capture (promiscuous, 256B snap)   │      │
│  └───────────────────┬──────────────────────────────────┘      │
│                      │ raw Ethernet frames                      │
│                      ▼                                           │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              dfi-capture-agent                        │      │
│  │                                                      │      │
│  │  ┌─────────────────────┐  ┌────────────────────┐   │      │
│  │  │  Evidence Collector  │  │  PCAP Pipeline      │   │      │
│  │  │                      │  │                     │   │      │
│  │  │  • ETW subscription  │  │  • Packet parser    │   │      │
│  │  │  • LogonId→IP map    │  │  • Flow reassembly  │   │      │
│  │  │  • IIS W3C tailing   │  │  • XGB features     │   │      │
│  │  │  • Pattern matching  │  │  • CNN tokens       │   │      │
│  │  │                      │  │  • Fingerprints     │   │      │
│  │  └──────────┬───────────┘  └──────────┬──────────┘   │      │
│  │             │                          │               │      │
│  │             ▼                          ▼               │      │
│  │  ┌──────────────────────────────────────────────┐    │      │
│  │  │         agent_buffer.db  (SQLite WAL)        │    │      │
│  │  │                                              │    │      │
│  │  │  events · pcap_flows · pcap_packets          │    │      │
│  │  │  pcap_fingerprints · source_stats            │    │      │
│  │  │  logon_map · flow_state                      │    │      │
│  │  └──────────────────────┬───────────────────────┘    │      │
│  │                         │                             │      │
│  │                         ▼                             │      │
│  │  ┌──────────────────────────────────────────────┐    │      │
│  │  │         REST API  (Flask/Waitress)            │    │      │
│  │  │         binds to eth1 (mgmt VLAN) only        │    │      │
│  │  └──────────────────────────────────────────────┘    │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                  │
│              eth1 (management VLAN, e.g. 172.16.x.x)            │
└──────────────────────────────────────────────────────────────────┘
         │
         │  DFI2 pulls via REST (or standalone CSV export)
         ▼
   ClickHouse / local CSV
```

### Threading Model

| Thread | Name | Role |
|--------|------|------|
| `dfi-capture` | CaptureThread | Npcap read loop → PacketParser → FlowTable.process_packet() |
| `dfi-evidence` | EvidenceCollector | ETW subscription loop + IIS log tailer → buffer.insert_event() |
| `dfi-sweep` | sweep_loop | Every 1s: FlowTable.sweep() emits timed-out flows |
| `dfi-cleanup` | cleanup_loop | Every 5min: buffer.cleanup() prunes old pulled data |
| `dfi-api` | Waitress | 4-thread WSGI serving Flask app on mgmt NIC |
| main | — | Signal handler, orchestration, shutdown coordination |

All threads are daemon threads except main. Shutdown signal (SIGINT/SIGTERM/SIGBREAK) sets a threading.Event, each component checks it and stops cleanly. On shutdown, FlowTable.emit_all() flushes every active flow to the buffer before exit.

---

## Package Structure

```
dfi-capture-agent/
├── dfi_agent/
│   ├── __init__.py          # __version__ = "1.0.0"
│   ├── __main__.py          # Entry point, orchestration, shutdown
│   ├── config.py            # Dataclass config, JSON loader, validation
│   ├── buffer.py            # SQLite WAL buffer, all tables, CRUD
│   ├── capture.py           # Npcap thread, Ethernet/IP/TCP parser
│   ├── flow_table.py        # Flow reassembly, XGB features, CNN tokens, fingerprints
│   ├── evidence.py          # Windows Event Log collector, LogonId chaining, IIS tail
│   ├── api.py               # Flask REST endpoints
│   └── export.py            # Standalone CSV export (XGB + CNN format)
├── install.ps1              # Universal PowerShell installer
├── uninstall.ps1            # Clean removal
├── config.template.json     # Default configuration
├── requirements.txt         # pcapy-ng, dpkt, flask, waitress, pywin32
└── pyproject.toml
```

Invocation: `python -m dfi_agent --config config.json [--foreground]`

---

## Configuration

JSON file. Every field has a sane default. The installer generates this from its parameters.

```json
{
    "vm_id": "win-honey-01",
    "mgmt_nic_ip": "172.16.0.10",
    "agent_port": 9200,
    "token": "pre-shared-secret",
    "buffer_path": "C:\\Program Files\\DFI\\data\\agent_buffer.db",
    "log_dir": "C:\\Program Files\\DFI\\logs",
    "log_level": "INFO",
    "retention_days": 7,

    "pcap": {
        "enabled": true,
        "interface": "Ethernet0",
        "snap_len": 256,
        "buffer_mb": 16,
        "bpf_filter": "(tcp port 3389 or tcp port 445 or ...) and not ...",
        "flow_timeout_s": 120,
        "flow_drain_rst_s": 2,
        "flow_drain_fin_s": 5,
        "max_active_flows": 50000,
        "max_event_pkts": 128,
        "max_flow_pkts": 10000,
        "capture_source": 1,
        "local_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    },

    "evidence": {
        "enabled": true,
        "channels": [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            "Microsoft-Windows-WinRM/Operational",
            "Microsoft-Windows-PowerShell/Operational"
        ],
        "iis_log_dir": "C:\\inetpub\\logs\\LogFiles\\W3SVC1",
        "logon_map_ttl_hours": 24,
        "suspicious_patterns": ["(cmd|powershell|pwsh).*(/c|/k|-enc)", "..."],
        "download_patterns": ["(certutil)\\s.*-urlcache", "..."]
    },

    "services": {
        "rdp":       { "port": 3389, "enabled": true },
        "smb":       { "port": 445,  "enabled": true },
        "winrm":     { "ports": [5985, 5986], "enabled": true },
        "mssql":     { "port": 1433, "enabled": true },
        "iis_http":  { "port": 80,   "enabled": true },
        "iis_https": { "port": 443,  "enabled": true }
    }
}
```

### Config Dataclasses

```
AgentConfig
├── vm_id: str
├── mgmt_nic_ip: str
├── agent_port: int (default 9200)
├── token: str
├── buffer_path: str
├── log_dir: str
├── log_level: str
├── retention_days: int (default 7)
├── pcap: PcapConfig
│   ├── enabled: bool
│   ├── interface: str
│   ├── snap_len: int (default 256)
│   ├── buffer_mb: int (default 16)
│   ├── bpf_filter: str
│   ├── flow_timeout_s: int (default 120)
│   ├── flow_drain_rst_s: int (default 2)
│   ├── flow_drain_fin_s: int (default 5)
│   ├── max_active_flows: int (default 50000)
│   ├── max_event_pkts: int (default 128)
│   ├── max_flow_pkts: int (default 10000)
│   ├── capture_source: int (default 1, meaning VM-captured)
│   └── local_networks: list[str]
├── evidence: EvidenceConfig
│   ├── enabled: bool
│   ├── channels: list[str]
│   ├── iis_log_dir: str
│   ├── logon_map_ttl_hours: int (default 24)
│   ├── suspicious_patterns: list[str]   → compiled to re.Pattern list
│   └── download_patterns: list[str]     → compiled to re.Pattern list
└── services: list[ServiceDef]
    ├── name: str
    ├── ports: list[int]
    └── enabled: bool
```

Helper methods on AgentConfig:
- `honeypot_ports() → set[int]` — union of all enabled service ports
- `port_to_service() → dict[int, str]` — reverse lookup for app_proto detection
- `local_ips → set[str]` — all IPv4 addresses on this host (for direction detection)

---

## Module 1: Packet Capture (`capture.py`)

### PacketParser

Zero-dependency Ethernet/IP/TCP/UDP parser. Does not require dpkt. Handles:

- Ethernet II frames (EtherType 0x0800 = IPv4)
- 802.1Q VLAN tags (EtherType 0x8100 → skip 4 bytes, read inner EtherType)
- IPv4 headers with variable IHL
- TCP with full flag byte extraction and window size
- UDP
- ICMP (tracked minimally — no ports)

**Input:** Raw bytes from Npcap `pcapy.open_live().next()`

**Output:** Dict or None:
```python
{
    "src_ip": "203.0.113.42",
    "dst_ip": "10.0.0.5",
    "src_port": 54321,
    "dst_port": 3389,
    "proto": 6,           # 6=TCP, 17=UDP, 1=ICMP
    "tcp_flags": 0x12,    # raw flags byte from TCP header offset 13
    "tcp_window": 65535,   # raw window from TCP header offset 14-15
    "pkt_len": 1500,       # IP total length
    "payload": b"...",     # bytes after TCP/UDP header, up to snap_len
}
```

**Parsing steps (TCP):**
1. Check `raw[12:14]` for EtherType. If 0x8100 (VLAN), shift ip_offset to 18 and re-read EtherType from `raw[16:18]`.
2. Verify EtherType == 0x0800 (IPv4). Skip otherwise.
3. Read IPv4 IHL from `raw[ip_offset] & 0x0F`, multiply by 4. Read ip_proto from offset+9.
4. Read src_ip/dst_ip from offset+12..19.
5. TCP: read src_port/dst_port from transport header. Read data_offset from `(raw[transport+12] >> 4) * 4`. Read tcp_flags from transport+13. Read tcp_window from transport+14..15.
6. Payload = raw[transport + data_offset : ip_offset + ip_total_length].

**TCP flag byte layout (offset 13 of TCP header):**
```
Bit 0 = FIN  (0x01)
Bit 1 = SYN  (0x02)
Bit 2 = RST  (0x04)
Bit 3 = PSH  (0x08)
Bit 4 = ACK  (0x10)
Bit 5 = URG  (0x20)
```

### CaptureThread

Background daemon thread. Lifecycle:

1. Import pcapy. If ImportError → log error, set `capture_running = False`, return.
2. `pcapy.open_live(interface, snap_len, 1 (promiscuous), 100 (read_timeout_ms))`. If fails → log available interfaces via `pcapy.findalldevs()`, return.
3. Apply BPF filter via `cap.setfilter()`. If invalid → log, return.
4. Set `capture_running = True`.
5. Loop until `_stop_event.is_set()`:
   - `header, raw = cap.next()` — returns (None, None) on timeout
   - Extract timestamp: `ts_sec, ts_usec = header.getts(); ts = ts_sec + ts_usec / 1_000_000`
   - `parsed = PacketParser.parse(raw)` — None on unrecognized frames
   - Call `flow_table.process_packet(ts, parsed["src_ip"], ...)` 
   - Increment `packets_received` counter
6. On exit: read `cap.stats().ps_drop` into `packets_dropped`. Set `capture_running = False`.

**Counters exposed:** `packets_received`, `packets_dropped`, `packets_parse_errors`, `capture_running`.

---

## Module 2: Flow Table (`flow_table.py`)

This is the core of the agent. One `FlowState` dataclass per bidirectional TCP/UDP flow. Packets enter via `process_packet()`, completed flows emit via `_emit_flow()` which computes all 75 XGB features, 5-channel CNN tokens, and protocol fingerprints in a single pass.

### FlowState Dataclass

```python
@dataclass
class FlowState:
    # ── Identity ─────────────────────────────────────
    flow_id: str              # uuid4
    session_key: str          # SHA256(sorted 5-tuple)[:16]
    src_ip: str               # attacker (SYN initiator, external)
    dst_ip: str               # honeypot (local)
    src_port: int
    dst_port: int
    ip_proto: int             # 6=TCP, 17=UDP, 1=ICMP
    app_proto: int            # DPI or port heuristic (codes below)
    first_ts: float           # epoch
    last_ts: float            # epoch
    state: str                # ACTIVE | FIN_WAIT | CLOSING

    # ── Volume ───────────────────────────────────────
    pkts_fwd: int             # attacker → honeypot
    pkts_rev: int             # honeypot → attacker
    bytes_fwd: int            # IP total length, forward
    bytes_rev: int            # IP total length, reverse

    # ── Timing ───────────────────────────────────────
    syn_ts: float | None      # timestamp of first forward SYN
    syn_ack_ts: float | None  # timestamp of first reverse SYN-ACK
    first_fwd_ts: float | None
    first_rev_ts: float | None
    prev_fwd_ts: float | None # for computing forward IATs
    fwd_iats: list[float]     # accumulated forward IATs (seconds), max 512

    # ── TCP ──────────────────────────────────────────
    syn_count: int
    fin_count: int
    rst_count: int
    psh_count: int
    ack_only_count: int       # ACK set, no SYN/FIN/RST/PSH, payload=0
    first_rst_pkt_num: int    # for rst_frac
    total_pkts: int           # all packets (including non-event)
    syn_to_data_count: int    # packets between SYN and first payload
    _seen_data: bool
    current_psh_run: int      # consecutive PSH count
    max_psh_run: int          # psh_burst_max
    window_size_init: int     # from SYN packet
    retransmit_set: set       # (payload_len, direction) tuples for dedup estimation

    # ── Event Packets (CNN) ──────────────────────────
    event_packets: list[EventPacket]   # max 128
    max_event_pkts: int                # from config

    # ── Payload Analysis ─────────────────────────────
    first_fwd_payload: bytes | None    # first 256 bytes of first forward payload
    fwd_entropy_sum: float             # running sum for mean
    fwd_entropy_count: int
    rev_entropy_sum: float
    rev_entropy_count: int
    fwd_high_entropy: int              # count of fwd payloads with entropy ≥ 7.0
    fwd_payload_sizes: list[int]       # max 512
    rev_payload_sizes: list[int]       # max 512

    # ── Size Histogram ───────────────────────────────
    hist_tiny: int                     # payload 1–63
    hist_small: int                    # 64–255
    hist_medium: int                   # 256–1023
    hist_large: int                    # 1024–1499
    hist_full: int                     # ≥ 1500

    # ── Fingerprints ─────────────────────────────────
    fp: FingerprintState

    # ── Drain Timer ──────────────────────────────────
    drain_until: float | None          # epoch when drain expires
```

### EventPacket Dataclass

```python
@dataclass
class EventPacket:
    seq_idx: int          # 0..127
    ts: float             # epoch, high-res
    direction: int        # 1=fwd, -1=rev
    payload_len: int
    pkt_len: int
    tcp_flags: int        # raw flags byte
    tcp_window: int
    payload_bytes: bytes  # first 256 bytes (for entropy computation)
```

### Session Key

Deterministic, direction-independent:
```python
endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
raw = f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}/{proto}"
session_key = sha256(raw)[:16]
```

### Direction Detection

For each packet, determine forward (attacker→honeypot) vs reverse (honeypot→attacker):
- If `dst_ip` is in `AgentConfig.local_ips` → forward (direction = +1), attacker is src
- If `src_ip` is in `AgentConfig.local_ips` → reverse (direction = -1), attacker is dst
- Neither → discard packet

`local_ips` is populated from `socket.getaddrinfo(hostname, None, AF_INET)` plus the configured `mgmt_nic_ip`.

### app_proto Detection

DPI first, port-heuristic fallback:

| Check | Result |
|-------|--------|
| Forward payload starts with `0x16` (TLS record) and offset+5 is `0x01` (ClientHello) | 3 (tls) |
| Forward payload starts with `GET `, `POST `, `HEAD `, `PUT `, `DELETE `, `OPTIONS `, `PATCH ` | 2 (http) |
| Otherwise, fall back to port map | See below |

**Port → app_proto map:**

| Port | app_proto | Name |
|------|-----------|------|
| 22 | 1 | ssh |
| 80 | 2 | http |
| 443 | 3 | tls |
| 53 | 4 | dns |
| 25 | 5 | smtp |
| 21 | 6 | ftp |
| 23 | 7 | telnet |
| 3389 | 8 | rdp |
| 5900 | 9 | vnc |
| 445 | 10 | smb |
| 3306 | 11 | mysql |
| 1433 | 12 | mssql |
| 5432 | 13 | postgres |
| 6379 | 14 | redis |
| 27017 | 15 | mongodb |
| 5985, 5986 | 2 | http (WinRM) |

### process_packet() — Per-Packet Logic

This is the hot path. Called once per captured packet from the capture thread. Must be fast.

```
LOCK ACQUIRED

1. Determine direction (fwd/rev) from local_ips
2. Compute session_key from sorted 5-tuple
3. Look up FlowState in _flows dict
4. If not found:
   a. If _flows at max_active_flows → evict oldest by last_ts, emit it
   b. Detect app_proto via DPI/port heuristic
   c. Create new FlowState with uuid4 flow_id
5. Update flow.last_ts
6. Increment flow.total_pkts

── Volume ──
7. If direction == fwd: pkts_fwd++, bytes_fwd += pkt_len, track first_fwd_ts
8. If direction == rev: pkts_rev++, bytes_rev += pkt_len, track first_rev_ts

── TCP Flags ──
9. Parse individual flags from tcp_flags byte:
   is_syn = tcp_flags & 0x02
   is_fin = tcp_flags & 0x01
   is_rst = tcp_flags & 0x04
   is_psh = tcp_flags & 0x08
   is_ack = tcp_flags & 0x10

10. If SYN:
    syn_count++
    If fwd and first SYN → store syn_ts, store window_size_init from tcp_window
    If rev and first SYN-ACK → store syn_ack_ts

11. If FIN:
    fin_count++
    If state == ACTIVE → state = FIN_WAIT, drain_until = ts + flow_drain_fin_s

12. If RST:
    rst_count++
    If first RST → store first_rst_pkt_num = total_pkts
    state = CLOSING, drain_until = ts + flow_drain_rst_s

13. If PSH: psh_count++, current_psh_run++, max_psh_run = max(max_psh_run, current_psh_run)
    Else: current_psh_run = 0

14. If ACK-only (ACK set, no SYN/FIN/RST/PSH, payload_len==0): ack_only_count++

15. syn_to_data tracking:
    If not _seen_data and payload_len > 0:
        _seen_data = True
        syn_to_data_count = total_pkts - 1

── Forward IAT ──
16. If fwd and prev_fwd_ts is not None:
    iat = ts - prev_fwd_ts
    Append to fwd_iats (capped at 512 entries)
17. If fwd: prev_fwd_ts = ts

── Event Packet Collection (CNN) ──
18. is_event = (payload_len > 0) OR (SYN or FIN or RST)
19. If is_event and len(event_packets) < max_event_pkts:
    Append EventPacket(seq_idx=len(event_packets), ts, direction,
                       payload_len, pkt_len, tcp_flags, tcp_window,
                       payload[:256])

── Payload Analysis ──
20. If payload_len > 0:
    a. Compute Shannon entropy of payload
    b. If fwd:
       - If first_fwd_payload is None → store payload[:256]
       - Accumulate: fwd_entropy_sum += entropy, fwd_entropy_count++
       - If entropy >= 7.0 → fwd_high_entropy++
       - Append payload_len to fwd_payload_sizes (capped 512)
    c. If rev:
       - rev_entropy_sum += entropy, rev_entropy_count++
       - Append payload_len to rev_payload_sizes (capped 512)
    d. Size histogram:
       1–63 → hist_tiny++
       64–255 → hist_small++
       256–1023 → hist_medium++
       1024–1499 → hist_large++
       ≥1500 → hist_full++
    e. Retransmit estimation: add (payload_len, direction) to retransmit_set

── Fingerprint Extraction ──
21. If fwd and payload_len > 0:
    extract_tls_fingerprint(payload, flow.fp)
    extract_http_fingerprint(payload, flow.fp)
22. If rev and payload_len > 0:
    extract_http_fingerprint(payload, flow.fp, is_response=True)

── Force-Emit ──
23. If total_pkts >= max_flow_pkts → pop flow from table, emit it

LOCK RELEASED
```

### sweep() — Periodic Timeout Check

Called every 1 second by the sweep thread.

```
LOCK ACQUIRED
For each flow in _flows:
    If drain_until is set and now >= drain_until → collect for emission
    Elif (now - last_ts) > flow_timeout_s → collect for emission
LOCK RELEASED

For each collected flow: _emit_flow(flow)
```

### _emit_flow() — Feature Extraction + Buffer Write

Called when a flow completes (timeout, FIN drain, RST drain, or force-emit). This is where all ML features are computed.

```
1. Compute XGB features dict (75 features) → see "XGB Feature Extraction" section
2. Compute CNN token rows (up to 128 dicts) → see "CNN Token Computation" section
3. Extract fingerprint dict → FingerprintState.to_dict() with flow_id set
4. Write all three to buffer:
   buffer.insert_flow(features_dict)
   buffer.insert_packets(token_rows)
   buffer.insert_fingerprint(fp_dict)
5. Update source_stats:
   buffer.upsert_source_stats(src_ip, dst_port, app_proto, dst_ip, pps, first_ts)
6. Increment flows_emitted counter
```

---

## XGB Feature Extraction — 75 Features

All features computed at flow emission from accumulated FlowState. Matches DFI_XGB_v1_Spec column-for-column.

### RTT Estimation

```python
if TCP and syn_ts and syn_ack_ts:
    rtt_ms = (syn_ack_ts - syn_ts) * 1000
elif first_rev_ts and first_fwd_ts:
    rtt_ms = (first_rev_ts - first_fwd_ts) * 1000
else:
    rtt_ms = None  # → ClickHouse Nullable, XGBoost native NaN
```

### F1. Target & Protocol (3 features)

| Feature | Type | Computation |
|---------|------|-------------|
| `dst_port` | uint16 | Honeypot port (from flow) |
| `ip_proto` | uint8 | 6=TCP, 17=UDP, 1=ICMP |
| `app_proto` | uint8 | DPI result or port heuristic |

### F2. Volume (8 features)

| Feature | Type | Computation |
|---------|------|-------------|
| `pkts_fwd` | uint32 | Counter from FlowState |
| `pkts_rev` | uint32 | Counter from FlowState |
| `bytes_fwd` | uint32 | Counter from FlowState |
| `bytes_rev` | uint32 | Counter from FlowState |
| `bytes_per_pkt_fwd` | float32 | `bytes_fwd / max(pkts_fwd, 1)` |
| `bytes_per_pkt_rev` | float32 | `bytes_rev / pkts_rev` if pkts_rev > 0, else None |
| `pkt_ratio` | float32 | `pkts_fwd / max(pkts_rev, 1)` |
| `byte_ratio` | float32 | `bytes_fwd / max(bytes_rev, 1)` |

### F3. Timing (10 features)

| Feature | Type | Computation |
|---------|------|-------------|
| `duration_ms` | uint32 | `max(0, int((last_ts - first_ts) * 1000))` |
| `rtt_ms` | float32? | See RTT estimation above. None if no response. |
| `iat_fwd_mean_ms` | float32? | `mean(fwd_iats * 1000)`. None if no IATs. |
| `iat_fwd_std_ms` | float32? | `std(fwd_iats * 1000)`. None if < 2 IATs. |
| `think_time_mean_ms` | float32? | `mean(max(0, iat_ms - rtt_ms) for each fwd_iat)`. None if no RTT. |
| `think_time_std_ms` | float32? | `std(think_times)`. None if < 2 or no RTT. |
| `iat_to_rtt` | float32? | `iat_fwd_mean_ms / max(rtt_ms, 0.1)`. None if no RTT. |
| `pps` | float32 | `total_pkts / max(duration_s, 0.001)` |
| `bps` | float32 | `(bytes_fwd + bytes_rev) / max(duration_s, 0.001)` |
| `payload_rtt_ratio` | float32? | `n_payload_pkts / max(duration_ms / rtt_ms, 1)`. None if no RTT. |

**Why think_time matters:** An SSH brute-forcer in São Paulo (300ms RTT) has raw IAT ~305ms. Same tool in Frankfurt (20ms RTT) has IAT ~25ms. Raw IATs differ 12×. But `think_time` is ~5ms for both — the attacker's behavioral pace with geography removed.

### F4. Size Shape (14 features)

| Feature | Type | Computation |
|---------|------|-------------|
| `n_events` | uint16 | `len(event_packets)` |
| `fwd_size_mean` | float32? | `mean(fwd_payload_sizes)`. None if empty. |
| `fwd_size_std` | float32? | `std(fwd_payload_sizes)`. None if < 2. |
| `fwd_size_min` | uint16 | `min(fwd_payload_sizes)`. 0 if empty. |
| `fwd_size_max` | uint16 | `max(fwd_payload_sizes)`. 0 if empty. |
| `rev_size_mean` | float32? | `mean(rev_payload_sizes)`. None if empty. |
| `rev_size_std` | float32? | `std(rev_payload_sizes)`. None if < 2. |
| `rev_size_max` | uint16 | `max(rev_payload_sizes)`. 0 if empty. |
| `hist_tiny` | uint16 | Payload 1–63 bytes |
| `hist_small` | uint16 | 64–255 bytes |
| `hist_medium` | uint16 | 256–1023 bytes |
| `hist_large` | uint16 | 1024–1499 bytes |
| `hist_full` | uint16 | ≥ 1500 bytes |
| `frac_full` | float32 | `hist_full / max(n_events, 1)` |

### F5. TCP Behavior (11 features)

| Feature | Type | Computation |
|---------|------|-------------|
| `syn_count` | uint8 | Counter. >1 → retransmit or flood. |
| `fin_count` | uint8 | Counter |
| `rst_count` | uint8 | Counter |
| `psh_count` | uint16 | Counter (data segments) |
| `ack_only_count` | uint16 | Pure ACK, zero payload |
| `conn_state` | uint8 | Computed from flags (see table below) |
| `rst_frac` | float32? | `first_rst_pkt_num / total_pkts`. None if no RST. |
| `syn_to_data` | uint8 | Packets between SYN and first payload |
| `psh_burst_max` | uint8 | Longest consecutive PSH run |
| `retransmit_est` | uint16 | `max(0, len(retransmit_set) - n_events)` |
| `window_size_init` | uint16 | TCP window from SYN. OS/tool fingerprint. |

**conn_state computation:**

```python
def compute_conn_state(flow):
    if ip_proto != 6: return 7                           # Non-TCP
    if syn_count > 1 and no syn_ack: return 6            # SYN flood/repeated probe
    if no syn_ack: return 0                              # Port closed/filtered
    if syn_ack and no data: return 1                     # Port open, attacker disconnected
    if data and psh_count <= 5:
        return 2 if has_fin else 3                       # Short session
    if psh_count > 5:
        return 4 if has_fin else 5                       # Extended session
```

### F6. Payload Content (8 features)

| Feature | Type | Computation |
|---------|------|-------------|
| `entropy_first` | float32? | Shannon entropy of first_fwd_payload (0.0–8.0). None if no payload. |
| `entropy_fwd_mean` | float32? | `fwd_entropy_sum / fwd_entropy_count`. None if 0. |
| `entropy_rev_mean` | float32? | `rev_entropy_sum / rev_entropy_count`. None if 0. |
| `printable_frac` | float32? | Fraction of bytes 0x20–0x7E in first_fwd_payload. None if no payload. |
| `null_frac` | float32? | Fraction of 0x00 bytes in first_fwd_payload. None if no payload. |
| `byte_std` | float32? | Std dev of byte values (0–255) in first_fwd_payload. None if no payload. |
| `high_entropy_frac` | float32? | `fwd_high_entropy / fwd_entropy_count`. None if 0. |
| `payload_len_first` | uint16 | `len(first_fwd_payload)`. 0 if none. |

**Shannon entropy:**
```python
def shannon_entropy(data: bytes) -> float:
    counts = [0] * 256
    for b in data: counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * log2(p)
    return entropy   # 0.0 (all same byte) to 8.0 (uniform random)
```

### NaN Convention

All Nullable features use Python `None` in the flow dict. The REST API omits None keys from JSON (DFI2 treats missing keys as NULL). The export module writes empty string. XGBoost handles NaN natively — do NOT impute.

---

## CNN Token Computation — 5 Channels × 128 Positions

Computed from `event_packets` at flow emission. One row per event packet, max 128 rows per flow. Remaining positions are zero-padded by the consumer.

### Event Packet Selection Rule

A packet is an "event packet" if:
- `payload_len > 0`, OR
- TCP flags include SYN (0x02), FIN (0x01), or RST (0x04)

Pure ACKs with zero payload are excluded. Maximum 128 event packets retained per flow (first 128).

### Channel 1: `size_dir_token` — Directional Size (Int8, range -11 to +11)

```python
def size_dir_token(pkt: EventPacket) -> int:
    size = pkt.payload_len if pkt.payload_len > 0 else pkt.pkt_len
    if size <= 0: size = 1
    raw_bin = floor(log2(size))
    b = min(11, max(1, raw_bin - 4))
    return pkt.direction * b   # +1..+11 for fwd, -1..-11 for rev
```

Vocab size: 23 (-11 to +11). 0 = padding.

| Bin | Payload Size | Typical Content |
|-----|-------------|-----------------|
| 1 | 1–63 | SYN/FIN/RST, tiny probes |
| 2 | 64–127 | SSH banner, DNS query |
| 3 | 128–255 | Small HTTP requests |
| 4 | 256–511 | Medium payloads |
| 5 | 512–1023 | Half-MSS |
| 6 | 1024–2047 | Near-MSS / standard MTU |
| 7 | 2048–4095 | Jumbo fragments |
| 8 | 4096–8191 | Large transfers |
| 9 | 8192–16383 | Jumbo frames |
| 10 | 16384–32767 | TSO/GRO offload |
| 11 | 32768+ | Capped |

### Channel 2: `flag_token` — TCP Control Flags (UInt8, range 0–16)

```python
def flag_token(pkt: EventPacket) -> int:
    token = 0
    if pkt.tcp_flags & 0x02: token |= 1   # SYN
    if pkt.tcp_flags & 0x01: token |= 2   # FIN
    if pkt.tcp_flags & 0x04: token |= 4   # RST
    if pkt.tcp_flags & 0x08: token |= 8   # PSH
    if token == 0: token = 16              # PRESENT (real packet, no control flags)
    return token
```

Vocab size: 17 (0–16). 0 = padding. Bitwise combos possible (e.g., 3 = SYN+FIN).

### Channel 3: `iat_log_ms_bin` — Absolute IAT (UInt8, range 0–8)

```python
def iat_log_ms_bin(seq_idx: int, iat_ms: float | None) -> int:
    if seq_idx == 0:       return 1   # first packet, no IAT
    if iat_ms is None:     return 1
    if iat_ms < 1:         return 2   # wire-speed burst
    if iat_ms < 10:        return 3   # fast automated tool
    if iat_ms < 100:       return 4   # typical LAN RTT
    if iat_ms < 1000:      return 5   # WAN RTT, brute-force
    if iat_ms < 10000:     return 6   # slow tool, human thinking
    if iat_ms < 60000:     return 7   # interactive pause
    return 8                           # long idle
```

Vocab size: 9 (0–8). 0 = padding. IAT computed between consecutive event packets (not all packets): `iat_ms = (event_pkt[i].ts - event_pkt[i-1].ts) * 1000`.

### Channel 4: `iat_rtt_bin` — RTT-Normalized IAT (UInt8, range 0–9)

```python
def iat_rtt_bin(seq_idx: int, iat_ms: float | None, rtt_ms: float | None) -> int:
    if seq_idx == 0 or rtt_ms is None or rtt_ms <= 0 or iat_ms is None:
        return 1                       # unknown
    ratio = iat_ms / rtt_ms
    if ratio < 0.5:    return 2        # pipelining
    if ratio < 1:      return 3        # request-response lockstep
    if ratio < 2:      return 4        # slightly paced
    if ratio < 5:      return 5        # rate-limited tool
    if ratio < 20:     return 6        # slow tool / short human pause
    if ratio < 100:    return 7        # long human pause
    if ratio < 1000:   return 8        # very long pause
    return 9                           # session idle
```

Vocab size: 10 (0–9). 0 = padding. When RTT unavailable, all positions get bin 1 — Channel 3 still provides temporal signal.

### Channel 5: `entropy_bin` — Payload Entropy (UInt8, range 0–6)

```python
def entropy_bin(payload: bytes | None) -> int:
    if not payload: return 0
    ent = shannon_entropy(payload)
    if ent < 1.0:   return 1    # constant/near-constant
    if ent < 3.0:   return 2    # low entropy (simple ASCII)
    if ent < 5.0:   return 3    # moderate (structured text)
    if ent < 6.5:   return 4    # moderate-high (mixed content)
    if ent < 7.5:   return 5    # high (compressed/encrypted)
    return 6                     # near-random (TLS, random padding)
```

Vocab size: 7 (0–6). 0 = padding / no payload.

### Token Row Output

One dict per event packet:
```python
{
    "flow_id": "uuid-string",
    "seq_idx": 0,              # 0..127
    "ts": "2025-02-26T14:30:22.123Z",
    "direction": 1,            # 1=fwd, -1=rev
    "payload_len": 48,
    "pkt_len": 100,
    "tcp_flags": 0x12,
    "tcp_window": 65535,
    "size_dir_token": 1,       # Channel 1
    "flag_token": 1,           # Channel 2
    "iat_log_ms_bin": 1,       # Channel 3
    "iat_rtt_bin": 1,          # Channel 4
    "entropy_bin": 3,          # Channel 5
    "iat_ms": None,            # raw, for re-binning
    "payload_entropy": 4.2,    # raw, for re-binning
}
```

---

## Fingerprint Extraction

Extracted from the first qualifying packet of each type. Once extracted, a flag prevents re-extraction from later packets in the same flow.

### TLS Fingerprint (from ClientHello on port 443)

**Trigger:** Forward payload starts with `0x16` (TLS content type: Handshake) and offset+5 is `0x01` (ClientHello).

**Parse path through the ClientHello:**
```
Offset 0: Content type (0x16)
Offset 1-2: Record version (e.g., 0x0301)
Offset 3-4: Record length
Offset 5: Handshake type (0x01 = ClientHello)
Offset 6-8: Handshake length (3 bytes)
Offset 9-10: Client version (e.g., 0x0303 for TLS 1.2)
Offset 11-42: Random (32 bytes)
Offset 43: Session ID length (1 byte)
Offset 43+1+sid_len: Cipher suites length (2 bytes, big-endian)
  → Read cs_len/2 cipher suite IDs (2 bytes each)
  → Filter out GREASE values (where low nibbles are 0x0a0a)
After ciphers: Compression methods length (1 byte) + methods
After compression: Extensions length (2 bytes)
  → Walk extensions: type(2) + length(2) + data(length)
  → Count extensions
  → If type == 0 (SNI): set tls_has_sni = 1
  → If type == 43 (supported_versions): check for 0x0304 (TLS 1.3)
```

**Output fields:**

| Field | Computation |
|-------|-------------|
| `ja3_hash` | MD5 of `"{tls_version},{comma-joined cipher IDs}"` (GREASE filtered) |
| `tls_version` | 0=none, 10=SSL3(0x0300), 11=TLS1.0(0x0301), 12=TLS1.2(0x0303), 13=TLS1.3(0x0304 in supported_versions) |
| `tls_cipher_count` | cs_len / 2 |
| `tls_ext_count` | Number of extensions parsed |
| `tls_has_sni` | 1 if SNI extension present, 0 otherwise |

**256-byte snap length is sufficient:** Typical ClientHello is ~200 bytes. Cipher list + extensions may extend beyond 256B in which case we extract what we can — partial extraction is still valuable.

### HTTP Fingerprint (from request on ports 80, 443, 5985, 5986)

**Trigger (request):** Forward payload. Check if first word before space matches known HTTP method.

**Parse:**
```
1. Find first space → method bytes before it
2. Map method: GET=1, POST=2, HEAD=3, PUT=4, everything else=5
3. Parse request line up to \r\n → extract URI → measure length
4. Count \r\n occurrences in header block (between first \r\n and \r\n\r\n) → header_count
5. Find "User-Agent:" header (case-insensitive) → MD5 hash of value → http_ua_hash
6. Check for Content-Length > 0 or Transfer-Encoding → http_has_body = 1
```

**Trigger (response):** Reverse payload starts with `HTTP/`. Extract status code from bytes 9-11.

**TLS visibility advantage:** Port 443 flows get JA3 from encrypted ClientHello via PCAP. IIS terminates TLS, so the evidence collector can also parse IIS W3C logs for the decrypted HTTP request details. The agent merges these at flow emission. This gives 6 additional discriminative features per HTTPS flow that Hunter (capturing externally) physically cannot extract.

### SMB Detection

Port 445 payloads starting with `\xffSMB` (SMB1) or `\xfeSMB` (SMB2/3) → app_proto = 10. No explicit SMB fingerprint fields in current schema.

### DNS Detection

Port 53, UDP: app_proto = 4. Currently tracked via port heuristic only.

### FingerprintState Fields

```python
@dataclass
class FingerprintState:
    ja3_hash: str | None = None
    tls_version: int = 0          # 0/10/11/12/13
    tls_cipher_count: int = 0
    tls_ext_count: int = 0
    tls_has_sni: int = 0          # 0/1
    hassh_hash: str | None = None # Always None on Windows (no SSH)
    ssh_kex_count: int = 0        # Always 0 on Windows
    http_method: int = 0          # 0=none, 1=GET, 2=POST, 3=HEAD, 4=PUT, 5=other
    http_uri_len: int = 0
    http_header_count: int = 0
    http_ua_hash: str | None = None  # MD5 of User-Agent value
    http_has_body: int = 0        # 0/1
    http_status: int = 0          # First response status (200, 401, etc.)
    dns_qtype: int = 0
    dns_qname_len: int = 0
    _tls_extracted: bool = False  # internal flag, not serialized
    _http_extracted: bool = False # internal flag, not serialized
```

---

## Module 3: Evidence Collector (`evidence.py`)

Subscribes to Windows Event Log channels via `win32evtlog.EvtSubscribe()` (pywin32). Each event is parsed from XML, the attacker's source IP is extracted, and the event is normalized to a standard schema before writing to the buffer.

### Normalized Event Schema

```json
{
    "ts":            "2025-02-26T14:30:22.123Z",
    "vm_id":         "win-honey-01",
    "source_ip":     "203.0.113.42",
    "source_port":   0,
    "service":       "rdp",
    "event_type":    "auth_failure",
    "evidence_bits": 1,
    "raw_event_id":  4625,
    "raw_channel":   "Security",
    "detail":        { "logon_type": "10", "target_user": "administrator" }
}
```

### Event Dispatch Table

| Windows Event ID | Channel | Handler | event_type | evidence_bits |
|------------------|---------|---------|------------|---------------|
| 4624 | Security | Logon success | `auth_success` | 0x02 (bit 1) |
| 4625 | Security | Logon failure | `auth_failure` | 0x01 (bit 0) |
| 4672 | Security | Special logon (priv) | `priv_escalation` | 0x40 (bit 6) |
| 4688 | Security | Process creation | `process_create` / `suspicious_cmd` / `file_download` | 0x04 / 0x10 / 0x30 |
| 4697 | Security | Service install | `service_install` | 0x08 (bit 3) |
| 4728 | Security | Member added to group | `priv_escalation` | 0x40 (bit 6) |
| 4732 | Security | Member added to group | `priv_escalation` | 0x40 (bit 6) |
| 5140 | Security | Share accessed | `share_access` | 0x00 (context) |
| 5145 | Security | Share object checked | `share_access` | 0x00 (context) |
| 7045 | System | Service installed | `service_install` | 0x08 (bit 3) |
| 131 | RdpCoreTS | RDP connection (pre-auth) | `connection` | 0x00 (context, for KNOCK) |
| 21/24/25 | TS-LSM | Session events | `session_event` | 0x00 (context) |
| 4104 | PowerShell | Script block | `suspicious_cmd` / `file_download` | 0x10 / 0x30 |
| 18456 | Application | MSSQL login failure | `auth_failure` | 0x01 |
| 18454 | Application | MSSQL login success | `auth_success` | 0x02 |

### evidence_mask Bitmask

| Bit | Value | Signal |
|-----|-------|--------|
| 0 | 0x01 | auth_failure |
| 1 | 0x02 | auth_success |
| 2 | 0x04 | process_create |
| 3 | 0x08 | service_install |
| 4 | 0x10 | suspicious_command |
| 5 | 0x20 | file_download |
| 6 | 0x40 | privilege_escalation |
| 7 | 0x80 | lateral_movement |

### Source IP Extraction

Different events store the attacker IP in different XML fields:

| Event ID | IP Source | XPath |
|----------|-----------|-------|
| 4624 | Direct | `EventData/Data[@Name='IpAddress']` |
| 4625 | Direct | `EventData/Data[@Name='IpAddress']` |
| 4672 | LogonId chain | Look up SubjectLogonId in map |
| 4688 | LogonId chain | Look up SubjectLogonId in map |
| 4697 | LogonId chain | Best-effort recent logon |
| 5140/5145 | Direct | `EventData/Data[@Name='IpAddress']` |
| 7045 | LogonId chain | Best-effort recent logon |
| RdpCoreTS 131 | Direct | `EventData/Data[@Name='ClientIP']` |
| TS-LSM 21/25 | Regex parse | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` from message |
| 18456 | Regex parse | `\[CLIENT:\s*(\d+\.\d+\.\d+\.\d+)\]` from message |
| 4104 | LogonId chain | Best-effort (use most recent WinRM/RDP logon) |

### LogonId Chaining

Events 4672, 4688, 7045, 4104 don't contain source IP. The agent maintains an in-memory `logon_id → (source_ip, service)` map populated by 4624 events:

```
4624 (Type 10, IP=203.0.113.42, LogonId=0x1A2B3C)
    → map["0x1A2B3C"] = ("203.0.113.42", "rdp")

4688 (SubjectLogonId=0x1A2B3C, CommandLine="whoami")
    → look up map["0x1A2B3C"] → ("203.0.113.42", "rdp")
    → emit: source_ip="203.0.113.42", service="rdp"
```

The map is persisted to SQLite (`logon_map` table) for restart survival. Entries pruned after `logon_map_ttl_hours` (default 24).

### Logon Type → Service Mapping

| Logon Type | Service |
|------------|---------|
| 10 | rdp |
| 3 | smb |
| 2 | console |
| other | system |

### Suspicious Command Patterns

Case-insensitive regex. All patterns are intentionally broad — false positives on a honeypot are features, not bugs.

**Bit 4 (suspicious_command):**
```
(cmd|powershell|pwsh).*(/c|/k|-enc|-e\s)
(nc|ncat|netcat)\s.*(-e|-c)
(wget|curl|invoke-webrequest|iwr)\s
(certutil)\s.*(-urlcache|-decode)
(bitsadmin)\s.*/transfer
(chmod|bash|/bin/sh)
(whoami|net\s+(user|localgroup|group))
(reg\s+(add|delete|query).*run)
(schtasks\s*/create)
(wmic\s+process\s+call\s+create)
(mshta|regsvr32|rundll32)\s
(python|perl|ruby)\s.*(-c|-e)
base64
(reverse|bind)\s*shell
(mimikatz|lazagne|procdump)
```

**Bit 5 (file_download) — also sets bit 4:**
```
(certutil)\s.*-urlcache
(bitsadmin)\s.*/transfer
(wget|curl|invoke-webrequest|iwr)\s+https?://
(powershell|pwsh).*downloadfile
(powershell|pwsh).*downloadstring
(start-bitstransfer)
```

### IIS W3C Log Tailing

Separate daemon sub-thread. Tails the most recent `u_ex*.log` in the configured IIS log directory.

Parse each line (space-delimited W3C format):
- `parts[2]` = client IP
- `parts[4]` = method
- `parts[5]` = URI
- `parts[7]` = status code

Emit `auth_failure` for status 401, `auth_success` for status 200 with username present, `suspicious_cmd` if URI matches suspicious patterns.

### Graceful Degradation

If `pywin32` is not installed → log warning, thread sleeps until stop. The agent continues to function for PCAP-only operation. This is important for testability on non-Windows platforms.

---

## Module 4: SQLite Buffer (`buffer.py`)

All data is stored in a single SQLite database with WAL mode for concurrent read/write. Located on the management-VLAN disk.

### Pragmas

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA busy_timeout = 5000;
```

### Table: `events`

```sql
CREATE TABLE events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,          -- ISO 8601
    vm_id         TEXT NOT NULL,
    source_ip     TEXT,
    source_port   INTEGER DEFAULT 0,
    service       TEXT NOT NULL,          -- rdp, smb, winrm, mssql, iis, system
    event_type    TEXT NOT NULL,          -- auth_failure, auth_success, etc.
    evidence_bits INTEGER NOT NULL,
    raw_event_id  INTEGER,
    raw_channel   TEXT,
    detail_json   TEXT,                   -- JSON-encoded service-specific fields
    pulled        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_events_pulled ON events (pulled, seq);
```

### Table: `pcap_flows`

One row per completed flow. Stores all 75 XGB features plus identity and metadata.

```sql
CREATE TABLE pcap_flows (
    flow_id            TEXT PRIMARY KEY,
    session_key        TEXT NOT NULL,
    src_ip             TEXT NOT NULL,
    dst_ip             TEXT NOT NULL,
    src_port           INTEGER NOT NULL,
    dst_port           INTEGER NOT NULL,
    ip_proto           INTEGER NOT NULL,
    app_proto          INTEGER NOT NULL DEFAULT 0,
    first_ts           TEXT NOT NULL,        -- ISO 8601
    last_ts            TEXT NOT NULL,

    -- F2. Volume (4 features)
    pkts_fwd           INTEGER NOT NULL,
    pkts_rev           INTEGER NOT NULL,
    bytes_fwd          INTEGER NOT NULL,
    bytes_rev          INTEGER NOT NULL,

    -- F3. Timing (10 features, Nullable where noted in spec)
    rtt_ms             REAL,                 -- NULL = unknown
    duration_ms        INTEGER NOT NULL,
    iat_fwd_mean_ms    REAL,
    iat_fwd_std_ms     REAL,
    think_time_mean_ms REAL,
    think_time_std_ms  REAL,
    iat_to_rtt         REAL,
    pps                REAL NOT NULL,
    bps                REAL NOT NULL,
    payload_rtt_ratio  REAL,

    -- F4. Size shape (14 features)
    n_events           INTEGER NOT NULL,
    fwd_size_mean      REAL,
    fwd_size_std       REAL,
    fwd_size_min       INTEGER NOT NULL DEFAULT 0,
    fwd_size_max       INTEGER NOT NULL DEFAULT 0,
    rev_size_mean      REAL,
    rev_size_std       REAL,
    rev_size_max       INTEGER NOT NULL DEFAULT 0,
    hist_tiny          INTEGER NOT NULL DEFAULT 0,
    hist_small         INTEGER NOT NULL DEFAULT 0,
    hist_medium        INTEGER NOT NULL DEFAULT 0,
    hist_large         INTEGER NOT NULL DEFAULT 0,
    hist_full          INTEGER NOT NULL DEFAULT 0,
    frac_full          REAL NOT NULL DEFAULT 0,

    -- F5. TCP behavior (11 features)
    syn_count          INTEGER NOT NULL DEFAULT 0,
    fin_count          INTEGER NOT NULL DEFAULT 0,
    rst_count          INTEGER NOT NULL DEFAULT 0,
    psh_count          INTEGER NOT NULL DEFAULT 0,
    ack_only_count     INTEGER NOT NULL DEFAULT 0,
    conn_state         INTEGER NOT NULL DEFAULT 0,
    rst_frac           REAL,
    syn_to_data        INTEGER NOT NULL DEFAULT 0,
    psh_burst_max      INTEGER NOT NULL DEFAULT 0,
    retransmit_est     INTEGER NOT NULL DEFAULT 0,
    window_size_init   INTEGER NOT NULL DEFAULT 0,

    -- F6. Payload content (8 features)
    entropy_first      REAL,
    entropy_fwd_mean   REAL,
    entropy_rev_mean   REAL,
    printable_frac     REAL,
    null_frac          REAL,
    byte_std           REAL,
    high_entropy_frac  REAL,
    payload_len_first  INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    capture_source     INTEGER NOT NULL DEFAULT 1,  -- 0=Hunter, 1=VM
    emitted_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    pulled             INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_flows_pulled ON pcap_flows (pulled, emitted_at);
CREATE INDEX idx_flows_src    ON pcap_flows (src_ip, first_ts);
```

### Table: `pcap_packets`

One row per CNN event packet. Up to 128 rows per flow.

```sql
CREATE TABLE pcap_packets (
    flow_id         TEXT    NOT NULL,
    seq_idx         INTEGER NOT NULL,     -- 0..127
    ts              TEXT    NOT NULL,
    direction       INTEGER NOT NULL,     -- 1=fwd, -1=rev
    payload_len     INTEGER NOT NULL,
    pkt_len         INTEGER NOT NULL,
    tcp_flags       INTEGER NOT NULL,
    tcp_window      INTEGER NOT NULL DEFAULT 0,

    size_dir_token  INTEGER NOT NULL,     -- Channel 1: [-11..+11]
    flag_token      INTEGER NOT NULL,     -- Channel 2: [0..16]
    iat_log_ms_bin  INTEGER NOT NULL,     -- Channel 3: [0..8]
    iat_rtt_bin     INTEGER NOT NULL,     -- Channel 4: [0..9]
    entropy_bin     INTEGER NOT NULL DEFAULT 0,  -- Channel 5: [0..6]

    iat_ms          REAL,                 -- raw, for re-binning
    payload_entropy REAL,                 -- raw, for re-binning

    pulled          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (flow_id, seq_idx)
);
CREATE INDEX idx_pkts_pulled ON pcap_packets (pulled, flow_id);
```

### Table: `pcap_fingerprints`

One row per flow. Protocol-specific handshake features.

```sql
CREATE TABLE pcap_fingerprints (
    flow_id          TEXT PRIMARY KEY,
    ja3_hash         TEXT,
    tls_version      INTEGER NOT NULL DEFAULT 0,
    tls_cipher_count INTEGER NOT NULL DEFAULT 0,
    tls_ext_count    INTEGER NOT NULL DEFAULT 0,
    tls_has_sni      INTEGER NOT NULL DEFAULT 0,
    hassh_hash       TEXT,
    ssh_kex_count    INTEGER NOT NULL DEFAULT 0,
    http_method      INTEGER NOT NULL DEFAULT 0,
    http_uri_len     INTEGER NOT NULL DEFAULT 0,
    http_header_count INTEGER NOT NULL DEFAULT 0,
    http_ua_hash     TEXT,
    http_has_body    INTEGER NOT NULL DEFAULT 0,
    http_status      INTEGER NOT NULL DEFAULT 0,
    dns_qtype        INTEGER NOT NULL DEFAULT 0,
    dns_qname_len    INTEGER NOT NULL DEFAULT 0,
    pulled           INTEGER NOT NULL DEFAULT 0
);
```

### Table: `source_stats`

Per-source-IP running aggregates. Updated incrementally at each flow emission.

```sql
CREATE TABLE source_stats (
    src_ip       TEXT PRIMARY KEY,
    flow_count   INTEGER NOT NULL DEFAULT 0,
    unique_ports TEXT NOT NULL DEFAULT '[]',    -- JSON array of ints
    unique_protos TEXT NOT NULL DEFAULT '[]',   -- JSON array of ints
    unique_dsts  TEXT NOT NULL DEFAULT '[]',    -- JSON array of strings
    first_seen   TEXT,
    last_seen    TEXT,
    sum_pps      REAL NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
```

Upsert logic: If src_ip exists → increment flow_count, union unique_ports/protos/dsts (parse JSON, add, re-serialize), min first_seen, max last_seen, sum_pps += pps. If not exists → INSERT with initial values.

### Table: `logon_map`

Persisted LogonId→IP map for evidence collector restart survival.

```sql
CREATE TABLE logon_map (
    logon_id   TEXT PRIMARY KEY,
    source_ip  TEXT NOT NULL,
    service    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
```

### Retention Cleanup

`buffer.cleanup(retention_days)` called every 5 minutes:
1. DELETE from events WHERE pulled=1 AND ts < now-retention_days
2. DELETE from pcap_flows WHERE pulled=1 AND emitted_at < now-retention_days
3. DELETE orphaned pcap_packets (flow_id not in pcap_flows)
4. DELETE orphaned pcap_fingerprints
5. DELETE flow_state WHERE last_activity > 300 seconds old
6. PRAGMA wal_checkpoint(TRUNCATE)

### Thread Safety

One `sqlite3.Connection` per thread via `threading.local()`. SQLite WAL mode allows concurrent readers + one writer. The `buffer.transaction()` context manager handles commit/rollback.

---

## Module 5: REST API (`api.py`)

Flask app. All endpoints require `X-DFI-Token` header (if configured). Binds to `mgmt_nic_ip` only. Served by Waitress (4 threads) or Flask dev server as fallback.

### Endpoints

#### GET /api/health

Returns agent status, capture metrics, and buffer stats.

```json
{
    "vm_id": "win-honey-01",
    "uptime_sec": 3600,
    "pcap": {
        "capture_running": true,
        "capture_interface": "Ethernet0",
        "active_flows": 142,
        "completed_flows_total": 58203,
        "unpulled_flows": 1204,
        "unpulled_packets": 38912,
        "unpulled_fingerprints": 1204,
        "packets_captured": 892341,
        "packets_dropped_npcap": 0,
        "source_ips_tracked": 312,
        "buffer_db_size_mb": 45.2
    },
    "evidence": {
        "events_buffered": 12804,
        "unpulled_events": 302,
        "logon_map_size": 48,
        "events_processed": 12804,
        "ip_extraction_failures": 23
    },
    "buffer": {
        "db_size_mb": 45.2,
        "wal_size_mb": 2.1
    }
}
```

#### GET /api/events

Query params: `since_seq` (int, default 0), `limit` (int, default 5000, max 50000)

Returns evidence events ordered by sequence number.

#### POST /api/ack/events

Body: `{"through_seq": 12345}`

Marks all events with seq ≤ through_seq as pulled.

#### GET /api/flows

Query params: `since_ts` (ISO 8601), `limit` (int, default 5000, max 50000), `pulled` (0 or 1, default 0)

Returns completed flows with all 75 XGB features. None/NaN values are omitted from JSON — the consumer treats missing keys as NULL.

#### GET /api/packets

Query params (two modes):
- By flow: `flow_ids=id1,id2,...` + `limit`
- By time: `since_flow_ts` + `limit` + `pulled`

Returns CNN event packets with all 5 channel tokens.

#### GET /api/fingerprints

Query params: `flow_ids=id1,id2,...` or `since_ts` + `limit` + `pulled`

#### POST /api/ack/flows

Body: `{"flow_ids": ["uuid1", "uuid2", ...]}`

**Atomic ack:** marks flows + associated packets + fingerprints as pulled in a single transaction. This prevents orphaned packets from flows acked before packets are fetched.

#### GET /api/source_stats

Query params: `updated_since` (ISO 8601)

Returns per-source-IP aggregates with JSON arrays for unique_ports/protos/dsts.

#### GET /api/pcap/stats

Detailed pipeline stats for operational dashboards.

### DFI2 Pull Pattern

1. `GET /api/flows?pulled=0&limit=5000` → get flow_ids
2. `GET /api/packets?flow_ids=id1,id2,...` (batch 200 IDs per request to avoid URI length limits)
3. `GET /api/fingerprints?flow_ids=id1,id2,...`
4. INSERT into ClickHouse dfi.flows_buffer / packets_buffer / fingerprints_buffer
5. `POST /api/ack/flows {"flow_ids": [...]}`
6. Repeat every 5 seconds

---

## Module 6: Standalone Export (`export.py`)

Generates XGB and CNN format CSVs directly from the SQLite buffer without DFI2 or ClickHouse.

### XGB Export

Column order matches DFI_XGB_v1_Spec:
```
flow_id, session_key,
dst_port, ip_proto, app_proto,
pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
rtt_ms, duration_ms, iat_fwd_mean_ms, iat_fwd_std_ms,
think_time_mean_ms, think_time_std_ms, iat_to_rtt, pps, bps, payload_rtt_ratio,
n_events, fwd_size_mean, fwd_size_std, fwd_size_min, fwd_size_max,
rev_size_mean, rev_size_std, rev_size_max,
hist_tiny, hist_small, hist_medium, hist_large, hist_full, frac_full,
syn_count, fin_count, rst_count, psh_count, ack_only_count, conn_state,
rst_frac, syn_to_data, psh_burst_max, retransmit_est, window_size_init,
entropy_first, entropy_fwd_mean, entropy_rev_mean,
printable_frac, null_frac, byte_std, high_entropy_frac, payload_len_first
```

Note: F7 (fingerprints) and F8 (source behavior) are not included in standalone export because frequency-encoding requires the global corpus and source stats require cross-VM aggregation. DFI2 handles these via ClickHouse JOINs.

### CNN Export

Column order:
```
flow_id, session_key,
size_dir_seq_1..size_dir_seq_128,       (128 cols)
tcp_flags_seq_1..tcp_flags_seq_128,     (128 cols)
iat_log_ms_seq_1..iat_log_ms_seq_128,   (128 cols)
iat_rtt_bin_seq_1..iat_rtt_bin_seq_128, (128 cols)
entropy_bin_seq_1..entropy_bin_seq_128, (128 cols)
dst_port, ip_proto, app_proto,
pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
rtt_ms, n_events,
entropy_first, entropy_fwd_mean, entropy_rev_mean,
printable_frac, null_frac, byte_std, high_entropy_frac, payload_len_first
```

Sequences are pivoted from the packets table: fetch all packets for each flow, group by flow_id, pad/truncate to 128 positions with zeros.

### Usage

```
python -m dfi_agent export --format xgb --output dfi_xgb.csv --buffer path/to/agent_buffer.db
python -m dfi_agent export --format cnn --output dfi_cnn.csv
python -m dfi_agent export --format both --output-dir ./exports
```

---

## Installer (`install.ps1`)

Universal PowerShell script. Requires elevation (RunAsAdministrator).

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-VMId` | $env:COMPUTERNAME | Unique VM identifier |
| `-MgmtNicIP` | "0.0.0.0" | Management NIC bind address |
| `-HoneypotNicName` | auto-detect | Network adapter name for capture |
| `-AgentPort` | 9200 | REST API port |
| `-AgentToken` | auto-generated | Pre-shared auth token |
| `-InstallDir` | "C:\Program Files\DFI" | Installation path |
| `-SkipNpcap` | false | Skip Npcap installation |
| `-SkipAuditPolicy` | false | Skip audit policy configuration |
| `-SkipServices` | false | Skip enabling honeypot services |
| `-BpfFilter` | auto-generated | Custom BPF capture filter |

### Steps

1. **Create directories:** InstallDir, data, logs, python, tools
2. **Install Python embeddable 3.11:** Download zip, extract, enable pip by uncommenting `import site` in `python*._pth`, install pip via get-pip.py
3. **Install Python dependencies:** Copy agent source + requirements.txt, pip install
4. **Install Npcap:** Bundle or prompt for manual install. Silent: `npcap-oem.exe /S /winpcap_mode=yes /loopback_support=yes /dot11_support=no`
5. **Configure audit policy:** auditpol for Logon, Special Logon, Process Creation, etc. Enable command-line logging in process creation (registry). Enable PowerShell script block logging (registry). Expand event log sizes (Security to 512MB, Application to 128MB, System to 64MB, PowerShell to 128MB).
6. **Enable honeypot services:** RDP (fDenyTSConnections=0), WinRM (Enable-PSRemoting, allow basic+unencrypted), SMB (create share), IIS (Install-WindowsFeature or DISM)
7. **Generate BPF filter:** Auto-generate from configured service ports, excluding management VLAN traffic
8. **Write config.json:** Populate from parameters
9. **Create Windows service:** Use NSSM (preferred, download if not present) or sc.exe fallback. Service name: DFICaptureAgent. Auto-start. Restart on failure.
10. **Firewall rule:** Allow inbound TCP on agent_port, restricted to mgmt NIC IP if specified

### Auto-detect Honeypot NIC

If `-HoneypotNicName` not specified:
1. Enumerate Up adapters via `Get-NetAdapter`
2. Skip adapters whose IP matches MgmtNicIP
3. Return first remaining adapter

### Uninstaller (`uninstall.ps1`)

1. Stop and remove DFICaptureAgent service (NSSM or sc.exe)
2. Remove firewall rule
3. Remove installation directory (optional `-KeepData` preserves data/ and logs/)
4. Note: does NOT uninstall Npcap or revert audit policies

---

## Resource Budget

| Resource | Typical | Worst Case |
|----------|---------|------------|
| CPU | 2–5% | 10% (burst) |
| RAM | 100–300 MB | 500 MB (50K active flows) |
| Disk (buffer) | 50–200 MB | 500 MB (7-day retention) |
| Npcap resident | 2 MB | 18 MB (16MB kernel buffer) |
| Network (API) | negligible | 5 Mbps (bulk pull) |

---

## Key Design Decisions

1. **Single process, multi-threaded.** No cross-process serialization overhead. SQLite WAL handles concurrent access from capture, evidence, and API threads.

2. **Features computed at emission, not at query time.** The flow table accumulates raw state; feature extraction runs once when the flow completes. This avoids recomputation on every API call.

3. **NaN as None/missing, never as 0.** XGBoost handles missing values natively and learns different split behavior for "RTT unknown" vs "RTT = 0ms". Imputing with 0 would destroy this signal.

4. **256-byte snap length.** Sufficient for Ethernet(14) + IPv4(20–60) + TCP(20–60) + ~100 bytes of payload for fingerprinting. Keeps Npcap buffer small and reduces disk I/O.

5. **direction via local_ips, not by first-SYN heuristic.** On a honeypot, the local IPs are always known. The "first SYN = initiator" heuristic fails for mid-flow captures and UDP. Checking against local_ips is deterministic.

6. **Atomic ack for flows+packets+fingerprints.** A single POST /api/ack/flows marks all three tables. Prevents orphaned packets from flows that were acked before their packets were pulled.

7. **Graceful degradation.** No pywin32 → evidence disabled, PCAP still works. No Npcap → capture disabled, evidence still works. No DFI2 → standalone export works. Each subsystem fails independently.

8. **NSSM over sc.exe for service management.** NSSM properly handles stdout/stderr logging, restart on failure, and process tree management. sc.exe is the fallback for environments where downloads are restricted.
