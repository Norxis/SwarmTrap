# Phase 3: Full Feature Extraction

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 2 (Hunter core running, data flowing to CH)

## Objective

Implement all 75 XGBoost scalar features and all 5 CNN packet token channels. After this phase, every flow written to ClickHouse has the complete feature set.

## Reference Files

| File | What to read |
|------|-------------|
| `~/ai-shared/DFI2/DFI2_XGB_v1_Spec.md` | All 75 features with exact formulas |
| `~/ai-shared/DFI2/DFI2_CNN_v1_Spec.md` | All 5 channels with exact binning |
| `~/DFI2/hunter/hunter.py` | Current SessionProfile (from Phase 2) |

## Output Files

```
~/DFI2/hunter/
├── features.py      # NEW: 75 XGBoost feature extraction
├── tokenizer.py     # NEW: 5-channel CNN packet tokenizer
├── hunter.py        # MODIFY: call features.py + tokenizer.py on flush
└── writer.py        # MODIFY: flow dicts now have all 75 columns
```

---

## features.py — All 75 Scalar Features

Single function: `extract_features(session: SessionProfile) -> dict`

Returns a dict mapping column names to values, ready for ClickHouse INSERT.

### F1. Protocol (3 features)
- `dst_port`: from session
- `ip_proto`: from session (6=TCP, 17=UDP, 1=ICMP)
- `app_proto`: port-based heuristic:
  ```
  22→1(ssh), 80/8080→2(http), 443→3(tls), 53→4(dns), 25→5(smtp),
  21→6(ftp), 23→7(telnet), 3389→8(rdp), 5900→9(vnc), 445→10(smb),
  3306→11(mysql), 1433→12(mssql), 5432→13(postgres), 6379→14(redis),
  27017→15(mongodb), else→0(unknown)
  ```

### F2. Volume (8 features)
- `pkts_fwd`, `pkts_rev`, `bytes_fwd`, `bytes_rev`: from session
- `bytes_per_pkt_fwd`: `bytes_fwd / max(pkts_fwd, 1)`
- `bytes_per_pkt_rev`: `bytes_rev / max(pkts_rev, 1)` or None if pkts_rev==0
- `pkt_ratio`: `pkts_fwd / max(pkts_rev, 1)`
- `byte_ratio`: `bytes_fwd / max(bytes_rev, 1)`

### F3. Timing (10 features) — CRITICAL NEW CODE

**RTT estimation:**
```python
def estimate_rtt(events):
    # Method 1: SYN → SYN-ACK
    syn_ts = None
    for e in events:
        if e.direction == 1 and (e.tcp_flags & 0x02):  # SYN
            syn_ts = e.ts
        elif e.direction == -1 and syn_ts is not None:  # first reverse after SYN
            return (e.ts - syn_ts) * 1000  # ms
    # Method 2: first fwd → first rev
    first_fwd = next((e.ts for e in events if e.direction == 1), None)
    first_rev = next((e.ts for e in events if e.direction == -1), None)
    if first_fwd and first_rev and first_rev > first_fwd:
        return (first_rev - first_fwd) * 1000
    return None  # NaN
```

**IAT computation (forward packets only):**
```python
fwd_timestamps = [e.ts for e in events if e.direction == 1]
fwd_iats = [fwd_timestamps[i] - fwd_timestamps[i-1] for i in range(1, len(fwd_timestamps))]
fwd_iats_ms = [iat * 1000 for iat in fwd_iats]
```

Features:
- `duration_ms`: `(last_ts - first_ts) * 1000`
- `rtt_ms`: from estimate_rtt()
- `iat_fwd_mean_ms`: mean of fwd_iats_ms
- `iat_fwd_std_ms`: std of fwd_iats_ms
- `think_time_mean_ms`: `mean(max(iat - rtt, 0) for iat in fwd_iats_ms)` — None if no RTT
- `think_time_std_ms`: std of think times
- `iat_to_rtt`: `iat_fwd_mean / max(rtt, 0.1)` — None if no RTT
- `pps`: `(pkts_fwd + pkts_rev) / max(duration_s, 0.001)`
- `bps`: `(bytes_fwd + bytes_rev) / max(duration_s, 0.001)`
- `payload_rtt_ratio`: `n_payload_pkts / max(duration_ms / rtt_ms, 1)` — None if no RTT

### F4. Size Shape (14 features)

Iterate events, separate fwd/rev, compute:
- `n_events`: count of event packets
- `fwd_size_mean`, `fwd_size_std`, `fwd_size_min`, `fwd_size_max`: from fwd payload_len
- `rev_size_mean`, `rev_size_std`, `rev_size_max`: from rev payload_len (None if no rev)
- Histograms (count fwd+rev payload_len):
  - `hist_tiny`: 1-63 bytes
  - `hist_small`: 64-255
  - `hist_medium`: 256-1023
  - `hist_large`: 1024-1499
  - `hist_full`: ≥1500
- `frac_full`: `hist_full / max(n_events, 1)`

### F5. TCP Behavior (11 features)

Count across ALL packets (not just events):
- `syn_count`: packets with SYN flag
- `fin_count`: FIN flag
- `rst_count`: RST flag
- `psh_count`: PSH flag
- `ack_only_count`: ACK set, no SYN/FIN/RST/PSH, zero payload

**conn_state classification:**
```
0: SYN only, no SYN-ACK
1: SYN-ACK → RST, no data
2: Handshake → data → FIN
3: Handshake → data → RST
4: Handshake → data(many) → FIN
5: Handshake → data(many) → RST
6: Multiple SYN, no completion
7: Non-TCP (UDP/ICMP)
```

- `rst_frac`: `index_of_first_RST / total_packets` (None if no RST)
- `syn_to_data`: packets between SYN and first payload
- `psh_burst_max`: longest consecutive run of PSH packets
- `retransmit_est`: count of (same direction, same payload_len) duplicate pairs
- `window_size_init`: TCP window from SYN packet

### F6. Payload Content (8 features)

```python
def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq if c > 0)
```

- `entropy_first`: entropy of first fwd payload
- `entropy_fwd_mean`: mean entropy across ALL fwd payloads
- `entropy_rev_mean`: mean entropy across ALL rev payloads
- `printable_frac`: fraction of bytes 0x20-0x7E in first fwd payload
- `null_frac`: fraction of 0x00 bytes in first fwd payload
- `byte_std`: std dev of byte values in first fwd payload
- `high_entropy_frac`: fraction of fwd payloads with entropy ≥7.0
- `payload_len_first`: size of first fwd payload (0 if none)

---

## tokenizer.py — All 5 CNN Channels

Single function: `tokenize_packets(events: list, rtt_ms: float) -> list[dict]`

Returns list of dicts (one per event packet, max 128), each with:
- `seq_idx`: 0-127
- `ts`: packet timestamp
- `direction`: 1 or -1
- `payload_len`, `pkt_len`, `tcp_flags`, `tcp_window`
- `size_dir_token`: Ch1
- `flag_token`: Ch2
- `iat_log_ms_bin`: Ch3
- `iat_rtt_bin`: Ch4
- `entropy_bin`: Ch5
- `iat_ms`: raw IAT (for re-binning)
- `payload_entropy`: raw entropy

### Ch1: size_dir_token (existing, from v7)
```python
raw_bin = max(1, min(11, int(math.log2(max(payload_len, 1))) - 4))
token = direction * raw_bin  # [-11..+11]
```

### Ch2: flag_token (existing, from v7)
```python
token = 0
if tcp_flags & 0x02: token |= 1   # SYN
if tcp_flags & 0x01: token |= 2   # FIN
if tcp_flags & 0x04: token |= 4   # RST
if tcp_flags & 0x08: token |= 8   # PSH
if token == 0 and ip_proto == 6: token = 16  # PRESENT
# Non-TCP: token = 16
```

### Ch3: iat_log_ms_bin (NEW)
```python
if seq_idx == 0: bin = 1  # first packet
elif iat_ms < 1: bin = 2
elif iat_ms < 10: bin = 3
elif iat_ms < 100: bin = 4
elif iat_ms < 1000: bin = 5
elif iat_ms < 10000: bin = 6
elif iat_ms < 60000: bin = 7
else: bin = 8
```

### Ch4: iat_rtt_bin (NEW)
```python
if seq_idx == 0 or rtt_ms is None: bin = 1
else:
    ratio = iat_ms / max(rtt_ms, 0.01)
    if ratio < 0.5: bin = 2
    elif ratio < 1: bin = 3
    elif ratio < 2: bin = 4
    elif ratio < 5: bin = 5
    elif ratio < 20: bin = 6
    elif ratio < 100: bin = 7
    elif ratio < 1000: bin = 8
    else: bin = 9
```

### Ch5: entropy_bin (NEW)
```python
if payload_len == 0: bin = 1  # control packet
else:
    H = shannon_entropy(payload_head[:payload_len])
    if H < 2.0: bin = 2
    elif H < 4.0: bin = 3
    elif H < 5.5: bin = 4
    elif H < 7.0: bin = 5
    else: bin = 6
```

---

## Integration: Modify hunter.py flush_ready()

In the flush path, after session expires:

```python
from .features import extract_features
from .tokenizer import tokenize_packets

def flush_session(session):
    features = extract_features(session)
    rtt_ms = features.get('rtt_ms')
    pkt_tokens = tokenize_packets(session.events, rtt_ms)
    fanout = build_fanout_hop(session, features)
    writer.insert_flow(features, pkt_tokens, fp=None, fanout, session.capture_depth)
```

---

## Verification

1. **Feature completeness:**
   ```bash
   clickhouse-client --query "SELECT * FROM dfi.flows LIMIT 1 FORMAT Vertical"
   # All 75+ columns should have non-NULL values (except Nullable fields)
   ```

2. **Token ranges:**
   ```bash
   clickhouse-client --query "SELECT min(size_dir_token), max(size_dir_token) FROM dfi.packets"
   # Should be in [-11, +11]
   clickhouse-client --query "SELECT min(iat_log_ms_bin), max(iat_log_ms_bin) FROM dfi.packets"
   # Should be in [1, 8]
   clickhouse-client --query "SELECT min(entropy_bin), max(entropy_bin) FROM dfi.packets"
   # Should be in [1, 6]
   ```

3. **Timing features:**
   ```bash
   clickhouse-client --query "SELECT avg(rtt_ms), avg(iat_to_rtt), avg(think_time_mean_ms) FROM dfi.flows WHERE rtt_ms IS NOT NULL"
   # rtt_ms: typically 1-500ms, iat_to_rtt: typically 0.1-1000
   ```

---

## Acceptance Criteria

- [ ] All 75 XGBoost features computed per flow
- [ ] All 5 CNN token channels populated per packet
- [ ] RTT estimation working (non-NULL for TCP flows with responses)
- [ ] conn_state correctly classified (spot-check against known traffic)
- [ ] Entropy computed correctly (SSH traffic ~7.5 after handshake)
- [ ] No performance regression (ingest rate same as Phase 2)
- [ ] features.py has unit tests for edge cases (zero packets, UDP, no payload)
- [ ] tokenizer.py has unit tests for binning correctness
