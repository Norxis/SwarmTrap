# DFI-CNN Dataset v1 — 1D Convolutional Network

## Same Two Sources, Different Structure

```
PCAP  ──────►  5-channel sequence  (per-packet timeline — CNN input)
              + 42 static scalars   (flow-level context — metadata branch)
evidence.db ──►  label               (kill-chain ground truth)
```

A 1D-CNN slides small kernels (width 3–7) over consecutive packets and learns
local patterns like "SYN, SYN-ACK, small fwd, small fwd, RST" = failed exploit attempt.
This is fundamentally different from XGBoost, which splits on scalar thresholds.

**Design principle:** If the CNN can learn it from the sequence, don't duplicate it
as a static feature. Give the CNN the raw sequential signal. Give the static branch
only what the sequence can't express (fingerprints, campaign context, whole-flow totals
beyond 128 packets).

---

## Architecture Overview

```
                   ┌──────────────────────────┐
                   │   5 × 128 sequence        │
                   │   (embed each channel,     │
                   │    concat per position,     │
                   │    Conv1D stack)            │
                   └────────────┬───────────────┘
                                │ flatten / global pool
                                ▼
                   ┌────────────────────────────┐
                   │       concatenate           │
                   └──┬─────────────────────┬───┘
                      │                     │
            ┌─────────┴──────┐    ┌─────────┴──────┐
            │ CNN features   │    │ 42 static      │
            │ (learned)      │    │ scalars         │
            └────────────────┘    └────────────────┘
                                          │
                                    ┌─────┴─────┐
                                    │  Dense     │
                                    │  → softmax │
                                    │  (5 class) │
                                    └───────────┘
```

---

## Labels — evidence.db (identical to XGBoost spec)

| Code | Name | evidence.db criteria |
|---|---|---|
| 0 | **RECON** | No host-side events for this source IP in ±window |
| 1 | **KNOCK** | Connection reached service, zero auth attempts |
| 2 | **BRUTEFORCE** | ≥3 authentication failures |
| 3 | **EXPLOIT** | Suspicious command detected in logs |
| 4 | **COMPROMISE** | Auth success + post-exploitation signal |

---

## Label Metadata (do not train)

| Column | Type | Purpose |
|---|---|---|
| `label_confidence` | float32 0–1 | Sample weight. |
| `evidence_mask` | uint8 | Bitmask of host events observed. |
| `evidence_detail` | string | Audit trail. |

---

## Identity (do not train)

| Column | Type | Purpose |
|---|---|---|
| `flow_id` | string | UUID per row. |
| `session_key` | string | 5-tuple hash. |
| `actor_id` | string | For GroupKFold splits. |

---

## Sequence Input — 5 Channels × 128 Positions

### Event Packet Selection

- **Include** if: `payload_len > 0` OR TCP flags include SYN/FIN/RST
- **Exclude** if: pure ACK with zero payload
- **Truncate** at 128 event packets (keep first 128)
- **Pad** remaining positions with 0

All five channels are aligned 1:1 by packet index.

---

### Channel 1: `size_dir_seq_1..128` — Directional Size Token

Signed log-binned packet size with direction.

| Value | Meaning |
|---|---|
| 0 | padding (no packet at this position) |
| +1 to +11 | forward packet, log2 size bin |
| −1 to −11 | reverse packet, log2 size bin |

```
raw_bin = floor(log2(payload_bytes))
bin     = min(11, max(1, raw_bin − 4))
token   = direction_sign × bin
```

Vocab size: **23** (−11 to +11 inclusive). Recommend embedding dim 12.

| Packet size | Bin | Typical content |
|---|---|---|
| 1–63 bytes | 1 | SYN/FIN/RST, tiny probes |
| 64–127 | 2 | SSH banner, DNS query |
| 128–255 | 3 | Small HTTP requests |
| 256–511 | 4 | Medium payloads |
| 512–1023 | 5 | Half-MSS |
| 1024–1499 | 6 | Near-MSS |
| 1500–2047 | 6 | Standard MTU |
| 2048–4095 | 7 | Jumbo fragments |
| 4096–8191 | 8 | Large transfers |
| 8192–16383 | 9 | Jumbo frames |
| 16384–32767 | 10 | TSO/GRO offload |
| 32768+ | 11 | Capped |

**What the CNN kernel sees:** `[+1, −2, +1, −2, +1]` = small request/response
exchange (brute-force auth). `[+1, −6, −6, −6, −6]` = one request, bulk download.

---

### Channel 2: `tcp_flags_seq_1..128` — TCP Control Flags

| Value | Meaning |
|---|---|
| 0 | padding (no packet) |
| 1 | SYN |
| 2 | FIN |
| 4 | RST |
| 8 | PSH |
| 16 | PRESENT — real packet, none of SYN/FIN/RST/PSH set (includes non-TCP) |
| combos | bitwise OR: e.g. 3 = SYN+FIN, 10 = FIN+PSH |

Vocab size: **17** (0 to 16). Recommend embedding dim 6.

**What the CNN kernel sees:** `[1, 16, 8, 8, 4]` = SYN → handshake → data → data → RST
(aborted session). `[1, 16, 8, 8, 2]` = same but clean FIN close.

---

### Channel 3: `iat_log_ms_seq_1..128` — Absolute Inter-Arrival Time (log-binned)

Time between consecutive event packets, log-binned at millisecond scale.
Jitter-robust because log binning compresses ±1ms noise into the same bin.

| Value | IAT range | Typical meaning |
|---|---|---|
| 0 | padding | No packet |
| 1 | first packet | No previous (no IAT) |
| 2 | < 1ms | Wire-speed burst, scanner spray |
| 3 | 1–10ms | Fast automated tool, local network |
| 4 | 10–100ms | Typical LAN RTT or paced scanner |
| 5 | 100ms–1s | WAN RTT, response-paced brute-force |
| 6 | 1–10s | Slow tool, rate-limited, or human thinking |
| 7 | 10–60s | Interactive human pause |
| 8 | > 60s | Long idle, session keepalive |

Vocab size: **9** (0 to 8). Recommend embedding dim 6.

```
iat_ms = (ts[i] − ts[i−1]) × 1000
if i == 0:           bin = 1
elif iat_ms < 1:     bin = 2
elif iat_ms < 10:    bin = 3
elif iat_ms < 100:   bin = 4
elif iat_ms < 1000:  bin = 5
elif iat_ms < 10000: bin = 6
elif iat_ms < 60000: bin = 7
else:                bin = 8
```

**What the CNN kernel sees:** Brute-force: `[5, 5, 5, 5, 5]` = constant ~500ms gaps.
Interactive: `[4, 7, 3, 7, 6]` = irregular pauses. Scanner: `[2, 2, 2, 2, 2]` = sub-ms bursts.

**Jitter robustness:** ±1ms jitter shifts 500ms → 499–501ms — still bin 5.

---

### Channel 4: `iat_rtt_bin_seq_1..128` — RTT-Normalized Inter-Arrival Time

Same IAT, divided by estimated RTT. Geography-independent behavioral rhythm.

| Value | IAT/RTT ratio | Meaning |
|---|---|---|
| 0 | padding | No packet |
| 1 | N/A | First packet, or no RTT estimate available |
| 2 | < 0.5 | Faster than round-trip — pipelining |
| 3 | 0.5–1 | One RTT — request-response lockstep |
| 4 | 1–2 | Slightly paced beyond RTT |
| 5 | 2–5 | Deliberate pacing (rate-limited tool) |
| 6 | 5–20 | Slow tool or short human pause |
| 7 | 20–100 | Long human pause, timeout backoff |
| 8 | 100–1000 | Very long pause relative to network speed |
| 9 | > 1000 | Session essentially idle |

Vocab size: **10** (0 to 9). Recommend embedding dim 6.

**RTT estimation:**

```
if TCP and SYN-ACK captured:
    rtt_ms = (syn_ack_ts − syn_ts) × 1000
elif any reverse packet exists:
    rtt_ms = (first_rev_ts − first_fwd_ts) × 1000
else:
    rtt_ms = NaN → all positions get bin 1 (unknown)
```

```
ratio = iat_ms / rtt_ms
if i == 0 or rtt unavailable: bin = 1
elif ratio < 0.5:             bin = 2
elif ratio < 1:               bin = 3
elif ratio < 2:               bin = 4
elif ratio < 5:               bin = 5
elif ratio < 20:              bin = 6
elif ratio < 100:             bin = 7
elif ratio < 1000:            bin = 8
else:                         bin = 9
```

**Why both Channel 3 and Channel 4:**

| Scenario | Ch3 (absolute) | Ch4 (RTT-normalized) |
|---|---|---|
| Brute-force, São Paulo (300ms RTT) | 5 (100ms–1s) | 3 (≈1 RTT) |
| Brute-force, Frankfurt (20ms RTT) | 4 (10–100ms) | 3 (≈1 RTT) |
| Scanner, São Paulo | 2 (<1ms) | 2 (<0.5 RTT) |
| Scanner, Frankfurt | 2 (<1ms) | 2 (<0.5 RTT) |
| Interactive, São Paulo | 7 (10–60s) | 7 (20–100× RTT) |
| Interactive, Frankfurt | 7 (10–60s) | 8 (100–1000× RTT) |

Channel 3 captures absolute tempo. Channel 4 captures behavioral intent relative
to network path. When RTT is unavailable, Channel 4 falls back to bin 1 everywhere;
Channel 3 still provides the temporal signal.

---

### Channel 5: `entropy_bin_seq_1..128` — Per-Packet Payload Entropy

Content character of each packet's payload. Captures **transitions** across the flow —
cleartext banner → encrypted handshake → high-entropy post-exploit traffic. The static
`entropy_fwd_mean` averages these into one number and loses the transition. This channel
preserves it.

| Value | Condition | Typical content |
|---|---|---|
| 0 | padding | No packet |
| 1 | payload_len == 0 | Control packet (SYN/FIN/RST) with no payload |
| 2 | entropy [0, 2) | Repeated bytes, null padding, fixed headers |
| 3 | entropy [2, 4) | Structured text, ASCII, HTTP headers, cleartext commands |
| 4 | entropy [4, 5.5) | Mixed text/binary, base64, encoded data |
| 5 | entropy [5.5, 7) | Compressed data, some encryption |
| 6 | entropy [7, 8] | Encrypted / random (TLS record, SSH post-handshake, shellcode) |

Vocab size: **7** (0 to 6). Recommend embedding dim 4.

```
if padding:              bin = 0
elif payload_len == 0:   bin = 1
else:
    H = shannon_entropy(payload_bytes)
    if   H < 2.0:  bin = 2
    elif H < 4.0:  bin = 3
    elif H < 5.5:  bin = 4
    elif H < 7.0:  bin = 5
    else:           bin = 6
```

**What the CNN kernel sees that nothing else captures:**

| Entropy sequence | What it means |
|---|---|
| `[1, 3, 3, 6, 6, 6, 6]` | SYN → cleartext headers → TLS kicks in (STARTTLS / protocol upgrade) |
| `[1, 3, 6, 6, 6]` | SYN → SSH banner (text) → encrypted session |
| `[1, 3, 3, 3, 4, 6]` | SYN → cleartext → cleartext → cleartext → encoded → encrypted (exploit injection mid-session) |
| `[1, 6, 6, 6, 6]` | SYN → all encrypted from first payload (pre-shared TLS, C2 channel) |
| `[1, 3, 3, 3, 3, 3]` | SYN → all cleartext (brute-force against unencrypted service) |
| `[1, 2, 2, 2, 2]` | SYN → structured/repetitive payloads (scanner with fixed probes) |

A width-3 kernel on `[3, 4, 6]` detects the exact moment an attacker transitions
from cleartext probing to encrypted payload delivery — a strong EXPLOIT signal.
The static `entropy_fwd_mean ≈ 4.5` averages bins 3 and 6 together and sees nothing.

---

### Sequence Summary

| Channel | Column pattern | Vocab | Embed dim | Signal captured |
|---|---|---|---|---|
| 1. size_dir | `size_dir_seq_1..128` | 23 | 12 | Packet size + direction |
| 2. tcp_flags | `tcp_flags_seq_1..128` | 17 | 6 | Connection control events |
| 3. iat_log_ms | `iat_log_ms_seq_1..128` | 9 | 6 | Absolute temporal rhythm |
| 4. iat_rtt_bin | `iat_rtt_bin_seq_1..128` | 10 | 6 | Geography-independent rhythm |
| 5. entropy_bin | `entropy_bin_seq_1..128` | 7 | 4 | Payload content character |

Per-position embedding: `[size ‖ flags ‖ iat_abs ‖ iat_rtt ‖ entropy]`
→ 34 dimensions per position, 128 positions → Conv1D input shape `(B, 34, 128)`.

**Padding mask:** Position is padding iff `size_dir_seq_i == 0`. Use as mask on
Conv1D outputs. `n_events` scalar tells you where real data ends.

**What the 5 channels give a single kernel:** At each position, the CNN sees
*what size packet, going which direction, with what TCP control flags, how long
after the previous packet in absolute and RTT-relative terms, and what kind of
content it carries.* That is the complete per-packet behavioral fingerprint.

---

## Static Metadata Branch — 42 Scalar Features

These features cannot be learned from the 128-packet sequence alone.
They provide flow-level context that conditions the CNN's interpretation.

### Why these and not the others?

| Feature type | In sequence? | In static? | Reason |
|---|---|---|---|
| Packet sizes | ✓ Ch1 | ✗ | CNN extracts distributions from sequence |
| TCP flag counts | ✓ Ch2 | ✗ | CNN counts flags via learned filters |
| Timing patterns | ✓ Ch3+Ch4 | ✗ | CNN learns temporal patterns from IAT channels |
| Payload entropy | ✓ Ch5 | ✗ | CNN sees content transitions per-packet |
| Protocol ID | ✗ | ✓ | Single value per flow, not sequential |
| RTT estimate | ✗ | ✓ | Informs interpretation of timing channels |
| Whole-flow entropy stats | ✗ | ✓ | Beyond 128-pkt window; complements Ch5 |
| Fingerprints | ✗ | ✓ | Per-flow handshake features |
| Source campaign | ✗ | ✓ | Cross-flow aggregate |
| Volume totals | ✗ | ✓ | Flow may have >128 pkts |

---

### S1. Protocol & Target (3 features)

| Column | Type | Description |
|---|---|---|
| `dst_port` | uint16 | Destination port |
| `ip_proto` | uint8 | 6=TCP, 17=UDP, 1=ICMP |
| `app_proto` | uint8 | DPI-detected protocol (same codes as XGBoost spec) |

---

### S2. Volume Totals (8 features)

The CNN only sees 128 event packets. If the flow has 500 packets, these totals
capture what the CNN can't see.

| Column | Type | Description |
|---|---|---|
| `pkts_fwd` | uint32 | Total forward packets |
| `pkts_rev` | uint32 | Total reverse packets |
| `bytes_fwd` | uint32 | Total forward bytes |
| `bytes_rev` | uint32 | Total reverse bytes |
| `bytes_per_pkt_fwd` | float32 | Mean forward packet size |
| `bytes_per_pkt_rev` | float32 | Mean reverse packet size. NaN if none. |
| `pkt_ratio` | float32 | `pkts_fwd / max(pkts_rev, 1)` |
| `byte_ratio` | float32 | `bytes_fwd / max(bytes_rev, 1)` |

---

### S3. Timing & Sequence Context (2 features)

| Column | Type | Description |
|---|---|---|
| `rtt_ms` | float32 | Estimated RTT. Conditions how the model reads Ch4. NaN if unknown. |
| `n_events` | uint16 | Event packet count (1–128). Attention mask length. 128 = flow was truncated. |

---

### S4. Payload Content (8 features)

Whole-flow entropy stats that complement Ch5's per-packet view.
Ch5 shows the transition pattern; these capture the overall content character
including packets beyond the 128-pkt window.

| Column | Type | Description |
|---|---|---|
| `entropy_first` | float32 | Shannon entropy of first fwd payload (0.0–8.0). NaN if none. |
| `entropy_fwd_mean` | float32 | Mean entropy across ALL fwd payloads (not just first 128). NaN if none. |
| `entropy_rev_mean` | float32 | Mean entropy across ALL rev payloads. NaN if none. |
| `printable_frac` | float32 | Printable ASCII fraction in first fwd payload. NaN if none. |
| `null_frac` | float32 | Null byte fraction in first fwd payload. NaN if none. |
| `byte_std` | float32 | Byte value std dev in first fwd payload. NaN if none. |
| `high_entropy_frac` | float32 | Fraction of ALL fwd payloads with entropy ≥7.0. NaN if none. |
| `payload_len_first` | uint16 | First fwd payload size in bytes. 0 if none. |

---

### S5. Protocol Fingerprints (15 features)

Same as XGBoost spec. Extracted from PCAP, frequency-encoded where applicable.

**TLS:**

| Column | Type | Description |
|---|---|---|
| `ja3_freq` | uint32 | Frequency of JA3 hash. 0 if not TLS. |
| `tls_version` | uint8 | 0/10/11/12/13 |
| `tls_cipher_count` | uint8 | Cipher suites offered |
| `tls_ext_count` | uint8 | Extensions count |
| `tls_has_sni` | uint8 | 0/1 |

**SSH:**

| Column | Type | Description |
|---|---|---|
| `hassh_freq` | uint32 | Frequency of HASSH. 0 if not SSH. |
| `ssh_kex_count` | uint8 | Kex algorithms offered |

**HTTP:**

| Column | Type | Description |
|---|---|---|
| `http_method` | uint8 | 0=none, 1=GET, 2=POST, 3=HEAD, 4=PUT, 5=other |
| `http_uri_len` | uint16 | URI length |
| `http_header_count` | uint8 | Request header count |
| `http_ua_freq` | uint32 | Frequency of UA hash. 0 if not HTTP. |
| `http_has_body` | uint8 | 0/1 |
| `http_status` | uint16 | First response status. 0 if none. |

**DNS:**

| Column | Type | Description |
|---|---|---|
| `dns_qtype` | uint8 | Query type. 0 if not DNS. |
| `dns_qname_len` | uint16 | Query name length |

---

### S6. Source Behavior (6 features)

Campaign context from the PCAP flow table. Cross-flow signal.

| Column | Type | Description |
|---|---|---|
| `src_flow_count` | uint32 | Total flows from this source IP |
| `src_unique_ports` | uint16 | Distinct dst_ports targeted |
| `src_unique_protos` | uint8 | Distinct app_proto values |
| `src_unique_dsts` | uint8 | Distinct honeypot IPs hit |
| `src_span_min` | float32 | Minutes between first and last flow from source |
| `src_avg_pps` | float32 | Average pps across all flows from source |

---

## Column Layout — Full CSV

### Identity + labels (7 columns)

```
flow_id, session_key, actor_id,
label, label_confidence, evidence_mask, evidence_detail
```

### Sequence channels (640 columns)

```
size_dir_seq_1 .. size_dir_seq_128          (128 cols, int [-11..+11])
tcp_flags_seq_1 .. tcp_flags_seq_128        (128 cols, int [0..16])
iat_log_ms_seq_1 .. iat_log_ms_seq_128      (128 cols, int [0..8])
iat_rtt_bin_seq_1 .. iat_rtt_bin_seq_128    (128 cols, int [0..9])
entropy_bin_seq_1 .. entropy_bin_seq_128    (128 cols, int [0..6])
```

### Static metadata (42 columns)

```
dst_port, ip_proto, app_proto,
pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
bytes_per_pkt_fwd, bytes_per_pkt_rev, pkt_ratio, byte_ratio,
rtt_ms, n_events,
entropy_first, entropy_fwd_mean, entropy_rev_mean,
printable_frac, null_frac, byte_std, high_entropy_frac, payload_len_first,
ja3_freq, tls_version, tls_cipher_count, tls_ext_count, tls_has_sni,
hassh_freq, ssh_kex_count,
http_method, http_uri_len, http_header_count, http_ua_freq,
http_has_body, http_status,
dns_qtype, dns_qname_len,
src_flow_count, src_unique_ports, src_unique_protos,
src_unique_dsts, src_span_min, src_avg_pps
```

---

## Summary

| Component | Columns | Purpose |
|---|---|---|
| Identity | 3 | Do not train |
| Labels + metadata | 4 | Target + weighting |
| **Ch1. size_dir_seq** | **128** | Directional size tokens |
| **Ch2. tcp_flags_seq** | **128** | Control flag tokens |
| **Ch3. iat_log_ms_seq** | **128** | Absolute timing tokens |
| **Ch4. iat_rtt_bin_seq** | **128** | RTT-normalized timing tokens |
| **Ch5. entropy_bin_seq** | **128** | Per-packet payload entropy |
| **Static metadata** | **42** | Flow-level context |
| **Total columns** | **689** | |
| **Training inputs** | **682** | 640 sequence + 42 static |

---

## PyTorch Usage

```python
import torch
import torch.nn as nn

class DFI_CNN(nn.Module):
    def __init__(self, num_classes=5):
        super().__init__()

        # Sequence embeddings (one per channel)
        self.size_emb    = nn.Embedding(23, 12, padding_idx=0)  # [-11..+11] → offset +11
        self.flag_emb    = nn.Embedding(17,  6, padding_idx=0)
        self.iat_emb     = nn.Embedding( 9,  6, padding_idx=0)
        self.rtt_emb     = nn.Embedding(10,  6, padding_idx=0)
        self.entropy_emb = nn.Embedding( 7,  4, padding_idx=0)
        # Per-position: 12 + 6 + 6 + 6 + 4 = 34 dims

        # Conv1D stack
        self.conv = nn.Sequential(
            nn.Conv1d(34, 64, kernel_size=5, padding=2),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=5, padding=2),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.AdaptiveMaxPool1d(1),  # → (batch, 128, 1)
        )

        # Static metadata branch
        self.static_bn = nn.BatchNorm1d(42)

        # Classifier
        self.head = nn.Sequential(
            nn.Linear(128 + 42, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, num_classes),
        )

    def forward(self, size_seq, flag_seq, iat_seq, rtt_seq, ent_seq, static_feat):
        # size_seq:  (B, 128) int, offset by +11 so range [0..22]
        # flag_seq:  (B, 128) int [0..16]
        # iat_seq:   (B, 128) int [0..8]
        # rtt_seq:   (B, 128) int [0..9]
        # ent_seq:   (B, 128) int [0..6]
        # static_feat: (B, 42) float

        s = self.size_emb(size_seq)      # (B, 128, 12)
        f = self.flag_emb(flag_seq)      # (B, 128, 6)
        i = self.iat_emb(iat_seq)        # (B, 128, 6)
        r = self.rtt_emb(rtt_seq)        # (B, 128, 6)
        e = self.entropy_emb(ent_seq)    # (B, 128, 4)

        x = torch.cat([s, f, i, r, e], dim=2)  # (B, 128, 34)
        x = x.transpose(1, 2)                   # (B, 34, 128)

        # Mask padding positions
        mask = (size_seq != 0).unsqueeze(1).float()  # (B, 1, 128)
        x = x * mask

        x = self.conv(x).squeeze(2)   # (B, 128)

        # Static branch
        m = self.static_bn(static_feat)  # (B, 42)

        # Fuse and classify
        out = self.head(torch.cat([x, m], dim=1))  # (B, 5)
        return out
```

### Data Loading

```python
import pandas as pd
import numpy as np

df = pd.read_csv('dfi_cnn_v1.csv')

# Sequence channels → numpy arrays
size_cols = [f'size_dir_seq_{i}' for i in range(1, 129)]
flag_cols = [f'tcp_flags_seq_{i}' for i in range(1, 129)]
iat_cols  = [f'iat_log_ms_seq_{i}' for i in range(1, 129)]
rtt_cols  = [f'iat_rtt_bin_seq_{i}' for i in range(1, 129)]
ent_cols  = [f'entropy_bin_seq_{i}' for i in range(1, 129)]

size_seq = df[size_cols].values + 11   # offset [-11..+11] → [0..22]
flag_seq = df[flag_cols].values
iat_seq  = df[iat_cols].values
rtt_seq  = df[rtt_cols].values
ent_seq  = df[ent_cols].values

STATIC_COLS = [
    'dst_port', 'ip_proto', 'app_proto',
    'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio',
    'rtt_ms', 'n_events',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean',
    'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac', 'payload_len_first',
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq',
    'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]
static = df[STATIC_COLS].fillna(0).values.astype(np.float32)

labels = df['label'].values
weights = df['label_confidence'].values
groups = df['actor_id'].values  # for GroupKFold
```

### Training Tips

```python
# Class imbalance: RECON dominates. Use weighted loss.
class_counts = np.bincount(labels, minlength=5)
class_weights = 1.0 / np.maximum(class_counts, 1)
class_weights = class_weights / class_weights.sum() * 5
criterion = nn.CrossEntropyLoss(
    weight=torch.tensor(class_weights, dtype=torch.float32)
)

# Sample weighting: multiply loss by label_confidence
loss = criterion(logits, targets)
loss = (loss * confidence_weights).mean()

# Kernel sizes: try [3, 5, 7] in parallel (inception-style).
# Width-3 catches flag transitions (SYN→ACK→RST).
# Width-5 catches request/response cycles.
# Width-7 catches brute-force authentication sequences.

# Sequence augmentation: randomly shift padding (right-pad → mixed-pad)
# to prevent position-dependent artifacts.
```

---

## What the 5 Channels Give a CNN Kernel

At each position, a single kernel window sees:

1. **What size** packet, going **which direction** (Ch1)
2. **What TCP control event** occurred (Ch2)
3. **How long** since the previous packet, absolute (Ch3)
4. **How long** relative to network conditions (Ch4)
5. **What kind of content** the payload carries (Ch5)

This is the complete per-packet behavioral fingerprint. A width-5 kernel
cross-correlating all 5 channels simultaneously can detect:

| 5-packet pattern (all channels) | Detection |
|---|---|
| [small fwd, small rev, small fwd, small rev, small fwd] + [all cleartext] + [constant ~1 RTT gaps] | Cleartext brute-force auth |
| [small fwd, large rev, large rev, large rev] + [text → encrypted → encrypted] + [fast bursts] | Banner grab then encrypted session |
| [small fwd, small rev, small fwd, small fwd] + [cleartext → cleartext → encoded → encrypted] + [accelerating gaps] | Exploit payload injection |
| [SYN only × 5] + [all <1ms] + [all no-payload entropy] | SYN flood / port scan |

No single channel captures these patterns. The discriminative power is in the
**cross-channel correlation at each position** — which is exactly what Conv1D
with multi-channel input computes.

---

## Relationship to XGBoost Spec

| Aspect | XGBoost (DFI-XGB v1) | CNN (DFI-CNN v1) |
|---|---|---|
| Total columns | 82 | 689 |
| Training inputs | 75 scalars | 640 tokens + 42 scalars |
| Timing | 10 scalar stats | 256 per-packet tokens (Ch3+Ch4) |
| Size | 14 distribution stats | 128 per-packet tokens (Ch1) |
| TCP | 11 aggregate counts | 128 per-packet tokens (Ch2) |
| Payload | 8 scalar stats | 128 per-packet tokens (Ch5) + 8 scalars |
| Labels | identical | identical |
| Identity / splits | identical | identical |
| Fingerprints | identical | identical |
| Source behavior | identical | identical |

**Both datasets are generated from the same two sources** (PCAP + evidence.db).
The difference is how the PCAP signal is encoded: scalars for trees,
sequences for convolutions. The 42 static features in the CNN spec are a
subset of the 75 XGBoost features — only the ones the sequence can't express.
