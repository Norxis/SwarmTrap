# DFI-XGB Dataset v1

## Two Sources, Clean Separation

```
PCAP  ──────►  75 features  (what the wire shows)
evidence.db ──►  label       (what actually happened on the host)
```

The model sees **only network traffic** at inference.
evidence.db is ground truth at training time only.

---

## Labels — evidence.db

Kill-chain stage. One integer. Derived entirely from host logs.

| Code | Name | evidence.db criteria |
|---|---|---|
| 0 | **RECON** | No host-side events for this source IP in ±window |
| 1 | **KNOCK** | Host logs mention source IP (connection reached a service) but zero auth attempts |
| 2 | **BRUTEFORCE** | ≥3 authentication failures (SSH, RDP, MSSQL, SMB, HTTP auth) |
| 3 | **EXPLOIT** | Suspicious command detected in logs (wget/curl/chmod/nc/reverse shell/certutil/etc.) |
| 4 | **COMPROMISE** | Auth success + any post-exploitation signal (process create, service install, file download) |

The correlation window is ±120 seconds around the flow's first-packet timestamp.
Match on source IP appearing in the log message body.

---

## Label Metadata (do not train — use for weighting and audit)

| Column | Type | Purpose |
|---|---|---|
| `label_confidence` | float32 0–1 | Sample weight for XGBoost. Higher when multiple evidence signals agree. |
| `evidence_mask` | uint8 | Bitmask of which host events were observed. See below. |
| `evidence_detail` | string | Human-readable audit trail. |

**evidence_mask bits:**

| Bit | Signal |
|---|---|
| 0 | auth_failure |
| 1 | auth_success |
| 2 | process_create |
| 3 | service_install |
| 4 | suspicious_command |
| 5 | file_download |
| 6 | privilege_escalation |
| 7 | lateral_movement (same src IP hit multiple VMs) |

---

## Identity (do not train)

| Column | Type | Purpose |
|---|---|---|
| `flow_id` | string | UUID per row. Traceability. |
| `session_key` | string | 5-tuple hash. Joins back to PCAP. |
| `actor_id` | string | Fingerprint-based cluster ID. **Use for GroupKFold splits** so the same attacker tool never appears in both train and test. |

---

## Features — All From PCAP

### F1. Target & Protocol (3 features)

| Column | Type | Description |
|---|---|---|
| `dst_port` | uint16 | Destination port. Highest-signal single feature for service targeting. |
| `ip_proto` | uint8 | 6=TCP, 17=UDP, 1=ICMP. |
| `app_proto` | uint8 | DPI-detected: 0=unknown, 1=ssh, 2=http, 3=tls, 4=dns, 5=smtp, 6=ftp, 7=telnet, 8=rdp, 9=vnc, 10=smb, 11=mysql, 12=mssql, 13=postgres, 14=redis, 15=mongodb, 19=other_known. Fall back to port heuristic if DPI misses. |

---

### F2. Volume (8 features)

Forward = SYN initiator → honeypot. Reverse = honeypot → attacker.

| Column | Type | Description |
|---|---|---|
| `pkts_fwd` | uint32 | Forward packet count |
| `pkts_rev` | uint32 | Reverse packet count |
| `bytes_fwd` | uint32 | Forward byte total |
| `bytes_rev` | uint32 | Reverse byte total |
| `bytes_per_pkt_fwd` | float32 | `bytes_fwd / max(pkts_fwd, 1)` |
| `bytes_per_pkt_rev` | float32 | `bytes_rev / max(pkts_rev, 1)`. NaN if 0 rev pkts. |
| `pkt_ratio` | float32 | `pkts_fwd / max(pkts_rev, 1)` |
| `byte_ratio` | float32 | `bytes_fwd / max(bytes_rev, 1)` |

---

### F3. Timing (10 features — jitter-robust, RTT-normalized)

Attackers connect from everywhere — São Paulo (300ms RTT), Frankfurt (20ms),
localhost (1ms). Raw IATs conflate attacker behavior with geography. These
features factor out the network path so the model sees what the attacker
is doing, not where they are.

All timing at millisecond resolution. Microsecond precision is noise on a
Proxmox vmbr0 → AF_PACKET → VM vNIC capture stack (±1–2ms kernel jitter).

**RTT estimation:**

```
if TCP and SYN-ACK captured:
    rtt_ms = (syn_ack_ts − syn_ts) × 1000
elif any reverse packet exists:
    rtt_ms = (first_rev_ts − first_fwd_ts) × 1000
else:
    rtt_ms = NaN
```

| Column | Type | Unit | Description |
|---|---|---|---|
| `duration_ms` | uint32 | ms | Last pkt − first pkt. Cumulative — jitter averages out. |
| `rtt_ms` | float32 | ms | Estimated round-trip time. **Also a feature** — local vs remote, VPN vs direct. NaN if no response. |
| `iat_fwd_mean_ms` | float32 | ms | Mean forward IAT. Raw, still useful at ms scale. |
| `iat_fwd_std_ms` | float32 | ms | Forward IAT std dev. Measures consistency — scripted=low, human=high, botnet=medium. |
| `think_time_mean_ms` | float32 | ms | `mean(fwd_iat − rtt)` clamped ≥0. Attacker's behavioral pace with network transit removed. Brute-forcer in Brazil and Frankfurt both show ~5ms. NaN if no RTT. |
| `think_time_std_ms` | float32 | ms | Std dev of think time. Constant = scripted. Variable = human or adaptive tool. NaN if no RTT. |
| `iat_to_rtt` | float32 | — | `iat_fwd_mean / max(rtt, 0.1)`. **Key normalized feature.** Scanner <1 (fires faster than RTT). Brute-forcer 1–5. Interactive >50. Dimensionless — geography cancels out. NaN if no RTT. |
| `pps` | float32 | pkt/s | Aggregate packet rate. Jitter-immune. |
| `bps` | float32 | byte/s | Aggregate byte rate. |
| `payload_rtt_ratio` | float32 | — | `n_payload_pkts / max(duration_ms / rtt_ms, 1)`. Payload packets per RTT window — how aggressively attacker fills the pipe. NaN if no RTT. |

**Behavior across geographies:**

| Attacker | RTT | Raw IAT | think_time | iat_to_rtt |
|---|---|---|---|---|
| Scanner (any location) | any | ~0.1ms | ~0 | <<1 |
| Brute-forcer, São Paulo | 300ms | 305ms | 5ms | ~1.0 |
| Brute-forcer, Frankfurt | 20ms | 25ms | 5ms | ~1.25 |
| Interactive SSH, Tokyo | 180ms | 8000ms | 7820ms | ~44 |
| Interactive SSH, local | 5ms | 8000ms | 7995ms | ~1600 |

Raw IATs differ 100x for the same behavior at different distances.
`think_time` and `iat_to_rtt` collapse them to the same neighborhood.

**What was deliberately excluded:**

- `iat_min` → dominated by kernel scheduling artifacts, not attacker behavior
- `iat_max` → one VM pause or GC stall makes this meaningless
- `iat_rev_*` → honeypots produce few reverse packets, unreliable stats
- Microsecond resolution → ms is the honest floor for this capture stack

---

### F4. Packet Size Shape (14 features)

Distribution summary. This is what XGBoost uses — not raw sequences.

| Column | Type | Description |
|---|---|---|
| `n_events` | uint16 | Event packet count (payload>0 or SYN/FIN/RST) |
| `fwd_size_mean` | float32 | Mean payload bytes, forward |
| `fwd_size_std` | float32 | Payload size std dev, forward |
| `fwd_size_min` | uint16 | Smallest forward payload |
| `fwd_size_max` | uint16 | Largest forward payload |
| `rev_size_mean` | float32 | Mean payload bytes, reverse. NaN if none. |
| `rev_size_std` | float32 | Std dev, reverse. NaN if none. |
| `rev_size_max` | uint16 | Largest reverse payload. 0 if none. |
| `hist_tiny` | uint16 | Packets with payload 1–63 bytes |
| `hist_small` | uint16 | 64–255 bytes |
| `hist_medium` | uint16 | 256–1023 bytes |
| `hist_large` | uint16 | 1024–1499 bytes |
| `hist_full` | uint16 | ≥1500 bytes (MSS / jumbo) |
| `frac_full` | float32 | Fraction at full segment. High → bulk transfer. |

---

### F5. TCP Behavior (11 features)

Connection lifecycle. NaN for non-TCP.

| Column | Type | Description |
|---|---|---|
| `syn_count` | uint8 | SYN packets. >1 → retransmit or flood. |
| `fin_count` | uint8 | FIN packets |
| `rst_count` | uint8 | RST packets |
| `psh_count` | uint16 | PSH packets (data segments) |
| `ack_only_count` | uint16 | Pure ACK, zero payload |
| `conn_state` | uint8 | Connection lifecycle category (see below) |
| `rst_frac` | float32 | Position of first RST as fraction of flow. NaN if none. |
| `syn_to_data` | uint8 | Packets between SYN and first payload. Handshake length. |
| `psh_burst_max` | uint8 | Longest consecutive PSH run |
| `retransmit_est` | uint16 | Estimated retransmits (duplicate size+direction pairs) |
| `window_size_init` | uint16 | TCP window from SYN. OS/tool fingerprint. |

**conn_state values:**

| Code | Pattern | Meaning |
|---|---|---|
| 0 | SYN only, no SYN-ACK | Port closed / filtered |
| 1 | SYN-ACK → RST, no data | Port open confirmed, attacker disconnected |
| 2 | Handshake → data → FIN | Normal short session |
| 3 | Handshake → data → RST | Short session, aborted |
| 4 | Handshake → data(many) → FIN | Extended interactive session |
| 5 | Handshake → data(many) → RST | Extended session, aborted |
| 6 | Multiple SYN, no completion | SYN flood / repeated probe |
| 7 | Non-TCP | UDP / ICMP |

---

### F6. Payload Content (8 features)

Byte-level analysis of payload content. No application parsing.

| Column | Type | Description |
|---|---|---|
| `entropy_first` | float32 | Shannon entropy of first fwd payload (0.0–8.0). NaN if none. |
| `entropy_fwd_mean` | float32 | Mean entropy across all fwd payloads. NaN if none. |
| `entropy_rev_mean` | float32 | Mean entropy across all rev payloads. NaN if none. |
| `printable_frac` | float32 | Fraction of printable ASCII (0x20–0x7E) in first fwd payload. NaN if none. |
| `null_frac` | float32 | Fraction of 0x00 bytes in first fwd payload. NaN if none. |
| `byte_std` | float32 | Std dev of byte values in first fwd payload. NaN if none. |
| `high_entropy_frac` | float32 | Fraction of fwd payloads with entropy ≥7.0. NaN if none. |
| `payload_len_first` | uint16 | Size of first fwd payload in bytes. 0 if none. |

**Why three content dimensions, not just entropy:** TLS and compressed both have
entropy ~7.5, but TLS has low printable_frac. HTTP exploits have entropy ~4.5 with
high printable_frac. Binary shellcode has medium entropy with high null_frac. Three
dimensions separate what one can't.

---

### F7. Protocol Fingerprints (15 features)

Extracted from raw PCAP bytes by your extractor (ClientHello parsing, SSH banner, HTTP headers).
Hash-based fields are **frequency-encoded**: the integer value is "how many times this
hash appears in the training corpus". XGBoost splits on `ja3_freq < 5` (rare tool) directly.

**TLS (from ClientHello):**

| Column | Type | Description |
|---|---|---|
| `ja3_freq` | uint32 | Frequency of JA3 hash in corpus. 0 if not TLS. |
| `tls_version` | uint8 | 0=none, 10=SSL3, 11=TLS1.0, 12=TLS1.2, 13=TLS1.3 |
| `tls_cipher_count` | uint8 | Cipher suites offered. Low = constrained tool. |
| `tls_ext_count` | uint8 | TLS extensions count. Browsers ~15, tools ~3. |
| `tls_has_sni` | uint8 | 0/1. Missing SNI = anomaly. |

**SSH (from banner + KEXINIT):**

| Column | Type | Description |
|---|---|---|
| `hassh_freq` | uint32 | Frequency of HASSH in corpus. 0 if not SSH. |
| `ssh_kex_count` | uint8 | Kex algorithms offered. Low = hardcoded tool. |

**HTTP (from request):**

| Column | Type | Description |
|---|---|---|
| `http_method` | uint8 | 0=none, 1=GET, 2=POST, 3=HEAD, 4=PUT, 5=other |
| `http_uri_len` | uint16 | URI length. Long = path traversal / SQLi / fuzzing. |
| `http_header_count` | uint8 | Request headers. Browsers ~15, curl ~5, exploit ~2. |
| `http_ua_freq` | uint32 | Frequency of UA hash. 0 if not HTTP. |
| `http_has_body` | uint8 | 0/1. POST/PUT with body. |
| `http_status` | uint16 | First response status. 0 if none. |

**DNS (from query):**

| Column | Type | Description |
|---|---|---|
| `dns_qtype` | uint8 | 0=none, 1=A, 28=AAAA, 16=TXT, 255=ANY |
| `dns_qname_len` | uint16 | Query name length. Long = DGA / tunneling. |

---

### F8. Source Behavior (6 features)

Per-source-IP aggregates computed from the PCAP flow table within the capture window.
Campaign-level context, not individual flow features.

| Column | Type | Description |
|---|---|---|
| `src_flow_count` | uint32 | Total flows from this source IP |
| `src_unique_ports` | uint16 | Distinct dst_ports targeted |
| `src_unique_protos` | uint8 | Distinct app_proto values |
| `src_unique_dsts` | uint8 | Distinct honeypot IPs hit |
| `src_span_min` | float32 | Minutes between first and last flow from this source |
| `src_avg_pps` | float32 | Average pps across all flows from this source |

**Why this matters:** A single SYN to port 22 is ambiguous. If the same source also
hit 200 ports across 8 VMs → clearly a scan. XGBoost learns
`src_unique_ports > 50 AND psh_count == 0 → RECON` in one tree.

---

## Summary

| Group | Count | Source |
|---|---|---|
| Identity (don't train) | 3 | generator |
| Label (target) | 1 | evidence.db |
| Label metadata (don't train) | 3 | evidence.db |
| F1. Protocol | 3 | PCAP |
| F2. Volume | 8 | PCAP |
| F3. Timing | 10 | PCAP |
| F4. Size shape | 14 | PCAP |
| F5. TCP behavior | 11 | PCAP |
| F6. Payload content | 8 | PCAP |
| F7. Fingerprints | 15 | PCAP |
| F8. Source behavior | 6 | PCAP |
| **Total columns** | **82** | |
| **Training features** | **75** | |

---

## XGBoost Usage

```python
ID_COLS   = ['flow_id', 'session_key', 'actor_id']
META_COLS = ['label_confidence', 'evidence_mask', 'evidence_detail']
TARGET    = 'label'
FEAT_COLS = [c for c in df.columns if c not in ID_COLS + META_COLS + [TARGET]]

# GroupKFold by actor_id — same tool never in train + test
from sklearn.model_selection import GroupKFold
gkf = GroupKFold(n_splits=5)
for train_idx, val_idx in gkf.split(X, y, groups=df['actor_id']):
    ...

# DMatrix with confidence weighting
dtrain = xgb.DMatrix(X_train, label=y_train,
                      weight=df.loc[train_idx, 'label_confidence'].values)

# Categorical features
CAT = ['ip_proto', 'app_proto', 'conn_state', 'http_method', 'dns_qtype', 'tls_version']

# NaN = missing. XGBoost handles natively. Do NOT impute.
```

### Parameters

```python
params = {
    'objective': 'multi:softprob',
    'num_class': 5,
    'max_depth': 8,
    'learning_rate': 0.05,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'min_child_weight': 5,
    'tree_method': 'hist',
    'eval_metric': 'mlogloss',
}
```

### What Every Split Means

With 75 features, every XGBoost split has a clear physical interpretation:

- `iat_to_rtt > 50` → attacker pausing way longer than network delay, interactive human session
- `think_time_mean_ms < 10 AND psh_count > 20` → scripted brute-force, regardless of geography
- `rtt_ms > 200 AND iat_fwd_mean_ms < 210` → fast scanner behind high-latency link
- `ja3_freq < 5` → rare TLS fingerprint, likely custom tool
- `src_unique_ports > 100` → horizontal scan campaign
- `entropy_first > 7.0 AND http_method == 2` → encrypted POST, possible C2
- `psh_count > 20 AND dst_port == 22` → SSH brute-force session
- `window_size_init == 65535 AND tls_cipher_count < 5` → scanning tool with hardcoded TCP stack
- `payload_rtt_ratio > 10` → flooding payloads as fast as the pipe allows, bulk transfer or exfil
