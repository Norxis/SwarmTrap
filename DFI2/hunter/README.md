# Hunter2 -- Capture Engine

Hunter2 is the core network capture and inline scoring engine for SwarmTrap. It captures raw SPAN traffic from a network mirror port using Linux AF_PACKET TPACKET_V3 sockets, reassembles bidirectional flows, extracts 75 statistical features per flow, scores them in real time with XGBoost and/or CNN models, and writes everything to ClickHouse.

## Architecture Overview

```
SPAN mirror port (10G+)
        |
  AF_PACKET TPACKET_V3 ring buffer
        |
  PACKET_FANOUT_HASH (5-tuple)
        |
  +---------+---------+---------+
  |Worker 0 |Worker 1 |Worker 2 | ... (N workers, one per process)
  |         |         |         |
  | ingest()| ingest()| ingest()|   <-- per-packet callback, zero IPC
  |         |         |         |
  | Session | Session | Session |   <-- OrderedDict LRU, per-worker
  | Tracker | Tracker | Tracker |
  |         |         |         |
  | flush() | flush() | flush() |   <-- background thread per worker
  |    |    |    |    |    |    |
  |  Writer |  Writer |  Writer |   <-- buffered CH inserts
  +---------+---------+---------+
        |
  ClickHouse (dfi, dfi_dirty, dfi_clean, dfi_recon)
```

Each worker process owns its own mmap ring buffer, session table, scorer instance, and ClickHouse writer. There is zero inter-process communication on the hot path. The only shared state is a tiny stats queue for monitoring (~4 dicts per 30 seconds).

## File Reference

### Core Pipeline

| File | Purpose |
|------|---------|
| `hunter.py` | Main entry point. `SessionTracker` manages flow state, `_worker_factory` sets up per-worker components, `main()` starts the capture. |
| `afpacket.py` | AF_PACKET TPACKET_V3 + PACKET_FANOUT_HASH capture engine. Handles raw socket creation, mmap ring buffers, Ethernet/IP/TCP/UDP parsing, CPU pinning, and multi-process fanout. Designed for 10G+ line rate. |
| `features.py` | Extracts 75 statistical features from a completed session. Covers protocol identification, volume metrics, timing/RTT analysis, packet size histograms, TCP flag behavior, and payload entropy. |
| `scorer.py` | Inline model scoring. `InlineScorer` loads an XGBoost Booster for <1ms binary or multi-class prediction. `InlineCNNScorer` loads a PyTorch CNN model (5-channel packet embeddings + 42 static features). |
| `tokenizer.py` | Converts raw packet events into 5-channel CNN tokens: `size_dir_token` (log2 payload size x direction), `flag_token` (TCP flag bitmask), `iat_log_ms_bin` (inter-arrival time bucket), `iat_rtt_bin` (IAT/RTT ratio bucket), `entropy_bin` (payload entropy bucket). Up to 128 tokens per flow. |
| `writer.py` | Buffered ClickHouse writer with per-table deques, background flush thread, column introspection, and automatic requeue on failure. Routes attack flows to `dfi`, norm flows to `dfi_dirty`/`dfi_clean`, recon detections to `dfi_recon`. |

### Supporting Modules

| File | Purpose |
|------|---------|
| `config.py` | All configuration via environment variables: interface, capture mode, worker count, ClickHouse connection, session timeouts, model paths, honeypot IPs, confidence thresholds. |
| `watchlist.py` | SQLite-backed watchlist reader with background refresh thread. Supports IP lookup, TTL-based expiry, and promote/upsert for adding new IPs. |
| `depth.py` | Capture depth constants and filtering logic. D0=DROP (skip entirely), D1=FLOW (metadata only), D2=SEQUENCE (packet tokens), D3=FULL (raw payloads). Controls what gets written per flow. |
| `filters.py` | Five packet filter strategies that determine which traffic to capture and how to orient flows (attacker vs peer): `HoneypotFilter`, `AllTrafficFilter`, `SpanWatchlistFilter`, `DirtyTrafficFilter`, `CleanTrafficFilter`. |
| `fingerprints.py` | Protocol fingerprint extraction: JA3 hash from TLS ClientHello, HASSH from SSH key exchange, HTTP request method/headers/User-Agent hash, DNS query type/name. |
| `evidence.py` | Unix domain socket reader for honeypot evidence events (auth failures, process creation, privilege escalation, etc.). Writes to `dfi.evidence_events`. |
| `cnn_server.py` | Standalone TCP server for batch CNN inference. Receives packed FlowRecord structs from a remote ARM processor, runs batch prediction, returns CNNResult structs. Length-prefixed binary protocol. |
| `xdp_honeypot_filter.c` | XDP eBPF program for pre-filtering SPAN traffic at the NIC driver level. Passes only honeypot-related traffic (216.126.0.128/25 and 108.181.161.199) to AF_PACKET, drops everything else before it reaches userspace. |
| `flow_evidence_enrich.py` | Cron job that joins `model_predictions` with `evidence_events` to produce enriched `flow_evidence` rows. Watermark-based incremental processing. |

### Burst Capture Scripts

| File | Purpose |
|------|---------|
| `dirty_capture_burst.sh` | Starts a time-limited dirty traffic capture burst (watchlist IPs only). |
| `clean_capture_burst.sh` | Starts a time-limited clean traffic capture burst (excludes watchlist + honeypot IPs). |
| `all_capture_burst.sh` | Starts a time-limited all-traffic capture burst. |
| `norm_capture_burst.sh` | Starts a norm traffic capture burst. |

## Feature Extraction (75 Features)

The 75 features are organized into 8 groups:

### F1. Protocol (3 features)
`dst_port`, `ip_proto`, `app_proto` -- Application protocol mapped from well-known ports (SSH=1, HTTP=2, HTTPS=3, DNS=4, SMTP=5, FTP=6, Telnet=7, RDP=8, VNC=9, SMB=10, MySQL=11, MSSQL=12, PostgreSQL=13, Redis=14, MongoDB=15).

### F2. Volume (8 features)
`pkts_fwd`, `pkts_rev`, `bytes_fwd`, `bytes_rev`, `bytes_per_pkt_fwd`, `bytes_per_pkt_rev`, `pkt_ratio`, `byte_ratio` -- Forward/reverse packet and byte counts with derived ratios.

### F3. Timing (10 features)
`duration_ms`, `rtt_ms`, `iat_fwd_mean_ms`, `iat_fwd_std_ms`, `think_time_mean_ms`, `think_time_std_ms`, `iat_to_rtt`, `pps`, `bps`, `payload_rtt_ratio` -- RTT estimated from SYN/SYN-ACK timing. Think time = IAT minus RTT. Payload-to-RTT ratio measures data density relative to network latency.

### F4. Size Shape (14 features)
`n_events`, `fwd_size_mean`, `fwd_size_std`, `fwd_size_min`, `fwd_size_max`, `rev_size_mean`, `rev_size_std`, `rev_size_max`, `hist_tiny` (1-63B), `hist_small` (64-255B), `hist_medium` (256-1023B), `hist_large` (1024-1499B), `hist_full` (1500B+), `frac_full` -- Payload size distribution histogram.

### F5. TCP Behavior (11 features)
`syn_count`, `fin_count`, `rst_count`, `psh_count`, `ack_only_count`, `conn_state` (0=SYN_ONLY through 6=SYN_FLOOD), `rst_frac`, `syn_to_data`, `psh_burst_max`, `retransmit_est`, `window_size_init` -- TCP handshake and teardown characteristics.

### F6. Payload Content (8 features)
`entropy_first`, `entropy_fwd_mean`, `entropy_rev_mean`, `printable_frac`, `null_frac`, `byte_std`, `high_entropy_frac`, `payload_len_first` -- Shannon entropy, byte distribution, and ASCII content analysis of first forward payload.

### F7. Protocol Fingerprints (15 features)
`ja3_freq`, `tls_version`, `tls_cipher_count`, `tls_ext_count`, `tls_has_sni`, `hassh_freq`, `ssh_kex_count`, `http_method`, `http_uri_len`, `http_header_count`, `http_ua_freq`, `http_has_body`, `http_status`, `dns_qtype`, `dns_qname_len` -- Frequency-encoded JA3/HASSH/User-Agent hashes plus protocol-specific metadata.

### F8. Source Behavior (6 features)
`src_flow_count`, `src_unique_ports`, `src_unique_protos`, `src_unique_dsts`, `src_span_min`, `src_avg_pps` -- Aggregated source IP statistics from ClickHouse `source_stats` materialized view.

## Scoring Pipeline

### XGBoost Inline Scoring
Loaded at worker startup from `XGB_MODEL_PATH`. Each completed flow is scored in <1ms using a DMatrix with the 75 feature columns. Supports binary (ATTACK/NORM) and multi-class (softprob) models. Missing features become NaN (handled natively by XGBoost).

### CNN Inline Scoring
Loaded from `.pt` files. Takes 5 packet sequence channels (128 tokens each) plus 42 static scalar features. Architecture: 5 learned embeddings -> multi-scale 1D convolutions (kernel 3/5/7) -> merge conv -> adaptive max pool -> concatenate with BatchNorm'd static features -> 2-layer classification head.

### Recon Scoring
Optional second XGBoost model (`RECON_MODEL_PATH`) specifically trained to detect reconnaissance/scanning. High-confidence detections are written to `dfi_recon.recon_flows` with full feature vectors.

## ClickHouse Write Path

The `DFIWriter` maintains separate buffer deques for each target table:

- `dfi.flows_buffer` -- Attack/labeled flows with all 75 features + CNN token arrays
- `dfi.fingerprints_buffer` -- JA3, HASSH, HTTP, DNS fingerprints per flow
- `dfi.fanout_hops_buffer` -- Attacker-to-target hop tracking
- `dfi.payload_bytes_buffer` -- Raw payload hex (D3 depth only)
- `dfi.evidence_events_buffer` -- Honeypot evidence from Unix socket
- `dfi.model_predictions_buffer` -- XGBoost/CNN prediction results
- `dfi_dirty.flows_buffer` / `dfi_clean.flows_buffer` -- Separated capture databases
- `dfi_recon.recon_flows_buffer` -- High-confidence recon detections

Buffers flush every 1 second or when any buffer exceeds 50,000 rows. Column names are introspected from ClickHouse DESCRIBE TABLE to handle schema evolution. Failed inserts are requeued up to 10x buffer size.

## Session Management

- Sessions are keyed by `(bad_ip, peer_ip, src_port, dst_port, ip_proto)`.
- `OrderedDict` provides O(1) LRU eviction when the session table is full.
- Sessions expire after `SESSION_TIMEOUT` seconds (default 120s) of inactivity.
- Maximum 500,000 concurrent sessions per worker (configurable via `MAX_SESSIONS`).
- Packet events are capped at 128 per session; deques capped at 256 entries to bound memory.

## Capture Modes

| Mode | Filter | Description |
|------|--------|-------------|
| `honeypot` | `HoneypotFilter` | Only traffic involving configured honeypot IPs. Identifies attackers by contact with honeypots. |
| `span` | `SpanWatchlistFilter` | Only traffic involving IPs on the SQLite watchlist. |
| `all` | `AllTrafficFilter` | All SPAN traffic. Honeypot/watchlist = attack, everything else = norm (actor_id='norm'). |
| `dirty` | `DirtyTrafficFilter` | Only watchlist IPs, excludes honeypots. For training data: known-bad traffic. |
| `clean` | `CleanTrafficFilter` | Excludes all watchlist AND honeypot IPs. For training data: known-clean traffic. |

## Capture Depth Levels

| Depth | Constant | Flow | Fingerprint | Fanout | Packets | Payload |
|-------|----------|------|-------------|--------|---------|---------|
| D0 | `D0_DROP` | No | No | No | No | No |
| D1 | `D1_FLOW` | Yes | Yes | Yes | No | No |
| D2 | `D2_SEQUENCE` | Yes | Yes | Yes | Yes | No |
| D3 | `D3_FULL` | Yes | Yes | Yes | Yes | Yes |

D0 IPs can be re-promoted to D2 if they contact a new port different from their `top_port` in the watchlist (port-novelty re-promotion).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HUNTER_IFACE` | `ens192` | Network interface to capture from |
| `CAPTURE_MODE` | `honeypot` | One of: `honeypot`, `span`, `all`, `dirty`, `clean` |
| `FANOUT_WORKERS` | `4` | Number of AF_PACKET fanout worker processes |
| `CPU_LIST` | `` | CPU core pinning (e.g., `0-3`, `8-15`) |
| `CH_HOST` | `localhost` | ClickHouse host |
| `CH_PORT` | `9000` | ClickHouse native port |
| `CH_DATABASE` | `dfi` | Primary ClickHouse database |
| `WATCHLIST_DB` | `/opt/dfi-hunter/watchlist.db` | SQLite watchlist path |
| `WATCHLIST_REFRESH` | `30` | Watchlist reload interval (seconds) |
| `SESSION_TIMEOUT` | `120` | Idle timeout before flushing a session (seconds) |
| `FLUSH_INTERVAL` | `10` | Background flush interval (seconds) |
| `MAX_SESSIONS` | `500000` | Max concurrent sessions per worker |
| `XGB_MODEL_PATH` | `` | Path to XGBoost `.json` model (empty = no scoring) |
| `RECON_MODEL_PATH` | `` | Path to recon XGBoost model (empty = disabled) |
| `HONEYPOT_IPS` | `` | Comma-separated honeypot IPs/CIDRs |
| `HONEYPOT_EXCLUDE` | `172.16.0.0/12,...` | CIDRs to exclude from honeypot filter |
| `SENSOR_ID` | `aio1` | Sensor identifier |
| `BLOCK_SIZE_MB` | `2` | TPACKET_V3 block size (MB, must be power of 2) |
| `BLOCK_COUNT` | `128` | Ring buffer blocks per worker (total ring = block_size * block_count) |

## systemd Services

Two example service files are provided:

- `dfi-dirty-capture.service` -- Runs continuously (`Restart=always`), captures watchlist/honeypot D2 traffic. Uses `env_dirty` environment file with `CPU_LIST=8-15`.
- `dfi-clean-capture.service` -- Runs on failure restart, captures clean SPAN traffic. Uses `env_clean` environment file with `CPU_LIST=16-23`.

Both require `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities and run as root. Working directory is `/opt/dfi2`, invoked as `python3 -m hunter.hunter`.

## Dependencies

- Python 3.10+
- `xgboost` (for inline XGBoost scoring)
- `torch` (for inline CNN scoring, optional)
- `clickhouse-driver` (ClickHouse native protocol)
- `numpy`
- Linux kernel with AF_PACKET TPACKET_V3 support
