# DFI-CNN Dataset v2 — 3-Class TCP-Only

## Changes from v1 → v2

### Why v2?

v1 had fundamental problems discovered during training (2026-03-18):

| Problem | v1 | v2 | Why |
|---------|----|----|-----|
| **5 classes too many** | RECON/KNOCK/BRUTE/EXPLOIT/COMPROMISE | **RECON/ATTACK/CLEAN** | KNOCK vs BRUTE indistinguishable at flow level (54% F1). Merge into ATTACK → 94.5% vs 91.3% |
| **ICMP/UDP noise** | All protocols | **TCP only (ip_proto=6)** | ICMP responses look clean. UDP probes have different profile. Mixing protocols confuses the model |
| **Egress in training data** | All VLANs | **Ingress only (vlan!=101)** | VLAN 101 = our hosts responding. Reversed src/dst, near-zero pkts_fwd → model learns trivial shortcut |
| **No-reply = RECON** | Label from evidence only | **pkts_rev=0 → force RECON** | Regardless of evidence label, zero reply packets means the target never responded → scanning, not interaction |
| **Tokenizer bug** | `tcp_flags_seq` used raw flags | **Fixed flag token mapping** | Embedding(17,6) but tokens could exceed vocab — caused silent OOB. Fixed 2026-03-21 |
| **Embedding offset** | Undocumented +11 offset | **Explicit: Embedding(23,12) with +11 offset** | size_dir tokens [-11..+11] must be offset to [0..22] for embedding lookup. v1 had inconsistent handling |
| **src_* features** | Real values from source_stats | **Zero-filled by design** | CNN trained with src_* zeroed → CNN learns from sequences only. At inline scoring time, src_* are unavailable anyway |
| **Clean data contamination** | Clean SPAN had 40% dirty | **Verified clean: `clean_real.csv`** | 33,941 IPs (13.5%) in clean SPAN were real scanners generating 40% of flows. Split out with XGB scoring |

### Key Lessons

1. **3-class > 5-class:** KNOCK/BRUTE indistinguishable at flow level. Merge into ATTACK → 98.9% XGB, 94.5% CNN
2. **TCP only:** ICMP/UDP pollute model. Filter `ip_proto=6`
3. **Ingress only:** VLAN 101 egress is our hosts responding — reversed direction, trivial clean shortcut
4. **No-reply = RECON:** Regardless of evidence label, `pkts_rev=0` means scanning
5. **Dirty replied split:** For training data generation, `conn_state` in {0,1,3,6,7} → ATTACK, `conn_state` in {2,4,5} → ATTACK (same class in v2)
6. **Pre-expand CNN arrays in prep:** Training loads flat columns. No parsing at train time
7. **Polars for prep:** Cast ALL non-string cols to Float64 before concat. Small batch test first (n_rows=1000)

---

## Labels — 3 Classes

| Code | Name | Criteria |
|------|------|----------|
| 0 | **RECON** | No reply packets (`pkts_rev=0`), OR no host-side events in ±120s window. Scanning/probing. |
| 1 | **ATTACK** | Merged KNOCK+BRUTE+EXPLOIT+COMPROMISE. Any flow with reply (`pkts_rev>0`) AND evidence of interaction: connection reached service, auth attempts, suspicious commands, exploitation. |
| 2 | **CLEAN** | Verified clean ingress traffic. From `clean_real.csv` (XGB-scored to remove scanner contamination). Background internet traffic, CDN, DNS, legitimate users. |

### v1 → v2 Label Mapping

| v1 label | v1 name | v2 label | v2 name | Reason |
|----------|---------|----------|---------|--------|
| 0 | RECON | 0 | RECON | Same |
| 1 | KNOCK | 1 | ATTACK | Merged — indistinguishable from BRUTE at flow level |
| 2 | BRUTEFORCE | 1 | ATTACK | Merged |
| 3 | EXPLOIT | 1 | ATTACK | Merged |
| 4 | COMPROMISE | 1 | ATTACK | Merged (very rare, 669 flows) |
| 5 | NORM/CLEAN | 2 | CLEAN | Renumbered; verified clean only |

---

## Label Metadata (do not train)

Same as v1:

| Column | Type | Purpose |
|--------|------|---------|
| `label_confidence` | float32 0–1 | Sample weight for loss function |
| `evidence_mask` | uint8 | Bitmask of host events observed |
| `evidence_detail` | string | Audit trail |

## Identity (do not train)

Same as v1:

| Column | Type | Purpose |
|--------|------|---------|
| `flow_id` | string | UUID per row |
| `session_key` | string | 5-tuple hash |
| `actor_id` | string | For GroupKFold splits — same attacker never in train+test |

---

## Data Filters (applied BEFORE training)

```python
# 1. TCP only
df = df.filter(pl.col('ip_proto') == 6)

# 2. Ingress only (exclude egress VLAN 101)
df = df.filter(pl.col('vlan_id') != 101)

# 3. No-reply → force RECON regardless of original label
df = df.with_columns(
    pl.when(pl.col('pkts_rev') == 0).then(0).otherwise(pl.col('label')).alias('label')
)

# 4. Map 5-class → 3-class
# 0→0 (RECON), 1/2/3/4→1 (ATTACK), 5→2 (CLEAN)
df = df.with_columns(
    pl.when(pl.col('label') == 0).then(0)
      .when(pl.col('label').is_in([1,2,3,4])).then(1)
      .when(pl.col('label') == 5).then(2)
      .otherwise(pl.col('label'))
      .alias('label')
)
```

---

## Sequence Input — 5 Channels × 128 Positions

**Identical structure to v1.** Same 5 channels, same vocabs, same embedding dims.

### Tokenizer Fixes (v2)

**Flag token (Channel 2):**
```python
# v1 bug: raw bitwise OR could produce tokens > 16
# v2 fix: cap combined flags
token = 0
if flags & 0x02: token |= 1    # SYN
if flags & 0x01: token |= 2    # FIN
if flags & 0x04: token |= 4    # RST
if flags & 0x08: token |= 8    # PSH
if flags & 0x10: token |= 16   # ACK (mapped to PRESENT)
if token == 0 and is_tcp: token = 16  # PRESENT (real packet, no flags)
# v2: vocab is STILL 17 (0..16) but never exceeds 16 due to explicit mapping
# v2 NOTE: Embedding(17, 6) — NOT Embedding(33, 6). The old code had Embedding(33,6)
#   due to a bug where raw tcp_flags (up to 0xFF) were passed directly
```

**Size dir token (Channel 1) — offset handling:**
```python
# Tokens are [-11..+11], stored as-is in pkt_size_dir column
# At training time, MUST offset by +11 before embedding lookup:
size_seq = df[size_cols].values + 11   # [-11..+11] → [0..22]
# Embedding(23, 12, padding_idx=0) — index 0 = padding, index 11 = zero-payload
```

**Entropy token (Channel 5) — pre-computed at ingest (v2 optimization):**
```python
# v1: computed from payload_head bytes at tokenize time
# v2: pre-computed at ingest time in hunter.py _update_session()
#   Saves ~32KB/session memory (no payload_head stored on events)
#   PacketEvent now has entropy_bin and payload_entropy fields
#   Tokenizer reads pre-computed values, falls back to old path for legacy events
```

### Channel Summary (unchanged from v1)

| Channel | Column pattern | Vocab | Embed dim | Signal |
|---------|---------------|-------|-----------|--------|
| 1. size_dir | `size_dir_seq_1..128` | 23 | 12 | Packet size + direction |
| 2. tcp_flags | `tcp_flags_seq_1..128` | 17 | 6 | TCP control events |
| 3. iat_log_ms | `iat_log_ms_seq_1..128` | 9 | 6 | Absolute timing |
| 4. iat_rtt_bin | `iat_rtt_bin_seq_1..128` | 10 | 6 | RTT-normalized timing |
| 5. entropy_bin | `entropy_bin_seq_1..128` | 7 | 4 | Payload content |

Per-position: 12+6+6+6+4 = **34 dims × 128 positions → Conv1D input (B, 34, 128)**

---

## Static Metadata Branch — 42 Scalar Features (v2 change: src_* zero-filled)

Same 42 features as v1, same groups (S1–S6).

**v2 change:** `src_*` features (S6, 6 columns) are **zero-filled by design**:

| Feature | v1 | v2 | Reason |
|---------|----|----|--------|
| `src_flow_count` | Real from source_stats | **0** | Not available at inline scoring time |
| `src_unique_ports` | Real | **0** | Same |
| `src_unique_protos` | Real | **0** | Same |
| `src_unique_dsts` | Real | **0** | Same |
| `src_span_min` | Real | **0** | Same |
| `src_avg_pps` | Real | **0** | Same |

**Why:** At inline scoring (hunter2 session flush), source_stats haven't been computed yet. The CNN must learn to classify from sequences + flow-level features WITHOUT campaign context. XGBoost gets src_* for batch scoring; CNN does not.

**The 42 static features remain identical in schema.** The only change is that S6 values are always 0 during both training and inference.

---

## Architecture — DFI_CNN v2

```python
class DFI_CNN(nn.Module):
    def __init__(self, num_classes=3):  # v2: 3 classes, not 5
        super().__init__()

        # Embeddings (unchanged from v1)
        self.size_emb    = nn.Embedding(23, 12, padding_idx=0)
        self.flag_emb    = nn.Embedding(17,  6, padding_idx=0)  # v2 fix: was Embedding(33,6)
        self.iat_emb     = nn.Embedding( 9,  6, padding_idx=0)
        self.rtt_emb     = nn.Embedding(10,  6, padding_idx=0)
        self.entropy_emb = nn.Embedding( 7,  4, padding_idx=0)

        # Conv1D: inception-style parallel kernels (v2: added kernel 3,5,7)
        self.conv3 = nn.Sequential(nn.Conv1d(34, 64, 3, padding=1), nn.BatchNorm1d(64), nn.ReLU())
        self.conv5 = nn.Sequential(nn.Conv1d(34, 64, 5, padding=2), nn.BatchNorm1d(64), nn.ReLU())
        self.conv7 = nn.Sequential(nn.Conv1d(34, 64, 7, padding=3), nn.BatchNorm1d(64), nn.ReLU())
        # Merge: 64*3 = 192
        self.pool = nn.AdaptiveMaxPool1d(1)  # → (B, 192, 1)

        self.static_bn = nn.BatchNorm1d(42)

        self.head = nn.Sequential(
            nn.Linear(192 + 42, 128),  # v2: 192 from 3 parallel convs
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, num_classes),  # v2: 3 classes
        )

    def forward(self, size_seq, flag_seq, iat_seq, rtt_seq, ent_seq, static_feat):
        s = self.size_emb(size_seq)
        f = self.flag_emb(flag_seq)
        i = self.iat_emb(iat_seq)
        r = self.rtt_emb(rtt_seq)
        e = self.entropy_emb(ent_seq)

        x = torch.cat([s, f, i, r, e], dim=2).transpose(1, 2)  # (B, 34, 128)
        mask = (size_seq != 0).unsqueeze(1).float()
        x = x * mask

        c3 = self.conv3(x)  # (B, 64, 128)
        c5 = self.conv5(x)  # (B, 64, 128)
        c7 = self.conv7(x)  # (B, 64, 128)
        x = torch.cat([c3, c5, c7], dim=1)  # (B, 192, 128)
        x = self.pool(x).squeeze(2)  # (B, 192)

        m = self.static_bn(static_feat)
        return self.head(torch.cat([x, m], dim=1))
```

---

## Column Layout — Full Parquet (v2)

**Total: 689 columns** (unchanged count, same schema, different semantics)

```
# Identity + Labels (7)
flow_id, session_key, actor_id,
label,              # v2: 0=RECON, 1=ATTACK, 2=CLEAN (was 0-4 in v1)
label_confidence, evidence_mask, evidence_detail

# CNN Sequence Channels (640)
size_dir_seq_1..128
tcp_flags_seq_1..128
iat_log_ms_seq_1..128
iat_rtt_bin_seq_1..128
entropy_bin_seq_1..128

# Static Metadata (42) — src_* always 0
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
src_flow_count, src_unique_ports, src_unique_protos,   # always 0
src_unique_dsts, src_span_min, src_avg_pps              # always 0
```

**Format:** Parquet (not CSV — 689 cols too wide for CSV). Use polars for loading.

---

## Training Data Prep

### Proven script: `prep_cnn_3class.py` (ai-shared/ml/)

```python
# Load with polars (fast, handles CH CSV nulls)
df = pl.read_csv(path, null_values=[r'\N', 'NULL', ''],
                 infer_schema_length=50000, ignore_errors=True,
                 truncate_ragged_lines=True)

# Cast ALL non-string cols to Float64 before concat
for c in df.columns:
    if df[c].dtype not in (pl.Utf8, pl.String):
        df = df.with_columns(pl.col(c).cast(pl.Float64, strict=False))

# Filter: TCP + ingress + no-reply→RECON
df = df.filter(pl.col('ip_proto') == 6)
df = df.filter(pl.col('vlan_id') != 101)
df = df.with_columns(
    pl.when(pl.col('pkts_rev') == 0).then(0).otherwise(pl.col('label')).alias('label')
)

# Map to 3 classes
df = df.with_columns(
    pl.when(pl.col('label') == 0).then(0)
      .when(pl.col('label').is_in([1,2,3,4])).then(1)
      .when(pl.col('label') == 5).then(2)
      .otherwise(pl.col('label')).alias('label')
)

# Balance: equal per class
min_count = df.group_by('label').count()['count'].min()
balanced = pl.concat([
    df.filter(pl.col('label') == c).sample(n=min_count, seed=42)
    for c in [0, 1, 2]
])

# Expand pkt_* arrays → 128 flat cols per channel
# Array columns stored as "[1,2,3,...]" strings in CH CSV
for ch in ['pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy']:
    col = balanced[ch].cast(pl.Utf8).str.strip_chars('[]"')
    split = col.str.split(',')
    exprs = [
        split.list.get(i, null_on_oob=True).cast(pl.Int8, strict=False).fill_null(0).alias(f'{ch.replace("pkt_","")}_seq_{i+1}')
        for i in range(128)
    ]
    balanced = balanced.with_columns(exprs)

# Label dtype: ensure Int32 (parquet stores Float64 by default)
balanced = balanced.with_columns(pl.col('label').cast(pl.Int32))

# Output
balanced.write_parquet('cnn_3class_training.parquet')
```

---

## Training

### Proven script: `train_cnn_3class.py` (ai-shared/ml/)

```bash
python3 -u train_cnn_3class.py cnn_3class_training.parquet \
    --epochs 50 --batch-size 16384 --lr 0.004 --folds 5 \
    --scale-pos-weight 5 -o ./models
```

Key settings:
- **GroupKFold** by `actor_id` — same attacker tool never in train+test
- **label_confidence** as per-sample loss weight
- **Early stopping** on val loss (patience=10)
- **scale_pos_weight=5** for attack class boost
- **GPU recommended** (A40 on Test server)

---

## v2 Results (2026-03-18)

### 3-Class CNN TCP
- **Accuracy:** 94.5% (5-fold avg), Macro F1: 94.5%
- **Per-class:** RECON 93.8%, ATTACK 94.5%, CLEAN 97.3%
- **Dirty detection:** 99.0% IP (any-attack), 97.3% IP (majority)
- **Clean ingress FP:** 0.93% flow, 5.49% IP
- **Data:** 12.6M TCP-only ingress flows, 4.2M per class, 693 cols

### vs v1 (5-class binary evil/clean)
| Metric | v1 (5-class binary) | v2 (3-class TCP) |
|--------|--------------------|--------------------|
| Accuracy | 95.0% | 94.5% |
| Dirty IP detection | 99.5% | 99.0% |
| Clean FP (flow) | 0.5% | 0.93% |
| RECON vs ATTACK confusion | High (KNOCK=54% F1) | N/A (merged) |
| Usable for inline scoring | Yes | Yes |
| Protocol noise | ICMP/UDP present | TCP-only, clean |

---

## Relationship to XGBoost v2

| Aspect | XGB 3-class TCP | CNN 3-class TCP |
|--------|----------------|-----------------|
| Classes | RECON/ATTACK/CLEAN | RECON/ATTACK/CLEAN |
| Accuracy | 98.93% | 94.5% |
| Training inputs | 75 scalars | 640 tokens + 42 scalars |
| Strength | Scanner detection (src_*), aggregate stats | Sequence patterns, protocol transitions |
| Weakness | Multi-packet session content | Single-packet thin probes |
| Inline scoring | Yes (feature extraction at flush) | Yes (pkt_tokens at flush) |
| src_* features | Real values (batch), zero (inline) | Always zero |

**Ensemble:** XGB + CNN together achieve >99.5% dirty IP detection. XGB catches scanners via campaign features; CNN catches exploits via sequence patterns.
