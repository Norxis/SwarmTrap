# GOD 1 Enhancements — Batch Scoring, Source Stats, Watchlist, Reputation, Persistence

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make GOD 1 production-quality with batch XGB scoring, per-IP source stats, watchlist+MikroTik integration, ip_reputation_builder integration, and IP table persistence.

**Architecture:** All changes are in 3 files: `god1_test.py` (AIO), `god2_verdict.py` (PV1), `god1_listener.py` (PV1). GOD 1 accumulates expired sessions and scores in batches. IPTable tracks per-IP source stats (flow count, unique ports/protos/dsts, span, avg pps). GOD 2 reads from ip_reputation_builder's settled state, writes verdicts to watchlist.db for MikroTik sync. IPTable saves/loads to JSON on shutdown/startup.

**Tech Stack:** Python 3.12, xgboost 3.2, nats-py, clickhouse-driver, sqlite3, numpy

---

## File Map

| File | Location | Changes |
|------|----------|---------|
| `god1_test.py` | `/home/colo8gent/DFI2/god1/god1_test.py` → AIO `/opt/dfi2/god1.py` | Batch scoring, source stats, IP table persistence, signal handler |
| `god2_verdict.py` | `/home/colo8gent/DFI2/god1/god2_verdict.py` → PV1 `/opt/dfi2/ml/god2_verdict.py` | Read reputation builder state, write to watchlist.db |
| `god1_listener.py` | `/home/colo8gent/DFI2/god1/god1_listener.py` → PV1 `/opt/dfi2/ml/god1_listener.py` | Include source stats in CH writes |

---

### Task 1: Batch XGB Scoring

**Files:**
- Modify: `god1_test.py` — `XGBScorer.score_batch()` method + capture loop batch accumulation

**Current:** `scorer.score(feat)` called once per expired session — creates a DMatrix per flow.
**Target:** Accumulate expired sessions, build one DMatrix for all, predict in one call.

- [ ] **Step 1: Add `score_batch()` to XGBScorer**

```python
def score_batch(self, feats: list[dict]) -> list[dict]:
    """Score multiple feature dicts in one DMatrix call."""
    if not feats:
        return []
    rows = []
    for feat in feats:
        rows.append([float(feat.get(f) if feat.get(f) is not None else 0.0) for f in self._feats])
    dmat = self._xgb.DMatrix(np.array(rows, dtype=np.float32), feature_names=self._feats, nthread=4)
    preds = self._booster.predict(dmat)
    results = []
    for raw in preds:
        if isinstance(raw, np.ndarray):
            label = int(np.argmax(raw))
            results.append({'label': label, 'name': CLASS_NAMES.get(label, '?'),
                            'confidence': float(raw[label]), 'probs': [float(p) for p in raw]})
        else:
            prob = float(raw)
            label = 1 if prob > 0.5 else 0
            results.append({'label': label, 'name': CLASS_NAMES.get(label, '?'),
                            'confidence': max(prob, 1-prob), 'probs': [1-prob, prob]})
    return results
```

- [ ] **Step 2: Change capture loop to batch score**

Replace the session expiry block (lines ~559-571) with:

```python
        # Expire sessions every 10s
        if now - last_expire >= 10.0:
            expired_sessions = []
            expired_keys = [k for k, s in sessions.items() if now - s.last_ts > SESSION_TIMEOUT]
            for k in expired_keys:
                s = sessions.pop(k)
                if s.pkts_fwd + s.pkts_rev >= 3:
                    expired_sessions.append(s)

            if expired_sessions:
                feats = [extract_features(s) for s in expired_sessions]
                results = scorer.score_batch(feats)
                for s, result in zip(expired_sessions, results):
                    ip_table.record(s.src_ip, result, s.last_ts)
                    nats_bridge.enqueue(s.src_ip, result, s.last_ts)
                    total_scored += 1

            drop_filter.expire()
            last_expire = now
```

- [ ] **Step 3: Deploy and verify**

```bash
scp -P 2222 god1_test.py colo8gent@172.16.3.113:/tmp/god1_test.py
# SSH to AIO via PV1, copy + restart
sudo cp /tmp/god1_test.py /opt/dfi2/god1.py && sudo systemctl restart dfi-god1
# Check log for batch scoring
journalctl -u dfi-god1 -n 10
```

Expected: same scored count per cycle, lower CPU (one DMatrix per batch, not per flow).

---

### Task 2: Source Stats

**Files:**
- Modify: `god1_test.py` — `IPTable` gains per-IP source tracking, `extract_features()` receives source stats

**Current:** IPTable stores per-IP attack counts. XGB features miss `src_flow_count`, `src_unique_ports`, `src_unique_protos`, `src_unique_dsts`, `src_span_min`, `src_avg_pps`.
**Target:** IPTable tracks unique ports, protos, dsts, timespan, and pps per src_ip. These are injected into the feature dict before scoring.

- [ ] **Step 1: Extend IPTable.record() to track source stats**

Add tracking fields to the per-IP record in `IPTable.__init__` default and `record()`:

```python
class IPTable:
    def __init__(self):
        self.ips = {}

    def record(self, src_ip: str, dst_ip: str, dst_port: int, ip_proto: int,
               pkts: int, duration_s: float, result: dict, ts: float):
        if src_ip not in self.ips:
            self.ips[src_ip] = {
                'flows': 0, 'attacks': 0, 'first_seen': ts, 'last_seen': ts,
                'worst_label': 4, 'worst_conf': 0.0, 'labels': defaultdict(int),
                'unique_ports': set(), 'unique_protos': set(), 'unique_dsts': set(),
                'total_pkts': 0,
            }
        rec = self.ips[src_ip]
        rec['flows'] += 1
        rec['last_seen'] = ts
        rec['labels'][result['label']] += 1
        rec['unique_ports'].add(dst_port)
        rec['unique_protos'].add(ip_proto)
        rec['unique_dsts'].add(dst_ip)
        rec['total_pkts'] += pkts
        if result['label'] < 4:
            rec['attacks'] += 1
        if result['label'] < rec['worst_label'] or (result['label'] == rec['worst_label'] and result['confidence'] > rec['worst_conf']):
            rec['worst_label'] = result['label']
            rec['worst_conf'] = result['confidence']

    def get_source_stats(self, src_ip: str) -> dict:
        """Return src_* features for XGB scoring."""
        rec = self.ips.get(src_ip)
        if not rec:
            return {}
        span_s = max(rec['last_seen'] - rec['first_seen'], 0.001)
        return {
            'src_flow_count': rec['flows'],
            'src_unique_ports': len(rec['unique_ports']),
            'src_unique_protos': len(rec['unique_protos']),
            'src_unique_dsts': len(rec['unique_dsts']),
            'src_span_min': span_s / 60.0,
            'src_avg_pps': rec['total_pkts'] / span_s,
        }
```

- [ ] **Step 2: Inject source stats into feature dict before scoring**

In the batch scoring block from Task 1:

```python
            if expired_sessions:
                feats = []
                for s in expired_sessions:
                    feat = extract_features(s)
                    feat.update(ip_table.get_source_stats(s.src_ip))
                    feats.append(feat)
                results = scorer.score_batch(feats)
                for s, result in zip(expired_sessions, results):
                    ip_table.record(s.src_ip, s.dst_ip, s.dst_port, s.ip_proto,
                                    s.pkts_fwd + s.pkts_rev,
                                    max(s.last_ts - s.first_ts, 0.0),
                                    result, s.last_ts)
                    nats_bridge.enqueue(s.src_ip, result, s.last_ts)
                    total_scored += 1
```

- [ ] **Step 3: Update NATS enqueue to include source stats**

In `NATSBridge.enqueue()`, add source stats fields so the listener can write them to CH:

```python
    def enqueue(self, src_ip: str, result: dict, ts: float, src_stats: dict = None):
        msg = {
            'src_ip': src_ip,
            'label': result['label'],
            'name': result['name'],
            'confidence': round(result['confidence'], 4),
            'probs': [round(p, 4) for p in result['probs']],
            'ts': round(ts, 3),
            'sensor': 'god1_aio',
        }
        if src_stats:
            msg['src_flow_count'] = src_stats.get('src_flow_count', 0)
            msg['src_unique_ports'] = src_stats.get('src_unique_ports', 0)
            msg['src_unique_dsts'] = src_stats.get('src_unique_dsts', 0)
        with self._lock:
            self._queue.append(msg)
```

Update the call site to pass source stats:
```python
                    nats_bridge.enqueue(s.src_ip, result, s.last_ts,
                                        ip_table.get_source_stats(s.src_ip))
```

- [ ] **Step 4: Deploy and verify**

Check that source stats features appear in scoring by comparing scores with/without. IPs with many unique ports should score higher on RECON.

---

### Task 3: Watchlist + MikroTik Sync

**Files:**
- Modify: `god2_verdict.py` — add watchlist.db upsert after CH write

**Current:** GOD 2 writes verdicts to CH ip_reputation only.
**Target:** Also upsert into `/opt/dfi-hunter/watchlist.db` (SQLite) with source='god2'. The existing `update_recon_addresslist.py` hourly cron reads watchlist.db and pushes to MikroTik.

- [ ] **Step 1: Add watchlist.db write to god2_verdict.py**

After the CH INSERT block, add:

```python
    # Write to watchlist.db for MikroTik sync
    if new_verdicts:
        import sqlite3
        WATCHLIST_DB = '/opt/dfi-hunter/watchlist.db'
        try:
            con = sqlite3.connect(WATCHLIST_DB)
            now_ts = time.time()
            expires = now_ts + 30 * 86400  # 30 days
            rows = [(v['ip'], 1, 2, 'god2', f"GOD2:{v['reason']}", expires, now_ts)
                    for v in new_verdicts]
            con.executemany(
                '''INSERT INTO watchlist (src_ip, capture_depth, priority, source, reason, expires_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(src_ip) DO UPDATE SET
                     capture_depth = excluded.capture_depth,
                     priority = excluded.priority,
                     source = excluded.source,
                     reason = excluded.reason,
                     expires_at = excluded.expires_at,
                     updated_at = excluded.updated_at''',
                rows
            )
            con.commit()
            con.close()
            log.info('Watchlist: upserted %d IPs (source=god2)', len(rows))
        except Exception as e:
            log.error('Watchlist write failed: %s', e)
```

- [ ] **Step 2: Deploy and verify**

```bash
scp god2_verdict.py root@192.168.0.100:/opt/dfi2/ml/god2_verdict.py
# Run manually
ssh root@192.168.0.100 "python3 /opt/dfi2/ml/god2_verdict.py"
# Check watchlist
ssh root@192.168.0.100 "sqlite3 /opt/dfi-hunter/watchlist.db \"SELECT source, count(*) FROM watchlist WHERE source='god2'\""
```

Expected: `god2|<count>` matching the number of verdicts sent. MikroTik sync will pick these up on next hourly cron run.

---

### Task 4: ip_reputation_builder Integration

**Files:**
- Modify: `god2_verdict.py` — use reputation builder's state/scores instead of raw XGB confidence

**Current:** GOD 2 queries raw `best_xgb_class < 4 AND best_xgb_confidence >= 0.80`.
**Target:** Use the reputation builder's computed fields: `state` (STATE_EVIDENCE=2 is highest confidence), `has_any_evidence`, `capture_score`, `score_reputation`. Evidence-confirmed IPs get priority over model-only IPs.

- [ ] **Step 1: Replace SETTLED_QUERY with reputation-aware query**

```python
SETTLED_QUERY = """
SELECT
    src_ip,
    best_xgb_class,
    best_xgb_confidence,
    total_flows,
    has_any_evidence,
    state,
    capture_score
FROM dfi.ip_reputation FINAL
WHERE updated_at >= now() - INTERVAL {window} HOUR
  AND is_clean_allowlist = 0
  AND is_research_benign = 0
  AND (
    -- Tier 1: Evidence-confirmed attackers (strongest signal)
    (has_any_evidence = 1 AND state >= 1)
    OR
    -- Tier 2: High-confidence XGB attack classification
    (best_xgb_class < 4 AND best_xgb_confidence >= {min_conf} AND total_flows >= {min_flows})
  )
ORDER BY has_any_evidence DESC, best_xgb_confidence DESC
"""
```

Note the `FINAL` keyword — ensures ReplacingMergeTree dedup is applied before querying.

- [ ] **Step 2: Add tier info to verdict reason**

```python
        tier = 'T1:evidence' if has_evidence else 'T2:model'
        new_verdicts.append({
            'ip': ip,
            'action': 'DROP',
            'reason': f"{tier}:{CLASS_NAMES.get(xgb_class, '?')}:{xgb_conf:.2f}:flows={total_flows}",
            ...
        })
```

- [ ] **Step 3: Deploy and verify**

Run manually, check that evidence-confirmed IPs appear first in the verdict list.

---

### Task 5: IP Table Persistence

**Files:**
- Modify: `god1_test.py` — add `IPTable.save(path)` / `IPTable.load(path)`, signal handler for graceful shutdown

**Current:** IP table lost on every restart. GOD 1 starts cold — no knowledge of previously seen IPs.
**Target:** On SIGTERM/SIGINT, save IP table to `/opt/dfi2/god1_iptable.json`. On startup, load it back.

- [ ] **Step 1: Add save/load to IPTable**

```python
IPTABLE_PATH = os.environ.get('GOD1_IPTABLE', '/opt/dfi2/god1_iptable.json')
```

```python
class IPTable:
    ...

    def save(self, path: str):
        """Save IP table to JSON. Sets are converted to lists for serialization."""
        data = {}
        for ip, rec in self.ips.items():
            data[ip] = {
                'flows': rec['flows'], 'attacks': rec['attacks'],
                'first_seen': rec['first_seen'], 'last_seen': rec['last_seen'],
                'worst_label': rec['worst_label'], 'worst_conf': rec['worst_conf'],
                'labels': dict(rec['labels']),
                'unique_ports': list(rec.get('unique_ports', set())),
                'unique_protos': list(rec.get('unique_protos', set())),
                'unique_dsts': list(rec.get('unique_dsts', set())),
                'total_pkts': rec.get('total_pkts', 0),
            }
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f)
        os.replace(tmp, path)
        log.info('IP table saved: %d IPs to %s', len(data), path)

    def load(self, path: str):
        """Load IP table from JSON."""
        if not os.path.isfile(path):
            log.info('No saved IP table at %s', path)
            return
        with open(path) as f:
            data = json.load(f)
        for ip, rec in data.items():
            self.ips[ip] = {
                'flows': rec['flows'], 'attacks': rec['attacks'],
                'first_seen': rec['first_seen'], 'last_seen': rec['last_seen'],
                'worst_label': rec['worst_label'], 'worst_conf': rec['worst_conf'],
                'labels': defaultdict(int, {int(k): v for k, v in rec['labels'].items()}),
                'unique_ports': set(rec.get('unique_ports', [])),
                'unique_protos': set(rec.get('unique_protos', [])),
                'unique_dsts': set(rec.get('unique_dsts', [])),
                'total_pkts': rec.get('total_pkts', 0),
            }
        log.info('IP table loaded: %d IPs from %s', len(self.ips), path)
```

- [ ] **Step 2: Add signal handler + load on startup**

In `main()`:

```python
import signal

def main():
    ...
    ip_table = IPTable()
    ip_table.load(IPTABLE_PATH)
    drop_filter = DropFilter()
    nats_bridge = NATSBridge(drop_filter)

    def _shutdown(signum, frame):
        log.info('Shutting down (signal %d)...', signum)
        ip_table.save(IPTABLE_PATH)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        capture_loop(IFACE, scorer, ip_table, drop_filter, nats_bridge)
    except KeyboardInterrupt:
        ip_table.save(IPTABLE_PATH)
        ...
```

- [ ] **Step 3: Update systemd service for graceful shutdown**

The systemd service already has `KillMode=control-group`. Add `TimeoutStopSec=10` to give time for save:

```ini
[Service]
...
TimeoutStopSec=10
```

- [ ] **Step 4: Deploy and verify**

```bash
# Deploy, restart
sudo cp /tmp/god1_test.py /opt/dfi2/god1.py
sudo systemctl restart dfi-god1
# Wait 2 minutes for IPs to accumulate
sleep 120
# Restart — should save then load
sudo systemctl restart dfi-god1
# Check load message
journalctl -u dfi-god1 -n 10 | grep "loaded"
```

Expected: `IP table saved: XXXX IPs` on shutdown, `IP table loaded: XXXX IPs` on startup.

---

## Deploy Checklist

After all 5 tasks:

- [ ] SCP `god1_test.py` to AIO, copy to `/opt/dfi2/god1.py`, restart `dfi-god1`
- [ ] SCP `god2_verdict.py` to PV1 `/opt/dfi2/ml/god2_verdict.py`
- [ ] SCP `god1_listener.py` to PV1 `/opt/dfi2/ml/god1_listener.py`, restart `god1-listener`
- [ ] Verify: `journalctl -u dfi-god1 -n 20` — batch scoring, source stats, NATS OK
- [ ] Verify: `python3 /opt/dfi2/ml/god2_verdict.py` — evidence-tiered verdicts, watchlist writes
- [ ] Verify: `sqlite3 /opt/dfi-hunter/watchlist.db "SELECT source, count(*) FROM watchlist WHERE source='god2'"` — god2 entries present
- [ ] Verify: `sudo systemctl restart dfi-god1` — IP table saved + loaded
