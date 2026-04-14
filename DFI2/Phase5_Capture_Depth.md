# Phase 5: Capture Depth System

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 2 (Hunter core running, data flowing to CH)

## Objective

Implement D0–D3 capture depth filtering in Hunter, driven by SQLite watchlist lookups. Control what data gets written to ClickHouse per-flow based on attacker classification.

## Reference Files

| File | What to read |
|------|-------------|
| `~/ai-shared/DFI2/DFI2_Behavioral_Architecture_Spec.md` | Capture Depth Levels (lines 46-117): D0-D3 definitions, promotion/demotion rules, D0 re-promotion, depth change events |
| `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` | Hunter write paths by capture depth (lines 757-774), `depth_changes` table (lines 495-510), SQLite watchlist schema (lines 729-753) |
| `~/DFI2/hunter/watchlist.py` | WatchlistReader from Phase 2 (already reads SQLite) |
| `~/DFI2/hunter/writer.py` | DFIWriter.insert_flow() — depth parameter |
| `~/DFI2/hunter/hunter.py` | SessionTracker + flush path |

## Output Files

```
~/DFI2/hunter/
├── depth.py       # NEW: Capture depth logic (D0-D3 filtering)
├── watchlist.py   # MODIFY: add D0 re-promotion support
├── hunter.py      # MODIFY: integrate depth decisions into ingest + flush
└── writer.py      # MODIFY: respect depth in write paths
```

---

## Step 1: depth.py — Capture Depth Decision Logic

```python
"""Capture depth filtering logic.

Depth levels:
    D0 (DROP):           Zero writes. Skip entirely. Check for re-promotion.
    D1 (FLOW METADATA):  flows + fingerprints + fanout_hops.
    D2 (FLOW + SEQUENCE): D1 + packets table (128 event packets, all CNN channels).
    D3 (FULL CAPTURE):   D2 + payload_bytes table.
"""

# Depth constants
D0_DROP = 0
D1_FLOW = 1
D2_SEQUENCE = 2
D3_FULL = 3

DEFAULT_DEPTH = D1_FLOW


def get_capture_depth(watchlist_entry: dict) -> int:
    """Get capture depth from watchlist entry.

    Args:
        watchlist_entry: dict from WatchlistReader.lookup() or None

    Returns:
        int: capture depth (0-3)
    """
    if watchlist_entry is None:
        return DEFAULT_DEPTH
    return watchlist_entry.get('capture_depth', DEFAULT_DEPTH)


def check_d0_repromotion(dst_port: int, watchlist_entry: dict) -> bool:
    """Check if a D0 IP should be re-promoted to D1.

    If the attacker is hitting a port different from their last-known
    top_port, it indicates behavior change — re-promote to D1.

    Args:
        dst_port: destination port of current flow
        watchlist_entry: dict with 'top_port' field

    Returns:
        True if IP should be re-promoted from D0 to D1
    """
    top_port = watchlist_entry.get('top_port')
    if top_port is None:
        return False  # No port info — stay D0
    return dst_port != top_port


def should_write_flow(depth: int) -> bool:
    """D1+ writes to flows table."""
    return depth >= D1_FLOW


def should_write_fingerprint(depth: int) -> bool:
    """D1+ writes to fingerprints table."""
    return depth >= D1_FLOW


def should_write_fanout(depth: int) -> bool:
    """D1+ writes to fanout_hops table (always for movement tracking)."""
    return depth >= D1_FLOW


def should_write_packets(depth: int) -> bool:
    """D2+ writes to packets table."""
    return depth >= D2_SEQUENCE


def should_write_payload(depth: int) -> bool:
    """D3 only writes to payload_bytes table."""
    return depth >= D3_FULL
```

---

## Step 2: Modify watchlist.py — Add D0 Re-promotion Support

Extend the WatchlistReader to support re-promotion tracking:

```python
class WatchlistReader:
    def __init__(self, db_path: str, refresh_interval: int = 30):
        self._db_path = db_path
        self._refresh_interval = refresh_interval
        self._cache = {}      # src_ip -> {capture_depth, priority, group_id, top_port, ...}
        self._lock = threading.Lock()
        self._last_refresh = 0
        self._repromotions = {}  # src_ip -> True (track D0 IPs re-promoted this cycle)
        self.refresh()

    def lookup(self, ip: str) -> dict:
        """Look up IP in watchlist cache.

        Returns dict with keys: capture_depth, priority, group_id, sub_group_id,
        top_port, reason, source, expires_at. Returns None if not found.
        """
        now = time.time()
        # Periodic refresh
        if now - self._last_refresh > self._refresh_interval:
            self.refresh()

        with self._lock:
            entry = self._cache.get(ip)

        if entry is None:
            return None

        # Check expiry
        expires = entry.get('expires_at')
        if expires is not None and expires < now:
            return None  # Expired — treat as unclassified (D1)

        return entry

    def mark_repromotion(self, ip: str):
        """Mark a D0 IP as re-promoted. Prevents repeated re-promotion checks
        until next watchlist refresh."""
        with self._lock:
            self._repromotions[ip] = True

    def is_repromoted(self, ip: str) -> bool:
        """Check if IP was already re-promoted this cycle."""
        with self._lock:
            return self._repromotions.get(ip, False)

    def refresh(self):
        """Re-read watchlist from SQLite."""
        try:
            import sqlite3
            conn = sqlite3.connect(self._db_path, timeout=5)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM watchlist").fetchall()
            conn.close()

            new_cache = {}
            for row in rows:
                new_cache[row['src_ip']] = {
                    'capture_depth': row['capture_depth'],
                    'priority': row['priority'],
                    'group_id': row['group_id'],
                    'sub_group_id': row['sub_group_id'],
                    'top_port': row['top_port'],
                    'reason': row['reason'],
                    'source': row['source'],
                    'expires_at': row['expires_at'],
                }

            with self._lock:
                self._cache = new_cache
                self._repromotions = {}  # Clear re-promotions on refresh
                self._last_refresh = time.time()
        except Exception as e:
            import logging
            logging.warning(f"Watchlist refresh failed: {e}")
```

---

## Step 3: Modify writer.py — Respect Depth in Write Paths

Update `DFIWriter.insert_flow()` to filter writes by capture depth:

```python
from .depth import (should_write_flow, should_write_fingerprint,
                    should_write_fanout, should_write_packets,
                    should_write_payload)

class DFIWriter:
    # ... existing __init__, buffers, etc.

    def insert_flow(self, flow: dict, pkts: list, fp: dict, fanout: dict, depth: int):
        """Insert flow data respecting capture depth.

        Args:
            flow: dict matching dfi.flows columns
            pkts: list of packet token dicts (for packets table)
            fp: fingerprint dict or None
            fanout: fanout_hop dict
            depth: capture depth (0-3)
        """
        # D0: nothing written at all
        if depth == 0:
            return

        with self._lock:
            # D1+: flows table
            if should_write_flow(depth):
                flow['capture_depth'] = depth
                self._flow_buf.append(flow)

            # D1+: fingerprints table (if fingerprint extracted)
            if should_write_fingerprint(depth) and fp is not None:
                self._fp_buf.append(fp)

            # D1+: fanout_hops table (movement tracking always on)
            if should_write_fanout(depth) and fanout is not None:
                self._fanout_buf.append(fanout)

            # D2+: packets table
            if should_write_packets(depth) and pkts:
                self._pkt_buf.extend(pkts)

            # D3: payload_bytes table
            if should_write_payload(depth) and pkts:
                for pkt in pkts:
                    if pkt.get('payload_head'):
                        self._payload_buf.append({
                            'flow_id': flow['flow_id'],
                            'src_ip': flow['src_ip'],
                            'dst_ip': flow['dst_ip'],
                            'flow_first_ts': flow['first_ts'],
                            'seq_idx': pkt['seq_idx'],
                            'direction': pkt['direction'],
                            'ts': pkt['ts'],
                            'payload_head': pkt['payload_head'].hex(),
                            'payload_len': pkt['payload_len'],
                        })

    def insert_depth_change(self, attacker_ip: str, old_depth: int, new_depth: int,
                            reason: str, triggered_by: str = 'rule'):
        """Log a depth change event to ClickHouse."""
        self.ch.execute(
            "INSERT INTO dfi.depth_changes VALUES",
            [{
                'attacker_ip': attacker_ip,
                'old_depth': old_depth,
                'new_depth': new_depth,
                'trigger_reason': reason,
                'triggered_by': triggered_by,
            }]
        )
```

**Note:** Add `_payload_buf = deque()` to `__init__` if not already present, and add payload_bytes flush logic to the flusher thread.

---

## Step 4: Modify hunter.py — Integrate Depth Decisions

### In the ingest path (SessionTracker.ingest):

```python
from .depth import get_capture_depth, check_d0_repromotion, D0_DROP, D1_FLOW

class SessionTracker:
    def ingest(self, pkt):
        # ... existing endpoint resolution ...

        bad_ip, peer_ip, direction = resolved

        # Capture depth decision (on first packet of session)
        session_key = make_session_key(bad_ip, peer_ip, pkt)

        if session_key not in self._sessions:
            # New session — look up watchlist
            wl_entry = self._watchlist.lookup(bad_ip)
            depth = get_capture_depth(wl_entry)

            # D0 re-promotion check
            if depth == D0_DROP and wl_entry is not None:
                if not self._watchlist.is_repromoted(bad_ip):
                    if check_d0_repromotion(pkt.dst_port, wl_entry):
                        depth = D1_FLOW
                        self._watchlist.mark_repromotion(bad_ip)
                        # Log re-promotion
                        self._writer.insert_depth_change(
                            bad_ip, D0_DROP, D1_FLOW,
                            f'D0 re-promotion: new port {pkt.dst_port} vs top_port {wl_entry["top_port"]}',
                            'rule'
                        )

            # D0: skip entirely
            if depth == D0_DROP:
                return

            # Create session with depth
            session = SessionProfile(
                src_ip=bad_ip, dst_ip=peer_ip,
                src_port=pkt.src_port, dst_port=pkt.dst_port,
                ip_proto=pkt.ip_proto,
                capture_depth=depth,
            )
            self._sessions[session_key] = session
        else:
            session = self._sessions[session_key]

            # D0 sessions were never created — no check needed here

        # Update session (existing logic)
        session.update(pkt, direction)
```

### In the flush path:

```python
def flush_session(self, session):
    depth = session.capture_depth

    # D0 should never reach here (filtered at ingest)
    if depth == 0:
        return

    # Extract features (always for D1+)
    features = extract_features(session)

    # Extract fingerprint (D1+)
    fp = extract_fingerprint(session) if depth >= 1 else None

    # Build packet tokens (D2+)
    rtt_ms = features.get('rtt_ms')
    pkt_tokens = tokenize_packets(session.events, rtt_ms) if depth >= 2 else []

    # Build fanout hop (D1+)
    fanout = build_fanout_hop(session, features)

    # Write — DFIWriter handles depth filtering internally
    self._writer.insert_flow(features, pkt_tokens, fp, fanout, depth)
```

---

## Step 5: Event Packet Collection Optimization

For D1 sessions, don't waste memory collecting 128 event packets (they won't be written to packets table). Modify SessionProfile.update():

```python
def update(self, pkt, direction):
    # ... volume counters (always) ...

    # Event packet collection — only for D2+ and feature extraction
    if self.capture_depth >= 2 or self.n_events < 128:
        if is_event_packet(pkt):
            if self.n_events < 128:
                self.events.append(PacketEvent(
                    ts=pkt.ts, direction=direction,
                    payload_len=pkt.payload_len, pkt_len=pkt.pkt_len,
                    tcp_flags=pkt.tcp_flags, tcp_window=pkt.tcp_window,
                    payload_head=pkt.payload[:min(pkt.payload_len, 256)] if self.capture_depth >= 1 else b'',
                ))
                self.n_events += 1
```

**Note:** D1 sessions still need SOME events for feature extraction (RTT estimation, timing, entropy of first payload). Keep collecting events for D1, but limit `payload_head` capture to what's needed for fingerprinting (first ~5 events). The optimization is mainly for D0 — which never creates a session at all.

---

## Verification

1. **D0 filtering (zero writes):**
   ```bash
   # Insert test D0 entry in watchlist
   sqlite3 /opt/dfi-hunter/watchlist.db "INSERT OR REPLACE INTO watchlist (src_ip, capture_depth, top_port) VALUES ('1.1.1.1', 0, 80)"

   # Wait for watchlist refresh (30s), then check
   clickhouse-client --query "SELECT count() FROM dfi.flows WHERE src_ip = '1.1.1.1'"
   # Should be 0 (or not growing)
   ```

2. **D1 default (flows + fingerprints, no packets):**
   ```bash
   # Pick a random IP not in watchlist
   clickhouse-client --query "
       SELECT src_ip, count() as flows,
              (SELECT count() FROM dfi.packets p WHERE p.src_ip = f.src_ip) as pkts
       FROM dfi.flows f
       WHERE src_ip NOT IN (SELECT src_ip FROM dfi.flows WHERE capture_depth > 1)
       GROUP BY src_ip
       LIMIT 5
   "
   # flows > 0, pkts should be 0 for D1-only IPs
   ```

3. **D2 sequence capture:**
   ```bash
   sqlite3 /opt/dfi-hunter/watchlist.db "INSERT OR REPLACE INTO watchlist (src_ip, capture_depth) VALUES ('2.2.2.2', 2)"

   # Wait for traffic + flush
   clickhouse-client --query "SELECT count() FROM dfi.packets WHERE src_ip = '2.2.2.2'"
   # Should show packet rows
   ```

4. **D0 re-promotion:**
   ```bash
   sqlite3 /opt/dfi-hunter/watchlist.db "INSERT OR REPLACE INTO watchlist (src_ip, capture_depth, top_port) VALUES ('3.3.3.3', 0, 22)"

   # If 3.3.3.3 sends traffic to port 80 (not 22), it should be re-promoted
   clickhouse-client --query "
       SELECT * FROM dfi.depth_changes
       WHERE attacker_ip = '3.3.3.3'
       ORDER BY changed_at DESC LIMIT 5
   "
   ```

5. **Depth distribution:**
   ```bash
   clickhouse-client --query "
       SELECT capture_depth, count() as flows
       FROM dfi.flows
       GROUP BY capture_depth
       ORDER BY capture_depth
   "
   # Expect: mostly D1, some D2, few D3
   ```

---

## Acceptance Criteria

- [ ] D0 IPs produce zero ClickHouse rows (flows, packets, fingerprints all zero)
- [ ] D1 IPs produce flows + fingerprints + fanout_hops, but zero packets rows
- [ ] D2 IPs produce flows + fingerprints + fanout_hops + packets (128 event tokens)
- [ ] D3 IPs produce everything D2 does + payload_bytes rows
- [ ] D0 re-promotion works: new port triggers D0 → D1 + depth_change event
- [ ] Watchlist lookup does not block the ingest hot path (dict lookup, no I/O)
- [ ] Expired watchlist entries treated as unclassified (D1)
- [ ] Depth change events logged to `dfi.depth_changes` table
- [ ] `capture_depth` column correctly set on flows rows
- [ ] No performance regression (D0 skip is fastest path, D1 is same as Phase 2)

## Important Notes

- **D0 skip is the hot-path optimization.** At 100K flows/sec, moving 40% of traffic to D0 saves ~40K flow writes/sec + fingerprint + fanout writes. This is significant.
- **Watchlist lookup must be sub-microsecond.** The WatchlistReader uses an in-memory dict snapshot. The SQLite read happens in a background refresh thread every 30s. Never block ingest on SQLite I/O.
- **D0 IPs still need dst_port visible.** The ingest path must parse enough of the packet header to extract dst_port BEFORE the D0 skip decision. This is already the case — IP/TCP header parsing happens before endpoint resolution.
- **Never demote while active.** The depth system only promotes immediately. Demotions happen through the classifier (Phase 8) updating the watchlist, not through Hunter directly.
