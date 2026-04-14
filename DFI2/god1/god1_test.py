#!/usr/bin/env python3
"""GOD 1 — Minimal proof-of-concept on AIO.
Captures SPAN on ens192, tracks flows, XGB scores at session end, prints IP table.
"""
import asyncio
import ctypes
import json
import logging
import math
import os
import signal
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Optional

import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('god1')

# ── Config ──────────────────────────────────────────────────────────────────
IFACE = os.environ.get('GOD1_IFACE', 'ens192')
MODEL_PATH = os.environ.get('GOD1_MODEL', '/opt/dfi2/ml/models/xgb_5class_v2.json')
SESSION_TIMEOUT = int(os.environ.get('GOD1_TIMEOUT', '120'))  # seconds idle → session end
STATS_INTERVAL = int(os.environ.get('GOD1_STATS', '30'))       # print stats every N seconds
MAX_SESSIONS = int(os.environ.get('GOD1_MAX_SESSIONS', '500000'))
IPTABLE_TTL = int(os.environ.get('GOD1_IPTABLE_TTL', str(30 * 86400)))  # 30 days in seconds

CLASS_NAMES = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTE', 3: 'EXPLOIT', 4: 'CLEAN'}
NATS_URL = os.environ.get('GOD1_NATS', 'nats://192.168.0.100:4222')
NATS_SUBJECT = 'dfi.xgb.score'              # GOD 1 publishes scores here
NATS_VERDICT_SUBJECT = 'dfi.reputation.verdict'  # GOD 2 sends verdicts here
NATS_BATCH = int(os.environ.get('GOD1_NATS_BATCH', '100'))  # publish in batches
NATS_FLUSH_SEC = float(os.environ.get('GOD1_NATS_FLUSH', '5.0'))  # max seconds before flush
DROP_TTL = int(os.environ.get('GOD1_DROP_TTL', '604800'))  # 7 days in seconds
DROP_THRESHOLD = int(os.environ.get('GOD1_DROP_THRESHOLD', '3'))  # (unused — DROP only via GOD 2 verdict)
IPSET_NAME = 'god1_drop'
IPTABLE_PATH = os.environ.get('GOD1_IPTABLE', '/opt/dfi2/god1_iptable.json')

# ── App Proto Map ───────────────────────────────────────────────────────────
APP_PROTO_MAP = {
    22: 1, 80: 2, 8080: 2, 443: 3, 53: 4, 25: 5, 21: 6, 23: 7,
    3389: 8, 5900: 9, 445: 10, 3306: 11, 1433: 12, 5432: 13,
    6379: 14, 27017: 15,
}


# ── Packet Event ────────────────────────────────────────────────────────────
@dataclass
class PacketEvent:
    ts: float
    direction: int       # 1=fwd (src→dst), -1=rev
    payload_len: int
    pkt_len: int
    tcp_flags: int
    tcp_window: int
    payload_head: bytes


# ── Session Profile ─────────────────────────────────────────────────────────
@dataclass
class SessionProfile:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_proto: int
    vlan_id: int = 0

    first_ts: float = 0.0
    last_ts: float = 0.0

    pkts_fwd: int = 0
    pkts_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0

    events: list = field(default_factory=list)
    fwd_timestamps: list = field(default_factory=list)
    fwd_payload_sizes: list = field(default_factory=list)
    rev_payload_sizes: list = field(default_factory=list)
    fwd_payload_entropy: list = field(default_factory=list)
    rev_payload_entropy: list = field(default_factory=list)

    n_payload_pkts: int = 0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_only_count: int = 0
    synack_seen: bool = False
    first_syn_index: Optional[int] = None
    first_payload_index: Optional[int] = None
    first_rst_index: Optional[int] = None
    first_fwd_payload: Optional[bytes] = None
    psh_burst_cur: int = 0
    psh_burst_max: int = 0
    retransmit_est: int = 0
    window_size_init: int = 0

    def add_packet(self, ev: PacketEvent):
        idx = len(self.events)
        self.events.append(ev)

        if self.first_ts == 0.0:
            self.first_ts = ev.ts
        self.last_ts = ev.ts

        if ev.direction == 1:
            self.pkts_fwd += 1
            self.bytes_fwd += ev.pkt_len
            self.fwd_timestamps.append(ev.ts)
            if ev.payload_len > 0:
                self.fwd_payload_sizes.append(ev.payload_len)
                self.fwd_payload_entropy.append(_shannon_entropy(ev.payload_head))
                if self.first_fwd_payload is None:
                    self.first_fwd_payload = ev.payload_head
        else:
            self.pkts_rev += 1
            self.bytes_rev += ev.pkt_len
            if ev.payload_len > 0:
                self.rev_payload_sizes.append(ev.payload_len)
                self.rev_payload_entropy.append(_shannon_entropy(ev.payload_head))

        if ev.payload_len > 0:
            self.n_payload_pkts += 1
            if self.first_payload_index is None:
                self.first_payload_index = idx

        # TCP flags
        flags = ev.tcp_flags
        if flags & 0x02:  # SYN
            self.syn_count += 1
            if self.first_syn_index is None:
                self.first_syn_index = idx
            if flags & 0x10:  # SYN+ACK
                self.synack_seen = True
                if self.window_size_init == 0:
                    self.window_size_init = ev.tcp_window
        if flags & 0x01:
            self.fin_count += 1
        if flags & 0x04:
            self.rst_count += 1
            if self.first_rst_index is None:
                self.first_rst_index = idx
        if flags & 0x08:
            self.psh_count += 1
            self.psh_burst_cur += 1
            self.psh_burst_max = max(self.psh_burst_max, self.psh_burst_cur)
        else:
            self.psh_burst_cur = 0
        if flags == 0x10:
            self.ack_only_count += 1


# ── Feature extraction (from proven features.py) ───────────────────────────
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = float(len(data))
    return float(-sum((c / n) * math.log2(c / n) for c in freq if c > 0))

def _safe_mean(v):
    return float(mean(v)) if v else None

def _safe_std(v):
    if not v: return None
    if len(v) == 1: return 0.0
    return float(pstdev(v))

def _classify_conn_state(s):
    if s.ip_proto != 6:
        return 7
    syn = s.syn_count > 0
    synack = s.synack_seen
    data = s.n_payload_pkts > 0
    fin = s.fin_count > 0
    rst = s.rst_count > 0
    many = s.n_payload_pkts >= 8
    if s.syn_count > 1 and not synack: return 6
    if syn and not synack: return 0
    if synack and not data and rst: return 1
    if synack and data and fin and not many: return 2
    if synack and data and rst and not many: return 3
    if synack and data and fin and many: return 4
    if synack and data and rst and many: return 5
    if synack and data and fin: return 2
    if synack and data and rst: return 3
    return 0

def extract_features(s: SessionProfile) -> dict:
    app_proto = APP_PROTO_MAP.get(s.dst_port, APP_PROTO_MAP.get(s.src_port, 0))
    dur_s = max(s.last_ts - s.first_ts, 0.0)
    dur_ms = int(dur_s * 1000.0)
    total_pkts = s.pkts_fwd + s.pkts_rev
    total_bytes = s.bytes_fwd + s.bytes_rev

    bpp_fwd = s.bytes_fwd / max(s.pkts_fwd, 1)
    bpp_rev = (s.bytes_rev / s.pkts_rev) if s.pkts_rev > 0 else None
    pkt_ratio = s.pkts_fwd / max(s.pkts_rev, 1)
    byte_ratio = s.bytes_fwd / max(s.bytes_rev, 1)

    rtt_ms = _estimate_rtt(s)

    fwd_iats = []
    for i in range(1, len(s.fwd_timestamps)):
        fwd_iats.append((s.fwd_timestamps[i] - s.fwd_timestamps[i-1]) * 1000.0)

    iat_fwd_mean = _safe_mean(fwd_iats)
    iat_fwd_std = _safe_std(fwd_iats)
    think_mean = think_std = iat_to_rtt = None
    if rtt_ms and fwd_iats:
        think = [max(x - rtt_ms, 0.0) for x in fwd_iats]
        think_mean = _safe_mean(think)
        think_std = _safe_std(think)
        iat_to_rtt = (iat_fwd_mean / max(rtt_ms, 0.1)) if iat_fwd_mean else None

    pps = float(total_pkts / max(dur_s, 0.001))
    bps = float(total_bytes / max(dur_s, 0.001))
    payload_rtt = (s.n_payload_pkts / max((dur_ms / max(rtt_ms, 0.1)), 1)) if rtt_ms else None

    fwd_sz = list(s.fwd_payload_sizes)
    rev_sz = list(s.rev_payload_sizes)
    all_sz = fwd_sz + rev_sz
    ne = len(s.events)
    ht = sum(1 for x in all_sz if 1 <= x <= 63)
    hs = sum(1 for x in all_sz if 64 <= x <= 255)
    hm = sum(1 for x in all_sz if 256 <= x <= 1023)
    hl = sum(1 for x in all_sz if 1024 <= x <= 1499)
    hf = sum(1 for x in all_sz if x >= 1500)

    rst_frac = (s.first_rst_index / total_pkts) if s.first_rst_index is not None and total_pkts > 0 else None
    syn_to_data = max(0, (s.first_payload_index or 0) - (s.first_syn_index or 0)) if s.first_syn_index is not None and s.first_payload_index is not None else 0

    entropy_first = printable_frac = null_frac = byte_std_val = None
    payload_len_first = 0
    if s.first_fwd_payload:
        d = s.first_fwd_payload
        payload_len_first = len(d)
        entropy_first = _shannon_entropy(d)
        n = max(len(d), 1)
        printable_frac = sum(1 for b in d if 0x20 <= b <= 0x7E) / n
        null_frac = sum(1 for b in d if b == 0) / n
        mu = sum(d) / n
        byte_std_val = math.sqrt(sum((b - mu)**2 for b in d) / n)

    hef = None
    if s.fwd_payload_entropy:
        hef = sum(1 for x in s.fwd_payload_entropy if x >= 7.0) / len(s.fwd_payload_entropy)

    def f(v): return float(v) if v is not None else None

    return {
        'dst_port': s.dst_port, 'ip_proto': s.ip_proto, 'app_proto': app_proto,
        'pkts_fwd': s.pkts_fwd, 'pkts_rev': s.pkts_rev, 'bytes_fwd': s.bytes_fwd, 'bytes_rev': s.bytes_rev,
        'bytes_per_pkt_fwd': float(bpp_fwd), 'bytes_per_pkt_rev': f(bpp_rev),
        'pkt_ratio': float(pkt_ratio), 'byte_ratio': float(byte_ratio),
        'duration_ms': dur_ms, 'rtt_ms': f(rtt_ms),
        'iat_fwd_mean_ms': f(iat_fwd_mean), 'iat_fwd_std_ms': f(iat_fwd_std),
        'think_time_mean_ms': f(think_mean), 'think_time_std_ms': f(think_std),
        'iat_to_rtt': f(iat_to_rtt), 'pps': pps, 'bps': bps, 'payload_rtt_ratio': f(payload_rtt),
        'n_events': ne,
        'fwd_size_mean': _safe_mean(fwd_sz), 'fwd_size_std': _safe_std(fwd_sz),
        'fwd_size_min': min(fwd_sz) if fwd_sz else 0, 'fwd_size_max': max(fwd_sz) if fwd_sz else 0,
        'rev_size_mean': _safe_mean(rev_sz), 'rev_size_std': _safe_std(rev_sz),
        'rev_size_max': max(rev_sz) if rev_sz else 0,
        'hist_tiny': ht, 'hist_small': hs, 'hist_medium': hm, 'hist_large': hl, 'hist_full': hf,
        'frac_full': float(hf / max(ne, 1)),
        'syn_count': s.syn_count, 'fin_count': s.fin_count, 'rst_count': s.rst_count,
        'psh_count': s.psh_count, 'ack_only_count': s.ack_only_count,
        'conn_state': _classify_conn_state(s),
        'rst_frac': f(rst_frac), 'syn_to_data': int(min(max(syn_to_data, 0), 255)),
        'psh_burst_max': int(min(max(s.psh_burst_max, 0), 255)),
        'retransmit_est': int(s.retransmit_est), 'window_size_init': int(s.window_size_init),
        'entropy_first': f(entropy_first), 'entropy_fwd_mean': _safe_mean(s.fwd_payload_entropy),
        'entropy_rev_mean': _safe_mean(s.rev_payload_entropy),
        'printable_frac': f(printable_frac), 'null_frac': f(null_frac),
        'byte_std': f(byte_std_val), 'high_entropy_frac': f(hef),
        'payload_len_first': int(payload_len_first),
    }

def _estimate_rtt(s: SessionProfile):
    for e in s.events:
        if e.direction == 1 and (e.tcp_flags & 0x02):
            syn_ts = e.ts
            for e2 in s.events:
                if e2.direction == -1 and e2.ts > syn_ts:
                    return (e2.ts - syn_ts) * 1000.0
            break
    fwd = next((e.ts for e in s.events if e.direction == 1), None)
    rev = next((e.ts for e in s.events if e.direction == -1), None)
    if fwd and rev and rev > fwd:
        return (rev - fwd) * 1000.0
    return None


# ── XGB Scorer ──────────────────────────────────────────────────────────────
class XGBScorer:
    def __init__(self, model_path: str):
        import xgboost as xgb
        self._booster = xgb.Booster({'nthread': 4})
        self._booster.load_model(model_path)
        self._feats = self._booster.feature_names
        self._xgb = xgb
        log.info('XGB loaded: %s (%d features)', os.path.basename(model_path), len(self._feats))

    def score(self, feat: dict) -> dict:
        row = [float(feat.get(f) if feat.get(f) is not None else 0.0) for f in self._feats]
        dmat = self._xgb.DMatrix(np.array([row], dtype=np.float32), feature_names=self._feats, nthread=4)
        raw = self._booster.predict(dmat)[0]
        if isinstance(raw, np.ndarray):
            label = int(np.argmax(raw))
            return {'label': label, 'name': CLASS_NAMES.get(label, '?'), 'confidence': float(raw[label]),
                    'probs': [float(p) for p in raw]}
        prob = float(raw)
        label = 1 if prob > 0.5 else 0
        return {'label': label, 'name': CLASS_NAMES.get(label, '?'), 'confidence': max(prob, 1-prob), 'probs': [1-prob, prob]}

    def score_batch(self, feats: list) -> list:
        """Score a list of feature dicts in one DMatrix call. Returns list of result dicts."""
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
                                'confidence': float(raw[label]),
                                'probs': [float(p) for p in raw]})
            else:
                prob = float(raw)
                label = 1 if prob > 0.5 else 0
                results.append({'label': label, 'name': CLASS_NAMES.get(label, '?'),
                                'confidence': max(prob, 1-prob), 'probs': [1-prob, prob]})
        return results


# ── IP Table ────────────────────────────────────────────────────────────────
class IPTable:
    """Per-IP score accumulator with source stats tracking."""
    def __init__(self):
        self.ips = {}  # ip -> {flows, scores, first_seen, last_seen, worst_label, worst_conf, ...}

    def record(self, src_ip: str, result: dict, ts: float,
               dst_ip: str = '', dst_port: int = 0, ip_proto: int = 0,
               pkts: int = 0, duration_s: float = 0.0):
        if src_ip not in self.ips:
            self.ips[src_ip] = {'flows': 0, 'attacks': 0, 'first_seen': ts, 'last_seen': ts,
                                'worst_label': 4, 'worst_conf': 0.0, 'labels': defaultdict(int),
                                'unique_ports': set(), 'unique_protos': set(),
                                'unique_dsts': set(), 'total_pkts': 0}
        rec = self.ips[src_ip]
        rec['flows'] += 1
        rec['last_seen'] = ts
        rec['labels'][result['label']] += 1
        if result['label'] < 4:  # not CLEAN
            rec['attacks'] += 1
        if result['label'] < rec['worst_label'] or (result['label'] == rec['worst_label'] and result['confidence'] > rec['worst_conf']):
            rec['worst_label'] = result['label']
            rec['worst_conf'] = result['confidence']
        # Source stats tracking
        if dst_port:
            rec['unique_ports'].add(dst_port)
        if ip_proto:
            rec['unique_protos'].add(ip_proto)
        if dst_ip:
            rec['unique_dsts'].add(dst_ip)
        rec['total_pkts'] += pkts

    def get_source_stats(self, src_ip: str) -> dict:
        """Return source-level stats for XGB feature injection."""
        if src_ip not in self.ips:
            return {}
        rec = self.ips[src_ip]
        span_s = max(rec['last_seen'] - rec['first_seen'], 0.0)
        return {
            'src_flow_count': rec['flows'],
            'src_unique_ports': len(rec['unique_ports']),
            'src_unique_protos': len(rec['unique_protos']),
            'src_unique_dsts': len(rec['unique_dsts']),
            'src_span_min': span_s / 60.0,
            'src_avg_pps': rec['total_pkts'] / max(span_s, 0.001),
        }

    def top_attackers(self, n=20):
        return sorted(
            [(ip, d) for ip, d in self.ips.items() if d['worst_label'] < 4],
            key=lambda x: (-x[1]['attacks'], -x[1]['worst_conf'])
        )[:n]

    def stats(self):
        total = len(self.ips)
        attackers = sum(1 for d in self.ips.values() if d['worst_label'] < 4)
        clean = total - attackers
        return total, attackers, clean

    def expire_ttl(self):
        """Remove IPs not seen in IPTABLE_TTL seconds (30 days default)."""
        now = time.time()
        cutoff = now - IPTABLE_TTL
        expired = [ip for ip, rec in self.ips.items() if rec['last_seen'] < cutoff]
        for ip in expired:
            del self.ips[ip]
        if expired:
            log.info('IP table TTL: expired %d IPs older than %dd (remaining=%d)',
                     len(expired), IPTABLE_TTL // 86400, len(self.ips))

    def save(self, path: str):
        """Persist IP table to JSON (atomic write via tmp+rename)."""
        data = {}
        for ip, rec in self.ips.items():
            data[ip] = {
                'flows': rec['flows'],
                'attacks': rec['attacks'],
                'first_seen': rec['first_seen'],
                'last_seen': rec['last_seen'],
                'worst_label': rec['worst_label'],
                'worst_conf': rec['worst_conf'],
                'labels': dict(rec['labels']),
                'unique_ports': list(rec['unique_ports']),
                'unique_protos': list(rec['unique_protos']),
                'unique_dsts': list(rec['unique_dsts']),
                'total_pkts': rec['total_pkts'],
            }
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f)
        os.replace(tmp, path)
        log.info('IP table saved: %d IPs to %s', len(data), path)

    def load(self, path: str):
        """Load IP table from JSON, reconstructing sets and defaultdicts."""
        if not os.path.exists(path):
            log.info('IP table file not found, starting fresh: %s', path)
            return
        with open(path, 'r') as f:
            data = json.load(f)
        cutoff = time.time() - IPTABLE_TTL
        skipped = 0
        for ip, rec in data.items():
            if rec['last_seen'] < cutoff:
                skipped += 1
                continue
            self.ips[ip] = {
                'flows': rec['flows'],
                'attacks': rec['attacks'],
                'first_seen': rec['first_seen'],
                'last_seen': rec['last_seen'],
                'worst_label': rec['worst_label'],
                'worst_conf': rec['worst_conf'],
                'labels': defaultdict(int, {int(k): v for k, v in rec['labels'].items()}),
                'unique_ports': set(rec['unique_ports']),
                'unique_protos': set(rec['unique_protos']),
                'unique_dsts': set(rec['unique_dsts']),
                'total_pkts': rec['total_pkts'],
            }
        log.info('IP table loaded: %d IPs from %s (skipped %d expired)', len(self.ips), path, skipped)


# ── NATS Bridge (publish scores, subscribe verdicts) ────────────────────────
class NATSBridge:
    """Async NATS client running in a background thread."""

    def __init__(self, drop_filter):
        self._drop_filter = drop_filter
        self._queue = []       # pending score messages
        self._lock = threading.Lock()
        self._connected = False
        self._published = 0
        self._verdicts = 0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        asyncio.run(self._async_main())

    async def _async_main(self):
        import nats
        while True:
            try:
                nc = await nats.connect(NATS_URL)
                self._connected = True
                log.info('NATS connected: %s', NATS_URL)

                # Subscribe to verdicts from GOD 2
                async def _on_verdict(msg):
                    try:
                        v = json.loads(msg.data)
                        ip = v.get('ip') or v.get('src_ip')
                        action = v.get('action', '')
                        if ip and action == 'DROP':
                            self._drop_filter.add(ip, reason=f"GOD2:{v.get('reason','verdict')}")
                            self._verdicts += 1
                    except Exception as e:
                        log.warning('verdict parse error: %s', e)

                await nc.subscribe(NATS_VERDICT_SUBJECT, cb=_on_verdict)
                log.info('NATS subscribed: %s', NATS_VERDICT_SUBJECT)

                # Publish loop
                while True:
                    await asyncio.sleep(NATS_FLUSH_SEC)
                    batch = self._drain()
                    if batch:
                        payload = json.dumps(batch).encode()
                        await nc.publish(NATS_SUBJECT, payload)
                        self._published += len(batch)

            except Exception as e:
                self._connected = False
                log.warning('NATS error: %s, reconnecting in 5s...', e)
                await asyncio.sleep(5)

    def enqueue(self, src_ip: str, result: dict, ts: float,
                session=None, src_stats: dict = None):
        """Queue a score for NATS publishing (called from capture thread)."""
        msg = {
            'src_ip': src_ip,
            'label': result['label'],
            'name': result['name'],
            'confidence': round(result['confidence'], 4),
            'probs': [round(p, 4) for p in result['probs']],
            'ts': round(ts, 3),
            'sensor': 'god1_aio',
        }
        if session:
            msg['dst_ip'] = session.dst_ip
            msg['dst_port'] = session.dst_port
            msg['ip_proto'] = session.ip_proto
            msg['pkts_rev'] = session.pkts_rev
            msg['first_ts'] = round(session.first_ts, 3)
            msg['last_ts'] = round(session.last_ts, 3)
            msg['vlan_id'] = session.vlan_id
        if src_stats:
            msg['src_flow_count'] = src_stats.get('src_flow_count', 0)
            msg['src_unique_ports'] = src_stats.get('src_unique_ports', 0)
            msg['src_unique_dsts'] = src_stats.get('src_unique_dsts', 0)
        with self._lock:
            self._queue.append(msg)

    def _drain(self):
        with self._lock:
            batch = self._queue[:NATS_BATCH * 10]
            self._queue = self._queue[NATS_BATCH * 10:]
        return batch

    def stats(self):
        return self._connected, self._published, self._verdicts


# ── Drop Filter (Layer 1: Python set + Layer 2: ipset/iptables) ─────────────
class DropFilter:
    """Manages dropped IPs at two layers: Python set (instant) + kernel ipset."""

    def __init__(self):
        self._drop_set = {}  # ip -> expire_ts
        self._drop_stats = defaultdict(int)  # ip -> packets dropped
        self._setup_ipset()

    def _setup_ipset(self):
        """Create kernel ipset and iptables rule for SPAN filtering."""
        try:
            os.system(f'ipset create {IPSET_NAME} hash:ip maxelem 1000000 timeout {DROP_TTL} 2>/dev/null')
            os.system(f'ipset flush {IPSET_NAME} 2>/dev/null')
            log.info('ipset %s ready', IPSET_NAME)
        except Exception as e:
            log.warning('ipset setup failed: %s (Layer 2 disabled, Layer 1 still active)', e)

    def add(self, ip: str, reason: str = ''):
        """Add IP to both drop layers."""
        now = time.time()
        if ip not in self._drop_set:
            self._drop_set[ip] = now + DROP_TTL
            os.system(f'ipset -q add {IPSET_NAME} {ip} timeout {DROP_TTL}')
            log.info('DROP +%s reason=%s (total=%d)', ip, reason, len(self._drop_set))

    def remove(self, ip: str):
        """Remove IP from both layers."""
        self._drop_set.pop(ip, None)
        os.system(f'ipset -q del {IPSET_NAME} {ip}')

    def is_dropped(self, ip: str) -> bool:
        """Layer 1 check — O(1) Python set lookup."""
        if ip not in self._drop_set:
            return False
        if time.time() > self._drop_set[ip]:
            # Expired
            del self._drop_set[ip]
            return False
        self._drop_stats[ip] += 1
        return True

    def expire(self):
        """Remove expired entries from Python set."""
        now = time.time()
        expired = [ip for ip, exp in self._drop_set.items() if now > exp]
        for ip in expired:
            del self._drop_set[ip]
        if expired:
            log.info('DROP expired %d IPs (remaining=%d)', len(expired), len(self._drop_set))

    def stats(self):
        return len(self._drop_set), sum(self._drop_stats.values())

    def top_dropped(self, n=5):
        return sorted(self._drop_stats.items(), key=lambda x: -x[1])[:n]


# ── Simple packet capture (raw socket, no AF_PACKET TPACKET needed for PoC)
def capture_loop(iface: str, scorer: XGBScorer, ip_table: IPTable, drop_filter: DropFilter, nats_bridge: NATSBridge):
    """Single-threaded raw socket capture with drop filter, VLAN, and NATS publishing."""
    ETH_P_ALL = 0x0003
    SOL_PACKET = 263       # linux/socket.h
    PACKET_AUXDATA = 8     # linux/if_packet.h
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.settimeout(1.0)
    # Enable PACKET_AUXDATA to get VLAN info via recvmsg() cmsg
    sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

    sessions = {}   # 5-tuple -> SessionProfile
    total_pkts = 0
    total_scored = 0
    total_dropped = 0
    last_stats = time.time()
    last_expire = time.time()
    last_ttl_check = time.time()

    log.info('Capturing on %s (timeout=%ds, max_sessions=%d, iptable_ttl=%dd)',
             iface, SESSION_TIMEOUT, MAX_SESSIONS, IPTABLE_TTL // 86400)

    while True:
        try:
            data, ancdata, _, _ = sock.recvmsg(65535, 1024)
        except socket.timeout:
            data = None
            ancdata = []

        now = time.time()

        if data:
            total_pkts += 1
            # Extract VLAN from PACKET_AUXDATA cmsg
            # struct tpacket_auxdata: tp_vlan_tci at offset 16 (uint16), tp_vlan_tpid at offset 18
            aux_vlan = 0
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if cmsg_level == SOL_PACKET and cmsg_type == PACKET_AUXDATA and len(cmsg_data) >= 20:
                    aux_vlan = struct.unpack_from('H', cmsg_data, 16)[0] & 0x0FFF
            pkt = _parse_packet(data, now, aux_vlan)
            if pkt:
                src_ip = pkt['src_ip']

                # Layer 1: Python drop set check — O(1)
                if drop_filter.is_dropped(src_ip):
                    total_dropped += 1
                    continue

                key = pkt['key']
                if key not in sessions:
                    if len(sessions) >= MAX_SESSIONS:
                        continue
                    sessions[key] = SessionProfile(
                        src_ip=src_ip, dst_ip=pkt['dst_ip'],
                        src_port=pkt['src_port'], dst_port=pkt['dst_port'],
                        ip_proto=pkt['ip_proto'], vlan_id=pkt.get('vlan_id', 0))

                sessions[key].add_packet(PacketEvent(
                    ts=now, direction=pkt['direction'],
                    payload_len=pkt['payload_len'], pkt_len=pkt['pkt_len'],
                    tcp_flags=pkt['tcp_flags'], tcp_window=pkt['tcp_window'],
                    payload_head=pkt['payload_head']))

        # Expire sessions every 10s
        if now - last_expire >= 10.0:
            expired = [k for k, s in sessions.items() if now - s.last_ts > SESSION_TIMEOUT]
            # Collect scoreable sessions, extract features in bulk
            score_sessions = []
            score_feats = []
            for k in expired:
                s = sessions.pop(k)
                if s.pkts_fwd + s.pkts_rev >= 3:
                    score_sessions.append(s)
                    score_feats.append(extract_features(s))
            # Batch XGB scoring — one DMatrix for all expired sessions
            if score_feats:
                # Inject per-IP source stats into feature dicts before scoring
                for i, s in enumerate(score_sessions):
                    src_stats = ip_table.get_source_stats(s.src_ip)
                    if src_stats:
                        score_feats[i].update(src_stats)
                results = scorer.score_batch(score_feats)
                for s, result in zip(score_sessions, results):
                    dur_s = max(s.last_ts - s.first_ts, 0.0)
                    ip_table.record(s.src_ip, result, s.last_ts,
                                    dst_ip=s.dst_ip, dst_port=s.dst_port,
                                    ip_proto=s.ip_proto,
                                    pkts=s.pkts_fwd + s.pkts_rev,
                                    duration_s=dur_s)
                    total_scored += 1
                    # Publish every score to NATS → PV1 CH ip_reputation
                    src_stats = ip_table.get_source_stats(s.src_ip)
                    nats_bridge.enqueue(s.src_ip, result, s.last_ts, session=s, src_stats=src_stats)
                    # NOTE: GOD 1 NEVER decides DROP. Only GOD 2 (CH verdicts via NATS) can add to drop filter.

            # Expire drop filter entries
            drop_filter.expire()
            last_expire = now

        # IP table TTL — check once per hour
        if now - last_ttl_check >= 3600:
            ip_table.expire_ttl()
            last_ttl_check = now

        # Print stats
        if now - last_stats >= STATS_INTERVAL:
            total_ips, attackers, clean = ip_table.stats()
            drop_count, drop_pkts = drop_filter.stats()
            nats_ok, nats_pub, nats_verd = nats_bridge.stats()
            log.info('[%ds] pkts=%d scored=%d dropped=%d sessions=%d | IPs: %d atk=%d clean=%d | DROP: %d/%dpkts | NATS: %s pub=%d verd=%d',
                     STATS_INTERVAL, total_pkts, total_scored, total_dropped, len(sessions),
                     total_ips, attackers, clean, drop_count, drop_pkts,
                     'OK' if nats_ok else 'DOWN', nats_pub, nats_verd)

            top = ip_table.top_attackers(10)
            if top:
                log.info('  Top attackers:')
                for ip, d in top:
                    labels_str = ' '.join(f'{CLASS_NAMES.get(l,"?")}: {c}' for l, c in sorted(d["labels"].items()))
                    log.info('    %-18s flows=%-5d attacks=%-4d worst=%s(%.2f) [%s]',
                             ip, d['flows'], d['attacks'], CLASS_NAMES.get(d['worst_label'],'?'),
                             d['worst_conf'], labels_str)

            td = drop_filter.top_dropped(5)
            if td:
                log.info('  Top dropped: %s', ' | '.join(f'{ip}:{n}pkts' for ip, n in td))

            total_pkts = 0
            total_scored = 0
            total_dropped = 0
            last_stats = now


# ── Packet parser ───────────────────────────────────────────────────────────
def _parse_packet(data: bytes, ts: float, aux_vlan: int = 0) -> Optional[dict]:
    """Parse Ethernet → IP → TCP/UDP. Returns dict or None."""
    if len(data) < 14:
        return None

    eth_type = struct.unpack('!H', data[12:14])[0]
    offset = 14
    vlan_id = 0

    # VLAN 802.1Q — check frame data first
    if eth_type == 0x8100:
        if len(data) < 18:
            return None
        vlan_id = struct.unpack('!H', data[14:16])[0] & 0x0FFF
        eth_type = struct.unpack('!H', data[16:18])[0]
        offset = 18

    # Kernel may strip VLAN from frame and put in PACKET_AUXDATA (tp_vlan_tci)
    if vlan_id == 0 and aux_vlan > 0:
        vlan_id = aux_vlan

    # SPAN VLAN: 100=ingress (attacker→honeypot), 101=egress (honeypot→attacker)
    # Drop anything else (non-SPAN)
    if vlan_id not in (100, 101):
        return None

    if eth_type != 0x0800:  # IPv4 only
        return None
    if len(data) < offset + 20:
        return None

    # Drop ICMP (ip_proto=1) — noise, not scoreable
    if data[offset + 9] == 1:
        return None

    ip_hdr = data[offset:]
    ihl = (ip_hdr[0] & 0x0F) * 4
    total_len = struct.unpack('!H', ip_hdr[2:4])[0]
    ip_proto = ip_hdr[9]
    src_ip = socket.inet_ntoa(ip_hdr[12:16])
    dst_ip = socket.inet_ntoa(ip_hdr[16:20])

    l4_offset = offset + ihl
    src_port = dst_port = 0
    tcp_flags = 0
    tcp_window = 0
    payload_offset = l4_offset

    if ip_proto == 6 and len(data) >= l4_offset + 20:  # TCP
        src_port = struct.unpack('!H', data[l4_offset:l4_offset+2])[0]
        dst_port = struct.unpack('!H', data[l4_offset+2:l4_offset+4])[0]
        tcp_flags = data[l4_offset + 13]
        tcp_window = struct.unpack('!H', data[l4_offset+14:l4_offset+16])[0]
        tcp_hdr_len = ((data[l4_offset + 12] >> 4) & 0x0F) * 4
        payload_offset = l4_offset + tcp_hdr_len
    elif ip_proto == 17 and len(data) >= l4_offset + 8:  # UDP
        src_port = struct.unpack('!H', data[l4_offset:l4_offset+2])[0]
        dst_port = struct.unpack('!H', data[l4_offset+2:l4_offset+4])[0]
        payload_offset = l4_offset + 8
    else:
        return None  # skip ICMP etc for now

    payload_len = max(0, (offset + total_len) - payload_offset)
    payload_head = data[payload_offset:payload_offset + 64] if payload_len > 0 else b''
    pkt_len = total_len

    # Direction from VLAN tag — VLAN is ground truth, no heuristic.
    # VLAN 100 = ingress: src_ip is ATTACKER → direction=1 (fwd)
    # VLAN 101 = egress:  src_ip is HONEYPOT → direction=-1 (rev), swap key
    if vlan_id == 100:
        direction = 1
        key = (src_ip, dst_ip, src_port, dst_port, ip_proto)
    else:  # vlan_id == 101
        direction = -1
        key = (dst_ip, src_ip, dst_port, src_port, ip_proto)

    return {
        'key': key, 'src_ip': key[0], 'dst_ip': key[1],
        'src_port': key[2], 'dst_port': key[3], 'ip_proto': ip_proto,
        'vlan_id': vlan_id, 'direction': direction,
        'payload_len': payload_len, 'pkt_len': pkt_len,
        'tcp_flags': tcp_flags, 'tcp_window': tcp_window,
        'payload_head': payload_head,
    }


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    log.info('GOD 1 — AIO Instant Catcher')
    log.info('Interface: %s, Model: %s', IFACE, MODEL_PATH)
    log.info('Session timeout: %ds, Drop threshold: %d attack flows, Drop TTL: %ds',
             SESSION_TIMEOUT, DROP_THRESHOLD, DROP_TTL)

    scorer = XGBScorer(MODEL_PATH)
    ip_table = IPTable()
    ip_table.load(IPTABLE_PATH)
    drop_filter = DropFilter()
    nats_bridge = NATSBridge(drop_filter)

    def _shutdown(signum, frame):
        log.info('Signal %d received, saving IP table...', signum)
        ip_table.save(IPTABLE_PATH)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        capture_loop(IFACE, scorer, ip_table, drop_filter, nats_bridge)
    except KeyboardInterrupt:
        log.info('Stopped.')
        ip_table.save(IPTABLE_PATH)
        total_ips, attackers, clean = ip_table.stats()
        drop_count, drop_pkts = drop_filter.stats()
        log.info('Final: %d IPs, %d attackers, %d clean, %d dropped (%d pkts)',
                 total_ips, attackers, clean, drop_count, drop_pkts)
        top = ip_table.top_attackers(20)
        for ip, d in top:
            log.info('  %-18s flows=%-5d attacks=%-4d worst=%s(%.2f)',
                     ip, d['flows'], d['attacks'], CLASS_NAMES.get(d['worst_label'],'?'), d['worst_conf'])


if __name__ == '__main__':
    main()
