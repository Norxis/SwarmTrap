#!/usr/bin/env python3
import hashlib
import logging
import multiprocessing
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from . import config
from .afpacket import FanoutCapture, ParsedPacket
from .depth import D0_DROP, D1_FLOW, D2_SEQUENCE, check_d0_repromotion, get_capture_depth
from .evidence import FEEDBACK_SOCKET, EvidenceReader
from .features import extract_features
from .fingerprints import extract_fingerprint
from .filters import AllTrafficFilter, CleanTrafficFilter, DirtyTrafficFilter, HoneypotFilter, SpanWatchlistFilter
from .tokenizer import tokenize_packets
from .watchlist import WatchlistReader
from .writer import DFIWriter


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s %(message)s',
)
log = logging.getLogger('hunter.core')


@dataclass
class PacketEvent:
    ts: float
    direction: int
    payload_len: int
    pkt_len: int
    tcp_flags: int
    tcp_window: int
    payload_head: bytes
    is_tcp: bool = True


@dataclass
class SessionProfile:
    flow_id: str
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
    capture_depth: int = 2
    flushed: bool = False

    packet_count: int = 0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_only_count: int = 0
    synack_seen: bool = False
    first_syn_index: Optional[int] = None
    first_payload_index: Optional[int] = None
    first_rst_index: Optional[int] = None
    psh_burst_cur: int = 0
    psh_burst_max: int = 0
    retransmit_est: int = 0
    window_size_init: int = 0
    n_payload_pkts: int = 0

    # Capped at 256 — prevents unbounded growth in all-traffic mode (long-lived normal sessions)
    fwd_timestamps: deque = field(default_factory=lambda: deque(maxlen=256))
    fwd_payload_sizes: deque = field(default_factory=lambda: deque(maxlen=256))
    rev_payload_sizes: deque = field(default_factory=lambda: deque(maxlen=256))
    fwd_payload_entropy: deque = field(default_factory=lambda: deque(maxlen=256))
    rev_payload_entropy: deque = field(default_factory=lambda: deque(maxlen=256))
    first_fwd_payload: Optional[bytes] = None

    is_attack_related: bool = True
    _xgb_scored: bool = False
    _recon_scored: bool = False
    _seen_pairs: set = field(default_factory=set)


class SessionTracker:
    def __init__(self, writer: DFIWriter, watchlist: WatchlistReader, filter_obj, scorer=None, recon_scorer=None, force_depth=None):
        self.writer = writer
        self.watchlist = watchlist
        self.filter_obj = filter_obj
        self._scorer = scorer
        self._recon_scorer = recon_scorer
        self._force_depth = force_depth

        self._sessions = OrderedDict()  # LRU order: front=oldest, back=newest
        self._ready = []
        self._lock = threading.Lock()

    def ingest(self, pkt: ParsedPacket):
        resolved = self.filter_obj.check_packet(pkt.src_ip, pkt.dst_ip)
        if not resolved:
            return

        bad_ip, peer_ip, direction, is_attack = resolved
        if direction == 1:
            src_port = pkt.src_port
            dst_port = pkt.dst_port
        else:
            src_port = pkt.dst_port
            dst_port = pkt.src_port

        ip_proto = self._ip_proto(pkt.l4_proto)
        key = (bad_ip, peer_ip, src_port, dst_port, ip_proto)

        now_ts = pkt.ts
        with self._lock:
            sess = self._sessions.get(key)
            if sess:
                self._sessions.move_to_end(key)  # O(1): mark as recently used
            else:
                if len(self._sessions) >= config.MAX_SESSIONS:
                    self._evict_oldest()
                if self._force_depth is not None:
                    depth = self._force_depth
                else:
                    wl_entry = self.watchlist.lookup(bad_ip)
                    depth = get_capture_depth(wl_entry)
                    if depth == D0_DROP and wl_entry is not None:
                        if not self.watchlist.is_repromoted(bad_ip) and check_d0_repromotion(dst_port, wl_entry):
                            depth = D2_SEQUENCE
                            self.watchlist.mark_repromotion(bad_ip)
                            self.writer.insert_depth_change(
                                bad_ip,
                                D0_DROP,
                                D2_SEQUENCE,
                                f"D0 re-promotion: new port {dst_port} vs top_port {wl_entry.get('top_port')}",
                                'rule',
                            )
                    if depth == D0_DROP:
                        return

                sess = SessionProfile(
                    flow_id=str(uuid4()),
                    src_ip=bad_ip,
                    dst_ip=peer_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    ip_proto=ip_proto,
                    vlan_id=pkt.vlan_id,
                    first_ts=now_ts,
                    last_ts=now_ts,
                    capture_depth=depth,
                    is_attack_related=is_attack,
                )
                self._sessions[key] = sess

            self._update_session(sess, pkt, direction)

    def expire_idle(self) -> int:
        now = time.time()
        expired = []
        with self._lock:
            for key, sess in list(self._sessions.items()):
                if (now - sess.last_ts) > config.SESSION_TIMEOUT and not sess.flushed:
                    sess.flushed = True
                    self._ready.append(sess)
                    expired.append(key)

            for key in expired:
                del self._sessions[key]

            if len(self._ready) > config.MAX_READY_Q:
                overflow = len(self._ready) - config.MAX_READY_Q
                if overflow > 0:
                    self._ready = self._ready[overflow:]

        return len(expired)

    def flush_ready(self):
        with self._lock:
            ready = self._ready
            self._ready = []

        for sess in ready:
            feat = extract_features(sess)
            pkt_tokens = tokenize_packets(sess.events, feat.get('rtt_ms'))
            fp = extract_fingerprint(sess)

            if self._scorer and not sess._xgb_scored:
                self._flush_score(sess, feat, pkt_tokens, fp)

            if self._recon_scorer and not sess._recon_scored:
                self._flush_recon_score(sess, feat, pkt_tokens, fp)

            flow = self._build_flow_row(sess, feat, pkt_tokens)
            packets = self._build_packet_rows(sess, pkt_tokens)
            fanout = self._build_fanout_row(sess, feat)

            self.writer.insert_flow(flow, packets, fp=fp, fanout=fanout, depth=sess.capture_depth)

    def _build_flow_row(self, s: SessionProfile, feat: dict, pkt_tokens: list = None) -> dict:
        first_dt = datetime.fromtimestamp(s.first_ts, tz=timezone.utc)
        last_dt = datetime.fromtimestamp(s.last_ts, tz=timezone.utc)

        return {
            'flow_id': s.flow_id,
            'session_key': self._session_key(s),
            'actor_id': s.src_ip if s.is_attack_related else 'norm',
            'src_ip': s.src_ip,
            'dst_ip': s.dst_ip,
            'src_port': s.src_port,
            'dst_port': int(feat['dst_port']),
            'ip_proto': int(feat['ip_proto']),
            'app_proto': int(feat['app_proto']),
            'vlan_id': s.vlan_id,
            'first_ts': first_dt,
            'last_ts': last_dt,
            'capture_depth': s.capture_depth,

            'pkts_fwd': int(feat['pkts_fwd']),
            'pkts_rev': int(feat['pkts_rev']),
            'bytes_fwd': int(feat['bytes_fwd']),
            'bytes_rev': int(feat['bytes_rev']),

            'rtt_ms': feat['rtt_ms'],
            'duration_ms': int(feat['duration_ms']),
            'iat_fwd_mean_ms': feat['iat_fwd_mean_ms'],
            'iat_fwd_std_ms': feat['iat_fwd_std_ms'],
            'think_time_mean_ms': feat['think_time_mean_ms'],
            'think_time_std_ms': feat['think_time_std_ms'],
            'iat_to_rtt': feat['iat_to_rtt'],
            'pps': float(feat['pps']),
            'bps': float(feat['bps']),
            'payload_rtt_ratio': feat['payload_rtt_ratio'],

            'n_events': int(feat['n_events']),
            'fwd_size_mean': feat['fwd_size_mean'],
            'fwd_size_std': feat['fwd_size_std'],
            'fwd_size_min': int(feat['fwd_size_min']),
            'fwd_size_max': int(feat['fwd_size_max']),
            'rev_size_mean': feat['rev_size_mean'],
            'rev_size_std': feat['rev_size_std'],
            'rev_size_max': int(feat['rev_size_max']),
            'hist_tiny': int(feat['hist_tiny']),
            'hist_small': int(feat['hist_small']),
            'hist_medium': int(feat['hist_medium']),
            'hist_large': int(feat['hist_large']),
            'hist_full': int(feat['hist_full']),
            'frac_full': float(feat['frac_full']),

            'syn_count': int(feat['syn_count']),
            'fin_count': int(feat['fin_count']),
            'rst_count': int(feat['rst_count']),
            'psh_count': int(feat['psh_count']),
            'ack_only_count': int(feat['ack_only_count']),
            'conn_state': int(feat['conn_state']),
            'rst_frac': feat['rst_frac'],
            'syn_to_data': int(feat['syn_to_data']),
            'psh_burst_max': int(feat['psh_burst_max']),
            'retransmit_est': int(feat['retransmit_est']),
            'window_size_init': int(feat['window_size_init']),

            'entropy_first': feat['entropy_first'],
            'entropy_fwd_mean': feat['entropy_fwd_mean'],
            'entropy_rev_mean': feat['entropy_rev_mean'],
            'printable_frac': feat['printable_frac'],
            'null_frac': feat['null_frac'],
            'byte_std': feat['byte_std'],
            'high_entropy_frac': feat['high_entropy_frac'],
            'payload_len_first': int(feat['payload_len_first']),

            # CNN packet sequences (embedded arrays, empty for D1)
            'pkt_size_dir': [int(t['size_dir_token']) for t in pkt_tokens] if pkt_tokens else [],
            'pkt_flag': [int(t['flag_token']) for t in pkt_tokens] if pkt_tokens else [],
            'pkt_iat_log_ms': [int(t['iat_log_ms_bin']) for t in pkt_tokens] if pkt_tokens else [],
            'pkt_iat_rtt': [int(t['iat_rtt_bin']) for t in pkt_tokens] if pkt_tokens else [],
            'pkt_entropy': [int(t['entropy_bin']) for t in pkt_tokens] if pkt_tokens else [],

            # Extra scalars kept in dict for downstream paths; writer filters unknown CH columns.
            'bytes_per_pkt_fwd': feat['bytes_per_pkt_fwd'],
            'bytes_per_pkt_rev': feat['bytes_per_pkt_rev'],
            'pkt_ratio': feat['pkt_ratio'],
            'byte_ratio': feat['byte_ratio'],
        }

    def _build_packet_rows(self, s: SessionProfile, pkt_tokens: list) -> list:
        rows = []
        flow_first_dt = datetime.fromtimestamp(s.first_ts, tz=timezone.utc)
        for tok in pkt_tokens:
            ts_dt = datetime.fromtimestamp(tok['ts'], tz=timezone.utc)
            rows.append(
                {
                    'flow_id': s.flow_id,
                    'src_ip': s.src_ip,
                    'dst_ip': s.dst_ip,
                    'flow_first_ts': flow_first_dt,
                    'seq_idx': int(tok['seq_idx']),
                    'ts': ts_dt,
                    'direction': int(tok['direction']),
                    'payload_len': int(tok['payload_len']),
                    'pkt_len': int(tok['pkt_len']),
                    'tcp_flags': int(tok['tcp_flags']),
                    'tcp_window': int(tok['tcp_window']),
                    'size_dir_token': int(tok['size_dir_token']),
                    'flag_token': int(tok['flag_token']),
                    'iat_log_ms_bin': int(tok['iat_log_ms_bin']),
                    'iat_rtt_bin': int(tok['iat_rtt_bin']),
                    'entropy_bin': int(tok['entropy_bin']),
                    'iat_ms': float(tok['iat_ms']),
                    'payload_entropy': float(tok['payload_entropy']),
                    'payload_head': tok.get('payload_head', b''),
                }
            )
        return rows

    def _build_fanout_row(self, s: SessionProfile, feat: dict) -> dict:
        return {
            'flow_id': s.flow_id,
            'attacker_ip': s.src_ip,
            'target_ip': s.dst_ip,
            'dst_port': s.dst_port,
            'app_proto': int(feat['app_proto']),
            'vlan_id': s.vlan_id,
            'first_ts': datetime.fromtimestamp(s.first_ts, tz=timezone.utc),
            'last_ts': datetime.fromtimestamp(s.last_ts, tz=timezone.utc),
            'pkts_fwd': int(feat['pkts_fwd']),
            'pkts_rev': int(feat['pkts_rev']),
            'bytes_fwd': int(feat['bytes_fwd']),
            'bytes_rev': int(feat['bytes_rev']),
            'duration_ms': int(feat['duration_ms']),
            'conn_state': int(feat['conn_state']),
            'n_events': int(feat['n_events']),
            'session_gap_sec': None,
        }

    def _update_session(self, sess: SessionProfile, pkt: ParsedPacket, direction: int):
        sess.last_ts = pkt.ts
        sess.packet_count += 1

        if direction == 1:
            sess.pkts_fwd += 1
            sess.bytes_fwd += pkt.payload_len
            sess.fwd_timestamps.append(pkt.ts)
            if pkt.payload_len > 0:
                sess.fwd_payload_sizes.append(pkt.payload_len)
        else:
            sess.pkts_rev += 1
            sess.bytes_rev += pkt.payload_len
            if pkt.payload_len > 0:
                sess.rev_payload_sizes.append(pkt.payload_len)

        is_tcp = pkt.l4_proto == 'tcp'
        if is_tcp:
            flags = pkt.tcp_flags
            has_ack = bool(flags & 0x10)
            has_syn = bool(flags & 0x02)
            has_fin = bool(flags & 0x01)
            has_rst = bool(flags & 0x04)
            has_psh = bool(flags & 0x08)

            if has_syn and not has_ack:
                sess.syn_count += 1
                if sess.first_syn_index is None:
                    sess.first_syn_index = sess.packet_count
                if sess.window_size_init == 0 and direction == 1:
                    sess.window_size_init = pkt.tcp_window
            if has_fin:
                sess.fin_count += 1
            if has_rst:
                sess.rst_count += 1
                if sess.first_rst_index is None:
                    sess.first_rst_index = sess.packet_count
            if has_psh:
                sess.psh_count += 1
                sess.psh_burst_cur += 1
                if sess.psh_burst_cur > sess.psh_burst_max:
                    sess.psh_burst_max = sess.psh_burst_cur
            else:
                sess.psh_burst_cur = 0

            if has_ack and not (has_syn or has_fin or has_rst or has_psh) and pkt.payload_len == 0:
                sess.ack_only_count += 1

            if has_syn and has_ack and direction == -1:
                sess.synack_seen = True

        if pkt.payload_len > 0:
            sess.n_payload_pkts += 1
            if sess.first_payload_index is None:
                sess.first_payload_index = sess.packet_count

            payload = pkt.raw_payload[: pkt.payload_len] if pkt.raw_payload else b''
            ent = _entropy(payload)
            if direction == 1:
                sess.fwd_payload_entropy.append(ent)
                if sess.first_fwd_payload is None:
                    sess.first_fwd_payload = payload
            else:
                sess.rev_payload_entropy.append(ent)

        pair = (direction, pkt.payload_len)
        if pair in sess._seen_pairs:
            sess.retransmit_est += 1
        else:
            sess._seen_pairs.add(pair)

        if len(sess.events) < 128 and self._is_event_packet(pkt.payload_len, pkt.tcp_flags, is_tcp):
            sess.events.append(
                PacketEvent(
                    ts=pkt.ts,
                    direction=direction,
                    payload_len=pkt.payload_len,
                    pkt_len=pkt.pkt_len,
                    tcp_flags=pkt.tcp_flags,
                    tcp_window=pkt.tcp_window,
                    payload_head=pkt.raw_payload[:256] if pkt.raw_payload else b'',
                    is_tcp=is_tcp,
                )
            )

    def _flush_score(self, sess: SessionProfile, feat: dict, pkt_tokens: list, fp: dict = None):
        sess._xgb_scored = True
        try:
            from .scorer import InlineCNNScorer
            if isinstance(self._scorer, InlineCNNScorer):
                pred = self._scorer.predict(feat, pkt_tokens)
                model_name = 'cnn_v2'
            else:
                pred = self._scorer.predict(feat)
                model_name = 'xgb_v7'
        except Exception as exc:
            log.warning('score_failed ip=%s err=%s', sess.src_ip, exc)
            return

        pred_row = {
            'flow_id': sess.flow_id,
            'src_ip': sess.src_ip,
            'dst_ip': sess.dst_ip,
            'dst_port': sess.dst_port,
            'flow_first_ts': datetime.fromtimestamp(sess.first_ts, tz=timezone.utc),
            'model_name': model_name,
            'model_version': self._scorer.model_version,
            'label': pred['label'],
            'confidence': pred['confidence'],
            'class_probs': pred['class_probs'],
        }
        self.writer.insert_predictions([pred_row], is_norm=not sess.is_attack_related)

        if pred['prob_attack'] >= config.XGB_CONFIDENCE_THRESHOLD:
            # watchlist promote disabled — watchlist now fed by honeypot + conversation only
            log.info('xgb_detected ip=%s conf=%.3f pkts=%d',
                     sess.src_ip, pred['confidence'], sess.packet_count)
            self.writer.insert_recon([{
                'flow_id': sess.flow_id,
                'ts': datetime.fromtimestamp(sess.first_ts, tz=timezone.utc),
                'src_ip': sess.src_ip,
                'dst_ip': sess.dst_ip,
                'dst_port': sess.dst_port,
                'protocol': sess.ip_proto,
                'recon_prob': pred['prob_attack'],
                'model_version': self._scorer.model_version,
                'detection_type': 'attack',
            }], feat=feat, fp=fp, pkt_tokens=pkt_tokens)

    def _flush_recon_score(self, sess: SessionProfile, feat: dict, pkt_tokens: list = None, fp: dict = None):
        sess._recon_scored = True
        try:
            pred = self._recon_scorer.predict(feat)
        except Exception as exc:
            log.warning('recon_score_failed ip=%s err=%s', sess.src_ip, exc)
            return

        recon_prob = pred['prob_attack']

        pred_row = {
            'flow_id': sess.flow_id,
            'src_ip': sess.src_ip,
            'dst_ip': sess.dst_ip,
            'dst_port': sess.dst_port,
            'flow_first_ts': datetime.fromtimestamp(sess.first_ts, tz=timezone.utc),
            'model_name': 'recon_v3',
            'model_version': self._recon_scorer.model_version,
            'label': pred['label'],
            'confidence': pred['confidence'],
            'class_probs': pred['class_probs'],
        }
        self.writer.insert_predictions([pred_row], is_norm=not sess.is_attack_related)

        if recon_prob >= config.RECON_CONFIDENCE_THRESHOLD:
            self.writer.insert_recon([{
                'flow_id': sess.flow_id,
                'ts': datetime.fromtimestamp(sess.first_ts, tz=timezone.utc),
                'src_ip': sess.src_ip,
                'dst_ip': sess.dst_ip,
                'dst_port': sess.dst_port,
                'protocol': sess.ip_proto,
                'recon_prob': recon_prob,
                'model_version': self._recon_scorer.model_version,
                'detection_type': 'recon',
            }], feat=feat, fp=fp, pkt_tokens=pkt_tokens)
            log.info('recon_detected ip=%s dst=%s:%d prob=%.3f',
                     sess.src_ip, sess.dst_ip, sess.dst_port, recon_prob)

    def _evict_oldest(self):
        # O(1): OrderedDict front = LRU (least recently used = oldest last_ts)
        if self._sessions:
            _, evicted = self._sessions.popitem(last=False)
            if not evicted.flushed:
                evicted.flushed = True
                self._ready.append(evicted)

    @staticmethod
    def _is_event_packet(payload_len: int, tcp_flags: int, is_tcp: bool) -> bool:
        if payload_len > 0:
            return True
        if is_tcp and (tcp_flags & 0x07):
            return True
        return False

    @staticmethod
    def _ip_proto(l4: str) -> int:
        if l4 == 'tcp':
            return 6
        if l4 == 'udp':
            return 17
        if l4 == 'icmp':
            return 1
        return 0

    @staticmethod
    def _session_key(sess: SessionProfile) -> str:
        base = f'{sess.src_ip}|{sess.dst_ip}|{sess.src_port}|{sess.dst_port}|{sess.ip_proto}|{sess.first_ts:.6f}'
        return hashlib.sha256(base.encode('utf-8')).hexdigest()[:24]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    import math
    return float(-sum((c / n) * math.log2(c / n) for c in counts if c > 0))


def _worker_factory(worker_idx: int, stop_event: multiprocessing.Event):
    watchlist = WatchlistReader(config.WATCHLIST_DB, config.WATCHLIST_REFRESH)
    is_clean = config.CAPTURE_MODE == 'clean'
    is_dirty = config.CAPTURE_MODE == 'dirty'
    norm_db = 'dfi_dirty' if is_dirty else ('dfi_clean' if is_clean else 'dfi')
    writer = DFIWriter(host=config.CH_HOST, port=config.CH_PORT, database=config.CH_DATABASE, norm_database=norm_db)

    if config.CAPTURE_MODE == 'honeypot':
        excludes = [x.strip() for x in config.HONEYPOT_EXCLUDE.split(',') if x.strip()]
        filt = HoneypotFilter(config.HONEYPOT_IPS, excludes)
    elif config.CAPTURE_MODE == 'all':
        excludes = [x.strip() for x in config.HONEYPOT_EXCLUDE.split(',') if x.strip()]
        filt = AllTrafficFilter(config.HONEYPOT_IPS, excludes)
    elif is_dirty:
        filt = DirtyTrafficFilter(watchlist, config.HONEYPOT_IPS)
    elif is_clean:
        filt = CleanTrafficFilter(watchlist, config.HONEYPOT_IPS)
    else:
        filt = SpanWatchlistFilter(watchlist)

    scorer = None
    if config.XGB_MODEL_PATH and not is_clean and not is_dirty:
        try:
            if config.XGB_MODEL_PATH.endswith('.pt'):
                from .scorer import InlineCNNScorer
                scorer = InlineCNNScorer(config.XGB_MODEL_PATH)
            else:
                from .scorer import InlineScorer
                scorer = InlineScorer(config.XGB_MODEL_PATH)
        except Exception as exc:
            log.warning('worker=%d scorer_load_failed err=%s', worker_idx, exc)

    recon_scorer = None
    if config.RECON_MODEL_PATH and not is_clean and not is_dirty:
        try:
            from .scorer import InlineScorer
            recon_scorer = InlineScorer(config.RECON_MODEL_PATH)
        except Exception as exc:
            log.warning('worker=%d recon_scorer_load_failed err=%s', worker_idx, exc)

    tracker = SessionTracker(writer=writer, watchlist=watchlist, filter_obj=filt,
                             scorer=scorer, recon_scorer=recon_scorer,
                             force_depth=D2_SEQUENCE if is_dirty else None)
    evidence_reader = None
    if worker_idx == 0 and os.path.exists(FEEDBACK_SOCKET):
        evidence_reader = EvidenceReader(writer)
        evidence_reader.start()

    def flush_loop():
        stagger = worker_idx * (config.FLUSH_INTERVAL / max(config.FANOUT_WORKERS, 1))
        if stagger > 0:
            time.sleep(stagger)

        while not stop_event.is_set():
            time.sleep(config.FLUSH_INTERVAL)
            try:
                tracker.expire_idle()
                tracker.flush_ready()
            except Exception as exc:
                log.warning('worker=%d flush_loop_error=%s', worker_idx, exc)

        try:
            tracker.expire_idle()
            tracker.flush_ready()
        finally:
            if evidence_reader:
                evidence_reader.stop()
            writer.close()
            watchlist.close()

    threading.Thread(target=flush_loop, daemon=True, name=f'flush-w{worker_idx}').start()
    return tracker.ingest


def main():
    cpu_list = config.CPU_LIST if config.CPU_LIST else None
    log.info(
        'starting hunter2 iface=%s mode=%s workers=%d ch=%s:%d',
        config.HUNTER_IFACE,
        config.CAPTURE_MODE,
        config.FANOUT_WORKERS,
        config.CH_HOST,
        config.CH_PORT,
    )

    cap = FanoutCapture(
        iface=config.HUNTER_IFACE,
        num_workers=config.FANOUT_WORKERS,
        worker_factory=_worker_factory,
        cpu_list=cpu_list,
        block_size_mb=config.BLOCK_SIZE_MB,
        block_count=config.BLOCK_COUNT,
    )
    cap.start()


if __name__ == '__main__':
    main()
