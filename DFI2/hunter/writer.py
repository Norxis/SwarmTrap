#!/usr/bin/env python3
import logging
import threading
import time
from collections import deque

from clickhouse_driver import Client
from .depth import (
    D0_DROP,
    should_write_fanout,
    should_write_fingerprint,
    should_write_flow,
    should_write_payload,
)

# 640 CNN sequence column names (5 channels × 128 positions)
_SEQ_COLS = (
    [f'size_dir_seq_{i}' for i in range(1, 129)] +
    [f'tcp_flags_seq_{i}' for i in range(1, 129)] +
    [f'iat_log_ms_seq_{i}' for i in range(1, 129)] +
    [f'iat_rtt_bin_seq_{i}' for i in range(1, 129)] +
    [f'entropy_bin_seq_{i}' for i in range(1, 129)]
)
_SEQ_KEYS = ['size_dir_token', 'flag_token', 'iat_log_ms_bin', 'iat_rtt_bin', 'entropy_bin']


log = logging.getLogger('hunter.writer')


class DFIWriter:
    FLUSH_INTERVAL = 1.0
    FLUSH_SIZE = 50000
    MAX_REQUEUE_MULTIPLIER = 10

    def __init__(self, host='localhost', port=9000, database='dfi', norm_database='dfi_dirty'):
        self.client = Client(host=host, port=port, database=database)
        self.norm_client = Client(host=host, port=port, database=norm_database)
        self.recon_client = Client(host=host, port=port, database='dfi_recon')
        self._lookup_client = Client(host=host, port=port, database=database)  # for src_stats/fp_freq only
        self._norm_db = norm_database
        self._column_cache = {}
        # Lookup caches (per-worker-process, no cross-process sharing needed)
        self._src_cache: dict = {}   # {src_ip_str: (expires_ts, stats_dict)}
        self._fp_cache: dict = {}    # {(field, hash_val): freq_int}

        self._flow_buf = deque()
        self._fp_buf = deque()
        self._fanout_buf = deque()
        self._payload_buf = deque()
        self._evidence_buf = deque()
        self._pred_buf = deque()

        # Norm buffers — routed to norm_database (dfi_dirty or dfi_clean per capture mode)
        self._norm_flow_buf = deque()
        self._norm_pred_buf = deque()

        # Recon buffer — routed to dfi_recon database
        self._recon_buf = deque()
        self._flow_feat_buf = deque()

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._flusher = threading.Thread(target=self._flush_loop, daemon=True, name='dfi-writer-flush')
        self._flusher.start()

    def insert_flow(self, flow: dict, pkts: list, fp: dict, fanout: dict, depth: int):
        if int(depth) == D0_DROP:
            return

        is_norm = flow.get('actor_id') == 'norm'

        with self._lock:
            if should_write_flow(depth):
                flow['capture_depth'] = int(depth)
                if is_norm:
                    self._norm_flow_buf.append(flow)
                else:
                    self._flow_buf.append(flow)
            # Skip fingerprints/fanout/payload for norm — not extracted
            if not is_norm:
                if should_write_fingerprint(depth) and fp:
                    self._fp_buf.append(fp)
                if should_write_fanout(depth) and fanout:
                    self._fanout_buf.append(fanout)
                if should_write_payload(depth) and pkts:
                    for pkt in pkts:
                        payload_head = pkt.get('payload_head')
                        if payload_head:
                            self._payload_buf.append(
                                {
                                    'flow_id': flow.get('flow_id'),
                                    'src_ip': flow.get('src_ip'),
                                    'dst_ip': flow.get('dst_ip'),
                                    'flow_first_ts': flow.get('first_ts'),
                                    'seq_idx': pkt.get('seq_idx', 0),
                                    'direction': pkt.get('direction', 1),
                                    'ts': pkt.get('ts'),
                                    'payload_head': payload_head.hex(),
                                    'payload_len': pkt.get('payload_len', 0),
                                }
                            )
            if self._largest_buffer_len() >= self.FLUSH_SIZE:
                self._flush_unlocked()

    def insert_evidence(self, events: list):
        if not events:
            return
        with self._lock:
            self._evidence_buf.extend(events)
            if len(self._evidence_buf) >= self.FLUSH_SIZE:
                self._flush_unlocked()

    def insert_predictions(self, preds: list, is_norm: bool = False):
        if not preds:
            return
        with self._lock:
            if is_norm:
                self._norm_pred_buf.extend(preds)
            else:
                self._pred_buf.extend(preds)
            if self._largest_buffer_len() >= self.FLUSH_SIZE:
                self._flush_unlocked()

    def insert_recon(self, rows: list, feat: dict = None, fp: dict = None, pkt_tokens: list = None):
        if not rows:
            return
        # Build flow_features rows OUTSIDE lock — may do CH lookups (src_stats, fp_freq)
        ff_rows = []
        if feat is not None:
            src_ip = str(rows[0].get('src_ip', ''))
            src_stats = self._get_src_stats(src_ip)
            fp_freqs = self._get_fp_freqs(fp)
            for row in rows:
                ff_rows.append(self._build_flow_features_row(row, feat, fp, pkt_tokens, src_stats, fp_freqs))
        with self._lock:
            self._recon_buf.extend(rows)
            if ff_rows:
                self._flow_feat_buf.extend(ff_rows)
            if self._largest_buffer_len() >= self.FLUSH_SIZE:
                self._flush_unlocked()

    def _get_src_stats(self, src_ip: str) -> dict:
        """Lookup src_* aggregate features from dfi.source_stats. Cached 5 min per IP."""
        now = time.time()
        cached = self._src_cache.get(src_ip)
        if cached and cached[0] > now:
            return cached[1]
        _zero = {'src_flow_count': 0, 'src_unique_ports': 0, 'src_unique_protos': 0,
                 'src_unique_dsts': 0, 'src_span_min': 0, 'src_avg_pps': 0.0}
        try:
            rows = self._lookup_client.execute(
                f"SELECT countMerge(flow_count), uniqMerge(unique_ports), uniqMerge(unique_protos),"
                f" uniqMerge(unique_dsts),"
                f" dateDiff('minute', minMerge(first_seen), maxMerge(last_seen)),"
                f" sumMerge(sum_pps) / greatest(countMerge(flow_count), 1)"
                f" FROM source_stats WHERE src_ip = toIPv4('{src_ip}')"
            )
            if rows and rows[0][0]:
                r = rows[0]
                stats = {
                    'src_flow_count': int(r[0]),
                    'src_unique_ports': int(r[1]),
                    'src_unique_protos': int(r[2]),
                    'src_unique_dsts': int(r[3]),
                    'src_span_min': int(r[4]) if r[4] is not None else 0,
                    'src_avg_pps': float(r[5]) if r[5] is not None else 0.0,
                }
            else:
                stats = _zero
        except Exception as exc:
            log.warning('src_stats_lookup_failed ip=%s err=%s', src_ip, exc)
            stats = _zero
        self._src_cache[src_ip] = (now + 300, stats)
        return stats

    def _get_fp_freqs(self, fp: dict) -> dict:
        """Lookup ja3_freq, hassh_freq, http_ua_freq from dfi.fingerprint_freq. Cached permanently."""
        if not fp:
            return {'ja3_freq': 0, 'hassh_freq': 0, 'http_ua_freq': 0}
        result = {}
        for col, field, hash_key in [
            ('ja3_freq', 'ja3', 'ja3_hash'),
            ('hassh_freq', 'hassh', 'hassh_hash'),
            ('http_ua_freq', 'ua', 'http_ua_hash'),
        ]:
            hv = fp.get(hash_key)
            if not hv:
                result[col] = 0
                continue
            key = (field, hv)
            if key in self._fp_cache:
                result[col] = self._fp_cache[key]
                continue
            try:
                rows = self._lookup_client.execute(
                    f"SELECT countMerge(freq) FROM fingerprint_freq"
                    f" WHERE field='{field}' AND hash_value='{hv}'"
                )
                freq = int(rows[0][0]) if rows else 0
            except Exception as exc:
                log.warning('fp_freq_lookup_failed field=%s err=%s', field, exc)
                freq = 0
            self._fp_cache[key] = freq
            # Evict oldest half when cache exceeds 50K entries (unbounded in all-traffic mode)
            if len(self._fp_cache) > 50000:
                for old_key in list(self._fp_cache.keys())[:25000]:
                    del self._fp_cache[old_key]
            result[col] = freq
        return result

    def _build_flow_features_row(self, recon_row: dict, feat: dict, fp: dict,
                                  pkt_tokens: list, src_stats: dict, fp_freqs: dict) -> dict:
        # Expand 5 sequence channels into 640 individual Int8 columns (padded to 128 with 0)
        channels = []
        for key in _SEQ_KEYS:
            vals = [int(t[key]) for t in pkt_tokens] if pkt_tokens else []
            vals = vals[:128]
            vals += [0] * (128 - len(vals))
            channels.append(vals)
        seq = {}
        for ch_idx, ch_name in enumerate(['size_dir_seq', 'tcp_flags_seq', 'iat_log_ms_seq',
                                           'iat_rtt_bin_seq', 'entropy_bin_seq']):
            for pos in range(128):
                seq[f'{ch_name}_{pos + 1}'] = channels[ch_idx][pos]

        fp = fp or {}
        row = {
            # Metadata
            'flow_id': recon_row['flow_id'],
            'ts': recon_row['ts'],
            'src_ip': recon_row['src_ip'],
            'dst_ip': recon_row['dst_ip'],
            'recon_prob': recon_row.get('recon_prob', 0.0),
            'model_version': recon_row.get('model_version', ''),
            'detection_type': recon_row.get('detection_type', 'recon'),
            # F1 Protocol (3)
            'dst_port': feat.get('dst_port') or recon_row.get('dst_port', 0),
            'ip_proto': feat.get('ip_proto'),
            'app_proto': feat.get('app_proto'),
            # F2 Volume (8)
            'pkts_fwd': feat.get('pkts_fwd'),
            'pkts_rev': feat.get('pkts_rev'),
            'bytes_fwd': feat.get('bytes_fwd'),
            'bytes_rev': feat.get('bytes_rev'),
            'bytes_per_pkt_fwd': feat.get('bytes_per_pkt_fwd'),
            'bytes_per_pkt_rev': feat.get('bytes_per_pkt_rev'),
            'pkt_ratio': feat.get('pkt_ratio'),
            'byte_ratio': feat.get('byte_ratio'),
            # F3 Timing (10)
            'duration_ms': feat.get('duration_ms'),
            'rtt_ms': feat.get('rtt_ms'),
            'iat_fwd_mean_ms': feat.get('iat_fwd_mean_ms'),
            'iat_fwd_std_ms': feat.get('iat_fwd_std_ms'),
            'think_time_mean_ms': feat.get('think_time_mean_ms'),
            'think_time_std_ms': feat.get('think_time_std_ms'),
            'iat_to_rtt': feat.get('iat_to_rtt'),
            'pps': feat.get('pps'),
            'bps': feat.get('bps'),
            'payload_rtt_ratio': feat.get('payload_rtt_ratio'),
            # F4 Packet Size Shape (14)
            'n_events': feat.get('n_events'),
            'fwd_size_mean': feat.get('fwd_size_mean'),
            'fwd_size_std': feat.get('fwd_size_std'),
            'fwd_size_min': feat.get('fwd_size_min'),
            'fwd_size_max': feat.get('fwd_size_max'),
            'rev_size_mean': feat.get('rev_size_mean'),
            'rev_size_std': feat.get('rev_size_std'),
            'rev_size_max': feat.get('rev_size_max'),
            'hist_tiny': feat.get('hist_tiny'),
            'hist_small': feat.get('hist_small'),
            'hist_medium': feat.get('hist_medium'),
            'hist_large': feat.get('hist_large'),
            'hist_full': feat.get('hist_full'),
            'frac_full': feat.get('frac_full'),
            # F5 TCP Behavior (11)
            'syn_count': feat.get('syn_count'),
            'fin_count': feat.get('fin_count'),
            'rst_count': feat.get('rst_count'),
            'psh_count': feat.get('psh_count'),
            'ack_only_count': feat.get('ack_only_count'),
            'conn_state': feat.get('conn_state'),
            'rst_frac': feat.get('rst_frac'),
            'syn_to_data': feat.get('syn_to_data'),
            'psh_burst_max': feat.get('psh_burst_max'),
            'retransmit_est': feat.get('retransmit_est'),
            'window_size_init': feat.get('window_size_init'),
            # F6 Payload Content (8)
            'entropy_first': feat.get('entropy_first'),
            'entropy_fwd_mean': feat.get('entropy_fwd_mean'),
            'entropy_rev_mean': feat.get('entropy_rev_mean'),
            'printable_frac': feat.get('printable_frac'),
            'null_frac': feat.get('null_frac'),
            'byte_std': feat.get('byte_std'),
            'high_entropy_frac': feat.get('high_entropy_frac'),
            'payload_len_first': feat.get('payload_len_first'),
            # F7 Protocol Fingerprints (15) — freq-encoded at write time
            'ja3_freq': fp_freqs.get('ja3_freq', 0),
            'tls_version': fp.get('tls_version', 0),
            'tls_cipher_count': fp.get('tls_cipher_count', 0),
            'tls_ext_count': fp.get('tls_ext_count', 0),
            'tls_has_sni': fp.get('tls_has_sni', 0),
            'hassh_freq': fp_freqs.get('hassh_freq', 0),
            'ssh_kex_count': fp.get('ssh_kex_count', 0),
            'http_method': fp.get('http_method', 0),
            'http_uri_len': fp.get('http_uri_len', 0),
            'http_header_count': fp.get('http_header_count', 0),
            'http_ua_freq': fp_freqs.get('http_ua_freq', 0),
            'http_has_body': fp.get('http_has_body', 0),
            'http_status': fp.get('http_status', 0),
            'dns_qtype': fp.get('dns_qtype', 0),
            'dns_qname_len': fp.get('dns_qname_len', 0),
            # F8 Source Behavior (6) — looked up at write time
            'src_flow_count': src_stats['src_flow_count'],
            'src_unique_ports': src_stats['src_unique_ports'],
            'src_unique_protos': src_stats['src_unique_protos'],
            'src_unique_dsts': src_stats['src_unique_dsts'],
            'src_span_min': src_stats['src_span_min'],
            'src_avg_pps': src_stats['src_avg_pps'],
        }
        row.update(seq)  # add all 640 sequence columns
        return row

    def close(self):
        self._stop.set()
        self._flusher.join(timeout=3)
        with self._lock:
            self._flush_unlocked()

    def _largest_buffer_len(self) -> int:
        return max(
            len(self._flow_buf),
            len(self._fp_buf),
            len(self._fanout_buf),
            len(self._payload_buf),
            len(self._evidence_buf),
            len(self._pred_buf),
            len(self._norm_flow_buf),
            len(self._norm_pred_buf),
            len(self._recon_buf),
            len(self._flow_feat_buf),
        )

    def _flush_loop(self):
        while not self._stop.is_set():
            time.sleep(self.FLUSH_INTERVAL)
            with self._lock:
                self._flush_unlocked()

    def _flush_unlocked(self):
        # Attack/main buffers → dfi
        self._flush_table('dfi.flows_buffer', self._flow_buf)
        self._flush_table('dfi.fingerprints_buffer', self._fp_buf)
        self._flush_table('dfi.fanout_hops_buffer', self._fanout_buf)
        self._flush_table('dfi.payload_bytes_buffer', self._payload_buf)
        self._flush_table('dfi.evidence_events_buffer', self._evidence_buf)
        self._flush_table('dfi.model_predictions_buffer', self._pred_buf)

        # Norm buffers → norm_database (dfi_dirty or dfi_clean per capture mode)
        self._flush_table(f'{self._norm_db}.flows_buffer', self._norm_flow_buf, client=self.norm_client)
        self._flush_table(f'{self._norm_db}.model_predictions_buffer', self._norm_pred_buf, client=self.norm_client)

        # Recon buffer → dfi_recon
        self._flush_table('dfi_recon.recon_flows_buffer', self._recon_buf, client=self.recon_client)
        self._flush_table('dfi_recon.flow_features_buffer', self._flow_feat_buf, client=self.recon_client)

    def insert_depth_change(self, attacker_ip: str, old_depth: int, new_depth: int, reason: str, triggered_by: str = 'rule'):
        row = {
            'attacker_ip': attacker_ip,
            'old_depth': int(old_depth),
            'new_depth': int(new_depth),
            'trigger_reason': reason,
            'triggered_by': triggered_by,
        }
        try:
            self.client.execute('INSERT INTO dfi.depth_changes VALUES', [row])
        except Exception as exc:
            log.warning('depth_change_insert_failed ip=%s err=%s', attacker_ip, exc)

    def _flush_table(self, table: str, buf: deque, client: Client = None):
        if not buf:
            return

        cl = client or self.client
        rows = list(buf)
        buf.clear()

        cols = self._get_table_columns(table, rows, cl)
        if not cols:
            log.warning('flush_skipped table=%s reason=no_columns', table)
            return

        payload = [list(r.get(c) for c in cols) for r in rows]

        try:
            cl.execute(
                f"INSERT INTO {table} ({','.join(cols)}) VALUES",
                payload,
                types_check=True,
            )
            log.info('flush table=%s rows=%d', table, len(rows))
        except Exception as exc:
            if len(buf) < self.FLUSH_SIZE * self.MAX_REQUEUE_MULTIPLIER:
                for row in reversed(rows):
                    buf.appendleft(row)
            log.warning('flush_failed table=%s rows=%d err=%s', table, len(rows), exc)

    def _get_table_columns(self, table: str, rows: list, client: Client = None) -> list:
        cl = client or self.client
        if table in self._column_cache:
            known = self._column_cache[table]
        else:
            try:
                # DESCRIBE returns rows: (name, type, default_type, default_expr, ...)
                desc = cl.execute(f'DESCRIBE TABLE {table}')
                known = {r[0] for r in desc}
                self._column_cache[table] = known
            except Exception:
                # Fallback to row keys if metadata lookup fails.
                return list(rows[0].keys())
        return [k for k in rows[0].keys() if k in known]
