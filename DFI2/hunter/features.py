#!/usr/bin/env python3
import math
from statistics import mean, pstdev


APP_PROTO_MAP = {
    22: 1,
    80: 2,
    8080: 2,
    443: 3,
    53: 4,
    25: 5,
    21: 6,
    23: 7,
    3389: 8,
    5900: 9,
    445: 10,
    3306: 11,
    1433: 12,
    5432: 13,
    6379: 14,
    27017: 15,
}


def _safe_mean(values):
    return float(mean(values)) if values else None


def _safe_std(values):
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return float(pstdev(values))


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = float(len(data))
    return float(-sum((c / n) * math.log2(c / n) for c in freq if c > 0))


def _estimate_rtt_ms(events):
    syn_ts = None
    for e in events:
        if e.direction == 1 and (e.tcp_flags & 0x02):
            syn_ts = e.ts
        elif e.direction == -1 and syn_ts is not None:
            if e.ts > syn_ts:
                return (e.ts - syn_ts) * 1000.0

    first_fwd = next((e.ts for e in events if e.direction == 1), None)
    first_rev = next((e.ts for e in events if e.direction == -1), None)
    if first_fwd is not None and first_rev is not None and first_rev > first_fwd:
        return (first_rev - first_fwd) * 1000.0
    return None


def _classify_conn_state(s):
    if s.ip_proto != 6:
        return 7

    syn = s.syn_count > 0
    synack = s.synack_seen
    data = s.n_payload_pkts > 0
    fin = s.fin_count > 0
    rst = s.rst_count > 0
    many = s.n_payload_pkts >= 8

    if s.syn_count > 1 and not synack:
        return 6
    if syn and not synack:
        return 0
    if synack and not data and rst:
        return 1
    if synack and data and fin and not many:
        return 2
    if synack and data and rst and not many:
        return 3
    if synack and data and fin and many:
        return 4
    if synack and data and rst and many:
        return 5
    if synack and data and fin:
        return 2
    if synack and data and rst:
        return 3
    return 0


def extract_features(session) -> dict:
    app_proto = APP_PROTO_MAP.get(session.dst_port, APP_PROTO_MAP.get(session.src_port, 0))

    duration_s = max(session.last_ts - session.first_ts, 0.0)
    duration_ms = int(duration_s * 1000.0)
    total_pkts = session.pkts_fwd + session.pkts_rev
    total_bytes = session.bytes_fwd + session.bytes_rev

    bytes_per_pkt_fwd = session.bytes_fwd / max(session.pkts_fwd, 1)
    bytes_per_pkt_rev = (session.bytes_rev / session.pkts_rev) if session.pkts_rev > 0 else None
    pkt_ratio = session.pkts_fwd / max(session.pkts_rev, 1)
    byte_ratio = session.bytes_fwd / max(session.bytes_rev, 1)

    rtt_ms = _estimate_rtt_ms(session.events)

    fwd_iats_ms = []
    fwd_ts = session.fwd_timestamps
    for i in range(1, len(fwd_ts)):
        fwd_iats_ms.append((fwd_ts[i] - fwd_ts[i - 1]) * 1000.0)

    iat_fwd_mean_ms = _safe_mean(fwd_iats_ms)
    iat_fwd_std_ms = _safe_std(fwd_iats_ms)

    think_time_mean_ms = None
    think_time_std_ms = None
    iat_to_rtt = None
    if rtt_ms is not None and fwd_iats_ms:
        think = [max(x - rtt_ms, 0.0) for x in fwd_iats_ms]
        think_time_mean_ms = _safe_mean(think)
        think_time_std_ms = _safe_std(think)
        iat_to_rtt = (iat_fwd_mean_ms / max(rtt_ms, 0.1)) if iat_fwd_mean_ms is not None else None

    pps = float(total_pkts / max(duration_s, 0.001))
    bps = float(total_bytes / max(duration_s, 0.001))

    payload_rtt_ratio = None
    if rtt_ms is not None:
        payload_rtt_ratio = session.n_payload_pkts / max((duration_ms / max(rtt_ms, 0.1)), 1)

    fwd_sizes = list(session.fwd_payload_sizes)
    rev_sizes = list(session.rev_payload_sizes)
    all_sizes = fwd_sizes + rev_sizes
    n_events = len(session.events)

    hist_tiny = sum(1 for x in all_sizes if 1 <= x <= 63)
    hist_small = sum(1 for x in all_sizes if 64 <= x <= 255)
    hist_medium = sum(1 for x in all_sizes if 256 <= x <= 1023)
    hist_large = sum(1 for x in all_sizes if 1024 <= x <= 1499)
    hist_full = sum(1 for x in all_sizes if x >= 1500)
    frac_full = float(hist_full / max(n_events, 1))

    rst_frac = None
    if session.first_rst_index is not None and total_pkts > 0:
        rst_frac = session.first_rst_index / total_pkts

    syn_to_data = 0
    if session.first_syn_index is not None and session.first_payload_index is not None:
        syn_to_data = max(0, session.first_payload_index - session.first_syn_index)

    entropy_first = None
    printable_frac = None
    null_frac = None
    byte_std = None
    payload_len_first = 0

    if session.first_fwd_payload is not None:
        data = session.first_fwd_payload
        payload_len_first = len(data)
        entropy_first = _shannon_entropy(data)
        n = max(len(data), 1)
        printable_frac = sum(1 for b in data if 0x20 <= b <= 0x7E) / n
        null_frac = sum(1 for b in data if b == 0) / n
        mu = sum(data) / n
        byte_std = math.sqrt(sum((b - mu) ** 2 for b in data) / n)

    entropy_fwd_mean = _safe_mean(session.fwd_payload_entropy)
    entropy_rev_mean = _safe_mean(session.rev_payload_entropy)

    high_entropy_frac = None
    if session.fwd_payload_entropy:
        high = sum(1 for x in session.fwd_payload_entropy if x >= 7.0)
        high_entropy_frac = high / len(session.fwd_payload_entropy)

    return {
        'dst_port': session.dst_port,
        'ip_proto': session.ip_proto,
        'app_proto': app_proto,

        'pkts_fwd': session.pkts_fwd,
        'pkts_rev': session.pkts_rev,
        'bytes_fwd': session.bytes_fwd,
        'bytes_rev': session.bytes_rev,
        'bytes_per_pkt_fwd': float(bytes_per_pkt_fwd),
        'bytes_per_pkt_rev': float(bytes_per_pkt_rev) if bytes_per_pkt_rev is not None else None,
        'pkt_ratio': float(pkt_ratio),
        'byte_ratio': float(byte_ratio),

        'duration_ms': duration_ms,
        'rtt_ms': float(rtt_ms) if rtt_ms is not None else None,
        'iat_fwd_mean_ms': float(iat_fwd_mean_ms) if iat_fwd_mean_ms is not None else None,
        'iat_fwd_std_ms': float(iat_fwd_std_ms) if iat_fwd_std_ms is not None else None,
        'think_time_mean_ms': float(think_time_mean_ms) if think_time_mean_ms is not None else None,
        'think_time_std_ms': float(think_time_std_ms) if think_time_std_ms is not None else None,
        'iat_to_rtt': float(iat_to_rtt) if iat_to_rtt is not None else None,
        'pps': pps,
        'bps': bps,
        'payload_rtt_ratio': float(payload_rtt_ratio) if payload_rtt_ratio is not None else None,

        'n_events': n_events,
        'fwd_size_mean': _safe_mean(fwd_sizes),
        'fwd_size_std': _safe_std(fwd_sizes),
        'fwd_size_min': min(fwd_sizes) if fwd_sizes else 0,
        'fwd_size_max': max(fwd_sizes) if fwd_sizes else 0,
        'rev_size_mean': _safe_mean(rev_sizes),
        'rev_size_std': _safe_std(rev_sizes),
        'rev_size_max': max(rev_sizes) if rev_sizes else 0,
        'hist_tiny': hist_tiny,
        'hist_small': hist_small,
        'hist_medium': hist_medium,
        'hist_large': hist_large,
        'hist_full': hist_full,
        'frac_full': frac_full,

        'syn_count': session.syn_count,
        'fin_count': session.fin_count,
        'rst_count': session.rst_count,
        'psh_count': session.psh_count,
        'ack_only_count': session.ack_only_count,
        'conn_state': _classify_conn_state(session),
        'rst_frac': float(rst_frac) if rst_frac is not None else None,
        'syn_to_data': int(min(max(syn_to_data, 0), 255)),
        'psh_burst_max': int(min(max(session.psh_burst_max, 0), 255)),
        'retransmit_est': int(session.retransmit_est),
        'window_size_init': int(session.window_size_init),

        'entropy_first': float(entropy_first) if entropy_first is not None else None,
        'entropy_fwd_mean': float(entropy_fwd_mean) if entropy_fwd_mean is not None else None,
        'entropy_rev_mean': float(entropy_rev_mean) if entropy_rev_mean is not None else None,
        'printable_frac': float(printable_frac) if printable_frac is not None else None,
        'null_frac': float(null_frac) if null_frac is not None else None,
        'byte_std': float(byte_std) if byte_std is not None else None,
        'high_entropy_frac': float(high_entropy_frac) if high_entropy_frac is not None else None,
        'payload_len_first': int(payload_len_first),
    }
