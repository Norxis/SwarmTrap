#!/usr/bin/env python3
import math


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = float(len(data))
    return float(-sum((c / n) * math.log2(c / n) for c in freq if c > 0))


def _size_dir_token(payload_len: int, direction: int) -> int:
    raw_bin = int(math.log2(max(payload_len, 1))) - 4
    raw_bin = max(1, min(11, raw_bin))
    return int(direction) * raw_bin


def _flag_token(tcp_flags: int, is_tcp: bool) -> int:
    token = 0
    if tcp_flags & 0x02:
        token |= 1
    if tcp_flags & 0x01:
        token |= 2
    if tcp_flags & 0x04:
        token |= 4
    if tcp_flags & 0x08:
        token |= 8
    if tcp_flags & 0x10:
        token |= 16
    if token == 0 and is_tcp:
        token = 32
    if not is_tcp:
        token = 32
    return token


def _iat_log_ms_bin(seq_idx: int, iat_ms: float) -> int:
    if seq_idx == 0:
        return 1
    if iat_ms < 1:
        return 2
    if iat_ms < 10:
        return 3
    if iat_ms < 100:
        return 4
    if iat_ms < 1000:
        return 5
    if iat_ms < 10000:
        return 6
    if iat_ms < 60000:
        return 7
    return 8


def _iat_rtt_bin(seq_idx: int, iat_ms: float, rtt_ms: float) -> int:
    if seq_idx == 0 or rtt_ms is None:
        return 1
    ratio = iat_ms / max(rtt_ms, 0.01)
    if ratio < 0.5:
        return 2
    if ratio < 1:
        return 3
    if ratio < 2:
        return 4
    if ratio < 5:
        return 5
    if ratio < 20:
        return 6
    if ratio < 100:
        return 7
    if ratio < 1000:
        return 8
    return 9


def _entropy_bin(payload_len: int, payload_head: bytes):
    if payload_len == 0:
        return 1, 0.0
    data = payload_head[:payload_len]
    h = _entropy(data)
    if h < 2.0:
        b = 2
    elif h < 4.0:
        b = 3
    elif h < 5.5:
        b = 4
    elif h < 7.0:
        b = 5
    else:
        b = 6
    return b, h


def tokenize_packets(events: list, rtt_ms: float):
    out = []
    prev_ts = None

    for seq_idx, ev in enumerate(events[:128]):
        iat_ms = 0.0 if seq_idx == 0 else max(0.0, (ev.ts - prev_ts) * 1000.0)
        prev_ts = ev.ts

        is_tcp = bool(getattr(ev, 'is_tcp', True))
        entropy_bin, payload_entropy = _entropy_bin(ev.payload_len, ev.payload_head or b'')

        out.append(
            {
                'seq_idx': seq_idx,
                'ts': ev.ts,
                'direction': ev.direction,
                'payload_len': ev.payload_len,
                'pkt_len': ev.pkt_len,
                'tcp_flags': ev.tcp_flags,
                'tcp_window': getattr(ev, 'tcp_window', 0),
                'size_dir_token': _size_dir_token(ev.payload_len, ev.direction),
                'flag_token': _flag_token(ev.tcp_flags, is_tcp),
                'iat_log_ms_bin': _iat_log_ms_bin(seq_idx, iat_ms),
                'iat_rtt_bin': _iat_rtt_bin(seq_idx, iat_ms, rtt_ms),
                'entropy_bin': entropy_bin,
                'iat_ms': iat_ms,
                'payload_entropy': payload_entropy,
                'payload_head': (ev.payload_head or b'')[: min(ev.payload_len, 512)],
            }
        )

    return out
