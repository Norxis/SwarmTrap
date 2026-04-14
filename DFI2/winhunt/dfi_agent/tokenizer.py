"""CNN token computation — 5 channels x 128 positions per spec.

Each channel converts raw packet metadata into categorical bins.
Thresholds match DFI_Windows_Capture_Agent_Spec.md exactly.
"""
from __future__ import annotations

import math
from typing import Any

from .features import shannon_entropy


def size_dir_token(pkt: dict[str, Any]) -> int:
    """Channel 1: directional log-binned size. Range: -11 to +11, 0=padding."""
    size = pkt.get("payload_len", 0)
    if not size:
        size = pkt.get("pkt_len", 0)
    if size <= 0:
        size = 1
    raw_bin = int(math.floor(math.log2(size)))
    b = min(11, max(1, raw_bin - 4))
    return int(pkt.get("direction", 1)) * b


def flag_token(pkt: dict[str, Any]) -> int:
    """Channel 2: TCP control flags. Range: 0-16, 0=padding."""
    flags = int(pkt.get("tcp_flags", 0))
    token = 0
    if flags & 0x02:
        token |= 1   # SYN
    if flags & 0x01:
        token |= 2   # FIN
    if flags & 0x04:
        token |= 4   # RST
    if flags & 0x08:
        token |= 8   # PSH
    if token == 0:
        token = 16    # PRESENT — real packet, no control flags
    return token


def iat_log_ms_bin(seq_idx: int, iat_ms: float | None) -> int:
    """Channel 3: absolute IAT bins. Range: 0-8, 0=padding.

    Thresholds per spec:
      1: first packet (no IAT)
      2: < 1ms (wire-speed)
      3: 1-10ms (fast automated)
      4: 10-100ms (LAN RTT)
      5: 100-1000ms (WAN RTT)
      6: 1-10s (slow tool)
      7: 10-60s (interactive pause)
      8: > 60s (long idle)
    """
    if seq_idx == 0 or iat_ms is None:
        return 1  # First packet
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


def iat_rtt_bin(seq_idx: int, iat_ms: float | None, rtt_ms: float | None) -> int:
    """Channel 4: RTT-normalized IAT bins. Range: 0-9, 0=padding.

    Thresholds per spec:
      1: unknown (first packet or no RTT)
      2: ratio < 0.5 (pipelining)
      3: 0.5-1 (lockstep)
      4: 1-2 (slightly paced)
      5: 2-5 (rate-limited)
      6: 5-20 (slow tool)
      7: 20-100 (long pause)
      8: 100-1000 (very long pause)
      9: > 1000 (session idle)
    """
    if seq_idx == 0 or rtt_ms is None or rtt_ms <= 0 or iat_ms is None:
        return 1  # Unknown
    ratio = iat_ms / rtt_ms
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


def entropy_bin(payload_bytes: bytes | None) -> int:
    """Channel 5: payload entropy bins. Range: 0-6, 0=padding/no payload.

    Thresholds per spec:
      1: < 1.0 (constant)
      2: 1.0-3.0 (simple ASCII)
      3: 3.0-5.0 (structured text)
      4: 5.0-6.5 (mixed content)
      5: 6.5-7.5 (compressed/encrypted)
      6: >= 7.5 (near-random)
    """
    if not payload_bytes:
        return 0
    ent = shannon_entropy(payload_bytes)
    if ent < 1.0:
        return 1
    if ent < 3.0:
        return 2
    if ent < 5.0:
        return 3
    if ent < 6.5:
        return 4
    if ent < 7.5:
        return 5
    return 6


def compute_token_rows(event_packets: list[dict[str, Any]], flow_id: str,
                       rtt_ms: float | None, max_len: int = 128) -> list[dict[str, Any]]:
    """Compute per-packet CNN token rows for buffer insertion.

    Returns list of dicts, one per event packet, with all 5 channel tokens
    plus raw iat_ms and payload_entropy for re-binning.
    """
    rows: list[dict[str, Any]] = []
    prev_ts: float | None = None

    for pkt in event_packets[:max_len]:
        seq_idx = pkt.get("seq_idx", len(rows))
        ts = float(pkt.get("ts", 0.0))
        iat_ms_val = None
        if prev_ts is not None:
            iat_ms_val = max(0.0, (ts - prev_ts) * 1000.0)
        prev_ts = ts

        payload = pkt.get("payload_bytes", b"") or b""
        p_entropy = shannon_entropy(payload) if payload else None

        rows.append({
            "flow_id": flow_id,
            "seq_idx": seq_idx,
            "ts": ts,
            "direction": pkt.get("direction", 1),
            "payload_len": pkt.get("payload_len", 0),
            "pkt_len": pkt.get("pkt_len", 0),
            "tcp_flags": pkt.get("tcp_flags", 0),
            "tcp_window": pkt.get("tcp_window", 0),
            "size_dir_token": size_dir_token(pkt),
            "flag_token": flag_token(pkt),
            "iat_log_ms_bin": iat_log_ms_bin(seq_idx, iat_ms_val),
            "iat_rtt_bin": iat_rtt_bin(seq_idx, iat_ms_val, rtt_ms),
            "entropy_bin": entropy_bin(payload),
            "iat_ms": iat_ms_val,
            "payload_entropy": p_entropy,
        })

    return rows
