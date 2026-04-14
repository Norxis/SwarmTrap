"""XGB feature extraction — 68 features (F1-F8) per spec.

Features are computed at flow emission from accumulated FlowState data.
F1-F6: Computed from flow state (54 features)
F7: Fingerprint frequency features (7 features)
F8: Source behavior features (7 features)
"""
from __future__ import annotations

import math
from statistics import mean, pstdev
from typing import Any


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _safe_mean(xs: list[float]) -> float | None:
    return mean(xs) if xs else None


def _safe_std(xs: list[float]) -> float | None:
    return pstdev(xs) if len(xs) >= 2 else None


def compute_conn_state(flow: dict[str, Any]) -> int:
    """Compute conn_state per spec (8 states, 0-7)."""
    ip_proto = flow.get("ip_proto", 6)
    if ip_proto != 6:
        return 7  # Non-TCP

    syn_count = flow.get("syn_count", 0)
    has_syn_ack = flow.get("syn_ack_ts") is not None
    has_fin = flow.get("fin_count", 0) > 0
    psh_count = flow.get("psh_count", 0)
    n_payload_pkts = flow.get("n_payload_pkts", 0)

    if syn_count > 1 and not has_syn_ack:
        return 6  # SYN flood / repeated probe
    if not has_syn_ack:
        return 0  # Port closed / filtered
    if has_syn_ack and n_payload_pkts == 0:
        return 1  # Port open, attacker disconnected
    if n_payload_pkts > 0 and psh_count <= 5:
        return 2 if has_fin else 3  # Short session
    if psh_count > 5:
        return 4 if has_fin else 5  # Extended session
    return 0


def estimate_rtt(flow: dict[str, Any]) -> float | None:
    """RTT in milliseconds from SYN→SYN-ACK or first_fwd→first_rev."""
    syn_ts = flow.get("syn_ts")
    syn_ack_ts = flow.get("syn_ack_ts")
    if syn_ts is not None and syn_ack_ts is not None and syn_ack_ts > syn_ts:
        return (syn_ack_ts - syn_ts) * 1000.0

    first_fwd = flow.get("first_fwd_ts")
    first_rev = flow.get("first_rev_ts")
    if first_fwd is not None and first_rev is not None and first_rev > first_fwd:
        return (first_rev - first_fwd) * 1000.0

    return None


def compute_xgb_features(flow: dict[str, Any]) -> dict[str, Any]:
    """Compute all 54 F1-F6 XGB features from flow state dict.

    The flow dict must contain accumulated state from FlowState:
    identity fields, volume counters, timing, TCP flags, payload
    analysis data, and histogram counters.
    """
    # ── Identity ──
    dst_port = flow.get("dst_port", 0)
    ip_proto = flow.get("ip_proto", 6)
    app_proto = flow.get("app_proto", 0)

    # ── Volume ──
    pkts_fwd = flow.get("pkts_fwd", 0)
    pkts_rev = flow.get("pkts_rev", 0)
    bytes_fwd = flow.get("bytes_fwd", 0)
    bytes_rev = flow.get("bytes_rev", 0)
    bytes_per_pkt_fwd = bytes_fwd / max(pkts_fwd, 1)
    bytes_per_pkt_rev = (bytes_rev / pkts_rev) if pkts_rev > 0 else None
    pkt_ratio = pkts_fwd / max(pkts_rev, 1)
    byte_ratio = bytes_fwd / max(bytes_rev, 1)

    # ── Timing ──
    first_ts = flow.get("first_ts", 0.0)
    last_ts = flow.get("last_ts", first_ts)
    duration_s = max(0.0, last_ts - first_ts)
    duration_ms = int(duration_s * 1000)
    rtt_ms = estimate_rtt(flow)

    fwd_iats_s: list[float] = flow.get("fwd_iats", [])
    fwd_iats_ms = [iat * 1000.0 for iat in fwd_iats_s]
    iat_fwd_mean_ms = _safe_mean(fwd_iats_ms)
    iat_fwd_std_ms = _safe_std(fwd_iats_ms)

    # Think time: IAT minus RTT for each forward IAT
    think_time_mean_ms = None
    think_time_std_ms = None
    if rtt_ms is not None and fwd_iats_ms:
        think_times = [max(0.0, iat - rtt_ms) for iat in fwd_iats_ms]
        think_time_mean_ms = _safe_mean(think_times)
        think_time_std_ms = _safe_std(think_times)

    iat_to_rtt = None
    if rtt_ms is not None and iat_fwd_mean_ms is not None:
        iat_to_rtt = iat_fwd_mean_ms / max(rtt_ms, 0.1)

    total_pkts = flow.get("total_pkts", pkts_fwd + pkts_rev)
    pps = total_pkts / max(duration_s, 0.001)
    bps = (bytes_fwd + bytes_rev) / max(duration_s, 0.001)

    n_payload_pkts = flow.get("n_payload_pkts", 0)
    payload_rtt_ratio = None
    if rtt_ms is not None and rtt_ms > 0 and duration_ms > 0:
        payload_rtt_ratio = n_payload_pkts / max(duration_ms / rtt_ms, 1.0)

    # ── Size Shape ──
    n_events = flow.get("n_events", 0)
    fwd_payload_sizes: list[int] = flow.get("fwd_payload_sizes", [])
    rev_payload_sizes: list[int] = flow.get("rev_payload_sizes", [])

    fwd_sizes_f = [float(s) for s in fwd_payload_sizes]
    rev_sizes_f = [float(s) for s in rev_payload_sizes]

    fwd_size_mean = _safe_mean(fwd_sizes_f)
    fwd_size_std = _safe_std(fwd_sizes_f)
    fwd_size_min = min(fwd_payload_sizes) if fwd_payload_sizes else 0
    fwd_size_max = max(fwd_payload_sizes) if fwd_payload_sizes else 0
    rev_size_mean = _safe_mean(rev_sizes_f)
    rev_size_std = _safe_std(rev_sizes_f)
    rev_size_max = max(rev_payload_sizes) if rev_payload_sizes else 0

    hist_tiny = flow.get("hist_tiny", 0)
    hist_small = flow.get("hist_small", 0)
    hist_medium = flow.get("hist_medium", 0)
    hist_large = flow.get("hist_large", 0)
    hist_full = flow.get("hist_full", 0)
    frac_full = hist_full / max(n_events, 1)

    # ── TCP Behavior ──
    syn_count = flow.get("syn_count", 0)
    fin_count = flow.get("fin_count", 0)
    rst_count = flow.get("rst_count", 0)
    psh_count = flow.get("psh_count", 0)
    ack_only_count = flow.get("ack_only_count", 0)
    conn_state = compute_conn_state(flow)

    first_rst_pkt_num = flow.get("first_rst_pkt_num", 0)
    rst_frac = (first_rst_pkt_num / total_pkts) if (rst_count > 0 and total_pkts > 0) else None

    syn_to_data = flow.get("syn_to_data_count", 0)
    psh_burst_max = flow.get("max_psh_run", 0)

    retransmit_set_size = flow.get("retransmit_set_size", 0)
    retransmit_est = max(0, retransmit_set_size - n_events) if retransmit_set_size > 0 else 0

    window_size_init = flow.get("window_size_init", 0) or 0

    # ── Payload Content ──
    first_fwd_payload: bytes | None = flow.get("first_fwd_payload")
    entropy_first = shannon_entropy(first_fwd_payload) if first_fwd_payload else None

    fwd_entropy_sum = flow.get("fwd_entropy_sum", 0.0)
    fwd_entropy_count = flow.get("fwd_entropy_count", 0)
    rev_entropy_sum = flow.get("rev_entropy_sum", 0.0)
    rev_entropy_count = flow.get("rev_entropy_count", 0)

    entropy_fwd_mean = (fwd_entropy_sum / fwd_entropy_count) if fwd_entropy_count > 0 else None
    entropy_rev_mean = (rev_entropy_sum / rev_entropy_count) if rev_entropy_count > 0 else None

    printable_frac = None
    null_frac = None
    byte_std = None
    if first_fwd_payload:
        total_bytes = len(first_fwd_payload)
        printable = sum(1 for b in first_fwd_payload if 0x20 <= b <= 0x7E)
        nulls = sum(1 for b in first_fwd_payload if b == 0)
        printable_frac = printable / total_bytes
        null_frac = nulls / total_bytes
        byte_vals = [float(b) for b in first_fwd_payload]
        byte_std = _safe_std(byte_vals) if len(byte_vals) >= 2 else None

    fwd_high_entropy = flow.get("fwd_high_entropy", 0)
    high_entropy_frac = (fwd_high_entropy / fwd_entropy_count) if fwd_entropy_count > 0 else None

    payload_len_first = len(first_fwd_payload) if first_fwd_payload else 0

    return {
        # F1
        "dst_port": dst_port,
        "ip_proto": ip_proto,
        "app_proto": app_proto,
        # F2
        "pkts_fwd": pkts_fwd,
        "pkts_rev": pkts_rev,
        "bytes_fwd": bytes_fwd,
        "bytes_rev": bytes_rev,
        "bytes_per_pkt_fwd": bytes_per_pkt_fwd,
        "bytes_per_pkt_rev": bytes_per_pkt_rev,
        "pkt_ratio": pkt_ratio,
        "byte_ratio": byte_ratio,
        # F3
        "duration_ms": duration_ms,
        "rtt_ms": rtt_ms,
        "iat_fwd_mean_ms": iat_fwd_mean_ms,
        "iat_fwd_std_ms": iat_fwd_std_ms,
        "think_time_mean_ms": think_time_mean_ms,
        "think_time_std_ms": think_time_std_ms,
        "iat_to_rtt": iat_to_rtt,
        "pps": pps,
        "bps": bps,
        "payload_rtt_ratio": payload_rtt_ratio,
        # F4
        "n_events": n_events,
        "fwd_size_mean": fwd_size_mean,
        "fwd_size_std": fwd_size_std,
        "fwd_size_min": fwd_size_min,
        "fwd_size_max": fwd_size_max,
        "rev_size_mean": rev_size_mean,
        "rev_size_std": rev_size_std,
        "rev_size_max": rev_size_max,
        "hist_tiny": hist_tiny,
        "hist_small": hist_small,
        "hist_medium": hist_medium,
        "hist_large": hist_large,
        "hist_full": hist_full,
        "frac_full": frac_full,
        # F5
        "syn_count": syn_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "ack_only_count": ack_only_count,
        "conn_state": conn_state,
        "rst_frac": rst_frac,
        "syn_to_data": syn_to_data,
        "psh_burst_max": psh_burst_max,
        "retransmit_est": retransmit_est,
        "window_size_init": window_size_init,
        # F6
        "entropy_first": entropy_first,
        "entropy_fwd_mean": entropy_fwd_mean,
        "entropy_rev_mean": entropy_rev_mean,
        "printable_frac": printable_frac,
        "null_frac": null_frac,
        "byte_std": byte_std,
        "high_entropy_frac": high_entropy_frac,
        "payload_len_first": payload_len_first,
    }


# ── F1-F8 ordered feature names for XGBoost vector ──

XGB_FEATURE_NAMES: list[str] = [
    # F1 Identity (3)
    "dst_port", "ip_proto", "app_proto",
    # F2 Volume (8)
    "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
    "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
    # F3 Timing (10)
    "duration_ms", "rtt_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
    "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt",
    "pps", "bps", "payload_rtt_ratio",
    # F4 Size (14)
    "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
    "rev_size_mean", "rev_size_std", "rev_size_max",
    "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
    # F5 TCP (11)
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count",
    "conn_state", "rst_frac", "syn_to_data", "psh_burst_max",
    "retransmit_est", "window_size_init",
    # F6 Entropy (8)
    "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
    "printable_frac", "null_frac", "byte_std", "high_entropy_frac",
    "payload_len_first",
    # F7 Fingerprint frequency (7)
    "ja3_freq", "hassh_freq", "http_ua_freq",
    "tls_cipher_count", "tls_ext_count", "http_header_count", "dns_qname_len",
    # F8 Source behavior (7)
    "src_flow_count", "src_unique_ports", "src_unique_protos", "src_unique_dsts",
    "src_span_min", "src_avg_pps", "src_port_entropy",
]


def to_xgb_vector(xgb_features: dict[str, Any],
                   fingerprint_stats: dict[str, Any] | None = None,
                   source_stats: dict[str, Any] | None = None) -> list[float | None]:
    """Build ordered feature vector (F1-F8) for XGBoost inference.

    Args:
        xgb_features: Dict from compute_xgb_features() (F1-F6).
        fingerprint_stats: Optional dict with F7 keys (ja3_freq, etc.).
        source_stats: Optional dict with F8 keys (src_flow_count, etc.).

    Returns:
        Ordered list of 68 float|None values. None = missing (XGBoost handles natively).
    """
    merged: dict[str, Any] = dict(xgb_features)
    if fingerprint_stats:
        merged.update(fingerprint_stats)
    if source_stats:
        merged.update(source_stats)

    vector: list[float | None] = []
    for name in XGB_FEATURE_NAMES:
        val = merged.get(name)
        if val is None:
            vector.append(None)
        else:
            try:
                vector.append(float(val))
            except (TypeError, ValueError):
                vector.append(None)
    return vector
