"""Real-time feature vector accumulation using Welford's algorithm.

Incrementally builds the 68-feature vector for a single flow as packets
arrive, without requiring the full flow to be completed first.
"""
from __future__ import annotations

import logging
import math
from typing import Any

log = logging.getLogger("winhunt.inference.accumulator")


class _WelfordState:
    """Welford's online algorithm for streaming mean and variance."""
    __slots__ = ("n", "mean", "m2")

    def __init__(self) -> None:
        self.n: int = 0
        self.mean: float = 0.0
        self.m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self.m2 / self.n  # population variance

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


# Ordered list of all 68 feature names (F1-F8)
FEATURE_NAMES: list[str] = [
    # F1 (3): Identity
    "dst_port", "ip_proto", "app_proto",
    # F2 (8): Volume
    "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
    "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
    # F3 (10): Timing
    "duration_ms", "rtt_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
    "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt",
    "pps", "bps", "payload_rtt_ratio",
    # F4 (14): Size shape
    "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
    "rev_size_mean", "rev_size_std", "rev_size_max",
    "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
    # F5 (11): TCP behavior
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count",
    "conn_state", "rst_frac", "syn_to_data", "psh_burst_max",
    "retransmit_est", "window_size_init",
    # F6 (8): Payload content
    "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
    "printable_frac", "null_frac", "byte_std", "high_entropy_frac",
    "payload_len_first",
    # F7 (7): Fingerprints (from source_stats or frequency table)
    "ja3_freq", "hassh_freq", "http_ua_freq",
    "tls_cipher_count", "tls_ext_count", "http_header_count", "dns_qname_len",
    # F8 (7): Source behavior
    "src_flow_count", "src_unique_ports", "src_unique_protos", "src_unique_dsts",
    "src_span_min", "src_avg_pps", "src_port_entropy",
]

_TOTAL_FEATURES = len(FEATURE_NAMES)  # 68


class FeatureAccumulator:
    """Incrementally builds a 68-feature vector for a single flow.

    Updated packet-by-packet. Uses Welford's algorithm for streaming
    mean/std of IATs, sizes, and entropy values.
    """

    def __init__(
        self,
        flow_id: str,
        dst_port: int,
        ip_proto: int,
        app_proto: int,
    ) -> None:
        self.flow_id = flow_id
        self.dst_port = dst_port
        self.ip_proto = ip_proto
        self.app_proto = app_proto

        # Volume counters
        self.pkts_fwd: int = 0
        self.pkts_rev: int = 0
        self.bytes_fwd: int = 0
        self.bytes_rev: int = 0

        # Timing
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.rtt_ms: float | None = None
        self.prev_fwd_ts: float | None = None

        # Welford accumulators
        self._iat_fwd = _WelfordState()
        self._think_time = _WelfordState()
        self._fwd_size = _WelfordState()
        self._rev_size = _WelfordState()
        self._entropy_fwd = _WelfordState()
        self._entropy_rev = _WelfordState()

        # Fwd size extremes
        self.fwd_size_min: int | None = None
        self.fwd_size_max: int = 0
        self.rev_size_max: int = 0

        # Size histogram
        self.hist_tiny: int = 0
        self.hist_small: int = 0
        self.hist_medium: int = 0
        self.hist_large: int = 0
        self.hist_full: int = 0

        # TCP behavior
        self.syn_count: int = 0
        self.fin_count: int = 0
        self.rst_count: int = 0
        self.psh_count: int = 0
        self.ack_only_count: int = 0
        self.first_rst_pkt_num: int = 0
        self.total_pkts: int = 0
        self.syn_to_data_count: int = 0
        self._seen_data: bool = False
        self.current_psh_run: int = 0
        self.max_psh_run: int = 0
        self.window_size_init: int = 0
        self._retransmit_set: set[tuple[int, int]] = set()

        # Conn state tracking
        self._has_syn_ack: bool = False
        self.n_payload_pkts: int = 0

        # Payload content
        self._first_fwd_payload: bytes | None = None
        self._entropy_first: float | None = None
        self._fwd_high_entropy: int = 0
        self._first_fwd_payload_len: int = 0

        # Printable/null stats from first payload
        self._printable_frac: float | None = None
        self._null_frac: float | None = None
        self._byte_std: float | None = None

        # Event count (payload-bearing or SYN/FIN/RST)
        self.n_events: int = 0

    def update(
        self,
        pkt_len: int,
        payload_len: int,
        direction: int,
        tcp_flags: int,
        tcp_window: int,
        payload_entropy: float | None,
        iat_ms: float | None,
        rtt_ms: float | None,
    ) -> None:
        """Update accumulators with a single packet's data.

        Args:
            pkt_len: Total IP packet length.
            payload_len: Application-layer payload length.
            direction: 1 = forward (attacker->honeypot), -1 = reverse.
            tcp_flags: Raw TCP flags byte.
            tcp_window: TCP window size.
            payload_entropy: Shannon entropy of payload (None if no payload).
            iat_ms: Inter-arrival time from previous forward packet in ms (None if first).
            rtt_ms: Estimated RTT in ms (None if unknown).
        """
        now_ts = self.last_ts  # caller should set first_ts/last_ts externally if needed
        self.total_pkts += 1

        # RTT update (take first non-None value)
        if rtt_ms is not None and self.rtt_ms is None:
            self.rtt_ms = rtt_ms

        # Volume
        if direction == 1:
            self.pkts_fwd += 1
            self.bytes_fwd += pkt_len
        else:
            self.pkts_rev += 1
            self.bytes_rev += pkt_len

        # TCP flags
        is_syn = bool(tcp_flags & 0x02)
        is_fin = bool(tcp_flags & 0x01)
        is_rst = bool(tcp_flags & 0x04)
        is_psh = bool(tcp_flags & 0x08)
        is_ack = bool(tcp_flags & 0x10)

        if is_syn:
            self.syn_count += 1
            if direction == 1 and tcp_window and self.window_size_init == 0:
                self.window_size_init = tcp_window
            if direction == -1 and is_ack:
                self._has_syn_ack = True

        if is_fin:
            self.fin_count += 1
        if is_rst:
            self.rst_count += 1
            if self.first_rst_pkt_num == 0:
                self.first_rst_pkt_num = self.total_pkts

        if is_psh:
            self.psh_count += 1
            self.current_psh_run += 1
            self.max_psh_run = max(self.max_psh_run, self.current_psh_run)
        else:
            self.current_psh_run = 0

        if is_ack and not (is_syn or is_fin or is_rst or is_psh) and payload_len == 0:
            self.ack_only_count += 1

        # syn_to_data
        if not self._seen_data and payload_len > 0:
            self._seen_data = True
            self.syn_to_data_count = self.total_pkts - 1

        # Event tracking
        is_event = payload_len > 0 or is_syn or is_fin or is_rst
        if is_event:
            self.n_events += 1

        # Forward IAT (Welford)
        if direction == 1 and iat_ms is not None:
            self._iat_fwd.update(iat_ms)
            # Think time = IAT - RTT
            if self.rtt_ms is not None:
                think = max(0.0, iat_ms - self.rtt_ms)
                self._think_time.update(think)

        # Payload analysis
        if payload_len > 0:
            self.n_payload_pkts += 1

            if direction == 1:
                self._fwd_size.update(float(payload_len))
                if self.fwd_size_min is None or payload_len < self.fwd_size_min:
                    self.fwd_size_min = payload_len
                if payload_len > self.fwd_size_max:
                    self.fwd_size_max = payload_len

                # First forward payload stats
                if self._first_fwd_payload is None and payload_entropy is not None:
                    self._entropy_first = payload_entropy
                    self._first_fwd_payload = b"(recorded)"  # sentinel
                    self._first_fwd_payload_len = payload_len

                if payload_entropy is not None:
                    self._entropy_fwd.update(payload_entropy)
                    if payload_entropy >= 7.0:
                        self._fwd_high_entropy += 1
            else:
                self._rev_size.update(float(payload_len))
                if payload_len > self.rev_size_max:
                    self.rev_size_max = payload_len
                if payload_entropy is not None:
                    self._entropy_rev.update(payload_entropy)

            # Size histogram
            if 1 <= payload_len <= 63:
                self.hist_tiny += 1
            elif 64 <= payload_len <= 255:
                self.hist_small += 1
            elif 256 <= payload_len <= 1023:
                self.hist_medium += 1
            elif 1024 <= payload_len <= 1499:
                self.hist_large += 1
            elif payload_len >= 1500:
                self.hist_full += 1

            # Retransmit estimation
            self._retransmit_set.add((payload_len, direction))

    def _compute_conn_state(self) -> int:
        """Compute conn_state per spec (8 states, 0-7)."""
        if self.ip_proto != 6:
            return 7  # Non-TCP

        if self.syn_count > 1 and not self._has_syn_ack:
            return 6  # SYN flood / repeated probe
        if not self._has_syn_ack:
            return 0  # Port closed / filtered
        if self._has_syn_ack and self.n_payload_pkts == 0:
            return 1  # Port open, attacker disconnected
        if self.n_payload_pkts > 0 and self.psh_count <= 5:
            return 2 if self.fin_count > 0 else 3  # Short session
        if self.psh_count > 5:
            return 4 if self.fin_count > 0 else 5  # Extended session
        return 0

    def to_vector(
        self,
        source_stats: dict[str, Any] | None = None,
        fingerprint_stats: dict[str, Any] | None = None,
    ) -> list[float | None]:
        """Return ordered 68-feature vector.

        Args:
            source_stats: Dict with F8 source behavior keys (src_flow_count, etc.)
            fingerprint_stats: Dict with F7 fingerprint keys (ja3_freq, etc.)

        Returns:
            List of 68 float|None values in FEATURE_NAMES order.
        """
        source_stats = source_stats or {}
        fingerprint_stats = fingerprint_stats or {}

        # Duration
        duration_ms: float | None = None
        if self.first_ts is not None and self.last_ts is not None:
            duration_ms = max(0.0, (self.last_ts - self.first_ts) * 1000.0)
        duration_s = (duration_ms / 1000.0) if duration_ms is not None else 0.001

        # Volume ratios
        bytes_per_pkt_fwd = self.bytes_fwd / max(self.pkts_fwd, 1)
        bytes_per_pkt_rev = (self.bytes_rev / self.pkts_rev) if self.pkts_rev > 0 else None
        pkt_ratio = self.pkts_fwd / max(self.pkts_rev, 1)
        byte_ratio = self.bytes_fwd / max(self.bytes_rev, 1)

        # Timing
        iat_fwd_mean = self._iat_fwd.mean if self._iat_fwd.n > 0 else None
        iat_fwd_std = self._iat_fwd.std if self._iat_fwd.n >= 2 else None
        think_mean = self._think_time.mean if self._think_time.n > 0 else None
        think_std = self._think_time.std if self._think_time.n >= 2 else None
        iat_to_rtt = None
        if self.rtt_ms is not None and iat_fwd_mean is not None:
            iat_to_rtt = iat_fwd_mean / max(self.rtt_ms, 0.1)

        total_pkts = self.pkts_fwd + self.pkts_rev
        pps = total_pkts / max(duration_s, 0.001)
        bps = (self.bytes_fwd + self.bytes_rev) / max(duration_s, 0.001)

        payload_rtt_ratio = None
        if self.rtt_ms is not None and self.rtt_ms > 0 and duration_ms is not None and duration_ms > 0:
            payload_rtt_ratio = self.n_payload_pkts / max(duration_ms / self.rtt_ms, 1.0)

        # Size shape
        fwd_size_mean = self._fwd_size.mean if self._fwd_size.n > 0 else None
        fwd_size_std = self._fwd_size.std if self._fwd_size.n >= 2 else None
        fwd_size_min = self.fwd_size_min if self.fwd_size_min is not None else 0
        rev_size_mean = self._rev_size.mean if self._rev_size.n > 0 else None
        rev_size_std = self._rev_size.std if self._rev_size.n >= 2 else None
        frac_full = self.hist_full / max(self.n_events, 1)

        # TCP behavior
        conn_state = self._compute_conn_state()
        rst_frac = (self.first_rst_pkt_num / self.total_pkts) if (self.rst_count > 0 and self.total_pkts > 0) else None
        retransmit_est = max(0, len(self._retransmit_set) - self.n_events) if self._retransmit_set else 0

        # Payload content
        entropy_fwd_mean = self._entropy_fwd.mean if self._entropy_fwd.n > 0 else None
        entropy_rev_mean = self._entropy_rev.mean if self._entropy_rev.n > 0 else None
        high_entropy_frac = (self._fwd_high_entropy / self._entropy_fwd.n) if self._entropy_fwd.n > 0 else None

        # F7 fingerprint features
        ja3_freq = fingerprint_stats.get("ja3_freq")
        hassh_freq = fingerprint_stats.get("hassh_freq")
        http_ua_freq = fingerprint_stats.get("http_ua_freq")
        tls_cipher_count = fingerprint_stats.get("tls_cipher_count")
        tls_ext_count = fingerprint_stats.get("tls_ext_count")
        http_header_count = fingerprint_stats.get("http_header_count")
        dns_qname_len = fingerprint_stats.get("dns_qname_len")

        # F8 source behavior features
        src_flow_count = source_stats.get("src_flow_count")
        src_unique_ports = source_stats.get("src_unique_ports")
        src_unique_protos = source_stats.get("src_unique_protos")
        src_unique_dsts = source_stats.get("src_unique_dsts")
        src_span_min = source_stats.get("src_span_min")
        src_avg_pps = source_stats.get("src_avg_pps")
        src_port_entropy = source_stats.get("src_port_entropy")

        return [
            # F1 (3)
            float(self.dst_port),
            float(self.ip_proto),
            float(self.app_proto),
            # F2 (8)
            float(self.pkts_fwd),
            float(self.pkts_rev),
            float(self.bytes_fwd),
            float(self.bytes_rev),
            bytes_per_pkt_fwd,
            bytes_per_pkt_rev,
            pkt_ratio,
            byte_ratio,
            # F3 (10)
            duration_ms,
            self.rtt_ms,
            iat_fwd_mean,
            iat_fwd_std,
            think_mean,
            think_std,
            iat_to_rtt,
            pps,
            bps,
            payload_rtt_ratio,
            # F4 (14)
            float(self.n_events),
            fwd_size_mean,
            fwd_size_std,
            float(fwd_size_min),
            float(self.fwd_size_max),
            rev_size_mean,
            rev_size_std,
            float(self.rev_size_max),
            float(self.hist_tiny),
            float(self.hist_small),
            float(self.hist_medium),
            float(self.hist_large),
            float(self.hist_full),
            frac_full,
            # F5 (11)
            float(self.syn_count),
            float(self.fin_count),
            float(self.rst_count),
            float(self.psh_count),
            float(self.ack_only_count),
            float(conn_state),
            rst_frac,
            float(self.syn_to_data_count),
            float(self.max_psh_run),
            float(retransmit_est),
            float(self.window_size_init),
            # F6 (8)
            self._entropy_first,
            entropy_fwd_mean,
            entropy_rev_mean,
            self._printable_frac,
            self._null_frac,
            self._byte_std,
            high_entropy_frac,
            float(self._first_fwd_payload_len),
            # F7 (7)
            ja3_freq,
            hassh_freq,
            http_ua_freq,
            tls_cipher_count,
            tls_ext_count,
            http_header_count,
            dns_qname_len,
            # F8 (7)
            src_flow_count,
            src_unique_ports,
            src_unique_protos,
            src_unique_dsts,
            src_span_min,
            src_avg_pps,
            src_port_entropy,
        ]

    def confidence(self) -> float:
        """Return 0.0-1.0 based on feature completeness (non-None / total)."""
        vec = self.to_vector()
        non_none = sum(1 for v in vec if v is not None)
        return non_none / _TOTAL_FEATURES

    def set_first_payload_stats(
        self,
        printable_frac: float | None,
        null_frac: float | None,
        byte_std: float | None,
    ) -> None:
        """Set first-payload content stats (called externally with raw bytes)."""
        self._printable_frac = printable_frac
        self._null_frac = null_frac
        self._byte_std = byte_std
