"""Unit tests for inference feature accumulator."""
from __future__ import annotations

import math
import statistics
import unittest


class _WelfordAccumulator:
    """Welford's online algorithm for streaming mean and std.

    This mirrors the accumulator's internal statistics logic for
    progressive feature computation.
    """

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self._m2 = 0.0

    def update(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self._m2 += delta * delta2

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self._m2 / self.n)

    @property
    def variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self._m2 / self.n


class _FeatureAccumulator:
    """Simplified feature accumulator for testing.

    Tracks 68 features across flow identity, volume, timing,
    size shape, TCP behavior, and payload content categories.
    """

    # Feature groups and counts matching the spec
    FEATURE_COUNT = 68

    def __init__(self) -> None:
        self.pkts_fwd = 0
        self.pkts_rev = 0
        self.bytes_fwd = 0
        self.bytes_rev = 0
        self.duration_ms = 0
        self._iat_acc = _WelfordAccumulator()
        self._fwd_size_acc = _WelfordAccumulator()
        self._rev_size_acc = _WelfordAccumulator()
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.total_observations = 0
        self._evidence_bits = 0

    def add_packet(self, direction: int, size: int, flags: int = 0,
                   iat_ms: float = 0.0) -> None:
        if direction == 1:
            self.pkts_fwd += 1
            self.bytes_fwd += size
            self._fwd_size_acc.update(float(size))
        else:
            self.pkts_rev += 1
            self.bytes_rev += size
            self._rev_size_acc.update(float(size))
        if iat_ms > 0:
            self._iat_acc.update(iat_ms)

    def add_observation(self, evidence_bits: int) -> None:
        self.total_observations += 1
        self._evidence_bits |= evidence_bits

    def confidence(self) -> float:
        """Confidence = observations / (observations + remaining_needed).

        More observations -> higher confidence.
        """
        if self.total_observations == 0:
            return 0.0
        # Assume we need at least 10 observations for full confidence
        return min(1.0, self.total_observations / 10.0)

    def to_vector(self) -> list[float]:
        """Return a fixed-length feature vector (68 features).

        Feature layout:
          F1: Identity (3): dst_port, ip_proto, app_proto
          F2: Volume (8): pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
                          bytes_per_pkt_fwd, bytes_per_pkt_rev, pkt_ratio, byte_ratio
          F3: Timing (10): duration_ms, rtt_ms, iat_fwd_mean_ms, iat_fwd_std_ms,
                           think_time_mean_ms, think_time_std_ms, iat_to_rtt,
                           pps, bps, payload_rtt_ratio
          F4: Size Shape (14): n_events, fwd_size_mean, fwd_size_std,
                               fwd_size_min, fwd_size_max, rev_size_mean, rev_size_std,
                               rev_size_max, hist_tiny..hist_full (5), frac_full
          F5: TCP Behavior (11): syn_count..window_size_init
          F6: Payload Content (8): entropy_first..payload_len_first
          F7: Fingerprint (14): ja3, tls, ssh, http, dns fields
          Total: 3 + 8 + 10 + 14 + 11 + 8 + 14 = 68
        """
        vec = [0.0] * self.FEATURE_COUNT

        # F1: Identity
        vec[0] = 0.0   # dst_port (placeholder)
        vec[1] = 6.0   # ip_proto (TCP)
        vec[2] = 0.0   # app_proto

        # F2: Volume
        vec[3] = float(self.pkts_fwd)
        vec[4] = float(self.pkts_rev)
        vec[5] = float(self.bytes_fwd)
        vec[6] = float(self.bytes_rev)
        vec[7] = self.bytes_fwd / max(self.pkts_fwd, 1)
        vec[8] = self.bytes_rev / max(self.pkts_rev, 1)
        vec[9] = self.pkts_fwd / max(self.pkts_rev, 1)
        vec[10] = self.bytes_fwd / max(self.bytes_rev, 1)

        # F3: Timing
        vec[11] = float(self.duration_ms)
        vec[12] = 0.0  # rtt_ms
        vec[13] = self._iat_acc.mean if self._iat_acc.n > 0 else 0.0
        vec[14] = self._iat_acc.std

        # Fill remaining with 0.0 (think_time, pps, bps, etc.)
        # ... (positions 15-20)

        # F4: Size Shape (positions 21-34)
        vec[21] = float(self.total_observations)
        vec[22] = self._fwd_size_acc.mean if self._fwd_size_acc.n > 0 else 0.0
        vec[23] = self._fwd_size_acc.std

        # F5: TCP Behavior (positions 35-45)
        vec[35] = float(self.syn_count)
        vec[36] = float(self.fin_count)
        vec[37] = float(self.rst_count)
        vec[38] = float(self.psh_count)

        # Remaining features are 0.0 (fingerprints, etc.)
        return vec


class TestFeatureAccumulator(unittest.TestCase):
    def test_feature_count(self):
        """to_vector should return exactly 68 features."""
        acc = _FeatureAccumulator()
        # Add some data
        acc.add_packet(1, 100, iat_ms=10.0)
        acc.add_packet(0, 200, iat_ms=20.0)
        acc.add_packet(1, 150, iat_ms=15.0)

        vec = acc.to_vector()
        self.assertEqual(len(vec), 68)

    def test_welford_mean_std(self):
        """Welford's algorithm should match the statistics module."""
        values = [10.0, 20.0, 30.0, 25.0, 15.0, 35.0, 5.0, 40.0]

        acc = _WelfordAccumulator()
        for v in values:
            acc.update(v)

        expected_mean = statistics.mean(values)
        expected_std = statistics.pstdev(values)

        self.assertAlmostEqual(acc.mean, expected_mean, places=10)
        self.assertAlmostEqual(acc.std, expected_std, places=10)

    def test_confidence(self):
        """confidence() should return correct ratio."""
        acc = _FeatureAccumulator()
        self.assertEqual(acc.confidence(), 0.0)

        # Add 5 observations -> 0.5 confidence
        for _ in range(5):
            acc.add_observation(0x01)
        self.assertAlmostEqual(acc.confidence(), 0.5)

        # Add 5 more -> 1.0 confidence (capped)
        for _ in range(5):
            acc.add_observation(0x02)
        self.assertAlmostEqual(acc.confidence(), 1.0)

        # Adding more doesn't exceed 1.0
        for _ in range(10):
            acc.add_observation(0x04)
        self.assertAlmostEqual(acc.confidence(), 1.0)

    def test_welford_single_value(self):
        """Single value should have mean=value, std=0."""
        acc = _WelfordAccumulator()
        acc.update(42.0)
        self.assertEqual(acc.mean, 42.0)
        self.assertEqual(acc.std, 0.0)

    def test_welford_identical_values(self):
        """Identical values should have std=0."""
        acc = _WelfordAccumulator()
        for _ in range(100):
            acc.update(7.5)
        self.assertAlmostEqual(acc.mean, 7.5)
        self.assertAlmostEqual(acc.std, 0.0, places=10)


if __name__ == "__main__":
    unittest.main()
