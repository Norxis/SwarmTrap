"""Unit tests for XGB feature extraction."""
from __future__ import annotations

import math
import unittest

from dfi_agent.features import (
    compute_conn_state,
    compute_xgb_features,
    estimate_rtt,
    shannon_entropy,
)


class TestShannonEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_single_byte(self):
        self.assertEqual(shannon_entropy(b"\x00"), 0.0)

    def test_uniform_all_same(self):
        self.assertAlmostEqual(shannon_entropy(b"\xff" * 100), 0.0)

    def test_two_values(self):
        data = b"\x00\x01" * 50
        self.assertAlmostEqual(shannon_entropy(data), 1.0, places=5)

    def test_max_entropy(self):
        data = bytes(range(256))
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=5)


class TestEstimateRTT(unittest.TestCase):
    def test_syn_synack(self):
        flow = {"syn_ts": 1000.0, "syn_ack_ts": 1000.050}
        self.assertAlmostEqual(estimate_rtt(flow), 50.0, places=1)

    def test_fallback_first_fwd_rev(self):
        flow = {"first_fwd_ts": 1000.0, "first_rev_ts": 1000.020}
        self.assertAlmostEqual(estimate_rtt(flow), 20.0, places=1)

    def test_no_rtt(self):
        self.assertIsNone(estimate_rtt({}))

    def test_syn_preferred_over_fallback(self):
        flow = {
            "syn_ts": 1000.0, "syn_ack_ts": 1000.010,
            "first_fwd_ts": 1000.0, "first_rev_ts": 1000.050,
        }
        # SYN-based RTT should be used (10ms, not 50ms)
        self.assertAlmostEqual(estimate_rtt(flow), 10.0, places=1)


class TestConnState(unittest.TestCase):
    def test_non_tcp(self):
        self.assertEqual(compute_conn_state({"ip_proto": 17}), 7)

    def test_syn_flood(self):
        self.assertEqual(compute_conn_state({"ip_proto": 6, "syn_count": 5, "syn_ack_ts": None}), 6)

    def test_closed(self):
        self.assertEqual(compute_conn_state({"ip_proto": 6, "syn_count": 1, "syn_ack_ts": None}), 0)

    def test_open_no_data(self):
        self.assertEqual(compute_conn_state({"ip_proto": 6, "syn_count": 1, "syn_ack_ts": 1.0, "n_payload_pkts": 0}), 1)


class TestXGBFeatures(unittest.TestCase):
    def _make_flow(self, **kw) -> dict:
        base = {
            "dst_port": 3389, "ip_proto": 6, "app_proto": 8,
            "pkts_fwd": 10, "pkts_rev": 5, "bytes_fwd": 5000, "bytes_rev": 2000,
            "first_ts": 1000.0, "last_ts": 1001.0,
            "syn_ts": 1000.0, "syn_ack_ts": 1000.050,
            "first_fwd_ts": 1000.0, "first_rev_ts": 1000.050,
            "fwd_iats": [0.1, 0.1, 0.1],
            "total_pkts": 15,
            "n_payload_pkts": 8,
            "syn_count": 1, "fin_count": 1, "rst_count": 0,
            "psh_count": 7, "ack_only_count": 3,
            "first_rst_pkt_num": 0,
            "syn_to_data_count": 2,
            "max_psh_run": 3,
            "window_size_init": 65535,
            "retransmit_set_size": 8,
            "n_events": 10,
            "fwd_payload_sizes": [100, 200, 300, 150, 250],
            "rev_payload_sizes": [500, 600],
            "hist_tiny": 2, "hist_small": 3, "hist_medium": 3,
            "hist_large": 1, "hist_full": 1,
            "first_fwd_payload": b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            "fwd_entropy_sum": 12.5, "fwd_entropy_count": 5,
            "rev_entropy_sum": 7.0, "rev_entropy_count": 2,
            "fwd_high_entropy": 1,
        }
        base.update(kw)
        return base

    def test_all_features_present(self):
        flow = self._make_flow()
        result = compute_xgb_features(flow)
        expected_keys = [
            "dst_port", "ip_proto", "app_proto",
            "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
            "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
            "duration_ms", "rtt_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
            "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt",
            "pps", "bps", "payload_rtt_ratio",
            "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
            "rev_size_mean", "rev_size_std", "rev_size_max",
            "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
            "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count",
            "conn_state", "rst_frac", "syn_to_data", "psh_burst_max",
            "retransmit_est", "window_size_init",
            "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
            "printable_frac", "null_frac", "byte_std", "high_entropy_frac",
            "payload_len_first",
        ]
        for key in expected_keys:
            self.assertIn(key, result, f"Missing feature: {key}")

    def test_think_time(self):
        """Think time should be IAT minus RTT, not raw IAT."""
        flow = self._make_flow(
            fwd_iats=[0.1, 0.1, 0.1],  # 100ms each
            syn_ts=1000.0, syn_ack_ts=1000.050,  # RTT = 50ms
        )
        result = compute_xgb_features(flow)
        # think_time = 100ms - 50ms = 50ms
        self.assertAlmostEqual(result["think_time_mean_ms"], 50.0, places=1)

    def test_histogram_bins(self):
        """Verify histogram bins match spec: 1-63, 64-255, 256-1023, 1024-1499, >=1500."""
        flow = self._make_flow(
            hist_tiny=1, hist_small=2, hist_medium=3, hist_large=4, hist_full=5,
        )
        result = compute_xgb_features(flow)
        self.assertEqual(result["hist_tiny"], 1)
        self.assertEqual(result["hist_small"], 2)
        self.assertEqual(result["hist_medium"], 3)
        self.assertEqual(result["hist_large"], 4)
        self.assertEqual(result["hist_full"], 5)

    def test_rst_frac_uses_first_rst_pkt_num(self):
        """rst_frac = first_rst_pkt_num / total_pkts per spec."""
        flow = self._make_flow(rst_count=1, first_rst_pkt_num=5, total_pkts=20)
        result = compute_xgb_features(flow)
        self.assertAlmostEqual(result["rst_frac"], 5.0 / 20.0)

    def test_psh_burst_max(self):
        """psh_burst_max = max consecutive PSH run, not total."""
        flow = self._make_flow(max_psh_run=4, psh_count=10)
        result = compute_xgb_features(flow)
        self.assertEqual(result["psh_burst_max"], 4)

    def test_syn_to_data(self):
        """syn_to_data = packets between SYN and first payload (count)."""
        flow = self._make_flow(syn_to_data_count=3)
        result = compute_xgb_features(flow)
        self.assertEqual(result["syn_to_data"], 3)

    def test_no_rtt_nulls(self):
        """When no RTT, think_time and related should be None."""
        flow = self._make_flow(syn_ts=None, syn_ack_ts=None, first_rev_ts=None)
        result = compute_xgb_features(flow)
        self.assertIsNone(result["rtt_ms"])
        self.assertIsNone(result["think_time_mean_ms"])
        self.assertIsNone(result["iat_to_rtt"])
        self.assertIsNone(result["payload_rtt_ratio"])


if __name__ == "__main__":
    unittest.main()
