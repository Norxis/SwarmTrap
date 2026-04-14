"""Unit tests for CNN tokenizer."""
from __future__ import annotations

import unittest

from dfi_agent.tokenizer import (
    entropy_bin,
    flag_token,
    iat_log_ms_bin,
    iat_rtt_bin,
    size_dir_token,
)


class TestSizeDirToken(unittest.TestCase):
    def test_small_forward(self):
        """1-63 bytes → bin 1, forward → +1."""
        pkt = {"payload_len": 32, "pkt_len": 52, "direction": 1}
        # log2(32)=5, raw_bin=5, b=min(11,max(1,5-4))=1
        self.assertEqual(size_dir_token(pkt), 1)

    def test_medium_reverse(self):
        """256-511 bytes → bin 4, reverse → -4."""
        pkt = {"payload_len": 300, "pkt_len": 340, "direction": -1}
        # log2(300)≈8.2, floor=8, b=min(11,max(1,8-4))=4
        self.assertEqual(size_dir_token(pkt), -4)

    def test_zero_payload_uses_pkt_len(self):
        pkt = {"payload_len": 0, "pkt_len": 64, "direction": 1}
        # log2(64)=6, b=min(11,max(1,6-4))=2
        self.assertEqual(size_dir_token(pkt), 2)


class TestFlagToken(unittest.TestCase):
    def test_syn(self):
        self.assertEqual(flag_token({"tcp_flags": 0x02}), 1)

    def test_syn_ack(self):
        self.assertEqual(flag_token({"tcp_flags": 0x12}), 1)  # SYN bit only in token

    def test_fin(self):
        self.assertEqual(flag_token({"tcp_flags": 0x01}), 2)

    def test_rst(self):
        self.assertEqual(flag_token({"tcp_flags": 0x04}), 4)

    def test_psh(self):
        self.assertEqual(flag_token({"tcp_flags": 0x08}), 8)

    def test_ack_only(self):
        """Pure ACK → PRESENT token (16)."""
        self.assertEqual(flag_token({"tcp_flags": 0x10}), 16)

    def test_syn_fin(self):
        self.assertEqual(flag_token({"tcp_flags": 0x03}), 3)


class TestIATLogBin(unittest.TestCase):
    def test_first_packet(self):
        self.assertEqual(iat_log_ms_bin(0, None), 1)

    def test_wire_speed(self):
        self.assertEqual(iat_log_ms_bin(1, 0.5), 2)

    def test_fast_tool(self):
        self.assertEqual(iat_log_ms_bin(1, 5.0), 3)

    def test_lan_rtt(self):
        self.assertEqual(iat_log_ms_bin(1, 50.0), 4)

    def test_wan_rtt(self):
        self.assertEqual(iat_log_ms_bin(1, 500.0), 5)

    def test_slow_tool(self):
        self.assertEqual(iat_log_ms_bin(1, 5000.0), 6)

    def test_interactive(self):
        self.assertEqual(iat_log_ms_bin(1, 30000.0), 7)

    def test_long_idle(self):
        self.assertEqual(iat_log_ms_bin(1, 120000.0), 8)


class TestIATRTTBin(unittest.TestCase):
    def test_first_packet(self):
        self.assertEqual(iat_rtt_bin(0, 50.0, 50.0), 1)

    def test_no_rtt(self):
        self.assertEqual(iat_rtt_bin(1, 50.0, None), 1)

    def test_pipelining(self):
        self.assertEqual(iat_rtt_bin(1, 10.0, 50.0), 2)  # ratio=0.2

    def test_lockstep(self):
        self.assertEqual(iat_rtt_bin(1, 40.0, 50.0), 3)  # ratio=0.8

    def test_slightly_paced(self):
        self.assertEqual(iat_rtt_bin(1, 75.0, 50.0), 4)  # ratio=1.5

    def test_rate_limited(self):
        self.assertEqual(iat_rtt_bin(1, 150.0, 50.0), 5)  # ratio=3.0

    def test_slow_tool(self):
        self.assertEqual(iat_rtt_bin(1, 500.0, 50.0), 6)  # ratio=10

    def test_long_pause(self):
        self.assertEqual(iat_rtt_bin(1, 2500.0, 50.0), 7)  # ratio=50

    def test_very_long(self):
        self.assertEqual(iat_rtt_bin(1, 25000.0, 50.0), 8)  # ratio=500

    def test_session_idle(self):
        self.assertEqual(iat_rtt_bin(1, 100000.0, 50.0), 9)  # ratio=2000


class TestEntropyBin(unittest.TestCase):
    def test_no_payload(self):
        self.assertEqual(entropy_bin(None), 0)
        self.assertEqual(entropy_bin(b""), 0)

    def test_constant(self):
        self.assertEqual(entropy_bin(b"\x00" * 100), 1)

    def test_near_random(self):
        self.assertEqual(entropy_bin(bytes(range(256))), 6)


if __name__ == "__main__":
    unittest.main()
