#!/usr/bin/env python3
import unittest
from types import SimpleNamespace

from hunter.tokenizer import tokenize_packets


class TestTokenizer(unittest.TestCase):
    def test_bins_and_ranges(self):
        events = [
            SimpleNamespace(ts=1.0, direction=1, payload_len=0, pkt_len=60, tcp_flags=0x02, tcp_window=0, payload_head=b'', is_tcp=True),
            SimpleNamespace(ts=1.001, direction=1, payload_len=50, pkt_len=90, tcp_flags=0x18, tcp_window=0, payload_head=b'A' * 50, is_tcp=True),
            SimpleNamespace(ts=2.0, direction=-1, payload_len=100, pkt_len=140, tcp_flags=0x10, tcp_window=0, payload_head=bytes(range(100)), is_tcp=True),
        ]
        out = tokenize_packets(events, rtt_ms=10.0)
        self.assertEqual(len(out), 3)
        self.assertTrue(-11 <= out[1]['size_dir_token'] <= 11)
        self.assertTrue(1 <= out[1]['iat_log_ms_bin'] <= 8)
        self.assertTrue(1 <= out[1]['iat_rtt_bin'] <= 9)
        self.assertTrue(1 <= out[1]['entropy_bin'] <= 6)

    def test_rtt_unknown_uses_bin1(self):
        events = [SimpleNamespace(ts=1.0, direction=1, payload_len=10, pkt_len=50, tcp_flags=0, tcp_window=0, payload_head=b'1234567890', is_tcp=False)]
        out = tokenize_packets(events, rtt_ms=None)
        self.assertEqual(out[0]['iat_rtt_bin'], 1)
        self.assertEqual(out[0]['flag_token'], 16)


if __name__ == '__main__':
    unittest.main()
