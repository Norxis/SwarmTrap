#!/usr/bin/env python3
import unittest
from types import SimpleNamespace

from hunter.features import extract_features


class TestFeatures(unittest.TestCase):
    def test_udp_no_payload(self):
        s = SimpleNamespace(
            src_port=12345,
            dst_port=53,
            ip_proto=17,
            first_ts=1000.0,
            last_ts=1001.0,
            pkts_fwd=1,
            pkts_rev=1,
            bytes_fwd=0,
            bytes_rev=0,
            events=[],
            fwd_timestamps=[1000.0],
            fwd_payload_sizes=[],
            rev_payload_sizes=[],
            syn_count=0,
            fin_count=0,
            rst_count=0,
            psh_count=0,
            ack_only_count=0,
            synack_seen=False,
            first_rst_index=None,
            first_syn_index=None,
            first_payload_index=None,
            psh_burst_max=0,
            retransmit_est=0,
            window_size_init=0,
            n_payload_pkts=0,
            first_fwd_payload=None,
            fwd_payload_entropy=[],
            rev_payload_entropy=[],
        )
        f = extract_features(s)
        self.assertEqual(f['ip_proto'], 17)
        self.assertEqual(f['conn_state'], 7)
        self.assertIsNone(f['rtt_ms'])
        self.assertEqual(f['payload_len_first'], 0)

    def test_tcp_with_rtt_and_entropy(self):
        ev = [
            SimpleNamespace(ts=1.0, direction=1, tcp_flags=0x02),
            SimpleNamespace(ts=1.05, direction=-1, tcp_flags=0x12),
            SimpleNamespace(ts=1.06, direction=1, tcp_flags=0x18),
        ]
        s = SimpleNamespace(
            src_port=50000,
            dst_port=22,
            ip_proto=6,
            first_ts=1.0,
            last_ts=2.0,
            pkts_fwd=3,
            pkts_rev=1,
            bytes_fwd=90,
            bytes_rev=50,
            events=ev,
            fwd_timestamps=[1.0, 1.06, 1.5],
            fwd_payload_sizes=[30, 60],
            rev_payload_sizes=[50],
            syn_count=1,
            fin_count=0,
            rst_count=0,
            psh_count=1,
            ack_only_count=0,
            synack_seen=True,
            first_rst_index=None,
            first_syn_index=1,
            first_payload_index=3,
            psh_burst_max=1,
            retransmit_est=0,
            window_size_init=0,
            n_payload_pkts=2,
            first_fwd_payload=b'GET / HTTP/1.1',
            fwd_payload_entropy=[4.0, 7.2],
            rev_payload_entropy=[6.8],
        )
        f = extract_features(s)
        self.assertIsNotNone(f['rtt_ms'])
        self.assertGreater(f['iat_to_rtt'], 0)
        self.assertGreaterEqual(f['high_entropy_frac'], 0.5)


if __name__ == '__main__':
    unittest.main()
