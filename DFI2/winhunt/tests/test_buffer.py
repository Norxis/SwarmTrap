"""Unit tests for SQLite buffer."""
from __future__ import annotations

import os
import tempfile
import unittest

from dfi_agent.buffer import AgentBuffer


class TestAgentBuffer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.buf = AgentBuffer(self.tmp.name, vm_id="test-vm")

    def tearDown(self):
        self.buf.close()
        os.unlink(self.tmp.name)
        for ext in ("-wal", "-shm"):
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def test_insert_and_get_event(self):
        self.buf.insert_event(
            ts=1000.0, vm_id="test", source_ip="1.2.3.4",
            source_port=0, service="rdp", event_type="auth_failure",
            evidence_bits=0x01, raw_event_id=4625, raw_channel="Security",
            detail={"user": "admin"},
        )
        rows = self.buf.get_events(pulled=0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_type"], "auth_failure")
        self.assertEqual(rows[0]["evidence_bits"], 1)

    def test_ack_events(self):
        self.buf.insert_event(
            ts=1000.0, vm_id="test", source_ip="1.2.3.4",
            source_port=0, service="rdp", event_type="auth_failure",
            evidence_bits=0x01, raw_event_id=4625, raw_channel="Security",
            detail=None,
        )
        rows = self.buf.get_events(pulled=0)
        self.assertEqual(len(rows), 1)
        self.buf.ack_events(rows[0]["seq"])
        self.assertEqual(len(self.buf.get_events(pulled=0)), 0)
        self.assertEqual(len(self.buf.get_events(pulled=1)), 1)

    def test_insert_and_get_flow(self):
        flow = {
            "flow_id": "test-flow-1", "session_key": "abc123",
            "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1",
            "src_port": 12345, "dst_port": 3389,
            "ip_proto": 6, "app_proto": 8,
            "first_ts": "2025-01-01T00:00:00.000Z",
            "last_ts": "2025-01-01T00:00:01.000Z",
            "pkts_fwd": 10, "pkts_rev": 5,
            "bytes_fwd": 5000, "bytes_rev": 2000,
            "rtt_ms": 50.0, "duration_ms": 1000,
            "iat_fwd_mean_ms": 100.0, "iat_fwd_std_ms": 10.0,
            "think_time_mean_ms": 50.0, "think_time_std_ms": 5.0,
            "iat_to_rtt": 2.0, "pps": 15.0, "bps": 7000.0,
            "payload_rtt_ratio": 0.5,
            "n_events": 10,
            "fwd_size_mean": 200.0, "fwd_size_std": 50.0,
            "fwd_size_min": 100, "fwd_size_max": 300,
            "rev_size_mean": 550.0, "rev_size_std": 50.0,
            "rev_size_max": 600,
            "hist_tiny": 2, "hist_small": 3, "hist_medium": 3,
            "hist_large": 1, "hist_full": 1, "frac_full": 0.1,
            "syn_count": 1, "fin_count": 1, "rst_count": 0,
            "psh_count": 7, "ack_only_count": 3,
            "conn_state": 4, "rst_frac": None,
            "syn_to_data": 2, "psh_burst_max": 3,
            "retransmit_est": 0, "window_size_init": 65535,
            "entropy_first": 4.5, "entropy_fwd_mean": 4.2,
            "entropy_rev_mean": 5.1,
            "printable_frac": 0.8, "null_frac": 0.02,
            "byte_std": 45.0, "high_entropy_frac": 0.1,
            "payload_len_first": 48,
            "capture_source": 1,
        }
        self.buf.insert_flow(flow)
        rows = self.buf.get_flows(pulled=0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["flow_id"], "test-flow-1")
        self.assertEqual(rows[0]["pkts_fwd"], 10)
        self.assertEqual(rows[0]["hist_tiny"], 2)

    def test_atomic_ack_flows(self):
        """Acking flows should also ack packets and fingerprints."""
        flow = {"flow_id": "f1", "session_key": "s1",
                "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                "src_port": 1, "dst_port": 2, "ip_proto": 6,
                "app_proto": 0,
                "first_ts": "2025-01-01T00:00:00Z", "last_ts": "2025-01-01T00:00:01Z",
                "pkts_fwd": 1, "pkts_rev": 0, "bytes_fwd": 100, "bytes_rev": 0,
                "rtt_ms": None, "duration_ms": 1000,
                "iat_fwd_mean_ms": None, "iat_fwd_std_ms": None,
                "think_time_mean_ms": None, "think_time_std_ms": None,
                "iat_to_rtt": None, "pps": 1.0, "bps": 100.0,
                "payload_rtt_ratio": None, "n_events": 1,
                "fwd_size_mean": None, "fwd_size_std": None,
                "fwd_size_min": 0, "fwd_size_max": 0,
                "rev_size_mean": None, "rev_size_std": None, "rev_size_max": 0,
                "hist_tiny": 0, "hist_small": 0, "hist_medium": 0,
                "hist_large": 0, "hist_full": 0, "frac_full": 0,
                "syn_count": 1, "fin_count": 0, "rst_count": 0,
                "psh_count": 0, "ack_only_count": 0, "conn_state": 0,
                "rst_frac": None, "syn_to_data": 0, "psh_burst_max": 0,
                "retransmit_est": 0, "window_size_init": 0,
                "entropy_first": None, "entropy_fwd_mean": None,
                "entropy_rev_mean": None, "printable_frac": None,
                "null_frac": None, "byte_std": None,
                "high_entropy_frac": None, "payload_len_first": 0,
                "capture_source": 1}
        self.buf.insert_flow(flow)
        pkt = {"flow_id": "f1", "seq_idx": 0, "ts": "2025-01-01T00:00:00Z",
               "direction": 1, "payload_len": 0, "pkt_len": 40,
               "tcp_flags": 2, "tcp_window": 65535,
               "size_dir_token": 1, "flag_token": 1,
               "iat_log_ms_bin": 1, "iat_rtt_bin": 1,
               "entropy_bin": 0, "iat_ms": None, "payload_entropy": None}
        self.buf.insert_packets([pkt])
        fp = {"flow_id": "f1", "ja3_hash": None, "tls_version": 0,
              "tls_cipher_count": 0, "tls_ext_count": 0, "tls_has_sni": 0,
              "hassh_hash": None, "ssh_kex_count": 0,
              "http_method": 0, "http_uri_len": 0, "http_header_count": 0,
              "http_ua_hash": None, "http_has_body": 0, "http_status": 0,
              "dns_qtype": 0, "dns_qname_len": 0}
        self.buf.insert_fingerprint(fp)

        # Before ack
        self.assertEqual(self.buf.get_flow_count(pulled=0), 1)
        self.assertEqual(self.buf.packet_count(pulled=0), 1)
        self.assertEqual(self.buf.fingerprint_count(pulled=0), 1)

        # Ack
        self.buf.ack_flows(["f1"])

        # After ack — all three tables updated atomically
        self.assertEqual(self.buf.get_flow_count(pulled=0), 0)
        self.assertEqual(self.buf.packet_count(pulled=0), 0)
        self.assertEqual(self.buf.fingerprint_count(pulled=0), 0)

    def test_logon_map(self):
        self.buf.upsert_logon("0x1234", "1.2.3.4", "rdp")
        result = self.buf.lookup_logon("0x1234")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "1.2.3.4")
        self.assertEqual(result[1], "rdp")

    def test_logon_map_miss(self):
        self.assertIsNone(self.buf.lookup_logon("nonexistent"))


if __name__ == "__main__":
    unittest.main()
