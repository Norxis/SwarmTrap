"""Unit tests for the socket monitor eye sensor."""
from __future__ import annotations

import threading
import unittest
from unittest.mock import MagicMock, patch

from dfi_agent.evidence_bits import (
    LATERAL_MOVEMENT as LATERAL_MOVEMENT_BIT,
    OUTBOUND_C2,
    SUSPICIOUS_COMMAND as SUSPICIOUS_COMMAND_BIT,
)
from dfi_agent.eyes.socket_monitor import (
    SocketMonitor, _parse_conn_line,
    _is_system_listener, _is_excluded_process,
)


def _make_ps_output(connections: list[dict]) -> str:
    """Build fake PowerShell pipe-delimited connection output (7 fields)."""
    lines = []
    for c in connections:
        pname = c.get("process_name", "unknown")
        lines.append(
            f"{c['local_addr']}|{c['local_port']}|"
            f"{c['remote_addr']}|{c['remote_port']}|"
            f"{c['state']}|{c['pid']}|{pname}"
        )
    return "\n".join(lines) + "\n"


class TestSocketMonitor(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.vm_id = "test-vm"
        self.config.mgmt_nic_ip = "172.16.3.160"
        self.config.honeypot_ports.return_value = {3389, 445, 5985, 1433, 80, 443}
        self.config.pcap.local_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        self.config.local_ips = {"127.0.0.1", "172.16.3.160"}
        self.buffer = MagicMock()
        self.stop_event = threading.Event()
        self.monitor = SocketMonitor(self.config, self.buffer, self.stop_event)

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_new_listener_detection(self, mock_run):
        """New listening port from non-system process should trigger alert."""
        connections = [
            {"local_addr": "0.0.0.0", "local_port": 9999, "remote_addr": "0.0.0.0",
             "remote_port": 0, "state": "Listen", "pid": 4444, "process_name": "backdoor"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()

        self.assertTrue(self.buffer.insert_observation.called)
        call_kwargs = self.buffer.insert_observation.call_args.kwargs
        self.assertEqual(call_kwargs["evidence_bits"], SUSPICIOUS_COMMAND_BIT)
        self.assertEqual(call_kwargs["obs_type"], "network_listener")

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_outbound_c2(self, mock_run):
        """Outbound from non-system process to external IP should trigger C2."""
        connections = [
            {"local_addr": "172.16.3.160", "local_port": 54321,
             "remote_addr": "8.8.8.8", "remote_port": 443,
             "state": "Established", "pid": 5555, "process_name": "evil"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()

        self.assertTrue(self.buffer.insert_observation.called)
        call_kwargs = self.buffer.insert_observation.call_args.kwargs
        self.assertEqual(call_kwargs["evidence_bits"], OUTBOUND_C2)
        self.assertEqual(call_kwargs["obs_type"], "outbound_connection")

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_lateral_movement(self, mock_run):
        """Outbound from non-system process to internal IP should trigger lateral."""
        connections = [
            {"local_addr": "172.16.3.160", "local_port": 54322,
             "remote_addr": "172.16.3.200", "remote_port": 445,
             "state": "Established", "pid": 6666, "process_name": "ssh"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()

        self.assertTrue(self.buffer.insert_observation.called)
        call_kwargs = self.buffer.insert_observation.call_args.kwargs
        self.assertEqual(call_kwargs["evidence_bits"], LATERAL_MOVEMENT_BIT)
        self.assertEqual(call_kwargs["obs_type"], "lateral_movement")

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_honeypot_listener_ignored(self, mock_run):
        """Listener on a honeypot port should NOT trigger an alert."""
        connections = [
            {"local_addr": "0.0.0.0", "local_port": 3389, "remote_addr": "0.0.0.0",
             "remote_port": 0, "state": "Listen", "pid": 1234, "process_name": "svchost"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()
        self.assertFalse(self.buffer.insert_observation.called)

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_system_listener_ignored(self, mock_run):
        """RPC/NetBIOS listeners from system processes should NOT trigger."""
        connections = [
            # RPC Endpoint Mapper
            {"local_addr": "0.0.0.0", "local_port": 135, "remote_addr": "0.0.0.0",
             "remote_port": 0, "state": "Listen", "pid": 1272, "process_name": "svchost"},
            # NetBIOS
            {"local_addr": "172.16.3.160", "local_port": 139, "remote_addr": "0.0.0.0",
             "remote_port": 0, "state": "Listen", "pid": 4, "process_name": "system"},
            # RPC dynamic port from lsass
            {"local_addr": "0.0.0.0", "local_port": 49664, "remote_addr": "0.0.0.0",
             "remote_port": 0, "state": "Listen", "pid": 916, "process_name": "lsass"},
            # RPC dynamic port from services.exe
            {"local_addr": "0.0.0.0", "local_port": 49670, "remote_addr": "0.0.0.0",
             "remote_port": 0, "state": "Listen", "pid": 676, "process_name": "services"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()
        self.assertFalse(self.buffer.insert_observation.called)

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_system_outbound_ignored(self, mock_run):
        """Outbound from svchost/telemetry processes should NOT trigger C2."""
        connections = [
            # svchost to Windows Update
            {"local_addr": "172.16.3.160", "local_port": 49700,
             "remote_addr": "20.59.87.226", "remote_port": 443,
             "state": "Established", "pid": 3312, "process_name": "svchost"},
            # StartMenu to Microsoft
            {"local_addr": "172.16.3.160", "local_port": 49743,
             "remote_addr": "52.110.19.167", "remote_port": 443,
             "state": "Established", "pid": 6392, "process_name": "startmenuexperiencehost"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()
        self.assertFalse(self.buffer.insert_observation.called)

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_meshcentral_lateral_ignored(self, mock_run):
        """MeshAgent connecting to MeshCentral server should NOT trigger lateral."""
        connections = [
            {"local_addr": "172.16.3.160", "local_port": 10224,
             "remote_addr": "172.16.3.112", "remote_port": 443,
             "state": "Established", "pid": 3208, "process_name": "meshagent"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()
        self.assertFalse(self.buffer.insert_observation.called)

    @patch("dfi_agent.eyes.socket_monitor.subprocess.run")
    def test_inbound_to_honeypot_ignored(self, mock_run):
        """Inbound connection to our WinRM port should NOT trigger lateral."""
        connections = [
            {"local_addr": "172.16.3.160", "local_port": 5985,
             "remote_addr": "172.16.3.174", "remote_port": 57148,
             "state": "Established", "pid": 4, "process_name": "system"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_make_ps_output(connections), stderr="")

        self.monitor._poll()
        self.assertFalse(self.buffer.insert_observation.called)


class TestParseConnLine(unittest.TestCase):
    def test_valid_7_field_line(self):
        line = "0.0.0.0|8080|1.2.3.4|443|Established|1234|python"
        result = _parse_conn_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["local_port"], 8080)
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["process_name"], "python")

    def test_valid_6_field_line(self):
        """Backward compat — 6 fields should still parse with unknown process."""
        line = "0.0.0.0|8080|1.2.3.4|443|Established|1234"
        result = _parse_conn_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["process_name"], "unknown")

    def test_short_line(self):
        result = _parse_conn_line("0.0.0.0|8080")
        self.assertIsNone(result)


class TestFilterHelpers(unittest.TestCase):
    def test_system_listener_rpc(self):
        self.assertTrue(_is_system_listener(135, "svchost"))

    def test_system_listener_dynamic_port_system(self):
        self.assertTrue(_is_system_listener(49664, "lsass"))

    def test_system_listener_dynamic_port_non_system(self):
        """Dynamic port from non-system process should NOT be whitelisted."""
        self.assertFalse(_is_system_listener(49664, "backdoor"))

    def test_excluded_process_svchost(self):
        self.assertTrue(_is_excluded_process("svchost"))

    def test_excluded_process_meshagent(self):
        self.assertTrue(_is_excluded_process("meshagent"))

    def test_excluded_process_telemetry(self):
        self.assertTrue(_is_excluded_process("startmenuexperiencehost"))

    def test_excluded_process_attacker(self):
        self.assertFalse(_is_excluded_process("nc"))


if __name__ == "__main__":
    unittest.main()
