"""Unit tests for the process monitor eye sensor."""
from __future__ import annotations

import json
import threading
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from dfi_agent.evidence_bits import MEMORY_ONLY_TOOL, PROCESS_CREATE, SUSPICIOUS_COMMAND
from dfi_agent.eyes.process_monitor import ProcessMonitor, _parse_process_line


def _make_ps_output(processes: list[dict]) -> str:
    """Build fake PowerShell pipe-delimited output."""
    lines = []
    for p in processes:
        lines.append(
            f"{p['pid']}|{p['name']}|{p.get('cmdline', '')}|"
            f"{p.get('ppid', 0)}|{p.get('exe', '')}|"
            f"{p.get('created', '2026-01-01T00:00:00.0000000+00:00')}"
        )
    return "\n".join(lines) + "\n"


class TestProcessMonitor(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.vm_id = "test-vm"
        self.buffer = MagicMock()
        self.stop_event = threading.Event()
        self.monitor = ProcessMonitor(self.config, self.buffer, self.stop_event)

    @patch("dfi_agent.eyes.process_monitor.subprocess.run")
    def test_new_process_detection(self, mock_run):
        """New PID appearing should trigger an observation insert."""
        # First poll: establish baseline
        baseline_procs = [
            {"pid": 1, "name": "System", "cmdline": "", "ppid": 0, "exe": r"C:\Windows\System"},
            {"pid": 100, "name": "svchost.exe", "cmdline": "svchost -k", "ppid": 1, "exe": r"C:\Windows\System32\svchost.exe"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_make_ps_output(baseline_procs),
            stderr="",
        )
        self.monitor._poll()
        self.assertEqual(len(self.monitor.known_pids), 2)

        # Second poll: new process appears
        new_procs = baseline_procs + [
            {"pid": 200, "name": "notepad.exe", "cmdline": "notepad.exe test.txt",
             "ppid": 100, "exe": r"C:\Windows\notepad.exe"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_make_ps_output(new_procs),
            stderr="",
        )
        self.monitor._poll()

        # Should have called insert_observation for the new PID
        self.assertTrue(self.buffer.insert_observation.called)
        call_kwargs = self.buffer.insert_observation.call_args
        # Check it was called with PROCESS_CREATE evidence bit
        if call_kwargs.kwargs:
            self.assertTrue(call_kwargs.kwargs.get("evidence_bits", 0) & PROCESS_CREATE)
        else:
            # positional args
            args = call_kwargs[1] if len(call_kwargs) > 1 else {}
            if "evidence_bits" in args:
                self.assertTrue(args["evidence_bits"] & PROCESS_CREATE)

    @patch("dfi_agent.eyes.process_monitor.subprocess.run")
    def test_suspicious_parent_chain(self, mock_run):
        """svchost -> cmd -> whoami should be detected as suspicious."""
        # First poll: baseline with svchost
        baseline = [
            {"pid": 1, "name": "System", "cmdline": "", "ppid": 0, "exe": ""},
            {"pid": 100, "name": "svchost.exe", "cmdline": "svchost -k",
             "ppid": 1, "exe": r"C:\Windows\System32\svchost.exe"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_make_ps_output(baseline),
            stderr="",
        )
        self.monitor._poll()
        self.buffer.reset_mock()

        # Second poll: cmd spawned by svchost, whoami spawned by cmd
        procs = baseline + [
            {"pid": 200, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami",
             "ppid": 100, "exe": r"C:\Windows\System32\cmd.exe"},
            {"pid": 300, "name": "whoami.exe", "cmdline": "whoami",
             "ppid": 200, "exe": r"C:\Windows\System32\whoami.exe"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_make_ps_output(procs),
            stderr="",
        )
        self.monitor._poll()

        # At least one call should have SUSPICIOUS_COMMAND bit set
        suspicious_found = False
        for call in self.buffer.insert_observation.call_args_list:
            kwargs = call.kwargs if call.kwargs else {}
            bits = kwargs.get("evidence_bits", 0)
            if bits & SUSPICIOUS_COMMAND:
                suspicious_found = True
                break
        self.assertTrue(suspicious_found, "Expected SUSPICIOUS_COMMAND bit in at least one observation")

    @patch("dfi_agent.eyes.process_monitor.subprocess.run")
    def test_deleted_executable(self, mock_run):
        """Process with missing exe path should trigger MEMORY_ONLY_TOOL."""
        # First poll: establish baseline with a process
        baseline = [
            {"pid": 1, "name": "System", "cmdline": "", "ppid": 0, "exe": ""},
            {"pid": 500, "name": "evil.exe", "cmdline": "evil.exe --payload",
             "ppid": 1, "exe": r"C:\Temp\evil.exe"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_make_ps_output(baseline),
            stderr="",
        )
        self.monitor._poll()
        self.buffer.reset_mock()

        # Set up the second subprocess.run to handle both poll and exe check
        # First call is _poll's Get-CimInstance, second is Test-Path returning False
        def side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            result = MagicMock(returncode=0, stderr="")
            if "Test-Path" in cmd_str:
                result.stdout = "False\n"
            else:
                # Same process list (process still running)
                result.stdout = _make_ps_output(baseline)
            return result

        mock_run.side_effect = side_effect
        self.monitor._poll()

        # Should detect deleted executable with MEMORY_ONLY_TOOL bit
        memory_tool_found = False
        for call in self.buffer.insert_observation.call_args_list:
            kwargs = call.kwargs if call.kwargs else {}
            bits = kwargs.get("evidence_bits", 0)
            if bits & MEMORY_ONLY_TOOL:
                memory_tool_found = True
                break
        self.assertTrue(memory_tool_found, "Expected MEMORY_ONLY_TOOL bit for deleted executable")


class TestParseProcessLine(unittest.TestCase):
    def test_valid_line(self):
        line = "1234|cmd.exe|cmd /c dir|5678|C:\\Windows\\System32\\cmd.exe|2026-01-01T00:00:00.0000000+00:00"
        result = _parse_process_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["name"], "cmd.exe")
        self.assertEqual(result["parent_pid"], 5678)

    def test_short_line(self):
        result = _parse_process_line("1234|cmd.exe")
        self.assertIsNone(result)

    def test_invalid_pid(self):
        result = _parse_process_line("abc|cmd.exe|cmd|0|path|time")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
