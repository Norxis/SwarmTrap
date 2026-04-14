"""Process monitor eye sensor — polls Win32_Process via CIM and detects anomalies.

Daemon thread that maintains a cache of known PIDs and detects:
- New process spawns
- Suspicious parent chains (e.g. svchost -> cmd -> whoami)
- Deleted executables (process running but exe path gone)
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from typing import Any

from ..evidence_bits import (
    MEMORY_ONLY_TOOL,
    PROCESS_CREATE,
    SUSPICIOUS_COMMAND,
)
from ..observation import (
    PRIORITY_HIGH,
    PRIORITY_NORMAL,
    PROCESS_SPAWN,
    SUSPICIOUS_COMMAND as OBS_SUSPICIOUS_COMMAND,
)

log = logging.getLogger("winhunt.eyes.process_monitor")

# Parent chain patterns that indicate exploitation
# Format: (grandparent, parent, child) — any match triggers alert
_SUSPICIOUS_CHAINS = [
    ("svchost.exe", "cmd.exe", "whoami.exe"),
    ("svchost.exe", "cmd.exe", "net.exe"),
    ("svchost.exe", "cmd.exe", "net1.exe"),
    ("svchost.exe", "powershell.exe", None),
    ("svchost.exe", "cmd.exe", "powershell.exe"),
    ("w3wp.exe", "cmd.exe", None),
    ("w3wp.exe", "powershell.exe", None),
    ("sqlservr.exe", "cmd.exe", None),
    ("sqlservr.exe", "powershell.exe", None),
    ("wmiprvse.exe", "cmd.exe", None),
    ("wmiprvse.exe", "powershell.exe", None),
]

# PowerShell command to list processes with pipe-delimited fields
_PS_CMD = (
    "Get-CimInstance Win32_Process | "
    "Select-Object ProcessId,Name,CommandLine,ParentProcessId,ExecutablePath,CreationDate | "
    "ForEach-Object { "
    "$_.ProcessId.ToString() + '|' + "
    "$_.Name + '|' + "
    "($_.CommandLine -replace '\\|','<PIPE>') + '|' + "
    "$_.ParentProcessId.ToString() + '|' + "
    "($_.ExecutablePath -replace '\\|','<PIPE>') + '|' + "
    "($_.CreationDate.ToString('o') -replace '\\|','<PIPE>') "
    "}"
)


def _parse_process_line(line: str) -> dict[str, Any] | None:
    """Parse a pipe-delimited process line into a dict."""
    parts = line.strip().split("|", 5)
    if len(parts) < 6:
        return None
    try:
        pid = int(parts[0])
    except (ValueError, TypeError):
        return None
    return {
        "pid": pid,
        "name": parts[1].strip(),
        "cmdline": parts[2].strip().replace("<PIPE>", "|"),
        "parent_pid": int(parts[3]) if parts[3].strip().isdigit() else 0,
        "exe_path": parts[4].strip().replace("<PIPE>", "|"),
        "create_time": parts[5].strip().replace("<PIPE>", "|"),
    }


class ProcessMonitor(threading.Thread):
    """Daemon thread that polls Win32_Process and detects anomalies."""

    def __init__(self, config: Any, buffer: Any, stop_event: threading.Event) -> None:
        super().__init__(daemon=True, name="eye-process-monitor")
        self.config = config
        self.buffer = buffer
        self.stop_event = stop_event
        self.known_pids: dict[int, dict[str, Any]] = {}
        self._memory_forensics: Any = None
        self._poll_interval = 5

    def set_memory_forensics(self, mf: Any) -> None:
        """Inject memory forensics module for anomaly callbacks."""
        self._memory_forensics = mf

    def run(self) -> None:
        log.info("Process monitor starting")
        if os.name != "nt":
            log.warning("Not running on Windows — process monitor idle")
            while not self.stop_event.is_set():
                self.stop_event.wait(timeout=self._poll_interval)
            return

        while not self.stop_event.is_set():
            try:
                self._poll()
            except Exception:
                log.exception("Error in process monitor poll")
            self.stop_event.wait(timeout=self._poll_interval)

        log.info("Process monitor stopped")

    def _poll(self) -> None:
        """Run PowerShell, parse output, detect new/suspicious processes."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", _PS_CMD],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            log.warning("Process poll timed out")
            return
        except FileNotFoundError:
            log.error("PowerShell not found")
            return

        if result.returncode != 0:
            log.warning("Process poll failed: %s", result.stderr[:200])
            return

        current_pids: dict[int, dict[str, Any]] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            proc = _parse_process_line(line)
            if proc is None:
                continue
            current_pids[proc["pid"]] = proc

        # Detect new PIDs
        new_pids = set(current_pids.keys()) - set(self.known_pids.keys())
        ts = time.time()

        for pid in new_pids:
            proc = current_pids[pid]
            self._handle_new_process(proc, current_pids, ts)

        # Check for deleted executables on all known processes
        for pid, proc in current_pids.items():
            self._check_deleted_exe(proc, ts)

        # Update cache
        self.known_pids = current_pids

    def _handle_new_process(self, proc: dict[str, Any],
                            all_procs: dict[int, dict[str, Any]],
                            ts: float) -> None:
        """Process a newly detected PID."""
        pid = proc["pid"]
        name = proc["name"].lower()
        parent_pid = proc["parent_pid"]

        # Check suspicious parent chains
        chain = self._build_chain(pid, all_procs, depth=3)
        chain_names = [p.lower() for p in chain]

        is_suspicious = False
        for pattern in _SUSPICIOUS_CHAINS:
            matched = True
            for i, expected in enumerate(pattern):
                if expected is None:
                    continue
                if i >= len(chain_names) or chain_names[i] != expected.lower():
                    matched = False
                    break
            if matched and any(p is not None for p in pattern):
                is_suspicious = True
                break

        detail = {
            "pid": pid,
            "name": proc["name"],
            "cmdline": proc["cmdline"],
            "parent_pid": parent_pid,
            "parent_chain": chain,
            "exe_path": proc["exe_path"],
        }

        if is_suspicious:
            log.warning("Suspicious parent chain: %s (PID %d)", " -> ".join(chain), pid)
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=OBS_SUSPICIOUS_COMMAND,
                session_id=None,
                source_ip=None,
                process_pid=pid,
                evidence_bits=SUSPICIOUS_COMMAND | PROCESS_CREATE,
                priority=PRIORITY_HIGH,
                detail=json.dumps(detail),
            )
            # Trigger memory forensics for suspicious processes
            if self._memory_forensics:
                try:
                    self._memory_forensics.capture_process(pid)
                except Exception:
                    log.exception("Memory forensics capture failed for PID %d", pid)
        else:
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=PROCESS_SPAWN,
                session_id=None,
                source_ip=None,
                process_pid=pid,
                evidence_bits=PROCESS_CREATE,
                priority=PRIORITY_NORMAL,
                detail=json.dumps(detail),
            )

    def _check_deleted_exe(self, proc: dict[str, Any], ts: float) -> None:
        """Check if process executable path no longer exists on disk."""
        exe_path = proc.get("exe_path", "")
        if not exe_path or exe_path == "":
            return
        # Check via PowerShell if the file exists
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Test-Path '{exe_path}'"],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip().lower() == "false":
                pid = proc["pid"]
                log.warning("Deleted executable detected: PID %d, path %s", pid, exe_path)
                detail = {
                    "pid": pid,
                    "name": proc["name"],
                    "deleted_exe": exe_path,
                    "cmdline": proc["cmdline"],
                }
                self.buffer.insert_observation(
                    ts=ts,
                    vm_id=self.config.vm_id,
                    obs_type=OBS_SUSPICIOUS_COMMAND,
                    session_id=None,
                    source_ip=None,
                    process_pid=pid,
                    evidence_bits=MEMORY_ONLY_TOOL,
                    priority=PRIORITY_HIGH,
                    detail=json.dumps(detail),
                )
                # Trigger memory forensics
                if self._memory_forensics:
                    try:
                        self._memory_forensics.capture_process(pid)
                    except Exception:
                        log.exception("Memory forensics capture failed for PID %d", pid)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _build_chain(self, pid: int, all_procs: dict[int, dict[str, Any]],
                     depth: int = 3) -> list[str]:
        """Build process name chain from child to grandparent.

        Returns list like ['grandparent.exe', 'parent.exe', 'child.exe'].
        """
        chain: list[str] = []
        current_pid = pid
        seen: set[int] = set()
        for _ in range(depth):
            if current_pid in seen or current_pid not in all_procs:
                break
            seen.add(current_pid)
            proc = all_procs[current_pid]
            chain.append(proc["name"])
            current_pid = proc["parent_pid"]
        chain.reverse()
        return chain

    def get_process_tree(self, pid: int) -> dict[str, Any] | None:
        """Get process info and parent chain for a given PID.

        Returns dict with process info and parent_chain list, or None if
        the PID is not in the current cache.
        """
        if pid not in self.known_pids:
            return None
        proc = self.known_pids[pid]
        chain = self._build_chain(pid, self.known_pids, depth=5)
        return {
            "pid": pid,
            "name": proc["name"],
            "cmdline": proc["cmdline"],
            "parent_pid": proc["parent_pid"],
            "exe_path": proc["exe_path"],
            "create_time": proc["create_time"],
            "parent_chain": chain,
        }
