"""Memory forensics eye sensor — on-demand process inspection.

Not a thread. Called by ProcessMonitor when anomalies are detected.
Captures process details (cmdline, modules, handles, environment)
via PowerShell and inserts observations when suspicious.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from typing import Any

from ..evidence_bits import MEMORY_ONLY_TOOL
from ..observation import (
    MEMORY_INJECTION,
    PRIORITY_IMMEDIATE,
)

log = logging.getLogger("winhunt.eyes.memory_forensics")

# PowerShell template for detailed process inspection
_PS_CAPTURE = (
    "try {{ "
    "$p = Get-Process -Id {pid} -ErrorAction Stop | Select-Object *; "
    "$mods = $p.Modules | ForEach-Object {{ $_.FileName }}; "
    "$env = [System.Environment]::GetEnvironmentVariables('Process'); "
    "'PID|' + $p.Id.ToString(); "
    "'NAME|' + $p.ProcessName; "
    "'PATH|' + $p.Path; "
    "'CMDLINE|' + $p.StartInfo.Arguments; "
    "'WORKDIR|' + $p.StartInfo.WorkingDirectory; "
    "'HANDLES|' + $p.HandleCount.ToString(); "
    "'THREADS|' + $p.Threads.Count.ToString(); "
    "'WS_MB|' + [math]::Round($p.WorkingSet64 / 1MB, 2).ToString(); "
    "'VM_MB|' + [math]::Round($p.VirtualMemorySize64 / 1MB, 2).ToString(); "
    "'STARTTIME|' + ($p.StartTime.ToString('o') -replace '\\|',''); "
    "'MODULES|' + ($mods -join ';'); "
    "'ENV_COUNT|' + $env.Count.ToString() "
    "}} catch {{ "
    "'ERROR|' + $_.Exception.Message "
    "}}"
)


class MemoryForensics:
    """On-demand process memory and metadata inspector.

    Called by ProcessMonitor when anomalies are detected (suspicious
    parent chains, deleted executables, etc). Captures detailed process
    information via PowerShell.
    """

    def __init__(self, config: Any, buffer: Any) -> None:
        self.config = config
        self.buffer = buffer

    def capture_process(self, pid: int) -> dict[str, Any] | None:
        """Capture detailed process information for forensic analysis.

        Args:
            pid: Process ID to inspect.

        Returns:
            Structured dict with process details, or None if capture fails
            or not running on Windows.
        """
        if os.name != "nt":
            log.debug("Not on Windows — skipping memory forensics for PID %d", pid)
            return None

        ps_cmd = _PS_CAPTURE.format(pid=pid)
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            log.warning("Memory forensics timed out for PID %d", pid)
            return None
        except FileNotFoundError:
            log.error("PowerShell not found")
            return None

        if result.returncode != 0:
            log.warning("Memory forensics failed for PID %d: %s", pid, result.stderr[:200])
            return None

        # Parse structured output
        info: dict[str, Any] = {"pid": pid}
        modules: list[str] = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            key, _, value = line.partition("|")
            key = key.strip()
            value = value.strip()

            if key == "ERROR":
                log.warning("Process capture error for PID %d: %s", pid, value)
                return None
            elif key == "PID":
                info["pid"] = int(value) if value.isdigit() else pid
            elif key == "NAME":
                info["name"] = value
            elif key == "PATH":
                info["path"] = value
            elif key == "CMDLINE":
                info["cmdline"] = value
            elif key == "WORKDIR":
                info["working_directory"] = value
            elif key == "HANDLES":
                info["handle_count"] = int(value) if value.isdigit() else 0
            elif key == "THREADS":
                info["thread_count"] = int(value) if value.isdigit() else 0
            elif key == "WS_MB":
                try:
                    info["working_set_mb"] = float(value)
                except ValueError:
                    info["working_set_mb"] = 0.0
            elif key == "VM_MB":
                try:
                    info["virtual_memory_mb"] = float(value)
                except ValueError:
                    info["virtual_memory_mb"] = 0.0
            elif key == "STARTTIME":
                info["start_time"] = value
            elif key == "MODULES":
                modules = [m.strip() for m in value.split(";") if m.strip()]
                info["modules"] = modules
                info["module_count"] = len(modules)
            elif key == "ENV_COUNT":
                info["env_var_count"] = int(value) if value.isdigit() else 0

        # Analyze for suspicious indicators
        suspicious = self._analyze(info, modules)
        if suspicious:
            info["suspicious_indicators"] = suspicious
            ts = time.time()
            log.warning(
                "Suspicious process PID %d: %s",
                pid, ", ".join(suspicious),
            )
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=MEMORY_INJECTION,
                session_id=None,
                source_ip=None,
                process_pid=pid,
                evidence_bits=MEMORY_ONLY_TOOL,
                priority=PRIORITY_IMMEDIATE,
                detail=json.dumps(info),
            )

        return info

    def _analyze(self, info: dict[str, Any], modules: list[str]) -> list[str]:
        """Analyze captured process data for suspicious indicators.

        Returns list of indicator strings, empty if nothing suspicious.
        """
        indicators: list[str] = []

        # Process with no path (memory-only / injected)
        path = info.get("path", "")
        if not path:
            indicators.append("no_executable_path")

        # Extremely high handle count (potential handle table manipulation)
        handle_count = info.get("handle_count", 0)
        if handle_count > 10000:
            indicators.append(f"high_handle_count_{handle_count}")

        # Check for known injection-related modules
        injection_dlls = {
            "clrjit.dll", "amsi.dll", "mscorlib.ni.dll",
        }
        module_names_lower = {os.path.basename(m).lower() for m in modules}

        # PowerShell host process loading .NET — could be fileless malware
        name = info.get("name", "").lower()
        if name in ("cmd", "conhost") and module_names_lower & {"clrjit.dll", "mscorlib.ni.dll"}:
            indicators.append("dotnet_in_cmd_process")

        # Very large working set for a shell process
        ws_mb = info.get("working_set_mb", 0.0)
        if name in ("cmd", "powershell", "pwsh") and ws_mb > 500:
            indicators.append(f"large_working_set_{ws_mb}mb")

        return indicators
