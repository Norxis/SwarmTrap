"""Individual command handler implementations.

Each handler is a module-level function with the signature::

    handler(config, args: dict) -> dict

On Windows, handlers shell out to PowerShell via ``subprocess.run``.
On non-Windows platforms (dev/test), handlers return stub responses so
the dispatcher can be exercised without a real Windows environment.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("winhunt.hand.handlers")

IS_WINDOWS = platform.system() == "Windows"

# ── helpers ──────────────────────────────────────────────────────────


def _ps_json(script: str, timeout: int = 30) -> Any:
    """Run a PowerShell snippet and parse its JSON output."""
    cmd = [
        "powershell.exe", "-NoProfile", "-NonInteractive",
        "-Command", script,
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell error (rc={result.returncode}): {result.stderr.strip()}"
        )
    return json.loads(result.stdout)


def _ps_raw(script: str, timeout: int = 30) -> str:
    """Run a PowerShell snippet and return raw stdout."""
    cmd = [
        "powershell.exe", "-NoProfile", "-NonInteractive",
        "-Command", script,
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell error (rc={result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


# ── handlers ─────────────────────────────────────────────────────────


def health_check(config: Any, args: dict) -> dict:
    """System health: CPU, memory, disk, uptime, agent version.

    Uses ``Get-CimInstance Win32_OperatingSystem`` and
    ``Get-CimInstance Win32_Processor``.
    """
    if not IS_WINDOWS:
        return _health_check_stub(config)

    script = r"""
$os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$disks = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } |
    Select-Object Name,
        @{N='total_gb';E={[math]::Round(($_.Used+$_.Free)/1GB,2)}},
        @{N='used_gb';E={[math]::Round($_.Used/1GB,2)}},
        @{N='available_gb';E={[math]::Round($_.Free/1GB,2)}}

$boot = $os.LastBootUpTime
$uptime = [int]((Get-Date) - $boot).TotalSeconds

@{
    cpu_pct        = [math]::Round($cpu, 1)
    memory         = @{
        total_mb     = [math]::Round($os.TotalVisibleMemorySize/1024, 0)
        available_mb = [math]::Round($os.FreePhysicalMemory/1024, 0)
        used_pct     = [math]::Round(100 - ($os.FreePhysicalMemory/$os.TotalVisibleMemorySize*100), 1)
    }
    disk           = @($disks | ForEach-Object {
        @{ drive=$_.Name; total_gb=$_.total_gb; used_gb=$_.used_gb; available_gb=$_.available_gb }
    })
    uptime_s       = $uptime
    agent_version  = '__VERSION__'
} | ConvertTo-Json -Depth 4
""".replace("__VERSION__", _agent_version())

    timeout = args.get("timeout", 30)
    return _ps_json(script, timeout=timeout)


def _health_check_stub(config: Any) -> dict:
    """Non-Windows stub for development/testing."""
    import psutil  # type: ignore[import-untyped]

    mem = psutil.virtual_memory()
    disk_info = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disk_info.append({
                "drive": part.mountpoint,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "available_gb": round(usage.free / (1024**3), 2),
            })
        except PermissionError:
            continue
    return {
        "cpu_pct": psutil.cpu_percent(interval=0.5),
        "memory": {
            "total_mb": round(mem.total / (1024**2)),
            "available_mb": round(mem.available / (1024**2)),
            "used_pct": mem.percent,
        },
        "disk": disk_info,
        "uptime_s": int(time.time() - psutil.boot_time()),
        "agent_version": _agent_version(),
    }


def service_status(config: Any, args: dict) -> dict:
    """Service status for one or more Windows services.

    ``args.filter``: list of service names, or ``None`` for all.
    Returns ``{name: {status, pid, start_type}, ...}``.
    """
    svc_filter = args.get("filter")
    if not IS_WINDOWS:
        return _service_status_stub(svc_filter)

    if svc_filter and isinstance(svc_filter, list):
        names = ",".join(f"'{s}'" for s in svc_filter)
        where = f" | Where-Object {{ $_.Name -in @({names}) }}"
    else:
        where = ""

    script = rf"""
Get-Service{where} | Select-Object Name, Status,
    @{{N='Pid';E={{(Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'" | Select-Object -First 1).ProcessId}}}},
    @{{N='StartType';E={{$_.StartType.ToString()}}}} |
    ConvertTo-Json -Depth 2
"""
    timeout = args.get("timeout", 30)
    raw = _ps_json(script, timeout=timeout)
    # Normalise: PS may return a single object instead of array
    if isinstance(raw, dict):
        raw = [raw]
    return {
        s["Name"]: {
            "status": s.get("Status", {}).get("Value", str(s.get("Status", ""))),
            "pid": s.get("Pid", 0),
            "start_type": s.get("StartType", ""),
        }
        for s in raw
    }


def _service_status_stub(svc_filter: list[str] | None) -> dict:
    return {
        "StubService": {"status": "Running", "pid": 0, "start_type": "Automatic"},
    }


def process_list(config: Any, args: dict) -> dict:
    """Process list.

    ``args.filter``:
      - ``"all"`` — every process (default)
      - ``"external"`` — processes with network connections not from agent
      - ``"attacker_tree"`` — processes spawned by honeypot services

    Returns ``{"processes": [...]}``.
    """
    proc_filter = args.get("filter", "all")
    if not IS_WINDOWS:
        return _process_list_stub(proc_filter)

    script = r"""
$procs = Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, ParentProcessId, CommandLine,
        @{N='WorkingSetMB';E={[math]::Round($_.WorkingSetSize/1MB,1)}},
        CreationDate
$procs | ConvertTo-Json -Depth 2
"""
    timeout = args.get("timeout", 30)
    raw = _ps_json(script, timeout=timeout)
    if isinstance(raw, dict):
        raw = [raw]
    processes = [
        {
            "pid": p.get("ProcessId"),
            "name": p.get("Name"),
            "ppid": p.get("ParentProcessId"),
            "cmdline": p.get("CommandLine", ""),
            "working_set_mb": p.get("WorkingSetMB", 0),
            "creation_date": str(p.get("CreationDate", "")),
        }
        for p in raw
    ]
    return {"processes": processes, "filter": proc_filter, "count": len(processes)}


def _process_list_stub(proc_filter: str) -> dict:
    return {"processes": [], "filter": proc_filter, "count": 0}


def network_state(config: Any, args: dict) -> dict:
    """Network interfaces, connections, listeners, routes.

    Uses ``Get-NetAdapter``, ``Get-NetTCPConnection``, ``Get-NetRoute``.
    """
    if not IS_WINDOWS:
        return _network_state_stub()

    script = r"""
$adapters = Get-NetAdapter | Where-Object Status -eq 'Up' |
    Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, Status |
    ConvertTo-Json -Depth 2

$conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    ConvertTo-Json -Depth 2

$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    ConvertTo-Json -Depth 2

$routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias |
    ConvertTo-Json -Depth 2

@{
    interfaces  = $adapters
    connections = $conns
    listeners   = $listeners
    routing     = $routes
} | ConvertTo-Json -Depth 3
"""
    timeout = args.get("timeout", 30)
    return _ps_json(script, timeout=timeout)


def _network_state_stub() -> dict:
    return {
        "interfaces": [],
        "connections": [],
        "listeners": [],
        "routing": [],
    }


def disk_usage(config: Any, args: dict) -> dict:
    """Per-drive disk usage via ``Get-PSDrive -PSProvider FileSystem``."""
    if not IS_WINDOWS:
        return _disk_usage_stub()

    script = r"""
Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } |
    Select-Object Name,
        @{N='total_gb';E={[math]::Round(($_.Used+$_.Free)/1GB,2)}},
        @{N='used_gb';E={[math]::Round($_.Used/1GB,2)}},
        @{N='available_gb';E={[math]::Round($_.Free/1GB,2)}} |
    ConvertTo-Json -Depth 2
"""
    timeout = args.get("timeout", 30)
    raw = _ps_json(script, timeout=timeout)
    if isinstance(raw, dict):
        raw = [raw]
    return {
        "drives": [
            {
                "drive": d.get("Name", ""),
                "total_gb": d.get("total_gb", 0),
                "used_gb": d.get("used_gb", 0),
                "available_gb": d.get("available_gb", 0),
            }
            for d in raw
        ]
    }


def _disk_usage_stub() -> dict:
    total, used, free = shutil.disk_usage("/")
    return {
        "drives": [
            {
                "drive": "/",
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "available_gb": round(free / (1024**3), 2),
            }
        ]
    }


def config_write(config: Any, args: dict) -> dict:
    """Write a config file with optional backup.

    ``args.path``: target path.
    ``args.content``: file content (string).
    ``args.backup``: create ``.bak`` before overwrite (default True).
    """
    path = args.get("path", "")
    content = args.get("content", "")
    do_backup = args.get("backup", True)

    if not path:
        raise ValueError("config_write: 'path' is required")
    if not content:
        raise ValueError("config_write: 'content' is required")

    target = Path(path)
    if do_backup and target.exists():
        bak = target.with_suffix(target.suffix + ".bak")
        shutil.copy2(str(target), str(bak))
        log.info("config_write: backup created %s", bak)

    # Validate JSON if the file looks like JSON
    if target.suffix.lower() == ".json":
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"config_write: invalid JSON — {exc}") from exc

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    log.info("config_write: wrote %d bytes to %s", len(content), path)

    return {
        "path": str(target),
        "bytes_written": len(content),
        "backup_created": do_backup and target.with_suffix(target.suffix + ".bak").exists(),
    }


def file_ops(config: Any, args: dict) -> dict:
    """File operations: read, write, delete, stat.

    ``args.op``: ``"read"`` | ``"write"`` | ``"delete"`` | ``"stat"``.
    ``args.path``: target file path.
    ``args.content``: (write only) file content.
    """
    op = args.get("op", "")
    path = args.get("path", "")
    if not op:
        raise ValueError("file_ops: 'op' is required")
    if not path:
        raise ValueError("file_ops: 'path' is required")

    target = Path(path)

    if op == "read":
        if not target.exists():
            raise FileNotFoundError(f"file_ops: {path} not found")
        content = target.read_text(encoding="utf-8", errors="replace")
        return {"op": "read", "path": str(target), "size": len(content), "content": content}

    elif op == "write":
        content = args.get("content", "")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"op": "write", "path": str(target), "bytes_written": len(content)}

    elif op == "delete":
        if not target.exists():
            return {"op": "delete", "path": str(target), "deleted": False, "reason": "not found"}
        target.unlink()
        return {"op": "delete", "path": str(target), "deleted": True}

    elif op == "stat":
        if not target.exists():
            raise FileNotFoundError(f"file_ops: {path} not found")
        st = target.stat()
        sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        return {
            "op": "stat",
            "path": str(target),
            "size": st.st_size,
            "sha256": sha256,
            "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
        }

    else:
        raise ValueError(f"file_ops: unknown op '{op}' — expected read|write|delete|stat")


def exec_cmd(config: Any, args: dict) -> dict:
    """Raw command execution (fallback, audited).

    ``args.command``: command string to execute.
    ``args.timeout``: execution timeout in seconds (default 30).
    """
    command = args.get("command", "")
    if not command:
        raise ValueError("exec: 'command' is required")

    timeout = args.get("timeout", 30)
    log.warning("exec_cmd: executing raw command (audited): %s", command[:200])

    if IS_WINDOWS:
        cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command]
    else:
        cmd = ["bash", "-c", command]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"command timed out after {timeout}s",
            "returncode": -1,
        }


# ── helpers ──

def _agent_version() -> str:
    try:
        from dfi_agent import __version__
        return __version__
    except Exception:
        return "unknown"


# ── registry ─────────────────────────────────────────────────────────

COMMAND_REGISTRY = {
    "health_check": health_check,
    "service_status": service_status,
    "process_list": process_list,
    "network_state": network_state,
    "disk_usage": disk_usage,
    "config_write": config_write,
    "file_ops": file_ops,
    "exec": exec_cmd,
}
