"""Socket monitor eye sensor — polls Get-NetTCPConnection for network anomalies.

Daemon thread that detects:
- New listeners not in configured services (backdoor listener)
- Outbound connections to external IPs (C2 beaconing)
- Outbound connections to internal IPs (lateral movement)

Filtering per AIO spec:
- Exclude: MeshCentral agent, agent's own execution, routine system processes
- Include: genuinely new listeners/outbound from attacker processes
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
from typing import Any

from ..evidence_bits import (
    LATERAL_MOVEMENT as LATERAL_MOVEMENT_BIT,
    OUTBOUND_C2,
    SUSPICIOUS_COMMAND as SUSPICIOUS_COMMAND_BIT,
)
from ..observation import (
    LATERAL_MOVEMENT as OBS_LATERAL_MOVEMENT,
    NETWORK_LISTENER,
    OUTBOUND_CONNECTION,
    PRIORITY_HIGH,
    PRIORITY_IMMEDIATE,
)

log = logging.getLogger("winhunt.eyes.socket_monitor")

# PowerShell command — include process name for filtering
_PS_CMD = (
    "Get-NetTCPConnection | ForEach-Object { "
    "$p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name; "
    "if (-not $p) { $p = 'unknown' }; "
    "$_.LocalAddress + '|' + "
    "$_.LocalPort.ToString() + '|' + "
    "$_.RemoteAddress + '|' + "
    "$_.RemotePort.ToString() + '|' + "
    "$_.State.ToString() + '|' + "
    "$_.OwningProcess.ToString() + '|' + "
    "$p "
    "}"
)

# ── Spec filtering: routine system processes to exclude ──
# These are core Windows processes that always have listeners and outbound
# connections. Attacker processes will NOT be in this set.
_SYSTEM_PROCESS_NAMES = frozenset({
    "system",           # PID 4 — SMB, WinRM, NetBIOS
    "lsass",            # Local Security Authority
    "services",         # Service Control Manager
    "wininit",          # Windows Init
    "svchost",          # Shared service host (Windows Update, RPC, etc.)
    "spoolsv",          # Print Spooler
    "csrss",            # Client/Server Runtime
    "smss",             # Session Manager
    "msmpeng",          # Windows Defender
    "nissrv",           # Defender Network Inspection
    "searchindexer",    # Windows Search
    "tiworker",         # Windows Module Installer
    "trustedinstaller", # Windows servicing
    "dfsrsvc",          # DFS Replication
})

# MeshCentral agent process — always exclude per spec
_MESHCENTRAL_PROCESS_NAMES = frozenset({
    "meshagent",
})

# Windows UI/telemetry processes — routine outbound to Microsoft, not C2
_TELEMETRY_PROCESS_NAMES = frozenset({
    "startmenuexperiencehost",
    "runtimebroker",
    "applicationframehost",
    "microsoftedge",
    "microsoftedgeupdate",
    "msedge",
    "msedgewebview2",
    "searchapp",
    "searchhost",
    "widgets",
    "windowsterminal",
    "explorer",
    "settingssynchost",
    "onedrive",
    "teams",
})

# Well-known Windows listener ports that are NOT honeypot services
# but are standard OS infrastructure. RPC dynamic range is 49152-65535.
_SYSTEM_LISTENER_PORTS = frozenset({
    135,    # RPC Endpoint Mapper
    139,    # NetBIOS Session
    47001,  # WinRM HTTP Compat
})

# RPC dynamic port range — Windows allocates these to system services
_RPC_DYNAMIC_RANGE = (49152, 65535)


def _parse_conn_line(line: str) -> dict[str, Any] | None:
    """Parse a pipe-delimited connection line (7 fields including process name)."""
    parts = line.strip().split("|", 6)
    if len(parts) < 6:
        return None
    try:
        return {
            "local_addr": parts[0].strip(),
            "local_port": int(parts[1].strip()),
            "remote_addr": parts[2].strip(),
            "remote_port": int(parts[3].strip()),
            "state": parts[4].strip(),
            "pid": int(parts[5].strip()),
            "process_name": parts[6].strip().lower() if len(parts) > 6 else "unknown",
        }
    except (ValueError, TypeError):
        return None


def _is_local(ip: str, local_networks: list[str]) -> bool:
    """Check if an IP is in any of the local network CIDRs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in local_networks:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_external(ip: str) -> bool:
    """Check if an IP is a routable external address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def _is_system_process(name: str) -> bool:
    """Check if process name is a known Windows system process."""
    return name in _SYSTEM_PROCESS_NAMES


def _is_excluded_process(name: str) -> bool:
    """Check if process should be fully excluded (system + mesh + telemetry)."""
    return (name in _SYSTEM_PROCESS_NAMES
            or name in _MESHCENTRAL_PROCESS_NAMES
            or name in _TELEMETRY_PROCESS_NAMES)


def _is_system_listener(port: int, process_name: str) -> bool:
    """Check if a listener is a known Windows system listener."""
    # Well-known system ports
    if port in _SYSTEM_LISTENER_PORTS:
        return True
    # RPC dynamic range from system processes
    if _RPC_DYNAMIC_RANGE[0] <= port <= _RPC_DYNAMIC_RANGE[1] and _is_system_process(process_name):
        return True
    return False


class SocketMonitor(threading.Thread):
    """Daemon thread that polls TCP connections and detects anomalies."""

    def __init__(self, config: Any, buffer: Any, stop_event: threading.Event) -> None:
        super().__init__(daemon=True, name="eye-socket-monitor")
        self.config = config
        self.buffer = buffer
        self.stop_event = stop_event
        self._poll_interval = 10
        self._known_listeners: set[tuple[str, int]] = set()
        self._alerted_outbound: set[tuple[str, int, str, int]] = set()
        # Agent's own API port — exclude from listener alerts
        self._agent_port = getattr(config, "agent_port", 9200)
        # Infrastructure IPs to exclude from lateral movement (e.g. MeshCentral)
        self._infra_ips: set[str] = set()
        mgmt = getattr(config, "mgmt_nic_ip", None)
        if mgmt:
            self._infra_ips.add(mgmt)
        # MeshCentral server IP (172.16.3.112)
        self._infra_ips.add("172.16.3.112")
        self._infra_ips.add("192.168.0.112")

    def run(self) -> None:
        log.info("Socket monitor starting")
        if os.name != "nt":
            log.warning("Not running on Windows — socket monitor idle")
            while not self.stop_event.is_set():
                self.stop_event.wait(timeout=self._poll_interval)
            return

        while not self.stop_event.is_set():
            try:
                self._poll()
            except Exception:
                log.exception("Error in socket monitor poll")
            self.stop_event.wait(timeout=self._poll_interval)

        log.info("Socket monitor stopped")

    def _poll(self) -> None:
        """Run PowerShell, parse connections, detect anomalies."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", _PS_CMD],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            log.warning("Socket poll timed out")
            return
        except FileNotFoundError:
            log.error("PowerShell not found")
            return

        if result.returncode != 0:
            log.warning("Socket poll failed: %s", result.stderr[:200])
            return

        connections: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            conn = _parse_conn_line(line)
            if conn is not None:
                connections.append(conn)

        ts = time.time()
        honeypot_ports = self.config.honeypot_ports()
        local_networks = self.config.pcap.local_networks
        local_ips = self.config.local_ips

        for conn in connections:
            state = conn["state"].lower()
            pname = conn.get("process_name", "unknown")

            # Detect new listeners
            if state == "listen":
                key = (conn["local_addr"], conn["local_port"])
                if key not in self._known_listeners:
                    self._known_listeners.add(key)
                    # Skip honeypot service ports
                    if conn["local_port"] in honeypot_ports:
                        continue
                    # Skip agent's own API port
                    if conn["local_port"] == self._agent_port:
                        continue
                    # Skip known system listeners (RPC, NetBIOS, etc.)
                    if _is_system_listener(conn["local_port"], pname):
                        continue
                    self._alert_new_listener(conn, ts)

            # Detect outbound connections
            elif state == "established":
                remote_ip = conn["remote_addr"]
                local_addr = conn["local_addr"]

                # Skip excluded processes (system, MeshCentral, telemetry)
                if _is_excluded_process(pname):
                    continue

                # Skip if local address isn't ours
                if local_addr not in local_ips and local_addr not in ("0.0.0.0", "::"):
                    continue

                # Skip inbound connections (remote initiated to our service port)
                if conn["local_port"] in honeypot_ports:
                    continue

                outbound_key = (
                    conn["local_addr"], conn["local_port"],
                    conn["remote_addr"], conn["remote_port"],
                )

                if outbound_key in self._alerted_outbound:
                    continue

                if _is_external(remote_ip):
                    self._alert_outbound_c2(conn, ts)
                    self._alerted_outbound.add(outbound_key)
                elif _is_local(remote_ip, local_networks) and remote_ip not in local_ips:
                    # Skip infrastructure IPs (MeshCentral server)
                    if remote_ip in self._infra_ips:
                        continue
                    self._alert_lateral_movement(conn, ts)
                    self._alerted_outbound.add(outbound_key)

    def _alert_new_listener(self, conn: dict[str, Any], ts: float) -> None:
        """Alert on a new unexpected listener."""
        log.warning(
            "Unexpected listener: %s:%d (PID %d, %s)",
            conn["local_addr"], conn["local_port"], conn["pid"],
            conn.get("process_name", "?"),
        )
        detail = {
            "local_addr": conn["local_addr"],
            "local_port": conn["local_port"],
            "pid": conn["pid"],
            "process_name": conn.get("process_name", "unknown"),
            "reason": "new_listener_not_in_services",
        }
        self.buffer.insert_observation(
            ts=ts,
            vm_id=self.config.vm_id,
            obs_type=NETWORK_LISTENER,
            session_id=None,
            source_ip=None,
            process_pid=conn["pid"],
            evidence_bits=SUSPICIOUS_COMMAND_BIT,
            priority=PRIORITY_HIGH,
            detail=json.dumps(detail),
        )

    def _alert_outbound_c2(self, conn: dict[str, Any], ts: float) -> None:
        """Alert on outbound connection to external IP."""
        log.warning(
            "Outbound C2 candidate: %s:%d -> %s:%d (PID %d, %s)",
            conn["local_addr"], conn["local_port"],
            conn["remote_addr"], conn["remote_port"], conn["pid"],
            conn.get("process_name", "?"),
        )
        detail = {
            "local_addr": conn["local_addr"],
            "local_port": conn["local_port"],
            "remote_addr": conn["remote_addr"],
            "remote_port": conn["remote_port"],
            "pid": conn["pid"],
            "process_name": conn.get("process_name", "unknown"),
            "reason": "outbound_to_external",
        }
        self.buffer.insert_observation(
            ts=ts,
            vm_id=self.config.vm_id,
            obs_type=OUTBOUND_CONNECTION,
            session_id=None,
            source_ip=conn["remote_addr"],
            process_pid=conn["pid"],
            evidence_bits=OUTBOUND_C2,
            priority=PRIORITY_IMMEDIATE,
            detail=json.dumps(detail),
        )

    def _alert_lateral_movement(self, conn: dict[str, Any], ts: float) -> None:
        """Alert on outbound connection to internal IP (lateral movement)."""
        log.warning(
            "Lateral movement candidate: %s:%d -> %s:%d (PID %d, %s)",
            conn["local_addr"], conn["local_port"],
            conn["remote_addr"], conn["remote_port"], conn["pid"],
            conn.get("process_name", "?"),
        )
        detail = {
            "local_addr": conn["local_addr"],
            "local_port": conn["local_port"],
            "remote_addr": conn["remote_addr"],
            "remote_port": conn["remote_port"],
            "pid": conn["pid"],
            "process_name": conn.get("process_name", "unknown"),
            "reason": "outbound_to_internal",
        }
        self.buffer.insert_observation(
            ts=ts,
            vm_id=self.config.vm_id,
            obs_type=OBS_LATERAL_MOVEMENT,
            session_id=None,
            source_ip=conn["remote_addr"],
            process_pid=conn["pid"],
            evidence_bits=LATERAL_MOVEMENT_BIT,
            priority=PRIORITY_IMMEDIATE,
            detail=json.dumps(detail),
        )

    def get_listeners(self) -> list[tuple[str, int]]:
        """Return list of known listener (address, port) tuples."""
        return list(self._known_listeners)

    def get_outbound(self) -> list[tuple[str, int, str, int]]:
        """Return list of alerted outbound connection tuples."""
        return list(self._alerted_outbound)
