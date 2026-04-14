"""Honeypot detection eye sensor — pattern matcher on 4688/4104 events.

Not a thread. Checks commands against known VM/honeypot detection patterns
used by sophisticated attackers to identify sandboxed environments.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from ..evidence_bits import EVASION_ATTEMPT
from ..observation import (
    EVASION,
    HONEYPOT_DETECTION as OBS_HONEYPOT_DETECTION,
    PRIORITY_HIGH,
)

log = logging.getLogger("winhunt.eyes.honeypot_detection")

# Individual VM/honeypot detection patterns
_VM_DETECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"systemd-detect-virt", re.IGNORECASE),
    re.compile(r"wmic\s+baseboard", re.IGNORECASE),
    re.compile(r"Get-MpComputerStatus", re.IGNORECASE),
    re.compile(r"reg\s+query\s+.*VirtualMachineGuest", re.IGNORECASE),
    re.compile(r"wmic\s+computersystem\s+get\s+model", re.IGNORECASE),
    re.compile(r"dmidecode", re.IGNORECASE),
    re.compile(r"lshw", re.IGNORECASE),
    re.compile(r"systeminfo", re.IGNORECASE),
]

# Recon commands that are suspicious only when combined with other recon
_RECON_PATTERNS: list[re.Pattern] = [
    re.compile(r"hostname", re.IGNORECASE),
    re.compile(r"ipconfig\s+/all", re.IGNORECASE),
]

# Minimum number of distinct recon commands within a window to trigger alert
_RECON_COMBO_THRESHOLD = 2
_RECON_WINDOW_S = 300  # 5 minutes


class HoneypotDetector:
    """Detects VM/honeypot detection attempts from 4688/4104 events.

    Checks commands against known patterns used by attackers to identify
    virtual machines, sandboxes, and honeypot environments. Emits
    EVASION_ATTEMPT when patterns match.
    """

    def __init__(self, config: Any, buffer: Any) -> None:
        self.config = config
        self.buffer = buffer
        # Track recent recon commands: list of (ts, pattern_name)
        self._recent_recon: list[tuple[float, str]] = []

    def check_event(self, event_id: int, cmd: str, ts: float) -> bool:
        """Check if a command matches VM detection patterns.

        Args:
            event_id: Windows event ID (4688 process create, 4104 script block).
            cmd: Command line or script block text.
            ts: Event timestamp as Unix epoch float.

        Returns:
            True if an evasion attempt was detected, False otherwise.
        """
        if not cmd:
            return False

        # Only process 4688 (process create) and 4104 (script block) events
        if event_id not in (4688, 4104):
            return False

        detected = False

        # Check direct VM detection patterns
        for pattern in _VM_DETECTION_PATTERNS:
            if pattern.search(cmd):
                log.warning(
                    "VM detection command: %s (event %d)",
                    cmd[:200], event_id,
                )
                detail = {
                    "event_id": event_id,
                    "command": cmd[:500],
                    "pattern": pattern.pattern,
                    "reason": "vm_detection_command",
                }
                self.buffer.insert_observation(
                    ts=ts,
                    vm_id=self.config.vm_id,
                    obs_type=OBS_HONEYPOT_DETECTION,
                    session_id=None,
                    source_ip=None,
                    process_pid=0,
                    evidence_bits=EVASION_ATTEMPT,
                    priority=PRIORITY_HIGH,
                    detail=json.dumps(detail),
                )
                detected = True
                break  # One match per command is enough

        # Check recon combination patterns
        for pattern in _RECON_PATTERNS:
            if pattern.search(cmd):
                self._recent_recon.append((ts, pattern.pattern))
                break

        # Evict old recon entries
        cutoff = ts - _RECON_WINDOW_S
        self._recent_recon = [
            (t, p) for t, p in self._recent_recon if t >= cutoff
        ]

        # Check if combined recon exceeds threshold
        unique_patterns = {p for _, p in self._recent_recon}
        if len(unique_patterns) >= _RECON_COMBO_THRESHOLD and not detected:
            # Also check if combined with any VM detection pattern
            # hostname + ipconfig /all alone isn't evasion, but combined
            # with other recon it may be
            log.warning(
                "Combined recon detected: %d unique patterns in %ds",
                len(unique_patterns), _RECON_WINDOW_S,
            )
            detail = {
                "event_id": event_id,
                "command": cmd[:500],
                "recon_patterns": list(unique_patterns),
                "recon_count": len(self._recent_recon),
                "reason": "combined_recon_activity",
            }
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=EVASION,
                session_id=None,
                source_ip=None,
                process_pid=0,
                evidence_bits=EVASION_ATTEMPT,
                priority=PRIORITY_HIGH,
                detail=json.dumps(detail),
            )
            detected = True
            # Reset recon tracker after alert to avoid repeated alerts
            self._recent_recon.clear()

        return detected
