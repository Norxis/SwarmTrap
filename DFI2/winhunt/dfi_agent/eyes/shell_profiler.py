"""Shell profiler eye sensor — session behavior classification from 4688 events.

Not a thread. Post-processing layer that accumulates per-session command
history (keyed by logon_id) and classifies attacker behavior after 60s
of activity.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from ..evidence_bits import SUSPICIOUS_COMMAND as SUSPICIOUS_COMMAND_BIT
from ..observation import (
    SUSPICIOUS_COMMAND as OBS_SUSPICIOUS_COMMAND,
    PRIORITY_HIGH,
    PRIORITY_NORMAL,
)

log = logging.getLogger("winhunt.eyes.shell_profiler")

# Classification constants
CLASS_AUTOMATED_SCANNER = "automated_scanner"
CLASS_MANUAL_OPERATOR = "manual_operator"
CLASS_BOTNET_DROPPER = "botnet_dropper"
CLASS_SOPHISTICATED_OPERATOR = "sophisticated_operator"
CLASS_UNKNOWN = "unknown"

# Minimum time (seconds) from first command before classification
_CLASSIFY_DELAY_S = 60

# VM/sandbox detection commands (for sophisticated_operator check)
_VM_CHECK_COMMANDS = {
    "systeminfo",
    "wmic baseboard",
    "wmic computersystem get model",
    "get-mpcomputerstatus",
    "reg query",
    "dmidecode",
    "lshw",
    "systemd-detect-virt",
}

# Payload/dropper commands (for botnet_dropper check)
_DROPPER_COMMANDS = {
    "certutil",
    "bitsadmin",
    "invoke-webrequest",
    "iwr",
    "wget",
    "curl",
    "downloadfile",
    "downloadstring",
    "start-bitstransfer",
    "mshta",
    "regsvr32",
    "rundll32",
}


class ShellProfiler:
    """Classifies attacker sessions based on command timing and patterns.

    Accumulates per-session command history keyed by logon_id. After 60s
    from the first command in a session, classifies the session as one of:

    - automated_scanner: sub-second gaps, fixed command order
    - manual_operator: variable timing with >2s gaps
    - botnet_dropper: direct to payload, <3 commands total
    - sophisticated_operator: VM/sandbox checks before payload
    """

    def __init__(self, config: Any, buffer: Any) -> None:
        self.config = config
        self.buffer = buffer
        # logon_id -> list of (timestamp, command)
        self._sessions: dict[str, list[tuple[float, str]]] = {}
        # logon_id -> classification result (None = not yet classified)
        self._classifications: dict[str, str | None] = {}

    def process_command(self, logon_id: str, cmd: str, ts: float) -> str | None:
        """Add a command to a session's history and classify if ready.

        Args:
            logon_id: Windows logon ID identifying the session.
            cmd: Command line string from 4688 event.
            ts: Event timestamp as Unix epoch float.

        Returns:
            Classification string if classification triggered, None otherwise.
        """
        if not logon_id:
            return None

        # Initialize session if new
        if logon_id not in self._sessions:
            self._sessions[logon_id] = []
            self._classifications[logon_id] = None

        self._sessions[logon_id].append((ts, cmd))

        # Already classified — return existing classification
        if self._classifications[logon_id] is not None:
            return self._classifications[logon_id]

        # Check if enough time has elapsed for classification
        history = self._sessions[logon_id]
        first_ts = history[0][0]
        elapsed = ts - first_ts

        if elapsed < _CLASSIFY_DELAY_S:
            return None

        # Classify the session
        classification = self._classify(history)
        self._classifications[logon_id] = classification

        log.info(
            "Session %s classified as %s (%d commands over %.1fs)",
            logon_id, classification, len(history), elapsed,
        )

        # Emit observation for non-unknown classifications
        if classification != CLASS_UNKNOWN:
            priority = PRIORITY_HIGH if classification in (
                CLASS_SOPHISTICATED_OPERATOR, CLASS_BOTNET_DROPPER
            ) else PRIORITY_NORMAL

            detail = {
                "logon_id": logon_id,
                "classification": classification,
                "command_count": len(history),
                "duration_s": round(elapsed, 1),
                "commands": [cmd for _, cmd in history[-10:]],
            }
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=OBS_SUSPICIOUS_COMMAND,
                session_id=logon_id,
                source_ip=None,
                process_pid=0,
                evidence_bits=SUSPICIOUS_COMMAND_BIT,
                priority=priority,
                detail=json.dumps(detail),
            )

        return classification

    def _classify(self, history: list[tuple[float, str]]) -> str:
        """Classify a session based on command timing and content.

        Args:
            history: List of (timestamp, command) tuples.

        Returns:
            Classification string.
        """
        if len(history) < 2:
            # Single command — check if it's a direct dropper
            if len(history) == 1:
                cmd_lower = history[0][1].lower()
                if any(d in cmd_lower for d in _DROPPER_COMMANDS):
                    return CLASS_BOTNET_DROPPER
            return CLASS_UNKNOWN

        # Calculate inter-command gaps
        gaps: list[float] = []
        for i in range(1, len(history)):
            gap = history[i][0] - history[i - 1][0]
            gaps.append(gap)

        avg_gap = sum(gaps) / len(gaps) if gaps else 0.0
        max_gap = max(gaps) if gaps else 0.0
        min_gap = min(gaps) if gaps else 0.0

        # Check for botnet_dropper: very few commands, direct to payload
        if len(history) <= 3:
            cmds_lower = [cmd.lower() for _, cmd in history]
            has_dropper = any(
                any(d in c for d in _DROPPER_COMMANDS)
                for c in cmds_lower
            )
            if has_dropper:
                return CLASS_BOTNET_DROPPER

        # Check for sophisticated_operator: VM checks come first
        cmds_lower = [cmd.lower() for _, cmd in history]
        first_cmds = cmds_lower[:min(5, len(cmds_lower))]
        vm_check_count = sum(
            1 for c in first_cmds
            if any(vc in c for vc in _VM_CHECK_COMMANDS)
        )
        if vm_check_count >= 2:
            return CLASS_SOPHISTICATED_OPERATOR

        # Check for automated_scanner: sub-second, fixed order
        if avg_gap < 1.0 and max_gap < 2.0 and len(history) >= 5:
            # Consistent timing suggests automation
            if max_gap - min_gap < 0.5:
                return CLASS_AUTOMATED_SCANNER

        # Check for manual_operator: variable timing with >2s gaps
        if avg_gap > 2.0 and len(history) >= 3:
            return CLASS_MANUAL_OPERATOR

        # Fallback: if mostly sub-second but many commands
        if avg_gap < 1.0 and len(history) >= 5:
            return CLASS_AUTOMATED_SCANNER

        return CLASS_UNKNOWN

    def get_session_history(self, logon_id: str) -> list[tuple[float, str]] | None:
        """Return command history for a session, or None if unknown."""
        return self._sessions.get(logon_id)

    def get_classification(self, logon_id: str) -> str | None:
        """Return classification for a session, or None if not yet classified."""
        return self._classifications.get(logon_id)
