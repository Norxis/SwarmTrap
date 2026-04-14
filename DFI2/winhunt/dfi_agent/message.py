"""Upstream message envelope for all agent->orchestrator communication."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MessageType(Enum):
    """Types of messages an agent can send upstream."""
    OBSERVATION = "OBSERVATION"
    COMMAND_RESULT = "COMMAND_RESULT"
    HEARTBEAT = "HEARTBEAT"
    ALERT = "ALERT"
    PREDICTION = "PREDICTION"


def create_envelope(
    msg_type: MessageType,
    vm_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Create a structured message envelope for upstream communication.

    Args:
        msg_type: The type of message being sent.
        vm_id: The agent's VM identifier.
        payload: The message payload dict.

    Returns:
        A dict with msg_type, vm_id, timestamp, and payload.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "msg_type": msg_type.value,
        "vm_id": vm_id,
        "timestamp": ts,
        "payload": payload,
    }


def serialize_envelope(envelope: dict[str, Any]) -> str:
    """Serialize an envelope dict to a compact JSON string.

    Args:
        envelope: The message envelope dict (from create_envelope).

    Returns:
        JSON string with no extra whitespace.
    """
    return json.dumps(envelope, ensure_ascii=True, separators=(",", ":"))
