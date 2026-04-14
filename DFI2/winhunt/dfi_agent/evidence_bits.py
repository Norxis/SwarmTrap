"""Named constants for the 16-bit evidence_bits field.

Bits 0-6 are backward-compatible with the original 7-bit schema.
Bits 7-15 are new for the AIO expansion.
"""
from __future__ import annotations

# ── Original bits (0-6) ──
AUTH_FAILURE         = 0x0001  # bit 0
AUTH_SUCCESS         = 0x0002  # bit 1
PROCESS_CREATE       = 0x0004  # bit 2
SERVICE_INSTALL      = 0x0008  # bit 3
SUSPICIOUS_COMMAND   = 0x0010  # bit 4
FILE_DOWNLOAD        = 0x0020  # bit 5
PRIVILEGE_ESCALATION = 0x0040  # bit 6

# ── New bits (7-15) ──
LATERAL_MOVEMENT     = 0x0080  # bit 7
OUTBOUND_C2          = 0x0100  # bit 8
CREDENTIAL_THEFT     = 0x0200  # bit 9
PERSISTENCE_MECHANISM = 0x0400  # bit 10
DATA_EXFILTRATION    = 0x0800  # bit 11
TOOL_DEPLOYMENT      = 0x1000  # bit 12
EVASION_ATTEMPT      = 0x2000  # bit 13
MEMORY_ONLY_TOOL     = 0x4000  # bit 14
DNS_TUNNELING        = 0x8000  # bit 15

# All bits for validation
ALL_BITS = {
    AUTH_FAILURE, AUTH_SUCCESS, PROCESS_CREATE, SERVICE_INSTALL,
    SUSPICIOUS_COMMAND, FILE_DOWNLOAD, PRIVILEGE_ESCALATION,
    LATERAL_MOVEMENT, OUTBOUND_C2, CREDENTIAL_THEFT,
    PERSISTENCE_MECHANISM, DATA_EXFILTRATION, TOOL_DEPLOYMENT,
    EVASION_ATTEMPT, MEMORY_ONLY_TOOL, DNS_TUNNELING,
}

# Name lookup for logging/display
BIT_NAMES: dict[int, str] = {
    AUTH_FAILURE: "AUTH_FAILURE",
    AUTH_SUCCESS: "AUTH_SUCCESS",
    PROCESS_CREATE: "PROCESS_CREATE",
    SERVICE_INSTALL: "SERVICE_INSTALL",
    SUSPICIOUS_COMMAND: "SUSPICIOUS_COMMAND",
    FILE_DOWNLOAD: "FILE_DOWNLOAD",
    PRIVILEGE_ESCALATION: "PRIVILEGE_ESCALATION",
    LATERAL_MOVEMENT: "LATERAL_MOVEMENT",
    OUTBOUND_C2: "OUTBOUND_C2",
    CREDENTIAL_THEFT: "CREDENTIAL_THEFT",
    PERSISTENCE_MECHANISM: "PERSISTENCE_MECHANISM",
    DATA_EXFILTRATION: "DATA_EXFILTRATION",
    TOOL_DEPLOYMENT: "TOOL_DEPLOYMENT",
    EVASION_ATTEMPT: "EVASION_ATTEMPT",
    MEMORY_ONLY_TOOL: "MEMORY_ONLY_TOOL",
    DNS_TUNNELING: "DNS_TUNNELING",
}

# Priority bits that trigger immediate export
PRIORITY_BITS = (
    AUTH_SUCCESS | OUTBOUND_C2 | PRIVILEGE_ESCALATION |
    CREDENTIAL_THEFT | TOOL_DEPLOYMENT
)


def describe_bits(evidence_bits: int) -> list[str]:
    """Return list of set bit names for display."""
    return [name for bit, name in BIT_NAMES.items() if evidence_bits & bit]
