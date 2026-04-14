"""Unit tests for evidence_bits constants."""
from __future__ import annotations

import unittest

from dfi_agent.evidence_bits import (
    ALL_BITS,
    AUTH_FAILURE,
    AUTH_SUCCESS,
    BIT_NAMES,
    CREDENTIAL_THEFT,
    DNS_TUNNELING,
    DATA_EXFILTRATION,
    EVASION_ATTEMPT,
    FILE_DOWNLOAD,
    LATERAL_MOVEMENT,
    MEMORY_ONLY_TOOL,
    OUTBOUND_C2,
    PERSISTENCE_MECHANISM,
    PRIORITY_BITS,
    PRIVILEGE_ESCALATION,
    PROCESS_CREATE,
    SERVICE_INSTALL,
    SUSPICIOUS_COMMAND,
    TOOL_DEPLOYMENT,
    describe_bits,
)


class TestEvidenceBits(unittest.TestCase):
    def test_all_unique(self):
        """All 16 bit values must be unique."""
        self.assertEqual(len(ALL_BITS), 16)

    def test_no_overlap(self):
        """No two bits share the same power of 2."""
        seen = set()
        for bit in ALL_BITS:
            # Each value must be a power of 2
            self.assertTrue(
                bit > 0 and (bit & (bit - 1)) == 0,
                f"0x{bit:04X} is not a power of 2",
            )
            self.assertNotIn(bit, seen, f"0x{bit:04X} is duplicated")
            seen.add(bit)

    def test_backward_compat(self):
        """Bits 0-6 match original values (0x01 through 0x40)."""
        expected = [
            (AUTH_FAILURE, 0x01),
            (AUTH_SUCCESS, 0x02),
            (PROCESS_CREATE, 0x04),
            (SERVICE_INSTALL, 0x08),
            (SUSPICIOUS_COMMAND, 0x10),
            (FILE_DOWNLOAD, 0x20),
            (PRIVILEGE_ESCALATION, 0x40),
        ]
        for actual, expected_val in expected:
            self.assertEqual(
                actual, expected_val,
                f"Expected 0x{expected_val:02X}, got 0x{actual:04X}",
            )

    def test_describe_bits(self):
        """describe_bits returns correct names for set bits."""
        # Single bit
        names = describe_bits(AUTH_FAILURE)
        self.assertEqual(names, ["AUTH_FAILURE"])

        # Multiple bits
        combined = AUTH_FAILURE | AUTH_SUCCESS | OUTBOUND_C2
        names = describe_bits(combined)
        self.assertIn("AUTH_FAILURE", names)
        self.assertIn("AUTH_SUCCESS", names)
        self.assertIn("OUTBOUND_C2", names)
        self.assertEqual(len(names), 3)

        # No bits
        names = describe_bits(0)
        self.assertEqual(names, [])

    def test_priority_bits(self):
        """PRIORITY_BITS contains the correct combination."""
        expected = (
            AUTH_SUCCESS | OUTBOUND_C2 | PRIVILEGE_ESCALATION |
            CREDENTIAL_THEFT | TOOL_DEPLOYMENT
        )
        self.assertEqual(PRIORITY_BITS, expected)

        # Verify individual bits are set
        self.assertTrue(PRIORITY_BITS & AUTH_SUCCESS)
        self.assertTrue(PRIORITY_BITS & OUTBOUND_C2)
        self.assertTrue(PRIORITY_BITS & PRIVILEGE_ESCALATION)
        self.assertTrue(PRIORITY_BITS & CREDENTIAL_THEFT)
        self.assertTrue(PRIORITY_BITS & TOOL_DEPLOYMENT)

        # Verify non-priority bits are NOT set
        self.assertFalse(PRIORITY_BITS & AUTH_FAILURE)
        self.assertFalse(PRIORITY_BITS & LATERAL_MOVEMENT)


if __name__ == "__main__":
    unittest.main()
