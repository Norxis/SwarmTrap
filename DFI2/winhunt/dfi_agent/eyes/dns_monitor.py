"""DNS monitor eye sensor — event-driven analysis of DNS Client events.

Not a thread. Called by the evidence collector when DNS Client Operational
channel events arrive (event ID 3006). Detects:
- DNS tunneling via high-frequency queries from a single process
- DGA-style C2 via high-entropy domain names
"""
from __future__ import annotations

import collections
import json
import logging
import math
import time
from typing import Any

from ..evidence_bits import DNS_TUNNELING, OUTBOUND_C2
from ..observation import (
    DNS_QUERY,
    OUTBOUND_CONNECTION,
    PRIORITY_HIGH,
    PRIORITY_IMMEDIATE,
)

log = logging.getLogger("winhunt.eyes.dns_monitor")

# Thresholds
_TUNNEL_QUERY_THRESHOLD = 50   # queries per 60s from single process
_TUNNEL_WINDOW_S = 60          # sliding window for query counting
_ENTROPY_THRESHOLD = 3.5       # bits per char — above = potential DGA


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _extract_domain(query_name: str) -> str:
    """Extract the registrable domain portion for entropy analysis.

    For 'abcdef123.evil.com' returns 'abcdef123' (the subdomain label).
    For 'evil.com' returns 'evil'.
    """
    parts = query_name.strip().rstrip(".").split(".")
    if len(parts) <= 2:
        return parts[0] if parts else ""
    # Return the leftmost subdomain label (most likely to be DGA-generated)
    return parts[0]


class DnsMonitor:
    """Event-driven DNS query analyzer.

    Called by the evidence collector for DNS Client Operational channel
    events. Maintains per-process query counts and detects tunneling
    and DGA-style C2 domains.
    """

    def __init__(self, config: Any, buffer: Any) -> None:
        self.config = config
        self.buffer = buffer
        # Per-process total query count
        self._process_query_count: dict[int, int] = collections.defaultdict(int)
        # Per-process recent queries: pid -> deque of (ts, domain)
        self._process_recent: dict[int, collections.deque] = {}
        # Already-alerted tunnel PIDs to avoid spam
        self._tunnel_alerted: set[int] = set()

    def process_dns_event(self, event_id: int, inserts: list[str],
                          msg: str, ts: float) -> None:
        """Process a DNS Client Operational event (event ID 3006).

        Args:
            event_id: Windows event ID (expected 3006 for DNS queries).
            inserts: StringInserts from the event record.
            msg: Full event message text.
            ts: Event timestamp as Unix epoch float.
        """
        if event_id != 3006:
            return

        # Extract query name from inserts or message
        query_name = ""
        if inserts and len(inserts) > 0:
            query_name = inserts[0].strip()
        if not query_name and msg:
            # Fallback: try to parse from message text
            for token in msg.split():
                if "." in token and not token.startswith("("):
                    query_name = token.strip()
                    break

        if not query_name:
            return

        # Extract PID — typically in inserts[1] or derive from context
        pid = 0
        if inserts and len(inserts) > 1:
            try:
                pid = int(inserts[1])
            except (ValueError, TypeError):
                pass

        # Track per-process queries
        self._process_query_count[pid] += 1

        if pid not in self._process_recent:
            self._process_recent[pid] = collections.deque()

        recent = self._process_recent[pid]
        recent.append((ts, query_name))

        # Evict entries older than window
        cutoff = ts - _TUNNEL_WINDOW_S
        while recent and recent[0][0] < cutoff:
            recent.popleft()

        # Check for DNS tunneling: high-frequency from single process
        if len(recent) > _TUNNEL_QUERY_THRESHOLD and pid not in self._tunnel_alerted:
            self._tunnel_alerted.add(pid)
            log.warning(
                "DNS tunneling candidate: PID %d made %d queries in %ds",
                pid, len(recent), _TUNNEL_WINDOW_S,
            )
            detail = {
                "pid": pid,
                "query_count_60s": len(recent),
                "sample_queries": [q for _, q in list(recent)[-10:]],
                "reason": "high_frequency_dns",
            }
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=DNS_QUERY,
                session_id=None,
                source_ip=None,
                process_pid=pid,
                evidence_bits=DNS_TUNNELING,
                priority=PRIORITY_IMMEDIATE,
                detail=json.dumps(detail),
            )

        # Check for DGA-style high-entropy domains
        subdomain = _extract_domain(query_name)
        if len(subdomain) >= 6:  # Only check domains with meaningful length
            entropy = _shannon_entropy(subdomain)
            if entropy > _ENTROPY_THRESHOLD:
                log.info(
                    "High-entropy domain: %s (%.2f bits) from PID %d",
                    query_name, entropy, pid,
                )
                detail = {
                    "pid": pid,
                    "query_name": query_name,
                    "subdomain": subdomain,
                    "entropy": round(entropy, 3),
                    "reason": "high_entropy_dga_candidate",
                }
                self.buffer.insert_observation(
                    ts=ts,
                    vm_id=self.config.vm_id,
                    obs_type=OUTBOUND_CONNECTION,
                    session_id=None,
                    source_ip=None,
                    process_pid=pid,
                    evidence_bits=OUTBOUND_C2,
                    priority=PRIORITY_HIGH,
                    detail=json.dumps(detail),
                )
