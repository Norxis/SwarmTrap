"""Frequency table for F7 fingerprint features.

Tracks how often each JA3/HASSH/HTTP-UA hash has been observed to compute
frequency-based features. Rare or unknown hashes (freq=0.0) are strong
signals for anomalous behavior.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("winhunt.inference.frequency")


class FrequencyTable:
    """Frequency lookup for fingerprint hashes (JA3, HASSH, HTTP UA).

    Maintains observation counts and total observations for computing
    frequency as count/total. Persists to/from JSON.
    """

    def __init__(self, path: str | None = None) -> None:
        self._counts: dict[str, int] = {}
        self._total: int = 0
        if path is not None:
            self.load(path)

    def lookup(self, hash_val: str | None) -> float:
        """Return frequency for a hash value.

        Args:
            hash_val: The fingerprint hash string. None or missing returns 0.0
                      (strong signal for unknown/novel fingerprint).

        Returns:
            Frequency as float 0.0-1.0.
        """
        if hash_val is None or hash_val not in self._counts:
            return 0.0
        if self._total == 0:
            return 0.0
        return self._counts[hash_val] / self._total

    def update(self, hash_val: str) -> None:
        """Increment observation count for a hash and recalculate total.

        Args:
            hash_val: The fingerprint hash string to record.
        """
        self._counts[hash_val] = self._counts.get(hash_val, 0) + 1
        self._total += 1

    def save(self, path: str) -> None:
        """Write frequency table to JSON file.

        Args:
            path: Output file path.
        """
        data: dict[str, Any] = {
            "total": self._total,
            "counts": self._counts,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=True, indent=2)
        log.debug("frequency table saved: %d entries, %d total observations",
                  len(self._counts), self._total)

    def load(self, path: str) -> None:
        """Read frequency table from JSON file.

        Args:
            path: Input file path. If file does not exist, table stays empty.
        """
        p = Path(path)
        if not p.exists():
            log.debug("frequency table not found at %s, starting empty", path)
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._total = int(data.get("total", 0))
            self._counts = {str(k): int(v) for k, v in data.get("counts", {}).items()}
            log.info("frequency table loaded: %d entries, %d total observations",
                     len(self._counts), self._total)
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            log.warning("failed to load frequency table from %s: %s", path, exc)
            self._counts = {}
            self._total = 0

    @property
    def size(self) -> int:
        """Number of unique hashes tracked."""
        return len(self._counts)

    @property
    def total_observations(self) -> int:
        """Total observation count."""
        return self._total
