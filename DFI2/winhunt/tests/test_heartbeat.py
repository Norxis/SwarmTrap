"""Unit tests for heartbeat generation."""
from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock


def _generate_heartbeat(config: object, buffer: object) -> dict:
    """Generate a heartbeat status dict.

    Contains: vm_id, timestamp, uptime_sec, buffer stats, and agent version.
    """
    from dfi_agent import __version__

    now = time.time()
    start_time = getattr(config, "_start_time", now - 3600)

    hb = {
        "vm_id": config.vm_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "uptime_sec": int(now - start_time),
        "agent_version": __version__,
        "buffer": {
            "db_size_mb": buffer.db_size_mb(),
            "event_count": buffer.event_count(),
            "flow_count": buffer.get_flow_count(),
            "unpulled_events": buffer.event_count(pulled=0),
            "unpulled_flows": buffer.get_flow_count(pulled=0),
        },
    }
    return hb


def _write_heartbeat(config: object, buffer: object, staging_dir: str) -> str:
    """Generate heartbeat and write to staging dir as JSON.

    Returns the path of the written file.
    """
    hb = _generate_heartbeat(config, buffer)
    Path(staging_dir).mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    filename = f"heartbeat_{config.vm_id}_{ts}.json"
    filepath = os.path.join(staging_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(hb, f, separators=(",", ":"))
    return filepath


class TestHeartbeat(unittest.TestCase):
    def _make_config(self):
        config = MagicMock()
        config.vm_id = "WINHUNT-SRV25"
        config._start_time = time.time() - 3600  # started 1 hour ago
        return config

    def _make_buffer(self):
        buffer = MagicMock()
        buffer.db_size_mb.return_value = 12.5
        buffer.event_count.side_effect = lambda pulled=None: 100 if pulled is None else 42
        buffer.get_flow_count.side_effect = lambda pulled=None: 500 if pulled is None else 30
        return buffer

    def test_heartbeat_structure(self):
        """Heartbeat JSON must have required fields."""
        config = self._make_config()
        buffer = self._make_buffer()

        hb = _generate_heartbeat(config, buffer)

        # Required top-level fields
        self.assertIn("vm_id", hb)
        self.assertIn("timestamp", hb)
        self.assertIn("uptime_sec", hb)
        self.assertIn("agent_version", hb)
        self.assertIn("buffer", hb)

        # VM ID matches config
        self.assertEqual(hb["vm_id"], "WINHUNT-SRV25")

        # Uptime is reasonable (around 3600s)
        self.assertGreater(hb["uptime_sec"], 3500)
        self.assertLess(hb["uptime_sec"], 3700)

        # Buffer sub-fields
        buf = hb["buffer"]
        self.assertIn("db_size_mb", buf)
        self.assertIn("event_count", buf)
        self.assertIn("flow_count", buf)
        self.assertIn("unpulled_events", buf)
        self.assertIn("unpulled_flows", buf)
        self.assertEqual(buf["db_size_mb"], 12.5)

    def test_heartbeat_writes_file(self):
        """Heartbeat should write a JSON file to the staging directory."""
        import tempfile

        config = self._make_config()
        buffer = self._make_buffer()

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = _write_heartbeat(config, buffer, tmpdir)

            # File should exist
            self.assertTrue(os.path.exists(filepath))

            # File should contain valid JSON with required fields
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(data["vm_id"], "WINHUNT-SRV25")
            self.assertIn("timestamp", data)
            self.assertIn("uptime_sec", data)
            self.assertIn("buffer", data)

            # Filename contains vm_id
            self.assertIn("WINHUNT-SRV25", os.path.basename(filepath))


if __name__ == "__main__":
    unittest.main()
