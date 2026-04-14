"""Test that config path normalization prevents backslash escape corruption."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from dfi_agent.config import AgentConfig, _fix_path


class TestFixPath(unittest.TestCase):
    def test_single_backslash(self):
        self.assertEqual(_fix_path("C:\\Program Files\\DFI"), "C:/Program Files/DFI")

    def test_double_backslash(self):
        """Double backslash (the '\\\\' mistake) should also be normalized."""
        self.assertEqual(_fix_path("C:\\\\Program Files\\\\DFI"), "C://Program Files//DFI")

    def test_forward_slash_unchanged(self):
        self.assertEqual(_fix_path("C:/already/good"), "C:/already/good")

    def test_mixed_slashes(self):
        self.assertEqual(_fix_path("C:\\mixed/path\\here"), "C:/mixed/path/here")


class TestConfigPathNormalization(unittest.TestCase):
    def test_defaults_normalized(self):
        """Default config paths should all use forward slashes."""
        cfg = AgentConfig()
        self.assertNotIn("\\", cfg.buffer_path)
        self.assertNotIn("\\", cfg.log_dir)
        self.assertNotIn("\\", cfg.exporter.staging_dir)
        self.assertNotIn("\\", cfg.inference.model_path)
        self.assertNotIn("\\", cfg.hand.action_log_path)
        for p in cfg.eyes.file_integrity_paths:
            self.assertNotIn("\\", p, f"backslash in file_integrity_paths: {p}")

    def test_from_json_normalizes(self):
        """Paths loaded from JSON with backslashes should be normalized."""
        config_data = {
            "vm_id": "test",
            "buffer_path": "C:\\Program Files\\DFI\\data\\agent_buffer.db",
            "log_dir": "C:\\Program Files\\DFI\\logs",
            "exporter": {
                "staging_dir": "C:\\Program Files\\DFI\\staging",
            },
            "inference": {
                "model_path": "C:\\Program Files\\DFI\\models\\xgb_model.json",
            },
            "hand": {
                "action_log_path": "C:\\Program Files\\DFI\\logs\\command_log.jsonl",
            },
            "eyes": {
                "file_integrity_paths": [
                    "C:\\inetpub\\wwwroot",
                    "C:\\Windows\\Tasks",
                ],
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            tmp = f.name
        try:
            cfg = AgentConfig.from_json(tmp)
            self.assertNotIn("\\", cfg.buffer_path)
            self.assertNotIn("\\", cfg.log_dir)
            self.assertNotIn("\\", cfg.exporter.staging_dir)
            self.assertNotIn("\\", cfg.inference.model_path)
            self.assertNotIn("\\", cfg.hand.action_log_path)
            for p in cfg.eyes.file_integrity_paths:
                self.assertNotIn("\\", p, f"backslash in {p}")
            # Verify paths are correct
            self.assertEqual(cfg.buffer_path, "C:/Program Files/DFI/data/agent_buffer.db")
            self.assertEqual(cfg.log_dir, "C:/Program Files/DFI/logs")
        finally:
            os.unlink(tmp)

    def test_double_backslash_config(self):
        """Even double-backslash paths from JSON should be corrected."""
        config_data = {
            "vm_id": "test",
            "buffer_path": "C:\\\\Program Files\\\\DFI\\\\data\\\\agent_buffer.db",
            "log_dir": "C:\\\\Program Files\\\\DFI\\\\logs",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            tmp = f.name
        try:
            cfg = AgentConfig.from_json(tmp)
            self.assertNotIn("\\", cfg.buffer_path)
            self.assertNotIn("\\", cfg.log_dir)
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
