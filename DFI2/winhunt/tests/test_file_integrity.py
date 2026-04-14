"""Unit tests for file integrity monitoring — baseline build and diff detection."""
from __future__ import annotations

import hashlib
import os
import unittest
from unittest.mock import MagicMock, patch


def _build_baseline(root_dir: str) -> dict[str, str]:
    """Build a baseline manifest: {relative_path: sha256_hex, ...}."""
    manifest: dict[str, str] = {}
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root_dir)
            h = hashlib.sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            manifest[rel] = h.hexdigest()
    return manifest


def _diff_baseline(baseline: dict[str, str], current: dict[str, str]) -> dict:
    """Compare current manifest against baseline.

    Returns:
        {
            "modified": [paths where hash changed],
            "new": [paths in current but not baseline],
            "deleted": [paths in baseline but not current],
        }
    """
    modified = []
    new = []
    deleted = []

    for path, cur_hash in current.items():
        if path not in baseline:
            new.append(path)
        elif baseline[path] != cur_hash:
            modified.append(path)

    for path in baseline:
        if path not in current:
            deleted.append(path)

    return {"modified": modified, "new": new, "deleted": deleted}


class TestFileIntegrity(unittest.TestCase):
    def test_baseline_build(self, tmp_path=None):
        """Baseline manifest should be created correctly."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            f1 = os.path.join(tmpdir, "file1.txt")
            f2 = os.path.join(tmpdir, "subdir", "file2.txt")
            os.makedirs(os.path.join(tmpdir, "subdir"), exist_ok=True)
            with open(f1, "w") as f:
                f.write("hello")
            with open(f2, "w") as f:
                f.write("world")

            manifest = _build_baseline(tmpdir)

            self.assertEqual(len(manifest), 2)
            self.assertIn("file1.txt", manifest)
            self.assertIn(os.path.join("subdir", "file2.txt"), manifest)

            # Verify hashes are correct SHA-256
            expected_hash_1 = hashlib.sha256(b"hello").hexdigest()
            self.assertEqual(manifest["file1.txt"], expected_hash_1)

            expected_hash_2 = hashlib.sha256(b"world").hexdigest()
            self.assertEqual(manifest[os.path.join("subdir", "file2.txt")], expected_hash_2)

    def test_diff_detection(self):
        """Modified, new, and deleted files should all be detected."""
        baseline = {
            "file1.txt": "aaa111",
            "file2.txt": "bbb222",
            "file3.txt": "ccc333",
        }

        current = {
            "file1.txt": "aaa111",      # unchanged
            "file2.txt": "MODIFIED999",  # modified
            # file3.txt is deleted (not in current)
            "file4.txt": "ddd444",       # new file
        }

        diff = _diff_baseline(baseline, current)

        # Modified file detected
        self.assertIn("file2.txt", diff["modified"])
        self.assertEqual(len(diff["modified"]), 1)

        # New file detected
        self.assertIn("file4.txt", diff["new"])
        self.assertEqual(len(diff["new"]), 1)

        # Deleted file detected
        self.assertIn("file3.txt", diff["deleted"])
        self.assertEqual(len(diff["deleted"]), 1)

    def test_no_changes(self):
        """Identical baseline and current should show no diffs."""
        baseline = {"a.txt": "hash1", "b.txt": "hash2"}
        current = {"a.txt": "hash1", "b.txt": "hash2"}

        diff = _diff_baseline(baseline, current)
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["new"], [])
        self.assertEqual(diff["deleted"], [])

    def test_empty_baseline(self):
        """Empty baseline means everything is new."""
        current = {"new1.txt": "h1", "new2.txt": "h2"}
        diff = _diff_baseline({}, current)
        self.assertEqual(len(diff["new"]), 2)
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["deleted"], [])


if __name__ == "__main__":
    unittest.main()
