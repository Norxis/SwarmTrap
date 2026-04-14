"""File integrity monitor eye sensor — SHA-256 baseline and change detection.

Daemon thread that builds a SHA-256 manifest of monitored paths on startup
and polls for changes every 60s. Detects new and modified files.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from ..evidence_bits import FILE_DOWNLOAD
from ..observation import (
    FILE_WRITE,
    PRIORITY_HIGH,
    PRIORITY_NORMAL,
)

log = logging.getLogger("winhunt.eyes.file_integrity")

# Default monitored paths (Windows honeypot)
_DEFAULT_PATHS = [
    r"C:\inetpub\wwwroot",
    r"C:\Windows\System32\drivers\etc",
    r"C:\Users\Administrator\.ssh",
    r"C:\ProgramData\ssh",
    r"C:\Windows\Tasks",
]


def _sha256_file(path: str) -> str | None:
    """Compute SHA-256 hash of a file. Returns None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _walk_paths(paths: list[str]) -> dict[str, str]:
    """Walk directory trees and return {filepath: sha256} manifest."""
    manifest: dict[str, str] = {}
    for base in paths:
        if not os.path.exists(base):
            continue
        if os.path.isfile(base):
            h = _sha256_file(base)
            if h is not None:
                manifest[base] = h
            continue
        for root, _dirs, files in os.walk(base):
            for fname in files:
                fpath = os.path.join(root, fname)
                h = _sha256_file(fpath)
                if h is not None:
                    manifest[fpath] = h
    return manifest


class FileIntegrityMonitor(threading.Thread):
    """Daemon thread that monitors file system integrity via SHA-256."""

    def __init__(self, config: Any, buffer: Any, stop_event: threading.Event) -> None:
        super().__init__(daemon=True, name="eye-file-integrity")
        self.config = config
        self.buffer = buffer
        self.stop_event = stop_event
        self._poll_interval = 60
        self._monitored_paths: list[str] = list(_DEFAULT_PATHS)
        self._baseline: dict[str, str] = {}

    def run(self) -> None:
        log.info("File integrity monitor starting")
        if os.name != "nt":
            log.warning("Not running on Windows — file integrity monitor idle")
            while not self.stop_event.is_set():
                self.stop_event.wait(timeout=self._poll_interval)
            return

        # Build initial baseline
        log.info("Building file integrity baseline for %d paths", len(self._monitored_paths))
        self._baseline = _walk_paths(self._monitored_paths)
        self._store_baseline()
        log.info("Baseline built: %d files", len(self._baseline))

        while not self.stop_event.is_set():
            self.stop_event.wait(timeout=self._poll_interval)
            if self.stop_event.is_set():
                break
            try:
                self._poll()
            except Exception:
                log.exception("Error in file integrity poll")

        log.info("File integrity monitor stopped")

    def _poll(self) -> None:
        """Scan monitored paths and compare against baseline."""
        current = _walk_paths(self._monitored_paths)
        ts = time.time()

        # Detect new files
        new_files = set(current.keys()) - set(self._baseline.keys())
        for fpath in new_files:
            log.warning("New file detected: %s", fpath)
            detail = {
                "path": fpath,
                "sha256": current[fpath],
                "change_type": "new",
            }
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=FILE_WRITE,
                session_id=None,
                source_ip=None,
                process_pid=0,
                evidence_bits=FILE_DOWNLOAD,
                priority=PRIORITY_HIGH,
                detail=json.dumps(detail),
            )

        # Detect modified files
        for fpath, new_hash in current.items():
            if fpath in self._baseline and self._baseline[fpath] != new_hash:
                log.warning("Modified file detected: %s", fpath)
                detail = {
                    "path": fpath,
                    "sha256_old": self._baseline[fpath],
                    "sha256_new": new_hash,
                    "change_type": "modified",
                }
                self.buffer.insert_observation(
                    ts=ts,
                    vm_id=self.config.vm_id,
                    obs_type=FILE_WRITE,
                    session_id=None,
                    source_ip=None,
                    process_pid=0,
                    evidence_bits=FILE_DOWNLOAD,
                    priority=PRIORITY_HIGH,
                    detail=json.dumps(detail),
                )

        # Detect deleted files
        deleted_files = set(self._baseline.keys()) - set(current.keys())
        for fpath in deleted_files:
            log.warning("Deleted file detected: %s", fpath)
            detail = {
                "path": fpath,
                "sha256_old": self._baseline[fpath],
                "change_type": "deleted",
            }
            self.buffer.insert_observation(
                ts=ts,
                vm_id=self.config.vm_id,
                obs_type=FILE_WRITE,
                session_id=None,
                source_ip=None,
                process_pid=0,
                evidence_bits=FILE_DOWNLOAD,
                priority=PRIORITY_NORMAL,
                detail=json.dumps(detail),
            )

        # Update baseline
        self._baseline = current

    def _store_baseline(self) -> None:
        """Store baseline in buffer's file_baseline table."""
        try:
            for fpath, sha in self._baseline.items():
                try:
                    stat = os.stat(fpath)
                    size = stat.st_size
                    mtime = stat.st_mtime
                except OSError:
                    size = 0
                    mtime = 0.0
                self.buffer.upsert_file_baseline(fpath, sha, size, mtime)
        except Exception:
            log.exception("Failed to store file baseline in buffer")
