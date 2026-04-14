from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("winhunt.health")


class HealthMonitor:
    def __init__(self, config: Any):
        self.config = config

    async def run(self, stop_event: asyncio.Event) -> None:
        out = Path(self.config.local_download_dir) / "health.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        interval = getattr(self.config, "health_interval_s", 60)

        while not stop_event.is_set():
            payload = {
                "ts": time.time(),
                "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "status": "ok",
                "download_dir": self.config.local_download_dir,
                "download_dir_exists": Path(self.config.local_download_dir).is_dir(),
            }
            # Check download dir is writable
            try:
                test_file = Path(self.config.local_download_dir) / ".health_check"
                test_file.write_text("ok")
                test_file.unlink()
                payload["download_dir_writable"] = True
            except OSError:
                payload["download_dir_writable"] = False
                payload["status"] = "degraded"

            try:
                out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            except OSError as exc:
                log.warning("failed to write health file: %s", exc)

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue
