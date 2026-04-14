"""Heartbeat thread -- emits structured agent health to staging."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dfi_agent

log = logging.getLogger("winhunt.heartbeat")

# Optional psutil for CPU metrics
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class HeartbeatThread(threading.Thread):
    """Periodic heartbeat emitter -- writes agent health to staging as NDJSON."""

    def __init__(
        self,
        config: Any,
        buffer: Any,
        capture_thread: Any,
        evidence_thread: Any,
        flow_table: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="dfi-heartbeat", daemon=True)
        self.config = config
        self.buffer = buffer
        self.capture_thread = capture_thread
        self.evidence_thread = evidence_thread
        self.flow_table = flow_table
        self.stop_event = stop_event
        self._start_ts = time.monotonic()
        self._seq = 0
        self._staging_dir = Path(config.exporter.staging_dir)
        self._staging_dir.mkdir(parents=True, exist_ok=True)

        # Heartbeat interval -- config.comm.heartbeat_interval_s if present, else 60
        self._interval_s: float = 60.0
        comm = getattr(config, "comm", None)
        if comm is not None:
            self._interval_s = float(getattr(comm, "heartbeat_interval_s", 60.0))

        # Process handle for memory measurement
        self._process: Any = None
        if HAS_PSUTIL:
            try:
                self._process = psutil.Process(os.getpid())
            except Exception:
                pass

    def run(self) -> None:
        log.info("heartbeat thread started (interval=%ds)", self._interval_s)
        while not self.stop_event.is_set():
            self.stop_event.wait(self._interval_s)
            if self.stop_event.is_set():
                break
            try:
                self._emit_heartbeat()
            except Exception as exc:
                log.error("heartbeat error: %s", exc)

    def _emit_heartbeat(self) -> None:
        now = datetime.now(timezone.utc)
        ts_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # CPU percent
        cpu_pct: float | None = None
        if HAS_PSUTIL and self._process is not None:
            try:
                cpu_pct = self._process.cpu_percent(interval=0)
            except Exception:
                cpu_pct = None

        # Memory RSS in MB
        mem_mb: float | None = None
        if HAS_PSUTIL and self._process is not None:
            try:
                mem_mb = round(self._process.memory_info().rss / (1024 * 1024), 2)
            except Exception:
                mem_mb = None

        # Queue depths
        unpulled_events = self.buffer.event_count(pulled=0)
        unpulled_flows = self.buffer.get_flow_count(pulled=0)

        # Active sessions
        active_sessions = self.flow_table.active_flow_count

        # Uptime
        uptime_sec = round(time.monotonic() - self._start_ts, 1)

        # Model version (from config if available)
        model_version: str | None = None
        inference_cfg = getattr(self.config, "inference", None)
        if inference_cfg is not None:
            model_version = getattr(inference_cfg, "model_version", None)

        # Capture stats
        packets_received = getattr(self.capture_thread, "packets_received", 0)
        packets_dropped = getattr(self.capture_thread, "packets_dropped", 0)
        flows_emitted = getattr(self.flow_table, "flows_emitted", 0)

        heartbeat: dict[str, Any] = {
            "msg_type": "HEARTBEAT",
            "vm_id": self.config.vm_id,
            "agent_version": dfi_agent.__version__,
            "timestamp": ts_iso,
            "cpu_pct": cpu_pct,
            "mem_mb": mem_mb,
            "unpulled_events": unpulled_events,
            "unpulled_flows": unpulled_flows,
            "active_sessions": active_sessions,
            "uptime_sec": uptime_sec,
            "model_version": model_version,
            "capture": {
                "packets_received": packets_received,
                "packets_dropped": packets_dropped,
                "flows_emitted": flows_emitted,
            },
        }

        # Write to staging dir
        self._seq += 1
        ts_file = int(time.time() * 1000)
        filename = f"dfi_heartbeat_{ts_file}_{self._seq}.ndjson"
        outpath = self._staging_dir / filename

        try:
            with open(outpath, "w", encoding="utf-8") as f:
                f.write(json.dumps(heartbeat, ensure_ascii=True, separators=(",", ":")) + "\n")
            log.debug("heartbeat written: %s (uptime=%ds, active=%d)",
                      filename, uptime_sec, active_sessions)
        except OSError as exc:
            log.error("failed to write heartbeat %s: %s", outpath, exc)
