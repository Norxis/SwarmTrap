"""NDJSON exporter thread — writes unstaged rows to staging dir AND pushes to ClickHouse.

AIO expansion adds:
- Observations export (Phase 1)
- Predictions export (Phase 5)
- Priority batching (Phase 4): idle=30s, active=5s, immediate for priority events
- ClickHouse HTTP push: direct INSERT to PV1 ClickHouse via JSONEachRow
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from .evidence_bits import PRIORITY_BITS

log = logging.getLogger("winhunt.exporter")


class NdjsonExporter(threading.Thread):
    def __init__(self, config, buffer, stop_event: threading.Event,
                 flow_table=None):
        super().__init__(name="dfi-export", daemon=True)
        self.config = config
        self.buffer = buffer
        self.stop_event = stop_event
        self.flow_table = flow_table  # for active session count
        self.staging_dir = Path(config.exporter.staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._priority_event = threading.Event()  # signaled for immediate export
        # ClickHouse HTTP push
        self._ch_url = config.exporter.clickhouse_url  # empty = disabled
        self._ch_db = config.exporter.clickhouse_db
        if self._ch_url:
            log.info("ClickHouse push enabled: %s/%s", self._ch_url, self._ch_db)

    def trigger_priority_export(self) -> None:
        """Signal immediate export for priority events."""
        self._priority_event.set()

    def run(self) -> None:
        if not self.config.exporter.enabled:
            log.info("NDJSON exporter disabled")
            return
        while not self.stop_event.is_set():
            try:
                self._export_once()
            except Exception as exc:
                log.error("export error: %s", exc)
            try:
                self._cleanup_old_files()
            except Exception as exc:
                log.debug("cleanup error: %s", exc)

            # Priority batching: determine wait interval
            interval = self._get_export_interval()
            # Wait for either interval or priority trigger
            self._priority_event.clear()
            self._priority_event.wait(interval)
            if self.stop_event.is_set():
                break

    def _get_export_interval(self) -> float:
        """Determine export interval based on active engagement."""
        comm = getattr(self.config, 'comm', None)
        if comm is None:
            return self.config.exporter.export_interval_s

        # Check for active sessions
        active_sessions = 0
        if self.flow_table:
            active_sessions = self.flow_table.active_flow_count

        if active_sessions > 0:
            return comm.batch_active_s  # 5s during active engagement
        return comm.batch_idle_s  # 30s idle

    def _export_once(self) -> None:
        max_rows = self.config.exporter.max_rows_per_file
        # Export packets and fingerprints BEFORE flows — ack_flows() marks
        # packets/fingerprints as pulled=1 atomically, so grab them first.
        self._export_packets(max_rows)
        self._export_fingerprints(max_rows)
        self._export_flows(max_rows)
        self._export_events(max_rows)
        self._export_observations(max_rows)
        self._export_predictions(max_rows)

    # ── ClickHouse HTTP push ──

    _CH_TABLE_MAP = {
        "packets": "wh_packets",
        "fingerprints": "wh_fingerprints",
        "flows": "wh_flows",
        "events": "wh_events",
        "observations": "wh_observations",
        "source_stats": "wh_source_stats",
    }

    def _ch_push(self, data_type: str, rows: list[dict]) -> int:
        """Push rows to ClickHouse via HTTP JSONEachRow. Returns count pushed."""
        if not self._ch_url or not rows:
            return 0
        table = self._CH_TABLE_MAP.get(data_type, f"wh_{data_type}")
        query = parse.quote(f"INSERT INTO {table} FORMAT JSONEachRow", safe="")
        url = f"{self._ch_url}/?database={self._ch_db}&query={query}"
        lines = []
        for row in rows:
            clean = {k: v for k, v in row.items() if k != "pulled" and v is not None}
            lines.append(json.dumps(clean, ensure_ascii=True, separators=(",", ":")))
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        req_obj = request.Request(url=url, data=payload, method="POST")
        req_obj.add_header("Content-Type", "application/json")
        try:
            with request.urlopen(req_obj, timeout=30) as resp:
                if resp.status < 300:
                    return len(rows)
                log.warning("CH push %s status=%d", table, resp.status)
                return 0
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            log.warning("CH push %s HTTP %d: %s", table, exc.code, body[:300])
            return 0
        except Exception as exc:
            log.warning("CH push %s error: %s", table, exc)
            return 0

    def _rows_to_dicts(self, rows) -> list[dict]:
        """Convert sqlite3.Row list to list of dicts (no None values)."""
        return [{k: row[k] for k in row.keys() if row[k] is not None} for row in rows]

    def _export_packets(self, max_rows: int) -> None:
        """Export CNN token packets to NDJSON staging + ClickHouse."""
        rows = self.buffer.pull_unexported_packets(max_rows)
        if not rows:
            return
        dicts = self._rows_to_dicts(rows)
        self._ch_push("packets", dicts)
        self._seq += 1
        ts = int(time.time() * 1000)
        outfile = self.staging_dir / f"{self.config.exporter.file_prefix}_packets_{ts}_{self._seq}.ndjson"
        try:
            with open(outfile, "w", encoding="utf-8") as f:
                for d in dicts:
                    f.write(json.dumps(d, ensure_ascii=True, separators=(",", ":")) + "\n")
        except OSError as exc:
            log.error("failed to write %s: %s", outfile, exc)
            return
        log.info("exported %d packets", len(dicts))

    def _export_fingerprints(self, max_rows: int) -> None:
        """Export TLS/SSH/HTTP fingerprints to NDJSON staging + ClickHouse."""
        rows = self.buffer.pull_unexported_fingerprints(max_rows)
        if not rows:
            return
        dicts = self._rows_to_dicts(rows)
        self._ch_push("fingerprints", dicts)
        self._seq += 1
        ts = int(time.time() * 1000)
        outfile = self.staging_dir / f"{self.config.exporter.file_prefix}_fingerprints_{ts}_{self._seq}.ndjson"
        try:
            with open(outfile, "w", encoding="utf-8") as f:
                for d in dicts:
                    f.write(json.dumps(d, ensure_ascii=True, separators=(",", ":")) + "\n")
        except OSError as exc:
            log.error("failed to write %s: %s", outfile, exc)
            return
        log.info("exported %d fingerprints", len(dicts))

    def _export_flows(self, max_rows: int) -> None:
        rows = self.buffer.pull_unexported_flows(max_rows)
        if not rows:
            return
        dicts = self._rows_to_dicts(rows)
        self._ch_push("flows", dicts)
        self._seq += 1
        ts = int(time.time() * 1000)
        outfile = self.staging_dir / f"{self.config.exporter.file_prefix}_flows_{ts}_{self._seq}.ndjson"
        flow_ids: list[str] = []
        try:
            with open(outfile, "w", encoding="utf-8") as f:
                for d in dicts:
                    flow_ids.append(d.get("flow_id", ""))
                    f.write(json.dumps(d, ensure_ascii=True, separators=(",", ":")) + "\n")
        except OSError as exc:
            log.error("failed to write %s: %s", outfile, exc)
            return
        if flow_ids:
            self.buffer.ack_flows(flow_ids)
        log.info("exported %d flows", len(flow_ids))

    def _export_events(self, max_rows: int) -> None:
        rows = self.buffer.pull_unexported_events(max_rows)
        if not rows:
            return
        dicts = self._rows_to_dicts(rows)
        self._ch_push("events", dicts)
        self._seq += 1
        ts = int(time.time() * 1000)
        outfile = self.staging_dir / f"{self.config.exporter.file_prefix}_events_{ts}_{self._seq}.ndjson"
        seqs: list[int] = []
        try:
            with open(outfile, "w", encoding="utf-8") as f:
                for d in dicts:
                    seqs.append(d.get("seq", 0))
                    f.write(json.dumps(d, ensure_ascii=True, separators=(",", ":")) + "\n")
        except OSError as exc:
            log.error("failed to write %s: %s", outfile, exc)
            return
        if seqs:
            self.buffer.ack_events(max(seqs))
        log.info("exported %d events", len(seqs))

    def _export_observations(self, max_rows: int) -> None:
        """Export observations (Phase 1 AIO expansion)."""
        rows = self.buffer.pull_unexported_observations(max_rows)
        if not rows:
            return
        dicts = self._rows_to_dicts(rows)
        self._ch_push("observations", dicts)
        self._seq += 1
        ts = int(time.time() * 1000)
        outfile = self.staging_dir / f"{self.config.exporter.file_prefix}_observations_{ts}_{self._seq}.ndjson"
        obs_ids: list[int] = []
        try:
            with open(outfile, "w", encoding="utf-8") as f:
                for d in dicts:
                    obs_ids.append(d.get("obs_id", 0))
                    f.write(json.dumps(d, ensure_ascii=True, separators=(",", ":")) + "\n")
        except OSError as exc:
            log.error("failed to write %s: %s", outfile, exc)
            return
        if obs_ids:
            self.buffer.ack_observations(max(obs_ids))
        log.info("exported %d observations", len(obs_ids))

    def _export_predictions(self, max_rows: int) -> None:
        """Export predictions (Phase 5 AIO expansion)."""
        rows = self.buffer.pull_unexported_predictions(max_rows)
        if not rows:
            return
        dicts = self._rows_to_dicts(rows)
        self._ch_push("predictions", dicts)
        self._seq += 1
        ts = int(time.time() * 1000)
        outfile = self.staging_dir / f"{self.config.exporter.file_prefix}_predictions_{ts}_{self._seq}.ndjson"
        pred_ids: list[int] = []
        try:
            with open(outfile, "w", encoding="utf-8") as f:
                for d in dicts:
                    pred_ids.append(d.get("pred_id", 0))
                    f.write(json.dumps(d, ensure_ascii=True, separators=(",", ":")) + "\n")
        except OSError as exc:
            log.error("failed to write %s: %s", outfile, exc)
            return
        if pred_ids:
            self.buffer.ack_predictions(max(pred_ids))
        log.info("exported %d predictions", len(pred_ids))

    def _cleanup_old_files(self) -> None:
        cutoff = time.time() - self.config.exporter.retention_hours * 3600
        for p in self.staging_dir.glob("*.ndjson"):
            try:
                if p.stat().st_mtime < cutoff:
                    os.unlink(p)
            except OSError:
                continue
