from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import Any
from urllib import error, parse, request

log = logging.getLogger("winhunt.ingestor")

_MAX_RETRY = 3
_RETRY_DELAY = 5


class ClickHouseIngestor:
    def __init__(self, config: Any):
        self.config = config
        self.rows_ingested = 0
        self.errors = 0

    def _insert_json_each_row(self, table: str, payload: bytes) -> int:
        query = parse.quote(f"INSERT INTO {table} FORMAT JSONEachRow", safe="")
        url = f"http://{self.config.clickhouse.host}:{self.config.clickhouse.port}/?database={self.config.clickhouse.database}&query={query}"
        req_obj = request.Request(url=url, data=payload, method="POST")
        req_obj.add_header("Content-Type", "application/json")
        if self.config.clickhouse.user:
            token = f"{self.config.clickhouse.user}:{self.config.clickhouse.password}".encode("utf-8")
            req_obj.add_header("Authorization", "Basic " + base64.b64encode(token).decode("ascii"))
        try:
            with request.urlopen(req_obj, timeout=60) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"ClickHouse insert failed status={resp.status}")
                return resp.status
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"ClickHouse HTTP error {exc.code}: {body[:2000]}") from exc

    def _determine_table(self, path: Path) -> str:
        """Determine ClickHouse table from filename prefix."""
        name = path.name.lower()
        if "flows" in name:
            return "pcap_flows_raw"
        if "events" in name:
            return "events_raw"
        log.warning("unknown file type %s — defaulting to events_raw", name)
        return "events_raw"

    def ingest_file_sync(self, path: Path) -> int:
        lines: list[str] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
        if not lines:
            return 0

        table = self._determine_table(path)
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        self._insert_json_each_row(table, payload)
        return len(lines)

    async def run(self, queue: asyncio.Queue, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set() or not queue.empty():
            try:
                path = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            file_path = Path(path)
            success = False
            for attempt in range(_MAX_RETRY):
                try:
                    count = await asyncio.to_thread(self.ingest_file_sync, file_path)
                    self.rows_ingested += count
                    log.info("ingested %d rows from %s", count, file_path.name)
                    success = True
                    break
                except Exception as exc:
                    self.errors += 1
                    log.warning("ingest attempt %d/%d for %s: %s",
                                attempt + 1, _MAX_RETRY, file_path.name, exc)
                    if attempt < _MAX_RETRY - 1:
                        await asyncio.sleep(_RETRY_DELAY)

            if success:
                # Only delete file on successful ingestion
                file_path.unlink(missing_ok=True)
            else:
                # Move to quarantine instead of deleting
                quarantine = file_path.parent / "quarantine"
                quarantine.mkdir(exist_ok=True)
                try:
                    file_path.rename(quarantine / file_path.name)
                    log.error("moved failed file to quarantine: %s", file_path.name)
                except OSError:
                    log.error("failed to quarantine %s — leaving in place", file_path.name)

            queue.task_done()
