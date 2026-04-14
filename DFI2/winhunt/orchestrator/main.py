from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from pathlib import Path

from .collector import MeshCollector
from .config import OrchestratorConfig
from .health import HealthMonitor
from .ingestor import ClickHouseIngestor


def setup_logging(log_file: str) -> None:
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )


async def run(config: OrchestratorConfig) -> None:
    log = logging.getLogger("winhunt.main")
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    stop_event = asyncio.Event()
    collector = MeshCollector(config)
    ingestor = ClickHouseIngestor(config)
    health = HealthMonitor(config)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass  # Windows doesn't support loop.add_signal_handler

    tasks = [
        asyncio.create_task(collector.run(queue, stop_event), name="collector"),
        asyncio.create_task(ingestor.run(queue, stop_event), name="ingestor"),
        asyncio.create_task(health.run(stop_event), name="health"),
    ]

    while not stop_event.is_set():
        done, _pending = await asyncio.wait(tasks, timeout=1.0, return_when=asyncio.FIRST_EXCEPTION)
        for d in done:
            exc = d.exception()
            if exc is not None:
                log.error("task %s failed: %s", d.get_name(), exc, exc_info=exc)
                stop_event.set()
                break

    # Drain queue with timeout to avoid hanging
    try:
        await asyncio.wait_for(queue.join(), timeout=30)
    except asyncio.TimeoutError:
        log.warning("queue drain timed out after 30s")

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    log.info("orchestrator shutdown complete")


def main() -> None:
    ap = argparse.ArgumentParser(description="WinHunt orchestrator")
    ap.add_argument("--config", required=True, help="Path to orchestrator config JSON")
    args = ap.parse_args()
    cfg = OrchestratorConfig.from_json(args.config)
    setup_logging(cfg.log_file)
    asyncio.run(run(cfg))


if __name__ == "__main__":
    main()
