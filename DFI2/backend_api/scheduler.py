import logging
import threading
import time

from .config import Settings
from .service import ControlPlaneService


log = logging.getLogger("backend_api.scheduler")


class QuietDemoter:
    def __init__(self, service: ControlPlaneService, settings: Settings):
        self.service = service
        self.settings = settings
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="quiet-demoter", daemon=True)
        self._thread.start()
        log.info("quiet_demoter_started interval=%s quiet_after=%s", self.settings.quiet_demote_interval_sec, self.settings.quiet_demote_after_sec)

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def _run(self) -> None:
        # Wait 15s after startup so the ClickHouse connection stabilises before first write
        self._stop.wait(15)
        while not self._stop.is_set():
            try:
                result = self.service.demote_quiet(quiet_after_sec=self.settings.quiet_demote_after_sec)
                log.info("quiet_demoter processed=%d skipped=%d", result.processed, result.skipped)
            except Exception as exc:
                log.error("quiet_demoter_failed err=%s", exc, exc_info=True)
            self._stop.wait(self.settings.quiet_demote_interval_sec)
